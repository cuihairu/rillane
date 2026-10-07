//! Mixed 入口协议实现（同端口同时支持 SOCKS5 与 HTTP CONNECT）

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use seep_config::Credential;
use seep_core::udp::UdpAssociateService;
use seep_core::{FlowOutput, FlowRouter, IngressEndpoint};
use tokio::net::{TcpListener, TcpStream};

use super::{http::handle_http_connect_stream, socks5::handle_socks5_stream};

/// Mixed 入口服务
pub struct MixedIngress {
    name: String,
    bind: String,
    /// 入站凭据表（socks5 分支 RFC 1929、http 分支 Proxy-Authorization Basic；
    /// 空表 = 两分支均匿名放行，语义同 Socks5/Http）
    credentials: Vec<Credential>,
    /// UDP ASSOCIATE 服务（socks5 分支共享；None = 未启用）
    udp: Option<Arc<UdpAssociateService>>,
}

impl MixedIngress {
    pub fn new(
        name: String,
        bind: String,
        credentials: Vec<Credential>,
        udp: Option<Arc<UdpAssociateService>>,
    ) -> Self {
        Self {
            name,
            bind,
            credentials,
            udp,
        }
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let mut first = [0u8; 1];
        let n = stream.peek(&mut first).await?;
        if n == 0 {
            bail!("连接意外关闭");
        }

        if first[0] == 0x05 {
            handle_socks5_stream(
                self.name.as_str(),
                &self.credentials,
                stream,
                router,
                output,
                self.udp.clone(),
            )
            .await
        } else {
            handle_http_connect_stream(
                self.name.as_str(),
                &self.credentials,
                stream,
                router,
                output,
            )
            .await
        }
    }
}

#[async_trait]
impl IngressEndpoint for MixedIngress {
    fn name(&self) -> &'static str {
        "mixed"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("无法监听 {}", self.bind))?;

        tracing::info!(
            target: "seep::mixed",
            bind = %self.bind,
            "Mixed 入口启动"
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();

            tokio::spawn(async move {
                if let Err(err) = this.handle_client(stream, router, output).await {
                    tracing::warn!(
                        target: "seep::mixed",
                        client = %addr,
                        error = %err,
                        "Mixed 连接处理失败"
                    );
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::{Flow, FlowContext, FlowReport, RouteDecision};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct FixedRouter;

    #[async_trait]
    impl FlowRouter for FixedRouter {
        async fn route(&self, _ctx: FlowContext) -> Result<RouteDecision> {
            Ok(RouteDecision::direct("mock-egress".into()))
        }
    }

    /// 空出口：握手通过后的 forward 只登记即收（本组测试只看分支握手应答）
    struct NullOutput;

    #[async_trait]
    impl FlowOutput for NullOutput {
        async fn forward(&self, _decision: RouteDecision, _flow: Flow) -> Result<FlowReport> {
            Ok(FlowReport {
                upstream: 0,
                downstream: 0,
            })
        }
    }

    fn creds() -> Vec<Credential> {
        vec![Credential {
            username: "alice".into(),
            password: "wonderland".into(),
        }]
    }

    /// 起 Mixed 入口（绑定后归还端口），返回地址 + 服务任务
    async fn spawn_ingress(
        credentials: Vec<Credential>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Result<()>>) {
        // 先占 :0 拿空闲端口再让位（探测窗口极小，冲突时 bind 会立刻报错）
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let ingress = Arc::new(MixedIngress::new(
            "test-mixed".into(),
            addr.to_string(),
            credentials,
            None,
        ));
        let handle = tokio::spawn(async move {
            ingress
                .run(Arc::new(FixedRouter), Arc::new(NullOutput))
                .await
        });
        (addr, handle)
    }

    /// run() 内部异步 bind，connect 需重试至监听就绪（免 spawn→connect 竞速）
    async fn connect_with_retry(addr: std::net::SocketAddr) -> TcpStream {
        for _ in 0..100 {
            if let Ok(s) = TcpStream::connect(addr).await {
                return s;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("Mixed 入口未在限时内就绪: {addr}");
    }

    #[tokio::test]
    async fn mixed_http_branch_enforces_basic_auth() {
        let (addr, server) = spawn_ingress(creds()).await;
        let mut client = connect_with_retry(addr).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let n = client.read(&mut chunk).await.unwrap();
            assert!(n > 0, "对端提前关闭");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let resp = String::from_utf8_lossy(&buf);
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "http 分支缺头应 407: {resp}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn mixed_socks5_branch_rejects_anonymous_when_auth_configured() {
        let (addr, server) = spawn_ingress(creds()).await;
        let mut client = connect_with_retry(addr).await;
        // 仅提供 0x00（无认证）法 → 凭据表非空时应回 0xFF（无可用方法）
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF], "配置凭据后 socks5 分支应强制 RFC 1929");
        server.abort();
    }

    #[tokio::test]
    async fn mixed_socks5_branch_accepts_correct_credentials() {
        let (addr, server) = spawn_ingress(creds()).await;
        let mut client = connect_with_retry(addr).await;
        // 方法协商：客户端提供 0x02
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        // RFC 1929 子协商：alice / wonderland
        let mut sub = vec![0x01u8, 0x05];
        sub.extend_from_slice(b"alice");
        sub.push(0x0a);
        sub.extend_from_slice(b"wonderland");
        client.write_all(&sub).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x01, 0x00], "正确凭据应通过");
        // CONNECT（域名）→ 成功应答
        let mut req = vec![0x05u8, 0x01, 0x00, 0x03, 0x05];
        req.extend_from_slice(b"e.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00, "认证通过后 CONNECT 应成功");
        server.abort();
    }

    #[tokio::test]
    async fn mixed_without_auth_config_allows_anonymous_socks5() {
        let (addr, server) = spawn_ingress(Vec::new()).await;
        let mut client = connect_with_retry(addr).await;
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00], "空凭据表应匿名放行");
        server.abort();
    }
}
