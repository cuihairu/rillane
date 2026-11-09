//! HTTP CONNECT 代理入口实现

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::BytesMut;
use seep_config::Credential;
use seep_core::{
    BoxedIo, Flow, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget, IngressEndpoint,
    TargetProto,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// 407 响应体（认证强制时缺头/错凭据统一应答；按已配置 scheme 通告挑战）
fn proxy_auth_required(basic: bool, bearer: bool) -> String {
    let mut challenge = String::from("HTTP/1.1 407 Proxy Authentication Required\r\n");
    if basic {
        challenge.push_str("Proxy-Authenticate: Basic realm=\"seep\"\r\n");
    }
    if bearer {
        challenge.push_str("Proxy-Authenticate: Bearer realm=\"seep\"\r\n");
    }
    challenge.push_str("Content-Length: 0\r\n\r\n");
    challenge
}

pub(crate) async fn handle_http_connect_stream(
    ingress_node_name: &str,
    credentials: &[Credential],
    bearer_tokens: &[String],
    mut stream: TcpStream,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
    fake_ip: Option<Arc<seep_core::fake_ip::FakeIpTable>>,
) -> Result<()> {
    let client_addr = stream.peer_addr().ok();

    // 读取 HTTP 请求
    let mut buf = BytesMut::with_capacity(4096);
    let mut temp = [0u8; 1024];

    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            bail!("连接意外关闭");
        }
        buf.extend_from_slice(&temp[..n]);

        // 检查是否收到完整的 HTTP 头
        if buf.len() > 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }

        if buf.len() > 8192 {
            bail!("HTTP 请求头过大");
        }
    }

    // 解析 HTTP 请求
    let request = String::from_utf8_lossy(&buf);
    let (method, target, proxy_auth) = parse_http_request(&request)?;

    // 入站认证：Basic 凭据表 / Bearer 令牌表任一非空即强制（对齐 Socks5Ingress
    // 强制协商口径）；两 scheme 并列，任一通过即放行，407 挑战同时通告已配置者
    let basic_forced = !credentials.is_empty();
    let bearer_forced = !bearer_tokens.is_empty();
    if basic_forced || bearer_forced {
        let basic_ok = basic_forced && verify_basic_auth(credentials, proxy_auth.as_deref());
        let bearer_ok = bearer_forced && verify_bearer_auth(bearer_tokens, proxy_auth.as_deref());
        if !basic_ok && !bearer_ok {
            let challenge = proxy_auth_required(basic_forced, bearer_forced);
            stream.write_all(challenge.as_bytes()).await?;
            bail!("HTTP 代理认证失败");
        }
    }

    if method != "CONNECT" {
        // 非 CONNECT 请求，返回 405
        let response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        bail!("不支持的 HTTP 方法: {}", method);
    }

    // 解析目标地址
    let (host, port) = parse_connect_target(&target)?;

    // 发送 200 Connection Established
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    stream.write_all(response.as_bytes()).await?;

    // 构建 Flow
    let mut metadata = FlowMetadata {
        tags: vec!["ingress:http".into(), format!("node:{}", ingress_node_name)],
        ..Default::default()
    };
    if let Some(addr) = client_addr {
        metadata
            .annotations
            .insert("client.addr".into(), addr.to_string());
    }
    metadata
        .annotations
        .insert("ingress.node".into(), ingress_node_name.to_string());

    // fake-ip 回填（G1-10）：target 为池段 IPv4 时反查原域名改写（DNS 面
    // 分配的假地址），路由按域名规则命中；原域名记 `dns.fakeip` 注解可观测
    let host = match fake_ip
        .as_ref()
        .and_then(|t| seep_core::fake_ip::reverse_host(t, &host))
    {
        Some(domain) => {
            metadata
                .annotations
                .insert("dns.fakeip".into(), domain.clone());
            domain
        }
        None => host,
    };

    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host,
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(stream) as BoxedIo,
        metadata,
    };

    // 路由并转发
    let ctx = flow.context();
    let decision = router.route(ctx).await.context("路由计算失败")?;
    output
        .forward(decision, flow)
        .await
        .context("出口转发失败")?;

    Ok(())
}

/// HTTP CONNECT 代理入口服务
pub struct HttpIngress {
    name: String,
    bind: String,
    /// 入站凭据表（None/空表 = 匿名放行；非空强制 Proxy-Authorization: Basic）
    credentials: Vec<Credential>,
    /// Bearer 令牌表（None/空表 = 不启用；非空强制 Proxy-Authorization: Bearer）
    bearer_tokens: Vec<String>,
    /// fake-ip 池（G1-10；None = 关闭，target 原样路由）
    fake_ip: Option<Arc<seep_core::fake_ip::FakeIpTable>>,
}

impl HttpIngress {
    pub fn new(
        name: String,
        bind: String,
        credentials: Vec<Credential>,
        bearer_tokens: Vec<String>,
        fake_ip: Option<Arc<seep_core::fake_ip::FakeIpTable>>,
    ) -> Self {
        Self {
            name,
            bind,
            credentials,
            bearer_tokens,
            fake_ip,
        }
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        handle_http_connect_stream(
            self.name.as_str(),
            &self.credentials,
            &self.bearer_tokens,
            stream,
            router,
            output,
            self.fake_ip.clone(),
        )
        .await
    }
}

#[async_trait]
impl IngressEndpoint for HttpIngress {
    fn name(&self) -> &'static str {
        "http"
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
            target: "seep::http",
            bind = %self.bind,
            "HTTP 代理入口启动"
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();

            tokio::spawn(async move {
                if let Err(err) = this.handle_client(stream, router, output).await {
                    tracing::warn!(
                        target: "seep::http",
                        client = %addr,
                        error = %err,
                        "HTTP 代理连接处理失败"
                    );
                }
            });
        }
    }
}

/// 解析 HTTP 请求行与 Proxy-Authorization 头
fn parse_http_request(request: &str) -> Result<(String, String, Option<String>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(request.as_bytes()) {
        Ok(httparse::Status::Complete(_)) => {
            let method = req.method.context("缺少 HTTP 方法")?.to_string();
            let path = req.path.context("缺少请求路径")?.to_string();
            let proxy_auth = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
                .map(|h| String::from_utf8_lossy(h.value).into_owned());
            Ok((method, path, proxy_auth))
        }
        Ok(httparse::Status::Partial) => {
            bail!("HTTP 请求不完整");
        }
        Err(e) => {
            bail!("HTTP 解析失败: {}", e);
        }
    }
}

/// 校验 Proxy-Authorization: Basic（对齐 socks5 perform_auth 的明文比对口径）
fn verify_basic_auth(credentials: &[Credential], header: Option<&str>) -> bool {
    let Some(value) = header else {
        return false;
    };
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded) = BASE64.decode(encoded.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((username, password)) = text.split_once(':') else {
        return false;
    };
    credentials.iter().any(|cred| {
        seep_core::constant_time_eq(cred.username.as_bytes(), username.as_bytes())
            && seep_core::constant_time_eq(cred.password.as_bytes(), password.as_bytes())
    })
}

/// 校验 Proxy-Authorization: Bearer（RFC 6750 token 语义，明文比对）
fn verify_bearer_auth(tokens: &[String], header: Option<&str>) -> bool {
    let Some(value) = header else {
        return false;
    };
    let Some(token) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return false;
    };
    tokens
        .iter()
        .any(|t| seep_core::constant_time_eq(t.as_bytes(), token.trim().as_bytes()))
}

/// 解析 CONNECT 目标地址
fn parse_connect_target(target: &str) -> Result<(String, u16)> {
    // CONNECT host:port HTTP/1.1
    // 目标格式: host:port
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("无效的端口号: {}", port_str))?;
        Ok((host.to_string(), port))
    } else {
        // 默认 443 端口
        Ok((target.to_string(), 443))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::{FlowContext, FlowReport, RouteDecision};

    struct FixedRouter;

    #[async_trait]
    impl FlowRouter for FixedRouter {
        async fn route(&self, _ctx: FlowContext) -> Result<RouteDecision> {
            Ok(RouteDecision::direct("mock-egress".into()))
        }
    }

    /// 空出口：认证通过后的 forward 只登记即收（本组测试只看握手应答）
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

    /// 一对一回环连接：accepted 半边交给 handler，返回客户端半边 + handler join
    async fn spawn_handler(
        credentials: &[Credential],
        bearer_tokens: &[String],
    ) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let credentials = credentials.to_vec();
        let bearer_tokens = bearer_tokens.to_vec();
        let handle = tokio::spawn(async move {
            handle_http_connect_stream(
                "test-http",
                &credentials,
                &bearer_tokens,
                stream,
                Arc::new(FixedRouter),
                Arc::new(NullOutput),
                None,
            )
            .await
        });
        (client, handle)
    }

    /// 读到完整应答头（以 \r\n\r\n 结束）为止
    async fn read_response(client: &mut TcpStream) -> String {
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
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn http_without_auth_config_allows_anonymous() {
        let (mut client, handle) = spawn_handler(&[], &[]).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "无认证配置应放行: {resp}");
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_missing_authorization_rejected_with_407() {
        let (mut client, handle) = spawn_handler(&creds(), &[]).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "缺头应 407: {resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains("proxy-authenticate: basic"),
            "应带 Proxy-Authenticate 挑战: {resp}"
        );
        assert!(handle.await.unwrap().is_err(), "认证失败 handler 应 Err");
    }

    #[tokio::test]
    async fn http_wrong_credentials_rejected_with_407() {
        let (mut client, handle) = spawn_handler(&creds(), &[]).await;
        let encoded = BASE64.encode("alice:wrong-pass");
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
             Proxy-Authorization: Basic {encoded}\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "错凭据应 407: {resp}");
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn http_correct_basic_auth_passes() {
        let (mut client, handle) = spawn_handler(&creds(), &[]).await;
        let encoded = BASE64.encode("alice:wonderland");
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
             Proxy-Authorization: Basic {encoded}\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "正确凭据应放行: {resp}");
        handle.await.unwrap().unwrap();
    }

    #[test]
    fn verify_basic_auth_rejects_malformed_values() {
        let creds = creds();
        // 缺头 / 非 Basic scheme / 非法 base64 / 无冒号分隔 / 大小写 scheme 容忍
        assert!(!verify_basic_auth(&creds, None));
        assert!(!verify_basic_auth(&creds, Some("Bearer abc")));
        assert!(!verify_basic_auth(&creds, Some("Basic !!!not-base64!!!")));
        assert!(!verify_basic_auth(&creds, Some("Basic ")));
        assert!(!verify_basic_auth(&creds, Some("Basic bm9jb2xvbg==")));
        assert!(verify_basic_auth(
            &creds,
            Some(&format!("basic {}", BASE64.encode("alice:wonderland")))
        ));
    }

    fn bearer() -> Vec<String> {
        vec!["secret-token-123".to_string()]
    }

    #[tokio::test]
    async fn http_bearer_token_passes() {
        let (mut client, handle) = spawn_handler(&[], &bearer()).await;
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
                    Proxy-Authorization: Bearer secret-token-123\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "正确 Bearer 应放行: {resp}"
        );
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_wrong_bearer_token_rejected_with_407() {
        let (mut client, handle) = spawn_handler(&[], &bearer()).await;
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
                    Proxy-Authorization: Bearer wrong-token\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "错令牌应 407: {resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains("proxy-authenticate: bearer"),
            "应带 Bearer 挑战: {resp}"
        );
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn http_bearer_only_challenge_advertises_bearer_not_basic() {
        let (mut client, handle) = spawn_handler(&[], &bearer()).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 407"));
        assert!(
            resp.to_ascii_lowercase()
                .contains("proxy-authenticate: bearer"),
            "应带 Bearer 挑战: {resp}"
        );
        assert!(
            !resp
                .to_ascii_lowercase()
                .contains("proxy-authenticate: basic"),
            "未配置 Basic 不应通告: {resp}"
        );
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn http_basic_and_bearer_both_configured_either_passes() {
        // Basic 通过
        let (mut client, handle) = spawn_handler(&creds(), &bearer()).await;
        let encoded = BASE64.encode("alice:wonderland");
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
             Proxy-Authorization: Basic {encoded}\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "Basic 应放行: {resp}");
        handle.await.unwrap().unwrap();

        // Bearer 通过
        let (mut client, handle) = spawn_handler(&creds(), &bearer()).await;
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
                    Proxy-Authorization: Bearer secret-token-123\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "Bearer 应放行: {resp}");
        handle.await.unwrap().unwrap();

        // 407 同时通告两 scheme
        let (mut client, handle) = spawn_handler(&creds(), &bearer()).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 407"));
        let lower = resp.to_ascii_lowercase();
        assert!(
            lower.contains("proxy-authenticate: basic"),
            "应通告 Basic: {resp}"
        );
        assert!(
            lower.contains("proxy-authenticate: bearer"),
            "应通告 Bearer: {resp}"
        );
        assert!(handle.await.unwrap().is_err());
    }

    #[test]
    fn verify_bearer_auth_rejects_malformed_values() {
        let tokens = bearer();
        assert!(!verify_bearer_auth(&tokens, None));
        assert!(!verify_bearer_auth(&tokens, Some("Basic abc")));
        assert!(!verify_bearer_auth(&tokens, Some("Bearer ")));
        assert!(!verify_bearer_auth(&tokens, Some("Bearer wrong")));
        assert!(verify_bearer_auth(&tokens, Some("Bearer secret-token-123")));
        assert!(verify_bearer_auth(&tokens, Some("bearer secret-token-123")));
    }
}
