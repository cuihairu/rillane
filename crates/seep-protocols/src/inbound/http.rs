//! HTTP CONNECT 代理入口实现

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use seep_core::{
    BoxedIo, Flow, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget, IngressEndpoint,
    TargetProto,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub(crate) async fn handle_http_connect_stream(
    ingress_node_name: &str,
    mut stream: TcpStream,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
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
    let (method, target) = parse_http_request(&request)?;

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
}

impl HttpIngress {
    pub fn new(name: String, bind: String) -> Self {
        Self { name, bind }
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        handle_http_connect_stream(self.name.as_str(), stream, router, output).await
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

/// 解析 HTTP 请求行
fn parse_http_request(request: &str) -> Result<(String, String)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(request.as_bytes()) {
        Ok(httparse::Status::Complete(_)) => {
            let method = req.method.context("缺少 HTTP 方法")?.to_string();
            let path = req.path.context("缺少请求路径")?.to_string();
            Ok((method, path))
        }
        Ok(httparse::Status::Partial) => {
            bail!("HTTP 请求不完整");
        }
        Err(e) => {
            bail!("HTTP 解析失败: {}", e);
        }
    }
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
