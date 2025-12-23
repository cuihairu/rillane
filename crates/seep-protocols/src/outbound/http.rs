//! HTTP CONNECT 出口连接器实现

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use seep_core::{EgressConnector, Flow, FlowReport};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::tls::create_tls_connector;

/// HTTP CONNECT 代理出口连接器
pub struct HttpConnector {
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
}

impl HttpConnector {
    pub fn new(
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: bool,
        skip_cert_verify: bool,
        sni: Option<String>,
    ) -> Self {
        Self {
            server,
            port,
            username,
            password,
            tls,
            skip_cert_verify,
            sni,
        }
    }

    fn proxy_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    fn build_connect_request(&self, target: &str) -> String {
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target, target
        );

        // 添加代理认证
        if let (Some(user), Some(pass)) = (self.username.as_ref(), self.password.as_ref()) {
            let credentials = format!("{}:{}", user, pass);
            let encoded = BASE64.encode(credentials.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        request.push_str("\r\n");
        request
    }
}

#[async_trait]
impl EgressConnector for HttpConnector {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let proxy_addr = self.proxy_addr();

        tracing::debug!(
            target: "seep::http_out",
            id = %flow.id.as_uuid(),
            %target,
            proxy = %proxy_addr,
            tls = %self.tls,
            "通过 HTTP 代理连接"
        );

        // 建立 TCP 连接
        let tcp_stream = TcpStream::connect(&proxy_addr)
            .await
            .with_context(|| format!("连接 HTTP 代理失败: {}", proxy_addr))?;

        if self.tls {
            // TLS 包装
            let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
            let connector = create_tls_connector(self.skip_cert_verify)?;
            let server_name =
                rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
            let tls_stream = connector.connect(server_name, tcp_stream).await?;

            // 发送 CONNECT 请求
            let mut outbound =
                perform_connect(tls_stream, &self.build_connect_request(&target)).await?;

            let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
                .await
                .context("双向转发失败")?;

            Ok(FlowReport {
                upstream: up,
                downstream: down,
            })
        } else {
            // 发送 CONNECT 请求
            let mut outbound =
                perform_connect(tcp_stream, &self.build_connect_request(&target)).await?;

            let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
                .await
                .context("双向转发失败")?;

            Ok(FlowReport {
                upstream: up,
                downstream: down,
            })
        }
    }
}

/// 执行 HTTP CONNECT 握手
async fn perform_connect<S>(mut stream: S, request: &str) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 发送 CONNECT 请求
    stream.write_all(request.as_bytes()).await?;

    // 读取响应
    let mut response = String::new();
    let mut buf = [0u8; 1];

    // 简单读取直到 \r\n\r\n
    loop {
        stream.read_exact(&mut buf).await?;
        response.push(buf[0] as char);

        if response.ends_with("\r\n\r\n") {
            break;
        }

        if response.len() > 8192 {
            bail!("HTTP 代理响应过大");
        }
    }

    // 检查状态码
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        bail!("HTTP 代理连接失败: {}", response.lines().next().unwrap_or("未知错误"));
    }

    Ok(stream)
}
