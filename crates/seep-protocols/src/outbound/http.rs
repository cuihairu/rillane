//! HTTP CONNECT 出口连接器实现

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use seep_core::{EgressConnector, Flow, FlowReport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::fingerprint::TlsFingerprint;
use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};

/// HTTP CONNECT 代理出口连接器
pub struct HttpConnector {
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    /// 客户端 TLS 指纹形态（P2-5；None = rustls 缺省形态；仅 tls=true 时生效）
    fingerprint: TlsFingerprint,
    /// 出站连接池（P1-5 §4.2；None = 旧行为内联路径，D-9）
    pool: Option<Arc<TransportPool>>,
    /// 共享 ClientConfig 工厂：pool=None 且 tls=true 时使 TLS 会话恢复独立于
    /// 池生效（§3.1「块存在即生效」；None = 既有每流 ClientConfig）
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl HttpConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: bool,
        skip_cert_verify: bool,
        sni: Option<String>,
        fingerprint: TlsFingerprint,
        pool: Option<Arc<TransportPool>>,
        factory: Option<Arc<TlsConnectorFactory>>,
    ) -> Self {
        Self {
            server,
            port,
            username,
            password,
            tls,
            skip_cert_verify,
            sni,
            fingerprint,
            pool,
            factory,
        }
    }

    fn proxy_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// 传输键（§4.2）：TLS 走五元组键，平文走 plain 键
    fn transport_key(&self) -> TransportKey {
        if self.tls {
            TransportKey::tls(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                &[],
                self.fingerprint,
            )
        } else {
            TransportKey::plain(&self.server, self.port)
        }
    }

    fn build_connect_request(&self, target: &str) -> String {
        let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);

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

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        match &self.pool {
            Some(pool) => self.forward_pooled(flow, pool).await,
            None => self.forward_inline(flow).await,
        }
    }
}

impl HttpConnector {
    /// 池借出路径（§4.2）：acquire（TLS/平文键分形）→ CONNECT 握手（bind，
    /// 首写首读失败 → stale 一次性重拨 D-11）→ 双向转发。
    async fn forward_pooled(
        &self,
        mut flow: Flow,
        pool: &Arc<TransportPool>,
    ) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        // P1 安全（出口层最后防线）：host 内插进 CONNECT 请求行与 Host 头，
        // 含 CR/LF/控制字符即请求走私/头注入——拒绝而非注入上游。
        if crate::host_has_injection_chars(&flow.target.host) {
            bail!("HTTP CONNECT 目标主机含非法控制字符（拒绝头注入）");
        }
        let proxy_addr = self.proxy_addr();
        tracing::debug!(
            target: "seep::http_out",
            id = %flow.id.as_uuid(),
            %target,
            proxy = %proxy_addr,
            tls = %self.tls,
            pooled = true,
            "通过 HTTP 代理连接"
        );

        let key = self.transport_key();
        let request = self.build_connect_request(&target);
        let (mut outbound, _lease) = pool
            .acquire_bound(&key, |io| {
                let request = request.clone();
                Box::pin(async move { perform_connect(io, &request).await })
            })
            .await
            .with_context(|| format!("连接 HTTP 代理失败: {proxy_addr}"))?;

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut outbound,
            seep_core::performance::relay_buffer(),
            seep_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }

    /// 内联路径（pool=None）：与既有实现逐 IO 序列同构（D-9）；factory=Some
    /// 且 tls 时 TLS 连接器改取共享 ClientConfig（tls_resumption 独立于池生效）。
    async fn forward_inline(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        // P1 安全（出口层最后防线）：见 forward_pooled 同型守卫。
        if crate::host_has_injection_chars(&flow.target.host) {
            bail!("HTTP CONNECT 目标主机含非法控制字符（拒绝头注入）");
        }
        let proxy_addr = self.proxy_addr();

        tracing::debug!(
            target: "seep::http_out",
            id = %flow.id.as_uuid(),
            %target,
            proxy = %proxy_addr,
            tls = %self.tls,
            "通过 HTTP 代理连接"
        );

        // 建立 TCP 连接（net_mark 统一拨号：SO_MARK 逃逸面，networking.md §2）
        let tcp_stream = seep_core::net_mark::connect_tcp(proxy_addr.clone())
            .await
            .with_context(|| format!("连接 HTTP 代理失败: {}", proxy_addr))?;

        if self.tls {
            // TLS 包装
            let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
            let connector = match &self.factory {
                Some(factory) => factory.connector(self.skip_cert_verify, &[], self.fingerprint)?,
                None => create_tls_connector_with_profile(
                    self.skip_cert_verify,
                    None,
                    self.fingerprint,
                )?,
            };
            let server_name = rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
            let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

            // 发送 CONNECT 请求
            perform_connect(&mut tls_stream, &self.build_connect_request(&target)).await?;

            let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                &mut flow.io,
                &mut tls_stream,
                seep_core::performance::relay_buffer(),
                seep_core::performance::relay_buffer(),
            )
            .await
            .context("双向转发失败")?;

            Ok(FlowReport {
                upstream: up,
                downstream: down,
            })
        } else {
            let mut outbound = tcp_stream;
            // 发送 CONNECT 请求
            perform_connect(&mut outbound, &self.build_connect_request(&target)).await?;

            let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                &mut flow.io,
                &mut outbound,
                seep_core::performance::relay_buffer(),
                seep_core::performance::relay_buffer(),
            )
            .await
            .context("双向转发失败")?;

            Ok(FlowReport {
                upstream: up,
                downstream: down,
            })
        }
    }
}

/// 执行 HTTP CONNECT 握手（`&mut` 形：池借出对象与内联流共用同一逻辑）
async fn perform_connect<S>(stream: &mut S, request: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
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
        bail!(
            "HTTP 代理连接失败: {}",
            response.lines().next().unwrap_or("未知错误")
        );
    }

    Ok(())
}
