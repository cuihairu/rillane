//! Cloudflared 出口连接器实现（RIL-128）。
//!
//! mesh 客户端面（出口）——经 Cloudflare Tunnel 公共主机名拨远程 TCP 服务
//! （CF Access 服务令牌可配）。本仓侧为 WS-over-TLS 客户端（RFC 6455）：
//! TLS（webpki-roots，ALPN http/1.1）→ `GET {path}` upgrade（可选
//! CF-Access-Client-Id/Secret 头）→ 101 校验 → 裸字节经 WS 帧双向泵
//! （掩码写/非掩码读，16KiB 内部分片，16MiB 读上限）。对端（真实 peer）
//! = Cloudflare 生产 edge（trycloudflare.com 或命名隧道公共主机名），
//! edge 终结 WS 帧并转 QUIC/H2 隧道至隧道客户端（载具 libcfd）；origin
//! 侧收到的是帧终结后的裸字节——与 `cloudflared access tcp` 的客户端
//! 语义同构（CF 将 tcp:// 路由以承载裸字节的 WS 连接暴露）。
//!
//! 目标寻址口径：`hostname` 即端点身份（公共主机名 → 单 ingress 服务），
//! flow 目标不参预路由——与 tailscale/tailcat 的「地址即端点」同口径，
//! 具名于此。
//!
//! 安全姿态与具名边界（见 protocol-backends.md#cloudflared）：载具 libcfd
//! 0.2.0（Apache-2.0，crates.io 发布；libcfd-rpc capnp 缺编译器回退
//! committed pregenerated=零安装面）。本仓仅交付客户端面（Cloudflare
//! Tunnel 隧道客户端/守护面不交付——本仓不做隧道服务端）；无 UDP/QUIC
//! 应用面（catalog udp=false）；命名隧道须 Access 服务令牌（admin 预配，
//! 本验收以 quick tunnel 自预配为对端）；edge 恒 443（hostname 不得带
//! 端口，具名拒绝）。

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::ws::{ws_client_handshake_extra, WsClient};
use crate::fingerprint::TlsFingerprint;
use crate::tls::create_tls_connector_with_profile;

/// Cloudflare edge HTTPS/WS 端口（恒 443；hostname 不得带端口）
const EDGE_PORT: u16 = 443;
/// 拨号/握手超时（载具 connect_timeout 同量级；具名于模块注释）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 有界 PONG 转发队列（同 vless 口径：满则丢弃，控制帧可丢）
const PONG_QUEUE: usize = 64;

/// Cloudflared 出口配置（IR `EgressConfig::Cloudflared` 展开后的私有形态）
#[derive(Debug, Clone)]
struct CloudflaredConfig {
    /// 公共隧道主机名（trycloudflare.com quick 或命名隧道；即端点）
    hostname: String,
    /// WS upgrade 路径（缺省 `/`）
    path: String,
    /// CF Access 服务令牌 Client-ID（与 Secret 成对；None = 匿名）
    access_client_id: Option<String>,
    /// CF Access 服务令牌 Client-Secret（与 ID 成对；None = 匿名）
    access_client_secret: Option<String>,
}

/// Cloudflared 连接器：一个公共主机名一个连接器；逐流独立 TLS+WS 拨号
/// （隧道无共享会话——CF edge 按连接处理，与 tailscale 共享 Device 不同
/// 口径，具名于模块注释）。
pub struct CloudflaredConnector {
    cfg: CloudflaredConfig,
}

impl CloudflaredConnector {
    pub fn new(
        hostname: String,
        path: String,
        access_client_id: Option<String>,
        access_client_secret: Option<String>,
    ) -> Result<Self> {
        let hostname = hostname.trim().to_string();
        if hostname.is_empty() {
            return Err(anyhow!(
                "cloudflared hostname 为空（公共隧道主机名即端点，必填）"
            ));
        }
        if hostname.contains("://") {
            return Err(anyhow!(
                "cloudflared hostname 须为裸主机名（含 scheme 拒绝：{hostname}）"
            ));
        }
        if hostname.contains(':') {
            return Err(anyhow!(
                "cloudflared hostname 不得带端口（edge 恒 {EDGE_PORT}）：{hostname}"
            ));
        }
        let path = {
            let p = path.trim();
            if p.is_empty() {
                "/".to_string()
            } else if !p.starts_with('/') {
                return Err(anyhow!("cloudflared path 须以 / 起首：{p}"));
            } else {
                p.to_string()
            }
        };
        // CF Access 服务令牌成对校验（id 无 secret / secret 无 id 均拒绝，
        // 不静默降级为匿名——连接必失败且无报错）
        match (&access_client_id, &access_client_secret) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(anyhow!(
                    "cloudflared CF Access 服务令牌须成对（access_client_id/access_client_secret）"
                ));
            }
            _ => {}
        }
        Ok(Self {
            cfg: CloudflaredConfig {
                hostname,
                path,
                access_client_id,
                access_client_secret,
            },
        })
    }

    /// CF Access 服务令牌头（成对时返回两行；匿名时空表）
    fn access_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let (Some(id), Some(secret)) = (
            self.cfg.access_client_id.as_deref(),
            self.cfg.access_client_secret.as_deref(),
        ) {
            headers.push(("CF-Access-Client-Id", id.to_string()));
            headers.push(("CF-Access-Client-Secret", secret.to_string()));
        }
        headers
    }

    async fn relay<R, W>(
        &self,
        flow: rillane_core::Flow,
        ws: WsClient<R, W>,
    ) -> Result<rillane_core::FlowReport>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        use rillane_core::FlowReport;
        let (mut client_r, mut client_w) = tokio::io::split(flow.io);
        let (mut ws_r, mut ws_w) = ws.split();
        let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PONG_QUEUE);
        ws_r.set_pong_sender(pong_tx);

        let up_task = tokio::spawn(async move {
            let mut up: u64 = 0;
            let mut buf = [0u8; 16 * 1024];
            loop {
                tokio::select! {
                    biased;
                    Some(payload) = pong_rx.recv() => {
                        ws_w.write_pong(&payload).await?;
                    }
                    n = client_r.read(&mut buf) => {
                        let n = n?;
                        if n == 0 {
                            break;
                        }
                        ws_w.write_binary(&buf[..n]).await?;
                        up += n as u64;
                    }
                }
            }
            // 客户端半关 → 向 edge 传播 ws Close（edge 对 origin 侧收尾后
            // 回 Close/关 TLS，下行侧经 read_data None 语义同步收敛）
            let _ = ws_w.write_close().await;
            Result::<u64>::Ok(up)
        });

        let down_task = tokio::spawn(async move {
            let mut down: u64 = 0;
            while let Some(msg) = ws_r.read_data().await? {
                if msg.is_empty() {
                    continue;
                }
                client_w.write_all(&msg).await?;
                down += msg.len() as u64;
            }
            let _ = client_w.shutdown().await;
            Result::<u64>::Ok(down)
        });

        let (up, down) =
            tokio::try_join!(up_task, down_task).context("cloudflared WS 双向转发任务失败")?;
        let up = up?;
        let down = down?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

/// edge 主机名解析：系统解析器优先，失败回退 Cloudflare DoH（字面 IP
/// 1.1.1.1:443 TLS + dns-json——IP 字面即无解析无递归）。取首个地址。
async fn resolve_edge_ip(hostname: &str) -> Result<std::net::IpAddr> {
    if let Ok(addrs) = tokio::net::lookup_host((hostname, EDGE_PORT)).await {
        if let Some(addr) = addrs.into_iter().next() {
            return Ok(addr.ip());
        }
    }
    doh_lookup(hostname).await
}

/// Cloudflare DoH 查询（A 优先，AAAA 兜底）：GET /dns-query?name=..&type=A
/// + Accept: application/dns-json（RFC 8484 的 JSON 面），Answer[].data 解析。
async fn doh_lookup(hostname: &str) -> Result<std::net::IpAddr> {
    let server_name = ServerName::try_from("1.1.1.1".to_string())
        .map_err(|e| anyhow!("DoH 服务器名非法：{e}"))?;
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let configuration =
        rustls::ClientConfig::builder_with_provider(crate::tls::tls_crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(store)
            .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(configuration));
    let tcp = TcpStream::connect((std::net::IpAddr::from([1u8, 1, 1, 1]), 443))
        .await
        .context("DoH TCP 连接失败（1.1.1.1:443）")?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .context("DoH TLS 失败")?;
    let request = format!(
        "GET /dns-query?name={hostname}&type=A HTTP/1.1\r\nHost: 1.1.1.1\r\n\
         Accept: application/dns-json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("DoH 请求写失败")?;
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .context("DoH 应答读失败")?;
    let header_end = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or_else(|| anyhow!("DoH 应答无头部结束符"))?;
    let head = String::from_utf8_lossy(&body[..header_end]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or_else(|| anyhow!("DoH 应答缺状态行"))?;
    if status != "200" {
        return Err(anyhow!("DoH 应答非 200：{status}"));
    }
    let payload: serde_json::Value =
        serde_json::from_slice(&body[header_end..]).context("DoH JSON 解析失败")?;
    // A(1) 优先；无 A 取 AAAA(28)
    for want_type in [1u64, 28] {
        if let Some(answers) = payload.get("Answer").and_then(|a| a.as_array()) {
            for answer in answers {
                let t = answer.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
                if t != want_type {
                    continue;
                }
                if let Some(data) = answer.get("data").and_then(|v| v.as_str()) {
                    if let Ok(ip) = data.parse::<std::net::IpAddr>() {
                        return Ok(ip);
                    }
                }
            }
        }
    }
    Err(anyhow!("DoH 应答无可用地址记录：{payload}"))
}

#[async_trait::async_trait]
impl rillane_core::EgressConnector for CloudflaredConnector {
    fn name(&self) -> &'static str {
        "cloudflared"
    }

    async fn forward(&self, flow: rillane_core::Flow) -> Result<rillane_core::FlowReport> {
        if !matches!(flow.target.proto, rillane_core::TargetProto::Tcp) {
            return Err(anyhow!(
                "Cloudflared 仅交付 TCP 应用面（UDP/QUIC 应用面不交付）"
            ));
        }
        // TLS 拨号：webpki-roots + ALPN http/1.1（WS upgrade 在 HTTP/1.1 面；
        // 指纹 None = 走 rustls 缺省构造，不伪装）
        let connector: TlsConnector = create_tls_connector_with_profile(
            false,
            Some(&["http/1.1".to_string()]),
            TlsFingerprint::None,
        )?;
        let server_name = ServerName::try_from(self.cfg.hostname.clone())
            .map_err(|e| anyhow!("cloudflared hostname 非合法主机名：{e}"))?;
        // DNS：系统解析器优先；失败回退 Cloudflare DoH（1.1.1.1 字面 IP
        // TLS，dns-json，无递归）——隧道主机名被本地解析器过滤/解析失败
        // 是真实故障面（载具 live 测试同口径回退，见
        // protocol-backends.md#cloudflared）
        let edge_ip = resolve_edge_ip(&self.cfg.hostname)
            .await
            .context("cloudflared hostname 解析失败（系统解析 + Cloudflare DoH 均未果）")?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((edge_ip, EDGE_PORT)))
            .await
            .context("cloudflared 拨号超时（edge 不可达）")?
            .context("cloudflared 拨号失败")?;
        let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .context("cloudflared TLS 握手超时")?
            .context("cloudflared TLS 握手失败")?;

        let headers = self.access_headers();
        let headers_ref: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let ws = ws_client_handshake_extra(tls, &self.cfg.hostname, &self.cfg.path, &headers_ref)
            .await
            .context("cloudflared WS upgrade 失败（hostname 无该路径/非隧道或 Access 被拒）")?;
        self.relay(flow, ws).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_hostname() {
        let err = CloudflaredConnector::new(String::new(), "/".into(), None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("hostname"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_hostname_with_scheme() {
        let err = CloudflaredConnector::new("https://x.example".into(), "/".into(), None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("scheme"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_hostname_with_port() {
        let err = CloudflaredConnector::new("x.example:443".into(), "/".into(), None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("端口"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_bad_path() {
        let err = CloudflaredConnector::new("x.example".into(), "ws".into(), None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("path"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_half_token_pair() {
        let err =
            CloudflaredConnector::new("x.example".into(), "/".into(), Some("id".into()), None)
                .err()
                .unwrap()
                .to_string();
        assert!(err.contains("成对"), "具名拒绝：{err}");
        let err =
            CloudflaredConnector::new("x.example".into(), "/".into(), None, Some("secret".into()))
                .err()
                .unwrap()
                .to_string();
        assert!(err.contains("成对"), "具名拒绝：{err}");
    }

    #[test]
    fn new_accepts_valid() {
        assert!(CloudflaredConnector::new("x.example".into(), "/".into(), None, None).is_ok());
        assert!(CloudflaredConnector::new("x.example".into(), "/p".into(), None, None).is_ok());
        assert!(CloudflaredConnector::new(
            "x.example".into(),
            "/".into(),
            Some("id".into()),
            Some("secret".into()),
        )
        .is_ok());
        // 空 path → 缺省 /
        assert!(CloudflaredConnector::new("x.example".into(), "  ".into(), None, None).is_ok());
    }
}
