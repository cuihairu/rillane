//! TrustTunnel 出口连接器（RIL-119）——TCP + UDP 客户端面。
//!
//! 线格式以官方规范（TrustTunnel/TrustTunnel `PROTOCOL.md` v1.0，
//! 2025-12-24，取证 docs/protocol-backends.md#trusttunnel）为唯一实现
//! 真源；实现家族（端点 Rust 应用 + C++ 客户端）无可用 Rust 库面
//! （评估留证同上），自写梯子开启。验收对官方端点 linux-x86_64 预构建
//! 二进制（Apache-2.0，黑盒对端）实机回环。规范钉定事实：
//! - TCP 面：TLS ≥1.2（SNI 必发、证书校验必须）+ ALPN `h2` 的
//!   HTTP/2 **CONNECT**——`:authority` = `host:port`（IPv6 加方括号，
//!   IPv4/域名直拼）；必发 `user-agent`（平台 + 应用名）与
//!   `proxy-authorization: Basic base64(user:pass)`；200 = 双向字节流、
//!   407 = 认证失败（具名族）、其余非 200 = 连接失败；流关闭即连接
//!   拆除（END_STREAM 优雅半关 / RST abrupt）。
//! - UDP 面：CONNECT 保留伪主机 `_udp2` 单流复用。上行包 =
//!   `[len u32 BE][src 16B][sport u16 BE][dst 16B][dport u16 BE]
//!   [appname-len u8][appname][payload]`（len 不含长度字段自身；
//!   IPv4 零填充 16B——首 12B 全零且非 ::1 判 v4）；下行包**无
//!   appname 字段**；端点按 4 元组跟踪（闲置 120s）。
//! - 保留伪主机：`_udp2`（UDP 复用）/ `_icmp`（ICMP——VPN 概念，
//!   非代理出口面，不交付）/ `_check`（健康检查流——策略面，不交付）。
//! - H3（QUIC，ALPN `h3`）载具另有规范——本仓不选（mihomo `quic: true`
//!   导入具名拒绝，防静默降级）。
//!
//! 交付边界（评估记录具名）：复用旋钮（max-connections/min-streams/
//! max-streams）与 health-check 键容忍读取不落行为；服务端面不交付
//! （端点是独立应用，mita 口径同例）；HTTP/2 初始窗口取 h2 crate 缺省
//! （spec 131072 是官方客户端取值，非线格式约束——流控自协商）。
//! UDP 伪源地址：连接器为本进程伪造稳定伪源（127.0.0.1 + 逐关联递增
//! 端口）——官方客户端发 TUN 接口地址，代理出口场景无 TUN，语义等价
//! （端点仅以 4 元组回拼，不路由到 src）。

use crate::fingerprint::TlsFingerprint;
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{Method, Request, StatusCode, Uri};
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use std::future::poll_fn;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// 分阶段拨号超时（TCP 连接——连接器面统一 15s 口径）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 隧道握手超时（TLS + h2 握手 + CONNECT 应答）
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// ALPN（spec §3.1：h2 载具必须协商 `h2`）
const ALPN_H2: [&str; 1] = ["h2"];
/// user-agent（spec §5.1：必发，平台标识 + 应用名）
fn user_agent() -> String {
    format!("{} rillane", std::env::consts::OS)
}
/// UDP 保留伪主机（spec §6.2 / Appendix A）
const PSEUDO_HOST_UDP: &str = "_udp2";
/// 上行包 appname 字段值（应用标识——规范任意串，官方客户端发应用名）
const APP_NAME: &str = "rillane";
/// 伪源端口分配起点（逐关联递增，wrap 即回绕——进程内唯一即可）
static UDP_PSEUDO_PORT: AtomicU16 = AtomicU16::new(40000);

// ---------------------------------------------------------------------------
// 线格式纯函数（向量测试钉定）
// ---------------------------------------------------------------------------

/// `:authority` 构造（spec §11.3）：IPv4 `ip:port`、IPv6 `[ip]:port`、
/// 域名 `host:port`。host 含注入字符（CR/LF/控制/空格/authority 元字符）
/// 具名拒绝——出口层最后防线口径（host_has_injection_chars 同源）。
fn trusttunnel_authority(host: &str, port: u16) -> Result<String> {
    if crate::host_has_injection_chars(host) {
        bail!("TrustTunnel 目标 host 含非法字符: {host:?}");
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        Ok(format!("{v4}:{port}"))
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        Ok(format!("[{v6}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

/// Basic 凭据（spec §9.1：`base64(username + ":" + password)`）
fn basic_credentials(username: &str, password: &str) -> String {
    BASE64.encode(format!("{username}:{password}"))
}

/// 16 字节地址编码（spec §11.2）：IPv4 零填充 12B + 4B；IPv6 原样 16B
fn encode_addr16(host: &str) -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        out[12..].copy_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        out = v6.octets();
    } else {
        bail!("TrustTunnel UDP 面目标须为 IP（域名先经运行时解析）: {host:?}");
    }
    Ok(out)
}

/// 16 字节地址解码（spec §11.2）：首 12B 全零且非 ::1 判 IPv4
fn decode_addr16(b: &[u8; 16]) -> std::net::IpAddr {
    let is_v4 = b[..12] == [0u8; 12] && *b != Ipv6Addr::LOCALHOST.octets();
    if is_v4 {
        std::net::IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else {
        std::net::IpAddr::V6(Ipv6Addr::from(*b))
    }
}

/// 上行 UDP 包组帧（spec §6.3）：
/// `[len u32 BE][src 16][sport u16][dst 16][dport u16][alen u8][appname][payload]`
/// （len 不含长度字段自身）
fn build_udp_upstream_frame(src: &SocketAddr, dst: &FlowTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let src_ip = encode_addr16(&src.ip().to_string())?;
    let dst_ip = encode_addr16(&dst.host)?;
    let appname = APP_NAME.as_bytes();
    if appname.len() > u8::MAX as usize {
        bail!("TrustTunnel UDP appname 超长");
    }
    let body_len = 16 + 2 + 16 + 2 + 1 + appname.len() + payload.len();
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.extend_from_slice(&src_ip);
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst_ip);
    out.extend_from_slice(&dst.port.to_be_bytes());
    out.push(appname.len() as u8);
    out.extend_from_slice(appname);
    out.extend_from_slice(payload);
    Ok(out)
}

/// 下行 UDP 包解帧（spec §6.4，无 appname 字段）：
/// `[len u32 BE][src 16][sport u16][dst 16][dport u16][payload]`
/// 返回（源 = 真实应答方、目标 = 我方伪源、载荷、消费字节数）；
/// 半包返回 None（等下一段）。
fn parse_udp_downstream_frame(buf: &[u8]) -> Option<(FlowTarget, FlowTarget, Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let body_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let total = 4 + body_len;
    if buf.len() < total || total < 4 + 36 {
        return None;
    }
    let b = &buf[4..total];
    let mut src = [0u8; 16];
    src.copy_from_slice(&b[0..16]);
    let sport = u16::from_be_bytes([b[16], b[17]]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&b[18..34]);
    let dport = u16::from_be_bytes([b[34], b[35]]);
    let src_target = FlowTarget {
        host: decode_addr16(&src).to_string(),
        port: sport,
        proto: TargetProto::Udp,
    };
    let dst_target = FlowTarget {
        host: decode_addr16(&dst).to_string(),
        port: dport,
        proto: TargetProto::Udp,
    };
    Some((src_target, dst_target, b[36..].to_vec(), total))
}

// ---------------------------------------------------------------------------
// 拨号核：TLS(ALPN h2) → h2 握手 → CONNECT（TCP 面 / _udp2 共用）
// ---------------------------------------------------------------------------

/// 拨号配置（TCP 连接器与 UDP 连接器共享的字段束）
#[derive(Clone)]
struct DialConfig {
    server: String,
    port: u16,
    username: String,
    password: String,
    /// SNI（缺省回落 server；spec：SNI 必发）
    sni: Option<String>,
    skip_cert_verify: bool,
    fingerprint: TlsFingerprint,
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl DialConfig {
    /// 构建期校验（配置错误装配期暴露）
    fn validate(&self) -> Result<()> {
        if self.server.is_empty() {
            bail!("TrustTunnel 缺少服务器地址");
        }
        if self.username.is_empty() {
            bail!("TrustTunnel 缺少用户名");
        }
        if self.password.is_empty() {
            bail!("TrustTunnel 缺少密码");
        }
        Ok(())
    }

    /// TLS(ALPN h2) → h2 客户端握手（连接驱动任务离场）
    async fn dial_h2_client(&self) -> Result<h2::client::SendRequest<Bytes>> {
        let addr = format!("{}:{}", self.server, self.port);
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .context("TrustTunnel 连接超时")?
            .with_context(|| format!("TrustTunnel 端点连接失败: {addr}"))?;
        let alpn: Vec<String> = ALPN_H2.iter().map(|s| s.to_string()).collect();
        let tls_connector = match &self.factory {
            Some(f) => f.connector(self.skip_cert_verify, &alpn, self.fingerprint)?,
            None => create_tls_connector_with_profile(
                self.skip_cert_verify,
                Some(&alpn),
                self.fingerprint,
            )?,
        };
        let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
        let server_name =
            rustls::pki_types::ServerName::try_from(sni).context("TrustTunnel 无效的 SNI")?;
        let tls = tls_connector
            .connect(server_name, tcp)
            .await
            .context("TrustTunnel TLS 握手失败")?;
        let (client, conn) = h2::client::handshake(tls)
            .await
            .context("TrustTunnel h2 握手失败")?;
        // 连接驱动：流全收尾/对端关闭即自然退出（h2.rs 同口径）
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(client)
    }

    /// CONNECT 一条流并校验 200（authority = host:port 或保留伪主机）。
    /// 407 = 认证具名失败族；其余非 200 = 连接失败（spec §5.2）。
    async fn connect_stream(&self, authority: &str) -> Result<(SendStream<Bytes>, RecvStream)> {
        let client = self.dial_h2_client().await?;
        let uri = Uri::builder()
            .authority(authority)
            .build()
            .with_context(|| format!("TrustTunnel authority 构造失败: {authority:?}"))?;
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("user-agent", user_agent())
            .header(
                "proxy-authorization",
                format!(
                    "Basic {}",
                    basic_credentials(&self.username, &self.password)
                ),
            )
            .body(())
            .map_err(|e| anyhow!("TrustTunnel CONNECT 请求构造失败: {e}"))?;
        let (resp, send) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut ready = client.ready().await.context("TrustTunnel h2 就绪失败")?;
            ready
                .send_request(req, false)
                .context("TrustTunnel 流打开失败")
        })
        .await
        .context("TrustTunnel 流打开超时")??;
        let resp = tokio::time::timeout(HANDSHAKE_TIMEOUT, resp)
            .await
            .context("TrustTunnel CONNECT 应答超时")?
            .context("TrustTunnel CONNECT 应答失败")?;
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
                bail!("TrustTunnel 端点认证失败（HTTP 407）——用户名/密码被拒")
            }
            other => bail!("TrustTunnel 隧道握手失败：HTTP {other}"),
        }
        Ok((send, resp.into_body()))
    }
}

// ---------------------------------------------------------------------------
// TCP 客户端面
// ---------------------------------------------------------------------------

/// TrustTunnel TCP 出口连接器（RIL-119）：官方 PROTOCOL.md v1.0 自写——
/// TLS(ALPN h2) + HTTP/2 CONNECT + Basic 认证，200 后流即纯目标字节面。
pub struct TrustTunnelConnector {
    dial: DialConfig,
}

impl TrustTunnelConnector {
    /// 构建期校验：空用户名/密码/服务器具名拒绝（配置错误在装配期暴露）。
    pub fn new(
        server: String,
        port: u16,
        username: String,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        fingerprint: TlsFingerprint,
    ) -> Result<Self> {
        let dial = DialConfig {
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            fingerprint,
            factory: None,
        };
        dial.validate()?;
        Ok(Self { dial })
    }

    /// 共享 ClientConfig 工厂（池面/传输键组合；None = 每流配置）
    pub fn with_factory(mut self, factory: Arc<TlsConnectorFactory>) -> Self {
        self.dial.factory = Some(factory);
        self
    }
}

#[async_trait]
impl EgressConnector for TrustTunnelConnector {
    fn name(&self) -> &'static str {
        "trusttunnel"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let authority =
            trusttunnel_authority(&flow.target.host, flow.target.port).with_context(|| {
                format!(
                    "TrustTunnel 目标非法: {}:{}",
                    flow.target.host, flow.target.port
                )
            })?;
        let (send, recv) = self.dial.connect_stream(&authority).await?;
        let mut stream = super::h2::H2Stream::from_parts(send, recv);

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("TrustTunnel 双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// UDP 客户端面（_udp2 伪主机单流复用）
// ---------------------------------------------------------------------------

/// TrustTunnel UDP 出口连接器（RIL-119）：每关联一条 `_udp2` CONNECT 流
/// （spec 的「单流复用」按官方客户端全会话一条流表述——本仓按关联开流，
/// 线格式不变：帧自携 4 元组，端点按元组跟踪，多流等价多关联）。
#[derive(Clone)]
pub struct TrustTunnelUdpConnector {
    dial: Arc<DialConfig>,
}

impl TrustTunnelUdpConnector {
    /// 构建期校验同 TCP 面。
    pub fn new(
        server: String,
        port: u16,
        username: String,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        fingerprint: TlsFingerprint,
    ) -> Result<Self> {
        let dial = DialConfig {
            server,
            port,
            username,
            password,
            sni,
            skip_cert_verify,
            fingerprint,
            factory: None,
        };
        dial.validate()?;
        Ok(Self {
            dial: Arc::new(dial),
        })
    }

    /// 共享 ClientConfig 工厂（同 TCP 面；new 后单属主期调用）
    pub fn with_factory(mut self, factory: Arc<TlsConnectorFactory>) -> Self {
        if let Some(d) = Arc::get_mut(&mut self.dial) {
            d.factory = Some(factory);
        }
        self
    }
}

#[async_trait]
impl EgressUdpConnector for TrustTunnelUdpConnector {
    fn name(&self) -> &str {
        "trusttunnel"
    }

    async fn associate(
        &self,
        _ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, {
            let dial = self.dial.clone();
            async move { dial.connect_stream(PSEUDO_HOST_UDP).await }
        })
        .await
        .context("TrustTunnel _udp2 关联超时")??;

        let pseudo_port = UDP_PSEUDO_PORT.fetch_add(1, Ordering::Relaxed);
        let pseudo = SocketAddr::from((Ipv4Addr::LOCALHOST, pseudo_port));
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(demux_udp_stream(recv, pseudo, tx));
        Ok(Arc::new(TrustTunnelUdpRelay {
            send: Mutex::new(send),
            rx: Mutex::new(rx),
            pseudo_port,
        }))
    }
}

/// 每关联一条 `_udp2` 流的 relay：上行组帧（src = 进程伪源）发流；
/// 下行 demux 任务按 dst == 伪源过滤后回拼（src = 真实应答方）。
/// drop 即发 EOS 收流（端点释放 4 元组）。
struct TrustTunnelUdpRelay {
    send: Mutex<SendStream<Bytes>>,
    rx: Mutex<mpsc::Receiver<(FlowTarget, Vec<u8>)>>,
    pseudo_port: u16,
}

impl TrustTunnelUdpRelay {
    fn pseudo_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.pseudo_port))
    }
}

impl Drop for TrustTunnelUdpRelay {
    fn drop(&mut self) {
        // EOS = 流关闭即连接拆除（spec §5.4 graceful）——端点释放 4 元组
        if let Ok(mut send) = self.send.try_lock() {
            let _ = send.send_data(Bytes::new(), true);
        }
    }
}

#[async_trait]
impl UdpRelay for TrustTunnelUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let frame =
            build_udp_upstream_frame(&self.pseudo_addr(), target, buf).with_context(|| {
                format!(
                    "TrustTunnel UDP 上行组帧失败: {}:{}",
                    target.host, target.port
                )
            })?;
        let mut send = self.send.lock().await;
        h2_send_all(&mut send, Bytes::from(frame)).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let (target, data) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .context("TrustTunnel UDP relay 已关闭")?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((target, n))
    }
}

/// h2 流写全（按容量授予分帧——h2.rs H2Writer 语义的 async 形）
async fn h2_send_all(send: &mut SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let granted = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("TrustTunnel h2 流已关闭"))?
            .map_err(|e| anyhow!("TrustTunnel h2 容量授予失败: {e}"))?;
        if granted == 0 {
            continue;
        }
        let n = granted.min(data.len());
        send.send_data(data.split_to(n), false)
            .map_err(|e| anyhow!("TrustTunnel h2 写入失败: {e}"))?;
    }
    Ok(())
}

/// `_udp2` 下行 demux：攒包解帧（跨 DATA 帧粘包容容），dst == 本关联
/// 伪源的帧回拼（其余 = 误路由/异关联残留——丢弃），通道关闭即收流。
async fn demux_udp_stream(
    mut recv: RecvStream,
    pseudo: SocketAddr,
    tx: mpsc::Sender<(FlowTarget, Vec<u8>)>,
) {
    let mut acc: Vec<u8> = Vec::new();
    loop {
        match recv.data().await {
            Some(Ok(chunk)) => {
                let n = chunk.len();
                acc.extend_from_slice(&chunk);
                let _ = recv.flow_control().release_capacity(n);
                while let Some((src, dst, payload, consumed)) = parse_udp_downstream_frame(&acc) {
                    acc.drain(..consumed);
                    if dst.host != pseudo.ip().to_string() || dst.port != pseudo.port() {
                        continue; // 非本关联元组——丢弃
                    }
                    if tx.send((src, payload)).await.is_err() {
                        // relay 已 drop（EOS 已随 Drop 发出）——收流
                        return;
                    }
                }
            }
            _ => return, // None = 对端 EOS（流关闭即连接拆除）；Err = 流复位
        }
    }
}

// ---------------------------------------------------------------------------
// 测试：向量钉定（真源 = 官方 PROTOCOL.md v1.0）+ 进程内 TLS 镜像对端
// 全链回环 + 官方端点实机对端（缺席记名跳过）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::{FlowId, TargetProto as TP};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn udp_target(host: &str, port: u16) -> FlowTarget {
        FlowTarget {
            host: host.to_string(),
            port,
            proto: TP::Udp,
        }
    }

    fn make_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
        let (client, outbound_side) = tokio::io::duplex(64 * 1024);
        let flow = Flow {
            id: FlowId::new(),
            target: rillane_core::FlowTarget {
                host: host.to_string(),
                port,
                proto: TP::Tcp,
            },
            io: Box::new(outbound_side),
            metadata: Default::default(),
        };
        (flow, client)
    }

    fn make_udp_ctx(target: FlowTarget) -> (FlowContext, RouteDecision) {
        (
            FlowContext {
                id: FlowId::new(),
                target,
                metadata: Default::default(),
            },
            RouteDecision::direct("tt-test".into()),
        )
    }

    /// ring provider 一次性安装（pool_tls_integration 同法——客户端工厂
    /// 侧 tls.rs 先到先装互尊重）
    fn install_ring_provider() {
        static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALL.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// 镜像服务端 TLS acceptor（rcgen 自签 SAN=localhost + ALPN h2——
    /// 客户端 skip_cert_verify 不校验链；ALPN 须协商 h2）
    fn mirror_tls_acceptor() -> TlsAcceptor {
        use rustls::pki_types::pem::PemObject as _;
        install_ring_provider();
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("证书 PEM 解析");
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("私钥读取");
        let builder = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::CryptoProvider::get_default()
                .expect("provider 已装")
                .clone(),
        )
        .with_safe_default_protocol_versions()
        .expect("协议版本");
        let mut config = builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("服务端证书装配");
        config.alpn_protocols = vec![b"h2".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    /// 进程内 TLS 镜像端点：TLS(ALPN h2) → h2 → CONNECT（校验 method +
    /// 必发头 + 可选 authority 钉定）→ 按 reply_status 应答；200 即裸
    /// 字节回声至 EOS（spec §5 TCP 面镜像）；407/503 即应答后收流。
    async fn spawn_tls_connect_server(
        reply_status: http::StatusCode,
        want_authority: Option<&'static str>,
    ) -> String {
        let acceptor = mirror_tls_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let Ok(tls) = acceptor.accept(socket).await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(tls).await.unwrap();
                    // 连接驱动留 accept 任务（h2.rs 同口径：body.data()
                    // await 期间须有人推进连接）
                    while let Some(req) = conn.accept().await {
                        let (req, mut respond) = req.unwrap();
                        tokio::spawn(async move {
                            assert_eq!(req.method(), http::Method::CONNECT);
                            if let Some(want) = want_authority {
                                // CONNECT 请求的 uri 即 :authority（authority 形）
                                let got = req
                                    .uri()
                                    .authority()
                                    .map(|a| a.as_str().to_string())
                                    .unwrap_or_else(|| req.uri().to_string());
                                assert_eq!(got, want, "CONNECT :authority 钉定");
                            }
                            assert!(req.headers().get("user-agent").is_some(), "user-agent 必发");
                            let auth = req.headers().get("proxy-authorization");
                            assert!(
                                auth.is_some()
                                    && auth.unwrap().to_str().unwrap().starts_with("Basic "),
                                "proxy-authorization: Basic 必发"
                            );
                            let response = http::Response::builder()
                                .status(reply_status)
                                .body(())
                                .unwrap();
                            let mut stream = respond.send_response(response, false).unwrap();
                            if reply_status != http::StatusCode::OK {
                                stream.send_data(Bytes::new(), true).unwrap();
                                return;
                            }
                            let mut body = req.into_body();
                            let mut pending: Bytes = Bytes::new();
                            loop {
                                if pending.is_empty() {
                                    match body.data().await {
                                        Some(Ok(chunk)) => {
                                            let len = chunk.len();
                                            body.flow_control().release_capacity(len).unwrap();
                                            if chunk.is_empty() {
                                                continue;
                                            }
                                            pending = chunk;
                                        }
                                        Some(Err(e)) => panic!("镜像读数据失败: {e}"),
                                        None => break,
                                    }
                                }
                                stream.reserve_capacity(pending.len());
                                let granted =
                                    match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await
                                    {
                                        Some(Ok(n)) => n,
                                        _other => break,
                                    };
                                let n = granted.min(pending.len());
                                stream.send_data(pending.split_to(n), false).unwrap();
                            }
                            stream.send_data(Bytes::new(), true).unwrap();
                        });
                    }
                });
            }
        });
        addr
    }

    /// TCP 面全链回环（TLS 镜像端点）：连接器 forward 全产线路径
    /// （TLS+ALPN h2+h2+CONNECT+200+双向中继）——文本 + 10KB 越帧界
    /// 逐字节还原 + FlowReport 计数对账。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connector_roundtrip_via_tls_mirror() {
        let addr = spawn_tls_connect_server(http::StatusCode::OK, Some("example.com:443")).await;
        let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
        let connector = std::sync::Arc::new(
            TrustTunnelConnector::new(
                "127.0.0.1".into(),
                port,
                "u".into(),
                "p".into(),
                Some("localhost".into()),
                true,
                TlsFingerprint::None,
            )
            .expect("构造"),
        );
        let (flow, mut client) = make_flow("example.com", 443);

        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let task_payload = payload.clone();
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            // join 并行（mieru 镜像回环口径）
            let (report, got) = tokio::join!(fw, async {
                client.write_all(b"tls hello").await.expect("上行写");
                client.write_all(&task_payload).await.expect("上行大块写");
                let mut got = vec![0u8; 9 + task_payload.len()];
                client.read_exact(&mut got).await.expect("下行读");
                drop(client); // 半关（END_STREAM）→ 镜像回完 EOS → forward 收束
                got
            });
            (report, got)
        });
        let (report, got) = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时")
            .expect("join");

        let mut expected = b"tls hello".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(got, expected, "镜像回环逐字节还原（含 10KB 越帧界）");
        let report = report.expect("forward 成功");
        assert_eq!(report.upstream as usize, expected.len(), "上行计数");
        assert_eq!(report.downstream as usize, expected.len(), "下行计数");
    }

    /// 407 认证具名失败族（spec §5.2）：镜像回 407 → forward 具名失败
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connect_407_fail_named() {
        let addr =
            spawn_tls_connect_server(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED, None).await;
        let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
        let connector = TrustTunnelConnector::new(
            "127.0.0.1".into(),
            port,
            "u".into(),
            "wrong".into(),
            Some("localhost".into()),
            true,
            TlsFingerprint::None,
        )
        .expect("构造");
        let (flow, _client) = make_flow("example.com", 443);
        let res = tokio::time::timeout(Duration::from_secs(15), connector.forward(flow))
            .await
            .expect("任务超时（应快速失败而非悬挂）");
        let err = res.expect_err("407 必须失败");
        assert!(
            format!("{err:#}").contains("407"),
            "具名失败（认证族）: {err:#}"
        );
    }

    /// 镜像对端专用：按上行形（§6.3 含 appname）解一条帧——产线只需
    /// 下行形，上行解帧仅测试对端使用。
    fn parse_udp_upstream_probe(frame: &[u8]) -> Option<(FlowTarget, FlowTarget, Vec<u8>)> {
        if frame.len() < 4 {
            return None;
        }
        let body_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        if frame.len() < 4 + body_len || body_len < 38 {
            return None;
        }
        let b = &frame[4..4 + body_len];
        let mut sb = [0u8; 16];
        sb.copy_from_slice(&b[0..16]);
        let sport = u16::from_be_bytes([b[16], b[17]]);
        let mut db = [0u8; 16];
        db.copy_from_slice(&b[18..34]);
        let dport = u16::from_be_bytes([b[34], b[35]]);
        let alen = b[36] as usize;
        if b.len() < 37 + alen {
            return None;
        }
        let src = FlowTarget {
            host: decode_addr16(&sb).to_string(),
            port: sport,
            proto: TargetProto::Udp,
        };
        let dst = FlowTarget {
            host: decode_addr16(&db).to_string(),
            port: dport,
            proto: TargetProto::Udp,
        };
        Some((src, dst, b[37 + alen..].to_vec()))
    }

    /// 进程内 TLS 镜像 `_udp2` 对端：CONNECT _udp2 校验 → 200 → 读一条
    /// 上行帧 → 解析 → 先发异元组残留帧再发真应答帧（spec §6.4 无
    /// appname 形）。
    async fn spawn_tls_udp_peer() -> String {
        let acceptor = mirror_tls_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let Ok(tls) = acceptor.accept(socket).await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(tls).await.unwrap();
                    // 外圈 accept 循环保持连接被并发推进（send_response 仅入队，
                    // HEADERS 帧冲刷依赖连接被 poll——与 TCP 镜像同口径）
                    while let Some(req) = conn.accept().await {
                        let (req, mut respond) = req.unwrap();
                        tokio::spawn(async move {
                            assert_eq!(req.method(), http::Method::CONNECT);
                            assert_eq!(req.uri().to_string(), "_udp2");
                            assert!(req.headers().get("proxy-authorization").is_some());
                            let response = http::Response::builder().status(200).body(()).unwrap();
                            let mut stream = respond.send_response(response, false).unwrap();
                            let mut body = req.into_body();
                            while let Some(Ok(chunk)) = body.data().await {
                                body.flow_control().release_capacity(chunk.len()).unwrap();
                                if let Some((src, dst, payload)) = parse_udp_upstream_probe(&chunk)
                                {
                                    // 异元组残留帧（dst ≠ 伪源端口）——demux 丢弃族
                                    let mut stray = Vec::new();
                                    stray.extend_from_slice(&(38u32).to_be_bytes());
                                    stray.extend_from_slice(&[0u8; 12]);
                                    stray.extend_from_slice(&[10, 0, 0, 1]);
                                    stray.extend_from_slice(&9999u16.to_be_bytes());
                                    stray.extend_from_slice(&[0u8; 12]);
                                    stray.extend_from_slice(&[127, 0, 0, 1]);
                                    stray.extend_from_slice(&65001u16.to_be_bytes());
                                    stray.extend_from_slice(b"zz");
                                    // 真应答帧：src = 应答方（原 dst）、dst = 伪源（原 src）
                                    let mut back = Vec::new();
                                    back.extend_from_slice(
                                        &((36 + payload.len()) as u32).to_be_bytes(),
                                    );
                                    back.extend_from_slice(&encode_addr16(&dst.host).unwrap());
                                    back.extend_from_slice(&dst.port.to_be_bytes());
                                    back.extend_from_slice(&encode_addr16(&src.host).unwrap());
                                    back.extend_from_slice(&src.port.to_be_bytes());
                                    back.extend_from_slice(&payload);
                                    stream.send_data(Bytes::from(stray), false).unwrap();
                                    stream.send_data(Bytes::from(back), false).unwrap();
                                    break;
                                }
                            }
                            // 连接驱动持续推进到对端收完
                            while body.data().await.is_some() {}
                        });
                    }
                });
            }
        });
        addr
    }

    /// UDP 面全链回环（TLS 镜像 `_udp2` 对端）：连接器 associate 全产线
    /// 路径——异元组帧丢弃 + 真应答回拼（src = 应答方、proto = Udp）
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn udp_relay_roundtrip_via_tls_mirror() {
        let addr = spawn_tls_udp_peer().await;
        let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
        let connector = TrustTunnelUdpConnector::new(
            "127.0.0.1".into(),
            port,
            "u".into(),
            "p".into(),
            Some("localhost".into()),
            true,
            TlsFingerprint::None,
        )
        .expect("构造");
        let (ctx, decision) = make_udp_ctx(udp_target("192.0.2.53", 53));
        let relay = connector.associate(ctx, &decision).await.expect("关联");

        relay
            .send_to(&udp_target("192.0.2.1", 53), b"dns-probe")
            .await
            .expect("上行");
        let mut buf = [0u8; 2048];
        let (src, n) = tokio::time::timeout(Duration::from_secs(10), relay.recv_from(&mut buf))
            .await
            .expect("回拼超时")
            .expect("relay 关闭");
        assert_eq!(src.host, "192.0.2.1", "回拼 src = 真实应答方");
        assert_eq!(src.port, 53);
        assert_eq!(src.proto, TP::Udp);
        assert_eq!(&buf[..n], b"dns-probe", "异元组帧须已丢弃、真应答回拼");
    }

    /// authority 向量（spec §11.3 三形 + 注入拒绝）
    #[test]
    fn authority_format_vectors() {
        assert_eq!(
            trusttunnel_authority("example.com", 443).unwrap(),
            "example.com:443"
        );
        assert_eq!(
            trusttunnel_authority("192.0.2.1", 443).unwrap(),
            "192.0.2.1:443"
        );
        assert_eq!(
            trusttunnel_authority("2001:db8::1", 443).unwrap(),
            "[2001:db8::1]:443"
        );
        assert!(trusttunnel_authority("", 443).is_err());
        assert!(trusttunnel_authority("evil.com\r\nX:1", 443).is_err());
        assert!(trusttunnel_authority("a b.com", 443).is_err());
        assert!(trusttunnel_authority("user@host", 443).is_err());
    }

    /// Basic 凭据向量（spec §9.1 形）
    #[test]
    fn basic_credentials_vector() {
        assert_eq!(
            basic_credentials("username", "password"),
            "dXNlcm5hbWU6cGFzc3dvcmQ="
        );
        assert_eq!(basic_credentials("u", "p"), "dTpw");
    }

    /// UDP 上行组帧向量（spec §6.3 字段逐字节：v4 零填充 + appname + 载荷）
    #[test]
    fn udp_upstream_frame_vector() {
        let src = SocketAddr::from((Ipv4Addr::LOCALHOST, 40001));
        let frame = build_udp_upstream_frame(&src, &udp_target("192.0.2.1", 53), b"hello").unwrap();
        // body = 16(src) + 2 + 16(dst) + 2 + 1 + 7("rillane") + 5 = 49
        assert_eq!(&frame[0..4], &49u32.to_be_bytes());
        assert_eq!(&frame[4..16], &[0u8; 12]);
        assert_eq!(&frame[16..20], &[127, 0, 0, 1]);
        assert_eq!(&frame[20..22], &40001u16.to_be_bytes());
        assert_eq!(&frame[22..34], &[0u8; 12]);
        assert_eq!(&frame[34..38], &[192, 0, 2, 1]);
        assert_eq!(&frame[38..40], &53u16.to_be_bytes());
        assert_eq!(frame[40], 7);
        assert_eq!(&frame[41..48], b"rillane");
        assert_eq!(&frame[48..], b"hello");
        assert_eq!(frame.len(), 4 + 49);
    }

    /// UDP 下行解帧向量（spec §6.4 无 appname；半包容忍 + 粘包逐帧消费）
    #[test]
    fn udp_downstream_frame_vector() {
        let mut f = Vec::new();
        let body_len = 36 + 3;
        f.extend_from_slice(&(body_len as u32).to_be_bytes());
        f.extend_from_slice(&[0u8; 12]);
        f.extend_from_slice(&[192, 0, 2, 1]);
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&[0u8; 12]);
        f.extend_from_slice(&[127, 0, 0, 1]);
        f.extend_from_slice(&40001u16.to_be_bytes());
        f.extend_from_slice(b"abc");
        let (src, dst, payload, consumed) = parse_udp_downstream_frame(&f).unwrap();
        assert_eq!(src.host, "192.0.2.1");
        assert_eq!(src.port, 53);
        assert_eq!(src.proto, TP::Udp);
        assert_eq!(dst.host, "127.0.0.1");
        assert_eq!(dst.port, 40001);
        assert_eq!(payload, b"abc");
        assert_eq!(consumed, f.len());

        // 半包：截断载荷 → None
        assert!(parse_udp_downstream_frame(&f[..f.len() - 1]).is_none());
        // 粘包：两连帧逐帧消费
        let mut two = f.clone();
        two.extend_from_slice(&f);
        let mut acc: &[u8] = &two;
        let mut count = 0;
        while let Some((_, _, _, consumed)) = parse_udp_downstream_frame(acc) {
            acc = &acc[consumed..];
            count += 1;
        }
        assert_eq!(count, 2);
        assert!(acc.is_empty());
    }

    /// v6 判定（spec §11.2 detection：首 12B 全零且非 ::1 判 v4）
    #[test]
    fn addr16_v6_detection() {
        let v6: [u8; 16] = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(decode_addr16(&v6).to_string(), "2001:db8::1");
        let loopback = Ipv6Addr::LOCALHOST.octets();
        assert_eq!(decode_addr16(&loopback).to_string(), "::1");
        assert_eq!(encode_addr16("2001:db8::1").unwrap(), v6);
    }

    /// 构建期校验具名拒绝（空用户名/密码/服务器）
    #[test]
    fn constructor_validations_named_rejects() {
        let fp = TlsFingerprint::None;
        let e = TrustTunnelConnector::new("".into(), 443, "u".into(), "p".into(), None, false, fp)
            .err()
            .unwrap();
        assert!(e.to_string().contains("服务器"));
        let e = TrustTunnelConnector::new(
            "s.example.com".into(),
            443,
            "".into(),
            "p".into(),
            None,
            false,
            fp,
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("用户名"));
        let e = TrustTunnelConnector::new(
            "s.example.com".into(),
            443,
            "u".into(),
            "".into(),
            None,
            false,
            fp,
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("密码"));
    }

    // -------------------------------------------------------------------
    // 官方端点实机对端（本席 /tmp/trusttunnelpeer 常驻，Apache-2.0 预构建
    // 二进制）；缺席记名跳过（mieru mita / snell 同口径）——验收断言以
    // 实机运行为准。
    // -------------------------------------------------------------------

    const TT_PEER_ADDR: (&str, u16) = ("127.0.0.1", 23430);

    async fn tt_peer_ready() -> bool {
        TcpStream::connect(format!("{}:{}", TT_PEER_ADDR.0, TT_PEER_ADDR.1))
            .await
            .is_ok()
    }

    /// 官方端点回环（TCP + UDP）：连接器 → trusttunnel_endpoint
    /// （127.0.0.1:23430，用户 ril119，自签证书 skip-cert-verify）→
    /// 本席回声上游。TCP 文本 + 10KB 逐字节还原 + 计数对账；UDP 关联 +
    /// 单数据报回环。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_official_endpoint_roundtrip() {
        if !tt_peer_ready().await {
            eprintln!("跳过：官方 trusttunnel_endpoint 对端缺席 (127.0.0.1:23430，/tmp/trusttunnelpeer 常驻实例)");
            return;
        }

        // ---- TCP 面 ----
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("回声绑定");
        let echo_addr: SocketAddr = listener.local_addr().expect("回声地址");
        let echo = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let connector = std::sync::Arc::new(
            TrustTunnelConnector::new(
                TT_PEER_ADDR.0.into(),
                TT_PEER_ADDR.1,
                "ril119".into(),
                "ril119-pass-2026".into(),
                Some("localhost".into()),
                true, // 官方端点自签证书面
                TlsFingerprint::None,
            )
            .expect("构造"),
        );
        let (flow, mut client) = make_flow(&echo_addr.ip().to_string(), echo_addr.port());

        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let task_payload = payload.clone();
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            let (report, got) = tokio::join!(fw, async {
                client.write_all(b"official hello").await.expect("上行写");
                client.write_all(&task_payload).await.expect("上行大块写");
                let mut got = vec![0u8; 14 + task_payload.len()];
                // 30s/45s：全仓并行 gate 载荷下外部进程 + TLS/h2 拨号链
                // 的余量（mieru 10s/20s 同形，此链更重）
                tokio::time::timeout(Duration::from_secs(30), client.read_exact(&mut got))
                    .await
                    .expect("下行超时（官方对端回放面）")
                    .expect("下行读");
                drop(client);
                got
            });
            (report, got)
        });
        let (report, got) = tokio::time::timeout(Duration::from_secs(45), task)
            .await
            .expect("任务超时（官方对端应答/中继面）")
            .expect("join");
        drop(echo);

        let mut expected = b"official hello".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(got, expected, "官方端点回环逐字节还原（含 10KB 越帧界）");
        let report = report.expect("forward 成功");
        assert_eq!(report.upstream as usize, expected.len(), "上行计数");
        assert_eq!(report.downstream as usize, expected.len(), "下行计数");

        // ---- UDP 面 ----
        let udp_conn = TrustTunnelUdpConnector::new(
            TT_PEER_ADDR.0.into(),
            TT_PEER_ADDR.1,
            "ril119".into(),
            "ril119-pass-2026".into(),
            Some("localhost".into()),
            true,
            TlsFingerprint::None,
        )
        .expect("构造");
        let echo_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_udp_addr = echo_udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = echo_udp.recv_from(&mut buf).await else {
                    return;
                };
                let _ = echo_udp.send_to(&buf[..n], from).await;
            }
        });
        let (ctx, decision) = make_udp_ctx(udp_target(
            &echo_udp_addr.ip().to_string(),
            echo_udp_addr.port(),
        ));
        let relay = udp_conn.associate(ctx, &decision).await.expect("UDP 关联");
        relay
            .send_to(
                &udp_target(&echo_udp_addr.ip().to_string(), echo_udp_addr.port()),
                b"official-udp",
            )
            .await
            .expect("UDP 上行");
        let mut buf = [0u8; 2048];
        let (src, n) = tokio::time::timeout(Duration::from_secs(30), relay.recv_from(&mut buf))
            .await
            .expect("UDP 回拼超时")
            .expect("UDP relay 关闭");
        assert_eq!(src.host, echo_udp_addr.ip().to_string());
        assert_eq!(src.port, echo_udp_addr.port());
        assert_eq!(&buf[..n], b"official-udp");
    }
}
