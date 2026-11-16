//! Hysteria2 出口连接器实现
//!
//! TCP/UDP 两面皆自写（RIL-138 起统一）：QUIC 链路建立 + 官方 HTTP/3 /auth
//! 认证面（状态码 233 + Hysteria-UDP 声明）+ 线格式镜像——TCPRequest/
//! TCPResponse（vendored hysteria2 crate 与官方 Go 服务端互验的客户端线
//! 格式）、UDPMessage（apernet/hysteria PROTOCOL.md §UDP，留证
//! protocol-backends.md#hysteria2）。vendored crate 的 connect() 不回持
//! Endpoint（HysteriaClient 仅持 Connection，endpoint 局部变量随 connect
//! 返回 Drop → quinn Endpoint 收束连带全部连接），其 TCP 面端到端即死——
//! 自写面以 RetainedConn 保活端点句柄规避。

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{mpsc, Mutex};

/// 连接建立（DNS 解析 + QUIC 握手 + HTTP/3 认证）超时上限（P2 深审
/// 2026-11-03）。连接缓存有意 single-flight（防连接风暴），但无超时则挂起
/// 拨号会永久钉住全部该出站流；此上限令挂起握手在超时后失败释放互斥，
/// 后续调用可重试。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// 保活的 QUIC 连接 + 端点句柄（端点绝不可先于连接 Drop——quinn Endpoint
/// 全句柄收束即关闭其上全部连接）
pub(crate) struct RetainedConn {
    pub conn: quinn::Connection,
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
}

/// Hysteria2 出口连接器
pub struct Hysteria2Connector {
    server: String,
    port: u16,
    password: String,
    /// 端口跳跃区间（语义同 UDP 面：接受不消费——端口跳跃归 crate 面已死，
    /// 自写面不交付；字段保形使 API/订阅映射零改动）
    #[allow(dead_code)]
    mport: Option<String>,
    obfs: Option<String>,
    obfs_param: Option<String>,
    server_name: Option<String>,
    skip_cert_verify: bool,
    alpn: Option<Vec<String>>,
    conn: Mutex<Option<RetainedConn>>,
}

impl Hysteria2Connector {
    /// 参数面镜像 `EgressConfig::Hysteria2` 字段 1:1，不收敛 options 结构
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        password: String,
        mport: Option<String>,
        obfs: Option<String>,
        obfs_param: Option<String>,
        server_name: Option<String>,
        skip_cert_verify: bool,
        alpn: Option<Vec<String>>,
    ) -> Self {
        Self {
            server,
            port,
            password,
            mport,
            obfs,
            obfs_param,
            server_name,
            skip_cert_verify,
            alpn,
            conn: Mutex::new(None),
        }
    }

    fn validate_config(&self) -> Result<()> {
        if self.obfs.is_some() || self.obfs_param.is_some() {
            return Err(anyhow!(
                "Hysteria2 暂不支持 obfs/obfs_param（自写面与 salamander 不组合）"
            ));
        }
        if let Some(alpn) = &self.alpn {
            // Hysteria2 认证握手基于 HTTP/3，ALPN 至少需要包含 h3。
            if !alpn.iter().any(|p| p == "h3") {
                return Err(anyhow!("Hysteria2 alpn 必须包含 \"h3\""));
            }
        }
        Ok(())
    }

    async fn connect_conn(&self) -> Result<RetainedConn> {
        self.validate_config()?;
        let link = tokio::time::timeout(
            CONNECT_TIMEOUT,
            establish_quic_link(
                &self.server,
                self.port,
                &self.password,
                self.server_name.as_deref(),
                self.skip_cert_verify,
                false,
            ),
        )
        .await
        .map_err(|_| anyhow!("Hysteria2 连接建立超时（{}s）", CONNECT_TIMEOUT.as_secs()))??;
        Ok(RetainedConn {
            conn: link.conn,
            endpoint: link.endpoint,
        })
    }

    async fn get_or_connect_conn(&self) -> Result<RetainedConn> {
        self.validate_config()?;
        let mut guard = self.conn.lock().await;
        if let Some(retained) = guard.as_ref() {
            return Ok(RetainedConn {
                conn: retained.conn.clone(),
                endpoint: retained.endpoint.clone(),
            });
        }

        // 持锁跨握手（single-flight 语义），但加显式超时：超时则释放互斥、
        // 不缓存半成品（fail-closed），后续调用可重新尝试。
        let retained = self.connect_conn().await?;
        *guard = Some(RetainedConn {
            conn: retained.conn.clone(),
            endpoint: retained.endpoint.clone(),
        });
        Ok(retained)
    }

    async fn invalidate_conn(&self) {
        let mut guard = self.conn.lock().await;
        *guard = None;
    }
}

/// 建立 QUIC 链路并完成 HTTP/3 认证（TCP/UDP 两面共用的链路面；端点句柄
/// 由调用方 RetainedConn/Hysteria2UdpRelay 保活）。`require_udp`：UDP 中继
/// 面须服务端显式声明 Hysteria-UDP: true 才可用；TCP 面与此声明无关
/// （官方客户端 TCP 通路不看该声明）。
pub(crate) async fn establish_quic_link(
    server: &str,
    port: u16,
    password: &str,
    server_name: Option<&str>,
    skip_cert_verify: bool,
    require_udp: bool,
) -> Result<RetainedConn> {
    let server_name = server_name.unwrap_or(server);
    let server_addr: SocketAddr = tokio::net::lookup_host((server, port))
        .await
        .with_context(|| format!("Hysteria2 服务器地址解析失败: {server}"))?
        .next()
        .ok_or_else(|| anyhow!("Hysteria2 服务器地址解析为空: {server}"))?;

    // QUIC 端点：ALPN h3（认证面 HTTP/3），证书校验口径两面一致
    let provider = crate::tls::tls_crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?;
    let mut crypto = if skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)
        .context("Hysteria2 QUIC 端点创建失败")?;
    let quinn_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow!("Hysteria2 QUIC TLS 配置失败: {e}"))?,
    ));
    endpoint.set_default_client_config(quinn_cfg);

    let connecting = endpoint
        .connect(server_addr, server_name)
        .context("Hysteria2 QUIC 连接发起失败")?;
    let conn = tokio::time::timeout(UDP_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            anyhow!(
                "Hysteria2 QUIC 握手超时（{}s）",
                UDP_CONNECT_TIMEOUT.as_secs()
            )
        })?
        .context("Hysteria2 QUIC 连接失败")?;

    tokio::time::timeout(UDP_CONNECT_TIMEOUT, h3_auth(&conn, password, require_udp))
        .await
        .map_err(|_| anyhow!("Hysteria2 认证超时（{}s）", UDP_CONNECT_TIMEOUT.as_secs()))?
        .context("Hysteria2 认证失败")?;

    Ok(RetainedConn { conn, endpoint })
}

// ===== TCPRequest/TCPResponse 线格式（vendored crate 互验的客户端面，自写） =====

/// TCPRequest：[varint 0x401][varint addr_len][addr][varint pad_len（恒 0）]
/// （vendored protocol/tcp_request.rs 口径；padding 语义仅混淆，客户端恒 0）
pub(crate) fn tcp_request_wire(address: &str) -> Vec<u8> {
    let mut wire = Vec::with_capacity(address.len() + 8);
    put_varint(&mut wire, 0x401);
    put_varint(&mut wire, address.len() as u64);
    wire.extend_from_slice(address.as_bytes());
    put_varint(&mut wire, 0);
    wire
}

/// QUIC 流上读 varint（入站面共用；vendored protocol/varint.rs 口径：
/// 首字节高 2 位定长档，余字节大端）
pub(crate) async fn read_varint_stream<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64> {
    let mut first = [0u8; 1];
    reader
        .read_exact(&mut first)
        .await
        .context("varint 首字节读取失败")?;
    let len = 1usize << (first[0] >> 6);
    let mut rest = [0u8; 7];
    reader
        .read_exact(&mut rest[..len - 1])
        .await
        .context("varint 余字节读取失败")?;
    let mut value = (first[0] & 0x3f) as u64;
    for byte in &rest[..len - 1] {
        value = (value << 8) | *byte as u64;
    }
    Ok(value)
}

/// TCPResponse：[u8 status][varint msg_len][msg][varint pad_len][pad 丢弃]
/// （vendored protocol/read_tcp_response.rs 口径；status 0 = OK）
pub(crate) async fn read_tcp_response_stream<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(u8, String)> {
    let mut status = [0u8; 1];
    reader
        .read_exact(&mut status)
        .await
        .context("TCP 响应状态字节读取失败")?;
    let msg_len = read_varint_stream(reader).await?;
    if msg_len > u16::MAX as u64 {
        bail!("TCP 响应错误消息超长: {msg_len}");
    }
    let mut msg = vec![0u8; msg_len as usize];
    reader
        .read_exact(&mut msg)
        .await
        .context("TCP 响应错误消息读取失败")?;
    let pad_len = read_varint_stream(reader).await?;
    const PAD_SCRATCH: usize = 4096;
    let mut scratch = [0u8; PAD_SCRATCH];
    let mut remaining = pad_len;
    while remaining > 0 {
        let take = remaining.min(PAD_SCRATCH as u64) as usize;
        reader
            .read_exact(&mut scratch[..take])
            .await
            .context("TCP 响应 padding 读取失败")?;
        remaining -= take as u64;
    }
    Ok((status[0], String::from_utf8_lossy(&msg).into_owned()))
}

/// 在已认证 QUIC 连接上开一条 TCP 双工流（发送 TCPRequest 后读 TCPResponse，
/// 发送侧不 finish——双工面，vendored hysteria_client.rs 同口径）
async fn open_tcp_stream(
    conn: &quinn::Connection,
    address: &str,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = conn.open_bi().await.context("Hysteria2 QUIC 流打开失败")?;
    send.write_all(&tcp_request_wire(address))
        .await
        .context("Hysteria2 TCP 请求发送失败")?;
    let (status, msg) = read_tcp_response_stream(&mut recv)
        .await
        .context("Hysteria2 TCP 响应读取失败")?;
    if status != 0 {
        return Err(anyhow!("Hysteria2 服务端拒绝 TCP 请求: {msg}"));
    }
    Ok((send, recv))
}

/// quinn 双工流桥接 tokio AsyncRead/AsyncWrite（入站面共用——QUIC 流搬运
/// 归 copy_bidirectional 的统一桥）
pub(crate) struct QuicDuplex {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl AsyncRead for QuicDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // quinn RecvStream 固有 poll_read_buf 与 tokio 惯例同构（ReadError → io::Error）
        std::task::ready!(self.get_mut().recv.poll_read_buf(cx, buf))
            .map_err(std::io::Error::from)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for QuicDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // quinn SendStream 固有 poll_write（WriteError → io::Error）遮蔽 trait 同名
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().send.finish().map_err(std::io::Error::from))
    }
}

#[async_trait]
impl EgressConnector for Hysteria2Connector {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            other => {
                return Err(anyhow!("Hysteria2 暂仅支持 TCP 转发（got {:?}）", other));
            }
        }

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_addr = format!("{}:{}", self.server, self.port);

        tracing::debug!(
            target: "rillane::hysteria2",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            "通过 Hysteria2 连接"
        );

        let retained = self.get_or_connect_conn().await?;
        let mut outbound = match open_tcp_stream(&retained.conn, &target).await {
            Ok((send, recv)) => QuicDuplex { send, recv },
            Err(err) => {
                tracing::warn!(
                    target: "rillane::hysteria2",
                    id = %flow.id.as_uuid(),
                    %target,
                    server = %server_addr,
                    error = %err,
                    "Hysteria2 tcp_connect 失败，尝试重连并重试"
                );

                self.invalidate_conn().await;
                let retained = self.get_or_connect_conn().await?;
                let (send, recv) = open_tcp_stream(&retained.conn, &target)
                    .await
                    .with_context(|| format!("Hysteria2 tcp_connect 失败: {}", target))?;
                QuicDuplex { send, recv }
            }
        };

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut outbound,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ===== RIL-133：Hysteria2 UDP 中继面（官方数据报协议，自写） =====

/// QUIC 数据报排空/收组超时：分片丢失按超时整包废弃（spec §Fragmentation）
const FRAG_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
/// QUIC 握手 + HTTP/3 认证整体超时（与 TCP 面 CONNECT_TIMEOUT 同口径）
const UDP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// send_datagram_wait 背压上限（QUIC 数据报缓冲满时等待，超时判连接不可用）
pub(crate) const DGRAM_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// 下行重装配输出队列深度（会话表 forwarder 消费）
const DOWNLINK_QUEUE: usize = 64;

/// Hysteria2 UDP 出站连接器（RIL-133）。hysteria2 crate 无数据报公开 API
/// （仅 TCP connect/DuplexStream，留证 protocol-backends.md#hysteria2），
/// 按官方 PROTOCOL.md §UDP 自写：QUIC 不可靠数据报承载 UDPMessage，
/// 认证复用官方 HTTP/3 /auth 面。
pub struct Hysteria2UdpConnector {
    server: String,
    port: u16,
    password: String,
    server_name: Option<String>,
    skip_cert_verify: bool,
    alpn: Option<Vec<String>>,
}

impl Hysteria2UdpConnector {
    /// 与 TCP 面同一份节点配置（from_connector 语义，见 shadowsocks 同例）
    pub fn from_connector(conn: &Hysteria2Connector) -> Self {
        Self {
            server: conn.server.clone(),
            port: conn.port,
            password: conn.password.clone(),
            server_name: conn.server_name.clone(),
            skip_cert_verify: conn.skip_cert_verify,
            alpn: conn.alpn.clone(),
        }
    }

    /// 构建期校验：obfs 与 TCP 面同口径判负（obfs 换整个 QUIC 载荷，自写面
    /// 不与 salamander 组合）；ALPN 须含 h3（认证面是 HTTP/3）
    fn validate_config(&self) -> Result<()> {
        // obfs 字段不在本结构（from_connector 前置校验归装配面），此处钉 ALPN
        let alpn_ok = match &self.alpn {
            Some(list) => list.iter().any(|p| p == "h3"),
            None => true,
        };
        if !alpn_ok {
            return Err(anyhow!("Hysteria2 alpn 必须包含 \"h3\""));
        }
        Ok(())
    }

    /// 建立 QUIC 连接并完成 HTTP/3 认证（官方 /auth 面：状态码 233 放行，
    /// Hysteria-UDP != true 点名拒绝——服务端不声明 UDP 支持时数据报会被
    /// 静默丢弃，绝不建立哑管道）
    async fn connect_and_auth(&self) -> Result<(quinn::Endpoint, quinn::Connection)> {
        self.validate_config()?;
        let link = establish_quic_link(
            &self.server,
            self.port,
            &self.password,
            self.server_name.as_deref(),
            self.skip_cert_verify,
            true,
        )
        .await?;
        Ok((link.endpoint, link.conn))
    }
}

/// 官方认证面：h3 POST https://hysteria/auth（Hysteria-Auth/CC-RX/Padding），
/// 状态码 233 放行；`require_udp` 时 Hysteria-UDP 须显式 true（官方服务器
/// 不声明 UDP 支持时会静默丢弃数据报，前置点名而非建立哑管道）
async fn h3_auth(conn: &quinn::Connection, password: &str, require_udp: bool) -> Result<()> {
    let (mut h3_conn, mut request_stream) =
        h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .context("Hysteria2 HTTP/3 层建立失败")?;

    let padding = random_padding();
    let req = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Host", "hysteria")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", padding)
        .body(())
        .context("Hysteria2 认证请求构建失败")?;

    let mut stream = request_stream
        .send_request(req)
        .await
        .context("Hysteria2 认证请求发送失败")?;
    stream.finish().await.context("Hysteria2 认证流收束失败")?;
    let resp = stream
        .recv_response()
        .await
        .context("Hysteria2 认证响应接收失败")?;

    // h3 连接保活（wait_idle 驱动控制面处理至 QUIC 连接收束——h3 连接 Drop
    // 会关闭自身控制流，对端按 H3_CLOSED_CRITICAL_STREAM 断链；SendRequest
    // 为连接存活句柄，最后一个实例 Drop 即按 H3_NO_ERROR 关闭整个连接）
    tokio::spawn(async move {
        let _sender = request_stream;
        let _closed = h3_conn.wait_idle().await;
    });

    let status = resp.status();
    if status.as_u16() != 233 {
        return Err(anyhow!(
            "Hysteria2 认证被拒绝（状态码 {}，须 233）——检查密码与服务端配置",
            status.as_u16()
        ));
    }
    let udp_declared = resp
        .headers()
        .get("Hysteria-UDP")
        .and_then(|v| v.to_str().ok())
        == Some("true");
    if require_udp && !udp_declared {
        return Err(anyhow!(
            "Hysteria2 服务端未声明 UDP 支持（Hysteria-UDP != true）——该节点不可用 UDP 中继"
        ));
    }
    Ok(())
}

/// 认证填充串（官方语义：随机长度 8..40 字母数字，仅混淆请求/响应形态）
fn random_padding() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(8..40);
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ---------- UDPMessage 编解码（apernet/hysteria PROTOCOL.md §UDP） ----------

/// QUIC varint（RFC 9000 §16）编码（地址长度字段；会话内地址长 < 2^62）
pub(crate) fn put_varint(buf: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        buf.push(v as u8);
    } else if v < 1 << 14 {
        buf.extend_from_slice(&((0b01 << 14) | v as u16).to_be_bytes());
    } else if v < 1 << 30 {
        buf.extend_from_slice(&((0b10 << 30) | v as u32).to_be_bytes());
    } else {
        buf.extend_from_slice(&((0b11u64 << 62) | v).to_be_bytes());
    }
}

/// 解析后的 UDPMessage（会话/分片头 + 地址 + 载荷切片）
type ParsedUdpMessage<'a> = (u32, u16, u8, u8, String, &'a [u8]);

/// 解析数据报为 (session_id, packet_id, frag_id, frag_count, addr, payload)
pub(crate) fn parse_udp_message(buf: &[u8]) -> Option<ParsedUdpMessage<'_>> {
    if buf.len() < 8 {
        return None;
    }
    let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_id = buf[6];
    let frag_count = buf[7];
    let (addr_len, addr_len_bytes) = get_varint(&buf[8..])?;
    let addr_start = 8 + addr_len_bytes;
    let addr_end = addr_start.checked_add(addr_len as usize)?;
    if addr_end > buf.len() {
        return None;
    }
    let addr = String::from_utf8_lossy(&buf[addr_start..addr_end]).into_owned();
    Some((
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr,
        &buf[addr_end..],
    ))
}

/// QUIC varint 解码，返回 (值, 字节数)
fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    match first >> 6 {
        0 => Some((first as u64, 1)),
        1 => {
            if buf.len() >= 2 {
                Some(((u16::from_be_bytes([first, buf[1]]) & 0x3FFF) as u64, 2))
            } else {
                None
            }
        }
        2 => {
            if buf.len() >= 4 {
                Some((
                    (u32::from_be_bytes([first, buf[1], buf[2], buf[3]]) & 0x3FFF_FFFF) as u64,
                    4,
                ))
            } else {
                None
            }
        }
        _ => {
            if buf.len() >= 8 {
                Some((
                    u64::from_be_bytes([
                        first & 0x3F,
                        buf[1],
                        buf[2],
                        buf[3],
                        buf[4],
                        buf[5],
                        buf[6],
                        buf[7],
                    ]),
                    8,
                ))
            } else {
                None
            }
        }
    }
}

/// 编码 UDPMessage（同一 packet 的分片各自携带完整头 + 地址，官方同构）
pub(crate) fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 5 + addr.len() + payload.len());
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.push(frag_id);
    buf.push(frag_count);
    put_varint(&mut buf, addr.len() as u64);
    buf.extend_from_slice(addr.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// 地址串 "host:port" → FlowTarget（IPv6 字面量按最后一个冒号劈分）
pub(crate) fn flow_target_of_addr(addr: &str) -> Result<FlowTarget> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("Hysteria2 数据报地址缺端口: {addr}"))?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("Hysteria2 数据报地址端口非法: {addr}"))?;
    Ok(FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Udp,
    })
}

// ---------- 分片重装配（下行） ----------

/// packet_id → (frag_count, frag_id → 分片载荷, 首片落位时刻)
type FragParts = (u8, BTreeMap<u8, Vec<u8>>, Instant);

#[derive(Default)]
pub(crate) struct Reassembler {
    parts: BTreeMap<u16, FragParts>,
}

impl Reassembler {
    /// 推入一个分片；完整则返回拼接载荷。丢失分片按超时整包废弃并计数。
    pub(crate) fn push(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        payload: &[u8],
        dropped: &AtomicU64,
    ) -> Option<Vec<u8>> {
        // 超时废弃滞留分片（防丢片撑爆会话内存）
        let now = Instant::now();
        self.parts
            .retain(|_, (_, _, born)| now.duration_since(*born) < FRAG_REASSEMBLY_TIMEOUT);
        if self.parts.len() > 256 {
            // 重装配表硬上限：溢出时整体清空并计数（病态流量下自保护）
            dropped.fetch_add(self.parts.len() as u64, Ordering::Relaxed);
            self.parts.clear();
        }

        if frag_count == 0 {
            return None; // 非法：frag_count 至少 1
        }
        if frag_id >= frag_count {
            return None;
        }
        if frag_count == 1 {
            return Some(payload.to_vec());
        }
        let entry = self
            .parts
            .entry(packet_id)
            .or_insert_with(|| (frag_count, BTreeMap::new(), Instant::now()));
        entry.1.insert(frag_id, payload.to_vec());
        if entry.1.len() == entry.0 as usize {
            let (_, frags, _) = self.parts.remove(&packet_id)?;
            let mut whole = Vec::with_capacity(frags.values().map(|f| f.len()).sum());
            for piece in frags.values() {
                whole.extend_from_slice(piece);
            }
            return Some(whole);
        }
        None
    }
}

/// 会话级下行统计（验收面：分片丢失/外来会话可观测）
#[derive(Default)]
pub struct UdpSessionStats {
    /// 外来会话数据报（session 不匹配，静默丢弃计数）
    pub foreign_dropped: AtomicU64,
    /// 整包废弃的分片/包计数（超时滞留、溢出清空、非法分片头）
    pub frag_dropped: AtomicU64,
}

/// 字节级 Hysteria2 UDP 中继：QUIC 连接 + 固定 session + 下行重装配任务
pub struct Hysteria2UdpRelay {
    /// 仅持句柄：保活 QUIC 端点（Drop 时全部关联连接随之收束）
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    session_id: u32,
    /// 会话默认目标（R7 固定目标语义；数据报协议头逐包携带，发送以参数为准）
    _fixed_target: FlowTarget,
    max_dgram: usize,
    addr_prefix_cache: StdMutex<BTreeMap<String, usize>>,
    packet_id: StdMutex<u16>,
    stats: Arc<UdpSessionStats>,
    /// 下行队列（tokio Mutex：UdpRelay::recv_from 是 &self 面）
    downlink: Mutex<mpsc::Receiver<(FlowTarget, Vec<u8>)>>,
    downlink_task: tokio::task::JoinHandle<()>,
}

impl Hysteria2UdpRelay {
    /// 会话统计句柄（验收面：取消/资源释放与分片丢弃计数可观测）
    pub fn stats(&self) -> &Arc<UdpSessionStats> {
        &self.stats
    }

    fn header_len(addr_len: usize) -> usize {
        // 4(session) + 2(packet) + 1(frag_id) + 1(frag_count) + varint(addr_len) + addr_len
        // varint 字节数按 RFC 9000 §16（前缀 2 位 + 6/14/30/62 位值域）
        8 + if addr_len < 1 << 6 {
            1
        } else if addr_len < 1 << 14 {
            2
        } else if addr_len < 1 << 30 {
            4
        } else {
            8
        } + addr_len
    }

    fn addr_of(target: &FlowTarget) -> String {
        format!("{}:{}", target.host, target.port)
    }

    fn next_packet_id(&self) -> u16 {
        let mut guard = self.packet_id.lock().unwrap();
        let id = *guard;
        *guard = guard.wrapping_add(1);
        id
    }
}

#[async_trait]
impl UdpRelay for Hysteria2UdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let addr = Self::addr_of(target);
        let overhead = {
            let mut cache = self.addr_prefix_cache.lock().unwrap();
            *cache
                .entry(addr.clone())
                .or_insert_with(|| Self::header_len(addr.len()))
        };
        let max_dgram = self.max_dgram;

        // 单包直发（官方口径 frag_count=1；Packet ID/Fragment ID 值不相关）
        if buf.len() + overhead <= max_dgram {
            let msg = encode_udp_message(self.session_id, self.next_packet_id(), 0, 1, &addr, buf);
            self.send_datagram(msg).await?;
            return Ok(());
        }

        // 分片：同一 Packet ID，Fragment ID 0..count（官方 §Fragmentation）
        let per_frag = max_dgram.saturating_sub(overhead);
        if per_frag == 0 {
            return Err(anyhow!(
                "Hysteria2 QUIC 数据报过小（{max_dgram}B），无法承载 UDP 分片头"
            ));
        }
        let count = buf.len().div_ceil(per_frag);
        if count > u8::MAX as usize {
            return Err(anyhow!(
                "Hysteria2 UDP 载荷过大（{}B，需 {count} 分片 > 255 上限）",
                buf.len()
            ));
        }
        let packet_id = self.next_packet_id();
        for (frag_id, chunk) in buf.chunks(per_frag).enumerate() {
            let msg = encode_udp_message(
                self.session_id,
                packet_id,
                frag_id as u8,
                count as u8,
                &addr,
                chunk,
            );
            self.send_datagram(msg).await?;
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut rx = self.downlink.lock().await;
        let (target, payload) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("Hysteria2 UDP 中继已关闭（QUIC 连接断开）"))?;
        if payload.len() > buf.len() {
            return Err(anyhow!(
                "Hysteria2 UDP 下行载荷 {}B 超过接收缓冲 {}B",
                payload.len(),
                buf.len()
            ));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((target, payload.len()))
    }
}

impl Hysteria2UdpRelay {
    async fn send_datagram(&self, msg: Vec<u8>) -> Result<()> {
        let wait = self.conn.send_datagram_wait(Bytes::from(msg));
        match tokio::time::timeout(DGRAM_SEND_TIMEOUT, wait).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(anyhow!("Hysteria2 QUIC 数据报发送失败: {e}")),
            Err(_) => Err(anyhow!(
                "Hysteria2 QUIC 数据报缓冲满超时（{}s）——连接不可用",
                DGRAM_SEND_TIMEOUT.as_secs()
            )),
        }
    }
}

impl Drop for Hysteria2UdpRelay {
    fn drop(&mut self) {
        // QUIC 连接随 relay 生命周期收束（资源释放面：对端可观 propagate close）
        self.conn.close(0u32.into(), b"hysteria2 udp relay dropped");
        self.downlink_task.abort();
    }
}

impl Hysteria2UdpConnector {
    /// 关联并返回具体中继句柄（验收面：会话统计/分片计数可观测；
    /// trait 面 `associate` 委托此方法）
    pub async fn connect_relay(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<Hysteria2UdpRelay>> {
        let (_endpoint, conn) = self.connect_and_auth().await?;

        let max_dgram = conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("Hysteria2 对端不支持 QUIC 数据报（无法承载 UDP 中继）"))?;

        let session_id: u32 = rand::random();
        let stats = Arc::new(UdpSessionStats::default());
        let (tx, rx) = mpsc::channel::<(FlowTarget, Vec<u8>)>(DOWNLINK_QUEUE);

        // 下行任务：读 QUIC 数据报 → 会话过滤 → 重装配 → 投递
        let recv_stats = stats.clone();
        let recv_conn = conn.clone();
        let task = tokio::spawn(async move {
            let mut reassembler = Reassembler::default();
            while let Ok(buf) = recv_conn.read_datagram().await {
                let Some((session, packet_id, frag_id, frag_count, addr, payload)) =
                    parse_udp_message(&buf)
                else {
                    recv_stats.frag_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if session != session_id {
                    recv_stats.foreign_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if let Some(whole) = reassembler.push(
                    packet_id,
                    frag_id,
                    frag_count,
                    payload,
                    &recv_stats.frag_dropped,
                ) {
                    match flow_target_of_addr(&addr) {
                        Ok(target) => {
                            if tx.send((target, whole)).await.is_err() {
                                break; // 中继已 drop
                            }
                        }
                        Err(_) => {
                            recv_stats.frag_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            // Err → 连接关闭/丢失 → 任务收束（资源释放面）
        });

        Ok(Arc::new(Hysteria2UdpRelay {
            endpoint: _endpoint,
            conn,
            session_id,
            _fixed_target: ctx.target,
            max_dgram,
            addr_prefix_cache: StdMutex::new(BTreeMap::new()),
            packet_id: StdMutex::new(0),
            stats,
            downlink: Mutex::new(rx),
            downlink_task: task,
        }))
    }
}

#[async_trait]
impl EgressUdpConnector for Hysteria2UdpConnector {
    fn name(&self) -> &str {
        "hysteria2"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        let relay = self.connect_relay(ctx, decision).await?;
        Ok(relay as Arc<dyn UdpRelay>)
    }
}
