//! MASQUE 出口连接器实现（RIL-120，RFC 9298 CONNECT-UDP / RFC 9114 §4.4 CONNECT）
//!
//! 载具 HTTP/3（QUIC + h3 0.0.8 + h3-quinn 0.0.10，仓内既有依赖零新增）。
//! 评估与验收对端留证 protocol-backends.md#masque（真实对端 = 本地构建的
//! quic-go/masque-go v0.6.0 cmd/proxy，MIT；TCP 面留证对端 = 进程内 h3
//! 镜像对端——masque-go proxy 只注册 URI 模板路径 handler，无通用 CONNECT
//! handler，真机 TCP 面走镜像对端并具名边界）。
//!
//! 线格式钉定（RFC 9298 §3-§5 + RFC 9297 §2.2/§3.3）：
//! - UDP 面：HTTP/3 Extended CONNECT——`:method=CONNECT`、`:protocol=
//!   connect-udp`（h3 `ext::Protocol` 扩展注入）、`:authority`/`:scheme`/
//!   `:path` 取自 URI 模板展开（RFC 6570 simple 展开：IPv6 冒号百分号编码
//!   `2001%3Adb8%3A%3A42`；zone id 不支持——目标 host 含 `%` 具名拒绝）、
//!   请求携 `capsule-protocol: ?1`；2xx 应答 = 关联成功（capsule-protocol
//!   头若在须 `?1`，masque-go 恒发）。数据面走 QUIC DATAGRAM 帧（H3 上
//!   不封 capsule）：载荷 = `varint(Quarter Stream ID) ++ varint(Context
//!   ID=0) ++ 原样 UDP 字节`（Quarter Stream ID = 请求流 ID >> 2，即 h3
//!   `StreamId::index()`）；Context ID 0 保留给 UDP 载荷，异值静默丢弃。
//!   超限数据报（> max_datagram_size）具名拒绝发送（RFC 9297 §2.1 客户端
//!   不得发超限帧）。代理侧 DNS 解析：代理负责，客户端不解析目标。
//! - TCP 面：HTTP/3 CONNECT（无 `:protocol`）——`:authority` = `目标
//!   host:port`（IPv6 方括号），2xx 后请求流即纯目标字节隧道。h3 0.0.8
//!   的 Pseudo::request 对 CONNECT 也强制注入缺省 `:scheme=https`/`:path=/`
//!   （载具怪癖，RFC 9114 §4.4 要求 CONNECT 无此二伪头——镜像对端同载具
//!   互验不受影响，真机 masque-go 无此 handler 归具名边界）。
//! - 套接字生命周期绑定请求流（RFC 9298 §4.1）：每关联一条 QUIC 连接 +
//!   一条 CONNECT-UDP 请求流（无连接复用池——masque-go 客户端共享
//!   ClientConn，本仓按关联独立，线格式等价）；relay Drop → `conn.close`
//!   （对端可观 propagate close，代理释放 UDP 套接字）。
//!
//! 订阅边界（mihomo `type: masque` 是密钥型客户端隧道——CONNECT-IP/L4
//! proxy（private-key/public-key/ip/ipv6/network h3|h2|h3-l4proxy），与
//! 本面（RFC 9298 代理客户端）不同协议族）：导入具名拒绝、导出具名跳过
//! （rillane-subscription 双向样本）。

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

use super::hysteria2::put_varint;

/// 连接建立（DNS 解析 + QUIC 握手 + HTTP/3 设置交换）超时上限（hysteria2
/// 面同口径）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// send_datagram_wait 背压上限（QUIC 数据报缓冲满时等待，超时判连接不可用；
/// hysteria2 面同口径）
const DGRAM_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// 下行投递队列深度（会话表 forwarder 消费；hysteria2 面同口径）
const DOWNLINK_QUEUE: usize = 64;

/// h3 客户端连接/请求句柄具体型（h3-quinn 载具）
type H3ClientSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
/// CONNECT-UDP 请求流（未拆分整流——UDP 面不用流承载数据，仅持活绑定
/// 代理侧套接字生命周期）
type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
/// TCP 隧道拆分后的发送半流
type H3SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
/// TCP 隧道拆分后的接收半流
type H3RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

// ---------------------------------------------------------------------------
// 配置与 URI 模板
// ---------------------------------------------------------------------------

/// MASQUE 出口节点配置（TCP/UDP 两面共用；uri_template 仅 UDP 面消费）
#[derive(Clone)]
struct MasqueConfig {
    server: String,
    port: u16,
    sni: Option<String>,
    skip_cert_verify: bool,
    uri_template: Option<String>,
}

impl MasqueConfig {
    /// 构建期校验：空服务器/零端口/畸形模板具名拒绝（配置错误装配期暴露，
    /// 节点级失败不拖垮整份订阅——与 trusttunnel/hysteria2 同口径）
    fn validate(&self) -> Result<()> {
        if self.server.is_empty() {
            bail!("MASQUE server 不能为空");
        }
        if self.port == 0 {
            bail!("MASQUE port 不能为 0");
        }
        if let Some(t) = &self.uri_template {
            validate_uri_template(t)?;
        }
        Ok(())
    }

    /// 解析本目标的 CONNECT-UDP URI（模板缺省 = RFC 9298 §3.1 缺省模板，
    /// authority 取节点 server:port——与 QUIC 拨号地址一致；显式模板允许
    /// 异于拨号地址的 authority——前置代理/公共域名场景，RFC 不禁）
    fn resolve_uri(&self, target: &FlowTarget) -> Result<String> {
        let template = match &self.uri_template {
            Some(t) => t.clone(),
            None => format!(
                "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                proxy_authority(&self.server, self.port)
            ),
        };
        expand_uri_template(&template, &target.host, target.port)
    }
}

/// 代理/目标 authority（host:port；IPv6 方括号——trusttunnel_authority
/// 同形；注入字符拒绝防伪头注入）
fn proxy_authority(host: &str, port: u16) -> String {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        format!("{v4}:{port}")
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        format!("[{v6}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 模板静态校验（构建期）：须为 https 绝对 URI、含
/// {target_host}/{target_port} 两变量、无其它变量
fn validate_uri_template(template: &str) -> Result<()> {
    let uri: http::Uri = template
        .parse()
        .with_context(|| format!("MASQUE uri_template 非法 URI: {template:?}"))?;
    if uri.scheme_str() != Some("https") {
        bail!(
            "MASQUE uri_template 须为 https（got {:?}）",
            uri.scheme_str()
        );
    }
    if uri.authority().map(|a| a.as_str()).unwrap_or("").is_empty() {
        bail!("MASQUE uri_template 缺 authority");
    }
    if !template.contains("{target_host}") || !template.contains("{target_port}") {
        bail!(
            "MASQUE uri_template 须含 {{target_host}} 与 {{target_port}}（RFC 9298 §3.1）: {template:?}"
        );
    }
    Ok(())
}

/// RFC 6570 simple 展开（仅 unreserved 保留：ALPHA/DIGIT/`-`/`.`/`_`/`~`，
/// 其余百分号编码——IPv6 冒号即 `2001%3Adb8%3A%3A42`）。目标 host 含 `%`
/// 具名拒绝（zone id 不支持，RFC 9298 §3.1；也是未编码残留的畸形信号）。
fn expand_uri_template(template: &str, host: &str, port: u16) -> Result<String> {
    if host.is_empty() {
        bail!("MASQUE target_host 为空");
    }
    if host.contains('%') {
        bail!("MASQUE target_host 含 %（zone id 不支持/畸形）: {host:?}");
    }
    if crate::host_has_injection_chars(host) {
        bail!("MASQUE target_host 含非法字符: {host:?}");
    }
    if !template.contains("{target_host}") || !template.contains("{target_port}") {
        bail!(
            "MASQUE uri_template 须含 {{target_host}} 与 {{target_port}}（RFC 9298 §3.1）: {template:?}"
        );
    }
    let mut encoded = String::with_capacity(host.len());
    for b in host.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(b as char)
            }
            _ => encoded.push_str(&format!("%{b:02X}")),
        }
    }
    let port_str = port.to_string();
    let out = template
        .replace("{target_host}", &encoded)
        .replace("{target_port}", &port_str);
    if out.contains('{') || out.contains('}') {
        bail!("MASQUE uri_template 含未知变量（仅允许 {{target_host}}/{{target_port}}）: {template:?}");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// H3 数据报线格式（RFC 9297 §2.2：varint(qsid) ++ varint(ctx) ++ 载荷）
// ---------------------------------------------------------------------------

/// 编码 HTTP/3 数据报帧载荷（Context ID 0 = UDP 载荷）
fn encode_h3_datagram(qsid: u64, context_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    put_varint(&mut out, qsid);
    put_varint(&mut out, context_id);
    out.extend_from_slice(payload);
    out
}

/// 解码 HTTP/3 数据报帧载荷 → (Quarter Stream ID, Context ID, UDP 载荷)
fn decode_h3_datagram(buf: &[u8]) -> Option<(u64, u64, &[u8])> {
    let (qsid, n1) = read_varint(buf)?;
    let (ctx, n2) = read_varint(&buf[n1..])?;
    Some((qsid, ctx, &buf[n1 + n2..]))
}

/// QUIC varint 解码（RFC 9000 §16；hysteria2 面同口径首字节高 2 位定长档）
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first >> 6 {
        0 => Some((first as u64, 1)),
        1 => {
            let b = buf.get(1).copied()?;
            Some(((u16::from_be_bytes([first, b]) & 0x3FFF) as u64, 2))
        }
        2 => {
            let b: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            Some(((u32::from_be_bytes(b) & 0x3FFF_FFFF) as u64, 4))
        }
        _ => {
            let b: [u8; 8] = buf.get(..8)?.try_into().ok()?;
            Some((u64::from_be_bytes(b) & 0x3FFF_FFFF_FFFF_FFFF, 8))
        }
    }
}

// ---------------------------------------------------------------------------
// H3 链路建立（TCP/UDP 两面共用）
// ---------------------------------------------------------------------------

impl MasqueConfig {
    /// 建立 QUIC + HTTP/3 链路：ALPN h3，extended-connect + datagram 设置
    /// 双开（UDP 面硬需求——masque-go 客户端同检对端声明；TCP 面开着
    /// 无害）。返回 (endpoint, quinn conn, h3 请求句柄)；h3 连接由内部
    /// spawn 的 wait_idle 保活任务持有（h3 连接 Drop 会关闭控制流，对端
    /// 按 H3_CLOSED_CRITICAL_STREAM 断链——hysteria2 h3_auth 同注）
    async fn establish_h3(&self) -> Result<(quinn::Endpoint, quinn::Connection, H3ClientSender)> {
        let server_name = self.sni.as_deref().unwrap_or(&self.server);
        let server_addr: SocketAddr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await
            .with_context(|| format!("MASQUE 代理地址解析失败: {}", self.server))?
            .next()
            .ok_or_else(|| anyhow!("MASQUE 代理地址解析为空: {}", self.server))?;

        // 证书校验口径与 hysteria2 面一致（skip_cert_verify → NoVerifier）
        let provider = crate::tls::tls_crypto_provider();
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?;
        let mut crypto = if self.skip_cert_verify {
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
            .context("MASQUE QUIC 端点创建失败")?;
        let quinn_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| anyhow!("MASQUE QUIC TLS 配置失败: {e}"))?,
        ));
        endpoint.set_default_client_config(quinn_cfg);

        let connecting = endpoint
            .connect(server_addr, server_name)
            .context("MASQUE QUIC 连接发起失败")?;
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| anyhow!("MASQUE QUIC 握手超时（{}s）", CONNECT_TIMEOUT.as_secs()))?
            .context("MASQUE QUIC 连接失败")?;

        let (mut h3_conn, sender) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_quinn::Connection::new(conn.clone()))
            .await
            .context("MASQUE HTTP/3 层建立失败")?;
        tokio::spawn(async move {
            let _closed = h3_conn.wait_idle().await;
        });
        Ok((endpoint, conn, sender))
    }
}

// ---------------------------------------------------------------------------
// TCP 客户端面（HTTP/3 CONNECT 隧道）
// ---------------------------------------------------------------------------

/// MASQUE TCP 出口连接器（RIL-120）：HTTP/3 CONNECT（无 `:protocol`），
/// 2xx 后请求流即纯目标字节隧道。每流一条 QUIC 连接（套接字生命周期
/// 绑定请求流——RFC 9298 同语义；无连接复用池，边界具名）
pub struct MasqueConnector {
    cfg: MasqueConfig,
}

impl MasqueConnector {
    pub fn new(
        server: String,
        port: u16,
        sni: Option<String>,
        skip_cert_verify: bool,
        uri_template: Option<String>,
    ) -> Result<Self> {
        let cfg = MasqueConfig {
            server,
            port,
            sni,
            skip_cert_verify,
            uri_template,
        };
        cfg.validate()?;
        Ok(Self { cfg })
    }

    /// 与 UDP 面同一份节点配置（from_connector 语义）
    fn udp_config(&self) -> MasqueConfig {
        self.cfg.clone()
    }
}

#[async_trait]
impl EgressConnector for MasqueConnector {
    fn name(&self) -> &'static str {
        "masque"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            other => bail!("MASQUE 暂仅支持 TCP 转发（got {:?}）", other),
        }
        let authority = proxy_authority(&flow.target.host, flow.target.port);
        let target_desc = format!("{}:{}", flow.target.host, flow.target.port);

        tracing::debug!(
            target: "rillane::masque",
            %target_desc,
            proxy = %format!("{}:{}", self.cfg.server, self.cfg.port),
            "通过 MASQUE HTTP/3 CONNECT 连接"
        );

        let (_endpoint, _conn, mut sender) = self.cfg.establish_h3().await?;
        // h3 0.0.8 Pseudo::request 对 CONNECT 也注入缺省 :scheme/:path——
        // 载具怪癖（头注）；authority 形 URI 使 :authority 落目标地址
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{authority}/"))
            .body(())
            .context("MASQUE CONNECT 请求构建失败")?;
        let mut stream = sender
            .send_request(req)
            .await
            .context("MASQUE CONNECT 请求发送失败")?;
        let resp = stream
            .recv_response()
            .await
            .context("MASQUE CONNECT 响应接收失败")?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!(
                "MASQUE CONNECT 被代理拒绝（状态码 {}，目标 {target_desc}）",
                status.as_u16()
            ));
        }

        let (mut send_half, mut recv_half) = stream.split();
        let (mut reader, mut writer) = tokio::io::split(flow.io);
        let (up, down) =
            relay_h3_tunnel(&mut reader, &mut writer, &mut send_half, &mut recv_half).await?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

/// TCP 隧道双向搬运：上行 flow.io → h3 发送半流（EOF → `finish()` 即对端
/// 可观 FIN）；下行 h3 接收半流 → flow.io（EOF → `shutdown()` 即客户端
/// 可观收束）。任一向出错即收束另一向（错误经 `r?` 即时上抛，未完成向
/// 的 future 随之取消——copy_bidirectional 错误面同语义）；干净 EOF 则
/// 经关闭传播等另一向自然完成（半关语义）。h3 0.0.8 请求流无 poll 面写
/// API（仅 async send_data），故手写而非 AsyncWrite 适配。
async fn relay_h3_tunnel<R, W>(
    reader: &mut R,
    writer: &mut W,
    send_half: &mut H3SendHalf,
    recv_half: &mut H3RecvHalf,
) -> Result<(u64, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let up = async {
        let mut total = 0u64;
        let mut buf = vec![0u8; rillane_core::performance::relay_buffer()];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    // 客户端侧已破——停流告知代理（best-effort）
                    send_half.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    return Err(anyhow::Error::new(e).context("MASQUE 上行读取失败"));
                }
            };
            if n == 0 {
                break;
            }
            if let Err(e) = send_half.send_data(Bytes::copy_from_slice(&buf[..n])).await {
                send_half.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                return Err(anyhow::Error::new(e)
                    .context(format!("MASQUE 上行发送失败（已传 {total} 字节）")));
            }
            total += n as u64;
        }
        send_half
            .finish()
            .await
            .context("MASQUE 上行收束（finish）失败")?;
        Ok::<u64, anyhow::Error>(total)
    };
    let down = async {
        let mut total = 0u64;
        while let Some(mut chunk) = recv_half.recv_data().await.context("MASQUE 下行接收失败")?
        {
            while chunk.has_remaining() {
                let n = writer
                    .write(chunk.chunk())
                    .await
                    .context("MASQUE 下行写入失败（客户端侧收束，代理隧道随连接关闭释放）")?;
                if n == 0 {
                    bail!("MASQUE 下行写入零字节");
                }
                let adv = n.min(chunk.remaining());
                chunk.advance(adv);
                total += adv as u64;
            }
        }
        writer
            .shutdown()
            .await
            .context("MASQUE 下行关闭（shutdown）失败")?;
        Ok::<u64, anyhow::Error>(total)
    };

    tokio::pin!(up);
    tokio::pin!(down);
    let mut up_done = false;
    let mut down_done = false;
    let mut up_total = 0u64;
    let mut down_total = 0u64;
    while !(up_done && down_done) {
        tokio::select! {
            r = &mut up, if !up_done => {
                up_done = true;
                up_total = r?;
            }
            r = &mut down, if !down_done => {
                down_done = true;
                down_total = r?;
            }
        }
    }
    Ok((up_total, down_total))
}

// ---------------------------------------------------------------------------
// UDP 客户端面（RFC 9298 CONNECT-UDP + H3 数据报）
// ---------------------------------------------------------------------------

/// MASQUE UDP 中继统计（验收面：成功/取消/丢弃可观测）
#[derive(Default)]
pub struct MasqueUdpStats {
    /// 上行数据报发送计数
    pub datagrams_sent: AtomicU64,
    /// 下行数据报投递计数（recv_from 成功投递后）
    pub datagrams_recv: AtomicU64,
    /// 丢弃计数（qsid/ctx 不匹配、帧畸形）
    pub datagrams_dropped: AtomicU64,
}

/// 字节级 MASQUE UDP 中继：QUIC 连接 + CONNECT-UDP 请求流 + 下行 demux
/// 任务（套接字生命周期绑定请求流——RFC 9298 §4.1）
pub struct MasqueUdpRelay {
    /// 保活 QUIC 端点句柄（Drop 时全部关联连接随之收束）
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    /// 请求流持活（代理侧套接字生命周期锚点；本面不用流承载数据）
    #[allow(dead_code)]
    _stream: H3RequestStream,
    /// h3 连接存活句柄（最后一个实例 Drop 即按 H3_NO_ERROR 关闭连接）
    #[allow(dead_code)]
    _sender: H3ClientSender,
    /// 本关联的 Quarter Stream ID（数据报帧路由键）
    qsid: u64,
    /// 关联固定目标（CONNECT-UDP 套接字绑定单一目标；send_to 异目标具名拒绝）
    fixed_target: FlowTarget,
    /// 对端最大数据报帧载荷（超限上行具名拒绝）
    max_dgram: usize,
    stats: Arc<MasqueUdpStats>,
    /// 下行队列（tokio Mutex：UdpRelay::recv_from 是 &self 面）
    downlink: Mutex<mpsc::Receiver<(FlowTarget, Vec<u8>)>>,
    downlink_task: tokio::task::JoinHandle<()>,
}

impl MasqueUdpRelay {
    /// 会话统计句柄
    pub fn stats(&self) -> &Arc<MasqueUdpStats> {
        &self.stats
    }
}

#[async_trait]
impl UdpRelay for MasqueUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        if target.host != self.fixed_target.host || target.port != self.fixed_target.port {
            bail!(
                "MASQUE UDP 关联目标不匹配（固定 {}:{}，请求 {}:{}）——CONNECT-UDP 套接字绑定单一目标",
                self.fixed_target.host,
                self.fixed_target.port,
                target.host,
                target.port
            );
        }
        let frame = encode_h3_datagram(self.qsid, 0, buf);
        if frame.len() > self.max_dgram {
            bail!(
                "MASQUE UDP 载荷超限（{}B + 头 > 对端最大数据报 {}B）——RFC 9297 §2.1 客户端不得发送超限帧",
                buf.len(),
                self.max_dgram
            );
        }
        let wait = self.conn.send_datagram_wait(Bytes::from(frame));
        match tokio::time::timeout(DGRAM_SEND_TIMEOUT, wait).await {
            Ok(Ok(())) => {
                self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow!("MASQUE QUIC 数据报发送失败: {e}")),
            Err(_) => Err(anyhow!(
                "MASQUE QUIC 数据报缓冲满超时（{}s）——连接不可用",
                DGRAM_SEND_TIMEOUT.as_secs()
            )),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut rx = self.downlink.lock().await;
        let (target, payload) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("MASQUE UDP 中继已关闭（QUIC 连接断开）"))?;
        if payload.len() > buf.len() {
            self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
            bail!(
                "MASQUE UDP 下行载荷 {}B 超过接收缓冲 {}B",
                payload.len(),
                buf.len()
            );
        }
        buf[..payload.len()].copy_from_slice(&payload);
        self.stats.datagrams_recv.fetch_add(1, Ordering::Relaxed);
        Ok((target, payload.len()))
    }
}

impl Drop for MasqueUdpRelay {
    fn drop(&mut self) {
        // QUIC 连接随 relay 生命周期收束（资源释放面：对端可观 propagate
        // close → 代理按 RFC 9298 §4.1 释放 UDP 套接字）
        self.conn.close(0u32.into(), b"masque udp relay dropped");
        self.downlink_task.abort();
    }
}

/// MASQUE UDP 出口连接器（RIL-120）：每关联一条 QUIC 连接 + 一条
/// CONNECT-UDP 请求流（无连接复用池——masque-go 客户端共享 ClientConn，
/// 本仓按关联独立，线格式等价；边界具名）。数据报走 QUIC DATAGRAM 帧
/// （H3 上不封 capsule），下行 demux 按 qsid/ctx 过滤。
#[derive(Clone)]
pub struct MasqueUdpConnector {
    cfg: Arc<MasqueConfig>,
}

impl MasqueUdpConnector {
    pub fn new(
        server: String,
        port: u16,
        sni: Option<String>,
        skip_cert_verify: bool,
        uri_template: Option<String>,
    ) -> Result<Self> {
        let cfg = MasqueConfig {
            server,
            port,
            sni,
            skip_cert_verify,
            uri_template,
        };
        cfg.validate()?;
        Ok(Self { cfg: Arc::new(cfg) })
    }

    /// 与 TCP 面同一份节点配置构建（from_connector 语义）
    pub fn from_connector(conn: &MasqueConnector) -> Self {
        Self {
            cfg: Arc::new(conn.udp_config()),
        }
    }

    /// 关联并返回具体中继句柄（验收面：统计/取消可观测；trait 面
    /// `associate` 委托此方法）
    pub async fn connect_relay(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<MasqueUdpRelay>> {
        let target = ctx.target;
        let uri = self.cfg.resolve_uri(&target)?;

        let (endpoint, conn, mut sender) = self.cfg.establish_h3().await?;
        // Extended CONNECT：:protocol=connect-udp 经扩展注入（h3 headers.rs
        // 对 CONNECT 方法从 Request extensions 取 Protocol）；capsule-
        // protocol: ?1 请求头（RFC 9297 §3.2 / masque-go 客户端同形）
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .header("capsule-protocol", "?1")
            .body(())
            .context("MASQUE connect-udp 请求构建失败")?;
        let mut stream = sender
            .send_request(req)
            .await
            .context("MASQUE connect-udp 请求发送失败")?;
        let resp = stream
            .recv_response()
            .await
            .context("MASQUE connect-udp 响应接收失败")?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!(
                "MASQUE connect-udp 被代理拒绝（状态码 {}，目标 {}:{}）",
                status.as_u16(),
                target.host,
                target.port
            ));
        }
        // capsule-protocol 响应头（RFC 9297 §3.2）：若在须 ?1（masque-go
        // proxy 恒发；容忍缺省——以 2xx 为准绳，masque-go 客户端同口径）
        if let Some(v) = resp.headers().get("capsule-protocol") {
            let v = v
                .to_str()
                .map_err(|_| anyhow!("MASQUE 响应 capsule-protocol 头非法"))?;
            if v != "?1" {
                bail!("MASQUE 响应 capsule-protocol != ?1（{v:?}）");
            }
        }

        let qsid = stream.id().index();
        let max_dgram = conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("MASQUE 对端不支持 QUIC 数据报（无法承载 UDP 中继）"))?;

        let stats = Arc::new(MasqueUdpStats::default());
        let (tx, rx) = mpsc::channel::<(FlowTarget, Vec<u8>)>(DOWNLINK_QUEUE);
        // 下行任务：读 QUIC 数据报 → qsid/ctx 过滤 → 投递（本关联独占连接，
        // 异 qsid 仅防御面；ctx != 0 = 未知上下文，静默丢弃计数）
        let recv_conn = conn.clone();
        let recv_stats = stats.clone();
        let fixed = target.clone();
        let task = tokio::spawn(async move {
            while let Ok(frame) = recv_conn.read_datagram().await {
                let Some((frame_qsid, ctx_id, payload)) = decode_h3_datagram(&frame) else {
                    recv_stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if frame_qsid != qsid || ctx_id != 0 {
                    recv_stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if tx.send((fixed.clone(), payload.to_vec())).await.is_err() {
                    break; // 中继已 drop
                }
            }
            // Err → 连接关闭/丢失 → 任务收束（资源释放面）
        });

        Ok(Arc::new(MasqueUdpRelay {
            endpoint,
            conn,
            _stream: stream,
            _sender: sender,
            qsid,
            fixed_target: target,
            max_dgram,
            stats,
            downlink: Mutex::new(rx),
            downlink_task: task,
        }))
    }
}

#[async_trait]
impl EgressUdpConnector for MasqueUdpConnector {
    fn name(&self) -> &str {
        "masque"
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

// ---------------------------------------------------------------------------
// 单元测试（线格式向量；端到端契约见 tests/masque_contract.rs）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9298 §3.1 样例：IPv6 字面量展开（冒号百分号编码）
    #[test]
    fn uri_template_expands_ipv6_with_percent_encoding() {
        let out = expand_uri_template(
            "https://masque.example:443/.well-known/masque/udp/{target_host}/{target_port}/",
            "2001:db8::42",
            443,
        )
        .unwrap();
        assert_eq!(
            out,
            "https://masque.example:443/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
        );
    }

    /// 域名/IPv4/端口原样展开（unreserved 不编码）
    #[test]
    fn uri_template_expands_domain_and_ipv4_verbatim() {
        let t = "https://p.example/.well-known/masque/udp/{target_host}/{target_port}/";
        assert_eq!(
            expand_uri_template(t, "example.com", 53).unwrap(),
            "https://p.example/.well-known/masque/udp/example.com/53/"
        );
        assert_eq!(
            expand_uri_template(t, "192.0.2.1", 65535).unwrap(),
            "https://p.example/.well-known/masque/udp/192.0.2.1/65535/"
        );
    }

    /// 拒绝面：空 host、含 % host、未知变量、缺变量
    #[test]
    fn uri_template_rejects_invalid() {
        assert!(expand_uri_template("https://p/{target_host}/{target_port}/", "", 1).is_err());
        assert!(expand_uri_template(
            "https://p/{target_host}/{target_port}/",
            "fe80::1%25eth0",
            1
        )
        .is_err());
        assert!(
            expand_uri_template("https://p/{target_host}/{target_port}/{other}/", "a.com", 1)
                .is_err()
        );
        assert!(expand_uri_template("https://p/{target_host}/", "a.com", 1).is_err());
    }

    /// 模板校验：非 https / 缺 authority 拒绝
    #[test]
    fn uri_template_validation_rejects_non_https() {
        assert!(validate_uri_template("http://p/udp/{target_host}/{target_port}/").is_err());
        assert!(validate_uri_template("https:///udp/{target_host}/{target_port}/").is_err());
        assert!(validate_uri_template(
            "https://p/.well-known/masque/udp/{target_host}/{target_port}/"
        )
        .is_ok());
    }

    /// RFC 9297 §2.2 帧向量：varint(qsid) ++ varint(ctx=0) ++ 载荷
    #[test]
    fn h3_datagram_roundtrip() {
        // qsid=0, ctx=0, payload "ping"（masque-go contextIDZero 同形）
        let frame = encode_h3_datagram(0, 0, b"ping");
        assert_eq!(&frame, &[0x00, 0x00, b'p', b'i', b'n', b'g']);
        let (qsid, ctx, payload) = decode_h3_datagram(&frame).unwrap();
        assert_eq!((qsid, ctx), (0, 0));
        assert_eq!(payload, b"ping");

        // 双字节 varint 档（qsid=4：流 16 → index 4）
        let frame = encode_h3_datagram(4, 0, b"x");
        assert_eq!(&frame[..2], &[0x04, 0x00]);
        let (qsid, _, _) = decode_h3_datagram(&frame).unwrap();
        assert_eq!(qsid, 4);

        // 异 ctx 解码出非零上下文（relay demux 丢弃族）
        let frame = encode_h3_datagram(0, 7, b"y");
        assert_eq!(decode_h3_datagram(&frame).unwrap().1, 7);
    }

    /// 畸形帧（截断 varint）解码 None
    #[test]
    fn h3_datagram_malformed_is_none() {
        assert!(decode_h3_datagram(&[0x40]).is_none()); // 双字节档缺尾
        assert!(decode_h3_datagram(&[]).is_none());
    }

    /// varint 边界档（RFC 9000 §16：2/4 字节档）
    #[test]
    fn varint_multibyte_roundtrip() {
        for v in [63u64, 64, 16383, 16384] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            assert_eq!(read_varint(&buf).unwrap().0, v, "varint {v}");
        }
    }

    /// 代理 authority 形（IPv6 方括号；与 trusttunnel_authority 同口径）
    #[test]
    fn proxy_authority_forms() {
        assert_eq!(proxy_authority("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(proxy_authority("192.0.2.1", 8443), "192.0.2.1:8443");
        assert_eq!(proxy_authority("masque.example", 443), "masque.example:443");
    }

    /// 配置校验：空服务器/零端口/畸形模板具名拒绝
    #[test]
    fn config_validation_rejects_invalid() {
        assert!(MasqueConfig {
            server: String::new(),
            port: 443,
            sni: None,
            skip_cert_verify: true,
            uri_template: None,
        }
        .validate()
        .is_err());
        assert!(MasqueConfig {
            server: "p.example".into(),
            port: 0,
            sni: None,
            skip_cert_verify: false,
            uri_template: None,
        }
        .validate()
        .is_err());
        assert!(MasqueConfig {
            server: "p.example".into(),
            port: 443,
            sni: None,
            skip_cert_verify: false,
            uri_template: Some("not-a-uri".into()),
        }
        .validate()
        .is_err());
    }

    /// 缺省模板解析（RFC 9298 §3.1 缺省路径 + 节点 authority）
    #[test]
    fn default_template_resolves_with_node_authority() {
        let cfg = MasqueConfig {
            server: "192.0.2.10".into(),
            port: 8443,
            sni: None,
            skip_cert_verify: true,
            uri_template: None,
        };
        cfg.validate().unwrap();
        let out = cfg
            .resolve_uri(&FlowTarget {
                host: "2001:db8::42".into(),
                port: 53,
                proto: TargetProto::Udp,
            })
            .unwrap();
        assert_eq!(
            out,
            "https://192.0.2.10:8443/.well-known/masque/udp/2001%3Adb8%3A%3A42/53/"
        );
    }
}
