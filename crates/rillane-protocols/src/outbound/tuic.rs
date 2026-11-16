//! TUIC v5 出口连接器实现（RIL-105，自写）
//!
//! 前置评估：EAimTY `tuic` 家族（tuic/tuic-quinn/tuic-client/tuic-server）
//! 全部已发布版本 yanked + GPL-3.0（与本仓 Apache-2.0 链接不兼容）——无可选
//! 库结论留证 protocol-backends.md#tuic 后，按官方 wire 规范自写
//! （EAimTY/tuic master SPEC.md，与 MetaCubeX fork `tuic/src/marshal.rs`
//! 交叉核对：Packet = [VER 05][CMD 02][ASSOC_ID u16][PKT_ID u16]
//! [FRAG_TOTAL u8][FRAG_ID u8][SIZE u16][ADDR]，ADDR None 仅单字节 0xff）。
//!
//! TCP 面：Connect 命令 over QUIC 双向流（协议无响应面——目标不可达由流收
//! 束承载）；UDP 面：Packet 命令 over QUIC 不可靠数据报（native 模式）+
//! Dissociate 收束 + Heartbeat 保活。v4 不实现不静默互换：客户端恒发
//! VER=0x05，服务端 VER≠0x05 点名拒绝（镜像对端验收）。

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

/// TUIC 协议版本（v5；v4 是不同的 wire 协议，不静默互换）
const TUIC_VERSION: u8 = 0x05;
/// 命令类型字节（官方 protocol/mod.rs 口径）
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;
/// 地址类型字节
const ADDR_DOMAIN: u8 = 0x00;
const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x02;
const ADDR_NONE: u8 = 0xff;

/// 连接建立（DNS 解析 + QUIC 握手 + Authenticate）超时上限（hysteria2 同
/// 口径：single-flight 持锁须有界，挂起拨号不得永久钉住出站流）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 会话保活 Heartbeat 间隔（官方语义：中继任务存续期周期发送）
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// QUIC 数据报发送背压上限（缓冲满等待，超时判连接不可用；hysteria2 同口径）
const DGRAM_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// 下行重装配输出队列深度
const DOWNLINK_QUEUE: usize = 64;
/// 重装配滞留分片超时（丢片按超时整包废弃）
const FRAG_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

// ===== TUIC v5 wire 编解码（ marshal.rs 口径） =====

/// TUIC 地址字段：None（分片后续片）仅单字节 0xff，无端口——官方
/// `Address::None => {}`（marshal.rs）逐字对应
#[derive(Debug, Clone, PartialEq, Eq)]
enum WireAddress {
    None,
    Domain(String, u16),
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

impl WireAddress {
    /// 序列化长度（TYPE 1 + ADDR + PORT 2；None 仅 TYPE）
    fn wire_len(&self) -> usize {
        match self {
            Self::None => 1,
            Self::Domain(d, _) => 2 + d.len() + 2,
            Self::V4(..) => 1 + 4 + 2,
            Self::V6(..) => 1 + 16 + 2,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::None => buf.push(ADDR_NONE),
            Self::Domain(d, port) => {
                buf.push(ADDR_DOMAIN);
                buf.push(d.len() as u8);
                buf.extend_from_slice(d.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::V4(octets, port) => {
                buf.push(ADDR_IPV4);
                buf.extend_from_slice(octets);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::V6(octets, port) => {
                buf.push(ADDR_IPV6);
                buf.extend_from_slice(octets);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// 解码返回 (地址, 消费字节数)；None 变体单字节
    fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        let ty = *buf.first()?;
        match ty {
            ADDR_NONE => Some((Self::None, 1)),
            ADDR_DOMAIN => {
                let len = *buf.get(1)? as usize;
                let end = 2usize.checked_add(len)?;
                let port_end = end.checked_add(2)?;
                if buf.len() < port_end {
                    return None;
                }
                let domain = String::from_utf8_lossy(&buf[2..end]).into_owned();
                let port = u16::from_be_bytes([buf[end], buf[end + 1]]);
                Some((Self::Domain(domain, port), port_end))
            }
            ADDR_IPV4 => {
                if buf.len() < 7 {
                    return None;
                }
                let octets = [buf[1], buf[2], buf[3], buf[4]];
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Some((Self::V4(octets, port), 7))
            }
            ADDR_IPV6 => {
                if buf.len() < 19 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Some((Self::V6(octets, port), 19))
            }
            _ => None,
        }
    }

    /// 路由目标 → 地址字段（host 按 IPv4/IPv6 字面量归类，余者按域名）
    fn of_target(target: &FlowTarget) -> Result<Self> {
        let host = target.host.trim();
        if let Ok(v4) = host.parse::<Ipv4Addr>() {
            return Ok(Self::V4(v4.octets(), target.port));
        }
        if let Ok(v6) = host.parse::<Ipv6Addr>() {
            return Ok(Self::V6(v6.octets(), target.port));
        }
        if host.is_empty() || host.len() > 255 {
            return Err(anyhow!(
                "TUIC 目标域名长度非法（{} 字节，须 1..=255）: {}",
                host.len(),
                host
            ));
        }
        Ok(Self::Domain(host.to_string(), target.port))
    }

    /// 地址字段 → 路由目标（None 无地址语义，返回 None）
    fn flow_target(&self) -> Option<FlowTarget> {
        match self {
            Self::None => None,
            Self::Domain(d, port) => Some(FlowTarget {
                host: d.clone(),
                port: *port,
                proto: TargetProto::Udp,
            }),
            Self::V4(octets, port) => Some(FlowTarget {
                host: Ipv4Addr::from(*octets).to_string(),
                port: *port,
                proto: TargetProto::Udp,
            }),
            Self::V6(octets, port) => Some(FlowTarget {
                host: Ipv6Addr::from(*octets).to_string(),
                port: *port,
                proto: TargetProto::Udp,
            }),
        }
    }
}

/// Packet 命令头常量长度（VER+TYPE + assoc/pkt/total/fid/size），不含地址
const PACKET_HEADER_LEN_NO_ADDR: usize = 10;

/// 解析后的 Packet 数据报（assoc_id, pkt_id, frag_total, frag_id, size,
/// 地址, 载荷切片）——载荷长度与 SIZE 字段的核对归重装配面（分片计数语义）
type ParsedPacket<'a> = (u16, u16, u8, u8, u16, WireAddress, &'a [u8]);

fn parse_packet_datagram(buf: &[u8]) -> Option<ParsedPacket<'_>> {
    if buf.len() < PACKET_HEADER_LEN_NO_ADDR {
        return None;
    }
    if buf[0] != TUIC_VERSION || buf[1] != CMD_PACKET {
        return None;
    }
    let assoc_id = u16::from_be_bytes([buf[2], buf[3]]);
    let pkt_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_total = buf[6];
    let frag_id = buf[7];
    let size = u16::from_be_bytes([buf[8], buf[9]]);
    let (addr, consumed) = WireAddress::decode(&buf[PACKET_HEADER_LEN_NO_ADDR..])?;
    let payload = &buf[PACKET_HEADER_LEN_NO_ADDR + consumed..];
    Some((assoc_id, pkt_id, frag_total, frag_id, size, addr, payload))
}

/// 编码 Packet 数据报（同一 pkt_id 的分片共享头；后续片地址 None——官方
/// `addr.take()` 语义）
fn encode_packet_datagram(
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: &WireAddress,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PACKET_HEADER_LEN_NO_ADDR + addr.wire_len() + payload.len());
    buf.push(TUIC_VERSION);
    buf.push(CMD_PACKET);
    buf.extend_from_slice(&assoc_id.to_be_bytes());
    buf.extend_from_slice(&pkt_id.to_be_bytes());
    buf.push(frag_total);
    buf.push(frag_id);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    addr.encode(&mut buf);
    buf.extend_from_slice(payload);
    buf
}

/// Authenticate 帧体：UUID 16 字节 + TOKEN 32 字节（帧头 VER+TYPE 由调用方
/// 前置——官方 Authenticate OPT 口径）
fn authenticate_body(uuid: &Uuid, token: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 32);
    buf.extend_from_slice(uuid.as_bytes());
    buf.extend_from_slice(token);
    buf
}

/// 官方 token 口径：TLS Keying Material Exporter，label = UUID、
/// context = 原始密码（绑定当前 TLS 会话——重放跨会话 token 无效）
fn auth_token(conn: &quinn::Connection, uuid: &Uuid, password: &str) -> Result<[u8; 32]> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid.as_bytes(), password.as_bytes())
        .map_err(|_| anyhow!("TUIC TLS 密钥材料导出失败（握手未完成或密钥不可导出）"))?;
    Ok(token)
}

// ===== 下行重装配（客户端侧；官方 UdpSessions 语义同构） =====

/// pkt_id → (frag_total, frag_id → 分片载荷, 首片地址, 落位时刻)
type FragParts = (u8, BTreeMap<u8, Vec<u8>>, Option<WireAddress>, Instant);

#[derive(Default)]
struct Reassembler {
    parts: BTreeMap<u16, FragParts>,
}

impl Reassembler {
    /// 推入一个分片；完整则返回 (地址, 拼接载荷)。SIZE 字段与载荷不符、
    /// 非法分片头、超时滞留、溢出清空均计入 frag_dropped。
    /// （参数面即官方 Packet 头字段 1:1——不收敛 options 结构）
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        size: u16,
        addr: WireAddress,
        payload: &[u8],
        dropped: &AtomicU64,
    ) -> Option<(WireAddress, Vec<u8>)> {
        let now = Instant::now();
        self.parts
            .retain(|_, (_, _, _, born)| now.duration_since(*born) < FRAG_REASSEMBLY_TIMEOUT);
        if self.parts.len() > 256 {
            dropped.fetch_add(self.parts.len() as u64, Ordering::Relaxed);
            self.parts.clear();
        }

        if frag_total == 0 || frag_id >= frag_total {
            dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if payload.len() != size as usize {
            dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let has_addr = !matches!(addr, WireAddress::None);
        // 首片（frag_id 0）必带地址；后续片必带 None——官方 addr.take() 口径
        if has_addr != (frag_id == 0) {
            dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let entry = self
            .parts
            .entry(pkt_id)
            .or_insert_with(|| (frag_total, BTreeMap::new(), None, Instant::now()));
        if entry.0 != frag_total {
            dropped.fetch_add(1, Ordering::Relaxed);
            self.parts.remove(&pkt_id);
            return None;
        }
        if has_addr {
            entry.2 = Some(addr);
        }
        entry.1.insert(frag_id, payload.to_vec());
        if entry.1.len() == entry.0 as usize {
            let (_, frags, addr, _) = self.parts.remove(&pkt_id)?;
            let addr = addr?; // 首片未到齐地址则不可能凑满（frag 0 必带地址）
            let mut whole = Vec::with_capacity(frags.values().map(|f| f.len()).sum());
            for piece in frags.values() {
                whole.extend_from_slice(piece);
            }
            return Some((addr, whole));
        }
        None
    }
}

/// 中继级下行统计（验收面：分片丢弃/完整交付可观测；外来数据报归会话级）
#[derive(Default)]
pub struct UdpSessionStats {
    /// 整包废弃的分片/包计数（超时滞留、溢出清空、非法分片头、SIZE 不符、
    /// 下行队列满）
    pub frag_dropped: AtomicU64,
    /// 重装配后完整交付的数据报计数
    pub datagrams_relayed: AtomicU64,
}

// ===== 共享 QUIC 会话（TUIC v5 天然多路复用：单连接承载全部 Connect/Packet） =====

/// demux 条目：(分片投递通道, 所属中继统计)
type DemuxEntry = (
    mpsc::Sender<(u16, u8, u8, u16, WireAddress, Bytes)>,
    Arc<UdpSessionStats>,
);

/// demux 投递的原始分片（pkt_id, frag_total, frag_id, size, 地址, 载荷）
type DemuxedFragment = (u16, u8, u8, u16, WireAddress, Bytes);

struct TuicSession {
    /// 仅持句柄：保活 QUIC 端点（Drop 时全部关联连接随之收束）
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    /// assoc_id → 下行分片通道（Drop 注销即停止投递）
    demux: Arc<StdMutex<BTreeMap<u16, DemuxEntry>>>,
    /// 未注册 assoc / 帧头非法的数据报（会话级外来丢弃计数）
    unknown_dropped: Arc<AtomicU64>,
    heartbeat_task: tokio::task::JoinHandle<()>,
}

impl TuicSession {
    /// 分配并预留 assoc_id（随机 + demux 查重）
    fn alloc_assoc_id(&self) -> u16 {
        let guard = self.demux.lock().unwrap();
        loop {
            let id: u16 = rand::random();
            if !guard.contains_key(&id) {
                return id;
            }
        }
    }
}

impl Drop for TuicSession {
    fn drop(&mut self) {
        // 会话收束即 QUIC 连接收束（资源释放面：对端可观 propagate close）
        self.conn.close(0u32.into(), b"tuic session ended");
        self.heartbeat_task.abort();
    }
}

// ===== TCP 面连接器 =====

/// TUIC v5 出口连接器（TCP 面：Connect 命令 over QUIC 双向流）
pub struct TuicConnector {
    server: String,
    port: u16,
    uuid: String,
    password: String,
    congestion_controller: Option<String>,
    server_name: Option<String>,
    skip_cert_verify: bool,
    alpn: Option<Vec<String>>,
    session: Mutex<Option<Arc<TuicSession>>>,
}

impl TuicConnector {
    /// 参数面镜像 `EgressConfig::Tuic` 字段 1:1，不收敛 options 结构
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        uuid: String,
        password: String,
        congestion_controller: Option<String>,
        server_name: Option<String>,
        skip_cert_verify: bool,
        alpn: Option<Vec<String>>,
    ) -> Self {
        Self {
            server,
            port,
            uuid,
            password,
            congestion_controller,
            server_name,
            skip_cert_verify,
            alpn,
            session: Mutex::new(None),
        }
    }

    fn parsed_uuid(&self) -> Result<Uuid> {
        Uuid::parse_str(self.uuid.trim())
            .with_context(|| format!("TUIC uuid 解析失败（须为标准 UUID）: {}", self.uuid))
    }

    /// 建立期校验：密码非空 + UUID 可解析 + 拥塞控制白名单（非 cubic 具名
    /// 拒绝——自写面乘 quinn 缺省 cubic，不静默降级）
    fn validate_config(&self) -> Result<()> {
        if self.password.is_empty() {
            return Err(anyhow!("TUIC password 不能为空"));
        }
        self.parsed_uuid()?;
        if let Some(cc) = &self.congestion_controller {
            if cc != "cubic" {
                return Err(anyhow!(
                    "TUIC congestion_controller 仅支持 cubic（RIL-105 自写面乘 quinn 缺省；bbr/new_reno 不静默降级），当前: {cc}"
                ));
            }
        }
        Ok(())
    }

    /// 官方认证：Authenticate 帧发首个单向流（UUID + TLS exporter token），
    /// 协议无响应面——失败由对端断链承载（后续首个操作浮出）
    async fn authenticate(&self, conn: &quinn::Connection, uuid: &Uuid) -> Result<()> {
        let token = auth_token(conn, uuid, &self.password)?;
        let mut send = conn.open_uni().await.context("TUIC 认证流开启失败")?;
        let mut frame = Vec::with_capacity(2 + 16 + 32);
        frame.push(TUIC_VERSION);
        frame.push(CMD_AUTHENTICATE);
        frame.extend_from_slice(&authenticate_body(uuid, &token));
        send.write_all(&frame)
            .await
            .context("TUIC 认证帧发送失败")?;
        // quinn 0.11 finish() 为同步面（FIN 入队即返回）
        send.finish().context("TUIC 认证流收束失败")?;
        Ok(())
    }

    async fn get_or_connect_session(&self) -> Result<Arc<TuicSession>> {
        self.validate_config()?;
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_ref() {
            return Ok(session.clone());
        }

        // 持锁跨握手（single-flight 语义），但加显式超时：超时则释放互斥、
        // 不缓存半成品（fail-closed），后续调用可重新尝试（hysteria2 同口径）
        let session = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_session())
            .await
            .map_err(|_| anyhow!("TUIC 连接建立超时（{}s）", CONNECT_TIMEOUT.as_secs()))??;
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn invalidate_session(&self) {
        let mut guard = self.session.lock().await;
        *guard = None;
    }

    /// Connect 命令建立双向流并回传适配器（会话失效重连一次——认证失败/
    /// 链路丢失场景，hysteria2 同口径）
    async fn open_connect_stream(&self, target: &FlowTarget) -> Result<TuicStream> {
        let session = self.get_or_connect_session().await?;
        match open_connect(&session.conn, target).await {
            Ok(stream) => Ok(stream),
            Err(first) => {
                tracing::warn!(
                    target: "rillane::tuic",
                    target = %format!("{}:{}", target.host, target.port),
                    error = %first,
                    "TUIC 连接失败，重连并重试"
                );
                self.invalidate_session().await;
                let session = self.get_or_connect_session().await?;
                open_connect(&session.conn, target)
                    .await
                    .with_context(|| format!("TUIC Connect 失败: {}:{}", target.host, target.port))
            }
        }
    }

    async fn connect_session(&self) -> Result<Arc<TuicSession>> {
        self.validate_config()?;
        let uuid = self.parsed_uuid()?;

        let server_name = self
            .server_name
            .clone()
            .unwrap_or_else(|| self.server.clone());
        let server_addr: SocketAddr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await
            .with_context(|| format!("TUIC 服务器地址解析失败: {}", self.server))?
            .next()
            .ok_or_else(|| anyhow!("TUIC 服务器地址解析为空: {}", self.server))?;

        // QUIC 端点：ALPN 按节点配置（协议规范不强制 ALPN），证书校验口径
        // 与 hysteria2/anytls 一致
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
        crypto.alpn_protocols = self
            .alpn
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)
            .context("TUIC QUIC 端点创建失败")?;
        let quinn_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| anyhow!("TUIC QUIC TLS 配置失败: {e}"))?,
        ));
        endpoint.set_default_client_config(quinn_cfg);

        let connecting = endpoint
            .connect(server_addr, &server_name)
            .context("TUIC QUIC 连接发起失败")?;
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| anyhow!("TUIC QUIC 握手超时（{}s）", CONNECT_TIMEOUT.as_secs()))?
            .context("TUIC QUIC 连接失败")?;

        self.authenticate(&conn, &uuid).await?;

        // 下行 demux：读 QUIC 数据报 → 按 assoc_id 路由到中继（未注册/
        // 非法帧计数丢弃；数据报通道关闭即连接丢失——任务收束）
        let demux: Arc<StdMutex<BTreeMap<u16, DemuxEntry>>> =
            Arc::new(StdMutex::new(BTreeMap::new()));
        let unknown_dropped = Arc::new(AtomicU64::new(0));
        {
            let conn = conn.clone();
            let demux = demux.clone();
            let unknown = unknown_dropped.clone();
            tokio::spawn(async move {
                while let Ok(buf) = conn.read_datagram().await {
                    let Some((assoc_id, pkt_id, frag_total, frag_id, size, addr, payload)) =
                        parse_packet_datagram(&buf)
                    else {
                        unknown.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let entry = demux.lock().unwrap().get(&assoc_id).cloned();
                    let Some((tx, stats)) = entry else {
                        unknown.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if tx
                        .try_send((
                            pkt_id,
                            frag_total,
                            frag_id,
                            size,
                            addr,
                            Bytes::copy_from_slice(payload),
                        ))
                        .is_err()
                    {
                        // 分片通道满/中继已收束——按整包废弃计数
                        stats.frag_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Err → 连接关闭/丢失 → 任务收束（资源释放面）
            });
        }

        // 会话保活：官方 Heartbeat 数据报周期发送（中继任务存续期；发送
        // 失败即连接丢失——任务收束）
        let heartbeat_task = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
                tick.tick().await; // 首拍立即返回——跳过
                loop {
                    tick.tick().await;
                    if conn
                        .send_datagram(Bytes::from_static(&[TUIC_VERSION, CMD_HEARTBEAT]))
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };

        Ok(Arc::new(TuicSession {
            endpoint,
            conn,
            demux,
            unknown_dropped,
            heartbeat_task,
        }))
    }
}

#[async_trait]
impl EgressConnector for TuicConnector {
    fn name(&self) -> &'static str {
        "tuic"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            other => {
                return Err(anyhow!("TUIC 暂仅支持 TCP 转发（got {:?}）", other));
            }
        }

        let mut stream = self.open_connect_stream(&flow.target).await?;
        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("TUIC 中继传输失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

/// Connect 双向流适配器：quinn 双向流的读/写半合并为单个 AsyncRead +
/// AsyncWrite 对象（copy_bidirectional 面）
pub struct TuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // quinn 0.11 的 poll_write 为固有面（WriteError 错误型）——经
        // AsyncWrite trait 面调用以统一 io::Error 映射
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Connect 命令帧发送 + 双向流交付（协议无响应面——目标不可达由对端流
/// 收束承载，见 protocol-backends.md#tuic 统计行）
async fn open_connect(conn: &quinn::Connection, target: &FlowTarget) -> Result<TuicStream> {
    let addr = WireAddress::of_target(target)?;
    let (mut send, recv) = conn.open_bi().await.context("TUIC 双向流开启失败")?;
    let mut frame = Vec::with_capacity(2 + addr.wire_len());
    frame.push(TUIC_VERSION);
    frame.push(CMD_CONNECT);
    addr.encode(&mut frame);
    send.write_all(&frame)
        .await
        .context("TUIC Connect 帧发送失败")?;
    Ok(TuicStream { send, recv })
}

// ===== UDP 面连接器（RIL-105：官方 v5 Packet 数据报，自写） =====

/// TUIC UDP 出站连接器：官方 v5 Packet 命令 over QUIC 不可靠数据报
/// （native 模式；quic-stream 中继模式不承载）+ Dissociate 收束
pub struct TuicUdpConnector {
    inner: TuicConnector,
}

impl TuicUdpConnector {
    /// 与 TCP 面同一份节点配置（from_connector 语义，见 shadowsocks 同例）
    pub fn from_connector(conn: &TuicConnector) -> Self {
        Self {
            inner: TuicConnector::new(
                conn.server.clone(),
                conn.port,
                conn.uuid.clone(),
                conn.password.clone(),
                conn.congestion_controller.clone(),
                conn.server_name.clone(),
                conn.skip_cert_verify,
                conn.alpn.clone(),
            ),
        }
    }

    /// 关联并返回具体中继句柄（验收面：会话统计/未知数据报计数可观测；
    /// trait 面 `associate` 委托此方法）
    pub async fn connect_relay(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<TuicUdpRelay>> {
        let session = self.inner.get_or_connect_session().await?;
        let max_dgram = session
            .conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("TUIC 对端不支持 QUIC 数据报（无法承载 UDP 中继）"))?;

        let assoc_id = session.alloc_assoc_id();
        let stats = Arc::new(UdpSessionStats::default());
        let (frag_tx, mut frag_rx) = mpsc::channel::<DemuxedFragment>(256);
        session
            .demux
            .lock()
            .unwrap()
            .insert(assoc_id, (frag_tx, stats.clone()));

        let (asm_tx, asm_rx) = mpsc::channel::<(FlowTarget, Vec<u8>)>(DOWNLINK_QUEUE);
        let reassembly_task = {
            let stats = stats.clone();
            tokio::spawn(async move {
                let mut reassembler = Reassembler::default();
                while let Some((pkt_id, frag_total, frag_id, size, addr, payload)) =
                    frag_rx.recv().await
                {
                    if let Some((wire, whole)) = reassembler.push(
                        pkt_id,
                        frag_total,
                        frag_id,
                        size,
                        addr,
                        &payload,
                        &stats.frag_dropped,
                    ) {
                        match wire.flow_target() {
                            Some(target) => {
                                if asm_tx.send((target, whole)).await.is_err() {
                                    break; // 中继已 drop
                                }
                                stats.datagrams_relayed.fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                stats.frag_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            })
        };

        Ok(Arc::new(TuicUdpRelay {
            session,
            assoc_id,
            _fixed_target: ctx.target,
            max_dgram,
            pkt_id: StdMutex::new(0),
            stats,
            downlink: Mutex::new(asm_rx),
            reassembly_task,
        }))
    }
}

#[async_trait]
impl EgressUdpConnector for TuicUdpConnector {
    fn name(&self) -> &str {
        "tuic"
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

/// 字节级 TUIC UDP 中继：共享 QUIC 会话 + assoc_id 会话 + 下行重装配任务
pub struct TuicUdpRelay {
    /// 共享会话（最后引用 Drop 即 QUIC 连接收束）
    session: Arc<TuicSession>,
    assoc_id: u16,
    /// 会话默认目标（R7 固定目标语义；数据报协议头逐包携带，发送以参数为准）
    _fixed_target: FlowTarget,
    max_dgram: usize,
    pkt_id: StdMutex<u16>,
    stats: Arc<UdpSessionStats>,
    /// 下行队列（tokio Mutex：UdpRelay::recv_from 是 &self 面）
    downlink: Mutex<mpsc::Receiver<(FlowTarget, Vec<u8>)>>,
    reassembly_task: tokio::task::JoinHandle<()>,
}

impl TuicUdpRelay {
    /// 中继级统计句柄（验收面：分片丢弃/完整交付计数可观测）
    pub fn stats(&self) -> &Arc<UdpSessionStats> {
        &self.stats
    }

    /// 会话级外来数据报计数（未注册 assoc / 非法帧头——demux 丢弃面）
    pub fn unknown_dropped(&self) -> u64 {
        self.session.unknown_dropped.load(Ordering::Relaxed)
    }

    fn next_pkt_id(&self) -> u16 {
        let mut guard = self.pkt_id.lock().unwrap();
        let id = *guard;
        *guard = guard.wrapping_add(1);
        id
    }

    async fn send_datagram(&self, msg: Vec<u8>) -> Result<()> {
        let wait = self.session.conn.send_datagram_wait(Bytes::from(msg));
        match tokio::time::timeout(DGRAM_SEND_TIMEOUT, wait).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(anyhow!("TUIC QUIC 数据报发送失败: {e}")),
            Err(_) => Err(anyhow!(
                "TUIC QUIC 数据报缓冲满超时（{}s）——连接不可用",
                DGRAM_SEND_TIMEOUT.as_secs()
            )),
        }
    }
}

#[async_trait]
impl UdpRelay for TuicUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let addr = WireAddress::of_target(target)?;

        // 单包直发（官方口径 frag_total=1）
        let first_capacity = self
            .max_dgram
            .saturating_sub(PACKET_HEADER_LEN_NO_ADDR + addr.wire_len());
        if buf.len() <= first_capacity {
            let pkt_id = self.next_pkt_id();
            let msg = encode_packet_datagram(self.assoc_id, pkt_id, 1, 0, &addr, buf);
            self.send_datagram(msg).await?;
            return Ok(());
        }

        // 分片：同一 pkt_id，frag_id 0..total；首片带地址，后续片 None
        // （官方 addr.take() 口径——后续片容量多出地址字段差）
        let cont_capacity = self
            .max_dgram
            .saturating_sub(PACKET_HEADER_LEN_NO_ADDR + WireAddress::None.wire_len());
        if first_capacity == 0 || cont_capacity == 0 {
            return Err(anyhow!(
                "TUIC QUIC 数据报过小（{}B），无法承载 UDP 分片头",
                self.max_dgram
            ));
        }
        let rem = buf.len() - first_capacity;
        let total = 1 + rem.div_ceil(cont_capacity);
        if total > u8::MAX as usize {
            return Err(anyhow!(
                "TUIC UDP 载荷过大（{}B，需 {total} 分片 > 255 上限）",
                buf.len()
            ));
        }
        let pkt_id = self.next_pkt_id();
        let mut rest = buf;
        let mut first = true;
        for frag_id in 0..total as u8 {
            let capacity = if first { first_capacity } else { cont_capacity };
            let take = rest.len().min(capacity);
            let (chunk, tail) = rest.split_at(take);
            let wire = if first {
                first = false;
                &addr
            } else {
                &WireAddress::None
            };
            let msg =
                encode_packet_datagram(self.assoc_id, pkt_id, total as u8, frag_id, wire, chunk);
            self.send_datagram(msg).await?;
            rest = tail;
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut rx = self.downlink.lock().await;
        let (target, payload) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("TUIC UDP 中继已关闭（QUIC 连接断开）"))?;
        if payload.len() > buf.len() {
            return Err(anyhow!(
                "TUIC UDP 下行载荷 {}B 超过接收缓冲 {}B",
                payload.len(),
                buf.len()
            ));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((target, payload.len()))
    }
}

impl Drop for TuicUdpRelay {
    fn drop(&mut self) {
        // 注销 demux（下行即停）+ 收束重装配任务
        self.session.demux.lock().unwrap().remove(&self.assoc_id);
        self.reassembly_task.abort();
        // 具名收束：Dissociate 单向流（尽力而为——会话已亡则 QUIC 层已收束）
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let conn = self.session.conn.clone();
            let assoc_id = self.assoc_id;
            handle.spawn(async move {
                if let Ok(mut send) = conn.open_uni().await {
                    let mut frame = Vec::with_capacity(4);
                    frame.push(TUIC_VERSION);
                    frame.push(CMD_DISSOCIATE);
                    frame.extend_from_slice(&assoc_id.to_be_bytes());
                    if send.write_all(&frame).await.is_ok() {
                        let _ = send.finish();
                    }
                }
            });
        }
    }
}

// ===== 编解码契约测试（wire 面字节级；镜像对端独立实现于验收套件） =====

#[cfg(test)]
mod tests {
    use super::*;

    /// 地址字段编解码字节级回环：None 单字节（官方 marshal.rs 口径）、
    /// 域名 TYPE+LEN+ADDR+PORT、v4/v6 定长
    #[test]
    fn wire_address_roundtrip_byte_exact() {
        let cases: Vec<(WireAddress, Vec<u8>)> = vec![
            (WireAddress::None, vec![0xff]),
            (WireAddress::Domain("example.com".into(), 443), {
                let mut v = vec![0x00, 11];
                v.extend_from_slice(b"example.com");
                v.extend_from_slice(&443u16.to_be_bytes());
                v
            }),
            (
                WireAddress::V4([1, 2, 3, 4], 80),
                [0x01, 1, 2, 3, 4, 0, 80].to_vec(),
            ),
            (
                WireAddress::V6(
                    [
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                    ],
                    8443,
                ),
                {
                    let mut v = vec![0x02];
                    v.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                    ]);
                    v.extend_from_slice(&8443u16.to_be_bytes());
                    v
                },
            ),
        ];
        for (addr, bytes) in cases {
            assert_eq!(addr.wire_len(), bytes.len(), "{addr:?} 长度自洽");
            let mut encoded = Vec::new();
            addr.encode(&mut encoded);
            assert_eq!(encoded, bytes, "{addr:?} 编码字节级");
            let (decoded, consumed) = WireAddress::decode(&bytes).expect("解码成功");
            assert_eq!(decoded, addr, "{addr:?} 解码回环");
            assert_eq!(consumed, bytes.len());
        }
        // 非法类型/截断输入 → None
        assert!(WireAddress::decode(&[0x42]).is_none());
        assert!(WireAddress::decode(&[0x00, 200]).is_none());
        assert!(WireAddress::decode(&[0x01, 1, 2, 3]).is_none());
    }

    /// Packet 数据报编解码回环 + 字段字节位（VER 05 / CMD 02 / BE 序）
    #[test]
    fn packet_datagram_roundtrip_field_exact() {
        let payload = vec![7u8; 33];
        let msg = encode_packet_datagram(
            0x1234,
            0x0042,
            1,
            0,
            &WireAddress::V4([10, 0, 0, 1], 53),
            &payload,
        );
        assert_eq!(msg[0], 0x05, "VER");
        assert_eq!(msg[1], 0x02, "CMD_PACKET");
        assert_eq!(&msg[2..4], &0x1234u16.to_be_bytes(), "assoc_id BE");
        assert_eq!(&msg[4..6], &0x0042u16.to_be_bytes(), "pkt_id BE");
        assert_eq!(msg[6], 1, "frag_total");
        assert_eq!(msg[7], 0, "frag_id");
        assert_eq!(&msg[8..10], &33u16.to_be_bytes(), "size BE");
        assert_eq!(msg[10], 0x01, "ADDR_IPV4");
        let (assoc, pkt, total, fid, size, addr, got) =
            parse_packet_datagram(&msg).expect("解析成功");
        assert_eq!(assoc, 0x1234);
        assert_eq!(pkt, 0x0042);
        assert_eq!((total, fid, size), (1, 0, 33));
        assert_eq!(addr, WireAddress::V4([10, 0, 0, 1], 53));
        assert_eq!(got, &payload[..]);
        // 截断帧拒收
        assert!(parse_packet_datagram(&msg[..9]).is_none());
        assert!(parse_packet_datagram(&[0x05, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0xff]).is_none());
    }

    /// Authenticate 帧体：UUID 16 字节 + TOKEN 32 字节，VER/TYPE 前置
    #[test]
    fn authenticate_frame_layout() {
        let uuid = Uuid::parse_str("2dd35bfe-7d81-4a7e-9325-97e5ae1f8e8e").expect("uuid");
        let token = [0xABu8; 32];
        let body = authenticate_body(&uuid, &token);
        assert_eq!(body.len(), 48);
        assert_eq!(&body[..16], uuid.as_bytes(), "UUID 原字节序");
        assert_eq!(&body[16..], &token[..], "TOKEN");
        let mut frame = Vec::new();
        frame.push(TUIC_VERSION);
        frame.push(CMD_AUTHENTICATE);
        frame.extend_from_slice(&body);
        assert_eq!(&frame[..2], &[0x05, 0x00]);
        assert_eq!(frame.len(), 50);
    }

    /// 重装配：乱序分片凑满交付、SIZE 不符拒收、非法分片头拒收、
    /// 后续片携带地址（违反 addr.take() 口径）拒收
    #[test]
    fn reassembly_orders_validates_and_delivers() {
        let dropped = AtomicU64::new(0);
        let mut r = Reassembler::default();
        let addr = WireAddress::V4([192, 0, 2, 9], 40443);

        // 三片乱序投递（frag 2 → frag 1 → frag 0）
        assert!(r
            .push(7, 3, 2, 4, WireAddress::None, b"DDDD", &dropped)
            .is_none());
        assert!(r
            .push(7, 3, 1, 4, WireAddress::None, b"CCCC", &dropped)
            .is_none());
        let (got_addr, whole) = r
            .push(7, 3, 0, 4, addr.clone(), b"BBBB", &dropped)
            .expect("凑满交付");
        assert_eq!(got_addr, addr);
        assert_eq!(whole, b"BBBBCCCCDDDD");

        // SIZE 与载荷不符 → 拒收计数
        assert!(r
            .push(8, 1, 0, 9, addr.clone(), b"XXXX", &dropped)
            .is_none());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        // 后续片携带地址（违反 None 口径）→ 拒收计数
        assert!(r.push(9, 2, 1, 1, addr.clone(), b"Y", &dropped).is_none());
        assert_eq!(dropped.load(Ordering::Relaxed), 2);

        // frag_total=0 / frag_id >= total → 拒收计数
        assert!(r.push(10, 0, 0, 1, addr.clone(), b"Z", &dropped).is_none());
        assert!(r
            .push(11, 2, 2, 1, WireAddress::None, b"Z", &dropped)
            .is_none());
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
    }

    /// 路由目标 ↔ 地址字段归类：v4/v6 字面量与域名，长度上限具名拒绝
    #[test]
    fn flow_target_address_classification() {
        let v4 = FlowTarget {
            host: "192.0.2.5".into(),
            port: 80,
            proto: TargetProto::Udp,
        };
        assert_eq!(
            WireAddress::of_target(&v4).expect("归类"),
            WireAddress::V4([192, 0, 2, 5], 80)
        );
        let domain = FlowTarget {
            host: "example.com".into(),
            port: 443,
            proto: TargetProto::Udp,
        };
        let wire = WireAddress::of_target(&domain).expect("归类");
        assert_eq!(wire, WireAddress::Domain("example.com".into(), 443));
        let back = wire.flow_target().expect("还原");
        assert_eq!(back.host, "example.com");
        assert_eq!(back.port, 443);
        assert_eq!(back.proto, TargetProto::Udp);

        let too_long = FlowTarget {
            host: "a".repeat(256),
            port: 1,
            proto: TargetProto::Udp,
        };
        let err = format!(
            "{}",
            WireAddress::of_target(&too_long).expect_err("超长拒绝")
        );
        assert!(err.contains("域名长度非法"), "具名拒绝: {err}");
    }

    /// 分片切块口径：首片容量含地址、后续片 None 省址扩容、末片短块
    #[test]
    fn fragmentation_layout_first_addr_rest_none() {
        // 模拟 send_to 的切块口径（不依赖 QUIC）：首片容量 C1、后续容量 C2
        let max_dgram = 1200usize;
        let addr = WireAddress::Domain("example.com".into(), 443);
        let header_no_addr = PACKET_HEADER_LEN_NO_ADDR;
        let first_capacity = max_dgram - header_no_addr - addr.wire_len();
        let cont_capacity = max_dgram - header_no_addr - WireAddress::None.wire_len();
        let payload_len = first_capacity + cont_capacity + 100;

        let rem = payload_len - first_capacity;
        let total = 1 + rem.div_ceil(cont_capacity);
        assert_eq!(total, 3, "首片 + 两后续片");

        // 逐片按官方 encode 组帧并解析回验：frag 0 带地址、frag 1/2 None
        let payload: Vec<u8> = vec![5u8; payload_len];
        let mut rest: &[u8] = &payload;
        let mut first = true;
        for frag_id in 0..total as u8 {
            let capacity = if first { first_capacity } else { cont_capacity };
            let take = rest.len().min(capacity);
            let (chunk, tail) = rest.split_at(take);
            let wire = if first {
                first = false;
                &addr
            } else {
                &WireAddress::None
            };
            let msg = encode_packet_datagram(9, 77, total as u8, frag_id, wire, chunk);
            let (assoc, pkt, got_total, got_fid, size, got_addr, got_payload) =
                parse_packet_datagram(&msg).expect("回验");
            assert_eq!(assoc, 9);
            assert_eq!(pkt, 77);
            assert_eq!(got_total, total as u8);
            assert_eq!(got_fid, frag_id);
            assert_eq!(size as usize, chunk.len());
            if frag_id == 0 {
                assert_eq!(got_addr, addr, "首片带地址");
            } else {
                assert_eq!(got_addr, WireAddress::None, "后续片 None");
            }
            assert_eq!(got_payload, chunk);
            rest = tail;
        }
        assert!(rest.is_empty(), "切块覆盖全载荷");
    }
}
