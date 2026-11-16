//! Hysteria v1 出口连接器实现（RIL-109）
//!
//! 全自写面：v1 无任何已评审库（选库留证 docs/protocol-backends.md#hysteria
//! ——crates.io 无 v1 crate、GitHub 同名项目皆 v2 重写），线格式以官方
//! aperet/hysteria v1.3.5 core/cs 为镜像口径（协议版本字节 0x03；struc 默认
//! 大端打包，v1 线结构不带端序标签——全部多字节字段 BE）。
//!
//! 面：
//! - 控制流（每连接首条客户端双向流，官方 protocolTimeout 10s）：
//!   [版本 0x03][SendBPS BE][RecvBPS BE][AuthLen BE][Auth] →
//!   serverHello [OK][SendBPS BE][RecvBPS BE][MessageLen BE][Message]；
//!   服务端硬性要求 SendBPS/RecvBPS 皆非零（否则协议错误），授权=min(对侧
//!   申报, 服务端上限)。Brutal 拥塞控制不交付——QUIC 缺省 CC 承载，速率
//!   申报如实发送（过服务端校验 + 对端观测），不伪装拥塞行为。
//! - TCP：逐请求新双向流 [UDP=false][HostLen BE][Host][Port BE] →
//!   [OK][UDPSessionID BE][MessageLen BE][Message]，之后双向搬运。
//! - UDP：QUIC 不可靠数据报 [SessionID BE][HostLen BE][Host][Port BE]
//!   [MsgID BE][FragID][FragCount][DataLen BE][Data]；UDP 会话经 UDP=true
//!   请求流建立（官方 Hold 语义：流存活即会话存活）。
//!
//! 边界（评估留证同页）：仅 QUIC over 原生 UDP 载体——obfs（XPlus）/wechat/
//! faketcp 包层传输点名拒绝；端口跳跃接受不消费（ACL/ACME/流量统计 API
//! 同不交付）；ALPN 缺省 "hysteria"（官方 config 旋钮口径），TLS 最低 1.3。

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU16, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{mpsc, Mutex};

/// v1 协议版本字节（官方 core/cs/protocol.go protocolVersion = 3）
pub(crate) const PROTOCOL_VERSION: u8 = 0x03;
/// 官方 protocolTimeout：控制流握手全程上限（core/cs/protocol.go）
pub(crate) const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(10);
/// 连接建立（DNS + QUIC 握手 + 控制流认证）外层上限（与 Hysteria2 面同口径，
/// 防挂起拨号钉死互斥）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 速率申报缺省值（Mbps）：与订阅转换（clash v1 → IR）硬编码同值——官方
/// 客户端必填 up/down 且服务端硬性要求非零，缺省此处兜底
const DEFAULT_UP_MBPS: u32 = 50;
const DEFAULT_DOWN_MBPS: u32 = 100;
/// Mbps → BPS（官方 app/cmd/config.go mbpsToBps）
pub(crate) const MBPS_TO_BPS: u64 = 1_000_000;
/// QUIC 应用错误码（官方 protocol.go：0 generic / 1 protocol / 2 auth）
pub(crate) const QERR_PROTOCOL: u32 = 1;
pub(crate) const QERR_AUTH: u32 = 2;

// ===== 线格式编解码（core/cs/protocol.go 镜像，全字段 BE，bool 一字节） =====

/// 控制流客户端写：[版本][SendBPS BE][RecvBPS BE][AuthLen BE][Auth]
/// （官方分两次写版本字节与 clientHello；一次写线格式等价——服务端先读
/// 1 字节再解包余量，单缓冲兼容）
pub(crate) fn pack_client_hello(send_bps: u64, recv_bps: u64, auth: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 2 + auth.len());
    buf.push(PROTOCOL_VERSION);
    buf.extend_from_slice(&send_bps.to_be_bytes());
    buf.extend_from_slice(&recv_bps.to_be_bytes());
    buf.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    buf.extend_from_slice(auth);
    buf
}

/// serverHello 读取：[OK][SendBPS BE][RecvBPS BE][MessageLen BE][Message]
pub(crate) async fn read_server_hello<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(bool, u64, u64, String)> {
    let mut head = [0u8; 1 + 8 + 8 + 2];
    reader
        .read_exact(&mut head)
        .await
        .context("serverHello 头读取失败")?;
    let ok = head[0] != 0;
    let send_bps = u64::from_be_bytes(head[1..9].try_into().unwrap());
    let recv_bps = u64::from_be_bytes(head[9..17].try_into().unwrap());
    let msg_len = u16::from_be_bytes(head[17..19].try_into().unwrap()) as usize;
    let mut msg = vec![0u8; msg_len];
    reader
        .read_exact(&mut msg)
        .await
        .context("serverHello 消息读取失败")?;
    Ok((
        ok,
        send_bps,
        recv_bps,
        String::from_utf8_lossy(&msg).into_owned(),
    ))
}

/// clientRequest：[UDP][HostLen BE][Host][Port BE]（bool 一字节）
pub(crate) fn pack_client_request(udp: bool, host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 2 + host.len() + 2);
    buf.push(udp as u8);
    buf.extend_from_slice(&(host.len() as u16).to_be_bytes());
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// serverResponse 读取：[OK][UDPSessionID BE][MessageLen BE][Message]
pub(crate) async fn read_server_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(bool, u32, String)> {
    let mut head = [0u8; 1 + 4 + 2];
    reader
        .read_exact(&mut head)
        .await
        .context("serverResponse 头读取失败")?;
    let ok = head[0] != 0;
    let session_id = u32::from_be_bytes(head[1..5].try_into().unwrap());
    let msg_len = u16::from_be_bytes(head[5..7].try_into().unwrap()) as usize;
    let mut msg = vec![0u8; msg_len];
    reader
        .read_exact(&mut msg)
        .await
        .context("serverResponse 消息读取失败")?;
    Ok((ok, session_id, String::from_utf8_lossy(&msg).into_owned()))
}

/// 解析后的 v1 UDPMessage（数据报头 + 地址 + 载荷切片）
pub(crate) struct ParsedUdpMessage<'a> {
    pub session_id: u32,
    pub host: String,
    pub port: u16,
    pub msg_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub data: &'a [u8],
}

/// udpMessage 编码：[SessionID BE][HostLen BE][Host][Port BE][MsgID BE]
/// [FragID][FragCount][DataLen BE][Data]（官方同构；未分片 FragCount=1，
/// MsgID 不相关；分片时 MsgID 必须非零）
pub(crate) fn encode_udp_message(
    session_id: u32,
    host: &str,
    port: u16,
    msg_id: u16,
    frag_id: u8,
    frag_count: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 2 + host.len() + 2 + 2 + 1 + 1 + 2 + data.len());
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&(host.len() as u16).to_be_bytes());
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&msg_id.to_be_bytes());
    buf.push(frag_id);
    buf.push(frag_count);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// 数据报解析（越界/截断 → None，静默丢弃口径同官方 struc.Unpack 失败 continue）
pub(crate) fn parse_udp_message(buf: &[u8]) -> Option<ParsedUdpMessage<'_>> {
    // 最短头：4(session)+2(host_len)+0(host)+2(port)+2(msg_id)+1+1+2(data_len)
    if buf.len() < 14 {
        return None;
    }
    let session_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let host_len = u16::from_be_bytes(buf[4..6].try_into().unwrap()) as usize;
    let host_end = 6usize.checked_add(host_len)?;
    if host_end + 8 > buf.len() {
        return None;
    }
    let host = String::from_utf8_lossy(&buf[6..host_end]).into_owned();
    let port = u16::from_be_bytes(buf[host_end..host_end + 2].try_into().unwrap());
    let msg_id = u16::from_be_bytes(buf[host_end + 2..host_end + 4].try_into().unwrap());
    let frag_id = buf[host_end + 4];
    let frag_count = buf[host_end + 5];
    let data_len = u16::from_be_bytes(buf[host_end + 6..host_end + 8].try_into().unwrap()) as usize;
    let data_start = host_end + 8;
    let data_end = data_start.checked_add(data_len)?;
    if data_end > buf.len() {
        return None;
    }
    Some(ParsedUdpMessage {
        session_id,
        host,
        port,
        msg_id,
        frag_id,
        frag_count,
        data: &buf[data_start..data_end],
    })
}

// ===== 分片重装配（官方 core/cs/frag.go defragger 逐语义镜像） =====

/// 官方 defragger 语义：FragCount<=1 直通；FragID >= FragCount 丢弃；
/// MsgID 变化或分片数不匹配 → 整体重置（官方无超时，状态随新消息自愈）；
/// 重复分片（槽位已占）丢弃；集齐即按 FragID 序拼接。此处仅增本地加固：
/// 滞留分片超过 FRAG_REASSEMBLY_TIMEOUT 后视作废弃（下一片触发重置）——
/// 不改任何合法流量线行为（与 Hysteria2 面同口径的内存自护）。
pub(crate) const FRAG_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// 重装配产物（host, port, 拼接载荷）
pub(crate) type AssembledUdp = (String, u16, Vec<u8>);

#[derive(Default)]
pub(crate) struct Defragger {
    msg_id: u16,
    frags: Vec<Option<Vec<u8>>>,
    count: usize,
    born: Option<Instant>,
}

impl Defragger {
    pub(crate) fn feed(&mut self, msg: &ParsedUdpMessage<'_>) -> Option<AssembledUdp> {
        if msg.frag_count <= 1 {
            return Some((msg.host.clone(), msg.port, msg.data.to_vec()));
        }
        if msg.frag_id >= msg.frag_count {
            return None;
        }
        // 本地加固：滞留分片超时废弃（官方无此检查；仅丢弃停滞状态）
        if let Some(born) = self.born {
            if born.elapsed() > FRAG_REASSEMBLY_TIMEOUT {
                self.frags.clear();
                self.count = 0;
                self.born = None;
            }
        }
        if msg.msg_id != self.msg_id || msg.frag_count as usize != self.frags.len() {
            // 新消息：清空既往状态（官方口径）
            self.msg_id = msg.msg_id;
            self.frags = vec![None; msg.frag_count as usize];
            self.count = 1;
            self.frags[msg.frag_id as usize] = Some(msg.data.to_vec());
            self.born = Some(Instant::now());
            return None;
        }
        if self.frags[msg.frag_id as usize].is_none() {
            self.frags[msg.frag_id as usize] = Some(msg.data.to_vec());
            self.count += 1;
            if self.count == self.frags.len() {
                // 集齐：按 FragID 序拼接（官方拼后状态保留，重复分片仍丢弃）
                let mut data = Vec::with_capacity(
                    self.frags
                        .iter()
                        .map(|f| f.as_ref().map_or(0, |p| p.len()))
                        .sum(),
                );
                for piece in self.frags.iter().flatten() {
                    data.extend_from_slice(piece);
                }
                return Some((msg.host.clone(), msg.port, data));
            }
        }
        None
    }
}

// ===== 参数解析（TCP/UDP 两面共用） =====

/// 认证字节解析（官方 app/cmd/client.go：len(Auth) > 0 取 Auth，否则
/// []byte(AuthString)；IR 必填 password 兜底末位）
pub(crate) fn resolve_auth_bytes(
    auth: Option<&String>,
    auth_str: Option<&String>,
    password: &str,
) -> Vec<u8> {
    if let Some(a) = auth.filter(|a| !a.is_empty()) {
        return a.clone().into_bytes();
    }
    if let Some(s) = auth_str.filter(|s| !s.is_empty()) {
        return s.clone().into_bytes();
    }
    password.as_bytes().to_vec()
}

/// 速率申报（BPS）：None → 缺省 50/100 Mbps（订阅转换同值）；Some(0)
/// 点名拒绝（官方 stringToBps 0 判非法；服务端硬性要求非零）
pub(crate) fn resolve_rates(up_mbps: Option<u32>, down_mbps: Option<u32>) -> Result<(u64, u64)> {
    let up = match up_mbps {
        None => DEFAULT_UP_MBPS as u64 * MBPS_TO_BPS,
        Some(0) => bail!("Hysteria v1 up_mbps 为 0——官方服务端硬性要求速率非零"),
        Some(v) => v as u64 * MBPS_TO_BPS,
    };
    let down = match down_mbps {
        None => DEFAULT_DOWN_MBPS as u64 * MBPS_TO_BPS,
        Some(0) => bail!("Hysteria v1 down_mbps 为 0——官方服务端硬性要求速率非零"),
        Some(v) => v as u64 * MBPS_TO_BPS,
    };
    Ok((up, down))
}

/// ALPN：缺省 ["hysteria"]（官方 NextProtos = [config.ALPN] 口径）；
/// 提供则原样呈报（QUIC TLS 强制 ALPN 协商，错配在握手指名）
pub(crate) fn resolve_alpn(alpn: Option<&Vec<String>>) -> Vec<Vec<u8>> {
    match alpn.filter(|l| !l.is_empty()) {
        Some(list) => list.iter().map(|p| p.clone().into_bytes()).collect(),
        None => vec![b"hysteria".to_vec()],
    }
}

/// 载体/混淆构建期校验（TCP/UDP 两面同口径）
pub(crate) fn validate_carrier(
    protocol: Option<&String>,
    obfs: Option<&String>,
    obfs_param: Option<&String>,
) -> Result<()> {
    if let Some(p) = protocol {
        if p != "udp" {
            return Err(anyhow!(
                "Hysteria v1 protocol 仅支持 \"udp\"（got {p:?}）——obfs/wechat/faketcp 包层传输不交付"
            ));
        }
    }
    if obfs.is_some() || obfs_param.is_some() {
        return Err(anyhow!(
            "Hysteria v1 暂不支持 obfs/obfs_param（XPlus 混淆包层不交付）"
        ));
    }
    Ok(())
}

// ===== 连接器 =====

/// Hysteria v1 出口连接器（TCP 面）
pub struct HysteriaConnector {
    server: String,
    port: u16,
    password: String,
    /// 载体协议（IR protocol 字段；缺省 "udp"——非 "udp" 点名拒绝：
    /// obfs/wechat/faketcp 包层传输不交付）
    protocol: Option<String>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    /// 认证字节（官方 Auth []byte——auth > auth_str > password 兜底解析）
    auth: Option<String>,
    auth_str: Option<String>,
    obfs: Option<String>,
    obfs_param: Option<String>,
    server_name: Option<String>,
    skip_cert_verify: bool,
    alpn: Option<Vec<String>>,
    conn: Mutex<Option<super::hysteria2::RetainedConn>>,
}

impl HysteriaConnector {
    /// 参数面镜像 `EgressConfig::Hysteria` 字段 1:1，不收敛 options 结构
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        password: String,
        protocol: Option<String>,
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        auth: Option<String>,
        auth_str: Option<String>,
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
            protocol,
            up_mbps,
            down_mbps,
            auth,
            auth_str,
            obfs,
            obfs_param,
            server_name,
            skip_cert_verify,
            alpn,
            conn: Mutex::new(None),
        }
    }

    fn resolve_rates(&self) -> Result<(u64, u64)> {
        resolve_rates(self.up_mbps, self.down_mbps)
    }

    fn validate_config(&self) -> Result<()> {
        validate_carrier(
            self.protocol.as_ref(),
            self.obfs.as_ref(),
            self.obfs_param.as_ref(),
        )?;
        self.resolve_rates()?;
        Ok(())
    }

    async fn connect_conn(&self) -> Result<super::hysteria2::RetainedConn> {
        self.validate_config()?;
        let (send_bps, recv_bps) = self.resolve_rates()?;
        let auth = resolve_auth_bytes(self.auth.as_ref(), self.auth_str.as_ref(), &self.password);
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            establish_quic_link(
                &self.server,
                self.port,
                &auth,
                send_bps,
                recv_bps,
                self.server_name.as_deref(),
                self.skip_cert_verify,
                resolve_alpn(self.alpn.as_ref()),
            ),
        )
        .await
        .map_err(|_| anyhow!("Hysteria v1 连接建立超时（{}s）", CONNECT_TIMEOUT.as_secs()))?
    }

    async fn get_or_connect_conn(&self) -> Result<super::hysteria2::RetainedConn> {
        self.validate_config()?;
        let mut guard = self.conn.lock().await;
        if let Some(retained) = guard.as_ref() {
            return Ok(super::hysteria2::RetainedConn {
                conn: retained.conn.clone(),
                endpoint: retained.endpoint.clone(),
            });
        }
        // 持锁跨握手（single-flight 语义），超时不缓存半成品（fail-closed）
        let retained = self.connect_conn().await?;
        *guard = Some(super::hysteria2::RetainedConn {
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

/// 建立 QUIC 链路并完成 v1 控制流认证（TCP/UDP 两面共用链路面）。认证/协议
/// 面失败由 control_stream_auth 按官方口径回发应用错误码（认证错误 2 /
/// 协议错误 1）后收束连接。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn establish_quic_link(
    server: &str,
    port: u16,
    auth: &[u8],
    send_bps: u64,
    recv_bps: u64,
    server_name: Option<&str>,
    skip_cert_verify: bool,
    alpn: Vec<Vec<u8>>,
) -> Result<super::hysteria2::RetainedConn> {
    let server_name = server_name.unwrap_or(server);
    let server_addr: SocketAddr = tokio::net::lookup_host((server, port))
        .await
        .with_context(|| format!("Hysteria v1 服务器地址解析失败: {server}"))?
        .next()
        .ok_or_else(|| anyhow!("Hysteria v1 服务器地址解析为空: {server}"))?;

    // v1 TLS 口径：最低 TLS 1.3（官方 client.go MinVersion），ALPN 配置旋钮
    let provider = crate::tls::tls_crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?;
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
    crypto.alpn_protocols = alpn;

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)
        .context("Hysteria v1 QUIC 端点创建失败")?;
    let quinn_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow!("Hysteria v1 QUIC TLS 配置失败: {e}"))?,
    ));
    endpoint.set_default_client_config(quinn_cfg);

    let connecting = endpoint
        .connect(server_addr, server_name)
        .context("Hysteria v1 QUIC 连接发起失败")?;
    let conn = tokio::time::timeout(PROTOCOL_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            anyhow!(
                "Hysteria v1 QUIC 握手超时（{}s）",
                PROTOCOL_TIMEOUT.as_secs()
            )
        })?
        .context("Hysteria v1 QUIC 连接失败")?;

    tokio::time::timeout(
        PROTOCOL_TIMEOUT,
        control_stream_auth(&conn, auth, send_bps, recv_bps),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Hysteria v1 控制流认证超时（{}s）",
            PROTOCOL_TIMEOUT.as_secs()
        )
    })?
    .context("Hysteria v1 认证失败")?;

    Ok(super::hysteria2::RetainedConn { conn, endpoint })
}

/// 控制流认证（每连接首条客户端双向流；官方 core/cs client.handleControlStream
/// 镜像）。授权速率仅过校验/对端观测——Brutal CC 不交付（QUIC 缺省 CC）。
/// 失败面：官方 !ok → qErrorAuth(2)，其余协议面失败 → qErrorProtocol(1)，
/// 均先对连接回发错误码再返回 Err。
async fn control_stream_auth(
    conn: &quinn::Connection,
    auth: &[u8],
    send_bps: u64,
    recv_bps: u64,
) -> Result<(u64, u64)> {
    match control_stream_auth_inner(conn, auth, send_bps, recv_bps).await {
        Err(ControlAuthError::Rejected(msg)) => {
            conn.close(quinn::VarInt::from_u32(QERR_AUTH), b"auth error");
            Err(anyhow!("Hysteria v1 认证被拒绝：{msg}"))
        }
        Err(ControlAuthError::Protocol(step, e)) => {
            conn.close(quinn::VarInt::from_u32(QERR_PROTOCOL), b"protocol error");
            Err(e).with_context(|| format!("Hysteria v1 控制流失败（{step}）"))
        }
        Ok(rates) => Ok(rates),
    }
}

/// 控制流失败分流（!ok serverHello = 认证拒绝；其余 = 协议面失败——
/// 错误码分流用，不外泄类型）
enum ControlAuthError {
    Rejected(String),
    Protocol(&'static str, anyhow::Error),
}

impl From<ControlAuthError> for anyhow::Error {
    fn from(err: ControlAuthError) -> Self {
        match err {
            ControlAuthError::Rejected(msg) => anyhow!("Hysteria v1 认证被拒绝：{msg}"),
            ControlAuthError::Protocol(step, e) => {
                e.context(format!("Hysteria v1 控制流失败（{step}）"))
            }
        }
    }
}

async fn control_stream_auth_inner(
    conn: &quinn::Connection,
    auth: &[u8],
    send_bps: u64,
    recv_bps: u64,
) -> Result<(u64, u64), ControlAuthError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
        ControlAuthError::Protocol("控制流打开", anyhow!("Hysteria v1 控制流打开失败: {e}"))
    })?;
    send.write_all(&pack_client_hello(send_bps, recv_bps, auth))
        .await
        .map_err(|e| {
            ControlAuthError::Protocol(
                "clientHello 发送",
                anyhow!("Hysteria v1 clientHello 发送失败: {e}"),
            )
        })?;
    let (ok, granted_send, granted_recv, msg) =
        read_server_hello(&mut recv).await.map_err(|e| {
            ControlAuthError::Protocol(
                "serverHello 读取",
                anyhow!("Hysteria v1 serverHello 读取失败: {e}"),
            )
        })?;
    if !ok {
        return Err(ControlAuthError::Rejected(msg));
    }
    tracing::debug!(
        target: "rillane::hysteria",
        granted_send_bps = granted_send,
        granted_recv_bps = granted_recv,
        "Hysteria v1 认证通过（Brutal CC 不交付，QUIC 缺省 CC 承载）"
    );
    Ok((granted_send, granted_recv))
}

/// 在已认证连接上开一条 TCP 请求流（官方 client.DialTCP 非快速打开口径：
/// 发 clientRequest 后读 serverResponse，OK 后双向搬运；拒绝仅收流不收连接）
async fn open_tcp_stream(
    conn: &quinn::Connection,
    host: &str,
    port: u16,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = conn.open_bi().await.context("Hysteria v1 流打开失败")?;
    send.write_all(&pack_client_request(false, host, port))
        .await
        .context("Hysteria v1 TCP 请求发送失败")?;
    let (ok, _, msg) = read_server_response(&mut recv)
        .await
        .context("Hysteria v1 TCP 响应读取失败")?;
    if !ok {
        return Err(anyhow!("Hysteria v1 服务端拒绝 TCP 请求: {msg}"));
    }
    Ok((send, recv))
}

#[async_trait]
impl EgressConnector for HysteriaConnector {
    fn name(&self) -> &'static str {
        "hysteria"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            other => {
                return Err(anyhow!("Hysteria v1 暂仅支持 TCP 转发（got {:?}）", other));
            }
        }

        // 线面 host 字段裸形（官方 SplitHostPort 后不含方括号——"[::1]" 归一）
        let target_host = bare_host(&flow.target.host).to_string();
        let target_port = flow.target.port;
        let target_addr = format!("{target_host}:{target_port}");
        let server_addr = format!("{}:{}", self.server, self.port);

        tracing::debug!(
            target: "rillane::hysteria",
            id = %flow.id.as_uuid(),
            target = %target_addr,
            server = %server_addr,
            "通过 Hysteria v1 连接"
        );

        let retained = self.get_or_connect_conn().await?;
        let mut outbound = match open_tcp_stream(&retained.conn, &target_host, target_port).await {
            Ok((send, recv)) => super::hysteria2::QuicDuplex { send, recv },
            Err(err) => {
                tracing::warn!(
                    target: "rillane::hysteria",
                    id = %flow.id.as_uuid(),
                    target = %target_addr,
                    server = %server_addr,
                    error = %err,
                    "Hysteria v1 tcp_connect 失败，尝试重连并重试"
                );

                self.invalidate_conn().await;
                let retained = self.get_or_connect_conn().await?;
                let (send, recv) = open_tcp_stream(&retained.conn, &target_host, target_port)
                    .await
                    .with_context(|| format!("Hysteria v1 tcp_connect 失败: {target_addr}"))?;
                super::hysteria2::QuicDuplex { send, recv }
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

// ===== UDP 中继面（官方 DialUDP + udpMessage 数据报，RIL-109） =====

/// send_datagram_wait 背压上限（QUIC 数据报缓冲满时等待，超时判连接不可用；
/// 与 Hysteria2 面同口径）
pub(crate) const DGRAM_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// 下行重装配输出队列深度
const DOWNLINK_QUEUE: usize = 64;

/// 会话级统计（验收面：分片丢弃/外来会话可观测）
#[derive(Default)]
pub struct HysteriaUdpStats {
    /// 外来会话数据报（session 不匹配，静默丢弃计数）
    pub foreign_dropped: AtomicU64,
    /// 畸形/非法分片丢弃计数
    pub frag_dropped: AtomicU64,
}

/// Hysteria v1 UDP 出站连接器
pub struct HysteriaUdpConnector {
    server: String,
    port: u16,
    password: String,
    protocol: Option<String>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    auth: Option<String>,
    auth_str: Option<String>,
    obfs: Option<String>,
    obfs_param: Option<String>,
    server_name: Option<String>,
    skip_cert_verify: bool,
    alpn: Option<Vec<String>>,
}

impl HysteriaUdpConnector {
    /// 与 TCP 面同一份节点配置（from_connector 语义，见 shadowsocks 同例）
    pub fn from_connector(conn: &HysteriaConnector) -> Self {
        Self {
            server: conn.server.clone(),
            port: conn.port,
            password: conn.password.clone(),
            protocol: conn.protocol.clone(),
            up_mbps: conn.up_mbps,
            down_mbps: conn.down_mbps,
            auth: conn.auth.clone(),
            auth_str: conn.auth_str.clone(),
            obfs: conn.obfs.clone(),
            obfs_param: conn.obfs_param.clone(),
            server_name: conn.server_name.clone(),
            skip_cert_verify: conn.skip_cert_verify,
            alpn: conn.alpn.clone(),
        }
    }

    /// 关联并返回具体中继句柄（验收面：会话统计可观测；trait 面 `associate`
    /// 委托此方法）
    pub async fn connect_relay(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<HysteriaUdpRelay>> {
        validate_carrier(
            self.protocol.as_ref(),
            self.obfs.as_ref(),
            self.obfs_param.as_ref(),
        )?;
        let (send_bps, recv_bps) = resolve_rates(self.up_mbps, self.down_mbps)?;
        let auth = resolve_auth_bytes(self.auth.as_ref(), self.auth_str.as_ref(), &self.password);

        // 独立链路（认证面同控制流口径；生命周期归中继——drop 即收束）
        let link = establish_quic_link(
            &self.server,
            self.port,
            &auth,
            send_bps,
            recv_bps,
            self.server_name.as_deref(),
            self.skip_cert_verify,
            resolve_alpn(self.alpn.as_ref()),
        )
        .await?;

        // UDP 会话请求流：[UDP=true][HostLen=0][Port=0] → 响应携带 UDPSessionID
        let (mut send, mut recv) = link
            .conn
            .open_bi()
            .await
            .context("Hysteria v1 流打开失败")?;
        send.write_all(&pack_client_request(true, "", 0))
            .await
            .context("Hysteria v1 UDP 请求发送失败")?;
        let (ok, session_id, msg) = read_server_response(&mut recv)
            .await
            .context("Hysteria v1 UDP 响应读取失败")?;
        if !ok {
            return Err(anyhow!("Hysteria v1 服务端拒绝 UDP 会话: {msg}"));
        }

        let max_dgram = link
            .conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("Hysteria v1 对端不支持 QUIC 数据报（无法承载 UDP 中继）"))?;

        let stats = Arc::new(HysteriaUdpStats::default());
        let (tx, rx) = mpsc::channel::<(FlowTarget, Vec<u8>)>(DOWNLINK_QUEUE);

        // 会话保活任务（官方 hyUDPConn.Hold 镜像：流存活即会话存活——读至
        // EOF/错误自然收束；send/recv 句柄持于任务内维持流不关）
        {
            tokio::spawn(async move {
                let _keep_send = send;
                let mut scratch = [0u8; 1024];
                while let Ok(read) = recv.read(&mut scratch).await {
                    if read.is_none() {
                        break;
                    }
                }
            });
        }

        // 下行任务：读 QUIC 数据报 → 解析 → 会话过滤 → 重装配 → 投递
        let recv_stats = stats.clone();
        let recv_conn = link.conn.clone();
        let sid = session_id;
        let task = tokio::spawn(async move {
            let mut defragger = Defragger::default();
            while let Ok(buf) = recv_conn.read_datagram().await {
                let Some(msg) = parse_udp_message(&buf) else {
                    recv_stats.frag_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if msg.session_id != sid {
                    recv_stats.foreign_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if let Some((host, port, whole)) = defragger.feed(&msg) {
                    // 线面 host/port 独立字段——直接构造目标（官方服务端下行
                    // host 为裸 IP 串，拼接重劈分会误折 IPv6）
                    let target = FlowTarget {
                        host,
                        port,
                        proto: TargetProto::Udp,
                    };
                    if tx.send((target, whole)).await.is_err() {
                        break; // 中继已 drop
                    }
                }
            }
            // Err → 连接关闭/丢失 → 任务收束（资源释放面）
        });

        Ok(Arc::new(HysteriaUdpRelay {
            endpoint: link.endpoint,
            conn: link.conn,
            session_id,
            _fixed_target: ctx.target,
            max_dgram,
            stats,
            msg_id: AtomicU16::new(1), // 分片 MsgID 必须非零，从 1 起循环
            downlink: Mutex::new(rx),
            downlink_task: task,
        }))
    }
}

/// 字节级 Hysteria v1 UDP 中继：QUIC 连接 + 服务端授予的 UDPSessionID +
/// 下行重装配任务
pub struct HysteriaUdpRelay {
    /// 仅持句柄：保活 QUIC 端点（Drop 时全部关联连接随之收束）
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    session_id: u32,
    /// 会话默认目标（R7 固定目标语义；数据报协议头逐包携带，发送以参数为准）
    _fixed_target: FlowTarget,
    max_dgram: usize,
    stats: Arc<HysteriaUdpStats>,
    /// 分片 MsgID 计数器（官方随机非零；此处从 1 递增循环——线语义等价，
    /// 非零即可）
    msg_id: AtomicU16,
    /// 下行队列（tokio Mutex：UdpRelay::recv_from 是 &self 面）
    downlink: Mutex<mpsc::Receiver<(FlowTarget, Vec<u8>)>>,
    downlink_task: tokio::task::JoinHandle<()>,
}

impl HysteriaUdpRelay {
    /// 会话统计句柄（验收面：取消/资源释放与分片丢弃计数可观测）
    pub fn stats(&self) -> &Arc<HysteriaUdpStats> {
        &self.stats
    }

    /// 数据报头长（不含载荷）：4(session)+2(host_len)+host+2(port)+2(msg_id)
    /// +1(frag_id)+1(frag_count)+2(data_len)
    fn header_len(host_len: usize) -> usize {
        12 + host_len
    }
}

#[async_trait]
impl UdpRelay for HysteriaUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        // 线面 host/port 独立字段：host 裸形（官方 SplitHostPort 后不含方括号）
        let host = bare_host(&target.host);
        let overhead = Self::header_len(host.len());
        let max_dgram = self.max_dgram;

        // 单包直发（官方口径 FragCount=1，MsgID 不相关恒 0）
        if buf.len() + overhead <= max_dgram {
            let msg = encode_udp_message(self.session_id, host, target.port, 0, 0, 1, buf);
            self.send_datagram(msg).await?;
            return Ok(());
        }

        // 分片：同一非零 MsgID，Fragment ID 0..count（官方 §fragUDPMessage）
        let per_frag = max_dgram.saturating_sub(overhead);
        if per_frag == 0 {
            return Err(anyhow!(
                "Hysteria v1 QUIC 数据报过小（{max_dgram}B），无法承载 UDP 分片头"
            ));
        }
        if per_frag > u16::MAX as usize {
            // DataLen 为 u16（官方线格式）：分片载荷上限钉在 65535
            return Err(anyhow!(
                "Hysteria v1 分片载荷上限 65535B（got {per_frag}B）"
            ));
        }
        let count = buf.len().div_ceil(per_frag);
        if count > u8::MAX as usize {
            return Err(anyhow!(
                "Hysteria v1 UDP 载荷过大（{}B，需 {count} 分片 > 255 上限）",
                buf.len()
            ));
        }
        let msg_id = {
            // 非零循环计数（官方随机非零；线语义等价）
            let id = self.msg_id.fetch_add(1, Ordering::Relaxed);
            if id == 0 {
                self.msg_id.store(1, Ordering::Relaxed);
                1
            } else {
                id
            }
        };
        for (frag_id, chunk) in buf.chunks(per_frag).enumerate() {
            let msg = encode_udp_message(
                self.session_id,
                host,
                target.port,
                msg_id,
                frag_id as u8,
                count as u8,
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
            .ok_or_else(|| anyhow!("Hysteria v1 UDP 中继已关闭（QUIC 连接断开）"))?;
        if payload.len() > buf.len() {
            return Err(anyhow!(
                "Hysteria v1 UDP 下行载荷 {}B 超过接收缓冲 {}B",
                payload.len(),
                buf.len()
            ));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((target, payload.len()))
    }
}

impl HysteriaUdpRelay {
    async fn send_datagram(&self, msg: Vec<u8>) -> Result<()> {
        let wait = self.conn.send_datagram_wait(Bytes::from(msg));
        match tokio::time::timeout(DGRAM_SEND_TIMEOUT, wait).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(anyhow!("Hysteria v1 QUIC 数据报发送失败: {e}")),
            Err(_) => Err(anyhow!(
                "Hysteria v1 QUIC 数据报缓冲满超时（{}s）——连接不可用",
                DGRAM_SEND_TIMEOUT.as_secs()
            )),
        }
    }
}

impl Drop for HysteriaUdpRelay {
    fn drop(&mut self) {
        // QUIC 连接随 relay 生命周期收束（资源释放面：对端可观 propagate close）
        self.conn.close(0u32.into(), b"hysteria udp relay dropped");
        self.downlink_task.abort();
    }
}

/// 裸 host 形：剥 IPv6 字面量方括号（官方 SplitHostPort 后线面 host 不含
/// 方括号——v1 线 host/port 为独立字段，拼接形不可入线）
pub(crate) fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

#[async_trait]
impl EgressUdpConnector for HysteriaUdpConnector {
    fn name(&self) -> &str {
        "hysteria"
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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 控制流编解码（全 BE 口径） ----

    #[test]
    fn client_hello_wire_is_big_endian() {
        let wire = pack_client_hello(50 * MBPS_TO_BPS, 100 * MBPS_TO_BPS, b"letmein");
        assert_eq!(wire[0], 0x03); // 版本字节
        assert_eq!(&wire[1..9], &(50_000_000u64).to_be_bytes());
        assert_eq!(&wire[9..17], &(100_000_000u64).to_be_bytes());
        assert_eq!(&wire[17..19], &7u16.to_be_bytes()); // AuthLen BE
        assert_eq!(&wire[19..], b"letmein");
        assert_eq!(wire.len(), 26);
    }

    #[test]
    fn client_hello_empty_auth() {
        let wire = pack_client_hello(1, 2, b"");
        assert_eq!(&wire[17..19], &0u16.to_be_bytes());
        assert_eq!(wire.len(), 19);
    }

    #[tokio::test]
    async fn server_hello_roundtrip() {
        let mut wire = Vec::new();
        wire.push(1u8); // OK
        wire.extend_from_slice(&(30_000_000u64).to_be_bytes());
        wire.extend_from_slice(&(80_000_000u64).to_be_bytes());
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(b"abc");
        let (ok, send, recv, msg) = read_server_hello(&mut &wire[..]).await.unwrap();
        assert!(ok);
        assert_eq!(send, 30_000_000);
        assert_eq!(recv, 80_000_000);
        assert_eq!(msg, "abc");
    }

    #[tokio::test]
    async fn server_hello_reject_and_empty_message() {
        let mut wire = Vec::new();
        wire.push(0u8); // !OK
        wire.extend_from_slice(&0u64.to_be_bytes());
        wire.extend_from_slice(&0u64.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        let (ok, send, recv, msg) = read_server_hello(&mut &wire[..]).await.unwrap();
        assert!(!ok);
        assert_eq!(send, 0);
        assert_eq!(recv, 0);
        assert_eq!(msg, "");
    }

    // ---- 请求/响应编解码 ----

    #[test]
    fn client_request_tcp_wire() {
        let wire = pack_client_request(false, "example.com", 443);
        assert_eq!(wire[0], 0); // UDP=false
        assert_eq!(&wire[1..3], &11u16.to_be_bytes());
        assert_eq!(&wire[3..14], b"example.com");
        assert_eq!(&wire[14..16], &443u16.to_be_bytes());
        assert_eq!(wire.len(), 16);
    }

    #[test]
    fn client_request_udp_wire_has_empty_host() {
        let wire = pack_client_request(true, "", 0);
        assert_eq!(wire, vec![1, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn server_response_roundtrip() {
        let mut wire = Vec::new();
        wire.push(1u8);
        wire.extend_from_slice(&42u32.to_be_bytes()); // UDPSessionID
        wire.extend_from_slice(&0u16.to_be_bytes());
        let (ok, session, msg) = read_server_response(&mut &wire[..]).await.unwrap();
        assert!(ok);
        assert_eq!(session, 42);
        assert_eq!(msg, "");
    }

    #[tokio::test]
    async fn server_response_rejection_carries_message() {
        let mut wire = Vec::new();
        wire.push(0u8);
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(b"no");
        let (ok, session, msg) = read_server_response(&mut &wire[..]).await.unwrap();
        assert!(!ok);
        assert_eq!(session, 0);
        assert_eq!(msg, "no");
    }

    // ---- UDPMessage 编解码 ----

    #[test]
    fn udp_message_roundtrip_unfragmented() {
        let wire = encode_udp_message(7, "1.2.3.4", 53, 0, 0, 1, b"query");
        let msg = parse_udp_message(&wire).expect("解析失败");
        assert_eq!(msg.session_id, 7);
        assert_eq!(msg.host, "1.2.3.4");
        assert_eq!(msg.port, 53);
        assert_eq!(msg.msg_id, 0);
        assert_eq!(msg.frag_id, 0);
        assert_eq!(msg.frag_count, 1);
        assert_eq!(msg.data, b"query");
    }

    #[test]
    fn udp_message_truncated_inputs_rejected() {
        // 全空
        assert!(parse_udp_message(&[]).is_none());
        // 头截断
        assert!(parse_udp_message(&[0u8; 13]).is_none());
        // host 越界
        let mut wire = encode_udp_message(1, "abcd", 1, 0, 0, 1, b"x");
        wire[4] = 0xFF; // host_len 虚标
        wire[5] = 0xFF;
        assert!(parse_udp_message(&wire).is_none());
        // data_len 虚标越界
        let mut wire = encode_udp_message(1, "a", 1, 0, 0, 1, b"x");
        let last = wire.len() - 2;
        wire[last] = 0xFF;
        wire[last + 1] = 0xFF;
        assert!(parse_udp_message(&wire).is_none());
    }

    // ---- 分片重装配（官方 defragger 逐语义镜像） ----

    fn frag_msg(msg_id: u16, frag_id: u8, frag_count: u8, data: &[u8]) -> Vec<u8> {
        encode_udp_message(9, "h", 1, msg_id, frag_id, frag_count, data)
    }

    #[test]
    fn defragger_passthrough_unfragmented() {
        let mut d = Defragger::default();
        let wire = encode_udp_message(1, "a.b", 5, 0, 0, 1, b"plain");
        let (host, port, data) = d.feed(&parse_udp_message(&wire).unwrap()).unwrap();
        assert_eq!(
            (host.as_str(), port, data.as_slice()),
            ("a.b", 5, b"plain".as_slice())
        );
    }

    #[test]
    fn defragger_invalid_frag_id_dropped() {
        let mut d = Defragger::default();
        let wire = frag_msg(5, 3, 2, b"x"); // FragID >= FragCount
        assert!(d.feed(&parse_udp_message(&wire).unwrap()).is_none());
    }

    #[test]
    fn defragger_assembles_in_order_and_out_of_order() {
        // 顺序
        let mut d = Defragger::default();
        let f0 = frag_msg(5, 0, 2, b"he");
        let f1 = frag_msg(5, 1, 2, b"llo");
        assert!(d.feed(&parse_udp_message(&f0).unwrap()).is_none());
        let (host, port, data) = d.feed(&parse_udp_message(&f1).unwrap()).unwrap();
        assert_eq!((host.as_str(), port), ("h", 1));
        assert_eq!(data, b"hello");

        // 乱序（1 先到）
        let mut d = Defragger::default();
        let f0 = frag_msg(6, 0, 2, b"he");
        let f1 = frag_msg(6, 1, 2, b"llo");
        assert!(d.feed(&parse_udp_message(&f1).unwrap()).is_none());
        let (_, _, data) = d.feed(&parse_udp_message(&f0).unwrap()).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn defragger_msgid_change_resets_state() {
        let mut d = Defragger::default();
        let stale = frag_msg(5, 0, 2, b"stale");
        assert!(d.feed(&parse_udp_message(&stale).unwrap()).is_none());
        // 新 MsgID：旧分片整体作废；新内容正常集齐
        let f0 = frag_msg(7, 0, 2, b"new");
        let f1 = frag_msg(7, 1, 2, b"!");
        assert!(d.feed(&parse_udp_message(&f0).unwrap()).is_none());
        let (_, _, data) = d.feed(&parse_udp_message(&f1).unwrap()).unwrap();
        assert_eq!(data, b"new!");
    }

    #[test]
    fn defragger_count_mismatch_resets_state() {
        let mut d = Defragger::default();
        let f0 = frag_msg(5, 0, 3, b"aaa");
        assert!(d.feed(&parse_udp_message(&f0).unwrap()).is_none());
        // 同 MsgID 但 FragCount 变化 → 重置
        let f0 = frag_msg(5, 0, 2, b"bb");
        let f1 = frag_msg(5, 1, 2, b"cc");
        assert!(d.feed(&parse_udp_message(&f0).unwrap()).is_none());
        let (_, _, data) = d.feed(&parse_udp_message(&f1).unwrap()).unwrap();
        assert_eq!(data, b"bbcc");
    }

    #[test]
    fn defragger_duplicate_fragment_dropped() {
        let mut d = Defragger::default();
        let f0 = frag_msg(5, 0, 2, b"a");
        let dup = frag_msg(5, 0, 2, b"a");
        let f1 = frag_msg(5, 1, 2, b"b");
        assert!(d.feed(&parse_udp_message(&f0).unwrap()).is_none());
        assert!(d.feed(&parse_udp_message(&dup).unwrap()).is_none()); // 槽位已占
        let (_, _, data) = d.feed(&parse_udp_message(&f1).unwrap()).unwrap();
        assert_eq!(data, b"ab"); // 不因重复片损坏
    }

    #[test]
    fn defragger_three_fragment_assembly() {
        let mut d = Defragger::default();
        assert!(d
            .feed(&parse_udp_message(&frag_msg(9, 1, 3, b"222")).unwrap())
            .is_none());
        assert!(d
            .feed(&parse_udp_message(&frag_msg(9, 0, 3, b"111")).unwrap())
            .is_none());
        let (_, _, data) = d
            .feed(&parse_udp_message(&frag_msg(9, 2, 3, b"333")).unwrap())
            .unwrap();
        assert_eq!(data, b"111222333");
    }

    // ---- 认证/速率/ALPN 解析 ----

    #[test]
    fn auth_resolution_prefers_auth_then_auth_str_then_password() {
        assert_eq!(resolve_auth_bytes(None, None, "pw"), b"pw".to_vec()); // password 兜底
        assert_eq!(
            resolve_auth_bytes(None, Some(&"str".to_string()), "pw"),
            b"str".to_vec()
        );
        assert_eq!(
            resolve_auth_bytes(Some(&"raw".to_string()), Some(&"str".to_string()), "pw"),
            b"raw".to_vec()
        );
        // 空串不拦路（官方 len(Auth) > 0 口径）
        assert_eq!(
            resolve_auth_bytes(Some(&"".to_string()), Some(&"str".to_string()), "pw"),
            b"str".to_vec()
        );
    }

    #[test]
    fn rate_resolution_defaults_and_rejects_zero() {
        let (up, down) = resolve_rates(None, None).unwrap();
        assert_eq!(up, 50 * MBPS_TO_BPS); // 缺省 50/100（订阅转换同值）
        assert_eq!(down, 100 * MBPS_TO_BPS);

        let (up, down) = resolve_rates(Some(12), Some(34)).unwrap();
        assert_eq!(up, 12 * MBPS_TO_BPS);
        assert_eq!(down, 34 * MBPS_TO_BPS);

        // 任一侧显式 0 → 拒绝；(None, None) = 缺省非零（上方已验）
        for up in [Some(0u32)] {
            for down in [Some(0u32), None] {
                assert!(resolve_rates(up, down).is_err(), "up=0 必须拒绝");
            }
        }
        for down in [Some(0u32)] {
            for up in [None, Some(10u32)] {
                assert!(resolve_rates(up, down).is_err(), "down=0 必须拒绝");
            }
        }
    }

    #[test]
    fn carrier_validation_refuses_by_name() {
        for proto in ["obfs", "wechat", "faketcp", ""] {
            assert!(
                validate_carrier(Some(&proto.to_string()), None, None).is_err(),
                "protocol {proto:?} 必须拒绝"
            );
        }
        assert!(validate_carrier(None, None, None).is_ok()); // None = 缺省 udp
        assert!(validate_carrier(Some(&"udp".to_string()), None, None).is_ok());

        assert!(validate_carrier(None, Some(&"salamander".to_string()), None).is_err());
        assert!(validate_carrier(None, None, Some(&"p".to_string())).is_err());
    }

    #[test]
    fn alpn_defaults_to_hysteria() {
        assert_eq!(resolve_alpn(None), vec![b"hysteria".to_vec()]);
        assert_eq!(resolve_alpn(Some(&Vec::new())), vec![b"hysteria".to_vec()]);
        assert_eq!(
            resolve_alpn(Some(&vec!["custom".to_string()])),
            vec![b"custom".to_vec()]
        );
    }
}
