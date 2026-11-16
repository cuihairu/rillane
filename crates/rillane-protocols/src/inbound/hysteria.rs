//! Hysteria v1 服务端入口协议实现（RIL-109）
//!
//! 自写 server 面（评估见两语 protocol-backends.md hysteria 段——v1 无任何
//! 可用库：crates.io 无 v1 crate、GitHub 同名项目皆 v2 重写）。线格式以官方
//! aperet/hysteria v1.3.5 core/cs 为镜像口径（struc 默认大端打包，全部多字节
//! 字段 BE，bool 一字节）：
//! - 控制流（每连接首条被接受双向流，官方 protocolTimeout 10s）：读 [版本
//!   0x03][SendBPS BE][RecvBPS BE][AuthLen BE][Auth]，版本不符/速率申报任一
//!   为零 → 协议错误（应用错误码 1，连接收束）；授权 = min(对侧申报, 本端
//!   上限) 交换口径（serverSend = min(客户端 RecvBPS, up 上限)、serverRecv =
//!   min(客户端 SendBPS, down 上限)，上限 None = 不封顶）；口令恒时比对通过
//!   回 [OK][SendBPS BE][RecvBPS BE][MessageLen BE][Message]，失败回 !OK 后
//!   按官方口径发认证错误（应用错误码 2）收束；
//! - TCP：后续 accept_bi 流上读 `[UDP=false][HostLen BE][Host][Port BE]`，
//!   回 `[OK][UDPSessionID=0][MessageLen BE][Message]` 后原样双向搬运；
//!   解析/路由失败回 !OK + 文案；
//! - UDP：会话经 `[UDP=true][HostLen=0][Port=0]` 请求流建立（响应携带
//!   UDPSessionID——官方 per-connection 计数器 0 起；流存活即会话存活，官方
//!   Hold 语义镜像：会话流 EOF 即注销该 session 登记项）；数据报
//!   `[SessionID BE][HostLen BE][Host][Port BE][MsgID BE][FragID][FragCount]
//!   [DataLen BE][Data]`——上行重装配（outbound/hysteria.rs Defragger 镜像
//!   互源），下行超预算分片（MsgID 非零），会话生命周期归 `UdpSessionTable`
//!   （粘滞键 = QUIC 连接远端地址；连接收束即吊销本关联键）。
//!
//! QUIC 端点即入口监听（TLS 材料内联 PEM 装配期解析，ALPN 恒 "hysteria"，
//! QUIC 载具 TLS 1.3 硬性要求）。授权速率如实回发（线面镜像）——Brutal
//! 拥塞控制不交付（QUIC 缺省 CC）。不交付：obfs/wechat/faketcp 包层传输、
//! ACL、ACME、流量统计 API。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex, Once,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rustls::pki_types::pem::PemObject as _;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use rillane_core::udp::{
    DownlinkPacket, DropReason, EgressUdpConnector, UdpIngressMetrics, UdpSessionKey,
    UdpSessionTable, UpResult,
};
use rillane_core::{
    constant_time_eq, fake_ip, BoxedIo, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput,
    FlowRouter, FlowTarget, IngressEndpoint, TargetProto,
};

use crate::outbound::hysteria::{
    bare_host, encode_udp_message, parse_udp_message, Defragger, QERR_AUTH, QERR_PROTOCOL,
};
use crate::outbound::hysteria2::{QuicDuplex, DGRAM_SEND_TIMEOUT};
use crate::tls::tls_crypto_provider;

/// v1 协议版本（官方 core/cs/protocol.go protocolVersion = 3）
const PROTOCOL_VERSION: u8 = 0x03;
/// 官方 protocolTimeout：控制流握手全程上限（core/cs/protocol.go）
const PROTOCOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Mbps → BPS（官方 app/cmd/config.go mbpsToBps）
const MBPS_TO_BPS: u64 = 1_000_000;

/// Hysteria v1 UDP 关联面装配件：进程级会话表 + 出站连接器族（与 vless/vmess/
/// socks5 ASSOCIATE 同源共享，由 RuntimeBuilder 从 UdpAssociateService 抽出传入）
#[derive(Clone)]
pub struct HysteriaUdpParts {
    pub table: Arc<UdpSessionTable>,
    pub connector: Arc<dyn EgressUdpConnector>,
}

/// Hysteria v1 入口服务
#[derive(Clone)]
pub struct HysteriaIngress {
    name: String,
    bind: String,
    /// 认证基准：共享口令（恒时比对）
    password: String,
    /// 服务端发送速率上限 BPS（客户端下行向；None = 不设上限——官方 >0 才
    /// 施加上限口径）
    send_bps_cap: Option<u64>,
    /// 服务端接收速率上限 BPS（客户端上行向；语义同 send_bps_cap）
    recv_bps_cap: Option<u64>,
    /// QUIC 服务端配置（TLS 材料 + ALPN 已装配；Endpoint 在 run 期绑定）
    server_config: quinn::ServerConfig,
    /// UDP 关联面（None = 拒绝 UDP 会话请求——官方 disableUDP 口径回 !OK）
    udp: Option<HysteriaUdpParts>,
    /// fake-ip 池表（G1-10；None = 关闭，target 原样路由；TCP/UDP 两面共用）
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    /// 周期回收任务随 UDP 面启用拉起（与 associate 服务各自 Once——多 UDP
    /// 面并存时至多两路 sweep，幂等无害）
    reclaimer_once: Arc<Once>,
}

impl HysteriaIngress {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        bind: String,
        password: &str,
        cert_pem: &str,
        key_pem: &str,
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        udp: Option<HysteriaUdpParts>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<Self> {
        let password = password.trim();
        if password.is_empty() {
            bail!("hysteria 入口 password 为空（认证面必须非空）");
        }
        // 上限旋钮：0 具名拒绝（不设上限用 None 表达——不重载官方 0 语义）
        for (label, v) in [("up_mbps", up_mbps), ("down_mbps", down_mbps)] {
            if v == Some(0) {
                bail!("hysteria 入口 {label} 为 0（不设上限用 None 表达）");
            }
        }
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .context("hysteria 入口证书 PEM 解析失败")?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .context("hysteria 入口私钥 PEM 解析失败")?;
        let mut config = rustls::ServerConfig::builder_with_provider(tls_crypto_provider())
            .with_safe_default_protocol_versions()
            .context("hysteria 入口 TLS 协议版本装配失败")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("hysteria 入口 TLS 证书装配失败")?;
        // QUIC TLS 要求 ALPN 非空（QuicServerConfig::try_from 校验）；官方
        // 缺省 ALPN 恒 "hysteria"（config 旋钮口径，IR 不留旋钮）
        config.alpn_protocols = vec![b"hysteria".to_vec()];
        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .map_err(|e| anyhow!("hysteria 入口 QUIC TLS 配置失败: {e}"))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        bind.parse::<SocketAddr>()
            .with_context(|| format!("hysteria 入口 bind 非法: {bind}"))?;
        Ok(Self {
            name,
            bind,
            password: password.to_string(),
            send_bps_cap: up_mbps.map(|v| v as u64 * MBPS_TO_BPS),
            recv_bps_cap: down_mbps.map(|v| v as u64 * MBPS_TO_BPS),
            server_config,
            udp,
            fake_ip,
            reclaimer_once: Arc::new(Once::new()),
        })
    }

    /// 单连接面：控制流认证门 → 流接受环（TCP 直连面 / UDP 会话面）+ UDP
    /// 数据报环（认证通过后才开）
    async fn serve_connection(
        &self,
        conn: quinn::Connection,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let peer = conn.remote_address();

        // ---- 控制流认证门：首条被接受双向流（官方 server.handleClient 口径，
        // accept_bi 顺序确定；protocolTimeout 内须完成） ----
        let control = tokio::time::timeout(PROTOCOL_TIMEOUT, conn.accept_bi())
            .await
            .map_err(|_| anyhow!("hysteria 控制流超时（{}s）", PROTOCOL_TIMEOUT.as_secs()))?
            .context("hysteria 控制流接受失败")?;
        tokio::time::timeout(
            PROTOCOL_TIMEOUT,
            handle_control_stream(
                &conn,
                control,
                &self.password,
                self.send_bps_cap,
                self.recv_bps_cap,
            ),
        )
        .await
        .map_err(|_| anyhow!("hysteria 控制流处理超时（{}s）", PROTOCOL_TIMEOUT.as_secs()))?
        .context("hysteria 控制流处理失败")?;

        // ---- UDP 连接级状态（会话面登记；官方 serverClient per-conn 状态
        // 镜像）：真实目标键 → 服务端授予 session id（回程回写同 id——客户端
        // 按本连接 session 过滤外来数据报）；per-connection 计数器 0 起
        //（官方 nextUDPSessionID 口径） ----
        let sessions: Arc<StdMutex<HashMap<String, u32>>> = Arc::new(StdMutex::new(HashMap::new()));
        let next_session = Arc::new(StdMutex::new(0u32));

        // ---- 流接受环：逐流解析请求 → UDP 会话面 / TCP 直连面 ----
        {
            let name = self.name.clone();
            let fake_ip = self.fake_ip.clone();
            let router = router.clone();
            let output = output.clone();
            let udp = self.udp.clone();
            let conn_streams = conn.clone();
            let sessions_loop = sessions.clone();
            let next_session_loop = next_session.clone();
            tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = conn_streams.accept_bi().await {
                    // 请求解析在环内（官方 handleStream 同口径）；解析失败回
                    // !OK 响应后收流（客户端见拒绝文案）
                    let (udp_req, host, port) = match read_client_request(&mut recv).await {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = send
                                .write_all(&pack_server_response(false, 0, "bad request"))
                                .await;
                            tracing::debug!(
                                target: "rillane::hysteria",
                                client = %peer,
                                error = %e,
                                "hysteria 流请求解析失败"
                            );
                            continue;
                        }
                    };
                    if udp_req {
                        match udp.as_ref() {
                            Some(_) => {
                                tokio::spawn(handle_udp_session(
                                    send,
                                    recv,
                                    sessions_loop.clone(),
                                    next_session_loop.clone(),
                                ));
                            }
                            None => {
                                // 官方 disableUDP 口径：回 !OK "UDP disabled"
                                let _ = send
                                    .write_all(&pack_server_response(false, 0, "UDP disabled"))
                                    .await;
                            }
                        }
                        continue;
                    }
                    tokio::spawn(handle_tcp_stream(
                        send,
                        recv,
                        host,
                        port,
                        name.clone(),
                        peer,
                        fake_ip.clone(),
                        router.clone(),
                        output.clone(),
                    ));
                }
                // 连接收束：accept_bi 报错退出（流资源随连接收束）
            });
        }

        // ---- UDP 面：QUIC 数据报环（仅启用时开） ----
        if let Some(parts) = self.udp.as_ref() {
            let key = UdpSessionKey::new(peer);
            let max_dgram = conn.max_datagram_size().unwrap_or(1200);
            let reassembler = Arc::new(tokio::sync::Mutex::new(Defragger::default()));
            let metrics = Arc::new(UdpIngressMetrics::default());
            let stats_dropped = Arc::new(AtomicU64::new(0));

            let conn_udp = conn.clone();
            let parts = parts.clone();
            let fake_ip = self.fake_ip.clone();
            let key_probe = key.clone();
            let sessions_up = sessions.clone();
            let stats_up = stats_dropped.clone();
            let metrics_up = metrics.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(buf) = conn_udp.read_datagram().await else {
                        break; // 连接收束/丢失 → 关联终止
                    };
                    let Some(msg) = parse_udp_message(&buf) else {
                        stats_up.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let mut target = FlowTarget {
                        host: msg.host.clone(),
                        port: msg.port,
                        proto: TargetProto::Udp,
                    };
                    // fake-ip 回填（G1-10）：池段假 IP 反查原域名改写
                    if let Some(table) = fake_ip.as_ref() {
                        if let Some(domain) = fake_ip::reverse_host(table, &target.host) {
                            target.host = domain;
                        }
                    }
                    // 上行登记 session id（回程回写）
                    {
                        let mut map = sessions_up.lock().expect("hysteria 会话映射锁中毒");
                        map.insert(format!("{}|{}", target.host, target.port), msg.session_id);
                    }

                    // 上行多分片重装配（Defragger 镜像互源：MsgID 重置语义）
                    let data = {
                        let mut re = reassembler.lock().await;
                        match re.feed(&msg) {
                            Some((_, _, whole)) => whole,
                            None => continue, // 未凑齐/非法分片头
                        }
                    };
                    bump(&metrics_up.uplink_packets);
                    let data = Bytes::from(data);

                    // 快路径：命中映射直接发
                    match parts.table.forward_up(&key, &target, data.clone()).await {
                        UpResult::Sent => continue,
                        UpResult::Dropped {
                            reason: DropReason::ShuttingDown,
                        } => break,
                        _ => {}
                    }
                    // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
                    if let Err(e) = slow_path_udp(
                        &parts,
                        conn_udp.clone(),
                        &sessions_up,
                        max_dgram,
                        metrics_up.clone(),
                        stats_up.clone(),
                        &key,
                        &target,
                        peer,
                        data,
                    )
                    .await
                    {
                        bump(&metrics_up.associate_errors);
                        tracing::debug!(
                            target: "rillane::hysteria_udp",
                            client = %peer,
                            target = %target.host,
                            error = %e,
                            "UDP 慢路径失败，数据报丢弃"
                        );
                    }
                }
                // 连接收束：吊销本关联键（vmess 控制流 EOF 同口径）
                parts.table.force_revoke(&key_probe);
            });
        }

        Ok(())
    }
}

/// 控制流认证（官方 core/cs server.handleControlStream 镜像）：版本校验 →
/// clientHello 解析 → 速率非零硬校验（否则协议错误收束）→ 授权 min 交换 →
/// 口令恒时比对 → serverHello。失败面：官方 !ok → qErrorAuth(2)，其余协议
/// 面失败 → qErrorProtocol(1)，均先回发错误码再返回 Err。
async fn handle_control_stream(
    conn: &quinn::Connection,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    password: &str,
    send_cap: Option<u64>,
    recv_cap: Option<u64>,
) -> Result<()> {
    let result = control_face(&mut send, &mut recv, password, send_cap, recv_cap).await;
    match result {
        Err(ControlFailure::Auth) => {
            // !OK serverHello 已回——连接按官方口径发认证错误收束
            conn.close(quinn::VarInt::from_u32(QERR_AUTH), b"auth error");
            Err(anyhow!("hysteria 认证被拒（口令不符），连接收束"))
        }
        Err(ControlFailure::Protocol(step, e)) => {
            conn.close(quinn::VarInt::from_u32(QERR_PROTOCOL), b"protocol error");
            Err(e).with_context(|| format!("hysteria 控制流失败（{step}）"))
        }
        Ok(()) => Ok(()),
    }
}

/// 控制流失败分流（口令不符 = 认证拒绝；版本/速率/线格式 = 协议面失败——
/// 错误码分流用，不外泄类型）
enum ControlFailure {
    Auth,
    Protocol(&'static str, anyhow::Error),
}

async fn control_face(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    password: &str,
    send_cap: Option<u64>,
    recv_cap: Option<u64>,
) -> Result<(), ControlFailure> {
    // 版本字节（官方 stream.Read 1 字节 → 比对 protocolVersion）
    let mut version = [0u8; 1];
    recv.read_exact(&mut version).await.map_err(|e| {
        ControlFailure::Protocol("版本读取", anyhow!("hysteria 版本字节读取失败: {e}"))
    })?;
    if version[0] != PROTOCOL_VERSION {
        return Err(ControlFailure::Protocol(
            "版本校验",
            anyhow!(
                "hysteria 不支持的协议版本 {}（期待 {PROTOCOL_VERSION}）",
                version[0]
            ),
        ));
    }
    // clientHello：[SendBPS BE][RecvBPS BE][AuthLen BE][Auth]
    let mut head = [0u8; 8 + 8 + 2];
    recv.read_exact(&mut head).await.map_err(|e| {
        ControlFailure::Protocol(
            "clientHello 解析",
            anyhow!("hysteria clientHello 头读取失败: {e}"),
        )
    })?;
    let client_send = u64::from_be_bytes(head[0..8].try_into().unwrap());
    let client_recv = u64::from_be_bytes(head[8..16].try_into().unwrap());
    let auth_len = u16::from_be_bytes(head[16..18].try_into().unwrap()) as usize;
    let mut auth = vec![0u8; auth_len];
    recv.read_exact(&mut auth).await.map_err(|e| {
        ControlFailure::Protocol(
            "clientHello 解析",
            anyhow!("hysteria 认证字节读取失败: {e}"),
        )
    })?;
    // 速率申报硬校验（官方：任一为零 = "invalid rate from client" 协议错误）
    if client_send == 0 || client_recv == 0 {
        return Err(ControlFailure::Protocol(
            "速率校验",
            anyhow!("hysteria 客户端速率申报为零（Send/Recv 须皆非零）"),
        ));
    }
    // 授权 min 交换（官方：上限 >0 才施加；serverSend 封客户端 RecvBPS，
    // serverRecv 封客户端 SendBPS）
    let server_send = match send_cap {
        Some(cap) if cap < client_recv => cap,
        _ => client_recv,
    };
    let server_recv = match recv_cap {
        Some(cap) if cap < client_send => cap,
        _ => client_send,
    };
    // 口令恒时比对（官方 connectFunc 返回 (ok, msg)）
    let ok = constant_time_eq(&auth, password.as_bytes());
    let hello = pack_server_hello(
        ok,
        server_send,
        server_recv,
        if ok { "" } else { "auth error" },
    );
    send.write_all(&hello).await.map_err(|e| {
        ControlFailure::Protocol(
            "serverHello 发送",
            anyhow!("hysteria serverHello 发送失败: {e}"),
        )
    })?;
    if !ok {
        return Err(ControlFailure::Auth);
    }
    tracing::debug!(
        target: "rillane::hysteria",
        server_send_bps = server_send,
        server_recv_bps = server_recv,
        "hysteria 控制流认证通过（Brutal CC 不交付，QUIC 缺省 CC 承载）"
    );
    Ok(())
}

/// serverHello 封帧：[OK][SendBPS BE][RecvBPS BE][MessageLen BE][Message]
fn pack_server_hello(ok: bool, send_bps: u64, recv_bps: u64, msg: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 2 + msg.len());
    buf.push(ok as u8);
    buf.extend_from_slice(&send_bps.to_be_bytes());
    buf.extend_from_slice(&recv_bps.to_be_bytes());
    buf.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    buf.extend_from_slice(msg.as_bytes());
    buf
}

/// clientRequest 读取：[UDP][HostLen BE][Host][Port BE]（bool 一字节）
async fn read_client_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(bool, String, u16)> {
    let mut head = [0u8; 1 + 2];
    reader
        .read_exact(&mut head)
        .await
        .context("clientRequest 头读取失败")?;
    let udp = head[0] != 0;
    let host_len = u16::from_be_bytes([head[1], head[2]]) as usize;
    if host_len > 512 {
        bail!("clientRequest 地址长度越限: {host_len}");
    }
    let mut host_bytes = vec![0u8; host_len];
    reader
        .read_exact(&mut host_bytes)
        .await
        .context("clientRequest 地址读取失败")?;
    let host = String::from_utf8(host_bytes).context("clientRequest 地址非 UTF-8")?;
    let mut port = [0u8; 2];
    reader
        .read_exact(&mut port)
        .await
        .context("clientRequest 端口读取失败")?;
    Ok((udp, host, u16::from_be_bytes(port)))
}

/// serverResponse 封帧：[OK][UDPSessionID BE][MessageLen BE][Message]
fn pack_server_response(ok: bool, session_id: u32, msg: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + 2 + msg.len());
    buf.push(ok as u8);
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    buf.extend_from_slice(msg.as_bytes());
    buf
}

/// UDP 会话面（官方 serverClient.handleUDP 镜像）：授予 per-connection 计数
/// session id → OK 响应 → Hold 语义（流存活即会话存活；EOF 即注销该 session
/// 的下行登记项）。数据报收发归数据报环（会话表粘滞键 = 连接远端地址）。
async fn handle_udp_session(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sessions: Arc<StdMutex<HashMap<String, u32>>>,
    next_session: Arc<StdMutex<u32>>,
) -> Result<()> {
    let assigned = {
        let mut gen = next_session.lock().expect("hysteria session 计数锁中毒");
        let id = *gen;
        *gen = gen.wrapping_add(1);
        id
    };
    send.write_all(&pack_server_response(true, assigned, ""))
        .await
        .context("hysteria UDP 会话响应发送失败")?;
    // Hold：读至 EOF/错误（客户端 Hold 镜像互源——两端互持至会话终结）
    let mut scratch = [0u8; 1024];
    while let Ok(read) = recv.read(&mut scratch).await {
        if read.is_none() {
            break;
        }
    }
    // 会话终结：注销该 session 的登记项（官方 delete(sessionMap, id) 口径）
    sessions
        .lock()
        .expect("hysteria 会话映射锁中毒")
        .retain(|_, v| *v != assigned);
    Ok(())
}

/// TCP 直连面：请求解出目标 → fake-ip 回填 → 路由 → OK 响应 → Flow 转发
/// （hysteria2 ingress 同构；io = QuicDuplex 原样承接）。解析已在环内完成，
/// 此处失败回非零状态响应；拨号失败面 = 流 EOF（拨号归 output 侧，与
/// vless/socks5 同口径）
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    raw_host: String,
    port: u16,
    node_name: String,
    client_addr: SocketAddr,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
) -> Result<()> {
    // 线面 host 裸形（官方 SplitHostPort 后不含方括号——"[::1]" 归一）
    let mut host = bare_host(&raw_host).to_string();
    let mut metadata = FlowMetadata {
        tags: vec!["ingress:hysteria".into(), format!("node:{}", node_name)],
        ..Default::default()
    };
    metadata
        .annotations
        .insert("client.addr".into(), client_addr.to_string());
    metadata
        .annotations
        .insert("ingress.node".into(), node_name.clone());

    // fake-ip 回填（G1-10）：池段假 IP 反查原域名改写
    if let Some(table) = fake_ip.as_ref() {
        if let Some(domain) = fake_ip::reverse_host(table, &host) {
            metadata
                .annotations
                .insert("dns.fakeip".into(), domain.clone());
            host = domain;
        }
    }

    let flow_id = FlowId::new();
    let ctx = FlowContext {
        id: flow_id,
        target: FlowTarget {
            host: host.clone(),
            port,
            proto: TargetProto::Tcp,
        },
        metadata: metadata.clone(),
    };
    let decision = match router.route(ctx).await {
        Ok(d) => d,
        Err(e) => {
            let _ = send
                .write_all(&pack_server_response(false, 0, "route failure"))
                .await;
            return Err(anyhow!("路由计算失败: {e}"));
        }
    };
    // OK 响应（UDPSessionID 恒 0——TCP 面不占用会话号；此后原样双向搬运）
    send.write_all(&pack_server_response(true, 0, ""))
        .await
        .context("hysteria TCP 响应发送失败")?;
    let flow = Flow {
        id: flow_id,
        target: FlowTarget {
            host,
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(QuicDuplex { send, recv }) as BoxedIo,
        metadata,
    };
    output
        .forward(decision, flow)
        .await
        .context("出口转发失败")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn slow_path_udp(
    parts: &HysteriaUdpParts,
    conn: quinn::Connection,
    sessions: &Arc<StdMutex<HashMap<String, u32>>>,
    max_dgram: usize,
    metrics: Arc<UdpIngressMetrics>,
    stats_dropped: Arc<AtomicU64>,
    key: &UdpSessionKey,
    target: &FlowTarget,
    peer: SocketAddr,
    data: Bytes,
) -> Result<()> {
    let sref = parts.table.resolve(key, target).await?;
    if !sref.has_mapping(target) {
        // 关联时机：首包路由决策产出后、映射创建处（relay-path §4.1）
        let ctx = FlowContext {
            id: *sref.id(),
            target: target.clone(),
            metadata: FlowMetadata::default(),
        };
        let decision = sref
            .decision()
            .ok_or_else(|| anyhow!("会话缺少路由决策（resolve 应已产出）"))?;
        let relay = parts
            .connector
            .associate(ctx, &decision)
            .await
            .context("出站 UDP 关联失败")?;
        sref.bind_mapping(target, relay).await?;
        // 按会话摘下行通道 → UDPMessage 编码沿 QUIC 数据报回送客户端
        //（多目标会话：单下行任务按包目标回写 session id）
        if let Some(rx) = sref.take_downlink_rx().await {
            tokio::spawn(downlink_loop(
                conn,
                rx,
                sessions.clone(),
                max_dgram,
                peer,
                metrics,
                stats_dropped,
            ));
        }
    }
    match sref.send_up(target, data).await {
        UpResult::Sent => Ok(()),
        // Miss：映射刚被策略吊销——本包丢弃，下一包重新关联
        UpResult::Miss => Ok(()),
        UpResult::Dropped { .. } => Ok(()), // 已在表侧计数，UDP 静默丢弃语义
    }
}

/// 下行任务：会话下行通道（多目标混流）→ 按包目标回写 session id →
/// UDPMessage 编码（超预算分片，MsgID 非零——客户端 Defragger 镜像互源）→
/// QUIC 数据报
#[allow(clippy::too_many_arguments)]
async fn downlink_loop(
    conn: quinn::Connection,
    mut rx: mpsc::Receiver<DownlinkPacket>,
    sessions: Arc<StdMutex<HashMap<String, u32>>>,
    max_dgram: usize,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
    stats_dropped: Arc<AtomicU64>,
) {
    let mut msg_id: u16 = 1; // 分片 MsgID 必须非零，从 1 起循环
    while let Some(pkt) = rx.recv().await {
        let real_key = format!("{}|{}", pkt.target.host, pkt.target.port);
        // 回程回写 session id（客户端按本连接 session 过滤外来数据报）
        let session = sessions
            .lock()
            .expect("hysteria 会话映射锁中毒")
            .get(&real_key)
            .copied();
        let Some(session) = session else {
            stats_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if let Err(e) = send_downlink(
            &conn,
            max_dgram,
            session,
            &mut msg_id,
            &pkt.target,
            &pkt.data,
        )
        .await
        {
            tracing::debug!(
                target: "rillane::hysteria_udp",
                client = %client,
                error = %e,
                "下行发送失败"
            );
            stats_dropped.fetch_add(1, Ordering::Relaxed);
            break; // 连接收束：后续帧无意义
        }
        bump(&metrics.downlink_packets);
    }
}

/// 下行单包/分片发送（客户端 send_to 镜像互源：单包直发 MsgID 恒 0，超预算
/// 同非零 MsgID 分片 frag_id 0..count，官方 fragUDPMessage 口径）
async fn send_downlink(
    conn: &quinn::Connection,
    max_dgram: usize,
    session: u32,
    msg_id: &mut u16,
    target: &FlowTarget,
    payload: &[u8],
) -> Result<()> {
    // 线面 host/port 独立字段：host 裸形（官方 IP.String() 不含方括号）
    let host = bare_host(&target.host);
    let overhead = 12 + host.len();

    if payload.len() + overhead <= max_dgram {
        let msg = encode_udp_message(session, host, target.port, 0, 0, 1, payload);
        return send_datagram(conn, msg).await;
    }

    // 分片：同一非零 MsgID，Fragment ID 0..count
    let per_frag = max_dgram.saturating_sub(overhead);
    if per_frag == 0 {
        bail!("hysteria QUIC 数据报过小（{max_dgram}B），无法承载 UDP 分片头");
    }
    if per_frag > u16::MAX as usize {
        bail!("hysteria 分片载荷上限 65535B（got {per_frag}B）");
    }
    let count = payload.len().div_ceil(per_frag);
    if count > u8::MAX as usize {
        bail!(
            "hysteria UDP 下行载荷过大（{}B，需 {count} 分片 > 255 上限）",
            payload.len()
        );
    }
    let id = *msg_id;
    *msg_id = msg_id.wrapping_add(1).max(1);
    for (frag_id, chunk) in payload.chunks(per_frag).enumerate() {
        let msg = encode_udp_message(
            session,
            host,
            target.port,
            id,
            frag_id as u8,
            count as u8,
            chunk,
        );
        send_datagram(conn, msg).await?;
    }
    Ok(())
}

async fn send_datagram(conn: &quinn::Connection, msg: Vec<u8>) -> Result<()> {
    let wait = conn.send_datagram_wait(Bytes::from(msg));
    match tokio::time::timeout(DGRAM_SEND_TIMEOUT, wait).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("hysteria QUIC 数据报发送失败: {e}")),
        Err(_) => Err(anyhow!(
            "hysteria QUIC 数据报缓冲满超时（{}s）——连接不可用",
            DGRAM_SEND_TIMEOUT.as_secs()
        )),
    }
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[async_trait]
impl IngressEndpoint for HysteriaIngress {
    fn name(&self) -> &'static str {
        "hysteria"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // 会话回收任务随 UDP 面启用即拉起（纯 Hysteria 入口无 ASSOCIATE，
        // 无人代拉；重复 sweep 幂等）
        if let Some(parts) = self.udp.as_ref() {
            let table = Arc::clone(&parts.table);
            let once = Arc::clone(&self.reclaimer_once);
            once.call_once(move || {
                table.spawn_reclaimer();
            });
        }

        let bind_addr: SocketAddr = self
            .bind
            .parse()
            .with_context(|| format!("hysteria 入口 bind 非法: {}", self.bind))?;
        let endpoint = quinn::Endpoint::server(self.server_config.clone(), bind_addr)
            .with_context(|| format!("无法监听 {}", self.bind))?;
        tracing::info!(
            target: "rillane::hysteria",
            bind = %self.bind,
            "Hysteria 入口启动"
        );

        loop {
            let Some(incoming) = endpoint.accept().await else {
                break;
            };
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();
            tokio::spawn(async move {
                let conn = match incoming.accept() {
                    Ok(connecting) => match connecting.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!(
                                target: "rillane::hysteria",
                                error = %e,
                                "QUIC 握手失败"
                            );
                            return;
                        }
                    },
                    Err(e) => {
                        tracing::debug!(
                            target: "rillane::hysteria",
                            error = %e,
                            "QUIC 连接受理失败"
                        );
                        return;
                    }
                };
                let peer = conn.remote_address();
                if let Err(err) = this.serve_connection(conn, router, output).await {
                    tracing::warn!(
                        target: "rillane::hysteria",
                        client = %peer,
                        error = %err,
                        "Hysteria 连接处理失败"
                    );
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::hysteria::pack_client_request;

    // ---- 控制流编解码（服务端视角） ----

    #[test]
    fn server_hello_wire_is_big_endian() {
        let wire = pack_server_hello(true, 30_000_000, 80_000_000, "");
        assert_eq!(wire[0], 1); // OK
        assert_eq!(&wire[1..9], &(30_000_000u64).to_be_bytes());
        assert_eq!(&wire[9..17], &(80_000_000u64).to_be_bytes());
        assert_eq!(&wire[17..19], &0u16.to_be_bytes());
        assert_eq!(wire.len(), 19);

        let fail = pack_server_hello(false, 0, 0, "auth error");
        assert_eq!(fail[0], 0);
        assert_eq!(&fail[17..19], &10u16.to_be_bytes());
        assert_eq!(&fail[19..], b"auth error");
    }

    #[test]
    fn server_response_wire_shape() {
        let ok = pack_server_response(true, 42, "");
        assert_eq!(ok, {
            let mut v = vec![1u8];
            v.extend_from_slice(&42u32.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v
        });
        let no = pack_server_response(false, 0, "no");
        assert_eq!(no[0], 0);
        assert_eq!(&no[5..7], &2u16.to_be_bytes());
        assert_eq!(&no[7..], b"no");
    }

    #[tokio::test]
    async fn client_request_roundtrip() {
        let wire = pack_client_request(false, "example.com", 443);
        let (udp, host, port) = read_client_request(&mut &wire[..]).await.unwrap();
        assert!(!udp);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let wire = pack_client_request(true, "", 0);
        let (udp, host, port) = read_client_request(&mut &wire[..]).await.unwrap();
        assert!(udp);
        assert_eq!(host, "");
        assert_eq!(port, 0);
    }

    #[tokio::test]
    async fn client_request_truncation_rejected() {
        assert!(read_client_request(&mut &[0u8, 0u8][..]).await.is_err());
        // host_len 虚标越界
        let mut wire = pack_client_request(false, "ab", 1);
        wire[1] = 0xFF;
        wire[2] = 0xFF;
        assert!(read_client_request(&mut &wire[..]).await.is_err());
    }

    // ---- 授权 min 交换语义（官方口径：上限 >0 才施加；交叉封顶） ----

    #[test]
    fn grant_semantics_mirror_official_min_swap() {
        // serverSend = min(客户端 RecvBPS, up 上限)；serverRecv = min(客户端
        // SendBPS, down 上限)——与 control_face 内联逻辑同构抽取验证
        let grant = |client_send: u64, client_recv: u64, up: Option<u64>, down: Option<u64>| {
            let server_send = match up {
                Some(cap) if cap < client_recv => cap,
                _ => client_recv,
            };
            let server_recv = match down {
                Some(cap) if cap < client_send => cap,
                _ => client_send,
            };
            (server_send, server_recv)
        };
        // 无上限 = 全按申报
        assert_eq!(
            grant(50_000_000, 100_000_000, None, None),
            (100_000_000, 50_000_000)
        );
        // 上限封顶（各自交叉向）
        assert_eq!(
            grant(50_000_000, 100_000_000, Some(30_000_000), None),
            (30_000_000, 50_000_000)
        );
        assert_eq!(
            grant(50_000_000, 100_000_000, None, Some(40_000_000)),
            (100_000_000, 40_000_000)
        );
        // 申报低于上限 = 申报原样（官方 min 语义）
        assert_eq!(
            grant(10_000_000, 20_000_000, Some(30_000_000), Some(40_000_000)),
            (20_000_000, 10_000_000)
        );
    }

    #[test]
    fn assembly_gate_refuses_empty_password_and_zero_caps() {
        let ck =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
        let cert = ck.cert.pem();
        let key = ck.key_pair.serialize_pem();
        assert!(
            HysteriaIngress::new(
                "t".into(),
                "127.0.0.1:0".into(),
                "  ",
                &cert,
                &key,
                None,
                None,
                None,
                None
            )
            .is_err(),
            "空口令须拒绝"
        );
        assert!(
            HysteriaIngress::new(
                "t".into(),
                "127.0.0.1:0".into(),
                "pw",
                &cert,
                &key,
                Some(0),
                None,
                None,
                None
            )
            .err()
            .map(|e| e.to_string().contains("up_mbps"))
            .unwrap_or(false),
            "up_mbps=0 须点名拒绝"
        );
        assert!(
            HysteriaIngress::new(
                "t".into(),
                "127.0.0.1:0".into(),
                "pw",
                &cert,
                &key,
                None,
                Some(0),
                None,
                None
            )
            .err()
            .map(|e| e.to_string().contains("down_mbps"))
            .unwrap_or(false),
            "down_mbps=0 须点名拒绝"
        );
        // 合法装配（caps Some 非零；UDP/fake-ip 皆 None）
        assert!(HysteriaIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "pw",
            &cert,
            &key,
            Some(50),
            Some(100),
            None,
            None
        )
        .is_ok());
        // 非法 bind 具名拒绝
        assert!(
            HysteriaIngress::new(
                "t".into(),
                "nope".into(),
                "pw",
                &cert,
                &key,
                None,
                None,
                None,
                None
            )
            .is_err(),
            "bind 非法须拒绝"
        );
    }

    #[test]
    fn bare_host_normalizes_bracketed_literals() {
        assert_eq!(bare_host("[::1]"), "::1");
        assert_eq!(bare_host("::1"), "::1");
        assert_eq!(bare_host("example.com"), "example.com");
    }
}
