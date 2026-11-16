//! RIL-105 TUIC v5 验收（官方 wire 规格镜像对端，QUIC 回环）。
//!
//! 自写面按官方 v5 规格（EAimTY SPEC.md × MetaCubeX marshal.rs 交叉核对）；
//! 镜像对端为独立实现：TLS exporter 自验 Authenticate（label = UUID、
//! context = 密码）、Connect 命令真实 TCP 中继、Packet 命令数据报中继到
//! 纯 UDP 回声端、Dissociate 注销、VER≠0x05 点名拒绝。
//!
//! 验收面（protocol-backends.md#tuic 承诺清单）：认证成功 / 错误 token 具名
//! 拒绝 / v4 具名拒绝 / TCP 往返（含会话复用与字节统计）/ 拨号失败收束 /
//! UDP 往返（协议头源地址逐字段）/ 分片（超数据报载荷双向分片重组逐字节
//! 一致）/ Dissociate 资源释放 / 统计 / 取消（relay + 连接器 drop → 对端
//! 连接收束计数）。v5 无认证响应面：拒绝由 QUIC 收束帧承载，字面理由经
//! 收束帧 reason 可观测（v4 面逐字断言）。

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use rillane_core::{
    udp::UdpRelay, EgressConnector, Flow, FlowContext, FlowId, FlowReport, FlowTarget,
    RouteDecision, RoutePath, RouteType, TargetProto,
};
use rillane_protocols::{TuicConnector, TuicUdpConnector};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
    time::{sleep, timeout},
};
use uuid::Uuid;

const CLIENT_UUID: &str = "2dd35bfe-7d81-4a7e-9325-97e5ae1f8e8e";

/// 会话收束轮询（20ms 步进）
async fn wait_for(cond: impl Fn() -> bool, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        sleep(Duration::from_millis(20)).await;
    }
    cond()
}

/// 带真实 TCP socket 驱动半边的 TCP Flow（客户端写入/读回/EOF 在测试内
/// 完成；回环 listener 对接 Flow.io 与驱动半边——EOF 经真实 FIN 传播）
async fn make_tcp_flow(host: &str, port: u16) -> (Flow, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind drive listener");
    let drive_addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(drive_addr)
        .await
        .expect("connect drive");
    let (outbound_side, _peer) = listener.accept().await.expect("accept drive");
    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

fn udp_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        metadata: Default::default(),
    }
}

fn target_of(echo: &SocketAddr) -> FlowTarget {
    FlowTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
        proto: TargetProto::Udp,
    }
}

fn decision() -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: "tuic-mirror-node".into(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

fn connector_at(server: SocketAddr, password: &str) -> TuicConnector {
    // 测试对端自签证书 → skip_cert_verify；ALPN/拥塞控制取缺省（cubic）
    TuicConnector::new(
        server.ip().to_string(),
        server.port(),
        CLIENT_UUID.into(),
        password.into(),
        None,
        None,
        true,
        None,
    )
}

fn udp_connector_of(server: SocketAddr, password: &str) -> TuicUdpConnector {
    let tcp = connector_at(server, password);
    TuicUdpConnector::from_connector(&tcp)
}

fn deterministic(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 11 + 5) as u8).collect()
}

/// 纯 TCP 回声端（镜像服务端按 Connect 地址真实拨到此）
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tokio::io::AsyncWriteExt::write_all(&mut sock, &buf[..n])
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 纯 UDP 回声端（镜像服务端按 Packet 协议头地址真实转发到此）
async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

// ---------- 镜像服务端（官方 v5 规格独立实现） ----------

#[derive(Default)]
struct MirrorStats {
    connections: AtomicU64,
    /// 连接收束（QUIC 连接关闭 → 数据报读环退出）
    closed: AtomicU64,
    auth_ok: AtomicU64,
    auth_failed: AtomicU64,
    /// VER≠0x05 点名拒绝（v4/其余版本字节）
    version_refused: AtomicU64,
    /// Dissociate 注销计数（资源释放面）
    dissociated: AtomicU64,
    /// 客户端 → 服务端有效 Packet 数据报（含分片）
    datagrams_relayed: AtomicU64,
    /// frag_total > 1 的上行数据报（分片验收面）
    fragmented_uplink: AtomicU64,
    /// Connect 目标拨号失败（流收束承载）
    dial_failures: AtomicU64,
}

struct Mirror {
    addr: SocketAddr,
    stats: Arc<MirrorStats>,
}

/// TUIC 地址字段（镜像侧独立编解码；None 仅单字节 0xff 无端口）
#[derive(Clone, Debug, PartialEq, Eq)]
enum MAddr {
    None,
    Domain(String, u16),
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

impl MAddr {
    fn wire_len(&self) -> usize {
        match self {
            Self::None => 1,
            Self::Domain(d, _) => 2 + d.len() + 2,
            Self::V4(..) => 7,
            Self::V6(..) => 19,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_len());
        match self {
            Self::None => buf.push(0xff),
            Self::Domain(d, port) => {
                buf.push(0x00);
                buf.push(d.len() as u8);
                buf.extend_from_slice(d.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::V4(octets, port) => {
                buf.push(0x01);
                buf.extend_from_slice(octets);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::V6(octets, port) => {
                buf.push(0x02);
                buf.extend_from_slice(octets);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }

    fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::V4(octets, port) => Some(SocketAddr::from((*octets, *port))),
            Self::V6(octets, port) => Some(SocketAddr::from((*octets, *port))),
            _ => None,
        }
    }
}

/// Packet 命令帧（[05][02][assoc u16][pkt u16][total u8][fid u8][size u16][addr][payload]）
fn encode_packet(
    assoc: u16,
    pkt: u16,
    total: u8,
    fid: u8,
    addr: &MAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + addr.wire_len() + payload.len());
    buf.push(0x05);
    buf.push(0x02);
    buf.extend_from_slice(&assoc.to_be_bytes());
    buf.extend_from_slice(&pkt.to_be_bytes());
    buf.push(total);
    buf.push(fid);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(&addr.encode());
    buf.extend_from_slice(payload);
    buf
}

type ParsedPacket<'a> = (u16, u16, u8, u8, u16, MAddr, &'a [u8]);

fn parse_packet(buf: &[u8]) -> Option<ParsedPacket<'_>> {
    if buf.len() < 10 || buf[0] != 0x05 || buf[1] != 0x02 {
        // Heartbeat [05][04] 等非 Packet 帧在此静默忽略（合法帧）
        return None;
    }
    let assoc = u16::from_be_bytes([buf[2], buf[3]]);
    let pkt = u16::from_be_bytes([buf[4], buf[5]]);
    let total = buf[6];
    let fid = buf[7];
    let size = u16::from_be_bytes([buf[8], buf[9]]);
    let (addr, consumed) = decode_maddr(&buf[10..])?;
    let payload = &buf[10 + consumed..];
    Some((assoc, pkt, total, fid, size, addr, payload))
}

fn decode_maddr(buf: &[u8]) -> Option<(MAddr, usize)> {
    match buf.first()? {
        0xff => Some((MAddr::None, 1)),
        0x00 => {
            let len = *buf.get(1)? as usize;
            let end = 2usize.checked_add(len)?;
            if buf.len() < end + 2 {
                return None;
            }
            let domain = String::from_utf8_lossy(&buf[2..end]).into_owned();
            let port = u16::from_be_bytes([buf[end], buf[end + 1]]);
            Some((MAddr::Domain(domain, port), end + 2))
        }
        0x01 => {
            if buf.len() < 7 {
                return None;
            }
            Some((
                MAddr::V4(
                    [buf[1], buf[2], buf[3], buf[4]],
                    u16::from_be_bytes([buf[5], buf[6]]),
                ),
                7,
            ))
        }
        0x02 => {
            if buf.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            Some((
                MAddr::V6(octets, u16::from_be_bytes([buf[17], buf[18]])),
                19,
            ))
        }
        _ => None,
    }
}

/// 从流上按帧读取地址字段（Connect 命令 / 分片重组前置）
async fn read_maddr(recv: &mut quinn::RecvStream) -> Option<MAddr> {
    let mut ty = [0u8; 1];
    recv.read_exact(&mut ty).await.ok()?;
    match ty[0] {
        0xff => Some(MAddr::None),
        0x00 => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; len[0] as usize];
            recv.read_exact(&mut name).await.ok()?;
            let mut port = [0u8; 2];
            recv.read_exact(&mut port).await.ok()?;
            Some(MAddr::Domain(
                String::from_utf8_lossy(&name).into_owned(),
                u16::from_be_bytes(port),
            ))
        }
        0x01 => {
            let mut rest = [0u8; 6];
            recv.read_exact(&mut rest).await.ok()?;
            Some(MAddr::V4(
                [rest[0], rest[1], rest[2], rest[3]],
                u16::from_be_bytes([rest[4], rest[5]]),
            ))
        }
        0x02 => {
            let mut rest = [0u8; 18];
            recv.read_exact(&mut rest).await.ok()?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            Some(MAddr::V6(octets, u16::from_be_bytes([rest[16], rest[17]])))
        }
        _ => None,
    }
}

/// 镜像服务端：exporter 自验 Authenticate（label = UUID、context = 密码，
/// 与客户端同规格独立实现）；Connect 真实 TCP 中继（拨号失败流收束）；
/// Packet 数据报真实转发到 UDP 回声端（分片重组 + 回源方向按服务端语义
/// 分片回包）；Dissociate 注销；VER≠0x05 具名拒绝。
/// inject_foreign：首个上行数据报后注入一条外来 assoc 数据报（会话过滤面）。
async fn spawn_mirror(server_password: &str, inject_foreign: bool) -> Mirror {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("自签证书");
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
    );
    let server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("协议版本")
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key_der)
    .expect("证书装配");
    // 客户端缺省不发 ALPN（协议不强制）——镜像同样留空
    let quinn_server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))
            .expect("QUIC TLS"),
    ));
    let endpoint =
        quinn::Endpoint::server(quinn_server, "127.0.0.1:0".parse().unwrap()).expect("bind mirror");
    let addr = endpoint.local_addr().unwrap();
    let stats = Arc::new(MirrorStats::default());
    let s2 = stats.clone();
    let password = server_password.to_string();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else {
                break;
            };
            s2.connections.fetch_add(1, Ordering::SeqCst);
            let s3 = s2.clone();
            let password = password.clone();
            tokio::spawn(handle_mirror_connection(conn, password, inject_foreign, s3));
        }
    });

    Mirror { addr, stats }
}

/// 单向流等待认证完成（认证流与 Connect 流跨流不保证有序——watch 同步）
async fn wait_authed(mut rx: watch::Receiver<bool>) -> bool {
    if *rx.borrow_and_update() {
        return true;
    }
    match timeout(Duration::from_secs(3), rx.changed()).await {
        Ok(Ok(())) => *rx.borrow_and_update(),
        _ => false,
    }
}

async fn handle_mirror_connection(
    conn: quinn::Connection,
    password: String,
    inject_foreign: bool,
    stats: Arc<MirrorStats>,
) {
    let (auth_tx, auth_rx) = watch::channel(false);
    let assoc_table: Arc<std::sync::Mutex<HashMap<u16, Arc<UdpSocket>>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // ---- 单向流：Authenticate（exporter 自验）/ Dissociate 注销 ----
    let uni_loop = {
        let conn = conn.clone();
        let stats = stats.clone();
        let auth_tx = auth_tx.clone();
        let assoc_table = assoc_table.clone();
        let password = password.clone();
        tokio::spawn(async move {
            while let Ok(stream) = conn.accept_uni().await {
                let mut buf = Vec::new();
                if stream.take(1024).read_to_end(&mut buf).await.is_err() || buf.len() < 2 {
                    continue;
                }
                if buf[0] != 0x05 {
                    // v4/其余版本字节：具名拒绝（不静默互换）
                    stats.version_refused.fetch_add(1, Ordering::SeqCst);
                    conn.close(0x03u32.into(), &b"tuic: unsupported version (v5 only)"[..]);
                    return;
                }
                match buf[1] {
                    0x00 => {
                        // Authenticate：UUID 16 + TOKEN 32（v4 形状仅 32 字节
                        // digest，长度不符即拒绝——UUID/TOKEN 边界不存在）
                        if buf.len() != 50 {
                            stats.auth_failed.fetch_add(1, Ordering::SeqCst);
                            conn.close(0x01u32.into(), &b"tuic: authenticate body length"[..]);
                            return;
                        }
                        let Ok(uuid) = Uuid::from_slice(&buf[2..18]) else {
                            stats.auth_failed.fetch_add(1, Ordering::SeqCst);
                            return;
                        };
                        let mut expect = [0u8; 32];
                        if conn
                            .export_keying_material(
                                &mut expect,
                                uuid.as_bytes(),
                                password.as_bytes(),
                            )
                            .is_err()
                        {
                            return;
                        }
                        if expect[..] == buf[18..50] {
                            stats.auth_ok.fetch_add(1, Ordering::SeqCst);
                            let _ = auth_tx.send(true);
                        } else {
                            stats.auth_failed.fetch_add(1, Ordering::SeqCst);
                            conn.close(0x02u32.into(), &b"tuic: authenticate token mismatch"[..]);
                            return;
                        }
                    }
                    0x03 => {
                        // Dissociate：assoc_id u16——注销会话（资源释放面）
                        if buf.len() == 4 {
                            let assoc = u16::from_be_bytes([buf[2], buf[3]]);
                            assoc_table.lock().unwrap().remove(&assoc);
                            stats.dissociated.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    _ => {}
                }
            }
        })
    };

    // ---- 双向流：Connect 命令 → 真实 TCP 中继 ----
    let bi_loop = {
        let conn = conn.clone();
        let stats = stats.clone();
        let auth_rx = auth_rx.clone();
        tokio::spawn(async move {
            while let Ok((send, mut recv)) = conn.accept_bi().await {
                let auth_rx = auth_rx.clone();
                let stats = stats.clone();
                tokio::spawn(async move {
                    let mut send = send;
                    if !wait_authed(auth_rx).await {
                        recv.stop(0x01u32.into()).ok();
                        let _ = send.reset(0x01u32.into());
                        return;
                    }
                    let mut head = [0u8; 2];
                    if recv.read_exact(&mut head).await.is_err()
                        || head[0] != 0x05
                        || head[1] != 0x01
                    {
                        let _ = send.reset(0x01u32.into());
                        return;
                    }
                    let Some(addr) = read_maddr(&mut recv).await else {
                        let _ = send.reset(0x01u32.into());
                        return;
                    };
                    // 协议无响应面：目标不可达由流收束承载（reset ≠ 静默吞）
                    let Some(sock_addr) = addr.socket_addr() else {
                        let _ = send.reset(0x01u32.into());
                        return;
                    };
                    let tcp = match timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(sock_addr),
                    )
                    .await
                    {
                        Ok(Ok(t)) => t,
                        _ => {
                            stats.dial_failures.fetch_add(1, Ordering::SeqCst);
                            recv.stop(0x02u32.into()).ok();
                            let _ = send.reset(0x02u32.into());
                            return;
                        }
                    };
                    let (mut tr, mut tw) = tcp.into_split();
                    // 双向并发中继（半双工顺序拷贝会在回读时死锁）
                    let up = tokio::spawn(async move {
                        let n = tokio::io::copy(&mut recv, &mut tw).await.unwrap_or(0);
                        let _ = tw.shutdown().await;
                        n
                    });
                    let down = tokio::spawn(async move {
                        let mut send = send;
                        let n = tokio::io::copy(&mut tr, &mut send).await.unwrap_or(0);
                        let _ = send.finish();
                        n
                    });
                    let _ = tokio::join!(up, down);
                });
            }
        })
    };

    // ---- 数据报：Packet 命令 → 真实 UDP 中继（会话表 + 分片重组 + 回源）----
    let max_dgram = conn.max_datagram_size().unwrap_or(1200);
    let down_pkt = AtomicU16::new(0);
    let injected = AtomicBool::new(false);
    // (assoc, pkt_id) → (frag_total, fid → 载荷, 首片地址)
    type FragEntry = (u8, BTreeMap<u8, Vec<u8>>, MAddr);
    let mut reassembly: HashMap<(u16, u16), FragEntry> = HashMap::new();
    loop {
        let Ok(buf) = conn.read_datagram().await else {
            break;
        };
        let Some((assoc, pkt, total, fid, _size, addr, payload)) = parse_packet(&buf) else {
            continue;
        };
        stats.datagrams_relayed.fetch_add(1, Ordering::SeqCst);
        if total > 1 {
            stats.fragmented_uplink.fetch_add(1, Ordering::SeqCst);
        }
        // 同一 (assoc, pkt_id) 全片齐才处理（首片带地址、后续片 None）
        let (whole, src) = if total <= 1 {
            (payload.to_vec(), addr)
        } else {
            let entry = reassembly
                .entry((assoc, pkt))
                .or_insert_with(|| (total, BTreeMap::new(), addr.clone()));
            if entry.0 != total || (fid == 0) != (!matches!(addr, MAddr::None)) {
                reassembly.remove(&(assoc, pkt));
                continue;
            }
            if fid == 0 {
                entry.2 = addr.clone();
            }
            entry.1.insert(fid, payload.to_vec());
            if entry.1.len() != entry.0 as usize {
                continue;
            }
            let (_, frags, first_addr) = reassembly.remove(&(assoc, pkt)).expect("已摘除");
            let mut v = Vec::with_capacity(frags.values().map(|f| f.len()).sum());
            for i in 0..total {
                if let Some(piece) = frags.get(&i) {
                    v.extend_from_slice(piece);
                }
            }
            (v, first_addr)
        };
        let Some(target) = src.socket_addr() else {
            continue;
        };
        let socket = {
            let existing = assoc_table.lock().unwrap().get(&assoc).cloned();
            match existing {
                Some(s) => s,
                None => {
                    let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("bind relay"));
                    assoc_table
                        .lock()
                        .unwrap()
                        .entry(assoc)
                        .or_insert_with(|| s.clone())
                        .clone()
                }
            }
        };
        if socket.connect(target).await.is_err() || socket.send(&whole).await.is_err() {
            continue;
        }

        // 会话过滤面：注入外来 assoc 数据报（客户端须丢弃并计数）
        if inject_foreign && !injected.swap(true, Ordering::SeqCst) {
            let bogus = assoc ^ 0x5555;
            let noise = encode_packet(bogus, 0xBEEF, 1, 0, &src, b"noise");
            let _ = conn.send_datagram(Bytes::from(noise));
        }

        // 回源方向：读回声 → 服务端语义回包（地址 = 协议头首片地址；
        // 超数据报尺寸回包分片：首片带地址、后续片 None 单字节）
        let rsock = socket.clone();
        let rconn = conn.clone();
        let pkt_base = down_pkt.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let mut rbuf = vec![0u8; 65536];
            let Ok(n) = rsock.recv(&mut rbuf).await else {
                return;
            };
            let per_first = max_dgram.saturating_sub(10 + src.wire_len()).max(1);
            let per_cont = max_dgram.saturating_sub(11).max(1);
            let total = if n <= per_first {
                1
            } else {
                1 + (n - per_first).div_ceil(per_cont)
            };
            if total > 255 {
                return;
            }
            let mut rest = &rbuf[..n];
            for fid in 0..total as u8 {
                let cap = if fid == 0 { per_first } else { per_cont };
                let take = rest.len().min(cap);
                let (chunk, tail) = rest.split_at(take);
                let addr = if fid == 0 { &src } else { &MAddr::None };
                let msg = encode_packet(assoc, pkt_base, total as u8, fid, addr, chunk);
                if rconn.send_datagram(Bytes::from(msg)).is_err() {
                    return;
                }
                rest = tail;
            }
        });
    }
    uni_loop.abort();
    bi_loop.abort();
    stats.closed.fetch_add(1, Ordering::SeqCst);
}

// ---------- 认证 + TCP 面 ----------

/// 单次 TCP 往返：写入载荷、逐字节读回、EOF 收束后取转发报告
async fn drive_tcp_roundtrip(connector: &TuicConnector, port: u16, payload: &[u8]) -> FlowReport {
    let (flow, mut client) = make_tcp_flow("127.0.0.1", port).await;
    let (forwarded, ()) = tokio::join!(
        connector.forward(flow),
        // async move：client 归驱动块所有，块完成即 drop → FIN → 全链收束
        // （借用捕获会在函数返回前持有半边，join 与 EOF 收束互锁）
        async move {
            client.write_all(payload).await.expect("写客户端半边");
            let mut echoed = vec![0u8; payload.len()];
            client.read_exact(&mut echoed).await.expect("读回声");
            assert_eq!(&echoed, payload, "TCP 往返须逐字节一致");
        }
    );
    forwarded.expect("转发失败")
}

#[tokio::test]
async fn tcp_roundtrip_reuses_session_and_reports_bytes() {
    let echo = spawn_tcp_echo().await;
    let mirror = spawn_mirror("tuic-secret", false).await;
    let connector = connector_at(mirror.addr, "tuic-secret");

    // 往返一：完整建连（认证 + Connect + 中继）+ 字节统计
    let payload = deterministic(4096);
    let report = timeout(
        Duration::from_secs(15),
        drive_tcp_roundtrip(&connector, echo.port(), &payload),
    )
    .await
    .expect("往返限时");
    assert_eq!(
        report.upstream,
        payload.len() as u64,
        "上行字节统计（协议头认证 + Connect + 中继）"
    );
    assert_eq!(report.downstream, payload.len() as u64, "下行字节统计");

    // 往返二：同一连接器（会话复用——单 QUIC 连接承载多 Connect）
    let report2 = timeout(
        Duration::from_secs(15),
        drive_tcp_roundtrip(&connector, echo.port(), &payload),
    )
    .await
    .expect("往返限时");
    assert_eq!(report2.upstream, payload.len() as u64, "复用后上行统计");
    assert_eq!(report2.downstream, payload.len() as u64, "复用后下行统计");
    assert_eq!(
        mirror.stats.connections.load(Ordering::SeqCst),
        1,
        "会话复用：两次转发仅一次 QUIC 连接"
    );
    assert!(
        mirror.stats.auth_ok.load(Ordering::SeqCst) >= 1,
        "认证成功（exporter 自验通过）"
    );
}

// ---------- 失败面 ----------

#[tokio::test]
async fn wrong_token_refused_by_name() {
    let mirror = spawn_mirror("server-pass", false).await;
    // 客户端密码 ≠ 服务端密码 → exporter token 不匹配
    let connector = connector_at(mirror.addr, "client-pass");
    let (flow, _client) = make_tcp_flow("127.0.0.1", 9).await;

    let err = match timeout(Duration::from_secs(15), connector.forward(flow))
        .await
        .expect("转发限时")
    {
        Ok(_) => panic!("错误 token 必须失败"),
        Err(e) => e,
    };
    // v5 无认证响应面：拒绝由收束承载——失败须落在 TUIC 具名面
    // （双向流开启失败链带收束帧 reason，或中继传输失败链带流停止）
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("token mismatch")
            || rendered.contains("TUIC 中继传输失败")
            || rendered.contains("TUIC 双向流"),
        "认证拒绝须具名浮出: {rendered}"
    );
    assert!(
        mirror.stats.auth_failed.load(Ordering::SeqCst) >= 1,
        "服务端 token 校验失败计数"
    );
}

#[tokio::test]
async fn v4_refused_by_name() {
    let mirror = spawn_mirror("tuic-secret", false).await;

    // rogue 客户端：v4 形状 Authenticate（仅 32 字节 digest、无 UUID——
    // EAimTY impl-0.7 证据），VER 取非 0x05 版本字节
    #[derive(Debug)]
    struct AcceptAll;
    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("协议版本")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAll))
    .with_no_client_auth();
    crypto.alpn_protocols = Vec::new();
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(crypto)).expect("QUIC TLS"),
    )));
    let conn = endpoint
        .connect(mirror.addr, "localhost")
        .expect("连接发起")
        .await
        .expect("握手");

    let mut auth = conn.open_uni().await.expect("认证流");
    let mut frame = vec![0x02u8, 0x00]; // VER≠0x05 + TYPE_AUTHENTICATE
    frame.extend_from_slice(&[0xABu8; 32]);
    auth.write_all(&frame).await.expect("写认证帧");
    let _ = auth.finish();

    // 镜像点名拒绝（VER≠0x05）→ 连接收束
    assert!(
        wait_for(
            || mirror.stats.version_refused.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(3),
        )
        .await,
        "镜像须拒绝 VER≠0x05"
    );
    sleep(Duration::from_millis(200)).await; // 收束帧送达本地
    match conn.open_bi().await {
        Err(quinn::ConnectionError::ApplicationClosed(closed)) => {
            let reason = String::from_utf8_lossy(&closed.reason);
            assert!(
                reason.contains("unsupported version"),
                "拒绝理由须逐字可观测: {reason}"
            );
        }
        other => panic!("连接须被具名收束: {other:?}"),
    }
}

#[tokio::test]
async fn tcp_dial_failure_teardown() {
    let mirror = spawn_mirror("tuic-secret", false).await;
    let connector = connector_at(mirror.addr, "tuic-secret");
    // 客户端半边持有不写：中继读环只有对端流收束一条出路
    let (flow, _client) = make_tcp_flow("127.0.0.1", 1).await;

    // 目标 127.0.0.1:1（关闭端口）→ 镜像拨号失败 → 流收束（reset）
    let err = match timeout(Duration::from_secs(15), connector.forward(flow))
        .await
        .expect("转发限时")
    {
        Ok(_) => panic!("拨号失败不得伪装成功（协议无响应面，收束即失败）"),
        Err(e) => e,
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("TUIC 中继传输失败"),
        "拨号失败须由流收束浮出: {rendered}"
    );
    assert!(
        mirror.stats.dial_failures.load(Ordering::SeqCst) >= 1,
        "镜像拨号失败计数"
    );
}

// ---------- UDP 面 ----------

#[tokio::test]
async fn udp_roundtrip_with_header_source_address() {
    let echo = spawn_udp_echo().await;
    // 注入外来 assoc 数据报：会话过滤验收面
    let mirror = spawn_mirror("tuic-secret", true).await;
    let udp = udp_connector_of(mirror.addr, "tuic-secret");

    let relay = timeout(
        Duration::from_secs(15),
        udp.connect_relay(udp_ctx("127.0.0.1", echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    let payload = deterministic(1200);
    relay
        .send_to(&target_of(&echo), &payload)
        .await
        .expect("send 失败");

    let mut buf = vec![0u8; 65536];
    let (ft, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .expect("recv 失败");
    assert_eq!(n, payload.len(), "载荷长度");
    assert_eq!(&buf[..n], &payload, "载荷须逐字节一致");
    // 协议头源地址逐字段（旁路面：地址取自 Packet 头，非关联参数）
    assert_eq!(ft.host, "127.0.0.1", "协议头源地址 host");
    assert_eq!(ft.port, echo.port(), "协议头源地址 port");
    assert_eq!(ft.proto, TargetProto::Udp, "协议头源地址 proto");

    // 统计面：完整交付计数 + 外来 assoc 丢弃计数 + 无分片丢失
    assert_eq!(
        relay.stats().datagrams_relayed.load(Ordering::SeqCst),
        1,
        "完整交付计数"
    );
    assert_eq!(
        relay.stats().frag_dropped.load(Ordering::SeqCst),
        0,
        "无分片丢失"
    );
    assert!(
        wait_for(|| relay.unknown_dropped() >= 1, Duration::from_secs(2),).await,
        "外来 assoc 数据报须丢弃计数"
    );
    assert!(
        mirror.stats.datagrams_relayed.load(Ordering::SeqCst) >= 1,
        "服务端中继计数"
    );
}

#[tokio::test]
async fn fragmented_payload_reassembles_byte_exact() {
    let echo = spawn_udp_echo().await;
    let mirror = spawn_mirror("tuic-secret", false).await;
    let udp = udp_connector_of(mirror.addr, "tuic-secret");

    let relay = timeout(
        Duration::from_secs(15),
        udp.connect_relay(udp_ctx("127.0.0.1", echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    // 8KB 载荷：上行必分片（QUIC 数据报 ~1200B 上限）；回声 8KB：下行同样分片
    let payload = deterministic(8192);
    relay
        .send_to(&target_of(&echo), &payload)
        .await
        .expect("分片发送失败");

    let mut buf = vec![0u8; 65536];
    let (ft, n) = timeout(Duration::from_secs(10), relay.recv_from(&mut buf))
        .await
        .expect("下行重装配限时")
        .expect("下行重装配失败");
    assert_eq!(n, payload.len(), "重组载荷长度");
    assert_eq!(&buf[..n], &payload, "分片重组须逐字节一致");
    assert_eq!(ft.port, echo.port(), "协议头源地址 port");
    assert_eq!(
        relay.stats().datagrams_relayed.load(Ordering::SeqCst),
        1,
        "重装配后完整交付一次"
    );
    assert_eq!(
        relay.stats().frag_dropped.load(Ordering::SeqCst),
        0,
        "分片丢失面"
    );
    assert!(
        mirror.stats.fragmented_uplink.load(Ordering::SeqCst) >= 2,
        "超尺寸上行须多分片"
    );
}

#[tokio::test]
async fn dissociate_releases_server_association() {
    let echo = spawn_udp_echo().await;
    let mirror = spawn_mirror("tuic-secret", false).await;
    let udp = udp_connector_of(mirror.addr, "tuic-secret");

    let relay = timeout(
        Duration::from_secs(15),
        udp.connect_relay(udp_ctx("127.0.0.1", echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    // 会话活性：往返一包
    let payload = deterministic(256);
    relay
        .send_to(&target_of(&echo), &payload)
        .await
        .expect("send 失败");
    let mut buf = vec![0u8; 65536];
    let (_, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .expect("recv 失败");
    assert_eq!(n, payload.len(), "Dissociate 前会话须已建立");

    // 资源释放：relay drop → Dissociate 单向流 → 服务端注销计数
    drop(relay);
    assert!(
        wait_for(
            || mirror.stats.dissociated.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(3),
        )
        .await,
        "relay drop 须发出 Dissociate 并被服务端注销"
    );
}

// ---------- 取消/资源释放面 ----------

#[tokio::test]
async fn cancel_drops_relay_and_releases_server_connection() {
    let echo = spawn_udp_echo().await;
    let mirror = spawn_mirror("tuic-secret", false).await;
    let udp = udp_connector_of(mirror.addr, "tuic-secret");

    let relay = timeout(
        Duration::from_secs(15),
        udp.connect_relay(udp_ctx("127.0.0.1", echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    // 会话活性：往返一包
    let payload = deterministic(256);
    relay
        .send_to(&target_of(&echo), &payload)
        .await
        .expect("send 失败");
    let mut buf = vec![0u8; 65536];
    let (_, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .expect("recv 失败");
    assert_eq!(n, payload.len(), "取消前会话须已建立");

    // 中途取消：relay drop（Dissociate 尽力而为）+ 连接器 drop（缓存会话
    // 归还）→ QUIC 连接收束 → 对端各循环收束（closed 计数）
    let started = mirror.stats.connections.load(Ordering::SeqCst);
    drop(relay);
    drop(udp);
    assert!(
        wait_for(
            || mirror.stats.closed.load(Ordering::SeqCst) >= started,
            Duration::from_secs(3),
        )
        .await,
        "取消后对端连接须收束（connections={} closed={}）",
        mirror.stats.connections.load(Ordering::SeqCst),
        mirror.stats.closed.load(Ordering::SeqCst)
    );
}
