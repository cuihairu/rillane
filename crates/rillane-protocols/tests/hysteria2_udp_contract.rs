//! RIL-133 Hysteria2 UDP 数据报面验收（官方协议镜像对端，QUIC 回环）。
//!
//! hysteria2 crate 无数据报公开 API（留证 protocol-backends.md#hysteria2），
//! 本面按官方 PROTOCOL.md 自写 UDPMessage（QUIC 不可靠数据报：[u32 session]
//! [u16 packet][u8 frag_id][u8 frag_count][varint addr_len][addr][payload]），
//! 认证复用官方 HTTP/3 /auth 面（状态码 233 + Hysteria-UDP 声明）。
//! 镜像对端 = 同规格服务端（h3 认证 + 数据报中继到纯 UDP 回声端）。
//!
//! 验收面：成功往返（载荷逐字节 + 协议头源地址逐字段，旁路语义）、分片
//! （超数据报尺寸载荷双向分片/重装配逐字节一致）、会话过滤（外来 session
//! 数据报丢弃计数）、失败（认证被拒状态码点名 / 服务端未声明 UDP 支持点名
//! 拒绝）、取消/资源释放（relay drop → 对端连接收束计数）、统计
//! （服务端中继计数 + 客户端会话统计可观测）。

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use rcgen::CertifiedKey;
use rillane_core::{
    udp::UdpRelay, FlowContext, FlowId, FlowTarget, RouteDecision, RoutePath, RouteType,
    TargetProto,
};
use rillane_protocols::{Hysteria2Connector, Hysteria2UdpConnector};
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

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
            node: "hy2-mirror-node".into(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

fn connector_of(server: SocketAddr, password: &str) -> Hysteria2UdpConnector {
    // 与 TCP 面同一节点配置（from_connector 语义）；测试对端自签证书 →
    // skip_cert_verify；alpn 缺省（认证面恒 h3）
    let tcp = Hysteria2Connector::new(
        server.ip().to_string(),
        server.port(),
        password.into(),
        None,
        None,
        None,
        None,
        true,
        None,
    );
    Hysteria2UdpConnector::from_connector(&tcp)
}

fn deterministic(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 11 + 5) as u8).collect()
}

/// 纯 UDP 回声端（镜像服务端按协议头把数据报真实转发到此）
async fn spawn_plain_udp_echo() -> SocketAddr {
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

// ---------- 镜像服务端（官方 PROTOCOL.md 同规格） ----------

#[derive(Default)]
struct ServerStats {
    connections: AtomicU64,
    /// 连接收束（客户端 drop → QUIC 连接关闭 → 服务端各循环收束）
    closed: AtomicU64,
    auth_failed: AtomicU64,
    /// 客户端 → 服务端方向收到的有效 UDPMessage 数据报（含分片）
    datagrams_relayed: AtomicU64,
}

struct MirrorServer {
    addr: SocketAddr,
    stats: Arc<ServerStats>,
}

/// QUIC varint（RFC 9000 §16）编码
fn put_varint(buf: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        buf.push(v as u8);
    } else if v < 1 << 14 {
        buf.extend_from_slice(&((0b01 << 14) | v as u16).to_be_bytes());
    } else {
        buf.extend_from_slice(&((0b10u32 << 30) | v as u32).to_be_bytes());
    }
}

/// QUIC varint 解码，返回 (值, 字节数)
fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first >> 6 {
        0 => Some((first as u64, 1)),
        1 => {
            if buf.len() >= 2 {
                Some(((u16::from_be_bytes([first, buf[1]]) & 0x3FFF) as u64, 2))
            } else {
                None
            }
        }
        _ => {
            if buf.len() >= 4 {
                Some((
                    (u32::from_be_bytes([first, buf[1], buf[2], buf[3]]) & 0x3FFF_FFFF) as u64,
                    4,
                ))
            } else {
                None
            }
        }
    }
}

/// 解析后的 UDPMessage（会话/分片头 + 地址 + 载荷切片）
type ParsedMirrorMessage<'a> = (u32, u16, u8, u8, String, &'a [u8]);

fn parse_udp_message(buf: &[u8]) -> Option<ParsedMirrorMessage<'_>> {
    if buf.len() < 9 {
        return None;
    }
    let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_id = buf[6];
    let frag_count = buf[7];
    let (addr_len, n) = get_varint(&buf[8..])?;
    let addr_end = 8 + n + addr_len as usize;
    if addr_end > buf.len() {
        return None;
    }
    let addr = String::from_utf8_lossy(&buf[8 + n..addr_end]).into_owned();
    Some((
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr,
        &buf[addr_end..],
    ))
}

fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9 + addr.len() + payload.len());
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.push(frag_id);
    buf.push(frag_count);
    put_varint(&mut buf, addr.len() as u64);
    buf.extend_from_slice(addr.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// 镜像服务端：h3 认证（状态码 233 + Hysteria-UDP 声明）→ 数据报中继到
/// 真实目标（按协议头地址 connect 纯 UDP socket）→ 回源方向按服务端语义
/// 回包（源地址 = 目标地址，超尺寸同样分片）。
/// udp_support=false 模拟不支持 UDP 的服务端（官方口径：认证仍 233，
/// Hysteria-UDP 声明 false）；inject_bogus 在认证后注入一条外来 session
/// 数据报（会话过滤验收面）。
async fn spawn_mirror(password: &str, udp_support: bool, inject_bogus: bool) -> MirrorServer {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("自签证书");
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );
    let server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("协议版本")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("证书装配");
    let mut server_crypto = server_crypto;
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quinn_server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))
            .expect("QUIC TLS"),
    ));
    let endpoint =
        quinn::Endpoint::server(quinn_server, "127.0.0.1:0".parse().unwrap()).expect("bind mirror");
    let addr = endpoint.local_addr().unwrap();
    let stats = Arc::new(ServerStats::default());
    let s2 = stats.clone();
    let password = password.to_string();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else {
                break;
            };
            s2.connections.fetch_add(1, Ordering::SeqCst);
            let s3 = s2.clone();
            let password = password.clone();
            tokio::spawn(async move {
                handle_mirror_connection(conn, &password, udp_support, inject_bogus, s3).await;
            });
        }
    });

    MirrorServer { addr, stats }
}

async fn handle_mirror_connection(
    conn: quinn::Connection,
    password: &str,
    udp_support: bool,
    inject_bogus: bool,
    stats: Arc<ServerStats>,
) {
    // ---- 认证面（官方 HTTP/3 /auth：233 + Hysteria-UDP 声明）----
    // h3 帧类型泛型需显式钉住（镜像不读请求体，无推断锚点）
    let mut h3: h3::server::Connection<h3_quinn::Connection, Bytes> = match h3::server::builder()
        .build(h3_quinn::Connection::new(conn.clone()))
        .await
    {
        Ok(h) => h,
        Err(_) => {
            stats.closed.fetch_add(1, Ordering::SeqCst);
            return;
        }
    };
    let mut authed = false;
    if let Ok(Some(resolver)) = h3.accept().await {
        if let Ok((req, mut stream)) = resolver.resolve_request().await {
            let is_auth = req.uri().path() == "/auth" && req.method() == "POST";
            let creds_ok = req
                .headers()
                .get("Hysteria-Auth")
                .and_then(|v| v.to_str().ok())
                == Some(password);
            // 官方口径：密码错按普通 web 服务器处置（404，客户端自行断开）；
            // 密码对但无 UDP 支持仍 233，仅 Hysteria-UDP 声明 false
            let status = if creds_ok { 233 } else { 404 };
            if is_auth && !creds_ok {
                stats.auth_failed.fetch_add(1, Ordering::SeqCst);
            }
            if is_auth && creds_ok && udp_support {
                authed = true;
            }
            let resp = http::Response::builder()
                .status(http::StatusCode::from_u16(status).expect("状态码"))
                .header("Hysteria-UDP", if udp_support { "true" } else { "false" })
                .header("Hysteria-CC-RX", "0")
                .body(())
                .expect("响应体");
            if stream.send_response(resp).await.is_ok() {
                let _ = stream.finish().await;
            }
        }
    }
    // h3 面保活（官方服务端认证后 h3 连接继续存活，随 QUIC 连接收束；
    // 认证失败路径同样须送达响应后随客户端断开收束——h3 Drop 会先关控制流）
    let keep = tokio::spawn(async move {
        while let Ok(Some(resolver)) = h3.accept().await {
            if let Ok((_, mut stream)) = resolver.resolve_request().await {
                let resp = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(())
                    .expect("响应体");
                if stream.send_response(resp).await.is_ok() {
                    let _ = stream.finish().await;
                }
            }
        }
    });

    if !authed {
        let _ = keep.await;
        stats.closed.fetch_add(1, Ordering::SeqCst);
        return;
    }

    // ---- 数据报中继面（会话表：session → 连向真实目标的 socket）----
    if inject_bogus {
        // 外来 session 数据报（客户端须丢弃并计数，不影响本会话）
        let noise = encode_udp_message(0xDEAD_BEEF, 1, 0, 1, "127.0.0.1:9", b"noise");
        let _ = conn.send_datagram(Bytes::from(noise));
    }
    let max_dgram = conn.max_datagram_size().unwrap_or(1200);
    let mut sessions: HashMap<u32, Arc<UdpSocket>> = HashMap::new();
    let mut packet_id: u16 = 0;
    // 分片重装配表：packet_id → (片数, 已收片, 首片地址)
    type FragEntry = (u8, HashMap<u8, Vec<u8>>, String);
    let mut reassembly: HashMap<u16, FragEntry> = HashMap::new();
    while let Ok(buf) = conn.read_datagram().await {
        let Some((session, pid, frag_id, frag_count, addr, payload)) = parse_udp_message(&buf)
        else {
            continue;
        };
        stats.datagrams_relayed.fetch_add(1, Ordering::SeqCst);
        // 官方 §Fragmentation：同一 Packet ID 全片齐才处理（全有或全无）
        let (whole, addr) = if frag_count <= 1 {
            (payload.to_vec(), addr)
        } else {
            let entry = reassembly
                .entry(pid)
                .or_insert_with(|| (frag_count, HashMap::new(), addr.clone()));
            entry.1.insert(frag_id, payload.to_vec());
            if entry.1.len() != entry.0 as usize {
                continue;
            }
            let (count, frags, first_addr) = reassembly.remove(&pid).expect("已摘除");
            let mut v = Vec::new();
            for i in 0..count {
                v.extend_from_slice(&frags[&i]);
            }
            (v, first_addr)
        };

        let Some(target) = addr.rsplit_once(':').and_then(|(h, p)| {
            Some(SocketAddr::new(
                h.parse::<IpAddr>().ok()?,
                p.parse::<u16>().ok()?,
            ))
        }) else {
            continue;
        };
        let socket = if let Some(s) = sessions.get(&session) {
            s.clone()
        } else {
            let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("bind relay"));
            sessions.insert(session, s.clone());
            s
        };
        // 按协议头地址真实转发（首个数据报决定会话方向）
        if socket.connect(target).await.is_err() || socket.send(&whole).await.is_err() {
            continue;
        }

        // 回源方向：读回声 → 服务端语义回包（源地址 = 目标地址，
        // 回包用客户端会话 ID；超数据报尺寸回包同样分片）
        let rsock = socket.clone();
        let rconn = conn.clone();
        let src = addr;
        packet_id = packet_id.wrapping_add(1);
        let base_pid = packet_id;
        tokio::spawn(async move {
            let mut rbuf = vec![0u8; 65536];
            let Ok(n) = rsock.recv(&mut rbuf).await else {
                return;
            };
            let overhead = 8 + 1 + src.len(); // 定界头（地址 < 64 → varint 1 字节）
            let per = max_dgram.saturating_sub(overhead).max(1);
            let count = n.div_ceil(per).min(255);
            for (i, chunk) in rbuf[..n].chunks(per).take(count).enumerate() {
                let msg = encode_udp_message(session, base_pid, i as u8, count as u8, &src, chunk);
                if rconn.send_datagram(Bytes::from(msg)).is_err() {
                    break;
                }
            }
        });
    }
    let _ = keep.await;
    stats.closed.fetch_add(1, Ordering::SeqCst);
}

// ---------- 编码面 ----------

#[test]
fn varint_roundtrip_matches_quic_encoding() {
    // 编解码互逆 + RFC 9000 §16 前缀字节逐例
    let mut buf = Vec::new();
    put_varint(&mut buf, 0);
    put_varint(&mut buf, 63);
    put_varint(&mut buf, 16383);
    put_varint(&mut buf, 1_073_741_823);
    assert_eq!(buf, vec![0x00, 0x3F, 0x7F, 0xFF, 0xBF, 0xFF, 0xFF, 0xFF]);
    let mut pos = 0;
    for expect in [0u64, 63, 16383, 1_073_741_823] {
        let (v, n) = get_varint(&buf[pos..]).expect("解码");
        assert_eq!(v, expect);
        pos += n;
    }
    assert_eq!(pos, buf.len());

    // UDPMessage 定界头 + 地址 + 载荷逐字段
    let msg = encode_udp_message(1, 2, 0, 1, "127.0.0.1:53", b"payload");
    let (s, p, f, c, addr, payload) = parse_udp_message(&msg).expect("解析");
    assert_eq!((s, p, f, c), (1, 2, 0, 1));
    assert_eq!(addr, "127.0.0.1:53");
    assert_eq!(payload, b"payload");
}

// ---------- 成功面 ----------

#[tokio::test]
async fn udp_roundtrip_with_header_source_address() {
    let echo = spawn_plain_udp_echo().await;
    // 注入外来 session 数据报：会话过滤验收面
    let mirror = spawn_mirror("hy2-secret", true, true).await;
    let udp = connector_of(mirror.addr, "hy2-secret");

    let relay = timeout(
        Duration::from_secs(10),
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
    // 协议头源地址逐字段（旁路面：地址取自 UDPMessage 头，非关联参数）
    assert_eq!(ft.host, "127.0.0.1", "协议头源地址 host");
    assert_eq!(ft.port, echo.port(), "协议头源地址 port");
    assert_eq!(ft.proto, TargetProto::Udp, "协议头源地址 proto");

    // 统计面：外来会话丢弃计数 + 无分片丢失 + 服务端中继计数
    assert_eq!(
        relay.stats().foreign_dropped.load(Ordering::SeqCst),
        1,
        "外来会话数据报须丢弃计数"
    );
    assert_eq!(
        relay.stats().frag_dropped.load(Ordering::SeqCst),
        0,
        "无分片丢失"
    );
    assert!(
        mirror.stats.datagrams_relayed.load(Ordering::SeqCst) >= 1,
        "服务端中继计数"
    );
}

#[tokio::test]
async fn fragmented_payload_reassembles_byte_exact() {
    let echo = spawn_plain_udp_echo().await;
    let mirror = spawn_mirror("hy2-secret", true, false).await;
    let udp = connector_of(mirror.addr, "hy2-secret");

    let relay = timeout(
        Duration::from_secs(10),
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
        relay.stats().frag_dropped.load(Ordering::SeqCst),
        0,
        "分片丢失面"
    );
    // 上行分片数据报数 > 1（服务端按原始数据报计数）
    assert!(
        mirror.stats.datagrams_relayed.load(Ordering::SeqCst) > 1,
        "超尺寸载荷须产生多分片"
    );
}

// ---------- 失败面 ----------

#[tokio::test]
async fn auth_failure_refused_by_name() {
    let echo = spawn_plain_udp_echo().await;
    let mirror = spawn_mirror("hy2-secret", true, false).await;
    let udp = connector_of(mirror.addr, "wrong-password");

    let err = match timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    {
        Err(e) => e,
        Ok(_) => panic!("错密码必须失败"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("认证被拒绝"),
        "认证失败须点名状态码语义: {rendered}"
    );
    assert_eq!(
        mirror.stats.auth_failed.load(Ordering::SeqCst),
        1,
        "服务端认证失败计数"
    );
}

#[tokio::test]
async fn udp_unsupported_refused_by_name() {
    let echo = spawn_plain_udp_echo().await;
    // 官方口径：认证仍过（233），Hysteria-UDP 声明 false
    let mirror = spawn_mirror("hy2-secret", false, false).await;
    let udp = connector_of(mirror.addr, "hy2-secret");

    let err = match timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    {
        Err(e) => e,
        Ok(_) => panic!("无 UDP 支持必须失败"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("未声明 UDP 支持"),
        "不支持组合须点名拒绝: {rendered}"
    );
}

// ---------- 取消/资源释放面 ----------

#[tokio::test]
async fn cancel_drops_relay_and_releases_server_connection() {
    let echo = spawn_plain_udp_echo().await;
    let mirror = spawn_mirror("hy2-secret", true, false).await;
    let udp = connector_of(mirror.addr, "hy2-secret");

    let relay = timeout(
        Duration::from_secs(10),
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

    // 中途取消：drop → QUIC 连接关闭 → 对端各循环收束（closed 计数）
    let started = mirror.stats.connections.load(Ordering::SeqCst);
    drop(relay);
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
