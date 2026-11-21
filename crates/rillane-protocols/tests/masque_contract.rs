//! RIL-120 MASQUE 出口面验收（RFC 9298 CONNECT-UDP + RFC 9114 §4.4 CONNECT）
//!
//! 镜像对端 = 进程内 h3 服务端（与客户端同载具 h3 0.0.8 + h3-quinn 0.0.10 +
//! quinn，仓内既有依赖零新增），两面分别验收：
//! - UDP 面：Extended CONNECT（`:protocol=connect-udp`）协商头逐字段 +
//!   URI 模板展开目标逐字段（平台旁路面：目标由路径承载，客户端不解析
//!   DNS——目标用 `.invalid` 保留域与 IPv6 字面量即证）+ QUIC DATAGRAM 帧
//!   载荷 `varint(qsid) ++ varint(ctx=0) ++ UDP 字节` 线格式（镜像记录帧
//!   解码结果并原样回发，qsid/ctx 逐字节保真）。
//! - TCP 面：CONNECT（无 `:protocol`）→ 2xx 后请求流即纯字节隧道；镜像按
//!   `:authority` 真实拨号 TCP 回声端双向中继（CONNECT 语义）。h3 0.0.8
//!   载具怪癖（Pseudo::request 对 CONNECT 强制注入缺省 `:scheme=https`/
//!   `:path=/`）由本镜像同载具互验钉定。
//!
//! 验收面：成功（协商头/路径/载荷逐字节 + 统计可观测）、失败（4xx 具名 +
//!   状态码点名；capsule-protocol 异值具名；对端未声明 QUIC 数据报具名）、
//!   拒发（异目标/超限载荷具名）、取消/资源释放（relay drop / 流中途取消 →
//!   对端 QUIC 连接收束计数）。
//!
//! 真机交叉面：本地构建的 quic-go/masque-go v0.6.0 cmd/proxy（MIT）见
//! docs/protocol-backends.md#masque；TCP 面真机边界（masque-go proxy 只
//! 注册 URI 模板路径 handler，无通用 CONNECT handler）同留证。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use rcgen::CertifiedKey;
use rillane_core::udp::UdpRelay;
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowId, FlowTarget, RouteDecision, TargetProto,
};
use rillane_protocols::{MasqueConnector, MasqueUdpConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

/// 镜像对端 h3 请求流（resolve_request 返回型）
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// 条件轮询（20ms 步进；对端观测计数异步到站）
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

// ---------- 测试脚手架（flow/ctx/connector） ----------

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

fn tcp_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(64 * 1024);
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

/// 节点配置 = 镜像对端地址 + 自签证书 → skip_cert_verify；缺省 URI 模板
fn udp_connector_of(server: SocketAddr) -> MasqueUdpConnector {
    MasqueUdpConnector::new(server.ip().to_string(), server.port(), None, true, None)
        .expect("UDP 连接器构建")
}

fn tcp_connector_of(server: SocketAddr) -> MasqueConnector {
    MasqueConnector::new(server.ip().to_string(), server.port(), None, true, None)
        .expect("TCP 连接器构建")
}

fn decision() -> RouteDecision {
    RouteDecision::direct("masque-mirror-node".into())
}

fn deterministic(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 + 7) as u8).collect()
}

// ---------- 镜像对端（h3 服务端，两面同进程承载） ----------

/// 镜像观测：请求协商面逐字段
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    authority: String,
    path: String,
    scheme: String,
    /// `:protocol` 伪头（Extended CONNECT；TCP 面恒 None——RFC 9114 §4.4）
    protocol: Option<String>,
    /// capsule-protocol 请求头（UDP 面必发 ?1，RFC 9297 §3.2）
    capsule: Option<String>,
    /// 从 URI 路径解析出的 CONNECT-UDP 目标（平台旁路面：路径承载目标）
    target: Option<FlowTarget>,
}

/// 镜像观测：首帧 H3 数据报线格式（RFC 9297 §2.2 定界头解码）
#[derive(Clone, Debug)]
struct WireFrame {
    qsid: u64,
    ctx: u64,
    frame_len: usize,
    payload_len: usize,
}

#[derive(Default)]
struct MirrorStats {
    connections: AtomicU64,
    /// 连接收束（客户端 drop / relay drop → QUIC 连接关闭 → 服务端可观）
    closed: AtomicU64,
    /// 收到的 H3 数据报帧计数
    datagram_frames: AtomicU64,
}

struct Mirror {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    wire: Arc<Mutex<Option<WireFrame>>>,
    stats: Arc<MirrorStats>,
}

/// 镜像行为开关
struct MirrorCfg {
    /// CONNECT-UDP / CONNECT 应答状态（2xx = 关联/隧道成功）
    reply_status: u16,
    /// CONNECT-UDP 响应 capsule-protocol 头值（"?1" = RFC 9297 §3.2 合规；
    /// 异值测客户端具名拒绝面）
    capsule_value: &'static str,
    /// 对端是否声明 QUIC 数据报（false = datagram_receive_buffer_size
    /// None → 不发 max_datagram_frame_size 传输参数，模拟不支持 UDP
    /// 中继的对端——客户端 max_datagram_size() 即 None）
    datagrams: bool,
}

async fn spawn_mirror(cfg: MirrorCfg) -> Mirror {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("自签证书");
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("协议版本")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("证书装配");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut quinn_server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))
            .expect("QUIC TLS"),
    ));
    if !cfg.datagrams {
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(None);
        quinn_server.transport = Arc::new(transport);
    }

    let endpoint =
        quinn::Endpoint::server(quinn_server, "127.0.0.1:0".parse().unwrap()).expect("bind mirror");
    let addr = endpoint.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let wire = Arc::new(Mutex::new(None));
    let stats = Arc::new(MirrorStats::default());
    let s2 = stats.clone();
    let seen_loop = seen.clone();
    let wire_loop = wire.clone();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else {
                break;
            };
            s2.connections.fetch_add(1, Ordering::SeqCst);
            let s3 = s2.clone();
            let seen = seen_loop.clone();
            let wire = wire_loop.clone();
            let status = cfg.reply_status;
            let capsule = cfg.capsule_value;
            tokio::spawn(async move {
                serve_mirror(conn, status, capsule, seen, wire, s3).await;
            });
        }
    });

    Mirror {
        addr,
        seen,
        wire,
        stats,
    }
}

/// 逐连接服务：解析首个请求 → 按 `:protocol` 分面应答 → UDP 面跑数据报
/// 回发、TCP 面真实拨号中继 → 连接收束计数（资源释放观测面）
async fn serve_mirror(
    conn: quinn::Connection,
    reply_status: u16,
    capsule_value: &'static str,
    seen: Arc<Mutex<Vec<Seen>>>,
    wire: Arc<Mutex<Option<WireFrame>>>,
    stats: Arc<MirrorStats>,
) {
    // 服务端须双开 extended_connect/datagram（否则 h3 拒 :protocol 面）
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true);
    builder.enable_datagram(true);
    let h3: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match builder.build(h3_quinn::Connection::new(conn.clone())).await {
            Ok(h) => h,
            Err(_) => return,
        };
    let mut h3 = h3;
    let Ok(Some(resolver)) = h3.accept().await else {
        return;
    };
    let Ok((req, mut stream)) = resolver.resolve_request().await else {
        return;
    };
    let s = record_seen(&req);
    seen.lock().await.push(s.clone());
    let is_udp = req.extensions().get::<h3::ext::Protocol>().copied()
        == Some(h3::ext::Protocol::CONNECT_UDP);
    let success = http::StatusCode::from_u16(reply_status)
        .expect("状态码")
        .is_success();

    let resp = mirror_response(
        reply_status,
        if is_udp && success {
            Some(capsule_value)
        } else {
            None
        },
    );
    if stream.send_response(resp).await.is_err() {
        return;
    }
    if !success {
        let _ = stream.finish().await;
    } else if is_udp {
        // 数据报面：帧线格式记录 + 原样回发（qsid/ctx 逐字节保真——代理按
        // qsid 查套接字回包同形）
        let dtask = tokio::spawn(datagram_echo(conn.clone(), wire, stats.clone()));
        // CONNECT-UDP 请求体为空——等客户端收束（关流/关连接）
        while let Ok(Some(_)) = stream.recv_data().await {}
        dtask.abort();
        let _ = stream.finish().await;
    } else {
        // TCP 面：CONNECT 语义——按 :authority 真实拨号 + 双向中继
        let authority = s.authority.clone();
        let _ = tokio::spawn(pump_tcp(stream, authority)).await;
    }

    // 保持面：h3 服务端连接保活至客户端侧收束——h3 连接 Drop 会先关控制流
    // （客户端可先看到 H3_NO_ERROR 连接关闭而丢响应，失败面尤甚；hysteria2
    // 镜像同法）。后续请求按 404 收束，连接收束计数随之落定。
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
    conn.closed().await;
    keep.abort();
    stats.closed.fetch_add(1, Ordering::SeqCst);
}

fn mirror_response(status: u16, capsule_value: Option<&str>) -> http::Response<()> {
    let mut builder =
        http::Response::builder().status(http::StatusCode::from_u16(status).expect("状态码"));
    if let Some(v) = capsule_value {
        builder = builder.header("capsule-protocol", v);
    }
    builder.body(()).expect("响应体")
}

/// 请求协商面逐字段记录（方法/authority/路径/scheme/:protocol/capsule/
/// 路径目标）
fn record_seen(req: &http::Request<()>) -> Seen {
    let uri = req.uri();
    let path = uri.path().to_string();
    Seen {
        method: req.method().as_str().to_string(),
        authority: uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_default(),
        path: path.clone(),
        scheme: uri.scheme_str().unwrap_or_default().to_string(),
        protocol: req
            .extensions()
            .get::<h3::ext::Protocol>()
            .map(|p| p.as_str().to_string()),
        capsule: req
            .headers()
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string()),
        target: parse_udp_target(&path),
    }
}

/// URI 路径尾两段 = {target_host}/{target_port}（缺省模板；host 段百分号
/// 解码——客户端 RFC 6570 simple 展开的逆运算，即平台旁路面留证）
fn parse_udp_target(path: &str) -> Option<FlowTarget> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    let port: u16 = segs[segs.len() - 1].parse().ok()?;
    let host = percent_decode(segs[segs.len() - 2])?;
    Some(FlowTarget {
        host,
        port,
        proto: TargetProto::Udp,
    })
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// 数据报回发面：解码首帧留证 + 全帧原样回发
async fn datagram_echo(
    conn: quinn::Connection,
    wire: Arc<Mutex<Option<WireFrame>>>,
    stats: Arc<MirrorStats>,
) {
    while let Ok(frame) = conn.read_datagram().await {
        stats.datagram_frames.fetch_add(1, Ordering::SeqCst);
        if wire.lock().await.is_none() {
            if let Some((qsid, ctx, payload)) = split_h3_datagram(&frame) {
                *wire.lock().await = Some(WireFrame {
                    qsid,
                    ctx,
                    frame_len: frame.len(),
                    payload_len: payload.len(),
                });
            }
        }
        if conn
            .send_datagram_wait(Bytes::copy_from_slice(&frame))
            .await
            .is_err()
        {
            break;
        }
    }
}

/// RFC 9297 §2.2 帧载荷定界：varint(qsid) ++ varint(ctx) ++ 载荷
fn split_h3_datagram(buf: &[u8]) -> Option<(u64, u64, &[u8])> {
    let (a, n1) = varint(buf)?;
    let (b, n2) = varint(&buf[n1..])?;
    Some((a, b, &buf[n1 + n2..]))
}

/// QUIC varint（RFC 9000 §16；测试本地独立实现——与被测代码互为印证）
fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first >> 6 {
        0 => Some((u64::from(first), 1)),
        1 => {
            let b = buf.get(1).copied()?;
            Some(((u16::from_be_bytes([first, b]) & 0x3FFF) as u64, 2))
        }
        _ => {
            let b: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            Some(((u32::from_be_bytes(b) & 0x3FFF_FFFF) as u64, 4))
        }
    }
}

/// TCP 面中继：h3 请求流 ↔ 目标 TCP 套接字双向搬运（拆分半流 + io::split
/// 使两向借用不相交；h3 无 poll 写面 → 手写 select 汇合）
async fn pump_tcp(stream: H3ServerStream, authority: String) -> (u64, u64) {
    let Ok(tcp) = TcpStream::connect(&authority).await else {
        return (0, 0);
    };
    let (send_half, recv_half) = stream.split();
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);

    let up = async move {
        // 目标 → 客户端（读 TCP → h3 发送半流；EOF → finish 即客户端可观 FIN）
        let mut send_half = send_half;
        let mut total = 0u64;
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_half
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = send_half.finish().await;
        total
    };
    let down = async move {
        // 客户端 → 目标（h3 接收半流 → 写 TCP；EOF → shutdown 收束目标侧）
        let mut recv_half = recv_half;
        let mut total = 0u64;
        while let Ok(Some(mut chunk)) = recv_half.recv_data().await {
            while chunk.has_remaining() {
                match tcp_write.write(chunk.chunk()).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        chunk.advance(n);
                        total += n as u64;
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
        total
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
                up_total = r;
            }
            r = &mut down, if !down_done => {
                down_done = true;
                down_total = r;
            }
        }
    }
    (up_total, down_total)
}

/// 纯 TCP 回声端（镜像按 CONNECT :authority 真实拨号到此）
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(socket);
                let mut buf = vec![0u8; 8192];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if w.write_all(&buf[..n]).await.is_err() {
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

// ---------- UDP 成功面 ----------

#[tokio::test]
async fn udp_roundtrip_negotiation_path_and_stats() {
    // 平台旁路面：目标 = 保留域（不可解析）——客户端若试图 DNS 解析目标
    // 即失败；目标仅由 URI 模板展开承载（RFC 9298 §3.1）
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let target_host = "masque-target.invalid";
    let relay = timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx(target_host, 53), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    // 协商面：Extended CONNECT 逐字段（:protocol / capsule-protocol 请求头）
    assert!(
        wait_for(
            || mirror.stats.connections.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(3)
        )
        .await,
        "镜像须收到连接"
    );
    let seen = mirror.seen.lock().await.clone();
    let s = seen.first().expect("镜像须收到请求");
    assert_eq!(s.method, "CONNECT", ":method");
    assert_eq!(s.protocol.as_deref(), Some("connect-udp"), ":protocol");
    assert_eq!(s.capsule.as_deref(), Some("?1"), "capsule-protocol 请求头");
    assert_eq!(
        s.authority,
        format!("{}:{}", mirror.addr.ip(), mirror.addr.port()),
        ":authority = 节点地址"
    );
    // 路径承载目标（缺省模板 .well-known/masque/udp/{host}/{port}/）
    assert!(
        s.path.ends_with("/masque-target.invalid/53/"),
        "路径须承载原样目标: {}",
        s.path
    );
    assert_target(
        s.target.as_ref().expect("路径目标解析"),
        target_host,
        53,
        "路径目标逐字段（平台旁路）",
    );

    // 数据面：单帧载荷逐字节往返 + 线格式留证
    let payload = deterministic(1000);
    relay
        .send_to(&relay_target(target_host, 53), &payload)
        .await
        .expect("send 失败");
    let mut buf = vec![0u8; 65536];
    let (ft, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .expect("recv 失败");
    assert_eq!(n, payload.len(), "载荷长度");
    assert_eq!(&buf[..n], &payload, "载荷须逐字节一致");
    assert_eq!(ft.host, target_host, "回包源 host = 固定目标");
    assert_eq!(ft.port, 53, "回包源 port = 固定目标");
    assert_eq!(ft.proto, TargetProto::Udp, "回包源 proto");

    // 线格式：首帧定界头（ctx=0 即 UDP 载荷；qsid/ctx 各占最小 varint 档）
    let wire = mirror
        .wire
        .lock()
        .await
        .clone()
        .expect("镜像须收到数据报帧");
    assert_eq!(wire.ctx, 0, "Context ID 须为 0（RFC 9297 §2.2）");
    assert_eq!(
        wire.qsid, 0,
        "Quarter Stream ID = 首条客户端双向流（raw 0）>> 2"
    );
    assert_eq!(
        wire.frame_len,
        payload.len() + 2,
        "帧 = varint(qsid) + varint(ctx) + 载荷（各 1 字节档）"
    );
    assert_eq!(wire.payload_len, payload.len(), "载荷长度（线上）");

    // 统计面
    assert_eq!(
        relay.stats().datagrams_sent.load(Ordering::SeqCst),
        1,
        "上行计数"
    );
    assert_eq!(
        relay.stats().datagrams_recv.load(Ordering::SeqCst),
        1,
        "下行计数"
    );
    assert_eq!(
        relay.stats().datagrams_dropped.load(Ordering::SeqCst),
        0,
        "零丢弃"
    );
}

fn relay_target(host: &str, port: u16) -> FlowTarget {
    FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Udp,
    }
}

/// 目标逐字段断言（FlowTarget 未派生 PartialEq——按字段比）
fn assert_target(target: &FlowTarget, host: &str, port: u16, what: &str) {
    assert_eq!(target.host, host, "{what}: host");
    assert_eq!(target.port, port, "{what}: port");
    assert_eq!(target.proto, TargetProto::Udp, "{what}: proto");
}

/// IPv6 字面量目标：RFC 6570 simple 展开（冒号百分号编码）承载于路径
#[tokio::test]
async fn udp_ipv6_target_percent_encoded_in_path() {
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let relay = timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("2001:db8::42", 443), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    let seen = mirror.seen.lock().await.clone();
    let s = seen.first().expect("镜像须收到请求");
    assert!(
        s.path.ends_with("/2001%3Adb8%3A%3A42/443/"),
        "IPv6 冒号须百分号编码: {}",
        s.path
    );
    // 镜像解码后与关联目标逐字段一致（客户端编码 ↔ 代理解码互证）
    assert_target(
        s.target.as_ref().expect("路径目标"),
        "2001:db8::42",
        443,
        "IPv6 路径目标",
    );

    let payload = b"v6-payload".to_vec();
    relay
        .send_to(&relay_target("2001:db8::42", 443), &payload)
        .await
        .expect("send 失败");
    let mut buf = vec![0u8; 65536];
    let (_, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .expect("recv 失败");
    assert_eq!(&buf[..n], &payload, "载荷须逐字节一致");
}

// ---------- UDP 失败面 ----------

#[tokio::test]
async fn udp_proxy_rejection_is_named() {
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 403,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let err = match timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", 9), &decision()),
    )
    .await
    .expect("关联限时")
    {
        Err(e) => e,
        Ok(_) => panic!("代理拒绝（403）必须失败"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("被代理拒绝") && rendered.contains("403"),
        "拒绝须点名状态码: {rendered}"
    );
}

#[tokio::test]
async fn udp_capsule_protocol_mismatch_is_named() {
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?0",
        datagrams: true,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let err = match timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", 9), &decision()),
    )
    .await
    .expect("关联限时")
    {
        Err(e) => e,
        Ok(_) => panic!("capsule-protocol 异值必须失败"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("capsule-protocol"),
        "capsule-protocol 异值须点名拒绝: {rendered}"
    );
}

#[tokio::test]
async fn udp_peer_without_datagrams_is_named() {
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: false,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let err = match timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", 9), &decision()),
    )
    .await
    .expect("关联限时")
    {
        Err(e) => e,
        Ok(_) => panic!("对端无 QUIC 数据报声明必须失败"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("不支持 QUIC 数据报"),
        "不支持组合须点名拒绝: {rendered}"
    );
}

// ---------- UDP 拒发面（异目标 / 超限载荷） ----------

#[tokio::test]
async fn udp_mismatched_target_and_oversized_are_named() {
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let relay = timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", 9), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    // 异目标：CONNECT-UDP 套接字绑定单一目标
    let err = relay
        .send_to(&relay_target("127.0.0.2", 9), b"x")
        .await
        .expect_err("异目标必须拒绝");
    assert!(
        format!("{err:#}").contains("目标不匹配"),
        "异目标须点名拒绝: {err:#}"
    );

    // 超限载荷（> 对端 max_datagram_size；RFC 9297 §2.1 客户端不得发超限帧）
    let oversized = deterministic(65500);
    let err = relay
        .send_to(&relay_target("127.0.0.1", 9), &oversized)
        .await
        .expect_err("超限载荷必须拒绝");
    assert!(
        format!("{err:#}").contains("超限"),
        "超限载荷须点名拒绝: {err:#}"
    );
}

// ---------- UDP 取消/资源释放面 ----------

#[tokio::test]
async fn udp_cancel_drops_relay_and_releases_peer_connection() {
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let udp = udp_connector_of(mirror.addr);

    let relay = timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx("127.0.0.1", 9), &decision()),
    )
    .await
    .expect("关联限时")
    .expect("关联失败");

    // 会话活性：往返一包
    let payload = deterministic(256);
    relay
        .send_to(&relay_target("127.0.0.1", 9), &payload)
        .await
        .expect("send 失败");
    let mut buf = vec![0u8; 65536];
    let (_, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .expect("recv 失败");
    assert_eq!(n, payload.len(), "取消前会话须已建立");

    // 取消：drop relay → QUIC 连接关闭 → 对端可观收束（closed 计数）
    drop(relay);
    assert!(
        wait_for(
            || mirror.stats.closed.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(3)
        )
        .await,
        "取消后对端连接须收束（closed={}）",
        mirror.stats.closed.load(Ordering::SeqCst)
    );
}

// ---------- TCP 成功面 ----------

#[tokio::test]
async fn tcp_connect_tunnel_roundtrip() {
    let echo = spawn_tcp_echo().await;
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let connector = tcp_connector_of(mirror.addr);

    let (flow, mut client) = tcp_flow(&echo.ip().to_string(), echo.port());
    let connector = Arc::new(connector);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    // 上行 → 镜像 CONNECT :authority 真实拨号回声端 → 下行回包
    let payload = b"masque-tcp-face-120".to_vec();
    client.write_all(&payload).await.expect("客户端写入");
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("回声限时")
        .expect("回声读取失败");
    assert_eq!(&buf[..n], &payload, "隧道回声须逐字节一致");

    // 协商面：CONNECT 无 :protocol（RFC 9114 §4.4）+ :authority = 目标；
    // h3 0.0.8 载具怪癖钉定（对 CONNECT 强制注入缺省 :scheme/:path）
    let seen = mirror.seen.lock().await.clone();
    let s = seen.first().expect("镜像须收到请求");
    assert_eq!(s.method, "CONNECT", ":method");
    assert!(
        s.protocol.is_none(),
        "TCP 面不得携 :protocol（got {:?}）",
        s.protocol
    );
    assert_eq!(
        s.authority,
        format!("{}:{}", echo.ip(), echo.port()),
        ":authority = 目标地址"
    );
    assert_eq!(s.scheme, "https", "载具怪癖：缺省 :scheme");
    assert_eq!(s.path, "/", "载具怪癖：缺省 :path");

    // 收束：客户端半关 → 上行 EOF → 隧道半关传播 → FlowReport
    client.shutdown().await.expect("客户端半关");
    let report = timeout(Duration::from_secs(5), task)
        .await
        .expect("forward 限时")
        .expect("join 失败")
        .expect("forward 失败");
    assert!(
        report.upstream >= payload.len() as u64,
        "上行计数（got {}）",
        report.upstream
    );
    assert!(
        report.downstream >= payload.len() as u64,
        "下行计数（got {}）",
        report.downstream
    );
}

// ---------- TCP 失败面 ----------

#[tokio::test]
async fn tcp_proxy_rejection_is_named() {
    let echo = spawn_tcp_echo().await;
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 407,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let connector = tcp_connector_of(mirror.addr);

    let (flow, _client) = tcp_flow(&echo.ip().to_string(), echo.port());
    let err = match timeout(Duration::from_secs(10), connector.forward(flow))
        .await
        .expect("forward 限时")
    {
        Err(e) => e,
        Ok(_) => panic!("代理拒绝（407）必须失败"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("被代理拒绝") && rendered.contains("407"),
        "拒绝须点名状态码: {rendered}"
    );
}

// ---------- TCP 取消/资源释放面 ----------

#[tokio::test]
async fn tcp_cancel_aborts_and_releases_peer_connection() {
    let echo = spawn_tcp_echo().await;
    let mirror = spawn_mirror(MirrorCfg {
        reply_status: 200,
        capsule_value: "?1",
        datagrams: true,
    })
    .await;
    let connector = Arc::new(tcp_connector_of(mirror.addr));

    let (flow, mut client) = tcp_flow(&echo.ip().to_string(), echo.port());
    let task = tokio::spawn(async move { connector.forward(flow).await });
    // 会话活性：一往一复
    client.write_all(b"before-cancel").await.expect("写入");
    let mut buf = vec![0u8; 1024];
    let _ = timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("回声限时")
        .expect("回声读取失败");

    // 中途取消：abort forward（流/连接句柄随任务取消 Drop）→ 对端可观收束
    task.abort();
    drop(client);
    assert!(
        wait_for(
            || mirror.stats.closed.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(3)
        )
        .await,
        "取消后对端连接须收束（closed={}）",
        mirror.stats.closed.load(Ordering::SeqCst)
    );
}

// ---------- 真机对端（quic-go/masque-go v0.6.0 cmd/proxy，MIT） ----------
//
// 缺省跳过（对端二进制在本机固定路径，CI 无此物）；显式运行：
// cargo test -p rillane-protocols --test masque_contract -- --ignored real_peer。
// 留证 docs/protocol-backends.md#masque。

/// 代理进程句柄（析构即杀，防泄漏）
struct ProxyProcess {
    child: std::process::Child,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// 纯 UDP 回声端（真机代理按路径目标转发到此）
async fn spawn_plain_udp_echo() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind echo");
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

/// 真机 UDP 面往返：masque-go proxy（Go 实现）按 RFC 9298 转发到本地 UDP
/// 回声端，载荷逐字节一致——线格式跨实现互证。
#[tokio::test]
#[ignore = "真机对端（/home/cui/masquepeer/masque-proxy），本地手动验收用"]
async fn real_peer_masque_proxy_udp_roundtrip() {
    let binary = std::env::var("MASQUE_PROXY_BIN")
        .unwrap_or_else(|_| "/home/cui/masquepeer/masque-proxy".into());
    if !std::path::Path::new(&binary).exists() {
        eprintln!("skip: 真机对端不在 {binary}");
        return;
    }

    // 自签证书 → 临时 PEM（masque-proxy -c/-k）
    let tmp = std::env::temp_dir().join(format!("rillane-masque-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("临时目录");
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("自签证书");
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("证书写入");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("私钥写入");

    // 选空闲 UDP 端口（先占后放）
    let proxy_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        s.local_addr().unwrap().port()
    };
    let template = format!(
        "https://127.0.0.1:{proxy_port}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
    );
    let log_path = tmp.join("proxy.log");
    let log = std::fs::File::create(&log_path).expect("日志文件");
    let log_err = log.try_clone().expect("日志 dup");
    let child = std::process::Command::new(&binary)
        .arg("-b")
        .arg(format!("127.0.0.1:{proxy_port}"))
        .arg("-c")
        .arg(&cert_path)
        .arg("-k")
        .arg(&key_path)
        .arg("-t")
        .arg(&template)
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err))
        .spawn()
        .expect("masque-proxy 启动");
    let _proxy = ProxyProcess { child };
    let log_of = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // 等代理就绪（QUIC/UDP 端口绑定）
    tokio::time::sleep(Duration::from_millis(800)).await;

    let echo = spawn_plain_udp_echo().await;
    let udp = MasqueUdpConnector::new("127.0.0.1".into(), proxy_port, None, true, None)
        .expect("UDP 连接器");
    let relay = timeout(
        Duration::from_secs(10),
        udp.connect_relay(udp_ctx(&echo.ip().to_string(), echo.port()), &decision()),
    )
    .await
    .expect("关联限时")
    .unwrap_or_else(|e| panic!("关联失败: {e:#}\n对端日志: {}", log_of()));

    let payload = deterministic(64);
    relay
        .send_to(&relay_target(&echo.ip().to_string(), echo.port()), &payload)
        .await
        .expect("send 失败");
    let mut buf = vec![0u8; 65536];
    let (ft, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .expect("recv 限时")
        .unwrap_or_else(|e| panic!("recv 失败: {e:#}\n对端日志: {}", log_of()));
    assert_eq!(n, payload.len(), "载荷长度");
    assert_eq!(&buf[..n], &payload, "真机载荷须逐字节一致");
    assert_eq!(ft.host, echo.ip().to_string(), "回包源 host = 固定目标");
    assert_eq!(ft.port, echo.port(), "回包源 port = 固定目标");
    drop(relay);
}
