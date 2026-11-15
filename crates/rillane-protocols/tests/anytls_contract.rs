//! AnyTLS 出口验收（RIL-106）：真实对端 = anytls 库自带服务端面
//! （rcgen 自签 TLS → read_auth → Session::new_server → accept_stream），
//! 与 protocol-backends.md#anytls 记录的角色边界一致——rillane 入口侧
//! 不编目 AnyTLS 监听，对端用库的服务端脸按协议语义应答。
//!
//! 覆盖：TCP 成功回环（文本+二进制）与会话复用、UoT UDP 回环、
//! 错误密码失败、不可达服务器点名错误、流释放对端可见、取消路径资源释放。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anytls::{
    Address, DEFAULT_MAX_SESSION_AGE, DEFAULT_SCHEME, PaddingFactory, Session, StreamIo,
    UotMode, read_auth, uot_encode_packet, uot_get_packet_from_stream,
    uot_get_request_from_stream, uot_is_sentinel_destination,
};
use rillane_core::udp::EgressUdpConnector;
use rillane_core::{EgressConnector, Flow, FlowContext, FlowId, RouteDecision, RoutePath, RouteType, TargetProto};
use rustls::pki_types::pem::PemObject;
use rillane_protocols::{AnytlsConnector, AnytlsUdpConnector};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

const PASSWORD: &str = "ril106-accept-password";

// ---------------------------------------------------------------------------
// 真实对端：库服务端脸 + echo 目标语义
// ---------------------------------------------------------------------------

/// 对端观测计数（验收对资源释放/会话复用的可见面）
#[derive(Clone)]
struct PeerState {
    /// TLS 连接数（= 会话数；两次 forward 共 1 连接即证明池复用）
    conns: Arc<AtomicUsize>,
    /// read_auth 失败数（错误密码验收）
    auth_failures: Arc<AtomicUsize>,
    /// 目标地址读取成功的会话流数
    streams_open: Arc<AtomicUsize>,
    /// 会话流处理结束数（对端视角的释放观察点）
    streams_closed: Arc<AtomicUsize>,
    tcp_streams: Arc<AtomicUsize>,
    udp_streams: Arc<AtomicUsize>,
}

impl PeerState {
    fn new() -> Self {
        Self {
            conns: Arc::new(AtomicUsize::new(0)),
            auth_failures: Arc::new(AtomicUsize::new(0)),
            streams_open: Arc::new(AtomicUsize::new(0)),
            streams_closed: Arc::new(AtomicUsize::new(0)),
            tcp_streams: Arc::new(AtomicUsize::new(0)),
            udp_streams: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// 进程级 ring 安装（与 tls.rs 同法；测试 crate 不可见私有 helper，此处独立）
fn rillane_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider 已安装")
        .clone()
}

/// SOCKS5 地址线格式读取（ATYP + 地址 + 端口 BE；与 socks5-impl
/// write_to_buf 同构——AsyncStreamOperation 特征未被 anytls 再导出）
async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Address> {
    let atyp = r.read_u8().await?;
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            r.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Address::from(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[4], b[5]]),
            )))
        }
        0x04 => {
            let mut b = [0u8; 18];
            r.read_exact(&mut b).await?;
            let octets: [u8; 16] = b[..16].try_into().expect("16 字节 IPv6");
            let ip = Ipv6Addr::from(octets);
            Ok(Address::from(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[16], b[17]]),
            )))
        }
        0x03 => {
            let n = r.read_u8().await? as usize;
            let mut d = vec![0u8; n];
            r.read_exact(&mut d).await?;
            let mut p = [0u8; 2];
            r.read_exact(&mut p).await?;
            Ok(Address::from((
                String::from_utf8_lossy(&d).to_string(),
                u16::from_be_bytes(p),
            )))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("非法 ATYP {other}"),
        )),
    }
}

/// 会话流处理：读目标地址 → sentinel 即 UoT 数据报 echo，否则 TCP echo
/// （echo = 对端目标语义的最小真实实现；流结束即计数，释放可观察）
async fn handle_stream(stream: anytls::Stream, state: PeerState) {
    // Stream 本体不实现 tokio AsyncRead/Write——经 StreamIo（库的 tokio 面）
    let (mut r, mut w) = tokio::io::split(StreamIo::new(stream));
    let target = match read_address(&mut r).await {
        Ok(t) => t,
        Err(_) => return,
    };
    state.streams_open.fetch_add(1, Ordering::SeqCst);

    if uot_is_sentinel_destination(&target) {
        state.udp_streams.fetch_add(1, Ordering::SeqCst);
        // UoT 声明：模式 + 会话目标（库 client_app 同序）
        let request = match uot_get_request_from_stream(&mut r).await {
            Ok(req) => req,
            Err(_) => {
                state.streams_closed.fetch_add(1, Ordering::SeqCst);
                return;
            }
        };
        assert_eq!(request.mode, UotMode::Datagram, "对端仅声明数据报模式");
        loop {
            let (_source, payload) = match uot_get_packet_from_stream(request.mode, &mut r).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let frame = match uot_encode_packet(request.mode, Some(&request.destination), &payload)
            {
                Ok(f) => f,
                Err(_) => break,
            };
            if w.write_all(&frame).await.is_err() {
                break;
            }
        }
    } else {
        state.tcp_streams.fetch_add(1, Ordering::SeqCst);
        // TCP echo：客户端写端关闭（FIN）即终止，回写关闭后下行亦见 EOF
        let _ = tokio::io::copy(&mut r, &mut w).await;
        let _ = w.shutdown().await;
    }
    state.streams_closed.fetch_add(1, Ordering::SeqCst);
}

/// 单 TLS 连接处理：会话认证（库面）→ 服务端会话 → 流接受循环
async fn handle_conn(
    mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    password: String,
    state: PeerState,
    next_id: Arc<AtomicUsize>,
) {
    let padding = Arc::new(RwLock::new(
        PaddingFactory::new(DEFAULT_SCHEME).expect("填充方案"),
    ));
    if read_auth(&mut tls, &password).await.is_err() {
        state.auth_failures.fetch_add(1, Ordering::SeqCst);
        return;
    }
    let id = next_id.fetch_add(1, Ordering::SeqCst);
    let session = Session::new_server(id, Box::new(tls), padding, DEFAULT_MAX_SESSION_AGE);
    // run() 内部 spawn 主循环后立即返回（reader 单次取用）
    if session.run().await.is_err() {
        return;
    }
    while let Ok(stream) = session.accept_stream().await {
        let state = state.clone();
        tokio::spawn(handle_stream(stream, state));
    }
}

/// 真实对端：rcgen 自签 TLS → read_auth → Session::new_server → echo
async fn spawn_anytls_peer(password: &str) -> (SocketAddr, PeerState) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(certified.cert.pem().as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM 解析");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        certified.key_pair.serialize_pem().as_bytes(),
    )
    .expect("私钥读取");

    let builder = rustls::ServerConfig::builder_with_provider(rillane_tls_provider())
        .with_safe_default_protocol_versions()
        .expect("协议版本");
    let acceptor = TlsAcceptor::from(Arc::new(
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("服务端证书装配"),
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let state = PeerState::new();
    let password = password.to_string();
    let next_id = Arc::new(AtomicUsize::new(1));

    let task_state = state.clone();
    tokio::spawn(async move {
        let state = task_state;
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            let password = password.clone();
            let next_id = next_id.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    state.conns.fetch_add(1, Ordering::SeqCst);
                    handle_conn(tls, password, state, next_id).await;
                }
            });
        }
    });
    (addr, state)
}

/// 等待计数到位（对端处理是异步的，验收以 2s 内可见为准）
async fn wait_for(v: &AtomicUsize, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while v.load(Ordering::SeqCst) < expected {
        let got = v.load(Ordering::SeqCst);
        assert!(
            tokio::time::Instant::now() < deadline,
            "等待计数 {expected} 超时（当前 {got}）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// duplex 客户端半边 + Flow（io 为出口侧；与 pool_tls_integration 同法）
fn make_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target: rillane_core::FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

fn connector_at(addr: SocketAddr, password: &str) -> AnytlsConnector {
    AnytlsConnector::new(
        addr.ip().to_string(),
        addr.port(),
        password.to_string(),
        Some("localhost".to_string()),
        true, // 自签证书：skip_cert_verify（与 mock TLS 对端惯例一致）
    )
}

fn flow_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: rillane_core::FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        metadata: Default::default(),
    }
}

fn decision() -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: "test-node".into(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

// ---------------------------------------------------------------------------
// 验收
// ---------------------------------------------------------------------------

/// TCP 成功回环：文本 + 二进制两次 forward，统计字节对账；两次流共用
/// 一条 TLS 连接 = 会话池复用（协议本体的复用面）
#[tokio::test]
async fn tcp_roundtrip_stats_and_session_reuse() {
    let (addr, peer) = spawn_anytls_peer(PASSWORD).await;
    let connector = Arc::new(connector_at(addr, PASSWORD));

    // 文本回环 + 统计对账
    let (flow, mut client) = make_flow("203.0.113.9", 443);
    let connector_task = connector.clone();
    let report =
        tokio::spawn(async move { connector_task.forward(flow).await });
    let payload = b"ril106 anytls tcp roundtrip";
    client.write_all(payload).await.expect("上行写入");
    client.shutdown().await.expect("客户端半边写关闭");
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.expect("下行回读");
    let report = report.await.expect("forward 任务").expect("forward 成功");
    assert_eq!(std::str::from_utf8(&echoed).unwrap(), "ril106 anytls tcp roundtrip");
    assert_eq!(report.upstream, payload.len() as u64, "上行统计对账");
    assert_eq!(report.downstream, payload.len() as u64, "下行统计对账");

    // 二进制回环（同一连接器 → 池复用）
    let (flow, mut client) = make_flow("203.0.113.10", 8443);
    let connector_task = connector.clone();
    let report =
        tokio::spawn(async move { connector_task.forward(flow).await });
    let binary: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    client.write_all(&binary).await.expect("上行写入");
    client.shutdown().await.expect("客户端半边写关闭");
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.expect("下行回读");
    let report = report.await.expect("forward 任务").expect("forward 成功");
    assert_eq!(echoed, binary, "二进制回环一致");
    assert_eq!(report.upstream + report.downstream, (binary.len() * 2) as u64);

    wait_for(&peer.streams_closed, 2).await;
    assert_eq!(
        peer.conns.load(Ordering::SeqCst),
        1,
        "两次 forward 应复用同一会话（单 TLS 连接）"
    );
    assert_eq!(peer.tcp_streams.load(Ordering::SeqCst), 2);
}

/// UoT UDP 回环：数据报上行（粘滞目标）→ 对端按 UotRequest 目标回注；
/// relay drop → 对端流结束可见（资源释放）
#[tokio::test]
async fn udp_uot_roundtrip_and_relay_drop_release() {
    let (addr, peer) = spawn_anytls_peer(PASSWORD).await;
    let connector = connector_at(addr, PASSWORD);
    let udp = AnytlsUdpConnector::from_connector(&connector);

    let relay = udp
        .associate(flow_ctx("198.51.100.7", 53), &decision())
        .await
        .expect("UoT 会话关联");

    let dns_like: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00";
    relay
        .send_to(&flow_ctx("198.51.100.7", 53).target, dns_like)
        .await
        .expect("上行数据报");
    let binary: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
    relay
        .send_to(&flow_ctx("198.51.100.7", 53).target, &binary)
        .await
        .expect("上行二进制数据报");

    let mut buf = vec![0u8; 8192]; // 容纳最大测试载荷（连接器对过小缓冲点名拒绝）
    let (source, len) = relay.recv_from(&mut buf).await.expect("下行数据报");
    assert_eq!(&buf[..len], dns_like, "首个数据报回环一致");
    // 对端按 UotRequest 目标（unspecified v4）回注——线格式行为的诚实断言
    assert_eq!(
        (source.host.as_str(), source.port),
        ("0.0.0.0", 0),
        "回注源 = 对端 UotRequest 会话目标"
    );
    let (source, len) = relay.recv_from(&mut buf).await.expect("下行二进制数据报");
    assert_eq!(&buf[..len], &binary, "二进制数据报回环一致");
    assert_eq!((source.host.as_str(), source.port), ("0.0.0.0", 0));

    wait_for(&peer.udp_streams, 1).await;
    // relay drop → 会话流 FIN → 对端处理结束可见（2s 内）
    drop(relay);
    wait_for(&peer.streams_closed, 1).await;
}

/// 错误密码：对端 read_auth 拒绝（PermissionDenied）→ 客户端 forward
/// 失败且错误点名 AnyTLS；对端认证失败计数可见
#[tokio::test]
async fn wrong_password_fails_named() {
    let (addr, peer) = spawn_anytls_peer("the-right-password").await;
    let connector = connector_at(addr, "wrong-password");

    // 客户端半边持开：对端认证拒绝关连 → 会话死亡杀流 → forward 错误
    // （先 drop 会立即 EOF，回环速度可能赶在对端拒绝前伪装成功）
    let (flow, _client) = make_flow("203.0.113.11", 443);
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        connector.forward(flow),
    )
    .await
    .expect("错误密码 5s 内应出错")
    .expect_err("错误密码必须失败");
    assert!(
        format!("{err:#}").contains("AnyTLS"),
        "错误应点名 AnyTLS: {err:#}"
    );
    wait_for(&peer.auth_failures, 1).await;
}

/// 不可达服务器：TCP 拨号失败 → 错误点名控制连接失败（含 server 上下文）
#[tokio::test]
async fn unreachable_server_names_control_failure() {
    // 127.0.0.1:1 回环保留端口，连接必拒（不依赖外网）
    let connector = AnytlsConnector::new(
        "127.0.0.1".into(),
        1,
        PASSWORD.into(),
        Some("localhost".into()),
        true,
    );
    let (flow, client) = make_flow("203.0.113.12", 443);
    drop(client);
    let err = connector
        .forward(flow)
        .await
        .expect_err("不可达必须失败");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("AnyTLS 控制连接失败"),
        "错误应点名控制连接失败: {rendered}"
    );
    assert!(rendered.contains("127.0.0.1:1"), "错误应携带 server 上下文: {rendered}");
}

/// 取消路径：forward 进行中 abort → 流随 future drop → 对端流结束可见
/// （取消同样释放对端资源，不遗留半开会话流）
#[tokio::test]
async fn cancel_releases_peer_stream() {
    let (addr, peer) = spawn_anytls_peer(PASSWORD).await;
    let connector = Arc::new(connector_at(addr, PASSWORD));

    let (flow, client) = make_flow("203.0.113.13", 443);
    let connector_task = connector.clone();
    let handle = tokio::spawn(async move { connector_task.forward(flow).await });
    // 客户端半边持开不写：forward 停在双向拷贝等待面
    tokio::time::sleep(Duration::from_millis(200)).await;
    wait_for(&peer.streams_open, 1).await;

    handle.abort();
    let _ = handle.await; // JoinError::Cancelled 即取消语义本身
    // 取消 → StreamIo/Flow io drop → 会话流 FIN → 对端 2s 内见释放
    drop(client);
    wait_for(&peer.streams_closed, 1).await;
}
