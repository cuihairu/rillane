//! RIL-109 Hysteria v1 入口契约（真实对端，crate 出口连接器双面回环）。
//!
//! 驱动真实 `IngressEndpoint::run`（QUIC 端点监听、控制流认证门（版本字节、
//! 速率申报非零硬校验、授权 min 交换、口令恒时比对）、TCP 逐流
//! clientRequest/serverResponse 搬运、udpMessage over QUIC 数据报会话表），
//! 客户端用 crate 真实出口面（HysteriaConnector / HysteriaUdpConnector——
//! RIL-109 自写数据报面），上游为真 TCP/UDP 回声服务。
//!
//! 验收面：
//! 成功——TCP 4KB 经入口 QUIC 流往返 + 元数据（tags/annotations）+ 统计；
//! UDP 数据报经入口会话表往返（回程按服务端回写地址对齐）；
//! 取消/资源释放——客户端收束关联（QUIC 连接收束）触发会话即时出表；
//! 会话空闲回收（sweep_once 驱动）同样出表；
//! 失败——错口令认证门 !OK 拒绝（恒时面），客户端收不到任何回声字节；
//! 速率申报为零 → 服务端协议错误收束（无 serverHello 回包）；
//! 速率面（原生 QUIC 客户端裸驱动）：上限 min 交换、无上限放行申报；
//! UDP 未声明面——服务端回 !OK "UDP disabled"，客户端关联点名拒绝，
//! TCP 通路照常；
//! 平台旁路——fake-ip 池段目标回填原域名（TCP 元数据 + UDP 端到端）；
//! 多流面——同一 QUIC 连接器先后两路 TCP 流独立路由（accept_bi 环）。

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use rcgen::CertifiedKey;
use rillane_core::{
    fake_ip,
    udp::{
        sweep_once, Clock, DirectUdpConnector, EgressUdpConnector, MockClock, UdpRelay,
        UdpSessionConfig, UdpSessionTable,
    },
    EgressConnector, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput, FlowReport, FlowRouter,
    FlowTarget, IngressEndpoint, RouteDecision, TargetProto,
};
use rillane_protocols::{
    HysteriaConnector, HysteriaIngress, HysteriaUdpConnector, HysteriaUdpParts,
};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{sleep, timeout},
};

const INGRESS_NAME: &str = "hy1-in";
const PASSWORD: &str = "hy1-pass-2026";
const WRONG_PASSWORD: &str = "not-the-password";
/// Mbps → BPS（官方 mbpsToBps——裸驱动速率面断言用）
const MBPS: u64 = 1_000_000;
/// 会话空闲上限（测试档：sweep_once 驱动免真钟等待）
const SESSION_IDLE: Duration = Duration::from_secs(2);

// ---------- 测试台架 ----------

/// 记录型路由器：捕获 route 上下文（元数据断言），决策恒直连
#[derive(Default)]
struct RecordingRouter {
    flows: Mutex<Vec<FlowContext>>,
}

impl RecordingRouter {
    fn recorded(&self) -> Vec<FlowContext> {
        self.flows.lock().unwrap().clone()
    }
}

#[async_trait]
impl FlowRouter for RecordingRouter {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        self.flows.lock().unwrap().push(ctx);
        Ok(RouteDecision::direct("direct-out".to_string()))
    }
}

/// 计量型回声出口：连真回声服务双向搬运（与真实出口连接器同形），
/// 记录在途连接数与搬运字节
struct EchoOutput {
    addr: SocketAddr,
    active: AtomicUsize,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

impl EchoOutput {
    fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            addr,
            active: AtomicUsize::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
        })
    }
}

#[async_trait]
impl FlowOutput for EchoOutput {
    async fn forward(&self, _decision: RouteDecision, mut flow: Flow) -> Result<FlowReport> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let relayed = async {
            let mut upstream = tokio::net::TcpStream::connect(self.addr).await?;
            let (up, down) = tokio::io::copy_bidirectional(flow.io.as_mut(), &mut upstream).await?;
            Ok::<FlowReport, anyhow::Error>(FlowReport {
                upstream: up,
                downstream: down,
            })
        }
        .await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        let report = relayed?;
        self.bytes_up.fetch_add(report.upstream, Ordering::Relaxed);
        self.bytes_down
            .fetch_add(report.downstream, Ordering::Relaxed);
        Ok(report)
    }
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回声 TCP 绑定");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(sock);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn spawn_udp_echo() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("回声 UDP 绑定");
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    addr
}

/// 占位 127.0.0.1:0 摘一个空闲端口（入口内部持有 quinn Endpoint，测试侧无法反查）
fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("占位绑定");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// rcgen 自签 TLS 材料（SAN=localhost；客户端 skip_cert_verify 不校验链）
fn self_signed_tls_material() -> (String, String) {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    (cert.pem(), key_pair.serialize_pem())
}

struct Harness {
    port: u16,
    table: Arc<UdpSessionTable>,
    clock: Arc<MockClock>,
    router: Arc<RecordingRouter>,
}

/// 起 Hysteria v1 入口（QUIC 监听 + 速率上限 + 可选数据报 UDP 面；出口恒指 echo）
async fn make_ingress(
    password: &str,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    udp: bool,
    echo: SocketAddr,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
) -> Harness {
    let port = reserve_port();
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let router = Arc::new(RecordingRouter::default());
    let clock = MockClock::new();
    let config = UdpSessionConfig {
        session_idle: SESSION_IDLE,
        ..Default::default()
    };
    let table = UdpSessionTable::new(config, router.clone(), clock.clone() as Arc<dyn Clock>)
        .expect("会话表装配");
    let udp_parts = udp.then(|| HysteriaUdpParts {
        table: table.clone(),
        connector: Arc::new(DirectUdpConnector),
    });
    let (cert, key) = self_signed_tls_material();
    let ingress = HysteriaIngress::new(
        INGRESS_NAME.into(),
        bind.to_string(),
        password,
        &cert,
        &key,
        up_mbps,
        down_mbps,
        udp_parts,
        fake_ip,
    )
    .expect("入口装配");
    let output = EchoOutput::new(echo);
    tokio::spawn(Arc::new(ingress).run(router.clone() as Arc<dyn FlowRouter>, output));
    // QUIC 端点绑定就绪窗口（占位端口已被本进程释放即复用，无跨进程竞态面）
    sleep(Duration::from_millis(100)).await;
    Harness {
        port,
        table,
        clock,
        router,
    }
}

async fn make_ingress_default(password: &str, udp: bool, echo: SocketAddr) -> Harness {
    make_ingress(password, None, None, udp, echo, None).await
}

/// crate 真实出口连接器作对端（自签证书：skip_cert_verify——测试面不验链；
/// ALPN 缺省 "hysteria" 由连接器内建；protocol 恒 "udp"——原生 QUIC 载具）
#[allow(clippy::too_many_arguments)]
fn client_connector(
    h: &Harness,
    password: &str,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
) -> HysteriaConnector {
    HysteriaConnector::new(
        "127.0.0.1".to_string(),
        h.port,
        password.to_string(),
        Some("udp".to_string()), // protocol（原生 UDP 上的 QUIC）
        up_mbps,
        down_mbps,
        None, // auth
        None, // auth_str
        None, // obfs（服务端面不交付，客户端携带即判负）
        None, // obfs_param
        None, // server_name（skip_cert_verify 下不校验）
        true, // skip_cert_verify
        None, // alpn（缺省 "hysteria"）
    )
}

fn client_connector_default(h: &Harness, password: &str) -> HysteriaConnector {
    client_connector(h, password, None, None)
}

async fn wait_for(cond: impl Fn() -> bool, limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("条件在 {limit:?} 内未达成");
}

/// 真出口连接器驱动的 TCP 4KB 往返（duplex 流作入口侧消费端）
async fn tcp_roundtrip(connector: HysteriaConnector, target: FlowTarget) -> Vec<u8> {
    let (client_side, ingress_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target,
        io: Box::new(ingress_side),
        metadata: FlowMetadata::default(),
    };
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let mut client = client_side;
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 249) as u8).collect();
    client.write_all(&payload).await.expect("上行写入");
    let mut got = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), client.read_exact(&mut got))
        .await
        .expect("回声超时")
        .expect("回声读取");
    // 收束客户端半 → 双向搬运 EOF → forward 归还统计
    drop(client);
    let report = timeout(Duration::from_secs(5), handle)
        .await
        .expect("forward 收束超时")
        .expect("forward join")
        .expect("forward 成功");
    assert!(report.upstream > 0, "客户端统计上行字节: {report:?}");
    assert!(report.downstream > 0, "客户端统计下行字节: {report:?}");
    got
}

/// 经 crate 真实 UDP 出口面建立关联（服务端 UDP 门开才建）
async fn udp_associate(h: &Harness, target: FlowTarget) -> Arc<dyn UdpRelay> {
    let connector = client_connector_default(h, PASSWORD);
    let udp = HysteriaUdpConnector::from_connector(&connector);
    let ctx = FlowContext {
        id: FlowId::new(),
        target,
        metadata: FlowMetadata::default(),
    };
    udp.associate(ctx, &RouteDecision::direct("direct-out".to_string()))
        .await
        .expect("UDP 关联")
}

// ---------- 裸 QUIC 客户端（速率面：绕开 crate 连接器的拨号期旋钮） ----------

/// 全收证书校验面（裸驱动自签对端；签名面全收——rcgen 键族不定，广谱广告）
#[derive(Debug)]
struct AcceptAll;

const BROAD_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::ED25519,
];

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        BROAD_SCHEMES.to_vec()
    }
}

/// serverHello 解形：[OK u8][SendBPS BE][RecvBPS BE][MsgLen BE][Msg]
async fn raw_client_hello(
    port: u16,
    auth: &[u8],
    send_bps: u64,
    recv_bps: u64,
) -> Result<std::result::Result<(bool, u64, u64, String), String>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut crypto = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"hysteria".to_vec()];
    let client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("QUIC TLS 配置"),
    ));
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().expect("端点绑定")).expect("客户端端点");
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost")
        .expect("连接发起")
        .await
        .expect("QUIC 握手");

    let (mut send, mut recv) = conn.open_bi().await.expect("控制流打开");
    // clientHello：[版本 0x03][SendBPS BE][RecvBPS BE][AuthLen BE][Auth]
    let mut hello = Vec::with_capacity(1 + 16 + 2 + auth.len());
    hello.push(0x03u8);
    hello.extend_from_slice(&send_bps.to_be_bytes());
    hello.extend_from_slice(&recv_bps.to_be_bytes());
    hello.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    hello.extend_from_slice(auth);
    send.write_all(&hello).await.expect("hello 写入");

    // serverHello 读形（连接被协议错误收束 → 读失败 → Err 面）
    let mut ok = [0u8; 1];
    if recv.read_exact(&mut ok).await.is_err() {
        return Ok(Err("connection closed without serverHello".to_string()));
    }
    let mut head = [0u8; 8 + 8 + 2];
    recv.read_exact(&mut head).await.expect("serverHello 头");
    let granted_send = u64::from_be_bytes(head[0..8].try_into().unwrap());
    let granted_recv = u64::from_be_bytes(head[8..16].try_into().unwrap());
    let msg_len = u16::from_be_bytes(head[16..18].try_into().unwrap()) as usize;
    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf)
        .await
        .expect("serverHello 消息");
    let msg = String::from_utf8(msg_buf).expect("serverHello 消息 UTF-8");
    Ok(Ok((ok[0] == 1, granted_send, granted_recv, msg)))
}

// ---------- 成功面：TCP 往返 + 元数据 + 统计 ----------

#[tokio::test]
async fn tcp_roundtrip_carries_metadata_and_stats() {
    let echo = spawn_tcp_echo().await;
    let h = make_ingress_default(PASSWORD, false, echo).await;
    let connector = client_connector_default(&h, PASSWORD);
    let got = tcp_roundtrip(
        connector,
        FlowTarget {
            host: echo.ip().to_string(),
            port: echo.port(),
            proto: TargetProto::Tcp,
        },
    )
    .await;
    assert_eq!(got.len(), 4096, "回声长度");

    // 元数据：入口标签 + 节点名 + 客户端地址 + 直连目标
    let flows = h.router.recorded();
    assert_eq!(flows.len(), 1, "恰一路 TCP flow");
    let ctx = &flows[0];
    assert_eq!(ctx.target.host, echo.ip().to_string());
    assert_eq!(ctx.target.port, echo.port());
    assert_eq!(ctx.target.proto, TargetProto::Tcp);
    assert!(
        ctx.metadata.tags.contains(&"ingress:hysteria".to_string()),
        "入口标签缺失：{:?}",
        ctx.metadata.tags
    );
    assert!(
        ctx.metadata.tags.contains(&format!("node:{INGRESS_NAME}")),
        "节点标签缺失：{:?}",
        ctx.metadata.tags
    );
    assert!(
        ctx.metadata.annotations.contains_key("client.addr"),
        "客户端地址注记缺失"
    );
    assert_eq!(
        ctx.metadata
            .annotations
            .get("ingress.node")
            .map(String::as_str),
        Some(INGRESS_NAME)
    );
}

// ---------- 多流面：先后两路流独立路由（accept_bi 环） ----------

#[tokio::test]
async fn tcp_streams_route_independently_across_two_targets() {
    let echo_a = spawn_tcp_echo().await;
    let echo_b = spawn_tcp_echo().await;
    let h = make_ingress_default(PASSWORD, false, echo_a).await;

    for echo in [echo_a, echo_b] {
        let got = tcp_roundtrip(
            client_connector_default(&h, PASSWORD),
            FlowTarget {
                host: echo.ip().to_string(),
                port: echo.port(),
                proto: TargetProto::Tcp,
            },
        )
        .await;
        assert_eq!(got.len(), 4096, "各流独立 4KB 往返");
    }
    let flows = h.router.recorded();
    assert_eq!(flows.len(), 2, "两路 flow 独立入路由");
    assert_ne!(flows[0].target.port, flows[1].target.port, "目标各自对位");
}

// ---------- 成功面：UDP 数据报经会话表往返 ----------

#[tokio::test]
async fn udp_datagram_roundtrip_via_session_table() {
    let echo = spawn_udp_echo().await;
    let h = make_ingress_default(PASSWORD, true, echo).await;
    let target = FlowTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
        proto: TargetProto::Udp,
    };
    let relay = udp_associate(&h, target.clone()).await;
    let payload = b"ingress-udp-ping".to_vec();
    relay.send_to(&target, &payload).await.expect("上行数据报");
    let mut rbuf = vec![0u8; 65535];
    let (from, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut rbuf))
        .await
        .expect("回程超时")
        .expect("回程读取");
    assert_eq!(&rbuf[..n], &payload[..], "数据报回声字节");
    // 回程按服务端回写的数据报地址对齐（真源地址语义）
    assert_eq!(from.host, echo.ip().to_string(), "回程源地址");
    assert_eq!(from.port, echo.port(), "回程源端口");
    // 会话入表（与出口 ASSOCIATE/TUN 同表语义）
    assert_eq!(h.table.snapshot().sessions_active, 1, "UDP 会话粘滞在表");
    assert!(h.table.snapshot().bytes_up > 0, "表级上行字节入账");
}

// ---------- 取消面：客户端收束关联 → 会话即时出表 ----------

#[tokio::test]
async fn eof_closes_association_releasing_resources() {
    let echo = spawn_udp_echo().await;
    let h = make_ingress_default(PASSWORD, true, echo).await;
    let target = FlowTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
        proto: TargetProto::Udp,
    };
    let relay = udp_associate(&h, target.clone()).await;
    relay.send_to(&target, b"ping").await.expect("上行数据报");
    wait_for(
        || h.table.snapshot().sessions_active == 1,
        Duration::from_secs(5),
    )
    .await;

    // 客户端丢弃 relay（QUIC 连接收束）→ 服务端数据报环收束 → 会话即时回收
    drop(relay);
    wait_for(
        || h.table.snapshot().sessions_active == 0,
        Duration::from_secs(5),
    )
    .await;
}

// ---------- 资源释放面：空闲回收出表 ----------

#[tokio::test]
async fn idle_session_is_reclaimed_releasing_resources() {
    let echo = spawn_udp_echo().await;
    let h = make_ingress_default(PASSWORD, true, echo).await;
    let target = FlowTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
        proto: TargetProto::Udp,
    };
    let relay = udp_associate(&h, target.clone()).await;
    relay.send_to(&target, b"ping").await.expect("上行数据报");
    wait_for(
        || h.table.snapshot().sessions_active == 1,
        Duration::from_secs(5),
    )
    .await;

    // relay 保持存活（QUIC 连接未断）→ 拨钟过空闲上限 → sweep 回收
    h.clock.advance(SESSION_IDLE.as_secs() + 1);
    let stats = sweep_once(&h.table);
    assert_eq!(stats.sessions_expired, 1, "空闲会话应被回收");
    wait_for(
        || h.table.snapshot().sessions_active == 0,
        Duration::from_secs(5),
    )
    .await;
}

// ---------- 失败面：错口令认证门拒绝、零回声 ----------

#[tokio::test]
async fn wrong_password_forward_fails_with_no_echo() {
    let echo = spawn_tcp_echo().await;
    let h = make_ingress_default(PASSWORD, false, echo).await;
    // 客户端用错口令 → 服务端恒时比对不过 → !OK "auth error" → 客户端认证面报错
    let connector = client_connector_default(&h, WRONG_PASSWORD);
    let (client_side, ingress_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: echo.ip().to_string(),
            port: echo.port(),
            proto: TargetProto::Tcp,
        },
        io: Box::new(ingress_side),
        metadata: FlowMetadata::default(),
    };
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let mut client = client_side;
    let _ = client.write_all(b"secret-request").await;
    // 认证门拒绝：客户端连接收束，任何读到的字节都不得是回声
    let mut buf = Vec::new();
    let outcome = timeout(Duration::from_secs(5), client.read_to_end(&mut buf)).await;
    match outcome {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!("错口令连接须收束（EOF/错误），不得悬挂"),
    }
    assert!(buf.is_empty(), "错口令不得收到任何回声字节：{}", buf.len());
    drop(client);
    let forward = timeout(Duration::from_secs(5), handle)
        .await
        .expect("forward 收束超时")
        .expect("forward join");
    // 连接器点名认证拒绝（!OK serverHello 文案）
    let err = forward.expect_err("错口令 forward 必须报错");
    let msg = format!("{err:#}");
    assert!(msg.contains("拒绝"), "错误须点名认证拒绝：{msg}");
}

// ---------- 失败面：速率申报为零 → 服务端协议错误收束（无 serverHello） ----------

#[tokio::test]
async fn zero_rate_client_hello_refused_with_protocol_error() {
    let echo = spawn_tcp_echo().await;
    let h = make_ingress_default(PASSWORD, false, echo).await;
    // 官方口径：任一申报为零 = "invalid rate from client" 协议错误——
    // serverHello 不回包，QUIC 连接按应用错误码收束
    let outcome = timeout(
        Duration::from_secs(5),
        raw_client_hello(h.port, PASSWORD.as_bytes(), 0, 100 * MBPS),
    )
    .await
    .expect("裸驱动超时")
    .expect("裸驱动失败");
    let Err(closed) = outcome else {
        panic!("零速率申报必须被协议错误收束，不得回 serverHello");
    };
    assert!(closed.contains("closed"), "收束文案面：{closed}");

    // 对照组：同连接器合法申报照常认证通过（协议错误面归零申报本身）
    let ok = timeout(
        Duration::from_secs(5),
        raw_client_hello(h.port, PASSWORD.as_bytes(), 50 * MBPS, 100 * MBPS),
    )
    .await
    .expect("裸驱动超时")
    .expect("裸驱动失败");
    let Ok((granted, send, recv, _)) = ok else {
        panic!("合法申报必须认证通过");
    };
    assert!(granted, "合法申报 OK 位");
    assert_eq!(send, 100 * MBPS, "无上限：serverSend = min(clientRecv, ∞)");
    assert_eq!(recv, 50 * MBPS, "无上限：serverRecv = min(clientSend, ∞)");
}

// ---------- 速率面：授权 min 交换（上限 >0 才施加） ----------

#[tokio::test]
async fn rate_negotiation_caps_apply_only_above_zero() {
    let echo = spawn_tcp_echo().await;
    // 服务端上限：发送 50M（封客户端下行申报），接收不设上限
    let h = make_ingress(PASSWORD, Some(50), None, false, echo, None).await;
    // 客户端申报 Send=200M（上行）Recv=100M（下行）：
    // serverSend = min(clientRecv=100M, cap=50M) = 50M
    // serverRecv = min(clientSend=200M, 无上限) = 200M
    let outcome = timeout(
        Duration::from_secs(5),
        raw_client_hello(h.port, PASSWORD.as_bytes(), 200 * MBPS, 100 * MBPS),
    )
    .await
    .expect("裸驱动超时")
    .expect("裸驱动失败");
    let Ok((granted, send, recv, _)) = outcome else {
        panic!("上限协商必须认证通过");
    };
    assert!(granted, "OK 位");
    assert_eq!(send, 50 * MBPS, "serverSend 被上限封顶: min(100M, 50M)");
    assert_eq!(recv, 200 * MBPS, "serverRecv 无上限放行申报: 200M");

    // 上限高于申报时不封顶（官方：cap < client 速率才施加）
    let h2 = make_ingress(PASSWORD, Some(500), Some(400), false, echo, None).await;
    let outcome = timeout(
        Duration::from_secs(5),
        raw_client_hello(h2.port, PASSWORD.as_bytes(), 200 * MBPS, 100 * MBPS),
    )
    .await
    .expect("裸驱动超时")
    .expect("裸驱动失败");
    let Ok((granted, send, recv, _)) = outcome else {
        panic!("宽上限协商必须认证通过");
    };
    assert!(granted, "OK 位");
    assert_eq!(send, 100 * MBPS, "宽上限不封顶: min(100M, 500M)");
    assert_eq!(recv, 200 * MBPS, "宽上限不封顶: min(200M, 400M)");
}

// ---------- UDP 未声明面 ----------

#[tokio::test]
async fn udp_disabled_refuses_associate_but_tcp_works() {
    let tcp_echo = spawn_tcp_echo().await;
    let h = make_ingress_default(PASSWORD, false, tcp_echo).await;

    // TCP 通路不受 UDP 关闭影响
    let got = tcp_roundtrip(
        client_connector_default(&h, PASSWORD),
        FlowTarget {
            host: tcp_echo.ip().to_string(),
            port: tcp_echo.port(),
            proto: TargetProto::Tcp,
        },
    )
    .await;
    assert_eq!(got.len(), 4096);

    // UDP 会话请求 → 服务端回 !OK "UDP disabled" → 客户端关联点名拒绝（不建哑管道）
    let connector = client_connector_default(&h, PASSWORD);
    let udp = HysteriaUdpConnector::from_connector(&connector);
    let ctx = FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: "127.0.0.1".to_string(),
            port: 53,
            proto: TargetProto::Udp,
        },
        metadata: FlowMetadata::default(),
    };
    let outcome = udp
        .associate(ctx, &RouteDecision::direct("direct-out".to_string()))
        .await;
    let Err(err) = outcome else {
        panic!("udp 未开时关联必须失败");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("UDP"), "拒绝文案须点名 UDP：{msg}");
    // 无会话入表（关联从未建立）
    assert_eq!(h.table.snapshot().sessions_active, 0, "不得有会话粘滞");
}

// ---------- 平台旁路面：fake-ip 池段回填原域名 ----------

#[tokio::test]
async fn fakeip_targets_reversed_to_original_domains() {
    let tcp_echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let table = Arc::new(fake_ip::FakeIpTable::from_cidr("198.18.0.0/15").expect("fake-ip 池装配"));
    let domain = "fakeip-reverse.example.test";
    let fake: Ipv4Addr = table.alloc(domain);
    assert!(table.reverse(&fake).is_some(), "池内地址须可反查");

    // TCP：目标为池段假 IP → 路由面看到原域名 + dns.fakeip 注记
    let h = make_ingress(PASSWORD, None, None, false, tcp_echo, Some(table.clone())).await;
    let got = tcp_roundtrip(
        client_connector_default(&h, PASSWORD),
        FlowTarget {
            host: fake.to_string(),
            port: tcp_echo.port(),
            proto: TargetProto::Tcp,
        },
    )
    .await;
    assert_eq!(got.len(), 4096, "回声经回填域名照常往返");
    let flows = h.router.recorded();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].target.host, domain, "假 IP 须回填原域名");
    assert_eq!(
        flows[0]
            .metadata
            .annotations
            .get("dns.fakeip")
            .map(String::as_str),
        Some(domain)
    );

    // UDP：数据报目标为池段假 IP → 回填域名可解析（localhost 级）→ 端到端往返
    let resolvable = "localhost";
    let fake_udp: Ipv4Addr = table.alloc(resolvable);
    let h2 = make_ingress(PASSWORD, None, None, true, udp_echo, Some(table.clone())).await;
    let target = FlowTarget {
        host: fake_udp.to_string(),
        port: udp_echo.port(),
        proto: TargetProto::Udp,
    };
    let relay = udp_associate(&h2, target.clone()).await;
    relay
        .send_to(&target, b"fakeip-udp")
        .await
        .expect("上行数据报");
    let mut rbuf = vec![0u8; 65535];
    let (_from, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut rbuf))
        .await
        .expect("回程超时")
        .expect("回程读取");
    assert_eq!(
        &rbuf[..n],
        b"fakeip-udp",
        "假 IP 数据报经回填域名端到端往返"
    );
    let flows = h2.router.recorded();
    assert!(
        flows
            .iter()
            .any(|f| f.target.proto == TargetProto::Udp && f.target.host == resolvable),
        "UDP 路由面须看到回填域名：{:?}",
        flows.iter().map(|f| &f.target).collect::<Vec<_>>()
    );
}
