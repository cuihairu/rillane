//! RIL-110 ShadowTLS v2 载具契约（真实对端，全链回环）。
//!
//! 台架：rcgen 自签伪装站点（rustls acceptor + TLS 回声）+ ShadowTlsIngress
//! （v2 挑战响应切换）+ 真实 ShadowsocksIngress 内层面 + 真 TCP 回声上游；
//! 客户端用 crate 出站面 ShadowsocksShadowTlsConnector。验收面：
//! 成功——SS over shadow-tls v2 全链往返（挑战命中切换）+ FlowReport 字节
//!       + 载具 router/output 零经手（无寻址面组合边界）；
//! 失败——错载具口令：TLS 握手照常成功（主动探测防御形态），内层 SS 面
//!       零流量，连接自然收束；
//! 无辜访客——不带 shadowtls 包装的裸 TLS 访客经载具与伪装站点端到端
//!       往返（主动探测防御的核心承诺）；
//! 主动探测——真 TLS 会话后灌伪挑战记录：不劫持（内层面零流量）、
//!       载具保持中继不悬挂（访客随伪装站点收束）；
//! 取消/资源释放——中途丢弃客户端，伪装站点与内层出口在途连接归零。

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowId, FlowOutput, FlowReport, FlowRouter, FlowTarget,
    IngressEndpoint, RouteDecision, RoutePath, RouteType, TargetProto,
};
use rillane_protocols::{ShadowTlsIngress, ShadowsocksIngress, ShadowsocksShadowTlsConnector};
use rustls::pki_types::pem::PemObject as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CAMO_DOMAIN: &str = "camo.example.test";
const METHOD: &str = "aes-128-gcm";
const SS_PASSWORD: &str = "inner-ss-password";
const CARRIER_PASSWORD: &str = "carrier-password";
const PAYLOAD_LEN: usize = 4096;

// ---------- 共享台架 ----------

fn tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider 已安装")
        .clone()
}

/// 占位 127.0.0.1:0 摘一个空闲端口（listener 在各面内部持有）
fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("占位绑定");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

async fn wait_for(cond: impl Fn() -> bool, limit: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("条件在 {limit:?} 内未达成: {what}");
}

/// 真 TCP 回声上游（内层 SS 面的数据终点）
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
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

/// 伪装站点：rcgen 自签（CAMO_DOMAIN）+ rustls acceptor + TLS 回声；
/// 计在途连接数（资源释放验收）
struct CamoState {
    conns: AtomicUsize,
}

async fn spawn_camo_tls_echo() -> (SocketAddr, Arc<CamoState>) {
    let certified =
        rcgen::generate_simple_self_signed(vec![CAMO_DOMAIN.to_string()]).expect("rcgen 自签");
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(certified.cert.pem().as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM 解析");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        certified.key_pair.serialize_pem().as_bytes(),
    )
    .expect("私钥读取");
    let config = rustls::ServerConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .expect("协议版本")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("伪装站点证书装配");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("伪装站点 bind");
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(CamoState {
        conns: AtomicUsize::new(0),
    });
    let task_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let state = task_state.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                state.conns.fetch_add(1, Ordering::SeqCst);
                let (mut r, mut w) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                state.conns.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, state)
}

/// 内层 SS 面的路由记录器（流量计数；直连决策）
struct RecordingRouter {
    flows: AtomicUsize,
}

impl RecordingRouter {
    fn flow_count(&self) -> usize {
        self.flows.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl FlowRouter for RecordingRouter {
    async fn route(&self, _ctx: FlowContext) -> Result<RouteDecision> {
        self.flows.fetch_add(1, Ordering::SeqCst);
        Ok(RouteDecision {
            path: RoutePath::Direct {
                node: "direct-out".into(),
            },
            reason: None,
            route_type: RouteType::Standard,
        })
    }
}

/// 内层 SS 面的回声出口：连真回声服务双向搬运并计量（在途连接数供释放验收）
struct EchoOutput {
    addr: SocketAddr,
    active: AtomicUsize,
}

impl EchoOutput {
    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl FlowOutput for EchoOutput {
    async fn forward(&self, _decision: RouteDecision, mut flow: Flow) -> Result<FlowReport> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let relayed = async {
            let mut upstream = TcpStream::connect(self.addr).await?;
            let (up, down) = tokio::io::copy_bidirectional(flow.io.as_mut(), &mut upstream).await?;
            Ok::<FlowReport, anyhow::Error>(FlowReport {
                upstream: up,
                downstream: down,
            })
        }
        .await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(relayed?)
    }
}

/// 载具无寻址面：run 的 router/output 不得经手（调用即计数，测试断言为零）
#[derive(Default)]
struct CountingFace {
    calls: AtomicUsize,
}

#[async_trait]
impl FlowRouter for CountingFace {
    async fn route(&self, _ctx: FlowContext) -> Result<RouteDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RouteDecision {
            path: RoutePath::Direct {
                node: "unused".into(),
            },
            reason: None,
            route_type: RouteType::Standard,
        })
    }
}

#[async_trait]
impl FlowOutput for CountingFace {
    async fn forward(&self, _decision: RouteDecision, _flow: Flow) -> Result<FlowReport> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(FlowReport::default())
    }
}

/// 全链台架：真 TCP 回声 ← 内层 SS 入口 ← ShadowTLS 载具 ← 伪装站点 TLS 回声
struct Rig {
    carrier_addr: SocketAddr,
    ss_router: Arc<RecordingRouter>,
    echo_out: Arc<EchoOutput>,
    camo: Arc<CamoState>,
    carrier_face: Arc<CountingFace>,
}

async fn start_rig() -> Rig {
    let echo_addr = spawn_tcp_echo().await;
    let echo_out = Arc::new(EchoOutput {
        addr: echo_addr,
        active: AtomicUsize::new(0),
    });
    let (camo_addr, camo) = spawn_camo_tls_echo().await;

    // 内层 SS 入口（TCP 面）
    let ss_port = reserve_port();
    let ss_router = Arc::new(RecordingRouter {
        flows: AtomicUsize::new(0),
    });
    let ss = ShadowsocksIngress::new(
        "ss-in".into(),
        format!("127.0.0.1:{ss_port}"),
        METHOD.into(),
        SS_PASSWORD.into(),
        None,
        None,
    )
    .expect("内层 SS 入口装配");
    tokio::spawn(Arc::new(ss).run(
        ss_router.clone() as Arc<dyn FlowRouter>,
        echo_out.clone() as Arc<dyn FlowOutput>,
    ));

    // ShadowTLS 载具入口：握手站点 = 伪装站点，数据服务器 = 内层 SS 入口
    let carrier_port = reserve_port();
    let carrier = ShadowTlsIngress::new(
        "stls-in".into(),
        format!("127.0.0.1:{carrier_port}"),
        CARRIER_PASSWORD.into(),
        camo_addr.to_string(),
        format!("127.0.0.1:{ss_port}"),
    )
    .expect("载具装配");
    let carrier_face = Arc::new(CountingFace::default());
    tokio::spawn(Arc::new(carrier).run(
        carrier_face.clone() as Arc<dyn FlowRouter>,
        carrier_face.clone() as Arc<dyn FlowOutput>,
    ));

    sleep(Duration::from_millis(100)).await;
    Rig {
        carrier_addr: format!("127.0.0.1:{carrier_port}").parse().unwrap(),
        ss_router,
        echo_out,
        camo,
        carrier_face,
    }
}

/// SS over shadow-tls 客户端出站面（skip_cert_verify = 台架自签证书）
fn carrier_client(addr: SocketAddr, carrier_password: &str) -> Arc<ShadowsocksShadowTlsConnector> {
    Arc::new(
        ShadowsocksShadowTlsConnector::new(
            addr.ip().to_string(),
            addr.port(),
            CAMO_DOMAIN.into(),
            carrier_password.into(),
            true,
            METHOD.into(),
            SS_PASSWORD.into(),
        )
        .expect("客户端装配"),
    )
}

/// duplex 客户端半边 + Flow（io 为出口侧；与 anytls_contract 同法）
fn make_flow() -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: "echo.internal".into(),
            port: 443,
            proto: TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

/// 无辜访客（裸 rustls，无 shadowtls 包装）的放行验证器
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

fn innocent_connector() -> TlsConnector {
    let crypto = rustls::ClientConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .expect("协议版本")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(crypto))
}

// ---------- 成功面：SS over shadow-tls 全链往返 + 统计 ----------

#[tokio::test]
async fn ss_over_shadowtls_roundtrip_with_stats() {
    let rig = start_rig().await;
    let conn = carrier_client(rig.carrier_addr, CARRIER_PASSWORD);
    let (flow, mut client_half) = make_flow();

    let handle = tokio::spawn({
        let conn = conn.clone();
        async move { conn.forward(flow).await }
    });

    let mut payload = vec![0u8; PAYLOAD_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payload);
    client_half.write_all(&payload).await.expect("上行写入");
    let mut got = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), client_half.read_exact(&mut got))
        .await
        .expect("回声超时")
        .expect("回声读取");
    assert_eq!(got, payload, "全链往返字节一致");

    // 收束客户端半边：copy_bidirectional 见 EOF 后 forward 才返回
    drop(client_half);
    let report = timeout(Duration::from_secs(10), handle)
        .await
        .expect("forward 收束超时")
        .expect("forward 任务")
        .expect("forward 成功");
    assert_eq!(report.upstream, payload.len() as u64, "上行统计字节");
    assert_eq!(report.downstream, payload.len() as u64, "下行统计字节");
    assert_eq!(rig.ss_router.flow_count(), 1, "内层 SS 面恰一流量");
    assert_eq!(
        rig.carrier_face.calls.load(Ordering::SeqCst),
        0,
        "载具无寻址面：router/output 不得经手"
    );
}

// ---------- 失败面：错载具口令 → 无辜中继、内层面零流量 ----------

#[tokio::test]
async fn wrong_carrier_password_keeps_inner_silent() {
    let rig = start_rig().await;
    let conn = carrier_client(rig.carrier_addr, "wrong-carrier-password");
    let (flow, mut client_half) = make_flow();

    let handle = tokio::spawn({
        let conn = conn.clone();
        async move { conn.forward(flow).await }
    });

    // TLS 握手经载具照常完成（挑战属切换面，不属握手面）——此处若握手
    // 失败说明载具把无辜形态掐死，直接暴露
    for _ in 0..8 {
        client_half
            .write_all(&[0xAB; PAYLOAD_LEN])
            .await
            .expect("灌数");
    }

    // 载具对错口令记录转入无辜中继 → 全部落到伪装站点 → 伪装站点解密
    // 失败收束 → 载具中继随对端收束（forward 自然返回，不悬挂）
    let _ = timeout(Duration::from_secs(10), handle)
        .await
        .expect("forward 未收束（无辜中继不得悬挂）");
    assert_eq!(
        rig.ss_router.flow_count(),
        0,
        "错口令不得切换：内层 SS 面零流量"
    );
}

// ---------- 无辜访客：裸 TLS 经载具与伪装站点端到端 ----------

#[tokio::test]
async fn innocent_tls_visitor_reaches_handshake_site() {
    let rig = start_rig().await;
    let connector = innocent_connector();
    let tcp = TcpStream::connect(rig.carrier_addr).await.expect("连载具");
    let mut tls = connector
        .connect(CAMO_DOMAIN.try_into().expect("SNI 名"), tcp)
        .await
        .expect("无辜访客 TLS 握手经载具照常成功");

    // 真会话应用数据经载具往返（前几条记录走挑战比对旁路，>3 条后走
    // 无辜中继——两条路径都须是纯中继语义）
    for i in 0..5u8 {
        let msg = format!("innocent-ping-{i}");
        tls.write_all(msg.as_bytes()).await.expect("无辜访客上行");
        let mut got = vec![0u8; msg.len()];
        timeout(Duration::from_secs(5), tls.read_exact(&mut got))
            .await
            .expect("无辜访客回声超时")
            .expect("无辜访客回声读取");
        assert_eq!(got, msg.as_bytes());
    }
    assert_eq!(rig.ss_router.flow_count(), 0, "无辜访客不得触达内层 SS 面");
}

// ---------- 主动探测：伪挑战记录不劫持、中继不悬挂 ----------

#[tokio::test]
async fn bogus_challenge_records_never_hijack() {
    let rig = start_rig().await;
    let connector = innocent_connector();
    let tcp = TcpStream::connect(rig.carrier_addr).await.expect("连载具");
    let tls = connector
        .connect(CAMO_DOMAIN.try_into().expect("SNI 名"), tcp)
        .await
        .expect("真 TLS 握手经载具照常成功");

    // 收回裸流（会话弃用）：裸灌 4 条形状合法、挑战恒错的伪记录
    let (mut sock, _session) = tls.into_inner();
    for i in 0..4u8 {
        let mut rec = vec![0x17, 0x03, 0x03, 0x00, 8];
        rec.extend_from_slice(&[i.wrapping_add(0x80); 8]);
        sock.write_all(&rec).await.ok(); // 伪装站点可能先行收束，写失败容忍
    }

    // 载具保持中继：伪装站点的告警/收束字节回传且 EOF（不劫持不悬挂）
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), sock.read_to_end(&mut got))
        .await
        .expect("载具收束超时（主动探测不得悬挂）")
        .expect("读取收束");
    assert_eq!(
        rig.ss_router.flow_count(),
        0,
        "伪挑战不得劫持：内层 SS 面零流量"
    );
}

// ---------- 取消/资源释放：中途丢弃客户端 ----------

#[tokio::test]
async fn drop_mid_stream_releases_sockets() {
    let rig = start_rig().await;
    let conn = carrier_client(rig.carrier_addr, CARRIER_PASSWORD);
    let (flow, client_half) = make_flow();

    let handle = tokio::spawn({
        let conn = conn.clone();
        async move { conn.forward(flow).await }
    });

    // 先注一针探针触发挑战切换（切换由数据驱动），等内层 SS 面见流量
    let mut client_half = client_half;
    client_half.write_all(b"probe").await.expect("探针写入");
    wait_for(
        || rig.ss_router.flow_count() == 1,
        Duration::from_secs(5),
        "切换完成（内层 SS 面见流量）",
    )
    .await;

    // 切换后在途注水并立刻丢弃客户端半边（在途取消）
    let _ = client_half.write_all(&[0x11; 65536]).await;
    drop(client_half);
    drop(conn);
    let _ = timeout(Duration::from_secs(5), handle)
        .await
        .expect("forward 收束超时");

    wait_for(
        || rig.echo_out.active() == 0,
        Duration::from_secs(5),
        "内层出口在途归零",
    )
    .await;
    wait_for(
        || rig.camo.conns.load(Ordering::SeqCst) == 0,
        Duration::from_secs(5),
        "伪装站点在途归零",
    )
    .await;
}
