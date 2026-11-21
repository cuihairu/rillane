//! RIL-135 Trojan 入口契约（真实对端，crate 出口连接器双面回环）。
//!
//! 驱动真实 `IngressEndpoint::run`（TLS + SHA224 恒时哈希认证 + 两阶段
//! 请求 + UDP-over-TLS 关联），客户端用 crate 真实出口面（TrojanConnector /
//! TrojanUdpRelay），上游为真 TCP/UDP 回声服务。验收面：
//! 成功——TCP 4KB 经 TLS 入口往返 + 元数据（tags/annotations）+ 统计；
//!       UDP 数据报经入口会话表往返（帧格式与出口同源）；
//! 取消/资源释放——客户端收束关联（TLS EOF）触发会话即时出表；
//!       会话空闲回收（sweep_once 驱动）同样出表；
//! 失败——错口令哈希恒时比对不过，客户端收不到任何回声字节；
//! UDP 未启用面——CMD 0x03 被拒（关联收束），TCP 通路照常；
//! 平台旁路——fake-ip 池段目标回填原域名（TCP 元数据 + UDP 端到端）。

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
    TlsFingerprint, TrojanConnector, TrojanIngress, TrojanUdpConnector, TrojanUdpParts,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const INGRESS_NAME: &str = "tj-in";
const PASSWORD: &str = "trojan-ingress-password";
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
            let mut upstream = TcpStream::connect(self.addr).await?;
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
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("回声 UDP 绑定");
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

/// 占位 127.0.0.1:0 摘一个空闲端口（入口内部持有 listener，测试侧无法反查）
fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("占位绑定");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// rcgen 自签证书（入口服务端面；客户端 skip_cert_verify 接受）
fn self_signed_tls_material() -> (String, String) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    (certified.cert.pem(), certified.key_pair.serialize_pem())
}

struct Harness {
    port: u16,
    table: Arc<UdpSessionTable>,
    clock: Arc<MockClock>,
    router: Arc<RecordingRouter>,
}

/// 起 Trojan 入口（TLS TCP 面 + 可选 UDP-over-TLS 面；fake_ip 默认关）
async fn make_ingress(
    password: &str,
    udp: bool,
    echo: SocketAddr,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
) -> Harness {
    let (cert, key) = self_signed_tls_material();
    let port = reserve_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let router = Arc::new(RecordingRouter::default());
    let clock = MockClock::new();
    let config = UdpSessionConfig {
        session_idle: SESSION_IDLE,
        ..Default::default()
    };
    let table = UdpSessionTable::new(config, router.clone(), clock.clone() as Arc<dyn Clock>)
        .expect("会话表装配");
    let udp_parts = udp.then(|| TrojanUdpParts {
        table: table.clone(),
        connector: Arc::new(DirectUdpConnector),
    });
    let ingress = TrojanIngress::new(
        INGRESS_NAME.into(),
        addr.to_string(),
        password.into(),
        &cert,
        &key,
        udp_parts,
        fake_ip,
    )
    .expect("入口装配");
    let output = EchoOutput::new(echo);
    tokio::spawn(Arc::new(ingress).run(router.clone() as Arc<dyn FlowRouter>, output));
    // TCP 监听就绪窗口（占位端口已被本进程释放即复用，无跨进程竞态面）
    sleep(Duration::from_millis(100)).await;
    Harness {
        port,
        table,
        clock,
        router,
    }
}

/// crate 真实出口连接器作对端（skip_cert_verify 接受自签证书）
fn client_connector(h: &Harness, password: &str) -> TrojanConnector {
    TrojanConnector::new(
        "127.0.0.1".to_string(),
        h.port,
        password.to_string(),
        Some("localhost".to_string()),
        true, // skip_cert_verify：自签证书
        TlsFingerprint::None,
        "tcp".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    )
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
async fn tcp_roundtrip(connector: TrojanConnector, target: FlowTarget) -> Vec<u8> {
    let (client_side, ingress_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target,
        io: Box::new(ingress_side),
        metadata: FlowMetadata::default(),
    };
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let mut client = client_side;
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
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

/// 经 crate 真实 UDP 出口面建立关联（TrojanUdpRelay）
async fn udp_associate(h: &Harness, target: FlowTarget) -> Arc<dyn UdpRelay> {
    let connector = client_connector(h, PASSWORD);
    let udp = TrojanUdpConnector::from_connector(&connector);
    let ctx = FlowContext {
        id: FlowId::new(),
        target,
        metadata: FlowMetadata::default(),
    };
    udp.associate(ctx, &RouteDecision::direct("direct-out".to_string()))
        .await
        .expect("UDP 关联")
}

// ---------- 成功面：TCP 往返 + 元数据 + 统计 ----------

#[tokio::test]
async fn tcp_roundtrip_carries_metadata_and_stats() {
    let echo = spawn_tcp_echo().await;
    let h = make_ingress(PASSWORD, false, echo, None).await;
    let connector = client_connector(&h, PASSWORD);
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
        ctx.metadata.tags.iter().any(|i| i == "ingress:trojan"),
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

// ---------- 成功面：UDP 数据报经会话表往返 ----------

#[tokio::test]
async fn udp_datagram_roundtrip_via_session_table() {
    let echo = spawn_udp_echo().await;
    let h = make_ingress(PASSWORD, true, echo, None).await;
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
    // 回包地址段 = 原目标（客户端按地址段区分来源）
    assert_eq!(from.host, echo.ip().to_string(), "回包地址段主机");
    assert_eq!(from.port, echo.port(), "回包地址段端口");
    // 会话入表（与出口 ASSOCIATE/TUN 同表语义）
    assert_eq!(h.table.snapshot().sessions_active, 1, "UDP 会话粘滞在表");
    assert!(h.table.snapshot().bytes_up > 0, "表级上行字节入账");
}

// ---------- 取消面：客户端收束关联 → 会话即时出表 ----------

#[tokio::test]
async fn eof_closes_association_releasing_resources() {
    let echo = spawn_udp_echo().await;
    let h = make_ingress(PASSWORD, true, echo, None).await;
    let target = FlowTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
        proto: TargetProto::Udp,
    };
    let relay = udp_associate(&h, target).await;
    relay
        .send_to(
            &FlowTarget {
                host: echo.ip().to_string(),
                port: echo.port(),
                proto: TargetProto::Udp,
            },
            b"ping",
        )
        .await
        .expect("上行数据报");
    wait_for(
        || h.table.snapshot().sessions_active == 1,
        Duration::from_secs(5),
    )
    .await;

    // 客户端丢弃 relay（TLS 流收束）→ 服务端 uplink EOF → 会话即时回收
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
    let h = make_ingress(PASSWORD, true, echo, None).await;
    let target = FlowTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
        proto: TargetProto::Udp,
    };
    let relay = udp_associate(&h, target).await;
    relay
        .send_to(
            &FlowTarget {
                host: echo.ip().to_string(),
                port: echo.port(),
                proto: TargetProto::Udp,
            },
            b"ping",
        )
        .await
        .expect("上行数据报");
    wait_for(
        || h.table.snapshot().sessions_active == 1,
        Duration::from_secs(5),
    )
    .await;

    // relay 保持存活（TLS 流未断）→ 拨钟过空闲上限 → sweep 回收
    h.clock.advance(SESSION_IDLE.as_secs() + 1);
    let stats = sweep_once(&h.table);
    assert_eq!(stats.sessions_expired, 1, "空闲会话应被回收");
    wait_for(
        || h.table.snapshot().sessions_active == 0,
        Duration::from_secs(5),
    )
    .await;
}

// ---------- 失败面：错口令哈希无回声字节 ----------

#[tokio::test]
async fn wrong_password_delivers_no_echo_bytes() {
    let echo = spawn_tcp_echo().await;
    let h = make_ingress(PASSWORD, false, echo, None).await;
    // 客户端用错口令（SHA224 哈希恒时比对不过，服务端立即收束）
    let connector = client_connector(&h, "definitely-wrong-password");
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
    // 收口：EOF 或错误均可，但任何读到的字节都不得是回声
    let mut buf = Vec::new();
    let outcome = timeout(Duration::from_secs(5), client.read_to_end(&mut buf)).await;
    match outcome {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!("错口令连接须收束（EOF/错误），不得悬挂"),
    }
    assert!(buf.is_empty(), "错口令不得收到任何回声字节：{}", buf.len());
    drop(client);
    let _ = timeout(Duration::from_secs(5), handle).await;
}

// ---------- UDP 未启用面 ----------

#[tokio::test]
async fn udp_disabled_refuses_associate_but_tcp_works() {
    let tcp_echo = spawn_tcp_echo().await;
    let h = make_ingress(PASSWORD, false, tcp_echo, None).await;

    // TCP 通路不受 UDP 关闭影响
    let got = tcp_roundtrip(
        client_connector(&h, PASSWORD),
        FlowTarget {
            host: tcp_echo.ip().to_string(),
            port: tcp_echo.port(),
            proto: TargetProto::Tcp,
        },
    )
    .await;
    assert_eq!(got.len(), 4096);

    // CMD 0x03 被拒：关联面不发应答直接收束 → recv 读到 EOF/错误
    let connector = client_connector(&h, PASSWORD);
    let udp = TrojanUdpConnector::from_connector(&connector);
    let ctx = FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: "127.0.0.1".to_string(),
            port: 53,
            proto: TargetProto::Udp,
        },
        metadata: FlowMetadata::default(),
    };
    let relay = udp
        .associate(ctx, &RouteDecision::direct("direct-out".to_string()))
        .await
        .expect("客户端关联请求写出阶段无服务端往返，本就成功");
    let mut rbuf = vec![0u8; 65535];
    let outcome = timeout(Duration::from_secs(5), relay.recv_from(&mut rbuf)).await;
    match outcome {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("udp 门关闭时不得有任何数据报回程"),
        Err(_) => panic!("udp 门关闭时关联须收束，不得悬挂"),
    }
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
    let h = make_ingress(PASSWORD, false, tcp_echo, Some(table.clone())).await;
    let got = tcp_roundtrip(
        client_connector(&h, PASSWORD),
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
    let h2 = make_ingress(PASSWORD, true, udp_echo, Some(table.clone())).await;
    let relay = udp_associate(
        &h2,
        FlowTarget {
            host: fake_udp.to_string(),
            port: udp_echo.port(),
            proto: TargetProto::Udp,
        },
    )
    .await;
    relay
        .send_to(
            &FlowTarget {
                host: fake_udp.to_string(),
                port: udp_echo.port(),
                proto: TargetProto::Udp,
            },
            b"fakeip-udp",
        )
        .await
        .expect("上行数据报");
    let mut rbuf = vec![0u8; 65535];
    let (from, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut rbuf))
        .await
        .expect("回程超时")
        .expect("回程读取");
    assert_eq!(
        &rbuf[..n],
        b"fakeip-udp",
        "假 IP 数据报经回填域名端到端往返"
    );
    assert_eq!(from.host, resolvable, "回包地址段为回填域名");
    let flows = h2.router.recorded();
    assert!(
        flows
            .iter()
            .any(|f| f.target.proto == TargetProto::Udp && f.target.host == resolvable),
        "UDP 路由面须看到回填域名：{:?}",
        flows.iter().map(|f| &f.target).collect::<Vec<_>>()
    );
}
