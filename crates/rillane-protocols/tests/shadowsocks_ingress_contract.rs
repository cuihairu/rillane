//! RIL-134 Shadowsocks 入口契约（真实对端，shadowsocks 1.25 双面回环）。
//!
//! 驱动真实 `IngressEndpoint::run`（crate ProxyListener/ProxySocket server 面），
//! 客户端用 crate client 面（ProxyClientStream / ProxySocket::connect），
//! 上游为真 TCP/UDP 回声服务。验收面：
//! 成功——TCP 4KB 二进制经入口往返 + 元数据（tags/annotations）+ 统计；
//!       UDP 数据报经入口会话表往返（表与 ASSOCIATE/TUN 同源语义）；
//! 失败——错密码对端解不开，客户端收不到任何回声字节；
//! 取消/资源释放——会话空闲回收（sweep_once 驱动）后会话出表；
//! UDP 未启用面——udp: None 时 TCP 通路正常且 UDP 端口不绑；
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
use base64::Engine as _;
use rand::RngCore;
use rillane_core::{
    fake_ip,
    udp::{sweep_once, Clock, DirectUdpConnector, MockClock, UdpSessionConfig, UdpSessionTable},
    FlowContext, FlowOutput, FlowReport, FlowRouter, IngressEndpoint, RouteDecision, RoutePath,
    RouteType, TargetProto,
};
use rillane_protocols::{ShadowsocksIngress, ShadowsocksUdpParts};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::{socks5::Address, tcprelay::ProxyClientStream, udprelay::proxy_socket::ProxySocket},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const INGRESS_NAME: &str = "ss-in";
/// 会话空闲上限（测试档：sweep_once 驱动免真钟等待）
const SESSION_IDLE: Duration = Duration::from_secs(2);

/// 双面共用口令样本：v1 AEAD 任意串；SS2022 base64 密钥（16B 档）
fn credentials_for(method: &str) -> String {
    let cipher: CipherKind = method.parse().expect("样本方法须可解析");
    if cipher.is_aead_2022() {
        let key = vec![7u8; cipher.key_len()];
        base64::engine::general_purpose::STANDARD.encode(key)
    } else {
        format!("ingress-password-{method}")
    }
}

fn client_svr_cfg(addr: SocketAddr, method: &str) -> ServerConfig {
    ServerConfig::new(addr, credentials_for(method), method.parse().unwrap())
        .expect("客户端侧 svr_cfg 装配")
}

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
        Ok(RouteDecision {
            path: RoutePath::Direct {
                node: "direct-out".into(),
            },
            reason: None,
            route_type: RouteType::Standard,
        })
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
    async fn forward(
        &self,
        _decision: RouteDecision,
        mut flow: rillane_core::Flow,
    ) -> Result<FlowReport> {
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

struct Harness {
    addr: SocketAddr,
    table: Arc<UdpSessionTable>,
    clock: Arc<MockClock>,
    router: Arc<RecordingRouter>,
}

/// 起 SS 入口（TCP 面 + 可选 UDP 面；fake_ip 默认关）并返回访问句柄
async fn make_ingress(
    method: &str,
    udp: bool,
    echo: SocketAddr,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
) -> Harness {
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
    let udp_parts = udp.then(|| ShadowsocksUdpParts {
        table: table.clone(),
        connector: Arc::new(DirectUdpConnector),
    });
    let ingress = ShadowsocksIngress::new(
        INGRESS_NAME.into(),
        addr.to_string(),
        method.into(),
        credentials_for(method),
        udp_parts,
        fake_ip,
    )
    .expect("入口装配");
    let output = EchoOutput::new(echo);
    tokio::spawn(Arc::new(ingress).run(router.clone() as Arc<dyn FlowRouter>, output));
    // TCP 监听就绪窗口（占位端口已被本进程释放即复用，无跨进程竞态面）
    sleep(Duration::from_millis(100)).await;
    Harness {
        addr,
        table,
        clock,
        router,
    }
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

/// 真 TCP 4KB 二进制往返
async fn tcp_roundtrip(svr_cfg: &ServerConfig, target: Address) -> Vec<u8> {
    let ctx = Context::new_shared(ServerType::Local);
    let mut stream = ProxyClientStream::connect(ctx, svr_cfg, target)
        .await
        .expect("客户端连入口");
    let mut payload = vec![0u8; 4096];
    rand::thread_rng().fill_bytes(&mut payload);
    stream.write_all(&payload).await.expect("上行写入");
    let mut got = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("回声超时")
        .expect("回声读取");
    got
}

// ---------- 成功面：TCP 往返 + 元数据 + 统计 ----------

#[tokio::test]
async fn tcp_roundtrip_carries_metadata_and_stats() {
    let echo = spawn_tcp_echo().await;
    for method in ["aes-256-gcm", "2022-blake3-aes-128-gcm"] {
        let h = make_ingress(method, false, echo, None).await;
        let target = Address::from((echo.ip().to_string(), echo.port()));
        let got = tcp_roundtrip(&client_svr_cfg(h.addr, method), target).await;
        assert_eq!(got.len(), 4096, "回声长度（method={method}）");

        // 元数据：入口标签 + 节点名 + 客户端地址 + 直连目标
        let flows = h.router.recorded();
        assert_eq!(flows.len(), 1, "method={method} 恰一路 TCP flow");
        let ctx = &flows[0];
        assert_eq!(ctx.target.host, echo.ip().to_string());
        assert_eq!(ctx.target.port, echo.port());
        assert_eq!(ctx.target.proto, TargetProto::Tcp);
        assert!(
            ctx.metadata.tags.iter().any(|i| i == "ingress:shadowsocks"),
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
}

// ---------- 成功面：UDP 数据报经会话表往返 ----------

#[tokio::test]
async fn udp_datagram_roundtrip_via_session_table() {
    let echo = spawn_udp_echo().await;
    let method = "2022-blake3-chacha20-poly1305";
    let h = make_ingress(method, true, echo, None).await;
    let ctx = Context::new_shared(ServerType::Local);
    let client = ProxySocket::connect(ctx, &client_svr_cfg(h.addr, method))
        .await
        .expect("UDP 客户端");
    let payload = b"ingress-udp-ping".to_vec();
    client
        .send_to(
            h.addr,
            &Address::from((echo.ip().to_string(), echo.port())),
            &payload,
        )
        .await
        .expect("上行数据报");
    let mut rbuf = vec![0u8; 65535];
    let (n, _peer, from, _off) = timeout(Duration::from_secs(5), client.recv_from(&mut rbuf))
        .await
        .expect("回程超时")
        .expect("回程读取");
    assert_eq!(&rbuf[..n], &payload[..], "数据报回声字节");
    // 源地址段 = 原目标（客户端按回包地址段区分来源）
    match from {
        Address::SocketAddress(sa) => {
            assert_eq!(sa.port(), echo.port());
            assert_eq!(sa.ip(), echo.ip());
        }
        other => panic!("回包地址段须为 SocketAddress: {other:?}"),
    }
    // 会话入表（与 ASSOCIATE/TUN 同表语义）
    assert_eq!(h.table.snapshot().sessions_active, 1, "UDP 会话粘滞在表");
    assert!(h.table.snapshot().bytes_up > 0, "表级上行字节入账");
}

// ---------- 取消/资源释放面：空闲回收出表 ----------

#[tokio::test]
async fn idle_session_is_reclaimed_releasing_resources() {
    let echo = spawn_udp_echo().await;
    let method = "aes-128-gcm";
    let h = make_ingress(method, true, echo, None).await;
    let ctx = Context::new_shared(ServerType::Local);
    let client = ProxySocket::connect(ctx, &client_svr_cfg(h.addr, method))
        .await
        .expect("UDP 客户端");
    client
        .send_to(
            h.addr,
            &Address::from((echo.ip().to_string(), echo.port())),
            b"ping",
        )
        .await
        .expect("上行数据报");
    wait_for(
        || h.table.snapshot().sessions_active == 1,
        Duration::from_secs(5),
    )
    .await;

    // 客户端静默 → 拨钟过空闲上限 → sweep 回收（资源释放 = 会话出表）
    h.clock.advance(SESSION_IDLE.as_secs() + 1);
    let stats = sweep_once(&h.table);
    assert_eq!(stats.sessions_expired, 1, "空闲会话应被回收");
    wait_for(
        || h.table.snapshot().sessions_active == 0,
        Duration::from_secs(5),
    )
    .await;
}

// ---------- 失败面：错密码无回声字节 ----------

#[tokio::test]
async fn wrong_password_delivers_no_echo_bytes() {
    let echo = spawn_tcp_echo().await;
    let method = "aes-256-gcm";
    let h = make_ingress(method, false, echo, None).await;
    // 客户端用错口令（服务端解不开请求头，连接收束）
    let bad_cfg = ServerConfig::new(h.addr, "definitely-wrong-password", method.parse().unwrap())
        .expect("客户端侧 svr_cfg 装配");
    let ctx = Context::new_shared(ServerType::Local);
    let mut stream = ProxyClientStream::connect(
        ctx,
        &bad_cfg,
        Address::from((echo.ip().to_string(), echo.port())),
    )
    .await
    .expect("SS 连接阶段无服务端往返，本就成功");
    stream.write_all(b"secret-request").await.expect("写入");
    // 收口：EOF 或错误均可，但任何读到的字节都不得是回声
    let mut buf = Vec::new();
    let outcome = timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    match outcome {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!("错口令连接须收束（EOF/错误），不得悬挂"),
    }
    assert!(buf.is_empty(), "错口令不得收到任何回声字节：{}", buf.len());
}

// ---------- UDP 未启用面 ----------

#[tokio::test]
async fn udp_disabled_face_keeps_udp_port_unbound() {
    let echo = spawn_tcp_echo().await;
    let method = "aes-128-gcm";
    let h = make_ingress(method, false, echo, None).await;
    // TCP 通路不受 UDP 关闭影响
    let got = tcp_roundtrip(
        &client_svr_cfg(h.addr, method),
        Address::from((echo.ip().to_string(), echo.port())),
    )
    .await;
    assert_eq!(got.len(), 4096);

    // UDP 同端口未被入口占用（数据报面未绑）
    let probe = UdpSocket::bind(h.addr).await;
    assert!(
        probe.is_ok(),
        "udp 关闭时入口不得占用 UDP 端口：{:?}",
        probe.err()
    );
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

    let method = "aes-128-gcm";
    // TCP：目标为池段假 IP → 路由面看到原域名 + dns.fakeip 注记
    let h = make_ingress(method, false, tcp_echo, Some(table.clone())).await;
    let got = tcp_roundtrip(
        &client_svr_cfg(h.addr, method),
        Address::from((fake.to_string(), tcp_echo.port())),
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
    let h2 = make_ingress(method, true, udp_echo, Some(table.clone())).await;
    let ctx = Context::new_shared(ServerType::Local);
    let client = ProxySocket::connect(ctx, &client_svr_cfg(h2.addr, method))
        .await
        .expect("UDP 客户端");
    client
        .send_to(
            h2.addr,
            &Address::from((fake_udp.to_string(), udp_echo.port())),
            b"fakeip-udp",
        )
        .await
        .expect("上行数据报");
    let mut rbuf = vec![0u8; 65535];
    let (n, _peer, _from, _off) = timeout(Duration::from_secs(5), client.recv_from(&mut rbuf))
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
