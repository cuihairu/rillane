//! P0-2 SOCKS5 UDP ASSOCIATE 测试（udp-relay-path.md §2.7 验收映射）。
//! 覆盖：头解析/编码往返、FRAG≠0 与截断准入、strict 源校验（纯函数级）、
//! 真 socket 的 DNS 式往返（direct 出站）、控制连接 EOF → force_revoke、
//! 并发 ASSOCIATE 拒绝、BND.PORT 真实性。

use rillane_core::udp::{
    encode_udp_header, parse_udp_header, Clock, DirectUdpConnector, MockClock, UdpAssociateService,
    UdpHeaderError, UdpIngressMetrics, UdpSessionConfig, UdpSessionKey, UdpSessionTable,
};
use rillane_core::{
    FlowContext, FlowRouter, FlowTarget, RouteDecision, RoutePath, RouteType, TargetProto,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

const NODE_A: &str = "node-a";

struct FixedRouter;
#[async_trait::async_trait]
impl FlowRouter for FixedRouter {
    async fn route(&self, _ctx: FlowContext) -> anyhow::Result<RouteDecision> {
        Ok(RouteDecision {
            path: RoutePath::Direct {
                node: NODE_A.into(),
            },
            reason: None,
            route_type: RouteType::Standard,
        })
    }
}

fn make_service(strict: bool) -> Arc<UdpAssociateService> {
    make_service_with_limits(strict, 256)
}

/// 可调并发上限建服务（P0-5 §1.2 max_associates 测试面）
fn make_service_with_limits(strict: bool, max_associates: usize) -> Arc<UdpAssociateService> {
    let config = UdpSessionConfig::default();
    let table = UdpSessionTable::new(
        config,
        Arc::new(FixedRouter) as Arc<dyn FlowRouter>,
        MockClock::new() as Arc<dyn Clock>,
    )
    .unwrap();
    UdpAssociateService::new(
        table,
        Arc::new(DirectUdpConnector),
        strict,
        max_associates,
        None,
    )
}

/// 回声 UDP 服务器（模拟 DNS：收什么回什么，同源回送）
async fn spawn_echo_server() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        }
    });
    addr
}

/// 建立控制连接对并跑 serve；返回 (客户端流, 中继端口, serve 句柄)
async fn associate(
    svc: &Arc<UdpAssociateService>,
) -> (TcpStream, u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(listen_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let svc = svc.clone();
    let handle = tokio::spawn(async move {
        let mut server = server;
        let _ = svc.serve(&mut server, None).await;
    });
    // 客户端发 ASSOCIATE 请求帧（DST 无意义，全零 IPv4）
    let mut client = client;
    client
        .write_all(&[0x05, 0x03, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "ASSOCIATE 应成功");
    assert_eq!(reply[3], 0x01);
    let bnd_port = u16::from_be_bytes([reply[8], reply[9]]);
    (client, bnd_port, handle)
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "wait_until 超时");
        sleep(Duration::from_millis(10)).await;
    }
}

// ---------- 头编解码 ----------

#[test]
fn header_parse_ipv4() {
    // RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) | payload
    let frame = [0, 0, 0, 1, 8, 8, 8, 8, 0x00, 0x35, b'q'];
    let (target, hlen) = parse_udp_header(&frame).unwrap();
    assert_eq!(target.host, "8.8.8.8");
    assert_eq!(target.port, 53);
    assert_eq!(target.proto, TargetProto::Udp);
    assert_eq!(hlen, 10);
}

#[test]
fn header_parse_domain() {
    let mut frame = vec![0, 0, 0, 3, 11];
    frame.extend_from_slice(b"example.com");
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.push(b'x');
    let (target, hlen) = parse_udp_header(&frame).unwrap();
    assert_eq!(target.host, "example.com");
    assert_eq!(target.port, 443);
    assert_eq!(hlen, 5 + 11 + 2);
}

#[test]
fn header_parse_ipv6() {
    let mut frame = vec![0, 0, 0, 4];
    frame.extend_from_slice(&[0x26; 16]);
    frame.extend_from_slice(&53u16.to_be_bytes());
    let (target, hlen) = parse_udp_header(&frame).unwrap();
    assert_eq!(target.host, "2626:2626:2626:2626:2626:2626:2626:2626");
    assert_eq!(target.port, 53);
    assert_eq!(hlen, 22);
}

#[test]
fn header_parse_rejects_short_and_bad_atyp() {
    assert_eq!(
        parse_udp_header(&[0, 0, 0]).unwrap_err(),
        UdpHeaderError::TooShort
    );
    // IPv4 截断（不足 10 字节）
    assert_eq!(
        parse_udp_header(&[0, 0, 0, 1, 8, 8]).unwrap_err(),
        UdpHeaderError::TooShort
    );
    // 域名长度截断
    assert_eq!(
        parse_udp_header(&[0, 0, 0, 3, 20, b'a']).unwrap_err(),
        UdpHeaderError::TooShort
    );
    assert_eq!(
        parse_udp_header(&[0, 0, 0, 9]).unwrap_err(),
        UdpHeaderError::BadAtyp(9)
    );
}

#[test]
fn header_encode_parse_roundtrip_all_atyps() {
    let cases = [
        FlowTarget {
            host: "1.2.3.4".into(),
            port: 53,
            proto: TargetProto::Udp,
        },
        FlowTarget {
            host: "example.com".into(),
            port: 8899,
            proto: TargetProto::Udp,
        },
        FlowTarget {
            host: "::1".into(),
            port: 443,
            proto: TargetProto::Udp,
        },
    ];
    for t in cases {
        let mut frame = encode_udp_header(&t, 2).unwrap();
        frame.extend_from_slice(b"ab");
        let (parsed, hlen) = parse_udp_header(&frame).unwrap();
        assert_eq!(parsed.host, t.host, "host 往返");
        assert_eq!(parsed.port, t.port);
        assert_eq!(&frame[hlen..], b"ab", "载荷完好");
    }
}

// ---------- 端到端：ASSOCIATE + direct 出站 UDP 往返 ----------

#[tokio::test]
async fn dns_style_roundtrip_via_associate_and_direct() {
    // P0-2 验收主路径：客户端 → ASSOCIATE 中继 → direct 出站 → 目标（回声）
    // → 下行封帧回客户端
    let svc = make_service(true);
    let target_addr = spawn_echo_server().await;

    let (mut control, relay_port, serve_handle) = associate(&svc).await;
    assert_ne!(relay_port, 0, "BND.PORT 必须真实（§2.2）");

    // 客户端 UDP socket（数据报源 = 粘滞键 client）
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = {
        let mut f = vec![0, 0, 0, 1]; // RSV(2) FRAG ATYP=IPv4
        match target_addr.ip() {
            std::net::IpAddr::V4(v4) => f.extend_from_slice(&v4.octets()),
            std::net::IpAddr::V6(v6) => {
                f[3] = 4;
                f.extend_from_slice(&v6.octets());
            }
        }
        f.extend_from_slice(&target_addr.port().to_be_bytes());
        f.extend_from_slice(b"query-payload");
        f
    };
    client_udp
        .send_to(&query, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();

    // 下行：SOCKS5 帧封装的回声应答
    let mut rxbuf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(2), client_udp.recv_from(&mut rxbuf))
        .await
        .expect("应在超时内收到下行应答")
        .unwrap();
    let (parsed, hlen) = parse_udp_header(&rxbuf[..n]).unwrap();
    assert_eq!(parsed.host, target_addr.ip().to_string());
    assert_eq!(parsed.port, target_addr.port());
    assert_eq!(&rxbuf[hlen..n], b"query-payload");

    let m = svc.metrics();
    assert_eq!(UdpIngressMetrics::get(&m.uplink_packets), 1);
    assert_eq!(UdpIngressMetrics::get(&m.downlink_packets), 1);

    // 会话可见（P0-5 的 rillanectl stats 数据源）
    let snap = svc.table().snapshot();
    assert_eq!(snap.sessions_active, 1);
    assert_eq!(snap.mappings_active, 1);

    // 控制连接 EOF → force_revoke（§2.5）
    control.shutdown().await.unwrap();
    let _ = serve_handle.await;
    wait_until(|| svc.table().snapshot().sessions_active == 0).await;
    wait_until(|| UdpIngressMetrics::get_gauge(&m.associates_active) == 0).await;
}

#[tokio::test]
async fn frag_and_malformed_are_dropped_and_counted() {
    let svc = make_service(false);
    let (_control, relay_port, _handle) = associate(&svc).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // FRAG=1 → 丢弃 + 计数（§2.3 步骤 2）
    let mut frag_frame = vec![0, 0, 1, 1, 8, 8, 8, 8, 0, 53];
    frag_frame.extend_from_slice(b"q");
    sock.send_to(&frag_frame, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();

    // 截断头 → 丢弃 + 计数
    sock.send_to(&[0, 0, 0, 1, 8, 8], format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();

    wait_until(|| {
        let m = svc.metrics();
        UdpIngressMetrics::get(&m.frag_dropped) == 1
            && UdpIngressMetrics::get(&m.malformed_dropped) == 1
    })
    .await;
    // 均未建会话
    assert_eq!(svc.table().snapshot().sessions_active, 0);
    assert_eq!(UdpIngressMetrics::get(&svc.metrics().uplink_packets), 2);
}

#[tokio::test]
async fn strict_source_rejects_foreign_source_ip() {
    // §2.3 步骤 3：数据报源 IP ≠ 控制连接对端 IP → 丢弃（127.0.0.2 伪装源）
    let svc = make_service(true);
    let target_addr = spawn_echo_server().await;
    let (_control, relay_port, _handle) = associate(&svc).await;

    // 伪装源：绑定 127.0.0.2（lo 全段可用；若环境不支持则跳过断言）
    let foreign = match UdpSocket::bind("127.0.0.2:0").await {
        Ok(s) => s,
        Err(_) => return, // 环境限制：纯函数级 strict 校验由 P0-1 测试面覆盖
    };
    let mut frame = vec![0, 0, 0, 1];
    match target_addr.ip() {
        std::net::IpAddr::V4(v4) => frame.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => {
            frame[3] = 4;
            frame.extend_from_slice(&v6.octets());
        }
    }
    frame.extend_from_slice(&target_addr.port().to_be_bytes());
    frame.extend_from_slice(b"spoofed");
    foreign
        .send_to(&frame, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();

    wait_until(|| UdpIngressMetrics::get(&svc.metrics().source_dropped) == 1).await;
    assert_eq!(svc.table().snapshot().sessions_active, 0);
}

#[tokio::test]
async fn concurrent_associate_from_same_client_rejected() {
    // §2.6：同键（同控制连接对端 (ip,port)）第二个 ASSOCIATE → 0x01 拒绝 + 计数
    let svc = make_service(false);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    // 预绑定源端口：local_addr 即 connect 后的对端地址，可先占并发门
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap();
    let peer = sock.local_addr().unwrap();
    assert!(svc.try_register_associate(&peer), "首占成功");
    assert!(
        !svc.try_register_associate(&peer),
        "同键二占失败（gate 语义）"
    );

    let client = sock.connect(listen_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let server = server;
    let svc2 = Arc::clone(&svc);
    let h = tokio::spawn(async move {
        let mut s = server;
        let _ = svc2.serve(&mut s, None).await;
    });
    let mut c = client;
    c.write_all(&[0x05, 0x03, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(2), c.read_exact(&mut reply))
        .await
        .expect("应答超时")
        .unwrap();
    assert_eq!(reply[1], 0x01, "并发 ASSOCIATE 应答 0x01 general failure");
    let _ = h.await;
    assert_eq!(UdpIngressMetrics::get(&svc.metrics().associate_rejected), 1);
    assert_eq!(
        UdpIngressMetrics::get_gauge(&svc.metrics().associates_active),
        0
    );
    svc.table().shutdown();
}

#[tokio::test]
async fn associate_survives_session_idle_but_revoke_on_eof() {
    // §2.5 反向：会话空闲回收不关控制连接（MVP 接受 O8 空挂语义）
    let svc = make_service(false);
    let _target_addr = spawn_echo_server().await;
    let (control, relay_port, serve_handle) = associate(&svc).await;

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 发一包建会话（目标指向本地回声，会话建立即满足）
    let mut frame = vec![0, 0, 0, 1, 127, 0, 0, 1];
    frame.extend_from_slice(&relay_port.to_be_bytes());
    // 注意：中继端口自身无回声服务，会建会话+映射但下行无回包——本测试只看生命周期
    client_udp
        .send_to(&frame, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();
    wait_until(|| svc.table().snapshot().sessions_active == 1).await;

    // 会话被 force_revoke 之外的方式（此处手动吊销模拟空闲回收）后，
    // 控制连接仍存活（serve 不返回）
    let key = UdpSessionKey::new(client_udp.local_addr().unwrap());
    assert!(svc.table().force_revoke(&key));
    wait_until(|| svc.table().snapshot().sessions_active == 0).await;
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        UdpIngressMetrics::get_gauge(&svc.metrics().associates_active),
        1,
        "控制连接未受会话回收影响"
    );

    // EOF 后整个关联收尾
    drop(control);
    let _ = serve_handle.await;
    wait_until(|| UdpIngressMetrics::get_gauge(&svc.metrics().associates_active) == 0).await;
}

#[tokio::test]
async fn mapping_layer_metrics_flow_through_associate() {
    // 上行/下行计数与会话表指标联动（P0-5 的数据面基础）
    let svc = make_service(false);
    let target_addr = spawn_echo_server().await;
    let (_control, relay_port, _handle) = associate(&svc).await;
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut frame = vec![0, 0, 0, 1];
    match target_addr.ip() {
        std::net::IpAddr::V4(v4) => frame.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => {
            frame[3] = 4;
            frame.extend_from_slice(&v6.octets());
        }
    }
    frame.extend_from_slice(&target_addr.port().to_be_bytes());
    for i in 0..5u8 {
        let mut f = frame.clone();
        f.push(i);
        client_udp
            .send_to(&f, format!("127.0.0.1:{relay_port}"))
            .await
            .unwrap();
    }
    wait_until(|| UdpIngressMetrics::get(&svc.metrics().downlink_packets) == 5).await;
    let snap = svc.table().snapshot();
    assert_eq!(snap.sessions[0].packets_count, 10); // 5 up + 5 down
    assert_eq!(snap.sessions[0].bytes_uploaded, 5); // 每包载荷 1 字节
}

// ---------- P0-5 S1：max_associates 总量门 + 入站快照 ----------

#[tokio::test]
async fn max_associates_cap_rejects_and_counts() {
    // §1.2：max=2 时两个不同 peer 注册成功、第 3 个拒（serve 路径 0x01 +
    // associate_rejected 计数）；同 peer 重复注册维持既有拒绝语义
    let svc = make_service_with_limits(false, 2);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    // 预占两个槽位（门只看 (ip,port) 集合，无需真实连接）
    assert!(svc.try_register_associate(&"127.0.0.1:50001".parse::<SocketAddr>().unwrap()));
    assert!(svc.try_register_associate(&"127.0.0.1:50002".parse::<SocketAddr>().unwrap()));
    // 总量满：第 3 个不同 peer 也拒
    assert!(!svc.try_register_associate(&"127.0.0.1:50003".parse::<SocketAddr>().unwrap()));
    // 同 peer 重复注册语义不变（insert 返回 false）
    assert!(!svc.try_register_associate(&"127.0.0.1:50001".parse::<SocketAddr>().unwrap()));

    // 真实 serve 路径：第 3 条控制连接 → 0x01 + 计数
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap();
    let client = sock.connect(listen_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let svc2 = Arc::clone(&svc);
    let h = tokio::spawn(async move {
        let mut s = server;
        let _ = svc2.serve(&mut s, None).await;
    });
    let mut c = client;
    c.write_all(&[0x05, 0x03, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(2), c.read_exact(&mut reply))
        .await
        .expect("应答超时")
        .unwrap();
    assert_eq!(reply[1], 0x01, "总量超限应答 0x01 general failure");
    let _ = h.await;
    assert_eq!(UdpIngressMetrics::get(&svc.metrics().associate_rejected), 1);
    assert_eq!(
        UdpIngressMetrics::get_gauge(&svc.metrics().associates_active),
        0
    );
    svc.table().shutdown();
}

#[tokio::test]
async fn ingress_snapshot_fields_complete() {
    // §10-S1 测试 3：驱动各类事件后九字段逐一断言（含 0 值字段存在，§6-2 口径）
    let svc = make_service(true);
    let target_addr = spawn_echo_server().await;
    let (mut control, relay_port, serve_handle) = associate(&svc).await;

    // 一次往返 + FRAG≠0 + 截断头
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut query = vec![0, 0, 0, 1, 127, 0, 0, 1];
    query.extend_from_slice(&target_addr.port().to_be_bytes());
    query.extend_from_slice(b"q");
    client_udp
        .send_to(&query, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();
    let mut rxbuf = [0u8; 2048];
    let _ = timeout(Duration::from_secs(2), client_udp.recv_from(&mut rxbuf))
        .await
        .unwrap();
    let frag = vec![0, 0, 1, 1, 8, 8, 8, 8, 0, 53, b'f'];
    client_udp
        .send_to(&frag, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();
    client_udp
        .send_to(&[0, 0, 0, 1, 8, 8], format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();

    wait_until(|| {
        let s = svc.ingress_snapshot();
        s.uplink_packets == 3
            && s.downlink_packets == 1
            && s.frag_dropped == 1
            && s.malformed_dropped == 1
    })
    .await;
    let snap = svc.ingress_snapshot();
    assert_eq!(snap.associates_active, 1);
    assert_eq!(snap.associates_total, 1);
    assert_eq!(snap.associate_rejected, 0, "零值字段恒在（§6-2）");
    assert_eq!(snap.associate_errors, 0);
    assert_eq!(snap.source_dropped, 0);

    // EOF 后 active 归零
    control.shutdown().await.unwrap();
    let _ = serve_handle.await;
    wait_until(|| svc.ingress_snapshot().associates_active == 0).await;
}

// ---------- G1-10 M2 残项②：socks5 UDP 数据报 fake-ip 回填 ----------

/// 捕获路由 target 的路由器（回填断言面：域名应抵达路由上下文）
struct CapturingRouter {
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl FlowRouter for CapturingRouter {
    async fn route(&self, ctx: FlowContext) -> anyhow::Result<RouteDecision> {
        self.seen.lock().unwrap().push(ctx.target.host.clone());
        Ok(RouteDecision {
            path: RoutePath::Direct {
                node: NODE_A.into(),
            },
            reason: None,
            route_type: RouteType::Standard,
        })
    }
}

#[tokio::test]
async fn fake_ip_datagram_target_backfills_domain() {
    // G1-10 UDP 面：池段假 IPv4 target 反查原域名（与 TCP 入口同款语义，
    // 路由按域名规则命中）；池外 IP target 原样直达路由
    let pool = Arc::new(rillane_core::fake_ip::FakeIpTable::from_cidr("198.18.0.0/15").unwrap());
    let fake = pool.alloc("udp.example");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let table = UdpSessionTable::new(
        UdpSessionConfig::default(),
        Arc::new(CapturingRouter {
            seen: Arc::clone(&seen),
        }) as Arc<dyn FlowRouter>,
        MockClock::new() as Arc<dyn Clock>,
    )
    .unwrap();
    let svc = UdpAssociateService::new(table, Arc::new(DirectUdpConnector), false, 256, Some(pool));
    let (_control, relay_port, _handle) = associate(&svc).await;

    let frame_for = |ip: std::net::Ipv4Addr, port: u16| {
        let mut f = vec![0, 0, 0, 1]; // RSV(2) FRAG ATYP=IPv4
        f.extend_from_slice(&ip.octets());
        f.extend_from_slice(&port.to_be_bytes());
        f
    };

    // 池外 IP：不回填，target 原样（UDP connect 本地即成，无网络依赖）
    let pass = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    pass.send_to(
        &frame_for(std::net::Ipv4Addr::new(8, 8, 8, 8), 53),
        format!("127.0.0.1:{relay_port}"),
    )
    .await
    .unwrap();
    wait_until(|| seen.lock().unwrap().iter().any(|h| h == "8.8.8.8")).await;

    // 池段假地址：反查回原域名，路由上下文见到的是域名而非假地址
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.send_to(&frame_for(fake, 443), format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();
    wait_until(|| seen.lock().unwrap().iter().any(|h| h == "udp.example")).await;
    assert!(
        !seen.lock().unwrap().iter().any(|h| *h == fake.to_string()),
        "池段假地址不得直达路由（必须反查回域名）"
    );
}

// ---------- RIL-083 第四段：关联面轨迹接线（活面取证） ----------

use rillane_core::collector::{CollectorConfig, FlowCollector};
use rillane_core::trace::{FlowOrigin, FlowTrace};
use rillane_core::udp::sweep_once;
use rillane_core::udp::MockUdpRelay;

/// 真实 ASSOCIATE 往返 → 控制链 EOF 吊销：轨迹四落点逐一核对
///（takeover → plan → association.mapped → association.reclaimed）。
#[tokio::test]
async fn trace_wiring_records_association_lifecycle() {
    let svc = make_service(false);
    let collector = Arc::new(Mutex::new(FlowCollector::new(
        CollectorConfig::new(64, 16, 64, 3_600_000, 1, true).unwrap(),
    )));
    svc.table()
        .attach_trace_wiring(Arc::clone(&collector), "local");
    let echo = spawn_echo_server().await;
    let (control, relay_port, handle) = associate(&svc).await;
    let target = FlowTarget {
        host: "127.0.0.1".into(),
        port: echo.port(),
        proto: TargetProto::Udp,
    };
    let frame = encode_udp_header(&target, 5).unwrap();
    let mut pkt = frame;
    pkt.extend_from_slice(b"hello");
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&pkt, format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("回声超时")
        .unwrap();
    assert_eq!(&buf[n - 5..n], b"hello", "回声载荷逐字节还原");
    // 控制链 EOF → force_revoke → reclaimed 终态
    drop(control);
    let _ = handle.await;

    let guard = collector.lock().unwrap();
    let assoc: &FlowTrace = guard
        .iter_traces()
        .find(|t| t.origin == FlowOrigin::Association)
        .expect("关联轨迹应入采集器（采样=全采）");
    assert!(assoc.closed, "吊销后轨迹应到终态");
    assert_eq!(assoc.generation, "local", "接线装配的代际");
    assert_eq!(assoc.events[0].code, "session.takeover", "首事件为接管");
    assert_eq!(
        assoc.events.last().unwrap().code,
        "association.reclaimed",
        "控制链收口吊销 = reclaimed 终态"
    );
    assert!(
        assoc.events.iter().any(|e| e.code == "association.mapped"),
        "映射建成应有观测事件"
    );
    assert!(
        assoc.events.iter().any(|e| e.code == "route.plan"),
        "决策应产 plan 事件（FixedRouter 无 reason → 无 rule 事件，不造数）"
    );
    assert!(
        !assoc.events.iter().any(|e| e.code.starts_with("transfer.")),
        "生产泵未逐次测量首字节——transfer 事件不得凭空出现"
    );
    assoc.validate().expect("轨迹自校验（序号连续/时间单调）");
    assert!(guard.stats().traces_admitted >= 1, "采集器准入计数");
}

/// 空闲回收路径：MockClock 拨过空闲上限 → sweep → association.closed
/// 终态（与 reclaimed 分立的正常收口码）。
#[tokio::test]
async fn trace_wiring_records_idle_expiry_close() {
    use rillane_core::udp::Clock;
    let config = UdpSessionConfig::default();
    let clock = rillane_core::udp::MockClock::new();
    let table = rillane_core::udp::UdpSessionTable::new(
        config,
        Arc::new(FixedRouter) as Arc<dyn FlowRouter>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .unwrap();
    let svc = UdpAssociateService::new(table, Arc::new(DirectUdpConnector), false, 256, None);
    let collector = Arc::new(Mutex::new(FlowCollector::new(
        CollectorConfig::new(64, 16, 64, 3_600_000, 1, true).unwrap(),
    )));
    svc.table()
        .attach_trace_wiring(Arc::clone(&collector), "local");
    let key = UdpSessionKey::new("127.0.0.1:41000".parse::<SocketAddr>().unwrap());
    let target = FlowTarget {
        host: "127.0.0.1".into(),
        port: 53,
        proto: TargetProto::Udp,
    };
    let sref = svc.table().resolve(&key, &target).await.unwrap();
    let (relay, _tx) = MockUdpRelay::new(target.clone());
    assert_eq!(
        sref.bind_mapping(&target, relay).await.unwrap(),
        rillane_core::udp::table::BindOutcome::Created,
        "首绑应创建映射"
    );

    clock.advance(181);
    let st = sweep_once(svc.table());
    assert_eq!(st.sessions_expired, 1, "拨过空闲上限应回收整会话");

    let guard = collector.lock().unwrap();
    let assoc: &FlowTrace = guard
        .iter_traces()
        .find(|t| t.origin == FlowOrigin::Association)
        .expect("空闲回收会话应有轨迹");
    assert!(assoc.closed, "回收后轨迹应到终态");
    assert_eq!(
        assoc.events.last().unwrap().code,
        "association.closed",
        "空闲回收 = closed 终态（非 reclaimed）"
    );
    assert!(
        assoc.events.iter().any(|e| e.code == "association.mapped"),
        "绑定的映射建成事件在场"
    );
    assoc.validate().expect("轨迹自校验");
}
