//! VLESS UDP 包编码验收合约（RIL-130）：真实对端 = 明文 TCP 镜像服务面 +
//! sing-vmess v0.2.4 xudp / packetaddr 语义自装配（帧形状逐字节核对）。
//!
//! 覆盖验收面：xudp 首报 New/后续 Keep 逐字节往返、逐报源地址（全锥
//! 能力面）、元长==4 回落会话目标、End 帧会话收束、packetaddr magic 地址
//! 载具头 + family-first 逐报寻址（含 v6 下行、域名目标具名拒绝）、
//! 越界数据报具名拒绝、取消与资源释放。
//!
//! 统计与平台旁路：UDP 面统计由 runtime UDP forwarder 计数面承载（协议
//! 无关，不在本合约重复）；拨号走 net_mark::connect_tcp 同一 TCP 面
//! （networking.md §2，与普通 VLESS 无差异）。

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rillane_core::udp::EgressUdpConnector;
use rillane_core::{
    FlowContext, FlowId, FlowTarget, RouteDecision, RoutePath, RouteType, TargetProto,
};
use rillane_protocols::{TlsFingerprint, VlessConnector, VlessUdpConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";

fn uuid_bytes() -> [u8; 16] {
    // b831381d-6324-4d2a-b1e7-1bf75a1db7b3 的 16B 二进制形
    [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x2a, 0xb1, 0xe7, 0x1b, 0xf7, 0x5a, 0x1d, 0xb7,
        0xb3,
    ]
}

fn target(host: &str, port: u16) -> FlowTarget {
    FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Udp,
    }
}

fn udp_connector(addr: SocketAddr, encoding: Option<&str>) -> VlessUdpConnector {
    let conn = VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        TEST_UUID.to_string(),
        None,
        None,
        "tcp".to_string(),
        None,
        None,
        None,
        None,
        encoding.map(str::to_string),
        false,
        false,
        None,
        None,
        TlsFingerprint::None,
        None,
        None,
    );
    VlessUdpConnector::from_connector(&conn)
}

fn udp_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: target(host, port),
        metadata: Default::default(),
    }
}

fn decision() -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: "packet-mirror-node".into(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

/// 明文 TCP 镜像对端：接受一连接、执行 serve，对端退出即计数（资源释放
/// 可见性）
async fn spawn_peer<F, Fut>(serve: F) -> SocketAddr
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (st, _) = listener.accept().await.expect("accept");
        tokio::spawn(async move {
            if let Err(e) = serve(st).await {
                eprintln!("镜像对端错误: {e:#}");
            }
        });
    });
    addr
}

/// 逐字节核对 vless Mux 载具头（xudp）：version+uuid+optlen0+命令 0x03，
/// **无端口/地址段**（mihomo transport/vless/conn.go Mux 分支）
async fn read_mux_header_expect_xudp(st: &mut TcpStream) {
    let mut head = [0u8; 19];
    st.read_exact(&mut head).await.expect("读 Mux 头");
    assert_eq!(head[0], 0x00, "版本位");
    assert_eq!(&head[1..17], &uuid_bytes(), "uuid 段");
    assert_eq!(head[17], 0x00, "optlen 位");
    assert_eq!(head[18], 0x03, "xudp 命令位（无地址段，头恰 19B）");
}

/// 逐字节核对 packetaddr 载具头：命令 0x02 + magic 地址
/// `sp.packet-addr.v2fly.arpa`:443
async fn read_header_expect_packetaddr(st: &mut TcpStream) {
    // version1+uuid16+optlen1+cmd1+port2+atype1+len1+域名25 = 48
    let mut head = [0u8; 48];
    st.read_exact(&mut head).await.expect("读 packetaddr 头");
    assert_eq!(head[0], 0x00, "版本位");
    assert_eq!(&head[1..17], &uuid_bytes(), "uuid 段");
    assert_eq!(head[17], 0x00, "optlen 位");
    assert_eq!(head[18], 0x02, "UDP 命令位");
    assert_eq!(&head[19..21], &[0x01, 0xBB], "magic 端口 443");
    assert_eq!(head[21], 0x02, "域名 atype");
    assert_eq!(head[22], 25, "magic 域名长");
    assert_eq!(
        &head[23..48],
        b"sp.packet-addr.v2fly.arpa",
        "packetaddr magic 地址（SeqPacketMagicAddress）"
    );
}

#[tokio::test]
async fn xudp_roundtrip_byte_exact_with_per_packet_source_addr() {
    let ended = Arc::new(AtomicUsize::new(0));
    let ended2 = ended.clone();
    let addr = spawn_peer(move |mut st| async move {
        // 载具头逐字节核对后回响应头（2B）
        read_mux_header_expect_xudp(&mut st).await;
        st.write_all(&[0x00, 0x00]).await.expect("写响应头");

        // 客户端首报 New 帧：目标 10.1.2.3:53（port-first 地址 7B，
        // 元长 = 5+7 = 12），载荷 b"xudp-ping"
        let mut new_frame = [0u8; 2 + 12 + 2 + 9];
        st.read_exact(&mut new_frame).await.expect("读 New 帧");
        let mut want = Vec::new();
        want.extend_from_slice(&12u16.to_be_bytes());
        want.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x02]);
        want.extend_from_slice(&[0x00, 0x35, 0x01, 10, 1, 2, 3]); // :53 v4
        want.extend_from_slice(&9u16.to_be_bytes());
        want.extend_from_slice(b"xudp-ping");
        assert_eq!(
            new_frame.as_slice(),
            want,
            "New 帧逐字节（sing-vmess xudp.go）"
        );

        // 下行：Keep 帧携**另一源地址** 10.9.9.9:9999（逐报寻址 = 全锥）
        let mut reply = Vec::new();
        reply.extend_from_slice(&12u16.to_be_bytes());
        reply.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x02]);
        reply.extend_from_slice(&[0x27, 0x0F, 0x01, 10, 9, 9, 9]); // :9999
        reply.extend_from_slice(&9u16.to_be_bytes());
        reply.extend_from_slice(b"xudp-pong");
        st.write_all(&reply).await.expect("写下行 Keep");

        // 客户端次报 Keep 帧：目标 10.1.2.4:54、载荷 b"second"
        let mut keep = [0u8; 2 + 12 + 2 + 6];
        st.read_exact(&mut keep).await.expect("读 Keep 帧");
        let mut want_keep = Vec::new();
        want_keep.extend_from_slice(&12u16.to_be_bytes());
        want_keep.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x02]);
        want_keep.extend_from_slice(&[0x00, 0x36, 0x01, 10, 1, 2, 4]); // :54
        want_keep.extend_from_slice(&6u16.to_be_bytes());
        want_keep.extend_from_slice(b"second");
        assert_eq!(keep.as_slice(), want_keep, "Keep 帧逐字节");

        // 下行：元长==4 帧（无寻址段）——客户端应回落会话目标 10.0.0.1:53
        let mut bare = Vec::new();
        bare.extend_from_slice(&4u16.to_be_bytes());
        bare.extend_from_slice(&[0x00, 0x00, 0x02, 0x01]);
        bare.extend_from_slice(&7u16.to_be_bytes());
        bare.extend_from_slice(b"bare-ok");
        st.write_all(&bare).await.expect("写无寻址 Keep");

        // 下行：End 帧（状态 3）——客户端会话收束
        st.write_all(&[0x00, 0x04, 0x00, 0x00, 0x03, 0x00])
            .await
            .expect("写 End 帧");
        ended2.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;

    let conn = udp_connector(addr, Some("xudp"));
    let relay = conn
        .associate(udp_ctx("10.0.0.1", 53), &decision())
        .await
        .expect("xudp 关联");

    // 首报（New 帧）→ 下行源地址 = 帧内逐报地址
    relay
        .send_to(&target("10.1.2.3", 53), b"xudp-ping")
        .await
        .expect("首报发送");
    let mut buf = [0u8; 64];
    let (src, n) = relay.recv_from(&mut buf).await.expect("首下行");
    assert_eq!(
        (src.host.as_str(), src.port),
        ("10.9.9.9", 9999),
        "逐报源地址"
    );
    assert_eq!(&buf[..n], b"xudp-pong");

    // 次报（Keep 帧，另一目标）
    relay
        .send_to(&target("10.1.2.4", 54), b"second")
        .await
        .expect("次报发送");
    let (src, n) = relay.recv_from(&mut buf).await.expect("次下行");
    // 元长==4：目标回落会话目标（ctx.target）
    assert_eq!(
        (src.host.as_str(), src.port),
        ("10.0.0.1", 53),
        "无寻址帧回落会话目标"
    );
    assert_eq!(&buf[..n], b"bare-ok");

    // End 帧 → 会话收束（EOF 语义）
    let err = relay
        .recv_from(&mut buf)
        .await
        .expect_err("End 帧必收束会话");
    assert!(format!("{err:#}").contains("会话收束"), "{err:#}");

    // 越界数据报具名拒绝（>65535）
    let big = vec![0u8; u16::MAX as usize + 1];
    let err = relay
        .send_to(&target("10.1.2.3", 53), &big)
        .await
        .expect_err("越界数据报必须拒绝");
    assert!(format!("{err:#}").contains("过大"), "{err:#}");

    // 资源释放：丢 relay 后对端服务面退出计数
    drop(relay);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "对端 2s 内应完成服务（End 帧后对端写毕即退）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn packetaddr_roundtrip_family_first_with_v6_source() {
    let ended = Arc::new(AtomicUsize::new(0));
    let ended2 = ended.clone();
    let addr = spawn_peer(move |mut st| async move {
        read_header_expect_packetaddr(&mut st).await;
        st.write_all(&[0x00, 0x00]).await.expect("写响应头");

        // 客户端上行：[2B len][0x01 v4][10.1.2.3][:53][载荷]
        let mut up = [0u8; 2 + 7 + 7];
        st.read_exact(&mut up).await.expect("读上行");
        let mut want = Vec::new();
        want.extend_from_slice(&14u16.to_be_bytes());
        want.extend_from_slice(&[0x01, 10, 1, 2, 3, 0x00, 0x35]);
        want.extend_from_slice(b"pa-ping");
        assert_eq!(up.as_slice(), want, "上行 family-first 逐字节");

        // 下行：v6 源地址 2001:db8::5:443（family-first，[0x02][16B][:443]）
        let mut down = Vec::new();
        down.extend_from_slice(&29u16.to_be_bytes());
        down.push(0x02);
        let mut v6 = [0u8; 16];
        v6[..2].copy_from_slice(&0x2001u16.to_be_bytes());
        v6[2..4].copy_from_slice(&0x0db8u16.to_be_bytes());
        v6[15] = 5;
        down.extend_from_slice(&v6);
        down.extend_from_slice(&443u16.to_be_bytes());
        down.extend_from_slice(b"pa-pong-v6");
        st.write_all(&down).await.expect("写下行");
        ended2.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;

    let conn = udp_connector(addr, Some("packetaddr"));
    let relay = conn
        .associate(udp_ctx("10.0.0.1", 53), &decision())
        .await
        .expect("packetaddr 关联");

    relay
        .send_to(&target("10.1.2.3", 53), b"pa-ping")
        .await
        .expect("上行发送");
    let mut buf = [0u8; 64];
    let (src, n) = relay.recv_from(&mut buf).await.expect("下行");
    assert_eq!(
        (src.host.as_str(), src.port),
        ("2001:db8::5", 443),
        "v6 源地址"
    );
    assert_eq!(&buf[..n], b"pa-pong-v6");

    // 域名目标具名拒绝（ErrFqdnUnsupported 同口径——packetaddr 无域名面）
    let err = relay
        .send_to(&target("dns.example", 53), b"no-domain")
        .await
        .expect_err("域名目标必须拒绝");
    let msg = format!("{err:#}");
    assert!(msg.contains("packetaddr"), "{msg}");
    assert!(msg.contains("域名"), "{msg}");

    // 资源释放：丢 relay → 对端读 EOF 退出计数
    drop(relay);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "对端 2s 内应见连接结束（资源释放）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn cancel_releases_xudp_session() {
    // 服务面挂读至 EOF：取消（丢 relay）后对端必然见到连接收束
    let ended = Arc::new(AtomicUsize::new(0));
    let ended2 = ended.clone();
    let addr = spawn_peer(move |mut st| async move {
        let mut head = [0u8; 19];
        if st.read_exact(&mut head).await.is_err() {
            return Ok(());
        }
        let _ = st.write_all(&[0x00, 0x00]).await;
        let mut sink = [0u8; 512];
        while st.read(&mut sink).await.unwrap_or(0) > 0 {}
        ended2.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;

    let conn = udp_connector(addr, Some("xudp"));
    let relay = conn
        .associate(udp_ctx("10.0.0.1", 53), &decision())
        .await
        .expect("关联");

    // 排一个 recv 挂读（无下行数据），随后取消
    let r = Arc::clone(&relay);
    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let _ = r.recv_from(&mut buf).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 取消：先弃挂读任务（释放其 Arc 引用），再丢 relay = 读写半整体丢弃
    recv_task.abort();
    let _ = recv_task.await;
    drop(relay);

    // 资源释放：对端 2s 内见 EOF
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "取消后对端 2s 内应见连接收束（资源释放）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
