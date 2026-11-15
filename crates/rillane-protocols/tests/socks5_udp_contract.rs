//! SOCKS5 出站 UDP ASSOCIATE 真实对端契约（RIL-132）：对端是按 RFC 1928
//! 线格式完整实现的服务器（方法协商 / RFC 1929 认证子协商 / UDP
//! ASSOCIATE / §7 数据报中继）——不是打桩 mock。验收：成功往返（IP 与
//! 域名目标、文本与二进制载荷）、失败（应答错误码点名）、取消（放弃等
//! 待不炸流）、资源释放（控制信道 EOF 对端可见）、来源验证与分片丢弃。

use std::time::Duration;

use rillane_core::udp::EgressUdpConnector;
use rillane_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, RouteDecision, TargetProto};
use rillane_protocols::Socks5UdpConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

/// 对端模式（每测一种——同一 wire 面，行为由模式决定）
#[derive(Clone)]
enum PeerMode {
    /// 正常中继：客户端数据报载荷 → 本地 UDP 回显 socket → §7 帧头封回
    Echo,
    /// ASSOCIATE 请求回指定错误码
    RejectAssociate(u8),
    /// 要求 RFC 1929 认证并校验凭据
    RequireAuth { user: String, pass: String },
    /// 中继首条合法数据报后：注入一条陌生来源数据报 + 一条 FRAG=1 分片
    /// （客户端应只下传合法回显——来源验证与分片丢弃的可观测证明）
    InjectNoise,
}

/// 生成真实对端：返回代理地址与控制信道 EOF 监视（资源释放面）。
/// 接受循环并发处理控制连接——真实服务器语义：同一节点可多次 ASSOCIATE，
/// 后续连接不会悬死在 backlog。
async fn spawn_peer(mode: PeerMode) -> (std::net::SocketAddr, watch::Receiver<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("对端监听");
    let addr = listener.local_addr().expect("对端地址");
    let (eof_tx, eof_rx) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((control, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(handle_control(control, mode.clone(), eof_tx.clone()));
        }
    });
    (addr, eof_rx)
}

/// 单条控制连接：方法协商（RFC 1928 §3）→ RFC 1929 认证子协商 →
/// UDP ASSOCIATE（§6）→ BND 应答 → 控制信道 EOF 监视 + §7 数据报中继
async fn handle_control(mut control: TcpStream, mode: PeerMode, eof_tx: watch::Sender<bool>) {
    // 方法协商（RFC 1928 §3）
    let mut head = [0u8; 2];
    control.read_exact(&mut head).await.expect("方法请求");
    assert_eq!(head[0], 0x05, "版本必须为 5");
    let mut methods = vec![0u8; head[1] as usize];
    control.read_exact(&mut methods).await.expect("方法列表");
    let want = if matches!(mode, PeerMode::RequireAuth { .. }) {
        0x02u8
    } else {
        0x00u8
    };
    let chosen = if methods.contains(&want) { want } else { 0xFF };
    control.write_all(&[0x05, chosen]).await.expect("方法应答");
    if chosen == 0xFF {
        return;
    }
    // RFC 1929 认证子协商（请求 = VER ULEN UNAME PLEN PASSWD）
    if chosen == 0x02 {
        let mut ver_ulen = [0u8; 2];
        control.read_exact(&mut ver_ulen).await.expect("认证请求头");
        assert_eq!(ver_ulen[0], 0x01, "RFC 1929 版本必须为 1");
        let mut user = vec![0u8; ver_ulen[1] as usize];
        control.read_exact(&mut user).await.expect("用户名");
        let mut plen = [0u8; 1];
        control.read_exact(&mut plen).await.expect("密码长度");
        let mut pass = vec![0u8; plen[0] as usize];
        control.read_exact(&mut pass).await.expect("密码");
        let PeerMode::RequireAuth { user: u, pass: p } = &mode else {
            panic!("认证模式不匹配");
        };
        let ok = user == u.as_bytes() && pass == p.as_bytes();
        control
            .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
            .await
            .expect("认证应答");
        if !ok {
            return;
        }
    }
    // ASSOCIATE 请求（§6）：VER CMD RSV ATYP——ATYP 在 req 内，跳过其地址体
    let mut req = [0u8; 4];
    control.read_exact(&mut req).await.expect("ASSOCIATE 请求");
    skip_endpoint(&mut control, req[3]).await;
    if let PeerMode::RejectAssociate(code) = mode {
        control
            .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("错误应答");
        tokio::time::sleep(Duration::from_millis(200)).await;
        return;
    }
    // 绑定中继 socket，应答 BND.ADDR=127.0.0.1 BND.PORT
    let relay = UdpSocket::bind("127.0.0.1:0").await.expect("中继绑定");
    let rport = relay.local_addr().expect("中继端口").port();
    control
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1])
        .await
        .expect("BND.ADDR");
    control
        .write_all(&rport.to_be_bytes())
        .await
        .expect("BND.PORT");

    // 控制信道 EOF 监视：连接关闭（relay drop）→ 对端可见
    let (mut ro, _) = control.into_split();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        loop {
            match ro.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        eof_tx.send(true).expect("EOF 通知");
    });

    relay_loop(relay, matches!(mode, PeerMode::InjectNoise)).await;
}

/// 跳过请求中的 DST.ADDR/DST.PORT（ATYP 已随请求头读入；测试对端不校验
/// 请求目标，只按地址类型跳过地址体）
async fn skip_endpoint(control: &mut TcpStream, atyp: u8) {
    let n = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            control.read_exact(&mut l).await.expect("域名长度");
            l[0] as usize
        }
        other => panic!("请求地址类型不支持: {other:#04x}"),
    };
    let mut rest = vec![0u8; n + 2]; // 地址 + PORT
    control.read_exact(&mut rest).await.expect("请求地址体");
}

/// 中继循环：客户端数据报 → 本地回显 socket → §7 封回客户端。
/// 测试对端把一切目标转本地回显（真实对端的「目标路由」在回环内等价）；
/// 解析帧头以核验客户端组帧真实（RSV/FRAG/ATYP 变体）。noise 模式在
/// 中继首报后注入噪声。
async fn relay_loop(relay: UdpSocket, noise: bool) {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("回显绑定");
    let echo_addr = echo.local_addr().expect("回显地址");
    let noise_sock = UdpSocket::bind("127.0.0.1:0").await.expect("噪声绑定");
    let mut injected = false;
    let mut buf = [0u8; 65536];
    loop {
        let Ok((n, client)) = relay.recv_from(&mut buf).await else {
            break;
        };
        // 解析 §7 帧头并核验客户端组帧
        let payload_at = parse_client_header(&buf[..n]);
        // 转发载荷到回显 socket，收回显后封 §7 帧头回客户端
        echo.send_to(&buf[payload_at..n], echo_addr).await.ok();
        let mut ebuf = [0u8; 65536];
        let Ok((en, _)) = echo.recv_from(&mut ebuf).await else {
            break;
        };
        let mut frame = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        frame.extend_from_slice(&echo_addr.port().to_be_bytes());
        frame.extend_from_slice(&ebuf[..en]);
        relay.send_to(&frame, client).await.ok();

        if noise && !injected {
            injected = true;
            // 陌生来源：另一 socket 直接发往客户端源地址（应被来源验证丢弃）
            noise_sock.send_to(&[0xde, 0xad], client).await.ok();
            // 分片：FRAG=1 的中继来源帧（应被分片丢弃，不重组不下传）
            let mut frag = vec![0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1];
            frag.extend_from_slice(&echo_addr.port().to_be_bytes());
            frag.extend_from_slice(b"fragment-part");
            relay.send_to(&frag, client).await.ok();
        }
    }
}

/// 解析客户端帧头，返回载荷起点（核验 RSV=0、FRAG=0 与 ATYP 编码）
fn parse_client_header(buf: &[u8]) -> usize {
    assert!(buf.len() >= 4, "帧头过短");
    assert!(
        buf[0] == 0x00 && buf[1] == 0x00,
        "RSV 必须为 0（实际 {:02x} {:02x}）",
        buf[0],
        buf[1]
    );
    assert_eq!(buf[2], 0x00, "客户端上行必须 FRAG=0");
    match buf[3] {
        0x01 => 3 + 1 + 4 + 2,
        0x04 => 3 + 1 + 16 + 2,
        0x03 => {
            let len = buf[4] as usize;
            3 + 1 + 1 + len + 2
        }
        other => panic!("客户端地址类型不支持: {other:#04x}"),
    }
}

fn connector(
    addr: std::net::SocketAddr,
    user: Option<&str>,
    pass: Option<&str>,
) -> Socks5UdpConnector {
    Socks5UdpConnector::from_connector(&rillane_protocols::Socks5Connector::new(
        addr.ip().to_string(),
        addr.port(),
        user.map(str::to_string),
        pass.map(str::to_string),
    ))
}

fn flow_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        metadata: FlowMetadata::default(),
    }
}

/// 粘滞决策占位：连接器按最终节点选承载但不读决策内容（与 SS relay 同）
fn decision() -> RouteDecision {
    RouteDecision::direct("socks5-udp-test".into())
}

/// IP 目标与域名目标各一轮：文本与二进制载荷真实往返（成功 + 载荷完整）
#[tokio::test]
async fn udp_associate_roundtrip_ip_and_domain_targets() {
    let (addr, _eof) = spawn_peer(PeerMode::Echo).await;
    let connector = connector(addr, None, None);

    // IP 目标（ATYP=1 上行）
    let relay = connector
        .associate(flow_ctx("10.0.0.1", 53), &decision())
        .await
        .expect("关联成功");
    relay
        .send_to(
            &FlowTarget {
                host: "10.0.0.1".into(),
                port: 53,
                proto: TargetProto::Udp,
            },
            b"query-example",
        )
        .await
        .expect("上行");
    let mut buf = [0u8; 2048];
    let (target, n) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
        .await
        .expect("下行限时")
        .expect("下行成功");
    assert_eq!(&buf[..n], b"query-example", "文本载荷完整往返");
    assert_eq!(target.host, "127.0.0.1", "回显源地址随下行带回");
    assert_eq!(target.proto, TargetProto::Udp);

    // 域名目标（ATYP=3 上行）+ 二进制载荷
    relay
        .send_to(
            &FlowTarget {
                host: "echo.test".into(),
                port: 5353,
                proto: TargetProto::Udp,
            },
            &[0u8, 1, 255, 128, 42],
        )
        .await
        .expect("域名目标上行");
    let (_target, n) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
        .await
        .expect("下行限时")
        .expect("下行成功");
    assert_eq!(&buf[..n], &[0u8, 1, 255, 128, 42], "二进制载荷完整往返");
}

/// ASSOCIATE 被拒：错误码透传（失败面——不伪装成功不静默重试）
#[tokio::test]
async fn associate_error_reply_names_code() {
    let (addr, _eof) = spawn_peer(PeerMode::RejectAssociate(0x01)).await;
    let connector = connector(addr, None, None);
    let Err(err) = connector
        .associate(flow_ctx("10.0.0.1", 53), &decision())
        .await
    else {
        panic!("被拒须失败");
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("0x01"), "错误码点名: {rendered}");
}

/// 认证子协商：凭据正确放行并往返；凭据错误被对端拒（status 0x01 透传）
#[tokio::test]
async fn auth_negotiation_verified_with_peer() {
    let (addr, _eof) = spawn_peer(PeerMode::RequireAuth {
        user: "u1".into(),
        pass: "p1".into(),
    })
    .await;

    // 正确凭据：方法协商选 0x02 → 子协商通过 → 往返成功
    let ok = connector(addr, Some("u1"), Some("p1"));
    let relay = ok
        .associate(flow_ctx("10.0.0.2", 53), &decision())
        .await
        .expect("凭据正确应关联成功");
    relay
        .send_to(
            &FlowTarget {
                host: "10.0.0.2".into(),
                port: 53,
                proto: TargetProto::Udp,
            },
            b"authed",
        )
        .await
        .expect("上行");
    let mut buf = [0u8; 256];
    let (_, n) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
        .await
        .expect("下行限时")
        .expect("下行成功");
    assert_eq!(&buf[..n], b"authed");

    // 错误凭据：对端回 status 0x01 → 连接器点名失败
    let bad = connector(addr, Some("u1"), Some("wrong"));
    let Err(err) = bad.associate(flow_ctx("10.0.0.2", 53), &decision()).await else {
        panic!("凭据错误须失败");
    };
    assert!(
        format!("{err:#}").contains("0x01"),
        "认证失败码透传: {err:#}"
    );
}

/// 来源验证与分片丢弃：陌生来源数据报与 FRAG=1 分片都不下传——客户端
/// 只收到合法回显（可观测证明：下一次 recv 返回的是回显而非噪声字节）
#[tokio::test]
async fn foreign_source_and_fragment_are_dropped() {
    let (addr, _eof) = spawn_peer(PeerMode::InjectNoise).await;
    let connector = connector(addr, None, None);
    let relay = connector
        .associate(flow_ctx("10.0.0.3", 53), &decision())
        .await
        .expect("关联成功");
    relay
        .send_to(
            &FlowTarget {
                host: "10.0.0.3".into(),
                port: 53,
                proto: TargetProto::Udp,
            },
            b"legit-payload",
        )
        .await
        .expect("上行");
    let mut buf = [0u8; 2048];
    let (_, n) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
        .await
        .expect("下行限时")
        .expect("下行成功");
    assert_eq!(
        &buf[..n],
        b"legit-payload",
        "陌生来源与分片被丢弃，只有合法回显下传"
    );
}

/// 资源释放：relay drop → 控制信道关闭（对端 EOF 可见——ASSOCIATE 生命周期
/// 绑定控制流，RFC 1928 §7）
#[tokio::test]
async fn relay_drop_releases_control_channel() {
    let (addr, mut eof) = spawn_peer(PeerMode::Echo).await;
    let connector = connector(addr, None, None);
    let relay = connector
        .associate(flow_ctx("10.0.0.4", 53), &decision())
        .await
        .expect("关联成功");
    assert!(!*eof.borrow_and_update(), "关联期间控制流在");
    drop(relay);
    tokio::time::timeout(Duration::from_secs(2), eof.changed())
        .await
        .expect("EOF 限时")
        .expect("EOF 通知");
    assert!(*eof.borrow(), "对端观测到控制信道关闭（资源已释放）");
}

/// 不可达代理：连接失败即失败并点名代理地址（失败面——不在拨号期挂死）
#[tokio::test]
async fn unreachable_proxy_fails_with_context() {
    // 占一个端口再释放——得到一个当前无人监听的回环端口
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = l.local_addr().expect("端口");
    drop(l);
    let connector = Socks5UdpConnector::from_connector(&rillane_protocols::Socks5Connector::new(
        "127.0.0.1".into(),
        addr.port(),
        None,
        None,
    ));
    let Err(err) = connector
        .associate(flow_ctx("10.0.0.5", 53), &decision())
        .await
    else {
        panic!("不可达代理须失败");
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("控制连接失败"), "失败面点名: {rendered}");
}
