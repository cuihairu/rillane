//! RIL-131 Shadowsocks 算法矩阵验收（真实对端，shadowsocks 1.25 双面回环）。
//!
//! 算法矩阵 = 当前依赖编译面（Cargo.toml features：aead-cipher + aead-cipher-2022）：
//! v1 AEAD：aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305
//! SS2022：2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm / 2022-blake3-chacha20-poly1305
//!
//! 验收面：
//! 成功——TCP 4KB 二进制经真实 ProxyListener 服务端往返 + FlowReport 统计；
//!       UDP 经真实 ProxySocket 服务端往返，且返回地址取自 SS 协议头（旁路
//!       语义归路由面，udp_egress.rs 已钉 R7 固定目标，此处钉协议头解码）；
//! 失败——错密码对端解不开，回声不达（EOF/静默，绝不出回声字节）；
//! 拒绝——none（解析成功但点名不放行）与未编译面（rc4-md5）构建期点名拒绝，
//!       SS2022 password 形状（base64、精确密钥长）构建期校验；
//! 取消/资源释放——客户端 abort 后服务端会话收束（started == ended）。

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::Engine as _;
use rand::RngCore;
use rillane_core::{
    udp::EgressUdpConnector as _, EgressConnector as _, Flow, FlowContext, FlowId, RouteDecision,
    RoutePath, RouteType, TargetProto,
};
use rillane_protocols::{ShadowsocksConnector, ShadowsocksUdpConnector};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    net::{AcceptOpts, TcpListener as ShadowTcpListener, UdpSocket as ShadowUdpSocket},
    relay::{
        socks5::Address,
        tcprelay::{
            utils::{copy_from_encrypted, copy_to_encrypted},
            ProxyListener,
        },
        udprelay::proxy_socket::{ProxySocket, UdpSocketType},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

/// 六算法矩阵（编译面全量：3 个 v1 AEAD + 3 个 SS2022）
const MATRIX: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// SS2022 的 password 是 base64 密钥（长度与算法密钥长精确一致），随机生成；
/// v1 AEAD 密码任意串
fn password_for(method: &str) -> String {
    let cipher: CipherKind = method.parse().expect("矩阵方法须可解析");
    if cipher.is_aead_2022() {
        let mut key = vec![0u8; cipher.key_len()];
        rand::thread_rng().fill_bytes(&mut key);
        base64::engine::general_purpose::STANDARD.encode(key)
    } else {
        format!("matrix-password-{method}")
    }
}

fn tcp_flow_target(host: &str, port: u16) -> rillane_core::FlowTarget {
    rillane_core::FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Tcp,
    }
}

fn flow_of(target: rillane_core::FlowTarget, io: DuplexStream) -> Flow {
    Flow {
        id: FlowId::new(),
        target,
        io: Box::new(io),
        metadata: Default::default(),
    }
}

fn decision() -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: "matrix-node".into(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

fn udp_ctx(host: &str, port: u16) -> FlowContext {
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

/// 纯 TCP 回声端（SS 服务端从协议头解析出目标后真实转发到此）
async fn spawn_plain_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
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

/// 纯 UDP 回声端
async fn spawn_plain_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
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

/// 真实 SS TCP 服务端（crate ProxyListener 面）：accept → 显式 handshake →
/// 按协议头连接目标 → 双向中继。started/ended 钉会话生命周期（资源释放面）。
async fn spawn_ss_tcp_peer(
    method: &str,
    password: &str,
) -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let cipher: CipherKind = method.parse().expect("矩阵方法须可解析");
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = ShadowTcpListener::bind_with_opts(&bind_addr, AcceptOpts::default())
        .await
        .expect("bind ss");
    let addr = listener.local_addr().unwrap();
    let svr_cfg = ServerConfig::new(addr, password.to_string(), cipher).expect("server cfg");
    let ctx = Context::new_shared(ServerType::Server);
    let listener = ProxyListener::from_listener(ctx, listener, &svr_cfg);

    let started = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicUsize::new(0));
    let (s2, e2) = (started.clone(), ended.clone());

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            s2.fetch_add(1, Ordering::SeqCst);
            let e3 = e2.clone();
            tokio::spawn(async move {
                // 中继限时兜底：即便半关传播异常也会收束会话
                let _ = timeout(Duration::from_secs(10), async {
                    let target = match stream.handshake().await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let remote = match target {
                        Address::SocketAddress(sa) => TcpStream::connect(sa).await,
                        Address::DomainNameAddress(ref d, p) => {
                            TcpStream::connect((d.as_str(), p)).await
                        }
                    };
                    let Ok(mut remote) = remote else {
                        return;
                    };
                    let (mut sr, mut sw) = tokio::io::split(stream);
                    let (mut mr, mut mw) = remote.split();
                    // 任一向收束即结束会话（crate copy 工具在 EOF 只 flush 不
                    // shutdown，排空向会悬到对端各自关闭；测试回声面无滞留数据，
                    // 直接整面收束 = 及时资源释放）
                    let _ = timeout(Duration::from_secs(5), async {
                        tokio::select! {
                            r = copy_from_encrypted(cipher, &mut sr, &mut mw) => {
                                let _ = r;
                            }
                            r = copy_to_encrypted(cipher, &mut mr, &mut sw) => {
                                let _ = r;
                            }
                        }
                    })
                    .await;
                })
                .await;
                e3.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (addr, started, ended)
}

/// 真实 SS UDP 服务端（crate ProxySocket Server 面）：解包 → 连真实目标回声 →
/// 按服务端语义回包。:0 绑定面 —— 已绑定的 tokio socket 直接包成 ShadowUdpSocket
/// 喂 from_socket（ProxySocket::bind 会按 svr_cfg 再绑一次，:0 场景撞 AddrInUse）
async fn spawn_ss_udp_peer(method: &str, password: &str) -> SocketAddr {
    let cipher: CipherKind = method.parse().expect("矩阵方法须可解析");
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind ss udp");
    let addr = socket.local_addr().unwrap();
    let svr_cfg = ServerConfig::new(addr, password.to_string(), cipher).expect("server cfg");
    let ctx = Context::new_shared(ServerType::Server);
    let socket = ProxySocket::from_socket(
        UdpSocketType::Server,
        ctx,
        &svr_cfg,
        ShadowUdpSocket::from(socket),
    );

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer, target, ..)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let sa = match target {
                Address::SocketAddress(sa) => sa,
                Address::DomainNameAddress(ref d, p) => match d.as_str().parse() {
                    Ok(ip) => SocketAddr::new(ip, p),
                    Err(_) => continue,
                },
            };
            let Ok(raw) = UdpSocket::bind("0.0.0.0:0").await else {
                break;
            };
            if raw.connect(sa).await.is_err() {
                continue;
            }
            if raw.send(&buf[..n]).await.is_err() {
                continue;
            }
            let mut rbuf = vec![0u8; 65536];
            if let Ok(Ok(n2)) = timeout(Duration::from_secs(2), raw.recv(&mut rbuf)).await {
                let _ = socket.send_to(peer, &target, &rbuf[..n2]).await;
            }
        }
    });
    addr
}

fn deterministic(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 13) as u8).collect()
}

// ---------- 成功面：TCP 矩阵 + 统计 ----------

#[tokio::test]
async fn tcp_matrix_roundtrip_with_stats() {
    for method in MATRIX {
        let password = password_for(method);
        let echo = spawn_plain_tcp_echo().await;
        let (ss_addr, started, ended) = spawn_ss_tcp_peer(method, &password).await;

        let conn = ShadowsocksConnector::new(
            ss_addr.ip().to_string(),
            ss_addr.port(),
            (*method).to_string(),
            password,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("[{method}] 构建失败: {e:#}"));

        let (mut user, ingress) = tokio::io::duplex(64 * 1024);
        let flow = flow_of(tcp_flow_target("127.0.0.1", echo.port()), ingress);
        let fwd = tokio::spawn(async move { conn.forward(flow).await });

        let payload = deterministic(4096);
        user.write_all(&payload)
            .await
            .unwrap_or_else(|e| panic!("[{method}] 写失败: {e}"));
        let mut back = vec![0u8; payload.len()];
        timeout(Duration::from_secs(5), user.read_exact(&mut back))
            .await
            .unwrap_or_else(|_| panic!("[{method}] 回声限时"))
            .unwrap_or_else(|e| panic!("[{method}] 读失败: {e}"));
        assert_eq!(back, payload, "[{method}] 回声须逐字节一致");

        // 自然收束：EOF 传播 → forward 返回 → 统计面成立
        drop(user);
        let report = timeout(Duration::from_secs(5), fwd)
            .await
            .expect("[{method}] forward 收束限时")
            .expect("任务不应 panic")
            .unwrap_or_else(|e| panic!("[{method}] forward 失败: {e:#}"));
        assert_eq!(report.upstream, payload.len() as u64, "[{method}] 上行统计");
        assert_eq!(
            report.downstream,
            payload.len() as u64,
            "[{method}] 下行统计"
        );

        // 资源释放：会话在服务端收束
        assert!(
            wait_for(
                || ended.load(Ordering::SeqCst) >= started.load(Ordering::SeqCst),
                Duration::from_secs(3)
            )
            .await,
            "[{method}] 服务端会话须随客户端收束"
        );
    }
}

// ---------- 成功面：UDP 矩阵 + 协议头地址 ----------

#[tokio::test]
async fn udp_matrix_roundtrip_with_header_address() {
    for method in MATRIX {
        let password = password_for(method);
        let echo = spawn_plain_udp_echo().await;
        let ss_addr = spawn_ss_udp_peer(method, &password).await;

        let conn = ShadowsocksConnector::new(
            ss_addr.ip().to_string(),
            ss_addr.port(),
            (*method).to_string(),
            password,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("[{method}] 构建失败: {e:#}"));
        let udp = ShadowsocksUdpConnector::from_connector(&conn);

        let relay = timeout(
            Duration::from_secs(5),
            udp.associate(udp_ctx("127.0.0.1", echo.port()), &decision()),
        )
        .await
        .expect("[{method}] associate 限时")
        .unwrap_or_else(|e| panic!("[{method}] associate 失败: {e:#}"));

        let payload = deterministic(1200);
        timeout(
            Duration::from_secs(5),
            relay.send_to(
                &rillane_core::FlowTarget {
                    host: "127.0.0.1".into(),
                    port: echo.port(),
                    proto: TargetProto::Udp,
                },
                &payload,
            ),
        )
        .await
        .expect("[{method}] send 限时")
        .unwrap_or_else(|e| panic!("[{method}] send 失败: {e:#}"));

        let mut buf = vec![0u8; 65536];
        let (ft, n) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("[{method}] recv 限时")
            .unwrap_or_else(|e| panic!("[{method}] recv 失败: {e:#}"));
        assert_eq!(n, payload.len(), "[{method}] UDP 载荷长度");
        assert_eq!(&buf[..n], &payload, "[{method}] UDP 载荷须逐字节一致");
        // 地址语义：返回地址取自 SS 协议头（服务端解码面），而非关联参数缓存
        assert_eq!(ft.host, "127.0.0.1", "[{method}] 协议头地址 host");
        assert_eq!(ft.port, echo.port(), "[{method}] 协议头地址 port");
        assert_eq!(ft.proto, TargetProto::Udp, "[{method}] 协议头地址 proto");
    }
}

// ---------- 失败面：错密码 ----------

#[tokio::test]
async fn wrong_password_yields_no_echo() {
    let echo = spawn_plain_tcp_echo().await;
    // 服务端/客户端密码不同构：对端解不开请求，回声不达
    let (ss_addr, _started, _ended) = spawn_ss_tcp_peer("aes-256-gcm", "server-secret").await;
    let conn = ShadowsocksConnector::new(
        ss_addr.ip().to_string(),
        ss_addr.port(),
        "aes-256-gcm".into(),
        "wrong-secret".into(),
        None,
        None,
    )
    .expect("错密码仍是合法形状，构建须成功");

    let (mut user, ingress) = tokio::io::duplex(64 * 1024);
    let flow = flow_of(tcp_flow_target("127.0.0.1", echo.port()), ingress);
    let _fwd = tokio::spawn(async move { conn.forward(flow).await });

    let payload = deterministic(1024);
    user.write_all(&payload).await.expect("写失败");
    let mut back = vec![0u8; payload.len()];
    let outcome = timeout(Duration::from_secs(3), user.read_exact(&mut back)).await;
    match outcome {
        // 服务端解密失败后关闭（EOF）或保持静默（限时）——两者都算"回声不达"
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("错密码绝不能收到回声字节"),
    }
}

// ---------- 拒绝面：不支持组合构建期点名拒绝 ----------

/// 构建须失败的组合，返回点名错误（ShadowsocksConnector 非 Debug，不走 expect_err）
fn must_refuse(method: &str, password: &str) -> anyhow::Error {
    match ShadowsocksConnector::new(
        "127.0.0.1".into(),
        8388,
        method.into(),
        password.into(),
        None,
        None,
    ) {
        Ok(_) => panic!("[{method}] 该组合必须拒绝"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn unsupported_combinations_refused_by_name() {
    // NONE 解析成功但点名不放行（无加密不进数据面）
    let err = must_refuse("none", "pw");
    assert!(
        format!("{err:#}").contains("无加密"),
        "NONE 拒绝语义: {err:#}"
    );

    // rc4-md5 属 stream 面（本仓未编译）→ 解析失败点名
    let err = must_refuse("rc4-md5", "pw");
    assert!(
        format!("{err:#}").contains("不支持的加密方法"),
        "未编译面拒绝语义: {err:#}"
    );
}

#[tokio::test]
async fn ss2022_password_shape_validated_at_construction() {
    // 长度不足（aes-128 须 16 字节）
    let short = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]);
    let err = must_refuse("2022-blake3-aes-128-gcm", &short);
    assert!(
        format!("{err:#}").contains("密钥长度须为 16"),
        "短密钥拒绝语义: {err:#}"
    );

    // 长度不匹配（aes-256 须 32 字节，给了 16）
    let half = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
    let err = must_refuse("2022-blake3-aes-256-gcm", &half);
    assert!(
        format!("{err:#}").contains("密钥长度须为 32"),
        "错长密钥拒绝语义: {err:#}"
    );

    // 非 base64
    let err = must_refuse("2022-blake3-chacha20-poly1305", "not-base64-password!!");
    assert!(
        format!("{err:#}").contains("base64"),
        "非 base64 拒绝语义: {err:#}"
    );

    // 正确形状放行（32 字节 chacha20）
    let ok = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    assert!(
        ShadowsocksConnector::new(
            "127.0.0.1".into(),
            8388,
            "2022-blake3-chacha20-poly1305".into(),
            ok,
            None,
            None,
        )
        .is_ok(),
        "正确形状须放行"
    );
}

// ---------- 取消/资源释放面 ----------

#[tokio::test]
async fn cancel_aborts_client_and_releases_server_session() {
    let method = "aes-256-gcm";
    let password = password_for(method);
    let echo = spawn_plain_tcp_echo().await;
    let (ss_addr, started, ended) = spawn_ss_tcp_peer(method, &password).await;

    let conn = ShadowsocksConnector::new(
        ss_addr.ip().to_string(),
        ss_addr.port(),
        method.to_string(),
        password,
        None,
        None,
    )
    .unwrap();

    let (mut user, ingress) = tokio::io::duplex(64 * 1024);
    let flow = flow_of(tcp_flow_target("127.0.0.1", echo.port()), ingress);
    let fwd = tokio::spawn(async move { conn.forward(flow).await });

    // 会话活性：写入并收到回声
    let payload = deterministic(1024);
    user.write_all(&payload).await.expect("写失败");
    let mut back = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), user.read_exact(&mut back))
        .await
        .expect("回声限时")
        .expect("读失败");
    assert_eq!(back, payload, "取消前会话须已建立");

    // 中途取消：abort → 全链资源随 drop 收束
    fwd.abort();
    let cancelled = matches!(fwd.await, Err(e) if e.is_cancelled());
    assert!(cancelled, "forward 任务须被取消");

    // 服务端会话收束（started == ended）
    assert!(
        wait_for(
            || ended.load(Ordering::SeqCst) >= started.load(Ordering::SeqCst),
            Duration::from_secs(3),
        )
        .await,
        "取消后服务端会话须收束（started={} ended={}）",
        started.load(Ordering::SeqCst),
        ended.load(Ordering::SeqCst)
    );
}
