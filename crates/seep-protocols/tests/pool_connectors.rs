//! P1-5 §8.1（M2 连接器两态）：pool=None 路径与既有行为同构（D-9 关闭态
//! 证明）+ Some 路径 acquire→bind→relay 时序与 stale 一次性重拨（D-11）。
//! 全 loopback 无特权；trojan 池路径的 TLS 往返归 M4 集成（mock TLS 服务端，
//! §10-9），此处由 http/vless/direct 平文路径覆盖池时序。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use seep_core::{Flow, FlowId, FlowTarget, TargetProto};
use seep_protocols::{
    DirectConnector, HttpConnector, LeaseGuard, PoolPolicy, TlsFingerprint, TransportPool,
    VlessConnector,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use seep_core::EgressConnector;

// ---------------------------------------------------------------------------
// 助手
// ---------------------------------------------------------------------------

fn test_policy() -> PoolPolicy {
    PoolPolicy {
        enabled: true,
        tls_resumption: false,
        max_idle_per_key: 2,
        max_idle_global: 16,
        low_watermark: 1,
        idle_timeout: Duration::from_secs(30),
        dial_timeout: Duration::from_secs(2),
        session_cache_size: 256,
        pre_dial_direct: false,
    }
}

/// duplex 客户端半边 + Flow（io 为对端）
fn make_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(4096);
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

/// 往返一次并收尾：写 payload → 读回 → shutdown → join forward
async fn roundtrip_and_finish(
    mut client: tokio::io::DuplexStream,
    handle: tokio::task::JoinHandle<anyhow::Result<seep_core::FlowReport>>,
    payload: &[u8],
) -> seep_core::FlowReport {
    client.write_all(payload).await.expect("客户端写入");
    client.flush().await.expect("flush");
    let mut buf = vec![0u8; payload.len()];
    client.read_exact(&mut buf).await.expect("读回");
    assert_eq!(&buf, payload, "echo 往返");
    client.shutdown().await.expect("半关触发 relay 收尾");
    handle.await.expect("forward join").expect("forward 成功")
}

async fn wait_until(cond: impl Fn() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("条件未在 5s 内满足");
}

// ---------------------------------------------------------------------------
// HTTP CONNECT（None = D-9 关闭态证明；Some = acquire→bind→relay）
// ---------------------------------------------------------------------------

/// HTTP 代理 mock：逐连接读 CONNECT 头 → 200 → echo；计数并留存首个请求原文。
async fn spawn_http_proxy() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Vec<u8>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let first_request = Arc::new(std::sync::Mutex::new(Vec::new()));
    let conns_task = conns.clone();
    let first_task = first_request.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            conns_task.fetch_add(1, Ordering::SeqCst);
            let first_task = first_task.clone();
            tokio::spawn(async move {
                // 读 CONNECT 头（至 \r\n\r\n）
                let mut head = Vec::new();
                let mut buf = [0u8; 1];
                loop {
                    if sock.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    head.push(buf[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }
                if first_task.lock().expect("first lock").is_empty() {
                    *first_task.lock().expect("first lock") = head.clone();
                }
                if sock
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                // echo 至 EOF
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, conns, first_request)
}

/// D-9 关闭态证明：pool=None 路径对代理发送的 CONNECT 字节与既有实现
/// 逐字节同构（无认证、无额外头），数据 echo 往返成立。
#[tokio::test]
async fn http_none_pool_sends_legacy_connect_bytes() {
    let (addr, _conns, first_request) = spawn_http_proxy().await;
    let connector = HttpConnector::new(
        addr.ip().to_string(),
        addr.port(),
        None,
        None,
        false,
        false,
        None,
        TlsFingerprint::None,
        None,
        None,
    );
    let (flow, client) = make_flow("example.com", 80);
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let report = roundtrip_and_finish(client, handle, b"ping").await;
    assert_eq!(report.upstream, 4);
    let sent = first_request.lock().expect("first lock").clone();
    assert_eq!(
        String::from_utf8(sent).expect("utf8"),
        "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
        "CONNECT 请求原文与既有实现一致"
    );
}

/// Some 路径时序：借出即消费不归还（D-1）→ 每流后水位补充 → 次流 hit；
/// 串行 3 流 = miss 1 + hit 2，服务端接受的连接总数 ≈ 流数（§10-1）。
#[tokio::test]
async fn http_pooled_acquire_bind_relay_and_refill_hits() {
    let (addr, conns, _first) = spawn_http_proxy().await;
    let pool = TransportPool::new(test_policy(), None);
    let connector = Arc::new(HttpConnector::new(
        addr.ip().to_string(),
        addr.port(),
        None,
        None,
        false,
        false,
        None,
        TlsFingerprint::None,
        Some(pool.clone()),
        None,
    ));

    // 流 1：miss 前台拨号
    let (flow, client) = make_flow("example.com", 80);
    let connector_for_task = connector.clone();
    let handle = tokio::spawn(async move { connector_for_task.forward(flow).await });
    roundtrip_and_finish(client, handle, b"one").await;
    let snap = pool.snapshot();
    assert_eq!(snap.acquires_miss, 1);
    assert_eq!(snap.acquires_hit, 0);

    // 水位补充落地 → 流 2 hit；同流 3
    wait_until(|| {
        pool.idle_count_of(&seep_protocols::TransportKey::plain(
            addr.ip().to_string(),
            addr.port(),
        )) == 1
    })
    .await;
    let (flow, client) = make_flow("example.com", 80);
    let connector_for_task = connector.clone();
    let handle = tokio::spawn(async move { connector_for_task.forward(flow).await });
    roundtrip_and_finish(client, handle, b"two").await;
    wait_until(|| {
        pool.idle_count_of(&seep_protocols::TransportKey::plain(
            addr.ip().to_string(),
            addr.port(),
        )) == 1
    })
    .await;
    let (flow, client) = make_flow("example.com", 80);
    let connector_for_task = connector.clone();
    let handle = tokio::spawn(async move { connector_for_task.forward(flow).await });
    roundtrip_and_finish(client, handle, b"three").await;

    let snap = pool.snapshot();
    assert_eq!(snap.acquires_hit, 2, "流 2/3 命中补充连接");
    assert_eq!(snap.acquires_miss, 1);

    // 借出即消费（D-1）：每流消耗一条 → 每流触发一次补充；服务端连接
    // 总数 = 1 前台 + 3 补充 = 4（复用/归还形态才会 ≤3，此处结构性排除）
    wait_until(|| pool.snapshot().dials_refill_ok == 3).await;
    let snap = pool.snapshot();
    assert_eq!(snap.dials_refill_ok, 3);
    assert_eq!(snap.dials_foreground_ok, 1);
    wait_until(|| conns.load(Ordering::SeqCst) == 4).await;
    assert_eq!(conns.load(Ordering::SeqCst), 4);
}

// ---------------------------------------------------------------------------
// VLESS TCP 平文（stale 一次性重拨 D-11）
// ---------------------------------------------------------------------------

/// VLESS mock：首个连接直接关闭（死闲连接），后续连接做协议应答 + echo。
async fn spawn_vless_mock() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut n = 0usize;
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            n += 1;
            tokio::spawn(async move {
                if n == 1 {
                    return; // 死闲连接：accept 后立即关闭
                }
                // 读 VLESS 请求头：ver(1) uuid(16) optlen(1) cmd(1) port(2) atype(1)...
                let mut head = [0u8; 22];
                if sock.read_exact(&mut head).await.is_err() {
                    return;
                }
                match head[21] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if sock.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        if sock.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut host = vec![0u8; l[0] as usize];
                        if sock.read_exact(&mut host).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
                if sock.write_all(&[0x00, 0x00]).await.is_err() {
                    return;
                }
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(m) => {
                            if sock.write_all(&buf[..m]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 借出连接已被服务端关闭 → bind 首读失败 → note_stale + acquire_fresh
/// 一次性重拨（D-11/E3）→ 新连接协议绑定成功、relay 成立；stale_redial=1。
#[tokio::test]
async fn vless_pooled_stale_redial_recovers_from_dead_idle() {
    let addr = spawn_vless_mock().await;
    let pool = TransportPool::new(test_policy(), None);
    let connector = VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        "00000000-0000-0000-0000-000000000000".to_string(),
        None,
        None,
        "tcp".to_string(),
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        TlsFingerprint::None,
        Some(pool.clone()),
        None,
    );

    // 预置死闲连接（服务端 accept 后立即关闭）
    let key = seep_protocols::TransportKey::plain(addr.ip().to_string(), addr.port());
    pool.prewarm(&key, 1);
    wait_until(|| pool.idle_count_of(&key) == 1).await;

    let (flow, client) = make_flow("1.2.3.4", 443);
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let report = roundtrip_and_finish(client, handle, b"vless-ping").await;
    assert_eq!(report.upstream, 10);

    let snap = pool.snapshot();
    assert_eq!(snap.acquires_stale_redial, 1, "stale 一次性重拨");
    assert_eq!(
        snap.acquires_hit, 1,
        "死闲连接按 hit 弹出（死活由 bind 判定）"
    );
    assert_eq!(snap.acquires_miss, 0, "stale_redial 独立计数不撞 miss");
    assert_eq!(snap.dials_foreground_ok, 1, "重拨 = 前台新拨");
}

/// pool=None 内联路径回归：同 mock 活连接服务应答 + echo（首连接被杀的
/// mock 对内联路径不适用——内联不命中预置死连接，直接获得服务连接）。
/// 等 5s 后首连接槽已被占用判定翻转，规避竞态：直接换独立 mock。
#[tokio::test]
async fn vless_none_pool_inline_roundtrip() {
    // 复用 mock 但跳过首连接死亡：先自拨一条占掉 n=1 死亡槽
    let addr = spawn_vless_mock().await;
    let probe = tokio::net::TcpStream::connect(addr).await.expect("占死槽");
    drop(probe);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        "00000000-0000-0000-0000-000000000000".to_string(),
        None,
        None,
        "tcp".to_string(),
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        TlsFingerprint::None,
        None,
        None,
    );
    let (flow, client) = make_flow("1.2.3.4", 443);
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let report = roundtrip_and_finish(client, handle, b"inline").await;
    assert_eq!(report.upstream, 6);
}

// ---------------------------------------------------------------------------
// direct（with_pool 选通；None = 既有路径）
// ---------------------------------------------------------------------------

async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// pool=None：既有直连路径不变（D-9）；with_pool：acquire miss 拨号 + relay。
#[tokio::test]
async fn direct_none_and_with_pool_paths() {
    let addr = spawn_echo_server().await;
    let host = addr.ip().to_string();
    let port = addr.port();

    // None 路径
    let legacy = DirectConnector::new();
    let (flow, client) = make_flow(&host, port);
    let handle = tokio::spawn(async move { legacy.forward(flow).await });
    roundtrip_and_finish(client, handle, b"legacy").await;

    // 池路径（pre_dial_direct 选通注入）
    let pool = TransportPool::new(test_policy(), None);
    let pooled = DirectConnector::with_pool(pool.clone());
    let (flow, client) = make_flow(&host, port);
    let handle = tokio::spawn(async move { pooled.forward(flow).await });
    roundtrip_and_finish(client, handle, b"pooled").await;

    let snap = pool.snapshot();
    assert_eq!(snap.acquires_miss, 1);
    assert_eq!(snap.dials_foreground_ok, 1);
}

// LeaseGuard 只作类型面引用（确保导出可用性），编译期即可证
#[allow(dead_code)]
fn _lease_type_witness(_g: Option<LeaseGuard>) {}
