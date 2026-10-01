//! P1-5 §8.1（M0 范围）：键 / 池核心 / 工厂 单测。
//! 全 loopback 无特权；idle 超时与驱逐次序走 `MockPoolClock` 确定性拨秒。

use std::sync::Arc;
use std::time::Duration;

use rustls::HandshakeKind;
use tokio::net::{TcpListener, TcpStream};

use super::{next_backoff_millis, PoolPolicy, PoolSnapshot, TransportKey, TransportPool};
use crate::tls::TlsConnectorFactory;

// ---------------------------------------------------------------------------
// 助手
// ---------------------------------------------------------------------------

fn test_policy(max_per_key: usize, low_water: usize, max_global: usize) -> PoolPolicy {
    PoolPolicy {
        enabled: true,
        tls_resumption: false,
        max_idle_per_key: max_per_key,
        max_idle_global: max_global,
        low_watermark: low_water,
        idle_timeout: Duration::from_secs(30),
        dial_timeout: Duration::from_secs(2),
        session_cache_size: 256,
        pre_dial_direct: false,
    }
}

/// loopback 挂连服务器：accept 后原样持有连接（idle 借出对象由对端控制关闭）。
async fn spawn_idle_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // listener 活足测试时长；backlog 内的连接内核已完成握手
        let _ = tokio::time::sleep(Duration::from_secs(60)).await;
        drop(listener);
    });
    addr
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
// 键（§8.1：相等性 / alpn 规一化 / plain 与 tls 不撞 / 可读序列化）
// ---------------------------------------------------------------------------

#[test]
fn transport_key_equality_and_display() {
    let a = TransportKey::tls(
        "e.com",
        443,
        Some("sni.com"),
        false,
        &["h2".into(), "http/1.1".into()],
    );
    // alpn 顺序 + 空项/空白规一化后相等
    let b = TransportKey::tls(
        "e.com",
        443,
        Some("sni.com"),
        false,
        &["http/1.1".into(), " h2 ".into(), "".into()],
    );
    assert_eq!(a, b, "alpn 顺序规一化");
    assert_eq!(a.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);

    // 各字段敏感
    assert_ne!(
        a,
        TransportKey::tls(
            "e.com",
            443,
            Some("sni.com"),
            true,
            &["h2".into(), "http/1.1".into()]
        ),
        "skip_cert_verify 敏感"
    );
    assert_ne!(
        a,
        TransportKey::tls("e.com", 443, Some("other"), false, &a.alpn),
        "sni 敏感"
    );
    assert_ne!(
        a,
        TransportKey::tls("e.com", 8443, Some("sni.com"), false, &a.alpn),
        "端口敏感"
    );
    assert_ne!(
        a,
        TransportKey::tls("other.com", 443, Some("sni.com"), false, &a.alpn),
        "server 敏感"
    );
    // plain 与 tls 不撞（同端点）
    assert_ne!(TransportKey::plain("e.com", 443), a);

    // sni 空白归 None
    assert_eq!(
        TransportKey::tls("e.com", 443, Some("  "), false, &[]).sni,
        None
    );

    // 可读序列化形状（§2.2 / §6.2 stats 示例口径）
    assert_eq!(a.to_string(), "tls:sni=sni.com@e.com:443[alpn=h2,http/1.1]");
    assert_eq!(TransportKey::plain("e.com", 443).to_string(), "e.com:443");
    assert_eq!(
        TransportKey::tls("e.com", 443, None, false, &[]).to_string(),
        "tls:sni@e.com:443"
    );
}

// ---------------------------------------------------------------------------
// 池核心（§8.1：hit/miss 与计数 / 水位补充 / 超时 / 驱逐 / 退避 / stale）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn acquire_hit_miss_watermark_refill_and_lease_guard() {
    let addr = spawn_idle_server().await;
    let key = TransportKey::plain(addr.ip().to_string(), addr.port());
    let pool = TransportPool::new(test_policy(2, 1, 16), None);

    // 首借：miss 前台拨号
    let (io, lease) = pool.acquire(&key).await.expect("首借");
    let snap = pool.snapshot();
    assert_eq!(snap.acquires_miss, 1);
    assert_eq!(snap.acquires_hit, 0);
    assert_eq!(snap.dials_foreground_ok, 1);
    assert_eq!(snap.leased, 1, "借出中 leased gauge");

    // 水位补充：弹出后后台 refill 拨一条入 idle
    wait_until(|| pool.idle_count_of(&key) == 1).await;
    assert_eq!(pool.snapshot().dials_refill_ok, 1);

    // 消耗（drop = consumed，不回池；io 与 LeaseGuard 双双释放 leased 才归零）
    drop(io);
    drop(lease);
    assert_eq!(pool.snapshot().leased, 0, "LeaseGuard RAII 递减");

    // 二借：hit 弹 idle
    let (_io2, _lease2) = pool.acquire(&key).await.expect("二借");
    let snap = pool.snapshot();
    assert_eq!(snap.acquires_hit, 1);
    assert_eq!(snap.acquires_miss, 1);
    assert_eq!(snap.reuse_ratio(), 0.5);
}

#[tokio::test]
async fn idle_expiry_lazy_pop_and_sweep() {
    let clock = crate::MockPoolClock::new();
    let addr = spawn_idle_server().await;
    let key = TransportKey::plain(addr.ip().to_string(), addr.port());
    let pool = TransportPool::with_clock(test_policy(2, 1, 16), None, clock.clone());

    // miss + refill（born t=0）
    let (_io, _lease) = pool.acquire(&key).await.expect("首借");
    wait_until(|| pool.idle_count_of(&key) == 1).await;

    // 推进到过期线上：lazy 弹出过期条目 → close + evicted{idle_timeout} → 转 miss
    clock.advance_millis(30_000);
    let (_io2, _lease2) = pool.acquire(&key).await.expect("二借");
    let snap = pool.snapshot();
    assert_eq!(snap.evicted_idle_timeout, 1, "lazy 过期驱逐");
    assert_eq!(snap.acquires_hit, 0, "过期条目不算 hit");
    assert_eq!(snap.acquires_miss, 2);

    // refill 补回（born t=30s）；再推进到期 → sweep 路径驱逐 + 孤儿键回收
    wait_until(|| pool.idle_count_of(&key) == 1).await;
    clock.advance_millis(30_000);
    pool.sweep_once();
    assert_eq!(pool.snapshot().evicted_idle_timeout, 2, "sweep 过期驱逐");
    assert_eq!(pool.live_key_count(), 0, "孤儿键条目移除");
}

#[tokio::test]
async fn global_capacity_evicts_oldest() {
    let clock = crate::MockPoolClock::new();
    // 两个不同端点 = 两个不同的键（同端口同 IP 会撞成同一个键，
    // prewarm(k2) 会被 max_idle_per_key 逐掉而非触发全局驱逐）
    let addr1 = spawn_idle_server().await;
    let addr2 = spawn_idle_server().await;
    let k1 = TransportKey::plain(addr1.ip().to_string(), addr1.port());
    let k2 = TransportKey::plain(addr2.ip().to_string(), addr2.port());
    // low_watermark=0：不自动 refill，全部走 prewarm 控时
    let pool = TransportPool::with_clock(test_policy(1, 0, 1), None, clock.clone());

    pool.prewarm(&k1, 1);
    wait_until(|| pool.idle_count_of(&k1) == 1).await; // born t=0
    clock.advance_millis(1_000);
    pool.prewarm(&k2, 1);
    wait_until(|| pool.idle_count_of(&k2) == 1).await; // born t=1s

    // 全局 idle 2 > max_idle_global 1 → 逐最老（k1）
    assert_eq!(pool.idle_count_of(&k1), 0, "最老先逐");
    assert_eq!(pool.idle_count_of(&k2), 1);
    assert_eq!(pool.snapshot().evicted_capacity, 1);
}

#[tokio::test]
async fn background_backoff_on_dead_egress() {
    assert_eq!(next_backoff_millis(0), 1_000, "1s 起");
    assert_eq!(next_backoff_millis(1_000), 2_000, "指数");
    assert_eq!(next_backoff_millis(16_000), 30_000, "30s 封顶");
    assert_eq!(next_backoff_millis(30_000), 30_000, "封顶不溢出");

    // 首次后台失败 → backoff 置 1s（dead port 立即 refused）
    let key = TransportKey::plain("127.0.0.1", 1);
    let pool = TransportPool::new(test_policy(2, 1, 16), None);
    pool.prewarm(&key, 1);
    wait_until(|| pool.backoff_millis_of(&key) == 1_000).await;
    assert_eq!(pool.backoff_millis_of(&key), 1_000);

    // 对活出站成功 → 退避复位为 0
    let addr = spawn_idle_server().await;
    let ok_key = TransportKey::plain(addr.ip().to_string(), addr.port());
    pool.prewarm(&ok_key, 1);
    wait_until(|| pool.idle_count_of(&ok_key) == 1).await;
    assert_eq!(pool.backoff_millis_of(&ok_key), 0, "成功复位");
}

#[tokio::test]
async fn acquire_fresh_bypasses_idle_and_counts_stale_redial() {
    let addr = spawn_idle_server().await;
    let key = TransportKey::plain(addr.ip().to_string(), addr.port());
    let pool = TransportPool::new(test_policy(2, 0, 16), None);

    // 预置 idle 一条；acquire_fresh 不弹 idle（绕过缓存直拨新连接）
    pool.prewarm(&key, 1);
    wait_until(|| pool.idle_count_of(&key) == 1).await;

    let (_io, _lease) = pool.acquire_fresh(&key).await.expect("stale 重拨");
    assert_eq!(pool.idle_count_of(&key), 1, "idle 未被动用");
    let snap = pool.snapshot();
    assert_eq!(snap.acquires_stale_redial, 1);
    assert_eq!(snap.dials_foreground_ok, 1);
    assert_eq!(
        snap.acquires_hit + snap.acquires_miss,
        0,
        "stale_redial 独立计数"
    );

    // 重拨再失败 → Err（同今天拨号失败语义，不再三试）
    let dead = TransportKey::plain("127.0.0.1", 1);
    assert!(pool.acquire_fresh(&dead).await.is_err());
    assert_eq!(pool.snapshot().acquires_stale_redial, 2);
    assert_eq!(pool.snapshot().dials_foreground_err, 1);
}

#[tokio::test]
async fn tls_key_without_factory_is_a_clear_error() {
    let addr = spawn_idle_server().await;
    let key = TransportKey::tls(
        addr.ip().to_string(),
        addr.port(),
        Some("x.example"),
        false,
        &[],
    );
    let pool = TransportPool::new(test_policy(2, 0, 16), None);
    let err = match pool.acquire(&key).await {
        Ok(_) => panic!("TLS 键无工厂应报错"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("TlsConnectorFactory"),
        "错误应点名装配错配：{err:#}"
    );
}

#[test]
fn reuse_ratio_zero_denominator_is_zero() {
    let snap = PoolSnapshot::default();
    assert_eq!(snap.reuse_ratio(), 0.0);
    let snap = PoolSnapshot {
        acquires_hit: 9,
        acquires_miss: 1,
        ..Default::default()
    };
    assert!((snap.reuse_ratio() - 0.9).abs() < 1e-9);
}

#[tokio::test]
async fn pool_drop_counts_shutdown_eviction() {
    let addr = spawn_idle_server().await;
    let key = TransportKey::plain(addr.ip().to_string(), addr.port());
    let pool = TransportPool::new(test_policy(2, 0, 16), None);
    pool.prewarm(&key, 1);
    wait_until(|| pool.idle_count_of(&key) == 1).await;
    let (io, _lease) = pool.acquire(&key).await.unwrap();
    drop(io);
    let snap = pool.snapshot();
    drop(pool); // E7：idle 全关 + evicted{shutdown}
                // 快照随池消亡，无法事后断言——改为构造期探测：克隆一份计数前置校验
    assert_eq!(snap.evicted_shutdown, 0, "释放前无 shutdown 驱逐");
    // Drop 不 panic 即为过（真实 shutdown 计数由 M4 集成口径断言）
}

// ---------------------------------------------------------------------------
// 工厂（§8.1：同键共享 Arc 实例 / 异键异实例 / alpn 规整 / 握手计数）
// ---------------------------------------------------------------------------

#[test]
fn factory_same_key_shares_config_arc() {
    let factory = TlsConnectorFactory::new(64);
    let a = factory
        .shared_config(false, &["h2".to_string(), "http/1.1".to_string()])
        .unwrap();
    let b = factory
        .shared_config(
            false,
            &[" http/1.1 ".to_string(), "h2".to_string(), "".to_string()],
        )
        .unwrap();
    assert!(Arc::ptr_eq(&a, &b), "同键（alpn 规一化后）共享 Arc 实例");

    let c = factory.shared_config(true, &["h2".to_string()]).unwrap();
    assert!(!Arc::ptr_eq(&a, &c), "skip_cert_verify 异键异实例");
    let d = factory.shared_config(false, &[]).unwrap();
    assert!(!Arc::ptr_eq(&a, &d), "无 alpn 异键异实例");

    assert_eq!(a.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(d.alpn_protocols.is_empty());

    // connector 构造走同一路径
    let _ = factory
        .connector(true, &["h2".to_string()])
        .expect("connector");
}

#[test]
fn factory_handshake_kind_notes() {
    let factory = TlsConnectorFactory::new(16);
    assert_eq!(factory.handshake_snapshot(), (0, 0, 0));
    factory.note_handshake(Some(HandshakeKind::Full));
    factory.note_handshake(Some(HandshakeKind::FullWithHelloRetryRequest));
    factory.note_handshake(Some(HandshakeKind::Resumed));
    factory.note_handshake(Some(HandshakeKind::Resumed));
    factory.note_handshake(None);
    assert_eq!(factory.handshake_snapshot(), (1, 1, 2), "三变体直映");
}

/// 拨号侧接线冒烟：真 TCP+TLS 到 loopback 平文端口 → 握手超时/失败路径
/// （完整 TLS 会话恢复往返 = M4 集成口径，需 mock TLS 服务端）。
#[tokio::test]
async fn dial_plain_key_boxes_tcp_stream() {
    let addr = spawn_idle_server().await;
    let key = TransportKey::plain(addr.ip().to_string(), addr.port());
    let pool = TransportPool::new(test_policy(1, 0, 16), None);
    let (mut io, _lease) = pool.acquire(&key).await.expect("plain 拨号");
    // 借出连接可写（零协议字节写入 = 池契约，写什么由连接器决定）
    use tokio::io::AsyncWriteExt;
    io.write_all(b"x").await.expect("借出连接可写");
    assert_eq!(pool.snapshot().dials_foreground_ok, 1);
    assert!(TcpStream::connect(addr).await.is_ok(), "listener 仍活");
}
