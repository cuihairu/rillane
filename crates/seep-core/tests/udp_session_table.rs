//! P0-1 UDP 会话表单测（udp-session-table.md §7 / udp-session-table-api.md §7）。
//! 覆盖：表项生命周期、MockClock 确定性超时回收、同一粘滞键复用映射不重建、
//! 容量拒新、粘滞决策失效与映射吊销、LRU 逐出、ledger O7 恢复、并发绑定。

use bytes::Bytes;
use seep_core::udp::{
    sweep_once, ChainFailureEvent, Clock, Dir, DropReason, MockUdpRelay,
    ProcessIdentity, ResolveError, SessionLedger, UdpSessionConfig, UdpSessionKey,
    UdpSessionTable,
};
use seep_core::{
    FailureType, FlowContext, FlowId, RouteDecision, RoutePath, RouteType, SessionStatus,
    TargetProto,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

// ---------- 测试基础设施 ----------

struct MockRouter {
    calls: AtomicUsize,
    node: String,
    fail: AtomicBool,
}

impl MockRouter {
    fn new(node: &str) -> Arc<Self> {
        Arc::new(Self { calls: AtomicUsize::new(0), node: node.to_string(), fail: AtomicBool::new(false) })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl seep_core::FlowRouter for MockRouter {
    async fn route(&self, _ctx: FlowContext) -> anyhow::Result<RouteDecision> {
        if self.fail.load(Ordering::SeqCst) {
            anyhow::bail!("route 不可用");
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RouteDecision {
            path: RoutePath::Direct { node: self.node.clone() },
            reason: None,
            route_type: RouteType::Standard,
        })
    }
}

const NODE_A: &str = "node-a";

fn addr(p: u16) -> SocketAddr {
    format!("127.0.0.1:{p}").parse().unwrap()
}

fn udp_target(host: &str, port: u16) -> seep_core::FlowTarget {
    seep_core::FlowTarget { host: host.to_string(), port, proto: TargetProto::Udp }
}

struct Ctx {
    table: Arc<UdpSessionTable>,
    router: Arc<MockRouter>,
    clock: Arc<seep_core::udp::MockClock>,
}

/// 可调参数建表（sweep_interval 缩短以便常驻回收任务测试）
async fn make_table(mut cfg: impl FnMut(&mut UdpSessionConfig)) -> Ctx {
    let mut config = UdpSessionConfig::default();
    cfg(&mut config);
    let router = MockRouter::new(NODE_A);
    let clock = seep_core::udp::MockClock::new();
    let table = UdpSessionTable::new(
        config,
        router.clone() as Arc<dyn seep_core::FlowRouter>,
        clock.clone() as Arc<dyn seep_core::udp::Clock>,
    )
    .unwrap();
    Ctx { table, router, clock }
}

/// 轮询至条件成立（forwarder 任务异步性的确定性等待）
async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "wait_until 超时"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

// ---------- 生命周期 ----------

#[tokio::test]
async fn lifecycle_resolve_creates_and_reuses_session() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(40000));
    let s1 = c.table.resolve(&key, &udp_target("example.com", 53)).await.unwrap();
    let s2 = c.table.resolve(&key, &udp_target("other.com", 9953)).await.unwrap();
    // 同一粘滞键：会话复用（同 FlowId），不重建
    assert_eq!(s1.id(), s2.id());
    let snap = c.table.snapshot();
    assert_eq!(snap.sessions_active, 1);
    assert_eq!(snap.sessions_total, 1);
}

#[tokio::test]
async fn sticky_key_dimensions_distinguish_sessions() {
    let c = make_table(|_| {}).await;
    let base = addr(41000);
    let k_plain = UdpSessionKey::new(base);
    let k_alice = UdpSessionKey::new(base).with_user(Some("Alice".into()));
    let k_bob = UdpSessionKey::new(base).with_user(Some("bob".into()));
    let k_proc = UdpSessionKey::new(base)
        .with_process(Some(ProcessIdentity { pid: 7, name: "game.exe".into() }));
    let t = udp_target("x.test", 1);
    let a = c.table.resolve(&k_plain, &t).await.unwrap();
    let b = c.table.resolve(&k_alice, &t).await.unwrap();
    let d = c.table.resolve(&k_bob, &t).await.unwrap();
    let e = c.table.resolve(&k_proc, &t).await.unwrap();
    assert_ne!(a.id(), b.id());
    assert_ne!(b.id(), d.id());
    assert_ne!(b.id(), e.id());
    // 用户名归一化：Alice → alice（快照里可见）
    let snap = c.table.snapshot();
    assert_eq!(snap.sessions_active, 4);
    assert!(snap.sessions.iter().any(|s| s.user.as_deref() == Some("alice")));
}

// ---------- 快路径与映射复用（P0-1 验收核心） ----------

#[tokio::test]
async fn forward_up_miss_then_bind_then_sent() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(42000));
    let t = udp_target("dns.test", 53);
    // 无会话：Miss（不隐式创建）
    let r = c.table.forward_up(&key, &t, Bytes::from_static(b"q")).await;
    assert_eq!(r, seep_core::udp::UpResult::Miss);
    assert_eq!(c.table.snapshot().sessions_active, 0);

    // resolve + bind → Sent
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (relay, _tx) = MockUdpRelay::new(t.clone());
    assert_eq!(sref.bind_mapping(&t, relay.clone()).await.unwrap(), seep_core::udp::BindOutcome::Created);
    let r = c.table.forward_up(&key, &t, Bytes::from_static(b"query")).await;
    assert_eq!(r, seep_core::udp::UpResult::Sent);
    assert_eq!(relay.send_count(), 1);
    let snap = c.table.snapshot();
    assert_eq!(snap.mappings_active, 1);
    assert_eq!(snap.sessions[0].bytes_uploaded, 5);
    assert_eq!(snap.sessions[0].packets_count, 1);
}

#[tokio::test]
async fn same_sticky_key_reuses_mapping_without_rebuild() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(43000));
    let t = udp_target("game.test", 7777);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (relay1, _tx1) = MockUdpRelay::new(t.clone());
    let (relay2, _tx2) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, relay1.clone()).await.unwrap();
    // 二次绑定同目标：Reused 且继续用原 relay（不重建）
    let out = sref.bind_mapping(&t, relay2.clone()).await.unwrap();
    assert_eq!(out, seep_core::udp::BindOutcome::Reused);
    sref.send_up(&t, Bytes::from_static(b"ping")).await;
    assert_eq!(relay1.send_count(), 1);
    assert_eq!(relay2.send_count(), 0);
    assert_eq!(c.table.snapshot().mappings_active, 1);
}

#[tokio::test]
async fn downlink_packets_flow_to_session_channel() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(44000));
    let t = udp_target("game.test", 7777);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (relay, tx) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, relay).await.unwrap();
    let mut rx = sref.take_downlink_rx().await.unwrap();
    // forwarder：mock 下行注入 → 会话下行通道
    tx.send(vec![1, 2, 3, 4]).await.unwrap();
    let pkt = timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(pkt.data.as_ref(), &[1, 2, 3, 4]);
    wait_until(|| {
        let snap = c.table.snapshot();
        snap.sessions[0].bytes_downloaded == 4
    })
    .await;
}

// ---------- 超时回收（MockClock 确定性） ----------

#[tokio::test]
async fn sweep_session_idle_expiry_boundary() {
    let c = make_table(|cfg| {
        cfg.session_idle = Duration::from_secs(180);
        cfg.mapping_idle = Duration::from_secs(60);
    })
    .await;
    let key = UdpSessionKey::new(addr(45000));
    let t = udp_target("s.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (relay, _tx) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, relay).await.unwrap();

    // 边界内（idle == 180 不回收，严格大于才回收）
    c.clock.advance(180);
    let st = sweep_once(&c.table);
    assert_eq!(st.sessions_expired, 0);
    assert_eq!(c.table.snapshot().sessions_active, 1);

    // 超限 1s → 会话连带映射回收（映射 idle 61>60 先触发一次，会话再触发一次：
    // expired["idle"] = 映射 1 + 会话 1 = 2）
    c.clock.advance(1);
    let st = sweep_once(&c.table);
    assert_eq!(st.sessions_expired, 1);
    let snap = c.table.snapshot();
    assert_eq!(snap.sessions_active, 0);
    assert_eq!(snap.mappings_active, 0);
    assert_eq!(snap.expired.get("idle"), Some(&2));
    // 同键再包 → 新会话
    assert!(c.table.resolve(&key, &t).await.is_ok());
    assert_eq!(c.table.snapshot().sessions_total, 2);
}

#[tokio::test]
async fn sweep_mapping_idle_expiry_keeps_session() {
    let c = make_table(|cfg| {
        cfg.mapping_idle = Duration::from_secs(60);
    })
    .await;
    let key = UdpSessionKey::new(addr(46000));
    let t1 = udp_target("a.test", 1);
    let t2 = udp_target("b.test", 2);
    let sref = c.table.resolve(&key, &t1).await.unwrap();
    let (r1, _x) = MockUdpRelay::new(t1.clone());
    let (r2, _x) = MockUdpRelay::new(t2.clone());
    sref.bind_mapping(&t1, r1).await.unwrap();
    // 错开绑定时间：t1 先绑 30s 后绑 t2
    c.clock.advance(30);
    sref.bind_mapping(&t2, r2).await.unwrap();

    // 再过 31s：t1 idle 61 > 60 过期；t2 idle 31 存活
    c.clock.advance(31);
    let st = sweep_once(&c.table);
    assert_eq!(st.mappings_expired, 1);
    assert_eq!(st.sessions_expired, 0);
    assert!(!sref.has_mapping(&t1));
    assert!(sref.has_mapping(&t2));
    assert_eq!(c.table.snapshot().sessions_active, 1);
}

#[tokio::test]
async fn sweep_session_lifetime_expiry() {
    let c = make_table(|cfg| {
        cfg.session_idle = Duration::from_secs(180);
        cfg.session_max_lifetime = Some(Duration::from_secs(300));
    })
    .await;
    let key = UdpSessionKey::new(addr(47000));
    let t = udp_target("long.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();

    // 持续活跃（每 50s 刷新 idle），300s 寿命到点即回收
    for _ in 0..6 {
        c.clock.advance(50);
        sweep_once(&c.table);
        let sref2 = c.table.get(&key).unwrap();
        sref2.touch(c.clock.now_epoch());
    }
    c.clock.advance(1);
    let st = sweep_once(&c.table);
    assert_eq!(st.sessions_expired, 1);
    assert_eq!(c.table.snapshot().expired.get("lifetime"), Some(&1));
}

#[tokio::test]
async fn spawned_reclaimer_sweeps_then_stops_on_shutdown() {
    let c = make_table(|cfg| {
        cfg.sweep_interval = Duration::from_millis(30);
    })
    .await;
    let key = UdpSessionKey::new(addr(48000));
    let t = udp_target("r.test", 1);
    c.table.resolve(&key, &t).await.unwrap();
    let handle = c.table.spawn_reclaimer();
    c.clock.advance(181);
    wait_until(|| c.table.snapshot().sessions_active == 0).await;
    c.table.shutdown();
    handle.await.unwrap();
}

// ---------- 容量与 LRU ----------

#[tokio::test]
async fn capacity_rejects_new_sessions_never_evicts_live() {
    let c = make_table(|cfg| cfg.max_sessions = 2).await;
    let t = udp_target("c.test", 1);
    let k1 = UdpSessionKey::new(addr(1));
    let k2 = UdpSessionKey::new(addr(2));
    let k3 = UdpSessionKey::new(addr(3));
    c.table.resolve(&k1, &t).await.unwrap();
    c.table.resolve(&k2, &t).await.unwrap();
    match c.table.resolve(&k3, &t).await {
        Err(ResolveError::CapacityLimited(2)) => {}
        Err(e) => panic!("期望 CapacityLimited(2)，实际 {e}"),
        Ok(_) => panic!("期望 CapacityLimited(2)，实际建会话成功"),
    }
    // 拒新不逐旧：已有会话仍可解析复用
    assert!(c.table.resolve(&k1, &t).await.is_ok());
    let snap = c.table.snapshot();
    assert_eq!(snap.sessions_active, 2);
    assert_eq!(snap.dropped.get("session_limit"), Some(&1));
}

#[tokio::test]
async fn mapping_overflow_evicts_least_recently_used() {
    let c = make_table(|cfg| cfg.max_mappings = 2).await;
    let key = UdpSessionKey::new(addr(49000));
    let t1 = udp_target("m1.test", 1);
    let t2 = udp_target("m2.test", 2);
    let t3 = udp_target("m3.test", 3);
    let sref = c.table.resolve(&key, &t1).await.unwrap();
    let (r1, _x) = MockUdpRelay::new(t1.clone());
    let (r2, _x) = MockUdpRelay::new(t2.clone());
    let (r3, _x) = MockUdpRelay::new(t3.clone());
    sref.bind_mapping(&t1, r1).await.unwrap();
    c.clock.advance(10);
    sref.bind_mapping(&t2, r2).await.unwrap();
    c.clock.advance(10); // t1 最久未动
    sref.bind_mapping(&t3, r3).await.unwrap();

    // 上界 2：t3 挤掉最久空闲的 t1
    assert!(!sref.has_mapping(&t1));
    assert!(sref.has_mapping(&t2));
    assert!(sref.has_mapping(&t3));
    assert_eq!(c.table.snapshot().mappings_active, 2);
}

// ---------- 粘滞决策：失效 / 重路由 / 链路吊销 ----------

#[tokio::test]
async fn chain_failure_invalidates_decision_and_revokes_mappings() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(50000));
    let t = udp_target("f.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    assert_eq!(c.router.calls(), 1);
    let (r, _x) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();
    assert!(sref.decision().is_some());

    // 无关链路：决策与映射均不受影响
    let n = c.table.handle_chain_failure(&ChainFailureEvent {
        chain_id: "direct:other-node".into(),
        failed_nodes: vec!["other-node".into()],
    });
    assert_eq!(n, 0);
    assert!(sref.decision().is_some());
    assert!(sref.has_mapping(&t));

    // 所在链故障：决策置 None + 映射吊销 + 台账记账
    let n = c.table.handle_chain_failure(&ChainFailureEvent {
        chain_id: format!("direct:{NODE_A}"),
        failed_nodes: vec![NODE_A.into()],
    });
    assert_eq!(n, 1);
    assert!(sref.decision().is_none());
    assert!(!sref.has_mapping(&t));
    assert_eq!(sref.ledger().status(), SessionStatus::Failed);

    // 下一包触发重路由（路由调用 +1，reroutes 指标 +1）
    let sref2 = c.table.resolve(&key, &t).await.unwrap();
    assert_eq!(c.router.calls(), 2);
    assert_eq!(c.table.snapshot().reroutes, 1);
    assert!(sref2.decision().is_some());
    // 新链可重新绑定
    let (r2, _x) = MockUdpRelay::new(t.clone());
    assert_eq!(
        sref2.bind_mapping(&t, r2).await.unwrap(),
        seep_core::udp::BindOutcome::Created
    );
}

#[tokio::test]
async fn ledger_failed_session_recovers_on_next_packet() {
    // O7：UDP 链路故障可退化——Failed 会话收到新包恢复 Active
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(51000));
    let t = udp_target("o7.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    sref.ledger().on_error(FailureType::Connection);
    assert_eq!(sref.ledger().status(), SessionStatus::Failed);
    let (r, _x) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();
    let res = sref.send_up(&t, Bytes::from_static(b"ok")).await;
    assert_eq!(res, seep_core::udp::UpResult::Sent);
    assert_eq!(sref.ledger().status(), SessionStatus::Active);
}

// ---------- force_revoke 与关停 ----------

#[tokio::test]
async fn force_revoke_closes_mappings_and_reports_missing() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(52000));
    let t = udp_target("v.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();

    assert!(c.table.force_revoke(&key));
    assert!(!c.table.force_revoke(&key)); // 二次吊销：不存在
    let snap = c.table.snapshot();
    assert_eq!(snap.sessions_active, 0);
    assert_eq!(snap.mappings_active, 0);
    assert_eq!(snap.expired.get("revoked"), Some(&1));
}

#[tokio::test]
async fn shutdown_drops_uplink_and_rejects_resolve() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(53000));
    let t = udp_target("sd.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();

    c.table.shutdown();
    let res = c.table.forward_up(&key, &t, Bytes::from_static(b"x")).await;
    assert_eq!(
        res,
        seep_core::udp::UpResult::Dropped { reason: DropReason::ShuttingDown }
    );
    assert!(matches!(
        c.table.resolve(&key, &t).await,
        Err(ResolveError::Route(_))
    ));
}

// ---------- 发送失败与下行满载 ----------

#[tokio::test]
async fn route_failure_revokes_mapping_and_clears_decision() {
    // §3.6：路由不可达 → 映射关闭 + 决策缓存清除（触发重路由）
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(54000));
    let t = udp_target("sf.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    r.fail_route(true);
    sref.bind_mapping(&t, r).await.unwrap();
    assert!(sref.decision().is_some());

    let res = sref.send_up(&t, Bytes::from_static(b"x")).await;
    assert_eq!(res, seep_core::udp::UpResult::Dropped { reason: DropReason::SendFailed });
    wait_until(|| !sref.has_mapping(&t)).await;
    assert!(sref.decision().is_none());
    assert_eq!(c.table.snapshot().dropped.get("send_failed"), Some(&1));
    // 错误分类："mock route failure" → Route 记账（Failed）
    wait_until(|| sref.ledger().status() == SessionStatus::Failed).await;
}

#[tokio::test]
async fn timeout_failure_keeps_mapping() {
    // §3.6：目标超时/不可达 → record_failure，映射保留待空闲回收
    //（游戏服务器"不回首个包"探测不被立即拆映射）
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(54100));
    let t = udp_target("to.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    r.fail_timeout(true);
    sref.bind_mapping(&t, r.clone()).await.unwrap();

    for _ in 0..3 {
        let res = sref.send_up(&t, Bytes::from_static(b"x")).await;
        assert_eq!(res, seep_core::udp::UpResult::Dropped { reason: DropReason::SendFailed });
    }
    sleep(Duration::from_millis(50)).await;
    assert!(sref.has_mapping(&t), "timeout 类失败不应拆映射");
    assert_eq!(c.table.snapshot().dropped.get("send_failed"), Some(&3));
    // 恢复后同一映射继续可用
    r.clear_failures();
    assert_eq!(sref.send_up(&t, Bytes::from_static(b"ok")).await, seep_core::udp::UpResult::Sent);
}

#[tokio::test]
async fn connection_failures_rebuild_mapping_after_three() {
    // §3.6：传输 IO 错误连续 ≥3 次触发映射重建；成功归零计数
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(54200));
    let t = udp_target("cn.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    r.fail_sends(true);
    sref.bind_mapping(&t, r).await.unwrap();

    for i in 1..=2 {
        let _ = sref.send_up(&t, Bytes::from_static(b"x")).await;
        sleep(Duration::from_millis(30)).await;
        assert!(sref.has_mapping(&t), "第 {i} 次连接类失败不应拆映射");
    }
    let _ = sref.send_up(&t, Bytes::from_static(b"x")).await; // 第 3 次
    wait_until(|| !sref.has_mapping(&t)).await;
}

#[tokio::test]
async fn success_resets_consecutive_error_count() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(54300));
    let t = udp_target("rs.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    r.fail_sends(true);
    sref.bind_mapping(&t, r.clone()).await.unwrap();

    let _ = sref.send_up(&t, Bytes::from_static(b"x")).await;
    let _ = sref.send_up(&t, Bytes::from_static(b"x")).await;
    r.clear_failures();
    assert_eq!(sref.send_up(&t, Bytes::from_static(b"ok")).await, seep_core::udp::UpResult::Sent);
    // 成功归零：再连挂 2 次仍不拆，第 3 次才拆
    r.fail_sends(true);
    let _ = sref.send_up(&t, Bytes::from_static(b"x")).await;
    let _ = sref.send_up(&t, Bytes::from_static(b"x")).await;
    sleep(Duration::from_millis(30)).await;
    assert!(sref.has_mapping(&t));
    let _ = sref.send_up(&t, Bytes::from_static(b"x")).await;
    wait_until(|| !sref.has_mapping(&t)).await;
}

#[tokio::test]
async fn downlink_full_is_counted_dropped() {
    let c = make_table(|cfg| cfg.downlink_capacity = 1).await;
    let key = UdpSessionKey::new(addr(55000));
    let t = udp_target("df.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, tx) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();
    let _rx = sref.take_downlink_rx().await; // 无人消费 → 通道容量 1

    tx.send(vec![1]).await.unwrap();
    tx.send(vec![2]).await.unwrap(); // 第二包触发 DownlinkFull
    wait_until(|| c.table.snapshot().dropped.get("downlink_full") == Some(&1)).await;
}

// ---------- 并发契约 ----------

#[tokio::test]
async fn concurrent_bind_same_target_yields_single_mapping() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(56000));
    let t = udp_target("cc.test", 1);
    let sref = Arc::new(c.table.resolve(&key, &t).await.unwrap());
    let (r1, _x) = MockUdpRelay::new(t.clone());
    let (r2, _x) = MockUdpRelay::new(t.clone());
    let a = {
        let sref = sref.clone();
        let t = t.clone();
        tokio::spawn(async move { sref.bind_mapping(&t, r1).await })
    };
    let b = {
        let sref = sref.clone();
        tokio::spawn(async move { sref.bind_mapping(&t, r2).await })
    };
    let (ra, rb) = tokio::join!(a, b);
    let outcomes = [ra.unwrap().unwrap(), rb.unwrap().unwrap()];
    // 一个 Created、一个 Reused；映射总数恒为 1
    assert_eq!(outcomes.iter().filter(|o| **o == seep_core::udp::BindOutcome::Created).count(), 1);
    assert_eq!(outcomes.iter().filter(|o| **o == seep_core::udp::BindOutcome::Reused).count(), 1);
    assert_eq!(c.table.snapshot().mappings_active, 1);
}

#[tokio::test]
async fn concurrent_forward_up_no_race() {
    let c = make_table(|_| {}).await;
    let t = udp_target("load.test", 1);
    let mut handles = Vec::new();
    // mock relay 的下行 tx 保活到快照之后：tx 一 drop forwarder 就拆映射
    let mut txs = Vec::new();
    for i in 0..32u16 {
        let table = c.table.clone();
        let t = t.clone();
        let (r, tx) = MockUdpRelay::new(t.clone());
        txs.push(tx);
        handles.push(tokio::spawn(async move {
            let key = UdpSessionKey::new(addr(60000 + i));
            let sref = table.resolve(&key, &t).await.unwrap();
            sref.bind_mapping(&t, r).await.unwrap();
            assert_eq!(sref.send_up(&t, Bytes::from_static(b"z")).await, seep_core::udp::UpResult::Sent);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let snap = c.table.snapshot();
    assert_eq!(snap.sessions_active, 32);
    assert_eq!(snap.mappings_active, 32);
    drop(txs);
}

// ---------- ledger 直测（SessionLedger 单写语义） ----------

#[test]
fn ledger_packet_accounting_and_o7_recovery() {
    let id = FlowId::new();
    let led = SessionLedger::create(id);
    assert_eq!(led.status(), SessionStatus::Initializing);
    led.on_packet(Dir::Up, 100);
    led.on_packet(Dir::Down, 50);
    led.on_packet(Dir::Up, 10);
    let u = led.usage();
    assert_eq!(u.bytes_uploaded, 110);
    assert_eq!(u.bytes_downloaded, 50);
    assert_eq!(u.packets_count, 3);
    assert_eq!(led.status(), SessionStatus::Active);

    led.on_error(FailureType::Timeout);
    assert_eq!(led.status(), SessionStatus::Failed);
    led.on_packet(Dir::Up, 1); // O7：新包恢复
    assert_eq!(led.status(), SessionStatus::Active);
}

#[test]
fn ledger_link_failure_only_for_attached_chain() {
    let led = SessionLedger::create(FlowId::new());
    // 未 attach：链路故障不影响
    assert!(led
        .on_link_failure("direct:x", &[("x".to_string())])
        .is_none());
    led.attach_chain("direct:x");
    let nodes = led.on_link_failure("direct:x", &["x".to_string()]);
    assert_eq!(nodes, Some(vec!["x".to_string()]));
    assert_eq!(led.status(), SessionStatus::Failed);
}

// ---------- 辅助：chain_id 口径 ----------

#[tokio::test]
async fn chain_id_matches_direct_decision() {
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(57000));
    let t = udp_target("cid.test", 1);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, r).await.unwrap();
    // direct:node-a 与 handle_chain_failure 的链 ID 口径一致（P0-2 runtime 对齐）
    let n = c.table.handle_chain_failure(&ChainFailureEvent {
        chain_id: "direct:node-a".into(),
        failed_nodes: vec![NODE_A.into()],
    });
    assert_eq!(n, 1);
    assert!(sref.decision().is_none());
}

// 防止未使用告警（mpsc 在部分测试中仅保 type 标注）
#[allow(dead_code)]
fn _unused(_tx: mpsc::Sender<()>) {}

// ---------- P0-5 S1：表级字节聚合 ----------

#[tokio::test]
async fn table_bytes_aggregate_tracks_mappings() {
    // §10-S1 测试 1：单会话上下行若干包后表级 bytes_up/down == per-mapping
    // 快照求和；并发写终值一致
    let c = make_table(|_| {}).await;
    let key = UdpSessionKey::new(addr(58000));
    let t = udp_target("bytes.test", 53);
    let sref = c.table.resolve(&key, &t).await.unwrap();
    let (relay, tx) = MockUdpRelay::new(t.clone());
    sref.bind_mapping(&t, relay).await.unwrap();

    // 上行 5+7+9 字节
    for payload in [Bytes::from_static(b"12345"), Bytes::from_static(b"1234567"), Bytes::from_static(b"123456789")] {
        assert_eq!(
            c.table.forward_up(&key, &t, payload).await,
            seep_core::udp::UpResult::Sent
        );
    }
    // 下行 4+6 字节（forwarder 异步计数）
    tx.send(vec![1, 2, 3, 4]).await.unwrap();
    tx.send(vec![1, 2, 3, 4, 5, 6]).await.unwrap();
    wait_until(|| c.table.snapshot().bytes_down == 10).await;

    let snap = c.table.snapshot();
    assert_eq!(snap.bytes_up, 21, "表级上行 = per-mapping 求和");
    assert_eq!(snap.bytes_down, 10, "表级下行 = per-mapping 求和");
    assert_eq!(snap.sessions[0].bytes_uploaded, 21);
    assert_eq!(snap.sessions[0].bytes_downloaded, 10);

    // 并发写：8 任务 × 50 包 × 10 字节（不同粘滞键各自建会话），终值一致
    let mut tasks = Vec::new();
    for i in 0..8u16 {
        let table = Arc::clone(&c.table);
        tasks.push(tokio::spawn(async move {
            let key = UdpSessionKey::new(addr(58100 + i));
            let t = udp_target("conc.test", 53);
            let sref = table.resolve(&key, &t).await.unwrap();
            let (relay, _tx) = MockUdpRelay::new(t.clone());
            sref.bind_mapping(&t, relay).await.unwrap();
            for _ in 0..50 {
                let data = vec![0u8; 10].into();
                assert_eq!(table.forward_up(&key, &t, data).await, seep_core::udp::UpResult::Sent);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let snap = c.table.snapshot();
    assert_eq!(snap.bytes_up, 21 + 8 * 50 * 10, "并发终值 = 单会话 + 并发总量");
    let per_session_sum: u64 = snap.sessions.iter().map(|s| s.bytes_uploaded).sum();
    assert_eq!(snap.bytes_up, per_session_sum, "表级与 per-mapping 快照一致");
}
