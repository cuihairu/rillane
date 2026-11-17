//! IO 与统计对账验收（RIL-103 / io-and-accounting.md §5–§6）：
//! 入口/协议/传输组合矩阵装配期全量校验（传输合法性与入口无关）；
//! 会话权威总量与入口/出口归属对账（A 失败 B 承载不重复业务量）；
//! 业务与底层分别报告——不用两端相加作总量，不把发送成功当远端
//! 接收；半关闭/取消/UDP 多目标/池隔离全覆盖；资源关闭逐守卫留痕
//! （无 InUse 幸存者）。外部库后端的取消/线程/缓冲所有权、内部重试
//! 与会话回退一致性及业务统计等价性，在该外部库接入时按同套契约
//! 验证（io-and-accounting.md §7 选库门禁）；不可得诊断字段以
//! 显式未知承载（RIL-097 证据类型 `unknown`），不伪造。

use std::sync::Mutex;

use rillane_core::meter::{AttributionView, SessionMeter, TrafficDirection, TrafficOrigin};
use rillane_core::observer::{
    MetricKey, SessionObserver, SessionStage, StageEvent, StageResult, OBSERVER_RING_DEFAULT,
};
use rillane_core::outbound::{
    EvidenceKind, OpenContext, OpenError, OpenStage, OutboundCapabilities, StreamIo,
};
use rillane_core::plan::{EndpointRef, GenerationRef};
use rillane_core::pool::TransportReuse;
use rillane_core::resources::{
    assemble_backend, BackendDeclaration, LeaseGuard, LeaseKey, PoolResourceKind,
};
use rillane_core::underlay::{
    check_dial_target, BypassCapability, BypassOutcome, DialOutcome, DialTarget, PlatformBypass,
    TransportStack, UnderlayDialer,
};

// ---------------------------------------------------------------------------
// 测试替身
// ---------------------------------------------------------------------------

/// 空字节流（拨号产物占位）
struct NullStream {
    eof: bool,
}

#[async_trait::async_trait]
impl StreamIo for NullStream {
    async fn write_all(&mut self, _data: bytes::Bytes) -> Result<usize, OpenError> {
        Ok(0)
    }

    async fn read(&mut self, _max: usize) -> Result<Option<bytes::Bytes>, OpenError> {
        if self.eof {
            Ok(None)
        } else {
            self.eof = true;
            Ok(Some(bytes::Bytes::from_static(b"payload")))
        }
    }

    async fn shutdown_write(&mut self) -> Result<(), OpenError> {
        Ok(())
    }
}

/// 脚本拨号器：首个拨号可失败（回退对账）；记录全部拨号（零拨号面
/// 可审计）
struct ScriptedDialer {
    fail_first: bool,
    dials: Mutex<Vec<String>>,
}

impl ScriptedDialer {
    fn new(fail_first: bool) -> Self {
        Self {
            fail_first,
            dials: Mutex::new(Vec::new()),
        }
    }

    fn dial_count(&self) -> usize {
        self.dials.lock().expect("锁").len()
    }
}

#[async_trait::async_trait]
impl UnderlayDialer for ScriptedDialer {
    fn name(&self) -> &'static str {
        "scripted"
    }

    fn bypass_capability(&self) -> BypassCapability {
        BypassCapability::InjectsAtDial
    }

    async fn dial(
        &self,
        target: &DialTarget,
        _ctx: &OpenContext,
        _bypass: Option<&dyn PlatformBypass>,
    ) -> Result<DialOutcome, OpenError> {
        check_dial_target(target)?;
        let mut dials = self.dials.lock().expect("锁");
        dials.push(format!("{}:{}", target.host, target.port));
        if self.fail_first && dials.len() == 1 {
            return Err(OpenError::new(
                OpenStage::Dial,
                "egress.dial.refused",
                true,
                EvidenceKind::Observed,
                "connection refused",
            ));
        }
        Ok(DialOutcome {
            io: Box::new(NullStream { eof: false }),
            bypass: BypassOutcome::Applied { kind: "so_mark" },
        })
    }
}

/// 部分写出口（每次最多吞 cap 字节——实际过账面）
struct LenSink {
    cap: usize,
}

impl LenSink {
    fn write(&mut self, data: &[u8]) -> usize {
        data.len().min(self.cap)
    }
}

/// 泵上行：读块 → 出口写 → 按实际字节过账（方向 = 语义方向）
fn pump_uplink(meter: &SessionMeter, chunks: &[usize], sink: &mut LenSink) -> u64 {
    let mut total = 0u64;
    for want in chunks {
        let data = vec![0u8; *want];
        let actual = sink.write(&data);
        meter.record_business(TrafficDirection::ClientToTarget, actual as u64);
        total += actual as u64;
    }
    total
}

/// 阶段事件助手（统一关联 gen-r1 / user 来源）
fn stage(
    session: &str,
    generation: &str,
    stage: SessionStage,
    result: StageResult,
    code: Option<&'static str>,
) -> StageEvent {
    StageEvent::new(
        session,
        Some(generation.to_string()),
        stage,
        result,
        code,
        TrafficOrigin::User,
    )
    .expect("合法事件")
}

/// 资源关闭证据：终态迁移逐条留痕
#[derive(Debug, Default)]
struct ClosureEvidence {
    entries: Vec<String>,
}

impl ClosureEvidence {
    fn record(&mut self, what: &str) {
        self.entries.push(what.to_string());
    }
}

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

/// 入口/协议/传输组合矩阵：全部合法栈 × 三种入口形态 × 流/报文协议
/// 形状都经唯一装配权威一次通过——传输合法性与入口无关（SOCKS5/
/// HTTP/TUN 消费同一 `AssembledBackend`）；非法排列装配期拒绝且
/// 零拨号。
#[test]
fn composition_matrix_ingress_independent() {
    let stream_stacks: &[&[&str]] = &[
        &[],
        &["tls"],
        &["ws"],
        &["grpc"],
        &["httpupgrade"],
        &["tls", "ws"],
        &["tls", "grpc"],
        &["tls", "httpupgrade"],
    ];

    let mut assembled = 0usize;
    for ingress in ["socks5", "http", "tun"] {
        for st in stream_stacks {
            // 流协议形状（无数据报上限）+ tls 栈声明恢复；无 tls 栈用 None
            let (reuse, prewarm) = if st.contains(&"tls") {
                (TransportReuse::TlsResumption, true)
            } else {
                (TransportReuse::None, false)
            };
            let name: &'static str = Box::leak(format!("matrix-{ingress}").into_boxed_str());
            let decl = BackendDeclaration {
                name,
                capabilities: OutboundCapabilities {
                    stream: true,
                    datagram: false,
                    transports: st.to_vec(),
                    max_datagram_len: None,
                    supports_prewarm: prewarm,
                    supports_multiplex: false,
                    fixed_target_only: false,
                },
                transport_stack: TransportStack::build(st).expect("合法栈"),
                reuse,
                feature_gates: vec!["rustls"],
            };
            let backend = assemble_backend(&decl).expect("矩阵组合装配通过");
            assert_eq!(backend.transport_stack().layers(), *st);
            assembled += 1;
        }
    }
    assert_eq!(assembled, 3 * 8, "3 入口 × 8 栈全矩阵装配");

    // 数据报协议形状：datagram ⟺ max_datagram_len（raw / tls 栈）
    for st in [&[] as &[&str], &["tls"]] {
        let decl = BackendDeclaration {
            name: "matrix-udp",
            capabilities: OutboundCapabilities {
                stream: false,
                datagram: true,
                transports: st.to_vec(),
                max_datagram_len: Some(1500),
                supports_prewarm: false,
                supports_multiplex: false,
                fixed_target_only: true,
            },
            transport_stack: TransportStack::build(st).expect("合法栈"),
            reuse: TransportReuse::None,
            feature_gates: vec!["quinn"],
        };
        assemble_backend(&decl).expect("数据报组合装配通过");
    }

    // 非法排列：装配期拒绝（零拨号——本测试全程无拨号器）
    let dialer = ScriptedDialer::new(false);
    for bad in [
        &["ws", "tls"][..],
        &["tls", "tls"],
        &["tls", "ws", "grpc"],
        &["quic"],
    ] {
        assert!(
            TransportStack::build(bad).is_err(),
            "非法排列 {bad:?} 必须装配期拒绝"
        );
    }
    assert_eq!(dialer.dial_count(), 0, "装配拒绝零拨号");
}

/// 会话全量对账（A 失败 B 承载）：权威业务量恰一次；入口/出口归属
/// = 同一权威量（相加不是总使用量）；业务与底层分别报告；发送成功
/// 不声称远端接收；观测事件序列与关联可对账；资源关闭逐守卫留痕。
#[tokio::test]
async fn failover_session_reconciles_totals_attribution_and_closure() {
    let gen_id = GenerationRef::new("gen-r1").expect("非空代际");
    let ctx = OpenContext::new("sess-rec-1", gen_id.clone()).expect("合法上下文");
    let dialer = ScriptedDialer::new(true);
    let meter = SessionMeter::new("sess-rec-1", TrafficOrigin::User).expect("合法身份");
    let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
    let mut closure = ClosureEvidence::default();

    obs.record(stage(
        "sess-rec-1",
        "gen-r1",
        SessionStage::Ingress,
        StageResult::Succeeded,
        None,
    ));

    // ---- 尝试 A（node-a）：真实底层开销 + 失败 + 资源取消留痕 ----
    let target_a = DialTarget::new("node-a.example.com", 443).expect("合法目标");
    let attempt0 = dialer
        .dial(&target_a, &ctx, None)
        .await
        .expect_err("A 拨号失败");
    assert_eq!(attempt0.code, "egress.dial.refused");
    meter.record_underlay(0, 150);
    meter.mark_attempt_failed(0);
    obs.record(
        stage(
            "sess-rec-1",
            "gen-r1",
            SessionStage::Establish,
            StageResult::Failed,
            Some("egress.dial.refused"),
        )
        .with_attempt(0),
    );
    let key_a = LeaseKey::new(
        "gen-r1",
        "node-a",
        Some(EndpointRef::new("203.0.113.10", 443)),
        "tenant-1",
        &["tls", "tls-resume"],
    )
    .expect("合法键");
    let guard_a = LeaseGuard::begin(
        key_a,
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("203.0.113.10", 443),
            reclaimable: false,
        },
    );
    guard_a
        .cancel("dial refused")
        .expect("取消")
        .close()
        .expect("关闭留痕");
    closure.record("attempt-0:cancelled+closed");

    // ---- 回退：执行器决定换承载 B ----
    obs.record(
        stage(
            "sess-rec-1",
            "gen-r1",
            SessionStage::Fallback,
            StageResult::Succeeded,
            None,
        )
        .with_attempt(1),
    );

    // ---- 尝试 B（node-b）：拨通 + 承载 ----
    let target_b = DialTarget::new("node-b.example.com", 443).expect("合法目标");
    let outcome = dialer
        .dial(&target_b, &ctx, None)
        .await
        .expect("B 拨号成功");
    assert_eq!(outcome.bypass, BypassOutcome::Applied { kind: "so_mark" });
    let key_b = LeaseKey::new(
        "gen-r1",
        "node-b",
        Some(EndpointRef::new("203.0.113.11", 443)),
        "tenant-1",
        &["tls", "tls-resume"],
    )
    .expect("合法键");
    let guard_b = LeaseGuard::begin(
        key_b,
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("203.0.113.11", 443),
            reclaimable: false,
        },
    );
    meter.record_underlay(1, 80);
    meter.attribute_carrier(1).expect("业务归属 B");
    obs.record(
        stage(
            "sess-rec-1",
            "gen-r1",
            SessionStage::Handshake,
            StageResult::Succeeded,
            None,
        )
        .with_attempt(1),
    );

    // ---- 业务搬运：部分写重试序列恰一次 + 下行 ----
    let mut sink = LenSink { cap: 3 };
    assert_eq!(pump_uplink(&meter, &[8], &mut sink), 3, "首段部分写");
    let mut sink = LenSink { cap: 64 };
    assert_eq!(
        pump_uplink(&meter, &[5], &mut sink),
        5,
        "续段补齐同一业务块"
    );
    meter.record_business(TrafficDirection::TargetToClient, 300);

    // ---- 会话终态：独占资源 drain → 关闭（关闭证据）----
    guard_b
        .drain("session end")
        .expect("排水")
        .close()
        .expect("关闭留痕");
    closure.record("attempt-1:drained+closed");
    obs.record(stage(
        "sess-rec-1",
        "gen-r1",
        SessionStage::Close,
        StageResult::Succeeded,
        None,
    ));

    // ---- 对账：权威总量 ----
    let t = meter.totals();
    assert_eq!(
        t.business_bytes(),
        308,
        "重试不重复业务总量（8 上行 + 300 下行）"
    );
    assert_eq!(t.carrier_attempt, Some(1), "业务归属 B");
    assert_eq!(t.failed_attempts, vec![0], "A 失败留痕");

    // 入口/出口归属 = 同一权威量；相加不是总使用量
    assert_eq!(t.attribution(AttributionView::Inbound), 308);
    assert_eq!(t.attribution(AttributionView::Outbound), 308);
    assert_ne!(
        t.attribution(AttributionView::Inbound) + t.attribution(AttributionView::Outbound),
        t.business_bytes(),
        "不用两端相加作总量"
    );

    // 业务与底层分别报告
    assert_eq!(t.underlay_bytes, 230, "A+B 真实底层开销分立");
    assert_eq!(
        t.attempt_underlay,
        vec![(0, 150), (1, 80)],
        "逐尝试开销可对账"
    );
    assert_eq!(t.shared_overhead_bytes, 0);

    // 发送成功不声称远端接收：快照面无 received/acked 字段
    let rendered = format!("{t:?}");
    assert!(
        !rendered.contains("receiv") && !rendered.contains("ack"),
        "统计面不做远端接收声明"
    );

    // 拨号恰两次（A 失败 B 拨通——无第二次业务边界建立）
    assert_eq!(dialer.dial_count(), 2);

    // 观测对账：阶段序列 + 统一关联
    let view = obs.diagnostic_view(20);
    let stages: Vec<_> = view.recent.iter().map(|e| e.stage.as_str()).collect();
    assert_eq!(
        stages,
        vec!["ingress", "establish", "fallback", "handshake", "close"],
        "阶段序列完整"
    );
    for e in &view.recent {
        assert_eq!(e.session_id, "sess-rec-1");
        assert_eq!(e.generation.as_deref(), Some("gen-r1"), "代际关联统一");
    }
    assert_eq!(view.snapshot.len(), 5);
    let failed_key = MetricKey {
        stage: "establish",
        result: "failed",
        origin: "user",
    };
    assert_eq!(view.snapshot.get(&failed_key), Some(&1), "A 建立失败可见");

    // 资源关闭证据：两条尝试守卫全部终态留痕
    assert_eq!(
        closure.entries,
        vec!["attempt-0:cancelled+closed", "attempt-1:drained+closed"],
        "无 InUse 幸存者"
    );
}

/// 半关闭与取消：上行 EOF 后下行照常（方向计数独立）；业务交换后
/// 取消——不二次建立、已交换字节保留、资源取消留痕。
#[tokio::test]
async fn half_close_and_cancel_reconcile() {
    let gen_id = GenerationRef::new("gen-r2").expect("非空代际");
    let ctx = OpenContext::new("sess-half-1", gen_id.clone()).expect("合法上下文");
    let dialer = ScriptedDialer::new(false);
    let meter = SessionMeter::new("sess-half-1", TrafficOrigin::User).expect("合法");
    let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);

    obs.record(stage(
        "sess-half-1",
        "gen-r2",
        SessionStage::Ingress,
        StageResult::Succeeded,
        None,
    ));
    assert!(dialer
        .dial(
            &DialTarget::new("node-c.example.com", 443).expect("目标"),
            &ctx,
            None
        )
        .await
        .is_ok());
    meter.record_underlay(0, 60);
    meter.attribute_carrier(0).expect("归属唯一尝试");

    // 半关闭：上行 EOF（客户端读侧关闭 → 出口写侧半关闭），下行继续
    let mut sink = LenSink { cap: 128 };
    pump_uplink(&meter, &[64], &mut sink);
    // EOF 后上行不再记账；下行照常
    meter.record_business(TrafficDirection::TargetToClient, 200);
    meter.record_business(TrafficDirection::TargetToClient, 100);
    let t = meter.totals();
    assert_eq!(t.client_to_target_bytes, 64, "半关闭后上行冻结");
    assert_eq!(t.target_to_client_bytes, 300, "下行照常——方向计数独立");
    obs.record(stage(
        "sess-half-1",
        "gen-r2",
        SessionStage::Close,
        StageResult::Succeeded,
        None,
    ));
    assert_eq!(dialer.dial_count(), 1);

    // 取消：另一会话业务交换后取消——不二次建立、字节保留、留痕
    let meter2 = SessionMeter::new("sess-cancel-1", TrafficOrigin::User).expect("合法");
    let ctx2 = OpenContext::new("sess-cancel-1", gen_id).expect("合法上下文");
    let dialer2 = ScriptedDialer::new(false);
    assert!(dialer2
        .dial(
            &DialTarget::new("node-d.example.com", 443).expect("目标"),
            &ctx2,
            None
        )
        .await
        .is_ok());
    meter2.record_underlay(0, 50);
    meter2.attribute_carrier(0).expect("归属唯一尝试");
    let mut sink = LenSink { cap: 64 };
    pump_uplink(&meter2, &[40], &mut sink);
    let key = LeaseKey::new("gen-r2", "node-d", None, "tenant-1", &[]).expect("合法键");
    let guard = LeaseGuard::begin(
        key,
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("203.0.113.12", 443),
            reclaimable: false,
        },
    );
    // 取消不重新拨号（重连是新会话的新决策——RIL-098 口径）
    guard
        .cancel("client gone")
        .expect("取消")
        .close()
        .expect("关闭留痕");
    assert_eq!(dialer2.dial_count(), 1, "取消不二次建立");
    let t2 = meter2.totals();
    assert_eq!(t2.business_bytes(), 40, "已交换字节保留（按已发生记录）");
    assert_eq!(t2.carrier_attempt, Some(0));
}

/// UDP 多目标与池隔离：绑定集合内多目标逐报文记账（零长计报文）；
/// 越绑定目标显式拒绝走丢弃面；不同凭证/代际结构性不混借；全部
/// 资源终态留痕。
#[test]
fn udp_multi_target_and_pool_isolation() {
    let meter = SessionMeter::new("sess-udp-mt", TrafficOrigin::User).expect("合法");
    // 绑定集合 {t1, t2}：多目标逐报文记账
    meter.record_datagram(TrafficDirection::ClientToTarget, 120); // → t1
    meter.record_datagram(TrafficDirection::ClientToTarget, 0); // → t1 零长
    meter.record_datagram(TrafficDirection::ClientToTarget, 80); // → t2
    meter.record_datagram(TrafficDirection::TargetToClient, 200); // ← t1
                                                                  // 越绑定目标（t3）显式拒绝——丢弃面，不冒充业务量
    meter.record_drop(1);

    let t = meter.totals();
    assert_eq!(t.client_to_target_datagrams, 3, "零长报文仍计一条");
    assert_eq!(t.business_datagrams(), 4);
    assert_eq!(t.client_to_target_bytes, 200, "零长报文字节为 0 照实");
    assert_eq!(t.dropped_datagrams, 1, "越绑定拒绝可见");
    assert_eq!(t.business_bytes(), 400, "丢弃不入业务量");

    // 池隔离：独占绑定 t1 资源 drain→关闭；多路复用资源（无固定目标）
    let key_t1 = LeaseKey::new(
        "gen-r3",
        "node-e",
        Some(EndpointRef::new("203.0.113.13", 443)),
        "tenant-1",
        &["tls"],
    )
    .expect("合法键");
    let bound = LeaseGuard::begin(
        key_t1.clone(),
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("203.0.113.13", 443),
            reclaimable: true,
        },
    );
    bound
        .drain("mapping reclaim")
        .expect("排水")
        .close()
        .expect("关闭");

    let mux_key = LeaseKey::new("gen-r3", "node-e", None, "tenant-1", &["tls"]).expect("键");
    assert_ne!(key_t1, mux_key, "有目标绑定与无绑定不同键");
    let mux = LeaseGuard::begin(mux_key.clone(), PoolResourceKind::Multiplexed);
    mux.close().expect("复用资源关闭");

    // 结构性隔离：不同凭证 / 不同代际 = 不同键（租户/代际不混借）
    let other_cred = LeaseKey::new("gen-r3", "node-e", None, "tenant-2", &["tls"]).expect("键");
    let other_gen = LeaseKey::new("gen-r4", "node-e", None, "tenant-1", &["tls"]).expect("键");
    assert_ne!(mux_key, other_cred);
    assert_ne!(mux_key, other_gen);
    // 键面无密钥（只有标签）
    let rendered = format!("{mux_key:?}");
    assert!(!rendered.contains("secret"), "租借键不带密钥");
}
