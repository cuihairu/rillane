//! 会话观测器契约（RIL-102）：统一 session/attempt/generation 关联的
//! 接入/建立/握手/回退/关闭低频事件；高频字节走计数器不逐读写分配
//! 事件；慢消费者与关闭观测不影响转发；高基数身份不进指标标签、只
//! 留有界尾环；CLI/MCP 复用同一诊断视图。

use rillane_core::{
    MetricKey, SessionMeter, SessionObserver, SessionStage, StageEvent, StageResult,
    TrafficDirection, TrafficOrigin, CODE_OBSERVER_EVENT, OBSERVER_RING_DEFAULT,
};

fn ev(
    session: &str,
    stage: SessionStage,
    result: StageResult,
    code: Option<&'static str>,
) -> StageEvent {
    StageEvent::new(
        session,
        Some("gen-c1".into()),
        stage,
        result,
        code,
        TrafficOrigin::User,
    )
    .expect("合法事件")
}

/// 一次含回退的会话生命周期：接入 → 建立 A 失败 → 回退 → 握手 B 成功
/// → 关闭——阶段序列完整可对账，逐尝试事件关联 attempt/generation。
#[test]
fn session_lifecycle_stages_correlate() {
    let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
    let sid = "sess-life-1";

    obs.record(ev(sid, SessionStage::Ingress, StageResult::Succeeded, None));
    obs.record(
        ev(
            sid,
            SessionStage::Establish,
            StageResult::Failed,
            Some("egress.dial.refused"),
        )
        .with_attempt(0),
    );
    obs.record(ev(sid, SessionStage::Fallback, StageResult::Succeeded, None).with_attempt(1));
    obs.record(ev(sid, SessionStage::Handshake, StageResult::Succeeded, None).with_attempt(1));
    obs.record(ev(sid, SessionStage::Close, StageResult::Succeeded, None));

    let view = obs.diagnostic_view(20);
    let stages: Vec<_> = view.recent.iter().map(|e| e.stage.as_str()).collect();
    assert_eq!(
        stages,
        vec!["ingress", "establish", "fallback", "handshake", "close"],
        "阶段序列完整"
    );
    // 统一关联：逐尝试事件携 attempt；全部事件携 session 与 generation
    let establish = &view.recent[1];
    assert_eq!(
        (establish.attempt_id, establish.result.as_str()),
        (Some(0), "failed")
    );
    assert_eq!(establish.code, Some("egress.dial.refused"));
    let fallback = &view.recent[2];
    assert_eq!(fallback.attempt_id, Some(1), "回退指向承载尝试 B");
    for e in &view.recent {
        assert_eq!(e.session_id, sid);
        assert_eq!(e.generation.as_deref(), Some("gen-c1"), "代际关联统一");
    }
    // A 失败 B 承载对账：失败与回退都可见，终态成功
    let snapshot = &view.snapshot;
    let failed = MetricKey {
        stage: "establish",
        result: "failed",
        origin: "user",
    };
    assert_eq!(snapshot.get(&failed), Some(&1), "A 的建立失败可见");
    assert_eq!(view.stats.events_recorded, 5);
}

/// 指标投影纯度：多会话/多代际高频事件后，快照键集仍是有界词汇积、
/// 不含任何 session/generation 身份——高基数只进受限尾环。
#[test]
fn metric_projection_is_identity_free_and_bounded() {
    let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
    for i in 0..40 {
        let sid = format!("tenant-{i}-domain-heavy-session-{i}");
        obs.record(ev(
            &sid,
            SessionStage::Ingress,
            StageResult::Succeeded,
            None,
        ));
        obs.record(
            ev(
                &sid,
                SessionStage::Handshake,
                StageResult::Failed,
                Some("tls.cert.invalid"),
            )
            .with_attempt(0),
        );
    }
    let snapshot = obs.snapshot();
    assert!(
        snapshot.len() <= 45,
        "键集 ≤ stage×result×origin 枚举积（实际 {}）",
        snapshot.len()
    );
    assert_eq!(snapshot.len(), 2, "同类事件归入同键");
    let rendered = format!("{snapshot:?}");
    assert!(
        !rendered.contains("tenant-") && !rendered.contains("domain-heavy"),
        "无高基数身份"
    );
    // 尾环（受限逐流视图）保留身份——有界
    let recent = obs.recent(5);
    assert_eq!(recent.len(), 5);
    assert!(recent.iter().all(|e| e.session_id.starts_with("tenant-")));
}

/// 转发隔离：观测器关闭或高驱逐运行时，泵循环的业务字节照常计数——
/// 统计状态从不反向影响数据面（record 是同步 try_lock 面，调用方
/// 不等待诊断；锁争用路径由单元测试持锁覆盖）。
#[test]
fn metering_survives_observer_states() {
    let meter = SessionMeter::new("sess-iso", TrafficOrigin::User).expect("合法");
    let off = SessionObserver::disabled();
    let hot = SessionObserver::new(2); // 极小容量——高频事件下持续驱逐

    for _ in 0..1_000 {
        meter.record_business(TrafficDirection::ClientToTarget, 16);
        off.record(ev("x", SessionStage::Ingress, StageResult::Succeeded, None));
        hot.record(ev("y", SessionStage::Ingress, StageResult::Succeeded, None));
    }
    assert_eq!(
        meter.totals().business_bytes(),
        16_000,
        "转发计数不受观测状态影响"
    );
    assert_eq!(off.stats().events_recorded, 0, "关闭态零入账");
    assert!(hot.stats().ring_evicted > 990, "高驱逐不影响入账纪律");
    assert_eq!(hot.stats().events_rejected, 0, "合法事件不被拒绝");
    assert_eq!(hot.recent(10).len(), 2, "尾环容量有界");
}

/// 事件纪律：非法事件（逐尝试缺 attempt/失败缺码/成功带码/空会话）
/// 被防御拒绝并计数——聚合不被污染；合法事件全数入账。
#[test]
fn invalid_events_are_counted_not_polluting() {
    let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
    obs.record(ev(
        "s-ok",
        SessionStage::Ingress,
        StageResult::Succeeded,
        None,
    ));
    // 结构体字面量绕过构造校验 → record 防御面兜底
    let no_attempt = StageEvent {
        session_id: "s-bad".into(),
        attempt_id: None,
        generation: None,
        stage: SessionStage::Establish,
        result: StageResult::Failed,
        code: Some("egress.dial.timeout"),
        origin: TrafficOrigin::User,
    };
    obs.record(no_attempt);
    let empty = StageEvent {
        session_id: String::new(),
        attempt_id: None,
        generation: None,
        stage: SessionStage::Close,
        result: StageResult::Succeeded,
        code: None,
        origin: TrafficOrigin::User,
    };
    obs.record(empty);
    let ok_with_code = StageEvent {
        session_id: "s-bad2".into(),
        attempt_id: None,
        generation: None,
        stage: SessionStage::Close,
        result: StageResult::Succeeded,
        code: Some("should.not.exist"),
        origin: TrafficOrigin::User,
    };
    obs.record(ok_with_code);
    // 构造面同样拒绝（失败缺码）
    let err = StageEvent::new(
        "s",
        None,
        SessionStage::Establish,
        StageResult::Rejected,
        None,
        TrafficOrigin::Probe,
    )
    .unwrap_err();
    assert_eq!(err.code, CODE_OBSERVER_EVENT);

    let stats = obs.stats();
    assert_eq!(stats.events_rejected, 3, "非法事件拒绝可见");
    assert_eq!(stats.events_recorded, 1, "合法事件入账");
    assert_eq!(obs.snapshot().len(), 1, "聚合不被污染");
}
