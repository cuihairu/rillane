//! RIL-055 逐连接查询服务验收：
//! - 活动/近期连接分页、过滤、流详情与事件读取；
//! - 超限/过期/未知/采样/订阅取走/追踪关闭的缺席逐码显式返回；
//! - 真实 `FlowId` 锚定——ingress/egress 聚合键不是流 ID，不会以
//!   聚合键命中任何流；
//! - 无记录时可查采集计数，缺席答复不给出「应用未发包」结论；
//! - 查询与订阅互不偷事件（订阅取走后查询显式回答 drained）。
//!
//! 直连采集器公共 API 钉契约；追踪器集成复用 RIL-053 埋点面。

use std::sync::{Arc, Mutex};

use rillane_core::collector::{
    CollectorConfig, FlowCollector, CODE_TRACE_GONE_ACTIVE_LIMIT, CODE_TRACE_GONE_DRAINED,
    CODE_TRACE_GONE_EVICTED, CODE_TRACE_GONE_EXPIRED,
};
use rillane_core::query::{
    FlowQueryFilter, FlowQueryService, FlowRecord, FlowState, ABSENT_NOTE, CODE_QUERY_FLOW_UNKNOWN,
    CODE_QUERY_PAGE_INVALID, CODE_QUERY_TRACING_DISABLED,
};
use rillane_core::trace::{FlowId, FlowOrigin, TraceStage};
use rillane_core::{EvidenceKind, SessionTracer, CODE_STREAM_CLOSED, CODE_TRACE_TAKEOVER};

fn collector(capacity: usize, active: usize, sample: u32) -> Arc<Mutex<FlowCollector>> {
    Arc::new(Mutex::new(FlowCollector::new(
        CollectorConfig::new(capacity, active, 64, 3_600_000, sample, true).expect("合法配置"),
    )))
}

fn admit(store: &Arc<Mutex<FlowCollector>>, flow: &str, wall: u64, stage: TraceStage) {
    let _ = store.lock().unwrap().admit(
        FlowId::new(flow).unwrap(),
        FlowOrigin::Stream,
        "gen-1",
        stage,
        "session.takeover",
        EvidenceKind::Observed,
        1_000,
        wall,
        "tcp 8.8.8.8:443",
    );
}

fn absent_code(record: FlowRecord) -> &'static str {
    match record {
        FlowRecord::Absent(absent) => {
            assert_eq!(absent.note, ABSENT_NOTE, "缺席答复带固定说明");
            absent.code
        }
        other => panic!("应显式缺席，得到 {other:?}"),
    }
}

/// ① 环形溢出逐出 → 显式 evicted；活动上限拒绝 → 显式 active_limit；
/// 两者都区别于「从未见过」
#[test]
fn evicted_and_active_limit_are_explicit() {
    // 容量 2：第三条新流准入时逐出最旧（f-1）
    let store = collector(2, 8, 1);
    admit(&store, "f-1", 1_000, TraceStage::Takeover);
    admit(&store, "f-2", 2_000, TraceStage::Takeover);
    admit(&store, "f-3", 3_000, TraceStage::Takeover);
    let service = FlowQueryService::new(store);

    assert_eq!(
        absent_code(service.flow(&FlowId::new("f-1").unwrap())),
        CODE_TRACE_GONE_EVICTED,
        "被顶掉的最旧迹显式回答 evicted"
    );
    match service.flow(&FlowId::new("f-3").unwrap()) {
        FlowRecord::Found(trace) => assert_eq!(trace.flow.as_str(), "f-3"),
        other => panic!("幸存迹应命中，得到 {other:?}"),
    }

    // 活动上限 1：第二条新流（仍活动）被拒绝准入
    let store = collector(8, 1, 1);
    admit(&store, "f-keep", 1_000, TraceStage::Takeover);
    admit(&store, "f-reject", 2_000, TraceStage::Takeover);
    let service = FlowQueryService::new(store);
    assert_eq!(
        absent_code(service.flow(&FlowId::new("f-reject").unwrap())),
        CODE_TRACE_GONE_ACTIVE_LIMIT,
        "活动上限拒绝流显式回答 active_limit"
    );
    assert_eq!(
        absent_code(service.flow(&FlowId::new("f-never").unwrap())),
        CODE_QUERY_FLOW_UNKNOWN,
        "从未见过的流是 unknown，不冒充其他缺席原因"
    );
}

/// ② TTL 过期 → 显式 expired；订阅取走 → 显式 drained（查询不偷
/// 订阅事件——取走后仍可对账去向）
#[test]
fn expired_and_drained_are_explicit() {
    // TTL 3_600_000ms：sweep 时钟越过 f-old 锚 + TTL，f-new 仍新鲜
    let store = collector(8, 8, 1);
    admit(&store, "f-old", 1_000, TraceStage::Takeover);
    admit(&store, "f-new", 3_601_000, TraceStage::Takeover);
    {
        let mut guard = store.lock().unwrap();
        assert_eq!(guard.sweep(3_601_000), 1, "TTL 过期清除 f-old");
    }
    let service = FlowQueryService::new(store.clone());
    assert_eq!(
        absent_code(service.flow(&FlowId::new("f-old").unwrap())),
        CODE_TRACE_GONE_EXPIRED,
        "过期迹显式回答 expired"
    );

    // 关闭 + 订阅侧取走：查询面显式回答 drained
    let flow_id = FlowId::new("f-new").unwrap();
    {
        let mut guard = store.lock().unwrap();
        let _ = guard.finish(
            &flow_id,
            CODE_STREAM_CLOSED,
            EvidenceKind::Observed,
            3_601_100,
            3_601_100,
            "c2e=0 e2c=0",
        );
        let drained = guard.drain_closed(4);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].events.len(), 2, "订阅者拿走完整轨迹");
    }
    assert_eq!(
        absent_code(service.flow(&flow_id)),
        CODE_TRACE_GONE_DRAINED,
        "订阅取走后查询显式回答 drained，不冒充 unknown"
    );
}

/// ③ 聚合键不是流 ID：ingress/egress 聚合形字符串不命中任何流，
/// 列表项只携带逐会话 FlowId
#[test]
fn aggregate_keys_never_resolve_as_flows() {
    let store = collector(8, 8, 1);
    admit(&store, "tcp-20261115-000001", 1_000, TraceStage::Takeover);
    let service = FlowQueryService::new(store);

    // /flows 聚合视图形态的键（端点对拼接）——查询面没有以聚合键
    // 求值的入口：包成 FlowId 也只按未知回答
    let aggregate = FlowId::new("8.8.8.8:443->9.9.9.9:443").unwrap();
    assert_eq!(
        absent_code(service.flow(&aggregate)),
        CODE_QUERY_FLOW_UNKNOWN,
        "聚合键不命中任何流"
    );
    let page = service
        .list(&FlowQueryFilter::default(), 0, 10)
        .expect("合法分页");
    assert_eq!(page.total_matching, 1);
    assert_ne!(
        page.items[0].flow.as_str(),
        aggregate.as_str(),
        "列表项是真实 flow ID，不是聚合键"
    );
}

/// ④ 追踪器集成：SessionTracer 埋点 → 查询命中完整轨迹（状态/摘要
/// 正确）；limit=0 显式拒绝；追踪关闭回答 disabled
#[test]
fn tracer_integration_and_page_validation() {
    let store = collector(16, 8, 1);
    {
        let mut tracer = SessionTracer::start(
            Some(store.clone()),
            FlowId::new("flow-q-1").unwrap(),
            FlowOrigin::Association,
            "gen-9",
            1_000,
            1_760_000_000_000,
            "udp 8.8.8.8:53",
        )
        .expect("开轨");
        tracer.close(CODE_STREAM_CLOSED, EvidenceKind::Observed, "c2e=1 e2c=1");
    }
    let service = FlowQueryService::new(store);

    match service.flow(&FlowId::new("flow-q-1").unwrap()) {
        FlowRecord::Found(trace) => {
            assert!(trace.closed, "终态轨迹可查");
            assert_eq!(
                trace.events.first().map(|e| e.code),
                Some(CODE_TRACE_TAKEOVER)
            );
        }
        other => panic!("埋点流应命中，得到 {other:?}"),
    }

    // 列表摘要：已关闭态 + 起止语义 + 代际 + 最近事件码
    let page = service
        .list(&FlowQueryFilter::default(), 0, 10)
        .expect("合法分页");
    assert_eq!(page.total_matching, 1);
    let summary = &page.items[0];
    assert_eq!(summary.state, FlowState::Closed);
    assert_eq!(summary.origin, FlowOrigin::Association);
    assert_eq!(summary.generation, "gen-9");

    let err = service
        .events(&FlowId::new("flow-q-1").unwrap(), 0, 0)
        .unwrap_err();
    assert_eq!(err.code(), CODE_QUERY_PAGE_INVALID);

    // 追踪关闭：缺席显式回答 disabled（配置事实），不冒充流事实
    let off = FlowQueryService::new(Arc::new(Mutex::new(FlowCollector::new(
        CollectorConfig::new(16, 8, 64, 3_600_000, 1, false).expect("合法配置"),
    ))));
    assert_eq!(
        absent_code(off.flow(&FlowId::new("flow-q-1").unwrap())),
        CODE_QUERY_TRACING_DISABLED
    );
}
