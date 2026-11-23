//! FlowTrace/TraceEvent/CollectorStats → 冻结 JSON 形态（RIL-150 抽取）。
//! 这些诊断类型不 derive Serialize——线格式只能经这些发射器表达；
//! 控制面（`/trace/*`）与 FFI（Android/iOS 客户端）共享同一发射器，
//! 保证两面输出字段一致（schema_version=1：字段面 + 机器码——
//! stage/evidence 用恒定机器口径，attempt 仅 Attempt 事件携带）。

use crate::{
    collector::CollectorStats,
    trace::{FlowTrace, TraceEvent},
};

/// FlowTrace → 冻结 JSON 形态（schema_version=1：字段面 + 机器码——
/// stage/evidence 用恒定机器口径，attempt 仅 Attempt 事件携带）
pub fn trace_json(trace: &FlowTrace) -> serde_json::Value {
    serde_json::json!({
        "flow": trace.flow.as_str(),
        "origin": trace.origin.as_str(),
        "generation": trace.generation,
        "closed": trace.closed,
        "events": trace.events.iter().map(trace_event_json).collect::<Vec<_>>(),
    })
}

/// TraceEvent → 冻结 JSON 形态（RIL-051 schema 的线格式）
pub fn trace_event_json(event: &TraceEvent) -> serde_json::Value {
    serde_json::json!({
        "seq": event.seq,
        "stage": event.stage.as_str(),
        "attempt": event.attempt.map(|a| a.0),
        "code": event.code,
        "evidence": event.evidence.as_str(),
        "monotonic_ms": event.monotonic_ms,
        "wall_ms": event.wall_ms,
        "detail": event.detail,
    })
}

/// CollectorStats → 冻结 JSON 形态（缺席答复的计数可见面）
pub fn collector_stats_json(stats: &CollectorStats) -> serde_json::Value {
    serde_json::json!({
        "traces_admitted": stats.traces_admitted,
        "traces_sampled_out": stats.traces_sampled_out,
        "flows_dropped_active_limit": stats.flows_dropped_active_limit,
        "events_dropped_per_flow": stats.events_dropped_per_flow,
        "traces_dropped_overflow": stats.traces_dropped_overflow,
        "events_dropped_overflow": stats.events_dropped_overflow,
        "traces_expired": stats.traces_expired,
        "closed_pending": stats.closed_pending,
        "active_traces": stats.active_traces,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        outbound::EvidenceKind,
        trace::{FlowId, FlowOrigin, TraceStage},
    };

    /// 控制面与 FFI 共享同一发射器：这里锁住字段面——`/trace/flow`、
    /// `/trace/flows` 与 Android/iOS 客户端连线格式由构造保证一致。
    #[test]
    fn trace_json_freezes_ril_051_shape() {
        let mut trace =
            FlowTrace::new(FlowId::new("flow-a1").unwrap(), FlowOrigin::Stream, "gen-7").unwrap();
        trace
            .push(
                TraceStage::Egress,
                None,
                "egress.ok",
                EvidenceKind::Observed,
                42,
                1_700_000_000_123,
                "ok",
            )
            .unwrap();
        let value = trace_json(&trace);
        assert_eq!(value["flow"], "flow-a1");
        assert_eq!(value["origin"], "stream");
        assert_eq!(value["generation"], "gen-7");
        assert_eq!(value["closed"], false);
        let event = &value["events"][0];
        assert_eq!(event["seq"], 0u64);
        assert_eq!(event["stage"], "egress");
        assert_eq!(event["attempt"], serde_json::Value::Null);
        assert_eq!(event["code"], "egress.ok");
        assert_eq!(event["evidence"], "observed");
        assert_eq!(event["monotonic_ms"], 42u64);
        assert_eq!(event["wall_ms"], 1_700_000_000_123u64);
        assert_eq!(event["detail"], "ok");
    }

    #[test]
    fn collector_stats_json_freezes_nine_counters() {
        let stats = CollectorStats::default();
        let value = collector_stats_json(&stats);
        for key in [
            "traces_admitted",
            "traces_sampled_out",
            "flows_dropped_active_limit",
            "events_dropped_per_flow",
            "traces_dropped_overflow",
            "events_dropped_overflow",
            "traces_expired",
            "closed_pending",
            "active_traces",
        ] {
            assert!(value.get(key).is_some(), "missing counter {key}");
        }
    }
}
