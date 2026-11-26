//! 诊断事件契约（RIL-083）：trace/event/collector 三面是 RIL-051 schema
//! 的线格式（RIL-150 抽取共享发射器——控制面 /trace/* 与 FFI 查询同源）。
//! `contracts/schema_v1/trace_face_v1.json` 以 **exact 面**（键集恰等）
//! 钉死：加键减键都要求显式过门（README 的 schema_v2 目录事务），不静默
//! 扩散到移动端 / 脚本消费者。
//!
//! trace_json.rs 内联测试钉字段值样本；本门钉**键集恰等**——补上「加键
//! 也算漂移」的半边（冻结形 = 字段集冻结，不是字段超集冻结）。

use rillane_core::collector::CollectorStats;
use rillane_core::outbound::EvidenceKind;
use rillane_core::trace::{FlowId, FlowOrigin, TraceEvent, TraceStage};
use rillane_core::trace_json::{collector_stats_json, trace_event_json, trace_json};
use serde_json::Value;
use std::collections::BTreeSet;

fn repo_root(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_face() -> Value {
    let path = repo_root("contracts/schema_v1/trace_face_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取 trace 面 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("trace 面 JSON 解析失败: {e}"))
}

fn face_of<'a>(face: &'a Value, id: &str) -> &'a Value {
    face["faces"]
        .get(id)
        .unwrap_or_else(|| panic!("trace 面文件缺 {id} 登记"))
}

/// serde_json 值类型词表 → 实测判定；`T|null` 复合声明任一命中即可
/// （attempt 仅 Attempt 事件携带——缺席面 null、在场面 number）。
fn type_matches(actual: &Value, declared: &str) -> bool {
    match declared {
        "object" => actual.is_object(),
        "array" => actual.is_array(),
        "string" => actual.is_string(),
        "boolean" => actual.is_boolean(),
        "number" => actual.is_number(),
        "null" => actual.is_null(),
        compound if compound.contains('|') => {
            compound.split('|').any(|t| type_matches(actual, t.trim()))
        }
        other => panic!("trace 面类型词表外声明「{other}」（face 文件自身写错）"),
    }
}

/// exact 面：实际键集恰等于声明键集，且每个声明键类型相符。
/// 加键 = 漂移（冻结形变更须过门）；减键 = 破坏兼容。
fn assert_exact_face(actual: &Value, face: &Value, face_id: &str) {
    let declared = face["keys"]
        .as_object()
        .unwrap_or_else(|| panic!("面 {face_id} 缺 keys 对象"));
    let obj = actual
        .as_object()
        .unwrap_or_else(|| panic!("面 {face_id}：实际投影不是对象"));
    let declared_keys: BTreeSet<&str> = declared.keys().map(String::as_str).collect();
    let actual_keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let missing: Vec<&str> = declared_keys.difference(&actual_keys).copied().collect();
    let extra: Vec<&str> = actual_keys.difference(&declared_keys).copied().collect();
    assert!(
        missing.is_empty(),
        "trace 面漂移 @ {face_id}：缺键 {missing:?}（减键=破坏兼容，须过 schema_v2 事务）"
    );
    assert!(
        extra.is_empty(),
        "trace 面漂移 @ {face_id}：多键 {extra:?}（加键=冻结形变更，须更新 face 并具名理由）"
    );
    for (k, declared) in declared {
        let declared = declared.as_str().expect("类型声明是字符串");
        let v = &obj[k];
        assert!(
            type_matches(v, declared),
            "trace 面漂移 @ {face_id}.{k}：类型漂移，声明 {declared}，实际 {v}"
        );
    }
}

fn sample_trace() -> rillane_core::trace::FlowTrace {
    let mut trace = rillane_core::trace::FlowTrace::new(
        FlowId::new("flow-c8").unwrap(),
        FlowOrigin::Stream,
        "gen-1",
    )
    .expect("trace");
    trace
        .push(
            TraceStage::Egress,
            None,
            "egress.ok",
            EvidenceKind::Observed,
            7,
            1_700_000_000_000,
            "ok",
        )
        .expect("event");
    trace
}

fn sample_event() -> TraceEvent {
    TraceEvent {
        seq: 0,
        stage: TraceStage::Egress,
        attempt: None,
        code: "egress.ok",
        evidence: EvidenceKind::Observed,
        monotonic_ms: 7,
        wall_ms: 1_700_000_000_000,
        detail: "ok".to_string(),
    }
}

#[test]
fn trace_faces_are_exactly_frozen() {
    let face = load_face();
    assert_eq!(face["schema_version"], serde_json::json!(1u32));
    assert_exact_face(
        &trace_json(&sample_trace()),
        face_of(&face, "trace_envelope"),
        "trace_envelope",
    );
    assert_exact_face(
        &trace_event_json(&sample_event()),
        face_of(&face, "trace_event"),
        "trace_event",
    );
    assert_exact_face(
        &collector_stats_json(&CollectorStats::default()),
        face_of(&face, "collector_stats"),
        "collector_stats",
    );
}

/// 对账器自证：face 漏登记一个真实存在的键 → 本门以「多键」点名失败
/// （face 落后于实际面 = 漂移被放行，同门可查——登记面与实现面互为镜像）。
#[test]
#[should_panic(expected = "trace 面漂移 @ collector_stats：多键 [\"active_traces\"]")]
fn comparator_bites_on_face_lagging_reality() {
    let mut face = load_face();
    face["faces"]["collector_stats"]["keys"]
        .as_object_mut()
        .expect("keys")
        .remove("active_traces");
    assert_exact_face(
        &collector_stats_json(&CollectorStats::default()),
        &face["faces"]["collector_stats"],
        "collector_stats",
    );
}

/// 对账器自证（加键半边）：实际面多出的键必须点名。
#[test]
#[should_panic(expected = "trace 面漂移 @ collector_stats：多键 [\"phantom\"]")]
fn comparator_bites_on_extra_key() {
    let mut stats = serde_json::json!({"phantom": 1});
    let base = collector_stats_json(&CollectorStats::default());
    for (k, v) in base.as_object().expect("obj") {
        stats[k] = v.clone();
    }
    let face = load_face();
    assert_exact_face(&stats, face_of(&face, "collector_stats"), "collector_stats");
}
