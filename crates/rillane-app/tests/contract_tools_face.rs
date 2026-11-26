//! MCP 工具目录契约（RIL-083）：工具目录是跨语言冻结面——模型客户端 /
//! 桌面页（RIL-148 六页入口引用同名操作）都按工具名与输入 schema 消费。
//! 本测试把 `tools::catalog()` 的**全量契约**（name/title/description/
//! scope/注解/输入输出 schema）与 contracts/schema_v1/mcp_tools_face_v1.json
//! 快照逐值对账：任何一面漂移（含文案改动）在本门具名失败，破坏兼容的
//! 变化明确失败而不是静默扩散。
//!
//! 对账面：快照是 exact 语义（Value 全等）；schema_version 升版 =
//! 整库复制 schema_v2 事务（contracts/schema_v1/README.md）。

use rillane_app::ops::AppOperation;
use rillane_app::tools::{catalog, tool_entry, tools_list_result};
use rillane_routing::DomainSource;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// 相对仓库根的契约样本路径（测试运行于 target/ 之下）
fn repo_root(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_face() -> Value {
    let path = repo_root("contracts/schema_v1/mcp_tools_face_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取契约样本 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("契约样本 JSON 解析失败: {e}"))
}

/// 首个分歧点的具名定位（Value 全等比较，分歧路径逐层点名）
fn assert_value_eq(actual: &Value, expected: &Value, path: &str) {
    if actual == expected {
        return;
    }
    match (actual, expected) {
        (Value::Object(a), Value::Object(e)) => {
            for (k, ev) in e {
                match a.get(k) {
                    None => panic!("契约漂移 @ {path}.{k}：实际面缺而快照有（减键=破坏兼容）"),
                    Some(av) => assert_value_eq(av, ev, &format!("{path}.{k}")),
                }
            }
            for k in a.keys() {
                if !e.contains_key(k) {
                    panic!(
                        "契约漂移 @ {path}.{k}：实际面有而快照无（加键=过门，须更新快照并具名理由）"
                    );
                }
            }
            panic!("契约漂移 @ {path}：对象分歧（见上方首因）");
        }
        (Value::Array(a), Value::Array(e)) => {
            assert_eq!(
                a.len(),
                e.len(),
                "契约漂移 @ {path}：数组长度 {} ≠ 快照 {}",
                a.len(),
                e.len()
            );
            for (i, (av, ev)) in a.iter().zip(e.iter()).enumerate() {
                assert_value_eq(av, ev, &format!("{path}[{i}]"));
            }
            panic!("契约漂移 @ {path}：数组元素分歧（见上方首因）");
        }
        _ => {
            let brief = |v: &Value| {
                let s = v.to_string();
                if s.len() > 120 {
                    format!("{}…", &s[..120])
                } else {
                    s
                }
            };
            panic!(
                "契约漂移 @ {path}：值不等 实际:{} 快照:{}",
                brief(actual),
                brief(expected)
            );
        }
    }
}

/// 全集操作样例（与 app_contract.rs 同口径——工具名与操作名一一对应的
/// 闭合集对账需要全集实例）
fn sample_ops() -> Vec<AppOperation> {
    let mut annotations = BTreeMap::new();
    annotations.insert("client.cidr".to_string(), "10.0.0.1/32".to_string());
    vec![
        AppOperation::RuntimeStats,
        AppOperation::RoutingQuality,
        AppOperation::FlowList(
            rillane_app::ops::FlowListFilter::new(
                Some(rillane_app::ops::StateFilter::Closed),
                Some(rillane_app::ops::OriginFilter::Association),
                Some("gen-1".to_string()),
                40,
                20,
            )
            .expect("filter"),
        ),
        AppOperation::FlowTrace {
            id: "f-1".to_string(),
        },
        AppOperation::FlowEvents(
            rillane_app::ops::FlowEventsParams::new("f-1".to_string(), 3, 200).expect("params"),
        ),
        AppOperation::FlowSvg {
            id: "f-1".to_string(),
        },
        AppOperation::Explain(Box::new(rillane_routing::ExplainInput {
            generation_id: "gen-1".to_string(),
            ingress: Some("mixed-in".to_string()),
            host: "example.com".to_string(),
            port: 443,
            proto: "tcp".to_string(),
            domain_source: DomainSource::UserProvided,
            process: None,
            annotations,
        })),
        AppOperation::ProbeList,
        AppOperation::ProbeSubmit(rillane_app::ops::ProbeJobSpec::UdpEcho {
            addr: "192.0.2.1:443".to_string(),
            payload_len: 64,
        }),
        AppOperation::ProbeCancel { id: 7 },
        AppOperation::ProbeResult { id: 7 },
        AppOperation::ConfigPreview {
            patch: json!({"telemetry": {"log_level": "debug"}}),
            scope: Some(vec!["telemetry".to_string()]),
        },
        AppOperation::ConfigPropose {
            patch: json!({"telemetry": {"log_level": "debug"}}),
            scope: vec!["telemetry".to_string()],
            ttl_ms: 60_000,
        },
        AppOperation::ConfigAudit,
        AppOperation::ConfigApply {
            proposal_id: "p-1".to_string(),
            approval_id: "a-1".to_string(),
            idempotency_key: "mcp-p-1-a-1".to_string(),
        },
        AppOperation::ConfigRollbackPrepare {
            target_key: "k-1".to_string(),
        },
        AppOperation::ConfigRollbackExecute {
            target_key: "k-1".to_string(),
            proposal_id: "rb-1".to_string(),
            approval_id: "a-2".to_string(),
            idempotency_key: "mcp-rb-rb-1-a-2".to_string(),
            drain_deadline_ms: None,
        },
    ]
}

/// 活目录 → 快照 Value（与生成快照时的投影同构——字段集即冻结契约面）
fn live_snapshot() -> Value {
    let tools: Vec<Value> = catalog()
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "title": t.title,
                "description": t.description,
                "scope": format!("{:?}", t.scope),
                "annotations": {
                    "read_only_hint": t.annotations.read_only_hint,
                    "destructive_hint": t.annotations.destructive_hint,
                    "idempotent_hint": t.annotations.idempotent_hint,
                    "open_world_hint": t.annotations.open_world_hint,
                },
                "input_schema": t.input_schema,
                "output_schema": t.output_schema,
            })
        })
        .collect();
    json!({"schema_version": 1u32, "tools": tools})
}

#[test]
fn tool_catalog_matches_frozen_snapshot() {
    let face = load_face();
    assert_eq!(
        face["schema_version"],
        json!(1u32),
        "契约样本版本面恒 1（升版 = schema_v2 目录事务）"
    );
    assert_value_eq(&live_snapshot()["tools"], &face["tools"], "tools");
}

#[test]
fn tool_names_and_operation_names_are_the_same_closed_set() {
    let mut tool_names: Vec<&str> = catalog().iter().map(|t| t.name).collect();
    tool_names.sort_unstable();
    tool_names.dedup();
    assert_eq!(
        tool_names.len(),
        16,
        "工具目录闭合集（本版 16 工具；目录变化须过快照门）"
    );
    let mut op_names: Vec<&str> = sample_ops().iter().map(|op| op.name()).collect();
    op_names.sort_unstable();
    op_names.dedup();
    assert_eq!(
        op_names, tool_names,
        "操作集 = 工具集（RIL-065 闭合口径：两边同集同名，rollback 双操作共享一名）"
    );
    // 每个工具名都能按名取回契约（未知名 → -32602 路径的对偶面）
    for name in tool_names {
        assert!(
            rillane_app::tools::tool(name).is_some(),
            "工具 {name} 应可按名取回"
        );
    }
}

#[test]
fn tools_list_entries_expose_the_frozen_entry_shape() {
    let result = tools_list_result();
    assert_eq!(result["resultType"], "complete", "单页全出、无游标");
    let tools = result["tools"].as_array().expect("tools 数组");
    assert_eq!(tools.len(), 16, "目录 16 项");
    for entry in tools {
        let keys: Vec<&str> = entry
            .as_object()
            .expect("条目对象")
            .keys()
            .map(String::as_str)
            .collect();
        let has_output = keys.contains(&"outputSchema");
        let expected_len = if has_output { 6 } else { 5 };
        assert_eq!(
            keys.len(),
            expected_len,
            "条目键集 name/title/description/inputSchema/annotations[/outputSchema]"
        );
        for k in ["name", "title", "description", "inputSchema", "annotations"] {
            assert!(keys.contains(&k), "条目缺 {k}");
        }
        let contract = rillane_app::tools::tool(entry["name"].as_str().expect("name"))
            .unwrap_or_else(|| panic!("条目 {} 应在目录", entry["name"]));
        // 注解 hint 与契约同源；scope 不出现在条目（服务端内部授权口径）
        assert!(
            entry.get("scope").is_none(),
            "scope 不得出现在 tools/list 条目"
        );
        assert_eq!(
            entry["annotations"]["readOnlyHint"],
            json!(contract.annotations.read_only_hint)
        );
        let _ = tool_entry(contract); // entry 形与投影函数同源（构造一致）
    }
}

/// 对账器自证：刻意漂移的快照必须在本门失败且点名首个分歧键——
/// 「破坏兼容的变化明确失败」是对账器自身行为的一部分。
#[test]
#[should_panic(expected = "契约漂移 @ tools[0].description")]
fn comparator_bites_on_description_drift() {
    let mut face = load_face();
    face["tools"][0]["description"] = json!("drifted text");
    assert_value_eq(&live_snapshot()["tools"], &face["tools"], "tools");
}

#[test]
#[should_panic(expected = "实际面缺而快照有")]
fn comparator_bites_on_added_key() {
    let mut face = load_face();
    face["tools"][0]["extra_key"] = json!(1);
    assert_value_eq(&live_snapshot()["tools"], &face["tools"], "tools");
}
