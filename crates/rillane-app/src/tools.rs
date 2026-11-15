//! MCP 工具契约（RIL-066，debug-and-mcp.md §5）：工具目录冻结——
//! 工具名与 [`crate::ops::AppOperation::name`] 同口径一一对应（闭合
//! 操作集 = 闭合工具集，RIL-065），每个工具带输入 schema（对象形、
//! `additionalProperties: false`——未知字段进不来）、答复形与错误
//! 语义映射。
//!
//! **注解不充当授权**：[`ToolAnnotations`] 全部是 hint 字段（官方
//! 规范口径——给客户端 UI 的展示建议），授权只读 [`ToolContract::
//! scope`]（服务端 RIL-068 强制）。两者是并列字段，不存在从注解
//! 推导权限的代码路径——这是结构性声明，不是文档约定。
//!
//! 错误语义（协议面 vs 带内，官方规范 tools/call 契约）：
//! - 未知工具名 / 参数畸形（未知字段、类型错、超限、超长）→
//!   JSON-RPC `-32602`（分派前拒绝，工具执行不发生）；
//! - 工具执行的业务答复——包括显式缺席（found:false）——都是**正常
//!   答复**：structuredContent 携带版本化信封，不置 isError；
//! - 执行失败（控制面不可达 / 非 2xx 错误信封）→ `isError: true` +
//!   structuredContent 携带稳定码错误信封。

use crate::mcp::{JsonRpcError, MAX_ARGUMENTS_BYTES};
use crate::reply::AppError;
use serde_json::{json, Value};

/// 服务端授权面（RIL-068 强制的口径——与注解无关）。
/// Write 档本版不存在工具（配置变更走 RIL-073+ 提案面），枚举臂
/// 保留以钉住「注解≠授权」的四档语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// 聚合统计与纯推演（脱敏读）
    Read,
    /// 逐连接轨迹/事件/图（含详细身份列——单独授权）
    DetailedIdentity,
    /// 主动探测（发起/取消——独立网络副作用授权）
    Probe,
    /// 配置写入（RIL-073+ 提案生命周期进入，当前无工具）
    Write,
}

/// 工具注解（官方规范 hint 字段——**只**是客户端 UI 建议，不是安全
/// 保证，更不是授权）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolAnnotations {
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

/// 单个工具的冻结契约
#[derive(Debug, Clone, PartialEq)]
pub struct ToolContract {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub scope: Scope,
    pub annotations: ToolAnnotations,
    /// JSON Schema（子集：object/properties/required/additionalProperties:
    /// false/type/enum/minimum/maximum/maxLength/oneOf/items）
    pub input_schema: Value,
    /// JSON 答复形（text 工具如 flow_svg 无——答复是正文不是信封）
    pub output_schema: Option<Value>,
}

/// 注解构造（读工具惯用形：只读/非破坏/幂等/不开世界）
const fn read_hints() -> ToolAnnotations {
    ToolAnnotations {
        read_only_hint: true,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    }
}

/// 信封答复形（schema_version 常量 1——structuredContent 的最小契约）
fn envelope_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"schema_version": {"const": 1}},
        "required": ["schema_version"],
    })
}

fn flow_id_schema() -> Value {
    json!({"type": "string", "maxLength": 256})
}

fn explain_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["host", "port", "proto"],
        "properties": {
            "host": {"type": "string", "maxLength": 256},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "proto": {"type": "string", "enum": ["tcp", "udp", "quic"]},
            "domain_source": {"type": "string",
                "enum": ["unknown", "user_provided", "dns_observed", "sniffed"]},
            "generation_id": {"type": "string", "maxLength": 128},
            "ingress": {"type": "string", "maxLength": 128},
            "process_name": {"type": "string", "maxLength": 256},
            "process_path": {"type": "string", "maxLength": 256},
            "annotations": {
                "type": "object",
                "additionalProperties": {"type": "string", "maxLength": 256},
            },
        },
    })
}

fn probe_submit_input_schema() -> Value {
    // kind 三分支各自闭合（additionalProperties:false——dns 不许带
    // addr，connect/udp_echo 不许带 host）
    json!({
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "host"],
                "properties": {
                    "kind": {"const": "dns"},
                    "host": {"type": "string", "maxLength": 256},
                },
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "addr"],
                "properties": {
                    "kind": {"const": "connect"},
                    "addr": {"type": "string", "maxLength": 64},
                },
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "addr", "payload_len"],
                "properties": {
                    "kind": {"const": "udp_echo"},
                    "addr": {"type": "string", "maxLength": 64},
                    "payload_len": {"type": "integer", "minimum": 1, "maximum": 1500},
                },
            },
        ],
    })
}

fn probe_id_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id"],
        "properties": {"id": {"type": "integer", "minimum": 0}},
    })
}

/// 工具目录（冻结——顺序即 tools/list 输出顺序；扩工具 = 显式加行
/// + 契约测试同步。目录构造含运行时 schema 值——OnceLock 装载一次）
pub fn catalog() -> &'static [ToolContract] {
    static CATALOG: std::sync::OnceLock<Vec<ToolContract>> = std::sync::OnceLock::new();
    CATALOG.get_or_init(build_catalog)
}

fn build_catalog() -> Vec<ToolContract> {
    vec![
        // ---- 读：聚合统计 ----
        ToolContract {
            name: "runtime_stats",
            title: "Runtime overview",
            description: "运行时总览（采集器/出口池/追踪开关等计数快照，脱敏读）",
            scope: Scope::Read,
            annotations: read_hints(),
            input_schema: json!({"type": "object", "additionalProperties": false, "properties": {}}),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "routing_quality",
            title: "Group quality",
            description: "组实时质量（成员数据源/p95/SLO 门控/当前选中端点，脱敏读）",
            scope: Scope::Read,
            annotations: read_hints(),
            input_schema: json!({"type": "object", "additionalProperties": false, "properties": {}}),
            output_schema: Some(envelope_output_schema()),
        },
        // ---- 读：逐连接（详细身份档）----
        ToolContract {
            name: "flow_list",
            title: "List flows",
            description: "活动/近期连接分页列表（匹配总数诚实、近期优先；摘要脱敏）",
            scope: Scope::Read,
            annotations: read_hints(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "state": {"type": "string", "enum": ["active", "closed"]},
                    "origin": {"type": "string", "enum": ["stream", "association"]},
                    "generation": {"type": "string", "maxLength": 128},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
            }),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "flow_trace",
            title: "Flow trace",
            description: "单流完整轨迹或显式缺席（found:false + 稳定码——缺席是正常答复不是错误）",
            scope: Scope::DetailedIdentity,
            annotations: read_hints(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["id"],
                "properties": {"id": flow_id_schema()},
            }),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "flow_events",
            title: "Flow events",
            description: "流事件增量读取（from_seq 起的增量页；事件序号连续、证据类型保留）",
            scope: Scope::DetailedIdentity,
            annotations: read_hints(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["id"],
                "properties": {
                    "id": flow_id_schema(),
                    "from_seq": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
            }),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "flow_svg",
            title: "Flow path SVG",
            description: "流路径图 SVG（与 JSON 答复同一查询快照；正文是 image/svg+xml 文本）",
            scope: Scope::DetailedIdentity,
            annotations: read_hints(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["id"],
                "properties": {"id": flow_id_schema()},
            }),
            output_schema: None,
        },
        // ---- 读：纯推演 ----
        ToolContract {
            name: "explain",
            title: "Explain route",
            description: "纯路由推演（生产求值器 + 冻结快照——无 DNS/拨号/OS 查询，零副作用；证据缺口逐项列出，条件性结论不冒充确定）",
            scope: Scope::Read,
            annotations: read_hints(),
            input_schema: explain_input_schema(),
            output_schema: Some(envelope_output_schema()),
        },
        // ---- 探测（独立授权）----
        ToolContract {
            name: "probe_list",
            title: "List probes",
            description: "探测作业列表（限额 + 作业快照；纯读）",
            scope: Scope::Read,
            annotations: read_hints(),
            input_schema: json!({"type": "object", "additionalProperties": false, "properties": {}}),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "probe_submit",
            title: "Run probe",
            description: "发起探测作业（dns/connect/udp_echo；目标限服务端登记表——范围外以稳定码拒绝；唯一网络副作用入口，独立探测授权）",
            scope: Scope::Probe,
            annotations: ToolAnnotations {
                read_only_hint: false,
                destructive_hint: false,
                idempotent_hint: false,
                open_world_hint: true,
            },
            input_schema: probe_submit_input_schema(),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "probe_cancel",
            title: "Cancel probe",
            description: "取消探测作业（排队中立即终态、运行中协作取消；幂等）",
            scope: Scope::Probe,
            annotations: ToolAnnotations {
                read_only_hint: false,
                destructive_hint: false,
                idempotent_hint: true,
                open_world_hint: false,
            },
            input_schema: probe_id_input_schema(),
            output_schema: Some(envelope_output_schema()),
        },
        ToolContract {
            name: "probe_result",
            title: "Probe result",
            description: "探测作业测量快照或显式缺席（测量只含执行器实际观测——无回应即 null，绝不造数）",
            scope: Scope::Read,
            annotations: read_hints(),
            input_schema: probe_id_input_schema(),
            output_schema: Some(envelope_output_schema()),
        },
    ]
}

/// 按名取工具契约（未知名 → None，调用方答 -32602）
pub fn tool(name: &str) -> Option<&'static ToolContract> {
    catalog().iter().find(|t| t.name == name)
}

/// tools/list 答复的工具条目形（name/title/description/inputSchema/
/// annotations——scope 是服务端内部授权口径，**不**出现在给模型的
/// 目录里；outputSchema 仅 JSON 答复工具携带）
pub fn tool_entry(t: &ToolContract) -> Value {
    let mut entry = json!({
        "name": t.name,
        "title": t.title,
        "description": t.description,
        "inputSchema": t.input_schema,
        "annotations": {
            "readOnlyHint": t.annotations.read_only_hint,
            "destructiveHint": t.annotations.destructive_hint,
            "idempotentHint": t.annotations.idempotent_hint,
            "openWorldHint": t.annotations.open_world_hint,
        },
    });
    if let Some(out) = &t.output_schema {
        entry["outputSchema"] = out.clone();
    }
    entry
}

/// tools/list 答复（本版工具集一页全出——11 个工具不设游标分页；
/// resultType 恒 complete，目录随二进制冻结故可缓存）
pub fn tools_list_result() -> Value {
    json!({
        "resultType": "complete",
        "tools": catalog().iter().map(tool_entry).collect::<Vec<_>>(),
        "cacheScope": "public",
    })
}

/// 分派前参数校验（tools/call 的 arguments）：序列化字节超
/// [`MAX_ARGUMENTS_BYTES`] → `mcp.input.oversize`；非对象（probe 系
/// 空参工具的 arguments 缺省按 `{}`）→ 类型错；schema 走查（未知
/// 字段/类型错/枚举越界/超长/越界 → 稳定码入 `data.code`）。全部以
/// -32602 应答——请求不进入任何工具执行。
pub fn validate_arguments(t: &ToolContract, arguments: Option<&Value>) -> Result<(), JsonRpcError> {
    let empty = json!({});
    let args = arguments.unwrap_or(&empty);
    let serialized = serde_json::to_string(args).unwrap_or_default();
    if serialized.len() > MAX_ARGUMENTS_BYTES {
        return Err(
            JsonRpcError::invalid_params("arguments exceed size cap").with_code_data(
                "mcp.input.oversize",
                json!({"max_bytes": MAX_ARGUMENTS_BYTES}),
            ),
        );
    }
    if !args.is_object() {
        return Err(JsonRpcError::invalid_params("arguments must be an object")
            .with_code_data("mcp.input.type", json!({"field": "(root)"})));
    }
    validate_value(&t.input_schema, args, "").map_err(|(field, code, message)| {
        JsonRpcError::invalid_params(message).with_code_data(code, json!({"field": field}))
    })
}

/// schema 走查错误（字段路径、稳定码、人读消息）
type SchemaError = (String, &'static str, String);

/// 迷你 JSON Schema 走查器（只支持本目录用到的关键字子集——完整
/// schema 引擎不在契约层引入）
fn validate_value(schema: &Value, value: &Value, path: &str) -> Result<(), SchemaError> {
    // oneOf：kind 判别臂优先——arguments.kind 与臂 const 一致即按该臂
    // 校验（具体错误直达字段，不被「恰一臂」掩码）；无判别命中再走
    // 恰一臂全量匹配
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let declared_kind = value.get("kind").and_then(Value::as_str);
        let discriminated = branches.iter().find(|branch| {
            branch["properties"]["kind"]["const"].as_str() == declared_kind
                && declared_kind.is_some()
        });
        if let Some(branch) = discriminated {
            return validate_value(branch, value, path);
        }
        let matched = branches
            .iter()
            .filter(|branch| validate_value(branch, value, path).is_ok())
            .count();
        if matched != 1 {
            return Err((
                path.to_string(),
                "mcp.input.one_of",
                format!("arguments must match exactly one kind schema (matched {matched})"),
            ));
        }
        return Ok(());
    }

    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        let ok = match expected {
            "object" => value.is_object(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            _ => true,
        };
        if !ok {
            return Err((
                path.to_string(),
                "mcp.input.type",
                format!("field `{path}` must be {expected}"),
            ));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            return Err((
                path.to_string(),
                "mcp.input.enum",
                format!("field `{path}` is outside the frozen value set"),
            ));
        }
    }

    if let Some(constant) = schema.get("const") {
        if value != constant {
            return Err((
                path.to_string(),
                "mcp.input.const",
                format!("field `{path}` has a frozen constant value"),
            ));
        }
    }

    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
        if let Some(s) = value.as_str() {
            if s.chars().count() as u64 > max {
                return Err((
                    path.to_string(),
                    "mcp.input.oversize",
                    format!("field `{path}` exceeds maxLength {max}"),
                ));
            }
        }
    }

    if let Some(max) = schema.get("maximum").and_then(Value::as_i64) {
        if let Some(n) = value.as_i64() {
            if n > max {
                return Err((
                    path.to_string(),
                    "mcp.input.range",
                    format!("field `{path}` exceeds maximum {max}"),
                ));
            }
        }
    }

    if let Some(min) = schema.get("minimum").and_then(Value::as_i64) {
        if let Some(n) = value.as_i64() {
            if n < min {
                return Err((
                    path.to_string(),
                    "mcp.input.range",
                    format!("field `{path}` is below minimum {min}"),
                ));
            }
        }
    }

    if let Some(inner) = schema.get("items") {
        if let Some(items) = value.as_array() {
            for (i, item) in items.iter().enumerate() {
                validate_value(inner, item, &format!("{path}[{i}]"))?;
            }
        }
    }

    // 对象面：required + 未知字段拒绝 + properties 递归
    if schema.get("type").and_then(Value::as_str) == Some("object")
        || schema.get("properties").is_some()
    {
        let obj = value.as_object().ok_or_else(|| {
            (
                path.to_string(),
                "mcp.input.type",
                "expected an object".into(),
            )
        })?;
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required {
                let key = key.as_str().unwrap_or_default();
                if !obj.contains_key(key) {
                    return Err((
                        key.to_string(),
                        "mcp.input.required",
                        format!("field `{key}` is required"),
                    ));
                }
            }
        }
        let additional_allowed = schema.get("additionalProperties");
        let props = schema
            .get("properties")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (key, val) in obj {
            if let Some(prop_schema) = props.get(key) {
                validate_value(prop_schema, val, key)?;
            } else {
                // 未知字段：additionalProperties:false（或值 schema——
                // 注解面 additionalProperties 是值 schema 时按键消毒
                // 交给服务端，此处只校验值形）
                match additional_allowed {
                    Some(Value::Bool(false)) => {
                        return Err((
                            key.clone(),
                            "mcp.input.unknown_field",
                            format!("unknown field `{key}`"),
                        ));
                    }
                    Some(value_schema) => validate_value(value_schema, val, key)?,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// 成功答复形（业务答复——含显式缺席 found:false：缺席是正常答复，
/// 不置 isError）。structuredContent 携带版本化信封原文，content 文本
/// 是紧凑 JSON（模型可读、字节有界——MAX_RESULT_BYTES 截断由装配面
/// 执行，本构造不截断以保持纯函数）。resultType 恒 complete（官方
/// CallToolResult 契约：resultType 必带）。
pub fn result_from_envelope(envelope: &Value) -> Value {
    json!({
        "resultType": "complete",
        "content": [{"type": "text", "text": envelope.to_string()}],
        "structuredContent": envelope,
        "isError": false,
    })
}

/// 纯文本答复形（flow_svg：正文是 SVG 文本，无 outputSchema——
/// structuredContent 必须缺席以符合「无 schema 即无结构化载荷」）
pub fn result_from_text(text: &str) -> Value {
    json!({
        "resultType": "complete",
        "content": [{"type": "text", "text": text}],
        "isError": false,
    })
}

/// 执行失败答复形（控制面不可达 / 非 2xx 错误信封 → isError:true +
/// 稳定码信封进 structuredContent；协议面 -32602 不在此——分派前
/// 已拒绝）
pub fn result_from_error(err: &AppError) -> Value {
    let status_note = match err.status {
        Some(status) => format!("HTTP {status}"),
        None => "控制面不可达".to_string(),
    };
    let structured = json!({
        "schema_version": 1,
        "error": {"code": err.code, "context": err.context},
    });
    json!({
        "resultType": "complete",
        "content": [{"type": "text", "text": format!("{}（{}）: {}", err.code, status_note, err.context)}],
        "structuredContent": structured,
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::codes;
    use crate::ops::AppOperation;
    use crate::reply::AppError;
    use serde_json::json;

    #[test]
    fn catalog_is_closed_and_matches_operation_set() {
        let cat = catalog();
        assert_eq!(cat.len(), 11, "工具数 = 闭合操作集大小（扩集两边同步）");
        for op_name in [
            AppOperation::RuntimeStats,
            AppOperation::RoutingQuality,
            AppOperation::ProbeList,
        ]
        .iter()
        .map(|op| op.name())
        {
            assert!(tool(op_name).is_some(), "工具 {op_name} 在目录");
        }
        // 一一对应：目录名集合 == 操作集机器名集合
        let mut tool_names: Vec<&str> = cat.iter().map(|t| t.name).collect();
        tool_names.sort_unstable();
        let mut op_names: Vec<&str> = vec![
            "runtime_stats",
            "routing_quality",
            "flow_list",
            "flow_trace",
            "flow_events",
            "flow_svg",
            "explain",
            "probe_list",
            "probe_submit",
            "probe_cancel",
            "probe_result",
        ];
        op_names.sort_unstable();
        assert_eq!(tool_names, op_names);
    }

    #[test]
    fn annotations_are_hints_and_scope_is_authority() {
        // 结构性分立：scope 与注解是并列字段——授权口径只看 scope。
        // 一致性面：Read 档工具恒只读 hint；Probe 档 submit 非只读。
        for t in catalog() {
            match t.scope {
                Scope::Read => assert!(
                    t.annotations.read_only_hint,
                    "{} 是脱敏读，readOnlyHint 必须真",
                    t.name
                ),
                Scope::DetailedIdentity | Scope::Probe | Scope::Write => {}
            }
        }
        let submit = tool("probe_submit").expect("submit");
        assert_eq!(submit.scope, Scope::Probe);
        assert!(!submit.annotations.read_only_hint);
        assert!(submit.annotations.open_world_hint, "探测开世界面如实标注");
        // cancel 是探测授权但幂等 hint 如实
        let cancel = tool("probe_cancel").expect("cancel");
        assert_eq!(cancel.scope, Scope::Probe);
        assert!(cancel.annotations.idempotent_hint);
        // 详细身份档与读档分立
        assert_eq!(
            tool("flow_trace").expect("trace").scope,
            Scope::DetailedIdentity
        );
        assert_eq!(tool("runtime_stats").expect("stats").scope, Scope::Read);
    }

    #[test]
    fn unknown_fields_are_rejected_before_dispatch() {
        let t = tool("flow_trace").expect("trace");
        let err = validate_arguments(t, Some(&json!({"id": "f-1", "raw": true}))).unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
        assert_eq!(
            err.data.as_ref().expect("data")["code"],
            "mcp.input.unknown_field"
        );

        // 空参工具带未知字段同样拒绝
        let stats = tool("runtime_stats").expect("stats");
        let err = validate_arguments(stats, Some(&json!({"verbose": 1}))).unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.unknown_field");

        // 缺 required
        let err = validate_arguments(t, Some(&json!({}))).unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.required");
    }

    #[test]
    fn type_enum_and_range_contracts_hold() {
        let t = tool("flow_list").expect("list");
        let err = validate_arguments(t, Some(&json!({"limit": 0}))).unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.range");

        let err = validate_arguments(t, Some(&json!({"state": "zombie"}))).unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.enum");

        let explain = tool("explain").expect("explain");
        let err = validate_arguments(
            explain,
            Some(&json!({"host": "example.com", "port": 443, "proto": "smtp"})),
        )
        .unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.enum");

        // 合法输入通过
        validate_arguments(
            explain,
            Some(&json!({
                "host": "example.com",
                "port": 443,
                "proto": "quic",
                "annotations": {"client.cidr": "10.0.0.1/32"},
            })),
        )
        .expect("valid explain arguments");
    }

    #[test]
    fn probe_submit_kinds_are_closed_per_branch() {
        let t = tool("probe_submit").expect("submit");
        validate_arguments(t, Some(&json!({"kind": "dns", "host": "example.com"})))
            .expect("dns ok");
        validate_arguments(
            t,
            Some(&json!({"kind": "connect", "addr": "192.0.2.1:443"})),
        )
        .expect("connect ok");
        validate_arguments(
            t,
            Some(&json!({"kind": "udp_echo", "addr": "192.0.2.1:53", "payload_len": 64})),
        )
        .expect("udp_echo ok");

        // dns 分支不许带 addr；未知 kind 恰零臂匹配
        let err = validate_arguments(
            t,
            Some(&json!({"kind": "dns", "host": "example.com", "addr": "192.0.2.1:53"})),
        )
        .unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);

        let err =
            validate_arguments(t, Some(&json!({"kind": "handshake", "addr": "x"}))).unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.one_of");

        // udp_echo 载荷越界
        let err = validate_arguments(
            t,
            Some(&json!({"kind": "udp_echo", "addr": "192.0.2.1:53", "payload_len": 9000})),
        )
        .unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.range");
    }

    #[test]
    fn oversize_arguments_rejected_with_stable_code() {
        let t = tool("flow_list").expect("list");
        let big = "x".repeat(MAX_ARGUMENTS_BYTES + 1);
        let err = validate_arguments(t, Some(&json!({"generation": big}))).unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
        assert_eq!(err.data.expect("data")["code"], "mcp.input.oversize");
    }

    #[test]
    fn list_result_carries_all_entries_without_scope() {
        let result = tools_list_result();
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["cacheScope"], "public");
        let tools = result["tools"].as_array().expect("tools");
        assert_eq!(tools.len(), 11);
        for entry in tools {
            assert!(entry.get("inputSchema").is_some());
            assert!(entry.get("annotations").is_some());
            // scope 是服务端内部授权口径——不出现在给模型的目录里
            assert!(entry.get("scope").is_none(), "scope 不进 tools/list");
            // 注解只含 hint 字段（无任何授权字段名）
            let annotations = entry["annotations"].as_object().expect("annotations");
            for key in annotations.keys() {
                assert!(key.ends_with("Hint"), "注解键 {key} 必须是 hint");
            }
        }
        // flow_svg 是文本答复工具——无 outputSchema
        let svg = tools
            .iter()
            .find(|e| e["name"] == "flow_svg")
            .expect("svg entry");
        assert!(svg.get("outputSchema").is_none());
        // JSON 答复工具带信封 outputSchema
        let trace = tools
            .iter()
            .find(|e| e["name"] == "flow_trace")
            .expect("trace entry");
        assert_eq!(
            trace["outputSchema"]["properties"]["schema_version"]["const"],
            1
        );
    }

    #[test]
    fn absence_is_a_normal_answer_errors_are_in_band() {
        // found:false 缺席信封 → isError:false（缺席是答复不是错误）
        let absent = json!({
            "schema_version": 1,
            "found": false,
            "absence": {"code": "query.flow.unknown", "note": "n"},
        });
        let out = result_from_envelope(&absent);
        assert_eq!(out["resultType"], "complete");
        assert_eq!(out["isError"], false);
        assert_eq!(
            out["structuredContent"]["absence"]["code"],
            "query.flow.unknown"
        );
        assert_eq!(out["content"][0]["type"], "text");

        // 执行失败 → isError:true + 稳定码信封
        let err = AppError::from_response(
            503,
            r#"{"error":{"code":"probe.disabled","context":"off"}}"#,
        );
        let out = result_from_error(&err);
        assert_eq!(out["resultType"], "complete");
        assert_eq!(out["isError"], true);
        assert_eq!(out["structuredContent"]["error"]["code"], "probe.disabled");

        // 传输失败 → isError:true + control.unreachable
        let out = result_from_error(&AppError::transport("refused".into()));
        assert_eq!(out["isError"], true);
        assert_eq!(
            out["structuredContent"]["error"]["code"],
            "control.unreachable"
        );
    }
}
