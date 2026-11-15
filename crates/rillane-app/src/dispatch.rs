//! MCP 工具分派适配（RIL-067）：**纯函数**——把已校验的 tools/call
//! 参数构造成闭合操作集的一个操作（RIL-065），把边界答复投影成
//! MCP 工具答复形（RIL-066）。分派适配器不做任何决策：工具目录是
//! 唯一入口（未知名拒绝）、schema 校验先行（非法参数不上线）、授权
//! 在服务端装配层（RIL-068 注入）。

use crate::mcp::JsonRpcError;
use crate::ops::{AppOperation, FlowEventsParams, FlowListFilter, OriginFilter, StateFilter};
use crate::reply::AppReply;
use crate::tools::{self, ToolContract};
use serde_json::{json, Value};

/// tools/call 参数 → 闭合操作。返回工具契约（调用方需要 outputSchema
/// 等元数据决定答复投影）。
/// 校验顺序：未知名 → `mcp.tool.unknown`；schema 违例（未知字段/超限
/// /类型错）→ `mcp.input.*`；构造失败（不应发生——schema 已挡）→
/// `mcp.input.invalid`。全部 -32602。
pub fn build_operation(
    name: &str,
    arguments: Option<&Value>,
) -> Result<(AppOperation, &'static ToolContract), JsonRpcError> {
    let tool = tools::tool(name).ok_or_else(|| {
        JsonRpcError::invalid_params(format!("unknown tool: {name}"))
            .with_code_data("mcp.tool.unknown", json!({"tool": name}))
    })?;
    tools::validate_arguments(tool, arguments)?;
    let args = arguments.cloned().unwrap_or_else(|| json!({}));
    let op = build_validated(tool.name, &args)?;
    Ok((op, tool))
}

/// schema 已通过的参数 → 操作（提取失败按内部一致性问题处理，仍以
/// -32602 应答——构造函数永不 panic）
fn build_validated(name: &str, args: &Value) -> Result<AppOperation, JsonRpcError> {
    let get_str = |key: &str| args.get(key).and_then(Value::as_str).map(String::from);
    let get_u64 = |key: &str| args.get(key).and_then(Value::as_u64);
    let invalid = |field: &str| -> JsonRpcError {
        JsonRpcError::invalid_params(format!("field `{field}` failed to construct operation"))
            .with_code_data("mcp.input.invalid", json!({"field": field}))
    };
    match name {
        "runtime_stats" => Ok(AppOperation::RuntimeStats),
        "routing_quality" => Ok(AppOperation::RoutingQuality),
        "probe_list" => Ok(AppOperation::ProbeList),
        "flow_trace" => Ok(AppOperation::FlowTrace {
            id: get_str("id").ok_or_else(|| invalid("id"))?,
        }),
        "flow_svg" => Ok(AppOperation::FlowSvg {
            id: get_str("id").ok_or_else(|| invalid("id"))?,
        }),
        "flow_events" => {
            let params = FlowEventsParams::new(
                get_str("id").ok_or_else(|| invalid("id"))?,
                get_u64("from_seq").unwrap_or(0),
                get_u64("limit").unwrap_or(200) as usize,
            )
            .map_err(|e| invalid_params_from_app_error(&e))?;
            Ok(AppOperation::FlowEvents(params))
        }
        "flow_list" => {
            let state = match args.get("state").and_then(Value::as_str) {
                None => None,
                Some("active") => Some(StateFilter::Active),
                Some("closed") => Some(StateFilter::Closed),
                Some(_) => return Err(invalid("state")),
            };
            let origin = match args.get("origin").and_then(Value::as_str) {
                None => None,
                Some("stream") => Some(OriginFilter::Stream),
                Some("association") => Some(OriginFilter::Association),
                Some(_) => return Err(invalid("origin")),
            };
            let filter = FlowListFilter::new(
                state,
                origin,
                get_str("generation"),
                get_u64("offset").unwrap_or(0) as usize,
                get_u64("limit").unwrap_or(20) as usize,
            )
            .map_err(|e| invalid_params_from_app_error(&e))?;
            Ok(AppOperation::FlowList(filter))
        }
        "explain" => {
            let proto = get_str("proto").ok_or_else(|| invalid("proto"))?;
            if !matches!(proto.as_str(), "tcp" | "udp" | "quic") {
                return Err(invalid("proto"));
            }
            let domain_source = match args.get("domain_source").and_then(Value::as_str) {
                None | Some("unknown") => rillane_routing::DomainSource::Unknown,
                Some("user_provided") => rillane_routing::DomainSource::UserProvided,
                Some("dns_observed") => rillane_routing::DomainSource::DnsObserved,
                Some("sniffed") => rillane_routing::DomainSource::Sniffed,
                Some(_) => return Err(invalid("domain_source")),
            };
            let process_name = get_str("process_name");
            let process_path = get_str("process_path");
            let process = if process_name.is_none() && process_path.is_none() {
                None
            } else {
                Some(rillane_routing::ProcessEvidence {
                    name: process_name,
                    path: process_path,
                })
            };
            let mut annotations = std::collections::BTreeMap::new();
            if let Some(map) = args.get("annotations").and_then(Value::as_object) {
                for (key, value) in map {
                    let value = value
                        .as_str()
                        .ok_or_else(|| invalid("annotations"))?
                        .to_string();
                    annotations.insert(key.clone(), value);
                }
            }
            Ok(AppOperation::Explain(Box::new(
                rillane_routing::ExplainInput {
                    generation_id: get_str("generation_id")
                        .unwrap_or_else(|| "unpinned".to_string()),
                    ingress: get_str("ingress"),
                    host: get_str("host").ok_or_else(|| invalid("host"))?,
                    port: get_u64("port").ok_or_else(|| invalid("port"))? as u16,
                    proto,
                    domain_source,
                    process,
                    annotations,
                },
            )))
        }
        "probe_submit" => {
            let kind = args.get("kind").and_then(Value::as_str).unwrap_or("");
            let spec = match kind {
                "dns" => crate::ops::ProbeJobSpec::Dns {
                    host: get_str("host").ok_or_else(|| invalid("host"))?,
                },
                "connect" => crate::ops::ProbeJobSpec::Connect {
                    addr: get_str("addr").ok_or_else(|| invalid("addr"))?,
                },
                "udp_echo" => crate::ops::ProbeJobSpec::UdpEcho {
                    addr: get_str("addr").ok_or_else(|| invalid("addr"))?,
                    payload_len: get_u64("payload_len").ok_or_else(|| invalid("payload_len"))?
                        as usize,
                },
                _ => return Err(invalid("kind")),
            };
            Ok(AppOperation::ProbeSubmit(spec))
        }
        "probe_cancel" => Ok(AppOperation::ProbeCancel {
            id: get_u64("id").ok_or_else(|| invalid("id"))?,
        }),
        "probe_result" => Ok(AppOperation::ProbeResult {
            id: get_u64("id").ok_or_else(|| invalid("id"))?,
        }),
        other => Err(
            JsonRpcError::invalid_params(format!("unknown tool: {other}"))
                .with_code_data("mcp.tool.unknown", json!({"tool": other})),
        ),
    }
}

/// 构造期拒绝（AppError）→ -32602（schema 已挡住常规违例——此臂是
/// 一致性兜底，码仍稳定）
fn invalid_params_from_app_error(e: &crate::reply::AppError) -> JsonRpcError {
    JsonRpcError::invalid_params(format!("{}: {}", e.code, e.context))
        .with_code_data("mcp.input.invalid", json!({"code": e.code}))
}

/// 边界答复 → MCP 工具答复形：JSON 信封走 structuredContent（含显式
/// 缺席 found:false——缺席是正常答复），纯文本正文（SVG 导出面）走
/// 纯 content；执行失败走 isError:true 带内稳定码。出口统一过
/// [`crate::tools::cap_result`] 字节闸（RIL-069 响应限长）。
pub fn call_result(reply: &AppReply) -> Value {
    let result = if let Some(text) = &reply.text {
        crate::tools::result_from_text(text)
    } else {
        match reply.json() {
            Some(envelope) => crate::tools::result_from_envelope(envelope),
            // 2xx 且既非 JSON 又非文本不可能出现——防御臂按空信封处理
            None => crate::tools::result_from_envelope(&json!({"schema_version": 1})),
        }
    };
    crate::tools::cap_result(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::codes;
    use serde_json::json;

    #[test]
    fn unknown_tool_and_unknown_fields_rejected_before_operation() {
        let err = build_operation("shell_exec", None).unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
        assert_eq!(err.data.expect("data")["code"], "mcp.tool.unknown");

        let err = build_operation("flow_trace", Some(&json!({"id": "f-1", "raw": 1}))).unwrap_err();
        assert_eq!(err.data.expect("data")["code"], "mcp.input.unknown_field");
    }

    #[test]
    fn read_tools_map_to_boundary_operations() {
        let (op, _) = build_operation("runtime_stats", None).expect("op");
        assert!(matches!(op, AppOperation::RuntimeStats));

        let (op, _) = build_operation(
            "flow_list",
            Some(
                &json!({"state": "closed", "origin": "association", "generation": "gen-1",
                          "offset": 40, "limit": 20}),
            ),
        )
        .expect("op");
        match op {
            AppOperation::FlowList(filter) => {
                assert_eq!(filter.state, Some(StateFilter::Closed));
                assert_eq!(filter.origin, Some(OriginFilter::Association));
                assert_eq!(filter.limit, 20);
                assert_eq!(filter.offset, 40);
            }
            other => panic!("expected flow_list, got {other:?}"),
        }

        // 缺省参数补齐（offset 0 / limit 20——schema 允许缺省）
        let (op, _) = build_operation("flow_list", Some(&json!({}))).expect("op");
        match op {
            AppOperation::FlowList(filter) => {
                assert_eq!(filter.offset, 0);
                assert_eq!(filter.limit, 20);
            }
            other => panic!("expected flow_list, got {other:?}"),
        }

        let (op, _) = build_operation("flow_events", Some(&json!({"id": "f-1"}))).expect("op");
        match op {
            AppOperation::FlowEvents(params) => {
                assert_eq!(params.from_seq, 0);
                assert_eq!(params.limit, 200);
            }
            other => panic!("expected flow_events, got {other:?}"),
        }
    }

    #[test]
    fn explain_and_probe_arguments_map_faithfully() {
        let (op, _) = build_operation(
            "explain",
            Some(&json!({
                "host": "example.com",
                "port": 443,
                "proto": "quic",
                "domain_source": "sniffed",
                "generation_id": "gen-1",
                "process_name": "game.exe",
                "annotations": {"client.cidr": "10.0.0.1/32"},
            })),
        )
        .expect("op");
        match op {
            AppOperation::Explain(input) => {
                assert_eq!(input.host, "example.com");
                assert_eq!(input.proto, "quic");
                assert!(matches!(
                    input.domain_source,
                    rillane_routing::DomainSource::Sniffed
                ));
                assert_eq!(input.generation_id, "gen-1");
                assert_eq!(
                    input.process.as_ref().and_then(|p| p.name.clone()),
                    Some("game.exe".to_string())
                );
                assert_eq!(
                    input.annotations.get("client.cidr").map(String::as_str),
                    Some("10.0.0.1/32")
                );
            }
            other => panic!("expected explain, got {other:?}"),
        }

        // generation 缺省 = unpinned（与 CLI 同口径——不冒充具体代际）
        let (op, _) = build_operation(
            "explain",
            Some(&json!({"host": "h", "port": 1, "proto": "udp"})),
        )
        .expect("op");
        match op {
            AppOperation::Explain(input) => {
                assert_eq!(input.generation_id, "unpinned");
                assert!(input.process.is_none());
            }
            other => panic!("expected explain, got {other:?}"),
        }

        let (op, _) = build_operation(
            "probe_submit",
            Some(&json!({"kind": "udp_echo", "addr": "192.0.2.1:53", "payload_len": 64})),
        )
        .expect("op");
        assert!(matches!(
            op,
            AppOperation::ProbeSubmit(crate::ops::ProbeJobSpec::UdpEcho {
                payload_len: 64,
                ..
            })
        ));

        let (op, _) = build_operation("probe_cancel", Some(&json!({"id": 7}))).expect("op");
        assert!(matches!(op, AppOperation::ProbeCancel { id: 7 }));
    }

    #[test]
    fn reply_shapes_project_to_tool_results() {
        // JSON 信封 → structuredContent（found:false 缺席是正常答复）
        let reply = AppReply {
            status: 200,
            schema_version: Some(1),
            json: Some(json!({"schema_version": 1, "found": false,
                               "absence": {"code": "query.flow.unknown", "note": "n"}})),
            text: None,
        };
        let out = call_result(&reply);
        assert_eq!(out["isError"], false);
        assert_eq!(
            out["structuredContent"]["absence"]["code"],
            "query.flow.unknown"
        );

        // 文本正文（SVG）→ 纯 content、无 structuredContent
        let reply = AppReply {
            status: 200,
            schema_version: None,
            json: None,
            text: Some("<svg/>".to_string()),
        };
        let out = call_result(&reply);
        assert_eq!(out["content"][0]["text"], "<svg/>");
        assert!(out.get("structuredContent").is_none());

        // 执行失败 → isError:true（由 result_from_error 承担——此处
        // 只钉 call_result 不把错误当答复）
        assert_eq!(call_result(&reply)["resultType"], "complete");
    }

    #[test]
    fn oversized_boundary_replies_come_back_capped() {
        // RIL-069 响应限长：边界答复投影统一过字节闸——超限信封以
        // mcp.result.oversize 带内作答，不把无界载荷写给模型
        let big = "x".repeat(crate::mcp::MAX_RESULT_BYTES + 1024);
        let reply = AppReply {
            status: 200,
            schema_version: Some(1),
            json: Some(json!({"schema_version": 1, "blob": big})),
            text: None,
        };
        let out = call_result(&reply);
        assert_eq!(out["isError"], true);
        assert_eq!(
            out["structuredContent"]["error"]["code"],
            "mcp.result.oversize"
        );
    }
}
