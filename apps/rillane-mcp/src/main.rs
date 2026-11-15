//! 可选 stdio MCP 程序（RIL-067，debug-and-mcp.md §5）：显式启动的
//! 本机 stdio 适配器——**默认不启用、不监听任何端口**（无
//! TcpListener；它是控制面的客户端，经 rillane-app 边界（RIL-065）
//! 出站访问守护进程）。
//!
//! stdio 契约（官方 2026-07-28 modern era，RIL-066 冻结）：
//! - stdout **只有**协议消息（一行一条 JSON-RPC）；日志全走 stderr；
//! - EOF（stdin 关闭）→ 干净退出（退出码 0）——进程不遗留后台任务：
//!   探测作业活在守护进程侧（服务端配额/TTL 管束），本进程退出即
//!   不再有调用方；
//! - 单请求限时（边界执行器 [`rillane_app::client::BlockingApp`] 内
//!   置 30 s 上限）——卡死的控制面不会无限占住会话；
//! - 取消：`notifications/cancelled` 登记后，被取消请求的答复**不写**
//!   （官方契约：停止处理、释放资源、不答复；登记集有界，超限挤最旧）。

use clap::Parser;
use rillane_app::client::BlockingApp;
use rillane_app::dispatch;
use rillane_app::mcp::{self, IncomingMessage, JsonRpcError, RequestId, ServerMethod};
use rillane_app::reply::AppError;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::io::BufRead;

/// 取消登记集上限（有界——恶意客户端的取消风暴不涨内存）
const CANCELLED_SET_CAP: usize = 4096;

#[derive(Parser)]
#[command(
    name = "rillane-mcp",
    about = "rillane optional stdio MCP adapter (off by default)"
)]
struct Cli {
    /// 配置文件路径（读 control.api_bind 与 admin_token 作默认值）
    #[arg(short, long, default_value = "config/rillane.yaml")]
    config: String,
    /// 控制面 base URL（覆盖配置）
    #[arg(long)]
    endpoint: Option<String>,
    /// 管理令牌（覆盖配置；只进执行器，不出现在任何答复/日志里）
    #[arg(long)]
    token: Option<String>,
}

/// 会话状态：边界执行器 + 被取消请求登记（有界队列 + 成员集）
struct ServerState {
    app: BlockingApp,
    cancelled_queue: VecDeque<RequestId>,
    cancelled_set: HashSet<RequestId>,
}

impl ServerState {
    fn new(app: BlockingApp) -> Self {
        Self {
            app,
            cancelled_queue: VecDeque::new(),
            cancelled_set: HashSet::new(),
        }
    }

    fn mark_cancelled(&mut self, id: RequestId) {
        if self.cancelled_set.contains(&id) {
            return;
        }
        if self.cancelled_queue.len() >= CANCELLED_SET_CAP {
            if let Some(oldest) = self.cancelled_queue.pop_front() {
                self.cancelled_set.remove(&oldest);
            }
        }
        self.cancelled_queue.push_back(id.clone());
        self.cancelled_set.insert(id);
    }

    fn take_cancelled(&mut self, id: &RequestId) -> bool {
        if self.cancelled_set.contains(id) {
            self.cancelled_set.remove(id);
            self.cancelled_queue.retain(|x| x != id);
            true
        } else {
            false
        }
    }
}

/// 单行处理 → 待写 stdout 的答复（None = 静默——通知/客户端答复/
/// 被取消请求不产生输出）。畸形消息答 -32700/-32600（id 不可知以
/// null 应答——JSON-RPC 2.0 规定）。
fn handle_line(state: &mut ServerState, line: &str) -> Option<Value> {
    match mcp::parse_line(line) {
        Err(err) => Some(mcp::error_response(None, &err)),
        Ok(None) => None,
        Ok(Some(IncomingMessage::Response { .. })) => None,
        Ok(Some(IncomingMessage::Notification { method, params })) => {
            if method == mcp::methods::CANCELLED_NOTIFICATION {
                if let Some(notice) = mcp::parse_cancelled(params.as_ref()) {
                    state.mark_cancelled(notice.request_id);
                }
            }
            None
        }
        Ok(Some(IncomingMessage::Request { id, method, params })) => {
            let outcome = dispatch_request(state, &method, params.as_ref());
            // 取消语义：处理期间收到取消 → 丢弃答复（不写）
            if state.take_cancelled(&id) {
                return None;
            }
            Some(match outcome {
                Ok(result) => mcp::result_response(&id, &result),
                Err(err) => mcp::error_response(Some(&id), &err),
            })
        }
    }
}

/// 请求分派：discover 是探测面（不要求版本声明）；其余逐请求版本门。
/// 工具执行失败是带内答复（isError:true）——只有协议面畸形走
/// JSON-RPC error。
fn dispatch_request(
    state: &mut ServerState,
    method: &str,
    params: Option<&Value>,
) -> Result<Value, JsonRpcError> {
    let classified =
        mcp::classify_request(method).ok_or_else(|| JsonRpcError::method_not_found(method))?;
    match classified {
        ServerMethod::Discover => Ok(mcp::discover_result()),
        ServerMethod::ToolsList => {
            mcp::check_request_version(params)?;
            Ok(rillane_app::tools::tools_list_result())
        }
        ServerMethod::ToolsCall => {
            mcp::check_request_version(params)?;
            let args = params.ok_or_else(|| {
                JsonRpcError::invalid_params("tools/call needs params")
                    .with_code_data("mcp.input.required", serde_json::json!({"field": "params"}))
            })?;
            let name = args.get("name").and_then(Value::as_str).ok_or_else(|| {
                JsonRpcError::invalid_params("tools/call needs a tool name")
                    .with_code_data("mcp.input.required", serde_json::json!({"field": "name"}))
            })?;
            let (op, _tool) = dispatch::build_operation(name, args.get("arguments"))?;
            let started = std::time::Instant::now();
            let reply = state.app.execute(op);
            eprintln!(
                "rillane-mcp: tool {} executed in {:?}",
                name,
                started.elapsed()
            );
            Ok(match reply {
                Ok(reply) => dispatch::call_result(&reply),
                Err(err) => log_and_result(name, &err),
            })
        }
    }
}

/// 执行失败：stderr 记日志（含稳定码，不含上下文正文——正文可能携带
/// 目标/地址等敏感面），带内答 isError:true。
fn log_and_result(tool: &str, err: &AppError) -> Value {
    eprintln!("rillane-mcp: tool {} failed with code {}", tool, err.code);
    rillane_app::tools::result_from_error(err)
}

fn main() {
    let cli = Cli::parse();
    let config = match rillane_config::RillaneConfig::load_from_path(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("rillane-mcp: config load failed: {err}");
            std::process::exit(1);
        }
    };
    let base = cli
        .endpoint
        .unwrap_or_else(|| format!("http://{}", config.control.api_bind));
    let token = cli.token.or(config.control.admin_token.clone());
    let app = match BlockingApp::new(&base, token.as_deref()) {
        Ok(app) => app,
        Err(err) => {
            eprintln!(
                "rillane-mcp: invalid control endpoint: {} ({})",
                err.code, err.context
            );
            std::process::exit(1);
        }
    };
    eprintln!(
        "rillane-mcp: stdio adapter started (protocol {}, no listener port)",
        mcp::PROTOCOL_VERSION
    );
    let mut state = ServerState::new(app);
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("rillane-mcp: stdin read error: {err}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(outgoing) = handle_line(&mut state, &line) {
            // stdout 只走协议（serde 序列化失败不可能——答复是构造的
            // Value；若发生按致命错误退出而不是写出残缺行）
            let text = serde_json::to_string(&outgoing).unwrap_or_else(|err| {
                eprintln!("rillane-mcp: reply serialization failed: {err}");
                std::process::exit(1);
            });
            println!("{text}");
        }
    }
    eprintln!("rillane-mcp: stdin closed, exiting");
    // EOF 干净退出：无后台任务可遗留（探测作业在守护进程侧配额管束）
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn state() -> ServerState {
        ServerState::new(BlockingApp::new("http://127.0.0.1:1", None).expect("app"))
    }

    fn meta_params() -> Value {
        json!({"_meta": {"io.modelcontextprotocol/protocolVersion": mcp::PROTOCOL_VERSION}})
    }

    #[test]
    fn discover_answers_without_version_declaration() {
        // era 探测面：无 _meta 版本也答 DiscoverResult（官方 stdio 探测契约）
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#;
        let out = handle_line(&mut state(), line).expect("answer");
        assert_eq!(out["id"], 1);
        assert_eq!(out["result"]["resultType"], "complete");
        assert_eq!(out["result"]["supportedVersions"][0], mcp::PROTOCOL_VERSION);
    }

    #[test]
    fn version_gate_rejects_legacy_and_missing_declarations() {
        // 无版本声明 → -32022
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let out = handle_line(&mut state(), line).expect("answer");
        assert_eq!(out["error"]["code"], -32022);
        assert_eq!(out["error"]["data"]["supported"][0], mcp::PROTOCOL_VERSION);

        // legacy 版本声明 → -32022 + requested 回显
        let line =
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}"#.to_string();
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["code"], -32022);
        assert_eq!(out["error"]["data"]["requested"], "2025-11-25");
    }

    #[test]
    fn initialize_is_unknown_on_modern_server() {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"initialize","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{}"}}}}}}"#,
            mcp::PROTOCOL_VERSION
        );
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["code"], -32601);
    }

    #[test]
    fn tools_list_carries_catalog_with_version() {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{}"}}}}}}"#,
            mcp::PROTOCOL_VERSION
        );
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["result"]["resultType"], "complete");
        assert_eq!(out["result"]["tools"].as_array().map(Vec::len), Some(11));
    }

    #[test]
    fn unknown_tool_and_bad_arguments_answer_invalid_params() {
        let base = json!({
            "_meta": {"io.modelcontextprotocol/protocolVersion": mcp::PROTOCOL_VERSION},
        });
        let mut unknown = base.clone();
        unknown["name"] = json!("shell_exec");
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{}}}"#,
            unknown
        );
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["code"], -32602);
        assert_eq!(out["error"]["data"]["code"], "mcp.tool.unknown");

        let mut bad = base;
        bad["name"] = json!("flow_trace");
        bad["arguments"] = json!({"id": "f-1", "raw": true});
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}}"#,
            bad
        );
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["data"]["code"], "mcp.input.unknown_field");

        // 缺 name
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{}"}}}}}}"#,
            mcp::PROTOCOL_VERSION
        );
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["data"]["code"], "mcp.input.required");
    }

    #[test]
    fn cancelled_request_answer_is_suppressed() {
        let mut st = state();
        // 正常请求有答复
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{}"}}}}}}"#,
            mcp::PROTOCOL_VERSION
        );
        assert!(handle_line(&mut st, &line).is_some());
        // 取消登记 + 同 id 请求 → 无答复
        let cancel = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9,"reason":"slow"}}"#;
        assert!(handle_line(&mut st, cancel).is_none());
        assert!(handle_line(&mut st, &line).is_none());
        // 登记已消费：再来一次同 id 请求恢复有答复
        assert!(handle_line(&mut st, &line).is_some());
    }

    #[test]
    fn parse_failures_answer_with_null_id() {
        let out = handle_line(&mut state(), "not json").expect("answer");
        assert_eq!(out["error"]["code"], -32700);
        assert_eq!(out["id"], serde_json::Value::Null);
        let out = handle_line(&mut state(), r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)
            .expect("answer");
        assert_eq!(out["error"]["code"], -32600);
    }

    #[test]
    fn tools_call_reaches_boundary_and_projects_envelope() {
        // 单连接应答器：/runtime/stats 回版本化信封——tools/call 端到端
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let body = r#"{"schema_version":1,"collector":{"traces":3}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        let mut st =
            ServerState::new(BlockingApp::new(&format!("http://{addr}"), None).expect("app"));
        let mut params = meta_params();
        params["name"] = json!("runtime_stats");
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{}}}"#,
            params
        );
        let out = handle_line(&mut st, &line).expect("answer");
        assert_eq!(out["id"], 10);
        assert_eq!(out["result"]["resultType"], "complete");
        assert_eq!(out["result"]["isError"], false);
        assert_eq!(out["result"]["structuredContent"]["collector"]["traces"], 3);
    }

    #[test]
    fn cancelled_set_is_bounded() {
        let mut st = state();
        for i in 0..(CANCELLED_SET_CAP + 10) {
            st.mark_cancelled(RequestId::Num(i as i64));
        }
        assert!(st.cancelled_queue.len() <= CANCELLED_SET_CAP);
        // 最旧的被挤出
        assert!(!st.cancelled_set.contains(&RequestId::Num(0)));
        assert!(st
            .cancelled_set
            .contains(&RequestId::Num(CANCELLED_SET_CAP as i64 + 9)));
    }
}
