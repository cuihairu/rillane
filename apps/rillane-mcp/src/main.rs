//! 可选 stdio MCP 程序（RIL-067，debug-and-mcp.md §5）：显式启动的
//! 本机 stdio 适配器——**默认不启用、不监听任何端口**（无
//! TcpListener；它是控制面的客户端，经 rillane-app 边界（RIL-065）
//! 出站访问守护进程）。
//!
//! stdio 契约（官方 2026-07-28 modern era，RIL-066 冻结）：
//! - stdout **只有**协议消息（一行一条 JSON-RPC）；日志全走 stderr；
//! - EOF（stdin 关闭）→ 干净退出（退出码 0）——进程不遗留后台任务：
//!   本会话已提交且未释放的探测作业逐个补发取消（RIL-071；作业本就
//!   受守护进程配额/TTL 管束，补发是会话礼貌）；
//! - 单请求限时（边界执行器 [`rillane_app::client::BlockingApp`] 内
//!   置 30 s 上限）——卡死的控制面不会无限占住会话；
//! - 取消：`notifications/cancelled` 登记后，被取消请求的答复**不写**；
//!   该请求已提交的探测作业同步补发释放（官方契约：停止处理、释放
//!   资源、不答复；登记集有界，超限挤最旧）。
//! - 授权（RIL-068）：授权档**只**来自启动配置（默认只读——最小面），
//!   请求面没有任何字段能改变它（模型声称授权不能升级范围是结构性
//!   保证）；越权/超限在执行前拒绝（稳定码 -32001/-32002），被拒请求
//!   不进入执行、不消耗配额；凭证只进执行器私有字段。

use clap::Parser;
use rillane_app::authz::{self, GrantedScopes, RateLimiter};
use rillane_app::client::BlockingApp;
use rillane_app::dispatch;
use rillane_app::mcp::{self, IncomingMessage, JsonRpcError, RequestId, ServerMethod};
use rillane_app::ops::AppOperation;
use rillane_app::reply::AppError;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::io::BufRead;

/// 取消登记集上限（有界——恶意客户端的取消风暴不涨内存）
const CANCELLED_SET_CAP: usize = 4096;

/// 探测作业追踪上限（RIL-071）：会话最多追踪这么多个「已提交未释放」
/// 的探测作业；溢出挤最旧（追踪是会话礼貌——硬边界在守护进程侧配额）
const PROBE_TRACK_CAP: usize = 256;

/// 速率限制固定窗口宽（每窗 = 每分钟）
const RATE_WINDOW_SECS: u64 = 60;

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
    /// 本会话授权档（逗号分隔 read|detailed|probe|write；默认只读；
    /// 启动期解析失败即退出——不带病运行）
    #[arg(long, default_value = "read")]
    scope: String,
    /// 每分钟窗内工具调用上限（0 = 不限速；默认 60）
    #[arg(long, default_value_t = 60)]
    rate_limit: u32,
}

/// 会话状态：边界执行器 + 授权态（RIL-068：只来自启动配置）+ 被取消
/// 请求登记（有界队列 + 成员集）+ 本会话已提交未释放的探测作业追踪
/// （RIL-071：(请求, 作业) 关联——取消命中或会话退出时补发释放）
struct ServerState {
    app: BlockingApp,
    grants: GrantedScopes,
    rate: RateLimiter,
    cancelled_queue: VecDeque<RequestId>,
    cancelled_set: HashSet<RequestId>,
    probe_jobs: VecDeque<(RequestId, u64)>,
}

impl ServerState {
    fn new(app: BlockingApp, grants: GrantedScopes, rate: RateLimiter) -> Self {
        Self {
            app,
            grants,
            rate,
            cancelled_queue: VecDeque::new(),
            cancelled_set: HashSet::new(),
            probe_jobs: VecDeque::new(),
        }
    }

    /// 登记一次成功提交的探测作业（容量有界——溢出挤最旧；被挤掉的
    /// 作业仍受守护进程配额/TTL 管束，追踪面只欠会话礼貌不欠硬保证）
    fn track_probe_job(&mut self, req: RequestId, job: u64) {
        if self.probe_jobs.len() >= PROBE_TRACK_CAP {
            self.probe_jobs.pop_front();
        }
        self.probe_jobs.push_back((req, job));
    }

    /// 按请求 ID 取出关联作业（取消命中时补发释放——取出即不再追踪）
    fn take_tracked_job(&mut self, req: &RequestId) -> Option<u64> {
        let pos = self.probe_jobs.iter().position(|(r, _)| r == req)?;
        let (_, job) = self.probe_jobs.remove(pos)?;
        Some(job)
    }

    /// 按作业 ID 解除登记（显式 probe_cancel 成功后——EOF 不再重复补发）
    fn forget_job(&mut self, job: u64) {
        self.probe_jobs.retain(|(_, j)| *j != job);
    }

    /// 未释放作业清单（EOF 退出时逐个补发取消）
    fn outstanding_jobs(&self) -> Vec<u64> {
        self.probe_jobs.iter().map(|(_, j)| *j).collect()
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
                    // 迟到的取消（请求已答完）：关联的探测作业若还挂着，
                    // 此刻补发释放——资源随取消归还，不活得比取消久
                    if let Some(job) = state.take_tracked_job(&notice.request_id) {
                        release_probe_job(state, job);
                    }
                    state.mark_cancelled(notice.request_id);
                }
            }
            None
        }
        Ok(Some(IncomingMessage::Request { id, method, params })) => {
            let outcome = dispatch_request(state, &id, &method, params.as_ref());
            // 取消语义：处理期间收到取消 → 丢弃答复（不写）。若该请求
            // 已提交探测作业（取消先于答复到达的竞态），补发释放——
            // 调用方看不到 job_id 不等于作业可以无人认领
            if state.take_cancelled(&id) {
                if let Some(job) = state.take_tracked_job(&id) {
                    release_probe_job(state, job);
                }
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
    id: &RequestId,
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
            // 范围门与限速门（RIL-068）先于参数校验：授权只读工具目录
            // 的服务端档位——请求面字段（声称授权/scope/granted 等）与
            // 工具注解都不参与判定；被拒请求不进入校验/执行、不消耗
            // 配额。未知名无档位可言——落回 build_operation 的 -32602。
            if let Some(tool) = rillane_app::tools::tool(name) {
                if !state.grants.grants(tool.scope) {
                    eprintln!(
                        "rillane-mcp: denied {} (requires {})",
                        name,
                        authz::scope_name(tool.scope)
                    );
                    return Err(authz::scope_denied_error(tool.scope));
                }
                if !state.rate.try_acquire_at(std::time::Instant::now()) {
                    eprintln!("rillane-mcp: rate limited ({})", name);
                    return Err(authz::rate_limited_error(state.rate.window()));
                }
            }
            let (op, _tool) = dispatch::build_operation(name, args.get("arguments"))?;
            // 显式取消面（RIL-071）：取消成功即解除登记——EOF 不再重复补发
            let explicitly_cancelled = match &op {
                AppOperation::ProbeCancel { id: job } => Some(*job),
                _ => None,
            };
            let started = std::time::Instant::now();
            let reply = state.app.execute(op);
            // 探测作业登记（RIL-071）：提交成功即关联 (请求, 作业)——
            // 取消命中或会话退出时补发释放；拒绝不产生作业（服务面契约），
            // 失败答复无可登记面
            if name == "probe_submit" {
                if let Ok(ok_reply) = &reply {
                    if let Some(job) = ok_reply
                        .json()
                        .and_then(|j| j.get("job_id"))
                        .and_then(Value::as_u64)
                    {
                        state.track_probe_job(id.clone(), job);
                    }
                }
            }
            if name == "probe_cancel" && reply.is_ok() {
                if let Some(job) = explicitly_cancelled {
                    state.forget_job(job);
                }
            }
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

/// 会话礼貌释放（RIL-071）：对本会话已提交、尚未释放的探测作业补发
/// 取消。这不是工具调用——不过范围门/限速门、不消耗配额（能留下作业
/// 的会话必然持有 probe 档：范围门已在提交时把守）；尽力而为——失败
/// 只记稳定码（正文可能携带目标面），作业本就受守护进程配额/TTL 管束。
fn release_probe_job(state: &mut ServerState, job: u64) {
    match state.app.execute(AppOperation::ProbeCancel { id: job }) {
        Ok(_) => eprintln!("rillane-mcp: probe job {job} released"),
        Err(err) => {
            eprintln!(
                "rillane-mcp: probe job {job} release failed with code {}",
                err.code
            )
        }
    }
}

/// 释放全部未释放作业（EOF 退出路径）——返回补发数供测试断言；
/// 登记随会话终结一并清空（追踪面已消费）
fn release_outstanding_jobs(state: &mut ServerState) -> usize {
    let outstanding = state.outstanding_jobs();
    for job in &outstanding {
        release_probe_job(state, *job);
    }
    state.probe_jobs.clear();
    outstanding.len()
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
    // 授权档启动期解析（RIL-068）——未知档名/空串退出，不带病运行
    let grants = match GrantedScopes::parse(&cli.scope) {
        Ok(grants) => grants,
        Err(reason) => {
            eprintln!("rillane-mcp: invalid --scope: {reason}");
            std::process::exit(1);
        }
    };
    let rate = RateLimiter::new(
        cli.rate_limit,
        std::time::Duration::from_secs(RATE_WINDOW_SECS),
        std::time::Instant::now(),
    );
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
        "rillane-mcp: stdio adapter started (protocol {}, scopes <{}>, no listener port)",
        mcp::PROTOCOL_VERSION,
        cli.scope
    );
    let mut state = ServerState::new(app, grants, rate);
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
    // EOF 干净退出（RIL-071）：本会话已提交且未释放的探测作业逐个补发
    // 取消（尽力而为——守护进程不在也只记稳定码）；作业本就受守护进程
    // 配额/TTL 管束，补发取消是会话礼貌：探测不活得比会话久
    let released = release_outstanding_jobs(&mut state);
    if released > 0 {
        eprintln!("rillane-mcp: released {released} probe job(s) at exit");
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn state() -> ServerState {
        state_with(GrantedScopes::read_only(), 0)
    }

    /// 自定授权态构造（rate_max = 0 → 不限速）
    fn state_with(grants: GrantedScopes, rate_max: u32) -> ServerState {
        ServerState::new(
            BlockingApp::new("http://127.0.0.1:1", None).expect("app"),
            grants,
            RateLimiter::new(
                rate_max,
                std::time::Duration::from_secs(RATE_WINDOW_SECS),
                std::time::Instant::now(),
            ),
        )
    }

    /// tools/call 请求行构造（带版本声明与 arguments）
    fn call_line(id: u64, name: &str, arguments: Value) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{}"}},"name":"{name}","arguments":{arguments}}}}}"#,
            mcp::PROTOCOL_VERSION
        )
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
        assert_eq!(out["result"]["tools"].as_array().map(Vec::len), Some(16));
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
        // flow_list 是 Read 档——只读会话能到参数校验（畸形字段在
        // 校验面拒绝，与范围门分立）
        bad["name"] = json!("flow_list");
        bad["arguments"] = json!({"raw": true});
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
        let mut st = ServerState::new(
            BlockingApp::new(&format!("http://{addr}"), None).expect("app"),
            GrantedScopes::read_only(),
            RateLimiter::new(
                0,
                std::time::Duration::from_secs(RATE_WINDOW_SECS),
                std::time::Instant::now(),
            ),
        );
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

    #[test]
    fn read_only_session_denies_detailed_and_probe_tools() {
        // 只读档（默认）：详细身份档与探测档在执行前拒绝——稳定码
        // -32001、data 只带所需档名（不带请求回显）
        for (name, args, required) in [
            ("flow_trace", json!({"id": "f-1"}), "detailed"),
            ("flow_events", json!({"id": "f-1"}), "detailed"),
            ("flow_svg", json!({"id": "f-1"}), "detailed"),
            (
                "probe_submit",
                json!({"kind": "dns", "host": "example.com"}),
                "probe",
            ),
            ("probe_cancel", json!({"id": 1}), "probe"),
            // RIL-080：提案登记是写档——只读会话在范围门即拒（预检
            // validate_config 是 Read 档，不在拒列表）
            (
                "preview_config_change",
                json!({"patch": {"telemetry": {}}}),
                "write",
            ),
            // RIL-081：应用/回滚是写档执行面——只读会话在范围门即拒
            (
                "apply_config_change",
                json!({"proposal_id": "p", "approval_id": "a"}),
                "write",
            ),
            ("rollback_config", json!({"target_key": "k"}), "write"),
        ] {
            let line = call_line(20, name, args);
            let out = handle_line(&mut state(), &line).expect("answer");
            assert_eq!(out["error"]["code"], -32001, "tool {name}");
            assert_eq!(
                out["error"]["data"]["code"], "mcp.scope.denied",
                "tool {name}"
            );
            assert_eq!(out["error"]["data"]["required"], required, "tool {name}");
        }
    }

    #[test]
    fn claimed_authorization_in_request_cannot_escalate_scope() {
        // 直接构造调用（携带声称授权的请求面字段：scope/granted/
        // authorized/_meta 附加键）——没有任何字段参与判定，仍按启动档
        // 拒绝（升级范围在结构上不可能：GrantedScopes 只来自启动配置）
        let mut params = meta_params();
        params["name"] = json!("flow_trace");
        params["arguments"] = json!({"id": "f-1"});
        params["scope"] = json!("write");
        params["granted"] = json!(["read", "detailed", "probe", "write"]);
        params["authorized"] = json!(true);
        params["_meta"]["x-rillane-authorized"] = json!(true);
        let line =
            format!(r#"{{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{params}}}"#);
        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["code"], -32001);
        assert_eq!(out["error"]["data"]["required"], "detailed");
    }

    #[test]
    fn granted_scope_reaches_execution_and_scope_gate_precedes_validation() {
        // 探测档会话里 probe_submit 越过范围门进入执行（边界不可达 →
        // 带内 control.unreachable——证明走的是执行路径而非拒绝）；
        // 只读会话里同一请求答 -32001（范围门先于参数校验——被拒请求
        // 不泄露参数面细节、不进入执行）
        let probe = GrantedScopes::parse("read,probe").expect("parse");
        let mut params = meta_params();
        params["name"] = json!("probe_submit");
        params["arguments"] = json!({"kind": "dns", "host": "example.com"});
        let line =
            format!(r#"{{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{params}}}"#);
        let out = handle_line(&mut state_with(probe, 0), &line).expect("answer");
        assert_eq!(out["id"], 22);
        assert_eq!(out["result"]["isError"], true);
        assert_eq!(
            out["result"]["structuredContent"]["error"]["code"],
            "control.unreachable"
        );

        let out = handle_line(&mut state(), &line).expect("answer");
        assert_eq!(out["error"]["code"], -32001);
    }

    #[test]
    fn rate_limit_blocks_excess_calls_in_window() {
        // 每窗 2 次：前两次（执行失败也消耗配额——配额约束的是到达执行
        // 的调用）有带内答复，第三次 -32002
        let mut st = state_with(GrantedScopes::read_only(), 2);
        let line = call_line(23, "runtime_stats", json!({}));
        assert!(handle_line(&mut st, &line).is_some());
        assert!(handle_line(&mut st, &line).is_some());
        let out = handle_line(&mut st, &line).expect("answer");
        assert_eq!(out["error"]["code"], -32002);
        assert_eq!(out["error"]["data"]["code"], "mcp.rate.limited");
        assert_eq!(out["error"]["data"]["window_secs"], RATE_WINDOW_SECS);
    }

    #[test]
    fn denied_calls_do_not_consume_rate_quota() {
        // 越权拒绝不消耗配额：任意多次越权后，合法调用仍按原配额可用
        let mut st = state_with(GrantedScopes::read_only(), 2);
        let denied = call_line(
            24,
            "probe_submit",
            json!({"kind": "dns", "host": "example.com"}),
        );
        for _ in 0..5 {
            let out = handle_line(&mut st, &denied).expect("answer");
            assert_eq!(out["error"]["code"], -32001);
        }
        let line = call_line(25, "runtime_stats", json!({}));
        assert!(handle_line(&mut st, &line).is_some());
        assert!(handle_line(&mut st, &line).is_some());
        let out = handle_line(&mut st, &line).expect("answer");
        assert_eq!(out["error"]["code"], -32002, "合法调用仍按 2 次窗满拒绝");
    }

    #[test]
    fn cli_defaults_are_read_only_with_minute_rate() {
        let cli = Cli::try_parse_from(["rillane-mcp"]).expect("defaults");
        assert_eq!(cli.scope, "read");
        assert_eq!(cli.rate_limit, 60);
        let cli =
            Cli::try_parse_from(["rillane-mcp", "--scope", "read,probe", "--rate-limit", "0"])
                .expect("custom");
        assert_eq!(cli.scope, "read,probe");
        assert_eq!(cli.rate_limit, 0);
        assert!(GrantedScopes::parse(&cli.scope).is_ok());
    }

    #[test]
    fn cancelled_probe_submission_releases_the_job() {
        // 迟到的取消（请求已答完）：提交成功登记 (请求, 作业)，取消命中
        // 即补发 POST /probe/cancel——资源随取消归还，不留无人认领作业
        let (seen, base) = scripted_stub(vec![
            ("HTTP/1.1 200 OK", r#"{"schema_version":1,"job_id":41}"#),
            (
                "HTTP/1.1 200 OK",
                r#"{"schema_version":1,"id":41,"verdict":"cancelled"}"#,
            ),
        ]);
        let mut st = state_probe_at(&base);
        let out = handle_line(
            &mut st,
            &call_line(
                50,
                "probe_submit",
                json!({"kind": "connect", "addr": "203.0.113.9:443"}),
            ),
        )
        .expect("answer");
        assert_eq!(out["result"]["structuredContent"]["job_id"], 41);
        assert_eq!(st.probe_jobs.len(), 1, "提交成功即登记");
        assert!(
            handle_line(&mut st, &cancel_notice(50)).is_none(),
            "取消通知不产生输出"
        );
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 2, "提交 + 释放各恰一次边界请求");
        assert!(requests[0].starts_with("POST /probe"), "{}", requests[0]);
        assert!(requests[0].contains("203.0.113.9:443"));
        assert!(
            requests[1].starts_with("POST /probe/cancel?id=41"),
            "{}",
            requests[1]
        );
        assert!(st.probe_jobs.is_empty(), "释放后追踪清空");
    }

    #[test]
    fn cancelled_before_answer_probe_job_is_still_released() {
        // 取消先于答复到达（投机取消竞态）：probe_submit 执行、job 已
        // 产生、调用方永远看不到 job_id——补发释放把资源收回（孤儿作业
        // 在结构上不可能：登记先于取消检查）
        let (seen, base) = scripted_stub(vec![
            ("HTTP/1.1 200 OK", r#"{"schema_version":1,"job_id":7}"#),
            (
                "HTTP/1.1 200 OK",
                r#"{"schema_version":1,"id":7,"verdict":"cancelled"}"#,
            ),
        ]);
        let mut st = state_probe_at(&base);
        assert!(handle_line(&mut st, &cancel_notice(51)).is_none());
        let out = handle_line(
            &mut st,
            &call_line(
                51,
                "probe_submit",
                json!({"kind": "dns", "host": "example.com"}),
            ),
        );
        assert!(out.is_none(), "被取消请求的答复不写");
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /probe"));
        assert!(
            requests[1].starts_with("POST /probe/cancel?id=7"),
            "{}",
            requests[1]
        );
        assert!(st.probe_jobs.is_empty());
    }

    #[test]
    fn eof_releases_outstanding_probe_jobs() {
        // 会话退出：未释放作业逐个补发取消（探测不活得比会话久）
        let (seen, base) = scripted_stub(vec![
            ("HTTP/1.1 200 OK", r#"{"schema_version":1,"job_id":3}"#),
            (
                "HTTP/1.1 200 OK",
                r#"{"schema_version":1,"id":3,"verdict":"cancelled"}"#,
            ),
        ]);
        let mut st = state_probe_at(&base);
        handle_line(
            &mut st,
            &call_line(
                52,
                "probe_submit",
                json!({"kind": "dns", "host": "example.com"}),
            ),
        )
        .expect("answer");
        assert_eq!(st.outstanding_jobs(), vec![3]);
        assert_eq!(release_outstanding_jobs(&mut st), 1);
        let requests = seen.lock().expect("lock").clone();
        assert!(
            requests[1].starts_with("POST /probe/cancel?id=3"),
            "{}",
            requests[1]
        );
        assert!(st.probe_jobs.is_empty());
    }

    #[test]
    fn explicit_cancel_forgets_tracked_job() {
        // 显式 probe_cancel 成功即解除登记——EOF 退出不再重复补发（作业
        // 的资源已由调用方自己的取消动作归还）
        let (seen, base) = scripted_stub(vec![
            ("HTTP/1.1 200 OK", r#"{"schema_version":1,"job_id":8}"#),
            (
                "HTTP/1.1 200 OK",
                r#"{"schema_version":1,"id":8,"verdict":"cancelled"}"#,
            ),
        ]);
        let mut st = state_probe_at(&base);
        handle_line(
            &mut st,
            &call_line(
                53,
                "probe_submit",
                json!({"kind": "dns", "host": "example.com"}),
            ),
        )
        .expect("answer");
        let out =
            handle_line(&mut st, &call_line(54, "probe_cancel", json!({"id": 8}))).expect("answer");
        assert_eq!(out["result"]["structuredContent"]["verdict"], "cancelled");
        assert!(st.probe_jobs.is_empty());
        assert_eq!(
            release_outstanding_jobs(&mut st),
            0,
            "已显式取消——退出无补发"
        );
        assert_eq!(seen.lock().expect("lock").len(), 2);
    }

    #[test]
    fn out_of_scope_intranet_target_is_rejected_by_daemon_policy() {
        // 任意内网目标被目标策略拒绝：适配层不预审目标（原样转发——
        // 允许/拒绝只由守护进程登记面裁决），拒绝信封原文贯通、拒绝不
        // 产生作业（无登记面可释放）
        let (seen, base) = scripted_stub(vec![(
            "HTTP/1.1 400 Bad Request",
            r#"{"schema_version":1,"error":{"code":"probe.target.out_of_scope","context":"target not in registered probe scope"}}"#,
        )]);
        let mut st = state_probe_at(&base);
        let out = handle_line(
            &mut st,
            &call_line(
                55,
                "probe_submit",
                json!({"kind": "connect", "addr": "192.168.1.1:443"}),
            ),
        )
        .expect("answer");
        assert_eq!(out["result"]["isError"], true);
        assert_eq!(
            out["result"]["structuredContent"]["error"]["code"],
            "probe.target.out_of_scope"
        );
        let requests = seen.lock().expect("lock").clone();
        assert!(requests[0].starts_with("POST /probe"));
        assert!(
            requests[0].contains("192.168.1.1:443"),
            "内网目标原样到达守护进程: {}",
            requests[0]
        );
        assert!(st.probe_jobs.is_empty(), "拒绝不产生作业");
    }

    #[test]
    fn budget_exhausted_answer_passes_through_verbatim() {
        // 单独配额面：预算耗尽显式拒绝（probe.limit.budget）原文贯通
        // ——适配层不吞码、不重试（重试会放大守护进程负载）
        let (seen, base) = scripted_stub(vec![(
            "HTTP/1.1 400 Bad Request",
            r#"{"schema_version":1,"error":{"code":"probe.limit.budget","context":"probe budget exhausted"}}"#,
        )]);
        let mut st = state_probe_at(&base);
        let out = handle_line(
            &mut st,
            &call_line(
                56,
                "probe_submit",
                json!({"kind": "udp_echo", "addr": "203.0.113.9:53", "payload_len": 64}),
            ),
        )
        .expect("answer");
        assert_eq!(
            out["result"]["structuredContent"]["error"]["code"],
            "probe.limit.budget"
        );
        assert_eq!(
            out["result"]["structuredContent"]["error"]["context"],
            "probe budget exhausted"
        );
        assert!(st.probe_jobs.is_empty());
        assert_eq!(seen.lock().expect("lock").len(), 1, "拒绝后无重试、无补发");
    }

    #[test]
    fn probe_job_tracking_is_bounded() {
        // 追踪面有界（溢出挤最旧）——提交风暴不涨内存；硬边界仍在守护
        // 进程配额
        let mut st = state_probe_at("http://127.0.0.1:1");
        for i in 0..PROBE_TRACK_CAP + 9 {
            st.track_probe_job(RequestId::Num(i as i64), i as u64);
        }
        assert_eq!(st.probe_jobs.len(), PROBE_TRACK_CAP);
        assert_eq!(st.outstanding_jobs()[0], 9, "最旧 9 条被挤出");
        assert_eq!(
            *st.outstanding_jobs().last().expect("last"),
            (PROBE_TRACK_CAP + 8) as u64
        );
    }

    #[test]
    fn malicious_answer_data_stays_data_and_protocol_stays_protocol() {
        // 守护进程载荷里的恶意订阅名（零宽 + CRLF + ANSI ESC + 伪 JSON-RPC
        // 文本）只能作为数据贯通：序列化后无裸控制字符（stdout 恒单行——
        // println 一行即一条协议消息，载荷变不成第二条指令）；后续协议
        // 行照常处理（无串扰）
        let payload = r#"{"groups":[{"name":"sub\u200bx\r\nGET /admin HTTP/1.1\u001b[31m{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}","members":[]}]}"#;
        let (seen, base) = capturing_one_shot("HTTP/1.1 200 OK", payload);
        let mut st = state_at(&base);
        let line = call_line(60, "routing_quality", json!({}));
        let out = handle_line(&mut st, &line).expect("answer");
        let _ = seen.lock().expect("lock").clone().expect("one request");
        let sc = &out["result"]["structuredContent"];
        let name = sc["groups"][0]["name"].as_str().expect("name");
        // 数据原文贯通（字节忠实——脱敏是守护进程侧 RIL-057 的契约）
        assert!(name.contains("tools/call"));
        assert!(name.contains('\r') && name.contains('\n'));
        let text = out.to_string();
        assert!(!text.contains('\n'), "答复序列化恒单行");
        assert!(!text.contains('\r'), "无裸回车");
        assert!(!text.contains('\u{1b}'), "无裸 ANSI ESC——控制字符全部转义");
        // 后续协议行照常处理（载荷不串扰协议流）
        let discover = r#"{"jsonrpc":"2.0","id":61,"method":"server/discover"}"#;
        let next = handle_line(&mut st, discover).expect("answer");
        assert_eq!(next["id"], 61);
        assert_eq!(next["result"]["resultType"], "complete");
    }

    #[test]
    fn malicious_flow_id_cannot_inject_boundary_requests() {
        // 恶意 flow id（空格 + & 参数注入 + CRLF 伪请求行）到不了守护
        // 进程第二行：ops 层消毒（控制字符→U+FFFD）+ 执行器值面百分号
        // 编码（& %26 空格 %20）——恰一次边界请求、请求行恒单行
        let payload = r#"{"schema_version":1,"found":true,"trace":{"flow_id":"f-1","events":[]}}"#;
        let (seen, base) = capturing_one_shot("HTTP/1.1 200 OK", payload);
        let mut st = state_at(&base);
        let line = call_line(
            62,
            "flow_trace",
            json!({"id": "f 1&x=2\r\nGET /admin HTTP/1.1"}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        assert_eq!(out["result"]["structuredContent"]["found"], true);
        let request = seen.lock().expect("lock").clone().expect("one request");
        assert_eq!(
            request.matches("GET ").count(),
            1,
            "请求行恰一处 GET——注入文本整体在值面内编码"
        );
        let first = request.lines().next().expect("request line");
        assert!(first.starts_with("GET /trace/flow?id=f%20"), "{first}");
        assert!(
            first.contains("%26x%3D2"),
            "& 编码成参数分隔符之外的值面: {first}"
        );
        assert!(first.contains("%EF%BF%BD"), "CRLF→U+FFFD→编码: {first}");
        assert!(!request.contains("\r\nGET /admin"), "无注入的第二请求行");
    }

    #[test]
    fn oversized_daemon_payload_answers_bounded_without_echo() {
        // 超大结果样本端到端（RIL-069 闸的线上一路）：>256 KiB 载荷 →
        // 有界 mcp.result.oversize 答复——无载荷回显、答复本身有界
        let mut payload = String::from(r#"{"schema_version":1,"blob":""#);
        payload.push_str(&"x".repeat(300_000));
        payload.push_str(r#"","marker":"TOPSECRET-blob-echo-test"}"#);
        let (seen, base) =
            capturing_one_shot("HTTP/1.1 200 OK", Box::leak(payload.into_boxed_str()));
        let mut st = state_at(&base);
        let line = call_line(63, "runtime_stats", json!({}));
        let out = handle_line(&mut st, &line).expect("answer");
        let _ = seen.lock().expect("lock").clone().expect("one request");
        assert_eq!(out["result"]["isError"], true);
        assert_eq!(
            out["result"]["structuredContent"]["error"]["code"],
            "mcp.result.oversize"
        );
        let text = out.to_string();
        assert!(text.len() < 4096, "答复自身有界: {} bytes", text.len());
        assert!(!text.contains("TOPSECRET-blob-echo-test"), "无载荷回显");
    }

    #[test]
    fn detailed_scope_cannot_bypass_probe_gate_or_secrecy() {
        // 详细身份档不能绕过：probe 门对 detailed 档同样关死（错误数据
        // 只带档名——无请求回显）；失败路径答复同样无凭证
        for grants in ["detailed", "read,detailed,write"] {
            let mut st = state_with(GrantedScopes::parse(grants).expect("parse"), 0);
            let line = call_line(
                64,
                "probe_submit",
                json!({"kind": "dns", "host": "example.com"}),
            );
            let out = handle_line(&mut st, &line).expect("answer");
            assert_eq!(out["error"]["code"], -32001, "grants {grants}");
            assert_eq!(out["error"]["data"]["required"], "probe");
            assert!(
                !out.to_string().contains("example.com"),
                "拒绝数据无请求回显"
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let body = r#"{"error":{"code":"control.auth","context":"bad token"}}"#;
                let response = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        let mut st = state_with(GrantedScopes::parse("read,detailed").expect("parse"), 0);
        st.app = BlockingApp::new(&format!("http://{addr}"), Some("sekrit-detailed-token"))
            .expect("app");
        let line = call_line(65, "runtime_stats", json!({}));
        let out = handle_line(&mut st, &line).expect("answer");
        assert_eq!(out["result"]["isError"], true);
        assert!(
            !out.to_string().contains("sekrit-detailed-token"),
            "详细身份档失败答复同样无凭证"
        );
    }

    #[test]
    fn status_quality_answers_are_byte_faithful_envelopes() {
        // /routing/stats 形载荷（守护进程 DTO，无信封版本字段）逐字段
        // 贯通：时效（source=legacy/real）与缺失（p95/loss/gate null）
        // 原样保留——不补零、不发明字段、不改名（与 CLI 消费同一守护
        // 进程载荷——同一端点同一服务，结果一致是结构性事实）
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = r#"{"groups":[{"name":"proxy","strategy":"latency","selected":"node-a","members":[{"name":"node-a","healthy":true,"source":"legacy","p95_ms":null,"loss_ratio":null,"score":null,"gate_pass":null},{"name":"node-b","healthy":false,"source":"real","p95_ms":420,"loss_ratio":0.02,"score":98.0,"gate_pass":false}]}]}"#;
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        let mut st = state_with(GrantedScopes::read_only(), 0);
        // 换上指向一次性应答器的执行器（state_with 默认执行器端口不可达）
        st.app = BlockingApp::new(&format!("http://{addr}"), None).expect("app");
        let line = call_line(30, "routing_quality", json!({}));
        let out = handle_line(&mut st, &line).expect("answer");
        let sc = out["result"]["structuredContent"].clone();
        let expected: Value = serde_json::from_str(payload).expect("payload json");
        assert_eq!(sc, expected, "信封原文贯通——不重排不加工");
        // 时效/缺失语义逐字段显式（legacy 数据源 + null 不当零）
        assert_eq!(sc["groups"][0]["members"][0]["source"], "legacy");
        assert_eq!(sc["groups"][0]["members"][0]["p95_ms"], Value::Null);
        assert_eq!(sc["groups"][0]["members"][1]["gate_pass"], false);
        assert_eq!(sc["groups"][0]["members"][1]["p95_ms"], 420);
    }

    #[test]
    fn admin_token_never_appears_in_answers() {
        // 凭证只进执行器（x-admin-token 头）：成功与失败两路的 stdout
        // 答复都不携带凭证字符串
        for (status, body, expect_error) in [
            (
                "HTTP/1.1 200 OK",
                r#"{"schema_version":1,"collector":{"traces":3}}"#,
                false,
            ),
            (
                "HTTP/1.1 401 Unauthorized",
                r#"{"error":{"code":"control.auth","context":"bad token"}}"#,
                true,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            std::thread::spawn(move || {
                if let Ok((mut sock, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf);
                    let response = format!(
                        "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes());
                }
            });
            let mut st = state_with(GrantedScopes::read_only(), 0);
            st.app =
                BlockingApp::new(&format!("http://{addr}"), Some("sekrit-mcp-token")).expect("app");
            let line = call_line(31, "runtime_stats", json!({}));
            let out = handle_line(&mut st, &line).expect("answer");
            assert_eq!(out["result"]["isError"], expect_error);
            assert!(
                !out.to_string().contains("sekrit-mcp-token"),
                "答复不携带凭证（{status}）"
            );
        }
    }

    /// 一次性捕获应答器：记录完整请求行（GET 查询串或 POST 正文），
    /// 回给定状态与正文——断言面同时覆盖「守护进程收到了什么」与
    /// 「模型看到了什么」。只接受一条连接：一次 tools/call 若隐式发出
    /// 第二个边界请求，将无应答超时而被测试捕获。
    fn capturing_one_shot(
        status: &'static str,
        body: &'static str,
    ) -> (std::sync::Arc<std::sync::Mutex<Option<String>>>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).unwrap_or(0);
                *seen2.lock().expect("lock") = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                let response = format!(
                    "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        (seen, format!("http://{addr}"))
    }

    fn state_at(base: &str) -> ServerState {
        // 连接/轨迹面需详细身份档（flow_trace/flow_events 是
        // DetailedIdentity 档工具——RIL-068 范围门放行）
        let mut st = state_with(GrantedScopes::parse("read,detailed").expect("parse"), 0);
        st.app = BlockingApp::new(base, None).expect("app");
        st
    }

    /// 探测档会话（read,probe——probe_submit/probe_cancel 过 RIL-068 范围门）
    fn state_probe_at(base: &str) -> ServerState {
        let mut st = state_with(GrantedScopes::parse("read,probe").expect("parse"), 0);
        st.app = BlockingApp::new(base, None).expect("app");
        st
    }

    /// 逐连接脚本应答器：按顺序接受 N 条连接、记录每条完整请求行、
    /// 各回脚本里的状态行与正文（每请求一条连接——Connection: close）。
    /// 请求序 = 适配层发出的边界请求序，断言面同时覆盖次序与内容。
    fn scripted_stub(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (std::sync::Arc<std::sync::Mutex<Vec<String>>>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut sock, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).unwrap_or(0);
                seen2
                    .lock()
                    .expect("lock")
                    .push(String::from_utf8_lossy(&buf[..n]).to_string());
                let response = format!(
                    "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        (seen, format!("http://{addr}"))
    }

    fn cancel_notice(id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id},"reason":"user"}}}}"#
        )
    }

    #[test]
    fn flow_list_paging_reaches_daemon_and_totals_stay_honest() {
        // 分页参数原样到达守护进程查询串；匹配总数诚实贯通——查询
        // 服务口径（匹配总数 + 近期优先）不被适配层改写
        let payload = r#"{"schema_version":1,"total":42,"returned":2,"flows":[
            {"flow_id":"f-a","generation":"g-9","origin":"stream","state":"closed"},
            {"flow_id":"f-b","generation":"g-9","origin":"association","state":"closed"}]}"#;
        let (seen, base) = capturing_one_shot("HTTP/1.1 200 OK", payload);
        let mut st = state_at(&base);
        let line = call_line(
            40,
            "flow_list",
            json!({"state": "closed", "origin": "stream", "generation": "gen-1",
                   "offset": 40, "limit": 2}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        let request = seen.lock().expect("lock").clone().expect("one request");
        assert!(
            request.starts_with(
                "GET /trace/flows?state=closed&origin=stream&generation=gen-1&offset=40&limit=2"
            ),
            "分页与过滤参数原样到达守护进程: {request}"
        );
        let expected: Value = serde_json::from_str(payload).expect("payload");
        assert_eq!(out["result"]["structuredContent"], expected, "信封原文贯通");
        assert_eq!(out["result"]["structuredContent"]["total"], 42);
    }

    #[test]
    fn flow_trace_and_events_preserve_generation_and_evidence_kinds() {
        // 代际与证据类型贯通：predicted/observed 逐事件原样保留（RIL-051
        // 口径——证据类型不混淆），代际 g-9 不被适配层改写
        let payload = r#"{"schema_version":1,"found":true,"trace":{
            "flow_id":"f-1","generation":"g-9","events":[
            {"seq":0,"stage":"rule","code":"route.selected","evidence":"predicted"},
            {"seq":1,"stage":"egress","code":"egress.established","evidence":"observed"},
            {"seq":2,"stage":"close","code":"association.reclaimed","evidence":"observed"}]}}"#;
        let (seen, base) = capturing_one_shot("HTTP/1.1 200 OK", payload);
        let mut st = state_at(&base);
        let line = call_line(41, "flow_trace", json!({"id": "f-1"}));
        let out = handle_line(&mut st, &line).expect("answer");
        let request = seen.lock().expect("lock").clone().expect("one request");
        assert!(request.starts_with("GET /trace/flow?id=f-1"), "{request}");
        let expected: Value = serde_json::from_str(payload).expect("payload");
        assert_eq!(out["result"]["structuredContent"], expected);
        let events = out["result"]["structuredContent"]["trace"]["events"]
            .as_array()
            .expect("events");
        assert_eq!(events[0]["evidence"], "predicted");
        assert_eq!(events[1]["evidence"], "observed");
        assert_eq!(
            out["result"]["structuredContent"]["trace"]["generation"],
            "g-9"
        );

        // 增量页：from_seq/limit 到达查询串
        let (seen, base) = capturing_one_shot("HTTP/1.1 200 OK", payload);
        let mut st = state_at(&base);
        let line = call_line(
            42,
            "flow_events",
            json!({"id": "f-1", "from_seq": 5, "limit": 50}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        let request = seen.lock().expect("lock").clone().expect("one request");
        assert!(
            request.starts_with("GET /trace/events?id=f-1&from_seq=5&limit=50"),
            "{request}"
        );
        assert_eq!(out["result"]["structuredContent"]["found"], true);
    }

    #[test]
    fn explain_posts_sanitized_input_and_answers_conditionality_verbatim() {
        // 纯推演面：POST /explain 零副作用（RIL-054 契约——无 DNS/拨号/
        // OS 查询），输入消毒在 ops 层（RIL-065 钉住），答复的条件性
        // 结论 + 证据缺口 + 输入摘要原文贯通——条件性不冒充确定
        let payload = r#"{"schema_version":1,"explain":{
            "conclusion":{"chain":["A"],"matched":false,"conditional":true},
            "gaps":["process annotation missing","geo database unloaded"],
            "input_digest":"3f7a…"} }"#;
        let (seen, base) = capturing_one_shot("HTTP/1.1 200 OK", payload);
        let mut st = state_at(&base);
        let line = call_line(
            43,
            "explain",
            json!({"host": "example.com", "port": 443, "proto": "tcp",
                   "process_name": "game.exe"}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        let request = seen.lock().expect("lock").clone().expect("one request");
        assert!(request.starts_with("POST /explain"), "{request}");
        assert!(request.contains(r#""host":"example.com""#), "{request}");
        assert!(request.contains(r#""proto":"tcp""#), "{request}");
        let expected: Value = serde_json::from_str(payload).expect("payload");
        assert_eq!(out["result"]["structuredContent"], expected);
        let sc = &out["result"]["structuredContent"];
        assert_eq!(sc["explain"]["conclusion"]["conditional"], true);
        assert_eq!(sc["explain"]["conclusion"]["matched"], false);
        assert_eq!(sc["explain"]["gaps"].as_array().map(Vec::len), Some(2));
    }

    /// RIL-080 端点隔离：validate_config（Read 档）恰一次请求打到
    /// /config/preview（只读投影——不触提案路径）；预检面透传为
    /// structuredContent（daemon 侧已脱敏）。
    #[test]
    fn validate_config_hits_preview_only() {
        let payload = r#"{"schema_version":1,"applicable":true,"diff":[{"op":"changed","path":"telemetry.log_level","before":"info","after":"debug"}],"diagnostics":[]}"#;
        let (seen, base) = scripted_stub(vec![("HTTP/1.1 200 OK", payload)]);
        let mut st = state_with(GrantedScopes::parse("read").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        let line = call_line(
            44,
            "validate_config",
            json!({"patch": {"telemetry": {"log_level": "debug"}}}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 1, "预检恰一次边界请求");
        assert!(
            requests[0].starts_with("POST /config/preview"),
            "{}",
            requests[0]
        );
        assert!(
            !requests[0].contains("/config/proposals"),
            "预检不触提案路径——只读会话无登记面"
        );
        assert_eq!(out["result"]["isError"], false);
        let sc = &out["result"]["structuredContent"];
        assert_eq!(sc["applicable"], true);
        assert_eq!(sc["diff"][0]["path"], "telemetry.log_level");
    }

    /// RIL-080 提案登记：写档会话 preview_config_change 打到
    /// /config/proposals；**owner 由适配器固定**（请求体 owner 恒
    /// "mcp"——模型面无 owner 字段，冒充他人在结构上不可能）；答复
    /// 携服务端提案 ID + 提案期预检（激活仍不在工具面——批准与应用
    /// 归操作员/独立授权）。
    #[test]
    fn write_session_proposes_with_fixed_owner() {
        let payload = r#"{"schema_version":1,"id":"prop-1","base_generation":"g1","base_hash":"h1","owner":"mcp","scope":["telemetry"],"created_ms":1,"expires_ms":2,"preview":{"applicable":true,"diff":[],"diagnostics":[]}}"#;
        let (seen, base) = scripted_stub(vec![("HTTP/1.1 201 Created", payload)]);
        let mut st = state_with(GrantedScopes::parse("read,write").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        let line = call_line(
            45,
            "preview_config_change",
            json!({"patch": {"telemetry": {"log_level": "debug"}}}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("POST /config/proposals"),
            "{}",
            requests[0]
        );
        assert!(
            requests[0].contains(r#""owner":"mcp""#),
            "owner 适配器固定: {}",
            requests[0]
        );
        assert_eq!(out["result"]["isError"], false);
        let sc = &out["result"]["structuredContent"];
        assert_eq!(sc["id"], "prop-1", "服务端提案 ID 透传");
        assert_eq!(sc["preview"]["applicable"], true);
        assert_eq!(sc["expires_ms"], 2, "限制面（有效期）透传");
    }

    /// RIL-080：只读会话 preview_config_change 被范围门拒（-32001）且
    /// 不产生任何边界请求（被拒请求不进入执行）。
    #[test]
    fn read_only_session_cannot_propose_config_change() {
        let (seen, base) = scripted_stub(vec![("HTTP/1.1 200 OK", "{}")]);
        let mut st = state_with(GrantedScopes::parse("read").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        let line = call_line(
            46,
            "preview_config_change",
            json!({"patch": {"telemetry": {}}}),
        );
        let out = handle_line(&mut st, &line).expect("answer");
        assert_eq!(out["error"]["code"], -32001);
        assert_eq!(out["error"]["data"]["required"], "write");
        assert_eq!(
            seen.lock().expect("lock").len(),
            0,
            "被拒请求不进入执行——无边界请求"
        );
    }

    /// RIL-081 应用面：apply_config_change 恰一次打到 /config/apply；
    /// owner 适配器固定 + 幂等键缺省确定性派生（同参重试领同一键——
    /// 服务端按键回放同一回执，重复调用天然安全）。凭证（proposal_id/
    /// approval_id）必须由操作员签发后经参数进入——工具面没有
    /// 「自批准」入口。
    #[test]
    fn apply_consumes_operator_credentials_with_derived_key() {
        let payload = r#"{"schema_version":1,"seq":7,"kind":"apply","proposal_id":"p1","approval_id":"a1","generation":"g2","label":"mcp-p1-a1"}"#;
        let (seen, base) = scripted_stub(vec![
            ("HTTP/1.1 200 OK", payload),
            ("HTTP/1.1 200 OK", payload),
        ]);
        let mut st = state_with(GrantedScopes::parse("read,write").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        let args = json!({"proposal_id": "p1", "approval_id": "a1"});
        let first = handle_line(&mut st, &call_line(47, "apply_config_change", args.clone()))
            .expect("answer");
        let replay =
            handle_line(&mut st, &call_line(48, "apply_config_change", args)).expect("answer");
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 2, "两次调用各一次边界请求");
        for request in &requests {
            assert!(request.starts_with("POST /config/apply"), "{request}");
            assert!(
                request.contains(r#""owner":"mcp""#),
                "owner 适配器固定: {request}"
            );
            assert!(
                request.contains(r#""idempotency_key":"mcp-p1-a1""#),
                "缺省幂等键确定性派生: {request}"
            );
        }
        assert_eq!(first["result"]["isError"], false);
        assert_eq!(replay["result"]["structuredContent"]["label"], "mcp-p1-a1");
    }

    /// RIL-081 回滚两阶段：无凭证 → /config/rollback-proposal（登记
    /// 待批准提案，owner 固定 + 限制面 ttl）；双凭证 → /config/rollback
    /// （回滚专用键前缀 mcp-rb-，drain 缺省不入体、显式值透传）。
    /// 半凭证在参数校验面即拒——不产生边界请求。
    #[test]
    fn rollback_two_phase_hits_distinct_endpoints() {
        let proposal = r#"{"schema_version":1,"id":"rb-p1","base_generation":"g2","base_hash":"h2","owner":"mcp","scope":[],"created_ms":1,"expires_ms":2,"preview":{"applicable":true,"diff":[],"diagnostics":[]}}"#;
        let receipt = r#"{"schema_version":1,"seq":8,"kind":"rollback","target_key":"k-1","generation":"g1","label":"mcp-rb-rb9-a7"}"#;
        let (seen, base) = scripted_stub(vec![
            ("HTTP/1.1 201 Created", proposal),
            ("HTTP/1.1 200 OK", receipt),
        ]);
        let mut st = state_with(GrantedScopes::parse("read,write").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");

        // 阶段一：准备（无凭证参数）
        let out = handle_line(
            &mut st,
            &call_line(49, "rollback_config", json!({"target_key": "k-1"})),
        )
        .expect("answer");
        assert_eq!(out["result"]["isError"], false);
        assert_eq!(out["result"]["structuredContent"]["id"], "rb-p1");

        // 阶段二：执行（操作员批准后的双凭证 + 显式 drain）
        let out = handle_line(
            &mut st,
            &call_line(
                50,
                "rollback_config",
                json!({"target_key": "k-1", "proposal_id": "rb9", "approval_id": "a7",
                       "drain_deadline_ms": 1_500}),
            ),
        )
        .expect("answer");
        assert_eq!(out["result"]["isError"], false);
        assert_eq!(out["result"]["structuredContent"]["generation"], "g1");

        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0].starts_with("POST /config/rollback-proposal"),
            "{}",
            requests[0]
        );
        assert!(requests[0].contains(r#""owner":"mcp""#), "{}", requests[0]);
        assert!(
            requests[0].contains(r#""ttl_ms":60000"#),
            "限制面与提案同口径: {}",
            requests[0]
        );
        assert!(
            requests[1].starts_with("POST /config/rollback"),
            "{}",
            requests[1]
        );
        assert!(requests[1].contains(r#""owner":"mcp""#), "{}", requests[1]);
        assert!(
            requests[1].contains(r#""idempotency_key":"mcp-rb-rb9-a7""#),
            "回滚键专用前缀: {}",
            requests[1]
        );
        assert!(
            requests[1].contains(r#""drain_deadline_ms":1500"#),
            "显式 drain 透传: {}",
            requests[1]
        );
    }

    /// RIL-081 审计面：config_audit 是 Read 档——只读会话即可读回执链
    /// （GET /config/receipts，恰一次请求）。
    #[test]
    fn config_audit_reads_receipts_under_read_scope() {
        let payload = r#"{"schema_version":1,"receipts":[{"seq":7,"kind":"apply","label":"mcp-p1-a1"}],"reconcile":{"in_sync":true}}"#;
        let (seen, base) = scripted_stub(vec![("HTTP/1.1 200 OK", payload)]);
        let mut st = state_with(GrantedScopes::parse("read").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        let out = handle_line(&mut st, &call_line(51, "config_audit", json!({}))).expect("answer");
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("GET /config/receipts"),
            "{}",
            requests[0]
        );
        assert_eq!(out["result"]["isError"], false);
        let sc = &out["result"]["structuredContent"];
        assert_eq!(sc["receipts"][0]["seq"], 7);
        assert_eq!(sc["reconcile"]["in_sync"], true);
    }

    /// RIL-081 稳定码贯通：服务端冲突（409 apply.base.conflict）→
    /// isError 答复 + 稳定码进 structuredContent——失败理由不含敏感
    /// 值（context 为守护进程侧稳定文案）。
    #[test]
    fn apply_conflict_answers_stable_code() {
        let body = r#"{"error":{"code":"apply.base.conflict","context":"base generation moved"}}"#;
        let (seen, base) = scripted_stub(vec![("HTTP/1.1 409 Conflict", body)]);
        let mut st = state_with(GrantedScopes::parse("read,write").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        let out = handle_line(
            &mut st,
            &call_line(
                52,
                "apply_config_change",
                json!({"proposal_id": "p1", "approval_id": "a1"}),
            ),
        )
        .expect("answer");
        let _ = seen.lock().expect("lock").clone();
        assert_eq!(out["result"]["isError"], true);
        assert_eq!(
            out["result"]["structuredContent"]["error"]["code"],
            "apply.base.conflict"
        );
    }

    /// RIL-081 半凭证即拒：回滚只带一侧凭证不是授权面——参数校验面
    /// 拒绝（mcp.input.invalid）且零边界请求。
    #[test]
    fn rollback_half_credentials_rejected_before_boundary() {
        let (seen, base) = scripted_stub(vec![("HTTP/1.1 200 OK", "{}")]);
        let mut st = state_with(GrantedScopes::parse("read,write").expect("parse"), 0);
        st.app = BlockingApp::new(&base, None).expect("app");
        for half in [
            json!({"target_key": "k-1", "proposal_id": "rb9"}),
            json!({"target_key": "k-1", "approval_id": "a7"}),
        ] {
            let out = handle_line(&mut st, &call_line(53, "rollback_config", half.clone()))
                .expect("answer");
            assert_eq!(out["error"]["code"], -32602, "{half}");
            assert_eq!(out["error"]["data"]["code"], "mcp.input.invalid", "{half}");
        }
        assert_eq!(
            seen.lock().expect("lock").len(),
            0,
            "半凭证不产生任何边界请求"
        );
    }
}
