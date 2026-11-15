//! MCP 协议契约（RIL-066，debug-and-mcp.md §5）：固定协议版本与
//! JSON-RPC 2.0 信封语义。本模块是**纯契约**——只定义线上形状与校验
//! 规则，不做 IO、不装配进程（RIL-067 的 `apps/rillane-mcp` 消费此处）。
//!
//! SDK 策略：不引入任何 MCP SDK（内核独立性承 RIL-065）——协议面以
//! 本模块直接对齐官方规范修订版。版本一次钉死：升级 = 显式改常量 +
//! 契约测试对照官方文本，不随传递依赖漂移。
//!
//! 对照锚点（官方规范 **modern era** 修订版 2026-07-28，2026-11-16 对
//! modelcontextprotocol.io 在线核对——stdio/tools/cancellation/
//! versioning/schema 逐页；debug-and-mcp.md §5 所引三链接同版）：
//! - **无 initialize 握手**（modern era：2026-07-28 起废除 legacy
//!   initialize——`ping`/`notifications/initialized` 同废）；每个请求
//!   在 `params._meta["io.modelcontextprotocol/protocolVersion"]` 声明
//!   协议版本，服务端逐请求接受或拒绝；
//! - 版本不支持的请求 MUST 答 `UnsupportedProtocolVersionError`
//!   （-32022，data 携带 `supported` 列表 + `requested`）；服务端 MUST
//!   实现 `server/discover`（客户端 era 探测 + 版本预查——stdio 客户端
//!   以它先行探测，答错非现代错误即回退 legacy）；
//! - `server/discover` 本身不要求版本声明（它就是探测面）；
//! - stdio 传输：换行分隔 JSON（一条消息不得内嵌换行）、stdout 只走
//!   协议、日志走 stderr；
//! - 取消：`notifications/cancelled`{requestId, reason?}——接收方
//!   SHOULD 停止处理、释放关联资源、**不**答复被取消请求；可忽略
//!   （未知/已完成/不可取消）；客户端丢弃迟到答复；
//! - 错误语义：协议面畸形（未知工具、不合 CallToolRequest schema 的
//!   参数）→ JSON-RPC -32602；工具执行失败 → result.isError=true
//!   （带内）；版本错误 → -32022。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 钉死的协议版本（官方规范 modern era 修订版 2026-07-28；2026-11-16
/// 在线核对为当前最新修订版）。每请求声明、服务端只认此值。
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// stdio 帧行上限（字节）：超长行按解析失败处理——超长输入进不了
/// 工具层（执行器侧硬闸；本常量是契约口径，装配面引用它）。
pub const MAX_LINE_BYTES: usize = 1_048_576;

/// tools/call arguments 序列化字节上限：超限在**分派前**以
/// -32602 + `mcp.input.oversize` 拒绝（请求不进入任何工具执行）。
pub const MAX_ARGUMENTS_BYTES: usize = 64 * 1024;

/// 工具答复字节上限：超限按截断策略处理（带内标注，非错误）——
/// 响应限长是工具面契约（RIL-069/070 落实），常量在此钉住口径。
pub const MAX_RESULT_BYTES: usize = 256 * 1024;

/// 请求 `_meta` 中声明协议版本的保留键（官方 modern era 契约）
pub const META_PROTOCOL_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// `_meta` 中自述服务端身份的保留键（clientInfo 同形；自报值仅作
/// 展示/日志——服务端不得依赖它改行为，更不得用于安全判断）
pub const META_SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// JSON-RPC 2.0 / MCP 规定错误码
pub mod codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    /// 服务端自定义码区间起点（-32000..=-32099 预留）
    pub const SERVER_ERROR_RANGE_START: i32 = -32000;
    pub const SERVER_ERROR_RANGE_END: i32 = -32099;
    /// UnsupportedProtocolVersionError（modern era 版本协商失败固定码）
    pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;
}

/// 本服务端接的请求方法全集（之外一律 -32601——含 legacy 时代的
/// `initialize`：modern 服务端不识别）。通知面另计
/// （`notifications/cancelled`；未知通知静默丢弃）。
pub mod methods {
    pub const DISCOVER: &str = "server/discover";
    pub const TOOLS_LIST: &str = "tools/list";
    pub const TOOLS_CALL: &str = "tools/call";
    pub const CANCELLED_NOTIFICATION: &str = "notifications/cancelled";
}

/// 服务端可分派的请求方法（未知方法 → -32601）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMethod {
    Discover,
    ToolsList,
    ToolsCall,
}

/// 请求方法 → 分派面（None = 未知方法，调用方答 -32601）
pub fn classify_request(method: &str) -> Option<ServerMethod> {
    match method {
        methods::DISCOVER => Some(ServerMethod::Discover),
        methods::TOOLS_LIST => Some(ServerMethod::ToolsList),
        methods::TOOLS_CALL => Some(ServerMethod::ToolsCall),
        _ => None,
    }
}

/// JSON-RPC id（MCP：请求 id 必须为字符串或整数——null/布尔/数组/
/// 对象一律 -32600；官方 schema：Unlike base JSON-RPC, the ID MUST
/// NOT be null）
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RequestId {
    Num(i64),
    Str(String),
}

/// JSON-RPC 错误对象（协议面错误；与带内工具错误 [`crate::reply::
/// AppError`] 分立）
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// 附稳定码数据（`data.code` 是机器口径——客户端按码分支，不解析文案）
    pub fn with_code_data(mut self, code: &str, extra: Value) -> Self {
        self.data = Some(serde_json::json!({"code": code, "detail": extra}));
        self
    }

    pub fn parse_error() -> Self {
        Self::new(codes::PARSE_ERROR, "parse error")
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            codes::METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, message)
    }

    /// UnsupportedProtocolVersionError（-32022）：data 列出本服务端
    /// 支持的版本 + 被拒版本——客户端从 supported 里挑共同版本重试
    pub fn unsupported_protocol_version(requested: Option<&str>) -> Self {
        Self {
            code: codes::UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".to_string(),
            data: Some(serde_json::json!({
                "supported": [PROTOCOL_VERSION],
                "requested": requested,
            })),
        }
    }
}

/// 入站消息三分（请求 / 通知 / 答复）
#[derive(Debug, Clone, PartialEq)]
pub enum IncomingMessage {
    Request {
        id: RequestId,
        method: String,
        params: Option<Value>,
    },
    Notification {
        method: String,
        params: Option<Value>,
    },
    /// 本服务端从不发起请求；客户端答复到达即丢弃（分派层忽略），
    /// 不答错（防错误应答风暴）
    Response { id: Option<RequestId> },
}

/// 单行 → 消息（stdio 传输：一行一条消息）。返回 `Ok(None)` = 静默
/// 丢弃（畸形通知——通知无 id 不可答错）；`Err` = 协议面错误（调用
/// 方以原 id 或 null id 答 JSON-RPC error）。
pub fn parse_line(line: &str) -> Result<Option<IncomingMessage>, JsonRpcError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(JsonRpcError::parse_error());
    }
    let value: Value = serde_json::from_str(line).map_err(|_| JsonRpcError::parse_error())?;
    let obj = value
        .as_object()
        .ok_or_else(|| JsonRpcError::invalid_request("message must be an object"))?;
    let jsonrpc_ok = obj.get("jsonrpc").and_then(Value::as_str) == Some("2.0");
    if !jsonrpc_ok {
        return Err(JsonRpcError::invalid_request("jsonrpc must be exactly 2.0"));
    }

    let id = obj.get("id");
    if let Some(method) = obj.get("method") {
        let method = method
            .as_str()
            .ok_or_else(|| JsonRpcError::invalid_request("method must be a string"))?;
        // params 形合法性与 id 位联动：通知（无 id）不可答错——畸形
        // params 直接丢弃（Ok(None)）；请求可答错（-32602）
        let params_is_object = obj.get("params").is_none_or(Value::is_object);
        match id {
            None => {
                if !params_is_object {
                    return Ok(None);
                }
                Ok(Some(IncomingMessage::Notification {
                    method: method.to_string(),
                    params: obj.get("params").cloned(),
                }))
            }
            Some(id) => {
                let id = parse_request_id(id)?;
                if !params_is_object {
                    return Err(JsonRpcError::invalid_params("params must be an object"));
                }
                Ok(Some(IncomingMessage::Request {
                    id,
                    method: method.to_string(),
                    params: obj.get("params").cloned(),
                }))
            }
        }
    } else {
        // 无 method：只有 id 位合法时才算答复（客户端→服务端答复本
        // 服务端不消费——分派层丢弃）
        match id {
            Some(raw) => {
                let id = parse_request_id(raw)?;
                Ok(Some(IncomingMessage::Response { id: Some(id) }))
            }
            None => Err(JsonRpcError::invalid_request(
                "message needs method or result/error",
            )),
        }
    }
}

/// id 校验：字符串或整数；null/布尔/数组/对象 → -32600
fn parse_request_id(raw: &Value) -> Result<RequestId, JsonRpcError> {
    serde_json::from_value::<RequestId>(raw.clone())
        .map_err(|_| JsonRpcError::invalid_request("id must be a string or number"))
}

/// 请求答复信封
pub fn result_response(id: &RequestId, result: &Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// 错误答复信封（id 不可知时以 null 应答——JSON-RPC 2.0 规定）
pub fn error_response(id: Option<&RequestId>, error: &JsonRpcError) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

/// `server/discover` 答复形（官方 DiscoverResult 契约：版本支持列表、
/// capabilities 与 `_meta` 自述服务端身份）。本服务端不做多版本兼容
/// 面——支持列表恒为单元素（钉死版本策略）。
pub fn discover_result() -> Value {
    serde_json::json!({
        "resultType": "complete",
        "supportedVersions": [PROTOCOL_VERSION],
        "capabilities": {"tools": {}},
        "_meta": {(META_SERVER_INFO_KEY): {"name": "rillane", "version": env!("CARGO_PKG_VERSION")}},
    })
}

/// 逐请求版本校验（`params._meta` 声明协议版本；`server/discover`
/// 除外——它就是探测面）。缺失或不符 → -32022（supported 列表指引
/// 客户端重试）。
pub fn check_request_version(params: Option<&Value>) -> Result<(), JsonRpcError> {
    let requested = params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(META_PROTOCOL_VERSION_KEY))
        .and_then(Value::as_str);
    match requested {
        Some(v) if v == PROTOCOL_VERSION => Ok(()),
        other => Err(JsonRpcError::unsupported_protocol_version(other)),
    }
}

/// 取消通知载荷（`notifications/cancelled`）
#[derive(Debug, Clone, PartialEq)]
pub struct CancelNotice {
    pub request_id: RequestId,
    pub reason: Option<String>,
}

/// 解析取消通知参数。畸形（缺 requestId / requestId 非字符串或整数）
/// → None（通知不可答错，静默丢弃）。语义契约：接收方 SHOULD 停止
/// 处理、释放关联资源、不答复被取消请求；可忽略（未知/已完成/不可
/// 取消）；客户端丢弃迟到答复。
pub fn parse_cancelled(params: Option<&Value>) -> Option<CancelNotice> {
    let params = params?;
    let request_id = params.get("requestId")?;
    let request_id = serde_json::from_value::<RequestId>(request_id.clone()).ok()?;
    Some(CancelNotice {
        request_id,
        reason: params
            .get("reason")
            .and_then(Value::as_str)
            .map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::codes;
    use serde_json::json;

    #[test]
    fn parse_request_notification_and_response() {
        let req = parse_line(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
        )
        .expect("request parses");
        match req {
            Some(IncomingMessage::Request { id, method, params }) => {
                assert_eq!(id, RequestId::Num(7));
                assert_eq!(method, "tools/call");
                assert!(params.expect("params").is_object());
            }
            other => panic!("expected request, got {other:?}"),
        }

        let resp = parse_line(r#"{"jsonrpc":"2.0","id":"abc","result":{}}"#).expect("response");
        assert!(matches!(resp, Some(IncomingMessage::Response { .. })));
    }

    #[test]
    fn protocol_malformations_map_to_stable_codes() {
        let err = parse_line("not json").unwrap_err();
        assert_eq!(err.code, codes::PARSE_ERROR);

        let err = parse_line(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#).unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);

        // id:null（官方 schema：请求 ID MUST NOT be null）
        let err = parse_line(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);

        // id 数组
        let err = parse_line(r#"{"jsonrpc":"2.0","id":[1],"method":"ping"}"#).unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);

        // params 非对象（请求可答错）
        let err = parse_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[1]}"#)
            .unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);

        // 既无 method 又无 id
        let err = parse_line(r#"{"jsonrpc":"2.0"}"#).unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);
    }

    #[test]
    fn notifications_are_never_answered_with_errors() {
        // 未知通知：解析为通知形（分派层忽略——不会答错）
        let unknown = parse_line(r#"{"jsonrpc":"2.0","method":"resources/updated"}"#).expect("ok");
        assert!(matches!(
            unknown,
            Some(IncomingMessage::Notification { .. })
        ));
        // 畸形取消通知（params 形合法但缺 requestId）：通知形保留——
        // 分派层 parse_cancelled 得 None 后忽略
        let bad_cancel =
            parse_line(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#)
                .expect("ok");
        assert!(matches!(
            bad_cancel,
            Some(IncomingMessage::Notification { .. })
        ));
        // params 非对象的通知：不可答错——直接丢弃（Ok(None)）
        let bad_params =
            parse_line(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":[]}"#)
                .expect("ok");
        assert!(bad_params.is_none());
    }

    #[test]
    fn cancelled_notice_carries_request_id_and_reason() {
        let params = json!({"requestId": "req-9", "reason": "user abort"});
        let notice = parse_cancelled(Some(&params)).expect("notice");
        assert_eq!(notice.request_id, RequestId::Str("req-9".into()));
        assert_eq!(notice.reason.as_deref(), Some("user abort"));

        let minimal = json!({"requestId": 42});
        let notice = parse_cancelled(Some(&minimal)).expect("notice");
        assert_eq!(notice.request_id, RequestId::Num(42));
        assert!(notice.reason.is_none());
    }

    #[test]
    fn envelopes_are_versioned_and_id_faithful() {
        let id = RequestId::Str("a1".into());
        let out = result_response(&id, &discover_result());
        assert_eq!(out["jsonrpc"], "2.0");
        assert_eq!(out["id"], "a1");
        assert_eq!(out["result"]["resultType"], "complete");

        let err = JsonRpcError::method_not_found("x");
        let out = error_response(Some(&id), &err);
        assert_eq!(out["error"]["code"], codes::METHOD_NOT_FOUND);

        // id 不可知 → null id
        let out = error_response(None, &JsonRpcError::parse_error());
        assert_eq!(out["id"], serde_json::Value::Null);

        // 字符串 id 原样往返（不做数值化）
        let req = parse_line(r#"{"jsonrpc":"2.0","id":"9","method":"tools/list"}"#)
            .expect("parses")
            .expect("request");
        match req {
            IncomingMessage::Request { id, .. } => assert_eq!(id, RequestId::Str("9".into())),
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn discover_pins_single_supported_version() {
        let d = discover_result();
        assert_eq!(d["resultType"], "complete");
        let versions = d["supportedVersions"].as_array().expect("versions");
        assert_eq!(versions.len(), 1, "钉死版本策略：supported 恒单元素");
        assert_eq!(versions[0], PROTOCOL_VERSION);
        assert_eq!(versions[0], "2026-07-28");
        assert!(d["capabilities"]["tools"].is_object(), "tools 能力面声明");
        let info = &d["_meta"][META_SERVER_INFO_KEY];
        assert_eq!(info["name"], "rillane");
        assert!(info["version"].is_string());
    }

    #[test]
    fn per_request_version_gate_answers_unsupported_protocol_version() {
        // 正确版本放行
        let ok_params = json!({"_meta": {META_PROTOCOL_VERSION_KEY: "2026-07-28"}});
        assert!(check_request_version(Some(&ok_params)).is_ok());

        // 未知版本 → -32022 + supported 列表 + requested 回显
        let old = json!({"_meta": {META_PROTOCOL_VERSION_KEY: "2025-11-25"}});
        let err = check_request_version(Some(&old)).unwrap_err();
        assert_eq!(err.code, codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(err.code, -32022);
        assert_eq!(
            err.data.as_ref().expect("data")["supported"][0],
            "2026-07-28"
        );
        assert_eq!(err.data.expect("data")["requested"], "2025-11-25");

        // 缺版本声明同样 -32022（requested:null——客户端可从 supported
        // 挑版本重试）
        let err = check_request_version(Some(&json!({}))).unwrap_err();
        assert_eq!(err.code, codes::UNSUPPORTED_PROTOCOL_VERSION);

        // legacy 握手方法在现代服务端是未知方法 → -32601（分类面拒绝）
        assert_eq!(classify_request("initialize"), None);
    }

    #[test]
    fn classification_covers_server_surface_only() {
        assert_eq!(
            classify_request("server/discover"),
            Some(ServerMethod::Discover)
        );
        assert_eq!(
            classify_request("tools/list"),
            Some(ServerMethod::ToolsList)
        );
        assert_eq!(
            classify_request("tools/call"),
            Some(ServerMethod::ToolsCall)
        );
        // 资源/提示/采样等未开放面 → None（分派层答 -32601）
        assert_eq!(classify_request("resources/list"), None);
        assert_eq!(classify_request("sampling/createMessage"), None);
        assert_eq!(classify_request("ping"), None);
    }
}
