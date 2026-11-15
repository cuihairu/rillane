//! 闭合操作集（RIL-065）：每一个诊断/配置调用都有名有型有界。请求
//! 行由 [`AppOperation::request`] 纯函数构造——路径是 `&'static str`
//! 常量、参数是类型化字段，**不存在**「任意方法+路径」的构造入口；
//! 新增操作必须在此枚举登记并通过形状契约测试（tests/app_contract.rs
//! 穷尽匹配无通配臂——漏臂编译失败）。

use rillane_core::redact::sanitize_untrusted;
use rillane_routing::ExplainInput;
use serde::Serialize;

/// HTTP 方法面（本边界只读为主 + 显式动作 POST——无 DELETE/PUT；
/// 原始管理员面（订阅增删/配置写/历史清除）不在本边界）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    /// 线上方法名（恒定大写）
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// 由操作构造的请求行：固定路径 + 类型化参数 + 版本化体。
/// 执行器（CLI blocking / 未来 MCP 异步）只负责发出去——不做任何决策。
#[derive(Debug, Clone, PartialEq)]
pub struct OpRequest {
    pub method: Method,
    pub path: &'static str,
    pub query: Vec<(&'static str, String)>,
    pub body: Option<serde_json::Value>,
}

/// 流状态过滤（线值冻结：active | closed）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFilter {
    Active,
    Closed,
}

impl StateFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            StateFilter::Active => "active",
            StateFilter::Closed => "closed",
        }
    }
}

/// 流起止语义过滤（线值冻结：stream | association）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginFilter {
    Stream,
    Association,
}

impl OriginFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            OriginFilter::Stream => "stream",
            OriginFilter::Association => "association",
        }
    }
}

/// 流列表过滤（逐字段可选；generation 经不可信文本消毒入查询串）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowListFilter {
    pub state: Option<StateFilter>,
    pub origin: Option<OriginFilter>,
    pub generation: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

impl FlowListFilter {
    /// 构造 + 客户端侧校验（值面冻结——非法值不发请求；limit=0 服务端
    /// 按 `query.page.invalid` 拒绝，客户端先行同码拒绝）
    pub fn new(
        state: Option<StateFilter>,
        origin: Option<OriginFilter>,
        generation: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<Self, crate::reply::AppError> {
        if limit == 0 {
            return Err(crate::reply::AppError::param(
                "query.page.invalid",
                "limit must be at least 1",
            ));
        }
        Ok(Self {
            state,
            origin,
            generation,
            offset,
            limit,
        })
    }
}

/// 事件增量读取参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEventsParams {
    pub id: String,
    pub from_seq: u64,
    pub limit: usize,
}

impl FlowEventsParams {
    pub fn new(id: String, from_seq: u64, limit: usize) -> Result<Self, crate::reply::AppError> {
        if limit == 0 {
            return Err(crate::reply::AppError::param(
                "query.page.invalid",
                "limit must be at least 1",
            ));
        }
        Ok(Self {
            id,
            from_seq,
            limit,
        })
    }
}

/// 探测提交规格（线形与控制面提交体同构：显式 `kind` 标签、addr 为
/// `ip:port` 文本、无自由文本目标——范围校验在服务端登记表）
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeJobSpec {
    Dns { host: String },
    Connect { addr: String },
    UdpEcho { addr: String, payload_len: usize },
}

/// MCP 配置提案的所有者标签（适配器固定——模型不能自选 owner，冒充
/// 他人提案在结构上不可能；批准与应用仍是操作员/独立授权面的事）。
pub const MCP_PROPOSAL_OWNER: &str = "mcp";

/// MCP 配置提案默认有效期（毫秒；与 CLI 默认同口径）。
pub const MCP_PROPOSE_TTL_MS: u64 = 60_000;

/// 闭合操作集：CLI/UI/MCP 能对本边界发出的**全部**调用。
/// （配置变更面经 RIL-073+ 提案生命周期另行进入；原始配置读/
/// 订阅 URL 是管理员-grade 面，刻意不在本边界。）
#[derive(Debug, Clone, PartialEq)]
pub enum AppOperation {
    /// 运行时总览（GET /runtime/stats）
    RuntimeStats,
    /// 组实时质量（GET /routing/stats——get_policy_quality 面）
    RoutingQuality,
    /// 活动/近期连接分页列表（GET /trace/flows）
    FlowList(FlowListFilter),
    /// 单流完整轨迹或显式缺席（GET /trace/flow）
    FlowTrace { id: String },
    /// 流事件增量读取（GET /trace/events）
    FlowEvents(FlowEventsParams),
    /// 流路径图 SVG（GET /trace/flow.svg）
    FlowSvg { id: String },
    /// 纯路由推演（POST /explain——生产求值器 + 冻结快照，无副作用）
    Explain(Box<ExplainInput>),
    /// 探测作业列表（GET /probe——纯读，网络副作用只经 Submit）
    ProbeList,
    /// 显式发起探测（POST /probe——本边界唯一的网络副作用入口，
    /// 授权/配额在服务端）
    ProbeSubmit(ProbeJobSpec),
    /// 取消探测作业（POST /probe/cancel）
    ProbeCancel { id: u64 },
    /// 探测作业结果（GET /probe/result）
    ProbeResult { id: u64 },
    /// 配置补丁预检（POST /config/preview——只读投影：现役为基的
    /// 规范化 diff/诊断/范围越界，秘密值脱敏；不落提案、不激活任何
    /// 配置。RIL-080）
    ConfigPreview {
        patch: serde_json::Value,
        scope: Option<Vec<String>>,
    },
    /// 配置变更提案（POST /config/proposals——服务端提案 ID + 提案期
    /// 预检投影；owner 由适配器固定 [`MCP_PROPOSAL_OWNER`]，不经模型；
    /// 批准与应用不在本操作——激活须操作员另行完成。RIL-080）
    ConfigPropose {
        patch: serde_json::Value,
        scope: Vec<String>,
        ttl_ms: u64,
    },
    /// 配置审计（GET /config/receipts——回执链 seq 降序 + reconcile
    /// 对账摘要，只读。RIL-081）
    ConfigAudit,
    /// 应用配置提案（POST /config/apply——消费**操作员签发**的批准
    /// 凭证；幂等键由 dispatch 缺省派生 [`MCP_PROPOSAL_OWNER`] 归属
    /// 不变。凭证签发不在本边界。RIL-081）
    ConfigApply {
        proposal_id: String,
        approval_id: String,
        idempotency_key: String,
    },
    /// 回滚准备（POST /config/rollback-proposal——目标回执须在册、
    /// Applied 且属于 [`MCP_PROPOSAL_OWNER`]；答复是待批准提案，
    /// 激活仍须操作员批准。RIL-081）
    ConfigRollbackPrepare { target_key: String },
    /// 回滚执行（POST /config/rollback——消费操作员对回滚提案的凭证；
    /// 盲覆盖防线/候选恢复/连接真相归服务端。RIL-081）
    ConfigRollbackExecute {
        target_key: String,
        proposal_id: String,
        approval_id: String,
        idempotency_key: String,
        drain_deadline_ms: Option<u64>,
    },
}

impl AppOperation {
    /// 操作的稳定机器名（错误消息与后续 MCP 工具名共用此口径）
    pub fn name(&self) -> &'static str {
        match self {
            AppOperation::RuntimeStats => "runtime_stats",
            AppOperation::RoutingQuality => "routing_quality",
            AppOperation::FlowList(_) => "flow_list",
            AppOperation::FlowTrace { .. } => "flow_trace",
            AppOperation::FlowEvents(_) => "flow_events",
            AppOperation::FlowSvg { .. } => "flow_svg",
            AppOperation::Explain(_) => "explain",
            AppOperation::ProbeList => "probe_list",
            AppOperation::ProbeSubmit(_) => "probe_submit",
            AppOperation::ProbeCancel { .. } => "probe_cancel",
            AppOperation::ProbeResult { .. } => "probe_result",
            AppOperation::ConfigPreview { .. } => "validate_config",
            AppOperation::ConfigPropose { .. } => "preview_config_change",
            AppOperation::ConfigAudit => "config_audit",
            AppOperation::ConfigApply { .. } => "apply_config_change",
            AppOperation::ConfigRollbackPrepare { .. } => "rollback_config",
            AppOperation::ConfigRollbackExecute { .. } => "rollback_config",
        }
    }

    /// 请求行构造（纯函数）：消毒只发生在进入查询串的不可信字段——
    /// 控制字符进不了 URL，长度有界，同输入同输出。
    pub fn request(&self) -> Result<OpRequest, crate::reply::AppError> {
        match self {
            AppOperation::RuntimeStats => Ok(OpRequest {
                method: Method::Get,
                path: "/runtime/stats",
                query: Vec::new(),
                body: None,
            }),
            AppOperation::RoutingQuality => Ok(OpRequest {
                method: Method::Get,
                path: "/routing/stats",
                query: Vec::new(),
                body: None,
            }),
            AppOperation::FlowList(filter) => {
                let mut query: Vec<(&'static str, String)> = Vec::new();
                if let Some(state) = filter.state {
                    query.push(("state", state.as_str().to_string()));
                }
                if let Some(origin) = filter.origin {
                    query.push(("origin", origin.as_str().to_string()));
                }
                if let Some(gen_id) = &filter.generation {
                    query.push(("generation", sanitize_untrusted(gen_id, 128)));
                }
                query.push(("offset", filter.offset.to_string()));
                query.push(("limit", filter.limit.to_string()));
                Ok(OpRequest {
                    method: Method::Get,
                    path: "/trace/flows",
                    query,
                    body: None,
                })
            }
            AppOperation::FlowTrace { id } => Ok(OpRequest {
                method: Method::Get,
                path: "/trace/flow",
                query: vec![("id", sanitize_untrusted(id, 256))],
                body: None,
            }),
            AppOperation::FlowEvents(params) => Ok(OpRequest {
                method: Method::Get,
                path: "/trace/events",
                query: vec![
                    ("id", sanitize_untrusted(&params.id, 256)),
                    ("from_seq", params.from_seq.to_string()),
                    ("limit", params.limit.to_string()),
                ],
                body: None,
            }),
            AppOperation::FlowSvg { id } => Ok(OpRequest {
                method: Method::Get,
                path: "/trace/flow.svg",
                query: vec![("id", sanitize_untrusted(id, 256))],
                body: None,
            }),
            AppOperation::Explain(input) => {
                let mut body = serde_json::to_value(input.as_ref()).map_err(|e| {
                    crate::reply::AppError::param("explain.input.invalid", &e.to_string())
                })?;
                // 序列化后消毒回显面字段（host/ingress/进程证据/注解——
                // 不可信文本进不了诊断输出）
                sanitize_explain_body(&mut body);
                Ok(OpRequest {
                    method: Method::Post,
                    path: "/explain",
                    query: Vec::new(),
                    body: Some(body),
                })
            }
            AppOperation::ProbeList => Ok(OpRequest {
                method: Method::Get,
                path: "/probe",
                query: Vec::new(),
                body: None,
            }),
            AppOperation::ProbeSubmit(spec) => {
                let body = serde_json::to_value(spec).map_err(|e| {
                    crate::reply::AppError::param("probe.param.invalid", &e.to_string())
                })?;
                Ok(OpRequest {
                    method: Method::Post,
                    path: "/probe",
                    query: Vec::new(),
                    body: Some(body),
                })
            }
            AppOperation::ProbeCancel { id } => Ok(OpRequest {
                method: Method::Post,
                path: "/probe/cancel",
                query: vec![("id", id.to_string())],
                body: None,
            }),
            AppOperation::ProbeResult { id } => Ok(OpRequest {
                method: Method::Get,
                path: "/probe/result",
                query: vec![("id", id.to_string())],
                body: None,
            }),
            AppOperation::ConfigPreview { patch, scope } => {
                let mut body = serde_json::json!({ "patch": patch });
                if let Some(scope) = scope {
                    body["scope"] = serde_json::json!(scope);
                }
                Ok(OpRequest {
                    method: Method::Post,
                    path: "/config/preview",
                    query: Vec::new(),
                    body: Some(body),
                })
            }
            AppOperation::ConfigPropose {
                patch,
                scope,
                ttl_ms,
            } => Ok(OpRequest {
                method: Method::Post,
                path: "/config/proposals",
                query: Vec::new(),
                // owner 适配器固定（[`MCP_PROPOSAL_OWNER`]）——模型请求
                // 面没有 owner 字段，冒充他人在结构上不可能
                body: Some(serde_json::json!({
                    "owner": MCP_PROPOSAL_OWNER,
                    "scope": scope,
                    "patch": patch,
                    "ttl_ms": ttl_ms,
                })),
            }),
            AppOperation::ConfigAudit => Ok(OpRequest {
                method: Method::Get,
                path: "/config/receipts",
                query: Vec::new(),
                body: None,
            }),
            AppOperation::ConfigApply {
                proposal_id,
                approval_id,
                idempotency_key,
            } => Ok(OpRequest {
                method: Method::Post,
                path: "/config/apply",
                query: Vec::new(),
                // owner 恒适配器标签：只能消费为本归属签发的凭证——
                // CLI 为其他所有者签发的凭证在此结构性失配
                body: Some(serde_json::json!({
                    "idempotency_key": idempotency_key,
                    "proposal_id": proposal_id,
                    "approval_id": approval_id,
                    "owner": MCP_PROPOSAL_OWNER,
                })),
            }),
            AppOperation::ConfigRollbackPrepare { target_key } => Ok(OpRequest {
                method: Method::Post,
                path: "/config/rollback-proposal",
                query: Vec::new(),
                body: Some(serde_json::json!({
                    "owner": MCP_PROPOSAL_OWNER,
                    "target_key": target_key,
                    "ttl_ms": MCP_PROPOSE_TTL_MS,
                })),
            }),
            AppOperation::ConfigRollbackExecute {
                target_key,
                proposal_id,
                approval_id,
                idempotency_key,
                drain_deadline_ms,
            } => {
                let mut body = serde_json::json!({
                    "idempotency_key": idempotency_key,
                    "target_key": target_key,
                    "proposal_id": proposal_id,
                    "approval_id": approval_id,
                    "owner": MCP_PROPOSAL_OWNER,
                });
                if let Some(deadline) = drain_deadline_ms {
                    body["drain_deadline_ms"] = serde_json::json!(deadline);
                }
                Ok(OpRequest {
                    method: Method::Post,
                    path: "/config/rollback",
                    query: Vec::new(),
                    body: Some(body),
                })
            }
        }
    }
}

/// explain 体回显面消毒：host/ingress/generation/进程证据/注解逐字段
/// 过不可信文本闸（服务端入口另有同语义消毒——双层不冲突：客户端先
/// 消毒保证日志/调试形态干净，服务端不信任任何来体）
fn sanitize_explain_body(body: &mut serde_json::Value) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    for key in ["generation_id", "host", "ingress"] {
        if let Some(serde_json::Value::String(s)) = obj.get_mut(key) {
            let sanitized = sanitize_untrusted(s, 256);
            *s = sanitized;
        }
    }
    if let Some(serde_json::Value::Object(process)) = obj.get_mut("process") {
        for key in ["name", "path"] {
            if let Some(serde_json::Value::String(s)) = process.get_mut(key) {
                *s = sanitize_untrusted(s, 256);
            }
        }
    }
    if let Some(serde_json::Value::Object(annotations)) = obj.get_mut("annotations") {
        // 键值双消毒重建（键消毒可能改变键名——一次性重建避免迭代中改表）
        let cleaned: serde_json::Map<String, serde_json::Value> = annotations
            .iter()
            .map(|(key, value)| {
                let clean_key = sanitize_untrusted(key, 64);
                let clean_value = match value {
                    serde_json::Value::String(s) => {
                        serde_json::Value::String(sanitize_untrusted(s, 256))
                    }
                    other => other.clone(),
                };
                (clean_key, clean_value)
            })
            .collect();
        *annotations = cleaned;
    }
}
