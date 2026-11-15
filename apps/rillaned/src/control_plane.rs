use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
// SystemTime：route handler 的 at 时间戳（Linux 门控体，platform-packaging.md）
// 与测试临时目录名用——非 Linux 非 test 编译单元缺席（免 unused）
#[cfg(any(target_os = "linux", test))]
use std::time::SystemTime;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use serde::{Deserialize, Serialize};

use rillane_core::udp::{TableSnapshot, UdpIngressMetrics, UdpIngressSnapshot};
use rillane_core::{JobSnapshot, ProbeOutcome, ProbeService};
use rillane_mesh::{LinkState, MeshRegistry, NodeCapability, NodeRecord, NodeRole};
use rillane_runtime::{
    ChainConstraints, FlowStatItem, Runtime, RuntimeEvent, SourceMergeStats, SwitchReason,
};
use rillane_subscription::{Subscription, SubscriptionConverter, SubscriptionType};

use crate::config_tx::{ConfigTxService, TxApplyRequest, TxError, TxRollbackRequest};

/// 请求体统一形（hyper 1.x 迁移）：产线路径 `Incoming`（服务）与测试
/// 直调 `Full<Bytes>`（`Incoming` 无公开构造）共用 handle/路由/read_json。
trait RequestBody: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static {}
impl<T: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static> RequestBody for T {}

/// 响应体统一形：全部端点均为内存完结体（无流式响应），`Full<Bytes>` 即够。
type RespBody = Full<Bytes>;

#[derive(Clone)]
pub struct ControlPlane {
    runtime: Arc<Runtime>,
    admin_token: Option<String>,
    metrics_enabled: bool,
    started_at: Instant,
    event_log: Arc<tokio::sync::Mutex<VecDeque<String>>>,
    max_event_log_lines: usize,
    telemetry_export: Arc<tokio::sync::RwLock<TelemetryExport>>,
    event_counters: Arc<tokio::sync::RwLock<CounterExport>>,
    /// RIL-061：主动探测作业服务（None = 探测面关闭——端点 503）。
    /// 装配在 rillaned 侧（build_probe_service）：探测授权只来自操作员
    /// 本地 config 的 probe 块，与 runtime 数据面零耦合。
    probe: Option<Arc<ProbeService>>,
    /// RIL-079：配置事务服务（None = 配置事务面关闭——端点 503）。
    /// 装配在 rillaned 侧（with_config_service）：提案/批准/应用/回滚/
    /// 审计的单一权威——CLI 与 MCP 同门，授权与版本检查无本地旁路。
    config_tx: Option<Arc<ConfigTxService>>,
}

impl ControlPlane {
    pub fn new(runtime: Arc<Runtime>, admin_token: Option<String>, metrics_enabled: bool) -> Self {
        let cp = Self {
            runtime,
            admin_token,
            metrics_enabled,
            started_at: Instant::now(),
            event_log: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            max_event_log_lines: 1000,
            telemetry_export: Arc::new(tokio::sync::RwLock::new(TelemetryExport::new(2000))),
            event_counters: Arc::new(tokio::sync::RwLock::new(CounterExport::new(2000))),
            probe: None,
            config_tx: None,
        };
        // 立即订阅事件：ControlPlane::new 在 runtime.start() 之前构造（main.rs），
        // 提前 subscribe 避免启动初段事件（ConfigUpdated/链路建链等）在 serve 才
        // 订阅而被广播通道静默丢弃（P2：事件广播 fire-and-forget）。
        cp.spawn_event_log_task();
        cp
    }

    /// RIL-061：挂探测作业服务（builder 风格——不改动既有 new 签名与
    /// 全部既有测试调用点；None 保持探测面关闭）。
    pub fn with_probe_service(mut self, probe: Option<Arc<ProbeService>>) -> Self {
        self.probe = probe;
        self
    }

    /// RIL-079：挂配置事务服务（builder 风格同上；None 保持配置事务
    /// 面关闭——端点 503）。
    pub fn with_config_service(mut self, service: Option<Arc<ConfigTxService>>) -> Self {
        self.config_tx = service;
        self
    }

    // —— RIL-079 配置事务面（提案/批准/应用/回滚/审计）——
    //
    // 端点只是装配：裁决全在 ConfigTxService + 纯面（提案守卫 / 版本
    // 前置检查 / 凭证核销 / 回执审计）。CLI / MCP 同门——授权与版本
    // 检查没有本地旁路。全部写端点过 admin_token 门（is_mutating）。

    /// 配置事务服务取用口（None = 503——探测面同分层口径）。Err 响应体
    /// 大小与 read_json 同款豁免（端点惯例，见下 `#[allow]`）。
    #[allow(clippy::result_large_err)]
    fn config_tx_or_503(&self) -> Result<Arc<ConfigTxService>, Response<RespBody>> {
        self.config_tx.clone().ok_or_else(|| {
            text(
                StatusCode::SERVICE_UNAVAILABLE,
                "config tx service not configured",
            )
        })
    }

    /// TxError → 稳定码信封（与 trace_error 同形：code + message，
    /// 消息面已脱敏——不含补丁值原文）。
    fn tx_error_response(err: &TxError) -> Response<RespBody> {
        let out = serde_json::json!({
            "error": {
                "code": err.code,
                "message": err.message,
            },
        });
        json(
            StatusCode::from_u16(err.status).unwrap_or(StatusCode::BAD_REQUEST),
            &out,
        )
    }

    async fn handle_config_state(&self) -> Response<RespBody> {
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        json(StatusCode::OK, &service.state())
    }

    async fn handle_config_receipts(&self) -> Response<RespBody> {
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        json(StatusCode::OK, &service.audit())
    }

    /// POST /config/proposals：登记正向提案（base 由 daemon 自填——
    /// 客户端不转述 live 面；坏 patch 在提案期就 400，不落账）。
    async fn handle_config_propose(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct Body {
            owner: String,
            scope: Vec<String>,
            patch: serde_json::Value,
            ttl_ms: u64,
        }
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let body: Body = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        match service.create_proposal(
            &body.owner,
            &body.scope,
            &body.patch,
            body.ttl_ms,
            crate::config_tx::now_ms(),
        ) {
            Ok(proposal) => json(StatusCode::CREATED, &proposal),
            Err(err) => Self::tx_error_response(&err),
        }
    }

    /// POST /config/rollback-proposal：登记回滚提案（标记范围 rollback；
    /// 目标回执须在册且 Applied 且属调用者）。
    async fn handle_config_rollback_proposal(
        &self,
        req: Request<impl RequestBody>,
    ) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct Body {
            owner: String,
            target_key: String,
            ttl_ms: u64,
        }
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let body: Body = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        match service.create_rollback_proposal(
            &body.owner,
            &body.target_key,
            body.ttl_ms,
            crate::config_tx::now_ms(),
        ) {
            Ok(proposal) => json(StatusCode::CREATED, &proposal),
            Err(err) => Self::tx_error_response(&err),
        }
    }

    /// POST /config/preview：只读投影面（diff / 诊断 / 受影响类别 /
    /// 副作用提示）——不落任何状态。
    async fn handle_config_preview(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct Body {
            patch: serde_json::Value,
            scope: Option<Vec<String>>,
        }
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let body: Body = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        json(
            StatusCode::OK,
            &service.preview(&body.patch, body.scope.as_deref()),
        )
    }

    /// POST /config/approve：操作员显式批准（凭证绑定提案摘要 + 所有
    /// 者 + 范围 + 有效期；一次性核销归 apply/rollback）。
    async fn handle_config_approve(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct Body {
            proposal_id: String,
            owner: String,
            scope: Option<Vec<String>>,
            ttl_ms: u64,
        }
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let body: Body = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        match service.approve(
            &body.proposal_id,
            &body.owner,
            body.scope,
            body.ttl_ms,
            crate::config_tx::now_ms(),
        ) {
            Ok(approval) => json(StatusCode::OK, &approval),
            Err(err) => Self::tx_error_response(&err),
        }
    }

    /// POST /config/apply：正向应用（版本/内容前置检查 + 凭证核销 +
    /// 执行 + 终态回执；幂等重试领回执）。live 身份 daemon 自填。
    async fn handle_config_apply(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct Body {
            idempotency_key: String,
            proposal_id: String,
            approval_id: Option<String>,
            owner: String,
        }
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let body: Body = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let request = TxApplyRequest {
            idempotency_key: body.idempotency_key,
            proposal_id: body.proposal_id,
            approval_id: body.approval_id,
            caller_owner: body.owner,
        };
        match service.apply(request, crate::config_tx::now_ms()) {
            Ok(outcome) => json(StatusCode::OK, &outcome),
            Err(err) => Self::tx_error_response(&err),
        }
    }

    /// POST /config/rollback：可校验回滚（候选身份 daemon 自目标回执
    /// 取得——客户端不供 candidate/live；报告三份如实）。
    async fn handle_config_rollback(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct Body {
            idempotency_key: String,
            target_key: String,
            proposal_id: String,
            approval_id: Option<String>,
            owner: String,
            drain_deadline_ms: Option<u64>,
        }
        let service = match self.config_tx_or_503() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let body: Body = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let request = TxRollbackRequest {
            idempotency_key: body.idempotency_key,
            target_key: body.target_key,
            proposal_id: body.proposal_id,
            approval_id: body.approval_id,
            caller_owner: body.owner,
            drain_deadline_ms: body.drain_deadline_ms,
        };
        match service.rollback(request, crate::config_tx::now_ms()) {
            Ok(report) => json(StatusCode::OK, &report),
            Err(err) => Self::tx_error_response(&err),
        }
    }

    pub async fn serve(
        self,
        bind: SocketAddr,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        // hyper 1.x：`hyper::Server` 已移除，监听/连接循环显式化——hyper-util
        // auto Builder + 每连接 `serve_connection_with_shutdown`；oneshot 关桥
        // 转 watch 广播（Receiver 不可克隆）给在途连接，停止 accept 后存量
        // 请求排空再返回，语义对齐旧 `with_graceful_shutdown`。
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let mut shutdown = shutdown;
        let builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();
        let mut conns = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                target: "rillane::control",
                                error = %e,
                                "control plane accept 失败，继续"
                            );
                            continue;
                        }
                    };
                    let state = self.clone();
                    let service = service_fn(move |req| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(state.handle(req).await) }
                    });
                    let conn = builder
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .into_owned();
                    let watcher = graceful.watcher();
                    conns.spawn(async move {
                        if let Err(e) = watcher.watch(conn).await {
                            tracing::debug!(
                                target: "rillane::control",
                                error = %e,
                                "control plane connection closed"
                            );
                        }
                    });
                }
            }
        }
        // 停止 accept 后等待在途请求排空（语义对齐旧 with_graceful_shutdown）
        graceful.shutdown().await;
        while conns.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Cheap health check.
        if method == Method::GET && path == "/health" {
            return text(StatusCode::OK, "ok");
        }

        // Read-only endpoints don't require auth; mutating endpoints (and sensitive reads) do (if token configured).
        let is_mutating = matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );
        // 敏感读面（RIL-063：逐连接轨迹携带详细身份——域名/进程/地址，
        // 权限控制归 admin_token；未配置 token 的本机部署照常开放）
        let is_sensitive_read = matches!(
            path.as_str(),
            "/runtime/config"
                | "/events"
                | "/logs"
                | "/trace/flows"
                | "/trace/flow"
                | "/trace/flow.svg"
                | "/trace/events"
        );
        if (is_mutating || is_sensitive_read)
            && self.admin_token.is_some()
            && !self.is_authorized(&req)
        {
            return text(StatusCode::UNAUTHORIZED, "unauthorized");
        }

        match (method, path.as_str()) {
            (Method::GET, "/nodes") => self.handle_nodes().await,
            (Method::GET, "/flows") => self.handle_flows().await,
            (Method::GET, "/trace/flows") => self.handle_trace_flows(req).await,
            (Method::GET, "/trace/flow") => self.handle_trace_flow(req).await,
            (Method::GET, "/trace/flow.svg") => self.handle_trace_flow_svg(req).await,
            (Method::DELETE, "/trace/history") => self.handle_trace_history_delete().await,
            (Method::GET, "/trace/events") => self.handle_trace_events(req).await,
            (Method::GET, "/probe") => self.handle_probe_list().await,
            (Method::GET, "/probe/result") => self.handle_probe_result(req).await,
            (Method::POST, "/probe") => self.handle_probe_submit(req).await,
            (Method::POST, "/probe/cancel") => self.handle_probe_cancel(req).await,
            (Method::POST, "/explain") => self.handle_explain(req).await,
            (Method::GET, "/metrics") => self.handle_metrics().await,
            (Method::GET, "/udp/stats") => self.handle_udp_stats().await,
            (Method::GET, "/egress/pool/stats") => self.handle_egress_pool_stats().await,
            (Method::GET, "/dns/stats") => self.handle_dns_stats().await,
            (Method::GET, "/plugins/stats") => self.handle_plugins_stats().await,
            (Method::GET, "/runtime/stats") => self.handle_runtime_stats().await,
            (Method::GET, "/routing/stats") => self.handle_routing_stats().await,
            (Method::GET, "/proxies") => self.handle_clash_proxies().await,
            (Method::GET, "/connections") => self.handle_clash_connections().await,
            (Method::GET, "/traffic") => self.handle_clash_traffic().await,
            (Method::GET, "/runtime/config") => self.handle_runtime_config().await,
            (Method::GET, "/events") => self.handle_events().await,
            (Method::GET, "/logs") => self.handle_logs(req).await,
            (Method::POST, "/mesh/nodes/register") => self.handle_register_node(req).await,
            (Method::POST, "/mesh/link-states") => self.handle_update_link_state(req).await,
            (Method::GET, "/mesh/switches") => self.handle_mesh_switches().await,
            (Method::GET, "/mtls/revoked") => self.handle_mtls_revoked().await,

            (Method::POST, "/chains/dry-run") => self.handle_chain_dry_run(req).await,
            (Method::POST, "/chains") => self.handle_chain_create(req).await,
            (Method::GET, "/chains/stats") => self.handle_chain_stats().await,

            (Method::GET, "/subscriptions") => self.handle_subscriptions_list().await,
            (Method::POST, "/subscriptions") => self.handle_subscription_add(req).await,
            (Method::POST, "/subscriptions/refresh") => {
                self.handle_subscriptions_refresh_all().await
            }
            (Method::POST, p) if p.starts_with("/subscriptions/") && p.ends_with("/refresh") => {
                self.handle_subscription_refresh(p).await
            }
            (Method::DELETE, p) if p.starts_with("/subscriptions/") => {
                self.handle_subscription_remove(p).await
            }

            // /chains/{chain_id}
            (Method::GET, p) if p.starts_with("/chains/") => self.handle_chain_get(p).await,
            (Method::DELETE, p) if p.starts_with("/chains/") => self.handle_chain_delete(p).await,

            // network/route endpoints (network-route.md §3)
            (Method::POST, "/network/route/apply") => self.handle_route_apply(req).await,
            (Method::POST, "/network/route/clear") => self.handle_route_clear(req).await,
            (Method::GET, "/network/route/status") => self.handle_route_status().await,
            // —— RIL-079 配置事务面 ——
            (Method::GET, "/config/state") => self.handle_config_state().await,
            (Method::GET, "/config/receipts") => self.handle_config_receipts().await,
            (Method::POST, "/config/proposals") => self.handle_config_propose(req).await,
            (Method::POST, "/config/rollback-proposal") => {
                self.handle_config_rollback_proposal(req).await
            }
            (Method::POST, "/config/preview") => self.handle_config_preview(req).await,
            (Method::POST, "/config/approve") => self.handle_config_approve(req).await,
            (Method::POST, "/config/apply") => self.handle_config_apply(req).await,
            (Method::POST, "/config/rollback") => self.handle_config_rollback(req).await,

            _ => text(StatusCode::NOT_FOUND, "not found"),
        }
    }

    fn spawn_event_log_task(&self) {
        let mut rx = self.runtime.get_event_receiver();
        let started_at = self.started_at;
        let log = self.event_log.clone();
        let max_lines = self.max_event_log_lines;
        let telemetry_export = self.telemetry_export.clone();
        let event_counters = self.event_counters.clone();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if let RuntimeEvent::TelemetryEvent {
                            metric_name,
                            value,
                            tags,
                        } = &ev
                        {
                            let mut guard = telemetry_export.write().await;
                            guard.upsert(metric_name, *value, tags);
                        }
                        match &ev {
                            RuntimeEvent::MeshEvent { event, .. } => {
                                let mut guard = event_counters.write().await;
                                guard.inc_mesh_event(event);
                            }
                            RuntimeEvent::NetworkEvent { event_type, .. } => {
                                let mut guard = event_counters.write().await;
                                guard.inc_network_event(event_type);
                            }
                            RuntimeEvent::SubscriptionEvent {
                                subscription_name,
                                event,
                            } => {
                                let mut guard = event_counters.write().await;
                                guard.inc_subscription_event(subscription_name, event);
                            }
                            RuntimeEvent::Error { source, .. } => {
                                let mut guard = event_counters.write().await;
                                guard.inc_error(source);
                            }
                            RuntimeEvent::ConfigUpdated { .. }
                            | RuntimeEvent::TelemetryEvent { .. } => {}
                        }

                        let line = format!("{:>9.3}s {ev:?}\n", started_at.elapsed().as_secs_f64());
                        let mut guard = log.lock().await;
                        guard.push_back(line);
                        while guard.len() > max_lines {
                            guard.pop_front();
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        let line = format!(
                            "{:>9.3}s [warn] event log lagged; dropped {n} events\n",
                            started_at.elapsed().as_secs_f64()
                        );
                        let mut guard = log.lock().await;
                        guard.push_back(line);
                        while guard.len() > max_lines {
                            guard.pop_front();
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    fn is_authorized(&self, req: &Request<impl RequestBody>) -> bool {
        let Some(expected) = self.admin_token.as_deref() else {
            return true;
        };

        // Accept either `Authorization: Bearer <token>` or `X-Admin-Token: <token>`.
        if let Some(v) = req
            .headers()
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
        {
            return rillane_core::constant_time_eq(v.as_bytes(), expected.as_bytes());
        }
        if let Some(v) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            return v
                .strip_prefix("Bearer ")
                .map(|t| rillane_core::constant_time_eq(t.as_bytes(), expected.as_bytes()))
                .unwrap_or(false);
        }
        false
    }

    // Err = 错误响应体（handler ? 早退惯例），不装箱
    #[allow(clippy::result_large_err)]
    fn mesh(&self) -> Result<Arc<MeshRegistry>, Response<RespBody>> {
        self.runtime
            .get_mesh_registry()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "mesh not enabled"))
    }

    // Err = 错误响应体（handler ? 早退惯例），不装箱
    #[allow(clippy::result_large_err)]
    fn chain_mgr(&self) -> Result<Arc<rillane_runtime::ChainManager>, Response<RespBody>> {
        self.runtime
            .get_chain_manager()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "chain not enabled"))
    }

    // Err = 错误响应体（handler ? 早退惯例），不装箱
    #[allow(clippy::result_large_err)]
    fn subscription_mgr(
        &self,
    ) -> Result<Arc<rillane_subscription::SubscriptionManager>, Response<RespBody>> {
        self.runtime
            .get_subscription_manager()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "subscription not enabled"))
    }

    async fn handle_metrics(&self) -> Response<RespBody> {
        if !self.metrics_enabled {
            return text(StatusCode::NOT_FOUND, "metrics disabled");
        }

        let mut out = String::new();
        let uptime = self.started_at.elapsed().as_secs_f64();
        push_gauge(
            &mut out,
            "rillane_uptime_seconds",
            "Rillane daemon uptime in seconds.",
            uptime,
        );

        if let Some(mesh) = self.runtime.get_mesh_registry() {
            push_gauge(
                &mut out,
                "rillane_mesh_enabled",
                "Whether mesh is enabled (1/0).",
                1.0,
            );

            let stats = mesh.get_stats();
            let online_client = mesh.get_nodes_by_role(NodeRole::Client).len();
            let online_relay = mesh.get_nodes_by_role(NodeRole::Relay).len();
            let online_exit = mesh.get_nodes_by_role(NodeRole::Exit).len();
            let online_hybrid = mesh.get_nodes_by_role(NodeRole::Hybrid).len();
            let links = mesh.get_all_link_states().len();
            let traffic = mesh.get_all_link_traffic();

            push_gauge(
                &mut out,
                "rillane_mesh_nodes_total",
                "Total registered mesh nodes.",
                stats.total_nodes as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_nodes_online",
                "Online mesh nodes.",
                stats.online_nodes as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_nodes_online_client",
                "Online mesh client nodes.",
                online_client as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_nodes_online_relay",
                "Online mesh relay nodes.",
                online_relay as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_nodes_online_exit",
                "Online mesh exit nodes.",
                online_exit as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_nodes_online_hybrid",
                "Online mesh hybrid nodes.",
                online_hybrid as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_sessions_active",
                "Active mesh sessions.",
                stats.active_sessions as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_links_total",
                "Total mesh link-state edges.",
                links as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_average_latency_ms",
                "Average mesh link latency in milliseconds.",
                stats.average_latency_ms as f64,
            );
            push_gauge(
                &mut out,
                "rillane_mesh_packet_loss_rate",
                "Average mesh link packet loss rate (0.0-1.0).",
                stats.packet_loss_rate as f64,
            );

            if !traffic.is_empty() {
                push_metric_header(
                    &mut out,
                    "rillane_mesh_link_bytes_total",
                    "Total bytes transferred over a directed mesh link.",
                    "counter",
                );
                push_metric_header(
                    &mut out,
                    "rillane_mesh_link_connections_total",
                    "Total connections observed on a directed mesh link.",
                    "counter",
                );
                push_metric_header(
                    &mut out,
                    "rillane_mesh_link_errors_total",
                    "Total errors observed on a directed mesh link.",
                    "counter",
                );

                for t in &traffic {
                    push_metric_labeled(
                        &mut out,
                        "rillane_mesh_link_bytes_total",
                        &[("from", &t.from), ("to", &t.to)],
                        t.bytes_total as f64,
                    );
                    push_metric_labeled(
                        &mut out,
                        "rillane_mesh_link_connections_total",
                        &[("from", &t.from), ("to", &t.to)],
                        t.connections_total as f64,
                    );
                    push_metric_labeled(
                        &mut out,
                        "rillane_mesh_link_errors_total",
                        &[("from", &t.from), ("to", &t.to)],
                        t.errors_total as f64,
                    );
                }

                // P2-1 §5：观测形丢包派生（D-2 = errors/connections；分母 0
                // 不出序列，E4——0/0 无意义。上报形 rillane_mesh_packet_loss_rate
                // 语义不同，保留不动不合并）
                if traffic.iter().any(|t| t.connections_total > 0) {
                    push_metric_header(
                        &mut out,
                        "rillane_mesh_link_loss_ratio",
                        "Observed link loss ratio (errors/connections) on a directed mesh link.",
                        "gauge",
                    );
                    for t in traffic.iter().filter(|t| t.connections_total > 0) {
                        push_metric_labeled(
                            &mut out,
                            "rillane_mesh_link_loss_ratio",
                            &[("from", &t.from), ("to", &t.to)],
                            t.errors_total as f64 / t.connections_total as f64,
                        );
                    }
                }
            }

            // P2-1 §5：per-link RTT 分位（D-1 上报流入环样本；环空链路不出
            // 序列，E3——无样本画 0ms 是误导）
            let rtts = mesh.get_all_link_rtt();
            if !rtts.is_empty() {
                push_metric_header(
                    &mut out,
                    "rillane_mesh_link_rtt_ms",
                    "Mesh link RTT quantile in milliseconds (reported-stream samples).",
                    "gauge",
                );
                for r in rtts {
                    push_metric_labeled(
                        &mut out,
                        "rillane_mesh_link_rtt_ms",
                        &[("from", &r.from), ("to", &r.to), ("quantile", "p50")],
                        r.p50_ms as f64,
                    );
                    push_metric_labeled(
                        &mut out,
                        "rillane_mesh_link_rtt_ms",
                        &[("from", &r.from), ("to", &r.to), ("quantile", "p95")],
                        r.p95_ms as f64,
                    );
                }
            }
        } else {
            push_gauge(
                &mut out,
                "rillane_mesh_enabled",
                "Whether mesh is enabled (1/0).",
                0.0,
            );
        }

        if let Some(chain_mgr) = self.runtime.get_chain_manager() {
            push_gauge(
                &mut out,
                "rillane_chain_enabled",
                "Whether chain is enabled (1/0).",
                1.0,
            );

            let stats = chain_mgr.get_stats().await;
            push_metric_header(
                &mut out,
                "rillane_chain_total_created",
                "Total chains created.",
                "counter",
            );
            out.push_str(&format!(
                "rillane_chain_total_created {}\n",
                stats.total_chains_created
            ));
            push_gauge(
                &mut out,
                "rillane_chain_active",
                "Active chains.",
                stats.active_chains as f64,
            );
            push_metric_header(
                &mut out,
                "rillane_chain_failover_total",
                "Chain failover count.",
                "counter",
            );
            out.push_str(&format!(
                "rillane_chain_failover_total {}\n",
                stats.failover_count
            ));
            push_metric_header(
                &mut out,
                "rillane_chain_failed_total",
                "Failed chains count.",
                "counter",
            );
            out.push_str(&format!(
                "rillane_chain_failed_total {}\n",
                stats.failed_chains
            ));
            push_gauge(
                &mut out,
                "rillane_chain_average_hop_count",
                "Average chain hop count.",
                stats.average_hop_count as f64,
            );
            push_gauge(
                &mut out,
                "rillane_chain_average_lifetime_seconds",
                "Average chain lifetime in seconds.",
                stats.average_chain_lifetime_seconds as f64,
            );
            push_gauge(
                &mut out,
                "rillane_chain_last_failover_epoch_seconds",
                "Unix epoch seconds of the most recent chain failover (0 if never).",
                stats.last_failover_epoch_seconds.unwrap_or(0) as f64,
            );

            // P2-1 §5：切换/终止原因计数族（恒渲染——四因零值也在，便于
            // Grafana absent 告警语义与按维查询）
            let counters = chain_mgr.switch_counters_snapshot();
            push_metric_header(
                &mut out,
                "rillane_mesh_switch_total",
                "Mesh chain switch/termination events by reason.",
                "counter",
            );
            for reason in SwitchReason::ALL {
                let n = counters.get(reason.as_str()).copied().unwrap_or(0);
                push_metric_labeled(
                    &mut out,
                    "rillane_mesh_switch_total",
                    &[("reason", reason.as_str())],
                    n as f64,
                );
            }
        } else {
            push_gauge(
                &mut out,
                "rillane_chain_enabled",
                "Whether chain is enabled (1/0).",
                0.0,
            );
        }

        let flow_stats = self.runtime.get_flow_stats();
        push_gauge(
            &mut out,
            "rillane_flow_pairs",
            "Number of (ingress, egress) flow stat pairs.",
            flow_stats.len() as f64,
        );

        push_metric_header(
            &mut out,
            "rillane_flow_connections_total",
            "Total flows forwarded.",
            "counter",
        );

        push_metric_header(
            &mut out,
            "rillane_flow_upstream_bytes_total",
            "Total upstream bytes forwarded.",
            "counter",
        );

        push_metric_header(
            &mut out,
            "rillane_flow_downstream_bytes_total",
            "Total downstream bytes forwarded.",
            "counter",
        );

        for item in flow_stats {
            push_metric_labeled(
                &mut out,
                "rillane_flow_connections_total",
                &[("ingress", &item.ingress), ("egress", &item.egress)],
                item.flows as f64,
            );
            push_metric_labeled(
                &mut out,
                "rillane_flow_upstream_bytes_total",
                &[("ingress", &item.ingress), ("egress", &item.egress)],
                item.upstream as f64,
            );
            push_metric_labeled(
                &mut out,
                "rillane_flow_downstream_bytes_total",
                &[("ingress", &item.ingress), ("egress", &item.egress)],
                item.downstream as f64,
            );
        }

        // ---- UDP 数据面（P0-5 §2.2–2.4，恒渲染：udp_service None / mesh 面未装配时全零，
        // 端点不因开关消失，§6-2）----
        let (udp_table, udp_ingress) = match self.runtime.get_udp_service() {
            Some(svc) => (svc.table().snapshot(), svc.ingress_snapshot()),
            None => (
                udp_zero_table_snapshot(),
                UdpIngressMetrics::default().snapshot(),
            ),
        };

        // §2.2 会话表序列
        push_gauge(
            &mut out,
            "rillane_udp_sessions_active",
            "Active UDP sessions.",
            udp_table.sessions_active as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_sessions_total",
            "Total UDP sessions created (including reclaimed).",
            udp_table.sessions_total as f64,
        );
        push_gauge(
            &mut out,
            "rillane_udp_mappings_active",
            "Active UDP destination mappings.",
            udp_table.mappings_active as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_reroutes_total",
            "UDP sticky-decision rebuilds.",
            udp_table.reroutes as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_udp_relay_bytes_total",
            "UDP relay bytes between client and egress.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "rillane_udp_relay_bytes_total",
            &[("direction", "up")],
            udp_table.bytes_up as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_udp_relay_bytes_total",
            &[("direction", "down")],
            udp_table.bytes_down as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_udp_relay_packets_total",
            "UDP relay datagrams.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "rillane_udp_relay_packets_total",
            &[("direction", "up")],
            udp_ingress.uplink_packets as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_udp_relay_packets_total",
            &[("direction", "down")],
            udp_ingress.downlink_packets as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_udp_dropped_total",
            "Dropped UDP datagrams.",
            "counter",
        );
        for reason in UDP_DROP_REASONS {
            push_metric_labeled(
                &mut out,
                "rillane_udp_dropped_total",
                &[("reason", reason)],
                udp_table.dropped.get(reason).copied().unwrap_or(0) as f64,
            );
        }
        push_metric_header(
            &mut out,
            "rillane_udp_expired_total",
            "Expired UDP sessions/mappings.",
            "counter",
        );
        for reason in UDP_EXPIRE_REASONS {
            push_metric_labeled(
                &mut out,
                "rillane_udp_expired_total",
                &[("reason", reason)],
                udp_table.expired.get(reason).copied().unwrap_or(0) as f64,
            );
        }

        // §2.3 ingress / ASSOCIATE 序列
        push_gauge(
            &mut out,
            "rillane_udp_associates_active",
            "Active SOCKS5 UDP ASSOCIATE control connections.",
            udp_ingress.associates_active as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_associates_total",
            "Total accepted SOCKS5 UDP ASSOCIATE requests.",
            udp_ingress.associates_total as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_associates_rejected_total",
            "Rejected SOCKS5 UDP ASSOCIATE requests.",
            udp_ingress.associate_rejected as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_associate_errors_total",
            "SOCKS5 UDP ASSOCIATE slow-path errors.",
            udp_ingress.associate_errors as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_frag_dropped_total",
            "UDP datagrams dropped for FRAG != 0.",
            udp_ingress.frag_dropped as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_source_dropped_total",
            "UDP datagrams dropped for mismatched source address.",
            udp_ingress.source_dropped as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_malformed_dropped_total",
            "UDP datagrams dropped for malformed SOCKS5 header.",
            udp_ingress.malformed_dropped as f64,
        );

        // §2.4 mesh UDP 面序列（面未启用/未 start → 全零；client 侧分立不混入面族）
        let udp_mesh = self.runtime.get_mesh_udp_snapshot().unwrap_or_default();
        push_gauge(
            &mut out,
            "rillane_udp_mesh_flows_active",
            "Active mesh UDP flow cache entries.",
            udp_mesh.flows_active as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_udp_mesh_forwarded_total",
            "Mesh UDP datagrams forwarded between hops.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "rillane_udp_mesh_forwarded_total",
            &[("direction", "up")],
            udp_mesh.forwarded_up as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_udp_mesh_forwarded_total",
            &[("direction", "down")],
            udp_mesh.forwarded_down as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_mesh_unknown_flow_total",
            "Mesh UDP CACHED envelopes with no flow match.",
            udp_mesh.unknown_flow as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_mesh_malformed_total",
            "Mesh UDP envelopes failing to decode.",
            udp_mesh.malformed as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_mesh_evicted_total",
            "Mesh UDP flow cache evictions.",
            udp_mesh.evicted as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_mesh_replay_dropped_total",
            "Mesh UDP envelopes dropped by the anti-replay window (E4).",
            udp_mesh.replay_dropped as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_mesh_client_dropped_total",
            "Client-side mesh UDP downlink drops.",
            self.runtime
                .get_udp_client_metrics()
                .map(|m| m.dropped())
                .unwrap_or(0) as f64,
        );
        push_counter(
            &mut out,
            "rillane_udp_mesh_client_replay_dropped_total",
            "Client-side mesh UDP downlink envelopes dropped by the anti-replay window.",
            self.runtime
                .get_udp_client_metrics()
                .map(|m| m.replay_dropped())
                .unwrap_or(0) as f64,
        );

        // TUN 数据面序列（tun-dataplane.md §2.8，恒渲染：未装配 TUN 时全零
        // ——与 UDP 族同口径，端点不因开关消失）。方向语义：up = tun 上行
        // 读入，down = tun 下行写回；TUN 流量不进 rillane_udp_* 族（§2.8 计量
        // 边界——两族口径不同，勿把 TUN 有流量时 rillane_udp_* 为零误读为故障）
        // TUN 指标取数（Linux 门控——platform-packaging.md；非 Linux 恒零值面，
        // TunIngressStats 平台无关、恒渲染口径 tun-dataplane.md §2.8 不变）
        #[cfg(target_os = "linux")]
        let (tun_stats, tun_flows) = match self.runtime.get_tun_ingress() {
            Some(t) => (t.get_stats(), t.active_flows()),
            None => (rillane_runtime::TunIngressStats::default(), 0),
        };
        #[cfg(not(target_os = "linux"))]
        let (tun_stats, tun_flows) = (rillane_runtime::TunIngressStats::default(), 0);
        push_gauge(
            &mut out,
            "rillane_tun_flows_active",
            "Active TUN flows (UDP NAT entries + TCP stack).",
            tun_flows as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_tun_packets_total",
            "TUN packets by direction (up = read from tun, down = written to tun).",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "rillane_tun_packets_total",
            &[("direction", "up")],
            tun_stats.packets_received as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_tun_packets_total",
            &[("direction", "down")],
            tun_stats.packets_sent as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_tun_bytes_total",
            "TUN bytes by direction (up = read from tun, down = written to tun).",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "rillane_tun_bytes_total",
            &[("direction", "up")],
            tun_stats.bytes_received as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_tun_bytes_total",
            &[("direction", "down")],
            tun_stats.bytes_sent as f64,
        );
        push_counter(
            &mut out,
            "rillane_tun_bypass_dropped_total",
            "TUN uplink packets dropped by bypass rules.",
            tun_stats.bypass_dropped as f64,
        );
        push_counter(
            &mut out,
            "rillane_tun_parse_errors_total",
            "TUN packets failing IP/UDP/TCP parse.",
            tun_stats.parse_errors as f64,
        );
        push_counter(
            &mut out,
            "rillane_tun_unknown_flow_total",
            "TUN downlink packets with no live flow match.",
            tun_stats.unknown_flow as f64,
        );
        push_counter(
            &mut out,
            "rillane_tun_process_attr_miss_total",
            "TUN first-packet process attribution misses.",
            tun_stats.process_attr_miss as f64,
        );

        // P1-4 §5 obfs 序列（恒渲染：关闭态全零 = 零开销旁路的可观测证据
        // §2.5/E11；invocations 的 {name} 标签 = 配置挂载集，空链无条目）
        let obfs = self.runtime.get_obfs_pad_snapshot();
        push_metric_header(
            &mut out,
            "rillane_obfs_padding_frames_total",
            "Chain envelope frames padded, by padding mode.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "rillane_obfs_padding_frames_total",
            &[("mode", "fixed")],
            obfs.frames_fixed as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_obfs_padding_frames_total",
            &[("mode", "bucket")],
            obfs.frames_bucket as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_obfs_padding_frames_total",
            &[("mode", "range")],
            obfs.frames_range as f64,
        );
        push_metric_labeled(
            &mut out,
            "rillane_obfs_padding_bytes_total",
            &[("direction", "added")],
            obfs.bytes_added as f64,
        );
        push_metric_header(
            &mut out,
            "rillane_obfs_padding_skipped_total",
            "Padding decisions skipped, by reason.",
            "counter",
        );
        for (reason, value) in [
            ("no_frame", obfs.skipped_no_frame),
            ("overhead_cap", obfs.skipped_overhead_cap),
            ("too_large", obfs.skipped_too_large),
            ("peer_version", obfs.skipped_peer_version),
            ("disabled", obfs.skipped_disabled),
        ] {
            push_metric_labeled(
                &mut out,
                "rillane_obfs_padding_skipped_total",
                &[("reason", reason)],
                value as f64,
            );
        }
        for (name, count) in rillane_core::middleware_invocations() {
            push_metric_labeled(
                &mut out,
                "rillane_obfs_middleware_invocations_total",
                &[("name", name)],
                count as f64,
            );
        }

        // P1-5 §6.1 池/握手序列：池启用才渲染（§8.2 对照关闭态 = 无
        // rillane_pool_* 序列，非恒渲染——区别于 obfs E11 恒零纪律）
        if let Some(pool) = self.runtime.get_transport_pool() {
            let s = pool.snapshot();
            push_metric_header(
                &mut out,
                "rillane_pool_acquires_total",
                "Pool lease outcomes, by result.",
                "counter",
            );
            for (result, value) in [
                ("hit", s.acquires_hit),
                ("miss", s.acquires_miss),
                ("stale_redial", s.acquires_stale_redial),
            ] {
                push_metric_labeled(
                    &mut out,
                    "rillane_pool_acquires_total",
                    &[("result", result)],
                    value as f64,
                );
            }
            push_metric_header(
                &mut out,
                "rillane_pool_dials_total",
                "Transport dials, by origin and result.",
                "counter",
            );
            for (origin, ok, err) in [
                ("foreground", s.dials_foreground_ok, s.dials_foreground_err),
                ("warm", s.dials_warm_ok, s.dials_warm_err),
                ("refill", s.dials_refill_ok, s.dials_refill_err),
            ] {
                push_metric_labeled(
                    &mut out,
                    "rillane_pool_dials_total",
                    &[("origin", origin), ("result", "ok")],
                    ok as f64,
                );
                push_metric_labeled(
                    &mut out,
                    "rillane_pool_dials_total",
                    &[("origin", origin), ("result", "error")],
                    err as f64,
                );
            }
            push_gauge(
                &mut out,
                "rillane_pool_idle_connections",
                "Idle pooled connections.",
                s.idle as f64,
            );
            push_gauge(
                &mut out,
                "rillane_pool_leased_connections",
                "Leased (in-use) pooled connections.",
                s.leased as f64,
            );
            push_gauge(
                &mut out,
                "rillane_pool_reuse_ratio",
                "Lease hits over hits+misses, since start.",
                s.reuse_ratio(),
            );
            push_metric_header(
                &mut out,
                "rillane_pool_evicted_total",
                "Idle connection evictions, by reason.",
                "counter",
            );
            for (reason, value) in [
                ("idle_timeout", s.evicted_idle_timeout),
                ("capacity", s.evicted_capacity),
                ("shutdown", s.evicted_shutdown),
            ] {
                push_metric_labeled(
                    &mut out,
                    "rillane_pool_evicted_total",
                    &[("reason", reason)],
                    value as f64,
                );
            }
        }
        if let Some(factory) = self.runtime.get_tls_factory() {
            let (full, full_hrr, resumed) = factory.handshake_snapshot();
            push_metric_header(
                &mut out,
                "rillane_tls_handshakes_total",
                "TLS handshakes through the shared config, by kind.",
                "counter",
            );
            for (kind, value) in [("full", full), ("resumed", resumed), ("full_hrr", full_hrr)] {
                push_metric_labeled(
                    &mut out,
                    "rillane_tls_handshakes_total",
                    &[("type", kind)],
                    value as f64,
                );
            }
        }

        if let Some(subs) = self.runtime.get_subscription_manager() {
            push_gauge(
                &mut out,
                "rillane_subscriptions_enabled",
                "Whether subscription manager is enabled (1/0).",
                1.0,
            );
            let count = subs.list_subscriptions().len();
            push_gauge(
                &mut out,
                "rillane_subscriptions_total",
                "Total subscriptions.",
                count as f64,
            );
        } else {
            push_gauge(
                &mut out,
                "rillane_subscriptions_enabled",
                "Whether subscription manager is enabled (1/0).",
                0.0,
            );
        }

        // RuntimeEvent::TelemetryEvent exports (best-effort, bounded, gauge-only).
        let export = self.telemetry_export.read().await;
        if !export.values.is_empty() {
            let mut wrote_header: HashSet<&str> = HashSet::new();
            for (series, value) in export.values.iter() {
                if wrote_header.insert(series.metric.as_str()) {
                    push_metric_header(
                        &mut out,
                        &series.metric,
                        "Telemetry gauge exported from RuntimeEvent::TelemetryEvent.",
                        "gauge",
                    );
                }
                let labels: Vec<(&str, &str)> = series
                    .labels
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                push_metric_labeled(&mut out, &series.metric, &labels, *value);
            }
        }

        // Event counters (best-effort, bounded, counter).
        let counters = self.event_counters.read().await;
        if !counters.values.is_empty() {
            let mut wrote_header: HashSet<&str> = HashSet::new();
            for (series, value) in counters.values.iter() {
                if wrote_header.insert(series.metric.as_str()) {
                    push_metric_header(
                        &mut out,
                        &series.metric,
                        "Event counter derived from RuntimeEvent stream.",
                        "counter",
                    );
                }
                let labels: Vec<(&str, &str)> = series
                    .labels
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                push_metric_labeled(&mut out, &series.metric, &labels, *value as f64);
            }
        }

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; version=0.0.4")
            .body(RespBody::new(Bytes::from(out)))
            .unwrap_or_else(|_| Response::new(RespBody::new(Bytes::from("internal error"))))
    }

    /// P0-5 §3.1/§9-1：UDP 观测 JSON。`table`/`ingress` 恒在（UDP 关闭时全零，
    /// §6-2）；`mesh` 仅面启用时为对象、否则 null（两态可区分）；
    /// `mesh_client` 仅 chain+udp client 桥装配时出现（§2.4 收编裁决：键省略）。
    async fn handle_udp_stats(&self) -> Response<RespBody> {
        let (table, ingress) = match self.runtime.get_udp_service() {
            Some(svc) => (svc.table().snapshot(), svc.ingress_snapshot()),
            None => (
                udp_zero_table_snapshot(),
                UdpIngressMetrics::default().snapshot(),
            ),
        };
        let dto = UdpStatsDto {
            table,
            ingress,
            mesh: self.runtime.get_mesh_udp_snapshot(),
            mesh_client: self
                .runtime
                .get_udp_client_metrics()
                .map(|m| UdpClientDroppedDto {
                    dropped: m.dropped(),
                    replay_dropped: m.replay_dropped(),
                }),
        };
        json(StatusCode::OK, &dto)
    }

    /// P1-5 §6.2 `GET /egress/pool/stats`：池快照 + 每键 idle + 计数族。
    /// 块缺席/未启用 = enabled:false 零值响应（形态稳定，脚本好消费）。
    async fn handle_egress_pool_stats(&self) -> Response<RespBody> {
        let block = self.runtime.get_config().egress_pool;
        let (enabled, tls_resumption) = match &block {
            Some(b) => (b.enabled, b.tls_resumption()),
            None => (false, false),
        };
        let pool = self.runtime.get_transport_pool();
        let snap = pool.as_ref().map(|p| p.snapshot());
        let keys: Option<Vec<EgressPoolKeyDto>> = pool.as_ref().map(|p| {
            p.key_snapshots()
                .into_iter()
                .map(|k| EgressPoolKeyDto {
                    key: k.key,
                    idle: k.idle,
                })
                .collect()
        });
        let counters = match &snap {
            Some(s) => EgressPoolCountersDto {
                hit: s.acquires_hit,
                miss: s.acquires_miss,
                stale_redial: s.acquires_stale_redial,
                dials_ok: s.dials_foreground_ok + s.dials_warm_ok + s.dials_refill_ok,
                dials_err: s.dials_foreground_err + s.dials_warm_err + s.dials_refill_err,
            },
            None => EgressPoolCountersDto::default(),
        };
        let dto = EgressPoolStatsDto {
            enabled,
            tls_resumption,
            keys: keys.unwrap_or_default(),
            counters,
            reuse_ratio: snap.as_ref().map(|s| s.reuse_ratio()).unwrap_or(0.0),
        };
        json(StatusCode::OK, &dto)
    }

    /// P2-8 M1 dns-partition.md §6 `GET /dns/stats`：引擎统计快照（验收
    /// 「缓存命中率有指标」）。块缺席/关闭 = enabled:false 零值响应
    /// （形态稳定，脚本好消费——§4 观测先例同款）。
    async fn handle_dns_stats(&self) -> Response<RespBody> {
        let dto = match self.runtime.get_dns_service() {
            Some(svc) => {
                let s = svc.stats_snapshot();
                DnsStatsDto {
                    enabled: true,
                    listen: Some(svc.listen().to_string()),
                    total_queries: s.total_queries,
                    cache_hits: s.cache_hits,
                    cache_misses: s.cache_misses,
                    cache_hit_rate: s.cache_hit_rate,
                    upstream_failures: s.upstream_failures,
                    pollution_suspected: s.pollution_suspected,
                    domestic_queries: s.domestic_queries,
                    trusted_queries: s.trusted_queries,
                }
            }
            None => DnsStatsDto {
                enabled: false,
                listen: None,
                total_queries: 0,
                cache_hits: 0,
                cache_misses: 0,
                cache_hit_rate: 0.0,
                upstream_failures: 0,
                pollution_suspected: 0,
                domestic_queries: 0,
                trusted_queries: 0,
            },
        };
        json(StatusCode::OK, &dto)
    }

    /// 观测轮（plugin-loader.md §0 计数面）`GET /plugins/stats`：per-plugin
    /// 计数快照（calls/denied/traps/fuel_exhausted）。空表 = obfs 未启用或
    /// 无 plugins 声明（形态稳定恒 200，/dns/stats 先例同款——插件面缺席
    /// 不是错误态）。RIL-040：small 档恒空表（无 WASM 插件面，路由形态不变
    /// ——TUN「恒渲染、数据源门控」同口径）。
    #[cfg(feature = "full")]
    async fn handle_plugins_stats(&self) -> Response<RespBody> {
        let plugins: Vec<PluginStatsDto> = self
            .runtime
            .get_plugin_stats()
            .into_iter()
            .map(|(name, s)| PluginStatsDto {
                name,
                calls: s.calls,
                denied: s.denied,
                traps: s.traps,
                fuel_exhausted: s.fuel_exhausted,
            })
            .collect();
        json(StatusCode::OK, &PluginsStatsDto { plugins })
    }

    /// RIL-040：small/mobile 档（无插件面）——路由形态稳定恒 200 空表。
    #[cfg(not(feature = "full"))]
    async fn handle_plugins_stats(&self) -> Response<RespBody> {
        json(
            StatusCode::OK,
            &PluginsStatsDto {
                plugins: Vec::new(),
            },
        )
    }

    /// P2-7 M0 §2.2：撤销生效面快照（静态 env 条目 + 文件载体态）。
    /// 503 语义 = 未装配 mesh / 纯明文 TCP 面（/nodes 先例分层口径）。
    async fn handle_mtls_revoked(&self) -> Response<RespBody> {
        let snap = match self.runtime.get_mesh_revoked_snapshot().await {
            Some(s) => s,
            None => return text(StatusCode::SERVICE_UNAVAILABLE, "mesh mTLS not enabled"),
        };
        json(StatusCode::OK, &MtlsRevokedDto::from(snap))
    }

    async fn handle_nodes(&self) -> Response<RespBody> {
        let registry = match self.mesh() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let snapshots = registry.get_all_node_snapshots();
        let nodes: Vec<MeshNodeDto> = snapshots
            .into_iter()
            .map(|s| MeshNodeDto {
                id: s.id,
                role: s.role.to_string(),
                addr: s.addr,
                capability: s.capability,
                online: s.online,
                last_seen_seconds: s.last_seen_seconds,
            })
            .collect();

        json(StatusCode::OK, &nodes)
    }

    async fn handle_flows(&self) -> Response<RespBody> {
        let stats = self.runtime.get_flow_stats();
        json(StatusCode::OK, &stats)
    }

    /// Trace 查询面（RIL-060，schema_version=1 冻结）：活动/近期连接
    /// 分页列表（RIL-055 查询服务）。参数 offset/limit/origin(stream|
    /// association)/state(active|closed)/generation；limit=0 与非法
    /// 取值 400 + 稳定码。
    async fn handle_trace_flows(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let query = req.uri().query().unwrap_or("");
        let mut offset = 0usize;
        let mut limit = 20usize;
        let mut filter = rillane_core::query::FlowQueryFilter::default();
        for kv in query.split('&') {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            match key {
                "offset" => match value.parse::<usize>() {
                    Ok(v) => offset = v,
                    Err(_) => return trace_bad_param("offset must be a number"),
                },
                "limit" => match value.parse::<usize>() {
                    Ok(v) => limit = v,
                    Err(_) => return trace_bad_param("limit must be a number"),
                },
                "origin" => match value {
                    "stream" => filter.origin = Some(rillane_core::trace::FlowOrigin::Stream),
                    "association" => {
                        filter.origin = Some(rillane_core::trace::FlowOrigin::Association)
                    }
                    _ => return trace_bad_param("origin must be stream or association"),
                },
                "state" => match value {
                    "active" => filter.state = Some(rillane_core::query::FlowState::Active),
                    "closed" => filter.state = Some(rillane_core::query::FlowState::Closed),
                    _ => return trace_bad_param("state must be active or closed"),
                },
                "generation" if !value.is_empty() => {
                    filter.generation = Some(rillane_core::redact::sanitize_untrusted(value, 128));
                }
                _ => {}
            }
        }
        let page = match self.runtime.flow_query().list(&filter, offset, limit) {
            Ok(page) => page,
            Err(err) => return trace_error(StatusCode::BAD_REQUEST, err.code(), &err.context),
        };
        let items: Vec<serde_json::Value> = page
            .items
            .iter()
            .map(|summary| {
                serde_json::json!({
                    "flow": summary.flow.as_str(),
                    "origin": summary.origin.as_str(),
                    "generation": summary.generation,
                    "state": match summary.state {
                        rillane_core::query::FlowState::Active => "active",
                        rillane_core::query::FlowState::Closed => "closed",
                    },
                    "events": summary.events,
                    "first_wall_ms": summary.first_wall_ms,
                    "last_code": summary.last_code,
                })
            })
            .collect();
        let out = serde_json::json!({
            "schema_version": 1u32,
            "total_matching": page.total_matching,
            "offset": page.offset,
            "limit": limit,
            "items": items,
        });
        json(StatusCode::OK, &out)
    }

    /// 单流详情（RIL-060）：命中 = 完整轨迹；缺席 = 200 + found:false
    /// + 稳定缺席码与采集计数（显式缺席不是 404 错误——CLI 据此退出码 2）。
    async fn handle_trace_flow(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let query = req.uri().query().unwrap_or("");
        let Some(id) = query.split('&').find_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            if parts.next() == Some("id") {
                parts.next().map(|v| v.to_string())
            } else {
                None
            }
        }) else {
            return trace_bad_param("id is required");
        };
        let flow = match rillane_core::trace::FlowId::new(&id) {
            Ok(flow) => flow,
            Err(err) => return trace_error(StatusCode::BAD_REQUEST, err.code(), &err.context),
        };
        let record = self.runtime.flow_query().flow(&flow);
        let out = match record {
            rillane_core::query::FlowRecord::Found(trace) => serde_json::json!({
                "schema_version": 1u32,
                "found": true,
                "trace": trace_trace_json(&trace),
                "absence": null,
            }),
            rillane_core::query::FlowRecord::Absent(absent) => serde_json::json!({
                "schema_version": 1u32,
                "found": false,
                "trace": null,
                "absence": {
                    "code": absent.code,
                    "note": absent.note,
                    "collector": collector_stats_json(&absent.collector),
                },
            }),
        };
        json(StatusCode::OK, &out)
    }

    /// 流轨迹 SVG 导出（RIL-062）：与 `/trace/flow` 同一查询快照——
    /// 图与 JSON 内容一致由「同一快照两种渲染」构造性保证。缺席
    /// （含未知 ID）→ 404 稳定码信封，不拿图糊弄缺席。
    async fn handle_trace_flow_svg(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let query = req.uri().query().unwrap_or("");
        let Some(id) = query.split('&').find_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            if parts.next() == Some("id") {
                parts.next().map(|v| v.to_string())
            } else {
                None
            }
        }) else {
            return trace_bad_param("id is required");
        };
        let flow = match rillane_core::trace::FlowId::new(&id) {
            Ok(flow) => flow,
            Err(err) => return trace_error(StatusCode::BAD_REQUEST, err.code(), &err.context),
        };
        match self.runtime.flow_query().flow(&flow) {
            rillane_core::query::FlowRecord::Found(trace) => svg(
                StatusCode::OK,
                &rillane_core::trace_svg::render_flow_svg(&trace),
            ),
            rillane_core::query::FlowRecord::Absent(absent) => {
                trace_error(StatusCode::NOT_FOUND, absent.code, absent.note)
            }
        }
    }

    /// 诊断历史显式清除（RIL-064 留存面）：只删已关闭迹（活动流不拆），
    /// 缺席答复从此带 `collector.flow.purged`。TTL 过期另有周期 sweeper
    /// （runtime start 装配）——本端点是操作员的显式「立即清」。
    async fn handle_trace_history_delete(&self) -> Response<RespBody> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let purged = self.runtime.trace_history_purge(now);
        json(
            StatusCode::OK,
            &serde_json::json!({
                "schema_version": 1u32,
                "purged": purged,
            }),
        )
    }

    /// 事件增量读取（RIL-060）：缺席/未知 ID → 404 + 稳定码；limit=0
    /// → 400 query.page.invalid。
    async fn handle_trace_events(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let query = req.uri().query().unwrap_or("");
        let mut id: Option<String> = None;
        let mut from_seq = 0u64;
        let mut limit = 200usize;
        for kv in query.split('&') {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            match key {
                "id" if !value.is_empty() => id = Some(value.to_string()),
                "from_seq" => match value.parse::<u64>() {
                    Ok(v) => from_seq = v,
                    Err(_) => return trace_bad_param("from_seq must be a number"),
                },
                "limit" => match value.parse::<usize>() {
                    Ok(v) => limit = v,
                    Err(_) => return trace_bad_param("limit must be a number"),
                },
                _ => {}
            }
        }
        let Some(id) = id else {
            return trace_bad_param("id is required");
        };
        let flow = match rillane_core::trace::FlowId::new(&id) {
            Ok(flow) => flow,
            Err(err) => return trace_error(StatusCode::BAD_REQUEST, err.code(), &err.context),
        };
        match self.runtime.flow_query().events(&flow, from_seq, limit) {
            Ok(events) => {
                let items: Vec<serde_json::Value> = events.iter().map(trace_event_json).collect();
                let out = serde_json::json!({
                    "schema_version": 1u32,
                    "flow": flow.as_str(),
                    "from_seq": from_seq,
                    "events": items,
                });
                json(StatusCode::OK, &out)
            }
            Err(err) => match err.code() {
                rillane_core::query::CODE_QUERY_PAGE_INVALID => {
                    trace_error(StatusCode::BAD_REQUEST, err.code(), &err.context)
                }
                // 缺席（未知/逐出/过期/采样/取走/关闭）= 404 + 稳定码
                _ => trace_error(StatusCode::NOT_FOUND, err.code(), &err.context),
            },
        }
    }

    /// 主动探测作业列表（RIL-061）：限额与作业快照一屏可见——网络副作用
    /// 只经 POST /probe 发生，本端点是纯读。
    async fn handle_probe_list(&self) -> Response<RespBody> {
        let Some(service) = self.probe.as_ref() else {
            return probe_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "probe.disabled",
                "probe block absent from config: no probe authority assembled",
            );
        };
        let limits = service.limits();
        let jobs: Vec<serde_json::Value> = service.list().iter().map(probe_job_json).collect();
        let out = serde_json::json!({
            "schema_version": 1u32,
            "limits": {
                "max_active": limits.max_active,
                "job_timeout_ms": limits.job_timeout_ms,
                "udp_payload_max_bytes": limits.udp_payload_max_bytes,
                "byte_budget": limits.byte_budget,
            },
            "jobs": jobs,
        });
        json(StatusCode::OK, &out)
    }

    /// 主动探测作业结果（RIL-061）：完成态带显式测量（RTT / 回显计数 /
    /// 丢包率分别标记——字段全部来自执行器回报，不推断机场内部路径）；
    /// 未知 ID → 404 + 显式缺席信封（`probe.job.unknown`）。
    async fn handle_probe_result(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let Some(service) = self.probe.as_ref() else {
            return probe_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "probe.disabled",
                "probe block absent from config: no probe authority assembled",
            );
        };
        let Some(id) = probe_id_from_query(req.uri().query().unwrap_or("")) else {
            return probe_bad_param("id must be a number");
        };
        match service.result(id) {
            Ok(snap) => {
                let out = serde_json::json!({
                    "schema_version": 1u32,
                    "found": true,
                    "job": probe_job_json(&snap),
                    "absence": null,
                });
                json(StatusCode::OK, &out)
            }
            Err(err) => {
                let out = serde_json::json!({
                    "schema_version": 1u32,
                    "found": false,
                    "job": null,
                    "absence": {
                        "code": err.code,
                        "note": err.detail,
                    },
                });
                json(StatusCode::NOT_FOUND, &out)
            }
        }
    }

    /// 显式发起探测（RIL-061）：目标必须已在装配范围登记（`probe.target.
    /// out_of_scope`），预算耗尽显式拒绝（`probe.limit.budget`）——拒绝
    /// 不产生作业（服务面契约）。网络副作用只经此端点发生。
    async fn handle_probe_submit(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let Some(service) = self.probe.as_ref() else {
            return probe_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "probe.disabled",
                "probe block absent from config: no probe authority assembled",
            );
        };
        let body: ProbeSubmitBody = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let target = match probe_target_from_body(body) {
            Ok(t) => t,
            Err(context) => return probe_bad_param(&context),
        };
        match service.submit(target) {
            Ok(id) => json(
                StatusCode::OK,
                &serde_json::json!({"schema_version": 1u32, "job_id": id}),
            ),
            Err(err) => {
                // 范围外/预算耗尽 = 请求语义问题（400 + 稳定码——服务面
                // 拒绝不产生作业，错误信封带服务面稳定码原样）
                json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({
                        "schema_version": 1u32,
                        "error": {"code": err.code, "context": err.detail},
                    }),
                )
            }
        }
    }

    /// 取消探测作业（RIL-061）：排队中取消立即终态（verdict = cancelled）；
    /// 运行中取消置协作令牌（verdict = probe.cancel.requested，终态由执行
    /// 器协作退出归类）；已终态作业返回其状态原样。未知 ID → 404。
    async fn handle_probe_cancel(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let Some(service) = self.probe.as_ref() else {
            return probe_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "probe.disabled",
                "probe block absent from config: no probe authority assembled",
            );
        };
        let Some(id) = probe_id_from_query(req.uri().query().unwrap_or("")) else {
            return probe_bad_param("id must be a number");
        };
        match service.cancel(id) {
            Ok(verdict) => json(
                StatusCode::OK,
                &serde_json::json!({"schema_version": 1u32, "id": id, "verdict": verdict}),
            ),
            Err(err) => probe_error(StatusCode::NOT_FOUND, err.code, &err.detail),
        }
    }

    /// 纯路由推演（RIL-065 共享应用服务面）：生产求值器 + 调用时刻冻结
    /// 快照（RIL-054）——无 DNS/拨号/OS 查询、零副作用。入体的不可信
    /// 回显字段（host/generation/ingress/进程证据/注解）逐字段消毒后才
    /// 进推演——输出由消毒后的输入构造，解释面干净出自构造。输入校验
    /// 错误（proto 非法等）答 400 + `explain.input.invalid` 稳定码。
    async fn handle_explain(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let input: rillane_routing::ExplainInput = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let input = sanitize_explain_input(input);
        match self.runtime.explain_route(&input) {
            Ok(explanation) => json(
                StatusCode::OK,
                &serde_json::json!({
                    "schema_version": 1u32,
                    "explanation": explanation,
                }),
            ),
            Err(err) => trace_error(
                StatusCode::BAD_REQUEST,
                "explain.input.invalid",
                &err.to_string(),
            ),
        }
    }

    /// Clash 兼容 `/proxies`：只读子集——每个出口名映射到 Clash 代理对象。
    /// `type` 取 direct/reject/其余按 egress_kind；`now`/`udp`/`history` 提供
    /// 面板所需最小字段。metacubexd/yacd 可直连读取。
    async fn handle_clash_proxies(&self) -> Response<RespBody> {
        let connectors = self.runtime.get_egress_connectors();
        let mut map: HashMap<String, ClashProxyDto> = HashMap::new();
        for (name, connector) in connectors {
            map.insert(
                name,
                ClashProxyDto {
                    r#type: connector.name().to_string(),
                    now: String::new(),
                    udp: false,
                    history: Vec::new(),
                },
            );
        }
        json(StatusCode::OK, &map)
    }

    /// Clash 兼容 `/connections`：只读子集——从 flow stats 派生。
    /// 聚合语义显式化（RIL-056）：映射细节见 [`clash_connections_view`]。
    async fn handle_clash_connections(&self) -> Response<RespBody> {
        let flows = self.runtime.get_flow_stats();
        json(StatusCode::OK, &clash_connections_view(flows))
    }

    /// Clash 兼容 `/traffic`：只读子集——runtime 全局流量（up/down）。
    async fn handle_clash_traffic(&self) -> Response<RespBody> {
        let s = self.runtime.get_stats();
        let out = serde_json::json!({
            "up": s.bytes_uploaded,
            "down": s.bytes_downloaded,
        });
        json(StatusCode::OK, &out)
    }

    async fn handle_runtime_stats(&self) -> Response<RespBody> {
        let stats = self.runtime.get_stats();
        let dto = RuntimeStatsDto::from(stats);
        json(StatusCode::OK, &dto)
    }

    /// O-slo1 观测面（slo-scoring.md §10）：组实时质量快照——成员数据源
    /// （real/legacy/unknown）、p95/丢包、门判定与 latency 组当前确定性选点。
    async fn handle_routing_stats(&self) -> Response<RespBody> {
        let groups: Vec<RoutingGroupQualityDto> = self
            .runtime
            .get_routing_quality()
            .into_iter()
            .map(RoutingGroupQualityDto::from)
            .collect();
        json(StatusCode::OK, &RoutingStatsDto { groups })
    }

    async fn handle_runtime_config(&self) -> Response<RespBody> {
        let cfg = self.runtime.get_config();
        json(StatusCode::OK, &cfg)
    }

    async fn handle_events(&self) -> Response<RespBody> {
        let guard = self.event_log.lock().await;
        let mut out = String::new();
        for line in guard.iter() {
            out.push_str(line);
        }
        text(StatusCode::OK, &out)
    }

    async fn handle_logs(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let lines = req
            .uri()
            .query()
            .and_then(|q| {
                q.split('&').find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    if k == "lines" {
                        v.parse::<usize>().ok()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(500);
        let lines = lines.clamp(1, 5000);

        match rillane_telemetry::logs_text(lines) {
            Some(t) if !t.is_empty() => text(StatusCode::OK, &t),
            Some(_) => text(StatusCode::OK, ""),
            None => text(StatusCode::NOT_FOUND, "log capture disabled"),
        }
    }

    async fn handle_register_node(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let registry = match self.mesh() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: RegisterNodeRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let role = match dto.role.as_str() {
            "client" => NodeRole::Client,
            "relay" => NodeRole::Relay,
            "exit" => NodeRole::Exit,
            "hybrid" => NodeRole::Hybrid,
            _ => return text(StatusCode::BAD_REQUEST, "invalid role"),
        };

        let addr: SocketAddr = match dto.addr.parse() {
            Ok(v) => v,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid addr"),
        };

        let mut record = NodeRecord::new(dto.id.clone(), role, addr);
        if let Some(cap) = dto.capability {
            record.capability = cap;
        }
        if let Err(e) = registry.register_node(record) {
            return text(StatusCode::BAD_REQUEST, &format!("register failed: {e}"));
        }

        json(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    async fn handle_update_link_state(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let registry = match self.mesh() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: LinkStateUpdateRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let link = LinkState {
            source: dto.source,
            target: dto.target,
            latency_ms: dto.latency_ms,
            bandwidth_mbps: dto.bandwidth_mbps,
            packet_loss_rate: dto.packet_loss_rate,
            last_updated: Instant::now(),
        };

        if let Err(e) = registry.update_link_state(link) {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("update link state failed: {e}"),
            );
        }

        json(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    /// P2-1 §5：最近链路变更事件（切换/终止按因留痕，cap 100 最新保留）。
    /// 门控随 mesh 能力存在性（§5 未启用 503 同 /nodes 先例——账本宿主链路
    /// 管理器在 mesh 关闭的构建形态下也存在，mesh 注册表才是能力边界）。
    async fn handle_mesh_switches(&self) -> Response<RespBody> {
        if let Err(r) = self.mesh() {
            return r;
        }
        let events = match self.runtime.get_chain_manager() {
            Some(mgr) => mgr.get_recent_switches(usize::MAX),
            None => Vec::new(),
        };
        json(StatusCode::OK, &MeshSwitchesDto { events })
    }

    async fn handle_chain_dry_run(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let dto: ChainDryRunRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let constraints = dto.constraints.map(Into::into);
        let res = self
            .runtime
            .dry_run_chain(&dto.source, &dto.target, constraints)
            .await;

        match res {
            Ok(r) => json(StatusCode::OK, &r),
            Err(e) => text(StatusCode::BAD_REQUEST, &format!("dry-run failed: {e}")),
        }
    }

    async fn handle_chain_create(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: ChainCreateRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let session_id = dto
            .session_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let session_uuid = match uuid::Uuid::parse_str(&session_id) {
            Ok(v) => v,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid session_id"),
        };

        let constraints: Option<ChainConstraints> = dto.constraints.map(Into::into);
        let chain = mgr
            .get_or_create_chain(session_uuid, &dto.source, &dto.target, constraints)
            .await;

        match chain {
            Ok(ctx) => json(StatusCode::OK, &ChainContextDto::from(ctx)),
            Err(e) => text(
                StatusCode::BAD_REQUEST,
                &format!("create chain failed: {e}"),
            ),
        }
    }

    async fn handle_chain_get(&self, path: &str) -> Response<RespBody> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let chain_id = path.trim_start_matches("/chains/").trim();
        if chain_id.is_empty() || chain_id == "stats" {
            return text(StatusCode::NOT_FOUND, "not found");
        }

        match mgr.get_chain(chain_id) {
            Some(ctx) => json(StatusCode::OK, &ChainContextDto::from(ctx)),
            None => text(StatusCode::NOT_FOUND, "chain not found"),
        }
    }

    async fn handle_chain_delete(&self, path: &str) -> Response<RespBody> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let chain_id = path.trim_start_matches("/chains/").trim();
        if chain_id.is_empty() || chain_id == "stats" {
            return text(StatusCode::NOT_FOUND, "not found");
        }

        match mgr.terminate_chain(chain_id).await {
            Ok(()) => json(StatusCode::OK, &serde_json::json!({ "ok": true })),
            Err(e) => text(StatusCode::BAD_REQUEST, &format!("terminate failed: {e}")),
        }
    }

    async fn handle_chain_stats(&self) -> Response<RespBody> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let stats = mgr.get_stats().await;
        json(StatusCode::OK, &stats)
    }

    async fn handle_subscriptions_list(&self) -> Response<RespBody> {
        let mgr = match self.subscription_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let subs = mgr.list_subscriptions();
        let dtos: Vec<SubscriptionDto> = subs.into_iter().map(SubscriptionDto::from).collect();
        json(StatusCode::OK, &dtos)
    }

    async fn handle_subscription_add(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        let mgr = match self.subscription_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: AddSubscriptionRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let mut sub = Subscription::new(dto.name, dto.url);
        sub.r#type = dto.r#type;
        if let Some(enabled) = dto.enabled {
            sub.enabled = enabled;
        }
        if let Some(refresh_interval) = dto.refresh_interval {
            sub.refresh_interval = refresh_interval;
        }
        if let Some(timeout) = dto.timeout {
            sub.timeout = timeout;
        }
        if let Some(headers) = dto.headers {
            sub.headers = headers;
        }
        sub.user_agent = dto.user_agent;

        if let Err(e) = mgr.add_subscription(sub) {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("add subscription failed: {e}"),
            );
        }

        json(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    async fn handle_subscription_remove(&self, path: &str) -> Response<RespBody> {
        let mgr = match self.subscription_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let name = path.trim_start_matches("/subscriptions/").trim();
        if name.is_empty() {
            return text(StatusCode::BAD_REQUEST, "missing name");
        }

        if let Err(e) = mgr.remove_subscription(name) {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("remove subscription failed: {e}"),
            );
        }
        json(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    async fn handle_subscription_refresh(&self, path: &str) -> Response<RespBody> {
        let mgr = match self.subscription_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let trimmed = path
            .trim_start_matches("/subscriptions/")
            .trim_end_matches("/refresh")
            .trim_matches('/');
        if trimmed.is_empty() {
            return text(StatusCode::BAD_REQUEST, "missing name");
        }

        let subscription = match mgr.get_subscription(trimmed) {
            Some(s) => s,
            None => return text(StatusCode::NOT_FOUND, "subscription not found"),
        };

        let old_hash = subscription.content_hash.clone();

        let content = match mgr.refresh_subscription(trimmed).await {
            Ok(v) => v,
            Err(e) => return text(StatusCode::BAD_REQUEST, &format!("refresh failed: {e}")),
        };

        let new_hash = mgr
            .get_subscription(trimmed)
            .and_then(|s| s.content_hash.clone());
        let changed = new_hash != old_hash;

        if !changed {
            return json(
                StatusCode::OK,
                &serde_json::json!({
                    "ok": true,
                    "subscription": trimmed,
                    "changed": false,
                }),
            );
        }

        let subscription = match mgr.get_subscription(trimmed) {
            Some(s) => s,
            None => return text(StatusCode::NOT_FOUND, "subscription not found"),
        };

        let converter = SubscriptionConverter::new();
        let converted = match converter.auto_convert(&subscription, &content).await {
            Ok(v) => v,
            Err(e) => return text(StatusCode::BAD_REQUEST, &format!("convert failed: {e}")),
        };

        // RIL-016：订阅名作来源命名空间——刷新只动自己名下对象，
        // 用户本地配置（游戏规则/监听口/系统路由/插件/凭证）与他订阅
        // 对象永不覆盖
        let merge_stats: SourceMergeStats = match self
            .runtime
            .merge_source_delta(trimmed, &converted.config)
            .await
        {
            Ok(v) => v,
            Err(e) => return text(StatusCode::BAD_REQUEST, &format!("apply failed: {e}")),
        };

        json(
            StatusCode::OK,
            &serde_json::json!({
                "ok": true,
                "subscription": trimmed,
                "changed": true,
                "converted": {
                    "nodes": converted.config.egress.len(),
                    "groups": converted.config.routing.groups.len(),
                    "rules": converted.config.routing.rules.len(),
                    "warnings": converted.warnings,
                },
                "merged": merge_stats,
            }),
        )
    }

    async fn handle_subscriptions_refresh_all(&self) -> Response<RespBody> {
        let mgr = match self.subscription_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let converter = SubscriptionConverter::new();
        let mut out = Vec::new();
        let names: Vec<String> = mgr
            .list_subscriptions()
            .into_iter()
            .map(|s| s.name)
            .collect();
        for name in names {
            let old_hash = mgr
                .get_subscription(&name)
                .and_then(|s| s.content_hash.clone());

            let content = match mgr.refresh_subscription(&name).await {
                Ok(v) => v,
                Err(e) => {
                    out.push(serde_json::json!({"name": name, "ok": false, "error": format!("refresh failed: {e}")}));
                    continue;
                }
            };

            let new_hash = mgr
                .get_subscription(&name)
                .and_then(|s| s.content_hash.clone());
            let changed = new_hash != old_hash;
            if !changed {
                out.push(serde_json::json!({
                    "name": name,
                    "ok": true,
                    "changed": false,
                }));
                continue;
            }

            let Some(sub) = mgr.get_subscription(&name) else {
                out.push(
                    serde_json::json!({"name": name, "ok": false, "error": "subscription missing"}),
                );
                continue;
            };

            match converter.auto_convert(&sub, &content).await {
                // RIL-016：来源作用域合并（订阅名 = 命名空间），同上
                Ok(converted) => match self.runtime.merge_source_delta(&name, &converted.config).await {
                    Ok(merge_stats) => out.push(serde_json::json!({
                        "name": name,
                        "ok": true,
                        "changed": true,
                        "converted_nodes": converted.config.egress.len(),
                        "merged": merge_stats,
                        "warnings": converted.warnings,
                    })),
                    Err(e) => out.push(serde_json::json!({"name": name, "ok": false, "error": format!("apply failed: {e}")})),
                },
                Err(e) => out.push(serde_json::json!({"name": name, "ok": false, "error": format!("convert failed: {e}")})),
            }
        }

        json(StatusCode::OK, &out)
    }

    /// network-route.md §3: POST /network/route/apply {dry_run?: bool}
    // 路由面属 TUN 数据面：Linux 门控（platform-packaging.md）；非 Linux 恒
    // 503——语义同 TUN 未装配分支，端点形状不因平台消失
    #[cfg(target_os = "linux")]
    async fn handle_route_apply(&self, req: Request<impl RequestBody>) -> Response<RespBody> {
        #[derive(Deserialize)]
        struct ApplyReq {
            #[serde(default)]
            dry_run: bool,
        }
        let ApplyReq { dry_run } = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let tun_ingress = match self.runtime.get_tun_ingress() {
            Some(t) => t,
            None => {
                return text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TUN 未启用（检查 network 配置与日志）",
                );
            }
        };

        let rm = tun_ingress.route_manager();
        let rm_guard = rm.lock().await;

        match rm_guard.apply_desired(dry_run).await {
            Ok(outcome) => {
                let mut planned = Vec::new();
                for step in &outcome.planned {
                    planned.push(serde_json::json!({
                        "argv": step.argv(),
                        "at": SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }));
                }
                let mut executed = Vec::new();
                for step in &outcome.executed {
                    executed.push(serde_json::json!({
                        "argv": step.argv(),
                        "at": SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }));
                }
                let mut rolled_back = Vec::new();
                for step in &outcome.rolled_back {
                    rolled_back.push(serde_json::json!({
                        "argv": step.undo_argv(),
                        "at": SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }));
                }
                json(
                    StatusCode::OK,
                    &serde_json::json!({
                        "planned": planned,
                        "executed": executed,
                        "rolled_back": rolled_back
                    }),
                )
            }
            Err(apply_failure) => {
                let mut rolled_back = Vec::new();
                for step in &apply_failure.rolled_back {
                    rolled_back.push(serde_json::json!({
                        "argv": step.undo_argv(),
                        "at": SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }));
                }
                json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({
                        "error": apply_failure.error.to_string(),
                        "rolled_back": rolled_back
                    }),
                )
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn handle_route_apply(&self, _req: Request<impl RequestBody>) -> Response<RespBody> {
        text(
            StatusCode::SERVICE_UNAVAILABLE,
            "TUN 未启用（仅 Linux 支持）",
        )
    }

    /// network-route.md §3: POST /network/route/clear
    #[cfg(target_os = "linux")]
    async fn handle_route_clear(&self, _req: Request<impl RequestBody>) -> Response<RespBody> {
        let tun_ingress = match self.runtime.get_tun_ingress() {
            Some(t) => t,
            None => {
                return text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TUN 未启用（检查 network 配置与日志）",
                );
            }
        };

        let rm = tun_ingress.route_manager();
        let rm_guard = rm.lock().await;

        match rm_guard.clear().await {
            Ok(undone) => {
                let mut steps = Vec::new();
                for step in undone {
                    steps.push(serde_json::json!({
                        "argv": step.undo_argv(),
                        "at": SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }));
                }
                json(StatusCode::OK, &serde_json::json!({ "undone": steps }))
            }
            Err(e) => text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("clear failed: {e}"),
            ),
        }
    }

    /// network-route.md §3: GET /network/route/status
    #[cfg(target_os = "linux")]
    async fn handle_route_status(&self) -> Response<RespBody> {
        let tun_ingress = match self.runtime.get_tun_ingress() {
            Some(t) => t,
            None => {
                return text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TUN 未启用（检查 network 配置与日志）",
                );
            }
        };

        let rm = tun_ingress.route_manager();
        let rm_guard = rm.lock().await;
        let status = rm_guard.status();

        let mut applied = Vec::new();
        for record in &status.applied {
            let at_secs = record
                .at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            applied.push(serde_json::json!({
                "argv": record.step.argv(),
                "at": at_secs
            }));
        }

        let mode = match self.runtime.get_network_mode() {
            Some(rillane_runtime::NetworkMode::Tun) => "tun",
            Some(rillane_runtime::NetworkMode::Transparent) => "transparent",
            Some(rillane_runtime::NetworkMode::Tap) => "tap",
            Some(rillane_runtime::NetworkMode::Hybrid) => "hybrid",
            None => "unknown",
        };

        json(
            StatusCode::OK,
            &serde_json::json!({
                "mode": mode,
                "device": status.device,
                "mtu": status.mtu,
                "up": status.up,
                "applied": applied
            }),
        )
    }

    #[cfg(not(target_os = "linux"))]
    async fn handle_route_clear(&self, _req: Request<impl RequestBody>) -> Response<RespBody> {
        text(
            StatusCode::SERVICE_UNAVAILABLE,
            "TUN 未启用（仅 Linux 支持）",
        )
    }

    #[cfg(not(target_os = "linux"))]
    async fn handle_route_status(&self) -> Response<RespBody> {
        text(
            StatusCode::SERVICE_UNAVAILABLE,
            "TUN 未启用（仅 Linux 支持）",
        )
    }
}

/// P0-5 §9-1 `/udp/stats` 响应体
#[derive(Debug, Clone, Serialize)]
struct UdpStatsDto {
    table: TableSnapshot,
    ingress: UdpIngressSnapshot,
    /// None 序列化为 null——面未启用与零流量两态可区分（§9-1）
    mesh: Option<rillane_runtime::UdpFaceSnapshot>,
    /// 仅 chain+udp client 桥装配时出现（§2.4 收编裁决：未装配省略该键）
    #[serde(skip_serializing_if = "Option::is_none")]
    mesh_client: Option<UdpClientDroppedDto>,
}

#[derive(Debug, Clone, Serialize)]
struct UdpClientDroppedDto {
    dropped: u64,
    /// P2-7 M1 §3.6：下行防重放窗口拒帧（E4，与 dropped 分立）
    replay_dropped: u64,
}

/// P2-8 M1 dns-partition.md §6 `/dns/stats` 响应体（引擎 `DnsStatsSnapshot`
/// 逐字段镜像 + 装配态；listen None 序列化为 null——关闭与启用两态可区分）
#[derive(Debug, Clone, Serialize)]
struct DnsStatsDto {
    enabled: bool,
    listen: Option<String>,
    total_queries: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_hit_rate: f64,
    upstream_failures: u64,
    pollution_suspected: u64,
    domestic_queries: u64,
    trusted_queries: u64,
}

/// 观测轮（plugin-loader.md §0 计数面）`/plugins/stats` 响应体。
/// plugins 空 = obfs 未启用/无 plugins 声明（客户端以数组空判形态）。
#[derive(Debug, Clone, Serialize)]
struct PluginsStatsDto {
    plugins: Vec<PluginStatsDto>,
}

#[derive(Debug, Clone, Serialize)]
struct PluginStatsDto {
    name: String,
    calls: u64,
    denied: u64,
    traps: u64,
    fuel_exhausted: u64,
}

/// P1-5 §6.2 响应体（keys = 每键 idle 快照；leased 全局 gauge 不分键记账）
#[derive(Debug, Clone, Serialize)]
struct EgressPoolStatsDto {
    enabled: bool,
    tls_resumption: bool,
    keys: Vec<EgressPoolKeyDto>,
    counters: EgressPoolCountersDto,
    reuse_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
struct EgressPoolKeyDto {
    key: String,
    idle: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
struct EgressPoolCountersDto {
    hit: u64,
    miss: u64,
    stale_redial: u64,
    dials_ok: u64,
    dials_err: u64,
}

/// P0-5 §2.2 reason 封闭枚举（与 `TableSnapshot` dropped/expired 映射键同源；
/// 渲染静态可枚举，恒渲染不依赖运行时 Map 键集）
const UDP_DROP_REASONS: [&str; 6] = [
    "session_limit",
    "mapping_limit",
    "no_binding",
    "shutting_down",
    "send_failed",
    "downlink_full",
];
const UDP_EXPIRE_REASONS: [&str; 3] = ["idle", "lifetime", "revoked"];

/// P0-5 §6-2 恒渲染：UDP 关闭时的全零表快照（reason 键齐全）
fn udp_zero_table_snapshot() -> TableSnapshot {
    TableSnapshot {
        sessions_active: 0,
        sessions_total: 0,
        mappings_active: 0,
        reroutes: 0,
        bytes_up: 0,
        bytes_down: 0,
        dropped: UDP_DROP_REASONS
            .iter()
            .map(|r| (r.to_string(), 0))
            .collect(),
        expired: UDP_EXPIRE_REASONS
            .iter()
            .map(|r| (r.to_string(), 0))
            .collect(),
        sessions: Vec::new(),
    }
}

/// P2-1 §5：`GET /mesh/switches` 响应体（事件形即 chain.rs SwitchEvent 序列化）
#[derive(Debug, Serialize)]
struct MeshSwitchesDto {
    events: Vec<rillane_runtime::SwitchEvent>,
}

/// P2-7 M0 §2.2：`GET /mtls/revoked` 响应体（RevokedSnapshot 序列化形状）
#[derive(Debug, Clone, Serialize)]
struct MtlsRevokedDto {
    static_count: usize,
    file: Option<MtlsRevokedFileDto>,
}

#[derive(Debug, Clone, Serialize)]
struct MtlsRevokedFileDto {
    path: String,
    loaded: bool,
    error: Option<String>,
    mtime_secs: u64,
    count: usize,
    entries: Vec<String>,
}

impl From<rillane_runtime::mesh_transport::RevokedSnapshot> for MtlsRevokedDto {
    fn from(s: rillane_runtime::mesh_transport::RevokedSnapshot) -> Self {
        Self {
            static_count: s.static_entries.len(),
            file: s.file.map(|f| MtlsRevokedFileDto {
                path: f.path,
                loaded: f.loaded,
                error: f.error,
                mtime_secs: f.mtime_secs,
                count: f.entries.len(),
                entries: f.entries,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct MeshNodeDto {
    id: String,
    role: String,
    addr: String,
    capability: NodeCapability,
    online: bool,
    last_seen_seconds: u64,
}

/// Clash 兼容 `/proxies` 单代理对象（只读子集）。
#[derive(Debug, Clone, Serialize)]
struct ClashProxyDto {
    r#type: String,
    now: String,
    udp: bool,
    history: Vec<ClashProxyHistory>,
}

#[derive(Debug, Clone, Serialize)]
struct ClashProxyHistory {
    time: u64,
    delay_ms: u32,
}

/// Clash 兼容 `/connections` 单连接（只读子集）。
/// Clash 兼容 `/connections` 视图映射（RIL-056，纯函数便于契约测试）：
/// 每条是 (ingress, egress) 流量统计对，**不是逐连接记录**。真实字段
/// 只有字节计数与聚合键；缺失事实（开始时刻/域名/规则/链路）一律
/// null/空不伪造；顶层 `rillane` 块显式声明聚合语义与可用性边界；
/// totals 是表内可见项求和（不虚报全局数）。逐连接真实轨迹在内核
/// 查询服务（RIL-055），与本聚合视图语义分立（`/flows` 同为聚合面）。
fn clash_connections_view(flows: Vec<FlowStatItem>) -> serde_json::Value {
    let upload_total: u64 = flows.iter().map(|f| f.upstream).sum();
    let download_total: u64 = flows.iter().map(|f| f.downstream).sum();
    let items: Vec<ClashConnectionDto> = flows
        .into_iter()
        .map(|f| ClashConnectionDto {
            id: format!("{}-{}", f.ingress, f.egress),
            metadata: ClashConnMeta { host: None },
            rule: None,
            rule_payload: None,
            chains: Vec::new(),
            start: None,
            upload: f.upstream,
            download: f.downstream,
            upload_total: f.upstream,
            download_total: f.downstream,
        })
        .collect();
    serde_json::json!({
        "downloadTotal": download_total,
        "uploadTotal": upload_total,
        "connections": items,
        "rillane": {
            "view": "aggregate",
            "id_semantics": "ingress-egress pair key, not a per-flow id",
            "note": "missing time/domain/rule/chains are null, not fabricated; per-flow traces live in the kernel query service",
        }
    })
}

/// Clash 兼容 `/connections` 条目（RIL-056）：聚合语义显式化——缺失
/// 事实序列化为 null/空（面板可辨「无记录」与「零值」的区别）。
#[derive(Debug, Clone, Serialize)]
struct ClashConnectionDto {
    /// 聚合键（`<ingress>-<egress>`）——不是逐连接 flow ID
    id: String,
    metadata: ClashConnMeta,
    /// 聚合统计不携带规则事实——null = 无记录，不伪造
    rule: Option<String>,
    /// 聚合统计不携带规则载荷——null = 无记录，不伪造
    rule_payload: Option<String>,
    /// 聚合统计不携带链路事实——空 = 无记录，不伪造
    chains: Vec<String>,
    /// 聚合统计不携带开始时刻——null = 无记录，不伪造
    start: Option<u64>,
    /// 观测窗口内上行/下行字节（真实计数）
    upload: u64,
    download: u64,
    upload_total: u64,
    download_total: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ClashConnMeta {
    /// 聚合统计不携带域名事实——null = 无记录，不伪造
    host: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeStatsDto {
    uptime_seconds: u64,
    total_connections: u64,
    active_connections: u64,
    total_bytes_transferred: u64,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    mesh_nodes: usize,
    mesh_sessions: usize,
    network_interfaces: usize,
    subscription_nodes: usize,
    error_count: u64,
    last_updated_ago_seconds: f64,
}

/// O-slo1 观测面 `/routing/stats` 响应体（rillane-routing `GroupQuality`/
/// `MemberQuality` 逐字段镜像）
#[derive(Debug, Clone, Serialize)]
struct RoutingStatsDto {
    groups: Vec<RoutingGroupQualityDto>,
}

#[derive(Debug, Clone, Serialize)]
struct RoutingGroupQualityDto {
    name: String,
    strategy: String,
    selected: Option<String>,
    members: Vec<RoutingMemberQualityDto>,
}

#[derive(Debug, Clone, Serialize)]
struct RoutingMemberQualityDto {
    name: String,
    healthy: bool,
    source: String,
    p95_ms: Option<u64>,
    loss_ratio: Option<f64>,
    score: Option<f64>,
    gate_pass: Option<bool>,
}

impl From<rillane_runtime::GroupQuality> for RoutingGroupQualityDto {
    fn from(g: rillane_runtime::GroupQuality) -> Self {
        Self {
            name: g.name,
            strategy: g.strategy,
            selected: g.selected,
            members: g.members.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<rillane_runtime::MemberQuality> for RoutingMemberQualityDto {
    fn from(m: rillane_runtime::MemberQuality) -> Self {
        Self {
            name: m.name,
            healthy: m.healthy,
            source: m.source.to_string(),
            p95_ms: m.p95_ms,
            loss_ratio: m.loss_ratio,
            score: m.score,
            gate_pass: m.gate_pass,
        }
    }
}

impl From<rillane_runtime::RuntimeStats> for RuntimeStatsDto {
    fn from(s: rillane_runtime::RuntimeStats) -> Self {
        Self {
            uptime_seconds: s.uptime_seconds,
            total_connections: s.total_connections,
            active_connections: s.active_connections,
            total_bytes_transferred: s.total_bytes_transferred,
            bytes_uploaded: s.bytes_uploaded,
            bytes_downloaded: s.bytes_downloaded,
            mesh_nodes: s.mesh_nodes,
            mesh_sessions: s.mesh_sessions,
            network_interfaces: s.network_interfaces,
            subscription_nodes: s.subscription_nodes,
            error_count: s.error_count,
            last_updated_ago_seconds: s.last_updated.elapsed().as_secs_f64(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct SubscriptionDto {
    name: String,
    url: String,
    r#type: Option<SubscriptionType>,
    enabled: bool,
    refresh_interval: u64,
    timeout: u64,
    last_error: Option<String>,
    last_updated: Option<String>,
}

impl From<Subscription> for SubscriptionDto {
    fn from(s: Subscription) -> Self {
        Self {
            name: s.name,
            url: s.url,
            r#type: s.r#type,
            enabled: s.enabled,
            refresh_interval: s.refresh_interval,
            timeout: s.timeout,
            last_error: s.last_error,
            last_updated: s.last_updated.map(|t| t.to_rfc3339()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct AddSubscriptionRequest {
    name: String,
    url: String,
    #[serde(default)]
    r#type: Option<SubscriptionType>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    refresh_interval: Option<u64>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterNodeRequest {
    id: String,
    role: String,
    addr: String,
    #[serde(default)]
    capability: Option<NodeCapability>,
}

#[derive(Debug, Deserialize)]
struct LinkStateUpdateRequest {
    source: String,
    target: String,
    latency_ms: u32,
    bandwidth_mbps: u32,
    #[serde(default)]
    packet_loss_rate: f32,
}

#[derive(Debug, Deserialize)]
struct ChainDryRunRequest {
    source: String,
    target: String,
    #[serde(default)]
    constraints: Option<ChainConstraintsDto>,
}

#[derive(Debug, Deserialize)]
struct ChainCreateRequest {
    #[serde(default)]
    session_id: Option<String>,
    source: String,
    target: String,
    #[serde(default)]
    constraints: Option<ChainConstraintsDto>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct ChainConstraintsDto {
    #[serde(default)]
    max_hops: Option<usize>,
    #[serde(default)]
    max_latency_ms: Option<u32>,
    #[serde(default)]
    min_bandwidth_mbps: Option<u32>,
    #[serde(default)]
    required_nodes: Vec<String>,
    #[serde(default)]
    forbidden_nodes: Vec<String>,
    #[serde(default)]
    required_countries: Vec<String>,
    #[serde(default)]
    forbidden_countries: Vec<String>,
}

impl From<ChainConstraintsDto> for ChainConstraints {
    fn from(v: ChainConstraintsDto) -> Self {
        Self {
            max_hops: v.max_hops,
            max_latency_ms: v.max_latency_ms,
            min_bandwidth_mbps: v.min_bandwidth_mbps,
            required_nodes: v.required_nodes,
            forbidden_nodes: v.forbidden_nodes,
            required_countries: v.required_countries,
            forbidden_countries: v.forbidden_countries,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ChainContextDto {
    chain_id: String,
    source_node: String,
    target_node: String,
    current_path: Vec<String>,
    hop_count: usize,
    hop_latencies: Vec<u32>,
    hop_bandwidths: Vec<u32>,
    reliability_score: f32,
    status: String,
    fallback_paths: Vec<Vec<String>>,
    current_fallback_index: usize,
    created_at_seconds: u64,
    last_updated_seconds: u64,
}

impl From<rillane_core::ChainContext> for ChainContextDto {
    fn from(v: rillane_core::ChainContext) -> Self {
        Self {
            chain_id: v.chain_id,
            source_node: v.source_node,
            target_node: v.target_node,
            current_path: v.current_path,
            hop_count: v.hop_count,
            hop_latencies: v.hop_latencies,
            hop_bandwidths: v.hop_bandwidths,
            reliability_score: v.reliability_score,
            status: format!("{:?}", v.status),
            fallback_paths: v.fallback_paths,
            current_fallback_index: v.current_fallback_index,
            created_at_seconds: v.created_at.elapsed().as_secs(),
            last_updated_seconds: v.last_updated.elapsed().as_secs(),
        }
    }
}

// Err = 错误响应体（handler ? 早退惯例），不装箱
#[allow(clippy::result_large_err)]
async fn read_json<T: for<'de> Deserialize<'de>>(
    req: Request<impl RequestBody>,
) -> Result<T, Response<RespBody>> {
    let bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|_| text(StatusCode::BAD_REQUEST, "invalid body"))?
        .to_bytes();
    serde_json::from_slice::<T>(&bytes)
        .map_err(|e| text(StatusCode::BAD_REQUEST, &format!("invalid json: {e}")))
}

/// Trace 查询面参数非法（400 + 稳定码）
fn trace_bad_param(context: &str) -> Response<RespBody> {
    trace_error(StatusCode::BAD_REQUEST, "query.param.invalid", context)
}

/// Trace 查询面稳定码错误（schema_version 冻结在错误信封内）
fn trace_error(status: StatusCode, code: &'static str, context: &str) -> Response<RespBody> {
    let out = serde_json::json!({
        "schema_version": 1u32,
        "error": {
            "code": code,
            "context": context,
        },
    });
    json(status, &out)
}

// ---------------------------------------------------------------------------
// 主动探测端点辅助（RIL-061）：与 trace 面同构的稳定码信封 + 快照冻结
// JSON 形。测量字段全部来自执行器回报——丢包率由 sent/replies 计数可算
// 而非独立发明，失败与丢包与 RTT 三路标记互不混写，无任何路径/跳点字段
// （不推断机场内部路径，debug-and-mcp.md §3）。
// ---------------------------------------------------------------------------

/// probe 端点稳定码错误（信封形状同 trace_error）
fn probe_error(status: StatusCode, code: &'static str, context: &str) -> Response<RespBody> {
    let out = serde_json::json!({
        "schema_version": 1u32,
        "error": {
            "code": code,
            "context": context,
        },
    });
    json(status, &out)
}

/// probe 端点参数非法（400 + 稳定码）
fn probe_bad_param(context: &str) -> Response<RespBody> {
    probe_error(StatusCode::BAD_REQUEST, "probe.param.invalid", context)
}

/// query 里的作业 ID（`?id=N`，非负整数；缺失/非数字 = None）
fn probe_id_from_query(query: &str) -> Option<u64> {
    query.split('&').find_map(|kv| {
        let mut parts = kv.splitn(2, '=');
        if parts.next() == Some("id") {
            parts.next().and_then(|v| v.parse::<u64>().ok())
        } else {
            None
        }
    })
}

/// explain 入体不可信回显字段消毒（RIL-065）：host/generation/ingress/
/// 进程证据/注解逐字段过不可信文本闸——推演输出由消毒后输入构造，
/// 解释面不含零宽/控制字符注入面。域名与 IP 字面量原样通过（仅不可见
/// 字符移除与有界截断——正常目标语义不受影响）。
fn sanitize_explain_input(
    mut input: rillane_routing::ExplainInput,
) -> rillane_routing::ExplainInput {
    input.generation_id = rillane_core::redact::sanitize_untrusted(&input.generation_id, 128);
    if let Some(ingress) = input.ingress.as_mut() {
        *ingress = rillane_core::redact::sanitize_untrusted(ingress, 128);
    }
    input.host = rillane_core::redact::sanitize_untrusted(&input.host, 256);
    if let Some(process) = input.process.as_mut() {
        if let Some(name) = process.name.as_mut() {
            *name = rillane_core::redact::sanitize_untrusted(name, 256);
        }
        if let Some(path) = process.path.as_mut() {
            *path = rillane_core::redact::sanitize_untrusted(path, 256);
        }
    }
    input.annotations = input
        .annotations
        .into_iter()
        .map(|(k, v)| {
            (
                rillane_core::redact::sanitize_untrusted(&k, 64),
                rillane_core::redact::sanitize_untrusted(&v, 256),
            )
        })
        .collect();
    input
}

/// 作业快照 → 冻结 JSON 形（schema_version=1：失败/测量分列，快照原样）
fn probe_job_json(s: &JobSnapshot) -> serde_json::Value {
    serde_json::json!({
        "id": s.id,
        "target": s.target,
        "state": s.state,
        "submitted_unix_ms": s.submitted_unix_ms,
        "finished_unix_ms": s.finished_unix_ms,
        "outcome": s.outcome.as_ref().map(probe_outcome_json),
        "failure": s.fail_code.map(|code| serde_json::json!({
            "code": code,
            "detail": s.fail_detail,
        })),
    })
}

/// 测量 → 冻结 JSON 形：`measurement` 字段显式标记测量类型；UDP 回显的
/// 丢包率由 sent/replies 可算（sent=0 → null，不造数），RTT 缺席如实 null
fn probe_outcome_json(o: &ProbeOutcome) -> serde_json::Value {
    match o {
        ProbeOutcome::Dns { resolved, rtt_ms } => serde_json::json!({
            "measurement": "dns",
            "resolved": resolved,
            "rtt_ms": rtt_ms,
        }),
        ProbeOutcome::Connect { rtt_ms } => serde_json::json!({
            "measurement": "connect",
            "rtt_ms": rtt_ms,
        }),
        ProbeOutcome::ProxyHandshake { rtt_ms } => serde_json::json!({
            "measurement": "proxy_handshake",
            "rtt_ms": rtt_ms,
        }),
        ProbeOutcome::UdpEcho {
            sent,
            replies,
            payload_len,
            rtt_ms,
        } => {
            let loss_ratio = if *sent > 0 {
                let raw = (*sent - *replies) as f64 / *sent as f64;
                Some((raw * 10_000.0).round() / 10_000.0)
            } else {
                None
            };
            serde_json::json!({
                "measurement": "udp_echo",
                "sent": sent,
                "replies": replies,
                "payload_len": payload_len,
                "loss_ratio": loss_ratio,
                "rtt_ms": rtt_ms,
            })
        }
    }
}

/// 提交体（显式类型标签——与配置登记表同构的闭合枚举，无自由文本；
/// addr 为 `ip:port` 文本，转换时解析校验）
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProbeSubmitBody {
    Dns {
        host: String,
    },
    Connect {
        addr: String,
    },
    UdpEcho {
        #[serde(default = "default_probe_payload_len")]
        payload_len: usize,
        addr: String,
    },
}

fn default_probe_payload_len() -> usize {
    64
}

/// 提交体 → 内核目标（addr 解析失败 = 参数非法，400 不入队）
fn probe_target_from_body(body: ProbeSubmitBody) -> Result<rillane_core::ProbeTarget, String> {
    match body {
        ProbeSubmitBody::Dns { host } => Ok(rillane_core::ProbeTarget::Dns { host }),
        ProbeSubmitBody::Connect { addr } => {
            let addr: SocketAddr = addr
                .parse()
                .map_err(|e| format!("addr must be ip:port ({e})"))?;
            Ok(rillane_core::ProbeTarget::Connect { addr })
        }
        ProbeSubmitBody::UdpEcho { payload_len, addr } => {
            let addr: SocketAddr = addr
                .parse()
                .map_err(|e| format!("addr must be ip:port ({e})"))?;
            Ok(rillane_core::ProbeTarget::UdpEcho { addr, payload_len })
        }
    }
}

/// FlowTrace → 冻结 JSON 形态（schema_version=1：字段面 + 机器码——
/// stage/evidence 用恒定机器口径，attempt 仅 Attempt 事件携带）
fn trace_trace_json(trace: &rillane_core::trace::FlowTrace) -> serde_json::Value {
    serde_json::json!({
        "flow": trace.flow.as_str(),
        "origin": trace.origin.as_str(),
        "generation": trace.generation,
        "closed": trace.closed,
        "events": trace.events.iter().map(trace_event_json).collect::<Vec<_>>(),
    })
}

/// TraceEvent → 冻结 JSON 形态（RIL-051 schema 的线格式）
fn trace_event_json(event: &rillane_core::trace::TraceEvent) -> serde_json::Value {
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
fn collector_stats_json(stats: &rillane_core::collector::CollectorStats) -> serde_json::Value {
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

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<RespBody> {
    match serde_json::to_vec(value) {
        Ok(buf) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::new(Bytes::from(buf)))
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
        Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn text(status: StatusCode, msg: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(RespBody::new(Bytes::from(msg.to_string())))
        .unwrap_or_else(|_| Response::new(RespBody::new(Bytes::from("internal error"))))
}

/// SVG 响应（RIL-062 路径图导出）——正文由渲染端生成端一次性转义
fn svg(status: StatusCode, body: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "image/svg+xml")
        .body(RespBody::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| Response::new(RespBody::new(Bytes::from("internal error"))))
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: f64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&format!("{value}\n"));
}

/// 无标签 counter 序列（P0-5 §2.1 两族之外的既有 chain 段渲染式收拢为助手）
fn push_counter(out: &mut String, name: &str, help: &str, value: f64) {
    push_metric_header(out, name, help, "counter");
    out.push_str(name);
    out.push(' ');
    out.push_str(&format!("{value}\n"));
}

fn push_metric_header(out: &mut String, name: &str, help: &str, typ: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(typ);
    out.push('\n');
}

fn push_metric_labeled(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    out.push_str(name);
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(&escape_label_value(v));
        out.push('"');
    }
    out.push('}');
    out.push(' ');
    out.push_str(&format!("{value}\n"));
}

fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TelemetrySeriesKey {
    metric: String,
    labels: Vec<(String, String)>,
}

#[derive(Debug)]
struct TelemetryExport {
    max_series: usize,
    order: VecDeque<TelemetrySeriesKey>,
    values: HashMap<TelemetrySeriesKey, f64>,
}

impl TelemetryExport {
    fn new(max_series: usize) -> Self {
        Self {
            max_series: max_series.max(1),
            order: VecDeque::new(),
            values: HashMap::new(),
        }
    }

    fn upsert(&mut self, metric_name: &str, value: f64, tags: &HashMap<String, String>) {
        let metric = sanitize_metric_name(metric_name);
        let mut labels: Vec<(String, String)> = tags
            .iter()
            .filter_map(|(k, v)| {
                let key = sanitize_label_key(k);
                if key.is_empty() {
                    None
                } else {
                    Some((key, v.clone()))
                }
            })
            .collect();
        labels.sort_by(|a, b| a.0.cmp(&b.0));
        labels.dedup_by(|a, b| a.0 == b.0);

        let key = TelemetrySeriesKey { metric, labels };
        if !self.values.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.values.insert(key.clone(), value);

        while self.order.len() > self.max_series {
            if let Some(k) = self.order.pop_front() {
                self.values.remove(&k);
            }
        }
    }
}

#[derive(Debug)]
struct CounterExport {
    max_series: usize,
    order: VecDeque<TelemetrySeriesKey>,
    values: HashMap<TelemetrySeriesKey, u64>,
}

impl CounterExport {
    fn new(max_series: usize) -> Self {
        Self {
            max_series: max_series.max(1),
            order: VecDeque::new(),
            values: HashMap::new(),
        }
    }

    fn inc(&mut self, metric_name: &str, labels: &[(&str, &str)]) {
        let metric = sanitize_metric_name_with_prefix("rillane_", metric_name);
        let mut label_pairs: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| (sanitize_label_key(k), (*v).to_string()))
            .filter(|(k, _)| !k.is_empty())
            .collect();
        label_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        label_pairs.dedup_by(|a, b| a.0 == b.0);

        let key = TelemetrySeriesKey {
            metric,
            labels: label_pairs,
        };
        if !self.values.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        let entry = self.values.entry(key).or_insert(0);
        *entry = entry.saturating_add(1);

        while self.order.len() > self.max_series {
            if let Some(k) = self.order.pop_front() {
                self.values.remove(&k);
            }
        }
    }

    fn inc_mesh_event(&mut self, event: &rillane_runtime::MeshEventType) {
        match event {
            rillane_runtime::MeshEventType::NodeRegistered { .. } => {
                self.inc("mesh_events_total", &[("type", "node_registered")]);
            }
            rillane_runtime::MeshEventType::NodeOffline { .. } => {
                self.inc("mesh_events_total", &[("type", "node_offline")]);
            }
            rillane_runtime::MeshEventType::SessionCreated { .. } => {
                self.inc("mesh_events_total", &[("type", "session_created")]);
            }
            rillane_runtime::MeshEventType::SessionEnded { .. } => {
                self.inc("mesh_events_total", &[("type", "session_ended")]);
            }
            rillane_runtime::MeshEventType::PathUpdated { .. } => {
                self.inc("mesh_events_total", &[("type", "path_updated")]);
            }
        }
    }

    fn inc_network_event(&mut self, event: &rillane_runtime::NetworkEventType) {
        match event {
            rillane_runtime::NetworkEventType::InterfaceCreated { .. } => {
                self.inc("network_events_total", &[("type", "interface_created")]);
            }
            rillane_runtime::NetworkEventType::InterfaceDestroyed { .. } => {
                self.inc("network_events_total", &[("type", "interface_destroyed")]);
            }
            rillane_runtime::NetworkEventType::InterfaceUp { .. } => {
                self.inc("network_events_total", &[("type", "interface_up")]);
            }
            rillane_runtime::NetworkEventType::InterfaceDown { .. } => {
                self.inc("network_events_total", &[("type", "interface_down")]);
            }
            rillane_runtime::NetworkEventType::RouteUpdated { .. } => {
                self.inc("network_events_total", &[("type", "route_updated")]);
            }
            rillane_runtime::NetworkEventType::PacketFiltered { .. } => {
                self.inc("network_events_total", &[("type", "packet_filtered")]);
            }
        }
    }

    fn inc_subscription_event(
        &mut self,
        subscription_name: &str,
        event: &rillane_runtime::SubscriptionEventType,
    ) {
        match event {
            rillane_runtime::SubscriptionEventType::Added { .. } => self.inc(
                "subscription_events_total",
                &[("type", "added"), ("subscription", subscription_name)],
            ),
            rillane_runtime::SubscriptionEventType::Removed { .. } => self.inc(
                "subscription_events_total",
                &[("type", "removed"), ("subscription", subscription_name)],
            ),
            rillane_runtime::SubscriptionEventType::Updated { .. } => self.inc(
                "subscription_events_total",
                &[("type", "updated"), ("subscription", subscription_name)],
            ),
            rillane_runtime::SubscriptionEventType::Refreshed { .. } => self.inc(
                "subscription_events_total",
                &[("type", "refreshed"), ("subscription", subscription_name)],
            ),
            rillane_runtime::SubscriptionEventType::Error { .. } => self.inc(
                "subscription_events_total",
                &[("type", "error"), ("subscription", subscription_name)],
            ),
        }
    }

    fn inc_error(&mut self, source: &str) {
        self.inc("errors_total", &[("source", source)]);
    }
}

fn sanitize_metric_name(metric_name: &str) -> String {
    sanitize_metric_name_with_prefix("rillane_telemetry_", metric_name)
}

fn sanitize_metric_name_with_prefix(prefix: &str, metric_name: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + metric_name.len());
    out.push_str(prefix);
    for (i, ch) in metric_name.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == ':';
        if ok {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

fn sanitize_label_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for (i, ch) in key.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_';
        if ok {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_config::{
        EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig, UdpConfig,
    };
    use rillane_runtime::{MeshConfig, RuntimeBuilder, RuntimeConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    /// env 设置守卫：测试结束恢复原值（并行测试不互相污染）。
    /// P2-7 M0 §4.3 用例专用（mTLS 装配仅能从 env 读取）。
    struct EnvGuard(Vec<(&'static str, Option<String>)>);

    impl EnvGuard {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            let old = std::env::var(key).ok();
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
            Self(vec![(key, old)])
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, old) in &self.0 {
                match old {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// 测试用自签证书（P2-7 M0 §4.3：平面构造只 load PEM 不握手，自签即可）。
    /// is_ca → BasicConstraints CA（rustls WebPkiClientVerifier root 解析要求）。
    fn gen_test_cert(cn: &str, is_ca: bool) -> (String, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
            KeyUsagePurpose,
        };
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["rillane".to_string()]).unwrap();
        params.is_ca = if is_ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    async fn build_runtime(mesh: bool, chain: bool) -> Arc<Runtime> {
        // mesh+chain 构建全部与 mtls env 快照测窗口串行（MESH_MTLS_ENV_TEST_LOCK
        // 注记）：build() 的 enable_mesh 分支在 RILLANE_MESH_MTLS=1 时无条件注入
        // from_env_strict()（runtime_builder.rs），任何并发 build 都可能吸入他测
        // env——锁住整个构建序列使窗口与调用者完全不相交（零差异路径不再赌时序）
        let _env_serial = MESH_MTLS_ENV_TEST_LOCK.lock().await;
        let cfg_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rillane.yaml");
        let cfg = RillaneConfig::load_from_path(cfg_path).unwrap();
        let rt_cfg = RuntimeConfig {
            enable_mesh: mesh,
            enable_chain: chain,
            mesh_config: if mesh {
                Some(MeshConfig {
                    allow_plaintext_data_plane: true,
                    // default() 的 data_plane_tls=from_env() 在并发测试窗口内
                    // 会吸入他测的 RILLANE_MESH_MTLS_*（mtls 快照测的临时文件），
                    // start() 读文件迟到 ENOENT——显式钉死 None 去随机性
                    data_plane_tls: None,
                    ..MeshConfig::default()
                })
            } else {
                None
            },
            ..RuntimeConfig::default()
        };
        Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(rt_cfg)
                .build()
                .unwrap(),
        )
    }

    /// P2-7 M0 §4.3：未装配 mesh → /mtls/revoked 503（/nodes 先例分层口径）。
    #[tokio::test]
    async fn mtls_revoked_503_without_mesh() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/mtls/revoked")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("mesh mTLS not enabled"));
    }

    /// P2-7 R3 测试收编：RILLANE_MESH_MTLS_* 是**进程级全局**——本测的 env 窗口
    /// 会泄漏进同进程并发跑 `start()` 的 udp_stats_endpoint_shape（build() 的
    /// data_plane_tls 注入读 env：窗口内路径存在但 cert 文件未写完 → start()
    /// load_cert_chain ENOENT 晚炸）。两测持同一把锁串行化，确定性消歧。
    static MESH_MTLS_ENV_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// P2-7 M0 §4.3：env 装配 mTLS（RILLANE_MESH_MTLS=1 + 撤销 env/文件）→ 200 形状——
    /// static_count/文件态（path/loaded/mtime_secs/count/entries/error:null）。
    #[tokio::test]
    async fn mtls_revoked_shape_with_mesh_tls() {
        let _env_serial = MESH_MTLS_ENV_TEST_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!(
            "rillaned_mtls_revoked_{}",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("ca.cert.pem");
        let cert_path = dir.join("node.cert.pem");
        let key_path = dir.join("node.key.pem");
        let revoked_path = dir.join("revoked.list");
        let (ca_pem, _ca_key) = gen_test_cert("rillane-ca", true);
        let (cert_pem, key_pem) = gen_test_cert("rillane-node", false);
        std::fs::write(&ca_path, &ca_pem).unwrap();
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        std::fs::write(&revoked_path, "node-c\nnode-b\n").unwrap();

        let _g1 = EnvGuard::set("RILLANE_MESH_MTLS", Some("1"));
        let _g2 = EnvGuard::set("RILLANE_MESH_MTLS_CA", Some(ca_path.to_str().unwrap()));
        let _g3 = EnvGuard::set("RILLANE_MESH_MTLS_CERT", Some(cert_path.to_str().unwrap()));
        let _g4 = EnvGuard::set("RILLANE_MESH_MTLS_KEY", Some(key_path.to_str().unwrap()));
        let _g5 = EnvGuard::set("RILLANE_MESH_MTLS_REVOKED_NODES", Some("node-a,node-b"));
        let _g6 = EnvGuard::set(
            "RILLANE_MESH_MTLS_REVOKED_NODES_FILE",
            Some(revoked_path.to_str().unwrap()),
        );

        // mTLS 装配 = start() 建 mesh plane（relay 角色 + UDP 面）后才回填；
        // 参照 rillane-runtime §10-S3 装配（role=relay + listen 127.0.0.1:0 + 显式明文）
        let mut cfg = RillaneConfig::load_from_path(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rillane.yaml"),
        )
        .unwrap();
        cfg.udp.enabled = true;
        let rt_cfg = RuntimeConfig {
            enable_mesh: true,
            enable_chain: true,
            mesh_config: Some(MeshConfig {
                node_id: "rillaned-mtls-test".into(),
                role: "relay".into(),
                listen_address: "127.0.0.1:0".parse().unwrap(),
                allow_plaintext_data_plane: true,
                udp_allow_plaintext_data_plane: true,
                ..MeshConfig::default()
            }),
            ..RuntimeConfig::default()
        };
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(rt_cfg)
                .build()
                .unwrap(),
        );
        let tasks = runtime.start().await.expect("start 应成功");
        let cp = ControlPlane::new(runtime, None, true);

        let body = get_body(&cp, "/mtls/revoked").await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["static_count"], 2, "静态 env 条目两条 node-a/node-b");
        let f = v["file"].as_object().expect("文件载体已配置");
        assert_eq!(f["loaded"], true);
        assert!(f["error"].is_null(), "成功载入 error 应为 null");
        assert!(f["mtime_secs"].as_u64().unwrap() > 0, "mtime 非零");
        assert_eq!(f["count"], 2, "文件条目 node-b/node-c");
        assert!(f["path"].as_str().unwrap().ends_with("revoked.list"));
        let entries: Vec<&str> = f["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect();
        assert_eq!(entries, vec!["node-b", "node-c"], "排序 + 去重");

        for t in tasks {
            t.abort();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn nodes_requires_mesh_enabled() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/nodes")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// hyper 1.x serve() 冒烟（迁移新增面：显式 accept 循环 + GracefulShutdown
    /// 排空路径——旧 hyper::Server 无直测，迁移轮补上真 socket 往返）：
    /// /health 200 返回 + oneshot 触发后 serve 任务在时限内排空退出。
    #[tokio::test]
    async fn serve_serves_health_and_shuts_down_gracefully() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, false);
        let bind: std::net::SocketAddr = free_bind().parse().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(cp.serve(bind, rx));

        // bind 在 serve() 内——轮询等监听就绪
        let mut ready = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(bind).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready, "serve 应在端口就绪");

        let mut s = tokio::net::TcpStream::connect(bind).await.unwrap();
        s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf);
        assert!(head.starts_with("HTTP/1.1 200 OK"), "health 应 200: {head}");

        let _ = tx.send(());
        timeout(Duration::from_secs(5), task)
            .await
            .expect("serve 应排空后退出")
            .expect("join")
            .expect("serve 无错误");
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text_when_enabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8(body.to_vec()).unwrap();
        assert!(s.contains("rillane_uptime_seconds"));
    }

    #[tokio::test]
    async fn metrics_returns_404_when_disabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, false);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// O-slo1 观测面：`/routing/stats` 返回配置组的实时质量报告
    #[tokio::test]
    async fn routing_stats_reports_configured_groups() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/routing/stats")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let groups = v["groups"].as_array().expect("groups 应为数组");
        let auto = groups
            .iter()
            .find(|g| g["name"] == "auto")
            .expect("模板组 auto 应在报告中");
        assert_eq!(auto["strategy"], "latency");
        let members = auto["members"].as_array().expect("members 应为数组");
        assert!(
            members
                .iter()
                .any(|m| m["name"] == "direct-main" && m["source"] == "unknown"),
            "无质量数据成员应标 unknown: {auto}"
        );
    }

    #[tokio::test]
    async fn can_register_node_when_mesh_enabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/mesh/nodes/register")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(
                r#"{"id":"n1","role":"relay","addr":"127.0.0.1:10001"}"#,
            ))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dry_run_and_create_chain_via_control_plane() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, true);

        // Register nodes.
        let reg = |id: &str, role: &str, port: u16| {
            Request::builder()
                .method(Method::POST)
                .uri("/mesh/nodes/register")
                .header(CONTENT_TYPE, "application/json")
                .body(RespBody::from(format!(
                    r#"{{"id":"{id}","role":"{role}","addr":"127.0.0.1:{port}"}}"#
                )))
                .unwrap()
        };
        assert_eq!(
            cp.handle(reg("client1", "client", 10001)).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            cp.handle(reg("exit1", "exit", 10002)).await.status(),
            StatusCode::OK
        );

        // Provide link-state so ChainBuilder uses mesh topology edges.
        let link = Request::builder()
            .method(Method::POST)
            .uri("/mesh/link-states")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(
                r#"{"source":"client1","target":"exit1","latency_ms":20,"bandwidth_mbps":100,"packet_loss_rate":0.0}"#,
            ))
            .unwrap();
        assert_eq!(cp.handle(link).await.status(), StatusCode::OK);

        // Dry-run should succeed.
        let dry = Request::builder()
            .method(Method::POST)
            .uri("/chains/dry-run")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(dry).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("success").and_then(|x| x.as_bool()), Some(true));

        // Create chain and query it back.
        let create = Request::builder()
            .method(Method::POST)
            .uri("/chains")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(create).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let chain_id = v
            .get("chain_id")
            .and_then(|x| x.as_str())
            .unwrap()
            .to_string();

        let get = Request::builder()
            .method(Method::GET)
            .uri(format!("/chains/{chain_id}"))
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// P2-1 §7-4：控制面三族按维查询 + /mesh/switches 端点。
    /// 驱动：注册双节点 + link-state（latency 20 入 RTT 环，D-1 上报流采样
    /// 源）→ 建链（单边拓扑无备用路径）→ handle_chain_failure 触发
    /// FallbackExhausted → record_link_connection/error 直写观测形丢包
    /// （数据面流驱动在单测里过重，计数器与渲染面同源）。
    #[tokio::test]
    async fn mesh_switches_endpoint_and_metric_families() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime.clone(), None, true);

        let reg = |id: &str, role: &str, port: u16| {
            Request::builder()
                .method(Method::POST)
                .uri("/mesh/nodes/register")
                .header(CONTENT_TYPE, "application/json")
                .body(RespBody::from(format!(
                    r#"{{"id":"{id}","role":"{role}","addr":"127.0.0.1:{port}"}}"#
                )))
                .unwrap()
        };
        assert_eq!(
            cp.handle(reg("client1", "client", 10001)).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            cp.handle(reg("exit1", "exit", 10002)).await.status(),
            StatusCode::OK
        );
        let link = Request::builder()
            .method(Method::POST)
            .uri("/mesh/link-states")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(
                r#"{"source":"client1","target":"exit1","latency_ms":20,"bandwidth_mbps":100,"packet_loss_rate":0.0}"#,
            ))
            .unwrap();
        assert_eq!(cp.handle(link).await.status(), StatusCode::OK);

        let create = Request::builder()
            .method(Method::POST)
            .uri("/chains")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(create).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let chain_id = v
            .get("chain_id")
            .and_then(|x| x.as_str())
            .unwrap()
            .to_string();

        // 无备用路径 → 首次故障即 FallbackExhausted（事件 + 计数器）
        runtime
            .get_chain_manager()
            .unwrap()
            .handle_chain_failure(
                &chain_id,
                "test failure",
                rillane_runtime::SwitchReason::FailureReported,
            )
            .await
            .unwrap();

        // 观测形丢包：1 连接 1 错误 → ratio 1
        let registry = runtime.get_mesh_registry().unwrap();
        registry.record_link_connection(&"client1".to_string(), &"exit1".to_string());
        registry.record_link_error(&"client1".to_string(), &"exit1".to_string());

        // /mesh/switches：事件形断言（chain_id/reason/detail 透传）
        let get = Request::builder()
            .method(Method::GET)
            .uri("/mesh/switches")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let events = v.get("events").and_then(|x| x.as_array()).unwrap();
        assert_eq!(events.len(), 1, "单事件（健康巡检 30s 间隔未触发）");
        assert_eq!(
            events[0].get("chain_id").and_then(|x| x.as_str()),
            Some(chain_id.as_str())
        );
        assert_eq!(
            events[0].get("reason").and_then(|x| x.as_str()),
            Some("fallback_exhausted")
        );
        assert_eq!(
            events[0].get("detail").and_then(|x| x.as_str()),
            Some("test failure")
        );
        assert_eq!(
            events[0].get("to_path"),
            Some(&serde_json::Value::Null),
            "耗尽事件 to=None"
        );

        // /metrics 三族按维查询（from/to/quantile/reason 标签断言）
        let get = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8(body.to_vec()).unwrap();

        // RTT 分位：单样本 20ms → p50 = p95 = 20
        assert!(s.contains(
            "rillane_mesh_link_rtt_ms{from=\"client1\",to=\"exit1\",quantile=\"p50\"} 20"
        ));
        assert!(s.contains(
            "rillane_mesh_link_rtt_ms{from=\"client1\",to=\"exit1\",quantile=\"p95\"} 20"
        ));
        // 观测形丢包 = 1/1
        assert!(s.contains("rillane_mesh_link_loss_ratio{from=\"client1\",to=\"exit1\"} 1"));
        // 切换计数族恒渲染：四因全在（零值也在），耗尽 = 1
        for reason in [
            "failure_reported",
            "fallback_exhausted",
            "ttl_expired",
            "terminated_unhealthy",
        ] {
            assert!(
                s.contains(&format!("rillane_mesh_switch_total{{reason=\"{reason}\"}}")),
                "恒渲染缺 {reason}"
            );
        }
        assert!(s.contains("rillane_mesh_switch_total{reason=\"fallback_exhausted\"} 1"));
        assert!(s.contains("rillane_mesh_switch_total{reason=\"failure_reported\"} 0"));
    }

    /// P2-1 §7-4/D-5：mesh 未启用 → 三族与端点均不渲染（链路观测随能力
    /// 存在性开落，无链路无序列名可立）
    #[tokio::test]
    async fn mesh_observability_absent_when_disabled() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let get = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8(body.to_vec()).unwrap();
        assert!(!s.contains("rillane_mesh_link_rtt_ms"));
        assert!(!s.contains("rillane_mesh_link_loss_ratio"));
        assert!(!s.contains("rillane_mesh_switch_total"));

        let get = Request::builder()
            .method(Method::GET)
            .uri("/mesh/switches")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn can_add_list_and_remove_subscription_via_control_plane() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime.clone(), None, true);

        // Add subscription.
        let add = Request::builder()
            .method(Method::POST)
            .uri("/subscriptions")
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(
                r#"{"name":"sub1","url":"https://example.com/sub.yaml","type":"clash"}"#,
            ))
            .unwrap();
        let resp = cp.handle(add).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // List subscriptions.
        let list = Request::builder()
            .method(Method::GET)
            .uri("/subscriptions")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(list).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().expect("subscription list array");
        assert!(arr
            .iter()
            .any(|s| s.get("name").and_then(|x| x.as_str()) == Some("sub1")));

        // Remove subscription.
        let remove = Request::builder()
            .method(Method::DELETE)
            .uri("/subscriptions/sub1")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(remove).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 事件广播在订阅前丢弃的回归：ControlPlane::new 必须立即订阅事件，
    /// 否则 runtime.start() 前发生的事件在 serve() 才订阅时已丢失。
    #[tokio::test]
    async fn events_before_serve_are_captured() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime.clone(), None, true);

        // 模拟生产时序：new() 构造后、serve() 订阅前，runtime 已可产生事件。
        let config = runtime.get_config();
        runtime.update_config(config).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let get = Request::builder()
            .method(Method::GET)
            .uri("/events")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("ConfigUpdated"),
            "事件应在 serve 前被订阅并记录，body: {body}"
        );
    }

    // ---------- P0-5 §10-S4 控制面渲染 ----------

    /// 找一个空闲端口（先绑后弃有竞态窗口，测试环境足够——与 runtime_builder 测试同法）
    fn free_bind() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("127.0.0.1:{}", l.local_addr().unwrap().port())
    }

    /// socks5 入口 + direct 出口 + udp.enabled 的最小配置（真 socket 往返用）
    fn s4_udp_config() -> RillaneConfig {
        RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: true,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "s4-socks".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: free_bind(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: UdpConfig {
                enabled: true,
                ..Default::default()
            },
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        }
    }

    /// P1-5 §6 测试配置：socks5 入口 + trojan(TLS) 出口 + egress_pool 启用块
    ///（全缺省子字段——验证缺省面 enabled=true/tls_resumption=true）
    fn pool_enabled_config() -> RillaneConfig {
        RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: true,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "pool-socks".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: free_bind(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![EgressDescriptor {
                name: "trojan-out".to_string(),
                spec: EgressConfig::Trojan {
                    server: "127.0.0.1".to_string(),
                    port: 1,
                    password: "pool-test".to_string(),
                    network: "tcp".to_string(),
                    path: None,
                    host: None,
                    grpc_service_name: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                    tls_fingerprint: None,
                },
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "trojan-out".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: UdpConfig {
                enabled: false,
                ..Default::default()
            },
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: Some(rillane_config::EgressPoolBlock {
                enabled: true,
                tls_resumption: None,
                max_idle_per_key: None,
                max_idle_global: None,
                low_watermark: None,
                idle_timeout_secs: None,
                dial_timeout_secs: None,
                session_cache_size: None,
                pre_dial_direct: None,
            }),
            probe: None,
        }
    }

    /// 从 /metrics 文本取指定序列（含标签）的值
    fn metric_value(body: &str, series: &str) -> Option<f64> {
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix(series) {
                if let Some(v) = rest.strip_prefix(' ') {
                    if let Ok(n) = v.trim().parse::<f64>() {
                        return Some(n);
                    }
                }
            }
        }
        None
    }

    async fn get_body(cp: &ControlPlane, path: &str) -> String {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    /// G2-14 Clash API 只读兼容子集：`/proxies` 返回出口映射、
    /// `/connections` 返回连接表、`/traffic` 返回全局 up/down。
    #[tokio::test]
    async fn clash_api_readonly_endpoints_shape() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let proxies = get_body(&cp, "/proxies").await;
        let v: serde_json::Value = serde_json::from_str(&proxies).unwrap();
        assert!(v.is_object(), "proxies 应为对象");

        let connections = get_body(&cp, "/connections").await;
        let c: serde_json::Value = serde_json::from_str(&connections).unwrap();
        assert!(c["connections"].is_array(), "connections 应为数组");
        assert!(c["downloadTotal"].is_u64(), "downloadTotal 应为 u64");

        let traffic = get_body(&cp, "/traffic").await;
        let t: serde_json::Value = serde_json::from_str(&traffic).unwrap();
        assert!(t["up"].is_u64(), "up 应为 u64");
        assert!(t["down"].is_u64(), "down 应为 u64");
    }

    /// 环回 UDP 回声（P0-2 集成先例同构）
    async fn spawn_echo_server() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], from).await;
            }
        });
        addr
    }

    /// ASSOCIATE 握手（带监听就绪重试）；控制连接随返回值存续（EOF 即吊销会话）
    async fn associate_relay_port(bind: &str) -> (tokio::net::TcpStream, u16) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut s = None;
        while s.is_none() {
            match tokio::net::TcpStream::connect(bind).await {
                Ok(stream) => s = Some(stream),
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(e) => panic!("connect {bind} 失败: {e}"),
            }
        }
        let mut s = s.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.unwrap();
        // 请求帧：VER CMD(0x03) RSV ATYP=0x01 DST=0.0.0.0:0（全零 IPv4）
        s.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00, "ASSOCIATE 应成功");
        let port = u16::from_be_bytes([reply[8], reply[9]]);
        assert_ne!(port, 0, "BND.PORT 必须真实");
        (s, port)
    }

    /// 测试 1：udp 关闭的默认 runtime——§2.2/§2.3/§2.4 序列名逐条命中且值为 0
    ///（验收 #2 恒渲染：端点不因开关消失）
    #[tokio::test]
    async fn metrics_contains_full_udp_family() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);
        let s = get_body(&cp, "/metrics").await;

        let zero_series = [
            // §2.2 会话表
            "rillane_udp_sessions_active",
            "rillane_udp_sessions_total",
            "rillane_udp_mappings_active",
            "rillane_udp_reroutes_total",
            "rillane_udp_relay_bytes_total{direction=\"up\"}",
            "rillane_udp_relay_bytes_total{direction=\"down\"}",
            "rillane_udp_relay_packets_total{direction=\"up\"}",
            "rillane_udp_relay_packets_total{direction=\"down\"}",
            "rillane_udp_dropped_total{reason=\"session_limit\"}",
            "rillane_udp_dropped_total{reason=\"mapping_limit\"}",
            "rillane_udp_dropped_total{reason=\"no_binding\"}",
            "rillane_udp_dropped_total{reason=\"shutting_down\"}",
            "rillane_udp_dropped_total{reason=\"send_failed\"}",
            "rillane_udp_dropped_total{reason=\"downlink_full\"}",
            "rillane_udp_expired_total{reason=\"idle\"}",
            "rillane_udp_expired_total{reason=\"lifetime\"}",
            "rillane_udp_expired_total{reason=\"revoked\"}",
            // §2.3 ingress / ASSOCIATE
            "rillane_udp_associates_active",
            "rillane_udp_associates_total",
            "rillane_udp_associates_rejected_total",
            "rillane_udp_associate_errors_total",
            "rillane_udp_frag_dropped_total",
            "rillane_udp_source_dropped_total",
            "rillane_udp_malformed_dropped_total",
            // §2.4 mesh 面 + client 侧
            "rillane_udp_mesh_flows_active",
            "rillane_udp_mesh_forwarded_total{direction=\"up\"}",
            "rillane_udp_mesh_forwarded_total{direction=\"down\"}",
            "rillane_udp_mesh_unknown_flow_total",
            "rillane_udp_mesh_malformed_total",
            "rillane_udp_mesh_evicted_total",
            "rillane_udp_mesh_replay_dropped_total",
            "rillane_udp_mesh_client_dropped_total",
            "rillane_udp_mesh_client_replay_dropped_total",
        ];
        for series in zero_series {
            assert_eq!(
                metric_value(&s, series),
                Some(0.0),
                "系列 {series} 应恒渲染且值为 0"
            );
        }
    }

    /// tun-dataplane.md §2.8：rillane_tun_* 序列族恒渲染（未装配 TUN 时全零
    /// ——get_tun_ingress()=None 走 default 快照），方向 up/down 双值齐全
    #[tokio::test]
    async fn metrics_contains_full_tun_family() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);
        let s = get_body(&cp, "/metrics").await;

        let zero_series = [
            "rillane_tun_flows_active",
            "rillane_tun_packets_total{direction=\"up\"}",
            "rillane_tun_packets_total{direction=\"down\"}",
            "rillane_tun_bytes_total{direction=\"up\"}",
            "rillane_tun_bytes_total{direction=\"down\"}",
            "rillane_tun_bypass_dropped_total",
            "rillane_tun_parse_errors_total",
            "rillane_tun_unknown_flow_total",
            "rillane_tun_process_attr_miss_total",
        ];
        for series in zero_series {
            assert_eq!(
                metric_value(&s, series),
                Some(0.0),
                "系列 {series} 应恒渲染且值为 0"
            );
        }
    }

    /// P1-4 §5/§7.2：obfs 序列族恒渲染（关闭态全零 = §2.5 零开销旁路的
    /// 可观测证据）；invocations 的 {name} 标签集 = 配置挂载集，测试进程
    /// 空链 → 无条目。
    #[tokio::test]
    async fn metrics_contains_full_obfs_family() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);
        let s = get_body(&cp, "/metrics").await;

        let zero_series = [
            // §5 帧计数（按 mode）+ 新增字节
            "rillane_obfs_padding_frames_total{mode=\"fixed\"}",
            "rillane_obfs_padding_frames_total{mode=\"bucket\"}",
            "rillane_obfs_padding_frames_total{mode=\"range\"}",
            "rillane_obfs_padding_bytes_total{direction=\"added\"}",
            // §5 跳过计数（按 reason；peer_version/disabled MVP 恒 0）
            "rillane_obfs_padding_skipped_total{reason=\"no_frame\"}",
            "rillane_obfs_padding_skipped_total{reason=\"overhead_cap\"}",
            "rillane_obfs_padding_skipped_total{reason=\"too_large\"}",
            "rillane_obfs_padding_skipped_total{reason=\"peer_version\"}",
            "rillane_obfs_padding_skipped_total{reason=\"disabled\"}",
        ];
        for series in zero_series {
            assert_eq!(
                metric_value(&s, series),
                Some(0.0),
                "系列 {series} 应恒渲染且值为 0"
            );
        }
        assert!(
            !s.contains("rillane_obfs_middleware_invocations_total"),
            "空链无挂载 → invocations 无条目（name 标签集 = 配置挂载集）"
        );
    }

    /// P1-5 §8.2 对照关闭态（无块）：`/egress/pool/stats` 报 enabled=false
    /// 空计数，/metrics 无 rillane_pool_* / rillane_tls_* 序列（§6.1 只随池存在渲染）。
    #[tokio::test]
    async fn pool_disabled_renders_no_pool_series() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let s = get_body(&cp, "/egress/pool/stats").await;
        assert!(
            s.contains("\"enabled\":false") && s.contains("\"reuse_ratio\":0"),
            "关闭态 stats 应报 enabled=false 零复用：{s}"
        );
        assert!(s.contains("\"hit\":0"), "关闭态计数应恒零：{s}");

        let m = get_body(&cp, "/metrics").await;
        assert!(
            !m.contains("rillane_pool_"),
            "无块 → 无 rillane_pool_* 序列（§8.2 对照关闭态）"
        );
        assert!(
            !m.contains("rillane_tls_handshakes"),
            "无块 → 无 rillane_tls_* 序列"
        );
    }

    /// P2-8 M1 dns-partition.md §6：network.dns 缺席 → `/dns/stats` 报
    /// enabled:false 零值形（形态稳定，脚本好消费）。
    #[tokio::test]
    async fn dns_stats_absent_block_renders_disabled_zero_shape() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let s = get_body(&cp, "/dns/stats").await;
        assert!(
            s.contains("\"enabled\":false") && s.contains("\"listen\":null"),
            "缺席态应报 enabled:false / listen null：{s}"
        );
        assert!(
            s.contains("\"total_queries\":0") && s.contains("\"cache_hit_rate\":0"),
            "零值计数应齐备：{s}"
        );
    }

    /// P2-8 M1 §6：块启用 → enabled:true + listen 承接配置 + 七计数键齐备
    /// （装配期零流量 → 全零；命中率口径由引擎单测钉，此处钉暴露面）。
    #[tokio::test]
    async fn dns_stats_present_block_renders_enabled_shape() {
        let mut cfg = {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../config/rillane.yaml");
            RillaneConfig::load_from_path(path).unwrap()
        };
        cfg.network = Some(rillane_config::NetworkBlockConfig {
            mode: rillane_config::NetworkBlockMode::Tun,
            tun: None,
            routing: None,
            egress_fwmark: None,
            dns: Some(rillane_config::DnsBlockConfig {
                enabled: true,
                domestic: vec![],
                trusted: vec!["1.1.1.1:53".to_string()],
                rules: vec![],
                default_group: rillane_config::DnsGroup::Trusted,
                anti_poison: rillane_config::DnsAntiPoisonMode::Off,
                tls_skip_verify: false,
                timeout_ms: 5_000,
                retries: 2,
                cache: None,
                listen_address: "127.0.0.1".parse().unwrap(),
                listen_port: 15_353,
                fake_ip: None,
                hosts: None,
            }),
        });
        let rt_cfg = RuntimeConfig {
            enable_mesh: false,
            enable_chain: false,
            mesh_config: None,
            ..RuntimeConfig::default()
        };
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(rt_cfg)
                .build()
                .unwrap(),
        );
        let cp = ControlPlane::new(runtime, None, true);

        let s = get_body(&cp, "/dns/stats").await;
        assert!(
            s.contains("\"enabled\":true") && s.contains("\"listen\":\"127.0.0.1:15353\""),
            "启用态应报 enabled:true 与配置监听：{s}"
        );
        for key in [
            "\"total_queries\":0",
            "\"cache_hits\":0",
            "\"cache_misses\":0",
            "\"upstream_failures\":0",
            "\"pollution_suspected\":0",
            "\"domestic_queries\":0",
            "\"trusted_queries\":0",
        ] {
            assert!(s.contains(key), "应含 {key}：{s}");
        }
    }

    /// 观测轮（plugin-loader.md §0 计数面）：无 obfs → `/plugins/stats` 报
    /// 空表形（恒 200，数组空判形态稳定）。
    #[tokio::test]
    async fn plugins_stats_absent_renders_empty_shape() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let s = get_body(&cp, "/plugins/stats").await;
        assert!(s.contains("\"plugins\":[]"), "缺席态应报空插件表：{s}");
    }

    /// 观测轮：plugins 声明 → 名字与四计数键齐备（装配期零流量 → 全零；
    /// 计数语义由 rillane-plugins 单测钉，此处钉控制面暴露面与 runtime 旁路
    /// 同实例性——getter 名字与 wasm plugin_name 固化名一致）。
    /// RIL-040：small 档无 WASM 面，本测试仅 full 档。
    #[cfg(feature = "full")]
    #[tokio::test]
    async fn plugins_stats_present_renders_counts_shape() {
        // 最小 wasm 插件（内联 WAT 落盘，同 obfs_config §4.3 测试法）
        let wat = r#"(module
            (memory (export "memory") 1)
            (global $heap (mut i32) (i32.const 1024))
            (data (i32.const 0) "observed-plugin\00")
            (func (export "alloc") (param $size i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $heap))
                (global.set $heap (i32.add (local.get $p) (i32.add (local.get $size) (i32.const 7))))
                (local.get $p))
            (func (export "plugin_name") (result i32) (i32.const 0))
            (func (export "on_flow") (param i32 i32 i32 i32) (result i32) (i32.const 0))
        )"#;
        let dir =
            std::env::temp_dir().join(format!("rillaned-plugins-stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wasm_path = dir.join("observed.wasm");
        std::fs::write(&wasm_path, wat::parse_str(wat).unwrap()).unwrap();

        let mut cfg = {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../config/rillane.yaml");
            RillaneConfig::load_from_path(path).unwrap()
        };
        cfg.obfuscation = Some(rillane_config::ObfuscationConfig {
            enabled: true,
            middleware: vec![],
            plugins: vec![rillane_config::ObfsPluginConfig {
                path: wasm_path,
                fuel: None,
            }],
            ..Default::default()
        });
        let rt_cfg = RuntimeConfig {
            enable_mesh: false,
            enable_chain: false,
            mesh_config: None,
            ..RuntimeConfig::default()
        };
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(rt_cfg)
                .build()
                .unwrap(),
        );
        let cp = ControlPlane::new(runtime.clone(), None, true);

        // getter 旁路与端点同源：名字一致、初始计数零
        let stats = runtime.get_plugin_stats();
        assert_eq!(stats.len(), 1, "应恰一插件");
        assert_eq!(stats[0].0, "observed-plugin");
        assert_eq!(stats[0].1.calls, 0);

        let s = get_body(&cp, "/plugins/stats").await;
        assert!(s.contains("\"observed-plugin\""), "应含插件名：{s}");
        for key in [
            "\"calls\":0",
            "\"denied\":0",
            "\"traps\":0",
            "\"fuel_exhausted\":0",
        ] {
            assert!(s.contains(key), "应含 {key}：{s}");
        }
    }

    /// P1-5 §6.1/§6.2：块启用 → 池/工厂句柄在位，stats 报 enabled=true 且
    /// 计数恒零初值，metrics 渲染完整 rillane_pool_* / rillane_tls_* 族（0 值）。
    #[tokio::test]
    async fn pool_enabled_renders_stats_and_metric_family() {
        let cfg = pool_enabled_config();
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(RuntimeConfig {
                    enable_hot_reload: false,
                    ..RuntimeConfig::default()
                })
                .build()
                .unwrap(),
        );
        let cp = ControlPlane::new(runtime, None, true);

        let s = get_body(&cp, "/egress/pool/stats").await;
        assert!(s.contains("\"enabled\":true"), "启用态：{s}");
        assert!(s.contains("\"tls_resumption\":true"), "缺省恢复开启：{s}");
        assert!(
            s.contains("\"hit\":0")
                && s.contains("\"miss\":0")
                && s.contains("\"stale_redial\":0")
                && s.contains("\"dials_ok\":0")
                && s.contains("\"dials_err\":0"),
            "启动即查无流量 → 计数恒零：{s}"
        );
        assert!(s.contains("\"keys\":[]"), "未预热未借出 → 空 keys：{s}");

        let m = get_body(&cp, "/metrics").await;
        let zero_series = [
            "rillane_pool_acquires_total{result=\"hit\"}",
            "rillane_pool_acquires_total{result=\"miss\"}",
            "rillane_pool_acquires_total{result=\"stale_redial\"}",
            "rillane_pool_dials_total{origin=\"foreground\",result=\"ok\"}",
            "rillane_pool_dials_total{origin=\"warm\",result=\"error\"}",
            "rillane_pool_dials_total{origin=\"refill\",result=\"ok\"}",
            "rillane_pool_evicted_total{reason=\"idle_timeout\"}",
            "rillane_pool_evicted_total{reason=\"capacity\"}",
            "rillane_pool_evicted_total{reason=\"shutdown\"}",
        ];
        for series in zero_series {
            assert_eq!(
                metric_value(&m, series),
                Some(0.0),
                "系列 {series} 应渲染且初值 0"
            );
        }
        for gauge in [
            "rillane_pool_idle_connections",
            "rillane_pool_leased_connections",
        ] {
            assert_eq!(metric_value(&m, gauge), Some(0.0), "{gauge} 初值 0");
        }
        assert!(
            metric_value(&m, "rillane_pool_reuse_ratio").is_some(),
            "reuse_ratio gauge 应渲染"
        );
        for kind in ["full", "resumed", "full_hrr"] {
            assert_eq!(
                metric_value(
                    &m,
                    &format!("rillane_tls_handshakes_total{{type=\"{kind}\"}}")
                ),
                Some(0.0),
                "rillane_tls_handshakes_total{{type={kind}}} 应渲染且初值 0"
            );
        }
    }

    /// 测试 2：真 socket ASSOCIATE + 环回 echo 往返后 packets/bytes 序列非零
    #[tokio::test]
    async fn metrics_udp_counters_after_traffic() {
        let cfg = s4_udp_config();
        let socks_bind = match &cfg.ingress[0].spec {
            IngressConfig::Socks5 { bind, .. } => bind.clone(),
            _ => unreachable!(),
        };
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(RuntimeConfig {
                    enable_hot_reload: false,
                    ..RuntimeConfig::default()
                })
                .build()
                .unwrap(),
        );
        let tasks = runtime.start().await.unwrap();
        let cp = ControlPlane::new(runtime, None, true);
        let echo_addr = spawn_echo_server().await;

        // 客户端 UDP socket（数据报源 = 粘滞键 client；strict 源校验同为 127.0.0.1）
        let (control, relay_port) = associate_relay_port(&socks_bind).await;
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut frame = vec![0, 0, 0, 1]; // RSV(2) FRAG ATYP=IPv4
        match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => frame.extend_from_slice(&v4.octets()),
            std::net::IpAddr::V6(v6) => {
                frame[3] = 4;
                frame.extend_from_slice(&v6.octets());
            }
        }
        frame.extend_from_slice(&echo_addr.port().to_be_bytes());
        frame.extend_from_slice(b"rillane-udp-metrics");
        client_udp
            .send_to(&frame, ("127.0.0.1", relay_port))
            .await
            .unwrap();

        // 下行：SOCKS5 帧封装的回声应答（收到即上行/下行两计数均已发生）
        let mut rxbuf = [0u8; 2048];
        let (n, _) = timeout(Duration::from_secs(2), client_udp.recv_from(&mut rxbuf))
            .await
            .expect("应在超时内收到下行回声")
            .unwrap();
        let (parsed, hlen) = rillane_core::udp::parse_udp_header(&rxbuf[..n]).unwrap();
        assert_eq!(parsed.host, echo_addr.ip().to_string());
        assert_eq!(parsed.port, echo_addr.port());
        assert_eq!(&rxbuf[hlen..n], b"rillane-udp-metrics");

        let s = get_body(&cp, "/metrics").await;
        assert!(
            metric_value(&s, "rillane_udp_relay_packets_total{direction=\"up\"}").unwrap() >= 1.0,
            "上行包计数应 ≥1"
        );
        assert!(
            metric_value(&s, "rillane_udp_relay_packets_total{direction=\"down\"}").unwrap() >= 1.0,
            "下行包计数应 ≥1"
        );
        assert!(
            metric_value(&s, "rillane_udp_relay_bytes_total{direction=\"up\"}").unwrap() > 0.0,
            "上行字节应非零"
        );
        assert!(
            metric_value(&s, "rillane_udp_relay_bytes_total{direction=\"down\"}").unwrap() > 0.0,
            "下行字节应非零"
        );

        drop(control);
        for t in tasks {
            t.abort();
        }
    }

    /// 测试 3：/udp/stats 结构对齐 §9-1——mesh 两态（未启用 null / 启用对象）+
    /// mesh_client 条件键 + table/ingress 恒在
    #[tokio::test]
    async fn udp_stats_endpoint_shape() {
        // —— 态一：mesh 面未启用（sample 配置 udp 关）→ 全零恒在、mesh null、
        //    mesh_client 键省略 ——
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);
        let s = get_body(&cp, "/udp/stats").await;
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        let table = v.get("table").expect("table 段恒在").as_object().unwrap();
        for f in [
            "sessions_active",
            "sessions_total",
            "mappings_active",
            "reroutes",
            "bytes_up",
            "bytes_down",
        ] {
            assert_eq!(table[f], serde_json::json!(0), "table.{f} 应为 0");
        }
        let dropped = table.get("dropped").unwrap().as_object().unwrap();
        assert_eq!(dropped.len(), 6, "dropped 六 reason 键齐全");
        for val in dropped.values() {
            assert_eq!(*val, serde_json::json!(0));
        }
        let expired = table.get("expired").unwrap().as_object().unwrap();
        assert_eq!(expired.len(), 3, "expired 三 reason 键齐全");
        assert!(table
            .get("sessions")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());

        let ingress = v
            .get("ingress")
            .expect("ingress 段恒在")
            .as_object()
            .unwrap();
        for f in [
            "associates_active",
            "associates_total",
            "associate_rejected",
            "associate_errors",
            "uplink_packets",
            "downlink_packets",
            "frag_dropped",
            "source_dropped",
            "malformed_dropped",
        ] {
            assert_eq!(ingress[f], serde_json::json!(0), "ingress.{f} 应为 0");
        }

        assert!(
            v.get("mesh").is_some_and(|m| m.is_null()),
            "面未启用 mesh 应为 null（与零流量对象两态可区分）"
        );
        assert!(
            v.get("mesh_client").is_none(),
            "未装配 client 桥应省略 mesh_client 键"
        );

        // —— 态二：relay 角色 + chain+udp + start() → mesh 对象（零流量全零）、
        //    mesh_client 出现（chain+udp 桥 build 期装配）——
        // 与 mtls env 快照测串行（MESH_MTLS_ENV_TEST_LOCK 注记：进程级 env 泄漏）
        let _env_serial = MESH_MTLS_ENV_TEST_LOCK.lock().await;
        let runtime2 = Arc::new(
            RuntimeBuilder::new(s4_udp_config())
                .with_runtime_config(RuntimeConfig {
                    enable_mesh: true,
                    enable_chain: true,
                    enable_hot_reload: false,
                    mesh_config: Some(MeshConfig {
                        node_id: "s4-relay".into(),
                        role: "relay".into(),
                        listen_address: "127.0.0.1:0".parse().unwrap(),
                        allow_plaintext_data_plane: true,
                        udp_allow_plaintext_data_plane: true,
                        // 同 build_runtime 注记：钉死 None 防并发 env 吸入（ENOENT 晚炸）
                        data_plane_tls: None,
                        ..MeshConfig::default()
                    }),
                    ..RuntimeConfig::default()
                })
                .build()
                .unwrap(),
        );
        let tasks = runtime2.start().await.unwrap();
        let cp2 = ControlPlane::new(runtime2, None, true);
        let s2 = get_body(&cp2, "/udp/stats").await;
        let v2: serde_json::Value = serde_json::from_str(&s2).unwrap();

        let mesh = v2
            .get("mesh")
            .and_then(|m| m.as_object())
            .expect("面启用后 mesh 应为对象");
        for f in [
            "forwarded_up",
            "forwarded_down",
            "malformed",
            "replay_dropped",
            "unknown_flow",
            "evicted",
            "flows_active",
        ] {
            assert_eq!(mesh[f], serde_json::json!(0), "mesh.{f} 零流量应为 0");
        }
        let mc = v2
            .get("mesh_client")
            .and_then(|m| m.as_object())
            .expect("chain+udp 桥装配应出现 mesh_client");
        assert_eq!(mc.get("dropped"), Some(&serde_json::json!(0)));
        assert_eq!(
            mc.get("replay_dropped"),
            Some(&serde_json::json!(0)),
            "mesh_client.replay_dropped 零流量应为 0"
        );

        for t in tasks {
            t.abort();
        }
    }

    // ---------- network-route.md §7.1：route 三端点 ----------
    // （Linux 门控——路由面属 TUN 数据面，platform-packaging.md）

    /// network-route.md §7.1 端点测试基座：Tun 模式 runtime（build 不 start——
    /// 设备未创建、接口名由测试注入，设备 I/O 面零触达）
    #[cfg(target_os = "linux")]
    async fn build_tun_runtime() -> Arc<Runtime> {
        let rc = RuntimeConfig {
            enable_network_virtualization: true,
            network_config: Some(rillane_platform::network::NetworkConfig {
                mode: rillane_runtime::NetworkMode::Tun,
                tun: Some(rillane_platform::network::TunConfig {
                    name: Some("rillaneR2ep".into()),
                    ipv4_addr: Some("10.198.0.1".parse().unwrap()),
                    ipv4_netmask: Some("255.255.255.0".parse().unwrap()),
                    mtu: 1400,
                    ..Default::default()
                }),
                routing: Some(rillane_platform::network::RoutingConfig {
                    enabled: true,
                    rules: vec![rillane_platform::network::RouteRule::new(
                        "include[0]".into(),
                        rillane_platform::network::RouteDestination::ipv4(
                            "203.0.113.0".parse().unwrap(),
                            24,
                        )
                        .unwrap(),
                    )],
                    ..Default::default()
                }),
                filtering: None,
                dns: None,
            }),
            ..RuntimeConfig::default()
        };
        Arc::new(
            RuntimeBuilder::new(s4_udp_config())
                .with_runtime_config(rc)
                .build()
                .unwrap(),
        )
    }

    /// POST JSON → Response（route 端点测试用）
    async fn post_json(cp: &ControlPlane, path: &str, body: &str) -> Response<RespBody> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(CONTENT_TYPE, "application/json")
            .body(RespBody::from(body.to_string()))
            .unwrap();
        cp.handle(req).await
    }

    /// 2xx 响应体 → JSON（调用方先断言状态码）
    // 仅 route 端点测试消费（Linux 门控面，platform-packaging.md）
    #[cfg(target_os = "linux")]
    async fn resp_json(resp: Response<RespBody>) -> serde_json::Value {
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// step JSON → argv 字符串表
    #[cfg(target_os = "linux")]
    fn step_argv(step: &serde_json::Value) -> Vec<String> {
        step["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// §6 E10：无 TUN 的 runtime 上 apply/clear/status 三端点均 503
    ///（TunIngress 未装配——/nodes 的 SERVICE_UNAVAILABLE 先例口径）
    #[tokio::test]
    async fn route_endpoints_503_without_tun() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let resp = post_json(&cp, "/network/route/apply", r#"{"dry_run":false}"#).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let resp = post_json(&cp, "/network/route/clear", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/network/route/status")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            s.contains("TUN 未启用"),
            "status 503 应携 E10 口径文本：{s}"
        );
    }

    /// §3/§7.1 端点形状：dry-run planned（argv 精确 + at）与 executed/rolled_back
    /// 两态 + E7 失败形（真 ip 对不存在设备非零退出——无特权可跑、零系统
    /// 变更）+ clear E8 空表 + status 对账（mode/device/mtu/up/applied）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn route_endpoints_shapes_on_unstarted_tun() {
        let runtime = build_tun_runtime().await;
        {
            let tun = runtime
                .get_tun_ingress()
                .expect("Tun 模式应装配 TunIngress");
            let rm = tun.route_manager();
            rm.lock().await.set_interface_name("rillaneR2ep".into());
        }
        let cp = ControlPlane::new(runtime, None, true);

        // dry-run：planned = addr + include 路由、executed/rolled_back 空
        let resp = post_json(&cp, "/network/route/apply", r#"{"dry_run":true}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = resp_json(resp).await;
        let planned = v["planned"].as_array().expect("planned 数组");
        assert_eq!(planned.len(), 2, "addr + 1 条 include：{v}");
        assert_eq!(
            step_argv(&planned[0]),
            [
                "ip",
                "addr",
                "replace",
                "10.198.0.1/24",
                "dev",
                "rillaneR2ep"
            ]
        );
        assert_eq!(
            step_argv(&planned[1]),
            [
                "ip",
                "route",
                "replace",
                "203.0.113.0/24",
                "dev",
                "rillaneR2ep",
                "metric",
                "0"
            ]
        );
        assert!(planned[0]["at"].as_u64().is_some(), "step 携 at");
        assert!(v["executed"].as_array().unwrap().is_empty());
        assert!(v["rolled_back"].as_array().unwrap().is_empty());

        // 真执行：设备不存在 → 首 ip 非零退出 → E7 形状 500 {error, rolled_back}
        let resp = post_json(&cp, "/network/route/apply", r#"{"dry_run":false}"#).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = resp_json(resp).await;
        assert!(
            v["error"].as_str().unwrap_or_default().contains("E7"),
            "error 应含 E7 口径：{v}"
        );
        assert!(v["rolled_back"].as_array().unwrap().is_empty());

        // clear：账本空 → Ok 空表（E8 幂等）
        let resp = post_json(&cp, "/network/route/clear", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = resp_json(resp).await;
        assert!(v["undone"].as_array().unwrap().is_empty());

        // status：mode/device/mtu/up + applied 空表（未 start → up=false）
        let s = get_body(&cp, "/network/route/status").await;
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["mode"], serde_json::json!("tun"));
        assert_eq!(v["device"], serde_json::json!("rillaneR2ep"));
        assert_eq!(v["mtu"], serde_json::json!(1400));
        assert_eq!(v["up"], serde_json::json!(false));
        assert!(v["applied"].as_array().unwrap().is_empty());
    }

    /// RIL-056：兼容 `/connections` 视图——真实字段映射与可用性说明。
    /// 缺失时间/域名/规则/链路不伪造（null/空）；id 是聚合键；顶层
    /// `rillane` 块声明聚合语义；totals 是表内求和；字节计数如实映射。
    #[test]
    fn clash_connections_view_maps_fields_honestly() {
        let flows = vec![
            FlowStatItem {
                ingress: "mixed-in".to_string(),
                egress: "proxy-a".to_string(),
                flows: 2,
                upstream: 100,
                downstream: 900,
            },
            FlowStatItem {
                ingress: "tun-in".to_string(),
                egress: "DIRECT".to_string(),
                flows: 1,
                upstream: 10,
                downstream: 0,
            },
        ];
        let view = clash_connections_view(flows);

        // totals 是表内可见项求和（不虚报全局数）
        assert_eq!(view["uploadTotal"], serde_json::json!(110));
        assert_eq!(view["downloadTotal"], serde_json::json!(900));

        // 视图语义显式声明：聚合面、聚合键口径、缺失即 null 的说明
        assert_eq!(view["rillane"]["view"], serde_json::json!("aggregate"));
        assert!(view["rillane"]["id_semantics"]
            .as_str()
            .unwrap()
            .contains("not a per-flow id"));
        assert!(view["rillane"]["note"].as_str().unwrap().contains("null"));

        let items = view["connections"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        let first = &items[0];
        // 真实字段：聚合键 id + 字节计数如实映射
        assert_eq!(first["id"], serde_json::json!("mixed-in-proxy-a"));
        assert_eq!(first["upload"], serde_json::json!(100));
        assert_eq!(first["download"], serde_json::json!(900));
        assert_eq!(first["upload_total"], serde_json::json!(100));
        assert_eq!(first["download_total"], serde_json::json!(900));
        // 缺失事实不伪造：时间/域名/规则/链路 = null/空
        assert!(first["start"].is_null(), "缺失时间不伪造为 0");
        assert!(first["metadata"]["host"].is_null(), "缺失域名不伪造为空串");
        assert!(first["rule"].is_null(), "聚合统计无规则事实");
        assert!(first["rule_payload"].is_null());
        assert!(
            first["chains"].as_array().unwrap().is_empty(),
            "聚合统计无链路事实，不拿出口标签冒充链路"
        );
        // 旧聚合 API 语义独立：ingress/egress 不再被塞进 rule/chains
        let second = &items[1];
        assert_eq!(second["id"], serde_json::json!("tun-in-DIRECT"));
        assert_eq!(second["download"], serde_json::json!(0), "零值与缺失可辨");
    }

    /// 非法参数请求（400/404 等）：与 get_body 同构但不断言 200
    async fn get_status_and_body(cp: &ControlPlane, path: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// RIL-060：/trace/flows 空态诚实——schema_version=1 + total_matching=0
    /// + 空 items（数据路径未接线 → 无流可报，不造数）
    #[tokio::test]
    async fn trace_flows_empty_state_is_versioned_and_honest() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let body = get_body(&cp, "/trace/flows?limit=10").await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["schema_version"], serde_json::json!(1));
        assert_eq!(v["total_matching"], serde_json::json!(0));
        assert_eq!(v["offset"], serde_json::json!(0));
        assert_eq!(v["limit"], serde_json::json!(10));
        assert!(v["items"].as_array().unwrap().is_empty());
    }

    /// RIL-060：/trace/flow 未知 ID = 200 + found:false + 稳定缺席码
    /// query.flow.unknown + 采集计数快照（显式缺席不是 404）
    #[tokio::test]
    async fn trace_flow_unknown_id_answers_explicit_absence() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let body = get_body(&cp, "/trace/flow?id=never-seen").await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["schema_version"], serde_json::json!(1));
        assert_eq!(v["found"], serde_json::json!(false));
        assert!(v["trace"].is_null());
        assert_eq!(
            v["absence"]["code"],
            serde_json::json!("query.flow.unknown")
        );
        assert_eq!(
            v["absence"]["note"],
            serde_json::json!("no record is not evidence of no traffic")
        );
        // 采集计数可见（缺席可对账）
        assert!(v["absence"]["collector"]["traces_admitted"]
            .as_u64()
            .is_some());
    }

    /// RIL-060：/trace/events 未知 ID = 404 + 稳定码信封（与 flow 的
    /// 200 found:false 有意不同——增量读取没有"部分答案"可给）
    #[tokio::test]
    async fn trace_events_unknown_id_is_404_with_stable_code() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let (status, body) = get_status_and_body(&cp, "/trace/events?id=never-seen").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["schema_version"], serde_json::json!(1));
        assert_eq!(v["error"]["code"], serde_json::json!("query.flow.unknown"));
    }

    /// RIL-062：/trace/flow.svg 参数面与 JSON 面同门——缺 id /
    /// 非法 id 逐项稳定码（400），未知 ID 缺席 = 404 信封不拿图糊弄
    #[tokio::test]
    async fn trace_flow_svg_param_and_absence_are_explicit() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        // 缺 id
        let (status, body) = get_status_and_body(&cp, "/trace/flow.svg").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.param.invalid"));

        // 空白 id → 内核 trace.flow_id.invalid
        let (status, body) = get_status_and_body(&cp, "/trace/flow.svg?id=").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["error"]["code"],
            serde_json::json!("trace.flow_id.invalid")
        );

        // 未知 ID = 404 显式缺席（SVG 端点不答 200 空图）
        let (status, body) = get_status_and_body(&cp, "/trace/flow.svg?id=never-seen").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.flow.unknown"));
        assert_eq!(
            v["error"]["context"],
            serde_json::json!("no record is not evidence of no traffic")
        );
    }

    /// 指标标签卫生检查（RIL-064）：标签键须在登记名单内（新增键必须
    /// 改本名单过审）；值不得是 ip:port / 裸地址形态（逐连接高基数身份
    /// 不得进标签）。返回首个违规（None = 干净）。
    fn metrics_label_hygiene_violation(body: &str) -> Option<String> {
        const ALLOWED: [&str; 14] = [
            "direction",
            "egress",
            "from",
            "ingress",
            "mode",
            "name",
            "origin",
            "quantile",
            "reason",
            "result",
            "source",
            "subscription",
            "to",
            "type",
        ];
        for line in body.lines() {
            let Some((metric, rest)) = line.split_once('{') else {
                continue;
            };
            let labels = rest.split('}').next().unwrap_or("");
            for pair in labels.split(',') {
                let Some((key, value)) = pair.split_once('=') else {
                    return Some(format!("标签形态非法: {line}"));
                };
                let key = key.trim();
                if !ALLOWED.contains(&key) {
                    return Some(format!("未登记标签键 {key}（{metric}）"));
                }
                let value = value.trim().trim_matches('"');
                if value.parse::<std::net::SocketAddr>().is_ok()
                    || value.parse::<std::net::IpAddr>().is_ok()
                {
                    return Some(format!("标签值携带地址形态（高基数身份）: {key}={value}"));
                }
            }
        }
        None
    }

    /// RIL-064：指标标签卫生 + 清除端点走鉴权门。admin token 绝不出现
    /// 在指标输出；标签键全集有界登记、值无地址形态（解析器自检：带
    /// 地址标签的伪造行必须被抓——扫描面不是摆设）；DELETE 历史是
    /// mutating：无 token 401、带 token 放行。
    #[tokio::test]
    async fn metrics_labels_are_bounded_and_purge_endpoint_requires_auth() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, Some("sekrit-token-1".into()), true);

        let body = get_body(&cp, "/metrics").await;
        assert!(
            !body.contains("sekrit-token-1"),
            "admin token 绝不进指标输出"
        );
        assert_eq!(
            metrics_label_hygiene_violation(&body),
            None,
            "指标标签卫生不过关"
        );
        let bogus = "rillane_test_metric{remote=\"10.0.0.1:443\"} 1\n";
        assert!(
            metrics_label_hygiene_violation(bogus).is_some(),
            "带地址标签的行必须被抓（解析器自检）"
        );

        // 清除端点是 mutating：无 token 401
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/trace/history")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 带 token 放行（空采集器答 0）
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/trace/history")
            .header("x-admin-token", "sekrit-token-1")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// RIL-064：DELETE /trace/history 显式清历史——空采集器答 0（不造数），
    /// 信封版本化
    #[tokio::test]
    async fn trace_history_delete_answers_versioned_purge_count() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/trace/history")
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["schema_version"], serde_json::json!(1));
        assert_eq!(v["purged"], serde_json::json!(0), "空采集器不造清除数");
    }

    /// RIL-065：POST /explain 纯推演——生产求值器 + 冻结快照，答复带
    /// 输入摘要（重放锚）与确定性级别；不可信回显字段（host 控制字符）
    /// 在入口消毒——解释面不含注入面
    #[tokio::test]
    async fn explain_answers_frozen_snapshot_explanation_with_sanitized_echo() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let body = serde_json::json!({
            "generation_id": "gen-1",
            "host": "ex\u{1}ample.com\u{200b}",
            "port": 443,
            "proto": "tcp",
            "ingress": "mixed-in",
        })
        .to_string();
        let (status, text) = post_probe(&cp, "/explain", &body).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema_version"], serde_json::json!(1));
        let explanation = &v["explanation"];
        // 输入摘要 = 64 hex 重放锚
        let digest = explanation["input_digest"].as_str().expect("digest");
        assert_eq!(digest.len(), 64, "SHA-256 摘要 {digest}");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        // 确定性级别显式（default 面 = Definitive——确定性策略 + 证据齐）
        assert!(explanation["certainty"].is_string());
        // 回显面消毒：host 控制字符/零宽不可见于解释
        let echoed_host = explanation["target"]["host"].as_str().expect("host");
        assert!(!echoed_host.contains('\u{1}'));
        assert!(!echoed_host.contains('\u{200b}'));
    }

    /// RIL-065：proto 非法 → 400 + `explain.input.invalid`（推演面不猜）
    #[tokio::test]
    async fn explain_rejects_invalid_proto_with_stable_code() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let body = serde_json::json!({
            "generation_id": "gen-1",
            "host": "example.com",
            "port": 443,
            "proto": "smtp",
        })
        .to_string();
        let (status, text) = post_probe(&cp, "/explain", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["error"]["code"],
            serde_json::json!("explain.input.invalid")
        );
        assert!(v["error"]["context"]
            .as_str()
            .unwrap_or("")
            .contains("proto"));
    }

    /// RIL-065：POST 属 mutating——配置 admin_token 后推演同样走鉴权门
    /// （模型侧无法无凭据触发推演）
    #[tokio::test]
    async fn explain_requires_admin_token_when_configured() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, Some("sekrit-token-1".to_string()), true);

        let body = serde_json::json!({
            "generation_id": "gen-1",
            "host": "example.com",
            "port": 443,
            "proto": "tcp",
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/explain")
            .body(RespBody::new(Bytes::from(body)))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/explain")
            .header("x-admin-token", "sekrit-token-1")
            .body(RespBody::new(Bytes::from(
                serde_json::json!({
                    "generation_id": "gen-1",
                    "host": "example.com",
                    "port": 443,
                    "proto": "tcp",
                })
                .to_string(),
            )))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// RIL-063：trace 读面携带详细身份（域名/进程/地址）——配置
    /// admin_token 后与 mutating 同门（无凭据 401；带凭据照常应答；
    /// 未配置 token 的本机部署照常开放）
    #[tokio::test]
    async fn trace_reads_require_admin_token_when_configured() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, Some("sekrit-token-2".to_string()), true);

        let make = |uri: &str, token: Option<&str>| {
            let mut b = Request::builder().method(Method::GET).uri(uri.to_string());
            if let Some(t) = token {
                b = b.header("x-admin-token", t);
            }
            b.body(RespBody::new(Bytes::new())).unwrap()
        };
        for uri in ["/trace/flows", "/trace/flow?id=f-1", "/trace/events?id=f-1"] {
            let resp = cp.handle(make(uri, None)).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "uri {uri}");
            let resp = cp.handle(make(uri, Some("sekrit-token-2"))).await;
            assert_ne!(resp.status(), StatusCode::UNAUTHORIZED, "uri {uri}");
        }
        // SVG 导出面同门
        let resp = cp.handle(make("/trace/flow.svg?id=f-1", None)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 未配置 token：读面照常开放（本机部署）
        let runtime2 = build_runtime(false, false).await;
        let cp2 = ControlPlane::new(runtime2, None, true);
        let resp = cp2.handle(make("/trace/flows", None)).await;
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// RIL-060：参数非法逐项显式拒绝——limit=0（内核 query.page.invalid）、
    /// 非法 origin/state/缺 id（控制面 query.param.invalid）
    #[tokio::test]
    async fn trace_param_validation_is_explicit_per_param() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let (status, body) = get_status_and_body(&cp, "/trace/flows?limit=0").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.page.invalid"));

        let (status, body) = get_status_and_body(&cp, "/trace/flows?origin=tcp").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.param.invalid"));

        let (status, body) = get_status_and_body(&cp, "/trace/flows?state=open").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.param.invalid"));

        let (status, body) = get_status_and_body(&cp, "/trace/flow").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.param.invalid"));

        // limit=0 校验发生在 id 解析之后——带 id 才能触达内核分页校验
        let (status, body) = get_status_and_body(&cp, "/trace/events?id=x&limit=0").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("query.page.invalid"));
    }

    // -------------------------------------------------------------------
    // 主动探测端点（RIL-061）
    // -------------------------------------------------------------------

    use rillane_core::{
        ProbeExecError, ProbeExecutor, ProbeLimits, ProbeTarget, TargetScope,
        CODE_PROBE_EXEC_FAILED, CODE_PROBE_JOB_UNKNOWN,
    };

    /// 固定测量桩：UDP 回显 sent=3 / replies=1 / rtt=9——丢包率标记断言用
    struct FixedEcho;

    #[async_trait::async_trait]
    impl ProbeExecutor for FixedEcho {
        async fn run(
            &self,
            _target: &ProbeTarget,
            _deadline: std::time::Instant,
            _cancel: &rillane_core::probe::CancelToken,
        ) -> Result<ProbeOutcome, ProbeExecError> {
            Ok(ProbeOutcome::UdpEcho {
                sent: 3,
                replies: 1,
                payload_len: 64,
                rtt_ms: Some(9),
            })
        }
    }

    fn probe_service_for(
        addrs: &[SocketAddr],
        executor: Arc<dyn ProbeExecutor>,
    ) -> Arc<ProbeService> {
        let mut scope = TargetScope::empty();
        for a in addrs {
            scope.allow_addr(*a);
        }
        let limits = ProbeLimits {
            max_active: 2,
            ..ProbeLimits::default()
        };
        Arc::new(ProbeService::new(
            scope,
            limits,
            executor,
            Arc::new(|| 1_760_000_000_000),
        ))
    }

    async fn post_probe(cp: &ControlPlane, path: &str, body: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(RespBody::new(Bytes::from(body.to_string())))
            .unwrap();
        let resp = cp.handle(req).await;
        let status = resp.status();
        let text = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        (status, text)
    }

    async fn poll_probe_result(cp: &ControlPlane, id: u64, want_state: &str) -> serde_json::Value {
        for _ in 0..500 {
            let (_, body) = get_status_and_body(cp, &format!("/probe/result?id={id}")).await;
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            if v["job"]["state"] == serde_json::json!(want_state) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("作业 {id} 未进入 {want_state}");
    }

    /// 未装配探测服务 → 四端点全部 503 + `probe.disabled`（/nodes 先例
    /// 分层口径：端点形状不因能力缺席消失）
    #[tokio::test]
    async fn probe_endpoints_503_without_service() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true); // 无 with_probe_service

        for (method, path) in [
            (Method::GET, "/probe"),
            (Method::GET, "/probe/result?id=0"),
            (Method::POST, "/probe"),
            (Method::POST, "/probe/cancel?id=0"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .body(RespBody::new(Bytes::new()))
                .unwrap();
            let resp = cp.handle(req).await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
            let body = String::from_utf8(
                resp.into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap();
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"]["code"], serde_json::json!("probe.disabled"));
        }
    }

    /// 显式发起 → 完成 → 结果可见：测量类型/RTT/失败三路分别标记；
    /// 目标必须在装配范围登记（真实回环建连）。
    #[tokio::test]
    async fn probe_submit_connect_completes_with_explicit_measurement() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let runtime = build_runtime(false, false).await;
        let cp =
            ControlPlane::new(runtime, None, true).with_probe_service(Some(probe_service_for(
                &[addr],
                Arc::new(rillane_platform::probe_exec::LocalProbeExecutor::new()),
            )));

        let body = format!(r#"{{"kind":"connect","addr":"{addr}"}}"#);
        let (status, text) = post_probe(&cp, "/probe", &body).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["job_id"], serde_json::json!(0));

        let v = poll_probe_result(&cp, 0, "completed").await;
        assert_eq!(v["found"], serde_json::json!(true));
        assert_eq!(
            v["job"]["target"],
            serde_json::json!(format!("connect:{addr}"))
        );
        assert_eq!(
            v["job"]["outcome"]["measurement"],
            serde_json::json!("connect")
        );
        assert!(
            v["job"]["outcome"]["rtt_ms"].is_u64(),
            "回环建连必有实测 RTT"
        );
        assert_eq!(v["job"]["failure"], serde_json::Value::Null);
    }

    /// 范围外目标显式拒绝（400 + 稳定码）且不产生作业；未知作业 ID
    /// 结果/取消均 404 显式缺席（`probe.job.unknown`）。
    #[tokio::test]
    async fn probe_out_of_scope_and_unknown_id_are_explicit() {
        let runtime = build_runtime(false, false).await;
        // 范围登记 127.0.0.1:9——提交目标不在其中
        let registered: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cp = ControlPlane::new(runtime, None, true)
            .with_probe_service(Some(probe_service_for(&[registered], Arc::new(FixedEcho))));

        let (status, text) = post_probe(
            &cp,
            "/probe",
            r#"{"kind":"connect","addr":"192.0.2.1:443"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["error"]["code"],
            serde_json::json!("probe.target.out_of_scope")
        );

        // 拒绝不产生作业
        let (_, body) = get_status_and_body(&cp, "/probe").await;
        let list: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["jobs"].as_array().map(Vec::len), Some(0));

        // 未知 ID：结果 = 404 显式缺席信封；取消 = 404 稳定码
        let (status, body) = get_status_and_body(&cp, "/probe/result?id=999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["found"], serde_json::json!(false));
        assert_eq!(
            v["absence"]["code"],
            serde_json::json!(CODE_PROBE_JOB_UNKNOWN)
        );

        let (status, text) = post_probe(&cp, "/probe/cancel?id=999", "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["error"]["code"],
            serde_json::json!(CODE_PROBE_JOB_UNKNOWN)
        );
    }

    /// 非法提交体：坏 JSON / 未知 kind / addr 非法 → 400（不入队）
    #[tokio::test]
    async fn probe_malformed_submit_is_400() {
        let runtime = build_runtime(false, false).await;
        let registered: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cp = ControlPlane::new(runtime, None, true)
            .with_probe_service(Some(probe_service_for(&[registered], Arc::new(FixedEcho))));

        let cases = [
            ("{not json", "invalid json"),
            (
                r#"{"kind":"handshake","egress":"x","addr":"127.0.0.1:1"}"#,
                "unknown variant",
            ),
            (r#"{"kind":"connect"}"#, "missing field"),
            (
                r#"{"kind":"connect","addr":"no-port"}"#,
                "probe.param.invalid",
            ),
            (r#"{"kind":"dns"}"#, "missing field"),
        ];
        for (body, needle) in cases {
            let (status, text) = post_probe(&cp, "/probe", body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(text.contains(needle), "{body} → {text}");
        }
        // 参数非法不产生作业
        let (_, body) = get_status_and_body(&cp, "/probe").await;
        let list: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["jobs"].as_array().map(Vec::len), Some(0));
    }

    /// 终态作业再取消：verdict 返回状态原样（服务面契约）；列表带限额
    /// 与快照（只读面）。
    #[tokio::test]
    async fn probe_cancel_terminal_returns_state_and_list_shows_limits() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let runtime = build_runtime(false, false).await;
        let cp =
            ControlPlane::new(runtime, None, true).with_probe_service(Some(probe_service_for(
                &[addr],
                Arc::new(rillane_platform::probe_exec::LocalProbeExecutor::new()),
            )));

        let body = format!(r#"{{"kind":"connect","addr":"{addr}"}}"#);
        let (_, text) = post_probe(&cp, "/probe", &body).await;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let id = v["job_id"].as_u64().unwrap();
        poll_probe_result(&cp, id, "completed").await;

        let (status, text) = post_probe(&cp, &format!("/probe/cancel?id={id}"), "").await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["verdict"], serde_json::json!("completed"));

        let (_, body) = get_status_and_body(&cp, "/probe").await;
        let list: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["limits"]["max_active"], serde_json::json!(2));
        assert_eq!(list["jobs"].as_array().map(Vec::len), Some(1));
        assert_eq!(list["jobs"][0]["state"], serde_json::json!("completed"));
    }

    /// UDP 回显测量三路标记：丢包率由计数可算（3 发 1 回 → 0.6667）、
    /// RTT 独立、failure 独立 null——逐字段来自执行器回报。
    #[tokio::test]
    async fn probe_udp_echo_marks_loss_rtt_failure_separately() {
        let runtime = build_runtime(false, false).await;
        let registered: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let cp = ControlPlane::new(runtime, None, true)
            .with_probe_service(Some(probe_service_for(&[registered], Arc::new(FixedEcho))));

        let (status, text) = post_probe(
            &cp,
            "/probe",
            r#"{"kind":"udp_echo","addr":"127.0.0.1:53"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let id = v["job_id"].as_u64().unwrap();

        let v = poll_probe_result(&cp, id, "completed").await;
        let outcome = &v["job"]["outcome"];
        assert_eq!(outcome["measurement"], serde_json::json!("udp_echo"));
        assert_eq!(outcome["sent"], serde_json::json!(3));
        assert_eq!(outcome["replies"], serde_json::json!(1));
        assert_eq!(outcome["payload_len"], serde_json::json!(64));
        assert_eq!(outcome["loss_ratio"], serde_json::json!(0.6667));
        assert_eq!(outcome["rtt_ms"], serde_json::json!(9));
        assert_eq!(v["job"]["failure"], serde_json::Value::Null);
    }

    /// 提交/取消是 mutating 面：admin_token 在场时无凭证 401（读面
    /// /probe 与 /probe/result 不要求）。
    #[tokio::test]
    async fn probe_mutating_endpoints_require_token() {
        let runtime = build_runtime(false, false).await;
        let registered: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cp = ControlPlane::new(runtime, Some("t".into()), true)
            .with_probe_service(Some(probe_service_for(&[registered], Arc::new(FixedEcho))));

        let (status, _) =
            post_probe(&cp, "/probe", r#"{"kind":"dns","host":"example.invalid"}"#).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = post_probe(&cp, "/probe/cancel?id=0", "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = get_status_and_body(&cp, "/probe/result?id=0").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "读面无 token 可达（未知 ID 显式缺席）"
        );
    }

    /// 执行器失败归类：稳定码 + detail 进 failure 对象（state=failed、
    /// outcome null——失败无测量）。
    #[tokio::test]
    async fn probe_failure_carries_stable_code() {
        struct Failing;
        #[async_trait::async_trait]
        impl ProbeExecutor for Failing {
            async fn run(
                &self,
                _target: &ProbeTarget,
                _deadline: std::time::Instant,
                _cancel: &rillane_core::probe::CancelToken,
            ) -> Result<ProbeOutcome, ProbeExecError> {
                Err(ProbeExecError::failed("boom"))
            }
        }
        let runtime = build_runtime(false, false).await;
        let registered: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cp = ControlPlane::new(runtime, None, true)
            .with_probe_service(Some(probe_service_for(&[registered], Arc::new(Failing))));

        let (status, text) =
            post_probe(&cp, "/probe", r#"{"kind":"connect","addr":"127.0.0.1:9"}"#).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let id = v["job_id"].as_u64().unwrap();
        let v = poll_probe_result(&cp, id, "failed").await;
        assert_eq!(
            v["job"]["failure"]["code"],
            serde_json::json!(CODE_PROBE_EXEC_FAILED)
        );
        assert_eq!(v["job"]["failure"]["detail"], serde_json::json!("boom"));
        assert_eq!(v["job"]["outcome"], serde_json::Value::Null);
    }

    // —— RIL-079 配置事务面（HTTP 契约）——

    /// 装配带配置事务服务的控制面（config 与 build_runtime 同源——
    /// 同一份 config/rillane.yaml；admin_token 可选）。
    async fn cp_with_config_tx(admin_token: Option<&str>) -> ControlPlane {
        let runtime = build_runtime(false, false).await;
        let cfg_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rillane.yaml");
        let cfg = RillaneConfig::load_from_path(cfg_path).unwrap();
        ControlPlane::new(runtime, admin_token.map(str::to_string), true).with_config_service(Some(
            Arc::new(crate::config_tx::ConfigTxService::new(
                cfg,
                rillane_config::CapabilitySet::full(),
            )),
        ))
    }

    async fn post_config(
        cp: &ControlPlane,
        path: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(RespBody::new(Bytes::from(body.to_string())))
            .unwrap();
        let resp = cp.handle(req).await;
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    async fn get_config(cp: &ControlPlane, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(RespBody::new(Bytes::new()))
            .unwrap();
        let resp = cp.handle(req).await;
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    /// 未装配配置事务服务 → 全部 /config 端点 503（探测面同分层口径）。
    #[tokio::test]
    async fn config_endpoints_503_without_service() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true); // 无 with_config_service
        for (method, path) in [
            (Method::GET, "/config/state"),
            (Method::GET, "/config/receipts"),
            (Method::POST, "/config/proposals"),
            (Method::POST, "/config/preview"),
            (Method::POST, "/config/apply"),
            (Method::POST, "/config/rollback"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .body(RespBody::new(Bytes::new()))
                .unwrap();
            let resp = cp.handle(req).await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        }
    }

    /// 授权与版本检查不能被 CLI/HTTP 绕过：admin_token 配置时写端点
    /// 无 token 401（门在装配面之前）；正确 token 进门后无凭证仍被
    /// 纯面拒（403 approval.required 稳定码信封）。
    #[tokio::test]
    async fn config_write_requires_admin_token_and_approval() {
        let cp = cp_with_config_tx(Some("secret")).await;
        let body = r#"{"idempotency_key":"k","proposal_id":"p","approval_id":null,"owner":"cli"}"#;

        // 无 token → 401
        let req = Request::builder()
            .method(Method::POST)
            .uri("/config/apply")
            .body(RespBody::new(Bytes::from(body)))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 正确 token → 进门；无凭证 → 纯面 approval.required（403 信封）
        let req = Request::builder()
            .method(Method::POST)
            .uri("/config/apply")
            .header("x-admin-token", "secret")
            .body(RespBody::new(Bytes::from(body)))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!("approval.required"));
    }

    /// e2e 闭环：提案（daemon 自填 base）→ preview → 批准 → 应用 →
    /// 现役翻新 → 回执审计闭合；同键重试领回执（replayed）不再翻新。
    #[tokio::test]
    async fn config_lifecycle_end_to_end() {
        let cp = cp_with_config_tx(None).await;

        let (g1, state) = get_config(&cp, "/config/state").await;
        assert_eq!(g1, StatusCode::OK);
        let base_gen = state["live_generation"].as_str().unwrap().to_string();

        // preview（只读——不落提案）
        let (s, v) = post_config(
            &cp,
            "/config/preview",
            r#"{"patch":{"telemetry":{"log_level":"debug"}},"scope":["telemetry"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applicable"], serde_json::json!(true));

        // 提案（daemon 自填 base）
        let (s, v) = post_config(
            &cp,
            "/config/proposals",
            r#"{"owner":"cli","scope":["telemetry"],"patch":{"telemetry":{"log_level":"debug"}},"ttl_ms":60000}"#,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let proposal_id = v["id"].as_str().unwrap().to_string();
        assert_eq!(v["base_generation"], serde_json::json!(base_gen));

        // 批准
        let (s, v) = post_config(
            &cp,
            "/config/approve",
            &format!(r#"{{"proposal_id":"{proposal_id}","owner":"cli","ttl_ms":60000}}"#),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let approval_id = v["approval_id"].as_str().unwrap().to_string();

        // 应用
        let apply_body = format!(
            r#"{{"idempotency_key":"e2e-1","proposal_id":"{proposal_id}","approval_id":"{approval_id}","owner":"cli"}}"#
        );
        let (s, v) = post_config(&cp, "/config/apply", &apply_body).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["phase"], serde_json::json!("executed"));
        assert_eq!(v["receipt"]["status"], serde_json::json!("apply.applied"));

        // 现役翻新
        let (_, state) = get_config(&cp, "/config/state").await;
        let new_gen = state["live_generation"].as_str().unwrap().to_string();
        assert_ne!(new_gen, base_gen, "现役已翻新");
        assert_eq!(state["history"], serde_json::json!(1));

        // 回执审计闭合
        let (_, audit) = get_config(&cp, "/config/receipts").await;
        assert_eq!(audit["reconcile"]["agrees"], serde_json::json!(true));
        assert_eq!(audit["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(
            audit["receipts"][0]["idempotency_key"],
            serde_json::json!("e2e-1")
        );

        // 幂等重试：同键领回执，现役不动
        let (s, v) = post_config(&cp, "/config/apply", &apply_body).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["phase"], serde_json::json!("replayed"));
        let (_, state) = get_config(&cp, "/config/state").await;
        assert_eq!(state["live_generation"], serde_json::json!(new_gen));
    }

    /// 版本检查不可绕过（HTTP 面）：旧提案（base = 翻新前）在新现役上
    /// 应用 → 409 apply.base.conflict 稳定码信封——live 身份 daemon
    /// 自填，客户端无法谎报基准。
    #[tokio::test]
    async fn config_apply_base_conflict_envelope() {
        let cp = cp_with_config_tx(None).await;

        // 旧提案（trace）先登记（base = g1）
        let (_, v) = post_config(
            &cp,
            "/config/proposals",
            r#"{"owner":"cli","scope":["telemetry"],"patch":{"telemetry":{"log_level":"trace"}},"ttl_ms":60000}"#,
        )
        .await;
        let stale_id = v["id"].as_str().unwrap().to_string();
        let (_, v) = post_config(
            &cp,
            "/config/approve",
            &format!(r#"{{"proposal_id":"{stale_id}","owner":"cli","ttl_ms":60000}}"#),
        )
        .await;
        let stale_approval = v["approval_id"].as_str().unwrap().to_string();

        // 另一提案（debug）翻新内容（g1 → g2）
        let (_, v) = post_config(
            &cp,
            "/config/proposals",
            r#"{"owner":"cli","scope":["telemetry"],"patch":{"telemetry":{"log_level":"debug"}},"ttl_ms":60000}"#,
        )
        .await;
        let fresh_id = v["id"].as_str().unwrap().to_string();
        let (_, v) = post_config(
            &cp,
            "/config/approve",
            &format!(r#"{{"proposal_id":"{fresh_id}","owner":"cli","ttl_ms":60000}}"#),
        )
        .await;
        let fresh_approval = v["approval_id"].as_str().unwrap().to_string();
        let (s, v) = post_config(
            &cp,
            "/config/apply",
            &format!(
                r#"{{"idempotency_key":"k-fresh","proposal_id":"{fresh_id}","approval_id":"{fresh_approval}","owner":"cli"}}"#
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "内容翻新应成功: {v}");

        // 旧提案对翻新后现役 → 409 信封
        let (s, v) = post_config(
            &cp,
            "/config/apply",
            &format!(
                r#"{{"idempotency_key":"k-stale","proposal_id":"{stale_id}","approval_id":"{stale_approval}","owner":"cli"}}"#
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(
            v["error"]["code"],
            serde_json::json!("apply.base.conflict"),
            "旧提案必须撞版本门"
        );
    }
}
