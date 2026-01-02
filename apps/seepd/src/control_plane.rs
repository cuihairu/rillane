use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use hyper::{
    body,
    header::{AUTHORIZATION, CONTENT_TYPE},
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use serde::{Deserialize, Serialize};

use seep_mesh::{LinkState, MeshRegistry, NodeCapability, NodeRecord, NodeRole};
use seep_runtime::{ChainConstraints, ConfigMergeStats, Runtime, RuntimeEvent};
use seep_subscription::{Subscription, SubscriptionConverter, SubscriptionType};

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
}

impl ControlPlane {
    pub fn new(runtime: Arc<Runtime>, admin_token: Option<String>, metrics_enabled: bool) -> Self {
        Self {
            runtime,
            admin_token,
            metrics_enabled,
            started_at: Instant::now(),
            event_log: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            max_event_log_lines: 1000,
            telemetry_export: Arc::new(tokio::sync::RwLock::new(TelemetryExport::new(2000))),
            event_counters: Arc::new(tokio::sync::RwLock::new(CounterExport::new(2000))),
        }
    }

    pub async fn serve(
        self,
        bind: SocketAddr,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        self.spawn_event_log_task();

        let make = make_service_fn(move |_conn| {
            let state = self.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let state = state.clone();
                    async move { Ok::<_, Infallible>(state.handle(req).await) }
                }))
            }
        });

        Server::bind(&bind)
            .serve(make)
            .with_graceful_shutdown(async move {
                let _ = shutdown.await;
            })
            .await?;
        Ok(())
    }

    async fn handle(&self, req: Request<Body>) -> Response<Body> {
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
        let is_sensitive_read = matches!(path.as_str(), "/runtime/config" | "/events" | "/logs");
        if (is_mutating || is_sensitive_read)
            && self.admin_token.is_some()
            && !self.is_authorized(&req)
        {
            return text(StatusCode::UNAUTHORIZED, "unauthorized");
        }

        match (method, path.as_str()) {
            (Method::GET, "/nodes") => self.handle_nodes().await,
            (Method::GET, "/flows") => self.handle_flows().await,
            (Method::GET, "/metrics") => self.handle_metrics().await,
            (Method::GET, "/runtime/stats") => self.handle_runtime_stats().await,
            (Method::GET, "/runtime/config") => self.handle_runtime_config().await,
            (Method::GET, "/events") => self.handle_events().await,
            (Method::GET, "/logs") => self.handle_logs(req).await,
            (Method::POST, "/mesh/nodes/register") => self.handle_register_node(req).await,
            (Method::POST, "/mesh/link-states") => self.handle_update_link_state(req).await,

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

    fn is_authorized(&self, req: &Request<Body>) -> bool {
        let Some(expected) = self.admin_token.as_deref() else {
            return true;
        };

        // Accept either `Authorization: Bearer <token>` or `X-Admin-Token: <token>`.
        if let Some(v) = req
            .headers()
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
        {
            return v == expected;
        }
        if let Some(v) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            return v
                .strip_prefix("Bearer ")
                .map(|t| t == expected)
                .unwrap_or(false);
        }
        false
    }

    fn mesh(&self) -> Result<Arc<MeshRegistry>, Response<Body>> {
        self.runtime
            .get_mesh_registry()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "mesh not enabled"))
    }

    fn chain_mgr(&self) -> Result<Arc<seep_runtime::ChainManager>, Response<Body>> {
        self.runtime
            .get_chain_manager()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "chain not enabled"))
    }

    fn subscription_mgr(
        &self,
    ) -> Result<Arc<seep_subscription::SubscriptionManager>, Response<Body>> {
        self.runtime
            .get_subscription_manager()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "subscription not enabled"))
    }

    async fn handle_metrics(&self) -> Response<Body> {
        if !self.metrics_enabled {
            return text(StatusCode::NOT_FOUND, "metrics disabled");
        }

        let mut out = String::new();
        let uptime = self.started_at.elapsed().as_secs_f64();
        push_gauge(
            &mut out,
            "seep_uptime_seconds",
            "Seep daemon uptime in seconds.",
            uptime,
        );

        if let Some(mesh) = self.runtime.get_mesh_registry() {
            push_gauge(
                &mut out,
                "seep_mesh_enabled",
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
                "seep_mesh_nodes_total",
                "Total registered mesh nodes.",
                stats.total_nodes as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_nodes_online",
                "Online mesh nodes.",
                stats.online_nodes as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_nodes_online_client",
                "Online mesh client nodes.",
                online_client as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_nodes_online_relay",
                "Online mesh relay nodes.",
                online_relay as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_nodes_online_exit",
                "Online mesh exit nodes.",
                online_exit as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_nodes_online_hybrid",
                "Online mesh hybrid nodes.",
                online_hybrid as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_sessions_active",
                "Active mesh sessions.",
                stats.active_sessions as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_links_total",
                "Total mesh link-state edges.",
                links as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_average_latency_ms",
                "Average mesh link latency in milliseconds.",
                stats.average_latency_ms as f64,
            );
            push_gauge(
                &mut out,
                "seep_mesh_packet_loss_rate",
                "Average mesh link packet loss rate (0.0-1.0).",
                stats.packet_loss_rate as f64,
            );

            if !traffic.is_empty() {
                push_metric_header(
                    &mut out,
                    "seep_mesh_link_bytes_total",
                    "Total bytes transferred over a directed mesh link.",
                    "counter",
                );
                push_metric_header(
                    &mut out,
                    "seep_mesh_link_connections_total",
                    "Total connections observed on a directed mesh link.",
                    "counter",
                );
                push_metric_header(
                    &mut out,
                    "seep_mesh_link_errors_total",
                    "Total errors observed on a directed mesh link.",
                    "counter",
                );

                for t in traffic {
                    push_metric_labeled(
                        &mut out,
                        "seep_mesh_link_bytes_total",
                        &[("from", &t.from), ("to", &t.to)],
                        t.bytes_total as f64,
                    );
                    push_metric_labeled(
                        &mut out,
                        "seep_mesh_link_connections_total",
                        &[("from", &t.from), ("to", &t.to)],
                        t.connections_total as f64,
                    );
                    push_metric_labeled(
                        &mut out,
                        "seep_mesh_link_errors_total",
                        &[("from", &t.from), ("to", &t.to)],
                        t.errors_total as f64,
                    );
                }
            }
        } else {
            push_gauge(
                &mut out,
                "seep_mesh_enabled",
                "Whether mesh is enabled (1/0).",
                0.0,
            );
        }

        if let Some(chain_mgr) = self.runtime.get_chain_manager() {
            push_gauge(
                &mut out,
                "seep_chain_enabled",
                "Whether chain is enabled (1/0).",
                1.0,
            );

            let stats = chain_mgr.get_stats().await;
            push_metric_header(
                &mut out,
                "seep_chain_total_created",
                "Total chains created.",
                "counter",
            );
            out.push_str(&format!("seep_chain_total_created {}\n", stats.total_chains_created));
            push_gauge(
                &mut out,
                "seep_chain_active",
                "Active chains.",
                stats.active_chains as f64,
            );
            push_metric_header(
                &mut out,
                "seep_chain_failover_total",
                "Chain failover count.",
                "counter",
            );
            out.push_str(&format!(
                "seep_chain_failover_total {}\n",
                stats.failover_count
            ));
            push_metric_header(
                &mut out,
                "seep_chain_failed_total",
                "Failed chains count.",
                "counter",
            );
            out.push_str(&format!(
                "seep_chain_failed_total {}\n",
                stats.failed_chains
            ));
            push_gauge(
                &mut out,
                "seep_chain_average_hop_count",
                "Average chain hop count.",
                stats.average_hop_count as f64,
            );
            push_gauge(
                &mut out,
                "seep_chain_average_lifetime_seconds",
                "Average chain lifetime in seconds.",
                stats.average_chain_lifetime_seconds as f64,
            );
            push_gauge(
                &mut out,
                "seep_chain_last_failover_epoch_seconds",
                "Unix epoch seconds of the most recent chain failover (0 if never).",
                stats.last_failover_epoch_seconds.unwrap_or(0) as f64,
            );
        } else {
            push_gauge(
                &mut out,
                "seep_chain_enabled",
                "Whether chain is enabled (1/0).",
                0.0,
            );
        }

        let flow_stats = self.runtime.get_flow_stats();
        push_gauge(
            &mut out,
            "seep_flow_pairs",
            "Number of (ingress, egress) flow stat pairs.",
            flow_stats.len() as f64,
        );

        push_metric_header(
            &mut out,
            "seep_flow_connections_total",
            "Total flows forwarded.",
            "counter",
        );

        push_metric_header(
            &mut out,
            "seep_flow_upstream_bytes_total",
            "Total upstream bytes forwarded.",
            "counter",
        );

        push_metric_header(
            &mut out,
            "seep_flow_downstream_bytes_total",
            "Total downstream bytes forwarded.",
            "counter",
        );

        for item in flow_stats {
            push_metric_labeled(
                &mut out,
                "seep_flow_connections_total",
                &[("ingress", &item.ingress), ("egress", &item.egress)],
                item.flows as f64,
            );
            push_metric_labeled(
                &mut out,
                "seep_flow_upstream_bytes_total",
                &[("ingress", &item.ingress), ("egress", &item.egress)],
                item.upstream as f64,
            );
            push_metric_labeled(
                &mut out,
                "seep_flow_downstream_bytes_total",
                &[("ingress", &item.ingress), ("egress", &item.egress)],
                item.downstream as f64,
            );
        }

        if let Some(subs) = self.runtime.get_subscription_manager() {
            push_gauge(
                &mut out,
                "seep_subscriptions_enabled",
                "Whether subscription manager is enabled (1/0).",
                1.0,
            );
            let count = subs.list_subscriptions().len();
            push_gauge(
                &mut out,
                "seep_subscriptions_total",
                "Total subscriptions.",
                count as f64,
            );
        } else {
            push_gauge(
                &mut out,
                "seep_subscriptions_enabled",
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
            .body(Body::from(out))
            .unwrap_or_else(|_| Response::new(Body::from("internal error")))
    }

    async fn handle_nodes(&self) -> Response<Body> {
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

    async fn handle_flows(&self) -> Response<Body> {
        let stats = self.runtime.get_flow_stats();
        json(StatusCode::OK, &stats)
    }

    async fn handle_runtime_stats(&self) -> Response<Body> {
        let stats = self.runtime.get_stats();
        let dto = RuntimeStatsDto::from(stats);
        json(StatusCode::OK, &dto)
    }

    async fn handle_runtime_config(&self) -> Response<Body> {
        let cfg = self.runtime.get_config();
        json(StatusCode::OK, &cfg)
    }

    async fn handle_events(&self) -> Response<Body> {
        let guard = self.event_log.lock().await;
        let mut out = String::new();
        for line in guard.iter() {
            out.push_str(line);
        }
        text(StatusCode::OK, &out)
    }

    async fn handle_logs(&self, req: Request<Body>) -> Response<Body> {
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

        match seep_telemetry::logs_text(lines) {
            Some(t) if !t.is_empty() => text(StatusCode::OK, &t),
            Some(_) => text(StatusCode::OK, ""),
            None => text(StatusCode::NOT_FOUND, "log capture disabled"),
        }
    }

    async fn handle_register_node(&self, req: Request<Body>) -> Response<Body> {
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

    async fn handle_update_link_state(&self, req: Request<Body>) -> Response<Body> {
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

    async fn handle_chain_dry_run(&self, req: Request<Body>) -> Response<Body> {
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

    async fn handle_chain_create(&self, req: Request<Body>) -> Response<Body> {
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

    async fn handle_chain_get(&self, path: &str) -> Response<Body> {
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

    async fn handle_chain_delete(&self, path: &str) -> Response<Body> {
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

    async fn handle_chain_stats(&self) -> Response<Body> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let stats = mgr.get_stats().await;
        json(StatusCode::OK, &stats)
    }

    async fn handle_subscriptions_list(&self) -> Response<Body> {
        let mgr = match self.subscription_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let subs = mgr.list_subscriptions();
        let dtos: Vec<SubscriptionDto> = subs.into_iter().map(SubscriptionDto::from).collect();
        json(StatusCode::OK, &dtos)
    }

    async fn handle_subscription_add(&self, req: Request<Body>) -> Response<Body> {
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

    async fn handle_subscription_remove(&self, path: &str) -> Response<Body> {
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

    async fn handle_subscription_refresh(&self, path: &str) -> Response<Body> {
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

        let merge_stats: ConfigMergeStats =
            match self.runtime.merge_config_delta(&converted.config).await {
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

    async fn handle_subscriptions_refresh_all(&self) -> Response<Body> {
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
                Ok(converted) => match self.runtime.merge_config_delta(&converted.config).await {
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

impl From<seep_runtime::RuntimeStats> for RuntimeStatsDto {
    fn from(s: seep_runtime::RuntimeStats) -> Self {
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

impl From<seep_core::ChainContext> for ChainContextDto {
    fn from(v: seep_core::ChainContext) -> Self {
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

async fn read_json<T: for<'de> Deserialize<'de>>(req: Request<Body>) -> Result<T, Response<Body>> {
    let bytes = body::to_bytes(req.into_body())
        .await
        .map_err(|_| text(StatusCode::BAD_REQUEST, "invalid body"))?;
    serde_json::from_slice::<T>(&bytes)
        .map_err(|e| text(StatusCode::BAD_REQUEST, &format!("invalid json: {e}")))
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(buf) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(buf))
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
        Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("internal error")))
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
        let metric = sanitize_metric_name_with_prefix("seep_", metric_name);
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

    fn inc_mesh_event(&mut self, event: &seep_runtime::MeshEventType) {
        match event {
            seep_runtime::MeshEventType::NodeRegistered { .. } => {
                self.inc("mesh_events_total", &[("type", "node_registered")]);
            }
            seep_runtime::MeshEventType::NodeOffline { .. } => {
                self.inc("mesh_events_total", &[("type", "node_offline")]);
            }
            seep_runtime::MeshEventType::SessionCreated { .. } => {
                self.inc("mesh_events_total", &[("type", "session_created")]);
            }
            seep_runtime::MeshEventType::SessionEnded { .. } => {
                self.inc("mesh_events_total", &[("type", "session_ended")]);
            }
            seep_runtime::MeshEventType::PathUpdated { .. } => {
                self.inc("mesh_events_total", &[("type", "path_updated")]);
            }
        }
    }

    fn inc_network_event(&mut self, event: &seep_runtime::NetworkEventType) {
        match event {
            seep_runtime::NetworkEventType::InterfaceCreated { .. } => {
                self.inc("network_events_total", &[("type", "interface_created")]);
            }
            seep_runtime::NetworkEventType::InterfaceDestroyed { .. } => {
                self.inc("network_events_total", &[("type", "interface_destroyed")]);
            }
            seep_runtime::NetworkEventType::InterfaceUp { .. } => {
                self.inc("network_events_total", &[("type", "interface_up")]);
            }
            seep_runtime::NetworkEventType::InterfaceDown { .. } => {
                self.inc("network_events_total", &[("type", "interface_down")]);
            }
            seep_runtime::NetworkEventType::RouteUpdated { .. } => {
                self.inc("network_events_total", &[("type", "route_updated")]);
            }
            seep_runtime::NetworkEventType::PacketFiltered { .. } => {
                self.inc("network_events_total", &[("type", "packet_filtered")]);
            }
        }
    }

    fn inc_subscription_event(
        &mut self,
        subscription_name: &str,
        event: &seep_runtime::SubscriptionEventType,
    ) {
        match event {
            seep_runtime::SubscriptionEventType::Added { .. } => self.inc(
                "subscription_events_total",
                &[("type", "added"), ("subscription", subscription_name)],
            ),
            seep_runtime::SubscriptionEventType::Removed { .. } => self.inc(
                "subscription_events_total",
                &[("type", "removed"), ("subscription", subscription_name)],
            ),
            seep_runtime::SubscriptionEventType::Updated { .. } => self.inc(
                "subscription_events_total",
                &[("type", "updated"), ("subscription", subscription_name)],
            ),
            seep_runtime::SubscriptionEventType::Refreshed { .. } => self.inc(
                "subscription_events_total",
                &[("type", "refreshed"), ("subscription", subscription_name)],
            ),
            seep_runtime::SubscriptionEventType::Error { .. } => self.inc(
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
    sanitize_metric_name_with_prefix("seep_telemetry_", metric_name)
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
    use seep_config::SeepConfig;
    use seep_runtime::{MeshConfig, RuntimeBuilder, RuntimeConfig};

    async fn build_runtime(mesh: bool, chain: bool) -> Arc<Runtime> {
        let cfg_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/seep.yaml");
        let cfg = SeepConfig::load_from_path(cfg_path).unwrap();
        let rt_cfg = RuntimeConfig {
            enable_mesh: mesh,
            enable_chain: chain,
            mesh_config: if mesh {
                Some(MeshConfig {
                    allow_plaintext_data_plane: true,
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

    #[tokio::test]
    async fn nodes_requires_mesh_enabled() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/nodes")
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text_when_enabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let s = String::from_utf8(body.to_vec()).unwrap();
        assert!(s.contains("seep_uptime_seconds"));
    }

    #[tokio::test]
    async fn metrics_returns_404_when_disabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, false);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn can_register_node_when_mesh_enabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None, true);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/mesh/nodes/register")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
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
                .body(Body::from(format!(
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
            .body(Body::from(
                r#"{"source":"client1","target":"exit1","latency_ms":20,"bandwidth_mbps":100,"packet_loss_rate":0.0}"#,
            ))
            .unwrap();
        assert_eq!(cp.handle(link).await.status(), StatusCode::OK);

        // Dry-run should succeed.
        let dry = Request::builder()
            .method(Method::POST)
            .uri("/chains/dry-run")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(dry).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("success").and_then(|x| x.as_bool()), Some(true));

        // Create chain and query it back.
        let create = Request::builder()
            .method(Method::POST)
            .uri("/chains")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(create).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let chain_id = v
            .get("chain_id")
            .and_then(|x| x.as_str())
            .unwrap()
            .to_string();

        let get = Request::builder()
            .method(Method::GET)
            .uri(format!("/chains/{chain_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
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
            .body(Body::from(
                r#"{"name":"sub1","url":"https://example.com/sub.yaml","type":"clash"}"#,
            ))
            .unwrap();
        let resp = cp.handle(add).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // List subscriptions.
        let list = Request::builder()
            .method(Method::GET)
            .uri("/subscriptions")
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(list).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().expect("subscription list array");
        assert!(arr
            .iter()
            .any(|s| s.get("name").and_then(|x| x.as_str()) == Some("sub1")));

        // Remove subscription.
        let remove = Request::builder()
            .method(Method::DELETE)
            .uri("/subscriptions/sub1")
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(remove).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
