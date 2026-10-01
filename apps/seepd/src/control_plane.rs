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

use seep_core::udp::{TableSnapshot, UdpIngressMetrics, UdpIngressSnapshot};
use seep_mesh::{LinkState, MeshRegistry, NodeCapability, NodeRecord, NodeRole};
use seep_runtime::{ChainConstraints, ConfigMergeStats, Runtime, RuntimeEvent, SwitchReason};
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
            (Method::GET, "/udp/stats") => self.handle_udp_stats().await,
            (Method::GET, "/egress/pool/stats") => self.handle_egress_pool_stats().await,
            (Method::GET, "/runtime/stats") => self.handle_runtime_stats().await,
            (Method::GET, "/runtime/config") => self.handle_runtime_config().await,
            (Method::GET, "/events") => self.handle_events().await,
            (Method::GET, "/logs") => self.handle_logs(req).await,
            (Method::POST, "/mesh/nodes/register") => self.handle_register_node(req).await,
            (Method::POST, "/mesh/link-states") => self.handle_update_link_state(req).await,
            (Method::GET, "/mesh/switches") => self.handle_mesh_switches().await,

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

    // Err = 错误响应体（handler ? 早退惯例），不装箱
    #[allow(clippy::result_large_err)]
    fn mesh(&self) -> Result<Arc<MeshRegistry>, Response<Body>> {
        self.runtime
            .get_mesh_registry()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "mesh not enabled"))
    }

    // Err = 错误响应体（handler ? 早退惯例），不装箱
    #[allow(clippy::result_large_err)]
    fn chain_mgr(&self) -> Result<Arc<seep_runtime::ChainManager>, Response<Body>> {
        self.runtime
            .get_chain_manager()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "chain not enabled"))
    }

    // Err = 错误响应体（handler ? 早退惯例），不装箱
    #[allow(clippy::result_large_err)]
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

                for t in &traffic {
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

                // P2-1 §5：观测形丢包派生（D-2 = errors/connections；分母 0
                // 不出序列，E4——0/0 无意义。上报形 seep_mesh_packet_loss_rate
                // 语义不同，保留不动不合并）
                if traffic.iter().any(|t| t.connections_total > 0) {
                    push_metric_header(
                        &mut out,
                        "seep_mesh_link_loss_ratio",
                        "Observed link loss ratio (errors/connections) on a directed mesh link.",
                        "gauge",
                    );
                    for t in traffic.iter().filter(|t| t.connections_total > 0) {
                        push_metric_labeled(
                            &mut out,
                            "seep_mesh_link_loss_ratio",
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
                    "seep_mesh_link_rtt_ms",
                    "Mesh link RTT quantile in milliseconds (reported-stream samples).",
                    "gauge",
                );
                for r in rtts {
                    push_metric_labeled(
                        &mut out,
                        "seep_mesh_link_rtt_ms",
                        &[("from", &r.from), ("to", &r.to), ("quantile", "p50")],
                        r.p50_ms as f64,
                    );
                    push_metric_labeled(
                        &mut out,
                        "seep_mesh_link_rtt_ms",
                        &[("from", &r.from), ("to", &r.to), ("quantile", "p95")],
                        r.p95_ms as f64,
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
            out.push_str(&format!(
                "seep_chain_total_created {}\n",
                stats.total_chains_created
            ));
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

            // P2-1 §5：切换/终止原因计数族（恒渲染——四因零值也在，便于
            // Grafana absent 告警语义与按维查询）
            let counters = chain_mgr.switch_counters_snapshot();
            push_metric_header(
                &mut out,
                "seep_mesh_switch_total",
                "Mesh chain switch/termination events by reason.",
                "counter",
            );
            for reason in SwitchReason::ALL {
                let n = counters.get(reason.as_str()).copied().unwrap_or(0);
                push_metric_labeled(
                    &mut out,
                    "seep_mesh_switch_total",
                    &[("reason", reason.as_str())],
                    n as f64,
                );
            }
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
            "seep_udp_sessions_active",
            "Active UDP sessions.",
            udp_table.sessions_active as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_sessions_total",
            "Total UDP sessions created (including reclaimed).",
            udp_table.sessions_total as f64,
        );
        push_gauge(
            &mut out,
            "seep_udp_mappings_active",
            "Active UDP destination mappings.",
            udp_table.mappings_active as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_reroutes_total",
            "UDP sticky-decision rebuilds.",
            udp_table.reroutes as f64,
        );
        push_metric_header(
            &mut out,
            "seep_udp_relay_bytes_total",
            "UDP relay bytes between client and egress.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "seep_udp_relay_bytes_total",
            &[("direction", "up")],
            udp_table.bytes_up as f64,
        );
        push_metric_labeled(
            &mut out,
            "seep_udp_relay_bytes_total",
            &[("direction", "down")],
            udp_table.bytes_down as f64,
        );
        push_metric_header(
            &mut out,
            "seep_udp_relay_packets_total",
            "UDP relay datagrams.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "seep_udp_relay_packets_total",
            &[("direction", "up")],
            udp_ingress.uplink_packets as f64,
        );
        push_metric_labeled(
            &mut out,
            "seep_udp_relay_packets_total",
            &[("direction", "down")],
            udp_ingress.downlink_packets as f64,
        );
        push_metric_header(
            &mut out,
            "seep_udp_dropped_total",
            "Dropped UDP datagrams.",
            "counter",
        );
        for reason in UDP_DROP_REASONS {
            push_metric_labeled(
                &mut out,
                "seep_udp_dropped_total",
                &[("reason", reason)],
                udp_table.dropped.get(reason).copied().unwrap_or(0) as f64,
            );
        }
        push_metric_header(
            &mut out,
            "seep_udp_expired_total",
            "Expired UDP sessions/mappings.",
            "counter",
        );
        for reason in UDP_EXPIRE_REASONS {
            push_metric_labeled(
                &mut out,
                "seep_udp_expired_total",
                &[("reason", reason)],
                udp_table.expired.get(reason).copied().unwrap_or(0) as f64,
            );
        }

        // §2.3 ingress / ASSOCIATE 序列
        push_gauge(
            &mut out,
            "seep_udp_associates_active",
            "Active SOCKS5 UDP ASSOCIATE control connections.",
            udp_ingress.associates_active as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_associates_total",
            "Total accepted SOCKS5 UDP ASSOCIATE requests.",
            udp_ingress.associates_total as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_associates_rejected_total",
            "Rejected SOCKS5 UDP ASSOCIATE requests.",
            udp_ingress.associate_rejected as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_associate_errors_total",
            "SOCKS5 UDP ASSOCIATE slow-path errors.",
            udp_ingress.associate_errors as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_frag_dropped_total",
            "UDP datagrams dropped for FRAG != 0.",
            udp_ingress.frag_dropped as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_source_dropped_total",
            "UDP datagrams dropped for mismatched source address.",
            udp_ingress.source_dropped as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_malformed_dropped_total",
            "UDP datagrams dropped for malformed SOCKS5 header.",
            udp_ingress.malformed_dropped as f64,
        );

        // §2.4 mesh UDP 面序列（面未启用/未 start → 全零；client 侧分立不混入面族）
        let udp_mesh = self.runtime.get_mesh_udp_snapshot().unwrap_or_default();
        push_gauge(
            &mut out,
            "seep_udp_mesh_flows_active",
            "Active mesh UDP flow cache entries.",
            udp_mesh.flows_active as f64,
        );
        push_metric_header(
            &mut out,
            "seep_udp_mesh_forwarded_total",
            "Mesh UDP datagrams forwarded between hops.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "seep_udp_mesh_forwarded_total",
            &[("direction", "up")],
            udp_mesh.forwarded_up as f64,
        );
        push_metric_labeled(
            &mut out,
            "seep_udp_mesh_forwarded_total",
            &[("direction", "down")],
            udp_mesh.forwarded_down as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_mesh_unknown_flow_total",
            "Mesh UDP CACHED envelopes with no flow match.",
            udp_mesh.unknown_flow as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_mesh_malformed_total",
            "Mesh UDP envelopes failing to decode.",
            udp_mesh.malformed as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_mesh_evicted_total",
            "Mesh UDP flow cache evictions.",
            udp_mesh.evicted as f64,
        );
        push_counter(
            &mut out,
            "seep_udp_mesh_client_dropped_total",
            "Client-side mesh UDP downlink drops.",
            self.runtime
                .get_udp_client_metrics()
                .map(|m| m.dropped())
                .unwrap_or(0) as f64,
        );

        // P1-4 §5 obfs 序列（恒渲染：关闭态全零 = 零开销旁路的可观测证据
        // §2.5/E11；invocations 的 {name} 标签 = 配置挂载集，空链无条目）
        let obfs = self.runtime.get_obfs_pad_snapshot();
        push_metric_header(
            &mut out,
            "seep_obfs_padding_frames_total",
            "Chain envelope frames padded, by padding mode.",
            "counter",
        );
        push_metric_labeled(
            &mut out,
            "seep_obfs_padding_frames_total",
            &[("mode", "fixed")],
            obfs.frames_fixed as f64,
        );
        push_metric_labeled(
            &mut out,
            "seep_obfs_padding_frames_total",
            &[("mode", "bucket")],
            obfs.frames_bucket as f64,
        );
        push_metric_labeled(
            &mut out,
            "seep_obfs_padding_frames_total",
            &[("mode", "range")],
            obfs.frames_range as f64,
        );
        push_metric_labeled(
            &mut out,
            "seep_obfs_padding_bytes_total",
            &[("direction", "added")],
            obfs.bytes_added as f64,
        );
        push_metric_header(
            &mut out,
            "seep_obfs_padding_skipped_total",
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
                "seep_obfs_padding_skipped_total",
                &[("reason", reason)],
                value as f64,
            );
        }
        for (name, count) in seep_core::middleware_invocations() {
            push_metric_labeled(
                &mut out,
                "seep_obfs_middleware_invocations_total",
                &[("name", name)],
                count as f64,
            );
        }

        // P1-5 §6.1 池/握手序列：池启用才渲染（§8.2 对照关闭态 = 无
        // seep_pool_* 序列，非恒渲染——区别于 obfs E11 恒零纪律）
        if let Some(pool) = self.runtime.get_transport_pool() {
            let s = pool.snapshot();
            push_metric_header(
                &mut out,
                "seep_pool_acquires_total",
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
                    "seep_pool_acquires_total",
                    &[("result", result)],
                    value as f64,
                );
            }
            push_metric_header(
                &mut out,
                "seep_pool_dials_total",
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
                    "seep_pool_dials_total",
                    &[("origin", origin), ("result", "ok")],
                    ok as f64,
                );
                push_metric_labeled(
                    &mut out,
                    "seep_pool_dials_total",
                    &[("origin", origin), ("result", "error")],
                    err as f64,
                );
            }
            push_gauge(
                &mut out,
                "seep_pool_idle_connections",
                "Idle pooled connections.",
                s.idle as f64,
            );
            push_gauge(
                &mut out,
                "seep_pool_leased_connections",
                "Leased (in-use) pooled connections.",
                s.leased as f64,
            );
            push_gauge(
                &mut out,
                "seep_pool_reuse_ratio",
                "Lease hits over hits+misses, since start.",
                s.reuse_ratio(),
            );
            push_metric_header(
                &mut out,
                "seep_pool_evicted_total",
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
                    "seep_pool_evicted_total",
                    &[("reason", reason)],
                    value as f64,
                );
            }
        }
        if let Some(factory) = self.runtime.get_tls_factory() {
            let (full, full_hrr, resumed) = factory.handshake_snapshot();
            push_metric_header(
                &mut out,
                "seep_tls_handshakes_total",
                "TLS handshakes through the shared config, by kind.",
                "counter",
            );
            for (kind, value) in [("full", full), ("resumed", resumed), ("full_hrr", full_hrr)] {
                push_metric_labeled(
                    &mut out,
                    "seep_tls_handshakes_total",
                    &[("type", kind)],
                    value as f64,
                );
            }
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

    /// P0-5 §3.1/§9-1：UDP 观测 JSON。`table`/`ingress` 恒在（UDP 关闭时全零，
    /// §6-2）；`mesh` 仅面启用时为对象、否则 null（两态可区分）；
    /// `mesh_client` 仅 chain+udp client 桥装配时出现（§2.4 收编裁决：键省略）。
    async fn handle_udp_stats(&self) -> Response<Body> {
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
                }),
        };
        json(StatusCode::OK, &dto)
    }

    /// P1-5 §6.2 `GET /egress/pool/stats`：池快照 + 每键 idle + 计数族。
    /// 块缺席/未启用 = enabled:false 零值响应（形态稳定，脚本好消费）。
    async fn handle_egress_pool_stats(&self) -> Response<Body> {
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

    /// P2-1 §5：最近链路变更事件（切换/终止按因留痕，cap 100 最新保留）。
    /// 门控随 mesh 能力存在性（§5 未启用 503 同 /nodes 先例——账本宿主链路
    /// 管理器在 mesh 关闭的构建形态下也存在，mesh 注册表才是能力边界）。
    async fn handle_mesh_switches(&self) -> Response<Body> {
        if let Err(r) = self.mesh() {
            return r;
        }
        let events = match self.runtime.get_chain_manager() {
            Some(mgr) => mgr.get_recent_switches(usize::MAX),
            None => Vec::new(),
        };
        json(StatusCode::OK, &MeshSwitchesDto { events })
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

/// P0-5 §9-1 `/udp/stats` 响应体
#[derive(Debug, Clone, Serialize)]
struct UdpStatsDto {
    table: TableSnapshot,
    ingress: UdpIngressSnapshot,
    /// None 序列化为 null——面未启用与零流量两态可区分（§9-1）
    mesh: Option<seep_runtime::UdpFaceSnapshot>,
    /// 仅 chain+udp client 桥装配时出现（§2.4 收编裁决：未装配省略该键）
    #[serde(skip_serializing_if = "Option::is_none")]
    mesh_client: Option<UdpClientDroppedDto>,
}

#[derive(Debug, Clone, Serialize)]
struct UdpClientDroppedDto {
    dropped: u64,
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
    events: Vec<seep_runtime::SwitchEvent>,
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

// Err = 错误响应体（handler ? 早退惯例），不装箱
#[allow(clippy::result_large_err)]
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
    use seep_config::{
        EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, SeepConfig, UdpConfig,
    };
    use seep_runtime::{MeshConfig, RuntimeBuilder, RuntimeConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

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
        let link = Request::builder()
            .method(Method::POST)
            .uri("/mesh/link-states")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"source":"client1","target":"exit1","latency_ms":20,"bandwidth_mbps":100,"packet_loss_rate":0.0}"#,
            ))
            .unwrap();
        assert_eq!(cp.handle(link).await.status(), StatusCode::OK);

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

        // 无备用路径 → 首次故障即 FallbackExhausted（事件 + 计数器）
        runtime
            .get_chain_manager()
            .unwrap()
            .handle_chain_failure(&chain_id, "test failure")
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
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
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
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let s = String::from_utf8(body.to_vec()).unwrap();

        // RTT 分位：单样本 20ms → p50 = p95 = 20
        assert!(
            s.contains("seep_mesh_link_rtt_ms{from=\"client1\",to=\"exit1\",quantile=\"p50\"} 20")
        );
        assert!(
            s.contains("seep_mesh_link_rtt_ms{from=\"client1\",to=\"exit1\",quantile=\"p95\"} 20")
        );
        // 观测形丢包 = 1/1
        assert!(s.contains("seep_mesh_link_loss_ratio{from=\"client1\",to=\"exit1\"} 1"));
        // 切换计数族恒渲染：四因全在（零值也在），耗尽 = 1
        for reason in [
            "failure_reported",
            "fallback_exhausted",
            "ttl_expired",
            "terminated_unhealthy",
        ] {
            assert!(
                s.contains(&format!("seep_mesh_switch_total{{reason=\"{reason}\"}}")),
                "恒渲染缺 {reason}"
            );
        }
        assert!(s.contains("seep_mesh_switch_total{reason=\"fallback_exhausted\"} 1"));
        assert!(s.contains("seep_mesh_switch_total{reason=\"failure_reported\"} 0"));
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
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let s = String::from_utf8(body.to_vec()).unwrap();
        assert!(!s.contains("seep_mesh_link_rtt_ms"));
        assert!(!s.contains("seep_mesh_link_loss_ratio"));
        assert!(!s.contains("seep_mesh_switch_total"));

        let get = Request::builder()
            .method(Method::GET)
            .uri("/mesh/switches")
            .body(Body::empty())
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

    // ---------- P0-5 §10-S4 控制面渲染 ----------

    /// 找一个空闲端口（先绑后弃有竞态窗口，测试环境足够——与 runtime_builder 测试同法）
    fn free_bind() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("127.0.0.1:{}", l.local_addr().unwrap().port())
    }

    /// socks5 入口 + direct 出口 + udp.enabled 的最小配置（真 socket 往返用）
    fn s4_udp_config() -> SeepConfig {
        SeepConfig {
            control: seep_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: seep_config::TelemetryConfig {
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
            routing: seep_config::RoutingConfig {
                default_node: "direct".to_string(),
                groups: vec![],
                rules: vec![],
            },
            udp: UdpConfig {
                enabled: true,
                ..Default::default()
            },
            network: None,
            obfuscation: None,
            egress_pool: None,
        }
    }

    /// P1-5 §6 测试配置：socks5 入口 + trojan(TLS) 出口 + egress_pool 启用块
    ///（全缺省子字段——验证缺省面 enabled=true/tls_resumption=true）
    fn pool_enabled_config() -> SeepConfig {
        SeepConfig {
            control: seep_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: seep_config::TelemetryConfig {
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
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                },
            }],
            routing: seep_config::RoutingConfig {
                default_node: "trojan-out".to_string(),
                groups: vec![],
                rules: vec![],
            },
            udp: UdpConfig {
                enabled: false,
                ..Default::default()
            },
            network: None,
            obfuscation: None,
            egress_pool: Some(seep_config::EgressPoolBlock {
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
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
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
            "seep_udp_sessions_active",
            "seep_udp_sessions_total",
            "seep_udp_mappings_active",
            "seep_udp_reroutes_total",
            "seep_udp_relay_bytes_total{direction=\"up\"}",
            "seep_udp_relay_bytes_total{direction=\"down\"}",
            "seep_udp_relay_packets_total{direction=\"up\"}",
            "seep_udp_relay_packets_total{direction=\"down\"}",
            "seep_udp_dropped_total{reason=\"session_limit\"}",
            "seep_udp_dropped_total{reason=\"mapping_limit\"}",
            "seep_udp_dropped_total{reason=\"no_binding\"}",
            "seep_udp_dropped_total{reason=\"shutting_down\"}",
            "seep_udp_dropped_total{reason=\"send_failed\"}",
            "seep_udp_dropped_total{reason=\"downlink_full\"}",
            "seep_udp_expired_total{reason=\"idle\"}",
            "seep_udp_expired_total{reason=\"lifetime\"}",
            "seep_udp_expired_total{reason=\"revoked\"}",
            // §2.3 ingress / ASSOCIATE
            "seep_udp_associates_active",
            "seep_udp_associates_total",
            "seep_udp_associates_rejected_total",
            "seep_udp_associate_errors_total",
            "seep_udp_frag_dropped_total",
            "seep_udp_source_dropped_total",
            "seep_udp_malformed_dropped_total",
            // §2.4 mesh 面 + client 侧
            "seep_udp_mesh_flows_active",
            "seep_udp_mesh_forwarded_total{direction=\"up\"}",
            "seep_udp_mesh_forwarded_total{direction=\"down\"}",
            "seep_udp_mesh_unknown_flow_total",
            "seep_udp_mesh_malformed_total",
            "seep_udp_mesh_evicted_total",
            "seep_udp_mesh_client_dropped_total",
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
            "seep_obfs_padding_frames_total{mode=\"fixed\"}",
            "seep_obfs_padding_frames_total{mode=\"bucket\"}",
            "seep_obfs_padding_frames_total{mode=\"range\"}",
            "seep_obfs_padding_bytes_total{direction=\"added\"}",
            // §5 跳过计数（按 reason；peer_version/disabled MVP 恒 0）
            "seep_obfs_padding_skipped_total{reason=\"no_frame\"}",
            "seep_obfs_padding_skipped_total{reason=\"overhead_cap\"}",
            "seep_obfs_padding_skipped_total{reason=\"too_large\"}",
            "seep_obfs_padding_skipped_total{reason=\"peer_version\"}",
            "seep_obfs_padding_skipped_total{reason=\"disabled\"}",
        ];
        for series in zero_series {
            assert_eq!(
                metric_value(&s, series),
                Some(0.0),
                "系列 {series} 应恒渲染且值为 0"
            );
        }
        assert!(
            !s.contains("seep_obfs_middleware_invocations_total"),
            "空链无挂载 → invocations 无条目（name 标签集 = 配置挂载集）"
        );
    }

    /// P1-5 §8.2 对照关闭态（无块）：`/egress/pool/stats` 报 enabled=false
    /// 空计数，/metrics 无 seep_pool_* / seep_tls_* 序列（§6.1 只随池存在渲染）。
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
            !m.contains("seep_pool_"),
            "无块 → 无 seep_pool_* 序列（§8.2 对照关闭态）"
        );
        assert!(
            !m.contains("seep_tls_handshakes"),
            "无块 → 无 seep_tls_* 序列"
        );
    }

    /// P1-5 §6.1/§6.2：块启用 → 池/工厂句柄在位，stats 报 enabled=true 且
    /// 计数恒零初值，metrics 渲染完整 seep_pool_* / seep_tls_* 族（0 值）。
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
            "seep_pool_acquires_total{result=\"hit\"}",
            "seep_pool_acquires_total{result=\"miss\"}",
            "seep_pool_acquires_total{result=\"stale_redial\"}",
            "seep_pool_dials_total{origin=\"foreground\",result=\"ok\"}",
            "seep_pool_dials_total{origin=\"warm\",result=\"error\"}",
            "seep_pool_dials_total{origin=\"refill\",result=\"ok\"}",
            "seep_pool_evicted_total{reason=\"idle_timeout\"}",
            "seep_pool_evicted_total{reason=\"capacity\"}",
            "seep_pool_evicted_total{reason=\"shutdown\"}",
        ];
        for series in zero_series {
            assert_eq!(
                metric_value(&m, series),
                Some(0.0),
                "系列 {series} 应渲染且初值 0"
            );
        }
        for gauge in ["seep_pool_idle_connections", "seep_pool_leased_connections"] {
            assert_eq!(metric_value(&m, gauge), Some(0.0), "{gauge} 初值 0");
        }
        assert!(
            metric_value(&m, "seep_pool_reuse_ratio").is_some(),
            "reuse_ratio gauge 应渲染"
        );
        for kind in ["full", "resumed", "full_hrr"] {
            assert_eq!(
                metric_value(&m, &format!("seep_tls_handshakes_total{{type=\"{kind}\"}}")),
                Some(0.0),
                "seep_tls_handshakes_total{{type={kind}}} 应渲染且初值 0"
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
        frame.extend_from_slice(b"seep-udp-metrics");
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
        let (parsed, hlen) = seep_core::udp::parse_udp_header(&rxbuf[..n]).unwrap();
        assert_eq!(parsed.host, echo_addr.ip().to_string());
        assert_eq!(parsed.port, echo_addr.port());
        assert_eq!(&rxbuf[hlen..n], b"seep-udp-metrics");

        let s = get_body(&cp, "/metrics").await;
        assert!(
            metric_value(&s, "seep_udp_relay_packets_total{direction=\"up\"}").unwrap() >= 1.0,
            "上行包计数应 ≥1"
        );
        assert!(
            metric_value(&s, "seep_udp_relay_packets_total{direction=\"down\"}").unwrap() >= 1.0,
            "下行包计数应 ≥1"
        );
        assert!(
            metric_value(&s, "seep_udp_relay_bytes_total{direction=\"up\"}").unwrap() > 0.0,
            "上行字节应非零"
        );
        assert!(
            metric_value(&s, "seep_udp_relay_bytes_total{direction=\"down\"}").unwrap() > 0.0,
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

        for t in tasks {
            t.abort();
        }
    }
}
