//! 运行时构建器
//!
//! 整合配置、路由、网络虚拟化与 Mesh/订阅组件，
//! 构建可运行的 Seep runtime。
//! 支持多跳链路构建与故障转移。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, Mutex},
    task::JoinHandle,
    time,
};

use seep_config::{
    EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, SeepConfig,
};
use seep_core::{
    EgressConnector, Flow, FlowContext, FlowOutput, FlowReport, FlowRouter, IngressEndpoint,
    RouteDecision, RoutePath,
};
use seep_mesh::{MeshRegistry, MeshSession, NodeId, SessionId};
use seep_platform::network::{NetworkConfig, NetworkManager};
use seep_protocols::{
    DirectConnector, HttpConnector, HttpIngress, MixedIngress, ShadowsocksConnector, Socks5Connector,
    Socks5Ingress, TrojanConnector, Hysteria2Connector,
};
use seep_routing::RoutingEngine;
use seep_subscription::SubscriptionManager;
use seep_subscription::SubscriptionConverter;

use crate::chain::{ChainBuilder, ChainConfig, ChainConstraints, ChainManager};
use crate::mesh_transport::{MeshDataPlane, MeshEnvelope};

/// 运行时构建器
pub struct RuntimeBuilder {
    config: SeepConfig,
    runtime_config: RuntimeConfig,
    ingress_endpoints: HashMap<String, Arc<dyn IngressEndpoint>>, 
    flow_outputs: HashMap<String, Arc<dyn FlowOutput>>,
    egress_connectors: HashMap<String, Arc<dyn EgressConnector>>,
}

impl RuntimeBuilder {
    /// 创建新的构建器
    pub fn new(config: SeepConfig) -> Self {
        Self {
            config,
            runtime_config: RuntimeConfig::default(),
            ingress_endpoints: HashMap::new(),
            flow_outputs: HashMap::new(),
            egress_connectors: HashMap::new(),
        }
    }

    /// 自定义运行时配置
    pub fn with_runtime_config(mut self, config: RuntimeConfig) -> Self {
        self.runtime_config = config;
        self
    }

    /// 注入自定义入口
    pub fn with_ingress_endpoint<S: Into<String>>(mut self, name: S, endpoint: Arc<dyn IngressEndpoint>) -> Self {
        self.ingress_endpoints.insert(name.into(), endpoint);
        self
    }

    /// 注入自定义流量输出
    pub fn with_flow_output<S: Into<String>>(mut self, name: S, output: Arc<dyn FlowOutput>) -> Self {
        self.flow_outputs.insert(name.into(), output);
        self
    }

    /// 注入自定义出口连接器
    pub fn with_egress_connector<S: Into<String>>(mut self, name: S, connector: Arc<dyn EgressConnector>) -> Self {
        self.egress_connectors.insert(name.into(), connector);
        self
    }

    /// 构建 Runtime
    pub fn build(mut self) -> Result<Runtime> {
        self.validate()?;

        let config = Arc::new(RwLock::new(self.config));
        let config_snapshot = config.read().expect("config poisoned").clone();

        // 创建路由引擎
        let router = Arc::new(RoutingEngine::new(config_snapshot.routing.clone()));

        // 入口/出口默认实现
        if self.ingress_endpoints.is_empty() {
            self.ingress_endpoints = build_ingress_endpoints(&config_snapshot.ingress)?;
        }
        if self.flow_outputs.is_empty() {
            let (outputs, connectors) = build_egress_outputs(&config_snapshot.egress)?;
            self.flow_outputs = outputs;
            if self.egress_connectors.is_empty() {
                self.egress_connectors = connectors;
            }
        }

        let network_manager = if self.runtime_config.enable_network_virtualization {
            if let Some(network_cfg) = &self.runtime_config.network_config {
                let mut manager = NetworkManager::new(network_cfg.clone());
                manager.initialize()?;
                Some(Arc::new(Mutex::new(manager)))
            } else {
                None
            }
        } else {
            None
        };

        let local_node_id = if self.runtime_config.enable_mesh {
            // Persist mesh_config back into runtime_config for later (listener bind, etc).
            if self.runtime_config.mesh_config.is_none() {
                self.runtime_config.mesh_config = Some(MeshConfig::default());
            }
            let mesh_cfg = self.runtime_config.mesh_config.clone().unwrap_or_default();
            let node_id = mesh_cfg.node_id.clone();
            let _registry = register_local_mesh_node(mesh_cfg)?;
            Some((node_id, _registry))
        } else {
            None
        };

        let (local_node_id, mesh_registry) = match local_node_id {
            Some((id, reg)) => (Some(id), Some(reg)),
            None => (None, None),
        };

        // 初始化链路管理器（需要先有 mesh_registry）
        let chain_manager = if self.runtime_config.enable_chain {
            if let Some(ref registry) = mesh_registry {
                let chain_cfg = self
                    .runtime_config
                    .chain_config
                    .clone()
                    .unwrap_or_default();
                let builder = Arc::new(ChainBuilder::new(chain_cfg.clone(), registry.clone()));
                Some(Arc::new(ChainManager::new(chain_cfg, builder, registry.clone())))
            } else {
                tracing::warn!(
                    target: "seep::runtime",
                    "链路功能已启用但 Mesh 未启用，链路管理器将不可用"
                );
                None
            }
        } else {
            None
        };

        let subscription_manager = if self.runtime_config.enable_hot_reload {
            Some(Arc::new(SubscriptionManager::new()))
        } else {
            None
        };

        let (event_tx, _event_rx) = broadcast::channel(1024);

        Ok(Runtime {
            config,
            runtime_config: self.runtime_config,
            router,
            local_node_id,
            ingress_endpoints: self.ingress_endpoints,
            flow_outputs: Arc::new(RwLock::new(self.flow_outputs)),
            egress_connectors: Arc::new(RwLock::new(self.egress_connectors)),
            mesh_registry,
            chain_manager,
            network_manager,
            subscription_manager,
            event_tx,
            stats: Arc::new(RwLock::new(RuntimeStats::new())),
            running: Arc::new(RwLock::new(false)),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.config.ingress.is_empty() {
            return Err(anyhow!("至少需要配置一个入口"));
        }
        if self.config.egress.is_empty() {
            return Err(anyhow!("至少需要配置一个出口"));
        }
        if self.runtime_config.enable_mesh {
            if let Some(mesh_cfg) = &self.runtime_config.mesh_config {
                if mesh_cfg.node_id.trim().is_empty() {
                    return Err(anyhow!("Mesh 节点 ID 不能为空"));
                }
            }
        }
        Ok(())
    }
}

/// 运行时配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub enable_mesh: bool,
    pub enable_network_virtualization: bool,
    pub enable_hot_reload: bool,
    /// 启用多跳链路支持
    pub enable_chain: bool,
    pub mesh_config: Option<MeshConfig>,
    pub network_config: Option<NetworkConfig>,
    /// 链路配置
    pub chain_config: Option<ChainConfig>,
    pub worker_threads: Option<usize>,
    pub connection_pool_size: Option<usize>,
    pub session_timeout: Option<Duration>,
    pub heartbeat_interval: Option<Duration>,
    pub stats_interval: Option<Duration>,
    /// 订阅检查间隔（用于 enable_hot_reload 的自动刷新与应用）
    pub subscription_check_interval: Option<Duration>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            enable_mesh: false,
            enable_network_virtualization: false,
            enable_hot_reload: true,
            enable_chain: false,
            mesh_config: None,
            network_config: None,
            chain_config: None,
            worker_threads: Some(num_cpus::get()),
            connection_pool_size: Some(1024),
            session_timeout: Some(Duration::from_secs(300)),
            heartbeat_interval: Some(Duration::from_secs(30)),
            stats_interval: Some(Duration::from_secs(60)),
            subscription_check_interval: Some(Duration::from_secs(30)),
        }
    }
}

/// Mesh 节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub node_id: String,
    pub role: String,
    pub listen_address: SocketAddr,
    pub topology_update_interval: Duration,
    pub health_check_interval: Duration,
    pub max_sessions: Option<usize>,
    pub enabled_features: Vec<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            node_id: whoami::fallible::hostname().unwrap_or_else(|_| "seep-node".to_string()),
            role: "client".into(),
            listen_address: "0.0.0.0:9091".parse().unwrap(),
            topology_update_interval: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(60),
            max_sessions: Some(10_000),
            enabled_features: vec!["relay".into(), "exit".into()],
        }
    }
}

/// 运行时事件
#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    ConfigUpdated { config: SeepConfig },
    MeshEvent { session_id: SessionId, event: MeshEventType },
    NetworkEvent { event_type: NetworkEventType, details: String },
    SubscriptionEvent { subscription_name: String, event: SubscriptionEventType },
    TelemetryEvent { metric_name: String, value: f64, tags: HashMap<String, String> },
    Error { source: String, error: String, context: HashMap<String, String> },
}

#[derive(Debug, Clone)]
pub enum MeshEventType {
    NodeRegistered { node_id: NodeId },
    NodeOffline { node_id: NodeId },
    SessionCreated { session: MeshSession },
    SessionEnded { session_id: SessionId, reason: String },
    PathUpdated { session_id: SessionId, path: Vec<NodeId> },
}

#[derive(Debug, Clone)]
pub enum NetworkEventType {
    InterfaceCreated { name: String },
    InterfaceDestroyed { name: String },
    InterfaceUp { name: String },
    InterfaceDown { name: String },
    RouteUpdated { action: String },
    PacketFiltered { rule_name: String },
}

#[derive(Debug, Clone)]
pub enum SubscriptionEventType {
    Added { node_count: usize },
    Removed { name: String },
    Updated { name: String, changes: Vec<String> },
    Refreshed { name: String, status: String },
    Error { name: String, error: String },
}

/// 运行时统计
#[derive(Debug, Clone)]
pub struct RuntimeStats {
    pub uptime_seconds: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_bytes_transferred: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub mesh_nodes: usize,
    pub mesh_sessions: usize,
    pub network_interfaces: usize,
    pub subscription_nodes: usize,
    pub error_count: u64,
    pub last_updated: Instant,
}

impl RuntimeStats {
    pub fn new() -> Self {
        Self {
            uptime_seconds: 0,
            total_connections: 0,
            active_connections: 0,
            total_bytes_transferred: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            mesh_nodes: 0,
            mesh_sessions: 0,
            network_interfaces: 0,
            subscription_nodes: 0,
            error_count: 0,
            last_updated: Instant::now(),
        }
    }

    pub fn update(&mut self) {
        self.last_updated = Instant::now();
    }
}

/// 配置合并统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMergeStats {
    pub nodes_added: usize,
    pub groups_added: usize,
    pub rules_added: usize,
}

/// Runtime 实例
pub struct Runtime {
    config: Arc<RwLock<SeepConfig>>,
    runtime_config: RuntimeConfig,
    router: Arc<RoutingEngine>,
    local_node_id: Option<NodeId>,
    ingress_endpoints: HashMap<String, Arc<dyn IngressEndpoint>>,
    flow_outputs: Arc<RwLock<HashMap<String, Arc<dyn FlowOutput>>>>,
    egress_connectors: Arc<RwLock<HashMap<String, Arc<dyn EgressConnector>>>>,
    mesh_registry: Option<Arc<MeshRegistry>>,
    /// 链路管理器（多跳链路支持）
    chain_manager: Option<Arc<ChainManager>>,
    network_manager: Option<Arc<Mutex<NetworkManager>>>,
    subscription_manager: Option<Arc<SubscriptionManager>>,
    event_tx: broadcast::Sender<RuntimeEvent>,
    stats: Arc<RwLock<RuntimeStats>>,
    running: Arc<RwLock<bool>>,
}

impl Runtime {
    /// 阻塞运行直到所有子任务结束
    pub async fn run(self) -> Result<()> {
        let handles = self.start().await?;
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(join_err) => {
                    return Err(anyhow!("runtime task panicked: {}", join_err));
                }
            }
        }
        Ok(())
    }

    /// 启动所有后台任务
    pub async fn start(&self) -> Result<Vec<JoinHandle<Result<()>>>> {
        let mut tasks = Vec::new();
        *self.running.write().expect("running lock poisoned") = true;

        // 创建流量输出路由器（支持多跳链路）
        let output_router = Arc::new(FlowOutputRouter::new(
            self.flow_outputs.clone(),
            self.chain_manager.clone(),
            self.mesh_registry.clone(),
            self.local_node_id.clone(),
        ));

        // Spawn mesh data-plane listener (TCP) for multi-hop transport (requires chain feature).
        if self.runtime_config.enable_chain {
            if let (Some(mesh), Some(local_id), Some(mesh_cfg)) = (
                self.mesh_registry.clone(),
                self.local_node_id.clone(),
                self.runtime_config.mesh_config.clone(),
            ) {
                let plane = MeshDataPlane::new(local_id, mesh);
                tasks.push(plane.spawn(mesh_cfg.listen_address));
            }
        }

        for (name, endpoint) in self.ingress_endpoints.iter() {
            let router = self.flow_router();
            let output = output_router.clone();
            let ingress = endpoint.clone();
            let label = name.clone();
            tasks.push(tokio::spawn(async move {
                ingress.run(router, output).await.map_err(|e| {
                    anyhow!("入口 {label} 异常退出: {e}")
                })
            }));
        }

        if let Some(manager) = &self.network_manager {
            let mgr = manager.clone();
            tasks.push(tokio::spawn(async move {
                let mut guard = mgr.lock().await;
                guard.start().await
            }));
        }

        if let Some(mesh) = &self.mesh_registry {
            let registry = mesh.clone();
            let tx = self.event_tx.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker = time::interval(Duration::from_secs(10));
                loop {
                    ticker.tick().await;
                    let stats = registry.get_stats();
                    let _ = tx.send(RuntimeEvent::TelemetryEvent {
                        metric_name: "mesh_nodes".into(),
                        value: stats.total_nodes as f64,
                        tags: HashMap::new(),
                    });
                }
            }));
        }

        // Subscription auto-refresh + apply loop.
        if self.runtime_config.enable_hot_reload {
            if let Some(sub_mgr) = &self.subscription_manager {
                let sub_mgr = sub_mgr.clone();
                let config = self.config.clone();
                let router = self.router.clone();
                let flow_outputs = self.flow_outputs.clone();
                let egress_connectors = self.egress_connectors.clone();
                let tx = self.event_tx.clone();
                let running = self.running.clone();
                let check_interval = self
                    .runtime_config
                    .subscription_check_interval
                    .unwrap_or(Duration::from_secs(30));

                tasks.push(tokio::spawn(async move {
                    let converter = SubscriptionConverter::new();
                    let mut ticker = time::interval(check_interval);
                    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

                    while *running.read().expect("running lock poisoned") {
                        ticker.tick().await;

                        let names_to_refresh: Vec<String> = sub_mgr
                            .list_subscriptions()
                            .into_iter()
                            .filter(|s| s.needs_refresh())
                            .map(|s| s.name)
                            .collect();

                        if names_to_refresh.is_empty() {
                            continue;
                        }

                        for name in names_to_refresh {
                            let old_hash = sub_mgr
                                .get_subscription(&name)
                                .and_then(|s| s.content_hash.clone());

                            let content = match sub_mgr.refresh_subscription(&name).await {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                        subscription_name: name.clone(),
                                        event: SubscriptionEventType::Error {
                                            name: name.clone(),
                                            error: e.to_string(),
                                        },
                                    });
                                    continue;
                                }
                            };

                            let new_hash = sub_mgr
                                .get_subscription(&name)
                                .and_then(|s| s.content_hash.clone());

                            let changed = new_hash != old_hash;
                            let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                subscription_name: name.clone(),
                                event: SubscriptionEventType::Refreshed {
                                    name: name.clone(),
                                    status: if changed {
                                        "changed".to_string()
                                    } else {
                                        "not_modified".to_string()
                                    },
                                },
                            });

                            if !changed {
                                continue;
                            }

                            let Some(sub) = sub_mgr.get_subscription(&name) else {
                                continue;
                            };

                            let converted = match converter.auto_convert(&sub, &content).await {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                        subscription_name: name.clone(),
                                        event: SubscriptionEventType::Error {
                                            name: name.clone(),
                                            error: format!("convert failed: {e}"),
                                        },
                                    });
                                    continue;
                                }
                            };

                            // Merge and apply.
                            let mut merged = config.read().expect("config lock poisoned").clone();
                            let merge_stats =
                                merge_config_delta_in_place(&mut merged, &converted.config);

                            let (outputs, connectors) = match build_egress_outputs(&merged.egress) {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                        subscription_name: name.clone(),
                                        event: SubscriptionEventType::Error {
                                            name: name.clone(),
                                            error: format!("build egress failed: {e}"),
                                        },
                                    });
                                    continue;
                                }
                            };

                            *config.write().expect("config lock poisoned") = merged.clone();
                            router.reload(merged.routing.clone());
                            *flow_outputs
                                .write()
                                .expect("flow_outputs lock poisoned") = outputs;
                            *egress_connectors
                                .write()
                                .expect("egress_connectors lock poisoned") = connectors;
                            let _ = tx.send(RuntimeEvent::ConfigUpdated { config: merged });

                            let changes = vec![
                                format!("nodes_added={}", merge_stats.nodes_added),
                                format!("groups_added={}", merge_stats.groups_added),
                                format!("rules_added={}", merge_stats.rules_added),
                            ];
                            let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                subscription_name: name.clone(),
                                event: SubscriptionEventType::Updated {
                                    name: name.clone(),
                                    changes,
                                },
                            });
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                }));
            }
        }

        // 启动链路管理器健康检查任务
        if let Some(chain_mgr) = &self.chain_manager {
            let mgr = chain_mgr.clone();
            let tx = self.event_tx.clone();
            tasks.push(tokio::spawn(async move {
                let mgr_clone = mgr.clone();
                tokio::spawn(async move {
                    mgr_clone.start_health_check_task().await;
                });

                // 定期报告链路统计
                let mut ticker = time::interval(Duration::from_secs(30));
                loop {
                    ticker.tick().await;
                    let stats = mgr.get_stats().await;
                    let _ = tx.send(RuntimeEvent::TelemetryEvent {
                        metric_name: "chain_active_count".into(),
                        value: stats.active_chains as f64,
                        tags: HashMap::new(),
                    });
                    let _ = tx.send(RuntimeEvent::TelemetryEvent {
                        metric_name: "chain_failover_count".into(),
                        value: stats.failover_count as f64,
                        tags: HashMap::new(),
                    });
                }
            }));
        }

        let stats = self.stats.clone();
        let tx = self.event_tx.clone();
        let stats_interval = self
            .runtime_config
            .stats_interval
            .unwrap_or(Duration::from_secs(60));
        tasks.push(tokio::spawn(async move {
            let mut ticker = time::interval(stats_interval);
            loop {
                ticker.tick().await;
                let mut guard = stats.write().expect("stats lock poisoned");
                guard.update();
                let snapshot = guard.clone();
                drop(guard);
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_uptime".into(),
                    value: snapshot.uptime_seconds as f64,
                    tags: HashMap::new(),
                });
            }
        }));

        Ok(tasks)
    }

    /// 停止运行时
    pub async fn stop(&self) -> Result<()> {
        *self.running.write().expect("running lock poisoned") = false;
        if let Some(manager) = &self.network_manager {
            let mut guard = manager.lock().await;
            guard.stop().await.ok();
        }
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        *self.running.read().expect("running lock poisoned")
    }

    pub fn get_stats(&self) -> RuntimeStats {
        self.stats.read().expect("stats lock poisoned").clone()
    }

    pub fn get_config(&self) -> SeepConfig {
        self.config.read().expect("config lock poisoned").clone()
    }

    pub async fn update_config(&self, new_config: SeepConfig) -> Result<()> {
        // Build egress outputs/connectors before mutating runtime state.
        let (outputs, connectors) = build_egress_outputs(&new_config.egress)?;

        *self.config.write().expect("config lock poisoned") = new_config.clone();
        self.router.reload(new_config.routing.clone());
        *self.flow_outputs.write().expect("flow_outputs lock poisoned") = outputs;
        *self.egress_connectors.write().expect("egress_connectors lock poisoned") = connectors;
        let _ = self.event_tx.send(RuntimeEvent::ConfigUpdated { config: new_config });
        Ok(())
    }

    /// 将订阅/外部生成的配置增量合并进当前配置，并触发 runtime 更新。
    ///
    /// 当前策略为“只追加不删除”：新增 egress / group，rules 直接追加（不去重）。
    pub async fn merge_config_delta(&self, delta: &SeepConfig) -> Result<ConfigMergeStats> {
        let mut merged = self.get_config();

        let stats = merge_config_delta_in_place(&mut merged, delta);

        self.update_config(merged).await?;

        Ok(stats)
    }

    /// 订阅运行时事件（广播通道）
    pub fn subscribe_events(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.event_tx.subscribe()
    }

    /// 兼容旧接口：返回事件订阅者
    pub fn get_event_receiver(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.subscribe_events()
    }

    /// 获取链路管理器
    pub fn get_chain_manager(&self) -> Option<Arc<ChainManager>> {
        self.chain_manager.clone()
    }

    /// 获取 Mesh 注册表
    pub fn get_mesh_registry(&self) -> Option<Arc<MeshRegistry>> {
        self.mesh_registry.clone()
    }

    /// 获取出口连接器
    pub fn get_egress_connectors(&self) -> HashMap<String, Arc<dyn EgressConnector>> {
        self.egress_connectors
            .read()
            .expect("egress_connectors lock poisoned")
            .clone()
    }

    /// 获取订阅管理器
    pub fn get_subscription_manager(&self) -> Option<Arc<SubscriptionManager>> {
        self.subscription_manager.clone()
    }

    /// 获取 FlowRouter（必要时自动包装为 mesh-chain 路由器）
    pub fn flow_router(&self) -> Arc<dyn FlowRouter> {
        if let (Some(chain_mgr), Some(mesh), Some(local_id)) = (
            self.chain_manager.clone(),
            self.mesh_registry.clone(),
            self.local_node_id.clone(),
        ) {
            Arc::new(RuntimeFlowRouter::new(
                self.router.clone(),
                mesh,
                chain_mgr,
                local_id,
            ))
        } else {
            self.router.clone()
        }
    }

    /// 执行链路 Dry Run（预检）
    pub async fn dry_run_chain(
        &self,
        source: &NodeId,
        target: &NodeId,
        constraints: Option<ChainConstraints>,
    ) -> Result<crate::chain::ChainDryRunResult> {
        // 验证链路管理器已启用
        let _ = self
            .chain_manager
            .as_ref()
            .ok_or_else(|| anyhow!("链路管理器未启用"))?;

        let mesh_registry = self
            .mesh_registry
            .as_ref()
            .ok_or_else(|| anyhow!("Mesh 注册表未启用"))?;

        let chain_cfg = self
            .runtime_config
            .chain_config
            .clone()
            .unwrap_or_default();

        let builder = ChainBuilder::new(chain_cfg, mesh_registry.clone());
        builder.dry_run(source, target, constraints).await
    }
}

fn merge_config_delta_in_place(target: &mut SeepConfig, delta: &SeepConfig) -> ConfigMergeStats {
    let mut existing_egress: std::collections::HashSet<String> =
        target.egress.iter().map(|e| e.name.clone()).collect();
    let mut existing_groups: std::collections::HashSet<String> =
        target.routing.groups.iter().map(|g| g.name.clone()).collect();

    let mut nodes_added = 0usize;
    for e in &delta.egress {
        if existing_egress.insert(e.name.clone()) {
            target.egress.push(e.clone());
            nodes_added += 1;
        }
    }

    let mut groups_added = 0usize;
    for g in &delta.routing.groups {
        if existing_groups.insert(g.name.clone()) {
            target.routing.groups.push(g.clone());
            groups_added += 1;
        }
    }

    let rules_added = delta.routing.rules.len();
    target.routing.rules.extend(delta.routing.rules.clone());

    ConfigMergeStats {
        nodes_added,
        groups_added,
        rules_added,
    }
}

/// 在普通 routing 结果之上，识别 mesh.* 目标并自动构建链路
struct RuntimeFlowRouter {
    engine: Arc<RoutingEngine>,
    mesh_registry: Arc<MeshRegistry>,
    chain_manager: Arc<ChainManager>,
    local_node_id: NodeId,
}

impl RuntimeFlowRouter {
    fn new(
        engine: Arc<RoutingEngine>,
        mesh_registry: Arc<MeshRegistry>,
        chain_manager: Arc<ChainManager>,
        local_node_id: NodeId,
    ) -> Self {
        Self {
            engine,
            mesh_registry,
            chain_manager,
            local_node_id,
        }
    }

    fn parse_mesh_target(target: &str) -> Option<&str> {
        target
            .strip_prefix("mesh.")
            .or_else(|| target.strip_prefix("mesh:"))
    }
}

#[async_trait]
impl FlowRouter for RuntimeFlowRouter {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        let base = self.engine.route(ctx.clone()).await?;

        // Already a chain decision; keep as-is.
        if matches!(base.path, RoutePath::Chain { .. }) {
            return Ok(base);
        }

        let target = base.final_node();
        let Some(mesh_target) = Self::parse_mesh_target(&target) else {
            return Ok(base);
        };

        // Validate the target exists/online; otherwise keep base decision.
        let online = self
            .mesh_registry
            .get_online_nodes()
            .into_iter()
            .any(|n| n.id == mesh_target);
        if !online {
            return Ok(base);
        }

        // Use FlowId UUID as session id, so retries of the same flow can reuse the chain.
        let session_id = ctx.id.as_uuid();
        let target_node: NodeId = mesh_target.to_string();
        match self
            .chain_manager
            .get_or_create_chain(session_id, &self.local_node_id, &target_node, None)
            .await
        {
            Ok(chain_ctx) => Ok(self.chain_manager.build_route_decision(&chain_ctx)),
            Err(_) => Ok(base),
        }
    }
}

/// 派发路由决策到具体出口（支持多跳链路）
struct FlowOutputRouter {
    outputs: Arc<RwLock<HashMap<String, Arc<dyn FlowOutput>>>>,
    /// 链路管理器（预留用于故障转移）
    #[allow(dead_code)]
    chain_manager: Option<Arc<ChainManager>>,
    mesh_registry: Option<Arc<MeshRegistry>>,
    local_node_id: Option<NodeId>,
}

impl FlowOutputRouter {
    fn new(
        outputs: Arc<RwLock<HashMap<String, Arc<dyn FlowOutput>>>>,
        chain_manager: Option<Arc<ChainManager>>,
        mesh_registry: Option<Arc<MeshRegistry>>,
        local_node_id: Option<NodeId>,
    ) -> Self {
        Self {
            outputs,
            chain_manager,
            mesh_registry,
            local_node_id,
        }
    }
}

#[async_trait]
impl FlowOutput for FlowOutputRouter {
    async fn forward(&self, decision: RouteDecision, flow: Flow) -> Result<FlowReport> {
        // 检查是否是多跳链路路由
        match &decision.path {
            RoutePath::Chain { hops } if !hops.is_empty() => {
                // 多跳链路转发
                self.forward_chain(&decision, flow, hops).await
            }
            _ => {
                // 单跳转发
                self.forward_single(&decision, flow).await
            }
        }
    }
}

impl FlowOutputRouter {
    /// 单跳转发
    async fn forward_single(&self, decision: &RouteDecision, flow: Flow) -> Result<FlowReport> {
        let mut target = decision.final_node();
        if let Some(stripped) = target.strip_prefix("egress.") {
            target = stripped.to_string();
        }

        let output = {
            let outputs = self.outputs.read().expect("flow_outputs lock poisoned");
            outputs.get(&target).cloned()
        };
        if let Some(output) = output {
            output.forward(decision.clone(), flow).await
        } else {
            Err(anyhow!("未找到出口 {target}"))
        }
    }

    /// 多跳链路转发
    async fn forward_chain(
        &self,
        decision: &RouteDecision,
        mut flow: Flow,
        hops: &[seep_core::RouteHop],
    ) -> Result<FlowReport> {
        if hops.is_empty() {
            return Err(anyhow!("多跳链路为空"));
        }

        // Always attach chain metadata (useful for telemetry and future multi-hop implementations).
        if let Ok(path_json) = serde_json::to_string(&decision.all_nodes()) {
            flow.metadata
                .annotations
                .insert("seep.chain.path".to_string(), path_json);
        }
        if let Some(reason) = decision.reason.as_deref() {
            flow.metadata
                .annotations
                .insert("seep.route.reason".to_string(), reason.to_string());
        }

        // For mesh chains, hops[0] is usually the local node id; the first actionable remote hop is hops[1].
        if hops.len() >= 2 {
            if let (Some(mesh), Some(local_id)) = (self.mesh_registry.clone(), self.local_node_id.clone()) {
                let next_hop = hops[1].node.clone();

                // Best-effort: if next_hop exists in mesh registry, use mesh transport; otherwise fall back.
                if mesh.get_node_addr(&next_hop).is_some() {
                    tracing::debug!(
                        target: "seep::mesh::transport",
                        next = %next_hop,
                        "使用 mesh data-plane 转发链路流量"
                    );

                    let plane = MeshDataPlane::new(local_id.clone(), mesh);
                    let env = MeshEnvelope::new(
                        flow.id.as_uuid().to_string(),
                        flow.target.host.clone(),
                        flow.target.port,
                        hops.iter().map(|h| h.node.clone()).collect(),
                    );

                    plane.dial_and_tunnel(&next_hop, &env, &mut *flow.io).await?;
                    return Ok(FlowReport::default());
                }
            }
        }

        // 记录链路信息到日志
        tracing::debug!(
            target: "seep::chain",
            path = ?hops.iter().map(|h| &h.node).collect::<Vec<_>>(),
            "执行多跳链路转发"
        );

        // Fallback behavior: try forward to the first hop that maps to an egress output.
        for hop in hops {
            let mut name = hop.node.clone();
            if let Some(stripped) = name.strip_prefix("egress.") {
                name = stripped.to_string();
            }
            let output = {
                let outputs = self.outputs.read().expect("flow_outputs lock poisoned");
                outputs.get(&name).cloned()
            };
            if let Some(output) = output {
                return output.forward(decision.clone(), flow).await;
            }
        }

        // Last resort: try forward to the final node like a regular egress.
        self.forward_single(decision, flow).await
    }
}

/// 将 EgressConnector 适配为 FlowOutput
struct ConnectorFlowOutput {
    name: String,
    connector: Arc<dyn EgressConnector>,
}

impl ConnectorFlowOutput {
    fn new(name: String, connector: Arc<dyn EgressConnector>) -> Self {
        Self { name, connector }
    }
}

#[async_trait]
impl FlowOutput for ConnectorFlowOutput {
    async fn forward(&self, _decision: RouteDecision, flow: Flow) -> Result<FlowReport> {
        self.connector
            .forward(flow)
            .await
            .map_err(|e| anyhow!("出口 {} 转发失败: {e}", self.name))
    }
}

fn build_ingress_endpoints(
    descriptors: &[IngressDescriptor],
) -> Result<HashMap<String, Arc<dyn IngressEndpoint>>> {
    let mut map = HashMap::new();
    for desc in descriptors {
        let endpoint: Arc<dyn IngressEndpoint> = match &desc.spec {
            IngressConfig::Socks5 { bind, auth } => {
                Arc::new(Socks5Ingress::new(
                    desc.name.clone(),
                    bind.clone(),
                    auth.clone().unwrap_or_default(),
                ))
            }
            IngressConfig::Http { bind } => {
                Arc::new(HttpIngress::new(desc.name.clone(), bind.clone()))
            }
            IngressConfig::Mixed { bind } => {
                Arc::new(MixedIngress::new(desc.name.clone(), bind.clone()))
            }
        };
        map.insert(desc.name.clone(), endpoint);
    }
    Ok(map)
}

fn build_egress_outputs(
    descriptors: &[EgressDescriptor],
) -> Result<(
    HashMap<String, Arc<dyn FlowOutput>>,
    HashMap<String, Arc<dyn EgressConnector>>,
)> {
    let mut outputs = HashMap::new();
    let mut connectors = HashMap::new();

    for desc in descriptors {
        match &desc.spec {
            EgressConfig::Direct => {
                let connector: Arc<dyn EgressConnector> = Arc::new(DirectConnector::default());
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Socks5 {
                server,
                port,
                username,
                password,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(Socks5Connector::new(
                    server.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Http {
                server,
                port,
                username,
                password,
                tls,
                skip_cert_verify,
                sni,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(HttpConnector::new(
                    server.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                    *tls,
                    *skip_cert_verify,
                    sni.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Shadowsocks {
                server,
                port,
                method,
                password,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(ShadowsocksConnector::new(
                    server.clone(),
                    *port,
                    method.clone(),
                    password.clone(),
                )?);
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Trojan {
                server,
                port,
                password,
                network,
                tls,
                skip_cert_verify,
                sni,
                ..
            } => {
                if network != "tcp" {
                    return Err(anyhow!(
                        "暂不支持的 Trojan network: {} (egress={})",
                        network,
                        desc.name
                    ));
                }
                if !*tls {
                    return Err(anyhow!(
                        "暂不支持的 Trojan 配置：tls=false (egress={})",
                        desc.name
                    ));
                }

                let connector: Arc<dyn EgressConnector> = Arc::new(TrojanConnector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Hysteria2 {
                server,
                port,
                password,
                mport,
                obfs,
                obfs_param,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(Hysteria2Connector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    mport.clone(),
                    obfs.clone(),
                    obfs_param.clone(),
                    server_name.clone(),
                    *skip_cert_verify,
                    alpn.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            _ => {
                return Err(anyhow!("暂不支持的出口类型: {}", desc.name));
            }
        }
    }

    Ok((outputs, connectors))
}

fn register_local_mesh_node(mesh_cfg: MeshConfig) -> Result<Arc<MeshRegistry>> {
    use seep_mesh::{NodeRecord, NodeRole};

    let registry = Arc::new(MeshRegistry::new());
    let role = match mesh_cfg.role.as_str() {
        "client" => NodeRole::Client,
        "relay" => NodeRole::Relay,
        "exit" => NodeRole::Exit,
        "hybrid" => NodeRole::Hybrid,
        _ => NodeRole::Client,
    };

    registry.register_node(NodeRecord::new(
        mesh_cfg.node_id.clone(),
        role,
        mesh_cfg.listen_address,
    ))?;

    let health_interval = mesh_cfg.health_check_interval;
    let topo_interval = mesh_cfg.topology_update_interval;
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        seep_mesh::spawn_health_checker(registry_clone, health_interval).await;
    });
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        seep_mesh::spawn_topology_updater(registry_clone, topo_interval).await;
    });

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{pin::Pin, task::{Context, Poll}};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Default)]
    struct DummyIo;

    impl AsyncRead for DummyIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DummyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CaptureOutput {
        annotations: Arc<Mutex<Option<std::collections::BTreeMap<String, String>>>>,
    }

    #[async_trait]
    impl FlowOutput for CaptureOutput {
        async fn forward(&self, _decision: RouteDecision, flow: Flow) -> Result<FlowReport> {
            let mut guard = self.annotations.lock().await;
            *guard = Some(flow.metadata.annotations);
            Ok(FlowReport::default())
        }
    }

    #[tokio::test]
	    async fn forward_chain_injects_metadata_annotations() {
	        let annotations = Arc::new(Mutex::new(None));
	        let mut outputs: HashMap<String, Arc<dyn FlowOutput>> = HashMap::new();
	        outputs.insert(
	            "direct".to_string(),
	            Arc::new(CaptureOutput {
	                annotations: annotations.clone(),
	            }),
	        );
	        let router = FlowOutputRouter::new(Arc::new(RwLock::new(outputs)), None, None, None);

        let decision = {
            let hops = vec![
                seep_core::RouteHop {
                    node: "direct".to_string(),
                    hop_type: seep_core::HopType::Ingress,
                },
                seep_core::RouteHop {
                    node: "exit1".to_string(),
                    hop_type: seep_core::HopType::Egress,
                },
            ];
            let mut d = RouteDecision::chain(hops);
            d.reason = Some("test".to_string());
            d
        };

        let flow = Flow {
            id: seep_core::FlowId::new(),
            target: seep_core::FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: seep_core::TargetProto::Tcp,
            },
            io: Box::new(DummyIo::default()),
            metadata: seep_core::FlowMetadata::default(),
        };

        router.forward(decision, flow).await.unwrap();
        let guard = annotations.lock().await;
        let map = guard.as_ref().expect("annotations captured");
        assert!(map.contains_key("seep.chain.path"));
        assert_eq!(map.get("seep.route.reason").map(|s| s.as_str()), Some("test"));
    }

    #[test]
    fn build_egress_outputs_supports_hysteria2() {
        let egress = vec![EgressDescriptor {
            name: "hy2".to_string(),
            spec: EgressConfig::Hysteria2 {
                server: "example.com".to_string(),
                port: 443,
                password: "secret".to_string(),
                mport: None,
                obfs: None,
                obfs_param: None,
                server_name: Some("example.com".to_string()),
                skip_cert_verify: true,
                alpn: None,
            },
        }];

        let (outputs, connectors) = build_egress_outputs(&egress).expect("build egress outputs");
        assert!(outputs.contains_key("hy2"));
        assert_eq!(
            connectors
                .get("hy2")
                .expect("connector")
                .name(),
            "hysteria2"
        );
    }

    #[tokio::test]
    async fn merge_config_delta_updates_egress_connectors() {
        let cfg = SeepConfig {
            control: seep_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: seep_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
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
        };

        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        assert!(!runtime.get_egress_connectors().contains_key("p1"));

        let delta = SeepConfig {
            control: seep_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: seep_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![],
            egress: vec![EgressDescriptor {
                name: "p1".to_string(),
                spec: EgressConfig::Socks5 {
                    server: "127.0.0.1".to_string(),
                    port: 1080,
                    username: None,
                    password: None,
                },
            }],
            routing: seep_config::RoutingConfig {
                default_node: "direct".to_string(),
                groups: vec![],
                rules: vec![],
            },
        };

        let stats = runtime
            .merge_config_delta(&delta)
            .await
            .expect("merge delta");
        assert_eq!(stats.nodes_added, 1);

        let connectors = runtime.get_egress_connectors();
        assert_eq!(connectors.get("p1").expect("p1 connector").name(), "socks5");
    }
}
