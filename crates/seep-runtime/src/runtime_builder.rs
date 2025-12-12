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
    sync::{mpsc, Mutex},
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
    inbound::Socks5Ingress,
    outbound::DirectConnector,
};
use seep_routing::RoutingEngine;
use seep_subscription::SubscriptionManager;

use crate::chain::{ChainBuilder, ChainConfig, ChainConstraints, ChainManager};

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
            let mesh_cfg = self
                .runtime_config
                .mesh_config
                .clone()
                .unwrap_or_default();
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

        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        Ok(Runtime {
            config,
            runtime_config: self.runtime_config,
            router,
            local_node_id,
            ingress_endpoints: self.ingress_endpoints,
            flow_outputs: self.flow_outputs,
            egress_connectors: self.egress_connectors,
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

/// Runtime 实例
pub struct Runtime {
    config: Arc<RwLock<SeepConfig>>,
    runtime_config: RuntimeConfig,
    router: Arc<RoutingEngine>,
    local_node_id: Option<NodeId>,
    ingress_endpoints: HashMap<String, Arc<dyn IngressEndpoint>>,
    flow_outputs: HashMap<String, Arc<dyn FlowOutput>>,
    egress_connectors: HashMap<String, Arc<dyn EgressConnector>>,
    mesh_registry: Option<Arc<MeshRegistry>>,
    /// 链路管理器（多跳链路支持）
    chain_manager: Option<Arc<ChainManager>>,
    network_manager: Option<Arc<Mutex<NetworkManager>>>,
    subscription_manager: Option<Arc<SubscriptionManager>>,
    event_tx: mpsc::UnboundedSender<RuntimeEvent>,
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
        ));

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
        *self.config.write().expect("config lock poisoned") = new_config.clone();
        self.router.reload(new_config.routing.clone());
        let _ = self.event_tx.send(RuntimeEvent::ConfigUpdated { config: new_config });
        Ok(())
    }

    pub fn get_event_receiver(&self) -> mpsc::UnboundedReceiver<RuntimeEvent> {
        let (_tx, rx) = mpsc::unbounded_channel();
        rx
    }

    /// 获取链路管理器
    pub fn get_chain_manager(&self) -> Option<Arc<ChainManager>> {
        self.chain_manager.clone()
    }

    /// 获取 Mesh 注册表
    pub fn get_mesh_registry(&self) -> Option<Arc<MeshRegistry>> {
        self.mesh_registry.clone()
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
        let chain_manager = self
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
    outputs: HashMap<String, Arc<dyn FlowOutput>>,
    chain_manager: Option<Arc<ChainManager>>,
}

impl FlowOutputRouter {
    fn new(outputs: HashMap<String, Arc<dyn FlowOutput>>, chain_manager: Option<Arc<ChainManager>>) -> Self {
        Self { outputs, chain_manager }
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

        if let Some(output) = self.outputs.get(&target) {
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

        // 获取第一跳（入口到第一个中继/出口）
        let first_hop = &hops[0];
        let mut target = first_hop.node.clone();
        if let Some(stripped) = target.strip_prefix("egress.") {
            target = stripped.to_string();
        }

        // 记录链路信息到日志
        tracing::debug!(
            target: "seep::chain",
            path = ?hops.iter().map(|h| &h.node).collect::<Vec<_>>(),
            "执行多跳链路转发"
        );

        // Attach chain path metadata for downstream protocol layers (future: actual mesh transport).
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

        // 对于多跳链路，需要在流量元数据中携带完整路径信息
        // 这里简化处理：将路由决策传递给第一跳，由协议层处理后续跳转
        if let Some(output) = self.outputs.get(&target) {
            output.forward(decision.clone(), flow).await
        } else {
            // 如果没有对应的出口，尝试通过 direct 出口
            if let Some(direct_output) = self.outputs.get("direct") {
                direct_output.forward(decision.clone(), flow).await
            } else {
                Err(anyhow!("多跳链路第一跳 {} 无可用出口", target))
            }
        }
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
            _ => {
                return Err(anyhow!("暂不支持的入口类型: {}", desc.name));
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
