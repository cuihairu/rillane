//! 多跳链路构建与管理
//!
//! 支持 source → relay → exit 多跳链路的构建、优化和故障转移。

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use petgraph::{
    algo::dijkstra,
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use rillane_core::{ChainContext, ChainStatus, HopType, RouteDecision, RouteHop, RouteType};
use rillane_mesh::{LinkState, MeshRegistry, NodeId, NodeRecord, NodeRole, SessionId};

fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 链路构建配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// 最大跳数限制
    pub max_hops: usize,
    /// 链路构建超时
    pub build_timeout: Duration,
    /// 是否启用故障转移
    pub enable_failover: bool,
    /// 备用路径数量
    pub fallback_path_count: usize,
    /// 路径优化策略
    pub optimization_strategy: PathOptimizationStrategy,
    /// 链路健康检查间隔
    pub health_check_interval: Duration,
    /// 链路过期时间
    pub chain_ttl: Duration,
    /// SLO 劣化 watcher（slo-scoring.md §2 D-5）：None = 不启（缺省）
    #[serde(default)]
    pub slo_watch: Option<SloWatch>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            max_hops: 5,
            build_timeout: Duration::from_secs(10),
            enable_failover: true,
            fallback_path_count: 2,
            optimization_strategy: PathOptimizationStrategy::BalancedLatencyBandwidth,
            health_check_interval: Duration::from_secs(30),
            chain_ttl: Duration::from_secs(300),
            slo_watch: None,
        }
    }
}

/// SLO 劣化 watcher 配置（slo-scoring.md §3）：当前路径末跳 p95/loss 任一
/// 越门即触发 `handle_chain_failure`（原因 SloDegraded）。程序化装配面
/// （`RuntimeBuilder.chain_config`）；YAML 面随 P2-3 profile。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloWatch {
    /// p95 RTT 门（ms）
    pub p95_ms: u32,
    /// 丢包率门（0.0-1.0）
    pub loss_ratio: f64,
    /// 评估周期（秒）
    pub interval_secs: u64,
}

/// 路径优化策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathOptimizationStrategy {
    /// 最低延迟优先
    LowestLatency,
    /// 最高带宽优先
    HighestBandwidth,
    /// 延迟带宽均衡
    BalancedLatencyBandwidth,
    /// 最少跳数
    MinimalHops,
    /// 最高可靠性
    HighestReliability,
}

/// 链路构建器
///
/// 负责根据 Mesh 拓扑构建多跳链路
pub struct ChainBuilder {
    config: ChainConfig,
    mesh_registry: Arc<MeshRegistry>,
}

impl ChainBuilder {
    /// 创建新的链路构建器
    pub fn new(config: ChainConfig, mesh_registry: Arc<MeshRegistry>) -> Self {
        Self {
            config,
            mesh_registry,
        }
    }

    /// 构建多跳链路
    ///
    /// 根据源节点、目标节点和约束条件构建最优路径
    pub async fn build_chain(
        &self,
        source: &NodeId,
        target: &NodeId,
        constraints: Option<ChainConstraints>,
    ) -> Result<ChainBuildResult> {
        let start_time = Instant::now();

        // 获取在线节点
        let online_nodes = self.mesh_registry.get_online_nodes();
        if online_nodes.is_empty() {
            return Err(anyhow!("没有可用的在线节点"));
        }

        // 验证源节点和目标节点
        let source_node = online_nodes
            .iter()
            .find(|n| &n.id == source)
            .ok_or_else(|| anyhow!("源节点 {} 不在线", source))?;

        let target_node = online_nodes
            .iter()
            .find(|n| &n.id == target)
            .ok_or_else(|| anyhow!("目标节点 {} 不在线", target))?;

        // 验证节点角色
        self.validate_node_roles(source_node, target_node)?;

        // 构建拓扑图（优先使用 Mesh 上报的 link-state 作为边）
        let link_states = self.mesh_registry.get_all_link_states();
        let (graph, node_indices) = self.build_topology_graph(&online_nodes, &link_states);

        // 获取源和目标的图索引
        let source_idx = *node_indices
            .get(source)
            .ok_or_else(|| anyhow!("源节点 {} 不在拓扑图中", source))?;
        let target_idx = *node_indices
            .get(target)
            .ok_or_else(|| anyhow!("目标节点 {} 不在拓扑图中", target))?;

        // 运行路径优化算法
        let primary_path =
            self.find_optimal_path(&graph, &node_indices, source_idx, target_idx, &constraints)?;

        // 构建备用路径
        let fallback_paths = if self.config.enable_failover {
            self.find_fallback_paths(
                &graph,
                &node_indices,
                source_idx,
                target_idx,
                &primary_path,
                &constraints,
            )?
        } else {
            Vec::new()
        };

        // 创建链路上下文
        let chain_id = Uuid::new_v4().to_string();
        let mut chain_context = ChainContext::new(chain_id.clone(), source.clone(), target.clone());
        chain_context.update_path(primary_path.clone());

        for fallback in &fallback_paths {
            chain_context.add_fallback_path(fallback.clone());
        }

        let build_duration = start_time.elapsed();

        info!(
            target: "rillane::chain",
            chain_id = %chain_id,
            source = %source,
            target = %target,
            hops = primary_path.len(),
            fallbacks = fallback_paths.len(),
            duration_ms = build_duration.as_millis(),
            "链路构建完成"
        );

        Ok(ChainBuildResult {
            chain_id,
            primary_path,
            fallback_paths,
            chain_context,
            build_duration,
        })
    }

    /// 验证节点角色
    fn validate_node_roles(&self, source: &NodeRecord, target: &NodeRecord) -> Result<()> {
        // 源节点应该是 Client 或 Hybrid
        match source.role {
            NodeRole::Client | NodeRole::Hybrid => {}
            _ => {
                return Err(anyhow!(
                    "源节点 {} 角色 {} 不能发起连接",
                    source.id,
                    source.role
                ));
            }
        }

        // 目标节点应该是 Exit 或 Hybrid
        match target.role {
            NodeRole::Exit | NodeRole::Hybrid => {}
            _ => {
                return Err(anyhow!(
                    "目标节点 {} 角色 {} 不能作为出口",
                    target.id,
                    target.role
                ));
            }
        }

        Ok(())
    }

    /// 构建拓扑图
    fn build_topology_graph(
        &self,
        nodes: &[NodeRecord],
        link_states: &[LinkState],
    ) -> (DiGraph<NodeId, LinkWeight>, HashMap<NodeId, NodeIndex>) {
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();

        // 添加所有节点
        for node in nodes {
            let idx = graph.add_node(node.id.clone());
            node_indices.insert(node.id.clone(), idx);
        }

        // 添加边：如果有 link_states，则以其为准；否则退化为“角色允许的全连接”。
        if !link_states.is_empty() {
            let node_map: HashMap<&NodeId, &NodeRecord> =
                nodes.iter().map(|n| (&n.id, n)).collect();

            for ls in link_states {
                let Some(source_node) = node_map.get(&ls.source) else {
                    continue;
                };
                let Some(target_node) = node_map.get(&ls.target) else {
                    continue;
                };
                if source_node.id == target_node.id {
                    continue;
                }
                if !self.can_connect(source_node, target_node) {
                    continue;
                }
                let (Some(&source_idx), Some(&target_idx)) = (
                    node_indices.get(&source_node.id),
                    node_indices.get(&target_node.id),
                ) else {
                    continue;
                };
                let weight = self.calculate_link_weight(source_node, target_node, Some(ls));
                graph.add_edge(source_idx, target_idx, weight);
            }
        } else {
            for source_node in nodes {
                for target_node in nodes {
                    if source_node.id == target_node.id {
                        continue;
                    }

                    if self.can_connect(source_node, target_node) {
                        let source_idx = node_indices[&source_node.id];
                        let target_idx = node_indices[&target_node.id];
                        let weight = self.calculate_link_weight(source_node, target_node, None);
                        graph.add_edge(source_idx, target_idx, weight);
                    }
                }
            }
        }

        (graph, node_indices)
    }

    /// 判断两个节点是否可以建立连接
    fn can_connect(&self, source: &NodeRecord, target: &NodeRecord) -> bool {
        match (source.role, target.role) {
            // Client 可以连接到 Relay, Exit, Hybrid
            (NodeRole::Client, NodeRole::Relay)
            | (NodeRole::Client, NodeRole::Exit)
            | (NodeRole::Client, NodeRole::Hybrid) => true,

            // Relay 可以连接到 Relay, Exit, Hybrid
            (NodeRole::Relay, NodeRole::Relay)
            | (NodeRole::Relay, NodeRole::Exit)
            | (NodeRole::Relay, NodeRole::Hybrid) => true,

            // Hybrid 可以连接到任何非 Client 节点
            (NodeRole::Hybrid, NodeRole::Relay)
            | (NodeRole::Hybrid, NodeRole::Exit)
            | (NodeRole::Hybrid, NodeRole::Hybrid) => true,

            _ => false,
        }
    }

    /// 计算链路权重
    fn calculate_link_weight(
        &self,
        source: &NodeRecord,
        target: &NodeRecord,
        link_state: Option<&LinkState>,
    ) -> LinkWeight {
        // Defaults (used when mesh doesn't provide link-state).
        let mut latency = 50u32;
        let mut bandwidth = target.capability.bandwidth_mbps.unwrap_or(100);
        let mut reliability = (source.health_score * target.health_score).clamp(0.0, 1.0);

        if let Some(ls) = link_state {
            if ls.latency_ms > 0 {
                latency = ls.latency_ms;
            }
            if ls.bandwidth_mbps > 0 {
                bandwidth = ls.bandwidth_mbps;
            }
            // Packet-loss reduces reliability further.
            reliability = (reliability * (1.0 - ls.packet_loss_rate)).clamp(0.0, 1.0);
        }

        // 根据策略计算综合权重
        let cost = match self.config.optimization_strategy {
            PathOptimizationStrategy::LowestLatency => latency as f32,
            PathOptimizationStrategy::HighestBandwidth => {
                if bandwidth > 0 {
                    1000.0 / bandwidth as f32
                } else {
                    1000.0
                }
            }
            PathOptimizationStrategy::BalancedLatencyBandwidth => {
                let latency_score = latency as f32 / 100.0;
                let bandwidth_score = if bandwidth > 0 {
                    100.0 / bandwidth as f32
                } else {
                    10.0
                };
                (latency_score + bandwidth_score) / 2.0
            }
            PathOptimizationStrategy::MinimalHops => 1.0,
            PathOptimizationStrategy::HighestReliability => {
                if reliability > 0.0 {
                    1.0 / reliability
                } else {
                    100.0
                }
            }
        };

        LinkWeight {
            cost,
            latency,
            bandwidth,
            reliability,
        }
    }

    /// 寻找最优路径
    fn find_optimal_path(
        &self,
        graph: &DiGraph<NodeId, LinkWeight>,
        node_indices: &HashMap<NodeId, NodeIndex>,
        source: NodeIndex,
        target: NodeIndex,
        constraints: &Option<ChainConstraints>,
    ) -> Result<Vec<NodeId>> {
        // 使用 Dijkstra 算法寻找最短路径
        let costs = dijkstra(graph, source, Some(target), |e| e.weight().cost as i32);

        if !costs.contains_key(&target) {
            return Err(anyhow!("无法找到从源到目标的路径"));
        }

        // 回溯路径
        let path = self.reconstruct_path(graph, node_indices, source, target, &costs)?;

        // 验证路径约束
        if let Some(constraints) = constraints {
            self.validate_path_constraints(&path, constraints)?;
        }

        // 验证跳数限制
        if path.len() > self.config.max_hops {
            return Err(anyhow!(
                "路径跳数 {} 超过限制 {}",
                path.len(),
                self.config.max_hops
            ));
        }

        Ok(path)
    }

    /// 重建路径
    fn reconstruct_path(
        &self,
        graph: &DiGraph<NodeId, LinkWeight>,
        node_indices: &HashMap<NodeId, NodeIndex>,
        source: NodeIndex,
        target: NodeIndex,
        costs: &HashMap<NodeIndex, i32>,
    ) -> Result<Vec<NodeId>> {
        // 反向索引
        let index_to_node: HashMap<NodeIndex, NodeId> =
            node_indices.iter().map(|(k, v)| (*v, k.clone())).collect();

        let mut path = Vec::new();
        let mut current = target;

        while current != source {
            let node_id = index_to_node
                .get(&current)
                .ok_or_else(|| anyhow!("节点索引 {:?} 不在映射中", current))?;
            path.push(node_id.clone());

            // 找到前驱节点
            let mut found_predecessor = false;
            for edge in graph.edges_directed(current, petgraph::Direction::Incoming) {
                let predecessor = edge.source();
                if let Some(&pred_cost) = costs.get(&predecessor) {
                    let edge_cost = edge.weight().cost as i32;
                    if let Some(&curr_cost) = costs.get(&current) {
                        if pred_cost + edge_cost == curr_cost {
                            current = predecessor;
                            found_predecessor = true;
                            break;
                        }
                    }
                }
            }

            if !found_predecessor {
                return Err(anyhow!("无法重建路径：找不到前驱节点"));
            }
        }

        // 添加源节点
        let source_id = index_to_node
            .get(&source)
            .ok_or_else(|| anyhow!("源节点索引 {:?} 不在映射中", source))?;
        path.push(source_id.clone());

        // 反转路径（从源到目标）
        path.reverse();

        Ok(path)
    }

    /// 验证路径约束
    fn validate_path_constraints(
        &self,
        path: &[NodeId],
        constraints: &ChainConstraints,
    ) -> Result<()> {
        // 检查跳数约束
        if let Some(max_hops) = constraints.max_hops {
            if path.len() > max_hops {
                return Err(anyhow!("路径跳数 {} 超过约束 {}", path.len(), max_hops));
            }
        }

        // 检查必经节点
        for required in &constraints.required_nodes {
            if !path.contains(required) {
                return Err(anyhow!("路径缺少必经节点 {}", required));
            }
        }

        // 检查禁止节点
        for forbidden in &constraints.forbidden_nodes {
            if path.contains(forbidden) {
                return Err(anyhow!("路径包含禁止节点 {}", forbidden));
            }
        }

        Ok(())
    }

    /// 寻找备用路径
    fn find_fallback_paths(
        &self,
        graph: &DiGraph<NodeId, LinkWeight>,
        node_indices: &HashMap<NodeId, NodeIndex>,
        source: NodeIndex,
        target: NodeIndex,
        primary_path: &[NodeId],
        constraints: &Option<ChainConstraints>,
    ) -> Result<Vec<Vec<NodeId>>> {
        let mut fallback_paths = Vec::new();
        let mut excluded_edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();

        for _ in 0..self.config.fallback_path_count {
            // 排除主路径中的某些边以找到不同的路径
            if !primary_path.is_empty() {
                // 选择主路径中的一条边进行排除
                let edge_to_exclude = primary_path.len() / 2;
                if edge_to_exclude < primary_path.len() - 1 {
                    if let (Some(&from_idx), Some(&to_idx)) = (
                        node_indices.get(&primary_path[edge_to_exclude]),
                        node_indices.get(&primary_path[edge_to_exclude + 1]),
                    ) {
                        excluded_edges.push((from_idx, to_idx));
                    }
                }
            }

            // 在排除某些边后重新计算路径
            let mut modified_graph = graph.clone();
            for (from, to) in &excluded_edges {
                if let Some(edge) = modified_graph.find_edge(*from, *to) {
                    modified_graph.remove_edge(edge);
                }
            }

            // 尝试找到新路径
            let costs = dijkstra(&modified_graph, source, Some(target), |e| {
                e.weight().cost as i32
            });

            if costs.contains_key(&target) {
                if let Ok(path) =
                    self.reconstruct_path(&modified_graph, node_indices, source, target, &costs)
                {
                    // 确保路径与主路径不同
                    if path != primary_path && !fallback_paths.contains(&path) {
                        // 验证约束
                        if let Some(ref c) = constraints {
                            if self.validate_path_constraints(&path, c).is_ok() {
                                fallback_paths.push(path);
                            }
                        } else {
                            fallback_paths.push(path);
                        }
                    }
                }
            }
        }

        Ok(fallback_paths)
    }

    /// Dry Run - 预检链路构建
    pub async fn dry_run(
        &self,
        source: &NodeId,
        target: &NodeId,
        constraints: Option<ChainConstraints>,
    ) -> Result<ChainDryRunResult> {
        let start_time = Instant::now();

        // 执行构建但不实际创建会话
        let build_result = self.build_chain(source, target, constraints).await;

        let validation_duration = start_time.elapsed();

        match build_result {
            Ok(result) => {
                // 计算路径质量评分
                let quality_score = result.chain_context.calculate_quality_score();

                Ok(ChainDryRunResult {
                    success: true,
                    primary_path: Some(result.primary_path),
                    fallback_paths: result.fallback_paths,
                    quality_score,
                    estimated_latency_ms: self.estimate_path_latency(&result.chain_context),
                    estimated_bandwidth_mbps: self.estimate_path_bandwidth(&result.chain_context),
                    validation_duration,
                    warnings: Vec::new(),
                    error: None,
                })
            }
            Err(e) => Ok(ChainDryRunResult {
                success: false,
                primary_path: None,
                fallback_paths: Vec::new(),
                quality_score: 0.0,
                estimated_latency_ms: 0,
                estimated_bandwidth_mbps: 0,
                validation_duration,
                warnings: Vec::new(),
                error: Some(e.to_string()),
            }),
        }
    }

    /// 估算路径延迟
    fn estimate_path_latency(&self, chain_context: &ChainContext) -> u32 {
        // 基于跳数估算延迟
        let base_latency_per_hop = 30u32; // 每跳基础延迟 30ms
        (chain_context.hop_count as u32) * base_latency_per_hop
    }

    /// 估算路径带宽
    fn estimate_path_bandwidth(&self, chain_context: &ChainContext) -> u32 {
        // 带宽受限于最慢的链路
        if chain_context.hop_bandwidths.is_empty() {
            100 // 默认 100Mbps
        } else {
            *chain_context.hop_bandwidths.iter().min().unwrap_or(&100)
        }
    }
}

/// 链路约束条件
#[derive(Debug, Clone, Default)]
pub struct ChainConstraints {
    /// 最大跳数
    pub max_hops: Option<usize>,
    /// 最大延迟 (ms)
    pub max_latency_ms: Option<u32>,
    /// 最小带宽 (Mbps)
    pub min_bandwidth_mbps: Option<u32>,
    /// 必经节点列表
    pub required_nodes: Vec<NodeId>,
    /// 禁止节点列表
    pub forbidden_nodes: Vec<NodeId>,
    /// 必须经过的国家
    pub required_countries: Vec<String>,
    /// 禁止经过的国家
    pub forbidden_countries: Vec<String>,
}

/// 链路权重
#[derive(Debug, Clone)]
pub struct LinkWeight {
    /// 综合成本（用于路径优化）
    pub cost: f32,
    /// 延迟 (ms)
    pub latency: u32,
    /// 带宽 (Mbps)
    pub bandwidth: u32,
    /// 可靠性评分 (0.0-1.0)
    pub reliability: f32,
}

/// 链路构建结果
#[derive(Debug)]
pub struct ChainBuildResult {
    /// 链路ID
    pub chain_id: String,
    /// 主路径
    pub primary_path: Vec<NodeId>,
    /// 备用路径列表
    pub fallback_paths: Vec<Vec<NodeId>>,
    /// 链路上下文
    pub chain_context: ChainContext,
    /// 构建耗时
    pub build_duration: Duration,
}

/// Dry Run 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDryRunResult {
    /// 是否成功
    pub success: bool,
    /// 主路径
    pub primary_path: Option<Vec<NodeId>>,
    /// 备用路径列表
    pub fallback_paths: Vec<Vec<NodeId>>,
    /// 路径质量评分
    pub quality_score: f32,
    /// 估算延迟
    pub estimated_latency_ms: u32,
    /// 估算带宽
    pub estimated_bandwidth_mbps: u32,
    /// 验证耗时
    #[serde(skip)]
    pub validation_duration: Duration,
    /// 警告信息
    pub warnings: Vec<String>,
    /// 错误信息
    pub error: Option<String>,
}

/// 链路变更原因（P2-1 §2 D-3 枚举化；自由文本降为 [`SwitchEvent::detail`]）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    /// 流错误触发切换到备用路径
    FailureReported,
    /// 备用路径耗尽，链路终止
    FallbackExhausted,
    /// 健康巡检：TTL 到期终止
    TtlExpired,
    /// 健康巡检：链路已处终止态清理
    TerminatedUnhealthy,
    /// SLO 劣化触发切换（slo-scoring.md §2 D-5；P2-2）
    SloDegraded,
}

impl SwitchReason {
    /// 全部原因值（控制面 `rillane_mesh_switch_total{reason}` 恒渲染零值用）
    pub const ALL: [SwitchReason; 5] = [
        SwitchReason::FailureReported,
        SwitchReason::FallbackExhausted,
        SwitchReason::TtlExpired,
        SwitchReason::TerminatedUnhealthy,
        SwitchReason::SloDegraded,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            SwitchReason::FailureReported => "failure_reported",
            SwitchReason::FallbackExhausted => "fallback_exhausted",
            SwitchReason::TtlExpired => "ttl_expired",
            SwitchReason::TerminatedUnhealthy => "terminated_unhealthy",
            SwitchReason::SloDegraded => "slo_degraded",
        }
    }
}

/// 链路变更事件（P2-1 §3.2）：账本 cap 100 最新保留
#[derive(Debug, Clone, Serialize)]
pub struct SwitchEvent {
    pub chain_id: String,
    /// 切换前路径（终止事件 = 终止时路径）
    pub from_path: Vec<String>,
    /// 切换后路径（终止事件 = None）
    pub to_path: Option<Vec<String>>,
    /// [`SwitchReason::as_str()`]
    pub reason: String,
    /// 自由文本细节（原 failure_reason 透传等）
    pub detail: String,
    pub epoch_seconds: u64,
}

/// 切换账本容量（P2-1 §2 D-3）
pub const SWITCH_LEDGER_CAP: usize = 100;

/// 链路管理器
///
/// 管理活跃链路的生命周期、故障转移和统计
pub struct ChainManager {
    config: ChainConfig,
    builder: Arc<ChainBuilder>,
    mesh_registry: Arc<MeshRegistry>,
    /// 活跃链路映射 (chain_id -> ChainContext)
    active_chains: DashMap<String, ChainContext>,
    /// 会话到链路的映射 (session_id -> chain_id)
    session_chain_map: DashMap<SessionId, String>,
    /// 链路统计
    stats: RwLock<ChainManagerStats>,
    /// 切换原因账本（P2-1 §3.2，cap 100 最新保留）
    switch_ledger: Mutex<VecDeque<SwitchEvent>>,
    /// 按原因计数（/metrics rillane_mesh_switch_total{reason} 数据源）
    switch_counters: Mutex<BTreeMap<&'static str, u64>>,
}

impl ChainManager {
    /// 创建新的链路管理器
    pub fn new(
        config: ChainConfig,
        builder: Arc<ChainBuilder>,
        mesh_registry: Arc<MeshRegistry>,
    ) -> Self {
        Self {
            config,
            builder,
            mesh_registry,
            active_chains: DashMap::new(),
            session_chain_map: DashMap::new(),
            stats: RwLock::new(ChainManagerStats::default()),
            switch_ledger: Mutex::new(VecDeque::new()),
            switch_counters: Mutex::new(BTreeMap::new()),
        }
    }

    /// 为会话创建或获取链路
    pub async fn get_or_create_chain(
        &self,
        session_id: SessionId,
        source: &NodeId,
        target: &NodeId,
        constraints: Option<ChainConstraints>,
    ) -> Result<ChainContext> {
        // 检查是否已有链路
        if let Some(chain_id) = self.session_chain_map.get(&session_id) {
            if let Some(chain) = self.active_chains.get(chain_id.value()) {
                // 检查链路是否仍然有效
                if chain.status != ChainStatus::Terminated {
                    return Ok(chain.clone());
                }
            }
        }

        // 构建新链路
        let build_result = self
            .builder
            .build_chain(source, target, constraints)
            .await?;

        // 注册链路
        self.active_chains.insert(
            build_result.chain_id.clone(),
            build_result.chain_context.clone(),
        );
        self.session_chain_map
            .insert(session_id, build_result.chain_id.clone());

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.total_chains_created += 1;
            stats.active_chains = self.active_chains.len();
        }

        Ok(build_result.chain_context)
    }

    /// 处理链路故障（`reason` = 触发因：流错误 FailureReported / SLO 劣化
    /// SloDegraded——P2-2 §2 D-5；备用耗尽终态恒记 FallbackExhausted）
    pub async fn handle_chain_failure(
        &self,
        chain_id: &str,
        failure_reason: &str,
        reason: SwitchReason,
    ) -> Result<Option<ChainContext>> {
        let mut chain = self
            .active_chains
            .get_mut(chain_id)
            .ok_or_else(|| anyhow!("链路 {} 不存在", chain_id))?;

        warn!(
            target: "rillane::chain",
            chain_id = %chain_id,
            reason = %failure_reason,
            "链路故障"
        );

        // P2-1：切换前取当前路径（账本 from_path 口径）
        let path_before = chain.get_current_path().unwrap_or_default();

        // 尝试切换到备用路径
        if chain.switch_fallback_path() {
            // 快照返回值并在释放分片守卫后再做账本/统计操作：RefMut 跨
            // stats.write().await 会与 get_or_create_chain 的 stats→len() 锁序
            // 成环（分片写→stats vs stats→分片读），先释放守卫再统计。
            let current_path = chain.get_current_path();
            let fallback_index = chain.current_fallback_index;
            let switched = chain.clone();
            drop(chain);

            self.record_switch(chain_id, path_before, current_path, reason, failure_reason);
            info!(
                target: "rillane::chain",
                chain_id = %chain_id,
                fallback_index = fallback_index,
                "切换到备用路径"
            );

            // 更新统计
            {
                let mut stats = self.stats.write().await;
                stats.failover_count += 1;
                stats.last_failover_epoch_seconds = Some(current_epoch_seconds());
            }

            Ok(Some(switched))
        } else {
            // 没有更多备用路径
            self.record_switch(
                chain_id,
                path_before,
                None,
                SwitchReason::FallbackExhausted,
                failure_reason,
            );
            chain.status = ChainStatus::Terminated;

            // 存量缺陷修缮（P2-1 账本测试首度覆盖本路径时暴露）：RefMut 尚持
            // 有时调 active_chains.len()——DashMap len() 对全部分片取读锁，
            // 与本线程已持有的分片写锁互斥即自锁。先释放分片守卫再更新统计。
            drop(chain);

            // 更新统计
            {
                let mut stats = self.stats.write().await;
                stats.failed_chains += 1;
                // 并发 terminate_chain 可能已在此窗口移除本链（len 已自减），
                // `len() - 1` 在 len==0 时下溢裹成 usize::MAX 污染指标；
                // saturating_sub 防裹（若已移除则 len 本身已正确，不再二次自减）。
                stats.active_chains = self.active_chains.len().saturating_sub(1);
            }

            Ok(None)
        }
    }

    /// 终止链路
    pub async fn terminate_chain(&self, chain_id: &str) -> Result<()> {
        if let Some(mut chain) = self.active_chains.get_mut(chain_id) {
            chain.status = ChainStatus::Terminated;
        }

        // 移除会话映射
        self.session_chain_map.retain(|_, v| v.as_str() != chain_id);

        // 从活跃链路中移除
        self.active_chains.remove(chain_id);

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.active_chains = self.active_chains.len();
        }

        info!(target: "rillane::chain", chain_id = %chain_id, "链路已终止");
        Ok(())
    }

    /// 获取链路上下文
    pub fn get_chain(&self, chain_id: &str) -> Option<ChainContext> {
        self.active_chains.get(chain_id).map(|c| c.clone())
    }

    /// 获取会话的链路
    pub fn get_chain_for_session(&self, session_id: &SessionId) -> Option<ChainContext> {
        self.session_chain_map
            .get(session_id)
            .and_then(|chain_id| self.active_chains.get(chain_id.value()).map(|c| c.clone()))
    }

    /// 构建路由决策
    pub fn build_route_decision(&self, chain_context: &ChainContext) -> RouteDecision {
        let path = chain_context.get_current_path().unwrap_or_default();

        let hops: Vec<RouteHop> = path
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let hop_type = if i == 0 {
                    HopType::Ingress
                } else if i == path.len() - 1 {
                    HopType::Egress
                } else {
                    HopType::Relay
                };
                RouteHop {
                    node: node.clone(),
                    hop_type,
                }
            })
            .collect();

        let mut decision = RouteDecision::chain(hops);
        decision.route_type = RouteType::Collaborative;
        decision.reason = Some(format!(
            "多跳链路 {} ({}跳)",
            chain_context.chain_id,
            path.len()
        ));

        decision
    }

    /// 启动健康检查任务
    pub async fn start_health_check_task(self: Arc<Self>) {
        let interval = self.config.health_check_interval;
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;
            self.check_chains_health().await;
        }
    }

    /// 启动 SLO 劣化 watcher（slo-scoring.md §2 D-5）：仅
    /// `config.slo_watch` 配置时有实义，未配置直接返回（spawn 侧零判）。
    pub async fn start_slo_watch_task(self: Arc<Self>) {
        let Some(watch) = self.config.slo_watch.clone() else {
            return;
        };
        let mut ticker = tokio::time::interval(Duration::from_secs(watch.interval_secs.max(1)));

        loop {
            ticker.tick().await;
            self.slo_watch_sweep(&watch).await;
        }
    }

    /// 单轮 SLO 劣化评估（§4 接线点）：各活跃链路当前路径末跳质量越门 →
    /// `handle_chain_failure`（SloDegraded）；切换/终止由其按 fallback 余量
    /// 分记。快照先行——RefMut 不跨 await（P2-1 死锁修缮同律）。
    async fn slo_watch_sweep(&self, watch: &SloWatch) {
        let active: Vec<(String, Vec<String>)> = self
            .active_chains
            .iter()
            .map(|c| {
                (
                    c.key().clone(),
                    c.value().get_current_path().unwrap_or_default(),
                )
            })
            .collect();

        for (chain_id, path) in active {
            if path.len() < 2 {
                continue;
            }
            let (from, to) = (&path[path.len() - 2], &path[path.len() - 1]);
            // 无该链路观测数据 → 跳过（§6 E3：unknown 不触发误切）
            let Some((p95, loss)) = link_quality_between(&self.mesh_registry, from, to) else {
                continue;
            };
            if p95 <= watch.p95_ms && loss <= watch.loss_ratio {
                continue;
            }
            let detail = format!(
                "slo degraded: p95={p95}ms loss={loss:.3} (门 p95={}ms loss={:.3})",
                watch.p95_ms, watch.loss_ratio
            );
            warn!(
                target: "rillane::chain",
                chain_id = %chain_id,
                detail = %detail,
                "SLO 劣化触发切换"
            );
            // 链路竞态消失等错误忽略（§6 E3：巡检快照外的 chain_id 即略）
            let _ = self
                .handle_chain_failure(&chain_id, &detail, SwitchReason::SloDegraded)
                .await;
        }
    }

    /// 检查所有链路健康状态
    async fn check_chains_health(&self) {
        // (chain_id, 终止原因, 终止时路径)——P2-1 §4：终止按因留痕
        let mut chains_to_terminate: Vec<(String, SwitchReason)> = Vec::new();

        for entry in self.active_chains.iter() {
            let chain = entry.value();

            // 检查链路状态（先于 TTL：已终止链的死因归其自身状态，TTL 只
            // 解释仍存活链的过期——ZERO TTL 巡检时二者同时成立，顺序即归因）
            if chain.status == ChainStatus::Terminated {
                chains_to_terminate.push((entry.key().clone(), SwitchReason::TerminatedUnhealthy));
                continue;
            }

            // 检查链路是否过期
            if chain.created_at.elapsed() > self.config.chain_ttl {
                chains_to_terminate.push((entry.key().clone(), SwitchReason::TtlExpired));
            }
        }

        // 终止过期链路
        for (chain_id, cause) in chains_to_terminate {
            let from_path = self
                .active_chains
                .get(&chain_id)
                .and_then(|c| c.get_current_path())
                .unwrap_or_default();
            self.record_switch(&chain_id, from_path, None, cause, "健康巡检终止");
            if let Err(e) = self.terminate_chain(&chain_id).await {
                warn!(
                    target: "rillane::chain",
                    chain_id = %chain_id,
                    error = %e,
                    "终止链路失败"
                );
            }
        }

        debug!(
            target: "rillane::chain",
            active_chains = self.active_chains.len(),
            "健康检查完成"
        );
    }

    /// 记录链路变更事件（P2-1 §3.2：账本尾进头出 cap 100 + 按原因计数）
    fn record_switch(
        &self,
        chain_id: &str,
        from_path: Vec<String>,
        to_path: Option<Vec<String>>,
        reason: SwitchReason,
        detail: &str,
    ) {
        let event = SwitchEvent {
            chain_id: chain_id.to_string(),
            from_path,
            to_path,
            reason: reason.as_str().to_string(),
            detail: detail.to_string(),
            epoch_seconds: current_epoch_seconds(),
        };
        let mut ledger = self.switch_ledger.lock().expect("switch ledger poisoned");
        if ledger.len() == SWITCH_LEDGER_CAP {
            ledger.pop_front();
        }
        ledger.push_back(event);
        *self
            .switch_counters
            .lock()
            .expect("switch counters poisoned")
            .entry(reason.as_str())
            .or_insert(0) += 1;
    }

    /// 最近 N 条变更事件（时间升序；n=0 → 空）
    pub fn get_recent_switches(&self, n: usize) -> Vec<SwitchEvent> {
        let ledger = self.switch_ledger.lock().expect("switch ledger poisoned");
        ledger.iter().rev().take(n).rev().cloned().collect()
    }

    /// 按原因计数快照（/metrics 数据源）
    pub fn switch_counters_snapshot(&self) -> BTreeMap<String, u64> {
        self.switch_counters
            .lock()
            .expect("switch counters poisoned")
            .iter()
            .map(|(k, v)| ((*k).to_string(), *v))
            .collect()
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ChainManagerStats {
        self.stats.read().await.clone()
    }

    /// 获取 Mesh 注册表引用
    pub fn mesh_registry(&self) -> &Arc<MeshRegistry> {
        &self.mesh_registry
    }
}

/// 链路管理器统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainManagerStats {
    /// 总共创建的链路数
    pub total_chains_created: u64,
    /// 当前活跃链路数
    pub active_chains: usize,
    /// 故障转移次数
    pub failover_count: u64,
    /// 失败的链路数
    pub failed_chains: u64,
    /// 平均链路跳数
    pub average_hop_count: f32,
    /// 平均链路存活时间 (秒)
    pub average_chain_lifetime_seconds: f32,
    /// 最近一次故障转移时间（Unix epoch seconds）
    pub last_failover_epoch_seconds: Option<u64>,
}

/// 末跳质量点查（slo-scoring.md §2 D-5 数据面）：双向匹配（上报方向与路径
/// 方向可能相反）；p95 取 RTT 环、loss 取 errors/connections（分母 0 视 0
/// ——无观测即无罚分）。无 RTT 样本 → None（watcher 跳过，§6 E3）。
fn link_quality_between(registry: &MeshRegistry, from: &str, to: &str) -> Option<(u32, f64)> {
    let p95 = registry
        .get_all_link_rtt()
        .into_iter()
        .find(|r| (r.from == from && r.to == to) || (r.from == to && r.to == from))
        .map(|r| r.p95_ms)?;
    let (conns, errs) = registry
        .get_all_link_traffic()
        .into_iter()
        .find(|t| (t.from == from && t.to == to) || (t.from == to && t.to == from))
        .map(|t| (t.connections_total, t.errors_total))
        .unwrap_or((0, 0));
    let loss = if conns > 0 {
        errs as f64 / conns as f64
    } else {
        0.0
    };
    Some((p95, loss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_config_default() {
        let config = ChainConfig::default();
        assert_eq!(config.max_hops, 5);
        assert!(config.enable_failover);
        assert_eq!(config.fallback_path_count, 2);
    }

    #[test]
    fn test_link_weight() {
        let weight = LinkWeight {
            cost: 1.5,
            latency: 50,
            bandwidth: 100,
            reliability: 0.95,
        };
        assert!(weight.cost > 0.0);
    }

    /// 直构 ChainManager（builder 不参与：active_chains 私有字段同模块
    /// 测试可直插，路径切换语义不依赖真实拓扑）
    fn ledger_manager() -> ChainManager {
        let registry = Arc::new(MeshRegistry::new());
        let builder = Arc::new(ChainBuilder::new(ChainConfig::default(), registry.clone()));
        ChainManager::new(ChainConfig::default(), builder, registry)
    }

    /// 带两条备用路径的链直插 active_chains
    fn insert_chain(mgr: &ChainManager, chain_id: &str) {
        let mut ctx = ChainContext::new(chain_id.to_string(), "c1".into(), "exit1".into());
        ctx.update_path(vec!["c1".into(), "relay1".into(), "exit1".into()]);
        ctx.add_fallback_path(vec!["c1".into(), "relay2".into(), "exit1".into()]);
        ctx.add_fallback_path(vec!["c1".into(), "relay3".into(), "exit1".into()]);
        mgr.active_chains.insert(chain_id.to_string(), ctx);
    }

    /// P2-1 §7-3：handle_chain_failure 两分支事件形——切换成功 =
    /// FailureReported{from=切换前路径,to=新 fallback, detail 透传}；
    /// 备用耗尽 = FallbackExhausted{to=None}；计数器同步聚合。
    #[tokio::test]
    async fn switch_ledger_records_failure_and_exhaustion() {
        let mgr = ledger_manager();
        insert_chain(&mgr, "ch1");

        // 首次故障：切换到 fallback[0]
        let out = mgr
            .handle_chain_failure("ch1", "upstream reset", SwitchReason::FailureReported)
            .await
            .unwrap();
        assert!(out.is_some(), "仍有备用路径应切换成功");
        let events = mgr.get_recent_switches(10);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.chain_id, "ch1");
        assert_eq!(ev.reason, "failure_reported");
        assert_eq!(
            ev.from_path,
            vec!["c1".to_string(), "relay1".to_string(), "exit1".to_string()]
        );
        assert_eq!(
            ev.to_path,
            Some(vec![
                "c1".to_string(),
                "relay2".to_string(),
                "exit1".to_string()
            ])
        );
        assert_eq!(ev.detail, "upstream reset", "自由文本降 detail 透传");

        // 连续两故障耗尽两条备用：第二次切换 + 第三次 FallbackExhausted
        let out = mgr
            .handle_chain_failure("ch1", "timeout", SwitchReason::FailureReported)
            .await
            .unwrap();
        assert!(out.is_some());
        let out = mgr
            .handle_chain_failure("ch1", "timeout again", SwitchReason::FailureReported)
            .await
            .unwrap();
        assert!(out.is_none(), "备用耗尽返回 None");
        let events = mgr.get_recent_switches(10);
        assert_eq!(events.len(), 3);
        let last = events.last().unwrap();
        assert_eq!(last.reason, "fallback_exhausted");
        assert_eq!(last.to_path, None);
        assert_eq!(last.detail, "timeout again");

        let counters = mgr.switch_counters_snapshot();
        assert_eq!(counters.get("failure_reported"), Some(&2));
        assert_eq!(counters.get("fallback_exhausted"), Some(&1));
    }

    /// P2-1 §7-3：账本 cap 环绕（最新保留）+ get_recent_switches(n) 截取
    #[tokio::test]
    async fn switch_ledger_cap_ring_and_tail() {
        let mgr = ledger_manager();
        // 无备用路径 → 每次故障都是 FallbackExhausted 事件（免切换路径纯计数）
        for i in 0..(SWITCH_LEDGER_CAP + 10) {
            let id = format!("ch-{i}");
            let mut ctx = ChainContext::new(id.clone(), "c1".into(), "exit1".into());
            ctx.update_path(vec!["c1".into(), "exit1".into()]);
            mgr.active_chains.insert(id.clone(), ctx);
            mgr.handle_chain_failure(&id, "e", SwitchReason::FailureReported)
                .await
                .unwrap();
        }
        let ledger = mgr.get_recent_switches(usize::MAX);
        assert_eq!(ledger.len(), SWITCH_LEDGER_CAP, "cap 100 最新保留");
        assert_eq!(ledger.last().unwrap().chain_id, "ch-109", "最新在尾");
        assert_eq!(ledger.first().unwrap().chain_id, "ch-10", "最旧被逐出");
        assert_eq!(mgr.get_recent_switches(3).len(), 3);
    }

    /// 并发故障上报 × 终止链路竞态下 active_chains 指标不得下溢裹 MAX。
    /// 旧代码 `handle_chain_failure` 备用耗尽分支在 drop 分片守卫后执行
    /// `len() - 1`：terminate_chain 在窗口内移除即 0-1 → usize::MAX。
    #[tokio::test]
    async fn concurrent_terminate_and_failure_no_active_chains_underflow() {
        let mgr = Arc::new(ledger_manager());
        for i in 0..64 {
            let id = format!("race-{i}");
            {
                let mut ctx = ChainContext::new(id.clone(), "c1".into(), "exit1".into());
                ctx.update_path(vec!["c1".into(), "exit1".into()]);
                mgr.active_chains.insert(id.clone(), ctx);
            }
            // 双臂同时开跑：一方走 FallbackExhausted（会 drop 分片后 len()-1），
            // 另一方走 terminate_chain（drop 后 remove）。旧代码长尾命中
            // 窗口时 active_chains 裹 usize::MAX。
            let a = tokio::spawn({
                let mgr = Arc::clone(&mgr);
                let id = id.clone();
                async move {
                    let _ = mgr
                        .handle_chain_failure(&id, "e", SwitchReason::FailureReported)
                        .await;
                }
            });
            let b = tokio::spawn({
                let mgr = Arc::clone(&mgr);
                let id = id.clone();
                async move {
                    let _ = mgr.terminate_chain(&id).await;
                }
            });
            let _ = tokio::join!(a, b);

            let stats = mgr.get_stats().await;
            assert!(
                stats.active_chains < 1000,
                "active_chains 不得下溢裹 usize::MAX，第 {i} 轮 got {}",
                stats.active_chains
            );
            // 清残余（若 failure 先入分片、terminate 晚到时表内可能留 Terminated 链）
            mgr.terminate_chain(&id).await.unwrap();
        }

        let stats = mgr.get_stats().await;
        assert_eq!(stats.active_chains, 0, "测试结束应为零");
    }

    /// P2-1 §7-3：健康巡检终止按因留痕——TTL 归零全量过期 =
    /// TtlExpired；状态本就 Terminated 的 = TerminatedUnhealthy。
    #[tokio::test]
    async fn switch_ledger_health_sweep_causes() {
        let registry = Arc::new(MeshRegistry::new());
        let builder = Arc::new(ChainBuilder::new(ChainConfig::default(), registry.clone()));
        let config = ChainConfig {
            chain_ttl: Duration::ZERO, // 全量过期
            ..ChainConfig::default()
        };
        let mgr = ChainManager::new(config, builder, registry);

        let mut ctx = ChainContext::new("ch-a".into(), "c1".into(), "exit1".into());
        ctx.update_path(vec!["c1".into(), "exit1".into()]);
        mgr.active_chains.insert("ch-a".into(), ctx);
        // ch-b 直插即 Terminated → TerminatedUnhealthy 分支
        let mut ctx_b = ChainContext::new("ch-b".into(), "c1".into(), "exit1".into());
        ctx_b.update_path(vec!["c1".into(), "exit1".into()]);
        ctx_b.status = ChainStatus::Terminated;
        mgr.active_chains.insert("ch-b".into(), ctx_b);

        mgr.check_chains_health().await;

        let counters = mgr.switch_counters_snapshot();
        assert_eq!(counters.get("ttl_expired"), Some(&1), "TTL 归零过期");
        assert_eq!(counters.get("terminated_unhealthy"), Some(&1), "终止态清理");
        let events = mgr.get_recent_switches(10);
        assert_eq!(events.len(), 2);
        assert!(
            events.iter().all(|e| e.to_path.is_none()),
            "终止事件 to=None"
        );
        assert_eq!(mgr.active_chains.len(), 0, "两链均被巡检终止移除");
    }

    /// P2-2 §7-4：SLO watcher——当前路径末跳质量越门 → SloDegraded 触发
    /// handle_chain_failure，账本事件 reason=slo_degraded 且 fallback 按声明
    /// 序提升；数据合规（§7-4a）与无观测数据（§7-4b）均不动作。
    #[tokio::test]
    async fn slo_watch_degradation_triggers_failover_and_ledger() {
        let registry = Arc::new(MeshRegistry::new());
        let builder = Arc::new(ChainBuilder::new(ChainConfig::default(), registry.clone()));
        let config = ChainConfig {
            slo_watch: Some(SloWatch {
                p95_ms: 100,
                loss_ratio: 0.1,
                interval_secs: 1,
            }),
            ..ChainConfig::default()
        };
        let mgr = ChainManager::new(config, builder, registry.clone());
        insert_chain(&mgr, "ch1");
        let watch = SloWatch {
            p95_ms: 100,
            loss_ratio: 0.1,
            interval_secs: 1,
        };

        // (b) 无观测数据：link_quality_between 为 None → sweep 不动作
        mgr.slo_watch_sweep(&watch).await;
        assert!(mgr.get_recent_switches(10).is_empty(), "无数据不触发误切");

        // (a) 合规数据：末跳 (relay1→exit1) p95=20 < 门 100 → 不动作
        registry
            .update_link_state(LinkState {
                source: "relay1".into(),
                target: "exit1".into(),
                latency_ms: 20,
                bandwidth_mbps: 100,
                packet_loss_rate: 0.0,
                last_updated: Instant::now(),
            })
            .unwrap();
        mgr.slo_watch_sweep(&watch).await;
        assert!(mgr.get_recent_switches(10).is_empty(), "合规不切换");

        // 越门：p95=300 > 100 → SloDegraded，fallback[0] (relay2) 按声明序提升
        registry
            .update_link_state(LinkState {
                source: "relay1".into(),
                target: "exit1".into(),
                latency_ms: 300,
                bandwidth_mbps: 100,
                packet_loss_rate: 0.0,
                last_updated: Instant::now(),
            })
            .unwrap();
        mgr.slo_watch_sweep(&watch).await;

        let events = mgr.get_recent_switches(10);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.reason, "slo_degraded");
        assert_eq!(ev.chain_id, "ch1");
        assert_eq!(
            ev.from_path,
            vec!["c1".to_string(), "relay1".to_string(), "exit1".to_string()]
        );
        assert_eq!(
            ev.to_path,
            Some(vec![
                "c1".to_string(),
                "relay2".to_string(),
                "exit1".to_string()
            ])
        );
        assert!(
            ev.detail.contains("p95=300ms"),
            "detail 携带实测值与门限：{}",
            ev.detail
        );
        assert_eq!(mgr.switch_counters_snapshot().get("slo_degraded"), Some(&1));
        let ctx = mgr.active_chains.get("ch1").unwrap();
        assert_eq!(
            ctx.get_current_path().unwrap(),
            vec!["c1".to_string(), "relay2".to_string(), "exit1".to_string()],
            "fallback 提升后 current_path 单源更新"
        );
    }
}
