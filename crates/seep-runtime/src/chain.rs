//! 多跳链路构建与管理
//!
//! 支持 source → relay → exit 多跳链路的构建、优化和故障转移。

use std::{
    collections::HashMap,
    sync::Arc,
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

use seep_core::{ChainContext, ChainStatus, HopType, RouteDecision, RouteHop, RouteType};
use seep_mesh::{LinkState, MeshRegistry, NodeId, NodeRecord, NodeRole, SessionId};

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
        }
    }
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
            target: "seep::chain",
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

    /// 处理链路故障
    pub async fn handle_chain_failure(
        &self,
        chain_id: &str,
        failure_reason: &str,
    ) -> Result<Option<ChainContext>> {
        let mut chain = self
            .active_chains
            .get_mut(chain_id)
            .ok_or_else(|| anyhow!("链路 {} 不存在", chain_id))?;

        warn!(
            target: "seep::chain",
            chain_id = %chain_id,
            reason = %failure_reason,
            "链路故障"
        );

        // 尝试切换到备用路径
        if chain.switch_fallback_path() {
            info!(
                target: "seep::chain",
                chain_id = %chain_id,
                fallback_index = chain.current_fallback_index,
                "切换到备用路径"
            );

            // 更新统计
            {
                let mut stats = self.stats.write().await;
                stats.failover_count += 1;
            }

            Ok(Some(chain.clone()))
        } else {
            // 没有更多备用路径
            chain.status = ChainStatus::Terminated;

            // 更新统计
            {
                let mut stats = self.stats.write().await;
                stats.failed_chains += 1;
                stats.active_chains = self.active_chains.len() - 1;
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

        info!(target: "seep::chain", chain_id = %chain_id, "链路已终止");
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

    /// 检查所有链路健康状态
    async fn check_chains_health(&self) {
        let mut chains_to_terminate: Vec<String> = Vec::new();

        for entry in self.active_chains.iter() {
            let chain = entry.value();

            // 检查链路是否过期
            if chain.created_at.elapsed() > self.config.chain_ttl {
                chains_to_terminate.push(entry.key().clone());
                continue;
            }

            // 检查链路状态
            if chain.status == ChainStatus::Terminated {
                chains_to_terminate.push(entry.key().clone());
            }
        }

        // 终止过期链路
        for chain_id in chains_to_terminate {
            if let Err(e) = self.terminate_chain(&chain_id).await {
                warn!(
                    target: "seep::chain",
                    chain_id = %chain_id,
                    error = %e,
                    "终止链路失败"
                );
            }
        }

        debug!(
            target: "seep::chain",
            active_chains = self.active_chains.len(),
            "健康检查完成"
        );
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
}
