use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use petgraph::{Directed, Graph};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::interval;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub type NodeId = String;
pub type SessionId = Uuid;

/// 节点角色定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeRole {
    /// 客户端节点 - 只能发起连接
    Client,
    /// 中继节点 - 只转发流量，不处理流量内容
    Relay,
    /// 出口节点 - 处理并发起最终连接
    Exit,
    /// 混合节点 - 可同时作为中继和出口
    Hybrid,
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeRole::Client => write!(f, "client"),
            NodeRole::Relay => write!(f, "relay"),
            NodeRole::Exit => write!(f, "exit"),
            NodeRole::Hybrid => write!(f, "hybrid"),
        }
    }
}

/// 节点能力描述
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeCapability {
    /// 带宽容量 (Mbps)
    pub bandwidth_mbps: Option<u32>,
    /// 节点所在国家
    pub country: Option<String>,
    /// ISP 提供商
    pub isp: Option<String>,
    /// 标签
    pub tags: Vec<String>,
    /// 地理位置坐标
    pub location: Option<GeoLocation>,
    /// 最大并发连接数
    pub max_connections: Option<u32>,
    /// 支持的协议
    pub supported_protocols: Vec<String>,
    /// 硬件规格
    pub hardware_spec: Option<HardwareSpec>,
}

/// 地理位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub city: Option<String>,
    pub region: Option<String>,
}

/// 硬件规格
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSpec {
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub storage_gb: u32,
}

/// 节点配额限制
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeQuota {
    /// 每日带宽限制 (GB)
    pub daily_bandwidth_gb: Option<u32>,
    /// 每月带宽限制 (GB)
    pub monthly_bandwidth_gb: Option<u32>,
    /// 每分钟连接数限制
    pub connections_per_minute: Option<u32>,
    /// 同时连接数限制
    pub max_concurrent_connections: Option<u32>,
    /// 数据包大小限制
    pub max_packet_size: Option<usize>,
}

/// 节点 ACL 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeACL {
    /// 允许的客户端 CIDR 列表
    pub allowed_client_cidrs: Vec<String>,
    /// 禁止的客户端 CIDR 列表
    pub denied_client_cidrs: Vec<String>,
    /// 允许的目标域名模式
    pub allowed_target_domains: Vec<String>,
    /// 禁止的目标域名模式
    pub denied_target_domains: Vec<String>,
    /// 允许的目标端口范围
    pub allowed_target_ports: Vec<(u16, u16)>,
    /// 禁止的目标端口范围
    pub denied_target_ports: Vec<(u16, u16)>,
}

/// 链路状态信息
#[derive(Debug, Clone)]
pub struct LinkState {
    pub source: NodeId,
    pub target: NodeId,
    pub latency_ms: u32,
    pub bandwidth_mbps: u32,
    pub packet_loss_rate: f32,
    pub last_updated: Instant,
}

impl LinkState {
    pub fn new(source: NodeId, target: NodeId) -> Self {
        Self {
            source,
            target,
            latency_ms: 0,
            bandwidth_mbps: 0,
            packet_loss_rate: 0.0,
            last_updated: Instant::now(),
        }
    }
}

/// 节点记录
#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub id: NodeId,
    pub role: NodeRole,
    pub addr: SocketAddr,
    pub capability: NodeCapability,
    pub quota: NodeQuota,
    pub acl: NodeACL,
    pub last_seen: Instant,
    pub online: bool,
    pub health_score: f32,
    pub connection_count: u32,
    pub total_bytes_transferred: u64,
    pub registered_at: Instant,
}

impl NodeRecord {
    pub fn new(id: NodeId, role: NodeRole, addr: SocketAddr) -> Self {
        Self {
            id,
            role,
            addr,
            capability: NodeCapability::default(),
            quota: NodeQuota::default(),
            acl: NodeACL::default(),
            last_seen: Instant::now(),
            online: true,
            health_score: 1.0,
            connection_count: 0,
            total_bytes_transferred: 0,
            registered_at: Instant::now(),
        }
    }
}

impl Default for NodeQuota {
    fn default() -> Self {
        Self {
            daily_bandwidth_gb: None,
            monthly_bandwidth_gb: None,
            connections_per_minute: None,
            max_concurrent_connections: None,
            max_packet_size: None,
        }
    }
}

impl Default for NodeACL {
    fn default() -> Self {
        Self {
            allowed_client_cidrs: Vec::new(),
            denied_client_cidrs: Vec::new(),
            allowed_target_domains: Vec::new(),
            denied_target_domains: Vec::new(),
            allowed_target_ports: Vec::new(),
            denied_target_ports: Vec::new(),
        }
    }
}

/// 网络拓扑图类型
type MeshTopology = Graph<NodeId, LinkState, Directed>;

/// Mesh 注册表
#[derive(Default)]
pub struct MeshRegistry {
    /// 节点注册信息
    nodes: RwLock<HashMap<NodeId, NodeRecord>>,
    /// 活跃会话
    sessions: DashMap<SessionId, MeshSession>,
    /// 链路状态
    link_states: DashMap<(NodeId, NodeId), LinkState>,
    /// 网络拓扑
    topology: RwLock<MeshTopology>,
    /// 统计信息
    stats: RwLock<MeshStats>,
}

/// Mesh 会话信息
#[derive(Debug, Clone)]
pub struct MeshSession {
    pub id: SessionId,
    pub client_node: NodeId,
    pub path: Vec<NodeId>,
    pub target_addr: SocketAddr,
    pub created_at: Instant,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub status: SessionStatus,
}

/// 会话状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Idle,
    Terminated,
    Failed,
}

/// Mesh 网络统计
#[derive(Debug, Clone, Default)]
pub struct MeshStats {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub active_sessions: usize,
    pub total_bytes_transferred: u64,
    pub average_latency_ms: f32,
    pub packet_loss_rate: f32,
}

impl MeshRegistry {
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            sessions: DashMap::new(),
            link_states: DashMap::new(),
            topology: RwLock::new(Graph::new()),
            stats: RwLock::new(MeshStats::default()),
        }
    }

    /// 注册或更新节点
    pub fn register_node(&self, mut record: NodeRecord) -> Result<()> {
        // 验证节点配置
        self.validate_node_record(&record)?;

        record.last_seen = Instant::now();
        record.online = true;
        record.registered_at = Instant::now();

        let node_id = record.id.clone();
        self.nodes
            .write()
            .expect("mesh registry poisoned")
            .insert(node_id.clone(), record);

        // 更新拓扑
        self.update_topology(&node_id);

        info!(target: "seep::mesh", node = %node_id, "节点注册成功");
        Ok(())
    }

    /// 更新节点健康状态
    pub fn update_node_health(&self, node_id: &str, health_score: f32) -> Result<()> {
        let mut nodes = self.nodes.write().expect("mesh registry poisoned");
        if let Some(record) = nodes.get_mut(node_id) {
            record.health_score = health_score.clamp(0.0, 1.0);
            record.last_seen = Instant::now();
            Ok(())
        } else {
            Err(anyhow!("节点 {} 未注册", node_id))
        }
    }

    /// 更新链路状态
    pub fn update_link_state(&self, link_state: LinkState) -> Result<()> {
        let key = (link_state.source.clone(), link_state.target.clone());
        self.link_states.insert(key, link_state.clone());
        self.rebuild_topology();
        debug!(
            target: "seep::mesh",
            from = %link_state.source,
            to = %link_state.target,
            latency = link_state.latency_ms,
            "链路状态更新"
        );
        Ok(())
    }

    /// 获取链路状态
    pub fn get_link_state(&self, source: &NodeId, target: &NodeId) -> Option<LinkState> {
        self.link_states
            .get(&(source.clone(), target.clone()))
            .map(|v| v.clone())
    }

    /// 获取全部链路状态
    pub fn get_all_link_states(&self) -> Vec<LinkState> {
        self.link_states.iter().map(|e| e.value().clone()).collect()
    }

    /// 创建会话
    pub fn create_session(
        &self,
        client_node: NodeId,
        path: Vec<NodeId>,
        target_addr: SocketAddr,
    ) -> Result<SessionId> {
        // 验证路径有效性
        self.validate_path(&client_node, &path)?;

        let session_id = SessionId::new_v4();
        let session = MeshSession {
            id: session_id,
            client_node,
            path,
            target_addr,
            created_at: Instant::now(),
            bytes_up: 0,
            bytes_down: 0,
            status: SessionStatus::Active,
        };

        self.sessions.insert(session_id, session);
        self.update_stats();

        info!(target: "seep::mesh", session = %session_id, "会话创建成功");
        Ok(session_id)
    }

    /// 更新会话统计
    pub fn update_session_stats(
        &self,
        session_id: SessionId,
        bytes_up: u64,
        bytes_down: u64,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        match self.sessions.entry(session_id) {
            Entry::Occupied(mut entry) => {
                let session = entry.get_mut();
                session.bytes_up += bytes_up;
                session.bytes_down += bytes_down;
                session.status = SessionStatus::Active;
                Ok(())
            }
            Entry::Vacant(_) => Err(anyhow!("会话 {:?} 不存在", session_id)),
        }
    }

    /// 终止会话
    pub fn terminate_session(&self, session_id: SessionId) -> Result<()> {
        if self.sessions.remove(&session_id).is_some() {
            self.update_stats();
            info!(target: "seep::mesh", session = %session_id, "会话终止");
            Ok(())
        } else {
            Err(anyhow!("会话 {:?} 不存在", session_id))
        }
    }

    /// 获取在线节点列表
    pub fn get_online_nodes(&self) -> Vec<NodeRecord> {
        self.nodes
            .read()
            .expect("mesh registry poisoned")
            .values()
            .filter(|record| record.online)
            .cloned()
            .collect()
    }

    /// 获取节点监听地址
    pub fn get_node_addr(&self, node_id: &NodeId) -> Option<SocketAddr> {
        self.nodes
            .read()
            .expect("mesh registry poisoned")
            .get(node_id)
            .map(|r| r.addr)
    }

    /// 按角色获取节点
    pub fn get_nodes_by_role(&self, role: NodeRole) -> Vec<NodeRecord> {
        self.nodes
            .read()
            .expect("mesh registry poisoned")
            .values()
            .filter(|record| record.online && record.role == role)
            .cloned()
            .collect()
    }

    /// 查找最优路径（暂时简化实现）
    pub fn find_optimal_path(&self, _from: &NodeId, to: &NodeId) -> Result<Vec<NodeId>> {
        // 简化实现：直接返回目标节点
        // 在实际应用中应该使用 Dijkstra 算法
        Ok(vec![to.clone()])
    }

    /// 验证节点记录
    fn validate_node_record(&self, record: &NodeRecord) -> Result<()> {
        // 验证配额配置
        if let Some(daily) = record.quota.daily_bandwidth_gb {
            if daily == 0 {
                return Err(anyhow!("日带宽配额不能为0"));
            }
        }

        if let Some(max_conn) = record.quota.max_concurrent_connections {
            if max_conn == 0 {
                return Err(anyhow!("最大并发连接数不能为0"));
            }
        }

        // 验证 ACL 配置
        for cidr in &record.acl.allowed_client_cidrs {
            if !self.is_valid_cidr(cidr) {
                return Err(anyhow!("无效的 CIDR: {}", cidr));
            }
        }

        Ok(())
    }

    /// 验证 CIDR 格式
    fn is_valid_cidr(&self, cidr: &str) -> bool {
        // 简单的 CIDR 验证，实际应用中应使用更完整的验证
        cidr.contains('/') && cidr.split('.').count() >= 4
    }

    /// 验证路径有效性
    fn validate_path(&self, client_node: &NodeId, path: &[NodeId]) -> Result<()> {
        if path.is_empty() {
            return Err(anyhow!("路径不能为空"));
        }

        let nodes = self.nodes.read().expect("mesh registry poisoned");

        // 验证所有节点都存在且在线
        if !nodes.contains_key(client_node) {
            return Err(anyhow!("客户端节点 {} 不存在", client_node));
        }

        for node_id in path {
            if !nodes.contains_key(node_id) {
                return Err(anyhow!("节点 {} 不存在", node_id));
            }

            if !nodes[node_id].online {
                return Err(anyhow!("节点 {} 离线", node_id));
            }
        }

        Ok(())
    }

    /// 更新网络拓扑
    fn update_topology(&self, node_id: &NodeId) {
        let mut topology = self.topology.write().expect("mesh topology poisoned");

        // 添加节点到拓扑（如果不存在）
        if topology
            .node_indices()
            .find(|i| topology[*i] == *node_id)
            .is_none()
        {
            topology.add_node(node_id.clone());
        }
    }

    /// 重建网络拓扑
    fn rebuild_topology(&self) {
        let mut topology = self.topology.write().expect("mesh topology poisoned");
        *topology = Graph::new();

        // 重新添加所有节点
        let nodes = self.nodes.read().expect("mesh registry poisoned");
        let mut node_indices = HashMap::new();

        for (node_id, _) in nodes.iter().filter(|(_, record)| record.online) {
            let idx = topology.add_node(node_id.clone());
            node_indices.insert(node_id.clone(), idx);
        }

        // 添加所有链路
        for entry in self.link_states.iter() {
            let (source, target) = entry.key();
            let link_state = entry.value();

            if let (Some(&source_idx), Some(&target_idx)) =
                (node_indices.get(source), node_indices.get(target))
            {
                topology.add_edge(source_idx, target_idx, link_state.clone());
            }
        }
    }

    /// 更新统计信息
    fn update_stats(&self) {
        let nodes = self.nodes.read().expect("mesh registry poisoned");
        let online_count = nodes.values().filter(|r| r.online).count();
        let session_count = self.sessions.len();

        let mut stats = self.stats.write().expect("mesh stats poisoned");
        stats.total_nodes = nodes.len();
        stats.online_nodes = online_count;
        stats.active_sessions = session_count;

        // 计算平均延迟
        let links: Vec<LinkState> = self
            .link_states
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        if !links.is_empty() {
            stats.average_latency_ms =
                links.iter().map(|l| l.latency_ms as f32).sum::<f32>() / links.len() as f32;
            stats.packet_loss_rate =
                links.iter().map(|l| l.packet_loss_rate).sum::<f32>() / links.len() as f32;
        }
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> MeshStats {
        self.update_stats();
        self.stats.read().expect("mesh stats poisoned").clone()
    }
}

/// 节点快照结构
#[derive(Debug, Clone, Serialize)]
pub struct NodeRecordSnapshot {
    pub id: NodeId,
    pub role: NodeRole,
    pub addr: String,
    pub capability: NodeCapability,
    pub online: bool,
    pub last_seen_seconds: u64,
    pub health_score: f32,
    pub connection_count: u32,
    pub total_bytes_transferred: u64,
}

/// 会话快照结构
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub id: SessionId,
    pub client_node: NodeId,
    pub path: Vec<NodeId>,
    pub target_addr: String,
    pub created_at_seconds: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub status: String,
    pub duration_seconds: u64,
}

/// Mesh 错误类型
#[derive(Debug, Error)]
pub enum MeshError {
    #[error("节点 {0} 未注册")]
    NotFound(String),
    #[error("节点 {0} 不在线")]
    Offline(String),
    #[error("节点 {0} 配置无效: {1}")]
    InvalidConfig(String, String),
    #[error("路径 {0:?} 无效: {1}")]
    InvalidPath(Vec<NodeId>, String),
    #[error("会话 {0:?} 不存在")]
    SessionNotFound(SessionId),
    #[error("配额超限: {0}")]
    QuotaExceeded(String),
    #[error("ACL 拒绝访问: {0}")]
    AccessDenied(String),
}

impl MeshRegistry {
    /// 获取节点快照
    pub fn get_node_snapshot(&self, node_id: &NodeId) -> Option<NodeRecordSnapshot> {
        let nodes = self.nodes.read().expect("mesh registry poisoned");
        nodes.get(node_id).map(|record| NodeRecordSnapshot {
            id: record.id.clone(),
            role: record.role,
            addr: record.addr.to_string(),
            capability: record.capability.clone(),
            online: record.online,
            last_seen_seconds: record.last_seen.elapsed().as_secs(),
            health_score: record.health_score,
            connection_count: record.connection_count,
            total_bytes_transferred: record.total_bytes_transferred,
        })
    }

    /// 获取所有节点快照
    pub fn get_all_node_snapshots(&self) -> Vec<NodeRecordSnapshot> {
        let nodes = self.nodes.read().expect("mesh registry poisoned");
        nodes
            .values()
            .map(|record| NodeRecordSnapshot {
                id: record.id.clone(),
                role: record.role,
                addr: record.addr.to_string(),
                capability: record.capability.clone(),
                online: record.online,
                last_seen_seconds: record.last_seen.elapsed().as_secs(),
                health_score: record.health_score,
                connection_count: record.connection_count,
                total_bytes_transferred: record.total_bytes_transferred,
            })
            .collect()
    }

    /// 获取会话快照
    pub fn get_session_snapshot(&self, session_id: SessionId) -> Option<SessionSnapshot> {
        self.sessions
            .get(&session_id)
            .map(|session| SessionSnapshot {
                id: session.id,
                client_node: session.client_node.clone(),
                path: session.path.clone(),
                target_addr: session.target_addr.to_string(),
                created_at_seconds: session.created_at.elapsed().as_secs(),
                bytes_up: session.bytes_up,
                bytes_down: session.bytes_down,
                status: format!("{:?}", session.status),
                duration_seconds: session.created_at.elapsed().as_secs(),
            })
    }

    /// 获取所有会话快照
    pub fn get_all_session_snapshots(&self) -> Vec<SessionSnapshot> {
        self.sessions
            .iter()
            .map(|entry| {
                let session = entry.value();
                SessionSnapshot {
                    id: session.id,
                    client_node: session.client_node.clone(),
                    path: session.path.clone(),
                    target_addr: session.target_addr.to_string(),
                    created_at_seconds: session.created_at.elapsed().as_secs(),
                    bytes_up: session.bytes_up,
                    bytes_down: session.bytes_down,
                    status: format!("{:?}", session.status),
                    duration_seconds: session.created_at.elapsed().as_secs(),
                }
            })
            .collect()
    }

    /// 标记节点为离线
    pub fn mark_node_offline(&self, node_id: &NodeId) -> Result<()> {
        let mut nodes = self.nodes.write().expect("mesh registry poisoned");
        if let Some(record) = nodes.get_mut(node_id) {
            record.online = false;
            self.rebuild_topology();
            info!(target: "seep::mesh", node = %node_id, "节点标记为离线");
            Ok(())
        } else {
            Err(MeshError::NotFound(node_id.clone()).into())
        }
    }

    /// 检查配额限制
    pub fn check_quota(&self, node_id: &NodeId, additional_bytes: u64) -> Result<()> {
        let nodes = self.nodes.read().expect("mesh registry poisoned");
        if let Some(record) = nodes.get(node_id) {
            // 检查日配额
            if let Some(daily_gb) = record.quota.daily_bandwidth_gb {
                let daily_bytes = daily_gb as u64 * 1024 * 1024 * 1024;
                if record.total_bytes_transferred + additional_bytes > daily_bytes {
                    return Err(
                        MeshError::QuotaExceeded(format!("日配额超限: {}GB", daily_gb)).into(),
                    );
                }
            }

            // 检查月配额
            if let Some(monthly_gb) = record.quota.monthly_bandwidth_gb {
                let monthly_bytes = monthly_gb as u64 * 1024 * 1024 * 1024;
                if record.total_bytes_transferred + additional_bytes > monthly_bytes {
                    return Err(
                        MeshError::QuotaExceeded(format!("月配额超限: {}GB", monthly_gb)).into(),
                    );
                }
            }

            // 检查并发连接数
            if let Some(max_connections) = record.quota.max_concurrent_connections {
                let current_connections = self
                    .sessions
                    .iter()
                    .filter(|entry| entry.value().client_node == *node_id)
                    .count();
                if current_connections >= max_connections as usize {
                    return Err(MeshError::QuotaExceeded(format!(
                        "并发连接数超限: {}",
                        max_connections
                    ))
                    .into());
                }
            }

            Ok(())
        } else {
            Err(MeshError::NotFound(node_id.clone()).into())
        }
    }

    /// 检查 ACL 规则
    pub fn check_acl(&self, client_node: &NodeId, target_addr: &SocketAddr) -> Result<()> {
        let nodes = self.nodes.read().expect("mesh registry poisoned");
        if let Some(record) = nodes.get(client_node) {
            let acl = &record.acl;

            // 这里应该实现完整的 ACL 检查逻辑
            // 为简化示例，暂时只检查基本规则

            // 检查目标端口
            let target_port = target_addr.port();
            for (start, end) in &acl.denied_target_ports {
                if target_port >= *start && target_port <= *end {
                    return Err(
                        MeshError::AccessDenied(format!("端口 {} 被禁止", target_port)).into(),
                    );
                }
            }

            if !acl.allowed_target_ports.is_empty() {
                let allowed = acl
                    .allowed_target_ports
                    .iter()
                    .any(|(start, end)| target_port >= *start && target_port <= *end);
                if !allowed {
                    return Err(
                        MeshError::AccessDenied(format!("端口 {} 未被允许", target_port)).into(),
                    );
                }
            }

            Ok(())
        } else {
            Err(MeshError::NotFound(client_node.clone()).into())
        }
    }
}

/// 启动健康检查器
pub async fn spawn_health_checker(registry: Arc<MeshRegistry>, ttl: Duration) {
    let mut ticker = interval(ttl / 4); // 更频繁的检查
    loop {
        ticker.tick().await;

        let stale_ids: Vec<NodeId> = {
            let nodes = registry.nodes.read().expect("mesh registry poisoned");
            nodes
                .iter()
                .filter(|(_, record)| record.online && record.last_seen.elapsed() >= ttl)
                .map(|(id, _)| id.clone())
                .collect()
        };

        if !stale_ids.is_empty() {
            warn!(target: "seep::mesh", stale = ?stale_ids, "节点超时，标记为离线");

            // 标记为离线并重建拓扑
            {
                let mut nodes = registry.nodes.write().expect("mesh registry poisoned");
                for id in &stale_ids {
                    if let Some(record) = nodes.get_mut(id) {
                        record.online = false;
                    }
                }
            }

            registry.rebuild_topology();
        }
    }
}

/// 启动拓扑更新器
pub async fn spawn_topology_updater(registry: Arc<MeshRegistry>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        registry.update_stats();
        debug!(target: "seep::mesh", "拓扑统计信息已更新");
    }
}
