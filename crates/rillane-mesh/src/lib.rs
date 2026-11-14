use std::{
    collections::{HashMap, VecDeque},
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

/// per-link RTT 样本环容量（P2-1 §3.1：尾进尾出，覆盖最旧）
pub const RTT_RING_CAP: usize = 256;

/// per-link RTT 样本环（P2-1 §3.1）：分位数快照时就地排序取最近秩
/// （256 样本开销可忽略，不引直方图桶配置）；环空返回 None（E3：无样本
/// 链路不渲染序列——画 0ms 是误导）。
#[derive(Debug, Default)]
pub struct RttRing {
    samples: VecDeque<u32>,
}

impl RttRing {
    pub fn record(&mut self, rtt_ms: u32) {
        if self.samples.len() == RTT_RING_CAP {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt_ms);
    }

    /// 最近秩分位：排序副本后 `idx = ceil(p * n) - 1`（p∈(0,1]）
    pub fn quantile(&self, p: f64) -> Option<u32> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<u32> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        let n = sorted.len();
        let idx = ((p * n as f64).ceil() as usize).clamp(1, n) - 1;
        sorted.get(idx).copied()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

/// 链路 RTT 分位快照（P2-1 §5 控制面数据源）
#[derive(Debug, Clone, Serialize)]
pub struct LinkRttSnapshot {
    pub from: NodeId,
    pub to: NodeId,
    pub p50_ms: u32,
    pub p95_ms: u32,
    pub samples: usize,
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
    /// 链路流量统计（按方向）
    link_traffic: DashMap<(NodeId, NodeId), LinkTrafficStats>,
    /// per-link RTT 样本环（P2-1 D-1）
    link_rtt: DashMap<(NodeId, NodeId), RttRing>,
    /// 网络拓扑
    topology: RwLock<MeshTopology>,
    /// 统计信息
    stats: RwLock<MeshStats>,
}

/// 链路流量统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinkTrafficStats {
    pub bytes_total: u64,
    pub connections_total: u64,
    pub errors_total: u64,
    /// 最后更新时间（Unix epoch seconds）
    pub last_updated_epoch_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkTrafficSnapshot {
    pub from: NodeId,
    pub to: NodeId,
    pub bytes_total: u64,
    pub connections_total: u64,
    pub errors_total: u64,
    pub age_seconds: u64,
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
            link_traffic: DashMap::new(),
            link_rtt: DashMap::new(),
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

        info!(target: "rillane::mesh", node = %node_id, "节点注册成功");
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
        // P2-1 D-1 采样源：上报值即样本（0 值 = 上报方未测，不入环避免
        // 拉偏分位数；真 RTT 待探测源 O-link-obs1）
        if link_state.latency_ms > 0 {
            self.link_rtt
                .entry(key.clone())
                .or_default()
                .record(link_state.latency_ms);
        }
        self.link_states.insert(key, link_state.clone());
        self.rebuild_topology();
        debug!(
            target: "rillane::mesh",
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

        info!(target: "rillane::mesh", session = %session_id, "会话创建成功");
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
            info!(target: "rillane::mesh", session = %session_id, "会话终止");
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

    /// 获取节点记录（快照）
    pub fn get_node(&self, node_id: &NodeId) -> Option<NodeRecord> {
        self.nodes
            .read()
            .expect("mesh registry poisoned")
            .get(node_id)
            .cloned()
    }

    /// 记录链路连接
    pub fn record_link_connection(&self, from: &NodeId, to: &NodeId) {
        let now = current_epoch_seconds();
        let key = (from.clone(), to.clone());
        self.link_traffic
            .entry(key)
            .and_modify(|s| {
                s.connections_total = s.connections_total.saturating_add(1);
                s.last_updated_epoch_seconds = now;
            })
            .or_insert_with(|| LinkTrafficStats {
                connections_total: 1,
                last_updated_epoch_seconds: now,
                ..LinkTrafficStats::default()
            });
    }

    /// 记录链路流量（字节）
    pub fn record_link_bytes(&self, from: &NodeId, to: &NodeId, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let now = current_epoch_seconds();
        let key = (from.clone(), to.clone());
        self.link_traffic
            .entry(key)
            .and_modify(|s| {
                s.bytes_total = s.bytes_total.saturating_add(bytes);
                s.last_updated_epoch_seconds = now;
            })
            .or_insert_with(|| LinkTrafficStats {
                bytes_total: bytes,
                last_updated_epoch_seconds: now,
                ..LinkTrafficStats::default()
            });
    }

    /// 记录链路 RTT 样本（P2-1 D-1 公开写点：探测源接线预留，O-link-obs1）
    pub fn record_link_rtt(&self, from: &NodeId, to: &NodeId, rtt_ms: u32) {
        if rtt_ms == 0 {
            return;
        }
        self.link_rtt
            .entry((from.clone(), to.clone()))
            .or_default()
            .record(rtt_ms);
    }

    /// 全部链路 RTT 分位快照（环空链路不产出，E3）
    pub fn get_all_link_rtt(&self) -> Vec<LinkRttSnapshot> {
        self.link_rtt
            .iter()
            .filter(|e| !e.value().is_empty())
            .map(|e| {
                let ((from, to), ring) = (e.key(), e.value());
                LinkRttSnapshot {
                    from: from.clone(),
                    to: to.clone(),
                    p50_ms: ring.quantile(0.5).unwrap_or(0),
                    p95_ms: ring.quantile(0.95).unwrap_or(0),
                    samples: ring.len(),
                }
            })
            .collect()
    }

    /// 记录链路错误
    pub fn record_link_error(&self, from: &NodeId, to: &NodeId) {
        let now = current_epoch_seconds();
        let key = (from.clone(), to.clone());
        self.link_traffic
            .entry(key)
            .and_modify(|s| {
                s.errors_total = s.errors_total.saturating_add(1);
                s.last_updated_epoch_seconds = now;
            })
            .or_insert_with(|| LinkTrafficStats {
                errors_total: 1,
                last_updated_epoch_seconds: now,
                ..LinkTrafficStats::default()
            });
    }

    /// 获取全部链路流量统计（快照）
    pub fn get_all_link_traffic(&self) -> Vec<LinkTrafficSnapshot> {
        let now = current_epoch_seconds();
        self.link_traffic
            .iter()
            .map(|e| {
                let (from, to) = e.key();
                let v = e.value();
                LinkTrafficSnapshot {
                    from: from.clone(),
                    to: to.clone(),
                    bytes_total: v.bytes_total,
                    connections_total: v.connections_total,
                    errors_total: v.errors_total,
                    age_seconds: now.saturating_sub(v.last_updated_epoch_seconds),
                }
            })
            .collect()
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

fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
        {
            let mut nodes = self.nodes.write().expect("mesh registry poisoned");
            if let Some(record) = nodes.get_mut(node_id) {
                record.online = false;
            } else {
                return Err(MeshError::NotFound(node_id.clone()).into());
            }
        }

        self.rebuild_topology();
        info!(target: "rillane::mesh", node = %node_id, "节点标记为离线");
        Ok(())
    }

    /// 健康检查单轮（快照收集 + 写锁复检 + 拓扑重建）。
    /// 返回被标记离线的节点数。公开供测试确定性注入「快照后心跳刷新」竞态。
    pub fn health_check_once(&self, ttl: Duration) -> usize {
        let stale_ids = self.stale_candidates(ttl);
        self.mark_stale_offline(&stale_ids, ttl)
    }

    /// 快照：收集当前超时（online 且 last_seen 超过 ttl）的节点候选。
    fn stale_candidates(&self, ttl: Duration) -> Vec<NodeId> {
        let stale_ids: Vec<NodeId> = {
            let nodes = self.nodes.read().expect("mesh registry poisoned");
            nodes
                .iter()
                .filter(|(_, record)| record.online && record.last_seen.elapsed() >= ttl)
                .map(|(id, _)| id.clone())
                .collect()
        };
        stale_ids
    }

    /// 写锁复检 + 标记离线 + 拓扑重建。
    fn mark_stale_offline(&self, stale_ids: &[NodeId], ttl: Duration) -> usize {
        if stale_ids.is_empty() {
            return 0;
        }
        // 写锁下复检：快照释放读锁后可能有心跳刷新 last_seen，
        // 无条件标记会误杀刚续期的节点，致拓扑/路由抖动。
        let mut marked = 0;
        {
            let mut nodes = self.nodes.write().expect("mesh registry poisoned");
            for id in stale_ids {
                if let Some(record) = nodes.get_mut(id) {
                    if record.online && record.last_seen.elapsed() >= ttl {
                        record.online = false;
                        marked += 1;
                    }
                }
            }
        }

        if marked > 0 {
            warn!(
                target: "rillane::mesh",
                stale = ?stale_ids,
                marked = marked,
                "节点超时，标记为离线"
            );
            self.rebuild_topology();
        }
        marked
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
        registry.health_check_once(ttl);
    }
}

/// 启动拓扑更新器
pub async fn spawn_topology_updater(registry: Arc<MeshRegistry>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        registry.update_stats();
        debug!(target: "rillane::mesh", "拓扑统计信息已更新");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn register_node_rejects_invalid_quota() {
        let registry = MeshRegistry::new();
        let mut record = NodeRecord::new("n1".into(), NodeRole::Client, addr());
        record.quota.daily_bandwidth_gb = Some(0);
        assert!(registry.register_node(record).is_err());
    }

    #[test]
    fn register_node_rejects_invalid_acl_cidr() {
        let registry = MeshRegistry::new();
        let mut record = NodeRecord::new("n1".into(), NodeRole::Client, addr());
        record.acl.allowed_client_cidrs = vec!["not-a-cidr".into()];
        assert!(registry.register_node(record).is_err());
    }

    #[test]
    fn create_session_validates_path_and_node_state() {
        let registry = MeshRegistry::new();
        registry
            .register_node(NodeRecord::new("client1".into(), NodeRole::Client, addr()))
            .unwrap();
        registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, addr()))
            .unwrap();

        let target_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(registry
            .create_session("client1".into(), vec![], target_addr)
            .is_err());
        assert!(registry
            .create_session("client1".into(), vec!["missing".to_string()], target_addr)
            .is_err());

        registry.mark_node_offline(&"exit1".to_string()).unwrap();
        assert!(registry
            .create_session("client1".into(), vec!["exit1".to_string()], target_addr)
            .is_err());
    }

    #[test]
    fn session_stats_update_and_termination() {
        let registry = MeshRegistry::new();
        registry
            .register_node(NodeRecord::new("client1".into(), NodeRole::Client, addr()))
            .unwrap();
        registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, addr()))
            .unwrap();

        let target_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let sid = registry
            .create_session("client1".into(), vec!["exit1".to_string()], target_addr)
            .unwrap();

        registry.update_session_stats(sid, 10, 20).unwrap();
        let snap = registry
            .get_session_snapshot(sid)
            .expect("session snapshot");
        assert_eq!(snap.bytes_up, 10);
        assert_eq!(snap.bytes_down, 20);

        registry.terminate_session(sid).unwrap();
        assert!(registry.terminate_session(sid).is_err());
        assert!(registry.update_session_stats(sid, 1, 1).is_err());
    }

    #[test]
    fn link_traffic_recording_and_snapshots() {
        let registry = MeshRegistry::new();
        let from = "n1".to_string();
        let to = "n2".to_string();

        registry.record_link_bytes(&from, &to, 0);
        assert!(registry.get_all_link_traffic().is_empty());

        registry.record_link_connection(&from, &to);
        registry.record_link_bytes(&from, &to, 100);
        registry.record_link_error(&from, &to);

        let snaps = registry.get_all_link_traffic();
        assert_eq!(snaps.len(), 1);
        let s = &snaps[0];
        assert_eq!(s.from, from);
        assert_eq!(s.to, to);
        assert_eq!(s.bytes_total, 100);
        assert_eq!(s.connections_total, 1);
        assert_eq!(s.errors_total, 1);
    }

    /// P2-1 §7-1：分位数数学（奇偶 n、边界、cap 覆写）
    #[test]
    fn rtt_ring_quantile_math_and_cap() {
        let mut ring = RttRing::default();
        assert!(ring.quantile(0.5).is_none(), "空环 E3：None");
        assert!(ring.is_empty());

        // 奇数 n=5：p50 = 中位
        for ms in [30, 10, 20, 50, 40] {
            ring.record(ms);
        }
        assert_eq!(ring.quantile(0.5), Some(30));
        assert_eq!(ring.quantile(0.95), Some(50));
        assert_eq!(ring.quantile(1.0), Some(50));

        // 偶数 n=6：最近秩（ceil(0.5*6)-1 = 2 → 第三小）
        let mut ring = RttRing::default();
        for ms in [10, 20, 30, 40, 50, 60] {
            ring.record(ms);
        }
        assert_eq!(ring.quantile(0.5), Some(30));
        // ceil(0.95*6)-1 = ceil(5.7)-1 = 5 → 最大
        assert_eq!(ring.quantile(0.95), Some(60));

        // p 边界钳制：p→0 取最小
        assert_eq!(ring.quantile(0.01), Some(10));

        // cap 覆写：cap+1 个样本后最旧被逐出
        let mut ring = RttRing::default();
        for i in 0..(RTT_RING_CAP + 1) as u32 {
            ring.record(i);
        }
        assert_eq!(ring.len(), RTT_RING_CAP);
        // p=0.001 → ceil(0.256)=1 → idx 0 = 最小值 1（样本 0 已被覆写逐出）
        assert_eq!(ring.quantile(0.001), Some(1), "样本 0 已被覆写逐出");
        assert_eq!(ring.quantile(1.0), Some(RTT_RING_CAP as u32));
    }

    /// P2-1 §7-2：采样源两路——update_link_state 上报入环（0 值不入）+
    /// record_link_rtt 直写；环空链路快照不产出
    #[test]
    fn registry_rtt_sampling_sources() {
        let registry = MeshRegistry::new();

        // 上报源：latency>0 入环；0 值不入环
        let mut ls = LinkState::new("a".into(), "b".into());
        ls.latency_ms = 42;
        registry.update_link_state(ls.clone()).unwrap();
        ls.latency_ms = 58;
        registry.update_link_state(ls.clone()).unwrap();
        ls.latency_ms = 0;
        registry.update_link_state(ls.clone()).unwrap();

        // 直写源
        registry.record_link_rtt(&"a".to_string(), &"b".to_string(), 100);
        registry.record_link_rtt(&"a".to_string(), &"b".to_string(), 0); // E：0 拒收

        let snaps = registry.get_all_link_rtt();
        assert_eq!(snaps.len(), 1, "环空链路（0 值单上报）不产出");
        let s = &snaps[0];
        assert_eq!(s.from, "a");
        assert_eq!(s.to, "b");
        assert_eq!(s.samples, 3, "42/58/100 三样本，0 值两处均不入环");
        assert_eq!(s.p50_ms, 58);
        assert_eq!(s.p95_ms, 100);

        // 无样本链路整体无序列
        assert!(registry.get_all_link_rtt().iter().all(|x| x.samples > 0));
    }

    #[test]
    fn check_quota_enforces_bytes_and_concurrency_limits() {
        let registry = MeshRegistry::new();
        let mut n1 = NodeRecord::new("client1".into(), NodeRole::Client, addr());
        n1.quota.daily_bandwidth_gb = Some(1);
        registry.register_node(n1).unwrap();

        {
            let mut nodes = registry.nodes.write().unwrap();
            let record = nodes.get_mut("client1").unwrap();
            record.total_bytes_transferred = 1024 * 1024 * 1024 - 10;
        }
        assert!(registry.check_quota(&"client1".to_string(), 20).is_err());

        let mut n2 = NodeRecord::new("client2".into(), NodeRole::Client, addr());
        n2.quota.max_concurrent_connections = Some(1);
        registry.register_node(n2).unwrap();
        registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, addr()))
            .unwrap();
        let _sid = registry
            .create_session(
                "client2".into(),
                vec!["exit1".to_string()],
                "127.0.0.1:443".parse().unwrap(),
            )
            .unwrap();
        assert!(registry.check_quota(&"client2".to_string(), 0).is_err());
    }

    #[test]
    fn check_acl_denied_and_allowed_ports() {
        let registry = MeshRegistry::new();
        let mut record = NodeRecord::new("client1".into(), NodeRole::Client, addr());
        record.acl.denied_target_ports = vec![(80, 80)];
        registry.register_node(record).unwrap();

        assert!(registry
            .check_acl(&"client1".to_string(), &"127.0.0.1:80".parse().unwrap())
            .is_err());

        let mut record = NodeRecord::new("client2".into(), NodeRole::Client, addr());
        record.acl.allowed_target_ports = vec![(443, 443)];
        registry.register_node(record).unwrap();

        assert!(registry
            .check_acl(&"client2".to_string(), &"127.0.0.1:80".parse().unwrap())
            .is_err());
        registry
            .check_acl(&"client2".to_string(), &"127.0.0.1:443".parse().unwrap())
            .unwrap();
    }

    #[test]
    fn find_optimal_path_returns_target_only() {
        let registry = MeshRegistry::new();
        let p = registry
            .find_optimal_path(&"client1".to_string(), &"exit1".to_string())
            .unwrap();
        assert_eq!(p, vec!["exit1".to_string()]);
    }

    #[tokio::test]
    async fn health_checker_marks_stale_nodes_offline() {
        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new("n1".into(), NodeRole::Client, addr()))
            .unwrap();
        {
            let mut nodes = registry.nodes.write().unwrap();
            let record = nodes.get_mut("n1").unwrap();
            record.last_seen = Instant::now() - Duration::from_millis(250);
        }

        let handle = tokio::spawn(spawn_health_checker(
            registry.clone(),
            Duration::from_millis(200),
        ));
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!registry.get_node(&"n1".to_string()).unwrap().online);
        handle.abort();
    }

    /// 写锁复检回归：快照收集后、写锁获取前心跳刷新 last_seen，
    /// 无条件标记会误杀刚续期的节点（致拓扑/路由抖动）。health_check_once
    /// 在写锁下复检 `last_seen`，刷新后的节点必须保持在线。
    #[test]
    fn health_check_reread_under_write_lock_keeps_refreshed_node_online() {
        let registry = MeshRegistry::new();
        registry
            .register_node(NodeRecord::new("n1".into(), NodeRole::Client, addr()))
            .unwrap();
        let ttl = Duration::from_millis(200);

        // 快照收集时已超时（last_seen 早于 ttl）。
        {
            let mut nodes = registry.nodes.write().unwrap();
            let record = nodes.get_mut("n1").unwrap();
            record.last_seen = Instant::now() - Duration::from_millis(300);
        }

        // 快照收集（候选含 n1，last_seen 已超时）。
        let stale = registry.stale_candidates(ttl);
        assert_eq!(stale, vec!["n1".to_string()], "快照应收集超时节点");

        // 模拟快照后、写锁前的真实心跳刷新。
        registry.update_node_health("n1", 0.5).unwrap();

        // 写锁复检必须看到新 last_seen → 不标记。
        let marked = registry.mark_stale_offline(&stale, ttl);
        assert_eq!(marked, 0, "刚续期节点不得被标记离线");
        assert!(registry.get_node(&"n1".to_string()).unwrap().online);
    }
}
