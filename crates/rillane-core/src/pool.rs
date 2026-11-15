//! 代理连接池边界（RIL-028）：网页出口的预热、TLS 恢复与池回收——
//! 只在**协议支持范围内**发生，且全程有硬资源上限。
//!
//! 规则边界（验收口径）：
//! - **实际减少建连成本**：`acquire` 命中空闲连接 → 该请求跳过完整
//!   拨号/TLS 握手（`PoolStats.hits` 逐次可数）；`plan_warm` 对已有
//!   空闲同端点返回 `Redundant`——预热不重复建连，省的是真握手；
//! - **资源上限是真的**：全池与单节点空闲数硬上限（offer/release
//!   双侧强制，超限拒绝、调用方关连接），空闲 TTL 到点由 `recycle`
//!   驱逐（调用方关闭 IO）；上限拒绝与驱逐都可观测；
//! - **代理池不当内容缓存**：池条目 [`PooledConn`] 只有端点、传输
//!   复用类与计数——**没有任何内容/响应/缓存字段**（结构排除：想
//!   把池当内容缓存连类型面都不允许）；
//! - **不为不支持协议伪造多路复用**：复用能力由出口声明
//!   [`TransportReuse`]——`None`（无会话语义）不入池、不预热、不
//!   共享（`pool.unsupported` 拒绝）；`TlsResumption` 只能独占取出
//!   （一次一个请求）；只有声明 `Multiplexed` 的连接才允许 `Share`
//!   共享（流数上限在 [`PoolLimits::max_streams_per_conn`]，到顶转
//!   独占取出）；
//! - **回收确定性**：驱逐原因显式（`IdleTtl` / `NodeRemoved`——后者
//!   与 RIL-023 端点删除接线），驱逐交还调用方关闭，池只管记账。
//!
//! 接线边界：runtime 侧冷路径走 RIL-022 `SessionExecutor` 正常拨号，
//! 热路径先 `acquire`；`recycle`/`evict_node` 挂在周期任务与目录删
//! 除回调上，对返回连接关闭底层 IO。池限空闲连接，RIL-024 预算限
//! 活跃会话——两套上限在 runtime 并联，互不替代。内核无时钟无 IO：
//! 时刻全部由调用方供给，本模块纯记账。

use std::collections::HashMap;
use std::fmt;

use crate::plan::EndpointRef;

/// 稳定原因码：池参数非法
pub const CODE_POOL_LIMITS_INVALID: &str = "pool.limits.invalid";
/// 稳定原因码：全池空闲上限已满
pub const CODE_POOL_CAPACITY_TOTAL: &str = "pool.capacity.total";
/// 稳定原因码：单节点空闲上限已满
pub const CODE_POOL_CAPACITY_NODE: &str = "pool.capacity.node";
/// 稳定原因码：出口未声明可复用能力——不入池不伪造
pub const CODE_POOL_UNSUPPORTED: &str = "pool.unsupported";

/// 传输复用能力（由出口按协议如实声明——池行为随类走，不越权）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportReuse {
    /// 无复用语义（如一次性隧道）——不入池、不预热、不共享
    None,
    /// TLS 会话恢复（session ticket/PSK）——连接可池化但一次只服务
    /// 一个请求（独占取出）
    TlsResumption,
    /// 连接多路复用（如 HTTP/2 单连接多流）——可共享，流数有上限
    Multiplexed,
}

impl TransportReuse {
    /// 是否可池化（None 类不可——伪造即越权）
    pub fn poolable(self) -> bool {
        matches!(
            self,
            TransportReuse::TlsResumption | TransportReuse::Multiplexed
        )
    }

    /// 机器口径
    pub fn as_str(self) -> &'static str {
        match self {
            TransportReuse::None => "none",
            TransportReuse::TlsResumption => "tls_resumption",
            TransportReuse::Multiplexed => "multiplexed",
        }
    }
}

/// 池参数（构造时校验：上限非零、TTL 为正、节点上限不超全池）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolLimits {
    /// 全池空闲连接上限（硬上限：入池双侧强制）
    pub max_idle_total: usize,
    /// 单节点空闲连接上限
    pub max_idle_per_node: usize,
    /// 空闲存活时长（毫秒；到点回收）
    pub idle_ttl_ms: u64,
    /// 多路复用单连接并发流上限（到顶转独占取出）
    pub max_streams_per_conn: u32,
}

impl PoolLimits {
    /// 校验：上限非零、TTL 为正、节点上限 ≤ 全池上限
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.max_idle_total == 0
            || self.max_idle_per_node == 0
            || self.max_idle_per_node > self.max_idle_total
            || self.idle_ttl_ms == 0
            || self.max_streams_per_conn == 0
        {
            return Err(PoolError::LimitsInvalid);
        }
        Ok(())
    }
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_idle_total: 32,
            max_idle_per_node: 4,
            idle_ttl_ms: 30_000,
            max_streams_per_conn: 32,
        }
    }
}

/// 池错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// 池参数非法（`pool.limits.invalid`）
    LimitsInvalid,
    /// 全池空闲上限已满（`pool.capacity.total`）
    CapacityTotal { used: usize, limit: usize },
    /// 单节点空闲上限已满（`pool.capacity.node`）
    CapacityNode { used: usize, limit: usize },
    /// 出口未声明可复用能力（`pool.unsupported`——调用方须关闭连接）
    Unsupported,
}

impl PoolError {
    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        match self {
            PoolError::LimitsInvalid => CODE_POOL_LIMITS_INVALID,
            PoolError::CapacityTotal { .. } => CODE_POOL_CAPACITY_TOTAL,
            PoolError::CapacityNode { .. } => CODE_POOL_CAPACITY_NODE,
            PoolError::Unsupported => CODE_POOL_UNSUPPORTED,
        }
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::LimitsInvalid => f.write_str("pool limits invalid"),
            PoolError::CapacityTotal { used, limit } => {
                write!(f, "pool full: {used}/{limit} idle connections")
            }
            PoolError::CapacityNode { used, limit } => {
                write!(f, "node pool full: {used}/{limit} idle connections")
            }
            PoolError::Unsupported => {
                f.write_str("outbound declared no reuse capability: not pooled")
            }
        }
    }
}

impl std::error::Error for PoolError {}

/// 预热决策（协议范围 + 上限 + 冗余三道门）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarmDecision {
    /// 该建（调用方拨号成功后 `offer` 入池）
    Warm,
    /// 该端点已有空闲连接——再建纯浪费（实际省成本的判定面）
    Redundant { idle: usize },
    /// 出口未声明复用能力——不为它预热（不伪造）
    Unsupported,
    /// 上限已满——资源上限挡住预热
    Full { total: usize, per_node: usize },
}

/// 池条目：只有端点与传输能力——**无内容字段**（代理池不是内容缓存）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledConn {
    /// 连接身份（runtime 以此映射底层 IO）
    pub conn_id: u64,
    /// 所属节点
    pub node: String,
    /// 出口端点
    pub endpoint: EndpointRef,
    /// 声明的复用能力（入池时已核验 poolable）
    pub reuse: TransportReuse,
    /// 建立时刻（毫秒）
    pub opened_ms: u64,
    /// 最近使用时刻（毫秒；TTL 与 LIFO 的依据）
    pub last_used_ms: u64,
    /// 服务过的请求次数（含首次建立——TLS 恢复省握手的证据计数）
    pub uses: u64,
    /// 在途流数（仅 Multiplexed 增长）
    pub streams_in_flight: u32,
}

/// 取用结果（热路径入口：命中/共享/冷）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acquire {
    /// 独占命中：整连离池（TlsResumption 常态；Multiplexed 流满时）
    Hit { conn: PooledConn },
    /// 共享命中：Multiplexed 连接留池，流数 +1（调用方按 conn_id 取流）
    Share { conn_id: u64, streams: u32 },
    /// 冷：池无可用连接——调用方走正常拨号（RIL-022 执行器）
    Miss,
}

/// 驱逐原因（回收可解释）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionReason {
    /// 空闲超 TTL
    IdleTtl,
    /// 节点被目录删除（与 RIL-023 端点删除接线）
    NodeRemoved,
}

impl EvictionReason {
    /// 机器口径
    pub fn as_str(self) -> &'static str {
        match self {
            EvictionReason::IdleTtl => "idle_ttl",
            EvictionReason::NodeRemoved => "node_removed",
        }
    }
}

/// 一条被驱逐的连接（池只记账——关闭底层 IO 由调用方完成）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecycledConn {
    /// 被驱逐的池条目
    pub conn: PooledConn,
    /// 驱逐时空闲了多久（毫秒）
    pub idle_ms: u64,
    /// 驱逐原因
    pub reason: EvictionReason,
}

/// 池用量与成本证据（hits = 免握手次数）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolStats {
    /// 当前空闲连接数
    pub total_idle: usize,
    /// 有空闲连接的节点数
    pub nodes: usize,
    /// 独占命中次数（每次 = 省一次完整建连）
    pub hits: u64,
    /// 共享命中次数（Multiplexed 流复用）
    pub shares: u64,
    /// 冷请求次数（走了完整拨号）
    pub misses: u64,
    /// 入池被上限拒绝次数
    pub offers_rejected: u64,
    /// 累计驱逐数
    pub evictions: u64,
}

/// 代理连接池：纯记账（无时钟无 IO）。上限在 offer/release 双侧强制，
/// 回收只产记录不动 IO。条目无内容字段——想当内容缓存连类型面都过
/// 不去。
#[derive(Debug)]
pub struct ConnPool {
    limits: PoolLimits,
    idle: HashMap<String, Vec<PooledConn>>,
    total_idle: usize,
    next_conn_id: u64,
    hits: u64,
    shares: u64,
    misses: u64,
    offers_rejected: u64,
    evictions: u64,
}

impl ConnPool {
    /// 构造连接池（参数非法拒绝——上限必须自洽才可信）
    pub fn new(limits: PoolLimits) -> Result<Self, PoolError> {
        limits.validate()?;
        Ok(Self {
            limits,
            idle: HashMap::new(),
            total_idle: 0,
            next_conn_id: 1,
            hits: 0,
            shares: 0,
            misses: 0,
            offers_rejected: 0,
            evictions: 0,
        })
    }

    /// 池参数（只读）
    pub fn limits(&self) -> &PoolLimits {
        &self.limits
    }

    /// 预热决策：能力门 → 冗余门 → 上限门，三道全过才 Warm
    pub fn plan_warm(
        &self,
        node: &str,
        endpoint: &EndpointRef,
        reuse: TransportReuse,
        _now_ms: u64,
    ) -> WarmDecision {
        if !reuse.poolable() {
            return WarmDecision::Unsupported;
        }
        if let Some(vec) = self.idle.get(node) {
            if vec.iter().any(|c| c.endpoint == *endpoint) {
                return WarmDecision::Redundant { idle: vec.len() };
            }
        }
        if self.total_idle >= self.limits.max_idle_total {
            return WarmDecision::Full {
                total: self.total_idle,
                per_node: self.node_idle(node),
            };
        }
        if self.node_idle(node) >= self.limits.max_idle_per_node {
            return WarmDecision::Full {
                total: self.total_idle,
                per_node: self.node_idle(node),
            };
        }
        WarmDecision::Warm
    }

    /// 入池（预热建连成功后调用）：重走三道门（与 plan_warm 同口径，
    /// 防决策与入池间上限漂移）；拒绝时调用方须关闭连接。返回连接
    /// 身份供 runtime 映射底层 IO。
    pub fn offer(
        &mut self,
        node: impl Into<String>,
        endpoint: EndpointRef,
        reuse: TransportReuse,
        now_ms: u64,
    ) -> Result<u64, PoolError> {
        if !reuse.poolable() {
            self.offers_rejected += 1;
            return Err(PoolError::Unsupported);
        }
        let node = node.into();
        if self.total_idle >= self.limits.max_idle_total {
            self.offers_rejected += 1;
            return Err(PoolError::CapacityTotal {
                used: self.total_idle,
                limit: self.limits.max_idle_total,
            });
        }
        let used = self.node_idle(&node);
        if used >= self.limits.max_idle_per_node {
            self.offers_rejected += 1;
            return Err(PoolError::CapacityNode {
                used,
                limit: self.limits.max_idle_per_node,
            });
        }
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;
        let node_key = node.clone();
        self.idle
            .entry(node_key.clone())
            .or_default()
            .push(PooledConn {
                conn_id,
                node: node_key,
                endpoint,
                reuse,
                opened_ms: now_ms,
                last_used_ms: now_ms,
                uses: 1,
                streams_in_flight: 0,
            });
        self.total_idle += 1;
        Ok(conn_id)
    }

    /// 热路径取用：LIFO 取该节点（可指定端点）最近用过的可用连接。
    /// TlsResumption → 独占 Hit（离池）；Multiplexed 未满流 → Share
    /// （留池，流数 +1），满流 → 独占 Hit。无可用 → Miss（走冷路径）。
    pub fn acquire(&mut self, node: &str, endpoint: Option<&EndpointRef>, now_ms: u64) -> Acquire {
        let Some(vec) = self.idle.get_mut(node) else {
            self.misses += 1;
            return Acquire::Miss;
        };
        // LIFO：最近使用者优先（TLS ticket 最新鲜，恢复成功率最高）
        let idx = vec
            .iter()
            .rposition(|c| endpoint.is_none_or(|ep| c.endpoint == *ep));
        let Some(idx) = idx else {
            self.misses += 1;
            return Acquire::Miss;
        };
        let conn = &mut vec[idx];
        conn.uses += 1;
        conn.last_used_ms = now_ms;
        if conn.reuse == TransportReuse::Multiplexed
            && conn.streams_in_flight < self.limits.max_streams_per_conn
        {
            conn.streams_in_flight += 1;
            self.shares += 1;
            return Acquire::Share {
                conn_id: conn.conn_id,
                streams: conn.streams_in_flight,
            };
        }
        let conn = vec.remove(idx);
        let now_empty = vec.is_empty();
        if now_empty {
            self.idle.remove(node);
        }
        self.total_idle -= 1;
        self.hits += 1;
        Acquire::Hit { conn }
    }

    /// 独占归还：连接还活着，回池待复用。重走上限门（满了拒绝，调用
    /// 方关闭——上限在归还侧同样是真的）。条目 last_used 刷新为 now。
    pub fn release(&mut self, mut conn: PooledConn, now_ms: u64) -> Result<(), PoolError> {
        if !conn.reuse.poolable() {
            return Err(PoolError::Unsupported);
        }
        let node = conn.node.clone();
        if self.total_idle >= self.limits.max_idle_total {
            return Err(PoolError::CapacityTotal {
                used: self.total_idle,
                limit: self.limits.max_idle_total,
            });
        }
        let used = self.node_idle(&node);
        if used >= self.limits.max_idle_per_node {
            return Err(PoolError::CapacityNode {
                used,
                limit: self.limits.max_idle_per_node,
            });
        }
        conn.last_used_ms = now_ms;
        self.idle.entry(node).or_default().push(conn);
        self.total_idle += 1;
        Ok(())
    }

    /// 多路复用流结束：流数 −1（连接留池）；条目 last_used 刷新。
    /// 未知 conn_id 返回 None（无臆造）。
    pub fn release_stream(&mut self, conn_id: u64, now_ms: u64) -> Option<u32> {
        for vec in self.idle.values_mut() {
            if let Some(conn) = vec.iter_mut().find(|c| c.conn_id == conn_id) {
                conn.streams_in_flight = conn.streams_in_flight.saturating_sub(1);
                conn.last_used_ms = now_ms;
                return Some(conn.streams_in_flight);
            }
        }
        None
    }

    /// TTL 回收：空闲超过 idle_ttl 的连接驱逐（交调用方关闭 IO）。
    /// 池内永不超限（offer/release 双侧强制），回收只需扫 TTL。
    pub fn recycle(&mut self, now_ms: u64) -> Vec<RecycledConn> {
        let mut evicted = Vec::new();
        let mut empty_nodes = Vec::new();
        for (node, vec) in self.idle.iter_mut() {
            let before = vec.len();
            for i in (0..vec.len()).rev() {
                let idle_ms = now_ms.saturating_sub(vec[i].last_used_ms);
                if idle_ms > self.limits.idle_ttl_ms {
                    let conn = vec.remove(i);
                    evicted.push(RecycledConn {
                        conn,
                        idle_ms,
                        reason: EvictionReason::IdleTtl,
                    });
                }
            }
            self.total_idle -= before - vec.len();
            if vec.is_empty() {
                empty_nodes.push(node.clone());
            }
        }
        for node in empty_nodes {
            self.idle.remove(&node);
        }
        self.evictions += evicted.len() as u64;
        evicted
    }

    /// 节点驱逐（目录删除接线，RIL-023）：该节点全部空闲连接驱逐，
    /// 其它节点不动。
    pub fn evict_node(&mut self, node: &str) -> Vec<RecycledConn> {
        let Some(vec) = self.idle.remove(node) else {
            return Vec::new();
        };
        self.total_idle -= vec.len();
        let evicted: Vec<RecycledConn> = vec
            .into_iter()
            .map(|conn| RecycledConn {
                conn,
                idle_ms: 0,
                reason: EvictionReason::NodeRemoved,
            })
            .collect();
        self.evictions += evicted.len() as u64;
        evicted
    }

    /// 池用量与成本证据
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_idle: self.total_idle,
            nodes: self.idle.len(),
            hits: self.hits,
            shares: self.shares,
            misses: self.misses,
            offers_rejected: self.offers_rejected,
            evictions: self.evictions,
        }
    }

    /// 某节点当前空闲数
    fn node_idle(&self, node: &str) -> usize {
        self.idle.get(node).map_or(0, |v| v.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_000_000;
    const TTL: u64 = 30_000;

    fn ep(host: &str) -> EndpointRef {
        EndpointRef::new(host, 443)
    }

    fn pool() -> ConnPool {
        ConnPool::new(PoolLimits {
            max_idle_total: 4,
            max_idle_per_node: 2,
            idle_ttl_ms: TTL,
            max_streams_per_conn: 3,
        })
        .expect("合法参数")
    }

    /// 能力范围：None 类不入池不预热（不伪造）；同端点已有空闲 →
    /// Redundant（预热不重复建连）；上限满 → Full
    #[test]
    fn warm_plan_respects_capability_scope_and_caps() {
        let mut pool = pool();

        assert_eq!(
            pool.plan_warm("node-a", &ep("10.0.0.1"), TransportReuse::None, T0),
            WarmDecision::Unsupported,
            "无复用能力的出口不预热——不为不支持协议伪造"
        );
        assert_eq!(
            pool.plan_warm("node-a", &ep("10.0.0.1"), TransportReuse::TlsResumption, T0),
            WarmDecision::Warm
        );

        // 预热建立后同端点再问：已有空闲 → Redundant（省真握手）
        pool.offer("node-a", ep("10.0.0.1"), TransportReuse::TlsResumption, T0)
            .expect("入池");
        assert_eq!(
            pool.plan_warm("node-a", &ep("10.0.0.1"), TransportReuse::TlsResumption, T0),
            WarmDecision::Redundant { idle: 1 }
        );
        // 不同端点同节点仍可 Warm，但单节点上限 2：第二条入池后 → Full
        assert_eq!(
            pool.plan_warm("node-a", &ep("10.0.0.2"), TransportReuse::TlsResumption, T0),
            WarmDecision::Warm
        );
        pool.offer("node-a", ep("10.0.0.2"), TransportReuse::TlsResumption, T0)
            .expect("入池");
        assert_eq!(
            pool.plan_warm("node-a", &ep("10.0.0.3"), TransportReuse::TlsResumption, T0),
            WarmDecision::Full {
                total: 2,
                per_node: 2
            },
            "单节点上限挡住预热"
        );
    }

    /// 上限是真的：offer 双侧强制（入池与归还都拒绝超限），稳定码可辨
    #[test]
    fn capacity_limits_are_hard_on_both_sides() {
        let mut pool = pool();
        pool.offer("node-a", ep("10.0.0.1"), TransportReuse::Multiplexed, T0)
            .expect("入池");
        pool.offer("node-a", ep("10.0.0.2"), TransportReuse::Multiplexed, T0)
            .expect("入池");

        // 单节点上限 2 已满
        let err = pool
            .offer("node-a", ep("10.0.0.3"), TransportReuse::Multiplexed, T0)
            .expect_err("节点上限应拒");
        assert_eq!(err.code(), CODE_POOL_CAPACITY_NODE);
        assert_eq!(pool.stats().offers_rejected, 1);

        // 全池上限 4：再填两个其它节点
        pool.offer("node-b", ep("10.1.0.1"), TransportReuse::TlsResumption, T0)
            .expect("入池");
        pool.offer("node-c", ep("10.2.0.1"), TransportReuse::Multiplexed, T0)
            .expect("入池");
        let err = pool
            .offer("node-d", ep("10.3.0.1"), TransportReuse::Multiplexed, T0)
            .expect_err("全池上限应拒");
        assert_eq!(err.code(), CODE_POOL_CAPACITY_TOTAL);

        // 归还侧同样强制：独占取出一条（全池 3）→ 补入另一条回到满（4）
        // → 此时归还手持连接被拒（上限在归还侧是真的）
        let Acquire::Hit { conn } = pool.acquire("node-b", None, T0) else {
            panic!("TLS 连接应独占命中");
        };
        assert_eq!(pool.stats().total_idle, 3);
        pool.offer("node-d", ep("10.3.0.1"), TransportReuse::Multiplexed, T0)
            .expect("腾出空位后可入池");
        let err = pool
            .release(conn, T0)
            .expect_err("全池满时归还应拒（调用方须关闭）");
        assert_eq!(err.code(), CODE_POOL_CAPACITY_TOTAL);
        assert_eq!(pool.stats().total_idle, 4, "拒绝未入池——上限未被突破");
    }

    /// 实际省建连成本：热请求 Hit 免完整建连（uses 计数），独占取后
    /// 再来是 Miss（走冷路径）；取用后归还可再复用
    #[test]
    fn acquire_hit_avoids_reconnect_and_release_reuses() {
        let mut pool = pool();
        let conn_id = pool
            .offer("node-a", ep("10.0.0.1"), TransportReuse::TlsResumption, T0)
            .expect("入池");

        // 第一次取：命中（免完整握手——TLS ticket 恢复）
        let Acquire::Hit { conn } = pool.acquire("node-a", None, T0 + 1_000) else {
            panic!("应命中");
        };
        assert_eq!(conn.conn_id, conn_id);
        assert_eq!(conn.uses, 2, "命中即第二次服务（首次为建立）");
        assert_eq!(conn.last_used_ms, T0 + 1_000);

        // 池空：第二次取是 Miss（冷路径拨号）
        assert_eq!(pool.acquire("node-a", None, T0), Acquire::Miss);
        let stats = pool.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);

        // 归还回池：LIFO 取最近用的，再命中
        pool.release(conn, T0 + 2_000).expect("回池");
        let Acquire::Hit { conn } = pool.acquire("node-a", Some(&ep("10.0.0.1")), T0 + 3_000)
        else {
            panic!("归还后应再命中");
        };
        assert_eq!(conn.uses, 3, "同一连接第三次服务——建连成本被摊薄");
        assert_eq!(pool.stats().hits, 2);
    }

    /// 多路复用只在声明 Multiplexed 的连接上发生：TlsResumption 永远
    /// 独占 Hit；Multiplexed 未满流 Share 留池、满流转 Hit；流结束
    /// release_stream 归还流数
    #[test]
    fn multiplex_only_for_declared_support() {
        let mut pool = pool();
        pool.offer("node-a", ep("10.0.0.1"), TransportReuse::TlsResumption, T0)
            .expect("入池");
        pool.offer("node-b", ep("10.1.0.1"), TransportReuse::Multiplexed, T0)
            .expect("入池");

        // TLS 恢复连接：独占取（离池），绝不 Share
        let Acquire::Hit { conn } = pool.acquire("node-a", None, T0) else {
            panic!("TLS 连接应独占命中");
        };
        assert_eq!(conn.reuse, TransportReuse::TlsResumption);

        // 多路复用连接：Share 留池，流数累加至上限
        let Acquire::Share { conn_id, streams } = pool.acquire("node-b", None, T0) else {
            panic!("复用连接应共享");
        };
        assert_eq!(streams, 1);
        let Acquire::Share { streams, .. } = pool.acquire("node-b", None, T0) else {
            panic!("第二条流应共享");
        };
        assert_eq!(streams, 2);
        let Acquire::Share { streams, .. } = pool.acquire("node-b", None, T0) else {
            panic!("第三条流应共享");
        };
        assert_eq!(streams, 3);

        // 流满（max_streams_per_conn = 3）：转独占 Hit 整连取出
        let Acquire::Hit { conn } = pool.acquire("node-b", None, T0) else {
            panic!("流满应整连取出");
        };
        assert_eq!(conn.reuse, TransportReuse::Multiplexed);
        assert_eq!(conn.streams_in_flight, 3);
        assert_eq!(conn.conn_id, conn_id);
        assert_eq!(pool.stats().total_idle, 0);

        // 流结束逐条归还（连接已离池 → 未知 conn_id 返回 None）
        assert_eq!(pool.release_stream(conn_id, T0), None);

        // 新一条 Multiplexed 连接入池后流归还路径生效
        let id2 = pool
            .offer("node-b", ep("10.1.0.2"), TransportReuse::Multiplexed, T0)
            .expect("入池");
        let Acquire::Share { .. } = pool.acquire("node-b", None, T0) else {
            panic!("应共享");
        };
        assert_eq!(
            pool.release_stream(id2, T0 + 100),
            Some(0),
            "流结束流数归零，连接留池"
        );
        assert_eq!(pool.stats().total_idle, 1, "连接未离池");
        assert_eq!(pool.stats().shares, 4);
    }

    /// None 类连接任何路径都拒（offer 与 release）——不为不支持协议
    /// 伪造池化
    #[test]
    fn unsupported_reuse_never_pooled() {
        let mut pool = pool();
        let err = pool
            .offer("node-a", ep("10.0.0.1"), TransportReuse::None, T0)
            .expect_err("None 类应拒入池");
        assert_eq!(err.code(), CODE_POOL_UNSUPPORTED);
        assert_eq!(pool.stats().offers_rejected, 1);
        assert_eq!(
            pool.acquire("node-a", None, T0),
            Acquire::Miss,
            "池空走冷路径"
        );

        // release 侧双保险：手工构造 None 条目也进不来
        let rogue = PooledConn {
            conn_id: 999,
            node: "node-a".into(),
            endpoint: ep("10.0.0.9"),
            reuse: TransportReuse::None,
            opened_ms: T0,
            last_used_ms: T0,
            uses: 1,
            streams_in_flight: 0,
        };
        let err = pool.release(rogue, T0).expect_err("None 类归还应拒");
        assert_eq!(err.code(), CODE_POOL_UNSUPPORTED);
        assert_eq!(pool.stats().total_idle, 0);
    }

    /// TTL 回收：到点驱逐交调用方关闭，TTL 内不误杀；驱逐后 acquire 是冷
    #[test]
    fn ttl_recycle_evicts_only_expired() {
        let mut pool = pool();
        pool.offer("node-a", ep("10.0.0.1"), TransportReuse::TlsResumption, T0)
            .expect("入池");

        // TTL 内：不回收
        assert!(pool.recycle(T0 + TTL).is_empty(), "TTL 边界内不误杀");
        assert_eq!(pool.stats().total_idle, 1);

        // 超点：驱逐且原因可解释
        let evicted = pool.recycle(T0 + TTL + 1_000);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].reason, EvictionReason::IdleTtl);
        assert_eq!(evicted[0].idle_ms, 31_000);
        assert_eq!(evicted[0].conn.endpoint, ep("10.0.0.1"));
        assert_eq!(pool.stats().total_idle, 0);
        assert_eq!(pool.stats().evictions, 1);
        assert_eq!(
            pool.acquire("node-a", None, T0 + TTL + 2_000),
            Acquire::Miss,
            "驱逐后是冷路径"
        );
    }

    /// 节点驱逐与 RIL-023 端点删除接线：只清该节点，其它节点不动
    #[test]
    fn evict_node_wires_catalog_deletion() {
        let mut pool = pool();
        pool.offer("node-a", ep("10.0.0.1"), TransportReuse::Multiplexed, T0)
            .expect("入池");
        pool.offer("node-a", ep("10.0.0.2"), TransportReuse::Multiplexed, T0)
            .expect("入池");
        pool.offer("node-b", ep("10.1.0.1"), TransportReuse::Multiplexed, T0)
            .expect("入池");

        let evicted = pool.evict_node("node-a");
        assert_eq!(evicted.len(), 2);
        assert!(evicted
            .iter()
            .all(|r| r.reason == EvictionReason::NodeRemoved && r.conn.node == "node-a"));
        assert_eq!(pool.stats().total_idle, 1);
        assert_eq!(pool.stats().evictions, 2);
        // node-b 不受波及
        assert!(matches!(
            pool.acquire("node-b", None, T0),
            Acquire::Share { .. }
        ));
        // 不存在的节点：空
        assert!(pool.evict_node("node-x").is_empty());
    }

    /// 池参数非法拒绝（零上限 / 零 TTL / 节点上限超全池 / 零流上限）
    #[test]
    fn invalid_limits_rejected() {
        for bad in [
            PoolLimits {
                max_idle_total: 0,
                max_idle_per_node: 1,
                idle_ttl_ms: 1_000,
                max_streams_per_conn: 1,
            },
            PoolLimits {
                max_idle_total: 4,
                max_idle_per_node: 0,
                idle_ttl_ms: 1_000,
                max_streams_per_conn: 1,
            },
            PoolLimits {
                max_idle_total: 4,
                max_idle_per_node: 8, // 节点上限 > 全池上限
                idle_ttl_ms: 1_000,
                max_streams_per_conn: 1,
            },
            PoolLimits {
                max_idle_total: 4,
                max_idle_per_node: 2,
                idle_ttl_ms: 0,
                max_streams_per_conn: 1,
            },
            PoolLimits {
                max_idle_total: 4,
                max_idle_per_node: 2,
                idle_ttl_ms: 1_000,
                max_streams_per_conn: 0,
            },
        ] {
            let err = ConnPool::new(bad).expect_err("非法参数应拒");
            assert_eq!(err.code(), CODE_POOL_LIMITS_INVALID);
        }
    }
}
