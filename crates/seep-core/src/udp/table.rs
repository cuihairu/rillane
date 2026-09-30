//! UDP 会话表：一级全局表（DashMap）+ 会话内目标映射 + 粘滞决策缓存。
//! 实现口径：`docs/design/udp-session-table-api.md`（§3 接口 / §5 并发契约），
//! 设计依据：`docs/design/udp-session-table.md` §3-§5。
//!
//! 锁序（严格）：DashMap shard（短暂） → mappings Mutex → decision RwLock → ledger；
//! 所有 IO（relay 收发）在锁外执行。

use crate::udp::clock::Clock;
use crate::udp::config::UdpSessionConfig;
use crate::udp::inner::{FlowTargetKey, MappingShared, UdpSessionInner};
use crate::udp::key::UdpSessionKey;
use crate::udp::ledger::SessionLedger;
use crate::udp::metrics::{
    Dir, DropReason, ExpireReason, SessionSnapshot, TableMetrics, TableSnapshot,
};
use crate::udp::relay::{DownlinkPacket, UdpRelay};
use crate::udp::ChainFailureEvent;
use crate::{
    FailureType, FlowContext, FlowId, FlowMetadata, FlowRouter, FlowTarget, RouteDecision,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, watch};

/// 上行投递结果（api 文档 §3.2）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpResult {
    /// 已交由映射 relay 发送
    Sent,
    /// 无映射（或无会话）——调用方走慢路径 resolve + associate + bind
    Miss,
    /// 已丢弃（含原因，已计数）
    Dropped { reason: DropReason },
}

/// 会话解析失败（api 文档 §3.3）
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// 全局会话满：拒新不逐旧
    #[error("udp 会话表已满（{0}），拒绝新会话")]
    CapacityLimited(usize),
    /// 路由决策失败
    #[error("路由决策失败: {0}")]
    Route(#[from] anyhow::Error),
}

/// bind_mapping 结果：命中已有映射复用（不重建），或新建并启动 forwarder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    Created,
    Reused,
}

pub struct UdpSessionTable {
    pub(crate) config: UdpSessionConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) router: Arc<dyn FlowRouter>,
    pub(crate) metrics: Arc<TableMetrics>,
    pub(crate) sessions: DashMap<UdpSessionKey, Arc<UdpSessionInner>>,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) shutdown_rx: watch::Receiver<bool>,
}

/// 错误分类（udp-relay-path.md §3.6）：发送失败 → FailureType 记账。
/// ConnectionRefused → Timeout（§3.2：目标端口未开，映射保留待空闲回收）。
pub fn classify_failure(e: &anyhow::Error) -> FailureType {
    let s = format!("{e:#}").to_lowercase();
    if s.contains("timeout") || s.contains("timed out") || s.contains("refused") {
        FailureType::Timeout
    } else if s.contains("mtu") {
        // wg MTU 超限：包本身丢弃（R8），映射保留待空闲回收（§3.6 Timeout 行）
        FailureType::Timeout
    } else if s.contains("route")
        || s.contains("unreachable")
        || s.contains("dns")
        || s.contains("resolve")
        || s.contains("allowed_ips")
        || s.contains("解析")
    {
        FailureType::Route
    } else {
        FailureType::Connection
    }
}

/// 决策对应的逻辑链标识（P0-1 约定；runtime 侧 ChainManager 的 chain_id
/// 须映射到同一字符串口径，见 udp-relay-path.md §4.2）
pub fn chain_id_of(decision: &RouteDecision) -> String {
    match &decision.path {
        crate::RoutePath::Direct { node } => format!("direct:{node}"),
        crate::RoutePath::ThroughGroup { group, .. } => format!("group:{group}"),
        crate::RoutePath::Chain { hops } => format!(
            "chain:{}",
            hops.iter()
                .map(|h| h.node.as_str())
                .collect::<Vec<_>>()
                .join("->")
        ),
    }
}

impl UdpSessionTable {
    pub fn new(
        config: UdpSessionConfig,
        router: Arc<dyn FlowRouter>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Ok(Arc::new(Self {
            config,
            clock,
            router,
            metrics: TableMetrics::new(),
            sessions: DashMap::new(),
            shutdown_tx,
            shutdown_rx,
        }))
    }

    pub fn config(&self) -> &UdpSessionConfig {
        &self.config
    }

    pub fn metrics(&self) -> &Arc<TableMetrics> {
        &self.metrics
    }

    /// 关停信号（reclaimer 与 forwarder 观测；置位后 forward_up 直接丢弃）
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn is_shutdown(&self) -> bool {
        *self.shutdown_rx.borrow()
    }

    pub(crate) fn now(&self) -> u64 {
        self.clock.now_epoch()
    }

    /// 查找已有会话；不存在返回 None（不隐式创建——创建只走 resolve 的容量门）
    pub fn get(&self, key: &UdpSessionKey) -> Option<Arc<UdpSessionInner>> {
        self.sessions.get(key).map(|e| Arc::clone(e.value()))
    }

    /// 解析（或按容量门创建）会话并保证粘滞决策就绪（api 文档 §3.3）。
    /// 会话满：返回 CapacityLimited，绝不逐出存活会话。
    pub async fn resolve(
        self: &Arc<Self>,
        key: &UdpSessionKey,
        target: &FlowTarget,
    ) -> Result<SessionRef, ResolveError> {
        if self.is_shutdown() {
            return Err(ResolveError::Route(anyhow::anyhow!("udp 会话表已关停")));
        }
        let inner = match self.sessions.get(key) {
            Some(e) => Arc::clone(e.value()),
            None => self.create_session(key)?,
        };
        let r = SessionRef {
            table: Arc::clone(self),
            inner,
        };
        // 粘滞决策：缓存命中直接用；失效（链路故障置 None）则重路由
        r.ensure_decision(target).await?;
        Ok(r)
    }

    fn create_session(
        self: &Arc<Self>,
        key: &UdpSessionKey,
    ) -> Result<Arc<UdpSessionInner>, ResolveError> {
        use dashmap::mapref::entry::Entry;
        // 容量门在 entry 之前：entry 持分片写锁期间不得调 len()/iter()（DashMap 死锁）
        // 并发窗口下允许极小超卖（分片 map 的软门语义）
        let active = self.sessions.len();
        if active >= self.config.max_sessions {
            self.metrics.drop_inc(DropReason::SessionLimit);
            return Err(ResolveError::CapacityLimited(active));
        }
        match self.sessions.entry(key.clone()) {
            Entry::Occupied(e) => Ok(Arc::clone(e.get())),
            Entry::Vacant(slot) => {
                let id = FlowId::new();
                let (tx, rx) = mpsc::channel(self.config.downlink_capacity);
                let inner = Arc::new(UdpSessionInner {
                    key: key.clone(),
                    id: id.clone(),
                    ledger: SessionLedger::create(id),
                    decision: RwLock::new(None),
                    mappings: std::sync::Mutex::new(std::collections::HashMap::new()),
                    downlink_tx: tx,
                    downlink_rx: tokio::sync::Mutex::new(Some(rx)),
                    last_activity: AtomicU64::new(self.now()),
                    created_at_epoch: self.now(),
                    decisions: AtomicU64::new(0),
                });
                slot.insert(Arc::clone(&inner));
                self.metrics.sessions_total.fetch_add(1, Ordering::Relaxed);
                self.metrics.sessions_active.fetch_add(1, Ordering::Relaxed);
                Ok(inner)
            }
        }
    }

    /// 上行快路径（api 文档 §3.2）：命中映射即发，未命中由调用方走慢路径。
    pub async fn forward_up(
        self: &Arc<Self>,
        key: &UdpSessionKey,
        target: &FlowTarget,
        data: Bytes,
    ) -> UpResult {
        if self.is_shutdown() {
            self.metrics.drop_inc(DropReason::ShuttingDown);
            return UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            };
        }
        let inner = match self.sessions.get(key) {
            Some(e) => Arc::clone(e.value()),
            None => return UpResult::Miss,
        };
        let fkey = FlowTargetKey::of(target);
        let mapping = {
            let map = inner.mappings.lock().unwrap();
            map.get(&fkey).cloned()
        };
        let mapping = match mapping {
            Some(m) => m,
            None => return UpResult::Miss,
        };
        send_via_mapping(&inner, &mapping, target, data, self.now(), &self.metrics).await
    }

    /// 强制吊销会话（ASSOCIATE 控制连接关闭 / 管理指令）。关下行、再摘映射、
    /// 后计数（teardown 顺序，udp-session-table.md §5.2）。返回会话是否存在。
    pub fn force_revoke(&self, key: &UdpSessionKey) -> bool {
        match self.sessions.remove(key) {
            Some((_, inner)) => {
                let removed = close_all_mappings(&inner);
                self.metrics
                    .mappings_active
                    .fetch_sub(removed as i64, Ordering::Relaxed);
                self.metrics.expired_inc(ExpireReason::Revoked);
                self.metrics.sessions_active.fetch_sub(1, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// 链路故障同步处理：决策缓存失效 + 相关会话映射吊销。
    /// 返回吊销的映射数（观测用）。`attach_chain_events` 的 pump 逐事件调用本方法。
    pub fn handle_chain_failure(&self, event: &ChainFailureEvent) -> usize {
        let mut revoked_total = 0usize;
        for item in self.sessions.iter() {
            let inner = item.value();
            // 决策是否骑在故障链上
            let invalidated = {
                let d = inner.decision.read().unwrap();
                matches!(&*d, Some(dec) if chain_id_of(dec) == event.chain_id)
            };
            if invalidated {
                *inner.decision.write().unwrap() = None;
            }
            if let Some(_failed_nodes) = inner
                .ledger
                .on_link_failure(&event.chain_id, &event.failed_nodes)
            {
                // 会话粘滞单链：链故障即吊销该会话全部映射（设计 R2；
                // 未受影响会话由 ledger 的链绑定门禁隔离）
                let mut map = inner.mappings.lock().unwrap();
                let revoked = map.len();
                for (_, m) in map.drain() {
                    m.close();
                }
                drop(map);
                if revoked > 0 {
                    self.metrics
                        .mappings_active
                        .fetch_sub(revoked as i64, Ordering::Relaxed);
                    revoked_total += revoked;
                }
            }
        }
        revoked_total
    }

    /// 订阅链路故障事件流（runtime 接线点；测试直接调 handle_chain_failure）
    pub fn attach_chain_events(self: &Arc<Self>, mut rx: mpsc::Receiver<ChainFailureEvent>) {
        let table = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                table.handle_chain_failure(&ev);
            }
        });
    }

    /// 表快照（/flows 与 seepctl stats 渲染）
    pub fn snapshot(&self) -> TableSnapshot {
        let now = self.now();
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for item in self.sessions.iter() {
            let inner = item.value();
            let usage = inner.ledger.usage();
            let mappings = inner.mappings.lock().unwrap().len();
            sessions.push(SessionSnapshot {
                client: inner.key.client.to_string(),
                user: inner.key.user.clone(),
                age_secs: inner.age_secs(now),
                idle_secs: inner.idle_secs(now),
                mappings,
                bytes_uploaded: usage.bytes_uploaded,
                bytes_downloaded: usage.bytes_downloaded,
                packets_count: usage.packets_count,
                current_path: inner.ledger.current_path(),
                reconnect_count: usage.reconnect_count,
            });
        }
        let drop_names = [
            (DropReason::SessionLimit, "session_limit"),
            (DropReason::MappingLimit, "mapping_limit"),
            (DropReason::NoBinding, "no_binding"),
            (DropReason::ShuttingDown, "shutting_down"),
            (DropReason::SendFailed, "send_failed"),
            (DropReason::DownlinkFull, "downlink_full"),
        ];
        let expire_names = [
            (ExpireReason::Idle, "idle"),
            (ExpireReason::Lifetime, "lifetime"),
            (ExpireReason::Revoked, "revoked"),
        ];
        TableSnapshot {
            sessions_active: self.sessions.len(),
            sessions_total: self.metrics.sessions_total.load(Ordering::Relaxed),
            mappings_active: self.metrics.mappings_active.load(Ordering::Relaxed),
            reroutes: self.metrics.reroutes.load(Ordering::Relaxed),
            bytes_up: self.metrics.bytes_up(),
            bytes_down: self.metrics.bytes_down(),
            dropped: drop_names
                .into_iter()
                .map(|(r, n)| (n.to_string(), self.metrics.drop_count(r)))
                .collect::<BTreeMap<_, _>>(),
            expired: expire_names
                .into_iter()
                .map(|(r, n)| (n.to_string(), self.metrics.expired_count(r)))
                .collect::<BTreeMap<_, _>>(),
            sessions,
        }
    }
}

/// 上行发送共用路径（forward_up 与 SessionRef::send_up 共用）
pub(crate) async fn send_via_mapping(
    inner: &Arc<UdpSessionInner>,
    mapping: &Arc<MappingShared>,
    target: &FlowTarget,
    data: Bytes,
    now: u64,
    metrics: &TableMetrics,
) -> UpResult {
    inner.touch(now);
    mapping.touch(now);
    inner.ledger.on_packet(Dir::Up, data.len());
    match mapping.relay.send_to(target, &data).await {
        Ok(()) => {
            mapping.count_up(data.len());
            // P0-5 §2.5：表级字节与 per-mapping 同点顺带累加（渲染零扫描）
            metrics.count_bytes(Dir::Up, data.len());
            mapping.consecutive_errors.store(0, Ordering::Relaxed);
            UpResult::Sent
        }
        Err(e) => {
            // 错误分类契约（udp-relay-path.md §3.6）：分类记账 + 分级 teardown
            let ft = classify_failure(&e);
            match &ft {
                FailureType::Route => {
                    // 路由不可达：映射关闭 + 决策缓存清除（触发重路由）
                    mapping.close();
                    *inner.decision.write().unwrap() = None;
                }
                FailureType::Timeout => {
                    // 目标不可达/超时：映射保留待空闲回收（游戏服务器
                    // "不回首个包"的探测不被 ICMP 立即拆映射）
                    mapping.consecutive_errors.store(0, Ordering::Relaxed);
                }
                FailureType::Connection => {
                    // 传输 IO 错误：连续 ≥3 次触发映射重建
                    let n = mapping.consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
                    if n >= 3 {
                        mapping.close();
                    }
                }
            }
            inner.ledger.on_error(ft);
            metrics.drop_inc(DropReason::SendFailed);
            UpResult::Dropped {
                reason: DropReason::SendFailed,
            }
        }
    }
}

fn close_all_mappings(inner: &Arc<UdpSessionInner>) -> usize {
    let mut map = inner.mappings.lock().unwrap();
    let n = map.len();
    for (_, m) in map.drain() {
        m.close();
    }
    n
}

/// 会话句柄：resolve 返回给中继路径（socks5 handler / egress 接线）。
pub struct SessionRef {
    pub(crate) table: Arc<UdpSessionTable>,
    pub(crate) inner: Arc<UdpSessionInner>,
}

impl SessionRef {
    pub fn key(&self) -> &UdpSessionKey {
        &self.inner.key
    }

    pub fn id(&self) -> &FlowId {
        &self.inner.id
    }

    pub fn ledger(&self) -> &SessionLedger {
        &self.inner.ledger
    }

    pub fn table(&self) -> &Arc<UdpSessionTable> {
        &self.table
    }

    /// 当前粘滞决策（None = 已失效待重路由）
    pub fn decision(&self) -> Option<Arc<RouteDecision>> {
        self.inner.decision.read().unwrap().clone()
    }

    /// 保证决策就绪：缓存命中直接用；否则路由 + 回写 + 链绑定。
    pub(crate) async fn ensure_decision(
        &self,
        target: &FlowTarget,
    ) -> Result<Arc<RouteDecision>, ResolveError> {
        if let Some(d) = self.decision() {
            return Ok(d);
        }
        let ctx = FlowContext {
            id: self.inner.id.clone(),
            target: target.clone(),
            metadata: FlowMetadata::default(),
        };
        let decision = Arc::new(
            self.table
                .router
                .route(ctx)
                .await
                .map_err(ResolveError::Route)?,
        );
        let prev_decisions = self.inner.decisions.fetch_add(1, Ordering::Relaxed);
        if prev_decisions > 0 {
            // 非首次决策 = 链路失效后的重路由（指标口径：udp_reroutes_total）
            self.table.metrics.reroutes.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.ledger.on_route_changed(&decision);
        self.inner.ledger.attach_chain(&chain_id_of(&decision));
        *self.inner.decision.write().unwrap() = Some(Arc::clone(&decision));
        Ok(decision)
    }

    /// 绑定目标映射：命中即复用（同一粘滞键不重建）；未命中创建映射并启动
    /// forwarder task（下行收包 → downlink 通道）。映射超上界先逐最久空闲。
    pub async fn bind_mapping(
        &self,
        target: &FlowTarget,
        relay: Arc<dyn UdpRelay>,
    ) -> Result<BindOutcome, ResolveError> {
        let fkey = FlowTargetKey::of(target);
        {
            let map = self.inner.mappings.lock().unwrap();
            if map.contains_key(&fkey) {
                return Ok(BindOutcome::Reused);
            }
        }
        // 映射创建前需要决策就绪（决策失效时此处触发重路由）
        self.ensure_decision(target).await?;

        let (close_tx, close_rx) = watch::channel(false);
        let now = self.table.now();
        let mapping = Arc::new(MappingShared {
            relay,
            last_activity: AtomicU64::new(now),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            pkts_up: AtomicU64::new(0),
            pkts_down: AtomicU64::new(0),
            close_tx,
            consecutive_errors: AtomicU64::new(0),
        });

        let mut map = self.inner.mappings.lock().unwrap();
        // 双检：并发绑定同目标只保留先到者（Reused，不重建）
        if map.contains_key(&fkey) {
            drop(map);
            return Ok(BindOutcome::Reused);
        }
        // 上界：溢出逐最久空闲（设计 §4.2 LRU）
        if map.len() >= self.table.config.max_mappings {
            let victim = map
                .iter()
                .min_by_key(|(_, m)| m.last_activity.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            if let Some(vk) = victim {
                if let Some(vm) = map.remove(&vk) {
                    vm.close();
                    self.table
                        .metrics
                        .mappings_active
                        .fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
        map.insert(fkey, Arc::clone(&mapping));
        drop(map);
        self.table
            .metrics
            .mappings_active
            .fetch_add(1, Ordering::Relaxed);

        // forwarder task（表侧持有，udp-relay-path.md §4）
        let fwd = ForwarderTask {
            inner: Arc::clone(&self.inner),
            mapping,
            target: target.clone(),
            close_rx,
            downlink_tx: self.inner.downlink_tx.clone(),
            metrics: Arc::clone(&self.table.metrics),
            clock: Arc::clone(&self.table.clock),
        };
        tokio::spawn(fwd.run());
        Ok(BindOutcome::Created)
    }

    pub fn has_mapping(&self, target: &FlowTarget) -> bool {
        let fkey = FlowTargetKey::of(target);
        self.inner.mappings.lock().unwrap().contains_key(&fkey)
    }

    /// 上行发送（快路径；Miss 时调用方决定是否重新 associate + bind）
    pub async fn send_up(&self, target: &FlowTarget, data: Bytes) -> UpResult {
        if self.table.is_shutdown() {
            self.table.metrics.drop_inc(DropReason::ShuttingDown);
            return UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            };
        }
        let fkey = FlowTargetKey::of(target);
        let mapping = { self.inner.mappings.lock().unwrap().get(&fkey).cloned() };
        match mapping {
            Some(m) => {
                send_via_mapping(
                    &self.inner,
                    &m,
                    target,
                    data,
                    self.table.now(),
                    &self.table.metrics,
                )
                .await
            }
            None => UpResult::Miss,
        }
    }

    /// 取走下行接收端（入站 handler 一次性持有；None = 已被取走）
    pub async fn take_downlink_rx(&self) -> Option<mpsc::Receiver<DownlinkPacket>> {
        self.inner.downlink_rx.lock().await.take()
    }
}

/// 每映射一个的下行 forwarder：relay.recv → 会话 downlink 通道。
/// 满即丢（UDP 无背压）+ DownlinkFull 计数；关闭信号或 relay 错误时退出并
/// 吊销映射。全部 IO 在锁外。
struct ForwarderTask {
    inner: Arc<UdpSessionInner>,
    mapping: Arc<MappingShared>,
    target: FlowTarget,
    close_rx: watch::Receiver<bool>,
    downlink_tx: mpsc::Sender<DownlinkPacket>,
    metrics: Arc<TableMetrics>,
    clock: Arc<dyn Clock>,
}

impl ForwarderTask {
    async fn run(mut self) {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                // close 信号只发一次 true，发送端 drop 也会触发 changed 的 Err——
                // 任一情况都意味着本映射应退出
                _ = self.close_rx.changed() => break,
                r = self.mapping.relay.recv_from(&mut buf) => match r {
                    Ok((from, n)) => {
                        let now = self.clock.now_epoch();
                        self.inner.touch(now);
                        self.mapping.touch(now);
                        self.mapping.count_down(n);
                        // P0-5 §2.5：表级字节与 per-mapping 同点顺带累加
                        self.metrics.count_bytes(Dir::Down, n);
                        self.inner.ledger.on_packet(Dir::Down, n);
                        let pkt = DownlinkPacket { target: from, data: Bytes::copy_from_slice(&buf[..n]) };
                        if let Err(e) = self.downlink_tx.try_send(pkt) {
                            match e {
                                mpsc::error::TrySendError::Full(_) => {
                                    self.metrics.drop_inc(DropReason::DownlinkFull);
                                }
                                mpsc::error::TrySendError::Closed(_) => break,
                            }
                        }
                    }
                    Err(e) => {
                        // 上游链路错误：记账 + 吊销自身映射，映射级故障不上抛会话
                        self.inner.ledger.on_error(classify_failure(&e));
                        break;
                    }
                },
            }
        }
        // teardown：关闭信号（防重复）→ 从表内摘除 → 计数
        self.mapping.close();
        {
            let mut map = self.inner.mappings.lock().unwrap();
            let fkey = FlowTargetKey::of(&self.target);
            if let Some(m) = map.remove(&fkey) {
                if Arc::ptr_eq(&m, &self.mapping) {
                    self.metrics.mappings_active.fetch_sub(1, Ordering::Relaxed);
                } else {
                    // 已被 LRU/吊销替换：把别人的映射放回去不动计数
                    map.insert(fkey, m);
                }
            }
        }
    }
}
