# P0-1 接口草案：UDP 会话表 API 与回收算法

> 状态：**已实施（todo P0-1 完成，2026-09）**· 实施面 = `crates/rillane-core/src/udp/`（下文 §2.2 草案签名与实施的差异以 §9 裁决表为准）· 设计依据：[udp-session-table.md](udp-session-table.md)（本文不重复论证，只给可转录的 API/算法）· 总设计：[udp-dataplane.md](udp-dataplane.md) · 中继路径契约：[udp-relay-path.md](udp-relay-path.md) §4 · 对应 [todo.md](../../../todo.md) P0-1
> 假设（如与实施冲突需回改本稿）：A1 时基用进程单调时钟秒值（免 NTP 跳变）；A2 下行通道容量 64 沿用 udp-relay-path.md §4.3；A3 `FlowSession` 结构不改（O7 走 wrapper，见 §4.4）；A4 指标命名沿 [udp-observability.md](udp-observability.md) §2.4（落地定稿）。

## 执行摘要

给出 `rillane-core::udp` 的**完整公共 API 草案**：模块布局与可见性、`UdpSessionTable`/`SessionRef`/`SessionLedger` 全部签名、超时回收的可转录伪码（epoch 时基 + 二次确认移除 + 锁外 teardown）、并发锁序与内存序契约、测试用时钟注入。目标：实施时可按本稿逐签名转录，设计权衡回看 udp-session-table.md 对应节。

## 1. 模块布局与可见性

```
crates/rillane-core/src/udp/
├── mod.rs          # pub use 公共面；模块文档（本文摘要）
├── key.rs          # UdpSessionKey / ProcessIdentity          （全 pub）
├── config.rs       # UdpSessionConfig + Default + validate     （pub）
├── table.rs        # UdpSessionTable / SessionRef / ResolveError / UpResult（pub）
├── inner.rs        # UdpSessionInner / UdpMapping / UdpBinding（pub(crate)，Binding 除外）
├── ledger.rs       # SessionLedger（§4，pub——入站/出站都要记账）
├── reclaim.rs      # 回收任务（pub(crate)；spawn 入口 pub）
├── metrics.rs      # TableMetrics / TableSnapshot（pub）
└── clock.rs        # Clock trait + RealClock（pub）/ MockClock（cfg(test)）
```

依赖方向：`table → inner/ledger/reclaim/metrics`；`reclaim → inner`；无环。`UdpBinding` 中 `Relay(Box<dyn UdpRelay>)` 需要 `UdpRelay`（udp-dataplane.md §1.2）— trait 定义留在 `rillane-core::udp`，避免 protocols 反向依赖 runtime。

## 2. 公共 API 草案

### 2.1 配置与键

```rust
pub struct UdpSessionConfig {
    pub mapping_idle: Duration,        // 默认 60s
    pub session_idle: Duration,        // 默认 180s
    pub sweep_interval: Duration,      // 默认 15s
    pub max_sessions: usize,           // 默认 4096
    pub max_mappings: usize,           // 默认 256/会话
    pub session_max_lifetime: Option<Duration>, // 默认 None
    pub downlink_capacity: usize,      // 默认 64（A2）
}
impl UdpSessionConfig { pub fn validate(&self) -> Result<()>; }  // 0 < idle 关系校验

pub struct UdpSessionKey {
    pub client: SocketAddr,            // 基线，恒有
    pub user: Option<String>,          // 小写化后参与哈希
    pub process: Option<ProcessIdentity>,
}
pub struct ProcessIdentity { pub pid: u32, pub name: String }
// derive Clone/Eq/Hash；Hash 全字段参与（维度出现即区分，udp-session-table.md §3.1）
```

### 2.2 UdpSessionTable

```rust
pub struct UdpSessionTable { /* DashMap + AtomicUsize live_count + config + metrics + clock */ }

impl UdpSessionTable {
    pub fn new(config: UdpSessionConfig, metrics: Arc<TableMetrics>, clock: Arc<dyn Clock>) -> Self;

    /// 每包入口（快路径优先）：命中→Sent；未命中→Miss（调用方改走 resolve，或放弃）
    pub async fn forward_up(&self, key: &UdpSessionKey, target: &FlowTarget, data: Bytes) -> UpResult;

    /// 慢路径：未命中时路由决策并建会话+首映射；满员→Err(CapacityLimited)
    pub async fn resolve(
        &self,
        key: UdpSessionKey,
        ctx: FlowContext,                 // 首包目标
        router: Arc<dyn FlowRouter>,
    ) -> Result<SessionRef, ResolveError>;

    /// ASSOCIATE 控制连接关闭等强制回收（udp-relay-path.md §2.5）；返回是否确实存在并移除了该会话
    pub fn force_revoke(&self, key: &UdpSessionKey) -> bool;

    /// 链路故障事件源（ChainManager），驱动决策缓存失效（udp-session-table.md §3.4）
    pub fn attach_chain_events(self: &Arc<Self>, rx: mpsc::Receiver<ChainFailureEvent>);

    /// 启动周期回收任务（sweep_interval；单一任务，重复调用 no-op）
    pub fn spawn_reclaimer(self: &Arc<Self>) -> JoinHandle<()>;

    /// /flows 与 rillanectl stats 快照
    pub fn snapshot(&self) -> TableSnapshot;
}

pub enum UpResult { Sent, Miss, Dropped { reason: DropReason } }
pub enum DropReason { SessionLimit, MappingLimit, NoBinding, ShuttingDown }
pub enum ResolveError { CapacityLimited, Route(anyhow::Error) }   // Route 不重试（决策失败按现有路由错误语义）

/// resolve 成功返回的句柄：Arc 内层 + 便捷方法；克隆廉价
#[derive(Clone)]
pub struct SessionRef { inner: Arc<UdpSessionInner> }
impl SessionRef {
    pub fn ledger(&self) -> &SessionLedger;
    pub fn key(&self) -> &UdpSessionKey;
    pub fn decision(&self) -> Arc<RouteDecision>;   // 粘滞决策只读视图
    pub fn id(&self) -> FlowId;                     // 同时供 mesh envelope flow_id
}
```

- `forward_up` 为**同步快路径**：命中时不进 async（锁内 send 直发，`UdpBinding::Local` 是已 connect 的 socket；`Relay` 走 `UdpRelay::send_to` 的同步封装——QUIC/socket 直发均为非阻塞）；
- 未命中返回 `Miss` 把决策权留给调用方：入站可选择丢弃小包（如游戏首包前的探测）或走 `resolve`，避免慢路径隐藏在表内。

### 2.3 快照

```rust
pub struct TableSnapshot {
    pub sessions_active: usize,   pub sessions_total: u64,
    pub mappings_active: usize,
    pub dropped: BTreeMap<DropReason, u64>,
    pub expired: BTreeMap<ExpireReason, u64>,
    pub reroutes: u64,            // 决策失效重路由计数
    pub sessions: Vec<SessionSnapshot>,   // 每会话：key（脱敏后）、age、idle、mappings 数、usage 摘要
}
pub enum ExpireReason { Idle, Lifetime, Revoked }
```

## 3. 超时回收算法（可转录伪码）

### 3.1 时基

`last_activity: AtomicU64` = **进程单调时钟秒值**（`clock.now_epoch()`，A1；RealClock 基于 `Instant` 起点，MockClock 可拨动）。取 `Relaxed` 序——单值新鲜度，无跨变量顺序依赖（§5.2）。`created_at_epoch: u64` 同基，供 lifetime 上限判定。

### 3.2 sweep 主循环

```
fn sweep(self, now: u64):
    expired: Vec<(UdpSessionKey, Arc<Inner>)> = []
    for shard in self.sessions.shards():
        # 读锁仅做判定，不删
        for (key, inner) in shard.read().iter():
            idle = now - inner.last_activity.load(Relaxed)
            if idle * 1s >= config.session_idle
               or (lifetime 启用 and now - inner.created_at_epoch >= lifetime):
                expired.push((key.clone(), inner.clone()))
    removed = 0
    for (key, inner) in expired:
        # DashMap::remove 原子；抢到的那个执行 teardown（二次确认语义，防并发重复回收）
        if let Some((_, inner)) = self.sessions.remove(&key):
            self.teardown(inner, ExpireReason::Idle_or_Lifetime)
            removed += 1
    self.metrics.set_active(self.live_count.load(Relaxed))
    # 映射级回收随 resolved/forward_up 惰性进行 + sweep 内轻扫（§3.3）
```

- **二次确认**：`remove` 的原子性天然保证同一会话只被一个 sweep 迭代真正回收；`force_revoke` 走同一 `remove + teardown` 路径，`ExpireReason::Revoked`；
- **不设批上限**：remove/teardown 单项为微秒级且不持读锁（见 §3.3），4096 项最坏一轮也在毫秒级；sweep 间隔可选 ±10% 抖动避开与其他周期任务对齐（非必须，默认关）。

### 3.3 映射级回收

```
fn sweep_mappings(inner: &Inner, now: u64):
    dead: Vec<FlowTargetKey> = []
    mappings.lock():
        for (k, m) in cache.iter():
            if now - m.last_activity_epoch >= mapping_idle: dead.push(k)
        for k in dead: cache.pop(&k)            # 锁内仅摘表
    for k in dead: teardown_binding(inner.take_binding(k))   # 锁外关 socket/relay（§5.1）
```

锁内只做表操作，IO 取消（drop binding、forwarder task 随 Sender 关闭退出）一律在锁外——锁序契约（§5.1）的强制项。

### 3.4 teardown（回收动作，udp-session-table.md §4.5 的函数化）

```
fn teardown(inner: Arc<Inner>, reason: ExpireReason):
    inner.downlink_tx.close()        # 1) 先断下行 → forwarder 逐个自然退出
    inner.take_all_bindings()        # 2) 取走 bindings（drop = 关闭）
    inner.ledger.snapshot() 入日志    # 3) 终态快照（可选 debug 级）
    metrics.expired[reason] += 1; live_count -= 1    # 4) 指标
```

in-flight 包安全：`resolve` 发出的 `SessionRef` 持 `Arc`，teardown 后其 send 落在已关闭 binding 上 → 返回 `UpResult::Dropped{NoBinding}`，调用方按丢包处理（UDP 语义，无异常路径）。

### 3.5 准入控制

`resolve` 慢路径先直读 `sessions.len()`（DashMap 长度，`table.rs:180`）≥ `max_sessions` → `Err(CapacityLimited)`（对应指标 `dropped{SessionLimit}`，拒新不逐旧）。草案中的独立 `live_count` 原子量**未实施**：容量门即直读实际长度，分片 map 软门语义下并发窗口允许极小超卖（§9-#12/#15），active 口径由 `TableMetrics` 原子量维护。

## 4. FlowSession 集成接口草案（SessionLedger）

### 4.1 单写入口

`FlowSession` 方法带副作用（`update_route` 置 Active、`record_failure` 置 Failed），多点直调易破不变式。**所有写经 `SessionLedger` 收口**：

```rust
pub struct SessionLedger { session: RwLock<FlowSession>, chain: Mutex<Option<ChainContext>> }

impl SessionLedger {
    /// 仅表内构造：FlowSession::new(FlowId::new(), ctx.target.clone()) + client_info 填充
    pub(crate) fn create(key: &UdpSessionKey, ctx: &FlowContext, auth: Option<AuthInfo>) -> Self;

    /// 每包记账：usage.update_usage(bytes) + usage.packets_count += 1
    ///   + last_active 刷新 + （O7 规则）Failed → Active 恢复
    pub fn on_packet(&self, dir: Dir, bytes: u64);

    /// 决策变更（首包不调；链路迁移时调）：update_route(path, reason) + RouteHistory(success=true)
    pub fn on_route_changed(&self, path: Vec<String>, reason: String);

    /// 链路故障迁移：RouteHistory(success=false, error=cause) + reconnect_count += 1
    ///   + ChainContext.switch_fallback_path()（有候选时），返回新 path 供表更新 CachedDecision
    pub fn on_link_failure(&self, failed_path: &[String], cause: &str) -> Option<Vec<String>>;

    /// relay 错误记账：record_failure(f)（会置 Failed——恢复规则在 on_packet，§4.4/O7）
    pub fn on_error(&self, f: FailureType);

    /// chain 决策创建时挂上下文：ChainContext::new(chain_id, source, target)
    pub fn attach_chain(&self, cc: ChainContext);

    pub fn snapshot(&self) -> FlowSession;            // Clone 供诊断/快照
    pub fn usage(&self) -> SessionUsage;
}
```

### 4.2 与表的协作时序

```
首包：resolve → router.route(ctx) → create ledger → (Chain?) attach_chain
      → mappings 建映射 → ledger.on_packet(Up, len)
迁移：chain 事件 → 表清 CachedDecision → 下一包重路由 → decision 变更
      → ledger.on_link_failure(old_path, cause) 拿 fallback 新 path
      → 成功后 ledger.on_route_changed(new_path, "chain-failover")
错误：binding send/recv Err → 分类（udp-relay-path.md §3.6）→ ledger.on_error(FailureType::*)
```

实施注（§9-#16）：`on_link_failure` 实况只做 `on_error(FailureType::Route)` 并**原样返回 `failed_nodes`**（`ledger.rs:63-73`），不切换 fallback——`add_fallback_path`/`switch_fallback_path` 在 UDP 面无调用点，链路失效后的重路由由 runtime 侧 ChainFailureEvent 驱动（下一包重路由 → `on_route_changed`）；草案的 `reconnect_count += 1` 无对应自增点（字段仅透传）。

### 4.3 字段对照（承 udp-session-table.md §5.2，API 落点）

`client_info.address` ← 键 `client`；`auth_info` ← ASSOCIATE 认证结果；`id` → mesh envelope `flow_id`；`usage.packets_count` 在 `on_packet` 维护（`update_usage` 不覆盖）；`current_path`/`route_history` 仅经 `on_route_changed`/`on_link_failure` 变更。

### 4.4 O7 wrapper 语义（本稿唯一"改行为"处，不改源码结构）

`on_packet` 开头：`if session.status == Failed { session.status = Active }`——Failed 只作为"自上次成功包以来出现过错误"的观测信号，不终结会话。若上游未来接受可恢复 Failed 语义（O7），删此三行即可，无其他迁移。

## 5. 并发契约

### 5.1 锁序（强制，违序即死锁风险）

```
DashMap shard (读，判定用，最短)  →  inner.mappings Mutex  →  ledger RwLock/Mutex
```

- 任何路径不得逆序；teardown/sweep_mappings 的 IO 操作全部在锁外（§3.3）；
- `force_revoke` 与 sweep 竞争同一会话：`DashMap::remove` 原子性仲裁，败者拿到 None 直接返回。

### 5.2 内存序

| 变量 | 序 | 理由 |
|------|-----|------|
| `last_activity` / `created_at_epoch` | Relaxed | 单变量新鲜度判定，无跨变量顺序 |
| `live_count`（草案，未实施） | — | 实况无独立原子量：容量门直读 `sessions.len()`，软门允许偏差（§9-#15） |
| `decision` / `ledger.session` | RwLock 默认 | 需要与映射变更互见，标准同步 |

### 5.3 task 生命周期

forwarder task 持 `Arc<Inner>` + 自己的 `UdpBinding` 一半；teardown 先 `downlink_tx.close()` 再 drop bindings → task 在下一次 recv Err/None 退出，不 require abort。表关闭（进程退出路径）：drop table 前 `force_revoke` 全表（由 `RuntimeBuilder` 关停序列调用，顺序在 mesh data-plane 停止之后）。

## 6. 测试挂钩

- `Clock` trait（`now_epoch`）+ `MockClock`：手动拨秒，**超时类验收全部确定性化**——不 sleep 真实时间；
- `TableMetrics` 计数器直读断言（不解析 Prometheus 文本）；
- `UdpRelay` 提供 `MockRelay`（可编程 send/recv Err 序列）驱动 §3.6/udp-relay-path.md §3.6 错误分类测试。

## 7. 验收映射（P0-1 原文 → 本稿落点）

| 验收 | 本稿落点 |
|------|---------|
| 会话创建/查询/超时回收有单测 | `resolve`/`forward_up` + MockClock 驱动 sweep（§3.2/§6）；五项测试清单见 udp-session-table.md §7 |
| 同一粘滞键复用映射不重建 | `forward_up` 命中路径 `Sent` 且 `snapshot().mappings_active` 不变；决策代数不变 |
| （设计内）满员拒绝 | §3.5 `CapacityLimited` + `dropped{SessionLimit}` |
| （设计内）决策失效 | `attach_chain_events` + `on_link_failure` 迁移时序（§4.2） |

## 8. 边界与衔接

- 本稿为 **P0-1 单条目接口草案**；`UdpRelay`/`EgressUdpConnector` 的出站侧契约、SOCKS5 入站解析在 [udp-relay-path.md](udp-relay-path.md)；mesh 跳间 flow 缓存复用本表 `last_activity` 常量但**不共用表实例**（relay 侧无路由决策，独立轻表，P0-4 实施时给出）；
- 实施若发现签名不适配（如 `forward_up` 同步化不可行——`Relay` 出站需要 async send），允许放宽为 `async fn forward_up`，但 §5 锁序与锁外 IO 原则不可让步；
- 本文完成后 P0-1 的三份文档链：总设计（udp-dataplane.md §1）→ 设计依据（udp-session-table.md）→ **接口草案（本稿）**。

## 9. 实施注记（P0-1 落地裁决，代码位于 `crates/rillane-core/src/udp/`）

实施时与草案的偏差与澄清，均已按 §8 的放宽许可裁决，锁序与锁外 IO 未动：

| # | 草案 | 实施 | 裁决理由 |
|---|------|------|---------|
| 1 | `forward_up` 同步 | `async fn forward_up`（§8 已预留） | `UdpRelay::send_to` 为 async；慢路径照旧 |
| 2 | `UdpBinding` 枚举（Bound/Ephemeral） | 统一 `Arc<MappingShared>`（含关闭 watch + 四原子计数） | 草案两态的"无 relay 临时态"在实施中不存在：映射创建必须先有 relay，枚举退化 |
| 3 | `MappingShared.relay: Box<dyn UdpRelay>` | `Arc<dyn UdpRelay>` | forwarder task 与发送路径共享所有权，Box 需额外注册表回收 |
| 4 | 新增 `SessionRef::{bind_mapping, send_up, has_mapping, take_downlink_rx}` | 同名落地 | 快路径 `Miss` 后的慢路径接线所需（socks5 handler / egress 关联） |
| 5 | 新增 `UdpSessionTable::get/get_shared` | `get(&key) -> Option<Arc<UdpSessionInner>>`（不创建） | 隐式创建收口到 `resolve` 的容量门，`forward_up` 严格只读 |
| 6 | `DropReason` 4 类 | 增 `SendFailed`/`DownlinkFull` 共 6 类 | 上行发送失败（映射吊销 + 重新关联）与下行通道满（UDP 无背压）需独立计数 |
| 7 | teardown 双路径（发送失败就地摘除 / forwarder 退出摘除） | **单点收敛**：发送失败只 `close()` 信号，摘除+扣计数统一在 forwarder 退出路径（`Arc::ptr_eq` 防误删替换后的新映射） | 消除双路径计数漂移与"删掉替换映射"竞态（实施中发现） |
| 8 | `reroutes` 口径未定 | 会话内非首次决策计数（`Inner.decisions` 原子） | 首次路由不算重路由；链路失效后的重路由 +1 |
| 9 | 链 ID 口径 | `chain_id_of(decision)`：`direct:{node}` / `group:{group}` / `chain:{hops.join("->")}` | runtime 侧 ChainManager 须映射到同一字符串（P0-2 接线点） |
| 10 | `sweep` 边界未定 | 严格大于（`idle > limit`，边界值存活） | MockClock 边界单测钉死（sweep_session_idle_expiry_boundary） |
| 11 | `TargetProto` derive | 补 `Copy + PartialEq + Eq + Hash`（lib.rs 既有类型） | `FlowTargetKey` 需作 HashMap 键；纯 derive 扩展，无语义变更 |
| 12 | DashMap entry 内做容量判定 | 容量判定移到 `entry()` 之前 | entry 持分片写锁期间调 `len()` 有同 map 死锁风险（实施中发现）；并发窗口允许极小超卖（软门语义） |
| 13 | `force_revoke` 无返回值 | `pub fn force_revoke(&self, key) -> bool` | ASSOCIATE 关闭路径需区分「确实回收」与「会话已不存在」，返回存在性布尔 |
| 14 | `attach_chain_events(&self, …)` | `pub fn attach_chain_events(self: &Arc<Self>, …)` | 事件消费 task 需持表弱/强引用跨 await，`&self` 裸引用无法 `Arc::clone` 进 task |
| 15 | 独立 `live_count` 原子量（§3.5 准入控制） | 无此变量：容量门直读 `sessions.len()`（`table.rs:180`），active 计数 = `TableMetrics` 原子量 | 独立计数与 DashMap 长度天然漂移、需 sweep 周期对账；直读零维护成本，软门语义（§8 放宽）允许并发窗口内极小超卖 |
| 16 | `on_link_failure` 切换 fallback + `reconnect_count += 1`（§4.1/§4.2） | 只 `on_error(FailureType::Route)` + 原样返回 `failed_nodes`（`ledger.rs:63-73`） | fallback 切换属 TCP `add_fallback_path` 面（UDP 无调用点）；UDP 重路由由 runtime 侧 ChainFailureEvent 驱动下一包重路由；`reconnect_count` 无自增点 |

测试锚点：`crates/rillane-core/tests/udp_session_table.rs`（**26 项**：生命周期 2、快路径与映射复用 3、超时回收 4、容量与 LRU 2、决策失效与重路由 1、吊销/关停 2、上行失败与下行满载 5、并发契约 2、ledger 直测 3、chain_id 口径 1、表级聚合 1）。
