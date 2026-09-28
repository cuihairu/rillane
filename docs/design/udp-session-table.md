# P0-1 实现级设计：seep-core NAT 式 UDP 会话表

> 状态：实现级设计稿（2026-09）· 本文是 [udp-dataplane.md](udp-dataplane.md) §1 的展开，是该条目的实现口径 · 对应 [todo.md](../../todo.md) P0-1 · 上游：[roadmap.md](roadmap.md) S1 · 缺口来源 [positioning.md](positioning.md) G1
> 本轮为设计稿：不改任何源码；文中"新增"均为 P0-1 实施工作量。

## 执行摘要

给出 `seep-core::udp` 模块中 UDP 会话表的实现级设计：**两级映射**（全局会话表 → 会话内目标映射）承担 NAT 语义；**粘滞键**按 进程 > 认证用户+五元组 > 五元组 > 源 IP 的优先级退化；**超时回收**用单任务周期扫描（映射 60s / 会话 180s / 扫描 15s），满员拒新不逐旧；与 `FlowSession` 按**组合**集成，逐字段映射，并处理两处现有语义差异（`record_failure` 置 Failed、`new()` 丢弃 target 参数）。文末给出对齐 todo P0-1 验收的测试清单。

## 1. 概念模型：三种身份

| 身份 | 含义 | 生命周期 | 对应 TCP 面 |
|------|------|---------|------------|
| **Client Identity**（粘滞键） | 谁在发：进程 / 认证用户 / 客户端地址五元组 | ASSOCIATE 建立到超时 | `Flow.io` 上的连接对端 |
| **Flow Target** | 发到哪：`FlowTarget{host, port, proto}` | 每个目标映射独立 | `Flow.target`（一对一） |
| **Upstream Binding** | 经谁走：绑定到某出站的 relay 句柄 | 目标映射空闲超时 | `Flow.io` 本身 |

TCP 面三者合一于一条 `Flow`（`Flow{id, target, io: BoxedIo}`，见 [architecture.md](../architecture.md) 关键接口）；UDP 的本质差异是 1 : N : N——一个客户端身份同时对应多个目标、每个目标一条独立绑定。会话表就是把这个 1:N:N 关系显式建模。

## 2. 映射结构：两级表

### 2.1 结构定义（`seep-core::udp`，细化自 udp-dataplane.md §1.2）

```rust
/// Level-1：全局会话表（并发分片）
pub struct UdpSessionTable {
    sessions: DashMap<UdpSessionKey, Arc<UdpSessionInner>>,
    config: UdpSessionConfig,       // §4 常量表
    stats: UdpTableStats,           // 原子计数：active/total/dropped{reason}
}

/// Level-2：会话内目标映射（有界 LRU）
pub struct UdpSessionInner {
    pub key: UdpSessionKey,
    pub decision: RwLock<CachedDecision>,   // 粘滞决策缓存（§3.4）
    pub mappings: Mutex<LruCache<FlowTargetKey, UdpMapping>>,   // 默认 256
    pub downlink_tx: mpsc::Sender<DownlinkPacket>,              // 下行通道（§2.3）
    pub session: RwLock<FlowSession>,                           // §5 集成
    pub last_activity: AtomicU64,       // epoch secs，双向任一包即刷新
    pub created_at: Instant,
}

pub struct UdpMapping {
    pub binding: UdpBinding,            // 上行绑定
    pub last_activity: Instant,         // 上/下行任一方向都刷新
    pub bytes_up: u64, pub bytes_down: u64,
    pub pkts_up: u64, pub pkts_down: u64,
}

pub enum UdpBinding {
    /// direct 出站：本地 UDP socket（已 connect 到目标）
    Local(UdpSocket),
    /// ss/hy2/wg/mesh 出站：EgressUdpConnector::associate 产出的句柄
    Relay(Box<dyn UdpRelay>),
}

pub struct DownlinkPacket {             // 上游 → 客户端方向
    pub target: FlowTarget,             // 来源目标（客户端侧封装 SOCKS5 头需要）
    pub data: Bytes,                    // bytes crate，复用 workspace 依赖
}
```

- `UdpSessionKey` / `UdpRelay` / `EgressUdpConnector` / `FlowContext` 沿用 udp-dataplane.md §1.2 定义的形状，本文不重复；差异点以下文 §3 为准（粘滞键细化）。
- **`FlowTargetKey`**：`FlowTarget` 的可哈希归一化（当前 `FlowTarget` 含 `String` host，直接可哈希；此处约定键语义——IP 字面量按文本，域名按小写原样字符串，**不做解析展开**，见 O6）。

### 2.2 上行快路径（每包）

```
recv → hash(UdpSessionKey) 查 Level-1（DashMap 读锁）
     → mappings.lock() 查/建 Level-2 映射（LRU，命中则 touch）
     → binding.send(data)；原子累加计数
```

两段临界区（shard 读 + 会话内 Mutex），无跨会话竞争；慢路径只有"首包建会话 / 新目标建映射 / 满员拒绝"三种，均一次完成。

### 2.3 下行反查：不用全局反向索引

上游数据到达后要送回客户端。方案对比：

| 方案 | 说明 | 结论 |
|------|-----|------|
| 全局反向索引 `BindingId → SessionKey` | 需与 Level-2 同步增删，双写一致性负担 | 弃 |
| **per-mapping forwarder task**（采用） | 每条映射创建时 spawn 一个 recv 循环，把收到的包连同 `target` 发进会话的 `downlink_tx`；映射回收即 task 随 `binding` drop 自然终止 | 生命周期跟随映射，无独立状态 |

入站侧（socks5 中继）持有 `downlink_rx`，把 `DownlinkPacket` 封 SOCKS5 UDP 头发回客户端。一个会话只有一条下行通道，多个目标的下行在同一 mpsc 汇聚——天然保持单客户端 socket 语义。

## 3. 粘滞键：进程 / 五元组优先级

### 3.1 键结构与优先级

```rust
pub struct UdpSessionKey {
    pub client: SocketAddr,             // 五元组的源 (ip, port)——基线，恒可用
    pub user: Option<String>,           // socks5 认证用户名（AuthInfo.username）
    pub process: Option<ProcessIdentity>, // P1 TUN 注入；P0 恒为 None
}

pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,                   // 可执行名（跨 pid 复用会话）
}
```

匹配优先级（高 → 低），按**实际可用信息**退化，退化不改变键类型：

1. `process + client` —— TUN 入站（P1-2 注入），同进程跨重启（pid 变）可经 `name` 归并；
2. `user + client` —— socks5 带认证；
3. `client` —— 无认证 socks5（NAT 后多客户端会被合并为一个会话，即上游文档 O1，已知且接受）。

`PartialEq`/`Hash` 按字段整体比较——进程/用户维度出现即参与区分，保证"同机两个游戏 = 两个会话"。

### 3.2 socks5 场景下 client 五元组的来源

ASSOCIATE 控制连接（TCP）与 UDP 数据报同源：MVP 按 udp-dataplane.md §2.2 的 `strict_udp_source` 校验**源 IP** 一致；会话键取数据报源 `(ip, port)`。同一客户端换源端口（重连中继）视为新会话——旧会话走超时回收，不做迁移（边界，见 §8）。

### 3.3 粘滞语义与反模式

- **首包**：查表未命中 → 路由决策（`FlowRouter.route(FlowContext)`）→ 建会话并缓存 `RouteDecision` → 建目标映射；
- **后续包**：复用缓解决策与映射，**绝不逐包重路由**（游戏会话跳链路 = 断线重连，这是反模式）；
- 决策缓存含 `route_reason`，供指标与 `RouteHistory` 记录。

### 3.4 决策缓存失效（对上游 R2 的落地）

单一失效触发源：订阅 `ChainManager::handle_chain_failure` 广播的链路故障事件（现有机制，见 [mesh.md](../mesh.md)）。处理：

1. 遍历会话表，凡 `CachedDecision.path` 含故障节点/链路的会话：清除决策缓存；
2. 下一个包触发重路由 → 新 `RouteDecision` → `update_route`（§5）→ 迁移映射（旧 binding 关闭、LRU 换新）；
3. 非 chain 决策不受链路事件影响，粘滞到会话结束（是否引入 TTL 重探见 O5）。

## 4. 超时回收：状态机与参数

### 4.1 参数表（`UdpSessionConfig`，来自 `udp:` 配置区块，见 udp-dataplane.md §5.2）

| 参数 | 默认 | 说明 |
|------|------|------|
| `mapping_idle_secs` | 60 | 目标映射空闲上限（双向任一方向刷新；游戏心跳间隔远小于此） |
| `session_idle_secs` | 180 | 会话空闲上限（= max(mapping.last_activity)） |
| `sweep_interval_secs` | 15 | 回收扫描周期 |
| `max_sessions` | 4096 | 全局并发会话上界 |
| `max_mappings_per_session` | 256 | 会话内映射上界（LRU 容量，溢出逐最久空闲） |
| `session_max_lifetime_secs` | 无（禁用） | 可选寿命上界，默认关（长局游戏不断流） |

### 4.2 状态流转

```
首包 ──► Active ──(mapping_idle 到期逐映射)──► Active(映射递减)
              │
              ├──(session_idle 到期)──► Expired（回收，§4.4）
              ├──(max_lifetime 到期，若启用)──► Expired
              └──(relay 错误)──► 降级标记*（不终结，下一包成功即回 Active）
* FlowSession.status=Failed 的语义差异处理见 §5.3。
```

### 4.3 回收算法：周期扫描（选型）

- **采用**：单 tokio 任务，`sweep_interval` 周期全表扫描（仿 `ChainManager::start_health_check_task` 既有模式）。4096 项 × 15s 一次的扫描成本可忽略（微秒级每项）；无定时器风暴，代码量最小；
- **弃用**：每映射一个 sleep 任务 / Hierarchical Timing Wheel——上界小，复杂度不值；
- 阈值判定读 `AtomicU64`（`last_activity`），不取锁；确认到期后才进锁删除，降低锁内工作量。

### 4.4 满员准入：拒新不逐旧

`max_sessions` 达到后：新客户端首包**丢弃**并计 `seep_udp_packets_dropped_total{reason="session_limit"}`，**绝不驱逐活跃会话**（游戏被挤下线比丢新会话严重得多）。容量规划建议随指标观察调整，非自动扩缩（非目标）。

### 4.5 回收动作清单

会话/映射到期时按序执行：① drop `UdpBinding`（relay 句柄/socket 关闭，§2.3 的 forwarder task 随之退出）；② 会话移出 Level-1；③ `downlink` 通道关闭，入站侧感知后清理 ASSOCIATE 关联状态；④ 指标：`seep_udp_sessions_expired_total{reason=idle|lifetime}` 自增、`seep_udp_sessions_active` 递减。回收不发送任何对端通知（UDP 无此语义）。

## 5. FlowSession 集成（逐字段映射）

### 5.1 集成方式：组合

`UdpSessionInner` 内嵌 `session: RwLock<FlowSession>`（`FlowSession` 定义于 `seep-core::lib.rs`：`id/created_at/last_active/status/client_info/current_path/route_history/usage/failure_stats`）。**不改动 `FlowSession` 结构本身**——所有集成走其现有方法，TCP 面零影响。

### 5.2 字段/方法映射表

| FlowSession 成员 | UDP 会话表用法 |
|-----------------|---------------|
| `id: FlowId` | 会话创建时 `FlowId::new()`；同时用作 mesh UDP envelope 的 `flow_id`（§4.2 中的 16B UUID，与 udp-dataplane.md §4.2 呼应） |
| `client_info.address` | 填粘滞键 `client`；`auth_info` 填 socks5 `AuthInfo{UsernamePassword, username}`；P1 后 `node_id` 留给 TUN 场景 |
| `last_active` | 随 `AtomicU64 last_activity` 在锁内同步刷新（回收判定用原子值，此字段供观测/诊断） |
| `usage.update_usage(up, down)` | 双向每包累加字节数；**包数注意**：`update_usage` 只计字节，`usage.packets_count` 需另处 `+= 1`（字段现成，方法不覆盖） |
| `update_route(path, reason)` | 决策缓存变更时调用（首包不调，故障迁移时调）；内部会 push `RouteHistory` 并置 `Active`、刷 `last_active`，正好承担迁移记录 |
| `current_path` / `route_history` | 迁移后与 `CachedDecision` 同步；`RouteHistory{success=false, error}` 记录故障切换原因（供 P2-1 切换原因指标） |
| `usage.reconnect_count` | 链路迁移成功后 `+= 1` |
| `record_failure(FailureType::*)` | relay 收发/建绑定错误时调用；`Timeout` 用于上游不可达，`Connection` 用于绑定失败——语义差异见 §5.3 |
| `ChainContext`（经 `current_path` 关联） | 决策为 `RouteDecision::Chain` 时构造 `ChainContext::new(chain_id, source, target)` 挂入会话缓存；`add_fallback_path`/`switch_fallback_path` 直接用于故障切换候选 |

### 5.3 两处现有语义差异（如实标注与处置）

1. **`record_failure` 会置 `status = Failed`**（现有实现行为）。TCP 语义下 Failed≈会话终结；UDP 下单次 relay 错误（如出站瞬时丢包）不应终结会话。**处置**：UDP 侧在下一包成功转发时将 `status` 回置 `Active`（包装器 `UdpSessionInner::note_success()` 统一处理，`failure_stats` 保留作观测）；是否值得上游给 `FlowSession` 增加"可恢复 Failed"语义，列为 O7，不在 P0-1 改。
2. **`FlowSession::new(id, _target)` 当前丢弃 target 参数**（字段里没有 target）。UDP 会话的目标集合存于 `mappings` 键集，`FlowSession` 不承担目标存储——本文档明示此现状，避免实施时误以为会话内可查目标列表。

## 6. 并发与内存预算

- **锁粒度**：DashMap 分片读锁（查会话）→ 会话内 `Mutex<LruCache>`（查/建映射）→ `binding` 自身 IO。会话间无共享可变状态；每包临界区为常数次哈希 + 微秒级操作；
- **吞吐量级**：4096 会话 × 单会话 120 pps（游戏上限）≈ 0.5M pps 理论上界，远低于 DashMap 分片能力，无需无锁结构；
- **内存上界**：`max_sessions × max_mappings × (binding ~ 数百 B + downlink 通道缓冲 64 × ~1.5KB)` ≈ 4096 × 256 × ~2KB ≈ **2 GiB 最坏上界**——实际上 256 映射/会话是给扫描器/DNS 类客户端的宽配额，游戏会话典型 ≤ 8 目标，真实占用低 1–2 个数量级；仍建议压测校准（上游 R1）；
- **缓冲复用**：`Bytes`/`BytesMut`（workspace 已有 `bytes`）池化收发缓冲，避免每包分配。

## 7. 指标与测试清单（对齐 todo P0-1 验收）

指标（命名沿用 udp-dataplane.md §5.3，本条目新增细化项）：

```
seep_udp_sessions_active / seep_udp_sessions_total
seep_udp_sessions_expired_total{reason=idle|lifetime}
seep_udp_packets_dropped_total{reason=timeout|frag|session_limit|no_mapping}
seep_udp_mappings_active                       # 新增：Level-2 总映射数
seep_udp_decision_reroutes_total{trigger=chain_failure}    # 新增：决策失效重路由计数
```

单元测试（验收原文 → 测试项）：

| todo P0-1 验收 | 测试 |
|----------------|------|
| 会话创建/查询/超时回收有单测 | ① 首包建会话、键查询命中；② 注入时钟推进过 `session_idle_secs` → sweep 后表空、expired 指标 +1；③ 映射级：推 `mapping_idle_secs` 后仅目标映射消失、会话保留 |
| 同一粘滞键复用映射不重建 | 同键连发 N 包（含多目标）：`mappings.len()` 与 `decision` 代数不变；换端口即新会话 |
| （本稿新增）满员拒绝 | 注满 `max_sessions` 后新键首包被拒且 `dropped{session_limit}` +1，既有会话不受影响 |
| （本稿新增）决策失效 | 构造 chain 会话 → 触发链路故障事件 → 断言决策缓存清空、下一包重路由且 `update_route`/`RouteHistory`/`reconnect_count` 正确 |
| （本稿新增）LRU 溢出 | 单会话注入 257 目标：最久空闲映射被逐，`max_mappings` 恒成立 |

## 8. 边界与非目标

- 不做通用 conntrack：无 TCP、无 FTP 类辅助通道关联、无 IP 分片重组（FRAG 在 socks5 层已拒，udp-dataplane.md §2.2）；
- QUIC 按 UDP 数据报处理（`TargetProto::Quic` 仅作标记），不做 QUIC 连接级感知；
- 无跨会话 hairpin（会话 A 经表直接发会话 B）；
- 源端口迁移不迁移会话（§3.2）；参数热调整不做，改配置重启生效（MVP 口径）。

## 9. 开放问题

| 编号 | 问题 | 衔接 |
|------|------|------|
| O5 | 非 chain 决策是否引入 TTL 重探（有更优节点时迁移）——默认粘滞到底 | P2-2 SLO 打分选路定 |
| O6 | 域名目标不在会话层缓存解析结果，每映射由出站自行 resolve（direct 每目标一次）；是否上移到会话层 | P2-8 DNS 分流定 |
| O7 | `FlowSession` 是否需要"可恢复 Failed"状态语义（当前 UDP 用包装器回置 Active 规避） | 独立小改动，随 P0-1 实施评估 |
