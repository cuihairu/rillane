# P2-1 per-link 细粒度指标（设计稿）

> 2026-10-02 就绪并同轮落地。范围：mesh 链路维度的时延分布（p50/p95）、
> 丢包观测、切换原因账本；节点间流量已有面（`LinkTrafficStats`）补齐暴露。
> 方法论循 udp-observability.md（P0-5）：恒渲染纪律、关闭态对照、统计口径
> 显式改写不缩水。
>
> **落地注记（2026-10-02，M1–M2 全部完成）**：M1（样本环+账本+存量缺陷修缮）
> `a9c7e11`、M2（控制面三族 + `/mesh/switches` + 文档回填）本提交。实施期
> 修缮三处存量缺陷（M1 账本测试首度覆盖暴露）：①`handle_chain_failure`
> 备用耗尽分支 RefMut 持有下调 `active_chains.len()`——DashMap 全分片读锁
> 与本线程分片写锁互斥即自锁，修 = 先 drop 分片守卫；②seep-core
> `ChainContext` 路径语义——fallback 非空时 `get_current_path()` 恒读
> `fallback_paths[idx]`：从未切换链路谎报 fallback[0] 为当前路径（路由决策
> 同源污染）且首跳跳过 fallback[0]，修 = 单口径 current_path + 按声明序
> 提升（`switch_fallback_path` 复用 update_path 升主）；③
> `check_chains_health` 归因顺序——状态先于 TTL（ZERO TTL 巡检下已终止链
> 两因同时成立，旧序冤枉死因为 TtlExpired）。§10-1（主动探测源）、
> §10-2（seepctl 包装）、§10-3（事件持久化）维持未决。

## 0. 范围与验收口径

**todo 原文**：per-link 细粒度指标：时延分布、丢包、切换原因、节点间流量。
**验收原文**：Grafana 可按 link 维度查询 p50/p95 RTT 与最近 N 次切换原因。

**可测口径（对齐 P0-3/P1-5 显式改写做法，非缩水）**：

1. **p50/p95 RTT**：`seep_mesh_link_rtt_ms{from,to,quantile="p50"|"p95"}`
   ——样本环分位数就地处（§3.1），`from`/`to` 标签 = 链路方向，Grafana 按
   link 维度直接查询；
2. **最近 N 次切换原因**：`GET /mesh/switches`（最近 100 事件 JSON）+
   `seep_mesh_switch_total{reason}` 计数族——原因枚举化（§2 D-3），自由文本
   降为 `detail` 字段；
3. **丢包**：观测形派生 `seep_mesh_link_loss_ratio{from,to}`
   = `errors_total / connections_total`（连接失败即丢；§2 D-2），上报形
   `seep_mesh_packet_loss_rate`（全局均值，既有）保留不动；
4. **节点间流量**：既有 `seep_mesh_link_{bytes,connections,errors}_total`
   （P0-5 已交付）即验收面，本文不重复建设。

## 1. 现状与结构约束（决策的事实输入）

- `MeshRegistry`（seep-mesh/src/lib.rs）已有：`link_states`（上报形单值
  latency_ms/bandwidth/packet_loss_rate，控制面 `/mesh/link-states` 写入）、
  `link_traffic`（按方向 connections/bytes/errors 计数，P0-5 暴露）——
  **单值延迟无分布**、**丢包只有上报值无观测值**、**无切换事件账本**；
- `ChainManager`（seep-runtime/src/chain.rs）`handle_chain_failure` 切换
  备用路径仅递增全局 `failover_count`，原因以自由文本日志即弃；健康巡检
  TTL/状态终止无原因留痕；
- 真探测源（主动 ping 帧 / LatencyProbe 注解回灌）尚不存在：P1-4 M2 后
  LatencyProbe 注解面才可接线（另一会话在途），本条目不阻塞其上。

## 2. 决策（D-x）

- **D-1 RTT 样本环**：per-link 环形样本（cap 256，尾进尾出）宿主
  `MeshRegistry.link_rtt`；快照时就地排序取最近秩分位（256 样本排序开销
  微不足道，不引外部依赖）。采样源 MVP = `update_link_state` 上报值入环
  （现有控制面流，零新协议）+ `record_link_rtt` 公开写点（探测源后接）。
- **D-2 丢包 = 观测派生**：`errors/connections` 比值就地处（connections=0
  → 无序列），不新增主动探测；上报形保持上报形（两者语义不同不合并）。
- **D-3 切换原因枚举化**：`SwitchReason = FailureReported（流错误触发切换）
  | FallbackExhausted（备用耗尽终止）| TtlExpired | TerminatedUnhealthy`；
  事件账本 `Mutex<VecDeque<SwitchEvent>>` cap 100（最新保留）+ 按原因计数
  `BTreeMap`（metrics 数据源）。终止类事件（TTL/状态）与切换同类记入——
  对 Grafana 而言都是"链路变更原因"，§9 偏差载明。
- **D-4 零 trait 变更 / 零新依赖**：账本挂 `ChainManager` 字段，环挂
  `MeshRegistry` 字段（`Default` 兼容——`DashMap` + `VecDeque` 均可
  derive）；UDP 侧 `table.handle_chain_failure`（P0-1 机制）不混入。
- **D-5 关闭态对照**：mesh 未启用 → 三个新族与 `/mesh/switches` 均不渲染
  （区别于 udp/obfs 恒渲染纪律：链路观测随 mesh 能力存在性开落，无链路
  无序列名可立；与 P1-5 seep_pool_* 同判）。

## 3. 数据结构

### 3.1 RttRing（seep-mesh）

```rust
pub struct RttRing { samples: VecDeque<u32> }   // cap = RTT_RING_CAP = 256
record(ms: u32)；quantile(p: f64) -> Option<u32> // 最近秩：sort 后
                                                 // idx = (p * n).ceil() - 1
```

`LinkRttSnapshot { from, to, p50_ms, p95_ms, samples }`（Serialize，控制面
DTO 与端点共用）。

### 3.2 SwitchEvent / 账本（seep-runtime chain.rs）

```rust
pub enum SwitchReason { FailureReported, FallbackExhausted, TtlExpired, TerminatedUnhealthy }
pub struct SwitchEvent { chain_id, from_path: Vec<String>,
                         to_path: Option<Vec<String>>, reason: String,
                         detail: String, epoch_seconds: u64 }
```

`ChainManager` 新字段 `switch_ledger: Mutex<VecDeque<SwitchEvent>>` +
`switch_counters: Mutex<BTreeMap<String, u64>>`；公开
`record_switch` / `get_recent_switches(n)` / `switch_counters_snapshot()`。

## 4. 接线点

| 点 | 现状 | 改动 |
|----|------|------|
| `MeshRegistry::update_link_state` | 覆写 LinkState | latency_ms>0 时入环（D-1 采样源） |
| `ChainManager::handle_chain_failure` | failover_count++ | 切换成功 → `FailureReported` 事件（from=切换前路径，to=新 fallback 路径，detail=原 failure_reason）；备用耗尽 → `FallbackExhausted`（to=None） |
| `ChainManager::check_chains_health` | TTL/状态终止无留痕 | 终止时按因记 `TtlExpired` / `TerminatedUnhealthy`（cause 随 chain_id 携带） |
| 探测源 | 无 | `record_link_rtt` 公开写点预留（O-link-obs1） |

## 5. 控制面暴露

- `/metrics`（mesh 块内）：`seep_mesh_link_rtt_ms{from,to,quantile}`（p50/
  p95 两序列/链路，环空不出）、`seep_mesh_link_loss_ratio{from,to}`、
  （chain 块内）`seep_mesh_switch_total{reason}`（恒渲染——计数器族零值
  也在，账本空时无事件端点条目）；
- `GET /mesh/switches`：`{ events: [...] }` 最近 100（mesh 启用门内，
  未启用 503 同 `/nodes` 先例）。

## 6. 错误路径

- E1 环满：尾进尾出覆写最旧，无错误面；
- E2 账本满：pop 头部，无错误面；
- E3 `quantile` 空环：返回 None → 序列不渲染（非 0 填充——无样本链路
  画"0ms"是误导）；
- E4 connections=0：loss_ratio 无序列（0/0 无意义）。

## 7. 测试策略

1. RttRing 分位数数学（奇偶 n、边界 p0/p1、cap 覆写）；
2. registry 采样源：update_link_state 入环 + record_link_rtt 直写；
3. 切换账本：handle_chain_failure 两分支事件形（路径/原因/detail 透传）
   + 健康巡检 TTL/终止两因 + cap 100 环绕 + 计数器聚合；
4. 控制面：metrics 三族按维查询（from/to 标签断言）+ /mesh/switches 端点
   + 关闭态缺席（D-5）；
5. 既有 259 项零回归。

## 8. 分步实施清单（M1–M2）

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M1 | 设计稿（本文）+ seep-mesh RttRing/采样源/快照 + seep-runtime 切换账本接线 + 单测 | — | §7-1..3 全绿 |
| M2 | seepd 控制面：/metrics 三族 + /mesh/switches + 测试 + todo/PROTOCOLS/roadmap 回填 | M1 | §7-4..5 全绿；§0 口径逐条可复现 |

## 9. 偏差与假设

- 终止类事件（TtlExpired/TerminatedUnhealthy）与路径切换同账本记录：对
  Grafana 查询者而言同为"链路变更原因"，分表无运营动作（D-3 注记）；
- p50/p95 就地排序计算而非桶直方图：256 cap 下开销可忽略，省 prometheus
  histogram 依赖与桶配置；样本量再升一档（>10k/链路）时改桶形；
- 采样源 MVP 只有上报流（无主动探测）：真 RTT 分布待探测源落地
  （O-link-obs1，P1-4 M2 后 LatencyProbe 注解回灌或 mesh ping 帧）——
  本条目验收口径（按维查询 p50/p95 与切换原因）不依赖探测源；
- loss_ratio 以 connections 为分母（连接失败即丢），非包级——mesh 面
  无逐包 ACK 语义，包级 loss 归 V2 QUIC 载具统计。

## 10. 风险与未决

- **R-obs1**：上报值即样本（D-1）——上报方语义是"当时延迟"非"测得 RTT"，
  分布形受上报方诚实度影响；探测源落地后切真测，序列名不变；
- **O-link-obs1**：主动探测源接线（LatencyProbe 注解回灌 / mesh ping 帧）；
- **O-link-obs2**：`seepctl switches` 子命令（端点已交付，CLI 包装随需求）；
- **O-link-obs3**：切换事件持久化（重启即失，MVP 不做——账本定位是
  近因观测非审计）。
