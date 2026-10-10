# P2-2 SLO 打分选路（设计稿）

> 2026-10-02 就绪并同轮落地（组策略 `slo:` 门内最低分选路 + chain `slo_watch`
> 劣化切换，测试全绿随批入仓——见 roadmap S4 注记）。以 p95 RTT/丢包为目标给组策略打分，升级 `latency`
> 策略；mesh 劣化时 chain 侧自动切换且原因入账本（P2-1）。「游戏 profile
> 默认启用」归 P2-3（profile 预设落地时接线，本稿交付能力面）。
>
> **落地状态**：已实现（M1 a9c7e11：SloPolicy 配置 + 评分核心/门/
> 来源优先级；M2 本提交：mesh→routing 质量桥 + ChainManager SLO
> watcher + `SwitchReason::SloDegraded` + `slo_watch` 程序化配置面）。
> YAML 面归 P2-3（D-6/O-slo2）；`slo_watch` 当前仅程序化构造
> `ChainConfig` 可达（serde 反序列化已支持，`seepd` 不透传）。
> §6 E2 偏差注记：零连接链路 loss 记 0.0（观测 API 无原子
> 「errors/connections 同快照」面，纯 RTT 节点不应被疑似丢包放大）。

## 0. 范围与验收口径

**todo 原文**：以 p95 RTT/丢包为目标打分，升级 `latency` 组策略；游戏 profile 默认启用。
**验收原文**：模拟链路劣化时自动切换且记录切换原因；`ChainContext` fallback 路径生效。

**可测口径（显式改写，非缩水）**：

1. **打分升级**：`latency` 策略选择 = SLO 目标门内最低分
   （score = p95_ms + loss_ratio × loss_penalty_ms）——单测注入两成员
   劣化/优化的 link_quality，断言选择翻转；
2. **劣化自动切换**：chain SLO watcher 检出当前路径越门 →
   `handle_chain_failure` 触发切换/终止，账本事件
   `reason="slo_degraded"`（P2-1 `seep_mesh_switch_total{reason}` 计数
   族自动可见，无新指标族）——单测注入劣化数据驱动 watcher；
3. **fallback 生效**：切换后 `ChainContext` 当前路径 = 备用路径提升
   （P2-1 M1 已修提升语义，get_current_path 单口径）——断言切换后
   from/to 路径形。

## 1. 现状与结构约束

- `RoutingEngine`（seep-routing）：`latency` 策略 = `latency_stats`
  最后样本取 min；**样本源是模拟值**（`measure_node_latency` 随机
  10–100ms——既有 `test_health_check_integration` 依赖该路径）；依赖
  仅 seep-config + seep-core（**不依赖 seep-mesh**——数据只能推进来，
  先例 `update_bandwidth_stats`）；
- P2-1 交付了真数据源：`MeshRegistry.link_rtt`（RttRing p50/p95）+
  `link_traffic`（errors/connections）——键是 `(from,to)` 链路方向，
  需聚合成节点维度才能进组策略（组员 = 节点名）；
- `ChainManager::handle_chain_failure`（P2-1 修缮后）：切换提升语义
  正确、账本按因留痕——劣化切换可直接复用，缺的只是「检出劣化」的
  触发器与原因枚举值；
- seep-config 无 chain YAML 块：`RuntimeBuilder.chain_config` 是唯一
  程序化入口（`Option<ChainConfig>`）。

## 2. 决策（D-x）

- **D-1 评分纯函数**：`slo_score(p95_ms, loss_ratio, penalty) =
  p95_ms as f64 + loss_ratio * penalty`——加性、时延主导、丢包按可配
  权重罚分（缺省 1000ms/单位丢包率：1% 丢包 ≈ +10ms 罚分，可解释）。
- **D-2 SLO 目标门**：组级 `slo: {p95_ms, loss_ratio}`（皆 Option）→
  合规集 = {有数据者 p95 ≤ 门 且 loss ≤ 门；**无数据成员视为合规**
  （unknown 不误杀）}；合规集内取最低分；合规集空 → 全体取最低分
  （不 dead-end）。`slo` 缺省 None → 无门纯最低分（存量行为兼容面）。
- **D-3 数据面**：`RoutingEngine::update_link_quality(node, p95_ms,
  loss_ratio)`（DashMap + TTL 60s 同 bandwidth_stats 惯例）；
  `latency` 策略取数优先级 = link_quality（真）→ legacy latency_stats
  （模拟/存量）→ 首个健康成员。语义变化注记：真数据在场时从「最后
  样本」升为「p95 分位」（§9）。
- **D-4 零依赖零 trait 变更**：seep-routing 不增依赖；mesh→routing
  桥放 seep-runtime（聚合 RttRing/LinkTraffic：节点 p95 = 相邻链路
  最差跳 max，节点 loss = Σerrors/Σconnections，有数据才推进）。
- **D-5 劣化自动切换**：`ChainConfig.slo_watch: Option<SloWatch{
  p95_ms, loss_ratio, interval_secs}>`（缺省 None = watcher 不启）；
  watcher 周期评估各活跃链路当前路径末跳质量（MeshRegistry 查询），
  越门 → `handle_chain_failure(chain_id, "slo degraded: p95=…ms
  loss=…")`；新增 `SwitchReason::SloDegraded`（枚举/as_str/ALL 增量
  三处，P2-1 计数族自动获得 `reason="slo_degraded"` 序列）。
- **D-6 配置面分两步**：组级 `PolicyGroup.slo`（serde default None，
  存量零差异）本步落 YAML；chain 侧 `slo_watch` 本步只落程序化面
  （`RuntimeBuilder.chain_config`）——seep-config 无 chain 块，YAML
  面随 P2-3 profile 一并落（游戏 profile 默认启用 = 该处接线）。

## 3. 数据结构

```rust
// seep-config
pub struct SloPolicy {            // PolicyGroup.slo: Option<...>（serde default）
    pub p95_ms: Option<u32>,      // 目标门（None = 该维不设门）
    pub loss_ratio: Option<f64>,  // 目标门（None = 该维不设门）
    pub loss_penalty_ms: Option<f64>, // 缺省 1000.0
}
// seep-runtime chain.rs
pub struct SloWatch {             // ChainConfig.slo_watch: Option<...>
    pub p95_ms: u32,
    pub loss_ratio: f64,
    pub interval_secs: u64,       // 缺省 10
}
```

## 4. 接线点

| 点 | 改动 |
|----|------|
| `PolicyGroup`（seep-config） | + `slo: Option<SloPolicy>`（default）；validate：loss_ratio ∈ [0,1]、penalty ≥ 0 |
| `RoutingEngine::select_latency_member` | 门 + 评分（D-2），取数优先级（D-3） |
| `RoutingEngine::update_link_quality` | 新公开写点 + TTL |
| seep-runtime 桥任务 | 周期聚合 MeshRegistry → update_link_quality（节点 = 链路任一端点名） |
| `ChainConfig` / `ChainManager` | + slo_watch 字段 + watcher 任务（start_health_check_task 同法 spawn） |
| `SwitchReason` | + SloDegraded（三处增量） |

## 5. 控制面

无新指标族/端点：劣化切换经 P2-1 `seep_mesh_switch_total{reason=
"slo_degraded"}` 与 `/mesh/switches` 自动可见（D-5 选枚举化的原因即
为此）。组策略选择结果属路由内部态，暴露归既有 diagnose 面（不在本
条目范围）。

## 6. 错误路径

- E1 成员无 link_quality 数据：视为合规（门不误杀）；评分退化 legacy
  latency_stats → 首个健康成员（优先级链）；
- E2 链路 loss 分母 0（P2-1 E4 无序列）：桥不推该节点 loss 维更新
  （保持 unknown）；
- E3 watcher 评估时链路已终止/被移除：跳过（active_chains 快照外的
  chain_id 查 registry 得 None 即略）；
- E4 slo_watch 与组级 slo 相互独立：watcher 只管切换，组策略只管
  选择——不联动配置（避免双重真值源）。

## 7. 测试策略

1. 评分/门纯函数：加性形、门过滤、unknown 合规、门全破不 dead-end；
2. latency 策略：注入 link_quality 劣化成员 vs 优化成员 → 选择翻转；
   legacy 数据在场且真数据缺席 → 旧行为；
3. 桥聚合：registry 两链路（p95 各异 + 一条 errors/connections）→
   节点 worst-hop p95 与聚合 loss 推进正确；
4. watcher：注入越门数据 → handle_chain_failure 触发、账本
   slo_degraded 事件、fallback 提升（from/to 路径形）；
5. 既有 268 项零回归（模拟源路径不动）。

## 8. 分步实施清单（M1–M2）

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M1 | seep-config SloPolicy + seep-routing 评分核心（update_link_quality/门/评分/取数优先级）+ 单测 §7-1/2 | — | §7-1/2 绿；存量 routing 测试零回归 |
| M2 | seep-runtime 桥 + SloWatch/watcher + SwitchReason::SloDegraded + 单测 §7-3/4 + 文档回填（todo/PROTOCOLS/roadmap/本稿落地注记） | M1 | §7-3/4 绿；§0 口径逐条可复现 |

## 9. 偏差与假设

- **语义变化**：真数据在场时 `latency` 策略从「最后样本 min」升为
  「p95 分位 min（门内）」——模拟源/无真数据部署行为不变（优先级链
  兜底），存量测试即兼容性证明；
- **采样源 MVP** = mesh 上报流（P2-1 D-1 同源），真主动探测归
  O-link-obs1；无 mesh 部署的组策略无真数据 → 优先级链退化旧行为；
- **节点聚合口径** = worst-hop p95 + 全邻接 loss 聚合：链路任一端
  劣化即反映到两端节点（保守方向，游戏场景宁可错杀换路径）；
- mesh `NodeId` 与组策略节点名同一命名空间（现有配置与 dry-run 测试
  即此假设，桥不做映射）。

## 10. 风险与未决

- **R-slo1**：watcher 误切（上报抖动瞬时越门）——MVP 无迟滞/去抖，
  interval 周期即天然平滑；误切率观察期后再定迟滞策略；
- **O-slo1**：`seepctl group` 子命令展示各成员实时 SLO 分（能力已在
  update_link_quality 快照，CLI 包装随需求）；
- **O-slo2**：游戏 profile 默认启用接线（P2-3）；
- **O-slo3**：迟滞/去抖（连续 N 周期越门才切）按 R-slo1 观测定。
