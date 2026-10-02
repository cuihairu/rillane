# P2-4 混淆中间件扩展（timing / shaping）（设计稿）

> 2026-10-02 就绪。在 P1-4 静态 middleware 管线上扩两策略：
> timing（微抖动注入）与 shaping（流形状归一），沿用 obfuscation-
> middleware.md §2 的「策略/执行分离」与 §3 的配置镜像 + 转换模式。
>
> **落地状态**：✅ 已实现（M0 `7d56d06`：设计稿 + seep-config 镜像 +
> seep-runtime 转换 + 测试；M1 `16d9eb2`：两 middleware + PacedIo +
> 白名单扩 + 链接线 + §7-3/4/5 测；M2 本提交：game 预设内联 timing 演示
> + profile 测试更新 + 文档回填）。

## 0. 范围与验收口径

**todo 原文**：微抖动注入、流形状归一。
**验收原文**：与 P1-4 同一统计方法验证时序特征偏移；延迟代价可量化
（p95 增幅 ≤ 配置上限）。

**可测口径（显式改写，非缩水）**：

1. **决策可观测**（对齐 P1-4「注解可见」口径）：`TimingMiddleware` /
   `ShapingMiddleware` 命中流把决策写入 `seep.obfs.timing` /
   `seep.obfs.shaping` 注解（毫秒值），单测断言；链统计经既有
   `MiddlewareChain` 调用计数可观测；
2. **时序特征偏移可证**：timing 决策值域 ⊂ [min_ms, max_ms] 且确定性
   （同 flow_id 恒同值，单测钉住）；shaping 在 burst 写入下产出相邻
   write 起始间隔 ≥ interval 的形状（单测以小间隔真实度量）；
3. **延迟代价可量化**：两策略均有硬闸门（timing 的 max_delay_ms /
   shaping 的 max_delay_ms），决策值不得越过——p95 增幅 ≤ 配置上限
   由闸门在构造期断言（单测注入越门决策断言 Err/不放行）。

## 1. 现状与结构约束

- P1-4 已落：`MiddlewareChain`（seep-core，声明序执行、空链旁路）、
  `PaddingMiddleware`（策略侧只写注解，帧执行侧填充）、`obfs_config.rs`
  （`to_padding_policy` + `build_middleware_chain`）、§3.3-5 白名单
  （当前 `padding|latency_probe`，timing/shaping 在白名单文案登记为
  「归 P2-4」）；
- `LatencyProbe` 已证明「handle 内 sleep」合法（探测用 1ms）；
- `Flow { io: BoxedIo, metadata: Metadata, .. }`，`IoStream` blanket
  impl（AsyncRead+AsyncWrite+Send+Sync+Unpin）——**中间件可包装 io**；
- P2-4 与 P1-4 的执行侧面差异：padding 改字节（需帧载体），timing /
  shaping 改**时间**——不需要新的线格式字段，执行侧可以直接在
  middleware 内完成（sleep / io 包装），这是与 padding 的关键区别。

## 2. 设计决策

- **D-1 timing = 启动抖动**：`TimingMiddleware::handle` 内 sleep 一次性
  决策值 d（连接建立前）；P2-4 M0 止于此。逐数据报抖动留 UDP 面
  （P0-4 帧载体有边界可定，随接入单测另步）。
- **D-2 shaping = 写网格归一（pacing）**：`ShapingMiddleware` wrap
  `flow.io`：每次 `AsyncWrite` 之前 sleep 至「自首包起第 k×interval +
  jitter 网格点」，把 burst 拉平成均匀形状。read 方向不动（归一写侧
  受控出口即流形状主观测面；读侧是对端行为，不归一）。
- **D-3 确定性同源**：决策随机源 = `hash(flow_id, seq)`（与 padding
  §2.2 range_hash 同族 FNV-1a + splitmix64，seq 由 middleware 内计数器
  递增）——无 RNG、跨平台确定、测试可复现。
- **D-4 双闸门**：timing/shaping 各有 `max_delay_ms`（配置期 validate
  须非 0 且 ≥ min_ms；决策值超限即截断到闸门 + Debug 日志，不 Err——
  混淆增益不得破坏转发，与 padding E10 同风格降级）。
- **D-5 配置形 = padding 三件套的对称扩展**：`ObfuscationConfig` 增
  `default_timing`/`default_shaping`（profile 引用，与 default_padding
  同语义）+ 内联 `timing`/`shaping` 块（同互斥规则）；
  `ObfsProfileConfig` 增 `timing`/`shaping` 内嵌。`TimingBlockConfig`/
  `ShapingBlockConfig` 形状参照 `PaddingBlockConfig`（mode 必填
  字符串 + 各模式字段 + validate 按 mode 校验，E2 同风格点名）。
- **D-6 middleware 名纳入 §3.3-5 白名单**：`padding|latency_probe|
  timing|shaping`；`build_middleware_chain` 同步认识新名字（声明序
  执行，padding/timing/shaping 任意组合——timing 先于 shaping 时
  shaping 的首个网格点从 shaping 开始起算，语义自洽）。
- **D-7 指标**：不新族；可观测性面 = 写入注解（§0-1）+ 既有
  `MiddlewareChain` 调用计数 + `seep_obfs_padding_*` 先例留给 M1
  在执行侧（io 包装层）追加 `seep_obfs_shaping_writes_total` 仅当
  shaping 实际生效——M0 不定指标名，M1 落。

## 3. 数据结构

```rust
// seep-config（镜像，deny_unknown_fields）
pub struct TimingBlockConfig {
    pub mode: String,          // "fixed" | "uniform"
    pub fixed_ms: u64,         // fixed 模式值（须非 0）
    pub min_ms: u64,           // uniform 下界
    pub max_ms: u64,           // uniform 上界（min ≤ max）
    pub max_delay_ms: u64,     // 硬闸门（须 ≥ 模式值域上界外的兜底；0 = 不配 → validate E2）
}
pub struct ShapingBlockConfig {
    pub mode: String,          // "interval"
    pub interval_ms: u64,      // 网格间隔（须非 0）
    pub jitter_ms: u64,        // 网格抖动幅度（须 ≤ interval_ms）
    pub max_delay_ms: u64,     // 硬闸门
}

// seep-core（运行期 spec，与 PaddingSpec 同文件同族 serde）
pub enum TimingMode { Fixed, Uniform }
pub struct TimingSpec {
    pub mode: TimingMode, pub fixed_ms: u64, pub min_ms: u64, pub max_ms: u64,
    pub max_delay_ms: u64,
}
pub enum ShapingMode { Interval }
pub struct ShapingSpec {
    pub mode: ShapingMode, pub interval_ms: u64, pub jitter_ms: u64,
    pub max_delay_ms: u64,
}
```

转换层（seep-runtime `obfs_config.rs`）：
`to_timing_policy(cfg, known_egress) -> Option<TimingPolicy>` /
`to_shaping_policy(...)`——与 `to_padding_policy` 同语义（enabled 总开关
共享、E5 降级、default_* 与内联互斥、profile 内嵌解析）。
`TimingPolicy::matches` / `ShapingPolicy::matches` 同 `PaddingPolicy`。

## 4. 接线点（M1 落）

| # | 点 | 动作 |
|---|----|------|
| 1 | `seep-protocols/middleware/` 新 `timing.rs` | `TimingMiddleware`：handle 内 decide（hash 确定）→ 注解 `seep.obfs.timing` → sleep(d)。纯决策函数 `decide_timing` 单测钉值域/确定性/闸门截断 |
| 2 | `seep-protocols/middleware/` 新 `shaping.rs` | `ShapingMiddleware`：decide → 注解 `seep.obfs.shaping` → wrap `flow.io`（`PacedWriter`：write 前 sleep 至网格点，seq 递增）。`decide_shaping_delay` 纯函数 + `PacedIo` 单测钉 ≥ interval |
| 3 | `obfs_config::build_middleware_chain` | 白名单加 timing/shaping，构造对应 middleware（selector 同形闭包固化） |
| 4 | 配置 validate | §3.3-5 文案扩为四名字；TimingBlockConfig/ShapingBlockConfig validate E2 矩阵 |

## 5. 控制面

无新端点/指标族（D-7）。`GET /metrics` 既有 `MIDDLEWARE_INVOCATIONS`
自动收录 `timing`/`shaping` 两个调用名。

## 6. 错误与边界

- E1..E5 沿 P1-4 §3.3/§6 同语义（enabled=false 短路、互斥/皆缺、E3
  引用缺失、E5 apply_to=egress:ghost 降级 Ok(None)）；
- E2 扩矩阵：timing mode ∈ {fixed, uniform}、fixed 非 0、uniform
  min ≤ max、max_delay_ms ≥ min_ms；shaping mode = interval、
  interval 非 0、jitter ≤ interval、max_delay_ms ≥ interval。

## 7. 测试策略

1. seep-config：timing/shaping 块解析/deny/往返/validate E2 矩阵
   （参照 padding 系列测）；
2. obfs_config：to_timing_policy / to_shaping_policy 两态矩阵
   （enabled 短路/引用解析/内联/E5 降级/对称 to_padding_policy 语义对齐）；
3. timing 引擎：fixed 直出 / uniform 值域 + 同 flow_id 确定 +
   闸门截断；middleware handle 冒烟（小 max 真 sleep 可感知 +
   注解写入）；
4. shaping 引擎：网格点决策（k×interval+jitter，闸门截断）；PacedIo
   真度量（tokio duplex + 小 interval：burst 3 片 write → 相邻间隔
   ≥ interval − 容差，总耗时上界）；
5. build_middleware_chain：四名字混排声明序断言。

## 8. 分步实施

| 步 | 内容 | 验收 |
|----|------|------|
| M0 | 设计稿 + §3 配置镜像 + validate E2 + obfs_config 转换 + 单测 | 转换矩阵绿；白名单文案暂维持三字集外提示（timing/shaping 单测驱动的转换全绿即合入） |
| M1 | §4-1/2/3：两 middleware + 链接线 + §7-3/4/5 测 | 全链路单测绿；§0 三口径可复现 |
| M2 | profile-game 示例接入 timing 演示 + 文档回填（todo/PROTOCOLS/roadmap/本稿落地注记） | 示例加载测绿；门禁全绿 |

## 9. 偏差与假设

1. **TCP 面逐 chunk 抖动 != 包长混淆**：timing 只改时间分布不改字节
   量，与 padding（字节）互补；R-obfs4 的「分布形状特征」分析的
   联合验证在 M1 落地时以同一统计方法（注解决策分布 vs 帧字节 golden）
   做一次对照记录；
2. **网格归一的保守语义**：PacedIo 只延后**新写**的下发，不缓冲
   （不引入额外分配与 flush 语义变更）；write 返回值语义不变
   （全部字节最终写入，仅时机变）；
3. **read 不归一**（D-2）：读侧形状由对端决定，本地改写无从施力；
   如需双向归一，留 O-p24-1。

## 10. 风险与未决

- **R-p24-1 延迟代价误配**：max_delay_ms 给大会直接抬 p95——§0-3 闸门
  + profile-game 示例值（game = 80ms p95 SLO，启动抖动示例取
  min 0 / max 20 / 闸门 50）对照 SLO 双门；
- **O-p24-1 双向 shaping**：读侧网格（对端无视本地时钟，需 ACK 层节奏，
  非本步）；
- **O-p24-2 UDP 面 timing**：逐数据报抖动需 hop 重编码钩子，随 P0-4
  §15 D-15 载体接缝另步。
