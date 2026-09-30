# P1-4 混淆中间件 MVP（padding）— 实现级设计

> 上游：[roadmap.md](roadmap.md) S3 · [positioning.md](positioning.md) §2.4（混淆横切层）与 §2.5（策略分化）· [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) §3（条目三）与 §5.5（"P1-4 的真实前置是建挂载点而非写一个中间件"）。
> 本文是落地定稿：**挂载点形态、填充策略与配置 schema、与既有 middleware/出站链的衔接、错误路径、测试策略、分步清单**。落地后偏差回填 §9。
> 复用基线：`FlowMiddleware` trait（`seep-core/src/lib.rs:234-238`）· `FlowOutput`/`FlowOutputRouter`（`seep-core/src/lib.rs:230-232` / `seep-runtime/src/runtime_builder.rs:1227`）· 注解注入先例 `seep.chain.path`（`runtime_builder.rs:1308`）· `UdpConfig` 镜像类型 + runtime 转换先例（[udp-dataplane.md](udp-dataplane.md) §5.2）· 新块 `deny_unknown_fields` 定向收口先例（[network-route.md](network-route.md) §1.5）· `MeshEnvelope`（`mesh_transport.rs:165-176`）。

## 0. 范围

| 在本条目内 | 归其他条目 |
|-----------|-----------|
| **静态 middleware 管线**（C1 收口：注册表 + 唯一调用点 + 顺序语义） | 动态加载（WASM/动态库 loader 与隔离）= P3-2，在本管线上扩展 |
| padding 策略引擎（三模式 + 上限保护）与 `PaddingSpec` 编解码 | timing / shaping 策略 = P2-4（复用本文管线与 spec 机制） |
| padding 的**帧执行侧**载体（MVP = chain 的 `MeshEnvelope` 帧） | TLS 指纹模拟 = P2-5；mesh envelope 二进制化 = P2-6 |
| `obfuscation:` 配置区块（seep-config 镜像 + runtime 转换）+ profile 开关 | `proxy`/`game`/`web` 三套场景预设 = P2-3（在本文 schema 上组合） |
| `seep_obfs_*` 指标 + 测试 + 统计验证口径 | 全局接管 / 系统路由 = P1-3；TUN 入站 = P1-2 |

**验收口径前置说明（对齐 P0-3 的显式改写做法，不静默缩水）**：todo P1-4 验收"开启后统计脚本显示**出口包长分布**偏离默认分布"在 TCP 面上不可字面达成——TCP 字节流的线上分段由内核决定，用户态中间件无法重塑"包"边界（§2.1 详述）。本条目可测的等价口径为：

1. **seep 自有帧**的线上字节长度分布按策略偏移——MVP 帧 = chain 路径的 `MeshEnvelope` 帧（真 wire 字节，抓包可验）；
2. 单跳 TCP 出站无自有帧 → 中间件决策**可**产生（注解可见）但**不产生填充字节**（no-op 旁路，计数可验）；
3. **UDP 面逐数据报填充**（游戏 QoS 对抗的主战场）随 P0-4 §2 `UdpEnvelope` 帧载体落地——该帧天然是"一个数据报 = 一个可控字节边界"，是 padding 的真实用武之地；本条目为其预留同一 `PaddingSpec` 与执行钩子（§2.3、§4.4）。

## 1. 挂载点：静态 middleware 管线（C1 收口）

### 1.1 现状（核对结论，非重述）

- `FlowMiddleware { name(); async handle(Flow) -> Result<Flow> }`（`seep-core/src/lib.rs:234-238`）——S0"trait 不变"成立；
- **零消费点**：全仓无任何代码调用 `FlowMiddleware::handle`，无任何位置构造 `LatencyProbe`（除定义与 re-export）；`ingress → FlowRouter → FlowOutputRouter → egress` 通路**没有注册表/管线/调用点**（status-audit §3，C1）；
- 因此本条目第一件事不是写 padding，而是**建静态挂载点**——padding/timing/shaping 的共同基座（status-audit §5.5）。

### 1.2 `MiddlewareChain`（seep-core 新增最小面）

```rust
// seep-core/src/lib.rs（与 trait 同文件同族，不新 crate）
#[derive(Clone, Default)]
pub struct MiddlewareChain {
    inner: Arc<Vec<Arc<dyn FlowMiddleware>>>,   // 静态链：build 期定序，运行期只读
}

impl MiddlewareChain {
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    /// 顺序执行；任一 middleware 返回 Err 即中止（错误冒泡，语义见 §6 E8）
    pub async fn run(&self, flow: Flow) -> Result<Flow> {
        let mut flow = flow;
        for mw in self.inner.iter() {
            flow = mw.handle(flow).await?;      // 借用检查：Arc 克隆一次，迭代无锁
        }
        Ok(flow)
    }
}
```

- **静态**（`Arc<Vec<..>>`）而非 `RwLock<Vec<..>>`：MVP 无运行期注册需求（P3-2 若需热插拔再改容器，trait 不动）；只读共享零锁开销；
- `LatencyProbe` 原样可入链（实现已满足 trait，无需改）。

### 1.3 调用点：`FlowOutputRouter::forward`（唯一双分派口）

选点理由（可核对）：`forward`（`runtime_builder.rs:1258` 起）是数据通路中**唯一同时持有 `decision` 与 `flow`** 的位置，且是 chain/单跳分派的分叉点（`forward_chain` / `forward_single`）。挂在这里得以在一次调用内完成三段：

```
forward(decision, flow):
  ① 上下文注解注入（§1.4）——把决策信息投影为 middleware 可读的注解
  ② middleware_chain.run(flow)  ← 新增调用点；关闭时 is_empty() 直接跳过
  ③ match &decision.path { Chain => forward_chain(..), _ => forward_single(..) }
```

- chain 与单跳**共用同一注入点**，无需两处接线；
- 与现有 `seep.chain.path` 注入（`runtime_builder.rs:1308`）同族：均为 carrier 侧向注解写数据；
- 入站侧（ingress）**不设**第二个挂载点：positioning §2.4 的位置语义是"egress 传输层两侧"，MVP 取"egress 之前"（决策已定、出站未连）——一处即可覆盖三场景；ingress 侧留待有实际需求时再议（记 §10 未决）。

### 1.4 上下文注解契约（carrier → middleware 单向信息流）

`FlowMiddleware::handle(Flow)` 只看得到 `Flow`（无 `decision` 参数，trait 不变）。因此 **carrier 负责把决策投影成注解**，middleware 只读注解、只写自己的 spec 注解：

| 注解散键 | 写入方 | 值 | 用途 |
|---------|-------|----|------|
| `seep.route.kind` | ①（carrier） | `"chain"` / `"single"` | 供 `apply_to: chain` 类选择器判别 |
| `seep.route.egress` | ①（carrier） | `decision.final_node()`（含 `egress.` 前缀剥离同 `forward_single` 口径） | 供 `apply_to: egress:<name>` 判别 |
| `seep.route.reason` | 已有（`forward_chain`） | 决策原因 | 现状不动 |
| `seep.chain.path` | 已有（`forward_chain`） | 路径 JSON | 现状不动 |
| `seep.obfs.padding` | ②（padding middleware） | `PaddingSpec` JSON | 输出：给帧执行侧读（§2.2） |

- 注解是**单向**的：middleware 只新增/覆盖自己的 `seep.obfs.*` 键，不改 carrier 键（避免中间件互相踩）；
- 键名 `seep.` 命名空间与 `geoip.country`/`client.cidr`（`seep-routing::matches_rule` 读注解的先例）/`seep.chain.path` 一致；
- 该契约使**零 trait 变更**成为可能：新策略（P2-4 timing）只需新增自己的键与执行侧读法。

### 1.5 顺序语义与 P3-2 关系

- 链内**声明顺序即执行顺序**，由 `obfuscation.middleware` 配置数组（§3.1）决定；MVP 仅 `padding` 一个实现，顺序无实义，但契约先钉（P2-4 多策略时会踩）；
- P3-2 动态加载 = 在该静态链之上加 loader：`MiddlewareChain` 的 `Vec<Arc<dyn FlowMiddleware>>` 由 loader 填充（原生动态库/WASM 适配器实现同一 trait）；**本条目不引入任何动态加载依赖**（workspace 现无 `libloading`/`wasmtime`/`wasmer`，已核对）。

## 2. padding 策略（策略 / 执行分离）

### 2.1 设计张力与裁决

- `FlowMiddleware::handle` 的输入是 `Flow{ io: Box<dyn IoStream>, .. }`——**流语义**：`IoStream = AsyncRead + AsyncWrite`（`seep-core/src/lib.rs:18-22`），无消息边界；
- padding 是**帧语义**问题（"把这个包补到 N 字节"）；在无边界字节流上"填充"没有定义——补的字节会被对端当作载荷，且 TCP 线上分段由内核决定，用户态填充不改变包长分布；
- **裁决：策略/执行分离**。不新增 trait、不改 `handle` 签名：
  - **策略侧**（middleware）：`handle` 依据 `flow.target` + §1.4 注解，判定"这个流是否填充、按什么形态填"，把结果写成 `seep.obfs.padding` 注解；**不触碰 `io`**；
  - **执行侧**（帧载体）：carrier 在自己拥有字节边界的位置（`forward_chain` 序列化帧之后、写 wire 之前）读该注解并实施填充；
  - 无自有帧的位置（单跳 TCP）→ 执行侧缺位 → no-op（§2.3），**不做伪实现**。

这一裁决同时解释了为什么 positioning §2.4 的 padding 在 TCP-only 现状下只能有限生效，而 P0-4 的 UDP 面（`UdpEnvelope` 帧）才是其主场。

### 2.2 `PaddingSpec` 与三模式

```rust
// seep-core（与注解契约同文件；serde 序列化进注解，故 core 不依赖 runtime）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaddingSpec {
    pub mode: PaddingMode,          // Fixed | Bucket | Range
    pub target: usize,              // Fixed: 目标长度；Bucket: 桶步长（见下）；Range: 忽略
    pub buckets: Vec<usize>,        // Bucket: 候选桶（升序，非空）
    pub min: usize,                 // Range: 下界
    pub max: usize,                 // Range: 上界
    pub max_overhead_ratio: f32,    // 保护上限（§2.6）
}
```

| 模式 | 语义 | 计算 | 适用 |
|------|------|------|------|
| `fixed` | 一律补到定长 | `len' = target`（若 `len > target` 则不填，计数） | 形态最平滑，开销最大；心跳类小包 |
| `bucket` | 对齐到最近的上界桶 | `len' = min{ b ∈ buckets : b ≥ len }`，无可用桶则不填 | 分布聚簇成少数形态，开销可控（对齐常见应用指纹） |
| `range` | 落入 `[min,max]` 的伪随机长度 | `len' = max(len, min + hash(flow_id, frame_seq) % (max-min+1))` | 打散众数，避免"全对齐"本身成为新特征 |

- **确定性**：`range` 的随机源 = `hash(flow_id, 帧序号)`，非真 RNG——测试可复现，无需 `seed` 配置项（`seep-protocols` 已有 `rand` 依赖，但为可复现性**不使用**它）；
- `frame_seq` 由执行侧**每帧递增**的自计数器提供（同一流内），使同流多帧取到不同长度（避免恒等长）。
- 选择器（"哪些流填"）不属 `PaddingSpec`，属配置层（§3.1 `apply_to`），在 middleware 构造时固定。

### 2.3 执行侧：帧清单（MVP 边界）

| 帧载体 | 是否存在 | MVP 处置 |
|--------|---------|---------|
| chain 的 `MeshEnvelope` 帧（JSON + 4 字节长度前缀，`mesh.md`） | ✅ 既有 | **本条目实现**：序列化后按 spec 填充 + 写 `pad_len`（§2.4） |
| UDP 数据报（P0-4 §2 `UdpEnvelope` 二进制帧） | ❌ 设计已就绪未实现 | 预留执行钩子 + 同 `PaddingSpec`；实施随 P0-4 S5（§4.4） |
| 单跳 TCP 出站载荷 | ❌ 无自有帧（协议各自封装，seep 不握边界） | **no-op**：middleware 可产出 spec 注解，执行侧无载体 → 不产生填充字节，`skipped_total{reason="no_frame"}` 计数 |
| TUN 入站 IP 包（P1-2） | ❌ 未实现 | 归 P1-2；其下行 IP/UDP 包构造点与 UDP 帧同族，届时复用（§10 未决） |

**验收口径落点**：可测的"出口包长分布偏移"= chain 帧（抓包/单测量帧长）；单跳 TCP 的偏移不由本条目承担（§0 说明）；游戏 UDP 的偏移随 P0-4。

### 2.4 `MeshEnvelope` 填充编解码与版本门

- 帧格式现状 = `[len: u32][json]`（`MeshEnvelope{version, flow_id, target_host, target_port, path}`，`mesh_transport.rs:165-176`）；
- 填充 = JSON 追加**尾部填充字节** + JSON 内新增**可选字段** `pad_len: u32`（缺省 0，serde 新增字段对旧端是未知字段）：

```
填充后帧 = [len: u32 覆盖 (json_bytes 含 pad_len=K) + K 填充字节][json][K 字节 0x00]
接收端   = 读 json.pad_len = K → 从帧尾截 K 字节 → 反序列化取 payload
```

- **版本门（必须，不可省）**：旧版接收端不认识 `pad_len`，会把尾部填充当 JSON 尾部 → 解析失败或行为异常。故：
  - 填充**仅在链路两端为支持版本（seep ≥ 本条目落地版本）时启用**；`MeshEnvelope.version` 字段既有，实施时以其值做能力判别（具体版本号实施时定，对齐 §9-4）；
  - 无法确认对端版本时不填充（`skipped_total{reason="peer_version"}` 计数），**连通性优先于伪装**（fail-open，§6 E6）；
  - MVP 简化：默认假定同版本部署（同一发布批次），异版本混布场景以"关闭填充"为安全默认，记 §10 风险。
- 填充字节内容：MVP = `0x00`（长度字节级伪装，不求内容伪装）；`pad_len` 与帧长一致性校验失败 → 丢弃帧 + 计数（§6 E7）。

### 2.5 关闭时零开销旁路

- `obfuscation.enabled=false`（**默认**）→ build 期不构造任何 middleware，`MiddlewareChain::default()`（空 `Arc<Vec>`）；
- `forward` ②处 `if chain.is_empty() { skip }`——一次分支，无锁、无分配、无 async 调用；
- 关闭时**不注入** §1.4 的两个 carrier 注解（省两次 `BTreeMap::insert`）：注解注入本身是填充执行侧的前置，关闭路径一并省去（测试断言注解缺失 = 零副作用，§7.1）；
- 现有配置（无 `obfuscation:` 块）行为**零差异**——沿用 `UdpConfig` 缺省模式（serde default）。

### 2.6 overhead 保护

- `max_overhead_ratio`（默认 0.5）：若 `len' > max(len * (1+ratio), min)`，则**不填充** + `skipped_total{reason="overhead_cap"}`；
- 理由：bucket/range 对小包（如 60B 心跳对齐 1024）会造成显著带宽放大；游戏中高频小包场景下这是真实的成本，必须有上限；
- 上限是**策略层**语义（middleware 判定，写 spec 前即放弃），执行侧只按 spec 办事（不再二次判定）。

## 3. profile 开关 schema（seep-config 镜像 + runtime 转换）

### 3.1 区块形状

```yaml
obfuscation:
  enabled: false                   # 总开关；false = 零开销（§2.5）
  default_padding: game            # 引用 profiles 中的名字；无则用内联 padding
  apply_to: chain                  # chain | single | all | "egress:<name>"
  middleware: [padding]            # 声明链顺序（MVP 仅 padding 可写）
  profiles:
    game:                          # 命名策略集（P2-3 三预设将落在此处）
      padding:
        mode: bucket
        buckets: [256, 512, 1024]
        max_overhead_ratio: 0.5
    web:
      padding:
        mode: range
        min: 512
        max: 1400
        max_overhead_ratio: 0.3
  padding:                         # 内联策略（无 default_padding 时生效；两者互斥，§3.3）
    mode: fixed
    target: 512
```

### 3.2 镜像类型与转换（裁决：镜像而非加依赖）

seep-config 零依赖 seep-core/platform（deps 仅 anyhow/serde 系），保持其轻：**seep-config 定义镜像 serde 类型，seep-runtime 增 `to_padding_policy()` 转换**（与 `UdpConfig` → `UdpSessionConfig` 同模式）。

| config 镜像类型（seep-config） | runtime 转换产物 |
|-------------------------------|-----------------|
| `ObfuscationConfig { enabled, default_padding: Option<String>, apply_to: ApplyTo, middleware: Vec<String>, profiles: BTreeMap<String, ObfsProfileConfig>, padding: Option<PaddingBlockConfig> }` | 构造 `Vec<Arc<dyn FlowMiddleware>>`（MVP 至多含一个 `PaddingMiddleware`）|
| `ApplyTo::{Chain, Single, All, Egress(String)}` | middleware 内固化的选择器闭包（匹配 §1.4 注解） |
| `ObfsProfileConfig { padding: Option<PaddingBlockConfig> }` | 解析出被选中的 `PaddingBlockConfig` |
| `PaddingBlockConfig { mode, .. 各模式字段 }` | `PaddingSpec`（`mode` 字符串 → `PaddingMode` 枚举，字段按模式校验后填充） |

### 3.3 校验（构建期，`ObfuscationConfig::validate`）

1. `enabled=false` → 后续字段全部无视（不报错，容忍半成品配置）；
2. `default_padding` 与内联 `padding` **同时存在** → Err（歧义）；两者皆缺且 `enabled=true` → Err（开了但没有策略）；
3. `default_padding` 指向 `profiles` 中不存在的名字 → Err；
4. `mode` 非 `fixed|bucket|range` → Err（E2）；`bucket` 时 `buckets` 空或非严格升序 → Err；`range` 时 `min > max` → Err；`fixed` 时 `target == 0` → Err；
5. `max_overhead_ratio < 0` → Err；`middleware` 含未知名字（MVP 仅 `padding`）→ Err；
6. `apply_to: egress:<name>` 指向配置中不存在的 egress 名 → **warning + 降级为不生效**（不 Err：egress 名可来自订阅热更新，构建期未必齐备，E5）。

### 3.4 兼容与静默忽略

- 存量配置无 `obfuscation:` → `#[serde(default)]` 缺省，行为零差异（serde 往返测试钉住，同 `udp` 块先例）；
- **`ObfuscationConfig` 加 `#[serde(deny_unknown_fields)]`**——新块无存量兼容负担，拼错子字段立刻报错（对齐 [network-route.md](network-route.md) §1.5 的 B2 定向收口）；全局 `SeepConfig` 维持宽松（存量配置可能携带额外键）。

### 3.5 与 P2-3 场景预设的边界

- P1-4 交付 `profiles` **容器语义**（命名策略集 + 选择）与 `game`/`web` 两个**示例**，不交付"三场景完整模板"（路由规则 + 调度目标 + 混淆开关的组合是 P2-3）；
- P2-3 落地时在 `profiles` 下扩字段（如 `routing_template`），本文 schema 为其**真子集**——不产生二次迁移。

## 4. 与既有 middleware / 出站链衔接

### 4.1 `LatencyProbe` 处置（不默认挂载）

- 现状：唯一 `FlowMiddleware` 实现，`handle` = `sleep(1ms)` 后原样返回（`seep-protocols/src/middleware/latency_probe.rs`）——**纯占位语义**，且 `sleep(1ms)` 每流引入 1ms 延迟；
- 裁决：**不纳入 MVP 默认链**（把 1ms 延迟加进生产通路不可接受）；仅在配置显式 `middleware: [latency_probe]` 时挂载，用于验证管线连通（§8 M1 的接线证明）与调试；
- 其"延迟探测"名义与 `seep-routing` 的 `latency` 组策略无关（组策略走 mesh 健康数据），文档明示避免误用。

### 4.2 chain 路径衔接（`forward_chain` 内）

- 新增执行点：`MeshEnvelope` 序列化为 JSON **之后**、经 `MeshDataPlane` 写 wire **之前**；
- 读 `flow.metadata.annotations["seep.obfs.padding"]` → 解析 `PaddingSpec` → 按 §2.4 填充并写 `pad_len`；
- 注解缺失/解析失败 → 不填充（E6/E8 语义：伪装是增益，不得破坏转发）；
- 帧长上界：填充后帧 ≤ TCP envelope 既有上限（64KB，`mesh.md`）；超限则不填充 + 计数（E4）。

### 4.3 单跳出站衔接（hook，MVP no-op）

- `forward_single` 同样**可读**注解，但 MVP 无帧载体 → 不做任何字节改写；仅在 §5 指标计数 `skipped_total{reason="no_frame"}`；
- 预留：未来若某出站协议提供自有帧（如 VLESS/VMess 的分帧载荷），以该出站的写入层为执行点，复用同一 spec——留 hook 不实现（§10 未决）。

### 4.4 UDP 面衔接（P0-4 §2 = 天然帧）

- P0-4 的 `UdpEnvelope`（二进制头 + payload，单包 ≤ MTU/65507）是 padding 的**理想载体**：一数据报 = 一个可控字节边界，填充直接影响 QoS/DPI 观察到的包长分布（游戏加速主场）；
- 衔接点 = P0-4 §4 `MeshDataPlane` UDP 面的**发送路径**（envelope 编码后、`send_to` 前），与 §4.2 的 chain 点位同构；
- 本条目**只留钩子 + spec 复用**，不实现：P0-4 落地时其 UDP 编码器读 `seep.obfs.padding` 即可，零 schema 变更（同一 `PaddingSpec`）。
- **2026-09-30 修订（P0-4 [udp-mesh-dataplane.md](udp-mesh-dataplane.md) §17-P1-4 / D-15）**：上文"UDP 编码器读注解"隐含注解已存在——但注解生产点（§1.3 middleware 链，挂在 `FlowOutputRouter::forward`）只在 TCP Flow 路径，**UDP 会话路径（associate → `UdpRelay::send_to`）无 Flow 可挂链**。裁决：UDP 面 spec 生产改为 **associate 会话级求值**（复用 `PaddingSpec` 与策略纯函数 + §3.1 选择器，按会话 target/egress 判定），不经 `FlowMiddleware::handle`——与本节 §2.1"流签名不承载帧语义"同因的第二次出现。执行钩子（编码后 send_to 前）、`PaddingSpec` 复用与零 schema 变更口径不变；重编码侧不追加填充等实施细节见 P0-4 D-16。

### 4.5 与 P2-6 envelope 二进制化的关系

- P2-6（TCP 面 envelope 二进制化）与本条目的 `pad_len` 字段**同处一个格式定稿点**：若 P2-6 先落地，`pad_len` 改为二进制头中的一个字段（语义不变，仅编码变化）；若 P1-4 先落地，P2-6 迁移时带上该字段。二者**不互斥、无先后硬依赖**，但实施时应对齐同一格式版本（记 §10）。

## 5. 指标（`seep_obfs_*` 家族，封闭标签集）

```
seep_obfs_middleware_invocations_total{name}          # 链内各 middleware 调用次数
seep_obfs_padding_frames_total{mode}                  # 实际填充的帧数（mode=fixed|bucket|range）
seep_obfs_padding_bytes_total{direction="added"}      # 累计新增填充字节
seep_obfs_padding_skipped_total{reason}               # no_frame | overhead_cap | too_large | peer_version | disabled
```

- 标签全为**封闭枚举**（R11 先例：不带 target/flow 维度，避免基数失控）；per-link/per-target 细分属 P2-1；
- 挂接 `/metrics` 手写渲染路径（`apps/seepd/src/control_plane.rs`，与 `seep_udp_*`/`seep_tun_*` 同族；与 [udp-observability.md](udp-observability.md) §7 落点清单并列）；
- `skipped_total{reason}` 与 §2.5 的零开销断言共同构成"关闭/不适用时无副作用"的可观测证据。

## 6. 错误路径

| # | 错误点 | 条件 | 语义与恢复 |
|---|--------|------|-----------|
| E1 | 配置缺策略 | `enabled=true` 且无 `default_padding`/内联 | 构建期 Err（§3.3-2） |
| E2 | 模式非法 | `mode` 非三值 / 参数不合法（空 buckets、min>max、target=0） | 构建期 Err 带原值（§3.3-4） |
| E3 | 策略名不存在 | `default_padding` 指向未定义 profile | 构建期 Err |
| E4 | 填充后超帧上限 | chain 帧 > 64KB（或 UDP 面 > 65507） | **不填充** + `skipped{too_large}`，转发继续 |
| E5 | `apply_to` 指向不存在 egress | 订阅热更新导致构建期未齐 | warning + 不生效（不 Err，§3.3-6） |
| E6 | 对端版本不支持 | 无法确认链路易端 ≥ 本条目版本 | **不填充** + `skipped{peer_version}`；连通性优先（§2.4） |
| E7 | 填充帧校验失败 | 接收侧 `pad_len` 与帧长不符 | 丢弃该帧 + 计数（不给上层错帧） |
| E8 | 中间件返回 Err | 任何 `handle` 失败 | 链 `run` 中止，错误冒泡至 `forward` → 转发失败（不静默继续；MVP 无中间件会真失败） |
| E9 | spec 注解解析失败 | 注解存在但非法 JSON/字段 | 视为无 spec → 不填充（伪装层不得破坏转发） |
| E10 | overhead 超上限 | `len' > max(len*(1+ratio), min)` | 策略层放弃 + `skipped{overhead_cap}`（§2.6） |
| E11 | 关闭路径 | `enabled=false` | 非错误：链空、注解不注入、零分配零锁（§2.5） |

## 7. 测试策略

### 7.1 单测（无特权，任何环境）

- **策略引擎**（纯函数，`PaddingSpec` → `(len', Option<pad_len>)`）：
  - `fixed`：`len ≤ target` 填到 `target`；`len > target` 不填；
  - `bucket`：`len` 恰在桶上不填；桶间隙取最近上界；超最大桶不填；buckets 升序不变式；
  - `range`：结果落 `[max(len,min), max]`；**同 flow_id 同帧序号可复现**（确定性断言）；不同帧序号取值不同；
  - `max_overhead_ratio`：小包对齐大桶时放弃填充（E10 断言）+ 计数；
- **`PaddingSpec` 编解码**：JSON roundtrip；非法 JSON 得 E9 语义（不填充）；
- **`MeshEnvelope` pad/strip**：填充后 `pad_len` 与帧长一致；strip 后 payload **逐字节相等**（golden vector）；`pad_len=0`（未填）路径与旧行为字节一致；
- **`MiddlewareChain`**：空链 `run` 直接返回（零调用断言：mock middleware 计数=0）；顺序（两个 mock 记录执行序）；`Err` 中止且不执行后续；`is_empty()` 旁路（§2.5）；
- **carrier 注解注入**：`chain` 决策 → `seep.route.kind=chain` + `seep.route.egress` 存在；单跳 → `kind=single`；**关闭时两键均缺席**（零副作用断言）；
- **schema**：无 `obfuscation:` 旧配置解析 ✓；含块 roundtrip ✓；未知子字段 deny 拒绝 ✓；三模式非法值/空 buckets/min>max/target=0 ✓；`default_padding`+内联并存 Err ✓；策略名不存在 Err ✓；
- **选择器**：`apply_to` 四值对 mock 注解集的匹配/不匹配两态。

### 7.2 集成（mock 链路，无特权）

- **chain 填充全链路**：mock `MeshRegistry` + 两端 `MeshDataPlane`（沿用 `runtime_builder.rs:1991` 既有测试形态）→ 一侧开启 `mode=bucket` 发流 → 抓取 wire 帧长断言 ∈ buckets（或 ≤ 上限）→ 对端 strip 后 payload 一致；
- **关闭对照**：同流同配置但 `enabled=false` → wire 帧长与开启前**完全一致**（分布不变，零字节差异）+ `padding_frames_total{...}=0`；
- **单跳 no-op**：mock egress 记录写入字节 → 开启 padding 后写入字节与关闭时一致 + `skipped{no_frame}` 递增；
- **包长分布统计脚本**（验收口径，§0）：对 wire 帧长取直方图，断言开启后分布偏离默认（如众数桶变化）；脚本随 M4 落地（§8）。

### 7.3 门禁

- 单测/集成套件**无特权依赖**（纯用户态 mock，CI 常规跑；不依赖 `/dev/net/tun`）；
- 全仓基线（当前 P0-3 时点 118 项 + 后续增量）**零回归**：本条目全部为增量，关闭路径不改既有行为（§2.5）；
- 关闭态断言必须存在（否则"零开销"不可证）。

## 8. 分步实施清单（M0–M5）

提交节奏循 P0-4 §9.1.1 / tun-dataplane §5 铁律：每步 `cargo build` + `cargo test` 全绿 → 单条 commit（引用本文 §节）→ `git fetch origin main` + rebase → push → 下一步；禁 tag/release/force push。

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M0 | seep-config：`ObfuscationConfig`/`ObfsProfileConfig`/`PaddingBlockConfig` + `deny_unknown_fields` + `validate`；seep-runtime：`to_padding_policy()` 转换 | — | 7.1 schema/转换全绿；旧配置零差异 |
| M1 | **挂载点**（C1 收口）：`MiddlewareChain`（seep-core）+ `FlowOutputRouter::forward` 三段接线 + §1.4 注解注入 + `LatencyProbe` 显式可挂 | — | 7.1 链与注解注入全绿；显式挂 `LatencyProbe` 证明管线通（默认不挂，§4.1） |
| M2 | `PaddingMiddleware`（seep-protocols）+ 策略引擎纯函数 + `PaddingSpec` | M0 | 7.1 策略引擎与编解码全绿 |
| M3 | 帧执行侧：`MeshEnvelope` pad/strip + 版本门 + 上限/overhead 计数 | M1,M2 | 7.1 pad/strip golden；7.2 chain 填充全链路 |
| M4 | 指标（§5）+ 统计脚本 + 关闭态对照断言 | M3 | 7.2 分布脚本；`seep_obfs_*` 序列可见 |
| M5 | 文档回填（PROTOCOLS.md 性能/安全节混淆行、positioning §2.4 现状注记、todo 勾选、验收口径核对） | M0–M4 | P1-4 验收逐条核对；口径改写（§0）与 todo 同步 |

验收对齐：P1-4 = M0–M4（M5 为文档收口）。"开启后包长分布偏离+可配置目标形态" = M3+M4（chain 帧口径，§0）；"关闭时零开销旁路" = M1 空链旁路 + M4 关闭态断言（§2.5、E11）。

## 9. 偏差与假设（信息缺失处的自行假设均已注明）

| # | 类型 | 内容 |
|---|------|------|
| 1 | 裁决 | **策略/执行分离**：middleware 只产出 `seep.obfs.padding` 注解，填充由帧载体执行（`handle(Flow)` 流签名无法承载帧语义，§2.1）；零 trait 变更 |
| 2 | 裁决 | 挂载点唯一且落在 `FlowOutputRouter::forward`（`runtime_builder.rs:1258`）——数据通路唯一同时持有 `decision` 与 `flow` 的位置；ingress 侧不设第二挂载点（positioning §2.4"egress 之前"） |
| 3 | 裁决 | 决策上下文经注解投影（`seep.route.kind`/`seep.route.egress`）供 middleware 只读；注解命名空间 `seep.` 循 `seep.chain.path` 先例 |
| 4 | 假设 | `MeshEnvelope.version` 可用作填充能力判别；具体版本号与旧端忽略未知字段的确切行为**实施时核对**（serde 默认忽略未知字段，但填充字节会污染尾部，故必须版本门而非仅靠字段忽略，§2.4） |
| 5 | 裁决 | MVP 帧载体仅 chain 的 `MeshEnvelope`；单跳 TCP 无自有帧 → no-op（不伪造），UDP 帧随 P0-4（§2.3、§4.4） |
| 6 | 裁决 | `LatencyProbe` **不默认挂载**（1ms sleep 为占位语义，进生产通路引入延迟）；仅显式配置时挂载用于验证管线（§4.1） |
| 7 | 裁决 | 静态链（`Arc<Vec<Arc<dyn FlowMiddleware>>>`）而非可写容器；P3-2 动态加载在此之上扩展，本条目不引动态加载依赖（§1.5） |
| 8 | 裁决 | 新块 `deny_unknown_fields`（无存量负担）；全局 `SeepConfig` 不收紧（存量兼容，同 network-route §1.5） |
| 9 | 修正 | todo 验收"出口包长分布偏离"在 TCP 面不可字面达成（内核决定线上分段）；口径改写为 chain 帧/ UDP 帧（§0），**显式登记而非静默缩水**（对齐 P0-3 hy2 改判做法） |
| 10 | 裁决 | 填充字节内容 MVP = `0x00`（只做长度伪装）；内容伪装与流量整形属 P2-4/P2-5 |
| 11 | 假设 | profile 容器语义由本条目交付，三场景完整模板归 P2-3；本文 schema 为 P2-3 真子集 |

## 10. 风险与未决

- **R-obfs1（核心）**：TCP 面 padding 的实际效力受限于"seep 自有帧"——现状只有 chain 的 JSON envelope 帧。逐包长度伪装对**任意 TCP 协议**需要协议级帧层（TLS record padding / 协议自带填充），非中间件可凭空做到；真正的抗 QoS/DPI 主场是 **UDP 面**（游戏为 P0-4，QUIC 透传同）——本设计不夸大 TCP 面能力（§2.3）。
- **R-obfs2 版本耦合**：chain 填充要求链路两端同支持版本，混布升级窗口内会退化为不填充（fail-open）；长窗口混布下"开而不效"需靠 `skipped{peer_version}` 指标被看见（§2.4、E6）。
- **R-obfs3 带宽成本**：填充直接放大出口字节量（尤其 `fixed` 大目标对高频小包）；`max_overhead_ratio` 是唯一闸门，默认值与压测确认记入 M4（§2.6）。
- **R-obfs4 对齐本身成为特征**：全流对齐到少数固定桶会使包长分布呈尖峰（众数偏移），可能被"分布形状"而非"具体值"识别——`range` 模式与"多个相邻桶"配置即为此；与 P2-4 timing 的联合验证（同一统计方法）在 P2-4 落地时进行（todo P2-4 验收已挂同款要求）。
- **O-obfs1**：ingress 侧挂载点（入向填充/解填充）是否需要——MVP 不做，需求出现再议（§1.3）。
- **O-obfs2**：单跳出站的具体帧机会（VLESS/VMess 分帧载荷）——留 hook 不实现（§4.3）。
- **O-obfs3**：TUN 入站下行包（P1-2 §2.3 的 IP/UDP 构造点）是否复用 UDP 帧填充——随 P0-4/P1-2 一并议（§2.3）。
- **O-obfs4**：与 P2-6 二进制 envelope 的格式定稿顺序（`pad_len` 字段编码）——无硬依赖，需对齐同一格式版本（§4.5）。
