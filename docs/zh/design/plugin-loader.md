# P3-2 插件动态加载（WASM FlowMiddleware）— 实现级设计

> 上游：[roadmap.md](roadmap.md) S4（「插件动态加载：WASM/动态库 `FlowMiddleware` 加载器 + 限速/内容过滤示例」勘误降级条目）· [obfuscation-middleware.md](obfuscation-middleware.md) §1.2/§1.5（静态链 + 「P3-2 动态加载在此容器之上扩展，trait 不动」）。
> 本文是落地定稿：**范围裁决、载具与 ABI、隔离机制、配置面、示例插件、计数面、测试策略、分步清单**。落地后偏差回填 §9。
> 复用基线：`FlowMiddleware` trait（seep-core，name/handle 两方法）· `MiddlewareChain` 静态容器（build 期定序、运行期只读，P1-4 §1.2 C1）· `FlowOutputRouter::forward` E8 错误路径（任一 middleware Err 即中止）· `ObfuscationConfig` schema + validate（E1/E2 先例）· P1-5 池/工厂进程级单例（D-10）单例先例。

## 0. 范围裁决

| 在本条目内 | 归 V2 / 其他 |
|-----------|-------------|
| **WASM 载具**（wasmtime）：载入器 + `FlowMiddleware` 适配器 + 进程级 engine 单例；崩溃（trap）与超时（fuel 指令预算）隔离 | **动态库直载**（libloading 同进程）：无法兑现「崩溃有隔离」验收（同地址空间无隔离边界），待有真实需求另开条目（§9 偏差 1） |
| **两个示例插件**：限速（令牌桶，实例内存态）+ 内容过滤（首块关键词扫描）；`plugins/` 目录独立构建（非 workspace 成员，wasm32-unknown-unknown 交叉编译） | 插件 I/O 面（网络/文件/时钟）：MVP 插件纯计算、零 WASI（宿主注入 `now_ms`——wasm32-unknown-unknown 无时钟）；异步 host function 归 V2 |
| **配置面**：`obfuscation.plugins` 块（路径 + fuel 预算），build_middleware_chain 追加挂载；seepd 现为启动时一次性读配置（配置热更新未接线），插件链进程内静态、随进程重启换代 | 插件热插拔/运行期装卸（无独立装卸 API）|
| **首块探测内容过滤**：`wants_payload` 导出声明 + `Flow.io` 首块探测/回放包装 | 载荷**改写**（MVP 只 allow/deny 二值裁决，不改写流字节——HTTP 级改写语义面归 V2）|
| **计数面**：per-plugin 原子计数（calls/denied/traps/fuel_exhausted）+ tracing 日志；**控制面 `GET /plugins/stats` 已接线**（2026-10-05 观测轮：runtime 旁路具体类型句柄 + getter 快照）| /metrics 指标族形态（端点 JSON 已可用；prometheus 序列归后续按需）|

**验收口径**（todo P3-2 原文，逐一兑现）：①「外部编译的示例插件可加载并生效」= `plugins/` 两示例以独立 cargo 构建 wasm32 产物，宿主载入后链上生效（限速：令牌耗尽后拒流；内容过滤：首块命中即拒）；②「崩溃/超时有隔离」= trap 插件（unreachable）与死循环插件（fuel 耗尽）均以 Err 收敛于该次 `handle` 调用（E8 拒流），进程与后续流不受影响（§4 单测钉死）。

## 1. 载具与 ABI

### 1.1 载具裁决：WASM（wasmtime）

- 验收「崩溃/超时有隔离」**只有 WASM 能兑现**：trap（unreachable/OOM/栈超）在 wasmtime 层转 Err，同进程动态库崩溃即进程崩溃，无隔离可言；fuel 指令预算是同步调用的唯一可硬中止机制（§3）；
- 依赖成本如实登记：wasmtime 进 workspace（seep-plugins crate），首编一次性成本（cranelift），`default-features = false` 只留 `cranelift + runtime + wat`（wat 供测试内联 WAT，生产载入二进制 .wasm）；
- engine 进程级单例（D-10 同法）：编译器/JIT 全局一份，插件间共享；每插件独立 `Instance`/`Store`（状态隔离）。

### 1.2 插件 ABI（wasm32-unknown-unknown，自定义导出，无 WASI）

插件导出（Rust 源面 = `#[no_mangle] extern "C"`）：

| 导出 | 签名 | 语义 |
|------|------|------|
| `memory` | linear memory | 宿主读写参数/结果区（`alloc` 分配） |
| `alloc(size: u32) -> u32` | bump 分配 | 宿主在插件线性内存里取结果缓冲（每次调用前分配，生命周期单次调用） |
| `plugin_name() -> u32` | ptr | NUL 结尾 UTF-8 插件名（宿主载入时读一次，`Box::leak` 固化为 `&'static str`——trait 签名不动，obfuscation-middleware.md §1.5 承诺兑现） |
| `wants_payload() -> u32` | 0/1 | 是否需要首块载荷（内容过滤类插件置 1；宿主据此决定是否探测） |
| `on_flow(ctx_ptr: u32, ctx_len: u32, out_ptr: u32, out_cap: u32) -> i32` | 写出长度 | ≥0 = 写入 out 缓冲的决策 JSON 字节数；<0 = 插件内错误码（宿主转 Err） |

### 1.3 上下文与决策（JSON over 线性内存）

宿主 → 插件（`FlowContext` JSON）：

```json
{"flow_id":"<uuid>","host":"example.com","port":443,"proto":"tcp",
 "now_ms":1760000000000,"annotations":{"seep.route.kind":"chain"},
 "first_chunk":"<base64，wants_payload=1 时携带；上限 4096B>"}
```

- `now_ms` 宿主注入——wasm32-unknown-unknown 无时钟（§0 载具裁决）；
- `first_chunk`：`wants_payload()=1` 时宿主先从 `Flow.io` 探测首块（单次 `read`，上限 4096B——内核按到达即返，交互流无额外迟滞），base64 入 ctx；插件拒/允许后宿主把探测字节以回放 io 包装还流（§2.2）。

插件 → 宿主（决策 JSON）：

```json
{"action":"allow|deny","note":"<可选说明>",
 "set_annotations":{"k":"v"},"remove_annotations":["k"]}
```

- `deny` → 适配器 `bail!`（E8 既有语义：该流中止，错误冒泡）；
- `set_annotations`/`remove_annotations`：插件可写 `metadata.annotations`（§1.4 契约同款——carrier 键 `seep.*` 由内置链写，插件建议用自有命名空间如 `plugin.<name>.*`，文档约定不强制）。

## 2. 宿主侧

### 2.1 载入器（crates/seep-plugins）

```rust
pub struct PluginLoadOptions { pub fuel: u64 }        // 每调用 fuel 预算
pub fn load_plugin(path: &Path, opts: PluginLoadOptions) -> Result<Arc<dyn FlowMiddleware>>;
```

- 流程：读 .wasm → `Module::new`（进程级 engine 单例）→ 实例化 → 校验必备导出（memory/alloc/plugin_name/on_flow）→ `wants_payload` 探测 → 组装 `WasmPluginMiddleware`；
- `Store` 以 `Mutex` 串行化（wasmtime `Func::call` 需 `&mut Store`；插件全局状态如令牌桶天然共享于同实例全部流——限速语义正确性所在；串行化代价 = 同插件调用排队，MVP 接受，§9 偏差 4）；
- 每次 `on_flow` 调用前重置 fuel（`set_fuel(opts.fuel)`）——预算按调用计，不按流计。

### 2.2 首块探测回放（`wants_payload=1`）

- `handle()` 内：`flow.io.read()` 单次读至多 4096B → 入 ctx → 调插件 → **deny 即 `bail!`**（探测字节随流丢弃，连接关闭）→ **allow 则把探测字节回放**：`ReplayIo { replay: Vec<u8>, inner: Box<dyn IoStream> }` 实现 `AsyncRead`（先回放后透传）+ `AsyncWrite`（直透）——`IoStream` blanket impl 自动适配（seep-core lib.rs:18）；
- 时序假设（如实登记）：`forward()` 在链执行（§2.1 runtime_builder.rs:1740）后才把 flow 交出站连接器，链内探测是首读者；观测面无违例先例。

### 2.3 配置面（seep-config `ObfuscationConfig.plugins`）

```yaml
obfuscation:
  enabled: true
  middleware: [padding]           # 内置链（既有，序在前）
  plugins:                        # P3-2 新增（内置链之后追加，MVP 裁决无执行序配置）
    - path: plugins/output/rate_limit.wasm
      fuel: 100000000             # 每调用指令预算（缺省 1e8）
```

- validate：`enabled` 时 path 必须存在（E1 同款构建期拦截）；`plugins` 计入「已配策略」判据（现有 E1「enabled=true 但未配策略」扩 `|| !plugins.is_empty()`）；
- 挂载点：`build_middleware_chain`（obfs_config.rs）内置循环之后追加插件适配器——链序 = 内置声明序 + plugins 声明序。

## 3. 隔离机制（验收②）

| 隔离面 | 机制 | 语义 |
|--------|------|------|
| 崩溃（trap：unreachable/OOM/栈超/除零） | wasmtime 转 `Err`（`Trap` downcast 记 `traps` 计数 + tracing warn） | 该次 `handle` Err → E8 拒该流；Store 未毒化（wasmtime trap 不灭实例），后续流照常 |
| 超时/死循环 | **fuel 指令预算**（每调用重置）：耗尽即 trap（`OutOfFuel`），`fuel_exhausted` 计数 | 硬上界与 wall-clock 无关——同步调用无法被外部抢占，fuel 是唯一可中止机制（§9 偏差 3：wall-clock 只观测报慢，不做中止依据） |
| 内存 | 线性内存有界（wasmtime 默认上限），宿主侧 `out_cap` 上界钳制 | 插件无法越界读写宿主内存（WASM 沙箱本征） |

## 4. 测试策略

### 4.1 单测（seep-plugins，内联 WAT，零外部文件，CI 确定性）

- **noop**：名字/allow/注解 set+remove 往返；
- **trap**：`unreachable` 模块 → Err 收敛、`traps=1`、**同插件下一调用仍成功**（Store 未毒化——隔离语义核心断言）；
- **死循环**：`loop br 0 end` → fuel 耗尽 Err、`fuel_exhausted=1`；
- **首块探测**：mock io（duplex 对），deny → 读侧 Err；allow → 回放字节完好 + 后续透传；
- **载入器负路径**：缺导出/坏 magic → Err 带因。

### 4.2 示例插件验收实况（`plugins/`，独立构建）

- `cargo build --target wasm32-unknown-unknown`（两示例 + 逻辑纯 Rust 单测随插件 crate 自跑）；
- 宿主集成验证（本机执行，成果入 todo 进度）：限速——第 N+1 流 deny 且 note 可见；内容过滤——首块含关键词 deny、干净载荷 allow 透传；
- trap/死循环隔离由 4.1 WAT 单测钉死（WAT 与插件同 ABI 面）。

### 4.3 配置面（seep-config / seep-runtime）

- plugins 块 deny_unknown_fields + validate 矩阵（path 不存在 E1、disabled 容忍半成品）；
- `build_middleware_chain` 装配测试：plugins 在内置链之后、链名序断言、坏路径构建期 Err。

## 5. 分步实施清单（R0–R2）

提交节奏循 P0-4 §9.1.1 铁律：每步 build/test 全绿 → 单 commit（引用本文 §节）→ fetch+rebase → push；禁 tag/force。

| 步 | 内容与落点 | 验收 |
|----|-----------|------|
| R0 | 本文设计稿 | — |
| R1 | loader + 适配器 + 首块回放 + 配置面：crates/seep-plugins（engine 单例/ABI/隔离/计数）+ seep-config plugins 块 + seep-runtime 装配 + 4.1/4.3 单测 | 全绿 |
| R2 | 示例插件 + 验收实况 + 文档回填：plugins/ 两示例（独立构建脚本）+ 4.2 实况 + todo P3-2 勾选 + obfuscation-middleware.md §1.5 注记 + §9 偏差 | 全绿 + 实况 |

## 6. 偏差与假设

| # | 类型 | 内容 |
|---|------|------|
| 1 | 范围 | **动态库直载不在 MVP**：同进程无法隔离崩溃（验收②不可兑现），libloading 路线待真实需求另开；「WASM/动态库」按 WASM 兑现 |
| 2 | 假设 | 插件纯计算零 WASI：时钟由宿主注入（now_ms）、无文件/网络面；异步 host function 归 V2 |
| 3 | 偏差 | wall-clock 不做中止依据（同步调用不可抢占）；fuel 是唯一硬上界，配置面暴露 fuel 预算调优 |
| 4 | 偏差 | 同插件调用经 Store Mutex 串行化——限速状态正确性优先于并发度；插件并发度归 V2（多实例分片） |
| 5 | 范围 | 载荷只 allow/deny 不改写（HTTP 级改写语义面归 V2）；观测面控制面接线已兑现（2026-10-05，`GET /plugins/stats`，§0 计数面行）|
| 6 | 假设 | 链内首块探测是 flow.io 首读者（forward 在链后才交出站连接器——runtime_builder §2.1 时序）；若未来有链前读者，探测语义需重裁 |

## 7. 风险与未决

- **P-load**：wasmtime 首编成本进 workspace（如实登记）；构建期 `plugins/` 不在 workspace members（wasm 专属 crate 不可宿主编译），seepd 发行物含 loader 不含示例产物（README 记构建法）；
- **R-name**：`plugin_name()` 返回宿主 `Box::leak` 固化——泄漏量 = 插件数 × 名字长（载入一次，生命周期进程级，可接受；记录于源注释）；
- **R-state**：插件实例状态（令牌桶）随 Store 存活至进程退出——seepd 无配置热更新接线（启动一次读入），链在进程内不重建，令牌桶实际随进程退出清零；若未来接入热更新重建链，旧实例随 `MiddlewareChain` Arc 消亡、状态同为清零语义。

## 9. 落地回填（2026-10-04，R1/R2 全部兑现）

**R1**（loader + 配置面）：`crates/seep-plugins`（lib.rs/abi.rs/loader.rs/plugin.rs/replay.rs）+ seep-config `ObfsPluginConfig` + seep-runtime `build_middleware_chain` 装配——§2/§3/§4.1/§4.3 逐条兑现；单测 10 项全绿（noop 注解往返 / deny bail / trap 隔离+Store 未毒化 / fuel 耗尽 / 首块回放+透传 / 探测后 deny / 谎报决策长度 / 坏 magic / 缺导出 / ReplayIo poll 语义）。

**R2**（示例 + 实况）：`plugins/rate-limit`（令牌桶容量 3、秒回 1，`now_ms` 宿主注入推进回补）与 `plugins/content-filter`（内置禁词表 base64 解码后小写化子串匹配）——独立 `[workspace]`、不入 members（§7 P-load），`plugins/build.sh` 产 `plugins/output/*.wasm`（gitignore 不入库）；宿主侧纯逻辑单测随 crate 自跑（回补封顶 / 大小写不敏感命中）。**验收实况**：`cargo run -p seep-plugins --example plugins_smoke`——限速 3 放 1 拒（note 可见）、`/wp-admin` 命中拒、干净载荷 allow 且首块回放完好 + 后续透传、per-plugin 计数实证。

实现期修正（与 §1/§2 初稿的差异，均不越 §0 范围裁决）：

| # | 项 | 落地形 |
|---|-----|--------|
| 1 | wasmtime 49 自有 `Error` 类型（非 anyhow re-export） | Cargo.toml 显式保留 `anyhow` feature（`From<wasmtime::Error> for anyhow::Error` 桥）；宿主侧上下文经 `map_err(anyhow::Error::from)` 后挂 anyhow `context` |
| 2 | wasmtime 49 导出查找 API | `get_typed_func` 返回 `Result`（缺导出即 Err，携「failed to find function export」）；可选导出（wants_payload）先 `get_export`（Option）探存在 |
| 3 | 载入期探测调用缺燃料 | `consume_fuel(true)` 引擎下 Store 初始 fuel=0——载入期 `wants_payload`/`plugin_name` 探测前先 `set_fuel(u64::MAX)` 放开（每调用预算重置语义仍归 invoke，§2.1 不变） |
| 4 | 示例插件线性内存扩容 | `alloc` 内 `memory_size`/`memory_grow` 按需扩页（`#[cfg(target_arch = "wasm32")]` 门控——宿主 `cargo test` 只走纯逻辑面不触 alloc）；cdylib 产物名随包名（`seep_plugin_<name>.wasm`），build.sh 复制为对外名 |
| 5 | 死循环 WAT 形 | `(loop br)` 后必须补 `unreachable` 方过 wasm 类型校验（函数结果 i32 的静态可达性要求） |
| 6 | 计数面观测载体 | §0 计数面「控制端点接线归后续观测轮」已兑现两步：`WasmPluginMiddleware::stats()`（`Debug` 呈现 + `plugins_smoke` 实证）；2026-10-05 观测轮补控制面 `GET /plugins/stats`（runtime `get_plugin_stats()` 快照旁路，`load_plugin_with_stats` 同实例双句柄——链内 trait 对象、观测具体类型，不二次 JIT）；/metrics 指标族形态归后续按需 |

§6 偏差表无新增（偏差 1–6 全部按原裁决兑现）。
