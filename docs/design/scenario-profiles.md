# P2-3 场景 profile 预设（设计稿）

> 2026-10-02 就绪。`proxy` / `game` / `web` 三套配置模板（路由规则 + 混淆
> 开关 + 调度目标），底层同一引擎。positioning.md §2.5：三场景差异 =
> 路由策略模板 + 中间件组合 + 出站协议选择，全部是配置层组合，不需要
> 分支代码路径。
>
> **落地状态**：✅ 已实现（M0 2369c0d：ProfileKind + apply_profile 缺省
> 填充 + 单测 §7-1..5；M1 本提交：examples/ 三份示例 + §7-6 集成测 +
> 文档回填）。

## 0. 范围与验收口径

**todo 原文**：`proxy` / `game` / `web` 三套配置模板（路由规则 + 混淆开关 + 调度目标），底层同一引擎。
**验收原文**：示例配置三选一即可运行；profile 间仅策略差异，无独立代码路径。

**可测口径（显式改写，非缩水）**：

1. **三选一可运行**：`examples/profile-{proxy,game,web}.yaml` 三份自包含
   示例，任选一份 `SEEP_CONFIG=<path> seepd` 即通过配置解析与运行时
   构建（集成测读取三份文件走 `load_from_path` 全链路断言）；
2. **仅策略差异**：三份示例 diff 仅落在 routing（组/规则）、obfuscation、
   egress_pool、udp（game 显式承载，§9-1）、`profile:` 一行——
   ingress/egress/control/telemetry 同构（集成测全等钉住）；
3. **无独立代码路径**：profile 是**配置期展开**（seep-config 纯函数把
   预设填入既有块），运行期不出现 `profile` 字段、不加任何运行时分支——
   展开产物与手写等价配置走完全相同的 build()/转换链。

## 1. 现状与结构约束

- `SeepConfig`（seep-config）：`routing.groups/rules`、`obfuscation`
  （P1-4 M0）、`egress_pool`（P1-5）均已成型；`udp` 是非 Option 的
  `UdpConfig`（缺省 `enabled: false`）——**无法区分「显式 false」与
  「缺省 false」**，profile 机制不能安全改写（见 §9 偏差）；
- 配置加载单入口：`load_from_path` → `from_str`（seepd main.rs:29 唯一
  生产调用；订阅转换是程序化构造 `SeepConfig` 字面量，不经 from_str）；
- obfuscation-middleware.md §3.5 已把 `obfuscation.profiles` 设计为
  「P2-3 三场景预设的落点容器」——本稿落**场景级**预设（顶层单字段），
  `obfuscation.profiles` 维持其原义（命名 padding 策略集），两者正交；
- 组成员引用用户 egress 名：机制无法预知用户拓扑，模板组员只能落到
  `default_node`（见 D-5）。

## 2. 设计决策

- **D-1 形态 = 顶层单字段** `profile: <proxy|game|web>`：`Option<ProfileKind>`
  枚举（serde snake_case，未知值 serde 层直接报 unknown variant，无需
  手写校验）；缺省 None = 存量配置零差异。
- **D-2 语义 = 缺省填充，显式恒优先**：profile 只往「未指定」的位填
  预设，用户显式给出的块（groups 非空 / rules 非空 / obfuscation 显式
  Some / egress_pool 显式 Some）一律不动——不覆盖、不删除、不合并。
  因此展开天然幂等（填过即非空，再展开是 no-op）。
- **D-3 展开点 = `SeepConfig::from_str` 尾部**：单入口 `apply_profile`
  纯函数（`&mut self`），`load_from_path` 经 from_str 自动覆盖；订阅
  转换等程序化构造不触发（同 obfuscation「订阅不产混淆块」先例）。
- **D-4「未指定」判定面**（能用 Option/空判的面才算）：
  `routing.groups.is_empty()`、`routing.rules.is_empty()`、
  `obfuscation.is_none()`、`egress_pool.is_none()`；
  `udp` 不在面内（§9 偏差 1）。
- **D-5 组模板成员 = `[default_node]`**：可运行的最低形态；真实多成员
  拓扑必须由用户 egress 决定，机制不猜名——示例 YAML 演示多成员写法
  （用户把节点填进组即获得完整 SLO 选路面）。
- **D-6 场景 = 策略矩阵行**（§4），三行互为「仅策略差异」的证明；
  game 是唯一带调度目标（组级 `slo`）与混淆开关的行，web 是唯一带
  连接池的行，proxy 行 = 既有 config/seep.yaml 的策略形（基线）。

## 3. 数据结构

```rust
/// 场景预设（P2-3）：配置期展开为既有块填充，运行期不可见
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind { Proxy, Game, Web }

// SeepConfig 增：
#[serde(default)]
pub profile: Option<ProfileKind>,
// SeepConfig 手写 Default 已有？（有——存量字段连带）；None 缺省同先例
```

## 4. 填充矩阵（D-6）

| 位 | proxy | game | web |
|----|-------|------|-----|
| `routing.groups` 空 → | `auto`：latency，[default_node]，无 slo | `game-auto`：latency，[default_node]，slo{p95_ms:80, loss_ratio:0.02}（调度目标——slo-scoring.md 组级 `slo:` YAML 面） | `web-auto`：latency，[default_node]，无 slo |
| `routing.rules` 空 → | `cn`：geoip CN → auto | 游戏平台域模板（domain_suffix：steampowered/steamcontent/epicgames/riotgames/battle.net/playstation/xbox/nintendo）→ game-auto | `cn`：geoip CN → web-auto |
| `obfuscation` None → | 不动 | `Some(enabled: true, padding: bucket{buckets:[128,256,512,1024]})`——QoS 包长打散（positioning §2.4；apply_to 缺省 chain = MVP 帧执行侧） | 不动 |
| `egress_pool` None → | 不动 | 不动 | `Some(enabled: true, 其余缺省)`——网页短连接复用（P1-5） |
| `udp` | 不动（§9 偏差 1：示例 YAML 显式承载） | 不动（同左，game 示例显式 `enabled: true` + 长局 `session_lifetime_secs`） | 不动 |

规则模板不含 catch-all：未命中规则天然落 `default_node`（既有路由语义），
模板只放场景特化条目。

## 5. 接线点

| # | 点 | 动作 |
|---|----|------|
| 1 | `SeepConfig::from_str` 尾部 | `config.apply_profile();`（唯一入口，订阅/程序化构造不触发） |
| 2 | 运行期 | **零接触**——展开产物即普通配置，build()/热更新/控制面不感知 profile |
| 3 | `examples/` | 三份自包含示例（M1）；集成测读三份走 `load_from_path` |

## 6. 错误与边界

- E1 `profile` 值非三枚举之一：serde unknown variant（解析期报，附合法值）；
- E2 profile 与显式块并存：合法（D-2 显式优先，逐面判定，无冲突报错）；
- E3 展开产物引用 `default_node` 但其名不在 egress：既有 build() 组成员
  校验面管（与手写同路径，机制不重复校验）；
- E4 展开幂等：同 config 二次 apply_profile 为 no-op（填过即非空）；
- E5 `profile` 与 obfuscation.profiles 命名集正交：前者场景级顶层展开，
  后者命名 padding 策略集，互不引用互不覆盖；
- E6 规则模板与组模板**同生共死**：模板规则 target 指向组模板名
  （auto/game-auto/web-auto）——用户自组在场（groups 非空）时组模板
  不创建，规则模板也不填充（用户组名不可猜测，避免悬空 target；
  此时 rules 空是合法形，未命中落 default_node）。

## 7. 测试策略

1. 三 profile 展开矩阵：空 routing + 各 profile → 组名/策略/slo/规则
   target、obfs/pool 逐面断言（§4 表逐格）；
2. 显式优先：带 groups/rules 的 config + profile: game → 两组一规则
   不动；obfs None 仍被填（逐面独立证明）；
3. 存量零差异：无 profile 字段 → 全部位不动（含缺省 None 反序列化）；
4. 非法值：`profile: fps` → unknown variant 报错；
5. 幂等：展开两次 == 展开一次（E4）；
6. 示例三选一（M1）：读 `examples/profile-*.yaml` 走 `load_from_path`
   全链路（含展开+既有 validate），三份 diff 仅策略块（口径 2）。

## 8. 分步实施清单

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M0 | seep-config ProfileKind + SeepConfig.profile + apply_profile + 单测 §7-1..5 | — | §7-1..5 绿；存量测试零回归 |
| M1 | examples/ 三份示例 + §7-6 集成测 + 文档回填（todo/PROTOCOLS/roadmap/positioning §2.5 现状注记/本稿落地注记） | M0 | §7-6 绿；口径 1–3 逐条可复现 |

## 9. 偏差与假设

1. **udp 不在填充面**：`SeepConfig.udp` 非 Option，无法区分显式/缺省
   false；profile 翻转它会覆盖显式关闭（违反 D-2）。game 的 UDP 需求
   （G1 已解，长局不断流）由示例 YAML 显式承载，机制不碰 udp 块；
2. **组模板单成员**是可运行最低形，不等于场景最佳实践——多成员 +
   SLO 选路的真实形态在示例 YAML 中演示，机制保持「不猜用户拓扑」；
3. **game slo 阈值**（p95 80ms / loss 2%）是预设缺省非标准——用户组级
   `slo:` 显式配置恒优先（D-2），阈值属调参面非协议面；
4. 游戏平台域模板是**示例性**域名集（common 平台），非穷举——规则
   模板的价值在展示「策略块怎么写」，精确清单归用户维护。

## 10. 风险与未决

- **R-prof1**：预设值随生态漂移（游戏域清单、slo 阈值）——预设属
  配置层，示例 YAML 可独立修订不发版；
- **O-prof1**：`seepctl profile` 子命令生成场景骨架配置（M1 后按需）；
- **O-prof2**：profile 与订阅合并语义（订阅推 egress、主配置产策略，
  现状已自然正交；出现冲突诉求再设计）。
