# 当前实现与边界

本页是现有代码的实现参考，不是另一版架构设计。**当前唯一设计基线是 [v1 架构设计](design/architecture-v1.md)**，配套[概念说明](design/architecture-concepts.md)与 [Debug / MCP](design/debug-and-mcp.md)；这些目标尚未整体实现。

## 代码组织

| 目录/模块 | 当前职责 |
|---|---|
| `apps/rillaned` | 配置加载、运行时装配、HTTP 控制面 |
| `apps/rillanectl` | 配置工具、控制面查询、订阅与证书管理 |
| `rillane-core` | Flow、FlowContext、RouteDecision/RoutePath、转发接口与 UDP 基础类型；流/计划/会话契约（`plan` 模块：RoutePlan 单向映射、SessionPin、TCP/UDP 绑定边界） |
| `rillane-config` | 配置模型、校验、profile 预设展开；配置版本与能力契约（`contract` 模块） |
| `rillane-routing` | 条件匹配、逻辑组与路由选择 |
| `rillane-protocols` | 入站、出站、拨号与传输 |
| `rillane-runtime` | 监听、会话、订阅接线、TUN 与 Mesh 装配 |
| `rillane-platform` | 系统接管、路由/DNS、平台适配类型和 Linux 实现；系统副作用日志与所有权撤销契约（`side_effects` 模块） |
| `rillane-subscription` | 拉取、识别、转换、缓存、内容摘要与刷新 |
| `rillane-mesh` / `rillane-plugins` | 受管节点协作与 WASM 中间件；v1 规划将其裁剪为可选依赖 |
| `rillane-telemetry` / `rillane-ffi` | 日志与移动 FFI 基础设施 |
| `platforms/` | 各平台宿主、安装和打包模板；有模板不等于代理已运行验收 |

## 能力状态

| 能力 | 当前边界 | v1 工作 |
|---|---|---|
| 通用代理 | SOCKS5 / HTTP CONNECT / mixed 与多种出站已存在 | 保持标准协议路径，与可选 Mesh 解耦 |
| Linux TUN | TCP/UDP 接入共享路由；有本机进程注解 | 完整身份、双栈旁路、权限与恢复强化 |
| 其他平台 | 有构建/宿主脚手架；Android 仍为有限 demo，iOS 有私有 fd 依赖 | Windows/macOS 正式接管与本机身份；移动完整数据面与公开 API |
| Clash/Mihomo | 拉取/转换/更新链路存在，但语义只部分兼容 | 来源替换、provider、保真组/规则和严格诊断 |
| 多场景 | `profile` 在配置期填充默认值；已有规则可分别选出口 | 并列 ScenarioPolicy、资源预算和有类型的质量闭环 |
| 诊断 | 聚合统计、组状态、Mesh dry-run、diagnose | 真正逐流轨迹、纯 Explain、显式 Probe；可选 MCP 尚无实现 |

RouteDecision/RoutePath 已包含组、链路与原因；v1 的 RoutePlan 在其上扩展，不新增第二套路由器。`plan` 模块（RIL-006）把规则结果冻结为只读 `DecisionSnapshot`，执行结果（拨号成功/失败）与规则结果分离，经 `SessionPin` 把流钉在明确代际上，TCP 字节流与 UDP 数据报关联在类型层面分侧。质量样本契约（RIL-026 `quality` 模块）：metric/source/target/count/time/validity 全字段类型化，连接失败率与丢包率是不同指标（拨号来源的旧 `packet_loss_rate` 迁移时改名），未知/过期显式报错不当零，丢包样本必须说明测量对端。订阅已有 SHA-256 变更检测，但不能据此声称有来源签名或新代际事务；不可变代际契约在 `rillane-config`（RIL-003 `RuntimeGeneration`）。

## 控制与配置更新

配置已携带 `version` 字段（当前仅 `1`）：缺省按 V1 适配存量配置，显式未知版本在解析期以稳定原因码 `config.version.unknown` 拒绝。构建能力集（`CapabilitySet`）用于在配置校验期拒绝当前构建不支持的组合（稳定原因码 `config.combo.unsupported`），避免拨号期才失败；缺省能力集为全量，现有调用方零差异。内核 `rillane-core` 不依赖 `rillane-config` 与 Clash 格式，订阅转换收敛于 `rillane-subscription` 侧。

控制面是 `control.api_bind` 上的 HTTP/REST，接口见 [CLI 参考](cli.md)。当前 `/flows` 为入口/出口组合的聚合；兼容 `/connections` 不是完整真实连接表。`diagnose` 包含敏感运行信息，不能默认视为可安全上传 AI 的材料。

`rillaned` 从 `RILLANE_CONFIG` 读取启动配置；没有通用文件 watch、SIGHUP 重载或 `rillanectl reload`。已有订阅和控制面更新路径不等于 v1 的跨 OS 代际事务。路由/DNS/防火墙变更的副作用契约（`side_effects`：变更日志、所有权登记、幂等撤销——只撤销本实例条目，既有系统配置只登记不撤销）已就位，Linux 执行侧接线归配置发布协调器（RIL-019）。当前按名称追加的合并、组语义与 interval 单位缺陷见[研究证据](research/proxy-architectures-2026-11-14.md#verified-gaps)。

使用说明：[协议](PROTOCOLS.md)、[配置](config.md)、[订阅](subscription.md)、[网络接管](networking.md)、[可选 Mesh](mesh.md)。新实现按根目录 `todo.md` 的依赖和验收条件推进。
