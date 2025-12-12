# Seep TODO

## 1. 架构与核心能力
- [x] 在 `seep-routing` 中引入 `GroupDescriptor` 概念，支持组内策略（latency/bandwidth/random/weighted），并允许组嵌套；调整 `RouteDecision` 以表达逻辑组和最终节点。
- [x] 设计 Mesh/协作节点模块 (`seep-mesh`)，包含节点注册、角色（client/relay/exit）、健康上报、拓扑管理、节点 ACL/配额 和 link-state API。
- [ ] 扩展 `RuntimeBuilder` 与守护进程控制面，使其能够消费 Mesh 拓扑并构建多跳链路（源 → relay → exit），支撑协作/游戏加速；加入链路 Dry Run / 预检。
- [x] 在 `seep-core`/`seep-runtime` 中增加 `FlowSession/ChainContext` 概念，保存多跳状态、节点使用统计、故障回退策略，用于"某节点使用了哪个节点流量"的统计。

## 2. 系统路由与虚拟网卡
- [x] 为 `seep-platform` 增加 `network` 模块，定义 `TunProvider`、`RouteManager` trait，并给出 Linux/OpenWrt/Windows/macOS/Android/iOS 的实现计划。
- [x] 实现 `TunIngress`/`TunEgress`（接入 TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel），接管系统流量并与 FlowRouter 对接。
- [x] 在配置中新增 `network` 区块（mode: tun/redir; bypass/include 列表；进程/应用过滤），并在 CLI 中提供 `route apply/route clear` 等命令。

## 3. 订阅与配置
- [x] 新建 `seep-subscription` crate：支持 Clash 订阅拉取、解析、映射为 SeepConfig（proxies → egress、proxy-groups → groups、rules → routing.rules）。
- [x] 设计 Seep 自有订阅 DSL（含 version/meta/nodes/chains/rulesets），提供示例与校验器，可导入导出成标准配置。
- [x] 为 `seepctl` 增加 `subscription` 子命令（add/remove/list/refresh），以及定时刷新器、ETag/Last-Modified 缓存，支持热更新 runtime。

## 4. 协作节点与安全
- [ ] 规划节点认证体系（mTLS/Noise），实现证书管理/轮换工具，并在 Mesh 模块中强制加密传输；区分 client/relay/exit 权限。
- [x] 为协作模式设计 ACL 与资源配额机制（哪些节点可作为 relay/exit，带宽/连接数限制，贡献度/积分追踪）。
- [ ] 在 Telemetry 中加入多节点观测指标（节点状态、链路延迟、切换记录、节点之间的流量统计），并提供 Grafana/Prometheus 仪表板模板。

## 5. 插件化与特色
- [x] 定义 FlowMiddleware 插件接口，支持 WASM/动态库加载，提供示例（限速、统计、内容过滤）。
- [ ] 实现链路 Dry Run / 策略模拟工具，便于在修改配置或订阅前验证效果。
- [ ] 提供一键诊断信息收集（配置、路由状态、节点拓扑、日志），帮助问题排查。

## 6. 文档与发布
- [ ] 更新 `docs/architecture.md`，加入 Mesh/节点组、虚拟网卡、订阅 DSL、协作安全等章节。
- [ ] 撰写 `docs/subscription.md`、`docs/networking.md`、`docs/mesh.md` 指南。
- [ ] 规划多平台打包脚本（systemd/launchd/Windows Service/OpenWrt/Android/iOS），并在 `platforms/` 目录完善样板。

---

## 进度统计

| 类别 | 完成 | 总计 | 进度 |
|------|------|------|------|
| 架构与核心能力 | 3 | 4 | 75% |
| 系统路由与虚拟网卡 | 3 | 3 | 100% |
| 订阅与配置 | 3 | 3 | 100% |
| 协作节点与安全 | 1 | 3 | 33% |
| 插件化与特色 | 1 | 3 | 33% |
| 文档与发布 | 0 | 3 | 0% |
| **总计** | **11** | **19** | **58%** |

## 未完成任务详情

### 高优先级
1. **RuntimeBuilder 多跳链路支持** - 需要整合 Mesh 拓扑与 Runtime，实现源→relay→exit 链路构建
2. **节点认证体系 (mTLS/Noise)** - 安全基础设施，需要证书管理和加密传输

### 中优先级
3. **Telemetry 多节点观测指标** - 需要扩展 seep-telemetry，添加 Prometheus metrics
4. **链路 Dry Run / 策略模拟** - 配置验证工具
5. **一键诊断信息收集** - 运维工具

### 低优先级
6. **文档更新** - architecture.md 需要补充新模块说明
7. **指南文档** - subscription.md, networking.md, mesh.md
8. **多平台打包脚本** - platforms/ 目录完善
