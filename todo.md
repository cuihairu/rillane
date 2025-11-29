# Seep TODO

## 1. 架构与核心能力
- [ ] 在 `seep-routing` 中引入 `GroupDescriptor` 概念，支持组内策略（latency/bandwidth/random/weighted），并调整 `RouteDecision` 可返回逻辑组与实际节点。
- [ ] 设计 Mesh/协作节点模块 (`seep-mesh`)，包含节点注册、角色（client/relay/exit）、健康上报、拓扑管理等 API。
- [ ] 扩展 `RuntimeBuilder` 与控制面，使其能够消费 Mesh 拓扑并构建多跳链路（源 → relay → exit），实现基本协作加速。
- [ ] 在 `seep-core`/`seep-runtime` 中增加 `FlowSession/ChainContext` 概念，保存多跳路由状态、故障回退策略。

## 2. 系统路由与虚拟网卡
- [ ] 为 `seep-platform` 增加 `network` 模块，定义 `TunProvider`、`RouteManager` trait，并给出 Linux/OpenWrt/Windows/macOS/Android/iOS 的实现计划。
- [ ] 实现 `TunIngress`/`TunEgress`（接入 TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel），接管系统流量并与 FlowRouter 对接。
- [ ] 在配置中新增 `network` 区块（mode: tun/redir; bypass/include 列表；进程/应用过滤），并在 CLI 中提供 `route apply/route clear` 等命令。

## 3. 订阅与配置
- [ ] 新建 `seep-subscription` crate：支持 Clash 订阅拉取、解析、映射为 SeepConfig（proxies → egress、proxy-groups → groups、rules → routing.rules）。
- [ ] 设计 Seep 自有订阅 DSL（含 version/meta/nodes/chains/rulesets），提供示例与校验器，可导入导出成标准配置。
- [ ] 为 `seepctl` 增加 `subscription` 子命令（add/remove/list/refresh），以及定时刷新器、ETag/Last-Modified 缓存，支持热更新 runtime。

## 4. 协作节点与安全
- [ ] 规划节点认证体系（mTLS/Noise），实现证书管理/轮换工具，并在 Mesh 模块中强制加密传输。
- [ ] 为协作模式设计 ACL 与资源配额机制（哪些节点可作为 relay/exit，带宽/连接数限制，贡献度追踪）。
- [ ] 在 Telemetry 中加入多节点观测指标（节点状态、链路延迟、切换记录），并提供 Grafana/Prometheus 仪表板模板。

## 5. 插件化与特色
- [ ] 定义 FlowMiddleware 插件接口，支持 WASM/动态库加载，提供示例（限速、统计、内容过滤）。
- [ ] 实现链路 Dry Run / 策略模拟工具，便于在修改配置或订阅前验证效果。
- [ ] 提供一键诊断信息收集（配置、路由状态、节点拓扑、日志），帮助问题排查。

## 6. 文档与发布
- [ ] 更新 `docs/architecture.md`，加入 Mesh/节点组、虚拟网卡、订阅 DSL、协作安全等章节。
- [ ] 撰写 `docs/subscription.md`、`docs/networking.md`、`docs/mesh.md` 指南。
- [ ] 规划多平台打包脚本（systemd/launchd/Windows Service/OpenWrt/Android/iOS），并在 `platforms/` 目录完善样板。
