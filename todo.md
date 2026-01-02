# Seep TODO

## 1. 架构与核心能力
- [x] 在 `seep-routing` 中引入 `GroupDescriptor` 概念，支持组内策略（latency/bandwidth/random/weighted），并允许组嵌套；调整 `RouteDecision` 以表达逻辑组和最终节点。
- [x] 设计 Mesh/协作节点模块 (`seep-mesh`)，包含节点注册、角色（client/relay/exit）、健康上报、拓扑管理、节点 ACL/配额 和 link-state API。
- [x] 扩展 `RuntimeBuilder` 与守护进程控制面，使其能够消费 Mesh 拓扑并构建多跳链路（源 → relay → exit），支撑协作/游戏加速；加入链路 Dry Run / 预检。
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
- [ ] 规划节点认证体系（mTLS/Noise），实现证书管理/轮换工具，并在 Mesh 模块中强制加密传输；区分 client/relay/exit 权限。（已提供 mesh data-plane mTLS 强制策略、`seepctl mtls` 生成/轮换证书、CA bundle（双信任窗口）与最小撤销列表；待补齐 CRL/OCSP/Noise 等高级能力）
- [x] 为协作模式设计 ACL 与资源配额机制（哪些节点可作为 relay/exit，带宽/连接数限制，贡献度/积分追踪）。
- [ ] 在 Telemetry 中加入多节点观测指标（节点状态、链路延迟、切换记录、节点之间的流量统计），并提供 Grafana/Prometheus 仪表板模板。（已提供 `/metrics` 与 Grafana 模板，待补齐 per-link 流量与切换记录等高级指标）

## 5. 插件化与特色
- [x] 定义 FlowMiddleware 插件接口，支持 WASM/动态库加载，提供示例（限速、统计、内容过滤）。
- [x] 实现链路 Dry Run / 策略模拟工具，便于在修改配置或订阅前验证效果。
- [x] 提供一键诊断信息收集（配置、路由状态、节点拓扑、日志），帮助问题排查。（`seepctl diagnose`：控制面快照 + 脱敏配置 + 本机路由/DNS/接口快照 + events + 可选 logs）

## 6. 文档与发布
- [ ] 更新 `docs/architecture.md`，加入 Mesh/节点组、虚拟网卡、订阅 DSL、协作安全等章节。
- [ ] 撰写 `docs/subscription.md`、`docs/networking.md`、`docs/mesh.md` 指南。
- [ ] 规划多平台打包脚本（systemd/launchd/Windows Service/OpenWrt/Android/iOS），并在 `platforms/` 目录完善样板。

---

## 进度统计

| 类别 | 完成 | 总计 | 进度 |
|------|------|------|------|
| 架构与核心能力 | 4 | 4 | 100% |
| 系统路由与虚拟网卡 | 3 | 3 | 100% |
| 订阅与配置 | 3 | 3 | 100% |
| 协作节点与安全 | 1 | 3 | 33% |
| 插件化与特色 | 3 | 3 | 100% |
| 文档与发布 | 0 | 3 | 0% |
| **总计** | **14** | **19** | **74%** |

## 未完成任务详情

### 高优先级
1. **节点认证体系 (mTLS/Noise)** - 安全基础设施，需要证书管理和加密传输，并在 Mesh data-plane 强制加密/鉴权

### 中优先级
2. **Telemetry 多节点观测指标** - 已提供 `GET /metrics` 与 Grafana 模板；已补齐 per-link 流量与事件计数（mesh/subscription/network/error），待继续补齐更细粒度的链路切换原因与 per-link 时延分布等高级指标
3. **一键诊断信息收集** - 已提供 `seepctl diagnose`（控制面快照、脱敏配置、runtime config/stats、events），待补齐系统路由状态/日志采集等

### 低优先级
4. **文档更新** - architecture.md 需要补充新模块说明
5. **指南文档** - subscription.md, networking.md, mesh.md
6. **多平台打包脚本** - platforms/ 目录完善
