# Seep TODO

> **定位**：一个代理内核，三种场景 —— 通用代理 / 游戏加速 / 网页加速。三者共享同一条数据通路（ingress → routing → egress/transport），混淆是横切层：加速 = 优化路由 + 流量伪装绕过 QoS/DPI，混淆 = 让流量渗过识别。
>
> **设计文档**：[docs/design/positioning.md](docs/design/positioning.md)（定位与底座拆解）· [docs/design/roadmap.md](docs/design/roadmap.md)（S0–S4 阶段规划）· [docs/design/udp-dataplane.md](docs/design/udp-dataplane.md)（S1 UDP 全链路设计稿）· [docs/architecture.md](docs/architecture.md) · [docs/mesh.md](docs/mesh.md) · [docs/PROTOCOLS.md](docs/PROTOCOLS.md)
>
> **优先级映射**：P0 → roadmap S1（UDP 全链路）；P1 → S2 + S3 前半（TUN / 混淆 MVP / 连接池）；P2 → S3 后半 + S4（调度闭环 / 安全 / profile）；P3 → 收尾（文档 / 插件 / 打包）。2026-09 对照代码核实后重排。

---

## 勘误：原清单与代码不符的条目（已重新打开）

原 todo.md 以下条目标注为 `[x]`，经 2026-09 对照代码核实为**部分完成或未完成**，重新归入对应优先级：

| 原条目（原标注 [x]） | 实际状态 | 去向 |
|---------------------|---------|------|
| 实现 TunIngress/TunEgress（接入 TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel） | `seep-platform` 仅有 trait 与数据结构；各平台 Provider 为占位实现（`platform.rs` 返回"未实现"）；runtime 未接线 | → P1 |
| 配置新增 network 区块（mode: tun/redir；bypass/include）+ CLI `route apply/route clear` | `SeepConfig` 无顶层 network 区块；`seepctl` 无 route 子命令 | → P1 |
| FlowMiddleware 支持 WASM/动态库加载，示例（限速、统计、内容过滤） | 仅有 `LatencyProbe` 一个实现，无动态加载机制 | → P3（降级） |

另：`docs/PROTOCOLS.md` 部分描述超前于实现（SOCKS5 UDP ASSOCIATE、VMess 出站、连接池、批量收发），文档回填见 P3。

---

## 已完成底座（原清单核实保留，对应 roadmap S0）

- [x] `GroupDescriptor` 组策略（latency/bandwidth/random/weighted 等 7 种，组嵌套）+ `RouteDecision` 表达逻辑组与最终节点（`seep-routing`）
- [x] Mesh/协作节点模块（`seep-mesh`：注册、client/relay/exit 角色、健康上报、拓扑、**ACL/配额**、link-state）
- [x] `RuntimeBuilder`/控制面消费 Mesh 拓扑构建多跳链路（源 → relay → exit）+ Dry Run 预检（`seep-runtime::chain`）
- [x] `FlowSession/ChainContext` 多跳状态、用量统计、故障回退（`seep-core`）
- [x] `seep-platform::network` trait 层与规则模型（`TunProvider`/`RouteManager`/`PacketFilter`/`DnsHandler`，含平台实现计划）
- [x] `seep-subscription`：Clash 订阅转换 + 自有 DSL + 定时刷新/ETag 缓存 + 热更新；`seepctl subscription`/`import-clash`
- [x] mesh data-plane TCP hop-by-hop 转发 + mTLS（强制策略、`seepctl mtls` 生成/轮换/CA bundle 双信任窗口/最小撤销列表）
- [x] `seepctl diagnose` 一键诊断（控制面快照 + 脱敏配置 + 本机路由/DNS/接口 + events + logs）
- [x] 链路 Dry Run / 策略模拟（`POST /chains/dry-run`、`seepctl chain dry-run`）
- [x] `/metrics` Prometheus 基础指标（mesh/chain/subscription/per-link 计数）+ Grafana 模板

---

## P0 — UDP 全链路（roadmap S1 · 游戏加速地基）

> 游戏流量以 UDP 为主，当前 `seep-protocols` 无任何 UDP 转发路径，这是三场景定位下最高杠杆的缺口。
> 设计稿：[docs/design/udp-dataplane.md](docs/design/udp-dataplane.md)（各条技术方案、复用/新增清单与风险编号 R*/V*/O* 均在该稿）。

- [ ] **P0-1 `seep-core` UDP 会话语义**：NAT 式 UDP 会话表（映射、超时回收、会话粘滞键=进程/五元组），与 `FlowSession` 打通。
  验收：会话创建/查询/超时回收有单测；同一粘滞键复用映射不重建。
- [ ] **P0-2 SOCKS5 UDP ASSOCIATE 入站**：按 RFC 1928 实现 UDP 中继，接入 FlowRouter。
  验收：标准客户端经 socks5 入站 + direct 出站完成 DNS UDP 查询往返；`seepctl stats` 可见 UDP 会话。
- [ ] **P0-3 出站 UDP 载荷**：direct / shadowsocks / hysteria2 / wireguard 出站承载 UDP。
  验收：QUIC 站点（HTTP/3）分别经 hy2 与 wg 出站可访问；不支持的出站类型在构建期明确报错。
- [ ] **P0-4 mesh data-plane UDP 转发**：多跳 UDP（envelope over UDP/QUIC 数据报），与现有 TCP 面共存。
  验收：两跳链路（client → relay → exit）UDP 双向转发；对端不可达时按超时回收。
- [ ] **P0-5 UDP 观测与配置**：ingress/egress UDP 开关与超时配置；`/metrics` 增加 UDP 会话数/字节数。
  验收：示例配置含 UDP 区块；Grafana 面板可见 UDP 序列。

## P1 — TUN 系统接管 + 混淆 MVP（roadmap S2 + S3 前半）

- [ ] **P1-1 Linux TUN 真实现**：`/dev/net/tun` + TUNSETIFF、包读写循环，替换 `platform.rs` 占位。
  验收：Linux 集成测试中 tun 设备创建、捕获 IP 包进入 FlowRouter；OpenWrt（musl）可复用同路径编译。
- [ ] **P1-2 TunIngress 接线 runtime**：IP 流重组 → `FlowContext`（注入进程/端口），TUN 作为新 ingress 类型接入。
  验收：按进程/端口规则将指定游戏流量路由至 mesh 链路；bypass（局域网/DNS/管理口）默认安全。
- [ ] **P1-3 network 配置区块 + `seepctl route apply/clear`**（勘误重开）：`SeepConfig` 顶层 `network` 区块（mode: tun/redir、bypass/include、进程过滤）；CLI 幂等应用/撤销系统路由。
  验收：`apply` 后 `ip rule`/路由表符合预期，`clear` 完全还原；重复执行幂等；失败时自动回滚。
- [ ] **P1-4 混淆中间件 MVP（padding）**：以 `FlowMiddleware` 形态实现包长填充策略，按 profile 开关。
  验收：开启后统计脚本显示出口包长分布偏离默认分布且可配置目标形态；关闭时零开销旁路。
- [ ] **P1-5 出站连接池**：同出口同 SNI keep-alive 复用 + TLS 会话恢复（网页加速核心项）。
  验收：重复请求同目标握手次数下降，`/metrics` 有连接复用率指标；现有配置无破坏性变更。

## P2 — 调度闭环与高级安全（roadmap S3 后半 + S4）

- [ ] **P2-1 per-link 细粒度指标**（原 §4 遗留收口）：时延分布、丢包、切换原因、节点间流量。
  验收：Grafana 可按 link 维度查询 p50/p95 RTT 与最近 N 次切换原因。
- [ ] **P2-2 SLO 打分选路**：以 p95 RTT/丢包为目标打分，升级 `latency` 组策略；游戏 profile 默认启用。
  验收：模拟链路劣化时自动切换且记录切换原因；`ChainContext` fallback 路径生效。
- [ ] **P2-3 场景 profile 预设**：`proxy` / `game` / `web` 三套配置模板（路由规则 + 混淆开关 + 调度目标），底层同一引擎。
  验收：示例配置三选一即可运行；profile 间仅策略差异，无独立代码路径。
- [ ] **P2-4 混淆中间件扩展（timing/shaping）**：微抖动注入、流形状归一。
  验收：与 P1-4 同一统计方法验证时序特征偏移；延迟代价可量化（p95 增幅 ≤ 配置上限）。
- [ ] **P2-5 客户端 TLS 指纹模拟**：uTLS 类能力挂载到出站 TLS 公共层（`tls.rs`）。
  验收：对外握手指纹可按配置选择（chrome/ios 等），指纹检测工具可区分。
- [ ] **P2-6 mesh envelope 二进制化**：替换 JSON 头降低固定开销（UDP 面尤其重要）。
  验收：envelope 编解码有兼容测试；UDP 面单包开销 ≤ 目标字节数。
- [ ] **P2-7 mesh 高级安全**（原 §4 遗留）：CRL/OCSP、多跳端到端 MAC/防重放。
  验收：撤销节点无需重启即可被拒（文件热加载已有，补 CRL 分发）；重放报文被丢弃并有计数。
- [ ] **P2-8 DNS 分流**（网页加速）：国内外 DNS 分流、缓存、防污染，对接 `seep-platform::network::dns` 设计。
  验收：分流解析正确且缓存命中率有指标；被污染域名返回可信结果。

## P3 — 文档、插件与平台发布（roadmap S4 收尾）

- [ ] **P3-1 文档对齐实现**（原 §6）：更新 `architecture.md`（Mesh/TUN/订阅/协作安全章节）；回填 `PROTOCOLS.md` 超前描述（UDP ASSOCIATE、VMess、连接池以 P0/P1 落地为准）；补 `docs/subscription.md`、`docs/networking.md`（mesh.md 已有）。
  验收：文档中每项能力声明能在代码中找到对应实现或 todo 条目。
- [ ] **P2/P3 原遗留——VMess 出站**：PROTOCOLS.md 已承诺，Clash 订阅转换会产出 vmess 节点，当前构建期报错。
  验收：vmess（ws+tls）出站可用；`import-clash` 转换的 vmess 节点可直连使用。
- [ ] **P3-2 插件动态加载**（勘误降级）：WASM/动态库 `FlowMiddleware` 加载器 + 限速/内容过滤示例。
  验收：外部编译的示例插件可加载并生效，崩溃/超时有隔离。
- [ ] **P3-3 平台打包**（原 §6）：systemd / launchd / Windows Service / OpenWrt init.d 模板与脚本，`platforms/` 样板完善。
  验收：Linux/macOS/Windows 三平台产出可安装二进制；OpenWrt 出 musl 静态包。
- [ ] **P3-4 移动端 FFI 骨架**：Android（VpnService）/ iOS（NEPacketTunnel）cdylib + C ABI 最小通路。
  验收：Android demo 通过 VpnService 建立 tun 并经内核代理一轮流量。

---

## 统计

| 优先级 | 条目 | 对应阶段 | 状态 |
|--------|------|---------|------|
| P0 | 5 | S1 UDP 全链路 | 未开始 |
| P1 | 5 | S2 TUN + S3 前半 | 未开始 |
| P2 | 8 | S3 后半 + S4 | 未开始 |
| P3 | 4+1 | S4 收尾 | 未开始 |

已完成底座（S0）9 大项见上文归档清单；原 19 条清单中 10 项核实为真实完成、3 项勘误重开、其余并入 P0–P3 对应条目。
