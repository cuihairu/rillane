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

- [x] **P0-1 `seep-core` UDP 会话语义**（2026-09 完成）：NAT 式 UDP 会话表（映射、超时回收、会话粘滞键=进程/五元组），与 `FlowSession` 打通。
  实现级设计：[docs/design/udp-session-table.md](docs/design/udp-session-table.md)（两级映射/粘滞键优先级/回收状态机/集成映射表）；接口草案：[docs/design/udp-session-table-api.md](docs/design/udp-session-table-api.md)（完整 API 签名/回收算法伪码/SessionLedger 单写入口/锁序契约；**§9 实施注记**为落地裁决：MappingShared 统一表示、teardown 单点收敛、chain_id 口径、DropReason 扩 6 类）。
  落地：`crates/seep-core/src/udp/`（table/ledger/inner/reclaim/key/config/clock/metrics/relay）；测试 `crates/seep-core/tests/udp_session_table.rs` 22 项（生命周期/超时回收 MockClock 确定性/粘滞复用不重建/容量拒新/链路失效决策失效+映射吊销/LRU/ledger O7 恢复/force_revoke/并发绑定与并发压测）。
  验收：会话创建/查询/超时回收有单测 ✅；同一粘滞键复用映射不重建 ✅（same_sticky_key_reuses_mapping_without_rebuild）。
- [x] **P0-2 SOCKS5 UDP ASSOCIATE 入站**（2026-09 完成）：按 RFC 1928 实现 UDP 中继，接入 FlowRouter。
  实现级设计：[docs/design/udp-relay-path.md](docs/design/udp-relay-path.md) §2（命令分支/BND 应答/准入校验/生命周期挂钩/并发 ASSOCIATE；**§6 实施注记**为落地裁决：DownlinkFull 计数命名、头编解码落 seep-core、§3.6 分级 teardown、并发门键口径）。
  落地：`seep-core/src/udp/associate.rs`（ASSOCIATE 服务/头编解码/准入/指标）+ `seep-protocols/src/inbound/socks5.rs`（0x01/0x03/其他 命令分派，认证用户名进粘滞键）+ `seep-config`（`udp:` 块，缺省关闭）+ `seep-runtime`（udp.enabled 接线 direct 连接器，mixed 入口同享）。测试 `seep-core/tests/udp_associate.rs` 11 项（头编解码往返×5、真 socket DNS 式往返、FRAG/截断丢弃计数、strict 源拒绝、EOF→force_revoke、并发 ASSOCIATE 拒绝、会话回收不关控制连接、计数联动）。
  验收：socks5 入站 + direct 出站 UDP 往返 ✅（真 socket 集成测试钉住；标准 CLI 联调归 P0-5）；`seepctl stats` 可见 UDP 会话 → 快照数据就绪，P0-5 渲染接线。
- [x] **P0-3 出站 UDP 载荷**（2026-09 完成）：direct / shadowsocks / wireguard 出站承载 UDP；**hysteria2 按设计 §3.4 分支 (c) 移 P0-4**（V1 核查结论：hysteria2 0.1.6 公开 API 仅 connect/tcp_connect，`quic_connection` 为 pub(crate)，无 UDP 出口——非静默缩水，验收显式改写）。
  实现级设计：[docs/design/udp-relay-path.md](docs/design/udp-relay-path.md) §3（能力表与构建期扫描/各协议承载/UdpRelay 错误分类；**§7 实施注记**为落地裁决：associate 签名带粘滞决策、RoutingUdpConnector 按最终节点分发、wg 走内核路由的机制偏差、MTU/allowed_ips 错误分类关键词、ProxySocket connect/bind 之辨、扫描范围含 mesh 目标豁免）。
  落地：`seep-core/src/udp/relay.rs`（RoutingUdpConnector + trait 扩展）+ `associate.rs`（传会话粘滞决策）+ `table.rs` classify_failure（`mtu`→Timeout 保映射 / `allowed_ips`→Route 拆映射，§3.6）+ `seep-protocols`（ShadowsocksUdpConnector：方法校验提前构建期、目标固定 R7；WireguardUdpConnector：allowed_ips 预检 + MTU 上限 mtu-80）+ `seep-runtime`（§3.1 能力扫描：default_node+规则目标+组成员闭包，逐个点名节点/类型/来源，socks5/http/trojan/vless/vmess/hy2 构建期报错）。
  测试：`seep-core/tests/udp_egress_selection.rs` 3 项（选路分发/wg MTU 保映射/wg allowed_ips 拆映射+重路由）+ `seep-protocols/tests/udp_egress.rs` 7 项（方法构建期拒绝/ss 发送路径真 socket+R7 固定/wg 预检与 MTU/无效 CIDR 拒绝/域名解析后预检）+ runtime 能力扫描 4 项；全仓 118 通过。
  验收：不支持的出站类型在构建期明确报错 ✅；direct/wg/ss 出站 UDP 可达 ✅（ss 为发送路径真 socket，完整解密往返需 shadowsocks-service 服务端、归 P0-5 联调）；"QUIC 站点经 hy2 出站可达"→ **P0-4**（与 mesh UDP 载荷同批落地）。
- [ ] **P0-4 mesh data-plane UDP 转发**：多跳 UDP（envelope over UDP/QUIC 数据报），与现有 TCP 面共存。
  实现级设计：[docs/design/udp-mesh-dataplane.md](docs/design/udp-mesh-dataplane.md)（§2 UdpEnvelope 二进制格式 / §3 跳缓存 / §4 MeshDataPlane UDP 面 / §5 UdpChainRouter / §6 明文门 / §8 chain_id 口径桥接 / §9.1 build() 时序裁决 + **分步实施清单 S0–S6**（每步含落点/依赖/验收，2026-09 设计就绪，实施未开始）；**§13 实施细节补全**：exit 下行 task 回收单点 `retire_flow`（修正 §4 的 Arc 阻 drop 缺陷）/ UdpFaceMetrics 字段定稿 / envelope 65507 上界 / serve 单循环并发裁决 / 明文门与 MeshConfig 字段合流点）。
  验收：两跳链路（client → relay → exit）UDP 双向转发；对端不可达时按超时回收；QUIC 站点经 hy2 出站可达（P0-3 §3.4(c) 移入本条，载具 quinn=V2 未决，明文门 MVP 先行）。
- [ ] **P0-5 UDP 观测与配置**：ingress/egress UDP 开关与超时配置；`/metrics` 增加 UDP 会话数/字节数。
  实现级设计：[docs/design/udp-observability.md](docs/design/udp-observability.md)（§1 配置项清单——UdpConfig 补齐 5 字段 + per-ingress `udp_enabled` 覆盖 + mesh 明文门；§2 `/metrics` 命名与语义——`seep_udp_*` 全集/R11 封闭标签/O4 关闭裁决；§3 seepctl stats UDP 段 + `udp-probe` 联调工具；§4 与 P0-4 衔接点汇总。**2026-09 设计稿就绪待实现**；**§9 实施细节补全**：`/udp/stats` 响应示例（ingress 字段已对照 P0-2 实现核实）/ stats 渲染样式 / `udp-probe` 退出码表 / per-ingress `udp_enabled` 判定伪码 / §7 增 `seep_tun_*` 衔接行）。
  验收：示例配置含 UDP 区块；Grafana 面板可见 UDP 序列；`seepctl udp-probe` 全链路 DNS 往返（收口 P0-2 遗留联调）。

## P1 — TUN 系统接管 + 混淆 MVP（roadmap S2 + S3 前半）

- [ ] **P1-1 Linux TUN 真实现**：`/dev/net/tun` + TUNSETIFF、包读写循环，替换 `platform.rs` 占位。
  实现级设计：[docs/design/tun-dataplane.md](docs/design/tun-dataplane.md) §1（设备生命周期/接口签名；最小 `LinuxRouteManager`＝main 表显式路由 + AppliedStep 回滚；模块接线与 `platform.rs`/`TunInterface` 占位处置——注意核对结论：该文件未编译且启用即编译失败，见 status-audit §1）；§5 清单 **T0–T2** 对应本条。
  验收：Linux 集成测试中 tun 设备创建、捕获 IP 包进入 FlowRouter（设计 §4.2 钉子）；OpenWrt（musl）可复用同路径编译（§6 假设 #9；交叉产物验收归 P3-3）。
- [ ] **P1-2 TunIngress 接线 runtime**：IP 流重组 → `FlowContext`（注入进程/端口），TUN 作为新 ingress 类型接入。
  实现级设计：[docs/design/tun-dataplane.md](docs/design/tun-dataplane.md) §2（TunFlowTable 镜像 P0-1 语义 / UDP 头编解码含 v6 强制校验和 / smoltcp TCP 面 / 进程注解 `process.*` + `MatchCondition::Process` / TunIngress 属主化不经 NetworkManager / §2.7 bypass 防环）+ §3 错误路径 + §4 测试策略 + §5 清单 **T3–T5**（**2026-09 设计稿就绪，实施未开始**）。
  验收：按进程/端口规则将指定游戏流量路由至 mesh 链路（TCP 对象 T4 即验；UDP 对象软依赖 P0-4 S5）；bypass（局域网/DNS/管理口）默认安全（auto-bypass 集 + 进程内兜底）。
- [ ] **P1-3 network 配置区块 + `seepctl route apply/clear`**（勘误重开）：`SeepConfig` 顶层 `network` 区块（mode: tun/transparent——命名裁决 B4；include 语义；进程过滤走 P1-2 `MatchCondition::Process`，不进本块）；CLI 幂等应用/撤销系统路由。
  实现级设计：[docs/design/network-route.md](docs/design/network-route.md)（§1 镜像类型 schema + 转换映射表——seep-config 不加 platform 依赖；§2 seepd 派生开关 + **NetworkManager 让路裁决**（修正 build() ④ 必失败路径，audit §1.2"接线存在但不可用"就此收口）；§3 控制面三端点；§5 幂等/回滚/还原状态机（"完全还原" = 撤销 seep 所加步骤）；§8 分步清单 **R0–R4**——R0 无依赖可先行，R1 起硬依赖 P1-1 T1/T2。**2026-09 设计稿就绪待实现**）。
  验收：`apply` 后 main 表显式路由符合预期（**口径修正**：MVP 不触碰 `ip rule`，全局接管归 V2），`clear` 完全还原；重复执行幂等；失败时自动回滚。
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

- [x] **P3-1 文档对齐实现**（原 §6，2026-09 完成）：`architecture.md` 四章节（Mesh/TUN/订阅/协作安全）改写为现状+边界口径并刷新过期路线节；`PROTOCOLS.md` 顶部新增实现状态总表 + 15 处就地状态标注（UDP ASSOCIATE→P0-2、出站 UDP→P0-3、VMess 构建期报错→遗留条目、连接池→P1-5、混淆→P1-4/P2-4/P2-5 等），修复底部失效链接；新增 `docs/subscription.md`（拉取/ETag/缓存/DSL/热更新实读）与 `docs/networking.md`（TUN 模型已建、实现未落地逐条对照 P1-1..P1-3）。
  待回填：P0/P1 落地后更新 PROTOCOLS.md 各节状态标注与顶部总表对应行、networking.md §2 现状节、udp-dataplane.md §0.2 状态表；VMess 出站落地后删除其超前标注。后续补：mesh.md 安全注记已与现状对齐（ACL/配额与撤销文件热加载已落地，端到端 MAC/CRL 待 P2-7）。
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
| P0 | 5 | S1 UDP 全链路 | 3/5（P0-1 会话表、P0-2 ASSOCIATE、P0-3 出站载荷完成；P0-4 实现级设计稿+分步实施清单就绪（含 hy2 UDP 补课）；P0-5 设计稿就绪待实现） |
| P1 | 5 | S2 TUN + S3 前半 | 0/5（P1-1/P1-2/P1-3 实现级设计稿就绪（tun-dataplane.md T0–T5 / network-route.md R0–R4 分步清单）；实施未开始） |
| P2 | 8 | S3 后半 + S4 | 未开始 |
| P3 | 4+1 | S4 收尾 | 1/5（P3-1 文档对齐完成） |

已完成底座（S0）9 大项见上文归档清单；原 19 条清单中 10 项核实为真实完成、3 项勘误重开、其余并入 P0–P3 对应条目。
