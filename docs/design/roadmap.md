# Seep 分阶段路线图

> 状态：设计文档（2026-09）· 定位依据：[positioning.md](positioning.md) · 可执行条目：[todo.md](../../todo.md)

## 执行摘要

以"一条数据通路、三种场景"为原则，把后续工作分为 5 个阶段（S0–S4）。核心判断：

- **S0 底座已基本就绪**（TCP 全链路 + mesh 链路 + 订阅 + 控制面），可直接复用，不需要重构；
- **S1 打通 UDP 全链路**是当前最高杠杆的一步——它是游戏加速的地基，也是 Hysteria2/WireGuard 出站真正发挥价值的条件；
- **S2 TUN 真实现**让系统级接管（游戏进程分流）落地，优先 Linux/OpenWrt；
- **S3 混淆横切层 + 网页加速**（连接复用）叠加在通路上，服务三场景；
- **S4 调度闭环与发布**用观测数据驱动低延迟选路，完成多平台打包。

每阶段给出「复用什么 / 新增什么 / 退出标准」，todo.md 中的 P0–P3 条目与本表阶段一一对应。

---

## S0：共用底座（已完成，持续维护）

**目标**：TCP 数据通路 + 协作节点 + 订阅 + 控制面。

| 复用（已实现） | 证据 |
|---------------|------|
| Flow/Session/Chain 数据模型 | `seep-core`（`Flow`、`FlowSession`、`ChainContext`、`RouteDecision`） |
| 规则路由 + 组策略（7 种策略、组嵌套） | `seep-routing::RoutingEngine` |
| 入站 socks5/http/mixed；出站 direct/ss/trojan/hy2/vless/wg/socks/http | `seep-protocols` |
| mesh 注册/心跳/link-state/ACL/配额；chain 构建/预检/健康检查/回退 | `seep-mesh`、`seep-runtime::chain` |
| mesh data-plane（TCP hop-by-hop + mTLS 强制 + CA 轮换/撤销） | `seep-runtime::mesh_transport`，见 [mesh.md](../mesh.md) |
| Clash 导入 + 自有 DSL + 热更新 | `seep-subscription` |
| 控制面 REST + seepctl（stats/nodes/chain/diagnose/mtls） | `apps/seepd`、`apps/seepctl` |
| Prometheus /metrics + Grafana 模板 | `seep-telemetry`、`docs/grafana/` |

无新增开发；本阶段产物作为 S1–S4 的契约层（`IngressEndpoint`/`EgressConnector`/`FlowMiddleware` trait 不变）。

## S1：UDP 全链路（对应 P0）

**目标**：让游戏流量（UDP 为主）走通「入站 → 路由 → 出站 → mesh 多跳」全程。

- **复用**：`seep-core` 的 `FlowTarget::Udp` 枚举与 `FlowSession`；`seep-routing` 不感知传输层，规则原样生效；Hysteria2/WireGuard/Shadowsocks 出站的既有握手/加密栈。
- **新增**：
  1. `seep-core`：UDP 会话语义（NAT 式映射表、超时回收、会话粘滞键 = 进程/五元组）；
  2. `seep-protocols`：SOCKS5 UDP ASSOCIATE 入站；direct/ss/hy2/wg 出站的 UDP 载荷封装；
  3. `seep-runtime::mesh_transport`：UDP 数据面转发（envelope over UDP 或 QUIC 数据报），与现有 TCP 面共存；
  4. `seepd`/config：ingress/egress 的 UDP 开关与超时配置。
- **退出标准**：SOCKS5 UDP 客户端经 direct 与 hy2 出站完成双向 UDP 代理；两跳 mesh 链路转发 UDP；会话表按超时回收； UDP 路径有独立指标。

## S2：TUN 与系统路由（对应 P1）

**目标**：系统级流量接管 + 进程/端口分流，游戏流量不依赖代理入站即可进入数据通路。

- **复用**：`seep-platform::network` 已有的 `TunProvider`/`RouteManager`/`PacketFilter` trait 与 TunConfig/规则模型（3825 行设计已成型）；`seep-core` 路由决策不变——TUN 只是新增一种 ingress。
- **新增**：
  1. Linux 真实现：`/dev/net/tun` + TUNSETIFF、policy routing（ip rule/fwmark）、redir 模式（nftables/iptables）；
  2. OpenWrt 复用 Linux 实现（musl 静态构建）；
  3. `seep-runtime`：接线 `TunIngress`（IP 包 → 流重组 → `FlowContext` 注入进程/端口信息）；
  4. `seepctl route apply/clear`（todo 勘误：此前标注完成，实际缺失）；
  5. Windows(Wintun)/macOS(utun)/Android(VpnService)/iOS(NEPacketTunnel) 按 Linux 模式后续填空（platform.rs 占位已是该形状）。
- **退出标准**：Linux 上 TUN 接管后，按进程/端口规则将游戏流量路由至 mesh 链路；`seepctl route apply/clear` 幂等可用；bypass 名单（局域网/DNS/管理口）默认安全。

## S3：混淆横切层 + 网页加速（对应 P1/P2）

**目标**：流量渗过识别（抗 QoS/DPI）+ 连接效率（网页场景）。

- **复用**：`FlowMiddleware` trait（混淆以中间件形态挂载）；各协议既有 TLS 伪装能力（Trojan/VLESS/Reality 类）；`seep-routing` 规则分流。
- **新增**：
  1. 混淆中间件（`seep-protocols::middleware`）：`padding`（包长分布对齐）、`timing`（微抖动）、`shaping`（流形状归一），按 profile 开关；
  2. 客户端 TLS 指纹模拟（uTLS 类能力，优先挂在 TLS 出站公共层 `tls.rs`）；
  3. obfs 插件兼容（simple-obfs http/tls；salamander 随 hy2 配置暴露）；
  4. 出站连接池：同出口 keep-alive 复用 + TLS 会话恢复，服务于网页短连接；
  5. mesh envelope 二进制化（替换 JSON 头，压缩固定开销）。
- **退出标准**：混淆开关开启后，包长/时序特征经统计脚本验证偏离默认分布；连接池使同目标重复请求握手次数下降（有指标佐证）；现有订阅/配置无破坏性变更。

## S4：调度闭环、观测与发布（对应 P2/P3）

**目标**：用真实链路数据驱动低延迟选路，完成平台化发布。

- **复用**：`LatencyProbe` 中间件、`latency/bandwidth` 组策略、`ChainManager` 健康检查与 fallback、`/metrics` + Grafana。
- **新增**：
  1. per-link 时延分布/丢包/切换原因指标（todo 遗留项收口）；
  2. 调度策略升级：以 SLO（如 p95 RTT）为目标打分选路，游戏 profile 默认启用；
  3. 场景 profile：`proxy`/`game`/`web` 三套配置预设（路由模板 + 混淆开关 + 调度目标），见 positioning.md §2.5；
  4. 高级安全收尾：CRL/OCSP、mesh 端到端 MAC/防重放（mesh.md「Security Notes」遗留）；
  5. 平台打包：systemd/launchd/Windows Service/OpenWrt；移动端 FFI 骨架。
- **退出标准**：游戏 profile 下链路切换由 SLO 打分驱动且有切换原因指标；三平台（Linux/macOS/Windows）出二进制产物；OpenWrt 出 musl 包。

## 阶段 × crate 映射总览

| 阶段 | seep-core | seep-routing | seep-protocols | seep-platform | seep-runtime | seep-mesh | seep-subscription | apps |
|------|-----------|--------------|----------------|---------------|--------------|-----------|-------------------|------|
| S0 ✅ | 会话/链路模型 | 规则+组策略 | TCP 入/出站 | trait 层 | chain+mesh TCP 面 | 注册/ACL/配额 | Clash+DSL+热更 | 控制面+CLI |
| S1 | UDP 会话语义 | 不变 | UDP 入/出站 | 不变 | UDP 数据面 | link-state 扩展 | 不变 | UDP 配置 |
| S2 | 不变 | 进程匹配增强 | 不变 | Linux TUN 真实现 | TunIngress 接线 | 不变 | 不变 | route apply/clear |
| S3 | 中间件挂点不变 | 不变 | 混淆中间件+连接池 | 不变 | envelope 二进制化 | 不变 | DSL 混淆字段 | profile 预设 |
| S4 | SLO 打分输入 | 策略升级 | 指标埋点 | 平台打包 | 调度闭环 | 端到端安全 | 不变 | 发布产物 |

## 风险与依赖

- **S1 是 S2/S4 的前置**：没有 UDP，TUN 接管的游戏流量无处可去，SLO 调度也无对象；
- **S2 依赖真实内核交互**，需要集成测试环境（Linux CI + NetworkNamespace 级测试），占位实现转正期间保持 trait 稳定；
- **S3 混淆的有效性验证**依赖测量方法（统计脚本/对抗样本），先建度量再调参；
- 协议文档 `PROTOCOLS.md` 存在超前描述（UDP ASSOCIATE、VMess、连接池等），以 todo.md 勘误与阶段退出标准为准回填。
