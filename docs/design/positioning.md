# Seep 产品定位与技术底座

> 状态：设计文档（2026-09）· 上游参考：[architecture.md](../architecture.md)、[PROTOCOLS.md](../PROTOCOLS.md)、[mesh.md](../mesh.md)

## 执行摘要

Seep 是**一个代理内核**，同时服务三个场景：**通用代理、游戏加速、网页加速**。三者不是三个产品，而是同一条数据通路（ingress → routing → egress/transport）上的三种策略组合：

- **加速 = 优化路由 + 流量伪装**：绕过 QoS 限速与 DPI 干扰，选择低延迟路径；
- **混淆 = 让流量渗过识别**：协议伪装与流量特征打散，是加速的前置条件，也是代理的生存能力；
- **网页加速 = 连接效率 + 分流精度**：连接复用与规则分流，复用同一套路由引擎。

本文拆解哪些层完全共用、哪些层场景特化、混淆如何作为横切层注入，并给出与当前 crates 的映射结论。阶段落地计划见 [roadmap.md](roadmap.md)，可执行条目见根目录 [todo.md](../../todo.md)。

---

## 1. 一个内核，三种场景

| 场景 | 用户价值 | 本质 |
|------|---------|------|
| 通用代理 | 访问与隐私 | 数据通路本身：入站接管 → 规则路由 → 协议出站 |
| 游戏加速 | 低延迟、不丢包、抗 QoS | UDP 优先的数据通路 + 低延迟调度 + 流量伪装 |
| 网页加速 | 首包快、吞吐稳 | 连接复用 + 精细分流 + 就近出口 |

三个场景共享 >70% 的技术面：入站接管、Flow 会话模型、规则路由、组策略选节点、多跳链路（mesh）、订阅、控制面与观测。差异集中在**策略参数与少数特化模块**，而非独立产品线。

## 2. 共用底座：一条数据通路

```
                     ┌──────────────── 横切：混淆层 (Obfuscation) ───────────────┐
                     │  协议伪装 / 流量特征打散 / TLS 指纹 / 填充与时序扰动        │
                     └──────────────────────────────────────────────────────────┘
 应用流量 ──► Ingress ──► Flow/Session ──► Routing ──► Egress/Transport ──► 目标
 (TUN/socks/  (socks5/     (五元组+进程     (规则+组策略   (direct/ss/trojan/
  http/redir)  http/mixed)  +域名+geoip)    +mesh 链路)    hy2/vless/wg/mesh)
                     │                                          │
                     └────────── Control Plane (seepd API + seepctl) ──────────┘
                     └────────── Telemetry (/metrics · /flows · /nodes) ───────┘
```

### 2.1 完全共用的层

| 层 | 职责 | 现状（crate） |
|----|------|--------------|
| 入站 | 流量接管：本地代理（socks5/http/mixed）+ 系统级（TUN/redir） | `seep-protocols` 入站已就绪（TCP）；TUN 见缺口清单 |
| Flow 会话 | 统一会话模型：目标、路由历史、用量、失败统计 | `seep-core` `Flow/FlowSession/ChainContext` 已就绪 |
| 路由引擎 | 规则匹配（domain/geoip/ipcidr/port/process）+ 组策略选路 | `seep-routing` 已就绪（latency/bandwidth/weighted/consistent-hash 等策略） |
| 多跳链路 | mesh 组网、chain 构建/预检/故障回退 | `seep-mesh` + `seep-runtime::chain` 已就绪（TCP） |
| 出站协议栈 | direct/ss/trojan/hy2/vless/wg/socks/http | `seep-protocols` 出站已就绪（TCP） |
| 订阅 | Clash 导入 + 自有 DSL + 热更新 | `seep-subscription` 已就绪 |
| 控制面 | REST API + seepctl + mTLS 工具 | `apps/seepd`、`apps/seepctl` 已就绪 |
| 观测 | per-flow/per-link 指标、诊断采集 | `seep-telemetry` 基础就绪，细化中 |

### 2.2 游戏加速特化（叠加在共用底座上）

1. **UDP 优先的数据通路**（当前最大缺口）：游戏流量 90% 是 UDP。需要全链路 UDP：
   - 入站：SOCKS5 UDP ASSOCIATE、TUN 层 NAT 会话；
   - 出站：UDP-capable 协议承载（Hysteria2/Shadowsocks-UDP/WireGuard/Direct，mesh data-plane 需增加 UDP 转发）；
   - 核心模型：`FlowTarget::Udp` 贯通 + UDP 会话表（NAT 语义、超时回收）。
2. **低延迟调度**：路径选择以 RTT/丢包/抖动为主目标（现有 `latency` 组策略与 `LatencyProbe` 中间件是起点），首包优先、小包优先于吞吐。
3. **会话保持**：同一游戏会话（进程 + 五元组）粘住同一条链路；链路故障时按 `ChainContext` 的 fallback 路径迁移并保持 NAT 映射，避免游戏断线重连。
4. **系统级接管**：游戏进程流量只能靠 TUN + 进程/端口规则捕获（代理入站抓不到），这是 TUN 层的游戏加速理由。

### 2.3 网页加速特化

1. **连接复用**：出站连接池与 keep-alive 复用（对同出口同 SNI 的短连接聚合握手），TLS 会话恢复/0-RTT；
2. **分流精度**：域名/geoip/ruleset 分流决定"谁走代理、谁直连"，直接决定网页体验（现有 `seep-routing` 规则 + 订阅 ruleset 转换已覆盖大部分）；
3. **DNS 优化**：分流感知的解析（国内外 DNS 分流、缓存、防污染），`seep-platform::network::dns` 的设计目标即此；
4. **复用而非新建**：以上全部作用在共用数据通路上，不引入独立的"网页加速模块"。

### 2.4 混淆：横切层，不是协议

混淆不是某个出口协议的功能点，而是插在 **egress 传输层两侧的横切能力**（对应 `FlowMiddleware` 的位置语义）：

| 手段 | 说明 | 生态参考（Clash / sing-box 做法） |
|------|------|--------------------------------|
| 协议内伪装 | Trojan=HTTPS、VLESS+Reality 偷 TLS 握手、Hysteria2 伪装 QUIC | 已有协议自带，`PROTOCOLS.md`「流量伪装」节 |
| obfs 插件 | simple-obfs（http/tls 填充）、Shadowsocks plugind 机制 | Clash `plugin: obfs/v2ray-plugin` |
| 混淆传输 | salamander（Hysteria2）、QUIC 流量整形 | hy2 原生 `obfs: salamander` |
| 指纹模拟 | uTLS/客户端 TLS 指纹（chrome/ios/safari） | sing-box `utls` |
| 特征打散 | 包长填充、时序扰动、心跳归一化——对抗基于统计的 QoS 识别 | 自行开发重点（见下） |

**自行开发重点——流量特征打散**：QoS/DPI 对游戏流量的识别多基于包长分布、包间隔、流形状（而非协议内容）。横切层应提供：

- `padding`：可控包长填充策略（对齐到目标分布）；
- `timing`：微抖动注入（可配置窗口，牺牲微延迟换抗识别）;
- `shaping`：流形状归一（首包簇、心跳间隔对齐到常见应用指纹）。

这三者作为 `FlowMiddleware` 实现挂在 egress 之前/之后，**对三种场景统一生效**：代理用它过 DPI，游戏加速用它过 QoS，网页加速用它维持 TLS 正常形态。

> **现状（2026-10，P1-4/P2-4/P2-5 落地）**：三者均已以 `FlowMiddleware` 落地——`padding`（P1-4 M0–M4，策略/执行分离：`PaddingSpec` 策略引擎纯函数 + 帧载体执行侧，MVP 帧载体 = mesh chain 的 `MeshEnvelope` 帧，fixed/bucket/range 三形态、overhead 比例闸门、`seep_obfs_*` 指标族恒渲染 + `scripts/obfs_padding_dist.py` 分布检查脚本）；`timing`/`shaping`（P2-4：`TimingMiddleware` 启动抖动 + `ShapingMiddleware` 写网格归一）。单跳 TCP 无自有帧 no-op；UDP 数据报填充载体（`UdpEnvelope`）已就绪而执行钩子未接（裁决见 udp-mesh-dataplane.md D-15）。TLS 指纹模拟已随 P2-5 落地（chrome/ios/safari 预设，见 [tls-fingerprint.md](tls-fingerprint.md)）；simple-obfs/salamander 生态插件兼容未做。详见 [obfuscation-middleware.md](obfuscation-middleware.md)。

### 2.5 数据通路视角的结论

- 三场景的差异 = **路由策略模板 + 中间件组合 + 出站协议选择**，全部是配置层组合，不需要分支代码路径；
- 配置上以 profile 表达：`proxy` / `game` / `web` 三套预设（路由规则模板 + 混淆开关 + 调度目标），底层同一引擎；
  > **现状（2026-10，P2-3 落地）**：顶层 `profile: proxy|game|web` 缺省填充展开（显式恒优先、运行期零分支），`examples/profile-*.yaml` 三选一即运行——见 [scenario-profiles.md](scenario-profiles.md)；
- 这是"共享底座、策略分化"的单内核架构，与 README 的模块化定位一致。

## 3. 与现状的差距（结论性清单）

| # | 缺口（2026-09 时点结论） | 影响 | 现状（2026-10-04） | 详见 |
|---|------|------|------|------|
| G1 | 协议层零 UDP（`seep-protocols` 无任何 UDP 转发路径） | 游戏加速不可用 | **已闭合**——P0-2/P0-3：UDP ASSOCIATE 入站 + direct/ss/wg 出站载荷 | roadmap S1 |
| G2 | TUN/系统路由为占位实现（`seep-platform::network::platform.rs` 各 Provider 均返回"未实现"，runtime 未接线） | 系统级接管/进程分流不可用 | **已闭合**——P1-1/P1-2/P1-3：linux.rs 真实现 + TunIngress 接线 + network 配置区块与 `seepctl route` | roadmap S2 |
| G3 | 无独立混淆横切层（仅协议自带伪装） | 抗 QoS/DPI 能力受限 | **已闭合**——P1-4 padding、P2-4 timing/shaping 落地；simple-obfs 经 SS SIP003 插件桥可用（2026-10-07，仅 SS TCP 面），salamander 归 V2 备选 | roadmap S3 |
| G4 | 无出站连接复用/池化 | 网页短连接开销高 | **已闭合**——P1-5 M0–M5 连接池 + TLS 会话恢复 | roadmap S3 |
| G5 | mesh data-plane 仅 TCP（JSON envelope 明文头） | 多跳 UDP 不可用；envelope 可优化为二进制 | **已闭合**——P0-4 UDP 多跳 + P2-6 二进制 envelope | roadmap S1/S3 |
| G6 | per-link 时延分布/切换原因等细粒度指标缺失 | 调度缺少数据闭环 | **已闭合**——P2-1 `seep_mesh_link_*`/`seep_mesh_switch_total` + `GET /mesh/switches` | roadmap S4 |

## 4. 文档索引

- 架构总览与 crate 划分：[docs/architecture.md](../architecture.md)（引用，不重写）
- 协议能力与兼容性：[docs/PROTOCOLS.md](../PROTOCOLS.md)（引用；其中与实现的偏差以本文件 §3 与 todo.md 勘误为准）
- Mesh/链路/数据面协议：[docs/mesh.md](../mesh.md)（引用，不重写）
- 阶段计划：[docs/design/roadmap.md](roadmap.md)
- 可执行清单：[todo.md](../../todo.md)
