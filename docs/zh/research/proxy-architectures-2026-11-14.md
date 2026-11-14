# 代理架构研究：Clash/Mihomo、sing-box、Surge

研究日期：2026-11-14。Rillane 对照基线：`46c2b1256e78e830a1d1783ae908893f7377b768`。本次交付是**研究与目标设计**，没有将六平台数据面或完整 Clash 兼容标为已实现。

配套阅读：[32 个架构概念及抽象依据](../design/architecture-concepts.md)、[Rillane 目标架构与迁移计划](../design/architecture-v1.md)、[当前实现](../architecture.md)。图由 `scripts/render_architecture_diagrams.py` 生成，SVG 可单独打开与导出。

**最新需求边界：按进程分别代理只要求 Windows、macOS、Linux 本机。** OpenWrt、Android、iOS 保留跨平台代理与网页/游戏并行处理计划，不要求桌面式进程归因；以下平台差异是设计约束，不是给移动端新增 PID 交付项。

## 1. 研究方法与可信范围

| 对象 | 本次依据 | 能得出的结论 | 不能得出的结论 |
|---|---|---|---|
| Clash/Mihomo | Mihomo **Meta 分支**快照 `0455d0d28c4526937380505153e65a843d8612e8`；配置、tunnel、provider、进程、DNS 与 fallback 源码；官方配置文档 | 当前快照中的模块边界与配置语义 | 原 Clash 所有历史版本均相同、所有 GUI 都有相同能力 |
| sing-box | **testing 分支**快照 `3dd8aa48d403f50cced084f46b4b0d5758bd4bd1`；Box、router、TUN、platform、libbox 源码；官方文档 | 类型化适配器、装配、平台回调、路由动作等抽象 | testing 中每项能力都已进入稳定版、所有宿主自动支持相同功能 |
| Surge | 官方功能手册、Smart Group、进程规则、代理链文档 | 公开功能的概念模型及使用边界 | 私有类图、内部线程/队列结构、未公开算法、性能领先结论 |

本次访问原 `Dreamacro/clash` 仓库返回 404，因此不声称审过原 Clash 源码；“Clash/Mihomo”图使用其生态中 Mihomo 的可核验实现。Mihomo 本次默认 `main` 分支元信息不对应代理内核，已显式切到具有 `github.com/metacubex/mihomo` 模块与 tunnel 实现的 **Meta** 分支，不能用默认 HEAD 推断架构。外部功能页持续变化，正式兼容验收必须再钉版本/fixture；这些快照是研究锚点，不是 Rillane 的新依赖。

图中实线绿箭头表示主要数据流，虚线蓝箭头表示配置/控制关系，虚线橙箭头表示质量反馈。图省略了具体调用、锁与重试，不等价于完整时序。Surge 图明确为文档重建；目标图的虚线框表示**提议边界**，并非整套代码已存在。

## 2. Clash/Mihomo：以 provider、规则和策略组组织代理

![Clash/Mihomo 模块架构](/architecture/mihomo.svg)

### 概念与实际路径

1. **配置与 provider**：`config/config.go` 描述配置，`hub/executor/executor.go::ApplyConfig` 负责装配；proxy-provider 提供节点集合，rule-provider 提供匹配数据，二者不能混同。订阅源刷新与用户选路偏好属于不同对象。[M1][M2][M3]
2. **入口与 Metadata**：代理监听与 TUN/重定向接管产生连接或数据报，`tunnel` 根据统一 Metadata 路由；域名、进程路径、网络类型按需补齐，不要求每个入口都天然知道进程。[M1][M4]
3. **规则 → 策略 → 具体代理**：规则说明“这条流应归谁处理”，策略组说明“从哪些成员中怎样选”，出站适配器说明“怎样连接”。URL-test 与 fallback 是不同语义，fallback 不是随机选点。[M3][M7]
4. **DNS 与会话**：DNS/fake-IP 为域名与地址建立上下文；UDP NAT/关联状态决定回包如何找回原连接。它们不是一个规则函数的附属字符串，也不是网页缓存。[M1][M5][M6]

### 为什么这样抽象

provider 的成员可以变化，而规则和用户偏好应能保持；规则可以引用一个逻辑组，而无需写死每个服务器地址。TCP 与 UDP 共用选路信息，却各自维护传输生命周期。代价是必须处理引用、循环组、失效成员、探测更新和配置迁移。

**Rillane 应吸收**：provider 的独立生命周期、稳定逻辑引用、组策略的真实语义、DNS/流上下文的一致性。**不能据此声称独有**：单进程、多入口、按进程规则、策略组和自动测试。

## 3. sing-box：类型化适配器与平台宿主边界

![sing-box 模块架构](/architecture/sing-box.svg)

### 概念与实际路径

1. **Box 与 manager 生命周期**：`box.go` 创建网络、DNS、入站、出站、路由等组件，通过 registry/context 提供依赖并分阶段启动与关闭；进程入口不需要包含所有协议逻辑。[S1]
2. **适配器与上下文**：`adapter.Router`、InboundContext 等提供连接/数据报路由契约；协议适配器实现具体输入输出，平台差异由 PlatformInterface 注入。[S2][S3]
3. **路由动作与 rule-set**：匹配条件与 route/reject/sniff 等动作分开；规则集合是独立可维护的数据。DNS 路由与业务连接路由相关但职责不同。[S4][S6]
4. **libbox 与宿主**：移动宿主可以提供 OpenTun、连接归属、网络变更及网络扩展状态。可嵌入并不意味着能绕开 Android/iOS 的 VPN 权限，也不意味着普通 CLI 自动获得宿主回调。[S5]

### 为什么这样抽象

协议、平台、运行时生命周期分别变化，拆开后能够复用核心，同时用宿主提供操作系统特有能力。收益是平台接口可测试、协议可扩展；代价是接口版本、生命周期顺序和跨语言资源所有权需要明确维护。

**Rillane 应吸收**：明确的平台端口、连接/数据报区别、能力查询与生命周期、规则集合与动作。不要照搬一个不断膨胀的“大平台接口”；按接管、身份、路由、DNS、旁路和网络事件拆端口。sing-box 已有嵌入能力，Rust/FFI 本身不是独占优势。

## 4. Surge：公开功能模型与可解释质量反馈

![Surge 文档功能架构](/architecture/surge.svg)

### 公开概念

官方将功能描述为接管、处理、转发和捕获；代理服务与虚拟网卡解决接管，规则和策略决定转发，可选抓包/MITM/重写解决另一类调试需求。这不是对其私有内部实现的反向工程。[G1]

策略组把规则与具体节点分开。Smart Group 使用真实连接质量与测试反馈，并带站点偏好和失败处理，不应把它描述成“只定时测 URL”。代理链也是已有公开能力。[G2][G4]

**平台边界明确**：Surge 官方说明进程规则仅 Mac 可用，iOS 忽略这些规则；DNS 查询阶段也未必已知发起进程。[G3]

### 为什么这样抽象

“选择哪个策略”与“协议怎么发包”解耦，诊断才能展示规则命中、策略与错误原因。真实连接反馈补充合成探测的不足，但会受到样本数量、目标站点和采样时效影响。

**Rillane 应吸收**：可解释路由、真实与合成观测区分、按平台如实声明能力。**不放进默认热路径**：内容 MITM、脚本和网页重写；它们不是透明游戏 UDP 加速的前置条件。

## 5. 概念对照与取舍

| 问题 | Mihomo 的主要概念 | sing-box 的主要概念 | Surge 的公开概念 | Rillane 取向 |
|---|---|---|---|---|
| 流量从哪来 | listener / TUN / Metadata | inbound / endpoint / context | takeover | CapturePort + FlowContext |
| 节点从哪来 | proxy-provider | typed outbound 配置与 registry | proxy/managed 配置 | SourceSnapshot + EndpointCatalog |
| 哪些流走哪里 | ordered rules / rule-provider | rule + action + rule-set | rule → policy | RuleSet + RoutePlan |
| 怎么选节点 | policy group / health | selector / URLTest | policy group / Smart | PolicyGroup + typed QualitySample |
| 如何跨平台 | TUN、process、路由实现 | PlatformInterface / libbox | Apple 宿主与功能限制 | 独立平台端口 + CapabilitySet |
| 配置改变怎么办 | 配置装配与 provider 更新 | manager 生命周期 | profile 更新（内部细节未知） | 提议：编译、预备、代际发布与旧流排空 |
| 游戏与网页共存 | 多规则、多组、多流 | 同一运行时不同路由 | 同一产品不同策略 | 并列场景目标 + 明确资源预算 |

这些是职责对应，不表示对象一对一，也不表示 Rillane 已完成最后一列。

<a id="verified-gaps"></a>

## 6. Rillane 现状复核：不能带进新设计的语义债务

| 已核对位置（基线） | 现象 | 设计要求 |
|---|---|---|
| `clash.rs::ClashConfig / ClashProxyGroup` | 没有完整 provider/use 根模型 | 将来源与节点目录单独建模 |
| `clash.rs::convert_group_type_to_strategy` | fallback→Random，relay→ConsistentHash | 不等价策略必须实现或明确拒绝 |
| `clash.rs::convert_clash_rule` | PROCESS-NAME / RULE-SET 被跳过 | 兼容级别与结构化诊断；禁止关键规则悄悄降级 |
| `clash.rs::convert_proxy_groups_to_groups` | ~~把 interval 当毫秒除以 1000~~ 已修（RIL-092，2026-11-15）：按秒读取，0/缺省按 300 秒；导出侧 300_000 同步改 300 | 单位策略已由 `clash_interval_secs` 单测与 YAML 反例测试固定 |
| `runtime_builder.rs::merge_config_delta_in_place` | 按名字只追加节点/组，规则 extend | 来源替换、删除、同名更新与本地策略需要独立语义 |
| `chain.rs::link_quality_between` | errors/connections 被命名为 loss | 区分连接失败率与真实数据包丢包率 |
| `network/mod.rs` 与 runtime TUN 分支 | Linux 之外仍拒绝真实 TUN | 打包成功不等于系统接管完成 |
| Android VpnService / iOS provider 示例 | 仅测试网段 ICMP；iOS 使用 KVC 私有 fd | 正式路径接入共享 TCP/UDP 数据面，Apple 使用公开 packetFlow API |
| `rillane-runtime` → `rillane-plugins` | Wasmtime 跟随默认依赖 | 轻量目标须有可验证的裁剪边界 |

源码位置按函数名定位，避免后续行号变化造成伪证据。这里只记录已读实现与相应缺口，没有宣称做过本轮跨平台实机验收。

## 7. 六平台边界是架构输入

![六平台能力边界](/architecture/platform-boundaries.svg)

- **Linux**：复用现有路径，强化权限、进程归因和重启/退出恢复；namespace 和缓存误归属需要单独验证。
- **OpenWrt**：路由器能看到设备、地址和端口，不能凭空知道另一台电脑的 PID。按应用分流需要端侧可信标记/代理配合，不能以路由器 `/proc` 冒充客户端身份。fw4/nftables/procd 集成与有限内存是独立目标。[P9]
- **Windows**：Wintun 提供三层包收发，不提供完整应用归因；需单独研究连接归属与 WFP/ALE 等系统机制，不能用装驱动代替这部分验收。[P1][P2]
- **macOS**：采用经确认的公开平台能力；区分 packet 与 app-flow 接口，验证应用身份来源、授权及签名分发。[P3]
- **Android**：VpnService 创建虚拟接口、protect 防出站回环；允许/排除应用名单决定是否入隧道，并不自动完成隧道内不同出口选择。API 29+ 的连接归属 UID 查询是有权限与可失败边界的可选能力，不是本次移动端交付前置。[P4][P5][P6]
- **iOS**：普通 Packet Tunnel 处理 IP 包，不承诺任意第三方进程名归因；企业受管 Per-App VPN 单独规划。使用 packetFlow 批量读写公开接口，不能以私有 fd 为发布依赖。[P7][P8]

所以“六平台可运行”不应定义成“六平台都具有桌面式进程规则”；应定义成**共用策略模型 + 能力匹配 + 平台实测**。iOS 可依域名/IP/端口等同时处理游戏和网页；同目标且无可信应用身份时无法保证区分。

## 8. 结论与可验证收益

吸收 provider 解耦、类型化平台边界、真实反馈与诊断；新增本地策略与订阅来源分离、并行场景目标、会话代际和资源预算。收益属于待验证的工程假设：订阅更新不覆盖用户规则、老流不被无意义切换、浏览下载与游戏竞争时有可测退化边界、同核心减少平台逻辑重复。

不承诺 Rust 自动更快、多跳自动更低延迟、混淆必然加速或 UDP 透明无缝换出口。下一步按 [迁移门禁](../design/architecture-v1.md#migration) 逐项交付，再做同节点、同网络和同负载的对照测量。

## 9. 官方证据目录

### Mihomo

- [M1] [Meta 快照 tunnel](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/tunnel/tunnel.go)、[Metadata](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/constant/metadata.go)、[配置装配](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/hub/executor/executor.go)。
- [M2] [proxy-providers](https://wiki.metacubex.one/config/proxy-providers/)。
- [M3] [策略组](https://wiki.metacubex.one/config/proxy-groups/)、[fallback](https://wiki.metacubex.one/config/proxy-groups/fallback/)。
- [M4] [路由规则及进程条件](https://wiki.metacubex.one/config/rules/)。
- [M5] [DNS resolver 源码](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/dns/resolver.go)。
- [M6] [rule-providers](https://wiki.metacubex.one/config/rule-providers/)。
- [M7] [fallback 源码](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/adapter/outboundgroup/fallback.go)。

### sing-box

- [S1] [Box 装配与生命周期](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/box.go)。
- [S2] [Router 接口](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/adapter/router.go)、[PlatformInterface](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/adapter/platform.go)。
- [S3] [TUN 配置](https://sing-box.sagernet.org/configuration/inbound/tun/)。
- [S4] [路由条件](https://sing-box.sagernet.org/configuration/route/rule/)、[动作](https://sing-box.sagernet.org/configuration/route/rule_action/)、[拨号与 detour](https://sing-box.sagernet.org/configuration/shared/dial/)。
- [S5] [libbox 平台回调](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/experimental/libbox/platform.go)。
- [S6] [rule-set](https://sing-box.sagernet.org/configuration/rule-set/)、[URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/)。

### Surge

- [G1] [官方功能与接管说明](https://manual.nssurge.com/book/understanding-surge/en/)。
- [G2] [Smart Group](https://manual.nssurge.com/policy-groups/smart.html)。
- [G3] [Process Rules：Mac only](https://manual.nssurge.com/rules/process.html)。
- [G4] [通用策略参数与代理链](https://manual.nssurge.com/policies/parameters.html)。

### 平台

- [P1] [Wintun 官方说明](https://www.wintun.net/)。
- [P2] [Microsoft WFP/ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)。
- [P3] [Apple Network Extension 配置与授权](https://developer.apple.com/documentation/xcode/configuring-network-extensions/)。
- [P4] [Android VpnService](https://developer.android.com/reference/android/net/VpnService)。
- [P5] [Android VpnService.Builder 应用名单](https://developer.android.com/reference/android/net/VpnService.Builder)。
- [P6] [Android 连接归属 UID](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress))。
- [P7] [Apple NEPacketTunnelFlow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow)、[Packet Tunnel 预期用途](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)。
- [P8] [Apple NETunnelProviderManager 与受管 Per-App VPN](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)。
- [P9] [OpenWrt 防火墙概览](https://openwrt.org/docs/guide-user/firewall/overview)。
