# 架构概念、抽象依据与收益

状态：2026-11-14 研究与设计提案，未将下列接口全部实现。范围是代理/加速内核的 **32 个核心概念**，不是竞品所有内部类型的穷举。

上游依据见 [架构研究及官方来源](../research/proxy-architectures-2026-11-14.md)；组合方案见 [目标架构](architecture-v1.md)。**进程分流验收限定 Windows、macOS、Linux 本机**；OpenWrt、Android、iOS 不承担此要求。

## 1. 抽象的判断标准

抽象必须隔离一个真实的变化来源：节点来源会刷新、用户规则希望稳定、操作系统权限不同、TCP/UDP 生命周期不同、网页与游戏目标不同。一个名字不应同时代表这些东西。抽象也必须有代价说明、现有模块落点和可验证的行为；不为画图而立即拆出 32 个 crate。

图的方框是责任边界，不等于进程或独立服务。桌面上可在一个 rillaned 中装配数据面；特权 helper、Android service、Apple extension 与 UI 可以是系统要求的其他进程。

## 2. 平面、入口与平台能力（C01–C08）

| ID / 概念 | 责任与输入输出 | 为什么单独抽象 | 收益与代价 |
|---|---|---|---|
| C01 控制面 / 数据面 | 控制面产出配置与命令；数据面处理流和数据报 | 配置刷新与逐包转发的频率、权限和失败方式不同 | 好处：拉订阅不阻塞收包；代价：必须定义代际与命令一致性 |
| C02 FlowContext | 保存入口、源/目标、TCP/UDP、域名证据、应用身份、规则代际 | SOCKS、TUN、平台 app-flow 的原始信息不同 | 好处：规则不依赖入口细节；代价：字段必须可选并带来源，不能伪造已知信息 |
| C03 CapturePort | 接收 socket、包批次或系统提供的流，交给统一数据面 | 捕获字节不是选出口，也不是查 PID | 好处：换 Wintun/packetFlow 不重写路由；代价：需处理 MTU、批量、背压和生命周期 |
| C04 CapabilitySet | 声明可用的接管、身份、旁路、路由和宿主能力 | 编译成功与当前权限下能运行是两件事 | 好处：启动前拒绝不可能的进程规则；代价：静态/动态能力及变更要一起维护 |
| C05 OwnerResolver | 本地五元组/系统流 → PID、可执行路径、用户及已知/未知原因 | TUN 包没有统一的进程字段，各 OS 查询方式不同 | 好处：三桌面本机统一进程规则；代价：首包开销、权限、缓存失效与 PID/端口复用 |
| C06 RouteTransaction | 计划、应用、记录与撤回本实例添加的路由/DNS/防火墙变更 | 系统副作用不能靠内存对象析构推定已恢复 | 好处：失败/崩溃能恢复且不删用户规则；代价：需持久操作日志与幂等回滚 |
| C07 SocketBypass | 标记/保护内核自己的出站 socket 与 DNS 上游 | 自己的连接被再次接管会形成环路 | 好处：业务路由与平台防环解耦；代价：TCP、UDP、DNS、订阅拉取须全部覆盖 |
| C08 NetworkEvents | 接口、地址、路由、网络切换及睡眠恢复通知 | 移动网络变化不是普通的节点失败 | 好处：统一重新绑定/清理；代价：事件去抖、重复通知、会话断开策略需定义 |

落点：现有 rillane-core / rillane-platform / rillane-runtime；新增端口先留在模块内。Mihomo 的 Metadata/process、sing-box 的 PlatformInterface 可作参照，但不复制其所有方法到一个巨型 trait。

## 3. 配置来源、兼容与代际（C09–C16）

| ID / 概念 | 责任与输入输出 | 为什么单独抽象 | 收益与代价 |
|---|---|---|---|
| C09 SourceSnapshot / Provider | 拉取节点或规则的一个完整版本，带来源 ID、hash、时间 | 订阅更新不应取得用户本地配置的所有权 | 好处：失败留旧版本、支持删除与替换；代价：命名空间与多来源冲突要明确 |
| C10 EndpointCatalog | provider 内稳定节点 ID → 地址、凭证引用、协议能力 | 显示名称不适合作为唯一身份或跨来源主键 | 好处：同名节点共存，刷新后保留偏好；代价：无上游 ID 时要定义稳定映射及变更诊断 |
| C11 RuleSet | 可引用、可更新的匹配数据及规则表达式 | 规则内容生命周期不同于代理节点和本地优先级 | 好处：兼容 rule-providers/RULE-SET；代价：格式、版本、引用图与执行成本要校验 |
| C12 Canonical IR / Provenance | 多种输入 → 类型化节点、规则、策略、平台需求，附来源位置 | 直接把 Clash YAML 塞进运行时会泄漏格式假设 | 好处：一处验证、精确报错、导入可测试；代价：映射需保证语义而非仅字段同名 |
| C13 CompatibilityDiagnostic | 输入对象 → 精确支持/不支持/显式有损转换报告 | fallback→随机、relay→哈希都不是兼容 | 好处：不让游戏规则悄悄消失；代价：严格模式会拒绝部分订阅，需友好定位与可选择的节点导入模式 |
| C14 RuntimeGeneration | 验证后的不可变配置图 + 版本；新流绑定版本 | 更新中不能让节点、规则、DNS 各自指向不同配置 | 好处：可回滚、可解释、旧流排空；代价：旧资源会短期共存，系统变更仍须事务补偿 |
| C15 DnsContext | 域名、解析结果、fake-IP 映射、命中策略和有效期 | 名称映射丢失会让流连到假地址或按错规则 | 好处：TCP/UDP 与 DNS 一致分流；代价：映射不能在旧流存活时被不安全复用 |
| C16 MetadataEnrichment | 受预算约束地补齐 sniff、域名、应用信息 | 规则可能需要迟到信息，但不能无限等首包 | 好处：减少无效查询并限制首包成本；代价：ECH/DoH/已加密载荷可能无法识别，未知必须显式处理 |

落点：rillane-subscription 负责输入，rillane-config 负责规范模型/验证，runtime 负责发布；DNS 与归因都是独立服务。IR 是进程内配置模型，不是发明另一个线上隧道协议。

## 4. 决策、场景与传输（C17–C24）

| ID / 概念 | 责任与输入输出 | 为什么单独抽象 | 收益与代价 |
|---|---|---|---|
| C17 Match / Action | 流条件匹配 → 路由、拒绝或必要元数据动作 | “是什么流”与“怎样处理”分别变化 | 好处：规则复用且保序；代价：需定义首中即停、AND/OR/NOT、DNS 前置条件与冲突优先级 |
| C18 RoutePlan | 目标逻辑组、场景、约束、队列类别、失败策略、命中原因 | 现有 RouteDecision/RoutePath 已含组、链路与原因，需继续补场景、队列、失败策略与能力约束 | 好处：选择与执行可分别测试；代价：计划要被会话执行层完整消费，不能成为孤儿字段 |
| C19 PolicyGroup | 有序/动态成员集合 + select/url-test/fallback/load-balance 等算法 | 规则引用稳定组，组再处理动态节点 | 好处：兼容现有订阅且可独立测选点；代价：引用循环、用户选择、嵌套及算法参数都要保真 |
| C20 ScenarioPolicy | game/web/general 的并行目标与资源偏好 | UDP 并不全是游戏，TCP 也并不全是网页 | 好处：游戏走稳态低尾延迟，网页走首字节/吞吐；代价：分类冲突要有优先级，不能依靠端口猜测覆盖用户规则 |
| C21 Endpoint / Dialer / Transport | 出口协议负责远端握手；dialer 负责连接/旁路；transport 承载字节或数据报 | TLS/WS/QUIC 传输与 SS/VLESS 等代理语义并非同一层 | 好处：能力组合与复用清楚；代价：必须检查合法组合，不能把不支持 UDP 的出口当可用 |
| C22 StreamSession / DatagramAssociation | TCP 流维持字节有序；UDP 关联维持目标、映射、超时和回包 | 游戏 UDP 生命周期不能强套成 TCP 连接 | 好处：保持数据报边界和 NAT 粘性；代价：关联淘汰、分片、MTU、回包验证要单测 |
| C23 SessionPin | 活跃流绑定配置代际、出口与必要源映射 | 每次健康分变化就换出口会破坏游戏会话 | 好处：新流适应，旧流稳定；代价：坏节点上的旧会话可能要失败重建，不能承诺透明迁移 |
| C24 TransportPool | 管理可复用的传输资源、预热、TLS 会话与配额 | “可预热连接”“可重绑目标”“可多路复用”不同 | 好处：降低代理侧建连阻塞；代价：每种协议需能力校验，不能把 HTTPS 网站会话与代理外层 TLS 混为一谈 |

落点：rillane-routing 做匹配与计划；rillane-protocols 做协议与拨号；runtime 连接会话。现有 profile: game/web 仅保留为导入/生成预设，不能继续作为两个运行场景互斥的总开关。

## 5. 质量、资源、嵌入与交付（C25–C32）

| ID / 概念 | 责任与输入输出 | 为什么单独抽象 | 收益与代价 |
|---|---|---|---|
| C25 QualitySample | 指标值 + 类型、来源、目标、时间、样本数与置信状态 | 握手耗时、RTT、连接失败率、包丢失率不是同一种数 | 好处：评分可解释，过期/未知不伪装成 0；代价：观测需要有界内存与明确采样成本 |
| C26 Objective / Hysteresis | 根据场景与可用样本选候选，定义冷却与切换阈值 | 测试最小值不等于游戏质量，瞬时波动不应触发抖动 | 好处：把优化目标变成可测试函数；代价：参数需实测，不得拿“目标 p95”当保证 |
| C27 ResourceBudget / QueueClass | 限制队列、会话、CPU/探测/拨号成本并按类别调度 | 共享一个进程不能消除浏览下载与游戏的竞争 | 好处：资源有界、相互影响可测；代价：本地队列不能控制 ISP/远端瓶颈，调度需避免网页饥饿 |
| C28 ManagedMesh | 受管节点、拓扑、安全和多跳作为可选出口能力 | 普通订阅服务器不认识 Rillane 的自定义帧 | 好处：自建网络可演进而不破坏机场订阅；代价：多跳增加运维/时延，UDP 安全未完整前不能默认启用 |
| C29 FFI / PacketBatch | 生命周期命令与包批次跨语言交接，明示所有权/取消 | Swift packetFlow 不等于一个永远可提取的私有 fd | 好处：公开平台 API 接入同核心；代价：拷贝、线程、批量、错误与版本契约要验证 |
| C30 HostLifecycle | daemon/service/extension 的启动、睡眠、重连、撤销与结束 | OS 生命周期不应由路由器循环顺带管理 | 好处：移动后台和桌面系统服务可独立验收；代价：IPC、签名、权限、进程边界不能省略 |
| C31 Explain / Telemetry / Secrets | 展示流命中、选点、样本、队列、失败原因；秘密用引用保管 | 无法解释的“智能加速”不可评估，观测又可能泄漏订阅密钥 | 好处：可定位和复现实验；代价：标签基数、数据留存、诊断脱敏与凭证生命周期要受控 |
| C32 FeatureProfile / Deployment | 各构建选择协议、插件、mesh 与观测组件并报告能力 | OpenWrt 和手机不应强制带整套桌面 WASM JIT | 好处：小内存、可维护的跨平台产物；代价：构建矩阵增加，必须验证功能裁剪而不只是改配置开关 |

## 6. 为什么不把这些东西合并成一个“加速模块”

### 例 1：游戏和浏览器访问同一个 IP:443

Windows/macOS/Linux 本机可先取得可信应用身份，分别生成 game/web 的 RoutePlan；QUIC 仍是 UDP 网页流量，不能以“UDP=游戏”分类。若身份查询临时失败，按显式 unknown 策略处理，不能假装匹配了进程规则。Android/iOS/OpenWrt 使用本次范围内的域名/IP/端口或设备策略；不为满足桌面要求而引入移动端 PID 承诺。

### 例 2：订阅删掉一个节点，同时用户仍在游戏

C09 形成新的来源版本，C12 验证引用，C14 为新流发布代际；C23 根据安全撤销/普通移除策略决定排空或终止旧流。不得直接 append 新规则而留下失效节点，也不得对每个 UDP 包重新选择“当前最快”出口。

### 例 3：网页下载把上行队列占满

C20 的游戏标签只说明意图；只有 C27 的队列/预算/公平调度才能在本地可控瓶颈保护延迟。C25 测量并报告实际 p95/丢包或错误，C26 才能按来源与样本量选路。外部瓶颈需配合 OS 整形/受管节点或接受不能保证的边界。

### 例 4：iOS 宿主更新系统后拿不到内部 fd

正式设计通过 C29 交接公开 packetFlow 批次，不依赖 KVC 私有字段；C03 不要求所有平台都提供 Linux 风格 fd。收益是接口契约稳定，代价是需验证批量与复制开销，而不是用未经支持的技巧掩盖这部分工作。

## 7. 目标接口契约（伪代码，不是现有 SDK）

```text
OwnerResolver.resolve(local_flow_key, deadline)
  -> Known(AppIdentity, source, observed_at) | Unknown(reason) | Unsupported

ConfigCompiler.compile(source_snapshots, local_policy, capabilities)
  -> CandidateGeneration | Diagnostics(source, location, severity, semantic_loss)

PolicyEngine.plan(flow_context, generation)
  -> RoutePlan(target, scenario, constraints, queue_class, failure_policy, reason)

SessionExecutor.open(route_plan, generation)
  -> StreamSession | DatagramAssociation

PacketPort.read_batch(deadline) / write_batch(packets)
  -> bounded batch | cancelled | platform error
```

这些端口应支持超时/取消，不能要求每个 OS 都有全部能力。没有必要逐接口新建 crate；以替换性、依赖方向和构建成本决定何时拆分。

## 8. 优势怎样才算成立

| 希望得到的优势 | 必须给出的证据 |
|---|---|
| Clash 用户迁移成本低 | provider/规则/策略组语义 fixture，错误不丢失，原配置与转换结果逐项对照 |
| 三桌面本机按进程代理一致 | 同目标不同进程的 TCP/UDP 真平台测试，未知/权限失败/PID 复用覆盖 |
| 网页与游戏同时优化 | 下载并发时游戏 p50/p95/抖动、网页 TTFB/吞吐、CPU/RSS 的前后对照 |
| 跨平台维护成本下降 | 公共核心契约测试 + 六平台最小真机验收；不是仅 cross check |
| 配置更新更可靠 | 删除/重名/错误来源/重启/更新中长流测试，证明代际与回滚有效 |
| 小设备可部署 | 不含 WASM JIT 的依赖图、包大小、启动与峰值 RSS、会话/队列上限 |

在这些证据产生之前，“更合理”表示边界和验收更清楚，不表示已证明比 Mihomo、sing-box 或 Surge 更快。

C31 的细化见 [Debug、路径解释与可选 MCP](debug-and-mcp.md)：RouteExplanation、FlowTrace/TraceEvent、ProbeJob、DiagnosticView、ConfigProposal/ApplyReceipt、MCPAdapter，分别说明职责、抽象理由、收益、成本与安全边界。

接入/出口接口、会话所有权、合法传输组合与分层流量统计统一见 [v1 IO 与统计契约](io-and-accounting.md)。
