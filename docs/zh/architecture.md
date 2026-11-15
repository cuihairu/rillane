# 当前实现与边界

本页是现有代码的实现参考，不是另一版架构设计。**当前唯一设计基线是 [v1 架构设计](design/architecture-v1.md)**，配套[概念说明](design/architecture-concepts.md)与 [Debug / MCP](design/debug-and-mcp.md)；这些目标尚未整体实现。

## 代码组织

| 目录/模块 | 当前职责 |
|---|---|
| `apps/rillaned` | 配置加载、运行时装配、HTTP 控制面 |
| `apps/rillanectl` | 配置工具、控制面查询、订阅与证书管理 |
| `apps/rillane-mcp` | 可选 stdio MCP 适配器（RIL-067）：默认不启用、不监听任何端口——显式启动的控制面客户端，经共享 `rillane-app` 边界出站访问守护进程；stdout 只走协议（一行一条 JSON-RPC，官方 2026-07-28 modern era 契约：逐请求版本门、`server/discover`、取消后不答复），日志走 stderr，单请求限时（30 s 上限），EOF 干净退出、不遗留后台作业（探测作业在守护进程侧配额管束）；会话授权档只来自启动参数（默认只读，RIL-068），带每分钟固定窗工具调用限速 |
| `rillane-core` | Flow、FlowContext、RouteDecision/RoutePath、转发接口与 UDP 基础类型；流/计划/会话契约（`plan` 模块：RoutePlan 单向映射、SessionPin、TCP/UDP 绑定边界）；入口两阶段接入契约（`inbound` 模块：`InboundSpec`/`InboundFactory`、一次性 responder 的 `PendingStream`/`PendingAssociation`、TUN 的 Capture 来源）；出口建立通道契约（`outbound` 模块：`StreamOutbound`/`DatagramOutbound`、`OpenContext`、已建立通道/关联、分阶段 `OpenError`）；会话执行接线（`session` 模块：接入确认→出口建立→成功回复→双向泵送的一条权威路径，业务交换后不重放）；诊断事件 Schema（`trace` 模块：`FlowTrace`/`TraceEvent`，flow/attempt/generation ID、成对单调/墙钟、证据类型分立、主版本精确的 schema 兼容规则）；有界事件采集器（`collector` 模块：环形缓冲、TTL、确定性采样、每流上限、可见丢事件计数、拉式订阅背压）；诊断脱敏边界（`redact` 模块：两档 `Redactor`——导出别名档 vs 本机详细档，秘密两档都剥除、白名单即方法集、不可信文本消毒）；真实流生命周期埋点（`session_trace` 模块：可选 `SessionTracer` 骑在权威会话路径上——调用方观测接管/身份/DNS/嗅探，内核落点规则/计划/尝试/出口/传输/关闭，注入时钟锚 + 真实流逝，尝试事件逐条携带 attempt_id，泵实测逐方向首字节时刻，UDP 映射与控制链回收分立为不同终态，缺少测量证据不生成 RTT/丢包）；逐连接查询服务（`query` 模块：采集器之上的只读分页/过滤/详情/事件读取——列表回答匹配总数诚实、近期优先，查询以真实 `FlowId` 为锚、ingress/egress 聚合键不会命中任何流，缺席经有界墓碑逐码显式（unknown/evicted/expired/active_limit/sampled_out/drained/disabled），每份缺席答复携带采集器计数与固定说明——无记录不是「应用未发包」的证据） |
| `rillane-config` | 配置模型、校验、profile 预设展开；配置版本与能力契约（`contract` 模块） |
| `rillane-routing` | 条件匹配、逻辑组与路由选择；纯 Explain 推演（`explain` 模块：生产求值器 + 冻结快照的规则重演——无 DNS/拨号/OS 查询，证据缺失条件性结果，随机策略只给候选池，输入摘要可离线重放） |
| `rillane-protocols` | 入站、出站、拨号与传输 |
| `rillane-runtime` | 监听、会话、订阅接线、TUN 与 Mesh 装配 |
| `rillane-app` | CLI/UI/MCP 共用的应用服务边界（RIL-065）：闭合操作集（`AppOperation`——每个调用映射恰一个固定 (method, path)，无通用 HTTP/shell/任意文件/管理员透传），参数类型化并在上线前校验、不可信文本消毒，版本化答复/错误信封解码、显式缺席与错误分立，feature 门控的阻塞 HTTP 执行器；核心不依赖 MCP SDK——配置读写属管理员级面，待提案生命周期（RIL-073+）另行进入 |
| `rillane-platform` | 系统接管、路由/DNS、平台适配类型和 Linux 实现；系统副作用日志与所有权撤销契约（`side_effects` 模块） |
| `rillane-subscription` | 拉取、识别、转换、缓存、内容摘要与刷新 |
| `rillane-mesh` / `rillane-plugins` | 受管节点协作与 WASM 中间件；插件已为可选依赖（runtime `plugins` feature，RIL-040：default=`full`，`small`/`mobile` 档依赖图无 Wasmtime） |
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

RouteDecision/RoutePath 已包含组、链路与原因；v1 的 RoutePlan 在其上扩展，不新增第二套路由器。`plan` 模块（RIL-006）把规则结果冻结为只读 `DecisionSnapshot`，执行结果（拨号成功/失败）与规则结果分离，经 `SessionPin` 把流钉在明确代际上，TCP 字节流与 UDP 数据报关联在类型层面分侧。质量样本契约（RIL-026 `quality` 模块）：metric/source/target/count/time/validity 全字段类型化，连接失败率与丢包率是不同指标（拨号来源的旧 `packet_loss_rate` 迁移时改名），未知/过期显式报错不当零，丢包样本必须说明测量对端。订阅已有 SHA-256 变更检测，但不能据此声称有来源签名或新代际事务；不可变代际契约在 `rillane-config`（RIL-003 `RuntimeGeneration`）。出口建立通道契约（`outbound` 模块，RIL-097）把「建立通道」与「业务搬运」分开：`OpenContext` 携带 session/attempt/generation 身份与截止时间、取消信号，但**不持有可重新求值的路由器**——出口只做一次建立尝试，回退归会话执行器按 RoutePlan 编排；`OpenedStream`/`OpenedAssociation` 持有协议包装后的 IO 与握手结果（加密/分帧状态随 IO 生命周期，不泄露给普通复制循环）；`TargetBinding` 区分固定目标与多目标映射；`OpenError` 分阶段携带稳定原因码、可重试性、证据类型（预测/观测/推断/未知）与已脱敏上下文。入口两阶段接入契约（`inbound` 模块，RIL-096）把「认证/解析」与「路由」分开：`PendingStream` 独占客户端通道与一次性 responder，**出口成功后才回复成功**（成功回复写失败在 `accept` 内就地释放已建立出口），丢弃不消费即关闭通道且不触发回复；UDP 准入（`PendingAssociation`）钉住来源校验、显式目标绑定与控制链回收；TUN 会话带 `Capture` 来源标记，回复由网络栈驱动，不套用代理回复模型。会话执行接线（`session` 模块，RIL-098）是这些契约之上的一条权威执行路径：出口建立复用 `SessionExecutor` 作为唯一选路实现（回退对账在 `attempts`——A 失败 B 拨通可追踪），成功回复只在出口建立之后发出；业务字节一旦交换，任何失败都按 `TransferFailed`/`session.cancelled` 携带方向与已交换字节数终止——**不发起第二次出口建立**（重连是新会话的新决策）；有界分片泵读一写一（背压）并按 TCP 语义半关闭；数据报中继逐报文校验目标绑定与上限（显式计数拒绝，不静默截断），控制链关闭即回收。诊断事件 Schema（`trace` 模块，RIL-051）把真实连接轨迹类型化：每 TCP 会话/UDP association 一条 `FlowTrace`，携带稳定 `FlowId`、计划代际与 `TraceEvent` 序列——事件序号从 0 连续、成对携带单调时钟与墙钟、逐条稳定原因码与证据类型，预测/观测/推断/未知互不混淆；`detail` 必须已脱敏（载荷/HTTP 内容在 schema 里没有字段可填）；schema 兼容规则主版本精确，更高主版本按 `trace.schema.unsupported` 拒绝而非静默降级。有界采集器（`collector` 模块，RIL-052）在这份 schema 上施加硬资源边界：写路径纯同步永不等待的环形缓冲（满则逐出最旧迹且计数可见）、调用方供钟的 TTL 清扫、确定性计数采样（第一条新流永远入选，内核不引入随机源）、永不丢终态 `Close` 事件的每流上限、拉式订阅背压——慢消费者只是让已关闭迹滞留环形缓冲（滞留量在统计可见），**结构上无法阻塞数据面**；关闭追踪时采集器整体 no-op。真实流生命周期埋点（`session_trace` 模块，RIL-053）骑在权威会话路径上：可选 `SessionTracer` 的本地轨迹恒为权威——不受采集器采样影响（被采样剔除的流仍有完整本地轨迹）；规则/计划按预测证据落点，尝试对账事件逐条携带 attempt_id（A 失败 B 拨通可完整解释），实际出口区分流建立与关联映射，泵实测逐方向首字节时刻（HTTP TTFB 与首个下行字节分立），终态区分正常关闭与控制链回收——时钟锚在开轨时注入、流逝为真实测量，缺少测量证据绝不生成 RTT/丢包。逐连接查询服务（`query` 模块，RIL-055）是采集器之上的读取面：活动/近期连接分页与过滤（匹配总数诚实、近期优先）、以真实 `FlowId` 为锚的单流详情与增量事件读取（ingress/egress 聚合键不会命中任何流），缺席回答逐原因显式——轨迹离开采集器时登记有界墓碑（溢出逐出、TTL 过期、订阅取走、活动上限/采样未准入），「从未见过」「见过但已离开（为何）」「追踪关闭」互不混淆，每份缺席答复携带采集器计数与固定说明：无记录不是「应用未发包」的证据；查询是只读快照，结构上无法偷走订阅者的事件。诊断脱敏边界（`redact` 模块，RIL-057）是 CLI/UI/MCP 共用的输出契约：诊断视图的每一列都必须经 `Redactor` 具名方法产出（方法集合就是白名单——没有附加原始字符串的后门），导出默认对域名/路径/地址/节点名使用稳定别名，本机详细档放大的只是身份字段；**秘密在两档范围内都不出边界**——订阅 URL 剥除凭证与 token/password 类查询参数，错误文本中的 PEM 私钥块与 password/token 键值对替换为占位符，原始配置块只出标签与字节数，日志/订阅名称按不可信文本消毒（零宽与控制字符、长度截断）在两档一致执行。纯 Explain 服务（`explain` 模块，RIL-054）是「为什么这条流走这里」的推演面：规则/场景匹配直接调用 `route()` 的同一组求值函数（不存在第二套匹配器），组状态（健康位/用户选择/链路质量/带宽）经快照显式冻结——同一（配置、快照、输入）三元组离线重放必得同一结论；证据缺失（进程注解缺席、Geo 库未装、域名不解析 DNS、规则集载荷缺席、链路质量无数据）按恒不命中评估并逐条列出缺口，结论标注条件性而非伪装确定；`random`/`weighted`/`round_robin` 在推演中无确定答案——只给健康候选池；全推演无 DNS、无拨号、无 OS 身份查询，输入摘要（SHA-256）随结论输出供诊断对照。

## 控制与配置更新

配置已携带 `version` 字段（当前仅 `1`）：缺省按 V1 适配存量配置，显式未知版本在解析期以稳定原因码 `config.version.unknown` 拒绝。构建能力集（`CapabilitySet`）用于在配置校验期拒绝当前构建不支持的组合（稳定原因码 `config.combo.unsupported`），避免拨号期才失败；缺省能力集为全量，现有调用方零差异。内核 `rillane-core` 不依赖 `rillane-config` 与 Clash 格式，订阅转换收敛于 `rillane-subscription` 侧。

控制面是 `control.api_bind` 上的 HTTP/REST，接口见 [CLI 参考](cli.md)。当前 `/flows` 为入口/出口组合的聚合；兼容 `/connections` 映射同一聚合面并在响应中显式声明语义（`rillane.view: aggregate`——`id` 是入口-出口组合键而非逐连接 flow ID，缺失的时间/域名/规则/链路序列化为 null/空而非伪造值；真实逐连接轨迹归内核查询服务，本聚合视图不替代之）。`diagnose` 按范围选择且默认安全：`safe` 不采集订阅列表/运行配置/完整日志，`full` 在每个出口剥除秘密（配置秘密键、订阅 URL 凭证、日志 key=value 秘密对与 PEM 块），`raw` 不脱敏并显式标注禁止上传；每份清单恒记录范围、需人工复核文件清单与仅限手动的上传政策——rillanectl 不做任何自动上传，诊断包不自动构成可安全上传 AI 的材料。trace 端点（`/trace/flows`、`/trace/flow`、`/trace/events`）以版本化信封（`schema_version=1`）暴露内核逐连接查询服务——以真实 flow ID 锚定、缺席逐因显式回答；Mesh dry-run 不冒充规则解释，也不冒充逐连接轨迹。`POST /explain` 以同一信封暴露纯 Explain 推演服务（生产求值器 + 冻结快照，零副作用；入口消毒，proto/域名来源非法值以 `explain.input.invalid` 拒绝）。CLI/UI/MCP 经共享 `rillane-app` 边界（RIL-065）消费控制面：闭合操作集——每个诊断调用是一个类型化操作、映射恰一个固定 (method, path)，答复经版本化信封解码、显式缺席与错误分立；管理员级面（原始配置读、订阅 URL、配置写）刻意留在边界之外。MCP 协议与工具契约（RIL-066）在同一 crate 冻结、不引入 SDK：协议版本钉死官方 modern era 修订版 2026-07-28（逐请求在 `params._meta` 声明版本、不符答 `UnsupportedProtocolVersionError` -32022、必实现 `server/discover`、取消走 `notifications/cancelled`——停止处理、释放资源、不答复被取消请求），工具目录与闭合操作集一一对应（11 个工具、类型化输入 schema——未知字段与超限参数在分派前拒绝），工具注解结构性只含 hint 字段、与服务端授权档分立（注解永不充当授权——stdio 服务端本体由 RIL-067 落地）。服务端范围鉴权（RIL-068）在参数校验与执行之前门控每一次 `tools/call`：授权档集合只来自启动配置（默认只读——最小面），授权只读冻结目录的服务端档位字段（永不读注解、永不读请求面任何授权声明字段——直接构造携带 `scope`/`granted`/`authorized` 的调用无法升级范围），拒绝以稳定码 -32001（`mcp.scope.denied` 附所需档名）作答且不进入执行、不消耗配额，固定窗口限速器（默认每分钟 60 次，`--rate-limit 0` 关闸）对窗外调用答 -32002（`mcp.rate.limited`）；凭证留在适配器执行器私有字段，不出现在任何答复/日志里。状态与质量工具（RIL-069）与 CLI 消费同一守护进程载荷——答复信封原文贯通（样本时效经成员 `source` 字段 real/legacy/unknown 表达、缺失样本以显式 null 呈现、绝不补零），且一切工具答复统一过响应字节闸（`MAX_RESULT_BYTES` 256 KiB）：超限载荷以带内 `mcp.result.oversize` 作答（只带字节数——不回显载荷、不写出残缺 JSON），凭证泄漏回归钉住 admin token 在成功/失败答复面均不出现。

`rillaned` 从 `RILLANE_CONFIG` 读取启动配置；没有通用文件 watch、SIGHUP 重载或 `rillanectl reload`。已有订阅和控制面更新路径不等于 v1 的跨 OS 代际事务。路由/DNS/防火墙变更的副作用契约（`side_effects`：变更日志、所有权登记、幂等撤销——只撤销本实例条目，既有系统配置只登记不撤销）已就位，Linux 执行侧接线归配置发布协调器（RIL-019）。当前按名称追加的合并、组语义与 interval 单位缺陷见[研究证据](research/proxy-architectures-2026-11-14.md#verified-gaps)。

使用说明：[协议](PROTOCOLS.md)、[配置](config.md)、[订阅](subscription.md)、[网络接管](networking.md)、[可选 Mesh](mesh.md)。新实现按根目录 `todo.md` 的依赖和验收条件推进。
