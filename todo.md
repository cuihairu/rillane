# Rillane v1 架构实施清单

更新：2026-11-14。**本文件完整替换旧待办，是后续实施的唯一任务入口。** 旧清单及审计过程保留在 Git 历史，不继续作为当前完成状态。当前研究和文档已交付，不代表下列功能已经实现；所有任务从未验收状态开始，已有代码经核验可以复用，不要求重写。

设计依据：[目标架构](docs/zh/design/architecture-v1.md)、[概念与抽象理由](docs/zh/design/architecture-concepts.md)、[Debug / MCP](docs/zh/design/debug-and-mcp.md)、[竞品研究](docs/zh/research/proxy-architectures-2026-11-14.md)。[当前实现说明](docs/zh/architecture.md)用于区分复用能力与缺口。

## 范围和执行约定

- 六平台：Linux、OpenWrt、Windows、macOS、Android、iOS；**进程分流只要求 Windows/macOS/Linux 本机**。OpenWrt 不识别远端 PID；移动应用名单与受管 Per-App VPN 不作为本轮前置。
- Clash/Mihomo 订阅按节点、组、规则、其他配置分级兼容；不支持的关键语义明确拒绝，不静默替换。
- 一份数据面同时运行 game/web/general 策略；UDP 不等于游戏，QUIC 网页也需要支持。
- Debug 先于 MCP；纯推演、真实轨迹和主动探测分开。MCP 默认关闭，先只读，再受控写入。
- 每项应独立评审，完成时附提交、验收证据和限制；关联依赖没有完成时，只能做不依赖它的技术探针。构建成功不能替代真机接管/恢复验证。
- 以下依赖为任务完成的硬前置；技术探针可在目标接口未冻结前使用最小实验桩，结论必须反哺接口，不能冒充正式适配。没有真机、权限或签名材料的任务保持未完成，记录阻塞证据。不得仅凭接口、mock 或文档勾选平台验收。
- 修改涉及的测试与安全边界随任务交付，最终阶段只做跨模块整体验证；不把全部验证推迟到发布前。

## 1. 共享契约与配置基础

- [x] **RIL-001｜P0｜配置/能力契约**；依赖：无。（2026-11-15 完成）
  交付：`crates/rillane-config/src/contract.rs` 新增 ConfigVersion（唯一 V1；接受 "1"/"1.0"/"1.1"，自定义 serde 串/整数双向）、ConfigError 稳定原因码（`config.version.unknown`/`config.combo.unsupported`/`config.ingress.unknown`/`config.egress.unknown` + `code()` 恒定机器口径）、CapabilitySet 六能力位（full/minimal/Default=full 零差异）与 `validate_config`（contract.rs:179，逐块点名 `udp.enabled`/`network`/`network.dns`/`obfuscation`/`egress_pool`）。`lib.rs:34` RillaneConfig 增 `#[serde(default)] version` 字段——旧配置缺 version 适配 V1；`lib.rs:1197` `peek_version_error_probe` + `lib.rs:1264` `parse_any_format` 让未知版本穿透三格式 fallback 链携带稳定码浮出。验收证据：`tests/config_contract.rs` 5 测全绿（旧配置样例通过；显式 "1"/1 双写法；未知版本字符串/整数拒绝且原样回显字面量+码恒定；全能力集放行全部块；逐块最小能力集拒绝并点名特性+最小配置×最小能力集正例；序列化携带 `"version":"1"` 且 round-trip 保持）+ contract.rs 3 单测。内核不依赖 Clash 格式核验：`crates/rillane-core/Cargo.toml` 零 rillane/clash 依赖，全仓 Cargo.toml 无 clash 引用，Clash 解析仅存在于 rillane-subscription。workspace 测试 52 个 result 行全 ok、`cargo clippy --workspace --all-targets --all-features -- -D warnings` 干净。commit：见 git log `feat: add config contract with version and capabilities`。
- [x] **RIL-002｜P0｜来源与诊断契约**；依赖：RIL-001。（2026-11-15 完成）
  交付：`crates/rillane-config/src/source.rs` 新增 SourceId（校验非空/≤128B/无控制字符，serde try_from 同口径）、ObjectId（`(来源, local_id)` 身份主键）、`derive_local_id`（无上游 ID 时 SHA-256 内容身份派生，同内容必同 ID）、SourceLocation（来源 + JSON Pointer 风格指针，`join` 链式下钻字段）、SourceSnapshot（content_hash+parser_version 参与版本判定，`is_same_version_as` 同内容同解析器=无新版本）、`diff` → SnapshotDiff（removed/renamed/added/unchanged 全显式；跨来源 diff 拒绝 `source.mismatch`）、ObjectCatalog（BTreeMap 按稳定 ID 聚合多来源；同来源同 local_id 显式报错不静默合并）、CompatibilityDiagnostic（`compat.unsupported`/`compat.lossy` 稳定码 + 对象 ID + 位置 + 可选字段，文案不作匹配依据）。验收证据：`tests/source_contract.rs` 6 测全绿——同名「香港 01」跨来源共存不冲突（目录 2 项、按名查找可区分返回两个）；诊断定位对象（`proxies/3`）与字段（`proxies/3/ws-opts.headers.Host`）；删除/改名显式（B 改名≠删+增、C 显式删、D 显式增、同名不同身份不判改名）；同来源重复 local_id 拒绝；跨来源 diff 拒绝；内容摘要定长 64 字符。`cargo clippy --workspace --all-targets --all-features -- -D warnings` 干净。订阅侧 ConversionReport（RIL-093）到本契约的收敛接线随 RIL-007 样本库落地。commit：见 git log `feat: add source and diagnostic contract`。
- [ ] **RIL-003｜P0｜不可变代际模型**；依赖：RIL-001、RIL-002。
  交付：RuntimeGeneration、引用图和内容摘要。验收：循环/悬空引用拒绝；失败候选不覆盖成功代际，旧代际可被存活会话引用。
- [x] **RIL-004｜P0｜平台端口契约**；依赖：RIL-001。（2026-11-15 完成）
  交付：`crates/rillane-platform/src/network/ports.rs` 新增 CapturedInput（Packet/Socket 两变体分别建模：PacketInput=整包字节+PacketMeta(src/dst/IpProtocol)，SocketInput=还原五元组 TransportProtocol/local/remote）、CapturePort（recv，Ok(None)=端口关闭）、SocketHandle（u64 不透明句柄，无 RawFd/平台类型）、SocketBypass（幂等标记旁路，对应 linux.rs SO_MARK 逃逸面）、NetworkEvent/NetworkEvents（DefaultRouteChanged/ConnectivityLost/Restored/SystemDnsChanged）、SystemChange（幂等键+适配器自有载荷，契约不解释）与 RouteTransaction（prepare 系统零改动/apply 失败补偿/rollback 幂等）+ InMemory 参考实现（同时证明四 trait 可 mock）。验收证据：ports 5 测全绿（packet_and_socket_inputs_modeled_separately 穷尽匹配；capture_port_mock_yields_then_closes；socket_handle_is_opaque_no_os_types 幂等旁路；network_events_minimal_surface；route_transaction_minimal_semantics prepare→apply→rollback×2）；OS 细节不流入规则求值=ports.rs 零 OS 类型（无 RawFd/libc）且 `crates/rillane-routing/Cargo.toml` 仅依赖 rillane-config+rillane-core（grep 无 platform）；Linux 当前转发回归=platform lib 65 测 0 失败、全仓 workspace 测试持续绿。真实 Linux 实现归 RIL-029/RIL-018。commit：见 git log `feat: add platform port and identity contracts`。
- [x] **RIL-005｜P0｜本机身份契约**；依赖：RIL-001。（2026-11-15 完成）
  交付：`crates/rillane-platform/src/network/owner.rs` 新增 ConnectionKey（传输+四元组，同目标两进程靠 local 端口区分）、ProcessIdentity（pid+started_at_unix_ms 启动身份防 PID 复用；executable_path 与 comm 分开建模且 comm_truncated 如实标注——截断不冒充完整名；user_id）、`same_process`（启动身份缺失=不可验证返回 false 不猜）、OwnerResolution 三态 Known/Unknown(reason: DeadlineExceeded/PermissionDenied/NotFound/BudgetExhausted)/Unsupported、OwnerResolver（deadline 绝对截止；InMemoryOwnerResolver 用 fake_now 驱动不真实睡眠）、UnknownOwnerPolicy（Reject/FallbackGroup 显式命名/ExplicitDirect——无隐式直连变体）。验收证据：owner 4 测全绿——pid_reuse_detected_by_start_identity（同 PID 不同启动时间判异、缺启动身份不判同、连接键区分同目标两连接）；known_unknown_unsupported_are_three_distinct_states（Unsupported≠Unknown、不伪造 PID，三桌面外不强制）；deadline_bounds_every_query（过截止立即 DeadlineExceeded 不无限等）；permission_denied_is_unknown_not_silent_direct（穷尽策略匹配、显式直连字样只在用户声明变体出现）。Linux /proc 真实现归 RIL-030。commit：见 git log `feat: add platform port and identity contracts`。
- [ ] **RIL-006｜P0｜流、计划与会话契约**；依赖：RIL-003、RIL-004、RIL-005。
  交付：现有 RouteDecision/RoutePath 到 RoutePlan 的单向兼容映射、SessionPin 和 TCP/UDP association 边界。验收：规则结果与执行结果分离；一个流绑定明确代际，元数据有来源和缺失状态；保留 path/reason/route_type 语义，禁止两套独立决策器。

## 2. Clash/Mihomo 订阅与本地策略

- [x] **RIL-092｜P0｜当前导入器 interval 单位修复**；依赖：无。（2026-11-15 完成）
  交付：`crates/rillane-subscription/src/clash.rs:70-78` 新增 `clash_interval_secs`——按秒原样透传，`0`/缺省按 300 秒；`clash.rs:1246` 接入；`ClashProxyGroup::interval` 注释改秒（`clash.rs:393`）。导出侧同源缺陷一并修：`clash_export.rs:694-702` `interval_ms`→`interval_secs`，300_000→300（否则 Mihomo 侧 300000 秒≈不探活）。文档同步：`docs/subscription.md:14`、`docs/zh/subscription.md:14`、研究缺口表标已修。验收证据：`test_urltest_interval_read_in_seconds`（300→300、60000→60000、0→300、缺省→300）+ `clash_interval_secs_policy` 单测 + 旧用例 `test_urltest_group_probe_config_mapped` 改断言 60000；rillane-subscription 74 测全绿。commit：见 git log `fix: read clash interval in seconds`。
- [x] **RIL-093｜P0｜当前导入器有损转换护栏**；依赖：无。（2026-11-15 完成）
  交付：`crates/rillane-subscription/src/clash.rs:820` 新增 `ConversionReport`（丢弃节点/降级组/跳过规则三清单 + `is_empty`/`summary`）；`clash.rs:934` `with_strict` 严格导入模式，`clash.rs:974` `convert_to_rillane_with_report`——宽松模式配置照常产出但损失清单随行返回，严格模式清单非空整体拒绝（Err 即完整损失清单）。fallback/relay 不再静默映射：`clash.rs:1403` `convert_group_type_to_strategy` 改返回 Result，宽松降级+报告、严格拒绝（完整 fallback 实现归 RIL-012）。`clash.rs:875` `is_supported_proxy_type`：类型级不支持节点（Snell）宽松丢弃+报告、严格记单拒绝，单节点不再炸掉整个导入；已支持类型配置错误（reality 缺 public-key）保持点名硬错误（G1-6 拒绝策略保持）。过滤节点与跳过规则全部进清单，跳过规则不再只记日志。管线 wiring：`converter.rs:54` `ConversionOptions::strict_import`（缺省 false）、`converter.rs:142` 接入 `with_strict`、损失清单进 `ConversionResult::warnings`。验收证据：`tests/clash_guardrails.rs` 8 测全绿（严格拒 fallback/relay 点名组名；宽松降级+报告语义；不支持规则 rule-1/rule-2 点名；空 server 与 snell 丢节点报告+严格拒；vless reality 缺 public-key 双模式硬错误；干净配置零误伤回归含 url-test interval=300；summary 渲染；管线 strict_import 拒绝/宽松 warnings 可见）；rillane-subscription 92 测全绿（72 lib + 8 guardrails + 12 dsl）。commit：见 git log `feat: add lossy import guardrails`。

- [ ] **RIL-007｜P0｜订阅兼容样本库**；依赖：RIL-002。
  交付：脱敏 inline/provider-only/full-policy 正反例及字段/单位支持表。验收：每个关键输入有预期对象/诊断；节点密码与带 token URL 不进入样本仓库。
- [ ] **RIL-008｜P0｜来源快照原子替换**；依赖：RIL-003、RIL-007。
  交付：以来源版本替换当前 append-only 合并。验收：更新、删除、同名、重复刷新均正确；失败保留旧快照，规则不会反复追加；复用现有 SHA-256，将获取内容摘要/解析器版本纳入来源版本与代际溯源。
- [ ] **RIL-009｜P0｜proxy-providers/use**；依赖：RIL-008。
  交付：provider-only、远端节点来源与 use 引用。验收：周期/单位正确、引用可追踪、失效成员退出新流候选；缺失来源明确报告，内容 hash 参与快照版本判定，ETag 不替代摘要。
- [ ] **RIL-010｜P0｜provider 下载生命周期**；依赖：RIL-009。
  交付：大小/并发上限、超时、取消、条件缓存、退避和失败状态。验收：超限/坏内容/断网不发布坏版本，凭证和重定向处理有明确边界且不泄漏日志；摘要只证明内容一致，来源可信另由传输/可选预置摘要策略约束。
- [ ] **RIL-011｜P0｜select 选择保真**；依赖：RIL-009。
  交付：嵌套组引用和用户选择持久化。验收：更新不随意清空有效选择，删除所选节点产生明确恢复策略；组循环拒绝。
- [ ] **RIL-012｜P0｜url-test/fallback 语义**；依赖：RIL-009。
  交付：探测参数及按顺序回退，修复 fallback 映射 Random。验收：单位、迟滞/健康状态可核验，故障优先级符合样本，不能随机替代回退。
- [ ] **RIL-013｜P0｜load-balance 与不支持组**；依赖：RIL-009。
  交付：支持的分配算法与 relay/chain 支持表。验收：会话选择可重现；无法保真的 relay 明确拒绝，不能映射成 ConsistentHash。
- [ ] **RIL-014｜P0｜规则集与顺序**；依赖：RIL-007、RIL-008。
  交付：rule-providers、RULE-SET、规则更新和展开/引用策略。验收：首匹配顺序、源/目标端口与支持的逻辑表达式正确；未知关键条件不能被跳过。
- [ ] **RIL-015｜P0｜进程规则转换**；依赖：RIL-005、RIL-014。
  交付：PROCESS-NAME/路径等字段到规范条件的映射。验收：大小写/名称/路径语义独立；无平台能力时按明确模式拒绝或显式降级并报告。
- [ ] **RIL-016｜P0｜本地策略所有权**；依赖：RIL-011、RIL-012、RIL-013、RIL-014、RIL-015。
  交付：nodes-only/full-policy、本地优先级及来源命名空间。验收：刷新不覆盖用户游戏规则、监听口、系统路由、插件或管理凭证；关键有损转换拒绝候选。
- [ ] **RIL-017｜P0｜旧 profile 迁移**；依赖：RIL-006、RIL-016。
  交付：proxy/game/web 预设展开到并列 ScenarioPolicy。验收：旧配置可读，有迁移诊断；新配置可同时声明 game/web，不能仍由单一互斥枚举控制。

## 3. 发布事务与共享数据面

- [ ] **RIL-018｜P0｜系统副作用计划/补偿**；依赖：RIL-003、RIL-004。
  交付：路由/DNS/防火墙变更日志、所有权与幂等撤销。验收：任一步失败只撤销本实例修改；已有系统配置不被误删。
- [ ] **RIL-019｜P0｜配置发布协调器**；依赖：RIL-016、RIL-018。
  交付：prepare/apply/publish/drain/reclaim 和持久化顺序。验收：OS 应用失败保留旧代际；发布中崩溃可恢复，磁盘与有效状态可解释且可对账。
- [ ] **RIL-020｜P0｜DNS 与代际一致性**；依赖：RIL-006、RIL-019。
  交付：解析上下文、fake-IP 生命周期与 socket 旁路。验收：旧会话引用不被提前复用，DNS 不进代理环，未知域名来源不误关联进程。
- [ ] **RIL-021｜P0｜并列场景求值**；依赖：RIL-017、RIL-019。
  交付：game/web/general 条件、优先级、目标与失败动作。验收：同目标的不同本机应用可选不同组；浏览器 QUIC 不因 UDP 被归入游戏。
- [ ] **RIL-022｜P0｜计划执行与会话绑定**；依赖：RIL-006、RIL-021。
  交付：具体端点/能力校验与允许的拨号回退。验收：旧 TCP/UDP 不随质量逐包换出口；新流采用新代际，计划与实际端点分别可见。
- [ ] **RIL-023｜P0｜流排空与安全撤销**；依赖：RIL-022。
  交付：普通更新排空、超时回收、强制撤销规则。验收：长连接更新行为确定；删除端点与撤销权限分别处理，断线需重连的边界明确。
- [ ] **RIL-024｜P0｜有界会话与队列预算**；依赖：RIL-022。
  交付：场景会话数、拨号、UDP 映射、发送队列及内存上限。验收：压力下拒绝/背压可解释、内存不无界增长，控制请求不阻塞转发。
- [ ] **RIL-025｜P0｜并行负载公平调度**；依赖：RIL-024。
  交付：游戏小包与网页吞吐的调度规则。验收：持续下载时游戏尾延迟可测、网页不饥饿；报告只能影响本地可控瓶颈。
- [ ] **RIL-026｜P0｜类型化质量样本**；依赖：RIL-006。
  交付：metric/source/target/count/time/validity 与当前指标迁移。验收：连接失败率不再名为丢包率；未知/过期不当零，真实丢包说明测量对端。
- [ ] **RIL-027｜P0｜场景评分与迟滞**；依赖：RIL-021、RIL-026。
  交付：不同目标权重、样本时效、切换阈值与冷却。验收：输入快照可重放理由；样本不足不伪造 SLO 达标，不影响已绑定流。
- [ ] **RIL-028｜P2｜网页连接优化边界**；依赖：RIL-022、RIL-024。
  交付：协议支持范围内的预热、TLS 恢复与池回收。验收：实际减少代理建连成本且有资源上限；不把代理池当内容缓存，不为不支持协议伪造多路复用。

## 4. 平台适配与构建裁剪

- [ ] **RIL-029｜P0｜Linux 接管端口迁移**；依赖：RIL-004、RIL-018、RIL-020。
  交付：复用现有 TUN 的双栈接管、旁路及网络事件。验收：TCP/UDP/QUIC、DNS、MTU 与多网卡回归，无自代理环。
- [ ] **RIL-030｜P0｜Linux 身份强化**；依赖：RIL-005、RIL-015、RIL-029。
  交付：完整名称/路径、权限/namespace 边界、有界缓存。验收：PID/端口复用、UDP、权限不足及 comm 截断不误归因；同目标两进程分别路由。
- [ ] **RIL-031｜P0｜Linux 生命周期恢复**；依赖：RIL-019、RIL-029。
  交付：systemd 启停、异常退出日志与重启修复。验收：终止/崩溃/网络切换后 DNS 与路由恢复，重复启动无残留。
- [ ] **RIL-032｜P0｜Windows 技术探针**；依赖：无（早期风险消减，反哺 RIL-004/RIL-005）。
  交付：Wintun、公开归属查询/WFP-ALE 的实测选型记录及最低版本/权限。验收：Windows 上展示 TCP/UDP 本机归因和原型防环证据，记录不可用字段。
- [ ] **RIL-033｜P1｜Windows 接管/旁路实现**；依赖：RIL-018、RIL-020、RIL-032。
  交付：packet I/O、双栈路由/DNS 和旁路。验收：真实浏览器/游戏流进入共享内核，DNS/代理拨号不循环，失败可补偿。
- [ ] **RIL-034｜P1｜Windows 进程适配**；依赖：RIL-015、RIL-032、RIL-033。
  交付：正式 OwnerResolver 和身份缓存。验收：同目标多进程、UDP、进程退出/端口复用/权限失败，unknown 策略均有真机证据。
- [ ] **RIL-035｜P1｜Windows 服务与退出恢复**；依赖：RIL-019、RIL-033、RIL-034。
  交付：SCM/权限、驱动依赖校验、安装/卸载恢复。验收：服务崩溃、休眠、切网和卸载不遗留路由/DNS；签名和依赖限制公开。
- [ ] **RIL-036｜P0｜macOS 技术探针**；依赖：无（早期风险消减，反哺 RIL-004/RIL-005）。
  交付：公开接管/本机身份方案、helper/extension 边界和签名 entitlement 记录。验收：真机验证所需身份可得性与发布约束，缺口明确，不靠私有 fd。
- [ ] **RIL-037｜P1｜macOS 接管与旁路**；依赖：RIL-018、RIL-020、RIL-036。
  交付：选定公开接口的数据面和路由/DNS 补偿。验收：双栈 TCP/UDP/QUIC、DNS、MTU 和系统代理共存；权限失败不半接管。
- [ ] **RIL-038｜P1｜macOS 本机身份**；依赖：RIL-015、RIL-036、RIL-037。
  交付：生产 OwnerResolver 与匹配适配。验收：同目标两本机应用分别出站、身份变化和权限失败有明确结果；不能用仅能接管证明可归因。
- [ ] **RIL-039｜P1｜macOS 宿主与恢复**；依赖：RIL-019、RIL-037、RIL-038。
  交付：签名宿主/辅助组件生命周期、升级及网络恢复。验收：授权拒绝、睡眠/唤醒、切网、退出与卸载在真机恢复系统状态。
- [ ] **RIL-040｜P0｜最小构建依赖裁剪**；依赖：RIL-004。
  交付：small/mobile/full feature 与可选 Wasmtime/内容检查/插件。验收：small 依赖图无 Wasmtime/JIT，标准订阅/共享转发仍工作，不能仅隐藏配置入口。
- [ ] **RIL-041｜P1｜OpenWrt 网关接线**；依赖：RIL-019、RIL-029、RIL-040。
  交付：musl 包、fw4/nftables 共存和 LAN/本机策略。验收：设备/IP/域名/端口、IPv4/IPv6、DNS 与 UDP 工作，不要求客户端 PID。
- [ ] **RIL-042｜P1｜OpenWrt 运维与资源**；依赖：RIL-041。
  交付：procd、配置更新恢复、低内存默认预算。验收：路由器启停/升级/断网恢复，测得 RSS/CPU/吞吐上限；不支持的架构明确列出。
- [ ] **RIL-094｜P0｜iOS 公开 packetFlow 早期探针**；依赖：无。
  交付：最小签名设备实验验证批量 read/write、缓冲所有权、取消、吞吐/RSS 与 App/Extension 边界。验收：不依赖私有 fd；结论修订 RIL-043，缺少签名/设备明确未验证，不等正式 FFI 完成才试。
- [ ] **RIL-043｜P1｜移动批次 FFI**；依赖：RIL-004、RIL-006、RIL-040、RIL-094。
  交付：包批次/缓冲所有权、线程、背压、取消、ABI 版本。验收：fd 与公开 packetFlow 都能桥接；无悬空指针、取消后回调或无界队列。
- [ ] **RIL-044｜P1｜移动宿主生命周期契约**；依赖：RIL-019、RIL-043。
  交付：配置/秘密引用注入、启动停止、网络变化及有界诊断 IPC。验收：停止可重复调用，核心不假定移动 VPN 与宿主同 OS 进程。
- [ ] **RIL-045｜P1｜Android 完整转发**；依赖：RIL-022、RIL-043、RIL-044。
  交付：VpnService/JNI 接入完整 TCP/UDP，移除仅测试网段 ICMP 的交付限制。验收：真实网站、QUIC 与游戏流通过同一实例，protect 防环与 DNS 有效。
- [ ] **RIL-046｜P1｜Android 服务与切网**；依赖：RIL-045。
  交付：前台服务、撤销授权、后台、Wi-Fi/蜂窝变化。验收：真机启停/切网/权限撤销/低内存恢复；不将应用名单作为基础交付前置。
- [ ] **RIL-047｜P1｜iOS 公开包桥接**；依赖：RIL-043、RIL-044。
  交付：NEPacketTunnelFlow readPackets/writePackets 批次桥接。验收：无私有 KVC fd 依赖；TCP/UDP 进入共享内核且背压/释放正确。
- [ ] **RIL-048｜P1｜iOS 宿主 IPC 与秘密**；依赖：RIL-047。
  交付：App/Extension 配置传递、共享凭证引用、状态与诊断通道。验收：未授权宿主读不到秘密；不假设可得任意第三方 PID，不默认启动入站 MCP。
- [ ] **RIL-049｜P1｜iOS 真机生命周期**；依赖：RIL-022、RIL-048。
  交付：签名产物、扩展内存预算、切网与后台恢复。验收：真机 DNS/双栈/UDP/QUIC/网站与游戏并行，暂停恢复和系统终止有证据。
- [ ] **RIL-050｜P2｜可选 Mesh/插件装配**；依赖：RIL-022、RIL-040。
  交付：标准代理不依赖 Mesh，受管能力协商与插件隔离。验收：普通订阅产物关闭扩展可用；未完成安全承载的 UDP Mesh 明确拒绝，不能明文旁路发布。

## 5. Debug、真实路径与诊断工具

- [ ] **RIL-051｜P0｜诊断与事件 Schema**；依赖：RIL-002、RIL-006、RIL-026。
  交付：FlowTrace/TraceEvent、原因码、generation/flow/attempt ID、时间与证据类型。验收：预测/观测/推断/未知互不混淆，schema 版本与兼容规则明确。
- [ ] **RIL-052｜P0｜有界事件采集器**；依赖：RIL-024、RIL-051。
  交付：环形缓冲、TTL、采样、每流上限和订阅背压。验收：慢消费者/满缓冲不阻塞数据面，丢事件计数可见，关闭追踪不影响转发。
- [ ] **RIL-053｜P0｜真实流生命周期埋点**；依赖：RIL-020、RIL-022、RIL-052。
  交付：接管、身份、DNS、规则、选组、拨号尝试、实际出口与关闭事件。验收：A 失败改拨 B 可完整解释；UDP association 与 TCP 的起止语义明确。
- [ ] **RIL-054｜P0｜纯 Explain 服务**；依赖：RIL-021、RIL-027、RIL-051。
  交付：使用生产求值器、固定配置/质量快照的规则推演。验收：无 DNS/拨号/OS 身份查询，证据缺失返回条件性结果，输入快照可离线重放。
- [ ] **RIL-055｜P0｜逐连接查询服务**；依赖：RIL-053。
  交付：活动/近期连接分页、过滤、流详情和事件读取。验收：超限/过期/未知 ID 明确返回；不能把 ingress-egress 聚合 ID 当真实 flow ID。
- [ ] **RIL-056｜P0｜兼容连接视图修正**；依赖：RIL-055。
  交付：兼容 `/connections` 的真实字段映射与可用性说明。验收：缺失时间、域名、链路不能伪造；旧聚合 API 保持明确独立语义。
- [ ] **RIL-057｜P0｜DiagnosticView 脱敏边界**；依赖：RIL-051。
  交付：结构化字段白名单、别名、详细身份范围及错误路径过滤。验收：URL token/密码/私钥/运行配置不外泄，日志/名称按不可信文本处理。
- [ ] **RIL-058｜P0｜diagnose 安全导出**；依赖：RIL-055、RIL-057。
  交付：按范围选择快照、日志和配置，默认安全的包清单。验收：检查 runtime_config/subscriptions/错误日志全部出口；现有原始包不自动传给模型。
- [ ] **RIL-059｜P1｜主动探测作业服务**；依赖：RIL-026、RIL-051、RIL-057。
  交付：DNS/connect/代理握手/支持的 UDP 回显作业。验收：目标范围、并发/流量限额、超时、取消生效；只读调用不隐式探测，不允许不可信文本扩展目标。
- [ ] **RIL-060｜P0｜Explain/Trace CLI**；依赖：RIL-054、RIL-055、RIL-057。
  交付：冻结命令语法、文本/版本化 JSON 与退出码。验收：同一代际的规则来源、计划与实际差异可查；现有 Mesh dry-run 不冒充普通规则解释。
- [ ] **RIL-061｜P1｜Probe CLI**；依赖：RIL-059、RIL-060。
  交付：显式发起/取消和结果展示。验收：网络副作用、目标和测量类型可见；失败率/RTT/丢包分别标记，不推断机场内部路径。
- [ ] **RIL-062｜P1｜路径图导出**；依赖：RIL-060。
  交付：从共享只读服务导出 SVG，标注路径层、时间与缺口。验收：计划/连接/Mesh/L3 不混画，长文本/恶意名称安全转义，图与 JSON 内容一致。
- [ ] **RIL-063｜P2｜交互路径检查入口**；依赖：RIL-055、RIL-057、RIL-062。
  交付：现有管理界面的连接筛选、逐段展开与配置来源定位。验收：不重复实现路由器，分页/断连/无权限/丢事件有明确状态，详细身份由权限控制。
- [ ] **RIL-064｜P1｜诊断开销与留存验证**；依赖：RIL-052、RIL-058、RIL-063。
  交付：默认上限与关闭/采样/全量的对照报告。验收：高并发下 CPU/RSS/尾延迟有证据，历史可过期/删除，指标标签不含高基数身份或秘密。

## 6. 可选只读 MCP

- [ ] **RIL-065｜P1｜共享应用服务边界**；依赖：RIL-054、RIL-055、RIL-057、RIL-059。
  交付：CLI/UI/MCP 可共用的窄化诊断与配置调用接口。验收：不暴露 shell、任意文件、通用 HTTP 或原始管理员转发；核心不依赖 MCP SDK。
- [ ] **RIL-066｜P1｜MCP 版本和工具契约**；依赖：RIL-065。
  交付：固定 SDK/协议版本、工具输入/输出 schema 和错误语义。验收：对照官方所选版本，未知字段/超长输入/取消行为有契约；工具注解不充当授权。
- [ ] **RIL-067｜P1｜可选 stdio 程序**；依赖：RIL-040、RIL-066。
  交付：`apps/rillane-mcp` 装配和显式启动入口。验收：默认不启用、不增加监听端口；stdout 只有协议，日志到 stderr，EOF/超时/退出不遗留作业。
- [ ] **RIL-068｜P1｜MCP 服务端范围鉴权**；依赖：RIL-057、RIL-067。
  交付：调用者身份、只读/详细身份/探测/写入权限及速率限制。验收：直接构造调用仍无法越权；凭证留在适配器，模型声称授权不能升级范围。
- [ ] **RIL-069｜P1｜MCP 状态和质量工具**；依赖：RIL-027、RIL-068。
  交付：get_status/get_policy_quality。验收：结果与 CLI 服务一致，样本时效/缺失明确，响应限长并脱敏。
- [ ] **RIL-070｜P1｜MCP 连接和 Explain 工具**；依赖：RIL-060、RIL-068。
  交付：list_flows/get_flow_trace/explain_route。验收：分页、代际和证据类型保留；查询不会隐式增加无限采集或网络请求。
- [ ] **RIL-071｜P1｜MCP 主动探测工具**；依赖：RIL-061、RIL-068。
  交付：run_probe/cancel_probe，单独授权及配额。验收：只读身份不能启动探测，取消/会话退出释放资源，任意内网目标被目标策略拒绝。
- [ ] **RIL-072｜P1｜不可信内容与泄漏回归**；依赖：RIL-069、RIL-070、RIL-071。
  交付：恶意订阅名称、日志指令、错误配置和超大结果样本。验收：数据无法变成工具指令，任何成功/失败响应均无秘密，详细身份权限不能绕过。

## 7. 配置提案与受控 MCP 写入

- [ ] **RIL-073｜P1｜ConfigProposal 存储**；依赖：RIL-019、RIL-065。
  交付：服务端 patch、基础代际/哈希、所有者、范围、TTL 与不可猜测 ID。验收：内容修改失效，过期/跨调用者读取拒绝，临时状态有容量和回收上限。
- [ ] **RIL-074｜P1｜验证和变更预览**；依赖：RIL-054、RIL-073。
  交付：规范化 diff、引用/能力验证、模拟受影响流类别和副作用报告。验收：校验不改变有效配置；诊断与 diff 脱敏，预测影响不冒充实际连接结果。
- [ ] **RIL-075｜P1｜精确授权绑定**；依赖：RIL-068、RIL-074。
  交付：批准绑定提案摘要/范围，兼容用户预授权的有限自动化。验收：改参数/重放/借用其他用户提案不能越权；默认只读无法写入，超范围需新增授权。
- [ ] **RIL-076｜P1｜并发与幂等 Apply**；依赖：RIL-019、RIL-075。
  交付：版本前置检查、幂等键和 ApplyReceipt。验收：人工修改后旧提案返回冲突；客户端超时重试只执行一次，磁盘/OS/代际状态可对账。
- [ ] **RIL-077｜P1｜可校验回滚**；依赖：RIL-023、RIL-076。
  交付：按回执恢复候选、重验权限/能力与补偿状态。验收：外部配置改变不被盲目覆盖；崩溃/部分失败报告明确，不能宣称回滚恢复旧连接。
- [ ] **RIL-078｜P1｜管理通路看门狗**；依赖：RIL-076、RIL-077。
  交付：可能断开管理连接的变更预警、宿主侧定时确认和恢复。验收：客户端断开/daemon 重启时仍按事务恢复并验证；恢复失败给出具体修复信息。
- [ ] **RIL-079｜P1｜配置 CLI 闭环**；依赖：RIL-074、RIL-076、RIL-077、RIL-078。
  交付：preview/apply/rollback、回执查询与审计摘要。验收：可以在不接 AI 时完成相同闭环，授权与版本检查不能被 CLI 绕过。
- [ ] **RIL-080｜P1｜MCP 提案工具**；依赖：RIL-070、RIL-074。
  交付：validate_config/preview_config_change。验收：返回服务端提案 ID、diff 和限制，不返回秘密；无写权限也不能利用预览激活配置。
- [ ] **RIL-081｜P1｜MCP 应用与回滚工具**；依赖：RIL-072、RIL-079、RIL-080。
  交付：apply_config_change/rollback_config 与审计。验收：正常闭环、拒绝授权、过期、冲突、重复调用、断连和部分失败均通过；不能提供任意管理 API 逃生口。
- [ ] **RIL-082｜P2｜移动/路由器诊断接入**；依赖：RIL-042、RIL-046、RIL-049、RIL-070。
  交付：OpenWrt 可选资源受限适配器、移动授权 IPC/脱敏导出与桌面桥接说明。验收：VPN 扩展无默认 MCP 服务/手机入站端口，宿主权限与导出范围受控。

## 8. 整体验证、产物与发布证据

- [ ] **RIL-083｜P1｜契约与跨语言 CI**；依赖：RIL-043、RIL-051、RIL-066。
  交付：IR/事件/API/FFI schema 与兼容样本检查。验收：破坏兼容的变化明确失败；Rust、宿主桥接和 MCP 工具对同一版本有一致解释。
- [ ] **RIL-084｜P1｜六平台构建产物矩阵**；依赖：RIL-035、RIL-039、RIL-040、RIL-042、RIL-046、RIL-049、RIL-067。
  交付：目标架构/最低系统/feature、签名与安装产物清单。验收：构建日志和依赖可复核，不把 cross-check 当运行通过；无签名设备证据保持未验证。
- [ ] **RIL-085｜P1｜三桌面进程端到端验收**；依赖：RIL-030、RIL-034、RIL-038、RIL-060。
  交付：相同目标浏览器/两个游戏的分组轨迹及故障样例。验收：TCP/UDP、名称/路径、权限不足、PID/端口复用均实测，规则来源可查。
- [ ] **RIL-086｜P1｜六平台并行场景验收**；依赖：RIL-025、RIL-031、RIL-035、RIL-039、RIL-042、RIL-046、RIL-049。
  交付：真实网站/QUIC 与游戏并行转发矩阵。验收：分别报告双栈、DNS、MTU、切网与退出恢复；不支持项明确拒绝或按配置降级。
- [ ] **RIL-087｜P0｜订阅到执行完整回归**；依赖：RIL-010、RIL-016、RIL-022、RIL-060。
  交付：多来源刷新、组回退、规则集、来源删除与本地覆盖场景。验收：输入→IR→代际→Explain→实际出口一致；凭证和关键策略不静默丢失。
- [ ] **RIL-088｜P1｜事务与故障注入验收**；依赖：RIL-019、RIL-023。
  交付：逐阶段失败、磁盘错误、崩溃、网络失联和多客户端并发。验收：旧版本保留/补偿/重启恢复行为可重放，未补偿问题不能用成功回执掩盖。
- [ ] **RIL-089｜P1｜并行负载性能对照**；依赖：RIL-025、RIL-027、RIL-031、RIL-064。
  交付：先提供 Linux 同节点/线路/负载对照，其他平台随适配追加；连接池优化单独对照，不阻断核心策略测量。验收：p50/p95、抖动、有效丢包样本、TTFB、吞吐、CPU/RSS 与重复次数完整；同时报告回退和无收益条件。
- [ ] **RIL-090｜P1｜MCP 客户端互操作验收**；依赖：RIL-072、RIL-081、RIL-083。
  交付：固定 SDK/协议的真实客户端读写演示与断连恢复证据。验收：取消/错误/分页/启动退出/权限拒绝正确；模型缺席时核心与 CLI 照常运行。
- [ ] **RIL-091｜P1｜完整范围文档与限制对齐**；依赖：RIL-084、RIL-085、RIL-086、RIL-087、RIL-088、RIL-089、RIL-090。
  交付：本轮完整范围的中英文功能矩阵、支持表、安装/恢复/Debug/MCP 示例及证据链接；各阶段产物先独立更新对应文档，不等待本项。验收：README、站点、命令 help 与实际产物一致，提案和已交付分开，链接/SVG/站点构建通过。

## 9. 独立里程碑与优先级

P0 = 首批用户价值/关键架构与高风险探针；P1 = 承诺范围的后续平台与工具；P2 = 可推迟的增强。优先级不覆盖硬依赖，P2 不得阻塞 P0/P1 阶段产物。各平台的自身运行与恢复门禁独立，不等六平台汇总任务全部完成才交付。

- [ ] **RIL-095｜P0｜Linux 兼容修复中间产物**；依赖：RIL-092、RIL-093。
  交付：基于已有 Linux 转发链路的可评审候选、兼容说明与回归证据。验收：订阅样例真实接管/转发、显式 300 秒不变 1 秒、有损配置拒绝、启停恢复正确；不宣称新 provider、完整 fallback 或新 ScenarioPolicy 已交付。

| 阶段 | 最小验收范围 | 不阻塞它的后续工作 |
|---|---|---|
| M0 风险探针 | RIL-032/036/094，反馈接口假设与资源限制 | 全量 IR、正式平台适配与签名发布 |
| M1 当前 Linux 兼容修复 | RIL-092/093 → RIL-095 | 新配置编译器、六平台、MCP |
| M2 新架构 Linux 基线 | RIL-001～023 中的兼容/事务依赖闭包 + RIL-029～031；订阅刷新和恢复实测 | Windows/macOS/mobile 完整验收与 Mesh |
| M3 Linux game/web 并行 | RIL-024～027，实测同一实例同时转发、稳定会话和有界资源 | 连接池优化、六平台性能汇总、MCP |
| M4 诊断和只读 MCP | RIL-051～060、065～070、相关鉴权/泄漏验证；先 CLI，再适配器 | 路径 GUI、写工具、移动桥接 |
| M5 后续平台与受控配置 | 各自正式适配门禁；RIL-073～081 独立通过写入闭环 | 可选 Mesh 增强、HTTP MCP |

M2/M3 的准确依赖以逐项任务为准，表中范围不是新的串行队列。后续汇总验收 RIL-084～091 不作为 M1/M2/M3 的统一发布锁；阶段交付仍须满足该范围的回归、文档与发布授权要求。

## 首批交付与暂缓范围

首批从 RIL-092/RIL-093 的现状修复与 RIL-032/RIL-036/RIL-094 的平台探针开始，同时推进 RIL-001～RIL-007；探针反馈用于修订 RIL-004/RIL-005/RIL-043。Debug 在共享路由/事件契约稳定后接入；MCP 读写分别过门禁。

HTTP MCP、远程公开管理、Android 按应用独立路由、iOS 受管 Per-App VPN、LAN 远端进程代理、内容 MITM 和无损跨出口迁移不属于本清单承诺。若后续纳入，需先补具体需求和设计；不能为勾完本表而隐式扩大范围。
