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
- [x] **RIL-003｜P0｜不可变代际模型**；依赖：RIL-001、RIL-002。（2026-11-15 完成）
  交付：`crates/rillane-config/src/generations.rs` 新增 `RuntimeGeneration`（generations.rs:122，字段只读、唯一构造入口 `build`）、`GenerationObject`（:76，稳定 ID + 类别 + 对象内容摘要）、`GenerationEdge`（:88，引用边）、`GenerationStore`（:332，事务式发布位）。引用图校验：悬空引用拒绝（`generation.reference.dangling`）、循环引用拒绝（`generation.reference.cycle`，白灰黑迭代 DFS、环路径首尾同一对象）、同 ID 冲突内容拒绝（`generation.object.duplicate`，同 ID 同内容按一条计不静默合并）。内容摘要：`digest_parts`（:98）与代际身份均为 SHA-256——域分隔前缀 + 排序对象（来源/local_id/类别/内容摘要）+ 排序引用边全部入哈希，同内容必同 `generation_id`，任一子变化产生新代际。反序列化经同一 `build` 复核并核对身份，被篡改代际以 `generation.id.mismatch` 拒绝（自定义 Deserialize，对象改存排序 Vec 以避开非字符串 map 键）。验收证据：`tests/generation_contract.rs` 4 测全绿——失败候选（悬空 + 循环两种）拒绝后发布位身份不变且内容完整；发布 v2 后旧 `Arc` 句柄仍完整可用（不可变、n1 保持 v1 摘要、边数 1），新代际 n1 为新内容互不干扰；同内容重复发布返回同一 `Arc`（指针相等）且内容回退后摘要身份复原；serde round-trip 保身份。generations.rs 6 单测（含冲突重复、篡改身份拒绝）。rillane-config 87 测全绿、`cargo clippy -p rillane-config --all-targets --all-features -- -D warnings` 干净。接线边界：订阅刷新发布归 RIL-008，RoutePlan/SessionPin 消费归 RIL-006。commit：见 git log `feat: add immutable generation contract`。
- [x] **RIL-004｜P0｜平台端口契约**；依赖：RIL-001。（2026-11-15 完成）
  交付：`crates/rillane-platform/src/network/ports.rs` 新增 CapturedInput（Packet/Socket 两变体分别建模：PacketInput=整包字节+PacketMeta(src/dst/IpProtocol)，SocketInput=还原五元组 TransportProtocol/local/remote）、CapturePort（recv，Ok(None)=端口关闭）、SocketHandle（u64 不透明句柄，无 RawFd/平台类型）、SocketBypass（幂等标记旁路，对应 linux.rs SO_MARK 逃逸面）、NetworkEvent/NetworkEvents（DefaultRouteChanged/ConnectivityLost/Restored/SystemDnsChanged）、SystemChange（幂等键+适配器自有载荷，契约不解释）与 RouteTransaction（prepare 系统零改动/apply 失败补偿/rollback 幂等）+ InMemory 参考实现（同时证明四 trait 可 mock）。验收证据：ports 5 测全绿（packet_and_socket_inputs_modeled_separately 穷尽匹配；capture_port_mock_yields_then_closes；socket_handle_is_opaque_no_os_types 幂等旁路；network_events_minimal_surface；route_transaction_minimal_semantics prepare→apply→rollback×2）；OS 细节不流入规则求值=ports.rs 零 OS 类型（无 RawFd/libc）且 `crates/rillane-routing/Cargo.toml` 仅依赖 rillane-config+rillane-core（grep 无 platform）；Linux 当前转发回归=platform lib 65 测 0 失败、全仓 workspace 测试持续绿。真实 Linux 实现归 RIL-029/RIL-018。commit：见 git log `feat: add platform port and identity contracts`。
- [x] **RIL-005｜P0｜本机身份契约**；依赖：RIL-001。（2026-11-15 完成）
  交付：`crates/rillane-platform/src/network/owner.rs` 新增 ConnectionKey（传输+四元组，同目标两进程靠 local 端口区分）、ProcessIdentity（pid+started_at_unix_ms 启动身份防 PID 复用；executable_path 与 comm 分开建模且 comm_truncated 如实标注——截断不冒充完整名；user_id）、`same_process`（启动身份缺失=不可验证返回 false 不猜）、OwnerResolution 三态 Known/Unknown(reason: DeadlineExceeded/PermissionDenied/NotFound/BudgetExhausted)/Unsupported、OwnerResolver（deadline 绝对截止；InMemoryOwnerResolver 用 fake_now 驱动不真实睡眠）、UnknownOwnerPolicy（Reject/FallbackGroup 显式命名/ExplicitDirect——无隐式直连变体）。验收证据：owner 4 测全绿——pid_reuse_detected_by_start_identity（同 PID 不同启动时间判异、缺启动身份不判同、连接键区分同目标两连接）；known_unknown_unsupported_are_three_distinct_states（Unsupported≠Unknown、不伪造 PID，三桌面外不强制）；deadline_bounds_every_query（过截止立即 DeadlineExceeded 不无限等）；permission_denied_is_unknown_not_silent_direct（穷尽策略匹配、显式直连字样只在用户声明变体出现）。Linux /proc 真实现归 RIL-030。commit：见 git log `feat: add platform port and identity contracts`。
- [x] **RIL-006｜P0｜流、计划与会话契约**；依赖：RIL-003、RIL-004、RIL-005。（2026-11-15 完成）
  交付：`crates/rillane-core/src/plan.rs` 新增 `RoutePlan`（plan.rs:187，唯一构造入口 `from_decision` plan.rs:199——现有 RouteDecision/RoutePath 单向派生，path/reason/route_type 逐字段透传保留，不存在旁路构造入口，**禁止两套独立决策器**）、`DecisionSnapshot`（:131，规则结果冻结快照，公开只读无再构造）、`ExecutionOutcome`（:143，Pending/Dialed/Failed——规则结果与执行结果分离，拨号失败留在执行侧不回写规则结果，重连可覆盖执行结果但决策快照不可变）、`SessionPin`（:290，`for_plan` :298 代际取自计划——一个流绑定明确代际）、`ObjectRef`（:269，(来源, local_id) 内核侧不透明承载）、`GenerationRef`（:22，空身份拒绝；内核不依赖 rillane-config）、`MetadataOrigin`（:49）+ `Provenanced`（:78，缺失是显式状态带稳定原因，不静默缺席）、`FlowAssociation`（:333，TCP Stream / UDP Datagram 类型层面强制分侧，datagram 带 NAT 映射键；两种绑定都经 `pin()` 携带代际）。lib.rs 挂 `pub mod plan` + 根重导出。验收证据：`tests/flow_plan_contract.rs` 5 测全绿（同 decision 多次派生等价 + final_node 语义一致；Chain 三跳类型保留且尾跳=final_node；失败/成功反复切换后决策快照原封不动；Stream/Datagram 两形态 pin 同代际 + Provenanced 来源/缺失状态显式可查；分侧断言）；plan.rs 5 单测（三种 RoutePath 逐字段透传含 reason/route_type；分离不变量；来源与缺失；钉绑定代际；空代际拒绝）。rillane-core 86 测全绿、`cargo clippy -p rillane-core --all-targets --all-features -- -D warnings` 干净、Cargo.toml 零 rillane-* 依赖保持内核独立。commit：见 git log `feat: add flow plan and session contracts`。

## 2. Clash/Mihomo 订阅与本地策略

- [x] **RIL-092｜P0｜当前导入器 interval 单位修复**；依赖：无。（2026-11-15 完成）
  交付：`crates/rillane-subscription/src/clash.rs:70-78` 新增 `clash_interval_secs`——按秒原样透传，`0`/缺省按 300 秒；`clash.rs:1246` 接入；`ClashProxyGroup::interval` 注释改秒（`clash.rs:393`）。导出侧同源缺陷一并修：`clash_export.rs:694-702` `interval_ms`→`interval_secs`，300_000→300（否则 Mihomo 侧 300000 秒≈不探活）。文档同步：`docs/subscription.md:14`、`docs/zh/subscription.md:14`、研究缺口表标已修。验收证据：`test_urltest_interval_read_in_seconds`（300→300、60000→60000、0→300、缺省→300）+ `clash_interval_secs_policy` 单测 + 旧用例 `test_urltest_group_probe_config_mapped` 改断言 60000；rillane-subscription 74 测全绿。commit：见 git log `fix: read clash interval in seconds`。
- [x] **RIL-093｜P0｜当前导入器有损转换护栏**；依赖：无。（2026-11-15 完成）
  交付：`crates/rillane-subscription/src/clash.rs:820` 新增 `ConversionReport`（丢弃节点/降级组/跳过规则三清单 + `is_empty`/`summary`）；`clash.rs:934` `with_strict` 严格导入模式，`clash.rs:974` `convert_to_rillane_with_report`——宽松模式配置照常产出但损失清单随行返回，严格模式清单非空整体拒绝（Err 即完整损失清单）。fallback/relay 不再静默映射：`clash.rs:1403` `convert_group_type_to_strategy` 改返回 Result，宽松降级+报告、严格拒绝（完整 fallback 实现归 RIL-012）。`clash.rs:875` `is_supported_proxy_type`：类型级不支持节点（Snell）宽松丢弃+报告、严格记单拒绝，单节点不再炸掉整个导入；已支持类型配置错误（reality 缺 public-key）保持点名硬错误（G1-6 拒绝策略保持）。过滤节点与跳过规则全部进清单，跳过规则不再只记日志。管线 wiring：`converter.rs:54` `ConversionOptions::strict_import`（缺省 false）、`converter.rs:142` 接入 `with_strict`、损失清单进 `ConversionResult::warnings`。验收证据：`tests/clash_guardrails.rs` 8 测全绿（严格拒 fallback/relay 点名组名；宽松降级+报告语义；不支持规则 rule-1/rule-2 点名；空 server 与 snell 丢节点报告+严格拒；vless reality 缺 public-key 双模式硬错误；干净配置零误伤回归含 url-test interval=300；summary 渲染；管线 strict_import 拒绝/宽松 warnings 可见）；rillane-subscription 92 测全绿（72 lib + 8 guardrails + 12 dsl）。commit：见 git log `feat: add lossy import guardrails`。

- [x] **RIL-007｜P0｜订阅兼容样本库**；依赖：RIL-002。（2026-11-15 完成）
  交付：脱敏样本库 `crates/rillane-subscription/tests/samples/`——inline 正例（ss/vmess/trojan + select/url-test 组 + 3 规则）、full-policy 有损反例（无效端口 + snell + fallback/relay 组 + PROCESS-NAME/RULE-SET 规则）、provider-only 反例；字段/单位支持表 `docs/subscription-support.md` + `docs/zh/subscription-support.md`（L1-L4 分级 ✅/⚠️/❌/⏳ + 单位表，url-test interval 秒口径与 RIL-092 一致）。补两处关键语义显式化：ClashConfig 捕获 `proxy-providers`（原解析期静默丢弃）、ConversionReport 新增 `unsupported_blocks`（整块缺失显式可见，宽松随行/严格拒绝）+ `diagnostics(&SourceId)` 桥（RIL-002 契约收敛：损失 → 稳定码 + 定位 `proxies/<名>`/`proxy-groups/<名>`/`rules/<rule-N>`/`blocks/<块名>`；转换期 local_id 以显示名暂代，稳定派生随 RIL-008 切换）。验收证据：`tests/subscription_samples.rs` 5 测全绿——正例零损失且对象精确（3 节点名单、PROXY=Fixed、AUTO=Latency interval_secs=300、3 规则、default_node=sample-ss）；反例逐项预期（bad-port-node+sample-snell 丢、fb-group+relay-group 降级、rule-1/2 跳过、保留面 good-node-a+2 规则不误伤）；诊断桥码与定位逐条断言（unsupported/lossy 各归其位）；严格拒绝错误点名全部 6 项；provider-only 零吸收 + blocks/proxy-providers 诊断 + 严格拒；脱敏守卫（password/psk 只允许 REDACTED-SAMPLE、uuid 全零占位、禁 token= URL）。rillane-subscription 97 测全绿（72 lib + 8 guardrails + 12 dsl + 5 samples）、`cargo clippy -p rillane-subscription --all-targets --all-features -- -D warnings` 干净。commit：见 git log `feat: add subscription compatibility sample library`。
- [x] **RIL-008｜P0｜来源快照原子替换**；依赖：RIL-003、RIL-007。（2026-11-15 完成）
  交付：`crates/rillane-subscription/src/snapshots.rs` 新增 `SourceSnapshotStore`——按 SourceId 原子替换：`refresh_with(source, content, parse)` 解析闭包由调用方注入（本层零网络，下载生命周期归 RIL-010）；新内容**完整解析成功才发布**，失败返回 `RefreshError` 旧快照原样保留；同 content_hash+parser_version 返回 `Unchanged` 不重发（`set_parser_version` 升级后同内容重新发布——解析器版本入来源版本）；发布差异经 RIL-002 `diff` 全显式；`remove` 整源移除返回最后成功快照。内容摘要复用 SHA-256（`SourceSnapshot::hash_content`，与既有 `Subscription::content_hash` 同源）。merge 侧替换 append-only：`runtime_builder.rs` `merge_config_delta_in_place` 规则改**按名原位替换**（rule-N 序号稳定，首匹配顺序保持原位，重复刷新零新增不反复追加）、同名节点/组改**原位更新**（内容变化必须生效，不再跳过滞留旧内容）；`ConfigMergeStats` 增 rules_updated/nodes_updated/groups_updated。验收证据：snapshots.rs 7 测全绿——首刷全量发布；重复刷新 Unchanged 且快照版本不变；更新/删除显式（unchanged 1 + added 1 + removed 2，同名新身份≠改名）；`BAD` 解析失败旧快照保留（hash+对象数不变）；parser 升级同内容重发；整源 remove 返回旧快照、重复移除 None；跨来源共存且跨源 diff 稳定码拒绝。runtime 回归 `merge_config_delta_repeated_refresh_replaces_in_place`（同 delta 二次合并 rules_added=0/updated=2/总数不变；r1 改 target 后刷新原位生效）+ 既有 dedupe/connectors/并发合并 3 测不回归（runtime lib 175 测全绿）。rillane-subscription 104 测全绿（79 lib + 8 guardrails + 12 dsl + 5 samples）；`cargo clippy -p rillane-runtime -p rillane-subscription --all-targets --all-features -- -D warnings` 干净。接线边界：control_plane 刷新循环改走 Store、代际发布挂 RIL-003 GenerationStore 归 RIL-019 发布协调器；来源命名空间整块替换归 RIL-016。commit：见 git log `feat: replace append-only merge with source snapshots`。
- [x] **RIL-009｜P0｜proxy-providers/use**；依赖：RIL-008。（2026-11-15 完成）
  交付：provider-only、远端节点来源与 use 引用。验收：周期/单位正确、引用可追踪、失效成员退出新流候选；缺失来源明确报告，内容 hash 参与快照版本判定，ETag 不替代摘要。
  交付：**声明面**——`rillane-config` 增 `ProxyProviderDecl`（`:2475`，type/url/path/`interval_secs`/`health_check`；Clash `interval` 即**秒原样带入不换算**，RIL-092 口径）与 `ProviderHealthCheck`（`:2496`，enable/url/`interval_secs`），挂 `RoutingConfig::proxy_providers: BTreeMap<名, 声明>`（`:1738`，serde default + 空面不落盘）。**成员面**——`GroupMember` 增 `Provider{name}` 变体（`:2352`，serde tagged `type: provider`，`:2388`），`Serialize`/`From<GroupMemberTagged>`/`as_name`/`as_weight` 四臂齐补（`:2368`/`:2410`/`:2436`）。**解析面**——`ProviderNodeLibrary`/`ProviderNodeEntry`（`:2517`/`:2527`，平铺 serde `provider_nodes: {<名>: {nodes: [...]}}`）挂 `RoutingConfig::provider_nodes`（`:1745`）；`nodes(name)`（`:2546`）**库无此名或为空 = 空集**，与 `RuleSetRef` 缺库恒不命中同语义；`is_empty`（`:2555`）驱动空面不落盘。**引用可追踪**——`validate` 增组内 provider 成员须已声明（`:1812`），悬空引用构建期点名拒绝（「组 {} 引用了未声明的 provider」）不静默少成员。**求值面**——rillane-routing `resolve_group_descriptor` 增 `Provider` 臂（`crates/rillane-routing/src/lib.rs:381`）按库展开为 `GroupDescriptorMember::Node`（weight 1、带健康态）；url-test 探测循环（`:504`）与 `group_quality_report`（`:678`）跳过/平铺 provider 成员，不拿 provider 名当探测目标。**构建面**——runtime_builder 可达性扫描（`crates/rillane-runtime/src/runtime_builder.rs:2617`）跳过 provider 成员（构建期无静态节点集，不展开成 provider 名——那会误报悬空引用）。**导入面**——rillane-subscription `ClashProxyGroup` 增 `#[serde(rename="use")] use_providers`（`crates/rillane-subscription/src/clash.rs:397`）、`ClashConfig::proxy_providers` 由未知键静默丢弃改为 `HashMap<名, ClashProxyProvider>`（`:1132`）、新增 `ClashProxyProvider`/`ClashProviderHealthCheck`（`:1164`，kebab `health-check` rename）；`convert_proxy_groups_to_groups` 签名带 providers（`:1897`）：`use:` 已声明→`GroupMember::Provider`、未声明→显式进损失清单定位 `proxy-groups/<组>/use/<provider>`（`:1928`）；整块 `proxy-providers` 由 RIL-007「未支持块」改为**声明吸收**。**显式降级**——`ConversionReport::degraded_providers`（`:1217`）：每个声明的 provider 都登记「声明已吸收但节点目录载荷未装入（下载生命周期归 RIL-010）：当前提供 0 个节点，引用它的组成员集为空集」（`:1514`），接入 `is_empty`（`:1227`，故严格模式对含 provider 的配置不再「全绿」）、`summary` 出「降级 provider N 个」（`:1270`）、`diagnostics` 桥为 `compat.lossy` 定位 `proxy-providers/<名>`（`:1335`）。**导出面**——clash_export 组成员分流：provider 成员回写 `use:`（`crates/rillane-subscription/src/clash_export.rs:114`），`member_name` 增臂（`:727`），round-trip 保真。
  验收证据：config `proxy_provider_and_member_roundtrip`（`crates/rillane-config/src/lib.rs:1958`：YAML 解析后声明 interval 3600 秒原样 + health_check 周期 300 保留、`type: provider` 成员、节点库 `nodes("remote")==["node-a"]`；先往返再清空——声明 interval/成员/节点库三项语义不变；`validate` 通过→清空声明→点名拒绝含 "remote"；空 `RoutingConfig::default()` 序列化既无 `proxy_providers:` 也无 `provider_nodes:`）；routing `provider_member_expands_from_provider_node_library`（`crates/rillane-routing/tests/routing_tests.rs:480`，helper `:450`：库装入→`["node1","remote-a","remote-b"]`；库缺席→仅 `["node1"]`；纯 provider 组空库→组仍在但 `members.is_empty()`，**不伪装出成员**）；subscription `provider_only_surfaces_block_loss_not_silent`（`crates/rillane-subscription/tests/subscription_samples.rs:178` 改写：`unsupported_blocks` 空、`proxy_providers` 1 项 type=http/interval 3600/health-check 周期 300、`degraded_providers` 1 项点名 "sample-provider"、诊断定位 `proxy-providers/sample-provider` 码 `compat.lossy`、严格模式错误含 "sample-provider"）；`process_rules_convert_and_report_degraded`（`crates/rillane-subscription/src/clash.rs:3692`）等既有用例不回归。文档：subscription-support.md（en/zh）L2 组表「嵌套组引用 / `use:`」⏳→✅（求值期按 `provider_nodes` 展开、空库=空集不冒充成员、无载荷声明按引擎降级）、L4 表 `proxy-providers` ❌(整块)→✅（声明面 + interval 秒口径 + 未声明引用拒绝 + RIL-010 前逐条降级）。
  全量绿：config 89、routing 41（30 lib + 11 集成）、subscription 113（87 lib + 8 guardrails + 12 dsl + 6 samples）、runtime 177；`cargo test --workspace` 57 组 793 全过；`cargo clippy -p rillane-config -p rillane-routing -p rillane-subscription -p rillane-runtime --all-targets --all-features` 干净（仅既有 manifest 未用依赖告警）。
  边界：provider 载荷**下载/缓存/退避/大小并发上限**（内容 hash 参与快照版本、ETag 不替代摘要那半验收）归 RIL-010——本条交付的是声明面 + 引用追踪 + 求值展开 + 缺失来源显式报告，下载闭环落地后 `degraded_providers` 自然清零；控制面把声明装配进快照→库的发布归 RIL-019。

- [x] **RIL-010｜P0｜provider 下载生命周期**；依赖：RIL-009。（2026-11-15 完成）
  交付：大小/并发上限、超时、取消、条件缓存、退避和失败状态。验收：超限/坏内容/断网不发布坏版本，凭证和重定向处理有明确边界且不泄漏日志；摘要只证明内容一致，来源可信另由传输/可选预置摘要策略约束。
  交付：**下载闭环模块**——新 `crates/rillane-subscription/src/provider_fetch.rs`（proxy-provider RIL-009 声明与 rule-provider RIL-014 声明共用；载荷语义由调用方注入 parse，与 RIL-008 `SourceSnapshotStore::refresh_with` 同构）：`ProviderFetchPolicy`（`:35`，max_bytes/timeout/max_retries/尝试内退避/并发 concurrency/刷新间退避）；`ProviderFetcher`（`:150`）= Semaphore 并发闸 + 每来源失败账本（`Mutex<BTreeMap<SourceId, 状态>>`，短临界区绝不跨 await 持锁）。**六件交付面**——大小上限：`FetcherConfig::max_bytes` 可配（`crates/rillane-subscription/src/fetcher.rs:51`，订阅默认 50MiB、provider 默认 10MiB），Content-Length 快速拒绝 + 流式分块双闸沿用；并发上限：Semaphore（`fetch_payload` `:222`，取消可打断排队）；超时：策略化 per-attempt timeout；取消：`CancelToken`（`:82`，`watch` 布尔旗，发送端未取消即 drop 视为永不取消；排队与在途两处 `select!`）；条件缓存：`ConditionalGet` + `fetch_conditional`（fetcher `:74`/`:239`，If-None-Match/If-Modified-Since，304 → `FetchResult::not_modified` `:153` → `RefreshOutcome::Unchanged` 且**不触发解析**）；退避与失败状态：尝试内 2^n 指数退避封顶（fetcher `max_backoff`）+ 刷新间退避账本——`refresh_backoff_delay`（`:71`，初值 ×2^(连续失败-1) 封顶，纯函数可核验）、失败记账 `record_failure`（连续失败 +1、next_allowed_at 后移、成功清零）、退避门在发起网络**之前**拦截（BackoffGate，未发起网络即拒绝）。**下载闭环**——`refresh_payload`（`:343`）：退避门 → 并发闸 → 条件获取 → 预置摘要比对 → `store.refresh_with`；**任何阶段失败都不发布**（超限/断网在下载面、坏内容在解析面——store 旧快照原样保留即 RIL-008 语义）；坏内容进失败账本并作废本次条件缓存（载荷从未发布，下次必须全量 GET，不让 304 掩盖「从未成功发布」）。
  **凭证与重定向边界**——`redact_url`（fetcher `:88`）：userinfo 剥离 + 凭证类查询键（token/key/secret/password/auth/sign 等 12 类，大小写不敏感）值打码；fetcher 一切 tracing 日志与错误文案走脱敏面；**reqwest 自身错误链嵌原始 URL，不得整链透传**——send 失败取最深一层原因（"connection refused" 类传输诊断，无 URL）重写文案（`:339`）；重定向 ≤10 跳、跨主机敏感头由 reqwest 内建剥离、不合并原查询串到新 Location。**摘要口径**——`FetchResult::content_digest`（fetcher `:157`，SHA-256 与快照 `content_hash` 同源）只证明内容一致；来源可信由传输或 `set_expected_digest`（`:185`）预置摘要比对另行约束，不符 = 终态失败不发布且进退避。
  验收证据：`bad_content_keeps_old_snapshot_and_enters_backoff`（`provider_fetch.rs:478`：BAD 载荷 → Parse 错误、旧快照 hash/对象数不变、fail_count=1 入账本、退避期内二刷 BackoffGate 未发起网络、过期后放行）；`oversize_rejected_and_snapshot_kept`（`:526`：64B 体超 32B 上限 → Fetch 错误「订阅内容过大」、快照不变）；`network_down_never_publishes`（`:571`：连接拒绝重试耗尽 → 快照不变、进退避）；`conditional_get_304_skips_parse`（`:614`：二刷携带 If-None-Match "v1"、服务端 304 → Unchanged、解析器调用数 0）；`cancellation_stops_inflight_download`（`:710`：hold 5s 在途下载取消后 <2s 返回 Canceled、不记摘要）；`concurrency_cap_respected`（`:743`：8 并发下载、服务端观测同时在线 ≤2）；`preset_digest_mismatch_rejects_publish`（`:811`：预置不符 → 拒发布 store 无快照、解除后发布且账本记下内容摘要）；`backoff_delay_grows_and_caps`（`:849`：1s/2s/4s/8s→60s 封顶）；`failure_messages_do_not_leak_credentials`（`:873`：口令与 token 不入失败文案与退避门文案）；`redact_url_masks_credentials`（fetcher `:632`：userinfo 剥离、凭证键打码、端口路径保留）。全量绿：subscription 122（97 lib + 8 guardrails + 12 dsl + 6 samples——lib 增 10 测）、workspace 57 组 803 全过；`cargo clippy -p rillane-subscription --all-targets --all-features -- -D warnings` 干净。
  边界：控制面把 ProviderFetcher 接进刷新循环、声明→载荷→`provider_nodes`/`rule_sets` 库的发布装配归 RIL-019（在此之前 `degraded_providers` 报告仍准确）；预置摘要的配置面字段（decl 上加 digest）待用户拍板后再挂；attempt 内退避沿用 fetcher 既有终态/瞬时分类（4xx 终态不重试、408/429/5xx 可重试）。
- [ ] **RIL-011｜P0｜select 选择保真**；依赖：RIL-009。
  交付：嵌套组引用和用户选择持久化。验收：更新不随意清空有效选择，删除所选节点产生明确恢复策略；组循环拒绝。
- [ ] **RIL-012｜P0｜url-test/fallback 语义**；依赖：RIL-009。
  交付：探测参数及按顺序回退，修复 fallback 映射 Random。验收：单位、迟滞/健康状态可核验，故障优先级符合样本，不能随机替代回退。
- [ ] **RIL-013｜P0｜load-balance 与不支持组**；依赖：RIL-009。
  交付：支持的分配算法与 relay/chain 支持表。验收：会话选择可重现；无法保真的 relay 明确拒绝，不能映射成 ConsistentHash。
- [x] **RIL-014｜P0｜规则集与顺序**；依赖：RIL-007、RIL-008。（2026-11-15 完成）
  交付：**规则面**——`rillane-config` `MatchCondition` 增三变体：`SrcPort`（源端口，经 `net.src_port` 注解面求值，与目标端口 `Port` 语义严格分离——修掉导入链 SRC-PORT 折进目标端口的混淆 bug）、`Proto`（传输协议，逻辑规则 `NETWORK,<proto>` 子条件落此）、`RuleSetRef`（命名规则集引用，按 `routing.rule_sets` 库解析，库中无此名恒不命中——与 GeoSite 缺库同语义不伪装命中）；`RuleSetLibrary`/`RuleSetEntry`（平铺 serde 名字→条件映射）与 `RuleProviderDecl`（type/behavior/format/url/path/interval_secs 声明面）挂 `RoutingConfig`（serde default，空面不落盘），`validate` 递归校验引用名非空。**求值面**——rillane-routing `matches_condition` 三新臂（SrcPort 注解三态/Proto 大小写不敏感/RuleSetRef 递归库解析），规则按数组序首匹配（route 注释钉住），热更随 `RoutingConfig` 整体换库。**导入面**——rillane-subscription：ClashConfig 捕获 `rule-providers` 声明（原解析期静默丢弃）；RULE-SET → RuleSetRef 且**引用可追踪**（未声明 provider 显式进损失清单/严格拒，不产生悬空引用）；声明落 `routing.rule_providers`（Clash interval 即秒原样）；逻辑规则 AND/OR/NOT 括号感知解析（嵌套逗号安全，子条件无 target 补占位）——AND 平铺进 matches、OR→Any、NOT→Not，OR/NOT 内嵌套 AND 显式拒绝不伪装；未知规则类型改 `Unknown` 变体保留原文（解析期不炸整份配置），转换期显式进损失清单；规则集载荷解析 `parse_rule_provider_payload(behavior, format, text)`（yaml payload 列表/text 行格式，behavior 域校验 domain/ipcidr/classical 越域点名拒绝）。**导出面**——clash_export：SRC-PORT/RULE-SET 回导出往返保真，rule-providers 声明块随文档导出，Proto 无独立 Clash 形态登记具体原因不静默。**文档**——subscription-support.md（en/zh）L3 规则表更新（RULE-SET ⏳→✅ 引用策略、逻辑规则 ✅、SRC-PORT/DST-PORT/NETWORK 新行）。验收证据：config `ruleset_and_port_conditions_roundtrip`（三新变体+声明+库 serde 往返、空面不落盘）；routing 3 新测（src_port 注解命中/不命中/缺席三态且目标端口值不串入、proto tcp/udp 分立、rule_set_ref 库解析+悬空不 panic+首匹配顺序+库内 DomainFull 不含子域语义保持）；subscription 6 新测（src/dst 端口分立回归、RULE-SET 引用追踪+未声明清单+严格拒+声明面断言、逻辑 AND/OR/NOT 展开顺序 rule-1..4+MATCH 最后、未知条件整条显式清单不做部分吸收、嵌套 AND 点名拒绝、载荷 yaml/text/behavior 越域/未知类型）；samples 新样本 `ruleset_logic.yaml` + 零损失断言（顺序/引用/声明/interval 秒口径）。全量绿：config 87、subscription 85 lib+8 guardrails+12 dsl+6 samples、routing 29 lib+10 集成、runtime 175+2；`cargo clippy -p rillane-config -p rillane-routing -p rillane-subscription --all-targets --all-features -- -D warnings` 干净。边界：载荷下载/缓存/退避归 RIL-010（parse fn 已就绪待接）、PROCESS-NAME 规范映射归 RIL-015、库的控制面装配（快照→库发布）归 RIL-019、TUN 侧 `net.src_port` 注入归 RIL-029。commit：见 git log `feat: add ruleset references and logic rules`。
- [x] **RIL-015｜P0｜进程规则转换**；依赖：RIL-005、RIL-014。（2026-11-15 完成）
  交付：PROCESS-NAME/路径等字段到规范条件的映射。验收：大小写/名称/路径语义独立；无平台能力时按明确模式拒绝或显式降级并报告。
  交付：**规范条件面**——`rillane-config` `MatchCondition` 增 `ProcessPath{values}` 变体（`crates/rillane-config/src/lib.rs:2424`，完整可执行路径经 `process.path` 注解求值），与 `Process{values}`（`/proc/<pid>/comm` 口径短名，`process.name` 注解）**语义严格分离**：路径含分隔符全串比较、不做 comm 截断；两者均**精确区分大小写不折叠**（`Process` 文档补注大小写语义，`crates/rillane-config/src/lib.rs:2413`）。**求值面**——rillane-routing 增 `ProcessPath` 臂读 `process.path` 注解（`crates/rillane-routing/src/lib.rs:1001`），三态钉死：全串相等命中 / 仅短名不冒充路径 / 大小写不同不命中 / 注解缺席恒不命中（`Process` 臂同补大小写不命中断言 `:1317`）。**导入面**——rillane-subscription：`ClashRule`/`ClashRuleTagged` 增 `ProcessPath{paths,target}`（`:549`/`:641`），`parse_rule_string` 增 `PROCESS-PATH` 臂（`:779`），规则集载荷 classical 面同增（`:1046`）；`convert_clash_rule` 由「进程名规则暂不支持」硬拒改为**转换保留**：`PROCESS-NAME`→`Process`、`PROCESS-PATH`→`ProcessPath`（`:2006`/`:2014`）。**显式降级**——`ConversionReport` 增 `degraded_rules: Vec<(规则名, 降级说明)>`（`:1170`）：含进程条件的规则转换保留但逐条登记「依赖 TUN 入口进程归因，非 TUN 流与归因不可得平台恒不命中；comm 可能截断，路径不可得不以短名冒充」（`:1904`）；接入 `is_empty`（`:1182`，故严格模式对含进程规则的配置不再「全绿」）、`summary` 出「降级规则 N 条:」（`:1217`）、`diagnostics` 桥为 `compat.lossy` 定位 `rules/<名>`（`:1269`）——**有损但保留 ≠ 不支持**，与 `dropped_rules` 的 `compat.unsupported` 分立。**导出面**——clash_export 增 `ProcessPath` 臂回导出 `PROCESS-PATH,<path>,<target>`（`crates/rillane-subscription/src/clash_export.rs:685`），往返保真不混写。
  验收证据：routing `process_path_condition_matches_full_path_exactly`（命中/短名不冒充/大小写不命中/注解缺席四态，`crates/rillane-routing/src/lib.rs:1339`）+ `process_condition_matches_on_process_name_annotation` 补 comm 大小写不命中断言（`:1317`）；subscription `process_rules_convert_and_report_degraded`（`crates/rillane-subscription/src/clash.rs:3572`：两条规则都转换保留、matches 分别为 Process/ProcessPath、dropped 0、degraded_rules=["rule-1","rule-2"] 点名、summary「降级规则 2 条」、diagnostics 定位 `rules/rule-1`）；clash_export `process_conditions_export_distinct_kinds`（`:960` 两种形态独立回写、skipped 空）。既有断言随语义修正：`clash_guardrails::unsupported_rules_reported_and_strict_rejected`（进程规则不再严格拒，dropped 1 / rules 2 / degraded=["rule-1"]）、`clash_guardrails::report_summary_renders_counts_and_names`（「跳过规则 1 条」→「降级规则 1 条」）、`subscription_samples::negative_lossy_reports_every_expected_loss`（dropped_rules=["rule-2"] 仅未声明引用、degraded_rules=["rule-1"]、保留规则 2→3、诊断计数含降级项、rule-1 诊断码 `compat.lossy` 而非 `compat.unsupported`）。文档：subscription-support.md（en/zh）L3 规则表 PROCESS 行 ❌→✅ 并注明引擎降级口径与「不以短名冒充路径」；subscription.md rules 映射行同步。
  全量绿：config 88、routing 40、subscription 113（87 lib + 8 guardrails + 12 dsl + 6 samples）、runtime 177；`cargo clippy -p rillane-config -p rillane-routing -p rillane-subscription --all-targets --all-features -- -D warnings` 干净。
  边界：`process.path` 注解的实际注入（OwnerResolver 三桌面身份查询、comm 截断处理）归 RIL-029/RIL-030/RIL-034/RIL-038；规则集载荷下载归 RIL-010。
  排障记一笔：本轮一度出现「`ProcessPath` 变体不存在」的幽灵编译错——共享 target 里同一 crate 累积了多份不同 feature hash 的 rmeta，unified 构建（`cargo test -p A -p B`）命中编辑前的陈旧 rmeta 判 Fresh；`cargo clean -p rillane-config` 后即恢复。单包构建不复现。
  commit：见 git log `feat: map process rules to canonical conditions`。
- [ ] **RIL-016｜P0｜本地策略所有权**；依赖：RIL-011、RIL-012、RIL-013、RIL-014、RIL-015。
  交付：nodes-only/full-policy、本地优先级及来源命名空间。验收：刷新不覆盖用户游戏规则、监听口、系统路由、插件或管理凭证；关键有损转换拒绝候选。
- [ ] **RIL-017｜P0｜旧 profile 迁移**；依赖：RIL-006、RIL-016。
  交付：proxy/game/web 预设展开到并列 ScenarioPolicy。验收：旧配置可读，有迁移诊断；新配置可同时声明 game/web，不能仍由单一互斥枚举控制。

## 3. 发布事务与共享数据面

- [x] **RIL-018｜P0｜系统副作用计划/补偿**；依赖：RIL-003、RIL-004。（2026-11-15 完成）
  交付：`crates/rillane-platform/src/network/side_effects.rs` 新增 `SideEffectJournal`（side_effects.rs:139）——路由/DNS/防火墙统一变更日志：`record_pre_existing`（:151，启动前既有系统配置只登记审计，恒无撤销动作）、`record_owned`（:165，apply 成功一步记一步，失败步骤从不入日志）、`rollback_plan`（:207，本实例 Owned 条目**逆序**撤销计划，后进先撤销保依赖安全）、`undo_entry`（:218，单条撤销，非本人条目拒绝）。所有权模型 `Ownership`（:44，Owned/PreExisting）；撤销动作 `InverseChange`（:54）显式携带不反推、全部幂等（目标不存在视为已撤销；DNS 撤销是 `RestoreDns` **还原先前内容而非删除**，None=还原系统默认）；稳定原因码 `side_effect.foreign`/`side_effect.unknown`（:15/:17，越权撤销与未知条目机器口径拒绝）；`SystemArea`（:21）route/dns/firewall `as_str` 恒定。纯契约零 OS 调用——Linux argv 构造与执行仍在 `linux.rs`，TUN 逃逸面现有 `AppliedStep` 日志归 RIL-019 配置发布协调器接线收敛。验收证据：side_effects.rs 6 单测全绿——撤销计划只含本实例 Owned 且逆序（PreExisting 不出现、序号单调）；PreExisting 撤销以 foreign 码拒绝且计划为空；双实例场景 a 的计划不含 b 条目、越权撤销 foreign 码拒绝、本人可撤销、未知条目 unknown 码；模拟 step1/2 成功 step3 失败（从未入日志）后回滚计划只含已成功条目；DNS 还原语义（Some 内容与 None 系统默认）不删除；area 字符串恒定。rillane-platform lib 71 测全绿、`cargo clippy -p rillane-platform --lib --all-features -- -D warnings` 干净。文档同步：docs/architecture.md（en/zh）平台行与控制更新节。commit：见 git log `feat: add side effect journal contract`。
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
- [x] **RIL-026｜P0｜类型化质量样本**；依赖：RIL-006。（2026-11-15 完成）
  交付：`crates/rillane-core/src/quality.rs` 新增 `QualitySample`（quality.rs:169，metric/source/target/count/time/validity 全字段；不实现 `Default`——「无测量=0.0=完美」是要消灭的反模式）与五类指标 `QualityMetric`（:31，handshake_ms/rtt_ms/connection_failure_ratio/packet_loss_ratio/throughput_mbps，`as_str` 恒定）、四类来源 `SampleSource`（:60，probe/dial_outcome/mesh_link/manual——同名字段语义随来源变化）、类型化值 `SampleValue`（:85，Latency p50/p95、Ratio 显式分子分母、Throughput）、状态 `SampleStatus`（:123，Current/Expired{age_ms}/Unknown）。构造入口 `latency`/`connection_failures`（:210）/`packet_loss`（:235，**测量对端必填**，空则拒绝）/`throughput`/`migrate_legacy_loss`（:288，当前指标迁移——拨号/探活来源旧 `packet_loss_rate` 改名迁移为连接失败率；mesh 链路来源保留丢包率但缺对端说明拒绝；比率万分比显式化）。未知/过期不当零：`status`（:375，age>lifetime 显式过期、分母 0 显式未知、时钟回拨按有效处理）+ `ratio_value`（:396，过期/未知以稳定码报错绝不回 0.0）+ 稳定原因码 `quality.expired`/`quality.unknown`/`quality.peer.missing`（quality.rs:23/25/27）。吞吐 0 是显式测得非缺失。验收证据：quality.rs 5 单测全绿——失败率是独立指标（as_str=connection_failure_ratio）且 3/10→0.3；分母 0 → unknown 码、超期 5s → expired 码带 age_ms、边界 age==lifetime 仍有效、非比率取比率 → unknown；丢包样本缺对端构造拒绝、带对端可查；迁移按来源改名（DialOutcome/Probe→connection_failure_ratio、MeshLink 缺对端 peer.missing 码拒绝、带对端保留 packet_loss_ratio、越界 7.5 收敛 1.0、Manual 来源拒绝不猜语义）。rillane-core 91 测全绿、`cargo clippy -p rillane-core --all-targets --all-features -- -D warnings` 干净。接线边界：mesh/chain 消费侧迁移归 RIL-027（rillane-mesh 不依赖 rillane-core，迁移入口在本模块供消费方调用）。文档同步：docs/architecture.md（en/zh）。commit：见 git log `feat: add typed quality samples`。
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
- [ ] **RIL-032｜P0｜Windows 技术探针**【BLOCKED 2026-11-15】缺 Windows 真机/虚拟机：Wintun 安装、WFP-ALE 归属查询与原型防环都需在 Windows 上实测，本机（Linux）无法产出验收要求的「Windows 上 TCP/UDP 本机归因和防环证据」；有环境后立即执行。
  交付：Wintun、公开归属查询/WFP-ALE 的实测选型记录及最低版本/权限。验收：Windows 上展示 TCP/UDP 本机归因和原型防环证据，记录不可用字段。
- [ ] **RIL-033｜P1｜Windows 接管/旁路实现**；依赖：RIL-018、RIL-020、RIL-032。
  交付：packet I/O、双栈路由/DNS 和旁路。验收：真实浏览器/游戏流进入共享内核，DNS/代理拨号不循环，失败可补偿。
- [ ] **RIL-034｜P1｜Windows 进程适配**；依赖：RIL-015、RIL-032、RIL-033。
  交付：正式 OwnerResolver 和身份缓存。验收：同目标多进程、UDP、进程退出/端口复用/权限失败，unknown 策略均有真机证据。
- [ ] **RIL-035｜P1｜Windows 服务与退出恢复**；依赖：RIL-019、RIL-033、RIL-034。
  交付：SCM/权限、驱动依赖校验、安装/卸载恢复。验收：服务崩溃、休眠、切网和卸载不遗留路由/DNS；签名和依赖限制公开。
- [ ] **RIL-036｜P0｜macOS 技术探针**【BLOCKED 2026-11-15】缺 macOS 真机：接管方案、helper/extension 边界、签名 entitlement 均需真机验证身份可得性与发布约束（CI macOS runner 只能编译不能装 profile/签名验收），无法产出验收要求的「真机验证缺口记录」；有设备后立即执行。
  交付：公开接管/本机身份方案、helper/extension 边界和签名 entitlement 记录。验收：真机验证所需身份可得性与发布约束，缺口明确，不靠私有 fd。
- [ ] **RIL-037｜P1｜macOS 接管与旁路**；依赖：RIL-018、RIL-020、RIL-036。
  交付：选定公开接口的数据面和路由/DNS 补偿。验收：双栈 TCP/UDP/QUIC、DNS、MTU 和系统代理共存；权限失败不半接管。
- [ ] **RIL-038｜P1｜macOS 本机身份**；依赖：RIL-015、RIL-036、RIL-037。
  交付：生产 OwnerResolver 与匹配适配。验收：同目标两本机应用分别出站、身份变化和权限失败有明确结果；不能用仅能接管证明可归因。
- [ ] **RIL-039｜P1｜macOS 宿主与恢复**；依赖：RIL-019、RIL-037、RIL-038。
  交付：签名宿主/辅助组件生命周期、升级及网络恢复。验收：授权拒绝、睡眠/唤醒、切网、退出与卸载在真机恢复系统状态。
- [x] **RIL-040｜P0｜最小构建依赖裁剪**；依赖：RIL-004。（2026-11-15 完成）
  交付：runtime `plugins` feature（crates/rillane-runtime/Cargo.toml:6-14，default=["plugins"] 即 full 档挂 wasmtime/JIT；`small`/`mobile` 标记位；rillane-plugins 改 optional）+ 三档位下游接线（apps/rillaned、apps/rillanectl features：default=["full"]，full=["rillane-runtime/plugins"]，small/mobile=[]，两 app 均对 runtime `default-features=false`；crates/rillane-ffi：mobile=["rillane-runtime/small"]——移动 cdylib 档依赖图无 wasmtime）+ 装配分侧（obfs_config.rs:297-308 `build_middleware_chain` 按 cfg 分派 `build_middleware_chain_with_plugins`/`build_middleware_chain_small`；共享 `builtin_middlewares` 提取；small 档 `obfuscation.plugins` 非空 → 配置校验期点名硬错误，稳定码 `config.combo.unsupported`（obfs_config.rs:359-377）——不是隐藏配置入口）+ runtime 插件面随档位缺席（runtime_builder.rs：`plugin_middlewares` 字段/初始化/`get_plugin_stats` 均 `#[cfg(feature = "plugins")]`）+ 控制面形态稳定（control_plane.rs：`/plugins/stats` 路由恒 200——full 取 getter 数据，small 恒空表，TUN「恒渲染、数据源门控」同口径；DTO 不门控）+ CI 守门（ci.yml 新增 `small` job：三档 `cargo check` + rillaned small 依赖图 wasmtime 计数==0 断言——test job `--all-features` 恒开 plugins 看不见 small cfg 分支）。验收证据：`cargo test -p rillane-runtime --lib` 默认档 175 测全绿、`--no-default-features --features small` 同 175 全绿（标准订阅/共享转发/内置混淆链不依赖 wasmtime 的回归面）；obfs_config 14 测两档各自全绿（plugins 档含 `build_chain_appends_plugins_after_builtins`；small 档新增 `small_mode_rejects_plugin_declarations`：plugins 声明 → `config.combo.unsupported` 点名拒绝 + 无声明内置链照常装配）；rillaned full 档 29+2 测全绿（含 `/plugins/stats` 空/有两侧）；`cargo tree -p rillaned --no-default-features --features small -e normal` wasmtime 命中 **0**、ffi mobile 同口径 **0**；rillaned/ffi/ctl small·mobile 档 `cargo check` 零错误；clippy 两档 `-D warnings` 干净（仅存量 manifest 提示：workspace `serde_urlencoded` 未用、runtime `notify` 在 HEAD 已无引用——均先于本任务存在，不属本项范围）；fmt 全净。文档同步：docs/architecture.md、docs/mesh.md（en/zh）。commit：见 git log `feat: add small build feature pruning`。
- [ ] **RIL-041｜P1｜OpenWrt 网关接线**；依赖：RIL-019、RIL-029、RIL-040。
  交付：musl 包、fw4/nftables 共存和 LAN/本机策略。验收：设备/IP/域名/端口、IPv4/IPv6、DNS 与 UDP 工作，不要求客户端 PID。
- [ ] **RIL-042｜P1｜OpenWrt 运维与资源**；依赖：RIL-041。
  交付：procd、配置更新恢复、低内存默认预算。验收：路由器启停/升级/断网恢复，测得 RSS/CPU/吞吐上限；不支持的架构明确列出。
- [ ] **RIL-094｜P0｜iOS 公开 packetFlow 早期探针**【BLOCKED 2026-11-15】缺 iOS 签名开发设备与开发者账号：packetFlow 批量 read/write、缓冲所有权、吞吐/RSS 实验必须在签名设备上跑 Network Extension，模拟器不加载扩展；无法产出「不依赖私有 fd」的实测结论；有签名设备后立即执行（结论反哺 RIL-043）。
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

交付顺序：真实连接列表 → 逐连接时间线 → 规则解释 → 主动探测。先准备共用契约与脱敏；Trace CLI 可先于 Explain 发布，只读 MCP 不等待主动探测或 GUI。字段与复现要求见 [链路诊断实施规格](docs/zh/design/debug-and-mcp.md)。

- [ ] **RIL-051｜P0｜诊断与事件 Schema**；依赖：RIL-002、RIL-006、RIL-026。
  交付：FlowTrace/TraceEvent、原因码、generation/flow/attempt ID、时间与证据类型。验收：预测/观测/推断/未知互不混淆，schema 版本与兼容规则明确。
- [ ] **RIL-052｜P0｜有界事件采集器**；依赖：RIL-024、RIL-051。
  交付：环形缓冲、TTL、采样、每流上限和订阅背压。验收：慢消费者/满缓冲不阻塞数据面，丢事件计数可见，关闭追踪不影响转发。
- [ ] **RIL-053｜P0｜真实流生命周期埋点**；依赖：RIL-020、RIL-022、RIL-052。
  交付：接管、身份、DNS、规则、选组、拨号尝试、实际出口与关闭事件。验收：A 失败改拨 B 可完整解释；UDP association 与 TCP 的起止语义明确；网页阶段耗时区分 HTTP TTFB 与首个下行字节，游戏记录映射/队列/切网，缺少测量证据不生成 RTT/丢包。
- [ ] **RIL-054｜P0｜纯 Explain 服务**；依赖：RIL-021、RIL-027、RIL-051。
  交付：使用生产求值器、固定配置/质量快照的规则推演。验收：无 DNS/拨号/OS 身份查询，证据缺失返回条件性结果，输入快照可离线重放。
- [ ] **RIL-055｜P0｜逐连接查询服务**；依赖：RIL-053。
  交付：活动/近期连接分页、过滤、流详情和事件读取。验收：超限/过期/未知 ID 明确返回；不能把 ingress-egress 聚合 ID 当真实 flow ID；无记录时可查接管/旁路/入口及采集计数，不能直接判定应用未发包。
- [ ] **RIL-056｜P0｜兼容连接视图修正**；依赖：RIL-055。
  交付：兼容 `/connections` 的真实字段映射与可用性说明。验收：缺失时间、域名、链路不能伪造；旧聚合 API 保持明确独立语义。
- [ ] **RIL-057｜P0｜DiagnosticView 脱敏边界**；依赖：RIL-051。
  交付：结构化字段白名单、别名、详细身份范围及错误路径过滤。验收：URL token/密码/私钥/运行配置不外泄，日志/名称按不可信文本处理。
- [ ] **RIL-058｜P0｜diagnose 安全导出**；依赖：RIL-055、RIL-057。
  交付：按范围选择快照、日志和配置，默认安全的包清单。验收：检查 runtime_config/subscriptions/错误日志全部出口；现有原始包不自动传给模型。
- [ ] **RIL-059｜P1｜主动探测作业服务**；依赖：RIL-026、RIL-051、RIL-057。
  交付：DNS/connect/代理握手/支持的 UDP 回显作业。验收：目标范围、并发/流量限额、超时、取消生效；只读调用不隐式探测，不允许不可信文本扩展目标。
- [ ] **RIL-060｜P0｜Explain/Trace CLI**；依赖：RIL-054、RIL-055、RIL-057。
  交付：分批交付 Trace CLI、Explain CLI，冻结语法、文本/版本化 JSON 与退出码；Trace 阶段不等待 Explain。验收：同一代际的规则来源、计划与实际差异可查；现有 Mesh dry-run 不冒充普通规则解释。
- [ ] **RIL-061｜P1｜Probe CLI**；依赖：RIL-059、RIL-060。
  交付：显式发起/取消和结果展示。验收：网络副作用、目标和测量类型可见；失败率/RTT/丢包分别标记，不推断机场内部路径。
- [ ] **RIL-062｜P1｜路径图导出**；依赖：RIL-060。
  交付：从共享只读服务导出 SVG，标注路径层、时间与缺口。验收：计划/连接/Mesh/L3 不混画，长文本/恶意名称安全转义，图与 JSON 内容一致。
- [ ] **RIL-063｜P2｜交互路径检查入口**；依赖：RIL-055、RIL-057、RIL-062。
  交付：现有管理界面的连接筛选、逐段展开与配置来源定位。验收：不重复实现路由器，分页/断连/无权限/丢事件有明确状态，详细身份由权限控制。
- [ ] **RIL-064｜P1｜诊断开销与留存验证**；依赖：RIL-052、RIL-058。
  交付：默认上限与关闭/采样/全量的对照报告。验收：高并发下 CPU/RSS/尾延迟有证据，历史可过期/删除，指标标签不含高基数身份或秘密。

## 6. 可选只读 MCP

- [ ] **RIL-065｜P1｜共享应用服务边界**；依赖：RIL-054、RIL-055、RIL-057。
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

## 10. 接入、出口与统计契约细化

本组是现有基础类型上的后续设计与迁移，不重置已完成任务。实施依据：[IO 与统计契约](docs/zh/design/io-and-accounting.md)。

- [ ] **RIL-096｜P0｜入口两阶段接入契约**；依赖：RIL-004、RIL-006。
  交付：InboundSpec/Factory、PendingStream/Responder、UDP/TUN 适配契约及资源所有权。验收：认证/解析与路由分开；出口成功后才回复成功，reject/accept 一次性消费；取消或回复失败无泄漏，TUN 不套用代理回复模型。
- [x] **RIL-097｜P0｜出口建立通道契约**；依赖：RIL-006。（2026-11-15 完成）
  交付：`crates/rillane-core/src/outbound.rs` 新增 `StreamOutbound`（:489）/`DatagramOutbound`（:506）两条出口建立契约——`open_stream(target, ctx)` 返回已建立通道，业务 IO 在通道句柄里，出口只在建立期出现一次；`OpenContext`（:203）携带 session_id/attempt_id/`GenerationRef`（代际取自 RIL-006 `plan` 模块）/绝对截止时间/取消信号/拨号策略不透明引用，**不持有可重新求值的路由器**（io-and-accounting.md §2），`check_openable`（:260）把取消与到期统一按不可重试失败在建立前拦下（时钟由调用方注入，本模块不依赖时钟）；`OpenedStream`（:275）/`OpenedAssociation`（:284）持有协议包装后的 IO 与握手结果，加密/分帧状态随 IO 生命周期，唯一消费入口是 `into_parts`（:359/:425）——不单独暴露分帧器；`TargetBinding`（:433）区分 `Fixed`/`Multi` 两种数据报绑定形态，`allows`（:448）固定目标精确匹配、多目标空集合=实现自决；`max_datagram_len`/`idle_timeout_ms` 显式携带；`OpenError`（:94）分阶段（`OpenStage` :28：dial/transport/handshake/pool）携带稳定原因码（6 个 `CODE_OPEN_*` :78-88）、可重试性、证据类型（`EvidenceKind` :54：预测/观测/推断/未知）与已脱敏上下文；`OutboundCapabilities`（:524）静态能力声明供装配期校验。TCP 字节流与 UDP 数据报在类型层面分侧（`StreamOutbound`/`DatagramOutbound`、`StreamIo`/`DatagramIo`），不共用一次 TCP 式路由决策。「先适配当前接口」：直接复用内核既有 `plan::EndpointRef`/`GenerationRef`，零新增外部依赖、零 rillane-* 依赖（内核独立保持）。验收证据：`tests/outbound_contract.rs` 4 测全绿（①建立与搬运分开——`transport`/`handshake_ms` 随通道持有，`into_parts` 取走 IO 后原句柄消失且 attempts==1；②一次建立只尝试一次——`fail_open` 立即返回 `CODE_OPEN_TIMEOUT`@Handshake，attempts 不自行二次增长，回退归会话执行器；③取消/到期在建立期拦下——`CODE_OPEN_CANCELLED`、retryable=false、**attempts==0**（未开始工作不计尝试）；④TCP/UDP 分侧——assoc `max_datagram_len`/`idle_timeout_ms` 显式，`Fixed` 拒陌生目标、`Multi` 空集合放行全部）；outbound.rs 5 单测（空会话拒绝+代际绑定；到期与取消不可重试；阶段/码/证据入文案；目标绑定语义；能力形态）。rillane-core 100 测全绿（含 lib 38）、`cargo clippy -p rillane-core --all-targets --all-features -- -D warnings` 干净（退出 0，仅余与本次改动无关的 workspace `serde_urlencoded` 提示）、`cargo fmt -p rillane-core -- --check` 干净、Cargo.toml 零 rillane-* 依赖。docs/architecture.md 与 docs/zh/architecture.md 的 rillane-core 行与叙述段同步。commit：见 git log `feat: add outbound establishment contract`。
- [ ] **RIL-098｜P0｜会话执行器统一接线**；依赖：RIL-096、RIL-097、RIL-022。
  交付：接入确认、出口尝试、转发、半关闭、取消、背压和计划内回退的一条权威执行路径。验收：TCP/UDP 使用不同生命周期；A 失败 B 成功可追踪，业务交换后不盲目重放；旧入口/出口适配不留下第二套选路/统计实现。
- [ ] **RIL-099｜P0｜拨号与传输组合边界**；依赖：RIL-004、RIL-097。
  交付：UnderlayDialer 与 TLS/WS/gRPC/HTTPUpgrade 的合法装配及平台旁路注入。验收：协议类不复制 DNS/旁路逻辑；非法排列拒绝，QUIC/WireGuard 可持有原生资源，不被强制转换为普通 TCP wrapper。 外部库自建 socket 也须可施加平台旁路；无法注入或保证防环的组合明确拒绝。
- [ ] **RIL-100｜P0｜能力声明与池资源类型**；依赖：RIL-097、RIL-099、RIL-024。
  交付：同源能力描述、预热消费/独占目标绑定/多路复用资源类型和租借键。验收：支持表不在 importer/runtime/connector 重复维护；不同身份/凭证/代际隔离，取消/drain 有所有者，TLS 恢复不等于连接复用。 后端能力按实际依赖和配置声明，重依赖可按 feature/crate 排除；先核实平台、维护与许可证要求。
- [ ] **RIL-101｜P0｜TrafficMeter 权威业务计数**；依赖：RIL-098、RIL-024。
  交付：业务通道计数、入口/出口归属、底层开销和 traffic_origin 分类。验收：客户端方向一致，部分写/重试不重复，零长 UDP 计报文；A 失败 B 承载不重复业务量；probe/prewarm 不混用户业务，共享开销不可精确归因时明确标记。
- [ ] **RIL-102｜P0｜SessionObserver 分阶段事件**；依赖：RIL-051、RIL-052、RIL-098、RIL-101。
  交付：统一 session/attempt/generation 关联及接入/握手/回退/关闭事件。验收：高频字节走计数器，不每次读写分配事件；慢消费者和关闭观测不影响转发，高基数身份不进指标标签，CLI/MCP 复用诊断视图。
- [ ] **RIL-103｜P1｜IO 与统计对账验收**；依赖：RIL-099、RIL-100、RIL-101、RIL-102、RIL-057。
  交付：入口/协议/传输组合矩阵、会话权威总量与入口/出口归属对账及资源关闭证据。验收：成功/拒绝/半关闭/取消/UDP 多目标/池隔离全部覆盖；业务与底层分别报告，不用两端相加作总量，不把发送成功当远端接收。 外部库后端需验证取消/线程/缓冲所有权、内部重试与会话回退一致，以及业务统计等价性；不可得诊断字段明确未知。

## 11. 外部实现复用与协议覆盖

统一依据：[协议接入计划](docs/zh/design/protocol-roadmap.md)。只在有检索/评估证据确认无可用实现时自写；优先适配、贡献上游或最小补丁，不能以包装不方便为由重写。P2 候选可延期，均不作为已有基础里程碑的额外发布锁。每项先选择后端，再交付该项方向/版本的适配，缺资源或后端保持未完成。

- [ ] **RIL-104｜P1｜协议注册与选库证据契约**；依赖：RIL-097、RIL-100。
  交付：协议目录/Factory 注册规范、feature 裁剪及后端评估记录模板。验收：记录候选库版本、许可、平台、公开 API、旁路/取消/统计与复用结论；无实现证据是自写前置，未审核配置不能直接进热路径。
- [ ] **RIL-105｜P1｜TUIC 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；v4/v5 分别核验，不静默互换；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-106｜P1｜AnyTLS 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；复用与 UDP 表达按库实际能力；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-107｜P1｜REALITY 接入与验收**；依赖：RIL-104。
  交付：安全握手扩展；先客户端，服务端按选库能力另验；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-108｜P1｜XTLS Vision 接入与验收**；依赖：RIL-104。
  交付：VLESS 流控/分帧扩展；与 REALITY 独立验收；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-109｜P2｜Hysteria v1 接入与验收**；依赖：RIL-104。
  交付：兼容协议客户端/服务端；保留版本和参数边界；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-110｜P2｜ShadowTLS 接入与验收**；依赖：RIL-104。
  交付：承载/握手组件；明确后续代理协议组合；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-111｜P2｜Snell 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；逐版本与 UDP 能力核验；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-112｜P2｜NaiveProxy 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；HTTP/TLS 与平台构建要求；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-113｜P2｜SSH 接入与验收**；依赖：RIL-104。
  交付：出站隧道；认证、host key 与连接生命周期；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-114｜P2｜Tor 接入与验收**；依赖：RIL-104。
  交付：出站后端；嵌入或受管实例，身份与资源生命周期；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-115｜P2｜ShadowsocksR 接入与验收**；依赖：RIL-104。
  交付：出站兼容；cipher/obfs/protocol 组合；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-116｜P2｜Mieru 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；认证与 TCP/UDP 能力；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-117｜P2｜Sudoku 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；版本、密码学参数与传输；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-118｜P2｜ShadowQUIC 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；QUIC 与数据报能力；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-119｜P2｜TrustTunnel 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；TLS、认证与数据报能力；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-120｜P2｜MASQUE 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端；CONNECT-UDP/IP 分别核验；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-121｜P2｜OpenConnect 接入与验收**；依赖：RIL-104。
  交付：客户端 endpoint；路由/DNS 与凭证集成；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-122｜P2｜OpenVPN 接入与验收**；依赖：RIL-104。
  交付：客户端/服务端 endpoint；模式与平台能力；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-123｜P2｜Tailscale 接入与验收**；依赖：RIL-104。
  交付：双向 endpoint；身份、控制连接与路由边界；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-124｜P2｜ZeroTier 接入与验收**；依赖：RIL-104。
  交付：组网 endpoint；授权、虚拟网络与退出恢复；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-125｜P2｜EasyTier 接入与验收**；依赖：RIL-104。
  交付：组网 endpoint；节点生命周期与路由所有权；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-126｜P2｜Gost Relay 接入与验收**；依赖：RIL-104。
  交付：出站兼容；区别于策略组 relay；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-127｜P2｜Tailcat 接入与验收**；依赖：RIL-104。
  交付：入口/出口；先核实具体上游版本和实现可复用性；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-128｜P2｜Cloudflared 接入与验收**；依赖：RIL-104。
  交付：入口隧道集成；控制/认证与服务生命周期；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-129｜P1｜XHTTP 接入与验收**；依赖：RIL-104。
  交付：传输扩展；模式、参数与具体代理组合分项核验；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-130｜P1｜公共传输与复用矩阵 接入与验收**；依赖：RIL-104。
  交付：TLS/WS/gRPC/H2/HTTPUpgrade、UoT/XUDP/多路复用；补齐实际缺口；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-131｜P1｜Shadowsocks 算法矩阵 接入与验收**；依赖：RIL-104。
  交付：核实现有库算法，包含 SS2022 候选；已有能力复用不重写；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-132｜P1｜SOCKS5 出站 UDP 接入与验收**；依赖：RIL-104。
  交付：标准 UDP ASSOCIATE 与来源验证，区别入口现有能力；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-133｜P1｜Hysteria2 UDP 接入与验收**；依赖：RIL-104。
  交付：适配具有数据报公开 API 的后端，TCP/UDP 独立验收；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-134｜P2｜Shadowsocks 服务端 接入与验收**；依赖：RIL-104。
  交付：规范 Inbound 与已有外部库接线；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-135｜P2｜Trojan 服务端 接入与验收**；依赖：RIL-104。
  交付：TLS/认证、两阶段接入与 UDP 关联；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-136｜P2｜VLESS 服务端 接入与验收**；依赖：RIL-104。
  交付：入站握手/认证、流/数据报；Vision/REALITY 组合另验；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-137｜P2｜VMess 服务端 接入与验收**；依赖：RIL-104。
  交付：AEAD 认证/重放防护与流/数据报；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-138｜P2｜Hysteria2 服务端 接入与验收**；依赖：RIL-104。
  交付：QUIC/认证/数据报与生命周期；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
- [ ] **RIL-139｜P2｜透明接管入口 接入与验收**；依赖：RIL-104。
  交付：redirect/TProxy/固定目标 tunnel；平台权限与恢复，复用现有 CapturePort；完成后端评估后，通过统一适配器提供本项能力。验收：版本/角色/合法组合明确，与真实对端验证成功、失败、取消、资源释放、统计及平台旁路；不支持组合明确拒绝，订阅涉及的字段双向转换有样本；无可用后端结论留证后才允许自写。
