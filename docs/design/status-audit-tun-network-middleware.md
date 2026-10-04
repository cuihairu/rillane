# 勘误重开条目现状核对报告：TUN / network 区块 / FlowMiddleware 动态加载

> 核对基准：2026-09-29 工作树（main @ 4e4cf6e）。方法：todo.md 勘误区与 docs/design/roadmap.md、docs/networking.md 的每条声称，逐条对照 `crates/seep-platform`（及关联 crate/app）实际代码。
> 本文只记录现状与差距，不改任何源码；由核对发现的**文档自身偏差**集中在 §4（建议后续文档轮回填，本轮不动）。

> **【2026-10-04 状态】本文为 2026-09-29 历史快照，正文保留当日原文。** 其后 P1-1/P1-2/P1-3/P1-4/P2-8/P3-2 已全部落地（c076fb8/75c7747/a9f11dc/b5785c2/7a3024d/1e1a7c0/1befbe7/750de34/955e4d6），§0–§3 多条结论已被推翻——**各节末尾的「2026-10-04 落地更新」块为准**，正文不要再当现状引用。

## 0. 结论速览

| 条目 | 勘误记录是否准确 | 核对新增发现（超出勘误记录的事实） | 2026-10-04 状态 |
|------|----------------|----------------------------------|----------------|
| ① TUN（P1-1/P1-2） | 基本准确（"runtime 未接线" ✓、无真实现 ✓） | `platform.rs` **根本未参与编译**（`network/mod.rs:21` 注释掉 `pub mod platform;`）；文件内**只有 macOS 占位**（无 Linux/Windows/Android/iOS 骨架）；且若启用**必然编译失败**（占位类型大面积缺 trait 方法）；`TunInterface` 写侧占位**假装成功并丢弃数据** | **已全部落地**（P1-1/P1-2：linux.rs 真实现 + TunIngress 接线，见 §1 更新块） |
| ② network 区块 + `seepctl route`（P1-3） | 准确（`SeepConfig` 无 network 块 ✓、seepctl 无 route 子命令 ✓） | serde 无 `deny_unknown_fields` → 用户写 `network:` 块会被**静默忽略**；`NetworkMode` 枚举命名是 `transparent` 而非计划文案的 `redir`；`RuntimeConfig.network_config` 挂钩已存在但 seepd 从不设置 | **已全部落地**（P1-3 R1–R4：schema/端点/seepctl route 齐备，B2/B4 已收口，见 §2 更新块） |
| ③ FlowMiddleware 动态加载（P3-2） | 准确（仅 LatencyProbe、无动态加载 ✓） | 差距比记录更深一层：**连静态挂载点都没有**——全仓零处调用 `FlowMiddleware::handle` / 构造 `LatencyProbe`，trait 完全游离于数据通路之外；workspace 无任何动态加载依赖 | **已全部落地**（P1-4 挂载点 + P3-2 WASM loader 与示例插件，见 §3 更新块） |

---

## 1. 条目一：TUN 真实现（todo P1-1 / P1-2；roadmap S2；networking.md）

### 1.1 文档声称

| 来源 | 声称 |
|------|------|
| todo.md 勘误区 | "实现 TunIngress/TunEgress（接入 TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel）… `seep-platform` 仅有 trait 与数据结构；**各平台 Provider 为占位实现（`platform.rs` 返回"未实现"）**；runtime 未接线 → P1" |
| roadmap.md S2 | "复用 `seep-platform::network` 已有的 `TunProvider`/`RouteManager`/`PacketFilter` trait 与 TunConfig/规则模型（**3825 行设计已成型**）"；"Windows(Wintun)/macOS(utun)/…（**platform.rs 占位已是该形状**）" |
| networking.md §1 | "`platform.rs`｜**Linux/OpenWrt/Windows/macOS/Android/iOS 各** Provider/RouteManager/PacketFilter/DnsHandler 骨架｜全部占位" |

### 1.2 代码实际

**模块编译面**：`network/mod.rs:16-21` 声明 `pub mod dns/filter/route/tun`；`platform.rs`（237 行）**不在模块树内**——`// pub mod platform;` 连同 `// TODO: 平台特定实现待完成` 一起被注释。编译进 crate 的只有 5 个文件共 **3588 行**（dns 995 + filter 1093 + mod 325 + route 646 + tun 529）；roadmap 的"3825 行"把未编译的 platform.rs 计入。

**platform.rs 现状**（死代码，磁盘存在、不参与构建）：
- 仅 5 个 **macOS** 占位类型：`MacosUtunProvider`/`MacosTapProvider`/`MacosRouteManager`/`MacosPacketFilter`/`MacosDnsHandler`——**没有任何 Linux/OpenWrt/Windows/Android/iOS 骨架**（networking.md §1 的"各平台"描述超前于文件）。
- 即便解开注释也无法通过编译（占位实现大面积缺 trait 必选方法，`#[async_trait]` 无默认实现）：

| 类型 | trait 必选方法数 | 已实现 | 缺失（关键项） |
|------|----------------|--------|----------------|
| `MacosUtunProvider` | `TunProvider` 15 | 3（read_packet/write_packet/packet_stream） | name/config/is_up/mtu/stats/create_interface/up_interface/down_interface/configure_ip/configure_routing/configure_dns/destroy_interface 共 12 |
| `MacosRouteManager` | `RouteManager` 12 | 10 | `flush_cache`、`monitor_changes` |
| `MacosPacketFilter` | `PacketFilter` 15 | 13 | `filter_packet`、`monitor_events` |
| `MacosDnsHandler` | `DnsHandler` 12 | 5 | add_server/remove_server/add_filter_rule/remove_filter_rule/clear_cache/flush_cache/monitor_events 共 7 |

**编译路径上的占位（实际生效的"未实现"）**：
- `network/mod.rs:304-325`：`create_tun_provider` / `create_route_manager` / `create_packet_filter` / `create_dns_handler` 四个工厂**恒 `Err("…平台特定实现待完成")`**——`NetworkManager::initialize()` 配置了任一子块即失败；
- `tun.rs:490-504` `create_tun_interface` 恒 `Err("平台特定的 TUN 实现未完成")`；
- `route.rs:597-646` `RouteManagerFactory::create` 与 `dns.rs:946-995` `DnsHandlerFactory::create` 对每个 `target_os` 分支恒 `Err("…待实现")`。

**占位类型有"行为"而非报错（风险点）**：`tun.rs:416-424` `TunPacketStream::poll_next` 恒 `Pending`；`tun.rs:453-487` `TunInterface` 的 `AsyncRead` 睡 1ms 返回 0 字节、`AsyncWrite` 睡 1ms 后**返回 `Ok(buf.len())` 但不落任何设备**——被误接即静默丢包。

**依赖与测试**：`seep-platform/Cargo.toml` 无任何 TUN 设备库（tokio-tun/tun-rs 类为零）；`nix`/`winapi` 为 optional 且无 feature 启用（死依赖）。全 crate **0 个测试**。

**runtime 接线面**：
- 全仓 grep `TunIngress|TunEgress` **零命中**——不存在任何 TUN ingress/egress 类型；
- `seep-runtime/src/runtime_builder.rs:165-175` 有 `NetworkManager` 条件构造（`enable_network_virtualization` + `network_config`），`start()`（598-604 行）会拉起它——**结构上接线存在**，但如上 initialize 必然失败；
- `apps/seepd/src/main.rs:33-36` 硬编码 `RuntimeConfig { enable_mesh: true, enable_chain: true, ..default }`，**从不设置** `enable_network_virtualization`——NetworkManager 路径对 seepd 而言是死代码；
- todo 勘误"runtime 未接线"指 IP 包→FlowRouter 通路，该判断成立；但"NetworkManager 完全未接线"不成立，准确说法是**"接线存在但任何配置下都不可用"**。

**进程维度缺口**（P1-2 的"注入进程/端口"前提）：
- `MatchCondition`（seep-config `lib.rs:529-535`）仅 DomainSuffix/DomainKeyword/Geoip/Network/Port，**无进程条件**（roadmap S2"进程匹配增强"即指此）；
- `FlowContext = {id, target, metadata}`（seep-core `lib.rs:85-89`）**无进程字段**；`FlowMetadata = {tags, annotations}` 只能以字符串注记承载；
- `ProcessIdentity{pid,name}` 目前仅存在于 UDP 粘滞键（`seep-core/src/udp/key.rs:15,32,40`，P0-1 预留），无通用注入通道。
- 另核实一条准确声称：`TargetProto::Quic` 枚举已存在（seep-core `lib.rs:38-42`，networking.md §3 所述无误）。

### 1.3 差距

| # | 差距 | 影响 | 归属 |
|---|------|------|------|
| A1 | 无任何平台的真实设备 I/O（打开 `/dev/net/tun`/TUNSETIFF 等代码为零） | P1-1 全量工作 | P1-1 |
| A2 | `platform.rs` 未编译且启用即编译失败 → P1-1 不能按"填充占位"实施，必须**重写并接入模块树**；同时 `nix` 死依赖可顺势启用或移除 | 实施方式裁决 | P1-1 |
| A3 | `TunInterface`/`TunPacketStream` 占位假装 I/O 成功（静默丢包语义） | 误用风险；建议 P1-1 一并删除或改为显式 Err | P1-1 |
| A4 | 无 `TunIngress`：IP 流重组→FlowContext 管线为零 | P1-2 全量工作 | P1-2 |
| A5 | seepd 永不启用 `enable_network_virtualization`；`RuntimeConfig.network_config` 为唯一程序化入口 | P1-2/P1-3 需新增配置→runtime 通道 | P1-3 |
| A6 | 路由/过滤模型无进程匹配（MatchCondition/FlowContext 双缺口） | "按进程分流游戏流量"验收的落点 | P1-2 |
| A7 | seep-platform 0 测试；trait 面（`TunProvider` 15 方法含 packet_stream/configure_dns 等）是否全部必要未经实战检验 | P1-1 落地时允许裁剪 trait（roadmap"保持 trait 稳定"应理解为语义稳定而非方法集冻结） | P1-1 |

### 2026-10-04 落地更新（推翻/闭合 §1 正文）

- **§1.2 模块编译面数字过时**：linux.rs 已入编译树（`network/mod.rs:24-25` `#[cfg(target_os="linux")] pub mod linux;`，现 1757 行含测试），mod.rs 现声明 dns/dns_engine/filter/ipcodec/route/tun/linux 共 7 模块；tun.rs 裁剪后 437 行——正文"5 个文件共 3588 行"与"platform.rs 237 行"（现 238 行）均为 09-29 数字。`platform.rs` 仍为未编译死稿（`// pub mod platform;` 未解开），该点仍真。
- **工厂恒 Err（L44）结论仍真但语境已变**：`create_tun_provider`/`create_route_manager` 等工厂对每个 `target_os` 分支恒 Err（现 `route.rs:588-646`/`dns.rs:943-1000`，行号漂移）；但 **TUN 主路径已绕过工厂**——TunIngress 直构 `LinuxTunProvider`/`LinuxRouteManager`（`network_config.rs:138,161`），工厂 Err 不再阻断 P1 链。
- **依赖与测试**：`nix` 已启用为普通依赖（`seep-platform/Cargo.toml:27` features=["ioctl","fs"]，仅 winapi 仍 optional）；seep-platform 已有测试（linux.rs 测试段、mod.rs、ipcodec golden 向量）——"0 个测试"已失效。
- **runtime 接线面**：`TunIngress` 存在并接线（`crates/seep-runtime/src/tun_ingress.rs` 1245 行，`runtime_builder.rs:477-493` 构造并插入 `ingress_endpoints["tun"]`）——"grep 零命中"已失效。
- **进程维度缺口**：seep-config `lib.rs:1735` 已增 `MatchCondition::Process { values }`（P1-2 T5），seep-routing `lib.rs:576-581` 已增读 `process.name` 注解臂 + 两态单测——"无进程条件"已失效。
- **差距表闭合**：A1（真实设备 I/O，`linux.rs:203 open_tun_file` + `TUNSETIFF` ioctl）@75c7747；A4（TunIngress 全链路）@a9f11dc/b5785c2/7a3024d；A7（trait 裁至 14 方法、`packet_stream`/`TunPacketStream`/`TunInterface` 已删 + 有测试）@c076fb8；A2/A3/A5/A6 随 P1-1/P1-3 落地闭合（见 §2/§5 更新块）。

---

## 2. 条目二：network 配置区块 + `seepctl route apply/clear`（todo P1-3）

### 2.1 文档声称

| 来源 | 声称 |
|------|------|
| todo.md 勘误区 | "配置新增 network 区块（mode: tun/redir；bypass/include）+ CLI `route apply/route clear` → `SeepConfig` **无顶层 network 区块**；`seepctl` **无 route 子命令** → P1" |
| networking.md §2 | 同上口径（"配置缺区块""CLI 缺命令"两条） |

### 2.2 代码实际

- `SeepConfig`（seep-config `lib.rs:12-21`）＝ `{control, telemetry, ingress, egress, routing, udp}`——**确无 network 块**（grep 命中的 `network:` 字段均属 vmess/vless/trojan 出站的传输层 `network: String`，无关）；
- **静默忽略风险（新发现）**：seep-config 全文件无 `deny_unknown_fields` → 用户在 YAML 里写 `network:` 块会被 serde **静默丢弃**，既不报错也不生效——比"配置不存在"更隐蔽；
- 模型已备而未暴露：`NetworkConfig{mode, tun, routing, filtering, dns}` 与 `NetworkMode::{Tun, Tap, Transparent, Hybrid}`（platform `network/mod.rs:39-64`）**只在 platform crate**，未进 `SeepConfig` schema；注意枚举字面量是 `transparent`，计划文案里的 "redir" 无对应命名（语义同一）；
- `RouteRule`/`BypassRule`/`default_bypass_rules()`（private_ip/loopback/multicast → Direct，`route.rs:571-595`）模型与默认 bypass 清单已写好，但**零消费点**；
- `RuntimeConfig.network_config: Option<NetworkConfig>`（`runtime_builder.rs:307`）是现成的程序化挂钩——P1-3 落地时"配置→runtime"有通道可走，仅需 seepd 侧接线；
- seepctl 顶层命令全集：`Check / Show / Stats / Nodes / Chain{dry-run,get,terminate,stats} / ImportClash / Subscription{…} / Diagnose / Mtls{…}`（`apps/seepctl/src/main.rs:29+`）——**确无 route 子命令**；diagnose 中的 "route" 字样仅为只读采集命令（`ip route`/`netstat -rn`/`scutil --route`），无 apply/clear 语义。

### 2.3 差距

| # | 差距 | 影响 | 归属 |
|---|------|------|------|
| B1 | `SeepConfig` 无 `network` 区块、schema 无对应类型 | P1-3 全量工作 | P1-3 |
| B2 | `network:` 块被静默忽略（无 deny_unknown_fields） | P1-3 落地前用户配置"写了没用"且无提示；建议 P1-3 顺带评估对未知顶层键显式告警 | P1-3 |
| B3 | seepctl 无 `route apply/clear`；控制面亦无对应端点 | P1-3 全量工作 | P1-3 |
| B4 | 命名口径未对齐：文档 "tun/redir" vs 枚举 `tun/transparent` | P1-3 写 schema 时需定名并回填文档 | P1-3 |

勘误记录本身（"无区块/无子命令"）**准确无夸大**。

### 2026-10-04 落地更新（推翻/闭合 §2 正文）

- **§2.2 各条全部反转**：`SeepConfig` 已有 `pub network: Option<NetworkBlockConfig>`（seep-config `lib.rs:36`，R1）；全文件已加 `#[serde(deny_unknown_fields)]`（`lib.rs:163`，B2 收口，拼错顶层键即报错）；`seepctl` 已有 `route` 子命令（apply/clear/status，1befbe7）；`derive_runtime_config` 已设 `network_config`（seepd 按 `config.network.is_some()` 接线）。
- **B4 命名裁决已闭合**：`transparent` 弃 `redir`，seep-config `lib.rs:179` 注释钉住该口径并回填 network-route.md §1.3。
- **差距闭合**：B1（schema）@1e1a7c0；B2（deny_unknown_fields）@B2 收口；B3（端点+子命令）@1e1a7c0/1befbe7；B4 见上。§5 第 4 条"现成通道"已全接通。

---

## 3. 条目三：FlowMiddleware 动态加载（todo P3-2，勘误降级项）

### 3.1 文档声称

| 来源 | 声称 |
|------|------|
| todo.md 勘误区 | "FlowMiddleware 支持 WASM/动态库加载，示例（限速、统计、内容过滤）→ **仅有 `LatencyProbe` 一个实现，无动态加载机制** → P3（降级）" |
| roadmap.md S0/S3 | S0："`FlowMiddleware` trait 不变"（列为契约层）；S3 复用："混淆以中间件形态挂载" |

### 3.2 代码实际

- trait 存在：`FlowMiddleware { name(); handle(Flow) -> Flow }`（seep-core `lib.rs:234-238`）——S0"trait 不变"声称成立；
- 唯一实现 `LatencyProbe`（`seep-protocols/src/middleware/latency_probe.rs`，34 行）：`sleep(1ms)` 后原样返回——纯占位语义，与 `seep-routing` 的 `latency` 组策略无关（组策略走 mesh 健康数据，不经中间件）；
- **零消费点（新发现，差距深于勘误记录）**：全仓无任何代码调用 `FlowMiddleware::handle`，也无任何位置构造 `LatencyProbe`（除定义与 re-export）；ingress→FlowRouter→FlowOutputRouter→egress 数据通路**没有中间件挂载点/注册表/管线**——trait 处于"已定义、未挂载"状态；
- 无动态加载设施：workspace 全部 Cargo.toml 无 `libloading`/`wasmtime`/`wasmer` 类依赖；
- 对 roadmap S3 的含义："复用 FlowMiddleware trait"的前半句（trait 在）成立，后半句（"以中间件形态挂载"）**挂载机制本身不存在**——P1-4（padding 混淆 MVP）实施时必须先建静态挂载点（例如 ingress/egress 侧的 middleware 链），动态加载才是 P3-2 在静态挂载点之上的扩展。

### 3.3 差距

| # | 差距 | 影响 | 归属 |
|---|------|------|------|
| C1 | 数据通路无中间件挂载点（无 registry/管线/调用点） | P1-4 的隐藏前置；roadmap S3 应补注"先建挂载点" | P1-4 |
| C2 | 无 WASM/动态库加载器与隔离机制 | P3-2 全量工作 | P3-2 |
| C3 | 无限速/统计/内容过滤示例中间件（LatencyProbe 亦为 sleep 占位） | P3-2 验收所需示例集 | P3-2 |

勘误记录"仅一个实现、无动态加载"**准确**，且实际还缺一层静态挂载。

### 2026-10-04 落地更新（推翻/闭合 §3 正文）

- **静态挂载点已建（P1-4）**：`seep-runtime/src/obfs_config.rs:306-317` 构建中间件链并推入 `Arc::new(LatencyProbe::new())` 等，`runtime_builder.rs:3053` 消费——"零消费点/无挂载点"已失效；混淆链在 runtime_builder 装配（静态链，注释"静态混淆链"）。
- **动态加载已落地（P3-2，955e4d6）**：`seep-plugins/src/loader.rs:35` 把 WASM 插件适配为 `Arc<dyn FlowMiddleware>`，workspace 已有 wasmtime 动态加载面 + 限速/内容过滤示例插件（见 plugin-loader.md §4.2）——C1/C2/C3 全部闭合，roadmap S3"以中间件形态挂载"的前半句与后半句均已成立。
- ⚠ 注意：**配置热更新重建链未落地**（seepd 启动一次性读配置，无 SIGHUP/watch；`HotReloadManager` 导出但从未实例化）——插件/中间件链为进程内静态，详见 plugins/README.md"启用"节 2026-10-04 标注。

---

## 4. 文档自身偏差（本轮不改，留待文档轮回填）

| 文档位置 | 偏差 | 应改为 |
|----------|------|--------|
| networking.md §1 platform.rs 行 | "Linux/OpenWrt/Windows/macOS/Android/iOS 各 Provider/… 骨架" | 实际仅 macOS 5 个占位类型，且模块未编译（`// pub mod platform;`） |
| networking.md §1/§7 "约 3800 行" | 含未编译 platform.rs | 编译内 3588 行；platform.rs 237 行未参与构建 |
| roadmap.md S2 "3825 行设计已成型" | 同上 | 同上 |
| roadmap.md S2 "platform.rs 占位已是该形状" | 占位不完整（启用即编译失败）且仅一平台 | "platform.rs 为未编译的单平台草稿，P1-1 需重写" |
| todo.md 勘误区条目① "各平台 Provider 为占位实现（platform.rs 返回"未实现"）" | "各平台"超前 | 可在 P1 落地时一并修正；精确表述见本文 §1.2 |

### 2026-10-04 落地更新（§4 表已随落地处理）

- networking.md §1/§7 的 platform.rs/"约 3800 行"口径已随 P1-1/P1-2 落地改写（linux.rs 入树、行数口径更新）；roadmap S2 同步回填。表内其余行作为 09-29 偏差记录保留存档。

## 5. 对后续实施的影响（供 P1-1..P1-3 / P1-4 / P3-2 设计稿直接引用）

1. **P1-1 不能按"替换 platform.rs 占位"叙述**：正确路径是新建 Linux 实现模块并接入 `network/mod.rs` 模块树；`platform.rs` 死稿可删除或留作 macOS 参考（启用前需补齐缺失方法）；
2. **`TunInterface`/`TunPacketStream` 占位应随 P1-1 处置**（真实实现覆盖或删除），其"假装写成功"语义不可保留；
3. **P1-2 的进程注入需要三处协同**：TUN 侧取进程信息（/proc 或 conntrack 反查）→ `FlowContext` 扩进程字段或约定 annotation 键 → `MatchCondition` 增 `Process` 变体；P0-1 的 `ProcessIdentity` 可直接复用为载体类型；
4. **P1-3 有现成通道**：`SeepConfig.network`（新）→ `RuntimeConfig.network_config`（已有）→ `NetworkManager`（已有骨架）；同时需裁决 `tun/redir` 与 `NetworkMode::{tun,transparent}` 的命名统一，以及未知顶层键的显式告警；
5. **P1-4 的真实前置是"建挂载点"而非"写一个中间件"**：静态 middleware 链（ingress 与/或 egress 侧）是 padding/timing/shaping 的共同基座；P3-2 动态加载是在该基座上加 loader 与隔离，不应先于基座动工。

### 2026-10-04 落地更新（§5 前瞻全部已落地）

1. P1-1 已按"新建 Linux 实现模块"路径实施——`network/linux.rs`（现 1757 行含测试）入树；`platform.rs` 死稿保留未动（仍 `// pub mod platform;`）；
2. `TunInterface`/`TunPacketStream` 占位已随 trait 裁剪删除（TunProvider 现为 14 方法）；
3. 进程注入已按三处协同落地——TUN 侧进程注解 → FlowMetadata annotation 键 → `MatchCondition::Process`（P1-2 T5，7a3024d）；
4. P1-3 通道已接通（R1–R4，1e1a7c0/1befbe7），`tun/transparent` 命名以 `transparent` 为准、未知顶层键以 `deny_unknown_fields` 显式报错；
5. P1-4 静态挂载点已建（obfs_config.rs 中间件链），P3-2 WASM loader 与示例插件已落地其上（955e4d6）。
