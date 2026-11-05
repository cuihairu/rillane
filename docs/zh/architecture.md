# Seep 架构草图

## 设计目标
- 以 Rust 实现跨平台代理内核：数据面走 tokio 异步运行时，mesh 数据面默认强制 mTLS，代码组织为 monorepo 分 crate。
- 全部 crate / app / 平台 glue 代码在一个 monorepo 内，依赖版本随 workspace 锁定，减少漂移。
- 目标平台为 Windows、Linux、macOS、Android、iOS、OpenWrt，共用同一套配置 schema 与控制面。

## 顶层目录
```
seep/
├── apps/            # 二进制入口 (守护进程、CLI)
├── crates/          # 复用库 (core、config、routing、protocols 等)
├── docs/            # 设计文档与 ADR
├── platforms/       # 特定平台 glue (android/ ios/ launchd/ openwrt/ systemd/ windows)
├── Cargo.toml       # Workspace 定义
└── README.md
```

## crate 划分
- `seep-core`：抽象统一的 Flow / Router / Middleware 接口，是所有协议实现的契约层。
- `seep-config`：定义配置 schema、解析/校验逻辑，支持 YAML/JSON/TOML 自动识别。
- `seep-routing`：策略与路由引擎，输出 `RouteDecision`；匹配以度量/条件为主；GeoIP/GeoSite 条件按可选的 `routing.geoip_db`/`routing.geosite_db` 数据库查询，数据库缺席或加载失败时条件恒不命中，PSL 匹配未实现。
- `seep-protocols`：入口、出口协议栈（Socks5/HTTP/Hysteria/Trojan/...），通过 `IngressEndpoint` 与 `EgressConnector` 接口挂接。
- `seep-telemetry`：日志与 Tracing 初始化 + 日志捕获环（`logs_text`）；指标不在此注册——Prometheus 文本由控制面 `handle_metrics` 渲染，计数器散布各 crate（如 seep-core UDP metrics）。
- `seep-platform`：封装各平台的安装、服务管理、权限处理，编译期通过 feature 划分实现。
- `seep-runtime`：编排引擎，串联配置、路由、协议组件，启动监听及热更新逻辑。
- `seep-mesh`：协作节点模型与注册表，维护节点角色（client/relay/exit）、能力与心跳，为后续组网/加速提供统一数据面。
- `seep-subscription`：订阅拉取/转换（Clash、分享链接、Seep DSL）/缓存/定时刷新全链路，内容哈希无变化时跳过重载。
- `seep-plugins`：WASM 插件加载器（wasmtime 动态加载，插件适配为 `FlowMiddleware` 挂入中间件链，见 [design/plugin-loader.md](design/plugin-loader.md)）。
- `seep-ffi`：移动平台 FFI 面（`cdylib` 导出，供 Android/iOS UI 侧调用）。

## 应用层
- `apps/seepd`：常驻守护进程 (service/daemon)，负责加载配置、初始化 Telemetry、启动 runtime。
- `apps/seepctl`：命令行控制台——配置校验与状态查看（18 个子命令），并经控制面触发路由/出站/订阅的运行时重建与 mTLS 证书管理；远程控制面为内置 HTTP/REST（端点总表与 seepctl 对应见 [docs/cli.md](cli.md)），无 gRPC/WebSocket 面。

## 关键接口
- `Flow`：一次代理会话的上下文，包含目标信息、标签等；`FlowRouter` 根据 `FlowContext` 决策。
- `IngressEndpoint`：监听入口，接入连接后调用路由器并交给 `EgressConnector`。
- `FlowMiddleware`：可选中间件，用于统计、限速、内容过滤。
- `ServiceInstaller` / `ServiceRuntime`：平台 glue，负责在 systemd/launchd/Windows Service/OpenWrt init.d 中部署。

## 平台策略
- **桌面/服务器**：提供 `seepd` 二进制 + systemd/launchd/Windows Service 模板。
- **Android/iOS**：核心以 `cdylib` 形式暴露 FFI，UI 侧使用 Kotlin/Swift/Flutter 调用。
- **OpenWrt**：musl 静态包（ipk 产线 + procd init.d）；LuCI/UCI 适配未做（LuCI 页面后置，见 `platforms/openwrt/README.md`）。
- **HarmonyOS（鸿蒙）**：`crates/seep-ffi` cdylib 在 aarch64/armv7/x86_64-ohos 三目标编译面 + ELF 静态核验已打通（armv7 走 wireguard 恒 Err 桩）；宿主接入（ArkTS/ArkUI）与真机面未做，见 `platforms/ohos/README.md`。

## 控制面与生态
- 控制面统一走 `control.api_bind` 的 HTTP/REST + `seepctl`（手写 HTTP 路由，无 gRPC/WebSocket 面）。
- 热更新口径：seepd 启动一次性读配置，**无配置文件 watch**（`seep-runtime::HotReloadManager` 导出但未接线，无 SIGHUP）；运行期热更新由订阅刷新与控制面端点驱动（路由/组/出站重建）。无 `seepctl reload` 子命令。
- 文档及 ADR 集中在 `docs/`，重要决策使用 ADR 记录。

## Mesh / 协作加速 / 节点组（现状）

- 每个安装节点视作一个网元，注册为 `client` / `relay` / `exit` / `hybrid`。`seep-mesh::MeshRegistry` 维护节点元数据、后台心跳清理与离线检测；`seep-runtime` 默认注册本地节点。
- 组与链路：`RoutingConfig.groups`（`PolicyGroup`）成员可为 `Node` / `Group`（嵌套） / `WeightedNode` / `WeightedGroup`，组策略含 latency/bandwidth/weighted/random/consistent_hash/round_robin/fixed；路由目标 `mesh.<node>` 会被 `ChainManager` 升级为 `RouteDecision::Chain`（源 → relay → exit）。
- 链路能力：构建（`ChainBuilder`，含约束与链路权重打分）、Dry Run 预检、健康检查任务、故障回退（`ChainContext` 备选路径切换）。控制面端点与数据面 wire format 见 [mesh.md](mesh.md)。
- 数据面：mesh data-plane 已实现 **TCP** hop-by-hop 转发（envelope 携带路径，逐跳剥离）与 **UDP** 多跳转发（2026-09 P0-4：`UdpEnvelope` 二进制头 over UDP 数据报、FULL/CACHED 跳缓存、同端口双栈——规格见 [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md)，概念稿 [design/udp-dataplane.md](design/udp-dataplane.md) §4）。
- 边界（当前不做）：UDP 面加密（**V2** quinn 载具未决；MVP 明文门已落地——chain+udp 未配加密时构建期拒绝启动）、端到端多跳 MAC/认证（无端到端密钥分发机制，归 V2）、OCSP/CA 直连撤销查询——见下「协作节点安全」与 todo P2-7。UDP 面**防重放已落地**（2026-10-04：v2 帧流序号 + per-(flow,dir) 64 位滑窗，`replay_dropped` 计数进入 /udp/stats 与 /metrics，见 [mesh.md](mesh.md) 与 [design/mesh-advanced-security.md](design/mesh-advanced-security.md)）；撤销分发=文件载体 + 运行期观测（`GET /mtls/revoked` + `seepctl mtls revoke status`）已落地。

## 系统路由与虚拟网卡（现状：Linux 已落地，跨平台 provider 占位）

- `seep-platform::network` 已建立完整 trait 与数据模型：`TunProvider`/`TunConfig`/`TunInterface`、`RouteManager`/`RouteRule`、`PacketFilter`/`FilteringConfig`（进程/端口/IP/域名规则）、`DnsHandler`；模块树现含 tun/route/filter/dns/dns_engine/ipcodec/linux 七个子模块（linux 为 Linux 实现，`#[cfg(target_os = "linux")]`）。
- **Linux 面已落地**（todo P1-1..P1-3，2026-10-03，详见 [networking.md](networking.md)）：`seep-runtime` 的 `TunIngress` 接线（`tun_ingress.rs`，TCP/UDP 数据面 + 自动绕过）、`SeepConfig` 顶层 `network` 区块（含 `deny_unknown_fields` 拼错即报错）、`seepctl route apply/clear/status` 三子命令与控制面 `/network/route/{apply,clear,status}` 三端点。
- **跨平台边界（如实标注）**：非 Linux 平台 Provider 仍为占位实现（构造即告警、收发返回"未实现"）；`RouteManagerFactory`/`DnsHandlerFactory` 的非 Linux 分支仍返回 Err——TUN 主路径不经工厂，直构 `LinuxTunProvider`/`LinuxRouteManager`。
- 只读能力：`seepctl diagnose` 采集本机路由/DNS/接口快照。

## 订阅与配置编译（现状：全链路已实现）

- Clash 订阅（proxies/proxy-groups/rules）与分享链接（vmess/vless/trojan/hysteria2/ss，含 base64 整体编码）均可转换为 `SeepConfig`；类型自动识别（`detect_type`）。转换中产出暂未实现的出站类型（如 hysteria v1——schema/订阅转换已支持，出站连接器缺）会在构建期报错提示。
- 自有 Seep DSL（version/meta/nodes/groups/rulesets，含认证/传输层/TLS/地理位置字段）支持导入导出与校验。
- 拉取器支持超时/UA/自定义头/代理与 ETag/Last-Modified 条件请求；缓存为 TTL+LRU；按订阅与全局两级刷新间隔定时刷新，内容哈希无变化时跳过重载；控制面提供订阅 CRUD 与手动/全量刷新端点（配置文件本身无自动监视——见「控制面与生态」节热更新口径）。
- 完整说明见 [subscription.md](subscription.md)。

## 协作节点安全（现状）与观测

- Mesh data-plane mTLS：chain 启用时**默认强制**（dev 可 `SEEP_MESH_ALLOW_PLAINTEXT=1` 豁免）；证书由 `seepctl mtls` 生成（CA/节点证书/轮换/CA bundle 双信任窗口），经 `SEEP_MESH_MTLS_*` 环境变量注入；撤销采用最小实现（按节点 CN 的撤销列表，文件 mtime 热加载）。详见 [mesh.md](mesh.md)。
- ACL 与配额：`NodeACL`（允许的 client CIDR、角色限制）与 `NodeQuota`（日/月带宽、并发连接数）在 registry 层强制，超限返回 `QuotaExceeded`。
- 边界：OCSP/CA 直连撤销查询未实现（V2——节点间除 mTLS 数据面外无 CA 通道）；多跳端到端 MAC/认证未实现（无端到端密钥分发机制，记 mesh-advanced-security.md §6 偏差 1）。撤销分发与 UDP 面防重放已落地（todo P2-7）：撤销文件 mtime 热加载 + 运行期生效面可查（`/mtls/revoked`）；UDP 面 v2 流序号 + 滑窗拒重放并计数。
- 观测：`telemetry.enable_metrics=true` 时 `GET /metrics` 暴露 Prometheus 文本（mesh per-link 计数、chain、subscription 事件等）；`GET /flows` 提供入口→出口流量统计；`GET /nodes` 提供节点快照；`GET /routing/stats` 提供组实时质量（成员数据源 real/legacy/unknown、p95/丢包、SLO 门判定与 latency 组当前选点——`seepctl group` 取数面，P2-2 O-slo1）。per-link 时延分布/切换原因等细粒度指标已随 P2-1 落地（`/mesh/switches` 切换账本，见 [mesh.md](mesh.md)）。控制面全部端点与 seepctl 对应关系见 [cli.md](cli.md) 端点总表。

## 当前状态与路线

- **已完成底座**（roadmap S0）：socks5/http/mixed 入站 + direct/ss/trojan/hysteria2/vmess/vless/wireguard/socks/http TCP 出站；组策略路由；mesh 控制面 + TCP 数据面 + mTLS；订阅全链路；控制面与 seepctl；基础 Prometheus 指标。协议实现边界见 [PROTOCOLS.md](PROTOCOLS.md) 状态标注。
- **进行中/规划**（见 [design/roadmap.md](design/roadmap.md)）：S1 UDP 全链路（P0-1..P0-5 会话表/入站/出站/mesh 数据面/观测与配置**全部已落地**——[设计稿](design/udp-dataplane.md)、[观测设计稿](design/udp-observability.md)）→ S2 TUN 系统接管 → S3 混淆横切层与连接复用 → S4 调度闭环与发布。可执行条目见根目录 [todo.md](../../todo.md)。
