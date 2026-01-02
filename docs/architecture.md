# Seep 架构草图

## 设计目标
- 以 Rust 实现跨平台代理内核，兼顾性能、安全与可维护性。
- 使用 monorepo 管理全部 crate / app / 平台 glue 代码，减少版本漂移。
- 支持 Windows、Linux、macOS、Android、iOS、OpenWrt，并提供一致的配置与控制面。

## 顶层目录
```
seep/
├── apps/            # 二进制入口 (守护进程、CLI)
├── crates/          # 复用库 (core、config、routing、protocols 等)
├── docs/            # 设计文档与 ADR
├── platforms/       # 特定平台 glue (后续补充 android/ ios/ openwrt)
├── Cargo.toml       # Workspace 定义
└── README.md
```

## crate 划分
- `seep-core`：抽象统一的 Flow / Router / Middleware 接口，是所有协议实现的契约层。
- `seep-config`：定义配置 schema、解析/校验逻辑，支持 YAML/JSON/TOML 自动识别。
- `seep-routing`：策略与路由引擎，实现 PSL/GeoIP/度量等匹配逻辑，输出 `RouteDecision`。
- `seep-protocols`：入口、出口协议栈（Socks5/HTTP/Hysteria/Trojan/...），通过 `IngressEndpoint` 与 `EgressConnector` 接口挂接。
- `seep-telemetry`：日志、指标、Tracing 初始化，提供统一 `TelemetryOptions` 供 daemon / CLI 复用。
- `seep-platform`：封装各平台的安装、服务管理、权限处理，编译期通过 feature 划分实现。
- `seep-runtime`：编排引擎，串联配置、路由、协议组件，启动监听及热更新逻辑。
- `seep-mesh`：协作节点模型与注册表，维护节点角色（client/relay/exit）、能力与心跳，为后续组网/加速提供统一数据面。

## 应用层
- `apps/seepd`：常驻守护进程 (service/daemon)，负责加载配置、初始化 Telemetry、启动 runtime。
- `apps/seepctl`：命令行控制台，用于配置校验、热更新、查看状态；后续可扩展远程 API。

## 关键接口
- `Flow`：一次代理会话的上下文，包含目标信息、标签等；`FlowRouter` 根据 `FlowContext` 决策。
- `IngressEndpoint`：监听入口，接入连接后调用路由器并交给 `EgressConnector`。
- `FlowMiddleware`：可选中间件，用于统计、限速、内容过滤。
- `ServiceInstaller` / `ServiceRuntime`：平台 glue，负责在 systemd/launchd/Windows Service/OpenWrt init.d 中部署。

## 平台策略
- **桌面/服务器**：提供 `seepd` 二进制 + systemd/launchd/Windows Service 模板。
- **Android/iOS**：核心以 `cdylib` 形式暴露 FFI，UI 侧使用 Kotlin/Swift/Flutter 调用。
- **OpenWrt**：默认构建 `musl` 静态包，并提供 UCI/ubus 适配器；LuCI 插件单独维护在 `platforms/openwrt`。

## 控制面与生态
- 控制面统一走 `control.api_bind` (gRPC/WebSocket/REST) + `seepctl`。
- 支持热更新：`seepctl reload` -> 守护进程 watch 配置 -> `RuntimeBuilder` reload。
- 文档及 ADR 集中在 `docs/`，重要决策使用 ADR 记录。

## Mesh / 协作加速 / 节点组
- Seep 将把每个安装节点视作一个网元，可注册为 `client` / `relay` / `exit`，支持互联互通。Mesh 控制面负责登记节点元数据（地区、ISP、带宽、健康状态）、拓扑与 ACL。
- 当前 `seep-mesh` crate 内提供 `MeshRegistry` 和后台心跳清理逻辑，`seep-runtime` 会默认注册本地节点并启动离线检测。
- `RoutingConfig` 将扩展 `GroupDescriptor` 与 `chains`：路由规则先定位逻辑组，再由组策略（latency/bandwidth/random/weighted）选出具体节点，可表达链路如 `client -> relay -> exit`。组可以嵌套，方便按地区/游戏类型组织。
- `FlowMetadata` / `ChainContext` 携带链路信息，egress/relay 会根据这些数据记录“哪个节点使用了哪个节点的流量”，便于统计与策略调度。
- 游戏加速场景：结合虚拟网卡/Tun，针对特定端口/进程劫持流量，经由附近的 relay 与最优出口出国，实现跨运营商加速、低延迟路径与自动故障切换。

## 系统路由与虚拟网卡
- `seep-platform` 将新增 `network` 模块，提供 `TunProvider`/`RouteManager` trait，并针对 Linux/OpenWrt（TUN+policy routing）、Windows（Wintun/WFP）、macOS（utun/NE）、Android（VpnService）、iOS（NEPacketTunnel）实现具体能力。
- `seep-runtime` 里会加入 `TunIngress`/`TunEgress`，直接处理 L3/L4 包，并与 FlowRouter 结合，实现“全局/指定流量”接管。
- 配置层会新增 `network` 区域，指定模式（tun/redir）、分流规则（bypass/include）、进程/应用过滤等；CLI/控制面提供路由应用/撤销命令。

## 订阅与配置编译
- 将兼容 Clash 订阅（proxies/proxy-groups/rules）并自动转换为 SeepConfig；另行设计 Seep DSL（version/meta/nodes/chains/rulesets）以表达多节点 mesh、链路特性。
- `seepctl subscription` 管理订阅源，支持 add/remove/list/refresh，守护进程可定时拉取并热更新路由。

## 安全与观测
- Mesh 节点通信支持 data-plane mTLS（可选），用于 hop-by-hop 转发加密与认证；证书可通过 `seepctl mtls` 生成（CA/节点证书），并通过环境变量 `SEEP_MESH_MTLS_*` 注入运行时（MVP：可选启用，强制策略与轮换后续补齐）。
- Telemetry/metrics 包含 per-node/per-link 流量、延迟、丢包、重试次数，方便控制面统计“谁使用了谁的流量”与 SLA。当前 `seepd` 在 `telemetry.enable_metrics=true` 时暴露 `GET /metrics`（Prometheus 文本格式），提供 mesh/chain/subscription 的基础指标；更细粒度的 per-link 流量与重试统计后续补齐。
- 控制面接口：`control.api_bind` 默认提供 HTTP 接口，现阶段可通过 `GET /flows` 获取入口→出口流量统计，通过 `GET /nodes` 获取 mesh 节点快照，通过 `GET /metrics` 拉取 Prometheus 指标，未来会扩展为完整的 REST/gRPC API。
  - 链路相关：`POST /chains/dry-run`、`POST /chains`、`GET /chains/{chain_id}`、`GET /chains/stats` 等接口用于多跳链路预检与管理（MVP：计算路径与附加元数据，数据面多跳转发后续实现）。

## 当前状态与路线
1. **MVP**（已完成）：Socks5 入站 + Direct 出站，完成基础 Flow/Router/Output 管线。
2. **下一阶段**：实现更多协议（Trojan/Reality/UDP 等）、节点组与 mesh 控制面雏形；补齐 Tun/系统路由支持，为游戏加速奠定基础。
3. **进阶阶段**：完成订阅 DSL、插件化中间件、自动链路自愈、Grafana/Prometheus 模板等，并在多平台发布。
