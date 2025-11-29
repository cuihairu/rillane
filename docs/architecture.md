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

## 后续路线
1. 完成最小 MVP：Socks5 入站 + Direct/Trojan 出站，提供基础路由。
2. 构建自动化测试 (unit + integration) 以及性能基准。
3. 接入 Telemetry（Prometheus/OTLP），再扩展多平台分发。
