# 功能矩阵

本仓交付面的**能力视图**。它与诚实账本互补，不互相替代：[平台支持与交付状态](platform-support.md)
是平台视图，[验收证据索引](acceptance-evidence/README.md) 列明什么在哪里跑过，
`contracts/` 下的机器可读矩阵由 `cargo test --workspace` 内的契约门钉住。

构建/交叉编译 ≠ 本地契约门 ≠ 真机验收。下表每一格都指向真实仓内产物；具名缺口保持缺口。

## 能力表

| ID | 能力 | 已交付面 | 边界与证据 |
|----|------|----------|------------|
| F-01 | 代理入站 | SOCKS5 / HTTP / Mixed 入站；SOCKS5 用户名/密码认证（RFC1929，常数时间比较）、HTTP Basic 与 Bearer 认证；逐入站 UDP ASSOCIATE 覆盖 | [CLI 参考](cli.md)；协议 crate `crates/rillane-protocols` 入站面；秘密可按引用注入（F-13） |
| F-02 | 透明接管入站 | `network.transparent.rule_backend` 下的 iptables 与 nftables 双规则后端；专用表 fw4 共存设计；LAN 与本机双面带逃逸 mark | 规则规划面本地已验（`nft -c` 解析仲裁）；路由器规则生效/撤销归 OpenWrt 机批次——RIL-041 见[系统路由与网络接管](networking.md) |
| F-03 | TUN 数据面 | Linux TUN 设备 + 最小 ICMP echo 通路；Android TUN fd 注入，坏 fd 具名拒绝 | 移动完整 TCP/UDP 转发是提案（见下）；[安装与 Debug](usage-bridge.md) Android/iOS 边界 |
| F-04 | 出站协议 | 27 个出站配置/装配面（direct、reject、socks5、http、shadowsocks（含 SIP003 插件）、vmess、vless、trojan、anytls、hysteria(2)、tuic、snell、shadowquic、mieru、shadowsocksr、trusttunnel、masque、openconnect、openvpn、ssh、tailscale、tailcat、cloudflared、tor、wireguard、shadow-tls 组合） | 逐协议诚实记录在[协议支持](protocol-backends.md)评估记录——REALITY 客户端参数拨号期具名拒绝（rustls 无 ClientHello 字节控制）、Naive/Sudoku 未决（见提案）；ShadowsocksR 已对 GPL 源码构建的真实对端验收（RIL-115） |
| F-05 | 传输与复用 | gRPC gun 流复用旋钮（RIL-130）、ShadowTLS v2 载具（RIL-110）、websocket/TLS 传输面 | 公共传输矩阵见[协议支持](protocol-backends.md)；不支持的组合在构建期具名拒绝 |
| F-06 | 路由与策略 | Rule / Global / Direct 三模式；select / fallback / url-test 组；14 类规则条件（域名后缀/关键字/全等/正则、geoip、geosite、network、ip-cidr、目标端口、源端口、传输协议、进程名、进程路径、规则集引用）；首匹配求值；`explain` 纯重演 | RIL-087 订阅到执行回归钉住 转换→代际→explain=实际出口；[CLI 参考](cli.md) explain 节 |
| F-07 | 订阅接入 | Clash/Mihomo 订阅转换（节点、组、规则）；FullPolicy 与 NodesOnly 两种导入模式；多源合并、悬挂引用显式失败；凭证转换不丢 | RIL-087 六测回归；[订阅支持](subscription-support.md) |
| F-08 | DNS | `network.dns` 块；控制面、FFI 与 MCP 查询面的 DNS 统计与解析器形状 | 缺席是诚实 `enabled:false` 空形态，不是落零——[配置参考](config.md) |
| F-09 | 配置事务 | 代际发布带 prepare/apply/commit 账本；崩溃点重放（两提交窗口子进程 SIGABRT）；补偿回滚；审计痕迹；MCP 写工具需真实操作员 proposal/approval ID | RIL-088 故障注入验收；磁盘故障以孤儿可见，不被静默吸收 |
| F-10 | Debug 诊断 | `diagnose`（safe/full/raw 脱敏档，永不自动上传）、`trace`（list/flow/svg/events/inspect，显式缺席退出码 2）、`explain`（零副作用）、`probe`（显式登记目标，未启用 503）；TCP 入口流由 SessionTracer 活面追踪 | [安装、恢复与 Debug](usage-bridge.md)；UDP 关联面与真机批次开放——[活面轨迹证据](acceptance-evidence/README.md) |
| F-11 | 可选 MCP 适配器 | stdio 适配器，冻结版本 2026-07-28；16 工具；read/detailed/probe/write scope，`-32001 mcp.scope.denied` 执行拒绝；每分钟限速；官方 SDK 验收驱动（12 场景、零模型） | 默认关闭——无监听端口、无后台进程；[usage-bridge MCP 节](usage-bridge.md)；RIL-090 证据在 `apps/rillane-mcp/sdk-acceptance/EVIDENCE.md` |
| F-12 | 平台接管面 | Linux 透明/iptables 本地已验；Windows Wintun 数据面、进程归属、SCM 服务与恢复在 `imac` 真机已验；OpenWrt ipk + procd init；macOS 构建脚手架 | 逐平台状态与具名缺口见[平台支持](platform-support.md)——本行绝不把构建面升格成设备验收 |
| F-13 | 移动 FFI 面 | 18 方法 JNI 面（`start`、`startWithSecrets`、`networkChanged`、诊断 IPC 起停、stop/isRunning、stats + 6 查询面、TUN fd start/stop）；`${secret:` 引用注入 fail-closed；网络变化冲刷 DNS 缓存；有界宿主诊断 IPC（宿主显式 UDS 路径、只读动词白名单、双向长度上限、一连接一请求；无默认监听）；坏 fd 拒绝且句柄不被污染；Rust/Kotlin 两半边停止可重复 | JNI 恰等门与 C 头恰等门随 `cargo test --workspace` 运行；真机批次（packetFlow、ABI、线程/背压、活切网、宿主 IPC 授权）开放——[FFI 证据](acceptance-evidence/README.md) |
| F-14 | 可选 Mesh 与插件 | 能力协商拒绝不可信信道与 UDP 安全承载未完成（绝不明文旁路发布）；full 档 wasm 插件与策略面隔离；small/mobile 档依赖图无 wasmtime | 标准代理产物关闭扩展可用——[Mesh](mesh.md)；构建档位由 CI `small` job 钉住（RIL-040） |
| F-15 | 性能账本 | 并行负载对照含 p50/p95、抖动、有效丢包、TTFB、吞吐、CPU/RSS 与重复次数；调度重演报告回退与无收益条件 | debug 构建回环实测、范围如实——[并行负载](parallel-load.md) |

## 提案，未交付

与上表分开——提案绝不读成能力：

- Windows/macOS v1 质量的捕获与身份（加固、双栈旁路、权限与恢复）——
  [架构能力边界](architecture.md) 的 v1 work 列。
- 完整移动转发与公开 packet API（Android/iOS）——阻塞于签名设备探针
  （RIL-094）与移动 FFI 真机批次。
- macOS/OpenWrt/Android/iOS 真机验收批次（`todo.md` 全部未勾，各有具名阻塞）。
- NaiveProxy（RIL-112）与 Sudoku（RIL-117）接入——分别待用户明示姿态与
  非 GPL authored 线规范；本仓拒绝静默降级。
