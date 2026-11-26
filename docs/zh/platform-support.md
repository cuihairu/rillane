# 平台支持与交付状态

逐平台交付与验收状态。全文坚持三层诚实分型：**构建/交叉编译**（对目标
可编译）不是**本地契约门**（本机测试钉住的条款），两者也都不是**真机
验收**（真硬件、真网络）。机器可读真源：`contracts/build_matrix_v1.json`、
`contracts/desktop_e2e_matrix_v1.json`、`contracts/parallel_scenario_matrix_v1.json`；
逐条证据见[验收证据索引](../acceptance-evidence/README)。协议级支持是
另一页（[协议支持](./PROTOCOLS)）。

## 六平台支持表

| 平台 | 构建面 | 已交付运行面 | 验收状态 | 具名缺口 |
|---|---|---|---|---|
| Linux (systemd/deb) | x86_64 + aarch64 nightly 产物；armv7 CI 仅检查；未声明发行版下限（glibc 随构建机） | TUN TCP/UDP 数据通路、进程身份归因、规则来源/Explain——最完整的平台 | tcp/udp/name_path/pid_reuse/rule_source 本地已验；permission_denied / port_reuse / 浏览器分组轨迹 / 故障样例未跑 | 桌面会话场景（真实浏览器 + 两款游戏）、跨属主拒绝面、端口复用面 |
| OpenWrt | 3 个产物三元组；下限 OpenWrt 22.03+（fw4/nftables，`rule_backend: nft`） | 网关接线脚手架 | 零真机验收——RIL-041/042 未跑 | 缺 OpenWrt 设备：接线、运维与资源验收全未跑 |
| Windows | x86_64 windows-gnu 交叉（仅编译级）；最低版本未验证 | 接管/旁路、进程归属、服务与退出恢复 | `imac` 机批次已验（RIL-032–035）：身份/接管/归属/服务恢复；规则来源本地已验（平台无关决策面） | 浏览器/游戏分组轨迹与故障样例（仅跑过 curl.exe HTTP 面）；DNS 劫持端到端；休眠恢复 |
| macOS (launchd) | 2 个 universal2 产物三元组；须 macOS 原生构建（Apple SDK 再分发限制） | 仅构建/宿主脚手架 | 全条款待 macOS SSH 接入（仅平台无关的规则来源面本地已验） | RIL-036–039 未交付——Intel mac 待接入 fleet |
| Android | 2 个三元组 + demo 应用（minSdk 24 / targetSdk 33） | FFI 库：14 符号 JNI 面、宿主生命周期停止面、TUN fd 注入面、查询面、最小 ICMP 回声通路——均有本地契约门钉住 | 真机批次未跑（RIL-043–046 未勾） | 完整转发（TunIngress 自开 `/dev/net/tun` 不收外来 fd、无 protect 钩子——具名未来工作）；真机生命周期/切网 |
| iOS | 3 个产物三元组（交叉编译） | 私有 fd 集成脚手架 | 零——NE 扩展不在模拟器运行；需签名设备 + 付费开发者账号 | RIL-094/047–049/149 阻塞在签名接入 |

## 提案，未交付

与上表分开——提案不得读成能力：

- Windows/macOS 达 v1 质量的捕获与身份（加固、双栈旁路、权限与恢复）——
  [能力边界](./architecture)的 v1 work 列。
- 完整移动转发与公开 packet API（Android/iOS）。
- macOS/OpenWrt/Android/iOS 真机验收批次（`todo.md` 全部未勾，各带具名
  阻塞）。

## 如何读状态

`verified_local` / `verified_device` 格指向真实仓内文件（测试文件或证据
文档）。`partial` 表示条款的一部分跑过、其余是具名缺口。`needs_*` 格
不携带证据——单元测试、交叉编译与构建产物绝不冒充真机验收。账本由
`cargo test --workspace` 内的契约门执行：状态与事实脱节时构建点名失败，
而不是默默烂掉。
