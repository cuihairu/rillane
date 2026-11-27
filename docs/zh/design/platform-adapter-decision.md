# 平台适配器选型：跨平台 TUN 架构（v1）

状态：**已接受为设计基线**（2026-11-22，用户指定的调研与比较）。本文记录六平台适配器策略背后的主流方案调研与由其推导的决策，是对 [v1 架构设计](architecture-v1.md) 中 RV1-11/12/19/20/21 指引的具体实现选型补充。实施任务统一在仓库根目录 todo.md 台账（RIL-033..035、RIL-036..039、RIL-041..042、RIL-045..049）。

## 1. 调研范围与证据边界

调研于 2026 年 11 月，来源均为公开资料：sing-box 内部实现（Go 生态 TUN + libbox 平台接口）、mihomo/Clash.Meta（sing-box 衍生）、Rust 侧内核（meow-rs、tun2proxy、TinyTun、concord）、用户态 TCP/IP 栈（smoltcp、经 netstack-lwip 的 lwIP）及其公开基准（Watfaq netstack-bench、netstack-lwip README）。本仓库未自行跑过私有基准；下文数字均引自所列项目自己的文档/基准，随版本可能变化。

## 2. 主流架构比较

### 2.1 核心架构

| 项目 | 语言 | TUN 架构 | 对 Rillane 的关键启示 |
|---|---|---|---|
| sing-box | Go | 双栈：`system`（内核 TCP/IP，有 ioctl 处最快）/ `gVisor`（可移植用户态栈）/ `mixed`（TCP 走内核、UDP 走 gVisor）。`auto_route` 跨平台；`auto_redirect` 走 Linux nftables。**`libbox.PlatformInterface` 把 TUN 创建、连接归属查询、网络监控倒置给宿主应用**（Android VpnService / iOS NE 实现它） | 事实标准实现。平台接口倒置正是一个内核吃到六平台的原因 |
| mihomo (Clash.Meta) | Go | 源自 sing-box，自带 `mips` 栈为缺省 | 衍生路线可行；不必比原版更激进 |
| meow-rs | Rust | wintun / tun / utun 设备 + 经仓内 tun2socks 绑定的 lwIP 用户态栈；流派发进正常路由引擎 | 最接近的 Rust 参照：同语言、同「监听器→路由引擎」形态 |
| tun2proxy / TinyTun / concord | Rust | `tun` crate (0.8) + ipstack/netstack；五平台含 Android/iOS，走 `--tun-fd` fd 注入与包信息模式 | fd 注入模式在移动端已验证：应用建 TUN、内核消费 fd |

### 2.2 用户态 TCP/IP 栈基准（Watfaq netstack-bench，iperf3 单流）

| 栈 | 吞吐 | 备注 |
|---|---|---|
| 内核直连（基线） | 9.3 Gbit/s | 上限参照 |
| **smoltcp**（纯 Rust） | **6.5 Gbit/s** | 最快的纯 Rust 选项；无 FFI、无 C 构建 |
| lwIP（C，netstack-lwip） | 3.9 Gbit/s | Go 生态内核常用；**全局锁串行化所有调用**——聚合吞吐随流数上升而下降（netstack-lwip 自己有记载） |

注意事项：均为单流数字；多流下 lwIP 的退化上游有记载；smoltcp 缓冲尺寸显著影响最大吞吐。在冻结 RIL 性能预算前，先在 Rillane 自己的负载上复测。

## 3. 决策

1. **D-PA-1：平台接口倒置（取自 sing-box）。** 移动端内核从不自建 TUN 设备。宿主应用（Android VpnService、iOS Network Extension）创建设备并把文件描述符交给内核；内核按 `--tun-fd` 形态消费。桌面端在权限允许处保留内核侧自建。这正是 RV1-19 已隐含的拆分（FFI packet/生命周期归属）；本决策把该模式具名。
2. **D-PA-2：用户态栈 = smoltcp（基准 + 同语言）。** 纯 Rust，所测用户态选项里最快，构建内无 C 绑定。若 smoltcp 撞到协议完整性墙，lwIP 保留为有记载的备选（RV1 性能预算复测把这扇门钉住）。
3. **D-PA-3：设备层 = `tun`/`tun2` crate 族（取自 tun2proxy/meow-rs）。** Linux `/dev/net/tun`、Windows wintun.dll、macOS utun——一个抽象、逐平台配置。不逐平台手写 ioctl。
4. **D-PA-4：移动端 = fd 注入，不是设备管理。** Android：VpnService 持有 TUN，`protect()` 标记出站 socket，逐应用分流走 tun2proxy 的会话信息内嵌模式（getConnectionOwnerUid）。iOS：NEPacketTunnelProvider packetFlow → fd（按 tun crate iOS 示例的记载，需要包信息前缀）。Rillane 内核保持应用商店中立的 Rust。
5. **D-PA-5：桌面 macOS = 与 meshlet 的 WG-MAC-BT 相同的 utun 机制。** utun 命名（`utun[0-9]+`）、`ifconfig`/`route` 方言、MTU 纪律、提权的 launchd helper。一台 Intel mac 设备同时验证 meshlet（WG）与 rillane（代理 TUN）两份探针。
6. **D-PA-6：iOS 保持硬门。** Network Extension 只在带开发者账号的签名设备上加载；模拟器不加载扩展。RIL-094 在 Apple 开发者账号 + 签名设备存在前保持 BLOCKED。任何设计工作都无法解除这扇门。

## 4. 平台矩阵（六平台后果）

| 平台 | TUN 来源 | 权限边界 | 内核参与 | Rillane 任务 |
|---|---|---|---|---|
| Linux | 经 tun crate 的 `/dev/net/tun` | root/CAP_NET_ADMIN | 全量（设备 + 栈） | 既有路径，持续改进归属/恢复 |
| OpenWrt | 同 Linux，内存受限 | root，procd 服务 | 全量，small 构建 | RIL-041/042 |
| Windows | wintun.dll | 提权（SCM 服务） | 全量 | RIL-033/034/035 |
| macOS | utun（tun crate） | launchd helper / sudo 白名单 | 全量 | RIL-036（P0 探针）→ 037/038/039 |
| Android | VpnService（宿主应用） | 应用 VPN 权限 | fd 消费 + 栈 | RIL-045/046 |
| iOS | NetworkExtension（宿主应用） | entitlement + 签名 | fd 消费 + 栈 | RIL-094（P0 探针，BLOCKED）→ 047/048/049 |

## 5. 本决策不声明的事

- 不声明 Rust 相对 Go 内核的自动提速（上游研究第 8 节已明确否掉）。
- smoltcp 基准数字是引用，不是本仓库复测；RIL 性能预算在 Rillane 负载上复检。
- iOS 解阻需要外部资源（开发者账号、签名设备），任何架构选择都无法替代。

## 6. 相关

- [上游架构研究](../research/proxy-architectures-2026-11-14.md)——Mihomo/sing-box/Surge 的概念映射与证据（M1-M9、S1-S6）。
- meshlet WG-MAC-BT（独立仓库）——Intel mac boringtun 验证共享同一设备与 utun 机制；结论回填 RIL-036 的探针记录。
