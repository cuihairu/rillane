# 平台宿主与安装参考

v1 设计覆盖 Linux、OpenWrt、Windows、macOS、Android、iOS。目标和验收见 [v1 架构](../docs/zh/design/architecture-v1.md)，任务统一在 [todo.md](../todo.md)。脚本、编译产物与真机完整代理分别验收。

| 目录 | 当前用途 | 边界 |
|---|---|---|
| [systemd](systemd/README.md) | Linux 服务与 deb | TUN/路由需要对应权限和退出恢复验证 |
| [openwrt](openwrt/README.md) | musl/ipk/procd | 网关 fw4、资源和双栈仍按设备验收，不识别 LAN PID |
| [windows](windows/README.md) | 交叉构建与服务模板 | 完整接管、本机身份与服务生命周期待实现/验收 |
| [launchd](launchd/README.md) | macOS 构建/安装模板 | 完整接管、身份和签名权限待真机验收 |
| [android](android/README.md) | VpnService/JNI demo | 有限测试通路，不等于完整 TCP/UDP 代理 |
| [ios](ios/README.md) | PacketTunnel 源码/构建脚手架 | 需要公开 packetFlow 桥接、签名设备与内存验收 |
| [ohos](ohos/README.md) | 实验编译集成 | 不属于当前六平台交付承诺，无完整宿主/真机支持 |

进程分流只要求 Windows/macOS/Linux 本机。移动平台不默认运行 MCP 入站服务。各目录只维护当前操作与限制，不另立架构路线图。
