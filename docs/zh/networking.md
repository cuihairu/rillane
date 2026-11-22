# 系统接管与路由（当前实现）

[当前实现](architecture.md)与 [v1 平台设计](design/architecture-v1.md)分别描述代码和目标。本页保留现有 Linux 的使用入口，不继续维护旧版接管设计。

## 当前范围

Linux `TunIngress` 将捕获的 TCP/UDP 接入共享路由/出站。TCP 基于 smoltcp 的用户态栈，首包可查询 `/proc` 注入本机进程注解。现有名称受 comm 长度、权限与缓存约束，不能当成 v1 的完整路径/启动身份支持。

Windows/macOS 完整接管与本机身份、Android 完整转发和 iOS 公开 packetFlow 桥接都仍是实施任务。OpenWrt 不识别 LAN 客户端 PID；移动平台不承担桌面进程归因要求。

## 配置与操作

配置见 [network 字段](config.md)。启动配置通过 `RILLANE_CONFIG` 提供；实际支持的参数以 [CLI 参考](cli.md)与 `--help` 为准。

```bash
rillanectl route status
rillanectl route apply --dry-run
rillanectl route apply
rillanectl route clear
```

对应控制面为 `GET /network/route/status`、`POST /network/route/apply`、`POST /network/route/clear`。没有启用 TUN 的实例不能据此应用 TUN 路由。路由操作需要系统权限，使用前检查计划及管理通路。

## 透明接管

`network.mode = "transparent"` 以 socket 级接管替换 TUN 捕获：被接管的 TCP 不经 TUN 设备直接交入运行时，且每个已接受连接固定指向 `network.transparent.target`（一个已声明出口节点名）。接管是固定的，不再询问路由引擎——决策恒为 `direct(target)`。

内核面由 `network.transparent.mode` 二选一：

- `redirect`：conntrack `NAT REDIRECT` 把流量送到本机监听；已接受 socket 的原目标经 `SO_ORIGINAL_DST`（先 `SOL_IP` 再 `SOL_IPV6`）恢复。**未接管**直连没有 conntrack NAT 记录，getsockopt 返回 `ENOENT`——按具名拒绝上抛，绝不静默用本地地址回答，避免非透明直连被误当成透明流量。
- `tproxy`：监听 socket 在绑定非本地地址前置 `IP_TRANSPARENT`，TPROXY 连接保持原目标为 socket 本地地址，故**原目标 = accepted socket 的 `local_addr()`**。

规则是入口的系统副作用，与 TUN 入口持有设备/路由同构：入口启动时应用，停止（shutdown 或失败）时按逆序撤销。应用把 `EEXIST` 类「规则已存在」视为幂等成功；撤销把「无此规则」视为已撤销，重启与部分失败可收敛。

已声明边界：

- 仅 IPv4。规则规划为 IPv4，`IP_TRANSPARENT` 在 `SOL_IP` 上设置；IPv6 监听地址按名拒绝。IPv6 需 `IPV6_TRANSPARENT` 与 v6 规则面，归后续。
- 仅 TCP 应用面。UDP/QUIC 应用面不声明；[旁路与恢复边界](#旁路与恢复边界) 的 `SO_MARK` 结论仍成立。
- 仅 Linux，接管面需 `CAP_NET_ADMIN`（iptables/nftables 规则、`IP_TRANSPARENT`）。无该能力时监听构造与规则应用以点名权限错误失败，不静默降级。真实应用规则、经它连接并撤销的验收门只在具备该能力的机器上运行。
- 复用既有捕获管线：本入口只是共享流管线上的又一个入口端点，因此继承而非解决当前旁路/恢复限制。

### 库选型留证（无可用组合载体 → 自写）

按本仓规则「自写前须留证无库结论」。

- 入口 socket 载体：`tproxy-config` 7.0.10（dl 91,812，2026-11-18 更新）是配置工具而非可内嵌监听器；`cproxy` 4.2.1 为 AGPL-3.0-or-later——copyleft，与本仓 permissive-only 立场不兼容——且走 cgroup `net_cls`，非 REDIRECT/TPROXY 面；`xtp-rs` 0.1.0（dl 19）与 `trans_proxy` 0.8.0（dl 63）在此下载量下未证；`transparent_proxy` 0.4.0（2022-12-04）是独立服务而非入口适配器。
- 规则管理：`iptables` 0.6.0（MIT，dl 1,016,471）是 shell-out 包装，依赖仅 `lazy_static` 与 `regex`——regex argv，无事务/幂等语义；本仓已按 RIL-029 路由/`ip` 面的 argv `StepExecutor` 执行规则，再加一层 shell-out 无增益。`nftables-nl` 0.5.0（dl 85，2026-11-11）全新未证；`nftables` 0.6.3 / `nftables-async` 0.4.1 是 `nft` 二进制的 JSON 壳，只是换一种执行底座，不带来本仓 `AppliedStep` 的事务记录。
- 结论：无被采纳库带可组合入流管线的 REDIRECT/TPROXY 监听器，也无库带规则事务——在既有 argv 执行面上自写。

## 旁路与恢复边界

纳入 TUN 的目标可能包含代理服务器、上游 DNS 或 daemon 自身的出站。配置与运行时防环应共同覆盖它们；当前 TCP `SO_MARK` 路径不能证明 QUIC/UDP 全部已保护。未知组合应先在受控环境验证。

当前路由管理器记录自己应用的步骤并提供撤销。它不等于 v1 的跨平台路由/DNS/持久化事务；崩溃、切网和权限变化都需独立验收。诊断可用 `rillanectl diagnose`，输出可能含配置、日志和网络身份，分享前检查。

## v1 验收要求

三桌面测试同目标不同本机进程的 TCP/UDP 路由，以及权限不足、PID/端口复用。所有平台测试双栈、DNS、防环、MTU、切网和退出恢复；游戏/网页并行不使用 UDP=游戏的分类假设。具体依赖与门禁统一在根目录 `todo.md`。
