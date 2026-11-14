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

## 旁路与恢复边界

纳入 TUN 的目标可能包含代理服务器、上游 DNS 或 daemon 自身的出站。配置与运行时防环应共同覆盖它们；当前 TCP `SO_MARK` 路径不能证明 QUIC/UDP 全部已保护。未知组合应先在受控环境验证。

当前路由管理器记录自己应用的步骤并提供撤销。它不等于 v1 的跨平台路由/DNS/持久化事务；崩溃、切网和权限变化都需独立验收。诊断可用 `rillanectl diagnose`，输出可能含配置、日志和网络身份，分享前检查。

## v1 验收要求

三桌面测试同目标不同本机进程的 TCP/UDP 路由，以及权限不足、PID/端口复用。所有平台测试双栈、DNS、防环、MTU、切网和退出恢复；游戏/网页并行不使用 UDP=游戏的分类假设。具体依赖与门禁统一在根目录 `todo.md`。
