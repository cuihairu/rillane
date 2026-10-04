# 系统路由与网络接管（现状：Linux TUN 数据面已接线）

> 状态：**Linux 数据面已接线**（P1-1 设备/路由真实现 + P1-2 TunIngress 接 runtime + P1-3 network 区块 + 控制面 route 三端点与 `seepctl route` CLI；跨平台 provider 未落地）· 相关：[architecture.md](architecture.md) · [design/positioning.md](design/positioning.md)（缺口 G2）· [design/roadmap.md](design/roadmap.md) S2 · todo P1-1..P1-3

## 执行摘要

系统级流量接管（TUN/redir + 进程/端口分流）是游戏加速场景的前提——代理入站抓不到不经过代理的应用流量。**2026-10-03 起 Linux 路径真实可用**：`seep-platform::network::linux`（LinuxTunProvider / LinuxRouteManager 真实现，`/dev/net/tun` + TUNSETIFF + main 表显式路由 + AppliedStep 回滚）+ `seep-runtime::tun_ingress`（TunIngress 作为新 ingress 类型：UDP 全链路 T3、smoltcp TCP 用户态终结 T4、`seep_tun_*` 指标族 T5）+ `SeepConfig` 顶层 `network` 区块接线 seepd（P1-3 R1）+ 控制面 `/network/route/{apply,clear,status}` 三端点与 `seepctl route apply [--dry-run]/clear/status` CLI（P1-3 R2–R4，1befbe7——RouteControl 契约 `apply_desired(dry_run)`/`clear`/`status`：幂等重放/逆序还原/E7 批内逆序回滚/E10 明确口径）。本机双场景走查实测（2026-10-03）：**同一目标 1.0.0.1 上按进程名分流**（python3→web-node、curl→game-node）、**按端口分流**（NTP UDP:123→game-node），三腿同机并发互不干扰；数据面本体延迟 ≈ 直连（UDP +2.6ms、TCP 热流 connect 1ms/首字节 ≈ 直连），每流首包付一次进程归因 `/proc` 扫描（本机 593 进程实测 60–86ms，TTL 30s 含负缓存）。**仍未落地**：macOS/Windows/Android/iOS 平台 provider（`platform.rs` 死稿未编译）、`filter.rs` 包过滤面（现由 routing 引擎 `MatchCondition` 承担）。实现级设计见 [design/tun-dataplane.md](design/tun-dataplane.md)（P1-1/P1-2）与 [design/network-route.md](design/network-route.md)（P1-3）。

## 1. 已建成（模型层 + 平台实现）

| 子模块 | 内容 | 状态 |
|--------|------|------|
| `tun.rs` | `TunProvider` trait、`TunConfig`（地址/路由/MTU）、`PacketInfo`/`PacketType`、`TunPacketStream`、`TunInterface<T: TunProvider>` | 模型完成；**Linux 真实现已落地**（`network/linux.rs` LinuxTunProvider，c076fb8/75c7747） |
| `route.rs` | `RouteManager` trait、`RoutingConfig`/`RouteRule`/`RouteDestination`/`RouteType`（含校验与匹配逻辑） | 模型完成；**Linux 真实现已落地**（LinuxRouteManager = main 表显式路由 + AppliedStep 回滚，92f12ba） |
| `filter.rs` | `PacketFilter` trait、`FilteringConfig`（`ProcessRule`/`PortRule`/`IpRule`/`DomainRule`/`ProtocolRule`/`ApplicationRule`）、`FilterStats` | 模型完成；无包过滤实现——进程/端口分流实际走 routing 引擎 `MatchCondition::Process/Port` + TunIngress 首包归因（2026-10-03 口径） |
| `dns.rs` | `DnsHandler` trait 与 DNS 代理/缓存/劫持/DoH 设计 | 模型完成；**运行实现已落地**（`dns_engine.rs` EngineDnsHandler + `DnsService`，todo DNS 子系统 M0–M1，2026-10-02） |
| `platform.rs` | **仅 macOS 5 个占位类型**（Utun/Tap Provider、RouteManager、PacketFilter、DnsHandler 草稿）；**未参与编译**且启用即编译失败（占位大面积缺 trait 方法） | 死稿：P1-1 已按 [design/tun-dataplane.md](design/tun-dataplane.md) §1.4 以新模块 `network/linux.rs` 重写接入——此文件仍保持不编译，非填充对象 |

## 2. 现状对照（2026-10-03 回填）

**已接线（代码 + 实测验收）**：

- **真实 TUN 设备（Linux）**：`/dev/net/tun` + TUNSETIFF、包读写循环、捕获 IP 包进入 FlowRouter——`network/linux.rs`（T0–T2：c076fb8 trait 裁剪+四工厂分派、75c7747 设备生命周期+读写+捕获钉子、92f12ba RouteManager+AppliedStep 回滚）。root 全权集成测 e2e 过：设备创建 → 应用路由 → 五元组进料 → 归因 → 回显 → teardown 路由回滚 + 设备销毁。
- **runtime 接线（TUN 作为新 ingress 类型）**：`seep-runtime` `TunIngress` 注入 `ingress_endpoints["tun"]` 与 socks5 等入口同场启动（2026-10-05 起 validate 允许 TUN-only：空 ingress 仅 `network.mode=tun` 放行，TUN 即入口；此前 MVP 要求 ≥1 非 TUN 入口）——**T3 a9f11dc**：五元组流表/首包 `/proc` 归因（`process.*` 注解 → `MatchCondition::Process` 生效）/auto-bypass 三源防环/§2.9 事件枚举单循环（tun guard 单任务独占，读写清扫 select 收口）；**T4 b5785c2**：smoltcp 0.14 TCP 用户态栈（首 SYN 粘滞路由 → Established 交接 `FlowOutput::forward`、SmolTcpStream 桥接 AsyncRead/Write、kick 事件驱动 + sweep 复用的单 poll 驱动点）；**T5 7a3024d**：`seep_tun_*` 指标族（packets/bytes 按 direction、flows_active、bypass_dropped、parse_errors、unknown_flow、process_attr_miss 恒渲染）。
- **配置区块**：`SeepConfig` 顶层 `network`（`mode: tun` + `tun`/`routing` 镜像子块）+ seepd 派生开关（`enable_network_virtualization`/`network_config`，NetworkManager 让路裁决）——P1-3 R0/R1，随 1e1a7c0 合入；`network.mode: tun` 即启用 TUN ingress。
- **路由控制面 + CLI（P1-3 R2–R4，1befbe7）**：`LinuxRouteManager` RouteControl 契约（`apply_desired(dry_run)` planner/执行/去重入账同源、`clear` 逆序还原、`status` 快照；E7 失败批内逆序回滚不入账、E10 = 接口未建明确口径）→ seepd 三端点 `POST /network/route/apply`（`{"dry_run"}`，无 TUN → 503）/ `POST /network/route/clear`（E8 空表幂等）/ `GET /network/route/status`（mode/device/mtu/up/applied）→ `seepctl route apply [--dry-run]/clear/status`（`plan:`/`ok:`/`undo:` 逐行 argv 表）；启动 apply ≡ CLI apply 同一方法、TunIngress teardown 自动还原。
- **双场景并发走查**（本机 seepd 实测，2026-10-03，配置样例 `config/seep-demo-dual.yaml`）：三腿同机并发——网页 python3 TCP→web-node（默认规则）、游戏 curl TCP→game-node（`process: ["curl"]` 规则）、游戏 NTP UDP:123→game-node（`port: [123]` 规则）——日志逐流 `流建立（交接）node=... process=...` 可对账；前后延迟对比见执行摘要。

**仍未落地**：

- **跨平台 provider**：macOS/Windows/Android/iOS 未实现（`platform.rs` 死稿不编译；Android VpnService 仅 seep-ffi 最小 ICMP 通路，TCP/UDP 真代理路径归 TunIngress 移植面）。
- **`filter.rs` 包过滤面**：trait 与配置模型在，无独立实现——分流由 routing 引擎承担（见 §1 口径）。
- **direct 出口自环盲区（走查发现）**：include 的 `/32` 路由把 seep(root) 自身 direct 出站也拽回 TUN（§2.7 auto-bypass 对 direct 出口无 server 字面量可排）——走查用 `ip rule uidrange 0-0` 逃逸绕行；正解（seepd 出站 socket SO_MARK + fwmark 逃逸规则）归后续增量。
- **当前唯一只读能力**：`seepctl diagnose` 采集本机路由/DNS/接口快照，用于问题排查（不变）。

## 3. 目标形态（Linux 路径已实现）

```
应用流量 ──► TUN 设备（TunProvider.read_packet）
              │  IP 流重组（五元组 → 流）
              ▼
        PacketFilter（进程/端口/bypass 规则；bypass：局域网/DNS/管理口 默认安全）
              ▼
        FlowContext（注入进程 ID、端口、协议）
              ▼
        FlowRouter ──► 与代理入站完全相同的路由/出站/链路管线
```

- TUN 只是**新增一种 ingress**：路由引擎与出站协议栈对 TUN 流量与 socks5 流量一视同仁（positioning.md §2.2）。
- UDP 流量经 TUN 进入后依赖 S1 UDP 全链路（[udp-dataplane.md](design/udp-dataplane.md)）；QUIC 流量以 `TargetProto::Quic` 标记（枚举已存在）。
- 平台实现顺序：Linux（已落地）→ OpenWrt（复用 Linux 路径，musl 静态）→ Windows(Wintun) / macOS(utun) / Android(VpnService) / iOS(NEPacketTunnel)。
- 进程维度会话：TUN 提供进程信息后，UDP 会话粘滞键的 `process_id` 字段（见 udp-dataplane.md §1.2）开始生效。

## 4. 验收对齐（todo P1-1..P1-3）

1. P1-1：**已过**——Linux 集成测试中 tun 设备创建、IP 包捕获进入 FlowRouter（skip 守卫两周期 + root 全权 e2e）；
2. P1-2：**已过**——按进程/端口规则分流（走查实测：同目标 1.0.0.1，python3→web-node、curl→game-node；UDP:123→game-node），bypass 默认安全（默认规则 ∪ 用户规则 ∪ auto-bypass 三源）；mesh 链路承载形态未纳入本轮走查（规则面同源，节点为 direct 演示）；
3. P1-3：**已过**——`SeepConfig.network` 区块 + seepd 派生开关（1e1a7c0）+ 控制面三端点与 `seepctl route apply [--dry-run]/clear/status`（1befbe7）；apply 后 main 表显式路由符合预期、clear 完全还原（仅撤 seep 所加步骤）、重复执行幂等（replace + 去重入账）、失败自动回滚（E7 批内逆序）——单测（mock executor/REST 形状/CLI 渲染）+ §7.2 守卫集成（`route_apply_clear_roundtrip`：dry-run 零变化/apply×2 前缀唯一/status 对账/clear 回基线）钉住。

本文随实现合入持续回填；本节状态口径 2026-10-03。
