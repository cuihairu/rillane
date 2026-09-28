# 系统路由与网络接管（现状：模型已建，实现未落地）

> 状态：**设计/未落地**（`crates/seep-platform::network`）· 相关：[architecture.md](architecture.md) · [design/positioning.md](design/positioning.md)（缺口 G2）· [design/roadmap.md](design/roadmap.md) S2 · todo P1-1..P1-3

## 执行摘要

系统级流量接管（TUN/redir + 进程/端口分流）是游戏加速场景的前提——代理入站抓不到不经过代理的应用流量。本模块的 trait 与数据模型已在 `seep-platform::network` 建成（五个子模块、约 3800 行），**但各平台实现均为占位，runtime 未接线，配置与 CLI 未落地**。本文如实标注现状与目标形态。

## 1. 已建成（模型层）

| 子模块 | 内容 | 状态 |
|--------|------|------|
| `tun.rs` | `TunProvider` trait、`TunConfig`（地址/路由/MTU）、`PacketInfo`/`PacketType`、`TunPacketStream`、`TunInterface<T: TunProvider>` | 模型完成；无真实设备实现 |
| `route.rs` | `RouteManager` trait、`RoutingConfig`/`RouteRule`/`RouteDestination`/`RouteType`（含校验与匹配逻辑） | 模型完成；无系统路由写入实现 |
| `filter.rs` | `PacketFilter` trait、`FilteringConfig`（`ProcessRule`/`PortRule`/`IpRule`/`DomainRule`/`ProtocolRule`/`ApplicationRule`）、`FilterStats` | 模型完成；无包过滤实现 |
| `dns.rs` | `DnsHandler` trait 与 DNS 代理/缓存/劫持/DoH 设计 | 模型完成；无运行实现（DNS 分流见 todo P2-8） |
| `platform.rs` | Linux/OpenWrt/Windows/macOS/Android/iOS 各 Provider/RouteManager/PacketFilter/DnsHandler 骨架 | **全部占位**：构造即告警"占位实现"，`read_packet`/`write_packet` 返回"未实现" |

## 2. 未落地（与代码一一对应）

- **无真实 TUN 设备**：任何平台都没有打开 `/dev/net/tun`、Wintun、utun 等的代码；占位实现即 `platform.rs` 现状（P1-1 落地 Linux 真实现）。
- **runtime 未接线**：`seep-runtime` 不存在 `TunIngress`/`TunEgress`，IP 包无法进入 `FlowRouter`（P1-2）。
- **配置缺区块**：`SeepConfig` 顶层只有 `control/telemetry/ingress/egress/routing`，没有 `network` 区块（mode: tun/redir、bypass/include、进程过滤）；`TunConfig`/`FilteringConfig` 仅存在于 platform crate，未进配置 schema（P1-3）。
- **CLI 缺命令**：`seepctl` 无 `route apply/clear`（P1-3）。
- **当前唯一可用能力**：`seepctl diagnose` 只读采集本机路由/DNS/接口快照，用于问题排查。

## 3. 目标形态（设计，未实现）

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
- 平台实现顺序：Linux（`/dev/net/tun` + policy routing + redir）→ OpenWrt（复用 Linux 路径，musl 静态）→ Windows(Wintun) / macOS(utun) / Android(VpnService) / iOS(NEPacketTunnel)。
- 进程维度会话：TUN 提供进程信息后，UDP 会话粘滞键的 `process_id` 字段（见 udp-dataplane.md §1.2）开始生效。

## 4. 验收对齐（todo P1-1..P1-3）

落地时以下列条目为验收口径（详见 todo.md）：

1. P1-1：Linux 集成测试中 tun 设备创建、IP 包捕获进入 FlowRouter；
2. P1-2：按进程/端口规则将游戏流量路由至 mesh 链路，bypass 默认安全；
3. P1-3：`SeepConfig.network` 区块 + `seepctl route apply/clear` 幂等可用、失败回滚。

本文「未落地」清单即 P1 三条的前置基线；实现合入后应同步更新本文 §2 为现状描述。
