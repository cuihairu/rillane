# RIL-086 六平台并行场景验收矩阵（本地可核验段，2026-11-27）

## 本次交付

`contracts/parallel_scenario_matrix_v1.json`：RIL-086 七项验收条款 × 六平台的
机器可读账本，由 `crates/rillane-platform/tests/parallel_scenario_matrix_contract.rs`
钉门（10/10 绿）。每格只允许四种诚实状态：

| 状态 | 含义 |
| --- | --- |
| `verified_local` | 本机真实可执行测试核验 |
| `verified_device` | 真机核验，证据文档在仓内 |
| `partial` | 只核验协议/配置/调度面或单应用面 |
| `needs_device` | 平台真机未接入/签名面未过 |

对账器钉住封闭的七条款/六平台集；所有 `verified_*` 格必须指向真实文件；
`needs_device` 格不得携带证据（cross-check 与产物不升格为验收）；任何平台
不得把核心「真实网站/QUIC 与游戏并行转发矩阵」标为已验。五个 `#[should_panic]`
自证门故意篡改矩阵，证明对账器会点名失败。Linux `dual_stack` 与 `dns` 门另
要求各自 `verified_local` 证据指向真实运行时测试——前者源码必须真的以并行
方式发起 IPv4（ATYP 0x01）与 IPv6（ATYP 0x04）目标，后者必须真跑并发查询
并断言 singleflight/缓存/冲刷；纯配置面来源会被拒。

## 逐条款证据账

- **MTU、退出恢复、不支持项拒绝/降级（Linux）**：`verified_local`。
  WireGuard MTU 超限归 Timeout 且保留粘滞映射
  （`crates/rillane-core/tests/udp_egress_selection.rs`），connector 侧拦截
  超限包（`crates/rillane-protocols/tests/udp_egress.rs`）；SIGTERM teardown
  与 `CrashJournal` 重复启动无残留
  （`crates/rillane-platform/src/network/recovery.rs`）；原生 QUIC/WireGuard
  承载不被强制包装进 TCP 栈（`crates/rillane-core/tests/underlay_contract.rs`）。
- **切网、退出恢复（Windows）**：`verified_device`。真机 `route delete` →
  `DefaultRouteChanged` → `reassert_routes` 幂等重放；SCM 崩溃重启 →
  `SVC RECOVER` 撤销 → 卸载清理，凭据
  `docs/acceptance-evidence/ril-035-windows-service-recovery.md`。
- **双栈（Linux）**：回环切片 `verified_local`。配置面测试
  （`crates/rillane-config/tests/network_block.rs`）加真实运行时测试
  （`crates/rillane-runtime/tests/dual_stack_parallel_acceptance.rs`）：同一
  运行时实例（SOCKS5 入口 → direct 出口）**并行**承载 IPv4（ATYP 0x01）与
  IPv6（ATYP 0x04）两条回环流，各自逐字节回显 64 KiB。同测试还覆盖同一实例
  同时绑 IPv4/IPv6 两个 SOCKS5 入口。仅回环实测——本机无 v6 默认路由；不声称
  外网 v6 可达性或六平台矩阵。
- **DNS 并行场景（Linux）**：回环切片 `verified_local`。配置测试
  （`crates/rillane-config/tests/dns_block.rs`）加真实运行时测试
  （`crates/rillane-runtime/tests/dns_parallel_acceptance.rs`）：活 `DnsService`
  本地 UDP 监听对同一冷名接收八个并发客户端查询，经 mock 上游 singleflight
  合并为一次上游交换（防 stampede）；重复查询走缓存不触上游；`clear_cache`
  后重回上游；不同域名独立解析不串答。仅回环——不测 TUN 劫持、公网解析器、
  六平台矩阵。
- **DNS、双栈、单应用流量（Windows）**：`partial`。真实 `ping.exe` ICMP/UDP
  与 `curl.exe` HTTP 事务入 Wintun 封环（`ril-033`）；旁路 UDP 真查询
  `223.5.5.5` 有应答（拨号不循环）；netsh DNS 劫持端到端未跑（会改用户网络配置）。
- **QUIC + 调度（Linux）**：核心条款只 `partial`。TUIC 会话复用（单 QUIC
  连接承载多 Connect）与公平调度（持续下载时游戏小包 0ms 头部服务、网页不
  饥饿）都是真实测试——但那是协议/调度面，不是真实网站/QUIC 与游戏并行
  转发运行。
- **macOS / OpenWrt / Android / iOS**：除平台无关测试与构建矩阵可算
  `partial` 外，所有条款皆 `needs_device`。RIL-039/042/046/049 未决；
  cross-check、模拟器 ping、构建产物均不升格为真实并行场景验收。

## 诚实边界——核心矩阵未实测

RIL-086 交付目标是真实网站/QUIC 与游戏并行转发矩阵，逐平台报告双栈、DNS、
MTU、切网与退出恢复，不支持项须明确拒绝或按配置降级。该核心矩阵**尚未运行**。
Linux 有协议/调度单测与新增的真实 IPv4/IPv6 回环转发测试；Windows 只有
ping/curl 单应用入环证据；都不是并行的浏览器/游戏运行。RIL-086 主勾选保持
关闭；RIL-039/042/046/049 真机依赖未决。

提交前已跑全 workspace 测试、`cargo fmt --all -- --check` 与 clippy
`-D warnings`，全绿。未创建任何正式版本、tag 或 GitHub Release。
