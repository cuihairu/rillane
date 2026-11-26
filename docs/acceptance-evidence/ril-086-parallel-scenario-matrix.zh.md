# RIL-086 六平台并行场景验收矩阵（本地可核验段，2026-11-26）

## 本次交付

`contracts/parallel_scenario_matrix_v1.json`：RIL-086 七项验收条款 × 六平台的
机器可读账本，由 `crates/rillane-platform/tests/parallel_scenario_matrix_contract.rs`
钉门（6/6 绿）。每格只允许四种诚实状态：

| 状态 | 含义 |
| --- | --- |
| `verified_local` | 本机真实可执行测试核验 |
| `verified_device` | 真机核验，证据文档在仓内 |
| `partial` | 只核验协议/配置/调度面或单应用面 |
| `needs_device` | 平台真机未接入/签名面未过 |

对账器钉住封闭的七条款/六平台集；所有 `verified_*` 格必须指向真实文件；
`needs_device` 格不得携带证据（cross-check 与产物不升格为验收）；任何平台
不得把核心「真实网站/QUIC 与游戏并行转发矩阵」标为已验。两个 `#[should_panic]`
自证门故意篡改矩阵，证明对账器会点名失败。

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
Linux 只有协议与调度单测；Windows 只有 ping/curl 单应用入环证据；二者都不是
并行的浏览器/游戏运行。RIL-086 主勾选保持关闭；RIL-039/042/046/049 真机依赖
未决。

提交前已跑全 workspace 测试、`cargo fmt --all -- --check` 与 clippy
`-D warnings`，全绿。未创建任何正式版本、tag 或 GitHub Release。
