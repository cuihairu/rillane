# RIL-085 三桌面进程端到端验收矩阵（本地可核验段，2026-11-26）

## 本次交付

机器可读验收账本 `contracts/desktop_e2e_matrix_v1.json`：RIL-085 验收条款 ×
三桌面平台（Linux / Windows / macOS），由
`crates/rillane-platform/tests/desktop_e2e_matrix_contract.rs` 钉门（9/9 绿）。
每格只允许一种诚实状态，可指认时附仓内证据文件路径：

| 状态 | 含义 |
| --- | --- |
| `verified_local` | 本机真实可执行测试核验 |
| `verified_device` | 真机核验，证据文档在仓内 |
| `partial` | 只核验了邻近面（如 curl HTTP 客户端，非浏览器） |
| `needs_runtime` | 需图形桌面会话驱动浏览器/游戏 |
| `needs_mac_ssh` | mac 真机未接入（RIL-036/037/038 未决） |

对账器钉住封闭的九条款集与三平台集；所有 `verified_*` 格必须指向真实文件；
`needs_*` 格不得携带证据；macOS 除平台无关的「规则来源可查」面外一律
`needs_mac_ssh`；两处 Linux 进程门保持诚实（权限不足格必指向真实 `setpriv`
进程测试、端口复用格必指向真实双 helper 进程测试）；两个核心场景永不标实测。
三个 `#[should_panic]` 自证门故意篡改矩阵（伪造 macOS 实测、伪造浏览器轨迹
实测、陈旧 Linux 权限格），证明对账器会点名失败。

## 逐条款证据账

- **TCP / UDP / 名称+路径 / PID 复用（Linux）**：`verified_local`，凭据
  `crates/rillane-platform/tests/owner_linux_contract.rs`——真实回环 TCP/UDP
  归因到测试进程；`readlink /proc/<pid>/exe` 出完整路径；`comm` 按内核 15
  字符上限如实标截断；启动时间戳在场。
- **TCP / UDP / 名称+路径 / PID+端口复用 / 权限不足（Windows）**：
  `verified_device`，凭据 RIL-032/033/034/035 证据文档——真实 `ping.exe`
  ICMP、`curl.exe` HTTP 事务、`Get-Process.StartTime` /
  `Win32_Process.CreationDate`、标准用户 token 下 `OpenProcess` err=5、
  UDP 固定口 A→B 与 TCP `SO_REUSEADDR` 重绑 C→D 缓存翻转。
- **规则来源可查**：三桌面均 `verified_local`——订阅→代际→Explain→实际出口
  决策面平台无关（`crates/rillane-routing/tests/subscription_to_execution.rs`、
  `crates/rillane-routing/tests/explain_contract.rs`）。这**不**表示该平台上的
  真实流量已归因到规则。
- **权限不足（Linux）**：`verified_local`，凭据
  `crates/rillane-platform/tests/owner_linux_permission_contract.rs`——`sudo -n` +
  `setpriv` 以 `nobody`(65534) 拉起真实 helper 进程；连接 socket inode 在
  `/proc/net/tcp` 可见，但跨 uid 的 `/proc/<pid>/fd` 不可列——
  `ProcOwnerResolver` 返回 `Unknown(PermissionDenied)`（具名、不伪造、不降级为
  `NotFound`）。同一监听口上同 uid 的控制连接仍归因到本进程，证明盲区是跨 uid
  而非解析器整体失效。无 sudo/setpriv 环境打印 `skip`，不冒充实测。
- **端口复用（Linux）**：`verified_local`，凭据
  `crates/rillane-platform/tests/owner_linux_port_reuse_contract.rs`——两个独立
  helper 进程连同一目标、本地端口各异；每条 `(本地端口, 远端)` 元组归到正确
  helper pid、启动身份在场、零串扰。这补上了「PID/端口复用实测」此前仅有
  Windows P4/P4b 真机证据的 Linux 半边。
- **macOS**：除规则来源外所有条款皆 `needs_mac_ssh`——RIL-036/037/038
  未决；cross-check 与单测不升格为真机验收。

## 诚实边界——核心场景未实测

RIL-085 的交付目标是「相同目标浏览器/两个游戏的分组轨迹及故障样例」。
核心场景在 Linux 标 `needs_runtime`、Windows 标 `partial`、macOS 标
`needs_mac_ssh`：

- Windows 有真实 `curl.exe` HTTP 事务（`ril-033`）与服务崩溃/切网/卸载恢复
  （`ril-035`），但那是 HTTP 客户端面与服务恢复面，**不是**浏览器/游戏分组
  轨迹，也不是浏览器/游戏故障样例。
- Linux 有归属与路由决策测试，但没有图形桌面会话驱动浏览器或两款游戏。
- macOS 完全没有真机接入。

RIL-085 主勾选保持关闭。依赖 RIL-038（Intel mac SSH 接入）仍未决，且浏览器/
游戏分组轨迹需交互式桌面夹具，尚未运行。本段仅交付本地可核验的验收账本，
依 RIL-150/RIL-090「内容可独立交付」先例办理。

提交前已跑全 workspace 测试、`cargo fmt --all -- --check` 与 clippy
`-D warnings`，全绿。未创建任何正式版本、tag 或 GitHub Release。
