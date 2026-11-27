# RIL-044 移动宿主生命周期——停止面（本地可核验段，2026-11-26）

## 本次交付

`crates/rillane-ffi/tests/host_lifecycle_contract.rs`（4/4 绿）钉住 RIL-044
验收条款「停止可重复调用」的两侧半边：

- **Rust 半边（真实主机测试）**：`rillane_ffi_stop(NULL)` 是文档化的幂等
  收尾路径——稳定 `-1` + 具名 `last_error`；NULL 句柄上的全查询面
  （`is_running`/`stats`/`routing`/`nodes`/`dns_stats`/`dns_resolvers`/
  `flows`/`flow`/`tun_stop`）都以稳定缺席形（-1/NULL）作答、不崩；
  真实 start → stop → 二次 NULL stop（宿主清零句柄后的调用形态）保持
  稳定缺席；start → stop → start 能起新实例且查询照常（生命周期可重复）。
- **Kotlin 半边（文本纪律门）**：`RillaneVpnService.stopVpn()` 必须守卫
  非零句柄、调 `RillaneFfi.stop(ffiHandle)` 并**立即**清零句柄（120 字符
  内不得插入别的 FFI 调用——按 Rust 契约 stop 后句柄悬空）；`onRevoke()`
  与 `onDestroy()` 都必须收敛到 `stopVpn()`（授权撤销时有序收尾 + 销毁时
  幂等兜底）。`#[should_panic]` 自证门抹掉清零行，证明对账器会点名该纪律。

停止契约本身：`rillane_ffi_stop(h)` 后句柄悬空、不得再用——重复停止安全
由「NULL 容忍（Rust）+ 宿主清零句柄（Kotlin）」组合而成，不是让已释放内存
继续可达。

## 诚实边界

本段交付时，配置/秘密引用注入、网络变化通知、有界诊断 IPC 尚在前方；
其核心半边已分别作为本地账本交付——[秘密注入](./ril-044-secret-injection.zh)、
[网络变化](./ril-044-network-change.zh)、[有界诊断 IPC](./ril-044-diagnostic-ipc.zh)。
RIL-043 真机面（缓冲所有权/线程/背压/ABI 版本）与 Kotlin 宿主半边保持开放。
「核心不假定移动 VPN 与宿主同 OS 进程」由 FFI fd 注入边界结构性承载
（`rillane_ffi_tun_start` 接收宿主持有的 tun fd；无共享栈对象、无同进程
VPN 假设）——记录为姿态，不冒充真机已验。主勾选保持关闭。

提交前已跑全 workspace 测试、`cargo fmt --all -- --check` 与 clippy
`-D warnings`，全绿。未创建任何正式版本、tag 或 GitHub Release。
