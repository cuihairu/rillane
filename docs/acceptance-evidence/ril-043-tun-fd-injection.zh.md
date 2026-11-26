# RIL-043 移动 FFI — TUN fd 注入面（本地可核验段，2026-11-26）

## 交付内容

`crates/rillane-ffi/tests/tun_fd_injection_contract.rs`（5/5 绿）钉住验收
条款「核心不假定移动 VPN 与宿主同 OS 进程」的注入半边：宿主经
`rillane_ffi_tun_start(handle, fd)` 移交 tun fd，本门覆盖宿主递来坏 fd
时的行为。

- **具名拒绝**：NULL 句柄与负 fd 都应答 `-1` 并留可诊断的具名
  `last_error`（「句柄或 fd 无效」）；拒绝路径不触碰 `tun_fd` 观测面。
  `tun_stop(NULL)` 保持具名缺席形态。
- **确定性坏 fd**：远超 `nr_open` 的 fd 号（1_000_000_000——进程内不可能
  打开，无竞态）必须以具名「TUN 启动失败」理由失败，且句柄不被污染：
  stats 的 `tun_fd` 观测面保持未挂载标记 `-1`、句柄仍存活（`is_running`
  照答）、未挂载 `tun_stop` 保持幂等、随后挂载真实 fd（socketpair 替身，
  EOF 自然收尾）照常成功——失败不得留下半挂载状态。
- **幂等**：未挂载的新鲜句柄上 `tun_stop` 可重复（0, 0），观测面不动。
- **源纪律文本门**（与符号门同一纪律的文本扫描）：`tun_start_inner` 里
  `try_clone` 必须先于 `tun_fd.store(fd)`（EBADF 路径走不到 store）、
  句柄构造初始 `tun_fd` 必须为 `-1`、TUN 线程退出必须复位为 `-1`。
  `#[should_panic]` 自证抹掉 `try_clone` 行后对账器点名缺失的顺序。

## 本门抓到并修复的缺陷

修复前驱动坏 fd 场景会 **abort 整进程**：`OwnedFd::from_raw_fd` 接管了
从未打开的 fd，`try_clone` 失败后 `File` drop 发出 `close(EBADF)`，Rust
std 视为 IO safety 违规（abort）。在 Android 上这会把宿主侧
double-detach 一类缺陷放大成整个 app 崩溃，而非具名 `-1`。修复
（`crates/rillane-ffi/src/lib.rs`，unix `tun_start_inner`）：接管所有权
**之前**先以 `fcntl(fd, F_GETFD)` 验证 fd——陈旧/伪造 fd 现在以具名
「TUN 启动失败：fd N 未打开」失败，句柄保持完全可用且可重挂载。

## 诚实边界

真实 TUN 设备数据通路（对真隧道的 ICMP 轮转、经
`ParcelFileDescriptor.detachFd()` 的各平台 fd 移交）属 RIL-043 真机
批次，主勾选保持关闭。本门里的 socketpair 只证明真实 fd 的可挂载性。

提交前已跑全 workspace 测试、`cargo fmt --all -- --check` 与
`-D warnings` clippy，全绿。未创建任何版本号、tag 或正式 GitHub Release。
