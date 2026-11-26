# RIL-043 mobile FFI — TUN fd injection face (local verifiable segment, 2026-11-26)

## What is delivered

`crates/rillane-ffi/tests/tun_fd_injection_contract.rs` (5/5 green) pins the
fd-injection half of the acceptance clause "core does not assume the mobile
VPN and host share an OS process": the host hands its tun fd to
`rillane_ffi_tun_start(handle, fd)`, and this gate covers what happens when
the host hands over garbage.

- **Named rejections**: NULL handle and negative fd both answer `-1` with a
  named `last_error` ("句柄或 fd 无效") that the host can surface for
  diagnosis; the rejection path never touches the `tun_fd` observation face.
  `tun_stop(NULL)` keeps its named absence form.
- **Deterministically bad fd**: a fd number far beyond `nr_open`
  (1_000_000_000 — impossible to have open in-process, so no race) must fail
  with the named "TUN 启动失败" reason and leave the handle untainted:
  the stats `tun_fd` observation face stays at its unmounted marker `-1`,
  the handle stays alive (`is_running` answers), unmounted `tun_stop` stays
  idempotent, and a subsequent mount of a real fd (socketpair stand-in,
  EOF-driven exit) succeeds — no half-mounted state survives a failure.
- **Idempotence**: `tun_stop` on an unmounted fresh handle is repeatable
  (0, 0) without moving the observation face.
- **Source discipline gate** (text scan, same discipline as the symbol gate):
  in `tun_start_inner`, `try_clone` must precede `tun_fd.store(fd)` (the
  EBADF path must not reach the store), the handle constructor must start
  `tun_fd` at `-1`, and the TUN thread exit must reset it to `-1`. A
  `#[should_panic]` self-test erases the `try_clone` line and proves the
  comparator names the missing order.

## Defect found and fixed by this gate

Driving the impossible-fd case against the pre-fix code aborted the whole
process: `OwnedFd::from_raw_fd` took ownership of an fd that was never open,
`try_clone` failed, and the resulting `File` drop issued a `close(EBADF)`
which Rust std treats as an IO-safety violation (`abort`). On Android that
turns a host-side double-detach bug into a full app crash instead of a
named `-1`. Fix (`crates/rillane-ffi/src/lib.rs`, unix `tun_start_inner`):
validate the fd with `fcntl(fd, F_GETFD)` **before** taking ownership —
a stale/fake fd now fails as a named "TUN 启动失败：fd N 未打开" error
while the handle stays fully usable and remountable.

## Honest boundary

Real TUN device data path (ICMP rotation against a real tunnel, per-platform
fd handoff via `ParcelFileDescriptor.detachFd()`) belongs to the RIL-043
device batch; the parent checkbox stays unchecked. The socketpair in this
gate proves mountability of a real fd only.

Full workspace tests, `cargo fmt --all -- --check`, and clippy with
`-D warnings` were run green before committing. No release version, tag, or
formal GitHub release was created.
