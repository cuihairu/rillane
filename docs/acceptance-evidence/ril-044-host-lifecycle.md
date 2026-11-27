# RIL-044 mobile host lifecycle — stop face (local verifiable segment, 2026-11-26)

## What is delivered

`crates/rillane-ffi/tests/host_lifecycle_contract.rs` (4/4 green) pins the
RIL-044 acceptance clause "stop is repeatable" on both of its halves:

- **Rust half (real host test)**: `rillane_ffi_stop(NULL)` is the documented
  idempotent-cleanup path — a stable `-1` plus a named `last_error`; every
  query (`is_running`/`stats`/`routing`/`nodes`/`dns_stats`/`dns_resolvers`/
  `flows`/`flow`/`tun_stop`) on a NULL handle answers with its stable absence
  form (-1 or NULL) without crashing; a real start → stop → second NULL stop
  sequence (the call shape a host produces after zeroing its handle) stays a
  stable absence; and start → stop → start brings up a fresh working instance
  (lifecycle is repeatable).
- **Kotlin half (text discipline gate)**: `RillaneVpnService.stopVpn()` must
  guard on a non-zero handle, call `RillaneFfi.stop(ffiHandle)` and zero the
  handle immediately after (within 120 chars — no other FFI call may sit
  between stop and zeroing, since the handle dangles per the Rust contract);
  both `onRevoke()` and `onDestroy()` must converge on `stopVpn()` (ordered
  teardown on authorization revocation plus idempotent bottom on destroy).
  A `#[should_panic]` self-test erases the zeroing line and proves the
  comparator names the missing discipline.

The stop contract itself: after `rillane_ffi_stop(h)` the handle dangles and
must not be reused — repeat-stop safety is deliberately composed from
NULL-tolerance (Rust) plus host-side handle zeroing (Kotlin), not from
keeping freed memory reachable.

## Honest boundary

At this segment's date, config/secret reference injection, network change
notification and bounded diagnostic IPC were still ahead. Their core halves
have since landed as separate local ledgers — [secret injection](./ril-044-secret-injection),
[network change](./ril-044-network-change) and
[bounded diagnostic IPC](./ril-044-diagnostic-ipc). The real RIL-043 device
face (buffer ownership, threading, backpressure, ABI version) and the Kotlin
host halves stay open.

"Core does not assume the mobile VPN and host share an OS process" is carried
structurally by the FFI fd-injection boundary (`rillane_ffi_tun_start`
receives the host-held tun fd; no shared stack objects, no same-process VPN
assumption) — recorded as posture, not claimed as device-verified. The parent
checkbox stays unchecked.

Full workspace tests, `cargo fmt --all -- --check`, and clippy with
`-D warnings` were run green before committing. No release version, tag, or
formal GitHub release was created.
