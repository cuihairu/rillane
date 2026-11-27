# RIL-043 mobile FFI — buffer ownership & concurrency face (local verifiable segment, 2026-11-27)

## What is delivered

`crates/rillane-ffi/tests/ownership_concurrency_contract.rs` (2/2 green,
5 consecutive stable runs) pins the pull-model half of the acceptance
clause "buffer ownership, threads, cancellation, ABI version". The FFI is
pull-model by construction — no callbacks, no shared queues — so the
host-side hazards that remain are buffer ownership, concurrent queries,
and ABI-version drift. All three are pinned against a real running
runtime (real SOCKS5 ingress, real transfer):

- **Heap vs static ownership families**: two `rillane_ffi_stats_json`
  calls on a live handle return distinct non-NULL pointers (per-call
  `CString` heap allocations — a static buffer returned twice would make
  the host's first free corrupt the second read), each parsing as valid
  JSON against the frozen stats subset face (`uptime_seconds`,
  `total_connections`, `is_running`, `tun_fd`; `is_running == true`).
  `rillane_ffi_version()` is the opposite family: two calls return the
  **same** pointer (process-lifetime static, documented as never freed),
  and its text must equal the root `Cargo.toml`
  `[workspace.package].version` verbatim (the `version.workspace = true`
  inheritance chain) — bumping the version without passing this gate
  fails.
- **Absence encoding**: querying with a NULL handle answers NULL (no
  garbage pointer); `rillane_ffi_free_string(NULL)` is tolerated.
- **last_error take-once**: after a failed start (invalid YAML) the error
  string is handed out exactly once — the second read is NULL — and the
  handed-out buffer is host-freed.
- **Concurrent queries do not stall the data plane**: 4 threads × 25
  iterations run stats/flows/nodes queries on one shared handle while a
  real transfer (hand-rolled SOCKS5 no-auth handshake, IPv4 CONNECT,
  8192-byte payload) traverses ingress → direct egress → echo server.
  Every byte comes back exact (no interference), every concurrent flows/
  nodes answer carries `schema_version == 1` (no torn/generation-mixed
  replies), and the echo server confirms it received the full payload
  length. The two tests serialize on a port guard (cargo runs tests in
  parallel threads; both use fixed ports).

## Honest boundary

- Cancellation as a device-facing concept lives in the host lifecycle
  gate (RIL-044 stop face); the FFI here has no cancel verb beyond
  `rillane_ffi_stop`.
- Public `packetFlow` batches (iOS NE) and real-device ABI batches are
  RIL-094 device-side work, not covered here.
- Dangling-handle dereference is UB and untestable; the host-side
  "clear references after stop" discipline is pinned by the host_lifecycle
  Kotlin text gate, and this gate does not pretend to cover it.
