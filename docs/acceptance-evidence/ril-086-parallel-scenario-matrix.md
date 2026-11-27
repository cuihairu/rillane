# RIL-086 six-platform parallel scenario acceptance matrix (local verifiable segment, 2026-11-27)

## What is delivered

`contracts/parallel_scenario_matrix_v1.json` is a machine-readable ledger for
RIL-086's seven acceptance clauses × six platforms, enforced by
`crates/rillane-platform/tests/parallel_scenario_matrix_contract.rs` (10/10 green).
Each cell uses one honest status:

| Status | Meaning |
| --- | --- |
| `verified_local` | Verified by a real test executable on this machine |
| `verified_device` | Verified on real hardware, evidence doc checked in |
| `partial` | Only the protocol/config/scheduling surface or a single application verified |
| `needs_device` | Platform hardware not connected / signature not available |

The comparator pins the closed seven-clause / six-platform sets, requires every
`verified_*` cell to point at a real repository file, forbids evidence on
`needs_device` cells (no cross-check or artifact promoted to acceptance), and
forbids any platform from marking the core "real website/QUIC + game parallel"
matrix as verified. Five `#[should_panic]` self-tests corrupt the matrix to prove
the comparator bites. Linux `dual_stack` and `dns` gates additionally require
the `verified_local` cells to point at real runtime tests — one that issues
IPv4 (ATYP 0x01) and IPv6 (ATYP 0x04) targets in parallel, and one that drives
concurrent DNS queries with singleflight/cache/flush assertions. A config-only
source is rejected.

## Evidence ledger by clause

- **MTU, exit recovery, unsupported reject/degrade (Linux)**: `verified_local`.
  WireGuard MTU oversize is classified as Timeout with sticky mapping retained
  (`crates/rillane-core/tests/udp_egress_selection.rs`) and oversize packets are
  dropped at the connector (`crates/rillane-protocols/tests/udp_egress.rs`);
  SIGTERM teardown plus `CrashJournal` leaves no residue on repeat start
  (`crates/rillane-platform/src/network/recovery.rs`); native QUIC/WireGuard
  underlays are not forced onto the TCP wrapper stack
  (`crates/rillane-core/tests/underlay_contract.rs`).
- **Network change / exit recovery (Windows)**: `verified_device`. Real
  `route delete` → `DefaultRouteChanged` → idempotent `reassert_routes`, and
  SCM crash restart → `SVC RECOVER` undo → clean uninstall, per
  `docs/acceptance-evidence/ril-035-windows-service-recovery.md`.
- **Dual-stack (Linux)**: `verified_local` for the loopback slice. Config-surface
  tests (`crates/rillane-config/tests/network_block.rs`) plus a real runtime
  test (`crates/rillane-runtime/tests/dual_stack_parallel_acceptance.rs`) where
  one Runtime instance (SOCKS5 ingress → Direct egress) carries an IPv4
  (ATYP 0x01) and an IPv6 (ATYP 0x04) loopback stream **concurrently**, each
  round-tripping 64 KiB byte-exactly. The same test also exercises two SOCKS5
  ingress bindings (v4 + v6) on one instance. This is loopback only — this
  machine has no IPv6 default route; no external v6 reachability or six-platform
  matrix is claimed.
- **DNS, parallel scenario (Linux)**: `verified_local` for the loopback slice.
  Config tests (`crates/rillane-config/tests/dns_block.rs`) plus a real runtime
  test (`crates/rillane-runtime/tests/dns_parallel_acceptance.rs`) where a live
  `DnsService` local UDP listener serves eight concurrent client queries for one
  cold domain through a mock upstream: singleflight collapses them to a single
  upstream exchange (stampede defense), repeat queries hit the cache without
  touching the upstream, `clear_cache` forces a fresh upstream round, and
  distinct domains resolve independently. Loopback only — no TUN hijack, no
  public resolver, no six-platform matrix claimed.
- **DNS, dual-stack, single-application traffic (Windows)**: `partial`.
  Real `ping.exe` ICMP/UDP and `curl.exe` HTTP transactions enter the Wintun
  ring (`ril-033`); escape-bind UDP DNS query to `223.5.5.5` succeeds
  (no lookup/proxy dial loop); netsh DNS hijack end-to-end is not run because
  it changes user network configuration.
- **QUIC + scheduling (Linux)**: `partial` for the core clause. TUIC session
  reuse (one QUIC connection for multiple Connect commands) and the fair
  scheduler (game small packet served at 0ms head-of-line under sustained
  download, web not starved) are real tests — but they are protocol/scheduling
  surfaces, not a real website/QUIC + game parallel forwarding run.
- **macOS / OpenWrt / Android / iOS**: every clause is `needs_device` except
  where a platform-neutral test or build matrix exists as `partial`. RIL-039,
  RIL-042, RIL-046, and RIL-049 are unresolved; no cross-check, emulator ping,
  or build artifact is promoted to real parallel-scenario acceptance.

## Honest boundary — core matrix NOT verified

RIL-086's deliverable is a real website/QUIC + game parallel forwarding matrix
reporting dual-stack, DNS, MTU, network-change, and exit-recovery behavior per
platform, with explicit rejection or configured degradation for unsupported
items. That core matrix has **not** been run. Linux has protocol/scheduling unit
tests and now a real IPv4/IPv6 loopback forwarding test; Windows has
single-application ping/curl loopback evidence; none is a parallel browser/game
run. The RIL-086 parent checkbox stays unchecked; RIL-039/042/046/049 device
dependencies remain unresolved.

Full workspace tests, `cargo fmt --all -- --check`, and clippy with `-D warnings`
were run green before committing. No release version, tag, or formal GitHub
release was created.
