# Platform support and delivery status

Per-platform delivery and acceptance status. Three honest tiers are kept
apart throughout: **build/cross-check** (compiles for the target) is not
**local contract gates** (clauses pinned by tests on this machine), and
neither is **device acceptance** (real hardware, real network). Machine
readable sources: `contracts/build_matrix_v1.json`,
`contracts/desktop_e2e_matrix_v1.json`,
`contracts/parallel_scenario_matrix_v1.json`; per-item evidence lives in
the [acceptance evidence index](./acceptance-evidence/README). Protocol
level support is a separate page ([protocol support](./PROTOCOLS)).

## Six-platform support table

| Platform | Build face | Runtime face delivered | Acceptance status | Named gaps |
|---|---|---|---|---|
| Linux (systemd/deb) | x86_64 + aarch64 nightly artifacts; armv7 CI check-only; no distro floor declared (glibc follows the build machine) | TUN TCP/UDP data plane, process identity attribution, rule source / Explain — the most complete platform | tcp/udp/name_path/pid_reuse/rule_source verified locally; cross-uid permission denial and same-target multi-process port reuse verified by real-process tests (real `setpriv`/two-process attribution); browser-grouped traces / fault samples not run | Desktop-session scenarios (real browser + two games), fault samples |
| OpenWrt | 3 artifact triples; floor OpenWrt 22.03+ (fw4/nftables, `rule_backend: nft`) | Gateway wiring scaffolding | Zero device acceptance — RIL-041/042 not run | Needs an OpenWrt device: wiring, operation and resource acceptance all unrun |
| Windows | x86_64 windows-gnu cross (compile level only); minimum version unverified | Takeover/bypass, process owner, service & exit recovery | Machine batch verified on `imac` (RIL-032–035): identity/takeover/owner/service-recovery; rule source verified locally (platform-independent decision face) | Browser/game grouped traces and fault samples (only curl.exe HTTP face run); DNS hijack end-to-end; suspend/resume |
| macOS (launchd) | 2 universal2 artifact triples; native macOS build required (Apple SDK redistribution limits) | Build/host scaffolds only | All clauses need macOS SSH access (only the platform-independent rule-source face is verified locally) | RIL-036–039 not delivered — Intel mac pending fleet access |
| Android | 2 triples + demo app (minSdk 24 / targetSdk 33) | FFI library: 18-symbol JNI face (`start`, `startWithSecrets`, `networkChanged`, `diagnosticIpcStart`, `diagnosticIpcStop`, stop/isRunning, stats + 6 query faces, TUN fd start/stop), host lifecycle stop face, TUN fd injection face, minimal ICMP echo path — all pinned by local contract gates | Real-device batch not run (RIL-043–046 unchecked) | Complete forwarding (TunIngress opens its own `/dev/net/tun`, accepts no foreign fd, no protect hook — named future work); on-device lifecycle/network-switch |
| iOS | 3 artifact triples (cross compile) | Private-fd integration scaffolds | Zero — NE extensions do not run in the simulator; needs a signing device + paid developer account | RIL-094/047–049/149 blocked on signing access |

## Proposed, not delivered

Kept separate from the table above — proposals never read as capability:

- Windows/macOS capture and identity at v1 quality (hardening, dual-stack
  bypass, permissions and recovery) — v1 work column of the
  [capability boundaries](./architecture).
- Complete mobile forwarding and public packet APIs (Android/iOS).
- macOS/OpenWrt/Android/iOS device acceptance batches (all unchecked in
  `todo.md`, each with its named blocker).

## How to read statuses

`verified_local` / `verified_device` cells point at real repository files
(test files or evidence documents). `partial` means part of the clause ran
and the remainder is a named gap. `needs_*` cells carry no evidence — unit
tests, cross-compilation and artifact builds are never claimed as device
acceptance. The ledgers are enforced by contract tests in
`cargo test --workspace`, so a status that drifts from reality fails the
build instead of rotting quietly.
