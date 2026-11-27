# RIL-085 desktop end-to-end acceptance matrix (local verifiable segment, 2026-11-26)

## What is delivered

A machine-readable acceptance ledger `contracts/desktop_e2e_matrix_v1.json` covering the
RIL-085 clauses × three desktop platforms (Linux, Windows, macOS), enforced by
`crates/rillane-platform/tests/desktop_e2e_matrix_contract.rs` (9/9 green). Each cell
carries exactly one honest status and, where appropriate, a path to a repository-local
evidence file:

| Status | Meaning |
| --- | --- |
| `verified_local` | Verified by a real test executable on this machine |
| `verified_device` | Verified on real hardware, evidence doc checked into the repository |
| `partial` | Only an adjacent surface verified (e.g. curl HTTP client, not a browser) |
| `needs_runtime` | Requires an interactive desktop session with browser/game sessions |
| `needs_mac_ssh` | Mac hardware not connected (RIL-036/037/038 unresolved) |

The comparator pins the closed nine-clause set and three-platform set, checks that
every `verified_*` cell points to a real file, that `needs_*` cells carry no evidence,
that macOS is `needs_mac_ssh` for everything except the platform-neutral rule-source
surface, that the two Linux process tests are kept honest (the permission-denied cell
points at a real `setpriv`-driven process test and the port-reuse cell at a real
two-helper-process test), and that the two core scenarios are never marked as
verified. Three `#[should_panic]` self-tests deliberately corrupt the matrix (fake
macOS verification, fake browser trace verification, stale Linux permission cell) to
prove the comparator bites.

## Evidence ledger by clause

- **TCP / UDP / name+path / PID reuse (Linux)**: `verified_local` via
  `crates/rillane-platform/tests/owner_linux_contract.rs` — real loopback TCP/UDP
  attributed to the test process, executable path from `readlink /proc/<pid>/exe`,
  `comm` truncation flagged (15-char kernel limit), start time present.
- **TCP / UDP / name+path / PID+port reuse / permission denied (Windows)**:
  `verified_device` via RIL-032/033/034/035 evidence docs — real `ping.exe` ICMP,
  `curl.exe` HTTP transactions, `Get-Process.StartTime` / `Win32_Process.CreationDate`,
  standard-user token `OpenProcess` error 5, UDP fixed-port A→B and TCP
  `SO_REUSEADDR` rebind C→D cache flips.
- **Rule source queryable**: `verified_local` on all three desktops, because the
  subscription → generation → Explain → actual-egress decision surface is
  platform-neutral (`crates/rillane-routing/tests/subscription_to_execution.rs`,
  `crates/rillane-routing/tests/explain_contract.rs`). This does **not** claim
  real traffic on that platform was attributed to a rule.
- **Permission denied (Linux)**: `verified_local` via
  `crates/rillane-platform/tests/owner_linux_permission_contract.rs` — `sudo -n` +
  `setpriv` starts a real helper process as `nobody` (uid 65534). The connection's
  socket inode is visible in `/proc/net/tcp` while `/proc/<pid>/fd` is not listable
  across uids; `ProcOwnerResolver` returns `Unknown(PermissionDenied)` (named, not
  fabricated, not downgraded to `NotFound`). A control connection from this uid
  on the same listener is still attributed to this process, proving the blind spot
  is cross-uid rather than a broken resolver. Without `sudo`/`setpriv` the test
  prints `skip` — it never claims a result it did not measure.
- **Port reuse (Linux)**: `verified_local` via
  `crates/rillane-platform/tests/owner_linux_port_reuse_contract.rs` — two independent
  helper processes connect to the same listener with distinct local ports; each
  `(local, remote)` tuple resolves to the correct helper pid with start time present
  and zero cross-attribution. This closes the Linux half of "PID/port reuse measured"
  that previously existed only as Windows P4/P4b device evidence.
- **macOS**: every clause except rule-source is `needs_mac_ssh` — RIL-036/037/038
  are unresolved; no cross-check or unit test is promoted to device verification.

## Honest boundary — core scenarios NOT verified

RIL-085's deliverable is "grouped traces for the same target across a browser and
two games, plus fault samples." Those core scenarios are marked `needs_runtime`
(Linux), `partial` (Windows), and `needs_mac_ssh` (macOS):

- Windows has real `curl.exe` HTTP transactions (`ril-033`) and real service
  crash/network-change/uninstall recovery (`ril-035`), but these are HTTP-client
  and service-recovery surfaces, **not** browser/game grouped traces or
  browser/game fault samples.
- Linux has owner attribution and routing decision tests, but no graphical
  desktop session driving a browser or two games.
- macOS has no device access at all.

The RIL-085 parent checkbox stays unchecked. The dependency RIL-038 (Intel mac
SSH access) remains unresolved, and the browser/game grouped-trace scenario
requires an interactive desktop harness that has not been run. This segment only
delivers the locally verifiable acceptance ledger, following the RIL-150/RIL-090
precedent for independently deliverable content.

Full workspace tests, `cargo fmt --all -- --check`, and clippy with `-D warnings`
were run green before committing. No release version, tag, or formal GitHub
release was created.
