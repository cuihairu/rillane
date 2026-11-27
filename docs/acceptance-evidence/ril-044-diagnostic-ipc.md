# RIL-044 bounded host diagnostic IPC (local verifiable segment, 2026-11-27)

## What is delivered

`crates/rillane-ffi/tests/diagnostic_ipc_contract.rs` (2/2 green) pins the
remaining RIL-044 lifecycle clause — authorized host diagnostic IPC — through
**real Unix-domain-socket round trips** against a live FFI runtime. The design
boundary comes from `docs/design/debug-and-mcp.md`: mobile VPN extensions do
not run MCP by default and gain no inbound management port; authorized host
IPC or redacted exports are the sanctioned path. This bridge is explicit-start
only:

- **No default listener**: before `rillane_ffi_diagnostic_ipc_start(handle,
  path)`, connecting to the host-chosen UDS path fails. There is no default
  path and no listening socket in the process until the host opts in. A second
  start (even on another path) is refused with `ipc.start.duplicate_path` —
  one bridge per process, never a silent rebind.
- **Read-only verbs**: the line protocol accepts exactly six verbs —
  `stats`, `routing`, `nodes`, `dns_stats`, `dns_resolvers`, `flows`.
  `write`, `probe`, `config`, `apply`, `reload` and unknown verbs all answer
  `ipc.request.unknown_verb`; the MCP write surface is never reachable here.
  Five verb responses are asserted byte-for-byte equal to the corresponding
  C query faces through the same DTO builders; `stats` is checked for all
  nine keys.
- **Bounded framing and resources**: one line = one request; a request over
  8 KiB without a newline answers `ipc.request.oversize` instead of growing
  unbounded; responses are capped at 256 KiB at a UTF-8 boundary; a single
  `REQUEST_TIMEOUT` (5 s) covers each request; the accept thread observes the
  stop flag within 100 ms; each connection is scoped to one request and one
  response.
- **Stable failure codes**: NULL handle → `ipc.start.null_handle`; empty
  path → `ipc.start.bad_path`; duplicate start →
  `ipc.start.duplicate_path`; stop without a running bridge →
  `ipc.stop.already_stopped`, all readable through `last_error`.
- **Stop ordering**: explicit stop unbinds the path and rejects further
  connects; `rillane_ffi_stop(handle)` also tears down the bridge before
  runtime shutdown, so no accept thread can outlive the handle's `Arc<Runtime>`.
- **Faces in lockstep**: the two C exports are declared in
  `crates/rillane-ffi/include/rillane_ffi.h`, registered in the RIL-082 ledger
  (`contracts/mobile_diagnostic_bridge_v1.json` transaction), and mirrored by
  `diagnosticIpcStart` / `diagnosticIpcStop` in the JNI bridge and Kotlin
  `RillaneFfi` (parity gate now pins 18 methods). The two C query faces are
  refactored onto the same DTO builders as the IPC dispatch, making "same
  shape" a shared-code fact rather than a copy.

## Honest boundary

This is the core half in the host process. Android VpnService / iOS NE wiring
(the consent decision that triggers an explicit bridge start, and the path
choice) and real-device behavior (consent UI, arm64, Wi-Fi ↔ cellular switch
with an active bridge) belong to the RIL-043/RIL-046 device batches and stay
open. No MCP server, JSON-RPC endpoint, or default phone inbound port is added;
the UDS path is supplied by the host and never defaulted. The parent checkbox
stays unchecked.
