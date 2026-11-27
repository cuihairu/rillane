# RIL-044 mobile host network change face (local verifiable segment, 2026-11-27)

## What is delivered

`crates/rillane-ffi/tests/network_changed_contract.rs` (3/3 green) pins the
RIL-044 acceptance clause "network change" on its core half.
`rillane_ffi_network_changed` (new C export, header + JNI bridge
`networkChanged` + Kotlin declaration and `onAvailable` wiring in the same
commit) tells the core that the host's underlying network changed:

- **Flush really takes effect (real DNS resolution round trip)**: the runtime
  starts with a `network.dns` block whose trusted upstream is a test-local
  mock that speaks the platform crate's own wire format (same dialect as the
  resolver). Two identical queries: the second is served from cache (upstream
  hit count unchanged, `dns_stats` cache_hits ≥ 1). After
  `network_changed`, the third query goes back to the upstream (hit count
  +1) — with a stale cache it would have stayed, and the comparator proves
  exactly that absence is detectable.
- **Idempotent and repeatable**: a second `network_changed` call again sends
  the next query upstream (hit count advances again); the call is stateless.
- **Absent DNS block is an honest no-op**: a runtime without `network.dns`
  returns 0 (flushing nothing is success) and its `dns_stats` face honestly
  reads `enabled:false`.
- **NULL handle named**: NULL → -1 with a stable `last_error`, never
  conflated with success 0.
- **Bridge faces in lockstep**: the JNI symbol parity gate now pins 16
  methods (adds `networkChanged` on both sides), the C header ↔ Rust export
  parity gate passes, and the RIL-082 diagnostic ledger registers the new
  export (`contracts/mobile_diagnostic_bridge_v1.json` transaction).

## Honest boundary

This gate pins the core half (cache flush behavior + handle face). The
session-drain boundary is named, not claimed: in-flight streams are not
actively killed — draining belongs to the RIL-022/023 consumer-side
boundary, and network change follows it (old-network streams fail naturally;
the host must not rely on this call to kill streams). The Kotlin
`onAvailable → networkChanged` wiring is a text-disciplined structural face;
live network switching (Wi-Fi ↔ cellular) on a device belongs to the RIL-046
device batch and stays open, as does bounded diagnostic IPC (the remaining
RIL-044 deliverable). The parent checkbox stays unchecked.
