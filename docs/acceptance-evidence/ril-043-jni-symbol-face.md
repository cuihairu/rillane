# RIL-043 mobile FFI — JNI symbol face (local verifiable segment, 2026-11-26)

## What is delivered

`crates/rillane-ffi/tests/jni_symbol_face.rs` (3/3 green) pins the Android JNI
bridge contract: the Kotlin host `RillaneFfi` object
(`platforms/android/app/src/main/java/com/rillane/rillane/RillaneFfi.kt`,
`external fun <name>`) and the Rust `jni_bridge.rs` exports
(`Java_com_rillane_rillane_RillaneFfi_<name>`) must name exactly the same
method set. This is the host-bridge link contract:

- Rust exports a symbol Kotlin does not declare → dead symbol on the wire;
- Kotlin declares a method Rust does not export → `UnsatisfiedLinkError` at
  library load time (a runtime failure, not compile time).

The gate also pins the known 18-method face (5 lifecycle/status + 7 query +
2 TUN fd methods + secret injection, network change and two bounded IPC
methods) so shrinking the bridge is an explicit action, and carries
two `#[should_panic]` self-tests that inject a phantom Kotlin declaration and
a phantom Rust export to prove the comparator names the drifting side.

RIL-083's C-header gate (`contract_query_face.rs`) explicitly excluded the JNI
face, deferring it to the RIL-043 batch gate — this segment delivers that gate
for the symbol face.

## Honest boundary

RIL-043's real acceptance — fd and public packetFlow both bridged, no dangling
pointers, no callbacks after cancellation, no unbounded queues, ABI versioning
on device — requires the mobile device batches (RIL-094 iOS device access
unresolved; Android full-forwarding batch pending). The parent checkbox stays
unchecked; this segment covers only the statically verifiable symbol parity
between the two host-bridge sides, following the RIL-150/RIL-090 precedent for
independently deliverable content.

Full workspace tests, `cargo fmt --all -- --check`, and clippy with
`-D warnings` were run green before committing. No release version, tag, or
formal GitHub release was created.
