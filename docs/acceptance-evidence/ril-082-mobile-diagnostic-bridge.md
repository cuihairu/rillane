# RIL-082 mobile/router diagnostic bridge — local ledger

**Kind**: local verifiable ledger (not device evidence). The main RIL-082 checkbox stays open: real-device consent, arm64/iOS NE lifecycle, OpenWrt opkg/procd/kmod-tun and signing acceptance remain unresolved.

The machine-readable source is `contracts/mobile_diagnostic_bridge_v1.json`, enforced by `crates/rillane-platform/tests/mobile_diagnostic_bridge_contract.rs` in `cargo test --workspace` (eleven tests including four `#[should_panic]` comparator self-checks).

## What is pinned

- **No default MCP service, no phone inbound admin port**: FFI exports are exactly the 19 C ABI symbols declared in the ledger (header ↔ Rust exports ↔ ledger, exact set); `crates/rillane-ffi` has no MCP dependency, and FFI/manifest/Kotlin/iOS/OpenWrt sources contain no MCP/JSON-RPC/listener tokens. Android `VpnService` is not `exported` and is guarded by `android.permission.BIND_VPN_SERVICE`; only the launcher activity is exported. Mobile configs bind the control plane to `127.0.0.1:9090`.
- **Authorized host IPC / redacted export**: the mobile host reads FFI query functions (flows/flow/stats/nodes/DNS/routing) in-process; there is no inbound listener or model-protocol endpoint. Desktop-side integration consumes **exported views**, not a phone MCP service. `rillanectl diagnose` keeps `safe` (default), `full` and `raw` scopes, a secret-key table and redaction helpers; `raw` (`--scope raw` / `--no-redact`) writes unredacted files locally only and is marked `do-not-upload`/`review-before-sharing` with an explicit “never uploads the bundle anywhere” policy.
- **OpenWrt optional resource-limited adapter**: `platforms/openwrt/build.sh` accepts `RILLANE_SMALL=1` to build `rillaned`+`rillanectl` with `--no-default-features --features small` (no WASM/JIT). Default builds stay unchanged. The ipk packages no `rillane-mcp`; the template keeps the control plane on loopback. `cargo check -p rillaned -p rillanectl --no-default-features --features small` and `cargo test -p rillane-ffi --no-default-features --features mobile` passed locally.
- **Cross-compiled small/mobile artifacts as shipped** (2026-11-27 batch): `RILLANE_SMALL=1 platforms/openwrt/build.sh x86_64-unknown-linux-musl aarch64-unknown-linux-musl` produced two ipk (`dist/openwrt/rillane_0.1.0-1_{x86_64,aarch64_generic}.ipk`, 26M/28M) with static stripped musl ELF and intact ar three-member ipk structure (`.build-log.txt`); `platforms/android/build.sh arm64-v8a x86_64` produced the mobile-profile FFI cdylib cross-built for both ABIs and the debug APK (214M) with both `.so` inside. **The mobile-profile build caught and fixed a real drift**: `jni_bridge.rs` had never been compiled for Android since `rillane_ffi_network_changed` was added (its import list missed the name) — host `cargo test` doesn't compile the android-gated bridge, so the 产线 was silently broken; the import list is now fixed and the cross build compiles, exporting exactly the 19 C ABI symbols and 18 JNI symbols with zero `wasmtime` symbols (mobile profile verified at artifact level, not just source). The android build script was also fixed to honor the documented mobile profile (it previously cross-built the default `full` profile — wasmtime/JIT into a mobile cdylib) and the Dockerfile NDK fetch is now resume+retry robust; both facts are pinned by the contract gate (`android mobile profile builds FFI without wasmtime`, one `#[should_panic]` self-check).
- **Desktop bridge documentation**: `docs/design/debug-and-mcp.md` and its Chinese counterpart state that Android/iOS do not run MCP by default in the VPN service/extension, that no inbound phone admin port is added, and that authorized host IPC/redacted export comes first, with a desktop adapter where needed.

- **Redaction helper semantics, real calls (2026-11-27 batch)**: `rillanectl` inline module
  `diagnose_export_redaction_tests` (3 tests) — the three export helpers are not merely
  "present" in CLI source: `redact_config_by_extension` recursively strips secret keys
  (`admin_token`/`password`/`private_key` etc. from the ledger key table) in YAML/JSON
  configs while keeping non-secret identity fields; `strip_json_url_secrets` removes
  userinfo and `token`/`password`/`secret`/`key`/`sign` query params from
  `subscription_url`/`url` strings while keeping hosts and non-secret params;
  `sanitize_diagnostic_log` strips PEM private key blocks wholesale and sanitizes
  `key=value` secret pairs per line. The contract gate `diagnose_export_scope_is_controlled`
  was upgraded in step: `export.runtime_gate` must point at this module, the gate asserts
  the tests really call the three helpers and checks the `#[test]` count — redaction went
  from "text presence" to "real-call pinned". The previous 9-test gate (3 `#[should_panic]`
  self-proofs) stays as-is underneath.

## Named gaps (not verified here)

- Real-device Android consent/performance (arm64) and iOS Network Extension entitlement/lifecycle on a paid developer account; iOS Swift is syntax-checked only (Linux dev host, no Xcode).
- OpenWrt opkg install/upgrade, procd respawn, kmod-tun throughput, and nftables transparent takeover behaviour on real hardware.
- Cross-compiled small/mobile binaries **for armv7 and OpenWrt devices**: the small-profile ipk built only for x86_64 and aarch64. armv7-unknown-linux-musleabihf fails in LuaJIT's 32-bit host stage (`luajit-src` builds `minilua` with `cc -m32`; the stock cross 0.2.5 armv7 container lacks 32-bit glibc multilib headers). This is feature-independent — `mlua`/`shadowquic` enter via `rillane-protocols`→`shadowquic` defaults (`plugin-vendored`), so the **full** profile would fail identically: no armv7 musl cross build has ever succeeded in this workspace. Root cause recorded; reopen conditions: a custom cross image with multilib host headers, or upstream shadowquic making the lua `plugin` feature optional.
- The shared data-plane TCP/UDP proxy path is not yet moved into the mobile TUN demo (ICMP echo only; global routing stays off).
- Android APK debug artifacts are large (214M) because the mobile cdylib ships unstripped in jniLibs; no AVD/real-device install or run was performed in this batch (the 2026-10 AVD acceptance used the pre-fix APK).

The contract gate pins structural facts, not device behaviour: a passing test means the source and ledger agree, not that a phone or router accepted traffic.
