# RIL-082 mobile/router diagnostic bridge — local ledger

**Kind**: local verifiable ledger (not device evidence). The main RIL-082 checkbox stays open: real-device consent, arm64/iOS NE lifecycle, OpenWrt opkg/procd/kmod-tun and signing acceptance remain unresolved.

The machine-readable source is `contracts/mobile_diagnostic_bridge_v1.json`, enforced by `crates/rillane-platform/tests/mobile_diagnostic_bridge_contract.rs` in `cargo test --workspace` (nine tests including three `#[should_panic]` comparator self-checks).

## What is pinned

- **No default MCP service, no phone inbound admin port**: FFI exports are exactly the 15 C ABI symbols declared in the ledger (header ↔ Rust exports ↔ ledger, exact set); `crates/rillane-ffi` has no MCP dependency, and FFI/manifest/Kotlin/iOS/OpenWrt sources contain no MCP/JSON-RPC/listener tokens. Android `VpnService` is not `exported` and is guarded by `android.permission.BIND_VPN_SERVICE`; only the launcher activity is exported. Mobile configs bind the control plane to `127.0.0.1:9090`.
- **Authorized host IPC / redacted export**: the mobile host reads FFI query functions (flows/flow/stats/nodes/DNS/routing) in-process; there is no inbound listener or model-protocol endpoint. Desktop-side integration consumes **exported views**, not a phone MCP service. `rillanectl diagnose` keeps `safe` (default), `full` and `raw` scopes, a secret-key table and redaction helpers; `raw` (`--scope raw` / `--no-redact`) writes unredacted files locally only and is marked `do-not-upload`/`review-before-sharing` with an explicit “never uploads the bundle anywhere” policy.
- **OpenWrt optional resource-limited adapter**: `platforms/openwrt/build.sh` accepts `RILLANE_SMALL=1` to build `rillaned`+`rillanectl` with `--no-default-features --features small` (no WASM/JIT). Default builds stay unchanged. The ipk packages no `rillane-mcp`; the template keeps the control plane on loopback. `cargo check -p rillaned -p rillanectl --no-default-features --features small` and `cargo test -p rillane-ffi --no-default-features --features mobile` passed locally.
- **Desktop bridge documentation**: `docs/design/debug-and-mcp.md` and its Chinese counterpart state that Android/iOS do not run MCP by default in the VPN service/extension, that no inbound phone admin port is added, and that authorized host IPC/redacted export comes first, with a desktop adapter where needed.

## Named gaps (not verified here)

- Real-device Android consent/performance (arm64) and iOS Network Extension entitlement/lifecycle on a paid developer account; iOS Swift is syntax-checked only (Linux dev host, no Xcode).
- OpenWrt opkg install/upgrade, procd respawn, kmod-tun throughput, and nftables transparent takeover behaviour on real hardware.
- Cross-compiled small/mobile binaries as shipped artifacts; only host-target feature checks were run in this batch.
- The shared data-plane TCP/UDP proxy path is not yet moved into the mobile TUN demo (ICMP echo only; global routing stays off).

The contract gate pins structural facts, not device behaviour: a passing test means the source and ledger agree, not that a phone or router accepted traffic.
