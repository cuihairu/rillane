# G1-6 design: REALITY + XTLS-Vision outbound

> Status: **M1 landed (capture + import reject, 2026-11-10) · M1.5 landed (keep config, dial-time named gate, 2026-11-10)** · M2–M4 blocked (§5) · Maps to [todo.md](../../todo.md) G1-6 · Related: [tls-fingerprint.md](tls-fingerprint.md) (ClientHello assembler decision space) · [udp-relay-path.md](udp-relay-path.md) (egress capability table)

## Executive Summary

Mainstream commercial subscriptions carry VLESS nodes with `reality-opts` (REALITY) and `flow: xtls-rprx-vision` (XTLS-Vision). Rillane's node models previously had no fields for either key, so serde silently dropped them and the node degraded into an ordinary TLS VLESS: against a REALITY server the non-REALITY handshake gets the camouflage site (traffic never reaches the proxy, no error anywhere); against a Vision server the connection fails because the server expects Vision framing. Both outcomes are silent and undiagnosable — worse than a loud import failure.

M1 landed capture + import-time reject; **M1.5 (same day) flipped the policy by decision**: all three import surfaces keep the captured fields in `EgressConfig::Vless` (serde no longer silently drops the keys), and the reject moved to **dial time** — `VlessConnector::gate_reality_and_flow` names REALITY/Vision before any network I/O. Rationale: node-level failure beats import-level failure (one REALITY node must not fail a whole bulk subscription; url-test marks it unhealthy while the rest works), and a loud dial-time error beats the silent degradation M1 existed to prevent. The full REALITY client transport (M2) remains blocked on ClientHello byte-level control that rustls does not provide (§4.3) and on a real xray REALITY node for interop acceptance; Vision (M3) additionally needs the Vision framing realized plus the same real-node acceptance.

## 1. Behavior matrix

| Node carries | Before | After (M1.5, current) |
|---|---|---|
| `reality-opts` (Clash YAML / Rillane DSL) | key silently dropped → plain TLS VLESS → camouflage site served, no error | fields parsed & kept in `EgressConfig::Vless.reality`; dial-time `Err` naming REALITY before any I/O |
| `pbk`/`sid`/`security=reality` (vless:// link) | params silently dropped → same silent degradation | link captured into the node, imported normally; dial-time named `Err` (TCP + UDP `associate`) |
| `flow: xtls-rprx-vision` | key silently dropped → plain VLESS → server expects Vision framing, connection fails | kept in `EgressConfig::Vless.flow`; dial-time `Err` naming the flow value |
| neither | normal VLESS (unchanged) | normal VLESS (unchanged) |

(M1's import-time reject is superseded — see the executive summary for why. `reality-opts` missing `public-key` still fails conversion loudly: half-configured REALITY is never silently turned into something else.)

Error policy (M1.5):

- **Import time**: keys are captured, never dropped; only an incomplete REALITY block (missing `public-key`) errors, naming the node.
- **Dial time** (TCP `forward` and UDP `associate`): a REALITY/flow node fails its own connection with a named error explaining why silent degradation is refused — before any network I/O. The rest of the subscription keeps working; url-test health marks the node unhealthy.

## 2. Landed surface (M1)

- `crates/rillane-subscription/src/clash.rs` — `ClashProxy` gains `flow: Option<String>` and `reality_opts: Option<serde_yaml::Value>` (aliases `reality-opts` / `reality_opts`); the VLESS convert arm rejects with a message naming the node.
- `crates/rillane-subscription/src/rillane_dsl.rs` — `RillaneNode` gains `flow` / `reality` (aliases `reality-opts` / `reality_opts`); the VLESS arm rejects likewise.
- `crates/rillane-subscription/src/converter.rs` — `parse_vless` captures `pbk` (public-key), `sid` (short-id), `security=reality` into `reality_opts` and `flow` into `flow`; `convert_v2ray` gates captured nodes into warnings + skip.
- Tests: serde capture proof (kebab + snake aliases), link param capture, bulk-import preserves the REALITY line.

### 2.1 Landed surface (M1.5, dial-time gate)

- `crates/rillane-config/src/lib.rs` — `RealityConfig { public_key, short_id }` (kebab aliases on the inner keys) + `EgressConfig::Vless.reality: Option<RealityConfig>`; `flow` already carried.
- `crates/rillane-subscription` — Clash/DSL/vless:// arms convert REALITY nodes successfully and preserve fields; only missing `public-key` errors.
- `crates/rillane-protocols/src/outbound/vless.rs` — `gate_reality_flow` fires at the top of `forward_pooled`/`forward_inline` and in `VlessUdpConnector::associate`, before any network I/O.
- `crates/rillane-runtime/src/runtime_builder.rs` — build no longer rejects flow/reality (build-time reject removed; both arms pass `reality` into the connector); clash export round-trips `reality-opts`.
- Tests: `build_egress_outputs_carries_vless_flow_and_reality` (runtime), `forward_rejects_reality_named_before_io` / `forward_rejects_flow_named_before_io` / `udp_associate_rejects_reality_named` (protocols), preserved-on-convert (clash + dsl), `test_v2ray_bulk_import_preserves_reality_line` (converter), `reality_config.rs` (config serde roundtrip).

## 3. Protocol analysis

### 3.1 REALITY handshake (client view)

REALITY (XTLS/Xray-core) is a TLS 1.3 camouflage scheme:

1. The client dials the server's port and sends a **forged ClientHello** whose SNI is the camouflage site; extension order/cipher list imitate a real browser (fingerprint imitation — the same decision space as [tls-fingerprint.md](tls-fingerprint.md)).
2. `ClientHello.session_id` (32 B) carries the authentication material: the configured `short-id` plus a truncated HMAC over the ClientHello body, keyed by a key derived from the X25519 shared secret `x25519(client_ephemeral, server public-key)` and a time window (the server accepts a bounded skew). This lets the server distinguish a REALITY client from a plain visitor **before** the handshake completes.
3. A REALITY client gets a genuine TLS 1.3 handshake whose certificate chain is generated for the camouflage SNI; a plain visitor gets the same handshake and is then reverse-proxied to the real camouflage site. This is precisely the silent fallback §1 describes when an un-aware client dials a REALITY server with plain TLS.
4. After the handshake the TLS session carries the data channel (VLESS-style framing inside).

### 3.2 XTLS-Vision (`flow = xtls-rprx-vision`)

Vision removes TLS-in-TLS double encryption. Over a standard VLESS request with `flow` set, both sides switch to Vision framing after the VLESS response: an initial padding frame, then — when the inner traffic is itself TLS — raw inner TLS records are relayed without re-encryption (direct copy), else the stream continues as ordinary VLESS. The client reads the inner TLS record boundaries from the local TLS client's plaintext output and relays records opaquely; it never decrypts the inner TLS.

### 3.3 Why M2 is blocked (stack constraint)

rustls does not expose byte-level ClientHello control: `session_id` content, extension order, and cipher list are internally generated. REALITY's step 2 requires writing auth material into `session_id` and fingerprinting the whole hello. No maintained Rust uTLS equivalent exists. Candidate approaches (same decision space as tls-fingerprint.md §9):

- **(a) hand-rolled minimal TLS 1.3 client handshake** for the REALITY dial only (key schedule + AEAD record layer): large, security-sensitive surface;
- **(b) vendored/forked BoringSSL-class stack**: packaging cost, breaks the current rustls-only dependency shape;
- **(c) rustls fork/shim with a hello assembler**: brittle across rustls upgrades.

None is selectable without a user-level stack decision, and none can be acceptance-tested without a real xray REALITY server node (server address, `public-key`, `short-id`, camouflage SNI).

## 4. Milestones

| Milestone | Content | Status |
|---|---|---|
| M1 | Capture `reality-opts`/`flow` on all three import surfaces + import-time explicit reject/warning + tests | **Landed (2026-11-10)** |
| M1.5 | Keep captured config in `EgressConfig::Vless`; move the reject to dial time (TCP + UDP), naming REALITY/Vision before any I/O; clash export round-trips `reality-opts` | **Landed (2026-11-10)** |
| M2 | REALITY outbound transport (dial-level) | BLOCKED: ClientHello-control approach needs a stack decision (§4.3); needs a real xray REALITY node for interop acceptance |
| M3 | Vision `flow` support over the VLESS egress | BLOCKED: depends on the M2 transport shape; needs a real Vision node; loopback vectors first (VMess xray-vector precedent) |
| M4 | Real-node acceptance for both | BLOCKED: external node credentials |

## 5. Acceptance mapping

- M1: `cargo test -p rillane-subscription` — `test_vless_reality_and_flow_nodes_preserved_on_convert` (clash + dsl, M1.5 flip), `test_rillane_node_captures_reality_and_flow_keys`, `test_vless_reality_link_params_captured`, `test_v2ray_bulk_import_preserves_reality_line` (M1.5 flip).
- M1.5: `cargo test -p rillane-config --test reality_config` (serde no-drop + roundtrip), `cargo test -p rillane-protocols` gate tests (dial-time named errors, TCP + UDP), `build_egress_outputs_carries_vless_flow_and_reality` (runtime build carries both).
- M2–M4: real-node interop only (xray/sing-box server with REALITY enabled), plus a ClientHello-capture assertion once the transport exists (same technique as tls-fingerprint.md's distinguishability test).
