# Protocol catalog and library-selection evidence (RIL-104)

This page is the catalog source of truth for egress protocols: each protocol is either reviewed-and-admitted (with its library-selection conclusion and evidence) or explicitly not admitted (refused at assembly). The machine face lives in `crates/rillane-config/src/protocol_catalog.rs` (`CATALOG`); the sections below (`## <kind>`) are its evidence anchors, verified field-by-field by that module's contract tests. User-facing capability boundaries live in [PROTOCOLS](PROTOCOLS.md); the UDP capability face is the build-time scan (`scan_udp_capability`, runtime).

## Registration spec (Factory ladder)

A protocol reaches the hot path only by completing every rung; a missing rung is a refusal:

1. **Library-selection record**: fill the corresponding section here — candidate library version, license, platforms, public API, and the bypass/cancel/stats/reuse conclusions. A "no usable library" conclusion must be recorded too — missing implementation evidence is the precondition for self-writing, not a license to self-write.
2. **Catalog entry**: add an entry in `protocol_catalog.rs` (registration state, UDP column, `Backend` conclusion). Catalog size must equal the IR egress variant count; a contract test enforces the sync.
3. **IR variant**: add the `EgressConfig` variant (closed enum — uncataloged types cannot enter the config face).
4. **Connector wiring**: register the factory in the rillane-protocols/runtime build match. Not-admitted types are refused at assembly with stable codes — `config.egress.not_admitted` (cataloged, not admitted) / `config.egress.unknown` (outside the catalog).
5. **Acceptance**: real-peer verification, explicit refusal of unsupported combinations, bidirectional subscription-field conversion samples (the uniform acceptance of RIL-105..134, see root `todo.md`).

**Feature pruning** (extends the RIL-040 profiles): a protocol backend that is feature-gated (e.g. a `proto-<name>` feature) is refused at config-validation time with the stable code `config.combo.unsupported` in builds that lack the feature — never the hot path, never hidden degradation. Today every backend ships in the default profile; per-platform exceptions (WireGuard's android/armv7-ohos stubs) are recorded in their sections.

## Evaluation record template

Every admitted section carries these fields (the contract test checks each one; a missing field fails the test):

- **Conclusion**: selected library / self-written (self-writing requires the recorded no-library conclusion first)
- **Version**: version requirement (Cargo.toml) + lock-resolved version
- **License**: SPDX expression
- **Platforms**: support surface and exceptions (stubs are never silent)
- **Public API**: the library/module surface in use
- **Bypass**: whether the library's internal I/O can be bypassed (libraries that own dialing/encryption block pool and dial-policy composition — recorded honestly)
- **Cancel**: whether open-phase cancellation/deadline reaches into the library (uninterruptible libraries are stated)
- **Stats**: observability points (how failures surface; no observation points are recorded as unknown)
- **Reuse**: connection reuse / prewarm / multiplex conclusions

## reject

- **Conclusion**: self-written (a one-line refusal face — no third-party option exists or is needed)
- **Version**: in-tree implementation (no third-party dependency)
- **License**: repository license (self-written)
- **Platforms**: all platforms (pure logic, no network I/O)
- **Public API**: `rillane_core::udp::RejectUdpConnector`, runtime `RejectFlowOutput` (crates/rillane-core/src/udp)
- **Bypass**: not applicable (flow dies on match; nothing to bypass)
- **Cancel**: not applicable (no connection is ever opened)
- **Stats**: hits surface through the forward-layer error face; no network observation
- **Reuse**: not applicable
- The UDP face registers a silently-dropping connector — ad/blocklist targets can intercept UDP flows without blocking the whole build (G0-5 semantics).

## direct

- **Conclusion**: self-written (no library exists for the direct face)
- **Version**: in-tree implementation (no third-party dependency)
- **License**: repository license (self-written)
- **Platforms**: six platforms (tokio TcpStream/UdpSocket base)
- **Public API**: `DirectConnector` (crates/rillane-protocols/src/outbound/direct.rs), `rillane_core::udp::DirectUdpConnector`
- **Bypass**: system bypass is owned by the rillane-platform dial policy (interface binding/fwmark); the connector never rewrites system routes — a TCP socket's fwmark does not prove every UDP dial is loop-safe (same wording as PROTOCOLS.md)
- **Cancel**: honors open-phase checks (OpenContext cancel/deadline)
- **Stats**: establishment/failures surface through the unified EgressConnector face
- **Reuse**: supports the pre_dial_direct prewarm pool (`DirectConnector::with_pool`, §2.5/D-6 — speculative predial off by default)
- UDP face: direct datagrams.

## socks5

- **Conclusion**: selected library `tokio-socks` (TCP face); UDP face self-written — the 0.5.2 sources contain only error/io/lib/tcp, no udp module, so no selectable library exists (conclusion recorded before self-writing, RIL-132)
- **Version**: requirement `0.5`, lock-resolved 0.5.2
- **License**: MIT
- **Platforms**: all platforms (tokio-compatible, pure Rust; UDP face on the same stack)
- **Public API**: `tokio_socks::TcpStream` (CONNECT + username/password auth); wrapped as `Socks5Connector`; UDP face self-written as `Socks5UdpConnector`/`Socks5UdpRelay` (RFC 1928 §6 ASSOCIATE + §7 datagram framing, same file outbound/socks5.rs)
- **Bypass**: TCP face — the library owns dialing, its internal socket establishment cannot be bypassed; transport pool / dial policy do not compose with library-owned connects (recorded honestly); UDP face — self-written, control stream and datagram socket both in-repo and composable
- **Cancel**: TCP face — the library's `connect` takes no cancellation; cancellation lives at the timeout and task-drop layers; in-library establishment is uninterruptible (recorded honestly); UDP face — the control stream is held for the relay's lifetime and drop closes the ASSOCIATE (RFC 1928 §7: closing the control stream invalidates the relay, visible to the server as EOF)
- **Stats**: TCP face — the library has no observation points, failures surface as io::Error (observed semantics); UDP face — source-verification and fragment-drop counters (foreign_dropped/frag_dropped) plus drop logs
- **Reuse**: no pool composition — each CONNECT dials independently; no prewarm; the UDP face reuses the TCP connector's node config via `from_connector` (address/credentials consistent)
- UDP: the outbound UDP ASSOCIATE self-written face is delivered (catalog udp=true) — tokio-socks 0.5.2 has no UDP module; the no-selectable-library conclusion was recorded before self-writing; source verification (only datagrams from the relay endpoint), FRAG≠0 drop, and control-stream lifetime binding all have real-peer contract tests.

## http

- **Conclusion**: self-written (CONNECT tunneling is small and transport-composition-heavy; a library binding would constrain more than it helps)
- **Version**: in-tree implementation; header parsing via httparse (shared component, not a protocol library)
- **License**: repository license (self-written); httparse MIT/Apache-2.0
- **Platforms**: all platforms
- **Public API**: `HttpConnector` (crates/rillane-protocols/src/outbound/http.rs; CONNECT tunnel, Basic auth, TLS stackable)
- **Bypass**: self-written face — TLS/transport composition goes through TlsConnectorFactory and composes
- **Cancel**: open-phase checks
- **Stats**: connection errors through the unified face
- **Reuse**: no prewarm composition
- UDP: none (catalog udp=false).

## shadowsocks

- **Conclusion**: selected library `shadowsocks` (shadowsocks-rust core)
- **Version**: requirement `1.25` (default-features=false + aead-cipher), lock-resolved 1.25.0 (shadowsocks-crypto 0.8.0)
- **License**: MIT
- **Platforms**: all platforms (pure Rust, aead-cipher feature set)
- **Public API**: `ShadowsocksConnector::new` + the shadowsocks crate client layer (ServerConfig cipher parsing, TCP/UDP data plane; crates/rillane-protocols/src/outbound/shadowsocks.rs)
- **Bypass**: reuses the library's cipher state machine but never lets it dial — the connector wraps its own streams, composing with the transport pool
- **Cancel**: open-phase checks; the data plane cancels with the stream (no independent blocking section)
- **Stats**: cipher-parse failures are named at build time; SIP003 plugin mode is a process bridge — the plugin's own I/O is outside this repository's observation points (recorded honestly)
- **Reuse**: the UDP face reuses the TCP face's server_config (`from_connector`); plugin (SIP003) mode refuses UDP (SIP003 defines only a TCP data plane)
- The cipher matrix follows the actual dependency and its validation (evidence precedes RIL-131).

## vmess

- **Conclusion**: self-written (current state; if a maintained, license-compatible third-party library appears, the registration ladder is re-run)
- **Version**: in-tree implementation (no third-party protocol library)
- **License**: repository license (self-written)
- **Platforms**: all platforms
- **Public API**: `VmessConnector` (crates/rillane-protocols/src/outbound/vmess.rs; AEAD only, alter_id=0 — legacy MD5 refused and named at build time)
- **Bypass**: self-written face composes with the TLS/WS/gRPC/H2 transport factories
- **Cancel**: open-phase checks
- **Stats**: security/network whitelists validated at build time; handshake errors through the unified face
- **Reuse**: no prewarm composition; the UDP face (network=tcp only) reuses the same node config
- UDP: network=tcp only (no UDP face for ws/grpc/h2; the build-time scan refuses).

## vless

- **Conclusion**: self-written (same as vmess — REALITY needs byte-level ClientHello control, which the rustls route does not offer; RIL-107 runs its own evaluation per the registration spec)
- **Version**: in-tree implementation
- **License**: repository license (self-written)
- **Platforms**: all platforms
- **Public API**: `VlessConnector` (crates/rillane-protocols/src/outbound/vless.rs)
- **Bypass**: composes with the transport factories
- **Cancel**: open-phase checks
- **Stats**: flow/REALITY refused at dial time by name (G1-6 — config is kept, no build-time refusal, preventing silent degradation)
- **Reuse**: no prewarm composition; the UDP face (network=tcp only) reuses the node config
- UDP: network=tcp only.

## trojan

- **Conclusion**: self-written (small protocol face, heavy transport-composition requirements)
- **Version**: in-tree implementation
- **License**: repository license (self-written)
- **Platforms**: all platforms
- **Public API**: `TrojanConnector` (crates/rillane-protocols/src/outbound/trojan.rs; always TLS-stacked, TCP/WS/gRPC/H2 composition)
- **Bypass**: TLS goes through TlsConnectorFactory (rustls)
- **Cancel**: open-phase checks
- **Stats**: tls=false refused at build time by name; handshake errors through the unified face
- **Reuse**: no prewarm composition; the UDP face (TLS + network=tcp) reuses the node config
- UDP: TLS + network=tcp only.

## anytls

- **Conclusion**: selected library `anytls` (ssrlive/anytls-rs) — a dual client/server library; the alternative anytls-rs (jxo-me, same name different repo) was also evaluated: no release since 2025-11 after 0.5.4, weaker maintenance than the former — the actively maintained one wins. Role boundary: the egress client is wired in this item (RIL-106); the server face is available in the library (Session::new_server + run + accept_stream + read_auth) but rillane's ingress face does not catalog an AnyTLS listener — the real-peer acceptance uses the library's own server face
- **Version**: requirement `0.5`, lock-resolved 0.5.4 (released 2026-11-11; 36 versions since first release 2026-04, actively maintained)
- **License**: MIT
- **Platforms**: all platforms (pure Rust, tokio/rustls stack, edition 2024)
- **Public API**: `Client::new(dialer, padding, idle_timeout, max_session_age)` + `create_stream()` (built-in idle session pool); `StreamIo` (AsyncRead/AsyncWrite adapter); `write_auth_with_client_id` (session auth); UoT face `uot_sentinel_destination`/`UotRequest`/`uot_encode_packet`/`uot_get_packet_from_stream`; wrapped as `AnytlsConnector`/`AnytlsUdpConnector` (crates/rillane-protocols/src/outbound/anytls.rs); the test peer uses the server face `Session::new_server`/`run`/`accept_stream` + `read_auth_with_client_id`
- **Bypass**: the library owns neither dialing nor TLS — the `Dialer` closure is caller-supplied; this repo composes it via TlsConnectorFactory (skip_cert_verify/sni controllable); session framing/multiplexing/padding stay in-library (not bypassed, recorded honestly)
- **Cancel**: `Client::shutdown`; the library re-exports tokio-util CancellationToken; stream drop → FIN close; session auth reads/writes take no timeout — connection-phase cancellation lives at the task-drop layer (recorded honestly)
- **Stats**: the library face has no observation points (traffic_status is the library's own CLI-app face, not part of the library API) — failures surface as io::Error (observed semantics); traffic accounting reuses FlowReport up/down bytes (copy_bidirectional semantics)
- **Reuse**: session reuse is the protocol itself — Client has a built-in idle session pool (idle_timeout/max_session_age parameterized); `create_stream` prefers opening a new stream on an idle session; no external pool needed
- UDP: the library's uot feature (UDP-over-TCP, delivered per actual library capability) — upstream `uot_encode_packet(UotMode::Datagram, dest, payload)`, downstream `uot_get_packet_from_stream`, with the session stream pre-writing the sentinel destination + UotRequest declaring datagram mode; catalog udp=true. Subscription-side alpn/client-fingerprint do not enter the IR (the conversion report names the loss; prefer omission over guessing).

## hysteria

**Not admitted** — no reviewed backend. A config schema and subscription fields are not a connector (same wording as PROTOCOLS.md): assembly refuses with the stable code `config.egress.not_admitted` and never silently falls back to direct.

- Preconditions: the RIL-109 library evaluation (version/license/platforms/public API/bypass/cancel/stats/reuse, each recorded); the UDP carrier (quinn) is undecided.
- Recovery path: complete the evaluation record → flip the catalog entry to admitted → wire the connector → real-peer acceptance.

## hysteria2

- **Conclusion**: selected library `hysteria2`
- **Version**: requirement `0.1.6`, lock-resolved 0.1.6
- **License**: MulanPSL-2.0
- **Platforms**: follows target-platform QUIC (quinn ecosystem) support
- **Public API**: `Hysteria2Connector` (crates/rillane-protocols/src/outbound/hysteria2.rs; TCP stream over QUIC)
- **Bypass**: the library owns the QUIC session — the connector performs no bottom-socket bypass
- **Cancel**: open-phase checks + the library's session-close face
- **Stats**: the library has no per-packet observation points — loss-class statistics are unavailable (never dressed up as game packet loss; same observability wording as mesh.md)
- **Reuse**: no prewarm composition
- UDP: the current connector has no usable UDP egress (carrier quinn undecided, V2 scope; the build-time scan refuses consistently).

## wireguard

- **Conclusion**: selected library `defguard_wireguard_rs` (boringtun core)
- **Version**: requirement `0.11`, lock-resolved 0.11.2
- **License**: Apache-2.0
- **Platforms**: six-platform mainline; exceptions — android and armv7-ohos are refusal stubs (defguard_boringtun lacks platform support / ohos 32-bit libc field collision, see platforms/ohos/README.md); cross-compilation does not prove availability
- **Public API**: `WireguardConnector`/`WireguardUdpConnector` (crates/rillane-protocols/src/outbound/wireguard.rs; userspace carriage)
- **Bypass**: the userspace WireGuard frame face routes by allowed_ips; no system-interface takeover
- **Cancel**: open-phase checks
- **Stats**: handshake failures through the unified face
- **Reuse**: session persistence + persistent_keepalive
- UDP: datagram face (catalog udp=true).

## Shared transport face (cross-protocol)

| Library | Version (requirement / lock) | License | Role |
|---|---|---|---|
| rustls | 0.23 / 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS transport |
| tokio-rustls | 0.26 / 0.26.4 | MIT OR Apache-2.0 | TLS async bridge |
| h2 | 0.4 / 0.4.19 | MIT | HTTP/2 transport |

Transport combinations (TLS/WS/gRPC/H2/HTTPUpgrade) are an orthogonal face of protocol fields and are accepted separately; this page does not repeat their conclusions per protocol.
