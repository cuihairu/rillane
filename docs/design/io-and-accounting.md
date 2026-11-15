# v1 inbound, outbound, session and traffic accounting contracts

Status: **proposal; interfaces are not implemented as a whole**. Refines C03/C21–C24/C31 alongside [v1 architecture](architecture-v1.md). Migrate existing types progressively without reopening completed foundation tasks.

## 1. Responsibilities

```text
Listener / CapturePort → Inbound → PendingSession
                                     ↓
                           SessionExecutor → Router → RoutePlan
                                     ↓
                                  Outbound
                                     ↓
                        UnderlayDialer / validated transports
```

| Abstraction | Responsibility | Reason |
|---|---|---|
| InboundSpec / Factory | Validate and assemble listeners, authentication and admission | Inbound configuration does not select outbounds |
| Listener / CapturePort | Sockets/IP packets into protocols or network stacks | Capture and identity have different OS authority |
| InboundProtocol | Parse/authenticate into target, evidence and pending session | Keep client-protocol responses and framing local |
| EndpointSpec / OutboundFactory | Immutable node/secret references into validated outbound | Subscription formats stay outside forwarding |
| StreamOutbound / DatagramOutbound | Target/OpenContext into stream or association | Establishment differs from forwarding and TCP differs from UDP |
| UnderlayDialer | Resolve/connect/bind/bypass into underlying connection | Platform ports own socket behavior |
| StreamTransport | TLS/WS/gRPC/HTTPUpgrade carriage | Reuse implementations, validate legal combinations |
| SessionExecutor | Establish, confirm inbound, relay and close | Own cancellation, budgets, backpressure, permitted fallback and accounting |
| ResourcePool | Typed prewarm/exclusive/multiplexed resources | Bound and single-use resources are not interchangeable |
| TrafficMeter / SessionObserver | Lightweight counters / lifecycle events | Consistent accounting without blocking forwarding |

Not every concept requires a trait/crate. Hysteria2 may own QUIC sessions and WireGuard tunnels; they expose channel capabilities without forcing every protocol through one stream pipeline.

## 2. Confirmation and ownership

SOCKS5 CONNECT/HTTP CONNECT follows authenticate/parse → PendingStream → route/open outbound → success response → AcceptedStream → relay. InboundResponder maps structured errors to client protocol failures before success. Adapt existing IngressEndpoint.run(router, output) progressively using one session executor.

PendingStream exclusively owns client IO/responder. Accept/reject consumes the responder exactly once. Cancellation/timeouts close resources; failure to write success releases the opened outbound. OpenedStream owns wrapped IO, protocol encryption/framing state and actual endpoint/transport/handshake evidence.

OpenContext contains session/attempt/generation IDs, deadline, cancellation and dial-policy references, not an arbitrary router. Outbound performs one open attempt; SessionExecutor follows RoutePlan fallback. Never blindly replay already-exchanged business data to another endpoint. Errors carry stage, stable code, retryability, evidence and sanitized context; timeout alone does not identify fault ownership.

## 3. UDP and TUN

DatagramAssociation declares fixed/multi-target behavior, maximum payload, source checks, idle/lifetime and close semantics. SOCKS5 UDP control connections govern admission and multiple target mappings; closing control reclaims resources. Each target mapping has its own pinned plan rather than imposing one stream-style decision on all destinations.

TUN network stacks create stream/datagram sessions and own TCP responses; they do not use SOCKS5 responders or inherently provide PID evidence. OwnerResolver provides identity separately. Inbounds budget authentication/admission; established-session resources belong to SessionExecutor.

## 4. Capabilities, transport and pooling

Implementations supply capabilities; factories validate combinations including stream/datagram, transport, payload size, target binding, prewarm and multiplexing. Do not independently duplicate support matrices across importers, runtime scans and protocol classes. Diagnose static incompatibility during assembly; report dynamic OS/network failures during open.

A valid VLESS/WS/TLS path is TCP dial → TLS → WS → VLESS target handshake → business channel. Ordering follows protocol requirements. Apply socket bypass when dialing, before wrappers.

Distinguish unused prewarmed connections (consumed on checkout), exclusive/target-bound channels (reuse only when protocol permits), and multiplexed sessions (open child streams). Keys cover generation/node, binding and transport/security identity; never cross credentials/tenants. TLS resumption is separate from connection reuse. Initialization, drain, cancellation and close have explicit owners.

## 5. Accounting boundaries

| Boundary | Measurements | Purpose |
|---|---|---|
| Inbound | Admissions, auth/reject failures, attributed business bytes | User/device/listener load |
| Session | Directional business bytes, duration, target/rule/scenario, close reason | Authoritative business total and per-flow analysis |
| Outbound/attempt | Open/handshake timing, failures/fallback, actual endpoint, UDP drops | Node quality/load |
| Transport/dialer | Observable underlying bytes, setup/framing, pool hits | Transport overhead, not NIC/IP totals |

Use one authoritative counter at an equivalent business-channel boundary, usually the relay loop or a protocol-specific adapter. Inbound/outbound are attribution views of the same traffic, not additive totals. Upstream consistently means client-to-target.

Declare measurement layer, direction and counting semantics. Distinguish reads, successful writes and drops; partial writes count actual bytes and retries do not duplicate business totals. Zero-length UDP is still one packet. Local send success does not prove remote receipt. Record overhead separately; unavailable network headers/retransmissions remain unknown.

If A fails and B carries the session, charge A its attempt/failure and measured overhead, B actual business attribution, and count session business bytes once. Mark probes/prewarming separately from user traffic. Multiplexed shared overhead stays resource-level when accurate per-flow allocation is unavailable.

TrafficMeter uses bounded lightweight counters. SessionObserver emits low-frequency open/handshake/fallback/close events, not one TraceEvent per read/write. High-cardinality session/attempt/domain/path information belongs in bounded diagnostic views, not Prometheus labels. Disabled statistics or slow consumers cannot block forwarding. Apply [Debug/MCP](debug-and-mcp.md) scope/redaction rules.

## 6. Migration gates

Freeze contracts/ownership then adapt current implementations. Verify responses, cancellation, half-close, partial writes, multi-target/zero-length UDP, pool isolation and no replay on fallback. Reconcile authoritative session totals with ingress/egress attribution while keeping transport totals separate. Root todo.md owns atomic RIL-096–103; this document does not claim implementation completion.

## 7. Prefer external protocol libraries and replaceable backends

A protocol directory is primarily an **adaptation/integration boundary**. Prefer mature existing implementations. Rillane owns contracts, option conversion, capabilities, ownership and necessary compatibility code. Write protocol implementation only after a documented search/evaluation confirms that no usable reusable implementation exists. Missing Rust wrappers, injection or platform support first calls for adapters, upstream contributions or minimal maintained patches, not a convenience rewrite. Existing dependencies already include shadowsocks, hysteria2, tokio-socks and defguard_wireguard_rs.

```text
SessionExecutor
    → StreamOutbound / DatagramOutbound / Inbound contracts
        → protocol adapter
            → external Rust library (preferred) / justified alternative backend
```

Separate protocol identity from implementation backend. Keep user configuration semantic; Factory/features choose a validated default backend rather than requiring per-node library selection. Replacement preserves capability/error/cancellation/accounting/lifecycle contracts, not a promise that every library supports identical transports. Start with one default backend per protocol; do not maintain speculative alternatives.

| Layer | Responsibility | Boundary |
|---|---|---|
| Rillane contracts | Targets, channels, capabilities, errors, events and lifecycle | External types/config/errors must not reach Router/SessionExecutor |
| Protocol adapter | Options, library calls, error translation, cancellation/close and observation | No duplicate routing, budgets or authoritative business counters |
| External library | Framing, authentication/crypto, handshakes and owned connection state | Internal mechanisms are not automatically observable Rillane stages |

Use `protocols/<name>/backend.rs` initially; split `backends/` only for actual alternatives. Keep validation/registration in the protocol module. Share TLS/transports where injection permits; do not forcibly dismantle native QUIC ownership. Isolate heavy dependencies using features or crates; small builds exclude disabled backends from their dependency graph.

Factories inject narrow dial/bypass, cancellation, secret and observation services. Evaluate platforms/architectures, public APIs, maintenance, licensing/redistribution, UDP/transports, injectable dialing/packet IO and build resources before choosing dependencies; these criteria do not certify an unevaluated library.

Library-owned sockets must support required bypass, such as mobile VPN protect. Reject unsupported platform combinations when safe injection/loop prevention cannot be established. Libraries owning relay must expose equivalent business accounting/lifecycle hooks; unavailable timing/transport details stay unknown. Coordinate library retries with executor fallback to avoid duplicate replay.

For other languages assess a stable C ABI/FFI first, then managed subprocesses if justified. Both require explicit threading, buffers, cancellation, crashes and packaging; neither is equivalent to a Rust trait adapter. Subprocesses are not the default architecture and MCP gains no generic execution tool.

Adapt existing working backends before selectively replacing them. Validate equivalent protocol inputs, success/failure, UDP, partial IO, cancellation, release, bypass and accounting. Upstream protocol support does not establish Rillane integration acceptance. Track this through RIL-097/099/100/103.

See the [protocol integration plan](protocol-roadmap.md) for additional protocols, roles and backend gates.
