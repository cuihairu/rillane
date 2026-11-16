# Protocol support (current implementation)

This page records existing boundaries. Future work follows [v1 design](design/architecture-v1.md) and root `todo.md`. Models and scaffolds alone do not prove capability.

## Inbounds

| Type | Supported | Limits |
|---|---|---|
| SOCKS5 | CONNECT, user/password, UDP ASSOCIATE | UDP requires `udp.enabled` and ingress permission |
| HTTP | CONNECT, Basic/Bearer authentication | No complete non-CONNECT HTTP forwarding, cache or MITM |
| mixed | SOCKS5/HTTP detection on one port | Inherits protocol limits |
| TUN | Shared Linux TCP/UDP data plane | Other platforms need complete integration and runtime evidence |

## Outbounds

| Type | Current carriage | Important limits |
|---|---|---|
| direct | TCP/UDP | Bypass required; TCP fwmark does not prove every UDP dial avoids loops |
| SOCKS5 | TCP tunnels + outbound UDP ASSOCIATE (RFC 1928 §6/§7, source verification + FRAG≠0 drop) | HTTP CONNECT remains TCP-tunnel only |
| AnyTLS | TCP over TLS with session reuse; UDP-over-TCP (UoT) | Subscription alpn/client-fingerprint do not enter the IR (named in the report) |
| Shadowsocks | TCP/UDP; SIP003 bridge for TCP | Plugin mode has no UDP; methods follow dependency/runtime validation |
| Trojan | TCP/TLS and supported transports | No promise of UDP/all upstream extensions |
| VLESS / VMess | TCP, WebSocket, gRPC, HTTP/2; REALITY over TCP (client side); XTLS Vision framing over tcp+TLS/REALITY (mirror-peer acceptance) | Validate transports/encryption; REALITY requires `network: tcp` with its own TLS posture; Vision requires `flow: xtls-rprx-vision`, tcp network and a TLS1.3 outer handshake, other flow values refused by name at dial time; no UDP; VMess requires AEAD/alter_id=0 |
| Hysteria2 | TCP streams over QUIC; UDP datagram face (official UDPMessage over QUIC unreliable datagrams, mirror-peer acceptance) | obfs (salamander) unsupported — refused on both TCP/UDP faces; servers without UDP support refused by name (Hysteria-UDP declaration check); not transparent web QUIC carriage |
| TUIC | TCP streams over QUIC (v5 Connect on bidirectional streams, token auth via TLS keying-material exporter); UDP datagram face (v5 Packet over QUIC unreliable datagrams, per-assoc server socket, client-side fragmentation, mirror-peer acceptance) | v5 only — v4 wire shapes have no code path and are refused by name; `congestion-controller` other than `cubic` refused by name at dial time (no silent downgrade); no error-response face — refusals arrive as stream/QUIC teardown |
| WireGuard | Userspace TCP/UDP carriage | Some targets use rejecting stubs; cross-build is not runtime proof |
| Hysteria v1 etc. | Not advertised as available | Schema/import fields or research do not establish a connector |

## Optional features and limits

Mesh is managed topology; ordinary subscription nodes do not understand its envelopes. TCP uses versioned envelopes and hop-by-hop mTLS. UDP Mesh without complete secure carriage remains rejected. Replay sequences do not replace integrity/authentication. See [Mesh reference](mesh.md).

Pools, TLS resumption, padding/timing/shaping and WASM middleware are separate configuration capabilities. Proxy prewarming is not website caching. TLS shape presets do not prove exact browser impersonation. Adding delay does not prove game acceleration. See [configuration](config.md) and [v1 measurement/resource design](design/architecture-v1.md).

Clash/Mihomo compatibility is partial. Validate nodes/groups/rules/transports separately. See [verified gaps](research/proxy-architectures-2026-11-14.md#verified-gaps) for fallback/relay/interval and skipped rules. Import success is not semantic fidelity.
