# Protocol support

Rillane is a network routing proxy system that supports a number of mainstream network protocols.

> **Implementation status notes (verified against the code 2026-09; backfilled P0-1..P0-4 landing status 2026-09-30; backfilled P1-4/P1-5/P2-1..P2-6 landing status 2026-10-02; backfilled P2-7 landing status 2026-10-04; backfilled gRPC/h2 transport landing status 2026-10-10)**: the protocol semantics in this document are design-level wording; the "Status" line at the top of each section is the actual state of the code. Overall comparison:
>
> | Capability | Status | Where it landed |
> |------|------|---------|
> | Ingress socks5 (CONNECT) / http (CONNECT) / mixed | implemented (TCP) | -- |
> | Ingress socks5 UDP ASSOCIATE | **implemented (2026-09, P0-2)**: RFC 1928 ASSOCIATE + datagram relay; the `udp:` block is off by default | -- |
> | Egress direct/socks5/http/shadowsocks/trojan/hysteria2/vless/wireguard (TCP) | implemented | -- |
> | Egress UDP underlay (direct/ss/wg) | **implemented (2026-09, P0-3)**; integration test tool = `rillanectl udp-probe` (P0-5, exit codes 0-4) | -- |
> | Mesh TCP/UDP envelope binary encoding (TCP plane JSON -> binary v2, receiver sniffs and stays compatible with legacy JSON) | **implemented (2026-10, P2-6)**: the UDP plane was binary from P0-4; this step switched the TCP plane `MeshEnvelope` | [mesh-envelope-binary.md](design/mesh-envelope-binary.md) |
> | Mesh UDP multi-hop forwarding (UdpEnvelope over UDP datagrams) | **implemented (2026-09, P0-4)**: FULL/CACHED hop caching, exit per-flow socket, same-port dual stack, plaintext gate (chain+udp without configured encryption is refused at build time) | -- |
> | UDP observability and integration testing (`rillane_udp_*` metric family / `/udp/stats` / the UDP section of `rillanectl stats` / `udp-probe`) | **implemented (2026-09, P0-5)**: `/metrics` always renders (all zeros when the switch is off, the endpoint does not disappear) + ingress-level `udp_enabled` override + all `udp:` config fields | -- |
> | Egress UDP underlay (hy2) | not implemented (the public API of `hysteria2` 0.1.6 has no UDP egress; P0-4 is done and **the re-ruling stands**) | V2 (quinn underlay, undecided) |
> | Egress vmess connector | **implemented (2026-10)**: VMess AEAD auth header (authID time window + anti-replay) + AES-128-GCM/ChaCha20-Poly1305 chunked stream data plane, tcp (optionally layered with TLS) / ws (optionally layered with TLS) / gRPC (always layered with TLS) / h2 (always layered with TLS); `alter_id=0` only, UDP underlay not implemented | the todo "VMess egress" item |
> | hysteria v1 | **egress connector not implemented** (config schema and subscription conversion are supported, build-time error) | no plans (hy2 only) |
> | Egress connection pool / TLS session resumption | **implemented (2026-10, P1-5)**: `egress_pool:` config block + pre-established borrow-and-consume pool (trojan/http/vless/vmess + direct selection) + TLS session resumption (process-wide shared ClientConfig) + `rillane_pool_*`/`rillane_tls_*` metrics + `GET /egress/pool/stats` | -- |
> | Packet-length padding obfuscation cross-cutting layer (`FlowMiddleware` + chain `MeshEnvelope` frame padding + `rillane_obfs_*` metric family + distribution check script) | **implemented (2026-10, P1-4)**: fixed/bucket/range shapes; a no-op for single-hop TCP with no own frame, UDP datagram padding has a reserved hook behind `UdpEnvelope` (V2) | [obfuscation-middleware.md](design/obfuscation-middleware.md) |
> | Mesh link observability (per-link RTT quantiles / observed loss / switch-reason ledger) | **implemented (2026-10, P2-1)**: `rillane_mesh_link_rtt_ms{from,to,quantile}` + `rillane_mesh_link_loss_ratio{from,to}` + `rillane_mesh_switch_total{reason}` (always rendered while chains are enabled) + `GET /mesh/switches` with the last 100 events; all three families and the endpoint are absent while mesh is disabled | [mesh-link-observability.md](design/mesh-link-observability.md) |
> | Mesh UDP anti-replay + revocation visibility | **implemented (2026-10-04, P2-7)**: v2 frame stream sequence numbers on the UDP plane + per-(flow,dir) 64-bit sliding window (`replay_dropped` counted into `/udp/stats` and `/metrics`) + revocation file carrier with mtime hot reload + runtime observability (`GET /mtls/revoked`, `rillanectl mtls revoke status`); OCSP/CA direct revocation queries and end-to-end MAC are deferred to V2 | [mesh-advanced-security.md](design/mesh-advanced-security.md) |
> | Timing/shaping perturbation (startup jitter + grid-aligned writes) | **implemented (2026-10, P2-4)**: `TimingMiddleware` sleeps inside handle (fixed/uniform, `max_delay_ms` gate), `ShapingMiddleware` wraps `flow.io` as `PacedIo` (interval grid + jitter, the read side is not wrapped); annotations are observable as `rillane.obfs.timing`/`rillane.obfs.shaping`; the game preset demonstrates the wiring | [obfuscation-timing-shaping.md](design/obfuscation-timing-shaping.md) |
> | SLO-scored path selection (group policy `slo:` gate + penalty scoring + chain-side `slo_watch` switch on degradation) | **implemented (2026-10, P2-2)**: the `latency` policy with real data present = the lowest score inside the gate (score = p95 + loss x penalty); the chain watcher switches as soon as the gate is crossed, ledger entry `reason="slo_degraded"`; deployments without real data behave unchanged; the `slo_watch` YAML surface is deferred to P2-3 | [slo-scoring.md](design/slo-scoring.md) |
> | Scenario profile presets (`profile: proxy\|game\|web`, expanded at config time) | **implemented (2026-10, P2-3)**: default-filling semantics (explicit always wins, zero branching at runtime); game = SLO targets + domain templates + bucket padding; web = connection pool; pick any one of `examples/profile-*.yaml` and it runs | [scenario-profiles.md](design/scenario-profiles.md) |
> | obfs/salamander plugins | not implemented (the salamander pseudo-state is not on this repo's roadmap) | V2 candidate |
> | Timing/shaping perturbation | **implemented (2026-10, P2-4)** | [obfuscation-timing-shaping.md](design/obfuscation-timing-shaping.md) |
> | Client TLS fingerprint shapes (none/chrome/ios/safari presets + pool-key/factory-key extension) | **implemented (2026-10, P2-5)**: selected by the egress `tls_fingerprint` config, the QUIC plane is not included | [tls-fingerprint.md](design/tls-fingerprint.md) |
>
> The word "aspirational" in the notes below means: this document keeps the design-goal description, but the current code does not contain that implementation.

## Ingress Protocols

### SOCKS5 proxy
> Status: CONNECT is implemented (including username/password authentication, `IngressConfig::Socks5`) and **UDP ASSOCIATE (2026-09, P0-2)** -- cmd 0x01/0x03 dispatch (`rillane-protocols/src/inbound/socks5.rs`), ASSOCIATE service/datagram header encoding/decoding and admission in `rillane-core/src/udp/associate.rs`, the auth username enters the sticky key, the mixed ingress shares the same path; the `udp:` config block is off by default (when off, 0x03 gets 0x07). Details in [udp-dataplane.md](design/udp-dataplane.md) §2 and [udp-relay-path.md](design/udp-relay-path.md) §2.

- **Protocol version**: SOCKS5 (RFC 1928)
- **Authentication**:
  - No authentication
  - Username/password authentication (RFC 1929)
- **Supported commands**:
  - CONNECT (TCP connection)
  - UDP ASSOCIATE (UDP proxy)
- **TLS support**: TLS connections can be established over SOCKS5

### HTTP proxy
> Status: the CONNECT tunnel is implemented (non-CONNECT requests get 405) + inbound Basic authentication (a non-empty `IngressConfig::Http.auth` credential table means enforcement: a missing `Proxy-Authorization` header or bad credentials both answer `407 Proxy Authentication Required` + `Proxy-Authenticate: Basic`; an empty table or absent means anonymous passthrough; only the CONNECT surface is checked, non-CONNECT requests pass auth first and then get 405) + **Bearer Token authentication (2026-10-10: the `IngressConfig::Http.bearer_tokens` token table -- `Proxy-Authorization: Bearer <token>` compared in plaintext, in parallel with Basic so either passing is enough, the 407 challenge advertises the configured scheme; the mixed ingress's http branch has the same semantics)**. The "supported methods" matrix below, request/response header rewriting and compression are still **aspirational descriptions** (the CONNECT tunnel data plane is a raw byte stream with no HTTP headers or compression to modify).

- **Protocol version**: HTTP/1.1
- **Supported methods**: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- **Authentication**:
  - Basic authentication (implemented, `auth` field + `Proxy-Authorization` check)
  - Bearer Token authentication (implemented, `bearer_tokens` field + `Proxy-Authorization: Bearer` check)
- **Features**:
  - HTTP CONNECT method support for HTTPS proxying
  - Request/response header rewriting (not implemented, aspirational description -- requires a full forwarding-proxy data plane, this ingress only does the CONNECT tunnel)
  - Compression support (gzip, deflate) (not implemented, aspirational description -- same as above)

### Mixed proxy
> Status: protocol auto-detection and port sharing are implemented; `IngressConfig::Mixed.auth` is wired -- the socks5 branch enforces RFC 1929 (answering 0xFF when only a no-auth method is offered), the http branch uses Basic authentication (407 refusal); an empty table or absent means both branches allow anonymous, same semantics as Socks5/Http; `bearer_tokens` is the same as Http (http branch only).

- **Description**: supports both SOCKS5 and HTTP protocols
- **Auto-detection**: identifies the protocol type from request characteristics
- **Port sharing**: multiple protocols served on the same port

## Egress Protocols

### Direct
> Status: TCP direct is implemented (multi-candidate **RFC 8305 Happy Eyeballs race, 2026-10-07**: IPv6-first dual-stack interleaving, a 250 ms staggered fallback, cover immediately on failure, the first success wins) and the **UDP underlay (2026-09, P0-3, direct carrier)** -- the "automatic IP version selection / Happy Eyeballs" aspirational description is cleared.

- **Description**: connect to the target server directly, without a proxy
- **Supported protocols**: TCP, UDP
- **Features**:
  - Minimal latency
  - Automatic IP version selection (IPv4/IPv6)
  - Happy Eyeballs algorithm support

### SOCKS5 egress
> Status: TCP forwarding and username/password authentication are implemented; "UDP relay" is **not implemented** and not in the S1 scope (see [udp-dataplane.md](design/udp-dataplane.md) §3.5) -- aspirational description.

- **Purpose**: forward traffic through an external SOCKS5 proxy
- **Authentication support**:
  - No authentication
  - Username/password authentication
- **Features**:
  - IPv4/IPv6 support
  - UDP relay support

### HTTP proxy egress
> Status: the CONNECT tunnel, Basic authentication and TLS+SNI are implemented (`EgressConfig::Http`); "proxy chaining" is not implemented as an egress parameter -- multi-hop is expressed through mesh chains (see [mesh.md](mesh.md)).

- **Purpose**: forward traffic through an external HTTP proxy
- **Supported versions**: HTTP/1.1, HTTP/1.0
- **Authentication**:
  - Basic authentication
  - ~~Bearer Token authentication~~ (Bearer is an ingress capability -- see the HTTP ingress section, not supported on egress)
- **Features**:
  - ~~Proxy chaining~~ (not implemented -- multi-hop is expressed through mesh chains, see the status note)
  - Automatic tunnel handling (CONNECT)

### Shadowsocks
> Status: TCP is implemented (AEAD encryption carried by the `shadowsocks` crate, the available methods follow crate 1.25, `method` is a free-form string and an illegal value errors at build time) and **UDP (2026-09, P0-3: `ShadowsocksUdpConnector`, method validation moved up to build time, fixed target address per R7 semantics; a full decrypt round trip needs integration testing with a shadowsocks-service server, deferred to P0-5)** and the **SIP003 plugin bridge (2026-10-07: `plugin`/`plugin_opts` fields -- the TCP data plane is bridged through the plugin process, the SS_LOCAL_*/SS_REMOTE_* environment convention + local port readiness probe + the child process is killed on connection teardown with kill_on_drop; the UDP plane does not go through the plugin (SIP003 defines TCP only), and UDP capability is judged negative at build time by scan_udp_capability in plugin mode; the subscription side's clash import converts via a translation table (obfs -> `obfs-local`, host -> `obfs=`/`obfs-host=`, v2ray-plugin passed through with original key/value names, bool true -> bare flag, other plugin names rejected rather than imported loosely), and export has no Clash equivalent so only a degradation notice is given; end-to-end plugin use needs a real plugin binary environment, and unit tests cover spawn failure / port probe in both states)**; dynamic port allocation is **not implemented** -- aspirational description.

- **Cipher suites**:
  - AES-256-GCM
  - AES-128-GCM
  - ChaCha20-IETF-Poly1305
  - XChaCha20-IETF-Poly1305
- **Supported protocols**: TCP, UDP
- **Features**:
  - Plugin system support (v2ray-plugin, obfs)
  - Dynamic port allocation (not implemented, aspirational description -- an SIP004 server-side feature, this repo's Shadow (SS) is egress-only)
  - Obfuscation and disguise

### VMess (V2Ray)
> Status: **egress connector implemented (2026-10)** -- VMess AEAD auth header (authID = AES-ECB(unix seconds ‖ random ‖ CRC32), server-side ±120 s time window + anti-replay) + chunked stream data plane (chunk-stream|chunk-masking|global-padding; SHAKE128(direction IV) derives the mask and the padding length, **per block draw the padding before the mask**, block nonce = counter ‖ IV[2..12] incremented); the KDF/request header/envelope/SHAKE extraction order is nailed down byte-by-byte against real-value vectors produced by a live run of Xray-core's kdf.go source (cross-checked with Go 1.27.1, V0-V16). security supports `auto`/`aes-128-gcm`/`chacha20-poly1305` (the xray AEAD scope; legacy `alter_id>0` and none/zero are refused at build time); transport tcp (optionally layered with TLS/SNI/ALPN/fingerprint), ws (optionally layered with TLS, an upgrade failure is marked stale and redialed once) and gRPC (2026-10: `network: grpc` + `grpc_service_name`, always layered with TLS + ALPN h2, POST `/{service}/Tun` single-stream tunnel, request header ‖ first block merged into the first gRPC message, 5-byte length-prefixed frames, 16 MiB message cap; the pool key carries ALPN h2, a tunnel handshake failure is marked stale and redialed once; the subscription side imports and exports clash `grpc-opts`). The h2 transport is implemented (2026-10: `network: h2` + `path`/`host`, always layered with TLS + ALPN h2, POST `{path}` single-stream tunnel, `:authority` = host first value -> sni -> server, request and response bodies are raw byte streams in both directions; after the request headers are written to the stream, `tokio::io::split` reuses the existing chunked stream relay; the pool key carries ALPN h2, the SNI chain is sni -> host first value -> server, a tunnel handshake failure is marked stale and redialed once; the subscription side imports and exports clash `h2-opts`); UDP underlay is not implemented (a build-time scan errors out).

- **Version**: VMess (V2Ray Protocol) -- AEAD auth header (Xray-core-aligned linear form authID‖sealedLen‖connNonce‖sealedHeader)
- **Security**: auto / AES-128-GCM / ChaCha20-Poly1305 (legacy MD5 authentication and none/zero were removed with xray)
- **Transport layer**:
  - TCP (optionally layered with TLS)
  - WebSocket (WS) (optionally layered with TLS)
  - gRPC (always layered with TLS, `grpc_service_name`)
  - HTTP/2 (h2) (always layered with TLS, `path`/`host`, raw byte stream single-stream tunnel)
- **Path configuration**:
  - Custom path (ws path, the `/` prefix is added automatically)
  - Host header camouflage (`host` first value wins, falling back to sni/server)
- **TLS support**:
  - TLS 1.2/1.3
  - SNI camouflage
  - ALPN negotiation
  - Client TLS fingerprint shape (`tls_fingerprint`, P2-5)

### VLESS
> Status: partially implemented -- uuid authentication + TCP direct / WebSocket / gRPC transport (tcp/ws can be layered with TLS/SNI/ALPN, `network: ws`; gRPC 2026-10: `network: grpc` + `grpc_service_name`, always layered with TLS + ALPN h2, POST `/{service}/Tun` single-stream tunnel, the request headers are the first gRPC message, the response header `[ver][opt_len][opt]` is extracted across messages, client EOF -> zero-length DATA + END_STREAM to close out; the pool key carries ALPN h2, a tunnel handshake failure is marked stale and redialed once; the subscription side imports and exports clash `grpc-opts`). The h2 transport is implemented (2026-10: `network: h2` + `path`/`host`, always layered with TLS + ALPN h2, POST `{path}` single-stream tunnel, request/response bodies are raw byte streams in both directions, and after the tunnel is up it is the same shape as the tcp arm with `copy_bidirectional`; the pool key carries ALPN h2, the SNI chain is sni -> host first value -> server, a tunnel handshake failure is marked stale and redialed once; the subscription side imports and exports clash `h2-opts`); **flow (e.g. xtls-rprx-vision) is explicitly rejected** (blocked at build time, RuntimeBuilder reports the assembly error and lists the node names, the same rule as `forward()` where `is_some()` means reject). The "QoS integration" and "VLESS-Vision" series are **aspirational descriptions**.

- **Characteristics**: lightweight protocol with no built-in encryption (plaintext underlay, confidentiality is the TLS transport layer's responsibility)
- **Flow control**:
  - VLESS-Vision-Stream (real-time stream)
  - VLESS-Vision-UDP (UDP support)
- **Transport layer**: same as VMess
- **Features**:
  - Lower performance overhead (one less layer of in-protocol encryption than VMess)

### Trojan
> Status: partially implemented -- TCP native + full TLS (SNI/certificate validation/`skip_cert_verify`/fingerprint), the "traffic looks like standard HTTPS" goal is met by the TLS shape; the WebSocket transport is implemented (trojan-go convention: ws always layers TLS, the request headers are the first binary frame, there is no separate response header; a pool upgrade failure is marked stale and redialed once); the gRPC transport is implemented (2026-10: `network: grpc` + `grpc_service_name`, always layered with TLS + ALPN h2, POST `/{service}/Tun` single-stream tunnel, the request headers are the first gRPC message, 5-byte length-prefixed frames, 16 MiB message cap; the pool key carries ALPN h2, a handshake failure is marked stale and redialed once; the subscription side imports and exports clash `grpc-opts`); the h2 transport is not implemented (the trojan whitelist is tcp/ws/grpc only, `network: h2` is refused at build time).

- **Protocol**: a proxy protocol camouflaged as TLS
- **TLS features**:
  - Full TLS 1.3 handshake
  - Certificate verification
  - SNI camouflage
- **Transport layer**:
  - TCP (native)
  - WebSocket
  - gRPC
- **Security**:
  - Traffic looks like standard HTTPS
  - Strong DPI / censorship resistance

### Hysteria
> Status: **the v1 egress connector is not implemented** (the config schema and subscription conversion are supported, build-time error "unsupported egress type"); this section is kept as background material.

- **Protocol**: a high-performance proxy based on QUIC
- **Version**: Hysteria v1/v2
- **Congestion control**:
  - BBR (Bottleneck Bandwidth and RTT)
  - Cubic
  - Custom algorithms
- **Authentication**:
  - Password authentication
  - Base64/Str string
- **Features**:
  - UDP first-packet optimization
  - Adaptive rate control
  - Low-latency transfer

### Hysteria2
> Status: partially implemented -- TCP over QUIC, password authentication, `mport`/`server_name`/`alpn`/`skip_cert_verify` take effect (carried by the `hysteria2` crate); congestion control algorithm selection and **UDP relay / first-packet optimization are not implemented** -- V1 verification result (2026-09): the public API of `hysteria2` 0.1.6 is connect/tcp_connect only, `quic_connection` is pub(crate), there is no UDP egress, this is not a silent shrinkage, and the re-ruling that moved it to P0-4 **stands when P0-4 was completed** (2026-09, todo P0-4 §0.1-③ -- the final state of hy2 UDP = V2, the quinn underlay is undecided, see the P0-3/P0-4 items in [todo.md](../todo.md) and [udp-mesh-dataplane.md](design/udp-mesh-dataplane.md)); salamander obfuscation is not implemented (no such field in the config; the packet-length padding cross-cutting layer landed at P1-4, timing/shaping perturbation landed at P2-4, salamander is a V2 candidate).

- **Protocol**: an improved version of Hysteria
- **Improvements**:
  - Simpler protocol design
  - Better mobile-network support
  - Lower CPU usage
- **Encryption**:
  - AES-128-GCM
  - ChaCha20-Poly1305
- **Authentication**:
  - Password or string
  - Obfuscation support (salamander)

### WireGuard
> Status: partially implemented -- TCP traffic is forwarded through the system WireGuard interface (`address`/`allowed_ips`/`preshared_key`/`persistent_keepalive`/`mtu`/`dns` take effect, needs a system WG interface and the corresponding permissions); "kernel-level implementation" means it depends on the system WG, and rillane does not do its own encryption/decryption; **the UDP underlay is implemented (2026-09, P0-3: `WireguardUdpConnector` -- pre-check after parsing `allowed_ips` (not in the set -> split the mapping and re-route) + an `mtu-80` cap, still through the system WG interface path)**, see [udp-relay-path.md](design/udp-relay-path.md).

- **Protocol**: a fast, modern VPN
- **Encryption**:
  - ChaCha20-Poly1305
  - AES-GCM
- **Key exchange**: Curve25519
- **Features**:
  - Layer 3 (IP) tunnel
  - Full forward secrecy
  - Simplified configuration
- **Performance**:
  - Kernel-level implementation
  - Very low CPU overhead

## Protocol extensions

Rillane's modular design lets a new protocol be attached as an `EgressConnector` implementation:

1. **Implement the protocol trait**: create a new protocol handler
2. **Register the protocol**: declare the new protocol in the config file
3. **Routing integration**: the protocol takes part in routing decisions automatically

### Example of adding a new protocol

```rust
use async_trait::async_trait;
use rillane_core::{Flow, FlowRouter};

pub struct MyProtocol;

#[async_trait]
impl EgressConnector for MyProtocol {
    fn name(&self) -> &'static str {
        "my-protocol"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        // implement the protocol forwarding logic
        todo!()
    }
}
```

## Performance optimization

> Status: async I/O (tokio) is implemented; **zero-copy/batched I/O landed within scope** (2026-10, P3-5: the relay buffer is parameterized as `performance.relay_buffer` (default 8192, zero difference) + `copy_bidirectional_with_sizes` at 16 relay points + mesh frame writes merged into one vectored submission; the benchmark and scope ruling are in [performance-io.md](design/performance-io.md) -- kernel splice and UDP recvmmsg/sendmmsg are out of scope, documented as-is); the **connection pool is implemented** (2026-10, P1-5: pre-established borrow-and-consume pool + TLS session resumption, the `egress_pool:` block, metrics such as `rillane_pool_reuse_ratio` are visible -- total dials not dropping below the flow count is a structural constraint because each flow consumes one connection, and reducing total connections is deferred to V2 multiplexing); "smart selection / failover" is partly true -- group-policy path selection (7 policies) and mesh chain failover are implemented; "session persistence" holds on the UDP side (2026-09, P0-1 session table: process/five-tuple sticky keys + idle/lifetime reclamation, `rillane-core/src/udp/`), and TCP connection reuse holds in pool form (2026-10, P1-5).

### Protocol-layer optimization
- **Zero-copy**: Rust's ownership system avoids unnecessary memory copies (**implemented (within scope)**, 2026-10 P3-5 -- a userspace relay cannot avoid copies entirely (TLS termination, middleware chain semantics), so what landed is fewer copies and syscalls: `performance.relay_buffer` makes the bidirectional buffers configurable (+67% median throughput in the 8K->256K benchmark), `copy_bidirectional_with_sizes` at 16 relay points, mesh frame writes merged into one vectored submission (about 26% faster on the 4 KiB frame benchmark; rustls has no vectored path on the TLS segment, so it falls back to today's equivalent), and kernel splice is ruled out of scope (the middleware chain wrapper breaks fd semantics), see [performance-io.md](design/performance-io.md))
- **Connection pool**: reuse TCP connections to cut handshake overhead (**implemented**, 2026-10 P1-5 -- the pool shape is pre-established + borrow-and-consume: a request served from a borrowed connection pays no dial and no handshake, and the handshake of warm-up/supplement dials is replaced by TLS session resumption; total dials not dropping below the flow count is a structural constraint, and reducing total connections is deferred to V2 multiplexing)
- **Async I/O**: non-blocking I/O based on Tokio (implemented)
- **Batching**: batched send and receive support (**not implemented** -- UDP recvmmsg/sendmmsg batched I/O is ruled out of scope: there is no evidence of a high-packet-rate scenario in production, and the complexity of libc direct calls + tokio-managed fd compatibility is not worth it; to be re-evaluated with a benchmark-driven approach once a real high-packet-rate device scenario exists, see [performance-io.md](design/performance-io.md) §2-D4)

### Routing optimization
- **Smart selection**: pick the best path by latency, bandwidth and load
- **Session persistence**: keep routing consistent for the same connection
- **Failover**: detect failures automatically and switch to a backup path
- **Link observability**: per-link RTT p50/p95 quantiles, observed loss ratio, a switch-reason ledger and counters (2026-10, P2-1, three families in `/metrics` + `GET /mesh/switches`)
- **SLO-scored path selection**: the `latency` policy scores against p95 RTT/loss targets (the `slo:` gate + penalty), the chain side's `slo_watch` switches automatically on degradation and the reason is ledgered (2026-10, P2-2, see [slo-scoring.md](design/slo-scoring.md))
- **TLS fingerprint shapes**: the four TLS variants of egress, `tls_fingerprint: none|chrome|ios|safari`, with pool-key/factory-key extension (2026-10, P2-5, `rillanectl tls-fingerprint` prints the preset shape_material comparison table, see [tls-fingerprint.md](design/tls-fingerprint.md))

## Security features

> Status: mesh-layer CA rotation / dual trust window / minimal revocation list are implemented ([mesh.md](mesh.md)); "automatic periodic key rotation", "multi-factor authentication" and "JWT/Token management" are **not implemented** -- aspirational descriptions; of "TLS camouflage", the Trojan/VLESS+TLS shapes are implemented, and for "protocol obfuscation / domain fronting" the packet-length padding cross-cutting layer landed at P1-4 and timing/shaping perturbation landed at P2-4 (see the current-state notes in [positioning.md](design/positioning.md) §2.4, todo P2-4/P2-5).

### Encryption support
- **End-to-end encryption**: all protocols support strong encryption
- **Key rotation**: automatic periodic key updates
- **Forward secrecy**: full forward secrecy support

### Authentication mechanisms
- **Multi-factor authentication**: support for combining multiple authentication methods
- **Certificate verification**: full certificate chain verification
- **Token management**: support for JWT and other token formats

### Traffic disguise
- **TLS camouflage**: make traffic look like normal HTTPS
- **Protocol obfuscation**: hide protocol fingerprints using plugins
- **Domain fronting**: hide the real server through a CDN

## Configuration example

> The field-level full reference (defaults and build-time validation of each block) is in [config.md](config.md).

```yaml
ingress:
  - name: socks5-proxy
    type: socks5
    bind: "0.0.0.0:1080"
    auth:
      - username: user1
        password: pass1

egress:
  - name: vmess-server
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789abc"
    alter_id: 0
    security: auto
    network: ws
    path: /path
    host: ["vmess.example.com"]
    tls: true
    sni: vmess.example.com
```

## Compatibility

### Client compatibility
Rillane's ingress is interoperable with mainstream proxy clients (the SOCKS5/HTTP CONNECT scope; methods the ingress does not support return 405):

- **Windows**: Shadowsocks-windows, Clash, v2rayN, Qv2ray
- **macOS**: ShadowsocksX-NG, ClashX, V2RayU
- **Linux**: shadowsocks-libev, clash, v2ray-core
- **Android**: v2rayNG, Clash for Android, Shadowsocks Android
- **iOS**: Shadowrocket, Quantumult X, Surge, Stash

### Server interoperability
- **V2Ray**: core VMess/VLESS surface interoperable (tcp/ws/gRPC/h2; VLESS flow is not supported, see the status line of each section)
- **Xray**: VMess AEAD (tcp/ws/gRPC/h2) + VLESS (tcp/ws/gRPC/h2, no flow) interoperable; flow is not supported
- **Shadowsocks**: AEAD methods interoperable (the method set follows the `shadowsocks` crate 1.25, an illegal `method` errors at build time)
- **Trojan**: standard Trojan protocol implementation (TCP native + TLS; ws/gRPC transport implemented)

## Roadmap

### Coming up
- [ ] QUIC v2 support
- [ ] HTTP/3 proxy
- [ ] WireGuard v2
- [x] Custom protocol plugin system (WASM loader landed, 2026-10-04 P3-2 -- [plugin-loader.md](design/plugin-loader.md))
- [x] Protocol performance benchmark tool (landed, 2026-10 P3-5 -- criterion benchmarks: median throughput across 8K-256K relay buffers and two-stage vectored frame-write comparison, the numbers and noise scope are in [performance-io.md](design/performance-io.md) §5)

### Future plans
- [ ] Native QUIC protocol proxy (unscheduled -- the hy2 egress UDP underlay follows the V2 quinn underlay ruling, see [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md))
- [x] gRPC protocol support (2026-10: trojan/vless/vmess egress `network: grpc` single-stream tunnel)
- [ ] eBPF acceleration (XDP)
- [x] WebAssembly protocol plugins (wasmtime dynamic loading + example plugin, same as P3-2 -- [plugin-loader.md](design/plugin-loader.md))
- [ ] Adaptive protocol selection

More information in the [architecture overview](architecture.md), the [subscription guide](subscription.md), [system routing](networking.md), the [Mesh guide](mesh.md) and the [design docs](design/positioning.md).
