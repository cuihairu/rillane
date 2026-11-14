# S1 UDP Full-Chain Design Draft (UDP Data Plane)

> Status: **Landed (todo P0-1..P0-5 complete, 2026-09)** · Maps to [roadmap.md](roadmap.md) S1 · Covers [todo.md](../../todo.md) P0-1..P0-5
> Upstream docs: [positioning.md](positioning.md) (positioning and gap G1) · [architecture.md](../architecture.md) (crate layout and key interfaces) · [mesh.md](../mesh.md) (TCP dataplane/envelope/mTLS) · [PROTOCOLS.md](../PROTOCOLS.md) (capability claims, partially aspirational, see §0.2 status labels)
> Implementation status is authoritative per each section's "status note" and the sub-draft status lines; deviations between design-time phrasing and reality have been backfilled as things landed.

## Executive Summary

> **Status note (2026-09-30 backfill)**: the paragraph below, "the current datapath is pure TCP", is a **design-time description, outdated once P0-1..P0-4 landed** -- inbound ASSOCIATE (P0-2), direct/ss/wg egress payloads (P0-3), and the mesh UDP data plane (P0-4) are all implemented; the as-landed state is authoritative per the §0.2 table.

The current datapath is pure TCP: inbound socks5 explicitly rejects UDP ASSOCIATE (`inbound/socks5.rs` accepts only cmd=0x01), egress hy2/wg dispatch by `TargetProto` and error on non-TCP, and the mesh data plane binds `MeshStream` to `AsyncRead+AsyncWrite`. This draft gives a parallel UDP plane that does not disturb the TCP plane:

1. **`rillane-core` gains a UDP session layer** (NAT-style session table + sticky key + parallel trait `EgressUdpConnector`) -- because `Flow.io: BoxedIo` is stream semantics and cannot be reused for UDP;
2. **socks5 inbound adds the 0x03 command**, reusing the existing auth/parsing framework;
3. **Four UDP-capable egress types** (direct/ss/hy2/wg); other types error at build time when UDP is routed to them;
4. **mesh UDP plane**: the first packet carries the path, later packets carry only flow_id with hop-to-hop cached forwarding; envelope binarization starts on the UDP plane (MTU is a hard constraint) and merges with P2-6;
5. **Observability/config**: top-level `udp:` block + new `rillane_udp_*` metric series under `/metrics`.

Design principle: the UDP plane and the TCP plane **coexist in parallel** inside the same process, sharing the Flow session model, routing engine, control plane, and subscriptions; there is no branched product path (positioning.md §2.5).

---

## 0. Overall View and Current-State Labels

### 0.1 Data flow overview

```
              TCP plane (current, untouched)                UDP plane (new in this draft)
app ──► socks5/http/mixed ─┐          app ──► socks5 UDP ASSOCIATE ─┐
                           │                                        │
                      Flow(io)                            UdpSession(session table + sticky key)
                           │                                        │
                    FlowRouter (shared, transport-agnostic) ◄──────────────────┘
                           │                                        │
                    EgressConnector                     EgressUdpConnector
                    (direct/ss/trojan/hy2/vless/wg)     (direct/ss/hy2/wg)
                           │                                        │
                    mesh TCP data-plane                 mesh UDP data-plane
                    (MeshEnvelope JSON, mTLS)           (UdpEnvelope binary, encryption see §4.4)
```

### 0.2 Cross references and PROTOCOLS.md status labels

> **2026-09-30 backfill (second round, alongside P0-4 completion)**: P0-1 (session table) / P0-2 (ASSOCIATE) / P0-3 (direct/ss/wg egress payloads) / **P0-4 (mesh UDP plane, S0–S6 all landed, 27 new tests all green)** have landed; the "as-landed state" column is labeled as-is; P0-5 has landed as well ([udp-observability.md](udp-observability.md), 2026-09), and related claims have been backfilled to match reality.

| Claim source | Status (at design time) | As-landed state (2026-09 backfill) | Handling in this draft |
|---------|------|------|---------|
| PROTOCOLS.md "SOCKS5 … UDP ASSOCIATE (UDP proxy)" | **Aspirational description (design text ahead of the implementation)** (code only had CONNECT) | Implemented (P0-2, 2026-09) | §2 landed complete; PROTOCOLS.md reference table and SOCKS5 section already changed to "implemented" |
| PROTOCOLS.md "Shadowsocks … TCP, UDP" | Partially aspirational (TCP only) | UDP implemented (P0-3 `ShadowsocksUdpConnector`; full decrypt round-trip integration test deferred to P0-5) | §3.2 landed complete |
| PROTOCOLS.md "Hysteria … UDP first-packet optimization" / hy2 subsection | Aspirational (TCP only) | Not implemented -- V1 check: `hysteria2` 0.1.6 public API has no UDP egress; moved to P0-4 and **the revision is upheld when P0-4 completes** (todo P0-4 §0.1-③), hy2 UDP final state = **V2 (quinn vehicle, undecided)** | §3.3 branch (c) rerouted |
| PROTOCOLS.md "WireGuard … Layer 3 (IP) tunnel" | Consistent with the implementation (TCP over WG already works) | UDP implemented (P0-3: `allowed_ips` pre-check + MTU ceiling `mtu-80`, still uses the system WG interface) | §3.4 extension landed |
| PROTOCOLS.md "SOCKS5 egress … UDP relay" | Aspirational | Remains out of S1 scope (§3.5) | Unchanged |
| mesh.md "Mesh Data-Plane Protocol" | Labeled at design time (TCP, MVP) | UDP plane implemented (P0-4, 2026-09) -- mesh.md's current-state note has removed the "(TCP, MVP)" qualifier and been rewritten per its original condition | §4 landed ([udp-mesh-dataplane.md](udp-mesh-dataplane.md)) |
| architecture.md "next phase … UDP etc." | Planned | P0-1..P0-4 landed; P0-5 design and work breakdown ready (architecture.md dataplane/roadmap UDP wording corrected in both places) | This draft + four implementation-level designs |

## 1. UDP Session Table and Sticky Key (P0-1)

> Implementation-level expansion: [udp-session-table.md](udp-session-table.md) (two-level mapping structure, sticky key priority and decision invalidation, reclaim state machine, FlowSession field-by-field integration and test checklist).

### 1.1 Reuse

| Existing asset | Use |
|---------|------|
| `rillane-core::TargetProto::{Udp, Quic}` | The enum already exists, used directly as the session target protocol marker (in the TUN phase Quic gets a distinct marker at identification; the forwarding plane is UDP datagrams either way) |
| `rillane-core::FlowTarget` | Each target mapping within a session reuses this structure |
| `rillane-core::FlowSession`/`SessionUsage`/`FailureStats` | Session statistics and failure record fields hang directly off the UDP session |
| `rillane-core::FlowRouter`/`FlowMiddleware` | Routing decisions and middleware apply equally to the UDP plane (transport-agnostic) |
| workspace dependency `dashmap 6.0` | Session table container |
| `rillane-routing::RoutingEngine` | Unchanged; a UDP session's first packet goes through the same routing decision |

### 1.2 New additions (`rillane-core` new module `udp.rs`)

```rust
pub struct UdpSessionKey {           // sticky key
    pub client: SocketAddr,          // inbound client source address (IP:port)
    pub client_id: Option<String>,   // socks5 auth username (optional dimension)
}

pub struct UdpSession {
    pub key: UdpSessionKey,
    pub decision: Arc<RouteDecision>,// first-packet routing decision cache -- the core of session stickiness
    pub mappings: LruCache<FlowTarget, UdpMapping>,  // NAT-style target mapping
    pub session: FlowSession,        // reused statistics
    pub last_activity: Instant,
    pub expires_at: Instant,
}

pub struct UdpSessionTable { /* DashMap<UdpSessionKey, UdpSession> + background reclaim task */ }

#[async_trait]
pub trait EgressUdpConnector: Send + Sync {
    fn name(&self) -> &'static str;
    /// Establish a UDP association to the target, returning a relay handle that can send and recv
    async fn associate(&self, ctx: FlowContext) -> Result<Box<dyn UdpRelay>>;
}

#[async_trait]
pub trait UdpRelay: Send {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)>;
}
```

**Design decision -- a parallel trait rather than extending `EgressConnector`**: the existing `EgressConnector::forward(flow: Flow) -> FlowReport` semantics is "take over the stream inside `Flow.io`, copy both ways, returning ends it" (8 TCP implementations depend on this contract). A UDP session is long-lived, datagram-oriented, and one client socket facing many targets (NAT semantics); cramming it into the same trait would force empty implementations into every TCP implementation and weaken type safety. A parallel `EgressUdpConnector` leaves the TCP plane untouched (the coexistence approach).

**Sticky semantics**: every packet with the same `UdpSessionKey` hits the same `RouteDecision` (cached in the session); a game session does not jump links because of per-packet rerouting. The **process dimension** of the sticky key (todo P0-1 mentions "process/five-tuple") depends on P1 TUN to obtain process info; S1 lands as `client addr + optional username`, the struct reserves a `process_id: Option<u32>` field, and P1 fills it -- structurally compatible already, no second migration needed.

**Timeout reclaim**: a background tokio interval task scans (reusing the existing `rillane-runtime` background task pattern, cf. `ChainManager::start_health_check_task`). Defaults: a session is reclaimed after 180s idle; a single target mapping inside a session is removed after 60s idle (game heartbeat intervals are far below this); max concurrent sessions per node defaults to 4096, over-limit packets are rejected and counted (see §5 metrics).

### 1.3 Coexistence with the TCP plane

- `FlowSession`/`ChainContext` instances can be shared (when one client has both TCP and UDP traffic, statistics merge);
- The session table is independent of any TCP connection state machine; the `FlowOutput` TCP path is unaware of it;
- The routing engine has no transport dispatch logic; a UDP first packet produces a `RouteDecision` as usual (including upgrading a `mesh.` target to a `Chain`).

### 1.4 Acceptance criteria (aligned to todo P0-1)

- Session create/query/timeout reclaim have unit tests: after idle exceeds `session_timeout` the table entry disappears; active sessions are not reclaimed;
- Consecutive packets with the same sticky key reuse the same `RouteDecision` and mapping without rebuilding (assert the mapping count in the table stays unchanged);
- Over-limit rejection has a counted metric (`rillane_udp_dropped_total{reason="session_limit"}`).

### 1.5 Risks and open items

- **R1 LRU capacity and churn**: the suggested default for the target mapping LRU capacity is 256/session; load tests must confirm no churn in game scenarios (multi-target DNS + game servers);
- **R2 Tension between stickiness and failover**: session stickiness delays failover (the decision cache is unaware a link died). Handling: subscribe to `ChainManager` failure events (existing `handle_chain_failure`) and proactively invalidate the decision cache of affected sessions -- recorded in the implementation checklist; the link event interface already exists;
- **O1 open**: the `client_id` dimension degrades to pure source address for unauthenticated socks5; multiple clients behind one NAT would be merged into a single session -- MVP accepts, documented.

## 2. SOCKS5 UDP ASSOCIATE Inbound (P0-2)

### 2.1 Reuse

| Existing asset | Use |
|---------|------|
| `rillane-protocols::inbound::socks5` overall framework | `negotiate_method`/`perform_auth`/address parsing (ATYP 0x01/0x03/0x04) reused as-is |
| `IngressEndpoint` trait | `SocksInbound::run` adds a parallel UDP listen branch; the trait is unchanged |
| `rillane-core::UdpSessionTable`/`EgressUdpConnector` (§1) | After the relay socket receives a packet it goes session table → routing → egress |
| `Credential` auth | Source of the `client_id` sticky key dimension |

### 2.2 New additions

1. `parse_request` accepts cmd `0x03` (UDP ASSOCIATE): the current implementation does `header[1] != 0x01 → send_error(0x07)`; change to a 0x01/0x03 dual branch (around line 226 of `inbound/socks5.rs`);
2. UDP relay socket: **bind UDP on the same port number as the TCP listener** (TCP/UDP port spaces are independent; client experience matches Clash);
3. ASSOCIATE reply: `BND.ADDR/BND.PORT` filled with the relay socket's **actual bound address** -- the existing `send_success` returning all zeros works for CONNECT (streams have no such semantics), but returning zeros for UDP leaves the client nowhere to send packets;
4. SOCKS5 UDP request header parsing (`RSV(2) FRAG(1) ATYP(1) ADDR PORT`):
   - `FRAG != 0`: MVP rejects it (RFC 1928 permits not supporting it) and reports a drop counter metric (`reason="frag"`) -- game traffic practically never fragments, so assembly complexity is bypassed;
   - First-packet source verification: the relay socket accepts only datagrams whose source IP matches the control connection's (RFC recommendation), config key `strict_udp_source` (default true);
5. Downlink direction: after the relay socket receives upstream data it wraps it in a SOCKS5 header and sends it back to the client (the session table's `mappings` reverse-lookup the client).

### 2.3 Coexistence with the TCP plane

Same port, same process: the TCP listener handles the CONNECT control flow (current, untouched), the UDP socket handles ASSOCIATE datagrams; the `ingress.socks5` config gains `udp_enabled` (default **false**, only enabled once turned on, see §5.2); while disabled, 0x03 gets a 0x07 error (matching current behavior).

### 2.4 Acceptance criteria (aligned to todo P0-2)

- A standard client completes a DNS UDP query round trip via socks5 inbound + direct egress (e.g. `dig @8.8.8.8 example.com` over socks5 udp);
- `rillanectl stats` shows UDP sessions and byte counts (depends on §5 metrics);
- With `udp_enabled=false`, a 0x03 request receives a 0x07 error, and TCP CONNECT behavior has no regression (existing socks5 tests all green).

### 2.5 Risks and open items

- **R3 BND address and multiple NICs**: on a multi-homed host, when the relay socket binds `0.0.0.0`, which BND.ADDR to return to the client (returning 0.0.0.0 is usually treated by the client as the control connection's peer IP, but compatibility varies) -- at implementation follow the Clash/sing-box convention of returning `0.0.0.0:actual-port`, and introduce an `advertise_addr` config only if problems appear;
- **R4 Downlink reordering/loss**: one relay socket sends and receives for many upstreams; bursty downlink may congest and drop -- handling: add `recv` buffering and per-client fair rotation to the relay socket; recorded in the implementation checklist;
- **O2 open**: whether FRAG fragmentation gets supported in a later version (depends on the TUN-phase large-DNS-packet scenario).

## 3. Egress UDP Underlay (P0-3)

### 3.0 General mechanism

`rillane-protocols::outbound` gains the UDP-capable connectors (`DirectUdpConnector` in `rillane_core::udp::relay`, `ShadowsocksUdpConnector` in `outbound/shadowsocks.rs`, `WireguardUdpConnector` in `outbound/wireguard.rs`; hy2 is deferred to V2); at build time (`RuntimeBuilder`/rillaned startup) it scans the egress types reachable from `routing`: when UDP traffic is routed to a **trojan/vless/socks5/http** or other type with no UDP capability, **startup fails immediately and lists the conflicting node names** (aligned to todo acceptance "unsupported egress types error clearly at build time") -- runtime silent dropping is not used. The existing hy2/wg egress already has a `TargetProto` dispatch skeleton (`Tcp => {}` + fallback error); the UDP branch falls straight into the same match.

### 3.1 direct (`outbound/direct.rs`)

- Reuse: existing direct address resolution (`lookup_host`) and the semantics of the IPv4/IPv6 selection logic;
- New: `DirectUdpConnector` -- one `tokio::net::UdpSocket` per target mapping (bind `0.0.0.0:0`, send/recv after `connect(target)`), wrapped by a `UdpRelay` handle;
- Coexistence: fully independent of TCP direct; no shared socket.

### 3.2 shadowsocks (`outbound/shadowsocks.rs`)

- Reuse: the workspace dependency `shadowsocks 1.21` **ships its own UDP relay capability** (`shadowsocks::relay::udp` plus `ServerConfig`) -- no hand-written AEAD packet format; and the existing ss egress method/password config structure (`EgressConfig::Shadowsocks`);
- New: per-packet independent wrapping (crate semantics: `[salt][encrypt(target address + data)]`, no connection concept, naturally fits NAT-style mapping); UDP over SS does no flow control; packet length ≤ 65507 is trimmed at inbound;
- Coexistence: the TCP ss connection pool/tunnel and the UDP association are unaware of each other.

### 3.3 hysteria2 (`outbound/hysteria2.rs`)

- Reuse: the existing `Hysteria2Connector`'s QUIC connection establishment, auth (`hysteria2` crate 0.1.6), and `TargetProto` match skeleton;
- New: the hy2 protocol UDP relay channel (QUIC datagram semantics; after the client requests connect, datagrams are sent/received by session id) -- **depends on whether the crate exposes a UDP API**;
- Coexistence: shares the same QUIC connection with TCP (as the protocol designs it), the only one of the four egress types where "the TCP plane and the UDP plane share an underlying connection"; connection lifetime management must prevent a TCP-side close from taking down UDP -- recorded in the implementation checklist;
- **Decided V1 (2026-09-30 landing check)**: check conclusion = `hysteria2 0.1.6` public API has only `HysteriaClient::connect` + `tcp_connect` (`quic_connection` is `pub(crate)`), **no UDP egress** -- **branch (c) adopted**: P0-3 acceptance explicitly rewritten and hy2 UDP moved to P0-4 (not a silent shrinkage); **the revision is upheld when P0-4 completes** (todo P0-4 §0.1-③), and the hy2 UDP final state = **V2 (quinn vehicle)**, with a separate ticket when the V2 choice is made. Original three-branch alternatives: a) upgrade the crate; b) implement the hy2 UDP channel on quinn ourselves; c) defer, downgrading to direct/ss/wg.

### 3.4 wireguard (`outbound/wireguard.rs`)

- Reuse: the existing `WireguardConnector`'s keys/`allowed_ips`/interface config (`defguard_wireguard_rs 0.11`), plus the existing "target IP must fall inside allowed_ips" verification semantics;
- New: UDP underlay = build an IP packet, write it into the WG interface, then receive back -- add a **lightweight IPv4/IPv6 + UDP header builder** (source address = WG interface address; the `address` config field already exists); the parse/receive direction likewise strips the header and reconstructs the `FlowTarget`;
- Coexistence: shares the same WG interface and session with TCP over WG (WG is itself L3, naturally the same track);
- Risk **R5**: the existing WG implementation depends on the system WG interface (kernel-mode/privileged operations); the UDP version does not change that premise -- integration tests need a privileged environment, which overlaps with the P1 TUN test environment need; build them together.

### 3.5 Explicitly out of S1 scope

- socks5 egress UDP (already claimed in PROTOCOLS.md, **status: aspirational**): the protocol supports it but S1 does not; build-time error as "no UDP capability";
- trojan UDP ASSOCIATE extension, vless/QUIC underlay: later versions; PROTOCOLS.md's corresponding subsections get status labels in sync.

### 3.6 Acceptance criteria (aligned to todo P0-3)

- A QUIC site (HTTP/3, e.g. `curl --http3`) is reachable via the **wg** egress (**verifiable framing**: QUIC is ordinary UDP with no special-casing; the P0-3 wg vehicle is reachable); the **hy2** half **keeps the revision to V2** (P0-4 §0.1-③; separate ticket with the quinn vehicle);
- A DNS UDP query round-trips successfully via the ss egress (verifying AEAD per-packet semantics);
- Point a UDP traffic rule at a trojan/vless node: rillaned **fails at startup** and names the conflicting node;
- direct egress UDP has independent send/recv counters (§5).

### 3.7 Risks and open items

- **R6 = V1 (decided)** (hy2 crate capability, see §3.3) -- once S1's largest external dependency risk; the check conclusion has settled (branch (c), moved to P0-4 with the revision upheld, final state V2);
- **R7 ss UDP anti-abuse**: SS UDP has no auth handshake semantics (each packet carries the address), so an open relay becomes an open resolver risk -- handling: by default only allow targets hit by routing rules + whitelist session table targets (mappings are only created after the first-packet routing decision);
- **R8 WG MTU**: an inner UDP packet exceeding the WG interface MTU (config default 1420) will silently fragment/drop -- document the MTU budget and fill in measured numbers.

## 4. mesh Multi-hop UDP Envelope (P0-4)

> **Landing note (2026-09-30)**: this chapter **landed complete** with P0-4 (S0–S6) -- for the implementation and deviations see [udp-mesh-dataplane.md](udp-mesh-dataplane.md) (§2 wire format / §3 hop cache / §4 plane state machine / §5 client egress / §6 plaintext gate / §13–§17 implementation completion), 27 tests all green; the text below keeps the design-time original, and the as-landed state is authoritative per that implementation-level design draft and todo P0-4 landing behavior.

### 4.1 Reuse

| Existing asset | Use |
|---------|------|
| `MeshEnvelope`'s path-stripping semantics (`path[0]` strips itself → forwards `path[1]`) | UDP hop behavior is fully isomorphic |
| `MeshRegistry` (node addressing/roles/quotas/ACL) | Next-hop resolution and admission checks reused as-is |
| `MeshTlsConfig` certificate material (`rillanectl mtls` output) | The §4.4 encryption scheme reuses the same CA/node certificates |
| `ChainManager` link building/health check/`handle_chain_failure` | UDP link failover reuses it (§1.5 R2) |

### 4.2 New: UdpEnvelope (binary header)

The TCP plane envelope is JSON + a 4-byte length prefix (64KB ceiling, see mesh.md) -- **the UDP plane cannot copy that**: a single packet must fit in the MTU (budget ≤ 1200B including payload), and JSON header size plus parse overhead is unacceptable. So the UDP plane uses a compact binary header from day one:

```
magic(2)="SU" | ver(1) | flags(1) | flow_id(16, UUID bytes)
| atyp(1)+addr(4/16)+port(2)            # final target
| path_mode(1)                           # 0=FULL first packet carries full path; 1=CACHED later packets
| hop_index(1)
| [FULL: node count(1) + node_id list(len+bytes)]
| payload(...)
```

- **First packet FULL**: carries the full path (aligned with TCP `MeshEnvelope`'s path semantics); each hop caches `(flow_id → {next_hop, hop_index, expiry})` on receipt and strips itself;
- **Later packets CACHED**: only `flow_id + hop_index`; each hop looks up the cache and forwards -- game traffic is dozens of packets per second, and the path is transmitted only once;
- Hop cache expiry = session expiry (same as the §1 timeout); `flow_id` collision probability is negligible (UUIDv4);
- **Relation to P2-6**: P2-6 (TCP plane envelope binarization) adopts this format directly as unified protocol v2; by the time the TCP plane migrates, the UDP plane already uses this format -- this section is P2-6's format definition draft.

### 4.3 Forwarding behavior (`rillane-runtime::mesh_transport` extension)

- `MeshDataPlane` holds in parallel a TCP listener (current) and a UDP socket (**same port number**, TCP/UDP dual stack on one port, `MeshConfig.listen_address` reused);
- The `MeshStream` trait is `AsyncRead+AsyncWrite` (TCP-specific); the UDP plane writes directly with `tokio::net::UdpSocket + §4.2 codecs`, without forcing a unified stream-interface abstraction;
- relay node: decode envelope → ACL/quota check (reuse `MeshRegistry::check_quota`/`acl`) → look up cache / strip path → send to next hop; exit node: the UDP version of the existing `connect_target` function semantics (new `udp_connect_target`);
- Each flow has a hop-to-hop session expiry (reusing the §1 timeout constants); when a relay's flow cache expires it is cleared.

### 4.4 Encryption (aligned with the TCP plane's mTLS semantics)

The TCP plane already implements "when a chain is enabled mTLS is enforced by default; `RILLANE_MESH_ALLOW_PLAINTEXT=1` is dev-only" (mesh.md). The UDP plane is designed at an equivalent security level, three candidates:

| Scheme | Description | Assessment |
|------|------|------|
| A (recommended) | QUIC datagrams (`quinn` crate) + reuse the existing rustls mTLS material | Encryption/anti-replay/no head-of-line blocking out of the box, at the cost of a new workspace dependency |
| B | DTLS | No mature maintained stack in the Rust ecosystem, excluded |
| C | Per-packet AEAD + self-managed replay window, keys derived from the mTLS certificate material | Zero new dependencies but carries crypto-engineering risk yourself |

**MVP fallback**: until the implementation round decides, the UDP plane is usable in plaintext only and must be explicitly enabled by `RILLANE_MESH_UDP_ALLOW_PLAINTEXT=1` (semantics mirror the TCP plane); a `chain+udp` combination refuses to start when encryption is not configured. The final choice is **open item V2**, leaning toward A.

### 4.5 Coexistence with the TCP plane

- Same port dual stack, same registry, same link health check; zero changes to the TCP plane code path;
- `RouteDecision::Chain` for UDP traffic is likewise produced by the `ChainManager` upgrade (at first-packet routing); link metadata (`rillane.chain.path` annotation semantics) is recorded for UDP sessions as well.

### 4.6 Acceptance criteria (aligned to todo P0-4)

- Two-hop link (client → relay → exit) UDP bidirectional forwarding: the client completes a DNS query round trip through the link;
- Peer unreachable / session idle timeout: the relay hop cache and session table entries are reclaimed on timeout (assert memory returns + reclaim counters);
- First-packet FULL / later CACHED verified by packet capture: from the 2nd packet on no path field is carried;
- With `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` unset and no encryption configured, `chain+udp` refuses to start (the error names the switch).

### 4.7 Risks and open items

- **R9 = V2** (UDP plane encryption choice, see §4.4);
- **R10 Memory ceiling of the relay hop cache**: each flow's cache is small but the volume is large, so a global flow-cache ceiling is needed (default 65536 entries, LRU eviction + counting);
- **O3 open**: NAT semantics across relays (whether a relay needs a back-to-source check against the previous hop) -- MVP relies on envelope flow_id integrity + encryption-layer authentication; an independent back-to-source check is deferred.

## 5. Observability and Config Switches (P0-5)

### 5.1 Reuse

| Existing asset | Use |
|---------|------|
| `RillaneConfig` top-level structure (`rillane-config`) | Adds a `udp:` block, a peer of `control/telemetry/ingress/egress/routing` |
| `IngressConfig::Socks5` (tagged enum) | The variant gains a `udp_enabled` field; serde backward-compatible (default false) |
| rillaned control plane `/metrics` hand-written Prometheus rendering (`apps/rillaned/src/control_plane.rs`) | Appends the `rillane_udp_*` series through the same rendering path as `rillane_mesh_link_bytes_total` |
| `docs/grafana/rillane-dashboard.json` | Appends UDP panel rows |

### 5.2 New config (illustrative, finalized with the implementation)

```yaml
udp:
  enabled: false                 # global master switch
  session_timeout_secs: 180      # §1.2
  mapping_idle_secs: 60
  max_sessions: 4096
  strict_udp_source: true        # §2.2
ingress:
  - type: socks5
    udp_enabled: true            # overrides the global switch (inherits by default)
```

No switch on egress: UDP capability is statically determined by type (direct/ss/hy2/wg have it, the rest do not), avoiding "config says yes, runtime says no" drift.

### 5.3 New metrics

```
rillane_udp_sessions_active            # current session table size
rillane_udp_sessions_total             # cumulative created
rillane_udp_relay_bytes_total{direction=up|down}
rillane_udp_dropped_total{reason=…}    # frag/source/malformed get their own separate series
rillane_udp_relay_handshake_errors_total   # mesh UDP plane (reserved)
```

> The as-landed metric names are authoritative per [udp-observability.md](udp-observability.md) §2.4 (landed final) and the `apps/rillaned/src/control_plane.rs` rendering.

The `/flows` control plane interface keeps the TCP direction counters; **the UDP plane is NOT folded into `/flows`** (UDP never enters `FlowOutputRouter`, so there is no proto dimension -- UDP is observed through `/udp/stats` and the `rillane_udp_*` metric family, see [udp-observability.md](udp-observability.md) §2.6; the `rillanectl stats` tail carries the UDP section).

### 5.4 Coexistence with the TCP plane

Same `/metrics` endpoint, same `/flows` snapshot, same Grafana dashboard file with appended rows; TCP series naming and semantics untouched.

### 5.5 Acceptance criteria (aligned to todo P0-5)

- The `config/rillane.yaml` example contains the §5.2 block and `cargo` validation passes (schema round trip: an old config file without `udp:` still parses);
- The Grafana panel shows UDP session/byte/drop series (dashboard json updated);
- With `udp.enabled=false`, no UDP socket is listening anywhere in the chain (verified by port scan).

### 5.6 Risks and open items

- **R11 Metric cardinality**: the `per-target` label dimension has unbounded cardinality, so MVP metrics carry no target label (session-level aggregation); per-link breakdown belongs to P2-1;
- **O4 decided (closed, 2026-09-30)**: `/chains/stats` does **not** split out UDP -- link-dimension UDP traffic already entered the existing `rillane_mesh_link_bytes_total` series via P0-4 `record_link_bytes`; a duplicate split adds no information (ruling see [udp-observability.md](udp-observability.md) §2.6).

## 6. Implementation Order and Dependencies

```
P0-1 session table (trait+table+reclaim) ──► P0-2 socks5 inbound ──► P0-3 egress underlay ──► P0-4 mesh UDP ──► P0-5 observability throughout
        │                                              ▲
        └────────── build-time capability scan (the §3.0 error mechanism depends on P0-3's type list)──────────┘
```

- P0-1/P0-2 can be developed in parallel with P0-3 (trait first, mock relay unit tests);
- P0-5 is not the tail: metric instrumentation lands with each step; the dashboard closes out last;
- V1 (hy2 crate capability check) is P0-3's first ticket, and its conclusion decides whether P0-3 acceptance runs under the original framing -- **executed**: conclusion = no UDP egress, branch (c) adopted, P0-3 acceptance explicitly rewritten (§3.3), hy2 UDP moved to P0-4 with the revision upheld (final state V2).

## 7. Risk and Open Item Summary

| No. | Type | Content | Owner |
|------|------|------|------|
| R1 | Risk | Session/mapping LRU capacity needs load-test confirmation | §1 |
| R2 | Risk | Sticky cache delays failover → hook `handle_chain_failure` to invalidate the cache | §1 |
| R3 | Risk | Multi-NIC BND.ADDR compatibility; add `advertise_addr` if needed | §2 |
| R4 | Risk | Relay downlink fairness and buffering | §2 |
| R5 | Risk | WG depends on a privileged interface; test environment built together with P1 TUN | §3.4 |
| R6/V1 | Decided (2026-09) | `hysteria2` crate has **no** UDP egress → branch (c) adopted, moved to P0-4 with the revision upheld, final state V2 (§3.3) | §3.3 |
| R7 | Risk | ss UDP open resolver risk → target whitelisting | §3.2 |
| R8 | Risk | WG MTU budget annotation | §3.4 |
| R9/V2 | Open (MVP plaintext gate landed) | mesh UDP encryption choice (leaning quinn/QUIC + reusing mTLS material) -- P0-4 landed the §4.4 MVP fallback (`RILLANE_MESH_UDP_ALLOW_PLAINTEXT` union `MeshConfig.udp_allow_plaintext_data_plane`, build-time refusal when no encryption configured); the choice itself remains V2 | §4.4 |
| R10 | Risk | relay flow cache global ceiling (default 65536 LRU) | §4.3 |
| R11 | Risk | Metric cardinality control (MVP has no target label) | §5 |
| O1 | Open | Sticky key degrades under unauthenticated socks5 | §1 |
| O2 | Open | When to support SOCKS5 FRAG fragmentation | §2 |
| O3 | Open | relay hop-to-hop back-to-source check | §4 |
| O4 | Decided (closed) | `/chains/stats` does not split out UDP (ruling see [udp-observability.md](udp-observability.md) §2.6) | §5 |
