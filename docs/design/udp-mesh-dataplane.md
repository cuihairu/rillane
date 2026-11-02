# P0-4 mesh data-plane UDP forwarding — implementation-level design

> Upstream design: [udp-dataplane.md](udp-dataplane.md) §4 (P0-4 concept draft: envelope format / forwarding behavior / encryption three-way choice / acceptance).
> This document is the implementation-level ruling: **exact format, type signatures, state machine, wiring points, test plan**. Deviations after landing are backfilled into §11 and the upstream §6 note.
> Decision index D-1..D-16, the interface seam list, mutual boundary references with P1-4/P1-5/P2-5, and explicit acceptance/metric framing (**fourth-round completion, 2026-09-30**) are in §0.1, §0.2, and §15–§17.
> Reuse baseline: P0-1 session table (`seep-core::udp`) · P0-3 egress underlay (`EgressUdpConnector` + RoutingUdpConnector) · TCP-plane data plane (`seep-runtime::mesh_transport`).
> **Status (2026-09-30): landed** -- P0-4 S0–S6 all complete (todo.md P0-4 checked off; §10 eight acceptance tests + 27 new tests all green); as-landed deviations are authoritative per code notes and todo P0-4 landing behavior, and this document keeps the implementation-level design final text. Observability and config continuation: [udp-observability.md](udp-observability.md) (todo P0-5, **landed**).

## 0. Scope

- UDP bidirectional forwarding on a two-hop link (client → relay → exit), first packet FULL / later CACHED;
- UDP-plane routing switches from the base `RoutingEngine` to `RuntimeFlowRouter` (chain decisions); link failure handling reuses `ChainManager`;
- Encryption follows upstream §4.4 MVP fallback: plaintext only via explicit `SEEP_MESH_UDP_ALLOW_PLAINTEXT=1`; with no encryption configured, chain+udp **refuses to start at build time** (V2 quinn choice is open, out of this item);
- Excludes: QUIC underlay (V2), cross-relay back-to-source verification (O3), TCP-plane envelope binarization (P2-6 uses this document's §2 format).

### 0.1 Acceptance framing (explicit; fourth-round completion 2026-09-30)

todo P0-4's three acceptance items, each given a measurable framing (following the P0-3/P1-4/P1-5 explicit-rewrite practice, no silent shrinkage):

1. **Two-hop link UDP bidirectional forwarding** = §10 T2: client `MeshUdpRelay` → relay plane → exit plane → loopback echo; real sockets, no privileges; dir=Down full-chain reply assertions;
2. **Reclaim on timeout when the peer is unreachable** = both paths have their own assertions: idle expiry (T4, expiry rewritten in place + `unknown_flow`) and exit-side recv Err (target unreachable/reset → `retire_flow` single point, §13-1 trigger point ②) -- "unreachable" is not collapsed into a single timeout framing;
3. **"QUIC sites reachable via hy2 egress" keeps the revision**: the hysteria2 crate 0.1.6 public API has no UDP egress (P0-3 V1 check); hy2 UDP is decided with the V2 quinn vehicle (§12) and is out of this item's MVP; **verifiable framing = QUIC sites are ordinary UDP** (`TargetProto::Quic` is not special-cased, §1) **reachable through the mesh UDP plane (two hops) to a P0-3 already-implemented vehicle (direct/ss/wg)**;
4. The semantics of **plaintext gate first** = with no encryption configured, chain+udp refuses to start at build time (T6); plaintext only via explicit `SEEP_MESH_UDP_ALLOW_PLAINTEXT=1` / config merge (§13-6).

### 0.2 Metric framing notes

- **Observational consequence of no deduplication (D-14)**: the mesh UDP plane may deliver the same datagram more than once (FULL periodic resend, best-effort semantics) -- acceptance and monitoring **must not use "zero duplicates" as a criterion**; duplication is expected behavior under the §14-2 ruling;
- `forwarded_up` includes all datagrams emitted locally, FULL/CACHED (§13-2); the FULL periodic resend (§5, 64 packets / 30s as a rough value) counts inside it -- when evaluating effective payload rate, know the denominator includes resend overhead;
- `seep_udp_mesh_*` (P0-5 §2.4, datagram/flow counters) and TCP-plane mesh accounting (`record_link_bytes` connection bytes) are **separate families, never mixed** -- the two planes' traffic on the same `listen_address` port belongs to two series families in monitoring;
- `malformed` covers both decode refusals and TTL circuit breaking (§14-1 reuses the existing field) -- attribution is split by logs into "format error vs. loop break", not split into series;
- `flows_active` is a direct gauge read (§13-2) with transient skew against the true table length at sweep time; monitoring accepts this.

## 1. Overview

```
client (MeshUdpRelay)          relay (MeshDataPlane UDP)        exit (MeshDataPlane UDP)
  │ UdpEnvelope FULL ──────────►│ cache flow→{next,prev}         │ cache flow→{next=None,prev}
  │      (path=[relay,exit])    │ strip self→FULL(path=[exit]) ─►│ udp_connect_target
  │ UdpEnvelope CACHED ────────►│ look up cache→CACHED ─────────►│ → target
  │      (no path field)        │                                │
  │ ◄────────── CACHED(dir=down)│ ◄──── CACHED(dir=down) ────────│ target reply→wrap dir=down→prev
  ▼ one shared UDP plane socket per node (forwarding + replies from the same source address); exit's target socket is per-flow
```

- **Socket topology**: one shared socket per node's UDP plane (same port as the TCP `listen_address`, dual stack on one port); the relay's forwarding and replies both leave through it → the source address is stable toward adjacent hops (NAT-friendly, downlink can flow back); the exit has one connected socket per flow toward the real target.
- **No TCP-ification**: does not go through the `MeshStream` abstraction (ruled in upstream §4.3); codecs write directly.
- **Selection boundary with the TCP plane** (split by transport protocol at ingress, no crossing, all based on existing dispatch points):
  - TCP connections (socks5 CONNECT etc.) → `Flow` → `FlowOutputRouter` → TCP-plane `MeshEnvelope` (JSON header + 4-byte length prefix, existing at `mesh_transport.rs:165-172`/`write_envelope`) -- zero changes in this item;
  - UDP datagrams → P0-1 session table → `UdpChainRouter` (§5) → UDP-plane binary envelope (§2);
  - QUIC sites = ordinary UDP (`TargetProto::Quic` not special-cased) through the UDP plane; the hy2 egress underlay (moved in by P0-3 §3.4(c)) is an **exit vehicle** question and does not go through the mesh UDP plane;
  - The two planes share only the `listen_address` port number and registry/accounting (`record_link_bytes`); envelope format, sockets, and lifecycle are fully independent -- the TCP-plane flow is per-connection (`MeshStream` bidirectional copy, one envelope header per connection); the UDP-plane flow is per-datagram and connectionless (every packet carries an envelope header);
  - Encryption-level difference (existing fact): the TCP-plane chain enforces mTLS by default (`SEEP_MESH_ALLOW_PLAINTEXT` is dev-only); the UDP-plane MVP goes through the §6 plaintext gate -- to be aligned when the V2 QUIC vehicle lands.

## 2. UdpEnvelope binary format (§4.2 made precise)

```
offset  field
0       magic(2) = 'S''U'
2       ver(1)   = 1   (v1; the in-band V2 frame uses `ver = 2`, see the P2-7 note in mesh-advanced-security.md §3.2)
3       flags(1) : bit0 = dir (0=uplink, 1=downlink); bit1 = has_seq (V2, P2-7); bit2..7 reserved, must be 0
4       flow_id(16)  raw UUID bytes (uuid::Uuid::as_bytes, not a string)
20      atyp(1)  : 1=IPv4, 4=IPv6, 3=domain
21      addr     : 4 / 16 / len(1)+bytes (domain ≤255)
…       port(2, BE)
…       path_mode(1) : 0=FULL, 1=CACHED
…       hop_index(1)
[FULL] hop_count(1) + node_id × hop_count (each item len(1)+bytes)
…       payload(...) (uplink = business datagram; downlink = target reply)
```

```rust
pub enum UdpDir { Up, Down }
pub enum UdpPathMode { Full, Cached }
pub struct UdpEnvelope {
    pub version: u8,                    // 1 (v1) or 2 (in-band V2, P2-7: HAS_SEQ + seq + replay window); other values are decode refusals
    pub dir: UdpDir,
    pub flow_id: [u8; 16],
    pub target_host: String,            // domain/v4/v6 stringified (used by exit)
    pub target_port: u16,
    pub path_mode: UdpPathMode,
    pub hop_index: u8,
    pub path: Vec<NodeId>,              // non-empty for Full; always empty for Cached (enforced at decode)
    pub payload: Vec<u8>,
}
pub fn encode_udp_envelope(env: &UdpEnvelope) -> Result<Vec<u8>>
pub fn decode_udp_envelope(buf: &[u8]) -> Result<UdpEnvelope>
```

- Validation: magic/ver/reserved bits/domain length/CACHED carrying a path (refuse); truncation is always an error (counted as `malformed`).
- Same style as the P0-2 SOCKS5 header codecs: pure functions, pinned by unit tests (precedent `seep-core/src/udp/associate.rs`).
- **Landing point**: `seep-runtime/src/mesh_transport.rs` (same file as the TCP `MeshEnvelope`; seep-mesh does not depend on tokio runtime details, and keeping the forwarding behavior in the same file makes joint testing easy).

## 3. Hop cache (UdpFlowCache)

```rust
struct FlowCacheEntry {
    next_hop: Option<(NodeId, SocketAddr)>, // None = the local node is the exit
    prev: SocketAddr,                       // uplink source (downlink reply address) -- §11-2 supplement
    expiry: Instant,                        // last_touch + mapping_idle
}
struct UdpFlowCache {
    map: DashMap<[u8; 16], FlowCacheEntry>,
    ttl: Duration, max: usize,              // defaults mapping_idle(60s) / 65536 (R10)
}
```

- FULL first packet: insert the `entry` (same flow_id already present → refresh prev/next and expiry, treated as re-association); CACHED: `get_mut` touches the expiry; a miss counts `unknown_flow` and is dropped.
- Ceiling (R10): on insert when full → first sweep out expired entries; if still full → evict the one with the **earliest expiry** (under equal TTL that is the longest untouched = LRU), eviction counter +1. An O(n) scan is acceptable (entries are small; volume is large but bounded at 65536).
- Reclaim: the serve loop lazily sweeps every second (removes expired; not a standalone task, decoupled from the TCP plane).

## 4. relay / exit forwarding behavior (`MeshDataPlane` extension)

```rust
impl MeshDataPlane {
    /// Single-datagram handling (called by serve_udp; tests call it directly)
    pub async fn handle_udp_datagram(&self, sock: &Arc<UdpSocket>, from: SocketAddr, buf: &[u8])
        -> Result<()>;
    /// Same-port dual-stack UDP serve (shares listen_address with the TCP spawn)
    pub fn spawn_udp(self: &Arc<Self>, bind: SocketAddr) -> JoinHandle<Result<()>>;
}
```

State machine (uplink dir=Up):

1. decode → magic/ver/reserved-bit validation fails: count `malformed` and drop;
2. `env.path` empty → error; `path[0] != local_node_id` → error (same semantics as the TCP plane);
3. **FULL**: verify the local role ∈ {Relay, Hybrid, Exit}; insert/refresh the cache;
   - `path.len() == 1` (the local node is the exit): the role must be ∈ {Exit, Hybrid}; switch to the exit branch;
   - otherwise `next = path[1]`, resolve the address via the registry (the role cannot be Client), **strip self**, then re-encode the whole packet as `FULL(path=path[1..])` and send to next -- no downgrade to CACHED (each hop maintains its own FULL/CACHED state, isomorphic with the TCP plane rewriting path at every hop);
4. **CACHED**: look up the cache; hit with `next_hop=None` → exit branch; hit with next present → forward as-is (dir/payload) to next; miss → `unknown_flow` drop.

Exit branch (uplink arrives at the exit):

```rust
// per-flow independent connected socket (reuses the P0-3 LocalRelay semantics)
flows: DashMap<[u8;16], Arc<UdpSocket>>  // empty ≙ cache entry.next_hop == None
send(payload) → target; downlink task: socket.recv → UdpEnvelope{dir:Down, path_mode:Cached,
  flow_id, hop_index:0, payload} → send_to(cache.prev)
```

- The downlink task is isomorphic with the P0-1 forwarder: recv Err (target unreachable/reset) → clear the flow socket + the cache entry + counters;
- The exit-side flow socket idle timeout = the cache entry expiry, reclaimed uniformly by the §3 lazy sweep (dropping the socket closes it) -- **§13-1 correction**: the downlink task holds an `Arc<UdpSocket>` which prevents the drop, so reclaim goes through the `retire_flow` single point.

Downlink dir=Down (relay receives): look up the cache → `send_to(cache.prev)` (do not rewrite the path field -- CACHED has no path field; **hop_index still increments +1 and is re-encoded at every hop**, see §14-1); miss → `unknown_flow` drop.

## 5. Client egress: UdpChainRouter + MeshUdpRelay

```rust
// seep-runtime (private): a chain-aware wrapper around the P0-3 RoutingUdpConnector
struct UdpChainRouter {
    inner: RoutingUdpConnector,          // non-chain decisions: dispatch by final_node (P0-3)
    mesh: Option<MeshUdpBridge>,         // chain decisions; None + chain decision → already blocked at build time
}
#[async_trait]
impl EgressUdpConnector for UdpChainRouter {
    async fn associate(&self, ctx, decision) -> Result<Arc<dyn UdpRelay>> {
        match &decision.path {
            RoutePath::Chain { hops } if hops.len() >= 2 => self.mesh.as_ref()
                .ok_or_else(|| anyhow!("chain UDP not enabled"))?.associate(ctx, hops).await,
            _ => self.inner.associate(ctx, decision).await,
        }
    }
}

struct MeshUdpBridge { local_node_id: NodeId, registry: Arc<MeshRegistry>, cfg: MeshUdpGate }
// associate: next=hops[1] → registry.get_node_addr → local UdpSocket bind ":0"
//            Arc<MeshUdpRelay>{ sock, next_addr, path: hops[1..].to_vec(), flow_id, target }
struct MeshUdpRelay { /* impl UdpRelay */
    // send_to: first packet FULL(path=path, hop_index=0), then CACHED (AtomicBool marks FULL sent;
    //          recovery from a lost FULL: the client cannot detect consecutive unknown_flow -- the MVP relies on re-association:
    //          resend FULL every N=64 packets or every 30s to refresh the cache, at the cost of one header)
    // recv_from: decode CACHED(dir=Down) → (target, payload); dir=Up or FULL → drop and count
}
```

- `MeshUdpRelay` implements the P0-1 `UdpRelay` trait directly → the session table / §3.6 staged teardown / forwarder are reused with zero changes;
- Role: the client has no data-plane listener, only an egress relay (§1 topology, left column).

## 6. Encryption gate (the MVP fallback for the §4.4 open V2)

```rust
pub struct MeshUdpGate { pub allow_plaintext: bool }  // env is read only at from_env; tests pass it explicitly
impl MeshUdpGate { fn ensure_usable(&self, tls: Option<&MeshTlsConfig>) -> Result<()> }
// tls is None and !allow_plaintext → Err("mesh UDP plane has no encryption configured and plaintext is not explicitly allowed
//   (SEEP_MESH_UDP_ALLOW_PLAINTEXT=1); the chain+udp combination refuses to start (udp-dataplane.md §4.4/V2)")
```

- **The landing point is at build time** (`RuntimeBuilder::build`): checked once before non-client roles bring up the UDP plane, and once before the client-side UdpChainRouter::mesh construction;
- The serve/associate layers do not re-check (after the build-time block, the path is necessarily valid);
- Same level as the TCP plane's "chain enforces mTLS by default"; `env_flag` reuses the existing mesh_transport helper;
- The gate's config merge point (`MeshConfig.udp_allow_plaintext_data_plane` ∪ env, P0-5 §1.5) is finalized in §13-6.

## 7. Accounting and quota

- Hop-to-hop bytes: call `record_link_bytes(prev_or_local, next_or_local, bytes)` for every forwarded/received packet (aligned with TCP-plane dial/forward semantics; UDP has no connections, so `record_link_connection` is recorded once per FULL first packet only);
- Quota: the exit's first out-direction bytes on a flow go through `registry.check_quota(exit_node, bytes)`; Err → drop + count (do not break the chain);
- Link errors: connect next fails / exit connect_target fails → the `record_link_error` pair (same points as the TCP plane).

## 8. Link failure wiring (landing the framing reserved by P0-1)

- The UDP table's router is replaced with `RuntimeFlowRouter` (where chain decisions are produced); the sticky decision cache / ledger chain binding (built in P0-1) keeps working as-is;
- **chain_id framing bridge**: `ChainManager.chain_id` is a random UUID string, while P0-1's `chain_id_of(decision)` is `chain:{hops.join("->")}` -- the two are not converted into each other. `ChainFailureEvent` is constructed by the runtime after `handle_chain_failure` succeeds: **the chain_id field is filled with `chain_id_of(the new decision after the switch)`**, and failed_nodes with the old chain's failed nodes. The ledger binding gate (revokes only on chain_id equality) hits under the new-decision framing;
- This UDP plane's flows after a switch: the decision has changed → the next packet's ensure_decision reroutes (P0-1 semantics), and the in-flight hop cache expires naturally.

## 9. RuntimeBuilder / seepd wiring

### 9.1 build() phase-order adjustment: move the UDP block down (this section is a precondition for implementation)

**Current state (the `RuntimeBuilder::build()` phase order after P0-3 landed)**:

| Phase | Content | Product |
|-----|------|------|
| ① | `validate()` + config snapshot + `RoutingEngine` construction | `router` |
| ② | **UDP block**: `build_udp_connectors` → `scan_udp_capability` → `RoutingUdpConnector` → `UdpSessionTable` (FlowRouter = ①'s base engine) → `UdpAssociateService` | `udp_service` |
| ③ | ingress/egress default implementations (`build_ingress_endpoints` is the **sole consumer of udp_service**; default egress construction is independent of it) | ingress_endpoints / flow_outputs |
| ④ | network_manager | – |
| ⑤ | mesh config completion: mTLS env enforcement, secure-by-default plaintext check, `register_local_mesh_node` | `local_node_id` / `mesh_registry` |
| ⑥ | `ChainManager` initialization (depends on ⑤'s registry) | `chain_manager` |
| ⑦ | `Ok(Runtime)` | – |

**Conflict**: §5/§8 require the UDP table's FlowRouter to be replaced with `RuntimeFlowRouter::new(engine, mesh_registry, chain_manager, local_node_id)`, whose three mesh parameters are products of ⑤/⑥ -- yet the UDP block is already constructed at ②; the order is inverted.

**Scheme (ruling): move the UDP block wholesale below ⑥**, new order ①③④⑤⑥②′⑦; leave a one-line comment at the original ② position pointing to the new location. One accompanying adjustment: the `build_ingress_endpoints` call (the sole udp_service consumer) is likewise pushed back to after ②′.

**Rationale**:
- `UdpSessionTable::new`'s FlowRouter parameter is fixed at construction, and both the sticky decision cache and the ledger chain binding point at that instance -- "construct early, swap late" is not viable (swapping the instance loses runtime state);
- The alternative "move the chain/mesh blocks ahead of ②" is rejected: ⑤'s mTLS enforcement and secure-by-default checks belong to the mesh config completion phase; moving them earlier changes the error-reporting order of validate→build (e.g. a missing-mTLS error would appear before the UDP capability scan error), and the blast radius is larger than moving the UDP block itself;
- UDP is an optional plane (with udp.enabled=false, ②′ is simply skipped), so the move does not affect the default build path;
- The `Runtime` struct's fields and construction point are unchanged (udp_service is ready before ⑦).

**Impact surface**:
- Internal block ordering inside `runtime_builder.rs::build()` adjusted; no function signature changes, no `Runtime` field changes;
- The `build_ingress_endpoints` call site is pushed back (signature/parameters unchanged);
- The `scan_udp_capability` error timing is pushed back with ②′ to after the mTLS/chain checks -- the error message is unchanged;
- Capability-scan and similar unit tests call helper functions directly, not through the `build()` ordering; zero impact.

**Acceptance framing**:
1. `udp.enabled=true + enable_chain=true` (mesh config complete): `build()` succeeds, and the UDP table holds `RuntimeFlowRouter` -- chain decisions are reachable on the UDP plane (§10 #7 dispatch test pins it; ordering correctness is guaranteed at compile time by Arc ownership flow);
2. `udp.enabled=true + enable_chain=false`: behavior equivalent to P0-3 (base engine routing; non-chain dispatch goes through `RoutingUdpConnector`);
3. `udp.enabled=false`: the build path has zero difference from before this item;
4. The whole-repo test baseline (118 items at the P0-3 point) all green.

#### 9.1.1 P0-4 step-by-step implementation checklist (S0–S6, executable)

**Dependency order**:

```
S0 ordering adjustment (pure refactor)─┐
S1 UdpEnvelope codec ─┼─► S3 MeshDataPlane UDP plane ─┐
S2 UdpFlowCache hop cache ─┘   S4 UdpChainRouter/MeshUdpRelay ─┴─► S5 wiring ─► S6 test closeout
(S1/S2 are independent of each other; S3 depends on S1+S2; S4 depends only on S1's decode and the P0-3 trait;
 S5 depends on S0+S3+S4; S6 depends on all. Each step is independently committable.)
```

**Commit cadence** (following the P0-1..P0-3 hard rule): each step = `cargo build` + `cargo test` all green → a single commit (message cites this document's §section) → `git fetch origin main` + `git rebase origin/main` → push → next step; no tag / release / force push. After all steps, check off todo.md per §10.

**S0 build() ordering adjustment** (landing the ruling above in this section, pure refactor)

- Landing point: `runtime_builder.rs::build()` -- the UDP block (`build_udp_connectors` → `scan_udp_capability` → `RoutingUdpConnector` → `UdpSessionTable` → `UdpAssociateService`) moved wholesale after `ChainManager` initialization; the `build_ingress_endpoints` call pushed back; a one-line comment left at the original position pointing to the new location.
- Dependencies: none.
- Acceptance: `cargo build --workspace` green; `cargo test --workspace` at the P0-3 baseline (118 items); the diff shows no UDP semantic change (in this step the UDP table's FlowRouter is still the base engine -- swapping in RuntimeFlowRouter is S5).

**S1 UdpEnvelope codec** (§2)

- Landing point: `mesh_transport.rs`: `UdpDir` / `UdpPathMode` / `UdpEnvelope` + the pure functions `encode_udp_envelope` / `decode_udp_envelope`.
- Dependencies: none.
- Implementation points: field order and byte layout strictly per §2; `version` not in {1,2} / nonzero reserved bits / domain length >255 / CACHED carrying path / truncation → all decode errors (v2 = the P2-7 in-band V2 frame, see [mesh-advanced-security.md](mesh-advanced-security.md) §3.2).
- Acceptance: §10 T1 all green (roundtrip × FULL/CACHED × v4/v6/domain × both dir bits; each of the 5 rejection classes asserted).

**S2 UdpFlowCache hop cache** (§3)

- Landing point: `mesh_transport.rs`: `FlowCacheEntry` / `UdpFlowCache` (DashMap + ttl/max + eviction counter + `sweep_expired`).
- Dependencies: none (can run in parallel with S1).
- Implementation points: ceiling eviction = when full, sweep expired first; if still full, evict the earliest expiry (§11-6); the entry's `expiry` field may be rewritten in place by tests (the same-file `#[cfg(test)]` reaches private fields, co-located with the existing TCP two-hop tests); no clock abstraction introduced.
- Acceptance: §10 T4 (expired entry judged a miss + `unknown_flow` counter), T5 (max=2, insert 3 → the earliest expiry evicted + eviction counter), T8 (after `sweep_expired`, `len == 0`) all green.

**S3 MeshDataPlane UDP plane** (§4 + §6)

- Landing point: `mesh_transport.rs`: `MeshUdpGate::ensure_usable`; `MeshDataPlane` gains a `udp: Option<UdpFace>` field and a `with_udp(gate)` constructor; `handle_udp_datagram` / `spawn_udp`; the exit branch's per-flow connected-socket table + downlink task.
- Dependencies: S1 + S2.
- Implementation points: forwarding and replies share the node-level UDP-plane socket (§1 topology); FULL → strip self and re-encode, CACHED → look up the cache and forward (§11-4); the exit downlink reads prev from the cache (after a FULL re-refreshes prev, the downlink follows the new direction); the gate only checks its explicit parameters, and env reading stays at the caller (§11-5).
- Acceptance: §10 T6 (tls=None and `!allow_plaintext` → Err message contains `SEEP_MESH_UDP_ALLOW_PLAINTEXT`), T3 (the relay calls `handle_udp_datagram` directly; the 2nd packet decodes as Cached with empty path), T4's unknown_flow path; a single-hop (client→exit) real-socket round trip pins the exit branch first.

**S4 UdpChainRouter + MeshUdpRelay** (§5)

- Landing point: new private module `udp_chain.rs` in `seep-runtime`: `UdpChainRouter` (`RoutePath::Chain{hops≥2}` → mesh, otherwise → the inner `RoutingUdpConnector`), `MeshUdpBridge::associate` (resolve the hops[1] address + local socket), `MeshUdpRelay` (impls P0-1 `UdpRelay`: FULL first packet → CACHED afterwards + periodic FULL resend; the downlink accepts only CACHED dir=Down with a matching flow_id).
- Dependencies: S1 (decode); the P0-3 trait surface (already in the repo).
- Acceptance: §10 T7 (Chain dispatch hits MeshUdpRelay / Direct falls to the inner connector); `MeshUdpRelay` against a stub UDP peer (fake relay: receives FULL, stores a sample, replies CACHED dir=Down) completes send/recv unit tests.

**S5 build() / seepd wiring** (§9.2 + §8)

- Landing point: `runtime_builder.rs::build()`: when udp.enabled && enable_chain, the UDP table's FlowRouter is swapped for `RuntimeFlowRouter` (at the position S0 freed); the egress connector is swapped for `UdpChainRouter`; non-client roles spawn `spawn_udp` alongside (gate in front); `ChainFailureEvent` is bridged per the §8 framing.
- Dependencies: S0 + S3 + S4.
- Acceptance: §9.1 acceptance framing 1–4 verified item by item (chain+udp builds successfully and chain decisions are reachable over UDP / without chain, equivalent to P0-3 / with udp off, zero difference / whole-repo baseline green).

**S6 test closeout** (the full §10 table)

- Landing point: the `#[cfg(test)]` modules of `mesh_transport.rs` / `udp_chain.rs` (co-located with the existing TCP two-hop tests, private fields reachable).
- Dependencies: all of S1–S5.
- Acceptance: §10 T2 two-hop real-socket round trip (client `MeshUdpRelay` → relay plane → exit plane → loopback echo, dir=Down full-chain reply); all eight §10 items present in the library and green; `cargo build --workspace` + `cargo test --workspace` green → check off todo.md P0-4 (citing §10 and this checklist; the hy2 acceptance item is ruled together per the V2 reality at check-off time).

### 9.2 serve and egress wiring

- `build()`: when udp.enabled and enable_chain, the UDP table's `FlowRouter` is replaced from the base engine with `RuntimeFlowRouter::new(engine, registry, chain_manager, local_id)` (feasible after the 9.1 ordering adjustment);
- Egress connector: `UdpChainRouter::new(RoutingUdpConnector, MeshUdpBridge::new(...))` replaces the bare RoutingUdpConnector (the §3.1 capability scan targets non-chain nodes only -- a chain decision's hops are mesh nodes, and the `mesh.` exemption in the capability table scan is already in place);
- mesh UDP plane serve: alongside the existing `plane.spawn(bind)`, add `Arc::clone(&plane).spawn_udp(bind)` (dual stack, same port); the gate check (§6) precedes both spawns;
- hy2 UDP (the acceptance moved in from P0-3) is still out of this item -- the vehicle is quinn (V2), progressing decoupled from mesh UDP.

## 10. Test plan (acceptance aligned to todo P0-4 / upstream §4.6)

| # | Test | Acceptance it pins |
|---|------|-----------|
| 1 | codec roundtrip: FULL/CACHED × v4/v6/domain × both dir bits; bad magic/ver/reserved bits/truncation/CACHED carrying a path → refuse | §2 format and validation |
| 2 | two-hop real-socket round trip: client MeshUdpRelay → relay plane → exit plane → loopback echo server; assert the client receives the reply (dir=down full chain) | "two-hop link UDP bidirectional forwarding" |
| 3 | FULL/CACHED packet-shape assertion: the relay calls `handle_udp_datagram` directly; the 2nd packet decodes with `path_mode=Cached` and an empty path | "from the 2nd packet on, no path field is carried" |
| 4 | idle expiry: after advancing a cache entry's expiry, CACHED → unknown_flow drop + counter | "reclaim on session idle timeout" |
| 5 | ceiling eviction: max=2, insert 3 → the earliest expiry evicted + eviction counter | R10 |
| 6 | plaintext gate: tls=None and allow_plaintext=false → `ensure_usable` Err with the switch name in the message | "refuse to start when no encryption is configured" |
| 7 | UdpChainRouter dispatch: Chain → MeshUdpRelay (registry address hit) / Direct → inner connector | §5 wiring |
| 8 | memory-return assertion: after the expiry sweep, cache len == 0 (merged into #4) | "assert memory return + reclaim counters" |

## 11. Deviations/supplements vs. the upstream design draft (backfilled into the upstream §6 note after landing)

| # | Upstream | Ruling here | Rationale |
|---|------|---------|------|
| 1 | §4.2 flags not defined bit by bit | bit0=dir (uplink/downlink) | downlink reflux needs a direction marker; CACHED has no path field, so a relay cannot tell the direction from the packet's shape |
| 2 | §4.2 cache entry `{next_hop, hop_index, expiry}` | add `prev: SocketAddr` | the reflux address for bidirectional forwarding; UDP has no connections, and without prev there is nowhere to send back |
| 3 | §4.2 flow_id "UUID bytes" | `[u8;16]` raw bytes as the cache key and wire format | stringifying is ×2.3 the size and parse overhead, exactly what §4.2 wanted to avoid |
| 4 | §4.3 "each hop strips itself on receipt" | each hop re-encodes FULL `path[1..]`; no downgrade to CACHED | isomorphic with the TCP plane's "each hop rewrites path"; the CACHED judgment stays local at each hop |
| 5 | §4.4 MVP fallback "plaintext only usable" | the gate lands at build time; explicit constructor parameters and env reading are separated | tests never touch the process env; the block point is reachable by unit tests |
| 6 | §4.7 R10 "LRU eviction" | under equal TTL, "earliest expiry = longest untouched"; O(n) eviction, no new dependency | the semantics is LRU; avoids pulling in the lru crate |
| 7 | §4.1 reuse "handle_chain_failure" | chain_id framing bridge: the event fills `chain_id_of(the new decision)` | the ChainManager UUID and the P0-1 framing are not isomorphic (P0-1 §9 note #7 previews this) |

## 12. Risks and open items

- **V2**: the QUIC/quinn underlay choice (leaning A); at landing, the UDP-plane socket topology is unchanged and only the transport layer is replaced;
- **O3**: the relay back-to-source check is deferred (to be re-evaluated once encryption-layer authentication exists);
- the FULL periodic resend frequency (§5) is a rough value (64 packets / 30s), to be adjusted by packet capture after landing -- not counted in acceptance;
- **pad_len wire position open (§17-P1-4)**: when padding lands in the UDP envelope, whether `pad_len` uses a §2 reserved bit or a new field, and the version-gate value, are finalized with the P1-4 UDP vehicle landing (fail-open aligned with its §2.4); this draft does not pre-fix the wire format.

## 13. Implementation-detail completion (second-round review, 2026-09)

> The product of a gap review against this document's first-round final draft, filling in the remaining details needed to implement S0–S6; this section corrects §4 and supplements §2/§6/§9.2; where it conflicts with the text above, this section wins. The same round's P0-5-side completion is in udp-observability.md §9.

### 13-1 exit downlink task lifecycle (corrects §4)

The original §4 wording "the lazy sweep reclaims uniformly (dropping the socket closes it)" has a hidden flaw: **the downlink task holds an `Arc<UdpSocket>`, so as long as the task is alive the refcount never reaches zero** -- after an entry is swept and removed, the socket is still open and the task still receives. Correction:

- the exit flow-table entry becomes an aggregate entry: `flows: DashMap<[u8;16], ExitFlow>`, `ExitFlow { sock: Arc<UdpSocket>, task: JoinHandle<()> }`;
- a single reclaim point `retire_flow(flow_id)` (following the P0-1 teardown single-point convergence precedent): `task.abort()` → `flows.remove(flow_id)` → `cache.remove(flow_id)` -- the three-step order is fixed (stop the task first, then tear down the two tables, preventing the downlink task from sending to an already-removed prev);
- all three trigger points call it: ① the lazy sweep finds an expired entry while the local node is the exit (`next_hop==None`) → reclaim the flow along with it; ② the downlink task recv Err (target unreachable/reset); ③ a FULL re-associates to a **new target** (the old socket is meaningless for the new target, see 13-4);
- the task's own Err exit path: first `flows.remove` itself, then return (`abort` on an already-finished task is a harmless no-op; the double safeguard is not required).

### 13-2 `UdpFaceMetrics` field finalization (data source for P0-5 §2.4)

```rust
pub struct UdpFaceMetrics {
    pub forwarded_up: AtomicU64,   // uplink forwarded datagrams (including FULL/CACHED emitted locally)
    pub forwarded_down: AtomicU64, // downlink reply datagrams
    pub malformed: AtomicU64,      // decode refusals (§2 validation failure + §13-3 out of bounds)
    pub unknown_flow: AtomicU64,   // CACHED/downlink misses
    pub evicted: AtomicU64,        // ceiling eviction (R10)
    pub flows_active: AtomicI64,   // cache entry count (insert +/evict −)
}
// all relaxed; get()/get_gauge() assemble a Snapshot (matching the P0-2 UdpIngressMetrics shape)
```

- Landing point: `mesh_transport.rs`, held inside `UdpFace`;
- `seep_udp_mesh_flows_active` reads the gauge directly (no `map.len()` scan -- skew exists only at the sweep point, acceptable for monitoring).

### 13-3 envelope size ceiling (supplements §2)

- `encode_udp_envelope`: total length > **65507** (the theoretical IPv4 UDP payload ceiling) → `Err`; the caller drops + counts `malformed` (the normal path's payload never exceeds it; this is a defensive assertion, which also blocks misuse where userspace stuffs an overlong packet before routing);
- the decode side already refuses truncation; no duplication;
- the mesh plane itself does not fragment: Ethernet paths beyond the exit MTU rely on kernel IP fragmentation (direct / next hop); the QUIC vehicle (V2) carries its own fragmentation. **MVP constraint**: no reliability promise for business UDP datagrams > 1400 bytes (typical game traffic ≤ MTU) -- stated in the docs, no config key added.

### 13-4 FULL re-association and reclaim order

- an uplink FULL hits an existing entry (§3 already decided: refresh prev/next/expiry) **and the exit-side target changes** (same flow_id, new target) → `retire_flow` first, then create the flow for the new target (13-1 ③);
- the relay side has no per-flow socket; re-association only refreshes the cache;
- the general rule of order: **abort the task first, then remove the flow table, and finally remove the cache entry** (already fixed inside the 13-1 single point).

### 13-5 serve-layer concurrency model (supplements §9.2)

- `spawn_udp` = a single-task loop: `recv_from → handle_udp_datagram` sequential processing, **no per-packet spawn** -- each packet's handling has no long blocking operation (the exit's first-packet target connect is the only await point; a serial cold start is acceptable);
- high-throughput needs (V2): `SO_REUSEPORT` multi-socket sharding (one per CPU); `spawn_udp`'s external interface is unchanged;
- the exit downlink task (per-flow recv) is independent of the serve loop and naturally concurrent.

### 13-6 plaintext gate config merge (aligned with P0-5 §1.5)

The gate's construction is parameterized (§6 already decided env appears only at the read layer); **the merge point is finalized**: evaluated once inside the `RuntimeBuilder::build()` UDP block

```
allow_plaintext = cfg.mesh.udp_allow_plaintext_data_plane /* bool, serde default false */
                  || env_flag("SEEP_MESH_UDP_ALLOW_PLAINTEXT")
```

The result is passed explicitly as `MeshUdpGate { allow_plaintext: bool }` into both consumers (before the non-client `spawn_udp` / before the client `UdpChainRouter` mesh arm construction) -- the two gate instances share one source; tests cover both branches just by passing arguments, without touching the process env (the §11-5 ruling stands).

## 14. Multi-hop TTL and deduplication (third-round completion)

> Gap-review conclusion: §2 defines the `hop_index` field but never gives it semantics; deduplication has zero coverage. This section fills both in -- **everything builds on existing fields and existing counters; no wire-format change, no new series**. TTL/dedup semantics are defined at the envelope layer, not the socket layer, so they carry over unchanged when V2 swaps in the QUIC vehicle (§12) (quinn's own packet-number anti-replay is another layer and does not substitute).

### 14-1 hop_index semantics and the TTL ceiling

- Semantics: **the number of hops this datagram has crossed** -- the sender sets 0 (uplink = the client `MeshUdpRelay`; downlink = the exit downlink task, §4 already sets `hop_index:0`), and **each relay crossed adds 1** (synchronized with the FULL self-strip / CACHED cache-lookup forwarding points, symmetric uplink and downlink; the downlink "+1 re-encode" is a supplementing correction to §4's original text, at the cost of one variable-length header re-encode);
- the ceiling `MAX_UDP_HOPS = 16` (a constant; mesh link depth is in practice constrained by ChainManager construction, and 16 is a defensive value far beyond a normal topology): a relay validates `hop_index >= MAX_UDP_HOPS` before forwarding → drop + `malformed` counter (reusing the §13-2 existing field); the client's `recv_from` applies the same check to the downlink;
- **FULL mode basically needs no TTL**: the path loses one element per hop (isomorphic with the TCP plane -- `MeshEnvelope.path` is "remaining path including the current node id as the first element"), so a loop means the path strictly shrinks to empty or `path[0] != local_node_id`, both rejected by §4-2's existing validation -- a FULL loop is naturally unsustainable, and hop_index in FULL mode is observation/debug only;
- **the TTL's real target surface is CACHED**: with no path field, two nodes' hop caches pointing at each other (stale state / topology churn / malicious construction) can loop -- `hop_index` is CACHED mode's only loop breaker, which is why it exists in the wire format;
- arrival at the exit does no cross-check of hop_index against path (the exit sees only the remaining stripped path and cannot reconcile the original length) -- the ceiling breaker plus the strictly decreasing path already close the loop.

### 14-2 Deduplication (duplicate suppression) ruling

- **no payload-level deduplication**: UDP semantics themselves allow duplicate delivery (best-effort), and QUIC/DNS/game protocols handle it at the application layer; the cost of a per-flow sequence/hash window on the mesh plane (per-hop state, false kills on reordering, cross-hop inconsistency) exceeds the benefit -- the MVP explicitly does not do it; this is a ruling, not an omission;
- **the FULL periodic resend is the only normal form of a "duplicate packet"**: hitting an existing cache = refreshing the entry (§3 already decided), idempotent with no side effects, no dedup needed;
- **stale/misrouted packets**: flow expired/evicted → CACHED miss → `unknown_flow` drop (existing); a flow_id not matching the cache key is handled the same way;
- **replay (malicious copy / delayed injection)**: **flow-level anti-replay has landed in-band (2026-10, P2-7)** -- the V2 frame carries a stream sequence number and each receiving hop runs a per-(flow,dir) 64-bit sliding window (`ReplayWindow`), with `replay_dropped` counters; the plaintext-gate dev scenario still has no source authentication (the V2 frame is not MAC'd), which stays grouped with O3 into the V2 QUIC vehicle -- quinn's connection ID + packet number anti-replay is another layer and does not substitute;
- **loops**: not blocked by dedup -- FULL relies on path validation (14-1), CACHED on the TTL breaker (14-1).

## 15. Core ruling index (D-x; fourth-round spec alignment 2026-09-30)

Existing rulings numbered -- the content stays in its original §section; this is an index only, with no restatement (dual sources are harmful, following this repo's "no new separate files" ruling discipline); **D-15/D-16 are new this round** (the body lands in §17-P1-4).

| # | Ruling | Landing point |
|---|------|------|
| D-1 | No TCP-ification: not through the `MeshStream` abstraction; codecs written directly | §1 |
| D-2 | Socket topology: one shared UDP-plane socket per node (forwarding/replies from the same source, NAT-friendly); the exit has a connected socket per flow | §1 |
| D-3 | Binary envelope format; flow_id uses the raw 16 UUID bytes (the cache key and wire format, not a string) | §2, §11-3 |
| D-4 | Each hop strips itself and re-encodes FULL; no downgrade to CACHED; the CACHED judgment stays local at each hop | §4, §11-4 |
| D-5 | The cache entry carries `prev` (the downlink reflux address); a FULL hit means re-association refresh | §3, §11-2, §13-4 |
| D-6 | Ceiling eviction = earliest expiry (under equal TTL, the longest untouched; semantics LRU), O(n), no new dependency | §3, §11-6 |
| D-7 | The exit downlink task's single reclaim point `retire_flow` (abort task → flow table → cache; the three-step order is fixed) | §13-1 |
| D-8 | The plaintext gate blocks at build time; the gate's explicit parameters and env reading are separated; the config merge `cfg ∪ env` is evaluated once in build() | §6, §11-5, §13-6 |
| D-9 | The build() UDP block moves wholesale below ChainManager (the FlowRouter is fixed at construction; construct-early-swap-late is not viable) | §9.1 |
| D-10 | chain_id framing bridge: ChainFailureEvent fills `chain_id_of(the new decision after the switch)` | §8, §11-7 |
| D-11 | serve is a single sequential loop, no per-packet spawn; the exit downlink task is independently concurrent | §13-5 |
| D-12 | The envelope ceiling is 65507 (encode refuses); no reliability promise for >1400-byte business packets (stated in docs, no config added) | §13-3 |
| D-13 | hop_index = hops crossed, +1 per hop, symmetric up/down; the real target surface of `MAX_UDP_HOPS=16` is the CACHED loop breaker (FULL is naturally loop-safe via the strictly decreasing path) | §14-1 |
| D-14 | No payload-level deduplication (UDP semantics allow duplication; the FULL resend is idempotent); replay protection = flow-level anti-replay landed in-band (P2-7 v2 frame + sliding window, `replay_dropped`); end-to-end source authentication belongs to the V2 QUIC vehicle | §14-2 |
| D-15 | **UDP padding spec production point = associate session-level evaluation** (reusing `PaddingSpec` and the policy pure functions + the obfuscation selector), not through `FlowMiddleware::handle` -- the UDP session path has no Flow, and the stream signature does not fit (same cause as P1-4 §2.1) | §17-P1-4 (new this round) |
| D-16 | **Padding execution point = the envelope wrapping side** (client FULL first send / exit downlink wrapping, after encoding and before send_to); relay re-encoding (strip self, hop_index+1) keeps `pad_len` unchanged without appending; CACHED forwarding segments add no padding | §17-P1-4 (new this round) |

## 16. Interface seams (internal; the contract list of existing dispatch points)

| Seam | Location | Contract |
|------|------|------|
| ingress dispatch | socks5 inbound 0x03 command dispatch (`seep-protocols/src/inbound/socks5.rs`) → `UdpAssociateService` (`seep-core/src/udp/associate.rs`) | existing from P0-2; zero changes in this item; datagrams enter via the session table |
| session → decision | `UdpSessionTable` (sticky key / ensure_decision / ledger) → `RouteDecision` | existing from P0-1; S5 swaps its FlowRouter for `RuntimeFlowRouter` (D-9) |
| decision → egress | `UdpChainRouter` implements P0-3 `EgressUdpConnector` (`seep-core/src/udp/relay.rs:259`): `Chain{hops≥2}` → `MeshUdpBridge`, otherwise → the inner `RoutingUdpConnector` (P0-3 dispatches by final_node) | §5; the capability scan `mesh.` exemption is already in place (§9.2); a chain decision's exit capability is expressed by the exit side's real connect |
| client underlay | `MeshUdpRelay` implements P0-1 `UdpRelay` | the session table / §3.6 staged teardown / forwarder reused with zero changes (§5) |
| with the TCP plane | shares only the `listen_address` port and `record_link_bytes` accounting; envelope/socket/lifecycle independent | §1 selection boundary (pointer, no restatement) |
| failure wiring | `ChainFailureEvent` (§8 framing); the in-flight hop cache expires naturally and is not actively torn down | §8, D-10 |
| observability | `UdpFaceMetrics` (§13-2) = the data source for P0-5 §2.4 `seep_udp_mesh_*` | data source contract; framing notes in §0.2 |
| annotation visibility | the UDP session's `FlowContext.metadata.annotations` (`seep-core/src/lib.rs:85-89`/`:52-55`, with the `process.*` family as the precedent) reachable at `associate(&ctx, &decision)` (`relay.rs:267`, where decision is the sticky decision) | the precondition for P1-4 padding session-level production (D-15); at implementation, verify whether ingress already writes the needed annotations, and if not, have ingress backfill them before associate (fallback option, out of scope for this item) |

## 17. Boundary cross-references (external items; fourth-round completion 2026-09-30)

### 17-P1-4 obfuscation middleware (padding vehicle seam -- this round fixes one production-point gap)

- [obfuscation-middleware.md](obfuscation-middleware.md) §2.3/§4.4 already lists this item's `UdpEnvelope` as padding's **ideal frame carrier** (one datagram = one controllable byte boundary) and reserves the execution hook -- the two drafts' mutual reference holds;
- **production-point correction (D-15)**: P1-4 §4.4's original wording "the UDP encoder reads the `seep.obfs.padding` annotation" implied the annotation already exists -- but that annotation's production point (the middleware chain at `FlowOutputRouter::forward` ②) exists only on the TCP Flow path, and the **UDP session path (associate → `UdpRelay::send_to`) has no Flow to hang a chain on**. Ruling: the UDP plane's padding spec is evaluated at the **associate session level** from the obfuscation config and selector (reusing `PaddingSpec` and the policy pure functions, with `apply_to` semantics judged by the session's target/egress), not through `FlowMiddleware::handle` -- the second occurrence of the same cause as P1-4 §2.1's "the stream signature does not carry frame semantics" (packet semantics likewise do not fit the stream trait); P1-4 §4.4 now carries a revision note cross-referencing this section;
- **execution point (D-16)**: padding is produced at two envelope wrapping points -- the client's FULL first send and the exit downlink wrapping (both "after encoding, before send_to", consistent with P1-4 §4.4's wording); the relay's FULL self-strip and hop_index+1 re-encoding **keep the existing `pad_len` without appending** (preventing per-hop padding accumulation); CACHED forwarding segments add no padding;
- wire format: `pad_len`'s wire position (§2 reserved bits vs. a new field) and the version-gate value are finalized with the P1-4 UDP vehicle landing (§12 already registers this), fail-open aligned with P1-4 §2.4 -- this draft does not pre-fix it.

### 17-P1-5 egress connection pool (zero-overlap confirmation)

- [egress-connection-pool.md](egress-connection-pool.md) §1.3's three-layer seam table has ruled: the pool belongs to the TCP transport layer (TCP[+TLS] sessions to egress servers); UDP datagrams have no connection-establishment semantics -- `EgressUdpConnector`/`UdpSessionTable`/this item's UDP plane never go through `TransportPool`;
- the exit's per-flow connected socket (§4) is P0-3 LocalRelay semantics (a target socket, not a "transport to the egress server"), so it does not hang off P1-5; if the UDP plane ever develops a "warm-up" need, that is a separate model (session warm-up ≠ connection pool) and would be discussed separately at that time.

### 17-P2-5 client TLS fingerprint simulation (different hook layer; V2 convergence)

- uTLS-class capabilities hook into the `tls.rs` egress TLS common layer (explicit in todo P2-5) -- that is the **TCP/TLS egress plane**, with no shared hook point with this item's UDP plane;
- this item's MVP plaintext gate (§6) has no TLS handshake and hence no fingerprint to speak of; the V2 QUIC vehicle (§12) will introduce a QUIC ClientHello -- **QUIC fingerprint/camouflage and uTLS are the same class of problem, different protocol**; the vehicle choice will be discussed together with P2-5 at that layer, and this draft neither reserves nor promises anything.
