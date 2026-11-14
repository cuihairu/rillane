# P1-5 egress connection pool -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) S2/S3 ("egress connection pool: same-egress keep-alive reuse + TLS session resumption, serving web short connections") · [PROTOCOLS.md](../PROTOCOLS.md) master table and performance section (connection pool not implemented -> P1-5) · [positioning.md](positioning.md) §2 (shared datapath for the three scenarios, a core item of web acceleration).
> This document is the finalized landing design: **mirror types and schema, assembly and hot reload, control plane, state machine, test strategy, step-by-step implementation checklist**. Deviations are backfilled into §10 after landing.
> Reuse baseline: `EgressConnector` takeover-style contract (`rillane-core/src/lib.rs:625-628`) · `ConnectorFlowOutput` adapter (`runtime_builder.rs:1466`) · `build_egress_outputs` assembly (`runtime_builder.rs:1635`, call sites :158 / :720 / :933) · `RuntimeConfig.connection_pool_size` (`runtime_builder.rs:311`, default `Some(1024)`, a zero-consumer orphan field repo-wide) · `tls.rs:10-47` rebuilding `ClientConfig` per flow (call sites trojan.rs:101 / http.rs:92 / vless.rs:190, :228) · the `perform_connect<S>` generic (http.rs:126) · the rustls 0.23.35 public surface (`Resumption::in_memory_sessions` is the default resumption policy, `HandshakeKind` observable via `CommonState::handshake_kind()`, source-verified, see §2.4) · the `UdpConfig` mirror + runtime conversion precedent ([udp-dataplane.md](udp-dataplane.md) §5.2) · targeted `deny_unknown_fields` closure for new blocks ([network-route.md](network-route.md) §1.5) · MockClock (P0-1) · closed label set (R11) · the control-plane getter pattern (`control_plane.rs:23`/`:259`/`:386`) and the hand-written `/metrics` (`:245`).

## 0. Scope and acceptance criteria

### 0.1 Scope

| In this item | Belongs to other items |
|-----------|-----------|
| `egress_pool:` config block (rillane-config mirror types) + `PoolPolicy`/`TransportPool`/`TlsConnectorFactory` (rillane-protocols) | Multiplexing (concurrent streams within one connection, including hy2/QUIC session reuse) = V2 -- for the structural reason total dials do not drop, see the §0.2 note |
| MVP matrix egress onboarding: trojan / http (incl. tls) / vless (tcp+ws, incl. tls) / vmess (2026-10-02 egress landing, passes through with the pool) / direct (`pre_dial_direct` opt-in) | socks5 / shadowsocks pooling = extension (the crate merges dial+bind, D-6); wg = system interface, no userspace dial |
| TLS session resumption (process-level shared `ClientConfig`) + `HandshakeKind` observability counters | uTLS fingerprint emulation = P2-5 (the same `tls.rs` mount point; the factory converges its injection surface, cross-referenced in §2.4) |
| `connection_pool_size` orphan-field adoption (global capacity default, D-8) | mesh hop dial reuse (`connect_next` dials per flow) = O item, non-commitment (§11) |
| `/metrics` `rillane_pool_*`/`rillane_tls_*` series + `GET /egress/pool/stats` + the acceptance statistics script | UDP side = P0-4/P0-5 (no connection-establishment semantics, zero overlap §1.3); obfuscation middleware = P1-4 (Flow level, strictly upstream/downstream §1.3) |

### 0.2 Acceptance criteria (explicit)

The original todo P1-5 acceptance text: "repeated requests to the same target see fewer handshakes, `/metrics` has a connection-reuse-ratio metric; no breaking changes for existing configs". Combined with this item's title stance (same egress same SNI keep-alive reuse + TLS session resumption), four criteria:

1. **Same-egress same-SNI keep-alive reuse (measurable)**: N>=10 serial requests to the same (egress, SNI) -> `rillane_pool_acquires_total{result="hit"}` >= N-1 (after assembly prewarm the first request already hits, miss may be 0), `rillane_pool_reuse_ratio` >= (N-1)/N;
2. **Fewer handshakes (scope note, aligned with the P0-3/P1-4 practice of explicit rewriting, no silent shrinkage)**: the measurable scope = **handshakes blocking the request path** -- a request served from a hit does zero dials and zero handshakes (the foreground dial count does not grow); on top of that, session resumption replaces the full handshakes of prewarm/refill dials with `HandshakeKind::Resumed` (compare `rillane_tls_handshakes_total{type}`). **Total dials ~= flow count, no reduction** -- every flow consumes one connection (§1.2 structural constraint); truly reducing total connections requires multiplexing (V2). The acceptance statistics script emits all three groups at once (foreground handshakes / resumed share / total dials) to avoid ambiguity;
3. **Connection reuse ratio metric**: `rillane_pool_reuse_ratio` (gauge) + `rillane_pool_acquires_total{result}` counters, visible in `/metrics`;
4. **No breaking changes for existing configs**: no `egress_pool:` block -> zero parsing and behavior difference (serde roundtrip + behavior-comparison assertions); `connection_pool_size` is consumed only when the block exists and `max_idle_global` is unwritten (before this it had zero consumers).

## 1. Current state and structural constraints (the factual inputs for the decisions)

### 1.1 Current state of connection-establishment paths (audit conclusions, not a restatement)

| Egress | Connection establishment inside forward (landing point) | Protocol binding (target-related bytes) | Transport/bind separability |
|------|--------------------------|--------------------------|----------------|
| direct | `TcpStream::connect(target)` (direct.rs) | none (pure pass-through) | the target is the transport endpoint, key=target |
| trojan | `TcpStream::connect(server)` -> `create_tls_connector` (trojan.rs:101) -> TLS connect(sni) | trojan request header (SHA224+CRLF+ATYP+target) | **naturally separable**: the header is written after TLS is established |
| http | `TcpStream::connect(proxy)` -> [TLS] (http.rs:92) -> `perform_connect` | the CONNECT request | **naturally separable**: the `perform_connect<S>` generic (http.rs:126), binding independent of transport |
| vless | `TcpStream::connect(server)` -> [TLS] (vless.rs:190 tcp / :228 ws) | vless header (tcp branch) / WS upgrade + vless header (ws branch, host/path decided by egress config, target-independent) | **separable**: both branches are "transport first, bind later" |
| socks5 | `tokio_socks::tcp::Socks5Stream::connect(proxy, target)` | greeting+auth+CONNECT **merged** with the dial inside the crate call | not separable (no external stream injection point; and without a TLS layer the gain is low) |
| shadowsocks | `ProxyClientStream::connect(context, server_cfg, target)` | the target address goes into the first write, **merged** with the dial | not separable (the crate's public API shape; re-verify the injection point at implementation time) |
| hysteria2 / wireguard | QUIC session / system interface | — | outside this model (QUIC reuse goes to V2 mux / no userspace dial) |

### 1.2 Structural constraint: binding is consumption (the derivation premise for the pool's shape)

- `EgressConnector::forward(Flow) -> FlowReport` (`rillane-core/src/lib.rs:625-628`) is **takeover-style**: the connection is established inside forward and ends with the flow. `copy_bidirectional` returning = bidirectional EOF (whichever side closes first, the other gets its write half shutdown) -- **a terminal connection state, not returnable for reuse**. This is tunnel-protocol semantics, not an implementation flaw: after the target connection closes, the proxy server closes the tunnel connection shortly after;
- Corollary: **a "check out then return" connection pool is unrealizable under the current architecture** (it would need changed forwarding semantics or mux, both out of bounds). The realizable shape = a **pre-established (warm) pool**: transport-layer connections pre-dialed as TCP[+TLS] with **zero protocol bytes written**, cached by key; on a flow's arrival one is checked out, the protocol header is written after checkout; when the flow ends the connection is consumed; a checkout triggers background watermark refill;
- Benefit position (the factual basis of the §0.2 note): foreground (request-path-blocking) handshakes -> 0 (on a hit); TLS session resumption turns the pool's own dials' full handshakes -> Resumed; **total dials ~= flow count, unchanged**.

### 1.3 Three-layer seams (boundary cross-references with P1-4 / P0-x)

| Layer | Item | Mount point | What it governs | Seam with this item |
|----|------|------|--------|---------------|
| Flow-level processing | P1-4 obfuscation middleware | `FlowOutputRouter::forward` steps ①②③ (**before** dispatch, [obfuscation-middleware.md](obfuscation-middleware.md) §1.3) | the flow's byte shape (padding spec annotations + frame-carrier execution) | **strictly upstream/downstream**: the pool sits inside connector.forward (**after** dispatch, at the transport level). The P1-4 MVP frame carrier is only the chain `MeshEnvelope` (its §2.3), zero overlap with the pool; if an egress-side filler appears later, the filler acts on the post-checkout flow bytes -- the pool governs connection lifecycle, not byte content, orthogonal |
| TCP transport | **this item** | `build_egress_outputs` assembly into the connector (§4) | the TCP[+TLS] session-establishment cost to the egress server | — |
| UDP session | P0-1/P0-4/P0-5 | `UdpSessionTable` / `UdpEnvelope` / `rillane_udp_*` | NAT-style datagram sessions (sticky/reclamation) | **zero overlap**: UDP has no connection-establishment semantics (no TCP/TLS handshake to eliminate), `EgressUdpConnector`/`RoutingUdpConnector`/`UdpSessionTable` are untouched; the three layers each govern one segment (IP session / Flow processing / TCP transport) |

mesh side: `connect_next` dials a hop per flow (`mesh_transport.rs:406`) -- this item **does not touch it** -- the mesh hop's `MeshEnvelope` first write is itself the protocol binding, and its shape is pool-compatible (key = hop address); future reuse is recorded as §11 O-pool1, non-commitment.

## 2. Decisions (D-x) and policy/execution separation

### 2.1 Decision summary table

| # | Decision | Summary |
|---|------|------|
| D-1 | Pool shape = pre-establish + checkout-is-consumption, **no return** | the direct conclusion of the §1.2 structural constraint; no fake "return for reuse" |
| D-2 | Key = transport identity `(server, port, tls, sni, skip_cert_verify, alpn)`, not the egress name | "same egress same SNI" implemented literally; the direct key = (target_host, target_port, tls=false); keys self-invalidate on scope change (D-10) |
| D-3 | Policy/execution separation (aligned with the [obfuscation-middleware.md](obfuscation-middleware.md) §2.1 methodology) | the three sides -- config-time policy / runtime execution / protocol binding -- have their duties pinned (§2.3) |
| D-4 | Zero trait changes | do not touch `EgressConnector`/`FlowOutput`/`FlowMiddleware`/`ConnectorFlowOutput`; connector constructors get an injected `Option<Arc<...>>` |
| D-5 | TLS session resumption = process-level shared `ClientConfig` factory | the per-flow rebuild in `tls.rs` is the root cause of resumption failing (§2.4); `HandshakeKind` observed via the public API |
| D-6 | MVP capability matrix | pooled = trojan/http/vless + direct opt-in; not pooled = socks5/ss/hy2/wg/vmess (§2.5). ~~vmess not pooled~~ -- with the 2026-10-02 vmess egress landing it passes through with the pool (the runtime_builder Vmess arm injects transport_pool, same as trojan/vless) |
| D-7 | Prewarm: TLS egresses prewarm at assembly; direct does not | TLS egress keys are known at assembly time; direct targets are unknown, traffic-driven (the first miss triggers a refill to serve later hits) |
| D-8 | `connection_pool_size` adoption = global idle capacity default | block exists and `max_idle_global` unwritten -> take `RuntimeConfig.connection_pool_size` (default 1024) |
| D-9 | Zero difference in the off state | no block -> connectors get pool=None, tls takes today's per-flow path, byte-level behavior unchanged (§2.6) |
| D-10 | Pool and factory = process-level singletons shared across hot reloads; parameter changes take effect on restart | :720/:933 only re-run the assembly with handles, do not rebuild the pool (the 30s-periodic subscription refresh does not kill warmth, §4.3) |
| D-11 | Stale handling = invalid-on-checkout -> one-shot foreground redial; no active probing | protocol-bind first-write/first-read failure judges stale: release + count + redial once; failing again -> Err (same as today's dial-failure semantics) |

### 2.2 Pool shape and keys (D-1/D-2)

- **Pool invariant**: idle entries have zero protocol bytes written (post-checkout the connection is in a clean state, the protocol header is written by the connector) -- this is the only contract between the pool and the protocol layer;
- The key contains `alpn`/`skip_cert_verify` (they shape the handshake -> hence transport identity); different egress names colliding on the same transport identity (e.g. direct to X:443 plaintext vs an http proxy at X:443 plaintext) share the key space -- semantically equivalent (both a bare TCP to X:443), harmless and beneficial;
- Human-readable serialization of `TransportKey` (for control plane/logs): the `tls?sni@server:port[alpn=..]` shape.

### 2.3 Policy/execution separation (D-3/D-4)

| Side | Carrier | Duties | What it does not do |
|----|------|------|---------|
| Policy side (config/assembly time) | `EgressPoolBlock` (rillane-config) -> `PoolPolicy` (conversion in rillane-runtime, precedent `to_padding_policy()`) | who participates (`enabled`/`pre_dial_direct`), capacity (per-key/global), watermark, timeouts, session cache size | contains no runtime state |
| Execution side (runtime) | `TransportPool` (rillane-protocols/src/pool.rs) | dial/cache/checkout/watermark refill/reclaim/backoff/counting | **zero protocol knowledge** (knows only `TransportKey`, never sees protocol bytes) |
| Protocol binding side | existing connectors (trojan/http/vless/direct) | write the protocol header after checkout + `copy_bidirectional` (current semantics unchanged) | unaware of pool internals (sees only the `acquire` API) |

Aligned with the same ruling logic as P1-4 §2.1: P1-4 split policy from execution because the `handle(Flow)` flow signature carries no frame semantics; this item splits "transport session" out of the connectors because their binding semantics all differ -- what the two splits share: **zero trait changes** (D-4, the rillane-core surface is untouched).

### 2.4 TLS session resumption (D-5)

**Root cause (source-verified, rustls 0.23.35)**: `Resumption::in_memory_sessions(num)` is rustls's **default resumption policy** (`client/client_conn.rs`: "This is the default `Resumption` choice", internally `handy::ClientSessionMemoryCache`) -- i.e. the default config already supports session resumption; the root cause of failure is on rillane's side: `tls.rs:10-47` builds a new `ClientConfig` on every `create_tls_connector[_with_alpn]`, and the session cache (`Arc<dyn ClientSessionStore>`) lives inside the instance and **dies with the flow** -- the ticket cannot survive into the next handshake. Call sites: trojan.rs:101, http.rs:92, vless.rs:190/:228.

**Fix**: `TlsConnectorFactory` (an extension inside rillane-protocols/src/tls.rs):

```rust
pub struct TlsConnectorFactory {
    configs: Mutex<HashMap<TlsConfigKey, Arc<ClientConfig>>>,  // key = (skip_cert_verify, normalized alpn)
}
impl TlsConnectorFactory {
    /// same key returns a TlsConnector sharing the Arc (TlsConnector::from(Arc<ClientConfig>) is a cheap clone)
    pub fn connector(&self, skip_cert_verify: bool, alpn: Option<&[String]>) -> Result<TlsConnector>;
}
```

- On the shared instance the default resumption policy takes effect immediately (the cache survives across flows); an explicit `config.resumption = Resumption::in_memory_sessions(session_cache_size)` pins the capacity (config item §3);
- **Observability (public API, verified)**: `CommonState::handshake_kind() -> Option<HandshakeKind>` (`common_state.rs:188`), variants `Full` / `FullWithHelloRetryRequest` / `Resumed` (publicly exported at `rustls` lib.rs:545); reachable via tokio-rustls `TlsStream::get_ref().1` -- read right after dialing completes, driving `rillane_tls_handshakes_total{type}`;
- Effective gate: block exists and `tls_resumption: true` (the default) -> the factory is injected -- **independent of `enabled`** (enabled=false turns off only the pool; session resumption is pure gain and stays on separately, see the §2.6 zero-difference boundary); no block -> no factory injection, connectors take today's per-flow path (D-9);
- Cross-reference with P2-5: uTLS's mount point is exactly `tls.rs` (todo P2-5 states it); once the factory converges `ClientConfig` construction into one place, that is precisely the injection surface for fingerprint replacement -- this item paves the way without crossing the line.

### 2.5 Capability matrix (D-6/D-7)

| Egress | MVP disposition | Basis (§1.1 separability) |
|------|---------|---------------------|
| trojan / http (incl. tls) / vless (tcp+ws, incl. tls) / vmess (2026-10-02 landing, passes through with the pool) | **pooled** (assembly injects pool + factory) | binding happens after transport establishment, naturally separable |
| direct | **opt-in pooling** (`pre_dial_direct`, default false) | key=target; speculative pre-dials create "unrequested connections" to the target, and the optics/cost are borne explicitly by the switch (R-pool2) |
| socks5 / shadowsocks | not pooled (recorded as extension) | the crate merges dial+bind; socks5 has no TLS layer, the gain is only 1-RTT |
| hysteria2 / wireguard | not pooled (each goes to V2 mux / system interface) | not the TCP transport model |

Prewarm (D-7): with `enabled=true`, the tail of assembly dials `min(max_idle_per_key, ...)` warm connections per known TLS egress key (failures back off and retry, without blocking startup -- the pool is an optimization, not a precondition); direct is not prewarmed.

### 2.6 Zero difference in the off state (D-9)

- No `egress_pool:` block (existing configs): parse None -> connectors pool=None, factory=None -> `TcpStream::connect` + per-flow `create_tls_connector` follows today's path byte for byte;
- Block exists with `enabled: false`: only `tls_resumption` (default true) is effective -- the shared factory is injected (resumption works across flows), the pool is not constructed;
- Both states above carry behavior-comparison assertions (§8.1) -- "zero difference" is provable, not a verbal promise.

## 3. Mirror types and schema (rillane-config)

### 3.1 Block shape

```yaml
egress_pool:
  enabled: false              # pool master switch (off by default, aligned with the udp:/obfuscation: precedent)
  tls_resumption: true        # shared ClientConfig + session cache; effective once the block exists, independent of enabled
  max_idle_per_key: 2         # per-key idle cap (prewarm/refill target)
  # max_idle_global: 1024     # global idle cap; unwritten -> takes RuntimeConfig.connection_pool_size (D-8)
  low_watermark: 1            # after checkout, idle below this value triggers a refill (<= max_idle_per_key)
  idle_timeout_secs: 30       # idle entry lifetime (from entering the pool)
  dial_timeout_secs: 5        # per-dial timeout (the whole TCP+TLS)
  session_cache_size: 256     # ClientSessionMemoryCache capacity
  pre_dial_direct: false      # pre-dial direct by target (speculative dialing, off by default, §2.5)
```

### 3.2 Mirroring and conversion (ruling: mirror rather than add a dependency, precedent udp-dataplane §5.2)

rillane-config has zero dependency on rillane-core/protocols (current deps only anyhow/serde family): **rillane-config defines mirror serde types, and rillane-runtime adds a `to_pool_policy()` conversion** (the `PoolPolicy` type is defined in rillane-protocols/src/pool.rs -- that crate needs tokio dialing; rillane-protocols already depends on rillane-config, so no new dependency edge).

| config mirror type (rillane-config) | Conversion product |
|-------------------------------|---------|
| `EgressPoolBlock { enabled, tls_resumption: Option<bool>, max_idle_per_key: Option<usize>, max_idle_global: Option<usize>, low_watermark: Option<usize>, idle_timeout_secs: Option<u64>, dial_timeout_secs: Option<u64>, session_cache_size: Option<usize>, pre_dial_direct: Option<bool> }` | `PoolPolicy { ... all fields valued }` (`to_pool_policy(default_global: usize)`, default_global = `runtime_config.connection_pool_size`, D-8) |
| `RillaneConfig.egress_pool: Option<EgressPoolBlock>` (`#[serde(default)]`) | `None` -> no pool, no factory (zero difference); `Some` and enabled -> `Some(Arc<TransportPool>)`; `Some` and tls_resumption -> `Some(Arc<TlsConnectorFactory>)` |

### 3.3 Validation (at build time, `EgressPoolBlock::validate`)

1. `enabled=false` and `tls_resumption=false` -> later capacity/watermark fields are ignored (no error, half-finished configs tolerated);
2. `max_idle_per_key == 0`, `low_watermark > max_idle_per_key`, `session_cache_size == 0` (when resumption is on) -> Err (E1);
3. `idle_timeout_secs < dial_timeout_secs` -> warning (not Err: an entry lifetime shorter than the dial duration is only prewarm waste, not an error);
4. `pre_dial_direct=true` but `enabled=false` -> Err (with no pool there is nothing to pre-dial into; guards against config delusion).

### 3.4 Compatibility

- Existing configs without `egress_pool:` -> None default, zero behavior difference (pinned by serde roundtrip, same as the udp block precedent);
- **`EgressPoolBlock` gets `#[serde(deny_unknown_fields)]`** (a new block carries no legacy burden, a misspelled sub-field errors immediately, aligned with network-route §1.5); the global `RillaneConfig` stays permissive.

## 4. Assembly and hot reload

### 4.1 build() assembly landing point

`RuntimeBuilder::build()` (`runtime_builder.rs:105`), before the `build_egress_outputs` call site (:158), following the existing pattern of the adjacent UDP block:

```
let egress_pool_cfg = config_snapshot.egress_pool;          // Option<EgressPoolBlock>
let tls_factory = egress_pool_cfg.as_ref()
    .filter(|b| b.tls_resumption().unwrap_or(true))
    .map(|_| Arc::new(TlsConnectorFactory::new(policy.session_cache_size)));
let transport_pool = egress_pool_cfg.as_ref()
    .filter(|b| b.enabled)
    .map(|b| Arc::new(TransportPool::new(b.to_pool_policy(
        self.runtime_config.connection_pool_size.unwrap_or(1024)), tls_factory.clone())));
// build_egress_outputs(&config_snapshot.egress, transport_pool.clone(), tls_factory.clone())
```

- `build_egress_outputs` (:1635) gains two parameters; each match arm passes them when constructing connectors (trojan/http/vless always; direct passes the pool only with `pre_dial_direct`) -- **`ConnectorFlowOutput` (:1466) and `FlowOutputRouter` (:1227) unchanged** (D-4);
- Runtime gains two fields holding the singletons + getters (`get_transport_pool()` / `get_tls_factory()`, following the `get_mesh_registry` :259 / `get_chain_manager` :386 precedent); the control plane and hot-reload closures take clones;
- Tail-of-assembly warm() (D-7): pre-dials per key for TLS egresses in the config, spawning a background task (failures back off, startup not blocked).

### 4.2 Connector onboarding shape (trojan as the example)

```rust
// constructor signature gains two Options (None = the old byte-for-byte path, D-9)
TrojanConnector::new(server, port, password, sni, skip_cert_verify,
                     pool: Option<Arc<TransportPool>>, factory: Option<Arc<TlsConnectorFactory>>)

async fn forward(&self, flow: Flow) -> Result<FlowReport> {
    let key = TransportKey::tls(&self.server, self.port, &self.sni, self.skip_cert_verify, &[]);
    // checkout (hit pops an idle entry / miss dials in the foreground) + watermark refill;
    // with both params None, take today's inlined path
    let (mut outbound, _lease) = self.pool.acquire(&key).await?;   // _lease: leased-- on Drop
    match self.bind_and_relay(flow, &mut outbound).await {          // write trojan header + copy_bidirectional
        Err(e) if first_write_or_read_failed && self.pool.is_some() => {
            self.pool.note_stale(&key);                             // count + release (lease drop)
            let (mut fresh, _lease) = self.pool.acquire_fresh(&key).await?;  // one-shot redial (D-11)
            self.bind_and_relay(flow, &mut fresh).await
        }
        other => other,
    }
}
```

- `LeaseGuard`: checkout returns `(BoxedIo, LeaseGuard)`, and the guard's Drop decrements the leased gauge -- the connector just holds one extra `_lease` binding; RAII needs no explicit return call (and there is no return semantics, D-1);
- http has the same shape (the `perform_connect` generic eats BoxedIo directly); vless's two branches (tcp/ws) have the same shape, with the ws upgrade happening after checkout (host/path target-independent, §1.1); direct: `TcpStream::connect(target)` -> `pool.acquire(TransportKey::plain(target))`.

### 4.3 Hot-reload semantics (D-10)

- The two rebuild paths (:720 subscription merge, :933 config apply) re-run `build_egress_outputs` -- **they only re-wire the assembly (pass/withdraw handles), not rebuild the pool and factory**: process-level singletons + key-scope self-invalidation (changing server/sni -> a new key != the old key -> the old entries get no checkouts and are naturally reclaimed by idle timeout, §5) -- the :720 subscription refresh runs a 30s period by default, and rebuilding would kill the pool continuously, killing warmth, so the singleton is a must, not an optimization;
- Changes to `enabled`/`pre_dial_direct`/the egress set: take effect immediately with the assembly (new connectors with/without handles);
- **Pool parameters (capacity/watermark/timeouts/cache size) are burned in at construction; changes need a restart** (aligned with the network-route O-hot / P0-5 §1.6 precedent); wholesale block removal -> the new assembly passes no handles, the pool is released with the Runtime, idle entries closed (E7).

## 5. State machine

### 5.1 Connection lifecycle

```
        [warm prewarm / refill watermark top-up / foreground miss] (origin's three values feed dials_total)
                    dial ──ok──► idle ──acquire──► leased ──protocol bind+copy──► consumed (TCP close, not returned to pool)
                     │                            │
                     │ err                         │ bind first-write/first-read failure = stale
                     ▼                            ▼
              backoff (exponential from 1s,        note_stale: release (lease drop)
              capped at 30s, reset on success;     + stale_redial counter
              only background refill backs off,    + acquire_fresh one-shot redial (D-11, failing again -> Err)
              a foreground miss failure is
              Err directly = today's semantics)
                     ▲
   idle: verify expiry on lazy pop (expired -> close + miss) + periodic sweep (idle_timeout/2)
   reclaiming expired and orphan-key entries
   capacity: on refill/entry, global idle above max_idle_global -> evict the oldest idle one by one
   (new entries not refused -- the pool is an optimization, not a quota)
```

### 5.2 States and invariants

- Per-connection state set: `dialing -> idle -> leased -> consumed|closed` (leased is the only active state before the terminal state; no returned state -- D-1);
- Pool-level invariants: `sum(idle) <= max_idle_global`; `idle(k) <= max_idle_per_key`; `inflight_refill(k) <= max_idle_per_key - idle(k)` (the concurrency cap on watermark refill; under a consumption storm each flow tops up at most one entry and the total is bounded = total dials ~= flow count);
- Refill trigger point = **acquire (after the pop)**; consume (lease drop) only adjusts the gauge and triggers no refill -- avoiding blind dials in the gap between "flow ended" and "next flow arrives".

## 6. Control plane

### 6.1 New `/metrics` series (closed label set, R11; rendering hooked at `handle_metrics` :245, same family as `rillane_mesh_*` :319)

```
rillane_pool_acquires_total{result="hit|miss|stale_redial"}
rillane_pool_dials_total{origin="foreground|warm|refill", result="ok|error"}
rillane_pool_idle_connections        # gauge
rillane_pool_leased_connections      # gauge
rillane_pool_reuse_ratio             # gauge = hits/(hits+miss), since startup
rillane_pool_evicted_total{reason="idle_timeout|capacity|shutdown"}
rillane_tls_handshakes_total{type="full|resumed|full_hrr"}   # when the factory is enabled; maps the three HandshakeKind variants directly
```

### 6.2 `GET /egress/pool/stats` (match arm aligned with the `/chains/dry-run` precedent)

```json
{"enabled": true, "tls_resumption": true,
 "keys": [{"key": "tls:sni=x@example.com:443", "idle": 2, "leased": 1}],
 "counters": {"hit": 9, "miss": 1, "stale_redial": 0, "dials_ok": 12, "dials_err": 0},
 "reuse_ratio": 0.9}
```

Data source = the `Runtime::get_transport_pool()` snapshot method (the §4.1 getter precedent); auth inherits the control-plane status quo. The `rillanectl pool status` subcommand has landed with O-pool3 (2026-10-11, see §11).

## 7. Error paths

| # | Error point | Condition | Semantics and recovery |
|---|--------|------|-----------|
| E1 | Invalid config | watermark > per-key cap / zero capacity / `pre_dial_direct` with no pool | build-time Err naming the field (§3.3) |
| E2 | Foreground dial failure | TCP/TLS timeout or refusal (miss or stale redial) | Err returned to the connector -> the flow fails (**same as today's dial-failure semantics**, the pool does not swallow errors) + `dials_total{origin=foreground,result=error}` |
| E3 | Invalid on checkout (stale) | idle connection closed by the peer (keep-alive timeout) | release + `acquires_total{stale_redial}` + one-shot `acquire_fresh` redial; failing again -> E2 |
| E4 | Background refill dials failing consecutively | egress unreachable | exponential backoff 1s->30s capped, reset on success; **does not block acquire** (a miss goes foreground) + counter |
| E5 | Global-capacity eviction | idle exceeds `max_idle_global` | close the oldest idle entries one by one + `evicted_total{capacity}` (new entries not refused) |
| E6 | Idle timeout | `idle_timeout_secs` expired (lazy + sweep dual paths) | close + `evicted_total{idle_timeout}`; hot-reload orphan keys drain naturally through this |
| E7 | Hot reload / block removal | handle withdrawn or pool released | the pool drops with the last handle -> all idle closed + `evicted_total{shutdown}`; checked-out connections end naturally with their flows (no waiting) |
| E8 | Factory construction failure | root store/verifier abnormal | build-time Err (same as today's `create_tls_connector` failure, but surfaced earlier, at assembly time) |
| E9 | Connection error during forwarding | `copy_bidirectional` Err | terminal consumption (not returned to the pool) + leased back to zero (lease drop); background refill proceeds as usual |
| E10 | Off path | no block / enabled=false | not an error: pool=None, factory injected per tls_resumption; pinned by behavior-comparison assertions (§2.6) |

## 8. Test strategy

### 8.1 Unit tests (no privileges, any environment)

- **schema**: parsing old configs with no block ✓; roundtrip with the block ✓; unknown sub-fields denied ✓; the four §3.3 validations in both states ✓; `to_pool_policy` default filling (incl. the D-8 mapping: global unwritten -> 1024/custom connection_pool_size) ✓;
- **keys**: equality (sensitive to sni/alpn/skip/port; alpn order normalized); the direct plaintext key never collides with a TLS key; the human-readable serialization shape;
- **pool core**: hit/miss counters and acquire semantics; watermark refill (post-pop inflight bound = the per-key invariant); per-key/global eviction order (oldest evicted first); idle timeout (**MockClock**, following the P0-1 test shape) over both the lazy and sweep paths; the backoff curve (1s->30s capped, reset on success); the stale one-shot redial (redial failing again -> Err, no third try); reuse_ratio computation;
- **factory**: two `connector()` calls with the same (skip, alpn) share the same underlying `Arc` (ptr_eq); different keys, different instances; alpn trim/empty-item filtering (aligned with the existing tls.rs behavior);
- **connectors (None/Some both states)**: the pool=None path is isomorphic to today byte for byte (mock-egress comparison assertion, the D-9 off-state proof); the Some path's acquire -> bind -> relay sequencing.

### 8.2 Integration (loopback, no privileges -- unlike the TUN series, no skip guard needed)

- **Main acceptance scenario**: mock trojan TLS server (self-signed cert: rcgen dev-dep or an embedded static PEM, one of the two chosen at implementation time and recorded in §10) + `egress_pool: {enabled: true}` -> N=10 serial same-target requests -> assert `acquires{hit}>=9`, `{miss}<=1`, `reuse_ratio>=0.9`, **foreground dial count increment <=1** (criteria 1/2);
- **Session resumption**: two dials through the same factory -> the second `handshake_kind() == Resumed` (direct assertion via the public API, §2.4; comparing the server-side handshake byte count is an optional cross-check);
- **Off-state comparison**: the same scenario with `enabled: false` (no block) -> foreground dials = N, no `rillane_pool_*` series, behavior consistent with the mainline baseline (criterion 4);
- **stale**: the server actively closes an idle connection -> the next request counts `stale_redial` +1 and succeeds (E3);
- **Hot reload**: switching the egress server triggers the :933 path -> new requests dial the new key, old-key entries reclaimed by idle timeout (short-timeout config + MockClock or a real wait); the pool singleton is not rebuilt (instance ptr assertion, warmth survives).

### 8.3 Gates

- Everything is loopback unit-testable, no privilege dependency (runs in normal CI); whole-repo baseline (118 items at the P0-3 point + later increments) with zero regressions -- this item is additive, and the None path changes no existing behavior (§2.6);
- The off-state comparison assertions must exist (otherwise "zero difference" is unprovable, same discipline as P1-4 E11).

## 9. Step-by-step implementation checklist (M0-M5)

Commit cadence follows the hard rule of P0-4 §9.1.1 / tun-dataplane §5: each step `cargo build` + `cargo test` fully green -> a single commit (referencing the §section of this document) -> `git fetch origin main` + rebase -> push -> next step; no tag/release/force push.

> **Landing note (2026-10-02)**: M0-M5 have all landed (M0 `0ecb477` / M1 `d1d0478` / M2 `97dbdf7` / M3 `1e90d04` / M4 `54df7cc` / M5 this commit); implementation-period deviations are recorded item by item in §10-11..§10-17; the gate baseline `cargo test --workspace --all-features` is 259 items fully green.

| Step | Content and landing point | Depends on | Acceptance |
|----|-----------|------|------|
| M0 | rillane-protocols `pool.rs`: `PoolPolicy`/`TransportKey`/`TransportPool` (acquire/acquire_fresh/watermark refill/idle sweep/eviction/backoff/counting/LeaseGuard) + `tls.rs` `TlsConnectorFactory` (shared ClientConfig + `in_memory_sessions` + HandshakeKind counting) | — | 8.1 pool core and factory fully green |
| M1 | rillane-config: `EgressPoolBlock` + deny + validate + `RillaneConfig.egress_pool`; rillane-runtime: `to_pool_policy()` (D-8 mapping) | M0 | 8.1 schema/conversion fully green; old configs zero difference |
| M2 | Connector onboarding: trojan/http/vless/direct(opt-in) constructor signatures gain two `Option`s, the forward dial site switches to acquire + the stale one-shot redial (the None path = old behavior) | M0 | 8.1 connectors fully green in both states; existing egress tests zero regressions |
| M3 | Assembly and hot reload: build() constructs pool/factory, `build_egress_outputs` gains parameters (the three call sites :158/:720/:933), Runtime holds + getters, tail-of-assembly warm() | M0-M2 | 8.1 assembly both states; hot-reload key self-invalidation and singleton survival assertions |
| M4 | Control plane + acceptance script: `/metrics` rendering + `GET /egress/pool/stats` + the statistics script (the three §0.2 groups) + the full §8.2 integration set | M3 | 8.2 fully green; criteria 1-3 reproducible |
| M5 | Documentation backfill: the connection-pool rows of the PROTOCOLS.md master table/performance section, roadmap S2/S3 progress, todo check-off, this document's §10 deviation backfill | M0-M4 | P1-5 acceptance table cross-checked item by item (§0.2) |

## 10. Deviations and assumptions (self-made assumptions where information was missing are all noted)

| # | Type | Content |
|---|------|------|
| 1 | Ruling | Pool shape = pre-establish + checkout-is-consumption with no return (derived from the §1.2 structural constraint; no fake "return for reuse"); total dials ~= flow count is honestly written into the acceptance criteria (the §0.2 note) |
| 2 | Ruling | Key = transport identity, not the egress name (D-2); key collisions are semantically equivalent and harmless |
| 3 | Ruling | Policy/execution separation + zero trait changes (D-3/D-4, methodology aligned with P1-4 §2.1; `ConnectorFlowOutput`/`FlowOutputRouter` untouched) |
| 4 | Verification | Resumption root cause = the per-flow new ClientConfig letting the default session cache die with the flow (rustls 0.23.35 source: `Resumption::in_memory_sessions` is the default policy); observability goes through the public `handshake_kind()` -- both verified against the Cargo.lock-pinned source, not speculation |
| 5 | Ruling | Capability matrix MVP = trojan/http/vless + direct opt-in (D-6); socks5/ss stay out of the MVP because the crate merges dial+bind (tokio_socks/shadowsocks public APIs have no external stream injection point -- judged from the public surface; if an injection point turns up at implementation time it upgrades smoothly, no blockage) |
| 6 | Ruling | Pool/factory as process-level singletons shared across hot reloads; parameter changes take effect on restart (D-10, precedent network-route O-hot) |
| 7 | Ruling | `connection_pool_size` adopted as the global capacity default (D-8) -- the orphan field's first consumer; still zero consumption zero behavior in the off state |
| 8 | Ruling | stale = one-shot foreground redial, no active probing (D-11): actively reading on a pre-established connection has a consumption-boundary ambiguity (TLS post-handshake messages), and retry covers the same scenario at lower complexity |
| 9 | Assumption (closed) | How integration tests generate self-signed certs -> **implementation chose the rcgen dev-dep** (`generate_simple_self_signed` + rustls-pemfile parsing, M4 `54df7cc`; from 2026-10-10 rustls-pemfile is out of the tree per RUSTSEC-2025-0134, parsing switched to the rustls-pki-types `PemObject`); the concurrent acceptance surface (criteria 1-3 in serial form) is now reproducible |
| 10 | Assumption (partially closed) | The bounded concurrency of prewarm/refill dials is guaranteed by the per-key invariant (§5.2); no global dial rate limiting -- serial acceptance has passed (M4); true-concurrency stress tests depend on real egress traffic shapes, which this repo's loopback integration tests do not construct; the R-pool3 observability surface (dials/idle/leased gauges) is in place, registered as pending verification during a real-traffic period |
| 11 | Deviation | §6.2 `keys[]` carries no per-key `leased`: under D-1 checkout-is-consumption, leased is accounted in the global gauge (`rillane_pool_leased_connections`); per-key leased has no operational action, and `KeySnapshot{key,idle}` is the final shape (M4) |
| 12 | Deviation | `acquire_bound`'s bind closure takes the boxed `FnMut(&mut dyn IoStream) -> Pin<Box<dyn Future>>` form rather than `AsyncFnMut`: the current rustc (1.99) does not generalize async closures over HRTBs ("AsyncFnMut is not general enough"); a boxed future + `&mut dyn` (not `&mut BoxedIo` -- the Box's inner 'static is fixed) is the stable idiom (same shape as tower services, M2) |
| 13 | Ruling | direct gets no stale one-shot redial: the bind semantics = first write first read; direct has no protocol handshake phase -> no stale detection point; a dead idle connection surfaces as a flow error, backstopped by idle_timeout (stated in an M2 comment) |
| 14 | Deviation | warm prewarm + the periodic sweeper hook `Runtime::start()` rather than `build()`: build() is synchronous assembly with no tokio context, and spawn/prewarm require the runtime in place (M3) |
| 15 | Bug fix | Implementation exposed a latent production bug in the existing egress TLS crashing on the first dial: after the dependency-graph feature unification, rustls held both the ring and aws_lc_rs features, and `ClientConfig::builder()` panics at runtime under the dual-provider ambiguity (rustls crypto/mod.rs) -- fix = an explicit OnceLock in `tls.rs` installing the ring default provider + `builder_with_provider` construction (M0); the mock server does the same (M4 tests) |
| 16 | Deviation | Refill-dial failure backoff + bounded retry: a `spawn_fill` round makes at most `MAX_FILL_ATTEMPTS=5` attempts (exponential backoff from 1s capped at 30s, reset on success), preventing a spinning dial storm when the server stays unreachable (M0) |
| 17 | Observability note | rustls treats a bare EOF without close_notify as `UnexpectedEof` (strict validation, 0.22+ behavior): `copy_bidirectional` ends with Err -- the existing inlined path has the same shape, not introduced by pooling; real trojan/http upstreams generally send close_notify, and the mock server explicitly shuts down at the end to send close_notify (M4 test note) |
| 18 | Deviation | Later extension of the capability matrix: the vmess egress landing (2026-10-02) passes through with the pool -- the runtime_builder Vmess arm injects transport_pool + tls_factory same as trojan/vless, and §0.1/§2.5/D-6 have been re-judged in sync; socks5/ss remain an extension, not pooled (the crate merges dial+bind) |

## 11. Risks and open items

- **R-pool1 (core)**: pre-established connections half-open or closed by middleboxes/servers (dead within the idle window) -- `idle_timeout_secs=30` (below common server idle caps) + the stale one-shot redial as the backstop; the stale rate is visible via `acquires_total{stale_redial}`, and past a threshold the operator should lower the per-key cap or shorten idle;
- **R-pool2**: direct's speculative pre-dials create "unrequested connections" to targets (optics close to scanning, consuming the server's connection quota) -- off by default (`pre_dial_direct=false`); whoever enables it bears this explicitly;
- **R-pool3**: concurrency races in checkout/reclaim (gauge and capacity accounting) -- atomic counters + re-check inside the lock window; concurrency stress testing follows the P0-1 shape (M0);
- **R-pool4**: pooling changes the connection-request timing (the connection exists before the request) -- no protocol difference for trojan/http/vless servers (the first bytes are still the protocol header); timing-correlation analysis from a DPI perspective belongs to the obfuscation-layer discussion, not claimed by this item;
- **O-pool1**: mesh hop dial reuse (`connect_next` shape-compatible: key = hop address, the MeshEnvelope first write is the binding) -- non-commitment, to be discussed when a need appears;
- **O-pool2**: socks5/shadowsocks onboarding (same vless shape after verifying the crate's external stream injection point);
- **O-pool3**: ~~`rillanectl pool status` subcommand~~ (**landed 2026-10-11**:
  `rillanectl pool status` -- the CLI fetch surface of `GET /egress/pool/stats`,
  rendering the switch/TLS resumption/reuse ratio/counter family
  (hit/miss/stale_redial/dials) and per-key idle; with the block disabled =
  `enabled:false`, the zero-value shape still renders);
- **O-pool4**: hy2/QUIC session reuse (designed together with V2 multiplexing; this item's explicit other half of the answer to not reducing total connections).
