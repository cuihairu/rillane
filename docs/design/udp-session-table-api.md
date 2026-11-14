# P0-1 Interface draft: UDP session table API and reclaim algorithm

> Status: **implemented (todo P0-1 complete, 2026-09)** - implementation surface = `crates/rillane-core/src/udp/` (differences between the draft signatures in §2.2 below and the implementation are adjudicated by the §9 table) - design basis: [udp-session-table.md](udp-session-table.md) (this document does not re-argue, it only gives transcribable API/algorithm) - overall design: [udp-dataplane.md](udp-dataplane.md) - relay path contract: [udp-relay-path.md](udp-relay-path.md) §4 - corresponding [todo.md](../../todo.md) P0-1
> Assumptions (if they conflict with the implementation this draft needs to be revised back): A1 time base uses process monotonic clock seconds (avoids NTP jumps); A2 downlink channel capacity 64 follows udp-relay-path.md §4.3; A3 `FlowSession` structure unchanged (O7 goes through a wrapper, see §4.4); A4 metric naming follows [udp-observability.md](udp-observability.md) §2.4 (finalized at landing).

## Executive summary

Give the **complete public API draft** of `rillane-core::udp`: module layout and visibility, all signatures of `UdpSessionTable`/`SessionRef`/`SessionLedger`, transcribable pseudocode for timeout reclaim (epoch time base + double-confirmation removal + teardown outside the lock), concurrency lock order and memory order contracts, test clock injection. Goal: during implementation you can transcribe signature by signature from this draft, and look back at udp-session-table.md for the design trade-offs in the corresponding section.

## 1. Module layout and visibility

```
crates/rillane-core/src/udp/
├── mod.rs          # pub use public surface; module docs (summary of this document)
├── key.rs          # UdpSessionKey / ProcessIdentity          (all pub)
├── config.rs       # UdpSessionConfig + Default + validate     (pub)
├── table.rs        # UdpSessionTable / SessionRef / ResolveError / UpResult (pub)
├── inner.rs        # UdpSessionInner / UdpMapping / UdpBinding (pub(crate), except Binding)
├── ledger.rs       # SessionLedger (§4, pub -- both ingress/egress need bookkeeping)
├── reclaim.rs      # reclaim task (pub(crate); spawn entry is pub)
├── metrics.rs      # TableMetrics / TableSnapshot (pub)
└── clock.rs        # Clock trait + RealClock (pub) / MockClock (cfg(test))
```

Dependency direction: `table -> inner/ledger/reclaim/metrics`; `reclaim -> inner`; no cycles. `UdpBinding`'s `Relay(Box<dyn UdpRelay>)` needs `UdpRelay` (udp-dataplane.md §1.2) -- the trait definition stays in `rillane-core::udp`, avoiding a reverse dependency from protocols back to runtime.

## 2. Public API draft

### 2.1 Config and key

```rust
pub struct UdpSessionConfig {
    pub mapping_idle: Duration,        // default 60s
    pub session_idle: Duration,        // default 180s
    pub sweep_interval: Duration,      // default 15s
    pub max_sessions: usize,           // default 4096
    pub max_mappings: usize,           // default 256/session
    pub session_max_lifetime: Option<Duration>, // default None
    pub downlink_capacity: usize,      // default 64 (A2)
}
impl UdpSessionConfig { pub fn validate(&self) -> Result<()>; }  // 0 < idle relationship checks

pub struct UdpSessionKey {
    pub client: SocketAddr,            // baseline, always present
    pub user: Option<String>,          // lowercased before participating in hash
    pub process: Option<ProcessIdentity>,
}
pub struct ProcessIdentity { pub pid: u32, pub name: String }
// derive Clone/Eq/Hash; Hash uses all fields (a dimension being present is a differentiator, udp-session-table.md §3.1)
```

### 2.2 UdpSessionTable

```rust
pub struct UdpSessionTable { /* DashMap + AtomicUsize live_count + config + metrics + clock */ }

impl UdpSessionTable {
    pub fn new(config: UdpSessionConfig, metrics: Arc<TableMetrics>, clock: Arc<dyn Clock>) -> Self;

    /// Per-packet entry (fast path first): hit->Sent; miss->Miss (caller switches to resolve, or gives up)
    pub async fn forward_up(&self, key: &UdpSessionKey, target: &FlowTarget, data: Bytes) -> UpResult;

    /// Slow path: on miss, route decision and create session + first mapping; full->Err(CapacityLimited)
    pub async fn resolve(
        &self,
        key: UdpSessionKey,
        ctx: FlowContext,                 // first-packet target
        router: Arc<dyn FlowRouter>,
    ) -> Result<SessionRef, ResolveError>;

    /// ASSOCIATE control connection close and other forced reclaims (udp-relay-path.md §2.5); returns whether that session actually existed and was removed
    pub fn force_revoke(&self, key: &UdpSessionKey) -> bool;

    /// Link failure event source (ChainManager), drives decision cache invalidation (udp-session-table.md §3.4)
    pub fn attach_chain_events(self: &Arc<Self>, rx: mpsc::Receiver<ChainFailureEvent>);

    /// Start the periodic reclaim task (sweep_interval; single task, repeated calls are no-op)
    pub fn spawn_reclaimer(self: &Arc<Self>) -> JoinHandle<()>;

    /// /flows and rillanectl stats snapshot
    pub fn snapshot(&self) -> TableSnapshot;
}

pub enum UpResult { Sent, Miss, Dropped { reason: DropReason } }
pub enum DropReason { SessionLimit, MappingLimit, NoBinding, ShuttingDown }
pub enum ResolveError { CapacityLimited, Route(anyhow::Error) }   // Route does not retry (decision failure follows existing route error semantics)

/// Handle returned by a successful resolve: Arc inner + convenience methods; cheap to clone
#[derive(Clone)]
pub struct SessionRef { inner: Arc<UdpSessionInner> }
impl SessionRef {
    pub fn ledger(&self) -> &SessionLedger;
    pub fn key(&self) -> &UdpSessionKey;
    pub fn decision(&self) -> Arc<RouteDecision>;   // sticky decision read-only view
    pub fn id(&self) -> FlowId;                     // also serves the mesh envelope flow_id
}
```

- `forward_up` is a **synchronous fast path**: on a hit it does not enter async (send directly inside the lock, `UdpBinding::Local` is an already-connected socket; `Relay` goes through the synchronous wrapper of `UdpRelay::send_to` -- both QUIC/socket direct sends are non-blocking);
- On a miss it returns `Miss`, leaving the decision to the caller: ingress can choose to drop the small packet (e.g. a probe before a game's first packet) or go through `resolve`, avoiding hiding the slow path inside the table.

### 2.3 Snapshot

```rust
pub struct TableSnapshot {
    pub sessions_active: usize,   pub sessions_total: u64,
    pub mappings_active: usize,
    pub dropped: BTreeMap<DropReason, u64>,
    pub expired: BTreeMap<ExpireReason, u64>,
    pub reroutes: u64,            // decision-invalidation re-route count
    pub sessions: Vec<SessionSnapshot>,   // per session: key (after masking), age, idle, mapping count, usage summary
}
pub enum ExpireReason { Idle, Lifetime, Revoked }
```

## 3. Timeout reclaim algorithm (transcribable pseudocode)

### 3.1 Time base

`last_activity: AtomicU64` = **process monotonic clock seconds** (`clock.now_epoch()`, A1; RealClock is based on an `Instant` origin, MockClock can be adjusted). Use the `Relaxed` order -- single-value freshness, no cross-variable ordering dependency (§5.2). `created_at_epoch: u64` is on the same base, for lifetime cap judgment.

### 3.2 sweep main loop

```
fn sweep(self, now: u64):
    expired: Vec<(UdpSessionKey, Arc<Inner>)> = []
    for shard in self.sessions.shards():
        # read lock only for judgment, no removal
        for (key, inner) in shard.read().iter():
            idle = now - inner.last_activity.load(Relaxed)
            if idle * 1s >= config.session_idle
               or (lifetime enabled and now - inner.created_at_epoch >= lifetime):
                expired.push((key.clone(), inner.clone()))
    removed = 0
    for (key, inner) in expired:
        # DashMap::remove is atomic; the one that wins executes teardown (double-confirmation semantics, prevents concurrent duplicate reclaim)
        if let Some((_, inner)) = self.sessions.remove(&key):
            self.teardown(inner, ExpireReason::Idle_or_Lifetime)
            removed += 1
    self.metrics.set_active(self.live_count.load(Relaxed))
    # mapping-level reclaim is lazy during resolved/forward_up + a light sweep inside sweep (§3.3)
```

- **Double confirmation**: the atomicity of `remove` naturally guarantees that the same session is only truly reclaimed by one sweep iteration; `force_revoke` goes through the same `remove + teardown` path, `ExpireReason::Revoked`;
- **No batch cap**: remove/teardown per item is microsecond-scale and does not hold the read lock (see §3.3), even 4096 items worst case in one round is millisecond-scale; the sweep interval can optionally add +/-10% jitter to avoid aligning with other periodic tasks (not required, default off).

### 3.3 Mapping-level reclaim

```
fn sweep_mappings(inner: &Inner, now: u64):
    dead: Vec<FlowTargetKey> = []
    mappings.lock():
        for (k, m) in cache.iter():
            if now - m.last_activity_epoch >= mapping_idle: dead.push(k)
        for k in dead: cache.pop(&k)            # inside the lock only remove from the table
    for k in dead: teardown_binding(inner.take_binding(k))   # outside the lock close socket/relay (§5.1)
```

Inside the lock only do table operations; IO cancellation (drop binding, the forwarder task exits when the Sender closes) always happens outside the lock -- a mandatory item of the lock order contract (§5.1).

### 3.4 teardown (the reclaim action, the functionalization of udp-session-table.md §4.5)

```
fn teardown(inner: Arc<Inner>, reason: ExpireReason):
    inner.downlink_tx.close()        # 1) close the downlink first -> forwarder exits naturally one by one
    inner.take_all_bindings()        # 2) take the bindings (drop = close)
    inner.ledger.snapshot() into logs    # 3) terminal snapshot (optional debug level)
    metrics.expired[reason] += 1; live_count -= 1    # 4) metrics
```

In-flight packet safety: the `SessionRef` issued by `resolve` holds an `Arc`, after teardown its send lands on an already-closed binding -> returns `UpResult::Dropped{NoBinding}`, the caller handles it as a lost packet (UDP semantics, no exception path).

### 3.5 Admission control

The `resolve` slow path first reads `sessions.len()` directly (DashMap length, `table.rs:180`) >= `max_sessions` -> `Err(CapacityLimited)` (corresponding metric `dropped{SessionLimit}`, reject new without evicting old). The draft's independent `live_count` atomic **was not implemented**: the capacity gate reads the actual length directly, under the soft-gate semantics of a sharded map a concurrency window allows tiny oversell (§9-#12/#15), the active accounting is maintained by the `TableMetrics` atomic.

## 4. FlowSession integration interface draft (SessionLedger)

### 4.1 Single write entry

`FlowSession` methods have side effects (`update_route` sets Active, `record_failure` sets Failed); direct calls from multiple points easily break invariants. **All writes go through `SessionLedger`**:

```rust
pub struct SessionLedger { session: RwLock<FlowSession>, chain: Mutex<Option<ChainContext>> }

impl SessionLedger {
    /// Constructed only inside the table: FlowSession::new(FlowId::new(), ctx.target.clone()) + client_info fill
    pub(crate) fn create(key: &UdpSessionKey, ctx: &FlowContext, auth: Option<AuthInfo>) -> Self;

    /// Per-packet bookkeeping: usage.update_usage(bytes) + usage.packets_count += 1
    ///   + last_active refresh + (O7 rule) Failed -> Active recovery
    pub fn on_packet(&self, dir: Dir, bytes: u64);

    /// Decision change (not called on the first packet; called during link migration): update_route(path, reason) + RouteHistory(success=true)
    pub fn on_route_changed(&self, path: Vec<String>, reason: String);

    /// Link failure migration: RouteHistory(success=false, error=cause) + reconnect_count += 1
    ///   + ChainContext.switch_fallback_path() (when a candidate exists), returns the new path for the table to update CachedDecision
    pub fn on_link_failure(&self, failed_path: &[String], cause: &str) -> Option<Vec<String>>;

    /// relay error bookkeeping: record_failure(f) (will set Failed -- the recovery rule is in on_packet, §4.4/O7)
    pub fn on_error(&self, f: FailureType);

    /// Hang context when a chain decision is created: ChainContext::new(chain_id, source, target)
    pub fn attach_chain(&self, cc: ChainContext);

    pub fn snapshot(&self) -> FlowSession;            // Clone for diagnostics/snapshots
    pub fn usage(&self) -> SessionUsage;
}
```

### 4.2 Cooperation timeline with the table

```
First packet: resolve -> router.route(ctx) -> create ledger -> (Chain?) attach_chain
      -> mappings creates mapping -> ledger.on_packet(Up, len)
Migration: chain event -> table clears CachedDecision -> next packet re-routes -> decision changes
      -> ledger.on_link_failure(old_path, cause) gets the fallback new path
      -> on success ledger.on_route_changed(new_path, "chain-failover")
Error: binding send/recv Err -> classify (udp-relay-path.md §3.6) -> ledger.on_error(FailureType::*)
```

Implementation note (§9-#16): `on_link_failure` in practice only does `on_error(FailureType::Route)` and **returns `failed_nodes` as-is** (`ledger.rs:63-73`), does not switch fallback -- `add_fallback_path`/`switch_fallback_path` have no call site on the UDP surface, re-routing after a link failure is driven by the runtime-side ChainFailureEvent (next packet re-routes -> `on_route_changed`); the draft's `reconnect_count += 1` has no corresponding increment point (the field is only pass-through).

### 4.3 Field mapping (continuing udp-session-table.md §5.2, API landing point)

`client_info.address` <- key `client`; `auth_info` <- ASSOCIATE auth result; `id` -> mesh envelope `flow_id`; `usage.packets_count` is maintained in `on_packet` (`update_usage` does not overwrite); `current_path`/`route_history` only change via `on_route_changed`/`on_link_failure`.

### 4.4 O7 wrapper semantics (the only "behavior change" in this draft, no source structure change)

At the start of `on_packet`: `if session.status == Failed { session.status = Active }` -- Failed only serves as an observational signal that "an error has occurred since the last successful packet", it does not terminate the session. If the upstream later accepts a recoverable Failed semantics (O7), deleting these three lines suffices, no other migration.

## 5. Concurrency contracts

### 5.1 Lock order (mandatory, violating the order means deadlock risk)

```
DashMap shard (read, for judgment, shortest)  ->  inner.mappings Mutex  ->  ledger RwLock/Mutex
```

- No path may reverse the order; all IO operations of teardown/sweep_mappings are outside the lock (§3.3);
- `force_revoke` and sweep compete for the same session: `DashMap::remove` atomicity arbitrates, the loser gets None and returns directly.

### 5.2 Memory order

| Variable | Order | Rationale |
|------|-----|------|
| `last_activity` / `created_at_epoch` | Relaxed | Single-variable freshness judgment, no cross-variable ordering |
| `live_count` (draft, not implemented) | -- | In practice there is no independent atomic: the capacity gate reads `sessions.len()` directly, the soft gate allows drift (§9-#15) |
| `decision` / `ledger.session` | RwLock default | Needs to be mutually visible with mapping changes, standard synchronization |

### 5.3 Task lifecycle

The forwarder task holds `Arc<Inner>` + its own half of the `UdpBinding`; teardown first `downlink_tx.close()` then drops the bindings -> the task exits at the next recv Err/None, no abort required. Table close (process exit path): `force_revoke` the entire table before dropping the table (called by the `RuntimeBuilder` shutdown sequence, ordered after the mesh data-plane stops).

## 6. Test hooks

- `Clock` trait (`now_epoch`) + `MockClock`: manually advance seconds, **all timeout-class acceptance becomes deterministic** -- no sleeping through real time;
- `TableMetrics` counter direct-read assertions (no Prometheus text parsing);
- `UdpRelay` provides `MockRelay` (programmable send/recv Err sequences) driving §3.6/udp-relay-path.md §3.6 error classification tests.

## 7. Acceptance mapping (P0-1 original text -> landing points in this draft)

| Acceptance | Landing point in this draft |
|------|---------|
| Session create/query/timeout reclaim has unit tests | `resolve`/`forward_up` + MockClock-driven sweep (§3.2/§6); the five-item test checklist is in udp-session-table.md §7 |
| The same sticky key reuses a mapping without rebuilding | `forward_up` hit path `Sent` and `snapshot().mappings_active` unchanged; decision generation unchanged |
| (In design) full capacity rejection | §3.5 `CapacityLimited` + `dropped{SessionLimit}` |
| (In design) decision invalidation | `attach_chain_events` + `on_link_failure` migration timeline (§4.2) |

## 8. Boundaries and connections

- This draft is a **P0-1 single-item interface draft**; the egress-side contracts of `UdpRelay`/`EgressUdpConnector` and SOCKS5 ingress parsing are in [udp-relay-path.md](udp-relay-path.md); mesh inter-hop flow caching reuses this table's `last_activity` constants but **does not share a table instance** (the relay side has no route decision, an independent light table, given during P0-4 implementation);
- If the implementation finds a signature does not fit (e.g. `forward_up` synchronization is not feasible -- `Relay` egress needs async send), it is allowed to relax to `async fn forward_up`, but §5 lock order and the outside-the-lock IO principle are non-negotiable;
- After this document is complete, the three-document chain for P0-1: overall design (udp-dataplane.md §1) -> design basis (udp-session-table.md) -> **interface draft (this document)**.

## 9. Implementation notes (P0-1 landing adjudication, code in `crates/rillane-core/src/udp/`)

Deviations and clarifications from the draft during implementation, all adjudicated per the relaxation license in §8; lock order and outside-the-lock IO untouched:

| # | Draft | Implementation | Adjudication rationale |
|---|------|------|---------|
| 1 | `forward_up` synchronous | `async fn forward_up` (§8 already reserved) | `UdpRelay::send_to` is async; slow path as before |
| 2 | `UdpBinding` enum (Bound/Ephemeral) | Unified `Arc<MappingShared>` (with close watch + four atomic counters) | The draft's two-state "no-relay temporary state" does not exist in the implementation: a mapping creation must first have a relay, the enum degenerates |
| 3 | `MappingShared.relay: Box<dyn UdpRelay>` | `Arc<dyn UdpRelay>` | forwarder task and send path share ownership, Box would need an extra registry reclaim |
| 4 | Added `SessionRef::{bind_mapping, send_up, has_mapping, take_downlink_rx}` | Same-name landed | Needed for slow-path wiring after a fast-path `Miss` (socks5 handler / egress association) |
| 5 | Added `UdpSessionTable::get/get_shared` | `get(&key) -> Option<Arc<UdpSessionInner>>` (does not create) | Implicit creation consolidated into `resolve`'s capacity gate, `forward_up` is strictly read-only |
| 6 | `DropReason` 4 classes | Added `SendFailed`/`DownlinkFull` for 6 classes | Uplink send failure (mapping revocation + re-association) and downlink channel full (UDP has no backpressure) need independent counts |
| 7 | teardown dual path (send failure removes on the spot / forwarder exit removes) | **Single-point convergence**: send failure only `close()` signals, removal + count decrement unified at the forwarder exit path (`Arc::ptr_eq` prevents accidentally removing a replaced new mapping) | Eliminates dual-path count drift and the "removes the replacement mapping" race (found during implementation) |
| 8 | `reroutes` accounting undetermined | Non-first decision count within a session (`Inner.decisions` atomic) | The first route does not count as a re-route; +1 for re-routing after a link failure |
| 9 | Chain ID accounting | `chain_id_of(decision)`: `direct:{node}` / `group:{group}` / `chain:{hops.join("->")}` | The runtime-side ChainManager must map to the same string (P0-2 wiring point) |
| 10 | `sweep` boundary undetermined | Strictly greater than (`idle > limit`, boundary value survives) | MockClock boundary unit test pinned (sweep_session_idle_expiry_boundary) |
| 11 | `TargetProto` derive | Added `Copy + PartialEq + Eq + Hash` (existing type in lib.rs) | `FlowTargetKey` needs to be a HashMap key; pure derive extension, no semantic change |
| 12 | Capacity judgment inside DashMap entry | Capacity judgment moved before `entry()` | Calling `len()` while the entry holds a shard write lock risks a same-map deadlock (found during implementation); the concurrency window allows tiny oversell (soft-gate semantics) |
| 13 | `force_revoke` no return value | `pub fn force_revoke(&self, key) -> bool` | The ASSOCIATE close path needs to distinguish "truly reclaimed" from "session already gone", returns a boolean existence |
| 14 | `attach_chain_events(&self, ...)` | `pub fn attach_chain_events(self: &Arc<Self>, ...)` | The event consumer task needs to hold a table weak/strong reference across await, a bare `&self` reference cannot `Arc::clone` into a task |
| 15 | Independent `live_count` atomic (§3.5 admission control) | No such variable: the capacity gate reads `sessions.len()` directly (`table.rs:180`), active count = `TableMetrics` atomic | An independent count naturally drifts from the DashMap length, needing periodic sweep reconciliation; direct read is zero maintenance cost, the soft-gate semantics (§8 relaxation) allows tiny oversell within a concurrency window |
| 16 | `on_link_failure` switches fallback + `reconnect_count += 1` (§4.1/§4.2) | Only `on_error(FailureType::Route)` + returns `failed_nodes` as-is (`ledger.rs:63-73`) | Fallback switching belongs to the TCP `add_fallback_path` surface (UDP has no call site); UDP re-routing is driven by the runtime-side ChainFailureEvent re-routing the next packet; `reconnect_count` has no increment point |

Test anchors: `crates/rillane-core/tests/udp_session_table.rs` (**26 items**: lifecycle 2, fast path and mapping reuse 3, timeout reclaim 4, capacity and LRU 2, decision invalidation and re-routing 1, revocation/shutdown 2, uplink failure and downlink full 5, concurrency contracts 2, ledger direct tests 3, chain_id accounting 1, table-level aggregation 1).
