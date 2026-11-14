# P0-1 implementation-level design: rillane-core NAT-style UDP session table

> Status: **Landed (todo P0-1 complete, 2026-09)** · This document expands [udp-dataplane.md](udp-dataplane.md) §1 and is that item's implementation framing · Maps to [todo.md](../../todo.md) P0-1 · Upstream: [roadmap.md](roadmap.md) S1 · Gap origin [positioning.md](positioning.md) G1
> Implementation surface = `crates/rillane-core/src/udp/` (`table.rs`/`inner.rs`/`reclaim.rs` etc.) · Interface draft (transcribable signatures/algorithm pseudocode): [udp-session-table-api.md](udp-session-table-api.md) (implemented; differences are authoritative per §9).
> The design text is preserved; implementation differences and the real metric state are in the api draft §9 and [udp-observability.md](udp-observability.md) §2.4.

## Executive Summary

Gives the implementation-level design of the UDP session table in the `rillane-core::udp` module: a **two-level mapping** (global session table → in-session target mappings) carries the NAT semantics; the **sticky key** degrades by the priority process > auth user + five-tuple > five-tuple > source IP; **timeout reclaim** uses a single-task periodic sweep (mappings 60s / sessions 180s / sweep 15s) and refuses new rather than evicting old when full; integration with `FlowSession` is by **composition**, field by field, handling two existing semantic differences (`record_failure` setting Failed, `new()` discarding the target parameter). The end gives the test checklist aligned with the todo P0-1 acceptance.

## 1. Conceptual model: three identities

| Identity | Meaning | Lifetime | TCP-plane counterpart |
|------|------|---------|------------|
| **Client Identity** (sticky key) | who is sending: process / auth user / client address five-tuple | ASSOCIATE established to timeout | the connection peer on `Flow.io` |
| **Flow Target** | where to send: `FlowTarget{host, port, proto}` | each target mapping independent | `Flow.target` (one to one) |
| **Upstream Binding** | via whom: a relay handle bound to an egress | the target mapping's idle timeout | `Flow.io` itself |

The TCP plane unifies the three into one `Flow` (`Flow{id, target, io: BoxedIo}`, see [architecture.md](../architecture.md) key interfaces); the essential UDP difference is 1 : N : N -- one client identity maps to many targets simultaneously, and each target to one independent binding. The session table is what models this 1:N:N relation explicitly.

## 2. Mapping structure: a two-level table

### 2.1 Structure definition (`rillane-core::udp`, refined from udp-dataplane.md §1.2)

```rust
/// Level-1: the global session table (concurrently sharded)
pub struct UdpSessionTable {
    sessions: DashMap<UdpSessionKey, Arc<UdpSessionInner>>,
    config: UdpSessionConfig,       // §4 constant table
    stats: UdpTableStats,           // atomic counters: active/total/dropped{reason}
}

/// Level-2: in-session target mappings (bounded LRU)
pub struct UdpSessionInner {
    pub key: UdpSessionKey,
    pub decision: RwLock<CachedDecision>,   // sticky decision cache (§3.4)
    pub mappings: Mutex<LruCache<FlowTargetKey, UdpMapping>>,   // default 256
    pub downlink_tx: mpsc::Sender<DownlinkPacket>,              // downlink channel (§2.3)
    pub session: RwLock<FlowSession>,                           // §5 integration
    pub last_activity: AtomicU64,       // epoch seconds; refreshed by a packet in either direction
    pub created_at: Instant,
}

pub struct UdpMapping {
    pub binding: UdpBinding,            // uplink binding
    pub last_activity: Instant,         // refreshed by either the uplink or the downlink direction
    pub bytes_up: u64, pub bytes_down: u64,
    pub pkts_up: u64, pub pkts_down: u64,
}

pub enum UdpBinding {
    /// direct egress: local UDP socket (already connected to the target)
    Local(UdpSocket),
    /// ss/hy2/wg/mesh egress: the handle produced by EgressUdpConnector::associate
    Relay(Box<dyn UdpRelay>),
}

pub struct DownlinkPacket {             // upstream → client direction
    pub target: FlowTarget,             // the source target (the client side needs it to wrap the SOCKS5 header)
    pub data: Bytes,                    // the bytes crate; reuses the workspace dependency
}
```

- `UdpSessionKey` / `UdpRelay` / `EgressUdpConnector` / `FlowContext` keep the shapes defined in udp-dataplane.md §1.2 and are not repeated here; the difference point is per the following §3 (sticky key refinement).
- **`FlowTargetKey`**: the hashable normalization of `FlowTarget` (the current `FlowTarget` contains a `String` host and is directly hashable; here the key semantics are fixed -- IP literals as text, domains as lowercase original strings, **no resolution expansion**, see O6).

### 2.2 Uplink fast path (per packet)

```
recv → hash(UdpSessionKey) looks up Level-1 (DashMap read lock)
     → mappings.lock() looks up/creates the Level-2 mapping (LRU; on hit, touch)
     → binding.send(data); atomic counter accumulation
```

Two critical sections (shard read + in-session Mutex) with no cross-session contention; the slow paths are only the three of "first packet creates a session / a new target creates a mapping / full refuses", each completed in one pass.

### 2.3 Downlink reverse lookup: no global reverse index

After upstream data arrives it must be sent back to the client. Option comparison:

| Option | Description | Conclusion |
|------|-----|------|
| Global reverse index `BindingId → SessionKey` | requires synchronized add/remove with Level-2, a double-write consistency burden | rejected |
| **per-mapping forwarder task** (adopted) | each mapping spawns one recv loop at creation, sending received packets along with their `target` into the session's `downlink_tx`; when a mapping is reclaimed the task ends naturally as the `binding` drops | the lifecycle follows the mapping, with no independent state |

The inbound side (socks5 relay) holds a `downlink_rx` and wraps each `DownlinkPacket` in a SOCKS5 UDP header before sending it back to the client. One session has one downlink channel, and many targets' downlinks converge onto the same mpsc -- naturally preserving single-client-socket semantics.

## 3. Sticky key: process / five-tuple priority

### 3.1 Key structure and priority

```rust
pub struct UdpSessionKey {
    pub client: SocketAddr,             // the five-tuple source (ip, port) -- the baseline, always available
    pub user: Option<String>,           // the socks5 auth username (AuthInfo.username)
    pub process: Option<ProcessIdentity>, // injected at P1 TUN; always None at P0
}

pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,                   // the executable name (shares a session across pid changes)
}
```

Matching priority (high → low), degrading by the **actually available information**; degradation does not change the key type:

1. `process + client` -- TUN inbound (P1-2 injection); the same process across restarts (a pid change) can be merged via `name`;
2. `user + client` -- socks5 with auth;
3. `client` -- unauthenticated socks5 (multiple clients behind one NAT are merged into a single session, i.e. upstream doc O1; known and accepted).

`PartialEq`/`Hash` compare all fields as a whole -- the process/user dimensions join the discrimination as soon as they appear, guaranteeing "two games on one machine = two sessions".

### 3.2 The source of the client five-tuple in the socks5 scenario

The ASSOCIATE control connection (TCP) and the UDP datagrams share a source: the MVP verifies **source IP** consistency per udp-dataplane.md §2.2's `strict_udp_source`; the session key takes the datagram source `(ip, port)`. The same client switching its source port (reconnecting the relay) counts as a new session -- the old session goes to timeout reclaim, with no migration (a boundary; see §8).

### 3.3 Sticky semantics and anti-patterns

- **First packet**: a table lookup miss → routing decision (`FlowRouter.route(FlowContext)`) → create the session and cache the `RouteDecision` → create the target mapping;
- **Later packets**: reuse the cached decision and mapping; **never reroute per packet** (a game session jumping links = a disconnect-and-reconnect; that is the anti-pattern);
- the decision cache carries `route_reason`, for metrics and `RouteHistory` recording.

### 3.4 Decision cache invalidation (landing upstream R2)

A single invalidation trigger source: subscribe to the link failure events broadcast by `ChainManager::handle_chain_failure` (an existing mechanism; see [mesh.md](../mesh.md)). Handling:

1. Walk the session table; for every session whose `CachedDecision.path` contains a failed node/link: clear the decision cache;
2. the next packet triggers rerouting → a new `RouteDecision` → `update_route` (§5) → migrate the mapping (the old binding closes and the LRU is replaced);
3. non-chain decisions are unaffected by link events and stay sticky until the session ends (whether to introduce TTL re-probing is in O5).

## 4. Timeout reclaim: state machine and parameters

### 4.1 Parameter table (`UdpSessionConfig`, from the `udp:` config block; see udp-dataplane.md §5.2)

| Parameter | Default | Note |
|------|------|------|
| `mapping_idle_secs` | 60 | the target mapping's idle ceiling (refreshed by either direction; game heartbeat intervals are far below this) |
| `session_idle_secs` | 180 | the session idle ceiling (= max(mapping.last_activity)) |
| `sweep_interval_secs` | 15 | the reclaim sweep period |
| `max_sessions` | 4096 | the global concurrent session ceiling |
| `max_mappings_per_session` | 256 | the per-session mapping ceiling (LRU capacity; overflow evicts the longest idle) |
| `session_max_lifetime_secs` | none (disabled) | an optional lifetime ceiling, off by default (long game sessions are not cut off) |

### 4.2 State transitions

```
first packet ──► Active ──(mapping_idle expiry evicts mappings)──► Active (mappings decreasing)
              │
              ├──(session_idle expiry)──► Expired (reclaim, §4.4)
              ├──(max_lifetime expiry, if enabled)──► Expired
              └──(relay error)──► demoted marker* (not terminal; a successful next packet returns to Active)
* The handling of the FlowSession.status=Failed semantic difference is in §5.3.
```

### 4.3 Reclaim algorithm: periodic sweep (the choice)

- **Adopted**: a single tokio task doing a full-table sweep every `sweep_interval` (following the existing `ChainManager::start_health_check_task` pattern). The cost of a 4096-entry sweep once every 15s is negligible (microsecond level per entry); no timer storm, and the smallest code size;
- **Rejected**: one sleep task per mapping / a Hierarchical Timing Wheel -- the ceilings are small and the complexity is not worth it;
- threshold judgments read an `AtomicU64` (`last_activity`) without a lock; the lock is taken only after confirming expiry to delete, keeping in-lock work low.

### 4.4 Full-capacity admission: refuse new, never evict old

Once `max_sessions` is reached: a new client's first packet is **dropped** and counted `rillane_udp_dropped_total{reason="session_limit"}`, and **active sessions are never evicted** (kicking a game offline is far worse than dropping a new session). Capacity planning should be tuned from observed metrics; automatic scaling is out of scope (non-goal).

### 4.5 Reclaim action list

When a session/mapping expires, run in order: ① drop the `UdpBinding` (the relay handle/socket closes; the §2.3 forwarder task exits with it); ② move the session out of Level-1; ③ close the `downlink` channel; after the inbound side notices, it cleans up the ASSOCIATE association state; ④ metrics: `rillane_udp_expired_total{reason=idle|lifetime|revoked}` increments and `rillane_udp_sessions_active` decrements. Reclaim sends no peer notification (UDP has no such semantics).

## 5. FlowSession integration (field by field)

### 5.1 Integration style: composition

`UdpSessionInner` embeds `session: RwLock<FlowSession>` (`FlowSession` is defined in `rillane-core::lib.rs`: `id/created_at/last_active/status/client_info/current_path/route_history/usage/failure_stats`). **The `FlowSession` structure itself is not modified** -- all integration goes through its existing methods, with zero impact on the TCP plane.

### 5.2 Field/method mapping table

| FlowSession member | UDP session table usage |
|-----------------|---------------|
| `id: FlowId` | `FlowId::new()` at session creation; also used as the mesh UDP envelope's `flow_id` (the 16B UUID in §4.2, echoing udp-dataplane.md §4.2) |
| `client_info.address` | filled with the sticky key's `client`; `auth_info` filled with the socks5 `AuthInfo{UsernamePassword, username}`; after P1, `node_id` is reserved for the TUN scenario |
| `last_active` | refreshed in-lock alongside `AtomicU64 last_activity` (the reclaim judgment uses the atomic value; this field is for observability/diagnosis) |
| `usage.update_usage(up, down)` | per-packet byte accumulation in both directions; **note on packet counts**: `update_usage` counts bytes only, so `usage.packets_count` needs a separate `+= 1` elsewhere (the field exists but the method does not cover it) |
| `update_route(path, reason)` | called when the decision cache changes (not on the first packet; called on failure migration); internally it pushes a `RouteHistory`, sets `Active`, and refreshes `last_active`, exactly carrying the migration record |
| `current_path` / `route_history` | synchronized with `CachedDecision` after migration; `RouteHistory{success=false, error}` records the failover reason (for the P2-1 failover-reason metrics) |
| `usage.reconnect_count` | `+= 1` after a successful link migration |
| `record_failure(FailureType::*)` | called on relay send/recv/binding errors; `Timeout` for an unreachable upstream, `Connection` for a bind failure -- the semantic difference is in §5.3 |
| `ChainContext` (associated via `current_path`) | when the decision is `RouteDecision::Chain`, construct `ChainContext::new(chain_id, source, target)` and hang it on the session cache; `add_fallback_path`/`switch_fallback_path` are used directly for failover candidates |

### 5.3 Two existing semantic differences (documented as-is and handled)

1. **`record_failure` sets `status = Failed`** (existing implementation behavior). Under TCP semantics Failed ≈ session terminated; under UDP, a single relay error (e.g. a transient egress packet loss) should not terminate the session. **Handling**: the UDP side resets `status` to `Active` when the next packet forwards successfully (the wrapper `UdpSessionInner::note_success()` handles it uniformly, keeping `failure_stats` for observability); whether it is worth adding "recoverable Failed" semantics to `FlowSession` upstream is listed as O7 and is not changed in P0-1.
2. **`FlowSession::new(id, _target)` currently discards the target parameter** (there is no target field). A UDP session's target set lives in the `mappings` key set, and `FlowSession` does not carry target storage -- this document states that as-is so the implementation does not mistakenly assume a target list can be queried inside a session.

## 6. Concurrency and memory budget

- **lock granularity**: DashMap shard read lock (session lookup) → in-session `Mutex<LruCache>` (mapping lookup/create) → the `binding`'s own IO. No shared mutable state between sessions; the per-packet critical section is a constant number of hashes plus microsecond-level operations;
- **throughput class**: 4096 sessions × 120 pps per session (game ceiling) ≈ 0.5M pps theoretical ceiling, far below DashMap's sharding capacity, so no lock-free structure is needed;
- **memory ceiling**: `max_sessions × max_mappings × (binding ~ a few hundred B + downlink channel buffer 64 × ~1.5KB)` ≈ 4096 × 256 × ~2KB ≈ **2 GiB worst-case ceiling** -- in practice 256 mappings/session is a generous quota for scanner/DNS-class clients, and a typical game session has ≤ 8 targets, so real usage is 1–2 orders of magnitude lower; load-test calibration is still recommended (upstream R1);
- **buffer reuse**: pooled send/recv buffers via `Bytes`/`BytesMut` (the workspace already has `bytes`), avoiding per-packet allocation.

## 7. Metrics and test checklist (aligned with the todo P0-1 acceptance)

Metrics (authoritative framing = [udp-observability.md](udp-observability.md) §2.4 landed final; the table below is synchronized to the real names):

```
rillane_udp_sessions_active / rillane_udp_sessions_total
rillane_udp_expired_total{reason=idle|lifetime|revoked}
rillane_udp_dropped_total{reason=…}    # frag/source/malformed get their own separate series
rillane_udp_mappings_active                       # new: total Level-2 mapping count
rillane_udp_reroutes_total                        # new: decision-invalidation reroute counter (no labels)
```

Unit tests (acceptance original text → test item):

| todo P0-1 acceptance | Test |
|----------------|------|
| session create/query/timeout reclaim have unit tests | ① the first packet creates a session and a key lookup hits; ② inject a clock advancing past `session_idle_secs` → after the sweep the table is empty and the expired metric is +1; ③ mapping level: after advancing `mapping_idle_secs`, only the target mapping disappears while the session is kept |
| the same sticky key reuses the mapping without rebuilding | send N consecutive packets under one key (including multiple targets): `mappings.len()` and the `decision` generation stay unchanged; switching port creates a new session |
| (new in this draft) full-capacity refusal | after filling `max_sessions`, a new key's first packet is refused and `dropped{session_limit}` is +1, with existing sessions unaffected |
| (new in this draft) decision invalidation | construct a chain session → trigger a link failure event → assert the decision cache is cleared, the next packet reroutes, and `update_route`/`RouteHistory`/`reconnect_count` are correct |
| (new in this draft) LRU overflow | inject 257 targets into one session: the longest-idle mapping is evicted and `max_mappings` always holds |

## 8. Boundaries and non-goals

- no general conntrack: no TCP, no FTP-class auxiliary channel association, no IP fragment reassembly (FRAG is already refused at the socks5 layer, udp-dataplane.md §2.2);
- QUIC is handled as UDP datagrams (`TargetProto::Quic` is only a marker); no QUIC connection-level awareness;
- no cross-session hairpin (session A sending to session B directly via the table);
- no session migration on a source port change (§3.2); no hot parameter adjustment, and config changes take effect on restart (MVP framing).

## 9. Open questions

| No. | Question | Follow-up |
|------|------|------|
| O5 | whether non-chain decisions should introduce TTL re-probing (migrate when a better node appears) -- by default stay sticky to the end | decided by P2-2 SLO-scored path selection |
| O6 | domain targets do not cache resolution results at the session layer; each mapping resolves on its own at the egress (direct, once per target); whether to move that up to the session layer | decided by P2-8 DNS split |
| O7 | whether `FlowSession` needs "recoverable Failed" state semantics (currently UDP avoids it by resetting to Active in a wrapper) | an independent small change, evaluated alongside the P0-1 implementation |
