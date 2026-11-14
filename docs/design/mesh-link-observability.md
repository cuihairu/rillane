# P2-1 per-link fine-grained metrics (design draft)

> Ready and landed the same round 2026-10-02. Scope: mesh link-dimensional latency distribution (p50/p95),
> packet loss observability, switch-reason ledger; filling the exposure of the already-existing inter-node
> traffic surface (`LinkTrafficStats`).
> Methodology follows udp-observability.md (P0-5): always-render discipline, closed-state contrast,
> explicitly rewritten statistical criteria without shrinkage.
>
> **Landing note (2026-10-02, M1-M2 all complete)**: M1 (sample ring + ledger + existing defect repair)
> `a9c7e11`, M2 (three control plane families + `/mesh/switches` + doc backfill) this commit. Three
> existing defects repaired during implementation (M1 ledger tests exposed them on first coverage):
> (1) `handle_chain_failure` backup-exhaustion branch calling `active_chains.len()` while holding a
> RefMut -- the DashMap's full-shard read locks are mutually exclusive with this thread's shard write
> lock, which self-deadlocks; fix = drop the shard guard first; (2) rillane-core `ChainContext` path
> semantics -- when fallback is non-empty, `get_current_path()` always reads `fallback_paths[idx]`: a
> link that never switched falsely reports fallback[0] as the current path (route decision same-source
> contamination) and the first hop skips fallback[0]; fix = single-criteria current_path + promotion by
> declaration order (`switch_fallback_path` reuses update_path to promote to primary); (3)
> `check_chains_health` attribution order -- state before TTL (under a ZERO TTL sweep, an already-terminated
> chain satisfies both causes simultaneously, the old order wrongly blames the dead cause as TtlExpired).
> §10-1 (active probe source), §10-2 (rillanectl wrapper), §10-3 (event persistence) remain open.

## 0. Scope and acceptance criteria

**todo original text**: per-link fine-grained metrics: latency distribution, packet loss, switch
reasons, inter-node traffic.
**Acceptance original text**: Grafana can query p50/p95 RTT and the most recent N switch reasons
by link dimension.

**Testable criteria (aligned with the P0-3/P1-5 explicit-rewrite approach, not shrinkage)**:

1. **p50/p95 RTT**: `rillane_mesh_link_rtt_ms{from,to,quantile="p50"|"p95"}` -- sample-ring quantiles
   computed in place (§3.1), `from`/`to` labels = link direction, Grafana queries directly by link
   dimension;
2. **Most recent N switch reasons**: `GET /mesh/switches` (most recent 100 events as JSON) +
   `rillane_mesh_switch_total{reason}` counter family -- reasons enumerated (§2 D-3), free text demoted
   to the `detail` field;
3. **Packet loss**: derived observability form `rillane_mesh_link_loss_ratio{from,to}` =
   `errors_total / connections_total` (a failed connection is a drop; §2 D-2), the reported form
   `rillane_mesh_packet_loss_rate` (global average, existing) is kept unchanged;
4. **Inter-node traffic**: the existing `rillane_mesh_link_{bytes,connections,errors}_total`
   (delivered by P0-5) is the acceptance surface, this document does not rebuild it.

## 1. Current state and structural constraints (the factual input to decisions)

- `MeshRegistry` (rillane-mesh/src/lib.rs) already has: `link_states` (the reported-form single values
  latency_ms/bandwidth/packet_loss_rate, written by the control plane `/mesh/link-states`),
  `link_traffic` (counted by direction connections/bytes/errors, exposed by P0-5) -- **single-value
  latency with no distribution**, **packet loss only has the reported value with no observed value**,
  **no switch event ledger**;
- `ChainManager` (rillane-runtime/src/chain.rs) `handle_chain_failure` switches to a backup path only by
  incrementing the global `failover_count`, the reason is free-text logged and discarded; the health
  sweep's TTL/state termination leaves no reason trace;
- A real probe source (active ping frames / LatencyProbe annotation backfill) does not yet exist: only
  after P1-4 M2 can the LatencyProbe annotation surface be wired (another session in flight), this item
  does not block it.

## 2. Decisions (D-x)

- **D-1 RTT sample ring**: a per-link ring sample (cap 256, tail-in tail-out) hosted at
  `MeshRegistry.link_rtt`; at snapshot time sort in place and take the nearest-rank quantile (sorting
  256 samples is negligible overhead, no external dependency). Sample source MVP =
  `update_link_state` reported values enter the ring (the existing control plane flow, zero new
  protocol) + a public `record_link_rtt` write point (probe source hooked in later).
- **D-2 packet loss = derived observation**: the `errors/connections` ratio computed in place
  (connections=0 -> no series), no new active probing added; the reported form stays the reported form
  (the two have different semantics and are not merged).
- **D-3 enumerated switch reasons**: `SwitchReason = FailureReported (a flow error triggers a switch)
  | FallbackExhausted (backup exhausted and terminated) | TtlExpired | TerminatedUnhealthy`; event
  ledger `Mutex<VecDeque<SwitchEvent>>` cap 100 (most recent retained) + a per-reason count
  `BTreeMap` (the metrics data source). Termination-class events (TTL/state) and switches are recorded
  in the same ledger -- for Grafana both are "link change reasons", §9 deviations record this.
- **D-4 zero trait changes / zero new dependencies**: the ledger hangs off a `ChainManager` field, the
  ring hangs off a `MeshRegistry` field (`Default`-compatible -- both `DashMap` + `VecDeque` can be
  derived); the UDP side `table.handle_chain_failure` (P0-1 mechanism) is not mixed in.
- **D-5 closed-state contrast**: mesh not enabled -> the three new families and `/mesh/switches` are
  all not rendered (different from the udp/obfs always-render discipline: link observability rises and
  falls with the existence of the mesh capability, with no links there are no series names to
  establish; same judgment as P1-5 rillane_pool_*).

## 3. Data structures

### 3.1 RttRing (rillane-mesh)

```rust
pub struct RttRing { samples: VecDeque<u32> }   // cap = RTT_RING_CAP = 256
record(ms: u32); quantile(p: f64) -> Option<u32> // nearest-rank: sort then
                                                 // idx = (p * n).ceil() - 1
```

`LinkRttSnapshot { from, to, p50_ms, p95_ms, samples }` (Serialize, shared by the control plane DTO
and the endpoint).

### 3.2 SwitchEvent / ledger (rillane-runtime chain.rs)

```rust
pub enum SwitchReason { FailureReported, FallbackExhausted, TtlExpired, TerminatedUnhealthy }
pub struct SwitchEvent { chain_id, from_path: Vec<String>,
                         to_path: Option<Vec<String>>, reason: String,
                         detail: String, epoch_seconds: u64 }
```

New `ChainManager` fields `switch_ledger: Mutex<VecDeque<SwitchEvent>>` +
`switch_counters: Mutex<BTreeMap<String, u64>>`; public `record_switch` / `get_recent_switches(n)` /
`switch_counters_snapshot()`.

## 4. Wiring points

| Point | Current state | Change |
|----|------|------|
| `MeshRegistry::update_link_state` | Overwrites LinkState | When latency_ms>0 push into the ring (D-1 sample source) |
| `ChainManager::handle_chain_failure` | failover_count++ | Switch success -> `FailureReported` event (from=pre-switch path, to=new fallback path, detail=original failure_reason); backup exhausted -> `FallbackExhausted` (to=None) |
| `ChainManager::check_chains_health` | TTL/state termination leaves no trace | On termination record `TtlExpired` / `TerminatedUnhealthy` by cause (cause carried with chain_id) |
| Probe source | None | `record_link_rtt` public write point reserved (O-link-obs1) |

## 5. Control plane exposure

- `/metrics` (within the mesh block): `rillane_mesh_link_rtt_ms{from,to,quantile}` (two p50/p95 series
  per link, not emitted when the ring is empty), `rillane_mesh_link_loss_ratio{from,to}`, (within the
  chain block) `rillane_mesh_switch_total{reason}` (always rendered -- the counter family is present even
  at zero, when the ledger is empty there is no event endpoint entry);
- `GET /mesh/switches`: `{ events: [...] }` the most recent 100 (within the mesh enabled gate, 503
  when not enabled per the `/nodes` precedent).

## 6. Error paths

- E1 ring full: tail-in tail-out overwrites the oldest, no error surface;
- E2 ledger full: pop from the head, no error surface;
- E3 `quantile` on an empty ring: return None -> the series is not rendered (not zero-filled -- drawing
  "0ms" for a link with no samples is misleading);
- E4 connections=0: no loss_ratio series (0/0 is meaningless).

## 7. Test strategy

1. RttRing quantile math (odd/even n, boundary p0/p1, cap overwrite);
2. registry sample source: update_link_state pushes into the ring + record_link_rtt direct write;
3. switch ledger: handle_chain_failure's two branches' event shape (path/reason/detail pass-through)
   + health sweep's TTL/termination two causes + cap 100 ring wrap + counter aggregation;
4. control plane: metrics three families queried by dimension (from/to label assertion) +
   /mesh/switches endpoint + closed-state absence (D-5);
5. Existing 259 tests zero regression.

## 8. Step-by-step implementation checklist (M1-M2)

| Step | Content and landing points | Dependencies | Acceptance |
|----|-----------|------|------|
| M1 | Design draft (this document) + rillane-mesh RttRing/sample source/snapshot + rillane-runtime switch ledger wiring + unit tests | -- | §7-1..3 all green |
| M2 | rillaned control plane: /metrics three families + /mesh/switches + tests + todo/PROTOCOLS/roadmap backfill | M1 | §7-4..5 all green; §0 criteria reproducible item by item |

## 9. Deviations and assumptions

- Termination-class events (TtlExpired/TerminatedUnhealthy) are recorded in the same ledger as path
  switches: for the Grafana querier both are "link change reasons", no separate table yields an
  operational action (D-3 note);
- p50/p95 computed by in-place sorting rather than a bucket histogram: overhead is negligible at the
  256 cap, saving the prometheus histogram dependency and bucket configuration; if the sample volume
  rises another tier (>10k/link) switch to the bucket form;
- The sample source MVP only has the reported flow (no active probing): the real RTT distribution waits
  for the probe source to land (O-link-obs1, after P1-4 M2 either LatencyProbe annotation backfill or a
  mesh ping frame) -- this item's acceptance criteria (querying p50/p95 and switch reasons by dimension)
  does not depend on the probe source;
- loss_ratio uses connections as the denominator (a failed connection is a drop), not packet-level --
  the mesh surface has no per-packet ACK semantics, packet-level loss goes to V2 QUIC transport stats.

## 10. Risks and open issues

- **R-obs1**: the reported value is the sample (D-1) -- the reporter's semantics is "latency at the
  time" not "measured RTT", the distribution shape is affected by the reporter's honesty; after the
  probe source lands, switch to real measurements, the series name stays the same;
- **O-link-obs1**: active probe source wiring (LatencyProbe annotation backfill / mesh ping frame);
- **O-link-obs2**: ~~`rillanectl switches` subcommand~~ (**landed 2026-10-10**: `rillanectl switches`
  renders the `/mesh/switches` ledger -- epoch/chain_id/pre-post paths/reason/detail, a termination
  event's absent to_path is rendered as `(terminate)`);
- **O-link-obs3**: switch event persistence (lost on restart, not done in MVP -- the ledger's purpose
  is recent-cause observability, not auditing).
