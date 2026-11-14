# P2-2 SLO-scored path selection (design draft)

> 2026-10-02 ready and landed in the same round (lowest-score selection inside the group policy `slo:`
> gate + the chain `slo_watch` degradation switch, all tests green and in the repo with the batch -- see
> the roadmap S4 note). Score the group policy with p95 RTT/loss as the target, upgrading the `latency`
> policy; when the mesh degrades, the chain side switches automatically and the reason is recorded in
> the ledger (P2-1). "Default enabled in the game profile" goes to P2-3 (wired when the profile presets
> land; this draft delivers the capability surface).
>
> **Landing status**: implemented (M1 a9c7e11: the SloPolicy config + the scoring core/gate/source
> precedence; M2 this commit: the mesh -> routing quality bridge + the ChainManager SLO watcher +
> `SwitchReason::SloDegraded` + the `slo_watch` programmatic config surface).
> The YAML side goes to P2-3 (D-6/O-slo2); `slo_watch` is currently reachable only through programmatic
> construction of `ChainConfig` (serde deserialization is supported, `rillaned` does not pass it through).
> §6 E2 deviation note: the loss of a link with zero connections is recorded as 0.0 (the observation API
> has no atomic "errors/connections in the same snapshot" surface, and a pure-RTT node should not be
> inflated by suspected loss).

## 0. Scope and acceptance wording

**todo original text**: score with p95 RTT/loss as the target, upgrading the `latency` group policy; default enabled in the game profile.
**Acceptance original text**: when a simulated link degrades, switch automatically and record the switch reason; the `ChainContext` fallback path takes effect.

**Measurable wording (explicit rewrite, not shrinking)**:

1. **Score upgrade**: `latency` policy selection = the lowest score within the SLO target gate
   (score = p95_ms + loss_ratio x loss_penalty_ms) -- unit tests inject a degraded/optimized
   link_quality for two members and assert the selection flips;
2. **Automatic switch on degradation**: the chain SLO watcher detects the current path crossing the
   gate -> `handle_chain_failure` triggers a switch/termination, ledger event
   `reason="slo_degraded"` (the P2-1 `rillane_mesh_switch_total{reason}` counting family is visible
   automatically, no new metric family) -- unit tests inject degradation data to drive the watcher;
3. **Fallback takes effect**: after the switch, the `ChainContext` current path = the promoted backup
   path (the promotion semantics were fixed in P2-1 M1, with a single get_current_path wording) --
   assert the from/to path shape after the switch.

## 1. Current state and structural constraints

- `RoutingEngine` (rillane-routing): the `latency` policy = min of the last sample in `latency_stats`;
  **the sample source is simulated** (`measure_node_latency` is random 10-100ms -- the existing
  `test_health_check_integration` depends on that path); dependencies are only rillane-config + rillane-core
  (**no dependency on rillane-mesh** -- data can only be pushed in, the precedent being
  `update_bandwidth_stats`);
- P2-1 delivered the real data source: `MeshRegistry.link_rtt` (RttRing p50/p95) +
  `link_traffic` (errors/connections) -- keyed by `(from,to)` link direction, which must be aggregated
  to the node dimension before it can enter a group policy (members = node names);
- `ChainManager::handle_chain_failure` (after the P2-1 repair): the promotion semantics on switch are
  correct and the ledger is left with traces by reason -- degradation switching can reuse it directly;
  what is missing is only the "degradation detected" trigger and the reason enum value;
- rillane-config has no chain YAML block: `RuntimeBuilder.chain_config` is the only programmatic entry
  (`Option<ChainConfig>`).

## 2. Decisions (D-x)

- **D-1 pure scoring function**: `slo_score(p95_ms, loss_ratio, penalty) =
  p95_ms as f64 + loss_ratio * penalty` -- additive, latency dominant, loss penalized by a configurable
  weight (default 1000ms per unit of loss ratio: 1% loss = about +10ms penalty, which is explainable).
- **D-2 SLO target gate**: group-level `slo: {p95_ms, loss_ratio}` (both Option) -> the compliant set
  = {those with data and p95 <= gate and loss <= gate; **members with no data are treated as
  compliant** (unknown does not kill by mistake)}; take the lowest score within the compliant set; an
  empty compliant set -> take the lowest score over all (no dead-end). `slo` default None -> no gate,
  pure lowest score (compatibility surface for existing configs).
- **D-3 data plane**: `RoutingEngine::update_link_quality(node, p95_ms,
  loss_ratio)` (DashMap + 60s TTL, the same convention as bandwidth_stats); the `latency` policy read
  precedence = link_quality (real) -> legacy latency_stats (simulated/existing) -> the first healthy
  member. Semantic change note: when real data is present the read goes from "last sample" up to "p95
  percentile" (§9).
- **D-4 zero new dependencies, zero trait changes**: rillane-routing adds no dependency; the mesh ->
  routing bridge lives in rillane-runtime (aggregating RttRing/LinkTraffic: a node's p95 = the max of the
  worst hop of the adjacent links, a node's loss = the sum of errors / the sum of connections, pushed
  only when there is data).
- **D-5 automatic switch on degradation**: `ChainConfig.slo_watch: Option<SloWatch{
  p95_ms, loss_ratio, interval_secs}>` (default None = watcher off); the watcher periodically evaluates
  the last-hop quality of the current path of each active link (queried from MeshRegistry); crossing
  the gate -> `handle_chain_failure(chain_id, "slo degraded: p95=...ms loss=...")`; add
  `SwitchReason::SloDegraded` (incremental in three places: enum/as_str/ALL, so the P2-1 counting
  family gains the `reason="slo_degraded"` series automatically).
- **D-6 the config surface in two steps**: the group-level `PolicyGroup.slo` (serde default None, zero
  difference for existing configs) lands in YAML this step; the chain-side `slo_watch` lands only in
  the programmatic surface this step (`RuntimeBuilder.chain_config`) -- rillane-config has no chain block,
  and the YAML side lands together with the P2-3 profile (default enabled in the game profile = wired
  there).

## 3. Data structures

```rust
// rillane-config
pub struct SloPolicy {            // PolicyGroup.slo: Option<...> (serde default)
    pub p95_ms: Option<u32>,      // target gate (None = no gate on this dimension)
    pub loss_ratio: Option<f64>,  // target gate (None = no gate on this dimension)
    pub loss_penalty_ms: Option<f64>, // default 1000.0
}
// rillane-runtime chain.rs
pub struct SloWatch {             // ChainConfig.slo_watch: Option<...>
    pub p95_ms: u32,
    pub loss_ratio: f64,
    pub interval_secs: u64,       // default 10
}
```

## 4. Wiring points

| Point | Change |
|----|------|
| `PolicyGroup` (rillane-config) | + `slo: Option<SloPolicy>` (default); validate: loss_ratio in [0,1], penalty >= 0 |
| `RoutingEngine::select_latency_member` | the gate + scoring (D-2), read precedence (D-3) |
| `RoutingEngine::update_link_quality` | new public write point + TTL |
| the rillane-runtime bridge task | periodically aggregate MeshRegistry -> update_link_quality (node = an endpoint name of the link) |
| `ChainConfig` / `ChainManager` | + the slo_watch field + the watcher task (spawned the same way as start_health_check_task) |
| `SwitchReason` | + SloDegraded (incremental in three places) |

## 5. Control plane

No new metric family or endpoint: a degradation switch is visible automatically through the P2-1
`rillane_mesh_switch_total{reason="slo_degraded"}` and `/mesh/switches` (the reason was chosen as an
enum value for exactly this purpose). The group policy selection result is routing-internal state,
exposed at the time of this draft's delivery via the existing diagnose surface; a later O-slo1
(2026-10-10) added a dedicated observability surface: `GET /routing/stats` + `rillanectl group` (a
real-time quality snapshot of the group, with the selected endpoint/gate/score and the selection from
the same source).

## 6. Error paths

- E1 a member has no link_quality data: treat it as compliant (the gate does not kill by mistake); the
  score falls back to legacy latency_stats -> the first healthy member (the precedence chain);
- E2 a link's loss denominator is 0 (no series under P2-1 E4): the bridge does not push a
  loss-dimension update for that node (keep it unknown);
- E3 the link is terminated/removed while the watcher evaluates: skip it (a chain_id outside the
  active_chains snapshot that queries the registry and gets None is skipped);
- E4 slo_watch and the group-level slo are independent: the watcher only governs switching, the group
  policy only governs selection -- no linked configuration (to avoid two sources of truth).

## 7. Test strategy

1. the scoring/gate pure functions: the additive shape, gate filtering, unknown compliance, no
   dead-end when every gate is broken;
2. the latency policy: inject a degraded member and an optimized member of link_quality -> the
   selection flips; legacy data present and real data absent -> the old behavior;
3. bridge aggregation: two links in the registry (different p95 + one with errors/connections) -> the
   node worst-hop p95 and the aggregated loss are pushed correctly;
4. the watcher: inject gate-crossing data -> handle_chain_failure is triggered, a slo_degraded ledger
   event, fallback promotion (the from/to path shape);
5. zero regression over the existing 268 items (the simulated source path is untouched).

## 8. Step-by-step implementation checklist (M1-M2)

| Step | Content and landing points | Depends on | Acceptance |
|----|-----------|------|------|
| M1 | the rillane-config SloPolicy + the rillane-routing scoring core (update_link_quality/gate/scoring/read precedence) + the §7-1/2 unit tests | - | §7-1/2 green; zero regression over existing routing tests |
| M2 | the rillane-runtime bridge + SloWatch/watcher + SwitchReason::SloDegraded + the §7-3/4 unit tests + documentation backfill (todo/PROTOCOLS/roadmap/landing note in this draft) | M1 | §7-3/4 green; the §0 wordings are reproducible item by item |

## 9. Deviations and assumptions

- **semantic change**: when real data is present the `latency` policy goes from "min of the last
  sample" up to "min of the p95 percentile (within the gate)" -- the behavior is unchanged for
  simulated-source/no-real-data deployments (the precedence chain is the fallback), and the existing
  tests are the proof of compatibility;
- **MVP sampling source** = the mesh report stream (the same source as P2-1 D-1); real active probing
  goes to O-link-obs1; the group policy of a no-mesh deployment has no real data -> the precedence
  chain falls back to the old behavior;
- **node aggregation wording** = worst-hop p95 + loss aggregation over all adjacency: degradation at
  either endpoint of a link is reflected in both endpoint nodes (the conservative direction; in game
  scenarios it is better to switch paths by mistake);
- mesh `NodeId` and the group policy node names share the same namespace (existing configs and the
  dry-run tests assume this, and the bridge does no mapping).

## 10. Risks and open items

- **R-slo1**: a spurious watcher switch (a transient crossing of the gate due to reporting jitter) --
  the MVP has no hysteresis/debounce, and the interval period is the natural smoothing; the hysteresis
  policy is decided after an observation period for the false-switch rate;
- **O-slo1**: ~~the `rillanectl group` subcommand shows the real-time SLO score of each member~~ (**landed
  2026-10-10**: the `RoutingEngine::group_quality_report` snapshot surface + the control plane
  `GET /routing/stats` + `rillanectl group` -- a member's data source of real/legacy/unknown, p95/loss,
  the gate judgment and the latency group's current deterministic selected endpoint; the
  selected-endpoint/gate/scoring wording is shared from the same source as select_latency_member);
- **O-slo2**: ~~the wiring of default enabled in the game profile (P2-3)~~ (**landed
  2026-10-02**: the game-auto group expanded from `profile: game` carries its own
  `slo{p95_ms: 80, loss_ratio: 0.02}`, see scenario-profiles.md §4);
- **O-slo3**: hysteresis/debounce (switch only after N consecutive gate-crossing periods), decided
  per the observation of R-slo1.
