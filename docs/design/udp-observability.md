# P0-5 UDP observability and config -- implementation-level design

> Upstream design: [udp-dataplane.md](udp-dataplane.md) §5 (P0-5 concept draft: config sketch / metric draft / R11 cardinality risk / O4 open).
> **Status: landed (todo P0-5 complete, 2026-09)** -- implementation surface = `rillane-core/src/udp/metrics.rs` + the `rillane-config` `udp:` block + `apps/rillaned/src/control_plane.rs` rendering and `/udp/stats`; the §10 S0-S6 step-by-step checklist has been fully implemented.
> This document is the finalized landed version: **config item list, `/metrics` naming and semantics, rillanectl rendering, and the integration points with the P0-4 data plane**.
> Reuse baseline: P0-1 session table metrics (`TableMetrics`/`TableSnapshot`) - P0-2 ASSOCIATE metrics (`UdpIngressMetrics`) - P0-3 capability table - P0-4 mesh UDP surface (`udp-mesh-dataplane.md`, **landed**).
>
> **2026-09-30 pre-assignment refinement**: added **step-by-step implementation checklist S0-S6 (§10, each step with landing point / dependencies / deliverables / test plan)** and **log criteria (§2.7)**; the whole document has been re-reviewed against the P0-4 landed reality and the rendering/control plane current state, places inconsistent with the initial draft are marked in place with "landing audit" (§1.5/§2.1/§2.4/§2.5/§3.2/§4/§7/§9-1).

## 0. Scope

- Fill in the `rillane-config` `udp:` block (P0-2 exposed only 3 of the 7 `UdpSessionConfig` fields);
- `/metrics` gains the full `rillane_udp_*` family (sessions/associates/bytes/dropped/expired + the P0-4 mesh surface);
- `rillanectl stats` gains a UDP section + new `rillanectl udp-probe` integration test tool (closes out P0-2's leftover "standard client integration test");
- Grafana dashboard adds UDP panel rows;
- Log criteria closeout (§2.7): structural events INFO / one-off path errors DEBUG / high-frequency events counted only not printed, zero new per-packet path logging;
- Excluded: per-target metric dimensions (R11, belongs to P2-1), UDP surface runtime hot-reload (§1.6 ruled to take effect on restart).

## 1. Config item list

### 1.1 Existing (landed by P0-2, semantics unchanged)

`RillaneConfig.udp` (`rillane-config`) = `UdpConfig`:

| Field | Default | Semantics |
|------|------|------|
| `enabled` | `false` | Master switch; when false socks5/mixed reply 0x07 to CMD 0x03 |
| `strict_udp_source` | `true` | Datagram source IP validation (prevents relay borrowing) |
| `session_idle_secs` | `180` | Session idle cap -> `UdpSessionConfig.session_idle` |
| `mapping_idle_secs` | `60` | Target mapping idle cap -> `mapping_idle` (P0-4 hop cache TTL same source, §4) |
| `max_sessions` | `4096` | Global concurrent session upper bound (reject new when full) |

### 1.2 P0-5 additions: UdpConfig fill-in (mapping the remaining UdpSessionConfig fields)

| New field | Default | -> UdpSessionConfig | Constraint (validate reuses existing checks) |
|---------|------|--------------------|------------------------------|
| `sweep_interval_secs` | `15` | `sweep_interval` | >=1s (the original implementation allowed ms-level, the config surface tightens to second granularity) |
| `max_mappings` | `256` | `max_mappings` | >=1 (per-session mapping upper bound, overflow evicts longest idle) |
| `session_lifetime_secs` | none (unbounded) | `session_max_lifetime: Option` | >= session_idle_secs |
| `downlink_queue_depth` | `64` | `downlink_capacity` | >=1 (drop when full + DownlinkFull count) |
| `max_associates` | `256` | (new: `UdpAssociateService` concurrent ASSOCIATE cap) | >=1; over-limit replies 0x01 and counts `associate_rejected` (the current implementation only has a concurrency gate with no cap, this item adds abuse protection) |

serde is all `#[serde(default)]` for backward compatibility (old configs missing fields still parse).

### 1.3 ingress per-ingress switch (upstream §5.2 `udp_enabled` landing)

- `IngressConfig::Socks5` / `IngressConfig::Mixed` each gain `#[serde(default)] pub udp_enabled: Option<bool>`:
  - `None` (default) -> inherit the global `udp.enabled`;
  - `Some(false)` -> that ingress explicitly off (ASSOCIATE replies 0x07), other ingresses unaffected;
  - `Some(true)` -> explicitly on (when globally off only that ingress is usable, a build-time warning notes the global switch semantics).
- Pass-through path: `build_ingress_endpoints(descriptors, udp)` already constructs per ingress -- the judgment of "whether that ingress gets `Some(service)`" changes from "global enabled" to "per-ingress override union global"; the service instance is still globally a single shared one (session table/metrics singleton).

### 1.4 egress: no switch (reaffirming the upstream principle)

UDP transport capability is statically determined by the outbound type (direct/shadowsocks/wireguard check; the rest error at build time, pinned by P0-3 §3.1). No egress config switch is added, avoiding the "config says yes, runtime says no" drift. wireguard MTU already has a node-level config (`egress.wireguard.mtu`), no duplicate exposure.

### 1.5 mesh UDP surface config (P0-4 integration; landing audit: **landed with P0-4 S5, P0-5 zero new config**)

| Field/source | Default | Semantics |
|----------|------|------|
| env `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` | unset | P0-4 plaintext gate (mirrors the TCP surface's `RILLANE_MESH_ALLOW_PLAINTEXT`); the only permit path when chain+udp is configured without encryption |
| `MeshConfig.udp_allow_plaintext_data_plane` | `false` | The persisted equivalent of the env (serde default false); the two are ORed |

**Landing audit (2026-09-30)**: both rows in the table above landed with P0-4 S5 (commit 1d2d8af) -- the merge point = `RuntimeBuilder::build()` evaluates once (`cfg.udp_allow_plaintext_data_plane union env`), both consumption points share the source (client bridge construction + the non-client surface's start via the `Runtime.mesh_udp_gate` copy). **The landing point is `crates/rillane-runtime/src/runtime_builder.rs` (`MeshConfig` is defined in that file, not rillane-config)**, the §7 table has been corrected accordingly. P0-5 only does sample backfill (S6: the `config/rillane.yaml` plaintext gate commented sample) and acceptance verification, does not touch the field.

### 1.6 Hot-reload semantics and validation

- **UDP config changes take effect on restart**: the subscription hot-reload pipeline does not touch the runtime `UdpSessionTable`/`UdpAssociateService` parameters (sticky decisions and session state cannot be hot-migrated); existing sessions are reclaimed naturally under the old timeouts. Docs and `rillanectl` help text state this explicitly.
- `UdpConfig::validate()` new field constraints are added with the implementation (columns in the table), illegal values error at build time.

## 2. /metrics naming and semantics

### 2.1 Render path and conventions

- Export point: `apps/rillaned/src/control_plane.rs::handle_metrics`. **Landing audit: the existing render helpers are only two families** -- `push_gauge` (unlabeled series, TYPE gauge) and `push_metric_header(name, help, "counter")` + `push_metric_labeled(name, labels, value)` (`rillane_mesh_link_bytes_total` uses this method, control_plane.rs:339-373); **no `push_counter` function exists** (initial draft typo). Labeled direction/reason series = header(counter) followed by one labeled per member of a closed enum, the series set is statically enumerable;
- **Always-render criteria**: all §2 series are always present on `/metrics` (0 when `udp.enabled=false` / the mesh surface is not enabled), the endpoint does not disappear because of a switch (§6-2);
- Prefix is uniformly `rillane_udp_`; counters only increase and reset to zero on process restart (rate semantics are Prometheus's job); gauges are instantaneous values;
- **Label cardinality (R11 landing)**: only the two closed enum labels `direction`/`reason`, no target/host/user labels (session-level aggregation; per-link detail belongs to P2-1);
- Data sources are all atomics read without locks: `TableMetrics` / `UdpIngressMetrics` / (P0-4) `UdpFaceMetrics`.

### 2.2 Session table series (P0-1 base -> rendered)

| Series | Type | Source | Semantics |
|------|------|--------|------|
| `rillane_udp_sessions_active` | gauge | `TableMetrics.sessions_active` | Currently live sessions |
| `rillane_udp_sessions_total` | counter | `TableMetrics.sessions_total` | Cumulative created (including reclaimed) |
| `rillane_udp_mappings_active` | gauge | `TableMetrics.mappings_active` | Currently live target mappings |
| `rillane_udp_reroutes_total` | counter | `TableMetrics.reroutes` | Sticky decision rebuilds (after link failure/cache cleared) |
| `rillane_udp_relay_bytes_total{direction="up\|down"}` | counter | **new table-level aggregate** (§2.5) | Relayed bytes (client<->egress) |
| `rillane_udp_relay_packets_total{direction="up\|down"}` | counter | `UdpIngressMetrics.uplink/downlink_packets` | Relayed datagrams |
| `rillane_udp_dropped_total{reason=...}` | counter x6 | `TableMetrics.dropped` | Drops; reason closed enum = `DropReason`: `session_limit`/`mapping_limit`/`no_binding`/`shutting_down`/`send_failed`/`downlink_full` |
| `rillane_udp_expired_total{reason=...}` | counter x3 | `TableMetrics.expired` | Reclaims; reason = `ExpireReason`: `idle`/`lifetime`/`revoked` |

### 2.3 ingress / ASSOCIATE series (P0-2 base -> rendered)

| Series | Type | Source | Semantics |
|------|------|--------|------|
| `rillane_udp_associates_active` | gauge | `UdpIngressMetrics.associates_active` | Current ASSOCIATE control connections |
| `rillane_udp_associates_total` | counter | `associates_total` | Cumulative accepted ASSOCIATEs |
| `rillane_udp_associates_rejected_total` | counter | `associate_rejected` | Rejections (concurrency gate/cap, 0x01 reply) |
| `rillane_udp_associate_errors_total` | counter | `associate_errors` | Slow path errors (association/binding failures) |
| `rillane_udp_frag_dropped_total` | counter | `frag_dropped` | FRAG!=0 fragments dropped (no reassembly support) |
| `rillane_udp_source_dropped_total` | counter | `source_dropped` | Source address mismatch (strict_udp_source) |
| `rillane_udp_malformed_dropped_total` | counter | `malformed_dropped` | SOCKS5 header parse failures |

### 2.4 mesh UDP surface series (P0-4 integration; naming absorbs the upstream reservation)

The upstream §5.3 reserved name `rillane_udp_relay_handshake_errors_total` is **deprecated**: the FULL/CACHED protocol has no handshake semantics. Errors are subdivided by actual form:

| Series | Type | Source (P0-4 `UdpFaceMetrics`) | Semantics |
|------|------|--------------------------------|------|
| `rillane_udp_mesh_flows_active` | gauge | hop cache len | Currently cached flow entries (relay/exit perspective) |
| `rillane_udp_mesh_forwarded_total{direction="up\|down"}` | counter | forward counters | Inter-hop forwarded datagrams |
| `rillane_udp_mesh_unknown_flow_total` | counter | unknown_flow | CACHED miss (including arrivals after expiry) |
| `rillane_udp_mesh_malformed_total` | counter | malformed | Envelope decode failures |
| `rillane_udp_mesh_evicted_total` | counter | eviction counter | Upper bound evictions (R10) |
| `rillane_udp_mesh_client_dropped_total` | counter | **new `UdpClientMetrics.dropped`** (process-level absorption of P0-4 `MeshUdpRelay.dropped`) | Client egress-side downlink drops (dir=Up / FULL / flow_id mismatch / decode failure -- the `recv_from` filter point) |
| `rillane_udp_mesh_replay_dropped_total` | counter | **new `UdpFaceMetrics.replay_dropped`** (P2-7 in-band V2 replay window) | Datagrams refused by the per-(flow,dir) sliding window at the surface (relay/exit) |
| `rillane_udp_mesh_client_replay_dropped_total` | counter | **new `UdpClientMetrics.replay_dropped`** (P2-7) | Replay refusals at the client egress-side `recv_from` window |

**Absorption ruling for the client-side `dropped` (added after the landing audit)**: P0-4 placed this counter in a per-relay `AtomicU64` (`udp_chain.rs`, annotated "read point = P0-5"); the per-flow instance cannot be aggregated. It is absorbed as process-level: `MeshUdpBridge::new` constructs `Arc<UdpClientMetrics>{dropped: AtomicU64}`, and `associate` passes **the same Arc** into each `MeshUdpRelay` (the field switches from `AtomicU64` to `Arc<UdpClientMetrics>`, the fetch_add point unchanged); `RuntimeBuilder::build()` extracts that Arc into a Runtime field (observable getter) before wrapping the `UdpChainRouter`. The surface (server perspective) and client (initiator perspective) are two separate series; the client side is not mixed into the `rillane_udp_mesh_*` surface family -- the naming/semantics agree with §0.2's "separate families, no cross-counting".

### 2.5 Byte aggregation implementation ruling

Today byte counting only exists per-mapping (`MappingShared.bytes_up/bytes_down`). If a `/metrics` scrape scans the full table to aggregate, that is O(active sessions) and scrape overhead varies with load. **Ruling**: `TableMetrics` gains global `bytes_up`/`bytes_down` AtomicU64s, accumulated incidentally at the existing count points (`count_up`/`count_down` call sites) -- rendering needs zero scanning; the per-mapping values are kept for `SessionSnapshot` (used by the rillanectl/stats detail).

**Landing audit (only two call sites in the whole repo)**: `table.rs:369` (uplink, `self.metrics` direct within a table method) and `table.rs:608` (downlink forwarder, already holds `Arc::clone(&self.table.metrics)` from construction, see table.rs:538) -- both contexts can already reach `TableMetrics`, zero new penetrations, zero new locks.

### 2.6 /flows and /chains/stats ruling (closing the upstream O4)

- **`/flows` gains no proto dimension**: UDP sessions do not go through `FlowOutputRouter` (since P0-2 the UDP surface enters the session table directly, no FlowStatItem); forcibly stitching two statistics models together only produces semantically ambiguous double accounting. UDP observability criteria = this document's `rillane_udp_*` + the `rillanectl stats` UDP section (§3).
- **`/chains/stats` does not get a UDP column** (closes O4): link-dimension UDP traffic already enters the mesh per-link series via P0-4's `record_link_bytes` (`rillane_mesh_link_bytes_total`, existing), a repeated column adds no incremental information.

### 2.7 Log criteria (tracing; division of labor with counters)

Current-state audit: the existing UDP-related targets = `rillane::socks5_udp` (`associate.rs`: INFO ASSOCIATE established/ended, DEBUG slow_path errors and downlink send failures), `rillane::socks5`/`rillane::mixed` (ingress start INFO, connection handling failure WARN), `rillane::mesh::transport` (mesh TCP/UDP surface: DEBUG datagram drops and connection close). P0-5 follows the same division of labor and closes out as follows:

| Event | Carrier | Level / target |
|------|------|--------------|
| ASSOCIATE established/ended, ingress start | existing logs (unchanged) | INFO, `rillane::socks5_udp` / `rillane::socks5` / `rillane::mixed` |
| slow_path errors, downlink send failures, mesh datagram drops | existing logs (unchanged) | DEBUG, `rillane::socks5_udp` / `rillane::mesh::transport` |
| per-ingress `Some(true)` while globally off | one-time build-time note (new) | WARN, `rillane::boot` |
| `max_associates` rejects new | counted only in `associate_rejected` + the existing 0x01 reply path (**no new print**) | -- |
| session/mapping reclaim sweeps, mesh flow create/reclaim (retire/forget) | **counted only, no logs** (carried by `expired`/`flows_active`/`unknown_flow`; a flow's lifecycle is second-scale, per-entry printing adds no incremental info) | -- |
| per-packet success / per-packet drop | **new prints forbidden** (forwarded/dropped/unknown_flow/malformed all carried by counters; the only existing exception = the mesh serve loop's DEBUG drop, kept as is) | -- |
| `udp-probe` output | CLI stdout/stderr (§9-3 exit code table), not through tracing | -- |

Config validation failures (validate) go through anyhow build-time bail (existing mechanism), not into tracing. General principle: **high-frequency events are always counters, logs only carry structural events and one-off errors** -- this task adds no new per-packet log path.

## 3. rillanectl: stats UDP section + udp-probe integration test tool

### 3.1 Control plane snapshot endpoint `/udp/stats` (new)

control_plane exposes JSON: `{ table: TableSnapshot, ingress: UdpIngressMetricsSnapshot, mesh: Option<UdpFaceMetricsSnapshot> }` (snapshot structures are all assembled from the existing `get()`/`get_gauge()`, no new state).

### 3.2 `rillanectl stats` rendering

**Landing audit**: the current `rillanectl stats` hits `/flows` (default `http://{control.api_bind}/flows`, `--endpoint` overrides; parses `Vec<FlowStatItem>` -- the rillanectl `Command::Stats` handling section). Change: in default mode first print the `/flows` table as now, then GET `/udp/stats` (§3.1) from the same base and render the UDP section appended (§9-2 style): sessions/mappings active/total, dropped x6, expired x3, bytes/packets up/down, associates active/rejected, the mesh section (when P0-4 is enabled). `--endpoint` override applies only to the `/flows` side (the UDP section is still derived from the same base); when `/udp/stats` is unreachable/404 the UDP section prints `(no UDP section on the control plane)` and it is not treated as a failure (compatible with older rillaned).

### 3.3 `rillanectl udp-probe` (closes P0-2's leftover "standard CLI integration test")

curl/dig both do not support SOCKS5 UDP ASSOCIATE (curl goes TCP, dig has no proxy surface), proxychains depends on the system stack and is not controllable. **Ruling**: build in a minimal RFC 1928 ASSOCIATE client:

```
rillanectl udp-probe --socks5 127.0.0.1:1080 --host example.com --port 53 \
                  --payload-hex <DNS query hex> [--timeout 3s] [--user u --pass p]
```

Flow: TCP ASSOCIATE -> receive BND -> per §7 header-encapsulate the target and send the query -> wait for the response (parse the header, print source and payload length) -> EOF revocation. Exit code 0 = round trip succeeded. As an acceptance tool it is directly executable (no new dependencies; rillanectl already has tokio).

**Implementation landing point**: the core logic (negotiation / ASSOCIATE / header encapsulation / packet receive / RTT timing) is extracted into `apps/rillanectl/src/udp_probe.rs` as a standalone module (rillanectl is currently a single-file `main.rs`, this task splits out exactly this one module); the function signatures take `&str`/`Duration`/socket parameters -- integration tests call the same functions directly (S5 test plan), `main.rs` only does clap wiring and exit code mapping (§9-3).

## 4. Integration points with the P0-4 data plane (summary)

| Integration point | P0-5 side | P0-4 side (udp-mesh-dataplane.md) |
|--------|---------|--------------------------------|
| Metrics, surface family | §2.4's first five series rendered | `UdpFaceMetrics` atomics + `UdpFlowCache::{unknown_flow,evicted}` (absorbed into the snapshot) |
| Metrics, client side | §2.4 `rillane_udp_mesh_client_dropped_total` | `MeshUdpRelay.dropped` -> `UdpClientMetrics` process-level absorption (§2.4 ruling) |
| Config, plaintext gate | §1.5 (**landed**, sample backfill belongs to S6) | consumed by `MeshUdpGate::ensure_usable` (merge point is build()) |
| Config, shared timeout source | `UdpConfig.mapping_idle_secs` single source of truth | hop cache TTL = mapping_idle (P0-4 §3, wired via `with_udp_limits` in S5) |
| Snapshot | the `mesh` section of `/udp/stats` | `UdpFaceSnapshot` (**new in P0-5**: no snapshot surface existed when P0-4 landed) |
| Reachability seams | control plane reads via `Runtime` | **the Runtime holding path is filled in by P0-5**: (1) `get_udp_service()` (the `Runtime.udp` field exists but had no getter); (2) `mesh_plane: OnceLock<Arc<MeshDataPlane>>` -- P0-4's plane Arc currently only lives in start()'s local and spawned tasks, unreachable for observability, S3 backfills after `spawn_udp`; (3) `udp_client_metrics` -- build() extracts from the bridge before wrapping the `UdpChainRouter` |
| Link bytes | no separate series (§2.6) | `record_link_bytes` -> existing `rillane_mesh_link_bytes_total` |
| Acceptance layering | rendering/endpoint tests (P0-5 §10 each step) | forwarding behavior tests (P0-4 §10), no overlap |

## 5. Grafana panels (appended to docs/grafana/rillane-dashboard.json)

Row 1 "UDP sessions": `rillane_udp_sessions_active`, `rillane_udp_associates_active`, `rillane_udp_mappings_active`;
Row 2 "UDP traffic": `rate(rillane_udp_relay_bytes_total[1m])` by direction, `rate(rillane_udp_relay_packets_total[1m])`;
Row 3 "UDP quality": `rate(rillane_udp_dropped_total[1m])` by reason, `rate(rillane_udp_expired_total[1m])` by reason, `rillane_udp_reroutes_total` increments;
Row 4 "mesh UDP" (when P0-4 is enabled): `rillane_udp_mesh_flows_active`, `rate(rillane_udp_mesh_unknown_flow_total[1m])`, `rate(rillane_udp_mesh_forwarded_total[1m])`, `rate(rillane_udp_mesh_client_dropped_total[1m])` (client perspective, §2.4).

## 6. Acceptance alignment (upstream §5.5 + P0-2 leftover)

1. Example configs contain the §1 UDP block (`examples/` or `config/` samples updated); schema round-trip test: an old config without `udp:` still parses (serde default pinned);
2. `/metrics` contains all §2 series; types/HELP complete; when `udp.enabled=false` the series exist but are 0 (gauge 0/counter 0 -- the endpoint does not disappear because of a switch, the scrape side needs no branching);
3. Grafana panels show UDP series (dashboard json updated and checked in);
4. `udp.enabled=false` means no UDP socket listening anywhere (build assertion: UdpAssociateService is None; acceptance-phase integration port scan);
5. `rillanectl stats` shows the UDP section;
6. `rillanectl udp-probe` goes through the socks5 ingress -> session table -> direct egress to complete a DNS query round trip (full-path integration test, closing the P0-2 leftover);
7. All config items pass validate (illegal values error at build time).

## 7. Implementation landing points (file list)

| File | Content |
|------|------|
| `crates/rillane-config` | `UdpConfig` gains 5 fields + validate; `IngressConfig::{Socks5,Mixed}` gain `udp_enabled: Option<bool>`; `resolve_udp_enabled` pure function. (~~MeshConfig gains a field~~ -- landing audit: landed with P0-4 S5 in rillane-runtime, this task does not touch it, §1.5) |
| `crates/rillane-core/src/udp/metrics.rs` | `TableMetrics` gains `bytes_up/bytes_down`; `TableSnapshot` gains bytes; new `UdpIngressSnapshot` structure |
| `crates/rillane-core/src/udp/table.rs` | the 369/608 two existing count points accumulate table-level bytes incidentally (§2.5 landing audit) |
| `crates/rillane-core/src/udp/associate.rs` | `max_associates` cap (`try_register_associate` total gate); snapshot assembly |
| `crates/rillane-runtime/src/runtime_builder.rs` | per-ingress udp_enabled judgment (`build_ingress_endpoints` gains a parameter); new config field mapping (extract pure function `udp_session_config(&UdpConfig)`); `Runtime` gains the three observability seams `get_udp_service()` / `mesh_plane: OnceLock<..>` / `udp_client_metrics` (§4) |
| `crates/rillane-runtime/src/mesh_transport.rs` | `UdpFaceSnapshot` pub structure + `UdpFace::snapshot()` (merges the four metric values and two cache counters) + `MeshDataPlane::udp_snapshot()` |
| `crates/rillane-runtime/src/udp_chain.rs` | `UdpClientMetrics{dropped}` absorption (`MeshUdpRelay` field switched to a shared Arc, §2.4 ruling) |
| `apps/rillaned/src/control_plane.rs` | `/metrics` UDP series rendering (`push_gauge` / `push_metric_header`+`push_metric_labeled`, §2.1 landing audit); `/udp/stats` endpoint |
| `apps/rillaned/src/control_plane.rs` (at P1-2) | `rillane_tun_*` series rendering (definitions in [tun-dataplane.md](tun-dataplane.md) §2.8; not part of this item, see §9-5) |
| `apps/rillanectl/src/main.rs` + new `apps/rillanectl/src/udp_probe.rs` | stats UDP section; `udp-probe` subcommand (core logic library-ized in `udp_probe.rs`, §3.3) |
| `docs/grafana/rillane-dashboard.json` | §5's four panel rows |
| `config/rillane.yaml` | `udp:` commented sample block + mesh plaintext gate commented sample (landing audit: the repo sample is this file, no examples/ directory) |

## 8. Risks and open issues

- **R11 (reaffirmed)**: no target/host/user labels; if P2-1 needs per-link UDP detail, at that time establish separate series with a cardinality budget, do not change this document's closed enums;
- `rillane_udp_relay_bytes_total`'s table-level aggregation is relaxed accumulation under concurrency, possibly with transient tiny drift from the per-mapping snapshot (acceptable for monitoring use);
- `udp-probe`'s DNS payload is given as hex by the caller (no DNS encoder), keeping the tool's minimal surface.

## 9. Implementation detail completion (second-round review, 2026-09)

> Gap review product from the same round as P0-4 §13; the cross-document integration after P1-2 (tun-dataplane.md) lands is closed out together as well. Field names have been verified against the P0-2 implementation (`UdpIngressMetrics`, `rillane-core/src/udp/associate.rs:106`).

### 9-1 `/udp/stats` response example (§3.1 made precise)

The `ingress` section fields are the existing names of the `UdpIngressMetrics` atomics (pinned by P0-2, do not rename); the `table` section follows the implemented fields of `TableSnapshot` (P0-1), the example lists them per the metric-name columns; the `mesh` section = P0-4 §13-2's final form:

```json
{
  "table": {
    "sessions_active": 3, "sessions_total": 128, "mappings_active": 7,
    "reroutes": 2, "bytes_up": 1048576, "bytes_down": 2097152,
    "dropped": {"session_limit": 0, "mapping_limit": 0, "no_binding": 0,
                "shutting_down": 0, "send_failed": 1, "downlink_full": 0},
    "expired": {"idle": 120, "lifetime": 0, "revoked": 1}
  },
  "ingress": {
    "associates_active": 3, "associates_total": 45, "associate_rejected": 2,
    "associate_errors": 0, "uplink_packets": 1024, "downlink_packets": 980,
    "frag_dropped": 0, "source_dropped": 0, "malformed_dropped": 0
  },
  "mesh": {
    "forwarded_up": 512, "forwarded_down": 480, "malformed": 0,
    "unknown_flow": 3, "evicted": 0, "flows_active": 4
  },
  "mesh_client": {"dropped": 0}
}
```

(The `mesh` section is an object only when the P0-4 surface is enabled, `null` otherwise -- the "surface not enabled" and "zero traffic" states are distinguishable; the `mesh_client` section appears only when the client-side egress is assembled (chain+udp), when not assembled the key is omitted (§2.4 absorption ruling); the `table`/`ingress` sections are always present (all zeros when UDP is off, §6-2); the numbers are illustrative.)

### 9-2 `rillanectl stats` UDP section rendering style (§3.2 made precise)

```
UDP:
  sessions    3 active / 128 total (mappings 7 active)
  relay       1.0 MiB up / 2.0 MiB down (1024 / 980 packets)
  associates  3 active / 45 total (2 rejected)
  dropped     send_failed=1
  expired     idle=120 revoked=1
  mesh        512 up / 480 down (flows 4, unknown_flow 3)   <- when P0-4 is enabled
```

Zero-value lines still print (same criteria as §6-2 "series do not disappear because of a switch", the render side needs no branching).

### 9-3 `udp-probe` exit codes (§3.3 completion)

| Code | Meaning | stderr detail |
|----|------|------------|
| 0 | Round trip succeeded (response received and header parsed) | source address and payload length |
| 1 | TCP connect / SOCKS5 handshake / auth failure | phase and IO error |
| 2 | ASSOCIATE rejected (REP 0x01/0x07) | REP code and semantics (0x07 = ingress UDP off) |
| 3 | Timed out with no response (`--timeout`, default 3s) | bytes already sent |
| 4 | Response header parse failure | decode error |

Non-0 means failure, making it easy for scripts to pin acceptance #6.

### 9-4 per-ingress `udp_enabled` judgment pseudocode (§1.3 pinned)

```rust
fn resolve_udp_enabled(global_enabled: bool, per_ingress: Option<bool>) -> bool {
    per_ingress.unwrap_or(global_enabled)
}
```

- Evaluation point: `build_ingress_endpoints` calls once per ingress (the `UdpAssociateService` instance is still a global singleton, §1.3);
- `Some(true)` while globally off -> build-time warning (§1.3 semantics);
- Three tests pin the three states: None inherits / Some(false) off / Some(true) on.

### 9-5 Cross-document integration: `rillane_tun_*` (P1-2)

The tun-dataplane.md §2.8 `rillane_tun_*` family is rendered through this document's same rendering pipeline (`push_gauge` / `push_metric_header`+`push_metric_labeled` after the §2.1 landing audit), **no new endpoint/mechanism**; the §7 list has gained the P1-2 integration row. P0-5 does not render that family at implementation time (skipped when the series are undefined); after P1-2's T5 lands it appears automatically -- zero coupling on both sides.

## 10. Step-by-step implementation checklist S0-S6 (pre-assignment refinement, 2026-09-30)

> Format follows [udp-mesh-dataplane.md](udp-mesh-dataplane.md) §9.1.1: each step gets **landing point / dependencies / deliverables / test plan**; one step one commit, the full repo test suite stays all green before moving to the next step (following the P0-4 rhythm).
> Dependency chain: **S0 and S1 do not depend on each other (parallelizable) -> S2 depends on S0+S1 -> S3 depends only on P0-4 (landed, can run parallel with S0-S2) -> S4 depends on S2+S3 -> S5 depends on S4 -> S6 wraps up** (panel query names use S4's finalized series names as the source of truth).

### S0 config surface (rillane-config)

- **Landing point**: `crates/rillane-config/src/lib.rs` -- `UdpConfig` gains the §1.2 table's 5 fields (serde all `#[serde(default)]` + default constants), `UdpConfig::validate()` gains constraints (`sweep_interval_secs >= 1`, `max_mappings >= 1`, `session_lifetime_secs` when present `>= session_idle_secs`, `downlink_queue_depth >= 1`, `max_associates >= 1`), `IngressConfig::{Socks5, Mixed}` gain `#[serde(default)] udp_enabled: Option<bool>`, `pub(crate) fn resolve_udp_enabled` (§9-4, consumed by S2).
- **Dependencies**: none.
- **Test plan** (appended to rillane-config's existing test files):
  1. `udp_config_defaults_backward_compatible` -- a YAML without the `udp:` block / one with the old 5 fields missing the new fields, both parse successfully and the new fields equal §1.2's defaults (acceptance #1 first half);
  2. `udp_config_validate_rejects_illegal` -- sweep=0 / max_mappings=0 / lifetime<idle / queue_depth=0 / max_associates=0, five groups each `Err` (acceptance #7);
  3. `resolve_udp_enabled_three_states` -- None inherits global / Some(false) explicitly off / Some(true) explicitly on (§9-4's three lines pinned);
  4. `ingress_udp_enabled_serde_roundtrip` -- socks5 and mixed entries with/without `udp_enabled` serialize round-trip equivalently (missing field = None).

### S1 core counting and caps (rillane-core)

- **Landing point**: `metrics.rs` -- `TableMetrics` gains `bytes_up/bytes_down: AtomicU64` (+read methods), `TableSnapshot` gains the two fields, new `UdpIngressSnapshot` (field names = the existing `UdpIngressMetrics` atomic names, §9-1's ingress section's nine fields); `table.rs` -- the 369/608 two points accumulate incidentally (§2.5 landing audit); `associate.rs` -- `UdpAssociateService` gains `max_associates` (constructor parameter, default 256 passed by caller S2), `try_register_associate` gains a total gate (currently only same-peer dedup, rejects when `active.len() >= max`).
- **Dependencies**: none (unrelated to S0).
- **Test plan** (appended to rillane-core/tests):
  1. `table_bytes_aggregate_tracks_mappings` -- after several up/down packets of a single session, table-level `bytes_up/down` == the per-mapping snapshot sum; then concurrent writes assert monotonic non-decrease and the final values agree (reuse the existing concurrency stress scaffolding);
  2. `max_associates_cap_rejects_and_counts` -- with max=2, two different peers register successfully, the third returns false and `associate_rejected` +1; repeated registration by the same peer keeps the existing rejection semantics;
  3. `ingress_snapshot_fields_complete` -- after driving the various events, assert the nine fields of `UdpIngressSnapshot` one by one (including zero-value fields being present, §6-2 criteria).

### S2 runtime wiring (rillane-runtime/runtime_builder)

- **Landing point**: build()'s UDP block -- change `UdpSessionConfig{..Default::default()}` to an explicit mapping (extract pure function `udp_session_config(&UdpConfig) -> UdpSessionConfig`, covering all five S0 fields); pass `max_associates` to `UdpAssociateService::new`; `build_ingress_endpoints` gains a global switch parameter, each ingress uses `resolve_udp_enabled(global, desc.udp_enabled)` to decide whether to pass `Some(Arc::clone(udp))` or `None` (the service instance is still a global singleton, §1.3); `Some(true)` while globally off -> one `tracing::warn!(target: "rillane::boot", ...)` (§2.7); `Runtime` gains `get_udp_service()`.
- **Dependencies**: S0 (fields/judgment function) + S1 (the `max_associates` parameter).
- **Test plan** (runtime_builder tests, following P0-4 S5's build-level four-test format):
  1. `udp_session_config_mapping` -- the pure function asserted field by field against a sample `UdpConfig` (including `session_lifetime_secs` None/Some both states), guarding against "field added but not wired";
  2. `per_ingress_override_disabled_entry_rejects_associate` -- globally on + socks5 explicit `udp_enabled: false`: starting that ingress (127.0.0.1:0) and sending CMD 0x03 gets 0x07, another mixed ingress is unaffected and can accept (P0-2 tests provide ASSOCIATE send/receive scaffolding; §1.3's three states verified at behavior level);
  3. `per_ingress_override_true_enables_when_global_off` -- globally off + mixed explicit true: that ingress can accept ASSOCIATE (the build-time WARN is not strongly tested, the judgment and assembly are the standard);
  4. `udp_disabled_all_ingress_closed` -- globally off and no overrides: all ingresses CMD 0x03 -> 0x07 (acceptance #4's build assertion half; the port scan half belongs to the acceptance phase).

### S3 mesh surface observability assembly (rillane-runtime: mesh_transport + udp_chain)

- **Landing point**: `mesh_transport.rs` -- `pub struct UdpFaceSnapshot` (six fields: `forwarded_up/forwarded_down/malformed/flows_active/unknown_flow/evicted` -- the last two absorbed from `UdpFlowCache`, guarding against double counting, criteria unchanged), `UdpFace::snapshot()`, `MeshDataPlane::udp_snapshot() -> Option<UdpFaceSnapshot>`; `udp_chain.rs` -- `UdpClientMetrics{dropped}` (§2.4 absorption ruling); `runtime_builder.rs` -- `Runtime` gains `mesh_plane: OnceLock<Arc<MeshDataPlane>>` (set by start() after `spawn_udp`, exactly once, observability read-only, no ArcSwap introduced) and `udp_client_metrics: Option<Arc<UdpClientMetrics>>` (build() extracts from the bridge before wrapping the `UdpChainRouter`) + two getters.
- **Dependencies**: only P0-4 (landed), parallel with S0-S2.
- **Test plan** (mesh_transport/udp_chain tests, reusing the T2/T7 scaffolding):
  1. `udp_face_snapshot_after_roundtrip` -- after a T2-style two-hop small flow, assert `udp_snapshot()` values on both sides (exit: forwarded_up/down=2, flows_active=1, unknown_flow/evicted/malformed=0);
  2. `udp_client_metrics_shared_across_relays` -- two `associate` calls on the same bridge, inject a non-matching downlink packet (dir=Up response) into one of them -> the shared `dropped` accumulates across relays (absorption semantics pinned);
  3. `runtime_mesh_plane_backfilled_after_start` -- reuse the S5 test helper (chain+udp+explicit plaintext) start() on 127.0.0.1:0, then `get_mesh_udp_snapshot()` is `Some` and all zeros; a client-only build (no gate) returning `None` is pinned by the same test.

### S4 control plane rendering (apps/rillaned/control_plane)

- **Landing point**: `handle_metrics` appends all §2 series (unlabeled gauges go through `push_gauge`; direction/reason series go through `push_metric_header(counter)` + one `push_metric_labeled` per closed enum member, §2.1 landing audit); new route `(GET, "/udp/stats")` -> `handle_udp_stats` (§3.1/§9-1 JSON, with the `mesh` null two-state and the conditional `mesh_client` key).
- **Dependencies**: S2 (getters/data reachability) + S3 (mesh snapshot).
- **Test plan** (rillaned tests):
  1. `metrics_contains_full_udp_family` -- request `/metrics` from a default runtime with udp off: §2.2/§2.3/§2.4 series names each hit with value 0 (acceptance #2; always-render criteria);
  2. `metrics_udp_counters_after_traffic` -- after socks5 ASSOCIATE + loopback echo (P0-2 integration precedent), `rillane_udp_relay_packets_total{direction="up"}` >= 1 and the bytes series nonzero;
  3. `udp_stats_endpoint_shape` -- `/udp/stats` deserializes aligned with the §9-1 structure; the `mesh` key's two states (null when not enabled / object when enabled) each get a test.

### S5 rillanectl (apps/rillanectl)

- **Landing point**: `main.rs` (stats changes §3.2 + `udp-probe` subcommand clap wiring and exit code mapping §9-3) + new `udp_probe.rs` (§3.3 core logic).
- **Dependencies**: S4 (the `/udp/stats` endpoint; probe only depends on the socks5 ingress, but is uniformly sequenced after S4 for closeout).
- **Test plan** (rillanectl tests):
  1. `udp_probe_roundtrip_against_local_stub` -- an in-process minimal socks5 UDP echo stub (TCP negotiation + ASSOCIATE reply + UDP loopback, real socket, unprivileged, same method as P0-2) -> `udp_probe::run()` Ok and RTT > 0, source/length backfill correct (acceptance #6 at stub level);
  2. `udp_probe_rejected_maps_exit_code_2` -- the stub replies REP 0x07 -> exit code 2, stderr contains the "ingress UDP off" semantics;
  3. `udp_probe_timeout_maps_exit_code_3` -- the stub swallows packets without replying -> a 1ms-scale timeout triggers exit code 3;
  4. `stats_udp_section_render` -- given §9-1's JSON -> assert §9-2's text line by line (pure function, zero network).
  - The real rillaned full path (probe -> rillaned -> direct egress -> loopback DNS-style target) is left to the acceptance phase for manual/script execution (acceptance #6's full criteria); CI does not depend on the external network.
- **Note**: `udp-probe`'s SOCKS5 auth parameters (`--user/--pass`) only implement no-auth and username/password (METHOD 0x00/0x02), aligned with the ingress's existing capability, no extended negotiation.

### S6 samples and panels (config/ + docs/grafana/ + doc backfill)

- **Landing point**: `config/rillane.yaml` -- `udp:` commented sample block (all fields + the "changes take effect on restart" note §1.6) + mesh plaintext gate commented sample (§1.5); `docs/grafana/rillane-dashboard.json` -- §5's four panel rows (query names = S4's finalized series names); todo.md check-off and PROTOCOLS.md/README status backfill.
- **Dependencies**: S4 (series names finalized); can run parallel with S5.
- **Test plan**:
  1. `grafana_dashboard_json_parses` -- rillaned tests read `docs/grafana/rillane-dashboard.json` (relative path `CARGO_MANIFEST_DIR/../../`), serde_json parse + assert it contains `rillane_udp_` query strings (guards against manual edits breaking the JSON or dropping series);
  2. `sample_config_parses_with_udp_block` -- `config/rillane.yaml` in full parses successfully through `RillaneConfig::from_str` (the sample is the documentation, a broken sample goes red at build time);
  3. docs internal link validation (`npm run build` dead link check, the repo's existing gate).

### Acceptance mapping (§6 -> steps)

| §6 acceptance item | Carrying step |
|----------|---------|
| #1 example config contains the UDP block + old config compatibility | S0 (test 1) + S6 (sample on disk) |
| #2 /metrics full series always present | S4 (tests 1/2) |
| #3 Grafana panel shows UDP series | S6 (test 1 + dashboard checked in) |
| #4 udp.enabled=false no UDP listening | S2 (test 4, build/behavior assertion) + acceptance-phase port scan |
| #5 rillanectl stats shows the UDP section | S5 (test 4) |
| #6 udp-probe full-path round trip | S5 (tests 1-3 stub level) + acceptance-phase full path |
| #7 all config items pass validate | S0 (test 2) |
