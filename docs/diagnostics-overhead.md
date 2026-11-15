# Diagnostics overhead and retention (RIL-064)

Comparison of the diagnostic collection face (bounded event collector + per-connection query service) across the default limits and the off / sampled / full modes, plus the retention contract.

**Honest scope:** the session data path is not wired to the collector yet (trace admission has no production call site until that landing), so this report measures the collector + query face itself — not end-to-end per-connection overhead. Numbers below are debug-build measurements from the overhead harness (`cargo test -p rillane-core --test collector_overhead -- --nocapture`); release builds are faster. Re-measure after the data-path wiring lands.

## Modes compared (daemon default shape: capacity 1024 / active cap 256 / per-flow 256 / TTL 1h; only the switch and sample denominator change)

| Mode | 8 000 new flows, admit avg | Traces admitted | Notes |
|------|------|------|------|
| off (`enabled: false`) | 0.28 µs | 0 | total no-op — one boolean check on the write path |
| sampled (`sample: 10`) | 0.80 µs | 256 | deterministic 1-in-10; the rest answer with explicit tombstones; active cap holds residency at 256 |
| full (`sample: 1`, default) | 4.77 µs | 8 000 | ring capacity evicts oldest, eviction counters visible |

Query face (hit path, 1024-trace linear scan, 2 000 lookups): p50 53 µs / p95 72 µs / p99 82 µs (debug build).

RSS delta of the harness process across the full-mode run: ~0.5 MiB — bounded by the ring capacity, not by traffic volume.

## Retention contract (history can expire / be deleted)

- **Expire:** TTL sweep runs every 60 s in the runtime (spawned by `Runtime::start`; missed ticks are skipped — best-effort maintenance). Expired traces leave `collector.flow.expired` tombstones; `traces_expired` is visible in every absence answer.
- **Delete:** `DELETE /trace/history` (operator, authenticated when `admin_token` is set) purges all closed traces immediately — active flows are never torn down. Purged traces answer `collector.flow.purged`, distinct from "never seen". The endpoint answers a versioned envelope `{schema_version: 1, purged: N}`; an empty collector answers `0`, never a fabricated count.
- **Bounded by construction:** ring capacity bounds residency; tombstones share the same bound; the per-flow event cap bounds any single trace. Nothing grows with traffic volume.

## Metric label hygiene

- The `/metrics` label key universe is a fixed, reviewed allowlist (`direction`, `egress`, `from`, `ingress`, `mode`, `name`, `origin`, `quantile`, `reason`, `result`, `source`, `subscription`, `to`, `type`) — a contract test rejects any new key until it is added to that list.
- No per-connection identity is used as a label value: values are config-defined names (ingress/egress), mesh node ids, or fixed enums — bounded by configuration, never by traffic.
- Label values are asserted to never be address-shaped (`ip:port` or bare IP) — high-cardinality identity cannot slip in as a label.
- Secrets (`control.admin_token`, subscription URL credentials) never appear in `/metrics` output (asserted in the same test).

## Harness

`crates/rillane-core/tests/collector_overhead.rs` prints the table above and pins conservative upper bounds (off-mode sub-µs admit, full-mode µs-scale p99 admit, tens-of-µs lookup p99) — a quadratic regression in the collector fails the test on any machine.
