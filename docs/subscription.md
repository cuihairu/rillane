# Subscription guide (current state)

> Status: fetching/conversion/reload exists; Clash/Mihomo semantic compatibility is partial (`crates/rillane-subscription`) · Related: [architecture.md](architecture.md) · [mesh.md](mesh.md) · the Rillane DSL schema is defined in `crates/rillane-subscription/src/rillane_dsl.rs`

2026-11-14 clarification: provider/use models and rule sets are incomplete; imported process rules are skipped; fallback/relay change semantics. The [architecture study](research/proxy-architectures-2026-11-14.md#verified-gaps) records code evidence and the [target design](design/architecture-v2.md#subscription-compatibility) defines migration gates.

## Executive summary

The Rillane subscription chain covers: fetch (conditional requests/proxy/custom headers) -> type auto-detection (Clash YAML / share links / base64) -> conversion into `RillaneConfig` -> TTL+LRU cache -> two-level scheduled refresh (reload skipped when the content hash is unchanged) -> control-plane CRUD and hot reload. This page describes each stage and its boundaries against the actual code.

There is also an offline conversion surface: `rule_source.rs` (O-dns1, 2026-10-10) parses geosite/chnroutes text rule sources into routing/DNS partition rule fragments (fed by `rillanectl import-rules`), bypassing the subscription cache chain.

## 1. Subscription sources and type detection

- Supported source types: **Clash YAML** (proxies/proxy-groups/rules) and **share link lists** (`vmess://`, `vless://`, `trojan://`, `hysteria2://`/`hy2://`, `ss://`, see `converter.rs`); link lists encoded as base64 as a whole are decoded automatically (`try_decode_base64`).
- Type auto-detection: `Subscription::detect_type` decides from content characteristics, no manual specification needed.
- Content validation: after fetching, `validate_content` checks non-emptiness and basic shape, so an empty response cannot overwrite the current config.

## 2. Fetch (`fetcher.rs`)

- Built on `reqwest` (rustls); configurable: timeout, User-Agent, custom request headers, outbound proxy (`with_proxy`), redirect policy.
- **Conditional requests**: `ETag` / `Last-Modified` are recorded and sent back; a 304 from the server hits the cache and skips re-conversion.
- The fetch result `FetchResult` carries response header metadata and the final content.

## 3. Conversion into RillaneConfig (`clash.rs` + `converter.rs`)

| Clash concept | Rillane mapping |
|-----------|----------|
| `proxies` | `egress` (the `EgressConfig` variants) |
| `proxy-groups` | `routing.groups` (`PolicyGroup`; mappings are partial and do not preserve every group algorithm) |
| `rules` | `routing.rules` |

- When conversion produces an **egress type not implemented yet** (e.g. hysteria v1 -- schema/subscription conversion supports it, the egress connector is missing) it is not silently dropped: it errors at the runtime build (`RuntimeBuilder`) stage with a message. Protocol implementation boundaries are in the status notes of [PROTOCOLS.md](PROTOCOLS.md).
- **Transport layer fields** (`network` + each `*-opts` block, completed with the protocol batch in 2026-10): import recognizes `network: tcp | ws | grpc | h2` and `ws-opts` (path / `headers.host`, Host header key accepted in three casings; flat `path`/`host` as fallback), `grpc-opts` (`grpc-service-name` canonical key + variant aliases), `h2-opts` (path/host, host accepted as a scalar or an array); SS `plugin`/`plugin-opts` convert to SIP003 per a translation table (the obfs family -> `obfs-local`, v2ray-plugin passed through with original key/value names, any other plugin name is rejected rather than imported loosely). Export is symmetric: ws/h2 emit a block per `network` (trojan does not produce h2 -- rillane's trojan whitelist has no h2 scope), `grpc-opts` only when `network=grpc`; SS plugins have no Clash equivalent, so export degrades with a notice instead of producing anything. `network` values outside rillane's whitelist error at RuntimeBuilder build time.
- Export into the native Rillane DSL and re-import is also supported (`rillane_dsl.rs`): `version/meta/nodes (auth/transport/tls/location)/groups (strategy, nested members)/rulesets`, with a validator.
- **Rillane -> Clash reverse export** (`clash_export.rs`, 2026-10-07): `ClashExporter::export(&RillaneConfig)` produces Clash YAML plus a report (exported/degraded lists). proxies cover ss/vmess/vless/trojan/http(s)/socks5/hysteria2/hysteria/wireguard (direct maps to the built-in `DIRECT` and produces no proxy); rules only when a single condition can be linearized (rillane multi-condition AND is not the same as Clash's first-match-stop, so multi-condition rules are skipped and ledgered); group policies Fixed->select, Latency->url-test (generate_204/300s), Random/Weighted/Bandwidth/RoundRobin->load-balance(round-robin), ConsistentHash->load-balance(consistent-hashing); field-level items with no counterpart (e.g. `tls_fingerprint`) are added to `skipped` one by one without blocking export.

## 4. Cache and refresh (`cache.rs` + `lib.rs`)

- `SubscriptionCache`: TTL + LRU two-dimensional eviction, default cleanup interval 1 hour; exposes stats such as hit rate (`CacheStats`).
- Two-level refresh cadence: per-subscription `refresh_interval` (minutes) and a global refresh loop (default one round every 300 seconds, `needs_refresh` decides expiry).
- **Change detection**: when the content hash (`has_content_changed`) is unchanged, conversion and runtime reload are skipped, avoiding invalid hot reloads.

## 5. Control plane and hot reload

Control plane (`control.api_bind`, authentication in the Auth subsection of [mesh.md](mesh.md)):

| Endpoint | Behavior |
|------|------|
| `GET /subscriptions` | list subscriptions with status (last refresh/error) |
| `POST /subscriptions` | add a subscription |
| `POST /subscriptions/refresh` | refresh all |
| `POST /subscriptions/{name}/refresh` | refresh one subscription |
| `DELETE /subscriptions/{name}` | delete a subscription |

- A successful refresh with content changes triggers a runtime hot reload (routing/group/egress rebuild), and subscription events are counted in metrics (`inc_subscription_event`).
- The config file itself is **not watched automatically at the moment**: rillaned reads config once at startup, and `rillane-runtime::HotReloadManager` (`watch_config_file`) is an exported capability that rillaned does not wire up -- changing config requires restarting the process or triggering a hot reload through subscriptions/the control plane.

## 6. CLI

```bash
rillanectl import-clash <url|file> --output rillane.yaml   # offline conversion preview (no daemon; -o is equivalent, default config/clash_import.yaml)
rillanectl export-clash <rillane config> -o clash.yaml     # Rillane -> Clash reverse export (offline; default config/clash_export.yaml, prints the degraded/skipped list at the end)
rillanectl import-rules <url|file> --target <group or egress> [--face routing|dns]  # batch import of geosite/chnroutes text rule sources (O-dns1; default stdout, --out writes a file; skip list goes to stderr)
rillanectl subscription list|add|remove|refresh      # managed through the control plane
```

Full `rillanectl` flags (including `--header`/`--refresh-interval`/`--timeout` units) and control-plane endpoint semantics are in [cli.md](cli.md).

## 7. Boundaries and not landed

- Subscription fetch has no built-in timed retry/backoff yet (failures rely on the next global refresh round to retry);
- "Clash -> Rillane" import and "Rillane -> Clash" reverse export are both implemented (`clash.rs` / `clash_export.rs`); native Rillane DSL (`rillane_dsl.rs`) -> Clash is not implemented;
- The conversion granularity of subscription rulesets is limited by the coverage of Clash rule types; uncovered types are noted at conversion time.
