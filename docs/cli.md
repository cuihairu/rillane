# rillanectl CLI reference

This page describes existing commands; use `rillanectl <command> --help` for current flags/defaults. See [subscriptions](subscription.md), [Mesh](mesh.md) and [capture](networking.md). v1 Explain/Trace/Probe/MCP are [proposed](design/debug-and-mcp.md), not current commands.

## Global options

| Option | Description |
|------|------|
| `-c, --config <CONFIG>` | config file path (default `config/rillane.yaml`); control-plane commands use it to read `control.api_bind` / `control.admin_token` |
| `-V, --version` | print version |

## Data sources

- **Control-plane commands** (`stats` / `group` / `switches` / `nodes` / `chain` / `pool` / `subscription` / `route` / `diagnose` / `mtls revoke status`): HTTP against the `rillaned` control plane; when `control.admin_token` is non-empty an `x-admin-token` header is attached, otherwise the request is anonymous.
  - `--endpoint` comes in two flavors (easy to confuse):
    - **Full-URL flavor** (replaces the whole target URL, must include the path): `stats` (default `http://{api_bind}/flows`), `group` (`/routing/stats`), `switches` (`/mesh/switches`), `pool status` (`/egress/pool/stats`), `nodes` (`/nodes`);
    - **Base-URL flavor** (replaces only the base, path appended internally): `chain`, `subscription`, `route`, `diagnose`, `trace`, `mtls revoke status`.
- **Offline commands** (`check` / `show` / `profile` / `tls-fingerprint` / `import-rules` / `udp-probe` / `import-clash` / `export-clash` / the `mtls` cert tools): no control plane, only local files are read (exception: `udp-probe` dials the SOCKS5 ingress directly).
- There is no `rillanectl reload` subcommand: rillaned reads config once at startup, and runtime hot reloads are driven only by subscription refresh and control-plane endpoints (see the hot-reload scope in [architecture.md](architecture.md)).

## Control-plane REST endpoint reference

Reconciled against the routing table in `apps/rillaned/src/control_plane.rs` (2026-10-11). Unless noted, all require the `x-admin-token` header (when `control.admin_token` is configured non-empty).

| Method | Path | Description | rillanectl counterpart |
|------|------|------|--------------|
| GET | `/health` | liveness probe | — |
| GET | `/nodes` | mesh node snapshot | `nodes` |
| GET | `/flows` | cumulative ingress->egress traffic stats | `stats` |
| GET | `/udp/stats` | UDP session/relay stats snapshot | `stats` (UDP section fetched together) |
| GET | `/routing/stats` | real-time group quality (member data source/p95/quality ratio (source-dependent)/SLO gate/current selected endpoint) | `group` |
| GET | `/mesh/switches` | chain switch ledger (last 100) | `switches` |
| GET | `/egress/pool/stats` | egress connection pool snapshot | `pool status` |
| GET | `/dns/stats` | DNS service stats snapshot | — (REST only) |
| GET | `/plugins/stats` | plugin stats | — (REST only) |
| GET | `/runtime/stats` | runtime stats | — (REST only) |
| GET | `/runtime/config` | snapshot of the currently effective config | — (REST only) |
| GET | `/events` | event log (last N lines) | — (REST only) |
| GET | `/logs` | recent logs (requires `RILLANE_CAPTURE_LOGS=1`) | `diagnose` (collects) |
| GET | `/metrics` | Prometheus text | — (Prometheus scraping) |
| GET | `/mtls/revoked` | effective view of the revocation list (mtime/entries/load errors) | `mtls revoke status` |
| GET | `/chains/stats` | chain stats | `chain stats` |
| GET | `/chains/{chain_id}` | chain details | `chain get` |
| POST | `/chains/dry-run` | chain pre-check | `chain dry-run` |
| POST | `/chains` | create a chain (reuses the same session_id) | `chain create` |
| DELETE | `/chains/{chain_id}` | terminate a chain | `chain terminate` |
| GET | `/subscriptions` | subscription list with status | `subscription list` |
| POST | `/subscriptions` | add a subscription | `subscription add` |
| POST | `/subscriptions/refresh` | refresh all | `subscription refresh` |
| POST | `/subscriptions/{name}/refresh` | refresh one subscription | `subscription refresh <NAME>` |
| DELETE | `/subscriptions/{name}` | delete a subscription | `subscription remove` |
| POST | `/network/route/apply` | apply route rules (idempotent) | `route apply` |
| POST | `/network/route/clear` | undo applied rules | `route clear` |
| GET | `/network/route/status` | route application status | `route status` |
| POST | `/mesh/nodes/register` | node registration (internal to the mesh plane) | — (inter-node) |
| POST | `/mesh/link-states` | link state reporting (internal to the mesh plane) | — (inter-node) |
| GET | `/trace/flows` | per-connection trace list (paged, filtered; versioned envelope `schema_version=1`) | `trace list` |
| GET | `/trace/flow?id=` | one flow's full trace, or an explicit absence answer (`found:false` + stable code) | `trace flow` |
| GET | `/trace/flow.svg?id=` | one flow's path as SVG (same query snapshot as the JSON answer; layers/time/gaps annotated) | `trace flow --svg` |
| GET | `/trace/events?id=&from_seq=&limit=` | incremental event read (unknown/absent id → 404 + stable code) | `trace events` |
| GET | `/probe` | probe job list (limits + job snapshots) | `probe list` |
| GET | `/probe/result?id=` | one job's measurement snapshot, or an explicit absence answer (`found:false` + stable code) | `probe result` |
| POST | `/probe` | submit a probe job (target must be registered in the server's probe scope) | `probe submit` |
| POST | `/probe/cancel?id=` | cancel a job (queued → immediate final state; running → cooperative cancel request) | `probe cancel` |

## Command overview

| Command | Description | Surface |
|------|------|----|
| `check` | validate a config file | offline |
| `show` | print a config summary | offline |
| `stats` | view traffic stats (UDP section appended: sessions/relay bytes/drops/expiry/mesh plane) | control plane `/flows` |
| `group` | view real-time group quality: member data source, p95/quality ratio (source-dependent), SLO gate decisions, the latency group's current selected endpoint | control plane `/routing/stats` |
| `switches` | view the chain switch ledger (last 100 events, with before/after paths and reasons) | control plane `/mesh/switches` |
| `profile` | generate a scenario skeleton config (`proxy\|game\|web`) | offline |
| `tls-fingerprint` | TLS fingerprint preset comparison table (four-dimension shape_material export of none/chrome/ios/safari) | offline |
| `import-rules` | batch import geosite/chnroutes text rule sources as routing/DNS rule YAML | offline |
| `udp-probe` | UDP ASSOCIATE integration probe (minimal RFC 1928 client; exit codes 0-4) | dials the SOCKS5 ingress directly |
| `nodes` | view mesh node registration info | control plane `/nodes` |
| `chain` | chain management (dry-run/create/get/terminate/stats) | control plane |
| `pool` | egress connection pool snapshot (status) | control plane `/egress/pool/stats` |
| `import-clash` | Clash YAML -> Rillane config (offline preview) | offline |
| `export-clash` | Rillane config -> Clash YAML reverse export (offline) | offline |
| `subscription` | subscription management (list/add/remove/refresh) | control plane |
| `route` | system route management (apply/clear/status) | control plane + local ip commands |
| `diagnose` | one-shot diagnostics collection (creates a diagnostics directory) | control plane + local snapshot |
| `trace` | per-connection trace queries (list / flow detail / incremental events; explicit absence = exit 2) | control plane `/trace/*` |
| `probe` | active probe jobs (submit/cancel/result/list; measurements only, no provider-internal path inference) | control plane `/probe*` |
| `mtls` | mesh mTLS certificate tools (init-ca/issue/rotate/bundle-ca/rotate-ca/revoke) | offline (except revoke status, which uses the control plane) |

## Flags per command

### Control-plane data

```bash
rillanectl stats   [--endpoint <full URL including /flows>]
rillanectl group   [--endpoint <full URL including /routing/stats>]
rillanectl switches [--endpoint <full URL including /mesh/switches>]
rillanectl nodes   [--endpoint <full URL including /nodes>]
rillanectl pool status [--endpoint <full URL including /egress/pool/stats>]
```

The UDP section of `stats` is derived from the same base as `/flows`: the `--endpoint` override only affects the `/flows` side.

### check / show

No flags; the config is given through the global `-c`. `show` prints a summary (control-plane listen address + ingress/egress counts); `check` prints "config valid".

### profile

```bash
rillanectl profile <proxy|game|web> [--out <path>]   # default prints to stdout
```

### tls-fingerprint

No flags; prints the comparison table of `shape_material` shape strings for the four presets (version|cipher suite|group|signature scheme).

### import-rules

```bash
rillanectl import-rules <SOURCE> --target <TARGET> [--face routing|dns] [--name <NAME>] [--out <path>]
```

- `<SOURCE>`: a file path or http(s) URL (a v2fly text manifest line set);
- `--target`: routing face = a group/egress name; dns face = `domestic | trusted`;
- `--face`: defaults to `routing`;
- `--name`: rule name, defaults to the source file name without extension;
- `--out`: defaults to stdout (pipeable); the skip list goes to **stderr**.

### udp-probe

```bash
rillanectl udp-probe --socks5 <address> --host <host> --port <port> --payload-hex <hex>
                  [--timeout <3s>] [--user <U>] [--pass <P>]
```

`--timeout` accepts `s/ms/m` units; exit code 0-4 semantics are in `--help`.

### chain

```bash
rillanectl chain dry-run   --source <S> --target <T>
rillanectl chain create    --source <S> --target <T> [--session-id <UUID>]   # reuses the chain for the same session_id
rillanectl chain get       <CHAIN_ID>
rillanectl chain terminate <CHAIN_ID>
rillanectl chain stats
```

`--endpoint` for the `chain` group is the **base-URL flavor**.

### import-clash / export-clash

```bash
rillanectl import-clash <url|file> [-o config/clash_import.yaml]   # -o is equivalent to --output
rillanectl export-clash <rillane config> [-o config/clash_export.yaml]   # prints the degraded/skipped list at the end
```

### subscription

```bash
rillanectl subscription list
rillanectl subscription add <NAME> <URL> [--type <T>] [--enabled true|false]
                       [--refresh-interval <min>] [--timeout <sec>]
                       [--header k=v]... [--user-agent <UA>]
rillanectl subscription remove <NAME>
rillanectl subscription refresh [NAME]    # refreshes all when no name given
```

`--header` can be passed multiple times. `--endpoint` is the base-URL flavor.

### route

```bash
rillanectl route apply   [--dry-run]   # idempotently replays the include targets from the config; --dry-run only prints the ip commands
rillanectl route clear               # removes all applied rules in reverse order
rillanectl route status              # device state + table of applied steps
```

`--endpoint` is the base-URL flavor. apply/clear need root or `CAP_NET_ADMIN`.

### diagnose

```bash
rillanectl diagnose [--endpoint <base URL>] [--output <dir>] [--scope safe|full|raw] [--no-redact] [--no-local]
```

Scope selection (default `safe`): `safe` omits the subscription list, runtime config and full logs and redacts the config; `full` collects everything but strips secrets on every exit (config secret keys, subscription URL credentials, log key=value pairs and PEM blocks); `raw` writes the bundle unredacted — the manifest marks it `ai_upload_policy: do-not-upload` (local human inspection only). `--no-redact` is equivalent to `--scope raw`; `--no-local` skips the local snapshot (routes/DNS/interfaces). `meta.json` always records the scope, the review-required file list, and the upload policy — rillanectl never uploads a bundle anywhere; bundles are not automatically safe for AI upload, review before sharing.

### trace

```bash
rillanectl trace list   [--state active|closed] [--origin stream|association] [--generation <G>] [--offset N] [--limit N] [--json]
rillanectl trace flow   <id> [--json] [--svg]
rillanectl trace events <id> [--from-seq N] [--limit N] [--json]
```

Per-connection trace queries against the kernel's flow query service (RIL-060). `--endpoint` is the base-URL flavor (default `http://{api_bind}`). Anchored on real flow IDs — the ingress/egress aggregate keys shown by `stats`/`/flows` never resolve as flow IDs here. Absence is explicit and coded (`query.flow.unknown` / `query.tracing.disabled` / `collector.flow.evicted|expired|active_limit|sampled_out|drained`); an absent answer always carries the collector counter snapshot and the fixed note "no record is not evidence of no traffic" — absence is never reported as "the app sent no packets". Text output is default; `--json` prints the versioned envelope (`schema_version=1`) verbatim.

Exit codes: `0` query answered; `1` connection or usage error; `2` explicit absence (`trace flow` answered `found:false`, or `trace events` got a 404 error envelope).

`trace flow <id> --svg` exports the path graph (RIL-062, `GET /trace/flow.svg?id=`). The SVG is rendered from the same query snapshot as the JSON answer — graph and JSON always agree. Events are grouped into separate lanes and never mixed: L3 (takeover/identity/dns/sniff), plan (rule/route plan), connection (attempt/egress/transfer/close); the mesh ledger is deliberately kept out of the graph (it lives at `/mesh/switches`). The time axis is the monotonic clock with explicit gap annotations for large inter-event deltas; lanes with no events say so instead of fabricating ticks. All embedded text (flow id, generation, event details) is XML-escaped, control-character-replaced and length-bounded — long or malicious names cannot break the document. Absence stays coded: an unknown id answers 404 with a stable code envelope (exit 2), never an empty picture. `--svg` and `--json` are mutually exclusive.

### probe

```bash
rillanectl probe submit --kind dns|connect|udp-echo [--host <H>] [--addr <ip:port>] [--payload-len N] [--json]
rillanectl probe cancel <id> [--json]
rillanectl probe result <id> [--json]
rillanectl probe list [--json]
```

Explicit active-probe jobs against operator-registered targets (RIL-061). The target must be in the daemon's `probe.targets` scope (operator config only — subscription text can never extend the scope); an out-of-scope submit is rejected with a stable code (`probe.target.out_of_scope`). With no `probe` block in the config the whole surface is off and every endpoint answers `503 probe.disabled` — no authorization, no network side effects. Measurements are exactly what the executor observed: `failure` (stable code + detail) or null, `rtt_ms` (null when nothing answered — never synthesized), and for UDP echo `sent`/`replies`/`loss_ratio`/`payload_len` (loss ratio computed from the reply counts). Measurements never include provider-internal path inference. Proxy-handshake probing is not offered in this version (the egress connector is a flow-level forward surface without a dial-and-measure shape), so no handshake kind exists on the CLI or in the config. Text output is default; `--json` prints the versioned envelope (`schema_version=1`) verbatim.

Exit codes: `0` answered; `1` connection, rejection or usage error; `2` explicit absence (`probe result` for an unknown job id).

### mtls

```bash
rillanectl mtls init-ca    --out-dir <dir> [--common-name rillane-mesh-ca] [--valid-days 3650]
rillanectl mtls issue      --node-id <ID> --ca-cert <pem> --ca-key <pem> --out-dir <dir>
                        [--server-name rillane] [--valid-days 365]
rillanectl mtls rotate     --node-id <ID> --ca-cert <pem> --ca-key <pem> --out-dir <dir>
                        [--no-backup] [--valid-days 365]    # backs up to *.bak.<epoch> by default; new connections pick it up automatically
rillanectl mtls bundle-ca  --ca-cert <pem>... --out-path <bundle.pem>
rillanectl mtls rotate-ca  --old-ca-cert <pem> --out-dir <dir>
                        [--common-name rillane-mesh-ca-next] [--valid-days 3650]   # outputs an old+new dual-trust bundle
rillanectl mtls revoke list   [--file <path>]
rillanectl mtls revoke add    --file <path> --node-id <ID>
rillanectl mtls revoke remove --file <path> --node-id <ID>
rillanectl mtls revoke status [--endpoint <base URL>]   # GET /mtls/revoked: the "effective" leg of the distribution -> effect -> verification loop
```

The revocation list file holds one `node_id` per line (empty lines/`#` comments/commas ignored); the recommended path matches `RILLANE_MESH_MTLS_REVOKED_NODES_FILE`.
