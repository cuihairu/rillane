# rillanectl CLI reference

This page describes existing commands; use `rillanectl <command> --help` for current flags/defaults. See [subscriptions](subscription.md), [Mesh](mesh.md) and [capture](networking.md). v1 Explain/Trace/Probe/MCP are [proposed](design/debug-and-mcp.md), not current commands.

## Global options

| Option | Description |
|------|------|
| `-c, --config <CONFIG>` | config file path (default `config/rillane.yaml`); control-plane commands use it to read `control.api_bind` / `control.admin_token` |
| `-V, --version` | print version |

## Data sources

- **Control-plane commands** (`stats` / `group` / `switches` / `nodes` / `chain` / `pool` / `subscription` / `route` / `config` / `diagnose` / `mtls revoke status`): HTTP against the `rillaned` control plane; when `control.admin_token` is non-empty an `x-admin-token` header is attached, otherwise the request is anonymous.
  - `--endpoint` comes in two flavors (easy to confuse):
    - **Full-URL flavor** (replaces the whole target URL, must include the path): `stats` (default `http://{api_bind}/flows`), `group` (`/routing/stats`), `switches` (`/mesh/switches`), `pool status` (`/egress/pool/stats`), `nodes` (`/nodes`);
    - **Base-URL flavor** (replaces only the base, path appended internally): `chain`, `subscription`, `route`, `config`, `diagnose`, `trace`, `mtls revoke status`.
- **Offline commands** (`check` / `show` / `profile` / `tls-fingerprint` / `import-rules` / `udp-probe` / `import-clash` / `export-clash` / `dev-env` / the `mtls` cert tools): no control plane, only local files are read (exceptions: `udp-probe` dials the SOCKS5 ingress directly; `dev-env --apply-git` runs two scoped `git config --global` keys and `dev-env --write-ssh` writes the managed block into `~/.ssh/config` with a backup — both only behind their explicit flags).
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
| POST | `/explain` | pure route explanation (production evaluator + frozen snapshot, zero side effects; invalid input → 400 + stable code) | `explain` |
| GET | `/probe` | probe job list (limits + job snapshots) | `probe list` |
| GET | `/probe/result?id=` | one job's measurement snapshot, or an explicit absence answer (`found:false` + stable code) | `probe result` |
| POST | `/probe` | submit a probe job (target must be registered in the server's probe scope) | `probe submit` |
| POST | `/probe/cancel?id=` | cancel a job (queued → immediate final state; running → cooperative cancel request) | `probe cancel` |
| GET | `/config/state` | live config-face snapshot (generation / content digest + proposal/approval/receipt/history counts) | `config state` |
| GET | `/config/receipts` | receipt chain (seq desc) + reconcile against the daemon's live face | `config receipts` |
| POST | `/config/proposals` | register a forward proposal (base generation filled by the daemon — a client cannot state the live face; invalid patches rejected at proposal time) | `config propose` |
| POST | `/config/rollback-proposal` | register a rollback proposal (marker scope `rollback`; target receipt must be Applied and owned by the caller) | `config rollback` (step 1) |
| POST | `/config/preview` | read-only patch preview (diff / diagnostics / affected categories / side-effect hints) | `config preview` |
| POST | `/config/approve` | operator approval (credential binds proposal digest / owner / scope / TTL; single-use consumption) | `config approve` |
| POST | `/config/apply` | idempotent apply (version + content prechecks, consume, terminal receipt; retries with the same key replay the receipt) | `config apply` |
| POST | `/config/rollback` | verifiable rollback (candidate identity daemon-filled from the target receipt; blind-overwrite guard) | `config rollback` (step 3) |
| POST | `/routing/ai` | AI routing template proposal (RIL-153: target validated against declared groups/egresses — stable codes `ai.target.empty` / `ai.target.unknown`; zero rule diff = explicit no-op, HTTP 200 without a proposal; a diff answers 201 with a normal config proposal that still goes through `/config/approve` + `/config/apply`) | `ai on` |
| DELETE | `/routing/ai` | remove the AI routing template (`ai-` prefix namespace only — user rules untouched; no template present = explicit no-op 200) | `ai off` |

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
| `dev-env` | developer terminal & config snippet preview (per-shell env vars / Git / SSH ProxyCommand snippets; copy modifies nothing, writes are flag-gated; RIL-147) | offline |
| `import-rules` | batch import geosite/chnroutes text rule sources as routing/DNS rule YAML | offline |
| `udp-probe` | UDP ASSOCIATE integration probe (minimal RFC 1928 client; exit codes 0-4) | dials the SOCKS5 ingress directly |
| `nodes` | view mesh node registration info | control plane `/nodes` |
| `chain` | chain management (dry-run/create/get/terminate/stats) | control plane |
| `pool` | egress connection pool snapshot (status) | control plane `/egress/pool/stats` |
| `import-clash` | Clash YAML -> Rillane config (offline preview) | offline |
| `export-clash` | Rillane config -> Clash YAML reverse export (offline) | offline |
| `subscription` | subscription management (list/add/remove/refresh) | control plane |
| `route` | system route management (apply/clear/status) | control plane + local ip commands |
| `config` | config transaction closure (propose/preview/approve/apply/rollback/state/receipts; RIL-079) | control plane `/config/*` |
| `ai` | AI routing template one-shot switch — `on <target>` / `off` (RIL-153); proposal → approve → apply in one command | control plane `/routing/ai` + `/config/*` |
| `diagnose` | one-shot diagnostics collection (creates a diagnostics directory) | control plane + local snapshot |
| `trace` | per-connection trace queries (list / flow detail / incremental events; explicit absence = exit 2) | control plane `/trace/*` |
| `probe` | active probe jobs (submit/cancel/result/list; measurements only, no provider-internal path inference) | control plane `/probe*` |
| `explain` | pure route explanation ("why would this target route here" — production evaluator + frozen snapshot, zero side effects) | control plane `/explain` |
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

### dev-env

```bash
rillanectl dev-env --shell <bash|zsh|fish|powershell|cmd> --http <host:port> --socks <host:port> \
                   [--ssh-hosts <comma-separated>] [--ssh-diff] [--write-ssh] [--apply-git]
```

Prints (default modifies nothing — copy to use): per-shell terminal proxy env vars (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`(SOCKS)/`NO_PROXY`), the two `git config --global` keys (`http.proxy`/`https.proxy`), and the SSH managed block. **SSH does not honor HTTP(S)_PROXY** — the snippet relays via `ProxyCommand nc -X connect -x <socks>` only; it never touches keys or host-key checks (generated blocks pass the forbidden-key audit). Tool presence (`git`, `nc`) is verified against PATH and gates the write faces. `--ssh-diff` previews the `~/.ssh/config` diff read-only; `--write-ssh` appends the managed block (backup `<path>.rillane-bak` first; idempotent via the managed-block marker; a stale backup is a named conflict with recovery = copy the backup back); `--apply-git` runs exactly the two `git config --global` keys via precise argv (no arbitrary shell).

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

### config

```bash
rillanectl config state                                  # live generation / digest + ledger counts
rillanectl config preview  --patch-file p.json [--scope routing]   # read-only: diff / diagnostics / side effects
rillanectl config propose  --owner cli:local --scope telemetry --patch-file p.json   # register proposal (base daemon-filled)
rillanectl config approve  --proposal-id <ID> --owner cli:local                     # sign credential (single-use)
rillanectl config apply    --idempotency-key k1 --proposal-id <ID> --approval-id <AID> --owner cli:local
rillanectl config rollback --idempotency-key k2 --target-key k1 --owner cli:local    # rollback proposal + approve + execute
rillanectl config receipts                               # receipt chain (seq desc) + reconcile
```

The closure mirrors the MCP path: the daemon fills the base generation, live digest and rollback candidate identity itself, so a client cannot bypass the version/content prechecks (`apply.base.conflict` / `apply.hash.conflict` arrive as 409 stable-code envelopes; the CLI prints them as `Control plane rejected: ... [code]`). `config rollback` performs all three authorized steps (rollback proposal → approval → execution) through the same daemon endpoints — approval stays a real daemon-signed credential. Retry discipline: `apply`/`rollback` retries must repeat the idempotency key verbatim (same key + same identity replays the receipt); a different proposal under the same key is refused (`apply.key.mismatch`).

### ai

```bash
rillanectl ai on --proxy auto            # template → target group/egress (proposal + approve + apply in one shot)
rillanectl ai on --proxy auto --owner cli:ai --ttl-ms 60000
rillanectl ai off                        # remove the template (ai- prefix namespace)
```

AI/LLM routing preset (RIL-153, design in `docs/design/ai-routing.md`): four domain-only rules (`ai-openai` / `ai-anthropic` / `ai-gemini` / `ai-other`) inserted after user rules and before the generalized region rules, all pointing at `--proxy` (a declared group or egress name; unknown targets are rejected with `ai.target.empty` / `ai.target.unknown`). Semantics:

- **It is an ordinary config transaction**: the daemon computes the `routing.rules` patch and registers a normal proposal — approval and the version/content prechecks are never bypassed. Zero rule diff (template already present with the same target, or nothing to remove) is an explicit no-op: no proposal, no generation bump. `ai on` retries are naturally idempotent.
- **The `ai-` prefix namespace belongs to the template**: rules you name with the `ai-` prefix are swept by `ai on` / `ai off` (documented ownership — do not use the prefix for your own rules). User rules with other names are never touched.
- **Effect surface is the in-memory live generation only**: apply does not rewrite the config file; a daemon restart (or a file-driven reload) reverts to the file's rules. Persist by writing the template rules into your config file (they are plain rules; `ai off` removes them again).
- **Recognition face is domain-only**: `domain_suffix` / `domain_keyword` / `domain_full` — no DPI, no content guessing. There is no UDP face (mainstream AI APIs are HTTPS/TCP). SSE / WebSocket streams are not interrupted by `ai on` (existing flows keep their session pin; only new connections take the new rules).

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
rillanectl trace inspect <id> [--json]
```

Per-connection trace queries against the kernel's flow query service (RIL-060). `--endpoint` is the base-URL flavor (default `http://{api_bind}`). Anchored on real flow IDs — the ingress/egress aggregate keys shown by `stats`/`/flows` never resolve as flow IDs here. Absence is explicit and coded (`query.flow.unknown` / `query.tracing.disabled` / `collector.flow.evicted|expired|active_limit|sampled_out|drained`); an absent answer always carries the collector counter snapshot and the fixed note "no record is not evidence of no traffic" — absence is never reported as "the app sent no packets". Text output is default; `--json` prints the versioned envelope (`schema_version=1`) verbatim.

Exit codes: `0` query answered; `1` connection or usage error; `2` explicit absence (`trace flow` answered `found:false`, or `trace events` got a 404 error envelope).

`trace flow <id> --svg` exports the path graph (RIL-062, `GET /trace/flow.svg?id=`). The SVG is rendered from the same query snapshot as the JSON answer — graph and JSON always agree. Events are grouped into separate lanes and never mixed: L3 (takeover/identity/dns/sniff), plan (rule/route plan), connection (attempt/egress/transfer/close); the mesh ledger is deliberately kept out of the graph (it lives at `/mesh/switches`). The time axis is the monotonic clock with explicit gap annotations for large inter-event deltas; lanes with no events say so instead of fabricating ticks. All embedded text (flow id, generation, event details) is XML-escaped, control-character-replaced and length-bounded — long or malicious names cannot break the document. Absence stays coded: an unknown id answers 404 with a stable code envelope (exit 2), never an empty picture. `--svg` and `--json` are mutually exclusive.

`trace inspect <id>` is the interactive path-inspection entry (RIL-063): exactly one boundary read (`GET /trace/flow`), rendered as (1) config attribution — the generation anchor plus the plan-lane events verbatim (the recorded rule evaluation; the CLI never re-evaluates rules — replay verification goes through `rillanectl explain --generation <G>`, the same frozen evaluator), (2) segment expansion — event counts and seq ranges grouped into the same lanes as the path graph (one shared stage→lane mapping; unknown stage names are listed explicitly instead of guessed), and (3) drill-down pointers to `trace events --from-seq` and `trace flow --svg` (no second fetch path is invented for the inspection face). Absence keeps exit code 2 with the collector counters; connection failure and missing permission surface as explicit stable codes (exit 1). Trace reads carry detailed identity (domains, process names, addresses), so when `admin_token` is configured on the daemon they are permission-gated like mutating endpoints (RIL-063: detailed identity is permission-controlled; a token-less local deployment stays open).

### probe

```bash
rillanectl probe submit --kind dns|connect|udp-echo [--host <H>] [--addr <ip:port>] [--payload-len N] [--json]
rillanectl probe cancel <id> [--json]
rillanectl probe result <id> [--json]
rillanectl probe list [--json]
```

Explicit active-probe jobs against operator-registered targets (RIL-061). The target must be in the daemon's `probe.targets` scope (operator config only — subscription text can never extend the scope); an out-of-scope submit is rejected with a stable code (`probe.target.out_of_scope`). With no `probe` block in the config the whole surface is off and every endpoint answers `503 probe.disabled` — no authorization, no network side effects. Measurements are exactly what the executor observed: `failure` (stable code + detail) or null, `rtt_ms` (null when nothing answered — never synthesized), and for UDP echo `sent`/`replies`/`loss_ratio`/`payload_len` (loss ratio computed from the reply counts). Measurements never include provider-internal path inference. Proxy-handshake probing is not offered in this version (the egress connector is a flow-level forward surface without a dial-and-measure shape), so no handshake kind exists on the CLI or in the config. Text output is default; `--json` prints the versioned envelope (`schema_version=1`) verbatim.

Exit codes: `0` answered; `1` connection, rejection or usage error; `2` explicit absence (`probe result` for an unknown job id).

### explain

```bash
rillanectl explain <host> --port <N> --proto tcp|udp|quic
                [--endpoint <base URL>] [--ingress <ID>] [--generation <G>]
                [--domain-source unknown|user_provided|dns_observed|sniffed]
                [--process-name <N>] [--process-path <P>]
                [--annotation k=v]... [--json]
```

Pure route explanation against the daemon's production evaluator (RIL-065): the question is "why would this target route here" — the server freezes current group state into a snapshot and replays the exact rules, with **zero side effects** (no DNS resolution, no dialing, no OS identity queries). Evidence the caller does not supply (process name/path, annotations) is evaluated as missing and reported gap-by-gap; conclusions affected by missing evidence are marked conditional instead of certain. Non-deterministic strategies (`random`/`weighted`/`round_robin`) report only the healthy candidate pool, never a fabricated pick. Text output lists target, certainty, match source, predicted egress (group chain → node), unknowns and notes; `--json` prints the versioned envelope (`schema_version=1`) verbatim. Invalid usage (`--proto smtp`, unknown `--domain-source`, `--annotation` without `=`) is rejected client-side before any request is sent. The command goes through the shared `rillane-app` boundary — the same closed operation set future UI/MCP surfaces consume.

Exit codes: `0` answered; `1` connection, usage or server-rejected input error (server rejects malformed input with `400 explain.input.invalid`).

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
