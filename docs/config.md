# Configuration reference

This page describes current configuration, not completed v1 fields. Definitions and validation live in `crates/rillane-config/src/lib.rs`; examples are in `config/rillane.yaml`. See [protocols](PROTOCOLS.md), [capture](networking.md) and the separate [v1 design](design/architecture-v1.md). Required fields have no serde default.

## Format and loading

- Path: the `RILLANE_CONFIG` environment variable (default `config/rillane.yaml`); rillaned has no `--config` flag.
- Format: parsed by extension hint (`.yaml`/`.yml`/`.json`/`.toml`); without a hint it tries YAML -> JSON -> TOML.
- The `profile:` scenario preset is **expanded only at the file-loading entrypoint** (default-filling semantics, see below); programmatic construction such as subscription conversion does not trigger it.
- New blocks (`udp:`/`network:`/`obfuscation:`/`egress_pool:`/`performance:`) are all `deny_unknown_fields`: a misspelled subfield errors immediately; a missing block = the whole block is off with zero behavioral difference (exception: `network.dns`, which is enabled by default when the block is present).

## Top-level blocks

| Block | Type | Description |
|----|------|------|
| `control` | required | control plane |
| `telemetry` | required | logging/metrics/tracing |
| `ingress` | required (may be empty) | ingress list |
| `egress` | required (may be empty) | egress list |
| `routing` | required | default node/groups/rules |
| `udp` | optional | UDP data plane (default off) |
| `network` | optional | TUN/system routing/DNS partition (default off) |
| `obfuscation` | optional | obfuscation cross-cutting layer (default off) |
| `egress_pool` | optional | egress connection pool (default off) |
| `probe` | optional | active-probe authorization (default None = the whole surface off) |
| `profile` | optional | scenario preset `proxy\|game\|web` |
| `performance` | optional | relay buffer parameters |

## control / telemetry

| Field | Required | Description |
|------|------|------|
| `control.api_bind` | yes | control-plane listen address (e.g. `127.0.0.1:9090`); rillanectl derives its data URL from it by default |
| `control.uds_path` |  | Unix domain socket path (optional) |
| `control.admin_token` |  | when non-empty the control plane requires the `x-admin-token` header; rillanectl attaches it automatically after reading the config |
| `telemetry.log_level` | yes | log level (e.g. `info`) |
| `telemetry.enable_metrics` | yes | `true` exposes `GET /metrics` (Prometheus text) |
| `telemetry.enable_tracing` | yes | `true` plus the `RILLANE_CAPTURE_LOGS=1` environment variable provides `GET /logs` |

## ingress[] (`type` tags)

| type | Fields |
|------|------|
| `socks5` | `bind` (required), `auth`?, `udp_enabled`? |
| `http` | `bind` (required), `auth`?, `bearer_tokens`? |
| `mixed` | `bind` (required), `auth`?, `udp_enabled`?, `bearer_tokens`? (http branch only) |

- `auth`: an `[{username, password}]` credential table -- **non-empty means enforced** (socks5 via RFC 1929, http via a `Proxy-Authorization: Basic` 407 challenge); absent/empty table = anonymous passthrough.
- `bearer_tokens`: a `[token]` list compared in plaintext (`Proxy-Authorization: Bearer`), in parallel with `auth`; either passing is enough; disabled by default.
- `udp_enabled`: ingress-level UDP ASSOCIATE override; defaults to inheriting `udp.enabled`, and an explicit `true`/`false` overrides it for that ingress (explicit true while the global switch is off is a build-time WARN).

## egress[] (`type` tags, 12 variants)

| type | Fields (yes = required) | Default |
|------|----------------|------|
| `direct` | — | — |
| `socks5` | `server`yes `port`yes `username`? `password`? | — |
| `http` | `server`yes `port`yes `username`? `password`? `tls` `skip_cert_verify` `sni`? `tls_fingerprint`? | `tls: false` |
| `shadowsocks` | `server`yes `port`yes `method`yes `password`yes `plugin`? `plugin_opts`? | — |
| `vmess` | `server`yes `port`yes `uuid`yes `alter_id` `security` `network` `path`? `host`? `grpc_service_name`? `grpc_reuse`? `tls` `skip_cert_verify` `sni`? `alpn`? `tls_fingerprint`? | `alter_id: 0`, `security: auto`, `network: tcp`, `tls: false` |
| `vless` | same as the vmess base + `flow`? `xhttp_mode`? `packet_encoding`? | `network: tcp`, `tls: false` |
| `trojan` | `server`yes `port`yes `password`yes `network` `path`? `host`? `grpc_service_name`? `grpc_reuse`? `tls` `skip_cert_verify` `sni`? `alpn`? `tls_fingerprint`? | `network: tcp`, **`tls: true`** |
| `hysteria` | `server`yes `port`yes `password`yes `protocol` `up_mbps`? `down_mbps`? `auth`? `auth_str`? `obfs`? `obfs_param`? `server_name`? `skip_cert_verify` `alpn`? | `protocol: udp` |
| `hysteria2` | `server`yes `port`yes `password`yes `mport`? `obfs`? `obfs_param`? `server_name`? `skip_cert_verify` `alpn`? | — |
| `anytls` | `server`yes `port`yes `password`yes `sni`? `skip_cert_verify` | — |
| `tuic` | `server`yes `port`yes `uuid`yes `password`yes `congestion_controller`? `server_name`? `skip_cert_verify` `alpn`? | `congestion_controller`: cubic |
| `wireguard` | `endpoint`yes `private_key`yes `public_key`yes `address`yes `allowed_ips`? `preshared_key`? `persistent_keepalive`? `listen_port`? `mtu`? `dns`? | — |

Transport and build-time constraints:

- `network` values: vless = `tcp | ws | httpupgrade | grpc | h2 | xhttp`, vmess = `tcp | ws | httpupgrade | grpc | h2`; trojan = `tcp | ws | grpc` (**no h2/httpupgrade scope**, anything outside the whitelist errors at build time). `grpc` requires `grpc_service_name` (online path `/{name}/Tun`) and always layers TLS (`tls: false` is refused at build time); `h2` also always layers TLS; `ws`/`httpupgrade`/`h2` use `path`/`host` (host is a string array; on the subscription side `httpupgrade` reads the `httpupgrade-opts` block, same shape as `ws-opts`); `xhttp` (vless only, RIL-129) always layers TLS (`tls: false` refused at build time), `path`/`host` follow the ws shape, and `xhttp_mode` is limited to `auto | packet-up | stream-one` (default auto; outside the whitelist refused at build time, undelivered carriers refused by name at dial time).
- `grpc_reuse` (vmess/vless/trojan, RIL-130): gRPC gun stream-reuse knobs, valid only on `network: grpc` -- carrying them on any other transport is refused at build time by name. Fields `max_connections`/`min_streams`/`max_streams` (all optional) map to the subscription keys `grpc-opts.max-connections/min-streams/max-streams`; all three absent = single connection with full stream reuse (mihomo client default). `max_streams` caps concurrent active streams per connection; the multiplexed connection holds its pool lease for its whole lifetime (shared resource -- the lease is not returned to the pool), and a dead peer connection is evicted and redialed on the next acquire.
- `packet_encoding` (vless only, RIL-130): UDP packet encoding, `raw | xudp | packetaddr`, default `raw`; outside the whitelist refused at build time. The subscription-side flat `packet-encoding` key converts both ways. VMess accepts the subscription key but only `raw` is deliverable (xudp/packetaddr carriers undelivered -- named refusal at conversion).
- `security` (vmess): `auto | aes-128-gcm | chacha20-poly1305`; `alter_id > 0` and non-AEAD security are refused at build time.
- `flow` (vless): dial-time validation — exactly `xtls-rprx-vision` accepted (Vision framing; requires `network: tcp` + `tls: true`/REALITY, UDP refused), any other value refused at dial time and names the node.
- `method` (shadowsocks): free-form string, invalid values error at build time (the set is whatever the shadowsocks crate 1.25 AEAD methods support); `plugin` goes through the SIP003 bridge (TCP plane via the plugin process, UDP plane judged negative in plugin mode).
- `hysteria` (v1): schema/subscription conversion is supported, but **the egress connector is missing** -- RuntimeBuilder errors at build time; `hysteria2` TCP and the UDP datagram plane are available (UDP limited to the obfs-free combination; servers without declared UDP support are refused by name).
- `tuic` (v5): TCP streams and the UDP datagram plane are available -- v5 only (no v4 code path; v4 wire shapes refused by name); `congestion_controller` other than `cubic` is refused by name at dial time (no silent downgrade); auth has no response face -- refusals arrive as stream/QUIC teardown.
- `tls_fingerprint`: `none | chrome | ios | safari` (comparison table: `rillanectl tls-fingerprint`); emulation is off by default.
- `address` (wireguard): comma-separated multiple CIDRs (e.g. `10.0.0.2/32,fd00::2/128`); `listen_port: 0` = automatic.

## routing

```yaml
routing:
  default_node: direct-main        # required
  groups:                          # required (may be empty)
    - name: auto
      strategy: latency
      members:                     # string shorthand = node reference
        - direct-main
        - type: weighted_node      # or node | group | weighted_group
          name: trojan-node
          weight: 3
      slo:                        # optional ; check quality provenance
        p95_ms: 80
        loss_ratio: 0.02
        loss_penalty_ms: 1000     # default 1000.0 (1% loss is about +10 ms penalty)
  rules:                           # required (may be empty); first match wins
    - name: cn
      target: auto
      matches:                     # multiple conditions within one rule = AND
        - type: geoip
          country: CN
```

- Seven `strategy` values: `fixed | latency | random | bandwidth | weighted | consistent_hash | round_robin`.
- Routing condition `type` tags: `any{conditions}` / `not{condition}` / `domain_suffix{values}` / `domain_keyword{values}` / `domain_regex{patterns}` / `domain_full{values}` / `geoip{country}` / `geo_site{category}` / `ip_cidr{cidrs}` / `network{cidrs}` / `port{values}` / `process{values}`. The process-name scope is `/proc/<pid>/comm` truncated to 15 bytes; **only the TUN ingress carries that annotation**, so other ingresses never match. `geoip` reads `routing.geoip_db` (MaxMind DB Country `.mmdb`, target IP literal only) and `geo_site` reads `routing.geosite_db` (v2fly `.dat`); if a database path is absent or fails to load, the condition never matches. Relative database paths are resolved against the config-file directory.
- `slo` validation: `loss_ratio` in [0,1], `loss_penalty_ms >= 0`; the `latency` strategy takes the lowest score inside the `slo:` gate, and the chain side's `slo_watch` switches automatically on degradation.

Existing loss_ratio names are retained for compatibility. Some link observations are connection error ratios, not measured game packet loss. Interpret them with their source/sample evidence; v1 introduces typed measurements.

## udp (the whole block is off by default; changes take effect on restart -- session state cannot be hot-migrated)

| Field | Default | Constraint |
|------|------|------|
| `enabled` | `false` | when false the ingress answers ASSOCIATE with 0x07 |
| `strict_udp_source` | `true` | datagram source IP validation (prevents relay borrowing) |
| `session_idle_secs` | `180` | session idle ceiling (seconds) |
| `mapping_idle_secs` | `60` | target-mapping idle ceiling (seconds) |
| `max_sessions` | `4096` | global concurrent session ceiling (new ones refused when full) |
| `sweep_interval_secs` | `15` | reclamation sweep interval (seconds) |
| `max_mappings` | `256` | per-session mapping ceiling (overflow evicts the longest-idle) |
| `session_lifetime_secs` | unlimited | if set it must be >= `session_idle_secs` |
| `downlink_queue_depth` | `64` | downlink queue depth (drop + count when full) |
| `max_associates` | `256` | concurrent ASSOCIATE ceiling (above it, answer 0x01) |

`sweep_interval_secs`/`max_mappings`/`downlink_queue_depth`/`max_associates` must be >= 1 (build-time error otherwise).

## network (default None = the whole block off)

```yaml
network:
  mode: tun                      # tun only (transparent/tap/hybrid refused at build time)
  tun:
    name: rillane0                  # default: automatic naming (tun%d)
    mtu: 1500                    # must be >= 68
    ipv4: 10.255.0.1/24          # CIDR; enters auto-bypass
    ipv6: fd00::1/128            # optional
    dns_servers: [1.1.1.1]       # optional; network.dns.domestic falls back to this list +53
  routing:
    include: ["10.111.0.0/16"]   # prefixes brought into the tun (include semantics; the negative is bypass)
  dns:                           # see the table below; fields described here
    enabled: true                # true by default when the block is present
    domestic: ["223.5.5.5:53"]   # empty = fall back to tun.dns_servers +53
    trusted: ["8.8.8.8:53"]      # ip:port; trustworthiness is the deployer's responsibility
    rules:                       # leading dot = suffix (.cn takes x.cn, not cn); first match wins; duplicate patterns error
      - pattern: ".cn"
        group: domestic          # domestic | trusted
    default_group: domestic      # fallback when nothing matches
    anti_poison: off             # off | cross_check (requires a non-empty trusted)
    timeout_ms: 5000             # >= 1
    retries: 2
    cache:                       # optional; None = no caching
      max_entries: 10000
      min_ttl: 60                # <= max_ttl
      max_ttl: 86400
      enable_negative_cache: true
      negative_ttl: 300          # >= 1
    listen_address: 127.0.0.1
    listen_port: 15353           # must not be 0
  egress_fwmark: 0               # 0/absent = no SO_MARK; non-zero needs root/CAP_NET_ADMIN (degrades to direct with a WARN)
```

- `routing.include` CIDRs must be in explicit `addr/prefix` form (bare IPs are rejected; write `/32` for host routes).
- Outbound fwmark escape surface (`egress_fwmark` != 0): the planner appends `ip rule fwmark` + an escape table with the 100 default route, and `rillanectl route apply/clear` manages the ledger.

## obfuscation (default None = the whole block off, zero overhead)

| Field | Default | Description |
|------|------|------|
| `enabled` | `false` | false tolerates a half-built config |
| `default_padding` / `default_timing` / `default_shaping` | — | reference a name in `profiles`; **mutually exclusive** with a same-named inline block |
| `apply_to` | `chain` | `chain \| single \| all \| "egress:<name>"` |
| `middleware` | `[padding]` | declares chain order; available names `padding \| latency_probe \| timing \| shaping` |
| `profiles` | `{}` | named policy set `{padding?, timing?, shaping?}` (a bad profile that is not selected is still caught at build time) |
| `padding` / `timing` / `shaping` | — | inline policies |
| `plugins` | `[]` | WASM plugins `{path, fuel?}` (fuel defaults to 1e8; when enabled the path must exist) |

Policy block validation:

- `padding`: `mode: fixed|bucket|range` -- fixed requires `target != 0`; bucket requires `buckets` strictly ascending and non-empty; range requires `min <= max`; `max_overhead_ratio` defaults to 0.5 and must be >= 0.
- `timing`: `mode: fixed|uniform` -- fixed requires `fixed_ms >= 1`; uniform requires `min_ms <= max_ms <= max_delay_ms`; `max_delay_ms >= 1` is required.
- `shaping`: `mode: interval` (the only value) -- `interval_ms >= 1`, `jitter_ms <= interval_ms`, `max_delay_ms >= interval_ms`.

With `enabled: true`, at least one dimension of policy must be configured (any of default_*/inline/plugins), otherwise it errors at build time.

## egress_pool (default None = the whole block off; the `tls_resumption` block is active as soon as it exists, independent of enabled)

| Field | Default | Constraint |
|------|------|------|
| `enabled` | `false` | pool master switch |
| `tls_resumption` | `true` | shared ClientConfig + session cache |
| `max_idle_per_key` | `2` | >= 1 |
| `max_idle_global` | takes the runtime `connection_pool_size` | — |
| `low_watermark` | `1` | <= `max_idle_per_key` |
| `idle_timeout_secs` | `30` | counted from when the connection entered the pool |
| `dial_timeout_secs` | `5` | the whole TCP+TLS span |
| `session_cache_size` | `256` | >= 1 when TLS resumption is on |
| `pre_dial_direct` | `false` | requires `enabled: true` |

Snapshot observability: `GET /egress/pool/stats` or `rillanectl pool status`.

## probe (default None = the whole surface off; targets are a closed registry, no handshake kind in this version)

| Field | Default | Constraint |
|------|------|------|
| `targets` | `[]` | closed target registry (empty = nothing probeable); each entry is `kind: dns` (`host`), `kind: connect` (`addr`), or `kind: udp_echo` (`addr`); `addr` is `ip:port`, validated at load time |
| `limits.max_active` | `4` | >= 1; jobs over the cap queue instead of being dropped |
| `limits.job_timeout_ms` | `5000` | >= 1, per-job deadline |
| `limits.udp_payload_max_bytes` | `512` | >= 1; submits above the cap are rejected |
| `limits.byte_budget` | `65536` | >= 1; reserved on submit, settled by actual bytes sent (refund + overage) |

The block only exists in operator-local config: the source merge surface is object registration (`SourceSnapshot.objects`), so a top-level `probe` block is structurally unreachable from subscription text — untrusted input can never extend the probe scope. No `probe` block = the whole surface off: the endpoints answer `503 probe.disabled` and no network side effects occur. Measurements are exactly what the executor observed (`failure` / `rtt_ms` / UDP echo `sent`/`replies`/`loss_ratio`/`payload_len`) and never include provider-internal path inference (debug-and-mcp.md §3). Proxy-handshake targets are deliberately absent from this version's config surface — the egress connector is a flow-level forward surface without a dial-and-measure shape.

Endpoint/CLI surface: `GET /probe`, `POST /probe`, `GET /probe/result?id=`, `POST /probe/cancel?id=` and `rillanectl probe submit|cancel|result|list` (see [cli.md](cli.md) § probe).

## profile / performance

- `profile: proxy|game|web`: **default-filling** expansion -- if groups are empty it creates groups (proxy=`auto`, game=`game-auto` (slo p95 80 ms / loss 2%), web=`web-auto`), and if rules are empty it fills in templates (game = suffixes for 8 game platform domains, proxy/web = geoip CN); game additionally gets padding(bucket)+timing(10 ms) obfuscation and web gets `egress_pool.enabled=true`; explicit config always wins and re-expanding is idempotent. Run any of the three via `examples/profile-*.yaml`.
- `performance.relay_buffer`: byte size of the bidirectional TCP relay buffer, `1..=1048576` (default 8192); set once at process startup, a change needs a restart.

## Environment variables

| Variable | Default | Description |
|------|------|------|
| `RILLANE_CONFIG` | `config/rillane.yaml` | rillaned config path |
| `RILLANE_CAPTURE_LOGS` | off | with `telemetry.enable_tracing=true` captures process logs for `GET /logs` (`rillanectl diagnose`) |
| `RILLANE_MESH_ALLOW_PLAINTEXT` | off | allows plaintext on the TCP mesh data plane (development only) |
| `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` | off | allows plaintext on the UDP mesh data plane (development only; ORed independently of the one above) |
| `RILLANE_MESH_MTLS` | `false` | master switch for mTLS environment configuration (false/absent = do not assemble mTLS from the environment) |
| `RILLANE_MESH_MTLS_CA/_CERT/_KEY` | — | the certificate trio paths |
| `RILLANE_MESH_MTLS_SERVER_NAME` | `rillane` | server_name for rustls validation |
| `RILLANE_MESH_MTLS_REQUIRE_CLIENT_AUTH` | `true` | enforces client certificate validation (keep it on in production; bypassing needs `RILLANE_MESH_ALLOW_NO_CLIENT_AUTH=1`) |
| `RILLANE_MESH_ALLOW_NO_CLIENT_AUTH` | off | development escape hatch that bypasses client certificate validation (mutually exclusive with the one above) |
| `RILLANE_MESH_MTLS_VERIFY_PEER_NODE_ID` | `true` | checks the peer certificate CN against the node ID |
| `RILLANE_MESH_MTLS_ALLOW_UNKNOWN_PEERS` | `false` | allow unknown node certificates |
| `RILLANE_MESH_MTLS_REVOKED_NODES` | — | inline revocation list (CSV) |
| `RILLANE_MESH_MTLS_REVOKED_NODES_FILE` | — | revocation list file path (hot-reloaded on mtime; `GET /mtls/revoked` shows the effective view) |

The SIP003 plugin bridge internals (`SS_LOCAL_*`/`SS_REMOTE_*`) are not part of the config surface. The mesh certificate toolchain is in [mesh.md](mesh.md) and `rillanectl mtls --help`.
