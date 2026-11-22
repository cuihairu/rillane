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
| `streaming` | optional | streaming availability probe (default None = the whole surface off) |
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
| `shadowsocks` | `bind` (required), `method` (required), `password` (required), `udp_enabled`? |
| `trojan` | `bind` (required), `password` (required), `cert` (required), `cert_key` (required), `udp_enabled`? |
| `vless` | `bind` (required), `uuid` (required), `cert` (required), `cert_key` (required), `udp_enabled`? |
| `vmess` | `bind` (required), `uuid` (required), `udp_enabled`? |
| `hysteria2` | `bind` (required), `password` (required), `cert` (required), `cert_key` (required), `udp_enabled`? |
| `hysteria` | `bind` (required), `password` (required), `cert` (required), `cert_key` (required), `up_mbps`?, `down_mbps`?, `udp_enabled`? |
| `shadow_tls` | `bind` (required), `password` (required), `handshake_addr` (required), `target_addr` (required) |

- `auth`: an `[{username, password}]` credential table -- **non-empty means enforced** (socks5 via RFC 1929, http via a `Proxy-Authorization: Basic` 407 challenge); absent/empty table = anonymous passthrough.
- `bearer_tokens`: a `[token]` list compared in plaintext (`Proxy-Authorization: Bearer`), in parallel with `auth`; either passing is enough; disabled by default.
- `udp_enabled`: ingress-level UDP override (SOCKS5 ASSOCIATE, mixed socks5 branch, Shadowsocks datagram face, Trojan/VLESS/VMess/Hysteria2 UDP association); defaults to inheriting `udp.enabled`, and an explicit `true`/`false` overrides it for that ingress (explicit true while the global switch is off is a build-time WARN).
- `trojan` `cert`/`cert_key`: certificate and private key as inline PEM strings, parsed at assembly time (garbage material errors before listen); the password is a plain string hashed to SHA224 hex on the wire.
- `vless` `uuid`: a standard-form UUID parsed at assembly time (garbage errors before listen) and compared on the wire with a constant-time equality over the 16 raw bytes; `cert`/`cert_key` same as trojan (inline PEM parsed at assembly). The server face is plain TLS + UUID auth only -- Vision/REALITY server combinations are a separately validated item and carry no config fields.
- `vmess` `uuid`: a standard-form UUID parsed at assembly time (garbage errors before listen); the wire auth key is `cmdKey = MD5(uuid || constant)`, and the AEAD sealed header IS the auth face -- the server carries no TLS fields (bare TCP) and no security knob (the client picks AES-128-GCM or ChaCha20-Poly1305 per connection; AEAD-only, `alter_id: 0` semantics).
- `hysteria2` `password`: constant-time compared at the HTTP/3 `/auth` gate (233 accept + `Hysteria-UDP` declaration); the QUIC endpoint IS the listen face -- `cert`/`cert_key` are inline PEM parsed at assembly time, ALPN is always `h3`. `obfs`/masquerade/ACME/Brutal are not delivered and carry no config fields.
- `hysteria` (v1) `password`/`up_mbps`/`down_mbps`: the password is constant-time compared on the control stream (version byte `0x03` handshake); the QUIC endpoint IS the listen face -- `cert`/`cert_key` are inline PEM parsed at assembly time, ALPN is always `hysteria`, TLS 1.3 minimum. `up_mbps`/`down_mbps` are server-side rate CAPS for the client's downlink/uplink direction respectively (`None` = uncapped -- the official `>0` applies-a-cap wording; `0` is refused by name at assembly time, use `None` to express "no cap"). obfs/wechat/faketcp packet transports, ACL routing, ACME and the traffic-stats API are not delivered and carry no config fields.
- `shadow_tls` (v2 carrier, RIL-110): `handshake_addr` is the handshake/camo site (pure TLS relay + challenge answering), `target_addr` is the inner protocol ingress bind the switched stream is handed to verbatim (usually a Shadowsocks ingress). No `udp_enabled` field -- the carrier has no UDP face. Empty password and malformed addresses error at assembly time.

## egress[] (`type` tags, 13 variants)

| type | Fields (yes = required) | Default |
|------|----------------|------|
| `direct` | — | — |
| `socks5` | `server`yes `port`yes `username`? `password`? | — |
| `http` | `server`yes `port`yes `username`? `password`? `tls` `skip_cert_verify` `sni`? `tls_fingerprint`? | `tls: false` |
| `shadowsocks` | `server`yes `port`yes `method`yes `password`yes `plugin`? `plugin_opts`? | — |
| `shadowsocks-shadow-tls` | `server`yes `port`yes `method`yes `password`yes `shadow_tls`yes (`host`yes `password`yes `version`? `skip_cert_verify`?) | `shadow_tls.version`: 2 |
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
- `shadowsocks-shadow-tls` (RIL-110): SS TCP face over the ShadowTLS v2 carrier -- SS `password` and carrier `shadow_tls.password` are independent; `shadow_tls.version` accepts absent/2 only (v1/v3 refused by name at build time, no silent downgrade); `skip_cert_verify` shares the vless/vmess TLS semantics. No UDP face anywhere -- a combo node under `udp.enabled` is refused by the build-time capability scan. The subscription side converts both ways with the mihomo plugin shape (`plugin: shadow-tls` + `plugin-opts`).
- `hysteria` (v1): TCP request streams and the UDP datagram plane are available (self-written face, RIL-109; wire mirror of official v1.3.5 core/cs) -- carriers other than `protocol: udp` (wechat/faketcp) and `obfs` packet transports are refused by name at dial time, and the UDP face additionally refuses them at build time when the node is in the UDP-reachable set; `up_mbps`/`down_mbps` of `0` are refused by name at dial time. `hysteria2` TCP and the UDP datagram plane are available (UDP limited to the obfs-free combination; servers without declared UDP support are refused by name).
- `tuic` (v5): TCP streams and the UDP datagram plane are available -- v5 only (no v4 code path; v4 wire shapes refused by name); `congestion_controller` other than `cubic` is refused by name at dial time (no silent downgrade); auth has no response face -- refusals arrive as stream/QUIC teardown.
- `tls_fingerprint`: `none | chrome | ios | safari` (comparison table: `rillanectl tls-fingerprint`); emulation is off by default.
- `address` (wireguard): comma-separated multiple CIDRs (e.g. `10.0.0.2/32,fd00::2/128`); `listen_port: 0` = automatic.

## routing

```yaml
routing:
  default_node: direct-main        # required
  mode: rule                       # rule (default) | global | direct
  global_node: proxy-group         # required when mode: global; declared group or egress name
  direct_node: direct-main         # required when mode: direct; must be a Direct egress node
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
  region_preset:                   # optional (RIL-141); presence expands versioned region rules
    kind: mainland_direct          # mainland_direct | mainland_proxy (reverse)
    direct: direct-main            # direct side target (group or Direct egress node); LAN bypass always uses it
    proxy: proxy-group             # proxy side target (mainland_proxy sends the CN face here)
  git_preset:                      # optional (RIL-146); presence expands versioned Git routing rules
    target: proxy-group            # target for Git HTTPS/API/release/LFS/download faces (group or egress name)
    ssh: direct                    # optional; target for Git over SSH faces, absent = same as target
```

- Seven `strategy` values: `fixed | latency | random | bandwidth | weighted | consistent_hash | round_robin`.
- `mode` (unified selection mode, RIL-140): decides how **already-captured** traffic picks an egress — orthogonal to traffic capture. `rule` (default) = scenarios → rules → default as declared; `global` / `direct` compile into the same decision path as a mode entry that short-circuits the scenario/rule faces (they are paused, not evaluated). The mode entry never touches authentication, resource limits, hard security rejections or loop prevention (they run before routing), and never changes DNS answers. Ordinary subscription REJECT rules are **not** hard security boundaries — switching to `global`/`direct` pauses them; `mode::mode_override_preview` names the paused scenarios/rules and the REJECT subset explicitly, and `mode::mode_receipt` reports requested vs effective mode, generation and conflicts. Validation/assembly gates: `global` requires `global_node` (a declared group or egress, `reject` included), `direct` requires `direct_node` naming a **Direct-type** egress node — undeclared names or wrong types are refused at build time, never at dial time. An unavailable global/direct egress fails the flow explicitly (group without healthy members errors out) — **never a silent fallback to direct**. New flows follow the current generation's mode; established flows stay pinned to their original generation.
- `region_preset` (region bypass preset, RIL-141): versioned in-tree presets — `mainland_direct` (CN domain/IP + LAN → `direct`, rest follows `default_node`, expected to point at a proxy group) and `mainland_proxy` (reverse: CN domain/IP → `proxy`, LAN still `direct`). Expansion appends three rules (`region-lan`, `region-cn-domain`, `region-cn-ip`) **after** user rules — user priority is never reordered or overwritten; a user-declared rule with the same name wins and the template yields; re-expansion is idempotent. The CN domain/IP rules combine database faces (`geo_site` `cn` / `geoip` `CN`) with versioned in-tree sample rule sets (`region-cn-domain-sample`, `region-cn-ip-sample`, plus the complete RFC-1918/4193 LAN set `region-lan`) — sample seeds are honestly labeled non-exhaustive; missing geo databases mean the conditions never match and traffic falls through to `default_node` (no ownership guessing). `region_preset_preview` reports the evaluation order sample, per-rule-set source cards (name/behavior/version/source/entries) and fixed notes (direction hint naming the current `default_node`, unknown-geography fallback, LAN independence, global/direct mode pausing preset rules — they are ordinary rules and appear in the mode override pause list). Unknown `direct`/`proxy` values fail at validation when empty; target existence resolves like any rule target.
- `git_preset` (Git/SSH/GitHub routing preset, RIL-146): a versioned in-tree preset that appends four rules after user rules and **before generalized region rules** — `git-ssh` (SSH hosts + port 22 AND-scoped, never a bare port hijack), `git-ssh-alt` (official SSH-over-443 endpoints like ssh.github.com + port 443), `git-https` (Git HTTPS/API main domains — API hosts are subdomains of the main domains, covered by suffix semantics), `git-assets` (release/LFS/download CDN redirect-domain samples, honestly labeled non-exhaustive). Same-name user rules/rule sets win and the template yields; re-expansion is idempotent. `ssh` absent falls back to `target`; an empty `target` or an explicitly empty `ssh` is refused at validation. `git_preset_preview` reports the order sample, four rule-set source cards (redirect domains / rule provenance queryable) and fixed notes: **connectivity is not acceleration** (the preset only rewrites routing direction; speed depends on the chosen egress link quality), **SSH host keys and auth are preserved** (domain-capability routing only — known_hosts/host-key verification and end-to-end auth are untouched, and the SSH face is never conflated with the HTTPS egress protocol), samples are non-exhaustive and extensible, and global/direct mode pauses the preset rules.
- AI/LLM routing preset (RIL-153): **not a config block** — a versioned in-tree template (`AI_PRESET_VERSION = 1`) managed through the config transaction face: `rillanectl ai on --proxy <group|egress>` / `ai off`, or `POST`/`DELETE /routing/ai`. The daemon computes the `routing.rules` merge patch and registers a normal proposal (approval + version/content prechecks never bypassed); the four domain-only rules (`ai-openai` / `ai-anthropic` / `ai-gemini` / `ai-other`, suffix/keyword/full faces only — no DPI, no content guessing, no UDP face) are inserted after user rules and **before generalized region rules**. Zero rule diff is an explicit no-op (no proposal, no generation bump); re-`on` is naturally idempotent and target switching replaces the whole template. **The `ai-` rule-name prefix namespace belongs to the template** — user rules using it are swept by on/off (documented ownership); other names are never touched. Effect surface is the **in-memory live generation only** — apply does not rewrite the config file; a restart or file-driven reload reverts to the file's rules (persist by writing the template rules into the file as plain rules). Targets are validated against declared groups/egresses at proposal time (stable codes `ai.target.empty` / `ai.target.unknown`). Like all preset rules these are ordinary rules: global/direct mode pauses them (they appear in `mode_override_preview`), and `ai on` does not interrupt established SSE/WebSocket flows (session pin; only new connections follow the new generation).
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
  mode: tun                      # tun | transparent (tap/hybrid refused at build time)
  tun:
    name: rillane0                  # default: automatic naming (tun%d)
    mtu: 1500                    # must be >= 68
    ipv4: 10.255.0.1/24          # CIDR; enters auto-bypass
    ipv6: fd00::1/128            # optional
    dns_servers: [1.1.1.1]       # optional; network.dns.domestic falls back to this list +53
  transparent:                   # required when mode = transparent; named refusal under other modes
    mode: redirect               # redirect | tproxy (RIL-139; see networking.md)
    listen: 0.0.0.0:12345        # SocketAddr; the redirect/tproxy listener
    target: edge-1               # fixed egress node name (must be a declared egress)
    intercept_ports: [80, 443]   # optional; empty = all destination ports
    rule_table: 100              # optional; tproxy ip rule/route table (default 100)
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
    fake_ip:                     # optional (RIL-142); absent = redir-host (real answers, zero diff)
      enabled: true              # true by default when the block is present
      range: 198.18.0.0/15       # IPv4 pool CIDR (prefix 1..=30; reserved-segment overlap rejected)
      range6: fc00::/64          # optional IPv6 pool; absent = AAAA keeps resolving for real (zero diff)
      exceptions: [example.com]  # full-label suffixes; matching A/AAAA skip the pool and resolve for real
    bootstrap:                   # optional (RIL-144); IP-literal-only upstreams for landing DoT domain hosts
      - "223.5.5.5:53"           # udp ip:port
      - "tls://1.1.1.1:853"      # or tls://ip:port — domain-form / DoH entries are rejected by name (a bootstrap that itself needs resolution is the loop vector)
  sniff:                         # optional (RIL-143); absent = on-demand default (zero diff from prior behavior)
    mode: on_demand              # off | on_demand | scope
    ports: [443, 80]             # explicit scope ports (scope requires an explicit target list)
    max_bytes: 16389             # first-packet byte bound (1..=65535; default fits the largest TLS record 16384+5)
    timeout_ms: 120              # first-packet wait bound in ms (1..=1000)
  egress_fwmark: 0               # 0/absent = no SO_MARK; non-zero needs root/CAP_NET_ADMIN (degrades to direct with a WARN)
```

- `routing.include` CIDRs must be in explicit `addr/prefix` form (bare IPs are rejected; write `/32` for host routes).
- Outbound fwmark escape surface (`egress_fwmark` != 0): the planner appends `ip rule fwmark` + an escape table with the 100 default route, and `rillanectl route apply/clear` manages the ledger.
- `sniff` (bounded domain-sniff policy, RIL-143): a three-state gate for TUN first-packet domain sniffing — `off` (no sniffing), `on_demand` (default: sniff only when the target is an IP literal, i.e. the routing face lacks domain evidence), `scope` (only the explicitly declared port table; an empty table sniffs nothing — the coverage target must be explicit). Byte/time bounds are configurable with hard caps (`max_bytes` 1..=65535, `timeout_ms` 1..=1000); peek does not consume data and the forwarded first packet reads normally (bounded and never swallowed). A hit is delivered with a provenance annotation — `sniff.source` (`tls_sni` | `http_host`) plus `sniff.domain`; ECH (encrypted ClientHello without server_name) and unsupported versions (SSLv2-style records / QUIC drafts) return unknown instead of guessing a domain. No HTTPS decryption, no PID inference, no crossing of the authentication boundary.
- `fake_ip` (fake-ip / redir-host answer modes, RIL-142): block present and enabled = the DNS listener answers A (and AAAA once `range6` is set) with virtual pool addresses; the inbound face restores the original domain by reverse lookup, so routing hits domain rules. Block absent or `enabled: false` = redir-host semantics — every query resolves for real (prior behavior, zero diff). Validation: `range` prefix 1..=30 with host bits clear; any overlap with loopback / link-local(APIPA) / RFC 1918 / RFC 5737 doc segments is rejected at load — a fake address landing in a reachable real segment would send real traffic when a mapping goes missing (the RFC 2544 benchmark segment is the canonical pool space); `range6` prefix 1..=126, host bits clear, loopback / link-local / doc-segment overlap rejected, ULA (`fc00::/7`) allowed as canonical fake-v6 space. `exceptions` match full-label suffixes (`example.com` hits the domain itself and its subdomains, not `notexample.com`). Explicit behaviors: mappings are in-memory only and kept per live generation — in-use (pinned) addresses are never reused, and a full pool with everything in use answers SERVFAIL instead of stealing; a lost mapping does not send traffic to a real network — the inbound falls back to the fake IP literal itself, unroutable by construction (which is what the segment-conflict rejection guards); restart rebuilds the pool empty — no persistence, stale client-side fake addresses simply stop resolving until the client re-queries (flush caches); switching the block on/off or changing ranges takes effect on restart, like the rest of `network`; the `cache` block only caches real answers (hosts / exception / upstream), fake answers leave with TTL 1; while both mappings are alive two domains never share one address (wrap-around reclaims only unused entries); queries that bypass this listener (hardcoded upstreams) get real answers and never receive fake mappings — the face covers only queries through the local listener; hosts-table hits answer the real mapped address first and never enter the pool; with `mode: tun` the builder refuses fake-ip at build time (TUN inbound backfill is not wired in this version).
- `bootstrap` (DNS upstream anti-loop, RIL-144): a dedicated group of IP-literal upstreams used exclusively to land DoT upstream `host` values that are domain names. Once declared, the bootstrap face is exclusive — a DoT domain host resolves only through this group, and if the landing fails the query fails with an error naming `bootstrap` (never a silent fallback to the system resolver — that would reopen the resolution-dependency loop). Validation accepts only `ip:port` (UDP) and `tls://ip[:port]`; domain-form DoT, DoH, and bare domains are rejected by name (a bootstrap that itself needs resolution is the loop vector). Absent = the prior behavior: domain-form DoT hosts land via the system resolver at connect time (a build-time WARN names the loop/leak risk). Two named residual gaps, not masked: DoH upstream URL hosts always land via the system stack in this version (reqwest has no socket-level entry — the bootstrap face does not cover it; use UDP/DoT upstreams if you need bootstrapped landing); DNS upstream queries always egress directly (SO_MARK bypass supported via `egress_fwmark` for UDP/DoT; DoH is not markable) — upstream queries via a proxy group / node DNS are not implemented in this version. `GET /dns/resolvers` on the control plane shows the actual resolver shape: upstream groups, bootstrap mode (`declared-exclusive` vs `system-fallback`), rules count, anti-poison, and the bypass state per transport (`doh_egress_marked` is always `false` — the named gap, not a fake zero-leak claim).

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

## streaming (default None = the whole surface off; closed service registry, no credentials, HTTP 200 ≠ playable)

| Field | Default | Constraint |
|------|------|------|
| `services` | `[]` | closed registry (empty = nothing probeable); each entry is `name` (unique, non-empty), `check_urls` (`http(s)://host[:port]/path`, tried in order — first parseable HTTP response wins; transport failure falls through to the next), `expect_markers` (substring, case-insensitive; empty = that service's 200 is always `Unknown`) |
| `max_active` | `8` | >= 1; concurrent job cap — `submit` over the cap is rejected with `streaming.limit.quota` |
| `ttl_secs` | `3600` | >= 1; result freshness window; expiry is a distinct state (`Expired`), not a failure |
| `probe_timeout_secs` | `10` | >= 1; whole-probe deadline (dial + HTTP round trip); timeout yields `Failed`, not a cancel |
| `auto_switch.enabled` | `false` | explicit enable gate; `false` = hard off, the decision is always `Stay` |
| `auto_switch.confirmations_needed` | `2` | >= 1; consecutive `Available` confirmations before a switch is suggested |
| `auto_switch.failures_needed` | `2` | >= 1; consecutive unavailable (`Restricted`/`Unknown`/`Failed`) before leaving is suggested |

The block is operator-local (same merge surface as `probe`: subscription converters hard-code `streaming = None`), so untrusted subscription text cannot extend the service registry. No `streaming` block or empty `services` = the whole surface off (`Runtime::get_streaming()` is `None`), zero overhead.

Verdict semantics (RIL-145 decision layer, which the executor feeds):
- **Statuses are distinct**: untested / running / available / restricted / unknown / failed / expired — never impersonating each other; cancel keeps the previous cache entry (a cancel is not a failure).
- **HTTP 200 ≠ playable**: a 200 with no playback marker and no block evidence is `Unknown`, structurally — the classifier cannot declare "200 = available".
- **Block evidence outranks markers**: 200 with playback markers but with block indicators is `Restricted`, not `Available`; 403/451 without any marker is `Restricted` too; 5xx and no-response are `Failed` (not service-side unavailability).
- **No credentials / no certificate install / no unlock promise**: the registry carries only check endpoints and judgment markers — there is no field that could hold account evidence.
- **Probe bytes are metered separately** from business traffic (`probe_bytes` per (service, exit); snapshot surface exposes them as distinct fields).
- **Auto-switch is advisory**: per (service, exit) hysteresis, suggestion only — it affects new-flow route selection and never claims seamless migration of in-flight flows.

Executor mechanics: each probe is submitted to the decision service, then the `check_urls` are dialed in order through the named exit's assembled `FlowOutput` (build-time snapshot, same precedent as the url-test handler) via a synthetic duplex flow down the existing forward path — a real HTTP/1.1 GET (never a handshake-RTT probe; the egress connector has no dial-and-measure shape, RIL-059). The response status line is parsed, `expect_markers` are matched case-insensitively over the response (head + body), bytes are counted, and the evidence is classified. Egress-side connect failure surfaces as EOF (no response bytes) and falls through to the next `check_url`; all endpoints failing yields `http_status=None` evidence → `Failed`. The response body is capped (256 KiB) against memory amplification.

Boundaries (honest): region and block extraction use the default rules (`region = None`, `block = []` — no fabricated evidence); real-service rules (Netflix/Disney region hints, DRM/geo copy) are a later batch injected via `StreamingEvidenceRules`. Control-plane endpoints and CLI are a later batch (the runtime face is already exposed via `Runtime::get_streaming()`; the streaming block itself does not hot-reload in this version).

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
