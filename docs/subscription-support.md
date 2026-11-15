# Subscription field/unit support matrix

Scope of this table: field-level compatibility of the current Clash/Mihomo importer
(`crates/rillane-subscription`), organized by the four compatibility levels of the
target architecture (§4.2). Status marks:

- ✅ faithful: semantics preserved on import
- ⚠️ degraded: explicit lossy mapping — listed in the conversion report in loose
  mode, whole import rejected in strict mode
- ❌ rejected: unsupported key semantics — dropped with a named report entry
  (loose) or rejects the import (strict); never silently dropped
- ⏳ pending: not accepted yet, arrives with the referenced backlog item

Samples backing this table live in
`crates/rillane-subscription/tests/samples/` (desensitized: placeholder
credentials only, no token-bearing URLs — RIL-007). Expected objects and
diagnostics per sample are asserted in `tests/subscription_samples.rs`.

## L1 Nodes

| Type | Fields | Status | Notes |
|---|---|---|---|
| ss | server/port/cipher/password, `plugin`/`plugin-opts` | ✅ | SIP003 conversion only for obfs/v2ray-plugin key families; other plugin names reject that node |
| vmess | uuid/alterId/cipher/tls/servername | ✅ | |
| vless | uuid, `reality` block | ✅ | reality without `public-key` is a hard per-node error (G1-6 rejection policy) |
| trojan | password/sni | ✅ | |
| http/https/socks5 | username/password | ✅ | |
| hysteria / hysteria2 | password, `mport` (aliases ports/ports-range/port-range), obfs fields | ✅ | unit: bandwidth fields not interpreted |
| wireguard | private-key/public-key/ip or ipv6 | ✅ | all three required, otherwise invalid node |
| snell | — | ❌ | type-level unsupported: dropped + reported (loose) / import rejected (strict) |

Validity gate: empty `server` or `port: 0` marks a node invalid; invalid nodes are
dropped with a named report entry (RIL-093), never crash the bulk import.

## L2 Policy groups

| Group type | Status | Notes |
|---|---|---|
| select | ✅ | member order preserved; user picks persist across updates (`routing.selections`, RIL-011): a still-present pick is honored even if unhealthy, a deleted pick falls back to the first healthy member with the recovery named in the decision reason, and reload keeps selections the new config does not carry. Nested group references are validated at build time — cycles and dangling refs are rejected by name |
| url-test | ✅ | `url` mapped; **`interval` unit is seconds** (official default 300; `0`/empty → 300, RIL-092); export side emits seconds as well |
| fallback | ✅ | faithful since RIL-012: maps to `Strategy::Fallback` — always the first healthy member in declaration order (failover walks the list, recovery returns to the head; never random). The group's `url`/`interval` come along as probe params (`UrlTestConfig`, interval in seconds), so imported configs keep probing members on the original cadence |
| relay | ❌ | rejected in both modes since RIL-013: relay chains traffic through the member chain — rillane v1 has no same-semantics config face, and mapping it to ConsistentHash would masquerade (members would be treated as a chain endpoint while traffic never traverses the chain). The import errors naming the group |
| load-balance | ✅ | audited in RIL-013: the `strategy` sub-key now dispatches — `consistent-hashing` (and missing, the Clash default) → `consistent_hash` (same target always lands on the same member), `round-robin` → `round_robin`; previously everything mapped to weighted-random, which is not reproducible. `sticky-sessions` approximates to `consistent_hash` with a named report entry (stickiness key differs: source session vs target); unknown sub-keys fall back to the default and name the raw value in the report |
| nested group references / `use:` | ✅ | provider references expand at evaluation time against `routing.provider_nodes` (reference strategy, RIL-009); an empty or absent library yields an empty member set, so a dead provider contributes no new-flow candidates — it never impersonates membership. Declarations without payloads are reported as engine-degraded |

## L3 Rules

| Rule | Status | Notes |
|---|---|---|
| DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX | ✅ | first-match order preserved |
| IP-CIDR / IP-CIDR-6 | ✅ | source vs destination distinction per converter |
| GEOIP / GEOSITE | ✅ | |
| SRC-PORT / DST-PORT | ✅ | separate conditions (source via `net.src_port`, destination via target port); ranges expand |
| NETWORK (inside logic) | ✅ | → `proto` condition |
| MATCH (fallback) | ✅ | must stay last |
| PROCESS-NAME / PROCESS-PATH | ✅ | → `process` (comm-style short name) / `process_path` (full executable path) conditions (RIL-015); comparison is exact and case-sensitive. Reported as engine-degraded: matching depends on TUN process attribution (`process.name` / `process.path` annotations), so flows from other ingress surfaces or platforms without attribution never match; the short name is never used to impersonate a path |
| RULE-SET / rule-providers | ✅ | reference strategy (RIL-014): provider declarations land in `routing.rule_providers` (interval in seconds, passthrough), RULE-SET resolves at match time against `routing.rule_sets`; undeclared references are rejected + reported; payload downloads share the RIL-010 lifecycle (conditional caching, backoff, preset digests), control-plane wiring lands with RIL-019 |
| logic expressions (AND/OR/NOT) | ✅ | AND flattens into the rule's match list; OR → `any`, NOT → `not`; nested AND inside OR/NOT is rejected + reported (needs single-condition form); unknown sub-conditions reject the whole rule |

## L4 Other configuration

| Block | Status | Notes |
|---|---|---|
| `proxy-providers` | ✅ | declarations land in `routing.proxy_providers` (type/url/path/interval/health-check; **`interval` unit is seconds**, passthrough, RIL-092); group `use:` references become provider members; undeclared references are rejected + reported. The download lifecycle landed with RIL-010 (bounded size/concurrency, timeout, cancellation, conditional caching via 304, exponential backoff, optional preset-digest verification); control-plane wiring that feeds downloads into the provider node library lands with RIL-019, so declarations still report engine-degraded until then |
| `dns` | captured, not imported | DNS partitioning belongs to the local policy layer (RIL-020) |
| mixed-port / allow-lan / external-controller | captured, not imported | ingress ownership stays with the user config (RIL-016) |

## Units

| Field | Unit | Notes |
|---|---|---|
| url-test `interval` | seconds | passthrough; `0`/missing → 300 (RIL-092) |
| provider `interval` | seconds | enforced when providers land (RIL-009) |
| health-check `interval` | seconds | |
