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
| select | ✅ | member order preserved |
| url-test | ✅ | `url` mapped; **`interval` unit is seconds** (official default 300; `0`/empty → 300, RIL-092); export side emits seconds as well |
| fallback | ⚠️ | degrades to Random with a named report entry; faithful ordered fallback ships with RIL-012 |
| relay | ⚠️ | degrades to ConsistentHash with a named report entry; faithful chain support decided in RIL-013 |
| load-balance | ✅ | distribution algorithms audited in RIL-013 |
| nested group references / `use:` | ⏳ | RIL-009 (proxy-providers/use) |

## L3 Rules

| Rule | Status | Notes |
|---|---|---|
| DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX | ✅ | first-match order preserved |
| IP-CIDR / IP-CIDR-6 | ✅ | source vs destination distinction per converter |
| GEOIP / GEOSITE | ✅ | |
| SRC-PORT / DST-PORT | ✅ | separate conditions (source via `net.src_port`, destination via target port); ranges expand |
| NETWORK (inside logic) | ✅ | → `proto` condition |
| MATCH (fallback) | ✅ | must stay last |
| PROCESS-NAME / process fields | ❌ | rejected + reported; canonical mapping ships with RIL-015 |
| RULE-SET / rule-providers | ✅ | reference strategy (RIL-014): provider declarations land in `routing.rule_providers` (interval in seconds, passthrough), RULE-SET resolves at match time against `routing.rule_sets`; undeclared references are rejected + reported; payload downloads ship with RIL-010 |
| logic expressions (AND/OR/NOT) | ✅ | AND flattens into the rule's match list; OR → `any`, NOT → `not`; nested AND inside OR/NOT is rejected + reported (needs single-condition form); unknown sub-conditions reject the whole rule |

## L4 Other configuration

| Block | Status | Notes |
|---|---|---|
| `proxy-providers` | ❌ (whole block) | captured at parse time and reported as an unsupported block (RIL-007); provider lifecycle arrives with RIL-009/RIL-010 |
| `dns` | captured, not imported | DNS partitioning belongs to the local policy layer (RIL-020) |
| mixed-port / allow-lan / external-controller | captured, not imported | ingress ownership stays with the user config (RIL-016) |

## Units

| Field | Unit | Notes |
|---|---|---|
| url-test `interval` | seconds | passthrough; `0`/missing → 300 (RIL-092) |
| provider `interval` | seconds | enforced when providers land (RIL-009) |
| health-check `interval` | seconds | |
