# Subscriptions (current implementation)

Clash/Mihomo compatibility is **partial**. Fetch/conversion/cache/refresh/control plumbing exists; source snapshots, complete providers and faithful groups/rules are [v1 targets](design/architecture-v1.md#subscription-compatibility).

## Input and conversion

Inputs include Clash YAML, share-link lists/base64 and Rillane DSL. Converter/runtime validation in `crates/rillane-subscription` defines supported fields. Current ClashConfig requirements do not establish arbitrary provider-only support.

| Input | Mapping | Limit |
|---|---|---|
| proxies | egress | Parsed fields do not prove platform/protocol availability |
| proxy-groups | routing.groups | fallback → Random and relay → ConsistentHash lose semantics |
| rules | routing.rules | Important PROCESS-NAME/RULE-SET conditions can be warned and skipped |
| url-test interval | Probe seconds | Read in seconds as of the RIL-092 fix; 0 and omission both default to 300 seconds |

Conversion success is not sufficient. Inspect critical conditions/groups/units. Root `todo.md` RIL-092/RIL-093 addresses early fixes; RIL-007–RIL-016 covers full fidelity. See [verified gaps](research/proxy-architectures-2026-11-14.md#verified-gaps).

## Fetch, cache and updates

Fetching supports timeouts, headers, proxies and conditional requests; caching uses TTL/LRU. Subscription already has SHA-256 change detection. A digest is not a signature or source authentication.

Current runtime merging appends unseen names and extends rules instead of reliably replacing/deleting source objects. Removing a source is not the v1 source/session transaction. Inspect effective configuration after refresh; existing updates do not prove atomic local-policy/session/OS changes.

## Commands and endpoints

```bash
rillanectl subscription --help
rillanectl import-clash --help
rillanectl export-clash --help
rillanectl import-rules --help
```

Import-rules converts geosite/chnroutes text into configuration fragments, not subscription RULE-SET runtime support. See [CLI](cli.md).

| Endpoint | Operation |
|---|---|
| GET /subscriptions | List/status |
| POST /subscriptions | Add |
| POST /subscriptions/refresh | Refresh all |
| POST /subscriptions/{name}/refresh | Refresh one |
| DELETE /subscriptions/{name} | Remove source |

See [configuration](config.md) for control.admin_token. Current ordinary reads and sensitive-read/write gates differ from v1 granular MCP scopes. Configuration files have no general watch or SIGHUP reload.

Credential URLs/headers, node secrets and raw runtime configuration must not be sent to models. Existing diagnose bundles do not automatically meet DiagnosticView redaction. See [Debug/MCP](design/debug-and-mcp.md).
