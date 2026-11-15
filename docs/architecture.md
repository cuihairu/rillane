# Current implementation and boundaries

This is an implementation reference, not another architecture design. The **single current design baseline is [v1 architecture](design/architecture-v1.md)**, supported by [concepts](design/architecture-concepts.md) and [Debug/MCP](design/debug-and-mcp.md). Those targets are not implemented as a whole.

## Code organization

| Directory/module | Current responsibility |
|---|---|
| `apps/rillaned` | Configuration, runtime assembly and HTTP control plane |
| `apps/rillanectl` | Configuration utilities, control queries, subscriptions and certificates |
| `rillane-core` | Flow/FlowContext, RouteDecision/RoutePath, forwarding and UDP contracts |
| `rillane-config` | Configuration models, validation, profile expansion and the config version/capability contract (`contract` module) |
| `rillane-routing` | Conditions, logical groups and routing decisions |
| `rillane-protocols` | Inbounds, outbounds, dialing and transports |
| `rillane-runtime` | Listeners, sessions, subscriptions, TUN and Mesh assembly |
| `rillane-platform` | Capture, route/DNS models and Linux integration |
| `rillane-subscription` | Fetch, detect, convert, cache, digest and refresh |
| `rillane-mesh` / `rillane-plugins` | Managed topology and WASM middleware; v1 will make dependencies optional |
| `rillane-telemetry` / `rillane-ffi` | Logging and mobile FFI foundations |
| `platforms/` | Hosts, installers and packages; scaffolding is not runtime acceptance |

## Capability boundaries

| Capability | Existing behavior | v1 work |
|---|---|---|
| Proxy | SOCKS5/HTTP CONNECT/mixed and multiple outbounds | Preserve standard protocols independently of optional Mesh |
| Linux TUN | TCP/UDP through shared routing with local-process annotations | Harden identity, dual-stack bypass, permissions and recovery |
| Other platforms | Build/host scaffolds; limited Android demo and private-fd iOS integration | Windows/macOS capture/identity; complete mobile forwarding/public APIs |
| Clash/Mihomo | Fetch/convert/update plumbing with partial semantics | Source replacement, providers, faithful groups/rules and strict diagnostics |
| Scenarios | Configuration-time profile defaults and separate rule-selected outbounds | Concurrent policies, resource budgets and typed quality feedback |
| Diagnostics | Aggregates, group state, Mesh dry-run and diagnose | Real flow traces, pure Explain, explicit Probe; MCP is not implemented |

RouteDecision/RoutePath already describes groups, chains and reasons; RoutePlan extends it without creating a second router. Subscription SHA-256 change detection exists but is not source authentication or transactional generations.

## Control and updates

Configurations carry a `version` field (currently only `1`): missing version adapts to V1 for legacy configs, and unknown versions are rejected at parse time with the stable reason code `config.version.unknown`. A build capability set (`CapabilitySet`) rejects combinations the current build cannot honor at config validation time (stable code `config.combo.unsupported`) instead of failing at dial time; the default capability set is full, so existing callers see no behavior change. The kernel `rillane-core` does not depend on `rillane-config` or Clash formats; subscription conversion stays in `rillane-subscription`.

Control uses HTTP/REST on `control.api_bind`; see [CLI reference](cli.md). `/flows` aggregates ingress/egress pairs; compatibility `/connections` is not a complete real connection table. Diagnose bundles may contain sensitive runtime information and are not automatically safe for AI upload.

`rillaned` loads `RILLANE_CONFIG` at startup. There is no general file watch, SIGHUP reload or `rillanectl reload`. Existing subscription/control updates are not v1 cross-OS transactions. See [verified gaps](research/proxy-architectures-2026-11-14.md#verified-gaps) for append-only merging, group semantics and interval units.

References: [protocols](PROTOCOLS.md), [configuration](config.md), [subscriptions](subscription.md), [capture](networking.md), [optional Mesh](mesh.md). Follow root `todo.md` for implementation dependencies and acceptance.
