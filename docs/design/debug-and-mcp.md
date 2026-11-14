# Debugging, path explanation and optional MCP

Status: **target design, not implemented**, 2026-11-14. Extends the [target architecture](architecture-v1.md) and concept C31. The repository-root `todo.md` is the execution backlog. New commands, APIs and tools below are proposed interfaces.

## 1. Rationale and influences

Mihomo's connection inspection, sing-box's typed contracts and host integration, and Surge's request diagnostics and real-connection feedback inform this design. See the [study and primary references](../research/proxy-architectures-2026-11-14.md). CLI, UI and MCP use one diagnostic/configuration application service and the production routing engine. AI does not participate in packet forwarding or maintain another router.

| Abstraction | Reason for separation | Benefit and cost |
|---|---|---|
| RouteExplanation | Evaluating policy does not establish a connection | Offline reproduction and previews; needs a pinned generation and explicit evidence |
| FlowTrace / TraceEvent | Real connections can retry and depart from a plan | Locate capture/owner/DNS/rule/dial failures; bounded collection and retention required |
| ProbeJob | Active checks send network traffic | Target scopes, cancellation and quotas; probes cannot prove every app's experience |
| DiagnosticView | Internal snapshots can contain secrets and private history | Shared CLI/UI/MCP contract; allowlisted fields and redaction tests required |
| ConfigProposal / ApplyReceipt | Validity, authorization and successful application are distinct | Reviewable changes and recovery; concurrency, journaling and compensation required |
| MCPAdapter | An optional client adapter | Core independent of models/SDKs; versioned protocol and permission maintenance required |

These refine C31 and compose with provenance C12, generations C14, plans C18, session pins C23 and host lifecycle C30. They do not require a new crate per concept.

![Proposed diagnostic and MCP architecture](/architecture/debug-mcp.svg)

## 2. Existing functionality and gaps

| Existing entry | Actual coverage | Limitation |
|---|---|---|
| `rillanectl stats`, `group` | Aggregates, group and quality state | No complete per-connection lifecycle |
| `rillanectl switches` | Mesh switching ledger | No ordinary subscription routing history |
| `rillanectl chain dry-run` | Managed Mesh preflight | Not general process/domain policy explanation |
| `rillanectl diagnose` | Collects configuration, logs and runtime snapshots | Bundle is not automatically safe to send to AI |
| `/flows` | Ingress/egress traffic aggregates | No stable per-connection IDs or complete timing/path |
| Compatibility `/connections` | Derived aggregate compatibility view | Missing domain/time fields are not real observations |

There is no current MCP service. Preserve aggregates while adding separate connection contracts. Expose field availability instead of inventing timestamps or success. Diagnostic exports require field-level review, including runtime configuration.

## 3. Three diagnostic modes

### Explain: pure policy evaluation

Inputs include a pinned generation, ingress, protocol, addresses, domain with provenance and optional local application identity. Supplied identity is caller evidence for simulation, never authority for real traffic. Use the production evaluator with frozen group/quality snapshots; do not dial, resolve DNS or perform OS owner lookups.

Return matched rule/source location, rejected candidates, scenario, logical group, predicted endpoint, capability/budget constraints and unknowns. Incomplete evidence produces conditional results. Include input digest and configuration/quality versions for replay.

### Trace: observed connection lifecycle

Assign stable flow IDs to TCP sessions/UDP associations and attempt IDs to each dial. Events carry sequence, monotonic time, wall clock, generation and reason codes:

```text
capture → context/owner → DNS/sniff → rule/scenario → RoutePlan
        → candidates/dial attempts → actual endpoint → counters → close/failure
```

Keep planned and actual endpoints separate, including permitted fallbacks. Mark evidence observed, inferred or unknown. Shared/prefetched DNS queries cannot reliably identify their originating application.

| Path layer | Observable result | Boundary |
|---|---|---|
| Policy | Rules, sources, scenario, predicted endpoint | Explanation is a simulation |
| Connection | Actual dial address, protocol, proxy and attempts | Connection establishment does not prove target application success |
| Managed Mesh | Logical nodes with owned telemetry | Cannot infer third-party provider internals |
| Internet L3 | Explicit traceroute-style responses | Incomplete/asymmetric and not necessarily the proxied business path |

Default collection excludes payloads, HTTP content and complete browsing history. Bound active records, ring buffers, per-flow events, sampling, TTL and subscriber backpressure. Report dropped events and truncation. Forwarding works with detailed tracing disabled.

### Probe: active verification

DNS, proxy setup, target connects and supported UDP echo are separate cancellable jobs. Record source, target, metric kind, sample count, time and timeout. Enforce caller-specific target scopes, concurrency/rate/traffic limits and retention. Untrusted source text must not authorize internal-network scans. Packet loss requires suitable observations/peer support; connection failure is a different metric.

## 4. CLI and path views

Proposed commands are `rillanectl explain`, `trace`, `probe` and `config preview/apply/rollback`; freeze syntax during implementation. Offer readable text and versioned JSON. CLI, UI and MCP share semantics. Start with terminal output and exported SVG, then a UI using the same read API.

Show evidence, rule provenance, planned/actual endpoints, timing and failures. Explain missing data. Exports default to aliases for sensitive domains, executable paths and node addresses; detailed local views need separate scope. Escape untrusted SVG text and prevent executable exported links.

## 5. MCP assembly and permissions

Propose an optional separate `apps/rillane-mcp` executable, disabled by default, initially local stdio. Adapter-held credentials stay outside model context. Expose narrow diagnostic/configuration operations, without shell, arbitrary files, generic HTTP forwarding or unrestricted administration proxies.

| Proposed tools | Service behavior | Authority/effect |
|---|---|---|
| `get_status`, `list_flows` | Status and paged summaries with truncation | Redacted reads; identity/history scoped separately |
| `get_flow_trace`, `explain_route` | Collected events or pure evaluation | Reads; no implicit unbounded tracing |
| `get_policy_quality` | Typed samples with source and validity | Reads; unknown is not zero |
| `run_probe`, `cancel_probe` | Bounded active jobs | Separate network-probe authority |
| `validate_config`, `preview_config_change` | Validate candidate, create diff/impact proposal | Bounded temporary state, no active-config changes |
| `apply_config_change` | Apply authorized unexpired proposal | Write scope and version checks |
| `rollback_config` | Restore validated state using a receipt | Write scope; revalidate external state/capabilities |

Enforce read, detailed identity, probing and writing scopes on the server. Tool annotations and prompts are not authorization. Users may preauthorize bounded automation; manual approval per call is not a protocol requirement. Reject changes outside granted scope even if the model claims consent.

Use stdout exclusively for stdio protocol messages and stderr for logs. Pin the implementation's SDK/protocol versions and test startup, EOF shutdown, cancellation, timeouts and structured errors. Future HTTP support needs a separate listener/origin/session/authorization design, not exposure of the daemon admin port. References: official [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio), [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). Recheck versions at implementation time.

OpenWrt may install the adapter within measured resource budgets. Android/iOS do not run MCP by default inside VPN services/extensions. Use authorized host IPC or redacted exports and an optional desktop bridge; no default inbound phone management listener.

## 6. AI-assisted configuration lifecycle

```text
read sanitized evidence → draft candidate → validate/simulate → review diff/impact
 → check prior authorization or approval → apply → verify generation/connectivity → recover
```

Store the normalized patch, base generation/hash, owner, expiry, scope and validation report server-side. Return an unguessable proposal ID. Authorization binds exact content, not an editable model-supplied approval token. Recheck generation and authority on application; reject expiry/concurrency conflicts instead of overwriting manual edits. Idempotency keys and ApplyReceipts prevent duplicated OS effects after client timeouts.

Persistence, OS changes and generation publication use one journaled transaction/compensation model. Recover consistent state after restart and report incomplete compensation. Rollback revalidates configuration; it does not restore old connections. Management-path changes need a host watchdog, timed recovery and verified restoration; unresolved recovery must return actionable steps.

Use structured allowlisted DiagnosticViews, never raw diagnose bundles. Exclude credential URLs, passwords, private keys, tokens and raw runtime config. Scope sensitive domain/path details. Subscription names, logs and comments are untrusted data, never instructions. Audit caller, authority, proposal digest, outcome and generation without raw secrets. Enforce pagination, size/TTL limits and error-path redaction.

## 7. Delivery gates

1. Shared contracts, real flow events, pure Explain and sanitized views; prove no implicit traffic or forwarding stalls.
2. CLI paths, explicit probes, text/JSON/SVG; distinguish prediction/observation and verify bounded resources.
3. Disabled-by-default read-only stdio MCP; verify CLI parity, no secret disclosure or scope escalation.
4. Preview and controlled writes; test conflicts, idempotent retries, denied access, partial failures, crash recovery and watchdog behavior.

Report fields/permissions per platform and Unsupported owner identity where appropriate. Builds do not replace device validation. Detailed atomic dependencies and acceptance criteria live in the root `todo.md`.
