# Architecture concepts: reasons, benefits and costs

Status: research/design proposal, 2026-11-14. These **32 core concepts** define the scope of a proxy/acceleration kernel; they are not an exhaustive inventory of competitors' private types or a claim that all interfaces exist.

Evidence: [upstream study](../research/proxy-architectures-2026-11-14.md). Composition: [target architecture](architecture-v1.md). **Process-based routing is required only on local Windows, macOS and Linux hosts**, not OpenWrt, Android or iOS.

## 1. What justifies an abstraction

An abstraction isolates a real source of change: providers refresh, local user rules should persist, OS permissions differ, TCP and UDP have different lifecycles, and games and websites have different objectives. It must have an owner, a contract, a testable outcome and an acknowledged cost. Thirty-two concepts do not require thirty-two new crates.

Boxes describe responsibilities, not mandatory processes. A desktop daemon may host the data plane, while privileged helpers, Android services or Apple extensions/UI have separate system lifecycles.

## 2. Planes, capture and platform capabilities: C01–C08

| ID / concept | Responsibility | Why separate it | Benefit and cost |
|---|---|---|---|
| C01 Control/data planes | Configuration and commands versus flow/packet handling | Different rates, privileges and failure modes | Refresh cannot stall packet handling; generation consistency must be specified |
| C02 FlowContext | Source/target, protocol, ingress, domain evidence, owner and generation | Inputs expose different metadata | Rules ignore ingress details; optional fields need provenance rather than invented values |
| C03 CapturePort | Sockets, packet batches or OS-provided flows into the core | Capture is neither selection nor PID discovery | Replace Wintun/packetFlow independently; manage MTU, batching, backpressure and teardown |
| C04 CapabilitySet | Available capture, ownership, bypass, route and host abilities | Build success differs from runtime permission | Reject impossible configurations early; maintain static and dynamic capabilities |
| C05 OwnerResolver | Local flow key to PID/path/user or explicit unknown state | TUN packets contain no universal process field | Desktop process routing shares rules; lookup cost, stale caches and PID/port reuse remain |
| C06 RouteTransaction | Plan/apply/journal/undo owned OS changes | Memory destruction cannot prove OS recovery | Recover without deleting user routes; persistent journals and idempotent rollback cost work |
| C07 SocketBypass | Protect outbound sockets and upstream DNS from recapture | Recursive interception forms loops | OS bypass stays separate from business policy; TCP/UDP/DNS/provider fetch all need coverage |
| C08 NetworkEvents | Interface/address/route changes, sleep and resume | Network replacement is not merely node failure | Common recovery contracts; debouncing and session behavior need explicit policy |

Initial homes: rillane-core/platform/runtime modules. Mihomo Metadata/process and sing-box platform interfaces are references, not a reason to copy a giant interface.

## 3. Sources, compatibility and generations: C09–C16

| ID / concept | Responsibility | Why separate it | Benefit and cost |
|---|---|---|---|
| C09 SourceSnapshot/Provider | A complete version of provider nodes or rules | Subscription ownership differs from user intent | Replace/delete atomically and keep last good content; define source namespaces |
| C10 EndpointCatalog | Stable provider-scoped IDs to addresses, secret references and capabilities | Display names are not unique identities | Preserve preferences across refreshes; define stable mapping when upstream lacks IDs |
| C11 RuleSet | Independently referenced matching data and expressions | Rule data has a different lifecycle from nodes | Import rule-providers/RULE-SET; validate formats, graphs and execution cost |
| C12 Canonical IR/Provenance | Input formats to typed nodes/rules/policies with source locations | Raw Clash assumptions should not leak into execution | Central validation and diagnostics; preserve behavior rather than just matching field names |
| C13 CompatibilityDiagnostic | Exact support, unsupported features and explicit semantic loss | Random fallback or hashed relay is not compatibility | Avoid missing game rules; strict imports reject some configurations and need actionable errors |
| C14 RuntimeGeneration | Immutable validated graph pinned by new flows | Nodes, rules and DNS cannot update independently | Explainable rollback/draining; old resources coexist and OS changes still need compensation |
| C15 DnsContext | Names, results, fake-IP ownership, policy and expiry | Lost mapping can route fake addresses incorrectly | Consistent TCP/UDP classification; avoid reusing mappings referenced by old flows |
| C16 MetadataEnrichment | Bounded sniff/domain/owner work | Metadata may arrive late but first packets cannot wait forever | Query only needed facts; encrypted/hidden information stays explicitly unknown |

Subscription owns input adaptation, config owns canonical validation, and runtime publishes generations. The IR is an internal configuration model, not a new tunnel protocol.

## 4. Decisions, scenarios and transport: C17–C24

| ID / concept | Responsibility | Why separate it | Benefit and cost |
|---|---|---|---|
| C17 Match/Action | Conditions produce route/reject/enrichment actions | Classification differs from execution | Reusable rules; specify order, boolean semantics and DNS dependencies |
| C18 RoutePlan | Group, scenario, constraints, queue, failure policy and explanation | Existing RouteDecision/RoutePath carries groups, chains and reasons; add scenario, queue, capabilities and failure policy | Test selection separately; every plan field must be consumed |
| C19 PolicyGroup | Dynamic/ordered members with precise selection algorithms | Rules should reference stable groups | Existing subscriptions retain meaning; validate cycles, nesting and user choices |
| C20 ScenarioPolicy | Parallel game/web/general objectives | UDP is not always gaming; TCP is not always web | Independent latency/stability/throughput goals; define classification priority |
| C21 Endpoint/Dialer/Transport | Proxy handshake, OS-safe dialing and stream/datagram carriage | TLS/WS/QUIC differ from proxy protocol semantics | Clear composition; reject unsupported combinations and UDP paths |
| C22 StreamSession/DatagramAssociation | Ordered byte streams versus mapped packets and replies | UDP associations are not TCP connections | Preserve datagram/NAT semantics; test expiry, fragmentation, MTU and reply validation |
| C23 SessionPin | Pin generation, endpoint and source mapping for an active flow | Constant reselection breaks sessions | New flows adapt while old ones remain stable; failed sessions may need reconnecting |
| C24 TransportPool | Reusable resources, pre-dialing, TLS resumption and budgets | Warming, target rebinding and multiplexing are different abilities | Reduce proxy setup blocking; do not confuse outer proxy TLS with browser-site sessions |

Routing plans, protocols execute, runtime owns sessions. Existing single-value profile remains a configuration preset; it must not make game and web runtime scenarios mutually exclusive.

## 5. Quality, budgets, embedding and deployment: C25–C32

| ID / concept | Responsibility | Why separate it | Benefit and cost |
|---|---|---|---|
| C25 QualitySample | Typed values with source, destination, age, count and validity | Handshake time, RTT, failure ratio and packet loss differ | Explainable scoring without false zeroes; bounded sampling has overhead |
| C26 Objective/Hysteresis | Scenario selection, cooldown and change thresholds | Minimum test latency is not game experience | Testable policy and less flapping; parameters require measurement |
| C27 ResourceBudget/QueueClass | Bound queues, sessions, probing and dialing per class | One process still shares congested resources | Measurable interference and bounded memory; avoid web starvation and acknowledge external bottlenecks |
| C28 ManagedMesh | Optional managed topology, security and multi-hop | Ordinary subscription nodes do not understand custom frames | Evolve owned networks independently; more hops add costs and insecure UDP must remain disabled |
| C29 FFI/PacketBatch | Lifecycle and packet ownership across language boundaries | Public Swift packetFlow is not a guaranteed private fd | One core through supported APIs; define copies, threads, batches, errors and cancellation |
| C30 HostLifecycle | Daemon/service/extension start, sleep, revoke, reconnect and stop | OS lifecycle does not belong inside rule matching | Independent mobile/desktop acceptance; IPC, signing and privileges remain necessary |
| C31 Explain/Telemetry/Secrets | Report rules, choices, samples and failures using protected secrets | Unexplained acceleration is untestable; diagnostics can leak credentials | Reproducible debugging; bound cardinality, retention and redaction |
| C32 FeatureProfile/Deployment | Build protocols/plugins/mesh/observability for each target | Routers and phones should not require desktop WASM JIT | Smaller products; feature combinations need real dependency and runtime verification |

## 6. Concrete abstraction examples

**Same destination, different desktop apps:** a trusted local owner produces separate game/web RoutePlans. QUIC remains UDP web traffic. A lookup timeout follows an explicit unknown policy; it is not silently treated as a matched process. Mobile/router targets use the evidence in their scope without adding a desktop PID requirement.

**Provider deletes a node during a game:** a new source version is compiled and published for new flows. SessionPin drains or terminates existing sessions according to ordinary removal versus security revocation. Neither append-only updates nor per-packet reselection is sufficient.

**A download fills the upload queue:** a game label expresses intent; budgets and scheduling protect only a controllable local bottleneck. Typed observations measure the result. ISP or third-party exit queues may need OS/remote cooperation and cannot be guaranteed away.

**An iOS private fd disappears after an update:** the production bridge uses public packetFlow batches, not KVC. CapturePort accepts platform batches without demanding a Linux-like fd. Copy/batch overhead must be measured rather than hidden with an unsupported assumption.

## 7. Proposed contracts: pseudocode, not current SDK

```text
OwnerResolver.resolve(local_flow_key, deadline)
  -> Known(AppIdentity, source, observed_at) | Unknown(reason) | Unsupported
ConfigCompiler.compile(source_snapshots, local_policy, capabilities)
  -> CandidateGeneration | Diagnostics(source, location, severity, semantic_loss)
PolicyEngine.plan(flow_context, generation)
  -> RoutePlan(target, scenario, constraints, queue_class, failure_policy, reason)
SessionExecutor.open(route_plan, generation)
  -> StreamSession | DatagramAssociation
PacketPort.read_batch(deadline) / write_batch(packets)
  -> bounded batch | cancelled | platform error
```

Ports support deadlines/cancellation and do not assume identical OS abilities. Split crates only when dependencies, independent reuse or build cost justify it.

## 8. Evidence required for advantages

| Desired benefit | Required evidence |
|---|---|
| Low-cost Clash migration | Provider/rule/group semantic fixtures and explicit failures |
| Consistent local desktop process routing | Same destination, different processes, TCP/UDP, permission and identity-reuse tests on three OSes |
| Concurrent game/web optimization | Concurrent download: game p50/p95/jitter, web TTFB/throughput, CPU and RSS comparisons |
| Less cross-platform duplication | Common contracts plus six actual platform smoke tests, not just cross-check |
| Reliable updates | Deletion/name collisions/bad sources/restart/long-flow generation and rollback tests |
| Small-device support | Dependency graph excluding WASM JIT; artifact size, startup and peak RSS, bounded sessions/queues |

Before this evidence exists, a more reasonable architecture means clearer boundaries and acceptance criteria, not proven superiority over Mihomo, sing-box or Surge.

See [Debugging, path explanation and optional MCP](debug-and-mcp.md) for C31 refinements: RouteExplanation, FlowTrace/TraceEvent, ProbeJob, DiagnosticView, ConfigProposal/ApplyReceipt and MCPAdapter, with rationale, costs and boundaries.
