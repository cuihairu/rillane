# Rillane v1 architecture design: six platforms and concurrent scenarios

Status: **proposal, not implemented as a whole**, 2026-11-14. Baseline: `46c2b12`. This page records design recommendations and migration gates; [current implementation](../architecture.md) remains distinct. Existing stable-release authorization boundaries do not change.

Read the [upstream study](../research/proxy-architectures-2026-11-14.md) and [32 concepts with rationale](architecture-concepts.md). This delivery contains research, SVGs, concepts and an implementation plan; documentation is not a platform release.

## 1. Requirements and boundaries

| ID | Requirement | Acceptance meaning |
|---|---|---|
| V1-R1 | Linux/OpenWrt/macOS/Windows/Android/iOS | Common core and configuration semantics; individual capture, DNS, lifecycle and artifact gates |
| V1-R2 | Clash/Mihomo site subscriptions | Explicit full-config/provider-only modes; preserved nodes/rules/groups and diagnostics for unsupported semantics |
| V1-R3 | Process-based routing | **Local Windows, macOS and Linux only**, including different processes reaching the same target |
| V1-R4 | Concurrent web/game acceleration | Parallel objectives within one data-plane instance, not a single mutually exclusive profile |
| V1-R5 | Explainable, measurable results | Trace sources, rules, generations, endpoint choices, observations and resource effects |
| V1-R6 | Debug and actual paths | Separate Explain/Trace/Probe; bounded sanitized evidence |
| V1-R7 | Optional MCP | Disabled by default, local reads first, controlled proposals/apply/rollback |

OpenWrt uses device/IP/domain/port policy without requiring remote client PIDs. Android/iOS do not need desktop process attribution. Optional application lists/UID features do not block their baseline delivery. Ordinary iOS VPN must not promise arbitrary third-party app process rules; managed Per-App VPN is a separate possible deployment.

## 2. Overall view and process topology

![Rillane target architecture](/architecture/rillane-target.svg)

A desktop/server daemon can assemble one data-plane instance; privileged OS operations may use a restricted helper. Android uses a VpnService host, Apple uses an app plus extension. One core does not mean exactly one OS process on every platform.

Dependency direction: source adapters → canonical IR; IR + capabilities → validated generation; flow + generation → RoutePlan; plan → session → endpoint. Inject capture, owner, DNS, bypass and network events as ports. Mesh/plugins are optional; ordinary subscription servers keep their standard protocols.

## 3. Recommended decisions

A1–A10 are recommendations for this proposal, not completed migrations or final choices of every OS API.

| Decision | Recommendation | Reason, benefit and cost | Concepts/requirements |
|---|---|---|---|
| A1 | One core with logical control/data separation | Reuse forwarding; refresh does not stall traffic; generations and cancellation required | C01/C02/C30; R1/R4 |
| A2 | Separate sources, local policy and catalog | Provider updates preserve user intent/deletions; stable IDs/conflicts require definition | C09–C14; R2 |
| A3 | Independent capture/owner/route/DNS/bypass ports | Packet I/O is not process identity; share core while testing OS integration | C03–C08; R1/R3 |
| A4 | Parallel game/web/general objectives and RoutePlan | Same target can use different local app policy; define classification priority | C17–C20; R3/R4 |
| A5 | Pin active sessions to generation/endpoint | Updates should not reroute each packet; failures may still require reconnect | C21–C24; R4 |
| A6 | Typed observations, budgets and hysteresis | Failure ratio is not packet loss; avoid flapping/interference; measure parameters | C25–C27; R4/R5 |
| A7 | Optional Mesh/inspection/WASM | Standard nodes lack custom framing; small builds need pruning; adds feature-matrix testing | C28/C32; R1/R2 |
| A8 | Shared embedding contracts and public Apple packet APIs | Avoid private-fd assumptions; specify batching/ownership/IPC and measure copy cost | C29/C30; R1 |
| A9 | Share production evaluation; separate simulation/observation/probes | CLI/UI/MCP evidence parity; bounded event collection and privacy costs | C12/C14/C18/C31; R5/R6 |
| A10 | Optional MCP adapter with transactional proposals | AI-independent core and verifiable authority; version/audit/recovery costs | C01/C14/C30/C31; R7 |

Reject mandatory six-platform PID support, separate game/web kernels, one giant OS/config/protocol trait, mandatory Mesh, default MITM, or performance claims inferred from Rust or hop counts.

<a id="subscription-compatibility"></a>

## 4. Compilation and Clash compatibility

### 4.1 Configuration ownership

1. SourceSnapshot versions and replaces each provider independently, including fetch credentials and status.
2. EndpointCatalog/RuleSet use source-scoped stable identities, distinguishing DIRECT/REJECT from ordinary nodes. Display names can repeat; references cannot be ambiguous.
3. LocalPolicy owns capture, DNS, user groups and scenario rules. Default node imports do not adopt remote OS/listener settings.
4. RuntimeGeneration validates references, cycles, capabilities and protocol options; publish only a fully valid candidate.

Expose explicit **nodes-only** and **full-policy** import modes. The latter imports namespaced rules/groups only where local policy references them. Subscription data cannot silently install listeners, routes, plugins, arbitrary file access or administration credentials.

### 4.2 Compatibility levels

| Level | Scope | Preserved behavior |
|---|---|---|
| L1 nodes | inline proxies, provider-only payload, proxy-providers/use | Identity, replace/delete, credentials, protocol/transport/UDP capabilities |
| L2 groups | select/url-test/fallback/load-balance and nesting | Order, health/fallback, probe units, user choices; unsupported chain/relay explicitly rejected |
| L3 rules | domain/IP/port/process, rule-providers/RULE-SET, supported boolean expressions | Ordering, source vs destination ports, matching modes, desktop ownership capabilities |
| L4 other config | Explicitly supported DNS/sniff options | Declared opt-in/override rules; no claim of complete GUI/API/all-extension compatibility |

Reports identify source locations, inputs, outputs, support levels and semantic loss. Strict full-policy rejects candidates with essential unsupported rules/groups and retains last-known-good configuration. Lenient nodes-only still reports discarded policy. Bound downloads/retries and redact credential-bearing URLs. Replace source versions instead of append-only name merging and rule extension.


SourceSnapshot records SHA-256 of fetched content, source/fetch/parser versions and cache evidence. Existing subscription code already has content_hash and SHA-256 change detection: reuse it and bind it to snapshots/generations. Define coverage as decoded pre-parse content with an explicit encoding. Identical content need not republish; parser/local-policy changes can still require a generation. ETag/Last-Modified are cache hints.

**A digest is not source authentication.** A source can replace both content and its digest. Separate transport trust, source authority and content identity. If a user explicitly pins an expected digest, mismatch rejects the candidate and retains last-known-good state. Signed subscriptions are not a compatibility prerequisite or an implemented feature claim.

## 5. Data plane, process identity and concurrent policies

<a id="route-plan-migration"></a>

### Compatible evolution from RouteDecision to RoutePlan

Existing core RouteDecision already has path/reason/route_type; RoutePath models Direct, ThroughGroup (including group/selected_node/intermediate_nodes) and Chain. This is not a string-only router. RoutePlan is a semantic superset: evolve in place or use one-way adaptation, not another evaluator.

| Existing field | Mapping |
|---|---|
| path | Preserve structured nodes/groups/chains; progressively resolve names to source-stable IDs |
| reason | Preserve legacy text; add structured reason codes/rule/provenance without parsing old prose into evidence |
| route_type | Preserve equivalent routing/terminal actions and existing rejection/error boundaries |
| New fields | Supply generation, scenario, capabilities, queue_class and failure_policy; legacy policy defaults to general/ordinary queues with explicitly equivalent failure behavior |

Keep one authoritative production output. Legacy APIs may expose read-only views, but execution consumes the full plan. Selection is not connection evidence; record actual attempts separately. Test every new field through execution. Existing `profile: proxy|game|web` presets remain configuration-time defaults, with explicit values taking priority and idempotent expansion; concurrent policies do not reintroduce runtime ProfileKind branches.

```text
CapturePort → FlowContext
  → bounded OwnerResolver (three local desktops) + DNS/sniff as needed
  → local-priority rules and explicitly referenced subscription rules
  → RoutePlan(group, scenario, capabilities, queue, failure policy, reason)
  → SessionExecutor(generation/endpoint pin)
  → DIRECT / standard proxy / optional managed Mesh
```

Desktop ownership validates flow keys, PID/start identity, executable path/user rather than caching a PID alone. Preserve imported name/path/matching semantics; truncated Linux comm is not a full executable path. Queries have deadlines and explicit Known/Unknown/Unsupported states. Rules depending on ownership declare their unknown policy rather than silently bypassing a proxy.

Other platforms classify using available domain/IP/port/device evidence. Without trusted app identity, two apps with indistinguishable targets cannot be guaranteed distinct policies. UDP may be web QUIC and TCP may be game traffic.

| Scenario | Objective | Mechanisms | Not promised |
|---|---|---|---|
| game | Small-packet tail latency, session stability, usable UDP | Stable endpoints, hysteresis, budgets and valid observations | Transparent IP changes or universal speedup |
| web | DNS/proxy setup/TTFB and throughput | Valid pre-dial/TLS resumption, domain rules, concurrency budgets | Automatic content caching/decryption or unlimited bandwidth |
| general | Predictable proxy/direct routing | Explicit rules, selection and capability checks | Automatic application identification |

Keep the existing profile enum as a compatible preset generator. The new model defines game/web policies together instead of another exclusive runtime mode.

## 6. Six-platform plan

![Platform boundaries](/architecture/platform-boundaries.svg)

| Platform | Reuse | New delivery | Local process gate |
|---|---|---|---|
| Linux | Current TUN TCP/UDP, routes and /proc lookup | Port extraction, full-name/permission handling, DNS/UDP loop prevention, recovery | **Required:** TCP/UDP, path identity, permission/PID/port reuse |
| Windows | Cross-build/installer templates | Wintun, routes/DNS, SCM, independent owner lookup | **Required:** prototype WFP/ALE or public owner APIs, validate on Windows |
| macOS | Packaging/model scaffold | Supported capture/ownership, signed host/helper/extension, recovery | **Required:** local app identity; freeze OS integration after a platform spike |
| OpenWrt | Linux core/musl/procd packaging | fw4/nftables coexistence, small build, gateway DNS/dual-stack | **Not required:** remote client PID; test device/IP/domain/port rules |
| Android | VpnService/JNI/ICMP demo | Full shared TCP/UDP plane, protect, foreground lifecycle, revoke/network switching | **Not required:** optional package/UID features separate |
| iOS | Swift provider/build scaffold | Public packetFlow batches, app/extension IPC, shared credentials, bounded memory/background lifecycle | **Not required:** domain/IP/port policies; signed-device tests |

Report dual-stack, DNS bypass, UDP/QUIC, MTU and network changes separately. Reject or explicitly degrade unsupported combinations before startup. Apple packet/app-flow APIs, Windows driver/ownership options and minimum OS/SDK versions require implementation spikes; do not fabricate finalized choices without device evidence.

## 7. Quality, budgets and stable sessions

QualitySample includes metric kind/value/source/target/count/time/validity. Separate proxy setup, synthetic RTT, application response, connection failures and measured packet loss. Sequence/echo-based loss requires a compatible peer. Unknown or stale is not zero, and insufficient samples do not prove an SLO.

Game/web classes have bounded sessions, dialing, queues and memory with fair scheduling. Protect only controllable bottlenecks; remote/ISP queues may require OS or managed-peer cooperation. New flows follow updated health. Existing sessions pin endpoint/generation/source mapping and drain normally, while security revocations may terminate them. TCP failure and UDP source changes can still require application reconnects.

## 8. Updates and safety boundaries

Build candidate → validate graph/capabilities → prepare resources → plan OS changes → apply reversible changes → publish generation → drain old flows → collect old resources. On failure retain old generation and compensate owned side effects. An in-memory pointer swap cannot make OS routes/DNS atomic; prove behavior using journals, compensation and fault injection.

Keep DNS/fake-IP ownership consistent with surviving sessions and generations. Revalidate capabilities after permission changes. Bound control/refresh/logging and use secret references; do not turn URLs, passwords or complete app histories into unbounded metric labels.

Mesh requires managed-peer capabilities. Standard subscription endpoints remain unchanged. Unsafe UDP Mesh stays rejected until secure carriage is complete. MITM/scripts/plugins remain opt-in, outside the default game hot path.

### 8.1 Debug and MCP boundary

See [Debugging, path explanation and optional MCP](debug-and-mcp.md) for concepts, interfaces, gaps and scopes. Current `/flows` is aggregate data; compatibility `/connections` is not a complete connection table. Existing diagnose bundles are not automatically AI-safe. New tools remain proposals.

CLI/UI/MCP share diagnostic/configuration services. Pure Explain pins generation/quality state; Trace records plans and actual attempts; Probe has network effects and separate authority. Start with local stdio and read scopes. Writes bind server-side proposals, base generations, exact authority and idempotent receipts, reusing publication transactions. Mobile uses authorized host IPC/exports rather than default MCP inside VPN extensions.

## 9. Module ownership and alternatives

| Existing module | Target responsibility |
|---|---|
| core | Flow, streams/datagrams, RoutePlan, ports; no OS or subscription formats |
| config | Canonical IR, reference/capability validation, preset compatibility |
| subscription | Providers, formats, source versions and diagnostics; no local-policy ownership |
| platform | Capture/owner/route/DNS/bypass/events and platform capability implementations |
| routing | Match/actions, group semantics, objectives and explainable choices |
| protocols | Standard protocols, dialers/transports, pools and capability declarations |
| runtime | Generation/session/budget assembly; incrementally reduce runtime_builder scope |
| mesh/plugins | Optional managed topology and extensions, excluded from minimal builds |
| ffi/apps/platform hosts | Batch/lifecycle bridge, CLI/daemon, OS services and IPC |
| Proposed diagnostic/configuration service | Explain/Trace/Probe, sanitized views, proposals/receipts; production router and transactions |
| Proposed optional apps/rillane-mcp | Narrow stdio tools/scopes; no duplicate router or generic admin proxy |

Start with interfaces/modules; split crates only for measurable dependency or reuse reasons. An alternative is building a client around an existing core: faster compatibility/platform delivery but upstream-controlled behavior and upgrades. Owning Rillane retains control at the cost of protocol, platform and measurement maintenance. This study borrows concepts, not upstream code; any later code dependency needs version-specific license review.

<a id="migration"></a>

## 10. Migration and acceptance

RV1 items are architectural indexes. The **single atomic execution backlog is repository-root `todo.md`, RIL-001–RIL-152**. It replaces the old checklist; history stays in Git. Use atomic task commits, fixtures and device evidence rather than independently marking RV1 complete.

| ID | Priority | Work package | Depends on | Gate |
|---|---|---|---|---|
| RV1-01 | P0 | Concepts/IR/diagnostics/capability contracts | — | Legacy config and rejection fixtures |
| RV1-02 | P0 | Source snapshots/stable catalog/replacement | 01 | Collisions, updates, deletion, last-known-good |
| RV1-03 | P0 | Provider/use/provider-only nodes | 02 | L1 fixtures, units/bounded fetch/content hash in snapshot |
| RV1-04 | P0 | Correct group semantics | 01/03 | select/url-test/fallback/load-balance; reject unsupported relay |
| RV1-05 | P0 | Rule sets/process conditions/order | 01/03 | L3 fixtures, src/dst ports, unsupported capabilities |
| RV1-06 | P0 | Local-policy ownership/import modes | 02/04/05 | Refresh does not overwrite user rules |
| RV1-07 | P0 | Generations and OS transactions | 01/06 | Rollback, drain and restart recovery |
| RV1-08 | P0 | Packet/bypass/network event ports | 01 | Linux regression and platform mocks |
| RV1-09 | P0 | Three-desktop owner contracts | 01 | Known/Unknown/Unsupported, deadline/cache/modes |
| RV1-10 | P0 | Linux capture/ownership hardening | 08/09 | TCP/UDP/path/PID/port reuse and permissions |
| RV1-11 | P1 | Windows spike and adapter | production 08/09; spike independent | Wintun/owner/routes/DNS/SCM on Windows |
| RV1-12 | P1 | macOS spike and adapter | production 08/09; spike independent | Public APIs/identity/signing/cleanup on macOS |
| RV1-13 | P0 | Concurrent scenarios/RoutePlan execution | 04/07 | One instance with game and web; preset migration |
| RV1-14 | P0 | Session pin/update/failure policies | 07/13 | Long TCP, UDP mappings, removal and reconnect |
| RV1-15 | P0 | Bounded budgets/queues/fairness | 13/14 | Concurrent download/game without unbounded use or web starvation |
| RV1-16 | P0 | Typed quality/hysteresis/explanation | 13 | Source/age semantics; failure ratio is not loss |
| RV1-17 | P0 | small/mobile/full build pruning | 08 | small excludes Wasmtime/JIT; graph and peak RSS |
| RV1-18 | P1 | OpenWrt gateway integration | 07/08/17 | fw4/procd/dual-stack/DNS/recovery; no remote PID |
| RV1-19 | P1 | FFI packet/lifecycle ownership | production 08/17; iOS spike early | fd and public packetFlow ports; cancellation/ABI tests |
| RV1-20 | P1 | Android full forwarding | 13/14/19 | TCP/UDP/protect/foreground/revoke/Wi-Fi-cellular |
| RV1-21 | P1 | iOS public Packet Tunnel integration | 13/14/19 | No private fd; signed device, IPC/memory/resume/DNS/UDP |
| RV1-22 | P2 | Optional Mesh/plugin boundaries | 14/17 | Standard nodes independent; insecure UDP rejected |
| RV1-23 | P1 | Six-platform contracts/artifacts/device CI | 10/11/12/18/20/21 | Build/capture/recovery reported separately |
| RV1-24 | P1 | Concurrent performance comparison | 15/16/23 | Same endpoint/network/load; p50/p95/jitter/TTFB/throughput/CPU/RSS |
| RV1-25 | P0 | Real traces, pure Explain and active Probe | 07/13/14/16 | RIL-051–061; bounded sanitized evidence |
| RV1-26 | P1 | Path inspection and retention | 25 | RIL-062–064; diagram/JSON parity |
| RV1-27 | P1 | Disabled-by-default read-only MCP | 25/17 | RIL-065–072; stdio, scopes and disclosure tests |
| RV1-28 | P1 | Proposals and controlled MCP writes | 07/27 | RIL-073–082; authority/concurrency/idempotency/recovery |

### 10.1 Critical path and independent deliveries

P0 covers first user value, core foundations and risk spikes; P1 covers later committed platforms/tools; P2 covers deferrable enhancements. Work-package dependencies describe production integration, not a ban on fixing existing bugs or running experiments before interfaces freeze. Atomic tasks are authoritative.

- **M0: early spikes.** RIL-032/036/094 independently test Windows ownership, macOS capture/identity and public iOS packetFlow. Findings inform platform/FFI contracts before freezing them.
- **M1: current Linux compatibility candidate.** RIL-092/093 → RIL-095 fixes interval units and guards semantic loss using existing forwarding. Do not claim complete fallback/provider/ScenarioPolicy delivery.
- **M2: new Linux baseline.** Source replacement, faithful imports, generations/OS compensation and Linux recovery form an independently reviewable candidate before concurrent scenarios or six-platform completion.
- **M3: concurrent Linux game/web.** Add scenario/session/budget behavior and measure controllable benefits. Pools, six-platform benchmarks and optional Mesh do not block it.
- **M4/M5: Debug, read-only MCP, controlled writes and other platforms.** Deliver through independent gates; reads do not wait for writes, and each platform can validate without all others finishing.

Six-platform summaries/full-scope documentation are closing evidence, not a universal lock on intermediate deliveries. Mesh enhancement may wait; insecure existing paths must still reject. Candidates do not imply stable-release authorization. Missing device evidence remains unverified.

See [v1 IO and accounting contracts](io-and-accounting.md) for inbound/outbound boundaries, ownership, transport composition and layered counters.

Protocol modules prefer external-library adapters; separate protocol identity from Factory/feature-selected backends. Keep dependency types outside routing/sessions and validate socket bypass, cancellation and equivalent accounting. See [IO contracts](io-and-accounting.md).

See the [protocol integration plan](protocol-roadmap.md): write protocols only when no usable implementation exists; evaluate/reuse backends before integration without blocking baseline milestones.

See [UI/control specification](ui-prototype-v1.md) and [10 saved prototypes](ui/README.md). Capture, routing mode, DNS answer form and query egress are independent; global/direct disclose overrides. Images are proposals, not implementation evidence.
