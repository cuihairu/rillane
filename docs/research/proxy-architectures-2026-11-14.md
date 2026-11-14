# Proxy architecture study: Clash/Mihomo, sing-box and Surge

Date: 2026-11-14. Rillane baseline: `46c2b1256e78e830a1d1783ae908893f7377b768`. This is a research and design package, not an implementation release.

Read the [32 architecture concepts](../design/architecture-concepts.md), [target architecture and migration](../design/architecture-v1.md), and [current implementation](../architecture.md). Standalone SVGs are reproducible with `scripts/render_architecture_diagrams.py`.

**Process-based routing is required only on local Windows, macOS and Linux hosts.** OpenWrt, Android and iOS remain proxy and concurrent game/web targets; desktop-style process attribution is not required there.

## 1. Evidence and limits

| Subject | Evidence inspected | Valid scope | Excluded claims |
|---|---|---|---|
| Clash/Mihomo | Mihomo **Meta** snapshot `0455d0d28c4526937380505153e65a843d8612e8`: config, executor, tunnel, provider, metadata, process, DNS and fallback; official docs | Modules and semantics in that snapshot | All historical Clash versions or every GUI behave identically |
| sing-box | **testing** snapshot `3dd8aa48d403f50cced084f46b4b0d5758bd4bd1`: Box, router, TUN, platform and libbox; official docs | Typed interfaces, assembly, platform callbacks and actions | Every development feature is in stable releases or every host |
| Surge | Official functional guide, Smart Group, process and policy documentation | A documented functional model | Private classes, internal queues/threads, undisclosed algorithms or performance superiority |

The original Dreamacro/clash repository returned 404 during this run. The Clash/Mihomo diagram therefore uses verifiable Mihomo evidence, not an alleged source audit of original Clash. The queried Mihomo default main metadata did not identify the proxy kernel; the research explicitly selected **Meta**, whose source imports github.com/metacubex/mihomo and implements the tunnel. Never infer project architecture from an unverified default HEAD.

Snapshots are research anchors, not new Rillane dependencies. Live documentation evolves; compatibility fixtures must pin their own supported versions. Solid green arrows show main data relationships, dashed blue configuration/control, and dashed amber quality feedback. Diagrams omit detailed calls, locks and retries. All dashed boxes in the Rillane target diagram describe proposed boundaries, not completed code.

## 2. Clash/Mihomo: provider-oriented policy composition

![Clash/Mihomo architecture](/architecture/mihomo.svg)

Configuration parsing and executor assembly install providers, rules and proxy objects. A proxy-provider supplies endpoints, while a rule-provider supplies matching data. Keeping them separate lets membership change without rewriting user policy. The tunnel accepts TCP/UDP inputs using Metadata; DNS, sniffing and process lookup enrich information when available. Rules select a policy, groups select a concrete adapter, and the adapter implements transport behavior. Fallback is an ordered availability policy, not random selection. See M1–M7 below.

**Adopt:** provider lifecycles, stable policy references, accurate group semantics, and consistent DNS/session context. **Cost:** reference graphs, cyclic groups, stale members, probes and updates require validation. Single-process operation, TUN, process conditions and policy groups are shared capabilities, not Rillane inventions.

## 3. sing-box: typed adapters and host composition

![sing-box architecture](/architecture/sing-box.svg)

Box assembles managers, dependencies and staged lifecycle operations. Router interfaces and connection metadata separate routing from protocol implementations. Rule actions and rule sets distinguish decisions from reusable matching data. PlatformInterface and libbox let an OS host supply TUN access, connection ownership and network state. An embedded host and a plain CLI can provide different capabilities; neither bypasses OS permissions. See S1–S6.

**Adopt:** typed ports, lifecycle ordering, stream/datagram contracts and explicit host capabilities. **Cost:** interface versions, ownership and shutdown are part of the design. Rillane should use smaller capture/owner/route/DNS/bypass/event ports rather than copy an ever-growing platform interface. Rust and FFI do not make embedding unique to Rillane.

## 4. Surge: documented functions and observed quality

![Surge documented functional model](/architecture/surge.svg)

The official guide distinguishes takeover, processing, forwarding and capture. Rules choose policies; groups implement selection. Smart Group incorporates real-connection observations and tests, including documented failure handling and per-site preferences. Proxy chains are already a public feature. Process rules are explicitly Mac-only; Surge iOS ignores them, and the originating process may be unknown at DNS time. See G1–G4.

**Adopt:** explainable choices, observations distinct from synthetic tests, and explicit platform limits. **Do not assume:** private implementation details or that Smart is merely a minimum periodic URL latency. Optional content capture, MITM and rewrites are separate product capabilities, not prerequisites for transparent game UDP forwarding.

## 5. Concept mapping

| Concern | Mihomo | sing-box | Surge documentation | Rillane proposal |
|---|---|---|---|---|
| Capture | listener/TUN/Metadata | inbound/endpoint/context | takeover | CapturePort + FlowContext |
| Endpoint sources | proxy-provider | outbound configuration/registry | proxy/managed configuration | SourceSnapshot + EndpointCatalog |
| Routing | ordered rules/providers | rule/action/rule-set | rule → policy | RuleSet + RoutePlan |
| Selection | groups/health checks | selector/URLTest | policy group/Smart | PolicyGroup + typed QualitySample |
| OS integration | process and network implementations | PlatformInterface/libbox | Apple host limits | independent ports + CapabilitySet |
| Updates | assembly and provider refresh | manager lifecycle | profile updates; internals unknown | proposed validated generations and draining |
| Concurrent use | rules/groups/flows | shared runtime/routing | policies for different traffic | parallel objectives and resource budgets |

These are responsibility correspondences, not identical types or proof that the last column is implemented.

<a id="verified-gaps"></a>

## 6. Verified Rillane gaps

| Baseline location | Observation | Architectural response |
|---|---|---|
| clash.rs root/group models | No complete provider/use model | Separate source snapshots from runtime endpoints |
| convert_group_type_to_strategy | fallback→Random; relay→ConsistentHash | Preserve semantics or reject explicitly |
| convert_clash_rule | PROCESS-NAME/RULE-SET skipped | Structured diagnostics and strict policy imports |
| convert_proxy_groups_to_groups | ~~interval treated as milliseconds~~ fixed (RIL-092, 2026-11-15): read as seconds; 0/omission map to 300 s; export side corrected in step | Unit policy pinned by `clash_interval_secs` unit tests and YAML counterexamples |
| merge_config_delta_in_place | Append-only names and rules | Source replacement, deletion and local ownership |
| link_quality_between | errors/connections named loss | Typed failure metrics versus packet loss |
| platform network/runtime TUN | Non-Linux TUN rejected | Actual adapter/runtime gates, not cross-build claims |
| Android/iOS demos | ICMP test subnet; private iOS KVC fd | Shared TCP/UDP plane and public packetFlow API |
| runtime → plugins dependency | Wasmtime follows default dependency graph | Verifiable small/mobile build boundary |

Locate by function name rather than assuming line numbers remain unchanged. This study reads code; it does not claim a new six-platform device test.

## 7. Six-platform constraints

![Platform boundaries](/architecture/platform-boundaries.svg)

Linux can reuse its current path while improving attribution and recovery. OpenWrt needs bounded router resources, fw4/procd coexistence and device-level routing; LAN packet forwarding cannot reveal a different host's PID. Windows requires capture and a separate ownership mechanism: Wintun packet I/O is not application identification. macOS needs supported APIs, attribution, signing and entitlement validation. See P1–P3/P9.

Android uses VpnService, protected outbound sockets and network lifecycle handling. Application allow/exclude lists are not equivalent to per-flow outbound selection. UID ownership is an optional, permission-dependent extension, not a delivery gate here. Ordinary iOS Packet Tunnel processes packets and does not promise arbitrary third-party process identity; managed Per-App VPN is a separate deployment case. Use public packetFlow APIs rather than private fd extraction. See P4–P8.

Shared policy semantics therefore coexist with different OS capabilities. On platforms without application identity, game/web selection uses domain/IP/port/device evidence; indistinguishable traffic to the same destination cannot be magically separated.

## 8. Result and next gate

Adopt source separation, typed OS boundaries, observed quality and diagnostics. Propose local-policy ownership, parallel scenario objectives, pinned sessions, generations and bounded resources. Expected benefits remain hypotheses until measured: preserved user intent after subscription changes, stable sessions, bounded competition and less duplicated platform logic.

Do not promise automatic Rust speedups, universally faster multi-hop, obfuscation gains or seamless UDP migration. Follow the [migration gates](../design/architecture-v1.md#migration) and measure under the same endpoints, network and load.

## 9. Official evidence

- **M1:** [tunnel/Metadata](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/tunnel/tunnel.go), [Metadata definition](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/constant/metadata.go), [executor](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/hub/executor/executor.go).
- **M2:** [proxy-providers](https://wiki.metacubex.one/config/proxy-providers/).
- **M3:** [groups](https://wiki.metacubex.one/config/proxy-groups/), [fallback](https://wiki.metacubex.one/config/proxy-groups/fallback/).
- **M4:** [rules/process matching](https://wiki.metacubex.one/config/rules/).
- **M5:** [DNS resolver source](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/dns/resolver.go).
- **M6:** [rule-providers](https://wiki.metacubex.one/config/rule-providers/).
- **M7:** [fallback source](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/adapter/outboundgroup/fallback.go).
- **S1:** [Box lifecycle](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/box.go).
- **S2:** [Router](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/adapter/router.go), [platform](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/adapter/platform.go).
- **S3:** [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/).
- **S4:** [rules](https://sing-box.sagernet.org/configuration/route/rule/), [actions](https://sing-box.sagernet.org/configuration/route/rule_action/), [dial/detour](https://sing-box.sagernet.org/configuration/shared/dial/).
- **S5:** [libbox platform callbacks](https://github.com/SagerNet/sing-box/blob/3dd8aa48d403f50cced084f46b4b0d5758bd4bd1/experimental/libbox/platform.go).
- **S6:** [rule sets](https://sing-box.sagernet.org/configuration/rule-set/), [URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/).
- **G1:** [Surge functional guide](https://manual.nssurge.com/book/understanding-surge/en/).
- **G2:** [Smart Group](https://manual.nssurge.com/policy-groups/smart.html).
- **G3:** [Mac-only process rules](https://manual.nssurge.com/rules/process.html).
- **G4:** [policy parameters/chains](https://manual.nssurge.com/policies/parameters.html).
- **P1:** [Wintun](https://www.wintun.net/).
- **P2:** [Microsoft WFP/ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-).
- **P3:** [Apple Network Extension configuration](https://developer.apple.com/documentation/xcode/configuring-network-extensions/).
- **P4:** [Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- **P5:** [Android application filters](https://developer.android.com/reference/android/net/VpnService.Builder).
- **P6:** [Android connection owner UID](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress)).
- **P7:** [Apple packetFlow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow), [expected Packet Tunnel use cases](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers).
- **P8:** [Apple tunnel manager/managed Per-App VPN](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager).
- **P9:** [OpenWrt firewall overview](https://openwrt.org/docs/guide-user/firewall/overview).
