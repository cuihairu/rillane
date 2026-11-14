# Rillane Phased Roadmap

> Status: design doc (2026-09) | positioning basis: [positioning.md](positioning.md) | actionable items: [todo.md](../../todo.md)
> Progress at a glance (2026-10-05): S0 complete | S1 complete 5/5 (P0-1..P0-5 all landed) | S2 complete (P1-1/P1-2 closed out T0-T5 on 2026-10-03; P1-3 R0-R4 landed) | S3 complete (P1-4 M0-M4, P1-5 M0-M5) | S4 complete (P2-1..P2-8 all landed, P2-7 closed out on 2026-10-04; all six P3 items closed -- P3-1 doc alignment, VMess egress 2026-10-02, P3-2 plugin dynamic loading, P3-3 platform packaging 2026-10-04, P3-4 mobile FFI 2026-10-02, P3-5 zero-copy/batched I/O 2026-10-05) | item-level statistics in the statistics section of [todo.md](../../todo.md) (P0 5/5, P1 5/5, P2 8/8, P3 6/6).

## Executive Summary

Organized around the principle of "one data path, three scenarios", the remaining work is split into 5 phases (S0-S4). Core judgments:

- **The S0 foundation is essentially ready** (full TCP path + mesh link + subscription + control plane), directly reusable, no rewrite needed;
- **S1 bringing UDP end to end** is the single highest-leverage step now -- it is the foundation for game acceleration and the condition for Hysteria2/WireGuard egress to actually deliver value;
- **S2 real TUN** lands system-level takeover (process steering for game traffic), Linux/OpenWrt first;
- **S3 obfuscation cross-cutting layer + web acceleration** (connection reuse) layered onto the path, serving all three scenarios;
- **S4 scheduling closed loop and release** use observability data to drive low-latency path selection and complete multi-platform packaging.

Each phase states "what to reuse / what to add / exit criteria", and the P0-P3 items in todo.md map one-to-one to the phases in this table.

---

## S0: Shared foundation (complete, ongoing maintenance)

**Goal**: TCP data path + peer nodes + subscription + control plane.

| Reuse (implemented) | Evidence |
|---------------|------|
| Flow/Session/Chain data model | `rillane-core` (`Flow`, `FlowSession`, `ChainContext`, `RouteDecision`) |
| Rule routing + group policy (7 strategies, nested groups) | `rillane-routing::RoutingEngine` |
| Ingress socks5/http/mixed; egress direct/ss/trojan/hy2/vless/wg/socks/http | `rillane-protocols` |
| mesh registration/heartbeat/link-state/ACL/quota; chain build/precheck/health check/fallback | `rillane-mesh`, `rillane-runtime::chain` |
| mesh data-plane (TCP hop-by-hop + mandatory mTLS + CA rotation/revocation) | `rillane-runtime::mesh_transport`, see [mesh.md](../mesh.md) |
| Clash import + own DSL + hot reload | `rillane-subscription` |
| Control plane REST + rillanectl (stats/nodes/chain/diagnose/mtls) | `apps/rillaned`, `apps/rillanectl` |
| Prometheus /metrics + Grafana templates | `rillane-telemetry`, `docs/grafana/` |

No new development; this phase's output is the contract layer for S1-S4 (the `IngressEndpoint`/`EgressConnector`/`FlowMiddleware` traits stay unchanged).

## S1: Full UDP path (corresponds to P0)

**Goal**: let game traffic (mostly UDP) traverse "ingress -> routing -> egress -> mesh multi-hop" end to end.

> **Progress (closed out 2026-10-02)**: 5/5 complete -- P0-1 session table / P0-2 UDP ASSOCIATE / P0-3 egress payload (direct/ss/wg) / P0-4 mesh UDP plane ([udp-mesh-dataplane.md](udp-mesh-dataplane.md) S0-S6 all landed, all 27 tests green) / P0-5 observability and config ([udp-observability.md](udp-observability.md) S0-S6 landed) are all done, details in the individual todo items. Exit-criteria errata: hy2 egress UDP carriage was re-judged after P0-3 review -- hysteria2 0.1.6 has no UDP egress in its public API, so it moved to P0-4; the re-judgment stands at P0-4 completion (final state V2, the quinn carrier is undecided).

- **Reuse**: the `FlowTarget` struct (`host`/`port`/`proto`, protocol as the `TargetProto` enum with a `Udp` variant) and `FlowSession` in `rillane-core`; `rillane-routing` is transport-agnostic, rules apply as-is; the existing handshake/cipher stack of the Hysteria2/WireGuard/Shadowsocks egress paths.
- **New**:
  1. `rillane-core`: UDP session semantics (NAT-style mapping table, timeout reclamation, session stickiness key = process/5-tuple);
  2. `rillane-protocols`: SOCKS5 UDP ASSOCIATE ingress; UDP payload framing for direct/ss/hy2/wg egress;
  3. `rillane-runtime::mesh_transport`: UDP data-plane forwarding (envelope over UDP or QUIC datagrams), coexisting with the existing TCP plane;
  4. `rillaned`/config: UDP switches and timeout configuration for ingress/egress.
- **Exit criteria**: a SOCKS5 UDP client completes bidirectional UDP proxying through the direct and hy2 egress paths (**the hy2 half re-judged to V2**, see the progress note above); a two-hop mesh link forwards UDP (achieved by P0-4, T2 real-socket loopback evidence); the session table is reclaimed on timeout (P0-1); the UDP path has independent metrics (deferred to P0-5).

## S2: TUN and system routing (corresponds to P1)

**Goal**: system-level traffic takeover + process/port steering, so game traffic enters the data path without depending on proxy ingress.

> **Progress (closed out 2026-10-03)**: P1-1/P1-2 (T0-T5 all landed: real device/routing implementation + TunIngress UDP/TCP plane wiring + process attribution, [tun-dataplane.md](tun-dataplane.md) step table with commit anchors); P1-3 (R0-R4 landed: network config block wiring + three control-plane endpoints + `rillanectl route`, [network-route.md](network-route.md)); P1-4 M0-M4 and P1-5 M0-M5 both complete (see the S3 note).

- **Reuse**: the existing `TunProvider`/`RouteManager`/`PacketFilter` traits and TunConfig/rule models in `rillane-platform::network` (the traits and rule models are already shaped -- roughly 3588 lines in compilation; `platform.rs` is 237 lines, not part of compilation and only holds a macOS draft, see [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) section 1.2); `rillane-core` routing decisions unchanged -- TUN just adds one more ingress.
- **New**:
  1. Real Linux implementation: `/dev/net/tun` + TUNSETIFF, policy routing (ip rule/fwmark), redir mode (nftables/iptables);
  2. OpenWrt reuses the Linux implementation (musl static build);
  3. `rillane-runtime`: wire up `TunIngress` (IP packet -> flow reassembly -> inject process/port info into `FlowContext`);
  4. `rillanectl route apply/clear` (todo errata: previously marked done, actually missing);
  5. Windows (Wintun) / macOS (utun) / Android (VpnService) / iOS (NEPacketTunnel) fill in later per the Linux pattern (`platform.rs` is a non-compiled single-platform draft; P1-1 rewrites it as a new module for integration -- tun-dataplane.md section 1.4).
- **Exit criteria**: after TUN takeover on Linux, route game traffic to a mesh link by process/port rules; `rillanectl route apply/clear` is idempotently usable; the bypass list (LAN/DNS/admin port) is safe by default.

## S3: Obfuscation cross-cutting layer + web acceleration (corresponds to P1/P2)

**Goal**: let traffic rillane past detection (QoS/DPI resistance) + connection efficiency (web scenario).

- **Reuse**: the `FlowMiddleware` trait (obfuscation mounts as middleware -- P1-4 already built the static middleware chain (`obfs_config.rs::build_middleware_chain`), and P3-2 adds a WASM loader on top of it; audit history in [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) section 3); the existing TLS impersonation capabilities of each protocol (Trojan/VLESS/Reality class); `rillane-routing` rule steering.
- **New**:
  1. Obfuscation middleware (`rillane-protocols::middleware`): `padding` (packet-length distribution alignment), `timing` (micro-jitter), `shaping` (flow-shape normalization), switched by profile (**complete as of 2026-10: padding P1-4 M0-M4, timing/shaping P2-4 M0-M2**);
  2. Client TLS fingerprint emulation (**complete as of 2026-10, P2-5** -- chrome/ios/safari preset shape parameter tables hang off the single `build_client_config` funnel, pool key/factory key extended, see [tls-fingerprint.md](tls-fingerprint.md));
  3. obfs plugin compatibility (**simple-obfs is available**, 2026-10-07 SS egress SIP003 plugin bridge -- `plugin: obfs-local`, SS TCP plane only; salamander deferred to V2 as an option, hy2 obfuscation config not exposed -- see the SS section of [PROTOCOLS.md](../PROTOCOLS.md));
  4. Egress connection pool: keep-alive reuse per egress + TLS session resumption, serving short web connections (**complete**, 2026-10-02 P1-5 M0-M5 -- [egress-connection-pool.md](egress-connection-pool.md), acceptance criteria 1-3 reproduced via TLS integration tests);
  5. Binary mesh envelope (replacing the JSON header, compressing fixed overhead) (**complete**, 2026-10-02 P2-6 -- [mesh-envelope-binary.md](mesh-envelope-binary.md), TCP plane backfilled with binary codec + receiver-side `{` sniffing for dual-format compatibility).
- **Exit criteria**: with the obfuscation switches on, packet-length/timing features are verified by the statistics script to deviate from the default distribution; the connection pool reduces the handshake count of repeated requests to the same target (metrics as evidence); no breaking changes to existing subscription/config.

## S4: Scheduling closed loop, observability and release (corresponds to P2/P3)

**Goal**: drive low-latency path selection with real link data, and complete platformized release.

- **Reuse**: the `LatencyProbe` middleware, `latency/bandwidth` group policies, `ChainManager` health check and fallback, `/metrics` + Grafana.
- **New**:
  1. per-link latency distribution / loss / switch-reason metrics (closes the todo leftover item; **complete as of 2026-10, P2-1** -- `rillane_mesh_link_rtt_ms`/`rillane_mesh_link_loss_ratio`/`rillane_mesh_switch_total` + `GET /mesh/switches`, see [mesh-link-observability.md](mesh-link-observability.md));
  2. Scheduling strategy upgrade: score and select by an SLO target (e.g. p95 RTT), enabled by default in the game profile (selection/watcher **complete as of 2026-10, P2-2** -- lowest score inside the group policy `slo:` gate + `slo_watch` degradation switching in chain, see [slo-scoring.md](slo-scoring.md); game profile wiring deferred to P2-3);
  3. Scenario profiles: three config presets `proxy`/`game`/`web` (routing templates + obfuscation switches + scheduling objectives), see positioning.md section 2.5 (**complete as of 2026-10, P2-3** -- `profile:` default-fill expansion + pick one of `examples/profile-*.yaml`, see [scenario-profiles.md](scenario-profiles.md));
  3b. Obfuscation middleware extension: timing/shaping perturbation (**complete as of 2026-10, P2-4** -- `TimingMiddleware` startup jitter + `ShapingMiddleware` write-grid normalization, see [obfuscation-timing-shaping.md](obfuscation-timing-shaping.md));
  4. Advanced security closeout: UDP-plane anti-replay + revocation visibility (**landed, 2026-10-04, P2-7**); CRL/OCSP queries and mesh end-to-end MAC are **deferred to V2** (todo P2-7 ruling, see [mesh-advanced-security.md](mesh-advanced-security.md));
  5. Platform packaging: systemd/launchd/Windows Service/OpenWrt; mobile FFI skeleton.
- **Exit criteria**: under the game profile, link switching is driven by SLO scoring and there are switch-reason metrics; binary artifacts for three platforms (Linux/macOS/Windows); a musl package for OpenWrt.

## Phase x crate mapping overview

| Phase | rillane-core | rillane-routing | rillane-protocols | rillane-platform | rillane-runtime | rillane-mesh | rillane-subscription | apps |
|------|-----------|--------------|----------------|---------------|--------------|-----------|-------------------|------|
| S0 (complete) | session/link model | rules + group policy | TCP ingress/egress | trait layer | chain + mesh TCP plane | registration/ACL/quota | Clash + DSL + hot reload | control plane + CLI |
| S1 (5/5) | UDP session semantics | unchanged | UDP ingress/egress | unchanged | UDP data plane | link-state extension | unchanged | UDP config |
| S2 (complete) | unchanged | process match enhancement | unchanged | real Linux TUN | TunIngress wiring | unchanged | unchanged | route apply/clear |
| S3 | middleware mount point unchanged | unchanged | obfuscation middleware + connection pool | unchanged | binary envelope | unchanged | DSL obfuscation fields | profile presets |
| S4 | SLO scoring input | strategy upgrade | metric instrumentation | platform packaging | scheduling closed loop | end-to-end security | unchanged | release artifacts |

## Risks and dependencies

- **S1 is a prerequisite for S2/S4**: without UDP, game traffic taken over by TUN has nowhere to go, and SLO scheduling has no target;
- **S2 depends on real kernel interaction**, needing an integration test environment (Linux CI + NetworkNamespace-level tests); the trait scope means **semantic stability rather than a frozen method set** (approved trimming: tun-dataplane.md section 1.2 removes the three fake I/O placeholders `packet_stream`/`TunPacketStream`/`TunInterface`);
- **S3 obfuscation effectiveness validation** depends on measurement methods (statistics scripts/adversarial samples); build the measurement first, then tune;
- Reconciliation progress on the protocol doc `PROTOCOLS.md` (2026-10-11 reconciliation): among the previously aspirational items (design text ahead of the implementation), VMess egress, egress connection pool, UDP ASSOCIATE, Happy Eyeballs, the SS SIP003 plugin bridge, gRPC/h2 transport, and TLS fingerprint shapes have all been backfilled as "implemented"; the remaining aspirational text is only out-of-scope/ruled-out-of-scope items -- HTTP header modification and compression, SOCKS5 egress UDP relay (not in S1 scope), SS dynamic port assignment (SIP004 server-side feature), VLESS QoS/Vision, mesh automatic key rotation/MFA/JWT, and hy2 UDP carriage (final state V2, quinn carrier undecided).
