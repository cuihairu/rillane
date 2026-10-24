# System routing and network takeover (current state: Linux TUN data plane wired)

> Status: **Linux data plane wired** (P1-1 real device/route implementation + P1-2 TunIngress wired into the runtime + P1-3 `network` block plus the three control-plane route endpoints and the `seepctl route` CLI; cross-platform providers not landed) · Related: [architecture.md](architecture.md) · [design/positioning.md](design/positioning.md) (gap G2) · [design/roadmap.md](design/roadmap.md) S2 · todo P1-1..P1-3

## Executive summary

System-level traffic takeover (TUN/redir + process/port partitioning) is the precondition of the game-acceleration scenario -- an application that does not go through the proxy cannot be caught by a proxy ingress. **Since 2026-10-03 the Linux path is genuinely usable**: `seep-platform::network::linux` (real LinuxTunProvider / LinuxRouteManager, `/dev/net/tun` + TUNSETIFF + explicit routing in the main table + AppliedStep rollback) + `seep-runtime::tun_ingress` (TunIngress as a new ingress type: full-chain UDP at T3, smoltcp userspace TCP termination at T4, the `seep_tun_*` metric family at T5) + the top-level `SeepConfig` `network` block wired into seepd (P1-3 R1) + the three control-plane endpoints `/network/route/{apply,clear,status}` and the `seepctl route apply [--dry-run]/clear/status` CLI (P1-3 R2-R4, 1befbe7 -- RouteControl contract `apply_desired(dry_run)`/`clear`/`status`: idempotent replay, reverse-order undo, E7 in-batch reverse rollback, E10 explicit scope). Local two-scenario walkthrough verified (2026-10-03): **per-process partitioning on the same target 1.0.0.1** (python3->web-node, curl->game-node), **per-port partitioning** (NTP UDP:123->game-node), three legs concurrent on one host without interfering; data-plane latency of the path itself is about the same as direct (UDP +2.6 ms, TCP hot-flow connect 1 ms / first byte about equal to direct), and the first packet of each flow pays a one-time `/proc` process-attribution scan (measured 60-86 ms on this host with 593 processes, TTL 30 s including a negative cache). **Still not landed**: macOS/Windows/Android/iOS platform providers (`platform.rs` is a dead draft, not compiled), the `filter.rs` packet-filter surface (currently carried by the routing engine's `MatchCondition`). Implementation-level design in [design/tun-dataplane.md](design/tun-dataplane.md) (P1-1/P1-2) and [design/network-route.md](design/network-route.md) (P1-3).

## 1. Built (model layer + platform implementation)

| Submodule | Content | Status |
|--------|------|------|
| `tun.rs` | `TunProvider` trait, `TunConfig` (address/route/MTU), `PacketInfo`/`PacketType`, `TunPacketStream`, `TunInterface<T: TunProvider>` | model complete; **Linux real implementation landed** (`network/linux.rs` LinuxTunProvider, c076fb8/75c7747) |
| `route.rs` | `RouteManager` trait, `RoutingConfig`/`RouteRule`/`RouteDestination`/`RouteType` (including validation and matching logic) | model complete; **Linux real implementation landed** (LinuxRouteManager = explicit main-table routing + AppliedStep rollback, 92f12ba) |
| `filter.rs` | `PacketFilter` trait, `FilteringConfig` (`ProcessRule`/`PortRule`/`IpRule`/`DomainRule`/`ProtocolRule`/`ApplicationRule`), `FilterStats` | model complete; no packet-filter implementation -- process/port partitioning actually runs through the routing engine `MatchCondition::Process/Port` + TunIngress first-packet attribution (2026-10-03 scope) |
| `dns.rs` | `DnsHandler` trait and the DNS proxy/cache/hijack/DoH design | model complete; **runtime implementation landed** (`dns_engine.rs` EngineDnsHandler + `DnsService`, todo DNS subsystem M0-M1, 2026-10-02) |
| `platform.rs` | **only five macOS placeholder types** (Utun/Tap Provider, RouteManager, PacketFilter, DnsHandler drafts); **not compiled** and would fail to compile if enabled (the placeholders lack most trait methods) | dead draft: P1-1 rewrote the integration as the new module `network/linux.rs` per [design/tun-dataplane.md](design/tun-dataplane.md) §1.4 -- this file intentionally stays uncompiled and is not a fill-in target |

## 2. Current-state cross-check (backfilled 2026-10-03)

**Wired (code + measured acceptance)**:

- **Real TUN device (Linux)**: `/dev/net/tun` + TUNSETIFF, packet read/write loop, captured IP packets entering FlowRouter -- `network/linux.rs` (T0-T2: c076fb8 trait trimming + four-factory dispatch, 75c7747 device lifecycle + read/write + capture pinning, 92f12ba RouteManager + AppliedStep rollback). Root-privileged integration test passed end to end: device creation -> route application -> five-tuple feed -> attribution -> echo -> teardown with route rollback + device destruction.
- **Runtime wiring (TUN as a new ingress type)**: `seep-runtime` `TunIngress` injected into `ingress_endpoints["tun"]` and started alongside ingress types such as socks5 (since 2026-10-05 validate allows TUN-only: an empty ingress list passes only when `network.mode=tun`, i.e. the TUN device is the ingress; earlier the MVP required at least one non-TUN ingress) -- **T3 a9f11dc**: five-tuple flow table / first-packet `/proc` attribution (`process.*` annotations -> `MatchCondition::Process` active) / three-source anti-loop auto-bypass / §2.9 event enumeration in a single loop (the tun guard is owned by one task, read/write and sweep consolidated into one select); **T4 b5785c2**: smoltcp 0.14 userspace TCP stack (first SYN sticks the route -> Established hands off to `FlowOutput::forward`, SmolTcpStream bridges AsyncRead/Write, single poll drive point combining kick events with sweep reuse); **T5 7a3024d**: the `seep_tun_*` metric family (packets/bytes per direction, flows_active, bypass_dropped, parse_errors, unknown_flow, process_attr_miss always rendered).
- **Config block**: top-level `network` in `SeepConfig` (`mode: tun` + mirrored `tun`/`routing` sub-blocks) + seepd derived switches (`enable_network_virtualization`/`network_config`, NetworkManager defer ruling) -- P1-3 R0/R1, merged with 1e1a7c0; `network.mode: tun` enables the TUN ingress.
- **Route control plane + CLI (P1-3 R2-R4, 1befbe7)**: RouteControl contract on `LinuxRouteManager` (`apply_desired(dry_run)` with a planner whose execution and deduplicated ledger come from the same source, `clear` for reverse-order undo, `status` snapshot; E7 in-batch reverse rollback on failure is not ledgered, E10 = explicit scope when the interface does not exist) -> three seepd endpoints `POST /network/route/apply` (`{"dry_run"}`, no TUN -> 503) / `POST /network/route/clear` (E8 idempotent on an empty table) / `GET /network/route/status` (mode/device/mtu/up/applied) -> `seepctl route apply [--dry-run]/clear/status` (line-per-argv table of `plan:`/`ok:`/`undo:`); startup apply and CLI apply are the same method, and TunIngress teardown undoes automatically.
- **Two-scenario concurrent walkthrough** (local seepd measured, 2026-10-03, config sample `config/seep-demo-dual.yaml`): three legs concurrent on one host -- web python3 TCP->web-node (default rule), game curl TCP->game-node (`process: ["curl"]` rule), game NTP UDP:123->game-node (`port: [123]` rule) -- the logs let you reconcile per flow (`flow established (handoff) node=... process=...`); latency comparison before/after is in the executive summary.

**Still not landed**:

- **Cross-platform providers**: macOS/Windows/Android/iOS not implemented (`platform.rs` is a dead draft, not compiled; the Android VpnService has only a minimal ICMP path in seep-ffi, and the real TCP/UDP proxy path is deferred to the TunIngress port).
- **The `filter.rs` packet-filter surface**: trait and config model exist, no standalone implementation -- partitioning is carried by the routing engine (see the §1 scope).
- **direct egress self-loop blind spot (found in the walkthrough -> implemented, 2026-10-05 egress fwmark batch R1-R3)**: the included `/32` route pulls seep(root)'s own direct outbound back into the TUN (the §2.7 auto-bypass has no server literal to exclude for direct egress) -- the walkthrough worked around it with an `ip rule uidrange 0-0` escape; the proper fix: **stamp `SO_MARK` on every outbound TCP socket (`seep_core::net_mark::connect_tcp`, default mark=0 for zero difference, configured by `network.egress_fwmark`) + LinuxRouteManager in TUN mode builds the escape table / `ip rule fwmark` escape rule on apply (AppliedStep rollback ledgered, EEXIST tolerated)**. Default None/0 means no mark; without CAP_NET_ADMIN it degrades to direct with one warning; the UDP plane (quinn/hy2) is not covered, documented as-is.
- **Current only read-only capability**: `seepctl diagnose` collects a snapshot of local routes/DNS/interfaces for troubleshooting (unchanged).
- **Outbound dial race (RFC 8305 Happy Eyeballs, 2026-10-07)**: `net_mark::connect_tcp` sorts multi-candidate resolution results IPv6-first in dual-stack interleaved order (v6[0], v4[0], v6[1], v4[1]...), dials the first choice immediately, covers with the second choice 250 ms later, and covers immediately on any failure, with the first success winning (in-flight losers drop themselves); if all fail it collapses to the last error. A single candidate keeps the original direct path (no spawn overhead). direct and every proxy egress share this unified dial surface and benefit automatically; the SO_MARK surface (fwmark above) applies per candidate inside the same race framework.

## 3. Target shape (Linux path implemented)

```
app traffic --> TUN device (TunProvider.read_packet)
                 |  IP flow reassembly (five-tuple -> flow)
                 v
           PacketFilter (process/port/bypass rules; bypass: LAN/DNS/admin ports default-safe)
                 v
           FlowContext (injects process ID, port, protocol)
                 v
           FlowRouter --> the exact same routing/egress/chain pipeline as proxy ingress
```

- TUN is just **one more ingress type**: the routing engine and the egress protocol stacks treat TUN traffic and socks5 traffic identically (positioning.md §2.2).
- UDP traffic entering through the TUN relies on the S1 full UDP chain ([udp-dataplane.md](design/udp-dataplane.md)); QUIC traffic is marked as `TargetProto::Quic` (the enum already exists).
- Platform implementation order: Linux (landed) -> OpenWrt (reuses the Linux path, static musl) -> Windows (Wintun) / macOS (utun) / Android (VpnService) / iOS (NEPacketTunnel).
- Process-dimension sessions: once TUN supplies process info, the `process_id` field of the UDP session sticky key (see udp-dataplane.md §1.2) starts to matter.

## 4. Acceptance alignment (todo P1-1..P1-3)

1. P1-1: **passed** -- in the Linux integration tests, TUN device creation and captured IP packets entering FlowRouter (skip guards for two cycles + root-privileged e2e);
2. P1-2: **passed** -- per-process/per-port partitioning (walkthrough measured: same target 1.0.0.1, python3->web-node, curl->game-node; UDP:123->game-node), bypass default-safe (default rules + user rules + auto-bypass, three sources); mesh chain transport was not in this round of walkthrough (same rule surface, nodes demoed as direct);
3. P1-3: **passed** -- the `SeepConfig.network` block + seepd derived switches (1e1a7c0) + the three control-plane endpoints and `seepctl route apply [--dry-run]/clear/status` (1befbe7); after apply the explicit main-table routes match expectations and clear restores fully (removing only the steps seep added), repeated runs are idempotent (replace + deduplicated ledger), failures roll back automatically (E7 in-batch reverse) -- pinned by unit tests (mock executor/REST shape/CLI rendering) plus the §7.2 guard integration (`route_apply_clear_roundtrip`: zero change on dry-run / unique prefixes for apply x2 / status reconciliation / clear back to baseline).

This page is backfilled continuously as implementations merge; the status scope of this section is 2026-10-03.
