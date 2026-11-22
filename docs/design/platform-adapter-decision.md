# Platform adapter decision: cross-platform TUN architecture (v1)

Status: **Accepted as design baseline** (2026-11-22, user-directed research and comparison). This document records the mainstream-solution survey behind the six-platform adapter strategy and the decisions derived from it. It amends RV1-11/12/19/20/21 guidance in [architecture-v1.md](architecture-v1.md) with concrete implementation choices. Implementation tasks live in the repository-root todo.md backlog (RIL-033..035, RIL-036..039, RIL-041..042, RIL-045..049).

## 1. Survey scope and evidence limits

Surveyed November 2026, public sources: sing-box internals (canonical Go TUN + libbox platform interface), mihomo/Clash.Meta (sing-box derivative), Rust-side cores (meow-rs, tun2proxy, TinyTun, concord), userspace TCP/IP stacks (smoltcp, lwIP via netstack-lwip) and their published benchmarks (Watfaq netstack-bench, netstack-lwip README). No private benchmarking was run by this repository; numbers below are quoted from the cited projects' own docs/benchmarks and may shift with versions.

## 2. Mainstream architecture comparison

### 2.1 Core architectures

| Project | Language | TUN architecture | Key lesson for Rillane |
|---|---|---|---|
| sing-box | Go | Dual-stack: `system` (kernel TCP/IP, fastest where ioctls exist) / `gVisor` (portable userspace stack) / `mixed` (TCP via kernel, UDP via gVisor). `auto_route` cross-platform; `auto_redirect` Linux nftables. **`libbox.PlatformInterface` inverts TUN creation, connection-owner lookup, network monitoring to the host app** (Android VpnService / iOS NE implement it) | The canonical implementation. Platform-interface inversion is why one core claims six platforms |
| mihomo (Clash.Meta) | Go | Derived from sing-box, own `mips` stack default | Derivative route is viable; no need to out-innovate the original |
| meow-rs | Rust | wintun / tun / utun devices + lwIP userspace stack via in-tree tun2socks bindings; flows dispatch into the normal routing engine | Closest Rust reference: same language, same shape as Rillane's listener→routing-engine split |
| tun2proxy / TinyTun / concord | Rust | `tun` crate (0.8) + ipstack/netstack; five platforms incl. Android/iOS via `--tun-fd` fd injection and packet-information mode | fd-injection pattern is proven for mobile: the app creates the TUN, the core consumes the fd |

### 2.2 Userspace TCP/IP stack benchmark (Watfaq netstack-bench, iperf3 single-stream)

| Stack | Throughput | Note |
|---|---|---|
| kernel direct (baseline) | 9.3 Gbit/s | Ceiling reference |
| **smoltcp** (pure Rust) | **6.5 Gbit/s** | Fastest pure-Rust option; no FFI, no C build |
| lwIP (C, netstack-lwip) | 3.9 Gbit/s | Common in Go-ecosystem cores; **global lock serialises all calls** — aggregate throughput falls as flow count rises (documented by netstack-lwip itself) |

Caveats: single-stream numbers; multi-flow lwIP degradation is documented upstream; smoltcp buffer sizing materially affects max throughput. Re-benchmark on Rillane's own workloads before freezing RIL performance budgets.

## 3. Decisions

1. **D-PA-1: platform-interface inversion (from sing-box).** The core never creates TUN devices on mobile. The host app (Android VpnService, iOS Network Extension) creates the device and hands the core a file descriptor; the core consumes `--tun-fd`-style. Desktop keeps core-side creation where privileges allow. This is the same split RV1-19 already implies (FFI packet/lifecycle ownership); this decision names the pattern explicitly.
2. **D-PA-2: userspace stack = smoltcp (from benchmark + same-language).** Pure Rust, fastest of the userspace options measured, no C bindings in the build. lwIP stays a documented alternative if smoltcp hits protocol-completeness walls (RV1 performance budget re-check gates this).
3. **D-PA-3: device layer = `tun`/`tun2` crate family (from tun2proxy/meow-rs).** Linux `/dev/net/tun`, Windows wintun.dll, macOS utun — one abstraction, per-platform configuration. Do not hand-roll ioctl per platform.
4. **D-PA-4: mobile = fd injection, not device management.** Android: VpnService owns the TUN, `protect()` marks outbound sockets, per-app routing via tun2proxy's session-info embedding pattern (getConnectionOwnerUid). iOS: NEPacketTunnelProvider packetFlow → fd (packet-information prefix required, as documented in tun crate iOS examples). Rillane core stays app-store-neutral Rust.
5. **D-PA-5: desktop macOS = same utun mechanics as meshlet's WG-MAC-BT.** utun naming (`utun[0-9]+`), `ifconfig`/`route` dialect, MTU discipline, launchd helper for privileges. One Intel-mac device validates both meshlet (WG) and rillane (proxy TUN) probes.
6. **D-PA-6: iOS keeps its hard gate.** Network Extension only loads on signed devices with a developer account; simulators cannot load extensions. RIL-094 stays BLOCKED until an Apple developer account + signing device exists. No design work can lift this gate.

## 4. Platform matrix (six-platform consequence)

| Platform | TUN source | Privilege boundary | Core involvement | Rillane tasks |
|---|---|---|---|---|
| Linux | `/dev/net/tun` via tun crate | root/CAP_NET_ADMIN | full (device + stack) | existing path, improving attribution/recovery |
| OpenWrt | same as Linux, bounded RAM | root, procd service | full, small build | RIL-041/042 |
| Windows | wintun.dll | elevation (SCM service) | full | RIL-033/034/035 |
| macOS | utun (tun crate) | launchd helper / sudo whitelist | full | RIL-036 (P0 probe) → 037/038/039 |
| Android | VpnService (host app) | app VPN permission | fd consumer + stack | RIL-045/046 |
| iOS | NetworkExtension (host app) | entitlement + signing | fd consumer + stack | RIL-094 (P0 probe, BLOCKED) → 047/048/049 |

## 5. What this decision does not claim

- No automatic Rust speedup over Go cores (explicitly rejected in the upstream study, section 8).
- smoltcp benchmark numbers are quoted, not re-measured here; RIL performance budgets re-check on Rillane workloads.
- iOS unblocking requires external assets (developer account, signing device) that no architecture choice can substitute.

## 6. Related

- [Upstream architecture study](../research/proxy-architectures-2026-11-14.md) — Mihomo/sing-box/Surge concept mapping and evidence (M1-M9, S1-S6).
- meshlet WG-MAC-BT (separate repository) — Intel-mac boringtun validation shares the device and the utun mechanics; findings feed back into RIL-036's probe record.
