# P1-1/P1-2 Linux TUN real implementation + TunIngress runtime wiring -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) S2 · [networking.md](../networking.md) §3 target shape · [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) §5 implementation impact (that report is authoritative for audit conclusions such as platform.rs not compiled / placeholder faking write success / missing mount points).
> This document is the finalized landing design: **device interface, data flow, error paths, test strategy, step-by-step implementation checklist**. Deviations are backfilled into §6 after landing.
> Reuse baseline: P0-1 session semantics (sticky key / idle reclamation / error classification, **mirrored not invoked**, see §2.2) · P0-3 `EgressUdpConnector` / capability scan · TCP mesh data plane (`mesh_transport`, existing) · `socket2` (already a seep-platform dependency) · annotation-matching precedent (`geoip.country`/`client.cidr`, `seep-routing::matches_rule`).

## 0. Scope and the P1-3 boundary

| In this item | Belongs to P1-3 / other items |
|-----------|-------------------|
| `LinuxTunProvider` (real device I/O) + minimal `LinuxRouteManager` (addr/route idempotency + rollback) | `SeepConfig.network` config block schema, `seepctl route apply/clear` CLI, full include/bypass semantics, global takeover (fwmark/ip rule/SO_MARK) |
| `TunIngress` (UDP NAT side + TCP userspace-stack side), programmatic runtime wiring (`RuntimeConfig.network_config`) | redir/transparent modes (nftables/iptables) |
| Process attribution (best-effort, carried via annotations) + `MatchCondition::Process` | DnsHandler implementation (P2-8), kernel-state PacketFilter implementation (does not exist; in-process rules are exactly the bypass matching of §2.7) |
| Linux (including OpenWrt musl on the same path) | Windows(Wintun)/macOS(utun)/Android/iOS (to be filled in later following this shape) |

Soft dependency: **UDP over a mesh link** requires P0-4 `UdpChainRouter` to land (S5) before it is usable; **TCP over a mesh link** works immediately with the existing `FlowOutputRouter::forward_chain`. If P1-2 acceptance targets a UDP game, it runs in the same period as P0-4; a TCP target can go first.

## 1. P1-1 `LinuxTunProvider`

### 1.1 Device lifecycle

- Open `/dev/net/tun` (`OpenOptions::new().read(true).write(true)` -> `OwnedFd`);
- `TUNSETIFF` ioctl (enable the existing optional dependency `nix`, features `ioctl`+`fs`, only under `[target.'cfg(target_os = "linux")'.dependencies]`): fill `ifreq` with `config.name` (`None` -> empty name, kernel assigns `tun%d`, `TUNGETIFF` reads back the actual name); flags = `IFF_TUN | IFF_NO_PI` -- **pure IP packets with no 4-byte prefix**, directly aligned with `tun.rs::PacketInfo::parse_ip_header`;
- Single fd (`IFF_MULTI_QUEUE` goes to V2), non-blocking + `tokio::io::unix::AsyncFd` readiness loop;
- Destroy = drop the fd (the kernel reclaims the interface automatically); MTU comes from `TunConfig.mtu` (default 1500; 1400 is the recommended setting for games/QUIC, a documentation hint, not enforced).

### 1.2 Interface signature

```rust
// crates/seep-platform/src/network/linux.rs (new single file, design estimated ~400 lines; landed at 1757 lines including tests)
pub struct LinuxTunProvider {
    config: TunConfig,
    fd: Option<AsyncFd<OwnedFd>>,
    name: String,          // read back via TUNGETIFF
    up: bool,
    stats: InterfaceStats,
}
impl TunProvider for LinuxTunProvider {
    // create/destroy/up/down per the previous section; configure_ip = ip addr replace; configure_routing delegates to LinuxRouteManager;
    // read_packet/write_packet = AsyncFd readiness + MTU buffer + parse_packet_info / whole-packet write
    // configure_dns: MVP pass-through (TunConfig.dns_servers recorded only; DNS hijacking belongs to P2-8)
}
pub struct LinuxRouteManager { config: RoutingConfig, applied: Mutex<Vec<AppliedStep>> } // §1.3
```

**Trait pruning (authorized by audit report A7)**: delete `TunProvider::packet_stream`, `TunPacketStream`, and `TunInterface` -- the placeholder `AsyncWrite` fakes success and drops data (`tun.rs:453-487`), which cannot be kept; the sole consumer of `packet_stream` is the stream being deleted. The trait goes from 15 methods -> 14, with stable semantics.

### 1.3 Interface attributes and system routing (minimal `LinuxRouteManager`)

- **MVP routing scope = explicit routes in the main table (include semantics)**: run `ip route replace <cidr> dev <tun> metric 0` only for the included set (configured CIDRs / the port ranges that accompany process rules cannot be expressed at the routing layer and stay in-process). Specific prefixes naturally take precedence over the default route -> traffic enters tun; **the default route is not modified**, so seep's own egress connections to relay addresses are unaffected (relay addresses also enter the §2.7 auto-bypass set). **The fwmark escape surface has landed (2026-10-05 egress fwmark batch)**: `network.egress_fwmark` config + uniform `SO_MARK` on egress TCP sockets (`seep_core::net_mark::connect_tcp`, default 0 for zero difference) + apply-time `ip rule fwmark` escape table/escape rules (recorded in AppliedStep for rollback, EEXIST tolerated) -- when fwmark is configured, apply uses ip rule; global takeover via default-route rewriting still belongs to V2.
- Tooling: the `ip` command as a subprocess (`tokio::process::Command`). Rationale: universal across Linux/OpenWrt (the busybox ip subset suffices); netlink (the `rtnetlink` crate) is for V2. Note: this is the repository's **first library-level write-operation shell-out** (the existing precedent is only seepctl diagnose's read-only collection), see §6 deviation #2.
- **Idempotency**: `ip addr replace`/`ip link set up` are naturally idempotent; route `replace` likewise. `AppliedStep` logs the executed steps;
- **Rollback**: on mid-apply failure -> undo the executed steps in reverse order, then bail (startup failure is not silenced); `clear_routing` = undo all AppliedSteps in reverse order (P1-3's `route clear` will reuse the same mechanism).

### 1.4 Module wiring

- `network/mod.rs` gains `#[cfg(target_os = "linux")] pub mod linux;`; the four factories (`mod.rs:304-325`) change from always-Err to: the tun/route factories dispatch to linux.rs under `#[cfg(linux)]`, other platforms keep Err; the filter/dns factories keep Err with error messages pointing to "filter = in-process rules (§2.7 of this document) / dns = P2-8";
- `platform.rs` dead draft: stays uncompiled, with a one-line comment at the top pointing to this document (to be added at implementation time; no source changes this round); the `nix` dead dependency is hereby enabled.

## 2. P1-2 `TunIngress`

### 2.1 Overall data flow

```
local application (socket follows tun routing)
   │ IP packet
   ▼ /dev/net/tun ──read_packet──► TunIngress packet loop (run)
   │ ① PacketInfo parsing (existing tun.rs) + IP/UDP/TCP header codec (§2.3 new pure functions)
   │ ② bypass matching (BypassRule::matches + §2.7 auto-bypass set)──hit──► drop + count
   ▼
TunFlowTable (§2.2: 5-tuple -> flow entry)
   │ first packet: FlowContext{target, metadata.annotations[process.*] (§2.5)}
   │      -> router.route (flow_router() injected by start(), RuntimeFlowRouter when chain)
   │      -> decision cached sticky in the flow entry
   ├── UDP ──► connector.associate(ctx, &decision) -> Arc<dyn UdpRelay> (P0-3: direct/ss/wg)
   │             │  send_to(payload) -> egress
   │             └ per-flow recv task: recv_from -> build downlink IP/UDP packet (incl. checksum) -> write_packet -> application
   └── TCP ──► smoltcp userspace stack terminates TCP (§2.4) -> IoStream adapter -> Flow{io}
                 -> output.forward(decision, flow) (FlowOutputRouter: single-hop egress / mesh link, existing)
```

### 2.2 `TunFlowTable`

```rust
struct TunFlowKey { proto: Proto, src: SocketAddr, dst: SocketAddr }   // Proto = Tcp|Udp
struct TunFlowEntry { decision: RouteDecision, relay: Option<Arc<dyn UdpRelay>>, // UDP side
                      last_active: Instant, expiry: Instant }
struct TunFlowTable { map: DashMap<TunFlowKey, TunFlowEntry>, idle_udp/idle_tcp: Duration, max: usize }
```

- **Mirror P0-1 semantics instead of reusing `UdpSessionTable`** (ruling): that table is bound to SOCKS5 control-connection/ASSOCIATE admission semantics (the DownlinkFull queue hangs off associate, the concurrency gate, strict source validation), while TUN has no control connection and the source is always the local tun address, so the table shape is simpler; sticky decision, idle reclamation, and `classify_failure` error classification (Timeout family keeps the mapping / Route family drops the mapping and reroutes) -- these **semantics** are mirrored item by item;
- Idle: UDP = `mapping_idle` (60s same-source), TCP = `session_idle` (180s), lazy cleanup + sweep every second (isomorphic with P0-1); upper bound defaults to 4096, evicting the earliest expiry when full (same argument as P0-4 §3 R10);
- Downlink miss (table entry expired/evicted) -> drop + `unknown_flow` counter (same semantics as P0-4).

### 2.3 UDP-side details

- Uplink: `FlowTarget{host: dst.ip as a string, port, proto: Udp}` (dst is an IP literal, no name-resolution step);
- associate goes through the P0-3 `RoutingUdpConnector` (direct/ss/wg); **when the decision is `RoutePath::Chain`**: it has uniformly switched to `UdpChainRouter` **as landed with P0-4 S5 (2026-09)** (chain decision -> mesh bridge, everything else falls to inner) -- the transitional state designed earlier, "first packet bails until wired", disappeared with S5, and this design is compatible with zero changes;
- **Downlink write-back** (new pure function, inside seep-platform, pinned by unit tests): construct `IP(dst=src.ip, src=dst.ip) + UDP header + payload`; the IPv4 checksum may be 0 but the **IPv6 UDP checksum is mandatory** -- implement real checksums uniformly (full computation, about 20 lines, pinned by golden vectors); IP id increments, TTL 64, DF set (no fragmentation).

### 2.4 TCP side: the smoltcp userspace stack

- Dependency assumption: `smoltcp` (new dependency, version decided at implementation time; tun2proxy is a mature precedent);
- Model: a single smoltcp `Interface` (phy layer = an Rx/TxToken adapter over `LinuxTunProvider`) carries all connections, one `TcpSocket` per TCP 5-tuple; smoltcp plays "the peer" to the local application (answering SYN-ACK/ACK/window) and **does not listen** -- a local SYN is an active inbound connection;
- `SmolTcpStream`: smoltcp socket <-> tokio `IoStream` adapter (double buffering + waker; implements `seep_core::IoStream`);
- Handoff: once the handshake completes, `Flow{id, target, io: Box::new(SmolTcpStream), metadata(+process annotations)}` -> `output.forward(decision, flow)`, with the decision taken from the sticky cache of the flow's first SYN;
- Window/MTU: smoltcp buffers sized as tun MTU-40-20; keep-alive not enabled (sensitive to game long-connections).

### 2.5 Process attribution (best-effort)

- Timing: attribute **once per flow on the first packet**, `(src ip:port) -> (pid, comm)` cached with a 30s TTL;
- Method: `/proc/net/{tcp,udp}` to get the inode -> scan `/proc/<pid>/fd` (expensive: do the fd scan only when the routing config contains a `MatchCondition::Process` rule, otherwise skip); netlink sock_diag goes to V2;
- Carrier: annotation keys **`process.name` / `process.pid`** (same-family precedent as `geoip.country`/`client.cidr`; `Flow::context()` already passes metadata through, zero struct breakage);
- Rule side: `seep-config` gains `MatchCondition::Process { values: Vec<String> }`, and `matches_rule` (`seep-routing/src/lib.rs:494`) gains an arm reading the `process.name` annotation (exact match on comm, or absolute-path suffix match -- pick one at implementation time and pin it with tests).

### 2.6 Runtime wiring

- **Ownership ruling**: `TunIngress` is the owner in TUN mode -- it internally composes `LinuxTunProvider` + `LinuxRouteManager` (device creation/addressing/route setup complete at `run()` startup, teardown on exit) and **does not go through `NetworkManager`** (whose generic container shape targets other modes; P1-3 [network-route.md](network-route.md) §2.2 already ruled it is not absorbed, and TunIngress ownership continues);
- Landing point: `runtime_builder::build()` gains a TUN block next to the UDP block -- condition `runtime_config.enable_network_virtualization && network_config.mode == Tun`, constructing `TunIngress` and inserting it into `ingress_endpoints["tun"]`; dependencies are only the router + egress descriptors (the UDP connector table and `scan_udp_capability` **share the same single build result with the P0-3 UDP block**), with no build() ordering problem (unlike P0-4 §9.1 -- `flow_router()` is only taken at `run()` time, and start() already uniformly injects RuntimeFlowRouter);
- `TunIngress: IngressEndpoint`: `run(self: Arc<Self>, router, output)` = device-ready gate -> packet loop + per-flow task family; isomorphic with the socks5 ingress, with zero changes to `start()`'s unified loop.
- **Coexistence and selection boundary with existing ingresses** (same gap closure as P0-4 §1): the TUN ingress and the socks5/mixed ingress coexist side by side in `ingress_endpoints`, both **injecting the same `FlowRouter`** (RuntimeFlowRouter when chain is enabled) and sharing the egress connector table and `scan_udp_capability` result; **the selection boundary is decided by the kernel/application configuration, not chosen by seep** -- socks5 traffic is an application explicitly using the proxy listen port, TUN traffic is the system routing steering application packets into the tun device, and the two paths do not overlap (a packet never enters two ingresses at once); on the UDP side, the TUN flow's `Arc<dyn UdpRelay>` is held by `TunFlowEntry` and **is not registered into the P0-1 `UdpSessionTable`** (that table is bound to the socks5 control connection), so TUN sessions are not counted in `seep_udp_sessions_active`, see §2.8.
- **TUN-only startup is now permitted (honored 2026-10-05; the original MVP startup-rejection constraint is revoked)**: `runtime_builder::validate()` with empty `ingress` permits startup only when `network.mode=tun` and network virtualization is enabled -- TUN itself is the ingress (`build()` injects `ingress_endpoints["tun"]`, `start()` spawns the same loop, with no special-casing for a conventional ingress); other empty-ingress configs are still rejected (the error message notes the exemption). Build-level pin `tun_only_config_builds_with_tun_as_sole_ingress`; TUN-only start on a real machine has not been separately walked through (the difference from the conventional shape is only the missing socks5 listener; the start loop is isomorphic).

### 2.7 Bypass and loop prevention

- **Auto-bypass set** (automatic at build time, no user configuration needed): resolved addresses of all egress `server`/`endpoint` ∪ mesh `listen_address` and registered peer addresses ∪ `control.api_bind` ∪ the tun's own subnet -- these prefixes are **not written into** include routes and also enter the in-process fallback list;
- Default bypass: reuse `route.rs::default_bypass_rules()` (private_ip/loopback/multicast -> Direct semantics = not entering tun);
- In-process fallback: at step ② of the packet loop, a `BypassRule::matches(dst_ip, iface)` hit drops + counts (the routing layer should never have let it through in the first place; belt and suspenders);
- Loop prevention: in explicit include-route mode, seep's egress sockets follow the main table's default route and their targets are already in auto-bypass, so there is naturally no loop.

### 2.8 Metrics (minimal set, names join the P0-5 `seep_*` family)

`seep_tun_packets_total{direction}`, `seep_tun_bytes_total{direction}`, `seep_tun_flows_active`, `seep_tun_bypass_dropped_total`, `seep_tun_parse_errors_total`, `seep_tun_unknown_flow_total`, `seep_tun_process_attr_miss_total`. Atomics + `/metrics` rendering hook into the P0-5 §7 landing-point list (they appear together when that document is accepted).
- **Metering boundary**: TUN traffic **does not enter `seep_udp_sessions_active`/`seep_udp_relay_bytes_total`** -- TunFlowTable is independent of the P0-1 `UdpSessionTable` (§2.2 mirrors without reuse); the P0-5 `seep_udp_*` series reflects only socks5 inbound UDP, while TUN sessions/bytes go only through this document's `seep_tun_*` family. Operators should not misread `seep_udp_*` being zero while TUN has traffic as a fault (the two sides use different definitions and belong to two separate series families).

### 2.9 smoltcp poll driving and downlink injection (T4 main-path completion)

> 2026-09-30 six-element audit completion: R-tun1 marks smoltcp integration as the main T4 workload, but §2.4 gave only the model without a driving mechanism -- T4 had nowhere to start; this section pins it down. No APIs are invented: `Interface::poll`, phy `RxToken`/`TxToken`, and tokio `Notify`/`Waker` all already exist (assumption; the version is decided at T4 implementation time, aligned with §6-1).

- **Single poll drive point**: each packet read by the `TunIngress::run` packet loop -> classified as TCP at the IP layer -> fed to the smoltcp phy's RxToken -> one `Interface::poll(&mut iface, Instant::now())`; IP packets to send produced by the poll are written back through the phy TxToken to `LinuxTunProvider::write_packet`;
- **Downlink injection** (egress -> application): the egress side writes `SmolTcpStream` (`AsyncWrite`) -> data enters the smoltcp socket's tx buffer -> **wakes the run loop via `tokio::sync::Notify` to run one more poll**, and the poll generates an IP segment containing the data sent toward tun. The run loop structure = `select` over tun read-readiness ∥ Notify; **no separate poll timer task is started** (MVP -- periodic polling would spin on idle flows, and read/write event driving already covers both directions);
- **Waker**: `SmolTcpStream`'s `AsyncRead`/`AsyncWrite` register a tokio waker when the socket cannot be satisfied immediately, and after poll advances the state the corresponding `IoStream` task is woken -- no busy polling (aligned with §2.4's double buffering);
- **Backpressure**: smoltcp window full -> `AsyncRead` returns Pending -> the egress-side output blocks naturally (same semantics as socks5 TCP flows, already handled by `FlowOutput`); keep-alive not enabled (§2.4, sensitive to game long-connections).

## 3. Error paths

| # | Error point | Condition/errno | Semantics and recovery |
|---|--------|-----------|-----------|
| E1 | Opening `/dev/net/tun` | ENOENT | Error with hint: `modprobe tun` or the container needs the device node mapped; startup fails |
| E2 | Same as above | EPERM/EACCES | Explicit hint that CAP_NET_ADMIN is required (root/capabilities); startup fails |
| E3 | TUNSETIFF | EEXIST | `config.name=Some` is treated as a forced name -> error; `None` never triggers it (kernel assigns) |
| E4 | TUNSETIFF | EINVAL | Illegal flags/name -> program bug, error includes the flags value |
| E5 | MTU validation | <68 | Existing `TunConfig::validate` check (at build time) |
| E6 | `ip` unavailable | NotFound | RouteManager probes `ip -Version` at build time, error includes a busybox hint |
| E7 | addr/route execution failure | non-zero exit | Roll back AppliedSteps in reverse order -> bail (E7 includes the failure reason) |
| E8 | Packet read | EIO/EBADF | Device closed/abnormal -> run loop exits (ingress termination semantics) |
| E9 | Packet parsing | truncated/unknown version/non-first fragment | Drop + `parse_errors` counter; **ICMP unsupported** (MVP drops + counts; PMTU impact see §7 O-icmp) |
| E10 | Flow table full | max | Evict earliest-expiry entries + counter (does not reject new) |
| E11 | UDP associate/send_to failure | per-carrier errors from P0-3 | `classify_failure` with the same keyword classification: Timeout family keeps the mapping (MTU class follows the P0-3 ruling); Route family drops the mapping -> re-decide on the next packet |
| ~~E12~~ | ~~UDP chain decision~~ | ~~`RoutePath::Chain` with P0-4 not wired~~ | **Invalidated (P0-4 S5)** -- Chain decisions are handled by `UdpChainRouter` (`build()` wraps it with `Some(bridge)` and injects it into TunIngress), and the "first packet bails until wired" transitional state disappeared with S5 (the §0 soft dependency is lifted accordingly) |
| E13 | Downlink miss | table expired/evicted | Drop + `unknown_flow` counter |
| E14 | TCP handshake | timeout/RST | smoltcp socket closed + flow table cleanup |
| E15 | Process attribution | proc gone/permissions | `process.*` annotations absent (Process rules do not match) + `process_attr_miss` counter, no error |
| E16 | Stop | stale fd | down + destroy (fd drop) idempotent; teardown rolls routes back in reverse order |

## 4. Test strategy

### 4.1 Unit tests (no privileges, any environment)

- IP/UDP header codec: roundtrip × v4/v6 × uplink/downlink + **checksum golden vectors** (v6 mandatory checksum, v4 both zeroed and true-value states) + truncated rejection;
- `TunFlowTable`: idle expiry (MockClock, following the P0-1 test shape) / upper-bound eviction / sticky decision reused without re-deciding / error classification dropping the mapping and rerouting (keyword-driven);
- Bypass: `BypassRule` matching (supplementary tests for existing logic) + auto-bypass set assembly (including egress/mesh/control sources);
- `MatchCondition::Process`: annotation injection -> matching/non-matching states;
- `ip` argument assembly: command construction separated from execution, asserting the argv vector (not actually executed).

### 4.2 Linux integration tests (`#[cfg(target_os = "linux")]` + runtime skip guard: no `/dev/net/tun` or no CAP_NET_ADMIN -> print skip and return, not counted as failure)

- Device lifecycle: creation (forced name / automatic name read-back) / up / addr / mtu assertions (`ip link show` output or TUNGETIFF);
- Routing: apply idempotency (repeated execution) + full clear restoration + failure rollback (inject a cidr conflict);
- **P1-1 acceptance pin "capture IP packets into FlowRouter"**: route the test prefix into tun -> local `UdpSocket` sends a packet -> mock `FlowRouter` (recording FlowContext) asserts the 5-tuple/target/`process.*` annotations;
- **UDP full path**: real device + mock `EgressUdpConnector`/`MockUdpRelay` (echo) -> application socket sends -> **receive echo** (a downlink reassembled packet with a bad checksum would be dropped by the kernel/application, making the test self-verifying); [landed as `tun_udp_e2e_capture_route_attribution_echo`, covering capture/routing/attribution/echo]
- **TCP full path**: real device + smoltcp + mock `FlowOutput` echo (`FixedReportOutput` same shape) -> `TcpStream::connect(test-prefix address)` sends and receives echo -- no real remote needed, the mock egress loopback verifies the whole path. [Landing deviation: the real-device integration test covers only UDP; TCP goes through device-less injection unit tests (`tcp_full_path_echo_without_device`) + `tun_tcp.rs` unit tests; real-device TCP e2e was not added]

### 4.3 Gates

- The unit test suite has no privilege dependency (runs in normal CI); the integration suite needs a rootful CI or an explicit skip annotation;
- Whole-repo baseline (118 items at the P0-3 point + subsequent P0-4/P0-5 increments) with zero regressions -- this item is entirely additive and changes no existing behavior path.

## 5. Step-by-step implementation checklist (T0-T5)

Dependencies: `T0 -> T1 -> T2 -> T3 (UDP side) / T4 (TCP side, depends only on T1) -> T5`; T3/T4 can run in parallel. Commit cadence follows P0-4 §9.1.1: each step build+test fully green -> a single commit referencing the §section of this document -> `git fetch origin main` + rebase -> push -> next step; no tag/release/force push.

| Step | Content and landing point | Depends on | Acceptance | Landed |
|----|-----------|------|------|------|
| T0 | Trait pruning (delete `packet_stream`/`TunPacketStream`/`TunInterface`) + `network/linux.rs` skeleton + four-factory cfg dispatch + enable nix | — | Compilation green; whole-repo baseline flat; existing seep-platform consumers unaware | `c076fb8` |
| T1 | `LinuxTunProvider`: open/TUNSETIFF/AsyncFd read-write loop + `PacketInfo` integration | T0 | 4.2 device lifecycle + the "capture IP packets into FlowRouter" pin (core of P1-1 acceptance) | `75c7747` |
| T2 | `LinuxRouteManager`: ip helper (construction/execution separation) + addr/route idempotency + AppliedStep rollback + auto-bypass set | T0 (independent of T1) | 4.2 routing idempotency/restoration/rollback | `92f12ba` |
| T3 | UDP side: header-codec pure functions + `TunFlowTable` + `TunIngress` UDP loop + connector wiring + build() TUN block | T1 (+T2 for routing) | 4.1 codec/flow table + 4.2 UDP full-path echo | `a9f11dc` |
| T4 | TCP side: smoltcp dependency + Interface/phy adaptation + `SmolTcpStream` + Flow handoff | T1 | 4.2 TCP full-path echo (mesh-link TCP reachable at this step; real-device TCP e2e see the §4.2 landing-deviation note) | `b5785c2` |
| T5 | Process attribution + `MatchCondition::Process` + §2.8 metrics + documentation backfill (rewrite of the networking.md §2 status section, todo check-off, execution of the status-audit §4 correction list) | T3+T4 | Process/port rule routing tests + metric series visible + P1-1/P1-2 acceptance table fully cross-checked | `7a3024d`+`55e4f14` (backfill 2/3; status-audit §4 was already completed in the 2026-10-04 document reconciliation round) |

Acceptance alignment: P1-1 = T1+T2 (+ musl cross-compilation smoke belongs to P3-3 packaging); P1-2 = T3/T4/T5 -- "route the specified game traffic over a mesh link by process/port rules": a TCP target is verifiable at T4; a UDP target follows P0-4 S5; "bypass safe by default" = T2 auto-bypass + the 4.2 routing tests.

## 6. Deviations and assumptions (self-made assumptions where information was missing are all noted)

| # | Type | Content |
|---|------|------|
| 1 | Assumption | smoltcp chosen as the userspace TCP stack (no repo precedent; tun2proxy precedent), version and phy adaptation details decided at implementation time |
| 2 | Deviation | The `ip` command as a subprocess is the MVP interface-manipulation method (universal on Linux/OpenWrt); the repository's first library-level write-operation shell-out; netlink is for V2 |
| 3 | Assumption | MVP routing scope = explicit routes in the main table (include semantics) + the fwmark escape surface (`SO_MARK` + `ip rule fwmark` escape table, landed 2026-10-05); global takeover via default-route rewriting belongs to V2 |
| 4 | Ruling | `IFF_NO_PI` single fd; multi-queue/TAP goes to V2 |
| 5 | Ruling | Do not reuse `UdpSessionTable`; mirror its semantics (rationale in §2.2) |
| 6 | Ruling | Process information goes through annotations (`process.name`/`process.pid`) rather than a typed `FlowContext` field (precedent `geoip.country`; zero breakage) |
| 7 | Ruling | `TunIngress` takes ownership of device + routing and does not go through `NetworkManager` (§2.6); `platform.rs` stays uncompiled with a pointing comment added |
| 8 | Deviation | The roadmap's "3825 lines" counts uncompiled files, and S2's "platform.rs placeholder already has that shape" does not hold -- backfill takes status-audit §4 as authoritative |
| 9 | Assumption | OpenWrt musl compiles on the same path (std/tokio/nix are all musl-compatible); acceptance of cross-compiled artifacts belongs to P3-3 |
| 10 | Assumption | UDP-over-mesh softly depends on P0-4; TCP-over-mesh is immediately usable |
| 11 | Assumption | ICMP not implemented (drop + count); QUIC is passed through as ordinary UDP (the `TargetProto::Quic` enum is kept without special-casing) |
| 12 | Deviation (registered at landing) | TCP "listen handles" are midwifed by smoltcp instead of the literal "pre-built per 5-tuple" -- smoltcp has no per-5-tuple pre-binding API (self-noted in `tun_tcp.rs` §6) |
| 13 | Deviation (registered at landing) | smoltcp TCP sockets disable Nagle (`nagle_enabled=false`) -- latency first |
| 14 | Deviation (registered at landing) | The `max_flows` limit, under the same definition, bounds **new connections**: over the limit, the SYN is dropped (no eviction of existing flows; a different source than the UDP-side E10 eviction semantics) |
| 15 | Assumption (registered at landing) | The TCP stack side is IPv4-only: smoltcp enables only the `proto-ipv4` feature, the IPv6 TCP shape is unsupported (self-noted in `ipcodec.rs` under the same definition); the UDP side supports both v4/v6 |

## 7. Risks and open items

- **R-tun1 (largest item, eliminated)**: smoltcp integration (phy adaptation/waker/window tuning) is the main T4 workload -- **T4 has landed @b5785c2** (`tun_tcp.rs` SmolTcpStream takeover, fallback path not enabled);
- **R-tun2**: cost of `/proc` fd scanning -- triggered only for new flows + only when a Process rule exists; sampling and the switch are left to be tuned at implementation time;
- **R-tun3**: seep's own control-plane/metrics traffic looping back in a global tun-takeover scenario -- include mode is naturally exempt; the fwmark escape surface has landed (egress socket `SO_MARK` + `ip rule fwmark` escape table), while the global mode with default-route rewriting still belongs to V2;
- **O-icmp**: compensation for ICMP (PMTUD/ping) being unsupported = recommend MTU 1400; whether game scenarios need ICMP pass-through is pending real testing;
- **O-quic**: whether QUIC traffic needs to be recognized as `TargetProto::Quic` for rules (the enum is already reserved) -- not done in MVP, to be discussed when a rule need appears;
- **O-netlink**: migration window from the `ip` command -> rtnetlink (P1-3 or V2).
