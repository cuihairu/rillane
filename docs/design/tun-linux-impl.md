# P1-1 Linux TUN real implementation -- implementation landing design (T0-T2)

> Upstream: [tun-dataplane.md](tun-dataplane.md) §1/§4/§5 (the design final draft -- device interface, data flow, error paths, test strategy, step-by-step checklist). This document is its **P1-1 half (T0-T2) implementation companion**: the TUNSETIFF interface, the packet read/write loop, the `platform.rs` placeholder replacement plan, `LinuxRouteManager` and the actual state of tests, with deviations backfilled in §6. T3+ (the `TunIngress` packet loop / UDP NAT / smoltcp TCP side) belongs to P1-2; the `network` config block and `seepctl route` belong to P1-3 ([network-route.md](network-route.md)).
> Landing points: `crates/seep-platform/src/network/linux.rs` (single file, skeleton started at T0, now 1757 lines including tests) · module wiring and the four factories in `network/mod.rs` · trait pruning in `network/tun.rs`.

## 1. Overview and commit anchors

| Step | Content | Commit | Design reference |
|----|------|------|---------|
| T0 | Trait pruning (delete `packet_stream`/`TunPacketStream`/`TunInterface`, 15->14 methods) + `linux.rs` skeleton + four-factory cfg dispatch + `nix` enabled + `platform.rs` dead-draft note | `c076fb8` | §1.2/§1.4 |
| T1 | `LinuxTunProvider`: open/TUNSETIFF/TUNGETIFF/AsyncFd read-write loop + `PacketInfo` linkage + the capture-pin integration test | `75c7747` | §1.1/§1.2 |
| T2 | `LinuxRouteManager`: ip helper (construction/execution separation) + addr/route idempotency + `AppliedStep` rollback + the auto-bypass half | `92f12ba` | §1.3 |

Dependencies and commit cadence follow design §5: T0 -> T1 -> T2 (T2 depends only on T0); one commit after each step's build+test goes fully green.

## 2. Device lifecycle and the TUNSETIFF interface (T1)

### 2.1 Creation sequence

`create_interface` (`linux.rs:320`) is idempotent (already holding the fd means `Ok`, same stance as E16), in five ordered steps:

```text
① open /dev/net/tun (open_tun_file, linux.rs:203)
     ENOENT   -> E1: error with "modprobe tun / container must map the device node"
     EPERM/EACCES -> E2: error with "CAP_NET_ADMIN required (root/capabilities)"
② build_iff_request (linux.rs:47) -- ifr_name from the given name (empty name = kernel assigns tun%d),
     flags fixed to IFF_TUN | IFF_NO_PI; a name length >= IFNAMSIZ(16) is intercepted early
     (a pre-defense for E4, avoiding a certain-EINVAL ioctl)
③ tun_set_iff (TUNSETIFF, _IOW('T',202,int) -- the nix ioctl_write_ptr_bad macro, linux.rs:42)
     errno mapping (map_tunsetiff_err, linux.rs:220):
       EEXIST -> E3 (a forced-name conflict with config.name; None is kernel-assigned and never triggers it)
       EPERM/EACCES -> E2 (CAP_NET_ADMIN)
       EINVAL -> E4 (illegal flags = program bug, error includes the flags value)
④ tun_get_iff (TUNGETIFF) reads back the actual interface name -- the kernel is the single source of truth for the name
     (ifreq_name takes the NUL-terminated string; reading back an empty name is treated as a kernel state anomaly and errors)
⑤ F_SETFL O_NONBLOCK (required by AsyncFd readiness semantics) -> convert File to OwnedFd -> register with AsyncFd
```

**Why TUNGETIFF rather than reusing the requested name**: `TunConfig.name` is `Option<String>`, and when it is `None` the kernel assigns `tun%d`, a name not present in the request buffer; and even for a forced name, reading it back is a defensive cross-check (the test cycles A and B pin the two states separately, §7.2).

### 2.2 Destruction and idempotency

- `destroy_interface` (`linux.rs:349`) = `fd.take()` -> drop the fd -> the kernel reclaims the interface automatically (E16 idempotent: `Ok` when never created). The integration test asserts the interface really vanished via a non-zero exit from `ip link show dev <name>`;
- The idempotency of `up`/`down`/`configure_ip` comes from the `ip` command itself (`set`/`replace` semantics, §2.3).

### 2.3 Interface attributes: `ip` command shell-out and construction/execution separation

- **Construction/execution separation** (§4.1 test requirement "assert the argv vector without executing"): `ip_argv_link_up/link_down/addr_replace/route_replace/route_del/addr_del/link_down_name` (`linux.rs:76-195`) only assemble argv; execution goes uniformly through `run_ip` (`linux.rs:120`) --
  - E6: `NotFound` -> error with "iproute2 or busybox ip required";
  - E7: non-zero exit -> rethrow with stdout/stderr (startup failure is not silent, and the information is complete before undo);
- `up_interface` combines up and MTU into one command (both idempotent), with MTU taken from `TunConfig.mtu` (default 1500); `configure_ip` = `ip addr replace <cidr> dev <name>`, defaulting the v4 mask to /32 and the v6 prefix to /128 (single-host assumption; `ipv4_gateway` is not consumed here -- default route/gateway takeover belongs to P1-3/V2);
- `configure_dns` is an MVP pass-through (`dns_servers` recorded only, DNS hijacking belongs to P2-8); `configure_routing` on the provider stays an **Err delegation point** (`linux.rs:396`) -- the device+route owner is `TunIngress` (design §2.6/§6-7 ruling), so the provider carries no routing of its own.

## 3. Packet read/write loop (T1)

### 3.1 Uplink `read_packet` (`linux.rs:414`)

```text
loop {
  guard = fd.readable().await              // AsyncFd readiness wait
  buf = vec![0; mtu]                        // MTU buffer per config.mtu
  try_io(nix::unistd::read)                 // EAGAIN -> converted to WouldBlock
  ├─ Ok(0)         -> continue               // 0 bytes is not a packet, back to readable waiting
  ├─ WouldBlock    -> continue               // readiness already cleared, wait again
  ├─ Err(e)        -> receive_errors++ -> Err // E8: device closed/abnormal, error propagated
  │                                          // (ingress termination semantics at runtime)
  └─ Ok(n)         -> buf.truncate(n)
       parse_tun_packet(buf)
       ├─ Err  -> receive_errors++ -> continue // E9: bad packet counted and dropped, the read stream continues
       └─ Ok   -> packets/bytes_received++ -> return (Bytes, PacketInfo)
}
```

Key point: **the split between E8 and E9** is the loop's lifeline -- a real error (EIO/EBADF) terminates the stream, while a bad packet (truncated/unknown version) is only counted and the loop continues; after link up the kernel may inject unrelated packets (such as IPv6 RS), which the upper layer filters by 5-tuple (the §7.2 capture pin is exactly this shape).

### 3.2 Downlink `write_packet` (`linux.rs:458`)

An isomorphic `writable().await` + `try_io(write)` loop; the difference is in the completion check: **a TUN packet is write-oriented, so a partial write should not happen** -- only `n == packet.len()` counts as returned, and a short write is treated as a program bug and errors (`send_errors++`), with no fragmented retry.

### 3.3 TUN packet parsing: IFF_NO_PI alignment (`parse_tun_packet`, `linux.rs:240`)

`IFF_TUN | IFF_NO_PI` input is a **pure IP packet** -- no Ethernet header, no 4-byte PI prefix. So `parse_packet_info` is not reused (its Ethernet-guessing path would misjudge the first two bytes of the source IP as an ethertype); instead the first nibble determines the version -> `PacketInfo::parse_ip_header`; empty/truncated/unknown versions are rejected (pinned by v4/v6 golden vectors, §7.1).

## 4. platform.rs placeholder replacement plan (T0 wiring)

The replacement is a **three-layer closure** rather than rewriting `platform.rs` itself:

| Layer | Action |
|----|------|
| trait (`tun.rs`) | Prune and delete `TunProvider::packet_stream` (15->14 methods) along with `TunPacketStream`/`TunInterface` -- the placeholder `AsyncWrite` fakes success and drops data and cannot be kept; the sole consumer of `packet_stream` is the deleted stream (design §1.2, authorized by audit report A7) |
| factories (`mod.rs`) | The four factories go from always-Err to cfg dispatch: `#[cfg(target_os = "linux")] pub mod linux;`, with the tun/route factories returning real implementations on Linux and other platforms keeping Err; the filter/dns factories keep Err but change the wording -- filter=in-process rules (§2.7) / dns=P2-8. The dispatch is the single source of truth: the `create_tun_interface` convenience function is changed to delegate to the factory and no longer carries its own always-Err placeholder |
| dead draft (`platform.rs`) | Remains uncompiled (not in the module tree), with a pointing note added at the top: the real implementation lands in `linux.rs` per tun-dataplane.md §1.4, and its `packet_stream` signature became stale with the trait pruning, so do not restore from it |

Dependency surface: `nix` moved into `[target.'cfg(target_os = "linux")'.dependencies]` (features `ioctl`+`fs`); tokio gains the `process` feature (the `ip` subprocess). Existing consumption points are unaware -- seep-runtime goes only through the four factories, and `enable_network_virtualization` defaults to false so it is never reached.

## 5. LinuxRouteManager (T2)

### 5.1 `AppliedStep`: the source of truth for idempotency and undo

```rust
pub enum AppliedStep {                       // linux.rs:498
    AddrReplaced { interface, cidr },        // ip addr replace <-> undo = addr del
    LinkUp { interface },                    // ip link set up <-> undo = link down
    RouteReplaced { cidr, interface, metric },// ip route replace <-> undo = route del
}
```

apply/clear read and write `applied: Mutex<Vec<AppliedStep>>`; the `Display` impl serves `remove_route`'s name lookup. Idempotency relies on `ip`'s `replace` semantics; **"full restoration" = undoing the steps seep added** (same stance as P1-3 §5), not a snapshot rollback.

### 5.2 apply / clear / rollback (`linux.rs:1000/1007`)

- `apply_routing`: `enabled=false` short-circuits -> address steps (when `tun_config` exists, the repeated replace with the provider's `configure_ip` is idempotently harmless -- compatible with standalone RouteManager use) -> rules one by one in **ascending priority**: disabled ones skipped, auto-bypass hits skipped (debug log with the name), a missing interface name falls back to `interface_name` (error if that is missing too);
- **Mid-run failure rollback**: a single rule failure -> reverse-undo this run's `temp_applied` (addr del/route del) -> `Err(e.context("...already rolled back"))` -- the E7 error includes the failure reason and the rollback fact; only a full success merges into `applied` (failure leaves no half-applied state);
- `clear_routing` = `rollback_all`: undo all steps in reverse order, best-effort without aborting on a single step failure;
- Single operations: `add_route` (an auto-bypass hit is rejected with a direct Err, no write) / `remove_route` (look up applied by name, take it out and del) / `modify_route` (del then add) / `enable_route` (true reapplies / false removes); the query side `get_routing_table`/`lookup_route` rebuilds from `applied` (no system read-back, MVP stance).

### 5.3 The auto-bypass set (current state and seam)

`compute_auto_bypass` (`linux.rs:603`) now collects the **tun's own subnet** (`ipv4_addr+netmask` / `ipv6_addr+prefix`); runtime injection of egress server/endpoint, mesh listen/peer, and control.api_bind addresses **has been merged in with T3/R1** (`runtime_builder.rs:457-488` derives the egress/api_bind literals and hosts at build time, `tun_ingress.rs:225-247` calls `rm.set_auto_bypass(bypass)` after DNS resolution at the start of run(), `linux.rs:733-737` merged = compute ∪ extra) -- so this function converges to the "static half". Default bypass (private/loopback/multicast) is enforced by in-process `BypassRule` matching and does not enter the CIDR set (the in-process side of the double insurance in design §2.7).

### 5.4 Locks and async: the MutexGuard Send problem

`std::sync::Mutex` guards are not `Send`, so holding a guard across `.await` does not compile -- `rollback_all`/`remove_route` first **drain/remove the steps, release the lock, then await** the `ip` command execution (`linux.rs:922` / `1036-1051`). The lock protects only `Vec` reads/writes, not subprocess execution.

## 6. Deviations and implementation discretion (against tun-dataplane.md)

| # | Type | Content |
|---|------|------|
| 1 | Deviation | Design §1.3-E6 says "RouteManager probes `ip -Version` at build time" -- implemented as **an immediate error on NotFound at the first `run_ip`** (E6 semantics unchanged, avoiding one speculative process spawn) |
| 2 | Addition | `build_iff_request` **intercepts early** for a name length >= IFNAMSIZ(16) (not mentioned in the design; a pre-defense for E4, with a unit test pinning the 15/16-byte boundary) |
| 3 | Addition | `read_packet` continues on a **0-byte read** (non-packet semantics); `write_packet` treats a **short write** as a program bug and errors without retrying (TUN packets are write-oriented) |
| 4 | Addition | `parse_tun_packet` as a standalone function + first-nibble version determination -- design §1.1 only says "align directly with `parse_ip_header`", while the implementation explicitly bypasses `parse_packet_info`'s Ethernet guessing and notes the misjudgment risk |
| 5 | Closed | `compute_auto_bypass` static half (tun subnet) + runtime injection of the full set -- **merged by T3/R1** (`runtime_builder.rs:457-488` derives the egress/api_bind surface, `tun_ingress.rs:225-247` set_auto_bypass, `linux.rs:733-737` merges; the R0 conversion layer network_config.rs removes with the same semantics) @a9f11dc/1e1a7c0 |
| 6 | Gap | `monitor_changes` always Err (a `RouteManager` trait method, no routing-monitoring need in MVP; not listed in the design) |
| 7 | Discretion | Interface name by injection: `LinuxRouteManager::set_interface_name` (injected by the owner after the TUNGETIFF read-back) rather than passed at construction -- `TunConfig.name` is Option, so there is no name before creation |
| 8 | Kept | `configure_routing` remains an Err delegation point on the provider (device+route owner = TunIngress, the §2.6 ruling unchanged) |
| 9 | Kept | musl same-path compilation is an assumption (§6-9); cross-compiled artifact acceptance belongs to P3-3 |

## 7. Test plan and actual state of landing

### 7.1 Unit tests (no privileges, any environment; §4.1)

| Test | Pinned |
|------|------|
| `iff_request_build_and_readback` | ifreq construction/read-back roundtrip; flags value assertion; empty name all zeros; **the 15/16-byte name-length boundary** |
| `netmask_prefix_conversion` | dotted mask -> prefix, four tiers (/0, /16, /24, /32) |
| `ip_argv_constructors` | link up (with MTU) / down / addr replace asserted argv by argv (the testable surface of **construction/execution separation**; route_replace/del and the same family are covered isomorphically) |
| `parse_tun_packet_v4_udp_golden` | minimal IPv4(20B)+UDP header -> src/dst IP, ports, proto=17, length, is_udp |
| `parse_tun_packet_v6_and_rejects` | IPv6+TCP header -> ports/proto=6; rejection side: empty packet/truncated/unknown version carrying the original value |
| `linux_tun_and_route_factories_dispatch` (mod.rs) | under cfg(linux) the tun/route factories dispatch to real implementations |
| `filter_factory_stays_err_and_dns_factory_dispatches` (mod.rs) | filter keeps the "in-process rules" Err stance; the dns factory has switched to a real implementation -- `create_dns_handler` assembles `dns_engine::EngineDnsHandler` (P2-8 M0, 750de34, success on the UDP upstream) |

### 7.2 Linux integration tests (§4.2: runtime skip guard)

`device_lifecycle_and_capture` (`linux.rs:1530`) -- guard at two points: `tun_device_available()` (no `/dev/net/tun` -> print skip) / `is_permission_skip` (error chain contains CAP_NET_ADMIN -> skip); **skip is not counted as failure**, so a non-privileged CI is unaffected:

- **Cycle A (forced name)**: create `seepT1<pid>` -> name read-back assertion -> up/addr/mtu read-back assertions via `ip addr|link show` (10.66.0.1/24, mtu) -> **the capture pin (the core of P1-1 acceptance, the provider half)**: a `UdpSocket` bound to `10.66.0.1:0` sends to `10.66.0.2:9999` -> the kernel injects into the tun fd over the connected route -> the `read_packet` loop filters by the target 5-tuple (send before read; the tun queue buffers so nothing is lost; non-target packets ignored) -> assertions on src/dst IP+port, proto, length, payload tail, and the receive counter -> down/destroy -> `ip link show` asserts the kernel reclaimed the interface;
- **Cycle B (automatic name)**: create with `TunConfig::default()` (name=None) -> assert the read-back name is of the form `tun%d` -> destroy.

The FlowRouter half of "capturing IP packets **entering FlowRouter**" has landed with T3's `TunIngress` -- `tun_ingress.rs` (`mod tests` from :855) already has ingress-loop wiring tests (including the `tun_udp_e2e_capture_route_attribution_echo` real-device e2e, see the landing note in tun-dataplane.md §4.2); the provider half (packets actually reaching `read_packet`'s return value from the kernel) is demonstrated as before.

### 7.3 Gates and baseline

- The unit test suite has no privilege dependency (runs in normal CI); the integration suite's skip guard guarantees zero failures on non-root CI;
- Whole-repo baseline at landing time: 172 items at T0 and T1 each (170+2), flat at 172 from T2 on; later P1-3 R0 / P1-4 M0 raised it to 200 items (as of 2026-10-01), all additive with zero regressions.

## 8. Seams with P1-2/P1-3 (closed)

- **P1-2 (T3/T4/T5) has landed** (a9f11dc/b5785c2/7a3024d): `TunIngress` takes ownership of `LinuxTunProvider`+`LinuxRouteManager` (creation/addressing/route setup complete at `run()` startup, teardown on exit); the `(Bytes, PacketInfo)` returned by `read_packet` is the packet loop's input; the full auto-bypass set is assembled there (§5.3);
- **P1-3 (R1-R4) has landed** (1e1a7c0/1befbe7): the `network` block -> `TunConfig`/`RoutingConfig` conversion is in `seep-runtime/src/network_config.rs` (including the auto-bypass removal half); `seepctl route apply/clear` reuse the same `apply_routing`/`rollback_all` mechanism (idempotent / full restoration / failure rollback are consistent in stance), and the three control-plane endpoints `/network/route/{apply,clear,status}` are in place.
