# Capture and routing (current implementation)

[Implementation](architecture.md) and [v1 platform design](design/architecture-v1.md) distinguish code from targets. This page documents existing Linux operations rather than maintaining an older capture design.

## Scope

Linux TunIngress forwards TCP/UDP through shared routing/outbounds. TCP uses smoltcp; first-packet `/proc` lookup can annotate local processes. Current names depend on comm length, permissions and caching, not full v1 executable/start identity.

Windows/macOS capture/identity, full Android forwarding and public iOS packetFlow remain implementation tasks. OpenWrt does not identify LAN client PIDs; mobile has no desktop-process requirement.

## Configuration and operations

See [configuration](config.md) for network fields. Set startup configuration with `RILLANE_CONFIG`; see [CLI](cli.md) and `--help` for supported options.

```bash
rillanectl route status
rillanectl route apply --dry-run
rillanectl route apply
rillanectl route clear
```

Endpoints are GET `/network/route/status`, POST `/network/route/apply` and POST `/network/route/clear`. An instance without TUN cannot apply TUN routes. Operations need OS authority; inspect the plan and management path first.

## Transparent takeover

`network.mode = "transparent"` replaces TUN capture with a socket-level takeover: intercepted TCP is handed to the runtime without a TUN device, and every accepted connection is pinned to one fixed egress node named by `network.transparent.target` (a declared egress). No routing-engine decision is consulted for a pinned takeover; the decision is always `direct(target)`.

Two kernel mechanisms are selectable via `network.transparent.mode`:

- `redirect`: conntrack `NAT REDIRECT` sends traffic to the local listener; the original destination is recovered from the accepted socket with `SO_ORIGINAL_DST` (`SOL_IP`, then `SOL_IPV6`). A connection that is *not* redirected has no conntrack NAT record and the getsockopt call returns `ENOENT` — that is reported as a named refusal and never silently answered with the local address, so a plain direct connect cannot be misrouted as transparent traffic.
- `tproxy`: the listener sets `IP_TRANSPARENT` before binding a non-local address, so an accepted TPROXY connection keeps its original destination as the socket's local address. The original destination is therefore the accepted socket's `local_addr()`.

Rules are system side effects owned by the ingress, the same way TUN ingress owns its device and routes: they are applied when the ingress starts and undone (in reverse order) when it stops, on both shutdown and failure. Applying reports `EEXIST`-style "rule already present" as idempotent success; undoing reports "no such rule" as already undone, so restarts and partial failures converge.

Declared limits:

- IPv4 only. Rule planning is IPv4 and `IP_TRANSPARENT` is set on `SOL_IP`; an IPv6 listen address is refused by name. IPv6 needs `IPV6_TRANSPARENT` plus an IPv6 rule plane and is deferred.
- TCP application face only. The UDP/QUIC app face is not claimed; the `SO_MARK` conclusion in [Bypass and recovery](#bypass-and-recovery) still applies.
- Linux only, and the takeover faces need `CAP_NET_ADMIN` (iptables/nftables rules, `IP_TRANSPARENT`). Without the capability the listener setup and rule application fail with a named permission error rather than degrading silently. A gate that applies the rules, connects through them and undoes them runs only where that capability exists.
- Reuse of existing capture plumbing: the ingress is one more ingress endpoint on the shared flow pipeline, so it inherits the current bypass/recovery limits instead of claiming to solve them.

### Library evidence (no composable carrier → self-write)

Recorded before self-writing, per the repo rule that a self-written face needs a recorded no-library conclusion.

- Ingress socket carrier: `tproxy-config` 7.0.10 (dl 91,812, updated 2026-11-18) is a configuration tool, not an embeddable listener; `cproxy` 4.2.1 is AGPL-3.0-or-later — copyleft, incompatible with the repo's permissive-only stance — and works through cgroup `net_cls`, not the REDIRECT/TPROXY faces; `xtp-rs` 0.1.0 (dl 19) and `trans_proxy` 0.8.0 (dl 63) are unvetted at these download counts; `transparent_proxy` 0.4.0 (2022-12-04) is a standalone server, not an ingress adapter.
- Rule management: `iptables` 0.6.0 (MIT, dl 1,016,471) is a shell-out wrapper whose dependencies are only `lazy_static` and `regex` — regex argv with no transaction or idempotency semantics; this repo already executes rules through the argv `StepExecutor` used by the RIL-029 route/`ip` face, so a second shell-out layer adds nothing. `nftables-nl` 0.5.0 (dl 85, 2026-11-11) is brand new and unvetted; `nftables` 0.6.3 / `nftables-async` 0.4.1 are JSON shells over the `nft` binary, which would swap one execution substrate for another without the `AppliedStep` bookkeeping.
- Conclusion: no admitted library carries a REDIRECT/TPROXY listener composable into the flow pipeline, and none carries rule transactions — self-written on the existing argv execution face.

## Bypass and recovery

Captured targets may include proxies, upstream DNS and daemon-originated connections. Configuration/runtime bypass must cover them. TCP SO_MARK does not prove QUIC/UDP protection. Validate unknown combinations in a controlled environment.

Current route bookkeeping supports undoing owned changes; it is not the v1 cross-platform route/DNS/persistence transaction. Crashes, network changes and permissions need individual validation. Diagnose bundles may include private configuration, logs and network identities; inspect before sharing.

## v1 acceptance

Test same-target local TCP/UDP processes on three desktops, permission failures and PID/port reuse. Test dual-stack, DNS, bypass, MTU, network changes and teardown per platform. Concurrent game/web classification must not assume UDP means game. Root `todo.md` owns dependencies and gates.
