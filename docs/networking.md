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

## Bypass and recovery

Captured targets may include proxies, upstream DNS and daemon-originated connections. Configuration/runtime bypass must cover them. TCP SO_MARK does not prove QUIC/UDP protection. Validate unknown combinations in a controlled environment.

Current route bookkeeping supports undoing owned changes; it is not the v1 cross-platform route/DNS/persistence transaction. Crashes, network changes and permissions need individual validation. Diagnose bundles may include private configuration, logs and network identities; inspect before sharing.

## v1 acceptance

Test same-target local TCP/UDP processes on three desktops, permission failures and PID/port reuse. Test dual-stack, DNS, bypass, MTU, network changes and teardown per platform. Concurrent game/web classification must not assume UDP means game. Root `todo.md` owns dependencies and gates.
