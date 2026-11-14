# Rillane architecture sketch

## Design goals
- Cross-platform proxy kernel in Rust: the data plane runs on the tokio async runtime, the mesh data plane enforces mTLS by default, and the code base is a monorepo split into crates.
- All crates / apps / platform glue live in one monorepo; dependency versions are pinned by the workspace to reduce drift.
- Target platforms are Windows, Linux, macOS, Android, iOS and OpenWrt, all sharing the same config schema and control plane.

## Top-level layout
```
rillane/
├── apps/            # binary entrypoints (daemon, CLI)
├── crates/          # reusable libraries (core, config, routing, protocols, ...)
├── docs/            # design docs and ADRs
├── platforms/       # platform-specific glue (android/ ios/ launchd/ openwrt/ systemd/ windows)
├── Cargo.toml       # workspace definition
└── README.md
```

## Crate breakdown
- `rillane-core`: unified abstractions for Flow / Router / Middleware, the contract layer every protocol implements against.
- `rillane-config`: config schema definition, parsing and validation; YAML/JSON/TOML are auto-detected.
- `rillane-routing`: policy and routing engine, emitting `RouteDecision`; matching is metric/condition based; GeoIP/GeoSite conditions query optional `.mmdb`/`.dat` databases configured by `routing.geoip_db`/`routing.geosite_db`, and absent or failed databases never match.
- `rillane-protocols`: ingress and egress protocol stacks (Socks5/HTTP/Hysteria/Trojan/...), plugged in through the `IngressEndpoint` and `EgressConnector` interfaces.
- `rillane-telemetry`: logging and tracing init + a log capture ring (`logs_text`); metrics are not registered here -- Prometheus text is rendered by the control plane's `handle_metrics`, counters live across crates (e.g. rillane-core UDP metrics).
- `rillane-platform`: per-platform installation, service management and permission handling, split at compile time via features.
- `rillane-runtime`: the orchestration engine, wiring config, routing and protocol components together, plus listener startup and hot-reload logic.
- `rillane-mesh`: cooperating-node model and registry, tracking node roles (client/relay/exit), capabilities and heartbeats, providing one shared data plane for later networking/acceleration work.
- `rillane-subscription`: the full subscription chain -- fetch/convert (Clash, share links, Rillane DSL)/cache/scheduled refresh; reloads are skipped when the content hash is unchanged.
- `rillane-plugins`: WASM plugin loader (dynamic loading via wasmtime, plugins adapted into `FlowMiddleware` and attached to the middleware chain, see [design/plugin-loader.md](design/plugin-loader.md)).
- `rillane-ffi`: the mobile-platform FFI surface (`cdylib` exports, called by the Android/iOS UI side).

## Applications
- `apps/rillaned`: resident daemon (service/daemon), loads config, initializes telemetry, starts the runtime.
- `apps/rillanectl`: command-line console -- config validation and status inspection (18 subcommands), plus runtime rebuilds of routing/egress/subscriptions triggered through the control plane and mTLS certificate management; the remote control plane is built-in HTTP/REST (the full endpoint table and its rillanectl counterpart is [docs/cli.md](cli.md)), with no gRPC/WebSocket surface.

## Key interfaces
- `Flow`: context of one proxied session, carrying target info, tags, etc.; `FlowRouter` decides based on `FlowContext`.
- `IngressEndpoint`: listener entrypoint; after accepting a connection it invokes the router and hands off to an `EgressConnector`.
- `FlowMiddleware`: optional middleware for stats, rate limiting, content filtering.
- `ServiceInstaller` / `ServiceRuntime`: platform glue, deploying into systemd/launchd/Windows Service/OpenWrt init.d.

## Platform strategy
- **Desktop/server**: `rillaned` binary + systemd/launchd/Windows Service templates.
- **Android/iOS**: the core is exposed as an FFI `cdylib`, called from Kotlin/Swift/Flutter UIs.
- **OpenWrt**: static musl packages (ipk build pipeline + procd init.d); LuCI/UCI adaptation is not done (LuCI pages deferred, see `platforms/openwrt/README.md`).
- **HarmonyOS**: the `crates/rillane-ffi` cdylib compiles for all three ohos targets aarch64/armv7/x86_64 with ELF static verification brought up end to end (armv7 goes through the wireguard stub that always returns Err); host-side integration (ArkTS/ArkUI) and real-device work are not done, see `platforms/ohos/README.md`.

## Control plane and ecosystem
- The control plane is uniformly HTTP/REST on `control.api_bind` + `rillanectl` (hand-rolled HTTP routing, no gRPC/WebSocket surface).
- Hot-reload scope: rillaned reads config once at startup, **there is no config-file watch** (`rillane-runtime::HotReloadManager` is exported but unwired, no SIGHUP); runtime reloads are driven by subscription refresh and control-plane endpoints (routing/group/egress rebuilds). There is no `rillanectl reload` subcommand.
- Docs and ADRs live under `docs/`; significant decisions are recorded as ADRs.

## Mesh / cooperative acceleration / node groups (current state)

- Every installed node is a network element registered as `client` / `relay` / `exit` / `hybrid`. `rillane-mesh::MeshRegistry` keeps node metadata, background heartbeat cleanup and offline detection; `rillane-runtime` registers the local node by default.
- Groups and chains: members of `RoutingConfig.groups` (`PolicyGroup`) may be `Node` / `Group` (nested) / `WeightedNode` / `WeightedGroup`; group policies are latency/bandwidth/weighted/random/consistent_hash/round_robin/fixed; the routing target `mesh.<node>` is promoted by `ChainManager` into a `RouteDecision::Chain` (source -> relay -> exit).
- Chain capabilities: building (`ChainBuilder`, with constraints and chain-weight scoring), Dry Run pre-checks, a health-check task, failover (`ChainContext` fallback path switching). Control-plane endpoints and the data-plane wire format are in [mesh.md](mesh.md).
- Data plane: mesh data-plane **TCP** hop-by-hop forwarding is implemented (envelope carries the path, stripped per hop) as is **UDP** multi-hop forwarding (2026-09 P0-4: `UdpEnvelope` binary header over UDP datagrams, FULL/CACHED hop caching, same-port dual stack -- spec in [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md), concept draft [design/udp-dataplane.md](design/udp-dataplane.md) §4).
- Boundaries (not done now): UDP-plane encryption (**V2** quinn underlay undecided; the MVP plaintext gate has landed -- chain+udp without configured encryption is refused at build time), end-to-end multi-hop MAC/authentication (no end-to-end key distribution mechanism, deferred to V2), OCSP/CA direct revocation queries -- see "Cooperative node security" below and todo P2-7. UDP-plane **anti-replay has landed** (2026-10-04: v2 frame stream sequence numbers + per-(flow,dir) 64-bit sliding window, `replay_dropped` counters surfaced in /udp/stats and /metrics, see [mesh.md](mesh.md) and [design/mesh-advanced-security.md](design/mesh-advanced-security.md)); revocation distribution = file carrier + runtime observability (`GET /mtls/revoked` + `rillanectl mtls revoke status`) has landed.

## System routing and virtual NIC (current state: Linux landed, cross-platform providers are placeholders)

- `rillane-platform::network` has the full trait and data model: `TunProvider`/`TunConfig`/`TunInterface`, `RouteManager`/`RouteRule`, `PacketFilter`/`FilteringConfig` (process/port/IP/domain rules), `DnsHandler`; the module tree now has seven submodules -- tun/route/filter/dns/dns_engine/ipcodec/linux (linux is the Linux implementation, `#[cfg(target_os = "linux")]`).
- **The Linux plane has landed** (todo P1-1..P1-3, 2026-10-03, see [networking.md](networking.md) for details): `TunIngress` wiring in `rillane-runtime` (`tun_ingress.rs`, TCP/UDP data plane + auto bypass), the top-level `network` block of `RillaneConfig` (with `deny_unknown_fields` so typos fail loudly), the three subcommands `rillanectl route apply/clear/status` and the three control-plane endpoints `/network/route/{apply,clear,status}`.
- **Cross-platform boundary (honestly labeled)**: on non-Linux platforms the providers are still placeholders (warn on construction, send/recv return "not implemented"); the non-Linux branches of `RouteManagerFactory`/`DnsHandlerFactory` still return Err -- the main TUN path bypasses the factories and constructs `LinuxTunProvider`/`LinuxRouteManager` directly.
- Read-only capability: `rillanectl diagnose` collects a snapshot of local routes/DNS/interfaces.

## Subscriptions and config compilation (current state: the whole chain is implemented)

- Clash subscriptions (proxies/proxy-groups/rules) and share links (vmess/vless/trojan/hysteria2/ss, including whole-payload base64) both convert into `RillaneConfig`; the type is auto-detected (`detect_type`). Conversions that produce egress types not implemented yet (e.g. hysteria v1 -- schema/subscription conversion supports it, the egress connector is missing) fail at build time with an explicit error.
- The native Rillane DSL (version/meta/nodes/groups/rulesets, including auth/transport/TLS/geo fields) supports import, export and validation.
- The fetcher supports timeout/UA/custom headers/proxy and ETag/Last-Modified conditional requests; the cache is TTL+LRU; refreshes run per subscription and globally on two levels of intervals, and reloads are skipped when the content hash is unchanged; the control plane offers subscription CRUD plus manual/full-refresh endpoints (the config file itself is not watched -- see the hot-reload scope under "Control plane and ecosystem").
- Full documentation in [subscription.md](subscription.md).

## Cooperative node security (current state) and observability

- Mesh data-plane mTLS: **mandatory by default** once chains are enabled (dev may set `RILLANE_MESH_ALLOW_PLAINTEXT=1` to opt out); certificates are generated by `rillanectl mtls` (CA/node certs/rotation/CA bundle dual trust window), injected through `RILLANE_MESH_MTLS_*` environment variables; revocation is a minimal implementation (per-node-CN revocation list, hot-reloaded on file mtime). See [mesh.md](mesh.md).
- ACLs and quotas: `NodeACL` (allowed client CIDRs, role restrictions) and `NodeQuota` (daily/monthly bandwidth, concurrent connections) are enforced at the registry layer; exceeding them returns `QuotaExceeded`.
- Boundaries: OCSP/CA direct revocation queries are not implemented (V2 -- nodes have no CA channel besides the mTLS data plane); multi-hop end-to-end MAC/authentication is not implemented (no end-to-end key distribution mechanism, recorded as mesh-advanced-security.md §6 deviation 1). Revocation distribution and UDP-plane anti-replay have landed (todo P2-7): revocation files hot-reload on mtime with a runtime-visible view (`/mtls/revoked`); the UDP plane rejects replays via v2 stream sequence numbers + sliding window, with counters.
- Observability: with `telemetry.enable_metrics=true`, `GET /metrics` exposes Prometheus text (mesh per-link counters, chains, subscription events, etc.); `GET /flows` provides ingress->egress traffic stats; `GET /nodes` provides a node snapshot; `GET /routing/stats` provides real-time group quality (member data source real/legacy/unknown, p95/loss, SLO gate decisions and the latency group's current selected endpoint -- the data source behind `rillanectl group`, P2-2 O-slo1). Fine-grained metrics like per-link latency distributions and switch reasons landed with P2-1 (`/mesh/switches` switch ledger, see [mesh.md](mesh.md)). The full control-plane endpoint table and rillanectl counterparts are in the [cli.md](cli.md) endpoint reference.

## Current status and roadmap

- **Foundation done** (roadmap S0): socks5/http/mixed ingress + direct/ss/trojan/hysteria2/vmess/vless/wireguard/socks/http TCP egress; group-policy routing; mesh control plane + TCP data plane + mTLS; the full subscription chain; control plane and rillanectl; basic Prometheus metrics. Protocol implementation boundaries are in the status notes of [PROTOCOLS.md](PROTOCOLS.md).
- **In progress / planned** (see [design/roadmap.md](design/roadmap.md)): S1 the full UDP chain (P0-1..P0-5 session table/inbound/outbound/mesh data plane/observability and config -- **all landed**, [design draft](design/udp-dataplane.md), [observability design](design/udp-observability.md)) -> S2 TUN system takeover -> S3 obfuscation cross-cutting layer and connection reuse -> S4 scheduling loop and release. Executable items live in the repo-root [todo.md](../todo.md).
