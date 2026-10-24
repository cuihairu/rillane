# Status audit report for errata-reopened items: TUN / network block / FlowMiddleware dynamic loading

> Audit baseline: the 2026-09-29 worktree (main @ 4e4cf6e). Method: every claim in the todo.md errata section and in docs/design/roadmap.md and docs/networking.md, cross-checked item by item against the actual code in `crates/seep-platform` (and related crates/apps).
> This document only records the current state and gaps and changes no source code; the **documentation's own deviations** found by the audit are collected in §4 (suggested for backfill in a later doc round, untouched this round).

> **[2026-10-04 status] This document is a 2026-09-29 historical snapshot; the body keeps the original text of that day.** Since then P1-1/P1-2/P1-3/P1-4/P2-8/P3-2 have all landed (c076fb8/75c7747/a9f11dc/b5785c2/7a3024d/1e1a7c0/1befbe7/750de34/955e4d6), and several conclusions in §0-§3 have been overturned -- **the "2026-10-04 landing update" blocks at the end of each section are authoritative**; do not cite the body text as the current state anymore.

## 0. Conclusions at a glance

| Item | Is the errata record accurate | New audit findings (facts beyond the errata record) | 2026-10-04 status |
|------|----------------|----------------------------------|----------------|
| ① TUN (P1-1/P1-2) | Basically accurate ("runtime not wired" ✓, no real implementation ✓) | `platform.rs` **never takes part in compilation at all** (`network/mod.rs:21` comments out `pub mod platform;`); the file contains **only macOS placeholders** (no Linux/Windows/Android/iOS skeletons); and enabling it **would necessarily fail to compile** (the placeholder types lack trait methods across the board); the `TunInterface` write-side placeholder **fakes success and discards data** | **All landed** (P1-1/P1-2: linux.rs real implementation + TunIngress wiring, see the §1 update block) |
| ② network block + `seepctl route` (P1-3) | Accurate (`SeepConfig` has no network block ✓, seepctl has no route subcommand ✓) | serde has no `deny_unknown_fields` -> a user-written `network:` block would be **silently ignored**; the `NetworkMode` enum names it `transparent`, not the planned wording `redir`; the `RuntimeConfig.network_config` hook already exists but seepd never sets it | **All landed** (P1-3 R1-R4: schema/endpoints/seepctl route all in place, B2/B4 closed, see the §2 update block) |
| ③ FlowMiddleware dynamic loading (P3-2) | Accurate (only LatencyProbe, no dynamic loading ✓) | The gap is one layer deeper than recorded: **there is not even a static mount point** -- zero places in the repo call `FlowMiddleware::handle` or construct `LatencyProbe`, the trait floats entirely outside the datapath; the workspace has no dynamic-loading dependency at all | **All landed** (P1-4 mount point + P3-2 WASM loader and sample plugins, see the §3 update block) |

---

## 1. Item one: real TUN implementation (todo P1-1 / P1-2; roadmap S2; networking.md)

### 1.1 What the docs claim

| Source | Claim |
|------|------|
| todo.md errata section | "Implement TunIngress/TunEgress (hooking up TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel) ... `seep-platform` has only traits and data structures; **every platform's Provider is a placeholder implementation (`platform.rs` returns "not implemented")**; runtime not wired -> P1" |
| roadmap.md S2 | "Reuse the existing `TunProvider`/`RouteManager`/`PacketFilter` traits and TunConfig/rule model in `seep-platform::network` (**3825 lines of design already shaped**)"; "Windows(Wintun)/macOS(utun)/... (**the platform.rs placeholder already has that shape**)" |
| networking.md §1 | "`platform.rs` | **Linux/OpenWrt/Windows/macOS/Android/iOS each** have Provider/RouteManager/PacketFilter/DnsHandler skeletons | all placeholders" |

### 1.2 What the code actually does

**Module compilation surface**: `network/mod.rs:16-21` declares `pub mod dns/filter/route/tun`; `platform.rs` (237 lines) **is not in the module tree** -- `// pub mod platform;` is commented out together with `// TODO: platform-specific implementations to be completed`. Only 5 files totaling **3588 lines** compile into the crate (dns 995 + filter 1093 + mod 325 + route 646 + tun 529); the roadmap's "3825 lines" counts the uncompiled platform.rs.

**platform.rs current state** (dead code, present on disk, not part of the build):
- Only 5 **macOS** placeholder types: `MacosUtunProvider`/`MacosTapProvider`/`MacosRouteManager`/`MacosPacketFilter`/`MacosDnsHandler` -- **no Linux/OpenWrt/Windows/Android/iOS skeletons at all** (networking.md §1's "each platform" description is an aspirational description (design text ahead of the implementation) relative to the file).
- Even with the comment removed it could not compile (the placeholder implementations lack required trait methods across the board; `#[async_trait]` has no default implementations):

| Type | Required trait methods | Implemented | Missing (key items) |
|------|----------------|--------|----------------|
| `MacosUtunProvider` | `TunProvider` 15 | 3 (read_packet/write_packet/packet_stream) | name/config/is_up/mtu/stats/create_interface/up_interface/down_interface/configure_ip/configure_routing/configure_dns/destroy_interface, 12 in total |
| `MacosRouteManager` | `RouteManager` 12 | 10 | `flush_cache`, `monitor_changes` |
| `MacosPacketFilter` | `PacketFilter` 15 | 13 | `filter_packet`, `monitor_events` |
| `MacosDnsHandler` | `DnsHandler` 12 | 5 | add_server/remove_server/add_filter_rule/remove_filter_rule/clear_cache/flush_cache/monitor_events, 7 in total |

**Placeholders on the compile path (the "not implemented" that actually takes effect)**:
- `network/mod.rs:304-325`: the four factories `create_tun_provider` / `create_route_manager` / `create_packet_filter` / `create_dns_handler` **always return `Err("...platform-specific implementations to be completed")`** -- `NetworkManager::initialize()` fails as soon as any sub-block is configured;
- `tun.rs:490-504` `create_tun_interface` always returns `Err("platform-specific TUN implementation not completed")`;
- `route.rs:597-646` `RouteManagerFactory::create` and `dns.rs:946-995` `DnsHandlerFactory::create` always return `Err("...to be implemented")` for every `target_os` branch.

**The placeholder types have "behavior" instead of erroring (risk)**: `tun.rs:416-424` `TunPacketStream::poll_next` is always `Pending`; `tun.rs:453-487` `TunInterface`'s `AsyncRead` sleeps 1ms and returns 0 bytes, and its `AsyncWrite` sleeps 1ms then **returns `Ok(buf.len())` without writing to any device** -- mis-wiring it silently drops packets.

**Dependencies and tests**: `seep-platform/Cargo.toml` has no TUN device library at all (zero tokio-tun/tun-rs and the like); `nix`/`winapi` are optional with no feature enabled (dead dependencies). The whole crate has **0 tests**.

**Runtime wiring surface**:
- A whole-repo grep for `TunIngress|TunEgress` has **zero hits** -- no TUN ingress/egress types exist;
- `seep-runtime/src/runtime_builder.rs:165-175` has the conditional `NetworkManager` construction (`enable_network_virtualization` + `network_config`), and `start()` (lines 598-604) would bring it up -- **structurally the wiring exists**, but as shown above initialize necessarily fails;
- `apps/seepd/src/main.rs:33-36` hardcodes `RuntimeConfig { enable_mesh: true, enable_chain: true, ..default }` and **never sets** `enable_network_virtualization` -- the NetworkManager path is dead code as far as seepd is concerned;
- The todo errata's "runtime not wired" refers to the IP packet -> FlowRouter path, and that judgment holds; but "NetworkManager is not wired at all" does not hold -- the accurate statement is **"the wiring exists but is unusable under any config"**.

**Process-dimension gaps** (the premise of P1-2's "process/port injection"):
- `MatchCondition` (seep-config `lib.rs:529-535`) has only DomainSuffix/DomainKeyword/Geoip/Network/Port, **no process condition** (roadmap S2's "process-matching enhancement" refers to this);
- `FlowContext = {id, target, metadata}` (seep-core `lib.rs:85-89`) has **no process field**; `FlowMetadata = {tags, annotations}` can only carry it as string annotations;
- `ProcessIdentity{pid,name}` currently exists only in the UDP sticky key (`seep-core/src/udp/key.rs:15,32,40`, reserved by P0-1), with no general injection channel.
- One more accurate claim verified: the `TargetProto::Quic` enum already exists (seep-core `lib.rs:38-42`; what networking.md §3 says is correct).

### 1.3 Gaps

| # | Gap | Impact | Owner |
|---|------|------|------|
| A1 | No real device I/O on any platform (zero code for opening `/dev/net/tun`, TUNSETIFF, etc.) | All of P1-1's work | P1-1 |
| A2 | `platform.rs` is uncompiled and enabling it fails to compile -> P1-1 cannot be done as "fill in the placeholders"; it must be **rewritten and wired into the module tree**; meanwhile the `nix` dead dependency can be enabled or removed in passing | Implementation-method ruling | P1-1 |
| A3 | The `TunInterface`/`TunPacketStream` placeholders fake I/O success (silent packet-drop semantics) | Misuse risk; recommend P1-1 delete them or turn them into explicit Err | P1-1 |
| A4 | No `TunIngress`: zero pipeline for IP flow reassembly -> FlowContext | All of P1-2's work | P1-2 |
| A5 | seepd never enables `enable_network_virtualization`; `RuntimeConfig.network_config` is the only programmatic entry | P1-2/P1-3 need a new config -> runtime channel | P1-3 |
| A6 | The routing/filtering model has no process matching (a double gap in MatchCondition/FlowContext) | The landing point of the "split game traffic by process" acceptance | P1-2 |
| A7 | seep-platform has 0 tests; whether the trait surface (`TunProvider`, 15 methods including packet_stream/configure_dns, etc.) is all necessary is unproven in practice | Trait pruning is allowed at P1-1 landing (roadmap's "keep the trait stable" should be read as semantic stability, not a frozen method set) | P1-1 |

### 2026-10-04 landing update (overturning/closing the §1 body)

- **§1.2 module compilation figures are outdated**: linux.rs has entered the compile tree (`network/mod.rs:24-25` `#[cfg(target_os="linux")] pub mod linux;`, now 1757 lines including tests), mod.rs now declares 7 modules total -- dns/dns_engine/filter/ipcodec/route/tun/linux; tun.rs is 437 lines after pruning -- the body's "5 files totaling 3588 lines" and "platform.rs 237 lines" (now 238) are both 09-29 numbers. `platform.rs` remains an uncompiled dead draft (`// pub mod platform;` still commented out); that point still holds.
- **The always-Err factories (L44) conclusion still holds but the context changed**: `create_tun_provider`/`create_route_manager` and the other factories still return Err for every `target_os` branch (now `route.rs:588-646`/`dns.rs:943-1000`, line numbers drifted); but **the TUN main path already bypasses the factories** -- TunIngress directly constructs (bypassing the factory) `LinuxTunProvider`/`LinuxRouteManager` (`network_config.rs:138,161`), so the factory Err no longer blocks the P1 chain.
- **Dependencies and tests**: `nix` is enabled as a normal dependency (`seep-platform/Cargo.toml:27` features=["ioctl","fs"], only winapi is still optional); seep-platform now has tests (the linux.rs test section, mod.rs, ipcodec golden vectors) -- "0 tests" is no longer true.
- **Runtime wiring surface**: `TunIngress` exists and is wired (`crates/seep-runtime/src/tun_ingress.rs`, 1245 lines; `runtime_builder.rs:477-493` constructs it and inserts `ingress_endpoints["tun"]`) -- "grep zero hits" is no longer true.
- **Process-dimension gaps**: seep-config `lib.rs:1735` has gained `MatchCondition::Process { values }` (P1-2 T5), and seep-routing `lib.rs:576-581` has gained the arm reading the `process.name` annotation + two-state unit tests -- "no process condition" is no longer true.
- **Gap table closed**: A1 (real device I/O, `linux.rs:203 open_tun_file` + `TUNSETIFF` ioctl) @75c7747; A4 (the full TunIngress chain) @a9f11dc/b5785c2/7a3024d; A7 (trait trimmed to 14 methods, `packet_stream`/`TunPacketStream`/`TunInterface` deleted + tests exist) @c076fb8; A2/A3/A5/A6 closed as P1-1/P1-3 landed (see the §2/§5 update blocks).

---

## 2. Item two: network config block + `seepctl route apply/clear` (todo P1-3)

### 2.1 What the docs claim

| Source | Claim |
|------|------|
| todo.md errata section | "Add a network config block (mode: tun/redir; bypass/include) + CLI `route apply/route clear` -> `SeepConfig` **has no top-level network block**; `seepctl` **has no route subcommand** -> P1" |
| networking.md §2 | Same stance (the two items "config missing the block" and "CLI missing the command") |

### 2.2 What the code actually does

- `SeepConfig` (seep-config `lib.rs:12-21`) = `{control, telemetry, ingress, egress, routing, udp}` -- **indeed no network block** (the `network:` fields hit by grep all belong to the vmess/vless/trojan egress transport layer `network: String`, unrelated);
- **Silent-ignore risk (new finding)**: seep-config has no `deny_unknown_fields` anywhere -> a `network:` block written in YAML would be **silently dropped** by serde, neither erroring nor taking effect -- more insidious than "the config does not exist";
- Model ready but unexposed: `NetworkConfig{mode, tun, routing, filtering, dns}` and `NetworkMode::{Tun, Tap, Transparent, Hybrid}` (platform `network/mod.rs:39-64`) exist **only in the platform crate**, not in the `SeepConfig` schema; note the enum literal is `transparent` -- the planned wording "redir" has no matching name (same semantics);
- `RouteRule`/`BypassRule`/`default_bypass_rules()` (private_ip/loopback/multicast -> Direct, `route.rs:571-595`) -- the model and the default bypass list are already written, but with **zero consumers**;
- `RuntimeConfig.network_config: Option<NetworkConfig>` (`runtime_builder.rs:307`) is a ready-made programmatic hook -- when P1-3 lands, the "config -> runtime" path has a channel available, needing only seepd-side wiring;
- The full seepctl top-level command set: `Check / Show / Stats / Nodes / Chain{dry-run,get,terminate,stats} / ImportClash / Subscription{...} / Diagnose / Mtls{...}` (`apps/seepctl/src/main.rs:29+`) -- **indeed no route subcommand**; the "route" wording inside diagnose is only a read-only collection command (`ip route`/`netstat -rn`/`scutil --route`), with no apply/clear semantics.

### 2.3 Gaps

| # | Gap | Impact | Owner |
|---|------|------|------|
| B1 | `SeepConfig` has no `network` block, and the schema has no corresponding type | All of P1-3's work | P1-3 |
| B2 | The `network:` block is silently ignored (no deny_unknown_fields) | Before P1-3 lands, user config is "written but useless" with no hint; recommend P1-3 also evaluate explicit warnings for unknown top-level keys | P1-3 |
| B3 | seepctl has no `route apply/clear`; the control plane has no corresponding endpoints either | All of P1-3's work | P1-3 |
| B4 | Naming stances not aligned: docs say "tun/redir" vs the enum `tun/transparent` | P1-3 must fix the name when writing the schema and backfill the docs | P1-3 |

The errata record itself ("no block / no subcommand") is **accurate without exaggeration**.

### 2026-10-04 landing update (overturning/closing the §2 body)

- **Every §2.2 item has flipped**: `SeepConfig` now has `pub network: Option<NetworkBlockConfig>` (seep-config `lib.rs:36`, R1); `#[serde(deny_unknown_fields)]` has been added file-wide (`lib.rs:163`, B2 closed, a misspelled top-level key now errors); `seepctl` now has the `route` subcommand (apply/clear/status, 1befbe7); `derive_runtime_config` now sets `network_config` (seepd wires it per `config.network.is_some()`).
- **The B4 naming ruling is closed**: `transparent` over `redir`; the seep-config `lib.rs:179` comment pins that stance and backfills network-route.md §1.3.
- **Gaps closed**: B1 (schema) @1e1a7c0; B2 (deny_unknown_fields) @ B2 closure; B3 (endpoints + subcommand) @1e1a7c0/1befbe7; B4 above. §5 item 4's "ready-made channel" is now fully connected.

---

## 3. Item three: FlowMiddleware dynamic loading (todo P3-2, errata downgraded item)

### 3.1 What the docs claim

| Source | Claim |
|------|------|
| todo.md errata section | "FlowMiddleware supports WASM/dynamic-library loading, samples (rate limiting, statistics, content filtering) -> **only one implementation, `LatencyProbe`, no dynamic loading mechanism** -> P3 (downgraded)" |
| roadmap.md S0/S3 | S0: "the `FlowMiddleware` trait is unchanged" (listed as a contract layer); S3 reuse: "obfuscation mounted in middleware form" |

### 3.2 What the code actually does

- The trait exists: `FlowMiddleware { name(); handle(Flow) -> Flow }` (seep-core `lib.rs:234-238`) -- the S0 claim "trait unchanged" holds;
- The sole implementation `LatencyProbe` (`seep-protocols/src/middleware/latency_probe.rs`, 34 lines): `sleep(1ms)` then returns as-is -- pure placeholder semantics, unrelated to `seep-routing`'s `latency` group policy (group policy goes through mesh health data, not through middleware);
- **Zero consumers (new finding, the gap is deeper than the errata record)**: no code anywhere in the repo calls `FlowMiddleware::handle`, and nothing constructs `LatencyProbe` anywhere (besides the definition and re-export); the ingress->FlowRouter->FlowOutputRouter->egress datapath **has no middleware mount point/registry/pipeline** -- the trait is in a "defined, not mounted" state;
- No dynamic-loading facility: no Cargo.toml in the workspace has a `libloading`/`wasmtime`/`wasmer`-style dependency;
- Implication for roadmap S3: the first half of "reuse the FlowMiddleware trait" (the trait exists) holds, while the second half ("mounted in middleware form") **has no mounting mechanism at all** -- when P1-4 (the padding obfuscation MVP) is implemented, a static mount point must be built first (e.g. a middleware chain on the ingress/egress side), and dynamic loading is then P3-2's extension on top of the static mount point.

### 3.3 Gaps

| # | Gap | Impact | Owner |
|---|------|------|------|
| C1 | No middleware mount point on the datapath (no registry/pipeline/call site) | A hidden prerequisite for P1-4; roadmap S3 should add a note "build the mount point first" | P1-4 |
| C2 | No WASM/dynamic-library loader or isolation mechanism | All of P3-2's work | P3-2 |
| C3 | No rate-limiting/statistics/content-filtering sample middleware (LatencyProbe is also a sleep placeholder) | The sample set needed for P3-2 acceptance | P3-2 |

The errata record's "only one implementation, no dynamic loading" is **accurate**, and in fact a static mounting layer is also missing.

### 2026-10-04 landing update (overturning/closing the §3 body)

- **The static mount point is built (P1-4)**: `seep-runtime/src/obfs_config.rs:306-317` builds the middleware chain and pushes in `Arc::new(LatencyProbe::new())` and more, consumed at `runtime_builder.rs:3053` -- "zero consumers / no mount point" is no longer true; the obfuscation chain is assembled in runtime_builder (a static chain, commented "static obfuscation chain").
- **Dynamic loading has landed (P3-2, 955e4d6)**: `seep-plugins/src/loader.rs:35` adapts WASM plugins into `Arc<dyn FlowMiddleware>`; the workspace now has the wasmtime dynamic-loading surface + rate-limiting/content-filtering sample plugins (see plugin-loader.md §4.2) -- C1/C2/C3 are all closed, and both halves of roadmap S3's "mounted in middleware form" now hold.
- ⚠ Note: **config-hot-reload chain rebuilding has not landed** (seepd reads config once at startup, no SIGHUP/watch; `HotReloadManager` is exported but never instantiated) -- the plugin/middleware chain is static within the process; see the 2026-10-04 annotation in the "Enable" section of plugins/README.md.

---

## 4. The documentation's own deviations (unchanged this round, left for a later doc round)

| Doc location | Deviation | Should read |
|----------|------|--------|
| networking.md §1 platform.rs row | "Linux/OpenWrt/Windows/macOS/Android/iOS each have Provider/... skeletons" | In reality only 5 macOS placeholder types, and the module is uncompiled (`// pub mod platform;`) |
| networking.md §1/§7 "about 3800 lines" | Counts the uncompiled platform.rs | 3588 lines compiled in; platform.rs, 237 lines, not part of the build |
| roadmap.md S2 "3825 lines of design already shaped" | Same | Same |
| roadmap.md S2 "the platform.rs placeholder already has that shape" | The placeholders are incomplete (enabling fails to compile) and cover only one platform | "platform.rs is an uncompiled single-platform draft; P1-1 must rewrite it" |
| todo.md errata item ① "every platform's Provider is a placeholder implementation (platform.rs returns "not implemented")" | "Every platform" is aspirational | Can be corrected alongside the P1 landing; the precise wording is in §1.2 of this document |

### 2026-10-04 landing update (the §4 table has been handled with the landing)

- The platform.rs / "about 3800 lines" stances in networking.md §1/§7 have been rewritten with the P1-1/P1-2 landing (linux.rs in the tree, line-count stance updated); roadmap S2 backfilled in sync. The remaining rows of the table are kept on file as the 09-29 deviation record.

## 5. Impact on later implementation (for direct citation by the P1-1..P1-3 / P1-4 / P3-2 design documents)

1. **P1-1 must not be narrated as "replace the platform.rs placeholders"**: the correct path is to create a new Linux implementation module and wire it into the `network/mod.rs` module tree; the `platform.rs` dead draft can be deleted or kept as a macOS reference (the missing methods must be filled in before enabling);
2. **The `TunInterface`/`TunPacketStream` placeholders should be dealt with in P1-1** (covered by a real implementation or deleted); their "fake write success" semantics cannot be kept;
3. **P1-2's process injection needs three coordinated changes**: the TUN side obtains process info (/proc or a conntrack reverse lookup) -> `FlowContext` gains a process field or an agreed annotation key -> `MatchCondition` gains a `Process` variant; P0-1's `ProcessIdentity` can be reused directly as the carrier type;
4. **P1-3 has a ready-made channel**: `SeepConfig.network` (new) -> `RuntimeConfig.network_config` (already exists) -> `NetworkManager` (skeleton already exists); at the same time, the naming unification of `tun/redir` vs `NetworkMode::{tun,transparent}` and an explicit warning for unknown top-level keys need rulings;
5. **P1-4's real prerequisite is "build the mount point", not "write a middleware"**: a static middleware chain (on the ingress and/or egress side) is the common foundation of padding/timing/shaping; P3-2's dynamic loading adds a loader and isolation on top of that foundation and must not start before it.

### 2026-10-04 landing update (all §5 forward-looking items have landed)

1. P1-1 was implemented along the "new Linux implementation module" path -- `network/linux.rs` (now 1757 lines including tests) is in the tree; the `platform.rs` dead draft is kept untouched (still `// pub mod platform;`);
2. The `TunInterface`/`TunPacketStream` placeholders were deleted with the trait pruning (TunProvider is now 14 methods);
3. Process injection landed with the three coordinated changes -- TUN-side process annotations -> FlowMetadata annotation keys -> `MatchCondition::Process` (P1-2 T5, 7a3024d);
4. The P1-3 channel is connected (R1-R4, 1e1a7c0/1befbe7); the `tun/transparent` naming follows `transparent`, and unknown top-level keys error explicitly via `deny_unknown_fields`;
5. The P1-4 static mount point is built (the obfs_config.rs middleware chain), and the P3-2 WASM loader and sample plugins have landed on top of it (955e4d6).
