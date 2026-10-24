# P1-3 network config block + seepctl route apply/clear -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) S2 · [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) §2 (B1-B4) and §5.4 (channel ruling) · [tun-dataplane.md](tun-dataplane.md) §1.3 (AppliedStep/rollback reuse) · §2.6 (ownership ruling carried over) · §2.7 (auto-bypass).
> This document is the finalized landing design: **config schema, runtime wiring, control-plane endpoints, CLI, idempotency/rollback/restoration semantics, error paths, test strategy, step-by-step checklist**. Deviations are backfilled into §9 after landing.
> Reuse baseline: `LinuxRouteManager` (P1-1 T2 product, **hard dependency** -- apply/clear is the CLI-ification of its `AppliedStep` rollback mechanism) · control_plane `(Method, path)` match dispatch (`/chains/dry-run` precedent) · clap nested subcommands (`Chain{command}` precedent) · route.rs `parse_cidr`/`ipv4_netmask` helpers.

## 0. Scope

| In this item | Belongs to V2 / other items |
|-----------|-----------------|
| `SeepConfig.network` block schema (seep-config mirror types) + conversion into platform `NetworkConfig` | Global takeover (default route + `ip rule` + fwmark + `SO_MARK` egress marking) |
| seepd wiring: `enable_network_virtualization` derived from config + `NetworkManager` stand-down ruling (§2.2) | transparent/redir (nftables/iptables), tap/hybrid mode implementation |
| Three control-plane endpoints (apply/clear/status) + the three `seepctl route` actions (including `--dry-run`) | filtering/dns sub-blocks (P2-8; not exposed at the schema layer at all, see E2) |
| Idempotency/rollback/restoration semantics (§5) | Process filtering (= P1-2 `MatchCondition::Process`, goes through routing rules, **not into the network block**) |
| User bypass explicit list not exposed (include negation is bypass, §1.4 ruling) | Config hot reload (restart takes effect, aligned with the P0-5 §1.6 ruling) |

**Implementation order**: R0 (schema) has no dependencies and can go first; from R1 onward there is a hard dependency on P1-1's T1 (device) + T2 (LinuxRouteManager) being landed -- without a device, routing has no `dev` to hang off.

## 1. Config schema (seep-config)

### 1.1 Block shape

```yaml
network:
  mode: tun                    # tun = MVP; transparent/tap/hybrid report "not implemented" at build time (E1)
  tun:
    name: seep0                # optional; default None -> kernel assigns tun%d (TUNGETIFF read-back)
    mtu: 1400                  # default 1500; >=68 (reusing the TunConfig::validate definition)
    ipv4: "10.255.0.1/24"      # default as left; the tun's own subnet enters auto-bypass (tun-dataplane §2.7)
    ipv6: "fd00:db8::1/64"     # optional
    dns_servers: ["1.1.1.1"]   # recorded only (consumption belongs to P2-8, TunConfig takes it as-is)
  routing:
    include:                   # main-table explicit route inclusion set (include semantics, tun-dataplane §1.3)
      - "203.0.113.0/24"
      - "2001:db8::/32"
      - "198.51.100.7/32"      # /32 is a host route, no separate Host representation needed
```

### 1.2 Mirror types and conversion (ruling: mirror rather than add a dependency)

seep-config currently has zero dependency on seep-platform (deps only anyhow/serde family), keeping it light: **seep-config defines mirror serde types, and seep-runtime adds a `to_platform()` conversion** (same pattern as `UdpConfig` -> `UdpSessionConfig` -- seep-config does not depend on seep-core either).

| config mirror type (seep-config) | platform conversion product (seep-runtime) |
|-------------------------------|----------------------------------|
| `NetworkBlockConfig { mode, tun: Option<TunBlockConfig>, routing: Option<RoutingBlockConfig> }` | `NetworkConfig { mode, tun, routing, filtering: None, dns: None }` |
| `NetworkBlockMode::{Tun, Transparent, Tap, Hybrid}` (serde names aligned with the enum) | `NetworkMode` variants of the same names |
| `TunBlockConfig { name, mtu, ipv4: Option<String>, ipv6: Option<String>, dns_servers }` | `TunConfig`: `ipv4` split by `parse_cidr` into `ipv4_addr` + `ipv4_netmask`; `ipv6` split into `ipv6_addr` + `ipv6_prefix_len`; `enable_routing = routing.is_some()`; `enable_dns = false`; both gateway fields None |
| `RoutingBlockConfig { include: Vec<String> }` | `RoutingConfig { mode: Ip, default_gateway: None, dns_servers: empty or taken from the tun block, rules: each include entry -> RouteRule{name: "include[i]", priority: 100+i, destination: Ipv4Network/Ipv6Network (per parse), gateway: None, interface: None, route_type: Unicast, metric: Some(0), enabled: true}, bypass_rules: default_bypass_rules(), enabled: true }` |

(`RoutingMode`/`RouteType`/priority/policy dimensions are not exposed in config -- MVP semantics are single-valued, fixed at the conversion site; see §9-6.)

### 1.3 Naming ruling (B4 closed)

The config literal follows the platform enum and uses **`transparent`**, dropping the planned wording "redir" (same semantics); todo/roadmap wording is backfilled per this document.

### 1.4 Validation (at build time, `NetworkBlockConfig::validate`)

1. `mode != Tun` -> Err (E1, with a "V2/future item" pointer);
2. `mtu < 68` -> Err; each `ipv4`/`ipv6`/`include` entry goes through `parse_cidr`, failure -> Err carrying the original string (E3);
3. An include entry hits the auto-bypass set (egress/mesh/control/tun subnets, assembled at build time as in tun-dataplane §2.7) -> **remove + warning** (not Err -- loop prevention takes precedence over strictness, E5);
4. `routing` absent = device only, no routes (legal: pure capture/test scenarios).

### 1.5 Compatibility and silent ignoring (B2 targeted closure)

- Existing configs without `network:` -> `Option` defaults to None, zero behavioral difference (pinned by a serde roundtrip test);
- **`NetworkBlockConfig` gets `#[serde(deny_unknown_fields)]`** -- a new block has no existing-compatibility burden, so a misspelled sub-field errors immediately; the global `SeepConfig` stays permissive (existing configs may carry extra keys, and global tightening is a breaking change, so no; B2's "explicit warning" is partially delivered by the new block's strictness, the global stance is recorded as an open item in §10).

## 2. Runtime wiring

### 2.1 seepd derived switches

`apps/seepd/src/main.rs` no longer hardcodes only mesh/chain: `enable_network_virtualization = cfg.network.is_some()`, `network_config = cfg.network.map(to_platform)`. The two hardcoded true values for mesh/chain are **not touched** (existing behavior, out of this item's scope, recorded as §9-8).

### 2.2 `NetworkManager` stand-down (ownership-conflict ruling, correcting build() item 4)

Status quo: `runtime_builder.rs:165-175` constructs `NetworkManager` when `enable_network_virtualization && network_config`, and its `initialize()` necessarily fails (all four factories always Err) -- audit §1.2 "the wiring exists but is unusable under any config". After P1-3 seepd really sets that switch, so this path will be hit. **Ruling**:

- Append `&& network_config.mode != Tun` to the construction condition -- when `mode == Tun` the data-plane owner is `TunIngress` (tun-dataplane §2.6, carried over, not absorbed); `NetworkManager` is kept as the future container for transparent/tap/hybrid, and any P1 config reaching it gets a clear Err from the factory (no longer silent);
- `mode == Tun` while the config carries filtering/dns intent -- the schema layer already denies it (§1.5), belt and suspenders.

### 2.3 `LinuxRouteManager` shared handle

- The build() TUN block constructs an `Arc<LinuxRouteManager>`: one clone into `TunIngress` (startup apply + exit teardown ownership duties), one into control-plane state (consumed by CLI apply/clear/status);
- **Serialization**: apply/clear/status and startup/teardown serialize through the manager's existing `Mutex<Vec<AppliedStep>>`, extended to **operation-level mutual exclusion** (a whole apply or clear runs holding the lock; steps are short -- the `ip` subprocess is millisecond-scale);
- `AppliedStep` (tun-dataplane §1.3) is the data source for status/clear: `{argv: Vec<String>, at: SystemTime}`, and clear = undo all recorded steps in reverse order (**"full restoration" = restoring only the steps seep added, not clearing the system routing table**, §9-7);
- **RouteControl in-process contract (added in the 2026-09-30 six-element audit)**: `LinuxRouteManager` exposes the following methods for direct consumption by the control plane (§3) (the `Arc<LinuxRouteManager>` itself is the contract, **no new trait** -- a single implementation gains no abstraction benefit):

  ```rust
  async fn apply_desired(&self, cfg: &RoutingConfig, dry_run: bool) -> Result<ApplyOutcome>;
  async fn clear(&self) -> Result<Vec<AppliedStep>>;
  fn status(&self) -> RouteStatus;   // synchronous read, does not hold the write lock
  // ApplyOutcome { planned, executed, rolled_back: Vec<AppliedStep> }
  // RouteStatus  { device, mtu, up, applied: Vec<AppliedStep> }
  ```

  All three methods serialize through the §2.3 operation-level mutual exclusion; `dry_run=true` runs only the planner (argv construction), executes no executor and does not mutate `applied` -- the planner/executor separation already has §7.1 assertions backing it.

## 3. Control-plane endpoints (control_plane.rs, match arms aligned with `/chains/dry-run`)

| Endpoint | Request | Success response | Failure response |
|------|------|---------|---------|
| `POST /network/route/apply` | `{"dry_run": false}` | `{"planned": [step], "executed": [step]}` (executed is empty when dry_run=true) | `{"error": "...", "rolled_back": [step]}` (E7: a mid-run failure was rolled back in reverse) |
| `POST /network/route/clear` | – | `{"undone": [step]}` | same as above |
| `GET /network/route/status` | – | `{"mode":"tun","device":"seep0","mtu":1400,"up":true,"applied":[step]}` | – |

`step = {"argv": ["ip","route","replace","203.0.113.0/24","dev","seep0","metric","0"], "at": 1760000000}`. Auth inherits the control-plane status quo (local HTTP, no new surface).

## 4. `seepctl route` (nested subcommands, aligned with the `Chain{command}` shape)

```
seepctl route apply   [--endpoint URL] [--dry-run]
seepctl route clear   [--endpoint URL]
seepctl route status  [--endpoint URL]
```

- `apply`: instructs seepd to **replay the desired route set** per the current config (idempotent, §5); `--dry-run` prints the planned argv without executing;
- `clear`: undo all AppliedSteps in reverse order;
- `status`: device state + table of applied steps;
- Output: an argv table line by line (dry-run prefix `plan:`, executed `ok:`, rollback `undo:`).

## 5. Idempotency / rollback / restoration semantics (state machine)

- **apply idempotency**: all steps `ip addr replace`/`ip route replace` are naturally idempotent; repeated applies produce identical AppliedStep contents -- **deduplicated recording** (an identical argv already on the books is not recorded again, so status is stable); test = after two consecutive applies, the include prefix in `ip route show` is unique with consistent attributes;
- **fwmark escape steps (half 2 of the 2026-10-05 egress fwmark batch landed)**: when `network.egress_fwmark` != 0 the planner appends two steps before the addr/route steps -- `FwmarkRule` (`ip rule add fwmark <mark> table 100`; iproute2 has no rule replace, so a repeated add reports File exists, which is **treated as already effective** -- EEXIST tolerance is idempotency, it does not trigger E7 rollback, and no other step is tolerated) + `EscapeRoute` (`ip route replace default <via_dev> table 100`; via_dev is taken from the first default route in the probed main table -- the part after `default ` on the first line of `ip route show default table main`; no default route -> skip the whole escape surface without erroring); both steps enter the AppliedStep ledger, and both E7 reverse rollback and clear restoration cover them (undo = `ip rule del` / `ip route del default table 100`); with the default mark=0 or no default route there are zero new steps and zero difference from existing behavior; the planned output of a dry-run shows these two steps as well. The escape table number is fixed at 100 (a user-defined range, avoiding the 255/254/253 system reservations);
- **Rollback on failure**: a non-zero exit of any apply step -> undo the executed steps of this batch in reverse order -> the Err response carries `rolled_back` (same mechanism as tun-dataplane E7, this item merely exposes it to the CLI);
- **clear restoration**: undo all steps on the books in reverse order -> empty the AppliedStep list; with no steps, Ok an empty table (E8); after clear, TunIngress **keeps running** (the data plane idles, packets no longer enter tun) -- that is the requested semantics, and `status` shows `applied: []` + device up;
- **Concurrency**: apply/clear are mutually exclusive and serialized (§2.3); an apply immediately followed by a clear is a net restoration;
- **Startup apply == CLI apply (added in the 2026-09-30 six-element audit)**: seepd startup's `TunIngress::run` call of `apply_desired(cfg, false)` and the CLI `route apply` go through the **same method** (idempotent replay); the only difference is the caller and whether dry_run -- there are not two route write paths;
- **Config file edits need a restart**: `route apply` replays seepd's **in-memory** `network` config (loaded at startup, §9-10 hot reload unsupported) -- editing the YAML and running `route apply` without restarting seepd will **not** reflect the file change; the role of `route apply` is runtime replay/reconciliation/fault recovery, not config hot loading.

## 6. Error paths

| # | Error point | Condition | Semantics and recovery |
|---|--------|------|-----------|
| E1 | mode is not tun | transparent/tap/hybrid | Build-time Err: "not implemented (V2/future item)" |
| E2 | Unknown field in the network sub-block | deny_unknown_fields | Build-time Err naming the field (§1.5 targeted closure) |
| E3 | Invalid CIDR/mtu | parse_cidr failure / mtu<68 | Build-time Err carrying the original string |
| E4 | routing absent | – | Legal (device only, no routes) |
| E5 | include hits auto-bypass | loop prevention | Remove + warning (not Err) |
| E6 | CLI cannot connect / no network block | seepd not running or not configured | CLI Err stating which of the two branches |
| E7 | apply fails mid-run | `ip` non-zero exit | Reverse-rollback this batch + Err carrying rolled_back |
| E8 | clear with no steps | – | Ok empty table (idempotent) |
| E9 | apply/clear concurrent | – | Mutual-exclusion queue (the later one runs after the earlier completes) |
| E10 | Device absent | TunIngress not running/already exited | Err: "TUN not enabled (check the network config and logs)" |

## 7. Test strategy

### 7.1 Unit tests (no privileges)

- schema: parsing old configs with no `network:` ✓; roundtrip with the block ✓; unknown sub-field denied ✓; three invalid mode values ✓; invalid CIDR/mtu ✓;
- conversion: `ipv4: "10.255.0.1/24"` -> `ipv4_addr=10.255.0.1, ipv4_netmask=255.255.255.0`; include -> full-field assertions on RouteRule (priority increasing / metric 0 / Unicast); auto-bypass hits removed + warning;
- rollback (mock executor): inject a non-zero exit at step k -> assert the previous k-1 steps receive reverse-order undo argv and AppliedStep is emptied;
- REST handler: assert the three endpoints' request/response shapes against a mock route control piece (including dry_run and the E7 shape);
- CLI: argument -> request-assembly assertions (no real sending).

### 7.2 Linux integration (skip guard reused from tun-dataplane §4.2: no `/dev/net/tun` or no CAP_NET_ADMIN -> skip)

- apply idempotency: two applies -> the include prefix in `ip route show` is unique, with `dev <tun>` and metric assertions;
- clear restoration: clear after apply -> capture the `ip route show` diff before/after apply and assert it is empty (only the lines seep added disappear);
- dry-run: `--dry-run` -> planned printed and `ip route show` unchanged;
- status: reconcile AppliedStep against the actual routes.

## 8. Step-by-step implementation checklist (R0-R4)

Commit cadence follows the hard rule of P0-4 §9.1.1 / tun-dataplane §5: each step `cargo build` + `cargo test` fully green -> a single commit (referencing the §section of this document) -> `git fetch origin main` + rebase -> push -> next step; no tag/release/force push.

| Step | Content and landing point | Depends on | Acceptance |
|----|-----------|------|------|
| R0 | seep-config: `NetworkBlockConfig`/`TunBlockConfig`/`RoutingBlockConfig` + deny + validate; seep-runtime: `to_platform()` conversion | — | 7.1 schema/conversion fully green; old configs zero difference |
| R1 | build() item 4 stand-down condition (mode != Tun) + seepd-derived `enable_network_virtualization` + `Arc<LinuxRouteManager>` dual handles + operation-level mutual exclusion | P1-1 T1+T2 | tun mode builds successfully with NetworkManager not constructed; non-tun modes get a clear Err |
| R2 | The three control-plane endpoints (apply/clear/status, dry_run passed through) | R1 | 7.1 REST handler tests |
| R3 | The three `seepctl route` actions + `--dry-run` + output format | R2 | 7.1 CLI assembly tests |
| R4 | 7.2 integration tests + documentation backfill (networking.md §2, todo/roadmap check-off, acceptance table cross-check) | R1-R3 | 7.2 fully green; P1-3 acceptance cross-checked item by item |

## 9. Deviations and assumptions (self-made assumptions where information was missing are all noted)

| # | Type | Content |
|---|------|------|
| 1 | Ruling | seep-config mirror types + runtime conversion, adding no seep-platform dependency to seep-config (keeps the config crate light; `UdpConfig` is the same-pattern precedent) |
| 2 | Ruling | mode literal is `transparent` (following the enum), dropping "redir" (B4) |
| 3 | Ruling | MVP does not expose a `routing.bypass` user list -- include negation is inherently bypass + `default_bypass_rules()` as the backstop; the explicit list comes with V2 global takeover |
| 4 | Ruling | `NetworkBlockConfig` deny_unknown_fields (new block, no compatibility burden); the global SeepConfig is not tightened (existing compatibility) |
| 5 | Assumption | REST JSON shapes aligned with the existing control-plane style (local HTTP without auth); `--dry-run` is shared by CLI and endpoint |
| 6 | Ruling | Policy dimensions such as RoutingMode/priority/metric are not exposed in config (MVP semantics are single-valued, fixed at the conversion site as `Ip`/`100+i`/`Some(0)`) |
| 7 | Clarification | "clear fully restores" = undoing the AppliedSteps seep added, not clearing the system routing table |
| 8 | Scope | seepd's hardcoded true values for `enable_mesh`/`enable_chain` are not touched (existing behavior, a separate item) |
| 9 | Correction | The todo acceptance "after apply, `ip rule`/the route table is as expected" -> MVP does not touch ip rule (main-table explicit route stance, tun-dataplane §1.3); **revised with half 2 of the 2026-10-05 fwmark batch**: once `network.egress_fwmark` is configured, apply creates the `ip rule fwmark` escape rule in table 100 plus the escape-table default route (§5 escape surface, not global takeover -- default-route rewriting still belongs to V2) |
| 10 | Assumption | include accepts only network prefix CIDRs (/32 expresses a host route); the `RouteDestination::Default`/`Host` variants do not enter the schema (V2 global takeover uses Default) |
| 11 | Deviation | The §2.3 `apply_desired(&cfg, dry_run)` signature landed as `apply_desired(dry_run)` -- the manager already holds the `RoutingConfig` at construction (injected alongside by `with_tun_config`), so the cfg parameter has no second source; the return is the typed failure `Result<ApplyOutcome, ApplyFailure>` (E7's structured `rolled_back` payload does not fit in anyhow, so the endpoint consumes it directly) |
| 12 | Deviation | §2.3's "build() constructs the `Arc<LinuxRouteManager>` dual handles" landed as a `TunIngress::route_manager()` accessor -- TunIngress owns device + routing (tun-dataplane §2.6 carried over), and the control plane obtains the same `Arc<TokioMutex<LinuxRouteManager>>` through the accessor, with no dual-instance risk; operation-level mutual exclusion is carried by two layers: that TokioMutex (serializing endpoints against each other and against run() startup/teardown) + the manager's internal `Mutex<Vec<AppliedRecord>>` (atomic ledger entry) |
| 13 | Deviation | §3's status endpoint "failure --" landed as a 503 text (when TunIngress is not assembled, following the `/nodes` precedent stance); TunIngress present but the device not created (not started/already exited) -> apply returns 500 `{"error": E10 stance}`, while status still returns 200 (device null/up false) -- the two "TUN unavailable" cases are layered by assembly state |
| 14 | Deviation | The step.at definition: status's applied carries the **ledger-entry time** (`AppliedRecord.at`), while apply/clear response steps carry the **response generation time** (executed/undone have no ledger semantics, so readability wins over falsely claiming an entry time); rolled_back/executed/undone steps render `undo_argv` (the undo fact -- E7 reverse rollback and clear restoration display the undo commands about to be executed) |
| 15 | Deviation | §4 CLI status output adds four device-state lines (mode/device/mtu/up) outside the argv table (aligned with the §3 response fields, with unknown/false fallbacks for missing keys); a successful apply response with a non-empty rolled_back appends an `undo:` section |
| 16 | Deviation | §8's R2-R4 steps merged into a single commit 1befbe7 (multiple sessions advancing the same item in parallel, so step cadence yielded to merged closure); the §7.1 REST/CLI tests landed with a subsequent test-fill commit (endpoint shapes including E10 503 / E7 500 / dry-run planned, plus CLI arguments and rendering pure functions) |

## 10. Risks and open items

- **O-global**: the existing breakage surface of a global `deny_unknown_fields` is not quantified (the B2 remainder) -- if tightening happens in the future, ship `seepctl check --strict` first as a probe;
- **R-route1**: an external process concurrently modifies routes (seep is not the system's only writer) -- `replace` semantics + idempotent apply replay can converge, with no conflict detection;
- **R-route2**: after clear the data plane idles (TunIngress still running) -- that is the requested semantics, stated explicitly in the docs (§5);
- **O-hot**: network-block hot reload is unsupported (restart takes effect, aligned with P0-5 §1.6); `route apply` is a runtime **routing-layer** replay and is not equivalent to config hot reload (changing tun-block parameters still needs a restart).
