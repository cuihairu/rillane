# P3-2 Plugin Dynamic Loading (WASM FlowMiddleware) -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) S4 (the "plugin dynamic loading: WASM/dynamic library `FlowMiddleware` loader + rate limiting/content filtering samples" errata-downgraded item) | [obfuscation-middleware.md](obfuscation-middleware.md) sections 1.2/1.5 (static chain + "P3-2 dynamic loading extends on top of this container, the trait does not move").
> This document is the landing finalization: **scope rulings, carrier and ABI, isolation mechanism, config surface, sample plugins, counter surface, test strategy, step-by-step checklist**. Deviations are backfilled into section 9 after landing.
> Reuse baseline: the `FlowMiddleware` trait (rillane-core, two methods name/handle) | the `MiddlewareChain` static container (order fixed at build time, read-only at runtime, P1-4 section 1.2 C1) | the `FlowOutputRouter::forward` E8 error path (any middleware Err aborts) | the `ObfuscationConfig` schema + validate (E1/E2 precedent) | the P1-5 pool/factory process-level singleton (D-10) singleton precedent.

## 0. Scope ruling

| In this item | Deferred to V2 / other |
|-----------|-------------|
| **WASM carrier** (wasmtime): loader + `FlowMiddleware` adapter + process-level engine singleton; crash (trap) and timeout (fuel instruction budget) isolation | **Direct dynamic library loading** (libloading in-process): cannot deliver the "crash has isolation" acceptance (no isolation boundary in the same address space), a separate item is opened when there is a real need (section 9 deviation 1) |
| **Two sample plugins**: rate limiting (token bucket, instance in-memory state) + content filtering (first-chunk keyword scan); the `plugins/` directory builds independently (not a workspace member, cross-compiled to wasm32-unknown-unknown) | Plugin I/O surface (network/file/clock): MVP plugins are pure computation, zero WASI (the host injects `now_ms` -- wasm32-unknown-unknown has no clock); asynchronous host functions deferred to V2 |
| **Config surface**: the `obfuscation.plugins` block (path + fuel budget), appended to build_middleware_chain; rillaned currently reads config once at startup (config hot reload is not wired), the plugin chain is static in-process and regenerates on process restart | Plugin hot-plug/runtime load-unload (no separate load/unload API) |
| **First-chunk probing content filtering**: `wants_payload` export declaration + `Flow.io` first-chunk probe/replay wrapping | Payload **rewriting** (the MVP only issues a binary allow/deny ruling, it does not rewrite stream bytes -- HTTP-level rewrite semantics deferred to V2) |
| **Counter surface**: per-plugin atomic counters (calls/denied/traps/fuel_exhausted) + tracing logs; **the control plane `GET /plugins/stats` is wired** (2026-10-05 observability round: the runtime bypasses concrete-type handles + a getter snapshot) | /metrics metric family form (the endpoint JSON is already usable; prometheus series deferred to later on demand) |

**Acceptance criteria** (the todo P3-2 original text, delivered one by one): 1 "externally compiled sample plugins can load and take effect" = the two samples in `plugins/` build wasm32 artifacts as independent cargo builds, and take effect on the chain after the host loads them (rate limiting: deny the flow after the token is exhausted; content filtering: deny on a first-chunk hit); 2 "crash/timeout has isolation" = a trap plugin (unreachable) and an infinite-loop plugin (fuel exhausted) both converge to Err on that single `handle` call (E8 flow denial), with the process and subsequent flows unaffected (pinned by section 4 unit tests).

## 1. Carrier and ABI

### 1.1 Carrier ruling: WASM (wasmtime)

- The acceptance "crash/timeout has isolation" **can only be delivered by WASM**: a trap (unreachable/OOM/stack overflow) is converted to Err at the wasmtime layer, whereas an in-process dynamic library crash is a process crash with no isolation to speak of; the fuel instruction budget is the only hard-abort mechanism for synchronous calls (section 3);
- Dependency cost documented as-is: wasmtime enters the workspace (the rillane-plugins crate), a one-time first-build cost (cranelift), with `default-features = false` keeping only `cranelift + runtime + wat` (wat for inline WAT in tests, production loads binary .wasm);
- Engine as a process-level singleton (same technique as D-10): one global compiler/JIT, shared across plugins; each plugin has its own `Instance`/`Store` (state isolation).

### 1.2 Plugin ABI (wasm32-unknown-unknown, custom exports, no WASI)

Plugin exports (the Rust source surface = `#[no_mangle] extern "C"`):

| Export | Signature | Semantics |
|------|------|------|
| `memory` | linear memory | the host reads/writes the argument/result areas (allocated by `alloc`) |
| `alloc(size: u32) -> u32` | bump allocation | the host obtains a result buffer inside the plugin's linear memory (allocated before each call, single-call lifetime) |
| `plugin_name() -> u32` | ptr | NUL-terminated UTF-8 plugin name (the host reads it once at load time, `Box::leak` fixes it as `&'static str` -- the trait signature does not move, delivering the promise in obfuscation-middleware.md section 1.5) |
| `wants_payload() -> u32` | 0/1 | whether the first-chunk payload is needed (content-filtering plugins set 1; the host uses it to decide whether to probe) |
| `on_flow(ctx_ptr: u32, ctx_len: u32, out_ptr: u32, out_cap: u32) -> i32` | written length | >=0 = the number of decision-JSON bytes written into the out buffer; <0 = in-plugin error code (the host converts it to Err) |

### 1.3 Context and decision (JSON over linear memory)

Host -> plugin (`FlowContext` JSON):

```json
{"flow_id":"<uuid>","host":"example.com","port":443,"proto":"tcp",
 "now_ms":1760000000000,"annotations":{"rillane.route.kind":"chain"},
 "first_chunk":"<base64, carried when wants_payload=1; capped at 4096B>"}
```

- `now_ms` is injected by the host -- wasm32-unknown-unknown has no clock (section 0 carrier ruling);
- `first_chunk`: when `wants_payload()=1` the host first probes the first chunk from `Flow.io` (a single `read`, capped at 4096B -- the kernel returns on arrival, so interactive flows incur no extra latency), then base64-encodes it into the ctx; after the plugin denies/allows, the host returns the probed bytes to the flow as a replay io wrapper (section 2.2).

Plugin -> host (decision JSON):

```json
{"action":"allow|deny","note":"<optional explanation>",
 "set_annotations":{"k":"v"},"remove_annotations":["k"]}
```

- `deny` -> the adapter `bail!` (the existing E8 semantics: this flow aborts, the error bubbles up);
- `set_annotations`/`remove_annotations`: a plugin may write `metadata.annotations` (the same contract as section 1.4 -- carrier keys `rillane.*` are written by the built-in chain, plugins are advised to use their own namespace such as `plugin.<name>.*`, a documented convention not enforced).

## 2. Host side

### 2.1 Loader (crates/rillane-plugins)

```rust
pub struct PluginLoadOptions { pub fuel: u64 }        // per-call fuel budget
pub fn load_plugin(path: &Path, opts: PluginLoadOptions) -> Result<Arc<dyn FlowMiddleware>>;
```

- Flow: read the .wasm -> `Module::new` (process-level engine singleton) -> instantiate -> validate the required exports (memory/alloc/plugin_name/on_flow) -> probe `wants_payload` -> assemble the `WasmPluginMiddleware`;
- `Store` is serialized with a `Mutex` (wasmtime `Func::call` needs `&mut Store`; plugin global state such as a token bucket is naturally shared across all flows of the same instance -- this is where rate-limiting semantic correctness lives; the serialization cost = calls to the same plugin queue up, accepted for the MVP, section 9 deviation 4);
- fuel is reset before each `on_flow` call (`set_fuel(opts.fuel)`) -- the budget is per call, not per flow.

### 2.2 First-chunk probe and replay (`wants_payload=1`)

- Inside `handle()`: `flow.io.read()` a single read of up to 4096B -> into the ctx -> call the plugin -> **deny means `bail!`** (the probed bytes are discarded with the flow, the connection closes) -> **allow means replay the probed bytes**: `ReplayIo { replay: Vec<u8>, inner: Box<dyn IoStream> }` implements `AsyncRead` (replay first, then pass through) + `AsyncWrite` (direct passthrough) -- the `IoStream` blanket impl adapts it automatically (rillane-core lib.rs:18);
- Timing assumption (documented as-is): `forward()` only hands the flow to the egress connector after the chain runs (section 2.1 runtime_builder.rs:1740), so probing inside the chain is the first reader; there is no prior observability violation.

### 2.3 Config surface (rillane-config `ObfuscationConfig.plugins`)

```yaml
obfuscation:
  enabled: true
  middleware: [padding]           # built-in chain (existing, ordered first)
  plugins:                        # new in P3-2 (appended after the built-in chain, the MVP ruling has no execution-order config)
    - path: plugins/output/rate_limit.wasm
      fuel: 100000000             # per-call instruction budget (default 1e8)
```

- validate: when `enabled`, the path must exist (the same build-time interception as E1); `plugins` counts toward the "strategy configured" criterion (the existing E1 "enabled=true but no strategy configured" extends `|| !plugins.is_empty()`);
- Mount point: after the built-in loop in `build_middleware_chain` (obfs_config.rs) append the plugin adapters -- chain order = built-in declaration order + plugins declaration order.

## 3. Isolation mechanism (acceptance 2)

| Isolation surface | Mechanism | Semantics |
|--------|------|------|
| Crash (trap: unreachable/OOM/stack overflow/division by zero) | wasmtime converts it to `Err` (downcast `Trap`, record the `traps` counter + a tracing warn) | that `handle` returns Err -> E8 denies that flow; the Store is not poisoned (a wasmtime trap does not kill the instance), subsequent flows proceed as normal |
| Timeout / infinite loop | **fuel instruction budget** (reset per call): exhaustion is a trap (`OutOfFuel`), the `fuel_exhausted` counter | a hard upper bound independent of wall-clock -- a synchronous call cannot be preempted from outside, so fuel is the only abort mechanism (section 9 deviation 3: wall-clock is only observed and reported as slow, not used as an abort basis) |
| Memory | linear memory is bounded (the wasmtime default limit), and the host clamps the upper bound via `out_cap` | a plugin cannot read/write host memory out of bounds (an intrinsic WASM sandbox property) |

## 4. Test strategy

### 4.1 Unit tests (rillane-plugins, inline WAT, zero external files, CI-deterministic)

- **noop**: name / allow / annotation set+remove round trip;
- **trap**: an `unreachable` module -> Err convergence, `traps=1`, **and the next call to the same plugin still succeeds** (the Store is not poisoned -- the core assertion of the isolation semantics);
- **infinite loop**: `loop br 0 end` -> Err on fuel exhaustion, `fuel_exhausted=1`;
- **first-chunk probe**: mock io (a duplex pair), deny -> Err on the read side; allow -> the replayed bytes are intact + subsequent passthrough;
- **loader negative paths**: missing exports / bad magic -> Err with a cause.

### 4.2 Sample plugin acceptance in practice (`plugins/`, independent builds)

- `cargo build --target wasm32-unknown-unknown` (both samples + pure-logic Rust unit tests running inside the plugin crate);
- Host integration verification (executed locally, results into the todo progress): rate limiting -- the N+1 flow is denied and the note is visible; content filtering -- a first chunk containing the keyword is denied, a clean payload is allowed through;
- trap/infinite-loop isolation is pinned by the 4.1 WAT unit tests (WAT and plugins share the same ABI surface).

### 4.3 Config surface (rillane-config / rillane-runtime)

- The plugins block has deny_unknown_fields + a validate matrix (a non-existent path is E1, a disabled state tolerates half-finished pieces);
- `build_middleware_chain` assembly test: plugins come after the built-in chain, chain name-order assertion, a bad path errors at build time.

## 5. Step-by-step implementation checklist (R0-R2)

Commit cadence follows the P0-4 section 9.1.1 hard rule: each step build/test all green -> a single commit (citing this document's sections) -> fetch+rebase -> push; no tags, no force.

| Step | Content and landing points | Acceptance |
|----|-----------|------|
| R0 | This design document | -- |
| R1 | loader + adapter + first-chunk replay + config surface: crates/rillane-plugins (engine singleton/ABI/isolation/counters) + the rillane-config plugins block + rillane-runtime assembly + the 4.1/4.3 unit tests | all green |
| R2 | Sample plugins + acceptance in practice + doc backfill: the two samples in plugins/ (independent build script) + the 4.2 practice + checking off todo P3-2 + a note in obfuscation-middleware.md section 1.5 + section 9 deviations | all green + the practice |

## 6. Deviations and assumptions

| # | Type | Content |
|---|------|------|
| 1 | Scope | **Direct dynamic library loading is not in the MVP**: it cannot isolate crashes in-process (acceptance 2 cannot be delivered), the libloading route waits for a real need as a separate item; "WASM/dynamic library" is delivered as WASM |
| 2 | Assumption | Plugins are pure computation with zero WASI: the clock is injected by the host (now_ms), no file/network surface; asynchronous host functions deferred to V2 |
| 3 | Deviation | Wall-clock is not used as an abort basis (a synchronous call cannot be preempted); fuel is the only hard upper bound, and the config surface exposes the fuel budget for tuning |
| 4 | Deviation | Calls to the same plugin are serialized through the Store Mutex -- rate-limiting state correctness takes priority over concurrency; plugin concurrency deferred to V2 (multi-instance sharding) |
| 5 | Scope | Payload is only allow/deny, no rewriting (HTTP-level rewrite semantics deferred to V2); the observability control-plane wiring is delivered (2026-10-05, `GET /plugins/stats`, the section 0 counter surface row) |
| 6 | Assumption | First-chunk probing inside the chain is the first reader of flow.io (forward hands the egress connector only after the chain -- the runtime_builder section 2.1 timing); if a pre-chain reader appears in the future, the probe semantics need re-ruling |

## 7. Risks and open items

- **P-load**: the wasmtime first-build cost enters the workspace (documented as-is); at build time `plugins/` is not in workspace members (wasm-only crates cannot be compiled by the host), so the rillaned release contains the loader but not the sample artifacts (the README records how to build);
- **R-name**: `plugin_name()` returns the host `Box::leak` fixup -- leak amount = number of plugins x name length (loaded once, process-level lifetime, acceptable; recorded in a source comment);
- **R-state**: plugin instance state (token bucket) lives with the Store until process exit -- rillaned has no config hot-reload wiring (one read at startup), the chain is not rebuilt in-process, so the token bucket actually clears with process exit; if hot reload is wired later and rebuilds the chain, the old instances die with the `MiddlewareChain` Arc and the state clears under the same semantics.

## 9. Landing backfill (2026-10-04, R1/R2 all delivered)

**R1** (loader + config surface): `crates/rillane-plugins` (lib.rs/abi.rs/loader.rs/plugin.rs/replay.rs) + rillane-config `ObfsPluginConfig` + rillane-runtime `build_middleware_chain` assembly -- sections 2/3/4.1/4.3 delivered item by item; all 10 unit tests green (noop annotation round trip / deny bail / trap isolation + Store not poisoned / fuel exhaustion / first-chunk replay + passthrough / deny after probing / lying decision length / bad magic / missing exports / ReplayIo poll semantics).

**R2** (samples + practice): `plugins/rate-limit` (token bucket capacity 3, replenish 1 per second, `now_ms` advanced by host injection) and `plugins/content-filter` (built-in blocklist with case-insensitive substring matching after base64 decoding) -- independent `[workspace]`, not in members (section 7 P-load), `plugins/build.sh` produces `plugins/output/*.wasm` (gitignored, not committed); host-side pure-logic unit tests run inside the crate (replenishment cap / case-insensitive hits). **Acceptance in practice**: `cargo run -p rillane-plugins --example plugins_smoke` -- rate limiting lets 3 through and denies 1 (note visible), `/wp-admin` hits and is denied, a clean payload is allowed with the first-chunk replay intact + subsequent passthrough, and the per-plugin counters are evidenced.

Implementation-time corrections (differences from the section 1/section 2 drafts, none crossing the section 0 scope ruling):

| # | Item | Landed form |
|---|-----|--------|
| 1 | wasmtime 49 has its own `Error` type (not an anyhow re-export) | Cargo.toml explicitly keeps the `anyhow` feature (a `From<wasmtime::Error> for anyhow::Error` bridge); host-side context goes through `map_err(anyhow::Error::from)` and then attaches an anyhow `context` |
| 2 | wasmtime 49 export-lookup API | `get_typed_func` returns `Result` (a missing export is an Err carrying "failed to find function export"); optional exports (wants_payload) first probe existence with `get_export` (Option) |
| 3 | Missing fuel for probe calls at load time | Under the `consume_fuel(true)` engine the Store starts with fuel=0 -- raise `set_fuel(u64::MAX)` before probing `wants_payload`/`plugin_name` at load time (the per-call budget reset semantics still belong to invoke, section 2.1 unchanged) |
| 4 | Sample plugin linear memory growth | `alloc` uses `memory_size`/`memory_grow` to grow pages on demand (gated by `#[cfg(target_arch = "wasm32")]` -- the host `cargo test` only exercises the pure-logic surface and never touches alloc); the cdylib artifact name follows the package name (`rillane_plugin_<name>.wasm`), and build.sh copies it to the outward-facing name |
| 5 | Infinite-loop WAT form | `(loop br)` must be followed by `unreachable` to pass wasm type checking (the static reachability requirement for an i32 function result) |
| 6 | Counter-surface observability carrier | The section 0 counter surface's "control endpoint wiring deferred to a later observability round" is delivered in two steps: `WasmPluginMiddleware::stats()` (`Debug` rendering + the `plugins_smoke` evidence); the 2026-10-05 observability round adds the control plane `GET /plugins/stats` (a runtime `get_plugin_stats()` snapshot bypass, `load_plugin_with_stats` gives the same instance two handles -- a trait object in the chain, a concrete type for observability, no second JIT); the /metrics metric family form is deferred to later on demand |

No additions to the section 6 deviation table (deviations 1-6 all delivered per the original ruling).
