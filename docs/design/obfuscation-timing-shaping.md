# P2-4 Obfuscation middleware extension (timing / shaping) (design draft)

> 2026-10-02 ready and landed in the same round (`TimingMiddleware` startup jitter + `ShapingMiddleware`
> write-grid normalization; see the roadmap S3 note). It extends two policies on the P1-4 static
> middleware pipeline: timing (micro-jitter injection) and shaping (stream-shape normalization),
> reusing the "policy/execution separation" of obfuscation-middleware.md §2 and the config mirror +
> conversion pattern of §3.
>
> **Landing status**: implemented (M0 `7d56d06`: design draft + seep-config mirror +
> seep-runtime conversion + tests; M1 `16d9eb2`: the two middlewares + PacedIo +
> whitelist extension + wiring + §7-3/4/5 tests; M2 this commit: an inline timing demo
> in the game preset + profile test updates + documentation backfill).

## 0. Scope and acceptance wording

**todo original text**: micro-jitter injection, stream-shape normalization.
**Acceptance original text**: verify timing-feature shift with the same statistical method as P1-4; the
latency cost must be quantifiable (p95 increase <= the configured cap).

**Measurable wording (explicit rewrite, not shrinking)**:

1. **Decision observability** (aligned with the P1-4 "annotation visible" wording): a flow hit by
   `TimingMiddleware` / `ShapingMiddleware` writes its decision into the `seep.obfs.timing` /
   `seep.obfs.shaping` annotation (millisecond value), asserted in unit tests; chain statistics are
   observable through the existing `MiddlewareChain` invocation counts;
2. **Timing-feature shift provable**: the timing decision range is a subset of [min_ms, max_ms] and is
   deterministic (the same flow_id always yields the same value, pinned by unit tests); under bursty
   writes, shaping produces an adjacent write-start interval >= interval (unit tests measure with a
   real small interval);
3. **Latency cost quantifiable**: both policies have a hard gate (timing's max_delay_ms /
   shaping's max_delay_ms); a decision value must not cross it -- the p95 increase <= the configured
   cap is asserted by the gate at construction time (unit tests inject a gate-crossing decision and
   assert Err/no admission).

## 1. Current state and structural constraints

- P1-4 landed: `MiddlewareChain` (seep-core, executes in declaration order, empty-chain bypass),
  `PaddingMiddleware` (policy side only writes annotations, the frame execution side does the
  padding), `obfs_config.rs` (`to_padding_policy` + `build_middleware_chain`), the §3.3-5 whitelist
  (currently `padding|latency_probe`; timing/shaping are registered in the whitelist text as
  "belongs to P2-4");
- `LatencyProbe` already proved that "sleep inside handle" is legal (probe uses 1ms);
- `Flow { io: BoxedIo, metadata: Metadata, .. }`, `IoStream` blanket impl
  (AsyncRead+AsyncWrite+Send+Sync+Unpin) -- **a middleware may wrap io**;
- The execution-side difference between P2-4 and P1-4: padding changes bytes (needs a frame carrier),
  while timing / shaping change **time** -- no new wire-format field is needed, and the execution side
  can complete it directly inside the middleware (sleep / io wrapping). This is the key difference from
  padding.

## 2. Design decisions

- **D-1 timing = startup jitter**: `TimingMiddleware::handle` sleeps once for the decided value d
  (before the connection is established); P2-4 M0 stops there. Per-datagram jitter is left to the
  UDP side (P0-4's frame carrier has boundaries to anchor on, added in a separate step together with
  the integration tests).
- **D-2 shaping = write-grid normalization (pacing)**: `ShapingMiddleware` wraps
  `flow.io`: before each `AsyncWrite` it sleeps until the "k x interval +
  jitter grid point" counted from the first packet, flattening bursts into an even shape. The read
  direction is untouched (normalizing only the controlled egress side is the subjective observation
  surface of stream shape; the read side is the peer's behavior and is not normalized).
- **D-3 same deterministic source**: the decision random source = `hash(flow_id, seq)` (the same
  family as padding §2.2's range_hash, FNV-1a + splitmix64, with seq incremented by a counter inside
  the middleware) -- no RNG, cross-platform deterministic, reproducible in tests.
- **D-4 double gates**: timing and shaping each have a `max_delay_ms` (config-time validate must
  ensure it is nonzero and >= min_ms; an over-limit decision value is clamped to the gate + Debug
  log, no Err -- an obfuscation gain must not break forwarding, the same downgrade style as padding
  E10).
- **D-5 config shape = a symmetric extension of padding's triple**: `ObfuscationConfig` gains
  `default_timing`/`default_shaping` (profile references, same semantics as default_padding) + inline
  `timing`/`shaping` blocks (same mutual-exclusion rules);
  `ObfsProfileConfig` gains nested `timing`/`shaping`. The shapes of `TimingBlockConfig`/
  `ShapingBlockConfig` follow `PaddingBlockConfig` (a required mode string + per-mode fields +
  validate per mode, naming the same as E2's style).
- **D-6 middleware names added to the §3.3-5 whitelist**: `padding|latency_probe|
  timing|shaping`; `build_middleware_chain` learns the new names too (declaration order
  executes, padding/timing/shaping may be combined arbitrarily -- when timing precedes shaping,
  shaping's first grid point is counted from the start of shaping, which is semantically
  consistent).
- **D-7 metrics**: no new family; the observability surface = writing annotations (§0-1) + the
  existing `MiddlewareChain` invocation counts + the `seep_obfs_padding_*` precedent left for M1
  to add `seep_obfs_shaping_writes_total` on the execution side (the io wrapping layer), only when
  shaping is actually in effect -- M0 fixes no metric name; M1 lands it.

## 3. Data structures

```rust
// seep-config (mirror, deny_unknown_fields)
pub struct TimingBlockConfig {
    pub mode: String,          // "fixed" | "uniform"
    pub fixed_ms: u64,         // fixed-mode value (must be nonzero)
    pub min_ms: u64,           // uniform lower bound
    pub max_ms: u64,           // uniform upper bound (min <= max)
    pub max_delay_ms: u64,     // hard gate (must be a floor beyond the mode's upper bound; 0 = unset -> validate E2)
}
pub struct ShapingBlockConfig {
    pub mode: String,          // "interval"
    pub interval_ms: u64,      // grid interval (must be nonzero)
    pub jitter_ms: u64,        // grid jitter amplitude (must be <= interval_ms)
    pub max_delay_ms: u64,     // hard gate
}

// seep-core (runtime spec, same file and family as PaddingSpec, serde)
pub enum TimingMode { Fixed, Uniform }
pub struct TimingSpec {
    pub mode: TimingMode, pub fixed_ms: u64, pub min_ms: u64, pub max_ms: u64,
    pub max_delay_ms: u64,
}
pub enum ShapingMode { Interval }
pub struct ShapingSpec {
    pub mode: ShapingMode, pub interval_ms: u64, pub jitter_ms: u64,
    pub max_delay_ms: u64,
}
```

Conversion layer (seep-runtime `obfs_config.rs`):
`to_timing_policy(cfg, known_egress) -> Option<TimingPolicy>` /
`to_shaping_policy(...)` -- the same semantics as `to_padding_policy` (shared enabled master switch,
E5 downgrade, default_* vs inline mutual exclusion, nested profile resolution).
`TimingPolicy::matches` / `ShapingPolicy::matches` are like `PaddingPolicy`.

## 4. Wiring points (landed in M1)

| # | Point | Action |
|---|----|------|
| 1 | new `timing.rs` in `seep-protocols/middleware/` | `TimingMiddleware`: decide inside handle (deterministic by hash) -> annotation `seep.obfs.timing` -> sleep(d). The pure decision function `decide_timing` is pinned by unit tests for range/determinism/gate clamping |
| 2 | new `shaping.rs` in `seep-protocols/middleware/` | `ShapingMiddleware`: decide -> annotation `seep.obfs.shaping` -> wrap `flow.io` (`PacedWriter`: sleep until the grid point before a write, seq increments). The `decide_shaping_delay` pure function + `PacedIo` unit tests pin >= interval |
| 3 | `obfs_config::build_middleware_chain` | add timing/shaping to the whitelist and construct the matching middleware (selector closures of the same shape) |
| 4 | config validate | extend the §3.3-5 text to four names; the TimingBlockConfig/ShapingBlockConfig validate E2 matrix |

## 5. Control plane

No new endpoints or metric families (D-7). The existing `MIDDLEWARE_INVOCATIONS` on `GET /metrics`
automatically collects the two invocation names `timing`/`shaping`.

## 6. Errors and boundaries

- E1..E5 follow P1-4 §3.3/§6 with the same semantics (enabled=false short-circuit,
  mutual exclusion/both absent, E3 missing reference, E5 apply_to=egress:ghost downgrade to Ok(None));
- the E2 matrix is extended: timing mode in {fixed, uniform}, fixed nonzero, uniform
  min <= max, max_delay_ms >= min_ms; shaping mode = interval, interval nonzero, jitter <= interval,
  max_delay_ms >= interval.

## 7. Test strategy

1. seep-config: timing/shaping block parsing/deny/roundtrip/validate E2 matrix
   (following the padding test series);
2. obfs_config: the two-state matrix of to_timing_policy / to_shaping_policy (enabled
   short-circuit/reference resolution/inline/E5 downgrade/semantics aligned with the symmetric to_padding_policy);
3. timing engine: fixed emitted directly / uniform range + same flow_id determinism +
   gate clamping; middleware handle smoke test (a small max with a real sleep that is perceptible +
   annotation written);
4. shaping engine: grid-point decision (k x interval + jitter, gate clamping); PacedIo
   real measurement (tokio duplex + small interval: three burst write pieces -> adjacent intervals
   >= interval - tolerance, an upper bound on total time);
5. build_middleware_chain: mixed four-name declaration-order assertions.

## 8. Step-by-step implementation

| Step | Content | Acceptance |
|----|------|------|
| M0 | design draft + §3 config mirror + validate E2 + obfs_config conversion + unit tests | the conversion matrix is green; the whitelist text temporarily keeps the three-name set plus a hint (timing/shaping merge once their unit tests drive the conversion green) |
| M1 | §4-1/2/3: the two middlewares + chain wiring + §7-3/4/5 tests | all unit tests on the full link are green; the three §0 wordings are reproducible |
| M2 | wire the profile-game example to a timing demo + documentation backfill (todo/PROTOCOLS/roadmap/landing note in this draft) | the example loading test is green; all gates green |

## 9. Deviations and assumptions

1. **per-chunk jitter on the TCP side != packet-length obfuscation**: timing changes only the
   time distribution, not byte volume, so it is complementary to padding (bytes); the joint
   verification of R-obfs4's "distribution shape feature" analysis is done in M1 with the same
   statistical method (a contrast record of annotation-decision distribution vs frame-byte golden);
2. **conservative semantics of grid normalization**: PacedIo only delays the delivery of a
   **new write** and does not buffer (no extra allocations and no change to flush semantics); the
   write return semantics are unchanged (all bytes end up written, only the timing changes);
3. **read is not normalized** (D-2): the read-side shape is decided by the peer, so there is nothing
   to apply locally; if bidirectional normalization is needed, leave O-p24-1.

## 10. Risks and open items

- **R-p24-1 latency cost misconfiguration**: a large max_delay_ms raises p95 directly -- the §0-3
  gate + the profile-game example values (game = 80ms p95 SLO, startup jitter example taking
  min 0 / max 20 / gate 50) checked against the SLO double gate;
- **O-p24-1 bidirectional shaping**: read-side grid (the peer ignores the local clock; it needs
  ACK-layer pacing, not this step);
- **O-p24-2 UDP-side timing**: per-datagram jitter needs a hop re-encoding hook, added in a separate
  step together with the P0-4 §15 D-15 carrier seam.
