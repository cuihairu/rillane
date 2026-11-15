# Parallel load comparison (RIL-089)

Three load arms over the same instance, the same route (default direct), and
the same loopback wire: game small-packet class alone, web throughput class
alone, and both coexisting in parallel. The full acceptance metric set
(p50/p95, jitter, effective loss, TTFB, throughput, CPU/RSS, repetition
rounds) is printed per round.

**Honest scope**: numbers are debug-build measurements over loopback
(measurement tool: `cargo test -p rillane-runtime --test
parallel_load_benchmark -- --nocapture --test-threads=1`); "same node/wire"
means the same rillane instance and the same loopback targets, not a real
external wire. Release builds are faster. The scheduling policy (RIL-025 fair
scheduler) is not wired into the egress send loop yet, so the policy
comparison runs as a deterministic replay at the decision layer (second half
of this report) — re-measure end-to-end policy gains once the wiring lands.
Pool-optimization comparison is separate and does not block the core policy
measurement.

## End-to-end three-arm comparison (same instance: SOCKS5 ingress → default direct → loopback echo targets)

Load shape: game arm = 4 sessions × 200 pings of 100 B; web arm = 4 sessions
× 2 MiB echo streams; parallel arm = both classes carried at once, repeated
for 5 rounds. Sample volume: 800 game RTT samples per round; 8 MiB web
payload per round.

| Arm/round | game p50 (ms) | game p95 (ms) | jitter (ms) | loss/attempts | web TTFB p50 (ms) | web throughput (MiB/s, worst session) |
|---|---|---|---|---|---|---|
| game alone | 0.37 | 0.43 | 0.04 | 0/800 | — | — |
| web alone | — | — | — | 0 | 5.9–11.8 | 89.9–108.1 |
| parallel [0] | 0.40 | 0.66 | 0.10 | 0/800 | 5.5 | 19.7 |
| parallel [1] | 0.37 | 0.49 | 0.12 | 0/800 | 12.3 | 32.1 |
| parallel [2] | 0.33 | 0.50 | 0.12 | 0/800 | 11.8 | 31.6 |
| parallel [3] | 0.37 | 0.67 | 0.12 | 0/800 | 9.2 | 34.4 |
| parallel [4] | 0.33 | 0.52 | 0.12 | 0/800 | 6.1 | 32.1 |

Process overhead during the parallel phase (measuring-process scope):
CPU ≈ 102% (core-equivalent, CLK_TCK=100); RSS delta ≈ 6 MiB (bounded, does
not grow with rounds).

**How to read this**: under coexistence, game p95 stays sub-millisecond
(0.49–0.67 ms against the 0.43 ms alone baseline) with zero effective loss;
web throughput drops from ≈90–108 MiB/s alone to ≈20–34 MiB/s — coexistence
interference is real and lands on the throughput side, not the latency side.
That is exactly the allocation face the fair scheduler (RIL-025) is meant to
take over: throughput gives up bandwidth headroom while the latency class
keeps a bounded tail.

## Scheduling policy comparison (deterministic replay, decision layer)

Shape: 16 KiB round window, 3 KiB latency budget (clamped to
[1 KiB, 8 KiB]), 5 ms round tick; load: one sustained 64 KiB download plus
one 100 B game packet per round.

| Metric | fair scheduler (RIL-025) | FIFO first-come |
|---|---|---|
| game wait p50 / p95 | 0 / 0 ms | 0 / 10 ms |
| download completion round | 4 | 3 |
| per-round served bytes | full round | full round |

- The fair scheduler pins the game tail inside one round (head-first with a
  byte budget); under FIFO the small packets queue behind download chunks
  (p95 = one chunk's round-splitting time). The throughput deficit is
  bounded (completion rounds differ by ≤ 2) — latency priority consumes
  budget bytes, never the whole round.

## Fallback and no-benefit conditions

- **Fallback (fair → FIFO-equivalent)**: with no latency-class traffic, the
  fair scheduler's per-round served bytes are identical to FIFO and the
  throughput completion round is the same (work-conserving — no latency
  traffic means no scheduling difference and no overhead difference).
- **No benefit (budget auto-lowers)**: when game RTT already meets target
  (rtt_p95 below half the target), `adapt_latency_budget` only lowers the
  budget, clamped at the declared minimum — never over-allocates for the
  latency class; steps are auditable (sum of applied steps = final −
  initial).
- **Fallback (scenario switching stays put)**: unknown current score
  (insufficient samples), no candidates, and unknown candidate score all
  stay on the current selection — missing data never triggers a blind switch
  (RIL-027); SLO never fabricates compliance.

## Measurement tool and guards

`crates/rillane-runtime/tests/parallel_load_benchmark.rs` prints the tables
above and pins conservative bounds: zero effective loss under parallel load,
game p95 < 1 s (starvation guard), web ≥ 1 MiB/s per session (anti-starvation
guard), RSS delta < 128 MiB (unbounded-residency guard) — a starvation or
unbounded-residency regression fails on any machine. Policy replay asserts:
fair game tail ≤ one round, FIFO baseline ≥ one round, per-round equality
when no latency traffic exists, and stays-put on missing data.
