# P3-5 Zero-copy / Batched I/O (implementation-level design)

> Upstream: [todo.md](../../todo.md) P3-5 (2026-09-30 downgraded registration from the PROTOCOLS.md
> "performance optimization" section)
> the performance section of [PROTOCOLS.md](../PROTOCOLS.md).
> This document is the landing finalization: **scope rulings (splice/recvmmsg out of scope), process-level relay
> buffer parameter,
> frame-write vectorization, benchmark plan, step checklist**. Deviations are backfilled into section 7 after
> landing.
> **Status: R0-R4 all landed** (2026-10-05. R1: seep-core `performance`
> module + seep-config `performance:` block + RuntimeBuilder wiring + 16
> relay points on `copy_bidirectional_with_sizes`; R2: `write_frame`
> vectorized + short-write advance + ShortWriter dedicated tests; R3: criterion
> benches actually run, numbers in the section 5 results table; R4: the
> PROTOCOLS.md performance section backfilled as "implemented (scoped)" +
> todo.md P3-5 checked off).

## 0. Scope and acceptance criteria

**todo original text**: the zero-copy and batch-processing descriptions in the PROTOCOLS.md "performance
optimization" section are ahead of the implementation with no near-term landing plan, and are downgraded from a
"design stance" to this registration item. **Acceptance original text**: at landing, back up the
throughput/latency gains with benchmark tests, and backfill the PROTOCOLS.md performance section status (the
"async I/O implemented" line is retained).

**Testable criteria (explicitly rewritten)**:

1. **Configurable relay buffer**: the TCP relay bidirectional buffer size is configurable via
   `performance.relay_buffer` (process-level, set at startup); default None = 8192 x 2 preserves current
   behavior, zero difference for existing traffic;
2. **Combined frame write**: the mesh `[len][payload]` frame write changes from two `write_all` calls to a
   single `write_all_vectored` submission -- plaintext TcpStream segments in one syscall; TLS segments have no
   vectored implementation in rustls and automatically fall back per segment (behavior no worse than the status
   quo);
3. **Benchmark evidence**: criterion benches -- loopback TCP relay throughput across 8K/32K/64K/256K buffers
   (simulating BDP scenarios), plus a two-segment vs vectored frame-write comparison; the result numbers are
   backfilled into section 6 of this document and synced to the PROTOCOLS.md performance section (an
   "implemented (scoped)" stance, with out-of-scope items honestly documented as not done).

## 1. Current state and structural constraints

- All TCP relay goes through `tokio::io::copy_bidirectional`: 12 sites in seep-protocols egress
  (direct/socks5/http x 3/trojan x 2/ss/hysteria2/vless x 2/wireguard) + 3 sites on the seep-runtime mesh plane
  (`mesh_transport.rs:1419/1481` and dial_and_tunnel) -- a fixed internal tokio 8192-byte x bidirectional
  userspace copy loop;
- **No config channel for connectors**: the `EgressConnector::forward(&self, Flow)` signature has no runtime
  parameters (seep-core lib.rs:766) -- passing parameters per connector would touch 12+ implementations and the
  trait; the same for `IngressEndpoint`;
- The mesh frame write `write_frame` (mesh_transport.rs:1961) = `write_u32(len)` + `write_all(payload)`, two
  writes -- two syscalls on plaintext segments, two record wrappings on TLS segments;
- `MAX_HEADER_BYTES = 64 KiB` (including the pad upper bound) -- the frame body is at most 64 KiB+pad, and a
  per-frame pre-concatenated whole-buffer approach would add up to 64 KiB of extra memcpy, so it is not taken
  (two-segment vectored zero-copy submission, see D-2);
- **No real vectored on TLS segments**: rustls 0.23 `TlsStream` does not implement `poll_write_vectored`
  (`is_write_vectored()=false`), and tokio `write_all_vectored` automatically falls back to per-segment
  `write_all` for such streams -- behavior equivalent to the status quo;
- The production mesh data plane mandates mTLS (dev only via `SEEP_MESH_ALLOW_PLAINTEXT=1`), and TLS-family
  egress protocols make up the majority -- **the plaintext direct-connect segment (socks5/http in ->
  direct/socks5 out) is the main beneficiary of vectorized writes and large buffers**.

## 2. Design decisions

- **D-1 Process-level relay buffer parameter (AtomicUsize)**: a new `performance` module in `seep-core` --
  `set_relay_buffer(usize)` (once at startup, only allowed to change away from the default; tests may reset) +
  `relay_buffer() -> usize` (default `DEFAULT_RELAY_BUFFER = 8192`). The 15 relay points switch to
  `tokio::io::copy_bidirectional_with_sizes(io_a, io_b, n, n)`. Rationale for process-level rather than
  per-connector parameters: the trait has no config channel (section 1), and the relay buffer has no per-egress
  differentiation need (BDP is determined by the path, not the egress type); precedent is the P1-5 pool/factory
  process-level singleton (egress-connection-pool.md D-10).
- **D-2 Vectorized frame write**: `write_frame` changes to `stream.write_all_vectored(&mut
  [IoSlice::new(&len_be), IoSlice::new(payload)])` -- streams where `is_write_vectored()` is true (TcpStream)
  submit in one syscall; false (rustls) falls back per segment with zero rollback cost. The 4-byte header from
  `write_u32` is carried by a stack array `len_be`, with no heap allocation.
- **D-3 splice out of scope**: kernel-side zero-copy (splice/tee) only applies to "plaintext<->plaintext with
  both ends as real fds" segments -- this repo's flow.io is wrapped by the FlowMiddleware chain (P1-4
  padding/timing/shaping are AsyncRead/Write wrappers that break splice semantics) and TLS segments dominate,
  and tokio does not expose splice either (needs nix + self-managed fds, conflicting with tokio's registration
  mechanism). Narrow beneficiary surface, high engineering risk -- out of scope, documented in section 7.
- **D-4 UDP recvmmsg/sendmmsg out of scope**: the UDP plane uses per-packet `recv_from`/`send_to`, one syscall
  per datagram, and batched I/O would need recvmmsg/sendmmsg (direct libc calls + tokio managed-fd compatibility
  is complex); current acceptance packet rates (ping-level on the AVD emulator) are several orders of magnitude
  from the syscall bottleneck, with no evidence justifying the added complexity -- out of scope, documented in
  section 7; re-evaluate on a benchmark basis once a real high-packet-rate scenario appears.
- **D-5 Default zero difference**: the `performance` block is default-unset (`Option`), the relay buffer
  defaults to 8192 = current behavior; with no config the whole-path byte behavior is unchanged.
- **D-6 Observability**: no new metric family -- the relay buffer is a static config shape; benchmark results go
  into section 6 of this document (static numbers).

## 3. Data structures and wiring points

```rust
// seep-core/src/performance.rs (new)
pub const DEFAULT_RELAY_BUFFER: usize = 8192;
static RELAY_BUFFER: AtomicUsize = AtomicUsize::new(DEFAULT_RELAY_BUFFER);
pub fn set_relay_buffer(n: usize) -> Result<()>;   // invalid values (0 / over upper bound) error
pub fn relay_buffer() -> usize;                    // read by all relay points
```

```rust
// seep-config: new top-level block (deny_unknown_fields, Option default)
pub struct PerformanceConfig {
    pub relay_buffer: Option<u32>,   // bytes; 8192..=1 MiB validation
}
```

| # | Point | Action |
|---|----|------|
| 1 | 12 seep-protocols egress sites + 3 mesh_transport sites | `copy_bidirectional` -> `copy_bidirectional_with_sizes(n, n)` (D-1) |
| 2 | `mesh_transport::write_frame` | vectored two-segment combination (D-2) |
| 3 | `runtime_builder` | read the `performance:` block -> `set_relay_buffer` (once at build time) |
| 4 | seepd config schema pass-through | `PerformanceConfig` enters the `SeepConfig` top level |

## 4. Errors and boundaries

- E1 invalid `relay_buffer` value (0 or > 1 MiB): seep-config validate errors with the original value
  (network/obfs precedent); `set_relay_buffer` performs the same error as second-line defense;
- E2 vectored fallback: rustls segment behavior = the current two-segment write (section 1), no regression
  surface;
- E3 memory cost of raising the buffer: 2 x n bytes per flow -- the 1 MiB upper bound x thousands of flows = a 2
  GiB extreme upper bound, the docs note estimation by concurrency (default 8192 unchanged);
- E4 frame-write header 4 bytes `payload.len() as u32` overflow: the `MAX_HEADER_BYTES` 64 KiB upper-bound check
  runs first (already present in the status quo), vectorization does not move the check position.

## 5. Benchmark plan (criterion, `benches/`)

- `relay_throughput`: local loopback TCP dueling -- one end `tokio::spawn`s to push N MiB, the relay task relays
  with the specified buffer, and throughput is measured; control groups 8K/32K/64K/256K; plus a "simulated BDP"
  group (a serialized 64 KiB with a `tokio::time::sleep` latency injected between two tokio tasks? No -- latency
  injection would distort the benchmark, so instead use large-payload unidirectional bulk writes to measure the
  amortization effect), results in MiB/s;
- `write_frame`: two-segment write vs vectored comparison (plaintext TcpStream loopback), two groups of 4 KiB/64
  KiB payload;
- Output: screenshot-style criterion numbers are backfilled into the section 6 table; benchmarks are not in the
  CI gate (run locally, high-noise environments are unstable and are not judged in CI).

**Results (2026-10-05 actual runs, median over multiple rounds)**. Actual-run landing points:
`seep-core/benches/{relay_throughput,write_frame}.rs`; one iteration of the relay group = 32 MiB unidirectional
bulk write relayed through `copy_bidirectional_with_sizes` and drained to completion; one iteration of the
frame-write group = 2048 frames written consecutively, with the read end draining the full volume to
convergence. The environment is a shared multi-session dev machine (load avg 19-45 during benches), so
run-to-run variance is significant, hence 3-4 rounds per configuration with the median taken; the numbers only
represent same-round relative comparisons, not absolute throughput commitments (section 7.4).

relay throughput (32 MiB unidirectional, multi-round median):

| Buffer | 8192 | 32768 | 65536 | 262144 |
|------|------|-------|-------|--------|
| Iteration time | 149 ms | 122 ms | 112 ms | 96 ms |
| Throughput | 214 MiB/s | 263 MiB/s | 286 MiB/s | 357 MiB/s |

8K->256K median throughput +67%; the direction and magnitude of syscall amortization from raising the buffer
reproduce stably.

Frame-write comparison (2048 frames/iteration, multi-round median):

| Write mode | 4 KiB payload | 64 KiB payload |
|------|---------------|----------------|
| Two-segment `write_all` | 33.8 ms / 243 MiB/s | 206.9 ms / 620 MiB/s |
| vectored combined | 25.3 ms / 318 MiB/s | 217.4 ms / 589 MiB/s |

4 KiB frames: vectored is about 26% faster at the median (up to 2.2x in quiet rounds, winning 3 of 4 rounds); 64
KiB frames are the same order of magnitude for both (about 5% apart, overlapping confidence intervals, judged no
regression) -- for large frames the syscall count share trends to zero, consistent with the section 2 D-2
expectation of "plaintext segments gain, TLS segments fall back equivalently"; TLS-segment equivalence is
guaranteed by the existing frame tests and the ShortWriter short-write dedicated tests.

## 6. Step-by-step implementation checklist

| Step | Content and landing points | Acceptance |
|----|-----------|------|
| R0 | This design draft | -- |
| R1 | seep-core `performance` module + seep-config `performance:` block (validate E1) + runtime_builder/seepd wiring + 15 relay points switched to `copy_bidirectional_with_sizes` + unit tests (set/get, invalid values, default zero difference) | all gates green; with no config, behavior matches the status quo byte for byte |
| R2 | `write_frame` vectorized + zero regression on existing frame tests | all mesh frame tests green |
| R3 | criterion benches (the two section 5 groups) + actual runs + numbers backfilled into the section 5 results table of this document | benchmarks produce real numbers (landed, see the section 5 results table) |
| R4 | PROTOCOLS.md performance section backfill ("implemented (scoped)" + out-of-scope item registration) + todo.md P3-5 checked off + this document's status line | docs aligned with the implementation (landed) |

## 7. Deviations and assumptions

1. **"Zero-copy" downgraded to "reduced copies/reduced syscalls"**: streaming relay in a userspace proxy cannot
   eliminate userspace copies (TLS termination, middleware chain semantics); this item delivers syscall
   amortization (large buffers) and vectored combined submission, with splice ruled out of scope (D-3);
2. **"Batch processing" downgraded to "UDP batched I/O out of scope"** (D-4): no evidence of a high-packet-rate
   scenario, so no direct libc-call complexity is introduced;
3. The relay buffer is a single process-level value (D-1) -- per-egress differentiation is left to a real need;
4. Benchmarks run on a dev machine loopback, and the numbers represent this machine's relative comparison rather
   than an absolute throughput commitment;
5. criterion is in dev-dependencies, and `benches/` is not in the CI gate (section 5).
