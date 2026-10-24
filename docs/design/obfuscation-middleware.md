# P1-4 Obfuscation middleware MVP (padding) -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) S3 · [positioning.md](positioning.md) §2.4 (obfuscation cross-cutting layer) and §2.5 (policy differentiation) · [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) §3 (item three) and §5.5 ("the real prerequisite of P1-4 is building a mount point, not writing a middleware").
> This document is the landed finalization: **mount-point shape, padding policy and config schema, integration with the existing middleware/egress chain, error paths, test strategy, step-by-step checklist**. Deviations are backfilled into §9 after landing.
> Reuse baseline: `FlowMiddleware` trait (`seep-core/src/lib.rs:234-238`) · `FlowOutput`/`FlowOutputRouter` (`seep-core/src/lib.rs:230-232` / `seep-runtime/src/runtime_builder.rs:1227`) · annotation injection precedent `seep.chain.path` (`runtime_builder.rs:1308`) · `UdpConfig` mirror type + runtime conversion precedent ([udp-dataplane.md](udp-dataplane.md) §5.2) · new-block `deny_unknown_fields` targeted closure precedent ([network-route.md](network-route.md) §1.5) · `MeshEnvelope` (`mesh_transport.rs:165-176`).

## 0. Scope

| In this item | Belongs to other items |
|-----------|-----------|
| **Static middleware pipeline** (C1 closure: registry + single call site + ordering semantics) | Dynamic loading (WASM/dynamic-library loader and isolation) = P3-2, extended on this pipeline |
| Padding policy engine (three modes + cap protection) and `PaddingSpec` codec | timing / shaping policy = P2-4 (reuses this pipeline and spec mechanism) |
| The **frame execution side** carrier of padding (MVP = chain's `MeshEnvelope` frame) | TLS fingerprint emulation = P2-5; mesh envelope binarization = P2-6 |
| `obfuscation:` config block (seep-config mirror + runtime conversion) + profile switch | `proxy`/`game`/`web` three scenario presets = P2-3 (composed on this schema) |
| `seep_obfs_*` metrics + tests + statistical verification wording | global takeover / system routing = P1-3; TUN ingress = P1-2 |

**Acceptance-wording preamble (aligned with P0-3's explicit-rewrite practice, no silent shrinking)**: todo P1-4 acceptance "after enabling, the statistics script shows the **egress packet-length distribution** deviating from the default distribution" cannot be literally achieved on the TCP side -- on-the-wire segmentation of a TCP byte stream is decided by the kernel, and a user-space middleware cannot reshape "packet" boundaries (detailed in §2.1). The measurable equivalent wording for this item is:

1. The on-the-wire byte-length distribution of **seep's own frames** shifts per policy -- MVP frame = chain-path `MeshEnvelope` frames (real wire bytes, verifiable by packet capture);
2. Single-hop TCP egress has no own frame -> the middleware decision **can** be produced (visible in annotations) but **produces no padding bytes** (no-op bypass, countable);
3. **UDP-side per-datagram padding** (the main battlefield against game QoS) lands with the P0-4 §2 `UdpEnvelope` frame carrier -- that frame is naturally "one datagram = one controllable byte boundary", which is where padding truly comes into play; this item reserves the same `PaddingSpec` and execution hook for it (§2.3, §4.4).

## 1. Mount point: static middleware pipeline (C1 closure)

### 1.1 Current state (verification conclusion, not a restatement)

- `FlowMiddleware { name(); async handle(Flow) -> Result<Flow> }` (`seep-core/src/lib.rs:234-238`) -- S0 "trait unchanged" holds;
- **Zero consumers**: no code anywhere in the repo calls `FlowMiddleware::handle`, and no location constructs `LatencyProbe` (other than the definition and re-export); the `ingress -> FlowRouter -> FlowOutputRouter -> egress` path has **no registry/pipeline/call site** (status-audit §3, C1);
- Therefore the first thing this item does is not to write padding, but to **build the static mount point** -- the common base of padding/timing/shaping (status-audit §5.5).

### 1.2 `MiddlewareChain` (new minimal surface in seep-core)

```rust
// seep-core/src/lib.rs (same file and family as the trait, no new crate)
#[derive(Clone, Default)]
pub struct MiddlewareChain {
    inner: Arc<Vec<Arc<dyn FlowMiddleware>>>,   // static chain: ordered at build time, read-only at runtime
}

impl MiddlewareChain {
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    /// Execute in order; abort as soon as any middleware returns Err (error bubbles up, semantics in §6 E8)
    pub async fn run(&self, flow: Flow) -> Result<Flow> {
        let mut flow = flow;
        for mw in self.inner.iter() {
            flow = mw.handle(flow).await?;      // borrow check: Arc cloned once, iteration lock-free
        }
        Ok(flow)
    }
}
```

- **Static** (`Arc<Vec<..>>`) rather than `RwLock<Vec<..>>`: MVP has no runtime registration need (P3-2 changes the container later if hot-plugging is needed, the trait stays untouched); read-only sharing has zero lock overhead;
- `LatencyProbe` can enter the chain as-is (its implementation already satisfies the trait, no change needed).

### 1.3 Call site: `FlowOutputRouter::forward` (the single double-dispatch point)

Reason for this choice (verifiable): `forward` (starting at `runtime_builder.rs:1258`) is the only place in the data path that **holds both `decision` and `flow`**, and it is the fork point of chain/single-hop dispatch (`forward_chain` / `forward_single`). Hooking there completes three stages in one call:

```
forward(decision, flow):
  (1) context annotation injection (§1.4) -- project the decision info into middleware-readable annotations
  (2) middleware_chain.run(flow)  <- new call site; when disabled, is_empty() skips directly
  (3) match &decision.path { Chain => forward_chain(..), _ => forward_single(..) }
```

- chain and single-hop **share the same injection point**, no wiring needed in two places;
- same family as the existing `seep.chain.path` injection (`runtime_builder.rs:1308`): both are carrier-side writes into annotations;
- the ingress side gets **no** second mount point: the positional semantics of positioning §2.4 is "both sides of the egress transport layer", and MVP takes "before egress" (decision made, egress not yet connected) -- one point covers all three scenarios; the ingress side is deferred until there is a real need (recorded in §10 open items).

### 1.4 Context annotation contract (carrier -> middleware one-way information flow)

`FlowMiddleware::handle(Flow)` sees only the `Flow` (no `decision` parameter, the trait is unchanged). Therefore **the carrier projects the decision into annotations**; middleware only reads annotations and only writes its own spec annotation:

| Annotation key | Writer | Value | Purpose |
|---------|-------|----|------|
| `seep.route.kind` | (1) (carrier) | `"chain"` / `"single"` | for selectors like `apply_to: chain` to discriminate |
| `seep.route.egress` | (1) (carrier) | `decision.final_node()` (including `egress.` prefix stripping, same wording as `forward_single`) | for `apply_to: egress:<name>` to discriminate |
| `seep.route.reason` | existing (`forward_chain`) | decision reason | unchanged for now |
| `seep.chain.path` | existing (`forward_chain`) | path JSON | unchanged for now |
| `seep.obfs.padding` | (2) (padding middleware) | `PaddingSpec` JSON | output: for the frame execution side to read (§2.2) |

- Annotations are **one-way**: middleware only adds/overwrites its own `seep.obfs.*` keys and never touches carrier keys (to keep middlewares from stepping on each other);
- key names under the `seep.` namespace are consistent with `geoip.country`/`client.cidr` (the precedent of `seep-routing::matches_rule` reading annotations) / `seep.chain.path`;
- this contract is what makes **zero trait changes** possible: a new policy (P2-4 timing) only needs to add its own key and the execution-side reading of it.

### 1.5 Ordering semantics and relation to P3-2

- **Declared order in the chain is execution order**, decided by the `obfuscation.middleware` config array (§3.1); during the P1-4 MVP there is only one implementation, `padding`, so order carries no real meaning, but the contract is pinned first -- once P2-4 lands `timing`/`shaping`, this contract is already consumed (the built-in chain is assembled in array order);
- P3-2 dynamic loading = a loader on top of this static chain: the `Vec<Arc<dyn FlowMiddleware>>` of `MiddlewareChain` is populated by the loader (native dynamic library/WASM adapters implementing the same trait); **this item introduces no dynamic-loading dependency** (the workspace currently has no `libloading`/`wasmtime`/`wasmer`, verified).
- **Landing note (2026-10-04, P3-2 landed)**: the trait promise is honored -- `WasmPluginMiddleware` implements the same `FlowMiddleware` trait (`name()` fixed to `&'static str` via `Box::leak`; the trait signature in this section stays unchanged, the promise is honored); the vehicle is WASM-only by ruling (`crates/seep-plugins`, wasmtime), chain order = built-in `middleware` declaration order + `plugins` declaration order, see [plugin-loader.md](plugin-loader.md) §1.5/§2.3.

## 2. Padding policy (policy/execution separation)

### 2.1 Design tension and ruling

- The input of `FlowMiddleware::handle` is `Flow{ io: Box<dyn IoStream>, .. }` -- **stream semantics**: `IoStream = AsyncRead + AsyncWrite` (`seep-core/src/lib.rs:18-22`), no message boundary;
- padding is a **frame-semantics** problem ("pad this packet to N bytes"); "padding" is undefined on a boundary-less byte stream -- the padded bytes would be taken as payload by the peer, and on-the-wire TCP segmentation is decided by the kernel, so user-space padding does not change the packet-length distribution;
- **Ruling: policy/execution separation**. No new trait, no change to the `handle` signature:
  - **Policy side** (middleware): based on `flow.target` + the §1.4 annotations, `handle` decides "whether this stream is padded and in what form", and writes the result as a `seep.obfs.padding` annotation; it **never touches `io`**;
  - **Execution side** (frame carrier): the carrier reads that annotation at the place where it owns byte boundaries (after `forward_chain` serializes the frame, before writing to the wire) and applies the padding;
  - where there is no own frame (single-hop TCP) -> the execution side is absent -> no-op (§2.3), **no fake implementation**.

This ruling also explains why positioning §2.4's padding can only have limited effect under the current TCP-only state, while P0-4's UDP side (`UdpEnvelope` frame) is its home ground.

### 2.2 `PaddingSpec` and the three modes

```rust
// seep-core (same file as the annotation contract; serde-serialized into the annotation, so core does not depend on runtime)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaddingSpec {
    pub mode: PaddingMode,          // Fixed | Bucket | Range
    pub target: usize,              // Fixed: target length; Bucket: bucket step (see below); Range: ignored
    pub buckets: Vec<usize>,        // Bucket: candidate buckets (ascending, non-empty)
    pub min: usize,                 // Range: lower bound
    pub max: usize,                 // Range: upper bound
    pub max_overhead_ratio: f32,    // protection cap (§2.6)
}
```

| Mode | Semantics | Computation | Applies to |
|------|------|------|------|
| `fixed` | always pad to a fixed length | `len' = target` (if `len > target`, do not pad, count it) | smoothest shape, highest overhead; heartbeat-like small packets |
| `bucket` | align to the nearest upper-bound bucket | `len' = min{ b in buckets : b >= len }`; if no usable bucket, do not pad | distribution clusters into a few shapes, overhead controllable (aligns to common application fingerprints) |
| `range` | pseudo-random length falling into `[min,max]` | `len' = max(len, min + hash(flow_id, frame_seq) % (max-min+1))` | scatters the mode, avoiding "fully aligned" itself becoming a new feature |

- **Determinism**: the random source of `range` = `hash(flow_id, frame sequence number)`, not a real RNG -- tests are reproducible, no `seed` config item needed (`seep-protocols` already has a `rand` dependency, but for reproducibility it is **not used**);
- `frame_seq` is provided by the execution side's **per-frame incrementing** self-counter (within the same stream), so multiple frames of the same stream get different lengths (avoiding a constant length).
- The selector ("which streams get padded") is not part of `PaddingSpec`; it belongs to the config layer (§3.1 `apply_to`) and is fixed when the middleware is constructed.

### 2.3 Execution side: frame inventory (MVP boundary)

| Frame carrier | Exists | MVP handling |
|--------|---------|---------|
| chain's `MeshEnvelope` frame (at the P1-4 timepoint, JSON + 4-byte length prefix; after P2-6, binary, with `pad_len` moved into the binary header) | existing | **implemented by this item**: pad per spec after serialization + write `pad_len` (§2.4; P2-6 migration is lossless, golden carried over) |
| UDP datagram (P0-4 §2 `UdpEnvelope` binary frame) | carrier ready (P0-4 S5 landed), padding execution hook not wired | reserved execution hook + same `PaddingSpec`; ruling in udp-mesh-dataplane.md D-15 (§4.4) |
| single-hop TCP egress payload | no own frame (each protocol does its own encapsulation, seep holds no boundary) | **no-op**: the middleware may produce a spec annotation, but the execution side has no carrier -> no padding bytes produced, `skipped_total{reason="no_frame"}` counted |
| TUN ingress IP packets | P1-2 data plane landed, padding not wired | its downlink IP/UDP packet construction points are the same family as the UDP frame, to be reused then (§10 open item) |

**Acceptance-wording landing point**: the measurable "egress packet-length distribution shift" = chain frames (packet capture / measuring frame lengths); the shift for single-hop TCP is not borne by this item (explained in §0); the shift for game UDP depends on the §4.4 hook being wired (not wired at present).

### 2.4 `MeshEnvelope` padding codec and version gate

> **State after P2-6 landed (2026-10-02)**: the TCP-side envelope has switched to binary (magic `SU` + `MESH_ENVELOPE_BIN_VERSION=2` header), `pad_len` is a 4-byte BE field at the tail of the binary header, the execution function is `pad_envelope_frame` -- the rest of this section is written against the JSON frame form at the P1-4 timepoint; the mechanism (tail padding + pad_len declaration + version gate) is isomorphic under both encodings, and the golden semantics are unchanged.

- Frame format (P1-4 timepoint) = `[len: u32][json]` (`MeshEnvelope{version, flow_id, target_host, target_port, path}`, starting at `mesh_transport.rs:174`);
- padding = the JSON gets **tail padding bytes** appended + a new **optional field** `pad_len: u32` inside the JSON (default 0; a new serde field is an unknown field to an old peer):

```
padded frame = [len: u32 covering (json_bytes incl. pad_len=K) + K padding bytes][json][K bytes 0x00]
receiver     = read json.pad_len = K -> trim K bytes from the frame tail -> deserialize to get the payload
```

- **Version gate (mandatory, cannot be omitted)**: an old-version receiver does not recognize `pad_len` and would treat the tail padding as the JSON tail -> parse failure or abnormal behavior. Hence:
  - padding is **enabled only when both ends of the link run a supporting version (seep >= this item's landing version)**; the `MeshEnvelope.version` field already exists, and the implementation uses its value for capability discrimination (the exact version number is decided at implementation time, aligned with §9-4);
  - when the peer version cannot be confirmed, do not pad (`skipped_total{reason="peer_version"}` counted), **connectivity takes priority over camouflage** (fail-open, §6 E6);
  - MVP simplification: by default assume same-version deployment (same release batch); for mixed-version deployment, "disable padding" is the safe default, recorded as a §10 risk.
- Padding byte content: MVP = `0x00` (byte-level length camouflage, not content camouflage); a failed consistency check between `pad_len` and the frame length -> discard the frame + count (§6 E7).

### 2.5 Zero-overhead bypass when disabled

- `obfuscation.enabled=false` (the **default**) -> no middleware constructed at build time, `MiddlewareChain::default()` (empty `Arc<Vec>`);
- at `forward` stage (2), `if chain.is_empty() { skip }` -- a single branch, no lock, no allocation, no async call;
- when disabled, the two carrier annotations of §1.4 are **not injected** (saving two `BTreeMap::insert` calls): annotation injection is itself a prerequisite of the padding execution side, so the disabled path skips it as well (tests assert the annotations' absence = zero side effects, §7.1);
- existing configs (no `obfuscation:` block) have **zero behavioral difference** -- following the `UdpConfig` default pattern (serde default).

### 2.6 Overhead protection

- `max_overhead_ratio` (default 0.5): if `len' > max(len * (1+ratio), min)`, then **do not pad** + `skipped_total{reason="overhead_cap"}`;
- rationale: bucket/range on small packets (e.g., a 60B heartbeat aligned to 1024) causes significant bandwidth amplification; in high-frequency small-packet game scenarios this is a real cost, so there must be a cap;
- the cap is a **policy-layer** semantic (decided by the middleware, which gives up before writing the spec); the execution side just follows the spec (no second judgment).

## 3. Profile switch schema (seep-config mirror + runtime conversion)

### 3.1 Block shape

```yaml
obfuscation:
  enabled: false                   # master switch; false = zero overhead (§2.5)
  default_padding: game            # references a name in profiles; if absent, use inline padding
  apply_to: chain                  # chain | single | all | "egress:<name>"
  middleware: [padding]            # declares chain order (may list padding/timing/shaping, the latter two from P2-4)
  profiles:
    game:                          # named policy set (P2-3's three presets will land here)
      padding:
        mode: bucket
        buckets: [256, 512, 1024]
        max_overhead_ratio: 0.5
    web:
      padding:
        mode: range
        min: 512
        max: 1400
        max_overhead_ratio: 0.3
  padding:                         # inline policy (takes effect when there is no default_padding; mutually exclusive with it, §3.3)
    mode: fixed
    target: 512
```

### 3.2 Mirror types and conversion (ruling: mirror rather than add a dependency)

seep-config has zero dependency on seep-core/platform (deps are only anyhow/serde family), keeping it light: **seep-config defines mirror serde types, seep-runtime adds a `to_padding_policy()` conversion** (same pattern as `UdpConfig` -> `UdpSessionConfig`).

| config mirror type (seep-config) | runtime conversion output |
|-------------------------------|-----------------|
| `ObfuscationConfig { enabled, default_padding: Option<String>, apply_to: ApplyTo, middleware: Vec<String>, profiles: BTreeMap<String, ObfsProfileConfig>, padding: Option<PaddingBlockConfig> }` (the table shows the P1-4-timepoint shape; P2-4 adds `default_timing/timing/default_shaping/shaping`, P3-2 adds `plugins`, see those documents) | constructs `Vec<Arc<dyn FlowMiddleware>>` (P1-4 contains at most one `PaddingMiddleware`; after P2-4/P3-2, assembled per chain) |
| `ApplyTo::{Chain, Single, All, Egress(String)}` | selector closure fixed inside the middleware (matching the §1.4 annotations) |
| `ObfsProfileConfig { padding: Option<PaddingBlockConfig> }` | resolves the selected `PaddingBlockConfig` |
| `PaddingBlockConfig { mode, .. per-mode fields }` | `PaddingSpec` (`mode` string -> `PaddingMode` enum; fields filled after per-mode validation) |

### 3.3 Validation (at build time, `ObfuscationConfig::validate`)

1. `enabled=false` -> all later fields are ignored (no error; half-finished configs are tolerated);
2. `default_padding` and inline `padding` **both present** -> Err (ambiguous); both absent with `enabled=true` -> Err (enabled but no policy);
3. `default_padding` points to a name that does not exist in `profiles` -> Err;
4. `mode` not `fixed|bucket|range` -> Err (E2); for `bucket`, empty or non-strictly-ascending `buckets` -> Err; for `range`, `min > max` -> Err; for `fixed`, `target == 0` -> Err;
5. `max_overhead_ratio < 0` -> Err; `middleware` containing an unknown name (MVP only `padding`) -> Err;
6. `apply_to: egress:<name>` pointing at an egress name absent from the config -> **warning + downgrade to no effect** (not an Err: egress names can come from subscription hot updates and may not be complete at build time, E5).

### 3.4 Compatibility and silent ignoring

- existing configs without `obfuscation:` -> `#[serde(default)]` default, zero behavioral difference (pinned by serde roundtrip tests, same as the `udp` block precedent);
- **add `#[serde(deny_unknown_fields)]` to `ObfuscationConfig`** -- the new block carries no legacy-compatibility burden, and a misspelled sub-field errors immediately (aligned with the B2 targeted closure in [network-route.md](network-route.md) §1.5); the global `SeepConfig` stays lenient (existing configs may carry extra keys).

### 3.5 Boundary with P2-3 scenario presets

- P1-4 delivers the **container semantics** of `profiles` (named policy sets + selection) and two **examples**, `game`/`web`; it does not deliver the "three-scenario complete templates" (the combination of routing rules + scheduling targets + obfuscation switches is P2-3);
- when P2-3 lands it extends fields under `profiles` (e.g., `routing_template`); this document's schema is a **true subset** of that -- no second migration.

## 4. Integration with the existing middleware / egress chain

### 4.1 `LatencyProbe` handling (not mounted by default)

- current state: the only `FlowMiddleware` implementation; `handle` = `sleep(1ms)` then return as-is (`seep-protocols/src/middleware/latency_probe.rs`) -- **pure placeholder semantics**, and `sleep(1ms)` adds 1ms latency to every stream;
- ruling: **not included in the MVP default chain** (adding 1ms latency to the production path is unacceptable); mounted only when the config explicitly says `middleware: [latency_probe]`, for verifying pipeline connectivity (the wiring proof of §8 M1) and debugging;
- its "latency probe" name is unrelated to `seep-routing`'s `latency` group policy (group policy goes through mesh health data); the docs state this explicitly to avoid misuse.

### 4.2 chain-path integration (inside `forward_chain`)

- new execution point: **after** the `MeshEnvelope` is serialized to JSON, **before** writing to the wire via `MeshDataPlane`;
- read `flow.metadata.annotations["seep.obfs.padding"]` -> parse the `PaddingSpec` -> pad per §2.4 and write `pad_len`;
- annotation missing / parse failure -> do not pad (E6/E8 semantics: camouflage is a gain and must not break forwarding);
- frame-length cap: the padded frame <= the TCP envelope's existing cap (64KB, `mesh.md`); if exceeded, do not pad + count (E4).

### 4.3 Single-hop egress integration (hook, MVP no-op)

- `forward_single` can **also read** the annotation, but the MVP has no frame carrier -> no byte rewriting at all; only the §5 metric `skipped_total{reason="no_frame"}` is counted;
- reserved: in the future, if some egress protocol provides its own framing (e.g., VLESS/VMess framed payloads), that egress's write layer becomes the execution point, reusing the same spec -- a hook is left, not implemented (§10 open item).

### 4.4 UDP-side integration (P0-4 §2 = a natural frame)

- P0-4's `UdpEnvelope` (binary header + payload, single packet <= MTU/65507) is the **ideal carrier** for padding: one datagram = one controllable byte boundary, and padding directly affects the packet-length distribution observed by QoS/DPI (the home ground of game acceleration);
- the integration point = the **send path** of the `MeshDataPlane` UDP side in P0-4 §4 (after envelope encoding, before `send_to`), isomorphic to §4.2's chain point;
- this item **only leaves the hook + spec reuse**, without implementing it: when P0-4 lands, its UDP encoder just reads `seep.obfs.padding` -- zero schema change (the same `PaddingSpec`).
- **2026-09-30 revision (P0-4 [udp-mesh-dataplane.md](udp-mesh-dataplane.md) §17-P1-4 / D-15)**: the above "UDP encoder reads the annotation" implied the annotation already exists -- but the annotation production point (§1.3 middleware chain, hung on `FlowOutputRouter::forward`) is only on the TCP Flow path; **the UDP session path (associate -> `UdpRelay::send_to`) has no Flow to hang a chain on**. Ruling: UDP-side spec production changes to **associate session-level evaluation** (reusing `PaddingSpec` and the policy pure functions + the §3.1 selector, decided per session target/egress), not going through `FlowMiddleware::handle` -- the second occurrence of the same cause as §2.1's "the stream signature carries no frame semantics". The execution hook (after encoding, before send_to), the `PaddingSpec` reuse, and the zero-schema-change wording are unchanged; implementation details such as no padding being appended on the re-encoding side are in P0-4 D-16.

### 4.5 Relation to P2-6 envelope binarization

- P2-6 (TCP-side envelope binarization) and this item's `pad_len` field sit **at the same format-finalization point**: if P2-6 lands first, `pad_len` becomes a field in the binary header (semantics unchanged, only the encoding changes); if P1-4 lands first, P2-6's migration carries the field over. The two are **not mutually exclusive and have no hard ordering dependency**, but implementation should align to the same format version (recorded in §10).
- **Timing outcome (P2-6 landed, 2026-10-02)**: the latter branch happened -- P1-4 landed first, and P2-6's migration put `pad_len` into the binary header (`MESH_ENVELOPE_BIN_VERSION=2`), `pad_envelope_frame` switched to binary, and the P1-4 golden was carried over; the conditional reasoning in the paragraph above is retained as a ruling record.

## 5. Metrics (the `seep_obfs_*` family, closed label set)

```
seep_obfs_middleware_invocations_total{name}          # per-middleware invocation count in the chain
seep_obfs_padding_frames_total{mode}                  # frames actually padded (mode=fixed|bucket|range)
seep_obfs_padding_bytes_total{direction="added"}      # cumulative added padding bytes
seep_obfs_padding_skipped_total{reason}               # no_frame | overhead_cap | too_large | peer_version | disabled
```

- labels are all **closed enums** (R11 precedent: no target/flow dimensions, avoiding cardinality explosion); per-link/per-target breakdown belongs to P2-1;
- hooked into the hand-written `/metrics` rendering path (`apps/seepd/src/control_plane.rs`, same family as `seep_udp_*`/`seep_tun_*`; listed alongside the landing points in [udp-observability.md](udp-observability.md) §7);
- `skipped_total{reason}` together with §2.5's zero-overhead assertion forms the observable evidence of "no side effects when disabled/not applicable".

## 6. Error paths

| # | Error point | Condition | Semantics and recovery |
|---|--------|------|-----------|
| E1 | config missing a policy | `enabled=true` with no `default_padding`/inline | build-time Err (§3.3-2) |
| E2 | illegal mode | `mode` not one of the three / illegal parameters (empty buckets, min>max, target=0) | build-time Err carrying the original value (§3.3-4) |
| E3 | policy name does not exist | `default_padding` points to an undefined profile | build-time Err |
| E4 | padded frame exceeds the cap | chain frame > 64KB (or UDP side > 65507) | **do not pad** + `skipped{too_large}`, forwarding continues |
| E5 | `apply_to` points to a nonexistent egress | subscription hot updates make it incomplete at build time | warning + no effect (not an Err, §3.3-6) |
| E6 | peer version unsupported | cannot confirm the link's far end >= this item's version | **do not pad** + `skipped{peer_version}`; connectivity first (§2.4) |
| E7 | padded-frame check failure | receiver-side `pad_len` does not match the frame length | discard that frame + count (never hand a bad frame to the upper layer) |
| E8 | middleware returns Err | any `handle` failure | chain `run` aborts, the error bubbles up to `forward` -> forwarding fails (no silent continuation; no MVP middleware can actually fail) |
| E9 | spec annotation parse failure | annotation present but invalid JSON/fields | treated as no spec -> do not pad (the camouflage layer must not break forwarding) |
| E10 | overhead exceeds the cap | `len' > max(len*(1+ratio), min)` | policy layer gives up + `skipped{overhead_cap}` (§2.6) |
| E11 | disabled path | `enabled=false` | not an error: chain empty, annotations not injected, zero allocation zero lock (§2.5) |

## 7. Test strategy

### 7.1 Unit tests (no privileges, any environment)

- **policy engine** (pure functions, `PaddingSpec` -> `(len', Option<pad_len>)`):
  - `fixed`: `len <= target` pads to `target`; `len > target` does not pad;
  - `bucket`: `len` exactly on a bucket does not pad; a bucket gap takes the nearest upper bound; beyond the largest bucket does not pad; buckets-ascending invariant;
  - `range`: result falls in `[max(len,min), max]`; **same flow_id + same frame sequence number is reproducible** (determinism assertion); different frame sequence numbers give different values;
  - `max_overhead_ratio`: a small packet aligned to a large bucket gives up padding (E10 assertion) + counted;
- **`PaddingSpec` codec**: JSON roundtrip; illegal JSON yields E9 semantics (no padding);
- **`MeshEnvelope` pad/strip**: after padding, `pad_len` matches the frame length; after stripping, the payload is **byte-for-byte equal** (golden vector); the `pad_len=0` (unpadded) path is byte-identical to the old behavior;
- **`MiddlewareChain`**: an empty chain's `run` returns directly (zero-invocation assertion: mock middleware count = 0); ordering (two mocks record execution order); `Err` aborts without running the rest; `is_empty()` bypass (§2.5);
- **carrier annotation injection**: a `chain` decision -> `seep.route.kind=chain` + `seep.route.egress` present; single-hop -> `kind=single`; **when disabled, both keys are absent** (zero-side-effect assertion);
- **schema**: old config without `obfuscation:` parses OK; roundtrip with the block OK; unknown sub-fields denied; three-mode illegal values / empty buckets / min>max / target=0 OK; `default_padding` + inline coexisting Err; nonexistent policy name Err;
- **selector**: the four `apply_to` values' match/non-match states against a mock annotation set.

### 7.2 Integration (mock link, no privileges)

- **chain padding full link**: mock `MeshRegistry` + two-end `MeshDataPlane` (following the existing test shape at `runtime_builder.rs:1991`) -> one side enables `mode=bucket` and sends a flow -> capture wire frame lengths and assert membership in buckets (or <= the cap) -> the peer strips and the payload matches;
- **disabled contrast**: same flow and config but `enabled=false` -> wire frame lengths **completely identical** to before enabling (distribution unchanged, zero byte difference) + `padding_frames_total{...}=0`;
- **single-hop no-op**: a mock egress records written bytes -> after enabling padding, the written bytes match the disabled case + `skipped{no_frame}` increments;
- **packet-length distribution statistics script** (acceptance wording, §0): histogram the wire frame lengths and assert the distribution deviates from the default after enabling (e.g., the mode bucket shifts); the script lands with M4 (§8).

### 7.3 Gates

- the unit/integration suites have **no privileged dependency** (pure user-space mocks, run routinely in CI; no `/dev/net/tun` dependency);
- full-repo baseline (currently 118 items at the P0-3 timepoint + later increments) with **zero regression**: this item is entirely additive, and the disabled path changes no existing behavior (§2.5);
- disabled-state assertions must exist (otherwise "zero overhead" cannot be proven).

## 8. Step-by-step implementation checklist (M0-M5)

The commit rhythm follows the P0-4 §9.1.1 / tun-dataplane §5 hard rule: each step `cargo build` + `cargo test` all green -> single commit (referencing this document's §section) -> `git fetch origin main` + rebase -> push -> next step; no tag/release/force push.

| Step | Content and landing points | Depends on | Acceptance |
|----|-----------|------|------|
| M0 | seep-config: `ObfuscationConfig`/`ObfsProfileConfig`/`PaddingBlockConfig` + `deny_unknown_fields` + `validate`; seep-runtime: `to_padding_policy()` conversion | - | 7.1 schema/conversion all green; old config zero difference |
| M1 | **mount point** (C1 closure): `MiddlewareChain` (seep-core) + `FlowOutputRouter::forward` three-stage wiring + §1.4 annotation injection + `LatencyProbe` explicitly mountable | - | 7.1 chain and annotation injection all green; explicitly mounting `LatencyProbe` proves the pipeline works (not mounted by default, §4.1) |
| M2 | `PaddingMiddleware` (seep-protocols) + policy-engine pure functions + `PaddingSpec` | M0 | 7.1 policy engine and codec all green |
| M3 | frame execution side: `MeshEnvelope` pad/strip + version gate + cap/overhead counting | M1,M2 | 7.1 pad/strip golden; 7.2 chain padding full link |
| M4 | metrics (§5) + statistics script + disabled-state contrast assertions | M3 | 7.2 distribution script; `seep_obfs_*` series visible |
| M5 | documentation backfill (PROTOCOLS.md performance/security section obfuscation row, positioning §2.4 current-state note, todo check-off, acceptance-wording verification) | M0-M4 | P1-4 acceptance checked item by item; the wording rewrite (§0) synced with todo |

Acceptance alignment: P1-4 = M0-M4 (M5 is documentation closure). "After enabling, packet-length distribution deviates + configurable target shapes" = M3+M4 (chain-frame wording, §0); "zero-overhead bypass when disabled" = M1 empty-chain bypass + M4 disabled-state assertions (§2.5, E11).

## 9. Deviations and assumptions (self-made assumptions where information was missing are all annotated)

| # | Type | Content |
|---|------|------|
| 1 | ruling | **policy/execution separation**: the middleware only produces a `seep.obfs.padding` annotation; the padding is executed by the frame carrier (the `handle(Flow)` stream signature cannot carry frame semantics, §2.1); zero trait changes |
| 2 | ruling | the mount point is unique and sits on `FlowOutputRouter::forward` (`runtime_builder.rs:1258`) -- the only place in the data path holding both `decision` and `flow`; no second mount point on the ingress side (positioning §2.4 "before egress") |
| 3 | ruling | the decision context is projected via annotations (`seep.route.kind`/`seep.route.egress`) for the middleware to read; the annotation namespace `seep.` follows the `seep.chain.path` precedent |
| 4 | assumption | `MeshEnvelope.version` can serve as the padding capability discriminator; the exact version number and the precise behavior of old peers ignoring unknown fields are **verified at implementation time** (serde ignores unknown fields by default, but the padding bytes pollute the tail, so a version gate is required rather than relying on field-ignoring alone, §2.4) |
| 5 | ruling | the MVP frame carrier is only chain's `MeshEnvelope`; single-hop TCP has no own frame -> no-op (nothing faked); the UDP frame comes with P0-4 (§2.3, §4.4) |
| 6 | ruling | `LatencyProbe` is **not mounted by default** (its 1ms sleep is placeholder semantics and would inject latency into the production path); mounted only when explicitly configured, to verify the pipeline (§4.1) |
| 7 | ruling | static chain (`Arc<Vec<Arc<dyn FlowMiddleware>>>`) rather than a writable container; P3-2 dynamic loading extends on top of it; this item adds no dynamic-loading dependency (§1.5) |
| 8 | ruling | new block `deny_unknown_fields` (no legacy burden); the global `SeepConfig` is not tightened (legacy compatibility, same as network-route §1.5) |
| 9 | correction | todo acceptance "egress packet-length distribution deviates" cannot be literally achieved on the TCP side (the kernel decides on-the-wire segmentation); the wording is rewritten to chain frames / UDP frames (§0), **explicitly registered rather than silently shrunk** (aligned with the P0-3 hy2 re-judgment practice) |
| 10 | ruling | padding byte content, MVP = `0x00` (length camouflage only); content camouflage and traffic shaping belong to P2-4/P2-5 |
| 11 | assumption | the profile container semantics are delivered by this item; the three-scenario complete templates belong to P2-3; this document's schema is a true subset of P2-3 |

## 10. Risks and open items

- **R-obfs1 (core)**: the actual effect of TCP-side padding is limited to "seep's own frames" -- at present only the chain's JSON envelope frame. Per-packet length camouflage for **arbitrary TCP protocols** requires a protocol-level frame layer (TLS record padding / protocol-native padding), which middleware cannot conjure; the real anti-QoS/DPI home ground is the **UDP side** (game is P0-4, QUIC passthrough likewise) -- this design does not overstate TCP-side capability (§2.3).
- **R-obfs2 version coupling**: chain padding requires both link ends to run a supporting version; during a mixed-deployment upgrade window it degrades to no padding (fail-open); under a long mixed-deployment window, "enabled but ineffective" must be visible via the `skipped{peer_version}` metric (§2.4, E6).
- **R-obfs3 bandwidth cost**: padding directly amplifies egress byte volume (especially `fixed` with a large target on high-frequency small packets); `max_overhead_ratio` is the only gate, and its default value and stress-test confirmation are recorded in M4 (§2.6).
- **R-obfs4 alignment itself becomes a feature**: aligning all streams to a few fixed buckets makes the packet-length distribution spiky (the mode shifts), which may be identified by "distribution shape" rather than "specific value" -- the `range` mode and "multiple adjacent buckets" config exist for this; joint verification with P2-4 timing (same statistical method) happens when P2-4 lands (todo P2-4 acceptance already carries the same requirement).
- **O-obfs1**: whether an ingress-side mount point (inbound padding/unpadding) is needed -- not done in the MVP; revisit when the need arises (§1.3).
- **O-obfs2**: concrete frame opportunities for single-hop egress (VLESS/VMess framed payloads) -- hook left, not implemented (§4.3).
- **O-obfs3**: whether TUN ingress downlink packets (P1-2 §2.3's IP/UDP construction points) reuse UDP frame padding -- to be discussed together with P0-4/P1-2 (§2.3).
- **O-obfs4**: the format-finalization order with P2-6's binary envelope (`pad_len` field encoding) -- no hard dependency, but alignment to the same format version is needed (§4.5).
