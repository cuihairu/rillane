# RIL-083 — live SessionTracer wiring (local verifiable segment, 2026-11-26)

## What is delivered

TCP ingress flows now emit real diagnosis traces into the shared
`FlowCollector`. The production assembly point is
`crates/rillane-runtime/src/runtime_builder.rs`: each ingress gets a
`TracedFlowOutput` wrapping the existing `StatsFlowOutput`, mounted in
`Runtime::start()` at the same per-ingress spawn site. One flow, one trace.

Event semantics (only kernel-visible facts; no synthetic measurements):

- **takeover** (`session.takeover`) — first event and collector admission
  anchor, with the sanitized ingress/proto/target detail.
- **rule** (`route.rule`, predicted) — only when the frozen decision carries
  a reason; **plan** (`route.plan`, predicted) — path summary of the frozen
  decision.
- **close** — `session.closed` on a successful forward (detail carries
  upstream/downstream byte counts), `session.failed` on a forward error
  (sanitized error detail). Both freeze the trace and finish the collector
  record, so terminal state is always observable.

Attempt and first-byte transfer events are intentionally absent: the
production pump does not measure per-dial attempts or per-direction first
bytes, so the trace answers "who was taken over / why routed / did it pass /
how many bytes" without pretending to have measured what it did not.

The generation is `local` — flows installed by build-time configuration
(RIL-016 source vocabulary); hot-reload generation progression belongs to
RIL-008 wiring. Details pass through `sanitize_untrusted` (RIL-057 gate)
before entering the trace.

## Live evidence (not a mock)

`crates/rillane-ffi/tests/contract_query_face.rs` (3/3 green) starts a real
runtime, drives a real socks5 → direct → local echo TCP round trip, and then
polls the FFI query surface until the trace reaches terminal state:

- `flows.items[*]` is non-empty and the first item matches the frozen
  `flows_item` exact face (origin `stream`, state `closed`,
  last_code `session.closed`, generation `local`, ≥3 events).
- `rillane_ffi_flow_json(id)` answers `found:true`, matches the frozen
  `flow_found` exact face, and its `trace` is closed, begins with
  `session.takeover`, and has an event count consistent with the list
  summary.
- The unknown-ID case still answers the stable `flow_absent` form — live
  traces do not change the explicit absence semantics.

`contracts/schema_v1/ffi_face_v1.json` had marked `flows_item` and
`flow_found` with `verification: pending_live_trace_wiring` since the
schema_v1 corpus landed (RIL-083 first segment). This segment replaces both
markers with `live_trace_wiring_ril083` and converts the old "markers must
be present" assertion into "live evidence must be present, pending markers
must not return" — marker removal is an explicit, gated action.

## Honest boundaries

- UDP association flows use a separate pump outside the `FlowOutput` chain;
  their traces (association mapped/reclaimed/closed) are not wired here.
- url-test probes call the egress `FlowOutput` directly, bypassing the
  ingress chain; probe traffic does not appear in `/trace/*`.
- Rejected flows (route failure before `FlowOutput.forward`) and route
  decisions without a reason produce no `rule` event by design; no fact is
  fabricated to fill the sequence.
- Device acceptance (Android/iOS hosts, RIL-043/094) is unchanged; this is
  the local verifiable segment only, and the main checkbox stays open.
- Full workspace tests, fmt and clippy -D warnings must be green in the
  delivery batch; this document records the segment, not a release.
