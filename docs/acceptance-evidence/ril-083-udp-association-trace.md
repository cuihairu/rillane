# RIL-083 — UDP association and probe trace wiring (local verifiable segment, 2026-11-27)

## What is delivered

The second segment's named gaps are closed: UDP association flows and
url-test probe flows now emit real diagnosis traces into the same shared
`FlowCollector`, so `/trace/*` covers both remaining kernel-visible
origins.

**UDP association face** — wired on the session table itself
(`crates/rillane-core/src/udp/trace.rs`, table method
`attach_trace_wiring`, called from `Runtime::start()` next to the TCP
`TracedFlowOutput` assembly; the collector did not exist at table build
time, same `attach_chain_events` precedent). UDP does not traverse the TCP
`FlowOutput` chain (separate pump, relay-path §4), so trace events land on
real session-table lifecycle points:

- **takeover** (`session.takeover`) — session creation after the capacity
  gate, sanitized `association client <addr> [user <name>]` detail.
- **rule** (`route.rule`, predicted) + **plan** (`route.plan`, predicted) —
  on each sticky decision, including reroutes (a reroute is a real event);
  `rule` only when the decision carries a reason.
- **association.mapped** (`association.mapped`, observed) — mapping bound
  (node from the decision path; Reused binds re-emit nothing).
- **association.reclaimed** (`association.reclaimed`, observed) — explicit
  revoke via `force_revoke` (SOCKS5 control link EOF, protocol UDP session
  teardown, admin revoke).
- **association.closed** (`association.closed`, observed) — idle/lifetime
  sweep expiry (reason in detail).

Every origin protocol that shares the table (SOCKS5 UDP, vless/vmess/
trojan/hysteria UDP faces) gets the same lifecycle events for free.

**url-test probe face** — the probe handler wraps the node's assembled
egress output in `TracedFlowOutput` (runtime_builder probe handler).
A probe is a synthetic duplex flow down the real forward path, so it
traces as `origin=stream` with takeover → rule (`url-test probe`) → plan
→ close; the trace's terminal state follows the real forward completion,
not the probe return value (a timed-out probe's forward task still winds
down and closes honestly — no event is fabricated at timeout).

## Live evidence

`crates/rillane-ffi/tests/contract_query_face.rs` extends the live
runtime face capture with a real SOCKS5 UDP ASSOCIATE roundtrip
(method negotiation → ASSOCIATE → SOCKS5-UDP datagram → local UDP echo →
control link EOF), then requires from the live collector:

- a `flows_item`-shaped entry with `origin=association`, `state=closed`,
  `last_code=association.reclaimed`, `generation=local`, ≥4 events;
- the detail trace via `flow_found`: first event `session.takeover`, an
  `association.mapped` event present, no `transfer.*` events (first bytes
  are not measured per-packet — none fabricated).

`crates/rillane-core/tests/udp_associate.rs` adds two deterministic tests:
a real roundtrip asserting the four lifecycle points plus
`FlowTrace::validate` (seq continuity, monotonic time), and a
`MockClock`-driven idle sweep asserting the `association.closed` terminal
code (distinct from `reclaimed`).

`contracts/schema_v1/ffi_face_v1.json`: the stale "UDP 关联面归后续批次"
clauses in `flows_item`/`flow_found` notes are replaced with the fourth-
segment fact. Key sets untouched — schema_v1 frozen shape not broken.

## Honest boundaries

- First-byte/per-packet events are still not produced: the UDP pump does
  not measure them per packet (same no-fabrication rule as the TCP face).
- Sessions created before `attach_trace_wiring` carry no trace; in
  production assembly the attach happens before any traffic, and no
  backfill is attempted.
- Probe traces enter the shared bounded ring; heavy url-test fleets can
  evict older entries (eviction counters stay visible in collector stats
  — bounded-diagnostics semantics, unchanged).
- Route-rejected sessions (capacity gate, table shutdown) produce no
  trace; `rule` needs a decision reason — none invented.
- Device acceptance (Android/iOS hosts, RIL-043/094) is unchanged; this is
  the local verifiable segment only, and the main RIL-083 checkbox stays
  open.
