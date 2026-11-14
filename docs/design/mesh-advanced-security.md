# P2-7 mesh advanced security: CRL distribution + UDP-side anti-replay -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) S4-4 ("advanced security wrap-up: CRL/OCSP, mesh end-to-end MAC/anti-replay") · [mesh.md](../mesh.md) "Security Notes" leftover · [architecture.md](../architecture.md) collaborator node security boundary.
> This document is the landed finalization: **scope ruling, CRL distribution shape, the UDP frame anti-replay protocol (v2 + stream sequence + sliding window), the counting surface, error paths, test strategy, step-by-step checklist**. Deviations are backfilled into §9 after landing.
> Reuse baseline: the `MeshTls` revoked-file mtime-fingerprint hot reload (`RILLANE_MESH_MTLS_REVOKED_NODES[ _FILE]`, mesh_transport.rs) · the `rillanectl mtls revoke` revoked-list file management (rillanectl main.rs) · the P0-4 UDP-side `UdpEnvelope` binary frame (P2-6 already byte-encoded it: magic `SU` + version + flags + flow_id...) · the `UdpFaceMetrics`/`UdpFaceSnapshot` counting surface (P0-5 §2.4) · control_plane (`Method, path`) dispatch and the `/udp/stats` mesh section (precedent).

## 0. Scope ruling

| In this item | Goes to V2 / other |
|-----------|-------------|
| **Form closure of revocation distribution**: on top of the existing file hot reload, add runtime visibility (a control-plane snapshot endpoint + a rillanectl query) and the documentation wording | OCSP/CA direct pulls, automatic CRL push distribution (there is no CA channel between nodes besides the mTLS data plane; distributing the revocation file via operations = the distribution vehicle, see D-2) |
| **Anti-replay for the UDP mesh data plane**: frame-level stream sequence + a 64-bit sliding window at the receiver + replay-drop counting (`replay_dropped`) | End-to-end MAC/authentication (no end-to-end key-distribution mechanism -- the registry has no node public keys, chain has no session-key negotiation; there is nowhere to hang an HMAC, recorded as a §9 deviation) |
| The TCP mesh data plane anti-replay stance (mTLS sequence numbers already prevent per-hop replay; the engineering argument for why envelope-level end-to-end anti-replay is infeasible) | DTLS/QUIC wholesale encryption (the udp-dataplane.md plan A, undecided in V2) |

**Acceptance wording** (the two todos of P2-7 in the original text, each delivered):
1. "a revoked node is rejected without a restart" -- **already in place** (file mtime-fingerprint hot reload + `is_revoked` at accept time); "**supplement CRL distribution**" = this item's M0 (distribution state is visible at runtime -- the revocation list's load/effective state is queryable, and together with the existing file vehicle it forms the "distribute -- take effect -- verify" closed loop);
2. "**replayed packets are dropped and counted**" = this item's M1 (the UDP-side sliding window drops + the `replay_dropped` count enters the `/udp/stats` mesh section and `/metrics`).

## 1. Current-state inventory (the premise for M0)

- Revocation vehicle: `RILLANE_MESH_MTLS_REVOKED_NODES` (static CSV) + `RILLANE_MESH_MTLS_REVOKED_NODES_FILE` (file, mtime-fingerprint hot reload); TCP accept calls `is_revoked(peer)` to refuse the connection (mesh_transport.rs:1164);
- Management surface: `rillanectl mtls revoke add/list/remove` (atomic file write, main.rs) -- **the file is already the distribution vehicle** (a shareable filesystem / CI push / operations push);
- The gap: **which revocations a running node has loaded right now is not observable** -- operations cannot confirm the distribution took effect; the provability of "rejected without a restart" exists only inside the `is_revoked` logs, and there are no counts/timestamps. M0 adds the observability surface.

## 2. M0: closure of the CRL distribution form (revocation snapshot endpoint)

### 2.1 `MeshTls::revoked_snapshot()`

```rust
pub struct RevokedSnapshot {
    /// static env entries (RILLANE_MESH_MTLS_REVOKED_NODES)
    pub static_entries: Vec<NodeId>,
    /// file vehicle (None = RILLANE_MESH_MTLS_REVOKED_NODES_FILE not configured)
    pub file: Option<RevokedFileState>,
}
pub struct RevokedFileState {
    pub path: String,
    pub loaded: bool,      // false when the load failed (error details go into error)
    pub error: Option<String>,
    pub mtime_secs: u64,   // mtime of the last loaded version of the file (epoch seconds)
    pub entries: Vec<NodeId>,
}
```

- call `maybe_reload()` before taking the snapshot (same wording as `is_revoked` -- the snapshot is the currently effective surface, no second state);
- implementation: `MeshTls` reads `cfg.revoked_node_ids` + `inner.revoked_node_ids` + `inner.fingerprint.revoked_mtime`; the failed-load state (load was once Err) is exposed by `load_revoked_nodes`' upward propagation -- `MeshTlsInner::load`'s current `?` propagates directly, which would make **a maybe_reload failure take the whole connection surface down**; M0 does not change that semantics (the existing behavior of a hot-reload failure = connection refused/error, fail-closed in the safe direction); the snapshot only shows the **most recently successful load** state + the static entries.

### 2.2 Control-plane endpoint `GET /mtls/revoked`

- no mesh/mTLS assembly (default `get_mesh_plane`) -> `SERVICE_UNAVAILABLE` (the `/nodes` precedent);
- response 200:

```json
{
  "static_count": 2,
  "file": {"path": "/etc/rillane/revoked.list", "loaded": true, "error": null,
           "mtime_secs": 1760000000, "count": 3, "entries": ["node-bad"]}
}
```

- authentication inherits the control plane's current state (local HTTP, `x-admin-token` if configured).

### 2.3 `rillanectl mtls revoke status [--endpoint]`

- calls `GET {base}/mtls/revoked`; renders line by line: `static: <count>`, `file: <path> (<loaded> mtime=<secs> entries=<count>)`, then `  revoked: <node>` per entry;
- non-2xx -> the existing `Control plane returned an error: {} - {}` bail shape (the Chain precedent).

### 2.4 A running node is rejected without a restart, closed-loop argument

`rillanectl mtls revoke add file ` (-> atomic file write) -> the node notices the mtime fingerprint -> the next `is_revoked` hits before accept -> the connection is refused. M0's endpoint/CLI makes "the distribution took effect" provable: `rillanectl mtls revoke status --endpoint` shows the new mtime and the new entries.

## 3. M1: UDP frame anti-replay (v2 sequence + sliding window)

### 3.1 Motivation and surface choice

- the UDP side has no TLS sequence protection (the plaintext gate or future encryption are both packet-level), so **replay can inject stale/copied business payloads** (a client replays an "old wallet transaction", and the exit side cannot tell);
- on the TCP side, mTLS sequence numbers already constitute per-hop anti-replay; "replaying a whole TCP connection" requires first passing mTLS and then being refused by session-state management -- **no envelope-level end-to-end anti-replay** (the only injection surface for replay distortion is the stateless packet level);
- therefore anti-replay lands on the **UDP side**, at flow level (keyed by flow_id), with end-to-end semantics (seq is generated by the sender; each receiving hop verifies independently).

### 3.2 Frame format: `UDP_ENVELOPE_VERSION_V2 = 2` (v1 compatible)

```
magic "SU" | version=2 | flags: bit0=dir, bit1=HAS_SEQ(=1) | flow_id(16)
| atyp | host | port | path_mode | hop_index | seq(4, BE, when HAS_SEQ=1) | path? | payload
```

- **seq is always carried**: new frames use version=2 with HAS_SEQ=1 (no branch in encoding); decoding v1 -> `seq_present=false`;
- reserved-bit matrix extended: v1 keeps `flags & 0xFE != 0 -> refuse`; v2 allows bit1, and any other nonzero reserved bit is still refused;
- `UdpEnvelope` gains the fields `seq: u32` and `seq_present: bool` (filled back on decode; encoding v2 always sets it);
- **mixed deployment fail-open (inherits the R-obfs2 same-version deployment assumption)**: an old end sends v1 (no seq) -> the new end receives: no verification (skip the window when `seq_present=false`); the new end sends v2 -> the old end's decode refuses the frame (version mismatch) -> **in a mixed-deployment window the new-end-to-old-end direction breaks the data plane**, same wording as the P0-4 plaintext gate: a grid mixed-deployment upgrade needs a window period (stated explicitly in the docs, the same gate as the P1-4 pad §10).

### 3.3 Sender side: a per-flow monotonic sequence

| Send point | Sequence source | Notes |
|-------|--------|------|
| client bridge `MeshUdpRelay::send_to` (uplink FULL/CACHED) | new field `next_seq: AtomicU32` | the relay is a single stream in a single direction -- fetch_add is monotonic |
| exit downlink `exit_downlink_loop` | new parameter `Arc<AtomicU32>` (created when the flow is built) | §13-1 lifecycle follows the ExitFlow |
| relay forwarding / relay downlink (one hop to the next) | **keep the incoming frame's seq value unchanged** | end-to-end semantics: seq is flow-level, not hop-level; each receiving hop has an independent window, so out-of-order tolerance is consistent |

- seq space 2^32; wrap handling: the window compares with a wrapping difference (`(seq.wrapping_sub(last))` decides order), monotonic within the 2^31 half-space -- a `u32::MAX` flow wraps **after 4 billion packets**, an MVP limitation recorded in §10 (a per-flow lifecycle is far shorter than that, see R-replay).

### 3.4 Receiver side: a 64-bit sliding window (the RFC 4303 style)

```rust
struct ReplayWindow { last: u32, bits: u64 }  // bit i = whether last - 1 - i was already received
```

Judgment (only when `seq_present`; wrapping difference `diff = seq - last`, order decided within the 2^31 half-space):
- `diff == 0` -> replay refused (last is always refused);
- `1 <= diff <= 64` -> advance and accept; `last = seq`; when `diff < 64` shift `bits <<= diff` (right shift of history), and when `diff == 64` clear the history (crossed the 64-bit window);
- `diff >= 65` and `< half space` -> **forward out-of-window refused** (same as RFC 4303: a jump-window frame is judged the same as a replay and dropped; an attacker's seq jump is dropped, flow-level isolation in §6 deviation 4);
- `diff >= half space` (equivalent to a regression) -> look up the bits bit where `back = last - seq <= 63`: already set -> replay refused; not set -> accept and set it; `back > 63` -> out-of-window refused (too old).
- the first packet (empty window) accepts any seq -- window entries are created lazily (§7 R-replay2).

Key: **`(flow_id, dir)`** (flow + direction; uplink and downlink each have their own window -- an exit downlink and a client uplink do not interfere with each other). There is no source-node id field (the frame does not carry one); flow_id is a 128-bit random UUID, so the cross-flow collision probability is negligible -- the same key premise as the P0-4 cache.

### 3.5 Storage and lifecycle

- `UdpFace` gains `replay: DashMap<([u8;16], u8), ReplayWindow>` (dir encoded 0/1);
- **entry lifecycle follows the flow cache**: the `sweep`/`retire_flow`/`forget_flow` cache-entry death points also call `replay.remove` (the same three-table reclamation semantics as §13-1, preventing unbounded growth of the window table);
- the verification point is in `handle_udp_datagram` (after decode, before path validation) and the client bridge's `recv_from` (downlink) -- both call the same function `replay_check(flow_id, dir, seq)`.

### 3.6 Counting surface

- `UdpFaceMetrics` gains `replay_dropped: AtomicU64` (snapshot/render invariant: a refusal is always counted, and not mixed into malformed/unknown_flow -- a new semantic gets a new count);
- `UdpFaceSnapshot` gains `replay_dropped`;
- client bridge `recv_from` window refusal -> `UdpClientMetrics` gains `replay_dropped` (the existing `dropped` is a general discard that includes decode errors -- replay is separately observable);
- observability rendering: the `/udp/stats` mesh section `replay_dropped` + the `mesh_client` section `replay_dropped`; `/metrics` `rillane_udp_mesh_replay_dropped_total` + `rillane_udp_mesh_client_replay_dropped_total` (appended to the P0-5 §2.4 family);
- rillanectl `UdpMeshDto`/`UdpMeshClientDto` gain a field with `#[serde(default)]` (fault tolerance for older rillaned).

### 3.7 Error paths

| # | Error point | Condition | Semantics |
|---|--------|------|------|
| E1 | v2 encoding dir-bit conflict | HAS_SEQ and dir share a bit (bit0 is fixed to dir) | constructor defect (encoding side always sets 0 in the single branch); no handling defined |
| E2 | v2 reserved bits nonzero | decode `flags & ~0x03 != 0` | malformed, drop + count (extends §13-3) |
| E3 | truncated seq segment | HAS_SEQ=1 but fewer than 4 bytes remain | malformed, drop (the udp_take out-of-range path) |
| E4 | seq out of window / replay | the window judgment refuses | **silent drop** (not malformed -- an attack or an out-of-order both need no notification of the sender) + replay_dropped |
| E5 | v1 mixed-deployment frame | decode version=1 | handled as-is (no verification) -- fail-open |

## 4. Test strategy

### 4.1 Unit tests (no privileges)

- **codec**: v2 with seq, byte-level golden (seq position/big endian); v1 golden regression (old bytes unchanged); the existing matrix in this file extended with the v2 reserved-bit two-state; seq truncation refused;
- **window** (pure function, table-driven): ascending receive, out-of-order receive (an unset bit within the window), replay refused, out-of-window refused, a jump-window receive (bits cleared), one before and one after the u32 wrap (wrapping difference);
- **counting**: after a replay refusal the snapshot's replay_dropped increments, while malformed/unknown_flow stay put.

### 4.2 Integration (real sockets, reusing the §13 face roundtrip precedent)

- relay plane roundtrip (the same kind of fixture as `udp_relay_plane`/`udp_exit_plane`): a client-side v2 uplink -> the exit receives (forwarded_up=1); **inject a replay frame with the same seq** -> the exit side's replay_dropped=1 and the exit target socket receives no duplicate payload;
- out-of-order frames (seq+1 before seq+0) -> both packets arrive and the window is in place;
- client bridge downlink replay: an exit downlink frame is replayed -> the client's `recv_from` refuses and keeps looping, `replay_dropped` increments.

### 4.3 Endpoint/CLI (M0)

- `GET /mtls/revoked`: no mesh -> 503; assembled state (env static + file) -> shape assertions (count/entries/mtime);
- the rillanectl rendering pure function + assembly assertions (no real request sent).

## 5. Step-by-step implementation checklist (R0-R4)

The commit rhythm follows the P0-4 §9.1.1 hard rule: each step build/test all green -> a single commit (referencing this document's §section) -> fetch + rebase -> push; no tags/force push.

| Step | Content and landing points | Acceptance |
|----|-----------|------|
| R0 | this design draft | - |
| R1 | M0: `RevokedSnapshot` + the `get_mesh_plane` getter + `GET /mtls/revoked` + rillanectl `mtls revoke status` | 4.3 all green |
| R2 | M1 codec + window: `UdpEnvelope.seq`/`seq_present` + v2 codec + the `ReplayWindow` pure function + `UdpFace.replay` lifecycle | 4.1 all green (golden + window matrix) |
| R3 | M1 wiring + counting: the three sender-side sequence sources, the two receiver-side verification points, the `replay_dropped` counting surface (metrics/snapshot//udp/stats//metrics/rillanectl) | 4.2 integration + updated existing /udp/stats assertions |
| R4 | documentation backfill: mesh.md Security Notes, architecture.md boundary, todo P2-7 check-off + progress, the `rillanectl mtls revoke status` help, §9 deviations | all gates green |

## 6. Deviations and assumptions

| # | Type | Content |
|---|------|------|
| 1 | scope | **end-to-end MAC/authentication is not in the MVP**: there is no end-to-end key-distribution mechanism (the registry has no node public keys, chain session has no key negotiation). The boundary of anti-replay without authentication: the window refuses replay, but an attacker cannot forge a new seq's semantics (forgery needs a MAC) -- the replay attack surface is flattened, and the forgery surface goes to V2 (quinn/DTLS, or a chain session key + HMAC). The todo/roadmap wording is backfilled with this document, and mesh.md's boundary line is synced |
| 2 | ruling | **the CRL distribution vehicle = file** (a shared filesystem / CI / operations push, with `rillanectl mtls revoke add` atomic writes); the closure of "distribution" = runtime observability (the M0 endpoint/CLI), not building a pull/push channel (there is no CA side channel between nodes, and OCSP needs a direct CA connection = V2) |
| 3 | assumption | the mixed-deployment upgrade window fail-open is inherited (R-obfs2): an old end's v1 is received by the new end without verification; a new end's v2 -> the old end refuses the frame (the version gate) -- stated explicitly in the docs, the same gate as the P1-4 pad (§10 R-obfs2 same-version deployment assumption) |
| 4 | assumption | seq space 2^32 per (flow,dir): the usage within the 60s idle TTL lifecycle is << the 2^31 half space (wrap judged safely by a wrapping difference); a constructed out-of-window attack (a seq jump of 2^31) affects only that flow's that direction's window (bits cleared to collected), flow-level isolation |
| 5 | deviation | the hot-reload failure semantics follow the existing fail-closed (load Err -> maybe_reload Err -> connection surface error); the snapshot shows the most recent successful load state, and the error field is kept for diagnosis |

## 7. Risks and open items

- **O-mix**: in a mixed-deployment window the UDP side breaks in the new-to-old direction (the version gate). Mitigation: stated explicitly in the docs + same-version grid upgrades; deployed in the same batch as the P0-4 plaintext gate/env;
- **R-replay2**: seq verification is after decode and before path validation -- can an attacker create a window entry for a frame that does not hit a window (a nonexistent flow) first? **Ruling: window entries are created lazily** (only frames that pass verification are inserted) -- a replay frame must first be pulled into the window by a real first packet, and a forged flow has no window to pollute; a real flow's first packet with a chaotic seq (not starting at 0) is refused and no entry is created (the window key enters the table only on acceptance);
- **R-replay3**: when multiple clients share a next_hop, the client bridges each have their own window -- the (flow_id, dir) key isolates them naturally, so no shared window is needed.

## 9. Landing notes (R1-R4 deviation backfill)

- **R1 (fffc103)**: M0 landed fully per §2 -- `MeshTls::revoked_snapshot()` (`maybe_reload` before the snapshot, same wording as `is_revoked`) + `GET /mtls/revoked` (no mesh 503) + rillanectl `mtls revoke status --endpoint` (rendered entry by entry: the static/file/revoked list). The help text landed in the same round as the CLI definition.
- **R2 (26e923d)**: M1 codec + window landed per §3.2/§3.4/§3.5 (v2 always carries seq, the `ReplayWindow` pure function, `UdpFace.replay` created lazily and reclaimed with retire/forget/sweep). **Wording backfill**: a forward out-of-window (`diff >= 65`) is judged a refusal the same as replay (same as RFC 4303 -- now in the §3.4 body); both directions of out-of-window are refused.
- **R3 (7a8a209)**: M1 wiring + counting landed per §3.3/§3.6/§3.7 (the three sender-side sequence sources, the two receiver-side verification points, the `replay_dropped` full observability chain). Deviations:
  - **§4.2 integration test shape**: an injected frame reaching the exit directly belongs to a FULL uplink, and the exit side's cached `prev` updates to the injection end as a result (§3: the uplink source is the downlink return target -- protocol-defined semantics), so the later/middle return packets go straight back to the injection socket rather than through relay/client. The test was changed to assert return packets read from the injection end (payload decoded from the envelope), and "the downlink reaches the client through relay" is asserted only for frames that went up through relay (the first ping roundtrip); "each receiving hop has an independent window" is corroborated by the exit counting 2 / the relay counting 0 / the client bridge counting 0;
  - **cross-test env global race**: the enable_mesh branch of `RuntimeBuilder::build()` injects `from_env_strict()` **unconditionally** when `RILLANE_MESH_MTLS=1` (runtime_builder.rs) -- process-level env is a surface shared between tests, so the rillaned side collects it under the `MESH_MTLS_ENV_TEST_LOCK` serialization lock (the full `build_runtime` holds the lock, plus the two inline build+start tests hold it), and the MeshConfig literal pins `data_plane_tls: None` explicitly; this is test-infra collection, not a product code change.
- **Acceptance delivered**: the two todos of P2-7 -- (1) "a revoked node is rejected without a restart": file mtime hot reload (existing) + M0's effective surface is provable (R1); (2) "replayed packets are dropped and counted": M1's sliding window refuses + `replay_dropped` enters /udp/stats and /metrics (R2/R3). End-to-end MAC/authentication is not in the two acceptance todos and goes to V2 (§6 deviation 1).
