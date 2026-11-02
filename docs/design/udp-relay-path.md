# P0-2 / P0-3 implementation-level design: single-hop UDP relay path

> Status: **Landed (todo P0-2/P0-3 complete, 2026-09)** · This document expands [udp-dataplane.md](udp-dataplane.md) §2/§3 and is the implementation framing for both items · Depends on the session table contract: [udp-session-table.md](udp-session-table.md) · Maps to [todo.md](../../todo.md) P0-2/P0-3 · Upstream: [roadmap.md](roadmap.md) S1
> Implementation surface = `seep-core/src/udp/associate.rs` (inbound) + `seep-protocols` egress underlay connectors; the design text is preserved, and deviations are authoritative per each section's landing note.

## Executive Summary

P0-2 (SOCKS5 UDP ASSOCIATE inbound) and P0-3 (direct/ss/hy2/wg egress underlay) share one **single-hop relay path**; this document gives the implementation-level design: on the inbound side, the control-plane command branch, the 10-byte datagram header parsing, BND reply semantics, the ASSOCIATE lifecycle and the session-table reclaim hook; on the egress side, the static capability table and build-time errors, the underlay used by each of the four protocols, and the classification contract from `UdpRelay` errors to `FailureType`. The end of the document maps the acceptance tests of both items.

## 1. End-to-end packet flow (single-hop view)

```
uplink: client ──[SOCKS5 UDP header|data]──► relay socket ──parse/verify──► UdpSessionTable (sticky key hit)
        ──► mapping.binding (direct = Local socket / protocol egress = UdpRelay handle) ──► target
downlink: target ──► per-mapping forwarder task (spawned on the table side) ──► downlink mpsc ──► inbound consume loop
        ──► wrap the SOCKS5 UDP header ──► client
```

Field transformation: the inbound strips `[RSV(2) FRAG(1) ATYP(1) ADDR(var) PORT(2)]` into a `FlowTarget`; the downlink re-wraps in the same format (`ATYP` backfills IPv4/IPv6/domain per the target address family). The session table's internals (stickiness, mappings, reclaim) are in [udp-session-table.md](udp-session-table.md) and are not repeated here.

## 2. P0-2: SOCKS5 UDP ASSOCIATE inbound

### 2.1 Control-plane command branch (reusing the existing framework)

`inbound/socks5.rs`'s existing `negotiate_method` (0x00/0x02) / `perform_auth` / `parse_request` (ATYP 0x01/0x03/0x04) are reused entirely; `parse_request`'s current `header[1] != 0x01 → send_error(0x07)` becomes a command dispatch:

| cmd | Behavior |
|-----|------|
| 0x01 CONNECT | Current path untouched (`Flow{io}` streaming) |
| 0x03 UDP ASSOCIATE | New: bind the relay socket → reply BND → enter the data plane (§2.3/§2.4) |
| Others (incl. 0x02 BIND) | `0x07 Command not supported` (current) |

Auth semantics: with `udp_enabled=false`, 0x03 returns 0x07 (consistent with current behavior; the master switch is udp-dataplane.md §5.2); whether auth passes does not affect ASSOCIATE availability, but it does affect the sticky key's `user` dimension (udp-session-table.md §3.1).

### 2.2 Relay socket binding and the BND reply

- The relay socket **binds UDP on the same port number as the TCP listener** (TCP/UDP port spaces are independent);
- Reply frame: `BND.ADDR = 0.0.0.0`, `BND.PORT = the relay socket's actual bound port` -- unlike the existing `send_success` returning zeros, the UDP **port must be real** (the client sends datagrams using it); a zero address is handled by the client as the control connection's peer IP (Clash/sing-box convention); the multi-homing compatibility issue and the `advertise_addr` reservation = upstream R3;
- The client expects to send to `BND`, and the actual datagram source address is recorded into the sticky key's `client` (five-tuple baseline).

### 2.3 Datagram parsing and admission

Per-packet flow (inside the relay socket's recv loop):

1. Parse the SOCKS5 UDP request header (≥10 bytes; `ATYP` 0x01/0x04 is a 4/16-byte address, 0x03 a variable-length domain);
2. `FRAG != 0` → drop + `seep_udp_packets_dropped_total{reason="frag"}` (the MVP does no fragment reassembly; upstream O2);
3. Source verification `strict_udp_source` (on by default): datagram source IP ≠ the control connection's peer IP → drop + count (prevents the relay being borrowed by third parties; the inbound side of upstream R7);
4. Build `UdpSessionKey{client=(src ip, src port), user, process:None}` and look up the session table; a miss goes to the first-packet path (routing decision → create session/mapping, udp-session-table.md §3.3);
5. `binding.send_to(target, data)`.

**Source-switch port semantics**: the client switching its UDP source port = a new sticky key = a new session; the old session is reclaimed by `session_idle`, with no migration (udp-session-table.md §3.2 already decided); for diagnosis, cross-check via `client_info.address`.

### 2.4 Downlink consume loop

The inbound side holds a `downlink_rx` per ASSOCIATE and loops: `DownlinkPacket{target, data}` → wrap `[00 00 00 | ATYP | ADDR | PORT]` → `send_to(client_addr)`. `client_addr` is taken from the control connection's peer address. When the channel is full (capacity 64), the downlink is dropped + `dropped{reason="no_mapping"}` counted separately -- UDP has no backpressure, so prefer dropping over blocking (the backpressure policy is defined uniformly in §4.3).

### 2.5 ASSOCIATE lifecycle and the session-table hook

RFC 1928: when the TCP control connection terminates, the server should end that association. Landing:

- The session table adds `force_revoke(key)`: executes the reclaim action list immediately (udp-session-table.md §4.5) without waiting for the idle sweep;
- The inbound side calls it on control connection EOF/error; the relay socket and the consume loop terminate along with the session reclaim;
- The reverse (session idle expiry) does **not** close the control connection: the TCP side stays, and the client's next packet re-creates the session (saving one ASSOCIATE round trip); the resource cost of an idle hanging control connection is in O8.

### 2.6 Concurrent ASSOCIATE (same key)

A second ASSOCIATE from the same `client (ip, port)`: the MVP **refuses** (reply `0x01 general failure`) + counts. Rationale: `downlink` is a single-consumer mpsc, and dual consumption would need a fan-out structure; two ASSOCIATEs from the same source port are abnormal client usage (normally, two games = two UDP source ports = two keys). The finalization discussion is listed as O9.

### 2.7 Acceptance alignment (todo P0-2)

| Acceptance original text | Test |
|---------|------|
| A standard client completes a DNS UDP query round trip via socks5 inbound + direct egress | Integration: `dig @8.8.8.8 example.com` over socks5 (UDP ASSOCIATE) + direct egress, round-trip assertion |
| `seepctl stats` shows UDP sessions | presented by `seepctl stats` once the session table metrics feed the `/flows` snapshot (P0-5 linkage) |
| (udp-dataplane §2.4 supplement) the switch off returns 0x07 | with `udp_enabled=false`, 0x03 → 0x07; CONNECT has no regression |
| (new in this draft) header parsing and admission | FRAG≠0 drop counter; forged source IP drop counter; a truncated 10-byte header does not panic |

## 3. P0-3: egress UDP underlay

### 3.1 Static capability table and build-time scan

| EgressConfig variant | UDP capability | Underlay |
|-------------------|---------|---------|
| `Direct` | yes | local UDP socket (§3.2) |
| `Shadowsocks` | yes (**judged no** when the `plugin` field is non-empty: the SIP003 plugin only defines a TCP data plane; for plugin mode, this scan errors at build time on that node's UDP needs, 2026-10-07) | crate UDP relay (§3.3) |
| `Hysteria2` | yes (premised on the V1 check) | QUIC datagrams (§3.4) |
| `WireGuard` | yes | IP packet encapsulation (§3.5) |
| `Socks5` / `Http` / `Trojan` / `Vless` | no (out of S1 scope, udp-dataplane.md §3.5) | build-time error |
| `Vmess` | no (the TCP connector landed 2026-10-02; the UDP underlay is not implemented, and the build-time scan errors immediately) | same as above |

- At `RuntimeBuilder` build time: compute the UDP capability closure over all egress nodes reachable from `routing.rules`/`default_node`/group `members`; a node that UDP traffic can reach but which has no UDP capability → **startup fails**, and the error lists each node name and rule source (todo P0-3 acceptance "clear error at build time");
- mesh targets (`mesh.*`) are not in this table; P0-4 handles them separately (udp-dataplane.md §4).

### 3.2 direct

`UdpSocket::bind("0.0.0.0:0")` → `connect(target)` → wrapped as `UdpBinding::Local`. A send error containing `ConnectionRefused` (target port closed) → classified `FailureType::Timeout` (§3.6), and the mapping is kept for idle reclaim -- game servers commonly probe by "not answering the first packet"; the mapping is not torn down immediately because of an ICMP.

### 3.3 shadowsocks

- Reuses the workspace `shadowsocks 1.21` UDP relay capability (`relay::udp`), with per-packet independent `[salt][AEAD(target address + data)]`, connectionless semantics, naturally fitting the mapping model;
- `method` validity checking moves from "erroring on the first runtime packet" **forward to build time** (incidentally fixing the same experience on the TCP plane);
- Landing framing for upstream R7 (open resolver): the egress sends only the `ctx.target` locked at `associate(ctx)`; the mapping layer has no "change address at will" interface -- target whitelisting is guaranteed by the session table's structure.

### 3.4 hysteria2 (premised on the V1 check)

The first implementation ticket = checking four checkpoints of `hysteria2 0.1.6`: ① does it expose a UDP/session API; ② do datagrams and the TCP session share connection management; ③ close semantics (does the TCP side's break take UDP down with it); ④ the bandwidth/congestion parameter entry points. Conclusion branches: a) API usable → connect directly; b) missing → implement the hy2 UDP channel on quinn ourselves (protocol framing in udp-dataplane.md §3.3); c) workload over budget → downgrade P0-3 acceptance (hy2 moves to P0-4 as a follow-up, **with the acceptance explicitly rewritten on the todo**, not silently shrunk). Lifetime isolation of the TCP/UDP shared QUIC connection (③) is a hard implementation requirement.

### 3.5 wireguard

- Underlay = build an IP packet and write it into the system WG interface (the same track as the TCP plane; WG is itself L3):

```
IPv4: [20B IP header (src=WG address config, dst=target, proto=17, checksum) | 8B UDP header (sport=mapping-assigned, dport=target.port, checksum) | data]
```

- the `allowed_ips` pre-check reuses the existing verification semantics (a target outside the ranges → errors at mapping creation, classified `FailureType::Route`);
- MTU budget: the WG interface MTU (config default 1420) minus the outer encapsulation → an application payload ceiling of ~1400B; over-limit packets are dropped + counted (upstream R8, fill in measured numbers);
- source port allocation: a fixed pseudo-random port per mapping (fixed at the first packet, unchanged for the session), ensuring correct downlink demultiplexing.

### 3.6 UdpRelay error classification contract (session table ↔ egress)

| Error shape | FailureType | Session table action |
|---------|-------------|-----------|
| bind/handshake failure (associate phase) | `Connection` | no mapping created; `record_failure` + `dropped{reason="no_mapping"}` |
| send/recv IO error (in transit) | `Connection` | `record_failure`; ≥3 consecutive trigger a mapping rebuild (re-associate for the same target) |
| target unreachable/timeout (ICMP, ss no response) | `Timeout` | `record_failure`; the mapping is kept for idle reclaim |
| route unreachable (wg allowed_ips etc.) | `Route` | mapping closed + decision cache cleared (triggers rerouting, udp-session-table.md §3.4) |

All errors are invisible through the §2.4 downlink channel -- the client only observes packet loss, matching UDP semantics.

### 3.7 Acceptance alignment (todo P0-3)

| Acceptance original text | Test |
|---------|------|
| QUIC sites (HTTP/3) reachable via both the hy2 and wg egresses | Integration: one round of `curl --http3` via each of the two egresses (premise: V1 passes) |
| unsupported egress types error clearly at build time | a rule pointing at a trojan/vless node → startup fails, the error contains the node name and rule name |
| (udp-dataplane §3.6 supplement) a DNS query round-trips via the ss egress | Integration: `dig` over ss UDP |
| (new in this draft) error classification | inject failures row by row per the §3.6 table, asserting the corresponding `FailureStats` counters and mapping behavior |

## 4. Interface contract with the session table

1. **associate timing**: after the first packet's routing decision is produced, at mapping creation (table side), one per mapping; reconnection (§3.6 consecutive errors) reuses the same call;
2. **the forwarder task belongs to the table side**: the egress only delivers a `UdpRelay` byte-level handle; the recv loop, downlink delivery, metrics, and error classification are all spawned/closed out on the table side -- egress implementations stay "pure pipes", and new egresses add zero observability code;
3. **backpressure policy**: all downlink channels have capacity 64, dropping when full + counting; the uplink has no queue (send passes straight through). The whole chain (inbound §2.4 / table §4 / P0-4 hop-to-hop) uses this one framing.

## 5. Boundaries and open questions

| No. | Content | Follow-up |
|------|------|------|
| O8 | after idle reclaim the control connection still hangs: from the client's view, "the ASSOCIATE is still valid but packets silently rebuild the session". MVP accepts; whether to reply ICMP/close explicitly on expiry is undecided | decided during implementation, no dependencies |
| O9 | whether the same-key concurrent ASSOCIATE refusal policy (§2.6) should be relaxed to fan-out | revisit on a real client need |
| V1 | the hy2 crate capability check = P0-3's first ticket (§3.4's four checkpoints) | decides whether the acceptance framing is downgraded |
| R3/R7/R8 | BND address multi-homing / ss anti-abuse (this document's §3.3 has landed structural guarantees) / WG MTU | see udp-dataplane.md §7 summary |

## 6. Implementation notes (P0-2 landing rulings, 2026-09)

Code: `seep-core/src/udp/associate.rs` (service and admission), `seep-protocols/src/inbound/socks5.rs` (command dispatch), `seep-runtime/src/runtime_builder.rs` (wiring), `seep-config` (the `udp:` block). Tests: `seep-core/tests/udp_associate.rs` (13 items) + `udp_session_table.rs` §3.6 staged teardown 4 items.

| # | Draft | Implementation | Ruling rationale |
|---|------|------|---------|
| 1 | §2.4 downlink full `dropped{reason="no_mapping"}` | `DropReason::DownlinkFull` (named for the table-side semantics) | "mapping exists but the channel is full" and "no mapping" are two different events; conflating them misleads |
| 2 | the SOCKS5 UDP frame codec's home was undecided | `seep-core::udp::associate` (the `parse_udp_header`/`encode_udp_header` pure functions) | the service loop's per-packet codec needs to sit on the table's side; the protocols→core dependency direction complies |
| 3 | §2.6 the concurrency gate's key | the control connection's peer (ip, port); datagram sources go into the sticky key as measured | at ASSOCIATE time the datagram source is unknown; same-key judgment lives at the gate layer and the session key at the table layer, each holding on its own level |
| 4 | §3.6 landing framing | sender-side staged teardown: Route → tear down the mapping + clear the decision cache; Timeout → keep the mapping (the counter returns to zero); Connection → tear down at ≥3 consecutive (success returns to zero); recv-side errors (forwarder) exit the mapping directly | a recv error means the relay is already dead with no recovery path; the send side implements the §3.6 table row by row with tests pinning it |
| 5 | the reclaim task's start timing was undecided | the first ASSOCIATE's `Once` spawns `spawn_reclaimer` | the build phase has no tokio context; a session cannot exist before an ASSOCIATE |
| 6 | P0-2's routing plane | the base `RoutingEngine` impls `FlowRouter`; mesh-chain-aware UDP routing belongs to P0-4 | single-hop scope (this document's §1); the RuntimeFlowRouter wrapper depends on mesh components and is wired in P0-4 |
| 7 | `EgressUdpConnector::associate`'s return type | `Arc<dyn UdpRelay>` (not Box; same framing as api doc §9 #3) | the forwarder and the send path share ownership |
| 8 | the mixed ingress was not mentioned | `MixedIngress` shares ASSOCIATE (transparent passthrough by the same service instance) | the socks5 branch reuses the same processing path, at no extra cost |
| 9 | `perform_auth` had no return | return the authenticated username → the sticky key's `user` dimension | the wiring point for udp-session-table.md §3.1's user dimension |

**Acceptance status (§2.7)**: the DNS-style UDP round trip (real socket, strict source verification on, direct egress, downlink framing) is pinned by `dns_style_roundtrip_via_associate_and_direct`; FRAG≠0 / truncated header / forged source (127.0.0.2) / concurrent ASSOCIATE refusal each have their own independent test. The "standard CLI client (curl/dig) + `seepctl stats` visible" integration test belongs to P0-5 (after the observability wiring).

## 7. Implementation notes (P0-3 landing rulings, 2026-09)

Code: `seep-core/src/udp/relay.rs` (RoutingUdpConnector + trait signature), `seep-protocols/src/outbound/{shadowsocks,wireguard}.rs` (UDP plane), `seep-runtime/src/runtime_builder.rs` (§3.1 capability scan + wiring). Tests: `seep-core/tests/udp_egress_selection.rs` (3 items) + `seep-protocols/tests/udp_egress.rs` (7 items) + 4 `seep-runtime` capability scan items.

| # | Draft | Implementation | Ruling rationale |
|---|------|------|---------|
| 10 | §3.4 hy2 V1 check | **branch (c): deferred to P0-4**. Checked hysteria2 0.1.6: the public API has only `HysteriaClient::connect` + `tcp_connect` (open_bi); `quic_connection` is `pub(crate)`, with no UDP/QUIC datagram egress at all | no silent shrinkage: the todo P0-3 acceptance was explicitly rewritten, and "QUIC sites reachable via hy2 egress" moved into P0-4 (in the same batch as mesh UDP underlay; at that time switch the crate version or use quinn directly) -- **postscript (2026-09-30)**: at P0-4 completion **the revision was upheld**, and the hy2 UDP final state = V2 (quinn vehicle, todo P0-4 §0.1-③) |
| 11 | §3.4 the `associate(ctx)` signature | expanded to `associate(ctx, decision: &RouteDecision)`; `RoutingUdpConnector` dispatches to the node connector by the decision's `final_node()` | vehicle selection must use the session's **sticky decision** (already cached at resolve time); rerouting would break same-session-same-exit; an unregistered node errors by name (the capability table scan is the fallback) |
| 12 | §3.5 the wg underlay mechanism | under the system-interface (wg-quick style) approach, UDP goes through **kernel routing**: a local UDP socket `connect`s the target and the kernel imports into the wg interface; no hand-built IP construction | the same architecture as this repo's TCP-plane wireguard connector; userspace hand encapsulation is another code path (to be re-evaluated at P1 TUN) |
| 13 | §3.5 the wg pre-check | `allowed_ips` parsed as CIDR at build time (invalid → startup fails); at associate the target is resolved first (domain→IP), and if it is in no range → a Route-class error "... is not inside the wireguard allowed_ips ranges"; empty ranges skip the pre-check (left to kernel routing) | the error message carries the `allowed_ips` keyword so classify_failure classifies it Route (tear down the mapping + clear the decision, §3.6) |
| 14 | §3.5 wg MTU | payload ceiling = `mtu-80` (a conservative 1400 if unconfigured); over-limit is dropped on the connector side, erroring "wireguard MTU exceeded..." classified **Timeout** (the mapping kept for idle reclaim) | R8 drop + count framing: the send_failed counter accumulates on the table side; Timeout is the behavior closest to "packet-level transient loss does not tear down the mapping" |
| 15 | §3.3 ss | encryption method validation moved up to `ShadowsocksConnector::new` (TCP/UDP share one `ServerConfig`; an invalid method errors at build time); the client socket uses `ProxySocket::connect` (`bind` is the server's inbound listener); the target is fixed at association (R7) | ss UDP has connectionless semantics and the target rides in each packet: a fixed target is the mapping semantics; verified against the shadowsocks 1.24.0 API |
| 16 | §3.1 scan scope | the reachable set = default_node + rule targets + group member closure (Weighted nodes/groups expanded too); **targets that are not egress nodes of this config (e.g. `mesh.exit1`) are skipped** (the router resolves them itself); errors list each node's name/type/source (`default_node` / `rule:{name}` / `group:{name}`) | mesh nodes' UDP capability belongs to the P0-4 mesh data plane, and this scan must not misreport it |

**Test framing (§3.7)**: "QUIC sites reachable via the direct/wg/ss egresses" is pinned by real-socket send-path tests + the §3.6 classification full-chain tests (a full ss decrypt round trip needs a `shadowsocks-service` server, which the repo does not depend on, so it belongs to the P0-5 integration test); "unsupported egress types error clearly at build time" is pinned by the `scan_udp_capability` series tests (naming the node, type, and rule source). The hy2 acceptance moved to P0-4 per #10 (P0-4 completed in 2026-09 and **the revision was upheld**; the hy2 UDP final state = V2 -- todo P0-4 §0.1-③).
