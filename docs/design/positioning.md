# Rillane Product Positioning and Technical Foundation

> Status: design doc (2026-09) | upstream references: [architecture.md](../architecture.md), [PROTOCOLS.md](../PROTOCOLS.md), [mesh.md](../mesh.md)

## Executive Summary

Rillane is **a single proxy kernel** serving three scenarios: **general proxy, game acceleration, web acceleration**. They are not three products but three strategy combinations over the same data path (ingress -> routing -> egress/transport):

- **Acceleration = routing optimization + traffic obfuscation**: bypass QoS rate limiting and DPI interference, choose low-latency paths;
- **Obfuscation = letting traffic rillane past detection**: protocol impersonation and traffic feature dispersion, a precondition for acceleration and also a proxy's survival capability;
- **Web acceleration = connection efficiency + steering precision**: connection reuse and rule-based steering, reusing the same routing engine.

This document breaks down which layers are fully shared, which are scenario-specific, how obfuscation is injected as a cross-cutting layer, and gives the mapping conclusions against the current crates. The phased landing plan is in [roadmap.md](roadmap.md); actionable items are in the root [todo.md](../../todo.md).

---

## 1. One kernel, three scenarios

| Scenario | User value | Essence |
|------|---------|------|
| General proxy | Access and privacy | The data path itself: ingress takeover -> rule routing -> protocol egress |
| Game acceleration | Low latency, no packet loss, QoS resistance | UDP-first data path + low-latency scheduling + traffic obfuscation |
| Web acceleration | Fast first packet, stable throughput | Connection reuse + fine-grained steering + nearest exit |

The three scenarios share >70% of the technical surface: ingress takeover, the Flow session model, rule routing, group policy for node selection, multi-hop links (mesh), subscription, control plane and observability. The differences concentrate in **strategy parameters and a few specialized modules**, not independent product lines.

## 2. Shared foundation: one data path

```
                     +-------- cross-cutting: obfuscation layer (Obfuscation) --------+
                     | protocol impersonation / traffic feature dispersion / TLS      |
                     | fingerprint / padding and timing perturbation                  |
                     +-----------------------------------------------------------------+
 application traffic ---> Ingress ---> Flow/Session ---> Routing ---> Egress/Transport ---> target
 (TUN/socks5/    (socks5/      (5-tuple + process   (rules + group policy   (direct/ss/trojan/
  http/redir)     http/mixed)   + domain + geoip)    + mesh links)           hy2/vless/wg/mesh)
                     |                                          |
                     +----------- Control Plane (rillaned API + rillanectl) -------------+
                     +----------- Telemetry (/metrics, /flows, /nodes) -------------+
```

### 2.1 Fully shared layers

| Layer | Responsibility | Current state (crate) |
|----|------|--------------|
| Ingress | Traffic takeover: local proxy (socks5/http/mixed) + system-level (TUN/redir) | `rillane-protocols` ingress ready (TCP); TUN see the gap list |
| Flow session | Unified session model: target, routing history, usage, failure stats | `rillane-core` `Flow/FlowSession/ChainContext` ready |
| Routing engine | Rule matching (domain/geoip/ipcidr/port/process) + group policy for route selection | `rillane-routing` ready (latency/bandwidth/weighted/consistent-hash and other strategies) |
| Multi-hop link | mesh networking, chain build/precheck/failure fallback | `rillane-mesh` + `rillane-runtime::chain` ready (TCP) |
| Egress protocol stack | direct/ss/trojan/hy2/vless/vmess/wg/socks/http + ws/grpc/h2 transports | `rillane-protocols` egress ready (TCP) |
| Subscription | Clash import + own DSL + hot reload | `rillane-subscription` ready |
| Control plane | REST API + rillanectl + mTLS tooling | `apps/rillaned`, `apps/rillanectl` ready |
| Observability | per-flow/per-link metrics, diagnostic collection | `rillane-telemetry` basically ready, refining |

### 2.2 Game acceleration specialization (layered on the shared foundation)

1. **UDP-first data path** (the largest current gap): 90% of game traffic is UDP. Full-path UDP is needed:
   - Ingress: SOCKS5 UDP ASSOCIATE, TUN-layer NAT sessions;
   - Egress: UDP-capable protocol carriers (Hysteria2/Shadowsocks-UDP/WireGuard/Direct; the mesh data-plane needs UDP forwarding added);
   - Core model: `FlowTarget::Udp` brought up end to end + UDP session table (NAT semantics, timeout reclamation).
2. **Low-latency scheduling**: path selection with RTT/packet loss/jitter as primary objectives (the existing `latency` group policy and `LatencyProbe` middleware are the starting point); first packet first, small packets over throughput.
3. **Session stickiness**: the same game session (process + 5-tuple) sticks to the same link; on link failure, migrate along the `ChainContext` fallback path and preserve the NAT mapping, avoiding game disconnect-and-reconnect.
4. **System-level takeover**: game process traffic can only be caught by TUN + process/port rules (proxy ingress cannot catch it); this is the rationale for the TUN layer in game acceleration.

### 2.3 Web acceleration specialization

1. **Connection reuse**: egress connection pool and keep-alive reuse (aggregating handshakes for short connections to the same exit and same SNI), TLS session resumption/0-RTT;
2. **Steering precision**: domain/geoip/ruleset steering decides "who goes through the proxy, who goes direct", directly determining the web experience (the existing `rillane-routing` rules + subscription ruleset conversion cover most of it);
3. **DNS optimization**: steering-aware resolution (domestic/foreign DNS steering, caching, pollution prevention); the design goal of `rillane-platform::network::dns` is exactly this;
4. **Reuse rather than build new**: all of the above operate on the shared data path and introduce no independent "web acceleration module".

### 2.4 Obfuscation: a cross-cutting layer, not a protocol

Obfuscation is not a feature of some egress protocol but a **cross-cutting capability inserted on both sides of the egress transport layer** (matching the positional semantics of `FlowMiddleware`):

| Means | Description | Ecosystem reference (Clash / sing-box practice) |
|------|------|--------------------------------|
| In-protocol impersonation | Trojan=HTTPS, VLESS+Reality borrows the TLS handshake, Hysteria2 impersonates QUIC | Built into existing protocols, `PROTOCOLS.md` "traffic obfuscation" section |
| obfs plugins | simple-obfs (http/tls padding), Shadowsocks plugind mechanism | Clash `plugin: obfs/v2ray-plugin` |
| Obfuscated transport | salamander (Hysteria2), QUIC traffic shaping | hy2 native `obfs: salamander` |
| Fingerprint emulation | uTLS/client TLS fingerprints (chrome/ios/safari) | sing-box `utls` |
| Feature dispersion | packet-length padding, timing perturbation, heartbeat normalization -- countering statistics-based QoS detection | Own-development focus (see below) |

**Own-development focus -- traffic feature dispersion**: QoS/DPI detection of game traffic is mostly based on packet-length distribution, inter-packet spacing, and flow shape (not protocol content). The cross-cutting layer should provide:

- `padding`: controllable packet-length padding strategy (aligned to a target distribution);
- `timing`: micro-jitter injection (configurable window, trading a little latency for detection resistance);
- `shaping`: flow-shape normalization (first-packet burst, heartbeat intervals aligned to common application fingerprints).

These three are implemented as `FlowMiddleware` and hung before/after egress, **uniformly effective across the three scenarios**: proxy uses it to pass DPI, game acceleration uses it to pass QoS, web acceleration uses it to keep TLS in normal form.

> **Current state (2026-10, P1-4/P2-4/P2-5 landed)**: all three have landed as `FlowMiddleware` -- `padding` (P1-4 M0-M4, strategy/execution split: `PaddingSpec` policy engine pure functions + a frame-carrier execution side, MVP frame carrier = the mesh chain's `MeshEnvelope` frames, three forms fixed/bucket/range, an overhead-ratio gate, the `rillane_obfs_*` metric family always rendered + the `scripts/obfs_padding_dist.py` distribution-check script); `timing`/`shaping` (P2-4: `TimingMiddleware` startup jitter + `ShapingMiddleware` write-grid normalization). Single-hop TCP with no own frame is a no-op; the UDP datagram padding carrier (`UdpEnvelope`) is ready but its execution hook is not wired (ruling in udp-mesh-dataplane.md D-15). TLS fingerprint emulation landed with P2-5 (chrome/ios/safari presets, see [tls-fingerprint.md](tls-fingerprint.md)); the SS SIP003 plugin bridge covers the simple-obfs ecosystem (`plugin`/`plugin_opts` + obfs-local, see [PROTOCOLS.md](../PROTOCOLS.md) and todo "SS 出站 SIP003 插件桥"); salamander (hy2) compatibility is not implemented. Details in [obfuscation-middleware.md](obfuscation-middleware.md).

### 2.5 Conclusions from the data-path perspective

- The differences across the three scenarios = **routing strategy templates + middleware combinations + egress protocol selection**, all configuration-layer combinations, requiring no branching code paths;
- Expressed in config as profiles: `proxy` / `game` / `web` preset sets (routing rule templates + obfuscation switches + scheduling objectives), same underlying engine;
  > **Current state (2026-10, P2-3 landed)**: top-level `profile: proxy|game|web` default-fill expansion (explicit always wins, zero branching at runtime); pick one of `examples/profile-*.yaml` and run -- see [scenario-profiles.md](scenario-profiles.md);
- This is a "shared foundation, strategy divergence" single-kernel architecture, consistent with the modular positioning in the README.

## 3. Gap against current state (concluding list)

| # | Gap (2026-09 point-in-time conclusion) | Impact | Current state (2026-10-04) | See |
|---|------|------|------|------|
| G1 | Zero UDP at the protocol layer (`rillane-protocols` has no UDP forwarding path) | Game acceleration unavailable | **Closed** -- P0-2/P0-3: UDP ASSOCIATE ingress + direct/ss/wg egress payload | roadmap S1 |
| G2 | TUN/system routing is a placeholder implementation (each Provider in `rillane-platform::network::platform.rs` returns "not implemented", runtime not wired) | System-level takeover / process steering unavailable | **Closed** -- P1-1/P1-2/P1-3: real linux.rs implementation + TunIngress wiring + network config block and `rillanectl route` | roadmap S2 |
| G3 | No independent obfuscation cross-cutting layer (only protocol-builtin impersonation) | QoS/DPI resistance limited | **Closed** -- P1-4 padding, P2-4 timing/shaping landed; simple-obfs usable via the SS SIP003 plugin bridge (2026-10-07, SS TCP side only), salamander deferred to V2 as an option | roadmap S3 |
| G4 | No egress connection reuse / pooling | High cost for short web connections | **Closed** -- P1-5 M0-M5 connection pool + TLS session resumption | roadmap S3 |
| G5 | mesh data-plane TCP only (JSON envelope with plaintext header) | Multi-hop UDP unavailable; envelope optimizable to binary | **Closed** -- P0-4 UDP multi-hop + P2-6 binary envelope | roadmap S1/S3 |
| G6 | Fine-grained metrics missing (per-link latency distribution, switch reason, etc.) | Scheduling lacks a data closed loop | **Closed** -- P2-1 `rillane_mesh_link_*`/`rillane_mesh_switch_total` + `GET /mesh/switches` | roadmap S4 |

## 4. Document index

- Architecture overview and crate split: [docs/architecture.md](../architecture.md) (referenced, not rewritten)
- Protocol capabilities and compatibility: [docs/PROTOCOLS.md](../PROTOCOLS.md) (referenced; deviations from the implementation are governed by section 3 of this file and the errata in todo.md)
- Mesh/link/data-plane protocols: [docs/mesh.md](../mesh.md) (referenced, not rewritten)
- Phased plan: [docs/design/roadmap.md](roadmap.md)
- Actionable checklist: [todo.md](../../todo.md)
