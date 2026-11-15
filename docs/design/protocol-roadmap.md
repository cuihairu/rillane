# v1 protocol integration plan

Status: **candidate implementation plan, not current support**. Reviewed 2026-11-15 against sing-box/Mihomo references. Verify versions individually: online development documentation does not certify a specific stable binary.

## Reuse and backend gates

**Write protocol implementation only when a documented search confirms no usable reusable implementation exists.** Record projects/versions, licensing, maintenance, platforms, public APIs, bypass, cancellation and accounting. Prefer Rust libraries, then validated FFI or justified managed backends. Missing integration calls for adaptation/upstream patches first. Without evidence, keep evaluation pending rather than rewriting.

Each protocol directory supplies validated options, Factory registration, role/transport/datagram capabilities and lifecycle. Reuse [IO contracts](io-and-accounting.md) for sessions, accounting and diagnostics. Start with one backend per protocol and prunable heavy dependencies. P1 prioritizes subscription/game interoperability; P2 does not block Linux, Debug or read-only MCP.

## Additional and incomplete capabilities

Roles below are proposed acceptance scope. Evaluate protocol versions, direction, platforms and datagrams per backend. Unavailable roles remain pending/explicitly rejected. Lack of an appropriate library may change scheduling, never bypass the reuse gate.

| Task | Capability | Priority | Proposed scope |
|---|---|---|---|
| RIL-105 | TUIC | P1 | Client/server; verify v4/v5 separately |
| RIL-106 | AnyTLS | P1 | Client/server; verify multiplexing/datagram semantics |
| RIL-107 | REALITY | P1 | Handshake extension; client first, server subject to backend |
| RIL-108 | XTLS Vision | P1 | VLESS framing/flow extension, independent from REALITY |
| RIL-109 | Hysteria v1 | P2 | Legacy client/server; preserve version boundaries |
| RIL-110 | ShadowTLS | P2 | Handshake/carriage with explicit inner protocol |
| RIL-111 | Snell | P2 | Client/server; version-specific datagram capability |
| RIL-112 | NaiveProxy | P2 | Client/server; HTTP/TLS and build requirements |
| RIL-113 | SSH | P2 | Outbound tunnel; authentication and host keys |
| RIL-114 | Tor | P2 | Outbound backend; identity and instance lifecycle |
| RIL-115 | ShadowsocksR | P2 | Outbound compatibility; cipher/obfs/protocol combinations |
| RIL-116 | Mieru | P2 | Client/server and transport capability |
| RIL-117 | Sudoku | P2 | Client/server; versions and crypto options |
| RIL-118 | ShadowQUIC | P2 | Client/server; QUIC/datagrams |
| RIL-119 | TrustTunnel | P2 | Client/server; TLS/auth/datagrams |
| RIL-120 | MASQUE | P2 | Client/server; CONNECT-UDP/IP separately |
| RIL-121 | OpenConnect | P2 | Client endpoint; routes/DNS/credentials |
| RIL-122 | OpenVPN | P2 | Client/server endpoint; modes/platforms |
| RIL-123 | Tailscale | P2 | Bidirectional endpoint; identity/control/routes |
| RIL-124 | ZeroTier | P2 | Overlay endpoint; authority and teardown |
| RIL-125 | EasyTier | P2 | Overlay endpoint; lifecycle and route ownership |
| RIL-126 | Gost Relay | P2 | Outbound compatibility; distinct from relay policy group |
| RIL-127 | Tailcat | P2 | Inbound/outbound; first verify upstream versions/reuse |
| RIL-128 | Cloudflared | P2 | Inbound tunnel; control/auth/service lifecycle |
| RIL-129 | XHTTP | P1 | Transport modes/options and legal proxy combinations |
| RIL-130 | 公共传输与复用矩阵 | P1 | TLS/WS/gRPC/H2/HTTPUpgrade, UoT/XUDP/multiplex; fill verified gaps |
| RIL-131 | Shadowsocks 算法矩阵 | P1 | Audit existing library algorithms including SS2022 candidates |
| RIL-132 | SOCKS5 出站 UDP | P1 | Outbound UDP ASSOCIATE and source checks |
| RIL-133 | Hysteria2 UDP | P1 | Backend with public datagram API; TCP/UDP separate |
| RIL-134 | Shadowsocks 服务端 | P2 | Inbound adapter using existing libraries |
| RIL-135 | Trojan 服务端 | P2 | Inbound TLS/auth and UDP association |
| RIL-136 | VLESS 服务端 | P2 | Inbound handshake/auth/stream/datagram; extensions separate |
| RIL-137 | VMess 服务端 | P2 | Inbound AEAD/replay/stream/datagram |
| RIL-138 | Hysteria2 服务端 | P2 | Inbound QUIC/auth/datagram/lifecycle |
| RIL-139 | 透明接管入口 | P2 | redirect/TProxy/fixed-target tunnel; privileges and recovery |

## Existing capabilities and configuration constructs

Adapt existing Direct, HTTP CONNECT, SOCKS5/mixed, Shadowsocks, Trojan, VLESS, VMess, Hysteria2 and WireGuard, filling verified gaps without recreating working functionality. TUN/mobile and WireGuard platform stubs follow platform gates.

Selector/url-test/fallback/load-balance are policy groups. DIRECT/REJECT/DNS/rematch/bridge are classified by action/service semantics rather than counted as new wire protocols. Coordination such as Hysteria2 Realm belongs to service integration, not another forwarding plane. Server support requires role-specific acceptance.

## Primary references

[sing-box outbound](https://sing-box.sagernet.org/configuration/outbound/)、[inbound](https://sing-box.sagernet.org/configuration/inbound/)、[endpoint](https://sing-box.sagernet.org/configuration/endpoint/)、[Mihomo proxies/listeners](https://wiki.metacubex.one/en/config/proxies/)、[Mihomo transport](https://wiki.metacubex.one/en/config/proxies/transport/)。
