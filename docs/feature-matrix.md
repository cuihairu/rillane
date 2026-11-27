# Feature matrix

The capability view of what is delivered in this repository. It complements,
never replaces, the honest ledgers: [platform support](platform-support.md) is
the per-platform view, the [acceptance evidence index](acceptance-evidence/README.md)
lists what ran where, and the machine-readable matrices under `contracts/` are
enforced by contract tests in `cargo test --workspace`.

Build/cross-check ≠ local contract gate ≠ device acceptance. Every cell below
points at a real repository artifact; a named gap stays a gap.

## Capability table

| ID | Capability | Delivered face | Boundary & evidence |
|----|------------|----------------|---------------------|
| F-01 | Proxy ingress | SOCKS5 / HTTP / Mixed ingresses; SOCKS5 username/password auth (RFC1929, constant-time compare), HTTP Basic and Bearer auth; per-ingress UDP ASSOCIATE override | [CLI reference](cli.md); protocol crate `crates/rillane-protocols` inbound face; secrets can be injected by reference (F-13) |
| F-02 | Transparent takeover ingress | iptables and nftables rule backends behind `network.transparent.rule_backend`; dedicated-table fw4 coexistence design; LAN and local-machine faces with escape mark | Rule planning verified locally (`nft -c` parse arbitration); router rule effect/undo needs the OpenWrt device batch (RIL-041) — evidence in [networking](networking.md) |
| F-03 | TUN dataplane | Linux TUN device with minimum ICMP echo path; Android TUN fd injection with bad-fd named rejection | Full TCP/UDP mobile forwarding is a proposal (see below); [usage-bridge](usage-bridge.md) Android/iOS boundaries |
| F-04 | Outbound protocols | 27 egress config/assembly faces (direct, reject, socks5, http, shadowsocks (+SIP003 plugin), vmess, vless, trojan, anytls, hysteria(2), tuic, snell, shadowquic, mieru, shadowsocksr, trusttunnel, masque, openconnect, openvpn, ssh, tailscale, tailcat, cloudflared, tor, wireguard, shadow-tls composite) | Per-protocol honesty lives in [protocol backends](protocol-backends.md) evaluation records — REALITY client options dial-time rejected (rustls has no ClientHello byte control), Naive/Sudoku pending (see proposals); ShadowsocksR accepted against a real peer built from GPL source (RIL-115) |
| F-05 | Transports and multiplexing | gRPC gun stream reuse knobs (RIL-130), ShadowTLS v2 carrier (RIL-110), websocket/TLS transport faces | Shared transport matrix in [protocol backends](protocol-backends.md); unsupported combinations are named at build time |
| F-06 | Routing and strategy | Rule / Global / Direct modes; select / fallback / url-test groups; 14 rule condition kinds (domain suffix/keyword/full/regex, geoip, geosite, network, ip-cidr, port, src-port, proto, process, process-path, rule-set ref); first-match evaluation; `explain` pure replay | Subscription-to-execution regression (RIL-087) pins conversion → generation → explain = actual egress; [CLI reference](cli.md) explain section |
| F-07 | Subscription ingestion | Clash/Mihomo subscription conversion (nodes, groups, rules); FullPolicy and NodesOnly import modes; multi-source merge with explicit dangling-reference failure; credentials survive conversion | RIL-087 six-test regression; [subscription support](subscription-support.md) |
| F-08 | DNS | `network.dns` block with stats and resolver-shape faces on the control plane, FFI and MCP query surfaces | Absence is an honest `enabled:false` empty form, not zeros — [config reference](config.md) |
| F-09 | Config transactions | Generation publication with prepare/apply/commit journal; crash-point replay (subprocess SIGABRT at two commit windows); compensating rollback; audit trail; MCP write tools require real operator proposal/approval IDs | RIL-088 fault-injection acceptance; disk faults leave orphans visible instead of silently absorbed |
| F-10 | Debug diagnostics | `diagnose` (safe/full/raw scopes with redaction, never auto-uploads), `trace` (list/flow/svg/events/inspect with explicit absence exit code 2), `explain` (no side effects), `probe` (explicit registered targets, 503 when disabled); TCP ingress flows traced live by SessionTracer | [Install, recover and Debug](usage-bridge.md); UDP association face and device batches open — [live trace evidence](acceptance-evidence/README.md) |
| F-11 | Optional MCP adapter | stdio adapter, frozen revision 2026-07-28; 16 tools; read/detailed/probe/write scopes with `-32001 mcp.scope.denied` enforcement; rate limiting; official SDK acceptance driver (12 scenarios, zero models) | Off by default — no listener port, no background process; [MCP section in usage-bridge](usage-bridge.md); RIL-090 evidence in `apps/rillane-mcp/sdk-acceptance/EVIDENCE.md` |
| F-12 | Platform takeover faces | Linux transparent/iptables verified locally; Windows Wintun dataplane, process owner, SCM service and recovery device-verified on `imac`; OpenWrt ipk + procd init; macOS build scaffolds | Per-platform status and named gaps in [platform support](platform-support.md) — this row never upgrades build faces to device acceptance |
| F-13 | Mobile FFI face | 15-method JNI surface (`start`, `startWithSecrets`, stop/isRunning, stats + 6 query faces, TUN fd start/stop); `${secret:` reference injection fail-closed; bad-fd rejection keeps the handle untainted; repeatable stop on both Rust and Kotlin halves | JNI parity and C-header parity gates in `cargo test --workspace`; device batches (packetFlow, ABI, threading/backpressure) open — [FFI evidence](acceptance-evidence/README.md) |
| F-14 | Optional Mesh and plugins | Capability negotiation refuses untrusted channels and incomplete UDP security (never plaintext-bypass); wasm plugins isolated from policy on the full profile; small/mobile profiles have a wasmtime-free dependency graph | Standard proxy product works with extensions off — [Mesh](mesh.md); build profiles pinned by CI `small` job (RIL-040) |
| F-15 | Performance ledger | Parallel load comparison with p50/p95, jitter, loss, TTFB, throughput, CPU/RSS and repeat counts; scheduling replay reports fallback and no-gain conditions | Debug-build loopback measurements, honestly scoped — [parallel load](parallel-load.md) |

## Proposals, not delivered

Kept separate from the table above — proposals never read as capability:

- Windows/macOS capture and identity at v1 quality (hardening, dual-stack
  bypass, permissions and recovery) — v1 work column of the
  [architecture capability boundaries](architecture.md).
- Complete mobile forwarding and public packet APIs (Android/iOS) — blocked on
  signed-device probes (RIL-094) and the mobile FFI device batches.
- macOS/OpenWrt/Android/iOS device acceptance batches (all unchecked in
  `todo.md`, each with its named blocker).
- NaiveProxy (RIL-112) and Sudoku (RIL-117) ingestion — awaiting an explicit
  posture decision / a non-GPL authored wire spec respectively; the repository
  refuses silent downgrades.
