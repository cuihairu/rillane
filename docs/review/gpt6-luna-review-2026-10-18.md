[0m
> build · gpt-6-luna
[0m→ [0mSkill "code-review"
> build · gpt-6-luna
[0m$ [0mgit status --short && git log -1 --oneline
M .gitignore
a56fe4d fix(deps): bump quinn-proto rustls wasmtime for rustsec advisories
[0m✱ [0mGlob "**/*" [90m2000 matches[0m
[0m✱ [0mGrep "TODO|FIXME|XXX|HACK" [90min . · 123 matches[0m
> build · gpt-6-luna
[0m→ [0mRead todo.md [90m[limit=280][0m
[0m→ [0mRead README.zh.md [90m[limit=220][0m
[0m→ [0mRead Cargo.toml [90m[limit=240][0m
[0m→ [0mRead docs/architecture.md [90m[limit=180][0m
[0m$ [0mgit ls-files | grep -vE '(^|/)(target|build)/' | wc -l && git ls-files | grep -E '(^|/)(\.github/workflows|tests|benches)/|^(README|docs/|todo)' | head -200
239
.github/workflows/ci.yml
README.md
README.zh.md
apps/rillaned/tests/samples.rs
crates/rillane-config/tests/dns_block.rs
crates/rillane-config/tests/egress_pool_block.rs
crates/rillane-config/tests/group_member_roundtrip.rs
crates/rillane-config/tests/network_block.rs
crates/rillane-config/tests/obfuscation_block.rs
crates/rillane-config/tests/profile_examples.rs
crates/rillane-config/tests/profile_presets.rs
crates/rillane-config/tests/tls_fingerprint_field.rs
crates/rillane-config/tests/udp_config.rs
crates/rillane-core/benches/relay_throughput.rs
crates/rillane-core/benches/write_frame.rs
crates/rillane-core/tests/middleware_chain.rs
crates/rillane-core/tests/udp_associate.rs
crates/rillane-core/tests/udp_egress_selection.rs
crates/rillane-core/tests/udp_session_table.rs
crates/rillane-protocols/tests/pool_connectors.rs
crates/rillane-protocols/tests/pool_tls_integration.rs
crates/rillane-protocols/tests/udp_egress.rs
crates/rillane-routing/tests/routing_tests.rs
crates/rillane-runtime/tests/mesh_chain_routing.rs
crates/rillane-runtime/tests/tun_ingress.rs
docs/.vitepress/config.mts
docs/.vitepress/theme/custom.css
docs/.vitepress/theme/index.ts
docs/PROTOCOLS.md
docs/architecture.md
docs/cli.md
docs/config.md
docs/design/dns-partition.md
docs/design/egress-connection-pool.md
docs/design/mesh-advanced-security.md
docs/design/mesh-envelope-binary.md
docs/design/mesh-link-observability.md
docs/design/network-route.md
docs/design/obfuscation-middleware.md
docs/design/obfuscation-timing-shaping.md
docs/design/performance-io.md
docs/design/platform-packaging.md
docs/design/plugin-loader.md
docs/design/positioning.md
docs/design/roadmap.md
docs/design/scenario-profiles.md
docs/design/slo-scoring.md
docs/design/status-audit-tun-network-middleware.md
docs/design/tls-fingerprint.md
docs/design/tun-dataplane.md
docs/design/tun-linux-impl.md
docs/design/udp-dataplane.md
docs/design/udp-mesh-dataplane.md
docs/design/udp-observability.md
docs/design/udp-relay-path.md
docs/design/udp-session-table-api.md
docs/design/udp-session-table.md
docs/grafana/README.md
docs/grafana/rillane-dashboard.json
docs/index.md
docs/mesh.md
docs/networking.md
docs/package-lock.json
docs/package.json
docs/public/logo.svg
docs/subscription.md
todo.md
> build · gpt-6-luna
[0m→ [0mRead todo.md [90m[offset=140, limit=90][0m
[0m→ [0mRead apps/rillaned/src/control_plane.rs [90m[limit=240][0m
[0m→ [0mRead crates/rillane-plugins/src/loader.rs [90m[limit=300][0m
[0m→ [0mRead crates/rillane-runtime/src/mesh_transport.rs [90m[limit=260][0m
[0m→ [0mRead docs/design/mesh-advanced-security.md [90m[offset=1, limit=230][0m
[0m→ [0mRead docs/design/roadmap.md [90m[limit=130][0m
> build · gpt-6-luna
[0m✱ [0mGrep "api_bind|admin_token|ControlPlane::new|control_plane.serve" [90min . · 100 matches[0m
[0m→ [0mRead crates/rillane-runtime/src/udp_chain.rs [90m[limit=280][0m
[0m→ [0mRead crates/rillane-plugins/src/plugin.rs [90m[limit=260][0m
[0m→ [0mRead crates/rillane-config/src/lib.rs [90m[limit=300][0m
[0m→ [0mRead config/rillane.yaml [90m[limit=260][0m
[0m✱ [0mGrep "TODO|FIXME|todo!\(|unimplemented!\(|return Err\(.*not implemented|always Err|not yet implemented" [90min . · 19 matches[0m
> build · gpt-6-luna
[0m→ [0mRead crates/rillane-config/src/lib.rs [90m[offset=1180, limit=130][0m
[0m→ [0mRead docs/design/plugin-loader.md [90m[limit=170][0m
[0m→ [0mRead crates/rillane-runtime/src/runtime_builder.rs [90m[offset=450, limit=105][0m
[0m→ [0mRead apps/rillaned/src/main.rs [90m[offset=45, limit=70][0m
[0m→ [0mRead crates/rillane-runtime/src/mesh_transport.rs [90m[offset=1140, limit=160][0m
[0m→ [0mRead crates/rillane-runtime/src/mesh_transport.rs [90m[offset=740, limit=260][0m
[0m→ [0mRead crates/rillane-runtime/src/tun_ingress.rs [90m[limit=280][0m
> build · gpt-6-luna
[0m✱ [0mGrep "handle_udp_datagram|serve_udp|udp_listener|recv_from\(&mut" [90min crates/rillane-runtime/src/mesh_transport.rs · 29 matches[0m
[0m→ [0mRead docs/architecture.md [90m[offset=82, limit=40][0m
[0m→ [0mRead docs/config.md [90m[limit=220][0m
[0m→ [0mRead docs/networking.md [90m[limit=130][0m
[0m→ [0mRead docs/design/tls-fingerprint.md [90m[limit=125][0m
[0m→ [0mRead crates/rillane-runtime/src/mesh_transport.rs [90m[offset=1370, limit=240][0m
> build · gpt-6-luna
[0m→ [0mRead crates/rillane-runtime/src/mesh_transport.rs [90m[offset=1609, limit=145][0m
> build · gpt-6-luna
[0m✱ [0mGrep "tls.is_none|plaintext gate|UDP.*encrypted|UDP.*plaintext|udp.*plaintext|allow_plaintext" [90min docs · 35 matches[0m
> build · gpt-6-luna
[0m→ [0mRead docs/design/udp-mesh-dataplane.md [90m[offset=1, limit=70][0m
[0m→ [0mRead docs/design/udp-mesh-dataplane.md [90m[offset=172, limit=28][0m
[0m→ [0mRead docs/design/positioning.md [90m[offset=1, limit=160][0m
[0m→ [0mRead docs/design/roadmap.md [90m[offset=79, limit=28][0m
[0m→ [0mRead apps/rillaned/src/control_plane.rs [90m[offset=250, limit=35][0m
[0m✱ [0mGrep "18 subcommands|18 commands|HotReloadManager|reload|LuCI|SCM 1053|TUN.*TCP.*UDP" [90min docs · 17 matches[0m
> build · gpt-6-luna
[0m→ [0mRead todo.md [90m[offset=227, limit=24][0m
> build · gpt-6-luna
[0m→ [0mRead crates/rillane-runtime/src/mesh_transport.rs [90m[offset=1905, limit=40][0m
> build · gpt-6-luna
## 1) The 3 weakest spots (ranked by risk)

1. **Mesh UDP plaintext gate may mislead into thinking encryption protection already exists | high risk**
   `crates/rillane-runtime/src/mesh_transport.rs:963-969,1291-1296,1915-1928`; client send path see `crates/rillane-runtime/src/udp_chain.rs:152-155,244-245`.
   `MeshUdpGate` only checks whether `MeshTlsConfig` is configured, and lets traffic through if it is; but the UDP surface sends and receives raw datagrams directly, with no TLS/mTLS wrapping. In other words, after configuring TCP mTLS, UDP may still start in plaintext when `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` is not set. The UDP replay window also has no MAC/authentication; a network-reachable attacker can forge new sequence numbers and inject packets. The gate should be fixed first so that "TCP mTLS configured" cannot be taken to mean "UDP encrypted".

2. **Control plane authentication can be configured to be fully off, with no non-loopback listening protection | high risk**
   `apps/rillaned/src/control_plane.rs:129-139,258-261`; bind point `apps/rillaned/src/main.rs:74-81`; config docs `docs/config.md:32-34`.
   When `admin_token` is empty, `is_authorized()` returns `true` directly, while `api_bind` can be configured to a non-loopback address; at that point route apply/clear, subscription changes and other admin operations have no authentication. The config docs only say the token is optional, with no warning that "non-loopback listening requires authentication configured", and the code does not reject the dangerous combination.

3. **WASM plugin load-time calls have no effective time limit | medium-high risk**
   `crates/rillane-plugins/src/loader.rs:64-70,86-105`.
   The load phase sets fuel to `u64::MAX`, then directly calls the plugin's exported `wants_payload`, `plugin_name`; if a plugin infinite-loops in these functions, it can stall startup. The fuel isolation described in the docs actually only covers each `on_flow` call (`crates/rillane-plugins/src/plugin.rs:130-144`), not the load-time probing. The init exports should get a separate finite budget, and linear memory should have a clear cap.

## 2) The 3 most worthwhile new capabilities

1. **Mesh UDP end-to-end encryption and authentication**
   The current UDP mesh lacks encryption and MAC; anti-replay cannot prevent forgery. It is absent because UDP encryption is explicitly deferred to V2, the QUIC transport has not been selected, and there is no end-to-end key distribution/negotiation mechanism (`docs/architecture.md:59`, `docs/design/mesh-advanced-security.md:11-13,176`).

2. **Control plane security boundary: mandatory authentication by default, and restricted remote exposure**
   Add startup validation for non-loopback listening, and provide a TLS/mTLS or UDS management endpoint; later split permissions by read-only, operations, etc. It is absent because the control plane is implemented as a local HTTP/REST minimal management surface, the token is only an optional config, and there is no threat model or permission system for remote management.

3. **Transactional config hot reload**
   Implement atomic switching after validation, coordinating the lifecycle of routing, TUN, connection pools, and middleware. It is absent because the current implementation reads config once at startup; `HotReloadManager` is exported but not wired up, and dynamically rebuilding sessions and system routes needs clear rollback/migration semantics (`docs/architecture.md:50`).

## 3) Where docs and implementation may not match

- `docs/architecture.md:85` still labels "S1...->S2...->S4..." as "in progress/planned", but `docs/design/roadmap.md:4` already claims S1-S4 and P3 are all complete.
- `docs/design/roadmap.md:89-91` still lists advanced security and platform packaging as new items; in reality P2-7 only delivered revocation status observability and UDP anti-replay, while OCSP and end-to-end MAC are explicitly not implemented; platform packaging also has unverified boundaries like Windows SCM real startup and macOS real machines (`todo.md:126-127,147`). The delivered subset and deferred items should be labeled separately.
- The UDP encryption gate has a risky gap between its stated criteria and the implementation: `docs/architecture.md:59` says UDP encryption is not implemented; but the implementation decides whether to let UDP through based on "whether TCP's `MeshTlsConfig` is configured" (`mesh_transport.rs:963-969,1291-1296`), while the UDP listener is still raw `recv_from` (`mesh_transport.rs:1915-1928`). The gate should be clearly stated as not equal to UDP encryption, and mTLS configuration should not silently let plaintext UDP through.
- `docs/config.md:32-34` describes `control.uds_path` as an optional UDS configuration; the current `ControlConfig` does define the field (`crates/rillane-config/src/lib.rs:1211-1216`), but `rillaned` startup only uses `api_bind` to create a TCP control plane (`apps/rillaned/src/main.rs:74-81`). The field appears to be an unconsumed config.
- The target data flow diagram in `docs/networking.md:43-47` draws `PacketFilter` as an actual processing stage, but the same document `:15` explicitly states there is no standalone packet filtering implementation, and the current split is handled by routing conditions; the diagram should be labeled as a conceptual model or changed to the actual path.
