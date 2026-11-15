# Optional Mesh reference

Mesh connects managed client/relay/exit nodes, separately from standard subscription proxies. [v1 architecture](design/architecture-v1.md) keeps it optional. A working proxy does not imply support for Rillane envelopes.

## Existing operations

| Operation | Entry |
|---|---|
| Nodes/topology | `rillanectl nodes`; GET `/nodes` |
| Preflight/chains | `rillanectl chain --help`; chain dry-run/create |
| Switching history | `rillanectl switches`; GET `/mesh/switches` |
| Certificates | `rillanectl mtls --help` |
| Revocation status | `rillanectl mtls revoke status`; GET `/mtls/revoked` |

See [CLI](cli.md) and [configuration](config.md). Mesh dry-run is managed-topology preflight, not general v1 Explain or visibility into provider internals.

## Security and forwarding

TCP chains use versioned MeshEnvelope and require hop-by-hop mTLS by default. Hop encryption is not end-to-end multi-hop authentication. Deployments own certificate trust, node identity and revocation distribution; file status does not imply online CA/OCSP checking.

UDP has envelope/session/replay state, but combinations without complete secure carriage remain rejected. Development plaintext switches are not a production solution; sequence windows do not replace authentication.

Padding, timing/shaping and WASM middleware are explicit features with no automatic performance benefit. Build profiles are pruned: the runtime `plugins` feature (default `full`) carries Wasmtime; `small`/`mobile` builds (`--no-default-features --features small`) drop Wasmtime from the dependency graph and reject `obfuscation.plugins` declarations at validation time with the stable code `config.combo.unsupported` — the builtin padding/timing/shaping chain and standard subscriptions keep working.

## Observability

Metrics and group/switch APIs expose recorded quality/state, not a full connection trace. Some current loss-labelled values are connection error ratios, not game packet loss. v1 separates kind, source, age and sample count; see [Debug/MCP](design/debug-and-mcp.md).

Health/config/fallback changes do not guarantee seamless migration of existing TCP/UDP sessions. Address/mapping changes may require app reconnects. Standard subscriptions, desktop process routing and six-platform basics do not wait for optional Mesh enhancements.

## Managed capability negotiation (RIL-050)

Capability exchange is a managed-channel contract (`crates/rillane-mesh/src/negotiation.rs`):

- **Trust first**: only declarations carried by an authenticated (mTLS-bound) channel count. Anonymous hellos are rejected outright with the stable code `mesh.cap.untrusted` — the negotiation face never treats a missing declaration as a present capability. (The send-side connectivity fallback — skip padding when the peer version is unknown — stays orthogonal: it is traffic-surface tolerance, not negotiation.)
- **Version intersection**: the data-plane envelope version is the highest version present in both declared sets; no intersection rejects with `mesh.cap.incompatible`, naming both sets.
- **Explicit conservation, never fail-open**: every capability is decided field by field. One-sided padding declarations disable padding with the missing side named in the negotiation notes; incomplete UDP secure carriage on either side refuses UDP mesh with the reason recorded. Fallbacks are auditable in the result, never silent.

## Standard proxy independence and the plaintext gate

A subscription-built runtime carries no mesh faces when mesh/chain are off (`enable_mesh`/`enable_chain` default false): no registry, no UDP face — assembly faces are honestly absent, not idle. Acceptance: `crates/rillane-runtime/tests/optional_extension_assembly.rs` forwards real traffic with every extension off.

The UDP mesh plaintext gate defaults to refuse: no TLS and no explicit plaintext opt-in rejects startup with the reason naming plaintext. With TLS configured the same gate passes. An explicit plaintext switch exists as a development face (`RILLANE_MESH_UDP_ALLOW_PLAINTEXT` / config equivalent) — it is never the default and never a production delivery path.

Plugins are isolated from the policy face: a runtime carrying a real Wasm plugin decides routes identically to an isomorphic plugin-free runtime, and the plugin performs byte-level work only — it neither redirects nor intercepts standard forwarding.
