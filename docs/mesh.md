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

Padding, timing/shaping and WASM middleware are explicit features with no automatic performance benefit. v1 small/mobile builds will prune dependencies further; current runtime still brings Wasmtime through plugins.

## Observability

Metrics and group/switch APIs expose recorded quality/state, not a full connection trace. Some current loss-labelled values are connection error ratios, not game packet loss. v1 separates kind, source, age and sample count; see [Debug/MCP](design/debug-and-mcp.md).

Health/config/fallback changes do not guarantee seamless migration of existing TCP/UDP sessions. Address/mapping changes may require app reconnects. Standard subscriptions, desktop process routing and six-platform basics do not wait for optional Mesh enhancements.
