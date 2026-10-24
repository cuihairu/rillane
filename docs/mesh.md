# Mesh & Chain Guide (MVP)

This document describes the current MVP-level mesh control plane and chain (multi-hop path) building.

## Concepts

- `NodeId`: a string identifier for a mesh node (e.g. `client1`, `exit1`).
- `NodeRole`: `client` / `relay` / `exit` / `hybrid`.
- `link-state`: directed edge metrics between two nodes (latency/bandwidth/loss).
- `chain`: a computed path from a source node to a target node. In the current MVP, Seep can *compute*
  chains and attach path metadata to flows. TCP flows can also be forwarded hop-by-hop via the mesh
  data-plane listener (supports optional mTLS for encryption/authentication); UDP flows are forwarded
  hop-by-hop since P0-4 (`UdpEnvelope` over UDP datagrams, same port dual-stack -- MVP plaintext gate,
  encryption selection remains V2).

## Control Plane (seepd)

Configured by `control.api_bind` in `SeepConfig` (default example in `config/seep.yaml`).

Auth:
- If `control.admin_token` is set, mutating requests must include either:
  - `X-Admin-Token: <token>` or
  - `Authorization: Bearer <token>`
- Sensitive reads (`GET /runtime/config`, `GET /events`, `GET /logs`) require the
  token too; other GET endpoints are token-free.

Endpoints (mesh scope):
- `GET /health`
- `GET /nodes` (mesh node snapshots)
- `POST /mesh/nodes/register` (register/update a node)
- `POST /mesh/link-states` (update directed link-state)
- `GET /mesh/switches` (the last 100 chain switch events, P2-1; data source for `seepctl switches`)
- `GET /mtls/revoked` (revocation list load state: mtime / entries / load errors, P2-7)
- `POST /chains/dry-run` (chain build pre-check)
- `POST /chains` (create/reuse chain; uses a session_id UUID)
- `GET /chains/{chain_id}`
- `DELETE /chains/{chain_id}`
- `GET /chains/stats`

Other control-plane endpoints (outside mesh scope, dispatcher in
`apps/seepd/src/control_plane.rs`):
- Observability: `GET /flows` / `GET /metrics` / `GET /udp/stats` /
  `GET /egress/pool/stats` / `GET /dns/stats` / `GET /runtime/stats` /
  `GET /routing/stats` (real-time group quality: member data source / SLO gate decisions / current selected endpoint, data source for `seepctl group`)
- Subscriptions: `GET|POST /subscriptions`, `POST /subscriptions/refresh`,
  `POST /subscriptions/{name}/refresh`, `DELETE /subscriptions/{name}`
- System routing (P1-3): `POST /network/route/apply` / `POST /network/route/clear`
  / `GET /network/route/status`
- Sensitive reads (token required): `GET /runtime/config` / `GET /events` / `GET /logs`

## Routing To A Mesh Target

Routing targets can use the prefix `mesh.` (or `mesh:`). For example:

```yaml
routing:
  default_node: mesh.exit1
```

When mesh + chain are enabled in the runtime, a route decision that resolves to `mesh.exit1` will be
upgraded to a `RouteDecision::Chain` via the `ChainManager`. The computed path will also be attached to
`FlowMetadata.annotations`:

- `seep.chain.path`: JSON array of node ids (e.g. `["client1","exit1"]`)
- `seep.route.reason`: the routing reason string (if present)

## Mesh Data-Plane Protocol

When `mesh` + `chain` are enabled, each node also listens on `MeshConfig.listen_address` (default
`0.0.0.0:9091`) for hop-by-hop forwarding.

> **Current-state note (updated 2026-09-30)**: the body of this section describes the **TCP plane**
> protocol (per-connection `MeshStream` bidirectional copy, one JSON `MeshEnvelope` header per connection).
> **The UDP data plane is implemented (todo P0-4, completed 2026-09)**: `UdpEnvelope` binary header over
> UDP datagrams, FULL/CACHED hop caching, exit per-flow socket with a downlink task, same-port dual stack
> (`spawn_udp` alongside TCP `spawn`), and the plaintext gate (env `SEEP_MESH_UDP_ALLOW_PLAINTEXT` union
> `MeshConfig.udp_allow_plaintext_data_plane`; chain+udp without configured encryption is **refused at
> build time**) -- spec and implementation in
> [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md) (the boundary chosen against the TCP plane
> is in its §1, the multi-hop TTL/dedup ruling in its §14);
> UDP-side observability and config in [design/udp-observability.md](design/udp-observability.md)
> (todo P0-5, **landed**: the `/udp/stats` snapshot + the `seep_udp_*` metric family + the ingress-level
> `udp_enabled` override).
> Per the original conditions of this note, the "(TCP, MVP)" qualifier in the title has been removed accordingly.

### mTLS (Recommended / Secure-by-default for chain)

- Enable mesh data-plane mTLS via env:
  - `SEEP_MESH_MTLS=1`
  - `SEEP_MESH_MTLS_CA=/path/to/ca.cert.pem`
  - `SEEP_MESH_MTLS_CERT=/path/to/<node>.cert.pem`
  - `SEEP_MESH_MTLS_KEY=/path/to/<node>.key.pem`
  - Optional: `SEEP_MESH_MTLS_SERVER_NAME=seep`
- When `chain` is enabled, seepd requires mTLS by default. For dev-only plaintext you can set:
  - `SEEP_MESH_ALLOW_PLAINTEXT=1`

#### CA Rotation (Bundle / dual trust window)

Seep supports pointing `SEEP_MESH_MTLS_CA` at a PEM file (bundle) holding **multiple CA certs**. The
recommended rotation flow:

1. Generate the new CA + bundle (old + new):
   - `seepctl mtls rotate-ca --old-ca-cert ca.cert.pem --out-dir ./mtls`
2. Distribute `./mtls/ca.bundle.pem` to all nodes and set `SEEP_MESH_MTLS_CA`; restart / roll out and enter the dual trust window
3. Re-issue each node's certificate with the new CA (`seepctl mtls rotate ... --ca-cert ./mtls/ca.next.cert.pem --ca-key ./mtls/ca.next.key.pem`)
4. Once the full switch is complete, converge `SEEP_MESH_MTLS_CA` from the bundle down to only the new CA

#### Revocation (minimal implementation)

- `SEEP_MESH_MTLS_REVOKED_NODES=nodeA,nodeB`: refuse mTLS connections from the named nodes by certificate CN (node_id); takes effect on restart.
- `SEEP_MESH_MTLS_REVOKED_NODES_FILE=/path/to/revoked.txt`: load the revocation list from a file, hot-reloaded (a change to the file mtime triggers a reload).

Helper commands (editing the revocation list file):
- `seepctl mtls revoke add --file revoked.txt --node-id nodeA`
- `seepctl mtls revoke remove --file revoked.txt --node-id nodeA`
- `seepctl mtls revoke list --file revoked.txt`

### Metrics

When `GET /metrics` is enabled, seepd exposes per-link counters (labels: `from`, `to`):
- `seep_mesh_link_bytes_total`
- `seep_mesh_link_connections_total`
- `seep_mesh_link_errors_total`

Chain-enabled deployments additionally render (P2-1, always rendered, absent while mesh is disabled):
- `seep_mesh_link_rtt_ms{from,to,quantile}` / `seep_mesh_link_loss_ratio{from,to}`
  / `seep_mesh_switch_total{reason}` — see
  [design/mesh-link-observability.md](design/mesh-link-observability.md)

UDP-side families (P0-5, same source as `/udp/stats`): `seep_udp_*` — see
[design/udp-observability.md](design/udp-observability.md); the mesh UDP replay
counter `seep_udp_mesh[_client]_replay_dropped_total` (P2-7).

### Wire Format (TCP plane, binary v2 since P2-6)

Each connection begins with one `[len: u32 BE][payload]` frame carrying the
`MeshEnvelope`. Since P2-6 the sender always emits the **binary** payload; the
receiver sniffs the first byte and stays compatible with the legacy JSON
framing (`{` → legacy JSON, `'S'` → binary):

```
+--------------------+----------------------------------+
| length (4 bytes BE)| binary v2 payload (or legacy JSON)|
+--------------------+----------------------------------+
```

Binary payload layout (big-endian, `MESH_ENVELOPE_BIN_VERSION = 2`,
`seep-runtime/src/mesh_transport.rs`):

```
magic(2)='SU' | struct_ver(1)=2 | flags(1)=0 (reserved) | env.version(4)
| flow_id_len(1) + flow_id | host_len(1) + target_host
| target_port(2) | hop_count(1) + [ node_len(1) + node_id ]*
| pad_len(4) + pad(0x00 × pad_len)
```

- Truncation / magic mismatch / struct version other than 2 / reserved bits non-zero / inconsistent pad are always Err (frame dropped).
- `pad_len > 0` requires `env.version ≥ PAD_ENVELOPE_VERSION` (P1-4 packet-length padding frames).
- Legacy JSON payload (receiver-side compatibility): `{"version":1,"flow_id":…,"target_host":…,`
  `"target_port":443,"path":[…]}`; trailing `0x00` padding is validated against `pad_len` (E7).
- Field semantics unchanged: `version` is the protocol version, `flow_id` the unique flow id,
  `target_host`/`target_port` the final destination, `path` the ordered node table (`path[0]` is the current node).

### Hop Behavior

1. **Relay Node**: If `path.len() > 1`, the node:
   - Strips `path[0]` (itself)
   - Connects to `path[1]` (next hop) via the mesh registry
   - Forwards the envelope with the shortened path
   - Bidirectionally copies data between inbound and outbound connections

2. **Exit Node**: If `path.len() == 1`, the node:
   - Connects directly to `target_host:target_port`
   - Bidirectionally copies data between client and target

### Example Flow

```
Client → Relay (path=[relay1, exit1]) → Exit (path=[exit1]) → Target
```

### Rust API

```rust
use seep_runtime::{MeshDataPlane, MeshEnvelope};
use seep_mesh::{MeshRegistry, NodeRecord, NodeRole};
use std::sync::Arc;

// Create data plane
let registry = Arc::new(MeshRegistry::new());
registry.register_node(NodeRecord::new(
    "my-node".into(),
    NodeRole::Hybrid,
    "0.0.0.0:9091".parse().unwrap(),
)).unwrap();
let plane = MeshDataPlane::new("my-node".into(), registry);

// Spawn listener
let handle = plane.spawn("0.0.0.0:9091".parse().unwrap());

// Or use dial_and_tunnel for outbound connections
let env = MeshEnvelope::new(
    "flow-id".into(),
    "target.example.com".into(),
    443,
    vec!["relay1".into(), "exit1".into()],
);
let flow_id = seep_core::FlowId::new();
plane
    .dial_and_tunnel(&"relay1".into(), &env, &mut io_stream, None, &flow_id)
    .await?;
```

## Minimal Example (curl)

Assume seepd is running on `127.0.0.1:9090` and `admin_token: seep`:

```bash
TOKEN=seep
BASE=http://127.0.0.1:9090

# register nodes
curl -sS -X POST "$BASE/mesh/nodes/register" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"id":"client1","role":"client","addr":"127.0.0.1:10001"}'

curl -sS -X POST "$BASE/mesh/nodes/register" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"id":"exit1","role":"exit","addr":"127.0.0.1:10002"}'

# publish link-state (directed edge)
curl -sS -X POST "$BASE/mesh/link-states" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"source":"client1","target":"exit1","latency_ms":20,"bandwidth_mbps":100,"packet_loss_rate":0.0}'

# dry-run (pre-check)
curl -sS -X POST "$BASE/chains/dry-run" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"source":"client1","target":"exit1"}'

# create chain
curl -sS -X POST "$BASE/chains" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"source":"client1","target":"exit1"}'
```

## Minimal Example (seepctl)

`seepctl` reads `control.api_bind` / `control.admin_token` from your config:

```bash
seepctl -c config/seep.yaml chain dry-run --source client1 --target exit1
seepctl -c config/seep.yaml chain create  --source client1 --target exit1
seepctl -c config/seep.yaml chain stats
```

## Security Notes (current status, 2026-10)

- mTLS on the mesh data-plane is **required by default** when `chain` is enabled
  (`SEEP_MESH_ALLOW_PLAINTEXT=1` only for dev). CA bundle dual-trust rotation and a
  minimal revocation list (by node cert CN, file hot-reload) are implemented — see above
  and [architecture.md](architecture.md).
- `NodeACL` (client CIDR / role restrictions) and `NodeQuota` (bandwidth / connection
  limits) are enforced at the registry layer.
- **UDP data-plane replay protection** (todo P2-7, 2026-10-04): per-(flow, dir)
  RFC4303-style 64-bit sliding window over v2 envelopes with flow sequence numbers
  (`UDP_FLAG_HAS_SEQ`). Rejected replays / out-of-window frames are dropped silently
  and counted (`replay_dropped`) in `/udp/stats` (mesh + mesh_client) and `/metrics`
  (`seep_udp_mesh[_client]_replay_dropped_total`); v1 frames bypass the window
  (fail-open during mixed-deployment window). Design: [design/mesh-advanced-security.md](design/mesh-advanced-security.md) §3.
- **Revocation distribution visibility** (todo P2-7, 2026-10-04): the revoked-list
  file hot-reload is now verifiable at runtime — `GET /mtls/revoked` (control plane)
  + `seepctl mtls revoke status` show the loaded file state (mtime / entries /
  load errors), closing the distribute—take-effect—verify loop. OCSP stays out of
  scope (needs direct CA connectivity, V2).
- Still NOT implemented (todo P2-7): end-to-end multi-hop MAC / authentication —
  there is no node public-key distribution or per-session key negotiation to anchor
  an HMAC on (see §6 deviation 1 of the design doc above).
