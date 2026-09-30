# Mesh & Chain Guide (MVP)

This document describes the current MVP-level mesh control plane and chain (multi-hop path) building.

## Concepts

- `NodeId`: a string identifier for a mesh node (e.g. `client1`, `exit1`).
- `NodeRole`: `client` / `relay` / `exit` / `hybrid`.
- `link-state`: directed edge metrics between two nodes (latency/bandwidth/loss).
- `chain`: a computed path from a source node to a target node. In the current MVP, Seep can *compute*
  chains and attach path metadata to flows. TCP flows can also be forwarded hop-by-hop via the mesh
  data-plane listener (supports optional mTLS for encryption/authentication); UDP flows are forwarded
  hop-by-hop since P0-4 (`UdpEnvelope` over UDP datagrams, same port dual-stack — MVP plaintext gate,
  encryption selection remains V2).

## Control Plane (seepd)

Configured by `control.api_bind` in `SeepConfig` (default example in `config/seep.yaml`).

Auth:
- If `control.admin_token` is set, mutating requests must include either:
  - `X-Admin-Token: <token>` or
  - `Authorization: Bearer <token>`

Endpoints:
- `GET /health`
- `GET /nodes` (mesh node snapshots)
- `POST /mesh/nodes/register` (register/update a node)
- `POST /mesh/link-states` (update directed link-state)
- `POST /chains/dry-run` (chain build pre-check)
- `POST /chains` (create/reuse chain; uses a session_id UUID)
- `GET /chains/{chain_id}`
- `DELETE /chains/{chain_id}`
- `GET /chains/stats`

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

> **现状注记（2026-09-30 更新）**：本节正文描述 **TCP 面**协议（逐连接 `MeshStream` 双向拷贝，每连接一个 JSON `MeshEnvelope` 头）。
> **UDP 数据面已实现（todo P0-4，2026-09 完成）**：`UdpEnvelope` 二进制头 over UDP 数据报、FULL/CACHED 跳缓存、
> exit per-flow socket 与下行 task、同端口双栈（`spawn_udp` 与 TCP `spawn` 并列）、明文门（env
> `SEEP_MESH_UDP_ALLOW_PLAINTEXT` ∪ `MeshConfig.udp_allow_plaintext_data_plane`，chain+udp 未配加密时**构建期拒绝启动**）——
> 规格与实施见 [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md)（与 TCP 面的选择边界见其 §1，多跳 TTL/去重裁决见其 §14）；
> UDP 侧观测与配置见 [design/udp-observability.md](design/udp-observability.md)（todo P0-5，未落地）。
> 按本注记原设条件，标题的 "(TCP, MVP)" 限定已随之移除。

### mTLS (Recommended / Secure-by-default for chain)

- Enable mesh data-plane mTLS via env:
  - `SEEP_MESH_MTLS=1`
  - `SEEP_MESH_MTLS_CA=/path/to/ca.cert.pem`
  - `SEEP_MESH_MTLS_CERT=/path/to/<node>.cert.pem`
  - `SEEP_MESH_MTLS_KEY=/path/to/<node>.key.pem`
  - Optional: `SEEP_MESH_MTLS_SERVER_NAME=seep`
- When `chain` is enabled, seepd requires mTLS by default. For dev-only plaintext you can set:
  - `SEEP_MESH_ALLOW_PLAINTEXT=1`

#### CA Rotation (Bundle / 双信任窗口)

Seep 支持把 `SEEP_MESH_MTLS_CA` 指向一个包含 **多个 CA cert** 的 PEM 文件（bundle）。推荐轮换流程：

1. 生成新 CA + bundle（旧+新）：
   - `seepctl mtls rotate-ca --old-ca-cert ca.cert.pem --out-dir ./mtls`
2. 将 `./mtls/ca.bundle.pem` 下发到所有节点并设置 `SEEP_MESH_MTLS_CA`，重启/滚动更新，进入双信任窗口
3. 逐个节点用新 CA 重签证书（`seepctl mtls rotate ... --ca-cert ./mtls/ca.next.cert.pem --ca-key ./mtls/ca.next.key.pem`）
4. 全量切换完成后，将 `SEEP_MESH_MTLS_CA` 从 bundle 收敛为仅新 CA

#### Revocation (最小实现)

- `SEEP_MESH_MTLS_REVOKED_NODES=nodeA,nodeB`：按证书 CN（node_id）拒绝指定节点的 mTLS 连接（需重启生效）。
- `SEEP_MESH_MTLS_REVOKED_NODES_FILE=/path/to/revoked.txt`：从文件加载撤销列表，支持热加载（文件 mtime 变化会触发 reload）。

辅助命令（编辑撤销列表文件）：
- `seepctl mtls revoke add --file revoked.txt --node-id nodeA`
- `seepctl mtls revoke remove --file revoked.txt --node-id nodeA`
- `seepctl mtls revoke list --file revoked.txt`

### Metrics

When `GET /metrics` is enabled, seepd exposes per-link counters (labels: `from`, `to`):
- `seep_mesh_link_bytes_total`
- `seep_mesh_link_connections_total`
- `seep_mesh_link_errors_total`

### Wire Format

Each connection begins with a `MeshEnvelope` header:

```
+------------------+--------------------+
| length (4 bytes) | JSON payload       |
+------------------+--------------------+
```

- `length`: u32 big-endian, the size of the JSON payload (max 64KB)
- JSON payload: `MeshEnvelope` structure

### MeshEnvelope Structure

```json
{
  "version": 1,
  "flow_id": "uuid-string",
  "target_host": "example.com",
  "target_port": 443,
  "path": ["client1", "relay1", "exit1"]
}
```

- `version`: Protocol version (currently 1)
- `flow_id`: Unique identifier for this flow
- `target_host`: Final destination hostname/IP
- `target_port`: Final destination port
- `path`: Ordered list of node IDs; `path[0]` is the current node

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
plane.dial_and_tunnel(&"relay1".into(), &env, &mut io_stream).await?;
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

## Security Notes (current status, 2026-09)

- mTLS on the mesh data-plane is **required by default** when `chain` is enabled
  (`SEEP_MESH_ALLOW_PLAINTEXT=1` only for dev). CA bundle dual-trust rotation and a
  minimal revocation list (by node cert CN, file hot-reload) are implemented — see above
  and [architecture.md](architecture.md).
- `NodeACL` (client CIDR / role restrictions) and `NodeQuota` (bandwidth / connection
  limits) are enforced at the registry layer.
- Still NOT implemented (todo P2-7): end-to-end multi-hop MAC / replay protection,
  CRL/OCSP auto-distribution.
