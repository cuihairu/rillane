# Mesh & Chain Guide (MVP)

This document describes the current MVP-level mesh control plane and chain (multi-hop path) building.

## Concepts

- `NodeId`: a string identifier for a mesh node (e.g. `client1`, `exit1`).
- `NodeRole`: `client` / `relay` / `exit` / `hybrid`.
- `link-state`: directed edge metrics between two nodes (latency/bandwidth/loss).
- `chain`: a computed path from a source node to a target node. In the current MVP, Rillane can *compute*
  chains and attach path metadata to flows. TCP flows can also be forwarded hop-by-hop via the mesh
  data-plane listener (supports optional mTLS for encryption/authentication); UDP flows are forwarded
  hop-by-hop since P0-4 (`UdpEnvelope` over UDP datagrams, same port dual-stack — MVP plaintext gate,
  encryption selection remains V2).

## Control Plane (rillaned)

Configured by `control.api_bind` in `RillaneConfig` (default example in `config/rillane.yaml`).

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
- `GET /mesh/switches` (最近 100 次 chain 切换事件，P2-1；`rillanectl switches` 取数面)
- `GET /mtls/revoked` (撤销列表加载状态：mtime / 条目 / 加载错误，P2-7)
- `POST /chains/dry-run` (chain build pre-check)
- `POST /chains` (create/reuse chain; uses a session_id UUID)
- `GET /chains/{chain_id}`
- `DELETE /chains/{chain_id}`
- `GET /chains/stats`

Other control-plane endpoints (outside mesh scope, dispatcher in
`apps/rillaned/src/control_plane.rs`):
- Observability: `GET /flows` / `GET /metrics` / `GET /udp/stats` /
  `GET /egress/pool/stats` / `GET /dns/stats` / `GET /runtime/stats` /
  `GET /routing/stats`（组实时质量：成员数据源/SLO 门判定/当前选点，`rillanectl group` 取数面）
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

- `rillane.chain.path`: JSON array of node ids (e.g. `["client1","exit1"]`)
- `rillane.route.reason`: the routing reason string (if present)

## Mesh Data-Plane Protocol

When `mesh` + `chain` are enabled, each node also listens on `MeshConfig.listen_address` (default
`0.0.0.0:9091`) for hop-by-hop forwarding.

> **现状注记（2026-09-30 更新）**：本节正文描述 **TCP 面**协议（逐连接 `MeshStream` 双向拷贝，每连接一个 JSON `MeshEnvelope` 头）。
> **UDP 数据面已实现（todo P0-4，2026-09 完成）**：`UdpEnvelope` 二进制头 over UDP 数据报、FULL/CACHED 跳缓存、
> exit per-flow socket 与下行 task、同端口双栈（`spawn_udp` 与 TCP `spawn` 并列）、明文门（env
> `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` ∪ `MeshConfig.udp_allow_plaintext_data_plane`，chain+udp 未配加密时**构建期拒绝启动**）——
> 规格与实施见 [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md)（与 TCP 面的选择边界见其 §1，多跳 TTL/去重裁决见其 §14）；
> UDP 侧观测与配置见 [design/udp-observability.md](design/udp-observability.md)
> （todo P0-5，**已落地**：`/udp/stats` 快照 + `rillane_udp_*` 指标族 + 入口级 `udp_enabled` 覆盖）。
> 按本注记原设条件，标题的 "(TCP, MVP)" 限定已随之移除。

### mTLS (Recommended / Secure-by-default for chain)

- Enable mesh data-plane mTLS via env:
  - `RILLANE_MESH_MTLS=1`
  - `RILLANE_MESH_MTLS_CA=/path/to/ca.cert.pem`
  - `RILLANE_MESH_MTLS_CERT=/path/to/<node>.cert.pem`
  - `RILLANE_MESH_MTLS_KEY=/path/to/<node>.key.pem`
  - Optional: `RILLANE_MESH_MTLS_SERVER_NAME=rillane`
- Client-certificate enforcement and peer-check controls (defaults; the full env-var table is in [config.md](config.md) "Environment variables"):
  - `RILLANE_MESH_MTLS_REQUIRE_CLIENT_AUTH=true` -- enforces client certificate validation (keep it on in production; bypassing needs `RILLANE_MESH_ALLOW_NO_CLIENT_AUTH=1`)
  - `RILLANE_MESH_MTLS_VERIFY_PEER_NODE_ID=true` -- checks the peer certificate CN against the node ID
  - `RILLANE_MESH_MTLS_ALLOW_UNKNOWN_PEERS=false` -- allow unknown node certificates
- When `chain` is enabled, rillaned requires mTLS by default. For dev-only plaintext you can set:
  - `RILLANE_MESH_ALLOW_PLAINTEXT=1`

#### CA Rotation (Bundle / 双信任窗口)

Rillane 支持把 `RILLANE_MESH_MTLS_CA` 指向一个包含 **多个 CA cert** 的 PEM 文件（bundle）。推荐轮换流程：

1. 生成新 CA + bundle（旧+新）：
   - `rillanectl mtls rotate-ca --old-ca-cert ca.cert.pem --out-dir ./mtls`
2. 将 `./mtls/ca.bundle.pem` 下发到所有节点并设置 `RILLANE_MESH_MTLS_CA`，重启/滚动更新，进入双信任窗口
3. 逐个节点用新 CA 重签证书（`rillanectl mtls rotate ... --ca-cert ./mtls/ca.next.cert.pem --ca-key ./mtls/ca.next.key.pem`）
4. 全量切换完成后，将 `RILLANE_MESH_MTLS_CA` 从 bundle 收敛为仅新 CA

#### Revocation (最小实现)

- `RILLANE_MESH_MTLS_REVOKED_NODES=nodeA,nodeB`：按证书 CN（node_id）拒绝指定节点的 mTLS 连接（需重启生效）。
- `RILLANE_MESH_MTLS_REVOKED_NODES_FILE=/path/to/revoked.txt`：从文件加载撤销列表，支持热加载（文件 mtime 变化会触发 reload）。

辅助命令（编辑撤销列表文件）：
- `rillanectl mtls revoke add --file revoked.txt --node-id nodeA`
- `rillanectl mtls revoke remove --file revoked.txt --node-id nodeA`
- `rillanectl mtls revoke list --file revoked.txt`

### Metrics

When `GET /metrics` is enabled, rillaned exposes per-link counters (labels: `from`, `to`):
- `rillane_mesh_link_bytes_total`
- `rillane_mesh_link_connections_total`
- `rillane_mesh_link_errors_total`

Chain-enabled deployments additionally render (P2-1, 恒渲染，mesh 未启用则缺席):
- `rillane_mesh_link_rtt_ms{from,to,quantile}` / `rillane_mesh_link_loss_ratio{from,to}`
  / `rillane_mesh_switch_total{reason}` — see
  [design/mesh-link-observability.md](design/mesh-link-observability.md)

UDP-side families (P0-5, 与 `/udp/stats` 同源): `rillane_udp_*` — see
[design/udp-observability.md](design/udp-observability.md); mesh UDP replay
counter `rillane_udp_mesh[_client]_replay_dropped_total` (P2-7).

### Wire Format (TCP 面，P2-6 起二进制 v2)

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
`rillane-runtime/src/mesh_transport.rs`):

```
magic(2)='SU' | struct_ver(1)=2 | flags(1)=0 (保留) | env.version(4)
| flow_id_len(1) + flow_id | host_len(1) + target_host
| target_port(2) | hop_count(1) + [ node_len(1) + node_id ]*
| pad_len(4) + pad(0x00 × pad_len)
```

- 截断 / magic 不符 / 结构版本非 2 / 保留位非 0 / pad 不一致一律 Err（帧丢弃）。
- `pad_len > 0` 要求 `env.version ≥ PAD_ENVELOPE_VERSION`（P1-4 包长填充帧）。
- Legacy JSON payload（接收侧兼容）：`{"version":1,"flow_id":…,"target_host":…,`
  `"target_port":443,"path":[…]}`，尾部 `0x00` 填充按 `pad_len` 校验（E7）。
- 字段语义不变：`version` 协议版本、`flow_id` 流唯一标识、
  `target_host`/`target_port` 最终目的地、`path` 有序节点表（`path[0]` 为当前节点）。

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
use rillane_runtime::{MeshDataPlane, MeshEnvelope};
use rillane_mesh::{MeshRegistry, NodeRecord, NodeRole};
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
let flow_id = rillane_core::FlowId::new();
plane
    .dial_and_tunnel(&"relay1".into(), &env, &mut io_stream, None, &flow_id)
    .await?;
```

## Minimal Example (curl)

Assume rillaned is running on `127.0.0.1:9090` and `admin_token: rillane`:

```bash
TOKEN=rillane
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
  -d '{
          "source": "client1",
          "target": "exit1",
          "latency_ms": 20,
          "bandwidth_mbps": 100,
          "packet_loss_rate": 0.0
        }'

# dry-run (pre-check)
curl -sS -X POST "$BASE/chains/dry-run" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"source":"client1","target":"exit1"}'

# create chain
curl -sS -X POST "$BASE/chains" \
  -H "content-type: application/json" -H "x-admin-token: $TOKEN" \
  -d '{"source":"client1","target":"exit1"}'
```

## Minimal Example (rillanectl)

`rillanectl` reads `control.api_bind` / `control.admin_token` from your config:

```bash
rillanectl -c config/rillane.yaml chain dry-run --source client1 --target exit1
rillanectl -c config/rillane.yaml chain create  --source client1 --target exit1
rillanectl -c config/rillane.yaml chain stats
```

## Security Notes (current status, 2026-10)

- mTLS on the mesh data-plane is **required by default** when `chain` is enabled
  (`RILLANE_MESH_ALLOW_PLAINTEXT=1` only for dev). CA bundle dual-trust rotation and a
  minimal revocation list (by node cert CN, file hot-reload) are implemented — see above
  and [architecture.md](architecture.md).
- `NodeACL` (client CIDR / role restrictions) and `NodeQuota` (bandwidth / connection
  limits) are enforced at the registry layer.
- **UDP data-plane replay protection** (todo P2-7, 2026-10-04): per-(flow, dir)
  RFC4303-style 64-bit sliding window over v2 envelopes with flow sequence numbers
  (`UDP_FLAG_HAS_SEQ`). Rejected replays / out-of-window frames are dropped silently
  and counted (`replay_dropped`) in `/udp/stats` (mesh + mesh_client) and `/metrics`
  (`rillane_udp_mesh[_client]_replay_dropped_total`); v1 frames bypass the window
  (fail-open during mixed-deployment window). Design: [design/mesh-advanced-security.md](design/mesh-advanced-security.md) §3.
- **Revocation distribution visibility** (todo P2-7, 2026-10-04): the revoked-list
  file hot-reload is now verifiable at runtime — `GET /mtls/revoked` (control plane)
  + `rillanectl mtls revoke status` show the loaded file state (mtime / entries /
  load errors), closing the distribute—take-effect—verify loop. OCSP stays out of
  scope (needs direct CA connectivity, V2).
- Still NOT implemented (todo P2-7): end-to-end multi-hop MAC / authentication —
  there is no node public-key distribution or per-session key negotiation to anchor
  an HMAC on (see §6 deviation 1 of the design doc above).
