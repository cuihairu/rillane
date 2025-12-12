# Mesh & Chain Guide (MVP)

This document describes the current MVP-level mesh control plane and chain (multi-hop path) building.

## Concepts

- `NodeId`: a string identifier for a mesh node (e.g. `client1`, `exit1`).
- `NodeRole`: `client` / `relay` / `exit` / `hybrid`.
- `link-state`: directed edge metrics between two nodes (latency/bandwidth/loss).
- `chain`: a computed path from a source node to a target node. In the current MVP, Seep can *compute*
  chains and attach path metadata to flows, while the actual multi-hop data-plane forwarding is still a
  follow-up task.

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

