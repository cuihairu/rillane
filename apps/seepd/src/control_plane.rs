use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Instant};

use hyper::{
    body,
    header::{AUTHORIZATION, CONTENT_TYPE},
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use serde::{Deserialize, Serialize};

use seep_mesh::{LinkState, MeshRegistry, NodeCapability, NodeRecord, NodeRole};
use seep_runtime::{ChainConstraints, Runtime};

#[derive(Clone)]
pub struct ControlPlane {
    runtime: Arc<Runtime>,
    admin_token: Option<String>,
}

impl ControlPlane {
    pub fn new(runtime: Arc<Runtime>, admin_token: Option<String>) -> Self {
        Self { runtime, admin_token }
    }

    pub async fn serve(self, bind: SocketAddr, shutdown: tokio::sync::oneshot::Receiver<()>) -> anyhow::Result<()> {
        let make = make_service_fn(move |_conn| {
            let state = self.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let state = state.clone();
                    async move { Ok::<_, Infallible>(state.handle(req).await) }
                }))
            }
        });

        Server::bind(&bind)
            .serve(make)
            .with_graceful_shutdown(async move {
                let _ = shutdown.await;
            })
            .await?;
        Ok(())
    }

    async fn handle(&self, req: Request<Body>) -> Response<Body> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Cheap health check.
        if method == Method::GET && path == "/health" {
            return text(StatusCode::OK, "ok");
        }

        // Read-only endpoints don't require auth; mutating endpoints do (if token configured).
        let is_mutating = matches!(method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE);
        if is_mutating && self.admin_token.is_some() && !self.is_authorized(&req) {
            return text(StatusCode::UNAUTHORIZED, "unauthorized");
        }

        match (method, path.as_str()) {
            (Method::GET, "/nodes") => self.handle_nodes().await,
            (Method::GET, "/flows") => json(StatusCode::OK, &Vec::<FlowStatItemDto>::new()),
            (Method::POST, "/mesh/nodes/register") => self.handle_register_node(req).await,
            (Method::POST, "/mesh/link-states") => self.handle_update_link_state(req).await,

            (Method::POST, "/chains/dry-run") => self.handle_chain_dry_run(req).await,
            (Method::POST, "/chains") => self.handle_chain_create(req).await,
            (Method::GET, "/chains/stats") => self.handle_chain_stats().await,

            // /chains/{chain_id}
            (Method::GET, p) if p.starts_with("/chains/") => self.handle_chain_get(p).await,
            (Method::DELETE, p) if p.starts_with("/chains/") => self.handle_chain_delete(p).await,

            _ => text(StatusCode::NOT_FOUND, "not found"),
        }
    }

    fn is_authorized(&self, req: &Request<Body>) -> bool {
        let Some(expected) = self.admin_token.as_deref() else {
            return true;
        };

        // Accept either `Authorization: Bearer <token>` or `X-Admin-Token: <token>`.
        if let Some(v) = req.headers().get("x-admin-token").and_then(|v| v.to_str().ok()) {
            return v == expected;
        }
        if let Some(v) = req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
            return v.strip_prefix("Bearer ").map(|t| t == expected).unwrap_or(false);
        }
        false
    }

    fn mesh(&self) -> Result<Arc<MeshRegistry>, Response<Body>> {
        self.runtime
            .get_mesh_registry()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "mesh not enabled"))
    }

    fn chain_mgr(&self) -> Result<Arc<seep_runtime::ChainManager>, Response<Body>> {
        self.runtime
            .get_chain_manager()
            .ok_or_else(|| text(StatusCode::SERVICE_UNAVAILABLE, "chain not enabled"))
    }

    async fn handle_nodes(&self) -> Response<Body> {
        let registry = match self.mesh() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let snapshots = registry.get_all_node_snapshots();
        let nodes: Vec<MeshNodeDto> = snapshots
            .into_iter()
            .map(|s| MeshNodeDto {
                id: s.id,
                role: s.role.to_string(),
                addr: s.addr,
                capability: s.capability,
                online: s.online,
                last_seen_seconds: s.last_seen_seconds,
            })
            .collect();

        json(StatusCode::OK, &nodes)
    }

    async fn handle_register_node(&self, req: Request<Body>) -> Response<Body> {
        let registry = match self.mesh() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: RegisterNodeRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let role = match dto.role.as_str() {
            "client" => NodeRole::Client,
            "relay" => NodeRole::Relay,
            "exit" => NodeRole::Exit,
            "hybrid" => NodeRole::Hybrid,
            _ => return text(StatusCode::BAD_REQUEST, "invalid role"),
        };

        let addr: SocketAddr = match dto.addr.parse() {
            Ok(v) => v,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid addr"),
        };

        let mut record = NodeRecord::new(dto.id.clone(), role, addr);
        if let Some(cap) = dto.capability {
            record.capability = cap;
        }
        if let Err(e) = registry.register_node(record) {
            return text(StatusCode::BAD_REQUEST, &format!("register failed: {e}"));
        }

        json(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    async fn handle_update_link_state(&self, req: Request<Body>) -> Response<Body> {
        let registry = match self.mesh() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: LinkStateUpdateRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let link = LinkState {
            source: dto.source,
            target: dto.target,
            latency_ms: dto.latency_ms,
            bandwidth_mbps: dto.bandwidth_mbps,
            packet_loss_rate: dto.packet_loss_rate,
            last_updated: Instant::now(),
        };

        if let Err(e) = registry.update_link_state(link) {
            return text(StatusCode::BAD_REQUEST, &format!("update link state failed: {e}"));
        }

        json(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    async fn handle_chain_dry_run(&self, req: Request<Body>) -> Response<Body> {
        let dto: ChainDryRunRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let constraints = dto.constraints.map(Into::into);
        let res = self
            .runtime
            .dry_run_chain(&dto.source, &dto.target, constraints)
            .await;

        match res {
            Ok(r) => json(StatusCode::OK, &r),
            Err(e) => text(StatusCode::BAD_REQUEST, &format!("dry-run failed: {e}")),
        }
    }

    async fn handle_chain_create(&self, req: Request<Body>) -> Response<Body> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let dto: ChainCreateRequest = match read_json(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };

        let session_id = dto
            .session_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let session_uuid = match uuid::Uuid::parse_str(&session_id) {
            Ok(v) => v,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid session_id"),
        };

        let constraints: Option<ChainConstraints> = dto.constraints.map(Into::into);
        let chain = mgr
            .get_or_create_chain(session_uuid, &dto.source, &dto.target, constraints)
            .await;

        match chain {
            Ok(ctx) => json(StatusCode::OK, &ChainContextDto::from(ctx)),
            Err(e) => text(StatusCode::BAD_REQUEST, &format!("create chain failed: {e}")),
        }
    }

    async fn handle_chain_get(&self, path: &str) -> Response<Body> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let chain_id = path.trim_start_matches("/chains/").trim();
        if chain_id.is_empty() || chain_id == "stats" {
            return text(StatusCode::NOT_FOUND, "not found");
        }

        match mgr.get_chain(chain_id) {
            Some(ctx) => json(StatusCode::OK, &ChainContextDto::from(ctx)),
            None => text(StatusCode::NOT_FOUND, "chain not found"),
        }
    }

    async fn handle_chain_delete(&self, path: &str) -> Response<Body> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };

        let chain_id = path.trim_start_matches("/chains/").trim();
        if chain_id.is_empty() || chain_id == "stats" {
            return text(StatusCode::NOT_FOUND, "not found");
        }

        match mgr.terminate_chain(chain_id).await {
            Ok(()) => json(StatusCode::OK, &serde_json::json!({ "ok": true })),
            Err(e) => text(StatusCode::BAD_REQUEST, &format!("terminate failed: {e}")),
        }
    }

    async fn handle_chain_stats(&self) -> Response<Body> {
        let mgr = match self.chain_mgr() {
            Ok(v) => v,
            Err(r) => return r,
        };
        let stats = mgr.get_stats().await;
        json(StatusCode::OK, &stats)
    }
}

#[derive(Debug, Clone, Serialize)]
struct MeshNodeDto {
    id: String,
    role: String,
    addr: String,
    capability: NodeCapability,
    online: bool,
    last_seen_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
struct FlowStatItemDto {
    ingress: String,
    egress: String,
    flows: u64,
    upstream: u64,
    downstream: u64,
}

#[derive(Debug, Deserialize)]
struct RegisterNodeRequest {
    id: String,
    role: String,
    addr: String,
    #[serde(default)]
    capability: Option<NodeCapability>,
}

#[derive(Debug, Deserialize)]
struct LinkStateUpdateRequest {
    source: String,
    target: String,
    latency_ms: u32,
    bandwidth_mbps: u32,
    #[serde(default)]
    packet_loss_rate: f32,
}

#[derive(Debug, Deserialize)]
struct ChainDryRunRequest {
    source: String,
    target: String,
    #[serde(default)]
    constraints: Option<ChainConstraintsDto>,
}

#[derive(Debug, Deserialize)]
struct ChainCreateRequest {
    #[serde(default)]
    session_id: Option<String>,
    source: String,
    target: String,
    #[serde(default)]
    constraints: Option<ChainConstraintsDto>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct ChainConstraintsDto {
    #[serde(default)]
    max_hops: Option<usize>,
    #[serde(default)]
    max_latency_ms: Option<u32>,
    #[serde(default)]
    min_bandwidth_mbps: Option<u32>,
    #[serde(default)]
    required_nodes: Vec<String>,
    #[serde(default)]
    forbidden_nodes: Vec<String>,
    #[serde(default)]
    required_countries: Vec<String>,
    #[serde(default)]
    forbidden_countries: Vec<String>,
}

impl From<ChainConstraintsDto> for ChainConstraints {
    fn from(v: ChainConstraintsDto) -> Self {
        Self {
            max_hops: v.max_hops,
            max_latency_ms: v.max_latency_ms,
            min_bandwidth_mbps: v.min_bandwidth_mbps,
            required_nodes: v.required_nodes,
            forbidden_nodes: v.forbidden_nodes,
            required_countries: v.required_countries,
            forbidden_countries: v.forbidden_countries,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ChainContextDto {
    chain_id: String,
    source_node: String,
    target_node: String,
    current_path: Vec<String>,
    hop_count: usize,
    hop_latencies: Vec<u32>,
    hop_bandwidths: Vec<u32>,
    reliability_score: f32,
    status: String,
    fallback_paths: Vec<Vec<String>>,
    current_fallback_index: usize,
    created_at_seconds: u64,
    last_updated_seconds: u64,
}

impl From<seep_core::ChainContext> for ChainContextDto {
    fn from(v: seep_core::ChainContext) -> Self {
        Self {
            chain_id: v.chain_id,
            source_node: v.source_node,
            target_node: v.target_node,
            current_path: v.current_path,
            hop_count: v.hop_count,
            hop_latencies: v.hop_latencies,
            hop_bandwidths: v.hop_bandwidths,
            reliability_score: v.reliability_score,
            status: format!("{:?}", v.status),
            fallback_paths: v.fallback_paths,
            current_fallback_index: v.current_fallback_index,
            created_at_seconds: v.created_at.elapsed().as_secs(),
            last_updated_seconds: v.last_updated.elapsed().as_secs(),
        }
    }
}

async fn read_json<T: for<'de> Deserialize<'de>>(req: Request<Body>) -> Result<T, Response<Body>> {
    let bytes = body::to_bytes(req.into_body())
        .await
        .map_err(|_| text(StatusCode::BAD_REQUEST, "invalid body"))?;
    serde_json::from_slice::<T>(&bytes).map_err(|e| text(StatusCode::BAD_REQUEST, &format!("invalid json: {e}")))
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(buf) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(buf))
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
        Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("internal error")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_config::SeepConfig;
    use seep_runtime::{RuntimeBuilder, RuntimeConfig};

    async fn build_runtime(mesh: bool, chain: bool) -> Arc<Runtime> {
        let cfg_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/seep.yaml");
        let cfg = SeepConfig::load_from_path(cfg_path).unwrap();
        let rt_cfg = RuntimeConfig {
            enable_mesh: mesh,
            enable_chain: chain,
            ..RuntimeConfig::default()
        };
        Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(rt_cfg)
                .build()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn nodes_requires_mesh_enabled() {
        let runtime = build_runtime(false, false).await;
        let cp = ControlPlane::new(runtime, None);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/nodes")
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn can_register_node_when_mesh_enabled() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/mesh/nodes/register")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"id":"n1","role":"relay","addr":"127.0.0.1:10001"}"#,
            ))
            .unwrap();
        let resp = cp.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dry_run_and_create_chain_via_control_plane() {
        let runtime = build_runtime(true, true).await;
        let cp = ControlPlane::new(runtime, None);

        // Register nodes.
        let reg = |id: &str, role: &str, port: u16| {
            Request::builder()
                .method(Method::POST)
                .uri("/mesh/nodes/register")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"id":"{id}","role":"{role}","addr":"127.0.0.1:{port}"}}"#
                )))
                .unwrap()
        };
        assert_eq!(cp.handle(reg("client1", "client", 10001)).await.status(), StatusCode::OK);
        assert_eq!(cp.handle(reg("exit1", "exit", 10002)).await.status(), StatusCode::OK);

        // Provide link-state so ChainBuilder uses mesh topology edges.
        let link = Request::builder()
            .method(Method::POST)
            .uri("/mesh/link-states")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"source":"client1","target":"exit1","latency_ms":20,"bandwidth_mbps":100,"packet_loss_rate":0.0}"#,
            ))
            .unwrap();
        assert_eq!(cp.handle(link).await.status(), StatusCode::OK);

        // Dry-run should succeed.
        let dry = Request::builder()
            .method(Method::POST)
            .uri("/chains/dry-run")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(dry).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("success").and_then(|x| x.as_bool()), Some(true));

        // Create chain and query it back.
        let create = Request::builder()
            .method(Method::POST)
            .uri("/chains")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"source":"client1","target":"exit1"}"#))
            .unwrap();
        let resp = cp.handle(create).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let chain_id = v.get("chain_id").and_then(|x| x.as_str()).unwrap().to_string();

        let get = Request::builder()
            .method(Method::GET)
            .uri(format!("/chains/{chain_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = cp.handle(get).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
