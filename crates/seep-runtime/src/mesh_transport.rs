//! Minimal mesh data-plane transport (TCP only).
//!
//! This implements a simple "hop-by-hop" forwarding protocol between Seep nodes.
//! It is intentionally minimal and currently has no authentication/encryption.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    task::JoinHandle,
};

use seep_core::IoStream;
use seep_mesh::{MeshRegistry, NodeId};

const MAX_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    pub version: u32,
    pub flow_id: String,
    pub target_host: String,
    pub target_port: u16,
    /// Remaining path including the current node id as the first element.
    pub path: Vec<NodeId>,
}

impl MeshEnvelope {
    pub fn new(flow_id: String, target_host: String, target_port: u16, path: Vec<NodeId>) -> Self {
        Self {
            version: 1,
            flow_id,
            target_host,
            target_port,
            path,
        }
    }
}

pub struct MeshDataPlane {
    local_node_id: NodeId,
    registry: Arc<MeshRegistry>,
}

impl MeshDataPlane {
    pub fn new(local_node_id: NodeId, registry: Arc<MeshRegistry>) -> Self {
        Self {
            local_node_id,
            registry,
        }
    }

    pub fn spawn(self, bind: SocketAddr) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { self.serve(bind).await })
    }

    async fn serve(self, bind: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind).await?;
        loop {
            let (stream, _peer) = listener.accept().await?;
            let this = Self {
                local_node_id: self.local_node_id.clone(),
                registry: self.registry.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = this.handle(stream).await {
                    tracing::debug!(target: "seep::mesh::transport", error = %e, "mesh transport connection closed");
                }
            });
        }
    }

    async fn handle(&self, mut inbound: TcpStream) -> Result<()> {
        let env = read_envelope(&mut inbound).await?;
        if env.version != 1 {
            return Err(anyhow!("unsupported mesh envelope version {}", env.version));
        }
        if env.path.is_empty() {
            return Err(anyhow!("empty mesh path"));
        }

        // Best-effort validation (don't hard fail on mismatch to keep MVP resilient).
        if env.path[0] != self.local_node_id {
            tracing::debug!(
                target: "seep::mesh::transport",
                expected = %self.local_node_id,
                got = %env.path[0],
                "mesh envelope path[0] does not match local node id"
            );
        }

        if env.path.len() == 1 {
            // Final hop: connect to the real target.
            let mut out = connect_target(&env.target_host, env.target_port).await?;
            let _ = copy_bidirectional(&mut inbound, &mut out).await?;
            return Ok(());
        }

        // Relay hop: forward to next node.
        let next = env.path[1].clone();
        let next_addr = self
            .registry
            .get_node_addr(&next)
            .ok_or_else(|| anyhow!("next hop {next} not found in registry"))?;

        let mut outbound = TcpStream::connect(next_addr).await?;
        let fwd = MeshEnvelope::new(
            env.flow_id,
            env.target_host,
            env.target_port,
            env.path[1..].to_vec(),
        );
        write_envelope(&mut outbound, &fwd).await?;

        let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    pub async fn dial_and_tunnel(
        &self,
        next_hop: &NodeId,
        envelope: &MeshEnvelope,
        io: &mut dyn IoStream,
    ) -> Result<()> {
        let addr = self
            .registry
            .get_node_addr(next_hop)
            .ok_or_else(|| anyhow!("next hop {next_hop} not found in registry"))?;
        let mut stream = TcpStream::connect(addr).await?;
        write_envelope(&mut stream, envelope).await?;
        let _ = copy_bidirectional(io, &mut stream).await?;
        Ok(())
    }
}

async fn connect_target(host: &str, port: u16) -> Result<TcpStream> {
    // lookup_host accepts "host:port" and yields SocketAddr entries.
    let mut addrs = lookup_host((host, port)).await?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow!("no resolved address for {host}:{port}"))?;
    Ok(TcpStream::connect(addr).await?)
}

async fn read_envelope(stream: &mut TcpStream) -> Result<MeshEnvelope> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > MAX_HEADER_BYTES {
        return Err(anyhow!("invalid mesh header length {}", len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn write_envelope(stream: &mut TcpStream, env: &MeshEnvelope) -> Result<()> {
    let buf = serde_json::to_vec(env)?;
    if buf.len() > MAX_HEADER_BYTES {
        return Err(anyhow!("mesh header too large: {} bytes", buf.len()));
    }
    stream.write_u32(buf.len() as u32).await?;
    stream.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_mesh::{MeshRegistry, NodeRecord, NodeRole};

    #[tokio::test]
    async fn relay_to_exit_to_target_roundtrip() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        // Exit node data-plane.
        let exit_registry = Arc::new(MeshRegistry::new());
        exit_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .unwrap();
        let exit_plane = MeshDataPlane::new("exit1".into(), exit_registry);
        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = exit_listener.accept().await.unwrap();
                // Handler does not require registry at final hop.
                let plane = MeshDataPlane::new("exit1".into(), Arc::new(MeshRegistry::new()));
                tokio::spawn(async move {
                    let _ = plane.handle(stream).await;
                });
            }
        });

        // Relay node data-plane (knows how to reach exit1).
        let relay_registry = Arc::new(MeshRegistry::new());
        relay_registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, exit_addr))
            .unwrap();
        let relay_plane = MeshDataPlane::new("relay1".into(), relay_registry.clone());
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = relay_listener.accept().await.unwrap();
                let this = MeshDataPlane::new("relay1".into(), relay_registry.clone());
                tokio::spawn(async move {
                    let _ = this.handle(stream).await;
                });
            }
        });

        // Client connects to relay.
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let env = MeshEnvelope::new(
            "flow1".into(),
            "127.0.0.1".into(),
            target_addr.port(),
            vec!["relay1".into(), "exit1".into()],
        );
        write_envelope(&mut client, &env).await.unwrap();
        client.write_all(&[1, 2, 3, 4]).await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
        drop(exit_plane);
        drop(relay_plane);
    }

    #[tokio::test]
    async fn direct_exit_hop() {
        // Test direct connection to exit node (single hop, no relay)
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut buf = vec![0u8; 8];
            let n = s.read_exact(&mut buf).await;
            if n.is_ok() {
                s.write_all(&buf).await.ok();
            }
        });

        // Exit node that directly connects to target
        let exit_registry = Arc::new(MeshRegistry::new());
        exit_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .unwrap();
        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();

        let registry_clone = exit_registry.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = exit_listener.accept().await.unwrap();
                let plane = MeshDataPlane::new("exit1".into(), registry_clone.clone());
                tokio::spawn(async move {
                    let _ = plane.handle(stream).await;
                });
            }
        });

        // Client connects directly to exit (single hop)
        let mut client = TcpStream::connect(exit_addr).await.unwrap();
        let env = MeshEnvelope::new(
            "flow-direct".into(),
            "127.0.0.1".into(),
            target_addr.port(),
            vec!["exit1".into()], // Single hop - exit only
        );
        write_envelope(&mut client, &env).await.unwrap();

        let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        client.write_all(&payload).await.unwrap();

        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, payload);
    }

    #[test]
    fn mesh_envelope_serialization() {
        let env = MeshEnvelope::new(
            "test-flow".into(),
            "example.com".into(),
            443,
            vec!["node1".into(), "node2".into(), "node3".into()],
        );

        assert_eq!(env.version, 1);
        assert_eq!(env.flow_id, "test-flow");
        assert_eq!(env.target_host, "example.com");
        assert_eq!(env.target_port, 443);
        assert_eq!(env.path.len(), 3);

        // Test JSON serialization roundtrip
        let json = serde_json::to_string(&env).unwrap();
        let decoded: MeshEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.flow_id, env.flow_id);
        assert_eq!(decoded.path, env.path);
    }

    #[test]
    fn mesh_data_plane_creation() {
        let registry = Arc::new(MeshRegistry::new());
        let plane = MeshDataPlane::new("test-node".into(), registry);
        // Ensure the data plane is created without panic
        assert_eq!(plane.local_node_id, "test-node");
    }
}
