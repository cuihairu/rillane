//! Minimal mesh data-plane transport (TCP only).
//!
//! This implements a simple "hop-by-hop" forwarding protocol between Seep nodes.
//! It is intentionally minimal, but supports optional mTLS for encryption/authentication.

use std::{
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

use anyhow::{anyhow, Result};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::parse_x509_certificate;

use seep_core::IoStream;
use seep_mesh::{MeshRegistry, NodeId, NodeRole};

const MAX_HEADER_BYTES: usize = 64 * 1024;

trait MeshStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> MeshStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshTlsConfig {
    pub ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default = "default_require_client_auth")]
    pub require_client_auth: bool,
    /// Whether to extract the peer node id from the client certificate CN.
    #[serde(default = "default_verify_peer_node_id")]
    pub verify_peer_node_id: bool,
    /// Allow peers not present in the local mesh registry (dev/bootstrapping only).
    #[serde(default)]
    pub allow_unknown_peers: bool,
    /// Comma-separated revoked node ids (CN) from `SEEP_MESH_MTLS_REVOKED_NODES`.
    #[serde(default)]
    pub revoked_node_ids: Vec<NodeId>,
    /// Optional revoked node list file path from `SEEP_MESH_MTLS_REVOKED_NODES_FILE`.
    #[serde(default)]
    pub revoked_nodes_path: Option<PathBuf>,
}

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn parse_csv_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_path_env(name: &str) -> Option<PathBuf> {
    std::env::var(name).ok().map(PathBuf::from)
}

fn default_server_name() -> String {
    "seep".to_string()
}

fn default_require_client_auth() -> bool {
    true
}

fn default_verify_peer_node_id() -> bool {
    true
}

impl MeshTlsConfig {
    /// Read mesh mTLS settings from environment variables.
    ///
    /// - `SEEP_MESH_MTLS=1|true` enables it.
    /// - `SEEP_MESH_MTLS_CA`, `SEEP_MESH_MTLS_CERT`, `SEEP_MESH_MTLS_KEY` must be set.
    /// - Optional: `SEEP_MESH_MTLS_SERVER_NAME` (default: "seep")
    /// - Optional: `SEEP_MESH_MTLS_REQUIRE_CLIENT_AUTH` (default: true)
    pub fn from_env() -> Option<Self> {
        let enabled = env_flag("SEEP_MESH_MTLS", false);
        if !enabled {
            return None;
        }

        let ca_cert_path = PathBuf::from(std::env::var("SEEP_MESH_MTLS_CA").ok()?);
        let cert_path = PathBuf::from(std::env::var("SEEP_MESH_MTLS_CERT").ok()?);
        let key_path = PathBuf::from(std::env::var("SEEP_MESH_MTLS_KEY").ok()?);
        let server_name =
            std::env::var("SEEP_MESH_MTLS_SERVER_NAME").unwrap_or_else(|_| "seep".to_string());
        let require_client_auth = env_flag("SEEP_MESH_MTLS_REQUIRE_CLIENT_AUTH", true);
        let verify_peer_node_id = env_flag("SEEP_MESH_MTLS_VERIFY_PEER_NODE_ID", true);
        let allow_unknown_peers = env_flag("SEEP_MESH_MTLS_ALLOW_UNKNOWN_PEERS", false);
        let revoked_node_ids = parse_csv_env("SEEP_MESH_MTLS_REVOKED_NODES");
        let revoked_nodes_path = parse_path_env("SEEP_MESH_MTLS_REVOKED_NODES_FILE");

        Some(Self {
            ca_cert_path,
            cert_path,
            key_path,
            server_name,
            require_client_auth,
            verify_peer_node_id,
            allow_unknown_peers,
            revoked_node_ids,
            revoked_nodes_path,
        })
    }

    pub fn enabled_by_env() -> bool {
        env_flag("SEEP_MESH_MTLS", false)
    }

    /// Strict parsing: if `SEEP_MESH_MTLS=1|true|...` is set but required variables are missing,
    /// return an error instead of silently disabling mTLS.
    pub fn from_env_strict() -> Result<Option<Self>> {
        if !Self::enabled_by_env() {
            return Ok(None);
        }
        let ca_cert_path = PathBuf::from(std::env::var("SEEP_MESH_MTLS_CA").map_err(|_| {
            anyhow!("SEEP_MESH_MTLS_CA is required when SEEP_MESH_MTLS is enabled")
        })?);
        let cert_path = PathBuf::from(std::env::var("SEEP_MESH_MTLS_CERT").map_err(|_| {
            anyhow!("SEEP_MESH_MTLS_CERT is required when SEEP_MESH_MTLS is enabled")
        })?);
        let key_path = PathBuf::from(std::env::var("SEEP_MESH_MTLS_KEY").map_err(|_| {
            anyhow!("SEEP_MESH_MTLS_KEY is required when SEEP_MESH_MTLS is enabled")
        })?);
        let server_name =
            std::env::var("SEEP_MESH_MTLS_SERVER_NAME").unwrap_or_else(|_| "seep".to_string());
        let require_client_auth = env_flag("SEEP_MESH_MTLS_REQUIRE_CLIENT_AUTH", true);
        let verify_peer_node_id = env_flag("SEEP_MESH_MTLS_VERIFY_PEER_NODE_ID", true);
        let allow_unknown_peers = env_flag("SEEP_MESH_MTLS_ALLOW_UNKNOWN_PEERS", false);
        let revoked_node_ids = parse_csv_env("SEEP_MESH_MTLS_REVOKED_NODES");
        let revoked_nodes_path = parse_path_env("SEEP_MESH_MTLS_REVOKED_NODES_FILE");

        Ok(Some(Self {
            ca_cert_path,
            cert_path,
            key_path,
            server_name,
            require_client_auth,
            verify_peer_node_id,
            allow_unknown_peers,
            revoked_node_ids,
            revoked_nodes_path,
        }))
    }
}

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

// ── P0-4 §2：UDP 面二进制 envelope（与 TCP 面 JSON MeshEnvelope 同文件；纯函数，单测钉住）──
//
// 布局（§2）：
//   0  magic(2)='S''U'  2 ver(1)=1  3 flags(1) bit0=dir、bit1..7 保留必须为 0
//   4  flow_id(16)  20 atyp(1): 1=v4 4=v6 3=domain  21 addr: 4/16/len(1)+bytes
//   … port(2,BE)  … path_mode(1): 0=FULL 1=CACHED  … hop_index(1)
//   [FULL] hop_count(1) + node_id × hop_count（每项 len(1)+bytes）  … payload(...)
//
// 结构不变式：FULL 带非空路径；CACHED 恒空（线格式 CACHED 无 path 字段——"CACHED 携带
// 路径拒绝"由编码侧强制，解码侧结构上不可能出现）。

pub const UDP_ENVELOPE_VERSION: u8 = 1;
/// IPv4 UDP 载荷理论上界（§13-3）：encode 总长超此值拒绝，调用方丢弃 + `malformed` 计数。
pub const UDP_ENVELOPE_MAX: usize = 65507;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDir {
    /// 上行（client → relay → exit）
    Up,
    /// 下行（exit → relay → client）
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPathMode {
    /// 首包携带完整路径
    Full,
    /// 后续包按各跳本地缓存转发（无路径字段）
    Cached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpEnvelope {
    /// 恒 1，其他值解码拒绝
    pub version: u8,
    pub dir: UdpDir,
    /// UUID 原始字节（非字符串化——缓存键与线上格式同源，§11-3）
    pub flow_id: [u8; 16],
    /// domain / v4 / v6 字符串化（exit 使用）
    pub target_host: String,
    pub target_port: u16,
    pub path_mode: UdpPathMode,
    /// 已穿越跳数（§14-1：发送端置 0，每经一个 relay +1，上下行对称）
    pub hop_index: u8,
    /// Full 时非空；Cached 恒空（编解码双向强制）
    pub path: Vec<NodeId>,
    pub payload: Vec<u8>,
}

/// 从 `buf[pos..]` 取 `n` 字节并推进游标；越界 = 截断错误。
fn udp_take<'a>(buf: &'a [u8], pos: &mut usize, n: usize, what: &str) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .ok_or_else(|| anyhow!("udp envelope: 长度溢出（{what}）"))?;
    let s = buf
        .get(*pos..end)
        .ok_or_else(|| anyhow!("udp envelope: 截断（{what}）"))?;
    *pos = end;
    Ok(s)
}

pub fn encode_udp_envelope(env: &UdpEnvelope) -> Result<Vec<u8>> {
    if env.version != UDP_ENVELOPE_VERSION {
        anyhow::bail!("udp envelope: 不支持的版本 {}（仅支持 1）", env.version);
    }
    match env.path_mode {
        UdpPathMode::Full if env.path.is_empty() => {
            anyhow::bail!("udp envelope: FULL 模式 path 不能为空");
        }
        UdpPathMode::Cached if !env.path.is_empty() => {
            anyhow::bail!("udp envelope: CACHED 模式 path 必须为空");
        }
        _ => {}
    }
    if env.path.len() > u8::MAX as usize {
        anyhow::bail!("udp envelope: path 节点数超上界 255");
    }
    for id in &env.path {
        if id.as_bytes().len() > u8::MAX as usize {
            anyhow::bail!("udp envelope: node_id 超长（{id}）");
        }
    }
    let (atyp, addr): (u8, Vec<u8>) = if let Ok(v4) = env.target_host.parse::<Ipv4Addr>() {
        (1, v4.octets().to_vec())
    } else if let Ok(v6) = env.target_host.parse::<Ipv6Addr>() {
        (4, v6.octets().to_vec())
    } else {
        let b = env.target_host.as_bytes();
        if b.is_empty() || b.len() > u8::MAX as usize {
            anyhow::bail!("udp envelope: 目标主机名长度非法（空或 >255）");
        }
        (3, b.to_vec())
    };

    let mut out = Vec::with_capacity(24 + addr.len() + env.path.len() * 8 + env.payload.len());
    out.extend_from_slice(b"SU");
    out.push(env.version);
    out.push(match env.dir {
        UdpDir::Up => 0u8,
        UdpDir::Down => 1,
    });
    out.extend_from_slice(&env.flow_id);
    out.push(atyp);
    if atyp == 3 {
        out.push(addr.len() as u8);
    }
    out.extend_from_slice(&addr);
    out.extend_from_slice(&env.target_port.to_be_bytes());
    out.push(match env.path_mode {
        UdpPathMode::Full => 0u8,
        UdpPathMode::Cached => 1,
    });
    out.push(env.hop_index);
    if matches!(env.path_mode, UdpPathMode::Full) {
        out.push(env.path.len() as u8);
        for id in &env.path {
            out.push(id.as_bytes().len() as u8);
            out.extend_from_slice(id.as_bytes());
        }
    }
    out.extend_from_slice(&env.payload);
    if out.len() > UDP_ENVELOPE_MAX {
        anyhow::bail!(
            "udp envelope: 编码后 {} 字节超上界 {}（§13-3）",
            out.len(),
            UDP_ENVELOPE_MAX
        );
    }
    Ok(out)
}

pub fn decode_udp_envelope(buf: &[u8]) -> Result<UdpEnvelope> {
    if buf.len() < 21 {
        anyhow::bail!("udp envelope: 截断（固定头 <21 字节）");
    }
    if &buf[0..2] != b"SU" {
        anyhow::bail!("udp envelope: magic 不符");
    }
    let version = buf[2];
    if version != UDP_ENVELOPE_VERSION {
        anyhow::bail!("udp envelope: 不支持的版本 {version}");
    }
    let flags = buf[3];
    if flags & 0xFE != 0 {
        anyhow::bail!("udp envelope: 保留位非 0（flags=0x{flags:02x}）");
    }
    let dir = if flags & 1 == 0 { UdpDir::Up } else { UdpDir::Down };
    let flow_id: [u8; 16] = buf[4..20].try_into().expect("长度已由固定头校验保证");
    let atyp = buf[20];
    let mut pos = 21usize;
    let target_host = match atyp {
        1 => {
            let o: [u8; 4] = udp_take(buf, &mut pos, 4, "addr v4")?
                .try_into()
                .unwrap();
            Ipv4Addr::from(o).to_string()
        }
        4 => {
            let o: [u8; 16] = udp_take(buf, &mut pos, 16, "addr v6")?
                .try_into()
                .unwrap();
            Ipv6Addr::from(o).to_string()
        }
        3 => {
            let len = udp_take(buf, &mut pos, 1, "domain len")?[0] as usize;
            let b = udp_take(buf, &mut pos, len, "domain")?;
            if len == 0 {
                anyhow::bail!("udp envelope: domain 长度为 0");
            }
            String::from_utf8(b.to_vec())
                .map_err(|_| anyhow!("udp envelope: domain 非 UTF-8"))?
        }
        other => anyhow::bail!("udp envelope: 未知 atyp {other}"),
    };
    let port = u16::from_be_bytes(udp_take(buf, &mut pos, 2, "port")?.try_into().unwrap());
    let pm = udp_take(buf, &mut pos, 1, "path_mode")?[0];
    let path_mode = match pm {
        0 => UdpPathMode::Full,
        1 => UdpPathMode::Cached,
        _ => anyhow::bail!("udp envelope: 非法 path_mode {pm}"),
    };
    let hop_index = udp_take(buf, &mut pos, 1, "hop_index")?[0];
    let path = if matches!(path_mode, UdpPathMode::Full) {
        let hop_count = udp_take(buf, &mut pos, 1, "hop_count")?[0] as usize;
        let mut path = Vec::with_capacity(hop_count);
        for i in 0..hop_count {
            let len = udp_take(buf, &mut pos, 1, "node_id len")?[0] as usize;
            let b = udp_take(buf, &mut pos, len, &format!("node_id #{i}"))?;
            path.push(
                String::from_utf8(b.to_vec())
                    .map_err(|_| anyhow!("udp envelope: node_id 非 UTF-8"))?,
            );
        }
        path
    } else {
        Vec::new()
    };
    let payload = buf.get(pos..).unwrap_or(&[]).to_vec();
    Ok(UdpEnvelope {
        version,
        dir,
        flow_id,
        target_host,
        target_port: port,
        path_mode,
        hop_index,
        path,
        payload,
    })
}

pub struct MeshDataPlane {
    local_node_id: NodeId,
    local_role: NodeRole,
    registry: Arc<MeshRegistry>,
    tls: Option<Arc<MeshTls>>,
}

impl MeshDataPlane {
    pub fn new(local_node_id: NodeId, registry: Arc<MeshRegistry>) -> Self {
        let local_role = registry
            .get_node(&local_node_id)
            .map(|r| r.role)
            .unwrap_or(NodeRole::Client);
        Self {
            local_node_id,
            local_role,
            registry,
            tls: None,
        }
    }

    pub async fn handle(&self, inbound: TcpStream) -> Result<()> {
        self.handle_tcp(inbound).await
    }

    pub fn with_tls(mut self, cfg: Option<MeshTlsConfig>) -> Result<Self> {
        self.tls = match cfg {
            Some(c) => Some(Arc::new(MeshTls::from_config(&c)?)),
            None => None,
        };
        Ok(self)
    }

    pub fn spawn(self, bind: SocketAddr) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { self.serve(bind).await })
    }

    async fn serve(self, bind: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind).await?;
        let tls = self.tls.clone();
        loop {
            let (stream, _peer) = listener.accept().await?;
            let this = Self {
                local_node_id: self.local_node_id.clone(),
                local_role: self.local_role,
                registry: self.registry.clone(),
                tls: tls.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = this.handle_tcp(stream).await {
                    tracing::debug!(target: "seep::mesh::transport", error = %e, "mesh transport connection closed");
                }
            });
        }
    }

    async fn handle_tcp(&self, inbound: TcpStream) -> Result<()> {
        if let Some(tls) = &self.tls {
            let inbound = tls.accept(inbound).await?;
            let peer_node_id = if tls.cfg().require_client_auth && tls.cfg().verify_peer_node_id {
                Some(peer_node_id_from_server_tls_stream(&inbound)?)
            } else {
                None
            };

            if tls.cfg().require_client_auth && tls.cfg().verify_peer_node_id {
                let peer = peer_node_id
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing peer node id"))?;
                if tls.is_revoked(peer).await? {
                    return Err(anyhow!("revoked mesh peer node: {peer}"));
                }
                if !tls.cfg().allow_unknown_peers && self.registry.get_node(peer).is_none() {
                    return Err(anyhow!("unregistered mesh peer node: {peer}"));
                }
            }

            self.handle_stream(inbound, peer_node_id).await
        } else {
            self.handle_stream(inbound, None).await
        }
    }

    async fn handle_stream<S>(&self, mut inbound: S, peer_node_id: Option<NodeId>) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let env = read_envelope(&mut inbound).await?;
        if env.version != 1 {
            return Err(anyhow!("unsupported mesh envelope version {}", env.version));
        }
        if env.path.is_empty() {
            return Err(anyhow!("empty mesh path"));
        }

        if let Some(peer) = &peer_node_id {
            tracing::debug!(
                target: "seep::mesh::transport",
                peer = %peer,
                local = %self.local_node_id,
                "mesh data-plane accepted connection"
            );
        }

        if env.path[0] != self.local_node_id {
            return Err(anyhow!(
                "mesh envelope path[0] mismatch: expected {}, got {}",
                self.local_node_id,
                env.path[0]
            ));
        }

        if env.path.len() == 1 {
            if !matches!(self.local_role, NodeRole::Exit | NodeRole::Hybrid) {
                return Err(anyhow!(
                    "node role {} cannot act as exit (target hop)",
                    self.local_role
                ));
            }
            if let Some(peer) = &peer_node_id {
                self.registry
                    .record_link_connection(peer, &self.local_node_id);
            }
            // Final hop: connect to the real target.
            let mut out = match connect_target(&env.target_host, env.target_port).await {
                Ok(v) => v,
                Err(e) => {
                    if let Some(peer) = &peer_node_id {
                        self.registry.record_link_error(peer, &self.local_node_id);
                    }
                    return Err(e);
                }
            };
            let (up, down) = match copy_bidirectional(&mut inbound, &mut out).await {
                Ok(v) => v,
                Err(e) => {
                    if let Some(peer) = &peer_node_id {
                        self.registry.record_link_error(peer, &self.local_node_id);
                        self.registry.record_link_error(&self.local_node_id, peer);
                    }
                    return Err(e.into());
                }
            };
            if let Some(peer) = &peer_node_id {
                self.registry
                    .record_link_bytes(peer, &self.local_node_id, up);
                self.registry
                    .record_link_bytes(&self.local_node_id, peer, down);
            }
            return Ok(());
        }

        if !matches!(self.local_role, NodeRole::Relay | NodeRole::Hybrid) {
            return Err(anyhow!(
                "node role {} cannot act as relay (forward hop)",
                self.local_role
            ));
        }

        // Relay hop: forward to next node.
        let next = env.path[1].clone();
        if let Some(next_rec) = self.registry.get_node(&next) {
            if next_rec.role == NodeRole::Client {
                return Err(anyhow!("invalid next hop role client: {next}"));
            }
        }
        if let Some(peer) = &peer_node_id {
            self.registry
                .record_link_connection(peer, &self.local_node_id);
        }
        self.registry
            .record_link_connection(&self.local_node_id, &next);
        let next_addr = self
            .registry
            .get_node_addr(&next)
            .ok_or_else(|| anyhow!("next hop {next} not found in registry"))?;

        let mut outbound = match self.connect_next(next_addr).await {
            Ok(v) => v,
            Err(e) => {
                self.registry.record_link_error(&self.local_node_id, &next);
                if let Some(peer) = &peer_node_id {
                    self.registry.record_link_error(peer, &self.local_node_id);
                }
                return Err(e);
            }
        };
        let fwd = MeshEnvelope::new(
            env.flow_id,
            env.target_host,
            env.target_port,
            env.path[1..].to_vec(),
        );
        write_envelope(&mut outbound, &fwd).await?;

        let (up, down) = match copy_bidirectional(&mut inbound, &mut outbound).await {
            Ok(v) => v,
            Err(e) => {
                self.registry.record_link_error(&self.local_node_id, &next);
                self.registry.record_link_error(&next, &self.local_node_id);
                if let Some(peer) = &peer_node_id {
                    self.registry.record_link_error(peer, &self.local_node_id);
                    self.registry.record_link_error(&self.local_node_id, peer);
                }
                return Err(e.into());
            }
        };
        self.registry
            .record_link_bytes(&self.local_node_id, &next, up);
        self.registry
            .record_link_bytes(&next, &self.local_node_id, down);
        if let Some(peer) = &peer_node_id {
            self.registry
                .record_link_bytes(peer, &self.local_node_id, up);
            self.registry
                .record_link_bytes(&self.local_node_id, peer, down);
        }
        Ok(())
    }

    async fn connect_next(&self, addr: SocketAddr) -> Result<Box<dyn MeshStream>> {
        let stream = TcpStream::connect(addr).await?;
        if let Some(tls) = &self.tls {
            let s = tls.connect(stream).await?;
            Ok(Box::new(s))
        } else {
            Ok(Box::new(stream))
        }
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
        self.registry
            .record_link_connection(&self.local_node_id, next_hop);
        let mut stream = match self.connect_next(addr).await {
            Ok(v) => v,
            Err(e) => {
                self.registry
                    .record_link_error(&self.local_node_id, next_hop);
                return Err(e);
            }
        };
        write_envelope(&mut stream, envelope).await?;
        let (up, down) = match copy_bidirectional(io, &mut stream).await {
            Ok(v) => v,
            Err(e) => {
                self.registry
                    .record_link_error(&self.local_node_id, next_hop);
                self.registry
                    .record_link_error(next_hop, &self.local_node_id);
                return Err(e.into());
            }
        };
        self.registry
            .record_link_bytes(&self.local_node_id, next_hop, up);
        self.registry
            .record_link_bytes(next_hop, &self.local_node_id, down);
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

async fn read_envelope<R>(stream: &mut R) -> Result<MeshEnvelope>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > MAX_HEADER_BYTES {
        return Err(anyhow!("invalid mesh header length {}", len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn write_envelope<W>(stream: &mut W, env: &MeshEnvelope) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let buf = serde_json::to_vec(env)?;
    if buf.len() > MAX_HEADER_BYTES {
        return Err(anyhow!("mesh header too large: {} bytes", buf.len()));
    }
    stream.write_u32(buf.len() as u32).await?;
    stream.write_all(&buf).await?;
    Ok(())
}

fn peer_node_id_from_server_tls_stream(
    stream: &tokio_rustls::server::TlsStream<TcpStream>,
) -> Result<NodeId> {
    let conn = stream.get_ref().1;
    let certs = conn.peer_certificates().ok_or_else(|| {
        anyhow!("mTLS client auth required but peer did not present a certificate")
    })?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("peer certificate chain is empty"))?;
    let (_, cert) = parse_x509_certificate(leaf.as_ref())
        .map_err(|e| anyhow!("invalid peer certificate: {e}"))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| anyhow!("peer certificate missing CommonName (CN)"))?
        .as_str()
        .map_err(|_| anyhow!("peer certificate CN is not valid UTF-8"))?;
    Ok(cn.to_string())
}

struct MeshTls {
    cfg: MeshTlsConfig,
    inner: tokio::sync::RwLock<MeshTlsInner>,
}

#[derive(Clone)]
struct MeshTlsInner {
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
    fingerprint: MeshTlsFingerprint,
    revoked_node_ids: Vec<NodeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MeshTlsFingerprint {
    ca_mtime: Option<SystemTime>,
    cert_mtime: Option<SystemTime>,
    key_mtime: Option<SystemTime>,
    revoked_mtime: Option<SystemTime>,
}

impl MeshTls {
    fn from_config(cfg: &MeshTlsConfig) -> Result<Self> {
        let inner = MeshTlsInner::load(cfg)?;
        Ok(Self {
            cfg: cfg.clone(),
            inner: tokio::sync::RwLock::new(inner),
        })
    }

    fn cfg(&self) -> &MeshTlsConfig {
        &self.cfg
    }

    async fn accept(
        &self,
        inbound: TcpStream,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
        self.maybe_reload().await?;
        let acceptor = { self.inner.read().await.acceptor.clone() };
        Ok(acceptor.accept(inbound).await?)
    }

    async fn connect(
        &self,
        stream: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        self.maybe_reload().await?;
        let (connector, server_name) = {
            let guard = self.inner.read().await;
            (guard.connector.clone(), guard.server_name.clone())
        };
        Ok(connector.connect(server_name, stream).await?)
    }

    async fn maybe_reload(&self) -> Result<()> {
        let current = fingerprint_paths(&self.cfg);
        let needs_reload = {
            let guard = self.inner.read().await;
            guard.fingerprint != current
        };
        if !needs_reload {
            return Ok(());
        }
        let mut guard = self.inner.write().await;
        // Double-check under write lock.
        let current2 = fingerprint_paths(&self.cfg);
        if guard.fingerprint == current2 {
            return Ok(());
        }
        *guard = MeshTlsInner::load(&self.cfg)?;
        Ok(())
    }

    async fn is_revoked(&self, node_id: &str) -> Result<bool> {
        self.maybe_reload().await?;
        if self.cfg.revoked_node_ids.iter().any(|n| n == node_id) {
            return Ok(true);
        }
        let guard = self.inner.read().await;
        Ok(guard.revoked_node_ids.iter().any(|n| n == node_id))
    }
}

impl MeshTlsInner {
    fn load(cfg: &MeshTlsConfig) -> Result<Self> {
        let root = load_root_store(&cfg.ca_cert_path)?;
        let certs = load_cert_chain(&cfg.cert_path)?;
        let key = load_private_key(&cfg.key_path)?;
        let revoked_node_ids = match &cfg.revoked_nodes_path {
            Some(p) => load_revoked_nodes(p)?,
            None => Vec::new(),
        };

        let client = ClientConfig::builder()
            .with_root_certificates(root.clone())
            .with_client_auth_cert(certs.clone(), key.clone_key())?;

        let server = if cfg.require_client_auth {
            let verifier = rustls::server::WebPkiClientVerifier::builder(root.into()).build()?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };

        let server_name = rustls::pki_types::ServerName::try_from(cfg.server_name.as_str())
            .map_err(|_| anyhow!("invalid mesh tls server_name: {}", cfg.server_name))?
            .to_owned();

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server)),
            connector: TlsConnector::from(Arc::new(client)),
            server_name,
            fingerprint: fingerprint_paths(cfg),
            revoked_node_ids,
        })
    }
}

fn fingerprint_paths(cfg: &MeshTlsConfig) -> MeshTlsFingerprint {
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let revoked_mtime = cfg
        .revoked_nodes_path
        .as_ref()
        .and_then(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    MeshTlsFingerprint {
        ca_mtime: mtime(&cfg.ca_cert_path),
        cert_mtime: mtime(&cfg.cert_path),
        key_mtime: mtime(&cfg.key_path),
        revoked_mtime,
    }
}

fn load_revoked_nodes(path: &PathBuf) -> Result<Vec<NodeId>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read revoked node list {}: {}", path.display(), e))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for part in line.split(',') {
            let v = part.trim();
            if !v.is_empty() {
                out.push(v.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn load_cert_chain(path: &PathBuf) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = File::open(path)?;
    let mut r = BufReader::new(f);
    let certs = rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let f = File::open(path)?;
    let mut r = BufReader::new(f);
    let key = rustls_pemfile::private_key(&mut r)?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))?;
    Ok(key)
}

fn load_root_store(path: &PathBuf) -> Result<RootCertStore> {
    let certs = load_cert_chain(path)?;
    let mut root = RootCertStore::empty();
    for c in certs {
        root.add(c)?;
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_mesh::{MeshRegistry, NodeRecord, NodeRole};

    #[test]
    fn from_env_strict_requires_paths_when_enabled() {
        std::env::set_var("SEEP_MESH_MTLS", "1");
        std::env::remove_var("SEEP_MESH_MTLS_CA");
        std::env::remove_var("SEEP_MESH_MTLS_CERT");
        std::env::remove_var("SEEP_MESH_MTLS_KEY");

        let r = MeshTlsConfig::from_env_strict();
        assert!(r.is_err());

        std::env::remove_var("SEEP_MESH_MTLS");
    }

    #[test]
    fn env_helpers_parse_flags_csv_and_paths() {
        std::env::set_var("SEEP_TEST_FLAG", "yes");
        assert!(env_flag("SEEP_TEST_FLAG", false));
        assert!(!env_flag("SEEP_TEST_MISSING", false));
        assert!(env_flag("SEEP_TEST_MISSING", true));
        std::env::remove_var("SEEP_TEST_FLAG");

        std::env::set_var("SEEP_TEST_CSV", " a, b ,,c , ");
        assert_eq!(
            parse_csv_env("SEEP_TEST_CSV"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        std::env::remove_var("SEEP_TEST_CSV");

        std::env::set_var("SEEP_TEST_PATH", "/tmp/seep-test-path");
        assert_eq!(
            parse_path_env("SEEP_TEST_PATH").unwrap(),
            PathBuf::from("/tmp/seep-test-path")
        );
        std::env::remove_var("SEEP_TEST_PATH");
    }

    #[test]
    fn load_revoked_nodes_parses_and_dedupes() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "seep_revoked_nodes_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "# comment\n\nnode3,node2\n node1 \nnode2\n").unwrap();

        let out = load_revoked_nodes(&path).unwrap();
        assert_eq!(
            out,
            vec![
                "node1".to_string(),
                "node2".to_string(),
                "node3".to_string()
            ]
        );

        let _ = std::fs::remove_file(&path);
    }

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
        let exit_registry_for_handler = Arc::new(MeshRegistry::new());
        exit_registry_for_handler
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, exit_addr))
            .unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = exit_listener.accept().await.unwrap();
                let plane = MeshDataPlane::new("exit1".into(), exit_registry_for_handler.clone());
                tokio::spawn(async move {
                    let _ = plane.handle_tcp(stream).await;
                });
            }
        });

        // Relay node data-plane (knows how to reach exit1).
        let relay_registry = Arc::new(MeshRegistry::new());
        relay_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .unwrap();
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
                    let _ = this.handle_tcp(stream).await;
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

    // ── P0-4 §2 UdpEnvelope 编解码（S1 / §10 T1）──

    fn udp_env_sample(host: &str, mode: UdpPathMode, dir: UdpDir) -> UdpEnvelope {
        UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir,
            flow_id: [0x0a; 16],
            target_host: host.to_string(),
            target_port: 4433,
            path_mode: mode,
            hop_index: 3,
            path: match mode {
                UdpPathMode::Full => vec!["relay-1".into(), "exit-1".into()],
                UdpPathMode::Cached => vec![],
            },
            payload: vec![1, 2, 3, 0xFF],
        }
    }

    /// T1：FULL/CACHED × v4/v6/domain × dir 两位全组合往返。
    #[test]
    fn udp_envelope_roundtrip_matrix() {
        for host in ["127.0.0.1", "2001:db8::1", "example.com"] {
            for mode in [UdpPathMode::Full, UdpPathMode::Cached] {
                for dir in [UdpDir::Up, UdpDir::Down] {
                    let env = udp_env_sample(host, mode, dir);
                    let wire = encode_udp_envelope(&env).unwrap();
                    assert_eq!(&wire[0..2], b"SU");
                    assert_eq!(wire[2], UDP_ENVELOPE_VERSION);
                    let back = decode_udp_envelope(&wire).unwrap();
                    assert_eq!(back, env, "roundtrip 失败: {host} {mode:?} {dir:?}");
                }
            }
        }
    }

    #[test]
    fn udp_envelope_atyp_encoding() {
        let v4 = encode_udp_envelope(&udp_env_sample("10.0.0.1", UdpPathMode::Cached, UdpDir::Up))
            .unwrap();
        assert_eq!(v4[20], 1);
        let v6 =
            encode_udp_envelope(&udp_env_sample("::1", UdpPathMode::Cached, UdpDir::Up)).unwrap();
        assert_eq!(v6[20], 4);
        let d = encode_udp_envelope(&udp_env_sample("example.com", UdpPathMode::Cached, UdpDir::Up))
            .unwrap();
        assert_eq!(d[20], 3);
        assert_eq!(d[21], b"example.com".len() as u8);
    }

    /// T1 拒绝类 1-3：坏 magic / ver / 保留位。
    #[test]
    fn udp_envelope_rejects_bad_magic_version_reserved() {
        let wire = encode_udp_envelope(&udp_env_sample("example.com", UdpPathMode::Full, UdpDir::Down))
            .unwrap();
        let mut bad = wire.clone();
        bad[0] = b'X';
        assert!(decode_udp_envelope(&bad).is_err(), "magic 应拒绝");
        let mut bad = wire.clone();
        bad[2] = 2;
        assert!(decode_udp_envelope(&bad).is_err(), "version 应拒绝");
        let mut bad = wire;
        bad[3] |= 0x02;
        assert!(decode_udp_envelope(&bad).is_err(), "保留位应拒绝");
    }

    /// T1 拒绝类 4：结构性截断（固定头/地址/路径区）一律错误——逐字节前缀全扫结构区。
    /// 注：payload 无长度字段（剩余字节即载荷），载荷区截断与合法空载荷不可区分；
    /// UDP 数据报边界由 recv_from 保证，线上无"半包"，恶意构造等同空载荷交上层语义丢弃。
    #[test]
    fn udp_envelope_rejects_truncation_everywhere() {
        let payload_len = 4usize;
        for mode in [UdpPathMode::Full, UdpPathMode::Cached] {
            let wire =
                encode_udp_envelope(&udp_env_sample("example.com", mode, UdpDir::Up)).unwrap();
            let structural_len = wire.len() - payload_len;
            for cut in 1..structural_len {
                assert!(
                    decode_udp_envelope(&wire[..cut]).is_err(),
                    "{mode:?} 截断至 {cut} 字节应拒绝（结构区长 {structural_len}）"
                );
            }
        }
    }

    /// T1 拒绝类 5：CACHED 携带路径 / FULL 空路径（编码侧强制，结构不变式）。
    #[test]
    fn udp_envelope_rejects_cached_with_path_and_full_without_path() {
        let mut env = udp_env_sample("example.com", UdpPathMode::Cached, UdpDir::Up);
        env.path = vec!["relay-1".into()];
        assert!(
            encode_udp_envelope(&env).is_err(),
            "CACHED 携带路径应拒绝（线格式无 path 字段，编码侧强制）"
        );
        let mut env = udp_env_sample("example.com", UdpPathMode::Full, UdpDir::Up);
        env.path = vec![];
        assert!(encode_udp_envelope(&env).is_err(), "FULL 空路径应拒绝");
    }

    /// §13-3：编码后总长超 65507 上界拒绝。
    #[test]
    fn udp_envelope_rejects_oversize() {
        let mut env = udp_env_sample("example.com", UdpPathMode::Cached, UdpDir::Up);
        env.payload = vec![0u8; UDP_ENVELOPE_MAX];
        assert!(
            encode_udp_envelope(&env).is_err(),
            "编码后超 65507 上界应拒绝（§13-3）"
        );
    }

    #[test]
    fn udp_envelope_empty_payload_roundtrip() {
        let mut env = udp_env_sample("127.0.0.1", UdpPathMode::Cached, UdpDir::Down);
        env.payload = vec![];
        let back = decode_udp_envelope(&encode_udp_envelope(&env).unwrap()).unwrap();
        assert_eq!(back, env);
        assert!(back.payload.is_empty());
    }
}
