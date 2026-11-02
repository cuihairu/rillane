//! Minimal mesh data-plane transport (TCP only).
//!
//! This implements a simple "hop-by-hop" forwarding protocol between Seep nodes.
//! It is intentionally minimal, but supports optional mTLS for encryption/authentication.

use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{copy_bidirectional_with_sizes, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream, UdpSocket},
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshEnvelope {
    pub version: u32,
    pub flow_id: String,
    pub target_host: String,
    pub target_port: u16,
    /// Remaining path including the current node id as the first element.
    pub path: Vec<NodeId>,
    /// P1-4 §2.4：尾部填充字节数（0 = 无填充，不序列化——未填充帧与
    /// 旧行为字节一致，§7.1 关闭对照口径）。旧端 serde 忽略未知字段，
    /// 但尾部填充字节会污染其 JSON 解析，故打填充的帧同时升 version=2
    /// （接收端见下），旧端在版本检查处显式拒绝而非解析错乱。
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pad_len: u32,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

impl MeshEnvelope {
    pub fn new(flow_id: String, target_host: String, target_port: u16, path: Vec<NodeId>) -> Self {
        Self {
            version: MESH_ENVELOPE_VERSION,
            flow_id,
            target_host,
            target_port,
            path,
            pad_len: 0,
        }
    }
}

// ── P1-4 §2.4/§4.2：MeshEnvelope 帧填充执行侧（TCP 面 chain 帧）──

/// P1-4 §2.4 版本门：MESH_ENVELOPE_VERSION=1 为既有帧形；本条目起打填充的
/// 帧升 version=2（携带 `pad_len` + 尾部 0x00）。发送端仅打填充时升版本
/// （未填充帧维持 1，与旧行为字节一致）；接收端 1|2 皆收、仅 2 可能携带
/// 填充。MVP 假定同版本部署（§2.4/§10 R-obfs2：无法确认对端版本时不填充
/// 的完整判定归后续版本协商；混布升级窗口退化为不填充，fail-open）。
pub const MESH_ENVELOPE_VERSION: u32 = 1;
pub const PAD_ENVELOPE_VERSION: u32 = 2;

/// P1-4 §5 `seep_obfs_padding_*` 快照（进程级计数，`/metrics` 渲染数据源）：
/// frames 按模式分桶（{mode} 封闭三值）、bytes 累计新增填充字节、skipped
/// 封闭五因——no_frame（单跳无帧载体 §4.3）/overhead_cap（E10 策略层）/
/// too_large（E4 执行层）生产自增；peer_version（E6）/disabled（E11）MVP
/// 恒 0 恒渲染（R-obfs2 同版本部署假定下无生产增量点，留标签保封闭集）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObfsPadSnapshot {
    pub frames_fixed: u64,
    pub frames_bucket: u64,
    pub frames_range: u64,
    pub bytes_added: u64,
    pub skipped_no_frame: u64,
    pub skipped_overhead_cap: u64,
    pub skipped_too_large: u64,
    pub skipped_peer_version: u64,
    pub skipped_disabled: u64,
}

// 进程级 statics（`MeshDataPlane` 每次 forward 现建，实例计数无法聚合）
static PAD_FRAMES_FIXED: AtomicU64 = AtomicU64::new(0);
static PAD_FRAMES_BUCKET: AtomicU64 = AtomicU64::new(0);
static PAD_FRAMES_RANGE: AtomicU64 = AtomicU64::new(0);
static PAD_BYTES_ADDED: AtomicU64 = AtomicU64::new(0);
static PAD_SKIPPED_NO_FRAME: AtomicU64 = AtomicU64::new(0);
static PAD_SKIPPED_TOO_LARGE: AtomicU64 = AtomicU64::new(0);
static PAD_SKIPPED_OVERHEAD: AtomicU64 = AtomicU64::new(0);

/// 填充计数快照（`/metrics` 渲染与测试用）。
pub fn obfs_pad_snapshot() -> ObfsPadSnapshot {
    ObfsPadSnapshot {
        frames_fixed: PAD_FRAMES_FIXED.load(Ordering::Relaxed),
        frames_bucket: PAD_FRAMES_BUCKET.load(Ordering::Relaxed),
        frames_range: PAD_FRAMES_RANGE.load(Ordering::Relaxed),
        bytes_added: PAD_BYTES_ADDED.load(Ordering::Relaxed),
        skipped_no_frame: PAD_SKIPPED_NO_FRAME.load(Ordering::Relaxed),
        skipped_overhead_cap: PAD_SKIPPED_OVERHEAD.load(Ordering::Relaxed),
        skipped_too_large: PAD_SKIPPED_TOO_LARGE.load(Ordering::Relaxed),
        // E6/E11：MVP 无生产增量点，恒 0（标签恒渲染保封闭集）
        skipped_peer_version: 0,
        skipped_disabled: 0,
    }
}

/// P1-4 §4.3/§5：单跳（MVP 无帧载体）持 spec 记 `skipped{no_frame}`——
/// `FlowOutputRouter::forward` 单跳分支在注解含 spec 时调用。
pub fn obfs_pad_note_no_frame() {
    PAD_SKIPPED_NO_FRAME.fetch_add(1, Ordering::Relaxed);
}

/// P1-4 §4.2 执行侧：按 spec 对 envelope 帧求填充决策并产填充帧 payload。
///
/// - 决策 = M2 策略引擎 `decide_padding`（overhead cap 在策略层，§2.6；
///   envelope 为每流一帧，frame_seq 恒 0——多样性来自 flow_id，§2.2）；
/// - 帧总长精确命中目标形态：`pad_len` 字段自身占字节，固定点迭代使
///   `json' + K == padded_len`（未收敛=字段开销吃尽填充 → 不填充）；
/// - E4：payload 超既有头部上限（`MAX_HEADER_BYTES`）→ 不填充 + 计数；
/// - InPlace/Skip/超限/未收敛 → `None`（不填充，连通性优先，§6 E4/E10）。
fn pad_envelope_frame(
    env: &MeshEnvelope,
    spec: &seep_core::PaddingSpec,
    flow_id: &seep_core::FlowId,
) -> Result<Option<Vec<u8>>> {
    let base = encode_mesh_envelope_binary(env)?;
    let decision = seep_protocols::middleware::decide_padding(spec, base.len(), flow_id, 0);
    let target = match decision {
        seep_protocols::middleware::PadDecision::Pad { padded_len, .. } => padded_len,
        seep_protocols::middleware::PadDecision::InPlace => return Ok(None),
        seep_protocols::middleware::PadDecision::Skip {
            reason: seep_protocols::middleware::PadSkipReason::TooLarge,
        } => {
            PAD_SKIPPED_TOO_LARGE.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        seep_protocols::middleware::PadDecision::Skip {
            reason: seep_protocols::middleware::PadSkipReason::OverheadCap,
        } => {
            PAD_SKIPPED_OVERHEAD.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
    };
    if target + 4 > MAX_HEADER_BYTES {
        PAD_SKIPPED_TOO_LARGE.fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }
    // 固定点：声明 K 使 json'(含 pad_len 字段) + K == target
    let mut declared = target.saturating_sub(base.len());
    for _ in 0..3 {
        let mut env2 = env.clone();
        env2.version = PAD_ENVELOPE_VERSION;
        env2.pad_len = declared as u32;
        let bin = encode_mesh_envelope_binary(&env2)?;
        match target.checked_sub(bin.len()) {
            Some(k) if k == declared => {
                let mut payload = bin;
                payload.resize(target, 0);
                // §5 {mode} 封闭标签：帧计数按决策所用 spec 模式分桶
                let frames = match spec.mode {
                    seep_core::PaddingMode::Fixed => &PAD_FRAMES_FIXED,
                    seep_core::PaddingMode::Bucket => &PAD_FRAMES_BUCKET,
                    seep_core::PaddingMode::Range => &PAD_FRAMES_RANGE,
                };
                frames.fetch_add(1, Ordering::Relaxed);
                PAD_BYTES_ADDED.fetch_add(declared as u64, Ordering::Relaxed);
                return Ok(Some(payload));
            }
            Some(k) => declared = k,
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// P1-4 §2.4 / P2-6：帧载荷解码——按首字节嗅探双格式（§9-1 假设：JSON
/// 帧恒以 `{` 开头、二进制帧恒以 `'S'` 开头，两者不相交）：
/// - `{` → 旧 JSON 路径（接收侧兼容；剥尾部 0x00 后 JSON 解析，E7 两门）；
/// - 否则 → 二进制路径（P2-6 `decode_mesh_envelope_binary`，E5/E6 在内）。
fn decode_envelope_payload(buf: &[u8]) -> Result<MeshEnvelope> {
    if buf.first() == Some(&b'{') {
        let zeros = buf.iter().rev().take_while(|&&b| b == 0).count();
        let env: MeshEnvelope = serde_json::from_slice(&buf[..buf.len() - zeros])?;
        if env.pad_len as usize != zeros {
            anyhow::bail!(
                "mesh envelope pad_len {} 与帧尾 {zeros} 字节 0x00 不一致（E7，丢弃帧）",
                env.pad_len
            );
        }
        if zeros > 0 && env.version < PAD_ENVELOPE_VERSION {
            anyhow::bail!(
                "mesh envelope version {} 携带填充（E7，须 ≥ {PAD_ENVELOPE_VERSION}）",
                env.version
            );
        }
        return Ok(env);
    }
    decode_mesh_envelope_binary(buf)
}

/// P2-6 §2：TCP 面二进制 envelope 头版本（结构 ver；与 `env.version`
/// 填充能力门正交）。
pub const MESH_ENVELOPE_BIN_VERSION: u8 = 2;

/// P2-6 §2：`MeshEnvelope` 二进制编码（大端，与 UDP `UdpEnvelope` 同风格布局）。
/// 校验失败一律 Err（截断/保留位/长度字段越界）；尾部 pad 一致性由
/// `decode_mesh_envelope_binary` 的 pad 校验兜底（E5/E6，§3）。
pub fn encode_mesh_envelope_binary(env: &MeshEnvelope) -> Result<Vec<u8>> {
    if env.path.len() > u8::MAX as usize {
        anyhow::bail!("mesh envelope: 路径节点数超上界 255");
    }
    if env.flow_id.is_empty() || env.flow_id.len() > u8::MAX as usize {
        anyhow::bail!("mesh envelope: flow_id 长度非法（空或 >255）");
    }
    if env.target_host.is_empty() || env.target_host.len() > u8::MAX as usize {
        anyhow::bail!("mesh envelope: target_host 长度非法（空或 >255）");
    }
    for id in &env.path {
        if id.is_empty() || id.len() > u8::MAX as usize {
            anyhow::bail!("mesh envelope: node_id 长度非法（空或 >255）");
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"SU");
    out.push(MESH_ENVELOPE_BIN_VERSION);
    out.push(0u8); // flags 保留位恒 0
    out.extend_from_slice(&env.version.to_be_bytes());
    out.push(env.flow_id.len() as u8);
    out.extend_from_slice(env.flow_id.as_bytes());
    out.push(env.target_host.len() as u8);
    out.extend_from_slice(env.target_host.as_bytes());
    out.extend_from_slice(&env.target_port.to_be_bytes());
    out.push(env.path.len() as u8);
    for id in &env.path {
        out.push(id.len() as u8);
        out.extend_from_slice(id.as_bytes());
    }
    out.extend_from_slice(&env.pad_len.to_be_bytes());
    Ok(out)
}

/// P2-6 §2/§3：二进制 envelope 解码——头部二进制解析 + 尾部 pad 一致性
///（E5：pad_len == 帧尾 0x00 数；E6 = P1-4 §2.4 版门：pad_len > 0 须
/// version ≥ PAD_ENVELOPE_VERSION）。`buf` 为完整帧体（含尾部 pad）。
pub fn decode_mesh_envelope_binary(buf: &[u8]) -> Result<MeshEnvelope> {
    if buf.len() < 2 + 1 + 1 + 4 + 1 + 1 + 1 + 2 + 1 + 4 {
        anyhow::bail!("mesh envelope: 截断（固定头）");
    }
    if &buf[0..2] != b"SU" {
        anyhow::bail!("mesh envelope: magic 不符");
    }
    let ver = buf[2];
    if ver != MESH_ENVELOPE_BIN_VERSION {
        anyhow::bail!(
            "mesh envelope: 不支持的二进制版本 {ver}（仅支持 {MESH_ENVELOPE_BIN_VERSION}）"
        );
    }
    let flags = buf[3];
    if flags != 0 {
        anyhow::bail!("mesh envelope: 保留位非 0（flags=0x{flags:02x}）");
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    let mut pos = 8usize;

    fn read_len_bytes<'a>(buf: &'a [u8], pos: &mut usize, what: &str) -> Result<&'a [u8]> {
        let len =
            *buf.get(*pos)
                .ok_or_else(|| anyhow!("mesh envelope: 截断（{what} len）"))? as usize;
        *pos += 1;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("mesh envelope: 长度溢出（{what}）"))?;
        let s = buf
            .get(*pos..end)
            .ok_or_else(|| anyhow!("mesh envelope: 截断（{what}）"))?;
        *pos = end;
        Ok(s)
    }

    let flow_id = String::from_utf8(read_len_bytes(buf, &mut pos, "flow_id")?.to_vec())
        .map_err(|_| anyhow!("mesh envelope: flow_id 非 UTF-8"))?;
    let target_host = String::from_utf8(read_len_bytes(buf, &mut pos, "target_host")?.to_vec())
        .map_err(|_| anyhow!("mesh envelope: target_host 非 UTF-8"))?;
    if target_host.is_empty() {
        anyhow::bail!("mesh envelope: target_host 为空");
    }
    let port_end = pos + 2;
    let target_port = u16::from_be_bytes(
        buf.get(pos..port_end)
            .ok_or_else(|| anyhow!("mesh envelope: 截断（port）"))?
            .try_into()
            .unwrap(),
    );
    pos = port_end;
    let hop_count = *buf
        .get(pos)
        .ok_or_else(|| anyhow!("mesh envelope: 截断（hop_count）"))? as usize;
    pos += 1;
    let mut path = Vec::with_capacity(hop_count);
    for _ in 0..hop_count {
        let id = String::from_utf8(read_len_bytes(buf, &mut pos, "node_id")?.to_vec())
            .map_err(|_| anyhow!("mesh envelope: node_id 非 UTF-8"))?;
        path.push(id);
    }
    let pad_len = u32::from_be_bytes(
        buf.get(pos..pos + 4)
            .ok_or_else(|| anyhow!("mesh envelope: 截断（pad_len）"))?
            .try_into()
            .unwrap(),
    ) as usize;
    pos += 4;
    let trailing = &buf[pos..];
    if trailing.iter().any(|&b| b != 0) {
        anyhow::bail!("mesh envelope: 头后存在非 0x00 字节（填充区污染）");
    }
    if trailing.len() != pad_len {
        anyhow::bail!(
            "mesh envelope pad_len {pad_len} 与帧尾 {} 字节 0x00 不一致（E7，丢弃帧）",
            trailing.len()
        );
    }
    if pad_len > 0 && version < PAD_ENVELOPE_VERSION {
        anyhow::bail!(
            "mesh envelope version {version} 携带填充（E7，须 ≥ {PAD_ENVELOPE_VERSION}）"
        );
    }
    Ok(MeshEnvelope {
        version,
        flow_id,
        target_host,
        target_port,
        path,
        pad_len: pad_len as u32,
    })
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
/// P2-7 M1 §3.2：带流序号版本（恒置 HAS_SEQ）；seq_present=false 时按 v1 编码。
pub const UDP_ENVELOPE_VERSION_V2: u8 = 2;
/// P2-7 M1 §3.2：flags bit1 = HAS_SEQ（帧携带 4 字节 BE 序号）
pub const UDP_FLAG_HAS_SEQ: u8 = 0x02;
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
    /// 恒 1（或 P2-7 M1 起恒 2），其他值解码拒绝
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
    /// P2-7 M1 §3.2：流序号（seq_present=true 时入帧；发送侧单调递增，
    /// relay 转发原样保留——端到端语义）。v1 帧恒 0。
    pub seq: u32,
    /// P2-7 M1 §3.2：本帧是否携带 seq（序列 = version=2 + HAS_SEQ；解码 v1 → false）
    pub seq_present: bool,
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
    // P2-7 M1 §3.2：版本由 seq_present 推导（v1 无 seq / v2 恒带 seq），
    // env.version 只做一致性校验（§3.7 E1：构造器缺陷可观测）。
    let wire_version = if env.seq_present {
        UDP_ENVELOPE_VERSION_V2
    } else {
        UDP_ENVELOPE_VERSION
    };
    if env.version != wire_version {
        anyhow::bail!(
            "udp envelope: version({}) 与 seq_present({}) 不一致（期望 {wire_version}）",
            env.version,
            env.seq_present
        );
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
        if id.len() > u8::MAX as usize {
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
    out.push(wire_version);
    let mut flags = match env.dir {
        UdpDir::Up => 0u8,
        UdpDir::Down => 1,
    };
    if env.seq_present {
        flags |= UDP_FLAG_HAS_SEQ;
    }
    out.push(flags);
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
    if env.seq_present {
        out.extend_from_slice(&env.seq.to_be_bytes());
    }
    if matches!(env.path_mode, UdpPathMode::Full) {
        out.push(env.path.len() as u8);
        for id in &env.path {
            out.push(id.len() as u8);
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
    let flags = buf[3];
    // P2-7 M1 §3.2 §3.7 E2/E5：v1 维持旧保留位矩阵；v2 仅新增 HAS_SEQ 位
    //（恒置——v2 无 seq 帧不存在）。
    let seq_present = match version {
        UDP_ENVELOPE_VERSION => {
            if flags & 0xFE != 0 {
                anyhow::bail!("udp envelope: 保留位非 0（flags=0x{flags:02x}）");
            }
            false
        }
        UDP_ENVELOPE_VERSION_V2 => {
            if flags & !0x03 != 0 {
                anyhow::bail!("udp envelope: v2 保留位非 0（flags=0x{flags:02x}）");
            }
            if flags & UDP_FLAG_HAS_SEQ == 0 {
                anyhow::bail!("udp envelope: v2 必须带 HAS_SEQ（flags=0x{flags:02x}）");
            }
            true
        }
        other => anyhow::bail!("udp envelope: 不支持的版本 {other}"),
    };
    let dir = if flags & 1 == 0 {
        UdpDir::Up
    } else {
        UdpDir::Down
    };
    let flow_id: [u8; 16] = buf[4..20].try_into().expect("长度已由固定头校验保证");
    let atyp = buf[20];
    let mut pos = 21usize;
    let target_host = match atyp {
        1 => {
            let o: [u8; 4] = udp_take(buf, &mut pos, 4, "addr v4")?.try_into().unwrap();
            Ipv4Addr::from(o).to_string()
        }
        4 => {
            let o: [u8; 16] = udp_take(buf, &mut pos, 16, "addr v6")?.try_into().unwrap();
            Ipv6Addr::from(o).to_string()
        }
        3 => {
            let len = udp_take(buf, &mut pos, 1, "domain len")?[0] as usize;
            let b = udp_take(buf, &mut pos, len, "domain")?;
            if len == 0 {
                anyhow::bail!("udp envelope: domain 长度为 0");
            }
            String::from_utf8(b.to_vec()).map_err(|_| anyhow!("udp envelope: domain 非 UTF-8"))?
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
    // P2-7 M1 §3.2：seq 段在 hop_index 之后（v2 恒 4 字节 BE；§3.7 E3 截断走 udp_take）
    let (seq, seq_present) = if seq_present {
        (
            u32::from_be_bytes(
                udp_take(buf, &mut pos, 4, "seq")?
                    .try_into()
                    .expect("长度由 udp_take 保证"),
            ),
            true,
        )
    } else {
        (0, false)
    };
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
        seq,
        seq_present,
        path,
        payload,
    })
}

// ── P2-7 M1 §3.4：RFC 4303 风格 64 位滑窗（防重放判定纯函数）──
//
// 键 = (flow_id, dir)——流 + 方向各自窗口。wrapping 差语义：diff = seq - last
// (wrapping) 为“前进量”；diff==0 重放、1..=63 前进接受（旧 last 入历史，
// 窗口前移）、d ≥ 64 且 < 2^31 视作前进跳变（接受并滑窗——标准防重放
// 语义，旧历史全部滑出 63 位窗口，重置 bits=0），其余视作“回退”（回退
// ≤63 位内查历史位，超窗拒）。2^32 空间半空间单调假设见 §6 偏差 4。
// 初始态（首包）无条件接受——窗口条目惰性创建（§7 R-replay2：仅校验
// 通过的流才入表）。

/// P2-7 M1 §3.4：单 (flow_id, dir) 窗口。bits bit i = 已收 seq == last-1-i；last
/// 本身不入 bits（相等即重放）；前进 d 时旧 last 落位 `bits |= 1 << (d-1)`——
/// 被超越的 last 成为历史（跳过的中间 seq 不置位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ReplayWindow {
    last: Option<u32>,
    bits: u64,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            last: None,
            bits: 0,
        }
    }

    /// 判定并前进：接受返回 true；重放/超窗返回 false 且状态不变。
    pub fn check_and_advance(&mut self, seq: u32) -> bool {
        let Some(last) = self.last else {
            self.last = Some(seq);
            return true;
        };
        let diff = seq.wrapping_sub(last) as u64;
        match diff {
            0 => false,
            // 前进窗口内（last+1 ..= last+63）：旧 last 入历史，窗口前移
            d @ 1..=63 => {
                self.bits = (self.bits << d) | (1u64 << (d - 1));
                self.last = Some(seq);
                true
            }
            // 前进超窗（d ≥ 64，半空间内即视为前进）：接受并滑动窗口。
            // 标准防重放语义（DTLS/IPsec）：前向跳变不可能是重放，须接受且
            // 窗口整体前移；旧历史全部滑出 63 位窗口，重置为仅新 last。
            // 反例：旧实现把 d ≥ 65 一律当「回退/跳变」拒掉且 last 不动——
            // seq 单调递增下窗口永不前进，一次丢 65+ 连续包即让该 flow 下行
            // 全拒直到 flow 消亡（TTL 回收）恢复，属真实可用性缺陷。
            d if d < (1u64 << 31) => {
                self.bits = 0;
                self.last = Some(seq);
                true
            }
            // 回退（wrapping 差落入后 2^31 半空间者）：last-63 ..= last-1
            // 内查历史位；更旧/跳变拒
            _ => {
                let back = last.wrapping_sub(seq) as u64;
                if (1..=63).contains(&back) {
                    let bit = 1u64 << (back - 1);
                    if self.bits & bit != 0 {
                        return false;
                    }
                    self.bits |= bit;
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// P2-7 M1 §3.5：防重放窗口键（flow_id + dir：上行 0 / 下行 1，与 flags 位一致）
pub(crate) type ReplayKey = ([u8; 16], u8);

// ── P0-4 §3：跳缓存 UdpFlowCache（relay/exit 的 flow_id → {next, prev, expiry} 本地状态）──
//
// FULL 首包 insert（已有同 flow_id = 重关联，刷新 prev/next/expiry）；CACHED touch 触碰
// expiry（惰性过期：过期条目判 miss 并移除）；上界驱逐 = 满时先扫过期、仍满逐最早
// expiry（同 TTL 下即最久未触，语义 LRU，§11-6，O(n) 无新依赖）；过期清扫由 serve
// 循环调用 sweep_expired（非独立任务）。expiry 字段允许测试就地改写（同文件
// #[cfg(test)] 可达私有字段），不引入时钟抽象。

#[derive(Debug, Clone)]
struct FlowCacheEntry {
    /// None = 本机为 exit
    next_hop: Option<(NodeId, SocketAddr)>,
    /// 上行来源（下行回送地址）
    prev: SocketAddr,
    /// last_touch + ttl
    expiry: Instant,
}

#[derive(Debug)]
struct UdpFlowCache {
    map: DashMap<[u8; 16], FlowCacheEntry>,
    ttl: Duration,
    max: usize,
    /// 上界驱逐计数（R10；过期清扫不计入）
    evicted: AtomicU64,
    /// CACHED/下行未命中计数（含"在表但已过期"的惰性过期 miss）
    unknown_flow: AtomicU64,
}

impl UdpFlowCache {
    fn new(ttl: Duration, max: usize) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            max,
            evicted: AtomicU64::new(0),
            unknown_flow: AtomicU64::new(0),
        }
    }

    /// FULL 首包插入 / 重关联刷新。满时先扫过期，仍满逐最早 expiry（§11-6）。
    fn insert(&self, flow_id: [u8; 16], entry: FlowCacheEntry) {
        if !self.map.contains_key(&flow_id) && self.map.len() >= self.max {
            self.sweep_expired(Instant::now());
            while self.map.len() >= self.max {
                let victim = self
                    .map
                    .iter()
                    .min_by_key(|r| r.value().expiry)
                    .map(|r| *r.key());
                match victim {
                    Some(k) => {
                        self.map.remove(&k);
                        self.evicted.fetch_add(1, Ordering::Relaxed);
                    }
                    None => break,
                }
            }
        }
        self.map.insert(flow_id, entry);
    }

    /// CACHED/下行查找：命中触碰 expiry 并返回条目克隆；未命中或已过期（惰性）
    /// 计 unknown_flow 并清除，返回 None。
    fn touch(&self, flow_id: &[u8; 16]) -> Option<FlowCacheEntry> {
        let now = Instant::now();
        let hit = if let Some(mut e) = self.map.get_mut(flow_id) {
            if now < e.expiry {
                e.expiry = now + self.ttl;
                Some(e.clone())
            } else {
                None // 在表但已过期
            }
        } else {
            None
        };
        if hit.is_none() {
            self.map.remove(flow_id);
            self.unknown_flow.fetch_add(1, Ordering::Relaxed);
        }
        hit
    }

    /// 移除条目（retire_flow 单点用，§13-1）。
    fn remove(&self, flow_id: &[u8; 16]) -> Option<FlowCacheEntry> {
        self.map.remove(flow_id).map(|(_, e)| e)
    }

    /// 过期清扫（serve 循环周期调用；时间由调用方传入，测试可显式控制）。
    fn sweep_expired(&self, now: Instant) {
        let expired: Vec<[u8; 16]> = self
            .map
            .iter()
            .filter(|r| r.value().expiry <= now)
            .map(|r| *r.key())
            .collect();
        for k in expired {
            self.map.remove(&k);
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)] // 观测读取点 = P0-5 get()/get_gauge() 装配（§13-2），S3 阶段仅测试消费
    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// P0-5 §2.4 快照读取点（`UdpFace::snapshot` 收编——计数归缓存所有，防双计）
    fn evicted_count(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    /// P0-5 §2.4 快照读取点（同上）
    fn unknown_flow_count(&self) -> u64 {
        self.unknown_flow.load(Ordering::Relaxed)
    }
}

// ── P0-4 §6：明文门（构建期拦截；env 只在读取层出现——§11-5/D-8）──

/// mesh UDP 面明文门。`ensure_usable` 只做显式参数检查；进程 env 的读取只发生在
/// `from_env`（调用方 = `RuntimeBuilder::build`，§13-6 合流点：cfg ∪ env 求值一次）。
/// Clone：§13-6 折叠值语义——client 桥（build）与非 client 面（start）消费同一合流结果的两个副本。
#[derive(Clone)]
pub struct MeshUdpGate {
    pub allow_plaintext: bool,
}

impl MeshUdpGate {
    pub fn new(allow_plaintext: bool) -> Self {
        Self { allow_plaintext }
    }

    /// env 读取层（唯一读 `SEEP_MESH_UDP_ALLOW_PLAINTEXT` 的地方；测试走 `new` 不碰 env）。
    pub fn from_env() -> Self {
        Self {
            allow_plaintext: env_flag("SEEP_MESH_UDP_ALLOW_PLAINTEXT", false),
        }
    }

    /// tls 缺失且未显式允许明文 → 拒绝启动（§6 / §10 T6）。
    pub fn ensure_usable(&self, tls: Option<&MeshTlsConfig>) -> Result<()> {
        if tls.is_none() && !self.allow_plaintext {
            anyhow::bail!(
                "mesh UDP 面未配置加密且未显式允许明文（SEEP_MESH_UDP_ALLOW_PLAINTEXT=1）；chain+udp 组合拒绝启动（udp-mesh-dataplane.md §4.4/V2）"
            );
        }
        Ok(())
    }
}

// ── P0-4 §13-2：UdpFaceMetrics（P0-5 §2.4 `seep_udp_mesh_*` 数据源）──
//
// 字段口径与 §13-2 六字段一致；偏差一处（循 S2 既有裁决）：`unknown_flow`/`evicted`
// 不在本结构复制——归 `UdpFlowCache` 所有（S2 注记：读取时经缓存取，防双计），本结构
// 只持有面自身计数。快照读取点 = P0-5 S3 `UdpFace::snapshot()`。

/// 缓存 TTL 默认 = `udp.mapping_idle_secs`（§3，60s；S5 接配置走 `with_udp_limits`）。
const UDP_FACE_DEFAULT_TTL: Duration = Duration::from_secs(60);
/// 缓存上界默认 = R10 的 65536（§3）。pub = runtime 接线点传参（ttl 走配置、上界走本默认）。
pub const UDP_FACE_DEFAULT_MAX: usize = 65536;
/// §14-1 hop_index 熔断上界：CACHED 成环的唯一断路器（FULL 靠 path 严格递减防环）。
const MAX_UDP_HOPS: u8 = 16;

struct UdpFaceMetrics {
    /// 上行方向成功发出的数据报（relay 重编码发出 / exit 发往 target）
    forwarded_up: AtomicU64,
    /// 下行方向成功发出的数据报（exit 下行封装发出 / relay 发往 prev）
    forwarded_down: AtomicU64,
    /// 解码拒绝（§2 校验失败）+ §13-3 超界 + §14-1 hop 溢出
    malformed: AtomicU64,
    /// P2-7 M1 §3.6：防重放窗口拒帧（E4 静默丢弃——不混 malformed/unknown_flow，
    /// 新语义新计数；拒绝即计数，与快照/渲染不变式一致）
    replay_dropped: AtomicU64,
    /// 缓存条目数 gauge（插/逐/清扫后同步——净额即 len；§13-2 允许 sweep 时点偏差）
    flows_active: AtomicI64,
}

impl UdpFaceMetrics {
    fn new() -> Self {
        Self {
            forwarded_up: AtomicU64::new(0),
            forwarded_down: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            replay_dropped: AtomicU64::new(0),
            flows_active: AtomicI64::new(0),
        }
    }
}

/// P0-5 §2.4：mesh UDP 面快照（`seep_udp_mesh_*` 数据源 / `/udp/stats` mesh 段）。
/// 六字段 = `UdpFaceMetrics` 四值 + `UdpFlowCache` 收编两计数（`unknown_flow`/
/// `evicted` 归缓存所有——防双计口径不变，§13-2 偏差注记）；`flows_active` 为
/// gauge（缓存条目净额），其余 counter。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct UdpFaceSnapshot {
    pub forwarded_up: u64,
    pub forwarded_down: u64,
    pub malformed: u64,
    /// P2-7 M1 §3.6：防重放窗口拒帧（E4），counter
    pub replay_dropped: u64,
    pub flows_active: i64,
    pub unknown_flow: u64,
    pub evicted: u64,
}

/// exit 每 flow 独立 connected socket + 下行 task（§4 / §13-1）。
struct ExitFlow {
    sock: Arc<UdpSocket>,
    task: JoinHandle<()>,
    /// (host, port)——§13-4 FULL 重关联的 target 变化判据；下行封装回填该 target
    target: (String, u16),
}

/// P0-4 UDP 面状态：跳缓存（§3）+ exit flow 表（§13-1）+ 计数（§13-2）。
///
/// 设计 §4 草图为 `MeshDataPlane.udp: Option<UdpFace>`；落地为 `Option<Arc<UdpFace>>`
/// ——exit 下行 task 需 `'static` 共享同一份状态（功能等价，task 所有权使然）。
struct UdpFace {
    cache: UdpFlowCache,
    flows: DashMap<[u8; 16], ExitFlow>,
    /// P2-7 M1 §3.5：防重放窗口表（(flow_id, dir) 键；条目惰性创建、随
    /// 缓存/flow 表消亡点回收——见 sweep/retire_flow/forget_flow 接缝）
    replay: DashMap<ReplayKey, ReplayWindow>,
    metrics: UdpFaceMetrics,
}

impl UdpFace {
    fn new() -> Self {
        Self::with_limits(UDP_FACE_DEFAULT_TTL, UDP_FACE_DEFAULT_MAX)
    }

    fn with_limits(ttl: Duration, max: usize) -> Self {
        Self {
            cache: UdpFlowCache::new(ttl, max),
            flows: DashMap::new(),
            replay: DashMap::new(),
            metrics: UdpFaceMetrics::new(),
        }
    }

    /// P2-7 M1 §3.4/§3.5：窗口判定（seq_present=false 的 v1 帧 fail-open 跳过）。
    /// 命中即返回——调用方丢弃报文（E4 静默，不计 malformed）。
    fn replay_check(&self, flow_id: [u8; 16], dir: UdpDir, seq: u32, seq_present: bool) -> bool {
        if !seq_present {
            return true;
        }
        let dir_bit = match dir {
            UdpDir::Up => 0u8,
            UdpDir::Down => 1,
        };
        match self.replay.get_mut(&(flow_id, dir_bit)) {
            Some(mut w) => w.check_and_advance(seq),
            // 惰性创建：首包无条件接受并建条目（§7 R-replay2——重放帧必先
            // 被真实首包拉出窗口；不存在流的伪造帧不建表污染）
            None => {
                let mut w = ReplayWindow::new();
                let ok = w.check_and_advance(seq);
                self.replay.insert((flow_id, dir_bit), w);
                ok
            }
        }
    }

    /// FULL 首包插入 / 重关联刷新（§3/§13-4）；gauge 随缓存条目数同步。
    fn associate(
        &self,
        flow_id: [u8; 16],
        next_hop: Option<(NodeId, SocketAddr)>,
        prev: SocketAddr,
    ) {
        let expiry = Instant::now() + self.cache.ttl;
        self.cache.insert(
            flow_id,
            FlowCacheEntry {
                next_hop,
                prev,
                expiry,
            },
        );
        self.sync_gauge();
    }

    fn contains(&self, flow_id: &[u8; 16]) -> bool {
        self.cache.map.contains_key(flow_id)
    }

    /// 无副作用读取（下行 task 现读 `prev`——FULL 重关联刷新后下行随之改向，§4）。
    /// 不触碰 expiry、不计 `unknown_flow`（那两个语义留给 CACHED/下行数据报的 touch）。
    fn peek_entry(&self, flow_id: &[u8; 16]) -> Option<FlowCacheEntry> {
        self.cache.map.get(flow_id).map(|r| r.value().clone())
    }

    /// §13-1 回收单点：abort task → flows.remove → cache.remove（三步顺序固定，
    /// 先停 task 再拆两表，杜绝下行 task 向已删 prev 发包）。
    fn retire_flow(&self, flow_id: &[u8; 16]) {
        if let Some(r) = self.flows.get(flow_id) {
            r.task.abort();
        }
        self.flows.remove(flow_id);
        self.cache.remove(flow_id);
        // P2-7 M1 §3.5：窗口条目随 flow 消亡回收（上行/下行键同流同删）
        self.replay.remove(&(*flow_id, 0));
        self.replay.remove(&(*flow_id, 1));
        self.sync_gauge();
    }

    /// 下行 task 自身退出路径（§13-1：task 自清理时不 abort 自己——取 retire_flow
    /// 的后两步，顺序保持 flows 先于 cache）。
    fn forget_flow(&self, flow_id: &[u8; 16]) {
        self.flows.remove(flow_id);
        self.cache.remove(flow_id);
        self.replay.remove(&(*flow_id, 0));
        self.replay.remove(&(*flow_id, 1));
        self.sync_gauge();
    }

    /// need_create=false 时按表内 per-flow socket 直发。并发 forget_flow 拆除
    /// → miss 静默丢弃且不计转发成功（UDP 容忍丢包，客户端重发 FULL 重建）。
    async fn send_existing_flow(&self, flow_id: &[u8; 16], payload: &[u8]) -> Result<bool> {
        let Some(flow_sock) = self.flows.get(flow_id).map(|e| Arc::clone(&e.sock)) else {
            return Ok(false);
        };
        flow_sock.send(payload).await?;
        self.metrics.forwarded_up.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// serve 循环懒清扫（§3 每秒；§13-1 触发点①）：过期条目出缓存后，exit flow 表
    /// 中不再有缓存条目者连带回收。
    fn sweep(&self) {
        self.cache.sweep_expired(Instant::now());
        let orphans: Vec<[u8; 16]> = self
            .flows
            .iter()
            .filter(|r| !self.cache.map.contains_key(r.key()))
            .map(|r| *r.key())
            .collect();
        for id in orphans {
            self.retire_flow(&id);
        }
        // P2-7 M1 §3.5：窗口条目随缓存生命周期——纯 relay/exit 转发流（无
        // ExitFlow）由 sweep 扫除：flow_id 已不在缓存/flow 两表的窗口键全删。
        let stale: Vec<ReplayKey> = self
            .replay
            .iter()
            .filter(|r| {
                !self.cache.map.contains_key(&r.key().0) && !self.flows.contains_key(&r.key().0)
            })
            .map(|r| *r.key())
            .collect();
        for k in stale {
            self.replay.remove(&k);
        }
        self.sync_gauge();
    }

    fn sync_gauge(&self) {
        self.metrics
            .flows_active
            .store(self.cache.len() as i64, Ordering::Relaxed);
    }

    /// P0-5 §2.4：面快照（metrics 四值 + 缓存两计数合并，relaxed 读——监控口径）。
    fn snapshot(&self) -> UdpFaceSnapshot {
        UdpFaceSnapshot {
            forwarded_up: self.metrics.forwarded_up.load(Ordering::Relaxed),
            forwarded_down: self.metrics.forwarded_down.load(Ordering::Relaxed),
            malformed: self.metrics.malformed.load(Ordering::Relaxed),
            replay_dropped: self.metrics.replay_dropped.load(Ordering::Relaxed),
            flows_active: self.metrics.flows_active.load(Ordering::Relaxed),
            unknown_flow: self.cache.unknown_flow_count(),
            evicted: self.cache.evicted_count(),
        }
    }
}

/// exit 下行 task（§4 / §13-1，与 P0-1 forwarder 同构）：target 回包 → 封
/// `UdpEnvelope{dir:Down, Cached, hop_index:0, version:2, seq: 递增}` → 面 socket
/// 发往 `cache.prev`（每次现读 prev——FULL 重关联刷新后下行随之改向）。
/// P2-7 M1 §3.3：`down_seq` 序号源随建流新建（§13-1 生命周期随 ExitFlow——重关联
/// retire 重建后序号归零，与接收侧窗口移除同步）。
async fn exit_downlink_loop(
    face: Arc<UdpFace>,
    flow: Arc<UdpSocket>,
    face_sock: Arc<UdpSocket>,
    flow_id: [u8; 16],
    target: (String, u16),
    down_seq: Arc<AtomicU32>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = match flow.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => {
                // §13-1 触发点②：target 不可达/复位 → 清 flow socket + 缓存条目
                face.forget_flow(&flow_id);
                return;
            }
        };
        let Some(prev) = face.peek_entry(&flow_id).map(|e| e.prev) else {
            // 条目已被清扫/回收（触发点①先于本 task 退出）→ 自清理
            face.forget_flow(&flow_id);
            return;
        };
        let env = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION_V2,
            dir: UdpDir::Down,
            flow_id,
            target_host: target.0.clone(),
            target_port: target.1,
            path_mode: UdpPathMode::Cached,
            hop_index: 0, // §14-1：下行发送端（exit）置 0
            // P2-7 M1 §3.3：exit 下行单调序号（建流时新建，fetch_add 即单调）
            seq: down_seq.fetch_add(1, Ordering::Relaxed),
            seq_present: true,
            path: Vec::new(),
            payload: buf[..n].to_vec(),
        };
        match encode_udp_envelope(&env) {
            Ok(wire) => {
                if face_sock.send_to(&wire, &prev).await.is_ok() {
                    face.metrics.forwarded_down.fetch_add(1, Ordering::Relaxed);
                }
                // send 失败（对端不可达）= 单包丢失；连接层错误由 recv 侧统一回收
            }
            Err(_) => {
                // §13-3：封包超 65507 上界 → 丢该包计 malformed
                face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub struct MeshDataPlane {
    local_node_id: NodeId,
    local_role: NodeRole,
    registry: Arc<MeshRegistry>,
    tls: Option<Arc<MeshTls>>,
    /// P0-4 §4 UDP 面（S3 挂载；None = 纯 TCP 面）。Arc 供下行 task `'static` 共享。
    udp: Option<Arc<UdpFace>>,
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
            udp: None,
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

    /// P0-4 §6/§9.1.1 S3：挂载 UDP 面。gate 先对既有 tls 配置过 `ensure_usable`——
    /// 检查点在拉起面之前（serve/associate 层不再重复检查，§6）。
    pub fn with_udp(self, gate: MeshUdpGate) -> Result<Self> {
        gate.ensure_usable(self.tls.as_ref().map(|t| t.cfg()))?;
        let mut me = self;
        me.udp = Some(Arc::new(UdpFace::new()));
        Ok(me)
    }

    /// 同 `with_udp`，TTL/上界走参数（S5 接 `udp.mapping_idle_secs` 等配置；测试传小值）。
    pub fn with_udp_limits(self, gate: MeshUdpGate, ttl: Duration, max: usize) -> Result<Self> {
        gate.ensure_usable(self.tls.as_ref().map(|t| t.cfg()))?;
        let mut me = self;
        me.udp = Some(Arc::new(UdpFace::with_limits(ttl, max)));
        Ok(me)
    }

    /// P0-5 §2.4：UDP 面快照（None = 纯 TCP 面——未挂 UDP 的 plane）。
    pub fn udp_snapshot(&self) -> Option<UdpFaceSnapshot> {
        self.udp.as_ref().map(|f| f.snapshot())
    }

    /// P2-7 M0 §2.1：撤销生效面快照（None = 未以 mTLS 装配——纯明文 TCP 面）。
    /// `GET /mtls/revoked` 数据源，经 runtime 观测接缝暴露（runtime_builder.rs）。
    pub async fn revoked_snapshot(&self) -> Option<RevokedSnapshot> {
        match &self.tls {
            Some(tls) => Some(tls.revoked_snapshot().await),
            None => None,
        }
    }

    /// TCP 面 serve（S5 起 `self: Arc<Self>`——与 `spawn_udp` 并列共享同一 plane 实例，
    /// 同端口双栈；§9.2）。
    pub fn spawn(self: Arc<Self>, bind: SocketAddr) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { self.serve(bind).await })
    }

    async fn serve(&self, bind: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind).await?;
        let tls = self.tls.clone();
        loop {
            let (stream, _peer) = listener.accept().await?;
            let this = Self {
                local_node_id: self.local_node_id.clone(),
                local_role: self.local_role,
                registry: self.registry.clone(),
                tls: tls.clone(),
                udp: self.udp.clone(),
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
        // P1-4 §2.4 版本门：1 = 既有帧形，2 = 填充能力版本（PAD_ENVELOPE_VERSION）；
        // 中继转发帧不追加填充（对齐 UDP 面 D-16 裁决），下游重编码为 version=1
        if env.version != MESH_ENVELOPE_VERSION && env.version != PAD_ENVELOPE_VERSION {
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
            let (up, down) = match copy_bidirectional_with_sizes(
                &mut inbound,
                &mut out,
                seep_core::performance::relay_buffer(),
                seep_core::performance::relay_buffer(),
            )
            .await
            {
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

        let (up, down) = match copy_bidirectional_with_sizes(
            &mut inbound,
            &mut outbound,
            seep_core::performance::relay_buffer(),
            seep_core::performance::relay_buffer(),
        )
        .await
        {
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
        // net_mark 统一拨号（SO_MARK 逃逸面，networking.md §2；缺省 0 零差异）
        let stream = seep_core::net_mark::connect_tcp(addr).await?;
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
        pad_spec: Option<&seep_core::PaddingSpec>,
        flow_id: &seep_core::FlowId,
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
        // P1-4 §4.2：执行点=序列化后、写 wire 前——spec 缺席（未选中/解析失败
        // E9）即旧行为 write_envelope；命中则写填充帧（帧长命中目标形态）
        let payload = match pad_spec {
            Some(spec) => pad_envelope_frame(envelope, spec, flow_id)?,
            None => None,
        };
        match payload {
            Some(padded) => write_frame(&mut stream, &padded).await?,
            None => write_envelope(&mut stream, envelope).await?,
        }
        let (up, down) = match copy_bidirectional_with_sizes(
            io,
            &mut stream,
            seep_core::performance::relay_buffer(),
            seep_core::performance::relay_buffer(),
        )
        .await
        {
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

    // ── P0-4 §4：UDP 面数据报处理（serve_udp 调用；测试直调）──

    /// 单数据报处理（§4 状态机）：解码 → 上行 FULL/CACHED 或下行回流分派。
    /// 转发与回包共用节点级共享面 socket `sock`（§1/D-2：相邻跳来源地址稳定）。
    pub async fn handle_udp_datagram(
        &self,
        sock: &Arc<UdpSocket>,
        from: SocketAddr,
        buf: &[u8],
    ) -> Result<()> {
        let face = self
            .udp
            .as_ref()
            .ok_or_else(|| anyhow!("mesh UDP 面未启用（先 with_udp）"))?;
        // §4 步骤 1 + §13-3：解码拒绝/超上界 → malformed 丢弃
        if buf.len() > UDP_ENVELOPE_MAX {
            face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!(
                "udp envelope: 数据报 {} 字节超上界 {}（§13-3）",
                buf.len(),
                UDP_ENVELOPE_MAX
            );
        }
        let env = match decode_udp_envelope(buf) {
            Ok(v) => v,
            Err(e) => {
                face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        // P2-7 M1 §3.4/§3.7 E4：防重放窗口（decode 后、分派前；v1 帧
        // seq_present=false fail-open）；重放/超窗静默丢弃即计数——§3.6
        // 拒绝即计数不变式（不混 malformed/unknown_flow）
        if !face.replay_check(env.flow_id, env.dir, env.seq, env.seq_present) {
            face.metrics.replay_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        match env.dir {
            UdpDir::Up => self.udp_uplink(face, sock, from, env).await,
            UdpDir::Down => self.udp_downlink(face, sock, env).await,
        }
    }

    /// 上行（dir=Up）状态机（§4 步骤 2-4）。
    async fn udp_uplink(
        &self,
        face: &Arc<UdpFace>,
        sock: &Arc<UdpSocket>,
        from: SocketAddr,
        env: UdpEnvelope,
    ) -> Result<()> {
        match env.path_mode {
            UdpPathMode::Full => {
                // §4 步骤 2 的 path 校验只对 FULL 生效：CACHED 结构上恒无 path 字段
                //（§4 步骤 2 列于分支前，但按步 4 的 CACHED 语义，非空/对位校验仅 FULL 可判）。
                if env.path.is_empty() {
                    anyhow::bail!("udp: FULL 路径为空（编码侧已禁，防御）");
                }
                if env.path[0] != self.local_node_id {
                    anyhow::bail!(
                        "udp envelope path[0] mismatch: expected {}, got {}",
                        self.local_node_id,
                        env.path[0]
                    );
                }
                if !matches!(
                    self.local_role,
                    NodeRole::Relay | NodeRole::Hybrid | NodeRole::Exit
                ) {
                    anyhow::bail!("node role {} cannot act as udp face", self.local_role);
                }
                if env.path.len() == 1 {
                    if !matches!(self.local_role, NodeRole::Exit | NodeRole::Hybrid) {
                        anyhow::bail!(
                            "node role {} cannot act as exit (target hop)",
                            self.local_role
                        );
                    }
                    self.exit_uplink(face, sock, from, env, true).await
                } else {
                    // 中继转发（§4 步骤 3 / D-4）：剥自身重编码，不降级 CACHED。
                    // 角色 ∈ {Relay, Hybrid}——§4 未逐字写本检查，与 TCP 面 forward hop
                    // 同语义（handle_stream 同点位）：exit-only 节点不当中继。
                    if !matches!(self.local_role, NodeRole::Relay | NodeRole::Hybrid) {
                        anyhow::bail!(
                            "node role {} cannot act as relay (forward hop)",
                            self.local_role
                        );
                    }
                    let next = env.path[1].clone();
                    if let Some(rec) = self.registry.get_node(&next) {
                        if rec.role == NodeRole::Client {
                            anyhow::bail!("invalid next hop role client: {next}");
                        }
                    }
                    let next_addr = self
                        .registry
                        .get_node_addr(&next)
                        .ok_or_else(|| anyhow!("next hop {next} not found in registry"))?;
                    let first = !face.contains(&env.flow_id);
                    face.associate(env.flow_id, Some((next.clone(), next_addr)), from);
                    let fwd = UdpEnvelope {
                        version: env.version,
                        dir: UdpDir::Up,
                        flow_id: env.flow_id,
                        target_host: env.target_host,
                        target_port: env.target_port,
                        path_mode: UdpPathMode::Full,
                        hop_index: env.hop_index.saturating_add(1), // §14-1 每经一跳 +1
                        // P2-7 M1 §3.3：转发保留入帧 seq（端到端语义，非逐跳重编号）
                        seq: env.seq,
                        seq_present: env.seq_present,
                        path: env.path[1..].to_vec(),
                        payload: env.payload,
                    };
                    let wire = match encode_udp_envelope(&fwd) {
                        Ok(w) => w,
                        Err(e) => {
                            face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                            return Err(e);
                        }
                    };
                    if let Err(e) = sock.send_to(&wire, &next_addr).await {
                        self.registry.record_link_error(&self.local_node_id, &next);
                        return Err(e.into());
                    }
                    if first {
                        // §7：record_link_connection 仅 FULL 首包记一次
                        self.registry
                            .record_link_connection(&self.local_node_id, &next);
                    }
                    self.registry
                        .record_link_bytes(&self.local_node_id, &next, wire.len() as u64);
                    face.metrics.forwarded_up.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            }
            UdpPathMode::Cached => {
                // §4 步骤 4：查缓存；未命中 = unknown_flow 丢弃（touch 已计数，§10 T4）
                let Some(entry) = face.cache.touch(&env.flow_id) else {
                    return Ok(());
                };
                match entry.next_hop {
                    None => self.exit_uplink(face, sock, from, env, false).await,
                    Some((next, next_addr)) => {
                        if env.hop_index >= MAX_UDP_HOPS {
                            // §14-1：CACHED 成环熔断
                            face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                            anyhow::bail!(
                                "udp: hop_index {} 超上限 {MAX_UDP_HOPS}（§14-1 环熔断）",
                                env.hop_index
                            );
                        }
                        let fwd = UdpEnvelope {
                            version: env.version,
                            dir: UdpDir::Up,
                            flow_id: env.flow_id,
                            target_host: env.target_host,
                            target_port: env.target_port,
                            path_mode: UdpPathMode::Cached,
                            hop_index: env.hop_index + 1, // 已过上界检查
                            seq: env.seq,
                            seq_present: env.seq_present, // §3.3 转发保留 seq
                            path: env.path,               // CACHED 恒空
                            payload: env.payload,
                        };
                        let wire = match encode_udp_envelope(&fwd) {
                            Ok(w) => w,
                            Err(e) => {
                                face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                                return Err(e);
                            }
                        };
                        if let Err(e) = sock.send_to(&wire, &next_addr).await {
                            self.registry.record_link_error(&self.local_node_id, &next);
                            return Err(e.into());
                        }
                        self.registry.record_link_bytes(
                            &self.local_node_id,
                            &next,
                            wire.len() as u64,
                        );
                        face.metrics.forwarded_up.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                }
            }
        }
    }

    /// 下行（dir=Down，relay 收到）（§4 下行）：查缓存 → `send_to(cache.prev)`，
    /// 重编码只 +1 hop_index（CACHED 无 path 字段，不动路径）；未命中 → unknown_flow 丢弃。
    async fn udp_downlink(
        &self,
        face: &Arc<UdpFace>,
        sock: &Arc<UdpSocket>,
        env: UdpEnvelope,
    ) -> Result<()> {
        let Some(entry) = face.cache.touch(&env.flow_id) else {
            return Ok(());
        };
        if env.hop_index >= MAX_UDP_HOPS {
            face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!(
                "udp: hop_index {} 超上限 {MAX_UDP_HOPS}（§14-1 环熔断）",
                env.hop_index
            );
        }
        let fwd = UdpEnvelope {
            version: env.version,
            dir: UdpDir::Down,
            flow_id: env.flow_id,
            target_host: env.target_host,
            target_port: env.target_port,
            path_mode: env.path_mode,
            hop_index: env.hop_index.saturating_add(1), // §14-1：每经一 relay +1（上下行对称）
            seq: env.seq,
            seq_present: env.seq_present, // §3.3 转发保留 seq
            path: env.path,
            payload: env.payload,
        };
        let wire = match encode_udp_envelope(&fwd) {
            Ok(w) => w,
            Err(e) => {
                face.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        // 从共享面 socket 回送（§1/D-2：对上一跳来源地址稳定）。registry 无 addr→node
        // 反查，下行方向不记 record_link_bytes——与 TCP 面「仅已知节点 id 方向记账」一致。
        sock.send_to(&wire, &entry.prev).await?;
        face.metrics.forwarded_down.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// exit 分支（§4）：每 flow 独立 connected socket 发往真实 target（复用 P0-3
    /// LocalRelay 语义），下行 task 从共享面 socket 回封（§13-1 生命周期）。
    /// `is_full` = FULL 重关联（插/刷缓存）；CACHED 的 touch 已在上层完成。
    async fn exit_uplink(
        &self,
        face: &Arc<UdpFace>,
        face_sock: &Arc<UdpSocket>,
        from: SocketAddr,
        env: UdpEnvelope,
        is_full: bool,
    ) -> Result<()> {
        let target = (env.target_host.clone(), env.target_port);
        let existing_target = face.flows.get(&env.flow_id).map(|f| f.target.clone());
        let need_create = existing_target.as_ref() != Some(&target);
        if need_create {
            // §13-4：FULL 重关联到新 target → 先回收旧 socket/task 再按新 target 建流
            if existing_target.is_some() {
                face.retire_flow(&env.flow_id);
            }
            // §7：exit 出向对 flow 首次出向字节走配额；Err → 丢弃（不拆链）。
            // 计数字段 §13-2 未列，P0-5 观测轮再定，不混入 malformed。
            self.registry
                .check_quota(&self.local_node_id, env.payload.len() as u64)?;
            let addr = {
                let mut addrs = lookup_host((env.target_host.as_str(), env.target_port)).await?;
                addrs.next().ok_or_else(|| {
                    anyhow!(
                        "no resolved address for {}:{}",
                        env.target_host,
                        env.target_port
                    )
                })?
            };
            let bind_addr = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let flow_sock = Arc::new(UdpSocket::bind(bind_addr).await?);
            flow_sock.connect(addr).await?;
            if let Err(e) = flow_sock.send(&env.payload).await {
                // 目标不可达：表项尚未建立，socket 直接丢弃（无需 §13-1 回收）
                return Err(e.into());
            }
            if is_full {
                face.associate(env.flow_id, None, from);
            }
            // P2-7 M1 §3.3：下行序号源随建流新建（旧 task 已 retire abort，
            // 序号归零与接收侧窗口移除同刻——重关联无序号断层混淆）
            let down_seq = Arc::new(AtomicU32::new(0));
            let task = tokio::spawn(exit_downlink_loop(
                Arc::clone(face),
                Arc::clone(&flow_sock),
                Arc::clone(face_sock),
                env.flow_id,
                target.clone(),
                down_seq,
            ));
            face.flows.insert(
                env.flow_id,
                ExitFlow {
                    sock: flow_sock,
                    task,
                    target,
                },
            );
        } else if is_full {
            // 重关联：同 flow 同 target → 只刷 prev/expiry（§3/§13-4）
            face.associate(env.flow_id, None, from);
        }
        if !need_create {
            // 拿出 Arc 再 await——避免持 DashMap Ref 跨 await（下行 task 可能并发 remove）
            // P1 修复：need_create=false 只保证读取瞬间条目存在；独立 worker 上的
            // 下行 task 可能在两次 get 间并发 forget_flow（§13-1 触发点②）。此前
            // .expect 在此 panic 会杀掉整条 serve_udp 任务——全节点 UDP 面停摆。
            // 命中即直发；miss = 条目被并发拆除 → 丢弃本包（客户端 ≤30s/64 包
            // 重发 FULL 自动重建，§5；UDP 语义容忍丢包），绝不 panic。
            face.send_existing_flow(&env.flow_id, &env.payload).await?;
            return Ok(());
        }
        face.metrics.forwarded_up.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // ── P0-4 §4/§13-5：同端口双栈 UDP serve（与 TCP spawn 共用 listen_address）──

    /// 单任务循环 serve：`recv_from → handle_udp_datagram` 顺序处理，不 per-packet
    /// spawn（§13-5/D-11）；每秒懒清扫并入本循环（§3：非独立任务）。
    pub fn spawn_udp(self: &Arc<Self>, bind: SocketAddr) -> JoinHandle<Result<()>> {
        let this = Arc::clone(self);
        tokio::spawn(async move { this.serve_udp(bind).await })
    }

    async fn serve_udp(&self, bind: SocketAddr) -> Result<()> {
        let sock = Arc::new(UdpSocket::bind(bind).await?);
        let face = self
            .udp
            .as_ref()
            .ok_or_else(|| anyhow!("mesh UDP 面未启用（先 with_udp 再 spawn_udp）"))?;
        let mut buf = vec![0u8; 65535];
        let mut last_sweep = Instant::now();
        loop {
            // timeout 先 poll recv（有包必取），仅在无包满 1s 时触发懒清扫——
            // 连续流量下按 last_sweep 补扫，保证"每秒"上界不因负载漂移。
            match tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    if let Err(e) = self.handle_udp_datagram(&sock, from, &buf[..n]).await {
                        tracing::debug!(
                            target: "seep::mesh::transport",
                            error = %e,
                            "mesh UDP 数据报丢弃"
                        );
                    }
                    if last_sweep.elapsed() >= Duration::from_secs(1) {
                        face.sweep();
                        last_sweep = Instant::now();
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    face.sweep();
                    last_sweep = Instant::now();
                }
            }
        }
    }
}

async fn connect_target(host: &str, port: u16) -> Result<TcpStream> {
    // lookup_host accepts "host:port" and yields SocketAddr entries.
    let mut addrs = lookup_host((host, port)).await?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow!("no resolved address for {host}:{port}"))?;
    // 解析面保持 lookup_host 首址语义；连接面走 net_mark 统一拨号
    // （SO_MARK 逃逸面，networking.md §2；缺省 0 零差异）
    Ok(seep_core::net_mark::connect_tcp(addr).await?)
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
    // P1-4 §2.4：接收侧解填充（未填充帧走纯 JSON 解析，与旧行为一致）
    decode_envelope_payload(&buf)
}

async fn write_envelope<W>(stream: &mut W, env: &MeshEnvelope) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let buf = encode_mesh_envelope_binary(env)?;
    write_frame(stream, &buf).await
}

/// P1-4 §2.4：`[len: u32][payload]` 帧写入（envelope 与填充帧共用）。
/// P3-5 performance-io.md §2-D2：两段 `write_vectored` 提交 + 短写推进——
/// 明文 TcpStream 段一次 syscall；rustls `TlsStream` 无 vectored 实现
/// （`is_write_vectored()=false`），tokio 默认实现回落单段写，行为等价
/// 现状两段 `write_all`。0 字节短写按连接关闭报错。
async fn write_frame<W>(stream: &mut W, payload: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if payload.len() > MAX_HEADER_BYTES {
        return Err(anyhow!("mesh header too large: {} bytes", payload.len()));
    }
    let len_be = (payload.len() as u32).to_be_bytes();
    let parts: [&[u8]; 2] = [&len_be, payload];
    let (mut si, mut so) = (0usize, 0usize);
    while si < parts.len() {
        let cur = &parts[si][so..];
        let next = parts.get(si + 1).copied().unwrap_or(&[]);
        let bufs = [std::io::IoSlice::new(cur), std::io::IoSlice::new(next)];
        let n = stream.write_vectored(&bufs).await?;
        if n == 0 {
            return Err(anyhow!("mesh 帧写：写入 0 字节（连接已关闭）"));
        }
        let mut rem = n;
        while rem > 0 && si < parts.len() {
            let avail = parts[si].len() - so;
            if rem < avail {
                so += rem;
                rem = 0;
            } else {
                rem -= avail;
                si += 1;
                so = 0;
            }
        }
    }
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

/// P2-7 M0 §2.1：撤销生效面运行期快照（`GET /mtls/revoked` 数据源）。
/// 调用前先 maybe_reload（与 is_revoked 同口径——快照即当前生效面）；
/// reload 失败沿用 fail-closed（连接面报错），快照呈现最近成功载入态并
/// 把失败详情放 `RevokedFileState::error` 供诊断。
#[derive(Debug, Clone)]
pub struct RevokedSnapshot {
    /// 静态 env 条目（SEEP_MESH_MTLS_REVOKED_NODES，CSV 解析后原样）
    pub static_entries: Vec<NodeId>,
    /// 文件载体（None = 未配置 SEEP_MESH_MTLS_REVOKED_NODES_FILE）
    pub file: Option<RevokedFileState>,
}

#[derive(Debug, Clone)]
pub struct RevokedFileState {
    pub path: String,
    /// 最近一次载入尝试是否成功（false = error 有值；entries 为最近成功态）
    pub loaded: bool,
    pub error: Option<String>,
    /// 最后成功载入版本的文件 mtime（epoch 秒；载入时刻指纹，非当前文件）
    pub mtime_secs: u64,
    pub entries: Vec<NodeId>,
}

fn mtime_epoch_secs(t: Option<SystemTime>) -> u64 {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl MeshTls {
    fn from_config(cfg: &MeshTlsConfig) -> Result<Self> {
        // rustls 在依赖图里同持 ring/aws-lc-rs 双特征（seep-protocols tls.rs
        // 同注）：`ClientConfig::builder()` 在多提供方歧义下直接 panic——
        // mesh 面构造处安装进程默认提供方（已装者生效，冲突忽略）。
        static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALL.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
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

    /// P2-7 M0 §2.1：撤销生效面快照（见 RevokedSnapshot 注释）。
    async fn revoked_snapshot(&self) -> RevokedSnapshot {
        let reload_err = self.maybe_reload().await.err().map(|e| format!("{:#}", e));
        let guard = self.inner.read().await;
        RevokedSnapshot {
            static_entries: self.cfg.revoked_node_ids.clone(),
            file: self
                .cfg
                .revoked_nodes_path
                .as_ref()
                .map(|p| RevokedFileState {
                    path: p.display().to_string(),
                    loaded: reload_err.is_none(),
                    error: reload_err.clone(),
                    mtime_secs: mtime_epoch_secs(guard.fingerprint.revoked_mtime),
                    entries: guard.revoked_node_ids.clone(),
                }),
        }
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
    let certs =
        rustls::pki_types::CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    rustls::pki_types::PrivateKeyDer::pem_file_iter(path)?
        .next()
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))?
        .map_err(|e| anyhow!("failed to parse private key {}: {e}", path.display()))
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
    use seep_core::udp::relay::UdpRelay;
    use seep_mesh::{MeshRegistry, NodeRecord, NodeRole};
    use std::pin::Pin;
    use std::task::{Context, Poll};

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

    // ── P1-4 §2.4/§4.2：MeshEnvelope 帧 pad/strip（§7.1 golden + §7.2 全链路）──

    fn pad_env_fixture() -> MeshEnvelope {
        MeshEnvelope::new(
            "flow-1".into(),
            "example.com".into(),
            443,
            vec!["relay1".into(), "exit1".into()],
        )
    }

    fn fixed_spec(target: usize) -> seep_core::PaddingSpec {
        seep_core::PaddingSpec {
            mode: seep_core::PaddingMode::Fixed,
            target,
            buckets: vec![],
            min: 0,
            max: 0,
            max_overhead_ratio: 0.5,
        }
    }

    /// §7.1 golden：fixed 模式填充帧总长精确命中 target（pad_len 字段自身
    /// 占字节，固定点迭代收敛）；尾部 K×0x00 与 pad_len 声明一致；decode
    /// 还原全部字段（envelope 即 payload，strip 后语义相等）；版本升 2。
    #[test]
    fn envelope_pad_strip_golden_fixed() {
        let env = pad_env_fixture();
        let base = encode_mesh_envelope_binary(&env).unwrap();
        assert_eq!(&base[0..2], b"SU", "P2-6 帧形：magic 开头");
        // ratio 放开隔离固定点逻辑（+120B 超 0.5 cap——cap 路径归 skip 测钉）
        let mut spec = fixed_spec(base.len() + 120);
        spec.max_overhead_ratio = 100.0;
        let pre = obfs_pad_snapshot();
        let payload = pad_envelope_frame(&env, &spec, &seep_core::FlowId::new())
            .unwrap()
            .expect("应产生填充帧");
        assert_eq!(payload.len(), base.len() + 120, "帧总长精确命中 target");
        let zeros = payload.iter().rev().take_while(|&&b| b == 0).count();
        assert_eq!(
            zeros, 120,
            "二进制头恒含 pad_len 字段——无字段开销抖动，zeros == 声明量"
        );
        // §5：{mode=fixed} 帧计数与新增字节计数联动（进程级 statics 与同
        // 二进制并行测试共享——本帧贡献恰 +1/+zeros，他测只增不减，故断下界）
        let post = obfs_pad_snapshot();
        assert!(post.frames_fixed > pre.frames_fixed, "fixed 帧计数递增");
        assert!(
            post.bytes_added >= pre.bytes_added + zeros as u64,
            "新增字节计数 ≥ 本帧填充量"
        );

        let decoded = decode_envelope_payload(&payload).unwrap();
        assert_eq!(decoded.pad_len as usize, zeros);
        assert_eq!(decoded.version, PAD_ENVELOPE_VERSION);
        assert_eq!(decoded.flow_id, env.flow_id);
        assert_eq!(decoded.target_host, env.target_host);
        assert_eq!(decoded.target_port, env.target_port);
        assert_eq!(decoded.path, env.path);
    }

    #[tokio::test]
    async fn envelope_unpadded_bytes_match_binary_golden_and_legacy_receive() {
        let env = pad_env_fixture();
        let bin = encode_mesh_envelope_binary(&env).unwrap();
        assert_eq!(env.version, MESH_ENVELOPE_VERSION);
        assert_eq!(bin[2], MESH_ENVELOPE_BIN_VERSION, "结构 ver=2");

        // wire 字节级：长度前缀 = 二进制帧字节数，帧体逐字节等于 golden
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_envelope(&mut client, &env).await.unwrap();
        let len = server.read_u32().await.unwrap() as usize;
        assert_eq!(len, bin.len());
        let mut buf = vec![0u8; len];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, bin, "wire 字节与二进制 golden 逐字节一致");

        // P2-6 §0-2：旧 JSON 帧仍可解码（接收侧嗅探分支）
        let legacy = serde_json::to_vec(&env).unwrap();
        let decoded_legacy = decode_envelope_payload(&legacy).unwrap();
        assert_eq!(decoded_legacy, env, "旧 JSON 帧接收兼容");

        // strip 路径往返（read_envelope 内走 decode_envelope_payload）
        let (mut c2, mut s2) = tokio::io::duplex(4096);
        write_envelope(&mut c2, &env).await.unwrap();
        let decoded = read_envelope(&mut s2).await.unwrap();
        assert_eq!(decoded, env);
        assert_eq!(decoded.pad_len, 0);
    }

    /// §6 E7：pad_len 声明与帧尾 0x00 数不符 / version=1 携带填充 → 丢帧。
    #[test]
    fn envelope_pad_e7_mismatch_rejected() {
        let env = pad_env_fixture();
        let mut env2 = env.clone();
        env2.version = PAD_ENVELOPE_VERSION;
        env2.pad_len = 99;
        let mut frame = serde_json::to_vec(&env2).unwrap();
        frame.resize(frame.len() + 3, 0); // 实际 3 字节 ≠ 声明 99
        let err = decode_envelope_payload(&frame).unwrap_err();
        assert!(err.to_string().contains("E7"), "{err}");

        let mut env3 = env.clone();
        env3.version = MESH_ENVELOPE_VERSION;
        env3.pad_len = 3;
        let mut frame3 = serde_json::to_vec(&env3).unwrap();
        frame3.resize(frame3.len() + 3, 0); // version=1 携带填充
        let err = decode_envelope_payload(&frame3).unwrap_err();
        assert!(err.to_string().contains("E7"), "{err}");

        // P2-6 §3 E5/E6 二进制帧形同门：声明 ≠ 实长 / version<2 携带填充
        let mut b2 = env.clone();
        b2.version = PAD_ENVELOPE_VERSION;
        b2.pad_len = 99;
        let frame_b = encode_mesh_envelope_binary(&b2).unwrap(); // 未附 99 字节 0x00
        let err = decode_envelope_payload(&frame_b).unwrap_err();
        assert!(err.to_string().contains("E7"), "{err}");

        let mut b3 = env.clone();
        b3.version = MESH_ENVELOPE_VERSION;
        b3.pad_len = 3;
        let mut frame_b3 = encode_mesh_envelope_binary(&b3).unwrap();
        frame_b3.resize(frame_b3.len() + 3, 0);
        let err = decode_envelope_payload(&frame_b3).unwrap_err();
        assert!(err.to_string().contains("E7"), "{err}");
    }

    /// §2.6/E10 + §6 E4：InPlace（恰为 target）→ None；overhead cap（策略层
    /// 放弃）与帧上限（执行层放弃）→ None 且对应计数递增。
    #[test]
    fn envelope_pad_skip_paths_and_counters() {
        let env = pad_env_fixture();
        let base = encode_mesh_envelope_binary(&env).unwrap();
        let id = seep_core::FlowId::new();

        // 恰为 target → InPlace → None
        let spec = fixed_spec(base.len());
        assert!(pad_envelope_frame(&env, &spec, &id).unwrap().is_none());

        // E10：r=0、min=0 → cap=len < target → 策略层放弃 + overhead 计数
        let mut spec = fixed_spec(base.len() + 10);
        spec.max_overhead_ratio = 0.0;
        let o0 = obfs_pad_snapshot().skipped_overhead_cap;
        assert!(pad_envelope_frame(&env, &spec, &id).unwrap().is_none());
        assert!(
            obfs_pad_snapshot().skipped_overhead_cap > o0,
            "overhead 计数递增"
        );

        // E4：target 超 MAX_HEADER_BYTES → 执行层放弃 + too_large 计数
        //（ratio 放开让策略层放行——cap 是比例上界，65636/96≈684 倍开销，
        // 100 仍不够；overhead cap 归策略层，帧上限归执行层，两层各自拦截）
        let mut spec = fixed_spec(MAX_HEADER_BYTES + 100);
        spec.max_overhead_ratio = 10000.0;
        let t0 = obfs_pad_snapshot().skipped_too_large;
        assert!(pad_envelope_frame(&env, &spec, &id).unwrap().is_none());
        assert!(
            obfs_pad_snapshot().skipped_too_large > t0,
            "too_large 计数递增"
        );
    }

    /// §7.2/§0 分布口径：range 模式多流帧长取值分散（未开启时帧长恒
    /// base.len() 单点——分布偏离默认的可测形）；各帧长均落 [min, max]，
    /// 且 {mode=range} 帧计数联动。
    #[test]
    fn envelope_pad_range_mode_distribution_shifts() {
        let env = pad_env_fixture();
        let spec = seep_core::PaddingSpec {
            mode: seep_core::PaddingMode::Range,
            target: 0,
            buckets: vec![],
            min: 300,
            max: 600,
            // ~100B 基底掷 [300,600] 需放开比例上限（cap 是相对 len 的比例）
            max_overhead_ratio: 10000.0,
        };
        let r0 = obfs_pad_snapshot().frames_range;
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..40 {
            let payload = pad_envelope_frame(&env, &spec, &seep_core::FlowId::new())
                .unwrap()
                .expect("range 掷点 ≥ min(300) > len 应产生填充帧");
            lengths.insert(payload.len());
        }
        assert!(lengths.len() >= 5, "40 流的帧长应分散（分布偏离单点默认）");
        for len in &lengths {
            assert!(
                (300..=600).contains(len),
                "帧长 {len} 应落 [min, max] = [300, 600]"
            );
        }
        assert_eq!(obfs_pad_snapshot().frames_range, r0 + 40, "range 帧计数");
    }

    /// §7.2 chain 填充全链路：client 经真实 `dial_and_tunnel` 打填充帧 →
    /// 对端读 wire：帧长 ∈ buckets（bucket 对齐 512）、尾部 0x00 ==
    /// pad_len、strip 还原字段；随后载荷回显，证明链路未被填充破坏。
    #[tokio::test]
    async fn padded_dial_wire_frame_hits_bucket_and_roundtrips() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(1);
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let len = s.read_u32().await.unwrap() as usize;
            let mut frame = vec![0u8; len];
            s.read_exact(&mut frame).await.unwrap();
            frame_tx.send((len, frame)).await.unwrap();
            // 充当 exit：回显后续载荷
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, peer_addr))
            .unwrap();
        let plane = MeshDataPlane::new("client1".into(), registry);

        let flow_id = seep_core::FlowId::new();
        let env = MeshEnvelope::new(
            flow_id.as_uuid().to_string(),
            "127.0.0.1".into(),
            peer_addr.port(),
            vec!["exit1".into()],
        );
        let spec = seep_core::PaddingSpec {
            mode: seep_core::PaddingMode::Bucket,
            target: 0,
            buckets: vec![512, 1024],
            min: 0,
            max: 0,
            // 放宽上限：帧长 ~120B 对齐 512 桶需 r ≥ ~3.3
            max_overhead_ratio: 100.0,
        };

        let (mut client_io, mut io_peer) = tokio::io::duplex(4096);
        let dial = {
            let plane = plane;
            tokio::spawn(async move {
                plane
                    .dial_and_tunnel(&"exit1".into(), &env, &mut client_io, Some(&spec), &flow_id)
                    .await
            })
        };

        let (wire_len, frame) = frame_rx.recv().await.unwrap();
        assert_eq!(wire_len, 512, "bucket 对齐：wire 帧长命中 512 桶");
        let decoded = decode_envelope_payload(&frame).unwrap();
        assert_eq!(decoded.version, PAD_ENVELOPE_VERSION);
        assert_eq!(
            decoded.pad_len as usize,
            frame.iter().rev().take_while(|&&b| b == 0).count(),
            "尾部填充与声明一致"
        );
        assert_eq!(decoded.target_host, "127.0.0.1");
        assert_eq!(decoded.path, vec!["exit1".to_string()]);

        io_peer.write_all(&[1, 2, 3, 4]).await.unwrap();
        let mut echo = [0u8; 4];
        io_peer.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, [1, 2, 3, 4], "填充帧后链路载荷回显不受影响");
        dial.abort();
    }

    /// §7.2 关闭对照：无 spec（enabled=false / 未选中 / E9）→ wire 帧长与
    /// 旧序列化形完全一致（零字节差异，§2.5）。
    #[tokio::test]
    async fn unpadded_dial_wire_frame_byte_identical_baseline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(1);
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let len = s.read_u32().await.unwrap() as usize;
            let mut frame = vec![0u8; len];
            s.read_exact(&mut frame).await.unwrap();
            frame_tx.send((len, frame)).await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, peer_addr))
            .unwrap();
        let plane = MeshDataPlane::new("client1".into(), registry);

        let flow_id = seep_core::FlowId::new();
        let env = MeshEnvelope::new(
            flow_id.as_uuid().to_string(),
            "127.0.0.1".into(),
            peer_addr.port(),
            vec!["exit1".into()],
        );
        let bin = encode_mesh_envelope_binary(&env).unwrap();

        let (mut client_io, mut io_peer) = tokio::io::duplex(4096);
        let dial = tokio::spawn(async move {
            plane
                .dial_and_tunnel(&"exit1".into(), &env, &mut client_io, None, &flow_id)
                .await
        });

        let (wire_len, frame) = frame_rx.recv().await.unwrap();
        assert_eq!(wire_len, bin.len());
        assert_eq!(frame, bin, "wire 帧 = P2-6 二进制 golden");

        io_peer.write_all(&[5, 6, 7, 8]).await.unwrap();
        let mut echo = [0u8; 4];
        io_peer.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, [5, 6, 7, 8]);
        dial.abort();
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

    /// P2-6 §6-1：二进制 golden——encode→decode 全字段往返 + 逐字节形状钉。
    #[test]
    fn mesh_envelope_binary_roundtrip_golden() {
        let env = MeshEnvelope::new(
            "flow-binary-1".into(),
            "target.example.com".into(),
            8443,
            vec!["relay-1".into(), "exit-1".into()],
        );

        let bin = encode_mesh_envelope_binary(&env).unwrap();
        // 逐字节形状钉：magic/ver/flags/version/flow_id/host/port/hop_count/path/pad_len
        assert_eq!(&bin[0..2], b"SU", "magic");
        assert_eq!(bin[2], MESH_ENVELOPE_BIN_VERSION, "ver=2");
        assert_eq!(bin[3], 0u8, "flags 保留位=0");
        assert_eq!(
            u32::from_be_bytes(bin[4..8].try_into().unwrap()),
            1,
            "env.version"
        );
        // flow_id len + bytes
        assert_eq!(bin[8], b"flow-binary-1".len() as u8);
        assert_eq!(&bin[9..9 + b"flow-binary-1".len()], b"flow-binary-1");
        // host len + bytes
        let host_start = 9 + b"flow-binary-1".len();
        assert_eq!(bin[host_start], b"target.example.com".len() as u8);
        assert_eq!(
            &bin[host_start + 1..host_start + 1 + b"target.example.com".len()],
            b"target.example.com"
        );
        // port
        let port_start = host_start + 1 + b"target.example.com".len();
        assert_eq!(
            u16::from_be_bytes(bin[port_start..port_start + 2].try_into().unwrap()),
            8443
        );
        // hop_count
        let hop_start = port_start + 2;
        assert_eq!(bin[hop_start], 2u8, "path 两跳");
        // path[0]
        let id0_start = hop_start + 1;
        assert_eq!(bin[id0_start], b"relay-1".len() as u8);
        assert_eq!(
            &bin[id0_start + 1..id0_start + 1 + b"relay-1".len()],
            b"relay-1"
        );
        // path[1]
        let id1_start = id0_start + 1 + b"relay-1".len();
        assert_eq!(bin[id1_start], b"exit-1".len() as u8);
        assert_eq!(
            &bin[id1_start + 1..id1_start + 1 + b"exit-1".len()],
            b"exit-1"
        );
        // pad_len
        let pad_start = id1_start + 1 + b"exit-1".len();
        assert_eq!(
            u32::from_be_bytes(bin[pad_start..pad_start + 4].try_into().unwrap()),
            0
        );

        // decode 全字段往返
        let back = decode_mesh_envelope_binary(&bin).unwrap();
        assert_eq!(back.flow_id, env.flow_id);
        assert_eq!(back.target_host, env.target_host);
        assert_eq!(back.target_port, env.target_port);
        assert_eq!(back.path, env.path);
        assert_eq!(back.version, env.version);
        assert_eq!(back.pad_len, env.pad_len);
    }

    /// P2-6 §6-2：旧 JSON 接收——serde_json 旧字节进 decode_envelope_payload 字段还原。
    #[test]
    fn mesh_envelope_legacy_json_receive() {
        let env = MeshEnvelope {
            version: 1,
            flow_id: "legacy-flow".into(),
            target_host: "legacy.example.com".into(),
            target_port: 443,
            path: vec!["r1".into(), "e1".into()],
            pad_len: 0,
        };
        let json = serde_json::to_vec(&env).unwrap();
        assert_eq!(json[0], b'{');

        let decoded = decode_envelope_payload(&json).unwrap();
        assert_eq!(decoded.flow_id, env.flow_id);
        assert_eq!(decoded.target_host, env.target_host);
        assert_eq!(decoded.target_port, env.target_port);
        assert_eq!(decoded.path, env.path);
        assert_eq!(decoded.version, env.version);
        assert_eq!(decoded.pad_len, env.pad_len);

        // 带填充的旧 JSON（version=2 + pad_len>0 + 尾部 0x00）
        let env_padded = MeshEnvelope {
            version: 2,
            flow_id: "legacy-padded".into(),
            target_host: "padded.example.com".into(),
            target_port: 443,
            path: vec!["r1".into()],
            pad_len: 4,
        };
        let json_padded = serde_json::to_vec(&env_padded).unwrap();
        let mut with_zeros = json_padded.clone();
        with_zeros.extend_from_slice(&[0u8; 4]);
        let decoded = decode_envelope_payload(&with_zeros).unwrap();
        assert_eq!(decoded.flow_id, env_padded.flow_id);
        assert_eq!(decoded.pad_len, 4);
    }

    /// P2-6 §6-4：E5/E6 拒帧（构造旧 JSON 与新二进制两形）。
    #[test]
    fn mesh_envelope_reject_bad_frames() {
        // E1: magic 不符（二进制路径）
        let mut bad_magic = b"XX".to_vec();
        bad_magic.extend_from_slice(&[2u8, 0u8, 0, 0, 0, 1]); // 补最小头
        assert!(decode_mesh_envelope_binary(&bad_magic).is_err());

        // E2: ver != 2 且首字节非 {
        let mut bad_ver = b"SU".to_vec();
        bad_ver.push(1u8); // ver=1
        bad_ver.extend_from_slice(&[0u8, 0, 0, 0, 1]); // 补最小头
        assert!(decode_mesh_envelope_binary(&bad_ver).is_err());

        // E3: flags 保留位非 0
        let mut bad_flags = b"SU".to_vec();
        bad_flags.extend_from_slice(&[2u8, 1u8, 0, 0, 0, 1]); // flags=1
        assert!(decode_mesh_envelope_binary(&bad_flags).is_err());

        // E4: 截断（固定头不足）
        let truncated = b"SU".to_vec();
        assert!(decode_mesh_envelope_binary(&truncated).is_err());

        // E5: pad_len 与帧尾 0x00 数不一致
        let mut env = MeshEnvelope::new("f".into(), "h".into(), 443, vec!["n".into()]);
        env.pad_len = 4;
        let mut bin = encode_mesh_envelope_binary(&env).unwrap();
        bin.extend_from_slice(&[0u8; 2]); // 只有 2 个零，pad_len=4
        assert!(decode_mesh_envelope_binary(&bin).is_err());

        // E6: version < 2 但携带填充
        let mut env2 = MeshEnvelope::new("f".into(), "h".into(), 443, vec!["n".into()]);
        env2.version = 1;
        env2.pad_len = 4;
        let mut bin2 = encode_mesh_envelope_binary(&env2).unwrap();
        bin2.extend_from_slice(&[0u8; 4]);
        assert!(decode_mesh_envelope_binary(&bin2).is_err());
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
            seq: 0,
            seq_present: false,
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

    // ── P2-7 M1 §3.2/§4.1：v2 序号帧编解码 + 滑窗判定 ──

    /// v2 往返 + 字节级 golden（Cached/v4/Up 布局：pm=27, hop=28, seq=29..33）；
    /// v1 字节不变回归（seq_present=false → 老路径逐字节一致）。
    #[test]
    fn udp_envelope_v2_seq_golden_and_v1_regression() {
        let mut env = udp_env_sample("10.0.0.1", UdpPathMode::Cached, UdpDir::Up);
        env.version = UDP_ENVELOPE_VERSION_V2;
        env.seq = 0xDEAD_BEEF;
        env.seq_present = true;

        let wire = encode_udp_envelope(&env).unwrap();
        assert_eq!(&wire[0..2], b"SU", "magic 不变");
        assert_eq!(wire[2], UDP_ENVELOPE_VERSION_V2, "version=2");
        assert_eq!(
            wire[3] & UDP_FLAG_HAS_SEQ,
            UDP_FLAG_HAS_SEQ,
            "HAS_SEQ 位置位"
        );
        assert_eq!(wire[3] & 1, 0, "dir=Up 的 bit0 保持 0");
        assert_eq!(wire[28], 3, "hop_index 原样");
        assert_eq!(
            &wire[29..33],
            &0xDEAD_BEEFu32.to_be_bytes(),
            "seq 大端黄金位"
        );
        assert_eq!(wire[33..], env.payload[..], "payload 原样");
        let back = decode_udp_envelope(&wire).unwrap();
        assert_eq!(back.seq, 0xDEAD_BEEF);
        assert!(back.seq_present);
        assert_eq!(back.version, UDP_ENVELOPE_VERSION_V2);

        // v1 回归：不带 HAS_SEQ、长度短 4、解码 seq_present=false/seq=0
        let v1 = udp_env_sample("10.0.0.1", UdpPathMode::Cached, UdpDir::Up);
        let wire_v1 = encode_udp_envelope(&v1).unwrap();
        assert_eq!(wire_v1[2], UDP_ENVELOPE_VERSION);
        assert_eq!(wire_v1[3] & UDP_FLAG_HAS_SEQ, 0, "v1 不带 HAS_SEQ");
        assert_eq!(wire_v1.len(), wire.len() - 4, "v2 比 v1 多 4 字节 seq");
        let back1 = decode_udp_envelope(&wire_v1).unwrap();
        assert!(!back1.seq_present);
        assert_eq!(back1.seq, 0);
    }

    /// §3.7 E2/E3/E5 矩阵：v2 保留位非 0 → 拒；v2 缺 HAS_SEQ → 拒；seq 截断 → 拒；
    /// v1 旧保留位矩阵回归（既有拒绝保持）。
    #[test]
    fn udp_envelope_v2_flags_matrix() {
        let mut env = udp_env_sample("10.0.0.1", UdpPathMode::Cached, UdpDir::Up);
        env.version = UDP_ENVELOPE_VERSION_V2;
        env.seq_present = true;
        env.seq = 1;
        env.payload = vec![];
        let wire = encode_udp_envelope(&env).unwrap();

        // E2：v2 保留位（bit2+）非 0
        let mut bad = wire.clone();
        bad[3] |= 0x04;
        assert!(decode_udp_envelope(&bad).is_err(), "v2 保留位应拒绝");

        // v1 保留位旧矩阵回归
        let v1 = encode_udp_envelope(&udp_env_sample("10.0.0.1", UdpPathMode::Cached, UdpDir::Up))
            .unwrap();
        let mut badv1 = v1;
        badv1[3] |= 0x04;
        assert!(decode_udp_envelope(&badv1).is_err(), "v1 保留位应拒绝");

        // E5-变体：v2 缺 HAS_SEQ（dir=Up 且无 bit1）
        let mut no_seq = wire.clone();
        no_seq[3] &= !UDP_FLAG_HAS_SEQ;
        assert!(
            decode_udp_envelope(&no_seq).is_err(),
            "v2 必须带 HAS_SEQ（恒带 seq 语义）"
        );

        // E3：seq 截断（payload 空 → 尾部即 seq 区，切 2 字节）
        let cut = &wire[..wire.len() - 2];
        assert!(decode_udp_envelope(cut).is_err(), "seq 截断应拒绝");
    }

    /// §3.4 §4.1 表驱动：首包任意起点 / 升序 / 乱序 / 重放 / 回退窗口位 / 超窗
    /// （前向与过旧两向）/ 移位语义 / u32 wrap（wrapping 差判先后）。
    #[test]
    fn replay_window_matrix() {
        let cases: &[(&[u32], &[bool], &str)] = &[
            (&[100], &[true], "首包任意起点接受"),
            (&[5, 6, 7], &[true, true, true], "升序"),
            (&[10, 12, 11], &[true, true, true], "乱序窗口内"),
            (&[10, 12, 11, 12], &[true, true, true, false], "重放拒"),
            (&[50, 50], &[true, false], "last 恒拒"),
            (&[5, 6, 5], &[true, true, false], "回退 1 已收拒"),
            (&[5, 6, 4], &[true, true, true], "回退 2 未收接受"),
            (&[50, 60, 59], &[true, true, true], "回退 1 未收接受"),
            (&[50, 100, 35], &[true, true, false], "回退 65 超窗拒"),
            (&[50, 100, 110], &[true, true, true], "前进 10 接受滑窗"),
            (&[10, 100], &[true, true], "前进超窗（diff=90）接受滑窗"),
            (
                &[10, 100, 101, 102],
                &[true, true, true, true],
                "前进超窗后连续前进不卡死（旧实现窗口停滞缺陷回归）",
            ),
            (
                &[10, 100, 20],
                &[true, true, false],
                "超窗滑到 100 后回退 80 仍拒（过旧）",
            ),
            (
                &[10, 12, 12, 11],
                &[true, true, false, true],
                "拒帧不前进窗口，后续窗口内可续",
            ),
            (
                &[10, 9, 70, 9],
                &[true, true, true, false],
                "跳窗移位：9 的历史随 bits 右移后仍命中",
            ),
            (
                &[10, 9, 70, 8],
                &[true, true, true, true],
                "跳窗后更旧未收可接受",
            ),
            (&[u32::MAX, 0], &[true, true], "u32 wrap：wrapping diff=1"),
            (
                &[u32::MAX, 4294967295 - 1],
                &[true, true],
                "wrap 前回退窗口内未收接受",
            ),
        ];
        for (seqs, expected, name) in cases {
            let mut w = ReplayWindow::new();
            let got: Vec<bool> = seqs.iter().map(|s| w.check_and_advance(*s)).collect();
            assert_eq!(&got[..], *expected, "{name}");
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
        let d = encode_udp_envelope(&udp_env_sample(
            "example.com",
            UdpPathMode::Cached,
            UdpDir::Up,
        ))
        .unwrap();
        assert_eq!(d[20], 3);
        assert_eq!(d[21], b"example.com".len() as u8);
    }

    /// T1 拒绝类 1-3：坏 magic / ver / 保留位。
    #[test]
    fn udp_envelope_rejects_bad_magic_version_reserved() {
        let wire = encode_udp_envelope(&udp_env_sample(
            "example.com",
            UdpPathMode::Full,
            UdpDir::Down,
        ))
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

    // ── P0-4 §3 UdpFlowCache 跳缓存（S2 / §10 T4/T5/T8）──

    fn udp_flow_id(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn udp_cache_entry(prev_port: u16) -> FlowCacheEntry {
        FlowCacheEntry {
            next_hop: Some(("next-hop".into(), "127.0.0.1:9000".parse().unwrap())),
            prev: format!("127.0.0.1:{prev_port}").parse().unwrap(),
            expiry: Instant::now() + Duration::from_secs(60),
        }
    }

    #[test]
    fn udp_flow_cache_insert_touch_and_reassociate() {
        let cache = UdpFlowCache::new(Duration::from_secs(60), 64);
        cache.insert(udp_flow_id(1), udp_cache_entry(1111));
        assert_eq!(cache.len(), 1);
        let hit = cache.touch(&udp_flow_id(1)).expect("应命中");
        assert_eq!(hit.prev.port(), 1111);
        // FULL 重关联：同 flow_id 再 insert 刷新 prev（§3）
        cache.insert(udp_flow_id(1), udp_cache_entry(2222));
        let hit = cache.touch(&udp_flow_id(1)).expect("重关联后应命中");
        assert_eq!(hit.prev.port(), 2222, "重关联应刷新 prev");
        assert_eq!(cache.len(), 1, "重关联不新增条目");
        assert_eq!(cache.unknown_flow_count(), 0);
    }

    /// T4：过期条目判 miss + unknown_flow 计数（惰性过期，就地改写 expiry）。
    #[test]
    fn udp_flow_cache_expired_touch_is_unknown() {
        let cache = UdpFlowCache::new(Duration::from_secs(10), 64);
        cache.insert(udp_flow_id(7), udp_cache_entry(1111));
        // 就地改写 expiry 至过去（设计 §3：不引入时钟抽象，测试直接改私有字段）
        if let Some(mut e) = cache.map.get_mut(&udp_flow_id(7)) {
            e.expiry = Instant::now() - Duration::from_secs(1);
        }
        assert!(cache.touch(&udp_flow_id(7)).is_none(), "过期应判 miss");
        assert_eq!(cache.unknown_flow_count(), 1);
        assert_eq!(cache.len(), 0, "过期条目应被惰性清除");
    }

    /// T5：max=2 插 3 → 最早 expiry 被逐 + 驱逐计数（R10/§11-6）。
    #[test]
    fn udp_flow_cache_capacity_evicts_earliest_expiry() {
        let cache = UdpFlowCache::new(Duration::from_secs(60), 2);
        cache.insert(udp_flow_id(1), udp_cache_entry(1111));
        cache.insert(udp_flow_id(2), udp_cache_entry(2222));
        // 控制驱逐顺序：flow 1 的 expiry 最早（最久未触）
        if let Some(mut e) = cache.map.get_mut(&udp_flow_id(1)) {
            e.expiry = Instant::now() + Duration::from_secs(1);
        }
        if let Some(mut e) = cache.map.get_mut(&udp_flow_id(2)) {
            e.expiry = Instant::now() + Duration::from_secs(3600);
        }
        cache.insert(udp_flow_id(3), udp_cache_entry(3333));
        assert_eq!(cache.len(), 2, "容量守恒");
        assert_eq!(cache.evicted_count(), 1, "最早 expiry 被逐");
        assert!(cache.touch(&udp_flow_id(1)).is_none(), "被逐条目判 miss");
        assert!(cache.touch(&udp_flow_id(2)).is_some());
        assert!(cache.touch(&udp_flow_id(3)).is_some());
    }

    /// 满时插入优先扫过期腾位（不产生驱逐计数）。
    #[test]
    fn udp_flow_cache_full_insert_sweeps_expired_first() {
        let cache = UdpFlowCache::new(Duration::from_secs(60), 2);
        cache.insert(udp_flow_id(1), udp_cache_entry(1111));
        cache.insert(udp_flow_id(2), udp_cache_entry(2222));
        for id in [1u8, 2u8] {
            if let Some(mut e) = cache.map.get_mut(&udp_flow_id(id)) {
                e.expiry = Instant::now() - Duration::from_secs(1);
            }
        }
        cache.insert(udp_flow_id(3), udp_cache_entry(3333));
        assert_eq!(cache.len(), 1, "过期两条已被扫除，仅剩新插入");
        assert_eq!(cache.evicted_count(), 0, "过期清扫不计驱逐（§13-2）");
    }

    /// T8：过期清扫后 len == 0；未过期不清。
    #[test]
    fn udp_flow_cache_sweep_expired_empties() {
        let cache = UdpFlowCache::new(Duration::from_secs(60), 64);
        for id in 1u8..=3 {
            cache.insert(udp_flow_id(id), udp_cache_entry(1000 + id as u16));
        }
        for id in 1u8..=3 {
            if let Some(mut e) = cache.map.get_mut(&udp_flow_id(id)) {
                e.expiry = Instant::now() - Duration::from_secs(1);
            }
        }
        let now = Instant::now();
        cache.sweep_expired(now);
        assert_eq!(cache.len(), 0, "全部过期应清空（T8）");
        // 未到期不受影响
        cache.insert(udp_flow_id(9), udp_cache_entry(1999));
        cache.sweep_expired(now);
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
    }

    /// retire_flow 单点的 remove 语义（§13-1）。
    #[test]
    fn udp_flow_cache_remove() {
        let cache = UdpFlowCache::new(Duration::from_secs(60), 64);
        cache.insert(udp_flow_id(5), udp_cache_entry(1551));
        assert!(cache.remove(&udp_flow_id(5)).is_some());
        assert!(cache.remove(&udp_flow_id(5)).is_none(), "重复 remove 无害");
        assert_eq!(cache.len(), 0);
    }

    // ── P0-4 §4/§6 UDP 面（S3 / §10 T3/T4/T6 + exit 单跳真 socket 往返）──

    /// §10 T6：tls=None 且 !allow_plaintext → Err 且信息含开关名；显式允许则通过。
    #[test]
    fn udp_gate_requires_tls_or_plaintext_flag() {
        let registry = Arc::new(MeshRegistry::new());
        let plane = MeshDataPlane::new("gate-node".into(), registry);
        let err = plane
            .with_udp(MeshUdpGate::new(false))
            .err()
            .expect("tls=None 且 !allow_plaintext 应拒绝");
        assert!(
            format!("{err:#}").contains("SEEP_MESH_UDP_ALLOW_PLAINTEXT"),
            "错误信息应含开关名: {err:#}"
        );

        let registry = Arc::new(MeshRegistry::new());
        let plane = MeshDataPlane::new("gate-node".into(), registry)
            .with_udp(MeshUdpGate::new(true))
            .expect("显式允许明文应通过");
        assert!(plane.udp.is_some());
    }

    /// relay 测试脚手架：注册 relay1(Relay) + exit1(Exit→next_addr)，返回挂了明文
    /// UDP 面的 relay plane（直接 handle 的测试共用）。
    fn udp_relay_plane(next_addr: SocketAddr) -> MeshDataPlane {
        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        registry
            .register_node(NodeRecord::new("exit1".into(), NodeRole::Exit, next_addr))
            .unwrap();
        MeshDataPlane::new("relay1".into(), registry)
            .with_udp(MeshUdpGate::new(true))
            .unwrap()
    }

    /// §10 T3：relay 直调 handle_udp_datagram——第 1 包 FULL 剥自身重编码
    /// （path=[exit1]），第 2 包 CACHED 原样转发且 path 恒空。
    #[tokio::test]
    async fn udp_relay_strips_full_then_forwards_cached() {
        let next_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let next_addr = next_sock.local_addr().unwrap();
        let plane = udp_relay_plane(next_addr);
        let face_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();

        let flow = [0x33u8; 16];
        let full = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: flow,
            target_host: "127.0.0.1".into(),
            target_port: 4433,
            path_mode: UdpPathMode::Full,
            hop_index: 0, // §14-1：发送端置 0
            seq: 0,
            seq_present: false,
            path: vec!["relay1".into(), "exit1".into()],
            payload: vec![1, 2, 3],
        };
        plane
            .handle_udp_datagram(&face_sock, from, &encode_udp_envelope(&full).unwrap())
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), next_sock.recv_from(&mut buf))
            .await
            .expect("FULL 应被转发到下一跳")
            .unwrap();
        let fwd = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(fwd.path, vec!["exit1".to_string()], "FULL 应剥自身");
        assert_eq!(fwd.path_mode, UdpPathMode::Full, "每跳不降级 CACHED（D-4）");
        assert_eq!(fwd.hop_index, 1, "每经一个 relay hop_index +1（§14-1）");
        assert_eq!(fwd.payload, vec![1, 2, 3]);

        let cached = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: flow,
            target_host: "127.0.0.1".into(),
            target_port: 4433,
            path_mode: UdpPathMode::Cached,
            hop_index: 0,
            seq: 0,
            seq_present: false,
            path: vec![],
            payload: vec![4, 5],
        };
        plane
            .handle_udp_datagram(&face_sock, from, &encode_udp_envelope(&cached).unwrap())
            .await
            .unwrap();

        let (n, _) = tokio::time::timeout(Duration::from_secs(2), next_sock.recv_from(&mut buf))
            .await
            .expect("CACHED 应按缓存转发")
            .unwrap();
        let fwd2 = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(fwd2.path_mode, UdpPathMode::Cached);
        assert!(fwd2.path.is_empty(), "第 2 个包起不携带路径字段（T3）");
        assert_eq!(fwd2.dir, UdpDir::Up);
        assert_eq!(fwd2.hop_index, 1);
        assert_eq!(fwd2.payload, vec![4, 5]);

        let face = plane.udp.as_ref().unwrap();
        let entry = face.peek_entry(&flow).expect("relay 应有跳缓存条目");
        assert_eq!(entry.next_hop.as_ref().unwrap().0, "exit1");
        assert_eq!(entry.prev, from, "prev = 上行来源（§11-2）");
        assert_eq!(face.metrics.forwarded_up.load(Ordering::Relaxed), 2);
        assert_eq!(face.cache.unknown_flow_count(), 0);
    }

    /// §10 T4：缓存条目过期后 CACHED → unknown_flow 丢弃 + 计数；未知 flow 同路径。
    #[tokio::test]
    async fn udp_cached_unknown_flow_drops_and_counts() {
        let next_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let next_addr = next_sock.local_addr().unwrap();
        let plane = udp_relay_plane(next_addr);
        let face_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();

        // 先 FULL 建条目（同时被转发——后续只应有这一包）
        let flow = [0x44u8; 16];
        let full = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: flow,
            target_host: "127.0.0.1".into(),
            target_port: 4433,
            path_mode: UdpPathMode::Full,
            hop_index: 0,
            seq: 0,
            seq_present: false,
            path: vec!["relay1".into(), "exit1".into()],
            payload: vec![1],
        };
        plane
            .handle_udp_datagram(&face_sock, from, &encode_udp_envelope(&full).unwrap())
            .await
            .unwrap();

        // 就地改写 expiry 至过去（S2 同款：测试可达私有字段，不引入时钟抽象）
        {
            let face = plane.udp.as_ref().unwrap();
            if let Some(mut e) = face.cache.map.get_mut(&flow) {
                e.expiry = Instant::now() - Duration::from_secs(1);
            }
        }

        // 过期条目上的 CACHED → 惰性 miss：丢弃 + unknown_flow=1 + 条目清除
        let expired = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: flow,
            target_host: "127.0.0.1".into(),
            target_port: 4433,
            path_mode: UdpPathMode::Cached,
            hop_index: 0,
            seq: 0,
            seq_present: false,
            path: vec![],
            payload: vec![2],
        };
        plane
            .handle_udp_datagram(&face_sock, from, &encode_udp_envelope(&expired).unwrap())
            .await
            .expect("unknown_flow 是丢弃不是错误");

        // 全新 flow 的 CACHED → 同路径 miss
        let unknown = UdpEnvelope {
            flow_id: [0x55u8; 16],
            ..expired
        };
        plane
            .handle_udp_datagram(&face_sock, from, &encode_udp_envelope(&unknown).unwrap())
            .await
            .expect("unknown_flow 是丢弃不是错误");

        let face = plane.udp.as_ref().unwrap();
        assert_eq!(face.cache.unknown_flow_count(), 2, "过期 miss + 未知 miss");
        assert!(!face.contains(&flow), "过期条目应被惰性清除");
        assert_eq!(
            face.metrics.forwarded_up.load(Ordering::Relaxed),
            1,
            "仅 FULL 被转发"
        );
        assert_eq!(face.metrics.malformed.load(Ordering::Relaxed), 0);

        // 下一跳只收到首包 FULL
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), next_sock.recv_from(&mut buf))
            .await
            .expect("首包 FULL 已转发")
            .unwrap();
        assert_eq!(
            decode_udp_envelope(&buf[..n]).unwrap().path_mode,
            UdpPathMode::Full
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), next_sock.recv_from(&mut buf))
                .await
                .is_err(),
            "unknown_flow 两包均被丢弃，不应有第二包到达下一跳"
        );
    }

    /// 单跳（client→exit）真 socket 往返：spawn_udp 收 FULL → exit 建 per-flow socket
    /// 发 echo → 下行 task 封 dir=Down/CACHED/hop_index=0 → 面 socket 回送 prev；
    /// 第 2 包 CACHED 复用既有 flow socket。
    #[tokio::test]
    async fn udp_exit_single_hop_roundtrip() {
        // 环回 echo server
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
            }
        });

        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        let plane = Arc::new(
            MeshDataPlane::new("exit1".into(), registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        // 探一个空闲端口（spawn_udp 内部 bind；同机竞争窗口可忽略）
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let face_addr = probe.local_addr().unwrap();
        drop(probe);
        let serve = plane.spawn_udp(face_addr);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let flow = [0x66u8; 16];

        let full = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: flow,
            target_host: "127.0.0.1".into(),
            target_port: echo_addr.port(),
            path_mode: UdpPathMode::Full,
            hop_index: 0,
            seq: 0,
            seq_present: false,
            path: vec!["exit1".into()],
            payload: vec![7, 7, 7],
        };
        client
            .send_to(&encode_udp_envelope(&full).unwrap(), face_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("exit 下行回包超时")
            .unwrap();
        let down = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(down.dir, UdpDir::Down, "下行 dir（§11-1）");
        assert_eq!(down.path_mode, UdpPathMode::Cached);
        assert!(down.path.is_empty());
        assert_eq!(down.flow_id, flow);
        assert_eq!(down.payload, vec![7, 7, 7], "echo 载荷原样回送");
        assert_eq!(down.hop_index, 0, "exit 下行 task 置 0（§14-1）");
        assert_eq!(down.target_port, echo_addr.port());

        // 第 2 包 CACHED：命中缓存 → 复用 per-flow socket
        let cached = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: flow,
            target_host: "127.0.0.1".into(),
            target_port: echo_addr.port(),
            path_mode: UdpPathMode::Cached,
            hop_index: 0,
            seq: 0,
            seq_present: false,
            path: vec![],
            payload: vec![8, 8],
        };
        client
            .send_to(&encode_udp_envelope(&cached).unwrap(), face_addr)
            .await
            .unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("CACHED 第二包下行超时")
            .unwrap();
        let down2 = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(down2.payload, vec![8, 8]);

        let face = plane.udp.as_ref().unwrap();
        let entry = face.peek_entry(&flow).expect("exit 应有缓存条目");
        assert!(entry.next_hop.is_none(), "next_hop=None 即本机为出口（§3）");
        assert_eq!(entry.prev, from, "prev = 客户端来源地址");
        assert_eq!(face.flows.len(), 1, "单 flow 一把 per-flow socket");
        assert_eq!(face.metrics.forwarded_down.load(Ordering::Relaxed), 2);

        serve.abort();
    }

    // ── P0-4 §10 T2（S6 收口）：两跳真 socket 往返 ──
    // 落本模块而非 udp_chain.rs：需直读面内部状态（flows/cache/metrics）。

    /// §0.1-② 第二路径：exit 侧回收语义（§13-1 触发点② 下行 task recv Err 走
    /// `forget_flow`、触发点③ FULL 重关联/孤儿清扫走 `retire_flow`）——两路均拆
    /// flows+cache 两表并同步 gauge（ICMP 诱发的真 recv Err 依赖环境，单测钉住
    /// 回收单点的表语义）。
    #[tokio::test]
    async fn exit_flow_retire_and_forget_cleanup() {
        let face = UdpFace::with_limits(Duration::from_secs(60), 64);
        let flow = [0x77u8; 16];
        let prev: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let task = tokio::spawn(async {});
        face.flows.insert(
            flow,
            ExitFlow {
                sock,
                task,
                target: ("127.0.0.1".into(), 53),
            },
        );
        face.associate(flow, None, prev);
        assert_eq!(face.flows.len(), 1);
        assert!(face.contains(&flow));
        assert_eq!(face.metrics.flows_active.load(Ordering::Relaxed), 1);

        // 触发点②路径：task 自清理（不 abort 自己）
        face.forget_flow(&flow);
        assert_eq!(face.flows.len(), 0, "forget_flow 拆 flows");
        assert!(!face.contains(&flow), "forget_flow 拆 cache");
        assert_eq!(face.metrics.flows_active.load(Ordering::Relaxed), 0);

        // 触发点③路径：外部回收（abort task → 两表 → gauge）
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let task = tokio::spawn(std::future::pending::<()>());
        face.flows.insert(
            flow,
            ExitFlow {
                sock,
                task,
                target: ("127.0.0.1".into(), 53),
            },
        );
        face.associate(flow, None, prev);
        face.retire_flow(&flow);
        assert_eq!(face.flows.len(), 0, "retire_flow 拆 flows");
        assert!(!face.contains(&flow), "retire_flow 拆 cache");
        assert_eq!(face.metrics.flows_active.load(Ordering::Relaxed), 0);
    }

    /// 并发 forget_flow 拆除后本包被静默丢弃（P1 修复）：flow miss 时
    /// `forwarded_up` 不得无条件 +1——转发成功计数只应计入真实转发的包。
    #[tokio::test]
    async fn send_existing_flow_miss_does_not_count_forwarded_up() {
        let face = UdpFace::with_limits(Duration::from_secs(60), 64);
        let flow = [0x9au8; 16];
        let before = face.metrics.forwarded_up.load(Ordering::Relaxed);
        let sent = face.send_existing_flow(&flow, &[1, 2, 3]).await.unwrap();
        assert!(!sent, "flow miss 应返回 false（静默丢弃）");
        assert_eq!(
            face.metrics.forwarded_up.load(Ordering::Relaxed),
            before,
            "flow miss 不得计入 forwarded_up"
        );
    }

    /// T2：client `MeshUdpRelay` → relay plane → exit plane → 环回 echo。上行 FULL
    /// 剥自身逐跳推进，exit 建 per-flow socket 发 echo；下行 dir=Down/CACHED 经
    /// relay 面 prev 链路回送——客户端 recv_from 只认 dir=Down，收到回包即
    /// "dir=down 全链路"成立。第 2 包走 CACHED 全链路并复用 exit 既有 flow socket。
    #[tokio::test]
    async fn t2_two_hop_real_socket_roundtrip() {
        use crate::udp_chain::MeshUdpBridge;
        use seep_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, RouteHop, TargetProto};

        // —— 环回 echo server ——
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
            }
        });

        // 探空闲端口（spawn_udp 内部 bind；同机竞争窗口可忽略——S3 同法）
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_udp_addr = probe.local_addr().unwrap();
        drop(probe);
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exit_udp_addr = probe.local_addr().unwrap();
        drop(probe);

        // —— exit plane（path 终点：exit 分支 + 下行 task）——
        let exit_registry = Arc::new(MeshRegistry::new());
        exit_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        let exit_plane = Arc::new(
            MeshDataPlane::new("exit1".into(), exit_registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        let exit_serve = exit_plane.spawn_udp(exit_udp_addr);

        // —— relay plane（FULL 剥自身 / CACHED 查缓存 / Down 回 prev）——
        let relay_registry = Arc::new(MeshRegistry::new());
        relay_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        relay_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                exit_udp_addr,
            ))
            .unwrap();
        let relay_plane = Arc::new(
            MeshDataPlane::new("relay1".into(), relay_registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        let relay_serve = relay_plane.spawn_udp(relay_udp_addr);

        // —— 客户端出站：MeshUdpBridge → MeshUdpRelay（hops = client1→relay1→exit1）——
        let client_registry = Arc::new(MeshRegistry::new());
        client_registry
            .register_node(NodeRecord::new(
                "client1".into(),
                NodeRole::Client,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        client_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                relay_udp_addr,
            ))
            .unwrap();
        let bridge = MeshUdpBridge::new(
            "client1".into(),
            client_registry,
            None,
            &MeshUdpGate::new(true),
        )
        .unwrap();
        let target = FlowTarget {
            host: "127.0.0.1".into(),
            port: echo_addr.port(),
            proto: TargetProto::Udp,
        };
        let ctx = FlowContext {
            id: FlowId::new(),
            target: target.clone(),
            metadata: FlowMetadata::default(),
        };
        let hops = vec![
            RouteHop {
                node: "client1".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
            RouteHop {
                node: "exit1".into(),
                hop_type: seep_core::HopType::Egress,
            },
        ];
        let relay = bridge.associate(ctx, &hops).await.unwrap();

        // —— 第 1 包：FULL 全链路 + dir=Down 回包 ——
        relay.send_to(&target, b"t2-ping").await.unwrap();
        let mut buf = [0u8; 2048];
        let (rt, rn) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("T2：两跳往返回包超时（dir=Down 全链路）")
            .unwrap();
        assert_eq!(&buf[..rn], b"t2-ping", "echo 载荷原样回送");
        assert_eq!(rt.host, "127.0.0.1");
        assert_eq!(rt.port, echo_addr.port());
        assert_eq!(rt.proto, TargetProto::Udp);

        // —— 第 2 包：CACHED 全链路（exit 复用 per-flow socket）——
        relay.send_to(&target, b"t2-second").await.unwrap();
        let (rt2, rn2) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("T2：CACHED 第二包回包超时")
            .unwrap();
        assert_eq!(&buf[..rn2], b"t2-second");
        assert_eq!(rt2.port, echo_addr.port());

        // exit 单 flow 一把 per-flow socket（两包共用）；relay/exit 各一条跳缓存
        let exit_face = exit_plane.udp.as_ref().unwrap();
        assert_eq!(exit_face.flows.len(), 1);
        assert_eq!(exit_face.cache.map.len(), 1, "exit 一条跳缓存");
        let relay_face = relay_plane.udp.as_ref().unwrap();
        assert_eq!(relay_face.cache.map.len(), 1, "relay 一条跳缓存");
        assert_eq!(
            exit_face.metrics.forwarded_down.load(Ordering::Relaxed),
            2,
            "exit 下行回封两包"
        );
        assert_eq!(exit_face.metrics.forwarded_up.load(Ordering::Relaxed), 2);

        relay_serve.abort();
        exit_serve.abort();
    }

    // ── P0-5 §10-S3 测试 1：面快照（UdpFaceSnapshot）经真 socket 往返驱动 ──

    /// 两跳小流量后 relay/exit 两侧 `udp_snapshot()` 数值断言（forwarded 双向=2、
    /// flows_active=1——跳缓存各一、unknown_flow/evicted/malformed 恒 0）；
    /// 起始全零态同测钉住。拓扑与 T2 同构（echo + 双 plane + client 桥）。
    #[tokio::test]
    async fn udp_face_snapshot_after_roundtrip() {
        use crate::udp_chain::MeshUdpBridge;
        use seep_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, RouteHop, TargetProto};

        // —— 环回 echo server ——
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
            }
        });

        // 探空闲端口（spawn_udp 内部 bind；T2 同法）
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_udp_addr = probe.local_addr().unwrap();
        drop(probe);
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exit_udp_addr = probe.local_addr().unwrap();
        drop(probe);

        // —— exit plane（path 终点：exit 分支 + 下行 task）——
        let exit_registry = Arc::new(MeshRegistry::new());
        exit_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        let exit_plane = Arc::new(
            MeshDataPlane::new("exit1".into(), exit_registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        let exit_serve = exit_plane.spawn_udp(exit_udp_addr);

        // —— relay plane（FULL 剥自身 / CACHED 查缓存 / Down 回 prev）——
        let relay_registry = Arc::new(MeshRegistry::new());
        relay_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        relay_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                exit_udp_addr,
            ))
            .unwrap();
        let relay_plane = Arc::new(
            MeshDataPlane::new("relay1".into(), relay_registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        let relay_serve = relay_plane.spawn_udp(relay_udp_addr);

        // 起始态：面快照全零（挂载即有、无流量恒零——验收 #2 恒渲染口径的数据侧对位）
        assert_eq!(relay_plane.udp_snapshot(), Some(UdpFaceSnapshot::default()));
        assert_eq!(exit_plane.udp_snapshot(), Some(UdpFaceSnapshot::default()));

        // —— 客户端出站两跳往返（FULL + CACHED 各一包）——
        let client_registry = Arc::new(MeshRegistry::new());
        client_registry
            .register_node(NodeRecord::new(
                "client1".into(),
                NodeRole::Client,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        client_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                relay_udp_addr,
            ))
            .unwrap();
        let bridge = MeshUdpBridge::new(
            "client1".into(),
            client_registry,
            None,
            &MeshUdpGate::new(true),
        )
        .unwrap();
        let target = FlowTarget {
            host: "127.0.0.1".into(),
            port: echo_addr.port(),
            proto: TargetProto::Udp,
        };
        let ctx = FlowContext {
            id: FlowId::new(),
            target: target.clone(),
            metadata: FlowMetadata::default(),
        };
        let hops = vec![
            RouteHop {
                node: "client1".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
            RouteHop {
                node: "exit1".into(),
                hop_type: seep_core::HopType::Egress,
            },
        ];
        let relay = bridge.associate(ctx, &hops).await.unwrap();

        relay.send_to(&target, b"s3-ping").await.unwrap();
        let mut buf = [0u8; 2048];
        let (_, rn) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("S3：两跳往返回包超时")
            .unwrap();
        assert_eq!(&buf[..rn], b"s3-ping", "echo 载荷原样回送");
        relay.send_to(&target, b"s3-second").await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("S3：CACHED 第二包回包超时")
            .unwrap();

        // 两包后 relay/exit 对称：上行各转发 2、下行各回送 2、跳缓存各 1、
        // unknown_flow/evicted/malformed/replay_dropped 恒 0
        let expect = UdpFaceSnapshot {
            forwarded_up: 2,
            forwarded_down: 2,
            malformed: 0,
            replay_dropped: 0,
            flows_active: 1,
            unknown_flow: 0,
            evicted: 0,
        };
        assert_eq!(relay_plane.udp_snapshot(), Some(expect), "relay 面快照");
        assert_eq!(exit_plane.udp_snapshot(), Some(expect), "exit 面快照");

        relay_serve.abort();
        exit_serve.abort();
    }

    // ── P2-7 M1 §4.2 集成：exit 面防重放端到端（真 socket 双 plane + echo）──

    /// 轮询等待异步平面计数到位（serve 任务内同步递增，注入后短窗内可见）。
    async fn wait_for(mut f: impl FnMut() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !f() {
            assert!(Instant::now() < deadline, "等待 {what} 超时");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 读下行回包（带 5s 超时——T2 同款窗；helper 规避「闭包返回借用入参的
    /// future」生命期问题）
    async fn recv_downlink(relay: &Arc<dyn UdpRelay>, rbuf: &mut [u8]) -> usize {
        let rt = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(rbuf))
            .await
            .expect("应收到下行回包")
            .unwrap();
        rt.1
    }

    /// §4.2 前两条：注入同 seq 重放帧 → exit 面 replay_dropped=1 且 echo 目标
    /// 收不到重复载荷（echo 观测通道无第四段）；乱序帧（seq+1 先于 seq+0）
    /// 两包都到、窗口就位（client 桥/relay 面计数不受牵连）。
    #[tokio::test]
    async fn udp_exit_plane_replay_drop_and_out_of_order() {
        use crate::udp_chain::MeshUdpBridge;
        use seep_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, RouteHop, TargetProto};

        // —— echo server，载荷逐段送观测通道（「未收到重复」的可断言证据）——
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let echo_addr = echo.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                    let _ = tx.send(buf[..n].to_vec()).await;
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
            }
        });

        // 探空闲端口（spawn_udp 内部 bind；T2 同法）
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_udp_addr = probe.local_addr().unwrap();
        drop(probe);
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exit_udp_addr = probe.local_addr().unwrap();
        drop(probe);

        // —— exit plane + relay plane（拓扑同 T2/S3）——
        let exit_registry = Arc::new(MeshRegistry::new());
        exit_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        let exit_plane = Arc::new(
            MeshDataPlane::new("exit1".into(), exit_registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        let exit_serve = exit_plane.spawn_udp(exit_udp_addr);

        let relay_registry = Arc::new(MeshRegistry::new());
        relay_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        relay_registry
            .register_node(NodeRecord::new(
                "exit1".into(),
                NodeRole::Exit,
                exit_udp_addr,
            ))
            .unwrap();
        let relay_plane = Arc::new(
            MeshDataPlane::new("relay1".into(), relay_registry)
                .with_udp(MeshUdpGate::new(true))
                .unwrap(),
        );
        let relay_serve = relay_plane.spawn_udp(relay_udp_addr);

        // —— client 桥（flow_id 持有，注入帧复用同 id）——
        let client_registry = Arc::new(MeshRegistry::new());
        client_registry
            .register_node(NodeRecord::new(
                "client1".into(),
                NodeRole::Client,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        client_registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                relay_udp_addr,
            ))
            .unwrap();
        let bridge = MeshUdpBridge::new(
            "client1".into(),
            client_registry,
            None,
            &MeshUdpGate::new(true),
        )
        .unwrap();
        let target = FlowTarget {
            host: "127.0.0.1".into(),
            port: echo_addr.port(),
            proto: TargetProto::Udp,
        };
        let ctx = FlowContext {
            id: FlowId::new(),
            target: target.clone(),
            metadata: FlowMetadata::default(),
        };
        let flow_id = *ctx.id.as_uuid().as_bytes();
        let hops = vec![
            RouteHop {
                node: "client1".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
            RouteHop {
                node: "exit1".into(),
                hop_type: seep_core::HopType::Egress,
            },
        ];
        let relay = bridge.associate(ctx, &hops).await.unwrap();
        let mut rbuf = [0u8; 2048];

        // echo 观测通道逐段断言（「未收到重复」的顺序一致性证据）
        let expect_echo_payloads = |got: Vec<u8>, w: &'static [u8]| {
            assert_eq!(got, w, "echo 收到的载荷应逐段匹配");
        };

        // —— 1) 首包上行（FULL seq=0）→ echo 收 1 段、下行回包 ——
        relay.send_to(&target, b"ping").await.unwrap();
        let n = recv_downlink(&relay, &mut rbuf).await;
        assert_eq!(&rbuf[..n], b"ping");
        expect_echo_payloads(
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("echo 观测通道应收到 ping")
                .unwrap(),
            b"ping",
        );

        // —— 2) 注入 FULL 帧直达 exit（绕过 relay——exit 面窗口独立）——
        let inject = |seq: u32, payload: &[u8]| {
            let env = UdpEnvelope {
                version: UDP_ENVELOPE_VERSION_V2,
                dir: UdpDir::Up,
                flow_id,
                target_host: "127.0.0.1".into(),
                target_port: echo_addr.port(),
                path_mode: UdpPathMode::Full,
                hop_index: 0,
                seq,
                seq_present: true,
                path: vec!["exit1".into()],
                payload: payload.to_vec(),
            };
            encode_udp_envelope(&env).unwrap()
        };
        let injector = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 乱序帧：seq=2（later）先于 seq=1（middle）→ 两包都到。
        // 注：注入的 FULL 使 exit 侧 prev 更新为 injector（§3 上行来源即下行
        // 回包目标）——later/middle 的回包直回 injector，不经 relay/client；
        // 这也正是「每接收跳独立窗口」的旁证：注入帧直入 exit 面窗口校验。
        injector
            .send_to(&inject(2, b"later"), exit_udp_addr)
            .await
            .unwrap();
        let mut ibuf = [0u8; 2048];
        let (n, _peer) =
            tokio::time::timeout(Duration::from_secs(5), injector.recv_from(&mut ibuf))
                .await
                .expect("应收到 later 回包")
                .unwrap();
        let env = decode_udp_envelope(&ibuf[..n]).expect("回包应为合法 envelope");
        assert_eq!(env.payload, b"later", "跳跃前进 seq=2 应接受");
        injector
            .send_to(&inject(1, b"middle"), exit_udp_addr)
            .await
            .unwrap();
        let (n, _peer) =
            tokio::time::timeout(Duration::from_secs(5), injector.recv_from(&mut ibuf))
                .await
                .expect("应收到 middle 回包")
                .unwrap();
        let env = decode_udp_envelope(&ibuf[..n]).expect("回包应为合法 envelope");
        assert_eq!(env.payload, b"middle", "窗口内回退 seq=1（未收位）应接受");
        expect_echo_payloads(
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("echo 观测通道应收到 later")
                .unwrap(),
            b"later",
        );
        expect_echo_payloads(
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("echo 观测通道应收到 middle")
                .unwrap(),
            b"middle",
        );

        // —— 3) 重放注入：同 seq=2（last 恒拒）→ injector 无回包、echo 无
        //    第四段、exit 计数 1 ——
        injector
            .send_to(&inject(2, b"later"), exit_udp_addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), injector.recv_from(&mut ibuf))
                .await
                .is_err(),
            "重放帧到达 exit 被拒——下行不应再有任何回包"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "echo 观测通道不应收到重放副本"
        );
        wait_for(
            || exit_plane.udp_snapshot().unwrap().replay_dropped == 1,
            "exit replay_dropped=1",
        )
        .await;

        // —— 4) 窗口内重放：同 seq=1（历史位已置）→ 计数 2 ——
        injector
            .send_to(&inject(1, b"middle"), exit_udp_addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), injector.recv_from(&mut ibuf))
                .await
                .is_err(),
            "窗口内重放同样被拒"
        );
        wait_for(
            || exit_plane.udp_snapshot().unwrap().replay_dropped == 2,
            "exit replay_dropped=2",
        )
        .await;

        // —— 5) 终态快照：exit 收 3 段（ping/later/middle）、重放计 2 且不
        //    混入 malformed/unknown；relay 面与 client 桥计数不受牵连 ——
        let exit_snap = exit_plane.udp_snapshot().unwrap();
        assert_eq!(exit_snap.forwarded_up, 3, "exit 上行三包");
        assert_eq!(exit_snap.forwarded_down, 3, "exit 下行三包");
        assert_eq!(exit_snap.replay_dropped, 2);
        assert_eq!(exit_snap.malformed, 0, "重放不混 malformed（E4 静默语义）");
        assert_eq!(exit_snap.unknown_flow, 0);
        let relay_snap = relay_plane.udp_snapshot().unwrap();
        assert_eq!(
            relay_snap.forwarded_up, 1,
            "relay 仅转发 ping（注入直达 exit）"
        );
        assert_eq!(
            relay_snap.forwarded_down, 1,
            "relay 仅下行转发 ping（later/middle 回包直回 injector，prev 已更新）"
        );
        assert_eq!(relay_snap.replay_dropped, 0, "relay 面窗口未见重放");
        assert_eq!(relay_snap.malformed, 0);
        let client = bridge.client_metrics();
        assert_eq!(client.replay_dropped(), 0, "client 桥下行无重放");
        assert_eq!(client.dropped(), 0);
        // echo 观测通道已整体消费（ping/later/middle 三段），无第四段残留
        assert!(rx.try_recv().is_err(), "echo 通道应已耗尽");

        relay_serve.abort();
        exit_serve.abort();
    }

    /// P3-5 R2：write_frame 短写推进钉死——mock 每次最多写 `cap` 字节，
    /// 断言 vectored 循环推进至收齐完整 `[len][payload]`。
    struct ShortWriter {
        cap: usize,
        written: Vec<u8>,
        calls: usize,
    }

    impl ShortWriter {
        fn new(cap: usize) -> Self {
            Self {
                cap,
                written: Vec::new(),
                calls: 0,
            }
        }
    }

    impl tokio::io::AsyncWrite for ShortWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.calls += 1;
            let n = buf.len().min(self.cap);
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.calls += 1;
            let total: usize = bufs.iter().map(|b| b.len()).sum();
            let n = total.min(self.cap);
            let mut rem = n;
            for b in bufs {
                if rem == 0 {
                    break;
                }
                let take = b.len().min(rem);
                self.written.extend_from_slice(&b[..take]);
                rem -= take;
            }
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_frame_short_write_drives_to_completion() {
        let payload = b"hello-mesh-frame-p3-5".repeat(7);
        let mut expect = (payload.len() as u32).to_be_bytes().to_vec();
        expect.extend_from_slice(&payload);

        // cap=3：len 4B 需两次 + payload 多次——短写推进全路径
        let mut w = ShortWriter::new(3);
        write_frame(&mut w, &payload).await.unwrap();
        assert_eq!(w.written, expect);

        // cap=1：最碎短写
        let mut w = ShortWriter::new(1);
        write_frame(&mut w, &payload).await.unwrap();
        assert_eq!(w.written, expect);

        // cap 充足：单次调用写齐（TcpStream 形态，无多余 syscall）
        let mut w = ShortWriter::new(usize::MAX);
        write_frame(&mut w, &payload).await.unwrap();
        assert_eq!(w.written, expect);
        assert_eq!(w.calls, 1, "vectored 充足容量应一轮写齐");
    }
}
