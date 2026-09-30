//! Minimal mesh data-plane transport (TCP only).
//!
//! This implements a simple "hop-by-hop" forwarding protocol between Seep nodes.
//! It is intentionally minimal, but supports optional mTLS for encryption/authentication.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::{
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{anyhow, Result};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use dashmap::DashMap;
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

    #[allow(dead_code)] // 观测读取点 = P0-5 get()/get_gauge() 装配（§13-2），S3 阶段仅测试消费
    fn evicted_count(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    #[allow(dead_code)] // 观测读取点 = P0-5 get()/get_gauge() 装配（§13-2），S3 阶段仅测试消费
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
// 只持有面自身计数。读取点（get()/get_gauge() 拼装）归 P0-5 观测轮。

/// 缓存 TTL 默认 = `udp.mapping_idle_secs`（§3，60s；S5 接配置走 `with_udp_limits`）。
const UDP_FACE_DEFAULT_TTL: Duration = Duration::from_secs(60);
/// 缓存上界默认 = R10 的 65536（§3）。pub = runtime 接线点传参（ttl 走配置、上界走本默认）。
pub const UDP_FACE_DEFAULT_MAX: usize = 65536;
/// §14-1 hop_index 熔断上界：CACHED 成环的唯一断路器（FULL 靠 path 严格递减防环）。
const MAX_UDP_HOPS: u8 = 16;

#[allow(dead_code)] // 读取点 = P0-5 get()/get_gauge()（§13-2），S3 仅写入
struct UdpFaceMetrics {
    /// 上行方向成功发出的数据报（relay 重编码发出 / exit 发往 target）
    forwarded_up: AtomicU64,
    /// 下行方向成功发出的数据报（exit 下行封装发出 / relay 发往 prev）
    forwarded_down: AtomicU64,
    /// 解码拒绝（§2 校验失败）+ §13-3 超界 + §14-1 hop 溢出
    malformed: AtomicU64,
    /// 缓存条目数 gauge（插/逐/清扫后同步——净额即 len；§13-2 允许 sweep 时点偏差）
    flows_active: AtomicI64,
}

impl UdpFaceMetrics {
    fn new() -> Self {
        Self {
            forwarded_up: AtomicU64::new(0),
            forwarded_down: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            flows_active: AtomicI64::new(0),
        }
    }
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
            metrics: UdpFaceMetrics::new(),
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
        self.sync_gauge();
    }

    /// 下行 task 自身退出路径（§13-1：task 自清理时不 abort 自己——取 retire_flow
    /// 的后两步，顺序保持 flows 先于 cache）。
    fn forget_flow(&self, flow_id: &[u8; 16]) {
        self.flows.remove(flow_id);
        self.cache.remove(flow_id);
        self.sync_gauge();
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
        self.sync_gauge();
    }

    fn sync_gauge(&self) {
        self.metrics
            .flows_active
            .store(self.cache.len() as i64, Ordering::Relaxed);
    }
}

/// exit 下行 task（§4 / §13-1，与 P0-1 forwarder 同构）：target 回包 → 封
/// `UdpEnvelope{dir:Down, Cached, hop_index:0}` → 面 socket 发往 `cache.prev`
/// （每次现读 prev——FULL 重关联刷新后下行随之改向）。
async fn exit_downlink_loop(
    face: Arc<UdpFace>,
    flow: Arc<UdpSocket>,
    face_sock: Arc<UdpSocket>,
    flow_id: [u8; 16],
    target: (String, u16),
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
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Down,
            flow_id,
            target_host: target.0.clone(),
            target_port: target.1,
            path_mode: UdpPathMode::Cached,
            hop_index: 0, // §14-1：下行发送端（exit）置 0
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
                        self.registry
                            .record_link_bytes(&self.local_node_id, &next, wire.len() as u64);
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
            let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let flow_sock = Arc::new(UdpSocket::bind(bind_addr).await?);
            flow_sock.connect(addr).await?;
            if let Err(e) = flow_sock.send(&env.payload).await {
                // 目标不可达：表项尚未建立，socket 直接丢弃（无需 §13-1 回收）
                return Err(e.into());
            }
            if is_full {
                face.associate(env.flow_id, None, from);
            }
            let task = tokio::spawn(exit_downlink_loop(
                Arc::clone(face),
                Arc::clone(&flow_sock),
                Arc::clone(face_sock),
                env.flow_id,
                target.clone(),
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
            let flow_sock = {
                let entry = face
                    .flows
                    .get(&env.flow_id)
                    .expect("need_create=false 即 flow 必在表");
                Arc::clone(&entry.sock)
            };
            flow_sock.send(&env.payload).await?;
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
        assert_eq!(face.metrics.forwarded_up.load(Ordering::Relaxed), 1, "仅 FULL 被转发");
        assert_eq!(face.metrics.malformed.load(Ordering::Relaxed), 0);

        // 下一跳只收到首包 FULL
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), next_sock.recv_from(&mut buf))
            .await
            .expect("首包 FULL 已转发")
            .unwrap();
        assert_eq!(decode_udp_envelope(&buf[..n]).unwrap().path_mode, UdpPathMode::Full);
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
}
