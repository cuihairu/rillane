use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SeepConfig {
    pub control: ControlConfig,
    pub telemetry: TelemetryConfig,
    pub ingress: Vec<IngressDescriptor>,
    pub egress: Vec<EgressDescriptor>,
    pub routing: RoutingConfig,
    /// UDP 数据面（P0-2；缺省整块关闭，兼容既有配置）
    #[serde(default)]
    pub udp: UdpConfig,
}

/// UDP 数据面配置（udp-dataplane.md §5.2 / udp-relay-path.md §2）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UdpConfig {
    /// 总开关：false 时 socks5 ASSOCIATE 应答 0x07（udp-relay-path.md §2.1）
    #[serde(default)]
    pub enabled: bool,
    /// 数据报源 IP 校验（防中继借用，§2.3 步骤 3；默认开）
    #[serde(default = "default_true")]
    pub strict_udp_source: bool,
    /// 会话空闲上限（秒）
    #[serde(default = "default_udp_session_idle")]
    pub session_idle_secs: u64,
    /// 目标映射空闲上限（秒）
    #[serde(default = "default_udp_mapping_idle")]
    pub mapping_idle_secs: u64,
    /// 全局并发会话上界（满员拒新）
    #[serde(default = "default_udp_max_sessions")]
    pub max_sessions: usize,
    /// 回收扫描周期（秒；P0-5 §1.2——配置面收紧到秒粒度）
    #[serde(default = "default_udp_sweep_interval")]
    pub sweep_interval_secs: u64,
    /// 会话内映射上界（溢出逐最久空闲）
    #[serde(default = "default_udp_max_mappings")]
    pub max_mappings: usize,
    /// 可选会话寿命上界（秒；缺省不限——长局游戏不断流）
    #[serde(default)]
    pub session_lifetime_secs: Option<u64>,
    /// 下行通道容量（满即丢 + DownlinkFull 计数，UDP 无背压）
    #[serde(default = "default_udp_downlink_queue_depth")]
    pub downlink_queue_depth: usize,
    /// 并发 ASSOCIATE 上限（超限回 0x01 且计数；P0-5 §1.2 防滥用）
    #[serde(default = "default_udp_max_associates")]
    pub max_associates: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strict_udp_source: true,
            session_idle_secs: 180,
            mapping_idle_secs: 60,
            max_sessions: 4096,
            sweep_interval_secs: 15,
            max_mappings: 256,
            session_lifetime_secs: None,
            downlink_queue_depth: 64,
            max_associates: 256,
        }
    }
}

const fn default_true() -> bool {
    true
}
const fn default_udp_session_idle() -> u64 {
    180
}
const fn default_udp_mapping_idle() -> u64 {
    60
}
const fn default_udp_max_sessions() -> usize {
    4096
}
const fn default_udp_sweep_interval() -> u64 {
    15
}
const fn default_udp_max_mappings() -> usize {
    256
}
const fn default_udp_downlink_queue_depth() -> usize {
    64
}
const fn default_udp_max_associates() -> usize {
    256
}

impl UdpConfig {
    /// P0-5 §1.6：非法值构建期报错（约束对齐 `UdpSessionConfig::validate`，
    /// `session_lifetime_secs` 存在时须 ≥ `session_idle_secs`）。
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.sweep_interval_secs >= 1, "udp.sweep_interval_secs 必须 ≥ 1");
        anyhow::ensure!(self.max_mappings >= 1, "udp.max_mappings 必须 ≥ 1");
        anyhow::ensure!(
            self.downlink_queue_depth >= 1,
            "udp.downlink_queue_depth 必须 ≥ 1"
        );
        anyhow::ensure!(self.max_associates >= 1, "udp.max_associates 必须 ≥ 1");
        if let Some(lifetime) = self.session_lifetime_secs {
            anyhow::ensure!(
                lifetime >= self.session_idle_secs,
                "udp.session_lifetime_secs 不应小于 udp.session_idle_secs"
            );
        }
        Ok(())
    }
}

/// per-ingress `udp_enabled` 判定（P0-5 §1.3/§9-4）：None 继承全局，
/// Some 显式覆盖。求值点 = `build_ingress_endpoints` 逐入口一次。
pub fn resolve_udp_enabled(global_enabled: bool, per_ingress: Option<bool>) -> bool {
    per_ingress.unwrap_or(global_enabled)
}

impl SeepConfig {
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件: {}", path.display()))?;
        let hint = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);
        Self::from_str(&raw, hint.as_deref())
    }

    pub fn from_str(raw: &str, hint: Option<&str>) -> Result<Self> {
        match hint {
            Some("json") => serde_json::from_str(raw).context("JSON 配置解析失败"),
            Some("toml") => toml::from_str(raw).context("TOML 配置解析失败"),
            Some("yaml") | Some("yml") => serde_yaml::from_str(raw).context("YAML 配置解析失败"),
            _ => serde_yaml::from_str(raw)
                .or_else(|_| serde_json::from_str(raw))
                .or_else(|_| toml::from_str(raw))
                .context("无法识别配置格式"),
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        PathBuf::from("/etc/seep")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    pub api_bind: String,
    pub uds_path: Option<PathBuf>,
    pub admin_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub enable_metrics: bool,
    pub enable_tracing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressDescriptor {
    pub name: String,
    #[serde(flatten)]
    pub spec: IngressConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDescriptor {
    pub name: String,
    #[serde(flatten)]
    pub spec: EgressConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IngressConfig {
    Socks5 {
        bind: String,
        auth: Option<Vec<Credential>>,
        /// per-ingress UDP 覆盖（P0-5 §1.3）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 ASSOCIATE。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
    Http {
        bind: String,
    },
    Mixed {
        bind: String,
        /// per-ingress UDP 覆盖（P0-5 §1.3），语义同 Socks5。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressConfig {
    Direct,
    Socks5 {
        server: String,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Http {
        server: String,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
    },
    Shadowsocks {
        server: String,
        port: u16,
        method: String,
        password: String,
    },
    Vmess {
        server: String,
        port: u16,
        uuid: String,
        #[serde(default)]
        alter_id: u16,
        #[serde(default = "default_security")]
        security: String,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Vless {
        server: String,
        port: u16,
        uuid: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<String>,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Trojan {
        server: String,
        port: u16,
        password: String,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        #[serde(default = "default_tls_true")]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Hysteria {
        server: String,
        port: u16,
        password: String,
        #[serde(default = "default_protocol")]
        protocol: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        up_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        down_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_str: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs_param: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_name: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Hysteria2 {
        server: String,
        port: u16,
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mport: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs_param: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_name: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Wireguard {
        endpoint: String,
        private_key: String,
        public_key: String,
        address: String,
        /// Allowed IPs for peer routing (e.g. ["10.0.0.0/24", "0.0.0.0/0"]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_ips: Option<Vec<String>>,
        /// Optional pre-shared key (base64 or hex).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preshared_key: Option<String>,
        /// Optional persistent keepalive in seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persistent_keepalive: Option<u16>,
        /// Optional local listen port (0/None means auto).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        listen_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mtu: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dns: Option<Vec<String>>,
    },
}

fn default_security() -> String {
    "auto".to_string()
}
fn default_network() -> String {
    "tcp".to_string()
}
fn default_protocol() -> String {
    "udp".to_string()
}
fn default_tls_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub default_node: String,
    pub groups: Vec<PolicyGroup>,
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGroup {
    pub name: String,
    pub strategy: Strategy,
    pub members: Vec<GroupMember>,
}

/// 运行时组描述符，包含解析后的组和统计信息
#[derive(Debug, Clone)]
pub struct GroupDescriptor {
    pub name: String,
    pub strategy: Strategy,
    pub members: Vec<GroupDescriptorMember>,
    pub fallback_enabled: bool,
    pub health_check_interval: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum GroupDescriptorMember {
    Node {
        name: String,
        weight: u32,
        is_healthy: bool,
    },
    Group {
        name: String,
        weight: u32,
        descriptor: Box<GroupDescriptor>,
    },
}

impl GroupDescriptorMember {
    pub fn as_name(&self) -> &str {
        match self {
            GroupDescriptorMember::Node { name, .. } => name,
            GroupDescriptorMember::Group { name, .. } => name,
        }
    }

    pub fn as_weight(&self) -> u32 {
        match self {
            GroupDescriptorMember::Node { weight, .. } => *weight,
            GroupDescriptorMember::Group { weight, .. } => *weight,
        }
    }

    pub fn is_healthy(&self) -> bool {
        match self {
            GroupDescriptorMember::Node { is_healthy, .. } => *is_healthy,
            GroupDescriptorMember::Group { descriptor, .. } => {
                // 组健康状态可以基于成员健康状态计算
                descriptor.has_healthy_members()
            }
        }
    }
}

impl GroupDescriptor {
    pub fn new(name: String, strategy: Strategy, members: Vec<GroupDescriptorMember>) -> Self {
        Self {
            name,
            strategy,
            members,
            fallback_enabled: true,
            health_check_interval: Some(30),
        }
    }

    pub fn has_healthy_members(&self) -> bool {
        self.members.iter().any(|m| m.is_healthy())
    }

    pub fn healthy_members(&self) -> Vec<&GroupDescriptorMember> {
        self.members.iter().filter(|m| m.is_healthy()).collect()
    }

    /// 展开所有节点（处理组嵌套）
    pub fn flatten_nodes(&self) -> Vec<(String, u32)> {
        let mut nodes = Vec::new();
        for member in &self.members {
            match member {
                GroupDescriptorMember::Node { name, weight, .. } => {
                    nodes.push((name.clone(), *weight));
                }
                GroupDescriptorMember::Group {
                    descriptor, weight, ..
                } => {
                    // 递归展开嵌套组，应用权重
                    let nested_nodes = descriptor.flatten_nodes();
                    for (node_name, node_weight) in nested_nodes {
                        nodes.push((node_name, node_weight.saturating_mul(*weight)));
                    }
                }
            }
        }
        nodes
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum GroupMember {
    /// 直接节点引用
    Node { name: String },
    /// 嵌套组引用
    Group { name: String },
    /// 带权重的节点
    WeightedNode { name: String, weight: u32 },
    /// 带权重的组
    WeightedGroup { name: String, weight: u32 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GroupMemberTagged {
    Node { name: String },
    Group { name: String },
    WeightedNode { name: String, weight: u32 },
    WeightedGroup { name: String, weight: u32 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum GroupMemberRepr {
    /// Shorthand: treat a plain string as `Node { name: ... }`.
    String(String),
    Tagged(GroupMemberTagged),
}

impl From<GroupMemberTagged> for GroupMember {
    fn from(v: GroupMemberTagged) -> Self {
        match v {
            GroupMemberTagged::Node { name } => GroupMember::Node { name },
            GroupMemberTagged::Group { name } => GroupMember::Group { name },
            GroupMemberTagged::WeightedNode { name, weight } => {
                GroupMember::WeightedNode { name, weight }
            }
            GroupMemberTagged::WeightedGroup { name, weight } => {
                GroupMember::WeightedGroup { name, weight }
            }
        }
    }
}

impl<'de> Deserialize<'de> for GroupMember {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let repr = GroupMemberRepr::deserialize(deserializer)?;
        Ok(match repr {
            GroupMemberRepr::String(name) => GroupMember::Node { name },
            GroupMemberRepr::Tagged(v) => v.into(),
        })
    }
}

impl GroupMember {
    pub fn as_name(&self) -> String {
        match self {
            GroupMember::Node { name } => name.clone(),
            GroupMember::Group { name } => name.clone(),
            GroupMember::WeightedNode { name, .. } => name.clone(),
            GroupMember::WeightedGroup { name, .. } => name.clone(),
        }
    }

    pub fn as_weight(&self) -> u32 {
        match self {
            GroupMember::Node { .. } => 1,
            GroupMember::Group { .. } => 1,
            GroupMember::WeightedNode { weight, .. } => *weight,
            GroupMember::WeightedGroup { weight, .. } => *weight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Fixed,
    Latency,
    Random,
    /// 基于带宽选择
    Bandwidth,
    /// 加权随机选择
    Weighted,
    /// 一致性哈希
    ConsistentHash,
    /// 轮询
    RoundRobin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub name: String,
    pub matches: Vec<MatchCondition>,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchCondition {
    DomainSuffix { values: Vec<String> },
    DomainKeyword { values: Vec<String> },
    Geoip { country: String },
    Network { cidrs: Vec<String> },
    Port { values: Vec<u16> },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("未知的入口类型: {0}")]
    UnknownIngress(String),
    #[error("未知的出口类型: {0}")]
    UnknownEgress(String),
}
