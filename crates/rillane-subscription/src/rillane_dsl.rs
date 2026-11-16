//! Rillane DSL 订阅处理

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use rillane_config::{
    EgressConfig, EgressDescriptor, GroupMember, MatchCondition, PolicyGroup, RealityConfig,
    RouteRule, RoutingConfig, Strategy,
};

/// reality-opts JSON 块 → `RealityConfig`（G1-6 配置保留面，与 clash.rs
/// 的 YAML 版同语义）：键 kebab/snake 兼容；块缺席 = None；缺 public-key
/// 点名拒绝（不静默造空）。
fn reality_from_json(
    value: &Option<serde_json::Value>,
    node: &str,
) -> anyhow::Result<Option<RealityConfig>> {
    let Some(v) = value else {
        return Ok(None);
    };
    let m = v
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("VLESS 节点 {node} 的 reality-opts 须为映射"))?;
    let get =
        |k: &str| -> Option<String> { m.get(k).and_then(|x| x.as_str()).map(|s| s.to_string()) };
    let public_key = get("public-key")
        .or_else(|| get("public_key"))
        .ok_or_else(|| anyhow::anyhow!("VLESS 节点 {node} 的 reality-opts 缺少 public-key"))?;
    Ok(Some(RealityConfig {
        public_key,
        short_id: get("short-id").or_else(|| get("short_id")),
    }))
}

/// Rillane DSL 版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RillaneVersion {
    #[serde(rename = "1.0")]
    V1_0,
    #[serde(rename = "1.1")]
    V1_1,
}

/// 节点类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    Direct,
    Reject,
    Socks5,
    Http,
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Hysteria2,
    Wireguard,
}

/// 节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RillaneNode {
    /// 节点名称
    pub name: String,
    /// 节点类型
    #[serde(rename = "type")]
    pub node_type: NodeType,
    /// 服务器地址
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// 服务器端口
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// 认证信息
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<NodeAuth>,
    /// 传输协议
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportConfig>,
    /// TLS 配置
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    /// 带宽限制（Mbps）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit: Option<u32>,
    /// 地理位置
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<NodeLocation>,
    /// 标签
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    /// VLESS flow（如 xtls-rprx-vision；G1-6）。捕获随节点保留（拨号期对
    /// 不支持面点名拒绝）——静默降级为普通 VLESS 会连不上真节点（xtls 服务
    /// 端期望 Vision 分帧）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// REALITY 选项块（public-key/short-id；G1-6）。捕获随节点保留（拨号
    /// 期点名拒绝）——静默降级为普通 TLS VLESS 后服务端回落伪装站点。
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "reality-opts",
        alias = "reality_opts"
    )]
    pub reality: Option<serde_json::Value>,
}

/// 节点认证信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NodeAuth {
    /// 用户名密码
    Password { username: String, password: String },
    /// UUID（用于 VMess/VLESS/Trojan/Hysteria2 等）
    Uuid {
        #[serde(alias = "value")]
        uuid: String,
    },
    /// 密钥（用于 Shadowsocks）
    Key { method: String, password: String },
    /// 无认证
    None,
}

/// 传输配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    /// TCP
    Tcp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
    },
    /// WebSocket
    Ws {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
    },
    /// gRPC
    Grpc {
        service_name: String,
        #[serde(default)]
        multi_mode: bool,
    },
    /// HTTP/2
    H2 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// QUIC
    Quic {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        security: Option<String>,
    },
}

/// TLS 配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// 是否启用 TLS
    #[serde(default)]
    pub enabled: bool,
    /// SNI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// ALPN
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// 跳过证书验证
    #[serde(default)]
    pub skip_cert_verify: bool,
    /// 指纹
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// 证书
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// 私钥
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// 节点位置信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLocation {
    /// 国家代码
    pub country: String,
    /// 国家名称
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    /// 城市
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// ISP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    /// 组织
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// 策略类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RillaneStrategy {
    Fixed,
    Random,
    Latency,
    Bandwidth,
    Weighted,
    ConsistentHash,
    RoundRobin,
}

/// 策略组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RillaneGroup {
    /// 组名称
    pub name: String,
    /// 策略类型
    pub strategy: RillaneStrategy,
    /// 成员列表
    pub members: Vec<GroupMemberRef>,
    /// 健康检查间隔（秒）
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u64,
    /// 启用故障转移
    #[serde(default = "default_fallback_enabled")]
    pub fallback_enabled: bool,
    /// 故障转移超时（秒）
    #[serde(default = "default_fallback_timeout")]
    pub fallback_timeout: u64,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

fn default_health_check_interval() -> u64 {
    30
}
fn default_fallback_enabled() -> bool {
    true
}
fn default_fallback_timeout() -> u64 {
    5
}

/// 组成员引用
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GroupMemberRef {
    /// 节点名称
    Node(String),
    /// 带权重的节点
    WeightedNode { name: String, weight: u32 },
    /// 组名称
    Group(String),
    /// 带权重的组
    WeightedGroup { name: String, weight: u32 },
}

/// 规则集
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RillaneRuleSet {
    /// 规则集名称
    pub name: String,
    /// 规则列表
    pub rules: Vec<RillaneRule>,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Rillane 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum RillaneRule {
    /// 域名后缀
    DomainSuffix {
        domains: Vec<String>,
        target: String,
    },
    /// 域名关键字
    DomainKeyword {
        keywords: Vec<String>,
        target: String,
    },
    /// 完全域名匹配
    Domain {
        domains: Vec<String>,
        target: String,
    },
    /// 域名正则匹配
    DomainRegex {
        patterns: Vec<String>,
        target: String,
    },
    /// IP CIDR
    IpCidr { cidrs: Vec<String>, target: String },
    /// GeoIP
    Geoip { country: String, target: String },
    /// GeoSite 站点类别（v2fly `.dat` 数据库）
    GeoSite { category: String, target: String },
    /// 端口范围
    Port { ports: Vec<u16>, target: String },
    /// 进程名
    Process {
        processes: Vec<String>,
        target: String,
    },
    /// 规则集引用
    RuleSet { name: String, target: String },
    /// 默认规则
    Match { target: String },
}

/// Rillane 配置根结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RillaneConfig {
    /// 配置版本
    pub version: RillaneVersion,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub meta: HashMap<String, String>,
    /// 节点列表
    pub nodes: Vec<RillaneNode>,
    /// 策略组列表
    pub groups: Vec<RillaneGroup>,
    /// 规则集列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rulesets: Vec<RillaneRuleSet>,
    /// 规则列表
    pub rules: Vec<RillaneRule>,
    /// 默认目标
    #[serde(default = "default_target")]
    pub default_target: String,
}

fn default_target() -> String {
    "direct".to_string()
}

/// Rillane DSL 转换器
pub struct RillaneDslConverter {
    /// 是否验证配置
    validate: bool,
    /// 是否过滤无效节点
    filter_invalid_nodes: bool,
}

impl RillaneDslConverter {
    /// 创建新的转换器
    pub fn new() -> Self {
        Self {
            validate: true,
            filter_invalid_nodes: true,
        }
    }

    /// 设置是否验证配置
    pub fn with_validation(mut self, validate: bool) -> Self {
        self.validate = validate;
        self
    }

    /// 设置是否过滤无效节点
    pub fn with_filtering(mut self, filter: bool) -> Self {
        self.filter_invalid_nodes = filter;
        self
    }

    /// 解析 Rillane DSL 配置
    pub fn parse(&self, content: &str) -> Result<RillaneConfig> {
        debug!(
            target: "rillane::subscription::rillane_dsl",
            "开始解析 Rillane DSL 配置"
        );

        let config: RillaneConfig =
            serde_yaml::from_str(content).context("解析 Rillane DSL 配置失败")?;

        if self.validate {
            self.validate_config(&config)?;
        }

        debug!(
            target: "rillane::subscription::rillane_dsl",
            version = ?config.version,
            nodes = config.nodes.len(),
            groups = config.groups.len(),
            rulesets = config.rulesets.len(),
            rules = config.rules.len(),
            "Rillane DSL 配置解析完成"
        );

        Ok(config)
    }

    /// 转换为标准 Rillane 配置
    pub fn convert_to_rillane(
        &self,
        rillane_config: &RillaneConfig,
    ) -> Result<rillane_config::RillaneConfig> {
        debug!(
            target: "rillane::subscription::rillane_dsl",
            "开始转换为标准 Rillane 配置"
        );

        // 转换节点为出口节点
        let egress = self.convert_nodes_to_egress(&rillane_config.nodes)?;

        // 转换策略组
        let groups = self.convert_groups_to_policy_groups(&rillane_config.groups)?;

        // 转换规则集为规则
        let mut rules = Vec::new();

        // 首先处理规则集
        for ruleset in &rillane_config.rulesets {
            for (index, rule) in ruleset.rules.iter().enumerate() {
                let name = format!("{}-rule-{}", ruleset.name, index + 1);
                let (matches, target) = self.convert_rillane_rule(rule)?;
                rules.push(RouteRule {
                    name,
                    matches,
                    target,
                });
            }
        }

        // 然后处理直接规则
        for (index, rule) in rillane_config.rules.iter().enumerate() {
            let name = format!("rule-{}", index + 1);
            let (matches, target) = self.convert_rillane_rule(rule)?;
            rules.push(RouteRule {
                name,
                matches,
                target,
            });
        }

        let routing = RoutingConfig {
            default_node: rillane_config.default_target.clone(),
            scenarios: Vec::new(),
            groups,
            rules,
            ..RoutingConfig::default()
        };

        let config = rillane_config::RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:9090".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: true,
                enable_tracing: false,
            },
            ingress: vec![], // Rillane DSL 不包含入口配置
            egress,
            routing,
            udp: rillane_config::UdpConfig::default(),
            // 订阅转换不产网络虚拟化块（P1-3 归用户主配置）
            network: None,
            // 订阅转换不产混淆块（P1-4 归用户主配置）
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        debug!(
            target: "rillane::subscription::rillane_dsl",
            egress = config.egress.len(),
            groups = config.routing.groups.len(),
            rules = config.routing.rules.len(),
            "标准 Rillane 配置转换完成"
        );

        Ok(config)
    }

    /// 验证配置
    fn validate_config(&self, config: &RillaneConfig) -> Result<()> {
        // 检查版本
        match config.version {
            RillaneVersion::V1_0 | RillaneVersion::V1_1 => {
                // 支持的版本
            }
        }

        // 检查节点名称唯一性
        let mut node_names = std::collections::HashSet::new();
        for node in &config.nodes {
            if !node_names.insert(node.name.clone()) {
                return Err(anyhow!("重复的节点名称: {}", node.name));
            }
        }

        // 检查组名称唯一性
        let mut group_names = std::collections::HashSet::new();
        for group in &config.groups {
            if !group_names.insert(group.name.clone()) {
                return Err(anyhow!("重复的组名称: {}", group.name));
            }
        }

        // 检查规则集名称唯一性
        let mut ruleset_names = std::collections::HashSet::new();
        for ruleset in &config.rulesets {
            if !ruleset_names.insert(ruleset.name.clone()) {
                return Err(anyhow!("重复的规则集名称: {}", ruleset.name));
            }
        }

        // 检查引用有效性
        self.validate_references(config)?;

        Ok(())
    }

    /// 验证引用有效性
    fn validate_references(&self, config: &RillaneConfig) -> Result<()> {
        let node_names: std::collections::HashSet<_> =
            config.nodes.iter().map(|n| n.name.as_str()).collect();

        let group_names: std::collections::HashSet<_> =
            config.groups.iter().map(|g| g.name.as_str()).collect();

        let ruleset_names: std::collections::HashSet<_> =
            config.rulesets.iter().map(|r| r.name.as_str()).collect();

        // 检查组成员引用
        for group in &config.groups {
            for member in &group.members {
                let ref_name = match member {
                    GroupMemberRef::Node(name) | GroupMemberRef::WeightedNode { name, .. } => name,
                    GroupMemberRef::Group(name) | GroupMemberRef::WeightedGroup { name, .. } => {
                        name
                    }
                };

                if !node_names.contains(ref_name.as_str())
                    && !group_names.contains(ref_name.as_str())
                {
                    return Err(anyhow!(
                        "组 {} 引用了不存在的节点或组: {}",
                        group.name,
                        ref_name
                    ));
                }
            }
        }

        // 检查规则引用
        for rule in &config.rules {
            if let RillaneRule::RuleSet { name, .. } = rule {
                if !ruleset_names.contains(name.as_str()) {
                    return Err(anyhow!("规则引用了不存在的规则集: {}", name));
                }
            }
        }

        // 检查规则集规则引用
        for ruleset in &config.rulesets {
            for rule in &ruleset.rules {
                if let RillaneRule::RuleSet { name, .. } = rule {
                    if !ruleset_names.contains(name.as_str()) {
                        return Err(anyhow!(
                            "规则集 {} 中的规则引用了不存在的规则集: {}",
                            ruleset.name,
                            name
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// 转换节点为出口节点
    fn convert_nodes_to_egress(&self, nodes: &[RillaneNode]) -> Result<Vec<EgressDescriptor>> {
        let mut egress = Vec::new();

        for node in nodes {
            if self.filter_invalid_nodes && !self.is_valid_node(node) {
                warn!(
                    target: "rillane::subscription::rillane_dsl",
                    name = %node.name,
                    node_type = ?node.node_type,
                    "跳过无效节点"
                );
                continue;
            }

            let egress_config = self.convert_node_to_egress_config(node)?;
            egress.push(EgressDescriptor {
                name: node.name.clone(),
                spec: egress_config,
            });
        }

        Ok(egress)
    }

    /// 转换单个节点为出口配置
    fn convert_node_to_egress_config(&self, node: &RillaneNode) -> Result<EgressConfig> {
        match node.node_type {
            NodeType::Direct => Ok(EgressConfig::Direct),
            NodeType::Reject => Err(anyhow!("Reject 节点类型暂不支持")),
            NodeType::Socks5 => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("Socks5 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("Socks5 节点缺少端口"))?;

                let (username, password) = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Password { username, password } => {
                            (Some(username.clone()), Some(password.clone()))
                        }
                        _ => return Err(anyhow!("Socks5 节点认证类型错误")),
                    }
                } else {
                    (None, None)
                };

                Ok(EgressConfig::Socks5 {
                    server,
                    port,
                    username,
                    password,
                })
            }
            NodeType::Http => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("HTTP 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("HTTP 节点缺少端口"))?;

                let (username, password) = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Password { username, password } => {
                            (Some(username.clone()), Some(password.clone()))
                        }
                        _ => return Err(anyhow!("HTTP 节点认证类型错误")),
                    }
                } else {
                    (None, None)
                };

                let tls_enabled = node.tls.as_ref().map(|t| t.enabled).unwrap_or(false);

                Ok(EgressConfig::Http {
                    server,
                    port,
                    username,
                    password,
                    tls: tls_enabled,
                    skip_cert_verify: node
                        .tls
                        .as_ref()
                        .map(|t| t.skip_cert_verify)
                        .unwrap_or(false),
                    sni: node.tls.as_ref().and_then(|t| t.server_name.clone()),
                    tls_fingerprint: None,
                })
            }
            NodeType::Shadowsocks => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("Shadowsocks 节点缺少服务器地址"))?;
                let port = node
                    .port
                    .ok_or_else(|| anyhow!("Shadowsocks 节点缺少端口"))?;

                let (method, password) = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Key { method, password } => (method.clone(), password.clone()),
                        _ => return Err(anyhow!("Shadowsocks 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("Shadowsocks 节点缺少认证信息"));
                };

                Ok(EgressConfig::Shadowsocks {
                    server,
                    port,
                    method,
                    password,
                    plugin: None,
                    plugin_opts: None,
                })
            }
            NodeType::Vmess => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("VMess 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("VMess 节点缺少端口"))?;

                let uuid = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Uuid { uuid } => uuid.clone(),
                        _ => return Err(anyhow!("VMess 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("VMess 节点缺少 UUID"));
                };

                let (network, path, host, grpc_service_name) =
                    if let Some(transport) = &node.transport {
                        match transport {
                            TransportConfig::Tcp { path: tcp_path, .. } => {
                                ("tcp".to_string(), tcp_path.clone(), None, None)
                            }
                            TransportConfig::Ws {
                                path: ws_path,
                                headers,
                            } => {
                                let host = headers
                                    .as_ref()
                                    .and_then(|h| h.get("Host").cloned())
                                    .or_else(|| node.server.clone())
                                    .map(|h| vec![h]);
                                ("ws".to_string(), Some(ws_path.clone()), host, None)
                            }
                            TransportConfig::Grpc { service_name, .. } => {
                                // gRPC 服务名落专用字段（线上路径 = /{name}/Tun）
                                ("grpc".to_string(), None, None, Some(service_name.clone()))
                            }
                            TransportConfig::H2 {
                                host: h2_host,
                                path: h2_path,
                                ..
                            } => ("h2".to_string(), h2_path.clone(), h2_host.clone(), None),
                            TransportConfig::Quic { .. } => ("quic".to_string(), None, None, None),
                        }
                    } else {
                        ("tcp".to_string(), None, None, None)
                    };

                let tls_config = node
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("VMess 节点缺少 TLS 配置"))?;

                Ok(EgressConfig::Vmess {
                    server,
                    port,
                    uuid,
                    alter_id: 0,
                    security: "auto".to_string(),
                    network,
                    path,
                    host,
                    grpc_service_name,
                    tls: tls_config.enabled,
                    skip_cert_verify: tls_config.skip_cert_verify,
                    sni: tls_config.server_name.clone(),
                    alpn: if tls_config.alpn.is_empty() {
                        None
                    } else {
                        Some(tls_config.alpn.clone())
                    },
                    tls_fingerprint: None,
                })
            }
            NodeType::Vless => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("VLESS 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("VLESS 节点缺少端口"))?;

                let uuid = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Uuid { uuid } => uuid.clone(),
                        _ => return Err(anyhow!("VLESS 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("VLESS 节点缺少 UUID"));
                };

                // REALITY/flow 配置保留（G1-6，2026-11-10 拍板改 M1 拒绝策略）：
                // 字段进 EgressConfig::Vless（serde 不再静默丢键）；不支持面
                // 在拨号期点名拒绝（防静默降级），节点级失败不阻塞其余节点。
                let reality = reality_from_json(&node.reality, &node.name)?;

                let (network, path, host, grpc_service_name) =
                    if let Some(transport) = &node.transport {
                        match transport {
                            TransportConfig::Ws {
                                path: ws_path,
                                headers,
                            } => {
                                let host = headers
                                    .as_ref()
                                    .and_then(|h| h.get("Host").cloned())
                                    .or_else(|| node.server.clone())
                                    .map(|h| vec![h]);
                                ("ws".to_string(), Some(ws_path.clone()), host, None)
                            }
                            TransportConfig::Grpc { service_name, .. } => {
                                // gRPC 服务名落专用字段（线上路径 = /{name}/Tun）
                                ("grpc".to_string(), None, None, Some(service_name.clone()))
                            }
                            TransportConfig::Tcp { path: tcp_path, .. } => {
                                ("tcp".to_string(), tcp_path.clone(), None, None)
                            }
                            TransportConfig::H2 {
                                host: h2_host,
                                path: h2_path,
                                ..
                            } => ("h2".to_string(), h2_path.clone(), h2_host.clone(), None),
                            TransportConfig::Quic { .. } => ("quic".to_string(), None, None, None),
                        }
                    } else {
                        ("tcp".to_string(), None, None, None)
                    };

                let tls_config = node
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("VLESS 节点缺少 TLS 配置"))?;

                Ok(EgressConfig::Vless {
                    server,
                    port,
                    uuid,
                    flow: node.flow.clone(),
                    reality,
                    network,
                    path,
                    host,
                    grpc_service_name,
                    // DSL TransportConfig 无 xhttp 载具：本面恒 None（xhttp
                    // 由 clash/IR 面承载，RIL-129）
                    xhttp_mode: None,
                    tls: tls_config.enabled,
                    skip_cert_verify: tls_config.skip_cert_verify,
                    sni: tls_config.server_name.clone(),
                    alpn: if tls_config.alpn.is_empty() {
                        None
                    } else {
                        Some(tls_config.alpn.clone())
                    },
                    tls_fingerprint: None,
                })
            }
            NodeType::Trojan => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("Trojan 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("Trojan 节点缺少端口"))?;

                let password = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Uuid { uuid } => uuid.clone(),
                        _ => return Err(anyhow!("Trojan 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("Trojan 节点缺少密码"));
                };

                let (network, path, host, grpc_service_name) =
                    if let Some(transport) = &node.transport {
                        match transport {
                            TransportConfig::Ws {
                                path: ws_path,
                                headers,
                            } => {
                                let host = headers
                                    .as_ref()
                                    .and_then(|h| h.get("Host").cloned())
                                    .or_else(|| node.server.clone())
                                    .map(|h| vec![h]);
                                ("ws".to_string(), Some(ws_path.clone()), host, None)
                            }
                            TransportConfig::Grpc { service_name, .. } => {
                                // gRPC 服务名落专用字段（线上路径 = /{name}/Tun）
                                ("grpc".to_string(), None, None, Some(service_name.clone()))
                            }
                            TransportConfig::Tcp { path: tcp_path, .. } => {
                                ("tcp".to_string(), tcp_path.clone(), None, None)
                            }
                            _ => ("tcp".to_string(), None, None, None),
                        }
                    } else {
                        ("tcp".to_string(), None, None, None)
                    };

                let tls_config = node
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("Trojan 节点缺少 TLS 配置"))?;

                Ok(EgressConfig::Trojan {
                    server,
                    port,
                    password,
                    network,
                    path,
                    host,
                    grpc_service_name,
                    tls: tls_config.enabled,
                    skip_cert_verify: tls_config.skip_cert_verify,
                    sni: tls_config.server_name.clone(),
                    alpn: if tls_config.alpn.is_empty() {
                        None
                    } else {
                        Some(tls_config.alpn.clone())
                    },
                    tls_fingerprint: None,
                })
            }
            NodeType::Hysteria => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("Hysteria 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("Hysteria 节点缺少端口"))?;

                let password = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Uuid { uuid } => uuid.clone(),
                        _ => return Err(anyhow!("Hysteria 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("Hysteria 节点缺少密码"));
                };

                Ok(EgressConfig::Hysteria {
                    server,
                    port,
                    password,
                    protocol: "udp".to_string(),
                    up_mbps: node.bandwidth_limit,
                    down_mbps: node.bandwidth_limit.map(|bw| bw * 2),
                    auth: None,
                    auth_str: None,
                    obfs: None,
                    obfs_param: None,
                    server_name: node.tls.as_ref().and_then(|t| t.server_name.clone()),
                    skip_cert_verify: node
                        .tls
                        .as_ref()
                        .map(|t| t.skip_cert_verify)
                        .unwrap_or(false),
                    alpn: if node
                        .tls
                        .as_ref()
                        .unwrap_or(&TlsConfig::default())
                        .alpn
                        .is_empty()
                    {
                        None
                    } else {
                        Some(
                            node.tls
                                .as_ref()
                                .unwrap_or(&TlsConfig::default())
                                .alpn
                                .clone(),
                        )
                    },
                })
            }
            NodeType::Hysteria2 => {
                let server = node
                    .server
                    .clone()
                    .ok_or_else(|| anyhow!("Hysteria2 节点缺少服务器地址"))?;
                let port = node.port.ok_or_else(|| anyhow!("Hysteria2 节点缺少端口"))?;

                let password = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Uuid { uuid } => uuid.clone(),
                        _ => return Err(anyhow!("Hysteria2 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("Hysteria2 节点缺少密码"));
                };

                let mport = node
                    .metadata
                    .get("mport")
                    .cloned()
                    .or_else(|| node.metadata.get("ports").cloned());
                let obfs = node.metadata.get("obfs").cloned();
                let obfs_param = node
                    .metadata
                    .get("obfs_param")
                    .cloned()
                    .or_else(|| node.metadata.get("obfs-param").cloned())
                    .or_else(|| node.metadata.get("obfs_password").cloned())
                    .or_else(|| node.metadata.get("obfs-password").cloned());

                Ok(EgressConfig::Hysteria2 {
                    server,
                    port,
                    password,
                    mport,
                    obfs,
                    obfs_param,
                    server_name: node.tls.as_ref().and_then(|t| t.server_name.clone()),
                    skip_cert_verify: node
                        .tls
                        .as_ref()
                        .map(|t| t.skip_cert_verify)
                        .unwrap_or(false),
                    alpn: if node
                        .tls
                        .as_ref()
                        .unwrap_or(&TlsConfig::default())
                        .alpn
                        .is_empty()
                    {
                        None
                    } else {
                        Some(
                            node.tls
                                .as_ref()
                                .unwrap_or(&TlsConfig::default())
                                .alpn
                                .clone(),
                        )
                    },
                })
            }
            NodeType::Wireguard => {
                let private_key = if let Some(auth) = &node.auth {
                    match auth {
                        NodeAuth::Key {
                            method: _,
                            password,
                        } => password.clone(),
                        _ => return Err(anyhow!("WireGuard 节点认证类型错误")),
                    }
                } else {
                    return Err(anyhow!("WireGuard 节点缺少私钥"));
                };

                let endpoint = format!(
                    "{}:{}",
                    node.server.as_deref().unwrap_or("127.0.0.1"),
                    node.port.unwrap_or(51820)
                );

                Ok(EgressConfig::Wireguard {
                    endpoint,
                    private_key,
                    public_key: "unknown".to_string(), // Rillane DSL 暂不提供
                    address: "10.0.0.2/32".to_string(),
                    allowed_ips: None,
                    preshared_key: None,
                    persistent_keepalive: None,
                    listen_port: None,
                    mtu: None,
                    dns: None,
                })
            }
        }
    }

    /// 验证节点是否有效
    pub fn is_valid_node(&self, node: &RillaneNode) -> bool {
        // 检查必需字段
        if node.name.is_empty() {
            return false;
        }

        // 根据节点类型检查特定字段
        match node.node_type {
            NodeType::Direct => true,
            NodeType::Reject => false, // 暂不支持
            NodeType::Socks5
            | NodeType::Http
            | NodeType::Shadowsocks
            | NodeType::Vmess
            | NodeType::Vless
            | NodeType::Trojan
            | NodeType::Hysteria
            | NodeType::Hysteria2
            | NodeType::Wireguard => {
                node.server.is_some() && node.port.is_some() && node.port.unwrap() > 0
            }
        }
    }

    /// 转换策略组
    fn convert_groups_to_policy_groups(&self, groups: &[RillaneGroup]) -> Result<Vec<PolicyGroup>> {
        let mut policy_groups = Vec::new();

        for group in groups {
            let strategy = self.convert_rillane_strategy(group.strategy);
            let members = self.convert_group_member_refs(&group.members);

            policy_groups.push(PolicyGroup {
                name: group.name.clone(),
                strategy,
                members,
                // 订阅不产 SLO 目标（归用户主配置，P1-3/P1-4 同判）
                slo: None,
                // Rillane DSL 组无探测目标字段，url-test 探测目标归主配置
                url_test: None,
            });
        }

        Ok(policy_groups)
    }

    /// 转换 Rillane 策略为标准策略
    fn convert_rillane_strategy(&self, strategy: RillaneStrategy) -> Strategy {
        match strategy {
            RillaneStrategy::Fixed => Strategy::Fixed,
            RillaneStrategy::Random => Strategy::Random,
            RillaneStrategy::Latency => Strategy::Latency,
            RillaneStrategy::Bandwidth => Strategy::Bandwidth,
            RillaneStrategy::Weighted => Strategy::Weighted,
            RillaneStrategy::ConsistentHash => Strategy::ConsistentHash,
            RillaneStrategy::RoundRobin => Strategy::RoundRobin,
        }
    }

    /// 转换组成员引用
    fn convert_group_member_refs(&self, refs: &[GroupMemberRef]) -> Vec<GroupMember> {
        refs.iter()
            .map(|member| match member {
                GroupMemberRef::Node(name) => GroupMember::Node { name: name.clone() },
                GroupMemberRef::WeightedNode { name, weight } => GroupMember::WeightedNode {
                    name: name.clone(),
                    weight: *weight,
                },
                GroupMemberRef::Group(name) => GroupMember::Group { name: name.clone() },
                GroupMemberRef::WeightedGroup { name, weight } => GroupMember::WeightedGroup {
                    name: name.clone(),
                    weight: *weight,
                },
            })
            .collect()
    }

    /// 转换 Rillane 规则
    fn convert_rillane_rule(&self, rule: &RillaneRule) -> Result<(Vec<MatchCondition>, String)> {
        let (matches, target) = match rule {
            RillaneRule::DomainSuffix { domains, target } => {
                let matches = vec![MatchCondition::DomainSuffix {
                    values: domains.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::DomainKeyword { keywords, target } => {
                let matches = vec![MatchCondition::DomainKeyword {
                    values: keywords.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::Domain { domains, target } => {
                let matches = vec![MatchCondition::DomainFull {
                    values: domains.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::DomainRegex { patterns, target } => {
                let matches = vec![MatchCondition::DomainRegex {
                    patterns: patterns.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::IpCidr { cidrs, target } => {
                let matches = vec![MatchCondition::IpCidr {
                    cidrs: cidrs.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::Geoip { country, target } => {
                let matches = vec![MatchCondition::Geoip {
                    country: country.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::GeoSite { category, target } => {
                let matches = vec![MatchCondition::GeoSite {
                    category: category.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::Port { ports, target } => {
                let matches = vec![MatchCondition::Port {
                    values: ports.clone(),
                }];
                (matches, target.clone())
            }
            RillaneRule::Process {
                processes: _,
                target: _,
            } => {
                // Rillane 暂不支持进程名匹配
                warn!(
                    target: "rillane::subscription::rillane_dsl",
                    "跳过进程名规则，Rillane 暂不支持"
                );
                return Err(anyhow!("进程名规则暂不支持"));
            }
            RillaneRule::RuleSet { name: _, target: _ } => {
                // Rillane 暂不支持规则集
                warn!(
                    target: "rillane::subscription::rillane_dsl",
                    "跳过规则集引用，Rillane 暂不支持"
                );
                return Err(anyhow!("规则集引用暂不支持"));
            }
            RillaneRule::Match { target } => {
                let matches = vec![];
                (matches, target.clone())
            }
        };

        Ok((matches, target))
    }

    /// 获取节点类型描述
    pub fn get_node_type_description(node_type: NodeType) -> &'static str {
        match node_type {
            NodeType::Direct => "Direct",
            NodeType::Reject => "Reject",
            NodeType::Socks5 => "SOCKS5",
            NodeType::Http => "HTTP",
            NodeType::Shadowsocks => "Shadowsocks",
            NodeType::Vmess => "VMess",
            NodeType::Vless => "VLESS",
            NodeType::Trojan => "Trojan",
            NodeType::Hysteria => "Hysteria",
            NodeType::Hysteria2 => "Hysteria2",
            NodeType::Wireguard => "WireGuard",
        }
    }

    /// 统计节点类型分布
    pub fn count_node_types(nodes: &[RillaneNode]) -> HashMap<NodeType, usize> {
        let mut counts = HashMap::new();

        for node in nodes {
            *counts.entry(node.node_type).or_insert(0) += 1;
        }

        counts
    }
}

impl Default for RillaneDslConverter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rillane_config_parsing() {
        let yaml_content = r#"
version: "1.0"
meta:
  name: "Test Config"
  description: "A test configuration"

nodes:
  - name: "direct"
    type: direct
  - name: "test-ss"
    type: shadowsocks
    server: example.com
    port: 8388
    auth:
      type: key
      method: aes-256-gcm
      password: password

groups:
  - name: "auto"
    strategy: latency
    members:
      - direct
      - test-ss
    health_check_interval: 30
    fallback_enabled: true

rules:
  - type: geoip
    country: CN
    target: direct
  - type: domain-suffix
    domains:
      - google.com
      - youtube.com
    target: auto
  - type: match
    target: auto
        "#;

        let converter = RillaneDslConverter::new();
        let rillane_config = converter.parse(yaml_content).unwrap();

        assert_eq!(rillane_config.version, RillaneVersion::V1_0);
        assert_eq!(rillane_config.nodes.len(), 2);
        assert_eq!(rillane_config.groups.len(), 1);
        assert_eq!(rillane_config.rules.len(), 3);

        let direct_node = &rillane_config.nodes[0];
        assert_eq!(direct_node.name, "direct");
        assert_eq!(direct_node.node_type, NodeType::Direct);

        let ss_node = &rillane_config.nodes[1];
        assert_eq!(ss_node.name, "test-ss");
        assert_eq!(ss_node.node_type, NodeType::Shadowsocks);

        let auto_group = &rillane_config.groups[0];
        assert_eq!(auto_group.name, "auto");
        assert_eq!(auto_group.strategy, RillaneStrategy::Latency);
        assert_eq!(auto_group.members.len(), 2);
    }

    #[test]
    fn test_node_validation() {
        let converter = RillaneDslConverter::new();

        let valid_node = RillaneNode {
            name: "test".to_string(),
            node_type: NodeType::Direct,
            server: None,
            port: None,
            auth: None,
            transport: None,
            tls: None,
            bandwidth_limit: None,
            location: None,
            tags: vec![],
            metadata: HashMap::new(),
            flow: None,
            reality: None,
        };
        assert!(converter.is_valid_node(&valid_node));

        let invalid_node = RillaneNode {
            name: "".to_string(),
            node_type: NodeType::Direct,
            server: None,
            port: None,
            auth: None,
            transport: None,
            tls: None,
            bandwidth_limit: None,
            location: None,
            tags: vec![],
            metadata: HashMap::new(),
            flow: None,
            reality: None,
        };
        assert!(!converter.is_valid_node(&invalid_node));
    }

    #[test]
    fn test_strategy_conversion() {
        let converter = RillaneDslConverter::new();

        assert_eq!(
            converter.convert_rillane_strategy(RillaneStrategy::Latency),
            Strategy::Latency
        );
        assert_eq!(
            converter.convert_rillane_strategy(RillaneStrategy::Random),
            Strategy::Random
        );
        assert_eq!(
            converter.convert_rillane_strategy(RillaneStrategy::Weighted),
            Strategy::Weighted
        );
    }

    #[test]
    fn test_node_type_counting() {
        let nodes = vec![
            RillaneNode {
                name: "direct1".to_string(),
                node_type: NodeType::Direct,
                server: None,
                port: None,
                auth: None,
                transport: None,
                tls: None,
                bandwidth_limit: None,
                location: None,
                tags: vec![],
                metadata: HashMap::new(),
                flow: None,
                reality: None,
            },
            RillaneNode {
                name: "direct2".to_string(),
                node_type: NodeType::Direct,
                server: None,
                port: None,
                auth: None,
                transport: None,
                tls: None,
                bandwidth_limit: None,
                location: None,
                tags: vec![],
                metadata: HashMap::new(),
                flow: None,
                reality: None,
            },
            RillaneNode {
                name: "ss1".to_string(),
                node_type: NodeType::Shadowsocks,
                server: Some("example.com".to_string()),
                port: Some(8388),
                auth: None,
                transport: None,
                tls: None,
                bandwidth_limit: None,
                location: None,
                tags: vec![],
                metadata: HashMap::new(),
                flow: None,
                reality: None,
            },
        ];

        let counts = RillaneDslConverter::count_node_types(&nodes);
        assert_eq!(counts.get(&NodeType::Direct), Some(&2));
        assert_eq!(counts.get(&NodeType::Shadowsocks), Some(&1));
        assert_eq!(counts.get(&NodeType::Vmess), None);
    }

    #[test]
    fn test_hysteria2_metadata_mapping_to_egress() {
        let yaml_content = r#"
version: "1.0"
meta:
  name: "Test Config"

nodes:
  - name: "hy2"
    type: hysteria2
    server: example.net
    port: 443
    auth:
      type: uuid
      value: secret
    metadata:
      mport: "35000-39000"

groups: []
rules: []
default_target: hy2
rulesets: []
        "#;

        let converter = RillaneDslConverter::new();
        let rillane_dsl = converter.parse(yaml_content).unwrap();
        let rillane_config = converter.convert_to_rillane(&rillane_dsl).unwrap();
        assert!(
            rillane_config.control.admin_token.is_none(),
            "订阅转换不得生成硬编码 admin_token"
        );

        let hy2 = rillane_config
            .egress
            .iter()
            .find(|e| e.name == "hy2")
            .expect("hy2 egress");

        match &hy2.spec {
            rillane_config::EgressConfig::Hysteria2 { mport, .. } => {
                assert_eq!(mport.as_deref(), Some("35000-39000"));
            }
            other => panic!("unexpected egress config: {:?}", other),
        }
    }

    /// G1-6 REALITY/flow 配置保留（Rillane DSL 面，与 clash 面同口径；拍板改
    /// M1 拒绝策略——转换成功且字段保留，拨号期才点名拒绝）。
    #[test]
    fn test_vless_reality_and_flow_nodes_preserved_on_convert() {
        let converter = RillaneDslConverter::new();
        let base = || RillaneNode {
            name: "vl".to_string(),
            node_type: NodeType::Vless,
            server: Some("127.0.0.1".to_string()),
            port: Some(443),
            auth: Some(NodeAuth::Uuid {
                uuid: "b831381d-6324-4d2a-b1e7-1bf75a1db7b3".to_string(),
            }),
            transport: None,
            tls: Some(TlsConfig {
                enabled: true,
                ..Default::default()
            }),
            bandwidth_limit: None,
            location: None,
            tags: vec![],
            metadata: HashMap::new(),
            flow: None,
            reality: None,
        };

        // REALITY
        let mut reality = base();
        reality.name = "vl-reality".to_string();
        reality.reality = Some(serde_json::json!({
            "public-key": "PBQh7j2tWxQmZHVub3RUYXJnZXQ",
            "short-id": "0123ac"
        }));
        // G1-6（拍板改 M1 拒绝策略）：转换不再拒绝，reality 字段完整保留
        //（serde 不静默丢键）；缺 public-key 仍点名报错
        let ok = converter
            .convert_node_to_egress_config(&reality)
            .expect("REALITY 节点应转换成功（配置保留）");
        match ok {
            EgressConfig::Vless { reality, .. } => {
                let r = reality.expect("reality 应保留");
                assert_eq!(r.public_key, "PBQh7j2tWxQmZHVub3RUYXJnZXQ");
                assert_eq!(r.short_id.as_deref(), Some("0123ac"));
            }
            other => panic!("应为 Vless: {other:?}"),
        }

        // reality-opts 缺 public-key → 转换期点名报错
        let mut bad = base();
        bad.name = "vl-reality".to_string();
        bad.reality = Some(serde_json::json!({ "short-id": "0123ac" }));
        let err = converter.convert_node_to_egress_config(&bad).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("public-key") && msg.contains("vl-reality"),
            "应点名缺 public-key 与节点名: {msg}"
        );

        // flow（XTLS-Vision 等流控）
        let mut flow = base();
        flow.name = "vl-vision".to_string();
        flow.flow = Some("xtls-rprx-vision".to_string());
        let ok = converter
            .convert_node_to_egress_config(&flow)
            .expect("flow 节点应转换成功（配置保留）");
        match ok {
            EgressConfig::Vless { flow, .. } => {
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            }
            other => panic!("应为 Vless: {other:?}"),
        }

        // 普通 VLESS 不受影响
        let ok = converter.convert_node_to_egress_config(&base()).unwrap();
        assert!(matches!(ok, EgressConfig::Vless { .. }));
    }

    /// G1-6 字段捕获：DSL `flow:` 与 `reality-opts:`（含下划线别名）须真的
    /// 进字段而非被 serde 静默丢弃——否则拒绝逻辑根本不会触发。
    #[test]
    fn test_rillane_node_captures_reality_and_flow_keys() {
        let node: RillaneNode = serde_yaml::from_str(
            r#"
name: vl
type: vless
server: 127.0.0.1
port: 443
auth:
  type: uuid
  value: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
tls:
  enabled: true
flow: xtls-rprx-vision
reality-opts:
  public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ
  short-id: "0123ac"
        "#,
        )
        .unwrap();
        assert_eq!(node.flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(node.reality.is_some(), "reality-opts 应被捕获");

        let node: RillaneNode = serde_yaml::from_str(
            r#"
name: vl
type: vless
server: 127.0.0.1
port: 443
auth:
  type: uuid
  value: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
tls:
  enabled: true
reality_opts:
  public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ
        "#,
        )
        .unwrap();
        assert!(node.reality.is_some(), "reality_opts 下划线别名应被捕获");
    }
}
