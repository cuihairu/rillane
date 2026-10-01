//! Seep DSL 订阅处理

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use seep_config::{
    EgressConfig, EgressDescriptor, GroupMember, MatchCondition, PolicyGroup, RouteRule,
    RoutingConfig, Strategy,
};

/// Seep DSL 版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeepVersion {
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
pub struct SeepNode {
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
pub enum SeepStrategy {
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
pub struct SeepGroup {
    /// 组名称
    pub name: String,
    /// 策略类型
    pub strategy: SeepStrategy,
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
pub struct SeepRuleSet {
    /// 规则集名称
    pub name: String,
    /// 规则列表
    pub rules: Vec<SeepRule>,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Seep 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SeepRule {
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
    /// IP CIDR
    IpCidr { cidrs: Vec<String>, target: String },
    /// GeoIP
    Geoip { country: String, target: String },
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

/// Seep 配置根结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeepConfig {
    /// 配置版本
    pub version: SeepVersion,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub meta: HashMap<String, String>,
    /// 节点列表
    pub nodes: Vec<SeepNode>,
    /// 策略组列表
    pub groups: Vec<SeepGroup>,
    /// 规则集列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rulesets: Vec<SeepRuleSet>,
    /// 规则列表
    pub rules: Vec<SeepRule>,
    /// 默认目标
    #[serde(default = "default_target")]
    pub default_target: String,
}

fn default_target() -> String {
    "direct".to_string()
}

/// Seep DSL 转换器
pub struct SeepDslConverter {
    /// 是否验证配置
    validate: bool,
    /// 是否过滤无效节点
    filter_invalid_nodes: bool,
}

impl SeepDslConverter {
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

    /// 解析 Seep DSL 配置
    pub fn parse(&self, content: &str) -> Result<SeepConfig> {
        debug!(
            target: "seep::subscription::seep_dsl",
            "开始解析 Seep DSL 配置"
        );

        let config: SeepConfig = serde_yaml::from_str(content).context("解析 Seep DSL 配置失败")?;

        if self.validate {
            self.validate_config(&config)?;
        }

        debug!(
            target: "seep::subscription::seep_dsl",
            version = ?config.version,
            nodes = config.nodes.len(),
            groups = config.groups.len(),
            rulesets = config.rulesets.len(),
            rules = config.rules.len(),
            "Seep DSL 配置解析完成"
        );

        Ok(config)
    }

    /// 转换为标准 Seep 配置
    pub fn convert_to_seep(&self, seep_config: &SeepConfig) -> Result<seep_config::SeepConfig> {
        debug!(
            target: "seep::subscription::seep_dsl",
            "开始转换为标准 Seep 配置"
        );

        // 转换节点为出口节点
        let egress = self.convert_nodes_to_egress(&seep_config.nodes)?;

        // 转换策略组
        let groups = self.convert_groups_to_policy_groups(&seep_config.groups)?;

        // 转换规则集为规则
        let mut rules = Vec::new();

        // 首先处理规则集
        for ruleset in &seep_config.rulesets {
            for (index, rule) in ruleset.rules.iter().enumerate() {
                let name = format!("{}-rule-{}", ruleset.name, index + 1);
                let (matches, target) = self.convert_seep_rule(rule)?;
                rules.push(RouteRule {
                    name,
                    matches,
                    target,
                });
            }
        }

        // 然后处理直接规则
        for (index, rule) in seep_config.rules.iter().enumerate() {
            let name = format!("rule-{}", index + 1);
            let (matches, target) = self.convert_seep_rule(rule)?;
            rules.push(RouteRule {
                name,
                matches,
                target,
            });
        }

        let routing = RoutingConfig {
            default_node: seep_config.default_target.clone(),
            groups,
            rules,
        };

        let config = seep_config::SeepConfig {
            control: seep_config::ControlConfig {
                api_bind: "127.0.0.1:9090".to_string(),
                uds_path: None,
                admin_token: Some("seep".to_string()),
            },
            telemetry: seep_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: true,
                enable_tracing: false,
            },
            ingress: vec![], // Seep DSL 不包含入口配置
            egress,
            routing,
            udp: seep_config::UdpConfig::default(),
            // 订阅转换不产网络虚拟化块（P1-3 归用户主配置）
            network: None,
            // 订阅转换不产混淆块（P1-4 归用户主配置）
            obfuscation: None,
            profile: None,
            egress_pool: None,
        };

        debug!(
            target: "seep::subscription::seep_dsl",
            egress = config.egress.len(),
            groups = config.routing.groups.len(),
            rules = config.routing.rules.len(),
            "标准 Seep 配置转换完成"
        );

        Ok(config)
    }

    /// 验证配置
    fn validate_config(&self, config: &SeepConfig) -> Result<()> {
        // 检查版本
        match config.version {
            SeepVersion::V1_0 | SeepVersion::V1_1 => {
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
    fn validate_references(&self, config: &SeepConfig) -> Result<()> {
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
            if let SeepRule::RuleSet { name, .. } = rule {
                if !ruleset_names.contains(name.as_str()) {
                    return Err(anyhow!("规则引用了不存在的规则集: {}", name));
                }
            }
        }

        // 检查规则集规则引用
        for ruleset in &config.rulesets {
            for rule in &ruleset.rules {
                if let SeepRule::RuleSet { name, .. } = rule {
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
    fn convert_nodes_to_egress(&self, nodes: &[SeepNode]) -> Result<Vec<EgressDescriptor>> {
        let mut egress = Vec::new();

        for node in nodes {
            if self.filter_invalid_nodes && !self.is_valid_node(node) {
                warn!(
                    target: "seep::subscription::seep_dsl",
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
    fn convert_node_to_egress_config(&self, node: &SeepNode) -> Result<EgressConfig> {
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

                let (network, path, host) = if let Some(transport) = &node.transport {
                    match transport {
                        TransportConfig::Tcp { path: tcp_path, .. } => {
                            ("tcp".to_string(), tcp_path.clone(), None)
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
                            ("ws".to_string(), Some(ws_path.clone()), host)
                        }
                        TransportConfig::Grpc { service_name, .. } => {
                            ("grpc".to_string(), Some(service_name.clone()), None)
                        }
                        TransportConfig::H2 {
                            host: h2_host,
                            path: h2_path,
                            ..
                        } => ("h2".to_string(), h2_path.clone(), h2_host.clone()),
                        TransportConfig::Quic { .. } => ("quic".to_string(), None, None),
                    }
                } else {
                    ("tcp".to_string(), None, None)
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

                let (network, path, host) = if let Some(transport) = &node.transport {
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
                            ("ws".to_string(), Some(ws_path.clone()), host)
                        }
                        TransportConfig::Grpc { service_name, .. } => {
                            ("grpc".to_string(), Some(service_name.clone()), None)
                        }
                        TransportConfig::Tcp { path: tcp_path, .. } => {
                            ("tcp".to_string(), tcp_path.clone(), None)
                        }
                        TransportConfig::H2 {
                            host: h2_host,
                            path: h2_path,
                            ..
                        } => ("h2".to_string(), h2_path.clone(), h2_host.clone()),
                        TransportConfig::Quic { .. } => ("quic".to_string(), None, None),
                    }
                } else {
                    ("tcp".to_string(), None, None)
                };

                let tls_config = node
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("VLESS 节点缺少 TLS 配置"))?;

                Ok(EgressConfig::Vless {
                    server,
                    port,
                    uuid,
                    flow: None,
                    network,
                    path,
                    host,
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

                let (network, path, host) = if let Some(transport) = &node.transport {
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
                            ("ws".to_string(), Some(ws_path.clone()), host)
                        }
                        TransportConfig::Grpc { service_name, .. } => {
                            ("grpc".to_string(), Some(service_name.clone()), None)
                        }
                        TransportConfig::Tcp { path: tcp_path, .. } => {
                            ("tcp".to_string(), tcp_path.clone(), None)
                        }
                        _ => ("tcp".to_string(), None, None),
                    }
                } else {
                    ("tcp".to_string(), None, None)
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
                    public_key: "unknown".to_string(), // Seep DSL 暂不提供
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
    pub fn is_valid_node(&self, node: &SeepNode) -> bool {
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
    fn convert_groups_to_policy_groups(&self, groups: &[SeepGroup]) -> Result<Vec<PolicyGroup>> {
        let mut policy_groups = Vec::new();

        for group in groups {
            let strategy = self.convert_seep_strategy(group.strategy);
            let members = self.convert_group_member_refs(&group.members);

            policy_groups.push(PolicyGroup {
                name: group.name.clone(),
                strategy,
                members,
                // 订阅不产 SLO 目标（归用户主配置，P1-3/P1-4 同判）
                slo: None,
            });
        }

        Ok(policy_groups)
    }

    /// 转换 Seep 策略为标准策略
    fn convert_seep_strategy(&self, strategy: SeepStrategy) -> Strategy {
        match strategy {
            SeepStrategy::Fixed => Strategy::Fixed,
            SeepStrategy::Random => Strategy::Random,
            SeepStrategy::Latency => Strategy::Latency,
            SeepStrategy::Bandwidth => Strategy::Bandwidth,
            SeepStrategy::Weighted => Strategy::Weighted,
            SeepStrategy::ConsistentHash => Strategy::ConsistentHash,
            SeepStrategy::RoundRobin => Strategy::RoundRobin,
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

    /// 转换 Seep 规则
    fn convert_seep_rule(&self, rule: &SeepRule) -> Result<(Vec<MatchCondition>, String)> {
        let (matches, target) = match rule {
            SeepRule::DomainSuffix { domains, target } => {
                let matches = vec![MatchCondition::DomainSuffix {
                    values: domains.clone(),
                }];
                (matches, target.clone())
            }
            SeepRule::DomainKeyword { keywords, target } => {
                let matches = vec![MatchCondition::DomainKeyword {
                    values: keywords.clone(),
                }];
                (matches, target.clone())
            }
            SeepRule::Domain { domains, target } => {
                // Seep 暂不支持完全域名匹配，转换为后缀匹配
                let matches = vec![MatchCondition::DomainSuffix {
                    values: domains.clone(),
                }];
                (matches, target.clone())
            }
            SeepRule::IpCidr { cidrs, target } => {
                let matches = vec![MatchCondition::Network {
                    cidrs: cidrs.clone(),
                }];
                (matches, target.clone())
            }
            SeepRule::Geoip { country, target } => {
                let matches = vec![MatchCondition::Geoip {
                    country: country.clone(),
                }];
                (matches, target.clone())
            }
            SeepRule::Port { ports, target } => {
                let matches = vec![MatchCondition::Port {
                    values: ports.clone(),
                }];
                (matches, target.clone())
            }
            SeepRule::Process {
                processes: _,
                target: _,
            } => {
                // Seep 暂不支持进程名匹配
                warn!(
                    target: "seep::subscription::seep_dsl",
                    "跳过进程名规则，Seep 暂不支持"
                );
                return Err(anyhow!("进程名规则暂不支持"));
            }
            SeepRule::RuleSet { name: _, target: _ } => {
                // Seep 暂不支持规则集
                warn!(
                    target: "seep::subscription::seep_dsl",
                    "跳过规则集引用，Seep 暂不支持"
                );
                return Err(anyhow!("规则集引用暂不支持"));
            }
            SeepRule::Match { target } => {
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
    pub fn count_node_types(nodes: &[SeepNode]) -> HashMap<NodeType, usize> {
        let mut counts = HashMap::new();

        for node in nodes {
            *counts.entry(node.node_type).or_insert(0) += 1;
        }

        counts
    }
}

impl Default for SeepDslConverter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seep_config_parsing() {
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

        let converter = SeepDslConverter::new();
        let seep_config = converter.parse(yaml_content).unwrap();

        assert_eq!(seep_config.version, SeepVersion::V1_0);
        assert_eq!(seep_config.nodes.len(), 2);
        assert_eq!(seep_config.groups.len(), 1);
        assert_eq!(seep_config.rules.len(), 3);

        let direct_node = &seep_config.nodes[0];
        assert_eq!(direct_node.name, "direct");
        assert_eq!(direct_node.node_type, NodeType::Direct);

        let ss_node = &seep_config.nodes[1];
        assert_eq!(ss_node.name, "test-ss");
        assert_eq!(ss_node.node_type, NodeType::Shadowsocks);

        let auto_group = &seep_config.groups[0];
        assert_eq!(auto_group.name, "auto");
        assert_eq!(auto_group.strategy, SeepStrategy::Latency);
        assert_eq!(auto_group.members.len(), 2);
    }

    #[test]
    fn test_node_validation() {
        let converter = SeepDslConverter::new();

        let valid_node = SeepNode {
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
        };
        assert!(converter.is_valid_node(&valid_node));

        let invalid_node = SeepNode {
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
        };
        assert!(!converter.is_valid_node(&invalid_node));
    }

    #[test]
    fn test_strategy_conversion() {
        let converter = SeepDslConverter::new();

        assert_eq!(
            converter.convert_seep_strategy(SeepStrategy::Latency),
            Strategy::Latency
        );
        assert_eq!(
            converter.convert_seep_strategy(SeepStrategy::Random),
            Strategy::Random
        );
        assert_eq!(
            converter.convert_seep_strategy(SeepStrategy::Weighted),
            Strategy::Weighted
        );
    }

    #[test]
    fn test_node_type_counting() {
        let nodes = vec![
            SeepNode {
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
            },
            SeepNode {
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
            },
            SeepNode {
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
            },
        ];

        let counts = SeepDslConverter::count_node_types(&nodes);
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

        let converter = SeepDslConverter::new();
        let seep_dsl = converter.parse(yaml_content).unwrap();
        let seep_config = converter.convert_to_seep(&seep_dsl).unwrap();

        let hy2 = seep_config
            .egress
            .iter()
            .find(|e| e.name == "hy2")
            .expect("hy2 egress");

        match &hy2.spec {
            seep_config::EgressConfig::Hysteria2 { mport, .. } => {
                assert_eq!(mport.as_deref(), Some("35000-39000"));
            }
            other => panic!("unexpected egress config: {:?}", other),
        }
    }
}
