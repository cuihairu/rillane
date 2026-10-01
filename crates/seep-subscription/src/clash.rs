//! Clash 配置订阅处理

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{de, Deserialize, Serialize};
use serde_with::serde_as;
use serde_yaml::Value;
use tracing::{debug, warn};

use seep_config::{
    EgressConfig, EgressDescriptor, GroupMember, MatchCondition, PolicyGroup, RouteRule,
    RoutingConfig, Strategy,
};

/// Clash 代理类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClashProxyType {
    Ss,
    Vmess,
    Vless,
    Trojan,
    Http,
    Https,
    #[serde(rename = "socks5")]
    Socks5,
    Snell,
    Hysteria,
    Hysteria2,
    Wireguard,
}

impl Default for ClashProxyType {
    fn default() -> Self {
        Self::Ss
    }
}

/// Clash 代理服务器配置
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashProxy {
    /// 代理名称
    pub name: String,
    /// 代理类型
    #[serde(rename = "type")]
    pub proxy_type: ClashProxyType,
    /// 服务器地址
    pub server: String,
    /// 服务器端口
    pub port: u16,
    /// 用户名（用于 HTTP/HTTPS）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// 密码
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Hysteria2: 端口跳跃范围（常见字段名为 ports，也可能叫 mport）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "ports",
        alias = "ports-range",
        alias = "port-range"
    )]
    pub mport: Option<String>,
    /// Hysteria2: obfs 类型（例如 salamander）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    /// Hysteria2: obfs 参数（例如密码）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "obfs-param",
        alias = "obfs_param",
        alias = "obfs-password",
        alias = "obfs_password"
    )]
    pub obfs_param: Option<String>,
    /// 加密方法（用于 Shadowsocks）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    /// UUID（用于 VMess/VLESS）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// 加密（用于 VMess）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypt: Option<String>,
    /// 传输协议
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// 伪装类型
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    /// 路径
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 主机
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// TLS
    #[serde(default)]
    pub tls: bool,
    /// Skip-cert-verify
    #[serde(default)]
    pub skip_cert_verify: bool,
    /// Alpn
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// Servername
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    /// Fingerprint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Private key (for WireGuard)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Public key (for WireGuard)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Pre-shared key (for WireGuard)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "preshared-key",
        alias = "preshared_key",
        alias = "pre-shared-key",
        alias = "pre_shared_key"
    )]
    pub preshared_key: Option<String>,
    /// Persistent keepalive (seconds)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "keepalive",
        alias = "persistent-keepalive",
        alias = "persistent_keepalive"
    )]
    pub persistent_keepalive: Option<u16>,
    /// WireGuard client IP(s) (Clash commonly uses `ip` and `ipv6`)
    #[serde_as(as = "Option<serde_with::OneOrMany<_>>")]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "ip",
        alias = "address"
    )]
    pub ip: Option<Vec<String>>,
    #[serde_as(as = "Option<serde_with::OneOrMany<_>>")]
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "ipv6")]
    pub ipv6: Option<Vec<String>>,
    /// Allowed IPs (for WireGuard peer routing)
    #[serde_as(as = "Option<serde_with::OneOrMany<_>>")]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "allowed-ips",
        alias = "allowed_ips",
        alias = "allowedips"
    )]
    pub allowed_ips: Option<Vec<String>>,
    /// DNS servers (WireGuard)
    #[serde_as(as = "Option<serde_with::OneOrMany<_>>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    /// MTU (WireGuard)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

/// Clash 代理组类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClashProxyGroupType {
    Select,
    // Clash commonly uses `url-test` / `load-balance` (with dashes).
    // Keep aliases for compatibility with older "urltest"/"loadbalance" spellings.
    #[serde(rename = "url-test", alias = "urltest")]
    UrlTest,
    Fallback,
    #[serde(rename = "load-balance", alias = "loadbalance")]
    LoadBalance,
    Relay,
}

/// Clash 代理组配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashProxyGroup {
    /// 代理组名称
    pub name: String,
    /// 代理组类型
    #[serde(rename = "type")]
    pub group_type: ClashProxyGroupType,
    /// 代理列表
    pub proxies: Vec<String>,
    /// URL 测试地址（用于 url-test）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 测试间隔（毫秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// 负载均衡策略
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

/// Clash 规则
#[derive(Debug, Clone, Serialize)]
pub enum ClashRule {
    /// 域名后缀
    DomainSuffix {
        #[serde(rename = "domain-suffix")]
        domains: Vec<String>,
        target: String,
    },
    /// 域名关键字
    DomainKeyword {
        #[serde(rename = "domain-keyword")]
        keywords: Vec<String>,
        target: String,
    },
    /// 域名完全匹配
    Domain {
        domains: Vec<String>,
        target: String,
    },
    /// IP CIDR
    IpCidr {
        #[serde(rename = "ip-cidr")]
        cidrs: Vec<String>,
        target: String,
    },
    /// GeoIP
    Geoip {
        country_code: String,
        target: String,
    },
    /// GeoSite
    Geosite {
        country_code: String,
        target: String,
    },
    /// 端口范围
    SrcPort {
        #[serde(rename = "src-port")]
        ports: Vec<u16>,
        target: String,
    },
    /// 目标端口
    DstPort {
        #[serde(rename = "dst-port")]
        ports: Vec<u16>,
        target: String,
    },
    /// 进程名
    ProcessName {
        #[serde(rename = "process-name")]
        processes: Vec<String>,
        target: String,
    },
    /// 规则集
    RuleSet {
        #[serde(rename = "rule-set")]
        rulesets: Vec<String>,
        target: String,
    },
    /// MATCH（默认规则）
    Match { target: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ClashRuleTagged {
    DomainSuffix {
        #[serde(rename = "domain-suffix")]
        domains: Vec<String>,
        target: String,
    },
    DomainKeyword {
        #[serde(rename = "domain-keyword")]
        keywords: Vec<String>,
        target: String,
    },
    Domain {
        domains: Vec<String>,
        target: String,
    },
    IpCidr {
        #[serde(rename = "ip-cidr")]
        cidrs: Vec<String>,
        target: String,
    },
    Geoip {
        country_code: String,
        target: String,
    },
    Geosite {
        country_code: String,
        target: String,
    },
    SrcPort {
        #[serde(rename = "src-port")]
        ports: Vec<u16>,
        target: String,
    },
    DstPort {
        #[serde(rename = "dst-port")]
        ports: Vec<u16>,
        target: String,
    },
    ProcessName {
        #[serde(rename = "process-name")]
        processes: Vec<String>,
        target: String,
    },
    RuleSet {
        #[serde(rename = "rule-set")]
        rulesets: Vec<String>,
        target: String,
    },
    Match {
        target: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ClashRuleRepr {
    String(String),
    Tagged(ClashRuleTagged),
}

impl From<ClashRuleTagged> for ClashRule {
    fn from(v: ClashRuleTagged) -> Self {
        match v {
            ClashRuleTagged::DomainSuffix { domains, target } => {
                ClashRule::DomainSuffix { domains, target }
            }
            ClashRuleTagged::DomainKeyword { keywords, target } => {
                ClashRule::DomainKeyword { keywords, target }
            }
            ClashRuleTagged::Domain { domains, target } => ClashRule::Domain { domains, target },
            ClashRuleTagged::IpCidr { cidrs, target } => ClashRule::IpCidr { cidrs, target },
            ClashRuleTagged::Geoip {
                country_code,
                target,
            } => ClashRule::Geoip {
                country_code,
                target,
            },
            ClashRuleTagged::Geosite {
                country_code,
                target,
            } => ClashRule::Geosite {
                country_code,
                target,
            },
            ClashRuleTagged::SrcPort { ports, target } => ClashRule::SrcPort { ports, target },
            ClashRuleTagged::DstPort { ports, target } => ClashRule::DstPort { ports, target },
            ClashRuleTagged::ProcessName { processes, target } => {
                ClashRule::ProcessName { processes, target }
            }
            ClashRuleTagged::RuleSet { rulesets, target } => {
                ClashRule::RuleSet { rulesets, target }
            }
            ClashRuleTagged::Match { target } => ClashRule::Match { target },
        }
    }
}

impl ClashRule {
    fn parse_rule_string(s: &str) -> Result<Self, String> {
        let raw = s.trim();
        if raw.is_empty() {
            return Err("empty rule".into());
        }
        let parts: Vec<&str> = raw
            .split(',')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        if parts.is_empty() {
            return Err("empty rule".into());
        }

        let kind = parts[0].to_ascii_uppercase();
        let get = |idx: usize| {
            parts
                .get(idx)
                .copied()
                .ok_or_else(|| format!("invalid rule: {raw}"))
        };

        fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
            let s = s.trim();
            if s.is_empty() {
                return Err("empty port".into());
            }
            if let Some((a, b)) = s.split_once('-') {
                let start: u16 = a
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port range: {s}"))?;
                let end: u16 = b
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port range: {s}"))?;
                if start > end {
                    return Err(format!("invalid port range: {s}"));
                }
                let span = (end - start) as usize;
                if span > 4096 {
                    return Err(format!("port range too large: {s}"));
                }
                return Ok((start..=end).collect());
            }
            let p: u16 = s.parse().map_err(|_| format!("invalid port: {s}"))?;
            Ok(vec![p])
        }

        match kind.as_str() {
            "DOMAIN-SUFFIX" => Ok(ClashRule::DomainSuffix {
                domains: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(ClashRule::DomainKeyword {
                keywords: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "DOMAIN" => Ok(ClashRule::Domain {
                domains: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(ClashRule::IpCidr {
                cidrs: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "GEOIP" => Ok(ClashRule::Geoip {
                country_code: get(1)?.to_string(),
                target: get(2)?.to_string(),
            }),
            "GEOSITE" => Ok(ClashRule::Geosite {
                country_code: get(1)?.to_string(),
                target: get(2)?.to_string(),
            }),
            "SRC-PORT" => Ok(ClashRule::SrcPort {
                ports: parse_ports(get(1)?)?,
                target: get(2)?.to_string(),
            }),
            "DST-PORT" => Ok(ClashRule::DstPort {
                ports: parse_ports(get(1)?)?,
                target: get(2)?.to_string(),
            }),
            "PROCESS-NAME" => Ok(ClashRule::ProcessName {
                processes: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "RULE-SET" => Ok(ClashRule::RuleSet {
                rulesets: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "MATCH" => Ok(ClashRule::Match {
                target: get(1)?.to_string(),
            }),
            _ => Err(format!("unsupported rule type: {}", parts[0])),
        }
    }
}

impl<'de> Deserialize<'de> for ClashRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let repr = ClashRuleRepr::deserialize(deserializer)?;
        match repr {
            ClashRuleRepr::Tagged(v) => Ok(v.into()),
            ClashRuleRepr::String(s) => ClashRule::parse_rule_string(&s).map_err(de::Error::custom),
        }
    }
}

/// Clash 配置根结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashConfig {
    /// 代理列表
    pub proxies: Vec<ClashProxy>,
    /// 代理组列表
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Vec<ClashProxyGroup>,
    /// 规则列表
    pub rules: Vec<ClashRule>,
    /// DNS 配置
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,
    /// 混合端口
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
    /// 允许局域网
    #[serde(default)]
    #[serde(rename = "allow-lan")]
    pub allow_lan: bool,
    /// 绑定地址
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 外部控制器
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "external-controller")]
    pub external_controller: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Clash 配置转换器
pub struct ClashConverter {
    /// 节点名称前缀
    node_prefix: String,
    /// 组名称前缀
    group_prefix: String,
    /// 规则名称前缀
    rule_prefix: String,
    /// 是否过滤无效节点
    filter_invalid_nodes: bool,
}

impl ClashConverter {
    /// 创建新的转换器
    pub fn new() -> Self {
        Self {
            node_prefix: String::new(),
            group_prefix: String::new(),
            rule_prefix: String::new(),
            filter_invalid_nodes: true,
        }
    }

    /// 设置节点名称前缀
    pub fn with_node_prefix(mut self, prefix: String) -> Self {
        self.node_prefix = prefix;
        self
    }

    /// 设置组名称前缀
    pub fn with_group_prefix(mut self, prefix: String) -> Self {
        self.group_prefix = prefix;
        self
    }

    /// 设置规则名称前缀
    pub fn with_rule_prefix(mut self, prefix: String) -> Self {
        self.rule_prefix = prefix;
        self
    }

    /// 设置是否过滤无效节点
    pub fn with_filtering(mut self, filter: bool) -> Self {
        self.filter_invalid_nodes = filter;
        self
    }

    /// 解析 Clash 配置
    pub fn parse(&self, content: &str) -> Result<ClashConfig> {
        debug!(
            target: "seep::subscription::clash",
            "开始解析 Clash 配置"
        );

        let config: ClashConfig =
            serde_yaml::from_str(content).context("解析 Clash YAML 配置失败")?;

        debug!(
            target: "seep::subscription::clash",
            proxies = config.proxies.len(),
            groups = config.proxy_groups.len(),
            rules = config.rules.len(),
            "Clash 配置解析完成"
        );

        Ok(config)
    }

    /// 转换为 Seep 配置
    pub fn convert_to_seep(&self, clash_config: &ClashConfig) -> Result<seep_config::SeepConfig> {
        debug!(
            target: "seep::subscription::clash",
            "开始转换为 Seep 配置"
        );

        // 转换代理为出口节点
        let egress = self.convert_proxies_to_egress(&clash_config.proxies)?;

        // 转换代理组为策略组
        let groups = self.convert_proxy_groups_to_groups(&clash_config.proxy_groups)?;

        // 转换规则为路由规则
        let rules = self.convert_rules_to_routing_rules(&clash_config.rules)?;

        // 创建默认节点
        let default_node = egress
            .first()
            .map(|e| e.name.clone())
            .unwrap_or_else(|| "direct".to_string());

        let routing = RoutingConfig {
            default_node,
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
                log_level: clash_config.log_level.clone(),
                enable_metrics: true,
                enable_tracing: false,
            },
            ingress: vec![], // Clash 配置不包含入口配置
            egress,
            routing,
            udp: seep_config::UdpConfig::default(),
            // 订阅转换不产网络虚拟化块（P1-3 归用户主配置）
            network: None,
            // 订阅转换不产混淆块（P1-4 归用户主配置）
            obfuscation: None,
        };

        debug!(
            target: "seep::subscription::clash",
            egress = config.egress.len(),
            groups = config.routing.groups.len(),
            rules = config.routing.rules.len(),
            "Seep 配置转换完成"
        );

        Ok(config)
    }

    /// 转换代理为出口节点
    fn convert_proxies_to_egress(&self, proxies: &[ClashProxy]) -> Result<Vec<EgressDescriptor>> {
        let mut egress = Vec::new();

        for proxy in proxies {
            if self.filter_invalid_nodes && !self.is_valid_proxy(proxy) {
                warn!(
                    target: "seep::subscription::clash",
                    name = %proxy.name,
                    proxy_type = ?proxy.proxy_type,
                    "跳过无效代理节点"
                );
                continue;
            }

            let name = format!("{}{}", self.node_prefix, proxy.name);
            let egress_config = self.convert_proxy_to_egress_config(proxy)?;

            egress.push(EgressDescriptor {
                name,
                spec: egress_config,
            });
        }

        Ok(egress)
    }

    /// 转换单个代理为出口配置
    fn convert_proxy_to_egress_config(&self, proxy: &ClashProxy) -> Result<EgressConfig> {
        match proxy.proxy_type {
            ClashProxyType::Http => Ok(EgressConfig::Http {
                server: proxy.server.clone(),
                port: proxy.port,
                username: proxy.username.clone(),
                password: proxy.password.clone(),
                tls: proxy.tls,
                skip_cert_verify: proxy.skip_cert_verify,
                sni: proxy.servername.clone(),
            }),
            ClashProxyType::Https => Ok(EgressConfig::Http {
                server: proxy.server.clone(),
                port: proxy.port,
                username: proxy.username.clone(),
                password: proxy.password.clone(),
                tls: true,
                skip_cert_verify: proxy.skip_cert_verify,
                sni: proxy.servername.clone(),
            }),
            ClashProxyType::Socks5 => Ok(EgressConfig::Socks5 {
                server: proxy.server.clone(),
                port: proxy.port,
                username: proxy.username.clone(),
                password: proxy.password.clone(),
            }),
            ClashProxyType::Ss => {
                let method = proxy
                    .cipher
                    .clone()
                    .unwrap_or_else(|| "aes-256-gcm".to_string());
                let password = proxy.password.clone().unwrap_or_default();

                Ok(EgressConfig::Shadowsocks {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    method,
                    password,
                })
            }
            ClashProxyType::Vmess => {
                let uuid = proxy
                    .uuid
                    .clone()
                    .ok_or_else(|| anyhow!("VMess 缺少 UUID"))?;
                let alter_id = 0; // Clash 默认 alterId 为 0

                Ok(EgressConfig::Vmess {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    uuid,
                    alter_id,
                    security: proxy.encrypt.clone().unwrap_or_else(|| "auto".to_string()),
                    network: proxy.network.clone().unwrap_or_else(|| "tcp".to_string()),
                    path: proxy.path.clone(),
                    host: proxy.host.clone().map(|h| vec![h]),
                    tls: proxy.tls,
                    skip_cert_verify: proxy.skip_cert_verify,
                    sni: proxy.servername.clone(),
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                })
            }
            ClashProxyType::Vless => {
                let uuid = proxy
                    .uuid
                    .clone()
                    .ok_or_else(|| anyhow!("VLESS 缺少 UUID"))?;

                Ok(EgressConfig::Vless {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    uuid,
                    flow: None, // Clash VLESS 通常不使用 flow
                    network: proxy.network.clone().unwrap_or_else(|| "tcp".to_string()),
                    path: proxy.path.clone(),
                    host: proxy.host.clone().map(|h| vec![h]),
                    tls: proxy.tls,
                    skip_cert_verify: proxy.skip_cert_verify,
                    sni: proxy.servername.clone(),
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                })
            }
            ClashProxyType::Trojan => {
                let password = proxy
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("Trojan 缺少密码"))?;

                Ok(EgressConfig::Trojan {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    password,
                    network: proxy.network.clone().unwrap_or_else(|| "tcp".to_string()),
                    path: proxy.path.clone(),
                    host: proxy.host.clone().map(|h| vec![h]),
                    tls: true,
                    skip_cert_verify: proxy.skip_cert_verify,
                    sni: proxy.servername.clone(),
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                })
            }
            ClashProxyType::Hysteria => {
                let password = proxy
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("Hysteria 缺少密码"))?;

                Ok(EgressConfig::Hysteria {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    password,
                    protocol: "udp".to_string(), // Clash Hysteria 通常使用 UDP
                    up_mbps: Some(50),
                    down_mbps: Some(100),
                    auth: None,
                    auth_str: None,
                    obfs: None,
                    obfs_param: None,
                    server_name: proxy.servername.clone(),
                    skip_cert_verify: proxy.skip_cert_verify,
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                })
            }
            ClashProxyType::Hysteria2 => {
                let password = proxy
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("Hysteria2 缺少密码"))?;

                Ok(EgressConfig::Hysteria2 {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    password,
                    mport: proxy.mport.clone(),
                    obfs: proxy.obfs.clone(),
                    obfs_param: proxy.obfs_param.clone(),
                    server_name: proxy.servername.clone(),
                    skip_cert_verify: proxy.skip_cert_verify,
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                })
            }
            ClashProxyType::Wireguard => {
                let private_key = proxy
                    .private_key
                    .clone()
                    .ok_or_else(|| anyhow!("WireGuard 缺少私钥"))?;
                let public_key = proxy
                    .public_key
                    .clone()
                    .ok_or_else(|| anyhow!("WireGuard 缺少公钥"))?;

                let address = build_wireguard_address(proxy)
                    .ok_or_else(|| anyhow!("WireGuard 缺少 ip/ipv6/address"))?;

                Ok(EgressConfig::Wireguard {
                    endpoint: format!("{}:{}", proxy.server, proxy.port),
                    private_key,
                    public_key,
                    address,
                    allowed_ips: proxy.allowed_ips.clone(),
                    preshared_key: proxy.preshared_key.clone(),
                    persistent_keepalive: proxy.persistent_keepalive,
                    listen_port: None,
                    mtu: proxy.mtu,
                    dns: proxy.dns.clone(),
                })
            }
            proxy_type => Err(anyhow!("暂不支持的代理类型: {:?}", proxy_type)),
        }
    }

    /// 转换代理组为策略组
    fn convert_proxy_groups_to_groups(
        &self,
        proxy_groups: &[ClashProxyGroup],
    ) -> Result<Vec<PolicyGroup>> {
        let mut groups = Vec::new();

        for group in proxy_groups {
            let name = format!("{}{}", self.group_prefix, group.name);
            let strategy = self.convert_group_type_to_strategy(group.group_type);
            let members = self.convert_proxies_to_group_members(&group.proxies);

            groups.push(PolicyGroup {
                name,
                strategy,
                members,
            });
        }

        Ok(groups)
    }

    /// 转换代理组类型为策略
    fn convert_group_type_to_strategy(&self, group_type: ClashProxyGroupType) -> Strategy {
        match group_type {
            ClashProxyGroupType::Select => Strategy::Fixed,
            ClashProxyGroupType::UrlTest => Strategy::Latency,
            ClashProxyGroupType::LoadBalance => Strategy::Weighted,
            ClashProxyGroupType::Fallback => Strategy::Random,
            ClashProxyGroupType::Relay => Strategy::ConsistentHash,
        }
    }

    /// 转换代理列表为组成员
    fn convert_proxies_to_group_members(&self, proxies: &[String]) -> Vec<GroupMember> {
        proxies
            .iter()
            .map(|proxy| GroupMember::Node {
                name: format!("{}{}", self.node_prefix, proxy),
            })
            .collect()
    }

    /// 转换规则为路由规则
    fn convert_rules_to_routing_rules(&self, rules: &[ClashRule]) -> Result<Vec<RouteRule>> {
        let mut routing_rules = Vec::new();

        for (index, rule) in rules.iter().enumerate() {
            let name = format!("{}rule-{}", self.rule_prefix, index + 1);
            match self.convert_clash_rule(rule) {
                Ok((matches, target)) => {
                    routing_rules.push(RouteRule {
                        name,
                        matches,
                        target,
                    });
                }
                Err(err) => {
                    warn!(
                        target: "seep::subscription::clash",
                        rule = ?rule,
                        error = %err,
                        "跳过不支持的 Clash 规则"
                    );
                }
            }
        }

        Ok(routing_rules)
    }

    /// 转换单个 Clash 规则
    fn convert_clash_rule(&self, rule: &ClashRule) -> Result<(Vec<MatchCondition>, String)> {
        match rule {
            ClashRule::DomainSuffix { domains, target } => {
                let matches = vec![MatchCondition::DomainSuffix {
                    values: domains.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::DomainKeyword { keywords, target } => {
                let matches = vec![MatchCondition::DomainKeyword {
                    values: keywords.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::Domain { domains, target } => {
                // Seep 暂不支持完全域名匹配，转换为后缀匹配
                let matches = vec![MatchCondition::DomainSuffix {
                    values: domains.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::IpCidr { cidrs, target } => {
                let matches = vec![MatchCondition::Network {
                    cidrs: cidrs.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::Geoip {
                country_code,
                target,
            } => {
                let matches = vec![MatchCondition::Geoip {
                    country: country_code.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::Geosite {
                country_code: _,
                target: _,
            } => {
                // Seep 暂不支持 GeoSite，跳过
                warn!(
                    target: "seep::subscription::clash",
                    "跳过 GeoSite 规则，Seep 暂不支持"
                );
                Err(anyhow!("GeoSite 规则暂不支持"))
            }
            ClashRule::SrcPort { ports, target } => {
                let matches = vec![MatchCondition::Port {
                    values: ports.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::DstPort { ports, target } => {
                let matches = vec![MatchCondition::Port {
                    values: ports.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::ProcessName {
                processes: _,
                target: _,
            } => {
                // Seep 暂不支持进程名匹配
                warn!(
                    target: "seep::subscription::clash",
                    "跳过进程名规则，Seep 暂不支持"
                );
                Err(anyhow!("进程名规则暂不支持"))
            }
            ClashRule::RuleSet {
                rulesets: _,
                target: _,
            } => {
                // Seep 暂不支持规则集
                warn!(
                    target: "seep::subscription::clash",
                    "跳过规则集规则，Seep 暂不支持"
                );
                Err(anyhow!("规则集规则暂不支持"))
            }
            ClashRule::Match { target } => {
                let matches = vec![]; // Match 规则不需要匹配条件
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
        }
    }

    /// 验证代理是否有效
    pub fn is_valid_proxy(&self, proxy: &ClashProxy) -> bool {
        // 检查必需字段
        if proxy.server.is_empty() || proxy.port == 0 {
            return false;
        }

        // 根据代理类型检查特定字段
        match proxy.proxy_type {
            ClashProxyType::Http | ClashProxyType::Https => true,
            ClashProxyType::Socks5 => true,
            ClashProxyType::Ss => proxy.cipher.is_some() && proxy.password.is_some(),
            ClashProxyType::Vmess | ClashProxyType::Vless => proxy.uuid.is_some(),
            ClashProxyType::Trojan => proxy.password.is_some(),
            ClashProxyType::Hysteria | ClashProxyType::Hysteria2 => proxy.password.is_some(),
            ClashProxyType::Snell => proxy.password.is_some(),
            ClashProxyType::Wireguard => {
                proxy.private_key.is_some()
                    && proxy.public_key.is_some()
                    && (proxy.ip.as_ref().is_some_and(|v| !v.is_empty())
                        || proxy.ipv6.as_ref().is_some_and(|v| !v.is_empty()))
            }
        }
    }

    /// 获取代理类型描述
    pub fn get_proxy_type_description(proxy_type: ClashProxyType) -> &'static str {
        match proxy_type {
            ClashProxyType::Ss => "Shadowsocks",
            ClashProxyType::Vmess => "VMess",
            ClashProxyType::Vless => "VLESS",
            ClashProxyType::Trojan => "Trojan",
            ClashProxyType::Http => "HTTP",
            ClashProxyType::Https => "HTTPS",
            ClashProxyType::Socks5 => "SOCKS5",
            ClashProxyType::Snell => "Snell",
            ClashProxyType::Hysteria => "Hysteria",
            ClashProxyType::Hysteria2 => "Hysteria2",
            ClashProxyType::Wireguard => "WireGuard",
        }
    }

    /// 统计代理类型分布
    pub fn count_proxy_types(proxies: &[ClashProxy]) -> HashMap<ClashProxyType, usize> {
        let mut counts = HashMap::new();

        for proxy in proxies {
            *counts.entry(proxy.proxy_type).or_insert(0) += 1;
        }

        counts
    }
}

impl Default for ClashConverter {
    fn default() -> Self {
        Self::new()
    }
}

fn build_wireguard_address(proxy: &ClashProxy) -> Option<String> {
    let mut addrs: Vec<String> = Vec::new();

    if let Some(ip_list) = &proxy.ip {
        for ip in ip_list {
            let ip = ip.trim();
            if ip.is_empty() {
                continue;
            }
            if ip.contains('/') {
                addrs.push(ip.to_string());
            } else {
                addrs.push(format!("{ip}/32"));
            }
        }
    }

    if let Some(ip_list) = &proxy.ipv6 {
        for ip in ip_list {
            let ip = ip.trim();
            if ip.is_empty() {
                continue;
            }
            if ip.contains('/') {
                addrs.push(ip.to_string());
            } else {
                addrs.push(format!("{ip}/128"));
            }
        }
    }

    if addrs.is_empty() {
        None
    } else {
        Some(addrs.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clash_config_parsing() {
        let yaml_content = r#"
proxies:
  - name: "test-ss"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password
  - name: "test-vmess"
    type: vmess
    server: example.org
    port: 443
    uuid: 12345678-1234-1234-1234-123456789abc
    network: ws
    tls: true
  - name: "test-hy2"
    type: hysteria2
    server: example.net
    port: 443
    password: secret
    ports: "35000-39000"

proxy-groups:
  - name: "auto"
    type: url-test
    proxies:
      - test-ss
      - test-vmess
    url: "http://www.gstatic.com/generate_204"
    interval: 300

rules:
  - DOMAIN-SUFFIX,google.com,auto
  - GEOIP,CN,DIRECT
  - MATCH,auto
        "#;

        let converter = ClashConverter::new();
        let clash_config = converter.parse(yaml_content).unwrap();

        assert_eq!(clash_config.proxies.len(), 3);
        assert_eq!(clash_config.proxy_groups.len(), 1);
        assert_eq!(clash_config.rules.len(), 3);

        let ss_proxy = &clash_config.proxies[0];
        assert_eq!(ss_proxy.proxy_type, ClashProxyType::Ss);
        assert_eq!(ss_proxy.name, "test-ss");

        let vmess_proxy = &clash_config.proxies[1];
        assert_eq!(vmess_proxy.proxy_type, ClashProxyType::Vmess);
        assert!(vmess_proxy.tls);

        let hy2_proxy = &clash_config.proxies[2];
        assert_eq!(hy2_proxy.proxy_type, ClashProxyType::Hysteria2);
        assert_eq!(hy2_proxy.mport.as_deref(), Some("35000-39000"));
    }

    #[test]
    fn test_hysteria2_ports_mapping_to_egress() {
        let yaml_content = r#"
proxies:
  - name: "test-hy2"
    type: hysteria2
    server: example.net
    port: 443
    password: secret
    ports: "35000-39000"

proxy-groups: []
rules: []
        "#;

        let converter = ClashConverter::new();
        let clash_config = converter.parse(yaml_content).unwrap();
        let seep_config = converter.convert_to_seep(&clash_config).unwrap();

        let hy2 = seep_config
            .egress
            .iter()
            .find(|e| e.name == "test-hy2")
            .expect("hy2 egress");

        match &hy2.spec {
            EgressConfig::Hysteria2 { mport, .. } => {
                assert_eq!(mport.as_deref(), Some("35000-39000"));
            }
            other => panic!("unexpected egress config: {:?}", other),
        }
    }

    #[test]
    fn test_proxy_type_conversion() {
        let converter = ClashConverter::new();

        assert_eq!(
            converter.convert_group_type_to_strategy(ClashProxyGroupType::Select),
            Strategy::Fixed
        );
        assert_eq!(
            converter.convert_group_type_to_strategy(ClashProxyGroupType::UrlTest),
            Strategy::Latency
        );
        assert_eq!(
            converter.convert_group_type_to_strategy(ClashProxyGroupType::LoadBalance),
            Strategy::Weighted
        );
    }

    #[test]
    fn test_proxy_validation() {
        let converter = ClashConverter::new();

        let valid_proxy = ClashProxy {
            name: "test".to_string(),
            proxy_type: ClashProxyType::Ss,
            server: "example.com".to_string(),
            port: 8388,
            cipher: Some("aes-256-gcm".to_string()),
            password: Some("password".to_string()),
            ..Default::default()
        };
        assert!(converter.is_valid_proxy(&valid_proxy));

        let invalid_proxy = ClashProxy {
            name: "test".to_string(),
            proxy_type: ClashProxyType::Ss,
            server: "".to_string(),
            port: 0,
            cipher: None,
            password: None,
            ..Default::default()
        };
        assert!(!converter.is_valid_proxy(&invalid_proxy));
    }

    #[test]
    fn test_proxy_type_counting() {
        let proxies = vec![
            ClashProxy {
                name: "ss1".to_string(),
                proxy_type: ClashProxyType::Ss,
                server: "example.com".to_string(),
                port: 8388,
                ..Default::default()
            },
            ClashProxy {
                name: "ss2".to_string(),
                proxy_type: ClashProxyType::Ss,
                server: "example.org".to_string(),
                port: 8388,
                ..Default::default()
            },
            ClashProxy {
                name: "vmess1".to_string(),
                proxy_type: ClashProxyType::Vmess,
                server: "example.net".to_string(),
                port: 443,
                ..Default::default()
            },
        ];

        let counts = ClashConverter::count_proxy_types(&proxies);
        assert_eq!(counts.get(&ClashProxyType::Ss), Some(&2));
        assert_eq!(counts.get(&ClashProxyType::Vmess), Some(&1));
        assert_eq!(counts.get(&ClashProxyType::Http), None);
    }
}
