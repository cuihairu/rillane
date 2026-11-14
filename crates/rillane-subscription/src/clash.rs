//! Clash 配置订阅处理

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{de, Deserialize, Serialize};
use serde_with::serde_as;
use serde_yaml::Value;
use tracing::{debug, warn};

use rillane_config::{
    EgressConfig, EgressDescriptor, GroupMember, MatchCondition, PolicyGroup, RealityConfig,
    RouteRule, RoutingConfig, Strategy, UrlTestConfig,
};

/// reality-opts YAML 块 → `RealityConfig`（G1-6 配置保留面）：键 kebab/snake
/// 兼容；块缺席 = None；缺 public-key 点名拒绝（无公钥的 REALITY 节点
/// 不可用且非法，不静默造空）。
fn reality_from_yaml(value: &Option<Value>, node: &str) -> Result<Option<RealityConfig>> {
    let Some(v) = value else {
        return Ok(None);
    };
    let m = v
        .as_mapping()
        .ok_or_else(|| anyhow!("VLESS 节点 {node} 的 reality-opts 须为映射"))?;
    let get = |k: &str| -> Option<String> {
        m.get(Value::String(k.to_string()))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
    };
    let public_key = get("public-key")
        .or_else(|| get("public_key"))
        .ok_or_else(|| anyhow!("VLESS 节点 {node} 的 reality-opts 缺少 public-key"))?;
    Ok(Some(RealityConfig {
        public_key,
        short_id: get("short-id").or_else(|| get("short_id")),
    }))
}

/// Clash url-test 组测试 URL →（probe `host:port`, path）（G1-9）。仅认
/// http/https URL；无端口按方案默认（80/443）补齐；空 authority 或端口
/// 非法返回 None——调用方不注入 url_test（宁缺不造）。
fn split_probe_url(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    let probe = match authority.rsplit_once(':') {
        Some((host, port_str)) => {
            let port: u16 = port_str.parse().ok()?;
            if port == 0 {
                return None;
            }
            format!("{host}:{port}")
        }
        None => format!("{authority}:{default_port}"),
    };
    Some((probe, path))
}

/// Clash/Mihomo 的 url-test `interval` 单位是**秒**（官方缺省 300），不是毫秒；
/// 这里原样透传，不做任何换算。`0` 表示配置者未填（YAML 里写了键但留空），
/// 按缺省 300 处理——若按字面值落成 0，运行期 `interval(0)` 会退化成每 tick 一次
/// 的探测风暴，且与「缺省 300」语义冲突（RIL-092）。
fn clash_interval_secs(interval: Option<u64>) -> u64 {
    match interval {
        Some(0) | None => 300,
        Some(secs) => secs,
    }
}

/// Clash 代理类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ClashProxyType {
    #[default]
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
    /// Shadowsocks: SIP003 插件名（捕获以防静默丢；导入时按换算表转 SIP003——
    /// 仅 obfs/v2ray-plugin 两族键名有把握，其余拒导）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// Shadowsocks: SIP003 插件参数（clash 侧为 map，导入时换算为分号 kv 串）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "plugin-opts",
        alias = "plugin_opts"
    )]
    pub plugin_opts: Option<Value>,
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
    /// Skip-cert-verify（Clash 规范键为 kebab-case `skip-cert-verify`，
    /// 缺别名时该键被 serde 静默丢弃 → 转换结果恒为 false，自签/私有 CA
    /// 证书握手必败；保留 snake 键名兼容存量配置）
    #[serde(default, alias = "skip-cert-verify")]
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
    /// WebSocket 传输选项（Clash 规范块键；path/Host 头在真实发行版里
    /// 恒在块内，平铺 `path`/`host` 仅少数变体使用——块缺失时回落实铺键）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "ws-opts",
        alias = "ws_opts",
        alias = "wsOptions"
    )]
    pub ws_opts: Option<ClashWsOpts>,
    /// gRPC 传输选项（Clash 规范块键 `grpc-opts.grpc-service-name`；
    /// network=grpc 时承载线上路径 /{name}/Tun 的服务名）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "grpc-opts",
        alias = "grpc_opts"
    )]
    pub grpc_opts: Option<ClashGrpcOpts>,
    /// HTTP/2 传输选项（Clash 规范块键 `h2-opts`；network=h2 时的 path/host）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "h2-opts",
        alias = "h2_opts",
        alias = "h2Options"
    )]
    pub h2_opts: Option<ClashH2Opts>,
    /// HTTPUpgrade 传输选项（Clash 规范块键 `httpupgrade-opts`；mihomo 口径，
    /// network=httpupgrade 时的 path/Host——headers 与 ws-opts 同形）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "httpupgrade-opts",
        alias = "httpupgrade_opts",
        alias = "httpupgradeOptions"
    )]
    pub httpupgrade_opts: Option<ClashHttpUpgradeOpts>,
    /// VLESS flow（如 xtls-rprx-vision；G1-6）。捕获随节点保留（拨号期对
    /// 不支持面点名拒绝）——静默降级为普通 VLESS 会连不上真节点（xtls 服务
    /// 端期望 Vision 分帧）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// REALITY 选项块（`reality-opts.public-key`/`short-id`；G1-6）。捕获随
    /// 节点保留（拨号期点名拒绝）——静默降级为普通 TLS VLESS 后，服务端按
    /// 非 REALITY 握手回落伪装站点，流量不走向代理且无任何报错。
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "reality-opts",
        alias = "reality_opts"
    )]
    pub reality_opts: Option<Value>,
}

/// Clash `ws-opts` 子块（vmess/vless 的 ws 传输）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashWsOpts {
    /// 请求路径
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 请求头（Host 伪装位）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<ClashWsHeaders>,
}

/// Clash `ws-opts.headers`（Host 头键大小写各发行版不一，三形兼容）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashWsHeaders {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "Host",
        alias = "HOST"
    )]
    pub host: Option<String>,
}

/// Clash `grpc-opts` 子块（vmess/vless/trojan 的 gRPC 传输）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashGrpcOpts {
    /// gRPC 服务名（线上路径 = /{name}/Tun；Clash 规范内键为
    /// `grpc-service-name`，其余为常见变体兜底）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "grpc-service-name",
        alias = "grpc_service_name",
        alias = "serviceName",
        alias = "service-name"
    )]
    pub grpc_service_name: Option<String>,
}

/// Clash `h2-opts` 子块（vmess/vless 的 HTTP/2 传输）
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashH2Opts {
    /// 请求路径
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Host/authority 列表（Clash 规范为数组；单值变体 OneOrMany 兜底）
    #[serde_as(as = "Option<serde_with::OneOrMany<_>>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
}

/// Clash `httpupgrade-opts` 子块（vmess/vless 的 httpupgrade 传输；mihomo
/// 口径 headers 与 ws-opts 同形）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashHttpUpgradeOpts {
    /// 请求路径
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 请求头（Host 伪装位；键大小写各发行版不一，三形兼容）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<ClashWsHeaders>,
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
    /// 测试间隔（秒；Clash/Mihomo 口径，0 视为缺省 300）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// 负载均衡策略
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

impl ClashProxy {
    /// ws 请求路径：平铺 `path` 优先（少数变体口径），否则 `ws-opts.path`
    /// （真实发行版口径）。空串按缺省处理（ws 节点 path 缺失即 `/`）。
    pub fn ws_path(&self) -> Option<String> {
        self.path
            .clone()
            .filter(|p| !p.is_empty())
            .or_else(|| self.ws_opts.as_ref().and_then(|w| w.path.clone()))
            .filter(|p| !p.is_empty())
    }

    /// ws Host 伪装头：平铺 `host` 优先，否则 `ws-opts.headers.host`
    /// （大小写三形由 serde 别名覆盖）。sni 回落由连接器侧负责。
    pub fn ws_host(&self) -> Option<String> {
        self.host
            .clone()
            .filter(|h| !h.is_empty())
            .or_else(|| {
                self.ws_opts
                    .as_ref()
                    .and_then(|w| w.headers.as_ref())
                    .and_then(|h| h.host.clone())
            })
            .filter(|h| !h.is_empty())
    }

    /// gRPC 服务名：`grpc-opts.grpc-service-name`（Clash 规范块键；
    /// 平铺变体由 serde 别名不覆盖——grpc 服务名无平铺口径）。空串按缺省处理
    /// （缺服务名的 grpc 节点由 RuntimeBuilder 构建期拦截）。
    pub fn grpc_service(&self) -> Option<String> {
        self.grpc_opts
            .as_ref()
            .and_then(|g| g.grpc_service_name.clone())
            .filter(|s| !s.is_empty())
    }

    /// h2 请求路径：平铺 `path` 优先（少数变体口径），否则 `h2-opts.path`。
    /// 空串按缺省处理（h2 节点 path 缺失即 `/`）。
    pub fn h2_path(&self) -> Option<String> {
        self.path
            .clone()
            .filter(|p| !p.is_empty())
            .or_else(|| self.h2_opts.as_ref().and_then(|h| h.path.clone()))
            .filter(|p| !p.is_empty())
    }

    /// h2 Host/authority 列表：`h2-opts.host`（数组规范；单值变体已由
    /// OneOrMany 收敛），平铺 `host` 单值兜底。空列表/空串按缺省处理
    /// （authority 回落链 sni → server 由连接器侧负责）。
    pub fn h2_hosts(&self) -> Option<Vec<String>> {
        self.h2_opts
            .as_ref()
            .and_then(|h| h.host.clone())
            .filter(|v| !v.is_empty())
            .or_else(|| self.host.clone().filter(|h| !h.is_empty()).map(|h| vec![h]))
    }

    /// httpupgrade 请求路径：平铺 `path` 优先（少数变体口径），否则
    /// `httpupgrade-opts.path`（mihomo 规范块键）。空串按缺省处理（path
    /// 缺失即 `/`）。
    pub fn httpupgrade_path(&self) -> Option<String> {
        self.path
            .clone()
            .filter(|p| !p.is_empty())
            .or_else(|| self.httpupgrade_opts.as_ref().and_then(|h| h.path.clone()))
            .filter(|p| !p.is_empty())
    }

    /// httpupgrade Host 伪装头：平铺 `host` 优先，否则
    /// `httpupgrade-opts.headers.host`（大小写三形由 serde 别名覆盖）。
    /// sni 回落由连接器侧负责。
    pub fn httpupgrade_host(&self) -> Option<String> {
        self.host
            .clone()
            .filter(|h| !h.is_empty())
            .or_else(|| {
                self.httpupgrade_opts
                    .as_ref()
                    .and_then(|h| h.headers.as_ref())
                    .and_then(|h| h.host.clone())
            })
            .filter(|h| !h.is_empty())
    }
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
    /// 域名正则匹配
    DomainRegex {
        #[serde(rename = "domain-regex")]
        patterns: Vec<String>,
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
    DomainRegex {
        #[serde(rename = "domain-regex")]
        patterns: Vec<String>,
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
            ClashRuleTagged::DomainRegex { patterns, target } => {
                ClashRule::DomainRegex { patterns, target }
            }
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
            "DOMAIN-REGEX" => Ok(ClashRule::DomainRegex {
                patterns: vec![get(1)?.to_string()],
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
            target: "rillane::subscription::clash",
            "开始解析 Clash 配置"
        );

        let config: ClashConfig =
            serde_yaml::from_str(content).context("解析 Clash YAML 配置失败")?;

        debug!(
            target: "rillane::subscription::clash",
            proxies = config.proxies.len(),
            groups = config.proxy_groups.len(),
            rules = config.rules.len(),
            "Clash 配置解析完成"
        );

        Ok(config)
    }

    /// 转换为 Rillane 配置
    pub fn convert_to_rillane(
        &self,
        clash_config: &ClashConfig,
    ) -> Result<rillane_config::RillaneConfig> {
        debug!(
            target: "rillane::subscription::clash",
            "开始转换为 Rillane 配置"
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
            ..RoutingConfig::default()
        };

        let config = rillane_config::RillaneConfig {
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:9090".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: clash_config.log_level.clone(),
                enable_metrics: true,
                enable_tracing: false,
            },
            ingress: vec![], // Clash 配置不包含入口配置
            egress,
            routing,
            udp: rillane_config::UdpConfig::default(),
            // 订阅转换不产网络虚拟化块（P1-3 归用户主配置）
            network: None,
            // 订阅转换不产混淆块（P1-4 归用户主配置）
            obfuscation: None,
            profile: None,
            performance: None,
            egress_pool: None,
        };

        debug!(
            target: "rillane::subscription::clash",
            egress = config.egress.len(),
            groups = config.routing.groups.len(),
            rules = config.routing.rules.len(),
            "Rillane 配置转换完成"
        );

        Ok(config)
    }

    /// 转换代理为出口节点
    fn convert_proxies_to_egress(&self, proxies: &[ClashProxy]) -> Result<Vec<EgressDescriptor>> {
        let mut egress = Vec::new();

        for proxy in proxies {
            if self.filter_invalid_nodes && !self.is_valid_proxy(proxy) {
                warn!(
                    target: "rillane::subscription::clash",
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
                tls_fingerprint: None,
            }),
            ClashProxyType::Https => Ok(EgressConfig::Http {
                server: proxy.server.clone(),
                port: proxy.port,
                username: proxy.username.clone(),
                password: proxy.password.clone(),
                tls: true,
                skip_cert_verify: proxy.skip_cert_verify,
                sni: proxy.servername.clone(),
                tls_fingerprint: None,
            }),
            ClashProxyType::Socks5 => Ok(EgressConfig::Socks5 {
                server: proxy.server.clone(),
                port: proxy.port,
                username: proxy.username.clone(),
                password: proxy.password.clone(),
            }),
            ClashProxyType::Ss => {
                // plugin 模式：SIP003 混淆由插件进程承载，直连 SS 协议对开启
                // 插件的服务端必握手失败——按换算表转 SIP003（仅 obfs/
                // v2ray-plugin 两族键名有把握），其余插件拒导（宁缺毋滥）
                let (plugin, plugin_opts) = clash_ss_plugin_to_sip003(proxy)?;

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
                    plugin,
                    plugin_opts,
                })
            }
            ClashProxyType::Vmess => {
                let uuid = proxy
                    .uuid
                    .clone()
                    .ok_or_else(|| anyhow!("VMess 缺少 UUID"))?;
                let alter_id = 0; // Clash 默认 alterId 为 0
                let network = proxy.network.clone().unwrap_or_else(|| "tcp".to_string());
                // path/host 取值随传输面分派：ws 走 ws-opts 口径，h2 走
                // h2-opts 口径（host 为数组），httpupgrade 走
                // httpupgrade-opts 口径（mihomo 规范）；其余 network 不消费两字段
                let is_h2 = network == "h2";
                let is_httpupgrade = network == "httpupgrade";
                let (path, host) = if is_h2 {
                    (proxy.h2_path(), proxy.h2_hosts())
                } else if is_httpupgrade {
                    (
                        proxy.httpupgrade_path(),
                        proxy.httpupgrade_host().map(|h| vec![h]),
                    )
                } else {
                    (proxy.ws_path(), proxy.ws_host().map(|h| vec![h]))
                };

                Ok(EgressConfig::Vmess {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    uuid,
                    alter_id,
                    security: proxy.encrypt.clone().unwrap_or_else(|| "auto".to_string()),
                    network,
                    path,
                    host,
                    grpc_service_name: proxy.grpc_service(),
                    tls: proxy.tls,
                    skip_cert_verify: proxy.skip_cert_verify,
                    sni: proxy.servername.clone(),
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                    tls_fingerprint: None,
                })
            }
            ClashProxyType::Vless => {
                let uuid = proxy
                    .uuid
                    .clone()
                    .ok_or_else(|| anyhow!("VLESS 缺少 UUID"))?;
                // REALITY/flow 配置保留（G1-6，2026-11-10 拍板改 M1 拒绝策略）：
                // 字段进 EgressConfig::Vless（serde 不再静默丢键，节点模型零
                // 信息损失）；不支持面在拨号期点名拒绝（防静默降级——普通 TLS
                // 会被 REALITY 服务端回落伪装站点，普通 VLESS 连不上期望
                // Vision 分帧的服务端且无报错），节点级失败不阻塞同订阅其余节点。
                let reality = reality_from_yaml(&proxy.reality_opts, &proxy.name)?;
                let network = proxy.network.clone().unwrap_or_else(|| "tcp".to_string());
                let is_h2 = network == "h2";
                let is_httpupgrade = network == "httpupgrade";
                let (path, host) = if is_h2 {
                    (proxy.h2_path(), proxy.h2_hosts())
                } else if is_httpupgrade {
                    (
                        proxy.httpupgrade_path(),
                        proxy.httpupgrade_host().map(|h| vec![h]),
                    )
                } else {
                    (proxy.ws_path(), proxy.ws_host().map(|h| vec![h]))
                };

                Ok(EgressConfig::Vless {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    uuid,
                    flow: proxy.flow.clone(),
                    reality,
                    network,
                    path,
                    host,
                    grpc_service_name: proxy.grpc_service(),
                    tls: proxy.tls,
                    skip_cert_verify: proxy.skip_cert_verify,
                    sni: proxy.servername.clone(),
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                    tls_fingerprint: None,
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
                    grpc_service_name: proxy.grpc_service(),
                    tls: true,
                    skip_cert_verify: proxy.skip_cert_verify,
                    sni: proxy.servername.clone(),
                    alpn: if proxy.alpn.is_empty() {
                        None
                    } else {
                        Some(proxy.alpn.clone())
                    },
                    tls_fingerprint: None,
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

            // G1-9：url-test 组的测试 URL/间隔映射为 UrlTestConfig，订阅导入
            // 后即按原节奏探活选路。url 缺席或解析失败 = 不注入（宁缺不造，
            // 不发明探测目标）；Clash interval 单位是秒，原样透传（RIL-092）。
            let url_test =
                match group.group_type {
                    ClashProxyGroupType::UrlTest => group
                        .url
                        .as_deref()
                        .and_then(split_probe_url)
                        .map(|(probe, path)| UrlTestConfig {
                            probe,
                            path,
                            interval_secs: clash_interval_secs(group.interval),
                            timeout_ms: 5000,
                        }),
                    _ => None,
                };

            groups.push(PolicyGroup {
                name,
                strategy,
                members,
                // 订阅不产 SLO 目标（归用户主配置，P1-3/P1-4 同判）
                slo: None,
                url_test,
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
                        target: "rillane::subscription::clash",
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
                let matches = vec![MatchCondition::DomainFull {
                    values: domains.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::DomainRegex { patterns, target } => {
                let matches = vec![MatchCondition::DomainRegex {
                    patterns: patterns.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            ClashRule::IpCidr { cidrs, target } => {
                let matches = vec![MatchCondition::IpCidr {
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
                country_code,
                target,
            } => {
                let matches = vec![MatchCondition::GeoSite {
                    category: country_code.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
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
                // Rillane 暂不支持进程名匹配
                warn!(
                    target: "rillane::subscription::clash",
                    "跳过进程名规则，Rillane 暂不支持"
                );
                Err(anyhow!("进程名规则暂不支持"))
            }
            ClashRule::RuleSet {
                rulesets: _,
                target: _,
            } => {
                // Rillane 暂不支持规则集
                warn!(
                    target: "rillane::subscription::clash",
                    "跳过规则集规则，Rillane 暂不支持"
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

/// clash SS 插件 → SIP003 (plugin 可执行名, plugin_opts 分号 kv 串)：
/// - `obfs`（simple-obfs 族）→ `obfs-local`，键名换算 mode→obfs、host→obfs-host
///   （mode 必填）；其他键拒导（simple-obfs 键名面仅此两个有把握）
/// - `v2ray-plugin` → 原名；键名原样透传（bool true → 裸 flag，false → 丢弃；
///   str/数值 → `key=value`；嵌套结构拒导）
/// - 其余插件名（kcptun 等）→ 拒导（无换算表，宁缺毋滥）
fn clash_ss_plugin_to_sip003(proxy: &ClashProxy) -> Result<(Option<String>, Option<String>)> {
    let Some(name) = proxy.plugin.as_deref() else {
        return Ok((None, None));
    };
    let opts = |what: &str| -> Result<serde_yaml::Mapping> {
        proxy
            .plugin_opts
            .as_ref()
            .and_then(|v| v.as_mapping().cloned())
            .ok_or_else(|| anyhow!("Shadowsocks 节点 {} 的 plugin-opts {what}", proxy.name))
    };

    match name {
        "obfs" | "obfs-local" | "simple-obfs" => {
            let m = opts("缺失或非 map")?;
            let mode = m
                .get(Value::String("mode".into()))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow!(
                        "Shadowsocks 节点 {} 的 obfs plugin-opts 缺 mode",
                        proxy.name
                    )
                })?;
            let mut parts = vec![format!("obfs={mode}")];
            if let Some(h) = m.get(Value::String("host".into())).and_then(|v| v.as_str()) {
                parts.push(format!("obfs-host={h}"));
            }
            Ok((Some("obfs-local".into()), Some(parts.join(";"))))
        }
        "v2ray-plugin" => {
            let m = opts("缺失或非 map")?;
            let mut parts = Vec::new();
            for (k, v) in m.iter() {
                let key = k.as_str().ok_or_else(|| {
                    anyhow!(
                        "Shadowsocks 节点 {} 的 v2ray-plugin plugin-opts 键非字符串",
                        proxy.name
                    )
                })?;
                match v {
                    Value::Bool(true) => parts.push(key.to_string()),
                    Value::Bool(false) => {}
                    Value::String(s) => parts.push(format!("{key}={s}")),
                    Value::Number(n) => parts.push(format!("{key}={n}")),
                    _ => anyhow::bail!(
                        "Shadowsocks 节点 {} 的 v2ray-plugin plugin-opts.{key} 为嵌套结构，无换算语义",
                        proxy.name
                    ),
                }
            }
            let opts_str = if parts.is_empty() {
                None
            } else {
                Some(parts.join(";"))
            };
            Ok((Some("v2ray-plugin".into()), opts_str))
        }
        other => Err(anyhow!(
            "Shadowsocks 节点 {} 的 plugin {other} 无换算表，暂不支持导入",
            proxy.name
        )),
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

    /// G1-9：url-test 组的 url/interval 映射为 UrlTestConfig——导入后即按
    /// 原节奏探活。url 缺席 = 不注入（宁缺不造）；非 url-test 组即便带
    /// url 也不注入。
    #[test]
    fn test_urltest_group_probe_config_mapped() {
        let yaml_content = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "auto"
    type: url-test
    url: "https://cp.cloudflare.com/generate_204"
    interval: 60000
    proxies:
      - "ss-1"
  - name: "manual"
    type: url-test
    proxies:
      - "ss-1"
  - name: "pick"
    type: select
    url: "https://cp.cloudflare.com/generate_204"
    proxies:
      - "ss-1"
rules:
  - MATCH,auto
        "#;
        let converter = ClashConverter::new();
        let config = converter.parse(yaml_content).unwrap();
        let groups = converter
            .convert_proxy_groups_to_groups(&config.proxy_groups)
            .unwrap();
        assert_eq!(groups.len(), 3);

        // auto：url 拆出 probe/path，interval 单位是秒——60000 即 60000 秒
        // （RIL-092：旧实现误当毫秒换算成 60 秒，探活被放大约 1000 倍）
        let auto = groups.iter().find(|g| g.name.ends_with("auto")).unwrap();
        let url_test = auto.url_test.as_ref().expect("url-test 组带 url 应注入");
        assert_eq!(url_test.probe, "cp.cloudflare.com:443");
        assert_eq!(url_test.path, "/generate_204");
        assert_eq!(url_test.interval_secs, 60000);

        // manual：url-test 组缺 url → 不注入（宁缺不造）
        let manual = groups.iter().find(|g| g.name.ends_with("manual")).unwrap();
        assert!(manual.url_test.is_none());

        // pick：select 组即便带 url 也不注入（只认 url-test 组）
        let pick = groups.iter().find(|g| g.name.ends_with("pick")).unwrap();
        assert!(pick.url_test.is_none());
    }

    /// RIL-092 反例：interval 单位是秒，不是毫秒。显式 300 → 300 秒、
    /// 显式 60000 → 60000 秒、缺省/写 0 → 300 秒。
    #[test]
    fn test_urltest_interval_read_in_seconds() {
        let yaml_content = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "sec-300"
    type: url-test
    url: "https://example.com/generate_204"
    interval: 300
    proxies:
      - "ss-1"
  - name: "sec-60000"
    type: url-test
    url: "https://example.com/generate_204"
    interval: 60000
    proxies:
      - "ss-1"
  - name: "zero"
    type: url-test
    url: "https://example.com/generate_204"
    interval: 0
    proxies:
      - "ss-1"
  - name: "defaulted"
    type: url-test
    url: "https://example.com/generate_204"
    proxies:
      - "ss-1"
rules:
  - MATCH,sec-300
        "#;
        let converter = ClashConverter::new();
        let config = converter.parse(yaml_content).unwrap();
        let groups = converter
            .convert_proxy_groups_to_groups(&config.proxy_groups)
            .unwrap();

        let interval_of = |suffix: &str| -> u64 {
            groups
                .iter()
                .find(|g| g.name.ends_with(suffix))
                .unwrap()
                .url_test
                .as_ref()
                .expect("url-test 组带 url 应注入探测配置")
                .interval_secs
        };
        assert_eq!(interval_of("sec-300"), 300);
        assert_eq!(interval_of("sec-60000"), 60000);
        // 0 与缺省同一策略：缺省 300 秒，不落成 0
        assert_eq!(interval_of("zero"), 300);
        assert_eq!(interval_of("defaulted"), 300);
    }

    /// RIL-092 单位策略的直接单测（不经 YAML，隔离策略本身）。
    #[test]
    fn clash_interval_secs_policy() {
        assert_eq!(clash_interval_secs(None), 300);
        assert_eq!(clash_interval_secs(Some(0)), 300);
        assert_eq!(clash_interval_secs(Some(300)), 300);
        assert_eq!(clash_interval_secs(Some(60000)), 60000);
        assert_eq!(clash_interval_secs(Some(1)), 1);
    }

    #[test]
    fn test_ss_plugin_obfs_import_converts_to_sip003() {
        let yaml_content = r#"
proxies:
  - name: "ss-obfs"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password
    plugin: obfs
    plugin-opts:
      mode: http
      host: www.example.com

proxy-groups:
  - name: "auto"
    type: select
    proxies:
      - "ss-obfs"
rules:
  - MATCH,auto
        "#;
        let converter = ClashConverter::new();
        let config = converter.parse(yaml_content).unwrap();
        let egress = converter
            .convert_proxies_to_egress(&config.proxies)
            .unwrap();
        assert_eq!(egress.len(), 1);
        match &egress[0].spec {
            EgressConfig::Shadowsocks {
                plugin,
                plugin_opts,
                ..
            } => {
                assert_eq!(plugin.as_deref(), Some("obfs-local"));
                assert_eq!(
                    plugin_opts.as_deref(),
                    Some("obfs=http;obfs-host=www.example.com")
                );
            }
            other => panic!("应为 Shadowsocks 配置: {other:?}"),
        }
    }

    #[test]
    fn test_ss_plugin_v2ray_import_converts_to_sip003() {
        let yaml_content = r#"
proxies:
  - name: "ss-v2ray"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: example.com
      path: /ws
      tls: true
      mux: false

proxy-groups:
  - name: "auto"
    type: select
    proxies:
      - "ss-v2ray"
rules:
  - MATCH,auto
        "#;
        let converter = ClashConverter::new();
        let config = converter.parse(yaml_content).unwrap();
        let egress = converter
            .convert_proxies_to_egress(&config.proxies)
            .unwrap();
        assert_eq!(egress.len(), 1);
        match &egress[0].spec {
            EgressConfig::Shadowsocks {
                plugin,
                plugin_opts,
                ..
            } => {
                assert_eq!(plugin.as_deref(), Some("v2ray-plugin"));
                // tls: true → 裸 flag；mux: false → 丢弃
                assert_eq!(
                    plugin_opts.as_deref(),
                    Some("mode=websocket;host=example.com;path=/ws;tls")
                );
            }
            other => panic!("应为 Shadowsocks 配置: {other:?}"),
        }
    }

    #[test]
    fn test_ss_plugin_unknown_rejected() {
        let yaml_content = r#"
proxies:
  - name: "ss-kcp"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password
    plugin: kcptun-client

proxy-groups:
  - name: "auto"
    type: select
    proxies:
      - "ss-kcp"
rules:
  - MATCH,auto
        "#;
        let converter = ClashConverter::new();
        let config = converter.parse(yaml_content).unwrap();
        let err = converter
            .convert_proxies_to_egress(&config.proxies)
            .expect_err("无换算表插件应拒导");
        assert!(
            err.to_string().contains("kcptun-client"),
            "错误应含插件名: {err:#}"
        );
    }

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
        let rillane_config = converter.convert_to_rillane(&clash_config).unwrap();
        assert!(
            rillane_config.control.admin_token.is_none(),
            "订阅转换不得生成硬编码 admin_token"
        );

        let hy2 = rillane_config
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
    fn test_vmess_ws_opts_path_and_host_converted() {
        // 回归：Clash vmess/vless 的 ws 传输参数在规范里位于 `ws-opts` 块
        // （path / headers.Host），平铺 `path`/`host` 仅少数变体使用——结构体
        // 无该块时 serde 静默丢弃 → 转换后 path/host 恒 None，ws 节点只能连
        // `/` 且无 Host 伪装，ws+tls 节点与真实服务端握手即败。
        let yaml_content = r#"
proxies:
  - name: "vm-wsopts"
    type: vmess
    server: 127.0.0.1
    port: 8443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: vm.test
    skip-cert-verify: true
    ws-opts:
      path: /vmws
      headers:
        Host: vm.test
  - name: "vl-wsopts"
    type: vless
    server: 127.0.0.1
    port: 8444
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: ws
    tls: true
    servername: vm.test
    ws-opts:
      path: /vl
      headers:
        host: lower.test
  - name: "vm-flat"
    type: vmess
    server: 127.0.0.1
    port: 8445
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: ws
    path: /flat
    host: flat.test

proxy-groups: []
rules: []
        "#;

        let converter = ClashConverter::new();
        let clash = converter.parse(yaml_content).unwrap();
        let rillane = converter.convert_to_rillane(&clash).unwrap();

        let grab = |name: &str| -> (Option<String>, Option<Vec<String>>) {
            let egress = rillane
                .egress
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("缺少出口 {name}"));
            match &egress.spec {
                EgressConfig::Vmess { path, host, .. } => (path.clone(), host.clone()),
                EgressConfig::Vless { path, host, .. } => (path.clone(), host.clone()),
                other => panic!("unexpected egress config: {other:?}"),
            }
        };

        assert_eq!(
            grab("vm-wsopts"),
            (Some("/vmws".into()), Some(vec!["vm.test".into()]))
        );
        assert_eq!(
            grab("vl-wsopts"),
            (Some("/vl".into()), Some(vec!["lower.test".into()]))
        );
        // 平铺键（存量变体）继续生效，且优先于块内同名键
        assert_eq!(
            grab("vm-flat"),
            (Some("/flat".into()), Some(vec!["flat.test".into()]))
        );

        // ws-opts 内无 path 时回落 None（连接器侧补 `/`）
        let only_headers = "proxies:\n  - name: n\n    type: vmess\n    server: h\n    port: 1\n    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3\n    network: ws\n    ws-opts:\n      headers:\n        Host: h.test\nproxy-groups: []\nrules: []\n";
        let c2 = converter.parse(only_headers).unwrap();
        assert_eq!(c2.proxies[0].ws_path(), None);
        assert_eq!(c2.proxies[0].ws_host(), Some("h.test".to_string()));
    }

    #[test]
    fn test_httpupgrade_opts_converted_for_vmess_and_vless() {
        // httpupgrade 传输（mihomo 规范块键 httpupgrade-opts：path /
        // headers.Host）：network 原样透传，path/host 从块内取值；平铺
        // 键优先。块缺失时 path/host = None（连接器侧补 `/`）。
        let yaml_content = r#"
proxies:
  - name: "vm-hu"
    type: vmess
    server: 127.0.0.1
    port: 8447
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    alterId: 0
    cipher: auto
    network: httpupgrade
    tls: true
    servername: vm.test
    httpupgrade-opts:
      path: /vmhu
      headers:
        Host: hu.test
  - name: "vl-hu"
    type: vless
    server: 127.0.0.1
    port: 8448
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: httpupgrade
    tls: true
    servername: vm.test
    httpupgrade-opts:
      path: /vlhu
      headers:
        host: lower.test

proxy-groups: []
rules: []
        "#;

        let converter = ClashConverter::new();
        let clash = converter.parse(yaml_content).unwrap();
        let rillane = converter.convert_to_rillane(&clash).unwrap();

        let grab = |name: &str| -> (String, Option<String>, Option<Vec<String>>) {
            let egress = rillane
                .egress
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("缺少出口 {name}"));
            match &egress.spec {
                EgressConfig::Vmess {
                    network,
                    path,
                    host,
                    ..
                } => (network.clone(), path.clone(), host.clone()),
                EgressConfig::Vless {
                    network,
                    path,
                    host,
                    ..
                } => (network.clone(), path.clone(), host.clone()),
                other => panic!("unexpected egress config: {other:?}"),
            }
        };

        let (network, path, host) = grab("vm-hu");
        assert_eq!(network, "httpupgrade");
        assert_eq!(path.as_deref(), Some("/vmhu"));
        assert_eq!(host, Some(vec!["hu.test".to_string()]));

        let (network, path, host) = grab("vl-hu");
        assert_eq!(network, "httpupgrade");
        assert_eq!(path.as_deref(), Some("/vlhu"));
        assert_eq!(host, Some(vec!["lower.test".to_string()]));

        // 块缺失：path/host 均 None（连接器侧补 `/`，Host 回落 sni/server）
        let bare = "proxies:\n  - name: n\n    type: vmess\n    server: h\n    port: 1\n    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3\n    network: httpupgrade\nproxy-groups: []\nrules: []\n";
        let c2 = converter.parse(bare).unwrap();
        assert_eq!(c2.proxies[0].httpupgrade_path(), None);
        assert_eq!(c2.proxies[0].httpupgrade_host(), None);
    }

    #[test]
    fn test_grpc_opts_service_name_converted() {
        // grpc 传输：Clash 规范块键 grpc-opts.grpc-service-name →
        // grpc_service_name（network=grpc 缺服务名由 RuntimeBuilder 构建期拦截）
        let yaml_content = r#"
proxies:
  - name: "vm-grpc"
    type: vmess
    server: 127.0.0.1
    port: 8446
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: grpc
    tls: true
    servername: vm.test
    grpc-opts:
      grpc-service-name: GunService
  - name: "tr-grpc"
    type: trojan
    server: 127.0.0.1
    port: 8447
    password: pass
    network: grpc
    skip-cert-verify: true
    grpc-opts:
      grpc-service-name: TrSvc

proxy-groups: []
rules: []
        "#;

        let converter = ClashConverter::new();
        let clash = converter.parse(yaml_content).unwrap();
        let rillane = converter.convert_to_rillane(&clash).unwrap();

        let grab = |name: &str| -> (String, Option<String>) {
            let egress = rillane
                .egress
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("缺少出口 {name}"));
            match &egress.spec {
                EgressConfig::Vmess {
                    network,
                    grpc_service_name,
                    ..
                }
                | EgressConfig::Vless {
                    network,
                    grpc_service_name,
                    ..
                }
                | EgressConfig::Trojan {
                    network,
                    grpc_service_name,
                    ..
                } => (network.clone(), grpc_service_name.clone()),
                other => panic!("unexpected egress config: {other:?}"),
            }
        };

        assert_eq!(grab("vm-grpc"), ("grpc".into(), Some("GunService".into())));
        assert_eq!(grab("tr-grpc"), ("grpc".into(), Some("TrSvc".into())));
    }

    #[test]
    fn test_h2_opts_converted_for_vmess_and_vless() {
        // h2 传输：Clash 规范块键 h2-opts.host（标量或数组）/h2-opts.path →
        // 平铺 path/host 字段（network=h2 缺 path 由协议连接器握手期报错）
        let yaml_content = r#"
proxies:
  - name: "vm-h2"
    type: vmess
    server: 127.0.0.1
    port: 8446
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: h2
    tls: true
    servername: vm.test
    h2-opts:
      host:
        - cdn.example.com
      path: /h2path
  - name: "vl-h2"
    type: vless
    server: 127.0.0.1
    port: 8447
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: h2
    tls: true
    servername: vl.test
    h2-opts:
      host: [alt.example.com]
      path: /h2vl

proxy-groups: []
rules: []
        "#;

        let converter = ClashConverter::new();
        let clash = converter.parse(yaml_content).unwrap();
        let rillane = converter.convert_to_rillane(&clash).unwrap();

        let grab = |name: &str| -> (String, Option<String>, Option<Vec<String>>) {
            let egress = rillane
                .egress
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("缺少出口 {name}"));
            match &egress.spec {
                EgressConfig::Vmess {
                    network,
                    path,
                    host,
                    ..
                }
                | EgressConfig::Vless {
                    network,
                    path,
                    host,
                    ..
                } => (network.clone(), path.clone(), host.clone()),
                other => panic!("unexpected egress config: {other:?}"),
            }
        };

        assert_eq!(
            grab("vm-h2"),
            (
                "h2".into(),
                Some("/h2path".into()),
                Some(vec!["cdn.example.com".into()])
            )
        );
        assert_eq!(
            grab("vl-h2"),
            (
                "h2".into(),
                Some("/h2vl".into()),
                Some(vec!["alt.example.com".into()])
            )
        );
    }

    #[test]
    fn test_vmess_skip_cert_verify_kebab_key_not_dropped() {
        // 回归：Clash 规范键为 kebab-case `skip-cert-verify`，struct 无
        // rename_all 且字段缺别名时该键被 serde 静默丢弃 → 转换恒为
        // false，自签证书握手必败。别名修复后 kebab 键必须生效，snake
        // 键（存量）保持兼容。
        let yaml_content = r#"
proxies:
  - name: "vm-kebab"
    type: vmess
    server: 127.0.0.1
    port: 8443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    servername: 127.0.0.1
    network: ws
    ws-opts:
      path: /vws
    skip-cert-verify: true
  - name: "vm-snake"
    type: vmess
    server: 127.0.0.1
    port: 8443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    tls: true
    skip_cert_verify: true

proxy-groups: []
rules: []
        "#;

        let converter = ClashConverter::new();
        let clash_config = converter.parse(yaml_content).unwrap();
        assert_eq!(clash_config.proxies.len(), 2);
        assert!(clash_config.proxies[0].skip_cert_verify);
        assert!(clash_config.proxies[1].skip_cert_verify);

        let rillane_config = converter.convert_to_rillane(&clash_config).unwrap();
        for name in ["vm-kebab", "vm-snake"] {
            let egress = rillane_config
                .egress
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("缺少出口 {name}"));
            match &egress.spec {
                EgressConfig::Vmess {
                    skip_cert_verify, ..
                } => assert!(skip_cert_verify, "{name} 的 skip_cert_verify 未透传"),
                other => panic!("unexpected egress config: {:?}", other),
            }
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

    /// G0-2 DOMAIN-REGEX 解析：字符串规则（`DOMAIN-REGEX,pat,target`）
    /// 与 tagged 形式（`type: domain-regex`）均产出 `DomainRegex` 变体，
    /// 且经 `convert_clash_rule` 映射为 `MatchCondition::DomainRegex`。
    #[test]
    fn test_domain_regex_rule_parsing_and_conversion() {
        // 字符串形式
        let rule = ClashRule::parse_rule_string(r"DOMAIN-REGEX,^ad\d+\.,auto").unwrap();
        match rule {
            ClashRule::DomainRegex { patterns, target } => {
                assert_eq!(patterns, vec![r"^ad\d+\.".to_string()]);
                assert_eq!(target, "auto");
            }
            other => panic!("应为 DomainRegex: {other:?}"),
        }

        // tagged 形式
        let yaml_content = r#"
proxies: []
proxy-groups: []
rules:
  - type: domain-regex
    domain-regex:
      - ^ad\d+\.
    target: auto
        "#;
        let converter = ClashConverter::new();
        let config = converter.parse(yaml_content).unwrap();
        assert!(matches!(config.rules[0], ClashRule::DomainRegex { .. }));

        // convert_clash_rule 映射
        let (matches, target) = converter
            .convert_clash_rule(&config.rules[0])
            .expect("DomainRegex 应可转换");
        assert_eq!(target, "auto");
        assert!(matches!(
            &matches[0],
            MatchCondition::DomainRegex { patterns } if patterns == &vec![r"^ad\d+\.".to_string()]
        ));
    }

    /// G1-6 REALITY/flow 配置保留（2026-11-10 拍板改 M1 拒绝策略）：含
    /// reality-opts/flow 的 VLESS convert 成功且字段完整保留（serde 不静默
    /// 丢键）；不支持面在拨号期点名拒绝（防静默降级为普通 TLS VLESS——服务
    /// 端回落伪装站点/期望 Vision 分帧且无报错）。缺 public-key 仍点名报错。
    #[test]
    fn test_vless_reality_and_flow_nodes_preserved_on_convert() {
        let converter = ClashConverter::new();

        // reality-opts（REALITY 协议）
        let reality_yaml = r#"
proxies:
  - name: "vl-reality"
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: tcp
    tls: true
    servername: www.apple.com
    reality-opts:
      public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ
      short-id: "0123ac"

proxy-groups: []
rules: []
        "#;
        let reality_clash = converter.parse(reality_yaml).unwrap();
        let rillane = converter.convert_to_rillane(&reality_clash).unwrap();
        let vl = rillane
            .egress
            .iter()
            .find(|e| e.name == "vl-reality")
            .expect("vl-reality egress 应存在");
        // G1-6（拍板改 M1 拒绝策略）：serde 不静默丢键——reality-opts 解析成功
        // 且字段完整保留（拨号期才点名拒绝）
        match &vl.spec {
            EgressConfig::Vless { reality, flow, .. } => {
                let r = reality.as_ref().expect("reality 应保留");
                assert_eq!(r.public_key, "PBQh7j2tWxQmZHVub3RUYXJnZXQ");
                assert_eq!(r.short_id.as_deref(), Some("0123ac"));
                assert!(flow.is_none(), "无 flow 节点 flow 应为 None");
            }
            other => panic!("应为 Vless: {other:?}"),
        }

        // reality-opts 缺 public-key → 转换期点名报错（配置不完整不静默半配）
        let bad_yaml = reality_yaml.replace("      public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ\n", "");
        let bad_clash = converter.parse(&bad_yaml).unwrap();
        let err = converter.convert_to_rillane(&bad_clash).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("public-key") && msg.contains("vl-reality"),
            "应点名缺 public-key 与节点名: {msg}"
        );

        // flow（XTLS-Vision 等流控）
        let flow_yaml = r#"
proxies:
  - name: "vl-vision"
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: tcp
    tls: true
    flow: xtls-rprx-vision

proxy-groups: []
rules: []
        "#;
        let flow_clash = converter.parse(flow_yaml).unwrap();
        let rillane = converter.convert_to_rillane(&flow_clash).unwrap();
        let vl = rillane
            .egress
            .iter()
            .find(|e| e.name == "vl-vision")
            .expect("vl-vision egress 应存在");
        match &vl.spec {
            EgressConfig::Vless { reality, flow, .. } => {
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"), "flow 应保留");
                assert!(reality.is_none(), "无 reality 节点 reality 应为 None");
            }
            other => panic!("应为 Vless: {other:?}"),
        }

        // 无 reality/flow 的普通 VLESS 不受影响
        let plain_yaml = r#"
proxies:
  - name: "vl-plain"
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    network: tcp
    tls: true

proxy-groups: []
rules: []
        "#;
        let plain = converter.parse(plain_yaml).unwrap();
        let rillane = converter.convert_to_rillane(&plain).unwrap();
        let vl = rillane
            .egress
            .iter()
            .find(|e| e.name == "vl-plain")
            .expect("vl-plain egress 应存在");
        assert!(matches!(vl.spec, EgressConfig::Vless { .. }));
    }
}
