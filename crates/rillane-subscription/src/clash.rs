//! Clash 配置订阅处理

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{de, Deserialize, Serialize};
use serde_with::serde_as;
use serde_yaml::Value;
use tracing::{debug, warn};

use rillane_config::{
    CompatibilityDiagnostic, EgressConfig, EgressDescriptor, GroupMember, GrpcReuseConfig,
    MatchCondition, ObjectId, PolicyGroup, RealityConfig, RouteRule, RoutingConfig, SourceId,
    SourceLocation, Strategy, UrlTestConfig,
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
    Anytls,
    Http,
    Https,
    #[serde(rename = "socks5")]
    Socks5,
    Snell,
    Hysteria,
    Hysteria2,
    Tuic,
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
    /// Hysteria: 载具协议（udp/wechat/faketcp；缺省 udp——仓内面仅交付原生
    /// UDP 上的 QUIC，其余载具拨号期具名拒绝，转换面不判负节点）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Hysteria: 上行带宽申报 Mbps（官方 mbpsToBps 口径）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<u32>,
    /// Hysteria: 下行带宽申报 Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<u32>,
    /// Hysteria: 字符串认证（常见键 auth-str，别名 auth_str——premium 侧
    /// 下划线形；导入缺 password 时回退本字段作认证面）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "auth-str",
        alias = "auth_str"
    )]
    pub auth_str: Option<String>,
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
    /// UUID（用于 VMess/VLESS/TUIC）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// TUIC: QUIC 拥塞控制（Clash 规范键 `congestion-controller`——无别名
    /// 则该键被 serde 静默丢弃，往返丢配置）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "congestion-controller",
        alias = "congestion_controller"
    )]
    pub congestion_controller: Option<String>,
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
    /// Servername（Clash 规范键为 `sni`，servername 为旧写法——clash_export
    /// 反向导出写 `sni:`，无别名则往返丢 SNI，自签/私有 CA 场景直连失败）
    #[serde(default, alias = "sni", skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    /// Fingerprint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Client fingerprint（Clash 规范键 `client-fingerprint`，uTLS 指纹——
    /// 与证书指纹 `fingerprint` 是两个不同字段，不得合并）
    #[serde(
        default,
        rename = "client-fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_fingerprint: Option<String>,
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
    /// XHTTP 传输选项（mihomo 块键 `xhttp-opts`；network=xhttp 时的
    /// mode/path/host，RIL-129）
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "xhttp-opts",
        alias = "xhttp_opts",
        alias = "xhttpOptions"
    )]
    pub xhttp_opts: Option<ClashXhttpOpts>,
    /// VLESS flow（如 xtls-rprx-vision；G1-6）。捕获随节点保留（拨号期对
    /// 不支持面点名拒绝）——静默降级为普通 VLESS 会连不上真节点（xtls 服务
    /// 端期望 Vision 分帧）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// vless UDP 包编码（RIL-130，mihomo 键位 `packet-encoding`）：raw（缺省，
    /// Xray 原生）/ xudp / packetaddr；白名单外构建期具名拒绝。Clash 规范键
    /// 为 kebab-case，别名面同 skip_cert_verify 口径
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "packet-encoding"
    )]
    pub packet_encoding: Option<String>,
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
    /// gun 流复用旋钮（RIL-130；Clash/mihomo 口径键位）。缺省（三键全缺）
    /// = 单连接全复用
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "max-connections",
        alias = "max_connections"
    )]
    pub max_connections: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "min-streams",
        alias = "min_streams"
    )]
    pub min_streams: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "max-streams",
        alias = "max_streams"
    )]
    pub max_streams: Option<u32>,
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

/// Clash `xhttp-opts` 子块（vless 的 XHTTP 传输，RIL-129；mihomo 口径
/// mode/path/host）
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashXhttpOpts {
    /// XHTTP 模式（auto/packet-up/stream-one；auto = 缺省判 packet-up）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// 请求路径
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Host/authority 列表（与 h2-opts 同形；单值变体 OneOrMany 兜底）
    #[serde_as(as = "Option<serde_with::OneOrMany<_>>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
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
    /// 代理列表（RIL-009 起可缺省：`use:` 型组成员来自 provider）
    #[serde(default)]
    pub proxies: Vec<String>,
    /// provider 引用（Clash `use:` 口径，RIL-009）：成员集 = 所列 provider
    /// 当前提供的节点。引用须指向已声明 proxy-provider，未声明引用显式
    /// 进损失清单（与 RULE-SET 同口径）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "use")]
    pub use_providers: Vec<String>,
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

    /// gun 流复用旋钮（RIL-130）：`grpc-opts` 内 max-connections/
    /// min-streams/max-streams → `GrpcReuseConfig`；三键全缺 = None（构建
    /// 侧缺省单连接全复用，mihomo NewClient 同口径）。
    pub fn grpc_reuse(&self) -> Option<GrpcReuseConfig> {
        let g = self.grpc_opts.as_ref()?;
        let reuse = GrpcReuseConfig {
            max_connections: g.max_connections,
            min_streams: g.min_streams,
            max_streams: g.max_streams,
        };
        if reuse == GrpcReuseConfig::default() {
            None
        } else {
            Some(reuse)
        }
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

    /// XHTTP 请求路径：平铺 `path` 优先（少数变体口径），否则
    /// `xhttp-opts.path`（mihomo 规范块键）。空串按缺省处理（path 缺失
    /// 即 `/`）。
    pub fn xhttp_path(&self) -> Option<String> {
        self.path
            .clone()
            .filter(|p| !p.is_empty())
            .or_else(|| self.xhttp_opts.as_ref().and_then(|x| x.path.clone()))
            .filter(|p| !p.is_empty())
    }

    /// XHTTP Host/authority 列表：`xhttp-opts.host`（与 h2-opts 同形，单值
    /// 变体已由 OneOrMany 收敛），平铺 `host` 单值兜底。authority 回落链
    /// sni → server 由连接器侧负责。
    pub fn xhttp_hosts(&self) -> Option<Vec<String>> {
        self.xhttp_opts
            .as_ref()
            .and_then(|x| x.host.clone())
            .filter(|v| !v.is_empty())
            .or_else(|| self.host.clone().filter(|h| !h.is_empty()).map(|h| vec![h]))
    }

    /// XHTTP 模式：`xhttp-opts.mode`（auto/packet-up/stream-one；None =
    /// auto 口径由连接器判 packet-up）。越界值保留原样（RuntimeBuilder
    /// 构建期具名拒绝，不静默降级）。
    pub fn xhttp_mode(&self) -> Option<String> {
        self.xhttp_opts
            .as_ref()
            .and_then(|x| x.mode.clone())
            .filter(|m| !m.is_empty())
    }

    /// vless UDP 包编码（RIL-130）：平铺 `packet-encoding` 键位；空串按
    /// 缺省处理（raw——Xray 原生 UDP 面）
    pub fn packet_encoding(&self) -> Option<String> {
        self.packet_encoding.clone().filter(|e| !e.is_empty())
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
    /// 进程可执行路径（RIL-015）：与进程名语义独立（路径全串精确比较、
    /// 不做 comm 截断）
    ProcessPath {
        #[serde(rename = "process-path")]
        paths: Vec<String>,
        target: String,
    },
    /// 规则集
    RuleSet {
        #[serde(rename = "rule-set")]
        rulesets: Vec<String>,
        target: String,
    },
    /// 逻辑 AND（RIL-014）：全部子条件命中即命中。顶层展开为 `matches`
    /// 列表（列表内即 AND 语义）；OR/NOT 嵌套内的 AND 需要单条件表达，
    /// 导入链显式拒绝（不能伪装成其它语义）
    LogicAnd {
        rules: Vec<ClashRule>,
        target: String,
    },
    /// 逻辑 OR（RIL-014）：任一子条件命中即命中 → `MatchCondition::Any`
    LogicOr {
        rules: Vec<ClashRule>,
        target: String,
    },
    /// 逻辑 NOT（RIL-014）：唯一子条件不命中即命中 → `MatchCondition::Not`
    LogicNot {
        rules: Vec<ClashRule>,
        target: String,
    },
    /// 传输协议子条件（RIL-014）：`NETWORK,<proto>` 只在逻辑规则子条件
    /// 内出现 → `MatchCondition::Proto`
    Network {
        protocols: Vec<String>,
        target: String,
    },
    /// 未知规则类型（RIL-014）：解析期不炸整份配置（宽松导入的损失清单
    /// 语义）——保留原文，转换期显式进损失清单（宽松随行/严格整体拒绝），
    /// 未知关键条件不跳过也不伪装
    Unknown { raw: String },
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
    ProcessPath {
        #[serde(rename = "process-path")]
        paths: Vec<String>,
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
            ClashRuleTagged::ProcessPath { paths, target } => {
                ClashRule::ProcessPath { paths, target }
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
        // 逻辑规则（RIL-014）：AND/OR/NOT 载荷内含嵌套逗号，不能走朴素
        // split——按头一个逗号前的 kind 提前分流到括号感知解析器。未知
        // 关键子条件在子解析里报错，整条规则显式拒绝（不得部分跳过）
        let head = raw
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        if matches!(head.as_str(), "AND" | "OR" | "NOT") {
            return Self::parse_logic_rule(&head, raw);
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
            // RIL-015：进程路径——与进程名语义独立
            "PROCESS-PATH" => Ok(ClashRule::ProcessPath {
                paths: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "RULE-SET" => Ok(ClashRule::RuleSet {
                rulesets: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            // RIL-014：传输协议——只在逻辑规则子条件内合法出现
            "NETWORK" => Ok(ClashRule::Network {
                protocols: vec![get(1)?.to_string()],
                target: get(2)?.to_string(),
            }),
            "MATCH" => Ok(ClashRule::Match {
                target: get(1)?.to_string(),
            }),
            _ => {
                // RIL-014：未知规则类型保留原文进 Unknown（解析期不炸整份
                // 配置）；转换期显式进损失清单，未知关键条件不跳过
                Ok(ClashRule::Unknown {
                    raw: raw.to_string(),
                })
            }
        }
    }

    /// 逻辑规则解析（RIL-014）：`AND,((SUB1),(SUB2)),TARGET` /
    /// `OR,((SUB1),(SUB2)),TARGET` / `NOT,((SUB)),TARGET`。子条件递归
    /// 走 [`ClashRule::parse_rule_string`]（占位 target 保留在子规则上，
    /// 转换期忽略）；未知/不支持子条件整条报错，不做部分吸收。
    fn parse_logic_rule(kind: &str, raw: &str) -> Result<Self, String> {
        // 载荷 = 第一个逗号之后的全部内容
        let payload = raw
            .split_once(',')
            .map(|(_, rest)| rest.trim())
            .ok_or_else(|| format!("invalid logic rule: {raw}"))?;
        let (subs, target) = split_logic_payload(payload)?;
        let rules = subs
            .iter()
            .map(|sub| {
                // 逻辑子条件不带 target（出口由外层逻辑规则给出）——嵌套
                // 逻辑规则与双段普通子条件都缺尾段，解析失败按形态补占位
                // target 重试，转换期忽略占位值
                ClashRule::parse_rule_string(sub).or_else(|err| {
                    let head = sub
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_uppercase();
                    let double_segment =
                        sub.split(',').filter(|p| !p.trim().is_empty()).count() == 2;
                    if matches!(head.as_str(), "AND" | "OR" | "NOT") || double_segment {
                        ClashRule::parse_rule_string(&format!("{sub},__LOGIC_SUB_TARGET__"))
                    } else {
                        Err(err)
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        match kind {
            "AND" => Ok(ClashRule::LogicAnd { rules, target }),
            "OR" => Ok(ClashRule::LogicOr { rules, target }),
            _ => Ok(ClashRule::LogicNot { rules, target }),
        }
    }
}

/// 端口/端口区间解析（RIL-014 从规则解析提取共享）：`80` 单端口 /
/// `1000-2000` 区间（上限 4096 防膨胀）。规则行与规则集载荷行共用。
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

/// 拆逻辑规则载荷（RIL-014）：`((SUB1),(SUB2)),TARGET` → (子条件串列表,
/// 目标)。括号感知扫描——子条件内的逗号属于子条件自身，顶层逗号才是
/// 分隔符；子条件必须逐个用 `( ... )` 包裹（Clash 逻辑规则语法）。
fn split_logic_payload(payload: &str) -> Result<(Vec<String>, String), String> {
    let rest = payload.trim();
    let Some(inner) = rest.strip_prefix('(') else {
        return Err(format!(
            "logic rule conditions must be wrapped in ( ): {payload}"
        ));
    };

    // 找与首个 ( 配对的 )——子条件块整体边界
    let mut depth = 1usize;
    let mut block_end = None;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    block_end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = block_end else {
        return Err("logic rule parentheses unbalanced".to_string());
    };
    let block = &inner[..end];
    let after = inner[end + 1..].trim_start();
    let Some(target) = after.strip_prefix(',') else {
        return Err("logic rule missing target".to_string());
    };

    // 块内按顶层逗号拆子条件：depth 0 处的 `,` 是分隔符，其余逗号属于
    // 子条件自身（如 DOMAIN,a.com）
    let mut subs = Vec::new();
    let mut cur = String::new();
    let mut inner_depth = 0usize;
    for c in block.chars() {
        match c {
            '(' => {
                inner_depth += 1;
                if inner_depth > 1 {
                    cur.push(c);
                }
            }
            ')' => {
                inner_depth -= 1;
                if inner_depth > 0 {
                    cur.push(c);
                } else {
                    subs.push(cur.trim().to_string());
                    cur.clear();
                }
            }
            ',' if inner_depth == 0 => {} // 子条件之间的分隔逗号
            _ => cur.push(c),
        }
    }
    if inner_depth != 0 || !cur.trim().is_empty() {
        return Err("logic rule parentheses unbalanced".to_string());
    }
    if subs.is_empty() {
        return Err("logic rule has no conditions".to_string());
    }
    Ok((subs, target.trim().to_string()))
}

/// 解析 rule-provider 载荷为条件列表（RIL-014 展开策略的载荷侧）：声明
/// `format` 决定文本形态——`yaml`（`payload:` 字符串列表）/ `text`（每行
/// 一条规则，`#` 注释与空行跳过）。载荷行不带 target（RULE-SET 的出口
/// 由引用行给出），行内多余参数（如 `no-resolve` 标志、行内 target）
/// 忽略；behavior 划定条件类型域（domain/ipcidr/classical），越域条件
/// 显式报错——载荷与声明不符不得静默混用。任何一行解析失败整体 Err
/// 并点名该行（未知关键条件不跳过）。
pub fn parse_rule_provider_payload(
    behavior: &str,
    format: &str,
    text: &str,
) -> Result<Vec<MatchCondition>> {
    let entries: Vec<String> = match format.to_ascii_lowercase().as_str() {
        "yaml" | "" => {
            let value: serde_yaml::Value =
                serde_yaml::from_str(text).map_err(|e| anyhow!("载荷 yaml 解析失败: {e}"))?;
            let payload = value
                .get("payload")
                .ok_or_else(|| anyhow!("载荷缺 payload 键（yaml 格式）"))?;
            let seq = payload
                .as_sequence()
                .ok_or_else(|| anyhow!("载荷 payload 必须是列表"))?;
            seq.iter()
                .map(|item| {
                    item.as_str()
                        .map(|s| s.to_string())
                        .ok_or_else(|| anyhow!("载荷 payload 项必须是字符串: {item:?}"))
                })
                .collect::<Result<Vec<_>>>()?
        }
        "text" => text
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect(),
        other => return Err(anyhow!("未知载荷格式: {other}（支持 yaml/text）")),
    };

    let mut conditions = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let condition = parse_payload_rule(entry)
            .map_err(|e| anyhow!("载荷第 {} 条解析失败（{}）: {e}", index + 1, entry))?;
        if !behavior_allows(behavior, &condition) {
            return Err(anyhow!(
                "载荷第 {} 条（{}）与声明 behavior `{}` 不符",
                index + 1,
                entry,
                behavior
            ));
        }
        conditions.push(condition);
    }
    Ok(conditions)
}

/// 单条载荷规则 → 条件（RIL-014）：kind + 值；载荷行 target/flag 参数
/// 忽略（出口由 RULE-SET 引用行给出）。逻辑规则与 MATCH 在载荷域无意义
/// /暂不支持——显式报错不静默跳过。
fn parse_payload_rule(entry: &str) -> Result<MatchCondition> {
    let raw = entry.trim();
    let parts: Vec<&str> = raw.split(',').map(|p| p.trim()).collect();
    let Some(kind_raw) = parts.first() else {
        return Err(anyhow!("空载荷行"));
    };
    let kind = kind_raw.to_ascii_uppercase();
    // 条件值：kind 后第一个参数；`no-resolve` 等标志参数在值之后
    let value = parts
        .get(1)
        .copied()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("载荷行缺值: {raw}"))?;

    let condition = match kind.as_str() {
        "DOMAIN" => MatchCondition::DomainFull {
            values: vec![value.to_string()],
        },
        "DOMAIN-SUFFIX" => MatchCondition::DomainSuffix {
            values: vec![value.to_string()],
        },
        "DOMAIN-KEYWORD" => MatchCondition::DomainKeyword {
            values: vec![value.to_string()],
        },
        "DOMAIN-REGEX" => MatchCondition::DomainRegex {
            patterns: vec![value.to_string()],
        },
        "GEOSITE" => MatchCondition::GeoSite {
            category: value.to_string(),
        },
        "GEOIP" => MatchCondition::Geoip {
            country: value.to_string(),
        },
        "IP-CIDR" | "IP-CIDR6" => MatchCondition::IpCidr {
            cidrs: vec![value.to_string()],
        },
        "SRC-PORT" => MatchCondition::SrcPort {
            values: parse_ports(value).map_err(|e| anyhow!("{e}"))?,
        },
        "DST-PORT" => MatchCondition::Port {
            values: parse_ports(value).map_err(|e| anyhow!("{e}"))?,
        },
        "PROCESS-NAME" => MatchCondition::Process {
            values: vec![value.to_string()],
        },
        "PROCESS-PATH" => MatchCondition::ProcessPath {
            values: vec![value.to_string()],
        },
        "AND" | "OR" | "NOT" => {
            return Err(anyhow!("载荷内嵌套逻辑规则暂不支持: {kind}"));
        }
        "MATCH" => return Err(anyhow!("MATCH 在载荷域无意义")),
        other => return Err(anyhow!("未知载荷规则类型: {other}")),
    };
    Ok(condition)
}

/// behavior 域校验（RIL-014）：domain 只收域名族，ipcidr 只收 IP 段，
/// classical 全收。未知 behavior 一律拒收（声明面拼错不得静默当 classical）。
fn behavior_allows(behavior: &str, condition: &MatchCondition) -> bool {
    match behavior {
        "domain" => matches!(
            condition,
            MatchCondition::DomainFull { .. }
                | MatchCondition::DomainSuffix { .. }
                | MatchCondition::DomainKeyword { .. }
                | MatchCondition::DomainRegex { .. }
                | MatchCondition::GeoSite { .. }
        ),
        "ipcidr" => matches!(condition, MatchCondition::IpCidr { .. }),
        "classical" => true,
        _ => false,
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
    /// proxy-provider 声明捕获（RIL-009）：节点目录来源元数据——转换期
    /// 按名落 `routing.proxy_providers` 声明并做 `use:` 引用追踪（未声明
    /// 引用显式进损失清单）；载荷下载/更新归 RIL-010
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[serde(rename = "proxy-providers")]
    pub proxy_providers: HashMap<String, ClashProxyProvider>,
    /// rule-providers 声明捕获（RIL-014）：RULE-SET 引用的规则集来源
    /// 元数据——转换期按名落 `routing.rule_providers` 声明并做引用追踪
    /// （未声明的 RULE-SET 引用显式进损失清单）；载荷下载/更新归 RIL-010
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[serde(rename = "rule-providers")]
    pub rule_providers: HashMap<String, ClashRuleProvider>,
}

/// Clash rule-provider 声明（RIL-014）：`type`(http/file) + `behavior`
/// (domain/ipcidr/classical) + `format`(yaml/text，缺省 yaml) + 来源
/// （url 或 path）+ `interval` 更新周期（秒——Clash 口径即秒，导入时
/// 不换算单位）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashRuleProvider {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub behavior: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
}

/// Clash proxy-provider 声明（RIL-009）：`type`(http/file) + 来源（url 或
/// path）+ `interval` 更新周期（秒——Clash 口径即秒，导入不换算单位）+
/// 目录级 `health-check`。`interval_secs` 与 rule-provider 同判（RIL-092）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashProxyProvider {
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// 更新周期（秒）；0 = 不自动更新（Clash 口径）
    #[serde(default)]
    pub interval: Option<u64>,
    /// 目录级健康检查块
    #[serde(default)]
    #[serde(rename = "health-check")]
    pub health_check: Option<ClashProviderHealthCheck>,
}

/// Clash provider `health-check` 块（RIL-009）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashProviderHealthCheck {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub url: Option<String>,
    /// 探测周期（秒）
    #[serde(default)]
    pub interval: Option<u64>,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// 转换损失清单：宽松模式导入继续，但被丢弃/降级的内容必须在这里可见，
/// 不能伪装成无损成功；严格模式清单非空即整体拒绝（RIL-093）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConversionReport {
    /// 被丢弃的节点（节点名, 原因）：未通过有效性校验或类型暂不支持
    pub dropped_nodes: Vec<(String, String)>,
    /// 语义被降级的节点（节点名, 降级说明）（RIL-106）：节点保留可导，
    /// 但字段损失显式可见（AnyTLS 的 alpn/fingerprint/client-fingerprint
    /// 不入 IR），与 degraded_rules/providers 同口径——不伪装无损
    pub degraded_nodes: Vec<(String, String)>,
    /// 语义被降级的组（组名, 降级说明）：relay 组直接拒绝不落此清单；
    /// load-balance 的 sticky-sessions/未知子键降级进此清单（RIL-013）
    pub degraded_groups: Vec<(String, String)>,
    /// 被跳过的规则（规则名, 原因）：暂不支持的规则类型
    pub dropped_rules: Vec<(String, String)>,
    /// 语义被降级的规则（规则名, 降级说明）（RIL-015）：如进程名/路径
    /// 规则——转换保留但依赖平台归因能力（TUN 面/路径可得性），降级
    /// 必须显式可见，不得伪装成无损
    pub degraded_rules: Vec<(String, String)>,
    /// 未吸收的整块输入（块名, 原因）（RIL-007）：如 proxy-providers——
    /// 关键语义整块缺失必须显式可见，不得伪装成完整配置转换成功
    pub unsupported_blocks: Vec<(String, String)>,
    /// 语义被降级的 provider（provider 名, 降级说明）（RIL-009）：声明已
    /// 吸收（落 `routing.proxy_providers`）但节点目录载荷尚未装入——
    /// 组成员集为空集，失效成员退出新流候选，载荷装入归 RIL-010。降级
    /// 必须显式可见，不得伪装成「组已带成员」
    pub degraded_providers: Vec<(String, String)>,
}

impl ConversionReport {
    /// 是否没有任何丢弃或降级
    pub fn is_empty(&self) -> bool {
        self.dropped_nodes.is_empty()
            && self.degraded_nodes.is_empty()
            && self.degraded_groups.is_empty()
            && self.dropped_rules.is_empty()
            && self.degraded_rules.is_empty()
            && self.degraded_providers.is_empty()
            && self.unsupported_blocks.is_empty()
    }

    /// 人可读的损失清单（逐行）；空报告返回「无损失」
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "无损失".to_string();
        }

        let mut lines = Vec::new();
        if !self.dropped_nodes.is_empty() {
            lines.push(format!("丢弃节点 {} 个:", self.dropped_nodes.len()));
            lines.extend(
                self.dropped_nodes
                    .iter()
                    .map(|(name, reason)| format!("  节点 {name}: {reason}")),
            );
        }
        if !self.degraded_nodes.is_empty() {
            lines.push(format!("降级节点 {} 个:", self.degraded_nodes.len()));
            lines.extend(
                self.degraded_nodes
                    .iter()
                    .map(|(name, reason)| format!("  节点 {name}: {reason}")),
            );
        }
        if !self.degraded_groups.is_empty() {
            lines.push(format!("降级组 {} 个:", self.degraded_groups.len()));
            lines.extend(
                self.degraded_groups
                    .iter()
                    .map(|(name, reason)| format!("  组 {name}: {reason}")),
            );
        }
        if !self.dropped_rules.is_empty() {
            lines.push(format!("跳过规则 {} 条:", self.dropped_rules.len()));
            lines.extend(
                self.dropped_rules
                    .iter()
                    .map(|(name, reason)| format!("  规则 {name}: {reason}")),
            );
        }
        if !self.degraded_rules.is_empty() {
            lines.push(format!("降级规则 {} 条:", self.degraded_rules.len()));
            lines.extend(
                self.degraded_rules
                    .iter()
                    .map(|(name, reason)| format!("  规则 {name}: {reason}")),
            );
        }
        if !self.degraded_providers.is_empty() {
            lines.push(format!(
                "降级 provider {} 个:",
                self.degraded_providers.len()
            ));
            lines.extend(
                self.degraded_providers
                    .iter()
                    .map(|(name, reason)| format!("  provider {name}: {reason}")),
            );
        }
        if !self.unsupported_blocks.is_empty() {
            lines.push(format!("未支持块 {} 个:", self.unsupported_blocks.len()));
            lines.extend(
                self.unsupported_blocks
                    .iter()
                    .map(|(name, reason)| format!("  块 {name}: {reason}")),
            );
        }
        lines.join("\n")
    }

    /// 收敛为规范兼容诊断（RIL-002 契约，RIL-007 样本验收口径）：每条
    /// 损失携带稳定码（`compat.unsupported`/`compat.lossy`）并定位到来源
    /// 对象——节点 `proxies/<显示名>`、组 `proxy-groups/<名>`、规则
    /// `rules/<rule-N>`、整块 `blocks/<块名>`。转换期 local_id 以显示名
    /// 暂代；稳定 ID 派生随 RIL-008 来源快照接入切换。
    pub fn diagnostics(&self, source: &SourceId) -> Vec<CompatibilityDiagnostic> {
        let mut diagnostics = Vec::new();

        for (name, reason) in &self.dropped_nodes {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::unsupported(
                Some(id),
                SourceLocation::new(source.clone(), format!("proxies/{name}")),
                reason.clone(),
            ));
        }
        for (name, reason) in &self.degraded_nodes {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::lossy(
                Some(id),
                SourceLocation::new(source.clone(), format!("proxies/{name}")),
                None,
                reason.clone(),
            ));
        }
        for (name, reason) in &self.degraded_groups {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::lossy(
                Some(id),
                SourceLocation::new(source.clone(), format!("proxy-groups/{name}")),
                None,
                reason.clone(),
            ));
        }
        for (name, reason) in &self.dropped_rules {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::unsupported(
                Some(id),
                SourceLocation::new(source.clone(), format!("rules/{name}")),
                reason.clone(),
            ));
        }
        for (name, reason) in &self.degraded_rules {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::lossy(
                Some(id),
                SourceLocation::new(source.clone(), format!("rules/{name}")),
                None,
                reason.clone(),
            ));
        }
        for (name, reason) in &self.degraded_providers {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::lossy(
                Some(id),
                SourceLocation::new(source.clone(), format!("proxy-providers/{name}")),
                None,
                reason.clone(),
            ));
        }
        for (name, reason) in &self.unsupported_blocks {
            let id = ObjectId::new(source.clone(), name.clone());
            diagnostics.push(CompatibilityDiagnostic::unsupported(
                Some(id),
                SourceLocation::new(source.clone(), format!("blocks/{name}")),
                reason.clone(),
            ));
        }

        diagnostics
    }
}

/// 该代理类型是否已有到 Rillane 的换算表（RIL-093：类型级不支持的节点按
/// 丢弃+报告处理，不再让单个节点炸掉整个导入；已支持类型的配置级错误——
/// 如 reality 缺 public-key——仍点名硬错误，不降级成静默丢节点，G1-6 保持）。
fn is_supported_proxy_type(proxy_type: ClashProxyType) -> bool {
    !matches!(proxy_type, ClashProxyType::Snell)
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
    /// 严格导入：任何语义损失（不支持类型/组/规则、无效节点）整体拒绝，
    /// 不产出半份伪装成功的配置；宽松模式继续导入但损失进 ConversionReport
    /// （RIL-093）
    strict: bool,
}

impl ClashConverter {
    /// 创建新的转换器
    pub fn new() -> Self {
        Self {
            node_prefix: String::new(),
            group_prefix: String::new(),
            rule_prefix: String::new(),
            filter_invalid_nodes: true,
            strict: false,
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

    /// 设置严格导入模式。严格 = true：任何语义损失整体拒绝；宽松 = false
    /// （缺省）：导入继续但损失清单随 `convert_to_rillane_with_report` 返回
    /// （RIL-093）
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
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

    /// 转换为 Rillane 配置。丢弃/降级内容只记日志不返回——需要损失清单
    /// （宽松模式报告 / 严格模式拒绝）用 `convert_to_rillane_with_report`
    /// （RIL-093）
    pub fn convert_to_rillane(
        &self,
        clash_config: &ClashConfig,
    ) -> Result<rillane_config::RillaneConfig> {
        self.convert_to_rillane_with_report(clash_config)
            .map(|(config, _)| config)
    }

    /// 转换为 Rillane 配置并返回损失清单。宽松模式：配置照常产出，被丢弃/
    /// 降级的内容进 `ConversionReport`；严格模式：清单非空即整体拒绝，
    /// Err 信息即完整损失清单，绝不产出半份伪装成功的配置（RIL-093）。
    pub fn convert_to_rillane_with_report(
        &self,
        clash_config: &ClashConfig,
    ) -> Result<(rillane_config::RillaneConfig, ConversionReport)> {
        debug!(
            target: "rillane::subscription::clash",
            "开始转换为 Rillane 配置"
        );

        let mut report = ConversionReport::default();

        // 转换代理为出口节点
        let egress = self.convert_proxies_to_egress(&clash_config.proxies, &mut report)?;

        // 转换代理组为策略组
        let groups = self.convert_proxy_groups_to_groups(
            &clash_config.proxy_groups,
            &clash_config.proxy_providers,
            &mut report,
        )?;

        // 转换规则为路由规则（RIL-014：RULE-SET 引用按 rule-providers
        // 声明追踪，未声明引用显式进损失清单）
        let rules = self.convert_rules_to_routing_rules(
            &clash_config.rules,
            &clash_config.rule_providers,
            &mut report,
        )?;

        // RIL-009：proxy-provider 声明按名落 routing.proxy_providers
        // （interval 秒口径原样、health-check 原样）。载荷下载与生命周期
        // 归 RIL-010：节点集此时为空——provider 组成员展开为空集，
        // 失效成员退出新流候选，不伪装成员已吸收
        let mut proxy_provider_decls = std::collections::BTreeMap::new();
        for (name, provider) in &clash_config.proxy_providers {
            proxy_provider_decls.insert(
                name.clone(),
                rillane_config::ProxyProviderDecl {
                    provider_type: provider.provider_type.clone(),
                    url: provider.url.clone(),
                    path: provider.path.clone(),
                    // RIL-092 同判：Clash interval 口径即秒，0/缺省 = 不自动更新
                    interval_secs: provider.interval.filter(|v| *v > 0),
                    health_check: provider.health_check.as_ref().map(|hc| {
                        rillane_config::ProviderHealthCheck {
                            enable: hc.enable,
                            url: hc.url.clone(),
                            interval_secs: hc.interval.filter(|v| *v > 0),
                        }
                    }),
                },
            );
            // 声明已吸收 ≠ 节点已吸收：导入链不下载载荷（归 RIL-010），
            // 故每个声明的 provider 都按降级显式报告——组成员集为空集，
            // 失效成员退出新流候选；不得伪装成「组已带成员」
            report.degraded_providers.push((
                name.clone(),
                format!(
                    "声明已吸收（type={}，更新周期 {}）但节点目录载荷未装入（下载生命周期归 RIL-010）：该 provider 当前提供 0 个节点，引用它的组成员集为空集",
                    provider.provider_type,
                    provider
                        .interval
                        .filter(|v| *v > 0)
                        .map(|v| format!("{v} 秒"))
                        .unwrap_or_else(|| "未设定".to_string())
                ),
            ));
        }

        // 严格导入：任何语义损失都拒绝，错误携带完整损失清单
        if self.strict && !report.is_empty() {
            return Err(anyhow!("严格导入拒绝有损转换:\n{}", report.summary()));
        }

        // 创建默认节点
        let default_node = egress
            .first()
            .map(|e| e.name.clone())
            .unwrap_or_else(|| "direct".to_string());

        let mut routing = RoutingConfig {
            default_node,
            groups,
            rules,
            ..RoutingConfig::default()
        };

        // rule-providers 声明落配置（RIL-014）：url/path/interval（Clash
        // interval 口径即秒）原样带入——载荷下载与更新生命周期归 RIL-010，
        // 此处只保声明面供引用追踪与下载器配置。HashMap 迭代无序，落
        // BTreeMap 后序列化确定
        for (name, provider) in &clash_config.rule_providers {
            routing.rule_providers.insert(
                name.clone(),
                rillane_config::RuleProviderDecl {
                    provider_type: provider.provider_type.clone(),
                    behavior: provider.behavior.clone(),
                    format: provider.format.clone(),
                    url: provider.url.clone(),
                    path: provider.path.clone(),
                    interval_secs: provider.interval,
                },
            );
        }

        // RIL-009：proxy-provider 声明挂配置（与 rule-provider 同形；
        // HashMap 迭代无序，声明面已是 BTreeMap 故序列化确定）
        routing.proxy_providers = proxy_provider_decls;

        let config = rillane_config::RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
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
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        debug!(
            target: "rillane::subscription::clash",
            egress = config.egress.len(),
            groups = config.routing.groups.len(),
            rules = config.routing.rules.len(),
            "Rillane 配置转换完成"
        );

        Ok((config, report))
    }

    /// 转换代理为出口节点
    fn convert_proxies_to_egress(
        &self,
        proxies: &[ClashProxy],
        report: &mut ConversionReport,
    ) -> Result<Vec<EgressDescriptor>> {
        let mut egress = Vec::new();

        for proxy in proxies {
            if self.filter_invalid_nodes && !self.is_valid_proxy(proxy) {
                warn!(
                    target: "rillane::subscription::clash",
                    name = %proxy.name,
                    proxy_type = ?proxy.proxy_type,
                    "跳过无效代理节点"
                );
                // 丢节点必须可见：宽松模式进损失清单，严格模式据此整体拒绝
                report.dropped_nodes.push((
                    proxy.name.clone(),
                    "未通过有效性校验（缺 server/port 或类型必填字段）".to_string(),
                ));
                continue;
            }

            let name = format!("{}{}", self.node_prefix, proxy.name);
            let egress_config = match self.convert_proxy_to_egress_config(proxy, report) {
                Ok(spec) => spec,
                Err(err) => {
                    // 类型级不支持（如 Snell）：宽松丢弃并报告、严格记入清单
                    // 统一拒绝——单节点不再炸掉整个导入；已支持类型的配置级
                    // 错误（如 reality 缺 public-key）保持点名硬错误，不降级
                    // 成静默丢节点（G1-6 拒绝策略，RIL-093 保持）
                    if is_supported_proxy_type(proxy.proxy_type) {
                        return Err(err);
                    }
                    report.dropped_nodes.push((name.clone(), err.to_string()));
                    continue;
                }
            };

            egress.push(EgressDescriptor {
                name,
                spec: egress_config,
            });
        }

        Ok(egress)
    }

    /// 转换单个代理为出口配置
    fn convert_proxy_to_egress_config(
        &self,
        proxy: &ClashProxy,
        report: &mut ConversionReport,
    ) -> Result<EgressConfig> {
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
                // RIL-130：vmess UDP 包编码不交付（sing-vmess mux/chunk 流与
                // 仓内 raw 单目标 UDP 面不同构）——非 raw 具名拒绝（G1-6：已
                // 支持类型的配置级错误保持硬错误，不静默降级成 raw）
                if let Some(enc) = proxy.packet_encoding() {
                    if enc != "raw" {
                        return Err(anyhow!(
                            "VMess packet-encoding 仅 raw 可交付（xudp/packetaddr 载具未交付），当前: {enc}"
                        ));
                    }
                }
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
                    grpc_reuse: proxy.grpc_reuse(),
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
                let is_xhttp = network == "xhttp";
                let (path, host) = if is_h2 {
                    (proxy.h2_path(), proxy.h2_hosts())
                } else if is_httpupgrade {
                    (
                        proxy.httpupgrade_path(),
                        proxy.httpupgrade_host().map(|h| vec![h]),
                    )
                } else if is_xhttp {
                    (proxy.xhttp_path(), proxy.xhttp_hosts())
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
                    grpc_reuse: proxy.grpc_reuse(),
                    xhttp_mode: proxy.xhttp_mode(),
                    packet_encoding: proxy.packet_encoding(),
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
                    grpc_reuse: proxy.grpc_reuse(),
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
            ClashProxyType::Anytls => {
                let password = proxy
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("AnyTLS 缺少密码"))?;
                // alpn/client-fingerprint 不入 IR（RIL-106 目录边界）：节点
                // 保留可用（anytls 无 alpn 协商约束），但损失显式可见——降级
                // 进损失清单（与 RIL-015「降级必须显式可见」同口径），不伪装无损
                let mut lost = Vec::new();
                if !proxy.alpn.is_empty() {
                    lost.push("alpn");
                }
                if proxy.client_fingerprint.is_some() {
                    lost.push("client-fingerprint");
                }
                if proxy.fingerprint.is_some() {
                    lost.push("fingerprint");
                }
                if !lost.is_empty() {
                    report.degraded_nodes.push((
                        proxy.name.clone(),
                        format!("AnyTLS {} 不入 IR，转换期丢弃", lost.join("/")),
                    ));
                }
                Ok(EgressConfig::Anytls {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    password,
                    sni: proxy.servername.clone(),
                    skip_cert_verify: proxy.skip_cert_verify,
                })
            }
            ClashProxyType::Hysteria => {
                // 认证面：password 键缺席时回退 auth-str（premium/mihomo 两侧
                // 键位并存；IR resolve 顺序 auth_str 优先，同一字节面）
                let password = proxy
                    .password
                    .clone()
                    .or_else(|| proxy.auth_str.clone())
                    .ok_or_else(|| anyhow!("Hysteria 缺少密码"))?;
                // protocol/up/down 键位直入 IR（RIL-109 字段面随自写客户端
                // 交付：非 "udp" 载具拨号期具名拒绝，转换面不判负节点；
                // up/down 缺省 None = 连接器按官方缺省 50/100 申报，不在此
                // 伪造数值）。obfs 包层传输换整个 QUIC 载荷、仓内面不交付
                // ——损失显式可见（降级清单），不伪装无损
                if proxy.obfs.is_some() || proxy.obfs_param.is_some() {
                    report.degraded_nodes.push((
                        proxy.name.clone(),
                        "Hysteria obfs 包层传输不入 IR，转换期丢弃".to_string(),
                    ));
                }
                Ok(EgressConfig::Hysteria {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    password,
                    protocol: proxy.protocol.clone().unwrap_or_else(|| "udp".to_string()),
                    up_mbps: proxy.up,
                    down_mbps: proxy.down,
                    auth: None,
                    auth_str: proxy.auth_str.clone(),
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
            ClashProxyType::Tuic => {
                let password = proxy
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("TUIC 缺少密码"))?;
                let uuid = proxy
                    .uuid
                    .clone()
                    .ok_or_else(|| anyhow!("TUIC 缺少 uuid"))?;

                Ok(EgressConfig::Tuic {
                    server: proxy.server.clone(),
                    port: proxy.port,
                    uuid,
                    password,
                    congestion_controller: proxy.congestion_controller.clone(),
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
        providers: &HashMap<String, ClashProxyProvider>,
        report: &mut ConversionReport,
    ) -> Result<Vec<PolicyGroup>> {
        let mut groups = Vec::new();

        for group in proxy_groups {
            let name = format!("{}{}", self.group_prefix, group.name);
            // RIL-013 分配算法审计：load-balance 按声明子键分派——缺省按
            // Clash 口径 consistent-hashing（目标键一致哈希，会话选择可
            // 重现）；round-robin 直映轮询（序列可重现）。旧实现一律映射
            // Weighted（加权随机，不可重现）属伪装成功。sticky-sessions
            // 粘滞键是「源会话」而非「目标」，v1 以目标一致性哈希近似但
            // 必须点名登记（降级可见，不静默）；未知子键按缺省处理并登记。
            // relay 明确拒绝（两种模式都拒绝，RIL-013 验收）：链式转发
            // 流量依次经成员链转发，Rillane v1 无同语义配置面——映射成
            // ConsistentHash 只会伪装成功（成员被当出口链终点，流量根本
            // 不过链），拒绝比伪装诚实。
            let strategy = match group.group_type {
                ClashProxyGroupType::Relay => {
                    return Err(anyhow!(
                        "组 {}: relay 组语义是链式转发（流量依次经成员链转发），Rillane v1 无同语义配置面，明确拒绝导入（不能映射成一致性哈希伪装）",
                        group.name
                    ));
                }
                ClashProxyGroupType::LoadBalance => {
                    let (strategy, note): (Strategy, Option<String>) =
                        match group.strategy.as_deref().map(str::trim) {
                            None | Some("consistent-hashing") => (Strategy::ConsistentHash, None),
                            Some("round-robin") => (Strategy::RoundRobin, None),
                            Some("sticky-sessions") => (
                                Strategy::ConsistentHash,
                                Some(
                                    "sticky-sessions 粘滞键是源会话，v1 以目标一致性哈希近似（会话可重现但粘滞键不同）"
                                        .to_string(),
                                ),
                            ),
                            Some(other) => (
                                Strategy::ConsistentHash,
                                Some(format!(
                                    "未知 load-balance strategy {other:?}，按缺省 consistent-hashing 处理"
                                )),
                            ),
                        };
                    if let Some(note) = note {
                        report
                            .degraded_groups
                            .push((name.clone(), format!("组 {}: {note}", group.name)));
                    }
                    strategy
                }
                other_type => self.convert_group_type_to_strategy(other_type)?,
            };
            // RIL-009：`use:` 引用按已声明 proxy-provider 追踪——未声明
            // 引用是导入链 bug（悬空引用会让组静默少成员），显式进损失
            // 清单；已声明引用落 GroupMember::Provider，求值期按
            // provider 节点库展开（载荷未装入 = 空集 = 失效成员退出候选）
            let mut members = self.convert_proxies_to_group_members(&group.proxies);
            for provider in &group.use_providers {
                if providers.contains_key(provider) {
                    members.push(GroupMember::Provider {
                        name: provider.clone(),
                    });
                } else {
                    report.dropped_rules.push((
                        format!("proxy-groups/{}/use/{provider}", group.name),
                        format!(
                            "组 {} 引用了未声明的 provider `{provider}`（须在 proxy-providers 中声明）",
                            group.name
                        ),
                    ));
                }
            }

            // G1-9：url-test 组的测试 URL/间隔映射为 UrlTestConfig，订阅导入
            // 后即按原节奏探活选路。url 缺席或解析失败 = 不注入（宁缺不造，
            // 不发明探测目标）；Clash interval 单位是秒，原样透传（RIL-092）。
            // RIL-012：fallback 组的 url/interval 与 url-test 同语义——
            // Clash 用同一套成员探活参数判定「首位是否还活着」，原样注入
            // UrlTestConfig（interval 秒透传，RIL-092），导入后即按原节奏
            // 探活驱动按序回退
            let url_test = match group.group_type {
                ClashProxyGroupType::UrlTest | ClashProxyGroupType::Fallback => group
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

    /// 转换代理组类型为策略。relay 与 load-balance 子键分派在调用方
    /// 处理（RIL-013：relay 明确拒绝、LB 按子键分派）；此处只收四类
    /// 同语义直映——fallback 自 RIL-012 起直映 Strategy::Fallback
    /// （恒取声明序首健康成员），不再降级伪装
    fn convert_group_type_to_strategy(&self, group_type: ClashProxyGroupType) -> Result<Strategy> {
        match group_type {
            ClashProxyGroupType::Select => Ok(Strategy::Fixed),
            ClashProxyGroupType::UrlTest => Ok(Strategy::Latency),
            ClashProxyGroupType::Fallback => Ok(Strategy::Fallback),
            ClashProxyGroupType::LoadBalance | ClashProxyGroupType::Relay => Err(anyhow!(
                "load-balance/relay 由调用方按声明子键分派处理（RIL-013）"
            )),
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
    fn convert_rules_to_routing_rules(
        &self,
        rules: &[ClashRule],
        providers: &HashMap<String, ClashRuleProvider>,
        report: &mut ConversionReport,
    ) -> Result<Vec<RouteRule>> {
        let mut routing_rules = Vec::new();

        for (index, rule) in rules.iter().enumerate() {
            let name = format!("{}rule-{}", self.rule_prefix, index + 1);
            match self.convert_clash_rule(rule, providers) {
                Ok((matches, target)) => {
                    // RIL-015：进程条件只对 TUN 归因流有效——非 TUN ingress
                    // 与进程归因不可得的平台恒不命中，降级必须显式可见
                    if matches.iter().any(|m| {
                        matches!(
                            m,
                            MatchCondition::Process { .. } | MatchCondition::ProcessPath { .. }
                        )
                    }) {
                        report.degraded_rules.push((
                            name.clone(),
                            "进程条件依赖 TUN 入口进程归因（process.name/process.path 注解）——非 TUN 流与归因不可得平台恒不命中；comm 可能被内核截断，路径不可得时不以短名冒充".to_string(),
                        ));
                    }
                    routing_rules.push(RouteRule {
                        name,
                        matches,
                        target,
                    });
                }
                Err(err) => {
                    // 跳过规则必须可见：此前只记日志，规则悄悄消失等于伪装
                    // 成功；宽松模式进损失清单，严格模式据此整体拒绝（RIL-093）
                    report.dropped_rules.push((name, err.to_string()));
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
    fn convert_clash_rule(
        &self,
        rule: &ClashRule,
        providers: &HashMap<String, ClashRuleProvider>,
    ) -> Result<(Vec<MatchCondition>, String)> {
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
            // RIL-014：源端口与目标端口语义严格分离——SRC-PORT 走
            // `MatchCondition::SrcPort`（net.src_port 注解面），不再折进
            // 目标端口 Port（混淆会让两条规则互串）
            ClashRule::SrcPort { ports, target } => {
                let matches = vec![MatchCondition::SrcPort {
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
            // RIL-015：进程名 → Process（comm 口径，区分大小写不折叠）。
            // 保留而非丢弃：路由面按 `process.name` 注解求值，注解由
            // TUN 入口归因注入——非 TUN 面恒不命中、comm 可能被内核截断，
            // 这些能力缺口由调用方按 degraded_rules 显式可见（不伪装无损）
            ClashRule::ProcessName { processes, target } => {
                let matches = vec![MatchCondition::Process {
                    values: processes.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-015：进程路径 → ProcessPath（全串精确比较，不做 comm
            // 截断）；路径不可得时注解缺席恒不命中，不以短名冒充
            ClashRule::ProcessPath { paths, target } => {
                let matches = vec![MatchCondition::ProcessPath {
                    values: paths.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-014：RULE-SET → 命名引用（展开/引用策略取引用侧——载荷
            // 生命周期归 RIL-010，导入期不内联展开）。引用可追踪：指向
            // 未声明 provider 的 RULE-SET 显式报错（宽松进损失清单、严格
            // 整体拒绝），不得静默产生永不命中的悬空引用
            ClashRule::RuleSet { rulesets, target } => {
                let name = rulesets
                    .first()
                    .ok_or_else(|| anyhow!("规则集引用名为空"))?;
                if !providers.contains_key(name) {
                    return Err(anyhow!(
                        "规则集 {} 未在 rule-providers 中声明（引用不可追踪）",
                        name
                    ));
                }
                let matches = vec![MatchCondition::RuleSetRef { name: name.clone() }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-014：逻辑 AND——子条件全部命中即命中，展开为 `matches`
            // 列表（列表内即 AND 语义；嵌套 AND 平铺展平）
            ClashRule::LogicAnd { rules, target } => {
                let mut matches = Vec::new();
                for sub in rules {
                    let (sub_matches, _) = self.convert_clash_rule(sub, providers)?;
                    matches.extend(sub_matches);
                }
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-014：逻辑 OR——任一子条件命中即命中 → Any
            ClashRule::LogicOr { rules, target } => {
                let conditions = self.convert_logic_subrules(rules, providers)?;
                let matches = vec![MatchCondition::Any { conditions }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-014：逻辑 NOT——唯一子条件不命中即命中 → Not
            ClashRule::LogicNot { rules, target } => {
                if rules.len() != 1 {
                    return Err(anyhow!(
                        "NOT 逻辑规则只允许一个子条件，当前 {}",
                        rules.len()
                    ));
                }
                let conditions = self.convert_logic_subrules(rules, providers)?;
                let matches = vec![MatchCondition::Not {
                    condition: Box::new(conditions.into_iter().next().expect("NOT 必有一个子条件")),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-014：NETWORK 子条件 → Proto（目标协议面）
            ClashRule::Network { protocols, target } => {
                let matches = vec![MatchCondition::Proto {
                    protocols: protocols.clone(),
                }];
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
            // RIL-014：未知类型显式拒绝进损失清单（宽松随行/严格整体拒绝）
            ClashRule::Unknown { raw } => Err(anyhow!("规则类型不支持: {}", raw)),
            ClashRule::Match { target } => {
                let matches = vec![]; // Match 规则不需要匹配条件
                Ok((matches, format!("{}{}", self.group_prefix, target)))
            }
        }
    }

    /// OR/NOT 子条件转换（RIL-014）：每个子条件必须恰好产出一个条件
    ///（嵌套 AND 展开为多条件，无法在 OR/NOT 内单条件表达——显式拒绝，
    /// 不伪装成其它语义）。
    fn convert_logic_subrules(
        &self,
        rules: &[ClashRule],
        providers: &HashMap<String, ClashRuleProvider>,
    ) -> Result<Vec<MatchCondition>> {
        let mut conditions = Vec::new();
        for sub in rules {
            let (sub_matches, _) = self.convert_clash_rule(sub, providers)?;
            if sub_matches.len() != 1 {
                return Err(anyhow!("OR/NOT 内嵌套 AND 暂不支持（需单条件表达）"));
            }
            conditions.push(sub_matches.into_iter().next().expect("长度已校验为 1"));
        }
        Ok(conditions)
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
            ClashProxyType::Trojan | ClashProxyType::Anytls => proxy.password.is_some(),
            // Hysteria v1 认证面：password 或 auth-str 任一即有效（转换面
            // 同口径回退）；Hysteria2 仅 password
            ClashProxyType::Hysteria => proxy.password.is_some() || proxy.auth_str.is_some(),
            ClashProxyType::Hysteria2 => proxy.password.is_some(),
            ClashProxyType::Tuic => proxy.password.is_some() && proxy.uuid.is_some(),
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
            ClashProxyType::Anytls => "AnyTLS",
            ClashProxyType::Http => "HTTP",
            ClashProxyType::Https => "HTTPS",
            ClashProxyType::Socks5 => "SOCKS5",
            ClashProxyType::Snell => "Snell",
            ClashProxyType::Hysteria => "Hysteria",
            ClashProxyType::Hysteria2 => "Hysteria2",
            ClashProxyType::Tuic => "TUIC",
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
            .convert_proxy_groups_to_groups(
                &config.proxy_groups,
                &std::collections::HashMap::new(),
                &mut Default::default(),
            )
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
            .convert_proxy_groups_to_groups(
                &config.proxy_groups,
                &std::collections::HashMap::new(),
                &mut Default::default(),
            )
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
            .convert_proxies_to_egress(&config.proxies, &mut Default::default())
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
            .convert_proxies_to_egress(&config.proxies, &mut Default::default())
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
            .convert_proxies_to_egress(&config.proxies, &mut Default::default())
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
    fn vmess_packet_encoding_non_raw_refused_by_name() {
        // RIL-130：vmess 非 raw 包编码不交付（sing-vmess mux/chunk 载具未自
        // 写）——G1-6 口径：已支持类型的配置级错误点名硬错误，不静默降级
        // 成 raw、不静默丢节点；raw 取值放行（随 vless 面同键进模型）
        let yaml_content = r#"
proxies:
  - name: "vm-xudp"
    type: vmess
    server: 127.0.0.1
    port: 8443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    cipher: auto
    packet-encoding: xudp
proxy-groups: []
rules: []
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml_content).unwrap();
        let err = converter
            .convert_to_rillane(&clash)
            .expect_err("vmess 非 raw 包编码必须点名拒绝");
        let msg = format!("{err:#}");
        assert!(msg.contains("VMess packet-encoding"), "{msg}");
        assert!(msg.contains("仅 raw 可交付"), "{msg}");
        assert!(msg.contains("xudp"), "点名当前取值: {msg}");

        // raw 取值放行且入 vless 面同形键位（vmess IR 无此字段——raw 即仓
        // 内 UDP 面，不携带也不降级）
        let raw_yaml = yaml_content
            .replace("packet-encoding: xudp", "packet-encoding: raw")
            .replace("type: vmess", "type: vless");
        let clash = converter.parse(&raw_yaml).unwrap();
        let rillane = converter.convert_to_rillane(&clash).unwrap();
        match &rillane.egress[0].spec {
            EgressConfig::Vless {
                packet_encoding, ..
            } => {
                assert_eq!(packet_encoding.as_deref(), Some("raw"), "raw 应入 IR");
            }
            other => panic!("unexpected egress config: {other:?}"),
        }
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
            converter
                .convert_group_type_to_strategy(ClashProxyGroupType::Select)
                .unwrap(),
            Strategy::Fixed
        );
        assert_eq!(
            converter
                .convert_group_type_to_strategy(ClashProxyGroupType::UrlTest)
                .unwrap(),
            Strategy::Latency
        );
        // RIL-013：LB/relay 子键分派在调用方，这里直接报错不再给 Weighted
        assert!(converter
            .convert_group_type_to_strategy(ClashProxyGroupType::LoadBalance)
            .is_err());
        assert!(converter
            .convert_group_type_to_strategy(ClashProxyGroupType::Relay)
            .is_err());
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
            .convert_clash_rule(&config.rules[0], &std::collections::HashMap::new())
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

    // ---------- RIL-014：规则集与顺序 ----------

    /// 源/目标端口语义严格分离：SRC-PORT → SrcPort（net.src_port 注解面），
    /// DST-PORT → Port（目标端口）——此前两者都折进 Port 互串。
    #[test]
    fn src_port_and_dst_port_convert_distinct() {
        let yaml = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["ss-1"]

rules:
  - SRC-PORT,1000-2000,PROXY
  - DST-PORT,443,PROXY
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml).unwrap();
        let (config, report) = converter.convert_to_rillane_with_report(&clash).unwrap();
        assert!(
            report.is_empty(),
            "端口规则必须零损失: {}",
            report.summary()
        );

        let src = &config.routing.rules[0];
        assert_eq!(src.matches.len(), 1);
        assert_eq!(
            src.matches[0],
            MatchCondition::SrcPort {
                values: (1000..=2000).collect()
            },
            "SRC-PORT 必须落 SrcPort（区间展开），不得折进 Port"
        );
        let dst = &config.routing.rules[1];
        assert_eq!(
            dst.matches[0],
            MatchCondition::Port { values: vec![443] },
            "DST-PORT 落目标端口 Port"
        );
    }

    /// RULE-SET 引用策略：已声明 provider → RuleSetRef 可追踪 + 声明
    /// （url/interval 秒口径）落 routing.rule_providers；未声明引用显式
    /// 进损失清单（宽松）/整体拒绝（严格），不产生悬空引用。
    #[test]
    fn ruleset_reference_tracked_and_undeclared_reported() {
        let yaml = r#"
rule-providers:
  ads:
    type: http
    behavior: domain
    format: yaml
    url: "https://example.invalid/rules/ads.yaml"
    interval: 86400
  local-list:
    type: file
    behavior: ipcidr
    path: ./rules/local.list

proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["ss-1"]

rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,local-list,PROXY
  - RULE-SET,ghost,PROXY
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml).unwrap();

        // 宽松：前两条转 RuleSetRef，ghost 未声明进损失清单
        let (config, report) = converter.convert_to_rillane_with_report(&clash).unwrap();
        assert_eq!(
            config.routing.rules[0].matches[0],
            MatchCondition::RuleSetRef {
                name: "ads".to_string()
            }
        );
        assert_eq!(
            config.routing.rules[1].matches[0],
            MatchCondition::RuleSetRef {
                name: "local-list".to_string()
            }
        );
        assert_eq!(report.dropped_rules.len(), 1, "ghost 必须显式进清单");
        assert!(
            report.dropped_rules[0].1.contains("ghost"),
            "损失原因点名未声明来源: {:?}",
            report.dropped_rules
        );

        // 声明面：url/path/interval（Clash interval 即秒）原样带入
        let ads = config
            .routing
            .rule_providers
            .get("ads")
            .expect("声明落配置");
        assert_eq!(ads.provider_type, "http");
        assert_eq!(ads.behavior, "domain");
        assert_eq!(ads.format.as_deref(), Some("yaml"));
        assert_eq!(
            ads.url.as_deref(),
            Some("https://example.invalid/rules/ads.yaml")
        );
        assert_eq!(ads.interval_secs, Some(86400), "Clash interval 口径即秒");
        let local = config
            .routing
            .rule_providers
            .get("local-list")
            .expect("file 声明落配置");
        assert_eq!(local.path.as_deref(), Some("./rules/local.list"));
        assert_eq!(local.interval_secs, None);

        // 严格：任一损失即整体拒绝并点名
        let strict = ClashConverter::new().with_strict(true);
        let err = strict
            .convert_to_rillane_with_report(&strict.parse(yaml).unwrap())
            .expect_err("严格导入必须拒绝未声明引用");
        assert!(err.to_string().contains("ghost"), "拒绝须点名 ghost: {err}");
    }

    /// 逻辑规则 AND/OR/NOT 正确展开：AND 平铺进 matches（含 NETWORK→
    /// Proto），OR → Any，NOT → Not；首匹配顺序与 rule-N 命名保持。
    #[test]
    fn logic_rules_expand_and_or_not_in_order() {
        let yaml = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["ss-1"]

rules:
  - AND,((DOMAIN-SUFFIX,internal.corp),(DST-PORT,8443),(NETWORK,TCP)),PROXY
  - OR,((SRC-PORT,9000),(DST-PORT,53)),DIRECT
  - NOT,((GEOIP,CN)),PROXY
  - MATCH,PROXY
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml).unwrap();
        let (config, report) = converter.convert_to_rillane_with_report(&clash).unwrap();
        assert!(
            report.is_empty(),
            "逻辑规则必须零损失: {}",
            report.summary()
        );

        // AND 平铺：matches 列表内即 AND，顺序保持
        let and = &config.routing.rules[0];
        assert_eq!(and.name, "rule-1");
        assert_eq!(and.matches.len(), 3);
        assert_eq!(
            and.matches[0],
            MatchCondition::DomainSuffix {
                values: vec!["internal.corp".to_string()]
            }
        );
        assert_eq!(and.matches[1], MatchCondition::Port { values: vec![8443] });
        assert_eq!(
            and.matches[2],
            MatchCondition::Proto {
                protocols: vec!["TCP".to_string()]
            },
            "NETWORK 子条件落 Proto"
        );

        // OR → Any
        let or = &config.routing.rules[1];
        assert_eq!(
            or.matches[0],
            MatchCondition::Any {
                conditions: vec![
                    MatchCondition::SrcPort { values: vec![9000] },
                    MatchCondition::Port { values: vec![53] },
                ]
            }
        );

        // NOT → Not（唯一子条件）
        let not = &config.routing.rules[2];
        assert_eq!(
            not.matches[0],
            MatchCondition::Not {
                condition: Box::new(MatchCondition::Geoip {
                    country: "CN".to_string()
                })
            }
        );

        // MATCH 兜底最后：首匹配顺序 = 声明顺序
        assert_eq!(config.routing.rules[3].name, "rule-4");
        assert!(config.routing.rules[3].matches.is_empty(), "MATCH 无条件");
    }

    /// 未知关键条件不跳过：普通规则未知类型、逻辑规则内未知子条件，
    /// 都必须整条显式进损失清单（宽松）/严格拒绝——不做部分吸收。
    #[test]
    fn unknown_conditions_dropped_explicitly_never_skipped() {
        let yaml = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["ss-1"]

rules:
  - FUTURE-TYPE,foo,PROXY
  - AND,((MYSTERY,x),(DST-PORT,80)),PROXY
  - DOMAIN-SUFFIX,kept.example,PROXY
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml).unwrap();
        let (config, report) = converter.convert_to_rillane_with_report(&clash).unwrap();

        let dropped: Vec<&str> = report
            .dropped_rules
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(
            dropped.contains(&"rule-1"),
            "未知规则类型必须进清单: {dropped:?}"
        );
        assert!(
            dropped.contains(&"rule-2"),
            "逻辑规则内未知子条件必须整条进清单（不做部分吸收）: {dropped:?}"
        );
        // 保留面不受损，顺序保持
        assert_eq!(config.routing.rules.len(), 1);
        assert_eq!(config.routing.rules[0].name, "rule-3");
        assert_eq!(
            config.routing.rules[0].matches[0],
            MatchCondition::DomainSuffix {
                values: vec!["kept.example".to_string()]
            }
        );

        // 严格整体拒绝并点名两条
        let strict = ClashConverter::new().with_strict(true);
        let err = strict
            .convert_to_rillane_with_report(&strict.parse(yaml).unwrap())
            .expect_err("严格导入必须拒绝");
        let message = err.to_string();
        assert!(message.contains("rule-1") && message.contains("rule-2"));
    }

    /// OR/NOT 内嵌套 AND 无法单条件表达——显式拒绝，不伪装成其它语义。
    #[test]
    fn nested_and_inside_or_rejected_explicitly() {
        let yaml = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password

proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["ss-1"]

rules:
  - OR,((AND,((DOMAIN,a.example),(DST-PORT,443))),(SRC-PORT,9000)),PROXY
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml).unwrap();
        let (_, report) = converter.convert_to_rillane_with_report(&clash).unwrap();
        assert_eq!(report.dropped_rules.len(), 1);
        assert!(
            report.dropped_rules[0].1.contains("嵌套 AND"),
            "拒绝原因须点名嵌套 AND: {:?}",
            report.dropped_rules
        );
    }

    /// 规则集载荷解析：yaml payload 列表与 text 行格式，behavior 域
    /// 校验（domain 收域名族、ipcidr 只收 IP 段），未知类型/越域显式报
    /// 错点名行号。
    #[test]
    fn rule_provider_payload_yaml_text_and_behavior_bounds() {
        // yaml domain 载荷
        let yaml_payload = "payload:\n  - DOMAIN,exact.example\n  - DOMAIN-SUFFIX,ads.example\n  - DOMAIN-KEYWORD,ads\n";
        let conditions =
            parse_rule_provider_payload("domain", "yaml", yaml_payload).expect("yaml 载荷解析");
        assert_eq!(conditions.len(), 3);
        assert_eq!(
            conditions[0],
            MatchCondition::DomainFull {
                values: vec!["exact.example".to_string()]
            }
        );

        // text classical 载荷：注释/空行跳过、IP-CIDR no-resolve 标志忽略
        let text_payload = "# comment\n\nIP-CIDR,10.0.0.0/8,no-resolve\nSRC-PORT,1000-2000\n";
        let conditions =
            parse_rule_provider_payload("classical", "text", text_payload).expect("text 载荷解析");
        assert_eq!(conditions.len(), 2);
        assert_eq!(
            conditions[0],
            MatchCondition::IpCidr {
                cidrs: vec!["10.0.0.0/8".to_string()]
            }
        );
        assert_eq!(
            conditions[1],
            MatchCondition::SrcPort {
                values: (1000..=2000).collect()
            }
        );

        // behavior 越域显式拒绝：domain 行进 ipcidr 库必须报错
        let err = parse_rule_provider_payload("ipcidr", "yaml", yaml_payload)
            .expect_err("domain 行进 ipcidr 库必须报错");
        assert!(
            err.to_string().contains("behavior"),
            "越域点名 behavior: {err}"
        );

        // 未知类型点名
        let err = parse_rule_provider_payload("classical", "text", "FUTURE-TYPE,foo\n")
            .expect_err("未知类型必须报错");
        assert!(
            err.to_string().contains("FUTURE-TYPE"),
            "点名未知类型: {err}"
        );
    }

    /// RIL-015：进程名/路径规则转换到规范条件，并作为引擎降级显式报告。
    /// PROCESS-NAME → Process（comm 口径）、PROCESS-PATH → ProcessPath（全串
    /// 精确）；两条转换保留，靠 degraded_rules 声明依赖平台归因能力。
    #[test]
    fn process_rules_convert_and_report_degraded() {
        let yaml = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password
proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "ss-1"
rules:
  - PROCESS-NAME,game.exe,PROXY
  - PROCESS-PATH,/Applications/Safari.app/Contents/MacOS/Safari,PROXY
        "#;
        let converter = ClashConverter::new();
        let clash = converter.parse(yaml).unwrap();
        let (config, report) = converter.convert_to_rillane_with_report(&clash).unwrap();
        assert_eq!(config.routing.rules.len(), 2, "两条进程规则都应转换保留");
        assert_eq!(
            config.routing.rules[0].matches,
            vec![MatchCondition::Process {
                values: vec!["game.exe".to_string()]
            }]
        );
        assert_eq!(
            config.routing.rules[1].matches,
            vec![MatchCondition::ProcessPath {
                values: vec!["/Applications/Safari.app/Contents/MacOS/Safari".to_string()]
            }]
        );
        assert_eq!(report.dropped_rules.len(), 0);

        // 降级必须显式可见：两条规则都点名，理由指向进程归因能力
        let names: Vec<&str> = report
            .degraded_rules
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names, vec!["rule-1", "rule-2"], "进程规则须逐条报告");
        assert!(
            report.degraded_rules[0].1.contains("进程"),
            "降级理由须点名进程归因: {:?}",
            report.degraded_rules
        );
        // 汇总与诊断都带出降级（不得埋在无损报告里）
        assert!(report.summary().contains("降级规则 2 条"));
        let source = SourceId::new("process-report").unwrap();
        assert!(report
            .diagnostics(&source)
            .iter()
            .any(|d| d.location.pointer == "rules/rule-1"));
    }
}
