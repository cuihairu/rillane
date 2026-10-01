//! DNS 处理模块
//!
//! 提供跨平台的 DNS 服务，包括：
//! - DNS 查询代理
//! - DNS 缓存
//! - DNS 劫持
//! - 自定义 DNS 规则
//! - DoH/DoT 支持

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::info;

/// DNS 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS 模式
    pub mode: DnsMode,
    /// DNS 服务器列表
    pub servers: Vec<DnsServer>,
    /// 缓存配置
    pub cache: Option<DnsCacheConfig>,
    /// 过滤规则
    pub filters: Vec<DnsFilterRule>,
    /// 是否启用 DNS
    pub enabled: bool,
    /// 本地监听端口
    pub local_port: u16,
    /// 本地监听地址
    pub local_address: IpAddr,
    /// 超时时间
    pub timeout: Duration,
    /// 重试次数
    pub retries: u32,
}

/// DNS 模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DnsMode {
    /// 直连模式
    Direct,
    /// 代理模式
    #[default]
    Proxy,
    /// 混合模式
    Hybrid,
    /// 劫持模式
    Hijack,
}

/// DNS 服务器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServer {
    /// 服务器名称
    pub name: String,
    /// 服务器地址
    pub address: SocketAddr,
    /// 服务器类型
    pub server_type: DnsServerType,
    /// 优先级
    pub priority: u8,
    /// 是否启用
    pub enabled: bool,
    /// 权重 (用于负载均衡)
    pub weight: u8,
    /// TLS 配置 (DoT/DoH)
    pub tls_config: Option<TlsConfig>,
}

impl DnsServer {
    /// 创建新的 DNS 服务器
    pub fn new(name: String, address: SocketAddr, server_type: DnsServerType) -> Self {
        Self {
            name,
            address,
            server_type,
            priority: 100,
            enabled: true,
            weight: 1,
            tls_config: None,
        }
    }

    /// 设置优先级
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// 设置权重
    pub fn with_weight(mut self, weight: u8) -> Self {
        self.weight = weight;
        self
    }

    /// 启用/禁用
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// 设置 TLS 配置
    pub fn with_tls(mut self, tls_config: TlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow!("DNS 服务器名称不能为空"));
        }

        // 验证 TLS 配置
        if matches!(self.server_type, DnsServerType::Dot | DnsServerType::Doh)
            && self.tls_config.is_none()
        {
            return Err(anyhow!("DoT/DoH 服务器需要 TLS 配置"));
        }

        Ok(())
    }
}

/// DNS 服务器类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DnsServerType {
    /// 传统 DNS (UDP)
    Udp,
    /// 传统 DNS (TCP)
    Tcp,
    /// DNS over TLS
    Dot,
    /// DNS over HTTPS
    Doh,
    /// DNS over QUIC
    Doq,
}

impl DnsServerType {
    /// 获取默认端口
    pub fn default_port(&self) -> u16 {
        match self {
            DnsServerType::Udp => 53,
            DnsServerType::Tcp => 53,
            DnsServerType::Dot => 853,
            DnsServerType::Doh => 443,
            DnsServerType::Doq => 784,
        }
    }

    /// 检查是否加密
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            DnsServerType::Dot | DnsServerType::Doh | DnsServerType::Doq
        )
    }

    /// 检查是否使用 HTTP
    pub fn uses_http(&self) -> bool {
        matches!(self, DnsServerType::Doh)
    }
}

/// TLS 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// 服务器名称 (SNI)
    pub server_name: String,
    /// CA 证书路径
    pub ca_cert_path: Option<String>,
    /// 客户端证书路径
    pub client_cert_path: Option<String>,
    /// 客户端私钥路径
    pub client_key_path: Option<String>,
    /// 验证服务器证书
    pub verify_cert: bool,
    /// TLS 版本
    pub min_version: Option<TlsVersion>,
}

impl TlsConfig {
    /// 创建新的 TLS 配置
    pub fn new(server_name: String) -> Self {
        Self {
            server_name,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            verify_cert: true,
            min_version: None,
        }
    }

    /// 设置 CA 证书
    pub fn with_ca_cert<S: Into<String>>(mut self, path: S) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// 设置客户端证书
    pub fn with_client_cert<S: Into<String>>(mut self, cert: S, key: S) -> Self {
        self.client_cert_path = Some(cert.into());
        self.client_key_path = Some(key.into());
        self
    }

    /// 启用/禁用证书验证
    pub fn with_verify_cert(mut self, verify: bool) -> Self {
        self.verify_cert = verify;
        self
    }

    /// 设置最小 TLS 版本
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_version = Some(version);
        self
    }
}

/// TLS 版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// TLS 1.2
    V1_2,
    /// TLS 1.3
    V1_3,
}

/// DNS 缓存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheConfig {
    /// 最大缓存条目数
    pub max_entries: usize,
    /// 缓存 TTL (秒)
    pub default_ttl: u64,
    /// 最小 TTL (秒)
    pub min_ttl: u64,
    /// 最大 TTL (秒)
    pub max_ttl: u64,
    /// 是否启用负缓存
    pub enable_negative_cache: bool,
    /// 负缓存 TTL (秒)
    pub negative_ttl: u64,
    /// 是否持久化缓存
    pub persistent: bool,
    /// 缓存文件路径
    pub cache_file: Option<String>,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            default_ttl: 300,
            min_ttl: 60,
            max_ttl: 86400,
            enable_negative_cache: true,
            negative_ttl: 300,
            persistent: false,
            cache_file: None,
        }
    }
}

/// DNS 过滤规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterRule {
    /// 规则名称
    pub name: String,
    /// 域名模式
    pub pattern: DomainPattern,
    /// 动作
    pub action: DnsFilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
    /// 记录日志
    pub log: bool,
}

impl DnsFilterRule {
    /// 创建新的过滤规则
    pub fn new(name: String, pattern: DomainPattern, action: DnsFilterAction) -> Self {
        Self {
            name,
            pattern,
            action,
            priority: 100,
            enabled: true,
            log: true,
        }
    }

    /// 设置优先级
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 启用/禁用
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// 设置日志
    pub fn with_log(mut self, log: bool) -> Self {
        self.log = log;
        self
    }

    /// 检查是否匹配域名
    pub fn matches(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }

        self.pattern.matches(domain)
    }
}

/// 域名模式 (复用 filter.rs 中的定义)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainPattern {
    /// 完全匹配
    Exact { domain: String },
    /// 后缀匹配
    Suffix { suffix: String },
    /// 正则表达式
    Regex { pattern: String },
    /// 域名列表
    List { domains: Vec<String> },
    /// 通配符
    Wildcard { pattern: String },
}

impl DomainPattern {
    /// 检查是否匹配域名
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainPattern::Exact { domain: d } => d == domain,
            DomainPattern::Suffix { suffix } => domain.ends_with(suffix),
            DomainPattern::Regex { pattern } => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(domain)
                } else {
                    false
                }
            }
            DomainPattern::List { domains } => domains.contains(&domain.to_string()),
            DomainPattern::Wildcard { pattern } => {
                let pattern_parts: Vec<&str> = pattern.split('*').collect();
                if pattern_parts.len() == 2 {
                    domain.starts_with(pattern_parts[0]) && domain.ends_with(pattern_parts[1])
                } else if pattern_parts.len() == 1 {
                    domain == pattern
                } else {
                    false
                }
            }
        }
    }
}

/// DNS 过滤动作
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFilterAction {
    /// 允许
    Allow,
    /// 拒绝
    Deny,
    /// 重定向到其他域名
    Redirect { domain: String },
    /// 修改应答
    Modify {
        /// 替换的 IP 地址
        replace_ips: Vec<IpAddr>,
        /// 添加的 IP 地址
        add_ips: Vec<IpAddr>,
        /// 删除的 IP 地址
        remove_ips: Vec<IpAddr>,
    },
    /// 阻塞 (返回 NXDOMAIN)
    Block,
}

/// DNS 记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordType {
    /// A 记录
    A,
    /// AAAA 记录
    Aaaa,
    /// CNAME 记录
    Cname,
    /// MX 记录
    Mx,
    /// TXT 记录
    Txt,
    /// NS 记录
    Ns,
    /// SOA 记录
    Soa,
    /// PTR 记录
    Ptr,
    /// SRV 记录
    Srv,
    /// 所有记录
    All,
}

impl DnsRecordType {
    /// 从数值解析
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => DnsRecordType::A,
            28 => DnsRecordType::Aaaa,
            5 => DnsRecordType::Cname,
            15 => DnsRecordType::Mx,
            16 => DnsRecordType::Txt,
            2 => DnsRecordType::Ns,
            6 => DnsRecordType::Soa,
            12 => DnsRecordType::Ptr,
            33 => DnsRecordType::Srv,
            255 => DnsRecordType::All,
            _ => DnsRecordType::All,
        }
    }

    /// 转换为数值
    pub fn as_u16(&self) -> u16 {
        match self {
            DnsRecordType::A => 1,
            DnsRecordType::Aaaa => 28,
            DnsRecordType::Cname => 5,
            DnsRecordType::Mx => 15,
            DnsRecordType::Txt => 16,
            DnsRecordType::Ns => 2,
            DnsRecordType::Soa => 6,
            DnsRecordType::Ptr => 12,
            DnsRecordType::Srv => 33,
            DnsRecordType::All => 255,
        }
    }

    /// 检查是否为 IP 地址类型
    pub fn is_ip_type(&self) -> bool {
        matches!(self, DnsRecordType::A | DnsRecordType::Aaaa)
    }
}

/// DNS 记录
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// 域名
    pub domain: String,
    /// 记录类型
    pub record_type: DnsRecordType,
    /// TTL
    pub ttl: u32,
    /// 数据
    pub data: DnsRecordData,
    /// 创建时间
    pub created_at: Instant,
    /// 过期时间
    pub expires_at: Option<Instant>,
}

impl DnsRecord {
    /// 创建新的 DNS 记录
    pub fn new(domain: String, record_type: DnsRecordType, ttl: u32, data: DnsRecordData) -> Self {
        let expires_at = if ttl > 0 {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        } else {
            None
        };

        Self {
            domain,
            record_type,
            ttl,
            data,
            created_at: Instant::now(),
            expires_at,
        }
    }

    /// 检查是否过期
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() > expires_at
        } else {
            false
        }
    }

    /// 刷新 TTL
    pub fn refresh_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
        self.expires_at = if ttl > 0 {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        } else {
            None
        };
    }

    /// 获取字符串表示
    pub fn as_string(&self) -> String {
        match &self.data {
            DnsRecordData::A(addr) => addr.to_string(),
            DnsRecordData::Aaaa(addr) => addr.to_string(),
            DnsRecordData::Cname(name) => name.clone(),
            DnsRecordData::Mx {
                preference,
                exchange,
            } => {
                format!("{} {}", preference, exchange)
            }
            DnsRecordData::Txt(data) => String::from_utf8_lossy(data).to_string(),
            DnsRecordData::Ns(name) => name.clone(),
            DnsRecordData::Ptr(name) => name.clone(),
            DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                format!("{} {} {} {}", priority, weight, port, target)
            }
            DnsRecordData::Unknown(data) => format!("{:?}", data),
        }
    }
}

/// DNS 记录数据
#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// A 记录
    A(Ipv4Addr),
    /// AAAA 记录
    Aaaa(Ipv6Addr),
    /// CNAME 记录
    Cname(String),
    /// MX 记录
    Mx { preference: u16, exchange: String },
    /// TXT 记录
    Txt(Vec<u8>),
    /// NS 讲录
    Ns(String),
    /// SOA 记录 (简化)
    Ptr(String),
    /// SRV 记录
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// 未知类型
    Unknown(Vec<u8>),
}

/// DNS 查询
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// 查询 ID
    pub id: u16,
    /// 域名
    pub domain: String,
    /// 记录类型
    pub record_type: DnsRecordType,
    /// 查询类型
    pub query_type: DnsQueryType,
    /// 客户端 IP
    pub client_ip: IpAddr,
    /// 查询时间
    pub timestamp: Instant,
}

/// DNS 查询类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryType {
    /// 标准查询
    Standard,
    /// 反向查询
    Inverse,
    /// 递归查询
    Recursive,
}

/// DNS 应答
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// 对应的查询
    pub query_id: u16,
    /// 响应码
    pub response_code: DnsResponseCode,
    /// 记录列表
    pub records: Vec<DnsRecord>,
    /// 权威记录
    pub authority_records: Vec<DnsRecord>,
    /// 额外记录
    pub additional_records: Vec<DnsRecord>,
    /// TTL
    pub ttl: u32,
    /// 响应时间
    pub response_time: Duration,
    /// 服务器地址
    pub server: SocketAddr,
}

/// DNS 响应码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseCode {
    /// 成功
    NoError,
    /// 格式错误
    FormErr,
    /// 服务器失败
    ServFail,
    /// 域名不存在
    NXDomain,
    /// 不支持的操作
    NotImp,
    /// 拒绝查询
    Refused,
    /// 其他错误
    Other(u8),
}

impl DnsResponseCode {
    /// 从数值解析
    pub fn from_u8(code: u8) -> Self {
        match code {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormErr,
            2 => DnsResponseCode::ServFail,
            3 => DnsResponseCode::NXDomain,
            4 => DnsResponseCode::NotImp,
            5 => DnsResponseCode::Refused,
            _ => DnsResponseCode::Other(code),
        }
    }

    /// 转换为数值
    pub fn as_u8(&self) -> u8 {
        match self {
            DnsResponseCode::NoError => 0,
            DnsResponseCode::FormErr => 1,
            DnsResponseCode::ServFail => 2,
            DnsResponseCode::NXDomain => 3,
            DnsResponseCode::NotImp => 4,
            DnsResponseCode::Refused => 5,
            DnsResponseCode::Other(code) => *code,
        }
    }

    /// 检查是否为成功
    pub fn is_success(&self) -> bool {
        matches!(self, DnsResponseCode::NoError)
    }
}

/// DNS 统计信息
#[derive(Debug, Clone)]
pub struct DnsStats {
    /// 总查询数
    pub total_queries: u64,
    /// 缓存命中数
    pub cache_hits: u64,
    /// 缓存未命中数
    pub cache_misses: u64,
    /// 过滤命中数
    pub filter_hits: u64,
    /// 成功响应数
    pub successful_responses: u64,
    /// 失败响应数
    pub failed_responses: u64,
    /// 平均响应时间 (毫秒)
    pub average_response_time_ms: f64,
    /// 各服务器查询数
    pub server_queries: HashMap<String, u64>,
    /// 各记录类型查询数
    pub record_type_queries: HashMap<DnsRecordType, u64>,
    /// 最后更新时间
    pub last_updated: Instant,
}

impl Default for DnsStats {
    fn default() -> Self {
        Self {
            total_queries: 0,
            cache_hits: 0,
            cache_misses: 0,
            filter_hits: 0,
            successful_responses: 0,
            failed_responses: 0,
            average_response_time_ms: 0.0,
            server_queries: HashMap::new(),
            record_type_queries: HashMap::new(),
            last_updated: Instant::now(),
        }
    }
}

impl DnsStats {
    /// 创建新的统计
    pub fn new() -> Self {
        Self::default()
    }

    /// 更新统计
    pub fn update(&mut self) {
        self.last_updated = Instant::now();
    }

    /// 记录查询
    pub fn record_query(&mut self, query: &DnsQuery) {
        self.total_queries += 1;
        *self
            .record_type_queries
            .entry(query.record_type)
            .or_insert(0) += 1;
    }

    /// 记录缓存命中
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    /// 记录缓存未命中
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    /// 记录过滤命中
    pub fn record_filter_hit(&mut self, _rule_name: &str) {
        self.filter_hits += 1;
        // 这里可以扩展为按规则名统计
    }

    /// 记录响应
    pub fn record_response(&mut self, response: &DnsResponse) {
        if response.response_code.is_success() {
            self.successful_responses += 1;
        } else {
            self.failed_responses += 1;
        }

        // 记录服务器查询
        let server_key = response.server.to_string();
        *self.server_queries.entry(server_key).or_insert(0) += 1;

        // 更新平均响应时间
        let response_time_ms = response.response_time.as_millis() as f64;
        self.average_response_time_ms = (self.average_response_time_ms
            * (self.successful_responses - 1) as f64
            + response_time_ms)
            / self.successful_responses as f64;
    }

    /// 获取缓存命中率
    pub fn cache_hit_rate(&self) -> f64 {
        if self.cache_hits + self.cache_misses == 0 {
            0.0
        } else {
            self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64
        }
    }

    /// 获取成功率
    pub fn success_rate(&self) -> f64 {
        if self.successful_responses + self.failed_responses == 0 {
            0.0
        } else {
            self.successful_responses as f64
                / (self.successful_responses + self.failed_responses) as f64
        }
    }
}

/// DNS 处理器抽象
#[async_trait]
pub trait DnsHandler: Send + Sync + fmt::Debug {
    /// 获取 DNS 配置
    fn config(&self) -> &DnsConfig;

    /// 获取统计信息
    fn stats(&self) -> DnsStats;

    /// 启动 DNS 服务
    async fn start(&self) -> Result<()>;

    /// 停止 DNS 服务
    async fn stop(&self) -> Result<()>;

    /// 处理 DNS 查询
    async fn handle_query(&self, query: DnsQuery) -> Result<DnsResponse>;

    /// 添加 DNS 服务器
    async fn add_server(&self, server: DnsServer) -> Result<()>;

    /// 删除 DNS 服务器
    async fn remove_server(&self, name: &str) -> Result<()>;

    /// 添加过滤规则
    async fn add_filter_rule(&self, rule: DnsFilterRule) -> Result<()>;

    /// 删除过滤规则
    async fn remove_filter_rule(&self, name: &str) -> Result<()>;

    /// 清空缓存
    async fn clear_cache(&self) -> Result<()>;

    /// 强制刷新缓存
    async fn flush_cache(&self) -> Result<()>;

    /// 监控 DNS 事件
    async fn monitor_events(&self) -> Result<Box<dyn DnsMonitor>>;
}

/// DNS 监控器
#[async_trait]
pub trait DnsMonitor: Send + Sync {
    /// 获取下一个事件
    async fn next_event(&mut self) -> Result<DnsEvent>;
}

/// DNS 事件
#[derive(Debug, Clone)]
pub enum DnsEvent {
    /// 查询事件
    Query(DnsQuery),
    /// 响应事件
    Response(DnsResponse),
    /// 缓存事件
    Cache { domain: String, action: CacheAction },
    /// 过滤事件
    Filter {
        rule_name: String,
        domain: String,
        action: DnsFilterAction,
    },
    /// 错误事件
    Error(String),
}

/// 缓存动作
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheAction {
    /// 添加到缓存
    Add,
    /// 从缓存删除
    Remove,
    /// 缓存过期
    Expire,
    /// 缓存刷新
    Refresh,
}

/// 便捷函数
pub fn parse_dns_server(s: &str) -> Result<DnsServer> {
    if let Some((name, addr_str)) = s.split_once('=') {
        let address: SocketAddr = addr_str
            .parse()
            .with_context(|| format!("无效的 DNS 服务器地址: {}", addr_str))?;

        // 根据端口猜测服务器类型
        let server_type = match address.port() {
            53 => DnsServerType::Udp,
            853 => DnsServerType::Dot,
            443 => DnsServerType::Doh,
            784 => DnsServerType::Doq,
            _ => DnsServerType::Udp, // 默认
        };

        Ok(DnsServer::new(name.to_string(), address, server_type))
    } else {
        Err(anyhow!("无效的 DNS 服务器格式: {}", s))
    }
}

/// 默认的 DNS 服务器
pub fn default_dns_servers() -> Vec<DnsServer> {
    vec![
        DnsServer::new(
            "Google".to_string(),
            "8.8.8.8:53".parse().unwrap(),
            DnsServerType::Udp,
        ),
        DnsServer::new(
            "Cloudflare".to_string(),
            "1.1.1.1:53".parse().unwrap(),
            DnsServerType::Udp,
        ),
        DnsServer::new(
            "AliDNS".to_string(),
            "223.5.5.5:53".parse().unwrap(),
            DnsServerType::Udp,
        ),
    ]
}

/// 默认的过滤规则
pub fn default_dns_filters() -> Vec<DnsFilterRule> {
    vec![
        DnsFilterRule::new(
            "block_ads".to_string(),
            DomainPattern::Suffix {
                suffix: ".doubleclick.net".to_string(),
            },
            DnsFilterAction::Block,
        ),
        DnsFilterRule::new(
            "block_tracking".to_string(),
            DomainPattern::Suffix {
                suffix: ".google-analytics.com".to_string(),
            },
            DnsFilterAction::Block,
        ),
    ]
}

/// DNS 处理器工厂
pub struct DnsHandlerFactory;

impl DnsHandlerFactory {
    /// 创建平台特定的 DNS 处理器
    pub async fn create(config: DnsConfig) -> Result<Box<dyn DnsHandler>> {
        info!(target: "seep::dns", mode = ?config.mode, "创建 DNS 处理器");

        #[cfg(target_os = "linux")]
        {
            // TODO: 平台特定实现待完成
            Err(anyhow!("Linux DNS 处理器待实现"))
        }

        #[cfg(target_os = "macos")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("macOS DNS 处理器待实现"));
        }

        #[cfg(target_os = "windows")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("Windows DNS 处理器待实现"));
        }

        #[cfg(target_os = "android")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("Android DNS 处理器待实现"));
        }

        #[cfg(target_os = "ios")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("iOS DNS 处理器待实现"));
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "android",
            target_os = "ios"
        )))]
        {
            return Err(anyhow!("不支持的平台"));
        }
    }
}
