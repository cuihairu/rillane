//! 流量过滤模块
//!
//! 提供跨平台的包过滤功能，包括：
//! - 应用程序过滤
//! - 进程过滤
//! - 协议过滤
//! - 端口过滤
//! - 域名过滤

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// IP 是否为私有地址的辅助函数
fn is_ip_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            addr.is_loopback() ||
                (octets[0] == 10) ||
                (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(addr) => {
            addr.is_loopback() || (addr.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// IP 是否为链路本地地址的辅助函数
fn is_ip_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_link_local(),
        IpAddr::V6(addr) => (addr.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// 过滤配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteringConfig {
    /// 过滤模式
    pub mode: FilteringMode,
    /// 应用程序规则
    pub applications: Vec<ApplicationRule>,
    /// 进程规则
    pub processes: Vec<ProcessRule>,
    /// 协议规则
    pub protocols: Vec<ProtocolRule>,
    /// 端口规则
    pub ports: Vec<PortRule>,
    /// IP 规则
    pub ip_addresses: Vec<IpRule>,
    /// 域名规则
    pub domains: Vec<DomainRule>,
    /// 是否启用过滤
    pub enabled: bool,
}

/// 过滤模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilteringMode {
    /// 黑名单模式
    Blacklist,
    /// 白名单模式
    Whitelist,
    /// 混合模式
    Hybrid,
}

impl Default for FilteringMode {
    fn default() -> Self {
        FilteringMode::Blacklist
    }
}

/// 应用程序规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationRule {
    /// 规则名称
    pub name: String,
    /// 应用程序标识符 (包名、路径等)
    pub identifier: String,
    /// 动作
    pub action: FilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
    /// 应用程序元数据
    pub metadata: HashMap<String, String>,
}

impl ApplicationRule {
    /// 创建新的应用程序规则
    pub fn new(name: String, identifier: String, action: FilterAction) -> Self {
        Self {
            name,
            identifier,
            action,
            priority: 100,
            enabled: true,
            metadata: HashMap::new(),
        }
    }

    /// 设置优先级
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 添加元数据
    pub fn with_metadata<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// 启用/禁用
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// 进程规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRule {
    /// 规则名称
    pub name: String,
    /// 进程名称或路径
    pub process_name: String,
    /// 进程 ID (可选)
    pub process_id: Option<u32>,
    /// 用户 ID (可选)
    pub user_id: Option<u32>,
    /// 动作
    pub action: FilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
}

impl ProcessRule {
    /// 创建新的进程规则
    pub fn new(name: String, process_name: String, action: FilterAction) -> Self {
        Self {
            name,
            process_name,
            process_id: None,
            user_id: None,
            action,
            priority: 100,
            enabled: true,
        }
    }

    /// 设置进程 ID
    pub fn with_process_id(mut self, pid: u32) -> Self {
        self.process_id = Some(pid);
        self
    }

    /// 设置用户 ID
    pub fn with_user_id(mut self, uid: u32) -> Self {
        self.user_id = Some(uid);
        self
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

    /// 检查是否匹配进程
    pub fn matches_process(&self, process_name: &str, pid: Option<u32>, uid: Option<u32>) -> bool {
        if !self.enabled {
            return false;
        }

        // 检查进程名称
        if !self.process_name.is_empty() && process_name != self.process_name {
            return false;
        }

        // 检查进程 ID
        if let (Some(rule_pid), Some(pid)) = (self.process_id, pid) {
            if rule_pid != pid {
                return false;
            }
        }

        // 检查用户 ID
        if let (Some(rule_uid), Some(uid)) = (self.user_id, uid) {
            if rule_uid != uid {
                return false;
            }
        }

        true
    }
}

/// 协议规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRule {
    /// 规则名称
    pub name: String,
    /// 协议类型
    pub protocol: ProtocolType,
    /// 动作
    pub action: FilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
}

impl ProtocolRule {
    /// 创建新的协议规则
    pub fn new(name: String, protocol: ProtocolType, action: FilterAction) -> Self {
        Self {
            name,
            protocol,
            action,
            priority: 100,
            enabled: true,
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
}

/// 协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolType {
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
    /// ICMPv6
    Icmpv6,
    /// 所有协议
    All,
}

impl ProtocolType {
    /// 从 IP 协议号解析
    pub fn from_ip_protocol(protocol: u8) -> Self {
        match protocol {
            1 => ProtocolType::Icmp,
            6 => ProtocolType::Tcp,
            17 => ProtocolType::Udp,
            58 => ProtocolType::Icmpv6,
            _ => ProtocolType::All,
        }
    }

    /// 获取 IP 协议号
    pub fn as_ip_protocol(&self) -> u8 {
        match self {
            ProtocolType::Icmp => 1,
            ProtocolType::Tcp => 6,
            ProtocolType::Udp => 17,
            ProtocolType::Icmpv6 => 58,
            ProtocolType::All => 0,
        }
    }

    /// 从字符串解析
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(ProtocolType::Tcp),
            "udp" => Ok(ProtocolType::Udp),
            "icmp" => Ok(ProtocolType::Icmp),
            "icmpv6" => Ok(ProtocolType::Icmpv6),
            "all" => Ok(ProtocolType::All),
            _ => Err(anyhow!("不支持的协议类型: {}", s)),
        }
    }
}

/// 端口规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    /// 规则名称
    pub name: String,
    /// 端口范围
    pub ports: PortRange,
    /// 动作
    pub action: FilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
}

impl PortRule {
    /// 创建新的端口规则
    pub fn new(name: String, ports: PortRange, action: FilterAction) -> Self {
        Self {
            name,
            ports,
            action,
            priority: 100,
            enabled: true,
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

    /// 检查是否匹配端口
    pub fn matches_port(&self, port: u16) -> bool {
        if !self.enabled {
            return false;
        }

        self.ports.contains(port)
    }
}

/// 端口范围
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortRange {
    /// 单个端口
    Single { port: u16 },
    /// 端口范围
    Range { start: u16, end: u16 },
    /// 端口列表
    List { ports: Vec<u16> },
    /// 所有端口
    All,
}

impl PortRange {
    /// 创建单个端口
    pub fn single(port: u16) -> Self {
        PortRange::Single { port }
    }

    /// 创建端口范围
    pub fn range(start: u16, end: u16) -> Result<Self> {
        if start > end {
            return Err(anyhow!("起始端口不能大于结束端口"));
        }
        Ok(PortRange::Range { start, end })
    }

    /// 创建端口列表
    pub fn list(ports: Vec<u16>) -> Self {
        PortRange::List { ports }
    }

    /// 创建所有端口
    pub fn all() -> Self {
        PortRange::All
    }

    /// 检查是否包含端口
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortRange::Single { port: p } => *p == port,
            PortRange::Range { start, end } => port >= *start && port <= *end,
            PortRange::List { ports } => ports.contains(&port),
            PortRange::All => true,
        }
    }

    /// 获取端口数量
    pub fn count(&self) -> usize {
        match self {
            PortRange::Single { .. } => 1,
            PortRange::Range { start, end } => (*end - *start + 1) as usize,
            PortRange::List { ports } => ports.len(),
            PortRange::All => 65536,
        }
    }
}

/// IP 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    /// 规则名称
    pub name: String,
    /// IP 地址范围
    pub addresses: IpRange,
    /// 动作
    pub action: FilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
}

impl IpRule {
    /// 创建新的 IP 规则
    pub fn new(name: String, addresses: IpRange, action: FilterAction) -> Self {
        Self {
            name,
            addresses,
            action,
            priority: 100,
            enabled: true,
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

    /// 检查是否匹配 IP
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return false;
        }

        self.addresses.contains(ip)
    }
}

/// IP 地址范围
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpRange {
    /// 单个 IP
    Single { address: IpAddr },
    /// CIDR 网络
    Network { network: IpAddr, prefix: u8 },
    /// IP 范围
    Range { start: IpAddr, end: IpAddr },
    /// IP 列表
    List { addresses: Vec<IpAddr> },
    /// 预定义范围
    Predefined { predefined: PredefinedIpRange },
}

impl IpRange {
    /// 创建单个 IP
    pub fn single(address: IpAddr) -> Self {
        IpRange::Single { address }
    }

    /// 创建 CIDR 网络
    pub fn network(network: IpAddr, prefix: u8) -> Result<Self> {
        match network {
            IpAddr::V4(_) => {
                if prefix > 32 {
                    return Err(anyhow!("IPv4 前缀长度不能超过 32"));
                }
            }
            IpAddr::V6(_) => {
                if prefix > 128 {
                    return Err(anyhow!("IPv6 前缀长度不能超过 128"));
                }
            }
        }
        Ok(IpRange::Network { network, prefix })
    }

    /// 创建 IP 范围
    pub fn range(start: IpAddr, end: IpAddr) -> Result<Self> {
        if (start.is_ipv4() && end.is_ipv4()) || (start.is_ipv6() && end.is_ipv6()) {
            Ok(IpRange::Range { start, end })
        } else {
            Err(anyhow!("起始地址和结束地址必须为同一 IP 版本"))
        }
    }

    /// 创建 IP 列表
    pub fn list(addresses: Vec<IpAddr>) -> Self {
        IpRange::List { addresses }
    }

    /// 创建预定义范围
    pub fn predefined(predefined: PredefinedIpRange) -> Self {
        IpRange::Predefined { predefined }
    }

    /// 检查是否包含 IP
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            IpRange::Single { address } => *address == ip,
            IpRange::Network { network, prefix } => {
                match (network, ip) {
                    (IpAddr::V4(net), IpAddr::V4(addr)) => {
                        let netmask = super::route::ipv4_netmask(*prefix);
                        let net_u32 = u32::from_be_bytes(net.octets());
                        let addr_u32 = u32::from_be_bytes(addr.octets());
                        (net_u32 & netmask) == (addr_u32 & netmask)
                    }
                    (IpAddr::V6(net), IpAddr::V6(addr)) => {
                        let netmask = super::route::ipv6_netmask(*prefix);
                        let net_u128 = u128::from_be_bytes(net.octets());
                        let addr_u128 = u128::from_be_bytes(addr.octets());
                        (net_u128 & netmask) == (addr_u128 & netmask)
                    }
                    _ => false,
                }
            }
            IpRange::Range { start, end } => {
                match (start, end, ip) {
                    (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(addr)) => {
                        let start_u32 = u32::from_be_bytes(start.octets());
                        let end_u32 = u32::from_be_bytes(end.octets());
                        let addr_u32 = u32::from_be_bytes(addr.octets());
                        addr_u32 >= start_u32 && addr_u32 <= end_u32
                    }
                    (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(addr)) => {
                        let start_u128 = u128::from_be_bytes(start.octets());
                        let end_u128 = u128::from_be_bytes(end.octets());
                        let addr_u128 = u128::from_be_bytes(addr.octets());
                        addr_u128 >= start_u128 && addr_u128 <= end_u128
                    }
                    _ => false,
                }
            }
            IpRange::List { addresses } => addresses.contains(&ip),
            IpRange::Predefined { predefined } => predefined.contains(ip),
        }
    }

    /// 获取范围描述
    pub fn as_string(&self) -> String {
        match self {
            IpRange::Single { address } => address.to_string(),
            IpRange::Network { network, prefix } => format!("{}/{}", network, prefix),
            IpRange::Range { start, end } => format!("{}-{}", start, end),
            IpRange::List { addresses } => {
                format!("[{}]", addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "))
            }
            IpRange::Predefined { predefined } => predefined.as_string(),
        }
    }
}

/// 预定义 IP 范围
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredefinedIpRange {
    /// 私有 IP
    Private,
    /// 本地回环
    Loopback,
    /// 链路本地
    LinkLocal,
    /// 组播
    Multicast,
    /// 广播
    Broadcast,
    /// 文档用途
    Documentation,
    /// 公网 IP
    Public,
}

impl PredefinedIpRange {
    /// 检查是否包含 IP
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            PredefinedIpRange::Private => is_ip_private(&ip),
            PredefinedIpRange::Loopback => ip.is_loopback(),
            PredefinedIpRange::LinkLocal => is_ip_link_local(&ip),
            PredefinedIpRange::Multicast => ip.is_multicast(),
            PredefinedIpRange::Broadcast => match ip {
                IpAddr::V4(addr) => {
                    addr.octets()[0] == 255 && addr.octets()[1] == 255 &&
                    addr.octets()[2] == 255 && addr.octets()[3] == 255
                }
                IpAddr::V6(_) => false, // IPv6 没有广播地址
            },
            PredefinedIpRange::Documentation => {
                match ip {
                    IpAddr::V4(addr) => {
                        let octets = addr.octets();
                        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                        (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) ||
                        (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) ||
                        (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                    }
                    IpAddr::V6(addr) => {
                        let segments = addr.segments();
                        // 2001:db8::/32
                        segments[0] == 0x2001 && segments[1] == 0x0db8
                    }
                }
            }
            PredefinedIpRange::Public => {
                !(is_ip_private(&ip) || ip.is_loopback() || is_ip_link_local(&ip) ||
                  ip.is_multicast() || match ip {
                    IpAddr::V4(addr) => addr.octets()[0] == 255,
                    IpAddr::V6(_) => false,
                })
            }
        }
    }

    /// 获取描述
    pub fn as_string(&self) -> String {
        match self {
            PredefinedIpRange::Private => "private".to_string(),
            PredefinedIpRange::Loopback => "loopback".to_string(),
            PredefinedIpRange::LinkLocal => "link_local".to_string(),
            PredefinedIpRange::Multicast => "multicast".to_string(),
            PredefinedIpRange::Broadcast => "broadcast".to_string(),
            PredefinedIpRange::Documentation => "documentation".to_string(),
            PredefinedIpRange::Public => "public".to_string(),
        }
    }
}

/// 域名规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    /// 规则名称
    pub name: String,
    /// 域名模式
    pub domains: DomainPattern,
    /// 动作
    pub action: FilterAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
}

impl DomainRule {
    /// 创建新的域名规则
    pub fn new(name: String, domains: DomainPattern, action: FilterAction) -> Self {
        Self {
            name,
            domains,
            action,
            priority: 100,
            enabled: true,
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

    /// 检查是否匹配域名
    pub fn matches_domain(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }

        self.domains.matches(domain)
    }
}

/// 域名模式
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
    /// 创建完全匹配
    pub fn exact(domain: String) -> Self {
        DomainPattern::Exact { domain }
    }

    /// 创建后缀匹配
    pub fn suffix(suffix: String) -> Self {
        DomainPattern::Suffix { suffix }
    }

    /// 创建正则表达式
    pub fn regex(pattern: String) -> Result<Self> {
        // 验证正则表达式
        regex::Regex::new(&pattern)?;
        Ok(DomainPattern::Regex { pattern })
    }

    /// 创建域名列表
    pub fn list(domains: Vec<String>) -> Self {
        DomainPattern::List { domains }
    }

    /// 创建通配符
    pub fn wildcard(pattern: String) -> Self {
        DomainPattern::Wildcard { pattern }
    }

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
                // 简单的通配符实现 (只支持 * )
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

/// 过滤动作
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    /// 允许
    Allow,
    /// 拒绝
    Deny,
    /// 重定向
    Redirect { target: String },
    /// 重写
    Rewrite { target: String },
    /// 限速
    Throttle { rate: u64, burst: u64 },
}

impl FilterAction {
    /// 检查是否为允许动作
    pub fn is_allow(&self) -> bool {
        matches!(self, FilterAction::Allow)
    }

    /// 检查是否为拒绝动作
    pub fn is_deny(&self) -> bool {
        matches!(self, FilterAction::Deny)
    }
}

/// 过滤统计信息
#[derive(Debug, Clone)]
pub struct FilterStats {
    /// 总包数
    pub total_packets: u64,
    /// 允许包数
    pub allowed_packets: u64,
    /// 拒绝包数
    pub denied_packets: u64,
    /// 重定向包数
    pub redirected_packets: u64,
    /// 规则命中统计
    pub rule_hits: HashMap<String, u64>,
    /// 最后更新时间
    pub last_updated: std::time::Instant,
}

impl Default for FilterStats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            allowed_packets: 0,
            denied_packets: 0,
            redirected_packets: 0,
            rule_hits: HashMap::new(),
            last_updated: std::time::Instant::now(),
        }
    }
}

impl FilterStats {
    /// 创建新的统计
    pub fn new() -> Self {
        Self::default()
    }

    /// 更新统计
    pub fn update(&mut self) {
        self.last_updated = std::time::Instant::now();
    }

    /// 记录包处理
    pub fn record_packet(&mut self, action: &FilterAction, rule_name: Option<&str>) {
        self.total_packets += 1;

        match action {
            FilterAction::Allow => self.allowed_packets += 1,
            FilterAction::Deny => self.denied_packets += 1,
            FilterAction::Redirect { .. } | FilterAction::Rewrite { .. } | FilterAction::Throttle { .. } => {
                self.redirected_packets += 1
            }
        }

        if let Some(name) = rule_name {
            *self.rule_hits.entry(name.to_string()).or_insert(0) += 1;
        }
    }

    /// 获取命中率
    pub fn hit_rate(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            self.denied_packets as f64 / self.total_packets as f64
        }
    }

    /// 获取热门规则
    pub fn top_rules(&self, limit: usize) -> Vec<(String, u64)> {
        let mut rules: Vec<_> = self.rule_hits.iter().collect();
        rules.sort_by(|a, b| b.1.cmp(a.1));
        rules.into_iter().take(limit).map(|(name, count)| (name.clone(), *count)).collect()
    }
}

/// 包过滤器抽象
#[async_trait]
pub trait PacketFilter: Send + Sync + fmt::Debug {
    /// 获取过滤配置
    fn config(&self) -> &FilteringConfig;

    /// 获取统计信息
    fn stats(&self) -> FilterStats;

    /// 应用过滤规则
    async fn enable(&self) -> Result<()>;

    /// 禁用过滤
    async fn disable(&self) -> Result<()>;

    /// 重新加载配置
    async fn reload(&self, config: FilteringConfig) -> Result<()>;

    /// 添加规则
    async fn add_application_rule(&self, rule: ApplicationRule) -> Result<()>;
    async fn add_process_rule(&self, rule: ProcessRule) -> Result<()>;
    async fn add_protocol_rule(&self, rule: ProtocolRule) -> Result<()>;
    async fn add_port_rule(&self, rule: PortRule) -> Result<()>;
    async fn add_ip_rule(&self, rule: IpRule) -> Result<()>;
    async fn add_domain_rule(&self, rule: DomainRule) -> Result<()>;

    /// 删除规则
    async fn remove_rule(&self, rule_type: &str, name: &str) -> Result<()>;

    /// 启用/禁用规则
    async fn enable_rule(&self, rule_type: &str, name: &str, enabled: bool) -> Result<()>;

    /// 过滤包
    async fn filter_packet(&self, packet_info: &PacketInfo) -> Result<FilterResult>;

    /// 监控过滤事件
    async fn monitor_events(&self) -> Result<Box<dyn FilterMonitor>>;
}

/// 包信息
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// 源 IP
    pub src_ip: IpAddr,
    /// 目标 IP
    pub dst_ip: IpAddr,
    /// 源端口
    pub src_port: Option<u16>,
    /// 目标端口
    pub dst_port: Option<u16>,
    /// 协议
    pub protocol: ProtocolType,
    /// 进程 ID (可选)
    pub process_id: Option<u32>,
    /// 用户 ID (可选)
    pub user_id: Option<u32>,
    /// 应用程序标识 (可选)
    pub application: Option<String>,
    /// 域名 (可选)
    pub domain: Option<String>,
    /// 包长度
    pub length: usize,
    /// 时间戳
    pub timestamp: std::time::Instant,
}

impl PacketInfo {
    /// 创建新的包信息
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: ProtocolType,
        length: usize,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            protocol,
            process_id: None,
            user_id: None,
            application: None,
            domain: None,
            length,
            timestamp: std::time::Instant::now(),
        }
    }

    /// 设置端口
    pub fn with_ports(mut self, src_port: u16, dst_port: u16) -> Self {
        self.src_port = Some(src_port);
        self.dst_port = Some(dst_port);
        self
    }

    /// 设置进程信息
    pub fn with_process(mut self, pid: u32, uid: u32) -> Self {
        self.process_id = Some(pid);
        self.user_id = Some(uid);
        self
    }

    /// 设置应用程序
    pub fn with_application<S: Into<String>>(mut self, app: S) -> Self {
        self.application = Some(app.into());
        self
    }

    /// 设置域名
    pub fn with_domain<S: Into<String>>(mut self, domain: S) -> Self {
        self.domain = Some(domain.into());
        self
    }
}

/// 过滤结果
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// 动作
    pub action: FilterAction,
    /// 匹配的规则名称
    pub rule_name: Option<String>,
    /// 拒绝原因
    pub reason: Option<String>,
    /// 是否命中
    pub matched: bool,
}

impl FilterResult {
    /// 创建允许结果
    pub fn allow() -> Self {
        Self {
            action: FilterAction::Allow,
            rule_name: None,
            reason: None,
            matched: false,
        }
    }

    /// 创建拒绝结果
    pub fn deny(rule_name: String, reason: String) -> Self {
        Self {
            action: FilterAction::Deny,
            rule_name: Some(rule_name),
            reason: Some(reason),
            matched: true,
        }
    }

    /// 创建重定向结果
    pub fn redirect(target: String, rule_name: String) -> Self {
        Self {
            action: FilterAction::Redirect { target },
            rule_name: Some(rule_name),
            reason: None,
            matched: true,
        }
    }

    /// 检查是否允许
    pub fn is_allowed(&self) -> bool {
        self.action.is_allow()
    }
}

/// 过滤监控器
#[async_trait]
pub trait FilterMonitor: Send + Sync {
    /// 获取下一个事件
    async fn next_event(&mut self) -> Result<FilterEvent>;
}

/// 过滤事件
#[derive(Debug, Clone)]
pub enum FilterEvent {
    /// 规则命中
    RuleHit {
        rule_type: String,
        rule_name: String,
        packet_info: PacketInfo,
        action: FilterAction,
    },
    /// 规则添加
    RuleAdded {
        rule_type: String,
        rule_name: String,
    },
    /// 规则删除
    RuleRemoved {
        rule_type: String,
        rule_name: String,
    },
    /// 配置重载
    ConfigReload,
    /// 错误
    Error(String),
}

/// 默认过滤配置
pub fn default_filtering_config() -> FilteringConfig {
    FilteringConfig {
        mode: FilteringMode::Blacklist,
        applications: vec![],
        processes: vec![],
        protocols: vec![],
        ports: vec![],
        ip_addresses: vec![],
        domains: vec![],
        enabled: false,
    }
}