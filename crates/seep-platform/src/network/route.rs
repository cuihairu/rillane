//! 路由管理模块
//!
//! 提供跨平台的系统路由管理，包括：
//! - 路由表增删改查
//! - 路由策略配置
//! - 路由优先级管理
//! - 路由规则匹配

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::info;

/// IP 是否为私有地址的辅助函数
fn is_ip_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            addr.is_loopback()
                || (octets[0] == 10)
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(addr) => addr.is_loopback() || (addr.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// IP 是否为链路本地地址的辅助函数
fn is_ip_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_link_local(),
        IpAddr::V6(addr) => (addr.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// 路由配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// 路由模式
    pub mode: RoutingMode,
    /// 默认网关
    pub default_gateway: Option<IpAddr>,
    /// DNS 服务器
    pub dns_servers: Vec<IpAddr>,
    /// 路由规则
    pub rules: Vec<RouteRule>,
    /// 绕过规则
    pub bypass_rules: Vec<BypassRule>,
    /// 是否启用路由
    pub enabled: bool,
}

/// 路由模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RoutingMode {
    /// 全局路由
    #[default]
    Global,
    /// 分应用路由
    Application,
    /// 域名路由
    Domain,
    /// IP 路由
    Ip,
    /// 混合路由
    Hybrid,
}

/// 路由规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    /// 规则名称
    pub name: String,
    /// 规则优先级 (数字越小优先级越高)
    pub priority: i32,
    /// 目标网络
    pub destination: RouteDestination,
    /// 网关
    pub gateway: Option<IpAddr>,
    /// 接口
    pub interface: Option<String>,
    /// 路由类型
    pub route_type: RouteType,
    /// 指标
    pub metric: Option<u32>,
    /// 是否启用
    pub enabled: bool,
}

impl RouteRule {
    /// 创建新的路由规则
    pub fn new(name: String, destination: RouteDestination) -> Self {
        Self {
            name,
            priority: 100,
            destination,
            gateway: None,
            interface: None,
            route_type: RouteType::Unicast,
            metric: None,
            enabled: true,
        }
    }

    /// 设置优先级
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 设置网关
    pub fn with_gateway(mut self, gateway: IpAddr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// 设置接口
    pub fn with_interface<S: Into<String>>(mut self, interface: S) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// 设置路由类型
    pub fn with_type(mut self, route_type: RouteType) -> Self {
        self.route_type = route_type;
        self
    }

    /// 设置指标
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// 启用/禁用
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// 验证规则
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow!("路由规则名称不能为空"));
        }

        self.destination.validate()?;

        // 验证网关和目标网络的兼容性
        if let Some(gateway) = self.gateway {
            if !self.destination.is_compatible_with(gateway) {
                return Err(anyhow!(
                    "网关 {} 与目标网络 {:?} 不兼容",
                    gateway,
                    self.destination
                ));
            }
        }

        Ok(())
    }
}

/// 路由目标
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteDestination {
    /// IPv4 网络
    Ipv4Network { network: Ipv4Addr, prefix: u8 },
    /// IPv6 网络
    Ipv6Network { network: Ipv6Addr, prefix: u8 },
    /// 默认路由
    #[default]
    Default,
    /// 主机路由
    Host { address: IpAddr },
}

impl RouteDestination {
    /// 创建 IPv4 网络
    pub fn ipv4(network: Ipv4Addr, prefix: u8) -> Result<Self> {
        if prefix > 32 {
            return Err(anyhow!("IPv4 前缀长度不能超过 32"));
        }
        Ok(RouteDestination::Ipv4Network { network, prefix })
    }

    /// 创建 IPv6 网络
    pub fn ipv6(network: Ipv6Addr, prefix: u8) -> Result<Self> {
        if prefix > 128 {
            return Err(anyhow!("IPv6 前缀长度不能超过 128"));
        }
        Ok(RouteDestination::Ipv6Network { network, prefix })
    }

    /// 创建主机路由
    pub fn host(address: IpAddr) -> Self {
        RouteDestination::Host { address }
    }

    /// 验证目标
    pub fn validate(&self) -> Result<()> {
        match self {
            RouteDestination::Ipv4Network { prefix, .. } => {
                if *prefix > 32 {
                    return Err(anyhow!("IPv4 前缀长度不能超过 32"));
                }
            }
            RouteDestination::Ipv6Network { prefix, .. } => {
                if *prefix > 128 {
                    return Err(anyhow!("IPv6 前缀长度不能超过 128"));
                }
            }
            RouteDestination::Default | RouteDestination::Host { .. } => {}
        }
        Ok(())
    }

    /// 检查与网关的兼容性
    pub fn is_compatible_with(&self, gateway: IpAddr) -> bool {
        match (self, gateway) {
            (RouteDestination::Ipv4Network { .. }, IpAddr::V4(_)) => true,
            (RouteDestination::Ipv6Network { .. }, IpAddr::V6(_)) => true,
            (RouteDestination::Host { address }, gateway) => match address {
                IpAddr::V4(_) => gateway.is_ipv4(),
                IpAddr::V6(_) => gateway.is_ipv6(),
            },
            (RouteDestination::Default, _) => true,
            _ => false,
        }
    }

    /// 检查地址是否匹配
    pub fn matches(&self, address: IpAddr) -> bool {
        match (self, address) {
            (RouteDestination::Ipv4Network { network, prefix }, IpAddr::V4(addr)) => {
                let netmask = ipv4_netmask(*prefix);
                u32::from_be_bytes(network.octets()) & netmask
                    == u32::from_be_bytes(addr.octets()) & netmask
            }
            (RouteDestination::Ipv6Network { network, prefix }, IpAddr::V6(addr)) => {
                let netmask = ipv6_netmask(*prefix);
                let network_u128 = u128::from_be_bytes(network.octets());
                let addr_u128 = u128::from_be_bytes(addr.octets());
                network_u128 & netmask == addr_u128 & netmask
            }
            (RouteDestination::Host { address }, addr) => *address == addr,
            (RouteDestination::Default, _) => true,
            _ => false,
        }
    }

    /// 获取字符串表示
    pub fn as_string(&self) -> String {
        match self {
            RouteDestination::Ipv4Network { network, prefix } => {
                format!("{}/{}", network, prefix)
            }
            RouteDestination::Ipv6Network { network, prefix } => {
                format!("{}/{}", network, prefix)
            }
            RouteDestination::Default => "default".to_string(),
            RouteDestination::Host { address } => address.to_string(),
        }
    }
}

/// 路由类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RouteType {
    /// 单播路由
    #[default]
    Unicast,
    /// 多播路由
    Multicast,
    /// 广播路由
    Broadcast,
    /// 任何路由
    Any,
}

/// 绕过规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRule {
    /// 规则名称
    pub name: String,
    /// 绕过条件
    pub condition: BypassCondition,
    /// 动作
    pub action: BypassAction,
    /// 优先级
    pub priority: i32,
    /// 是否启用
    pub enabled: bool,
}

impl BypassRule {
    /// 创建新的绕过规则
    pub fn new(name: String, condition: BypassCondition, action: BypassAction) -> Self {
        Self {
            name,
            condition,
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

    /// 检查是否匹配
    pub fn matches(&self, address: IpAddr, interface: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }

        match &self.condition {
            BypassCondition::IpRange { start, end } => match (address, start, end) {
                (IpAddr::V4(addr), IpAddr::V4(start), IpAddr::V4(end)) => {
                    let addr_u32 = u32::from_be_bytes(addr.octets());
                    let start_u32 = u32::from_be_bytes(start.octets());
                    let end_u32 = u32::from_be_bytes(end.octets());
                    addr_u32 >= start_u32 && addr_u32 <= end_u32
                }
                (IpAddr::V6(addr), IpAddr::V6(start), IpAddr::V6(end)) => {
                    let addr_u128 = u128::from_be_bytes(addr.octets());
                    let start_u128 = u128::from_be_bytes(start.octets());
                    let end_u128 = u128::from_be_bytes(end.octets());
                    addr_u128 >= start_u128 && addr_u128 <= end_u128
                }
                _ => false,
            },
            BypassCondition::Interface { name } => interface.map(|i| i == name).unwrap_or(false),
            BypassCondition::PrivateIp => {
                is_ip_private(&address) || address.is_loopback() || is_ip_link_local(&address)
            }
            BypassCondition::LanIp => is_ip_private(&address) || is_ip_link_local(&address),
        }
    }
}

/// 绕过条件
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BypassCondition {
    /// IP 范围
    IpRange { start: IpAddr, end: IpAddr },
    /// 接口名称
    Interface { name: String },
    /// 私有 IP
    PrivateIp,
    /// 局域网 IP
    LanIp,
}

/// 绕过动作
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassAction {
    /// 直接连接
    Direct,
    /// 忽略
    Ignore,
    /// 转发
    Forward { gateway: IpAddr },
}

/// 路由统计信息
#[derive(Debug, Clone)]
pub struct RouteStats {
    /// 活跃路由数
    pub active_routes: usize,
    /// 总路由数
    pub total_routes: usize,
    /// 路由命中次数
    pub route_hits: HashMap<String, u64>,
    /// 绕过命中次数
    pub bypass_hits: HashMap<String, u64>,
    /// 路由失败次数
    pub route_failures: u64,
    /// 最后更新时间
    pub last_updated: std::time::Instant,
}

impl Default for RouteStats {
    fn default() -> Self {
        Self {
            active_routes: 0,
            total_routes: 0,
            route_hits: HashMap::new(),
            bypass_hits: HashMap::new(),
            route_failures: 0,
            last_updated: std::time::Instant::now(),
        }
    }
}

impl RouteStats {
    /// 创建新的统计
    pub fn new() -> Self {
        Self::default()
    }

    /// 更新统计
    pub fn update(&mut self) {
        self.last_updated = std::time::Instant::now();
    }

    /// 记录路由命中
    pub fn record_hit(&mut self, rule_name: &str) {
        *self.route_hits.entry(rule_name.to_string()).or_insert(0) += 1;
    }

    /// 记录绕过命中
    pub fn record_bypass(&mut self, rule_name: &str) {
        *self.bypass_hits.entry(rule_name.to_string()).or_insert(0) += 1;
    }

    /// 记录失败
    pub fn record_failure(&mut self) {
        self.route_failures += 1;
    }

    /// 获取热门路由
    pub fn top_routes(&self, limit: usize) -> Vec<(String, u64)> {
        let mut routes: Vec<_> = self.route_hits.iter().collect();
        routes.sort_by(|a, b| b.1.cmp(a.1));
        routes
            .into_iter()
            .take(limit)
            .map(|(name, count)| (name.clone(), *count))
            .collect()
    }
}

/// 路由管理器抽象
#[async_trait]
pub trait RouteManager: Send + Sync + fmt::Debug {
    /// 获取路由配置
    fn config(&self) -> &RoutingConfig;

    /// 获取统计信息
    fn stats(&self) -> RouteStats;

    /// 应用路由配置
    async fn apply_routing(&self) -> Result<()>;

    /// 清理路由配置
    async fn clear_routing(&self) -> Result<()>;

    /// 添加路由规则
    async fn add_route(&self, rule: RouteRule) -> Result<()>;

    /// 删除路由规则
    async fn remove_route(&self, name: &str) -> Result<()>;

    /// 修改路由规则
    async fn modify_route(&self, rule: RouteRule) -> Result<()>;

    /// 获取路由表
    async fn get_routing_table(&self) -> Result<Vec<RouteRule>>;

    /// 查找路由
    async fn lookup_route(&self, destination: IpAddr) -> Result<Option<RouteRule>>;

    /// 启用/禁用路由
    async fn enable_route(&self, name: &str, enabled: bool) -> Result<()>;

    /// 刷新路由缓存
    async fn flush_cache(&self) -> Result<()>;

    /// 监控路由变化
    async fn monitor_changes(&self) -> Result<Box<dyn RouteMonitor>>;
}

/// 路由监控器
#[async_trait]
pub trait RouteMonitor: Send + Sync {
    /// 获取下一个变化事件
    async fn next_event(&mut self) -> Result<RouteEvent>;
}

/// 路由事件
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// 路由添加
    Added(RouteRule),
    /// 路由删除
    Removed(String),
    /// 路由修改
    Modified(RouteRule),
    /// 路由表刷新
    Flush,
    /// 错误
    Error(String),
}

/// 便捷函数
pub fn ipv4_netmask(prefix: u8) -> u32 {
    if prefix >= 32 {
        0xFFFFFFFF
    } else {
        0xFFFFFFFF << (32 - prefix)
    }
}

pub fn ipv6_netmask(prefix: u8) -> u128 {
    if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// 解析 CIDR 格式
pub fn parse_cidr(cidr: &str) -> Result<RouteDestination> {
    if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
        let addr: IpAddr = addr_str
            .parse()
            .with_context(|| format!("无效的 IP 地址: {}", addr_str))?;
        let prefix: u8 = prefix_str
            .parse()
            .with_context(|| format!("无效的前缀长度: {}", prefix_str))?;

        match addr {
            IpAddr::V4(v4) => RouteDestination::ipv4(v4, prefix),
            IpAddr::V6(v6) => RouteDestination::ipv6(v6, prefix),
        }
    } else {
        // 如果没有前缀，尝试解析为主机地址
        let addr: IpAddr = cidr
            .parse()
            .with_context(|| format!("无效的 IP 地址: {}", cidr))?;
        Ok(RouteDestination::host(addr))
    }
}

/// 默认的绕过规则
pub fn default_bypass_rules() -> Vec<BypassRule> {
    vec![
        BypassRule::new(
            "private_ip".to_string(),
            BypassCondition::PrivateIp,
            BypassAction::Direct,
        ),
        BypassRule::new(
            "loopback".to_string(),
            BypassCondition::IpRange {
                start: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)),
            },
            BypassAction::Direct,
        ),
        BypassRule::new(
            "multicast".to_string(),
            BypassCondition::IpRange {
                start: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255)),
            },
            BypassAction::Direct,
        ),
    ]
}

/// 路由管理器工厂
pub struct RouteManagerFactory;

impl RouteManagerFactory {
    /// 创建平台特定的路由管理器
    pub async fn create(config: RoutingConfig) -> Result<Box<dyn RouteManager>> {
        info!(target: "seep::route", mode = ?config.mode, "创建路由管理器");

        #[cfg(target_os = "linux")]
        {
            // TODO: 平台特定实现待完成
            Err(anyhow!("Linux 路由管理器待实现"))
        }

        #[cfg(target_os = "macos")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("macOS 路由管理器待实现"));
        }

        #[cfg(target_os = "windows")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("Windows 路由管理器待实现"));
        }

        #[cfg(target_os = "android")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("Android 路由管理器待实现"));
        }

        #[cfg(target_os = "ios")]
        {
            // TODO: 平台特定实现待完成
            return Err(anyhow!("iOS 路由管理器待实现"));
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
