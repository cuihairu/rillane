//! 网络虚拟化模块
//!
//! 提供跨平台的 TUN/TAP 虚拟网卡支持，包括：
//! - TUN/TAP 接口抽象
//! - 路由管理
//! - 流量拦截和重定向
//! - 跨平台实现适配

use std::{
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub mod tun;
pub mod route;
pub mod filter;
pub mod dns;
// TODO: 平台特定实现待完成
// pub mod platform;

pub use tun::{PacketInfo as TunPacketInfo, PacketType, TunConfig, TunProvider};
pub use route::{
    BypassAction, BypassCondition, BypassRule, RouteDestination, RouteManager, RouteRule,
    RouteStats, RouteType, RoutingConfig, RoutingMode,
};
pub use filter::{
    ApplicationRule, DomainPattern as FilterDomainPattern, FilterAction, FilterResult,
    FilterStats, FilteringConfig, FilteringMode, IpRule, PacketFilter, PortRule, ProcessRule,
    ProtocolRule,
};
pub use dns::{
    DnsConfig, DnsFilterAction, DnsHandler, DnsRecordType,
    DomainPattern as DnsDomainPattern,
};
// pub use platform::*;

/// 网络虚拟化配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// 网络模式
    pub mode: NetworkMode,
    /// TUN 接口配置
    pub tun: Option<TunConfig>,
    /// 路由配置
    pub routing: Option<RoutingConfig>,
    /// 流量过滤配置
    pub filtering: Option<FilteringConfig>,
    /// DNS 配置
    pub dns: Option<DnsConfig>,
}

/// 网络模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// TUN 模式 - Layer 3 IP 层虚拟化
    Tun,
    /// TAP 模式 - Layer 2 以太网层虚拟化
    Tap,
    /// 透明代理模式 - 通过 iptables/nftables 重定向
    Transparent,
    /// 混合模式
    Hybrid,
}

impl Default for NetworkMode {
    fn default() -> Self {
        NetworkMode::Tun
    }
}

/// 流量统计信息
#[derive(Debug, Clone)]
pub struct NetworkStats {
    /// 上传字节数
    pub bytes_uploaded: u64,
    /// 下载字节数
    pub bytes_downloaded: u64,
    /// 上传包数
    pub packets_uploaded: u64,
    /// 下载包数
    pub packets_downloaded: u64,
    /// 连接数
    pub connections_established: u64,
    /// 错误数
    pub errors: u64,
    /// 开始时间
    pub start_time: std::time::Instant,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            packets_uploaded: 0,
            packets_downloaded: 0,
            connections_established: 0,
            errors: 0,
            start_time: std::time::Instant::now(),
        }
    }
}

impl NetworkStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn upload_speed_bps(&self) -> f64 {
        let duration_secs = self.duration().as_secs_f64();
        if duration_secs > 0.0 {
            self.bytes_uploaded as f64 / duration_secs
        } else {
            0.0
        }
    }

    pub fn download_speed_bps(&self) -> f64 {
        let duration_secs = self.duration().as_secs_f64();
        if duration_secs > 0.0 {
            self.bytes_downloaded as f64 / duration_secs
        } else {
            0.0
        }
    }
}

/// 网络管理器
pub struct NetworkManager {
    config: NetworkConfig,
    tun_provider: Option<Box<dyn TunProvider>>,
    route_manager: Option<Box<dyn RouteManager>>,
    packet_filter: Option<Box<dyn PacketFilter>>,
    dns_handler: Option<Box<dyn DnsHandler>>,
    stats: Arc<RwLock<NetworkStats>>,
    running: Arc<RwLock<bool>>,
}

impl NetworkManager {
    /// 创建新的网络管理器
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            tun_provider: None,
            route_manager: None,
            packet_filter: None,
            dns_handler: None,
            stats: Arc::new(RwLock::new(NetworkStats::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// 初始化网络组件
    pub fn initialize(&mut self) -> Result<()> {
        info!(target: "seep::network", mode = ?self.config.mode, "初始化网络管理器");

        // 初始化 TUN 提供者
        if let Some(tun_config) = &self.config.tun {
            let tun_provider = create_tun_provider(tun_config, self.config.mode)?;
            self.tun_provider = Some(tun_provider);
        }

        // 初始化路由管理器
        if let Some(routing_config) = &self.config.routing {
            let route_manager = create_route_manager(routing_config)?;
            self.route_manager = Some(route_manager);
        }

        // 初始化包过滤器
        if let Some(filtering_config) = &self.config.filtering {
            let packet_filter = create_packet_filter(filtering_config)?;
            self.packet_filter = Some(packet_filter);
        }

        // 初始化 DNS 处理器
        if let Some(dns_config) = &self.config.dns {
            let dns_handler = create_dns_handler(dns_config)?;
            self.dns_handler = Some(dns_handler);
        }

        Ok(())
    }

    /// 启动网络虚拟化
    pub async fn start(&mut self) -> Result<()> {
        {
            let mut running = self.running.write().await;
            if *running {
                warn!(target: "seep::network", "网络管理器已在运行");
                return Ok(());
            }
            *running = true;
        }

        info!(target: "seep::network", "启动网络虚拟化");

        // 启动 TUN 接口
        if let Some(tun_provider) = self.tun_provider.as_mut() {
            tun_provider.create_interface().await
                .context("创建 TUN 接口失败")?;
            tun_provider.up_interface().await
                .context("启动 TUN 接口失败")?;
        }

        // 应用路由规则
        if let Some(route_manager) = self.route_manager.as_ref() {
            route_manager.apply_routing().await
                .context("应用路由规则失败")?;
        }

        // 启动包过滤
        if let Some(packet_filter) = self.packet_filter.as_ref() {
            packet_filter.enable().await
                .context("启用包过滤失败")?;
        }

        // 启动 DNS 处理
        if let Some(dns_handler) = self.dns_handler.as_ref() {
            dns_handler.start().await
                .context("启动 DNS 处理失败")?;
        }

        info!(target: "seep::network", "网络虚拟化启动成功");
        Ok(())
    }

    /// 停止网络虚拟化
    pub async fn stop(&mut self) -> Result<()> {
        {
            let mut running = self.running.write().await;
            if !*running {
                return Ok(());
            }
            *running = false;
        }

        info!(target: "seep::network", "停止网络虚拟化");

        // 停止 DNS 处理
        if let Some(dns_handler) = self.dns_handler.as_ref() {
            if let Err(e) = dns_handler.stop().await {
                error!(target: "seep::network", error = %e, "停止 DNS 处理失败");
            }
        }

        // 禁用包过滤
        if let Some(packet_filter) = self.packet_filter.as_ref() {
            if let Err(e) = packet_filter.disable().await {
                error!(target: "seep::network", error = %e, "禁用包过滤失败");
            }
        }

        // 清理路由规则
        if let Some(route_manager) = self.route_manager.as_ref() {
            if let Err(e) = route_manager.clear_routing().await {
                error!(target: "seep::network", error = %e, "清理路由规则失败");
            }
        }

        // 停止 TUN 接口
        if let Some(tun_provider) = self.tun_provider.as_mut() {
            if let Err(e) = tun_provider.down_interface().await {
                error!(target: "seep::network", error = %e, "停止 TUN 接口失败");
            }
            if let Err(e) = tun_provider.destroy_interface().await {
                error!(target: "seep::network", error = %e, "销毁 TUN 接口失败");
            }
        }

        info!(target: "seep::network", "网络虚拟化已停止");
        Ok(())
    }

    /// 获取网络统计信息
    pub async fn get_stats(&self) -> NetworkStats {
        self.stats.read().await.clone()
    }

    /// 更新网络统计
    pub async fn update_stats<F>(&self, updater: F)
    where
        F: FnOnce(&mut NetworkStats),
    {
        let mut stats = self.stats.write().await;
        updater(&mut stats);
    }

    /// 检查是否在运行
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

}

/// 创建平台特定的 TUN 提供者
fn create_tun_provider(_config: &TunConfig, _mode: NetworkMode) -> Result<Box<dyn TunProvider>> {
    // TODO: 平台特定实现待完成
    Err(anyhow::anyhow!("TUN 提供者平台特定实现待完成"))
}

/// 创建平台特定的路由管理器
fn create_route_manager(_config: &RoutingConfig) -> Result<Box<dyn RouteManager>> {
    // TODO: 路由管理器平台特定实现待完成
    Err(anyhow::anyhow!("路由管理器平台特定实现待完成"))
}

/// 创建平台特定的包过滤器
fn create_packet_filter(_config: &FilteringConfig) -> Result<Box<dyn PacketFilter>> {
    // TODO: 包过滤器平台特定实现待完成
    Err(anyhow::anyhow!("包过滤器平台特定实现待完成"))
}

/// 创建平台特定的 DNS 处理器
fn create_dns_handler(_config: &DnsConfig) -> Result<Box<dyn DnsHandler>> {
    // TODO: DNS 处理器平台特定实现待完成
    Err(anyhow::anyhow!("DNS 处理器平台特定实现待完成"))
}
