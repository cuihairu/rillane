//! 网络虚拟化模块
//!
//! 提供跨平台的 TUN/TAP 虚拟网卡支持，包括：
//! - TUN/TAP 接口抽象
//! - 路由管理
//! - 流量拦截和重定向
//! - 跨平台实现适配

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub mod dns;
pub mod dns_engine;
pub mod filter;
// 本机身份契约（RIL-005）：OwnerResolver 三态 + 截止时间 + unknown 策略
pub mod owner;
// Linux 本机身份真实实现（RIL-030）：/proc 四元组→inode→pid→身份
#[cfg(target_os = "linux")]
pub mod owner_linux;
// IP/UDP/TCP 报文编解码纯函数（tun-dataplane.md §2.3/§4.1）
pub mod ipcodec;
// 平台端口契约（RIL-004）：CapturePort/SocketBypass/NetworkEvents/
// RouteTransaction 最小接口，packet 与 socket 输入分别建模
pub mod ports;
pub mod route;
// 系统副作用计划/补偿契约（RIL-018）：变更日志 + 所有权 + 幂等撤销
pub mod side_effects;
pub mod tun;
// Linux TUN 真实现（tun-dataplane.md §1.4）；其余平台待落地
#[cfg(target_os = "linux")]
pub mod linux;
// Linux 接管端口迁移（RIL-029）：RIL-004 四契约的 Linux 实现——复用
// 现有 TUN 数据面与逃逸表
#[cfg(target_os = "linux")]
pub mod takeover;
// Linux 生命周期恢复（RIL-031）：崩溃日志（持久化 JSONL）+ 重启修复
// + 网络切换恢复动作映射
#[cfg(target_os = "linux")]
pub mod recovery;
// Windows 接管面决策层（RIL-033 代码面）：事务/快照解析 OS-free——
// Linux 验证席确定性可测；真机 IO（route print/netsh 真读、socket
// 旁路真绑定、wireguard-nt）归 win_net（cfg windows，跨编译检查验证；
// 运行期验收证据待真机——SSH 授权面恢复后归机批次）
pub mod win_takeover;
#[cfg(target_os = "windows")]
pub mod win_net;
// TODO: 平台特定实现待完成（死稿，见 platform.rs 头部注记）
// pub mod platform;

pub use dns::{
    DnsConfig, DnsFilterAction, DnsHandler, DnsRecordType, DomainPattern as DnsDomainPattern,
};
pub use dns_engine::{
    AntiPoison, DnsAnswer, DnsAnswerData, DnsPartition, DnsResolver, DnsStatsCounters,
    DnsStatsSnapshot, EngineDnsHandler, LocalDnsServer, PartitionPattern, ResolveError,
    ResolverConfig, UpstreamGroup,
};
pub use filter::{
    ApplicationRule, DomainPattern as FilterDomainPattern, FilterAction, FilterResult, FilterStats,
    FilteringConfig, FilteringMode, IpRule, PacketFilter, PortRule, ProcessRule, ProtocolRule,
};
pub use owner::{
    ConnectionKey, InMemoryOwnerResolver, OwnerCapability, OwnerResolution, OwnerResolver,
    ProcessIdentity, UnknownOwnerPolicy, UnknownReason,
};
#[cfg(target_os = "linux")]
pub use owner_linux::ProcOwnerResolver;
pub use ports::{
    CapturePort, CapturedInput, InMemoryNetworkEvents, InMemoryRouteTransaction, IpProtocol,
    NetworkEvent, NetworkEvents, PacketInput, PacketMeta, RouteTransaction, SocketBypass,
    SocketHandle, SocketInput, SystemChange, TransportProtocol,
};
#[cfg(target_os = "linux")]
pub use recovery::{
    handle_network_event, journaling_executor, plan_for_event, recover, CrashJournal, JournalEntry,
    JournalSnapshot, NetworkRecoveryAction, RecoveryReport, AUDIT_TARGET,
};
pub use route::{
    BypassAction, BypassCondition, BypassRule, RouteDestination, RouteManager, RouteRule,
    RouteStats, RouteType, RoutingConfig, RoutingMode,
};
pub use side_effects::{
    ChangeEntry, InverseChange, Ownership, SideEffectError, SideEffectJournal, SystemArea,
    CODE_SIDE_EFFECT_FOREIGN, CODE_SIDE_EFFECT_UNKNOWN,
};
#[cfg(target_os = "linux")]
pub use takeover::{
    parse_default_ifaces, parse_packet_meta, parse_resolv_nameservers, parse_step_payload,
    pump_tun, read_net_snapshot, read_so_mark, step_payload, LinuxNetworkEvents,
    LinuxRouteTransaction, LinuxSocketBypass, LinuxTakeoverPort, NetSnapshot, StepExecutor,
    TakeoverPortStats, TAKEOVER_FWMARK,
};
pub use tun::{PacketInfo as TunPacketInfo, PacketType, TunConfig, TunProvider};
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
#[derive(Default)]
pub enum NetworkMode {
    /// TUN 模式 - Layer 3 IP 层虚拟化
    #[default]
    Tun,
    /// TAP 模式 - Layer 2 以太网层虚拟化
    Tap,
    /// 透明代理模式 - 通过 iptables/nftables 重定向
    Transparent,
    /// 混合模式
    Hybrid,
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
        info!(target: "rillane::network", mode = ?self.config.mode, "初始化网络管理器");

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
                warn!(target: "rillane::network", "网络管理器已在运行");
                return Ok(());
            }
            *running = true;
        }

        info!(target: "rillane::network", "启动网络虚拟化");

        // 启动 TUN 接口
        if let Some(tun_provider) = self.tun_provider.as_mut() {
            tun_provider
                .create_interface()
                .await
                .context("创建 TUN 接口失败")?;
            tun_provider
                .up_interface()
                .await
                .context("启动 TUN 接口失败")?;
        }

        // 应用路由规则
        if let Some(route_manager) = self.route_manager.as_ref() {
            route_manager
                .apply_routing()
                .await
                .context("应用路由规则失败")?;
        }

        // 启动包过滤
        if let Some(packet_filter) = self.packet_filter.as_ref() {
            packet_filter.enable().await.context("启用包过滤失败")?;
        }

        // 启动 DNS 处理
        if let Some(dns_handler) = self.dns_handler.as_ref() {
            dns_handler.start().await.context("启动 DNS 处理失败")?;
        }

        info!(target: "rillane::network", "网络虚拟化启动成功");
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

        info!(target: "rillane::network", "停止网络虚拟化");

        // 停止 DNS 处理
        if let Some(dns_handler) = self.dns_handler.as_ref() {
            if let Err(e) = dns_handler.stop().await {
                error!(target: "rillane::network", error = %e, "停止 DNS 处理失败");
            }
        }

        // 禁用包过滤
        if let Some(packet_filter) = self.packet_filter.as_ref() {
            if let Err(e) = packet_filter.disable().await {
                error!(target: "rillane::network", error = %e, "禁用包过滤失败");
            }
        }

        // 清理路由规则
        if let Some(route_manager) = self.route_manager.as_ref() {
            if let Err(e) = route_manager.clear_routing().await {
                error!(target: "rillane::network", error = %e, "清理路由规则失败");
            }
        }

        // 停止 TUN 接口
        if let Some(tun_provider) = self.tun_provider.as_mut() {
            if let Err(e) = tun_provider.down_interface().await {
                error!(target: "rillane::network", error = %e, "停止 TUN 接口失败");
            }
            if let Err(e) = tun_provider.destroy_interface().await {
                error!(target: "rillane::network", error = %e, "销毁 TUN 接口失败");
            }
        }

        info!(target: "rillane::network", "网络虚拟化已停止");
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

/// 创建平台特定的 TUN 提供者（tun-dataplane.md §1.4：
/// Linux 分派 linux.rs 真骨架；其余平台保留 Err）
fn create_tun_provider(config: &TunConfig, mode: NetworkMode) -> Result<Box<dyn TunProvider>> {
    #[cfg(target_os = "linux")]
    {
        // TUN/TAP 模式差异化（Tap 拒绝）归 T1；工厂层当前不按模式分派
        let _ = mode;
        Ok(Box::new(linux::LinuxTunProvider::new(config.clone())))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, mode);
        Err(anyhow::anyhow!(
            "TUN 提供者真实现仅 Linux（tun-dataplane.md）；当前平台待落地"
        ))
    }
}

/// 创建平台特定的路由管理器（Linux 分派 linux.rs 真骨架；其余平台保留 Err）
fn create_route_manager(config: &RoutingConfig) -> Result<Box<dyn RouteManager>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxRouteManager::new(config.clone())))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(anyhow::anyhow!(
            "路由管理器真实现仅 Linux（tun-dataplane.md）；当前平台待落地"
        ))
    }
}

/// 创建平台特定的包过滤器——恒 Err：过滤走进程内规则（tun-dataplane.md §2.7），
/// 不落内核态
fn create_packet_filter(_config: &FilteringConfig) -> Result<Box<dyn PacketFilter>> {
    Err(anyhow::anyhow!(
        "包过滤器不落内核态：filter=进程内规则（tun-dataplane.md §2.7）"
    ))
}

/// 创建 DNS 处理器——P2-8 切真实现：UDP 直连上游引擎（dns-partition.md
/// §2-D-6）；加密上游/零上游由引擎装配期 Err 带指引
fn create_dns_handler(config: &DnsConfig) -> Result<Box<dyn DnsHandler>> {
    Ok(Box::new(dns_engine::EngineDnsHandler::from_dns_config(
        config,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing_config() -> RoutingConfig {
        RoutingConfig {
            mode: RoutingMode::Global,
            default_gateway: None,
            dns_servers: vec![],
            rules: vec![],
            bypass_rules: vec![],
            enabled: true,
        }
    }

    /// T0：Linux 上 tun/route 工厂分派到 linux.rs 骨架并返回实例
    /// （设备/路由 I/O 归 T1/T2，工厂构造即成功）
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_and_route_factories_dispatch() {
        let tun = create_tun_provider(&TunConfig::default(), NetworkMode::Tun)
            .expect("Linux 工厂应返回 LinuxTunProvider");
        assert_eq!(tun.mtu(), 1500);
        assert_eq!(tun.name(), ""); // 内核分配名 TUNGETIFF 读回归 T1

        let route =
            create_route_manager(&routing_config()).expect("Linux 工厂应返回 LinuxRouteManager");
        assert_eq!(route.config().mode, RoutingMode::Global);
    }

    /// T0：filter 工厂保持 Err（进程内规则）；DNS 工厂切 P2-8 引擎——
    /// UDP 上游可用、加密/零上游 Err（dns-partition.md §2-D-6 口径转换）
    #[test]
    fn filter_factory_stays_err_and_dns_factory_dispatches() {
        let filtering = FilteringConfig {
            mode: FilteringMode::Blacklist,
            applications: vec![],
            processes: vec![],
            protocols: vec![],
            ports: vec![],
            ip_addresses: vec![],
            domains: vec![],
            enabled: true,
        };
        let err = create_packet_filter(&filtering).unwrap_err();
        assert!(
            err.to_string().contains("进程内规则"),
            "错误应指向进程内规则：{err}"
        );

        let dns_cfg = |servers: Vec<dns::DnsServer>| DnsConfig {
            mode: dns::DnsMode::Direct,
            servers,
            cache: None,
            filters: vec![],
            enabled: true,
            local_port: 15353,
            local_address: "127.0.0.1".parse().unwrap(),
            timeout: std::time::Duration::from_secs(5),
            retries: 2,
        };
        let udp = dns::DnsServer::new(
            "udp".to_string(),
            "223.5.5.5:53".parse().unwrap(),
            dns::DnsServerType::Udp,
        );
        let handler = create_dns_handler(&dns_cfg(vec![udp])).expect("UDP 上游应装配引擎（P2-8）");
        assert_eq!(handler.config().local_port, 15353);

        let err = create_dns_handler(&dns_cfg(vec![])).unwrap_err();
        assert!(
            err.to_string().contains("UDP"),
            "零上游错误应指引 UDP 面：{err}"
        );
    }
}
