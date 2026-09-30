//! Linux TUN 真实现（tun-dataplane.md §1）
//!
//! T0 骨架：结构与工厂分派先落——设备生命周期（§1.1：/dev/net/tun +
//! TUNSETIFF + AsyncFd）与系统路由（§1.3：ip 子进程 + AppliedStep 回滚）
//! 的真实现分别归 T1/T2。落地前本文件全部 I/O 方法显式 Err 并点名归属，
//! 不产生任何「假成功」。

use std::{
    fmt,
    os::fd::OwnedFd,
    sync::Mutex,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::unix::AsyncFd;

use super::route::{RouteManager, RouteMonitor, RouteRule, RouteStats, RoutingConfig};
use super::tun::{InterfaceStats, PacketInfo, TunConfig, TunProvider};

/// Linux TUN 设备提供者（tun-dataplane.md §1.1/§1.2）
///
/// 单 fd（IFF_MULTI_QUEUE 归 V2）；`fd = None` 表示设备尚未创建，
/// `name` 在 T1 由 TUNGETIFF 读回（内核分配 tun%d）。
pub struct LinuxTunProvider {
    config: TunConfig,
    fd: Option<AsyncFd<OwnedFd>>,
    name: String,
    up: bool,
    stats: InterfaceStats,
}

impl fmt::Debug for LinuxTunProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // AsyncFd 不承诺 Debug；fd 只输出开关态
        f.debug_struct("LinuxTunProvider")
            .field("name", &self.name)
            .field("fd_open", &self.fd.is_some())
            .field("up", &self.up)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LinuxTunProvider {
    /// 创建提供者（不触碰设备；设备 open/attach 在 `create_interface`）
    pub fn new(config: TunConfig) -> Self {
        Self {
            name: config.name.clone().unwrap_or_default(),
            fd: None,
            config,
            up: false,
            stats: InterfaceStats::default(),
        }
    }
}

#[async_trait]
impl TunProvider for LinuxTunProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn config(&self) -> &TunConfig {
        &self.config
    }

    fn is_up(&self) -> bool {
        self.up
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn stats(&self) -> InterfaceStats {
        self.stats.clone()
    }

    async fn create_interface(&mut self) -> Result<()> {
        Err(anyhow!("Linux TUN 设备创建（/dev/net/tun + TUNSETIFF）归 T1（tun-dataplane.md §1.1）"))
    }

    async fn destroy_interface(&mut self) -> Result<()> {
        Err(anyhow!("Linux TUN 设备销毁（drop fd）归 T1（tun-dataplane.md §1.1）"))
    }

    async fn up_interface(&mut self) -> Result<()> {
        Err(anyhow!("Linux TUN 接口拉起（ip link set up）归 T1（tun-dataplane.md §1.1）"))
    }

    async fn down_interface(&mut self) -> Result<()> {
        Err(anyhow!("Linux TUN 接口停用归 T1（tun-dataplane.md §1.1）"))
    }

    async fn configure_ip(&mut self) -> Result<()> {
        Err(anyhow!("Linux TUN 地址配置（ip addr replace）归 T1（tun-dataplane.md §1.3）"))
    }

    async fn configure_routing(&mut self) -> Result<()> {
        Err(anyhow!("Linux TUN 路由配置（委托 LinuxRouteManager）归 T1（tun-dataplane.md §1.3）"))
    }

    async fn configure_dns(&mut self) -> Result<()> {
        // MVP 直通：TunConfig.dns_servers 仅记录，DNS 劫持归 P2-8
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<(Bytes, PacketInfo)> {
        Err(anyhow!("Linux TUN 读包（AsyncFd 就绪循环）归 T1（tun-dataplane.md §1.1）"))
    }

    async fn write_packet(&mut self, _packet: Bytes) -> Result<()> {
        Err(anyhow!("Linux TUN 写包（整包写 fd）归 T1（tun-dataplane.md §1.1）"))
    }
}

/// 已执行的配置步骤——apply 逆序撤销与 clear_routing 的事实源
/// （tun-dataplane.md §1.3：ip addr/link/route replace 均幂等，
/// 撤销对应 del/down）
#[derive(Debug, Clone)]
pub enum AppliedStep {
    /// `ip addr replace` 配置到接口的地址
    AddrReplaced { interface: String, cidr: String },
    /// `ip link set up` 拉起的接口
    LinkUp { interface: String },
    /// `ip route replace` 安装到 main 表的路由
    RouteReplaced {
        cidr: String,
        interface: String,
        metric: u32,
    },
}

/// Linux 系统路由管理器（tun-dataplane.md §1.3）
///
/// MVP = main 表显式路由 include 语义（不改默认路由、不用 ip rule、
/// 无需 fwmark）；`ip` 命令子进程执行（netlink 归 V2）。
#[derive(Debug)]
pub struct LinuxRouteManager {
    config: RoutingConfig,
    /// T2 起由 apply/clear 读写（记录已执行步骤供逆序撤销）
    #[allow(dead_code)]
    applied: Mutex<Vec<AppliedStep>>,
}

impl LinuxRouteManager {
    /// 创建路由管理器（不触碰系统路由；首次变更在 `apply_routing`）
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config,
            applied: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl RouteManager for LinuxRouteManager {
    fn config(&self) -> &RoutingConfig {
        &self.config
    }

    fn stats(&self) -> RouteStats {
        RouteStats::default()
    }

    async fn apply_routing(&self) -> Result<()> {
        Err(anyhow!("Linux 路由应用（ip route replace + AppliedStep 记录）归 T2（tun-dataplane.md §1.3）"))
    }

    async fn clear_routing(&self) -> Result<()> {
        Err(anyhow!("Linux 路由清理（逆序撤销 AppliedStep）归 T2（tun-dataplane.md §1.3）"))
    }

    async fn add_route(&self, _rule: RouteRule) -> Result<()> {
        Err(anyhow!("Linux 单条路由添加归 T2（tun-dataplane.md §1.3）"))
    }

    async fn remove_route(&self, _name: &str) -> Result<()> {
        Err(anyhow!("Linux 单条路由删除归 T2（tun-dataplane.md §1.3）"))
    }

    async fn modify_route(&self, _rule: RouteRule) -> Result<()> {
        Err(anyhow!("Linux 路由修改归 T2（tun-dataplane.md §1.3）"))
    }

    async fn get_routing_table(&self) -> Result<Vec<RouteRule>> {
        Err(anyhow!("Linux 路由表读取归 T2（tun-dataplane.md §1.3）"))
    }

    async fn lookup_route(&self, _destination: std::net::IpAddr) -> Result<Option<RouteRule>> {
        Err(anyhow!("Linux 路由查找归 T2（tun-dataplane.md §1.3）"))
    }

    async fn enable_route(&self, _name: &str, _enabled: bool) -> Result<()> {
        Err(anyhow!("Linux 路由启停归 T2（tun-dataplane.md §1.3）"))
    }

    async fn flush_cache(&self) -> Result<()> {
        // 骨架无路由缓存可刷——真缓存随 T2 落地
        Ok(())
    }

    async fn monitor_changes(&self) -> Result<Box<dyn RouteMonitor>> {
        Err(anyhow!("Linux 路由变化监控归 T2+（tun-dataplane.md §1.3）"))
    }
}
