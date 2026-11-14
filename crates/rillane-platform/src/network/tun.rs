//! TUN/TAP 虚拟网卡抽象
//!
//! 提供统一的 TUN/TAP 接口 API，支持：
//! - TUN 模式 (Layer 3 IP 层)
//! - TAP 模式 (Layer 2 以太网层)
//! - 跨平台实现 (Linux, Windows, macOS, Android, iOS)

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// TUN/TAP 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// 接口名称 (可选)
    pub name: Option<String>,
    /// MTU 大小
    pub mtu: u16,
    /// IPv4 地址
    pub ipv4_addr: Option<Ipv4Addr>,
    /// IPv4 子网掩码
    pub ipv4_netmask: Option<Ipv4Addr>,
    /// IPv4 网关
    pub ipv4_gateway: Option<Ipv4Addr>,
    /// IPv6 地址
    pub ipv6_addr: Option<Ipv6Addr>,
    /// IPv6 前缀长度
    pub ipv6_prefix_len: Option<u8>,
    /// IPv6 网关
    pub ipv6_gateway: Option<Ipv6Addr>,
    /// DNS 服务器
    pub dns_servers: Vec<IpAddr>,
    /// 是否启用路由
    pub enable_routing: bool,
    /// 是否启用 DNS
    pub enable_dns: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: 1500,
            ipv4_addr: None,
            ipv4_netmask: None,
            ipv4_gateway: None,
            ipv6_addr: None,
            ipv6_prefix_len: None,
            ipv6_gateway: None,
            dns_servers: vec![],
            enable_routing: true,
            enable_dns: true,
        }
    }
}

impl TunConfig {
    /// 创建新的 TUN 配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置接口名称
    pub fn with_name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    /// 设置 MTU
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// 设置 IPv4 配置
    pub fn with_ipv4(mut self, addr: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        self.ipv4_addr = Some(addr);
        self.ipv4_netmask = Some(netmask);
        self.ipv4_gateway = Some(gateway);
        self
    }

    /// 设置 IPv6 配置
    pub fn with_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8, gateway: Ipv6Addr) -> Self {
        self.ipv6_addr = Some(addr);
        self.ipv6_prefix_len = Some(prefix_len);
        self.ipv6_gateway = Some(gateway);
        self
    }

    /// 添加 DNS 服务器
    pub fn with_dns_servers(mut self, servers: Vec<IpAddr>) -> Self {
        self.dns_servers = servers;
        self
    }

    /// 启用/禁用路由
    pub fn with_routing(mut self, enable: bool) -> Self {
        self.enable_routing = enable;
        self
    }

    /// 启用/禁用 DNS
    pub fn with_dns(mut self, enable: bool) -> Self {
        self.enable_dns = enable;
        self
    }

    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        if self.mtu < 68 {
            return Err(anyhow::anyhow!("无效的 MTU: {}", self.mtu));
        }

        if let Some(prefix_len) = self.ipv6_prefix_len {
            if prefix_len > 128 {
                return Err(anyhow::anyhow!("无效的 IPv6 前缀长度: {}", prefix_len));
            }
        }

        // 检查 IPv4 配置完整性
        let ipv4_fields = [
            self.ipv4_addr.is_some(),
            self.ipv4_netmask.is_some(),
            self.ipv4_gateway.is_some(),
        ];
        if ipv4_fields.iter().any(|&f| f) && !ipv4_fields.iter().all(|&f| f) {
            warn!(target: "rillane::tun", "IPv4 配置不完整");
        }

        // 检查 IPv6 配置完整性
        let ipv6_fields = [
            self.ipv6_addr.is_some(),
            self.ipv6_prefix_len.is_some(),
            self.ipv6_gateway.is_some(),
        ];
        if ipv6_fields.iter().any(|&f| f) && !ipv6_fields.iter().all(|&f| f) {
            warn!(target: "rillane::tun", "IPv6 配置不完整");
        }

        Ok(())
    }
}

/// 网络包类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// IPv4 包
    Ipv4,
    /// IPv6 包
    Ipv6,
    /// ARP 包 (仅 TAP 模式)
    Arp,
    /// 未知类型
    Unknown,
}

impl PacketType {
    /// 从以太网帧头解析包类型
    pub fn from_ethertype(ethertype: u16) -> Self {
        match ethertype {
            0x0800 => PacketType::Ipv4,
            0x86DD => PacketType::Ipv6,
            0x0806 => PacketType::Arp,
            _ => PacketType::Unknown,
        }
    }

    /// 获取以太网类型值
    pub fn as_ethertype(&self) -> u16 {
        match self {
            PacketType::Ipv4 => 0x0800,
            PacketType::Ipv6 => 0x86DD,
            PacketType::Arp => 0x0806,
            PacketType::Unknown => 0x0000,
        }
    }

    /// 从 IP 版本字段解析
    pub fn from_ip_version(version: u8) -> Self {
        match version {
            4 => PacketType::Ipv4,
            6 => PacketType::Ipv6,
            _ => PacketType::Unknown,
        }
    }
}

/// 网络包信息
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// 包类型
    pub packet_type: PacketType,
    /// 源 IP 地址
    pub src_ip: Option<IpAddr>,
    /// 目标 IP 地址
    pub dst_ip: Option<IpAddr>,
    /// 源端口 (TCP/UDP)
    pub src_port: Option<u16>,
    /// 目标端口 (TCP/UDP)
    pub dst_port: Option<u16>,
    /// 协议 (TCP, UDP, ICMP 等)
    pub protocol: Option<u8>,
    /// 包长度
    pub length: usize,
    /// 是否入站
    pub inbound: bool,
}

impl PacketInfo {
    /// 创建新的包信息
    pub fn new(packet_type: PacketType, length: usize) -> Self {
        Self {
            packet_type,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            length,
            inbound: false,
        }
    }

    /// 解析 IP 包头
    pub fn parse_ip_header(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let version = (data[0] >> 4) & 0x0F;
        match version {
            4 => self.parse_ipv4_header(data)?,
            6 => self.parse_ipv6_header(data)?,
            _ => return Err(anyhow::anyhow!("不支持的 IP 版本: {}", version)),
        }

        Ok(())
    }

    /// 解析 IPv4 包头
    fn parse_ipv4_header(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("IPv4 包头太短"));
        }

        let header_len = (data[0] & 0x0F) as usize * 4;
        if data.len() < header_len {
            return Err(anyhow::anyhow!("IPv4 包头长度不完整"));
        }

        // 解析 IP 地址
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        self.src_ip = Some(IpAddr::V4(src_ip));
        self.dst_ip = Some(IpAddr::V4(dst_ip));
        self.protocol = Some(data[9]);

        // 解析端口 (TCP/UDP)
        if let Some(protocol) = self.protocol {
            if matches!(protocol, 6 /* TCP */ | 17 /* UDP */) && data.len() >= header_len + 4 {
                self.src_port = Some(u16::from_be_bytes([data[header_len], data[header_len + 1]]));
                self.dst_port = Some(u16::from_be_bytes([
                    data[header_len + 2],
                    data[header_len + 3],
                ]));
            }
        }

        Ok(())
    }

    /// 解析 IPv6 包头
    fn parse_ipv6_header(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 40 {
            return Err(anyhow::anyhow!("IPv6 包头太短"));
        }

        // 解析 IPv6 地址 (16 字节)
        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        dst_bytes.copy_from_slice(&data[24..40]);

        let src_ip = Ipv6Addr::from(src_bytes);
        let dst_ip = Ipv6Addr::from(dst_bytes);

        self.src_ip = Some(IpAddr::V6(src_ip));
        self.dst_ip = Some(IpAddr::V6(dst_ip));
        self.protocol = Some(data[6]); // Next Header

        // 简化的端口解析 (实际需要处理扩展头)
        if let Some(protocol) = self.protocol {
            if matches!(protocol, 6 /* TCP */ | 17 /* UDP */) && data.len() >= 44 {
                self.src_port = Some(u16::from_be_bytes([data[40], data[41]]));
                self.dst_port = Some(u16::from_be_bytes([data[42], data[43]]));
            }
        }

        Ok(())
    }

    /// 检查是否为 TCP 包
    pub fn is_tcp(&self) -> bool {
        matches!(self.protocol, Some(6))
    }

    /// 检查是否为 UDP 包
    pub fn is_udp(&self) -> bool {
        matches!(self.protocol, Some(17))
    }

    /// 检查是否为 ICMP 包
    pub fn is_icmp(&self) -> bool {
        matches!(self.protocol, Some(1)) || matches!(self.protocol, Some(58))
    }
}

/// TUN/TAP 接口统计
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    /// 接收字节数
    pub bytes_received: u64,
    /// 发送字节数
    pub bytes_sent: u64,
    /// 接收包数
    pub packets_received: u64,
    /// 发送包数
    pub packets_sent: u64,
    /// 接收错误数
    pub receive_errors: u64,
    /// 发送错误数
    pub send_errors: u64,
    /// 丢弃包数
    pub packets_dropped: u64,
}

/// TUN/TAP 接口抽象
///
/// trait 15→14：`packet_stream`/`TunPacketStream`/`TunInterface` 占位假实现已删
/// （tun-dataplane.md §1.2——「写成功」不可保留）；消费方统一走
/// `read_packet`/`write_packet` 对。
#[async_trait]
pub trait TunProvider: Send + Sync + fmt::Debug {
    /// 获取接口名称
    fn name(&self) -> &str;

    /// 获取接口配置
    fn config(&self) -> &TunConfig;

    /// 获取接口状态
    fn is_up(&self) -> bool;

    /// 获取 MTU
    fn mtu(&self) -> u16;

    /// 获取统计信息
    fn stats(&self) -> InterfaceStats;

    /// 创建 TUN/TAP 接口
    async fn create_interface(&mut self) -> Result<()>;

    /// 销毁 TUN/TAP 接口
    async fn destroy_interface(&mut self) -> Result<()>;

    /// 启动接口
    async fn up_interface(&mut self) -> Result<()>;

    /// 停止接口
    async fn down_interface(&mut self) -> Result<()>;

    /// 配置 IP 地址
    async fn configure_ip(&mut self) -> Result<()>;

    /// 配置路由
    async fn configure_routing(&mut self) -> Result<()>;

    /// 配置 DNS
    async fn configure_dns(&mut self) -> Result<()>;

    /// 读取网络包
    async fn read_packet(&mut self) -> Result<(Bytes, PacketInfo)>;

    /// 写入网络包
    async fn write_packet(&mut self, packet: Bytes) -> Result<()>;
}

/// 便捷函数：创建和配置 TUN 接口
///
/// 分派唯一事实源 = `network::create_tun_provider` 工厂（tun-dataplane.md §1.4），
/// 本函数仅补 validate 前置与日志。
pub async fn create_tun_interface(
    config: TunConfig,
    mode: super::NetworkMode,
) -> Result<Box<dyn TunProvider>> {
    config.validate().context("验证 TUN 配置失败")?;

    debug!(target: "rillane::tun",
        name = ?config.name,
        mtu = config.mtu,
        "创建 TUN 接口");

    super::create_tun_provider(&config, mode)
}

/// 便捷函数：解析网络包
pub fn parse_packet_info(data: &[u8]) -> Result<PacketInfo> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("空数据包"));
    }

    let packet_type = if data.len() >= 14 {
        // 可能是以太网帧
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        PacketType::from_ethertype(ethertype)
    } else {
        // 可能是纯 IP 包
        let version = (data[0] >> 4) & 0x0F;
        PacketType::from_ip_version(version)
    };

    let mut info = PacketInfo::new(packet_type, data.len());

    if data.len() >= 20 {
        info.parse_ip_header(data)?;
    }

    Ok(info)
}
