//! 平台特定实现（占位）
//!
//! 这个模块包含各平台的具体实现。
//! 目前提供占位实现，实际功能待完成。

use std::net::IpAddr;
use std::pin::Pin;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use tracing::warn;

use super::dns::{DnsConfig, DnsHandler, DnsQuery, DnsResponse, DnsStats};
use super::filter::{
    ApplicationRule, DomainRule, FilterStats, FilteringConfig, IpRule, PacketFilter, PortRule,
    ProcessRule, ProtocolRule,
};
use super::route::{RouteRule, RouteStats, RouteManager, RoutingConfig};
use super::tun::{PacketInfo as TunPacketInfo, TunConfig, TunProvider};

/// macOS Utun 提供者（占位实现）
#[derive(Debug)]
pub struct MacosUtunProvider {
    config: TunConfig,
}

impl MacosUtunProvider {
    pub fn new(config: TunConfig) -> Result<Self> {
        warn!("MacosUtunProvider 是占位实现，功能未完成");
        Ok(Self { config })
    }
}

#[async_trait]
impl TunProvider for MacosUtunProvider {
    async fn read_packet(&mut self) -> Result<(Bytes, TunPacketInfo)> {
        Err(anyhow!("MacosUtunProvider 未实现"))
    }

    async fn write_packet(&mut self, _packet: Bytes) -> Result<()> {
        Err(anyhow!("MacosUtunProvider 未实现"))
    }

    fn packet_stream(&self) -> Pin<Box<dyn Stream<Item = Result<(Bytes, TunPacketInfo)>> + Send>> {
        Box::pin(futures::stream::empty())
    }
}

/// macOS TAP 提供者（占位实现）
#[derive(Debug)]
pub struct MacosTapProvider {
    config: TunConfig,
}

impl MacosTapProvider {
    pub fn new(config: TunConfig) -> Result<Self> {
        warn!("MacosTapProvider 是占位实现，功能未完成");
        Ok(Self { config })
    }
}

#[async_trait]
impl TunProvider for MacosTapProvider {
    async fn read_packet(&mut self) -> Result<(Bytes, TunPacketInfo)> {
        Err(anyhow!("MacosTapProvider 未实现"))
    }

    async fn write_packet(&mut self, _packet: Bytes) -> Result<()> {
        Err(anyhow!("MacosTapProvider 未实现"))
    }

    fn packet_stream(&self) -> Pin<Box<dyn Stream<Item = Result<(Bytes, TunPacketInfo)>> + Send>> {
        Box::pin(futures::stream::empty())
    }
}

/// macOS 路由管理器（占位实现）
#[derive(Debug)]
pub struct MacosRouteManager {
    config: RoutingConfig,
}

impl MacosRouteManager {
    pub async fn new(config: RoutingConfig) -> Result<Self> {
        warn!("MacosRouteManager 是占位实现，功能未完成");
        Ok(Self { config })
    }
}

#[async_trait]
impl RouteManager for MacosRouteManager {
    fn config(&self) -> &RoutingConfig {
        &self.config
    }

    fn stats(&self) -> RouteStats {
        RouteStats::default()
    }

    async fn apply_routing(&self) -> Result<()> {
        Ok(())
    }

    async fn clear_routing(&self) -> Result<()> {
        Ok(())
    }

    async fn add_route(&self, _rule: RouteRule) -> Result<()> {
        Err(anyhow!("MacosRouteManager 未实现"))
    }

    async fn remove_route(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn modify_route(&self, _rule: RouteRule) -> Result<()> {
        Err(anyhow!("MacosRouteManager 未实现"))
    }

    async fn get_routing_table(&self) -> Result<Vec<RouteRule>> {
        Ok(Vec::new())
    }

    async fn lookup_route(&self, _destination: IpAddr) -> Result<Option<RouteRule>> {
        Ok(None)
    }

    async fn enable_route(&self, _name: &str, _enabled: bool) -> Result<()> {
        Ok(())
    }
}

/// macOS 包过滤器（占位实现）
#[derive(Debug)]
pub struct MacosPacketFilter {
    config: FilteringConfig,
}

impl MacosPacketFilter {
    pub fn new(config: FilteringConfig) -> Result<Self> {
        warn!("MacosPacketFilter 是占位实现，功能未完成");
        Ok(Self { config })
    }
}

#[async_trait]
impl PacketFilter for MacosPacketFilter {
    fn config(&self) -> &FilteringConfig {
        &self.config
    }

    fn stats(&self) -> FilterStats {
        FilterStats::default()
    }

    async fn enable(&self) -> Result<()> {
        Ok(())
    }

    async fn disable(&self) -> Result<()> {
        Ok(())
    }

    async fn reload(&self, _config: FilteringConfig) -> Result<()> {
        Ok(())
    }

    async fn add_application_rule(&self, _rule: ApplicationRule) -> Result<()> {
        Ok(())
    }

    async fn add_process_rule(&self, _rule: ProcessRule) -> Result<()> {
        Ok(())
    }

    async fn add_protocol_rule(&self, _rule: ProtocolRule) -> Result<()> {
        Ok(())
    }

    async fn add_port_rule(&self, _rule: PortRule) -> Result<()> {
        Ok(())
    }

    async fn add_ip_rule(&self, _rule: IpRule) -> Result<()> {
        Ok(())
    }

    async fn add_domain_rule(&self, _rule: DomainRule) -> Result<()> {
        Ok(())
    }

    async fn remove_rule(&self, _rule_type: &str, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn enable_rule(&self, _rule_type: &str, _name: &str, _enabled: bool) -> Result<()> {
        Ok(())
    }
}

/// macOS DNS 处理器（占位实现）
#[derive(Debug)]
pub struct MacosDnsHandler {
    config: DnsConfig,
}

impl MacosDnsHandler {
    pub async fn new(config: DnsConfig) -> Result<Self> {
        warn!("MacosDnsHandler 是占位实现，功能未完成");
        Ok(Self { config })
    }
}

#[async_trait]
impl DnsHandler for MacosDnsHandler {
    fn config(&self) -> &DnsConfig {
        &self.config
    }

    fn stats(&self) -> DnsStats {
        DnsStats::default()
    }

    async fn start(&self) -> Result<()> {
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn handle_query(&self, _query: DnsQuery) -> Result<DnsResponse> {
        Err(anyhow!("MacosDnsHandler 未实现"))
    }
}
