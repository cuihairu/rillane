//! wireguard 出站的 android 构建占位（P3-4）
//!
//! defguard_boringtun 0.6 无 android 支撑（内部 `tun` crate 不识别目标
//! E0432 + cfg 面守卫类型错位 E0308，实测定；见 platforms/android/README.md
//! 边界节）——android 目标下实现整体剥离，仅保留同形类型：构造恒 Err /
//! forward 恒 Err，runtime 侧 egress 工厂构建期即拦截。口径同 network
//! 四工厂非 Linux 恒 Err 与 windows `ensure_interface` 双定义先例。
//! 宿主（linux/mac/windows）面零差异。

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowContext, FlowReport, RouteDecision};
use std::sync::Arc;

/// wireguard 出站占位（android：构造成功但 forward 恒 Err——构造签名保形）
pub struct WireguardConnector;

#[allow(clippy::too_many_arguments)]
impl WireguardConnector {
    pub fn new(
        _egress_name: String,
        _endpoint: String,
        _private_key: String,
        _public_key: String,
        _address: String,
        _allowed_ips: Option<Vec<String>>,
        _preshared_key: Option<String>,
        _persistent_keepalive: Option<u16>,
        _listen_port: Option<u16>,
        _mtu: Option<u16>,
        _dns: Option<Vec<String>>,
    ) -> Self {
        Self
    }
}

#[async_trait]
impl EgressConnector for WireguardConnector {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    async fn forward(&self, _flow: Flow) -> Result<FlowReport> {
        Err(anyhow!(
            "WireGuard 出站不支持 android 构建（boringtun 无平台支撑）"
        ))
    }
}

/// wireguard UDP 出站占位：构造即 Err（runtime 侧 egress 工厂在此拦截）
pub struct WireguardUdpConnector;

impl WireguardUdpConnector {
    pub fn new(_allowed_ips: Option<Vec<String>>, _mtu: Option<u16>) -> Result<Self> {
        Err(anyhow!(
            "WireGuard 出站不支持 android 构建（boringtun 无平台支撑）"
        ))
    }
}

#[async_trait]
impl seep_core::udp::EgressUdpConnector for WireguardUdpConnector {
    fn name(&self) -> &str {
        "wireguard"
    }

    async fn associate(
        &self,
        _ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn seep_core::udp::UdpRelay>> {
        Err(anyhow!(
            "WireGuard 出站不支持 android 构建（boringtun 无平台支撑）"
        ))
    }
}
