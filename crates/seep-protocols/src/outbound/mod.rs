//! 出口协议实现
//!
//! 提供各种出口协议的客户端连接器实现。

mod direct;
mod grpc;
mod h2;
mod http;
mod hysteria2;
mod shadowsocks;
mod socks5;
mod trojan;
mod vless;
mod vmess;
mod ws;
// android：defguard_boringtun 无平台支撑（见 wireguard_stub.rs 头注）——
// 实现剥离为恒 Err 桩，类型名保形使 runtime 侧零改动
#[cfg(not(target_os = "android"))]
mod wireguard;
#[cfg(target_os = "android")]
mod wireguard_stub;

pub use direct::DirectConnector;
pub use http::HttpConnector;
pub use hysteria2::Hysteria2Connector;
pub use shadowsocks::{ShadowsocksConnector, ShadowsocksUdpConnector};
pub use socks5::Socks5Connector;
pub use trojan::TrojanConnector;
pub use vless::VlessConnector;
pub use vmess::{VmessConnector, VmessSecurity};
#[cfg(not(target_os = "android"))]
pub use wireguard::{WireguardConnector, WireguardUdpConnector};
#[cfg(target_os = "android")]
pub use wireguard_stub::{WireguardConnector, WireguardUdpConnector};

use std::sync::Arc;

/// 出口连接器的类型别名
pub type DynEgressConnector = Arc<dyn seep_core::EgressConnector>;
