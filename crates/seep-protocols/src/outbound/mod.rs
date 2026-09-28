//! 出口协议实现
//!
//! 提供各种出口协议的客户端连接器实现。

mod direct;
mod http;
mod hysteria2;
mod shadowsocks;
mod socks5;
mod trojan;
mod vless;
mod wireguard;

pub use direct::DirectConnector;
pub use http::HttpConnector;
pub use hysteria2::Hysteria2Connector;
pub use shadowsocks::{ShadowsocksConnector, ShadowsocksUdpConnector};
pub use socks5::Socks5Connector;
pub use trojan::TrojanConnector;
pub use vless::VlessConnector;
pub use wireguard::{WireguardConnector, WireguardUdpConnector};

use std::sync::Arc;

/// 出口连接器的类型别名
pub type DynEgressConnector = Arc<dyn seep_core::EgressConnector>;
