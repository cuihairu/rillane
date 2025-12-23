//! 出口协议实现
//!
//! 提供各种出口协议的客户端连接器实现。

mod direct;
mod socks5;
mod http;
mod shadowsocks;
mod trojan;
mod hysteria2;

pub use direct::DirectConnector;
pub use socks5::Socks5Connector;
pub use http::HttpConnector;
pub use shadowsocks::ShadowsocksConnector;
pub use trojan::TrojanConnector;
pub use hysteria2::Hysteria2Connector;

use std::sync::Arc;

/// 出口连接器的类型别名
pub type DynEgressConnector = Arc<dyn seep_core::EgressConnector>;
