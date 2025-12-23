//! Seep 协议实现
//!
//! 提供入口（Ingress）和出口（Egress）协议的具体实现。
//!
//! ## 入口协议
//! - SOCKS5 - 完整支持，含用户名密码认证
//! - HTTP Proxy - HTTP CONNECT 隧道代理
//!
//! ## 出口协议
//! - Direct - 直连目标服务器
//! - SOCKS5 - 通过 SOCKS5 代理连接
//! - HTTP - 通过 HTTP CONNECT 代理连接
//! - Shadowsocks - Shadowsocks 协议
//! - Trojan - Trojan 协议（TLS + 密码认证）

pub mod inbound;
pub mod outbound;
pub mod middleware;
mod tls;

pub use inbound::{HttpIngress, MixedIngress, Socks5Ingress};
pub use outbound::{
    DirectConnector, HttpConnector, Hysteria2Connector, ShadowsocksConnector, Socks5Connector,
    TrojanConnector,
};
pub use middleware::LatencyProbe;
