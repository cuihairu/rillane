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
//! - WireGuard - WireGuard VPN（系统级接口）

pub mod fingerprint;
pub mod inbound;
pub mod middleware;
pub mod outbound;
pub mod pool;
mod tls;

pub use fingerprint::TlsFingerprint;
pub use inbound::{HttpIngress, MixedIngress, Socks5Ingress};
pub use middleware::LatencyProbe;
pub use outbound::{
    DirectConnector, HttpConnector, Hysteria2Connector, ShadowsocksConnector,
    ShadowsocksUdpConnector, Socks5Connector, TrojanConnector, VlessConnector, WireguardConnector,
    WireguardUdpConnector,
};
pub use pool::{
    BoxedIo, KeySnapshot, LeaseGuard, MockPoolClock, PoolClock, PoolPolicy, PoolSnapshot,
    SystemClock, TransportKey, TransportPool,
};
pub use tls::TlsConnectorFactory;
