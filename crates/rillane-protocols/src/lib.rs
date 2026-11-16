//! Rillane 协议实现
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
pub use inbound::{
    HttpIngress, Hysteria2Ingress, Hysteria2UdpParts, HysteriaIngress, HysteriaUdpParts,
    MixedIngress, ShadowsocksIngress, ShadowsocksUdpParts, Socks5Ingress, TrojanIngress,
    TrojanUdpParts, VlessIngress, VlessUdpParts, VmessIngress, VmessUdpParts,
};
pub use middleware::LatencyProbe;
pub use outbound::{
    AnytlsConnector, AnytlsUdpConnector, DirectConnector, HttpConnector, Hysteria2Connector,
    Hysteria2UdpConnector, Hysteria2UdpRelay, HysteriaConnector, HysteriaUdpConnector,
    HysteriaUdpRelay, ShadowsocksConnector, ShadowsocksShadowTlsConnector, ShadowsocksUdpConnector,
    Socks5Connector,
    Socks5UdpConnector, TrojanConnector, TrojanUdpConnector, TuicConnector, TuicStream,
    TuicUdpConnector, TuicUdpRelay, VlessConnector, VlessUdpConnector, VmessConnector,
    VmessSecurity, VmessUdpConnector, WireguardConnector, WireguardUdpConnector,
};
pub use pool::{
    BoxedIo, KeySnapshot, LeaseGuard, MockPoolClock, PoolClock, PoolPolicy, PoolSnapshot,
    SystemClock, TransportKey, TransportPool,
};
pub use tls::TlsConnectorFactory;

/// 目标主机是否含 HTTP 请求行/头注入字符（空 / CR / LF / 控制字符 /
/// 空格 / authority 元字符）。
///
/// P1 安全：SOCKS5 入口的域名字符串与 HTTP CONNECT 出口都把 host 内插进
/// 请求行与 `Host` 头。未校验即允许 SOCKS5 客户端向上游代理注入任意头
/// （请求走私/头伪造）——出口层为最后防线，入口层为第一道闸。
///
/// 空格分隔请求行，`@`/`/`/`?`/`#` 为 URI authority 分隔符：host 内插进
/// CONNECT 请求行与 `Host` 头时，这些字符可被上游按 `userinfo@host`、
/// `host/path`、`host?query`、`host#fragment` 解析致目标混淆（请求走私/
/// SSRF 变体），故一并拒绝。
pub(crate) fn host_has_injection_chars(host: &str) -> bool {
    host.is_empty()
        || host.bytes().any(|b| {
            b < 0x20 || b == 0x7F || b == b' ' || b == b'@' || b == b'/' || b == b'?' || b == b'#'
        })
}
