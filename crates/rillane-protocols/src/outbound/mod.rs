//! 出口协议实现
//!
//! 提供各种出口协议的客户端连接器实现。

mod anytls;
mod direct;
mod grpc;
mod h2;
mod http;
mod httpupgrade;
mod hysteria2;
mod reality;
mod shadowsocks;
mod socks5;
mod trojan;
mod tuic;
mod vision;
mod vless;
mod vmess;
mod ws;
mod xhttp;
// android / armv7-ohos：defguard_boringtun 无平台支撑（见 wireguard_stub.rs 头注）——
// 实现剥离为恒 Err 桩，类型名保形使 runtime 侧零改动
#[cfg(not(any(
    target_os = "android",
    all(target_os = "linux", target_env = "ohos", target_arch = "arm")
)))]
mod wireguard;
#[cfg(any(
    target_os = "android",
    all(target_os = "linux", target_env = "ohos", target_arch = "arm")
))]
mod wireguard_stub;

pub use anytls::{AnytlsConnector, AnytlsUdpConnector};
pub use direct::DirectConnector;
pub use http::HttpConnector;
pub use hysteria2::{Hysteria2Connector, Hysteria2UdpConnector, Hysteria2UdpRelay, UdpSessionStats};
pub use reality::{
    derive_auth_key, extract_client_random, extract_session_id, extract_x25519_key_share,
    handshake, hmac_cert_tag, open_session_id, seal_session_id, zero_session_id_slot,
    RealityAuthSession, RealityDial, RealityStream, TlsAdapter, CORE_VERSION,
};
pub use shadowsocks::{ShadowsocksConnector, ShadowsocksUdpConnector};
pub use socks5::{Socks5Connector, Socks5UdpConnector};
pub use trojan::{TrojanConnector, TrojanUdpConnector};
pub use tuic::{TuicConnector, TuicStream, TuicUdpConnector, TuicUdpRelay};
pub use vision::{
    is_complete_tls_record, padding_len, relay, vision_flow_addons, FrameBuilder, FrameDecoder,
    InnerTlsFilter, VisionRelayStats, VisionSignal, VisionTlsFace, VisionWriteAction,
    VisionWritePolicy, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END,
    DEFAULT_TESTSEED, FLOW_VISION,
};
pub use vless::{VlessConnector, VlessUdpConnector};
pub use vmess::{VmessConnector, VmessSecurity, VmessUdpConnector};
#[cfg(not(any(
    target_os = "android",
    all(target_os = "linux", target_env = "ohos", target_arch = "arm")
)))]
pub use wireguard::{WireguardConnector, WireguardUdpConnector};
#[cfg(any(
    target_os = "android",
    all(target_os = "linux", target_env = "ohos", target_arch = "arm")
))]
pub use wireguard_stub::{WireguardConnector, WireguardUdpConnector};

use std::sync::Arc;

/// 出口连接器的类型别名
pub type DynEgressConnector = Arc<dyn rillane_core::EgressConnector>;
