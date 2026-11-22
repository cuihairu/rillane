//! 协议目录与注册契约（RIL-104）：出口协议的编目、准入与选库证据锚点。
//!
//! - **编目即事实**：每个出口协议类型在目录中恰有一条记录——已评审准入
//!   （带证据锚点与选库结论）或明确未准入（带原因）。目录外类型不存在
//!   「隐式可用」；配置 IR 是封闭枚举，未知类型在订阅转换面即被丢弃/拒绝，
//!   IR 面只会出现编目内类型。
//! - **准入才进热路径**：装配期（RuntimeBuilder）先查目录，未准入类型在
//!   建立任何连接器之前以稳定原因码拒绝——未审核配置不会走到拨号/转发。
//! - **无实现证据是自写前置**：准入条目必须带评估记录锚点（版本、许可、
//!   平台、公开 API、旁路/取消/统计与复用结论）；「无可选库」的结论本身
//!   也要留证，之后才允许自写实现（RIL-105..134 的统一前置）。
//!
//! 数据报能力列与运行期构建期扫描（runtime `scan_udp_capability`，口径
//! 同 udp-relay-path §3.1 能力表）一致：目录是静态事实源，扫描是执行面。

use crate::EgressConfig;

/// 稳定原因码：出口类型已编目但后端未准入（装配期拒绝）。
pub const CODE_EGRESS_NOT_ADMITTED: &str = "config.egress.not_admitted";

/// 后端来源（选库结论的机器口径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// 仓库自写实现（评估记录以源路径为证据；「无可选库」结论留证后才自写）
    InTree {
        /// 自写实现的源路径
        path: &'static str,
    },
    /// 第三方库（评估记录点名版本、许可、平台、公开 API）
    Library {
        /// 库名（crates.io 名）
        crate_name: &'static str,
        /// 版本要求（Cargo.toml 声明；lock 实测版本在评估记录）
        version_req: &'static str,
        /// 许可（SPDX 表达式，取自库发布清单）
        license: &'static str,
    },
    /// 尚无后端（未准入的根因——不允许静默当 direct 用）
    None,
}

/// 注册状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// 已评审准入：证据锚点指向两语文档同名小节（`## <kind>`），
    /// 小节内必含版本/许可/平台/公开 API/旁路/取消/统计/复用/结论。
    Admitted {
        /// 评估记录锚点（相对 docs/ 的路径 + 小节锚）
        evidence: &'static str,
    },
    /// 编目在案但未准入：配置可解析，装配期拒绝——不进热路径。
    NotAdmitted {
        /// 拒绝原因（点名缺什么、谁是前置）
        reason: &'static str,
    },
}

/// 目录条目：一个出口协议类型的全部编目事实。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    /// 稳定类型名（= IR 出口类型口径，与 runtime `egress_kind` 同源）
    pub kind: &'static str,
    pub registration: Registration,
    /// 数据报能力（目录口径 = 构建期 UDP 能力扫描的支持集）
    pub udp: bool,
    pub backend: Backend,
}

impl CatalogEntry {
    /// 已准入则返回证据锚点
    pub fn evidence(self) -> Option<&'static str> {
        match self.registration {
            Registration::Admitted { evidence } => Some(evidence),
            Registration::NotAdmitted { .. } => None,
        }
    }
}

/// 协议目录（静态事实源；顺序即文档顺序）。
pub const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        kind: "reject",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#reject",
        },
        udp: true, // UDP 面注册为静默丢弃连接器（与 TCP 同口径拦截）
        backend: Backend::InTree {
            path: "crates/rillane-core/src/udp（RejectUdpConnector）+ rillane-runtime RejectFlowOutput",
        },
    },
    CatalogEntry {
        kind: "direct",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#direct",
        },
        udp: true,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/direct.rs",
        },
    },
    CatalogEntry {
        kind: "socks5",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#socks5",
        },
        // RIL-132：出站 UDP ASSOCIATE 自写面（tokio-socks 无 UDP 面——
        // 选库结论留证于评估记录）
        udp: true,
        backend: Backend::Library {
            crate_name: "tokio-socks",
            version_req: "0.5",
            license: "MIT",
        },
    },
    CatalogEntry {
        kind: "http",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#http",
        },
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/http.rs",
        },
    },
    CatalogEntry {
        kind: "shadowsocks",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#shadowsocks",
        },
        udp: true, // 插件（SIP003）模式 UDP 判负——见评估记录
        backend: Backend::Library {
            crate_name: "shadowsocks",
            version_req: "1.25",
            license: "MIT",
        },
    },
    CatalogEntry {
        kind: "shadowsocks-shadow-tls",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#shadowsocks-shadow-tls",
        },
        // RIL-110：载具与内层 SS 组合均无 UDP 面（shadow-tls 仅 TCP 伪
        // 记录中继）——节点判负 UDP 连接器
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/shadowtls.rs",
        },
    },
    CatalogEntry {
        kind: "vmess",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#vmess",
        },
        udp: true, // 仅 network=tcp（ws/grpc/h2 的 UDP 面未实现）
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/vmess.rs",
        },
    },
    CatalogEntry {
        kind: "vless",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#vless",
        },
        // RIL-107：reality 传输面随客户端交付（rustls fork pin）；RIL-108：
        // flow=xtls-rprx-vision 分帧随客户端交付（其余 flow 拨号期点名拒绝）
        udp: true, // 仅 network=tcp；vless+reality 的 UDP 面走 VLESS UDP 面
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/vless.rs",
        },
    },
    CatalogEntry {
        kind: "trojan",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#trojan",
        },
        udp: true, // 恒叠 TLS 且仅 network=tcp
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/trojan.rs",
        },
    },
    CatalogEntry {
        kind: "anytls",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#anytls",
        },
        // RIL-106：UoT（UDP-over-TCP）面随客户端特性交付（按库实际能力）
        udp: true,
        backend: Backend::Library {
            crate_name: "anytls",
            version_req: "0.5",
            license: "MIT",
        },
    },
    CatalogEntry {
        kind: "hysteria",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#hysteria",
        },
        // RIL-109：官方 UDP 会话+数据报协议自写面（v1 无任何可用库——评估
        // 留证后自写；obfs/wechat/faketcp 包层传输判负，载具 = 原生 UDP 上的 QUIC）
        udp: true,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/hysteria.rs",
        },
    },
    CatalogEntry {
        kind: "hysteria2",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#hysteria2",
        },
        udp: true, // RIL-133：官方 UDPMessage 数据报协议自写面（crate 无数据报 API，obfs 判负）
        backend: Backend::Library {
            crate_name: "hysteria2",
            version_req: "0.1.6",
            license: "MulanPSL-2.0",
        },
    },
    CatalogEntry {
        kind: "tuic",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#tuic",
        },
        // RIL-105：官方 v5 Packet 数据报面随客户端自写交付
        // （tuic 家族全版本 yanked + GPL-3.0 结论留证）
        udp: true,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/tuic.rs",
        },
    },
    CatalogEntry {
        kind: "wireguard",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#wireguard",
        },
        udp: true,
        backend: Backend::Library {
            crate_name: "defguard_wireguard_rs",
            version_req: "0.11",
            license: "Apache-2.0",
        },
    },
    CatalogEntry {
        kind: "snell",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#snell",
        },
        // RIL-111：TCP 段自写面（obfs=none/v4）；官方 UDP over TCP 数据报面
        // 与协议内建复用未交付
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/snell.rs",
        },
    },
    CatalogEntry {
        kind: "shadowquic",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#shadowquic",
        },
        // RIL-118：库承载 TCP 面（shadowquic 0.4.12——协议自身 Rust 实现）；
        // 两种 UDP 中继面（over-datagram / over-stream）与服务端面未交付
        udp: false,
        backend: Backend::Library {
            crate_name: "shadowquic",
            version_req: "0.4.12",
            license: "MIT",
        },
    },
    CatalogEntry {
        kind: "mieru",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#mieru",
        },
        // RIL-116：官方 protocol.md 自写 TCP 客户端面（GPL 源未读——纯
        // spec + 官方二进制黑盒对端）；UDP 载具与服务端面未交付
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/mieru.rs",
        },
    },
    CatalogEntry {
        kind: "trusttunnel",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#trusttunnel",
        },
        // RIL-119：官方 PROTOCOL.md v1.0 自写客户端面（Apache-2.0 端点
        // 仓二进制黑盒对端）；TCP + UDP 两面交付，H3/QUIC 载具与 ICMP/
        // 服务器面不交付
        udp: true,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/trusttunnel.rs",
        },
    },
    CatalogEntry {
        kind: "masque",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#masque",
        },
        // RIL-120：RFC 9298 CONNECT-UDP 自写客户端面（真实对端 = 本地
        // 构建的 quic-go/masque-go v0.6.0 cmd/proxy，MIT；TCP 面留证对端
        // = 进程内 h3 镜像对端——masque-go proxy 无通用 CONNECT handler）；
        // TCP + UDP 两面交付；连接复用池与 mihomo 密钥隧道面未交付
        udp: true,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/masque.rs",
        },
    },
    CatalogEntry {
        kind: "openconnect",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#openconnect",
        },
        // RIL-121：CSTP 自写客户端面（真实对端 = apt ocserv 1.3.0，本地
        // /home/cui/ocpeer；线格式对照 OpenConnect 源码 cstp.c/auth.c 核
        // 读）；TCP 面交付（用户态 smoltcp 三层桥 + 隧道 DNS），UDP/QUIC
        // 应用面、DTLS 数据面与系统 TUN 路线未交付
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/openconnect.rs",
        },
    },
    CatalogEntry {
        kind: "openvpn",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#openvpn",
        },
        // RIL-122：corevpn-protocol 0.6.0 库承载三层 VPN 客户端面（标准对端 =
        // apt openvpn 2.7.0，本席实机互通实测：TLS 1.3 握手 + KeyMethodV2 +
        // PUSH_REPLY + 数据通道密钥派生全链通过）；TCP 面交付（用户态
        // smoltcp 三层桥，与 OpenConnect 共用栈），UDP/QUIC 应用面、服务端
        // 面与系统 TUN 路线未交付
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/openvpn.rs",
        },
    },
    CatalogEntry {
        kind: "tailscale",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#tailscale",
        },
        // RIL-123：tailscale 0.7.1（tailscale-rs）库承载三层 mesh 客户端面
        // （自托管 headscale 或官方协调端点 + preauth key + WireGuard 数据
        // 通道经 ts_netstack_smoltcp 用户态栈，Device::tcp_connect 直出
        // 已解封 TCP 流）；TCP 面交付，UDP/QUIC 应用面、服务端面与系统 TUN
        // 路线未交付（载具 pre-1.0 无兼容保证、NAT 穿透在研可能回退 DERP）
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/tailscale.rs",
        },
    },
    CatalogEntry {
        kind: "tailcat",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#tailcat",
        },
        // RIL-127：tailcat-client 0.1.1（kosumic/whip，MIT）库承载 mesh 客户端
        // 面（出口）——tc 紧凑地址即端点身份（服务端 WireGuard 公钥 + 发现密钥 +
        // DERP 区域 + 预共享密钥，即访问凭证），boringtun WireGuard + smoltcp
        // 0.14 用户态栈 + DERP 中继，dial_tcp 直出已解封 TCP 流（无 TUN/无路由/
        // 无 root）；TCP 面交付，UDP/QUIC 应用面与服务端面未交付（载具 client-
        // only；入口/服务端载具 tailcat 0.1.0 被 ssh-key 精确 rc 冲突硬阻断——
        // 见 protocol-backends.md#tailcat）
        udp: false,
        backend: Backend::InTree {
            path: "crates/rillane-protocols/src/outbound/tailcat.rs",
        },
    },
    CatalogEntry {
        kind: "ssh",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#ssh",
        },
        // RIL-113：russh 客户端面（direct-tcpip 仅 TCP）；协议内建通道复用
        // 与服务端面未交付
        udp: false,
        backend: Backend::Library {
            crate_name: "russh",
            version_req: "0.65",
            license: "Apache-2.0",
        },
    },
    CatalogEntry {
        kind: "tor",
        registration: Registration::Admitted {
            evidence: "protocol-backends.md#tor",
        },
        // RIL-114：arti-client 嵌入式客户端面（逐流隔离，客户端流仅 TCP）；
        // 服务端面（onion service）未交付
        udp: false,
        backend: Backend::Library {
            crate_name: "arti-client",
            version_req: "0.48",
            license: "MIT OR Apache-2.0",
        },
    },
];

/// 目录条目查询。
pub fn entry_for(kind: &str) -> Option<&'static CatalogEntry> {
    CATALOG.iter().find(|e| e.kind == kind)
}

/// 准入判定（装配期热路径门）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// 已评审准入（可进装配）
    Admitted(&'static CatalogEntry),
    /// 已编目但未准入（装配期拒绝，带条目内原因）
    NotAdmitted(&'static CatalogEntry),
    /// 目录外类型（`config.egress.unknown`——IR 封闭枚举下装配面不可达，
    /// 保留给订阅转换/诊断面点名未知类型）
    Unknown,
}

/// 按类型名判定准入。
pub fn admission(kind: &str) -> Admission {
    match entry_for(kind) {
        Some(e) => match e.registration {
            Registration::Admitted { .. } => Admission::Admitted(e),
            Registration::NotAdmitted { .. } => Admission::NotAdmitted(e),
        },
        None => Admission::Unknown,
    }
}

/// IR 出口类型 → 稳定类型名（规范映射；runtime 的 `egress_kind` 委托本函数）。
pub const fn egress_kind(spec: &EgressConfig) -> &'static str {
    match spec {
        EgressConfig::Reject => "reject",
        EgressConfig::Direct => "direct",
        EgressConfig::Socks5 { .. } => "socks5",
        EgressConfig::Http { .. } => "http",
        EgressConfig::Shadowsocks { .. } => "shadowsocks",
        EgressConfig::ShadowsocksShadowTls { .. } => "shadowsocks-shadow-tls",
        EgressConfig::Vmess { .. } => "vmess",
        EgressConfig::Vless { .. } => "vless",
        EgressConfig::Trojan { .. } => "trojan",
        EgressConfig::Anytls { .. } => "anytls",
        EgressConfig::Hysteria { .. } => "hysteria",
        EgressConfig::Hysteria2 { .. } => "hysteria2",
        EgressConfig::Tuic { .. } => "tuic",
        EgressConfig::Snell { .. } => "snell",
        EgressConfig::ShadowQuic { .. } => "shadowquic",
        EgressConfig::Mieru { .. } => "mieru",
        EgressConfig::TrustTunnel { .. } => "trusttunnel",
        EgressConfig::Masque { .. } => "masque",
        EgressConfig::OpenConnect { .. } => "openconnect",
        EgressConfig::OpenVpn { .. } => "openvpn",
        EgressConfig::Tailscale { .. } => "tailscale",
        EgressConfig::Tailcat { .. } => "tailcat",
        EgressConfig::Ssh { .. } => "ssh",
        EgressConfig::Tor { .. } => "tor",
        EgressConfig::Wireguard { .. } => "wireguard",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::CODE_UNKNOWN_EGRESS;

    /// 构造每个 IR 出口变体（枚举增删字段即编译失败——目录必须同步更新），
    /// 断言规范映射逐一落在目录内。
    #[test]
    fn catalog_covers_every_egress_variant() {
        let samples = [
            EgressConfig::Reject,
            EgressConfig::Direct,
            EgressConfig::Socks5 {
                server: "203.0.113.1".into(),
                port: 1080,
                username: None,
                password: None,
            },
            EgressConfig::Http {
                server: "203.0.113.2".into(),
                port: 8080,
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
                sni: None,
                tls_fingerprint: None,
            },
            EgressConfig::Shadowsocks {
                server: "203.0.113.3".into(),
                port: 8388,
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                plugin: None,
                plugin_opts: None,
            },
            EgressConfig::ShadowsocksShadowTls {
                server: "203.0.113.30".into(),
                port: 8388,
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                shadow_tls: crate::ShadowTlsEgressConfig {
                    host: "camo.example.test".into(),
                    password: "carrier-pw".into(),
                    version: None,
                    skip_cert_verify: false,
                },
            },
            EgressConfig::Vmess {
                server: "203.0.113.4".into(),
                port: 443,
                uuid: "00000000-0000-0000-0000-000000000000".into(),
                alter_id: 0,
                security: "auto".into(),
                network: "tcp".into(),
                path: None,
                host: None,
                grpc_service_name: None,
                grpc_reuse: None,
                tls: true,
                skip_cert_verify: false,
                sni: None,
                alpn: None,
                tls_fingerprint: None,
            },
            EgressConfig::Vless {
                server: "203.0.113.5".into(),
                port: 443,
                uuid: "00000000-0000-0000-0000-000000000001".into(),
                flow: None,
                reality: None,
                network: "tcp".into(),
                path: None,
                host: None,
                grpc_service_name: None,
                grpc_reuse: None,
                xhttp_mode: None,
                packet_encoding: None,
                tls: true,
                skip_cert_verify: false,
                sni: None,
                alpn: None,
                tls_fingerprint: None,
            },
            EgressConfig::Trojan {
                server: "203.0.113.6".into(),
                port: 443,
                password: "pw".into(),
                network: "tcp".into(),
                path: None,
                host: None,
                grpc_service_name: None,
                grpc_reuse: None,
                tls: true,
                skip_cert_verify: false,
                sni: None,
                alpn: None,
                tls_fingerprint: None,
            },
            EgressConfig::Anytls {
                server: "203.0.113.11".into(),
                port: 443,
                password: "pw".into(),
                sni: None,
                skip_cert_verify: false,
            },
            EgressConfig::Hysteria {
                server: "203.0.113.7".into(),
                port: 443,
                password: "pw".into(),
                protocol: "udp".into(),
                up_mbps: None,
                down_mbps: None,
                auth: None,
                auth_str: None,
                obfs: None,
                obfs_param: None,
                server_name: None,
                skip_cert_verify: false,
                alpn: None,
            },
            EgressConfig::Hysteria2 {
                server: "203.0.113.8".into(),
                port: 443,
                password: "pw".into(),
                mport: None,
                obfs: None,
                obfs_param: None,
                server_name: None,
                skip_cert_verify: false,
                alpn: None,
            },
            EgressConfig::Tuic {
                server: "203.0.113.11".into(),
                port: 443,
                uuid: "2dd35bfe-7d81-4a7e-9325-97e5ae1f8e8e".into(),
                password: "pw".into(),
                congestion_controller: None,
                server_name: None,
                skip_cert_verify: false,
                alpn: None,
            },
            EgressConfig::Wireguard {
                endpoint: "203.0.113.9:51820".into(),
                private_key: "pk".into(),
                public_key: "pub".into(),
                address: "10.0.0.2/32".into(),
                allowed_ips: None,
                preshared_key: None,
                persistent_keepalive: None,
                listen_port: None,
                mtu: None,
                dns: None,
            },
            EgressConfig::Snell {
                server: "203.0.113.12".into(),
                port: 6160,
                psk: "pw".into(),
            },
            EgressConfig::ShadowQuic {
                server: "203.0.113.14".into(),
                port: 443,
                username: "u".into(),
                password: "pw".into(),
                server_name: None,
                alpn: None,
                congestion_controller: None,
                zero_rtt: None,
                udp_over_stream: None,
            },
            EgressConfig::Mieru {
                server: "203.0.113.15".into(),
                port: 23420,
                username: "u".into(),
                password: "pw".into(),
            },
            EgressConfig::TrustTunnel {
                server: "203.0.113.16".into(),
                port: 443,
                username: "u".into(),
                password: "pw".into(),
                sni: Some("tt.example.test".into()),
                skip_cert_verify: false,
                tls_fingerprint: None,
            },
            EgressConfig::Masque {
                server: "203.0.113.17".into(),
                port: 8443,
                sni: Some("masque.example.test".into()),
                skip_cert_verify: false,
                uri_template: None,
            },
            EgressConfig::OpenConnect {
                server: "203.0.113.20".into(),
                port: 443,
                username: "demo".into(),
                password: "demo".into(),
                sni: Some("openconnect.example.test".into()),
                skip_cert_verify: false,
            },
            EgressConfig::OpenVpn {
                server: "203.0.113.21".into(),
                port: 1194,
                ca_pem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".into(),
                cert_pem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".into(),
                key_pem: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n".into(),
                cipher: "AES-256-GCM".into(),
                tls_auth_key: None,
                key_direction: None,
                sni: Some("openvpn.example.test".into()),
            },
            EgressConfig::Tailscale {
                control_url: "http://127.0.0.1:8080".into(),
                auth_key: "preauth-key-xyz".into(),
                hostname: Some("rillane-node".into()),
                ephemeral: true,
                key_file: "/tmp/tsrs_keys.json".into(),
            },
            EgressConfig::Tailcat {
                server_address: "tcAAAA".into(),
                private_key: None,
                relay_only: true,
                derp_map_url: None,
            },
            EgressConfig::Ssh {
                server: "203.0.113.13".into(),
                port: 22,
                username: "cui".into(),
                password: None,
                private_key: Some("/tmp/id_ed25519".into()),
                private_key_passphrase: None,
                host_key: "SHA256:RX6tz+xibncBQGQAVCfeUBJ+NgVjabphorAM/IGnFPU".into(),
            },
            EgressConfig::Tor {
                proxy: Some("http://10.0.0.1:7897".into()),
            },
        ];
        assert_eq!(
            CATALOG.len(),
            samples.len(),
            "目录条目数 = IR 出口变体数（增变体必须同步编目）"
        );
        for spec in &samples {
            let kind = egress_kind(spec);
            let entry = entry_for(kind).unwrap_or_else(|| panic!("变体 {kind} 未编目"));
            assert_eq!(entry.kind, kind);
        }
        // 目录无重复类型名
        let mut kinds: Vec<_> = CATALOG.iter().map(|e| e.kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), CATALOG.len(), "类型名唯一");
    }

    /// 准入判定稳定：全目录条目均已准入（RIL-109 flip 后无未准入条目；
    /// 若再引入 NotAdmitted 条目，须同步在本测试与验收面登记拒绝样例）；
    /// 目录外类型 → Unknown（订阅/诊断面按 `config.egress.unknown` 点名）。
    #[test]
    fn admission_decisions_are_stable() {
        for e in CATALOG {
            let verdict = admission(e.kind);
            match e.registration {
                Registration::Admitted { .. } => {
                    assert!(
                        matches!(verdict, Admission::Admitted(got) if got.kind == e.kind),
                        "{} 应准入",
                        e.kind
                    );
                }
                Registration::NotAdmitted { reason } => {
                    panic!(
                        "编目出现未准入条目 {}（原因 {reason}）——准入决策面变更须同步登记拒绝样例",
                        e.kind
                    );
                }
            }
        }
        for unknown in ["ss", "trojan-go", ""] {
            assert_eq!(
                admission(unknown),
                Admission::Unknown,
                "目录外类型 {unknown} 应 Unknown"
            );
            assert_eq!(CODE_UNKNOWN_EGRESS, "config.egress.unknown");
        }
    }

    /// 准入条目必须带证据锚点与选库结论；未准入条目必须带原因且无后端；
    /// UDP 能力列与构建期扫描口径一致（§3.1 支持集）。
    #[test]
    fn admitted_requires_evidence_and_backend() {
        const UDP_SUPPORTED: [&str; 14] = [
            "direct",
            "shadowsocks",
            "wireguard",
            "reject",
            "vmess",
            "vless",
            "trojan",
            "socks5",
            "anytls",
            "hysteria",
            "hysteria2",
            "tuic",
            "trusttunnel",
            "masque",
        ];
        for e in CATALOG {
            match e.registration {
                Registration::Admitted { evidence } => {
                    assert!(
                        evidence.starts_with("protocol-backends.md#") && !evidence.ends_with('#'),
                        "{} 证据锚点须指向评估记录小节: {evidence}",
                        e.kind
                    );
                    assert_ne!(e.backend, Backend::None, "{} 已准入必须有选库结论", e.kind);
                    assert_eq!(
                        e.udp,
                        UDP_SUPPORTED.contains(&e.kind),
                        "{} UDP 能力列须与 §3.1 能力表一致",
                        e.kind
                    );
                }
                Registration::NotAdmitted { reason } => {
                    assert!(!reason.is_empty(), "未准入必带原因");
                    assert!(!e.udp, "未准入不声明 UDP 能力");
                    assert_eq!(e.backend, Backend::None);
                }
            }
        }
    }

    /// 证据记录存在性（RIL-104 验收核心）：每个已准入条目的锚点在两语文档
    /// 各有一个 `## <kind>` 小节，小节内必含 版本/许可/平台/公开 API/旁路/
    /// 取消/统计/复用/结论（中文）与对应英文字段——缺字段即测试失败，
    /// 「记录了什么」由文档小节承载，「必须记录什么」由本测试钉死。
    #[test]
    fn evidence_records_exist_for_every_admitted_entry() {
        const ZH_FIELDS: [&str; 9] = [
            "版本",
            "许可",
            "平台",
            "公开 API",
            "旁路",
            "取消",
            "统计",
            "复用",
            "结论",
        ];
        const EN_FIELDS: [&str; 9] = [
            "Version",
            "License",
            "Platforms",
            "Public API",
            "Bypass",
            "Cancel",
            "Stats",
            "Reuse",
            "Conclusion",
        ];
        let manifest = env!("CARGO_MANIFEST_DIR");
        let zh = std::fs::read_to_string(format!("{manifest}/../../docs/zh/protocol-backends.md"))
            .expect("中文评估记录须存在");
        let en = std::fs::read_to_string(format!("{manifest}/../../docs/protocol-backends.md"))
            .expect("英文评估记录须存在");

        // 按 `## ` 切小节，取 `## <kind>` 起到下一小节（或 EOF）的内容
        let section = |doc: &str, kind: &str| -> String {
            let header = format!("## {kind}");
            let start = doc
                .find(&format!("\n{header}\n"))
                .expect("小节锚点须存在且独立成行");
            let rest = &doc[start + 1..];
            let end = rest[header.len()..]
                .find("\n## ")
                .map(|p| p + header.len() + 1)
                .unwrap_or(rest.len());
            rest[..end].to_string()
        };

        for e in CATALOG.iter().filter(|e| e.evidence().is_some()) {
            let zh_sec = section(&zh, e.kind);
            let en_sec = section(&en, e.kind);
            for f in ZH_FIELDS {
                assert!(zh_sec.contains(f), "zh#{} 小节缺字段「{f}」", e.kind);
            }
            for f in EN_FIELDS {
                assert!(
                    en_sec.contains(f),
                    "en#{} section missing field \"{f}\"",
                    e.kind
                );
            }
            // 选库结论与目录机器口径一致：库名/自写路径必须出现在小节里
            match e.backend {
                Backend::Library {
                    crate_name,
                    version_req,
                    ..
                } => {
                    assert!(
                        zh_sec.contains(crate_name) && en_sec.contains(crate_name),
                        "{} 小节须点名选库 {crate_name}",
                        e.kind
                    );
                    assert!(
                        zh_sec.contains(version_req),
                        "zh#{} 小节须记录版本要求 {version_req}",
                        e.kind
                    );
                }
                Backend::InTree { path } => {
                    let src = path.split("（").next().unwrap_or(path);
                    let dir = src.split(" + ").next().unwrap_or(src);
                    assert!(
                        zh_sec.contains(dir) && en_sec.contains(dir),
                        "{} 小节须点名自写路径 {dir}",
                        e.kind
                    );
                }
                Backend::None => unreachable!("准入条目无 None 后端"),
            }
        }
    }
}
