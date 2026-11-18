//! 协议目录准入验收（RIL-104）：未准入/编目外出口类型在装配期被点名稳
//! 定原因码拒绝——未审核配置不能进热路径（建立任何连接器之前）；目录的
//! UDP 能力列与运行期构建期能力扫描（udp-relay-path §3.1 口径）在装配
//! 面一致。

use rillane_config::{
    protocol_catalog, ControlConfig, EgressConfig, EgressDescriptor, IngressConfig,
    IngressDescriptor, RillaneConfig, RoutingConfig, TelemetryConfig, UdpConfig,
};
use rillane_runtime::{RuntimeBuilder, RuntimeConfig};

/// 可装配配置外壳（订阅产物无关——本验收直接手写 IR 面）
fn shell(egress: Vec<EgressDescriptor>, default_node: &str, udp_enabled: bool) -> RillaneConfig {
    RillaneConfig {
        version: rillane_config::ConfigVersion::default(),
        control: ControlConfig {
            api_bind: "127.0.0.1:0".to_string(),
            uds_path: None,
            admin_token: None,
        },
        telemetry: TelemetryConfig {
            log_level: "warn".to_string(),
            enable_metrics: false,
            enable_tracing: false,
        },
        ingress: vec![IngressDescriptor {
            name: "admission-socks".to_string(),
            spec: IngressConfig::Socks5 {
                bind: "127.0.0.1:0".to_string(),
                auth: None,
                udp_enabled: Some(false),
            },
        }],
        egress,
        routing: RoutingConfig {
            default_node: default_node.to_string(),
            ..Default::default()
        },
        udp: UdpConfig {
            enabled: udp_enabled,
            ..Default::default()
        },
        network: None,
        obfuscation: None,
        profile: None,
        scenarios: Default::default(),
        performance: None,
        egress_pool: None,
        probe: None,
    }
}

fn opts() -> RuntimeConfig {
    RuntimeConfig {
        enable_hot_reload: false,
        ..RuntimeConfig::default()
    }
}

fn direct_node() -> EgressDescriptor {
    EgressDescriptor {
        name: "direct-out".to_string(),
        spec: EgressConfig::Direct,
    }
}

/// Hysteria v1 节点（RIL-109 已准入：自写面，载具 = 原生 UDP 上的 QUIC；
/// 参数可参——protocol/obfs 组合驱动载具判负样例）
#[allow(clippy::too_many_arguments)]
fn hysteria_node_params(
    name: &str,
    protocol: &str,
    obfs: Option<&str>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
) -> EgressDescriptor {
    EgressDescriptor {
        name: name.to_string(),
        spec: EgressConfig::Hysteria {
            server: "203.0.113.7".to_string(),
            port: 443,
            password: "REDACTED".to_string(),
            protocol: protocol.to_string(),
            up_mbps,
            down_mbps,
            auth: None,
            auth_str: None,
            obfs: obfs.map(str::to_string),
            obfs_param: obfs.map(|_| "30:REDACTED".to_string()),
            server_name: None,
            skip_cert_verify: false,
            alpn: None,
        },
    }
}

fn hysteria_node() -> EgressDescriptor {
    hysteria_node_params("hy1-node", "udp", None, None, None)
}

fn hysteria2_node() -> EgressDescriptor {
    EgressDescriptor {
        name: "hy2-out".to_string(),
        spec: EgressConfig::Hysteria2 {
            server: "203.0.113.8".to_string(),
            port: 443,
            password: "REDACTED".to_string(),
            mport: None,
            obfs: None,
            obfs_param: None,
            server_name: None,
            skip_cert_verify: false,
            alpn: None,
        },
    }
}

/// 目录机器口径（RIL-109 flip 后）：全目录条目均已准入且带证据锚点与
/// 选库结论——装配期「未准入拒绝」路径成为纯防御面（无编目条目可触发，
/// 回归由目录单测钉住）；目录外类型恒 Unknown（订阅转换/诊断面点名）。
#[test]
fn catalog_entries_all_admitted_with_evidence() {
    assert_eq!(protocol_catalog::CATALOG.len(), 16, "全目录十六条");
    for e in protocol_catalog::CATALOG {
        let evidence = e
            .evidence()
            .unwrap_or_else(|| panic!("{} 已准入必带证据锚点", e.kind));
        assert!(
            evidence.starts_with("protocol-backends.md#"),
            "{} 证据锚点口径: {evidence}",
            e.kind
        );
        assert!(
            !matches!(e.backend, protocol_catalog::Backend::None),
            "{} 已准入必有选库结论",
            e.kind
        );
        assert_eq!(
            protocol_catalog::admission(e.kind),
            protocol_catalog::Admission::Admitted(e),
            "{} 准入判定稳定",
            e.kind
        );
    }
    // hysteria v1 具体口径（RIL-109）：自写面 + UDP 数据报承载
    let hy = protocol_catalog::entry_for("hysteria").expect("已编目");
    assert!(hy.udp, "RIL-109 数据报面已承载");
    assert!(
        matches!(
            hy.backend,
            protocol_catalog::Backend::InTree {
                path: "crates/rillane-protocols/src/outbound/hysteria.rs"
            }
        ),
        "hysteria 后端 = 仓库自写: {:?}",
        hy.backend
    );
    // shadow-tls 组合具体口径（RIL-110）：自写面 + 载具无 UDP 面（组合判负）
    let st = protocol_catalog::entry_for("shadowsocks-shadow-tls").expect("已编目");
    assert!(!st.udp, "RIL-110 载具与内层 SS 组合均无 UDP 面");
    assert!(
        matches!(
            st.backend,
            protocol_catalog::Backend::InTree {
                path: "crates/rillane-protocols/src/outbound/shadowtls.rs"
            }
        ),
        "shadow-tls 组合后端 = 仓库自写: {:?}",
        st.backend
    );
    // snell 具体口径（RIL-111）：自写面 + 无 UDP 面（数据报面未交付）
    let sn = protocol_catalog::entry_for("snell").expect("已编目");
    assert!(!sn.udp, "RIL-111 TCP 段自写面，UDP 数据报面未交付");
    assert!(
        matches!(
            sn.backend,
            protocol_catalog::Backend::InTree {
                path: "crates/rillane-protocols/src/outbound/snell.rs"
            }
        ),
        "snell 后端 = 仓库自写: {:?}",
        sn.backend
    );
    // ssh 具体口径（RIL-113）：russh 承载 + 无 UDP 面（direct-tcpip 仅 TCP）
    let ssh = protocol_catalog::entry_for("ssh").expect("已编目");
    assert!(!ssh.udp, "RIL-113 direct-tcpip 仅 TCP，UDP 面未交付");
    assert!(
        matches!(
            ssh.backend,
            protocol_catalog::Backend::Library {
                crate_name: "russh",
                version_req: "0.65",
                license: "Apache-2.0"
            }
        ),
        "ssh 后端 = russh 库承载: {:?}",
        ssh.backend
    );
    for unknown in ["mieru", "ss", ""] {
        assert_eq!(
            protocol_catalog::admission(unknown),
            protocol_catalog::Admission::Unknown,
            "目录外类型 {unknown} 应 Unknown"
        );
    }
}

/// Hysteria v1 装配面（RIL-109）：基础组合作为 default 装配成功（TCP 工厂
/// 全变体穷尽——hysteria 臂接入后编译期兜底）；UDP 开启时基础组合产数据报
/// 连接器装配成功，载具判负组合（obfs 包层传输）被能力扫描构建期点名。
#[test]
fn hysteria_assembly_carrier_gate() {
    // 正面：default=hy1-node（基础组合，速率缺省）→ 装配成功（仅装配，不启动）
    let cfg = shell(vec![direct_node(), hysteria_node()], "hy1-node", false);
    let _ok_runtime = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("hysteria 基础组合装配成功（RIL-109 自写面）");

    // 正面：UDP 开 + hysteria（目录 udp=true）→ 数据报连接器注册，装配成功
    let cfg = shell(vec![direct_node(), hysteria_node()], "hy1-node", true);
    let _ok_runtime = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("hysteria UDP 数据报面装配成功");

    // 反面：UDP 开 + obfs 包层传输（换整个 QUIC 载荷）→ 能力扫描点名判负
    let obfs_node = hysteria_node_params("hy1-obfs", "udp", Some("salamander"), None, None);
    let cfg = shell(vec![direct_node(), obfs_node], "hy1-obfs", true);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("UDP 可达集内的包层传输节点须构建期判负");
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("不支持 UDP"), "能力扫描点名: {rendered}");
    assert!(rendered.contains("hy1-obfs"), "点名节点: {rendered}");

    // 反面：UDP 开 + protocol 非 "udp"（无 QUIC 载具）→ 能力扫描点名判负
    let faketcp_node = hysteria_node_params("hy1-faketcp", "faketcp", None, None, None);
    let cfg = shell(vec![direct_node(), faketcp_node], "hy1-faketcp", true);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("UDP 可达集内的非 QUIC 载具节点须构建期判负");
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("不支持 UDP"), "能力扫描点名: {rendered}");
    assert!(rendered.contains("hy1-faketcp"), "点名节点: {rendered}");
}

/// HTTP 代理节点（目录 udp=false——CONNECT 仅隧道面）
fn http_node() -> EgressDescriptor {
    EgressDescriptor {
        name: "http-out".to_string(),
        spec: EgressConfig::Http {
            server: "203.0.113.10".to_string(),
            port: 8080,
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
            sni: None,
            tls_fingerprint: None,
        },
    }
}

/// 目录 UDP 能力列与构建期扫描一致：hysteria2 已准入且 UDP 数据报面随
/// RIL-133 交付（目录 udp=true）——基础组合（无 obfs）作为 default 装配
/// 成功；开 UDP 后无 UDP 类型（http，目录 udp=false）仍被点名判负
/// （扫描按能力判，不一刀切）。
#[test]
fn catalog_udp_column_matches_build_scan() {
    let entry = protocol_catalog::entry_for("hysteria2").expect("已编目");
    assert!(
        entry.udp,
        "hysteria2 UDP 数据报面已承载（RIL-133 目录口径）"
    );

    // 正面：default=hy2-out（基础组合）→ 产 UDP 连接器，装配成功（仅装配，
    // 不启动——无网络面依赖）
    let cfg = shell(vec![direct_node(), hysteria2_node()], "hy2-out", true);
    let _ok_runtime = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("hysteria2 基础组合装配成功（RIL-133 数据报面）");

    // 反面：UDP 开 + http（目录 udp=false）→ 能力扫描点名判负
    let cfg = shell(vec![direct_node(), http_node()], "http-out", true);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("UDP 可达集内的无 UDP 节点须构建期判负");
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("不支持 UDP"), "能力扫描点名: {rendered}");
    assert!(rendered.contains("http-out"), "点名节点: {rendered}");
    assert!(rendered.contains("http"), "点名类型: {rendered}");

    // 正面控制：UDP 开 + 仅 direct（目录 udp=true）装配成功
    let cfg = shell(vec![direct_node()], "direct-out", true);
    let _ok_runtime = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("目录 UDP 列为真的类型装配成功");
}

/// vless 节点（RIL-130：packet-encoding 白名单构建期校验面；tcp 平文——
/// 包编码仅 UDP 面，与 TLS 无关）
fn vless_packet_node(encoding: Option<&str>) -> EgressDescriptor {
    EgressDescriptor {
        name: "vl-packet".to_string(),
        spec: EgressConfig::Vless {
            server: "127.0.0.1".to_string(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            flow: None,
            reality: None,
            network: "tcp".to_string(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: None,
            packet_encoding: encoding.map(str::to_string),
            tls: false,
            skip_cert_verify: false,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        },
    }
}

#[test]
fn vless_packet_encoding_whitelist_enforced_at_build() {
    // 反面：白名单外取值构建期点名拒绝（同 xhttp mode 口径）
    let cfg = shell(
        vec![direct_node(), vless_packet_node(Some("smux"))],
        "direct-out",
        false,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("白名单外包编码须在构建期拒绝");
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("raw/xudp/packetaddr"), "{rendered}");
    assert!(rendered.contains("smux"), "点名当前取值: {rendered}");
    assert!(rendered.contains("vl-packet"), "点名出口: {rendered}");

    // 正面：白名单内取值（raw/xudp/packetaddr）与缺席均可装配
    for enc in [None, Some("raw"), Some("xudp"), Some("packetaddr")] {
        let cfg = shell(
            vec![direct_node(), vless_packet_node(enc)],
            "direct-out",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|err| panic!("白名单内取值 {enc:?} 必须可装配: {err:#}"));
    }
}

// ---------- grpc-opts 流复用旋钮键位准入（RIL-130） ----------

fn grpc_reuse_knobs() -> Option<rillane_config::GrpcReuseConfig> {
    Some(rillane_config::GrpcReuseConfig {
        max_connections: Some(2),
        min_streams: Some(1),
        max_streams: Some(4),
    })
}

/// vmess/vless/trojan 三族 node：network 与 grpc_reuse 旋钮可参
fn gun_knob_node(
    proto: &str,
    network: &str,
    reuse: Option<rillane_config::GrpcReuseConfig>,
) -> EgressDescriptor {
    let name = format!("gr-{proto}");
    let spec = match proto {
        "vmess" => EgressConfig::Vmess {
            server: "127.0.0.1".to_string(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            network: network.to_string(),
            path: None,
            host: None,
            grpc_service_name: Some("gun-svc".to_string()),
            grpc_reuse: reuse,
            tls: true,
            skip_cert_verify: false,
            sni: Some("localhost".to_string()),
            alpn: None,
            tls_fingerprint: None,
        },
        "vless" => EgressConfig::Vless {
            server: "127.0.0.1".to_string(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            flow: None,
            reality: None,
            network: network.to_string(),
            path: None,
            host: None,
            grpc_service_name: Some("gun-svc".to_string()),
            grpc_reuse: reuse,
            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: false,
            sni: Some("localhost".to_string()),
            alpn: None,
            tls_fingerprint: None,
        },
        _ => EgressConfig::Trojan {
            server: "127.0.0.1".to_string(),
            port: 443,
            password: "gr-acceptance".to_string(),
            network: network.to_string(),
            path: None,
            host: None,
            grpc_service_name: Some("gun-svc".to_string()),
            grpc_reuse: reuse,
            tls: true,
            skip_cert_verify: false,
            sni: Some("localhost".to_string()),
            alpn: None,
            tls_fingerprint: None,
        },
    };
    EgressDescriptor { name, spec }
}

#[test]
fn grpc_reuse_knobs_refused_on_non_grpc_network_at_build() {
    // 反面：旋钮键位出现在非 grpc 传输 → 构建期点名拒绝（三族 × tcp/ws）
    for proto in ["vmess", "vless", "trojan"] {
        for network in ["tcp", "ws"] {
            let cfg = shell(
                vec![
                    direct_node(),
                    gun_knob_node(proto, network, grpc_reuse_knobs()),
                ],
                "direct-out",
                false,
            );
            let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
                panic!("{proto}/{network} 携带流复用旋钮须在构建期拒绝");
            };
            let rendered = format!("{err:#}");
            assert!(
                rendered.contains("仅 network=grpc 可携带"),
                "{proto}/{network}: {rendered}"
            );
            assert!(rendered.contains(network), "点名当前传输: {rendered}");
            assert!(
                rendered.contains(&format!("gr-{proto}")),
                "点名出口: {rendered}"
            );
        }
    }

    // 反面补充：旋钮缺席（None）时非 grpc 网络照常装配（不误伤）
    for proto in ["vmess", "vless", "trojan"] {
        let cfg = shell(
            vec![direct_node(), gun_knob_node(proto, "tcp", None)],
            "direct-out",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|err| panic!("{proto}/tcp 无旋钮必须可装配: {err:#}"));
    }
}

#[test]
fn grpc_reuse_knobs_assemble_on_grpc_network() {
    // 正面：network=grpc + 旋钮三族均可装配（构建期只做键位准入，
    // 旋钮语义由连接器 gun 面消费——grpc_gun_contract 真对端覆盖）
    for proto in ["vmess", "vless", "trojan"] {
        let cfg = shell(
            vec![
                direct_node(),
                gun_knob_node(proto, "grpc", grpc_reuse_knobs()),
            ],
            "direct-out",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|err| panic!("{proto}/grpc + 旋钮必须可装配: {err:#}"));
    }
}

// ---------- RIL-134：Shadowsocks 入口装配面 ----------

fn ss_ingress_shell(
    ingress: Vec<IngressDescriptor>,
    default_node: &str,
    udp_enabled: bool,
) -> RillaneConfig {
    let mut cfg = shell(vec![direct_node()], default_node, udp_enabled);
    cfg.ingress = ingress;
    cfg
}

fn ss_ingress_node(method: &str, password: &str, udp_enabled: Option<bool>) -> IngressDescriptor {
    IngressDescriptor {
        name: "ss-in".to_string(),
        spec: IngressConfig::Shadowsocks {
            bind: "127.0.0.1:0".to_string(),
            method: method.to_string(),
            password: password.to_string(),
            udp_enabled,
        },
    }
}

/// 构建期点名拒绝（egress 同口径）：none 不放行、未编译面方法名拒绝、
/// SS2022 password 形状（base64/精确密钥长）拒绝
#[test]
fn shadowsocks_ingress_refused_at_assembly_for_bad_method() {
    let cases = [
        ("none", "whatever", "none（无加密）不放行"),
        ("rc4-md5", "whatever", "不支持的加密方法"),
        ("2022-blake3-aes-128-gcm", "不是base64!!", "base64"),
    ];
    for (method, password, expect) in cases {
        let cfg = ss_ingress_shell(
            vec![ss_ingress_node(method, password, None)],
            "direct-main",
            true,
        );
        let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
            panic!("method={method} 坏形状必须装配期拒绝");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(expect),
            "method={method} 应含「{expect}」：{msg}"
        );
    }
}

/// SS2022 错长度（aes-128 需 16B，给 32B）装配期拒绝
#[test]
fn shadowsocks_ingress_refused_at_assembly_for_ss2022_key_length() {
    use base64::Engine as _;
    let long = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let cfg = ss_ingress_shell(
        vec![ss_ingress_node("2022-blake3-aes-128-gcm", &long, None)],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("SS2022 错长度必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("16 字节"), "应含密钥长点名：{msg}");
}

/// 正面控制：合法 method/password 装配成功——含 udp_enabled: Some(true)
/// 且全局 udp.enabled=false 的 WARN 组合（入口级 UDP 门语义同 socks5）
#[test]
fn shadowsocks_ingress_assembles_with_valid_credentials() {
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode([9u8; 16]);
    for (method, password) in [
        ("aes-256-gcm", "valid-sample-password"),
        ("2022-blake3-aes-128-gcm", key.as_str()),
    ] {
        let cfg = ss_ingress_shell(
            vec![ss_ingress_node(method, password, Some(true))],
            "direct-main",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|e| panic!("method={method} 必须装配成功: {e}"));
    }
}

// ---------- RIL-135：Trojan 入口装配面 ----------

fn trojan_ingress_node(
    bind: &str,
    password: &str,
    cert: &str,
    cert_key: &str,
    udp_enabled: Option<bool>,
) -> IngressDescriptor {
    IngressDescriptor {
        name: "tj-in".to_string(),
        spec: IngressConfig::Trojan {
            bind: bind.to_string(),
            password: password.to_string(),
            cert: cert.to_string(),
            cert_key: cert_key.to_string(),
            udp_enabled,
        },
    }
}

/// rcgen 自签 TLS 材料（SAN=localhost；客户端 skip_cert_verify 不校验链）
fn self_signed_tls_material() -> (String, String) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    (certified.cert.pem(), certified.key_pair.serialize_pem())
}

/// 构建期点名拒绝（空密码 / TLS 材料垃圾 PEM）——错误启动时暴露
#[test]
fn trojan_ingress_refused_at_assembly_for_bad_material() {
    let cfg = ss_ingress_shell(
        vec![trojan_ingress_node(
            "127.0.0.1:0",
            "",
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("空密码必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("密码不得为空"), "应含空密码点名：{msg}");

    let cfg = ss_ingress_shell(
        vec![trojan_ingress_node(
            "127.0.0.1:0",
            "pw",
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("垃圾 TLS 材料必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("PEM"), "应含材料解析点名：{msg}");
}

/// 正面控制：合法 TLS 材料 + 密码装配成功——含 udp_enabled: Some(true)
/// 且全局 udp.enabled=false 的 WARN 组合（入口级 UDP 门语义同 socks5）
#[test]
fn trojan_ingress_assembles_with_valid_credentials() {
    let (cert, key) = self_signed_tls_material();
    for (password, udp) in [("tj-valid-password", Some(true)), ("tj-min", None)] {
        let cfg = ss_ingress_shell(
            vec![trojan_ingress_node(
                "127.0.0.1:0",
                password,
                &cert,
                &key,
                udp,
            )],
            "direct-main",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|e| panic!("password={password} 必须装配成功: {e}"));
    }
}

/// RIL-136 VLESS 入口描述子（装配面：bind/uuid/cert/cert_key/udp_enabled）
fn vless_ingress_node(
    bind: &str,
    uuid: &str,
    cert: &str,
    cert_key: &str,
    udp_enabled: Option<bool>,
) -> IngressDescriptor {
    IngressDescriptor {
        name: "vl-in".to_string(),
        spec: IngressConfig::Vless {
            bind: bind.to_string(),
            uuid: uuid.to_string(),
            cert: cert.to_string(),
            cert_key: cert_key.to_string(),
            udp_enabled,
        },
    }
}

/// 构建期点名拒绝（非法 uuid / TLS 材料垃圾 PEM）——错误启动时暴露
#[test]
fn vless_ingress_refused_at_assembly_for_bad_material() {
    let cfg = ss_ingress_shell(
        vec![vless_ingress_node(
            "127.0.0.1:0",
            "not-a-uuid",
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("非法 uuid 必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("uuid"), "应含 uuid 点名：{msg}");

    let cfg = ss_ingress_shell(
        vec![vless_ingress_node(
            "127.0.0.1:0",
            "b831381d-6324-4d2a-b1e7-1bf75a1db7b3",
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("垃圾 TLS 材料必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("PEM"), "应含材料解析点名：{msg}");
}

/// 正面控制：合法 TLS 材料 + uuid 装配成功——含 udp_enabled: Some(true)
/// 且全局 udp.enabled=false 的 WARN 组合（入口级 UDP 门语义同 socks5/trojan）
#[test]
fn vless_ingress_assembles_with_valid_credentials() {
    let (cert, key) = self_signed_tls_material();
    for (uuid, udp) in [
        ("b831381d-6324-4d2a-b1e7-1bf75a1db7b3", Some(true)),
        ("47840d09-1911-4ef9-b5e3-30687d1f532f", None),
    ] {
        let cfg = ss_ingress_shell(
            vec![vless_ingress_node("127.0.0.1:0", uuid, &cert, &key, udp)],
            "direct-main",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|e| panic!("uuid={uuid} 必须装配成功: {e}"));
    }
}

/// RIL-137 VMess 入口描述子（装配面：bind/uuid/udp_enabled；裸 TCP 承载，
/// 无 TLS 材料——AEAD 封头即认证面）
#[allow(clippy::too_many_arguments)]
fn vmess_ingress_node(bind: &str, uuid: &str, udp_enabled: Option<bool>) -> IngressDescriptor {
    IngressDescriptor {
        name: "vm-in".to_string(),
        spec: IngressConfig::Vmess {
            bind: bind.to_string(),
            uuid: uuid.to_string(),
            udp_enabled,
        },
    }
}

/// 构建期点名拒绝（非法 uuid）——错误启动时暴露
#[test]
fn vmess_ingress_refused_at_assembly_for_bad_uuid() {
    let cfg = ss_ingress_shell(
        vec![vmess_ingress_node("127.0.0.1:0", "not-a-uuid", None)],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("非法 uuid 必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("uuid"), "应含 uuid 点名：{msg}");
}

/// 正面控制：合法 uuid 装配成功——含 udp_enabled: Some(true) 且全局
/// udp.enabled=false 的 WARN 组合（入口级 UDP 门语义同 socks5/trojan/vless）
#[test]
fn vmess_ingress_assembles_with_valid_credentials() {
    for (uuid, udp) in [
        ("b831381d-6324-4d2a-b1e7-1bf75a1db7b3", Some(true)),
        ("47840d09-1911-4ef9-b5e3-30687d1f532f", None),
    ] {
        let cfg = ss_ingress_shell(
            vec![vmess_ingress_node("127.0.0.1:0", uuid, udp)],
            "direct-main",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|e| panic!("uuid={uuid} 必须装配成功: {e}"));
    }
}

/// RIL-138 Hysteria2 入口描述子（装配面：bind/password/cert/cert_key/
/// udp_enabled；QUIC 端点即监听面，ALPN 恒 h3）
#[allow(clippy::too_many_arguments)]
fn hysteria2_ingress_node(
    bind: &str,
    password: &str,
    cert: &str,
    cert_key: &str,
    udp_enabled: Option<bool>,
) -> IngressDescriptor {
    IngressDescriptor {
        name: "hy-in".to_string(),
        spec: IngressConfig::Hysteria2 {
            bind: bind.to_string(),
            password: password.to_string(),
            cert: cert.to_string(),
            cert_key: cert_key.to_string(),
            udp_enabled,
        },
    }
}

/// 构建期点名拒绝（空口令 / 垃圾 TLS 材料）——错误启动时暴露
#[test]
fn hysteria2_ingress_refused_at_assembly_for_bad_material() {
    let (cert, key) = self_signed_tls_material();

    // 空口令：认证面必须非空
    let cfg = ss_ingress_shell(
        vec![hysteria2_ingress_node(
            "127.0.0.1:0",
            "   ",
            &cert,
            &key,
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("空口令必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("password"), "应含 password 点名：{msg}");

    // 垃圾 PEM：TLS 材料装配期解析
    let cfg = ss_ingress_shell(
        vec![hysteria2_ingress_node(
            "127.0.0.1:0",
            "hy-pass",
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("垃圾 TLS 材料必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("PEM"), "应含材料解析点名：{msg}");
}

/// 正面控制：合法 TLS 材料 + 非空口令装配成功——含 udp_enabled: Some(true)
/// 且全局 udp.enabled=false 的 WARN 组合（入口级 UDP 门语义同
/// socks5/trojan/vless/vmess）
#[test]
fn hysteria2_ingress_assembles_with_valid_credentials() {
    let (cert, key) = self_signed_tls_material();
    for udp in [Some(true), None] {
        let cfg = ss_ingress_shell(
            vec![hysteria2_ingress_node(
                "127.0.0.1:0",
                "hy-pass-2026",
                &cert,
                &key,
                udp,
            )],
            "direct-main",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|e| panic!("udp={udp:?} 必须装配成功: {e}"));
    }
}

// ---------- RIL-109：Hysteria v1 入口装配面 ----------

/// Hysteria v1 入口描述子（装配面：bind/password/cert/cert_key/up_mbps/
/// down_mbps/udp_enabled；QUIC 端点即监听面，ALPN 恒 "hysteria"）
#[allow(clippy::too_many_arguments)]
fn hysteria_ingress_node(
    bind: &str,
    password: &str,
    cert: &str,
    cert_key: &str,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    udp_enabled: Option<bool>,
) -> IngressDescriptor {
    IngressDescriptor {
        name: "hy1-in".to_string(),
        spec: IngressConfig::Hysteria {
            bind: bind.to_string(),
            password: password.to_string(),
            cert: cert.to_string(),
            cert_key: cert_key.to_string(),
            up_mbps,
            down_mbps,
            udp_enabled,
        },
    }
}

/// 构建期点名拒绝（空口令 / 速率为 0 / 垃圾 TLS 材料 / bind 非法）——
/// 错误启动时暴露（None = 不设上限；0 具名拒绝）
#[test]
fn hysteria_ingress_refused_at_assembly_for_bad_material() {
    let (cert, key) = self_signed_tls_material();

    // 空口令：认证面必须非空
    let cfg = ss_ingress_shell(
        vec![hysteria_ingress_node(
            "127.0.0.1:0",
            "   ",
            &cert,
            &key,
            None,
            None,
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("空口令必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("password"), "应含 password 点名：{msg}");

    // 速率为 0：不设上限用 None 表达，Some(0) 具名拒绝（上/下行两向）
    for (up, down) in [(Some(0), None), (None, Some(0)), (Some(0), Some(0))] {
        let cfg = ss_ingress_shell(
            vec![hysteria_ingress_node(
                "127.0.0.1:0",
                "hy-pass",
                &cert,
                &key,
                up,
                down,
                None,
            )],
            "direct-main",
            true,
        );
        let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
            panic!("速率 {up:?}/{down:?} 为 0 必须装配期拒绝");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("不设上限用 None 表达"),
            "{up:?}/{down:?}: {msg}"
        );
    }

    // 垃圾 PEM：TLS 材料装配期解析
    let cfg = ss_ingress_shell(
        vec![hysteria_ingress_node(
            "127.0.0.1:0",
            "hy-pass",
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
            None,
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("垃圾 TLS 材料必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("PEM"), "应含材料解析点名：{msg}");

    // bind 非法：QUIC 端点监听面装配期解析
    let cfg = ss_ingress_shell(
        vec![hysteria_ingress_node(
            "not-an-addr",
            "hy-pass",
            &cert,
            &key,
            None,
            None,
            None,
        )],
        "direct-main",
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("非法 bind 必须装配期拒绝");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("bind"), "应含 bind 点名：{msg}");
}

/// 正面控制：合法 TLS 材料 + 非空口令装配成功——速率上限合法组合
///（None = 不设上限；Some = 正整数上限）与 udp_enabled 两态全覆盖
#[test]
fn hysteria_ingress_assembles_with_valid_credentials() {
    let (cert, key) = self_signed_tls_material();
    for (up, down, udp) in [
        (None, None, Some(true)),
        (Some(100), Some(50), None),
        (Some(200), None, Some(false)),
    ] {
        let cfg = ss_ingress_shell(
            vec![hysteria_ingress_node(
                "127.0.0.1:0",
                "hy-pass-2026",
                &cert,
                &key,
                up,
                down,
                udp,
            )],
            "direct-main",
            false,
        );
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|e| panic!("速率 {up:?}/{down:?} udp={udp:?} 必须装配成功: {e}"));
    }
}
