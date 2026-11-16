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

/// Hysteria v1 节点（编目在案、后端未准入——RIL-109 前置）
fn hysteria_node() -> EgressDescriptor {
    EgressDescriptor {
        name: "hy1-node".to_string(),
        spec: EgressConfig::Hysteria {
            server: "203.0.113.7".to_string(),
            port: 443,
            password: "REDACTED".to_string(),
            protocol: "udp".to_string(),
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
    }
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

/// 未准入协议不得进热路径：同装配里 direct（已准入）+ hysteria（未准入）
/// ——整份构建被拒绝（不是部分装配），错误点名稳定码、类型名、节点与
/// 前置项；构建失败即无运行时可用（装配面准入先于一切连接器）。
#[test]
fn not_admitted_protocol_refused_at_assembly() {
    let cfg = shell(vec![direct_node(), hysteria_node()], "direct-out", false);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("未准入协议须在装配期拒绝");
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("config.egress.not_admitted"),
        "稳定原因码点名: {rendered}"
    );
    assert!(rendered.contains("hysteria"), "点名出口类型: {rendered}");
    assert!(rendered.contains("hy1-node"), "点名节点: {rendered}");
    assert!(
        rendered.contains("RIL-109"),
        "原因点名前置项（谁欠评估）: {rendered}"
    );

    // 目录机器口径与本验收一致：hysteria = NotAdmitted + 无后端 + 无 UDP
    let entry = protocol_catalog::entry_for("hysteria").expect("已编目");
    assert!(entry.evidence().is_none(), "未准入无证据锚点");
    assert!(!entry.udp);
    assert_eq!(
        protocol_catalog::admission("hysteria"),
        protocol_catalog::Admission::NotAdmitted(entry)
    );
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
        let cfg = shell(vec![direct_node(), vless_packet_node(enc)], "direct-out", false);
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts())
            .build()
            .unwrap_or_else(|err| panic!("白名单内取值 {enc:?} 必须可装配: {err:#}"));
    }
}
