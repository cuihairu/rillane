//! RIL-110 装配面验收：shadowsocks-shadow-tls 组合出站与 ShadowTLS 入口
//! 载具经 RuntimeBuilder 装配（仅装配不启动）。验收面：
//! 版本门——None/Some(2) 装配成功，Some(1)/Some(3) 装配期点名拒绝（不
//!       静默降级）；
//! UDP 判负——udp.enabled 下组合节点被能力扫描构建期点名（载具无 UDP 面）；
//! 入口装配——ShadowTls 入口正常装配，空口令/非法地址装配期拒绝。

use rillane_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig,
    RoutingConfig, ShadowTlsEgressConfig, TelemetryConfig, UdpConfig,
};
use rillane_runtime::{RuntimeBuilder, RuntimeConfig};

/// 可装配配置外壳（订阅产物无关——本验收直接手写 IR 面）
fn shell(
    ingress: Vec<IngressDescriptor>,
    egress: Vec<EgressDescriptor>,
    udp_enabled: bool,
) -> RillaneConfig {
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
        ingress,
        egress,
        routing: RoutingConfig {
            default_node: "stls-node".to_string(),
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
        streaming: None,
    }
}

fn opts() -> RuntimeConfig {
    RuntimeConfig {
        enable_hot_reload: false,
        ..RuntimeConfig::default()
    }
}

fn socks_ingress() -> IngressDescriptor {
    IngressDescriptor {
        name: "asm-socks".to_string(),
        spec: IngressConfig::Socks5 {
            bind: "127.0.0.1:0".to_string(),
            auth: None,
            udp_enabled: Some(false),
        },
    }
}

fn direct_node() -> EgressDescriptor {
    EgressDescriptor {
        name: "direct-out".to_string(),
        spec: EgressConfig::Direct,
    }
}

/// shadowsocks-shadow-tls 组合节点（version 直通——版本门样例由调用方给）
fn combo_node(version: Option<u8>) -> EgressDescriptor {
    EgressDescriptor {
        name: "stls-node".to_string(),
        spec: EgressConfig::ShadowsocksShadowTls {
            server: "203.0.113.9".to_string(),
            port: 443,
            method: "aes-128-gcm".to_string(),
            password: "inner-ss-password".to_string(),
            shadow_tls: ShadowTlsEgressConfig {
                host: "camo.example.test".to_string(),
                password: "carrier-password".to_string(),
                version,
                skip_cert_verify: false,
            },
        },
    }
}

/// ShadowTLS 入口载具（handshake/target 直通——装配校验样例由调用方给）
fn shadowtls_ingress(password: &str, handshake_addr: &str, target_addr: &str) -> IngressDescriptor {
    IngressDescriptor {
        name: "stls-in".to_string(),
        spec: IngressConfig::ShadowTls {
            bind: "127.0.0.1:0".to_string(),
            password: password.to_string(),
            handshake_addr: handshake_addr.to_string(),
            target_addr: target_addr.to_string(),
        },
    }
}

// ---------- 版本门：仅 v2 装配，v1/v3 点名拒绝 ----------

#[test]
fn combo_version_gate_admits_only_v2() {
    // None = 2（缺省即 v2）：装配成功（仅装配，不启动）
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(None)],
        false,
    );
    let _ok = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("缺省版本（=v2）装配成功");

    // 显式 Some(2)：装配成功
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(Some(2))],
        false,
    );
    let _ok = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("显式 v2 装配成功");

    // v1：官方已死、无主动探测防御——装配期点名拒绝
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(Some(1))],
        false,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("shadowtls v1 须装配期拒绝");
    };
    assert!(
        err.to_string().contains("v1") && err.to_string().contains("仅 v2"),
        "v1 拒绝须点名版本口径: {err}"
    );

    // v3：会话劫持面 machinery 未交付——装配期点名拒绝
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(Some(3))],
        false,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("shadowtls v3 须装配期拒绝");
    };
    assert!(
        err.to_string().contains("v3") && err.to_string().contains("仅 v2"),
        "v3 拒绝须点名版本口径: {err}"
    );

    // 未知版本：装配期点名拒绝
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(Some(9))],
        false,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("shadowtls 未知版本须装配期拒绝");
    };
    assert!(err.to_string().contains("9"), "未知版本拒绝须带值: {err}");
}

// ---------- UDP 判负：能力扫描构建期点名 ----------

#[test]
fn combo_node_offends_udp_capability_scan() {
    // udp.enabled + 组合节点为 default（可达集内）→ 能力扫描点名判负
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(None)],
        true,
    );
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("udp.enabled 下组合节点须构建期判负（载具无 UDP 面）");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("shadowsocks-shadow-tls"),
        "判负名单须按目录类型点名组合节点: {msg}"
    );

    // 同一节点在 udp.enabled=false 下装配成功（判负只随 UDP 需求生效）
    let cfg = shell(
        vec![socks_ingress()],
        vec![direct_node(), combo_node(None)],
        false,
    );
    let _ok = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("udp 关闭时组合节点装配成功");
}

// ---------- 入口装配：构造期校验拒绝落在装配期 ----------

#[test]
fn shadowtls_ingress_assembles_and_refuses_bad_material() {
    // 正面：入口 + 内层 SS 入口（数据服务器指向其 bind）装配成功
    let ingress = vec![
        socks_ingress(),
        shadowtls_ingress("carrier-password", "203.0.113.10:443", "127.0.0.1:21051"),
    ];
    let cfg = shell(ingress, vec![direct_node()], false);
    let _ok = RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .expect("ShadowTLS 入口装配成功");

    // 反面：空口令——装配期拒绝
    let ingress = vec![shadowtls_ingress("", "203.0.113.10:443", "127.0.0.1:21051")];
    let cfg = shell(ingress, vec![direct_node()], false);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("空载具口令须装配期拒绝");
    };
    assert!(
        err.to_string().contains("password"),
        "空口令拒绝须点名 password: {err}"
    );

    // 反面：握手站点地址非法——装配期拒绝
    let ingress = vec![shadowtls_ingress("pw", "nope", "127.0.0.1:21051")];
    let cfg = shell(ingress, vec![direct_node()], false);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("非法握手站点地址须装配期拒绝");
    };
    assert!(
        err.to_string().contains("握手站点地址非法"),
        "地址拒绝须点名握手站点: {err}"
    );

    // 反面：数据服务器地址非法——装配期拒绝
    let ingress = vec![shadowtls_ingress("pw", "203.0.113.10:443", "nope")];
    let cfg = shell(ingress, vec![direct_node()], false);
    let Err(err) = RuntimeBuilder::new(cfg).with_runtime_config(opts()).build() else {
        panic!("非法数据服务器地址须装配期拒绝");
    };
    assert!(
        err.to_string().contains("数据服务器地址非法"),
        "地址拒绝须点名数据服务器: {err}"
    );
}
