//! RIL-140 装配面验收：统一选路模式（rule/global/direct）的出口装配门。
//! 验收面：
//! 规则模式（默认）装配零差异；
//! 全局模式出口须引用已声明组或已声明出口（含 reject 出口），未声明
//!       装配期点名拒绝，缺声明（global_node 缺席）配置校验期点名拒绝；
//! 直连模式出口须为 Direct 类型出口节点——代理类型出口/缺席均装配期
//!       点名拒绝（无静默直连：坏引用不流到建连期才失败）。

use rillane_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig,
    RoutingConfig, SelectionMode, TelemetryConfig, UdpConfig,
};
use rillane_runtime::{RuntimeBuilder, RuntimeConfig};

/// 可装配配置外壳（订阅产物无关——本验收直接手写 IR 面）
fn shell(
    mode: SelectionMode,
    global_node: Option<&str>,
    direct_node: Option<&str>,
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
        ingress: vec![IngressDescriptor {
            name: "mode-socks".to_string(),
            spec: IngressConfig::Socks5 {
                bind: "127.0.0.1:0".to_string(),
                auth: None,
                udp_enabled: Some(false),
            },
        }],
        egress: vec![
            EgressDescriptor {
                name: "direct-out".to_string(),
                spec: EgressConfig::Direct,
            },
            EgressDescriptor {
                name: "proxy-out".to_string(),
                spec: EgressConfig::Socks5 {
                    server: "203.0.113.20".to_string(),
                    port: 1080,
                    username: None,
                    password: None,
                },
            },
            EgressDescriptor {
                name: "reject-out".to_string(),
                spec: EgressConfig::Reject,
            },
        ],
        routing: RoutingConfig {
            default_node: "direct-out".to_string(),
            mode,
            global_node: global_node.map(str::to_string),
            direct_node: direct_node.map(str::to_string),
            groups: vec![rillane_config::PolicyGroup {
                name: "global-group".to_string(),
                strategy: rillane_config::Strategy::Fixed,
                members: vec![rillane_config::GroupMember::Node {
                    name: "proxy-out".to_string(),
                }],
                slo: None,
                url_test: None,
            }],
            ..Default::default()
        },
        udp: UdpConfig {
            enabled: false,
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

fn build(cfg: RillaneConfig) -> Result<(), anyhow::Error> {
    RuntimeBuilder::new(cfg)
        .with_runtime_config(opts())
        .build()
        .map(|_| ())
}

// ---------- 规则模式（默认）：装配零差异 ----------

#[test]
fn rule_mode_assembles_unchanged() {
    build(shell(SelectionMode::Rule, None, None)).expect("规则模式（默认）装配成功");
}

// ---------- 全局模式：出口存在性 ----------

#[test]
fn global_mode_assembles_with_declared_targets() {
    // 全局出口 = 已声明组
    build(shell(SelectionMode::Global, Some("global-group"), None))
        .expect("全局出口指向已声明组装配成功");
    // 全局出口 = 已声明出口节点（含 reject 出口）
    build(shell(SelectionMode::Global, Some("proxy-out"), None))
        .expect("全局出口指向已声明出口装配成功");
    build(shell(SelectionMode::Global, Some("reject-out"), None))
        .expect("全局出口指向 reject 出口装配成功");
}

#[test]
fn global_mode_refuses_undeclared_target() {
    let Err(err) = build(shell(SelectionMode::Global, Some("ghost-node"), None)) else {
        panic!("全局出口未声明须装配期拒绝");
    };
    assert!(
        err.to_string().contains("未声明"),
        "拒绝须点名未声明出口: {err}"
    );
}

#[test]
fn global_mode_refuses_missing_target() {
    let Err(err) = build(shell(SelectionMode::Global, None, None)) else {
        panic!("全局模式缺 global_node 须拒绝");
    };
    assert!(
        err.to_string().contains("global_node"),
        "拒绝须点名 global_node 字段: {err}"
    );
}

// ---------- 直连模式：存在性 + Direct 类型面 ----------

#[test]
fn direct_mode_assembles_with_direct_egress() {
    build(shell(SelectionMode::Direct, None, Some("direct-out")))
        .expect("直连出口指向 Direct 出口装配成功");
}

#[test]
fn direct_mode_refuses_proxy_egress() {
    // proxy-out 是 socks5 代理出口——直连模式点名类型不符
    let Err(err) = build(shell(SelectionMode::Direct, None, Some("proxy-out"))) else {
        panic!("直连出口指向代理出口须装配期拒绝");
    };
    assert!(
        err.to_string().contains("Direct 类型"),
        "拒绝须点名 Direct 类型面: {err}"
    );
}

#[test]
fn direct_mode_refuses_missing_target() {
    let Err(err) = build(shell(SelectionMode::Direct, None, None)) else {
        panic!("直连模式缺 direct_node 须拒绝");
    };
    assert!(
        err.to_string().contains("direct_node"),
        "拒绝须点名 direct_node 字段: {err}"
    );
}
