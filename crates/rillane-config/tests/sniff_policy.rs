//! RIL-143 有界域名嗅探策略契约验收：network.sniff 块 serde 往返 /
//! 构建期校验门（scope 空端口、双界越界点名拒绝）/ 缺席零差异。

use rillane_config::{
    NetworkBlockConfig, NetworkBlockMode, RillaneConfig, SniffMode, SniffPolicy,
    SNIFF_MAX_BYTES_CAP, SNIFF_TIMEOUT_MS_CAP,
};

const BASE_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: false
  enable_tracing: false
ingress: []
egress:
  - name: direct
    type: direct
routing:
  default_node: direct
  groups: []
  rules: []
"#;

/// 块缺席（network 不在场）= 整块关；策略缺省按需 + 既有双界（零差异口径）
#[test]
fn absent_network_block_yields_default_on_demand_policy() {
    let cfg = RillaneConfig::from_str(BASE_YAML, None).expect("解析");
    assert!(cfg.network.is_none(), "块缺席即 None");
    let p = SniffPolicy::default();
    assert_eq!(p.mode, SniffMode::OnDemand);
    assert!(p.applies(true, 443), "缺省按需 = 既有 TUN 嗅探行为");
}

/// network 块在场但 sniff 缺席 = 按需缺省；显式 scope 声明 serde 往返保形
#[test]
fn network_block_sniff_roundtrip() {
    let yaml = format!(
        "{BASE_YAML}\nnetwork:\n  mode: tun\n  sniff:\n    mode: scope\n    ports: [443, 8443]\n    max_bytes: 4096\n    timeout_ms: 200\n"
    );
    let cfg = RillaneConfig::from_str(&yaml, None).expect("解析");
    let sniff = cfg
        .network
        .as_ref()
        .and_then(|n| n.sniff.as_ref())
        .expect("策略在场");
    assert_eq!(sniff.mode, SniffMode::Scope);
    assert_eq!(sniff.ports, vec![443, 8443]);
    assert_eq!(sniff.max_bytes, 4096);
    assert_eq!(sniff.timeout_ms, 200);
    assert!(sniff.validate().is_ok());
    assert!(sniff.applies(true, 8443));
    assert!(!sniff.applies(true, 80), "未声明端口不嗅探");

    // sniff 缺席 → None（消费侧 unwrap_or_default = 按需零差异）
    let bare_yaml = format!("{BASE_YAML}\nnetwork:\n  mode: tun\n");
    let bare = RillaneConfig::from_str(&bare_yaml, None).expect("解析");
    assert!(bare
        .network
        .as_ref()
        .and_then(|n| n.sniff.as_ref())
        .is_none());

    // 序列化保形：mode snake_case
    let json = serde_json::to_string(sniff).expect("可序列化");
    assert!(
        json.contains("\"mode\":\"scope\""),
        "模式名 snake_case: {json}"
    );
}

/// 校验门（装配前）：scope 空端口具名拒绝——覆盖目标需显式配置
#[test]
fn validate_refuses_scope_without_ports() {
    let mut cfg = RillaneConfig::from_str(&format!("{BASE_YAML}\nnetwork:\n  mode: tun\n"), None)
        .expect("解析");
    let network = cfg.network.as_mut().expect("块在场");
    network.sniff = Some(SniffPolicy {
        mode: SniffMode::Scope,
        ..SniffPolicy::default()
    });
    let err = network.validate().expect_err("scope 空端口须拒绝");
    assert!(err.to_string().contains("ports"), "点名 ports: {err}");
}

/// 校验门：双界越界（0 与超硬上限）具名拒绝
#[test]
fn validate_refuses_unbounded_limits() {
    let mut cfg = RillaneConfig::from_str(&format!("{BASE_YAML}\nnetwork:\n  mode: tun\n"), None)
        .expect("解析");
    let network = cfg.network.as_mut().expect("块在场");

    network.sniff = Some(SniffPolicy {
        max_bytes: 0,
        ..SniffPolicy::default()
    });
    let err = network.validate().expect_err("0 字节界须拒绝");
    assert!(
        err.to_string().contains("max_bytes"),
        "点名 max_bytes: {err}"
    );

    network.sniff = Some(SniffPolicy {
        max_bytes: SNIFF_MAX_BYTES_CAP + 1,
        ..SniffPolicy::default()
    });
    assert!(network.validate().is_err(), "越字节硬上限须拒绝");

    network.sniff = Some(SniffPolicy {
        timeout_ms: 0,
        ..SniffPolicy::default()
    });
    let err = network.validate().expect_err("0 时间界须拒绝");
    assert!(
        err.to_string().contains("timeout_ms"),
        "点名 timeout_ms: {err}"
    );

    network.sniff = Some(SniffPolicy {
        timeout_ms: SNIFF_TIMEOUT_MS_CAP + 1,
        ..SniffPolicy::default()
    });
    assert!(network.validate().is_err(), "越时间硬上限须拒绝");

    // 双界上限本身合法（有界但可配到顶）
    network.sniff = Some(SniffPolicy {
        max_bytes: SNIFF_MAX_BYTES_CAP,
        timeout_ms: SNIFF_TIMEOUT_MS_CAP,
        ..SniffPolicy::default()
    });
    assert!(network.validate().is_ok(), "硬上限内合法");
}

/// off 模式忽略端口表（校验不拒绝——多余声明无害）
#[test]
fn off_mode_tolerates_declared_ports() {
    let network = NetworkBlockConfig {
        mode: NetworkBlockMode::default(),
        tun: None,
        routing: None,
        dns: None,
        egress_fwmark: None,
        sniff: Some(SniffPolicy {
            mode: SniffMode::Off,
            ports: vec![443],
            ..SniffPolicy::default()
        }),
    };
    assert!(network.validate().is_ok());
    assert!(!network.sniff.as_ref().expect("在场").applies(true, 443));
}
