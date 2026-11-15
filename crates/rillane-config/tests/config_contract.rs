//! 配置/能力契约验收（RIL-001）：旧配置适配、未知版本稳定原因码、
//! 能力集不支持组合稳定原因码。纯解析/校验，零网络零 OS 依赖。

use rillane_config::{
    CapabilitySet, ConfigError, ConfigVersion, RillaneConfig, CODE_UNKNOWN_VERSION,
    CODE_UNSUPPORTED_COMBINATION,
};

/// 旧配置样例：无 version 字段（RIL-001 之前的一切存量配置口径）
const LEGACY_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
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

/// 最小骨架（显式字段全量的旧样例由 LEGACY_YAML 覆盖）
fn minimal_config_yaml(extra: &str) -> String {
    format!(
        "version: \"1\"\ncontrol:\n  api_bind: 127.0.0.1:9090\ntelemetry:\n  log_level: info\n  enable_metrics: true\n  enable_tracing: false\ningress: []\negress:\n  - name: direct\n    type: direct\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n{extra}"
    )
}

#[test]
fn legacy_config_without_version_adapts_to_v1() {
    // 旧配置样例必须通过（验收：旧配置样例通过）
    let config = RillaneConfig::from_str(LEGACY_YAML, None).expect("旧配置必须可解析");
    assert_eq!(config.version, ConfigVersion::V1);

    // 显式 V1 亦通过（字符串与整数两种写法）
    for yaml in [
        minimal_config_yaml(""),
        minimal_config_yaml("").replace("version: \"1\"", "version: 1"),
    ] {
        let config = RillaneConfig::from_str(&yaml, None).expect("V1 配置必须可解析");
        assert_eq!(config.version, ConfigVersion::V1);
    }
}

#[test]
fn unknown_version_rejected_with_stable_code() {
    for yaml in [
        minimal_config_yaml("").replace("version: \"1\"", "version: \"2.0\""),
        minimal_config_yaml("").replace("version: \"1\"", "version: 2"),
    ] {
        let err = RillaneConfig::from_str(&yaml, None)
            .expect_err("未知版本必须拒绝")
            .to_string();
        assert!(
            err.contains(CODE_UNKNOWN_VERSION),
            "错误须含稳定原因码 {CODE_UNKNOWN_VERSION}，实际: {err}"
        );
        assert!(err.contains("2"), "错误须报告收到的版本字面量: {err}");
    }

    // ConfigError 本体的 code() 恒定（机器口径）
    assert_eq!(
        ConfigError::UnknownVersion {
            version: "2.0".to_string()
        }
        .code(),
        CODE_UNKNOWN_VERSION
    );
}

#[test]
fn capability_full_set_validates_all_blocks() {
    // 全能力集：各块全开也通过
    let yaml = minimal_config_yaml(
        "udp:\n  enabled: true\nnetwork:\n  mode: tun\n  dns:\n    enabled: true\n    domestic: []\n    trusted: []\n    default_group: domestic\n    anti_poison: off\n    timeout_ms: 3000\nobfuscation:\n  enabled: true\n  padding:\n    mode: fixed\n    target: 512\negress_pool:\n  enabled: true\n",
    );
    let config = RillaneConfig::from_str(&yaml, None).expect("配置必须可解析");
    CapabilitySet::full()
        .validate_config(&config)
        .expect("全能力集必须放行全部块");
    CapabilitySet::default()
        .validate_config(&config)
        .expect("缺省能力集=全量（零差异）");
}

#[test]
fn capability_mismatch_rejected_with_stable_code_and_feature() {
    // 逐块：最小能力集逐一拒绝并点名特性，码恒定
    // minimal() 保留 UDP（small 构建设计如此），udp 用例改用自定义能力集
    let udp_yaml = minimal_config_yaml("udp:\n  enabled: true\n");
    let udp_config = RillaneConfig::from_str(&udp_yaml, None).expect("配置必须可解析");
    let no_udp = CapabilitySet {
        udp_forwarding: false,
        ..CapabilitySet::full()
    };
    let err = no_udp
        .validate_config(&udp_config)
        .expect_err("无 UDP 能力必须拒绝 udp.enabled");
    assert_eq!(err.code(), CODE_UNSUPPORTED_COMBINATION);
    assert!(matches!(
        &err,
        ConfigError::UnsupportedCombination {
            feature: "udp.enabled",
            ..
        }
    ));

    let cases: [(&str, &str, CapabilitySet); 4] = [
        ("network:\n  mode: tun\n", "network", CapabilitySet::minimal()),
        (
            "network:\n  mode: tun\n  dns:\n    enabled: true\n    domestic: []\n    trusted: []\n    default_group: domestic\n    anti_poison: off\n    timeout_ms: 3000\n",
            "network.dns",
            // tun 能力在场，仅缺 DNS 分流——才能打到 network.dns 这一关
            CapabilitySet {
                dns_partition: false,
                ..CapabilitySet::full()
            },
        ),
        ("obfuscation: {}\n", "obfuscation", CapabilitySet::minimal()),
        ("egress_pool: {}\n", "egress_pool", CapabilitySet::minimal()),
    ];

    for (extra, feature, caps) in cases {
        let yaml = minimal_config_yaml(extra);
        let config = RillaneConfig::from_str(&yaml, None).expect("配置必须可解析");
        let err = caps
            .validate_config(&config)
            .expect_err("能力集必须拒绝该块");
        assert_eq!(err.code(), CODE_UNSUPPORTED_COMBINATION);
        match &err {
            ConfigError::UnsupportedCombination {
                feature: f,
                detail: _,
            } => assert_eq!(*f, feature),
            other => panic!("应为 UnsupportedCombination，实际 {other:?}"),
        }
    }

    // 反例：最小配置在最小能力集下通过（small 构建可用）
    let config = RillaneConfig::from_str(&minimal_config_yaml(""), None).unwrap();
    CapabilitySet::minimal()
        .validate_config(&config)
        .expect("最小配置+最小能力集必须通过");
}

#[test]
fn version_serializes_into_config_output() {
    // 新产出配置携带版本字段（未来适配边界可识别）
    let config = RillaneConfig::from_str(LEGACY_YAML, None).unwrap();
    let json = serde_json::to_string(&config).expect("可序列化");
    assert!(
        json.contains("\"version\":\"1\""),
        "序列化应携带 version 字段，实际: {json}"
    );

    // round-trip 保持版本
    let back: RillaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.version, ConfigVersion::V1);
}
