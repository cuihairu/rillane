//! probe 授权块契约（RIL-061）：块缺席 = 探测面整体关闭；目标逐条
//! 类型化登记（无自由文本变体）；限额可选覆盖；非法值构建期拒绝。
//! 顶层块结构上不在来源合并面（合并面是对象登记）——契约此处只钉
//! 解析与校验形态。

use rillane_config::{ProbeConfigBlock, ProbeLimitsConfig, ProbeTargetSpec, RillaneConfig};

const BASE_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
  enable_tracing: false
ingress: []
egress: []
routing:
  default_node: direct
  groups: []
  rules: []
"#;

#[test]
fn block_absent_by_default() {
    let cfg: RillaneConfig = serde_yaml::from_str(BASE_YAML).unwrap();
    assert!(cfg.probe.is_none(), "无 probe 块 = 探测面整体关闭");
}

#[test]
fn full_block_roundtrip_with_typed_targets() {
    let yaml = format!(
        "{BASE_YAML}probe:\n  targets:\n    - kind: dns\n      host: example.invalid\n    - kind: connect\n      addr: 192.0.2.1:443\n    - kind: udp_echo\n      addr: 192.0.2.1:53\n  limits:\n    max_active: 2\n    job_timeout_ms: 3000\n    udp_payload_max_bytes: 256\n    byte_budget: 32768\n"
    );
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).unwrap();
    let probe = cfg.probe.as_ref().expect("probe 块应解析");
    assert_eq!(
        probe.targets,
        vec![
            ProbeTargetSpec::Dns {
                host: "example.invalid".into()
            },
            ProbeTargetSpec::Connect {
                addr: "192.0.2.1:443".into()
            },
            ProbeTargetSpec::UdpEcho {
                addr: "192.0.2.1:53".into()
            },
        ]
    );
    assert_eq!(
        probe.limits,
        ProbeLimitsConfig {
            max_active: Some(2),
            job_timeout_ms: Some(3000),
            udp_payload_max_bytes: Some(256),
            byte_budget: Some(32768),
        }
    );
    probe.validate().expect("全合法块应通过校验");
}

#[test]
fn limits_default_to_core_values_and_empty_targets_allowed() {
    let yaml = format!("{BASE_YAML}probe:\n  targets: []\n");
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).unwrap();
    let probe = cfg.probe.as_ref().unwrap();
    assert!(probe.targets.is_empty());
    assert_eq!(probe.limits, ProbeLimitsConfig::default());
    probe.validate().expect("空目标合法（无目标可探测）");
}

#[test]
fn unknown_fields_are_rejected() {
    let yaml = format!("{BASE_YAML}probe:\n  targets: []\n  typo_limit: 1\n");
    assert!(serde_yaml::from_str::<RillaneConfig>(&yaml).is_err());
}

#[test]
fn unknown_target_kind_is_rejected() {
    // handshake 变体不在配置面：本版执行器无代理握手实现——登记了
    // 也只会恒失败，装配期宁可拒绝（诚实边界）
    let yaml = format!(
        "{BASE_YAML}probe:\n  targets:\n    - kind: handshake\n      egress: direct\n      addr: 192.0.2.1:443\n"
    );
    assert!(serde_yaml::from_str::<RillaneConfig>(&yaml).is_err());
}

/// 装载入口（from_str → from_str_with_diagnostics）构建期拒绝非法
/// addr——不带病装配探测授权。
#[test]
fn invalid_addr_rejected_at_load_time() {
    let yaml =
        format!("{BASE_YAML}probe:\n  targets:\n    - kind: connect\n      addr: not-an-addr\n");
    let err = RillaneConfig::from_str(&yaml, None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("probe.targets"), "应点名非法位置: {err}");
}

#[test]
fn invalid_addr_and_empty_host_rejected_by_validate() {
    let mut probe = ProbeConfigBlock {
        targets: vec![ProbeTargetSpec::Connect {
            addr: "not-an-addr".into(),
        }],
        limits: ProbeLimitsConfig::default(),
    };
    assert!(probe.validate().is_err());

    probe.targets = vec![ProbeTargetSpec::UdpEcho {
        addr: "192.0.2.1".into(), // 缺端口
    }];
    assert!(probe.validate().is_err());

    probe.targets = vec![ProbeTargetSpec::Dns { host: "   ".into() }];
    assert!(probe.validate().is_err());
}

#[test]
fn zero_limits_are_rejected() {
    let probe = ProbeConfigBlock {
        targets: vec![],
        limits: ProbeLimitsConfig {
            max_active: Some(0),
            job_timeout_ms: None,
            udp_payload_max_bytes: None,
            byte_budget: None,
        },
    };
    let err = probe.validate().unwrap_err().to_string();
    assert!(err.contains("max_active"), "应点名非法字段: {err}");

    let probe = ProbeConfigBlock {
        targets: vec![],
        limits: ProbeLimitsConfig {
            max_active: None,
            job_timeout_ms: Some(0),
            udp_payload_max_bytes: None,
            byte_budget: None,
        },
    };
    assert!(probe.validate().is_err());

    let probe = ProbeConfigBlock {
        targets: vec![],
        limits: ProbeLimitsConfig {
            max_active: None,
            job_timeout_ms: None,
            udp_payload_max_bytes: Some(0),
            byte_budget: None,
        },
    };
    assert!(probe.validate().is_err());

    let probe = ProbeConfigBlock {
        targets: vec![],
        limits: ProbeLimitsConfig {
            max_active: None,
            job_timeout_ms: None,
            udp_payload_max_bytes: None,
            byte_budget: Some(0),
        },
    };
    assert!(probe.validate().is_err());
}

#[test]
fn valid_block_passes_validation() {
    let probe = ProbeConfigBlock {
        targets: vec![
            ProbeTargetSpec::Dns {
                host: "example.invalid".into(),
            },
            ProbeTargetSpec::Connect {
                addr: "127.0.0.1:443".into(),
            },
        ],
        limits: ProbeLimitsConfig {
            max_active: Some(1),
            job_timeout_ms: Some(1),
            udp_payload_max_bytes: Some(1),
            byte_budget: Some(1),
        },
    };
    probe.validate().expect("全部字段合法应通过");
}
