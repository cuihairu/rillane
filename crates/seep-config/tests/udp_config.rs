//! P0-5 §10-S0 测试计划：UdpConfig 新字段缺省向后兼容 / validate 拒非法 /
//! per-ingress 判定三态 / ingress serde 往返（udp-observability.md）。

use seep_config::{resolve_udp_enabled, IngressConfig, IngressDescriptor, SeepConfig, UdpConfig};

/// 不含 `udp:` 块与只含旧 5 字段的两份 YAML 均可解析，且新字段等于 §1.2 缺省。
#[test]
fn udp_config_defaults_backward_compatible() {
    let base_yaml = r#"
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
    // ① 完全不含 udp: 块
    let cfg: SeepConfig = serde_yaml::from_str(base_yaml).expect("无 udp 块应可解析");
    assert_eq!(cfg.udp.sweep_interval_secs, 15);
    assert_eq!(cfg.udp.max_mappings, 256);
    assert_eq!(cfg.udp.session_lifetime_secs, None);
    assert_eq!(cfg.udp.downlink_queue_depth, 64);
    assert_eq!(cfg.udp.max_associates, 256);

    // ② 只含 P0-2 旧 5 字段，缺 5 个新字段
    let old_yaml = format!(
        "{base_yaml}udp:\n  enabled: true\n  strict_udp_source: false\n  session_idle_secs: 120\n  mapping_idle_secs: 30\n  max_sessions: 512\n"
    );
    let cfg: SeepConfig = serde_yaml::from_str(&old_yaml).expect("旧 5 字段应可解析");
    assert!(cfg.udp.enabled);
    assert!(!cfg.udp.strict_udp_source);
    assert_eq!(cfg.udp.session_idle_secs, 120);
    assert_eq!(cfg.udp.mapping_idle_secs, 30);
    assert_eq!(cfg.udp.max_sessions, 512);
    assert_eq!(cfg.udp.sweep_interval_secs, 15);
    assert_eq!(cfg.udp.max_mappings, 256);
    assert_eq!(cfg.udp.session_lifetime_secs, None);
    assert_eq!(cfg.udp.downlink_queue_depth, 64);
    assert_eq!(cfg.udp.max_associates, 256);
}

/// §1.6 约束逐组拒非法（sweep=0 / max_mappings=0 / lifetime<idle / queue_depth=0 / max_associates=0）。
#[test]
fn udp_config_validate_rejects_illegal() {
    type Mutate = Box<dyn Fn(&mut UdpConfig)>;
    let cases: Vec<(&str, Mutate)> = vec![
        (
            "sweep_interval_secs",
            Box::new(|c: &mut UdpConfig| c.sweep_interval_secs = 0),
        ),
        (
            "max_mappings",
            Box::new(|c: &mut UdpConfig| c.max_mappings = 0),
        ),
        (
            "session_lifetime_secs",
            Box::new(|c: &mut UdpConfig| {
                c.session_lifetime_secs = Some(10); // < 默认 session_idle_secs=180
            }),
        ),
        (
            "downlink_queue_depth",
            Box::new(|c: &mut UdpConfig| c.downlink_queue_depth = 0),
        ),
        (
            "max_associates",
            Box::new(|c: &mut UdpConfig| c.max_associates = 0),
        ),
    ];
    for (field, mutate) in cases {
        let mut cfg = UdpConfig::default();
        mutate(&mut cfg);
        let err = cfg.validate().expect_err("非法值应被拒绝");
        assert!(
            err.to_string().contains(field),
            "错误信息应点名 {field}，实得: {err}"
        );
    }
    // 边界：合法下界与 lifetime==idle 均通过
    let mut ok = UdpConfig::default();
    ok.sweep_interval_secs = 1;
    ok.max_mappings = 1;
    ok.downlink_queue_depth = 1;
    ok.max_associates = 1;
    ok.session_lifetime_secs = Some(ok.session_idle_secs);
    ok.validate().expect("合法边界值应通过");
}

/// §9-4 三态：None 继承全局 / Some(false) 显式关 / Some(true) 显式开。
#[test]
fn resolve_udp_enabled_three_states() {
    assert!(!resolve_udp_enabled(false, None));
    assert!(resolve_udp_enabled(true, None));
    assert!(!resolve_udp_enabled(true, Some(false)));
    assert!(resolve_udp_enabled(false, Some(true)));
}

/// socks5 与 mixed 条目带/不带 udp_enabled 序列化往返等价（缺字段 = None）。
#[test]
fn ingress_udp_enabled_serde_roundtrip() {
    let yaml = r#"
- name: socks-in
  type: socks5
  bind: 127.0.0.1:1080
- name: socks-explicit
  type: socks5
  bind: 127.0.0.1:1081
  udp_enabled: false
- name: mixed-in
  type: mixed
  bind: 127.0.0.1:7890
- name: mixed-explicit
  type: mixed
  bind: 127.0.0.1:7891
  udp_enabled: true
"#;
    let parsed: Vec<IngressDescriptor> = serde_yaml::from_str(yaml).expect("ingress 列表应可解析");
    let expect = [
        (0, None::<bool>),
        (1, Some(false)),
        (2, None::<bool>),
        (3, Some(true)),
    ];
    for (idx, want) in expect {
        let got = match &parsed[idx].spec {
            IngressConfig::Socks5 { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Mixed { udp_enabled, .. } => *udp_enabled,
            other => panic!("第 {idx} 项应为 socks5/mixed，实为 {other:?}"),
        };
        assert_eq!(got, want, "第 {idx} 项 udp_enabled 应为 {want:?}");
    }

    let rendered = serde_yaml::to_string(&parsed).expect("应可序列化");
    let reparsed: Vec<IngressDescriptor> =
        serde_yaml::from_str(&rendered).expect("序列化结果应可往返");
    assert_eq!(
        serde_yaml::to_string(&reparsed).unwrap(),
        rendered,
        "二次序列化应稳定"
    );
    // 缺字段项不输出键（skip_serializing_if），显式项保留
    let after = rendered.split("name: socks-in").nth(1).unwrap();
    let socks_block = after.split("name: socks-explicit").next().unwrap();
    assert!(!socks_block.contains("udp_enabled"));
    assert!(rendered.contains("udp_enabled: false"));
    assert!(rendered.contains("udp_enabled: true"));
}
