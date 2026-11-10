//! G1-6：EgressConfig::Vless 的 REALITY 配置面——serde 不静默丢键：
//! `reality`（native 键，内层 RealityConfig 容 kebab/snake 别名）与 `flow`
//! 解析必须成功且字段完整保留；缺省 None 零差异；序列化往返保真。

use seep_config::{EgressConfig, RealityConfig, SeepConfig};

const BASE_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
  enable_tracing: false
ingress: []
routing:
  default_node: direct
  groups: []
  rules: []
"#;

fn vless_yaml(extra: &str) -> String {
    format!(
        "{BASE_YAML}egress:\n  - name: vl\n    type: vless\n    server: s.example\n    port: 443\n    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3\n    network: tcp\n    tls: true\n{extra}"
    )
}

fn parse_vless(yaml: &str) -> EgressConfig {
    let cfg: SeepConfig = serde_yaml::from_str(yaml).expect("应可解析");
    cfg.egress[0].spec.clone()
}

/// `reality:`（native 键）+ 内层 kebab 键位（Clash 口径别名）解析成功且字段完整保留。
#[test]
fn vless_reality_kebab_keys_parse_and_preserve() {
    let spec = parse_vless(&vless_yaml(
        "    reality:\n      public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ\n      short-id: \"0123ac\"\n",
    ));
    match &spec {
        EgressConfig::Vless { reality, flow, .. } => {
            let r = reality.as_ref().expect("reality 应保留");
            assert_eq!(r.public_key, "PBQh7j2tWxQmZHVub3RUYXJnZXQ");
            assert_eq!(r.short_id.as_deref(), Some("0123ac"));
            assert!(flow.is_none());
        }
        other => panic!("应为 Vless，实为 {other:?}"),
    }
}

/// snake 别名键位（public_key/short_id）同口径解析。
#[test]
fn vless_reality_snake_keys_parse() {
    let spec = parse_vless(&vless_yaml(
        "    reality:\n      public_key: PBQh7j2tWxQmZHVub3RUYXJnZXQ\n      short_id: \"ab12\"\n",
    ));
    match &spec {
        EgressConfig::Vless { reality, .. } => {
            let r = reality.as_ref().expect("reality 应保留");
            assert_eq!(r.public_key, "PBQh7j2tWxQmZHVub3RUYXJnZXQ");
            assert_eq!(r.short_id.as_deref(), Some("ab12"));
        }
        other => panic!("应为 Vless，实为 {other:?}"),
    }
}

/// flow 字段解析保留（XTLS-Vision；拨号期门控，导入面不丢）。
#[test]
fn vless_flow_field_parse_and_preserve() {
    let spec = parse_vless(&vless_yaml("    flow: xtls-rprx-vision\n"));
    match &spec {
        EgressConfig::Vless { flow, reality, .. } => {
            assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            assert!(reality.is_none());
        }
        other => panic!("应为 Vless，实为 {other:?}"),
    }
}

/// 两字段缺省 = None（存量零差异）；short-id 缺席 = None。
#[test]
fn vless_reality_absent_is_none_zero_diff() {
    let spec = parse_vless(&vless_yaml(""));
    match &spec {
        EgressConfig::Vless { flow, reality, .. } => {
            assert_eq!(flow, &None);
            assert_eq!(reality, &None);
        }
        other => panic!("应为 Vless，实为 {other:?}"),
    }

    // short-id 缺席：public-key 在即可解析，short_id = None
    let spec = parse_vless(&vless_yaml(
        "    reality:\n      public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ\n",
    ));
    match &spec {
        EgressConfig::Vless { reality, .. } => {
            let r = reality.as_ref().expect("reality 应保留");
            assert_eq!(r.short_id, None);
        }
        other => panic!("应为 Vless，实为 {other:?}"),
    }
}

/// 序列化往返保真：RealityConfig（kebab 键位）与 flow 均不丢；
/// None 不产出键（skip_serializing_if 零差异）。
#[test]
fn vless_reality_roundtrip_preserves_fields() {
    let spec = parse_vless(&vless_yaml(
        "    flow: xtls-rprx-vision\n    reality:\n      public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ\n      short-id: \"0123ac\"\n",
    ));
    let out = serde_yaml::to_string(&spec).expect("应可序列化");
    assert!(out.contains("public_key"), "往返应保留公钥键位: {out}");
    assert!(out.contains("short_id"), "往返应保留 short_id: {out}");
    assert!(out.contains("xtls-rprx-vision"), "往返应保留 flow: {out}");
    assert!(!out.contains("reality: null"), "None 不产出 null 键: {out}");

    let reparsed: EgressConfig = serde_yaml::from_str(&out).expect("应可重解析");
    assert_eq!(reparsed, spec, "往返应相等");
}

/// RealityConfig 直接构造等价于解析结果（字段语义对齐）。
#[test]
fn reality_config_direct_construction_matches() {
    let expected = RealityConfig {
        public_key: "PBQh7j2tWxQmZHVub3RUYXJnZXQ".to_string(),
        short_id: Some("0123ac".to_string()),
    };
    let spec = parse_vless(&vless_yaml(
        "    reality:\n      public-key: PBQh7j2tWxQmZHVub3RUYXJnZXQ\n      short-id: \"0123ac\"\n",
    ));
    match &spec {
        EgressConfig::Vless { reality, .. } => assert_eq!(reality.as_ref(), Some(&expected)),
        other => panic!("应为 Vless，实为 {other:?}"),
    }
}
