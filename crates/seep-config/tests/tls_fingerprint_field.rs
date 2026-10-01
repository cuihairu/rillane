//! P2-5 M1：egress 四 TLS 变体的 tls_fingerprint 配置面——
//! 缺省 None / 显式值往返 / 未知值不在 schema 层拦截（运行期转换报错带原值，§4-3 E1）。

use seep_config::{EgressConfig, SeepConfig};

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

/// §4-3：四变体字段缺省 None（存量零差异），显式 chrome 往返保真。
#[test]
fn egress_tls_variants_carry_tls_fingerprint() {
    let yaml = format!(
        "{BASE_YAML}egress:\n  - name: t\n    type: trojan\n    server: s.example\n    port: 443\n    password: pw\n    tls_fingerprint: chrome\n"
    );
    let cfg: SeepConfig = serde_yaml::from_str(&yaml).expect("应可解析");
    match &cfg.egress[0].spec {
        EgressConfig::Trojan {
            tls_fingerprint, ..
        } => {
            assert_eq!(tls_fingerprint.as_deref(), Some("chrome"));
        }
        other => panic!("应为 Trojan，实为 {other:?}"),
    }

    // 缺省：不写该字段 → None
    let yaml = format!(
        "{BASE_YAML}egress:\n  - name: t\n    type: trojan\n    server: s.example\n    port: 443\n    password: pw\n"
    );
    let cfg: SeepConfig = serde_yaml::from_str(&yaml).expect("应可解析");
    match &cfg.egress[0].spec {
        EgressConfig::Trojan {
            tls_fingerprint, ..
        } => assert_eq!(tls_fingerprint, &None),
        other => panic!("应为 Trojan，实为 {other:?}"),
    }
}
