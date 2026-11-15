//! Clash 导入有损转换护栏（RIL-093）：宽松导入必须报告丢弃/降级内容，
//! 严格导入必须整体拒绝；已支持面零误伤回归。纯函数，零网络。

use rillane_config::Strategy;
use rillane_subscription::{
    ClashConverter, ConversionOptions, Subscription, SubscriptionConverter, SubscriptionType,
};

/// 基线配置：全部落在已支持面（ss 节点 + select/url-test 组 + 支持的规则）
const CLEAN: &str = r#"
proxies:
  - name: n1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw
proxy-groups: []
rules: []
"#;

fn with_groups(groups: &str) -> String {
    CLEAN.replace("proxy-groups: []", groups)
}

fn with_rules(rules: &str) -> String {
    CLEAN.replace("rules: []", rules)
}

// ---------- 组：fallback / relay 不再伪装成功 ----------

#[test]
fn strict_rejects_fallback_and_relay_groups() {
    for group_type in ["fallback", "relay"] {
        let yaml = with_groups(&format!(
            "proxy-groups:\n  - name: g1\n    type: {group_type}\n    proxies: [n1]"
        ));
        let converter = ClashConverter::new().with_strict(true);
        let clash = converter.parse(&yaml).unwrap();
        let err = converter
            .convert_to_rillane(&clash)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(group_type) && err.contains("g1"),
            "严格模式应点名 {group_type} 组 g1，实际: {err}"
        );
    }
}

#[test]
fn lenient_degrades_and_reports_groups() {
    for (group_type, degraded) in [
        ("fallback", Strategy::Random),
        ("relay", Strategy::ConsistentHash),
    ] {
        let yaml = with_groups(&format!(
            "proxy-groups:\n  - name: g1\n    type: {group_type}\n    proxies: [n1]"
        ));
        let converter = ClashConverter::new();
        let clash = converter.parse(&yaml).unwrap();
        let (config, report) = converter.convert_to_rillane_with_report(&clash).unwrap();

        // 宽松：照常产出，但降级必须报告
        assert_eq!(config.routing.groups[0].strategy, degraded);
        assert_eq!(report.degraded_groups.len(), 1);
        assert_eq!(report.degraded_groups[0].0, "g1");
        assert!(
            report.degraded_groups[0].1.contains(group_type),
            "降级说明应点名 {group_type}，实际: {:?}",
            report.degraded_groups[0].1
        );
        assert!(!report.is_empty());
    }
}

// ---------- 规则：不支持规则跳过必须可见 ----------

#[test]
fn unsupported_rules_reported_and_strict_rejected() {
    let yaml = with_rules(
        "rules:\n  - PROCESS-NAME,game.exe,n1\n  - RULE-SET,ads,n1\n  - DOMAIN-SUFFIX,example.com,n1",
    );

    // 严格：未声明的 RULE-SET 引用点名拒绝（RIL-014 起走引用追踪）；
    // RIL-015 起 PROCESS-NAME 可转换，不再构成拒绝理由。
    let strict = ClashConverter::new().with_strict(true);
    let clash = strict.parse(&yaml).unwrap();
    let err = strict.convert_to_rillane(&clash).unwrap_err().to_string();
    assert!(err.contains("rule-2"), "实际: {err}");
    assert!(err.contains("ads"), "未声明引用须点名规则集名: {err}");
    assert!(err.contains("rule-providers"));

    // 宽松：仅丢未声明引用，进程规则转换并按降级显式报告
    let lenient = ClashConverter::new();
    let clash = lenient.parse(&yaml).unwrap();
    let (config, report) = lenient.convert_to_rillane_with_report(&clash).unwrap();
    assert_eq!(report.dropped_rules.len(), 1);
    assert_eq!(config.routing.rules.len(), 2);
    assert_eq!(config.routing.rules[0].target, "n1");
    let degraded: Vec<&str> = report
        .degraded_rules
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(degraded, vec!["rule-1"]);
}

// ---------- 节点：无效与类型不支持分别报告，支持类型硬错误保持 ----------

#[test]
fn dropped_nodes_reported_and_strict_rejected() {
    // 在 n1 后追加两个问题节点：空 server（有效性校验不过）与 snell（类型不支持）
    let yaml = CLEAN.replace(
        "proxy-groups: []",
        concat!(
            "  - name: bad-server\n",
            "    type: ss\n",
            "    server: \"\"\n",
            "    port: 8388\n",
            "    cipher: aes-256-gcm\n",
            "    password: pw\n",
            "  - name: sn1\n",
            "    type: snell\n",
            "    server: example.com\n",
            "    port: 6160\n",
            "    password: pw\n",
            "proxy-groups: []",
        ),
    );

    // 宽松：两个节点都丢弃并点名；n1 照常导入
    let lenient = ClashConverter::new();
    let clash = lenient.parse(&yaml).unwrap();
    let (config, report) = lenient.convert_to_rillane_with_report(&clash).unwrap();
    assert_eq!(config.egress.len(), 1, "只有 n1 应导入");
    assert_eq!(report.dropped_nodes.len(), 2);
    let names: Vec<&str> = report
        .dropped_nodes
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(names.contains(&"bad-server"));
    assert!(names.contains(&"sn1"));

    // 严格：丢节点即整体拒绝
    let strict = ClashConverter::new().with_strict(true);
    let clash = strict.parse(&yaml).unwrap();
    let err = strict.convert_to_rillane(&clash).unwrap_err().to_string();
    assert!(
        err.contains("bad-server") && err.contains("sn1"),
        "实际: {err}"
    );
}

#[test]
fn broken_supported_type_hard_errors_in_both_modes() {
    // 已支持类型（vless + reality-opts）缺 public-key：两模式都点名硬错误，
    // 不降级成静默丢节点（G1-6 拒绝策略，RIL-093 保持）
    let yaml = r#"
proxies:
  - name: vl1
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d2a-b1e7-1bf75a1db7b3
    tls: true
    servername: www.apple.com
    reality-opts:
      short-id: "0123ac"
proxy-groups: []
rules: []
"#;
    for strict in [false, true] {
        let converter = ClashConverter::new().with_strict(strict);
        let clash = converter.parse(yaml).unwrap();
        let err = converter
            .convert_to_rillane(&clash)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("public-key") && err.contains("vl1"),
            "strict={strict} 应点名 public-key 与节点名，实际: {err}"
        );
    }
}

// ---------- 已支持面零误伤回归 ----------

#[test]
fn clean_supported_config_has_empty_report() {
    let yaml = format!(
        r#"{head}
proxy-groups:
  - name: sel
    type: select
    proxies: [n1]
  - name: ut
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies: [n1]
rules:
  - DOMAIN-SUFFIX,example.com,n1
  - MATCH,n1
"#,
        head = CLEAN.replace("\nproxy-groups: []\nrules: []", "")
    );

    // 严格模式全绿：没有丢弃/降级才有资格通过
    let strict = ClashConverter::new().with_strict(true);
    let clash = strict.parse(&yaml).unwrap();
    let (config, report) = strict.convert_to_rillane_with_report(&clash).unwrap();
    assert!(report.is_empty(), "已支持面不应误报: {}", report.summary());
    assert_eq!(config.egress.len(), 1);
    assert_eq!(config.routing.groups.len(), 2);
    assert_eq!(config.routing.rules.len(), 2);
    assert_eq!(config.routing.groups[0].strategy, Strategy::Fixed);
    assert_eq!(config.routing.groups[1].strategy, Strategy::Latency);
    // RIL-092 回归：url-test interval 按秒读取
    let ut = config.routing.groups[1].url_test.as_ref().unwrap();
    assert_eq!(ut.interval_secs, 300);
    assert_eq!(report.summary(), "无损失");
}

// ---------- 报告渲染 + 管线 wiring ----------

#[test]
fn report_summary_renders_counts_and_names() {
    let yaml = with_groups("proxy-groups:\n  - name: g1\n    type: fallback\n    proxies: [n1]")
        .replace("rules: []", "rules:\n  - PROCESS-NAME,game.exe,n1");
    let converter = ClashConverter::new();
    let clash = converter.parse(&yaml).unwrap();
    let (_, report) = converter.convert_to_rillane_with_report(&clash).unwrap();

    let summary = report.summary();
    assert!(summary.contains("降级组 1 个"));
    assert!(summary.contains("g1"));
    // RIL-015：进程规则不再是跳过项，而是显式降级项
    assert!(summary.contains("降级规则 1 条"), "进程规则须按降级报告: {summary}");
    assert!(summary.contains("rule-1"));
    // 空报告字面量
    assert_eq!(
        rillane_subscription::ConversionReport::default().summary(),
        "无损失"
    );
}

#[tokio::test]
async fn strict_import_option_propagates_to_pipeline() {
    let yaml = with_groups("proxy-groups:\n  - name: fb\n    type: fallback\n    proxies: [n1]");

    let sub = Subscription {
        name: "test".to_string(),
        url: "unused".to_string(),
        r#type: Some(SubscriptionType::Clash),
        enabled: true,
        refresh_interval: 0,
        timeout: 5,
        headers: std::collections::HashMap::new(),
        user_agent: None,
        last_updated: None,
        last_error: None,
        etag: None,
        content_hash: None,
        last_modified: None,
    };

    // 严格：管线整体拒绝，不产出半份配置
    let strict = SubscriptionConverter::with_options(ConversionOptions {
        strict_import: true,
        ..Default::default()
    });
    assert!(strict.auto_convert(&sub, &yaml).await.is_err());

    // 宽松：导入成功但损失清单进 warnings
    let lenient = SubscriptionConverter::with_options(ConversionOptions::default());
    let result = lenient.auto_convert(&sub, &yaml).await.unwrap();
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("有损转换报告") && w.contains("fb")),
        "损失应进 warnings，实际: {:?}",
        result.warnings
    );
}
