//! Rillane DSL 转换面全量单测（覆盖率批次：validate 错误路径 / 节点各类型
//! 转换 / 规则各变体 / 规则集）。全部纯函数，零网络。

use rillane_subscription::{
    GroupMemberRef, NodeType, RillaneDslConverter, RillaneGroup, RillaneNode, RillaneRule,
    RillaneRuleSet, RillaneStrategy, RillaneVersion,
};
use std::collections::HashMap;

fn node(name: &str, ty: &str, server: Option<&str>, port: Option<u16>) -> RillaneNode {
    RillaneNode {
        name: name.to_string(),
        node_type: serde_json::from_str(&format!("\"{}\"", ty)).expect("节点类型字面量"),
        server: server.map(String::from),
        port,
        auth: None,
        transport: None,
        tls: None,
        bandwidth_limit: None,
        location: None,
        tags: vec![],
        metadata: HashMap::new(),
        flow: None,
        reality: None,
    }
}

// ---------- validate 错误路径 ----------

#[test]
fn duplicate_names_rejected_for_nodes_groups_rulesets() {
    let converter = RillaneDslConverter::new();

    let yaml_dup_node = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
  - name: "a"
    type: direct
groups: []
rules: []
"#;
    let err = converter.parse(yaml_dup_node).unwrap_err().to_string();
    assert!(err.contains("重复的节点名称"), "实际: {err}");

    let yaml_dup_group = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups:
  - name: "g"
    strategy: fixed
    members: ["a"]
  - name: "g"
    strategy: fixed
    members: ["a"]
rules: []
"#;
    let err = converter.parse(yaml_dup_group).unwrap_err().to_string();
    assert!(err.contains("重复的组名称"), "实际: {err}");

    let yaml_dup_ruleset = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups: []
rulesets:
  - name: "rs"
    rules: []
  - name: "rs"
    rules: []
rules: []
"#;
    let err = converter.parse(yaml_dup_ruleset).unwrap_err().to_string();
    assert!(err.contains("重复的规则集名称"), "实际: {err}");
}

#[test]
fn dangling_group_and_ruleset_references_rejected() {
    let converter = RillaneDslConverter::new();

    let yaml = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups:
  - name: "g"
    strategy: fixed
    members: ["ghost"]
rules: []
"#;
    let err = converter.parse(yaml).unwrap_err().to_string();
    assert!(err.contains("引用了不存在的节点或组: ghost"), "实际: {err}");

    let yaml_rs = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups: []
rules:
  - type: rule-set
    name: "ghost-rs"
    target: a
"#;
    let err = converter.parse(yaml_rs).unwrap_err().to_string();
    assert!(err.contains("规则引用了不存在的规则集"), "实际: {err}");

    let yaml_rs_in_rs = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups: []
rulesets:
  - name: "rs"
    rules:
      - type: rule-set
        name: "other"
        target: a
rules: []
"#;
    let err = converter.parse(yaml_rs_in_rs).unwrap_err().to_string();
    assert!(
        err.contains("规则集 rs 中的规则引用了不存在的规则集"),
        "实际: {err}"
    );
}

#[test]
fn validation_can_be_disabled() {
    let converter = RillaneDslConverter::new().with_validation(false);
    let yaml = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups:
  - name: "g"
    strategy: fixed
    members: ["ghost"]
rules: []
"#;
    let cfg = converter.parse(yaml).expect("关闭校验后悬空引用不再拒绝");
    assert_eq!(cfg.groups[0].members.len(), 1);
}

// ---------- 节点转换：各类型 / 缺字段错误 / 过滤 ----------

#[test]
fn socks5_http_ss_convert_with_auth_variants() {
    let yaml = r#"
version: "1.0"
nodes:
  - name: "s5"
    type: socks5
    server: 1.2.3.4
    port: 1080
    auth:
      type: password
      username: u
      password: p
  - name: "s5-plain"
    type: socks5
    server: 1.2.3.4
    port: 1080
  - name: "http-tls"
    type: http
    server: example.com
    port: 443
    tls:
      enabled: true
      server_name: sni.example.com
      skip_cert_verify: true
  - name: "ss"
    type: shadowsocks
    server: example.com
    port: 8388
    auth:
      type: key
      method: aes-256-gcm
      password: pw
groups: []
rules: []
"#;
    let cfg = RillaneDslConverter::new().parse(yaml).unwrap();
    let out = RillaneDslConverter::new()
        .convert_to_rillane(&cfg)
        .expect("全部合法节点应可转换");
    assert_eq!(out.egress.len(), 4);

    let by_name = |n: &str| out.egress.iter().find(|e| e.name == n).unwrap();
    match &by_name("s5").spec {
        rillane_config::EgressConfig::Socks5 {
            server,
            port,
            username,
            password,
        } => {
            assert_eq!((server.as_str(), *port), ("1.2.3.4", 1080));
            assert_eq!(username.as_deref(), Some("u"));
            assert_eq!(password.as_deref(), Some("p"));
        }
        other => panic!("s5 应为 Socks5，实际 {other:?}"),
    }
    match &by_name("s5-plain").spec {
        rillane_config::EgressConfig::Socks5 { username, .. } => {
            assert_eq!(*username, None);
        }
        other => panic!("s5-plain 应为 Socks5，实际 {other:?}"),
    }
    match &by_name("http-tls").spec {
        rillane_config::EgressConfig::Http {
            tls,
            skip_cert_verify,
            sni,
            ..
        } => {
            assert!(*tls);
            assert!(*skip_cert_verify);
            assert_eq!(sni.as_deref(), Some("sni.example.com"));
        }
        other => panic!("http-tls 应为 Http，实际 {other:?}"),
    }
    match &by_name("ss").spec {
        rillane_config::EgressConfig::Shadowsocks {
            method, password, ..
        } => {
            assert_eq!(method, "aes-256-gcm");
            assert_eq!(password, "pw");
        }
        other => panic!("ss 应为 Shadowsocks，实际 {other:?}"),
    }
}

#[test]
fn missing_required_fields_rejected_per_type() {
    let converter = RillaneDslConverter::new();

    // socks5 缺端口：filtering 关闭才走到字段校验（缺省时无效节点被静默过滤）
    let nofilter = RillaneDslConverter::new().with_filtering(false);
    let cfg = nofilter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: "s5"
    type: socks5
    server: 1.2.3.4
groups: []
rules: []
"#,
        )
        .unwrap();
    assert!(nofilter.convert_to_rillane(&cfg).is_err());

    // 对照：filtering 开启时同一节点被跳过而非报错
    let cfg = converter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: "s5"
    type: socks5
    server: 1.2.3.4
groups: []
rules: []
"#,
        )
        .unwrap();
    assert_eq!(converter.convert_to_rillane(&cfg).unwrap().egress.len(), 0);

    // socks5 认证类型错误（uuid ≠ password）
    let cfg = converter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: "s5"
    type: socks5
    server: 1.2.3.4
    port: 1080
    auth:
      type: uuid
      uuid: 12345678-1234-1234-1234-123456789abc
groups: []
rules: []
"#,
        )
        .unwrap();
    let err = converter.convert_to_rillane(&cfg).unwrap_err().to_string();
    assert!(err.contains("认证类型错误"), "实际: {err}");

    // ss 缺认证
    let cfg = converter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: "ss"
    type: shadowsocks
    server: example.com
    port: 8388
groups: []
rules: []
"#,
        )
        .unwrap();
    let err = converter.convert_to_rillane(&cfg).unwrap_err().to_string();
    assert!(err.contains("缺少认证信息"), "实际: {err}");

    // vmess 缺 UUID
    let cfg = converter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: "vm"
    type: vmess
    server: example.com
    port: 443
groups: []
rules: []
"#,
        )
        .unwrap();
    let err = converter.convert_to_rillane(&cfg).unwrap_err().to_string();
    assert!(err.contains("缺少 UUID"), "实际: {err}");

    // reject 节点直接拒绝（filtering 关闭才不被 is_valid_node 静默过滤）
    let cfg = nofilter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: "blk"
    type: reject
groups: []
rules: []
"#,
        )
        .unwrap();
    let err = nofilter.convert_to_rillane(&cfg).unwrap_err().to_string();
    assert!(err.contains("Reject 节点类型暂不支持"), "实际: {err}");
}

#[test]
fn invalid_nodes_filtered_when_filtering_enabled() {
    // filtering=true（缺省）：无效节点跳过，转换仍成功
    let converter = RillaneDslConverter::new();
    let cfg = converter
        .parse(
            r#"
version: "1.0"
nodes:
  - name: ""
    type: direct
  - name: "ok"
    type: direct
groups: []
rules: []
"#,
        )
        .unwrap();
    let out = converter.convert_to_rillane(&cfg).unwrap();
    assert_eq!(out.egress.len(), 1, "空名节点应被过滤");

    // filtering=false：无效节点进入转换（direct 无必填字段，仍成功）
    let nofilter = RillaneDslConverter::new().with_filtering(false);
    let out2 = nofilter.convert_to_rillane(&cfg).unwrap();
    assert_eq!(out2.egress.len(), 2);
}

// ---------- 规则与规则集 ----------

#[test]
fn all_supported_rule_variants_convert() {
    let yaml = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups: []
rulesets:
  - name: "rs-main"
    rules:
      - type: domain-suffix
        domains: ["google.com"]
        target: a
      - type: domain-keyword
        keywords: ["ads"]
        target: a
      - type: domain
        domains: ["x.com"]
        target: a
      - type: domain-regex
        patterns: ["^y\\." ]
        target: a
      - type: ip-cidr
        cidrs: ["10.0.0.0/8"]
        target: a
      - type: geoip
        country: CN
        target: a
      - type: geo-site
        category: category-games
        target: a
      - type: port
        ports: [80, 443]
        target: a
      - type: match
        target: a
rules:
  - type: domain-suffix
    domains: ["top.com"]
    target: a
default_target: a
"#;
    let cfg = RillaneDslConverter::new().parse(yaml).unwrap();
    let out = RillaneDslConverter::new().convert_to_rillane(&cfg).unwrap();
    // 规则集 9 条在前 + 直接规则 1 条在后
    assert_eq!(out.routing.rules.len(), 10);
    assert!(out.routing.rules[0].name.starts_with("rs-main-rule-"));
    assert_eq!(out.routing.rules[9].name, "rule-1");
    // match 规则产出空 matches
    let match_rule = out
        .routing
        .rules
        .iter()
        .find(|r| r.name == "rs-main-rule-9")
        .unwrap();
    assert!(match_rule.matches.is_empty());
    assert_eq!(match_rule.target, "a");
    // default_target 透传
    assert_eq!(out.routing.default_node, "a");
}

#[test]
fn process_and_ruleset_rules_rejected_not_silently_dropped() {
    let converter = RillaneDslConverter::new();

    let cfg = RillaneConfigFixture::with_rules(vec![RillaneRule::Process {
        processes: vec!["game.exe".into()],
        target: "a".into(),
    }]);
    let err = converter
        .convert_to_rillane(&cfg.0)
        .unwrap_err()
        .to_string();
    assert!(err.contains("进程名规则暂不支持"), "实际: {err}");

    let cfg = RillaneConfigFixture::with_rules(vec![RillaneRule::RuleSet {
        name: "rs".into(),
        target: "a".into(),
    }]);
    let err = converter
        .convert_to_rillane(&cfg.0)
        .unwrap_err()
        .to_string();
    assert!(err.contains("规则集引用暂不支持"), "实际: {err}");
}

/// 直接构造 DSL RillaneConfig（跳过 YAML）的测试脚手架。
struct RillaneConfigFixture(rillane_subscription::RillaneConfig);

impl RillaneConfigFixture {
    fn with_rules(rules: Vec<RillaneRule>) -> Self {
        Self(rillane_subscription::RillaneConfig {
            version: RillaneVersion::V1_0,
            meta: HashMap::new(),
            nodes: vec![node("a", "direct", None, None)],
            groups: vec![],
            rulesets: vec![],
            rules,
            default_target: "a".to_string(),
        })
    }
}

// ---------- 元数据面 ----------

#[test]
fn node_type_descriptions_and_counts() {
    use RillaneDslConverter as Dsl;

    assert_eq!(Dsl::get_node_type_description(NodeType::Direct), "Direct");
    assert_eq!(Dsl::get_node_type_description(NodeType::Reject), "Reject");
    assert_eq!(Dsl::get_node_type_description(NodeType::Socks5), "SOCKS5");
    assert_eq!(Dsl::get_node_type_description(NodeType::Http), "HTTP");
    assert_eq!(
        Dsl::get_node_type_description(NodeType::Shadowsocks),
        "Shadowsocks"
    );
    assert_eq!(Dsl::get_node_type_description(NodeType::Vmess), "VMess");
    assert_eq!(Dsl::get_node_type_description(NodeType::Vless), "VLESS");
    assert_eq!(Dsl::get_node_type_description(NodeType::Trojan), "Trojan");
    assert_eq!(
        Dsl::get_node_type_description(NodeType::Hysteria),
        "Hysteria"
    );
    assert_eq!(
        Dsl::get_node_type_description(NodeType::Hysteria2),
        "Hysteria2"
    );
    assert_eq!(
        Dsl::get_node_type_description(NodeType::Wireguard),
        "WireGuard"
    );

    let nodes = vec![
        node("a", "direct", None, None),
        node("b", "direct", None, None),
        node("c", "socks5", Some("1.2.3.4"), Some(1080)),
    ];
    let counts = Dsl::count_node_types(&nodes);
    assert_eq!(counts[&NodeType::Direct], 2);
    assert_eq!(counts[&NodeType::Socks5], 1);
}

#[test]
fn strategy_all_variants_roundtrip_via_conversion() {
    // 七种策略逐一进 YAML 再转换，断言一一映射
    use RillaneStrategy as RS;
    for (yaml_strategy, expect) in [
        ("fixed", RS::Fixed),
        ("random", RS::Random),
        ("latency", RS::Latency),
        ("bandwidth", RS::Bandwidth),
        ("weighted", RS::Weighted),
        ("consistenthash", RS::ConsistentHash),
        ("roundrobin", RS::RoundRobin),
    ] {
        let yaml = format!(
            r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
groups:
  - name: "g"
    strategy: {yaml_strategy}
    members: ["a"]
rules: []
"#
        );
        let cfg = RillaneDslConverter::new().parse(&yaml).unwrap();
        assert_eq!(cfg.groups[0].strategy, expect, "策略 {yaml_strategy}");
        let out = RillaneDslConverter::new().convert_to_rillane(&cfg).unwrap();
        assert_eq!(out.routing.groups.len(), 1);
    }
}

#[test]
fn weighted_members_and_defaults_roundtrip() {
    let yaml = r#"
version: "1.0"
nodes:
  - name: "a"
    type: direct
  - name: "b"
    type: direct
groups:
  - name: "g"
    strategy: weighted
    members:
      - "a"
      - name: "b"
        weight: 3
rules: []
"#;
    let cfg = RillaneDslConverter::new().parse(yaml).unwrap();
    let g: &RillaneGroup = &cfg.groups[0];
    // 缺省字段：interval 30 / fallback true / timeout 5
    assert_eq!(g.health_check_interval, 30);
    assert!(g.fallback_enabled);
    assert_eq!(g.fallback_timeout, 5);
    assert!(matches!(g.members[0], GroupMemberRef::Node(_)));
    assert!(matches!(
        g.members[1],
        GroupMemberRef::WeightedNode { weight: 3, .. }
    ));

    // default_target 缺省 direct
    let minimal = r#"
version: "1.1"
nodes:
  - name: "a"
    type: direct
groups: []
rules: []
"#;
    let cfg = RillaneDslConverter::new().parse(minimal).unwrap();
    assert_eq!(cfg.version, RillaneVersion::V1_1);
    assert_eq!(cfg.default_target, "direct");

    // is_valid_node：端口 0 无效
    let mut zero = node("z", "socks5", Some("s"), Some(0));
    assert!(!RillaneDslConverter::new().is_valid_node(&zero));
    zero.port = Some(1);
    assert!(RillaneDslConverter::new().is_valid_node(&zero));
    let empty = node("", "direct", None, None);
    assert!(!RillaneDslConverter::new().is_valid_node(&empty));
    let reject = node("r", "reject", None, None);
    assert!(!RillaneDslConverter::new().is_valid_node(&reject));
}

#[test]
fn ruleset_metadata_and_serialization_roundtrip() {
    let rs = RillaneRuleSet {
        name: "rs".into(),
        rules: vec![RillaneRule::DomainSuffix {
            domains: vec!["a.com".into()],
            target: "a".into(),
        }],
        metadata: HashMap::new(),
    };
    let yaml = serde_yaml::to_string(&rs).expect("规则集可序列化");
    let back: RillaneRuleSet = serde_yaml::from_str(&yaml).expect("规则集可反序列化");
    assert_eq!(back.name, "rs");
    assert_eq!(back.rules.len(), 1);

    // RillaneNode 序列化面（skip none 字段）
    let n = node("n", "vmess", Some("example.com"), Some(443));
    let y = serde_yaml::to_string(&n).expect("节点可序列化");
    assert!(y.contains("name: \"n\"") || y.contains("name: n"));
    let back: RillaneNode = serde_yaml::from_str(&y).expect("节点可反序列化");
    assert_eq!(back.node_type, NodeType::Vmess);

    let _ = RillaneDslConverter::default(); // Default 与 new 等价
    let _ = RillaneStrategy::Fixed; // 覆盖 derive 路径
}
