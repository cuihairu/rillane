//! GroupMember serde 往返：序列化面（手写 internally-tagged `{type, name,
//! weight?}` 形）与反序列化面（GroupMemberRepr：字符串简写 / type: 标签形）
//! 必须互认——否则 serde_yaml 落盘的 RillaneConfig（rillanectl import-clash 等）
//! rillaned 读不回。

use rillane_config::{GroupMember, PolicyGroup, RillaneConfig, RoutingConfig, Strategy};

fn base_config() -> RillaneConfig {
    serde_yaml::from_str::<RillaneConfig>(
        r#"
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
"#,
    )
    .expect("基线配置应可解析")
}

/// 全四变体 YAML 序列化 → 读回相等（tag 为 snake_case `type` 字段形）。
#[test]
fn group_member_yaml_roundtrip_all_variants() {
    let mut cfg = base_config();
    cfg.routing.groups.push(PolicyGroup {
        name: "g".into(),
        strategy: Strategy::Fixed,
        members: vec![
            GroupMember::Node { name: "n1".into() },
            GroupMember::Group { name: "g2".into() },
            GroupMember::WeightedNode {
                name: "n3".into(),
                weight: 7,
            },
            GroupMember::WeightedGroup {
                name: "g4".into(),
                weight: 3,
            },
        ],
        slo: None,
        url_test: None,
    });

    let rendered = serde_yaml::to_string(&cfg).expect("应可序列化");
    // externally-tagged `!Node` 形不允许再出现
    assert!(!rendered.contains("!Node"), "禁止 externally-tagged 形");
    assert!(rendered.contains("type: node"));
    assert!(rendered.contains("type: weighted_node"));
    assert!(rendered.contains("weight: 7"));

    let parsed: RillaneConfig = serde_yaml::from_str(&rendered).expect("序列化产物应可读回");
    let members = &parsed.routing.groups[0].members;
    assert_eq!(members.len(), 4);
    assert!(matches!(&members[0], GroupMember::Node { name } if name == "n1"));
    assert!(matches!(&members[1], GroupMember::Group { name } if name == "g2"));
    assert!(
        matches!(&members[2], GroupMember::WeightedNode { name, weight } if name == "n3" && *weight == 7)
    );
    assert!(
        matches!(&members[3], GroupMember::WeightedGroup { name, weight } if name == "g4" && *weight == 3)
    );
}

/// 反序列化面保持既有两形态：字符串简写与 `type:` 标签形（含权重）。
#[test]
fn group_member_deserialize_shapes_unchanged() {
    let routing: RoutingConfig = serde_yaml::from_str(
        r#"
default_node: direct
groups:
  - name: g
    strategy: fixed
    members:
      - plain-node
      - type: node
        name: tagged-node
      - type: weighted_node
        name: wn
        weight: 9
rules: []
"#,
    )
    .expect("两形态均应可解析");
    let members = &routing.groups[0].members;
    assert!(matches!(&members[0], GroupMember::Node { name } if name == "plain-node"));
    assert!(matches!(&members[1], GroupMember::Node { name } if name == "tagged-node"));
    assert!(
        matches!(&members[2], GroupMember::WeightedNode { name, weight } if name == "wn" && *weight == 9)
    );
}
