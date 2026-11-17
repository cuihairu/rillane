//! 并列场景求值（RIL-021）配置面回归：`ScenarioRule` serde 默认值与
//! roundtrip、空场景面不落盘、构建期校验（name/target 非空；条件正则
//! 按 `scenario:<名>` 归因——与规则面同口径，非法正则不得吞成默认路由）。

use rillane_config::{MatchCondition, RoutingConfig, ScenarioFailureAction};

#[test]
fn scenario_rule_defaults_and_roundtrip() {
    let text = r#"
default_node: direct
groups: []
rules: []
scenarios:
  - name: game
    target: game-exit
    conditions:
      - type: process
        values: ["steam"]
      - type: proto
        protocols: ["udp"]
  - name: general
    target: web-exit
    priority: 5
    on_failure: reject
"#;
    let config: RoutingConfig = serde_yaml::from_str(text).expect("场景配置解析");
    assert_eq!(config.scenarios.len(), 2);

    let game = &config.scenarios[0];
    assert_eq!(game.name, "game");
    assert_eq!(game.target, "game-exit");
    assert_eq!(game.priority, 100, "缺省优先级 100");
    assert_eq!(
        game.on_failure,
        ScenarioFailureAction::Fallback,
        "缺省失败动作 fallback"
    );
    assert_eq!(game.conditions.len(), 2);

    let general = &config.scenarios[1];
    assert_eq!(general.priority, 5);
    assert_eq!(general.on_failure, ScenarioFailureAction::Reject);
    assert!(
        general.conditions.is_empty(),
        "条件缺省为空 = 全量兜底场景（general）"
    );

    // roundtrip 保持全部字段
    let text = serde_yaml::to_string(&config).expect("序列化");
    let re: RoutingConfig = serde_yaml::from_str(&text).expect("回读");
    assert_eq!(re.scenarios, config.scenarios);
}

#[test]
fn empty_scenarios_omitted_from_serialization() {
    let config = RoutingConfig {
        default_node: "direct".into(),
        ..Default::default()
    };
    let text = serde_yaml::to_string(&config).expect("序列化");
    assert!(
        !text.contains("scenarios:"),
        "空场景面不落盘（skip_serializing_if）: {text}"
    );
}

#[test]
fn validate_rejects_empty_name_and_target() {
    let config = RoutingConfig {
        default_node: "direct".into(),
        scenarios: vec![rillane_config::ScenarioRule {
            name: "  ".into(),
            conditions: Vec::new(),
            target: "game-exit".into(),
            priority: 100,
            on_failure: ScenarioFailureAction::Fallback,
        }],
        ..Default::default()
    };
    let err = config.validate().expect_err("空场景名应被构建期拦截");
    assert!(format!("{err}").contains("场景名不得为空"));

    let config = RoutingConfig {
        default_node: "direct".into(),
        scenarios: vec![rillane_config::ScenarioRule {
            name: "game".into(),
            conditions: Vec::new(),
            target: " ".into(),
            priority: 100,
            on_failure: ScenarioFailureAction::Fallback,
        }],
        ..Default::default()
    };
    let err = config.validate().expect_err("空 target 应被构建期拦截");
    let msg = format!("{err}");
    assert!(msg.contains("game"), "错误应点名场景: {msg}");
    assert!(msg.contains("target 不得为空"), "{msg}");
}

#[test]
fn invalid_scenario_regex_rejected_with_scenario_scope() {
    let config = RoutingConfig {
        default_node: "direct".into(),
        scenarios: vec![rillane_config::ScenarioRule {
            name: "game".into(),
            conditions: vec![MatchCondition::DomainRegex {
                patterns: vec!["(unclosed".into()],
            }],
            target: "game-exit".into(),
            priority: 100,
            on_failure: ScenarioFailureAction::Fallback,
        }],
        ..Default::default()
    };
    let err = config.validate().expect_err("场景内非法正则应被构建期拦截");
    let msg = format!("{err}");
    assert!(
        msg.contains("scenario:game"),
        "错误应按 scenario:<名> 归因: {msg}"
    );
    assert!(msg.contains("(unclosed"), "错误应含非法 pattern: {msg}");
}

#[test]
fn valid_scenario_with_conditions_passes_validate() {
    let config = RoutingConfig {
        default_node: "direct".into(),
        scenarios: vec![rillane_config::ScenarioRule {
            name: "web".into(),
            conditions: vec![
                MatchCondition::Process {
                    values: vec!["chrome".into()],
                },
                MatchCondition::DomainSuffix {
                    values: vec!["example.com".into()],
                },
            ],
            target: "web-exit".into(),
            priority: 10,
            on_failure: ScenarioFailureAction::Reject,
        }],
        ..Default::default()
    };
    config.validate().expect("合法场景配置应通过校验");
}
