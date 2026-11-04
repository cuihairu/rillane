//! 路由正则构建期校验（审核发现 2026-11-04：非法或不支持的 Rust regex
//! 未在配置构建时校验，匹配时吞掉编译错误回落默认路由致规则静默失效）。
//! 回归：`RoutingConfig::validate` 对 `DomainRegex` pattern 逐条编译校验，
//! 非法 pattern 报 Err（含规则名与 pattern），合法 pattern 通过。

use seep_config::{MatchCondition, RouteRule, RoutingConfig};

fn cfg(rules: Vec<RouteRule>) -> RoutingConfig {
    RoutingConfig {
        default_node: "direct".into(),
        groups: vec![],
        rules,
    }
}

#[test]
fn valid_regex_passes_validate() {
    let config = cfg(vec![RouteRule {
        name: "ads".into(),
        matches: vec![MatchCondition::DomainRegex {
            patterns: vec![r"^ad\d+\.".into(), "^example\\.com$".into()],
        }],
        target: "block".into(),
    }]);
    config.validate().expect("合法正则应通过构建期校验");
}

#[test]
fn invalid_regex_fails_validate_with_rule_name() {
    let config = cfg(vec![RouteRule {
        name: "bad-rule".into(),
        matches: vec![MatchCondition::DomainRegex {
            patterns: vec!["(unclosed".into()],
        }],
        target: "block".into(),
    }]);
    let err = config.validate().expect_err("未闭合括号应被构建期拦截");
    let msg = format!("{err}");
    assert!(msg.contains("bad-rule"), "错误应含规则名: {msg}");
    assert!(msg.contains("(unclosed"), "错误应含非法 pattern: {msg}");
}

#[test]
fn nested_any_not_regex_validated_recursively() {
    let config = cfg(vec![RouteRule {
        name: "nested".into(),
        matches: vec![MatchCondition::Any {
            conditions: vec![MatchCondition::Not {
                condition: Box::new(MatchCondition::DomainRegex {
                    patterns: vec!["[".into()],
                }),
            }],
        }],
        target: "block".into(),
    }]);
    let err = config
        .validate()
        .expect_err("嵌套 Any/Not 内非法正则也应被拦截");
    assert!(format!("{err}").contains("nested"));
}
