//! 订阅兼容样本库验收（RIL-007）：脱敏正反例逐个断言预期对象/诊断——
//! 每个关键输入的产出与损失必须可预期；样本仓库不带节点密码与带 token
//! 的 URL（守卫测试钉住脱敏红线）。纯解析/转换，零网络。

use std::path::PathBuf;

use rillane_config::{SourceId, Strategy, CODE_COMPAT_LOSSY, CODE_COMPAT_UNSUPPORTED};
use rillane_subscription::ClashConverter;

fn sample(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("样本 {path:?} 必须可读: {err}"))
}

fn loose(
    sample_name: &str,
) -> (
    rillane_config::RillaneConfig,
    rillane_subscription::ConversionReport,
) {
    let yaml = sample(sample_name);
    let converter = ClashConverter::new();
    let clash = converter.parse(&yaml).expect("样本必须可解析");
    converter
        .convert_to_rillane_with_report(&clash)
        .expect("宽松导入必须成功")
}

// ---------- 正例：inline 完整配置无损 ----------

#[test]
fn inline_positive_converts_losslessly() {
    let (config, report) = loose("inline_positive.yaml");
    assert!(
        report.is_empty(),
        "正例必须零损失，实际: {}",
        report.summary()
    );

    // 预期对象：3 节点
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-ss", "sample-vmess", "sample-trojan"]);

    // 预期对象：2 组——select 原语义、url-test 300 秒（RIL-092 口径不变）
    let groups = &config.routing.groups;
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].name, "PROXY");
    assert_eq!(groups[0].strategy, Strategy::Fixed);
    assert_eq!(groups[0].members.len(), 3);
    assert_eq!(groups[1].name, "AUTO");
    assert_eq!(groups[1].strategy, Strategy::Latency);
    let url_test = groups[1].url_test.as_ref().expect("url-test 组带探测配置");
    assert_eq!(url_test.interval_secs, 300);

    // 预期对象：3 规则（含 MATCH 兜底）
    assert_eq!(config.routing.rules.len(), 3);
    assert_eq!(config.routing.default_node, "sample-ss");
}

// ---------- 反例：full-policy 有损输入逐项可预期 ----------

#[test]
fn negative_lossy_reports_every_expected_loss() {
    let (config, report) = loose("negative_lossy.yaml");

    // 丢弃节点：port:0 无效节点 + snell 类型暂不支持
    let dropped: Vec<&str> = report
        .dropped_nodes
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        dropped.contains(&"bad-port-node"),
        "无效端口节点必须进清单: {dropped:?}"
    );
    assert!(
        dropped.contains(&"sample-snell"),
        "snell 类型节点必须进清单: {dropped:?}"
    );

    // 降级组：fallback→Random、relay→ConsistentHash
    let degraded: Vec<&str> = report
        .degraded_groups
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(degraded.contains(&"fb-group"), "fallback 降级必须进清单");
    assert!(degraded.contains(&"relay-group"), "relay 降级必须进清单");

    // 跳过规则：PROCESS-NAME 与 RULE-SET（rule-N 命名含序号）
    let dropped_rules: Vec<&str> = report
        .dropped_rules
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        dropped_rules.contains(&"rule-1") && dropped_rules.contains(&"rule-2"),
        "前两条不支持规则必须进清单: {dropped_rules:?}"
    );

    // 保留面：好节点、select 组、支持的两条规则照常产出
    assert_eq!(config.egress.len(), 1, "只有 good-node-a 产出");
    assert_eq!(config.routing.rules.len(), 2, "DOMAIN-SUFFIX+MATCH 保留");

    // 诊断桥（RIL-002 契约）：每条损失带稳定码并定位到来源对象
    let source = SourceId::new("sample-lossy").unwrap();
    let diagnostics = report.diagnostics(&source);
    assert_eq!(
        diagnostics.len(),
        report.dropped_nodes.len() + report.degraded_groups.len() + report.dropped_rules.len()
    );
    for diagnostic in &diagnostics {
        assert_eq!(diagnostic.location.source.as_str(), "sample-lossy");
    }
    let node_diagnostic = diagnostics
        .iter()
        .find(|d| d.location.pointer == "proxies/bad-port-node")
        .expect("无效节点定位到 proxies/<名>");
    assert_eq!(node_diagnostic.code, CODE_COMPAT_UNSUPPORTED);
    assert_eq!(
        node_diagnostic.object.as_ref().unwrap().local_id,
        "bad-port-node"
    );
    let group_diagnostic = diagnostics
        .iter()
        .find(|d| d.location.pointer == "proxy-groups/fb-group")
        .expect("降级组定位到 proxy-groups/<名>");
    assert_eq!(group_diagnostic.code, CODE_COMPAT_LOSSY);
    let rule_diagnostic = diagnostics
        .iter()
        .find(|d| d.location.pointer == "rules/rule-1")
        .expect("跳过规则定位到 rules/<名>");
    assert_eq!(rule_diagnostic.code, CODE_COMPAT_UNSUPPORTED);
}

#[test]
fn negative_lossy_strict_rejects_with_full_list() {
    let yaml = sample("negative_lossy.yaml");
    let converter = ClashConverter::new().with_strict(true);
    let clash = converter.parse(&yaml).expect("样本必须可解析");
    let err = converter
        .convert_to_rillane_with_report(&clash)
        .expect_err("严格导入必须拒绝有损样本");
    let message = err.to_string();
    for expected in [
        "bad-port-node",
        "sample-snell",
        "fb-group",
        "relay-group",
        "rule-1",
        "rule-2",
    ] {
        assert!(
            message.contains(expected),
            "严格拒绝错误须点名 {expected}，实际:\n{message}"
        );
    }
}

// ---------- 反例：provider-only 输入整块显式可见 ----------

#[test]
fn provider_only_surfaces_block_loss_not_silent() {
    let (config, report) = loose("provider_only.yaml");

    // 节点零吸收（proxies: []，provider 未吸收）
    assert!(
        config.egress.is_empty(),
        "provider 生命周期归 RIL-009，当前不得伪装吸收"
    );

    // 整块进未支持清单（宽松可见）
    assert_eq!(report.unsupported_blocks.len(), 1);
    let (block_name, reason) = &report.unsupported_blocks[0];
    assert_eq!(block_name, "proxy-providers");
    assert!(
        reason.contains('1'),
        "原因须含 provider 数量，实际: {reason}"
    );
    assert!(!report.is_empty());

    // 诊断桥：compat.unsupported 定位 blocks/proxy-providers
    let source = SourceId::new("sample-provider-only").unwrap();
    let diagnostics = report.diagnostics(&source);
    let block = diagnostics
        .iter()
        .find(|d| d.location.pointer == "blocks/proxy-providers")
        .expect("provider 块必须被诊断定位");
    assert_eq!(block.code, CODE_COMPAT_UNSUPPORTED);

    // 严格模式：整块缺失即拒绝
    let yaml = sample("provider_only.yaml");
    let converter = ClashConverter::new().with_strict(true);
    let clash = converter.parse(&yaml).expect("样本必须可解析");
    let err = converter
        .convert_to_rillane_with_report(&clash)
        .expect_err("严格导入必须拒绝 provider-only 样本");
    assert!(
        err.to_string().contains("proxy-providers"),
        "拒绝错误须点名块: {}",
        err
    );
}

// ---------- RIL-014：rule-providers + RULE-SET + 逻辑规则样本 ----------

#[test]
fn ruleset_logic_sample_converts_with_tracked_references() {
    let (config, report) = loose("ruleset_logic.yaml");
    assert!(
        report.is_empty(),
        "样本必须零损失，实际: {}",
        report.summary()
    );

    // 首匹配顺序 = 声明顺序；rule-N 命名稳定；MATCH 兜底最后
    let names: Vec<&str> = config
        .routing
        .rules
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(names, vec!["rule-1", "rule-2", "rule-3", "rule-4", "rule-5"]);

    // RULE-SET → 命名引用（可追踪）
    assert_eq!(
        config.routing.rules[0].matches[0],
        rillane_config::MatchCondition::RuleSetRef {
            name: "ads".to_string()
        }
    );

    // AND 平铺三条件（域名后缀 + 目标端口）、OR → Any（源端口 + 目标
    // 端口语义分离）、NOT → Not
    assert_eq!(config.routing.rules[1].matches.len(), 2);
    assert!(matches!(
        &config.routing.rules[1].matches[0],
        rillane_config::MatchCondition::DomainSuffix { .. }
    ));
    assert!(matches!(
        &config.routing.rules[1].matches[1],
        rillane_config::MatchCondition::Port { .. }
    ));
    assert!(matches!(
        &config.routing.rules[2].matches[0],
        rillane_config::MatchCondition::Any { .. }
    ));
    assert!(matches!(
        &config.routing.rules[3].matches[0],
        rillane_config::MatchCondition::Not { .. }
    ));
    assert!(config.routing.rules[4].matches.is_empty(), "MATCH 无条件");

    // 声明面：http + file 两个 provider，interval 秒口径原样带入
    assert_eq!(config.routing.rule_providers.len(), 2);
    let ads = config.routing.rule_providers.get("ads").expect("ads 声明");
    assert_eq!(ads.behavior, "domain");
    assert_eq!(ads.interval_secs, Some(86400));
    let direct = config
        .routing
        .rule_providers
        .get("direct-cidr")
        .expect("direct-cidr 声明");
    assert_eq!(direct.behavior, "ipcidr");
    assert_eq!(direct.provider_type, "file");
}

// ---------- 脱敏红线：样本仓库不得带真实凭据 ----------

#[test]
fn samples_contain_no_secrets() {
    let samples_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    let mut checked = 0;
    for entry in std::fs::read_dir(&samples_dir).expect("样本目录必须存在") {
        let path = entry.expect("可读").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("样本必须可读");
        // 带凭证 URL：任何查询串 token 一律禁止
        assert!(
            !content.contains("token="),
            "{path:?} 不得携带带 token 的 URL"
        );
        // 凭据字段：只允许占位值
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("password:") || line.starts_with("psk:") {
                assert!(
                    line.contains("REDACTED-SAMPLE"),
                    "{path:?} 凭据必须是占位值: {line}"
                );
            }
            if line.starts_with("uuid:") {
                assert!(
                    line.contains("00000000-0000-0000-0000-000000000000"),
                    "{path:?} UUID 必须是全零占位: {line}"
                );
            }
        }
        checked += 1;
    }
    assert!(checked >= 3, "样本库至少 3 份，实际 {checked}");
}
