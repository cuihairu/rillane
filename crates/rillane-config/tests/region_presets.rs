//! RIL-141 区域绕过预设契约验收：展开顺序（先用户后区域）/ 方向矩阵 /
//! 幂等 / 用户同名声明退让 / 校验门 / 样例预览 / 模式暂停集成。

use rillane_config::{
    region_preset_preview, RegionPresetBlock, RegionPresetKind, RillaneConfig,
    REGION_CN_DOMAIN_RULE, REGION_CN_IP_RULE, REGION_LAN_RULE,
};

const BASE_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: false
  enable_tracing: false
ingress: []
egress:
  - name: direct
    type: direct
routing:
  default_node: proxy-group
  groups: []
  rules:
    - name: user-first
      target: proxy-group
      matches:
        - type: domain_suffix
          values: [user.example]
"#;

fn yaml_with_preset(preset_yaml: &str) -> String {
    format!("{BASE_YAML}\n  region_preset:\n{preset_yaml}")
}

fn mainland_direct_yaml() -> String {
    yaml_with_preset("    kind: mainland_direct\n    direct: direct\n    proxy: proxy-group")
}

fn mainland_proxy_yaml() -> String {
    yaml_with_preset("    kind: mainland_proxy\n    direct: direct\n    proxy: proxy-group")
}

/// 展开顺序：用户规则保持位 0，预设规则追加其后（先用户后区域——
/// 用户优先级不被改写）；大陆直连方向 CN 面 → direct。
#[test]
fn mainland_direct_expands_after_user_rules() {
    let cfg = RillaneConfig::from_str(&mainland_direct_yaml(), None).expect("解析");
    let rules = &cfg.routing.rules;
    assert_eq!(rules[0].name, "user-first", "用户规则保持位 0");
    assert_eq!(rules[0].target, "proxy-group");
    assert_eq!(rules[1].name, REGION_LAN_RULE);
    assert_eq!(rules[1].target, "direct", "LAN 绕过恒直连侧");
    assert_eq!(rules[2].name, REGION_CN_DOMAIN_RULE);
    assert_eq!(rules[2].target, "direct", "大陆直连：CN 域名面 → 直连");
    assert_eq!(rules[3].name, REGION_CN_IP_RULE);
    assert_eq!(rules[3].target, "direct");
    assert_eq!(rules.len(), 4);
    // 版本化规则集注入
    for set in [
        "region-lan",
        "region-cn-domain-sample",
        "region-cn-ip-sample",
    ] {
        assert!(
            cfg.routing.rule_sets.get(set).is_some(),
            "预设规则集 {set} 须已注入"
        );
    }
}

/// 反向预设方向矩阵：CN 面 → proxy，LAN 恒直连。
#[test]
fn reverse_preset_targets_proxy_for_cn() {
    let cfg = RillaneConfig::from_str(&mainland_proxy_yaml(), None).expect("解析");
    let rules = &cfg.routing.rules;
    assert_eq!(rules[1].target, "direct", "LAN 旁路独立于方向");
    assert_eq!(rules[2].target, "proxy-group", "反向预设 CN 域名面 → 代理");
    assert_eq!(rules[3].target, "proxy-group", "反向预设 CN IP 面 → 代理");
    let block = cfg.routing.region_preset.expect("块在场");
    assert_eq!(block.kind, RegionPresetKind::MainlandProxy);
}

/// 幂等：重复展开不产生重复规则/规则集。
#[test]
fn preset_expansion_is_idempotent() {
    let mut cfg = RillaneConfig::from_str(&mainland_direct_yaml(), None).expect("解析");
    let before = cfg.routing.rules.clone();
    cfg.routing.apply_region_preset();
    assert_eq!(cfg.routing.rules, before, "重复展开不追加重复规则");
    // 规则集数量不变（3 个预设集，无重复注入）
    let set_names: Vec<_> = [
        "region-lan",
        "region-cn-domain-sample",
        "region-cn-ip-sample",
    ]
    .iter()
    .map(|n| cfg.routing.rule_sets.get(n).is_some())
    .collect();
    assert_eq!(set_names, vec![true, true, true]);
}

/// 用户同名声明退让：用户自建 region-lan 规则不被模板覆盖/复制。
#[test]
fn user_named_region_rules_are_respected() {
    let yaml = format!(
        "{BASE_YAML}    - name: region-lan\n      target: user-target\n      matches:\n        - type: ip_cidr\n          cidrs: [10.9.0.0/16]\n\n  region_preset:\n    kind: mainland_direct\n    direct: direct\n    proxy: proxy-group"
    );
    let cfg = RillaneConfig::from_str(&yaml, None).expect("解析");
    let lan: Vec<_> = cfg
        .routing
        .rules
        .iter()
        .filter(|r| r.name == REGION_LAN_RULE)
        .collect();
    assert_eq!(lan.len(), 1, "同名规则不复制: {:?}", lan);
    assert_eq!(lan[0].target, "user-target", "用户显式声明优先");
    assert_eq!(cfg.routing.rules[0].name, "user-first");
    assert_eq!(
        cfg.routing.rules[1].name, "region-lan",
        "用户声明仍在预设追加段之前"
    );
}

/// 校验门：direct/proxy 两侧目标非空。
#[test]
fn validate_requires_nonempty_targets() {
    let mut cfg = RillaneConfig::from_str(&mainland_direct_yaml(), None).expect("解析");
    cfg.routing.region_preset = Some(RegionPresetBlock {
        kind: RegionPresetKind::MainlandDirect,
        direct: "  ".to_string(),
        proxy: "proxy-group".to_string(),
    });
    let err = cfg.routing.validate().expect_err("空 direct 须拒绝");
    assert!(err.to_string().contains("direct"), "点名 direct: {err}");

    cfg.routing.region_preset = Some(RegionPresetBlock {
        kind: RegionPresetKind::MainlandDirect,
        direct: "direct".to_string(),
        proxy: String::new(),
    });
    let err = cfg.routing.validate().expect_err("空 proxy 须拒绝");
    assert!(err.to_string().contains("proxy"), "点名 proxy: {err}");
}

/// 样例预览：求值序、来源卡片、固定说明；无块 → None。
#[test]
fn preview_reports_order_cards_and_notes() {
    let cfg = RillaneConfig::from_str(&mainland_direct_yaml(), None).expect("解析");
    let p = region_preset_preview(&cfg.routing).expect("有块须有预览");
    assert_eq!(p.kind, RegionPresetKind::MainlandDirect);
    assert_eq!(p.order_sample.len(), 3);
    assert!(p.order_sample[0].starts_with(REGION_LAN_RULE));
    assert_eq!(p.rule_sets.len(), 3);
    for card in &p.rule_sets {
        assert!(!card.source.is_empty(), "来源卡片可查: {}", card.name);
        assert!(card.entries > 0);
    }
    let joined = p.notes.join("\n");
    assert!(joined.contains("proxy-group"), "方向提示点名 default_node");
    assert!(joined.contains("兜底"));
    assert!(joined.contains("暂停"));

    let bare = RillaneConfig::from_str(BASE_YAML, None).expect("解析");
    assert!(region_preset_preview(&bare.routing).is_none(), "无块无预览");
}

/// 模式集成：展开后的配置在全局模式下，暂停清单含预设规则名
/// （「全局/直连显示暂停」验收面）。
#[test]
fn mode_preview_pauses_preset_rules() {
    let cfg = RillaneConfig::from_str(&mainland_direct_yaml(), None).expect("解析");
    let p =
        rillane_config::mode_override_preview(&cfg.routing, rillane_config::SelectionMode::Global);
    for name in [REGION_LAN_RULE, REGION_CN_DOMAIN_RULE, REGION_CN_IP_RULE] {
        assert!(
            p.paused_rules.iter().any(|r| r == name),
            "暂停清单须含 {name}: {:?}",
            p.paused_rules
        );
    }
    // 预设规则也是普通规则——REJECT 点名清单为空（预设无 reject target）
    assert!(p.paused_reject_rules.is_empty());
}

/// serde 往返：region_preset 块保形。
#[test]
fn region_preset_block_roundtrip() {
    let cfg = RillaneConfig::from_str(&mainland_proxy_yaml(), None).expect("解析");
    let json = serde_json::to_string(&cfg).expect("可序列化");
    assert!(
        json.contains("mainland_proxy"),
        "kind 标签 snake_case: {json}"
    );
    let back: RillaneConfig = serde_json::from_str(&json).expect("回读可解析");
    assert_eq!(back.routing.region_preset, cfg.routing.region_preset);
}
