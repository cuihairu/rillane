//! RIL-146 Git/SSH/GitHub 路由预设契约验收：展开顺序（先用户 → 应用
//! 预设 → 区域）/ SSH 面目标回落与显式 / 幂等 / 用户同名声明退让 /
//! 校验门 / 预览 / 与区域预设并存次序 / serde 往返。

use rillane_config::{
    git_preset_preview, GitPresetBlock, RillaneConfig, GIT_ASSETS_RULE, GIT_HTTPS_RULE,
    GIT_PRESET_VERSION, GIT_SSH_ALT_RULE, GIT_SSH_RULE,
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

fn yaml_with_git(git_yaml: &str) -> String {
    format!("{BASE_YAML}\n  git_preset:\n{git_yaml}")
}

fn git_yaml_target_only() -> String {
    "    target: proxy-group\n".to_string()
}

fn git_yaml_ssh_split() -> String {
    "    target: proxy-group\n    ssh: direct\n".to_string()
}

/// 展开顺序：用户规则保持位 0，预设规则按声明序追加（先用户 → 应用预设）；
/// SSH 面目标缺席回落 target。
#[test]
fn git_expands_after_user_rules_with_ssh_fallback() {
    let cfg = RillaneConfig::from_str(&yaml_with_git(&git_yaml_target_only()), None).expect("解析");
    let rules = &cfg.routing.rules;
    assert_eq!(rules[0].name, "user-first", "用户规则保持位 0");
    assert_eq!(rules[1].name, GIT_SSH_RULE);
    assert_eq!(rules[1].target, "proxy-group", "SSH 目标缺席回落 target");
    assert_eq!(rules[2].name, GIT_SSH_ALT_RULE);
    assert_eq!(rules[3].name, GIT_HTTPS_RULE);
    assert_eq!(rules[4].name, GIT_ASSETS_RULE);
    assert_eq!(rules.len(), 5);
    // 版本化规则集注入（4 集）
    for set in [
        "git-ssh-hosts",
        "git-ssh-alt-hosts",
        "git-https-hosts",
        "git-assets-hosts",
    ] {
        assert!(
            cfg.routing.rule_sets.get(set).is_some(),
            "预设规则集 {set} 须已注入"
        );
    }
}

/// SSH 面目标显式：git-ssh/git-ssh-alt 走 ssh，HTTPS/下载面走 target。
#[test]
fn ssh_split_targets_by_face() {
    let cfg = RillaneConfig::from_str(&yaml_with_git(&git_yaml_ssh_split()), None).expect("解析");
    let rules = &cfg.routing.rules;
    assert_eq!(rules[1].target, "direct", "SSH:22 面走 ssh 目标");
    assert_eq!(rules[2].target, "direct", "SSH:443 备用面走 ssh 目标");
    assert_eq!(rules[3].target, "proxy-group", "HTTPS/API 面走 target");
    assert_eq!(rules[4].target, "proxy-group", "下载面走 target");
}

/// 幂等：重复展开不产生重复规则/规则集。
#[test]
fn preset_expansion_is_idempotent() {
    let mut cfg =
        RillaneConfig::from_str(&yaml_with_git(&git_yaml_ssh_split()), None).expect("解析");
    let before = cfg.routing.rules.clone();
    cfg.routing.apply_git_preset();
    assert_eq!(cfg.routing.rules, before, "重复展开不追加重复规则");
    let sets = [
        "git-ssh-hosts",
        "git-ssh-alt-hosts",
        "git-https-hosts",
        "git-assets-hosts",
    ]
    .iter()
    .map(|n| cfg.routing.rule_sets.get(n).is_some())
    .collect::<Vec<_>>();
    assert_eq!(sets, vec![true, true, true, true], "规则集在场且无重复注入");
}

/// 用户同名声明退让：用户自建 git-https 规则不被模板覆盖/复制。
#[test]
fn user_named_git_rules_are_respected() {
    let yaml = format!(
        "{BASE_YAML}    - name: git-https\n      target: user-target\n      matches:\n        - type: domain_suffix\n          values: [gh.corp.example]\n\n  git_preset:\n    target: proxy-group\n"
    );
    let cfg = RillaneConfig::from_str(&yaml, None).expect("解析");
    let https: Vec<_> = cfg
        .routing
        .rules
        .iter()
        .filter(|r| r.name == GIT_HTTPS_RULE)
        .collect();
    assert_eq!(https.len(), 1, "同名规则不复制: {:?}", https);
    assert_eq!(https[0].target, "user-target", "用户显式声明优先");
    assert_eq!(cfg.routing.rules[0].name, "user-first");
}

/// 与区域预设并存：Git 规则先于区域规则展开（先用户 → 应用预设 → 区域）。
#[test]
fn git_rules_precede_region_rules() {
    let yaml = format!(
        "{BASE_YAML}  git_preset:\n    target: proxy-group\n  region_preset:\n    kind: mainland_direct\n    direct: direct\n    proxy: proxy-group\n"
    );
    let cfg = RillaneConfig::from_str(&yaml, None).expect("解析");
    let names: Vec<_> = cfg.routing.rules.iter().map(|r| r.name.as_str()).collect();
    let git_pos = names
        .iter()
        .position(|n| *n == GIT_HTTPS_RULE)
        .expect("git 规则在场");
    let region_pos = names
        .iter()
        .position(|n| *n == "region-cn-domain")
        .expect("区域规则在场");
    assert!(git_pos < region_pos, "应用预设先于区域规则: {names:?}");
    assert_eq!(names[0], "user-first", "用户规则恒位 0");
}

/// 校验门：target 显式非空、ssh 显式声明时非空（空串点名拒绝）。
#[test]
fn validate_requires_nonempty_targets() {
    let mut cfg =
        RillaneConfig::from_str(&yaml_with_git(&git_yaml_target_only()), None).expect("解析");
    cfg.routing.git_preset = Some(GitPresetBlock {
        target: "  ".to_string(),
        ssh: None,
    });
    let err = cfg.routing.validate().expect_err("空 target 须拒绝");
    assert!(err.to_string().contains("target"), "点名 target: {err}");

    cfg.routing.git_preset = Some(GitPresetBlock {
        target: "proxy-group".to_string(),
        ssh: Some(String::new()),
    });
    let err = cfg.routing.validate().expect_err("空 ssh 须拒绝");
    assert!(err.to_string().contains("ssh"), "点名 ssh: {err}");

    cfg.routing.git_preset = Some(GitPresetBlock {
        target: "proxy-group".to_string(),
        ssh: None,
    });
    assert!(cfg.routing.validate().is_ok(), "合法块通过");
}

/// 预览：求值序、来源卡片、固定说明；无块 → None。
#[test]
fn preview_reports_order_cards_and_notes() {
    let cfg = RillaneConfig::from_str(&yaml_with_git(&git_yaml_ssh_split()), None).expect("解析");
    let p = git_preset_preview(&cfg.routing).expect("有块须有预览");
    assert_eq!(p.version, GIT_PRESET_VERSION);
    assert_eq!(p.order_sample.len(), 4);
    assert_eq!(p.ssh, "direct", "预览点名展开后的 SSH 目标");
    assert_eq!(p.rule_sets.len(), 4);
    for card in &p.rule_sets {
        assert!(!card.source.is_empty(), "来源卡片可查: {}", card.name);
        assert!(card.entries > 0);
    }
    let joined = p.notes.join("\n");
    assert!(joined.contains("连通不等于加速"));
    assert!(joined.contains("主机密钥"));
    assert!(joined.contains("暂停"));

    let bare = RillaneConfig::from_str(BASE_YAML, None).expect("解析");
    assert!(git_preset_preview(&bare.routing).is_none(), "无块无预览");
}

/// serde 往返：git_preset 块保形；无 ssh 字段时序列化不带键。
#[test]
fn git_preset_block_roundtrip() {
    let cfg = RillaneConfig::from_str(&yaml_with_git(&git_yaml_ssh_split()), None).expect("解析");
    let json = serde_json::to_string(&cfg).expect("可序列化");
    assert!(
        json.contains("\"git_preset\""),
        "块序列化在场: {}",
        json.contains("\"git_preset\"")
    );
    let back: RillaneConfig = serde_json::from_str(&json).expect("回读可解析");
    assert_eq!(back.routing.git_preset, cfg.routing.git_preset);

    // target-only：skip_serializing_if 不带 ssh 键
    let cfg2 =
        RillaneConfig::from_str(&yaml_with_git(&git_yaml_target_only()), None).expect("解析");
    let json2 = serde_json::to_string(&cfg2).expect("可序列化");
    assert!(!json2.contains("\"ssh\""), "ssh 缺席不带键: {json2}");
}
