//! P2-3 scenario-profiles.md §7（M0）：场景 profile 预设——展开矩阵 /
//! 显式优先 / 存量零差异 / 非法值 / 幂等。示例三选一集成测（§7-6）归 M1。

use rillane_config::{ProfileKind, RillaneConfig};

const BASE_YAML: &str = r#"
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
"#;

fn base_with_profile(profile: &str) -> String {
    format!("{BASE_YAML}profile: {profile}\n")
}

/// §7-1 展开矩阵：三 profile 逐格断言（组名/策略/slo/规则 target/
/// obfs/pool 填充面）。
#[test]
fn profile_expansion_matrix_three_kinds() {
    // proxy：auto 组（latency 无 slo）+ cn 规则；obfs/pool 不动
    let cfg: RillaneConfig =
        RillaneConfig::from_str(&base_with_profile("proxy"), Some("yaml")).expect("proxy 应可解析");
    assert_eq!(cfg.profile, Some(ProfileKind::Proxy));
    assert_eq!(cfg.routing.groups.len(), 1);
    let g = &cfg.routing.groups[0];
    assert_eq!(g.name, "auto");
    assert!(matches!(g.strategy, rillane_config::Strategy::Latency));
    assert_eq!(g.slo, None, "proxy 无调度目标");
    assert_eq!(g.members.len(), 1, "D-5 组模板单成员");
    assert!(
        matches!(&g.members[0], rillane_config::GroupMember::Node { name } if name == "direct"),
        "组模板成员 = [default_node]"
    );
    assert_eq!(cfg.routing.rules.len(), 1);
    assert_eq!(cfg.routing.rules[0].target, "auto");
    assert!(matches!(
        &cfg.routing.rules[0].matches[0],
        rillane_config::MatchCondition::Geoip { country } if country == "CN"
    ));
    assert_eq!(cfg.obfuscation, None, "proxy 不碰混淆");
    assert_eq!(cfg.egress_pool, None, "proxy 不碰连接池");

    // game：game-auto 组（latency + slo 80ms/2%）+ 域名模板规则；
    // obfs enabled + bucket；pool 不动
    let cfg: RillaneConfig =
        RillaneConfig::from_str(&base_with_profile("game"), Some("yaml")).expect("game 应可解析");
    assert_eq!(cfg.routing.groups.len(), 1);
    let g = &cfg.routing.groups[0];
    assert_eq!(g.name, "game-auto");
    let slo = g.slo.as_ref().expect("game 应带调度目标");
    assert_eq!(slo.p95_ms, Some(80));
    assert_eq!(slo.loss_ratio, Some(0.02));
    assert!(slo.validate().is_ok(), "预设 slo 值域合法");
    assert!(cfg.routing.rules.len() >= 8, "游戏平台域模板非空");
    assert!(
        cfg.routing.rules.iter().all(|r| r.target == "game-auto"),
        "模板规则全部指向场景组"
    );
    assert!(matches!(
        &cfg.routing.rules[0].matches[0],
        rillane_config::MatchCondition::DomainSuffix { .. }
    ));
    let obfs = cfg.obfuscation.as_ref().expect("game 应开混淆");
    assert!(obfs.enabled);
    let padding = obfs.padding.as_ref().expect("game 预设应带内联 padding");
    assert_eq!(padding.mode, "bucket");
    assert_eq!(padding.buckets, vec![128, 256, 512, 1024]);
    // P2-4 M2：game 预设连带 timing 启动抖动（对称概览注释 + 单测钉住）
    let timing = obfs.timing.as_ref().expect("game 预设应带内联 timing");
    assert_eq!(timing.mode, "fixed");
    assert_eq!(timing.fixed_ms, 10);
    assert_eq!(timing.max_delay_ms, 20);
    assert_eq!(
        obfs.middleware,
        vec!["padding".to_string(), "timing".to_string()],
        "game 预设 middleware 链 = padding + timing"
    );
    assert_eq!(cfg.egress_pool, None, "game 不碰连接池");

    // web：web-auto 组（latency 无 slo）+ cn 规则；pool enabled；obfs 不动
    let cfg: RillaneConfig =
        RillaneConfig::from_str(&base_with_profile("web"), Some("yaml")).expect("web 应可解析");
    assert_eq!(cfg.routing.groups[0].name, "web-auto");
    assert_eq!(cfg.routing.groups[0].slo, None);
    assert_eq!(cfg.routing.rules[0].target, "web-auto");
    assert_eq!(cfg.obfuscation, None, "web 不碰混淆");
    let pool = cfg.egress_pool.as_ref().expect("web 应开连接池");
    assert!(pool.enabled);
    assert_eq!(pool.max_idle_per_key, None, "其余字段缺省 = §3.1 缺省值");
}

/// §7-2 显式优先：已有 groups/rules 时组/规则模板不填（E6 同生共死），
/// obfs 未指定仍被填（逐面独立判定 D-2）。
#[test]
fn explicit_blocks_win_and_face_is_independent() {
    // 用带显式组/规则的 YAML 重建（BASE_YAML groups/rules 置空面）
    let yaml = format!("{BASE_YAML}profile: game\n");
    let yaml = yaml.replace(
        "  groups: []\n",
        "  groups:\n    - name: mine\n      strategy: fixed\n      members:\n        - direct\n",
    );
    let cfg: RillaneConfig =
        RillaneConfig::from_str(&yaml, Some("yaml")).expect("显式组 + game 应可解析");
    assert_eq!(cfg.routing.groups.len(), 1, "用户组不被覆盖");
    assert_eq!(cfg.routing.groups[0].name, "mine");
    assert_eq!(
        cfg.routing.rules.len(),
        0,
        "E6：用户自组在场时规则模板不填（悬空 target 防御）"
    );
    let obfs = cfg.obfuscation.as_ref().expect("obfs 面独立判定，仍被填");
    assert!(obfs.enabled);
}

/// §7-3 存量零差异：无 profile 字段 → 全部位不动。
#[test]
fn no_profile_field_untouched() {
    let cfg: RillaneConfig =
        RillaneConfig::from_str(BASE_YAML, Some("yaml")).expect("存量应可解析");
    assert_eq!(cfg.profile, None);
    assert!(cfg.routing.groups.is_empty());
    assert!(cfg.routing.rules.is_empty());
    assert_eq!(cfg.obfuscation, None);
    assert_eq!(cfg.egress_pool, None);
}

/// §7-4 非法值：serde unknown variant（E1）。
#[test]
fn unknown_profile_kind_rejected() {
    let yaml = base_with_profile("fps");
    let err = RillaneConfig::from_str(&yaml, Some("yaml")).expect_err("非法 profile 值应被拒");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("fps") || msg.to_lowercase().contains("unknown variant"),
        "报错应指认原值或 unknown variant：{msg}"
    );
}

/// §7-5 幂等：展开两次 == 展开一次（E4——填过即非空，再展开 no-op）。
#[test]
fn expansion_is_idempotent() {
    let once: RillaneConfig =
        RillaneConfig::from_str(&base_with_profile("game"), Some("yaml")).expect("首次展开");
    let mut twice = once.clone();
    twice.apply_profile();
    assert_eq!(
        serde_yaml::to_string(&once).unwrap(),
        serde_yaml::to_string(&twice).unwrap(),
        "二次展开应零变化"
    );

    // 反向序也稳：先显式给 obfs，再展开 game —— obfs 不被覆盖（D-2）
    let yaml = format!("{BASE_YAML}profile: game\nobfuscation:\n  enabled: false\n");
    let cfg: RillaneConfig =
        RillaneConfig::from_str(&yaml, Some("yaml")).expect("显式 obfs + game 应可解析");
    let obfs = cfg.obfuscation.as_ref().expect("显式块应保留");
    assert!(!obfs.enabled, "显式 enabled: false 恒优先，profile 不覆盖");
    assert_eq!(obfs.padding, None, "显式块内联形状不被模板改写");
}
