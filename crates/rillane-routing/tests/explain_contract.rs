//! RIL-054 纯 Explain 服务契约测试（debug-and-mcp.md §3.1）：
//! 生产求值器推演与 `route()` 同源；证据缺失 → 条件性结果；输入快照
//! 可离线重放；无 DNS/拨号/OS 身份查询（推演主体是纯函数）。

use std::collections::BTreeMap;

use rillane_config::{
    GroupMember, MatchCondition, PolicyGroup, RouteRule, RoutingConfig, ScenarioFailureAction,
    ScenarioRule, Strategy,
};
use rillane_routing::{
    explain_offline, DomainSource, EgressCertainty, EvaluatedStep, ExplainInput, ExplainSnapshot,
    FrozenGroup, FrozenMember, FrozenQuality, FrozenSlo, ProcessEvidence, RoutingEngine,
};

fn base_config() -> RoutingConfig {
    RoutingConfig {
        default_node: "DIRECT".to_string(),
        ..Default::default()
    }
}

fn input(host: &str) -> ExplainInput {
    ExplainInput {
        generation_id: "gen-1".to_string(),
        ingress: None,
        host: host.to_string(),
        port: 443,
        proto: "tcp".to_string(),
        domain_source: DomainSource::UserProvided,
        process: None,
        annotations: BTreeMap::new(),
    }
}

fn rule(name: &str, cond: MatchCondition, target: &str) -> RouteRule {
    RouteRule {
        name: name.to_string(),
        matches: vec![cond],
        target: target.to_string(),
    }
}

fn frozen_node(name: &str, healthy: bool) -> FrozenMember {
    FrozenMember::Node {
        name: name.to_string(),
        weight: 1,
        healthy,
    }
}

fn frozen_group(name: &str, strategy: &str, members: Vec<FrozenMember>) -> FrozenGroup {
    FrozenGroup {
        name: name.to_string(),
        strategy: strategy.to_string(),
        slo: None,
        members,
    }
}

fn snapshot_with(groups: Vec<FrozenGroup>) -> ExplainSnapshot {
    ExplainSnapshot {
        groups: groups.into_iter().map(|g| (g.name.clone(), g)).collect(),
        ..Default::default()
    }
}

/// 规则命中带来源位置：评估序逐项记录（含未命中项）、决策来源、
/// 预测节点、摘要锚
#[test]
fn rule_hit_reports_source_position() {
    let mut config = base_config();
    config.rules = vec![
        rule(
            "first",
            MatchCondition::DomainFull {
                values: vec!["google.com".to_string()],
            },
            "A",
        ),
        rule(
            "second",
            MatchCondition::DomainFull {
                values: vec!["example.com".to_string()],
            },
            "B",
        ),
    ];
    let engine = RoutingEngine::new(config);
    let snap = ExplainSnapshot::default();
    let out = engine.explain(&snap, &input("example.com")).unwrap();

    assert_eq!(out.matched_by.as_deref(), Some("second"));
    assert_eq!(out.predicted.as_ref().unwrap().node.as_deref(), Some("B"));
    assert_eq!(out.certainty, EgressCertainty::Definitive);
    assert!(out.unknowns.is_empty());
    assert_eq!(
        out.evaluated,
        vec![
            EvaluatedStep::Rule {
                index: 0,
                name: "first".to_string(),
                matched: false
            },
            EvaluatedStep::Rule {
                index: 1,
                name: "second".to_string(),
                matched: true
            },
        ],
        "评估序含未命中项——为什么不是那条规则可直接读出"
    );
    // 命中规则即返回——不再评估 default
    assert_eq!(out.evaluated.len(), 2);
    // 摘要锚：与独立计算一致、64 位十六进制
    assert_eq!(out.input_digest, input("example.com").digest());
    assert_eq!(out.input_digest.len(), 64);
    assert_eq!(out.generation_id, "gen-1");
    assert_eq!(out.target.host, "example.com");
    assert_eq!(out.target.proto, "tcp");
}

/// 场景目标不可用 + fallback：落回规则面（说明显式，不静默）
#[test]
fn scenario_target_unavailable_falls_back_to_rules() {
    let mut config = base_config();
    config.scenarios = vec![ScenarioRule {
        name: "work".to_string(),
        conditions: vec![MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        }],
        target: "empty-group".to_string(),
        priority: 10,
        on_failure: ScenarioFailureAction::Fallback,
    }];
    config.rules = vec![rule(
        "rule-b",
        MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        },
        "B",
    )];
    let engine = RoutingEngine::new(config);
    let snap = snapshot_with(vec![frozen_group(
        "empty-group",
        "fallback",
        vec![frozen_node("X", false)],
    )]);

    let out = engine.explain(&snap, &input("example.com")).unwrap();
    assert_eq!(
        out.matched_by.as_deref(),
        Some("rule-b"),
        "fallback 落回规则面"
    );
    assert!(out.reject.is_none() && out.error.is_none());
    assert_eq!(out.notes.len(), 1, "落回说明显式记录");
    assert!(out.notes[0].contains("fallback"));
    assert_eq!(out.predicted.unwrap().node.as_deref(), Some("B"));
}

/// 场景 reject：显式拒绝终止推演，不落回规则面
#[test]
fn scenario_reject_is_explicit() {
    let mut config = base_config();
    config.scenarios = vec![ScenarioRule {
        name: "work".to_string(),
        conditions: vec![MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        }],
        target: "empty-group".to_string(),
        priority: 10,
        on_failure: ScenarioFailureAction::Reject,
    }];
    config.rules = vec![rule(
        "rule-b",
        MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        },
        "B",
    )];
    let engine = RoutingEngine::new(config);
    let snap = snapshot_with(vec![frozen_group(
        "empty-group",
        "fallback",
        vec![frozen_node("X", false)],
    )]);

    let out = engine.explain(&snap, &input("example.com")).unwrap();
    assert!(
        out.reject.as_deref().unwrap().contains("work"),
        "拒绝原因点名场景"
    );
    assert!(out.predicted.is_none());
    assert_eq!(out.evaluated.len(), 1, "reject 显式终止——不评估规则面");
    assert_eq!(
        out.certainty,
        EgressCertainty::Definitive,
        "显式拒绝是确定结论"
    );
}

/// 证据缺失 → 条件性结果：进程注解缺席按恒不命中评估并标注缺口；
/// 证据到位后同一推演给出确定结论
#[test]
fn missing_process_evidence_is_conditional() {
    let mut config = base_config();
    config.rules = vec![rule(
        "chrome-direct",
        MatchCondition::Process {
            values: vec!["chrome".to_string()],
        },
        "B",
    )];
    let engine = RoutingEngine::new(config.clone());
    let snap = ExplainSnapshot::default();

    // 无进程证据：规则不命中 → default；缺口显式列出
    let out = engine.explain(&snap, &input("example.com")).unwrap();
    assert_eq!(out.matched_by.as_deref(), Some("default"));
    assert_eq!(out.certainty, EgressCertainty::Conditional);
    assert!(out.unknowns.iter().any(|u| u.field == "process.name"));

    // 证据到位：同一推演给出确定命中
    let mut with_process = input("example.com");
    with_process.process = Some(ProcessEvidence {
        name: Some("chrome".to_string()),
        path: None,
    });
    let out = engine.explain(&snap, &with_process).unwrap();
    assert_eq!(out.matched_by.as_deref(), Some("chrome-direct"));
    assert_eq!(out.predicted.unwrap().node.as_deref(), Some("B"));
    assert_eq!(out.certainty, EgressCertainty::Definitive);
    assert!(out.unknowns.is_empty());
    // 摘要区分不同输入
    assert_ne!(out.input_digest, input("example.com").digest());
}

/// GeoIP 证据缺口：数据库未加载 / 域名不解析 DNS——条件按恒不命中
/// 评估，结论条件性（不伪装确定）
#[test]
fn geoip_marks_missing_evidence() {
    let mut config = base_config();
    config.rules = vec![rule(
        "us-egress",
        MatchCondition::Geoip {
            country: "US".to_string(),
        },
        "B",
    )];
    let snap = ExplainSnapshot::default();

    // 域名目标（无数据库——离线形态 geo=None）
    let out = explain_offline(&config, None, &snap, &input("example.com")).unwrap();
    assert_eq!(out.matched_by.as_deref(), Some("default"));
    assert_eq!(out.certainty, EgressCertainty::Conditional);
    assert!(out.unknowns.iter().any(|u| u.field == "geoip.db"));

    // IP 字面量目标：库仍缺席——缺口点名数据库而非 DNS
    let out = explain_offline(&config, None, &snap, &input("1.2.3.4")).unwrap();
    assert_eq!(out.certainty, EgressCertainty::Conditional);
    assert!(out.unknowns.iter().any(|u| u.field == "geoip.db"));
    assert!(
        !out.unknowns.iter().any(|u| u.field == "dns"),
        "IP 目标不产生 DNS 缺口"
    );
}

/// Fixed 组选择面（RIL-011 推演镜像）：无选择 → 首健康；手动点选
/// 不健康成员被尊重（全成员集）；陈旧选择回落 + 显式说明，且只读
/// ——不修改快照
#[test]
fn fixed_group_selection_and_stale_recovery() {
    let snap = snapshot_with(vec![frozen_group(
        "pick",
        "fixed",
        vec![frozen_node("A", true), frozen_node("B", false)],
    )]);
    let mut config = base_config();
    config.default_node = "pick".to_string();
    let engine = RoutingEngine::new(config);
    let inp = input("example.com");

    // 无选择 → 首健康
    let out = engine.explain(&snap, &inp).unwrap();
    assert_eq!(out.predicted.as_ref().unwrap().node.as_deref(), Some("A"));
    assert!(out.predicted.as_ref().unwrap().note.is_none());

    // 手动点选不健康成员——显式点选不被健康门槛二次猜测
    let mut snap_sel = snap.clone();
    snap_sel
        .selections
        .insert("pick".to_string(), "B".to_string());
    let out = engine.explain(&snap_sel, &inp).unwrap();
    assert_eq!(out.predicted.as_ref().unwrap().node.as_deref(), Some("B"));
    assert!(out.predicted.as_ref().unwrap().note.is_none());

    // 陈旧选择 → 回落首健康 + 说明；Explain 只读——快照选择不被清除
    let mut snap_stale = snap;
    snap_stale
        .selections
        .insert("pick".to_string(), "GONE".to_string());
    let out = engine.explain(&snap_stale, &inp).unwrap();
    assert_eq!(out.predicted.as_ref().unwrap().node.as_deref(), Some("A"));
    let note = out.predicted.as_ref().unwrap().note.clone().unwrap();
    assert!(note.contains("回落"), "回落原因显式: {note}");
    assert_eq!(
        snap_stale.selections.get("pick").map(String::as_str),
        Some("GONE"),
        "Explain 无副作用——不修改快照"
    );
}

/// Fallback 策略：首健康成员（不健康跳过，声明序）
#[test]
fn fallback_strategy_skips_unhealthy() {
    let snap = snapshot_with(vec![frozen_group(
        "g",
        "fallback",
        vec![frozen_node("A", false), frozen_node("B", true)],
    )]);
    let mut config = base_config();
    config.default_node = "g".to_string();
    let engine = RoutingEngine::new(config);
    let out = engine.explain(&snap, &input("example.com")).unwrap();
    assert_eq!(out.predicted.unwrap().node.as_deref(), Some("B"));
    assert_eq!(out.certainty, EgressCertainty::Definitive);
}

/// 带冻结质量的 latency 组：门 + 评分与生产同口径（无门最低分；
/// SLO 门把超门 real 成员出局）
fn latency_snapshot(p95_gate: Option<u32>) -> ExplainSnapshot {
    let mut g = frozen_group(
        "lat",
        "latency",
        vec![
            frozen_node("A", true),
            frozen_node("B", true),
            frozen_node("C", true),
        ],
    );
    g.slo = Some(FrozenSlo {
        p95_ms: p95_gate,
        loss_ratio: None,
        loss_penalty_ms: None,
    });
    let mut snap = snapshot_with(vec![g]);
    snap.quality.insert(
        "A".to_string(),
        FrozenQuality {
            p95_ms: 100,
            loss_ratio: 0.0,
        },
    );
    snap.quality.insert(
        "B".to_string(),
        FrozenQuality {
            p95_ms: 200,
            loss_ratio: 0.0,
        },
    );
    snap.quality.insert(
        "C".to_string(),
        FrozenQuality {
            p95_ms: 50,
            loss_ratio: 0.5,
        },
    );
    snap
}

#[test]
fn latency_group_gate_and_pick_with_frozen_quality() {
    let mut config = base_config();
    config.default_node = "lat".to_string();
    let engine = RoutingEngine::new(config);
    let inp = input("example.com");

    // 无门：score = p95 + loss × 1000 → A(100) < B(200) < C(550)
    let out = engine.explain(&latency_snapshot(None), &inp).unwrap();
    assert_eq!(out.predicted.as_ref().unwrap().node.as_deref(), Some("A"));
    assert_eq!(out.certainty, EgressCertainty::Definitive);

    // 门 p95 ≤ 80：A/B（real 源受门）出局，C 过门 → C
    let out = engine.explain(&latency_snapshot(Some(80)), &inp).unwrap();
    assert_eq!(out.predicted.as_ref().unwrap().node.as_deref(), Some("C"));
    assert_eq!(out.certainty, EgressCertainty::Definitive);
}

/// latency 组无质量数据：回落首健康（显式说明 + 证据缺口 → 条件性）
#[test]
fn latency_group_without_quality_data_is_conditional() {
    let snap = snapshot_with(vec![frozen_group(
        "lat",
        "latency",
        vec![frozen_node("A", true), frozen_node("B", true)],
    )]);
    let mut config = base_config();
    config.default_node = "lat".to_string();
    let engine = RoutingEngine::new(config);
    let out = engine.explain(&snap, &input("example.com")).unwrap();

    assert_eq!(
        out.predicted.as_ref().unwrap().node.as_deref(),
        Some("A"),
        "无数据回落首健康（生产同口径）"
    );
    assert!(out
        .predicted
        .as_ref()
        .unwrap()
        .note
        .as_deref()
        .unwrap()
        .contains("回落"));
    assert_eq!(out.certainty, EgressCertainty::Conditional);
    assert!(out.unknowns.iter().any(|u| u.field == "link_quality:lat"));
}

/// 随机/计数策略：只给健康候选池 + NonDeterministic——绝不假装选中
#[test]
fn nondeterministic_strategies_report_pool_only() {
    for strategy in ["random", "weighted", "round_robin"] {
        let snap = snapshot_with(vec![frozen_group(
            "g",
            strategy,
            vec![
                frozen_node("A", true),
                frozen_node("B", true),
                frozen_node("C", false),
            ],
        )]);
        let mut config = base_config();
        config.default_node = "g".to_string();
        let engine = RoutingEngine::new(config);
        let out = engine.explain(&snap, &input("example.com")).unwrap();

        let pred = out.predicted.as_ref().unwrap();
        assert_eq!(pred.node, None, "{strategy}: 不假装选中");
        assert_eq!(
            pred.member_pool,
            vec!["A".to_string(), "B".to_string()],
            "{strategy}: 候选池 = 健康集（声明序）"
        );
        assert!(pred.unavailable_reason.is_none());
        assert_eq!(out.certainty, EgressCertainty::NonDeterministic);
        assert!(
            pred.note.as_deref().unwrap().contains(strategy),
            "原因点名策略"
        );
    }
}

/// 一致性哈希：确定性可重放（同输入同节点），节点必在健康候选内
#[test]
fn consistent_hash_is_replayable() {
    let snap = snapshot_with(vec![frozen_group(
        "g",
        "consistent_hash",
        vec![
            frozen_node("A", true),
            frozen_node("B", true),
            frozen_node("C", true),
        ],
    )]);
    let mut config = base_config();
    config.default_node = "g".to_string();
    let engine = RoutingEngine::new(config);
    let inp = input("www.example.com");

    let out1 = engine.explain(&snap, &inp).unwrap();
    let out2 = engine.explain(&snap, &inp).unwrap();
    let node1 = out1.predicted.as_ref().unwrap().node.clone().unwrap();
    assert_eq!(
        node1,
        out2.predicted.as_ref().unwrap().node.as_deref().unwrap(),
        "同快照同输入必得同节点（纯函数）"
    );
    assert!(["A", "B", "C"].contains(&node1.as_str()));
    assert_eq!(out1.certainty, EgressCertainty::Definitive);

    // 哈希键 = 目标主机（生产同键）：不同 host 落在候选内
    let other = engine
        .explain(&snap, &input("other.org"))
        .unwrap()
        .predicted
        .unwrap()
        .node
        .unwrap();
    assert!(["A", "B", "C"].contains(&other.as_str()));
}

/// 离线重放：同一 (config, snapshot, input) 序列化往返后经
/// `explain_offline` 重放，结论逐字段一致
#[test]
fn deterministic_replay_roundtrip() {
    let mut config = base_config();
    config.rules = vec![rule(
        "by-domain",
        MatchCondition::DomainSuffix {
            values: vec!["example.com".to_string()],
        },
        "pick",
    )];
    let snap = snapshot_with(vec![frozen_group(
        "pick",
        "consistent_hash",
        vec![frozen_node("A", true), frozen_node("B", true)],
    )]);
    let inp = input("www.example.com");

    let engine = RoutingEngine::new(config.clone());
    let first = engine.explain(&snap, &inp).unwrap();
    let second = engine.explain(&snap, &inp).unwrap();
    assert_eq!(first, second, "同三元组必得同一结论");

    let snap_json = serde_json::to_string(&snap).unwrap();
    let inp_json = serde_json::to_string(&inp).unwrap();
    let snap2: ExplainSnapshot = serde_json::from_str(&snap_json).unwrap();
    let inp2: ExplainInput = serde_json::from_str(&inp_json).unwrap();
    let replayed = explain_offline(&config, None, &snap2, &inp2).unwrap();
    assert_eq!(replayed, first, "序列化往返后离线重放一致");
    assert_eq!(replayed.certainty, EgressCertainty::Definitive);
    assert!(replayed.predicted.unwrap().node.is_some());
}

/// 嵌套组：组链外→内逐级记录，终至节点
#[test]
fn nested_group_chain_is_traced() {
    let inner = frozen_group(
        "inner",
        "fallback",
        vec![frozen_node("X", true), frozen_node("Y", true)],
    );
    let outer = FrozenGroup {
        name: "outer".to_string(),
        strategy: "fallback".to_string(),
        slo: None,
        members: vec![FrozenMember::Group {
            name: "inner".to_string(),
            weight: 1,
            group: Box::new(inner),
        }],
    };
    let snap = snapshot_with(vec![outer]);
    let mut config = base_config();
    config.default_node = "outer".to_string();
    let engine = RoutingEngine::new(config);

    let out = engine.explain(&snap, &input("example.com")).unwrap();
    let pred = out.predicted.unwrap();
    assert_eq!(pred.node.as_deref(), Some("X"));
    assert_eq!(pred.group.as_deref(), Some("outer"), "group = 最外层命中组");
    assert_eq!(
        pred.group_chain,
        vec!["outer".to_string(), "inner".to_string()],
        "组链外→内"
    );
    assert_eq!(out.certainty, EgressCertainty::Definitive);
}

/// 引擎冻结：健康位/质量/带宽/选择在冻结时刻烙定，推演在冻结态重放
#[test]
fn engine_freeze_freezes_group_state() {
    let mut config = base_config();
    config.groups = vec![PolicyGroup {
        name: "g".to_string(),
        strategy: Strategy::Fallback,
        members: vec![
            GroupMember::Node {
                name: "A".to_string(),
            },
            GroupMember::Node {
                name: "B".to_string(),
            },
        ],
        slo: None,
        url_test: None,
    }];
    config.selections.insert("g".to_string(), "B".to_string());
    config.default_node = "g".to_string();
    let engine = RoutingEngine::new(config);
    engine.set_node_health("A", false);
    engine.update_link_quality("B", 42, 0.01);
    engine.update_bandwidth_stats("B", 9000);

    let snap = engine.freeze_explain_snapshot();
    let g = snap.groups.get("g").unwrap();
    assert_eq!(g.strategy, "fallback", "策略机器口径");
    assert_eq!(
        g.members[0],
        FrozenMember::Node {
            name: "A".to_string(),
            weight: 1,
            healthy: false
        },
        "健康位烙定"
    );
    assert_eq!(snap.quality.get("B").unwrap().p95_ms, 42);
    assert_eq!(snap.bandwidth.get("B"), Some(&9000));
    assert_eq!(snap.selections.get("g").map(String::as_str), Some("B"));

    // 冻结态推演：A 已摘除 → fallback 首健康 = B
    let out = engine.explain(&snap, &input("example.com")).unwrap();
    assert_eq!(out.predicted.unwrap().node.as_deref(), Some("B"));
    assert_eq!(out.certainty, EgressCertainty::Definitive);
}

// ---------- RIL-140 选路模式：推演镜像模式入口 ----------

/// 全局模式：推演短路场景/规则面——求值序为空（不得宣称普通规则
/// 「正在生效」）、matched_by 带 mode:global、预测走显式全局出口。
#[test]
fn global_mode_explain_skips_rules_and_scenarios() {
    let mut config = base_config();
    config.mode = rillane_config::SelectionMode::Global;
    config.global_node = Some("GLOBAL-GW".to_string());
    config.scenarios = vec![ScenarioRule {
        name: "catch-all".to_string(),
        conditions: vec![],
        target: "S".to_string(),
        priority: 10,
        on_failure: ScenarioFailureAction::Fallback,
    }];
    config.rules = vec![rule(
        "hit",
        MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        },
        "B",
    )];
    let engine = RoutingEngine::new(config);
    let snap = ExplainSnapshot::default();
    let out = engine.explain(&snap, &input("example.com")).unwrap();

    assert_eq!(out.matched_by.as_deref(), Some("mode:global"));
    assert!(
        out.evaluated.is_empty(),
        "普通场景/规则面暂停——推演不得宣称正在生效: {:?}",
        out.evaluated
    );
    assert_eq!(
        out.predicted.as_ref().unwrap().node.as_deref(),
        Some("GLOBAL-GW")
    );
    assert_eq!(out.certainty, EgressCertainty::Definitive);
}

/// 直连模式：推演走显式直连出口，matched_by 带 mode:direct。
#[test]
fn direct_mode_explain_uses_explicit_direct_node() {
    let mut config = base_config();
    config.mode = rillane_config::SelectionMode::Direct;
    config.direct_node = Some("direct-main".to_string());
    config.rules = vec![rule(
        "hit",
        MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        },
        "B",
    )];
    let engine = RoutingEngine::new(config);
    let snap = ExplainSnapshot::default();
    let out = engine.explain(&snap, &input("example.com")).unwrap();

    assert_eq!(out.matched_by.as_deref(), Some("mode:direct"));
    assert!(out.evaluated.is_empty());
    assert_eq!(
        out.predicted.as_ref().unwrap().node.as_deref(),
        Some("direct-main")
    );
}

/// 模式出口缺席：推演给确定性失败（生产面同路径上抛），不静默落
/// 规则面/默认节点。
#[test]
fn mode_explain_missing_target_is_definitive_error() {
    let mut config = base_config();
    config.mode = rillane_config::SelectionMode::Global;
    config.rules = vec![rule(
        "hit",
        MatchCondition::DomainFull {
            values: vec!["example.com".to_string()],
        },
        "B",
    )];
    let engine = RoutingEngine::new(config);
    let snap = ExplainSnapshot::default();
    let out = engine.explain(&snap, &input("example.com")).unwrap();

    assert_eq!(out.matched_by.as_deref(), Some("mode:global"));
    let err = out.error.expect("缺模式出口须确定性失败");
    assert!(
        err.contains("global_node"),
        "错误须点名 routing.global_node: {err}"
    );
    assert_eq!(out.certainty, EgressCertainty::Definitive);
    assert!(out.predicted.is_none());
}
