use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use rillane_config::{
    GroupMember, MatchCondition, PolicyGroup, RouteRule, RoutingConfig, SelectionMode, Strategy,
};
use rillane_core::{FlowContext, FlowId, FlowMetadata, FlowRouter, FlowTarget, TargetProto};
use rillane_routing::RoutingEngine;
use tokio::time::Duration;

fn create_test_config() -> RoutingConfig {
    RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: Vec::new(),
        groups: vec![
            PolicyGroup {
                name: "primary-group".to_string(),
                strategy: Strategy::RoundRobin,
                members: vec![
                    GroupMember::Node {
                        name: "node1".to_string(),
                    },
                    GroupMember::Node {
                        name: "node2".to_string(),
                    },
                    GroupMember::WeightedNode {
                        name: "node3".to_string(),
                        weight: 3,
                    },
                ],
                slo: None,
                url_test: None,
            },
            PolicyGroup {
                name: "latency-group".to_string(),
                strategy: Strategy::Latency,
                members: vec![
                    GroupMember::Node {
                        name: "node1".to_string(),
                    },
                    GroupMember::Node {
                        name: "node2".to_string(),
                    },
                ],
                slo: None,
                url_test: None,
            },
            PolicyGroup {
                name: "bandwidth-group".to_string(),
                strategy: Strategy::Bandwidth,
                members: vec![
                    GroupMember::Node {
                        name: "node1".to_string(),
                    },
                    GroupMember::Node {
                        name: "node2".to_string(),
                    },
                ],
                slo: None,
                url_test: None,
            },
            PolicyGroup {
                name: "hash-group".to_string(),
                strategy: Strategy::ConsistentHash,
                members: vec![
                    GroupMember::Node {
                        name: "node1".to_string(),
                    },
                    GroupMember::Node {
                        name: "node2".to_string(),
                    },
                    GroupMember::Node {
                        name: "node3".to_string(),
                    },
                ],
                slo: None,
                url_test: None,
            },
            PolicyGroup {
                name: "random-group".to_string(),
                strategy: Strategy::Random,
                members: vec![
                    GroupMember::Node {
                        name: "node1".to_string(),
                    },
                    GroupMember::Node {
                        name: "node2".to_string(),
                    },
                ],
                slo: None,
                url_test: None,
            },
        ],
        rules: vec![
            RouteRule {
                name: "google-rule".to_string(),
                matches: vec![MatchCondition::DomainSuffix {
                    values: vec!["google.com".to_string(), "gmail.com".to_string()],
                }],
                target: "primary-group".to_string(),
            },
            RouteRule {
                name: "latency-rule".to_string(),
                matches: vec![MatchCondition::DomainKeyword {
                    values: vec!["api".to_string()],
                }],
                target: "latency-group".to_string(),
            },
            RouteRule {
                name: "bandwidth-rule".to_string(),
                matches: vec![MatchCondition::Port {
                    values: vec![8080, 8443],
                }],
                target: "bandwidth-group".to_string(),
            },
            RouteRule {
                name: "hash-rule".to_string(),
                matches: vec![MatchCondition::DomainKeyword {
                    values: vec!["cdn".to_string()],
                }],
                target: "hash-group".to_string(),
            },
        ],
        ..Default::default()
    }
}

fn create_flow_context(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        metadata: FlowMetadata::default(),
    }
}

#[tokio::test]
async fn test_direct_routing() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    let ctx = create_flow_context("example.com", 80);
    let decision = engine.route(ctx).await?;

    assert_eq!(decision.final_node(), "direct-node");
    assert!(decision.reason.is_some());

    Ok(())
}

#[tokio::test]
async fn test_domain_suffix_routing() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    let ctx = create_flow_context("mail.google.com", 443);
    let decision = engine.route(ctx).await?;

    assert!(decision.final_node().starts_with("node"));
    assert_eq!(decision.reason, Some("google-rule".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_round_robin_routing() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    let mut node_counts = HashMap::new();

    // 执行多次路由，测试轮询
    for _ in 0..12 {
        let ctx = create_flow_context("google.com", 443);
        let decision = engine.route(ctx).await?;
        let node = decision.final_node();
        *node_counts.entry(node).or_insert(0) += 1;
    }

    // 验证轮询分配（node3权重为3，应该出现3次）
    assert!(node_counts.contains_key("node1"));
    assert!(node_counts.contains_key("node2"));
    assert!(node_counts.contains_key("node3"));

    Ok(())
}

#[tokio::test]
async fn test_consistent_hash_routing() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    // 相同的host应该路由到相同的节点
    let host = "cdn.example.com";
    let mut selected_nodes = Vec::new();

    for _ in 0..5 {
        let ctx = create_flow_context(host, 443);
        let decision = engine.route(ctx).await?;
        selected_nodes.push(decision.final_node());
    }

    // 验证一致性哈希：相同host应该总是路由到相同节点
    let first_node = &selected_nodes[0];
    for node in &selected_nodes[1..] {
        assert_eq!(node, first_node);
    }

    // 不同host可能路由到不同节点
    let ctx2 = create_flow_context("cdn2.example.com", 443);
    let decision2 = engine.route(ctx2).await?;
    let node2 = decision2.final_node();

    // 不一定不同，但验证哈希在工作
    assert!(node2.starts_with("node"));

    Ok(())
}

#[tokio::test]
async fn test_random_routing() -> Result<()> {
    let mut config = create_test_config();

    // 添加规则使用随机组
    config.rules.push(RouteRule {
        name: "random-rule".to_string(),
        matches: vec![MatchCondition::DomainKeyword {
            values: vec!["random".to_string()],
        }],
        target: "random-group".to_string(),
    });

    let engine = RoutingEngine::new(config);

    let mut selected_nodes = Vec::new();

    // 执行多次路由
    for _ in 0..100 {
        let ctx = create_flow_context("random.example.com", 443);
        let decision = engine.route(ctx).await?;
        selected_nodes.push(decision.final_node());
    }

    // 验证随机性（应该有不同的节点）
    let unique_nodes: std::collections::HashSet<_> = selected_nodes.iter().collect();
    assert!(unique_nodes.len() > 1);

    Ok(())
}

#[tokio::test]
async fn test_bandwidth_routing() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    // 更新带宽统计
    engine.update_bandwidth_stats("node1", 1000); // 1Mbps
    engine.update_bandwidth_stats("node2", 2000); // 2Mbps

    // 直接使用带宽组名进行测试
    let direct_ctx = create_flow_context("bandwidth-test.example.com", 443);
    // 手动创建一个流量上下文来测试带宽组选择

    // 创建一个新的配置，默认节点指向带宽组
    let mut bandwidth_config = create_test_config();
    bandwidth_config.default_node = "bandwidth-group".to_string();

    let bandwidth_engine = RoutingEngine::new(bandwidth_config);
    bandwidth_engine.update_bandwidth_stats("node1", 1000); // 1Mbps
    bandwidth_engine.update_bandwidth_stats("node2", 2000); // 2Mbps

    let decision = bandwidth_engine.route(direct_ctx).await?;

    // 应该选择带宽更高的node2
    assert_eq!(decision.final_node(), "node2");

    Ok(())
}

#[tokio::test]
async fn test_group_nesting() -> Result<()> {
    let mut config = create_test_config();

    // 添加嵌套组
    config.groups.push(PolicyGroup {
        name: "nested-group".to_string(),
        strategy: Strategy::Fixed,
        members: vec![
            GroupMember::Group {
                name: "primary-group".to_string(),
            },
            GroupMember::Node {
                name: "node4".to_string(),
            },
        ],
        slo: None,
        url_test: None,
    });

    // 添加规则使用嵌套组
    config.rules.push(RouteRule {
        name: "nested-rule".to_string(),
        matches: vec![MatchCondition::DomainKeyword {
            values: vec!["nested".to_string()],
        }],
        target: "nested-group".to_string(),
    });

    let engine = RoutingEngine::new(config);

    let ctx = create_flow_context("nested.example.com", 443);
    let decision = engine.route(ctx).await?;

    assert!(decision.final_node().starts_with("node"));

    Ok(())
}

/// G1-9 重写：健康数据唯一来源是注入的探测句柄；未注入 = no-op 不产数据
///（旧随机 mock 已删——随机假数据比无数据更害选路）。url_test 组配置探测
/// 目标/间隔/超时；断言面：健康表、延迟表、组过滤、间隔门控。
fn urltest_group_config() -> RoutingConfig {
    let mut config = create_test_config();
    config.groups = vec![PolicyGroup {
        name: "auto".to_string(),
        strategy: Strategy::Latency,
        members: vec![
            GroupMember::Node {
                name: "node1".to_string(),
            },
            GroupMember::Node {
                name: "node2".to_string(),
            },
        ],
        slo: None,
        url_test: Some(rillane_config::UrlTestConfig {
            probe: "127.0.0.1:9".to_string(),
            path: "/generate_204".to_string(),
            interval_secs: 3600,
            timeout_ms: 1000,
        }),
    }];
    config
}

#[tokio::test]
async fn test_health_check_integration() -> Result<()> {
    // 前半：无 url_test 组且未注入句柄——no-op 不产数据
    let plain = RoutingEngine::new(create_test_config());
    plain.perform_health_checks().await;
    assert_eq!(plain.get_health_stats(), (0, 0));

    // 后半：url_test 组 + 假句柄（node1 健康 42ms，其余 Err）——确定性断言
    let engine = RoutingEngine::new(urltest_group_config());
    engine.set_probe_handler(Arc::new(
        |node: &str, _host: &str, _port: u16, _path: &str, _timeout: Duration| {
            // 先落 own 再进 async 块：future 与入参引用生命周期解耦
            let node = node.to_string();
            Box::pin(async move {
                if node == "node1" {
                    Ok(42u64)
                } else {
                    Err(format!("{node} probe failed"))
                }
            }) as Pin<Box<dyn Future<Output = Result<u64, String>> + Send>>
        },
    ));
    engine.perform_health_checks().await;

    let (healthy, total) = engine.get_health_stats();
    assert_eq!(total, 2, "仅 url_test 组成员入健康表");
    assert_eq!(healthy, 1, "node1 健康、node2 不健康");
    assert_eq!(engine.get_node_latency("node1"), Some(42));
    assert_eq!(engine.get_node_latency("node2"), None, "探测失败不产延迟值");

    Ok(())
}

#[tokio::test]
async fn test_urltest_probe_interval_gating_and_group_filter() -> Result<()> {
    let mut config = urltest_group_config();
    // 追加无 url_test 的组：其成员绝不入探测
    config.groups.push(PolicyGroup {
        name: "plain".to_string(),
        strategy: Strategy::RoundRobin,
        members: vec![GroupMember::Node {
            name: "node3".to_string(),
        }],
        slo: None,
        url_test: None,
    });

    let engine = RoutingEngine::new(config);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_in_handler = Arc::clone(&calls);
    engine.set_probe_handler(Arc::new(
        move |_node: &str, _host: &str, _port: u16, _path: &str, _timeout: Duration| {
            calls_in_handler.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(10u64) })
                as Pin<Box<dyn Future<Output = Result<u64, String>> + Send>>
        },
    ));

    // 第一轮：url_test 组 2 成员各探测一次；plain 组不入探测不入健康表
    engine.perform_health_checks().await;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(engine.get_health_stats().1, 2, "plain 组成员不入健康表");

    // 第二轮：interval_secs=3600 未到期，整组跳过
    engine.perform_health_checks().await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "间隔未到期不得重复探测"
    );

    Ok(())
}

#[tokio::test]
async fn test_config_reload() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    // 验证初始配置
    let ctx = create_flow_context("google.com", 443);
    let decision = engine.route(ctx).await?;
    assert!(decision.final_node().starts_with("node"));

    // 重新加载配置
    let mut new_config = create_test_config();
    new_config.default_node = "new-default-node".to_string();
    engine.reload(new_config);

    // 验证配置已更新
    let ctx = create_flow_context("other.com", 443);
    let decision = engine.route(ctx).await?;
    assert_eq!(decision.final_node(), "new-default-node");

    Ok(())
}

// ---------- RIL-009：provider 成员按节点库展开 ----------

fn provider_group_config(provider_nodes: Vec<String>) -> RoutingConfig {
    let mut config = RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: Vec::new(),
        groups: vec![PolicyGroup {
            name: "provider-group".to_string(),
            strategy: Strategy::Fixed,
            members: vec![
                GroupMember::Node {
                    name: "node1".to_string(),
                },
                GroupMember::Provider {
                    name: "remote".to_string(),
                },
            ],
            slo: None,
            url_test: None,
        }],
        rules: vec![],
        ..RoutingConfig::default()
    };
    if !provider_nodes.is_empty() {
        config.provider_nodes.insert("remote", provider_nodes);
    }
    config
}

/// RIL-009：provider 成员展开为 provider 节点库当前提供的节点集，
/// 与静态节点成员并列进组。库未装入 = 空集——失效成员退出新流候选，
/// 组不因此伪装出成员（与 RuleSetRef 缺库恒不命中同语义）。
#[test]
fn provider_member_expands_from_provider_node_library() {
    // 库已装入：静态节点 + provider 展开的节点集都在观测面
    let engine = RoutingEngine::new(provider_group_config(vec![
        "remote-a".into(),
        "remote-b".into(),
    ]));
    let report = engine.group_quality_report();
    let members: Vec<String> = report
        .iter()
        .find(|g| g.name == "provider-group")
        .expect("provider 组应解析出描述符")
        .members
        .iter()
        .map(|m| m.name.clone())
        .collect();
    assert_eq!(members, vec!["node1", "remote-a", "remote-b"]);

    // 库未装入：provider 展开空集，仅静态成员存活
    let empty = RoutingEngine::new(provider_group_config(Vec::new()));
    let members: Vec<String> = empty
        .group_quality_report()
        .iter()
        .find(|g| g.name == "provider-group")
        .expect("仅静态成员的组仍应解析出描述符")
        .members
        .iter()
        .map(|m| m.name.clone())
        .collect();
    assert_eq!(members, vec!["node1"], "provider 空集不得伪装出成员");

    // 全 provider 组 + 库未装入：组仍存在但成员集为空 = 退出新流候选。
    // 组不因此消失（配置事实），但不得伪装出成员（求值面对该组无候选可给）
    let only_provider = RoutingEngine::new(RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: Vec::new(),
        groups: vec![PolicyGroup {
            name: "only-provider".to_string(),
            strategy: Strategy::Fixed,
            members: vec![GroupMember::Provider {
                name: "remote".to_string(),
            }],
            slo: None,
            url_test: None,
        }],
        ..RoutingConfig::default()
    });
    let report = only_provider.group_quality_report();
    let only = report
        .iter()
        .find(|g| g.name == "only-provider")
        .expect("组仍在配置中，不应从观测面消失");
    assert!(only.members.is_empty(), "provider 空集不得伪装出成员");
}

// ---------- RIL-011：select 选择保真 ----------

fn fixed_pick_group(members: Vec<GroupMember>) -> RoutingConfig {
    let config = RoutingConfig {
        default_node: "pick".to_string(),
        scenarios: Vec::new(),
        groups: vec![PolicyGroup {
            name: "pick".to_string(),
            strategy: Strategy::Fixed,
            members,
            slo: None,
            url_test: None,
        }],
        rules: vec![],
        ..RoutingConfig::default()
    };
    // 健康态默认全真（get_node_health 缺数据 = 健康）
    config
}

/// RIL-011：`Strategy::Fixed` 尊重用户选择——selections 命中组成员时
/// 按所选成员出流（而非首成员）。
#[tokio::test]
async fn select_honors_user_selection() -> Result<()> {
    let mut config = fixed_pick_group(vec![
        GroupMember::Node {
            name: "node1".into(),
        },
        GroupMember::Node {
            name: "node2".into(),
        },
    ]);
    config
        .selections
        .insert("pick".to_string(), "node2".to_string());
    let engine = RoutingEngine::new(config);

    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(
        decision.final_node(),
        "node2",
        "用户选择 node2 优先于首成员 node1"
    );
    Ok(())
}

/// RIL-012：`Strategy::Fallback` 按声明序取首个健康成员——故障优先级
/// 符合样本：首位下线顺延次位，再下线顺延第三位；恢复后回到首位。
/// 健康态经 `set_node_health` 注入，可核验、无随机性。
#[tokio::test]
async fn fallback_follows_declaration_order() -> Result<()> {
    let config = RoutingConfig {
        default_node: "fb".to_string(),
        scenarios: Vec::new(),
        groups: vec![PolicyGroup {
            name: "fb".to_string(),
            strategy: Strategy::Fallback,
            members: vec![
                GroupMember::Node { name: "n1".into() },
                GroupMember::Node { name: "n2".into() },
                GroupMember::Node { name: "n3".into() },
            ],
            slo: None,
            url_test: None,
        }],
        rules: vec![],
        ..RoutingConfig::default()
    };
    let engine = RoutingEngine::new(config);

    // 全健康 → 首位 n1（重复路由同答案，无随机替代）
    for _ in 0..3 {
        let decision = engine.route(create_flow_context("example.com", 80)).await?;
        assert_eq!(decision.final_node(), "n1", "全健康恒取首位");
    }

    // 首位下线 → 顺延次位 n2
    engine.set_node_health("n1", false);
    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(decision.final_node(), "n2", "首位下线须顺延次位");

    // 前两位下线 → 顺延第三位 n3
    engine.set_node_health("n2", false);
    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(decision.final_node(), "n3", "前两位下线须顺延第三位");

    // 首位恢复 → 回到首位（按序回退，不是随机换点）
    engine.set_node_health("n1", true);
    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(decision.final_node(), "n1", "首位恢复即回首位");

    // 次位也恢复但首位仍健康 → 保持首位
    engine.set_node_health("n2", true);
    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(decision.final_node(), "n1", "次位恢复不夺位");
    Ok(())
}

/// RIL-012：fallback 全员不健康 → 显式报错（不伪装随机选点）。
#[tokio::test]
async fn fallback_all_unhealthy_errors() -> Result<()> {
    let config = RoutingConfig {
        default_node: "fb".to_string(),
        scenarios: Vec::new(),
        groups: vec![PolicyGroup {
            name: "fb".to_string(),
            strategy: Strategy::Fallback,
            members: vec![
                GroupMember::Node { name: "n1".into() },
                GroupMember::Node { name: "n2".into() },
            ],
            slo: None,
            url_test: None,
        }],
        rules: vec![],
        ..RoutingConfig::default()
    };
    let engine = RoutingEngine::new(config);
    engine.set_node_health("n1", false);
    engine.set_node_health("n2", false);
    let err = engine
        .route(create_flow_context("example.com", 80))
        .await
        .expect_err("全员不健康须报错");
    assert!(
        err.to_string().contains("无健康成员"),
        "报错须点名无健康成员，实际: {err}"
    );
    Ok(())
}

/// RIL-011：所选成员不健康时仍尊重手动点选（显式意图不被健康门槛
/// 二次猜测，与 Clash select 语义一致）。
#[tokio::test]
async fn select_honors_selection_even_if_unhealthy() -> Result<()> {
    let mut config = fixed_pick_group(vec![
        GroupMember::Node {
            name: "node1".into(),
        },
        GroupMember::Node {
            name: "node2".into(),
        },
    ]);
    config
        .selections
        .insert("pick".to_string(), "node2".to_string());
    let engine = RoutingEngine::new(config);
    engine.set_node_health("node2", false);

    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(
        decision.final_node(),
        "node2",
        "不健康的手动点选仍生效（用户显式选择）"
    );
    Ok(())
}

/// RIL-011：所选成员已被更新/删除移除 → 明确恢复策略：回落首健康成员、
/// 决策原因点名恢复、引擎内陈旧选择被清除（不反复报告）。
#[tokio::test]
async fn stale_selection_recovers_to_first_member() -> Result<()> {
    let mut config = fixed_pick_group(vec![
        GroupMember::Node {
            name: "node1".into(),
        },
        GroupMember::Node {
            name: "node2".into(),
        },
    ]);
    config
        .selections
        .insert("pick".to_string(), "node-gone".to_string());
    let engine = RoutingEngine::new(config);

    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(decision.final_node(), "node1", "陈旧选择回落首健康成员");
    let reason = decision.reason.unwrap_or_default();
    assert!(
        reason.contains("node-gone") && reason.contains("回落"),
        "恢复原因须点名所选成员与回落: {reason}"
    );

    // 陈旧选择已清除：二次路由不再重复报告
    let decision2 = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(decision2.final_node(), "node1");
    assert!(
        !decision2
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("回落"),
        "清除后不得重复报告恢复: {:?}",
        decision2.reason
    );
    Ok(())
}

/// RIL-011：更新不随意清空有效选择——新配置未携带 selections 时，
/// reload 保留旧选择（组仍声明且成员仍在 → 依旧生效）。
#[tokio::test]
async fn reload_preserves_valid_selections() -> Result<()> {
    let mut config = fixed_pick_group(vec![
        GroupMember::Node {
            name: "node1".into(),
        },
        GroupMember::Node {
            name: "node2".into(),
        },
    ]);
    config
        .selections
        .insert("pick".to_string(), "node2".to_string());
    let engine = RoutingEngine::new(config);

    // 更新：同组结构但新配置未带选择面（订阅刷新重写配置的现实形态）
    let updated = fixed_pick_group(vec![
        GroupMember::Node {
            name: "node1".into(),
        },
        GroupMember::Node {
            name: "node2".into(),
        },
    ]);
    engine.reload(updated);

    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(
        decision.final_node(),
        "node2",
        "更新后有效选择不得被随意清空"
    );
    Ok(())
}

// ===== RIL-021 并列场景求值 =====

use rillane_config::{ScenarioFailureAction, ScenarioRule};

fn one_node_group(name: &str, node: &str) -> PolicyGroup {
    PolicyGroup {
        name: name.to_string(),
        strategy: Strategy::RoundRobin,
        members: vec![GroupMember::Node {
            name: node.to_string(),
        }],
        slo: None,
        url_test: None,
    }
}

fn scenario(
    name: &str,
    conditions: Vec<MatchCondition>,
    target: &str,
    priority: i64,
    on_failure: ScenarioFailureAction,
) -> ScenarioRule {
    ScenarioRule {
        name: name.to_string(),
        conditions,
        target: target.to_string(),
        priority,
        on_failure,
    }
}

fn ctx_with_process(
    host: &str,
    port: u16,
    proto: TargetProto,
    process: Option<&str>,
) -> FlowContext {
    let mut ctx = create_flow_context(host, port);
    ctx.target.proto = proto;
    if let Some(p) = process {
        ctx.metadata
            .annotations
            .insert("process.name".to_string(), p.to_string());
    }
    ctx
}

/// 验收①：同目标（同 host:port）的不同本机应用可选不同组——场景面按
/// 进程注解分流，先于泛化规则。
#[tokio::test]
async fn scenario_same_target_different_apps_pick_different_groups() -> Result<()> {
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: vec![
            scenario(
                "game-scene",
                vec![MatchCondition::Process {
                    values: vec!["cs2".to_string()],
                }],
                "game-exit",
                10,
                ScenarioFailureAction::Fallback,
            ),
            scenario(
                "web-scene",
                vec![MatchCondition::Process {
                    values: vec!["firefox".to_string()],
                }],
                "web-exit",
                10,
                ScenarioFailureAction::Fallback,
            ),
        ],
        groups: vec![
            one_node_group("game-exit", "game-node"),
            one_node_group("web-exit", "web-node"),
        ],
        rules: vec![],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);

    let game = engine
        .route(ctx_with_process(
            "match.example.com",
            27015,
            TargetProto::Udp,
            Some("cs2"),
        ))
        .await?;
    assert_eq!(game.final_node(), "game-node");
    assert_eq!(game.reason.as_deref(), Some("scenario:game-scene"));

    let web = engine
        .route(ctx_with_process(
            "match.example.com",
            27015,
            TargetProto::Tcp,
            Some("firefox"),
        ))
        .await?;
    assert_eq!(web.final_node(), "web-node");
    assert_eq!(web.reason.as_deref(), Some("scenario:web-scene"));

    Ok(())
}

/// 验收②：浏览器 QUIC 不因 UDP 承载被归入游戏——场景 Proto 条件
/// quic ≠ udp（与规则面同一非折叠语义），QUIC 流落规则面默认路由。
#[tokio::test]
async fn browser_quic_flow_not_caught_by_udp_game_scenario() -> Result<()> {
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: vec![scenario(
            "game-scene",
            vec![MatchCondition::Proto {
                protocols: vec!["udp".to_string()],
            }],
            "game-exit",
            10,
            ScenarioFailureAction::Fallback,
        )],
        groups: vec![one_node_group("game-exit", "game-node")],
        rules: vec![],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);

    // 真 UDP 游戏流命中场景
    let udp = engine
        .route(ctx_with_process(
            "relay.example.com",
            27015,
            TargetProto::Udp,
            None,
        ))
        .await?;
    assert_eq!(udp.final_node(), "game-node");
    assert_eq!(udp.reason.as_deref(), Some("scenario:game-scene"));

    // QUIC 流：不入 udp 场景，落默认路由
    let quic = engine
        .route(ctx_with_process(
            "http3.example.com",
            443,
            TargetProto::Quic,
            Some("firefox"),
        ))
        .await?;
    assert_eq!(quic.final_node(), "direct-node");
    assert_ne!(
        quic.reason.as_deref(),
        Some("scenario:game-scene"),
        "QUIC 不得因 UDP 承载被归入游戏场景"
    );

    Ok(())
}

/// 失败动作：目标组无健康成员时 fallback = warn 落回规则面（规则面
/// 接管，决策不带场景原因）；reject = 显式上抛并点名场景与目标。
#[tokio::test]
async fn scenario_on_failure_fallback_falls_to_rules_reject_errors() -> Result<()> {
    let build = |on_failure: ScenarioFailureAction| RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: vec![scenario(
            "game-scene",
            vec![MatchCondition::DomainSuffix {
                values: vec!["play.example.com".to_string()],
            }],
            "dead-group",
            10,
            on_failure,
        )],
        groups: vec![
            one_node_group("dead-group", "dead-node"),
            one_node_group("primary-group", "primary-node"),
        ],
        rules: vec![RouteRule {
            name: "catch".to_string(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["play.example.com".to_string()],
            }],
            target: "primary-group".to_string(),
        }],
        ..Default::default()
    };

    // fallback：dead-group 无健康成员 → 落回规则面，catch 规则接管
    let engine = RoutingEngine::new(build(ScenarioFailureAction::Fallback));
    engine.set_node_health("dead-node", false);
    let ctx = create_flow_context("play.example.com", 443);
    let decision = engine.route(ctx).await?;
    assert_eq!(
        decision.final_node(),
        "primary-node",
        "fallback 应由规则面接管"
    );
    assert_eq!(
        decision.reason.as_deref(),
        Some("catch"),
        "决策原因应为规则名（非场景）"
    );

    // reject：同名失配场景显式报错，含场景名与目标
    let engine = RoutingEngine::new(build(ScenarioFailureAction::Reject));
    engine.set_node_health("dead-node", false);
    let ctx = create_flow_context("play.example.com", 443);
    let err = engine.route(ctx).await.expect_err("reject 应显式上抛");
    let msg = format!("{err:#}");
    assert!(msg.contains("game-scene"), "错误应点名场景: {msg}");
    assert!(msg.contains("dead-group"), "错误应点名目标: {msg}");

    Ok(())
}

/// 优先级：数值小者先评估（与声明序无关）；同优先级保持声明序，
/// 先声明的兜底场景先吃掉流量。
#[tokio::test]
async fn scenario_priority_ascending_and_tie_keeps_declaration_order() -> Result<()> {
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: vec![
            scenario(
                "late-high",
                Vec::new(),
                "late-exit",
                200,
                ScenarioFailureAction::Fallback,
            ),
            scenario(
                "early-low",
                Vec::new(),
                "early-exit",
                10,
                ScenarioFailureAction::Fallback,
            ),
            scenario(
                "tie-first",
                Vec::new(),
                "tie-exit",
                10,
                ScenarioFailureAction::Fallback,
            ),
        ],
        groups: vec![
            one_node_group("late-exit", "late-node"),
            one_node_group("early-exit", "early-node"),
            one_node_group("tie-exit", "tie-node"),
        ],
        rules: vec![],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);

    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(
        decision.reason.as_deref(),
        Some("scenario:early-low"),
        "优先级数值小者先评估（200 的兜底场景不得抢先）"
    );
    assert_eq!(decision.final_node(), "early-node");

    // 同优先级：仅 tie-first 生效（声明序第一），命中即返回
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        scenarios: vec![
            scenario(
                "tie-a",
                Vec::new(),
                "exit-a",
                100,
                ScenarioFailureAction::Fallback,
            ),
            scenario(
                "tie-b",
                Vec::new(),
                "exit-b",
                100,
                ScenarioFailureAction::Fallback,
            ),
        ],
        groups: vec![
            one_node_group("exit-a", "node-a"),
            one_node_group("exit-b", "node-b"),
        ],
        rules: vec![],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);
    let decision = engine.route(create_flow_context("example.com", 80)).await?;
    assert_eq!(
        decision.reason.as_deref(),
        Some("scenario:tie-a"),
        "同优先级按声明序，不重排"
    );

    Ok(())
}

// ---------- RIL-140 统一选路模式：全局/直连入口 ----------

/// 验收：全局模式短路场景与规则面——普通求值暂停，业务流走显式全局
/// 出口；reason 带 mode:global 可追溯（回执面逐流可解释）。
#[tokio::test]
async fn global_mode_short_circuits_scenarios_and_rules() -> Result<()> {
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        mode: SelectionMode::Global,
        global_node: Some("global-exit".to_string()),
        scenarios: vec![scenario(
            "catch-all-scene",
            vec![],
            "game-exit",
            10,
            ScenarioFailureAction::Fallback,
        )],
        groups: vec![
            one_node_group("global-exit", "global-node"),
            one_node_group("game-exit", "game-node"),
        ],
        rules: vec![RouteRule {
            name: "example-rule".to_string(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["example.com".to_string()],
            }],
            target: "rule-exit".to_string(),
        }],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);

    // 命中规则 + 无条件命中的场景都本可截走——全局入口短路两者
    let decision = engine
        .route(create_flow_context("example.com", 443))
        .await?;
    assert_eq!(decision.final_node(), "global-node");
    assert_eq!(decision.reason.as_deref(), Some("mode:global"));

    Ok(())
}

/// 验收：全局出口不可用（组无健康成员）= 显式失败上抛——不静默落
/// 直连/规则面/默认节点（设计：全局出口不可用按显式失败策略返回）。
#[tokio::test]
async fn global_mode_failure_is_explicit_not_silent_direct() -> Result<()> {
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        mode: SelectionMode::Global,
        global_node: Some("empty-exit".to_string()),
        groups: vec![one_node_group("empty-exit", "dead-node")],
        rules: vec![],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);
    engine.set_node_health("dead-node", false);

    let err = engine
        .route(create_flow_context("example.com", 443))
        .await
        .expect_err("全局出口无健康成员须显式失败，不静默改道");
    assert!(
        err.to_string().contains("无健康成员"),
        "失败信息须点名组健康面: {err}"
    );

    Ok(())
}

/// 验收：直连模式走显式直连出口，场景/规则面暂停；reason 带
/// mode:direct。直连不等于关闭 DNS/统计（那些面不归路由器）——本
/// 断言只钉选路行为。
#[tokio::test]
async fn direct_mode_uses_explicit_direct_node_and_pauses_rules() -> Result<()> {
    let config = RoutingConfig {
        default_node: "direct-node".to_string(),
        mode: SelectionMode::Direct,
        direct_node: Some("direct-main".to_string()),
        scenarios: vec![scenario(
            "catch-all-scene",
            vec![],
            "game-exit",
            10,
            ScenarioFailureAction::Fallback,
        )],
        groups: vec![one_node_group("game-exit", "game-node")],
        rules: vec![RouteRule {
            name: "example-rule".to_string(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["example.com".to_string()],
            }],
            target: "proxy-node".to_string(),
        }],
        ..Default::default()
    };
    let engine = RoutingEngine::new(config);

    let decision = engine
        .route(create_flow_context("example.com", 443))
        .await?;
    assert_eq!(decision.final_node(), "direct-main");
    assert_eq!(decision.reason.as_deref(), Some("mode:direct"));

    Ok(())
}
