use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use seep_config::{GroupMember, MatchCondition, PolicyGroup, RouteRule, RoutingConfig, Strategy};
use seep_core::{FlowContext, FlowId, FlowMetadata, FlowRouter, FlowTarget, TargetProto};
use seep_routing::RoutingEngine;
use tokio::time::{sleep, Duration};

fn create_test_config() -> RoutingConfig {
    RoutingConfig {
        default_node: "direct-node".to_string(),
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
        url_test: Some(seep_config::UrlTestConfig {
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
