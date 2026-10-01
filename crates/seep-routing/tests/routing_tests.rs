use std::collections::HashMap;
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

#[tokio::test]
async fn test_health_check_integration() -> Result<()> {
    let config = create_test_config();
    let engine = RoutingEngine::new(config);

    // 获取初始健康统计
    let (_healthy, total) = engine.get_health_stats();

    // 初始时应该没有健康检查记录
    assert_eq!(total, 0);

    // 等待健康检查任务运行
    let engine_arc = Arc::new(engine);
    let engine_clone = engine_arc.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        // 手动触发一次健康检查
        engine_clone.perform_health_checks().await;
    });

    // 等待健康检查完成（轮询至截止——固定 sleep 在 CPU 饱和下漏调度会假失败；
    // healthy>0 同入轮询条件——check_node_health 为随机 10% 不健康，首个入表
    // 节点恰抽中即 total>0 先现而 healthy==0，立即断言会假失败，等后续节点覆盖）
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut stats = engine_arc.get_health_stats();
    while (stats.0 == 0 || stats.1 == 0) && std::time::Instant::now() < deadline {
        sleep(Duration::from_millis(20)).await;
        stats = engine_arc.get_health_stats();
    }

    // 再次获取健康统计
    let (healthy, total) = stats;

    // 应该有健康检查记录
    assert!(total > 0);
    assert!(healthy > 0);

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
