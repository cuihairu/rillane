use std::{collections::HashMap, sync::RwLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rand::{seq::SliceRandom, thread_rng, Rng};
use seep_config::{MatchCondition, PolicyGroup, RouteRule, RoutingConfig, Strategy, GroupDescriptor, GroupDescriptorMember};
use seep_core::{FlowContext, FlowRouter, RouteDecision};

pub struct RoutingEngine {
    config: RwLock<RoutingConfig>,
    group_cache: RwLock<HashMap<String, GroupDescriptor>>,
    round_robin_counters: RwLock<HashMap<String, usize>>,
}

impl RoutingEngine {
    pub fn new(config: RoutingConfig) -> Self {
        let engine = Self {
            config: RwLock::new(config),
            group_cache: RwLock::new(HashMap::new()),
            round_robin_counters: RwLock::new(HashMap::new()),
        };
        engine.build_group_cache();
        engine
    }

    pub fn reload(&self, next: RoutingConfig) {
        *self.config.write().expect("routing poisoned") = next;
        self.build_group_cache();
        self.clear_round_robin_counters();
    }

    fn snapshot(&self) -> RoutingConfig {
        self.config.read().expect("routing poisoned").clone()
    }

    /// 构建组描述符缓存
    fn build_group_cache(&self) {
        let config = self.snapshot();
        let mut cache = self.group_cache.write().expect("group cache poisoned");
        cache.clear();

        // 多轮解析以支持组嵌套
        let mut resolved_groups = std::collections::HashSet::new();
        let mut max_iterations = config.groups.len() * 2; // 防止循环依赖

        while resolved_groups.len() < config.groups.len() && max_iterations > 0 {
            max_iterations -= 1;

            for group in &config.groups {
                if !resolved_groups.contains(&group.name) {
                    if let Some(descriptor) = self.resolve_group_descriptor(&config, group, &resolved_groups) {
                        cache.insert(group.name.clone(), descriptor);
                        resolved_groups.insert(group.name.clone());
                    }
                }
            }
        }
    }

    /// 递归解析组描述符
    fn resolve_group_descriptor(
        &self,
        config: &RoutingConfig,
        group: &PolicyGroup,
        resolved: &std::collections::HashSet<String>,
    ) -> Option<GroupDescriptor> {
        let mut members = Vec::new();

        for member in &group.members {
            match member {
                seep_config::GroupMember::Node { name } => {
                    members.push(GroupDescriptorMember::Node {
                        name: name.clone(),
                        weight: 1,
                        is_healthy: true, // TODO: 集成健康检查
                    });
                }
                seep_config::GroupMember::Group { name } => {
                    if resolved.contains(name) {
                        if let Some(nested_group) = config.groups.iter().find(|g| g.name == *name) {
                            if let Some(nested_descriptor) = self.resolve_group_descriptor(config, nested_group, resolved) {
                                members.push(GroupDescriptorMember::Group {
                                    name: name.clone(),
                                    weight: 1,
                                    descriptor: Box::new(nested_descriptor),
                                });
                            }
                        }
                    }
                }
                seep_config::GroupMember::WeightedNode { name, weight } => {
                    members.push(GroupDescriptorMember::Node {
                        name: name.clone(),
                        weight: *weight,
                        is_healthy: true,
                    });
                }
                seep_config::GroupMember::WeightedGroup { name, weight } => {
                    if resolved.contains(name) {
                        if let Some(nested_group) = config.groups.iter().find(|g| g.name == *name) {
                            if let Some(nested_descriptor) = self.resolve_group_descriptor(config, nested_group, resolved) {
                                members.push(GroupDescriptorMember::Group {
                                    name: name.clone(),
                                    weight: *weight,
                                    descriptor: Box::new(nested_descriptor),
                                });
                            }
                        }
                    }
                }
            }
        }

        if members.is_empty() {
            None
        } else {
            Some(GroupDescriptor::new(group.name.clone(), group.strategy.clone(), members))
        }
    }

    /// 获取组描述符
    fn get_group_descriptor(&self, name: &str) -> Option<GroupDescriptor> {
        let cache = self.group_cache.read().expect("group cache poisoned");
        cache.get(name).cloned()
    }

    /// 清理轮询计数器
    fn clear_round_robin_counters(&self) {
        let mut counters = self.round_robin_counters.write().expect("round robin counters poisoned");
        counters.clear();
    }

    /// 获取下一个轮询索引
    fn get_next_round_robin_index(&self, group_name: &str, member_count: usize) -> usize {
        let mut counters = self.round_robin_counters.write().expect("round robin counters poisoned");
        let index = counters.entry(group_name.to_string()).or_insert(0);
        let current = *index;
        *index = (current + 1) % member_count;
        current
    }
}

#[async_trait]
impl FlowRouter for RoutingEngine {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        let config = self.snapshot();
        for rule in &config.rules {
            if matches_rule(rule, &ctx) {
                return self.resolve_target(&rule.target, Some(rule.name.clone())).await;
            }
        }

        self.resolve_target(&config.default_node, Some("default".into())).await
    }
}

impl RoutingEngine {
    /// 解析目标并返回路由决策
    async fn resolve_target(&self, target: &str, reason: Option<String>) -> Result<RouteDecision> {
        // 如果是组，则从组描述符中选择
        if let Some(descriptor) = self.get_group_descriptor(target) {
            self.select_from_group(&descriptor, reason).await
        } else {
            // 直接节点
            let mut decision = RouteDecision::direct(target.to_string());
            decision.reason = reason;
            Ok(decision)
        }
    }

    /// 从组中选择成员
    async fn select_from_group(&self, descriptor: &GroupDescriptor, reason: Option<String>) -> Result<RouteDecision> {
        let healthy_members = descriptor.healthy_members();
        if healthy_members.is_empty() {
            return Err(anyhow!("组 {} 无健康成员", descriptor.name));
        }

        let selected_member = match descriptor.strategy {
            Strategy::Fixed => healthy_members.first().copied(),
            Strategy::Random => {
                let mut rng = thread_rng();
                healthy_members.choose(&mut rng).copied()
            }
            Strategy::Weighted => self.select_weighted_member(&healthy_members),
            Strategy::Bandwidth => {
                // TODO: 集成带宽监控
                healthy_members.first().copied()
            }
            Strategy::ConsistentHash => {
                // TODO: 实现一致性哈希
                healthy_members.first().copied()
            }
            Strategy::RoundRobin => {
                let index = self.get_next_round_robin_index(&descriptor.name, healthy_members.len());
                healthy_members.get(index).copied()
            }
            Strategy::Latency => {
                // TODO: 集成延迟监控
                healthy_members.first().copied()
            }
        };

        let selected_member = selected_member.ok_or_else(|| {
            anyhow!("组 {} 选择成员失败", descriptor.name)
        })?;

        match selected_member {
            GroupDescriptorMember::Node { name, .. } => {
                let mut decision = RouteDecision::through_group(
                    descriptor.name.clone(),
                    name.clone(),
                    Vec::new(), // 中间节点目前为空
                );
                decision.reason = reason;
                Ok(decision)
            }
            GroupDescriptorMember::Group { descriptor: nested_desc, .. } => {
                // 递归选择嵌套组的成员
                Box::pin(self.select_from_group(nested_desc.as_ref(), reason)).await
            }
        }
    }

    /// 加权随机选择
    fn select_weighted_member<'a>(&self, members: &'a [&GroupDescriptorMember]) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        let total_weight: u32 = members.iter().map(|m| m.as_weight()).sum();
        if total_weight == 0 {
            return None;
        }

        let mut rng = thread_rng();
        let mut random_weight = rng.gen_range(0..total_weight);

        for member in members {
            if random_weight < member.as_weight() {
                return Some(member);
            }
            random_weight -= member.as_weight();
        }

        members.first().copied()
    }
}

fn matches_rule(rule: &RouteRule, ctx: &FlowContext) -> bool {
    rule.matches.iter().all(|matcher| match matcher {
        MatchCondition::DomainSuffix { values } => values
            .iter()
            .any(|suffix| ctx.target.host.ends_with(suffix)),
        MatchCondition::DomainKeyword { values } => values
            .iter()
            .any(|keyword| ctx.target.host.contains(keyword)),
        MatchCondition::Geoip { country } => ctx
            .metadata
            .annotations
            .get("geoip.country")
            .map(|c| c == country)
            .unwrap_or(false),
        MatchCondition::Network { cidrs } => ctx
            .metadata
            .annotations
            .get("client.cidr")
            .map(|cidr| cidrs.iter().any(|rule_cidr| rule_cidr == cidr))
            .unwrap_or(false),
        MatchCondition::Port { values } => values.contains(&ctx.target.port),
    })
}
