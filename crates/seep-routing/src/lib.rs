use std::{collections::HashMap, sync::{Arc, RwLock}, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use rand::{seq::SliceRandom, thread_rng, Rng};
use seep_config::{MatchCondition, PolicyGroup, RouteRule, RoutingConfig, Strategy, GroupDescriptor, GroupDescriptorMember};
use seep_core::{FlowContext, FlowRouter, RouteDecision};
use sha2::{Digest, Sha256};
use tokio::time::{interval, sleep};

pub struct RoutingEngine {
    config: RwLock<RoutingConfig>,
    group_cache: RwLock<HashMap<String, GroupDescriptor>>,
    round_robin_counters: RwLock<HashMap<String, usize>>,
    // 节点健康状态缓存 (node_name -> (is_healthy, last_check_time))
    health_status: DashMap<String, (bool, std::time::Instant)>,
    // 节点延迟统计缓存 (node_name -> latency_ms)
    latency_stats: DashMap<String, u32>,
    // 节点带宽统计缓存 (node_name -> (bandwidth_kbps, last_update_time))
    bandwidth_stats: DashMap<String, (u32, std::time::Instant)>,
}

impl RoutingEngine {
    pub fn new(config: RoutingConfig) -> Self {
        let engine = Self {
            config: RwLock::new(config),
            group_cache: RwLock::new(HashMap::new()),
            round_robin_counters: RwLock::new(HashMap::new()),
            health_status: DashMap::new(),
            latency_stats: DashMap::new(),
            bandwidth_stats: DashMap::new(),
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
                    let is_healthy = self.get_node_health(name);
                    members.push(GroupDescriptorMember::Node {
                        name: name.clone(),
                        weight: 1,
                        is_healthy,
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
                    let is_healthy = self.get_node_health(name);
                    members.push(GroupDescriptorMember::Node {
                        name: name.clone(),
                        weight: *weight,
                        is_healthy,
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

    /// 获取节点健康状态
    fn get_node_health(&self, node_name: &str) -> bool {
        const HEALTH_CHECK_TTL: Duration = Duration::from_secs(30);

        if let Some(entry) = self.health_status.get(node_name) {
            let (is_healthy, last_check) = entry.value();
            // 如果缓存仍然有效，返回缓存的状态
            if last_check.elapsed() < HEALTH_CHECK_TTL {
                return *is_healthy;
            }
        }

        // 默认健康，实际应用中应该执行健康检查
        true
    }

    /// 启动健康检查任务
    pub async fn start_health_check_task(self: Arc<Self>) {
        let health_check_interval = interval(Duration::from_secs(10));
        tokio::pin!(health_check_interval);

        loop {
            health_check_interval.tick().await;
            self.perform_health_checks().await;
        }
    }

    /// 执行健康检查
    pub async fn perform_health_checks(&self) {
        let config = self.snapshot();
        let nodes_to_check: Vec<String> = config.groups.iter()
            .flat_map(|group| group.members.iter())
            .map(|member| member.as_name())
            .collect();

        for node_name in nodes_to_check {
            // 模拟健康检查 - 实际应用中应该是真实的连接测试
            let is_healthy = self.check_node_health(&node_name).await;

            // 更新健康状态缓存
            self.health_status.insert(node_name.clone(), (is_healthy, std::time::Instant::now()));

            // 如果节点健康，更新延迟统计
            if is_healthy {
                if let Some(latency) = self.measure_node_latency(&node_name).await {
                    self.latency_stats.insert(node_name.clone(), latency);
                }
            }
        }
    }

    /// 检查单个节点的健康状态
    async fn check_node_health(&self, _node_name: &str) -> bool {
        // 模拟健康检查 - 实际应用中应该是TCP连接测试或HTTP请求
        sleep(Duration::from_millis(10)).await;

        // 模拟90%的健康率
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(0..100) < 90
    }

    /// 测量节点延迟
    async fn measure_node_latency(&self, _node_name: &str) -> Option<u32> {
        // 模拟延迟测量 - 实际应用中应该测量真实的往返时间
        sleep(Duration::from_millis(5)).await;

        // 模拟10-100ms的延迟
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Some(rng.gen_range(10..100))
    }

    /// 基于带宽选择成员
    fn select_bandwidth_member<'a>(&self, members: &'a [&GroupDescriptorMember]) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        let now = std::time::Instant::now();
        const BANDWIDTH_TTL: Duration = Duration::from_secs(60);

        // 过滤出有有效带宽统计的成员
        let members_with_bandwidth: Vec<(&GroupDescriptorMember, u32)> = members.iter()
            .filter_map(|member| {
                if let Some(entry) = self.bandwidth_stats.get(member.as_name()) {
                    let (bandwidth, last_update) = entry.value();
                    if now.duration_since(*last_update) < BANDWIDTH_TTL {
                        return Some((*member, *bandwidth));
                    }
                }
                None
            })
            .collect();

        if members_with_bandwidth.is_empty() {
            // 如果没有带宽统计，返回第一个健康成员
            return members.first().copied();
        }

        // 选择带宽最高的成员
        members_with_bandwidth.into_iter()
            .max_by_key(|(_, bandwidth)| *bandwidth)
            .map(|(member, _)| member)
    }

    /// 基于延迟选择成员
    fn select_latency_member<'a>(&self, members: &'a [&GroupDescriptorMember]) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        // 过滤出有延迟统计的成员
        let members_with_latency: Vec<(&GroupDescriptorMember, u32)> = members.iter()
            .filter_map(|member| {
                self.latency_stats.get(member.as_name())
                    .map(|latency| (*member, *latency))
            })
            .collect();

        if members_with_latency.is_empty() {
            // 如果没有延迟统计，返回第一个健康成员
            return members.first().copied();
        }

        // 选择延迟最低的成员
        members_with_latency.into_iter()
            .min_by_key(|(_, latency)| *latency)
            .map(|(member, _)| member)
    }

    /// 更新节点带宽统计
    pub fn update_bandwidth_stats(&self, node_name: &str, bandwidth_kbps: u32) {
        self.bandwidth_stats.insert(
            node_name.to_string(),
            (bandwidth_kbps, std::time::Instant::now())
        );
    }

    /// 获取节点健康状态统计
    pub fn get_health_stats(&self) -> (usize, usize) {
        let total = self.health_status.len();
        let healthy = self.health_status.iter()
            .filter(|entry| entry.value().0)
            .count();
        (healthy, total)
    }
}

#[async_trait]
impl FlowRouter for RoutingEngine {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        let config = self.snapshot();
        for rule in &config.rules {
            if matches_rule(rule, &ctx) {
                return self.resolve_target(&rule.target, Some(rule.name.clone()), Some(&ctx)).await;
            }
        }

        self.resolve_target(&config.default_node, Some("default".into()), Some(&ctx)).await
    }
}

impl RoutingEngine {
    /// 解析目标并返回路由决策
    async fn resolve_target(&self, target: &str, reason: Option<String>, ctx: Option<&FlowContext>) -> Result<RouteDecision> {
        // 如果是组，则从组描述符中选择
        if let Some(descriptor) = self.get_group_descriptor(target) {
            self.select_from_group(&descriptor, reason, ctx).await
        } else {
            // 直接节点
            let mut decision = RouteDecision::direct(target.to_string());
            decision.reason = reason;
            Ok(decision)
        }
    }

    /// 从组中选择成员
    async fn select_from_group(&self, descriptor: &GroupDescriptor, reason: Option<String>, ctx: Option<&FlowContext>) -> Result<RouteDecision> {
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
                self.select_bandwidth_member(&healthy_members)
            }
            Strategy::ConsistentHash => {
                self.select_consistent_hash_member(&healthy_members, ctx)
            }
            Strategy::RoundRobin => {
                let index = self.get_next_round_robin_index(&descriptor.name, healthy_members.len());
                healthy_members.get(index).copied()
            }
            Strategy::Latency => {
                self.select_latency_member(&healthy_members)
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
                Box::pin(self.select_from_group(nested_desc.as_ref(), reason, ctx)).await
            }
        }
    }

    /// 一致性哈希选择
    fn select_consistent_hash_member<'a>(&self, members: &'a [&GroupDescriptorMember], ctx: Option<&FlowContext>) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        // 获取哈希键，优先使用目标主机，否则使用节点名的组合
        let hash_key = match ctx {
            Some(ctx) => ctx.target.host.clone(),
            None => {
                // 如果没有上下文，使用所有成员名的组合作为哈希键
                members.iter()
                    .map(|m| m.as_name())
                    .collect::<Vec<_>>()
                    .join(":")
            }
        };

        // 计算哈希值
        let hash = Sha256::digest(hash_key.as_bytes());
        let hash_num = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);

        // 使用哈希值选择成员
        let index = (hash_num as usize) % members.len();
        members.get(index).copied()
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
