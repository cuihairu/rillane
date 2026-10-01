use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use rand::{seq::SliceRandom, thread_rng, Rng};
use seep_config::{
    GroupDescriptor, GroupDescriptorMember, MatchCondition, PolicyGroup, RouteRule, RoutingConfig,
    SloPolicy, Strategy,
};
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
    // 节点真链路质量缓存 (node_name -> (p95_ms, loss_ratio, last_update))
    // ——slo-scoring.md §2 D-3：seep-runtime 桥自 MeshRegistry 聚合推进
    // （update_link_quality），seep-routing 保持零 seep-mesh 依赖（D-4）
    link_quality: DashMap<String, (u32, f64, std::time::Instant)>,
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
            link_quality: DashMap::new(),
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
                    if let Some(descriptor) =
                        self.resolve_group_descriptor(&config, group, &resolved_groups)
                    {
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
                            if let Some(nested_descriptor) =
                                self.resolve_group_descriptor(config, nested_group, resolved)
                            {
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
                            if let Some(nested_descriptor) =
                                self.resolve_group_descriptor(config, nested_group, resolved)
                            {
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
            Some(GroupDescriptor::new(
                group.name.clone(),
                group.strategy.clone(),
                members,
                group.slo.clone(),
            ))
        }
    }

    /// 获取组描述符
    fn get_group_descriptor(&self, name: &str) -> Option<GroupDescriptor> {
        let cache = self.group_cache.read().expect("group cache poisoned");
        cache.get(name).cloned()
    }

    /// 清理轮询计数器
    fn clear_round_robin_counters(&self) {
        let mut counters = self
            .round_robin_counters
            .write()
            .expect("round robin counters poisoned");
        counters.clear();
    }

    /// 获取下一个轮询索引
    fn get_next_round_robin_index(&self, group_name: &str, member_count: usize) -> usize {
        let mut counters = self
            .round_robin_counters
            .write()
            .expect("round robin counters poisoned");
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
        let nodes_to_check: Vec<String> = config
            .groups
            .iter()
            .flat_map(|group| group.members.iter())
            .map(|member| member.as_name())
            .collect();

        for node_name in nodes_to_check {
            // 模拟健康检查 - 实际应用中应该是真实的连接测试
            let is_healthy = self.check_node_health(&node_name).await;

            // 更新健康状态缓存
            self.health_status
                .insert(node_name.clone(), (is_healthy, std::time::Instant::now()));

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
    fn select_bandwidth_member<'a>(
        &self,
        members: &'a [&GroupDescriptorMember],
    ) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        let now = std::time::Instant::now();
        const BANDWIDTH_TTL: Duration = Duration::from_secs(60);

        // 过滤出有有效带宽统计的成员
        let members_with_bandwidth: Vec<(&GroupDescriptorMember, u32)> = members
            .iter()
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
        members_with_bandwidth
            .into_iter()
            .max_by_key(|(_, bandwidth)| *bandwidth)
            .map(|(member, _)| member)
    }

    /// 更新节点真链路质量（slo-scoring.md §2 D-3：seep-runtime 桥推进，
    /// p95 = 相邻链路最差跳，loss = Σerrors/Σconnections）
    pub fn update_link_quality(&self, node_name: &str, p95_ms: u32, loss_ratio: f64) {
        self.link_quality.insert(
            node_name.to_string(),
            (p95_ms, loss_ratio, std::time::Instant::now()),
        );
    }

    /// 节点真链路质量快照 (node, p95_ms, loss_ratio)（测试与 O-slo1 观测面）
    pub fn link_quality_snapshot(&self) -> Vec<(String, u32, f64)> {
        self.link_quality
            .iter()
            .map(|e| (e.key().clone(), e.value().0, e.value().1))
            .collect()
    }

    /// 基于延迟选择成员（slo-scoring.md §2 D-2/D-3 升级：SLO 目标门 + 加性
    /// 罚分评分；取数优先级 = 真链路质量（TTL 内）→ legacy latency_stats →
    /// 首个健康成员）
    fn select_latency_member<'a>(
        &self,
        members: &'a [&GroupDescriptorMember],
        slo: Option<&SloPolicy>,
    ) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        let now = std::time::Instant::now();
        const QUALITY_TTL: Duration = Duration::from_secs(60);

        // 取数：真链路质量优先；缺席回退 legacy 最后样本（loss 未知记 0——
        // 语义 = legacy 源无丢包观测，§9 语义变化注记）
        let candidates: Vec<(&GroupDescriptorMember, f64, f64, bool)> = members
            .iter()
            .filter_map(|member| {
                if let Some(entry) = self.link_quality.get(member.as_name()) {
                    let (p95, loss, at) = entry.value();
                    if now.duration_since(*at) < QUALITY_TTL {
                        return Some((*member, *p95 as f64, *loss, true));
                    }
                }
                self.latency_stats
                    .get(member.as_name())
                    .map(|latency| (*member, *latency.value() as f64, 0.0, false))
            })
            .collect();

        if candidates.is_empty() {
            return members.first().copied();
        }

        let penalty = slo.map(SloPolicy::penalty_or_default).unwrap_or(1000.0);
        // score = p95 + loss × penalty（D-1 加性形；legacy 源 loss=0）
        let score =
            |&(_, p95, loss, _): &(&GroupDescriptorMember, f64, f64, bool)| p95 + loss * penalty;
        // 门（D-2）：仅真数据成员受门约束（legacy/unknown 视为合规）；
        // 门内空 → 全体候选（不 dead-end）
        let compliant: Vec<_> = match slo {
            Some(slo) => {
                let gated: Vec<_> = candidates
                    .iter()
                    .filter(|(_, p95, loss, real)| {
                        !*real
                            || (slo.p95_ms.is_none_or(|t| *p95 <= f64::from(t))
                                && slo.loss_ratio.is_none_or(|t| *loss <= t))
                    })
                    .collect();
                if gated.is_empty() {
                    candidates.iter().collect()
                } else {
                    gated
                }
            }
            None => candidates.iter().collect(),
        };

        compliant
            .into_iter()
            .min_by(|a, b| score(a).total_cmp(&score(b)))
            .map(|(member, _, _, _)| *member)
    }

    /// 更新节点带宽统计
    pub fn update_bandwidth_stats(&self, node_name: &str, bandwidth_kbps: u32) {
        self.bandwidth_stats.insert(
            node_name.to_string(),
            (bandwidth_kbps, std::time::Instant::now()),
        );
    }

    /// 获取节点健康状态统计
    pub fn get_health_stats(&self) -> (usize, usize) {
        let total = self.health_status.len();
        let healthy = self
            .health_status
            .iter()
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
                return self
                    .resolve_target(&rule.target, Some(rule.name.clone()), Some(&ctx))
                    .await;
            }
        }

        self.resolve_target(&config.default_node, Some("default".into()), Some(&ctx))
            .await
    }
}

impl RoutingEngine {
    /// 解析目标并返回路由决策
    async fn resolve_target(
        &self,
        target: &str,
        reason: Option<String>,
        ctx: Option<&FlowContext>,
    ) -> Result<RouteDecision> {
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
    async fn select_from_group(
        &self,
        descriptor: &GroupDescriptor,
        reason: Option<String>,
        ctx: Option<&FlowContext>,
    ) -> Result<RouteDecision> {
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
            Strategy::Bandwidth => self.select_bandwidth_member(&healthy_members),
            Strategy::ConsistentHash => self.select_consistent_hash_member(&healthy_members, ctx),
            Strategy::RoundRobin => {
                let index =
                    self.get_next_round_robin_index(&descriptor.name, healthy_members.len());
                healthy_members.get(index).copied()
            }
            Strategy::Latency => {
                self.select_latency_member(&healthy_members, descriptor.slo.as_ref())
            }
        };

        let selected_member =
            selected_member.ok_or_else(|| anyhow!("组 {} 选择成员失败", descriptor.name))?;

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
            GroupDescriptorMember::Group {
                descriptor: nested_desc,
                ..
            } => {
                // 递归选择嵌套组的成员
                Box::pin(self.select_from_group(nested_desc.as_ref(), reason, ctx)).await
            }
        }
    }

    /// 一致性哈希选择
    fn select_consistent_hash_member<'a>(
        &self,
        members: &'a [&GroupDescriptorMember],
        ctx: Option<&FlowContext>,
    ) -> Option<&'a GroupDescriptorMember> {
        if members.is_empty() {
            return None;
        }

        // 获取哈希键，优先使用目标主机，否则使用节点名的组合
        let hash_key = match ctx {
            Some(ctx) => ctx.target.host.clone(),
            None => {
                // 如果没有上下文，使用所有成员名的组合作为哈希键
                members
                    .iter()
                    .map(|m| m.as_name())
                    .collect::<Vec<_>>()
                    .join(":")
            }
        };

        // 计算哈希值
        let hash = Sha256::digest(hash_key.as_bytes());
        let hash_num = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        // 使用哈希值选择成员
        let index = (hash_num as usize) % members.len();
        members.get(index).copied()
    }

    /// 加权随机选择
    fn select_weighted_member<'a>(
        &self,
        members: &'a [&GroupDescriptorMember],
    ) -> Option<&'a GroupDescriptorMember> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 双成员健康组直构（slo-scoring.md §7-2：选择翻转断言面）
    fn two_member_group() -> Vec<GroupDescriptorMember> {
        vec![
            GroupDescriptorMember::Node {
                name: "good".into(),
                weight: 1,
                is_healthy: true,
            },
            GroupDescriptorMember::Node {
                name: "bad".into(),
                weight: 1,
                is_healthy: true,
            },
        ]
    }

    /// §7-2：真链路质量注入驱动选择——低 p95 成员入选；注入劣化后翻转
    #[test]
    fn latency_strategy_flips_on_real_quality_degradation() {
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "good".into(),
            groups: vec![],
            rules: vec![],
        });
        let members = two_member_group();
        let refs: Vec<&GroupDescriptorMember> = members.iter().collect();

        // 初始：good p95 30ms / bad p95 80ms（loss 皆 0）→ 选 good
        engine.update_link_quality("good", 30, 0.0);
        engine.update_link_quality("bad", 80, 0.0);
        assert_eq!(
            engine.select_latency_member(&refs, None).unwrap().as_name(),
            "good"
        );

        // 劣化注入：good p95 升至 120 → 选 bad（验收「模拟链路劣化」选择面）
        engine.update_link_quality("good", 120, 0.0);
        assert_eq!(
            engine.select_latency_member(&refs, None).unwrap().as_name(),
            "bad"
        );
    }

    /// §7-1/D-1：丢包罚分参与排序——同 p95 下高丢包成员落选；
    /// 门（D-2）：越门真数据成员被过滤，门内空不 dead-end 回全体
    #[test]
    fn slo_gate_filters_violators_and_never_dead_ends() {
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "good".into(),
            groups: vec![],
            rules: vec![],
        });
        let members = two_member_group();
        let refs: Vec<&GroupDescriptorMember> = members.iter().collect();

        // 罚分翻转到胜利方向：bad p95 20 分 70（20+0.05×1000）< good p95 80
        // 分 80 → 无门选 bad（丢包罚分不改变此处排序，仅垫高劣化者）
        engine.update_link_quality("good", 80, 0.0);
        engine.update_link_quality("bad", 20, 0.05);
        let slo = SloPolicy {
            p95_ms: None,
            loss_ratio: None,
            loss_penalty_ms: None,
        };
        assert_eq!(
            engine
                .select_latency_member(&refs, Some(&slo))
                .unwrap()
                .as_name(),
            "bad"
        );

        // 罚分压倒性形：good p95 50 loss 0 分 50 < bad p95 45 loss 5% 分 95
        // → 高丢包成员落选（D-1 罚分参与排序）
        engine.update_link_quality("good", 50, 0.0);
        engine.update_link_quality("bad", 45, 0.05);
        assert_eq!(
            engine
                .select_latency_member(&refs, Some(&slo))
                .unwrap()
                .as_name(),
            "good"
        );

        // 门（D-2）：bad loss 5% 越门 1% → 被过滤只剩 good（尽管 bad 分更低）
        engine.update_link_quality("good", 80, 0.0);
        engine.update_link_quality("bad", 20, 0.05);
        let slo_strict = SloPolicy {
            p95_ms: None,
            loss_ratio: Some(0.01),
            loss_penalty_ms: None,
        };
        assert_eq!(
            engine
                .select_latency_member(&refs, Some(&slo_strict))
                .unwrap()
                .as_name(),
            "good"
        );

        // 门全破不 dead-end：两成员皆越门 → 回全体取最低分（bad 70 < good 580）
        engine.update_link_quality("good", 80, 0.5);
        assert_eq!(
            engine
                .select_latency_member(&refs, Some(&slo_strict))
                .unwrap()
                .as_name(),
            "bad"
        );
    }

    /// §7-2/§6 E1：无真数据成员视为合规（门不误杀）+ 取数优先级——真数据
    /// 在场压过 legacy；真数据缺席回 legacy 最后样本；皆缺席回首个成员
    #[test]
    fn quality_source_priority_and_unknown_compliance() {
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "good".into(),
            groups: vec![],
            rules: vec![],
        });
        let members = two_member_group();
        let refs: Vec<&GroupDescriptorMember> = members.iter().collect();

        // 皆无数据 → 首个健康成员
        assert_eq!(
            engine.select_latency_member(&refs, None).unwrap().as_name(),
            "good"
        );

        // 仅 legacy：bad 20ms < good 60ms → 选 bad（旧路径保持）
        engine.latency_stats.insert("good".into(), 60);
        engine.latency_stats.insert("bad".into(), 20);
        assert_eq!(
            engine.select_latency_member(&refs, None).unwrap().as_name(),
            "bad"
        );

        // 成员级真数据优先（D-3）：真数据只覆盖本成员的 legacy 值——good
        // legacy 60 被真数据 10ms 覆盖后以 10 分入选（若仍读 legacy 60 则
        // bad 20 胜）；bad 无真数据继续用 legacy 20
        engine.update_link_quality("good", 10, 0.0);
        assert_eq!(
            engine.select_latency_member(&refs, None).unwrap().as_name(),
            "good"
        );

        // §6 E1：strict 门下 good 真数据越门、bad 无真数据（unknown 合规）
        // → bad 以 legacy 分入选（unknown 不被门误杀）
        engine.update_link_quality("good", 100, 0.5);
        let slo_strict = SloPolicy {
            p95_ms: Some(50),
            loss_ratio: None,
            loss_penalty_ms: None,
        };
        assert_eq!(
            engine
                .select_latency_member(&refs, Some(&slo_strict))
                .unwrap()
                .as_name(),
            "bad"
        );
    }

    /// §7-1：SloPolicy 值域 validate（seep-config 层）
    #[test]
    fn slo_policy_validate_ranges() {
        use seep_config::RoutingConfig as Cfg;
        let ok = Cfg {
            default_node: "n".into(),
            groups: vec![PolicyGroup {
                name: "g".into(),
                strategy: Strategy::Latency,
                members: vec![],
                slo: Some(SloPolicy {
                    p95_ms: Some(150),
                    loss_ratio: Some(0.05),
                    loss_penalty_ms: Some(500.0),
                }),
            }],
            rules: vec![],
        };
        assert!(ok.validate().is_ok());

        let bad_loss = Cfg {
            groups: vec![PolicyGroup {
                name: "g".into(),
                strategy: Strategy::Latency,
                members: vec![],
                slo: Some(SloPolicy {
                    p95_ms: None,
                    loss_ratio: Some(1.5),
                    loss_penalty_ms: None,
                }),
            }],
            ..ok.clone()
        };
        let err = bad_loss.validate().unwrap_err().to_string();
        assert!(err.contains("g"), "错误应点名组：{err}");
        assert!(err.contains("loss_ratio"), "错误应带原值维：{err}");

        let bad_penalty = Cfg {
            groups: vec![PolicyGroup {
                name: "g".into(),
                strategy: Strategy::Latency,
                members: vec![],
                slo: Some(SloPolicy {
                    p95_ms: None,
                    loss_ratio: None,
                    loss_penalty_ms: Some(-1.0),
                }),
            }],
            ..ok
        };
        assert!(bad_penalty.validate().is_err());
    }
}
