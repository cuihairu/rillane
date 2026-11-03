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
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::{interval, sleep};

/// 判断 IP 是否落在 CIDR 内（G0-1 目的 IP-CIDR 匹配）。仅支持 IP 字面量
/// CIDR（`a.b.c.d/nn` 或 `::/nn`）；host 形式（无 `/`）按主机 /32 或 /128 处理；
/// 无法解析返回 false（路由面不解析 DNS）。
fn ip_in_cidr(ip: std::net::IpAddr, cidr: &str) -> bool {
    let Some((addr_str, prefix_str)) = cidr.split_once('/') else {
        return ip.to_string() == cidr;
    };
    let Ok(net_addr) = addr_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match (ip, net_addr) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(net)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(net)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// 单成员实时质量（O-slo1 观测面：控制面 `/routing/stats` 与 `seepctl group`
/// 取数；取数/门/评分口径与 [`RoutingEngine::select_latency_member`] 同源）
#[derive(Debug, Clone, Serialize)]
pub struct MemberQuality {
    pub name: String,
    pub healthy: bool,
    /// 数据源：`"real"`（link_quality TTL 内）/ `"legacy"`（latency_stats）/
    /// `"unknown"`（两者皆无）
    pub source: &'static str,
    pub p95_ms: Option<u64>,
    pub loss_ratio: Option<f64>,
    /// score = p95 + loss × penalty（D-1 加性形；仅 latency 组计算）
    pub score: Option<f64>,
    /// 门判定（D-2）：仅 latency 组 + 有门 + real 数据成员有值；
    /// legacy/unknown 自动合规记 `None`
    pub gate_pass: Option<bool>,
}

/// 单组实时质量报告（O-slo1）
#[derive(Debug, Clone, Serialize)]
pub struct GroupQuality {
    pub name: String,
    /// 策略名（serde snake_case 口径，与配置一致）
    pub strategy: String,
    /// 当前数据下 latency 策略的确定性选点（与 select_latency_member
    /// 同口径）；非 latency 组 = `None`
    pub selected: Option<String>,
    pub members: Vec<MemberQuality>,
}

/// 策略显示名（serde snake_case 口径）
fn strategy_name(s: &Strategy) -> &'static str {
    match s {
        Strategy::Fixed => "fixed",
        Strategy::Latency => "latency",
        Strategy::Random => "random",
        Strategy::Bandwidth => "bandwidth",
        Strategy::Weighted => "weighted",
        Strategy::ConsistentHash => "consistent_hash",
        Strategy::RoundRobin => "round_robin",
    }
}

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

    /// 取数候选（D-3 优先级：真链路质量 TTL 内 → legacy latency_stats；
    /// 缺席者不入候选）——select_latency_member 与 group_quality_report 共用
    fn quality_candidates(
        &self,
        member_names: impl Iterator<Item = String>,
    ) -> Vec<(String, f64, f64, bool)> {
        let now = std::time::Instant::now();
        const QUALITY_TTL: Duration = Duration::from_secs(60);
        member_names
            .filter_map(|name| {
                // 取数：真链路质量优先；缺席回退 legacy 最后样本（loss 未知记
                // 0——语义 = legacy 源无丢包观测，§9 语义变化注记）
                if let Some(entry) = self.link_quality.get(&name) {
                    let (p95, loss, at) = entry.value();
                    if now.duration_since(*at) < QUALITY_TTL {
                        return Some((name, *p95 as f64, *loss, true));
                    }
                }
                self.latency_stats
                    .get(&name)
                    .map(|latency| (name, *latency.value() as f64, 0.0, false))
            })
            .collect()
    }

    /// 门 + 评分选点（D-1/D-2）：仅 real 成员受门约束（legacy/unknown 自动
    /// 合规）；门内空 → 全体候选（不 dead-end）；score = p95 + loss × penalty
    fn gate_and_pick<'a>(
        &self,
        candidates: &'a [(String, f64, f64, bool)],
        slo: Option<&SloPolicy>,
    ) -> Option<&'a (String, f64, f64, bool)> {
        let penalty = slo.map(SloPolicy::penalty_or_default).unwrap_or(1000.0);
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
            .min_by(|a, b| (a.1 + a.2 * penalty).total_cmp(&(b.1 + b.2 * penalty)))
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

        let names: Vec<String> = members.iter().map(|m| m.as_name().to_string()).collect();
        let candidates = self.quality_candidates(names.iter().cloned());

        if candidates.is_empty() {
            return members.first().copied();
        }

        let chosen = self.gate_and_pick(&candidates, slo)?;
        members.iter().find(|m| m.as_name() == chosen.0).copied()
    }

    /// 组实时质量报告（O-slo1 观测面）：逐组列出成员数据源/质量/门/评分，
    /// latency 组附当前确定性选点。只读，无副作用。
    pub fn group_quality_report(&self) -> Vec<GroupQuality> {
        let config = self.snapshot();
        config
            .groups
            .iter()
            .map(|group| {
                // score/gate/selected 仅 latency 组有语义（其余策略不消费
                // SLO 数据），如实留空不误导
                let is_latency = matches!(group.strategy, Strategy::Latency);
                let slo = if is_latency { group.slo.as_ref() } else { None };
                let penalty = slo.map(SloPolicy::penalty_or_default).unwrap_or(1000.0);
                let names: Vec<String> = group
                    .members
                    .iter()
                    .map(|m| match m {
                        seep_config::GroupMember::Node { name }
                        | seep_config::GroupMember::WeightedNode { name, .. } => name.clone(),
                        seep_config::GroupMember::Group { name }
                        | seep_config::GroupMember::WeightedGroup { name, .. } => name.clone(),
                    })
                    .collect();
                let candidates = self.quality_candidates(names.iter().cloned());
                // selected 仅 latency 组计算（gate_and_pick 对 slo=None 也会
                // 取最低分，非 latency 组的确定性选点无意义）
                let chosen = if is_latency {
                    self.gate_and_pick(&candidates, slo).map(|c| c.0.clone())
                } else {
                    None
                };
                let members = names
                    .iter()
                    .map(|name| {
                        let (source, p95, loss, real) =
                            match candidates.iter().find(|(n, ..)| n == name) {
                                Some((_, p95, loss, real)) => (
                                    if *real { "real" } else { "legacy" },
                                    Some(*p95),
                                    Some(*loss),
                                    *real,
                                ),
                                None => ("unknown", None, None, false),
                            };
                        let (score, gate_pass) = if is_latency {
                            match (p95, loss) {
                                (Some(p), Some(l)) => {
                                    let gate_pass = if real {
                                        slo.map(|s| {
                                            s.p95_ms.is_none_or(|t| p <= f64::from(t))
                                                && s.loss_ratio.is_none_or(|t| l <= t)
                                        })
                                    } else {
                                        None
                                    };
                                    (Some(p + l * penalty), gate_pass)
                                }
                                _ => (None, None),
                            }
                        } else {
                            (None, None)
                        };
                        MemberQuality {
                            name: name.clone(),
                            healthy: self.get_node_health(name),
                            source,
                            p95_ms: p95.map(|v| v as u64),
                            loss_ratio: loss,
                            score,
                            gate_pass,
                        }
                    })
                    .collect();
                GroupQuality {
                    name: group.name.clone(),
                    strategy: strategy_name(&group.strategy).to_string(),
                    selected: chosen,
                    members,
                }
            })
            .collect()
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
        MatchCondition::IpCidr { cidrs } => {
            let Ok(ip) = ctx.target.host.parse::<std::net::IpAddr>() else {
                return false;
            };
            cidrs.iter().any(|cidr| ip_in_cidr(ip, cidr))
        }
        MatchCondition::Port { values } => values.contains(&ctx.target.port),
        // tun-dataplane.md §2.5：TUN 首包归因注入的 process.name 注解
        // （= /proc/<pid>/comm，内核截断 15 字节）精确匹配；注解缺席恒不命中
        MatchCondition::Process { values } => ctx
            .metadata
            .annotations
            .get("process.name")
            .map(|name| values.iter().any(|v| v == name))
            .unwrap_or(false),
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

    /// §2.5 Process 条件钉测（tun-dataplane.md §2.5 实施二选一 = comm 精确匹配）：
    /// process.name 注解精确相等命中规则；comm 不同 / 注解缺席均不命中（落默认节点）。
    /// 注解由 TunIngress 首包归因注入——无 TUN 面的 ingress 流恒不命中本条件。
    #[tokio::test]
    async fn process_condition_matches_on_process_name_annotation() {
        use seep_core::{FlowId, FlowMetadata, FlowTarget, TargetProto};

        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "game".into(),
                matches: vec![MatchCondition::Process {
                    values: vec!["cs2".into()],
                }],
                target: "game-node".into(),
            }],
        });
        let mut ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "203.0.113.9".into(),
                port: 27015,
                proto: TargetProto::Udp,
            },
            metadata: FlowMetadata::default(),
        };

        // 命中：注解 = comm 精确相等
        ctx.metadata
            .annotations
            .insert("process.name".into(), "cs2".into());
        let decision = engine.route(ctx.clone()).await.expect("route");
        assert_eq!(decision.final_node(), "game-node", "comm 命中走规则目标");

        // 不命中：comm 不同 → 落默认
        ctx.metadata
            .annotations
            .insert("process.name".into(), "firefox".into());
        assert_eq!(
            engine.route(ctx.clone()).await.expect("route").final_node(),
            "direct",
            "comm 不匹配应落默认节点"
        );

        // 不命中：注解缺席（非 TUN 流 / 归因 miss）→ 落默认
        ctx.metadata.annotations.clear();
        assert_eq!(
            engine.route(ctx).await.expect("route").final_node(),
            "direct",
            "注解缺席应落默认节点"
        );
    }

    /// O-slo1 观测面：报告逐成员标注数据源（real/legacy/unknown）
    #[test]
    fn quality_report_marks_sources() {
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![PolicyGroup {
                name: "g".into(),
                strategy: Strategy::Latency,
                members: vec![
                    seep_config::GroupMember::Node {
                        name: "real".into(),
                    },
                    seep_config::GroupMember::Node {
                        name: "legacy".into(),
                    },
                    seep_config::GroupMember::Node {
                        name: "unknown".into(),
                    },
                ],
                slo: None,
            }],
            rules: vec![],
        });
        engine.update_link_quality("real", 30, 0.0);
        engine.latency_stats.insert("legacy".into(), 40);

        let report = engine.group_quality_report();
        assert_eq!(report.len(), 1);
        let g = &report[0];
        assert_eq!(g.strategy, "latency");
        let by_name = |n: &str| g.members.iter().find(|m| m.name == n).unwrap();
        let real = by_name("real");
        assert_eq!(real.source, "real");
        assert_eq!(real.p95_ms, Some(30));
        assert_eq!(real.loss_ratio, Some(0.0));
        let legacy = by_name("legacy");
        assert_eq!(legacy.source, "legacy");
        assert_eq!(legacy.p95_ms, Some(40));
        assert_eq!(legacy.loss_ratio, Some(0.0));
        let unknown = by_name("unknown");
        assert_eq!(unknown.source, "unknown");
        assert_eq!(unknown.p95_ms, None);
        assert_eq!(unknown.loss_ratio, None);
        // 无门 → gate_pass 缺席；score 与 penalty 缺省 1000 口径
        assert_eq!(real.gate_pass, None);
        assert_eq!(real.score, Some(30.0));
        assert_eq!(legacy.gate_pass, None);
        assert_eq!(legacy.score, Some(40.0));
        assert_eq!(unknown.score, None);
        // 选点与 select 同源：real(30) < legacy(40)
        assert_eq!(g.selected.as_deref(), Some("real"));
    }

    /// O-slo1 观测面：门判定仅在 real + 有门时给值；legacy/unknown 合规
    #[test]
    fn quality_report_gate_marks_only_real_members() {
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![PolicyGroup {
                name: "g".into(),
                strategy: Strategy::Latency,
                members: vec![
                    seep_config::GroupMember::Node { name: "ok".into() },
                    seep_config::GroupMember::Node {
                        name: "violator".into(),
                    },
                    seep_config::GroupMember::Node {
                        name: "legacy".into(),
                    },
                    seep_config::GroupMember::Node {
                        name: "unknown".into(),
                    },
                ],
                slo: Some(SloPolicy {
                    p95_ms: Some(50),
                    loss_ratio: Some(0.01),
                    loss_penalty_ms: None,
                }),
            }],
            rules: vec![],
        });
        engine.update_link_quality("ok", 30, 0.0);
        engine.update_link_quality("violator", 80, 0.02);
        engine.latency_stats.insert("legacy".into(), 90);

        let g = &engine.group_quality_report()[0];
        let by_name = |n: &str| g.members.iter().find(|m| m.name == n).unwrap();
        assert_eq!(by_name("ok").gate_pass, Some(true));
        assert_eq!(by_name("violator").gate_pass, Some(false));
        // legacy/unknown 自动合规但无门判定语义 → None
        assert_eq!(by_name("legacy").gate_pass, None);
        assert_eq!(by_name("unknown").gate_pass, None);
        // 选点：violator 越门被过滤 → ok(30) 胜 legacy(90)（与 select 同源）
        assert_eq!(g.selected.as_deref(), Some("ok"));
    }

    /// O-slo1 观测面：门内空 → 回全体候选（不 dead-end）；非 latency 组
    /// 不产 score/gate/selected（数据如实列出，选路语义不外推）
    #[test]
    fn quality_report_no_dead_end_and_non_latency_neutral() {
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![
                PolicyGroup {
                    name: "all-bad".into(),
                    strategy: Strategy::Latency,
                    members: vec![
                        seep_config::GroupMember::Node { name: "a".into() },
                        seep_config::GroupMember::Node { name: "b".into() },
                    ],
                    slo: Some(SloPolicy {
                        p95_ms: Some(10),
                        loss_ratio: None,
                        loss_penalty_ms: None,
                    }),
                },
                PolicyGroup {
                    name: "fixed-g".into(),
                    strategy: Strategy::Fixed,
                    members: vec![seep_config::GroupMember::Node { name: "x".into() }],
                    slo: Some(SloPolicy {
                        p95_ms: Some(10),
                        loss_ratio: None,
                        loss_penalty_ms: None,
                    }),
                },
            ],
            rules: vec![],
        });
        engine.update_link_quality("a", 80, 0.0);
        engine.update_link_quality("b", 60, 0.0);
        engine.update_link_quality("x", 70, 0.0);

        let report = engine.group_quality_report();
        let all_bad = &report[0];
        // 门内空 → 全体候选取最低分：b(60) < a(80)
        assert_eq!(all_bad.selected.as_deref(), Some("b"));
        assert_eq!(
            all_bad
                .members
                .iter()
                .find(|m| m.name == "a")
                .unwrap()
                .gate_pass,
            Some(false)
        );

        let fixed = &report[1];
        assert_eq!(fixed.strategy, "fixed");
        assert_eq!(fixed.selected, None);
        let x = fixed.members.iter().find(|m| m.name == "x").unwrap();
        // 非 latency：原始质量如实，score/gate 不计算
        assert_eq!(x.source, "real");
        assert_eq!(x.score, None);
        assert_eq!(x.gate_pass, None);
    }

    /// G0-1 目的 IP-CIDR 匹配回归：IP 字面量按前缀命中/不命中；主机形式
    /// 按精确地址；域名目标不命中（路由面不做 DNS）。
    #[tokio::test]
    async fn ip_cidr_matches_target_ip_prefix() {
        use seep_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "private-net".into(),
                matches: vec![MatchCondition::IpCidr {
                    cidrs: vec![
                        "10.0.0.0/8".into(),
                        "192.168.1.0/24".into(),
                        "2001:db8::/32".into(),
                        "203.0.113.9".into(),
                    ],
                }],
                target: "proxy".into(),
            }],
        });

        async fn hit(engine: &RoutingEngine, host: &str) -> String {
            let ctx = FlowContext {
                id: FlowId::new(),
                target: FlowTarget {
                    host: host.to_string(),
                    port: 443,
                    proto: TargetProto::Tcp,
                },
                metadata: Default::default(),
            };
            engine.route(ctx).await.unwrap().final_node().to_string()
        }

        assert_eq!(hit(&engine, "10.1.2.3").await, "proxy", "IPv4 前缀命中");
        assert_eq!(hit(&engine, "192.168.1.254").await, "proxy", "IPv4 边界内命中");
        assert_eq!(hit(&engine, "2001:db8:1::9").await, "proxy", "IPv6 前缀命中");
        assert_eq!(hit(&engine, "203.0.113.9").await, "proxy", "主机形式精确命中");
        assert_eq!(hit(&engine, "11.0.0.1").await, "direct", "CIDR 外不命中");
        assert_eq!(hit(&engine, "203.0.113.10").await, "direct", "主机形式不匹配");
        assert_eq!(hit(&engine, "example.com").await, "direct", "域名目标不命中");
    }
}
