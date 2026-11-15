use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use rand::{seq::SliceRandom, thread_rng, Rng};
use rillane_config::{
    GroupDescriptor, GroupDescriptorMember, MatchCondition, PolicyGroup, RouteRule, RoutingConfig,
    RuleSetLibrary, SloPolicy, Strategy,
};
use rillane_core::{FlowContext, FlowRouter, RouteDecision, TargetProto};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::interval;

mod geo;
pub use geo::{geoip_country, host_to_ip, GeoDatabases, GeoSiteDb};

/// G0-2 域名正则热路径编译缓存（审核发现 2026-11-04）：同一 pattern 反复
/// 出现的规则源在每流逐条 `Regex::new` 会重复编译并占用 Tokio 工作线程。
/// 引擎级缓存只编译一次；命中 O(1)（DashMap get + clone Arc）。并发 miss
/// 经 `entry` 单例编译——后者等待前者，返回的 Arc 恒为 map 内实例，不多次
/// 编译同一 pattern（审核发现 2026-11-05）。`reload` 按新配置保留仍用
/// pattern、剔除失效 pattern，不随历史规则集差异累积（审核发现 2026-11-05）。
fn cached_regex(
    cache: &DashMap<String, Arc<regex::Regex>>,
    pattern: &str,
) -> Option<Arc<regex::Regex>> {
    cached_regex_with(cache, pattern, |pattern| {
        regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .ok()
            .map(Arc::new)
    })
}

fn cached_regex_with(
    cache: &DashMap<String, Arc<regex::Regex>>,
    pattern: &str,
    compile: impl Fn(&str) -> Option<Arc<regex::Regex>>,
) -> Option<Arc<regex::Regex>> {
    if let Some(re) = cache.get(pattern) {
        return Some(Arc::clone(&re));
    }
    match cache.entry(pattern.to_string()) {
        dashmap::mapref::entry::Entry::Occupied(occupied) => Some(Arc::clone(occupied.get())),
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            let re = compile(pattern)?;
            vacant.insert(Arc::clone(&re));
            Some(re)
        }
    }
}

/// 递归收集条件树内全部 `DomainRegex` pattern（`prune_regex_cache` 用）。
fn collect_regex_patterns(conds: &[MatchCondition], out: &mut HashSet<String>) {
    for cond in conds {
        match cond {
            MatchCondition::Any { conditions } => {
                for c in conditions {
                    collect_regex_patterns(std::slice::from_ref(c), out);
                }
            }
            MatchCondition::Not { condition } => {
                collect_regex_patterns(std::slice::from_ref(condition.as_ref()), out)
            }
            MatchCondition::DomainRegex { patterns } => {
                for p in patterns {
                    out.insert(p.clone());
                }
            }
            _ => {}
        }
    }
}

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

/// 单成员实时质量（O-slo1 观测面：控制面 `/routing/stats` 与 `rillanectl group`
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
        Strategy::Fallback => "fallback",
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
    // ——slo-scoring.md §2 D-3：rillane-runtime 桥自 MeshRegistry 聚合推进
    // （update_link_quality），rillane-routing 保持零 rillane-mesh 依赖（D-4）
    link_quality: DashMap<String, (u32, f64, std::time::Instant)>,
    // 域名正则编译缓存（G0-2）：`DomainRegex` pattern → 编译后 Regex。
    // 引擎级缓存，`reload` 时按新配置 prune 失效 pattern，避免热更新/订阅
    // 刷新后历史 pattern 占内存累积（审核发现 2026-11-05）。
    regex_cache: DashMap<String, Arc<regex::Regex>>,
    // GeoIP/GeoSite 数据库容器（G0-2）：懒加载，路径取配置
    // `routing.geoip_db`/`routing.geosite_db`。`reload` 时路径未变复用已
    // 加载句柄；路径变化重建容器（热更路径切换生效）。`RwLock` 使
    // `reload(&self)` 可原地替换（route 面读锁取当前容器）。
    geo: RwLock<Arc<GeoDatabases>>,
    // url-test 成员探测句柄（G1-9）：运行时注入——按节点名经其出口对
    // 探测目标做 HTTP 探测，返回 RTT 毫秒。None = 未注入（无探测，默认
    // 健康兜底；此前此处的随机 mock 已删——随机假数据比无数据更害）。
    probe: RwLock<Option<NodeProbeFn>>,
    // 组级最近探测轮时刻（G1-9）：组名 → 最近一轮 perform 的 Instant，
    // url_test.interval_secs 到期才探测（任务 tick 10s 粒度对齐组间隔）。
    urltest_last: RwLock<HashMap<String, std::time::Instant>>,
}

/// 成员探测句柄类型（G1-9）：（节点名, 探测 host, 端口, 路径, 超时）→
/// RTT 毫秒 / Err（不健康）。运行时注入——内部经该节点出口以探测目标为
/// target 走 forward 管道（见 rillane-core `probe_via_output`）。
pub type NodeProbeFn = Arc<
    dyn Fn(
            &str,
            &str,
            u16,
            &str,
            Duration,
        ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send>>
        + Send
        + Sync,
>;

/// 拆分探测目标 `host:port`（G1-9）：与 rillane-config `UrlTestConfig::validate`
/// 同一语义（最后一个 `:` 分隔；IPv6 字面量本方案不支持，validate 已挡）。
/// 解析失败返回 None——探测循环整组跳过而非用坏数据污染健康表。
fn split_probe_target(probe: &str) -> Option<(String, u16)> {
    let (host, port_str) = probe.rsplit_once(':')?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((host.to_string(), port))
}

/// 拼接路由原因与恢复说明（RIL-011）：两者都有时以「；」衔接，
/// 恢复说明不吞掉原有 reason。
fn merge_reason(reason: Option<String>, note: Option<String>) -> Option<String> {
    match (reason, note) {
        (Some(r), Some(n)) => Some(format!("{r}；{n}")),
        (Some(r), None) => Some(r),
        (None, Some(n)) => Some(n),
        (None, None) => None,
    }
}

impl RoutingEngine {
    pub fn new(config: RoutingConfig) -> Self {
        let geo = Arc::new(GeoDatabases::new(
            config.geoip_db.clone(),
            config.geosite_db.clone(),
        ));
        let engine = Self {
            config: RwLock::new(config),
            group_cache: RwLock::new(HashMap::new()),
            round_robin_counters: RwLock::new(HashMap::new()),
            health_status: DashMap::new(),
            latency_stats: DashMap::new(),
            bandwidth_stats: DashMap::new(),
            link_quality: DashMap::new(),
            regex_cache: DashMap::new(),
            geo: RwLock::new(geo),
            probe: RwLock::new(None),
            urltest_last: RwLock::new(HashMap::new()),
        };
        engine.build_group_cache();
        engine
    }

    /// 注入成员探测句柄（G1-9）：运行时构建出口面后调用一次；重复注入
    /// 覆盖旧句柄（热更重建出口面场景）。
    pub fn set_probe_handler(&self, probe: NodeProbeFn) {
        *self.probe.write().expect("probe lock poisoned") = Some(probe);
    }

    pub fn reload(&self, next: RoutingConfig) {
        // G0-2：GeoIP/GeoSite 路径随配置热更。路径未变保留已加载句柄
        // （懒加载只做一次）；路径变化重建容器（新路径下次匹配时加载）。
        let need_new_geo = {
            let cur = self.config.read().expect("routing poisoned");
            cur.geoip_db != next.geoip_db || cur.geosite_db != next.geosite_db
        };
        if need_new_geo {
            *self.geo.write().expect("geo lock poisoned") = Arc::new(GeoDatabases::new(
                next.geoip_db.clone(),
                next.geosite_db.clone(),
            ));
        }
        // RIL-011：更新不随意清空有效选择——selections 是用户运行态，
        // 新配置未携带的组保留旧选择（新配置显式携带的键以新配置为准）。
        // 所选成员已删除的陈旧选择由 Fixed 求值期恢复策略清除。
        let next = {
            let cur = self.config.read().expect("routing poisoned");
            let mut next = next;
            for (group, sel) in &cur.selections {
                next.selections
                    .entry(group.clone())
                    .or_insert_with(|| sel.clone());
            }
            next
        };
        *self.config.write().expect("routing poisoned") = next;
        self.build_group_cache();
        self.clear_round_robin_counters();
        self.prune_regex_cache();
    }

    /// 按当前配置保留仍被引用的正则 pattern，剔除失效 pattern（配置热更新/
    /// 订阅刷新后旧规则集 pattern 不再占内存）。O(patterns) 遍历取仍用集合，
    /// O(cache) 剔除；热更新低频，不构成热路径开销。
    fn prune_regex_cache(&self) {
        let config = self.snapshot();
        let mut live = HashSet::new();
        for rule in &config.rules {
            collect_regex_patterns(&rule.matches, &mut live);
        }
        self.regex_cache
            .retain(|pattern, _| live.contains(pattern.as_str()));
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
                rillane_config::GroupMember::Node { name } => {
                    let is_healthy = self.get_node_health(name);
                    members.push(GroupDescriptorMember::Node {
                        name: name.clone(),
                        weight: 1,
                        is_healthy,
                    });
                }
                rillane_config::GroupMember::Group { name } => {
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
                rillane_config::GroupMember::WeightedNode { name, weight } => {
                    let is_healthy = self.get_node_health(name);
                    members.push(GroupDescriptorMember::Node {
                        name: name.clone(),
                        weight: *weight,
                        is_healthy,
                    });
                }
                rillane_config::GroupMember::WeightedGroup { name, weight } => {
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
                // RIL-009：provider 成员展开为 provider 当前提供的节点集。
                // 库未装入/来源失效 = 空集，即失效成员退出新流候选——
                // 该组不因此伪装出成员（与 RuleSetRef 缺库恒不命中同语义）。
                rillane_config::GroupMember::Provider { name } => {
                    for node in config.provider_nodes.nodes(name) {
                        let is_healthy = self.get_node_health(&node);
                        members.push(GroupDescriptorMember::Node {
                            name: node,
                            weight: 1,
                            is_healthy,
                        });
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

    /// 手动标记节点健康态（RIL-011 求值面：控制面/运维手动摘除节点；
    /// 与探活任务写入同一健康缓存，TTL 内生效）。RIL-012：写入后重建
    /// 组描述符缓存——成员 `is_healthy` 在构建期烙进描述符，不重建则
    /// 摘除/恢复对后续路由不可见（健康状态必须可核验）。
    pub fn set_node_health(&self, node_name: &str, is_healthy: bool) {
        self.health_status.insert(
            node_name.to_string(),
            (is_healthy, std::time::Instant::now()),
        );
        self.build_group_cache();
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

    /// 执行健康检查（G1-9）：只探测配置了 `url_test` 的策略组，组级按
    /// `interval_secs` 门控轮转（探测任务 10s tick 粒度）；其余组不动。
    /// 未注入探测句柄时整体 no-op——不产生任何假健康/延迟数据（此前
    /// 此处的随机 mock 已删：随机假数据比无数据更害选路）。
    pub async fn perform_health_checks(&self) {
        let probe = self.probe.read().expect("probe lock poisoned").clone();
        let Some(probe) = probe else {
            return;
        };

        let config = self.snapshot();
        let now = std::time::Instant::now();
        for group in &config.groups {
            let Some(url_test) = &group.url_test else {
                continue;
            };

            // 组级间隔门控：未到期整组跳过本轮
            {
                let last = self
                    .urltest_last
                    .read()
                    .expect("urltest_last lock poisoned");
                if let Some(last) = last.get(&group.name) {
                    if now.duration_since(*last) < Duration::from_secs(url_test.interval_secs) {
                        continue;
                    }
                }
            }
            self.urltest_last
                .write()
                .expect("urltest_last lock poisoned")
                .insert(group.name.clone(), now);

            let Some((host, port)) = split_probe_target(&url_test.probe) else {
                continue;
            };
            let path = url_test.path.clone();
            let timeout = Duration::from_millis(url_test.timeout_ms);

            // 逐成员串行探测：并发探测互相抢带宽会失真 RTT
            for member in &group.members {
                // RIL-009：provider 成员是来源引用而非节点，不能作为
                // 探测目标（其展开节点随库装入，装入后按节点名探测）
                if matches!(member, rillane_config::GroupMember::Provider { .. }) {
                    continue;
                }
                let node_name = member.as_name();
                match probe(&node_name, &host, port, &path, timeout).await {
                    Ok(rtt) => {
                        self.health_status.insert(node_name.clone(), (true, now));
                        self.latency_stats
                            .insert(node_name, (rtt.min(u32::MAX as u64)) as u32);
                    }
                    Err(_) => {
                        self.health_status.insert(node_name, (false, now));
                    }
                }
            }
        }
        // RIL-012：探测结果写入健康缓存后重建组描述符缓存，让本轮
        // 探活在下一次路由即刻可见（否则描述符烙的是上一轮健康态，
        // url-test/fallback 探活形同虚设）
        self.build_group_cache();
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

    /// 更新节点真链路质量（slo-scoring.md §2 D-3：rillane-runtime 桥推进，
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
                // RIL-009：provider 成员按节点库展开，观测面与求值面同口径
                // （库未装入 = 空集，该 provider 不贡献候选）
                let mut names: Vec<String> = Vec::new();
                for m in &group.members {
                    match m {
                        rillane_config::GroupMember::Node { name }
                        | rillane_config::GroupMember::WeightedNode { name, .. } => names.push(name.clone()),
                        rillane_config::GroupMember::Group { name }
                        | rillane_config::GroupMember::WeightedGroup { name, .. } => names.push(name.clone()),
                        rillane_config::GroupMember::Provider { name } => {
                            for node in config.provider_nodes.nodes(name) {
                                names.push(node);
                            }
                        }
                    }
                }
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

    /// 获取节点最近探测 RTT（毫秒）（G1-9 url-test 写入，探测失败不清除
    /// 旧值——健康表已单独标不健康，选路看健康位）
    pub fn get_node_latency(&self, node_name: &str) -> Option<u32> {
        self.latency_stats.get(node_name).map(|v| *v.value())
    }
}

#[async_trait]
impl FlowRouter for RoutingEngine {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        let config = self.snapshot();
        let geo = self.geo.read().expect("geo lock poisoned").clone();
        for rule in &config.rules {
            // RIL-014：规则按数组序首匹配——先声明的规则先参与匹配，
            // RULE-SET 引用按 config.rule_sets 库解析（载荷缺席恒不命中）。
            if matches_rule(&self.regex_cache, &geo, &config.rule_sets, rule, &ctx) {
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

    /// RIL-011 select 保真：`Strategy::Fixed` 的用户选择面。
    /// 选择命中组成员集（**全成员集，含不健康**——显式手动点选不被健康
    /// 门槛二次猜测，与 Clash select 语义一致）；所选成员已被更新/删除
    /// 移除 → 明确恢复策略：清除引擎配置副本里的陈旧选择、回落首健康
    /// 成员、回落原因显式返回（由调用方并入 decision.reason，不静默）。
    fn apply_fixed_selection<'a>(
        &self,
        descriptor: &'a GroupDescriptor,
        healthy: &[&'a GroupDescriptorMember],
    ) -> (Option<&'a GroupDescriptorMember>, Option<String>) {
        let selection = {
            let config = self.config.read().expect("routing poisoned");
            config.selections.get(&descriptor.name).cloned()
        };
        let Some(selected) = selection else {
            return (healthy.first().copied(), None);
        };
        if let Some(member) = descriptor.members.iter().find(|m| m.as_name() == selected) {
            return (Some(member), None);
        }
        // 恢复策略：陈旧选择清除（不反复报告同一失效选择）
        {
            let mut config = self.config.write().expect("routing poisoned");
            config.selections.remove(&descriptor.name);
        }
        (
            healthy.first().copied(),
            Some(format!(
                "组 {} 所选成员 `{selected}` 已不存在（更新/删除），清除选择并回落首健康成员",
                descriptor.name
            )),
        )
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

        let mut fixed_note: Option<String> = None;
        let selected_member = match descriptor.strategy {
            Strategy::Fixed => {
                // RIL-011 select 保真：用户选择优先；所选成员已被移除走
                // 明确恢复策略（清除选择 + 回落首健康成员 + 原因显式）
                let (member, note) = self.apply_fixed_selection(descriptor, &healthy_members);
                fixed_note = note;
                member
            }
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
            // RIL-012 按序回退：healthy_members 保声明序（filter 不重排），
            // 首个健康成员即答案——首位下线顺延次位，首位恢复即回首位；
            // 随机性在此策略无位置（Clash fallback 口径）
            Strategy::Fallback => healthy_members.first().copied(),
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
                decision.reason = merge_reason(reason, fixed_note);
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

fn matches_rule(
    regex_cache: &DashMap<String, Arc<regex::Regex>>,
    geo: &GeoDatabases,
    rule_sets: &RuleSetLibrary,
    rule: &RouteRule,
    ctx: &FlowContext,
) -> bool {
    rule.matches
        .iter()
        .all(|matcher| matches_condition(regex_cache, geo, rule_sets, matcher, ctx))
}

/// 单条件匹配（递归支持 Any/Not 逻辑组合与 RuleSetRef 引用展开）。
fn matches_condition(
    regex_cache: &DashMap<String, Arc<regex::Regex>>,
    geo: &GeoDatabases,
    rule_sets: &RuleSetLibrary,
    cond: &MatchCondition,
    ctx: &FlowContext,
) -> bool {
    match cond {
        MatchCondition::Any { conditions } => conditions
            .iter()
            .any(|c| matches_condition(regex_cache, geo, rule_sets, c, ctx)),
        MatchCondition::Not { condition } => {
            !matches_condition(regex_cache, geo, rule_sets, condition, ctx)
        }
        MatchCondition::DomainSuffix { values } => {
            let host = ctx.target.host.to_ascii_lowercase();
            values
                .iter()
                .any(|suffix| host.ends_with(&suffix.to_ascii_lowercase()))
        }
        MatchCondition::DomainKeyword { values } => {
            let host = ctx.target.host.to_ascii_lowercase();
            values
                .iter()
                .any(|keyword| host.contains(&keyword.to_ascii_lowercase()))
        }
        MatchCondition::DomainFull { values } => {
            let host = ctx.target.host.to_ascii_lowercase();
            values.iter().any(|v| host == v.to_ascii_lowercase())
        }
        MatchCondition::DomainRegex { patterns } => patterns.iter().any(|pattern| {
            // 构建期 `RoutingConfig::validate` 已拦截非法 pattern；此处
            // `unwrap_or(false)` 仅为防御面（程序化构造绕过 validate 时
            // 不 panic）。编译结果走引擎级缓存（`regex_cache`），同一
            // pattern 只编译一次，`reload` 时按新配置 prune 失效 pattern。
            cached_regex(regex_cache, pattern)
                .map(|re| re.is_match(&ctx.target.host))
                .unwrap_or(false)
        }),
        MatchCondition::Geoip { country } => {
            // G0-2：数据库查询替换注解等价物。目标为域名时不解析 DNS
            // （路由面不做解析），恒不命中；IP 字面量查 mmdb 国家码。
            let Some(ip) = host_to_ip(&ctx.target.host) else {
                return false;
            };
            let Some(db) = geo.geoip() else {
                return false;
            };
            geoip_country(&db, ip)
                .map(|c| c.eq_ignore_ascii_case(country))
                .unwrap_or(false)
        }
        MatchCondition::GeoSite { category } => {
            // G0-2：GeoSite 站点类别按目标主机查询 `.dat` 数据库。
            // 域名/IP 均可查询（域名条目按域名比较；IP 字面量对域名
            // 条目恒不命中——v2fly 站点库仅域名面）。
            let Some(db) = geo.geosite() else {
                return false;
            };
            db.matches(category, &ctx.target.host)
        }
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
        // （= /proc/<pid>/comm，内核截断 15 字节）精确匹配（区分大小写
        // ——RIL-015 大小写语义独立，不折叠）；注解缺席恒不命中
        MatchCondition::Process { values } => ctx
            .metadata
            .annotations
            .get("process.name")
            .map(|name| values.iter().any(|v| v == name))
            .unwrap_or(false),
        // RIL-015：进程可执行路径——`process.path` 注解全串精确比较
        // （区分大小写、不做 comm 截断）；路径不可得时注解缺席恒不命中，
        // 不以短名冒充路径（ProcessIdentity 同口径）
        MatchCondition::ProcessPath { values } => ctx
            .metadata
            .annotations
            .get("process.path")
            .map(|path| values.iter().any(|v| v == path))
            .unwrap_or(false),
        // RIL-014：源端口——本机五元组源端口经 `net.src_port` 注解进入
        // 求值面（与 client.cidr/process.name 同一注入先例）；注解缺席
        // 恒不命中。与 `Port`（目标端口）语义严格分离。
        MatchCondition::SrcPort { values } => ctx
            .metadata
            .annotations
            .get("net.src_port")
            .and_then(|v| v.parse::<u16>().ok())
            .map(|src| values.contains(&src))
            .unwrap_or(false),
        // RIL-014：传输协议——目标 proto 精确归类（tcp/udp/quic），大小写
        // 不敏感；Quic 属 UDP 面，但此处按 proto 字面归类不折叠。
        MatchCondition::Proto { protocols } => {
            let actual = match ctx.target.proto {
                TargetProto::Tcp => "tcp",
                TargetProto::Udp => "udp",
                TargetProto::Quic => "quic",
            };
            protocols
                .iter()
                .any(|p| p.eq_ignore_ascii_case(actual))
        }
        // RIL-014：规则集引用——按名查 `routing.rule_sets` 库，库中条件
        // 任一命中即命中（递归支持逻辑组合）；无此名（载荷未加载/来源
        // 失效）恒不命中——与 GeoSite 缺数据库同一语义，不伪装命中。
        MatchCondition::RuleSetRef { name } => rule_sets
            .get(name)
            .map(|entry| {
                entry
                    .conditions
                    .iter()
                    .any(|c| matches_condition(regex_cache, geo, rule_sets, c, ctx))
            })
            .unwrap_or(false),
    }
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    /// §7-1：SloPolicy 值域 validate（rillane-config 层）
    #[test]
    fn slo_policy_validate_ranges() {
        use rillane_config::RoutingConfig as Cfg;
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
                url_test: None,
            }],
            rules: vec![],
            ..Default::default()
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
                url_test: None,
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
                url_test: None,
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
        use rillane_core::{FlowId, FlowMetadata, FlowTarget, TargetProto};

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
            ..Default::default()
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

        // 不命中：仅大小写不同（comm 比较区分大小写，不折叠）
        ctx.metadata
            .annotations
            .insert("process.name".into(), "CS2".into());
        assert_eq!(
            engine.route(ctx.clone()).await.expect("route").final_node(),
            "direct",
            "comm 比较区分大小写"
        );

        // 不命中：注解缺席（非 TUN 流 / 归因 miss）→ 落默认
        ctx.metadata.annotations.clear();
        assert_eq!(
            engine.route(ctx).await.expect("route").final_node(),
            "direct",
            "注解缺席应落默认节点"
        );
    }

    /// RIL-015：进程路径条件——`process.path` 注解全串精确相等命中；
    /// 仅短名（comm）不得冒充路径；大小写不同不命中；注解缺席恒不命中。
    #[tokio::test]
    async fn process_path_condition_matches_full_path_exactly() {
        use rillane_core::{FlowId, FlowMetadata, FlowTarget, TargetProto};

        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            rules: vec![RouteRule {
                name: "browser".into(),
                matches: vec![MatchCondition::ProcessPath {
                    values: vec!["/usr/bin/firefox".into()],
                }],
                target: "browse-node".into(),
            }],
            ..Default::default()
        });
        let mut ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "203.0.113.9".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: FlowMetadata::default(),
        };

        // 命中：全串路径精确相等
        ctx.metadata
            .annotations
            .insert("process.path".into(), "/usr/bin/firefox".into());
        assert_eq!(
            engine.route(ctx.clone()).await.expect("route").final_node(),
            "browse-node"
        );

        // 不命中：只有短名（comm），不得冒充路径
        ctx.metadata.annotations.clear();
        ctx.metadata
            .annotations
            .insert("process.name".into(), "firefox".into());
        assert_eq!(
            engine.route(ctx.clone()).await.expect("route").final_node(),
            "direct",
            "短名不得替代全路径命中"
        );

        // 不命中：大小写不同（不折叠）
        ctx.metadata
            .annotations
            .insert("process.path".into(), "/usr/bin/Firefox".into());
        assert_eq!(
            engine.route(ctx.clone()).await.expect("route").final_node(),
            "direct",
            "路径比较区分大小写"
        );

        // 不命中：注解缺席
        ctx.metadata.annotations.clear();
        assert_eq!(
            engine.route(ctx).await.expect("route").final_node(),
            "direct"
        );
    }

    /// RIL-014：源端口条件——`net.src_port` 注解命中/不命中/缺席三态，
    /// 与目标端口（Port）语义分离。
    #[tokio::test]
    async fn src_port_matches_annotation_only() {
        use rillane_core::{FlowId, FlowMetadata, FlowTarget, TargetProto};

        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            rules: vec![RouteRule {
                name: "local-src".into(),
                matches: vec![MatchCondition::SrcPort {
                    values: (9000..=9010).collect(),
                }],
                target: "src-node".into(),
            }],
            ..Default::default()
        });
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "203.0.113.5".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: FlowMetadata::default(),
        };

        let mut hit = ctx.clone();
        hit.metadata
            .annotations
            .insert("net.src_port".into(), "9005".into());
        assert_eq!(
            engine.route(hit).await.expect("route").final_node(),
            "src-node",
            "源端口在区间内命中"
        );

        let mut miss = ctx;
        miss.metadata
            .annotations
            .insert("net.src_port".into(), "80".into());
        assert_eq!(
            engine.route(miss).await.expect("route").final_node(),
            "direct",
            "源端口不在区间落默认"
        );

        // 目标端口 443 不得让 SrcPort 规则误命中（语义分离）
        let no_annotation = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "203.0.113.5".into(),
                port: 9005,
                proto: TargetProto::Tcp,
            },
            metadata: FlowMetadata::default(),
        };
        assert_eq!(
            engine.route(no_annotation).await.expect("route").final_node(),
            "direct",
            "注解缺席恒不命中——目标端口值不得串入源端口条件"
        );
    }

    /// RIL-014：传输协议条件按目标 proto 精确归类。
    #[tokio::test]
    async fn proto_condition_matches_target_proto() {
        use rillane_core::{FlowId, FlowMetadata, FlowTarget, TargetProto};

        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            rules: vec![RouteRule {
                name: "udp-only".into(),
                matches: vec![MatchCondition::Proto {
                    protocols: vec!["udp".into()],
                }],
                target: "udp-node".into(),
            }],
            ..Default::default()
        });
        let ctx_for = |proto| FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "203.0.113.7".into(),
                port: 443,
                proto,
            },
            metadata: FlowMetadata::default(),
        };

        assert_eq!(
            engine
                .route(ctx_for(TargetProto::Udp))
                .await
                .expect("route")
                .final_node(),
            "udp-node"
        );
        assert_eq!(
            engine
                .route(ctx_for(TargetProto::Tcp))
                .await
                .expect("route")
                .final_node(),
            "direct",
            "tcp 不命中 udp 条件"
        );
    }

    /// RIL-014：规则集引用按 `routing.rule_sets` 库解析——命中、不命中、
    /// 悬空引用（库中无此名）恒不命中不 panic；首匹配顺序 = 声明顺序。
    #[tokio::test]
    async fn rule_set_ref_resolves_library_and_first_match_order() {
        use rillane_core::{FlowId, FlowMetadata, FlowTarget, TargetProto};

        let mut rule_sets = RuleSetLibrary::new();
        rule_sets.insert(
            "ads",
            vec![
                MatchCondition::DomainSuffix {
                    values: vec!["ads.example".into()],
                },
                MatchCondition::DomainFull {
                    values: vec!["tracker.example".into()],
                },
            ],
        );
        rule_sets.insert(
            "blocked",
            vec![MatchCondition::Port {
                values: vec![6881],
            }],
        );

        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            rules: vec![
                RouteRule {
                    name: "ads-block".into(),
                    matches: vec![MatchCondition::RuleSetRef {
                        name: "ads".into(),
                    }],
                    target: "reject".into(),
                },
                RouteRule {
                    name: "p2p-block".into(),
                    matches: vec![MatchCondition::RuleSetRef {
                        name: "blocked".into(),
                    }],
                    target: "reject".into(),
                },
                RouteRule {
                    name: "dangling".into(),
                    matches: vec![MatchCondition::RuleSetRef {
                        name: "ghost".into(),
                    }],
                    target: "reject".into(),
                },
            ],
            rule_sets,
            ..Default::default()
        });
        let ctx_for = |host: &str, port: u16| FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: host.into(),
                port,
                proto: TargetProto::Tcp,
            },
            metadata: FlowMetadata::default(),
        };

        // 首匹配：域名命中第一条（规则集任一条件命中即命中）
        assert_eq!(
            engine
                .route(ctx_for("sub.ads.example", 443))
                .await
                .expect("route")
                .final_node(),
            "reject",
            "首条规则集引用命中"
        );
        // 第二条端口条件（同 reject 目标，用默认旁证顺序：改经端口命中需
        // 上面域名不命中——tracker.example 只落 full 条件仍在 ads 库）
        assert_eq!(
            engine
                .route(ctx_for("other.example", 6881))
                .await
                .expect("route")
                .final_node(),
            "reject",
            "第二条规则集（端口）命中"
        );
        // 悬空引用恒不命中 → 落默认
        assert_eq!(
            engine
                .route(ctx_for("nothing.example", 80))
                .await
                .expect("route")
                .final_node(),
            "direct",
            "库中无此名的引用恒不命中"
        );
        // 规则集内 full 相等（不含子域）验证：host=tracker.example 命中，
        // host=sub.tracker.example 不命中（走默认）
        assert_eq!(
            engine
                .route(ctx_for("sub.tracker.example", 443))
                .await
                .expect("route")
                .final_node(),
            "direct",
            "DomainFull 不含子域语义在规则集内保持"
        );
        assert_eq!(
            engine
                .route(ctx_for("tracker.example", 443))
                .await
                .expect("route")
                .final_node(),
            "reject",
            "DomainFull 精确相等命中"
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
                    rillane_config::GroupMember::Node {
                        name: "real".into(),
                    },
                    rillane_config::GroupMember::Node {
                        name: "legacy".into(),
                    },
                    rillane_config::GroupMember::Node {
                        name: "unknown".into(),
                    },
                ],
                slo: None,
                url_test: None,
            }],
            rules: vec![],
            ..Default::default()
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
                    rillane_config::GroupMember::Node { name: "ok".into() },
                    rillane_config::GroupMember::Node {
                        name: "violator".into(),
                    },
                    rillane_config::GroupMember::Node {
                        name: "legacy".into(),
                    },
                    rillane_config::GroupMember::Node {
                        name: "unknown".into(),
                    },
                ],
                slo: Some(SloPolicy {
                    p95_ms: Some(50),
                    loss_ratio: Some(0.01),
                    loss_penalty_ms: None,
                }),
                url_test: None,
            }],
            rules: vec![],
            ..Default::default()
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
                        rillane_config::GroupMember::Node { name: "a".into() },
                        rillane_config::GroupMember::Node { name: "b".into() },
                    ],
                    slo: Some(SloPolicy {
                        p95_ms: Some(10),
                        loss_ratio: None,
                        loss_penalty_ms: None,
                    }),
                    url_test: None,
                },
                PolicyGroup {
                    name: "fixed-g".into(),
                    strategy: Strategy::Fixed,
                    members: vec![rillane_config::GroupMember::Node { name: "x".into() }],
                    slo: Some(SloPolicy {
                        p95_ms: Some(10),
                        loss_ratio: None,
                        loss_penalty_ms: None,
                    }),
                    url_test: None,
                },
            ],
            rules: vec![],
            ..Default::default()
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
        use rillane_core::{FlowId, FlowTarget, TargetProto};
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
            ..Default::default()
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
        assert_eq!(
            hit(&engine, "192.168.1.254").await,
            "proxy",
            "IPv4 边界内命中"
        );
        assert_eq!(
            hit(&engine, "2001:db8:1::9").await,
            "proxy",
            "IPv6 前缀命中"
        );
        assert_eq!(
            hit(&engine, "203.0.113.9").await,
            "proxy",
            "主机形式精确命中"
        );
        assert_eq!(hit(&engine, "11.0.0.1").await, "direct", "CIDR 外不命中");
        assert_eq!(
            hit(&engine, "203.0.113.10").await,
            "direct",
            "主机形式不匹配"
        );
        assert_eq!(
            hit(&engine, "example.com").await,
            "direct",
            "域名目标不命中"
        );
    }

    /// G0-2 逻辑规则回归：`Any`（OR）与 `Not`（NOT）语义——顶层 `matches`
    /// 仍为 AND；Any 内任一命中即命中；Not 内不命中即命中。
    #[tokio::test]
    async fn logical_any_not_condition_semantics() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![
                RouteRule {
                    name: "ads-or-game".into(),
                    matches: vec![MatchCondition::Any {
                        conditions: vec![
                            MatchCondition::DomainSuffix {
                                values: vec!["ads.com".into()],
                            },
                            MatchCondition::DomainSuffix {
                                values: vec!["game.net".into()],
                            },
                        ],
                    }],
                    target: "block".into(),
                },
                RouteRule {
                    name: "not-private".into(),
                    matches: vec![MatchCondition::Not {
                        condition: Box::new(MatchCondition::IpCidr {
                            cidrs: vec!["10.0.0.0/8".into()],
                        }),
                    }],
                    target: "proxy".into(),
                },
            ],
            ..Default::default()
        });

        async fn route_to(engine: &RoutingEngine, host: &str) -> String {
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

        assert_eq!(
            route_to(&engine, "x.ads.com").await,
            "block",
            "Any: 首项命中"
        );
        assert_eq!(
            route_to(&engine, "y.game.net").await,
            "block",
            "Any: 次项命中"
        );
        assert_eq!(
            route_to(&engine, "other.com").await,
            "proxy",
            "Any: 均不命中 → 下条"
        );
        // NOT(private): 非 10/8 命中 proxy；10/8 不命中 NOT → 落到 default
        assert_eq!(
            route_to(&engine, "8.8.8.8").await,
            "proxy",
            "Not: 非私网命中"
        );
        assert_eq!(
            route_to(&engine, "10.0.0.1").await,
            "direct",
            "Not: 私网反选"
        );
    }

    /// G0-2 域名正则匹配回归：`DomainRegex` 按 Rust `regex` 对目标 host
    /// `is_match`；合法 pattern 命中/不命中符合预期；非法 pattern 恒不命中
    /// （路由面不做构建期拒绝），落默认节点。
    #[tokio::test]
    async fn domain_regex_matches_target_host() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "ads-regex".into(),
                matches: vec![MatchCondition::DomainRegex {
                    patterns: vec![r"^ad\d+\.".into(), r"\.doubleclick\.net$".into()],
                }],
                target: "block".into(),
            }],
            ..Default::default()
        });

        async fn route_to(engine: &RoutingEngine, host: &str) -> String {
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

        assert_eq!(
            route_to(&engine, "ad123.example.com").await,
            "block",
            "^ad 前缀命中"
        );
        assert_eq!(
            route_to(&engine, "x.doubleclick.net").await,
            "block",
            "suffix 正则命中"
        );
        assert_eq!(route_to(&engine, "ads.com").await, "direct", "正则不命中");
    }

    /// G0-2 域名正则负形：非法 pattern（未闭合括号）恒不命中，落默认节点
    /// ——路由面惰性编译不做拒绝（构建期校验面拦截）。
    #[tokio::test]
    async fn domain_regex_invalid_pattern_never_matches() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "bad-regex".into(),
                matches: vec![MatchCondition::DomainRegex {
                    patterns: vec!["(unclosed".into()],
                }],
                target: "block".into(),
            }],
            ..Default::default()
        });
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: Default::default(),
        };
        let decision = engine.route(ctx).await.unwrap();
        assert_eq!(decision.final_node(), "direct");
    }

    /// G0-2 正则编译缓存回归（审核发现 2026-11-04：每流逐条同步重编译
    /// 增大连接建立延迟）：同一 pattern 首流编译后，次流经缓存命中——
    /// 结果一致即可观测缓存语义（DashMap 首写 + 后续读）。
    #[tokio::test]
    async fn domain_regex_cached_across_flows() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "cached".into(),
                matches: vec![MatchCondition::DomainRegex {
                    patterns: vec![r"^cached\.example\.com$".into()],
                }],
                target: "proxy".into(),
            }],
            ..Default::default()
        });
        let route_once = |host: &str| {
            let ctx = FlowContext {
                id: FlowId::new(),
                target: FlowTarget {
                    host: host.to_string(),
                    port: 443,
                    proto: TargetProto::Tcp,
                },
                metadata: Default::default(),
            };
            async { engine.route(ctx).await.unwrap().final_node().to_string() }
        };

        assert_eq!(route_once("cached.example.com").await, "proxy", "首流命中");
        assert_eq!(
            route_once("cached.example.com").await,
            "proxy",
            "次流经缓存命中"
        );
        assert_eq!(route_once("other.example.com").await, "direct", "不命中");
    }

    /// G0-2 域名匹配大小写口径回归：Suffix/Keyword/Full/Regex 四类统一
    /// ASCII 小写匹配——旧实现仅 Full 小写、Regex 原始大小写，四类分裂。
    #[tokio::test]
    async fn domain_match_conditions_are_case_insensitive() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![
                RouteRule {
                    name: "suffix".into(),
                    matches: vec![MatchCondition::DomainSuffix {
                        values: vec!["example.com".into()],
                    }],
                    target: "suffix-node".into(),
                },
                RouteRule {
                    name: "keyword".into(),
                    matches: vec![MatchCondition::DomainKeyword {
                        values: vec!["video".into()],
                    }],
                    target: "keyword-node".into(),
                },
                RouteRule {
                    name: "full".into(),
                    matches: vec![MatchCondition::DomainFull {
                        values: vec!["exact.org".into()],
                    }],
                    target: "full-node".into(),
                },
                RouteRule {
                    name: "regex".into(),
                    matches: vec![MatchCondition::DomainRegex {
                        // 审核发现 2026-11-05：pattern 含大写（`^AD\d+\.`）须仍
                        // 命中大写 host（`AD123.example.net`）——旧实现仅对
                        // host 小写而保留 pattern 大小写敏感，`^AD` 匹配
                        // `ad123` 失败，代理/拦截规则静默失效。
                        patterns: vec![r"^AD\d+\.".into()],
                    }],
                    target: "regex-node".into(),
                },
            ],
            ..Default::default()
        });

        async fn route_to(engine: &RoutingEngine, host: &str) -> String {
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

        assert_eq!(route_to(&engine, "WWW.Example.Com").await, "suffix-node");
        assert_eq!(route_to(&engine, "myVIDEO.net").await, "keyword-node");
        assert_eq!(route_to(&engine, "EXACT.Org").await, "full-node");
        assert_eq!(route_to(&engine, "AD123.example.net").await, "regex-node");
    }

    /// 审核发现 2026-11-05：进程级缓存永不剔除，热更新后旧规则集的
    /// pattern 永久残留并随差异缓慢累积。回归：`reload` 换新规则集后，
    /// 失效 pattern 被剔除，仍用 pattern 保留，且新旧路由语义正常。
    #[tokio::test]
    async fn reload_prunes_stale_domain_regex_cache() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "old".into(),
                matches: vec![MatchCondition::DomainRegex {
                    patterns: vec![r"^old\.example\.com$".into()],
                }],
                target: "proxy".into(),
            }],
            ..Default::default()
        });
        // 先经旧规则集路由，把旧 pattern 编入缓存。
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "old.example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: Default::default(),
        };
        assert_eq!(engine.route(ctx).await.unwrap().final_node(), "proxy");
        assert!(
            engine.regex_cache.contains_key(r"^old\.example\.com$"),
            "旧 pattern 应先入缓存"
        );
        engine.reload(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "new".into(),
                matches: vec![MatchCondition::DomainRegex {
                    patterns: vec![r"^new\.example\.com$".into()],
                }],
                target: "proxy".into(),
            }],
            ..Default::default()
        });
        assert!(
            !engine.regex_cache.contains_key(r"^old\.example\.com$"),
            "reload 后失效 pattern 应被剔除"
        );
        // 新 pattern 路由仍正常（缓存可再入新规则）。
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "new.example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: Default::default(),
        };
        assert_eq!(engine.route(ctx).await.unwrap().final_node(), "proxy");
    }

    /// 审核发现 2026-11-05：并发 miss 时两个线程各编译一次再 insert，后者
    /// 覆盖前者，返回的 Arc 与 map 内实例可能不同。回归：用引擎级 `entry`
    /// 单例写入，并发 miss 后 map 内恰有一条且返回同一 Arc 语义。由于
    /// `cached_regex` 私有，本测试通过缓存 map 数量 + 并发路由结果稳定性
    /// 验证。
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn cached_regex_concurrent_miss_is_single_instance_semantics() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = std::sync::Arc::new(RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "concurrent".into(),
                matches: vec![MatchCondition::DomainRegex {
                    patterns: vec![r"^concurrent\.example\.com$".into()],
                }],
                target: "proxy".into(),
            }],
            ..Default::default()
        }));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let engine = std::sync::Arc::clone(&engine);
            tasks.push(tokio::spawn(async move {
                let ctx = FlowContext {
                    id: FlowId::new(),
                    target: FlowTarget {
                        host: "concurrent.example.com".into(),
                        port: 443,
                        proto: TargetProto::Tcp,
                    },
                    metadata: Default::default(),
                };
                engine.route(ctx).await.unwrap().final_node().to_string()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), "proxy");
        }
        assert_eq!(
            engine.regex_cache.len(),
            1,
            "并发 miss 后缓存内应恰有一条 pattern"
        );
    }

    /// G0-2 回归：并发 miss 时同一 pattern 只编译一次。可注入 `compile`
    /// 计数使旧「get 后无条件 insert」实现的并发双编译确定性失败。
    #[test]
    fn cached_regex_concurrent_miss_compiles_once() {
        let cache = std::sync::Arc::new(DashMap::<String, Arc<regex::Regex>>::new());
        let compiles = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let pattern = r"^once\.example\.com$".to_string();
                let cache = std::sync::Arc::clone(&cache);
                let compiles = std::sync::Arc::clone(&compiles);
                std::thread::spawn(move || {
                    cached_regex_with(&cache, &pattern, |pattern| {
                        compiles.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        regex::Regex::new(pattern).ok().map(Arc::new)
                    })
                    .is_some()
                })
            })
            .collect();
        assert!(handles.into_iter().all(|handle| handle.join().unwrap()));
        assert_eq!(compiles.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(cache.len(), 1);
    }

    /// G0-2 路由面 GeoIP/GeoSite 集成：合成 mmdb/.dat 写入临时文件，引擎
    /// 以对应配置加载；IP 字面量按国家码分流、域名按 geosite 类别分流；
    /// 无数据库时条件恒不命中落默认节点。
    #[tokio::test]
    async fn geoip_geosite_routes_through_databases() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};

        // 合成 GeoIP Country mmdb：1.0.0.0/8 → CN。
        let mmdb_dir =
            std::env::temp_dir().join(format!("rillane-rt-geoip-{}", std::process::id()));
        std::fs::create_dir_all(&mmdb_dir).unwrap();
        let mmdb_path = mmdb_dir.join("cn.mmdb");
        let mut mmdb = maxminddb_writer::Database::default();
        mmdb.metadata.database_type = "GeoLite2-Country".to_string();
        mmdb.metadata.languages = vec!["en".to_string()];
        mmdb.metadata.binary_format_major_version = 2;
        let cn: maxminddb::geoip2::Country = maxminddb::geoip2::Country {
            country: maxminddb::geoip2::country::Country {
                iso_code: Some("CN"),
                ..Default::default()
            },
            ..Default::default()
        };
        let data = mmdb.insert_value(cn).unwrap();
        mmdb.insert_node(
            "1.0.0.0/8"
                .parse::<maxminddb_writer::paths::IpAddrWithMask>()
                .unwrap(),
            data,
        );
        let mut mmdb_buf = Vec::new();
        mmdb.write_to(&mut mmdb_buf).unwrap();
        std::fs::write(&mmdb_path, &mmdb_buf).unwrap();

        // 合成 GeoSite dat：cn 类别含 Domain=example.com、Full=exact.org。
        let dat_path = mmdb_dir.join("cn.dat");
        let geosite = geosite_rs::GeoSiteList {
            entry: vec![geosite_rs::GeoSite {
                country_code: "cn".into(),
                domain: vec![geosite_rs::Domain {
                    r#type: geosite_rs::domain::Type::Domain as i32,
                    value: "example.com".into(),
                    attribute: vec![],
                }],
            }],
        };
        std::fs::write(&dat_path, geosite_rs::encode_geosite(geosite)).unwrap();

        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![
                RouteRule {
                    name: "cn-geoip".into(),
                    matches: vec![MatchCondition::Geoip {
                        country: "CN".into(),
                    }],
                    target: "cn-node".into(),
                },
                RouteRule {
                    name: "cn-geosite".into(),
                    matches: vec![MatchCondition::GeoSite {
                        category: "cn".into(),
                    }],
                    target: "cn-node".into(),
                },
                RouteRule {
                    name: "exact-domain".into(),
                    matches: vec![MatchCondition::DomainFull {
                        values: vec!["exact.org".into()],
                    }],
                    target: "full-node".into(),
                },
            ],
            geoip_db: Some(mmdb_path.clone()),
            geosite_db: Some(dat_path.clone()),
            ..rillane_config::RoutingConfig::default()
        });

        async fn route_to(engine: &RoutingEngine, host: &str) -> String {
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

        // GeoIP：IP 字面量命中 CN；非 CN 不命中（域名不解析）。
        assert_eq!(
            route_to(&engine, "1.2.3.4").await,
            "cn-node",
            "GeoIP CN 命中"
        );
        assert_eq!(route_to(&engine, "8.8.8.8").await, "direct", "非 CN 不命中");
        assert_eq!(
            route_to(&engine, "example.com").await,
            "cn-node",
            "GeoSite 后缀命中"
        );
        assert_eq!(
            route_to(&engine, "www.example.com").await,
            "cn-node",
            "GeoSite 子域命中"
        );
        assert_eq!(
            route_to(&engine, "exact.org").await,
            "full-node",
            "DomainFull 命中"
        );
        assert_eq!(
            route_to(&engine, "sub.exact.org").await,
            "direct",
            "DomainFull 子域不命中"
        );
        assert_eq!(
            route_to(&engine, "other.net").await,
            "direct",
            "均不命中落默认"
        );
    }

    /// G0-2 无数据库（路径缺省 None）时 GeoIP/GeoSite 条件恒不命中——
    /// 与原「注解等价物无生产者」行为一致，不阻塞路由。
    #[tokio::test]
    async fn geo_conditions_never_match_without_db() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![
                RouteRule {
                    name: "geoip".into(),
                    matches: vec![MatchCondition::Geoip {
                        country: "CN".into(),
                    }],
                    target: "cn".into(),
                },
                RouteRule {
                    name: "geosite".into(),
                    matches: vec![MatchCondition::GeoSite {
                        category: "cn".into(),
                    }],
                    target: "cn".into(),
                },
            ],
            ..Default::default()
        });
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "1.2.3.4".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: Default::default(),
        };
        assert_eq!(engine.route(ctx).await.unwrap().final_node(), "direct");
    }

    /// G0-2 数据库路径热更：`reload` 换新数据库路径后，新路径在下次匹配
    /// 时生效（容器重建）；路径未变则复用已加载句柄。
    #[tokio::test]
    async fn reload_swaps_geo_database_path() {
        use rillane_core::{FlowId, FlowTarget, TargetProto};
        let engine = RoutingEngine::new(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "cn".into(),
                matches: vec![MatchCondition::Geoip {
                    country: "CN".into(),
                }],
                target: "cn-node".into(),
            }],
            ..Default::default()
        });
        // 无数据库：不命中。
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "1.2.3.4".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: Default::default(),
        };
        assert_eq!(engine.route(ctx).await.unwrap().final_node(), "direct");

        // 热更到合成 mmdb 路径：下次匹配加载并命中。
        let mmdb_dir =
            std::env::temp_dir().join(format!("rillane-rt-reload-{}", std::process::id()));
        std::fs::create_dir_all(&mmdb_dir).unwrap();
        let mmdb_path = mmdb_dir.join("cn.mmdb");
        let mut mmdb = maxminddb_writer::Database::default();
        mmdb.metadata.database_type = "GeoLite2-Country".to_string();
        mmdb.metadata.languages = vec!["en".to_string()];
        mmdb.metadata.binary_format_major_version = 2;
        let cn: maxminddb::geoip2::Country = maxminddb::geoip2::Country {
            country: maxminddb::geoip2::country::Country {
                iso_code: Some("CN"),
                ..Default::default()
            },
            ..Default::default()
        };
        let data = mmdb.insert_value(cn).unwrap();
        mmdb.insert_node(
            "1.0.0.0/8"
                .parse::<maxminddb_writer::paths::IpAddrWithMask>()
                .unwrap(),
            data,
        );
        let mut mmdb_buf = Vec::new();
        mmdb.write_to(&mut mmdb_buf).unwrap();
        std::fs::write(&mmdb_path, &mmdb_buf).unwrap();

        engine.reload(RoutingConfig {
            default_node: "direct".into(),
            groups: vec![],
            rules: vec![RouteRule {
                name: "cn".into(),
                matches: vec![MatchCondition::Geoip {
                    country: "CN".into(),
                }],
                target: "cn-node".into(),
            }],
            geoip_db: Some(mmdb_path.clone()),
            geosite_db: None,
            ..rillane_config::RoutingConfig::default()
        });
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "1.2.3.4".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            metadata: Default::default(),
        };
        assert_eq!(engine.route(ctx).await.unwrap().final_node(), "cn-node");
    }

    /// G1-9：探测目标拆分——host:port 正常、IPv6 方括号剥除；空 host /
    /// 缺端口 / 端口 0 / 非数字端口拒绝。
    #[test]
    fn split_probe_target_forms() {
        assert_eq!(
            split_probe_target("127.0.0.1:443"),
            Some(("127.0.0.1".to_string(), 443))
        );
        assert_eq!(
            split_probe_target("[::1]:80"),
            Some(("::1".to_string(), 80))
        );
        assert_eq!(split_probe_target("host"), None);
        assert_eq!(split_probe_target(":443"), None);
        assert_eq!(split_probe_target("host:0"), None);
        assert_eq!(split_probe_target("host:notaport"), None);
    }
}
