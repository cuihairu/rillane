//! 纯 Explain 服务（RIL-054，debug-and-mcp.md §3.1）：生产求值器 + 冻结
//! 快照的规则推演——无 DNS、无拨号、无 OS 身份查询。
//!
//! 设计口径落点（debug-and-mcp.md §3.1）：
//! - **生产求值器**：规则/场景匹配直接调用 `route()` 使用的同一组自由
//!   函数（`matches_rule`/`matches_condition`）——推演结论与生产路径
//!   同源，不存在"第二套匹配器"漂移；
//! - **固定快照**：配置取调用时刻的 `snapshot()`（本推演期间固定），
//!   组健康位/用户选择/链路质量/带宽经 [`ExplainSnapshot`] 显式冻结
//!   ——同一 (config, snapshot, input) 三元组离线重放必得同一结论；
//!   TTL 判定在冻结时刻完成，推演期不再读时钟（纯函数）；
//! - **证据缺失 = 条件性结果**：进程/网络注解缺席、Geo 数据库未加载、
//!   域名未解析（路由面不解析 DNS）、规则集载荷未装入、链路质量无
//!   数据——这些都会让真实路由随证据到位而改变，推演结论按
//!   [`EgressCertainty::Conditional`] 标注并列出缺口，不伪装成确定；
//! - **随机/计数策略只给候选池**：`random`/`weighted`（RNG）与
//!   `round_robin`（推进计数器）在推演中无确定答案——列出健康候选池
//!   并按 [`EgressCertainty::NonDeterministic`] 标注，绝不假装选中了
//!   某个成员；确定性策略（fixed/fallback/consistent_hash/latency/
//!   bandwidth）按生产同口径在快照上重放；
//! - **可重放锚**：输入快照的 SHA-256 摘要随结论输出（`input_digest`）
//!   ——诊断面可以精确对照"哪份输入得出哪条结论"；
//! - **只读推演**：陈旧选择/不可用目标只报告不修改（生产面会清除
//!   陈旧选择并告警，Explain 无副作用——恢复动作留给真实路由）。

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rillane_config::{
    GroupDescriptor, GroupDescriptorMember, MatchCondition, RoutingConfig, RuleSetLibrary,
    ScenarioFailureAction,
};
use rillane_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, TargetProto};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{host_to_ip, matches_condition, matches_rule, strategy_name, GeoDatabases};

/// 域名来源（§3.1 显式证据）：Explain 输入必须声明目标域名怎么来的
/// ——推演与诊断据此判断身份可信级；`unknown` = 来源不明（如无嗅探
/// 能力的 ingress 上伪装的 SNI）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
    /// 来源不明
    #[default]
    Unknown,
    /// 用户/配置显式给出
    UserProvided,
    /// DNS 观测回填
    DnsObserved,
    /// TLS/QUIC 嗅探
    Sniffed,
}

impl DomainSource {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            DomainSource::Unknown => "unknown",
            DomainSource::UserProvided => "user_provided",
            DomainSource::DnsObserved => "dns_observed",
            DomainSource::Sniffed => "sniffed",
        }
    }
}

/// 进程证据（显式声明面）：内核不在推演期做 OS 查询——进程条件以此
/// 为准按生产"注解"语义求值；None/缺字段 = 证据缺失（条件按注解缺席
/// "恒不命中"评估，推演标注条件性）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvidence {
    /// `/proc/<pid>/comm` 口径进程名（内核截断 15 字节）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 可执行路径（`process.path` 注解口径）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Explain 输入快照：可序列化、可比较、可离线重放——与
/// [`ExplainSnapshot`]（组状态）一起构成一次推演的全部输入
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplainInput {
    /// 计划代际（决策钉住的配置代际——重放校验用）
    pub generation_id: String,
    /// 入口标识（诊断可读；不参与匹配）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<String>,
    /// 目标主机（域名或 IP 字面量——与生产流同一语义）
    pub host: String,
    pub port: u16,
    /// 传输协议字面归类：`tcp`/`udp`/`quic`（与 `Proto` 条件同一口径，
    /// 不折叠——`quic` ≠ `udp`）
    pub proto: String,
    /// 域名来源（显式证据）
    #[serde(default)]
    pub domain_source: DomainSource,
    /// 进程证据；None = 证据缺失
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessEvidence>,
    /// 显式注解面：生产注解的逐键重放（`client.cidr`/`net.src_port`/
    /// `process.name` 等）——与生产求值面同一注入先例，注解键优先于
    /// `process` 字段（注解即最终权威）
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl ExplainInput {
    /// 输入快照 SHA-256（可重放锚）：序列化字节的摘要——诊断面精确
    /// 对照"哪份输入得出哪条结论"
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("explain input serialize");
        let hash = Sha256::digest(&bytes);
        let mut out = String::with_capacity(hash.len() * 2);
        for byte in hash {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// 转生产求值上下文：注解面按生产注入先例构造（进程证据 → 注解，
    /// 显式注解逐键覆盖）
    fn to_flow_context(&self) -> Result<FlowContext> {
        let proto = match self.proto.to_ascii_lowercase().as_str() {
            "tcp" => TargetProto::Tcp,
            "udp" => TargetProto::Udp,
            "quic" => TargetProto::Quic,
            other => {
                return Err(anyhow!(
                    "explain.input.proto 非法（{other}）: 须为 tcp/udp/quic"
                ))
            }
        };
        let mut metadata = FlowMetadata::default();
        if let Some(process) = &self.process {
            if let Some(name) = &process.name {
                metadata
                    .annotations
                    .insert("process.name".to_string(), name.clone());
            }
            if let Some(path) = &process.path {
                metadata
                    .annotations
                    .insert("process.path".to_string(), path.clone());
            }
        }
        for (key, value) in &self.annotations {
            metadata.annotations.insert(key.clone(), value.clone());
        }
        Ok(FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: self.host.clone(),
                port: self.port,
                proto,
            },
            metadata,
        })
    }
}

/// 冻结的真链路质量样本（TTL 内 `link_quality` 在冻结时刻的取值）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrozenQuality {
    pub p95_ms: u64,
    pub loss_ratio: f64,
}

/// 冻结的组级 SLO 门（`PolicyGroup.slo` 的显式拷贝——语义与生产
/// D-1/D-2 同口径）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FrozenSlo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_penalty_ms: Option<f64>,
}

impl FrozenSlo {
    /// 罚分权重（None → 1000.0，与生产同缺省）
    fn penalty_or_default(&self) -> f64 {
        self.loss_penalty_ms.unwrap_or(1000.0)
    }
}

/// 冻结的组成员（健康位在冻结时刻烙定——推演期不再变化）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FrozenMember {
    Node {
        name: String,
        #[serde(default)]
        weight: u32,
        healthy: bool,
    },
    Group {
        name: String,
        #[serde(default)]
        weight: u32,
        group: Box<FrozenGroup>,
    },
}

/// 冻结的组：策略 + 成员树 + SLO 门——组状态快照的形状
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrozenGroup {
    pub name: String,
    /// 策略机器口径（`strategy_name`：fixed/latency/fallback/random/
    /// bandwidth/weighted/consistent_hash/round_robin）
    pub strategy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slo: Option<FrozenSlo>,
    pub members: Vec<FrozenMember>,
}

impl FrozenGroup {
    /// 任一成员健康（嵌套组按其成员树递归判定——与生产
    /// `GroupDescriptorMember::is_healthy` 同口径）
    fn has_healthy(&self) -> bool {
        self.members.iter().any(frozen_member_healthy)
    }
}

/// 冻结成员名
fn frozen_member_name(member: &FrozenMember) -> &str {
    match member {
        FrozenMember::Node { name, .. } | FrozenMember::Group { name, .. } => name,
    }
}

/// 冻结成员健康位（嵌套组 = 成员树有健康者）
fn frozen_member_healthy(member: &FrozenMember) -> bool {
    match member {
        FrozenMember::Node { healthy, .. } => *healthy,
        FrozenMember::Group { group, .. } => group.has_healthy(),
    }
}

/// 组状态快照（RIL-054 冻结面）：健康/选择/质量/带宽在冻结时刻的
/// 全体取值——离线重放的组状态锚
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExplainSnapshot {
    /// 冻结组树（组名 → 组）
    pub groups: BTreeMap<String, FrozenGroup>,
    /// 真链路质量（real 源，TTL 内）：node → (p95, loss)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quality: BTreeMap<String, FrozenQuality>,
    /// legacy 测速：node → RTT ms（loss 记 0——与生产 `quality_candidates`
    /// 同口径：legacy 源无丢包观测）
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub legacy_latency: BTreeMap<String, u64>,
    /// 带宽统计（kbps，TTL 内）：node → 带宽
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bandwidth: BTreeMap<String, u64>,
    /// 用户选择（RIL-011）：组名 → 成员名
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub selections: BTreeMap<String, String>,
}

/// 推演确定性级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressCertainty {
    /// 同输入必得同结论（确定性策略 + 证据齐全）
    Definitive,
    /// 结论受缺失证据影响——证据到位后可能改变（`unknowns` 列出缺口）
    Conditional,
    /// 策略本身非确定（RNG/计数器）——只给候选池
    NonDeterministic,
}

/// 证据缺口：推演中按"恒不命中/回落"评估的证据依赖——逐条说明字段
/// 与原因（§3.1「证据缺失返回条件性结果」）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownEvidence {
    pub field: String,
    pub reason: String,
}

/// 评估步骤（推演过程面）：按生产求值顺序逐项记录，含未命中项——
/// "为什么不是那条规则"可从序号与命中位直接读出（来源位置）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvaluatedStep {
    Scenario {
        name: String,
        priority: i64,
        matched: bool,
        /// 失败动作（fallback/reject）
        on_failure: String,
    },
    Rule {
        index: usize,
        name: String,
        matched: bool,
    },
    Default,
}

/// 预测出口
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictedEgress {
    /// 命中的组（直接节点 = None）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// 预测节点（非确定策略 = None——只给候选池）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// 健康候选池（声明序）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_pool: Vec<String>,
    /// 恢复/回落说明（陈旧选择回落、无质量数据回落等——显式不静默）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// 穿过的嵌套组链（外→内，含最外层）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_chain: Vec<String>,
    /// 不可用原因（组无健康成员等；存在时 `node` = None）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// 路由推演结论（RIL-054）：生产求值器在固定配置 + 冻结组状态上对
/// 一条流的完整推演——评估序、决策来源、预测出口、证据缺口与确定性
/// 级别一体输出
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteExplanation {
    /// 输入快照 SHA-256（重放锚——`ExplainInput::digest`）
    pub input_digest: String,
    pub generation_id: String,
    /// 推演目标回显
    pub target: ExplainedTarget,
    pub domain_source: DomainSource,
    /// 求值序（场景优先级序 → 规则声明序 → default），含未命中项
    pub evaluated: Vec<EvaluatedStep>,
    /// 决策来源："scenario:<名>" / 规则名 / "default"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_by: Option<String>,
    /// 场景显式拒绝（on_failure: reject 且目标不可用）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject: Option<String>,
    /// 目标不可用错误（规则/默认面无 fallback 语义——生产面同路径上抛）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 场景 fallback 落回说明（生产面 WARN 的推演对应物——不静默）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicted: Option<PredictedEgress>,
    /// 证据缺口（条件性结果的具体原因）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknowns: Vec<UnknownEvidence>,
    pub certainty: EgressCertainty,
}

/// 推演目标回显
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainedTarget {
    pub host: String,
    pub port: u16,
    /// 协议字面归类（小写：tcp/udp/quic）
    pub proto: String,
}

/// 场景失败动作机器口径
fn failure_action_name(action: ScenarioFailureAction) -> &'static str {
    match action {
        ScenarioFailureAction::Fallback => "fallback",
        ScenarioFailureAction::Reject => "reject",
    }
}

/// 纯 Explain（离线形态）：给配置与（可选）Geo 数据库即可重放——
/// 输入快照与组快照都经序列化传递，不要求活引擎。Geo 数据库缺席时
/// 相关条件按"未加载恒不命中"评估并标注证据缺口（不伪装确定）。
pub fn explain_offline(
    config: &RoutingConfig,
    geo: Option<&GeoDatabases>,
    snapshot: &ExplainSnapshot,
    input: &ExplainInput,
) -> Result<RouteExplanation> {
    match geo {
        Some(geo) => explain_over(config, geo, snapshot, input),
        None => {
            let empty = GeoDatabases::new(None, None);
            explain_over(config, &empty, snapshot, input)
        }
    }
}

/// 推演主体：生产求值器（`matches_rule`/`matches_condition` 自由函数
/// ——`route()` 的同一匹配面）+ 冻结组状态重放。无 await、无时钟读、
/// 无 DNS/拨号/OS 查询。
fn explain_over(
    config: &RoutingConfig,
    geo: &GeoDatabases,
    snapshot: &ExplainSnapshot,
    input: &ExplainInput,
) -> Result<RouteExplanation> {
    let ctx = input.to_flow_context()?;
    // 推演期私有正则缓存：编译语义与生产同口径（同一 builder 参数），
    // 只编译一次不跨推演复用——离线重放不需要引擎级缓存生命周期
    let regex_cache: DashMap<String, std::sync::Arc<regex::Regex>> = DashMap::new();
    let mut unknowns: Vec<UnknownEvidence> = Vec::new();
    let mut evaluated: Vec<EvaluatedStep> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // RIL-021 场景面（镜像 route()）：优先级稳定排序 → 条件合取 →
    // 目标解析（fallback 落回规则面 / reject 显式拒绝）
    let mut ordered: Vec<&rillane_config::ScenarioRule> = config.scenarios.iter().collect();
    ordered.sort_by_key(|s| s.priority);
    for scenario in ordered {
        let matched = scenario
            .conditions
            .iter()
            .all(|c| matches_condition(&regex_cache, geo, &config.rule_sets, c, &ctx));
        // 证据缺口对未命中的场景同样收集——证据到位可能翻转命中面，
        // 当前结论因此条件性
        collect_unknowns(
            geo,
            &config.rule_sets,
            &scenario.conditions,
            &ctx,
            &mut unknowns,
        );
        let on_failure = failure_action_name(scenario.on_failure);
        evaluated.push(EvaluatedStep::Scenario {
            name: scenario.name.clone(),
            priority: scenario.priority,
            matched,
            on_failure: on_failure.to_string(),
        });
        if matched {
            match resolve_frozen_target(snapshot, &scenario.target, &ctx.target.host, &mut unknowns)
            {
                Ok(predicted) => {
                    return Ok(finish(
                        input,
                        evaluated,
                        notes,
                        unknowns,
                        Some(format!("scenario:{}", scenario.name)),
                        None,
                        None,
                        Some(predicted),
                    ));
                }
                Err(reason) => match scenario.on_failure {
                    ScenarioFailureAction::Fallback => {
                        notes.push(format!(
                            "场景 {} 目标 {} 不可用（{reason}），fallback 落回规则面",
                            scenario.name, scenario.target
                        ));
                    }
                    ScenarioFailureAction::Reject => {
                        return Ok(finish(
                            input,
                            evaluated,
                            notes,
                            unknowns,
                            Some(format!("scenario:{}", scenario.name)),
                            None,
                            Some(format!(
                                "场景 {} 目标 {} 不可用（on_failure: reject）: {reason}",
                                scenario.name, scenario.target
                            )),
                            None,
                        ));
                    }
                },
            }
        }
    }

    // 规则面（镜像 route()）：声明序首匹配
    for (index, rule) in config.rules.iter().enumerate() {
        let matched = matches_rule(&regex_cache, geo, &config.rule_sets, rule, &ctx);
        // 证据缺口对未命中的规则同样收集（未命中规则里的缺口可能翻转
        // 命中面——结论因此条件性）
        collect_unknowns(geo, &config.rule_sets, &rule.matches, &ctx, &mut unknowns);
        evaluated.push(EvaluatedStep::Rule {
            index,
            name: rule.name.clone(),
            matched,
        });
        if matched {
            return match resolve_frozen_target(
                snapshot,
                &rule.target,
                &ctx.target.host,
                &mut unknowns,
            ) {
                Ok(predicted) => Ok(finish(
                    input,
                    evaluated,
                    notes,
                    unknowns,
                    Some(rule.name.clone()),
                    None,
                    None,
                    Some(predicted),
                )),
                Err(reason) => Ok(finish(
                    input,
                    evaluated,
                    notes,
                    unknowns,
                    Some(rule.name.clone()),
                    Some(format!(
                        "规则 {} 目标 {} 不可用: {reason}",
                        rule.name, rule.target
                    )),
                    None,
                    None,
                )),
            };
        }
    }

    // 默认出口（镜像 route()）
    evaluated.push(EvaluatedStep::Default);
    let (matched_by, error, predicted) = match resolve_frozen_target(
        snapshot,
        &config.default_node,
        &ctx.target.host,
        &mut unknowns,
    ) {
        Ok(predicted) => (Some("default".to_string()), None, Some(predicted)),
        Err(reason) => (
            Some("default".to_string()),
            Some(format!("默认出口 {} 不可用: {reason}", config.default_node)),
            None,
        ),
    };
    Ok(finish(
        input, evaluated, notes, unknowns, matched_by, error, None, predicted,
    ))
}

/// 汇总结论：确定性级别按 显式失败 > 非确定策略 > 证据缺口 > 确定 判定
#[allow(clippy::too_many_arguments)]
fn finish(
    input: &ExplainInput,
    evaluated: Vec<EvaluatedStep>,
    notes: Vec<String>,
    mut unknowns: Vec<UnknownEvidence>,
    matched_by: Option<String>,
    error: Option<String>,
    reject: Option<String>,
    predicted: Option<PredictedEgress>,
) -> RouteExplanation {
    // 去重保序：同一缺口在多条规则重复出现只报一次
    let mut seen = HashSet::new();
    unknowns.retain(|u| seen.insert((u.field.clone(), u.reason.clone())));

    let certainty = if error.is_some() || reject.is_some() {
        // 显式失败/拒绝是确定结论（生产面同路径同结果）
        EgressCertainty::Definitive
    } else if predicted
        .as_ref()
        .is_some_and(|p| p.node.is_none() && p.unavailable_reason.is_none())
    {
        EgressCertainty::NonDeterministic
    } else if !unknowns.is_empty() {
        EgressCertainty::Conditional
    } else {
        EgressCertainty::Definitive
    };

    RouteExplanation {
        input_digest: input.digest(),
        generation_id: input.generation_id.clone(),
        target: ExplainedTarget {
            host: input.host.clone(),
            port: input.port,
            proto: input.proto.to_ascii_lowercase(),
        },
        domain_source: input.domain_source,
        evaluated,
        matched_by,
        reject,
        error,
        notes,
        predicted,
        unknowns,
        certainty,
    }
}

/// 冻结目标解析（镜像 `resolve_target`）：非组名 = 直接节点；组名 =
/// 冻结组重放
fn resolve_frozen_target(
    snapshot: &ExplainSnapshot,
    target: &str,
    host: &str,
    unknowns: &mut Vec<UnknownEvidence>,
) -> Result<PredictedEgress, String> {
    let Some(group) = snapshot.groups.get(target) else {
        return Ok(PredictedEgress {
            group: None,
            node: Some(target.to_string()),
            member_pool: Vec::new(),
            note: None,
            group_chain: Vec::new(),
            unavailable_reason: None,
        });
    };
    let mut chain = vec![group.name.clone()];
    let mut resolved = resolve_frozen_group(snapshot, group, host, unknowns, &mut chain)?;
    // group 语义与生产 `through_group` 同口径：最外层命中组（嵌套链在
    // group_chain 逐级记录）
    resolved.group = Some(group.name.clone());
    Ok(resolved)
}

/// 冻结组重放（镜像 `select_from_group` 的确定性子集）：健康候选 =
/// 健康位过滤（声明序不重排）；无健康成员同生产报错；策略按机器口径
/// 分派——RNG/计数器策略只给候选池
fn resolve_frozen_group(
    snapshot: &ExplainSnapshot,
    group: &FrozenGroup,
    host: &str,
    unknowns: &mut Vec<UnknownEvidence>,
    chain: &mut Vec<String>,
) -> Result<PredictedEgress, String> {
    let healthy: Vec<&FrozenMember> = group
        .members
        .iter()
        .filter(|m| frozen_member_healthy(m))
        .collect();
    if healthy.is_empty() {
        return Err(format!("组 {} 无健康成员", group.name));
    }
    let pool: Vec<String> = healthy
        .iter()
        .map(|m| frozen_member_name(m).to_string())
        .collect();

    enum FrozenPick<'a> {
        Member(&'a FrozenMember, Option<String>),
        PoolOnly(&'static str),
    }

    let pick = match group.strategy.as_str() {
        // RIL-011 select 保真（镜像 `apply_fixed_selection`）：用户选择
        // 命中全成员集（含不健康）即尊重；陈旧选择只报告不修改（生产
        // 面清除引擎副本——Explain 只读，恢复动作留给真实路由）
        "fixed" => match snapshot.selections.get(&group.name) {
            Some(selected) => match group
                .members
                .iter()
                .find(|m| frozen_member_name(m) == selected.as_str())
            {
                Some(member) => FrozenPick::Member(member, None),
                None => FrozenPick::Member(
                    healthy[0],
                    Some(format!(
                        "组 {} 所选成员 `{selected}` 已不存在（更新/删除），回落首健康成员",
                        group.name
                    )),
                ),
            },
            None => FrozenPick::Member(healthy[0], None),
        },
        // RIL-012 按序回退（镜像 `Strategy::Fallback`）：首健康成员
        "fallback" => FrozenPick::Member(healthy[0], None),
        // 一致性哈希（镜像 `select_consistent_hash_member`）：sha256(host)
        // 首 8 字节大端取模——纯函数，可重放
        "consistent_hash" => {
            let hash = Sha256::digest(host.as_bytes());
            let hash_num = u64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            FrozenPick::Member(healthy[(hash_num as usize) % healthy.len()], None)
        }
        // 延迟策略（镜像 `select_latency_member`）：real 源 → legacy 测速
        // → 无数据回落首健康（显式说明 + 证据缺口）；门 + 评分与生产
        // `gate_and_pick` 同口径
        "latency" => {
            let mut candidates: Vec<(String, f64, f64, bool)> = Vec::new();
            for member in &healthy {
                let name = frozen_member_name(member);
                if let Some(q) = snapshot.quality.get(name) {
                    candidates.push((name.to_string(), q.p95_ms as f64, q.loss_ratio, true));
                } else if let Some(latency) = snapshot.legacy_latency.get(name) {
                    candidates.push((name.to_string(), *latency as f64, 0.0, false));
                }
            }
            if candidates.is_empty() {
                unknowns.push(UnknownEvidence {
                    field: format!("link_quality:{}", group.name),
                    reason: "组内成员无链路质量数据——按首健康成员回落，质量数据到位后选点可能改变"
                        .to_string(),
                });
                FrozenPick::Member(
                    healthy[0],
                    Some(format!("组 {} 无链路质量数据，回落首健康成员", group.name)),
                )
            } else {
                let picked = frozen_gate_and_pick(&candidates, group.slo.as_ref());
                let name = &picked.0;
                let member = healthy
                    .iter()
                    .find(|m| frozen_member_name(m) == name.as_str())
                    .expect("candidate names come from healthy members");
                FrozenPick::Member(member, None)
            }
        }
        // 带宽策略（镜像 `select_bandwidth_member`）：有统计取最高
        // （同序 max_by_key——并列取后者）；无统计回落首健康
        "bandwidth" => {
            let with_bw: Vec<(&FrozenMember, u64)> = healthy
                .iter()
                .filter_map(|m| {
                    snapshot
                        .bandwidth
                        .get(frozen_member_name(m))
                        .map(|bw| (*m, *bw))
                })
                .collect();
            if with_bw.is_empty() {
                FrozenPick::Member(healthy[0], None)
            } else {
                // max_by_key 并列取后者（与生产 select_bandwidth_member 同序同语义）
                FrozenPick::Member(
                    with_bw
                        .into_iter()
                        .max_by_key(|(_, bw)| *bw)
                        .expect("with_bw checked non-empty")
                        .0,
                    None,
                )
            }
        }
        // RNG/计数器策略：推演无确定答案——候选池 + 显式原因
        "random" => FrozenPick::PoolOnly("random 策略由 RNG 决定——离线推演只给健康候选池"),
        "weighted" => FrozenPick::PoolOnly("weighted 策略按权重随机——离线推演只给健康候选池"),
        "round_robin" => {
            FrozenPick::PoolOnly("round_robin 策略依赖推进计数器——离线推演只给健康候选池")
        }
        // 手工构造快照的防御面：未知策略不伪装确定
        _other => FrozenPick::PoolOnly("策略缺少离线推演口径——只给健康候选池"),
    };

    match pick {
        FrozenPick::PoolOnly(reason) => Ok(PredictedEgress {
            group: Some(group.name.clone()),
            node: None,
            member_pool: pool,
            note: Some(reason.to_string()),
            group_chain: chain.clone(),
            unavailable_reason: None,
        }),
        FrozenPick::Member(FrozenMember::Node { name, .. }, note) => Ok(PredictedEgress {
            group: Some(group.name.clone()),
            node: Some(name.clone()),
            member_pool: pool,
            note,
            group_chain: chain.clone(),
            unavailable_reason: None,
        }),
        FrozenPick::Member(FrozenMember::Group { group: nested, .. }, note) => {
            // 嵌套组递归（镜像 `select_from_group` 的 Group 递归分支）
            chain.push(nested.name.clone());
            let mut resolved = resolve_frozen_group(snapshot, nested, host, unknowns, chain)?;
            if resolved.note.is_none() {
                resolved.note = note;
            }
            Ok(resolved)
        }
    }
}

/// 门 + 评分选点（镜像生产 `gate_and_pick`，D-1/D-2）：仅 real 成员受门
/// 约束（legacy/unknown 自动合规）；门内空 → 全体候选；score =
/// p95 + loss × penalty（并列取先声明者）
fn frozen_gate_and_pick<'a>(
    candidates: &'a [(String, f64, f64, bool)],
    slo: Option<&FrozenSlo>,
) -> &'a (String, f64, f64, bool) {
    let penalty = slo.map(FrozenSlo::penalty_or_default).unwrap_or(1000.0);
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
        .expect("compliant is never empty (gated-empty falls back to all candidates)")
}

/// 证据缺口收集（不影响匹配结果——匹配恒由生产求值器判定）：对评估过
/// 的条件树逐项记录"按恒不命中/回落评估"的证据依赖。未命中规则里的
/// 缺口同样记录——证据到位可能翻转命中面，结论因此条件性。
fn collect_unknowns(
    geo: &GeoDatabases,
    rule_sets: &RuleSetLibrary,
    conditions: &[MatchCondition],
    ctx: &FlowContext,
    out: &mut Vec<UnknownEvidence>,
) {
    for cond in conditions {
        collect_condition_unknowns(geo, rule_sets, cond, ctx, out);
    }
}

fn collect_condition_unknowns(
    geo: &GeoDatabases,
    rule_sets: &RuleSetLibrary,
    cond: &MatchCondition,
    ctx: &FlowContext,
    out: &mut Vec<UnknownEvidence>,
) {
    match cond {
        MatchCondition::Any { conditions } => {
            collect_unknowns(geo, rule_sets, conditions, ctx, out)
        }
        MatchCondition::Not { condition } => {
            collect_condition_unknowns(geo, rule_sets, condition, ctx, out)
        }
        MatchCondition::Geoip { .. } => {
            if geo.geoip().is_none() {
                out.push(UnknownEvidence {
                    field: "geoip.db".to_string(),
                    reason: "GeoIP 数据库未加载——条件按恒不命中评估，数据库就绪后结论可能改变"
                        .to_string(),
                });
            } else if host_to_ip(&ctx.target.host).is_none() {
                out.push(UnknownEvidence {
                    field: "dns".to_string(),
                    reason: "目标为域名且推演面不解析 DNS——Geoip 按恒不命中评估".to_string(),
                });
            }
        }
        MatchCondition::GeoSite { .. } => {
            if geo.geosite().is_none() {
                out.push(UnknownEvidence {
                    field: "geosite.db".to_string(),
                    reason: "GeoSite 数据库未加载——条件按恒不命中评估，数据库就绪后结论可能改变"
                        .to_string(),
                });
            }
        }
        MatchCondition::Process { .. } => {
            if !ctx.metadata.annotations.contains_key("process.name") {
                out.push(UnknownEvidence {
                    field: "process.name".to_string(),
                    reason: "进程注解缺失（无 TUN 归因/未显式提供）——条件按恒不命中评估"
                        .to_string(),
                });
            }
        }
        MatchCondition::ProcessPath { .. } => {
            if !ctx.metadata.annotations.contains_key("process.path") {
                out.push(UnknownEvidence {
                    field: "process.path".to_string(),
                    reason: "进程路径注解缺失（无 TUN 归因/未显式提供）——条件按恒不命中评估"
                        .to_string(),
                });
            }
        }
        MatchCondition::Network { .. } => {
            if !ctx.metadata.annotations.contains_key("client.cidr") {
                out.push(UnknownEvidence {
                    field: "client.cidr".to_string(),
                    reason: "来源网段注解缺失——条件按恒不命中评估".to_string(),
                });
            }
        }
        MatchCondition::SrcPort { .. } => {
            if !ctx.metadata.annotations.contains_key("net.src_port") {
                out.push(UnknownEvidence {
                    field: "net.src_port".to_string(),
                    reason: "源端口注解缺失——条件按恒不命中评估".to_string(),
                });
            }
        }
        MatchCondition::RuleSetRef { name } if rule_sets.get(name).is_none() => {
            out.push(UnknownEvidence {
                field: format!("rule_set:{name}"),
                reason: "规则集载荷未装入——引用按恒不命中评估".to_string(),
            });
        }
        _ => {}
    }
}

/// 由生产组描述符构造冻结组（`freeze_explain_snapshot` 的递归面）
fn frozen_group_from_descriptor(descriptor: &GroupDescriptor) -> FrozenGroup {
    FrozenGroup {
        name: descriptor.name.clone(),
        strategy: strategy_name(&descriptor.strategy).to_string(),
        slo: descriptor.slo.as_ref().map(|s| FrozenSlo {
            p95_ms: s.p95_ms,
            loss_ratio: s.loss_ratio,
            loss_penalty_ms: s.loss_penalty_ms,
        }),
        members: descriptor
            .members
            .iter()
            .map(|member| match member {
                GroupDescriptorMember::Node {
                    name,
                    weight,
                    is_healthy,
                } => FrozenMember::Node {
                    name: name.clone(),
                    weight: *weight,
                    healthy: *is_healthy,
                },
                GroupDescriptorMember::Group {
                    name,
                    weight,
                    descriptor,
                } => FrozenMember::Group {
                    name: name.clone(),
                    weight: *weight,
                    group: Box::new(frozen_group_from_descriptor(descriptor)),
                },
            })
            .collect(),
    }
}

impl super::RoutingEngine {
    /// 冻结组状态快照（RIL-054）：健康位/用户选择/链路质量/带宽在调用
    /// 时刻定格（TTL 判定在冻结时刻完成）——离线重放的组状态锚
    pub fn freeze_explain_snapshot(&self) -> ExplainSnapshot {
        let config = self.snapshot();
        let now = std::time::Instant::now();
        const QUALITY_TTL: Duration = Duration::from_secs(60);
        const BANDWIDTH_TTL: Duration = Duration::from_secs(60);

        let mut groups = BTreeMap::new();
        for (name, descriptor) in self
            .group_cache
            .read()
            .expect("group cache poisoned")
            .iter()
        {
            groups.insert(name.clone(), frozen_group_from_descriptor(descriptor));
        }
        let quality: BTreeMap<String, FrozenQuality> = self
            .link_quality
            .iter()
            .filter(|entry| now.duration_since(entry.value().2) < QUALITY_TTL)
            .map(|entry| {
                (
                    entry.key().clone(),
                    FrozenQuality {
                        p95_ms: u64::from(entry.value().0),
                        loss_ratio: entry.value().1,
                    },
                )
            })
            .collect();
        let legacy_latency: BTreeMap<String, u64> = self
            .latency_stats
            .iter()
            .map(|entry| (entry.key().clone(), u64::from(*entry.value())))
            .collect();
        let bandwidth: BTreeMap<String, u64> = self
            .bandwidth_stats
            .iter()
            .filter(|entry| now.duration_since(entry.value().1) < BANDWIDTH_TTL)
            .map(|entry| (entry.key().clone(), u64::from(entry.value().0)))
            .collect();

        ExplainSnapshot {
            groups,
            quality,
            legacy_latency,
            bandwidth,
            selections: config.selections.clone(),
        }
    }

    /// 纯 Explain（RIL-054）：生产求值器 + 冻结组快照的路由推演。无
    /// DNS/拨号/OS 查询——匹配复用 `route()` 的同一组自由函数，组解析
    /// 在冻结快照上按确定性策略重放；证据缺失按条件性结果标注，随机/
    /// 计数策略只给候选池。配置取调用时刻快照（本推演期间固定）。
    pub fn explain(
        &self,
        snapshot: &ExplainSnapshot,
        input: &ExplainInput,
    ) -> Result<RouteExplanation> {
        let config = self.snapshot();
        let geo = self.geo.read().expect("geo lock poisoned").clone();
        explain_over(&config, &geo, snapshot, input)
    }
}
