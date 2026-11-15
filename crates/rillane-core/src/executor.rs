//! 会话执行器（RIL-022）：把「计划」变成「已建立会话」的唯一入口。
//! 出口契约（[`crate::outbound`]）一次尝试不回退——回退编排归本模块：
//! 计划节点 → 目录声明的回退序列（声明序、有界、去重），逐候选
//! **先静态校验端点与能力再拨号**（预测证据），失败逐次记录对账。
//!
//! 会话绑定不变量（验收口径）：
//! - 旧 TCP/UDP **不随质量逐包换出口**——一次执行一次建立；已绑定会话
//!   的端点与代际在台账中不可变（无改道 API，结构上排除逐包换出口）；
//! - 新流采用**新代际**——拨号上下文的代际强制等于计划代际（计划在
//!   建计划时刻取当下代际，RIL-006）；错配按稳定码拒绝，不静默改写
//!   （出口配置与计划必须同代）；
//! - **计划与实际端点分别可见**——规则结果冻结在决策快照（计划节点），
//!   执行结果记录拨号返回的实际端点（可与目录端点不同：DNS 解析、
//!   服务端重定向），二者不合并。
//!
//! 接线边界：runtime 拨号侧把本执行器接到 TUN/UDP 会话建立点；fake-ip
//! `pin`/`release` 的调用点接线（RIL-020 边界）与代际发布位读数同归
//! runtime 接线面。

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::outbound::{
    DatagramOutbound, OpenContext, OpenError, OpenStage, OpenedAssociation, OpenedStream,
    StreamOutbound, TargetBinding, CODE_OPEN_CANCELLED, CODE_OPEN_UNSUPPORTED,
};
use crate::plan::{EndpointRef, GenerationRef, RoutePlan, SessionPin};

/// 稳定原因码：代际中无此节点的拨号端点（目录缺席——不臆造端点）
pub const CODE_NODE_UNKNOWN: &str = "plan_exec.node_unknown";
/// 稳定原因码：目录给出的端点畸形（空 host）
pub const CODE_ENDPOINT_INVALID: &str = "plan_exec.endpoint_invalid";
/// 稳定原因码：拨号上下文与计划代际不一致（建立前拒绝）
pub const CODE_GENERATION_MISMATCH: &str = "plan_exec.generation_mismatch";

/// 允许回退目录（声明序）：执行器**只**拨目录给出的候选——计划节点
/// 优先，随后按声明序回退；内核不自造回退，也不对失败候选无限重试。
pub trait FallbackCatalog: Send + Sync {
    /// 节点在指定代际的拨号端点；None = 该代际无此节点（跳过，不拨）
    fn endpoint(&self, generation: &GenerationRef, node: &str) -> Option<EndpointRef>;

    /// 计划节点的允许回退序列（声明序；不含计划节点自身，重复项由
    /// 执行器去重）
    fn fallbacks(&self, generation: &GenerationRef, node: &str) -> Vec<String>;
}

/// 一次候选尝试的结果（诊断对账：每次尝试要么可指出跳过原因，
/// 要么可指出失败阶段与证据类型）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// 静态校验不通过，未发起拨号（预测证据：能力表/目录缺席）
    Skipped {
        /// 稳定原因码
        code: &'static str,
        /// 人读原因
        detail: String,
    },
    /// 已拨号但失败（观测证据）
    Failed {
        /// 失败阶段（`dial`/`transport`/`handshake`/`pool`）
        stage: &'static str,
        /// 稳定原因码
        code: &'static str,
        /// 证据类型机器口径
        evidence: &'static str,
    },
    /// 建立成功
    Dialed,
}

/// 一次候选尝试的记录
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    /// 尝试序号（候选在候选序列中的位置）
    pub attempt_id: u32,
    /// 候选节点名
    pub node: String,
    /// 候选拨号端点（目录缺席时为空端点：对账可见「为何没拨」）
    pub endpoint: EndpointRef,
    /// 结果
    pub outcome: AttemptOutcome,
}

/// 已建立的会话：钉（代际 + 出口）与实际端点在此冻结——后续质量
/// 变化不改写本结构（无改写入口，验收「旧流不换出口」的结构半边）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSession {
    pin: SessionPin,
    endpoint: EndpointRef,
    attempts: Vec<AttemptRecord>,
}

impl EstablishedSession {
    /// 测试装配入口（crate 内可见；生产路径唯一入口是执行器建立收尾）
    #[cfg(test)]
    pub(crate) fn assemble(
        pin: SessionPin,
        endpoint: EndpointRef,
        attempts: Vec<AttemptRecord>,
    ) -> Self {
        Self {
            pin,
            endpoint,
            attempts,
        }
    }

    /// 会话钉（代际取自计划）
    pub fn pin(&self) -> &SessionPin {
        &self.pin
    }

    /// 实际端点（拨号返回，可与计划节点目录端点不同）
    pub fn endpoint(&self) -> &EndpointRef {
        &self.endpoint
    }

    /// 全部尝试记录
    pub fn attempts(&self) -> &[AttemptRecord] {
        &self.attempts
    }
}

/// 执行失败（计划节点 + 全部允许回退耗尽 / 调用方取消 / 上下文错配）。
/// 不回写规则结果——失败留在执行侧（[`RoutePlan::record_failed`] 已记录）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanExecError {
    /// 调用方取消/截止——回退立即停止（不给已放弃的会话继续拨号）
    Cancelled { attempts: Vec<AttemptRecord> },
    /// 全部候选耗尽（含零候选：计划路径无可执行节点）
    Exhausted { attempts: Vec<AttemptRecord> },
    /// 拨号上下文代际与计划代际不一致（建立前拒绝，零拨号）
    GenerationMismatch {
        plan_generation: String,
        context_generation: String,
    },
}

impl PlanExecError {
    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        match self {
            PlanExecError::Cancelled { .. } => CODE_OPEN_CANCELLED,
            PlanExecError::Exhausted { .. } => "plan_exec.exhausted",
            PlanExecError::GenerationMismatch { .. } => CODE_GENERATION_MISMATCH,
        }
    }

    /// 尝试记录（诊断对账）
    pub fn attempts(&self) -> &[AttemptRecord] {
        match self {
            PlanExecError::Cancelled { attempts } | PlanExecError::Exhausted { attempts } => {
                attempts
            }
            PlanExecError::GenerationMismatch { .. } => &[],
        }
    }
}

impl fmt::Display for PlanExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanExecError::Cancelled { attempts } => write!(
                f,
                "session dial cancelled after {} attempt(s)",
                attempts.len()
            ),
            PlanExecError::Exhausted { attempts } => {
                write!(f, "all {} dial candidate(s) failed", attempts.len())
            }
            PlanExecError::GenerationMismatch {
                plan_generation,
                context_generation,
            } => write!(
                f,
                "open context generation {context_generation} != plan generation {plan_generation}"
            ),
        }
    }
}

impl std::error::Error for PlanExecError {}

/// 建立失败（RIL-098 会话接线面）：计划层错误 + 最近一次真实拨号错误。
/// `last_open_error` 供入口协议错误映射**原样透传**稳定码/阶段/证据
/// （未发生拨号时为 None——静态跳过、代际错配、建立期取消）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelFailure {
    /// 计划执行错误（稳定码/尝试对账）
    pub plan: PlanExecError,
    /// 最近一次真实拨号错误
    pub last_open_error: Option<OpenError>,
}

impl ChannelFailure {
    /// 稳定原因码（计划层口径）
    pub fn code(&self) -> &'static str {
        self.plan.code()
    }

    /// 尝试记录（诊断对账）
    pub fn attempts(&self) -> &[AttemptRecord] {
        self.plan.attempts()
    }
}

/// 已建立的流通道（RIL-098）：会话对账 + 协议包装 IO 配对交付——
/// 通道所有权随本结构走，转发面由 session 模块统一接线。
pub struct EstablishedChannel {
    /// 已建立会话（计划节点/实际端点/尝试对账冻结）
    pub session: EstablishedSession,
    /// 协议包装后的出口流
    pub stream: OpenedStream,
}

/// 已建立的数据报关联通道（RIL-098）：会话对账 + 关联 IO 配对交付。
pub struct EstablishedAssociationChannel {
    /// 已建立会话
    pub session: EstablishedSession,
    /// 协议包装后的数据报关联
    pub association: OpenedAssociation,
}

/// 候选：节点名 + 目录端点（None = 代际中无此节点，尝试层显式跳过）
struct Candidate {
    node: String,
    endpoint: Option<EndpointRef>,
}

impl Candidate {
    /// 端点缺口（None = 可拨）：目录缺席 / 畸形端点（空 host）
    fn gap(&self) -> Option<(&'static str, String)> {
        match &self.endpoint {
            None => Some((
                CODE_NODE_UNKNOWN,
                format!("generation has no endpoint for node {}", self.node),
            )),
            Some(endpoint) if endpoint.host.is_empty() => Some((
                CODE_ENDPOINT_INVALID,
                format!("node {} has empty endpoint host", self.node),
            )),
            Some(_) => None,
        }
    }

    /// 对账记录用的端点（缺席时为空端点占位）
    fn record_endpoint(&self) -> EndpointRef {
        self.endpoint
            .clone()
            .unwrap_or_else(|| EndpointRef::new(String::new(), 0))
    }
}

/// 会话执行器：按计划编排「校验 → 拨号 → 回退」，产出已建立会话。
#[derive(Clone)]
pub struct SessionExecutor {
    catalog: Arc<dyn FallbackCatalog>,
}

impl fmt::Debug for SessionExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionExecutor").finish_non_exhaustive()
    }
}

impl SessionExecutor {
    /// 构造执行器（目录声明候选与端点）
    pub fn new(catalog: Arc<dyn FallbackCatalog>) -> Self {
        Self { catalog }
    }

    /// 建立 TCP 字节流会话（一次调用 = 一次会话建立；已建立的会话
    /// 由调用方绑定台账，本方法不再触碰）。
    ///
    /// `base_ctx` 的代际必须与计划一致（新流在计划时刻取当下代际；
    /// 出口配置与计划同代是回退编排的前提）。
    pub async fn open_stream(
        &self,
        plan: &mut RoutePlan,
        outbound: Arc<dyn StreamOutbound>,
        base_ctx: OpenContext,
        now_ms: u64,
    ) -> Result<EstablishedSession, PlanExecError> {
        Ok(self
            .open_stream_channel(plan, outbound, base_ctx, now_ms)
            .await
            .map_err(|failure| failure.plan)?
            .session)
    }

    /// 建立流通道并**配对交付**协议包装 IO（RIL-098 会话接线面）。
    /// 选路与回退编排与 [`SessionExecutor::open_stream`] 完全同源——
    /// 只有一条候选序列实现；差别仅在成功时保留 [`OpenedStream`]
    /// （旧方法不保留，转发面无法接线）并在失败时携带最近一次真实
    /// 拨号错误（供入口协议错误原样映射）。
    pub async fn open_stream_channel(
        &self,
        plan: &mut RoutePlan,
        outbound: Arc<dyn StreamOutbound>,
        base_ctx: OpenContext,
        now_ms: u64,
    ) -> Result<EstablishedChannel, ChannelFailure> {
        check_generation(plan, &base_ctx).map_err(|plan| ChannelFailure {
            plan,
            last_open_error: None,
        })?;
        let via_chain = via_chain(plan);
        let mut attempts = Vec::new();
        let mut last_open_error = None;
        for (index, candidate) in self.candidates(plan).into_iter().enumerate() {
            // 静态校验先于拨号：端点缺口 / 能力缺口都按预测证据跳过
            let outcome = if let Some((code, detail)) = candidate.gap() {
                AttemptOutcome::Skipped { code, detail }
            } else if let Some(detail) = stream_capability_gap(&outbound) {
                AttemptOutcome::Skipped {
                    code: CODE_OPEN_UNSUPPORTED,
                    detail,
                }
            } else if let Err(err) = base_ctx.check_openable(now_ms) {
                attempts.push(record(index, &candidate, failed_outcome(&err)));
                plan.record_failed(err.stage.as_str(), err.context.clone());
                return Err(ChannelFailure {
                    plan: PlanExecError::Cancelled { attempts },
                    last_open_error,
                });
            } else {
                let ctx = dial_context(&base_ctx, index);
                match outbound
                    .open_stream(candidate.endpoint.as_ref().expect("gap 已排除"), &ctx)
                    .await
                {
                    Ok(opened) => {
                        let session = finish(
                            plan,
                            index,
                            &candidate,
                            opened.endpoint(),
                            attempts,
                            via_chain,
                        );
                        return Ok(EstablishedChannel {
                            session,
                            stream: opened,
                        });
                    }
                    Err(err) => {
                        last_open_error = Some(err.clone());
                        attempts.push(record(index, &candidate, failed_outcome(&err)));
                        if err.code == CODE_OPEN_CANCELLED {
                            plan.record_failed(err.stage.as_str(), err.context.clone());
                            return Err(ChannelFailure {
                                plan: PlanExecError::Cancelled { attempts },
                                last_open_error: Some(err),
                            });
                        }
                        continue;
                    }
                }
            };
            attempts.push(record(index, &candidate, outcome));
        }
        plan.record_failed(OpenStage::Dial.as_str(), "all dial candidates exhausted");
        Err(ChannelFailure {
            plan: PlanExecError::Exhausted { attempts },
            last_open_error,
        })
    }

    /// 建立 UDP 数据报关联（与字节流同一编排纪律；能力校验按数据报面）。
    pub async fn open_association(
        &self,
        plan: &mut RoutePlan,
        outbound: Arc<dyn DatagramOutbound>,
        binding: TargetBinding,
        base_ctx: OpenContext,
        now_ms: u64,
    ) -> Result<EstablishedSession, PlanExecError> {
        Ok(self
            .open_association_channel(plan, outbound, binding, base_ctx, now_ms)
            .await
            .map_err(|failure| failure.plan)?
            .session)
    }

    /// 建立数据报关联通道并**配对交付**关联 IO（RIL-098 会话接线面）。
    /// 选路与回退编排与 [`SessionExecutor::open_association`] 完全同源；
    /// 差别仅在成功时保留 [`OpenedAssociation`] 并在失败时携带最近一次
    /// 真实拨号错误。
    pub async fn open_association_channel(
        &self,
        plan: &mut RoutePlan,
        outbound: Arc<dyn DatagramOutbound>,
        binding: TargetBinding,
        base_ctx: OpenContext,
        now_ms: u64,
    ) -> Result<EstablishedAssociationChannel, ChannelFailure> {
        check_generation(plan, &base_ctx).map_err(|plan| ChannelFailure {
            plan,
            last_open_error: None,
        })?;
        let via_chain = via_chain(plan);
        let mut attempts = Vec::new();
        let mut last_open_error = None;
        for (index, candidate) in self.candidates(plan).into_iter().enumerate() {
            let outcome = if let Some((code, detail)) = candidate.gap() {
                AttemptOutcome::Skipped { code, detail }
            } else if let Some(detail) = datagram_capability_gap(&outbound, &binding) {
                AttemptOutcome::Skipped {
                    code: CODE_OPEN_UNSUPPORTED,
                    detail,
                }
            } else if let Err(err) = base_ctx.check_openable(now_ms) {
                attempts.push(record(index, &candidate, failed_outcome(&err)));
                plan.record_failed(err.stage.as_str(), err.context.clone());
                return Err(ChannelFailure {
                    plan: PlanExecError::Cancelled { attempts },
                    last_open_error,
                });
            } else {
                let ctx = dial_context(&base_ctx, index);
                match outbound.open_association(&binding, &ctx).await {
                    Ok(opened) => {
                        let session = finish(
                            plan,
                            index,
                            &candidate,
                            opened.endpoint(),
                            attempts,
                            via_chain,
                        );
                        return Ok(EstablishedAssociationChannel {
                            session,
                            association: opened,
                        });
                    }
                    Err(err) => {
                        last_open_error = Some(err.clone());
                        attempts.push(record(index, &candidate, failed_outcome(&err)));
                        if err.code == CODE_OPEN_CANCELLED {
                            plan.record_failed(err.stage.as_str(), err.context.clone());
                            return Err(ChannelFailure {
                                plan: PlanExecError::Cancelled { attempts },
                                last_open_error: Some(err),
                            });
                        }
                        continue;
                    }
                }
            };
            attempts.push(record(index, &candidate, outcome));
        }
        plan.record_failed(OpenStage::Dial.as_str(), "all dial candidates exhausted");
        Err(ChannelFailure {
            plan: PlanExecError::Exhausted { attempts },
            last_open_error,
        })
    }

    /// 候选序列：计划节点优先，随后目录声明的回退（声明序、去重、
    /// 有界——不因失败追加新候选）
    fn candidates(&self, plan: &RoutePlan) -> Vec<Candidate> {
        let planned = planned_node(plan);
        if planned.is_empty() {
            return Vec::new();
        }
        let mut nodes = vec![planned.clone()];
        for fallback in self.catalog.fallbacks(plan.generation(), &planned) {
            if fallback != planned && !nodes.contains(&fallback) {
                nodes.push(fallback);
            }
        }
        nodes
            .into_iter()
            .map(|node| Candidate {
                endpoint: self.catalog.endpoint(plan.generation(), &node),
                node,
            })
            .collect()
    }
}

/// 计划的目标节点：Direct 取节点；ThroughGroup 取选中成员；Chain 取尾跳
/// （尾跳即 final_node 语义，与 [`crate::RouteDecision::final_node`] 一致）
fn planned_node(plan: &RoutePlan) -> String {
    match &plan.decision().path {
        crate::RoutePath::Direct { node } => node.clone(),
        crate::RoutePath::ThroughGroup { selected_node, .. } => selected_node.clone(),
        crate::RoutePath::Chain { hops } => {
            hops.last().map(|hop| hop.node.clone()).unwrap_or_default()
        }
    }
}

/// 经过链路（`record_dialed` 的 via_chain）：Direct 空；ThroughGroup 取
/// 中间节点；Chain 取尾跳前的全部跳
fn via_chain(plan: &RoutePlan) -> Vec<String> {
    match &plan.decision().path {
        crate::RoutePath::Direct { .. } => Vec::new(),
        crate::RoutePath::ThroughGroup {
            intermediate_nodes, ..
        } => intermediate_nodes.clone(),
        crate::RoutePath::Chain { hops } => hops
            .split_last()
            .map(|(_, rest)| rest.iter().map(|hop| hop.node.clone()).collect())
            .unwrap_or_default(),
    }
}

/// 上下文与计划的代际一致性（建立前拒绝，不静默改写）
fn check_generation(plan: &RoutePlan, ctx: &OpenContext) -> Result<(), PlanExecError> {
    if ctx.generation.as_str() != plan.generation().as_str() {
        return Err(PlanExecError::GenerationMismatch {
            plan_generation: plan.generation().as_str().to_string(),
            context_generation: ctx.generation.as_str().to_string(),
        });
    }
    Ok(())
}

/// 字节流面能力缺口（None = 可拨）
fn stream_capability_gap(outbound: &Arc<dyn StreamOutbound>) -> Option<String> {
    let caps = outbound.capabilities();
    if !caps.stream {
        return Some(format!("outbound {} cannot open stream", outbound.name()));
    }
    None
}

/// 数据报面能力缺口（None = 可拨）：无数据报能力，或声明仅固定目标
/// 却被要求绑定非空多目标集合（具体多目标需求，静态拒绝；空集合 =
/// 实现自行准入，放行由出口终审）
fn datagram_capability_gap(
    outbound: &Arc<dyn DatagramOutbound>,
    binding: &TargetBinding,
) -> Option<String> {
    let caps = outbound.capabilities();
    if !caps.datagram {
        return Some(format!(
            "outbound {} cannot open datagram association",
            outbound.name()
        ));
    }
    if caps.fixed_target_only {
        if let TargetBinding::Multi { allowed } = binding {
            if !allowed.is_empty() {
                return Some(format!(
                    "outbound {} is fixed-target-only but {} targets requested",
                    outbound.name(),
                    allowed.len()
                ));
            }
        }
    }
    None
}

/// 观测失败 → 尝试结果
fn failed_outcome(err: &crate::outbound::OpenError) -> AttemptOutcome {
    AttemptOutcome::Failed {
        stage: err.stage.as_str(),
        code: err.code,
        evidence: err.evidence.as_str(),
    }
}

/// 单次尝试的拨号上下文（同会话身份，序号递增供诊断对账）
fn dial_context(base: &OpenContext, index: usize) -> OpenContext {
    let mut ctx = base.clone();
    ctx.attempt_id = index as u32;
    ctx
}

/// 对账记录
fn record(index: usize, candidate: &Candidate, outcome: AttemptOutcome) -> AttemptRecord {
    AttemptRecord {
        attempt_id: index as u32,
        node: candidate.node.clone(),
        endpoint: candidate.record_endpoint(),
        outcome,
    }
}

/// 建立成功收尾：写执行结果（计划/实际分别可见）+ 派生会话钉
fn finish(
    plan: &mut RoutePlan,
    index: usize,
    candidate: &Candidate,
    actual: &EndpointRef,
    mut attempts: Vec<AttemptRecord>,
    via_chain: Vec<String>,
) -> EstablishedSession {
    attempts.push(AttemptRecord {
        attempt_id: index as u32,
        node: candidate.node.clone(),
        endpoint: actual.clone(),
        outcome: AttemptOutcome::Dialed,
    });
    plan.record_dialed(actual.clone(), via_chain);
    EstablishedSession {
        pin: SessionPin::for_plan(plan, &candidate.node),
        endpoint: actual.clone(),
        attempts,
    }
}

/// 台账条目（绑定即冻结：pin 与实际端点只读，无改写入口）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pin: SessionPin,
    endpoint: EndpointRef,
    established_ms: u64,
}

impl LedgerEntry {
    /// 会话钉（代际 + 出口）
    pub fn pin(&self) -> &SessionPin {
        &self.pin
    }

    /// 实际端点
    pub fn endpoint(&self) -> &EndpointRef {
        &self.endpoint
    }

    /// 建立时刻（毫秒，调用方时钟）
    pub fn established_ms(&self) -> u64 {
        self.established_ms
    }
}

/// 已建立会话台账：会话身份 → 冻结的钉与端点。**无改道/改写端点
/// API**——质量探针、代际发布都不经由台账触碰存量会话（验收「旧
/// TCP/UDP 不随质量逐包换出口」的结构半边）；同身份重bind = 重连
/// 语义（整条替换，不部分改写）。台账归会话管理面独占持有（`&mut`
/// 入口），共享并发面由上层封装。
#[derive(Debug, Default)]
pub struct SessionLedger {
    sessions: HashMap<String, LedgerEntry>,
}

impl SessionLedger {
    /// 绑定已建立会话（同身份重bind = 重连：整条替换）
    pub fn bind(
        &mut self,
        session_id: impl Into<String>,
        session: EstablishedSession,
        now_ms: u64,
    ) {
        self.sessions.insert(
            session_id.into(),
            LedgerEntry {
                pin: session.pin,
                endpoint: session.endpoint,
                established_ms: now_ms,
            },
        );
    }

    /// 查询绑定（克隆快照——条目不可变，克隆即守恒）
    pub fn entry(&self, session_id: &str) -> Option<LedgerEntry> {
        self.sessions.get(session_id).cloned()
    }

    /// 解绑（流结束/撤销）
    pub fn unbind(&mut self, session_id: &str) -> Option<LedgerEntry> {
        self.sessions.remove(session_id)
    }

    /// 全部会话身份（遍历用；快照语义，遍历期间不受并发影响）
    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// 当前绑定数
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::{EvidenceKind, OpenError, OpenStage, CODE_OPEN_REFUSED};
    use crate::plan::ExecutionOutcome;
    use crate::{RouteDecision, RouteType};
    use std::sync::Mutex;

    fn generation(id: &str) -> GenerationRef {
        GenerationRef::new(id).expect("非空代际")
    }

    fn plan_for(node: &str, gen: &GenerationRef) -> RoutePlan {
        RoutePlan::from_decision(&RouteDecision::direct(node.to_string()), gen.clone())
            .expect("合法计划")
    }

    /// 测试目录：端点表 + 回退表（Mutex 可变，模拟质量/代际变化）
    struct TestCatalog {
        endpoints: Mutex<HashMap<String, Option<EndpointRef>>>,
        fallbacks: Mutex<HashMap<String, Vec<String>>>,
    }

    impl TestCatalog {
        fn new(entries: &[(&str, Option<(&str, u16)>)], fallbacks: &[(&str, Vec<&str>)]) -> Self {
            Self {
                endpoints: Mutex::new(
                    entries
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.to_string(),
                                v.map(|(host, port)| EndpointRef::new(host, port)),
                            )
                        })
                        .collect(),
                ),
                fallbacks: Mutex::new(
                    fallbacks
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.to_string(),
                                v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                            )
                        })
                        .collect(),
                ),
            }
        }

        fn set_endpoint(&self, node: &str, endpoint: Option<(&str, u16)>) {
            self.endpoints.lock().expect("catalog").insert(
                node.to_string(),
                endpoint.map(|(h, p)| EndpointRef::new(h, p)),
            );
        }
    }

    impl FallbackCatalog for TestCatalog {
        fn endpoint(&self, _generation: &GenerationRef, node: &str) -> Option<EndpointRef> {
            self.endpoints
                .lock()
                .expect("catalog")
                .get(node)
                .cloned()
                .flatten()
        }

        fn fallbacks(&self, _generation: &GenerationRef, node: &str) -> Vec<String> {
            self.fallbacks
                .lock()
                .expect("catalog")
                .get(node)
                .cloned()
                .unwrap_or_default()
        }
    }

    /// 测试出口：按预设脚本返回成功/失败；记录每次调用的端点与上下文
    #[derive(Default)]
    struct MockStreamOutbound {
        caps: Mutex<Option<crate::outbound::OutboundCapabilities>>,
        script: Mutex<Vec<Result<EndpointRef, OpenError>>>,
        calls: Mutex<Vec<(EndpointRef, OpenContext)>>,
    }

    impl MockStreamOutbound {
        fn ok_node(host: &str, port: u16) -> Self {
            Self {
                script: Mutex::new(vec![Ok(EndpointRef::new(host, port))]),
                ..Default::default()
            }
        }

        fn script(items: Vec<Result<EndpointRef, OpenError>>) -> Self {
            Self {
                script: Mutex::new(items),
                ..Default::default()
            }
        }

        fn dial_count(&self) -> usize {
            self.calls.lock().expect("calls").len()
        }

        fn captured_generations(&self) -> Vec<String> {
            self.calls
                .lock()
                .expect("calls")
                .iter()
                .map(|(_, ctx)| ctx.generation.as_str().to_string())
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl StreamOutbound for MockStreamOutbound {
        fn name(&self) -> &'static str {
            "mock-stream"
        }

        fn capabilities(&self) -> crate::outbound::OutboundCapabilities {
            self.caps
                .lock()
                .expect("caps")
                .clone()
                .unwrap_or_else(crate::outbound::OutboundCapabilities::stream_only)
        }

        async fn open_stream(
            &self,
            target: &EndpointRef,
            ctx: &OpenContext,
        ) -> Result<crate::outbound::OpenedStream, OpenError> {
            self.calls
                .lock()
                .expect("calls")
                .push((target.clone(), ctx.clone()));
            let mut script = self.script.lock().expect("script");
            match script.pop() {
                Some(Ok(actual)) => Ok(crate::outbound::OpenedStream::new(
                    "mock-stream",
                    actual,
                    "raw",
                    0,
                    Box::new(NullIo),
                )),
                Some(Err(err)) => Err(err),
                None => Err(OpenError::timeout(OpenStage::Dial, "script exhausted")),
            }
        }
    }

    /// 空字节流 IO（测试占位）
    struct NullIo;

    #[async_trait::async_trait]
    impl crate::outbound::StreamIo for NullIo {
        async fn write_all(&mut self, _data: bytes::Bytes) -> Result<usize, OpenError> {
            Ok(0)
        }

        async fn read(&mut self, _max: usize) -> Result<Option<bytes::Bytes>, OpenError> {
            Ok(None)
        }

        async fn shutdown_write(&mut self) -> Result<(), OpenError> {
            Ok(())
        }
    }

    /// 计划/实际端点分别可见：决策快照保留计划节点，执行结果记录
    /// 拨号返回的实际端点（与目录端点不同），尝试对账 Dialed
    #[tokio::test]
    async fn plan_and_actual_endpoint_visible_separately() {
        let catalog = Arc::new(TestCatalog::new(
            &[("node-a", Some(("node-a.example", 443)))],
            &[],
        ));
        let executor = SessionExecutor::new(catalog);
        // 目录端点 node-a.example:443，出口实际落在 10.0.0.7:443（解析后）
        let outbound = Arc::new(MockStreamOutbound::ok_node("10.0.0.7", 443));
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-1", generation("gen-1")).expect("上下文");

        let session = executor
            .open_stream(&mut plan, outbound, ctx, 0)
            .await
            .expect("建立成功");
        match plan.execution() {
            ExecutionOutcome::Dialed {
                endpoint,
                via_chain,
            } => {
                assert_eq!(endpoint.host, "10.0.0.7");
                assert_eq!(endpoint.port, 443);
                assert!(via_chain.is_empty(), "直连链路为空");
            }
            other => panic!("应为 Dialed，实际 {other:?}"),
        }
        // 计划侧（决策快照）不动
        match &plan.decision().path {
            crate::RoutePath::Direct { node } => assert_eq!(node, "node-a"),
            other => panic!("决策快照不得被执行改写 {other:?}"),
        }
        assert_eq!(session.endpoint().host, "10.0.0.7");
        assert_eq!(session.pin().egress(), "node-a");
        assert_eq!(session.pin().generation().as_str(), "gen-1");
        assert_eq!(session.attempts().len(), 1);
        assert_eq!(session.attempts()[0].outcome, AttemptOutcome::Dialed);
    }

    /// 验收「新流采用新代际」：代际翻转后新流拨号上下文携带新代际；
    /// 已绑定台账的旧会话钉与端点原封不动（旧流不换出口，不重拨）
    #[tokio::test]
    async fn new_flow_adopts_new_generation_while_old_session_sticks() {
        let catalog = Arc::new(TestCatalog::new(
            &[("node-a", Some(("a.example", 443)))],
            &[],
        ));
        let executor = SessionExecutor::new(catalog.clone());

        // 旧流：gen-1 建立并绑定
        let outbound1 = Arc::new(MockStreamOutbound::ok_node("10.0.0.1", 443));
        let mut plan1 = plan_for("node-a", &generation("gen-1"));
        let ctx1 = OpenContext::new("s-1", generation("gen-1")).expect("上下文");
        let session1 = executor
            .open_stream(&mut plan1, outbound1.clone(), ctx1, 100)
            .await
            .expect("旧流建立");
        let mut ledger = SessionLedger::default();
        ledger.bind("flow-1", session1, 100);
        assert_eq!(outbound1.dial_count(), 1);

        // 质量探针改写目录（模拟换出口的诱因）——台账不受影响
        catalog.set_endpoint("node-a", Some(("a2.example", 8443)));
        assert!(matches!(
            ledger.entry("flow-1").expect("仍在台账").endpoint(),
            EndpointRef { host, .. } if host == "10.0.0.1"
        ));

        // 新流：代际翻转到 gen-2，拨号上下文必须带新代际
        let outbound2 = Arc::new(MockStreamOutbound::ok_node("10.0.0.2", 443));
        let mut plan2 = plan_for("node-a", &generation("gen-2"));
        let ctx2 = OpenContext::new("s-2", generation("gen-2")).expect("上下文");
        let session2 = executor
            .open_stream(&mut plan2, outbound2.clone(), ctx2, 200)
            .await
            .expect("新流建立");
        assert_eq!(outbound2.dial_count(), 1);
        assert_eq!(outbound1.dial_count(), 1, "旧流不得被重拨");
        assert_eq!(outbound2.captured_generations(), vec!["gen-2".to_string()]);
        ledger.bind("flow-2", session2, 200);

        // 台账：两条会话各自钉住自己的代际与实际端点
        let e1 = ledger.entry("flow-1").expect("flow-1");
        let e2 = ledger.entry("flow-2").expect("flow-2");
        assert_eq!(e1.pin().generation().as_str(), "gen-1");
        assert_eq!(e2.pin().generation().as_str(), "gen-2");
        assert_eq!(e1.endpoint().host, "10.0.0.1");
        assert_eq!(e2.endpoint().host, "10.0.0.2");
    }

    /// 代际错配（上下文 ≠ 计划）建立前拒绝，零拨号
    #[tokio::test]
    async fn generation_mismatch_rejected_before_dial() {
        let catalog = Arc::new(TestCatalog::new(
            &[("node-a", Some(("a.example", 443)))],
            &[],
        ));
        let executor = SessionExecutor::new(catalog);
        let outbound = Arc::new(MockStreamOutbound::ok_node("10.0.0.1", 443));
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-1", generation("gen-9")).expect("上下文");

        let err = executor
            .open_stream(&mut plan, outbound.clone(), ctx, 0)
            .await
            .expect_err("错配应拒绝");
        assert_eq!(err.code(), CODE_GENERATION_MISMATCH);
        assert_eq!(outbound.dial_count(), 0, "错配不得发起拨号");
        assert!(
            matches!(plan.execution(), ExecutionOutcome::Pending),
            "建立前拒绝不写执行结果"
        );
    }

    /// 目录缺席（代际无此节点）跳过不拨，顺延声明回退；目录端点与
    /// 回退序正确传递给出口
    #[tokio::test]
    async fn unknown_node_skips_and_falls_to_declared_fallback() {
        let catalog = Arc::new(TestCatalog::new(
            &[("node-a", None), ("node-b", Some(("b.example", 8443)))],
            &[("node-a", vec!["node-b", "node-c"])],
        ));
        let executor = SessionExecutor::new(catalog);
        let outbound = Arc::new(MockStreamOutbound::ok_node("10.0.0.9", 443));
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-1", generation("gen-1")).expect("上下文");

        let session = executor
            .open_stream(&mut plan, outbound.clone(), ctx, 0)
            .await
            .expect("回退成功");
        assert_eq!(outbound.dial_count(), 1, "缺席候选不拨号");
        let calls = outbound.calls.lock().expect("calls");
        assert_eq!(calls[0].0.host, "b.example");
        assert_eq!(calls[0].0.port, 8443);
        assert_eq!(calls[0].1.attempt_id, 1, "回退候选序号递增");
        drop(calls);
        let attempts = session.attempts();
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts[0].outcome,
            AttemptOutcome::Skipped {
                code: CODE_NODE_UNKNOWN,
                detail: "generation has no endpoint for node node-a".to_string(),
            }
        );
        assert_eq!(attempts[0].node, "node-a");
        assert_eq!(attempts[1].outcome, AttemptOutcome::Dialed);
        assert_eq!(session.pin().egress(), "node-b");
    }

    /// 回退序声明保序 + 计划节点重复项去重；前序失败后序成功
    #[tokio::test]
    async fn fallback_order_respected_and_planned_node_deduped() {
        let refused = OpenError::new(
            OpenStage::Dial,
            CODE_OPEN_REFUSED,
            false,
            EvidenceKind::Observed,
            "refused",
        );
        let catalog = Arc::new(TestCatalog::new(
            &[
                ("node-a", Some(("a.example", 443))),
                ("node-b", Some(("b.example", 443))),
                ("node-c", Some(("c.example", 443))),
            ],
            // 声明序 b, a(重复计划节点，去重), c
            &[("node-a", vec!["node-b", "node-a", "node-c"])],
        ));
        let executor = SessionExecutor::new(catalog);
        let outbound = Arc::new(MockStreamOutbound::script(vec![
            Ok(EndpointRef::new("10.0.0.3", 443)),
            Err(refused),
            Err(OpenError::timeout(OpenStage::Dial, "a timeout")),
        ]));
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-1", generation("gen-1")).expect("上下文");

        let session = executor
            .open_stream(&mut plan, outbound, ctx, 0)
            .await
            .expect("第三候选成功");
        let attempts = session.attempts();
        assert_eq!(attempts.len(), 3, "a 重复项应去重");
        assert_eq!(attempts[0].node, "node-a");
        assert_eq!(attempts[1].node, "node-b");
        assert_eq!(attempts[2].node, "node-c");
        assert!(matches!(attempts[0].outcome, AttemptOutcome::Failed { .. }));
        assert!(matches!(attempts[1].outcome, AttemptOutcome::Failed { .. }));
        assert_eq!(attempts[2].outcome, AttemptOutcome::Dialed);
    }

    /// 全部候选耗尽（观测失败）→ Exhausted + 执行结果 Failed（不回写
    /// 规则结果——决策快照原封不动）
    #[tokio::test]
    async fn exhausted_records_failed_without_rewriting_decision() {
        let catalog = Arc::new(TestCatalog::new(
            &[("node-a", Some(("a.example", 443)))],
            &[("node-a", vec!["node-b"])],
        ));
        // node-b 端点缺席 → Skipped；node-a 拨号超时
        let executor = SessionExecutor::new(catalog);
        let outbound = Arc::new(MockStreamOutbound::script(vec![Err(OpenError::timeout(
            OpenStage::Dial,
            "a timeout",
        ))]));
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-1", generation("gen-1")).expect("上下文");

        let err = executor
            .open_stream(&mut plan, outbound, ctx, 0)
            .await
            .expect_err("全部耗尽");
        assert_eq!(err.code(), "plan_exec.exhausted");
        assert_eq!(err.attempts().len(), 2);
        assert!(matches!(plan.execution(), ExecutionOutcome::Failed { .. }));
        match &plan.decision().path {
            crate::RoutePath::Direct { node } => assert_eq!(node, "node-a"),
            other => panic!("决策快照不得改写 {other:?}"),
        }
        assert_eq!(plan.decision().reason, None);
        assert_eq!(plan.decision().route_type, RouteType::Standard);
    }

    /// 取消/截止立即终止回退（不给已放弃的会话继续拨号）
    #[tokio::test]
    async fn cancelled_stops_fallback_immediately() {
        let catalog = Arc::new(TestCatalog::new(
            &[
                ("node-a", Some(("a.example", 443))),
                ("node-b", Some(("b.example", 443))),
            ],
            &[("node-a", vec!["node-b"])],
        ));
        let executor = SessionExecutor::new(catalog);
        let outbound = Arc::new(MockStreamOutbound::script(vec![Err(OpenError::cancelled(
            OpenStage::Dial,
        ))]));
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-1", generation("gen-1")).expect("上下文");
        ctx.cancel.cancel();

        let err = executor
            .open_stream(&mut plan, outbound.clone(), ctx, 0)
            .await
            .expect_err("已取消");
        assert_eq!(err.code(), CODE_OPEN_CANCELLED);
        assert_eq!(err.attempts().len(), 1, "取消后不继续回退");
        assert!(matches!(plan.execution(), ExecutionOutcome::Failed { .. }));
    }

    /// 数据报面：能力缺失（datagram=false）全候选跳过零拨号
    #[tokio::test]
    async fn datagram_capability_gap_skips_without_dialing() {
        struct StreamOnlyDatagram;
        #[async_trait::async_trait]
        impl DatagramOutbound for StreamOnlyDatagram {
            fn name(&self) -> &'static str {
                "stream-only-dgram"
            }
            fn capabilities(&self) -> crate::outbound::OutboundCapabilities {
                crate::outbound::OutboundCapabilities::stream_only()
            }
            async fn open_association(
                &self,
                _target: &TargetBinding,
                _ctx: &OpenContext,
            ) -> Result<crate::outbound::OpenedAssociation, OpenError> {
                panic!("能力缺口不得触达出口");
            }
        }

        let catalog = Arc::new(TestCatalog::new(
            &[
                ("node-a", Some(("a.example", 443))),
                ("node-b", Some(("b.example", 443))),
            ],
            &[("node-a", vec!["node-b"])],
        ));
        let executor = SessionExecutor::new(catalog);
        let outbound = Arc::new(StreamOnlyDatagram);
        let mut plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-udp", generation("gen-1")).expect("上下文");

        let err = executor
            .open_association(
                &mut plan,
                outbound,
                TargetBinding::Fixed {
                    target: EndpointRef::new("1.2.3.4", 53),
                },
                ctx,
                0,
            )
            .await
            .expect_err("能力缺失应耗尽");
        assert_eq!(err.code(), "plan_exec.exhausted");
        for attempt in err.attempts() {
            assert!(matches!(
                attempt.outcome,
                AttemptOutcome::Skipped {
                    code: CODE_OPEN_UNSUPPORTED,
                    ..
                }
            ));
        }
        assert!(matches!(plan.execution(), ExecutionOutcome::Failed { .. }));
    }

    /// 仅固定目标的出口拒绝非空多目标绑定（具体多目标需求，静态拒绝）；
    /// 空多目标集合（实现自决）放行由出口终审
    #[tokio::test]
    async fn fixed_target_only_rejects_nonempty_multi_binding() {
        struct FixedOnly;
        #[async_trait::async_trait]
        impl DatagramOutbound for FixedOnly {
            fn name(&self) -> &'static str {
                "fixed-only"
            }
            fn capabilities(&self) -> crate::outbound::OutboundCapabilities {
                crate::outbound::OutboundCapabilities {
                    datagram: true,
                    fixed_target_only: true,
                    ..Default::default()
                }
            }
            async fn open_association(
                &self,
                target: &TargetBinding,
                _ctx: &OpenContext,
            ) -> Result<crate::outbound::OpenedAssociation, OpenError> {
                assert!(
                    matches!(target, TargetBinding::Multi { allowed } if allowed.is_empty()),
                    "只有空多目标（实现自决）应到达出口"
                );
                Ok(crate::outbound::OpenedAssociation::new(
                    "fixed-only",
                    EndpointRef::new("10.0.0.5", 443),
                    "raw",
                    0,
                    target.clone(),
                    1200,
                    None,
                    Box::new(NullDatagramIo),
                ))
            }
        }

        struct NullDatagramIo;
        #[async_trait::async_trait]
        impl crate::outbound::DatagramIo for NullDatagramIo {
            async fn send(
                &mut self,
                _target: &EndpointRef,
                _payload: bytes::Bytes,
            ) -> Result<(), OpenError> {
                Ok(())
            }
            async fn recv(&mut self) -> Result<Option<(EndpointRef, bytes::Bytes)>, OpenError> {
                Ok(None)
            }
        }

        let catalog = Arc::new(TestCatalog::new(
            &[("node-a", Some(("a.example", 443)))],
            &[],
        ));
        let executor = SessionExecutor::new(catalog);
        let mut plan = plan_for("node-a", &generation("gen-1"));

        // 非空多目标：静态拒绝
        let ctx = OpenContext::new("s-udp-1", generation("gen-1")).expect("上下文");
        let outbound = Arc::new(FixedOnly);
        let err = executor
            .open_association(
                &mut plan,
                outbound.clone(),
                TargetBinding::Multi {
                    allowed: vec![EndpointRef::new("1.1.1.1", 53)],
                },
                ctx,
                0,
            )
            .await
            .expect_err("非空多目标应被静态拒绝");
        assert_eq!(
            err.attempts()[0].outcome,
            AttemptOutcome::Skipped {
                code: CODE_OPEN_UNSUPPORTED,
                detail: "outbound fixed-only is fixed-target-only but 1 targets requested"
                    .to_string(),
            }
        );
        assert!(matches!(plan.execution(), ExecutionOutcome::Failed { .. }));

        // 空多目标（实现自决）：放行到出口
        plan = plan_for("node-a", &generation("gen-1"));
        let ctx = OpenContext::new("s-udp-2", generation("gen-1")).expect("上下文");
        let session = executor
            .open_association(
                &mut plan,
                outbound,
                TargetBinding::Multi { allowed: vec![] },
                ctx,
                0,
            )
            .await
            .expect("空多目标放行");
        assert_eq!(session.endpoint().host, "10.0.0.5");
        assert!(matches!(plan.execution(), ExecutionOutcome::Dialed { .. }));
    }

    /// 台账：绑定即冻结、查询为克隆快照、解绑回收、同身份重bind = 重连
    #[test]
    fn ledger_bind_freeze_unbind_and_rebind() {
        let mut ledger = SessionLedger::default();
        let pin = SessionPin::for_plan(&plan_for("node-a", &generation("gen-1")), "node-a");
        let session = EstablishedSession {
            pin,
            endpoint: EndpointRef::new("10.0.0.1", 443),
            attempts: Vec::new(),
        };
        ledger.bind("flow-1", session, 42);
        let entry = ledger.entry("flow-1").expect("已绑定");
        assert_eq!(entry.pin().generation().as_str(), "gen-1");
        assert_eq!(entry.endpoint().host, "10.0.0.1");
        assert_eq!(entry.established_ms(), 42);
        assert_eq!(ledger.len(), 1);

        // 解绑回收
        let removed = ledger.unbind("flow-1").expect("解绑返回条目");
        assert_eq!(removed.endpoint().port, 443);
        assert!(ledger.is_empty());
        assert!(ledger.entry("flow-1").is_none());

        // 重bind = 重连整条替换
        let session2 = EstablishedSession {
            pin: SessionPin::for_plan(&plan_for("node-a", &generation("gen-2")), "node-a"),
            endpoint: EndpointRef::new("10.0.0.2", 443),
            attempts: Vec::new(),
        };
        ledger.bind("flow-1", session2, 50);
        let entry2 = ledger.entry("flow-1").expect("重连绑定");
        assert_eq!(entry2.pin().generation().as_str(), "gen-2");
        assert_eq!(entry2.established_ms(), 50);
        assert_eq!(ledger.len(), 1);
    }
}
