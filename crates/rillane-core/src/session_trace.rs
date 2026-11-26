//! 真实流生命周期埋点（RIL-053）：会话执行权威路径（RIL-098）上的
//! 阶段事件记录——接管/身份/DNS/嗅探由调用方观测推进（[`SessionTracer::observe`]
//! 显式供钟），规则/计划/拨号尝试/实际出口/传输/关闭由内核路径如实
//! 落点（debug-and-mcp.md §3.2 阶段顺序）。
//!
//! 设计口径落点：
//! - **缺少测量证据不造数**：本模块没有任何 RTT/丢包生成入口——事件
//!   只携带观测到的阶段事实（稳定码 + 证据类型 + 时间）；内核未测量
//!   的量（队列深度、远端应用结果）不出现。游戏面关心的三类内核可见
//!   事实有对应落点：映射 = [`CODE_ASSOCIATION_MAPPED`]、报文超限拒绝
//!   计入关联关闭 detail、切网的内核可见面 = 控制链回收
//!   （[`CODE_ASSOCIATION_RECLAIMED`]——链路切换表现为控制链重建）；
//! - **本地权威轨迹 + 可选汇聚**：[`SessionTracer`] 恒构建完整
//!   `FlowTrace`（逐会话契约，不受采样/上限影响——采样语义归采集器）；
//!   传入采集器（RIL-052）时同步转发 admit/record/finish；
//! - **时钟锚由调用方注入**：`start` 注入单调锚与墙钟锚，内核事件取
//!   「锚 + 真实流逝」（`Instant` 实测）——注入的是基准，流逝是真实
//!   测量；调用方自观测事件（[`SessionTracer::observe`]）显式供钟；
//! - **A 失败改拨 B 可完整解释**：尝试对账事件逐条携带 attempt_id、
//!   节点、稳定码与证据（跳过 = 预测证据；失败 = 观测/推断；拨通 =
//!   观测）。尝试时长执行器未逐次测量——不逐次造数，各尝试事件共享
//!   对账时刻（诚实面：能答「谁失败为何」，不假装测过没测的东西）；
//! - **detail 预脱敏**：节点名/原因文案按不可信文本消毒（RIL-057 同一
//!   消毒闸）后才进轨迹——订阅节点名不能变成轨迹里的注入载荷。

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::collector::FlowCollector;
use crate::executor::{AttemptOutcome, AttemptRecord};
use crate::outbound::EvidenceKind;
use crate::plan::RoutePlan;
use crate::redact::sanitize_untrusted;
use crate::session::TransferDirection;
use crate::trace::{AttemptId, FlowId, FlowOrigin, FlowTrace, TraceError, TraceStage};

/// 稳定原因码：接管（轨迹首事件——采集器准入锚点）
pub const CODE_TRACE_TAKEOVER: &str = "session.takeover";
/// 稳定原因码：规则/场景命中（计划携带的决策原因）
pub const CODE_TRACE_RULE: &str = "route.rule";
/// 稳定原因码：RoutePlan 形成（预测证据——选中 ≠ 连通）
pub const CODE_TRACE_PLAN: &str = "route.plan";
/// 稳定原因码：拨号尝试成功（观测证据；失败/跳过码来自尝试记录）
pub const CODE_ATTEMPT_DIALED: &str = "outbound.dialed";
/// 稳定原因码：TCP 实际出口建立
pub const CODE_EGRESS_ESTABLISHED: &str = "outbound.established";
/// 稳定原因码：UDP 关联映射建立
pub const CODE_ASSOCIATION_MAPPED: &str = "association.mapped";
/// 稳定原因码：首个上行字节（客户端 → 出口）
pub const CODE_TRANSFER_FIRST_UP: &str = "transfer.first_up";
/// 稳定原因码：首个下行字节（出口 → 客户端）——HTTP TTFB 与首个下行
/// 字节经此分立（TTFB ≈ 上行完成后的 first_down，两者时间独立可算）
pub const CODE_TRANSFER_FIRST_DOWN: &str = "transfer.first_down";
/// 稳定原因码：流正常关闭（半关闭/EOF 全收口）
pub const CODE_STREAM_CLOSED: &str = "session.closed";
/// 稳定原因码：流转发失败（数据面观测——出口不可达/泵送中断等非正常
/// 收口；与 session.closed 的正常 EOF 收口分立）
pub const CODE_STREAM_FAILED: &str = "session.failed";
/// 稳定原因码：关联正常关闭（出口/客户端读侧结束）
pub const CODE_ASSOCIATION_CLOSED: &str = "association.closed";
/// 稳定原因码：关联因控制链关闭回收（SOCKS5 UDP 控制连接结束/切网重建）
pub const CODE_ASSOCIATION_RECLAIMED: &str = "association.reclaimed";
/// 稳定原因码：成功回复写失败（出口已就地释放）
pub const CODE_REPLY_FAILED: &str = "session.reply_failed";

const DETAIL_MAX: usize = 128;

/// 会话轨迹记录器：本地权威 `FlowTrace` + 可选采集器转发。时钟锚在
/// `start` 注入；内核事件时间 = 锚 + 真实流逝。
pub struct SessionTracer {
    flow: FlowId,
    trace: FlowTrace,
    collector: Option<Arc<Mutex<FlowCollector>>>,
    epoch: Instant,
    base_mono_ms: u64,
    base_wall_ms: u64,
}

impl SessionTracer {
    /// 开轨：接管事件为轨迹首事件（采集器准入锚点）。单调/墙钟锚由
    /// 调用方注入；`detail` 必须已脱敏。
    pub fn start(
        collector: Option<Arc<Mutex<FlowCollector>>>,
        flow: FlowId,
        origin: FlowOrigin,
        generation: impl Into<String>,
        now_mono_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) -> Result<Self, TraceError> {
        let generation = generation.into();
        let detail = detail.into();
        let mut trace = FlowTrace::new(flow.clone(), origin, generation.clone())?;
        trace.push(
            TraceStage::Takeover,
            None,
            CODE_TRACE_TAKEOVER,
            EvidenceKind::Observed,
            now_mono_ms,
            wall_ms,
            &detail,
        )?;
        if let Some(collector) = &collector {
            let _ = collector.lock().expect("collector poisoned").admit(
                flow.clone(),
                origin,
                generation,
                TraceStage::Takeover,
                CODE_TRACE_TAKEOVER,
                EvidenceKind::Observed,
                now_mono_ms,
                wall_ms,
                detail,
            );
        }
        Ok(SessionTracer {
            flow,
            trace,
            collector,
            epoch: Instant::now(),
            base_mono_ms: now_mono_ms,
            base_wall_ms: wall_ms,
        })
    }

    /// 调用方自观测事件（身份/DNS/嗅探等内核路径之外的事实）——时间
    /// 显式供钟（观测方手里的钟），本方法不做任何推断。
    #[allow(clippy::too_many_arguments)] // 参数即 schema：逐事件写全
    pub fn observe(
        &mut self,
        stage: TraceStage,
        attempt: Option<AttemptId>,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) {
        self.write(
            stage,
            attempt,
            code,
            evidence,
            monotonic_ms,
            wall_ms,
            detail,
        );
    }

    /// 内核供钟写入：单调 = 注入锚 + 真实流逝；墙钟 = 墙钟锚 + 同一
    /// 流逝（成对推进——耗时计算与跨进程对齐分开）
    fn emit(
        &mut self,
        stage: TraceStage,
        attempt: Option<AttemptId>,
        code: &'static str,
        evidence: EvidenceKind,
        detail: impl Into<String>,
    ) {
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        self.write(
            stage,
            attempt,
            code,
            evidence,
            self.base_mono_ms.saturating_add(elapsed),
            self.base_wall_ms.saturating_add(elapsed),
            detail,
        );
    }

    /// 本地权威轨迹恒写；采集器可选转发（采样/上限语义归采集器）
    #[allow(clippy::too_many_arguments)] // 参数即 schema：逐事件写全
    fn write(
        &mut self,
        stage: TraceStage,
        attempt: Option<AttemptId>,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        let _ = self.trace.push(
            stage,
            attempt,
            code,
            evidence,
            monotonic_ms,
            wall_ms,
            &detail,
        );
        if let Some(collector) = &self.collector {
            let _ = collector.lock().expect("collector poisoned").record(
                &self.flow,
                stage,
                attempt,
                code,
                evidence,
                monotonic_ms,
                wall_ms,
                detail,
            );
        }
    }

    /// 规则/场景命中事件（计划携带的决策原因；无原因不造数——不发事件）
    pub fn rule(&mut self, plan: &RoutePlan) {
        let Some(reason) = &plan.decision().reason else {
            return;
        };
        self.emit(
            TraceStage::Rule,
            None,
            CODE_TRACE_RULE,
            EvidenceKind::Predicted,
            sanitize_untrusted(reason, DETAIL_MAX),
        );
    }

    /// 计划事件（预测证据）：路径摘要——direct / 组选择（选组可解释）
    /// / 链
    pub fn plan(&mut self, plan: &RoutePlan) {
        let decision = plan.decision();
        let path = match &decision.path {
            crate::RoutePath::Direct { node } => {
                format!("direct {}", sanitize_untrusted(node, 64))
            }
            crate::RoutePath::ThroughGroup {
                group,
                selected_node,
                intermediate_nodes,
            } => {
                let via = if intermediate_nodes.is_empty() {
                    "-".to_string()
                } else {
                    intermediate_nodes
                        .iter()
                        .map(|n| sanitize_untrusted(n, 64))
                        .collect::<Vec<_>>()
                        .join(">")
                };
                format!(
                    "group {} via {} select {}",
                    sanitize_untrusted(group, 64),
                    via,
                    sanitize_untrusted(selected_node, 64)
                )
            }
            crate::RoutePath::Chain { hops } => format!("chain {} hops", hops.len()),
        };
        self.emit(
            TraceStage::Plan,
            None,
            CODE_TRACE_PLAN,
            EvidenceKind::Predicted,
            path,
        );
    }

    /// 尝试对账事件：每条尝试记录一个 Attempt 事件（必须携带
    /// attempt_id——A 失败 B 成功逐条可解释）
    pub fn attempts(&mut self, records: &[AttemptRecord]) {
        for record in records {
            let node = sanitize_untrusted(&record.node, 64);
            let (code, evidence, detail) = match &record.outcome {
                AttemptOutcome::Skipped { code, detail } => (
                    *code,
                    EvidenceKind::Predicted,
                    format!("node {node} skip: {}", sanitize_untrusted(detail, 64)),
                ),
                AttemptOutcome::Failed {
                    stage,
                    code,
                    evidence,
                } => (
                    *code,
                    evidence_from_str(evidence),
                    format!("node {node} stage {stage}"),
                ),
                AttemptOutcome::Dialed => (
                    CODE_ATTEMPT_DIALED,
                    EvidenceKind::Observed,
                    format!("node {node}"),
                ),
            };
            self.emit(
                TraceStage::Attempt,
                Some(AttemptId(record.attempt_id)),
                code,
                evidence,
                detail,
            );
        }
    }

    /// 实际出口事件（观测证据）：流 = 出口建立；关联 = 映射建立
    pub fn egress(&mut self, node: &str, endpoint: &str, association: bool) {
        let (code, label) = if association {
            (CODE_ASSOCIATION_MAPPED, "map")
        } else {
            (CODE_EGRESS_ESTABLISHED, "node")
        };
        self.emit(
            TraceStage::Egress,
            None,
            code,
            EvidenceKind::Observed,
            format!(
                "{label} {} endpoint {}",
                sanitize_untrusted(node, 64),
                sanitize_untrusted(endpoint, 64)
            ),
        );
    }

    /// 首字节事件（观测证据）：上行/下行分立——网页阶段耗时区分 HTTP
    /// TTFB 与首个下行字节（两者时间独立可算），游戏映射时延取上行首
    /// 包。`elapsed_ms` 是泵实测的首字节距泵启动流逝。
    pub fn transfer_first(&mut self, direction: TransferDirection, elapsed_ms: u64) {
        let (code, detail) = match direction {
            TransferDirection::ClientToEgress => (CODE_TRANSFER_FIRST_UP, "up"),
            TransferDirection::EgressToClient => (CODE_TRANSFER_FIRST_DOWN, "down"),
        };
        self.emit(
            TraceStage::Transfer,
            None,
            code,
            EvidenceKind::Observed,
            format!("{detail} {elapsed_ms}ms"),
        );
    }

    /// 终态关闭/失败事件并冻结轨迹（本地 close + 采集器 finish——终态
    /// 不丢）
    pub fn close(&mut self, code: &'static str, evidence: EvidenceKind, detail: impl Into<String>) {
        let detail = detail.into();
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        let mono = self.base_mono_ms.saturating_add(elapsed);
        let wall = self.base_wall_ms.saturating_add(elapsed);
        let _ = self.trace.close(code, evidence, mono, wall, &detail);
        if let Some(collector) = &self.collector {
            let _ = collector
                .lock()
                .expect("collector poisoned")
                .finish(&self.flow, code, evidence, mono, wall, detail);
        }
    }

    /// 本地权威轨迹（逐会话完整——不受采集器采样影响）
    pub fn trace(&self) -> &FlowTrace {
        &self.trace
    }

    /// 消费本地轨迹
    pub fn into_trace(self) -> FlowTrace {
        self.trace
    }
}

/// 尝试记录的证据机器口径 → 证据类型（未知口径按 Unknown——不猜测）
pub fn evidence_from_str(code: &str) -> EvidenceKind {
    match code {
        "observed" => EvidenceKind::Observed,
        "inferred" => EvidenceKind::Inferred,
        "predicted" => EvidenceKind::Predicted,
        _ => EvidenceKind::Unknown,
    }
}
