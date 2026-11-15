//! 诊断与事件 Schema（RIL-051，debug-and-mcp.md §3.2/§8）：真实连接轨迹
//! 的类型化契约——`FlowTrace`（每 TCP 会话/UDP association 一条）+
//! `TraceEvent`（序号/单调时间/墙钟/代际/原因码/证据类型）。
//!
//! 验收口径落点：
//! - **四种证据互不混淆**：事件逐条携带 [`crate::outbound::EvidenceKind`]
//!   （预测/观测/推断/未知），每变体机器口径恒定且两两不同，不存在
//!   "未知当观测"；
//! - **schema 版本与兼容规则明确**：当前版本 [`TRACE_SCHEMA_VERSION`]，
//!   兼容规则只有一条——主版本一致才可读（更高/更低主版本按
//!   [`CODE_TRACE_SCHEMA_UNSUPPORTED`] 拒绝，静默降级会混淆语义）；
//!   同主版本内新增字段视为可容忍演进，读取方不得因未知字段失败
//!   （与 RIL-026 质量样本同口径：schema 即字段面 + 机器码，JSON 形态
//!   在查询服务 RIL-055 冻结）；
//! - **ID 三件套**：`flow_id`（每会话/关联稳定）、`attempt_id`（每次
//!   拨号）、generation（计划代际）全部显式字段，不靠聚合键反推；
//! - **时间成对**：单调时钟（耗时计算）与墙钟（跨进程对齐）逐事件
//!   携带，由调用方注入（本模块不依赖时钟）；
//! - **终态冻结**：关闭/失败事件经 [`FlowTrace::close`] 写入后轨迹不可
//!   再追加——关闭后的轨迹是冻结事实；读取方校验
//!   （[`FlowTrace::validate`]）钉住序号连续与非终态关闭；
//! - **采集边界在类型上预备**：`detail` 必须已脱敏（与 RIL-097
//!   `OpenError::context` 同纪律），载荷/HTTP 内容不在 schema 里——
//!   没有字段可填就没有东西可泄（RIL-052 采集器/RIL-057 脱敏视图
//!   在此契约上继续收窄）。

use std::fmt;

use crate::outbound::EvidenceKind;

/// Schema 版本（读取兼容规则：主版本一致才可读）
pub const TRACE_SCHEMA_VERSION: u32 = 1;

/// 稳定原因码：轨迹 schema 主版本不受支持（读取方拒绝）
pub const CODE_TRACE_SCHEMA_UNSUPPORTED: &str = "trace.schema.unsupported";
/// 稳定原因码：flow_id/代际空白
pub const CODE_TRACE_FLOW_ID_INVALID: &str = "trace.flow_id.invalid";
/// 稳定原因码：事件序号断裂或非终态关闭（校验失败）
pub const CODE_TRACE_SEQ_BROKEN: &str = "trace.seq.broken";
/// 稳定原因码：已关闭轨迹继续追加事件
pub const CODE_TRACE_CLOSED: &str = "trace.closed";

/// 事件采集路径层（TCP 会话与 UDP association 起止语义在类型上分侧）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOrigin {
    /// TCP 流会话
    Stream,
    /// UDP 数据报关联
    Association,
}

impl FlowOrigin {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            FlowOrigin::Stream => "stream",
            FlowOrigin::Association => "association",
        }
    }
}

/// 事件阶段：接管 → 身份 → DNS/嗅探 → 规则 → 计划 → 拨号尝试 →
/// 实际出口 → 传输统计 → 关闭/失败（debug-and-mcp.md §3.2 顺序）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStage {
    /// 接管（TUN/代理入口开始观察到该流）
    Takeover,
    /// 上下文/本机身份（进程归因等；平台不支持时为 Unknown 证据）
    Identity,
    /// DNS 解析或缓存命中
    Dns,
    /// 目标嗅探（与 DNS 分列：来源不同不能混写）
    Sniff,
    /// 规则/场景求值
    Rule,
    /// RoutePlan 形成（计划出口——预测证据）
    Plan,
    /// 候选/拨号尝试（必须携带 [`TraceEvent::attempt`]）
    Attempt,
    /// 实际出口（选中 ≠ 连通；连通 ≠ 远端应用成功）
    Egress,
    /// 传输统计（字节数/阶段耗时；无测量证据的阶段不造数）
    Transfer,
    /// 关闭/失败（原因码区分正常关闭与失败；终态）
    Close,
}

impl TraceStage {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            TraceStage::Takeover => "takeover",
            TraceStage::Identity => "identity",
            TraceStage::Dns => "dns",
            TraceStage::Sniff => "sniff",
            TraceStage::Rule => "rule",
            TraceStage::Plan => "plan",
            TraceStage::Attempt => "attempt",
            TraceStage::Egress => "egress",
            TraceStage::Transfer => "transfer",
            TraceStage::Close => "close",
        }
    }
}

/// 稳定流 ID：每 TCP 会话/UDP association 一个（不能把入口/出口聚合键
/// 当真实 flow ID——RIL-055 的查询契约以此为锚）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowId(String);

impl FlowId {
    /// 构造（空白拒绝——诊断必须能定位会话）
    pub fn new(id: impl Into<String>) -> Result<Self, TraceError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(TraceError::flow_id_invalid());
        }
        Ok(FlowId(id))
    }

    /// 机器口径
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 拨号尝试 ID：同会话内 A 失败后 B 重试时递增（与 RIL-097
/// `OpenContext::attempt_id` 同源口径）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId(pub u32);

/// 单条轨迹事件：序号、单调时间、墙钟、原因码与证据类型逐条携带
/// （debug-and-mcp.md §3.2）。`detail` 必须已脱敏。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    /// 会话内单调递增序号（从 0 连续，不跳不重——校验在
    /// [`FlowTrace::validate`]）
    pub seq: u64,
    /// 事件阶段
    pub stage: TraceStage,
    /// 拨号尝试 ID（仅 [`TraceStage::Attempt`] 事件携带）
    pub attempt: Option<AttemptId>,
    /// 稳定原因码（机器判定，不靠文案匹配）
    pub code: &'static str,
    /// 证据类型（预测/观测/推断/未知互不混淆）
    pub evidence: EvidenceKind,
    /// 单调时钟（毫秒；耗时计算用）
    pub monotonic_ms: u64,
    /// 墙钟（毫秒时间戳；跨进程对齐用）
    pub wall_ms: u64,
    /// 已脱敏的人读上下文（载荷/HTTP 内容不在 schema 中）
    pub detail: String,
}

/// 一条真实连接轨迹：稳定 flow ID + 起止语义 + 代际 + 事件序列。
/// 追加经 [`FlowTrace::push`]（自动分配连续序号），终态经
/// [`FlowTrace::close`]（之后不可再追加——关闭后的轨迹是冻结事实）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTrace {
    /// 稳定流 ID
    pub flow: FlowId,
    /// 流/关联起止语义
    pub origin: FlowOrigin,
    /// 计划代际 ID（RIL-006；事件不再逐条重复代际）
    pub generation: String,
    /// 事件序列
    pub events: Vec<TraceEvent>,
    /// 是否已到终态（关闭/失败事件已写入）
    pub closed: bool,
}

impl FlowTrace {
    /// 新建轨迹（空白 flow ID/代际拒绝——诊断必须能定位会话与代际）
    pub fn new(
        flow: FlowId,
        origin: FlowOrigin,
        generation: impl Into<String>,
    ) -> Result<Self, TraceError> {
        let generation = generation.into();
        if generation.trim().is_empty() {
            return Err(TraceError::flow_id_invalid());
        }
        Ok(FlowTrace {
            flow,
            origin,
            generation,
            events: Vec::new(),
            closed: false,
        })
    }

    /// 追加事件：序号由本结构分配（连续递增），已关闭轨迹拒绝追加
    #[allow(clippy::too_many_arguments)] // 参数即 schema：序号外的每列都必须逐事件显式
    pub fn push(
        &mut self,
        stage: TraceStage,
        attempt: Option<AttemptId>,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) -> Result<u64, TraceError> {
        if self.closed {
            return Err(TraceError::closed());
        }
        let seq = self.events.len() as u64;
        self.events.push(TraceEvent {
            seq,
            stage,
            attempt,
            code,
            evidence,
            monotonic_ms,
            wall_ms,
            detail: detail.into(),
        });
        Ok(seq)
    }

    /// 追加终态关闭/失败事件并冻结轨迹。此后任何 `push` 报
    /// [`CODE_TRACE_CLOSED`]。
    pub fn close(
        &mut self,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) -> Result<(), TraceError> {
        self.push(
            TraceStage::Close,
            None,
            code,
            evidence,
            monotonic_ms,
            wall_ms,
            detail,
        )?;
        self.closed = true;
        Ok(())
    }

    /// 读取方校验：序号从 0 连续、不重复；已关闭轨迹的最后一个事件
    /// 必须是关闭/失败。跨边界（IPC/持久化）读取都应过这道闸。
    pub fn validate(&self) -> Result<(), TraceError> {
        for (idx, event) in self.events.iter().enumerate() {
            if event.seq != idx as u64 {
                return Err(TraceError::seq_broken());
            }
        }
        if self.closed && !matches!(self.events.last().map(|e| e.stage), Some(TraceStage::Close)) {
            return Err(TraceError::seq_broken());
        }
        Ok(())
    }
}

/// Schema 兼容规则：主版本一致才可读。同主版本内的新增字段视为可
/// 容忍演进（读取方不得因未知字段失败）；更高/更低主版本一律按
/// [`CODE_TRACE_SCHEMA_UNSUPPORTED`] 拒绝——静默降级会混淆语义。
pub fn schema_supported(wire_version: u32) -> bool {
    wire_version == TRACE_SCHEMA_VERSION
}

/// 轨迹 schema 错误（稳定码 + 已脱敏上下文）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceError {
    /// 失败阶段
    pub stage: &'static str,
    /// 稳定原因码
    pub code: &'static str,
    /// 已脱敏的人读上下文
    pub context: String,
}

impl TraceError {
    /// 构造失败。`context` 必须已脱敏。
    pub fn new(stage: &'static str, code: &'static str, context: impl Into<String>) -> Self {
        TraceError {
            stage,
            code,
            context: context.into(),
        }
    }

    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trace {} failed ({}): {}",
            self.stage, self.code, self.context
        )
    }
}

impl std::error::Error for TraceError {}

impl TraceError {
    fn flow_id_invalid() -> Self {
        TraceError::new(
            "schema",
            CODE_TRACE_FLOW_ID_INVALID,
            "empty flow id or generation",
        )
    }

    fn seq_broken() -> Self {
        TraceError::new(
            "validate",
            CODE_TRACE_SEQ_BROKEN,
            "sequence gap or non-terminal close",
        )
    }

    fn closed() -> Self {
        TraceError::new("push", CODE_TRACE_CLOSED, "flow trace already closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 稳定码与 schema 版本口径
    #[test]
    fn trace_codes_and_schema_version_are_stable() {
        assert_eq!(TRACE_SCHEMA_VERSION, 1);
        assert_eq!(CODE_TRACE_SCHEMA_UNSUPPORTED, "trace.schema.unsupported");
        assert_eq!(CODE_TRACE_FLOW_ID_INVALID, "trace.flow_id.invalid");
        assert_eq!(CODE_TRACE_SEQ_BROKEN, "trace.seq.broken");
        assert_eq!(CODE_TRACE_CLOSED, "trace.closed");
    }

    /// 兼容规则只有一条：主版本一致才可读
    #[test]
    fn schema_compatibility_rule_is_major_exact() {
        assert!(schema_supported(1));
        assert!(!schema_supported(2), "更高主版本拒绝——静默降级混淆语义");
        assert!(!schema_supported(0), "更低主版本拒绝");
    }

    /// flow ID/代际空白拒绝；合法构造放行
    #[test]
    fn flow_id_and_generation_reject_blank() {
        assert!(FlowId::new("").is_err());
        assert!(FlowId::new("   ").is_err());
        assert!(FlowTrace::new(FlowId::new("f-1").unwrap(), FlowOrigin::Stream, "").is_err());
        let trace = FlowTrace::new(
            FlowId::new("f-1").unwrap(),
            FlowOrigin::Association,
            "gen-1",
        )
        .unwrap();
        assert_eq!(trace.flow.as_str(), "f-1");
        assert_eq!(trace.origin.as_str(), "association");
        assert_eq!(trace.events.len(), 0);
        assert!(!trace.closed);
        assert!(trace.validate().is_ok(), "空轨迹合法");
    }

    /// 序号自动分配且连续；关闭事件计入序列并冻结；关闭后追加拒绝
    #[test]
    fn push_assigns_contiguous_seq_and_close_freezes() {
        let mut trace =
            FlowTrace::new(FlowId::new("f-2").unwrap(), FlowOrigin::Stream, "gen-1").unwrap();
        assert_eq!(
            trace
                .push(
                    TraceStage::Takeover,
                    None,
                    "trace.taken_over",
                    EvidenceKind::Observed,
                    0,
                    1000,
                    "mixed :8080"
                )
                .unwrap(),
            0
        );
        assert_eq!(
            trace
                .push(
                    TraceStage::Attempt,
                    Some(AttemptId(0)),
                    "outbound.open.timeout",
                    EvidenceKind::Observed,
                    30,
                    1030,
                    "A dial timeout"
                )
                .unwrap(),
            1
        );
        assert_eq!(
            trace
                .push(
                    TraceStage::Egress,
                    Some(AttemptId(1)),
                    "plan.attempt.dialed",
                    EvidenceKind::Observed,
                    80,
                    1080,
                    "B dialed"
                )
                .unwrap(),
            2
        );
        trace
            .close(
                "session.closed",
                EvidenceKind::Observed,
                200,
                1200,
                "both halves shut",
            )
            .unwrap();
        assert!(trace.closed);
        assert!(matches!(
            trace.events.last().unwrap().stage,
            TraceStage::Close
        ));
        assert_eq!(trace.events.len(), 4, "close 事件计入事件序列");
        assert!(trace.validate().is_ok());
        let err = trace
            .push(
                TraceStage::Transfer,
                None,
                "x",
                EvidenceKind::Unknown,
                1,
                1,
                "",
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_TRACE_CLOSED);
        assert_eq!(err.stage, "push");
    }

    /// 校验器抓序号断裂与非终态关闭（跨边界读取的闸）
    #[test]
    fn validate_catches_seq_gaps_and_bad_close() {
        let mut trace =
            FlowTrace::new(FlowId::new("f-3").unwrap(), FlowOrigin::Stream, "gen-1").unwrap();
        trace
            .push(
                TraceStage::Takeover,
                None,
                "trace.taken_over",
                EvidenceKind::Observed,
                0,
                0,
                "",
            )
            .unwrap();
        // 手工破坏序号连续性（模拟跨边界损坏）
        trace.events[0].seq = 5;
        let err = trace.validate().unwrap_err();
        assert_eq!(err.code(), CODE_TRACE_SEQ_BROKEN);

        let mut honest =
            FlowTrace::new(FlowId::new("f-4").unwrap(), FlowOrigin::Stream, "gen-1").unwrap();
        honest
            .push(
                TraceStage::Rule,
                None,
                "rule.matched",
                EvidenceKind::Observed,
                0,
                0,
                "",
            )
            .unwrap();
        honest.closed = true; // 标记关闭但最后一个事件不是 Close
        let err = honest.validate().unwrap_err();
        assert_eq!(
            err.code(),
            CODE_TRACE_SEQ_BROKEN,
            "关闭轨迹必须以关闭事件收尾"
        );
    }

    /// 四种证据互不混淆：机器口径恒定且两两不同；阶段机器口径覆盖
    /// 全部变体
    #[test]
    fn evidence_and_stage_machine_codes_cover_all_variants() {
        let kinds = [
            (EvidenceKind::Observed, "observed"),
            (EvidenceKind::Inferred, "inferred"),
            (EvidenceKind::Predicted, "predicted"),
            (EvidenceKind::Unknown, "unknown"),
        ];
        for (i, (kind, code)) in kinds.iter().enumerate() {
            assert_eq!(kind.as_str(), *code);
            for (_, other) in kinds.iter().skip(i + 1) {
                assert_ne!(kind.as_str(), *other, "证据口径两两不同");
            }
        }

        let stages = [
            (TraceStage::Takeover, "takeover"),
            (TraceStage::Identity, "identity"),
            (TraceStage::Dns, "dns"),
            (TraceStage::Sniff, "sniff"),
            (TraceStage::Rule, "rule"),
            (TraceStage::Plan, "plan"),
            (TraceStage::Attempt, "attempt"),
            (TraceStage::Egress, "egress"),
            (TraceStage::Transfer, "transfer"),
            (TraceStage::Close, "close"),
        ];
        for (stage, code) in stages {
            assert_eq!(stage.as_str(), code);
        }
    }

    /// "A 失败 B 成功可追踪"的 schema 形状：Attempt 事件携带 attempt_id，
    /// 计划与执行差异可表达（计划出口 vs 实际出口分属 Plan/Egress 阶段）
    #[test]
    fn fallback_shape_expressible_in_schema() {
        let mut trace =
            FlowTrace::new(FlowId::new("f-6").unwrap(), FlowOrigin::Stream, "gen-9").unwrap();
        trace
            .push(
                TraceStage::Plan,
                None,
                "plan.built",
                EvidenceKind::Predicted,
                5,
                500,
                "node A",
            )
            .unwrap();
        trace
            .push(
                TraceStage::Attempt,
                Some(AttemptId(0)),
                "outbound.open.timeout",
                EvidenceKind::Observed,
                35,
                530,
                "A timeout",
            )
            .unwrap();
        trace
            .push(
                TraceStage::Attempt,
                Some(AttemptId(1)),
                "plan.attempt.dialed",
                EvidenceKind::Observed,
                90,
                585,
                "B dialed",
            )
            .unwrap();
        trace
            .push(
                TraceStage::Egress,
                None,
                "trace.egress",
                EvidenceKind::Observed,
                91,
                586,
                "B",
            )
            .unwrap();
        trace
            .close("session.closed", EvidenceKind::Observed, 200, 700, "done")
            .unwrap();

        assert!(trace.validate().is_ok());
        let attempts: Vec<_> = trace
            .events
            .iter()
            .filter(|e| e.stage == TraceStage::Attempt)
            .collect();
        assert_eq!(attempts.len(), 2, "两次拨号尝试各自成事件");
        assert_eq!(attempts[0].attempt, Some(AttemptId(0)));
        assert_eq!(attempts[1].attempt, Some(AttemptId(1)));
        // 计划（预测）与执行（观测）证据类型分立——选中 A ≠ 实际走 A
        let plan = trace
            .events
            .iter()
            .find(|e| e.stage == TraceStage::Plan)
            .unwrap();
        assert_eq!(plan.evidence, EvidenceKind::Predicted);
        let egress = trace
            .events
            .iter()
            .find(|e| e.stage == TraceStage::Egress)
            .unwrap();
        assert_eq!(egress.evidence, EvidenceKind::Observed);
        // 耗时可由成对时间计算（单调时钟逐事件携带）
        assert!(egress.monotonic_ms > plan.monotonic_ms);
    }
}
