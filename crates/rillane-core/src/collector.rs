//! 有界事件采集器（RIL-052，debug-and-mcp.md §3.2）：在 RIL-051 轨迹
//! schema 之上的有界采集面——环形缓冲、TTL、采样、每流事件上限、活动
//! 流上限与订阅背压。
//!
//! 验收口径落点：
//! - **慢消费者/满缓冲不阻塞数据面**：采集器是纯同步有界结构，写路径
//!   没有 await、没有通道——数据面调用点（[`FlowCollector::admit`]/
//!   [`FlowCollector::record`]/[`FlowCollector::finish`]）永远立即返回；
//!   环形缓冲满按"逐出最旧"推进；订阅侧只能拉
//!   （[`FlowCollector::drain_closed`] 有界批量），拉不动只是让已关闭
//!   迹滞留环形缓冲直到被逐出/TTL 清除，**结构性不存在阻塞点**；
//! - **丢事件计数可见**：采样淘汰、活动上限拒绝、每流上限截断、环形
//!   溢出逐出、TTL 过期五路丢弃各有独立计数（[`CollectorStats`]），
//!   截断/丢弃不静默（debug-and-mcp.md §3.2「丢事件/截断必须显式返回
//!   计数」）；
//! - **关闭追踪不影响转发**：`enabled=false` 时采集器整体 no-op——
//!   admit 立即返回 [`Admission::Disabled`]，不建迹不计数，路由与转发
//!   照常（内核只提供契约，接线面在 runtime）；
//! - **终态不丢**：每流上限只截业务事件，`Close` 事件永远写入——
//!   轨迹的关闭事实与截断事实同时可见（RIL-051 `validate` 仍通过）；
//! - **TTL 与采样确定性**：TTL 按迹首事件墙钟计时（sweep 由调用方
//!   供钟，内核不依赖时钟）；采样是确定性计数采样（每 N 条新流采
//!   1 条），内核不引入随机源——可复现的诊断优先。

use std::collections::VecDeque;

use crate::outbound::EvidenceKind;
use crate::trace::{AttemptId, FlowId, FlowOrigin, FlowTrace, TraceError, TraceStage};

/// 稳定原因码：采集器配置非法（零容量/零上限/零 TTL/零采样分母）
pub const CODE_COLLECTOR_CONFIG_INVALID: &str = "trace.collector.config_invalid";

/// 稳定原因码：迹已被环形溢出逐出（最旧被顶掉）
pub const CODE_TRACE_GONE_EVICTED: &str = "collector.flow.evicted";
/// 稳定原因码：迹已按 TTL 过期清除
pub const CODE_TRACE_GONE_EXPIRED: &str = "collector.flow.expired";
/// 稳定原因码：新流被活动上限拒绝（从未入环形缓冲）
pub const CODE_TRACE_GONE_ACTIVE_LIMIT: &str = "collector.flow.active_limit";
/// 稳定原因码：新流被确定性采样淘汰（从未入环形缓冲）
pub const CODE_TRACE_GONE_SAMPLED_OUT: &str = "collector.flow.sampled_out";
/// 稳定原因码：已关闭迹被订阅侧取走（合法离场——事件已交付订阅者）
pub const CODE_TRACE_GONE_DRAINED: &str = "collector.flow.drained";
/// 稳定原因码：历史被操作员显式清除（RIL-064 留存面——清除是显式
/// 动作，缺席答复与「从未见过」分立）
pub const CODE_TRACE_GONE_PURGED: &str = "collector.flow.purged";

/// 一条流离开采集器的墓碑记录（有界——容量与环形缓冲一致）。查询面
/// 据此区分「从未见过」与「见过但已离开」，离开原因显式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTombstone {
    /// 离开的流 ID
    pub flow: FlowId,
    /// 离开原因（稳定码）
    pub reason: &'static str,
    /// 最后已知墙钟（毫秒；准入/最后事件时刻）
    pub wall_ms: u64,
    /// 离开前已见事件数（0 = 未入环形缓冲即被剔除）
    pub events_seen: usize,
}

/// 采集器配置（构造期校验，运行期只读）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    /// 环形缓冲容量（同时存在的迹上限——含活动与已关闭）
    pub capacity: usize,
    /// 活动流上限（未关闭的迹数上限；超限拒绝新流并计数）
    pub max_active_flows: usize,
    /// 每流业务事件上限（Close 事件不受此限——终态不丢）
    pub per_flow_max_events: usize,
    /// 迹保留时长（毫秒，按迹首事件的墙钟计时）
    pub ttl_ms: u64,
    /// 采样分母：每 N 条新流采 1 条（1 = 全采；确定性计数采样）
    pub sample_rate: u32,
    /// 追踪总开关（false = 整体 no-op，不建迹不计数）
    pub enabled: bool,
}

impl CollectorConfig {
    /// 构造并校验（非法配置在装配期拒绝而非采集中途失败）
    pub fn new(
        capacity: usize,
        max_active_flows: usize,
        per_flow_max_events: usize,
        ttl_ms: u64,
        sample_rate: u32,
        enabled: bool,
    ) -> Result<Self, TraceError> {
        if capacity == 0
            || max_active_flows == 0
            || per_flow_max_events == 0
            || ttl_ms == 0
            || sample_rate == 0
        {
            return Err(TraceError::new(
                "collector",
                CODE_COLLECTOR_CONFIG_INVALID,
                "capacity/active/per-flow/ttl/sample must be non-zero",
            ));
        }
        Ok(CollectorConfig {
            capacity,
            max_active_flows,
            per_flow_max_events,
            ttl_ms,
            sample_rate,
            enabled,
        })
    }
}

/// 新流准入结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// 已建迹（首事件已写入，采集开始）
    Admitted,
    /// 采样淘汰（本条新流未入选——计数可见）
    SampledOut,
    /// 活动流上限拒绝（满载不挤占存量——计数可见）
    ActiveLimit,
    /// 追踪关闭：整体 no-op（不建迹不计数）
    Disabled,
}

/// 单条事件记录结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// 已写入
    Recorded,
    /// 每流上限截断（Close 事件不受限，业务事件被丢——计数可见）
    DroppedPerFlow,
    /// 迹不存在（未准入/已采样淘汰/已被逐出——调用方按 no-op 处理）
    UnknownFlow,
    /// 迹已关闭（终态冻结，RIL-051 口径）
    AlreadyClosed,
}

/// 丢弃与保留计数快照（丢事件/截断必须显式可见）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CollectorStats {
    /// 已建迹总数（首事件已写入）
    pub traces_admitted: u64,
    /// 采样淘汰的新流数
    pub traces_sampled_out: u64,
    /// 活动流上限拒绝数
    pub flows_dropped_active_limit: u64,
    /// 每流上限截断的业务事件数
    pub events_dropped_per_flow: u64,
    /// 环形溢出逐出的迹数（最旧被顶掉）
    pub traces_dropped_overflow: u64,
    /// 溢出逐出携带走的事件数（含未读的已关闭迹与活动迹剩余事件）
    pub events_dropped_overflow: u64,
    /// TTL 过期清除的迹数
    pub traces_expired: u64,
    /// 已关闭待订阅读取的迹数（当前滞留量——背压可见）
    pub closed_pending: u64,
    /// 当前活动迹数
    pub active_traces: u64,
}

/// 有界事件采集器：环形缓冲持有活动与已关闭迹。写路径纯同步无
/// await——数据面调用点永远立即返回；订阅侧有界拉取。
#[derive(Debug)]
pub struct FlowCollector {
    config: CollectorConfig,
    ring: VecDeque<FlowTrace>,
    /// 离场墓碑（有界：容量与环形缓冲一致——查询面的显式缺席依据）
    tombstones: VecDeque<FlowTombstone>,
    /// 采样计数（确定性：第 k 条新流，k % sample_rate == 0 入选）
    flow_counter: u64,
    stats: CollectorStats,
}

impl FlowCollector {
    /// 装配（配置非法在装配期拒绝——见 [`CollectorConfig::new`]）
    pub fn new(config: CollectorConfig) -> Self {
        FlowCollector {
            config,
            ring: VecDeque::new(),
            tombstones: VecDeque::new(),
            flow_counter: 0,
            stats: CollectorStats::default(),
        }
    }

    /// 配置只读视图
    pub fn config(&self) -> &CollectorConfig {
        &self.config
    }

    /// 计数快照（滞留量实时结算）
    pub fn stats(&self) -> CollectorStats {
        let mut stats = self.stats;
        stats.closed_pending = self.ring.iter().filter(|t| t.closed).count() as u64;
        stats.active_traces = (self.ring.len() as u64) - stats.closed_pending;
        stats
    }

    /// 新流准入并写入首事件（接管/身份等，阶段由调用方选择——trace 的
    /// 首事件是 TTL 计时锚点）。关闭态 no-op；确定性采样；活动上限
    /// 拒绝；容量不足先逐出最旧迹（环形语义，逐出计数可见）。
    #[allow(clippy::too_many_arguments)] // 首事件即 schema 列：准入必须一次写全
    pub fn admit(
        &mut self,
        flow: FlowId,
        origin: FlowOrigin,
        generation: impl Into<String>,
        first_stage: TraceStage,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) -> Admission {
        if !self.config.enabled {
            return Admission::Disabled;
        }
        self.flow_counter += 1;
        // 确定性：第 k 条新流（k 从 1 起）满足 (k-1) % N == 0 入选——
        // 第一条新流永远入选，采样窗口可复现
        if !(self.flow_counter - 1).is_multiple_of(self.config.sample_rate as u64) {
            self.stats.traces_sampled_out += 1;
            self.entomb(flow, CODE_TRACE_GONE_SAMPLED_OUT, wall_ms, 0);
            return Admission::SampledOut;
        }
        let active = self.ring.iter().filter(|t| !t.closed).count();
        if active >= self.config.max_active_flows {
            self.stats.flows_dropped_active_limit += 1;
            self.entomb(flow, CODE_TRACE_GONE_ACTIVE_LIMIT, wall_ms, 0);
            return Admission::ActiveLimit;
        }
        // 环形容量：满则逐出最旧迹（无论活动与否——有界承诺优先）
        while self.ring.len() >= self.config.capacity {
            if let Some(evicted) = self.ring.pop_front() {
                self.stats.traces_dropped_overflow += 1;
                self.stats.events_dropped_overflow += evicted.events.len() as u64;
                let wall = evicted.events.last().map(|e| e.wall_ms).unwrap_or(0);
                self.entomb(
                    evicted.flow,
                    CODE_TRACE_GONE_EVICTED,
                    wall,
                    evicted.events.len(),
                );
            }
        }
        let mut trace = FlowTrace::new(flow, origin, generation)
            .expect("admit 的 flow id/generation 由调用方保证非空");
        let _ = trace.push(
            first_stage,
            None,
            code,
            evidence,
            monotonic_ms,
            wall_ms,
            detail,
        );
        self.ring.push_back(trace);
        self.stats.traces_admitted += 1;
        Admission::Admitted
    }

    /// 追加业务事件：按 flow id 定位活动迹；每流上限截断显式计数。
    fn locate_mut(&mut self, flow: &FlowId) -> Option<&mut FlowTrace> {
        self.ring
            .iter_mut()
            .find(|t| !t.closed && t.flow.as_str() == flow.as_str())
    }

    /// 追加业务事件。未知流/已关闭按 [`RecordOutcome`] 显式区分。
    #[allow(clippy::too_many_arguments)] // 事件即 schema 列：逐条必须写全
    pub fn record(
        &mut self,
        flow: &FlowId,
        stage: TraceStage,
        attempt: Option<AttemptId>,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) -> RecordOutcome {
        let cap = self.config.per_flow_max_events;
        let Some(trace) = self.locate_mut(flow) else {
            return RecordOutcome::UnknownFlow;
        };
        if trace.closed {
            return RecordOutcome::AlreadyClosed;
        }
        // 每流上限只截业务事件；Close 由 finish 绕过上限保证终态落地
        if trace.events.len() >= cap {
            self.stats.events_dropped_per_flow += 1;
            return RecordOutcome::DroppedPerFlow;
        }
        let _ = trace.push(
            stage,
            attempt,
            code,
            evidence,
            monotonic_ms,
            wall_ms,
            detail,
        );
        RecordOutcome::Recorded
    }

    /// 追加终态关闭/失败事件并冻结（Close 事件绕过每流上限——终态
    /// 不丢；RIL-051 `validate` 仍通过）。
    pub fn finish(
        &mut self,
        flow: &FlowId,
        code: &'static str,
        evidence: EvidenceKind,
        monotonic_ms: u64,
        wall_ms: u64,
        detail: impl Into<String>,
    ) -> RecordOutcome {
        let Some(trace) = self.locate_mut(flow) else {
            return RecordOutcome::UnknownFlow;
        };
        if trace.closed {
            return RecordOutcome::AlreadyClosed;
        }
        let _ = trace.close(code, evidence, monotonic_ms, wall_ms, detail);
        RecordOutcome::Recorded
    }

    /// TTL 清扫：按迹首事件墙钟过期清除（调用方供钟）。返回清除数。
    pub fn sweep(&mut self, now_wall_ms: u64) -> usize {
        let ttl = self.config.ttl_ms;
        let taken = std::mem::take(&mut self.ring);
        let (kept, expired): (Vec<_>, Vec<_>) = taken.into_iter().partition(|t| {
            let anchor = t.events.first().map(|e| e.wall_ms).unwrap_or(0);
            now_wall_ms.saturating_sub(anchor) < ttl
        });
        self.ring = kept.into();
        let removed = expired.len();
        for trace in expired {
            let wall = trace.events.last().map(|e| e.wall_ms).unwrap_or(0);
            self.entomb(
                trace.flow,
                CODE_TRACE_GONE_EXPIRED,
                wall,
                trace.events.len(),
            );
        }
        self.stats.traces_expired += removed as u64;
        removed
    }

    /// 只读遍历环形缓冲（准入序）。查询服务在此之上做过滤/分页——
    /// 本方法不改变缓冲，与订阅侧 `drain_closed` 互不影响。
    pub fn iter_traces(&self) -> std::collections::vec_deque::Iter<'_, FlowTrace> {
        self.ring.iter()
    }

    /// 墓碑查找：流离开采集器的显式记录。`None` = 从未见过（不是
    /// 「离开」——缺席原因的机器口径由查询服务落码）。
    pub fn tombstone(&self, flow: &FlowId) -> Option<&FlowTombstone> {
        self.tombstones
            .iter()
            .rev()
            .find(|t| t.flow.as_str() == flow.as_str())
    }

    /// 离场墓碑登记（有界：满则挤掉最旧墓碑——承诺与环形缓冲同界）
    fn entomb(&mut self, flow: FlowId, reason: &'static str, wall_ms: u64, events_seen: usize) {
        while self.tombstones.len() >= self.config.capacity {
            self.tombstones.pop_front();
        }
        self.tombstones.push_back(FlowTombstone {
            flow,
            reason,
            wall_ms,
            events_seen,
        });
    }

    /// 订阅侧有界拉取：取走至多 `max_batch` 条已关闭迹。慢消费者拉不
    /// 动时迹滞留环形缓冲（滞留量在 [`FlowCollector::stats`] 可见），
    /// 写路径永不等待。
    pub fn drain_closed(&mut self, max_batch: usize) -> Vec<FlowTrace> {
        let mut batch = Vec::new();
        let mut kept = VecDeque::new();
        while let Some(trace) = self.ring.pop_front() {
            if trace.closed && batch.len() < max_batch {
                batch.push(trace);
            } else {
                kept.push_back(trace);
            }
        }
        self.ring = kept;
        for trace in &batch {
            let wall = trace.events.last().map(|e| e.wall_ms).unwrap_or(0);
            self.entomb(
                trace.flow.clone(),
                CODE_TRACE_GONE_DRAINED,
                wall,
                trace.events.len(),
            );
        }
        batch
    }

    /// 操作员显式清除历史（RIL-064 留存面）：删除全部已关闭迹（活动流
    /// 保留——清历史不拆活动流），逐条墓碑化为 [`CODE_TRACE_GONE_PURGED`]
    /// （此后查询该流答显式「已被清除」，与「从未见过」分立）。
    /// 返回删除条数。
    pub fn purge_closed(&mut self, now_wall_ms: u64) -> usize {
        let (kept, purged): (Vec<_>, Vec<_>) = self.ring.drain(..).partition(|t| !t.closed);
        self.ring = kept.into();
        let removed = purged.len();
        for trace in &purged {
            let wall = trace
                .events
                .last()
                .map(|e| e.wall_ms)
                .unwrap_or(now_wall_ms);
            self.entomb(
                trace.flow.clone(),
                CODE_TRACE_GONE_PURGED,
                wall,
                trace.events.len(),
            );
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW: &str = "f-1";

    fn config(
        capacity: usize,
        active: usize,
        per_flow: usize,
        ttl: u64,
        sample: u32,
    ) -> CollectorConfig {
        CollectorConfig::new(capacity, active, per_flow, ttl, sample, true).unwrap()
    }

    fn flow(id: &str) -> FlowId {
        FlowId::new(id).unwrap()
    }

    /// 非法配置在装配期拒绝（零值全拒绝，稳定码明确）
    #[test]
    fn invalid_config_rejected_at_assembly() {
        for cfg in [
            CollectorConfig::new(0, 1, 1, 100, 1, true),
            CollectorConfig::new(1, 0, 1, 100, 1, true),
            CollectorConfig::new(1, 1, 0, 100, 1, true),
            CollectorConfig::new(1, 1, 1, 0, 1, true),
            CollectorConfig::new(1, 1, 1, 100, 0, true),
        ] {
            let err = cfg.unwrap_err();
            assert_eq!(err.code(), CODE_COLLECTOR_CONFIG_INVALID);
            assert_eq!(err.stage, "collector");
        }
    }

    /// 关闭追踪 = 整体 no-op：admit 返回 Disabled、不建迹不计数——
    /// 关闭追踪不影响转发（数据面只付一次布尔检查的代价）
    #[test]
    fn disabled_collector_is_total_noop() {
        let config = CollectorConfig::new(4, 2, 8, 100, 1, false).unwrap();
        let mut collector = FlowCollector::new(config);
        let admission = collector.admit(
            flow(FLOW),
            FlowOrigin::Stream,
            "gen-1",
            TraceStage::Takeover,
            "trace.taken_over",
            EvidenceKind::Observed,
            0,
            1000,
            "",
        );
        assert_eq!(admission, Admission::Disabled);
        assert_eq!(
            collector.record(
                &flow(FLOW),
                TraceStage::Transfer,
                None,
                "x",
                EvidenceKind::Unknown,
                1,
                1001,
                ""
            ),
            RecordOutcome::UnknownFlow,
            "关闭态下 record 同样 no-op"
        );
        assert_eq!(collector.stats(), CollectorStats::default());
    }

    /// 确定性采样：每 2 条采 1 条——第 1、3 条入选，第 2、4 条淘汰且
    /// 计数可见
    #[test]
    fn deterministic_sampling_kept_and_counted() {
        let mut collector = FlowCollector::new(config(8, 8, 8, 1000, 2));
        let mut results = Vec::new();
        for i in 0..4 {
            results.push(collector.admit(
                flow(&format!("f-{i}")),
                FlowOrigin::Stream,
                "gen-1",
                TraceStage::Takeover,
                "trace.taken_over",
                EvidenceKind::Observed,
                i as u64,
                1000 + i as u64,
                "",
            ));
        }
        assert_eq!(
            results,
            vec![
                Admission::Admitted,
                Admission::SampledOut,
                Admission::Admitted,
                Admission::SampledOut
            ],
            "确定性：第 k 条新流 k%2==0 入选"
        );
        let stats = collector.stats();
        assert_eq!(stats.traces_admitted, 2);
        assert_eq!(stats.traces_sampled_out, 2);
    }

    /// 活动流上限：满载拒绝新流并计数，存量不挤占
    #[test]
    fn active_limit_rejects_without_evicting() {
        let mut collector = FlowCollector::new(config(8, 1, 8, 1000, 1));
        assert_eq!(
            collector.admit(
                flow("a"),
                FlowOrigin::Stream,
                "g",
                TraceStage::Takeover,
                "t",
                EvidenceKind::Observed,
                0,
                1000,
                ""
            ),
            Admission::Admitted
        );
        assert_eq!(
            collector.admit(
                flow("b"),
                FlowOrigin::Stream,
                "g",
                TraceStage::Takeover,
                "t",
                EvidenceKind::Observed,
                1,
                1001,
                ""
            ),
            Admission::ActiveLimit
        );
        assert_eq!(collector.stats().flows_dropped_active_limit, 1);
        // 存量照常可写
        assert_eq!(
            collector.record(
                &flow("a"),
                TraceStage::Rule,
                None,
                "rule.matched",
                EvidenceKind::Observed,
                2,
                1002,
                ""
            ),
            RecordOutcome::Recorded
        );
    }

    /// 每流上限截断：事件总数（含准入首事件）超限被丢且计数可见；
    /// **Close 事件绕过上限**——终态不丢，validate 仍通过
    #[test]
    fn per_flow_cap_truncates_but_close_always_lands() {
        let mut collector = FlowCollector::new(config(8, 8, 2, 1000, 1));
        collector.admit(
            flow(FLOW),
            FlowOrigin::Stream,
            "g",
            TraceStage::Takeover,
            "t",
            EvidenceKind::Observed,
            0,
            1000,
            "",
        );
        assert_eq!(
            collector.record(
                &flow(FLOW),
                TraceStage::Rule,
                None,
                "c1",
                EvidenceKind::Observed,
                1,
                1001,
                ""
            ),
            RecordOutcome::Recorded
        );
        assert_eq!(
            collector.record(
                &flow(FLOW),
                TraceStage::Rule,
                None,
                "c2",
                EvidenceKind::Observed,
                2,
                1002,
                ""
            ),
            RecordOutcome::DroppedPerFlow,
            "首事件 + 1 条业务已满上限，第 2 条业务事件被截断"
        );
        assert_eq!(collector.stats().events_dropped_per_flow, 1);
        // 终态不受上限约束
        assert_eq!(
            collector.finish(
                &flow(FLOW),
                "session.closed",
                EvidenceKind::Observed,
                9,
                1009,
                ""
            ),
            RecordOutcome::Recorded
        );
        let batch = collector.drain_closed(10);
        assert_eq!(batch.len(), 1);
        assert!(
            batch[0].validate().is_ok(),
            "截断后的轨迹仍是合法 schema（close 在末尾）"
        );
        assert_eq!(batch[0].events.len(), 3, "首事件 + 1 条业务 + 1 条 close");
        // 已关闭迹再 record/finish 显式报 AlreadyClosed
        assert_eq!(
            collector.record(
                &flow(FLOW),
                TraceStage::Transfer,
                None,
                "x",
                EvidenceKind::Unknown,
                10,
                1010,
                ""
            ),
            RecordOutcome::UnknownFlow,
            "已关闭且已被取走 → 未知流"
        );
    }

    /// 环形溢出：容量满逐出最旧迹，逐出的迹数与事件数都可见
    #[test]
    fn ring_overflow_evicts_oldest_with_visible_counts() {
        let mut collector = FlowCollector::new(config(2, 8, 8, 10_000, 1));
        collector.admit(
            flow("old"),
            FlowOrigin::Stream,
            "g",
            TraceStage::Takeover,
            "t",
            EvidenceKind::Observed,
            0,
            1000,
            "",
        );
        collector.record(
            &flow("old"),
            TraceStage::Rule,
            None,
            "c",
            EvidenceKind::Observed,
            1,
            1001,
            "",
        );
        collector.admit(
            flow("mid"),
            FlowOrigin::Stream,
            "g",
            TraceStage::Takeover,
            "t",
            EvidenceKind::Observed,
            2,
            1002,
            "",
        );
        // 第 3 条准入 → 逐出最旧 "old"（2 个事件计入溢出）
        assert_eq!(
            collector.admit(
                flow("new"),
                FlowOrigin::Stream,
                "g",
                TraceStage::Takeover,
                "t",
                EvidenceKind::Observed,
                3,
                1003,
                ""
            ),
            Admission::Admitted
        );
        let stats = collector.stats();
        assert_eq!(stats.traces_dropped_overflow, 1);
        assert_eq!(stats.events_dropped_overflow, 2);
        // 被逐出的流再 record → UnknownFlow（不复活，不阻塞）
        assert_eq!(
            collector.record(
                &flow("old"),
                TraceStage::Rule,
                None,
                "x",
                EvidenceKind::Unknown,
                4,
                1004,
                ""
            ),
            RecordOutcome::UnknownFlow
        );
        assert_eq!(collector.drain_closed(10).len(), 0, "活动迹不进订阅批次");
    }

    /// TTL 清扫：过期迹按首事件墙钟清除并计数；未过期存活
    #[test]
    fn ttl_sweep_removes_expired_only() {
        let mut collector = FlowCollector::new(config(8, 8, 8, 500, 1));
        collector.admit(
            flow("a"),
            FlowOrigin::Stream,
            "g",
            TraceStage::Takeover,
            "t",
            EvidenceKind::Observed,
            0,
            1000,
            "",
        );
        collector.admit(
            flow("b"),
            FlowOrigin::Stream,
            "g",
            TraceStage::Takeover,
            "t",
            EvidenceKind::Observed,
            1,
            1400,
            "",
        );
        assert_eq!(collector.sweep(1_400), 0, "锚点：a 恰好 400ms < 500ms 存活");
        assert_eq!(collector.sweep(1_501), 1, "a 过期（501ms ≥ 500ms）被清除");
        let stats = collector.stats();
        assert_eq!(stats.traces_expired, 1);
        assert_eq!(
            collector.record(
                &flow("a"),
                TraceStage::Rule,
                None,
                "x",
                EvidenceKind::Unknown,
                9,
                1501,
                ""
            ),
            RecordOutcome::UnknownFlow
        );
        assert_eq!(
            collector.record(
                &flow("b"),
                TraceStage::Rule,
                None,
                "y",
                EvidenceKind::Observed,
                9,
                1501,
                ""
            ),
            RecordOutcome::Recorded,
            "未过期迹不受清扫影响"
        );
    }

    /// 订阅背压：有界批量拉取；消费者拉不动时迹滞留环形缓冲（滞留量
    /// 可见），写路径继续推进永不等待——满缓冲不阻塞数据面
    #[test]
    fn slow_consumer_never_blocks_writes_and_backlog_visible() {
        let mut collector = FlowCollector::new(config(4, 8, 8, 10_000, 1));
        // 产出 3 条已关闭迹
        for i in 0..3 {
            let id = format!("f-{i}");
            collector.admit(
                flow(&id),
                FlowOrigin::Stream,
                "g",
                TraceStage::Takeover,
                "t",
                EvidenceKind::Observed,
                i,
                1000 + i,
                "",
            );
            collector.finish(
                &flow(&id),
                "session.closed",
                EvidenceKind::Observed,
                i + 1,
                1000 + i,
                "",
            );
        }
        assert_eq!(
            collector.stats().closed_pending,
            3,
            "消费者未来拉——滞留可见"
        );
        // 消费者一次只拉 2 条（有界批量）
        assert_eq!(collector.drain_closed(2).len(), 2);
        assert_eq!(collector.stats().closed_pending, 1);
        // 写路径不受滞留影响：新流照常准入
        assert_eq!(
            collector.admit(
                flow("f-x"),
                FlowOrigin::Stream,
                "g",
                TraceStage::Takeover,
                "t",
                EvidenceKind::Observed,
                9,
                1009,
                ""
            ),
            Admission::Admitted
        );
        assert_eq!(collector.drain_closed(10).len(), 1, "剩余滞留批次可继续拉");
    }

    /// 语义借用：drain_closed 不会动到活动迹（不抢在途轨迹）
    #[test]
    fn drain_closed_leaves_active_traces_alone() {
        let mut collector = FlowCollector::new(config(4, 8, 8, 10_000, 1));
        collector.admit(
            flow("live"),
            FlowOrigin::Association,
            "g",
            TraceStage::Takeover,
            "t",
            EvidenceKind::Observed,
            0,
            1000,
            "",
        );
        assert!(collector.drain_closed(10).is_empty());
        assert_eq!(
            collector.record(
                &flow("live"),
                TraceStage::Transfer,
                None,
                "bytes",
                EvidenceKind::Observed,
                5,
                1005,
                ""
            ),
            RecordOutcome::Recorded,
            "活动迹在 drain 后仍可写"
        );
    }

    /// 显式清除历史（RIL-064）：只删已关闭迹、活动流保留；被清除流
    /// 的缺席答复从此带 collector.flow.purged（与「从未见过」分立）
    #[test]
    fn purge_closed_removes_history_keeps_active_and_marks_tombstones() {
        let mut collector = FlowCollector::new(config(8, 8, 8, 10_000, 1));
        for id in ["done", "live"] {
            collector.admit(
                flow(id),
                FlowOrigin::Stream,
                "g",
                TraceStage::Takeover,
                "t",
                EvidenceKind::Observed,
                0,
                1000,
                "",
            );
        }
        collector.finish(
            &flow("done"),
            "session.closed",
            EvidenceKind::Observed,
            50,
            1050,
            "",
        );
        assert_eq!(collector.purge_closed(2_000), 1, "只删已关闭迹");
        assert_eq!(collector.stats().active_traces, 1, "活动流不被清除拆掉");
        assert!(
            collector.tombstone(&flow("done")).is_some(),
            "被清除流留墓碑"
        );
        assert_eq!(
            collector.tombstone(&flow("done")).unwrap().reason,
            CODE_TRACE_GONE_PURGED
        );
        assert!(
            collector.tombstone(&flow("never")).is_none(),
            "从未见过的流没有墓碑——两态分立"
        );
        // 活动迹仍可写（清除不破坏活动面）
        assert_eq!(
            collector.record(
                &flow("live"),
                TraceStage::Transfer,
                None,
                "bytes",
                EvidenceKind::Observed,
                60,
                1060,
                ""
            ),
            RecordOutcome::Recorded
        );
        // 幂等：再清一次 = 0 条
        assert_eq!(collector.purge_closed(2_100), 0);
    }
}
