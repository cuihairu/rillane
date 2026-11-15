//! 逐连接查询服务（RIL-055，debug-and-mcp.md §3.2 Trace 查询面）：
//! 采集器（RIL-052）之上的只读面——活动/近期连接分页、过滤、单流
//! 详情与事件读取。
//!
//! 契约落点：
//! - **真实 `FlowId` 锚定**：查询入参与列表项都以 [`FlowId`] 为锚——
//!   ingress/egress 聚合键不是流 ID，本服务不存在以聚合键求值的入口
//!   （`/flows` 聚合视图归 RIL-056 兼容面，与本服务语义分立）；
//! - **缺席显式且可解释**：查无此流不是单一错误码——从未见过
//!   （[`CODE_QUERY_FLOW_UNKNOWN`]）、环形溢出逐出、TTL 过期、活动
//!   上限拒绝、采样淘汰、订阅取走（离场墓碑，`collector.flow.*` 稳定
//!   码）、追踪关闭（[`CODE_QUERY_TRACING_DISABLED`]）逐码分立；每份
//!   缺席答复携带采集器计数快照与固定说明——**无记录 ≠ 应用未发包**
//!   （采样/上限/逐出/关闭都在中间，缺席答复绝不给出「未发包」结论）；
//! - **只读不偷事件**：查询与订阅是两个面——查询走只读快照
//!   （[`FlowCollector::iter_traces`]），订阅走 [`FlowCollector::drain_closed`]；
//!   查询结构上无法取走订阅者还没读的事件，分页/详情读取不改变缓冲；
//! - **分页诚实**：列表返回过滤后匹配总数 + 当前页（近期优先——最新
//!   准入在前），`limit=0` 按参数非法显式拒绝（[`CODE_QUERY_PAGE_INVALID`]）。

use std::sync::{Arc, Mutex};

use crate::collector::{CollectorStats, FlowCollector};
use crate::trace::{FlowId, FlowOrigin, FlowTrace, TraceError, TraceEvent};

/// 稳定原因码：查询目标从未进入采集器（环形缓冲与墓碑均无）
pub const CODE_QUERY_FLOW_UNKNOWN: &str = "query.flow.unknown";
/// 稳定原因码：追踪关闭（采集器整体 no-op——缺席是配置事实而非流事实）
pub const CODE_QUERY_TRACING_DISABLED: &str = "query.tracing.disabled";
/// 稳定原因码：分页参数非法（limit 为 0）
pub const CODE_QUERY_PAGE_INVALID: &str = "query.page.invalid";
/// 缺席答复固定说明（机器口径）：无记录不是「应用未发包」的证据
pub const ABSENT_NOTE: &str = "no record is not evidence of no traffic";

/// 流状态（活动/已关闭——已关闭迹滞留环形缓冲期内可查）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// 未关闭（业务仍在进行）
    Active,
    /// 已到终态（滞留环形缓冲待订阅或逐出）
    Closed,
}

/// 列表项摘要（真实 FlowId 锚定——不是 ingress/egress 聚合键）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    /// 稳定流 ID
    pub flow: FlowId,
    /// 流/关联起止语义
    pub origin: FlowOrigin,
    /// 计划代际 ID
    pub generation: String,
    /// 活动/已关闭
    pub state: FlowState,
    /// 已见事件数
    pub events: usize,
    /// 首事件墙钟（毫秒）
    pub first_wall_ms: u64,
    /// 最近事件码（轨迹为空时 None——不造数）
    pub last_code: Option<&'static str>,
}

/// 过滤器（逐字段 None = 不过滤）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowQueryFilter {
    /// 按起止语义过滤
    pub origin: Option<FlowOrigin>,
    /// 按状态过滤
    pub state: Option<FlowState>,
    /// 按计划代际过滤
    pub generation: Option<String>,
}

/// 分页结果：过滤后匹配总数 + 当前页（近期优先）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPage {
    /// 当前页摘要项
    pub items: Vec<FlowSummary>,
    /// 过滤后匹配总数（分页总量的诚实口径）
    pub total_matching: usize,
    /// 本页起始偏移（回显调用方参数）
    pub offset: usize,
}

/// 单流查询答复：命中或显式缺席
#[derive(Debug, Clone, PartialEq)]
pub enum FlowRecord {
    /// 命中：完整轨迹（活动态是截至当前的快照——继续追加不回传）
    Found(FlowTrace),
    /// 显式缺席：稳定码 + 采集器计数快照 + 固定说明
    Absent(FlowRecordAbsent),
}

/// 显式缺席答复。`code` 区分缺席原因；`collector` 是缺席时刻的计数
/// 快照（丢事件/逐出/过期/采样计数齐全——为什么缺席可对账）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecordAbsent {
    /// 稳定缺席码（query.* / collector.flow.* / query.tracing.*）
    pub code: &'static str,
    /// 采集器计数快照
    pub collector: CollectorStats,
    /// 固定说明：无记录 ≠ 未发包
    pub note: &'static str,
}

/// 逐连接查询服务：采集器之上的只读面。共享采集器所有权（与会话
/// 埋点同一把锁），查询期间持锁一次、无重入。
#[derive(Clone)]
pub struct FlowQueryService {
    collector: Arc<Mutex<FlowCollector>>,
}

impl FlowQueryService {
    /// 装配：与埋点面共享同一采集器实例
    pub fn new(collector: Arc<Mutex<FlowCollector>>) -> Self {
        FlowQueryService { collector }
    }

    /// 活动/近期连接分页列表。近期优先（最新准入在前）；`limit=0`
    /// 显式拒绝。
    pub fn list(
        &self,
        filter: &FlowQueryFilter,
        offset: usize,
        limit: usize,
    ) -> Result<FlowPage, TraceError> {
        if limit == 0 {
            return Err(TraceError::new(
                "query",
                CODE_QUERY_PAGE_INVALID,
                "limit must be non-zero",
            ));
        }
        let collector = self.collector.lock().expect("collector poisoned");
        let matches: Vec<FlowSummary> = collector
            .iter_traces()
            .rev()
            .filter(|trace| filter_matches(filter, trace))
            .map(flow_summary)
            .collect();
        let total_matching = matches.len();
        let items = matches.into_iter().skip(offset).take(limit).collect();
        Ok(FlowPage {
            items,
            total_matching,
            offset,
        })
    }

    /// 单流详情：命中 = 完整轨迹；缺席 = 显式缺席答复（稳定码 +
    /// 计数快照——从不给出「应用未发包」结论）。
    pub fn flow(&self, flow: &FlowId) -> FlowRecord {
        let collector = self.collector.lock().expect("collector poisoned");
        if !collector.config().enabled {
            return FlowRecord::Absent(FlowRecordAbsent {
                code: CODE_QUERY_TRACING_DISABLED,
                collector: collector.stats(),
                note: ABSENT_NOTE,
            });
        }
        if let Some(trace) = collector
            .iter_traces()
            .find(|t| t.flow.as_str() == flow.as_str())
        {
            return FlowRecord::Found(trace.clone());
        }
        match collector.tombstone(flow) {
            Some(tomb) => FlowRecord::Absent(FlowRecordAbsent {
                code: tomb.reason,
                collector: collector.stats(),
                note: ABSENT_NOTE,
            }),
            None => FlowRecord::Absent(FlowRecordAbsent {
                code: CODE_QUERY_FLOW_UNKNOWN,
                collector: collector.stats(),
                note: ABSENT_NOTE,
            }),
        }
    }

    /// 事件读取：`from_seq` 起至多 `limit` 条（序号推进读取——流详情
    /// 拿全量，本方法拿增量）。缺席/未知 ID 显式报错。
    pub fn events(
        &self,
        flow: &FlowId,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<TraceEvent>, TraceError> {
        if limit == 0 {
            return Err(TraceError::new(
                "query",
                CODE_QUERY_PAGE_INVALID,
                "limit must be non-zero",
            ));
        }
        match self.flow(flow) {
            FlowRecord::Found(trace) => Ok(trace
                .events
                .iter()
                .filter(|event| event.seq >= from_seq)
                .take(limit)
                .cloned()
                .collect()),
            FlowRecord::Absent(absent) => Err(TraceError::new("query", absent.code, absent.note)),
        }
    }
}

/// 过滤器判定（逐字段 None 跳过）
fn filter_matches(filter: &FlowQueryFilter, trace: &FlowTrace) -> bool {
    if let Some(origin) = filter.origin {
        if trace.origin != origin {
            return false;
        }
    }
    if let Some(state) = filter.state {
        let trace_state = if trace.closed {
            FlowState::Closed
        } else {
            FlowState::Active
        };
        if trace_state != state {
            return false;
        }
    }
    if let Some(generation) = &filter.generation {
        if trace.generation != *generation {
            return false;
        }
    }
    true
}

/// 轨迹摘要投影（列表项——不含事件载荷）
fn flow_summary(trace: &FlowTrace) -> FlowSummary {
    FlowSummary {
        flow: trace.flow.clone(),
        origin: trace.origin,
        generation: trace.generation.clone(),
        state: if trace.closed {
            FlowState::Closed
        } else {
            FlowState::Active
        },
        events: trace.events.len(),
        first_wall_ms: trace.events.first().map(|e| e.wall_ms).unwrap_or(0),
        last_code: trace.events.last().map(|e| e.code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{CollectorConfig, CODE_TRACE_GONE_SAMPLED_OUT};
    use crate::outbound::EvidenceKind;
    use crate::trace::{FlowOrigin, TraceStage};

    fn collector(capacity: usize, active: usize, sample: u32, enabled: bool) -> FlowCollector {
        FlowCollector::new(
            CollectorConfig::new(capacity, active, 64, 3_600_000, sample, enabled).unwrap(),
        )
    }

    fn admit(collector: &mut FlowCollector, flow: &str, wall: u64) {
        let _ = collector.admit(
            FlowId::new(flow).unwrap(),
            FlowOrigin::Stream,
            "gen-1",
            TraceStage::Takeover,
            "session.takeover",
            EvidenceKind::Observed,
            1_000,
            wall,
            "tcp 8.8.8.8:443",
        );
    }

    /// 分页：近期优先、总数诚实、offset/limit 切片正确
    #[test]
    fn list_pages_newest_first_with_honest_total() {
        let mut store = collector(16, 8, 1, true);
        admit(&mut store, "f-a", 1_000);
        admit(&mut store, "f-b", 2_000);
        admit(&mut store, "f-c", 3_000);
        let service = FlowQueryService::new(std::sync::Arc::new(std::sync::Mutex::new(store)));

        let page = service
            .list(&FlowQueryFilter::default(), 0, 10)
            .expect("合法分页");
        assert_eq!(page.total_matching, 3);
        let ids: Vec<&str> = page.items.iter().map(|s| s.flow.as_str()).collect();
        assert_eq!(ids, vec!["f-c", "f-b", "f-a"], "近期优先");

        let page = service
            .list(&FlowQueryFilter::default(), 1, 1)
            .expect("合法分页");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].flow.as_str(), "f-b");
        assert_eq!(page.total_matching, 3, "总数不随分页缩小");
        assert_eq!(page.offset, 1);

        let err = service.list(&FlowQueryFilter::default(), 0, 0).unwrap_err();
        assert_eq!(err.code(), CODE_QUERY_PAGE_INVALID);
    }

    /// 过滤：起止语义/状态/代际逐字段生效
    #[test]
    fn list_filters_by_origin_state_and_generation() {
        let mut store = collector(16, 8, 1, true);
        admit(&mut store, "f-a", 1_000);
        let _ = store.admit(
            FlowId::new("f-b").unwrap(),
            FlowOrigin::Association,
            "gen-2",
            TraceStage::Takeover,
            "session.takeover",
            EvidenceKind::Observed,
            1_000,
            2_000,
            "udp 8.8.8.8:53",
        );
        admit(&mut store, "f-c", 3_000);
        let service = FlowQueryService::new(std::sync::Arc::new(std::sync::Mutex::new(store)));

        let filter = FlowQueryFilter {
            origin: Some(FlowOrigin::Association),
            ..Default::default()
        };
        let page = service.list(&filter, 0, 10).expect("合法分页");
        assert_eq!(page.total_matching, 1);
        assert_eq!(page.items[0].flow.as_str(), "f-b");

        let filter = FlowQueryFilter {
            generation: Some("gen-2".to_string()),
            ..Default::default()
        };
        let page = service.list(&filter, 0, 10).expect("合法分页");
        assert_eq!(page.total_matching, 1);
        assert_eq!(page.items[0].generation, "gen-2");
    }

    /// 详情命中 + 事件增量读取；缺席/未知 ID 在事件面显式报错
    #[test]
    fn flow_detail_and_incremental_events() {
        let mut store = collector(16, 8, 1, true);
        admit(&mut store, "f-a", 1_000);
        let _ = store.record(
            &FlowId::new("f-a").unwrap(),
            TraceStage::Egress,
            None,
            "outbound.established",
            EvidenceKind::Observed,
            1_010,
            1_010,
            "node A endpoint 9.9.9.9:443",
        );
        let service = FlowQueryService::new(std::sync::Arc::new(std::sync::Mutex::new(store)));
        let flow_id = FlowId::new("f-a").unwrap();

        match service.flow(&flow_id) {
            FlowRecord::Found(trace) => {
                assert_eq!(trace.events.len(), 2);
                assert_eq!(trace.origin, FlowOrigin::Stream);
            }
            other => panic!("应命中轨迹，得到 {other:?}"),
        }

        let events = service.events(&flow_id, 1, 10).expect("命中流可读事件");
        assert_eq!(events.len(), 1, "from_seq=1 起增量读取");
        assert_eq!(events[0].seq, 1);
        let events = service.events(&flow_id, 0, 1).expect("命中流可读事件");
        assert_eq!(events.len(), 1, "limit 有界");
        assert_eq!(events[0].seq, 0);

        let err = service
            .events(&FlowId::new("f-ghost").unwrap(), 0, 10)
            .unwrap_err();
        assert_eq!(err.code(), CODE_QUERY_FLOW_UNKNOWN);
    }

    /// 缺席显式分码：从未见过 / 采样淘汰 / 追踪关闭；缺席答复带
    /// 计数快照与固定说明（无记录 ≠ 未发包）
    #[test]
    fn absent_answers_are_explicit_per_reason() {
        // 采样率 2：第二条新流被确定性淘汰
        let mut store = collector(16, 8, 2, true);
        admit(&mut store, "f-keep", 1_000);
        admit(&mut store, "f-dropped", 2_000);
        let service = FlowQueryService::new(std::sync::Arc::new(std::sync::Mutex::new(store)));

        let unknown = service.flow(&FlowId::new("f-never").unwrap());
        match unknown {
            FlowRecord::Absent(absent) => {
                assert_eq!(absent.code, CODE_QUERY_FLOW_UNKNOWN);
                assert_eq!(absent.note, ABSENT_NOTE);
            }
            other => panic!("未知流应显式缺席，得到 {other:?}"),
        }

        let sampled = service.flow(&FlowId::new("f-dropped").unwrap());
        match sampled {
            FlowRecord::Absent(absent) => {
                assert_eq!(absent.code, CODE_TRACE_GONE_SAMPLED_OUT);
                assert_eq!(absent.note, ABSENT_NOTE);
                assert_eq!(absent.collector.traces_sampled_out, 1, "计数可对账");
            }
            other => panic!("采样淘汰流应显式缺席，得到 {other:?}"),
        }

        let disabled = FlowQueryService::new(std::sync::Arc::new(std::sync::Mutex::new(
            collector(16, 8, 1, false),
        )));
        match disabled.flow(&FlowId::new("f-keep").unwrap()) {
            FlowRecord::Absent(absent) => {
                assert_eq!(absent.code, CODE_QUERY_TRACING_DISABLED);
            }
            other => panic!("追踪关闭应显式缺席，得到 {other:?}"),
        }
    }
}
