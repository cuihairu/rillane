//! SessionObserver 低频阶段事件（RIL-102 / io-and-accounting.md §1、§5）。
//!
//! 高频业务字节走 [`crate::meter::SessionMeter`] 计数器——本面只记录
//! **接入/建立/握手/回退/关闭**等低频阶段事件，API 里不存在逐读写的
//! 字节事件（不为每次读写分配事件）。每条事件统一携带
//! session/attempt/generation 关联；指标投影
//! （[`MetricKey`]：stage×result×origin 有界枚举积）结构上无法携带
//! session_id/域名/路径等高基数身份——高基数信息只留在有界诊断尾环
//! （受限逐流视图）。`record` 永不阻塞调用方（try_lock + 可见丢弃
//! 计数）——统计关闭（容量 0）或慢消费者都不能影响转发；CLI/MCP
//! 经同一 [`ObserverView`] 复用诊断视图。

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::meter::TrafficOrigin;
use crate::resources::ResourceError;

/// 稳定原因码：阶段事件非法（空会话/尝试阶段缺 attempt/失败缺原因码）
pub const CODE_OBSERVER_EVENT: &str = "observer.event.invalid";

/// 诊断尾环缺省容量（有界——溢出弹最旧，驱逐可见）
pub const OBSERVER_RING_DEFAULT: usize = 256;

/// 会话阶段（低频、封闭枚举）：接入 → 建立 → 握手 → 回退 → 关闭。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionStage {
    /// 接入（入口准入完成）
    Ingress,
    /// 建立（出口建连尝试——逐尝试，须带 attempt_id）
    Establish,
    /// 握手（协议/承载握手——逐尝试，须带 attempt_id）
    Handshake,
    /// 回退（执行器决定换承载——A 失败 B 承载对账）
    Fallback,
    /// 关闭（会话终态）
    Close,
}

impl SessionStage {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStage::Ingress => "ingress",
            SessionStage::Establish => "establish",
            SessionStage::Handshake => "handshake",
            SessionStage::Fallback => "fallback",
            SessionStage::Close => "close",
        }
    }

    /// 逐尝试阶段（缺 attempt_id 的事件非法）
    pub fn needs_attempt(self) -> bool {
        matches!(
            self,
            SessionStage::Establish | SessionStage::Handshake | SessionStage::Fallback
        )
    }
}

/// 阶段结果（封闭枚举）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StageResult {
    /// 成功完成
    Succeeded,
    /// 失败（携带稳定原因码）
    Failed,
    /// 显式拒绝（携带稳定原因码）
    Rejected,
}

impl StageResult {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            StageResult::Succeeded => "succeeded",
            StageResult::Failed => "failed",
            StageResult::Rejected => "rejected",
        }
    }
}

/// 指标键：stage × result × origin 的**有界枚举积**（≤ 5×3×3 = 45）。
/// 全部字段是词汇表静态串——结构上无法携带 session_id/域名/路径等
/// 高基数身份（高基数信息只进受限逐流视图，不进指标标签）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetricKey {
    /// 阶段
    pub stage: &'static str,
    /// 结果
    pub result: &'static str,
    /// 流量来源（probe/prewarm 与用户业务分桶）
    pub origin: &'static str,
}

/// 阶段事件：统一 session/attempt/generation 关联。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageEvent {
    /// 会话身份（非空——高基数身份，只进诊断尾环）
    pub session_id: String,
    /// 尝试身份（逐尝试阶段必填）
    pub attempt_id: Option<u32>,
    /// 配置代际（可选关联）
    pub generation: Option<String>,
    /// 阶段
    pub stage: SessionStage,
    /// 结果
    pub result: StageResult,
    /// 稳定原因码（Failed/Rejected 必填；Succeeded 禁止）
    pub code: Option<&'static str>,
    /// 流量来源（构造期分类——probe/prewarm 与用户业务分桶）
    pub origin: TrafficOrigin,
}

impl StageEvent {
    /// 构造并校验：会话身份非空；逐尝试阶段必须带 attempt_id；
    /// Failed/Rejected 必须带稳定原因码；Succeeded 不得带原因码。
    /// 非法返回 [`CODE_OBSERVER_EVENT`]——事件面不做静默修复。
    pub fn new(
        session_id: impl Into<String>,
        generation: Option<String>,
        stage: SessionStage,
        result: StageResult,
        code: Option<&'static str>,
        origin: TrafficOrigin,
    ) -> Result<Self, ResourceError> {
        let session_id = session_id.into();
        if session_id.is_empty() {
            return Err(ResourceError::new(CODE_OBSERVER_EVENT, "session id empty"));
        }
        // attempt 关联由调用方经 with_attempt 补齐；record 防御面校验
        // （逐尝试阶段缺 attempt 即拒绝——关联不做静默补默认）
        if result != StageResult::Succeeded && code.is_none() {
            return Err(ResourceError::new(
                CODE_OBSERVER_EVENT,
                "failed/rejected event requires a stable code",
            ));
        }
        if result == StageResult::Succeeded && code.is_some() {
            return Err(ResourceError::new(
                CODE_OBSERVER_EVENT,
                "succeeded event must not carry a failure code",
            ));
        }
        Ok(Self {
            session_id,
            attempt_id: None,
            generation,
            stage,
            result,
            code,
            origin,
        })
    }

    /// 设置尝试身份（逐尝试阶段用；链式）
    pub fn with_attempt(mut self, attempt_id: u32) -> Self {
        self.attempt_id = Some(attempt_id);
        self
    }

    /// 指标投影（丢弃 session/attempt/generation——只保有界词汇）
    pub fn metric_key(&self) -> MetricKey {
        MetricKey {
            stage: self.stage.as_str(),
            result: self.result.as_str(),
            origin: self.origin.as_str(),
        }
    }

    /// 事件合法性（record 防御面：逐尝试阶段缺 attempt 非法）
    fn valid(&self) -> bool {
        if self.session_id.is_empty() {
            return false;
        }
        if self.stage.needs_attempt() && self.attempt_id.is_none() {
            return false;
        }
        match self.result {
            StageResult::Succeeded => self.code.is_none(),
            _ => self.code.is_some(),
        }
    }
}

/// 观测统计（可见性：丢弃/拒绝不是静默的）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverStats {
    /// 已入账事件数（含尾环与聚合）
    pub events_recorded: u64,
    /// 因锁争用或环满被丢弃的事件数（try_lock 不等待——丢弃可见）
    pub events_dropped: u64,
    /// 非法事件拒绝数（防御面——不污染聚合）
    pub events_rejected: u64,
    /// 尾环驱逐数（溢出弹最旧——驱逐可见）
    pub ring_evicted: u64,
    /// 是否处于关闭态（容量 0——纯 no-op）
    pub disabled: bool,
}

/// 诊断视图：CLI/MCP 复用的**唯一**读面（聚合 + 尾环 + 统计同源）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverView {
    /// 指标聚合（有界枚举积键——无高基数身份）
    pub snapshot: BTreeMap<MetricKey, u64>,
    /// 有界诊断尾环（最新在后——受限逐流视图，携带 session/attempt）
    pub recent: Vec<StageEvent>,
    /// 统计
    pub stats: ObserverStats,
}

/// 会话观测器：低频阶段事件面（同步、非阻塞、有界）。
#[derive(Debug)]
pub struct SessionObserver {
    capacity: usize,
    aggregates: Mutex<BTreeMap<MetricKey, u64>>,
    ring: Mutex<VecDeque<StageEvent>>,
    recorded: AtomicU64,
    dropped: AtomicU64,
    rejected: AtomicU64,
    evicted: AtomicU64,
}

impl SessionObserver {
    /// 构造（capacity = 0 即关闭态——纯 no-op，转发路径零开销）
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            aggregates: Mutex::new(BTreeMap::new()),
            ring: Mutex::new(VecDeque::new()),
            recorded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
        }
    }

    /// 关闭态观测器（容量 0——统计关闭不能影响转发）
    pub fn disabled() -> Self {
        Self::new(0)
    }

    /// 记录阶段事件（**永不阻塞**：try_lock 争用即丢弃并计数——慢
    /// 消费者持有诊断锁时不等待；非法事件拒绝计数——不污染聚合；
    /// 关闭态纯 no-op。高频字节不走本面——见 [`crate::meter`]）。
    pub fn record(&self, event: StageEvent) {
        if self.capacity == 0 {
            return;
        }
        if !event.valid() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let key = event.metric_key();
        // try_lock：争用即丢弃（转发不等待诊断）——丢弃可见
        if let Ok(mut aggregates) = self.aggregates.try_lock() {
            *aggregates.entry(key).or_insert(0) += 1;
            drop(aggregates);
            if let Ok(mut ring) = self.ring.try_lock() {
                if ring.len() >= self.capacity {
                    ring.pop_front();
                    self.evicted.fetch_add(1, Ordering::Relaxed);
                }
                ring.push_back(event);
                self.recorded.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// 指标聚合快照（有界枚举积键——Prometheus 标签安全投影）
    pub fn snapshot(&self) -> BTreeMap<MetricKey, u64> {
        self.aggregates.lock().expect("观测聚合锁").clone()
    }

    /// 有界诊断尾环（受限逐流视图——携带 session/attempt/generation）
    pub fn recent(&self, limit: usize) -> Vec<StageEvent> {
        let ring = self.ring.lock().expect("观测尾环锁");
        let skip = ring.len().saturating_sub(limit);
        ring.iter().skip(skip).cloned().collect()
    }

    /// 统计
    pub fn stats(&self) -> ObserverStats {
        ObserverStats {
            events_recorded: self.recorded.load(Ordering::Relaxed),
            events_dropped: self.dropped.load(Ordering::Relaxed),
            events_rejected: self.rejected.load(Ordering::Relaxed),
            ring_evicted: self.evicted.load(Ordering::Relaxed),
            disabled: self.capacity == 0,
        }
    }

    /// 诊断视图（CLI/MCP 复用的唯一读面——聚合/尾环/统计同源）
    pub fn diagnostic_view(&self, recent_limit: usize) -> ObserverView {
        ObserverView {
            snapshot: self.snapshot(),
            recent: self.recent(recent_limit),
            stats: self.stats(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::meter::TrafficOrigin;

    /// 词汇机器口径；事件构造校验五路（空会话/失败缺码/成功带码/
    /// 逐尝试缺 attempt/合法）
    #[test]
    fn event_vocab_and_validation() {
        assert_eq!(SessionStage::Ingress.as_str(), "ingress");
        assert_eq!(SessionStage::Fallback.as_str(), "fallback");
        assert_eq!(StageResult::Rejected.as_str(), "rejected");
        assert!(SessionStage::Establish.needs_attempt());
        assert!(SessionStage::Handshake.needs_attempt());
        assert!(SessionStage::Fallback.needs_attempt());
        assert!(!SessionStage::Ingress.needs_attempt());
        assert!(!SessionStage::Close.needs_attempt());

        // 空会话身份
        let err = StageEvent::new(
            "",
            None,
            SessionStage::Ingress,
            StageResult::Succeeded,
            None,
            TrafficOrigin::User,
        )
        .unwrap_err();
        assert_eq!(err.code, CODE_OBSERVER_EVENT);
        // 失败缺稳定原因码
        let err = StageEvent::new(
            "s",
            None,
            SessionStage::Ingress,
            StageResult::Failed,
            None,
            TrafficOrigin::User,
        )
        .unwrap_err();
        assert_eq!(err.code, CODE_OBSERVER_EVENT);
        // 成功带原因码
        let err = StageEvent::new(
            "s",
            None,
            SessionStage::Ingress,
            StageResult::Succeeded,
            Some("x.y"),
            TrafficOrigin::User,
        )
        .unwrap_err();
        assert_eq!(err.code, CODE_OBSERVER_EVENT);
        // 合法事件 + 指标投影（丢弃关联身份）
        let ev = StageEvent::new(
            "sess-1",
            Some("gen-9".into()),
            SessionStage::Establish,
            StageResult::Failed,
            Some("egress.dial.refused"),
            TrafficOrigin::User,
        )
        .expect("合法")
        .with_attempt(0);
        let key = ev.metric_key();
        assert_eq!(
            (key.stage, key.result, key.origin),
            ("establish", "failed", "user")
        );
    }

    /// 聚合有界：键集 ≤ 枚举积；计数按键归位；快照无高基数身份
    #[test]
    fn aggregates_are_bounded_and_identity_free() {
        let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
        let session_id = "sess-with-a-very-identifiable-name-xyz";
        let ev = StageEvent::new(
            session_id,
            Some("gen-1".into()),
            SessionStage::Handshake,
            StageResult::Succeeded,
            None,
            TrafficOrigin::User,
        )
        .expect("合法")
        .with_attempt(2);
        for _ in 0..5 {
            obs.record(ev.clone());
        }
        let snapshot = obs.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(
            snapshot.values().next().expect("键存在"),
            &5,
            "同键事件归位累计"
        );
        assert!(snapshot.len() <= 45, "键集有界（5×3×3）");
        // 指标投影无高基数身份
        let rendered = format!("{snapshot:?}");
        assert!(
            !rendered.contains("sess-with-a-very-identifiable-name-xyz")
                && !rendered.contains("gen-1"),
            "指标快照不含 session/generation 身份"
        );
        // 逐尝试阶段缺 attempt → record 防御拒绝
        let bad = StageEvent::new(
            "s2",
            None,
            SessionStage::Establish,
            StageResult::Failed,
            Some("egress.dial.timeout"),
            TrafficOrigin::User,
        )
        .expect("构造合法（record 时校验 attempt）");
        assert!(bad.attempt_id.is_none());
        obs.record(bad);
        assert_eq!(obs.stats().events_rejected, 1, "非法事件拒绝可见");
        assert_eq!(obs.snapshot().len(), 1, "聚合未被污染");
    }

    /// 高频字节走计数器：泵循环逐块过账 meter，观测器只有阶段边界
    /// 事件——不为每次读写分配事件
    #[test]
    fn high_frequency_bytes_go_to_meter_not_events() {
        let meter =
            crate::meter::SessionMeter::new("sess-pump", TrafficOrigin::User).expect("合法");
        let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
        obs.record(
            StageEvent::new(
                "sess-pump",
                None,
                SessionStage::Ingress,
                StageResult::Succeeded,
                None,
                TrafficOrigin::User,
            )
            .expect("合法"),
        );
        // 泵循环：10_000 块业务字节——只有 meter 计数，零观测事件
        for _ in 0..10_000 {
            meter.record_business(crate::meter::TrafficDirection::ClientToTarget, 64);
        }
        obs.record(
            StageEvent::new(
                "sess-pump",
                None,
                SessionStage::Close,
                StageResult::Succeeded,
                None,
                TrafficOrigin::User,
            )
            .expect("合法"),
        );
        assert_eq!(obs.stats().events_recorded, 2, "只有阶段边界事件");
        assert_eq!(meter.totals().business_bytes(), 640_000, "字节在计数器");
    }

    /// 慢消费者/关闭观测不影响转发：诊断锁被持有期间 record 立即
    /// 返回（丢弃可见，不等待不死锁）；关闭态纯 no-op
    #[test]
    fn slow_consumer_and_disabled_never_block() {
        let obs = SessionObserver::new(16);
        // 模拟慢消费者：同时持有聚合与尾环锁
        let _held_agg = obs.aggregates.lock().expect("锁");
        let _held_ring = obs.ring.lock().expect("锁");
        let ev = StageEvent::new(
            "s",
            None,
            SessionStage::Close,
            StageResult::Succeeded,
            None,
            TrafficOrigin::User,
        )
        .expect("合法");
        for _ in 0..50 {
            obs.record(ev.clone()); // try_lock 争用 → 立即丢弃计数
        }
        assert_eq!(obs.stats().events_dropped, 50, "争用丢弃可见");
        assert_eq!(obs.stats().events_recorded, 0);
        drop(_held_agg);
        drop(_held_ring);
        obs.record(ev.clone());
        assert_eq!(obs.stats().events_recorded, 1, "锁释放后恢复入账");

        // 关闭态：纯 no-op
        let off = SessionObserver::disabled();
        off.record(ev);
        assert!(off.stats().disabled);
        assert_eq!(off.stats().events_recorded, 0);
        assert!(off.snapshot().is_empty());
        assert!(off.diagnostic_view(10).recent.is_empty());
    }

    /// 尾环有界：溢出弹最旧、驱逐可见；recent 只取尾部 limit 条
    #[test]
    fn ring_is_bounded_and_eviction_visible() {
        let obs = SessionObserver::new(4);
        for i in 0..6 {
            obs.record(
                StageEvent::new(
                    format!("s-{i}"),
                    None,
                    SessionStage::Ingress,
                    StageResult::Succeeded,
                    None,
                    TrafficOrigin::User,
                )
                .expect("合法"),
            );
        }
        let stats = obs.stats();
        assert_eq!(stats.events_recorded, 6);
        assert_eq!(stats.ring_evicted, 2, "驱逐可见");
        let tail = obs.recent(10);
        assert_eq!(tail.len(), 4, "尾环容量有界");
        assert_eq!(
            tail.iter()
                .map(|e| e.session_id.as_str())
                .collect::<Vec<_>>(),
            vec!["s-2", "s-3", "s-4", "s-5"],
            "保留最新、弹最旧"
        );
        assert_eq!(obs.recent(2).len(), 2, "limit 截断");
    }

    /// 关联统一 + 诊断视图同源：session/attempt/generation 经尾环保留；
    /// 视图的聚合/尾环/统计来自同一观测器（CLI/MCP 复用同一读面）
    #[test]
    fn correlation_survives_and_view_is_single_surface() {
        let obs = SessionObserver::new(OBSERVER_RING_DEFAULT);
        // 回退对账链：establish A 失败 → fallback → establish B 成功 → close
        let sid = "sess-obs-9";
        obs.record(
            StageEvent::new(
                sid,
                Some("gen-3".into()),
                SessionStage::Establish,
                StageResult::Failed,
                Some("egress.dial.refused"),
                TrafficOrigin::User,
            )
            .expect("合法")
            .with_attempt(0),
        );
        obs.record(
            StageEvent::new(
                sid,
                Some("gen-3".into()),
                SessionStage::Fallback,
                StageResult::Succeeded,
                None,
                TrafficOrigin::User,
            )
            .expect("合法")
            .with_attempt(1),
        );
        obs.record(
            StageEvent::new(
                sid,
                Some("gen-3".into()),
                SessionStage::Handshake,
                StageResult::Succeeded,
                None,
                TrafficOrigin::User,
            )
            .expect("合法")
            .with_attempt(1),
        );
        obs.record(
            StageEvent::new(
                sid,
                Some("gen-3".into()),
                SessionStage::Close,
                StageResult::Succeeded,
                None,
                TrafficOrigin::User,
            )
            .expect("合法"),
        );
        let view = obs.diagnostic_view(10);
        assert_eq!(view.recent.len(), 4);
        // 关联统一：逐尝试事件携带 session+attempt+generation
        let est = &view.recent[0];
        assert_eq!(est.session_id, sid);
        assert_eq!(est.attempt_id, Some(0));
        assert_eq!(est.generation.as_deref(), Some("gen-3"));
        let hs = &view.recent[2];
        assert_eq!(hs.attempt_id, Some(1), "B 尝试的握手关联 attempt 1");
        // 聚合同源：establish failed=1、handshake succeeded=1、fallback/close
        assert_eq!(view.snapshot.len(), 4);
        assert_eq!(view.stats.events_recorded, 4);
        // 尾环 limit 截断与聚合独立（视图仍同源）
        let short = obs.diagnostic_view(2);
        assert_eq!(short.recent.len(), 2);
        assert_eq!(short.snapshot, view.snapshot, "聚合不随 limit 变化");
    }
}
