//! TrafficMeter 权威业务计数（RIL-101 / io-and-accounting.md §5）。
//!
//! 业务字节在**语义等价的业务通道边界**设唯一权威计数器：会话总量
//! 按**客户端→目标 / 目标→客户端**定义（[`TrafficDirection`]）——
//! API 里不存在 socket 读写方向，计数不随读写翻转。入口/出口是同一
//! 业务流量的**归属视图**（相加不是总使用量）；底层加密/握手开销
//! 单独记录（不并入业务）；A 建连失败后回退 B：A 记 attempt 失败与
//! 真实底层开销，业务归属 B，**会话总量只累计一次**；probe/prewarm
//! 在构造期分类（[`TrafficOrigin`]）与用户业务分别汇总；共享多路
//! 复用资源的公共开销计入共享面并**明确标记不可精确归因**（不伪造
//! 每流精度）。计数语义显式：部分写只累加实际字节，重试是 attempt
//! 层的事（不重复统计业务总量），零长度 UDP 仍计一条报文
//! （[`SessionMeter::record_datagram`]），**发送成功不证明对端已
//! 收到**（本面没有「远端已收」字段）。

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::resources::ResourceError;

/// 有界尝试追踪上限（回退循环受 RoutePlan 约束——超限只计聚合，
/// 不无限占内存）
pub const MAX_TRACKED_ATTEMPTS: usize = 64;

/// 稳定原因码：会话身份非法（空）
pub const CODE_METER_SESSION: &str = "meter.session.invalid";
/// 稳定原因码：承载归属已定（A 失败 B 承载——二次归属即拒）
pub const CODE_METER_CARRIER: &str = "meter.carrier.settled";
/// 稳定原因码：归属到未知尝试（必须先有该 attempt 的真实观测）
pub const CODE_METER_ATTEMPT: &str = "meter.attempt.unknown";

/// 业务方向（语义口径）：统一按客户端→目标 / 目标→客户端定义。
/// **没有 socket 读写方向**——读还是写不进入类型面，计数不随
/// 读写方向翻转。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficDirection {
    /// 客户端 → 目标（上行）
    ClientToTarget,
    /// 目标 → 客户端（下行）
    TargetToClient,
}

impl TrafficDirection {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            TrafficDirection::ClientToTarget => "client_to_target",
            TrafficDirection::TargetToClient => "target_to_client",
        }
    }
}

/// 流量来源分类：probe/prewarm 与用户业务分别汇总，互不入账。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficOrigin {
    /// 用户业务（缺省）
    User,
    /// 系统主动探测
    Probe,
    /// 连接预热
    Prewarm,
}

impl TrafficOrigin {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            TrafficOrigin::User => "user",
            TrafficOrigin::Probe => "probe",
            TrafficOrigin::Prewarm => "prewarm",
        }
    }
}

/// 归属视图：入口/出口是**同一业务流量**的两个归属视角——相加不是
/// 总使用量（总使用量只看会话权威量）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributionView {
    /// 入口归属（业务经入口进来）
    Inbound,
    /// 出口归属（业务经出口出去）
    Outbound,
}

impl AttributionView {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            AttributionView::Inbound => "inbound",
            AttributionView::Outbound => "outbound",
        }
    }
}

/// 会话权威总量快照（不可变视图）。业务量只在此处权威；底层开销、
/// 共享开销与丢弃是**分立字段**，任何汇总都不得把它们并入业务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTotals {
    /// 会话身份
    pub session_id: String,
    /// 流量来源分类
    pub origin: TrafficOrigin,
    /// 客户端→目标业务字节
    pub client_to_target_bytes: u64,
    /// 客户端→目标报文数（零长报文也计一条）
    pub client_to_target_datagrams: u64,
    /// 目标→客户端业务字节
    pub target_to_client_bytes: u64,
    /// 目标→客户端报文数（零长报文也计一条）
    pub target_to_client_datagrams: u64,
    /// 底层开销字节（拨号/握手/加密封装——单独记录，不并入业务；
    /// 含失败尝试的真实开销）
    pub underlay_bytes: u64,
    /// 共享资源公共开销（多路复用等——**不可精确归因**，显式分立，
    /// 不伪造每流精度）
    pub shared_overhead_bytes: u64,
    /// 显式丢弃的报文数（丢弃与写入语义分立，不冒充业务量）
    pub dropped_datagrams: u64,
    /// 实际承载业务的尝试（A 失败 B 承载——只记 B）
    pub carrier_attempt: Option<u32>,
    /// 失败的尝试列表（真实面照实记录）
    pub failed_attempts: Vec<u32>,
    /// 逐尝试底层开销明细（有界 ≤ [`MAX_TRACKED_ATTEMPTS`]——
    /// 失败 A 的真实开销在明细里可对账）
    pub attempt_underlay: Vec<(u32, u64)>,
    /// 超出追踪上限的尝试数（聚合仍入 [`Self::underlay_bytes`]，
    /// 明细不再展开——诚实可见）
    pub attempt_overflow: u64,
}

impl SessionTotals {
    /// 业务总量（两方向字节之和）——**唯一的会话权威业务量**；
    /// 入口/出口归属视图相加不得当总使用量。
    pub fn business_bytes(&self) -> u64 {
        self.client_to_target_bytes + self.target_to_client_bytes
    }

    /// 业务报文总量（零长报文也计）
    pub fn business_datagrams(&self) -> u64 {
        self.client_to_target_datagrams + self.target_to_client_datagrams
    }

    /// 归属视图：入口/出口看到的是**同一份**权威业务量（视图 = 归属
    /// 投影；两者相加 = 双倍计数——没有「总量 = in + out」这回事）
    pub fn attribution(&self, view: AttributionView) -> u64 {
        match view {
            AttributionView::Inbound | AttributionView::Outbound => self.business_bytes(),
        }
    }
}

/// 尝试维度账（有界：超 [`MAX_TRACKED_ATTEMPTS`] 只计聚合，明细
/// 不再展开——溢出计数诚实可见）。
#[derive(Debug, Default)]
struct AttemptLedger {
    /// 已观测的尝试（登记即可归属；明细有界）
    known: Vec<u32>,
    /// 逐尝试底层开销明细（只含 `known` 内的尝试）
    underlay: BTreeMap<u32, u64>,
    failed: Vec<u32>,
    /// 超界尝试数（其开销只进聚合原子量，不进明细）
    overflow: u64,
    carrier: Option<u32>,
}

impl AttemptLedger {
    /// 登记尝试（有界：超出上限只计溢出，明细不膨胀）
    fn note_attempt(&mut self, attempt_id: u32) {
        if self.known.contains(&attempt_id) {
            return;
        }
        if self.known.len() >= MAX_TRACKED_ATTEMPTS {
            self.overflow += 1;
            return;
        }
        self.known.push(attempt_id);
    }
}

/// 会话计量器：业务通道边界的**唯一权威计数器**（有界维度——只带
/// session/attempt/方向/来源四个固定维度，无域名/路径等高基数信息）。
/// 线程安全（会话跨任务搬运）；快照口径见 [`Self::totals`]。
#[derive(Debug)]
pub struct SessionMeter {
    session_id: String,
    origin: TrafficOrigin,
    c2t_bytes: AtomicU64,
    c2t_datagrams: AtomicU64,
    t2c_bytes: AtomicU64,
    t2c_datagrams: AtomicU64,
    underlay_bytes: AtomicU64,
    shared_overhead_bytes: AtomicU64,
    dropped_datagrams: AtomicU64,
    attempts: Mutex<AttemptLedger>,
}

impl SessionMeter {
    /// 构造（会话身份非空——空身份返回 `None` 即
    /// [`CODE_METER_SESSION`] 面；来源在构造期分类、此后不可变——
    /// probe/prewarm 不会中途混进用户账）
    pub fn new(session_id: impl Into<String>, origin: TrafficOrigin) -> Option<Self> {
        let session_id = session_id.into();
        if session_id.is_empty() {
            return None;
        }
        Some(Self {
            session_id,
            origin,
            c2t_bytes: AtomicU64::new(0),
            c2t_datagrams: AtomicU64::new(0),
            t2c_bytes: AtomicU64::new(0),
            t2c_datagrams: AtomicU64::new(0),
            underlay_bytes: AtomicU64::new(0),
            shared_overhead_bytes: AtomicU64::new(0),
            dropped_datagrams: AtomicU64::new(0),
            attempts: Mutex::new(AttemptLedger::default()),
        })
    }

    /// 会话身份
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 流量来源（构造期分类，不可变）
    pub fn origin(&self) -> TrafficOrigin {
        self.origin
    }

    /// 记录业务字节（业务通道边界——**唯一权威入口**，流语义）。
    ///
    /// - `bytes` 是**实际过账的字节数**：部分写只累加实际值（写 3 记 3，
    ///   调用方按真实面给数），不按缓冲区名义长度记；
    /// - 重试是 attempt 层的事——业务量只在本边界过账一次，不因
    ///   回退重试重复统计；
    /// - 语义 = 本地成功写入/读取；**发送成功不证明对端已收到**——
    ///   本面没有「远端已收」字段，任何实现不得把 Written 记成 Acked。
    pub fn record_business(&self, direction: TrafficDirection, bytes: u64) {
        match direction {
            TrafficDirection::ClientToTarget => {
                self.c2t_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            TrafficDirection::TargetToClient => {
                self.t2c_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    /// 记录一条数据报（报文语义）：零长度报文**仍计一条**——
    /// 字节为 0 不吞报文计数；字节照实累加（0 就是 0）。
    pub fn record_datagram(&self, direction: TrafficDirection, bytes: u64) {
        match direction {
            TrafficDirection::ClientToTarget => {
                self.c2t_bytes.fetch_add(bytes, Ordering::Relaxed);
                self.c2t_datagrams.fetch_add(1, Ordering::Relaxed);
            }
            TrafficDirection::TargetToClient => {
                self.t2c_bytes.fetch_add(bytes, Ordering::Relaxed);
                self.t2c_datagrams.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 记录显式丢弃的报文（丢弃与写入分立——不冒充任何方向的业务量）
    pub fn record_drop(&self, datagrams: u64) {
        self.dropped_datagrams
            .fetch_add(datagrams.max(1), Ordering::Relaxed);
    }

    /// 记录一次尝试的真实底层开销（拨号/握手/加密封装字节——
    /// 单独记录，永不并入业务量；失败尝试也照实记录其真实开销）
    pub fn record_underlay(&self, attempt_id: u32, bytes: u64) {
        self.underlay_bytes.fetch_add(bytes, Ordering::Relaxed);
        let mut ledger = self.attempts.lock().expect("meter 账本锁");
        ledger.note_attempt(attempt_id);
        if ledger.known.contains(&attempt_id) {
            *ledger.underlay.entry(attempt_id).or_insert(0) += bytes;
        }
        // 溢出尝试：开销已在聚合原子量里，明细不再展开（诚实口径）
    }

    /// 标记尝试失败（A 失败——真实底层开销已由 [`Self::record_underlay`]
    /// 照实记录，业务量不受影响）
    pub fn mark_attempt_failed(&self, attempt_id: u32) {
        let mut ledger = self.attempts.lock().expect("meter 账本锁");
        ledger.note_attempt(attempt_id);
        if ledger.known.contains(&attempt_id) && !ledger.failed.contains(&attempt_id) {
            ledger.failed.push(attempt_id);
        }
    }

    /// 归属实际承载业务的尝试（A 失败后回退 B——业务归属 B，只记
    /// 一次）。二次归属拒绝（[`CODE_METER_CARRIER`]）；归属到无任何
    /// 真实观测的尝试拒绝（[`CODE_METER_ATTEMPT`]——不得虚构承载）。
    pub fn attribute_carrier(&self, attempt_id: u32) -> Result<(), ResourceError> {
        let mut ledger = self.attempts.lock().expect("meter 账本锁");
        if let Some(held) = ledger.carrier {
            return Err(ResourceError::new(
                CODE_METER_CARRIER,
                format!("carrier already attributed to attempt {held}"),
            ));
        }
        if !ledger.known.contains(&attempt_id) {
            return Err(ResourceError::new(
                CODE_METER_ATTEMPT,
                "carrier must be a previously observed attempt",
            ));
        }
        ledger.carrier = Some(attempt_id);
        Ok(())
    }

    /// 记录共享资源公共开销（多路复用连接的公共封装等——**不可精确
    /// 归因**：计入共享面并显式标记，不摊分、不伪造每流精度）
    pub fn record_shared_overhead(&self, bytes: u64) {
        self.shared_overhead_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// 权威总量快照（各原子字段独立读取——快照是近似一致视图，
    /// 统计面不阻塞转发）
    pub fn totals(&self) -> SessionTotals {
        let ledger = self.attempts.lock().expect("meter 账本锁");
        SessionTotals {
            session_id: self.session_id.clone(),
            origin: self.origin,
            client_to_target_bytes: self.c2t_bytes.load(Ordering::Relaxed),
            client_to_target_datagrams: self.c2t_datagrams.load(Ordering::Relaxed),
            target_to_client_bytes: self.t2c_bytes.load(Ordering::Relaxed),
            target_to_client_datagrams: self.t2c_datagrams.load(Ordering::Relaxed),
            underlay_bytes: self.underlay_bytes.load(Ordering::Relaxed),
            shared_overhead_bytes: self.shared_overhead_bytes.load(Ordering::Relaxed),
            dropped_datagrams: self.dropped_datagrams.load(Ordering::Relaxed),
            carrier_attempt: ledger.carrier,
            failed_attempts: ledger.failed.clone(),
            attempt_underlay: ledger.underlay.iter().map(|(k, v)| (*k, *v)).collect(),
            attempt_overflow: ledger.overflow,
        }
    }
}

/// 来源账本：按 [`TrafficOrigin`] 分别汇总各会话快照——probe/prewarm
/// 与用户业务**分桶展示**，任何桶都不互相吸收。
#[derive(Debug, Default)]
pub struct OriginLedger {
    buckets: Mutex<BTreeMap<&'static str, (u64, u64, u64)>>,
}

impl OriginLedger {
    /// 汇入一份会话快照（业务字节 / 底层开销 / 共享开销分列入桶）
    pub fn absorb(&self, totals: &SessionTotals) {
        let mut buckets = self.buckets.lock().expect("来源账本锁");
        let entry = buckets.entry(totals.origin.as_str()).or_insert((0, 0, 0));
        entry.0 += totals.business_bytes();
        entry.1 += totals.underlay_bytes;
        entry.2 += totals.shared_overhead_bytes;
    }

    /// 某来源的业务总量（probe 桶的字节永远不会出现在 user 桶）
    pub fn business_of(&self, origin: TrafficOrigin) -> u64 {
        self.buckets
            .lock()
            .expect("来源账本锁")
            .get(origin.as_str())
            .map(|b| b.0)
            .unwrap_or(0)
    }

    /// 某来源的底层开销总量
    pub fn underlay_of(&self, origin: TrafficOrigin) -> u64 {
        self.buckets
            .lock()
            .expect("来源账本锁")
            .get(origin.as_str())
            .map(|b| b.1)
            .unwrap_or(0)
    }

    /// 某来源的共享开销总量
    pub fn shared_of(&self, origin: TrafficOrigin) -> u64 {
        self.buckets
            .lock()
            .expect("来源账本锁")
            .get(origin.as_str())
            .map(|b| b.2)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 会话身份非空；方向/来源/归属视图机器口径恒定
    #[test]
    fn meter_basics_and_vocab() {
        assert!(
            SessionMeter::new("", TrafficOrigin::User).is_none(),
            "空身份拒绝"
        );
        let m = SessionMeter::new("s-1", TrafficOrigin::User).expect("合法");
        assert_eq!(m.session_id(), "s-1");
        assert_eq!(m.origin(), TrafficOrigin::User);
        assert_eq!(
            TrafficDirection::ClientToTarget.as_str(),
            "client_to_target"
        );
        assert_eq!(TrafficOrigin::Probe.as_str(), "probe");
        assert_eq!(AttributionView::Inbound.as_str(), "inbound");
    }

    /// 部分写只累加实际字节；零长 UDP 计报文；丢弃与写入分立
    #[test]
    fn partial_writes_zero_datagrams_and_drops() {
        let m = SessionMeter::new("s-2", TrafficOrigin::User).expect("合法");
        // 部分写：写 3 记 3（调用方按实际过账，不按名义长度）
        m.record_business(TrafficDirection::ClientToTarget, 3);
        m.record_business(TrafficDirection::ClientToTarget, 5);
        let t = m.totals();
        assert_eq!(t.client_to_target_bytes, 8);
        assert_eq!(t.client_to_target_datagrams, 0, "流语义不产生报文计数");
        // 零长 UDP 仍是一条报文
        m.record_datagram(TrafficDirection::TargetToClient, 0);
        let t = m.totals();
        assert_eq!(t.target_to_client_bytes, 0);
        assert_eq!(t.target_to_client_datagrams, 1, "零长报文计数不吞");
        // 报文字节照实累加
        m.record_datagram(TrafficDirection::TargetToClient, 140);
        let t = m.totals();
        assert_eq!(t.target_to_client_bytes, 140);
        assert_eq!(t.target_to_client_datagrams, 2);
        // 丢弃分立：不冒充业务量（零数丢弃也至少计一条——保守面）
        m.record_drop(2);
        m.record_drop(0);
        let t = m.totals();
        assert_eq!(t.dropped_datagrams, 3, "2 + 零数至少计 1");
        assert_eq!(t.business_bytes(), 148, "丢弃不进业务量");
    }

    /// A 失败 B 承载：attempt 失败与真实底层开销照实记录；业务量只计
    /// 一次（不因重试翻倍）；二次归属/未知归属拒绝；逐尝试明细可对账
    #[test]
    fn failover_counts_business_once() {
        let m = SessionMeter::new("s-3", TrafficOrigin::User).expect("合法");
        // A 尝试：真实底层开销 + 失败
        m.record_underlay(0, 120);
        m.mark_attempt_failed(0);
        // B 尝试：真实底层开销 + 承载
        m.record_underlay(1, 90);
        m.attribute_carrier(1).expect("归属 B");
        // 业务字节过账一次（业务通道边界——不是按 attempt 重复计）
        m.record_business(TrafficDirection::ClientToTarget, 512);
        let t = m.totals();
        assert_eq!(t.business_bytes(), 512, "业务总量只累计一次");
        assert_eq!(t.carrier_attempt, Some(1), "业务归属 B");
        assert_eq!(t.failed_attempts, vec![0], "A 的失败照实记录");
        assert_eq!(t.underlay_bytes, 210, "A+B 真实底层开销分立记录");
        assert_eq!(t.client_to_target_bytes, 512, "业务与底层分立——不混账");
        assert_eq!(
            t.attempt_underlay,
            vec![(0, 120), (1, 90)],
            "逐尝试明细可对账（A 的失败开销可追溯）"
        );
        assert_eq!(t.attempt_overflow, 0);

        // 二次归属拒绝
        let err = m.attribute_carrier(0).unwrap_err();
        assert_eq!(err.code, CODE_METER_CARRIER);
        // 未知尝试归属拒绝（不得虚构承载）
        let m2 = SessionMeter::new("s-4", TrafficOrigin::User).expect("合法");
        let err = m2.attribute_carrier(9).unwrap_err();
        assert_eq!(err.code, CODE_METER_ATTEMPT);
    }

    /// 归属视图：入口/出口是同一业务量的投影——相加 = 双倍，不是总量
    #[test]
    fn attribution_views_are_not_additive() {
        let m = SessionMeter::new("s-5", TrafficOrigin::User).expect("合法");
        m.record_business(TrafficDirection::ClientToTarget, 100);
        m.record_business(TrafficDirection::TargetToClient, 40);
        let t = m.totals();
        let inbound = t.attribution(AttributionView::Inbound);
        let outbound = t.attribution(AttributionView::Outbound);
        assert_eq!(inbound, 140, "入口视图 = 同一权威业务量");
        assert_eq!(outbound, 140, "出口视图 = 同一权威业务量");
        assert_ne!(
            inbound + outbound,
            t.business_bytes(),
            "两端相加不是总使用量"
        );
        assert_eq!(t.business_bytes(), 140);
    }

    /// 共享开销分立显式标记：不摊分进业务、不伪造每流精度
    #[test]
    fn shared_overhead_stays_separate() {
        let m = SessionMeter::new("s-6", TrafficOrigin::User).expect("合法");
        m.record_business(TrafficDirection::ClientToTarget, 200);
        m.record_shared_overhead(37);
        let t = m.totals();
        assert_eq!(t.business_bytes(), 200, "共享开销不并入业务");
        assert_eq!(t.shared_overhead_bytes, 37, "共享开销显式分立");
    }

    /// 尝试追踪有界：超限只计聚合不崩；溢出数诚实可见；聚合总量完整
    #[test]
    fn attempt_ledger_is_bounded() {
        let m = SessionMeter::new("s-7", TrafficOrigin::User).expect("合法");
        let extra = 10u32;
        for i in 0..(MAX_TRACKED_ATTEMPTS as u32 + extra) {
            m.record_underlay(i, 1);
        }
        let t = m.totals();
        assert_eq!(
            t.underlay_bytes,
            MAX_TRACKED_ATTEMPTS as u64 + u64::from(extra),
            "聚合总量完整（含溢出部分）"
        );
        assert_eq!(t.attempt_underlay.len(), MAX_TRACKED_ATTEMPTS, "明细有界");
        assert_eq!(t.attempt_overflow, u64::from(extra), "溢出可见");
        // 溢出尝试不可归属（无明细观测面）
        let overflow_id = MAX_TRACKED_ATTEMPTS as u32 + 1;
        assert_eq!(
            m.attribute_carrier(overflow_id).unwrap_err().code,
            CODE_METER_ATTEMPT,
            "溢出尝试无明细——归属拒绝"
        );
    }

    /// 来源分桶：probe/prewarm 与用户业务分别汇总、互不吸收
    #[test]
    fn origins_are_aggregated_apart() {
        let ledger = OriginLedger::default();
        let user = SessionMeter::new("u-1", TrafficOrigin::User).expect("合法");
        user.record_business(TrafficDirection::ClientToTarget, 1000);
        let probe = SessionMeter::new("p-1", TrafficOrigin::Probe).expect("合法");
        probe.record_business(TrafficDirection::ClientToTarget, 64);
        probe.record_underlay(0, 8);
        let warm = SessionMeter::new("w-1", TrafficOrigin::Prewarm).expect("合法");
        warm.record_shared_overhead(12);
        ledger.absorb(&user.totals());
        ledger.absorb(&probe.totals());
        ledger.absorb(&warm.totals());
        assert_eq!(ledger.business_of(TrafficOrigin::User), 1000);
        assert_eq!(ledger.business_of(TrafficOrigin::Probe), 64, "probe 分桶");
        assert_eq!(
            ledger.business_of(TrafficOrigin::Prewarm),
            0,
            "prewarm 无业务字节"
        );
        assert_eq!(ledger.underlay_of(TrafficOrigin::Probe), 8);
        assert_eq!(ledger.shared_of(TrafficOrigin::Prewarm), 12);
        assert_eq!(ledger.underlay_of(TrafficOrigin::User), 0);
    }
}
