//! 有界会话与队列预算（RIL-024）：压力下每一类资源都有显式上限，
//! 超限拒绝**可解释**（携带资源种类、当前用量、上限、稳定码），内存
//! 有界（预算由 RAII 许可守恒——许可释放即归还，无泄漏增长路径），
//! **控制请求不阻塞转发**（控制面预算池独立，计数只走原子量，不与
//! 转发面的队列记账锁竞争）。
//!
//! 资源面：
//! - 会话数（总量 + 场景范围各自上限——`admit_session(scope)`）；
//! - 并发拨号（`begin_dial`/许可）；
//! - UDP NAT 映射数（`admit_udp_mapping`）；
//! - 发送队列字节（单会话上限 + 全局总量——内存不无界增长的结构半边）；
//! - 控制面并发（独立池：数据面全满时控制请求仍被接纳）。
//!
//! 边界：本模块只做记账与准入门（背压决策点），不做排队/丢弃的 IO
//! 策略——调用方按 [`BudgetRejection`] 的解释决定丢弃或延迟；runtime
//! 把许可见到 TUN/UDP 会话建立点（RIL-022 执行器入口）与发送循环。

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// 稳定原因码：会话总量上限
pub const CODE_BUDGET_SESSIONS: &str = "budget.sessions.exhausted";
/// 稳定原因码：场景范围会话数上限
pub const CODE_BUDGET_SESSION_SCOPE: &str = "budget.session_scope.exhausted";
/// 稳定原因码：并发拨号上限
pub const CODE_BUDGET_DIALING: &str = "budget.dialing.exhausted";
/// 稳定原因码：UDP 映射数上限
pub const CODE_BUDGET_UDP_MAPPING: &str = "budget.udp_mapping.exhausted";
/// 稳定原因码：单会话发送队列字节上限
pub const CODE_BUDGET_QUEUE_SESSION: &str = "budget.queue_session.exhausted";
/// 稳定原因码：全局队列字节总量上限
pub const CODE_BUDGET_QUEUE_TOTAL: &str = "budget.queue_total.exhausted";
/// 稳定原因码：控制面并发上限
pub const CODE_BUDGET_CONTROL: &str = "budget.control.exhausted";

/// 预算上限（None = 不限；Some(0) = 全拒——合法的闸门语义）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BudgetLimits {
    /// 会话总量上限
    pub max_sessions_total: Option<u64>,
    /// 单场景范围会话数上限（scope = 场景名，RIL-021）
    pub max_sessions_per_scope: Option<u64>,
    /// 并发拨号上限
    pub max_dialing: Option<u64>,
    /// UDP NAT 映射数上限
    pub max_udp_mappings: Option<u64>,
    /// 单会话发送队列字节上限
    pub max_queue_bytes_per_session: Option<u64>,
    /// 全局发送队列字节总量上限（内存不无界增长）
    pub max_queue_bytes_total: Option<u64>,
    /// 控制面并发上限（独立池）
    pub max_control: Option<u64>,
}

impl BudgetLimits {
    /// 只限会话总量（其余不限）
    pub fn with_max_sessions_total(limit: u64) -> Self {
        Self {
            max_sessions_total: Some(limit),
            ..Default::default()
        }
    }

    /// 只限单会话队列字节
    pub fn with_max_queue_bytes_per_session(limit: u64) -> Self {
        Self {
            max_queue_bytes_per_session: Some(limit),
            ..Default::default()
        }
    }
}

/// 被拒的资源种类（拒绝可解释的「哪一半」）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetKind {
    /// 会话总量
    SessionsTotal,
    /// 场景范围会话数（带范围名）
    SessionScope(String),
    /// 并发拨号
    Dialing,
    /// UDP 映射数
    UdpMapping,
    /// 单会话队列字节（带会话身份）
    QueueSession(String),
    /// 全局队列字节总量
    QueueTotal,
    /// 控制面并发
    Control,
}

impl BudgetKind {
    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        match self {
            BudgetKind::SessionsTotal => CODE_BUDGET_SESSIONS,
            BudgetKind::SessionScope(_) => CODE_BUDGET_SESSION_SCOPE,
            BudgetKind::Dialing => CODE_BUDGET_DIALING,
            BudgetKind::UdpMapping => CODE_BUDGET_UDP_MAPPING,
            BudgetKind::QueueSession(_) => CODE_BUDGET_QUEUE_SESSION,
            BudgetKind::QueueTotal => CODE_BUDGET_QUEUE_TOTAL,
            BudgetKind::Control => CODE_BUDGET_CONTROL,
        }
    }
}

impl fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BudgetKind::SessionsTotal => f.write_str("sessions_total"),
            BudgetKind::SessionScope(scope) => write!(f, "session_scope:{scope}"),
            BudgetKind::Dialing => f.write_str("dialing"),
            BudgetKind::UdpMapping => f.write_str("udp_mapping"),
            BudgetKind::QueueSession(id) => write!(f, "queue_session:{id}"),
            BudgetKind::QueueTotal => f.write_str("queue_total"),
            BudgetKind::Control => f.write_str("control"),
        }
    }
}

/// 预算拒绝（压力下拒绝可解释：种类 + 当前用量 + 上限）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRejection {
    /// 被拒的资源种类
    pub kind: BudgetKind,
    /// 拒绝时刻用量
    pub used: u64,
    /// 上限
    pub limit: u64,
}

impl BudgetRejection {
    /// 稳定原因码（取种类）
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for BudgetRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "budget exhausted: {} used={} limit={} ({})",
            self.kind,
            self.used,
            self.limit,
            self.code()
        )
    }
}

impl std::error::Error for BudgetRejection {}

/// 用量快照（可观测面）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BudgetUsage {
    /// 当前会话数
    pub sessions_total: u64,
    /// 当前并发拨号
    pub dialing: u64,
    /// 当前 UDP 映射数
    pub udp_mappings: u64,
    /// 当前队列字节总量
    pub queue_bytes_total: u64,
    /// 当前控制面并发
    pub control: u64,
}

/// 计数状态（许可守恒：准入门 CAS，Drop 归还）
#[derive(Debug, Default)]
struct BudgetState {
    sessions_total: AtomicU64,
    dialing: AtomicU64,
    udp_mappings: AtomicU64,
    control: AtomicU64,
    queue_bytes_total: AtomicU64,
    sessions_by_scope: Mutex<HashMap<String, u64>>,
    queue_by_session: Mutex<HashMap<String, u64>>,
}

/// CAS 准入：达上限即拒并返回当时用量（None 上限 = 无界放行）
fn try_inc(counter: &AtomicU64, max: Option<u64>) -> Result<u64, u64> {
    match max {
        None => Ok(counter.fetch_add(1, Ordering::Relaxed) + 1),
        Some(limit) => counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_add(1).filter(|next| *next <= limit)
            })
            .map(|_| 0)
            .map_err(|used| used + 1),
    }
}

fn dec(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        v.checked_sub(1).or(Some(0))
    });
}

fn dec_bytes(counter: &AtomicU64, bytes: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(bytes))
    });
}

/// 会话许可（Drop 归还总量 + 场景范围两本账）
pub struct SessionPermit {
    state: Arc<BudgetState>,
    scope: Option<String>,
}

impl fmt::Debug for SessionPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPermit")
            .field("scope", &self.scope)
            .finish()
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        dec(&self.state.sessions_total);
        if let Some(scope) = &self.scope {
            if let Ok(mut map) = self.state.sessions_by_scope.lock() {
                if let Some(used) = map.get_mut(scope) {
                    *used = used.saturating_sub(1);
                    if *used == 0 {
                        map.remove(scope);
                    }
                }
            }
        }
    }
}

/// 拨号许可（Drop 归还）
#[derive(Debug)]
pub struct DialPermit {
    state: Arc<BudgetState>,
}

impl Drop for DialPermit {
    fn drop(&mut self) {
        dec(&self.state.dialing);
    }
}

/// UDP 映射许可（Drop 归还）
#[derive(Debug)]
pub struct MappingPermit {
    state: Arc<BudgetState>,
}

impl Drop for MappingPermit {
    fn drop(&mut self) {
        dec(&self.state.udp_mappings);
    }
}

/// 队列字节占用（Drop 归还单会话与全局两本账——内存守恒）
pub struct QueueReservation {
    state: Arc<BudgetState>,
    session_id: String,
    bytes: u64,
}

impl fmt::Debug for QueueReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueueReservation")
            .field("session_id", &self.session_id)
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for QueueReservation {
    fn drop(&mut self) {
        dec_bytes(&self.state.queue_bytes_total, self.bytes);
        if let Ok(mut map) = self.state.queue_by_session.lock() {
            if let Some(used) = map.get_mut(&self.session_id) {
                *used = used.saturating_sub(self.bytes);
                if *used == 0 {
                    map.remove(&self.session_id);
                }
            }
        }
    }
}

/// 控制面许可（独立池——Drop 归还）
#[derive(Debug)]
pub struct ControlPermit {
    state: Arc<BudgetState>,
}

impl Drop for ControlPermit {
    fn drop(&mut self) {
        dec(&self.state.control);
    }
}

/// 预算账本：全部资源面共用一本上限、各自计数。准入门只做 CAS 与
/// 两处小映射表加锁（队列/范围记账）；控制面准入门只走原子量——
/// 不与转发面任何锁竞争（控制请求不阻塞转发的结构半边）。
#[derive(Debug, Clone)]
pub struct Budgets {
    limits: BudgetLimits,
    state: Arc<BudgetState>,
}

impl Budgets {
    /// 构造账本
    pub fn new(limits: BudgetLimits) -> Self {
        Self {
            limits,
            state: Arc::new(BudgetState::default()),
        }
    }

    /// 准入一个会话（场景范围记账；总量与范围任一超限即拒）
    pub fn admit_session(
        &self,
        scope: impl Into<String>,
    ) -> Result<SessionPermit, BudgetRejection> {
        let scope = scope.into();
        match try_inc(&self.state.sessions_total, self.limits.max_sessions_total) {
            Err(used) => Err(BudgetRejection {
                kind: BudgetKind::SessionsTotal,
                used,
                limit: self.limits.max_sessions_total.expect("拒绝必有上限"),
            }),
            Ok(_) => {
                let scope_used = {
                    let mut map = self.state.sessions_by_scope.lock().expect("scope 记账锁");
                    let used = map.entry(scope.clone()).or_insert(0);
                    *used += 1;
                    *used
                };
                if let Some(limit) = self.limits.max_sessions_per_scope {
                    if scope_used > limit {
                        // 回滚总量记账后按范围上限拒绝
                        dec(&self.state.sessions_total);
                        if let Ok(mut map) = self.state.sessions_by_scope.lock() {
                            if let Some(used) = map.get_mut(&scope) {
                                *used -= 1;
                                if *used == 0 {
                                    map.remove(&scope);
                                }
                            }
                        }
                        return Err(BudgetRejection {
                            kind: BudgetKind::SessionScope(scope),
                            used: scope_used,
                            limit,
                        });
                    }
                }
                Ok(SessionPermit {
                    state: Arc::clone(&self.state),
                    scope: Some(scope),
                })
            }
        }
    }

    /// 准入一次拨号
    pub fn begin_dial(&self) -> Result<DialPermit, BudgetRejection> {
        try_inc(&self.state.dialing, self.limits.max_dialing).map_err(|used| BudgetRejection {
            kind: BudgetKind::Dialing,
            used,
            limit: self.limits.max_dialing.expect("拒绝必有上限"),
        })?;
        Ok(DialPermit {
            state: Arc::clone(&self.state),
        })
    }

    /// 准入一条 UDP NAT 映射
    pub fn admit_udp_mapping(&self) -> Result<MappingPermit, BudgetRejection> {
        try_inc(&self.state.udp_mappings, self.limits.max_udp_mappings).map_err(|used| {
            BudgetRejection {
                kind: BudgetKind::UdpMapping,
                used,
                limit: self.limits.max_udp_mappings.expect("拒绝必有上限"),
            }
        })?;
        Ok(MappingPermit {
            state: Arc::clone(&self.state),
        })
    }

    /// 占用发送队列字节（单会话 + 全局两本账；任一超限即拒——背压
    /// 决策点：调用方按解释丢弃或延迟，内核不排队）
    pub fn reserve_queue_bytes(
        &self,
        session_id: impl Into<String>,
        bytes: u64,
    ) -> Result<QueueReservation, BudgetRejection> {
        let session_id = session_id.into();
        if let Some(limit) = self.limits.max_queue_bytes_per_session {
            let used = self
                .state
                .queue_by_session
                .lock()
                .expect("队列记账锁")
                .get(&session_id)
                .copied()
                .unwrap_or(0);
            if used + bytes > limit {
                return Err(BudgetRejection {
                    kind: BudgetKind::QueueSession(session_id),
                    used: used + bytes,
                    limit,
                });
            }
        }
        match try_inc_bytes(
            bytes,
            &self.state.queue_bytes_total,
            self.limits.max_queue_bytes_total,
        ) {
            Err(used) => Err(BudgetRejection {
                kind: BudgetKind::QueueTotal,
                used,
                limit: self.limits.max_queue_bytes_total.expect("拒绝必有上限"),
            }),
            Ok(_) => {
                if bytes > 0 {
                    let mut map = self.state.queue_by_session.lock().expect("队列记账锁");
                    *map.entry(session_id.clone()).or_insert(0) += bytes;
                }
                Ok(QueueReservation {
                    state: Arc::clone(&self.state),
                    session_id,
                    bytes,
                })
            }
        }
    }

    /// 准入一个控制请求（独立池——数据面全满不影响控制面准入）
    pub fn admit_control(&self) -> Result<ControlPermit, BudgetRejection> {
        try_inc(&self.state.control, self.limits.max_control).map_err(|used| BudgetRejection {
            kind: BudgetKind::Control,
            used,
            limit: self.limits.max_control.expect("拒绝必有上限"),
        })?;
        Ok(ControlPermit {
            state: Arc::clone(&self.state),
        })
    }

    /// 用量快照（可观测）
    pub fn usage(&self) -> BudgetUsage {
        BudgetUsage {
            sessions_total: self.state.sessions_total.load(Ordering::Relaxed),
            dialing: self.state.dialing.load(Ordering::Relaxed),
            udp_mappings: self.state.udp_mappings.load(Ordering::Relaxed),
            queue_bytes_total: self.state.queue_bytes_total.load(Ordering::Relaxed),
            control: self.state.control.load(Ordering::Relaxed),
        }
    }

    /// 上限引用（诊断对账）
    pub fn limits(&self) -> &BudgetLimits {
        &self.limits
    }
}

/// 字节量 CAS 准入（与计数同一守恒语义）
fn try_inc_bytes(bytes: u64, counter: &AtomicU64, max: Option<u64>) -> Result<(), u64> {
    match max {
        None => {
            counter.fetch_add(bytes, Ordering::Relaxed);
            Ok(())
        }
        Some(limit) => counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_add(bytes).filter(|next| *next <= limit)
            })
            .map(|_| ())
            .map_err(|used| used + bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 会话总量与场景范围两道门：范围超限可解释（点名范围），其它范围
    /// 不受影响；总量门独立生效
    #[test]
    fn session_caps_per_scope_and_total() {
        let budgets = Budgets::new(BudgetLimits {
            max_sessions_per_scope: Some(2),
            ..Default::default()
        });

        let _a1 = budgets.admit_session("game").expect("game 1");
        let _a2 = budgets.admit_session("game").expect("game 2");
        let err = budgets.admit_session("game").expect_err("game 第 3 个应拒");
        assert_eq!(err.code(), CODE_BUDGET_SESSION_SCOPE);
        assert_eq!(err.kind, BudgetKind::SessionScope("game".to_string()));
        assert_eq!(err.used, 3);
        assert_eq!(err.limit, 2);

        // 其它范围不受影响
        let _w1 = budgets.admit_session("web").expect("web 独立记账");
        assert_eq!(budgets.usage().sessions_total, 3);

        // 总量门独立生效
        drop(_a1);
        drop(_a2);
        drop(_w1);
        assert_eq!(budgets.usage().sessions_total, 0, "Drop 归还记账");
        let budgets = Budgets::new(BudgetLimits {
            max_sessions_total: Some(1),
            ..Default::default()
        });
        let _only = budgets.admit_session("game").expect("第 1 个");
        let err = budgets.admit_session("web").expect_err("总量满");
        assert_eq!(err.code(), CODE_BUDGET_SESSIONS);
        assert_eq!(err.kind, BudgetKind::SessionsTotal);
    }

    /// 拨号上限：达限拒绝、完成（Drop）释放
    #[test]
    fn dial_cap_and_completion_releases() {
        let budgets = Budgets::new(BudgetLimits {
            max_dialing: Some(2),
            ..Default::default()
        });
        let d1 = budgets.begin_dial().expect("dial 1");
        let d2 = budgets.begin_dial().expect("dial 2");
        let err = budgets.begin_dial().expect_err("第 3 个应拒");
        assert_eq!(err.code(), CODE_BUDGET_DIALING);
        assert_eq!(err.used, 3);
        drop(d1);
        let _d3 = budgets.begin_dial().expect("释放后可再拨");
        drop(d2);
        assert_eq!(budgets.usage().dialing, 1);
    }

    /// UDP 映射上限
    #[test]
    fn udp_mapping_cap() {
        let budgets = Budgets::new(BudgetLimits {
            max_udp_mappings: Some(1),
            ..Default::default()
        });
        let _m = budgets.admit_udp_mapping().expect("映射 1");
        let err = budgets.admit_udp_mapping().expect_err("第 2 条应拒");
        assert_eq!(err.code(), CODE_BUDGET_UDP_MAPPING);
        assert_eq!(err.kind, BudgetKind::UdpMapping);
    }

    /// 单会话队列字节上限：超限拒绝可解释（点名会话与字节数）
    #[test]
    fn queue_bytes_per_session_cap() {
        let budgets = Budgets::new(BudgetLimits::with_max_queue_bytes_per_session(1000));
        let _r1 = budgets
            .reserve_queue_bytes("flow-1", 600)
            .expect("600B 可占");
        let err = budgets
            .reserve_queue_bytes("flow-1", 500)
            .expect_err("累计 1100B 应拒");
        assert_eq!(err.code(), CODE_BUDGET_QUEUE_SESSION);
        assert_eq!(err.kind, BudgetKind::QueueSession("flow-1".to_string()));
        assert_eq!(err.used, 1100);
        assert_eq!(err.limit, 1000);

        // 其它会话不受单会话门影响
        let _r2 = budgets
            .reserve_queue_bytes("flow-2", 500)
            .expect("flow-2 独立记账");
    }

    /// 全局队列字节总量上限：零散占用累积触顶即拒；释放后可再占
    /// （内存不无界增长）
    #[test]
    fn queue_bytes_total_cap_and_release() {
        let budgets = Budgets::new(BudgetLimits {
            max_queue_bytes_total: Some(1000),
            ..Default::default()
        });
        let r1 = budgets.reserve_queue_bytes("flow-1", 400).expect("400B");
        let _r2 = budgets.reserve_queue_bytes("flow-2", 600).expect("600B");
        let err = budgets
            .reserve_queue_bytes("flow-3", 1)
            .expect_err("总量触顶应拒");
        assert_eq!(err.code(), CODE_BUDGET_QUEUE_TOTAL);
        assert_eq!(err.used, 1001);
        assert_eq!(err.limit, 1000);
        assert_eq!(budgets.usage().queue_bytes_total, 1000);

        // 释放即归还
        drop(r1);
        assert_eq!(budgets.usage().queue_bytes_total, 600);
        let _r3 = budgets
            .reserve_queue_bytes("flow-3", 400)
            .expect("归还后可占");
    }

    /// 控制面独立池：数据面（会话+队列）全满时控制请求仍被接纳；
    /// 控制面自己的上限独立生效
    #[test]
    fn control_plane_never_blocked_by_data_plane() {
        let budgets = Budgets::new(BudgetLimits {
            max_sessions_total: Some(1),
            max_queue_bytes_total: Some(1),
            max_control: Some(2),
            ..Default::default()
        });
        let _s = budgets.admit_session("game").expect("占满会话");
        let _q = budgets.reserve_queue_bytes("flow-1", 1).expect("占满队列");

        // 数据面全满：控制面照常准入（独立池，不阻塞）
        let c1 = budgets.admit_control().expect("控制请求 1");
        let _c2 = budgets.admit_control().expect("控制请求 2");
        let err = budgets.admit_control().expect_err("控制面自身上限生效");
        assert_eq!(err.code(), CODE_BUDGET_CONTROL);
        assert_eq!(err.kind, BudgetKind::Control);
        assert_eq!(err.used, 3);
        drop(c1);
        assert_eq!(budgets.usage().control, 1, "Drop 归还控制面记账");
    }

    /// 拒绝解释完备：种类/用量/上限/稳定码四元组齐备（抽实名种核对）
    #[test]
    fn rejection_is_explained() {
        let budgets = Budgets::new(BudgetLimits {
            max_dialing: Some(0),
            max_udp_mappings: Some(0),
            max_control: Some(0),
            max_sessions_total: Some(0),
            ..Default::default()
        });
        // Some(0) = 闸门全关：每类拒绝都给出 used/limit 与稳定码
        let cases = [
            budgets.admit_session("game").expect_err("会话拒"),
            budgets.begin_dial().expect_err("拨号拒"),
            budgets.admit_udp_mapping().expect_err("映射拒"),
            budgets.admit_control().expect_err("控制拒"),
        ];
        for r in &cases {
            assert!(r.limit == 0, "上限入拒绝: {r:?}");
            assert!(r.used >= 1, "用量入拒绝: {r:?}");
            assert!(!r.to_string().is_empty());
        }
        assert_eq!(cases[0].code(), CODE_BUDGET_SESSIONS);
        assert_eq!(cases[1].code(), CODE_BUDGET_DIALING);
        assert_eq!(cases[2].code(), CODE_BUDGET_UDP_MAPPING);
        assert_eq!(cases[3].code(), CODE_BUDGET_CONTROL);

        // 零字节占位恒可（无字节无占用）
        let budgets = Budgets::new(BudgetLimits {
            max_queue_bytes_total: Some(0),
            ..Default::default()
        });
        let _zero = budgets
            .reserve_queue_bytes("flow-1", 0)
            .expect("零字节恒可");
        assert_eq!(budgets.usage().queue_bytes_total, 0);
    }

    /// 场景范围许可 Drop 后范围记账归零（范围映射表不留死条目）
    #[test]
    fn scope_ledger_garbage_free_after_release() {
        let budgets = Budgets::new(BudgetLimits {
            max_sessions_per_scope: Some(1),
            ..Default::default()
        });
        let p = budgets.admit_session("game").expect("game 1");
        let err = budgets.admit_session("game").expect_err("范围满");
        assert_eq!(err.code(), CODE_BUDGET_SESSION_SCOPE);
        drop(p);
        // 释放后同范围可再准入（记账归零）
        let _p2 = budgets.admit_session("game").expect("释放后可再入");
    }
}
