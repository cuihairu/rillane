//! 会话执行器统一接线（RIL-098）：接入确认 → 出口尝试（计划内回退，
//! 选路唯一入口是 [`crate::executor::SessionExecutor`]，不在此复刻候选
//! 序列）→ 成功回复 → 双向转发 → 半关闭/取消/回收的一条权威执行路径。
//!
//! 验收口径落点：
//! - **TCP 与 UDP 不同生命周期**：流走两阶段 `PendingStream::accept` 配对
//!   双向字节泵；关联走 `PendingAssociation::accept` 配对数据报泵
//!   （固定/多目标绑定逐报文校验、报文上限显式拒绝、控制链关闭回收）；
//! - **A 失败 B 成功可追踪**：回退对账在 `EstablishedSession::attempts`
//!   （每次尝试的节点/端点/结果），本模块不另行记录；
//! - **业务交换后不盲目重放**：成功回复一旦发出、字节一旦开始交换，
//!   任何失败都按 [`SessionRunError::TransferFailed`] 终止——**不再发起
//!   第二次出口建立**（失败边界显式，重连是新会话的新决策）；
//! - **背压**：双向泵按有界分片（[`CHUNK`]]）读一写一，未写出前不读下
//!   一片，无内部队列；半关闭按 TCP 语义驱动对侧 `shutdown_write`；
//! - **取消**：建立期取消直接返回、不回复客户端（调用方丢弃
//!   PendingStream 关闭资源——不重复回复）；搬运期取消按稳定码
//!   `session.cancelled` 终止，同样不重放；
//! - **生命周期埋点**（RIL-053，[`crate::session_trace`]）：可选
//!   `SessionTracer` 贯穿每条退出路径——规则/计划（预测）、尝试对账
//!   （逐条 attempt_id）、实际出口/映射、首字节（上/下行分立）、终态
//!   关闭（关闭码区分正常/取消/失败/回收）；缺少测量证据不造数。

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::executor::{EstablishedSession, SessionExecutor};
use crate::inbound::{
    ClientChannel, ControlLink, InboundError, PendingAssociation, PendingStream, RejectCause,
};
use crate::outbound::{
    CancelToken, DatagramIo, DatagramOutbound, EvidenceKind, OpenContext, OpenError, StreamIo,
    StreamOutbound, TargetBinding,
};
use crate::plan::{EndpointRef, RoutePlan};
use crate::session_trace::{
    SessionTracer, CODE_ASSOCIATION_CLOSED, CODE_ASSOCIATION_RECLAIMED, CODE_REPLY_FAILED,
    CODE_STREAM_CLOSED,
};

/// 稳定原因码：搬运期调用方取消（不重放）
pub const CODE_SESSION_CANCELLED: &str = "session.cancelled";
/// 稳定原因码：搬运期 IO 失败（业务交换已发生，不重放）
pub const CODE_SESSION_TRANSFER: &str = "session.transfer";

/// 有界分片：泵每轮至多读写的字节数（背压的量化口径）
pub const CHUNK: usize = 16 * 1024;
/// 搬运期取消令牌的轮询间隔（毫秒）
pub const CANCEL_POLL_MS: u64 = 100;

/// 搬运失败的方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// 客户端 → 出口
    ClientToEgress,
    /// 出口 → 客户端
    EgressToClient,
}

impl TransferDirection {
    /// 机器口径
    pub fn as_str(self) -> &'static str {
        match self {
            TransferDirection::ClientToEgress => "client_to_egress",
            TransferDirection::EgressToClient => "egress_to_client",
        }
    }
}

/// 会话运行失败（显式声明业务交换边界：Rejected/ReplyFailed 发生在
/// 业务字节之前；TransferFailed/Cancelled 发生之后——两者都不得重放）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRunError {
    /// 接入被拒：出口建立失败已映射为协议错误回复（对账在
    /// attempts——A 失败可见）
    Rejected {
        /// 稳定原因码（最近一次真实出口码；静态耗尽无拨号时为计划码，
        /// 与协议回复同源）
        code: &'static str,
        /// 尝试次数
        attempts: usize,
    },
    /// 成功回复失败（出口已在 accept 内就地释放）
    ReplyFailed(InboundError),
    /// 业务搬运期失败——不得重放到其它出口
    TransferFailed {
        /// 失败方向
        direction: TransferDirection,
        /// 稳定原因码
        code: &'static str,
        /// 已交换的业务字节数（双向）
        client_to_egress: u64,
        egress_to_client: u64,
    },
    /// 调用方取消（建立期零字节；搬运期携带已交换字节，同样不重放）
    Cancelled {
        client_to_egress: u64,
        egress_to_client: u64,
    },
}

impl fmt::Display for SessionRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionRunError::Rejected { code, attempts } => {
                write!(f, "ingress rejected ({code}) after {attempts} attempt(s)")
            }
            SessionRunError::ReplyFailed(err) => write!(f, "accept reply failed: {err}"),
            SessionRunError::TransferFailed {
                direction,
                code,
                client_to_egress,
                egress_to_client,
            } => write!(
                f,
                "transfer failed ({}, {}: no replay after business exchange) c2e={} e2c={}",
                direction.as_str(),
                code,
                client_to_egress,
                egress_to_client
            ),
            SessionRunError::Cancelled {
                client_to_egress,
                egress_to_client,
            } => write!(
                f,
                "session cancelled: c2e={} e2c={}",
                client_to_egress, egress_to_client
            ),
        }
    }
}

impl std::error::Error for SessionRunError {}

/// 泵实测统计（含首字节时刻——网页阶段耗时区分 HTTP TTFB 与首个下行
/// 字节的量化面：两个方向的首字节流逝独立可算）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamPumpStats {
    pub client_to_egress: u64,
    pub egress_to_client: u64,
    pub client_closed: bool,
    pub egress_closed: bool,
    /// 首个上行字节距泵启动的单调流逝（毫秒；None = 未观测到上行字节）
    pub first_up_ms: Option<u64>,
    /// 首个下行字节距泵启动的单调流逝（毫秒；None = 未观测到下行字节）
    pub first_down_ms: Option<u64>,
}

/// 数据报泵实测统计（首报文时刻 + 显式拒绝计数）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramPumpStats {
    pub client_to_egress: u64,
    pub egress_to_client: u64,
    pub rejected_too_large: u64,
    pub rejected_target: u64,
    pub reclaimed_by_control: bool,
    pub client_closed: bool,
    pub egress_closed: bool,
    /// 首个上行报文距泵启动的单调流逝（毫秒；None = 未观测到）
    pub first_up_ms: Option<u64>,
    /// 首个下行报文距泵启动的单调流逝（毫秒；None = 未观测到）
    pub first_down_ms: Option<u64>,
}

/// 流会话转发报告：已建立会话（含回退对账）+ 业务字节统计与半关闭状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamForwardReport {
    /// 已建立会话（计划节点 + 实际端点 + 尝试对账冻结）
    pub session: EstablishedSession,
    /// 客户端 → 出口业务字节
    pub client_to_egress: u64,
    /// 出口 → 客户端业务字节
    pub egress_to_client: u64,
    /// 客户端读侧是否正常关闭（EOF → 出口写侧半关闭）
    pub client_closed: bool,
    /// 出口读侧是否正常关闭（EOF → 客户端写侧半关闭）
    pub egress_closed: bool,
    /// 首个上行字节流逝（毫秒；None = 未观测到）
    pub first_up_ms: Option<u64>,
    /// 首个下行字节流逝（毫秒；None = 未观测到）
    pub first_down_ms: Option<u64>,
}

/// 关联会话转发报告：绑定校验与回收语义显式可见。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramForwardReport {
    /// 已建立会话（含回退对账）
    pub session: EstablishedSession,
    /// 客户端 → 出口数据报数（仅合法目标）
    pub client_to_egress: u64,
    /// 出口 → 客户端数据报数
    pub egress_to_client: u64,
    /// 超过报文上限被显式拒绝的报文数（不静默截断）
    pub rejected_too_large: u64,
    /// 目标不在绑定集合内被拒绝的报文数（固定目标不得旁落）
    pub rejected_target: u64,
    /// 是否因控制链关闭而回收（SOCKS5 UDP 控制连接结束 → 按契约回收）
    pub reclaimed_by_control: bool,
    /// 客户端中继读侧是否关闭
    pub client_closed: bool,
    /// 出口读侧是否关闭
    pub egress_closed: bool,
    /// 首个上行报文流逝（毫秒；None = 未观测到）
    pub first_up_ms: Option<u64>,
    /// 首个下行报文流逝（毫秒；None = 未观测到）
    pub first_down_ms: Option<u64>,
}

/// 流会话权威路径：出口建立（计划内回退，复用执行器唯一选路）→
/// 成功回复 → 双向转发。失败按 [`SessionRunError`] 声明业务交换边界。
///
/// 建立失败且非取消时，拒绝回复经 `RejectCause::Egress` 携带**最近一次
/// 真实拨号错误**（稳定码/阶段/证据原样透传）；取消时不回复——调用方
/// 丢弃 `PendingStream` 即关闭资源（取消不重复回复）。
///
/// `tracer`（RIL-053）可选：传入即记录规则/计划/尝试对账/实际出口/
/// 传输首字节/关闭事件——每条退出路径（含失败）都以终态关闭事件收口。
pub async fn run_stream_session(
    executor: &SessionExecutor,
    pending: &mut PendingStream,
    plan: &mut RoutePlan,
    outbound: Arc<dyn StreamOutbound>,
    ctx: OpenContext,
    now_ms: u64,
    mut tracer: Option<&mut SessionTracer>,
) -> Result<StreamForwardReport, SessionRunError> {
    let cancel = ctx.cancel.clone();
    // 埋点：规则命中与计划形成（预测证据——选中 ≠ 连通）
    if let Some(t) = tracer.as_deref_mut() {
        t.rule(plan);
        t.plan(plan);
    }
    let established = match executor
        .open_stream_channel(plan, outbound, ctx, now_ms)
        .await
    {
        Ok(channel) => channel,
        Err(failure) => {
            if failure.plan.code() == crate::outbound::CODE_OPEN_CANCELLED {
                // 取消/截止：不回复，调用方丢弃 pending 关闭资源
                if let Some(t) = tracer.as_deref_mut() {
                    t.attempts(failure.attempts());
                    t.close(
                        CODE_SESSION_CANCELLED,
                        EvidenceKind::Observed,
                        "cancelled before establishment",
                    );
                }
                return Err(SessionRunError::Cancelled {
                    client_to_egress: 0,
                    egress_to_client: 0,
                });
            }
            let attempts = failure.attempts().len();
            // 拒绝码与协议回复同源：最近一次真实出口码；静态耗尽（无拨号）
            // 才退回计划码
            let code = match &failure.last_open_error {
                Some(open_err) => open_err.code,
                None => failure.code(),
            };
            if let Some(t) = tracer {
                t.attempts(failure.attempts());
                t.close(code, EvidenceKind::Observed, "establish failed");
            }
            match failure.last_open_error {
                Some(open_err) => {
                    pending
                        .reject(RejectCause::Egress(open_err))
                        .await
                        .map_err(SessionRunError::ReplyFailed)?;
                }
                None => {
                    // 静态跳过/耗尽（无真实拨号错误）：按计划口径已脱敏拒绝
                    pending
                        .reject(RejectCause::Policy(failure.plan.to_string()))
                        .await
                        .map_err(SessionRunError::ReplyFailed)?;
                }
            }
            return Err(SessionRunError::Rejected { code, attempts });
        }
    };
    let (session, opened) = (established.session, established.stream);
    // 埋点：尝试对账 + 实际出口（观测证据——A 失败 B 成功逐条可解释）
    if let Some(t) = tracer.as_deref_mut() {
        t.attempts(session.attempts());
        t.egress(
            session.pin().egress(),
            &format!("{}:{}", session.endpoint().host, session.endpoint().port),
            false,
        );
    }
    // 接入确认：成功回复失败 → 出口已在 accept 内就地释放（无泄漏）
    let accepted = match pending.accept(opened).await {
        Ok(accepted) => accepted,
        Err(err) => {
            if let Some(t) = tracer.as_deref_mut() {
                t.close(
                    CODE_REPLY_FAILED,
                    EvidenceKind::Observed,
                    "success reply failed",
                );
            }
            return Err(SessionRunError::ReplyFailed(err));
        }
    };
    let (mut client, egress) = accepted.into_parts();
    let (_endpoint, _transport, mut egress_io) = egress.into_parts();

    let stats = pump_stream(&mut *client, &mut *egress_io, &cancel).await;
    match stats {
        Ok(s) => {
            // 埋点：首字节（上/下行分立——TTFB 与首个下行字节可区分）+
            // 终态关闭
            if let Some(t) = tracer.as_deref_mut() {
                if let Some(elapsed) = s.first_up_ms {
                    t.transfer_first(TransferDirection::ClientToEgress, elapsed);
                }
                if let Some(elapsed) = s.first_down_ms {
                    t.transfer_first(TransferDirection::EgressToClient, elapsed);
                }
                t.close(
                    CODE_STREAM_CLOSED,
                    EvidenceKind::Observed,
                    format!(
                        "c2e={} e2c={} client_closed={} egress_closed={}",
                        s.client_to_egress, s.egress_to_client, s.client_closed, s.egress_closed
                    ),
                );
            }
            Ok(StreamForwardReport {
                session,
                client_to_egress: s.client_to_egress,
                egress_to_client: s.egress_to_client,
                client_closed: s.client_closed,
                egress_closed: s.egress_closed,
                first_up_ms: s.first_up_ms,
                first_down_ms: s.first_down_ms,
            })
        }
        Err(err) => {
            if let Some(t) = tracer {
                match &err {
                    SessionRunError::Cancelled {
                        client_to_egress: c2e,
                        egress_to_client: e2c,
                    } => t.close(
                        CODE_SESSION_CANCELLED,
                        EvidenceKind::Observed,
                        format!("cancelled c2e={c2e} e2c={e2c}"),
                    ),
                    SessionRunError::TransferFailed {
                        direction,
                        code,
                        client_to_egress,
                        egress_to_client,
                    } => t.close(
                        code,
                        EvidenceKind::Observed,
                        format!(
                            "{} c2e={client_to_egress} e2c={egress_to_client}",
                            direction.as_str()
                        ),
                    ),
                    other => t.close(
                        CODE_SESSION_TRANSFER,
                        EvidenceKind::Observed,
                        format!("transfer ended: {other:?}"),
                    ),
                }
            }
            Err(err)
        }
    }
}

/// 关联会话权威路径：数据报出口建立 → 准入回复（中继地址）→ 数据报泵。
/// 逐报文校验目标绑定与上限（显式拒绝计数，不静默截断/旁落）；
/// 控制链关闭即回收。搬运期失败/取消不重放（同流会话口径）。
///
/// `client_endpoint` 是出口 → 客户端方向数据报的回程元组（客户端中继
/// 适配器按它投递）；`client_relay` 是客户端中继 IO（RIL-096 保持
/// 适配器持有，此处只借用泵送）。`tracer`（RIL-053）可选：关联生命
/// 周期同流会话埋点——出口事件为映射建立（association.mapped），关闭
/// 事件区分控制链回收（association.reclaimed）与正常关闭。
#[allow(clippy::too_many_arguments)] // 参数即契约：执行器/准入/计划/出口/绑定/取消/回程/埋点各占其一
pub async fn run_association_session(
    executor: &SessionExecutor,
    pending: &mut PendingAssociation,
    plan: &mut RoutePlan,
    outbound: Arc<dyn DatagramOutbound>,
    binding: TargetBinding,
    ctx: OpenContext,
    now_ms: u64,
    relay: &EndpointRef,
    client_endpoint: &EndpointRef,
    client_relay: &mut dyn DatagramIo,
    mut tracer: Option<&mut SessionTracer>,
) -> Result<DatagramForwardReport, SessionRunError> {
    let cancel = ctx.cancel.clone();
    if let Some(t) = tracer.as_deref_mut() {
        t.rule(plan);
        t.plan(plan);
    }
    let established = match executor
        .open_association_channel(plan, outbound, binding, ctx, now_ms)
        .await
    {
        Ok(channel) => channel,
        Err(failure) => {
            if failure.plan.code() == crate::outbound::CODE_OPEN_CANCELLED {
                if let Some(t) = tracer.as_deref_mut() {
                    t.attempts(failure.attempts());
                    t.close(
                        CODE_SESSION_CANCELLED,
                        EvidenceKind::Observed,
                        "cancelled before establishment",
                    );
                }
                return Err(SessionRunError::Cancelled {
                    client_to_egress: 0,
                    egress_to_client: 0,
                });
            }
            let attempts = failure.attempts().len();
            // 同流会话口径：最近一次真实出口码，静态耗尽才退回计划码
            let code = match &failure.last_open_error {
                Some(open_err) => open_err.code,
                None => failure.code(),
            };
            if let Some(t) = tracer.as_deref_mut() {
                t.attempts(failure.attempts());
                t.close(code, EvidenceKind::Observed, "establish failed");
            }
            match failure.last_open_error {
                Some(open_err) => {
                    pending
                        .reject(RejectCause::Egress(open_err))
                        .await
                        .map_err(SessionRunError::ReplyFailed)?;
                }
                None => {
                    pending
                        .reject(RejectCause::Policy(failure.plan.to_string()))
                        .await
                        .map_err(SessionRunError::ReplyFailed)?;
                }
            }
            return Err(SessionRunError::Rejected { code, attempts });
        }
    };
    let (session, association) = (established.session, established.association);
    let max_datagram_len = association.max_datagram_len();
    let (_, egress_binding, mut egress_io) = association.into_parts();

    // 埋点：尝试对账 + 映射建立（切网重建的对照面）
    if let Some(t) = tracer.as_deref_mut() {
        t.attempts(session.attempts());
        t.egress(
            session.pin().egress(),
            &format!("{}:{}", session.endpoint().host, session.endpoint().port),
            true,
        );
    }

    // 准入：回复中继地址；回复失败 → 控制链已在 accept 内就地释放
    let ingress = match pending.accept(relay).await {
        Ok(ingress) => ingress,
        Err(err) => {
            if let Some(t) = tracer.as_deref_mut() {
                t.close(
                    CODE_REPLY_FAILED,
                    EvidenceKind::Observed,
                    "admit reply failed",
                );
            }
            return Err(SessionRunError::ReplyFailed(err));
        }
    };
    let (_source, _targets, control) = ingress.into_parts();

    let stats = pump_association(
        client_relay,
        &mut *egress_io,
        &egress_binding,
        max_datagram_len,
        client_endpoint,
        &control,
        &cancel,
    )
    .await;
    match stats {
        Ok(s) => {
            // 埋点：首报文 + 终态（回收 = 切网的内核可见面；关闭 detail
            // 携带显式拒绝计数——超限/旁落逐报文计数不静默）
            if let Some(t) = tracer.as_deref_mut() {
                if let Some(elapsed) = s.first_up_ms {
                    t.transfer_first(TransferDirection::ClientToEgress, elapsed);
                }
                if let Some(elapsed) = s.first_down_ms {
                    t.transfer_first(TransferDirection::EgressToClient, elapsed);
                }
                let close_code = if s.reclaimed_by_control {
                    CODE_ASSOCIATION_RECLAIMED
                } else {
                    CODE_ASSOCIATION_CLOSED
                };
                t.close(
                    close_code,
                    EvidenceKind::Observed,
                    format!(
                        "c2e={} e2c={} reject_too_large={} reject_target={}",
                        s.client_to_egress,
                        s.egress_to_client,
                        s.rejected_too_large,
                        s.rejected_target
                    ),
                );
            }
            Ok(DatagramForwardReport {
                session,
                client_to_egress: s.client_to_egress,
                egress_to_client: s.egress_to_client,
                rejected_too_large: s.rejected_too_large,
                rejected_target: s.rejected_target,
                reclaimed_by_control: s.reclaimed_by_control,
                client_closed: s.client_closed,
                egress_closed: s.egress_closed,
                first_up_ms: s.first_up_ms,
                first_down_ms: s.first_down_ms,
            })
        }
        Err(err) => {
            if let Some(t) = tracer {
                match &err {
                    SessionRunError::Cancelled {
                        client_to_egress: c2e,
                        egress_to_client: e2c,
                    } => t.close(
                        CODE_SESSION_CANCELLED,
                        EvidenceKind::Observed,
                        format!("cancelled c2e={c2e} e2c={e2c}"),
                    ),
                    SessionRunError::TransferFailed {
                        direction,
                        code,
                        client_to_egress,
                        egress_to_client,
                    } => t.close(
                        code,
                        EvidenceKind::Observed,
                        format!(
                            "{} c2e={client_to_egress} e2c={egress_to_client}",
                            direction.as_str()
                        ),
                    ),
                    other => t.close(
                        CODE_SESSION_TRANSFER,
                        EvidenceKind::Observed,
                        format!("transfer ended: {other:?}"),
                    ),
                }
            }
            Err(err)
        }
    }
}

/// 双向字节泵：有界分片读一写一（未写出前不读下一片——背压），
/// 单侧 EOF 驱动对侧半关闭，双侧 EOF 结束，取消按轮询间隔响应。
/// 首字节时刻按方向实测（距泵启动流逝——TTFB 与首个下行字节分立）。
async fn pump_stream(
    client: &mut dyn ClientChannel,
    egress: &mut dyn StreamIo,
    cancel: &CancelToken,
) -> Result<StreamPumpStats, SessionRunError> {
    let started = std::time::Instant::now();
    let mut first_up_ms: Option<u64> = None;
    let mut first_down_ms: Option<u64> = None;
    let (mut c2e, mut e2c) = (0u64, 0u64);
    let mut client_closed = false;
    let mut egress_closed = false;

    loop {
        if cancel.is_cancelled() {
            return Err(SessionRunError::Cancelled {
                client_to_egress: c2e,
                egress_to_client: e2c,
            });
        }
        if client_closed && egress_closed {
            return Ok(StreamPumpStats {
                client_to_egress: c2e,
                egress_to_client: e2c,
                client_closed,
                egress_closed,
                first_up_ms,
                first_down_ms,
            });
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(CANCEL_POLL_MS)) => continue,
            r = client.read(CHUNK), if !client_closed => match r {
                Ok(Some(data)) => {
                    let n = data.len() as u64;
                    if first_up_ms.is_none() {
                        first_up_ms = Some(started.elapsed().as_millis() as u64);
                    }
                    egress
                        .write_all(data)
                        .await
                        .map_err(|e| transfer_err(TransferDirection::ClientToEgress, e, c2e, e2c))?;
                    c2e += n;
                }
                Ok(None) => {
                    client_closed = true;
                    egress
                        .shutdown_write()
                        .await
                        .map_err(|e| transfer_err(TransferDirection::ClientToEgress, e, c2e, e2c))?;
                }
                Err(e) => {
                    return Err(client_transfer_err(TransferDirection::ClientToEgress, e, c2e, e2c));
                }
            },
            r = egress.read(CHUNK), if !egress_closed => match r {
                Ok(Some(data)) => {
                    let n = data.len() as u64;
                    if first_down_ms.is_none() {
                        first_down_ms = Some(started.elapsed().as_millis() as u64);
                    }
                    client
                        .write_all(data)
                        .await
                        .map_err(|e| client_transfer_err(TransferDirection::EgressToClient, e, c2e, e2c))?;
                    e2c += n;
                }
                Ok(None) => {
                    egress_closed = true;
                    client
                        .shutdown()
                        .await
                        .map_err(|e| client_transfer_err(TransferDirection::EgressToClient, e, c2e, e2c))?;
                }
                Err(e) => {
                    return Err(transfer_err(TransferDirection::EgressToClient, e, c2e, e2c));
                }
            },
        }
    }
}

/// 数据报泵：逐报文校验上限与目标绑定（显式计数拒绝），控制链关闭
/// 即回收。首报文时刻按方向实测（距泵启动流逝）。
#[allow(clippy::too_many_arguments)]
async fn pump_association(
    client_relay: &mut dyn DatagramIo,
    egress: &mut dyn DatagramIo,
    binding: &TargetBinding,
    max_datagram_len: usize,
    client_endpoint: &EndpointRef,
    control: &ControlLink,
    cancel: &CancelToken,
) -> Result<DatagramPumpStats, SessionRunError> {
    let started = std::time::Instant::now();
    let mut first_up_ms: Option<u64> = None;
    let mut first_down_ms: Option<u64> = None;
    let (mut c2e, mut e2c, mut too_large, mut wrong_target) = (0u64, 0u64, 0u64, 0u64);

    macro_rules! settle {
        ($reclaimed:expr, $client_closed:expr, $egress_closed:expr) => {
            Ok(DatagramPumpStats {
                client_to_egress: c2e,
                egress_to_client: e2c,
                rejected_too_large: too_large,
                rejected_target: wrong_target,
                reclaimed_by_control: $reclaimed,
                client_closed: $client_closed,
                egress_closed: $egress_closed,
                first_up_ms,
                first_down_ms,
            })
        };
    }

    loop {
        if cancel.is_cancelled() {
            return Err(SessionRunError::Cancelled {
                client_to_egress: c2e,
                egress_to_client: e2c,
            });
        }
        if control.is_closed() {
            return settle!(true, false, false);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(CANCEL_POLL_MS)) => continue,
            r = client_relay.recv() => match r {
                Ok(Some((target, payload))) => {
                    if payload.len() > max_datagram_len {
                        // 超限显式失败（计数可见），不静默截断
                        too_large += 1;
                        continue;
                    }
                    if !binding.allows(&target) {
                        // 固定目标不得旁落 / 多目标白名单外
                        wrong_target += 1;
                        continue;
                    }
                    if first_up_ms.is_none() {
                        first_up_ms = Some(started.elapsed().as_millis() as u64);
                    }
                    egress
                        .send(&target, payload)
                        .await
                        .map_err(|e| transfer_err(TransferDirection::ClientToEgress, e, c2e, e2c))?;
                    c2e += 1;
                }
                Ok(None) => {
                    // 控制链已关闭 → 按回收口径结束（关闭与客户端关闭同时
                    // 发生也归回收——控制链关闭是关联生命的终点）
                    if control.is_closed() {
                        return settle!(true, false, false);
                    }
                    return settle!(false, true, false);
                }
                Err(e) => {
                    return Err(transfer_err(TransferDirection::ClientToEgress, e, c2e, e2c));
                }
            },
            r = egress.recv() => match r {
                Ok(Some((_peer, payload))) => {
                    if first_down_ms.is_none() {
                        first_down_ms = Some(started.elapsed().as_millis() as u64);
                    }
                    client_relay
                        .send(client_endpoint, payload)
                        .await
                        .map_err(|e| transfer_err(TransferDirection::EgressToClient, e, c2e, e2c))?;
                    e2c += 1;
                }
                Ok(None) => {
                    // 出口读侧结束：控制链若已关闭仍归回收（关联生命
                    // 终点与客户侧口径一致——不因观察到关闭的一侧而异）
                    if control.is_closed() {
                        return settle!(true, false, false);
                    }
                    return settle!(false, false, true);
                }
                Err(e) => {
                    return Err(transfer_err(TransferDirection::EgressToClient, e, c2e, e2c));
                }
            },
        }
    }
}

/// 搬运期失败统一口径：稳定码 + 方向 + 已交换字节（不重放的失败边界）
fn transfer_err(
    direction: TransferDirection,
    err: OpenError,
    c2e: u64,
    e2c: u64,
) -> SessionRunError {
    if err.code == crate::outbound::CODE_OPEN_CANCELLED {
        return SessionRunError::Cancelled {
            client_to_egress: c2e,
            egress_to_client: e2c,
        };
    }
    SessionRunError::TransferFailed {
        direction,
        code: err.code,
        client_to_egress: c2e,
        egress_to_client: e2c,
    }
}

/// 客户端侧搬运失败：`ClientChannel` 的错误是 [`InboundError`]，同样按
/// 稳定码 + 方向 + 已交换字节收敛（取消映射会话取消，其余按搬运失败）。
fn client_transfer_err(
    direction: TransferDirection,
    err: InboundError,
    c2e: u64,
    e2c: u64,
) -> SessionRunError {
    if err.code == crate::inbound::CODE_INBOUND_CANCELLED {
        return SessionRunError::Cancelled {
            client_to_egress: c2e,
            egress_to_client: e2c,
        };
    }
    SessionRunError::TransferFailed {
        direction,
        code: err.code,
        client_to_egress: c2e,
        egress_to_client: e2c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{AttemptRecord, PlanExecError};

    /// 稳定码与口径常量
    #[test]
    fn session_codes_are_stable() {
        assert_eq!(CODE_SESSION_CANCELLED, "session.cancelled");
        assert_eq!(CODE_SESSION_TRANSFER, "session.transfer");
        assert_eq!(CHUNK, 16 * 1024);
        assert_eq!(CANCEL_POLL_MS, 100);
    }

    /// 失败边界口径：搬运失败携带方向/码/已交换字节；取消区分于失败
    #[test]
    fn transfer_err_maps_codes_and_boundaries() {
        let e = transfer_err(
            TransferDirection::ClientToEgress,
            OpenError::new(
                crate::outbound::OpenStage::Transport,
                "outbound.io.reset",
                true,
                crate::outbound::EvidenceKind::Observed,
                "peer reset",
            ),
            100,
            7,
        );
        assert_eq!(
            e,
            SessionRunError::TransferFailed {
                direction: TransferDirection::ClientToEgress,
                code: "outbound.io.reset",
                client_to_egress: 100,
                egress_to_client: 7,
            }
        );
        assert!(e.to_string().contains("no replay"));

        let c = transfer_err(
            TransferDirection::EgressToClient,
            OpenError::cancelled(crate::outbound::OpenStage::Transport),
            1,
            2,
        );
        assert_eq!(
            c,
            SessionRunError::Cancelled {
                client_to_egress: 1,
                egress_to_client: 2,
            },
            "出口侧取消映射会话取消而非失败"
        );

        // 客户端侧错误（InboundError）同口径：取消 → Cancelled，其余 → TransferFailed
        let ce = client_transfer_err(
            TransferDirection::EgressToClient,
            InboundError::new(
                crate::inbound::InboundStage::Admit,
                "inbound.client.write",
                true,
                crate::outbound::EvidenceKind::Observed,
                "client write failed",
            ),
            3,
            9,
        );
        assert_eq!(
            ce,
            SessionRunError::TransferFailed {
                direction: TransferDirection::EgressToClient,
                code: "inbound.client.write",
                client_to_egress: 3,
                egress_to_client: 9,
            }
        );
        let cc = client_transfer_err(
            TransferDirection::ClientToEgress,
            InboundError::cancelled(),
            4,
            5,
        );
        assert_eq!(
            cc,
            SessionRunError::Cancelled {
                client_to_egress: 4,
                egress_to_client: 5,
            },
            "客户端侧取消同样映射会话取消"
        );
    }

    /// 方向机器口径
    #[test]
    fn direction_as_str_stable() {
        assert_eq!(
            TransferDirection::ClientToEgress.as_str(),
            "client_to_egress"
        );
        assert_eq!(
            TransferDirection::EgressToClient.as_str(),
            "egress_to_client"
        );
    }

    /// 编译期锚：AttemptRecord 是回退对账的唯一载体（本模块不另行记录）
    #[test]
    fn attempts_come_from_established_session_only() {
        let rec = AttemptRecord {
            attempt_id: 0,
            node: "a".into(),
            endpoint: EndpointRef::new("1.1.1.1", 443),
            outcome: crate::executor::AttemptOutcome::Dialed,
        };
        assert_eq!(rec.node, "a");
        assert_eq!(
            PlanExecError::Exhausted {
                attempts: vec![rec]
            }
            .code(),
            "plan_exec.exhausted"
        );
    }
}
