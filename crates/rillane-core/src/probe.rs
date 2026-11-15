//! 主动探测作业服务（RIL-059）：DNS / TCP connect / 代理握手 / UDP 回显
//! 四类**显式**探测作业——探测只经 [`ProbeService::submit`] 发生，只读
//! 查询（[`ProbeService::result`]/[`ProbeService::list`]）结构上无法
//! 隐式触发探测。
//!
//! 契约落点：
//! - **目标范围闭合**：探测目标只在装配时经 [`TargetScope`] 显式登记
//!   （键为已类型化的 host/addr/egress 名——没有从任意文本构造范围
//!   的入口），`submit` 逐目标核对范围，范围外的目标显式拒绝
//!   （[`CODE_PROBE_TARGET_OUT_OF_SCOPE`]）——不可信文本（订阅内容、
//!   远端响应）无法扩展探测面；
//! - **限额诚实**：并发上限（[`ProbeLimits::max_active`]）经信号量
//!   强制——超额作业排队而非绕过；流量预算（[`ProbeLimits::byte_budget`]）
//!   在提交时预留、完成时按实耗结算，预算耗尽显式拒绝
//!   （[`CODE_PROBE_BUDGET_EXHAUSTED`]）；每作业超时由服务强制
//!   （到点置取消令牌并记 [`JOB_STATE_TIMED_OUT`]）；
//! - **取消生效**：排队作业取消即永不运行；运行中作业经
//!   [`CancelToken`] 协作取消——执行器退出后一律归类
//!   [`JOB_STATE_CANCELLED`]；
//! - **测量不造数**：结果字段全部来自执行器回报（[`ProbeOutcome`]），
//!   UDP 回显显式携带 sent/replies——丢包率由计数可算而非推断；
//!   无回应时 RTT 为 `None`，服务绝不编造测量值；
//! - **执行器可注入**：[`ProbeExecutor`] 是唯一 I/O 面——真实实现
//!   归运行时装配（RIL-061 接线），本模块只钉作业编排契约。

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Semaphore;

/// 稳定原因码：目标不在探测范围内
pub const CODE_PROBE_TARGET_OUT_OF_SCOPE: &str = "probe.target.out_of_scope";
/// 稳定原因码：流量预算耗尽
pub const CODE_PROBE_BUDGET_EXHAUSTED: &str = "probe.limit.budget";
/// 稳定原因码：作业 ID 未知（只读查询/取消的显式缺席）
pub const CODE_PROBE_JOB_UNKNOWN: &str = "probe.job.unknown";
/// 稳定原因码：探测目标类型无执行器支持（显式如实回答，不冒充测量）
pub const CODE_PROBE_UNSUPPORTED: &str = "probe.exec.unsupported";
/// 稳定原因码：执行器回报的失败
pub const CODE_PROBE_EXEC_FAILED: &str = "probe.exec.failed";

/// 作业状态：排队（未见执行器）
pub const JOB_STATE_QUEUED: &str = "queued";
/// 作业状态：运行中（执行器持有）
pub const JOB_STATE_RUNNING: &str = "running";
/// 作业状态：完成（有 [`ProbeOutcome`]）
pub const JOB_STATE_COMPLETED: &str = "completed";
/// 作业状态：服务强制超时（令牌已置位）
pub const JOB_STATE_TIMED_OUT: &str = "timed_out";
/// 作业状态：显式取消（排队取消即永不运行；运行中协作退出）
pub const JOB_STATE_CANCELLED: &str = "cancelled";
/// 作业状态：执行器失败（稳定码 + 已脱敏 detail）
pub const JOB_STATE_FAILED: &str = "failed";

/// 取消终态的稳定码（快照 fail_code）
pub const CODE_PROBE_CANCELLED: &str = "probe.cancelled";
/// 运行中作业取消请求已受理的稳定码（终态仍归 cancelled）
pub const CODE_PROBE_CANCEL_REQUESTED: &str = "probe.cancel.requested";
/// 服务强制超时的稳定码
pub const CODE_PROBE_TIMEOUT: &str = "probe.timeout";

/// 协作取消令牌：服务持有置位权，执行器只读观测
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// 置位（服务在取消/超时路径调用）
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// 是否已置位（执行器协作检查点读这里）
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// 探测目标范围：装配时显式登记的闭合集合。键全部为已类型化/
/// 已校验的值——没有从任意文本构造范围的入口（不可信文本无法
/// 扩展探测面，RIL-059 验收项）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetScope {
    hosts: BTreeSet<String>,
    addrs: BTreeSet<SocketAddr>,
    egresses: BTreeSet<String>,
}

impl TargetScope {
    /// 空范围（测试/最小装配用——任何目标都范围外）
    pub fn empty() -> Self {
        Self::default()
    }

    /// 登记可探测 DNS 目标（host 为已校验的配置值，原样入集）
    pub fn allow_host(&mut self, host: impl Into<String>) -> &mut Self {
        self.hosts.insert(host.into());
        self
    }

    /// 登记可探测地址（TCP connect / UDP 回显）
    pub fn allow_addr(&mut self, addr: SocketAddr) -> &mut Self {
        self.addrs.insert(addr);
        self
    }

    /// 登记可探测出口（代理握手经此名取连接器——名字来自配置，
    /// 不接受任意文本）
    pub fn allow_egress(&mut self, egress: impl Into<String>) -> &mut Self {
        self.egresses.insert(egress.into());
        self
    }

    /// host 是否在范围内
    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }

    /// 地址是否在范围内
    pub fn allows_addr(&self, addr: SocketAddr) -> bool {
        self.addrs.contains(&addr)
    }

    /// 出口名是否在范围内
    pub fn allows_egress(&self, egress: &str) -> bool {
        self.egresses.contains(egress)
    }
}

/// 探测目标（闭合枚举——四类作业，无自由文本变体）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeTarget {
    /// DNS 解析探测（host 必须在范围内）
    Dns { host: String },
    /// TCP connect 探测（地址必须在范围内）
    Connect { addr: SocketAddr },
    /// 代理握手探测（经已登记出口名到固定地址）
    ProxyHandshake { egress: String, addr: SocketAddr },
    /// UDP 回显探测（地址在范围内；载荷长度受
    /// [`ProbeLimits::udp_payload_max_bytes`] 约束）
    UdpEcho { addr: SocketAddr, payload_len: usize },
}

impl ProbeTarget {
    /// 作业标签（稳定机器口径——范围核对与快照显示共用）
    pub fn label(&self) -> String {
        match self {
            ProbeTarget::Dns { host } => format!("dns:{host}"),
            ProbeTarget::Connect { addr } => format!("connect:{addr}"),
            ProbeTarget::ProxyHandshake { egress, addr } => {
                format!("handshake:{egress}->{addr}")
            }
            ProbeTarget::UdpEcho { addr, payload_len } => {
                format!("udp-echo:{addr}?len={payload_len}")
            }
        }
    }

    /// 预算预留字节数（UDP 回显按载荷预留——提交即计；其余作业
    /// 预留 0，执行器回报的实耗在结算时补记）
    fn reserved_bytes(&self) -> u64 {
        match self {
            ProbeTarget::UdpEcho { payload_len, .. } => u64::from(u16::try_from(*payload_len).unwrap_or(u16::MAX)).max(1),
            _ => 0,
        }
    }
}

/// 限额配置（全部有界——探测面不无限占用资源）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeLimits {
    /// 同时运行作业上限（超额排队）
    pub max_active: usize,
    /// 单作业超时（毫秒）
    pub job_timeout_ms: u64,
    /// UDP 回显载荷上限（字节）
    pub udp_payload_max_bytes: usize,
    /// 流量预算（字节；提交预留、完成按实耗结算）
    pub byte_budget: u64,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        ProbeLimits {
            max_active: 4,
            job_timeout_ms: 5_000,
            udp_payload_max_bytes: 512,
            byte_budget: 64 * 1024,
        }
    }
}

/// 探测测量结果（字段全部来自执行器回报——无回应不造 RTT）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// DNS 解析：解析出的地址 + 实测 RTT
    Dns {
        resolved: Vec<std::net::IpAddr>,
        rtt_ms: Option<u64>,
    },
    /// TCP connect：实测建连 RTT
    Connect { rtt_ms: u64 },
    /// 代理握手：实测握手 RTT
    ProxyHandshake { rtt_ms: u64 },
    /// UDP 回显：显式 sent/replies 计数（丢包率由计数可算）；
    /// replies=0 时 RTT 为 None
    UdpEcho {
        sent: u32,
        replies: u32,
        rtt_ms: Option<u64>,
    },
}

impl ProbeOutcome {
    /// 本测量消耗的字节数（预算结算口径——UDP 回显按实发计）
    pub fn bytes_used(&self) -> u64 {
        match self {
            ProbeOutcome::UdpEcho { sent, .. } => u64::from(*sent),
            _ => 0,
        }
    }
}

/// 执行器错误（稳定码 + 已脱敏 detail——文本归
/// `Redactor::error_message` 口径，执行器自证）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeExecError {
    /// 稳定原因码（[`CODE_PROBE_UNSUPPORTED`] / [`CODE_PROBE_EXEC_FAILED`]）
    pub code: &'static str,
    /// 已脱敏说明
    pub detail: String,
}

impl ProbeExecError {
    /// 构造失败（detail 由调用方保证已脱敏）
    pub fn failed(detail: impl Into<String>) -> Self {
        ProbeExecError {
            code: CODE_PROBE_EXEC_FAILED,
            detail: detail.into(),
        }
    }

    /// 构造不支持（目标类型该执行器无法测量）
    pub fn unsupported(detail: impl Into<String>) -> Self {
        ProbeExecError {
            code: CODE_PROBE_UNSUPPORTED,
            detail: detail.into(),
        }
    }
}

/// 探测执行器：唯一 I/O 面。真实实现归运行时装配；取消经令牌
/// 协作（服务在取消/超时时置位——执行器应尽快返回）。
#[async_trait]
pub trait ProbeExecutor: Send + Sync {
    /// 执行一次探测。deadline 由服务按限额计算（到点服务置令牌并
    /// 记超时——执行器超时返回也按超时归类）。
    async fn run(
        &self,
        target: &ProbeTarget,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError>;
}

/// 作业快照（只读面——`result`/`list` 的返回形态）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSnapshot {
    /// 作业 ID（从 0 递增——服务实例内唯一）
    pub id: u64,
    /// 目标标签（[`ProbeTarget::label`]）
    pub target: String,
    /// 状态（`queued`/`running`/`completed`/`timed_out`/`cancelled`/`failed`）
    pub state: &'static str,
    /// 提交时刻（注入钟的 unix ms）
    pub submitted_unix_ms: u64,
    /// 终态时刻（注入钟；未终态为 None）
    pub finished_unix_ms: Option<u64>,
    /// 完成时的测量（其余状态为 None）
    pub outcome: Option<ProbeOutcome>,
    /// 失败/超时/取消的稳定码（完成/排队/运行为 None）
    pub fail_code: Option<&'static str>,
    /// 失败说明（已脱敏；其余状态为 None）
    pub fail_detail: Option<String>,
}

/// 提交/取消/查询错误的稳定码形态
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError {
    /// 稳定原因码
    pub code: &'static str,
    /// 已脱敏说明
    pub detail: String,
}

/// 作业内部记录（含运行编排所需的取消令牌）
struct JobRecord {
    target: ProbeTarget,
    submitted_unix_ms: u64,
    state: &'static str,
    finished_unix_ms: Option<u64>,
    outcome: Option<ProbeOutcome>,
    fail_code: Option<&'static str>,
    fail_detail: Option<String>,
    cancel: CancelToken,
}

/// 内部记录 → 只读快照
fn snapshot(id: u64, record: &JobRecord) -> JobSnapshot {
    JobSnapshot {
        id,
        target: record.target.label(),
        state: record.state,
        submitted_unix_ms: record.submitted_unix_ms,
        finished_unix_ms: record.finished_unix_ms,
        outcome: record.outcome.clone(),
        fail_code: record.fail_code,
        fail_detail: record.fail_detail.clone(),
    }
}

/// 主动探测作业服务。探测只经 [`submit`](ProbeService::submit) 发生；
/// `result`/`list` 是纯读——结构上无法隐式触发探测。
pub struct ProbeService {
    scope: TargetScope,
    limits: ProbeLimits,
    executor: Arc<dyn ProbeExecutor>,
    now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    jobs: Arc<Mutex<BTreeMap<u64, JobRecord>>>,
    order: Arc<Mutex<VecDeque<u64>>>,
    next_id: Arc<Mutex<u64>>,
    permits: Arc<Semaphore>,
    budget_remaining: Arc<Mutex<u64>>,
}

impl ProbeService {
    /// 装配：范围 + 限额 + 执行器 + 注入钟（unix ms）一次性钉死
    pub fn new(
        scope: TargetScope,
        limits: ProbeLimits,
        executor: Arc<dyn ProbeExecutor>,
        now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        let budget = limits.byte_budget;
        ProbeService {
            scope,
            limits: limits.clone(),
            executor,
            now_unix_ms,
            jobs: Arc::new(Mutex::new(BTreeMap::new())),
            order: Arc::new(Mutex::new(VecDeque::new())),
            next_id: Arc::new(Mutex::new(0)),
            permits: Arc::new(Semaphore::new(limits.max_active.max(1))),
            budget_remaining: Arc::new(Mutex::new(budget)),
        }
    }

    /// 显式提交探测作业。范围外/预算耗尽/载荷超额显式拒绝（不发
    /// 作业）；并发超额时作业排队（信号量强制——不丢弃不绕过）。
    ///
    /// 返回作业 ID；运行编排由服务内部 spawn（调用方无需 await
    /// 完成——[`result`](ProbeService::result) 轮询快照）。
    pub fn submit(&self, target: ProbeTarget) -> Result<u64, ProbeError> {
        // 范围核对逐目标类型（闭合集合——不可信文本无入口）
        let in_scope = match &target {
            ProbeTarget::Dns { host } => self.scope.allows_host(host),
            ProbeTarget::Connect { addr } => self.scope.allows_addr(*addr),
            ProbeTarget::ProxyHandshake { egress, addr } => {
                self.scope.allows_egress(egress) && self.scope.allows_addr(*addr)
            }
            ProbeTarget::UdpEcho { addr, payload_len } => {
                *payload_len <= self.limits.udp_payload_max_bytes
                    && self.scope.allows_addr(*addr)
            }
        };
        if !in_scope {
            return Err(ProbeError {
                code: CODE_PROBE_TARGET_OUT_OF_SCOPE,
                detail: format!(
                    "target {} is outside the configured probe scope",
                    target.label()
                ),
            });
        }
        // 流量预算：提交时预留，完成按实耗结算（超时/失败的作业
        // 不退还——流量可能已真实发出）
        let reserved = target.reserved_bytes();
        {
            let mut budget = self.budget_remaining.lock().expect("budget poisoned");
            if *budget < reserved {
                return Err(ProbeError {
                    code: CODE_PROBE_BUDGET_EXHAUSTED,
                    detail: format!("byte budget exhausted: need {reserved}, left {budget}"),
                });
            }
            *budget -= reserved;
        }
        let id = {
            let mut next = self.next_id.lock().expect("ids poisoned");
            let id = *next;
            *next += 1;
            id
        };
        let record = JobRecord {
            target,
            submitted_unix_ms: (self.now_unix_ms)(),
            state: JOB_STATE_QUEUED,
            finished_unix_ms: None,
            outcome: None,
            fail_code: None,
            fail_detail: None,
            cancel: CancelToken::default(),
        };
        self.jobs.lock().expect("jobs poisoned").insert(id, record);
        self.order.lock().expect("order poisoned").push_back(id);
        self.spawn_worker(id);
        Ok(id)
    }

    /// 显式取消。排队作业立即终态（永不运行）；运行中作业置令牌
    /// （执行器协作退出后归类 [`JOB_STATE_CANCELLED`]）。
    /// 未知 ID 显式回答（不静默）。
    pub fn cancel(&self, id: u64) -> Result<&'static str, ProbeError> {
        let mut jobs = self.jobs.lock().expect("jobs poisoned");
        let record = jobs.get_mut(&id).ok_or_else(|| ProbeError {
            code: CODE_PROBE_JOB_UNKNOWN,
            detail: format!("job {id} is unknown"),
        })?;
        match record.state {
            JOB_STATE_QUEUED => {
                record.state = JOB_STATE_CANCELLED;
                record.finished_unix_ms = Some((self.now_unix_ms)());
                record.fail_code = Some(CODE_PROBE_CANCELLED);
                record.cancel.cancel();
                Ok(JOB_STATE_CANCELLED)
            }
            JOB_STATE_RUNNING => {
                record.cancel.cancel();
                Ok(CODE_PROBE_CANCEL_REQUESTED)
            }
            _ => Ok(record.state),
        }
    }

    /// 只读快照（未知 ID 显式缺席——绝不创建/触发任何作业）
    pub fn result(&self, id: u64) -> Result<JobSnapshot, ProbeError> {
        let jobs = self.jobs.lock().expect("jobs poisoned");
        let record = jobs.get(&id).ok_or_else(|| ProbeError {
            code: CODE_PROBE_JOB_UNKNOWN,
            detail: format!("job {id} is unknown"),
        })?;
        Ok(snapshot(id, record))
    }

    /// 只读列表（提交顺序——纯读，不触发任何作业）
    pub fn list(&self) -> Vec<JobSnapshot> {
        let jobs = self.jobs.lock().expect("jobs poisoned");
        self.order
            .lock()
            .expect("order poisoned")
            .iter()
            .filter_map(|id| jobs.get(id).map(|record| snapshot(*id, record)))
            .collect()
    }

    /// 运行编排：排队等许可（max_active 强制点）→ 运行（服务强制
    /// 超时 + 协作取消）→ 终态归类。排队期间被取消的作业不进执行器。
    fn spawn_worker(&self, id: u64) {
        let jobs = self.jobs.clone();
        let executor = self.executor.clone();
        let permits = self.permits.clone();
        let now_unix_ms = self.now_unix_ms.clone();
        let budget = self.budget_remaining.clone();
        let timeout = Duration::from_millis(self.limits.job_timeout_ms);
        tokio::spawn(async move {
            let permit = permits.acquire().await.expect("semaphore closed");
            let (target, cancel) = {
                let mut guard = jobs.lock().expect("jobs poisoned");
                let Some(record) = guard.get_mut(&id) else {
                    drop(permit);
                    return;
                };
                if record.state == JOB_STATE_CANCELLED {
                    drop(permit);
                    return;
                }
                record.state = JOB_STATE_RUNNING;
                (record.target.clone(), record.cancel.clone())
            };
            let deadline = Instant::now() + timeout;
            let raced =
                tokio::time::timeout(timeout, executor.run(&target, deadline, &cancel)).await;
            let mut guard = jobs.lock().expect("jobs poisoned");
            let Some(record) = guard.get_mut(&id) else {
                drop(permit);
                return;
            };
            record.finished_unix_ms = Some((now_unix_ms)());
            match raced {
                // 取消后才完成的测量仍按完成记——测量本身是事实
                Ok(Ok(measure)) => {
                    record.state = JOB_STATE_COMPLETED;
                    record.outcome = Some(measure.clone());
                    // 预算结算：预留与实耗的差额退还
                    let spent = measure.bytes_used();
                    let reserved = target.reserved_bytes();
                    if spent < reserved {
                        *budget.lock().expect("budget poisoned") += reserved - spent;
                    }
                }
                Ok(Err(exec_err)) => {
                    if cancel.is_cancelled() {
                        // 协作取消：执行器在检查点退出
                        record.state = JOB_STATE_CANCELLED;
                        record.fail_code = Some(CODE_PROBE_CANCELLED);
                    } else {
                        record.state = JOB_STATE_FAILED;
                        record.fail_code = Some(exec_err.code);
                        record.fail_detail = Some(exec_err.detail);
                    }
                }
                Err(_elapsed) => {
                    record.state = JOB_STATE_TIMED_OUT;
                    record.fail_code = Some(CODE_PROBE_TIMEOUT);
                    record.fail_detail = Some(format!(
                        "job exceeded the {}ms probe timeout",
                        timeout.as_millis()
                    ));
                }
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_with_addr(addr: SocketAddr) -> TargetScope {
        let mut scope = TargetScope::empty();
        scope.allow_addr(addr);
        scope
    }

    fn limits(max_active: usize, timeout_ms: u64) -> ProbeLimits {
        ProbeLimits {
            max_active,
            job_timeout_ms: timeout_ms,
            udp_payload_max_bytes: 512,
            byte_budget: 1024,
        }
    }

    fn fixed_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
        Arc::new(|| 1_760_000_000_000)
    }

    /// 范围核对逐目标类型：未登记 host/addr/egress 显式拒绝；
    /// 范围内目标受理
    #[tokio::test]
    async fn out_of_scope_targets_are_rejected_per_kind() {
        let in_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut scope = scope_with_addr(in_addr);
        scope
            .allow_host("example.invalid")
            .allow_egress("direct");
        let service = ProbeService::new(scope, limits(2, 1_000), Arc::new(InstantExec), fixed_clock());

        let err = service
            .submit(ProbeTarget::Dns {
                host: "other.invalid".into(),
            })
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE);
        let out_addr: SocketAddr = "10.9.9.9:443".parse().unwrap();
        let err = service
            .submit(ProbeTarget::Connect { addr: out_addr })
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE);
        let err = service
            .submit(ProbeTarget::ProxyHandshake {
                egress: "hidden".into(),
                addr: in_addr,
            })
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE);
        let err = service
            .submit(ProbeTarget::UdpEcho {
                addr: in_addr,
                payload_len: 10_000,
            })
            .unwrap_err();
        assert_eq!(
            err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE,
            "载荷超额与范围外同码——都不受理"
        );

        assert!(service
            .submit(ProbeTarget::Dns {
                host: "example.invalid".into()
            })
            .is_ok());
        assert!(service.submit(ProbeTarget::Connect { addr: in_addr }).is_ok());
    }

    /// 不可信文本无法扩展范围：范围是装配时闭合集合——后缀/前缀
    /// 变体拒绝；未知作业的取消/查询显式回答
    #[tokio::test]
    async fn scope_is_closed_and_unknown_jobs_answer_explicitly() {
        let mut scope = TargetScope::empty();
        scope.allow_host("example.invalid");
        let service = ProbeService::new(scope, limits(1, 1_000), Arc::new(InstantExec), fixed_clock());
        // 订阅/远端文本常见的扩展手法逐类拒绝
        for host in [
            "example.invalid.",
            "evil-example.invalid",
            "example.invalid.evil",
            "Example.Invalid",
        ] {
            let err = service
                .submit(ProbeTarget::Dns { host: host.into() })
                .unwrap_err();
            assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE, "{host} 应范围外");
        }
        let err = service.cancel(999).unwrap_err();
        assert_eq!(err.code, CODE_PROBE_JOB_UNKNOWN);
        let err = service.result(999).unwrap_err();
        assert_eq!(err.code, CODE_PROBE_JOB_UNKNOWN);
    }

    /// 预算：提交预留、耗尽显式拒绝、完成按实耗退还差额
    #[tokio::test]
    async fn byte_budget_reserves_rejects_and_settles() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let service = ProbeService::new(
            scope_with_addr(addr),
            ProbeLimits {
                max_active: 8,
                job_timeout_ms: 1_000,
                udp_payload_max_bytes: 512,
                byte_budget: 100,
            },
            Arc::new(InstantExec),
            fixed_clock(),
        );
        let first = service
            .submit(ProbeTarget::UdpEcho {
                addr,
                payload_len: 100,
            })
            .expect("预算恰好覆盖首作业");
        let err = service
            .submit(ProbeTarget::UdpEcho {
                addr,
                payload_len: 100,
            })
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_BUDGET_EXHAUSTED, "预算已预留");
        wait_state(&service, first, JOB_STATE_COMPLETED).await;
        // InstantExec 报 sent=10：预留 100 - 实耗 10 = 90 退还 →
        // 恰好 90 可提交（载荷 100 仍拒绝——结算按实耗而非预留）
        let err = service
            .submit(ProbeTarget::UdpEcho {
                addr,
                payload_len: 100,
            })
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_BUDGET_EXHAUSTED);
        let second = service
            .submit(ProbeTarget::UdpEcho { addr, payload_len: 90 })
            .expect("结算后按实耗回收 90");
        wait_state(&service, second, JOB_STATE_COMPLETED).await;
    }

    /// 只读调用不隐式探测：result/list 不创建作业——空服务读后仍空
    #[test]
    fn read_only_surfaces_never_probe() {
        let service = ProbeService::new(
            TargetScope::empty(),
            limits(1, 1_000),
            Arc::new(InstantExec),
            fixed_clock(),
        );
        assert!(service.list().is_empty());
        let _ = service.result(0);
        assert!(service.list().is_empty(), "读后无作业被创建");
    }

    /// 立即完成的桩执行器（确定性测量——编排类测试共用）
    struct InstantExec;

    #[async_trait]
    impl ProbeExecutor for InstantExec {
        async fn run(
            &self,
            target: &ProbeTarget,
            _deadline: Instant,
            _cancel: &CancelToken,
        ) -> Result<ProbeOutcome, ProbeExecError> {
            Ok(match target {
                ProbeTarget::Dns { .. } => ProbeOutcome::Dns {
                    resolved: vec!["192.0.2.1".parse().unwrap()],
                    rtt_ms: Some(5),
                },
                ProbeTarget::Connect { .. } => ProbeOutcome::Connect { rtt_ms: 7 },
                ProbeTarget::ProxyHandshake { .. } => ProbeOutcome::ProxyHandshake { rtt_ms: 9 },
                ProbeTarget::UdpEcho { .. } => ProbeOutcome::UdpEcho {
                    sent: 10,
                    replies: 8,
                    rtt_ms: Some(3),
                },
            })
        }
    }

    /// 受控桩执行器：进执行器即计数；运行至门开或取消置位
    struct GatedExec {
        entered: AtomicBool,
        gate: AtomicBool,
    }

    impl GatedExec {
        fn new() -> Arc<Self> {
            Arc::new(GatedExec {
                entered: AtomicBool::new(false),
                gate: AtomicBool::new(false),
            })
        }

        fn open_gate(&self) {
            self.gate.store(true, Ordering::SeqCst);
        }

        fn answer_for(target: &ProbeTarget) -> ProbeOutcome {
            match target {
                ProbeTarget::Dns { .. } => ProbeOutcome::Dns {
                    resolved: vec![],
                    rtt_ms: None,
                },
                ProbeTarget::Connect { .. } => ProbeOutcome::Connect { rtt_ms: 1 },
                ProbeTarget::ProxyHandshake { .. } => ProbeOutcome::ProxyHandshake { rtt_ms: 1 },
                ProbeTarget::UdpEcho { .. } => ProbeOutcome::UdpEcho {
                    sent: 1,
                    replies: 1,
                    rtt_ms: Some(1),
                },
            }
        }
    }

    #[async_trait]
    impl ProbeExecutor for GatedExec {
        async fn run(
            &self,
            target: &ProbeTarget,
            _deadline: Instant,
            cancel: &CancelToken,
        ) -> Result<ProbeOutcome, ProbeExecError> {
            self.entered.store(true, Ordering::SeqCst);
            loop {
                // 取消优先于门开——取消请求后的执行器必经检查点退出
                if cancel.is_cancelled() {
                    return Err(ProbeExecError::failed("cancelled at checkpoint"));
                }
                if self.gate.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok(Self::answer_for(target))
        }
    }

    /// 并发限额：max_active=1 时第二作业排队不并行；首作业完成
    /// 后第二作业获得许可
    #[tokio::test]
    async fn concurrency_limit_queues_extra_jobs() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let exec = GatedExec::new();
        let service = ProbeService::new(
            scope_with_addr(addr),
            limits(1, 10_000),
            exec.clone(),
            fixed_clock(),
        );
        let first = service
            .submit(ProbeTarget::Connect { addr })
            .expect("首作业受理");
        let second = service
            .submit(ProbeTarget::Connect { addr })
            .expect("第二作业受理（排队）");
        // 首作业进入执行器、第二作业仍在排队
        wait_until(|| exec.entered.load(Ordering::SeqCst)).await;
        assert_eq!(service.result(second).unwrap().state, JOB_STATE_QUEUED);
        // 开门：两作业先后完成
        exec.open_gate();
        wait_state(&service, first, JOB_STATE_COMPLETED).await;
        wait_state(&service, second, JOB_STATE_COMPLETED).await;
        let snaps = service.list();
        assert_eq!(snaps.len(), 2);
        assert_eq!(
            snaps.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec![first, second],
            "list 保持提交顺序"
        );
    }

    /// 超时：慢执行器在服务限额内未返回 → timed_out（令牌置位、
    /// 稳定码 probe.timeout）
    #[tokio::test]
    async fn service_enforces_per_job_timeout() {
        struct SlowExec;
        #[async_trait]
        impl ProbeExecutor for SlowExec {
            async fn run(
                &self,
                _target: &ProbeTarget,
                _deadline: Instant,
                cancel: &CancelToken,
            ) -> Result<ProbeOutcome, ProbeExecError> {
                // 模拟不受执行器自律约束的慢操作：睡到令牌或
                // 整体上限——服务的 40ms 超时先于这里命中
                let mut waited = Duration::ZERO;
                while waited < Duration::from_secs(10) && !cancel.is_cancelled() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    waited += Duration::from_millis(5);
                }
                Err(ProbeExecError::failed("still running at deadline"))
            }
        }
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let service = ProbeService::new(
            scope_with_addr(addr),
            limits(2, 40),
            Arc::new(SlowExec),
            fixed_clock(),
        );
        let id = service.submit(ProbeTarget::Connect { addr }).unwrap();
        wait_state(&service, id, JOB_STATE_TIMED_OUT).await;
        let snap = service.result(id).unwrap();
        assert_eq!(snap.fail_code, Some(CODE_PROBE_TIMEOUT));
        assert!(snap.outcome.is_none(), "超时无测量——不造数");
    }

    /// 取消：运行中作业置令牌后归类 cancelled；排队作业取消即
    /// 永不运行（执行器进入计数不增）
    #[tokio::test]
    async fn cancel_is_effective_for_running_and_queued() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let exec = GatedExec::new();
        let service = ProbeService::new(
            scope_with_addr(addr),
            limits(1, 10_000),
            exec.clone(),
            fixed_clock(),
        );
        // 运行中取消
        let running = service.submit(ProbeTarget::Connect { addr }).unwrap();
        wait_until(|| exec.entered.load(Ordering::SeqCst)).await;
        assert_eq!(
            service.cancel(running).unwrap(),
            CODE_PROBE_CANCEL_REQUESTED,
            "运行中取消先受理"
        );
        // 排队取消：许可被首作业占着，第二作业必在排队
        let queued = service.submit(ProbeTarget::Connect { addr }).unwrap();
        assert_eq!(service.result(queued).unwrap().state, JOB_STATE_QUEUED);
        assert_eq!(service.cancel(queued).unwrap(), JOB_STATE_CANCELLED);
        let snap = service.result(queued).unwrap();
        assert_eq!(snap.state, JOB_STATE_CANCELLED);
        assert_eq!(snap.fail_code, Some(CODE_PROBE_CANCELLED));
        assert!(snap.finished_unix_ms.is_some(), "排队取消也有终态时刻");
        // 开门放首作业：第二作业的执行器进入计数不变（从未运行）
        exec.open_gate();
        wait_state(&service, running, JOB_STATE_CANCELLED).await;
        assert_eq!(
            service.result(running).unwrap().state,
            JOB_STATE_CANCELLED,
            "运行中协作退出后归类 cancelled"
        );
        assert_eq!(service.result(queued).unwrap().state, JOB_STATE_CANCELLED);
    }

    /// 测量不造数：UDP 回显 replies=0 时 RTT 为 None；快照携带
    /// 显式 sent/replies 计数
    #[tokio::test]
    async fn outcomes_carry_explicit_counts_without_fabrication() {
        struct SilentEcho;
        #[async_trait]
        impl ProbeExecutor for SilentEcho {
            async fn run(
                &self,
                _target: &ProbeTarget,
                _deadline: Instant,
                _cancel: &CancelToken,
            ) -> Result<ProbeOutcome, ProbeExecError> {
                Ok(ProbeOutcome::UdpEcho {
                    sent: 3,
                    replies: 0,
                    rtt_ms: None,
                })
            }
        }
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let service = ProbeService::new(
            scope_with_addr(addr),
            limits(2, 1_000),
            Arc::new(SilentEcho),
            fixed_clock(),
        );
        let id = service
            .submit(ProbeTarget::UdpEcho {
                addr,
                payload_len: 64,
            })
            .unwrap();
        wait_state(&service, id, JOB_STATE_COMPLETED).await;
        match service.result(id).unwrap().outcome {
            Some(ProbeOutcome::UdpEcho {
                sent,
                replies,
                rtt_ms,
            }) => {
                assert_eq!((sent, replies), (3, 0));
                assert_eq!(rtt_ms, None, "无回应不造 RTT");
            }
            other => panic!("应得 UDP 回显测量，得到 {other:?}"),
        }
    }

    /// 执行器失败与不支持显式归类（稳定码透传）
    #[tokio::test]
    async fn executor_failures_keep_stable_codes() {
        struct PickyExec;
        #[async_trait]
        impl ProbeExecutor for PickyExec {
            async fn run(
                &self,
                target: &ProbeTarget,
                _deadline: Instant,
                _cancel: &CancelToken,
            ) -> Result<ProbeOutcome, ProbeExecError> {
                match target {
                    ProbeTarget::ProxyHandshake { .. } => Err(ProbeExecError::unsupported(
                        "no proxy connector wired in this deployment",
                    )),
                    _ => Err(ProbeExecError::failed("refused by policy")),
                }
            }
        }
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut scope = scope_with_addr(addr);
        scope.allow_egress("direct");
        let service = ProbeService::new(scope, limits(2, 1_000), Arc::new(PickyExec), fixed_clock());
        let hs = service
            .submit(ProbeTarget::ProxyHandshake {
                egress: "direct".into(),
                addr,
            })
            .unwrap();
        wait_state(&service, hs, JOB_STATE_FAILED).await;
        assert_eq!(
            service.result(hs).unwrap().fail_code,
            Some(CODE_PROBE_UNSUPPORTED)
        );
        let conn = service.submit(ProbeTarget::Connect { addr }).unwrap();
        wait_state(&service, conn, JOB_STATE_FAILED).await;
        assert_eq!(
            service.result(conn).unwrap().fail_code,
            Some(CODE_PROBE_EXEC_FAILED)
        );
    }

    /// 轮询等待作业到达指定状态（编排是异步的——测试辅助）
    async fn wait_state(service: &ProbeService, id: u64, state: &str) {
        for _ in 0..400 {
            if service.result(id).map(|s| s.state == state).unwrap_or(false) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "作业 {id} 未到达状态 {state}: {:?}",
            service.result(id).unwrap()
        );
    }

    /// 轮询等待条件成立（测试辅助）
    async fn wait_until(cond: impl Fn() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("条件未在期限内成立");
    }
}
