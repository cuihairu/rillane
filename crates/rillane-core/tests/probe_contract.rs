//! RIL-059 探测作业服务验收（契约面，跨模块集成）：
//! - **范围闭合**：不可信文本（未登记 host/addr/egress）无入口——
//!   TargetScope 是闭合集合（无 FromStr，文本不可能扩范围），提交面
//!   逐目标类型核对，范围外显式拒绝且不产生作业；
//! - **预算**：提交预留、完成按实耗结算（差额退还）、耗尽显式拒绝
//!   且不产生作业；
//! - **并发**：max_active 是强制排队点（不丢弃不绕过）；
//! - **超时/取消**：归类 + 稳定码；排队取消永不进执行器，运行取消走
//!   协作令牌；
//! - **只读面零探测副作用**：`result`/`list` 结构上无法触发探测；
//! - **测量显式性**：快照测量逐字段等于执行器回报（无回应不造 RTT）。
//!
//! 真实网络执行器（DNS/TCP/UDP/代理握手）归 RIL-061 运行时装配——
//! 本契约全部用注入执行器（决定性，无网络依赖）。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rillane_core::{
    ProbeExecError, ProbeExecutor, ProbeLimits, ProbeOutcome, ProbeService, ProbeTarget,
    TargetScope, CODE_PROBE_BUDGET_EXHAUSTED, CODE_PROBE_CANCELLED, CODE_PROBE_CANCEL_REQUESTED,
    CODE_PROBE_EXEC_FAILED, CODE_PROBE_JOB_UNKNOWN, CODE_PROBE_TARGET_OUT_OF_SCOPE,
    CODE_PROBE_TIMEOUT, JOB_STATE_CANCELLED, JOB_STATE_COMPLETED, JOB_STATE_FAILED,
    JOB_STATE_QUEUED, JOB_STATE_RUNNING, JOB_STATE_TIMED_OUT,
};

const IN_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);

fn scope() -> TargetScope {
    let mut scope = TargetScope::empty();
    scope.allow_addr(IN_ADDR);
    scope.allow_host("example.invalid");
    scope.allow_egress("direct");
    scope
}

fn limits(max_active: usize, timeout_ms: u64, budget: u64) -> ProbeLimits {
    ProbeLimits {
        max_active,
        job_timeout_ms: timeout_ms,
        udp_payload_max_bytes: 512,
        byte_budget: budget,
    }
}

fn fixed_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| 1_760_000_000_000)
}

/// 立即返回 Connect 测量的执行器（RTT 恒 7ms）。
struct InstantExec;

#[async_trait::async_trait]
impl ProbeExecutor for InstantExec {
    async fn run(
        &self,
        _target: &ProbeTarget,
        _deadline: Instant,
        _cancel: &rillane_core::probe::CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        Ok(ProbeOutcome::Connect { rtt_ms: 7 })
    }
}

/// 计数执行器：记录进执行器次数（只读面零副作用断言用）。
struct CountingExec(Arc<AtomicU32>);

#[async_trait::async_trait]
impl ProbeExecutor for CountingExec {
    async fn run(
        &self,
        _target: &ProbeTarget,
        _deadline: Instant,
        _cancel: &rillane_core::probe::CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ProbeOutcome::Connect { rtt_ms: 1 })
    }
}

/// 门控执行器：门开返回测量；门关则循环等待（检查取消令牌——协作
/// 退出路径）。计数进执行器次数。
struct GatedExec {
    gate: Arc<AtomicBool>,
    runs: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl ProbeExecutor for GatedExec {
    async fn run(
        &self,
        _target: &ProbeTarget,
        _deadline: Instant,
        cancel: &rillane_core::probe::CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        loop {
            if cancel.is_cancelled() {
                return Err(ProbeExecError {
                    code: CODE_PROBE_CANCELLED,
                    detail: "cancelled at checkpoint".into(),
                });
            }
            if self.gate.load(Ordering::SeqCst) {
                return Ok(ProbeOutcome::Connect { rtt_ms: 1 });
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// 按 sent 回报 UdpEcho（预算结算断言用）。
struct SettlingExec {
    sent: u32,
    replies: u32,
}

#[async_trait::async_trait]
impl ProbeExecutor for SettlingExec {
    async fn run(
        &self,
        _target: &ProbeTarget,
        _deadline: Instant,
        _cancel: &rillane_core::probe::CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        Ok(ProbeOutcome::UdpEcho {
            sent: self.sent,
            replies: self.replies,
            rtt_ms: if self.replies == 0 { None } else { Some(9) },
        })
    }
}

/// 恒失败执行器（稳定码断言用）。
struct FailingExec;

#[async_trait::async_trait]
impl ProbeExecutor for FailingExec {
    async fn run(
        &self,
        _target: &ProbeTarget,
        _deadline: Instant,
        _cancel: &rillane_core::probe::CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        Err(ProbeExecError::failed("boom"))
    }
}

/// 轮询到作业进入期望状态（cap 5s——防死等）。
async fn wait_state(service: &ProbeService, id: u64, want: &str) {
    for _ in 0..500 {
        if service.result(id).map(|s| s.state == want) == Ok(true) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snap = service.result(id).expect("作业应在");
    panic!("作业 {id} 未进入 {want}（当前 {}）", snap.state);
}

// —— 范围闭合 ——

#[tokio::test]
async fn untrusted_text_cannot_extend_scope() {
    let service = ProbeService::new(
        scope(),
        limits(2, 1_000, 64_000),
        Arc::new(InstantExec),
        fixed_clock(),
    );

    // 未登记 host：显式拒绝（范围外文本无入口——TargetScope 无
    // FromStr，文本不可能扩范围；提交面是唯一核对点）
    let err = service
        .submit(ProbeTarget::Dns {
            host: "evil.example".into(),
        })
        .unwrap_err();
    assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE);
    assert!(err.detail.contains("dns:evil.example"));

    // 未登记 egress 名：显式拒绝
    let err = service
        .submit(ProbeTarget::ProxyHandshake {
            egress: "hidden".into(),
            addr: IN_ADDR,
        })
        .unwrap_err();
    assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE);

    // 拒绝不产生作业（结构上无旁路提交入口）
    assert!(service.list().is_empty());
}

#[tokio::test]
async fn udp_payload_over_limit_is_rejected_before_job_creation() {
    let service = ProbeService::new(
        scope(),
        limits(2, 1_000, 64_000),
        Arc::new(InstantExec),
        fixed_clock(),
    );
    let err = service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 513,
        })
        .unwrap_err();
    assert_eq!(err.code, CODE_PROBE_TARGET_OUT_OF_SCOPE);
    assert!(service.list().is_empty());
}

// —— 预算 ——

#[tokio::test]
async fn budget_exhaustion_rejects_without_job() {
    let service = ProbeService::new(
        scope(),
        limits(2, 1_000, 100),
        Arc::new(InstantExec),
        fixed_clock(),
    );
    service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 100,
        })
        .expect("首笔在预算内");
    // 预算被首笔预留：再要同额显式拒绝
    let err = service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 100,
        })
        .unwrap_err();
    assert_eq!(err.code, CODE_PROBE_BUDGET_EXHAUSTED);
    // 零头（need 1 > left 0）也拒绝
    let err = service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 1,
        })
        .unwrap_err();
    assert_eq!(err.code, CODE_PROBE_BUDGET_EXHAUSTED);
    // 被拒的提交没有留下任何作业
    assert_eq!(service.list().len(), 1);
}

#[tokio::test]
async fn budget_settles_by_actual_usage_on_completion() {
    // 预算 1000；提交预留 100，实耗 40 → 退还 60，可用 960。
    // 载荷上限抬高（默认 512 会先卡 960 的提交——预算项单独钉）。
    let mut cap = limits(2, 1_000, 1_000);
    cap.udp_payload_max_bytes = 2_048;
    let service = ProbeService::new(
        scope(),
        cap,
        Arc::new(SettlingExec {
            sent: 40,
            replies: 2,
        }),
        fixed_clock(),
    );
    let id = service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 100,
        })
        .unwrap();
    wait_state(&service, id, JOB_STATE_COMPLETED).await;
    // 恰好 960 可用：精确钉结算数（reserved-spent 差额已退还）
    service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 960,
        })
        .expect("结算后 960 应可用");
    // 多一个字节都拒绝
    let err = service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 1,
        })
        .unwrap_err();
    assert_eq!(err.code, CODE_PROBE_BUDGET_EXHAUSTED);
}

// —— 并发 ——

#[tokio::test]
async fn concurrency_cap_queues_instead_of_dropping() {
    let gate = Arc::new(AtomicBool::new(false));
    let runs = Arc::new(AtomicU32::new(0));
    let service = ProbeService::new(
        scope(),
        limits(1, 10_000, 64_000),
        Arc::new(GatedExec {
            gate: gate.clone(),
            runs: runs.clone(),
        }),
        fixed_clock(),
    );
    let first = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    let second = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    wait_state(&service, first, JOB_STATE_RUNNING).await;
    // max_active=1：第二个排队（不丢弃不绕过）
    assert_eq!(service.result(second).unwrap().state, JOB_STATE_QUEUED);
    gate.store(true, Ordering::SeqCst);
    wait_state(&service, first, JOB_STATE_COMPLETED).await;
    wait_state(&service, second, JOB_STATE_COMPLETED).await;
    assert_eq!(runs.load(Ordering::SeqCst), 2);
    // list 按提交序
    let ids: Vec<u64> = service.list().iter().map(|s| s.id).collect();
    assert_eq!(ids, vec![first, second]);
}

// —— 超时/取消 ——

#[tokio::test]
async fn timeout_is_classified_with_stable_code() {
    let gate = Arc::new(AtomicBool::new(false));
    let runs = Arc::new(AtomicU32::new(0));
    let service = ProbeService::new(
        scope(),
        limits(1, 60, 64_000),
        Arc::new(GatedExec { gate, runs }),
        fixed_clock(),
    );
    let id = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    wait_state(&service, id, JOB_STATE_TIMED_OUT).await;
    let snap = service.result(id).unwrap();
    assert_eq!(snap.fail_code, Some(CODE_PROBE_TIMEOUT));
    assert_eq!(snap.submitted_unix_ms, 1_760_000_000_000);
    assert!(snap.finished_unix_ms.is_some());
    assert!(snap.outcome.is_none(), "超时无测量——不造数");
}

#[tokio::test]
async fn cancel_queued_job_never_reaches_executor() {
    let gate = Arc::new(AtomicBool::new(false));
    let runs = Arc::new(AtomicU32::new(0));
    let service = ProbeService::new(
        scope(),
        limits(1, 10_000, 64_000),
        Arc::new(GatedExec {
            gate: gate.clone(),
            runs: runs.clone(),
        }),
        fixed_clock(),
    );
    let first = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    let second = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    wait_state(&service, first, JOB_STATE_RUNNING).await;
    // 排队中取消：立即终态（返回状态本身），永不进执行器
    let verdict = service.cancel(second).unwrap();
    assert_eq!(verdict, JOB_STATE_CANCELLED);
    let snap = service.result(second).unwrap();
    assert_eq!(snap.state, JOB_STATE_CANCELLED);
    assert_eq!(snap.fail_code, Some(CODE_PROBE_CANCELLED));
    assert_eq!(snap.finished_unix_ms, Some(1_760_000_000_000));
    gate.store(true, Ordering::SeqCst);
    wait_state(&service, first, JOB_STATE_COMPLETED).await;
    // 执行器只被第一个作业进过（第二个排队取消零执行）
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancel_running_sets_token_and_classifies_cancelled() {
    struct Cooperative;
    #[async_trait::async_trait]
    impl ProbeExecutor for Cooperative {
        async fn run(
            &self,
            _target: &ProbeTarget,
            _deadline: Instant,
            cancel: &rillane_core::probe::CancelToken,
        ) -> Result<ProbeOutcome, ProbeExecError> {
            // 协作检查点：令牌置位即退出
            loop {
                if cancel.is_cancelled() {
                    return Err(ProbeExecError {
                        code: CODE_PROBE_CANCELLED,
                        detail: "stopped at checkpoint".into(),
                    });
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
    let service = ProbeService::new(
        scope(),
        limits(1, 10_000, 64_000),
        Arc::new(Cooperative),
        fixed_clock(),
    );
    let id = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    wait_state(&service, id, JOB_STATE_RUNNING).await;
    // 运行中取消：置令牌，返回 cancel_requested（终态由协作退出归类）
    let verdict = service.cancel(id).unwrap();
    assert_eq!(verdict, CODE_PROBE_CANCEL_REQUESTED);
    wait_state(&service, id, JOB_STATE_CANCELLED).await;
    let snap = service.result(id).unwrap();
    assert_eq!(snap.fail_code, Some(CODE_PROBE_CANCELLED));
    assert!(snap.outcome.is_none());
}

// —— 只读面零副作用 ——

#[tokio::test]
async fn readonly_surfaces_trigger_no_probe() {
    let runs = Arc::new(AtomicU32::new(0));
    let service = ProbeService::new(
        scope(),
        limits(2, 1_000, 64_000),
        Arc::new(CountingExec(runs.clone())),
        fixed_clock(),
    );
    let id = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    wait_state(&service, id, JOB_STATE_COMPLETED).await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    // 只读查询任意多次：执行器零新增调用（结构上无法隐式探测）
    for _ in 0..10 {
        let _ = service.result(id).unwrap();
        let _ = service.list();
    }
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    // 未知 ID 显式缺席（稳定码），且不创建任何东西
    let err = service.result(999).unwrap_err();
    assert_eq!(err.code, CODE_PROBE_JOB_UNKNOWN);
    let err = service.cancel(999).unwrap_err();
    assert_eq!(err.code, CODE_PROBE_JOB_UNKNOWN);
    assert_eq!(service.list().len(), 1);
}

// —— 测量显式性 ——

#[tokio::test]
async fn measurements_are_explicit_not_fabricated() {
    // replies=0（无回应）：RTT None 原样传递——不发明数值
    let service = ProbeService::new(
        scope(),
        limits(2, 1_000, 64_000),
        Arc::new(SettlingExec {
            sent: 3,
            replies: 0,
        }),
        fixed_clock(),
    );
    let id = service
        .submit(ProbeTarget::UdpEcho {
            addr: IN_ADDR,
            payload_len: 64,
        })
        .unwrap();
    wait_state(&service, id, JOB_STATE_COMPLETED).await;
    let snap = service.result(id).unwrap();
    assert_eq!(
        snap.outcome,
        Some(ProbeOutcome::UdpEcho {
            sent: 3,
            replies: 0,
            rtt_ms: None,
        }),
        "无回应不造 RTT——测量逐字段等于执行器回报"
    );
    assert_eq!(snap.fail_code, None);
    assert_eq!(snap.fail_detail, None);
}

#[tokio::test]
async fn exec_failure_carries_stable_code_and_detail() {
    let service = ProbeService::new(
        scope(),
        limits(2, 1_000, 64_000),
        Arc::new(FailingExec),
        fixed_clock(),
    );
    let id = service
        .submit(ProbeTarget::Connect { addr: IN_ADDR })
        .unwrap();
    wait_state(&service, id, JOB_STATE_FAILED).await;
    let snap = service.result(id).unwrap();
    assert_eq!(snap.fail_code, Some(CODE_PROBE_EXEC_FAILED));
    assert_eq!(snap.fail_detail.as_deref(), Some("boom"));
    assert_eq!(snap.state, JOB_STATE_FAILED);
    assert_eq!(snap.outcome, None, "失败无测量");
}

#[tokio::test]
async fn ids_increase_monotonically_within_instance() {
    let service = ProbeService::new(
        scope(),
        limits(4, 1_000, 64_000),
        Arc::new(InstantExec),
        fixed_clock(),
    );
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(
            service
                .submit(ProbeTarget::Connect { addr: IN_ADDR })
                .unwrap(),
        );
    }
    assert_eq!(ids, vec![0, 1, 2]);
    for id in ids {
        wait_state(&service, id, JOB_STATE_COMPLETED).await;
    }
}
