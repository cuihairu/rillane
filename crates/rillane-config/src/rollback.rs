//! 可校验回滚（RIL-077）：按回执恢复候选、重验权限/能力与补偿状态。
//!
//! 回滚是**一次普通的 apply 级写操作**——走 [`crate::apply::ApplyLedger`]
//! 的同一单入口（幂等键、终态回执、版本前置检查、一次性核销全部复用），
//! 本模块只做回滚特有的三道校验与两份真相报告：
//!
//! 1. **按回执恢复候选**（`rollback.candidate.mismatch`）：调用方从
//!    RIL-019 journal 暂存/保留目录恢复候选内容，本面验证候选身份与
//!    目标回执登记的前置代际/摘要逐字一致——「按回执恢复」不是口号，
//!    是逐字段比对。
//! 2. **重验权限**（一次性核销语义天然重验）：原 apply 的凭证已被核销
//!    不可复用——回滚须**新提案**（以现役面为基）+ **新凭证**，走
//!    `ApplyLedger::execute` 完整校验链（守卫/前置检查/核销同 apply）。
//! 3. **盲覆盖防线**（验收「外部配置改变不被盲目覆盖」，`rollback.live.moved`）：
//!    现役代际 ≠ 目标回执产物代际即拒绝——apply 之后发生过任何带外变更
//!    （人工修改 / 订阅刷新 / 更晚的 apply），回滚到更早状态会把它抹掉，
//!    必须显式重定基（新提案以新现役为基）后重新决策。内容级漂移由
//!    回滚提案自身的 `base_hash` 前置检查兜底（同 apply 第二道检查）。
//!
//! **崩溃/部分失败报告明确**：回滚执行与 apply 同契约——执行器 Err /
//! OS 未全部落地 / 能力未申报一律登记**失败终态回执**（旧现役面保持
//! 有效，对账线 [`crate::apply::ApplyLedger::reconcile`] 不被脏产物
//! 污染）；进程崩溃恢复归 RIL-019 journal（publish 是提交点，未提交
//! 即不作数）——本面只承诺：ledger 里没有 Applied 回执的回滚，等于
//! 没有发生过。
//!
//! **连接真相**（验收「不能宣称回滚恢复旧连接」）：类型面钉死——
//! [`RollbackReport::connections`] 只表达「既有会话钉在回滚前代际」，
//! 不存在「已恢复连接」这一表达；迁移由排空时限决定（RIL-023
//! `DrainController::open_update`），强制断线仍只有撤销/超时回收两个
//! 动作。
//!
//! **边界**：候选内容恢复（磁盘读）、候选配置能力校验的**执行**
//! （`CapabilitySet::validate_config`）、排空计划的**执行**、OS 面
//! 补偿全部归调用方执行器与控制面（RIL-079/081 接线）——本面契约化
//! 申报与报告，不触碰 IO 与会话台账。

use crate::apply::{ApplyError, ApplyLedger, ApplyReceipt, ApplyStatus, ExecutionOutcome};
use crate::approval::ApprovalAuthority;
use crate::proposal::{ConfigProposal, ProposalStore};

/// 稳定原因码：输入标签非法（空 / 超长 / 控制字符）。
pub const CODE_ROLLBACK_INPUT_INVALID: &str = "rollback.input.invalid";
/// 稳定原因码：目标回执键在账无记录。
pub const CODE_ROLLBACK_TARGET_UNKNOWN: &str = "rollback.target.unknown";
/// 稳定原因码：目标回执不是 Applied（失败 apply 无可回滚之物）。
pub const CODE_ROLLBACK_TARGET_NOT_APPLIED: &str = "rollback.target.not_applied";
/// 稳定原因码：目标回执属于他人。
pub const CODE_ROLLBACK_TARGET_FOREIGN: &str = "rollback.target.foreign";
/// 稳定原因码：候选与回执登记的前置代际/摘要不一致——「按回执恢复」
/// 未兑现。
pub const CODE_ROLLBACK_CANDIDATE_MISMATCH: &str = "rollback.candidate.mismatch";
/// 稳定原因码：现役代际已前进（目标 apply 不再是现役尖）——回滚会盲
/// 覆盖带外变更，拒绝。
pub const CODE_ROLLBACK_LIVE_MOVED: &str = "rollback.live.moved";

/// 连接真相固定陈述（机器可比对——报告不宣称恢复任何连接）。
pub const CONNECTION_TRUTH_STATEMENT: &str =
    "回滚只恢复配置面；既有会话钉在原代际路径不断线不迁移，迁移由排空时限决定（RIL-023），本报告不宣称恢复任何连接";

/// 回滚请求（候选身份由调用方从 RIL-019 暂存/保留目录恢复后上报）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRequest {
    /// 回滚自身的幂等键（独立于原 apply 的键——回滚重试逐字同键）
    pub idempotency_key: String,
    /// 被回退 apply 的幂等键（回执寻址）
    pub target_key: String,
    /// 回滚提案 id（以现役面为基的新提案——原凭证已核销，重验走新链）
    pub proposal_id: String,
    /// 回滚凭证；None = 默认只读（`approval.required`）
    pub approval_id: Option<String>,
    /// 调用者所有者
    pub caller_owner: String,
    /// 调用方现役代际（盲覆盖防线基准）
    pub live_generation: String,
    /// 调用方现役内容摘要（回滚提案 base_hash 前置检查基准）
    pub live_hash: String,
    /// 按回执恢复的候选代际（须逐字 = 目标回执 base_generation）
    pub candidate_generation: String,
    /// 候选内容摘要（须逐字 = 目标回执 base_hash）
    pub candidate_hash: String,
    /// 排空时限（epoch 毫秒；None = 操作员未定——计划仍产出，时限留空）
    pub drain_deadline_ms: Option<u64>,
}

/// 回滚执行器成功产物：比 apply 多一项**能力申报**——执行器必须申报
/// 候选配置已过能力校验（`CapabilitySet::validate_config`），未申报
/// 一律按失败登记（不产 Applied 回执）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackExecution {
    /// 产物代际身份（= 候选代际——执行器自证）
    pub generation_id: String,
    /// OS 面补偿是否全部落地
    pub os_applied: bool,
    /// 能力申报：候选配置已过能力校验
    pub capabilities_validated: bool,
}

/// 排空补偿计划（报告面——执行归 RIL-023 DrainController，接线归控制面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainPlan {
    /// 回滚退役的代际（= 目标回执产物代际——存量会话钉在此）
    pub retired_generation: String,
    /// 回滚重接入的代际（= 候选代际——新流自此准入）
    pub readmitted_generation: String,
    /// 排空时限（epoch 毫秒；None = 操作员未定）
    pub deadline_ms: Option<u64>,
    /// 计划去向（固定说明）
    pub note: &'static str,
}

const DRAIN_PLAN_NOTE: &str =
    "本计划交 DrainController::open_update 执行——本面不触碰会话台账（RIL-023 接线归控制面）";

/// 连接真相（类型面钉死不断言恢复）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTruth {
    /// 既有会话仍钉住的代际（= 回滚前的现役代际）
    pub pinned_generation: String,
    /// 真相陈述（固定文案 [`CONNECTION_TRUTH_STATEMENT`]）
    pub statement: &'static str,
}

/// 回滚报告：终态回执 + 排空补偿计划 + 连接真相（三份都如实，不冒充）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    /// 回滚自身的终态回执（在 ledger 在册——对账链完整可见；重试逐字
    /// 同键同身份领同一回执）
    pub receipt: ApplyReceipt,
    /// 排空补偿计划（Applied 时在场；失败回执无补偿计划）
    pub drain: Option<DrainPlan>,
    /// 连接真相（只在 Applied 时在场——失败回滚没有「连接真相」可讲，
    /// 现役面未变）
    pub connections: Option<ConnectionTruth>,
}

/// 回滚错误（文案可演进，`code()` 恒定；apply 链错误原码透传）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RollbackError {
    /// 输入标签非法
    #[error("{CODE_ROLLBACK_INPUT_INVALID}: 输入字段非法: {field}")]
    InputInvalid {
        /// 人读字段名（稳定字面量）
        field: &'static str,
    },
    /// 目标回执不存在
    #[error("{CODE_ROLLBACK_TARGET_UNKNOWN}: 目标回执键在账无记录——回滚按回执寻址，不猜")]
    TargetUnknown,
    /// 目标回执非 Applied
    #[error("{CODE_ROLLBACK_TARGET_NOT_APPLIED}: 目标回执不是 Applied（失败 apply 无可回滚之物）")]
    TargetNotApplied,
    /// 目标回执属于他人
    #[error("{CODE_ROLLBACK_TARGET_FOREIGN}: 目标回执所有者与调用者不符")]
    TargetForeign,
    /// 候选与回执前置身份不一致
    #[error("{CODE_ROLLBACK_CANDIDATE_MISMATCH}: 候选代际/摘要与目标回执登记的前置身份不一致——按回执恢复未兑现")]
    CandidateMismatch,
    /// 现役已前进（盲覆盖防线）
    #[error("{CODE_ROLLBACK_LIVE_MOVED}: 现役代际已前进——目标 apply 不再是现役尖，回滚将盲覆盖带外变更，须显式重定基")]
    LiveMoved,
    /// apply 链错误（input / required / 幂等 / capacity / proposal.* /
    /// approval.* / base.conflict / execute.failed 原码透传）
    #[error(transparent)]
    Apply(#[from] ApplyError),
}

impl RollbackError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            RollbackError::InputInvalid { .. } => CODE_ROLLBACK_INPUT_INVALID,
            RollbackError::TargetUnknown => CODE_ROLLBACK_TARGET_UNKNOWN,
            RollbackError::TargetNotApplied => CODE_ROLLBACK_TARGET_NOT_APPLIED,
            RollbackError::TargetForeign => CODE_ROLLBACK_TARGET_FOREIGN,
            RollbackError::CandidateMismatch => CODE_ROLLBACK_CANDIDATE_MISMATCH,
            RollbackError::LiveMoved => CODE_ROLLBACK_LIVE_MOVED,
            RollbackError::Apply(err) => err.code(),
        }
    }
}

/// 单入口可校验回滚（顺序契约）：输入面 → 目标回执裁决（unknown →
/// not_applied → foreign）→ 盲覆盖防线 → 候选身份比对 → 委托
/// [`crate::apply::ApplyLedger::execute`]（守卫 / 前置检查 / 核销 /
/// 执行 / 终态回执全复用）→ 报告装配。执行器成败皆终态；重试逐字同
/// 键同身份领同一回执（`Replayed` 分支同样装配完整报告）。
pub fn rollback_apply<F>(
    ledger: &mut ApplyLedger,
    proposals: &mut ProposalStore,
    approvals: &mut ApprovalAuthority,
    request: RollbackRequest,
    now_ms: u64,
    executor: F,
) -> Result<RollbackReport, RollbackError>
where
    F: FnOnce(&ConfigProposal) -> Result<RollbackExecution, String>,
{
    // —— 1 输入面 ——
    validate_label(&request.idempotency_key).map_err(|_| RollbackError::InputInvalid {
        field: "idempotency_key",
    })?;
    validate_label(&request.target_key).map_err(|_| RollbackError::InputInvalid {
        field: "target_key",
    })?;
    validate_label(&request.proposal_id).map_err(|_| RollbackError::InputInvalid {
        field: "proposal_id",
    })?;
    validate_label(&request.caller_owner).map_err(|_| RollbackError::InputInvalid {
        field: "caller_owner",
    })?;
    validate_label(&request.live_generation).map_err(|_| RollbackError::InputInvalid {
        field: "live_generation",
    })?;
    validate_label(&request.live_hash)
        .map_err(|_| RollbackError::InputInvalid { field: "live_hash" })?;
    validate_label(&request.candidate_generation).map_err(|_| RollbackError::InputInvalid {
        field: "candidate_generation",
    })?;
    validate_label(&request.candidate_hash).map_err(|_| RollbackError::InputInvalid {
        field: "candidate_hash",
    })?;

    // —— 2 目标回执裁决（unknown → not_applied → foreign）——
    let target = ledger
        .receipt(&request.target_key)
        .ok_or(RollbackError::TargetUnknown)?;
    if target.status != ApplyStatus::Applied {
        return Err(RollbackError::TargetNotApplied);
    }
    if target.owner != request.caller_owner {
        return Err(RollbackError::TargetForeign);
    }
    let target_generation = target.generation.clone().unwrap_or_default();

    // —— 3 盲覆盖防线（验收「外部配置改变不被盲目覆盖」）——
    if request.live_generation != target_generation {
        return Err(RollbackError::LiveMoved);
    }

    // —— 4 候选身份比对（验收「按回执恢复」）——
    if request.candidate_generation != target.base_generation
        || request.candidate_hash != target.base_hash
    {
        return Err(RollbackError::CandidateMismatch);
    }

    // —— 5 委托 apply 单入口（守卫 / 前置检查 / 核销 / 执行 / 终态回执
    //    全复用；能力未申报按失败登记，不产 Applied 回执）——
    let apply_request = crate::apply::ApplyRequest {
        idempotency_key: request.idempotency_key.clone(),
        proposal_id: request.proposal_id.clone(),
        approval_id: request.approval_id.clone(),
        caller_owner: request.caller_owner.clone(),
        live_generation: request.live_generation.clone(),
        live_hash: request.live_hash.clone(),
    };
    let result = ledger
        .execute(
            proposals,
            approvals,
            apply_request,
            now_ms,
            |proposal| match executor(proposal) {
                Ok(execution) => {
                    if !execution.capabilities_validated {
                        Err(
                            "执行器未申报候选配置能力重验（capabilities_validated=false）"
                                .to_string(),
                        )
                    } else {
                        Ok(ExecutionOutcome {
                            generation_id: execution.generation_id,
                            os_applied: execution.os_applied,
                        })
                    }
                }
                Err(reason) => Err(reason),
            },
        )
        .map_err(RollbackError::Apply)?;

    // —— 6 报告装配（Replayed 分支同样完整——重试领同一份真相）——
    let receipt = match &result {
        crate::apply::ApplyResult::Executed(receipt) => receipt.clone(),
        crate::apply::ApplyResult::Replayed(receipt) => receipt.clone(),
    };
    if receipt.status == ApplyStatus::Applied {
        Ok(RollbackReport {
            receipt,
            drain: Some(DrainPlan {
                retired_generation: target_generation.clone(),
                readmitted_generation: request.candidate_generation,
                deadline_ms: request.drain_deadline_ms,
                note: DRAIN_PLAN_NOTE,
            }),
            connections: Some(ConnectionTruth {
                pinned_generation: target_generation,
                statement: CONNECTION_TRUTH_STATEMENT,
            }),
        })
    } else {
        Ok(RollbackReport {
            receipt,
            drain: None,
            connections: None,
        })
    }
}

/// 标签纪律（与 apply / proposal / approval 面同款）。
fn validate_label(field: &str) -> Result<(), &'static str> {
    if field.is_empty() || field.chars().count() > crate::apply::APPLY_LABEL_MAX_CHARS {
        return Err(CODE_ROLLBACK_INPUT_INVALID);
    }
    if field.chars().any(char::is_control) {
        return Err(CODE_ROLLBACK_INPUT_INVALID);
    }
    Ok(())
}

#[cfg(test)]
mod rollback_tests {
    use super::*;
    use crate::apply::{ApplyRequest, ApplyResult, APPLY_LABEL_MAX_CHARS};
    use crate::approval::ProposalApproval;
    use crate::proposal::{new_proposal_id, ProposalInput};

    const OWNER: &str = "cli:local";
    const GEN_A: &str = "gen-a";
    const GEN_B: &str = "gen-b";
    const HASH_A: &str = "hash-a";
    const HASH_B: &str = "hash-b";

    fn input_on(gen: &str, hash: &str) -> ProposalInput {
        ProposalInput {
            base_generation: gen.to_string(),
            base_hash: hash.to_string(),
            owner: OWNER.to_string(),
            scope: vec!["routing".to_string()],
            patch: serde_json::json!({"routing": {"default_node": "proxy"}}),
            ttl_ms: 600_000,
        }
    }

    /// 在 gen-A 现役上登记提案并 apply 到 gen-B，返回（原回执键）。
    fn seed_apply(
        ledger: &mut ApplyLedger,
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
        key: &str,
    ) -> String {
        let p = proposals
            .create(new_proposal_id(), input_on(GEN_A, HASH_A), 0)
            .expect("登记提案");
        let a: ProposalApproval = approvals.approve(&p, None, 0, 600_000).expect("批准");
        let req = ApplyRequest {
            idempotency_key: key.to_string(),
            proposal_id: p.id,
            approval_id: Some(a.approval_id),
            caller_owner: OWNER.to_string(),
            live_generation: GEN_A.to_string(),
            live_hash: HASH_A.to_string(),
        };
        match ledger
            .execute(proposals, approvals, req, 1, |_| {
                Ok(ExecutionOutcome {
                    generation_id: GEN_B.to_string(),
                    os_applied: true,
                })
            })
            .expect("原 apply 成功")
        {
            ApplyResult::Executed(_) => key.to_string(),
            _ => panic!("应是 Executed"),
        }
    }

    /// 回滚请求底座：候选 = gen-A（原 apply 回执的前置身份）。
    fn rollback_request(
        key: &str,
        target_key: &str,
        proposal_id: &str,
        approval_id: &str,
    ) -> RollbackRequest {
        RollbackRequest {
            idempotency_key: key.to_string(),
            target_key: target_key.to_string(),
            proposal_id: proposal_id.to_string(),
            approval_id: Some(approval_id.to_string()),
            caller_owner: OWNER.to_string(),
            live_generation: GEN_B.to_string(),
            live_hash: HASH_B.to_string(),
            candidate_generation: GEN_A.to_string(),
            candidate_hash: HASH_A.to_string(),
            drain_deadline_ms: Some(5_000),
        }
    }

    /// 登记回滚提案（以现役 gen-B 为基）并批准，返回（提案 id，凭证 id）。
    fn seed_rollback_grant(
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
    ) -> (String, String) {
        let p = proposals
            .create(new_proposal_id(), input_on(GEN_B, HASH_B), 1)
            .expect("登记回滚提案");
        let a = approvals.approve(&p, None, 1, 600_000).expect("批准回滚");
        (p.id, a.approval_id)
    }

    fn ok_executor() -> impl FnOnce(&ConfigProposal) -> Result<RollbackExecution, String> {
        |_| {
            Ok(RollbackExecution {
                generation_id: GEN_A.to_string(),
                os_applied: true,
                capabilities_validated: true,
            })
        }
    }

    /// 全链路：apply → 回滚 → 回执链与报告三份真相逐项核对。
    #[test]
    fn full_roundtrip_restores_from_receipt() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        let report = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb", &target_key, &pid, &aid),
            2,
            ok_executor(),
        )
        .expect("回滚成功");

        // 回执：终态 Applied，产物代际 = 候选（恢复面如实）
        assert_eq!(report.receipt.status, ApplyStatus::Applied);
        assert_eq!(report.receipt.generation_or_empty(), GEN_A);
        assert!(report.receipt.os_applied);

        // 排空补偿计划：退役 gen-B（回滚前现役）、重接入 gen-A（候选）
        let drain = report.drain.as_ref().expect("Applied 应有排空计划");
        assert_eq!(drain.retired_generation, GEN_B);
        assert_eq!(drain.readmitted_generation, GEN_A);
        assert_eq!(drain.deadline_ms, Some(5_000));
        assert_eq!(drain.note, "本计划交 DrainController::open_update 执行——本面不触碰会话台账（RIL-023 接线归控制面）");

        // 连接真相：钉在 gen-B（回滚前现役），陈述为固定文案
        let truth = report.connections.as_ref().expect("Applied 应有连接真相");
        assert_eq!(truth.pinned_generation, GEN_B);
        assert_eq!(truth.statement, CONNECTION_TRUTH_STATEMENT);

        // 对账链：回滚进同一账本——现役 gen-A 即闭合
        let reconcile = ledger.reconcile(GEN_A);
        assert!(reconcile.agrees);
        assert_eq!(reconcile.applied_count, 2, "原 apply + 回滚两笔在账");
    }

    /// 验收「外部配置改变不被盲目覆盖」：现役前进后回滚显式拒绝，
    /// 执行器不触达、回执账不变——重定基（新提案以新现役为基）后可再决策。
    #[test]
    fn external_change_blocks_blind_overwrite() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        // 带外变更：现役 gen-B → gen-C（人工修改 / 订阅刷新 / 更晚 apply）
        let mut req = rollback_request("k-rb", &target_key, &pid, &aid);
        req.live_generation = "gen-c".to_string();
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req,
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_LIVE_MOVED);
        assert_eq!(ledger.len(), 1, "被拒不登记回滚回执");

        // 重定基：以新现役 gen-C 为基的新提案走常规 apply（不在回滚面）——
        // 回滚到 gen-A 的旧愿望被显式打断，带外变更不被抹掉
        assert_eq!(
            ledger.receipt(&target_key).map(|r| r.generation_or_empty()),
            Some(GEN_B)
        );
    }

    /// 验收「按回执恢复候选」：候选代际/摘要与回执前置身份逐字比对，
    /// 任一不一致即 `rollback.candidate.mismatch`。
    #[test]
    fn candidate_must_match_receipt_base() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        // 候选代际不一致（冒充恢复）
        let mut req = rollback_request("k-rb", &target_key, &pid, &aid);
        req.candidate_generation = "gen-x".to_string();
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req,
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_CANDIDATE_MISMATCH);

        // 候选摘要不一致
        let mut req = rollback_request("k-rb", &target_key, &pid, &aid);
        req.candidate_hash = "hash-x".to_string();
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req,
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_CANDIDATE_MISMATCH);
        assert_eq!(ledger.len(), 1);
    }

    /// 目标回执裁决：unknown → not_applied → foreign；被拒不触执行器。
    #[test]
    fn target_resolution_guards() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        // 未知目标
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb", "k-missing", &pid, &aid),
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_TARGET_UNKNOWN);

        // 失败 apply 无可回滚之物
        let fp = proposals
            .create(new_proposal_id(), input_on(GEN_A, HASH_A), 1)
            .expect("登记失败提案");
        let fa = approvals.approve(&fp, None, 1, 600_000).expect("批准");
        ledger
            .execute(
                &mut proposals,
                &mut approvals,
                ApplyRequest {
                    idempotency_key: "k-fail".to_string(),
                    proposal_id: fp.id,
                    approval_id: Some(fa.approval_id),
                    caller_owner: OWNER.to_string(),
                    live_generation: GEN_A.to_string(),
                    live_hash: HASH_A.to_string(),
                },
                1,
                |_| Err("失败".to_string()),
            )
            .expect("失败也登记回执");
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb", "k-fail", &pid, &aid),
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_TARGET_NOT_APPLIED);

        // 他人目标
        let mut req = rollback_request("k-rb", &target_key, &pid, &aid);
        req.caller_owner = "cli:other".to_string();
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req,
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_TARGET_FOREIGN);
    }

    /// 重验权限：原 apply 凭证绑定原提案（对回滚提案摘要失配 stale）；
    /// None 凭证 approval.required——回滚须新提案 + 新凭证。
    #[test]
    fn reverify_requires_fresh_authorization() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");

        // 找回原 apply 的凭证 id——出示它对回滚提案：摘要先失配（stale，
        // 凭证绑定原提案）——旧凭证对回滚链路不可用即重验通过的反面
        let original = ledger.receipt(&target_key).expect("原回执在场").clone();
        let (pid, _aid) = seed_rollback_grant(&mut proposals, &mut approvals);
        let mut req = rollback_request("k-rb", &target_key, &pid, &original.approval_id);
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req.clone(),
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(
            err.code(),
            "approval.stale",
            "原凭证绑定原提案，对回滚提案摘要失配"
        );

        // None 凭证
        req.approval_id = None;
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req,
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.required");
        assert_eq!(ledger.len(), 1, "被拒不登记回滚回执");
    }

    /// 验收「崩溃/部分失败报告明确」：执行器失败 / OS 未全部落地 /
    /// 能力未申报一律失败终态——旧现役面保持有效，报告无补偿计划、
    /// 无连接真相（没有可宣称的恢复）；重试领同一失败回执不重放。
    #[test]
    fn partial_failures_report_clearly_and_replay() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");

        // 执行器失败
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);
        let mut calls = 0usize;
        let report = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb-fail", &target_key, &pid, &aid),
            2,
            |p| {
                calls += 1;
                let _ = p;
                Err("OS 路由补偿被拒".to_string())
            },
        )
        .expect("失败也返回报告");
        assert_eq!(report.receipt.status, ApplyStatus::Failed);
        assert_eq!(report.receipt.status.code(), "apply.execute.failed");
        assert_eq!(
            report.receipt.failure_reason.as_deref(),
            Some("OS 路由补偿被拒")
        );
        assert!(report.drain.is_none(), "失败无补偿计划");
        assert!(report.connections.is_none(), "失败无连接真相——现役未变");
        assert!(ledger.reconcile(GEN_B).agrees, "现役仍在 gen-B");
        assert_eq!(calls, 1);

        // 重试：同键同身份领同一失败回执，不重放（凭证已核销也照常领）
        let replay = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb-fail", &target_key, &pid, &aid),
            3,
            ok_executor(),
        )
        .expect("重试领失败报告");
        assert_eq!(replay.receipt.status, ApplyStatus::Failed);
        assert_eq!(replay.receipt.executed_ms, 2, "回执保持首次终态时刻");
        assert!(replay.drain.is_none() && replay.connections.is_none());
        assert_eq!(calls, 1, "失败回滚重试不重放执行器");
    }

    /// 能力申报契约：未申报能力重验的执行器产物按失败登记（不产
    /// Applied 回执——不冒充已校验）。
    #[test]
    fn capability_unattested_refuses_applied() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        let report = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb-nocap", &target_key, &pid, &aid),
            2,
            |_| {
                Ok(RollbackExecution {
                    generation_id: GEN_A.to_string(),
                    os_applied: true,
                    capabilities_validated: false,
                })
            },
        )
        .expect("返回报告");
        assert_eq!(report.receipt.status, ApplyStatus::Failed);
        assert!(
            report
                .receipt
                .failure_reason
                .as_deref()
                .unwrap_or_default()
                .contains("能力重验"),
            "失败理由点名能力申报"
        );
        assert!(report.receipt.generation.is_none(), "未校验产物不得入账");
        assert!(report.connections.is_none());
    }

    /// 回滚幂等重试与回滚的回滚：同键同身份领同一报告；回滚回执自身
    /// 可作为目标再回滚（对账链完整）。
    #[test]
    fn rollback_replay_and_rollback_of_rollback() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let target_key = seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        let first = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            rollback_request("k-rb", &target_key, &pid, &aid),
            2,
            ok_executor(),
        )
        .expect("首次回滚");

        // 重试：同键同身份——提案虽过期/取消也领同一报告
        proposals.cancel(&pid, OWNER, 3).expect("取消回滚提案");
        let mut retry_req = rollback_request("k-rb", &target_key, &pid, &aid);
        retry_req.live_hash = HASH_B.to_string();
        let replay = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            retry_req,
            4,
            ok_executor(),
        )
        .expect("重试领报告");
        assert_eq!(replay, first, "重试报告逐字段同");
        assert_eq!(ledger.len(), 2);

        // 回滚的回滚：以回滚回执为目标（gen-A 现役 → 回到 gen-B）
        let (pid2, aid2) = seed_rollback_grant_on(&mut proposals, &mut approvals, GEN_A, HASH_A);
        let mut back_req = rollback_request("k-rb2", "k-rb", &pid2, &aid2);
        back_req.live_generation = GEN_A.to_string();
        back_req.live_hash = HASH_A.to_string();
        back_req.candidate_generation = GEN_B.to_string();
        back_req.candidate_hash = HASH_B.to_string();
        let back = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            back_req,
            5,
            |_| {
                Ok(RollbackExecution {
                    generation_id: GEN_B.to_string(),
                    os_applied: true,
                    capabilities_validated: true,
                })
            },
        )
        .expect("回滚的回滚");
        assert_eq!(back.receipt.generation_or_empty(), GEN_B);
        let truth = back.connections.as_ref().expect("连接真相");
        assert_eq!(truth.pinned_generation, GEN_A, "既有会话钉在回滚前现役");
        assert!(ledger.reconcile(GEN_B).agrees);
    }

    /// 输入面与顺序：输入非法先行（先于目标裁决）；目标/候选字段同样
    /// 受标签纪律约束。
    #[test]
    fn input_validation_precedes_target_resolution() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        seed_apply(&mut ledger, &mut proposals, &mut approvals, "k-orig");
        let (pid, aid) = seed_rollback_grant(&mut proposals, &mut approvals);

        // 空键（即使目标也未知——输入先行）
        let mut req = rollback_request("", "k-missing", &pid, &aid);
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req.clone(),
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_INPUT_INVALID);

        // 候选代际控制字符 / 超长
        req.idempotency_key = "k-rb".to_string();
        req.candidate_generation = "bad\u{7}gen".to_string();
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req.clone(),
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_INPUT_INVALID);
        req.candidate_generation = "g".repeat(APPLY_LABEL_MAX_CHARS + 1);
        let err = rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            req,
            2,
            ok_executor(),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_ROLLBACK_INPUT_INVALID);
        assert_eq!(ledger.len(), 1, "被拒不登记");
    }

    /// 在指定现役面上登记回滚提案并批准（回滚的回滚用）。
    fn seed_rollback_grant_on(
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
        gen: &str,
        hash: &str,
    ) -> (String, String) {
        let p = proposals
            .create(new_proposal_id(), input_on(gen, hash), 2)
            .expect("登记提案");
        let a = approvals.approve(&p, None, 2, 600_000).expect("批准");
        (p.id, a.approval_id)
    }
}
