//! 配置应用账本（RIL-076）：并发与幂等 Apply 纯面——版本前置检查、
//! 幂等键、`ApplyReceipt`。
//!
//! 三条验收的结构化对应：
//!
//! 1. **人工修改后旧提案返回冲突**——版本前置检查：apply 以调用方上报
//!    的 `live_generation` + `live_hash` 与提案登记的 `base_generation` /
//!    `base_hash` 逐项比对。人工带外写入必然移动 live 面：代际已前进
//!    答 `apply.base.conflict`（订阅刷新 / 另一笔 apply 顶替）；同代际
//!    内容漂移（原位手改）答 `apply.hash.conflict`。冲突后旧提案不自动
//!    重定基——须重新提案（新提案以新 live 面为基）再走批准。
//! 2. **客户端超时重试只执行一次**——幂等键账本：键首次触达执行器的
//!    **结果（含失败）**登记为 `ApplyReceipt`；同键同身份（owner +
//!    proposal_id + approval_id 三元全同）的重试不再触达执行器，原样
//!    返回已登记回执（[`ApplyResult::Replayed`]）。同键换身份 = 键被
//!    挪用，显式 `apply.key.mismatch`——想再执行须换新键（新键走完整
//!    校验链）。回执查询先于一切状态面：提案此后被取消 / 过期 / 清扫
//!    都不影响重试领回执。
//! 3. **磁盘 / OS / 代际状态可对账**——回执链对账 [`ApplyLedger::reconcile`]
//!    ：回执链最近一次 Applied 的产物代际与调用方现役代际比对，一致
//!    即 `agrees`；分歧显式报告两侧值。磁盘目录 / journal 面的对账归
//!    RIL-019 `PublishCoordinator::reconcile()`，控制面把两面接起来
//!    归 RIL-079/081——本模块契约化「执行产物 = 现役」这条对账线。
//!
//! **单入口 [`ApplyLedger::execute`] 顺序契约**：`apply.input.invalid`
//! → `approval.required`（None 凭证——码常量冻结在 approval 模块）→
//! 幂等键裁决（Replayed / `apply.key.mismatch`）→ `apply.capacity`
//! （满员不烧凭证）→ 提案守卫（`proposal.unknown/foreign/expired`
//! 原码透传）→ 版本前置检查（`apply.base.conflict` / `apply.hash.conflict`）
//! → 凭证核销（`approval.*` 原码透传；核销在前——防检查与执行之间
//! 被并发出示同一凭证二次通过；校验失败不核销）→ 执行器（成败皆登记
//! 为终态回执；执行器故障产物标签非法同样按失败登记）。
//!
//! **边界**：执行器由调用方注入（本层零 IO 零线程——OS 面 / 磁盘面
//! / runtime 面的落地归执行器实现侧）；执行失败是终态——幂等键登记
//! 失败回执，重试不得重放半途 OS 操作，修复后须换新键并重新批准
//! （失败路径凭证已核销）。错误正文与失败理由不得携带敏感值——调用
//! 方纪律（预览面已按此纪律脱敏，本模块只登记不加工）。

use std::collections::HashMap;

use crate::approval::{ApprovalAuthority, ApprovalError, CODE_APPROVAL_REQUIRED};
use crate::proposal::{ConfigProposal, ProposalStore};

/// 稳定原因码：幂等键 / 标签输入非法（空、超长、控制字符）。
pub const CODE_APPLY_INPUT_INVALID: &str = "apply.input.invalid";
/// 稳定原因码：幂等键已被**不同身份**使用——键挪用显式拒绝。
pub const CODE_APPLY_KEY_MISMATCH: &str = "apply.key.mismatch";
/// 稳定原因码：回执账已满（[`APPLY_RECEIPT_CAP`]）且未清扫——不逐出
/// 既有回执（逐出即重放防线破洞）。
pub const CODE_APPLY_CAPACITY: &str = "apply.capacity";
/// 稳定原因码：代际前置检查失配——live 代际已前进（人工修改 / 订阅
/// 刷新 / 另一笔 apply），旧提案基于旧代际，冲突。
pub const CODE_APPLY_BASE_CONFLICT: &str = "apply.base.conflict";
/// 稳定原因码：内容前置检查失配——同代际内容漂移（原位手改）。
pub const CODE_APPLY_HASH_CONFLICT: &str = "apply.hash.conflict";
/// 稳定原因码：执行器失败（OS / 磁盘 / runtime 落地失败或产物标签
/// 非法）——旧 live 面保持有效，失败已登记为终态回执。
pub const CODE_APPLY_EXECUTE_FAILED: &str = "apply.execute.failed";

/// 回执账硬上限：满员显式拒绝新 apply，重试（同键）不受影响。
pub const APPLY_RECEIPT_CAP: usize = 64;
/// 幂等键 / 标签字段字符上限（与 proposal / approval 面同纪律）。
pub const APPLY_LABEL_MAX_CHARS: usize = 128;

/// 执行器成功产物（OS / 代际两个对账面的最小回执原料）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    /// 执行产物代际身份（执行器自证——账本回执尾据此与现役对账）
    pub generation_id: String,
    /// OS 面副作用是否全部落地（路由 / 设备 / DNS 监听等——预览面
    /// 提示的 side_effects 在此兑现；false = 部分落地，按失败登记）
    pub os_applied: bool,
}

/// 应用终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStatus {
    /// 已应用（执行器成功且产物标签合法）
    Applied,
    /// 已失败（执行器 Err / 产物标签非法）——终态，重试不得重放
    Failed,
}

impl ApplyStatus {
    /// 稳定状态码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            ApplyStatus::Applied => "apply.applied",
            ApplyStatus::Failed => CODE_APPLY_EXECUTE_FAILED,
        }
    }
}

/// 一次 apply 的终态回执（幂等键唯一绑定；成败皆登记）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReceipt {
    /// 账内单调序号（对账排序用——HashMap 无序，回执链按 seq 定「最近」）
    pub seq: u64,
    /// 幂等键（客户端供；重试须逐字同键）
    pub idempotency_key: String,
    /// 发起者（与提案所有者同校验）
    pub owner: String,
    /// 应用目标提案
    pub proposal_id: String,
    /// 核销的授权凭证（三元身份之一）
    pub approval_id: String,
    /// 提案登记的前置代际（冲突对账面）
    pub base_generation: String,
    /// 提案登记的前置内容摘要
    pub base_hash: String,
    /// 终态
    pub status: ApplyStatus,
    /// 产物代际（Applied 时在场）
    pub generation: Option<String>,
    /// OS 面是否全部落地（Applied 时为执行器上报值；Failed 时 false）
    pub os_applied: bool,
    /// 失败理由（Failed 时在场；不含敏感值——调用方纪律）
    pub failure_reason: Option<String>,
    /// 终态登记时刻（epoch 毫秒，调用方供钟）
    pub executed_ms: u64,
}

impl ApplyReceipt {
    /// 产物代际或空串（对账面便捷读法——Failed 无产物）
    pub fn generation_or_empty(&self) -> &str {
        self.generation.as_deref().unwrap_or_default()
    }
}

/// execute 的一回合结果：区分「本次触达执行器」与「幂等重试领回执」
/// ——回执内容全同，`Replayed` 保证执行器未再触达。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// 本次执行（成败皆此——见回执 status）
    Executed(ApplyReceipt),
    /// 幂等重试：同键同身份命中已登记回执，执行器未触达
    Replayed(ApplyReceipt),
}

/// apply 请求（调用方上报 live 面——账本不持有 IO，无从自证现役，
/// 上报即责任签收；对账面 [`ApplyLedger::reconcile`] 检验上报一致性）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyRequest {
    /// 幂等键（重试须逐字同键；换身份同键 = 挪用）
    pub idempotency_key: String,
    /// 目标提案 id
    pub proposal_id: String,
    /// 授权凭证 id；None = 默认只读，写路径直接拒绝（`approval.required`）
    pub approval_id: Option<String>,
    /// 调用者所有者（与提案所有者同校验）
    pub caller_owner: String,
    /// 调用方现役代际身份（版本前置检查基准）
    pub live_generation: String,
    /// 调用方现役内容摘要（人工修改检测基准）
    pub live_hash: String,
}

/// 应用账本错误（文案可演进，`code()` 恒定）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// 幂等键 / 标签非法
    #[error("{CODE_APPLY_INPUT_INVALID}: 输入字段非法: {field}")]
    InputInvalid {
        /// 人读字段名（稳定字面量）
        field: &'static str,
    },
    /// 未出示凭证（默认只读——码常量冻结在 approval 模块）
    #[error("{CODE_APPROVAL_REQUIRED}: 写操作需要授权凭证——默认只读，无凭证即无写权限")]
    Required,
    /// 幂等键被不同身份使用
    #[error("{CODE_APPLY_KEY_MISMATCH}: 幂等键已绑定其他身份（owner/proposal/approval 任一不同）")]
    KeyMismatch,
    /// 回执账已满
    #[error("{CODE_APPLY_CAPACITY}: 应用回执账已满且未清扫——重试不受影响，新 apply 须先 prune")]
    Capacity,
    /// 提案守卫拒绝（proposal.* 原码透传）
    #[error("提案守卫拒绝: {0}")]
    Proposal(&'static str),
    /// 代际前置检查失配
    #[error("{CODE_APPLY_BASE_CONFLICT}: 现役代际已前进——旧提案基于旧代际，须重新提案（人工修改即触发此冲突）")]
    BaseConflict,
    /// 内容前置检查失配
    #[error(
        "{CODE_APPLY_HASH_CONFLICT}: 同代际内容已漂移（原位人工修改）——旧提案失效，须重新提案"
    )]
    HashConflict,
    /// 凭证校验 / 核销失败（approval.* 原码透传）
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    /// 执行器失败
    #[error("{CODE_APPLY_EXECUTE_FAILED}: 执行器失败（旧现役面保持有效）: {reason}")]
    ExecutionFailed {
        /// 人读理由（不含敏感值——调用方纪律）
        reason: String,
    },
}

impl ApplyError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            ApplyError::InputInvalid { .. } => CODE_APPLY_INPUT_INVALID,
            ApplyError::Required => CODE_APPROVAL_REQUIRED,
            ApplyError::KeyMismatch => CODE_APPLY_KEY_MISMATCH,
            ApplyError::Capacity => CODE_APPLY_CAPACITY,
            ApplyError::Proposal(code) => code,
            ApplyError::BaseConflict => CODE_APPLY_BASE_CONFLICT,
            ApplyError::HashConflict => CODE_APPLY_HASH_CONFLICT,
            ApplyError::Approval(err) => err.code(),
            ApplyError::ExecutionFailed { .. } => CODE_APPLY_EXECUTE_FAILED,
        }
    }
}

/// 对账报告（验收「磁盘 / OS / 代际状态可对账」的纯面）：回执链最近
/// 一次 Applied 的产物代际 vs 调用方现役代际。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReconcile {
    /// 调用方上报的现役代际
    pub live_generation: String,
    /// 回执链最近一次 Applied 的产物代际（None = 无应用史）
    pub last_applied_generation: Option<String>,
    /// 两面是否闭合（None 应用史不算一致——首启装配由 RIL-019 发布
    /// 协调器自证，不在本面对账范围）
    pub agrees: bool,
    /// 链上 Applied 回执数
    pub applied_count: usize,
    /// 链上 Failed 回执数
    pub failed_count: usize,
}

/// 应用账本（RIL-076 纯面）：提案存储 + 授权账 + 回执账的单点编排。
/// 持有二者使 `execute` 单入口无借用纠缠；控制面按需可变借用各分册
/// （`proposals_mut` / `approvals_mut`）做提案登记、批准等前置步骤。
#[derive(Default)]
pub struct ApplyLedger {
    /// 回执账：幂等键 → 终态回执（含失败——失败也占键，防半途 OS 操作重放）
    receipts: HashMap<String, ApplyReceipt>,
    /// 单调序号（对账排序）
    next_seq: u64,
}

impl ApplyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前回执数（含失败回执——重试防线依赖其在册）。
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// 按幂等键查回执（控制面查询口）。
    pub fn receipt(&self, idempotency_key: &str) -> Option<&ApplyReceipt> {
        self.receipts.get(idempotency_key)
    }

    /// 清扫早于窗口的回执（显式回收——绝不自动逐出：回执在册期重试
    /// 才有「只执行一次」保证）。返回回收数。
    pub fn prune_older_than(&mut self, now_ms: u64, older_than_ms: u64) -> usize {
        let before = self.receipts.len();
        self.receipts
            .retain(|_, r| now_ms < r.executed_ms.saturating_add(older_than_ms));
        before - self.receipts.len()
    }

    /// 单入口 apply（顺序契约见模块文档）。执行器由调用方注入：收到
    /// 提案本体（patch 已过守卫与前置检查），返回产物代际 + OS 落地面；
    /// Err 即失败终态。
    pub fn execute<F>(
        &mut self,
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
        request: ApplyRequest,
        now_ms: u64,
        executor: F,
    ) -> Result<ApplyResult, ApplyError>
    where
        F: FnOnce(&ConfigProposal) -> Result<ExecutionOutcome, String>,
    {
        // —— 1 输入面（标签纪律同 proposal / approval 模块）——
        validate_label(&request.idempotency_key).map_err(|_| ApplyError::InputInvalid {
            field: "idempotency_key",
        })?;
        validate_label(&request.caller_owner).map_err(|_| ApplyError::InputInvalid {
            field: "caller_owner",
        })?;
        validate_label(&request.live_generation).map_err(|_| ApplyError::InputInvalid {
            field: "live_generation",
        })?;
        validate_label(&request.live_hash)
            .map_err(|_| ApplyError::InputInvalid { field: "live_hash" })?;
        let approval_id = request.approval_id.as_deref().ok_or(ApplyError::Required)?;
        validate_label(approval_id).map_err(|_| ApplyError::InputInvalid {
            field: "approval_id",
        })?;

        // —— 2 幂等键裁决（先于一切状态面：提案此后取消 / 过期 / 清扫
        //    都不影响重试领回执——重试窗口不依赖提案在册）——
        if let Some(seen) = self.receipts.get(&request.idempotency_key) {
            if seen.owner == request.caller_owner
                && seen.proposal_id == request.proposal_id
                && seen.approval_id == approval_id
            {
                return Ok(ApplyResult::Replayed(seen.clone()));
            }
            return Err(ApplyError::KeyMismatch);
        }

        // —— 3 容量（先于核销与执行——满员不烧凭证，重试不受影响）——
        if self.receipts.len() >= APPLY_RECEIPT_CAP {
            return Err(ApplyError::Capacity);
        }

        // —— 4 提案守卫（unknown → foreign → expired 原码透传）——
        let proposal = proposals
            .peek(&request.proposal_id, &request.caller_owner, now_ms)
            .map_err(ApplyError::Proposal)?;

        // —— 5 版本前置检查（人工修改冲突面；代际优先于内容——代际
        //    前进是粗粒度事实，内容漂移是同代际细化）——
        if request.live_generation != proposal.base_generation {
            return Err(ApplyError::BaseConflict);
        }
        if request.live_hash != proposal.base_hash {
            return Err(ApplyError::HashConflict);
        }

        // —— 6 凭证核销（一次性——请求范围即提案全范围；校验失败不
        //    核销，核销在前防检查与执行之间同一凭证二次通过）——
        approvals
            .consume(
                approval_id,
                proposal,
                &request.caller_owner,
                now_ms,
                &proposal.scope,
            )
            .map_err(ApplyError::Approval)?;

        // —— 7 执行器（成败皆登记终态——失败回执同样占键，防半途
        //    OS 操作被重放）——
        let seq = self.next_seq;
        self.next_seq += 1;
        let receipt = match executor(proposal) {
            Ok(outcome) => {
                if validate_label(&outcome.generation_id).is_err() {
                    ApplyReceipt {
                        seq,
                        status: ApplyStatus::Failed,
                        failure_reason: Some(
                            "执行器产物代际标签非法（空 / 超长 / 控制字符）".to_string(),
                        ),
                        ..base_receipt(seq, &request, approval_id, proposal, now_ms)
                    }
                } else if !outcome.os_applied {
                    ApplyReceipt {
                        seq,
                        status: ApplyStatus::Failed,
                        failure_reason: Some("执行器上报 OS 面未全部落地".to_string()),
                        ..base_receipt(seq, &request, approval_id, proposal, now_ms)
                    }
                } else {
                    ApplyReceipt {
                        seq,
                        status: ApplyStatus::Applied,
                        generation: Some(outcome.generation_id),
                        os_applied: true,
                        failure_reason: None,
                        ..base_receipt(seq, &request, approval_id, proposal, now_ms)
                    }
                }
            }
            Err(reason) => ApplyReceipt {
                seq,
                status: ApplyStatus::Failed,
                failure_reason: Some(reason),
                os_applied: false,
                generation: None,
                ..base_receipt(seq, &request, approval_id, proposal, now_ms)
            },
        };
        self.receipts
            .insert(request.idempotency_key.clone(), receipt.clone());
        Ok(ApplyResult::Executed(receipt))
    }

    /// 对账（验收「磁盘 / OS / 代际状态可对账」）：回执链最近一次
    /// Applied 的产物代际与调用方现役比对。
    pub fn reconcile(&self, live_generation: &str) -> ApplyReconcile {
        let mut last: Option<&ApplyReceipt> = None;
        let mut applied_count = 0;
        let mut failed_count = 0;
        for receipt in self.receipts.values() {
            match receipt.status {
                ApplyStatus::Applied => {
                    applied_count += 1;
                    if last.is_none_or(|seen| receipt.seq > seen.seq) {
                        last = Some(receipt);
                    }
                }
                ApplyStatus::Failed => failed_count += 1,
            }
        }
        let last_applied = last.map(|r| r.generation.clone().unwrap_or_default());
        ApplyReconcile {
            live_generation: live_generation.to_string(),
            agrees: last_applied.as_deref() == Some(live_generation),
            last_applied_generation: last_applied,
            applied_count,
            failed_count,
        }
    }
}

/// 回执公共字段底座（成败分支共享）。
fn base_receipt(
    seq: u64,
    request: &ApplyRequest,
    approval_id: &str,
    proposal: &ConfigProposal,
    now_ms: u64,
) -> ApplyReceipt {
    ApplyReceipt {
        seq,
        idempotency_key: request.idempotency_key.clone(),
        owner: request.caller_owner.clone(),
        proposal_id: request.proposal_id.clone(),
        approval_id: approval_id.to_string(),
        base_generation: proposal.base_generation.clone(),
        base_hash: proposal.base_hash.clone(),
        status: ApplyStatus::Applied,
        generation: None,
        os_applied: false,
        failure_reason: None,
        executed_ms: now_ms,
    }
}

/// 标签纪律（与 proposal / approval 面同款）：非空、不超限、无控制字符。
fn validate_label(field: &str) -> Result<(), &'static str> {
    if field.is_empty() || field.chars().count() > APPLY_LABEL_MAX_CHARS {
        return Err(CODE_APPLY_INPUT_INVALID);
    }
    if field.chars().any(char::is_control) {
        return Err(CODE_APPLY_INPUT_INVALID);
    }
    Ok(())
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::approval::ProposalApproval;
    use crate::proposal::{
        new_proposal_id, ProposalInput, CODE_PROPOSAL_FOREIGN, CODE_PROPOSAL_UNKNOWN,
    };

    const OWNER: &str = "cli:local";
    const GEN_1: &str = "gen-a";
    const GEN_2: &str = "gen-b";
    const HASH_1: &str = "hash-a";
    const HASH_2: &str = "hash-b";

    fn proposal_input() -> ProposalInput {
        ProposalInput {
            base_generation: GEN_1.to_string(),
            base_hash: HASH_1.to_string(),
            owner: OWNER.to_string(),
            scope: vec!["routing".to_string()],
            patch: serde_json::json!({"routing": {"default_node": "proxy"}}),
            ttl_ms: 60_000,
        }
    }

    /// 登记提案并显式批准，返回（提案 id，凭证 id）。
    fn seeded(
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
    ) -> (String, String) {
        let p = proposals
            .create(new_proposal_id(), proposal_input(), 0)
            .expect("登记提案");
        let a: ProposalApproval = approvals.approve(&p, None, 0, 60_000).expect("批准");
        (p.id, a.approval_id)
    }

    fn request(key: &str, proposal_id: &str, approval_id: &str) -> ApplyRequest {
        ApplyRequest {
            idempotency_key: key.to_string(),
            proposal_id: proposal_id.to_string(),
            approval_id: Some(approval_id.to_string()),
            caller_owner: OWNER.to_string(),
            live_generation: GEN_1.to_string(),
            live_hash: HASH_1.to_string(),
        }
    }

    fn ok_executor(
        generation: &str,
    ) -> impl FnOnce(&ConfigProposal) -> Result<ExecutionOutcome, String> + '_ {
        move |_| {
            Ok(ExecutionOutcome {
                generation_id: generation.to_string(),
                os_applied: true,
            })
        }
    }

    /// 输入面与默认只读：无凭证 `approval.required`；输入非法先行。
    #[test]
    fn requires_approval_and_valid_input() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, _) = seeded(&mut proposals, &mut approvals);

        // None 凭证：写路径直接拒绝（码冻结在 approval 模块）
        let mut req = request("k1", &pid, "unused");
        req.approval_id = None;
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                req.clone(),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPROVAL_REQUIRED);

        // 空键 / 超长键 / 控制字符键
        for bad in ["", &"x".repeat(APPLY_LABEL_MAX_CHARS + 1), "bad\u{7}key"] {
            req.idempotency_key = bad.to_string();
            let err = ledger
                .execute(
                    &mut proposals,
                    &mut approvals,
                    req.clone(),
                    1,
                    ok_executor(GEN_2),
                )
                .unwrap_err();
            assert_eq!(err.code(), CODE_APPLY_INPUT_INVALID, "键 {bad:?} 应拒");
        }
        assert!(ledger.is_empty(), "失败输入不留回执");
    }

    /// 验收「人工修改后旧提案返回冲突」：代际前进 / 同代际内容漂移
    /// 各有独立稳定码；冲突不烧凭证、不触达执行器。
    #[test]
    fn manual_move_conflicts_old_proposal() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);

        // 人工修改：代际前进（订阅刷新 / 另一笔 apply / 带外发布）
        let mut req = request("k-move", &pid, &aid);
        req.live_generation = GEN_2.to_string();
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                req.clone(),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPLY_BASE_CONFLICT);

        // 人工修改：同代际原位手改（内容漂移）
        req.live_generation = GEN_1.to_string();
        req.live_hash = HASH_2.to_string();
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                req.clone(),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPLY_HASH_CONFLICT);

        // 冲突不烧凭证：修正回 live 基准后原凭证仍可核销
        assert!(approvals
            .consume(
                &aid,
                proposals.peek(&pid, OWNER, 1).unwrap(),
                OWNER,
                1,
                &["routing".to_string()]
            )
            .is_ok());
        assert!(ledger.is_empty());
    }

    /// 验收「客户端超时重试只执行一次」：同键重试领同一回执，执行器
    /// 只触达一次；提案此后被取消也照常领回执（重试不依赖提案在册）。
    #[test]
    fn timeout_retry_executes_once() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);

        let mut calls = 0usize;
        let first = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-retry", &pid, &aid),
                1,
                |p| {
                    calls += 1;
                    assert_eq!(p.scope, &["routing".to_string()], "执行器收守卫后提案");
                    Ok(ExecutionOutcome {
                        generation_id: GEN_2.to_string(),
                        os_applied: true,
                    })
                },
            )
            .expect("首次执行");
        let ApplyResult::Executed(receipt) = &first else {
            panic!("首次应是 Executed");
        };
        assert_eq!(receipt.status, ApplyStatus::Applied);
        assert_eq!(receipt.generation_or_empty(), GEN_2);
        assert!(receipt.os_applied);
        assert_eq!(calls, 1, "执行器恰好触达一次");

        // 超时重试：同键同身份 → Replayed，执行器不再触达
        let replay = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-retry", &pid, &aid),
                2,
                ok_executor(GEN_2),
            )
            .expect("重试应领回执");
        let ApplyResult::Replayed(replayed) = &replay else {
            panic!("重试应是 Replayed");
        };
        assert_eq!(replayed, receipt, "回执逐字段同");
        assert_eq!(replayed.executed_ms, 1, "回执保持首次终态时刻");
        assert_eq!(calls, 1, "重试不触达执行器");

        // 提案此后被取消：重试仍领回执（裁决先于状态面）
        proposals.cancel(&pid, OWNER, 3).expect("取消");
        let replay = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-retry", &pid, &aid),
                4,
                ok_executor(GEN_2),
            )
            .expect("取消后重试仍领回执");
        assert!(matches!(replay, ApplyResult::Replayed(_)));
        assert_eq!(calls, 1);
    }

    /// 键挪用防线：同键换提案 / 换凭证 / 换所有者一律 `apply.key.mismatch`。
    #[test]
    fn key_mismatch_rejects_identity_swap() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);
        let (pid2, aid2) = seeded(&mut proposals, &mut approvals);

        let first = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-swap", &pid, &aid),
                1,
                ok_executor(GEN_2),
            )
            .expect("首次执行");
        assert!(matches!(first, ApplyResult::Executed(_)));

        // 换提案 / 换凭证 / 换所有者——逐路显式拒绝
        let mut req = request("k-swap", &pid2, &aid);
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                req.clone(),
                2,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPLY_KEY_MISMATCH);
        req.proposal_id = pid.clone();
        req.approval_id = Some(aid2.clone());
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                req.clone(),
                2,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPLY_KEY_MISMATCH);
        req.approval_id = Some(aid.clone());
        req.caller_owner = "cli:other".to_string();
        let err = ledger
            .execute(&mut proposals, &mut approvals, req, 2, ok_executor(GEN_2))
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPLY_KEY_MISMATCH);
    }

    /// 守卫与凭证透传：unknown / foreign 提案、stale / replayed 凭证
    /// 各按原码答；校验失败不核销、不触达执行器。
    #[test]
    fn guard_and_approval_failures_preserve_state() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);

        // 未知提案
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-u", "missing", &aid),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_PROPOSAL_UNKNOWN);

        // 他人提案
        let (foreign_pid, foreign_aid) = seeded_as(&mut proposals, &mut approvals, "cli:other");
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-f", &foreign_pid, &aid),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_PROPOSAL_FOREIGN);

        // 借用他人凭证出示（凭证所有者与提案所有者不符 → foreign 先于 stale）
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-s", &pid, &foreign_aid),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), "approval.foreign");

        // 同所有者的内容失配（stale——P2 凭证对 P1 提案出示，摘要不含彼此）
        let (_pid2, aid2) = seeded(&mut proposals, &mut approvals);
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-s", &pid, &aid2),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), "approval.stale");

        // 失败不核销：P1 原凭证对 P1 仍可用且可成功应用
        let first = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-ok", &pid, &aid),
                1,
                ok_executor(GEN_2),
            )
            .expect("原凭证仍可用");
        assert!(matches!(
            first,
            ApplyResult::Executed(ApplyReceipt {
                status: ApplyStatus::Applied,
                ..
            })
        ));

        // 核销一次性：新键出示已消耗凭证 → approval.replayed 透传
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-new", &pid, &aid),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), "approval.replayed");
        assert!(ledger.receipt("k-u").is_none(), "被拒路径不留回执");
    }

    /// 验收「超时重试」失败分支：执行器失败登记为终态失败回执；同键
    /// 重试领失败回执不重放半途操作；换新键 + 新凭证才可再尝试。
    #[test]
    fn execution_failure_is_terminal_and_replayable() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);

        let mut calls = 0usize;
        let first = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-fail", &pid, &aid),
                1,
                |p| {
                    calls += 1;
                    let _ = p;
                    Err("路由表写入被拒".to_string())
                },
            )
            .expect("失败也返回回执");
        let ApplyResult::Executed(receipt) = &first else {
            panic!("失败也是本次执行");
        };
        assert_eq!(receipt.status, ApplyStatus::Failed);
        assert_eq!(receipt.status.code(), CODE_APPLY_EXECUTE_FAILED);
        assert_eq!(receipt.failure_reason.as_deref(), Some("路由表写入被拒"));
        assert!(!receipt.os_applied);
        assert!(receipt.generation.is_none());
        assert_eq!(calls, 1);

        // 重试：领失败回执，不再触达执行器（半途 OS 操作不得重放）
        let replay = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-fail", &pid, &aid),
                2,
                ok_executor(GEN_2),
            )
            .expect("重试领失败回执");
        let ApplyResult::Replayed(replayed) = &replay else {
            panic!("重试应是 Replayed");
        };
        assert_eq!(replayed.status, ApplyStatus::Failed);
        assert_eq!(calls, 1, "失败重试不重放执行");

        // 恢复路径：新提案 + 新凭证 + 新键 → 可再尝试（凭证已被首笔核销）
        let (pid2, aid2) = seeded(&mut proposals, &mut approvals);
        let retry = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-fail-2", &pid2, &aid2),
                3,
                ok_executor(GEN_2),
            )
            .expect("恢复路径应可执行");
        assert!(matches!(
            retry,
            ApplyResult::Executed(ApplyReceipt {
                status: ApplyStatus::Applied,
                ..
            })
        ));
    }

    /// 执行器产物面故障：代际标签非法 / OS 未全部落地 → 按失败登记，
    /// 不产 Applied 回执（对账面不被脏产物污染）。
    #[test]
    fn malformed_executor_outcomes_register_as_failed() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);

        // 产物代际标签非法
        let outcome = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-bad-label", &pid, &aid),
                1,
                |_| {
                    Ok(ExecutionOutcome {
                        generation_id: "bad\u{7}gen".to_string(),
                        os_applied: true,
                    })
                },
            )
            .expect("返回回执");
        let ApplyResult::Executed(receipt) = &outcome else {
            panic!("应是 Executed");
        };
        assert_eq!(receipt.status, ApplyStatus::Failed);
        assert!(receipt.generation.is_none());
    }

    /// 容量：满员拒绝新 apply（不烧凭证），同键重试不受影响；
    /// prune 腾位后新 apply 恢复。
    #[test]
    fn capacity_rejects_new_but_replay_still_works() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();

        // 单提案复用（apply 不注销提案）——逐笔新凭证装满 CAP 份回执
        let p = proposals
            .create(new_proposal_id(), proposal_input(), 0)
            .expect("登记提案");
        let mut aids: Vec<String> = Vec::new();
        for i in 0..APPLY_RECEIPT_CAP {
            let a = approvals.approve(&p, None, 0, 60_000).expect("批准");
            let req = request(&format!("k{i}"), &p.id, &a.approval_id);
            aids.push(a.approval_id);
            let outcome = ledger.execute(
                &mut proposals,
                &mut approvals,
                req,
                1 + i as u64,
                ok_executor(&format!("gen-{i}")),
            );
            assert!(matches!(outcome, Ok(ApplyResult::Executed(_))), "第 {i} 笔");
        }
        assert_eq!(ledger.len(), APPLY_RECEIPT_CAP);

        // 清扫已消耗凭证腾出授权位（回执账仍满——apply 容量独立受检）
        assert_eq!(approvals.sweep(1), APPLY_RECEIPT_CAP);
        let a = approvals.approve(&p, None, 1, 60_000).expect("新批准");

        // 满：新 apply 显式拒绝且不烧凭证
        let err = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-over", &p.id, &a.approval_id),
                1,
                ok_executor(GEN_2),
            )
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPLY_CAPACITY);

        // 在册键重试不受容量影响（裁决先于容量——身份逐字同才领回执）
        let replay = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k0", &p.id, &aids[0]),
                1,
                ok_executor(GEN_2),
            )
            .expect("在册键重试不受容量影响");
        assert!(matches!(replay, ApplyResult::Replayed(_)));

        // prune 腾位：窗口外回执回收，原凭证未被烧毁——新 apply 恢复
        let pruned = ledger.prune_older_than(500, 100);
        assert_eq!(
            pruned, APPLY_RECEIPT_CAP,
            "窗口 100ms 早于全部 1+ms 时刻+窗口"
        );
        assert!(ledger.is_empty());
        let outcome = ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-over", &p.id, &a.approval_id),
                600,
                ok_executor(GEN_2),
            )
            .expect("腾位后恢复");
        assert!(matches!(outcome, ApplyResult::Executed(_)));
    }

    /// 验收「磁盘 / OS / 代际状态可对账」：回执尾与现役闭合 / 分歧两侧
    /// 显式；无应用史不算一致。
    #[test]
    fn reconcile_compares_receipt_trail_with_live() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let (pid, aid) = seeded(&mut proposals, &mut approvals);

        // 无应用史：不算一致
        let report = ledger.reconcile(GEN_1);
        assert!(report.last_applied_generation.is_none());
        assert!(!report.agrees);
        assert_eq!(report.applied_count, 0);

        // 应用后闭合
        ledger
            .execute(
                &mut proposals,
                &mut approvals,
                request("k-r1", &pid, &aid),
                1,
                ok_executor(GEN_2),
            )
            .expect("应用");
        let report = ledger.reconcile(GEN_2);
        assert_eq!(report.last_applied_generation.as_deref(), Some(GEN_2));
        assert!(report.agrees);
        assert_eq!(report.applied_count, 1);

        // 人工带外修改：现役前进，回执尾停在旧代际——分歧两侧显式
        let report = ledger.reconcile(GEN_1);
        assert!(!report.agrees);
        assert_eq!(report.live_generation, GEN_1);
        assert_eq!(report.last_applied_generation.as_deref(), Some(GEN_2));

        // 失败回计入 failed_count，不进回执尾
        let (pid2, aid2) = seeded(&mut proposals, &mut approvals);
        let _ = ledger.execute(
            &mut proposals,
            &mut approvals,
            request("k-r2", &pid2, &aid2),
            2,
            |_| Err("失败".to_string()),
        );
        let report = ledger.reconcile(GEN_2);
        assert_eq!(report.failed_count, 1);
        assert_eq!(report.applied_count, 1);
        assert!(report.agrees, "失败回执不挪回执尾");
    }

    /// 跨所有者登记辅助（foreign 用例）：owner 不同的提案 + 凭证。
    fn seeded_as(
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
        owner: &str,
    ) -> (String, String) {
        let mut input = proposal_input();
        input.owner = owner.to_string();
        let p = proposals.create(new_proposal_id(), input, 0).expect("登记");
        let a = approvals.approve(&p, None, 0, 60_000).expect("批准");
        (p.id, a.approval_id)
    }
}
