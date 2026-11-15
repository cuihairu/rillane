//! 配置事务服务（RIL-079）：把 RIL-073/074/075/076/077 的纯面装配成
//! 守护进程侧的单一权威——提案、批准、应用、回滚、回执审计。
//!
//! **为什么装配在守护进程**：CLI / MCP 都走同一组端点（验收「不接 AI
//! 完成相同闭环」「授权与版本检查不能被 CLI 绕过」的结构性保证）——
//! 基准代际 / 内容摘要 / live 面 / 候选身份全部由本服务自填（不信任
//! 客户端转述），凭证核销与版本前置检查全在纯面内发生，客户端没有
//! 任何本地旁路。
//!
//! **身份与内容**：live_generation / live_hash 都是配置规范序列化的
//! SHA-256（不同版本标签派生，见 [`config_identity`]）；提案创建以
//! 服务端 live 面为基；正向执行器 = merge patch（RFC 7396）→ 反序列化
//! → 能力集校验 → 翻新 live 面（旧面进内容历史）；回滚执行器 = 按
//! 服务端内容历史恢复候选（候选身份 = 目标回执 base_*，逐字校验由
//! RIL-077 纯面完成——本服务只提供内容，不参与裁决）。历史有界
//! （[`CONFIG_TX_HISTORY_CAP`]），超界候选显式报失败（不冒充恢复）。
//!
//! **回滚标记范围**：回滚提案范围固定 `rollback`（本服务
//! `create_rollback_proposal` 创建）——正向 apply 拒绝回滚标记提案、
//! 回滚要求回滚标记提案，两路不能互串。
//!
//! **授权边界**：本服务不持有任何凭证签发捷径——批准走
//! [`ApprovalAuthority::approve`]（操作员显式决定），daemon 不自我
//! 批准；`self_approve` / 预授权档不在本服务装配面（需要有限自动化
//! 时由宿主另行装配）。
//!
//! **接线边界**：本服务维护配置事务账与配置内容面（daemon 权威）。
//! 运行时热更 / TUN / 路由 OS 面的落地与 side_effects 所有权登记归
//! 后续接线项；`ExecutionOutcome::os_applied = true` 在本服务的语义
//! 是「本服务落地面（配置内容账 + 代际账）已全部落地」。看门狗
//! （RIL-078）归宿主侧装配，不在本服务内。

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::Serialize;

use rillane_config::{
    ApplyError, ApplyLedger, ApplyReceipt, ApplyReconcile, ApplyRequest, ApplyResult, ApplyStatus,
    ApprovalAuthority, ApprovalError, CapabilitySet, ConfigPreview, ConfigProposal,
    ExecutionOutcome, ProposalApproval, ProposalInput, ProposalStore, ProposalStoreError,
    RillaneConfig, RollbackError, RollbackExecution, RollbackReport, RollbackRequest, digest_parts,
    merge_patch, new_proposal_id, preview_config_patch, rollback_apply,
};

/// 回滚提案的标记范围（daemon 创建回滚提案时固定使用；正向提案禁用）。
pub const ROLLBACK_SCOPE_MARKER: &str = "rollback";
/// 内容历史保留界（超界候选显式失败——不冒充恢复）。
pub const CONFIG_TX_HISTORY_CAP: usize = 8;

/// 服务错误：HTTP 状态 + 稳定码 + 人读消息（稳定码 = 纯面 code() 原样）。
#[derive(Debug, Clone)]
pub struct TxError {
    /// HTTP 状态
    pub status: u16,
    /// 稳定原因码
    pub code: String,
    /// 人读消息
    pub message: String,
}

impl TxError {
    fn bad_request(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: 400,
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn conflict(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: 409,
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn unprocessable(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: 422,
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn not_found(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: 404,
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn forbidden(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: 403,
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// 提案存储错误 → HTTP（unknown=404、foreign=403、其余 400/409）。
    fn from_proposal(err: &ProposalStoreError) -> Self {
        let code = err.code();
        match code {
            "proposal.input.invalid" | "proposal.scope.invalid" | "proposal.ttl.invalid" => {
                Self::bad_request(code, err.to_string())
            }
            "proposal.unknown" => Self::not_found(code, err.to_string()),
            "proposal.foreign" => Self::forbidden(code, err.to_string()),
            "proposal.capacity" | "proposal.id.clash" => Self::conflict(code, err.to_string()),
            _ => Self::bad_request(code, err.to_string()),
        }
    }

    /// 授权错误 → HTTP（required 族=403、unknown=404、容量=409）。
    fn from_approval(err: &ApprovalError) -> Self {
        let code = err.code();
        match code {
            "approval.required" => Self::forbidden(code, err.to_string()),
            "approval.unknown" => Self::not_found(code, err.to_string()),
            "approval.capacity" | "approval.policy.exhausted" => {
                Self::conflict(code, err.to_string())
            }
            _ => Self::forbidden(code, err.to_string()),
        }
    }

    /// apply 错误 → HTTP（版本/内容冲突=409、执行失败=422、守卫透传
    /// 按 proposal./approval. 前缀分派）。
    fn from_apply(err: &ApplyError) -> Self {
        let code = err.code();
        match code {
            "apply.input.invalid" | "apply.key.mismatch" => {
                Self::bad_request(code, err.to_string())
            }
            "apply.capacity" => Self::conflict(code, err.to_string()),
            "apply.base.conflict" | "apply.hash.conflict" => Self::conflict(code, err.to_string()),
            "apply.execute.failed" => Self::unprocessable(code, err.to_string()),
            c if c.starts_with("proposal.") => Self::from_guard_code(c),
            c if c.starts_with("approval.") => Self::from_approval_code(c),
            _ => Self::bad_request(code, err.to_string()),
        }
    }

    /// 回滚错误 → HTTP（盲覆盖=409、目标裁决按码、候选失配=409）。
    fn from_rollback(err: &RollbackError) -> Self {
        let code = err.code();
        match code {
            "rollback.input.invalid" => Self::bad_request(code, err.to_string()),
            "rollback.target.unknown" => Self::not_found(code, err.to_string()),
            "rollback.target.not_applied" => Self::conflict(code, err.to_string()),
            "rollback.target.foreign" => Self::forbidden(code, err.to_string()),
            "rollback.candidate.mismatch" | "rollback.live.moved" => {
                Self::conflict(code, err.to_string())
            }
            c if c.starts_with("proposal.") => Self::from_guard_code(c),
            c if c.starts_with("approval.") => Self::from_approval_code(c),
            _ => Self::bad_request(code, err.to_string()),
        }
    }

    /// 守卫透传码（proposal.*）→ HTTP。
    fn from_guard_code(code: &str) -> Self {
        match code {
            "proposal.unknown" => Self::not_found(code, "提案不在账或已过期"),
            "proposal.foreign" => Self::forbidden(code, "提案所有者与调用者不符"),
            "proposal.expired" => Self::conflict(code, "提案已过期"),
            "proposal.base_changed" => Self::conflict(code, "提案基础内容已变"),
            _ => Self::bad_request(code, "提案守卫拒绝"),
        }
    }

    /// 授权透传码（approval.*）→ HTTP。
    fn from_approval_code(code: &str) -> Self {
        match code {
            "approval.required" => Self::forbidden(code, "写操作需要授权凭证"),
            "approval.unknown" => Self::not_found(code, "授权凭证不存在"),
            _ => Self::forbidden(code, "凭证校验失败"),
        }
    }
}

/// 配置身份派生：generation / hash 都是配置规范序列化的 SHA-256（不同
/// 版本标签）——同内容必同身份，同身份必同内容（身份是内容的纯函数）。
fn config_identity(config: &RillaneConfig) -> (String, String) {
    let canonical = serde_json::to_string(config).expect("有效配置序列化不可失败");
    (
        digest_parts(&["config-generation-v1", &canonical]),
        digest_parts(&["config-content-v1", &canonical]),
    )
}

/// 服务内部状态（Mutex 保护——端点串行化裁决）。
struct ConfigTxInner {
    proposals: ProposalStore,
    approvals: ApprovalAuthority,
    ledger: ApplyLedger,
    /// 内容历史：(generation, hash, config)——回滚恢复的内容来源，
    /// 有界（超界弃最旧）。
    history: VecDeque<(String, String, RillaneConfig)>,
    /// 现役配置面（内容 + 身份）——daemon 权威，客户端不转述。
    live: LiveState,
}

/// 现役配置面。
struct LiveState {
    generation: String,
    hash: String,
    config: RillaneConfig,
}

/// 配置事务服务（守护进程侧单一权威）。
pub struct ConfigTxService {
    inner: Mutex<ConfigTxInner>,
    capabilities: CapabilitySet,
}

/// live 面快照（GET /config/state 响应体）。
#[derive(Debug, Clone, Serialize)]
pub struct ConfigStateDto {
    pub live_generation: String,
    pub live_hash: String,
    pub proposals: usize,
    pub approvals: usize,
    pub receipts: usize,
    pub history: usize,
}

/// 回执审计条目（ApplyReceipt 的序列化投影——纯面回执不带 Serialize，
/// 守护进程侧投影为审计面）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptDto {
    pub seq: u64,
    pub idempotency_key: String,
    pub owner: String,
    pub proposal_id: String,
    pub approval_id: String,
    pub base_generation: String,
    pub base_hash: String,
    pub status: String,
    pub generation: Option<String>,
    pub os_applied: bool,
    pub failure_reason: Option<String>,
    pub executed_ms: u64,
}

impl From<&ApplyReceipt> for ReceiptDto {
    fn from(r: &ApplyReceipt) -> Self {
        Self {
            seq: r.seq,
            idempotency_key: r.idempotency_key.clone(),
            owner: r.owner.clone(),
            proposal_id: r.proposal_id.clone(),
            approval_id: r.approval_id.clone(),
            base_generation: r.base_generation.clone(),
            base_hash: r.base_hash.clone(),
            status: r.status.code().to_string(),
            generation: r.generation.clone(),
            os_applied: r.os_applied,
            failure_reason: r.failure_reason.clone(),
            executed_ms: r.executed_ms,
        }
    }
}

/// 对账投影（ApplyReconcile 的序列化投影）。
#[derive(Debug, Clone, Serialize)]
pub struct ReconcileDto {
    pub live_generation: String,
    pub last_applied_generation: Option<String>,
    pub agrees: bool,
    pub applied_count: usize,
    pub failed_count: usize,
}

impl From<&ApplyReconcile> for ReconcileDto {
    fn from(r: &ApplyReconcile) -> Self {
        Self {
            live_generation: r.live_generation.clone(),
            last_applied_generation: r.last_applied_generation.clone(),
            agrees: r.agrees,
            applied_count: r.applied_count,
            failed_count: r.failed_count,
        }
    }
}

/// 提案登记答复（POST /config/proposals 响应体）：提案身份字段平铺
///（CLI 既有消费面不变）+ 提案期预检投影 `preview`（RIL-080 MCP 工具
/// 与 CLI 共用的 diff/诊断/限制面）。**不含补丁回显**——patch 是调用者
/// 自给的输入，不必回读；缩小答复面（大补丁不占答复、秘密键值不因
/// 回显而多一处副本）。预检与登记同锁同刻——`preview.diff` 就是登记
/// 依据，不是事后另算的近似。
#[derive(Debug, Clone, Serialize)]
pub struct CreatedProposalDto {
    pub id: String,
    pub base_generation: String,
    pub base_hash: String,
    pub owner: String,
    pub scope: Vec<String>,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub preview: ConfigPreview,
}

impl CreatedProposalDto {
    fn from_proposal(proposal: &ConfigProposal, preview: ConfigPreview) -> Self {
        Self {
            id: proposal.id.clone(),
            base_generation: proposal.base_generation.clone(),
            base_hash: proposal.base_hash.clone(),
            owner: proposal.owner.clone(),
            scope: proposal.scope.clone(),
            created_ms: proposal.created_ms,
            expires_ms: proposal.expires_ms,
            preview,
        }
    }
}

/// 审计摘要（GET /config/receipts 响应体）：回执链（seq 降序）+
/// 回执链 vs 现役面 reconcile。
#[derive(Debug, Clone, Serialize)]
pub struct ConfigAuditDto {
    pub live_generation: String,
    pub live_hash: String,
    pub reconcile: ReconcileDto,
    pub receipts: Vec<ReceiptDto>,
}

/// 正向 apply 请求（daemon 面——live 身份由服务端自填，客户端不转述）。
#[derive(Debug, Clone)]
pub struct TxApplyRequest {
    /// 幂等键（重试须逐字同键）
    pub idempotency_key: String,
    /// 目标提案 id
    pub proposal_id: String,
    /// 授权凭证 id；None = 默认只读（`approval.required`）
    pub approval_id: Option<String>,
    /// 调用者所有者（与提案所有者同校验）
    pub caller_owner: String,
}

/// 回滚请求（daemon 面——候选身份由服务端自目标回执取得）。
#[derive(Debug, Clone)]
pub struct TxRollbackRequest {
    /// 回滚自身的幂等键（重试须逐字同键）
    pub idempotency_key: String,
    /// 被回退 apply 的幂等键（回执寻址）
    pub target_key: String,
    /// 回滚提案 id（回滚标记提案——由 `create_rollback_proposal` 签发）
    pub proposal_id: String,
    /// 回滚凭证；None = 默认只读
    pub approval_id: Option<String>,
    /// 调用者所有者
    pub caller_owner: String,
    /// 排空时限（epoch 毫秒；None = 操作员未定——计划仍产出）
    pub drain_deadline_ms: Option<u64>,
}

/// apply 一回合结果（ApplyResult 的序列化投影）。
#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutcomeDto {
    /// `executed` = 本次触达执行器；`replayed` = 幂等重试领回执
    pub phase: &'static str,
    pub receipt: ReceiptDto,
}

impl From<&ApplyResult> for ApplyOutcomeDto {
    fn from(r: &ApplyResult) -> Self {
        match r {
            ApplyResult::Executed(receipt) => Self {
                phase: "executed",
                receipt: ReceiptDto::from(receipt),
            },
            ApplyResult::Replayed(receipt) => Self {
                phase: "replayed",
                receipt: ReceiptDto::from(receipt),
            },
        }
    }
}

/// 排空补偿计划投影。
#[derive(Debug, Clone, Serialize)]
pub struct DrainPlanDto {
    pub retired_generation: String,
    pub readmitted_generation: String,
    pub deadline_ms: Option<u64>,
    pub note: String,
}

/// 连接真相投影。
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionTruthDto {
    pub pinned_generation: String,
    pub statement: String,
}

/// 回滚报告投影（RollbackReport 的序列化投影）。
#[derive(Debug, Clone, Serialize)]
pub struct RollbackReportDto {
    pub receipt: ReceiptDto,
    pub drain: Option<DrainPlanDto>,
    pub connections: Option<ConnectionTruthDto>,
}

impl From<&RollbackReport> for RollbackReportDto {
    fn from(r: &RollbackReport) -> Self {
        Self {
            receipt: ReceiptDto::from(&r.receipt),
            drain: r.drain.as_ref().map(|d| DrainPlanDto {
                retired_generation: d.retired_generation.clone(),
                readmitted_generation: d.readmitted_generation.clone(),
                deadline_ms: d.deadline_ms,
                note: d.note.to_string(),
            }),
            connections: r.connections.as_ref().map(|c| ConnectionTruthDto {
                pinned_generation: c.pinned_generation.clone(),
                statement: c.statement.to_string(),
            }),
        }
    }
}

/// 历史入列（有界——超界弃最旧；回滚面「候选在历史」的可用窗口即此界）。
fn push_history(
    history: &mut VecDeque<(String, String, RillaneConfig)>,
    entry: (String, String, RillaneConfig),
) {
    while history.len() >= CONFIG_TX_HISTORY_CAP {
        history.pop_front();
    }
    history.push_back(entry);
}

/// 当前时刻（epoch 毫秒，宿主时钟——纯面「调用方供钟」纪律的 daemon
/// 侧实现；控制面端点统一取此钟）。
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl ConfigTxService {
    /// 以初始配置装配（boot 面调）：live 面即初始配置的身份。
    pub fn new(config: RillaneConfig, capabilities: CapabilitySet) -> Self {
        let (generation, hash) = config_identity(&config);
        Self {
            inner: Mutex::new(ConfigTxInner {
                proposals: ProposalStore::new(),
                approvals: ApprovalAuthority::new(),
                ledger: ApplyLedger::new(),
                history: VecDeque::new(),
                live: LiveState {
                    generation,
                    hash,
                    config,
                },
            }),
            capabilities,
        }
    }

    /// live 面快照（GET /config/state）。
    pub fn state(&self) -> ConfigStateDto {
        let inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        ConfigStateDto {
            live_generation: inner.live.generation.clone(),
            live_hash: inner.live.hash.clone(),
            proposals: inner.proposals.len(),
            approvals: inner.approvals.len(),
            receipts: inner.ledger.len(),
            history: inner.history.len(),
        }
    }

    /// 登记正向提案：daemon 自填 base（live 面）+ 提案期 preview 预检
    /// （不落状态、不烧凭证——坏 patch 在提案期就显式报）。范围含
    /// `rollback` 标记者拒绝（标记范围由 `create_rollback_proposal`
    /// 专用）。返回提案身份（无补丁回显——调用者自给自足，缩小答复
    /// 面）+ 提案期预检投影（RIL-080 MCP 工具与 CLI 共用的 diff/诊断
    /// /限制面——预检与登记同锁同刻，diff 就是登记依据不是事后拼凑）。
    pub fn create_proposal(
        &self,
        owner: &str,
        scope: &[String],
        patch: &serde_json::Value,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<CreatedProposalDto, TxError> {
        if scope.iter().any(|s| s == ROLLBACK_SCOPE_MARKER) {
            return Err(TxError::bad_request(
                "proposal.scope.invalid",
                "rollback 标记范围由 /config/rollback-proposal 创建，正向提案不得使用",
            ));
        }
        let mut inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        let ConfigTxInner {
            proposals, live, ..
        } = &mut *inner;
        let preview = self.preview_checked(&live.config, patch, scope)?;
        let proposal = proposals
            .create(
                new_proposal_id(),
                ProposalInput {
                    base_generation: live.generation.clone(),
                    base_hash: live.hash.clone(),
                    owner: owner.to_string(),
                    scope: scope.to_vec(),
                    patch: patch.clone(),
                    ttl_ms,
                },
                now_ms,
            )
            .map_err(|e| TxError::from_proposal(&e))?;
        Ok(CreatedProposalDto::from_proposal(&proposal, preview))
    }

    /// 登记回滚提案（daemon 创建）：范围固定 rollback 标记、patch 为空
    /// 对象（回滚按候选代际恢复内容，不走 merge 语义）。目标回执必须
    /// 在册且 Applied 且属调用者——回滚提案寻址真实事务。
    pub fn create_rollback_proposal(
        &self,
        owner: &str,
        target_key: &str,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<ConfigProposal, TxError> {
        let mut inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        let ConfigTxInner {
            proposals,
            ledger,
            live,
            ..
        } = &mut *inner;
        let target = ledger
            .receipt(target_key)
            .ok_or_else(|| TxError::not_found("rollback.target.unknown", "目标回执不在账"))?;
        if target.status != ApplyStatus::Applied {
            return Err(TxError::conflict(
                "rollback.target.not_applied",
                "目标回执非 Applied——无可回滚之物",
            ));
        }
        if target.owner != owner {
            return Err(TxError::forbidden(
                "rollback.target.foreign",
                "目标回执所有者与调用者不符",
            ));
        }
        proposals
            .create(
                new_proposal_id(),
                ProposalInput {
                    base_generation: live.generation.clone(),
                    base_hash: live.hash.clone(),
                    owner: owner.to_string(),
                    scope: vec![ROLLBACK_SCOPE_MARKER.to_string()],
                    patch: serde_json::json!({}),
                    ttl_ms,
                },
                now_ms,
            )
            .map_err(|e| TxError::from_proposal(&e))
    }

    /// 显式批准（操作员决定）：凭证绑定提案内容摘要 + 所有者 + 授权
    /// 范围 + 有效期；一次性核销归 apply/rollback 的 consume。范围缺省
    /// = 提案全范围。
    pub fn approve(
        &self,
        proposal_id: &str,
        owner: &str,
        scope: Option<Vec<String>>,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<ProposalApproval, TxError> {
        let mut inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        let ConfigTxInner {
            proposals,
            approvals,
            ..
        } = &mut *inner;
        let proposal = proposals
            .peek(proposal_id, owner, now_ms)
            .map_err(TxError::from_guard_code)?;
        approvals
            .approve(proposal, scope, now_ms, ttl_ms)
            .map_err(|e| TxError::from_approval(&e))
    }

    /// preview（只读投影面——不落任何状态、不烧凭证）：对现役配置应用
    /// 补丁并产出 diff / 诊断 / 受影响类别 / 副作用提示四份报告。
    pub fn preview(&self, patch: &serde_json::Value, scope: Option<&[String]>) -> ConfigPreview {
        let inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        preview_config_patch(&inner.live.config, patch, &self.capabilities, scope)
    }

    /// 正向应用（提案守卫 → 版本/内容前置检查 → 凭证核销 → 执行 →
    /// 终态回执；成败皆终态、幂等重试领同一回执）。执行器：merge patch
    /// → 反序列化 → 能力校验 → 翻新 live 面（旧面进历史）。
    pub fn apply(&self, request: TxApplyRequest, now_ms: u64) -> Result<ApplyOutcomeDto, TxError> {
        let mut inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        let ConfigTxInner {
            proposals,
            approvals,
            ledger,
            live,
            history,
        } = &mut *inner;

        // 回滚标记提案不能走正向 apply（两路不互串）
        if let Ok(proposal) = proposals.peek(&request.proposal_id, &request.caller_owner, now_ms) {
            if proposal.scope.len() == 1 && proposal.scope[0] == ROLLBACK_SCOPE_MARKER {
                return Err(TxError::bad_request(
                    "proposal.scope.invalid",
                    "回滚标记提案须走 /config/rollback",
                ));
            }
            // 执行前 preview 兜底预检（不烧凭证——现役面形状失配在此
            // 显式报，执行器失败只留给不可预知的内部错误）
            self.preview_checked(&live.config, &proposal.patch, &proposal.scope)?;
        }

        let pure_request = ApplyRequest {
            idempotency_key: request.idempotency_key,
            proposal_id: request.proposal_id,
            approval_id: request.approval_id,
            caller_owner: request.caller_owner,
            live_generation: live.generation.clone(),
            live_hash: live.hash.clone(),
        };

        let result = ledger
            .execute(proposals, approvals, pure_request, now_ms, |proposal| {
                let current = serde_json::to_value(&live.config)
                    .map_err(|_| "现役配置序列化失败（内部形状错误）".to_string())?;
                let merged = merge_patch(&current, &proposal.patch);
                let next: RillaneConfig = serde_json::from_value(merged)
                    .map_err(|_| "合并结果反序列化失败（形状失配——重新提案）".to_string())?;
                self.capabilities
                    .validate_config(&next)
                    .map_err(|e| format!("能力集校验失败: {e}"))?;
                let (generation, hash) = config_identity(&next);
                let retired = std::mem::replace(
                    live,
                    LiveState {
                        generation: generation.clone(),
                        hash,
                        config: next,
                    },
                );
                let LiveState {
                    generation: rg,
                    hash: rh,
                    config: rc,
                } = retired;
                push_history(history, (rg, rh, rc));
                Ok(ExecutionOutcome {
                    generation_id: generation,
                    os_applied: true,
                })
            })
            .map_err(|e| TxError::from_apply(&e))?;
        Ok(ApplyOutcomeDto::from(&result))
    }

    /// 回滚执行：候选身份由服务端自目标回执取得（客户端不供 candidate
    /// / live——盲覆盖防线与候选比对基准全部服务端自证）；授权走新链
    /// （回滚提案 → 操作员批准 → 核销）。报告三份如实（回执 + 排空
    /// 补偿计划 + 连接真相）。
    pub fn rollback(
        &self,
        request: TxRollbackRequest,
        now_ms: u64,
    ) -> Result<RollbackReportDto, TxError> {
        let mut inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        let ConfigTxInner {
            proposals,
            approvals,
            ledger,
            live,
            history,
        } = &mut *inner;

        // 必须是回滚标记提案（正向提案不能被借用为回滚凭证载体）
        if let Ok(proposal) = proposals.peek(&request.proposal_id, &request.caller_owner, now_ms) {
            if proposal.scope.len() != 1 || proposal.scope[0] != ROLLBACK_SCOPE_MARKER {
                return Err(TxError::bad_request(
                    "proposal.scope.invalid",
                    "回滚须用回滚标记提案（/config/rollback-proposal 创建）",
                ));
            }
        }

        // 候选身份服务端自填（不信任请求侧转述）
        let target = ledger
            .receipt(&request.target_key)
            .ok_or_else(|| TxError::not_found("rollback.target.unknown", "目标回执不在账"))?;
        if target.status != ApplyStatus::Applied {
            return Err(TxError::conflict(
                "rollback.target.not_applied",
                "目标回执非 Applied",
            ));
        }
        if target.owner != request.caller_owner {
            return Err(TxError::forbidden(
                "rollback.target.foreign",
                "目标回执所有者与调用者不符",
            ));
        }
        let candidate_generation = target.base_generation.clone();
        let candidate_hash = target.base_hash.clone();

        let pure_request = RollbackRequest {
            idempotency_key: request.idempotency_key,
            target_key: request.target_key,
            proposal_id: request.proposal_id,
            approval_id: request.approval_id,
            caller_owner: request.caller_owner,
            live_generation: live.generation.clone(),
            live_hash: live.hash.clone(),
            candidate_generation: candidate_generation.clone(),
            candidate_hash: candidate_hash.clone(),
            drain_deadline_ms: request.drain_deadline_ms,
        };

        let report = rollback_apply(
            ledger,
            proposals,
            approvals,
            pure_request,
            now_ms,
            |_proposal| {
                let (_, _, restored) = history
                    .iter()
                    .find(|(g, h, _)| g == &candidate_generation && h == &candidate_hash)
                    .cloned()
                    .ok_or_else(|| {
                        "候选代际不在服务内容历史（超出保留界）——按手工对账恢复".to_string()
                    })?;
                self.capabilities
                    .validate_config(&restored)
                    .map_err(|e| format!("候选配置能力校验失败: {e}"))?;
                let (gen_id, hash, config) =
                    (candidate_generation.clone(), candidate_hash, restored);
                let retired = std::mem::replace(
                    live,
                    LiveState {
                        generation: gen_id.clone(),
                        hash,
                        config,
                    },
                );
                let LiveState {
                    generation: rg,
                    hash: rh,
                    config: rc,
                } = retired;
                push_history(history, (rg, rh, rc));
                Ok(RollbackExecution {
                    generation_id: gen_id,
                    os_applied: true,
                    capabilities_validated: true,
                })
            },
        )
        .map_err(|e| TxError::from_rollback(&e))?;
        Ok(RollbackReportDto::from(&report))
    }

    /// 审计摘要（GET /config/receipts）：回执链（seq 降序）+ 回执链
    /// vs 服务端现役面对账（daemon 自证——不采信任何客户端转述）。
    pub fn audit(&self) -> ConfigAuditDto {
        let inner = self.inner.lock().expect("配置事务锁不可 poisoned");
        let reconcile = inner.ledger.reconcile(&inner.live.generation);
        ConfigAuditDto {
            live_generation: inner.live.generation.clone(),
            live_hash: inner.live.hash.clone(),
            reconcile: ReconcileDto::from(&reconcile),
            receipts: inner
                .ledger
                .receipts()
                .iter()
                .map(|r| ReceiptDto::from(*r))
                .collect(),
        }
    }

    /// preview 预检口（guard 持有期调）：不适用即 400（稳定码并列为
    /// 人读消息——消息面已脱敏）；适用则交还预检投影（提案登记据此
    /// 同刻入账——RIL-080 答复里的 diff 与登记依据同源）。
    fn preview_checked(
        &self,
        current: &RillaneConfig,
        patch: &serde_json::Value,
        scope: &[String],
    ) -> Result<ConfigPreview, TxError> {
        let preview = preview_config_patch(current, patch, &self.capabilities, Some(scope));
        if !preview.applicable {
            let codes = preview
                .diagnostics
                .iter()
                .map(|d| d.code)
                .collect::<Vec<_>>()
                .join(",");
            return Err(TxError::bad_request(
                "preview.config.invalid",
                format!("补丁不适用（{codes}）"),
            ));
        }
        Ok(preview)
    }
}

#[cfg(test)]
mod config_tx_tests {
    use super::*;

    const OWNER: &str = "cli:local";

    fn boot_config() -> RillaneConfig {
        RillaneConfig::from_str(
            "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
            Some("yaml"),
        )
        .expect("基线配置应解析")
    }

    fn patch() -> serde_json::Value {
        serde_json::json!({"routing": {"default_node": "proxy"}})
    }

    fn apply_req(key: &str, proposal_id: &str, approval_id: &str) -> TxApplyRequest {
        TxApplyRequest {
            idempotency_key: key.to_string(),
            proposal_id: proposal_id.to_string(),
            approval_id: Some(approval_id.to_string()),
            caller_owner: OWNER.to_string(),
        }
    }

    /// 全闭环：提案（daemon 自填 base）→ 批准 → 应用 → 现役翻新 +
    /// 旧面入历史；同键重试领回执不翻新；新提案基于新现役可再应用。
    #[test]
    fn propose_approve_apply_roundtrip_and_idempotent_retry() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());
        let before = service.state();

        let proposal = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 0)
            .expect("登记提案");
        assert_eq!(
            proposal.base_generation, before.live_generation,
            "daemon 自填 base"
        );
        assert_eq!(proposal.base_hash, before.live_hash);

        let approval = service
            .approve(&proposal.id, OWNER, None, 60_000, 1)
            .expect("批准");
        assert_eq!(approval.proposal_id, proposal.id);

        let outcome = service
            .apply(apply_req("k1", &proposal.id, &approval.approval_id), 2)
            .expect("应用成功");
        assert_eq!(outcome.phase, "executed");
        assert_eq!(outcome.receipt.status, "apply.applied");

        let after = service.state();
        assert_ne!(after.live_generation, before.live_generation, "现役已翻新");
        assert_eq!(after.history, 1, "旧面进历史");

        // 幂等重试：同键领回执，现役与历史不动
        let replay = service
            .apply(apply_req("k1", &proposal.id, &approval.approval_id), 3)
            .expect("同键重试");
        assert_eq!(replay.phase, "replayed");
        assert_eq!(replay.receipt, outcome.receipt);
        assert_eq!(service.state().live_generation, after.live_generation);
        assert_eq!(service.state().history, 1);

        // 新提案基于新现役：闭环可继续
        let p2 = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 4)
            .expect("第二提案");
        let a2 = service
            .approve(&p2.id, OWNER, None, 60_000, 4)
            .expect("第二批准");
        let o2 = service
            .apply(apply_req("k2", &p2.id, &a2.approval_id), 5)
            .expect("第二应用");
        assert_eq!(o2.receipt.status, "apply.applied");
        assert_eq!(service.state().history, 2);
    }

    /// 授权与版本检查不能被绕过：无凭证 403（approval.required）、
    /// 他人提案 foreign、同键换提案 key.mismatch（挪用防线）、旧提案
    /// 对翻新后的现役 = base.conflict（daemon 自填 live 决定——客户端
    /// 无法谎报基准）。
    #[test]
    fn authorization_and_version_checks_cannot_be_bypassed() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());
        let proposal = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 0)
            .expect("登记提案");

        // 无凭证
        let mut noauth = apply_req("k-noauth", &proposal.id, "unused");
        noauth.approval_id = None;
        let err = service.apply(noauth, 1).unwrap_err();
        assert_eq!(err.code, "approval.required");
        assert_eq!(err.status, 403);

        // 他人提案（foreign）：调用者非所有者
        let intruder = TxApplyRequest {
            idempotency_key: "k-f".to_string(),
            proposal_id: proposal.id.clone(),
            approval_id: Some("unused".to_string()),
            caller_owner: "intruder".to_string(),
        };
        let err = service.apply(intruder, 1).unwrap_err();
        assert_eq!(err.code, "proposal.foreign");

        // 批准后正常应用（内容翻新 gen-A → gen-B），再以同键换提案 =
        // key.mismatch（挪用防线）
        let approval = service
            .approve(&proposal.id, OWNER, None, 60_000, 1)
            .expect("批准");
        service
            .apply(apply_req("k-id", &proposal.id, &approval.approval_id), 2)
            .expect("应用");
        let p_other = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 3)
            .expect("第二提案");
        let a_other = service
            .approve(&p_other.id, OWNER, None, 60_000, 3)
            .expect("第二批准");
        let err = service
            .apply(apply_req("k-id", &p_other.id, &a_other.approval_id), 3)
            .unwrap_err();
        assert_eq!(err.code, "apply.key.mismatch");

        // 版本检查：旧提案（base = gen-B）对翻新后的现役 = base.conflict
        // ——先登记旧提案，再用**内容不同**的提案翻新（gen-B → gen-C），
        // 旧提案即撞版本门（daemon 自填 live，客户端无法谎报基准）
        let stale = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 4)
            .expect("翻新前登记的提案");
        let a_stale = service
            .approve(&stale.id, OWNER, None, 60_000, 4)
            .expect("批准");
        let mover = service
            .create_proposal(
                OWNER,
                &["routing".to_string()],
                &serde_json::json!({"routing": {"default_node": "backup"}}),
                60_000,
                4,
            )
            .expect("内容翻新提案");
        let a_mover = service
            .approve(&mover.id, OWNER, None, 60_000, 4)
            .expect("批准");
        service
            .apply(apply_req("k-move", &mover.id, &a_mover.approval_id), 5)
            .expect("内容翻新应用");
        let err = service
            .apply(apply_req("k-stale", &stale.id, &a_stale.approval_id), 6)
            .unwrap_err();
        assert_eq!(
            err.code, "apply.base.conflict",
            "旧提案对翻新后现役必须冲突"
        );
        assert_eq!(err.status, 409);
    }

    /// 回滚闭环：回滚提案（标记范围）→ 批准 → 执行 → 内容恢复到候选
    /// 身份 + 对账闭合；回滚的回滚亦可行（内容历史双向面）；报告三份
    /// 如实（回执 + 排空计划 + 连接真相）。
    #[test]
    fn rollback_restores_content_and_reconciles() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());
        let boot = service.state();

        // 正向应用（内容真实变化）
        let p1 = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 0)
            .expect("提案");
        let a1 = service
            .approve(&p1.id, OWNER, None, 60_000, 0)
            .expect("批准");
        let fwd = service
            .apply(apply_req("k-fwd", &p1.id, &a1.approval_id), 1)
            .expect("应用");
        let after = service.state();
        assert_ne!(after.live_generation, boot.live_generation);
        let fwd_gen = fwd
            .receipt
            .generation
            .clone()
            .expect("Applied 回执带产物代际");

        // 回滚提案 + 批准 + 执行
        let rp = service
            .create_rollback_proposal(OWNER, "k-fwd", 60_000, 2)
            .expect("回滚提案");
        assert_eq!(rp.scope, vec![ROLLBACK_SCOPE_MARKER.to_string()]);
        let ra = service
            .approve(&rp.id, OWNER, None, 60_000, 2)
            .expect("回滚批准");
        let report = service
            .rollback(
                TxRollbackRequest {
                    idempotency_key: "k-rb".to_string(),
                    target_key: "k-fwd".to_string(),
                    proposal_id: rp.id,
                    approval_id: Some(ra.approval_id),
                    caller_owner: OWNER.to_string(),
                    drain_deadline_ms: Some(90_000),
                },
                3,
            )
            .expect("回滚成功");
        assert_eq!(report.receipt.status, "apply.applied");
        let drain = report.drain.expect("Applied 回滚带排空计划");
        assert_eq!(drain.retired_generation, fwd_gen, "退役代际 = 原产物");
        assert_eq!(
            drain.readmitted_generation, boot.live_generation,
            "重接入候选 = boot 代际"
        );
        let truth = report.connections.expect("Applied 回滚带连接真相");
        assert_eq!(truth.pinned_generation, fwd_gen);

        // 内容恢复：live 身份回到 boot 身份；对账闭合
        let restored = service.state();
        assert_eq!(
            restored.live_generation, boot.live_generation,
            "恢复到候选代际"
        );
        assert_eq!(restored.live_hash, boot.live_hash, "内容逐字恢复");
        let audit = service.audit();
        assert!(audit.reconcile.agrees);
        assert_eq!(audit.reconcile.applied_count, 2, "正向 + 回滚两条 Applied");

        // 回滚的回滚：目标 k-rb（候选 = gen-B），历史在册 → 可行
        let rp2 = service
            .create_rollback_proposal(OWNER, "k-rb", 60_000, 4)
            .expect("回滚的回滚提案");
        let ra2 = service
            .approve(&rp2.id, OWNER, None, 60_000, 4)
            .expect("批准");
        let report2 = service
            .rollback(
                TxRollbackRequest {
                    idempotency_key: "k-rb2".to_string(),
                    target_key: "k-rb".to_string(),
                    proposal_id: rp2.id,
                    approval_id: Some(ra2.approval_id),
                    caller_owner: OWNER.to_string(),
                    drain_deadline_ms: None,
                },
                5,
            )
            .expect("回滚的回滚成功");
        assert_eq!(report2.receipt.status, "apply.applied");
        assert_eq!(service.state().live_generation, fwd_gen, "内容回到正向产物");
    }

    /// 提案期预检与标记隔离：坏 patch 提案期显式报（不落提案）；回滚
    /// 标记范围不得用于正向提案；非在册回执不可寻址（404）。
    #[test]
    fn proposal_time_gates_and_marker_isolation() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());

        // 坏 patch：提案期报、不落账
        let bad = serde_json::json!({"routing": {"default_node": 42}});
        let err = service
            .create_proposal(OWNER, &["routing".to_string()], &bad, 60_000, 0)
            .unwrap_err();
        assert_eq!(err.code, "preview.config.invalid");
        assert_eq!(service.state().proposals, 0, "被拒提案不落账");

        // 回滚标记范围禁用于正向提案
        let err = service
            .create_proposal(OWNER, &["rollback".to_string()], &patch(), 60_000, 0)
            .unwrap_err();
        assert_eq!(err.code, "proposal.scope.invalid");

        // 未在册回执不可寻址
        let err = service
            .create_rollback_proposal(OWNER, "nope", 60_000, 0)
            .unwrap_err();
        assert_eq!(err.code, "rollback.target.unknown");
        assert_eq!(err.status, 404);
    }

    /// 审计摘要：回执按 seq 降序、对账字段如实、live 身份在册。
    #[test]
    fn audit_summary_lists_receipts_newest_first() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());
        let p = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 0)
            .expect("提案");
        let a = service
            .approve(&p.id, OWNER, None, 60_000, 0)
            .expect("批准");
        service
            .apply(apply_req("k-a", &p.id, &a.approval_id), 1)
            .expect("应用");

        let audit = service.audit();
        assert_eq!(audit.receipts.len(), 1);
        assert_eq!(audit.receipts[0].idempotency_key, "k-a");
        assert_eq!(audit.receipts[0].status, "apply.applied");
        assert_eq!(audit.receipts[0].owner, OWNER);
        assert!(audit.reconcile.agrees, "回执链与现役面闭合");
        assert_eq!(audit.reconcile.applied_count, 1);
        assert_eq!(audit.live_generation, service.state().live_generation);
    }

    /// preview 投影面：只读（现役不变、不落提案）、diff / 诊断如实。
    #[test]
    fn preview_is_read_only_projection() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());
        let before = service.state();

        let preview = service.preview(&patch(), Some(&["routing".to_string()]));
        assert!(preview.applicable);
        assert!(!preview.diff.is_empty(), "有变化的 diff 如实呈现");
        assert!(preview.scope_violations.is_empty());

        let bad = service.preview(&serde_json::json!({"routing": {"default_node": 42}}), None);
        assert!(!bad.applicable, "非法补丁在诊断面显式报");
        assert!(!bad.diagnostics.is_empty());

        assert_eq!(
            service.state().live_generation,
            before.live_generation,
            "preview 不翻新现役"
        );
        assert_eq!(
            service.state().proposals,
            before.proposals,
            "preview 不落提案"
        );
    }

    /// RIL-080：提案登记答复带提案期预检投影（同锁同刻——diff 就是
    /// 登记依据）且**不回显补丁**（序列化面无 patch 键——调用者自给
    /// 自足，大补丁不占答复、秘密值不多一处副本）。
    #[test]
    fn created_proposal_carries_preview_and_omits_patch_echo() {
        let service = ConfigTxService::new(boot_config(), CapabilitySet::full());
        let created = service
            .create_proposal(OWNER, &["routing".to_string()], &patch(), 60_000, 0)
            .expect("登记提案");
        assert!(created.preview.applicable, "登记面预检必已过");
        assert!(
            !created.preview.diff.is_empty(),
            "diff 非空（default_node 变更）"
        );
        assert_eq!(created.preview.diff[0].path, "routing.default_node");
        assert_eq!(created.scope, vec!["routing".to_string()]);

        let text = serde_json::to_string(&created).expect("序列化");
        let v: serde_json::Value = serde_json::from_str(&text).expect("解析");
        assert!(v.get("patch").is_none(), "登记答复不回显补丁——缩小面");
        assert!(v.get("preview").is_some(), "预检投影在场");
        assert!(v["preview"]["diff"].is_array());
    }
}
