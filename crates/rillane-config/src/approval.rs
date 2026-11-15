//! 提案授权绑定（RIL-075）：把「批准」绑定为一份可校验的凭证——绑定
//! 提案内容摘要、提案 ID、所有者与授权范围。Apply 入口（RIL-076）必须
//! 出示一份与当前提案内容、所有者、范围三方都吻合的凭证才能执行：
//!
//! - **改参数不能越权**：凭证绑定提案内容摘要（SHA-256，含提案 ID 与
//!   全部字段）——批准后提案内容任何变化即摘要失配 → `approval.stale`；
//! - **重放不能越权**：凭证单次有效——消耗登记一次性核销，二次使用
//!   → `approval.replayed`（先核先赢）；
//! - **借用其他用户提案不能越权**：凭证绑定所有者（双向：提案所有者
//!   ≠ 凭证所有者、调用者 ≠ 提案所有者都拒）→ `approval.foreign`；
//! - **默认只读无法写入**：`ApprovalAuthority` 初始为空、无任何隐式
//!   写授权——没有凭证就是没有写权限（RIL-076 入口对 None 凭证直接
//!   以 `approval.required` 拒绝）；凭证本身经 `new_proposal_id()` 同源
//!   随机生成，不可猜测；
//! - **超范围需新增授权**：请求范围超出凭证授权范围 → `approval.scope.
//!   exceeded`——扩大范围必须走一次新的显式批准。
//!
//! **有限自动化**：操作员可预授权一份**有主、有界、有期**的授权档
//! （`PreauthorizedGrant`：绑所有者 + 范围 + 剩余次数 + 过期时刻）——
//! 落在档内的提案可 `self_approve` 自动获批，但每次自动批准都消耗一档
//! 次数且产物仍是单次凭证（重放防线对自动化产物同样成立）。
//!
//! 资源边界与时间纪律同 [`crate::proposal`]：容量硬上限、调用方供钟、
//! 纯存储面。拒绝顺序契约：`unknown → foreign → replayed/expired →
//! stale → scope.exceeded`（foreign 先于 replayed——非所有者探测他人
//! 凭证的核销状态只得到 foreign）。

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::generations::digest_parts;
use crate::proposal::{new_proposal_id, ConfigProposal};

/// 稳定原因码：未出示凭证（默认只读——写入口对 None 凭证的拒绝）。
pub const CODE_APPROVAL_REQUIRED: &str = "approval.required";
/// 稳定原因码：凭证不存在。
pub const CODE_APPROVAL_UNKNOWN: &str = "approval.unknown";
/// 稳定原因码：凭证已过期。
pub const CODE_APPROVAL_EXPIRED: &str = "approval.expired";
/// 稳定原因码：凭证与提案内容失配（批准后提案已变——含提案 ID 调换）。
pub const CODE_APPROVAL_STALE: &str = "approval.stale";
/// 稳定原因码：所有者不符（借用他人提案/他人凭证）。
pub const CODE_APPROVAL_FOREIGN: &str = "approval.foreign";
/// 稳定原因码：凭证已被消耗（重放拒绝）。
pub const CODE_APPROVAL_REPLAYED: &str = "approval.replayed";
/// 稳定原因码：请求范围超出凭证授权范围（超范围需新增授权）。
pub const CODE_APPROVAL_SCOPE_EXCEEDED: &str = "approval.scope.exceeded";
/// 稳定原因码：批准范围不是提案范围的子集（签发期校验）。
pub const CODE_APPROVAL_SCOPE_INVALID: &str = "approval.scope.invalid";
/// 稳定原因码：凭证存储已满且无过期项可回收。
pub const CODE_APPROVAL_CAPACITY: &str = "approval.capacity";
/// 稳定原因码：预授权档次数耗尽（有限自动化的界）。
pub const CODE_APPROVAL_POLICY_EXHAUSTED: &str = "approval.policy.exhausted";

/// 凭证存储容量硬上限。
pub const APPROVAL_STORE_CAP: usize = 64;
/// 预授权档数量上限。
pub const PREAUTH_GRANT_CAP: usize = 16;

/// 授权标签/范围条目的共享校验上限（与提案存储同值）。
const MAX_LABEL_CHARS: usize = 128;
const MAX_SCOPE_ITEMS: usize = 16;
const MAX_SCOPE_ITEM_CHARS: usize = 64;

/// 授权凭证（RIL-075）：绑定一份提案的内容摘要 + 所有者 + 授权范围 +
/// 有效期。字段只读——凭证一经签发不可改写（改参数要走新提案 + 新批准）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProposalApproval {
    /// 不可猜测凭证 ID（与提案 ID 同源随机）
    pub approval_id: String,
    /// 绑定的提案 ID
    pub proposal_id: String,
    /// 绑定的提案内容摘要（含提案 ID——ID 调换即失配）
    pub proposal_digest: String,
    /// 绑定的提案所有者（双向绑定——借他人提案或他人凭证皆拒）
    pub owner: String,
    /// 授权范围（提案范围的子集；Apply 请求范围不得超出）
    pub scope: Vec<String>,
    /// 签发时刻（调用方时钟，毫秒）
    pub granted_ms: u64,
    /// 过期时刻
    pub expires_ms: u64,
}

/// 计算提案内容摘要（规范算法）：覆盖全部字段（含提案 ID）的序列化
/// 原文 + 版本标签——任何字段变化即摘要变化。
pub fn proposal_digest(proposal: &ConfigProposal) -> String {
    let canonical = serde_json::to_string(proposal).expect("提案序列化不可失败");
    digest_parts(&["proposal-v1", &canonical])
}

/// 授权错误（文案可演进，`code()` 恒定）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    /// 未出示凭证（默认只读）
    #[error("{CODE_APPROVAL_REQUIRED}: 写操作需要授权凭证——默认只读，无凭证即无写权限")]
    Required,
    /// 凭证不存在
    #[error("{CODE_APPROVAL_UNKNOWN}: 授权凭证不存在")]
    Unknown,
    /// 凭证已过期
    #[error("{CODE_APPROVAL_EXPIRED}: 授权凭证已过期")]
    Expired,
    /// 凭证与提案内容失配
    #[error(
        "{CODE_APPROVAL_STALE}: 提案内容与凭证绑定摘要不一致（批准后提案已变——须重新提案并批准）"
    )]
    Stale,
    /// 所有者不符
    #[error("{CODE_APPROVAL_FOREIGN}: 凭证所有者与提案/调用者不符")]
    Foreign,
    /// 凭证已被消耗
    #[error("{CODE_APPROVAL_REPLAYED}: 授权凭证已消耗（单次有效）")]
    Replayed,
    /// 请求范围超界
    #[error("{CODE_APPROVAL_SCOPE_EXCEEDED}: 请求范围超出凭证授权范围——扩大范围须新增授权")]
    ScopeExceeded,
    /// 批准范围不是提案范围子集
    #[error("{CODE_APPROVAL_SCOPE_INVALID}: 批准范围须为提案范围的子集且非空")]
    ScopeInvalid,
    /// 存储已满
    #[error("{CODE_APPROVAL_CAPACITY}: 凭证存储已满且无过期项可回收")]
    Capacity,
    /// 预授权次数耗尽
    #[error("{CODE_APPROVAL_POLICY_EXHAUSTED}: 预授权档剩余次数耗尽")]
    PolicyExhausted,
}

impl ApprovalError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            ApprovalError::Required => CODE_APPROVAL_REQUIRED,
            ApprovalError::Unknown => CODE_APPROVAL_UNKNOWN,
            ApprovalError::Expired => CODE_APPROVAL_EXPIRED,
            ApprovalError::Stale => CODE_APPROVAL_STALE,
            ApprovalError::Foreign => CODE_APPROVAL_FOREIGN,
            ApprovalError::Replayed => CODE_APPROVAL_REPLAYED,
            ApprovalError::ScopeExceeded => CODE_APPROVAL_SCOPE_EXCEEDED,
            ApprovalError::ScopeInvalid => CODE_APPROVAL_SCOPE_INVALID,
            ApprovalError::Capacity => CODE_APPROVAL_CAPACITY,
            ApprovalError::PolicyExhausted => CODE_APPROVAL_POLICY_EXHAUSTED,
        }
    }
}

/// 凭证的三方校验（提案内容 × 所有者 × 范围）：不消耗凭证——消耗
/// 是 [`ApprovalAuthority::consume`] 的一次性核销。顺序：foreign →
/// expired → stale → scope.exceeded。
impl ProposalApproval {
    pub fn verify(
        &self,
        proposal: &ConfigProposal,
        caller_owner: &str,
        now_ms: u64,
        requested_scope: &[String],
    ) -> Result<(), ApprovalError> {
        if proposal.owner != caller_owner || proposal.owner != self.owner {
            return Err(ApprovalError::Foreign);
        }
        if now_ms >= self.expires_ms {
            return Err(ApprovalError::Expired);
        }
        if proposal_digest(proposal) != self.proposal_digest {
            return Err(ApprovalError::Stale);
        }
        if !requested_scope.iter().all(|s| self.scope.contains(s)) {
            return Err(ApprovalError::ScopeExceeded);
        }
        Ok(())
    }
}

/// 预授权档（有限自动化）：绑所有者 + 范围 + 剩余次数 + 过期时刻。
/// 档内提案自动获批，每次消耗一次次数；产物仍为单次凭证。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreauthorizedGrant {
    /// 适用的提案所有者（档不跨所有者）
    pub owner: String,
    /// 预授权范围（提案范围须为其子集）
    pub scopes: Vec<String>,
    /// 剩余可用次数（有限自动化的界）
    pub remaining_uses: u32,
    /// 过期时刻（调用方时钟，毫秒）
    pub expires_ms: u64,
}

/// 授权权威（RIL-075）：凭证账本 + 预授权档。初始为空 = 默认只读——
/// 无凭证无写权限；一切写路径必须经 `consume` 核销一份有效凭证。
#[derive(Debug, Default)]
pub struct ApprovalAuthority {
    approvals: HashMap<String, ProposalApproval>,
    consumed: HashSet<String>,
    grants: Vec<PreauthorizedGrant>,
}

impl ApprovalAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前登记凭证数（含已消耗/未清扫过期项）。
    pub fn len(&self) -> usize {
        self.approvals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.approvals.is_empty()
    }

    /// 显式批准（操作员决定）：授权范围缺省 = 提案全范围；显式给定须为
    /// 提案范围的非空子集。
    pub fn approve(
        &mut self,
        proposal: &ConfigProposal,
        scope: Option<Vec<String>>,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<ProposalApproval, ApprovalError> {
        let scope = match scope {
            Some(s) => {
                validate_grant_scope(&s)?;
                if !s.iter().all(|item| proposal.scope.contains(item)) {
                    return Err(ApprovalError::ScopeInvalid);
                }
                s
            }
            None => proposal.scope.clone(),
        };
        self.register(proposal, scope, now_ms, ttl_ms)
    }

    /// 预授权自动批准（有限自动化）：提案所有者与范围落在某档内、该档
    /// 未过期且剩余次数 > 0 → 签发凭证并消耗一档次数。无匹配档 = 默认
    /// 拒绝（`approval.scope.exceeded`——档面就是预授权边界）。
    pub fn self_approve(
        &mut self,
        proposal: &ConfigProposal,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<ProposalApproval, ApprovalError> {
        let Some(index) = self.grants.iter().position(|g| {
            g.owner == proposal.owner && proposal.scope.iter().all(|s| g.scopes.contains(s))
        }) else {
            return Err(ApprovalError::ScopeExceeded);
        };
        let grant = &self.grants[index];
        if now_ms >= grant.expires_ms {
            return Err(ApprovalError::Expired);
        }
        if grant.remaining_uses == 0 {
            return Err(ApprovalError::PolicyExhausted);
        }
        self.grants[index].remaining_uses -= 1;
        let scope = proposal.scope.clone();
        match self.register(proposal, scope, now_ms, ttl_ms) {
            Ok(approval) => Ok(approval),
            Err(err) => {
                // 登记失败回滚次数消耗（容量拒绝不留档损）
                self.grants[index].remaining_uses += 1;
                Err(err)
            }
        }
    }

    /// 登记预授权档（有主、有界、有期）。过期时刻必须在未来。
    pub fn grant_preauthorized(
        &mut self,
        grant: PreauthorizedGrant,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        validate_label(&grant.owner)?;
        validate_grant_scope(&grant.scopes)?;
        if grant.remaining_uses == 0 {
            return Err(ApprovalError::PolicyExhausted);
        }
        if now_ms >= grant.expires_ms {
            return Err(ApprovalError::Expired);
        }
        if self.grants.len() >= PREAUTH_GRANT_CAP {
            return Err(ApprovalError::Capacity);
        }
        self.grants.push(grant);
        Ok(())
    }

    /// 写路径闸门（RIL-076 消费）：出示凭证 → 三方校验 + 一次性核销。
    /// 顺序契约：unknown → foreign → replayed → expired → stale →
    /// scope.exceeded。校验失败不核销（凭证仍可修正后续次使用——核销
    /// 只发生在全部检查通过之后）。
    #[allow(clippy::too_many_arguments)]
    pub fn consume(
        &mut self,
        approval_id: &str,
        proposal: &ConfigProposal,
        caller_owner: &str,
        now_ms: u64,
        requested_scope: &[String],
    ) -> Result<(), ApprovalError> {
        let Some(approval) = self.approvals.get(approval_id) else {
            return Err(ApprovalError::Unknown);
        };
        approval.verify(proposal, caller_owner, now_ms, requested_scope)?;
        if self.consumed.contains(approval_id) {
            return Err(ApprovalError::Replayed);
        }
        self.consumed.insert(approval_id.to_string());
        Ok(())
    }

    /// 清扫过期凭证（预授权档不清扫——档面由操作员显式管理）。已消耗
    /// 凭证一并回收（一次性核销后无再校验价值——重放防线依赖核销记录
    /// 仅在凭证仍在册期间成立；回收即凭证彻底消失，再出示即 unknown）。
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let before = self.approvals.len();
        let reclaim: Vec<String> = self
            .approvals
            .iter()
            .filter(|(id, a)| now_ms >= a.expires_ms || self.consumed.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &reclaim {
            self.approvals.remove(id);
            self.consumed.remove(id);
        }
        before - self.approvals.len()
    }

    fn register(
        &mut self,
        proposal: &ConfigProposal,
        scope: Vec<String>,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<ProposalApproval, ApprovalError> {
        if ttl_ms == 0 {
            return Err(ApprovalError::Expired);
        }
        if self.approvals.len() >= APPROVAL_STORE_CAP {
            self.sweep(now_ms);
            if self.approvals.len() >= APPROVAL_STORE_CAP {
                return Err(ApprovalError::Capacity);
            }
        }
        let approval = ProposalApproval {
            approval_id: new_proposal_id(),
            proposal_id: proposal.id.clone(),
            proposal_digest: proposal_digest(proposal),
            owner: proposal.owner.clone(),
            scope,
            granted_ms: now_ms,
            expires_ms: now_ms.saturating_add(ttl_ms),
        };
        self.approvals
            .insert(approval.approval_id.clone(), approval.clone());
        Ok(approval)
    }
}

fn validate_label(field: &str) -> Result<(), ApprovalError> {
    if field.is_empty() || field.chars().count() > MAX_LABEL_CHARS {
        return Err(ApprovalError::ScopeInvalid);
    }
    if field.chars().any(char::is_control) {
        return Err(ApprovalError::ScopeInvalid);
    }
    Ok(())
}

fn validate_grant_scope(scope: &[String]) -> Result<(), ApprovalError> {
    if scope.is_empty() || scope.len() > MAX_SCOPE_ITEMS {
        return Err(ApprovalError::ScopeInvalid);
    }
    for item in scope {
        if item.is_empty()
            || item.chars().count() > MAX_SCOPE_ITEM_CHARS
            || item.chars().any(char::is_control)
        {
            return Err(ApprovalError::ScopeInvalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use crate::generations::digest_parts;
    use crate::proposal::ProposalInput;

    fn proposal() -> ConfigProposal {
        let input = ProposalInput {
            base_generation: digest_parts(&["gen-1"]),
            base_hash: digest_parts(&["config-v1"]),
            owner: "cli:local".to_string(),
            scope: vec!["routing".to_string(), "dns".to_string()],
            patch: serde_json::json!({"routing": {"default_node": "proxy"}}),
            ttl_ms: 60_000,
        };
        let mut store = crate::proposal::ProposalStore::new();
        store.create(new_proposal_id(), input, 0).expect("提案登记")
    }

    /// 改参数即换摘要：内容任何字段变化 → digest 变（摘要覆盖全字段
    /// 含提案 ID）。
    #[test]
    fn digest_changes_when_content_changes() {
        let p = proposal();
        let d1 = proposal_digest(&p);
        let mut p2 = p.clone();
        p2.patch = serde_json::json!({"routing": {"default_node": "web"}});
        assert_ne!(proposal_digest(&p2), d1, "改参数即换摘要");
        let mut p3 = p.clone();
        p3.id = new_proposal_id();
        assert_ne!(proposal_digest(&p3), d1, "提案 ID 调换即换摘要");
    }

    /// 正路径：显式批准 → 三方校验通过 → 一次性核销成功。
    #[test]
    fn approve_and_consume_roundtrip() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal();
        let approval = auth
            .approve(&p, None, 1_000, 60_000)
            .expect("显式批准应签发");
        assert_eq!(approval.owner, "cli:local");
        assert_eq!(approval.scope, p.scope, "缺省范围 = 提案全范围");
        assert!(auth.len() == 1);
        auth.consume(&approval.approval_id, &p, "cli:local", 2_000, &p.scope)
            .expect("三方吻合应核销");
    }

    /// 验收「改参数不能越权」：批准后提案内容变化 → `approval.stale`。
    #[test]
    fn content_change_invalidates_approval() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal();
        let approval = auth.approve(&p, None, 0, 60_000).expect("批准");
        let mut p2 = p.clone();
        p2.patch = serde_json::json!({"routing": {"default_node": "evil"}});
        let err = auth
            .consume(&approval.approval_id, &p2, "cli:local", 1, &p2.scope)
            .expect_err("改参数须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_STALE);
        // 校验失败不核销——原提案仍可用原凭证（修正后重试）
        auth.consume(&approval.approval_id, &p, "cli:local", 1, &p.scope)
            .expect("失败校验不核销原凭证");
    }

    /// 验收「重放不能越权」：凭证单次有效，二次使用 `approval.replayed`。
    #[test]
    fn replay_rejected() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal();
        let approval = auth.approve(&p, None, 0, 60_000).expect("批准");
        auth.consume(&approval.approval_id, &p, "cli:local", 1, &p.scope)
            .expect("首次核销");
        let err = auth
            .consume(&approval.approval_id, &p, "cli:local", 1, &p.scope)
            .expect_err("重放须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_REPLAYED);
    }

    /// 验收「借用其他用户提案不能越权」：提案所有者 ≠ 凭证所有者、
    /// 调用者 ≠ 提案所有者两个方向都拒；foreign 先于 replayed（非所有者
    /// 探测他人凭证核销状态只得 foreign）。
    #[test]
    fn foreign_proposal_rejected() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal(); // owner = cli:local
        let approval = auth.approve(&p, None, 0, 60_000).expect("批准");
        auth.consume(&approval.approval_id, &p, "cli:local", 1, &p.scope)
            .expect("首次核销");

        // 他人提案（同形内容、不同所有者）借用他人凭证
        let mut other = p.clone();
        other.owner = "ui:remote".to_string();
        let err = auth
            .consume(&approval.approval_id, &other, "ui:remote", 1, &other.scope)
            .expect_err("借用他人凭证须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_FOREIGN);
        // 调用者与提案所有者不符
        let err = auth
            .consume(&approval.approval_id, &p, "attacker", 1, &p.scope)
            .expect_err("冒用提案须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_FOREIGN);
    }

    #[test]
    fn unknown_and_expired_rejected() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal();
        // 未知凭证
        let err = auth
            .consume("nonexistent", &p, "cli:local", 0, &p.scope)
            .expect_err("未知凭证须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_UNKNOWN);
        // 过期凭证（未消耗、仍登记 → 显式 expired）
        let approval = auth.approve(&p, None, 0, 1_000).expect("批准");
        let err = auth
            .consume(&approval.approval_id, &p, "cli:local", 1_000, &p.scope)
            .expect_err("过期须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_EXPIRED);
    }

    /// 验收「超范围需新增授权」：请求范围超出凭证范围 →
    /// `approval.scope.exceeded`；签发期范围越界 → `approval.scope.invalid`。
    #[test]
    fn scope_exceeded_requires_new_approval() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal(); // scope = [routing, dns]
                            // 签发期：批准范围不是提案范围子集 → ScopeInvalid
        let err = auth
            .approve(&p, Some(vec!["egress".to_string()]), 0, 60_000)
            .expect_err("越界批准须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_INVALID);
        // 窄范围批准合法
        let approval = auth
            .approve(&p, Some(vec!["routing".to_string()]), 0, 60_000)
            .expect("窄范围批准");
        let err = auth
            .consume(
                &approval.approval_id,
                &p,
                "cli:local",
                1,
                &["routing".to_string(), "dns".to_string()],
            )
            .expect_err("超范围须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_EXCEEDED);
        // 窄范围请求通过并核销
        auth.consume(
            &approval.approval_id,
            &p,
            "cli:local",
            1,
            &["routing".to_string()],
        )
        .expect("范围内请求应核销");
    }

    /// 验收「默认只读无法写入」+ 有限自动化：初始权威无任何隐式写授权
    /// ——self_approve 无档即默认拒绝；档内自动获批但每次消耗次数，
    /// 耗尽即 `approval.policy.exhausted`；过期档显式 `approval.expired`。
    #[test]
    fn preauthorized_automation_is_bounded() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal();
        // 默认：无档 = 默认拒绝（默认只读无法写入）
        let err = auth
            .self_approve(&p, 0, 60_000)
            .expect_err("无预授权须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_EXCEEDED);
        // 跨所有者档不适用
        auth.grant_preauthorized(
            PreauthorizedGrant {
                owner: "ui:remote".to_string(),
                scopes: vec!["routing".to_string(), "dns".to_string()],
                remaining_uses: 5,
                expires_ms: 60_000,
            },
            0,
        )
        .expect("预授权档登记");
        let err = auth.self_approve(&p, 0, 60_000).expect_err("他人档不适用");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_EXCEEDED);
        // 本所有者档：范围覆盖提案、次数有界（2 次），第 3 次耗尽
        auth.grant_preauthorized(
            PreauthorizedGrant {
                owner: "cli:local".to_string(),
                scopes: vec!["routing".to_string(), "dns".to_string()],
                remaining_uses: 2,
                expires_ms: 60_000,
            },
            0,
        )
        .expect("预授权档登记");
        let a1 = auth.self_approve(&p, 1, 60_000).expect("自动批准 1");
        assert_eq!(a1.scope, p.scope, "自动批准范围 = 提案范围");
        let a2 = auth.self_approve(&p, 1, 60_000).expect("自动批准 2");
        let err = auth
            .self_approve(&p, 1, 60_000)
            .expect_err("次数耗尽须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_POLICY_EXHAUSTED);
        // 自动批准产物仍是单次凭证（重放防线对自动化产物同样成立）
        auth.consume(&a1.approval_id, &p, "cli:local", 2, &p.scope)
            .expect("核销 1");
        let err = auth
            .consume(&a1.approval_id, &p, "cli:local", 2, &p.scope)
            .expect_err("自动化产物重放须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_REPLAYED);
        let _ = a2;
        // 过期档显式 expired（独立权威——多档匹配按登记序取首个，
        // 隔离前面的耗尽档）
        let mut fresh = ApprovalAuthority::new();
        fresh
            .grant_preauthorized(
                PreauthorizedGrant {
                    owner: "cli:local".to_string(),
                    scopes: vec!["routing".to_string(), "dns".to_string()],
                    remaining_uses: 5,
                    expires_ms: 1_000,
                },
                0,
            )
            .expect("预授权档登记");
        let err = fresh
            .self_approve(&p, 1_000, 60_000)
            .expect_err("过期档须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_EXPIRED);
    }

    /// 容量硬上限 + 清扫：满员显式拒绝（不逐出活凭证）；过期清扫腾位；
    /// 已消耗凭证一并回收。
    #[test]
    fn capacity_bounded_with_expired_reclaim() {
        let mut auth = ApprovalAuthority::new();
        let p = proposal();
        for _ in 0..APPROVAL_STORE_CAP {
            auth.approve(&p, None, 0, 1_000).expect("签发应成功");
        }
        let err = auth.approve(&p, None, 0, 1_000).expect_err("满员须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_CAPACITY);
        // 过期后签发自动回收腾位
        auth.approve(&p, None, 2_000, 60_000)
            .expect("过期回收后应腾位");
        assert_eq!(auth.len(), 1, "回收 64 + 新增 1");
        // sweep 回收过期项
        let mut auth2 = ApprovalAuthority::new();
        let early = auth2.approve(&p, None, 0, 1_000).expect("签发");
        auth2
            .consume(&early.approval_id, &p, "cli:local", 1, &p.scope)
            .expect("核销");
        let later = auth2.approve(&p, None, 1, 60_000).expect("签发第 2 份");
        assert_eq!(auth2.sweep(2_000), 1, "已消耗凭证回收；活凭证留存");
        assert_eq!(auth2.len(), 1);
        // 过期项到点回收
        assert_eq!(auth2.sweep(61_000), 1, "过期凭证回收");
        assert!(auth2.is_empty());
        let _ = later;
    }

    /// 签发期输入校验：预授权档字段非法（空范围/0 次/过期时刻在过去/
    /// 空所有者/控制字符所有者）拒绝；被拒输入不留痕。
    #[test]
    fn grant_input_validation() {
        let mut auth = ApprovalAuthority::new();

        let err = auth
            .grant_preauthorized(
                PreauthorizedGrant {
                    owner: "cli:local".to_string(),
                    scopes: Vec::new(),
                    remaining_uses: 1,
                    expires_ms: 60_000,
                },
                0,
            )
            .expect_err("空范围须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_INVALID);

        let err = auth
            .grant_preauthorized(
                PreauthorizedGrant {
                    owner: "cli:local".to_string(),
                    scopes: vec!["routing".to_string()],
                    remaining_uses: 0,
                    expires_ms: 60_000,
                },
                0,
            )
            .expect_err("0 次档须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_POLICY_EXHAUSTED);

        let err = auth
            .grant_preauthorized(
                PreauthorizedGrant {
                    owner: "cli:local".to_string(),
                    scopes: vec!["routing".to_string()],
                    remaining_uses: 1,
                    expires_ms: 0,
                },
                0,
            )
            .expect_err("过期时刻在过去须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_EXPIRED);

        let err = auth
            .grant_preauthorized(
                PreauthorizedGrant {
                    owner: String::new(),
                    scopes: vec!["routing".to_string()],
                    remaining_uses: 1,
                    expires_ms: 60_000,
                },
                0,
            )
            .expect_err("空所有者须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_INVALID);

        let err = auth
            .grant_preauthorized(
                PreauthorizedGrant {
                    owner: "cli\u{7}local".to_string(),
                    scopes: vec!["routing".to_string()],
                    remaining_uses: 1,
                    expires_ms: 60_000,
                },
                0,
            )
            .expect_err("控制字符所有者须拒绝");
        assert_eq!(err.code(), CODE_APPROVAL_SCOPE_INVALID);

        assert!(auth.is_empty(), "被拒输入不留痕");
        assert!(auth.grants.is_empty());
    }
}
