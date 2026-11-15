//! 流排空与安全撤销（RIL-023）：在 RIL-022 会话台账之上定义「事件 →
//! 存量会话」的确定性边界——
//!
//! - **普通更新排空**：代际更替（[`DrainReason::GenerationRetired`]）与
//!   端点删除（[`DrainReason::EndpointDeleted`]）都**不**产生立即断线：
//!   存量会话进入排空态（行为确定：自然结束优先，截至 deadline），新流
//!   由 [`DrainController::admit`] 拒入退役代际（结合 RIL-022「新流采用
//!   新代际」完成换代）；
//! - **超时回收**：排空超过 deadline 的残留由 [`DrainController::sweep`]
//!   强制回收（调用方供钟，内核无时钟）；
//! - **强制撤销**：[`DrainReason::Revoked`] 是唯一立即断线事件，必须
//!   携带非空权限署名（撤销权限与端点删除分别处理：删除走排空，撤销
//!   走点名强杀），署名进入对账记录；
//! - **断线需重连的边界**：仅 {撤销、超时回收} 两个强制动作要求重连；
//!   普通更新/端点删除在任何时刻都不切断存量流。
//!
//! 接线边界：runtime 侧在代际发布（RIL-019/RIL-008）回调里调
//! `open_update`、在目录装配更新里调 `delete_endpoint`、控制面撤销
//! 请求里调 `revoke_*`；周期任务里调 `sweep`。本模块只承载台账与
//! 状态机，不触碰 IO。

use std::collections::{HashMap, HashSet};

use crate::executor::{EstablishedSession, LedgerEntry, SessionLedger};

/// 稳定原因码：强制撤销缺权限署名（撤销必须可追溯）
pub const CODE_AUTHORITY_MISSING: &str = "drain.authority_missing";

/// 排空/撤销事件的动因（决定行为边界：是否立即断线）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainReason {
    /// 普通更新：代际更替——存量会话排空至自然结束或 deadline
    GenerationRetired {
        /// 退役代际
        generation: String,
    },
    /// 端点删除：目录摘除端点——存量会话不立即断，排空处理
    EndpointDeleted {
        /// 被删端点所属节点
        node: String,
    },
    /// 强制撤销：有权限方点名撤销——立即断线，需重连
    Revoked {
        /// 权限署名（非空强制；进入对账记录）
        authority: String,
    },
}

impl DrainReason {
    /// 是否立即断线（唯一 true：强制撤销——断线需重连的边界）
    pub fn force_disconnect(&self) -> bool {
        matches!(self, DrainReason::Revoked { .. })
    }

    /// 机器口径（诊断对账）
    pub fn as_str(&self) -> &'static str {
        match self {
            DrainReason::GenerationRetired { .. } => "generation_retired",
            DrainReason::EndpointDeleted { .. } => "endpoint_deleted",
            DrainReason::Revoked { .. } => "revoked",
        }
    }
}

/// 存量会话的流状态（确定性三态：Streaming → Draining → 回收/自然结束）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFlowState {
    /// 正常在流（无排空事件触达）
    Streaming,
    /// 排空中：自然结束优先，deadline 后由 sweep 回收（撤销不走此态）
    Draining { reason: DrainReason, deadline_ms: u64 },
}

/// 超时回收记录（sweep 产物；断线需重连边界的一个强制动作）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimRecord {
    /// 被回收会话
    pub session_id: String,
    /// 排空动因（撤销态不进 sweep——撤销已即时处理）
    pub reason: DrainReason,
    /// 超期时长（now - deadline，毫秒）
    pub overdue_ms: u64,
}

/// 撤销结果（立即断线，需重连；署名入对账）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// 被撤销会话
    pub session_id: String,
    /// 撤销前的台账条目（端点/pin 留证）
    pub entry: LedgerEntry,
    /// 权限署名
    pub authority: String,
    /// 恒 true：撤销必断线
    pub require_reconnect: bool,
}

/// 撤销类 API 的失败（当前仅缺署名）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainError {
    /// 撤销缺权限署名（`drain.authority_missing`）
    AuthorityMissing,
}

impl DrainError {
    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        match self {
            DrainError::AuthorityMissing => CODE_AUTHORITY_MISSING,
        }
    }
}

impl std::fmt::Display for DrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrainError::AuthorityMissing => f.write_str("revocation requires non-empty authority"),
        }
    }
}

impl std::error::Error for DrainError {}

/// 排空控制器：持有 RIL-022 会话台账 + 每会话排空态 + 退役代际集。
/// 事件入口三对：`open_update` / `delete_endpoint`（排空，不断线）、
/// `revoke_session` / `revoke_generation`（强杀，需署名）、`sweep`
/// （超时回收）。后到事件覆盖先前排空态（按事件序确定，deadline 取新值）。
#[derive(Debug, Default)]
pub struct DrainController {
    ledger: SessionLedger,
    states: HashMap<String, SessionFlowState>,
    retired_generations: HashSet<String>,
}

impl DrainController {
    /// 空控制器
    pub fn new() -> Self {
        Self::default()
    }

    /// 绑定已建立会话（透传台账；新建会话默认 Streaming）
    pub fn bind(
        &mut self,
        session_id: impl Into<String>,
        session: EstablishedSession,
        now_ms: u64,
    ) {
        self.ledger.bind(session_id, session, now_ms);
    }

    /// 查询台账条目（克隆快照）
    pub fn entry(&self, session_id: &str) -> Option<LedgerEntry> {
        self.ledger.entry(session_id)
    }

    /// 自然结束解绑（清台账 + 清排空态——自然结束不产生回收记录）
    pub fn unbind(&mut self, session_id: &str) -> Option<LedgerEntry> {
        self.states.remove(session_id);
        self.ledger.unbind(session_id)
    }

    /// 当前绑定数
    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.ledger.is_empty()
    }

    /// 存量会话的流状态（无台账 → None）
    pub fn session_state(&self, session_id: &str) -> Option<SessionFlowState> {
        self.ledger.entry(session_id)?;
        Some(
            self.states
                .get(session_id)
                .cloned()
                .unwrap_or(SessionFlowState::Streaming),
        )
    }

    /// 该代际是否还接纳新会话（退役代际拒入——新流换代际的判定入口）
    pub fn admit(&self, generation: &str) -> bool {
        !self.retired_generations.contains(generation)
    }

    /// 普通更新：退役一代际。该代际全部存量会话进入排空态（不断线，
    /// deadline 前自然结束优先），代际拒入新会话。返回进入排空的会话。
    pub fn open_update(
        &mut self,
        retired_generation: &str,
        deadline_ms: u64,
        _now_ms: u64,
    ) -> Vec<String> {
        self.retired_generations.insert(retired_generation.to_string());
        self.mark_draining(
            |entry| entry.pin().generation().as_str() == retired_generation,
            DrainReason::GenerationRetired {
                generation: retired_generation.to_string(),
            },
            deadline_ms,
        )
    }

    /// 端点删除：目录摘除某节点的端点。该节点出口的全部存量会话进入
    /// 排空态（**不**立即断线——删除与撤销分别处理），节点本身不拒新会话
    /// （新端点由目录声明）。返回进入排空的会话。
    pub fn delete_endpoint(
        &mut self,
        node: &str,
        deadline_ms: u64,
        _now_ms: u64,
    ) -> Vec<String> {
        self.mark_draining(
            |entry| entry.pin().egress() == node,
            DrainReason::EndpointDeleted {
                node: node.to_string(),
            },
            deadline_ms,
        )
    }

    /// 强制撤销单个会话：立即断线需重连。`authority` 必须非空（撤销
    /// 权限署名，进入对账记录）。
    pub fn revoke_session(
        &mut self,
        session_id: &str,
        authority: &str,
    ) -> Result<Option<RevokeOutcome>, DrainError> {
        let authority = require_authority(authority)?;
        Ok(self.revoke_inner(session_id, authority))
    }

    /// 强制撤销一代际的全部会话（如凭证泄露处置）：立即断线需重连，
    /// 只触达该代际（其它代际会话不受影响）。
    pub fn revoke_generation(
        &mut self,
        generation: &str,
        authority: &str,
    ) -> Result<Vec<RevokeOutcome>, DrainError> {
        let authority = require_authority(authority)?;
        let targets: Vec<String> = self
            .ledger_sessions()
            .into_iter()
            .filter(|(_, entry)| entry.pin().generation().as_str() == generation)
            .map(|(id, _)| id)
            .collect();
        Ok(targets
            .into_iter()
            .filter_map(|id| self.revoke_inner(&id, authority.clone()))
            .collect())
    }

    /// 超时回收：排空态过 deadline 的残留强制回收（断线需重连边界的
    /// 另一强制动作）。撤销态不存在于此（撤销已即时移除）。
    pub fn sweep(&mut self, now_ms: u64) -> Vec<ReclaimRecord> {
        let expired: Vec<(String, DrainReason, u64)> = self
            .states
            .iter()
            .filter_map(|(id, state)| match state {
                SessionFlowState::Draining { reason, deadline_ms } if *deadline_ms <= now_ms => {
                    Some((id.clone(), reason.clone(), now_ms - *deadline_ms))
                }
                _ => None,
            })
            .collect();
        expired
            .into_iter()
            .map(|(id, reason, overdue_ms)| {
                self.ledger.unbind(&id);
                self.states.remove(&id);
                ReclaimRecord {
                    session_id: id,
                    reason,
                    overdue_ms,
                }
            })
            .collect()
    }

    /// 台账会话清单（id → 条目克隆）
    fn ledger_sessions(&self) -> Vec<(String, LedgerEntry)> {
        self.ledger
            .session_ids()
            .into_iter()
            .filter_map(|id| self.ledger.entry(&id).map(|entry| (id, entry)))
            .collect()
    }

    /// 按谓词把存量会话置入排空态（后到事件覆盖先前态——按事件序确定）
    fn mark_draining(
        &mut self,
        pred: impl Fn(&LedgerEntry) -> bool,
        reason: DrainReason,
        deadline_ms: u64,
    ) -> Vec<String> {
        let mut drained = Vec::new();
        for (id, entry) in self.ledger_sessions() {
            if pred(&entry) {
                self.states.insert(
                    id.clone(),
                    SessionFlowState::Draining {
                        reason: reason.clone(),
                        deadline_ms,
                    },
                );
                drained.push(id);
            }
        }
        drained
    }

    /// 撤销执行（署名已校验）：移除台账与排空态，产出对账记录
    fn revoke_inner(&mut self, session_id: &str, authority: String) -> Option<RevokeOutcome> {
        let entry = self.ledger.unbind(session_id)?;
        self.states.remove(session_id);
        Some(RevokeOutcome {
            session_id: session_id.to_string(),
            entry,
            authority,
            require_reconnect: true,
        })
    }
}

/// 权限署名校验（空署名 = 无权限证明，拒绝）
fn require_authority(authority: &str) -> Result<String, DrainError> {
    if authority.trim().is_empty() {
        return Err(DrainError::AuthorityMissing);
    }
    Ok(authority.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::EndpointRef;
    use crate::plan::{GenerationRef, RoutePlan, SessionPin};
    use crate::RouteDecision;

    fn generation(id: &str) -> GenerationRef {
        GenerationRef::new(id).expect("非空代际")
    }

    fn session(node: &str, gen: &str, host: &str) -> EstablishedSession {
        let plan = RoutePlan::from_decision(
            &RouteDecision::direct(node.to_string()),
            generation(gen),
        )
        .expect("合法计划");
        EstablishedSession::assemble(
            SessionPin::for_plan(&plan, node),
            EndpointRef::new(host, 443),
            Vec::new(),
        )
    }

    /// 普通更新：存量长连接不断线、端点不变、进入排空态；deadline 前
    /// sweep 不回收（长连接更新行为确定）
    #[test]
    fn normal_update_keeps_long_lived_sessions_until_deadline() {
        let mut dc = DrainController::new();
        dc.bind("flow-1", session("node-a", "gen-1", "10.0.0.1"), 100);

        let drained = dc.open_update("gen-1", 1_000, 100);
        assert_eq!(drained, vec!["flow-1".to_string()]);

        // 台账条目原封不动：端点/代际不变
        let entry = dc.entry("flow-1").expect("不断线");
        assert_eq!(entry.endpoint().host, "10.0.0.1");
        assert_eq!(entry.pin().generation().as_str(), "gen-1");
        // 状态：排空中（动因 = 代际退役）
        assert_eq!(
            dc.session_state("flow-1"),
            Some(SessionFlowState::Draining {
                reason: DrainReason::GenerationRetired {
                    generation: "gen-1".to_string()
                },
                deadline_ms: 1_000,
            })
        );

        // deadline 前 sweep：不回收
        assert!(dc.sweep(999).is_empty());
        assert!(dc.entry("flow-1").is_some(), "deadline 前不得切断存量流");
    }

    /// 退役代际拒入新会话；未退役代际照常
    #[test]
    fn retired_generation_rejects_new_admission() {
        let mut dc = DrainController::new();
        dc.bind("flow-1", session("node-a", "gen-1", "10.0.0.1"), 100);
        assert!(dc.admit("gen-1"));

        dc.open_update("gen-1", 1_000, 100);
        assert!(!dc.admit("gen-1"), "退役代际拒入新会话");
        assert!(dc.admit("gen-2"), "新代际照常接纳");
    }

    /// 超时回收：deadline 过后 sweep 强制回收并清理台账与排空态
    #[test]
    fn sweep_reclaims_expired_drains() {
        let mut dc = DrainController::new();
        dc.bind("flow-1", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.open_update("gen-1", 1_000, 100);

        let reclaimed = dc.sweep(1_050);
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].session_id, "flow-1");
        assert_eq!(reclaimed[0].overdue_ms, 50);
        assert!(dc.entry("flow-1").is_none(), "回收后台账清空");
        assert!(dc.session_state("flow-1").is_none());
        assert!(dc.is_empty());
    }

    /// 自然结束解绑清理排空态，不产生回收记录
    #[test]
    fn natural_end_clears_drain_state() {
        let mut dc = DrainController::new();
        dc.bind("flow-1", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.open_update("gen-1", 1_000, 100);

        let entry = dc.unbind("flow-1").expect("自然结束");
        assert_eq!(entry.pin().generation().as_str(), "gen-1");
        assert!(dc.session_state("flow-1").is_none());
        assert!(dc.sweep(2_000).is_empty(), "已结束会话不进回收");
    }

    /// 端点删除走排空不断线（删除 ≠ 撤销）：条目存活至 deadline，
    /// 节点其它代际/出口不受影响
    #[test]
    fn endpoint_delete_drains_but_never_force_closes() {
        let mut dc = DrainController::new();
        dc.bind("flow-a", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.bind("flow-b", session("node-b", "gen-1", "10.0.0.2"), 100);

        let drained = dc.delete_endpoint("node-a", 1_000, 100);
        assert_eq!(drained, vec!["flow-a".to_string()]);

        // 删除时刻：不断线
        assert!(dc.entry("flow-a").is_some(), "端点删除不得立即断线");
        assert!(dc.entry("flow-b").is_some());
        assert_eq!(
            dc.session_state("flow-a"),
            Some(SessionFlowState::Draining {
                reason: DrainReason::EndpointDeleted {
                    node: "node-a".to_string()
                },
                deadline_ms: 1_000,
            })
        );
        assert_eq!(dc.session_state("flow-b"), Some(SessionFlowState::Streaming));

        // deadline 前：仍存活；deadline 后：sweep 回收
        assert!(dc.sweep(500).is_empty());
        let reclaimed = dc.sweep(1_200);
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(
            reclaimed[0].reason,
            DrainReason::EndpointDeleted {
                node: "node-a".to_string()
            }
        );
        assert!(dc.entry("flow-b").is_some(), "其它出口不受影响");
    }

    /// 撤销必须携带非空权限署名（撤销权限与端点删除分别处理的一半：
    /// 撤销有权限门）
    #[test]
    fn revocation_requires_authority() {
        let mut dc = DrainController::new();
        dc.bind("flow-1", session("node-a", "gen-1", "10.0.0.1"), 100);

        for bad in ["", "   "] {
            let err = dc
                .revoke_session("flow-1", bad)
                .expect_err("空署名应拒绝");
            assert_eq!(err.code(), CODE_AUTHORITY_MISSING);
        }
        assert!(dc.entry("flow-1").is_some(), "拒绝后条目不动");
    }

    /// 撤销立即断线需重连：条目即时移除、署名入对账；其它会话不动
    #[test]
    fn revocation_disconnects_immediately() {
        let mut dc = DrainController::new();
        dc.bind("flow-1", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.bind("flow-2", session("node-a", "gen-1", "10.0.0.1"), 100);

        let outcome = dc
            .revoke_session("flow-1", "admin-console")
            .expect("署名合法")
            .expect("目标存在");
        assert_eq!(outcome.session_id, "flow-1");
        assert_eq!(outcome.authority, "admin-console");
        assert!(outcome.require_reconnect, "撤销必断线需重连");
        assert!(dc.entry("flow-1").is_none(), "撤销立即移除台账");
        assert!(dc.session_state("flow-1").is_none());
        assert!(dc.entry("flow-2").is_some(), "点名撤销不波及其它会话");

        // 不存在的会话：None（无臆造结果）
        assert!(
            dc.revoke_session("flow-x", "admin-console")
                .expect("署名合法")
                .is_none()
        );
    }

    /// 按代际撤销只杀该代际；其它代际会话不受影响
    #[test]
    fn revoke_generation_kills_only_that_generation() {
        let mut dc = DrainController::new();
        dc.bind("flow-a", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.bind("flow-b", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.bind("flow-c", session("node-a", "gen-2", "10.0.0.2"), 100);

        let outcomes = dc
            .revoke_generation("gen-1", "security-desk")
            .expect("署名合法");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.require_reconnect));
        assert!(dc.entry("flow-a").is_none());
        assert!(dc.entry("flow-b").is_none());
        assert!(dc.entry("flow-c").is_some(), "其它代际不受波及");
        assert_eq!(dc.len(), 1);

        // 全空代际撤销：空结果
        assert!(
            dc.revoke_generation("gen-9", "security-desk")
                .expect("署名合法")
                .is_empty()
        );
    }

    /// 后到排空事件覆盖先前态（按事件序确定）；撤销态不进 sweep
    /// （撤销已即时处理——sweep 只回收排空残留）
    #[test]
    fn later_event_overwrites_drain_state_and_sweep_skips_revoked() {
        let mut dc = DrainController::new();
        dc.bind("flow-a", session("node-a", "gen-1", "10.0.0.1"), 100);
        dc.delete_endpoint("node-a", 1_000, 100);
        // 同会话后到一次代际退役：状态被覆盖（deadline 取新值）
        dc.open_update("gen-1", 2_000, 150);
        assert_eq!(
            dc.session_state("flow-a"),
            Some(SessionFlowState::Draining {
                reason: DrainReason::GenerationRetired {
                    generation: "gen-1".to_string()
                },
                deadline_ms: 2_000,
            })
        );

        // 撤销即时移除——不留排空态给 sweep
        dc.bind("flow-b", session("node-b", "gen-1", "10.0.0.2"), 100);
        dc.revoke_session("flow-b", "admin-console")
            .expect("署名合法");
        assert!(
            dc.sweep(1_999).is_empty(),
            "撤销态不进 sweep；deadline 前排空也不回收"
        );
        assert!(dc.entry("flow-b").is_none());
        // flow-a 到点回收，且回收清单里绝无已撤销会话
        let reclaimed = dc.sweep(2_500);
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].session_id, "flow-a");
    }
}
