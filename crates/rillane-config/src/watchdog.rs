//! 管理通路看门狗（RIL-078）：可能断开管理连接的变更预警、宿主侧
//! 定时确认和事务化恢复。
//!
//! **为什么需要看门狗**：管理通路（HTTP 控制面 / MCP admin）是唯一
//! 能改配置的通道——一次改坏 listen 地址 / admin 凭证 / 管理开关的
//! apply 会把这条通道自己切断，之后任何客户端都无法再修正。看门狗
//! 是**宿主侧**的安全网（本面纯逻辑，定时器归宿主）：变更前预警，
//! 变更后开确认窗口，窗口内宿主定时探测管理通路仍应答才算数，窗口
//! 到点未确认 → 按事务（RIL-077 回滚）恢复。
//!
//! 三个子面的结构化对应：
//!
//! 1. **变更预警** [`assess_management_risk`]：对 preview diff 路径做
//!    管理通路关键段分类（listen / 凭证 / 开关）——命中即 `may_sever`
//!    真值与逐条建议；宿主可注入额外关键段前缀（宿主知道自己拓扑，
//!    例如管理通路骑在 DNS 监听上时把 `dns.listen` 也列为关键）。
//! 2. **定时确认** [`Watchdog::arm`] / [`Watchdog::confirm`] / [`Watchdog::miss`]
//!    / [`Watchdog::evaluate`]：arm 以**目标回执**寻址（回执产物代际
//!    即受试代际——不信任调用方转述），confirm 必须逐字应答受试代际
//!    （探错代际不算确认），miss 记缺失不计失败，窗口由宿主供。
//! 3. **事务化恢复** [`Watchdog::take_recovery`]：窗口到点 → 产出
//!    `RecoveryPlan`（候选身份 = 目标回执 base_*——按回执恢复，走
//!    RIL-077 `rollback_apply` 执行；本面不触碰 IO 与会话台账）→
//!    [`Watchdog::verify_recovery`] 验证恢复回执 Applied 且产物代际 =
//!    候选。恢复失败（`RollbackError`）→ [`repair_guidance`] 给出按
//!    稳定码分类的**具体修复步骤**（验收「恢复失败给出具体修复信息」）。
//!
//! **验收「客户端断开/daemon 重启时仍按事务恢复并验证」**：
//! - 客户端断开：确认窗口是 daemon 侧状态，与客户端连接无关——窗口
//!   不重置、miss 不清零（测试钉住断开后窗口语义原样）。
//! - daemon 重启：[`WatchdogSnapshot`] 落盘归宿主；`resume` **不信快照
//!   单方面之言**——快照须与回执账对得上（目标回执仍在册、仍
//!   Applied、产物代际逐字一致）才重立窗口，账本才是权威（对账纪律
//!   与 RIL-019 journal 同源）。
//!
//! **边界**：定时器、管理通路探测（HTTP/路由存活检查）、快照落盘、
//! 回滚执行全部归宿主与控制面（RIL-079/081 接线）；盲覆盖防线与
//! RIL-077 同款——恢复计划产出前核实现役未前进（`watchdog.live.moved`）。

use serde::{Deserialize, Serialize};

use crate::apply::{ApplyLedger, ApplyStatus};

/// 稳定原因码：输入标签非法。
pub const CODE_WATCHDOG_INPUT_INVALID: &str = "watchdog.input.invalid";
/// 稳定原因码：确认窗口非法（0 或超上限）。
pub const CODE_WATCHDOG_WINDOW_INVALID: &str = "watchdog.window.invalid";
/// 稳定原因码：确认代际与受试代际不符（探错对象不算确认）。
pub const CODE_WATCHDOG_GENERATION_MISMATCH: &str = "watchdog.generation.mismatch";
/// 稳定原因码：窗口已过——迟到确认不清窗（恢复已到期）。
pub const CODE_WATCHDOG_WINDOW_EXPIRED: &str = "watchdog.window.expired";
/// 稳定原因码：确认窗口未到期——看门狗不早退。
pub const CODE_WATCHDOG_NOT_DUE: &str = "watchdog.not.due";
/// 稳定原因码：目标回执不在册（被 prune）。
pub const CODE_WATCHDOG_TARGET_UNKNOWN: &str = "watchdog.target.unknown";
/// 稳定原因码：目标回执已非受试时的 Applied/产物（事务面已变）。
pub const CODE_WATCHDOG_TARGET_GONE: &str = "watchdog.target.gone";
/// 稳定原因码：现役已前进——恢复到受试前状态会盲覆盖带外变更。
pub const CODE_WATCHDOG_LIVE_MOVED: &str = "watchdog.live.moved";
/// 稳定原因码：恢复验证失配（回执未登记/未 Applied/产物代际不符）。
pub const CODE_WATCHDOG_VERIFY_MISMATCH: &str = "watchdog.verify.mismatch";

/// 默认确认窗口（宿主可自定；只是建议值——窗口本身由宿主供）。
pub const WATCHDOG_DEFAULT_WINDOW_MS: u64 = 30_000;
/// 确认窗口上限（超限拒绝——看门狗不是常驻挂起态）。
pub const WATCHDOG_MAX_WINDOW_MS: u64 = 3_600_000;

// —— 1 变更预警（交付一：可能断开管理连接的变更预警）——

/// 管理通路风险类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementRiskKind {
    /// 监听面（地址 / 端口 / 绑定）——改错即通路消失
    Listen,
    /// 凭证面（admin token / 密码 / 认证）——改错即拒绝应答
    Auth,
    /// 开关面（enable / disable）——关掉即通路下线
    Toggle,
}

impl ManagementRiskKind {
    /// 稳定类别码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            ManagementRiskKind::Listen => "watchdog.risk.listen",
            ManagementRiskKind::Auth => "watchdog.risk.auth",
            ManagementRiskKind::Toggle => "watchdog.risk.toggle",
        }
    }
}

/// 单条管理通路风险。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementRisk {
    /// 触发路径（diff 路径或宿主注入的额外关键段）
    pub path: String,
    /// 风险类别
    pub kind: ManagementRiskKind,
    /// 逐条建议
    pub advice: &'static str,
}

/// 管理通路风险评估（apply 前调——与 RIL-074 preview 的 diff 路径对接）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagementAssessment {
    /// 是否可能切断管理通路（任一风险命中即真）
    pub may_sever: bool,
    /// 命中的关键路径（宿主侧据此决定是否 arm 确认窗口）
    pub critical_paths: Vec<String>,
    /// 逐条风险明细
    pub risks: Vec<ManagementRisk>,
    /// 总结建议（固定文案）
    pub advice: &'static str,
}

const ASSESSMENT_ADVICE: &str =
    "此变更可能切断管理通路——apply 后立即以产物回执开确认窗口（Watchdog::arm），窗口内宿主定时探测管理通路应答";

/// 变更预警：对 diff 路径做管理通路关键段分类。`extra_critical` 是宿主
/// 注入的额外关键段前缀（宿主拓扑自知——例如管理通路骑在 DNS 监听上
/// 时把 `"dns.listen"` 也列为关键）。命中路径按下表分类：
/// listen/host/port/bind → Listen；token/password/auth/secret/credential →
/// Auth；enable/disable → Toggle（前缀命中按宿主注入段处理，类别
/// Listen——宿主注入即监听拓扑关切）。
pub fn assess_management_risk(
    diff_paths: &[&str],
    extra_critical: &[&str],
) -> ManagementAssessment {
    let mut assessment = ManagementAssessment::default();
    for path in diff_paths {
        if let Some(kind) = classify_management_path(path) {
            assessment.risks.push(ManagementRisk {
                path: (*path).to_string(),
                kind,
                advice: risk_advice(kind),
            });
            assessment.critical_paths.push((*path).to_string());
        }
    }
    for prefix in extra_critical {
        if prefix.is_empty() {
            continue;
        }
        let hit = diff_paths.iter().any(|p| {
            p == prefix
                || p.starts_with(&format!("{prefix}."))
                || p.starts_with(&format!("{prefix}/"))
        });
        if hit {
            assessment.risks.push(ManagementRisk {
                path: (*prefix).to_string(),
                kind: ManagementRiskKind::Listen,
                advice: risk_advice(ManagementRiskKind::Listen),
            });
            assessment.critical_paths.push((*prefix).to_string());
        }
    }
    assessment.may_sever = !assessment.risks.is_empty();
    if assessment.may_sever {
        assessment.advice = ASSESSMENT_ADVICE;
    }
    assessment
}

/// 关键段分类（management 块内按子段关键词；其余路径不命中）。
fn classify_management_path(path: &str) -> Option<ManagementRiskKind> {
    let top = path.split(['.', '/']).next()?;
    if top != "management" {
        return None;
    }
    let lower = path.to_lowercase();
    if ["token", "password", "auth", "secret", "credential"]
        .iter()
        .any(|kw| lower.contains(kw))
    {
        return Some(ManagementRiskKind::Auth);
    }
    if ["enable", "disable"].iter().any(|kw| lower.contains(kw)) {
        return Some(ManagementRiskKind::Toggle);
    }
    if ["listen", "host", "port", "bind"]
        .iter()
        .any(|kw| lower.contains(kw))
    {
        return Some(ManagementRiskKind::Listen);
    }
    None
}

fn risk_advice(kind: ManagementRiskKind) -> &'static str {
    match kind {
        ManagementRiskKind::Listen => {
            "监听面变更——确认新地址可达后再 arm 窗口；旧地址仅在回滚候选中保留"
        }
        ManagementRiskKind::Auth => {
            "凭证面变更——新凭证须先在宿主侧验证可用；旧凭证不保留在报告面（脱敏纪律）"
        }
        ManagementRiskKind::Toggle => {
            "开关面变更——关闭管理通路前先准备带外恢复路径（宿主侧定时探测 + 回滚候选）"
        }
    }
}

// —— 2/3 定时确认与事务化恢复（交付二/三）——

/// 确认中状态（daemon 侧——与客户端连接无关）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogSnapshot {
    /// 受试 apply 的幂等键（回执寻址）
    pub receipt_key: String,
    /// 受试产物代际（自回执取得——不信任转述）
    pub generation: String,
    /// arm 时刻（epoch 毫秒）
    pub armed_ms: u64,
    /// 确认时限（epoch 毫秒——重启后不重置）
    pub deadline_ms: u64,
    /// 窗口内缺失计数
    pub misses: u32,
}

/// 确认中的内部状态（与快照同形——快照即其持久化面）。
type ConfirmingState = WatchdogSnapshot;

/// 看门狗裁决（宿主定时器的读数口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchdogVerdict {
    /// 无确认窗口
    Idle,
    /// 确认中——窗口未到期
    Confirming {
        /// 受试回执键
        receipt_key: String,
        /// 受试代际
        generation: String,
        /// 剩余窗口（毫秒）
        remaining_ms: u64,
        /// 缺失计数
        misses: u32,
    },
    /// 窗口到点未确认——恢复到期
    Due {
        /// 受试回执键
        receipt_key: String,
        /// 受试代际
        generation: String,
        /// 逾期毫秒
        overdue_ms: u64,
        /// 缺失计数
        misses: u32,
    },
}

/// 事务化恢复计划（按回执恢复——执行归 RIL-077 `rollback_apply`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// 受试 apply 的幂等键
    pub receipt_key: String,
    /// 恢复候选代际（= 目标回执 base_generation——按回执恢复）
    pub candidate_generation: String,
    /// 恢复候选摘要（= 目标回执 base_hash）
    pub candidate_hash: String,
    /// 被回退的代际（= 目标回执产物——存量会话钉在其上，恢复同样
    /// 不恢复连接：见
    /// [`crate::rollback::CONNECTION_TRUTH_STATEMENT`])
    pub retired_generation: String,
    /// 窗口内缺失计数（恢复决策的观测面）
    pub misses: u32,
    /// 执行前提示（固定步骤）
    pub guidance: Vec<&'static str>,
}

/// 恢复结果裁决（daemon 重启半边的验收面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeOutcome {
    /// 无快照——空闲
    Idle,
    /// 快照与账本对上——窗口照旧重立（deadline 不重置）
    Reinstated {
        /// 受试回执键
        receipt_key: String,
        /// 受试代际
        generation: String,
        /// 原时限（不重置）
        deadline_ms: u64,
    },
    /// 快照与账本对不上（回执被 prune / 非 Applied / 产物代际不符）
    /// ——事务面已变，确认失效直接解除（不信快照单方面之言）
    TargetGone {
        /// 受试回执键
        receipt_key: String,
        /// 失配稳定码（`watchdog.target.unknown` / `watchdog.target.gone`）
        code: &'static str,
    },
}

/// 看门狗错误（文案可演进，`code()` 恒定）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WatchdogError {
    /// 输入标签非法
    #[error("{CODE_WATCHDOG_INPUT_INVALID}: 输入字段非法: {field}")]
    InputInvalid {
        /// 人读字段名（稳定字面量）
        field: &'static str,
    },
    /// 确认窗口非法
    #[error("{CODE_WATCHDOG_WINDOW_INVALID}: 确认窗口须在 (0, {WATCHDOG_MAX_WINDOW_MS}] 毫秒")]
    WindowInvalid,
    /// 确认代际不符
    #[error("{CODE_WATCHDOG_GENERATION_MISMATCH}: 确认代际与受试代际不符——探错对象不算确认")]
    GenerationMismatch,
    /// 窗口已过
    #[error("{CODE_WATCHDOG_WINDOW_EXPIRED}: 确认窗口已到点——迟到的确认不清窗，恢复已到期")]
    WindowExpired,
    /// 未到期
    #[error("{CODE_WATCHDOG_NOT_DUE}: 确认窗口未到期——看门狗不早退")]
    NotDue,
    /// 目标回执不在册
    #[error("{CODE_WATCHDOG_TARGET_UNKNOWN}: 目标回执键在账无记录")]
    TargetUnknown,
    /// 目标回执事务面已变
    #[error("{CODE_WATCHDOG_TARGET_GONE}: 目标回执已非受试时的 Applied/产物——事务面已变")]
    TargetGone,
    /// 现役已前进（盲覆盖防线）
    #[error("{CODE_WATCHDOG_LIVE_MOVED}: 现役代际已前进——恢复会盲覆盖带外变更，先核实再决策")]
    LiveMoved,
    /// 恢复验证失配
    #[error("{CODE_WATCHDOG_VERIFY_MISMATCH}: 恢复验证失配: {detail}")]
    VerifyMismatch {
        /// 人读细节（稳定码组合，不含敏感值）
        detail: String,
    },
}

impl WatchdogError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            WatchdogError::InputInvalid { .. } => CODE_WATCHDOG_INPUT_INVALID,
            WatchdogError::WindowInvalid => CODE_WATCHDOG_WINDOW_INVALID,
            WatchdogError::GenerationMismatch => CODE_WATCHDOG_GENERATION_MISMATCH,
            WatchdogError::WindowExpired => CODE_WATCHDOG_WINDOW_EXPIRED,
            WatchdogError::NotDue => CODE_WATCHDOG_NOT_DUE,
            WatchdogError::TargetUnknown => CODE_WATCHDOG_TARGET_UNKNOWN,
            WatchdogError::TargetGone => CODE_WATCHDOG_TARGET_GONE,
            WatchdogError::LiveMoved => CODE_WATCHDOG_LIVE_MOVED,
            WatchdogError::VerifyMismatch { .. } => CODE_WATCHDOG_VERIFY_MISMATCH,
        }
    }
}

/// 管理通路看门狗（纯状态机——定时器与探测归宿主）。
#[derive(Debug, Default, Clone)]
pub struct Watchdog {
    /// 确认中状态（None = 空闲）
    confirming: Option<ConfirmingState>,
}

impl Watchdog {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前是否在确认窗口内（快照读数口——宿主落盘用）。
    pub fn snapshot(&self) -> Option<WatchdogSnapshot> {
        self.confirming.clone()
    }

    /// 开确认窗口（交付二）：以目标回执寻址——受试代际自回执取得，
    /// 不信任调用方转述。回执须在册且 Applied；窗口须在 (0,
    /// [`WATCHDOG_MAX_WINDOW_MS`]]。后到 arm 覆盖先前窗口（与 RIL-023
    /// 「后到事件覆盖先前态」同纪律——窗口随最近一次可能断通路的变更）。
    pub fn arm(
        &mut self,
        ledger: &ApplyLedger,
        receipt_key: &str,
        window_ms: u64,
        now_ms: u64,
    ) -> Result<WatchdogSnapshot, WatchdogError> {
        validate_label(receipt_key).map_err(|_| WatchdogError::InputInvalid {
            field: "receipt_key",
        })?;
        if window_ms == 0 || window_ms > WATCHDOG_MAX_WINDOW_MS {
            return Err(WatchdogError::WindowInvalid);
        }
        let receipt = ledger
            .receipt(receipt_key)
            .ok_or(WatchdogError::TargetUnknown)?;
        if receipt.status != ApplyStatus::Applied {
            return Err(WatchdogError::TargetGone);
        }
        let generation = receipt.generation.clone().unwrap_or_default();
        if generation.is_empty() {
            return Err(WatchdogError::TargetGone);
        }
        let state = ConfirmingState {
            receipt_key: receipt_key.to_string(),
            generation,
            armed_ms: now_ms,
            deadline_ms: now_ms.saturating_add(window_ms),
            misses: 0,
        };
        self.confirming = Some(state.clone());
        Ok(state)
    }

    /// 宿主探测成功——确认应答（交付二）：代际须逐字 = 受试代际（探错
    /// 代际不算确认）；迟到的确认不清窗（恢复已到期）。
    pub fn confirm(&mut self, generation: &str, now_ms: u64) -> Result<(), WatchdogError> {
        let Some(state) = self.confirming.as_ref() else {
            return Err(WatchdogError::NotDue);
        };
        validate_label(generation).map_err(|_| WatchdogError::InputInvalid {
            field: "generation",
        })?;
        if generation != state.generation {
            return Err(WatchdogError::GenerationMismatch);
        }
        if now_ms >= state.deadline_ms {
            return Err(WatchdogError::WindowExpired);
        }
        self.confirming = None;
        Ok(())
    }

    /// 宿主探测失败——记缺失（交付二）：不立即判死（瞬时抖动容忍），
    /// 到点由 [`Watchdog::evaluate`] 裁决。
    pub fn miss(&mut self, reason: &str, now_ms: u64) -> Result<(), WatchdogError> {
        let Some(state) = self.confirming.as_mut() else {
            return Err(WatchdogError::NotDue);
        };
        validate_label(reason).map_err(|_| WatchdogError::InputInvalid { field: "reason" })?;
        if now_ms >= state.deadline_ms {
            return Err(WatchdogError::WindowExpired);
        }
        state.misses = state.misses.saturating_add(1);
        Ok(())
    }

    /// 宿主定时器读数（交付二）。
    pub fn evaluate(&self, now_ms: u64) -> WatchdogVerdict {
        let Some(state) = self.confirming.as_ref() else {
            return WatchdogVerdict::Idle;
        };
        if now_ms < state.deadline_ms {
            WatchdogVerdict::Confirming {
                receipt_key: state.receipt_key.clone(),
                generation: state.generation.clone(),
                remaining_ms: state.deadline_ms - now_ms,
                misses: state.misses,
            }
        } else {
            WatchdogVerdict::Due {
                receipt_key: state.receipt_key.clone(),
                generation: state.generation.clone(),
                overdue_ms: now_ms - state.deadline_ms,
                misses: state.misses,
            }
        }
    }

    /// 窗口到点 → 事务化恢复计划（交付三）：候选身份 = 目标回执
    /// base_*（按回执恢复）；核实现役未前进（盲覆盖防线）；目标回执
    /// 复核仍 Applied 且产物一致（事务面未变）。产出即解除窗口（一次性
    /// 移交——重复索取 `watchdog.not.due`）。
    pub fn take_recovery(
        &mut self,
        ledger: &ApplyLedger,
        live_generation: &str,
        now_ms: u64,
    ) -> Result<RecoveryPlan, WatchdogError> {
        let Some(state) = self.confirming.as_ref() else {
            return Err(WatchdogError::NotDue);
        };
        if now_ms < state.deadline_ms {
            return Err(WatchdogError::NotDue);
        }
        validate_label(live_generation).map_err(|_| WatchdogError::InputInvalid {
            field: "live_generation",
        })?;
        if live_generation != state.generation {
            return Err(WatchdogError::LiveMoved);
        }
        let receipt = ledger
            .receipt(&state.receipt_key)
            .ok_or(WatchdogError::TargetUnknown)?;
        if receipt.status != ApplyStatus::Applied
            || receipt.generation.as_deref() != Some(state.generation.as_str())
        {
            return Err(WatchdogError::TargetGone);
        }
        let plan = RecoveryPlan {
            receipt_key: state.receipt_key.clone(),
            candidate_generation: receipt.base_generation.clone(),
            candidate_hash: receipt.base_hash.clone(),
            retired_generation: state.generation.clone(),
            misses: state.misses,
            guidance: RECOVERY_GUIDANCE.to_vec(),
        };
        self.confirming = None;
        Ok(plan)
    }

    /// 恢复验证（验收「恢复并验证」）：宿主执行回滚后调用——恢复回执
    /// 须在册、Applied、产物代际 = 候选。
    pub fn verify_recovery(
        &self,
        ledger: &ApplyLedger,
        recovery_key: &str,
        expected_generation: &str,
    ) -> Result<(), WatchdogError> {
        validate_label(recovery_key).map_err(|_| WatchdogError::InputInvalid {
            field: "recovery_key",
        })?;
        validate_label(expected_generation).map_err(|_| WatchdogError::InputInvalid {
            field: "expected_generation",
        })?;
        let Some(receipt) = ledger.receipt(recovery_key) else {
            return Err(WatchdogError::VerifyMismatch {
                detail: "恢复回执未在账（回滚未执行或键不符）".to_string(),
            });
        };
        if receipt.status != ApplyStatus::Applied {
            return Err(WatchdogError::VerifyMismatch {
                detail: format!("恢复回执非 Applied（status {}）", receipt.status.code()),
            });
        }
        if receipt.generation.as_deref() != Some(expected_generation) {
            return Err(WatchdogError::VerifyMismatch {
                detail: format!(
                    "恢复产物代际不符（期望 {expected_generation}，实际 {}）",
                    receipt.generation_or_empty()
                ),
            });
        }
        Ok(())
    }

    /// daemon 重启恢复（验收「daemon 重启时仍按事务恢复并验证」）：
    /// 快照须与回执账对账——目标回执在册、Applied、产物代际逐字一致
    /// 才重立窗口（deadline 不重置）；对不上直接解除（账本是权威，
    /// 不信快照单方面之言）。
    pub fn resume(
        &mut self,
        snapshot: Option<WatchdogSnapshot>,
        ledger: &ApplyLedger,
    ) -> ResumeOutcome {
        let Some(snapshot) = snapshot else {
            return ResumeOutcome::Idle;
        };
        let Some(receipt) = ledger.receipt(&snapshot.receipt_key) else {
            self.confirming = None;
            return ResumeOutcome::TargetGone {
                receipt_key: snapshot.receipt_key,
                code: CODE_WATCHDOG_TARGET_UNKNOWN,
            };
        };
        if receipt.status != ApplyStatus::Applied
            || receipt.generation.as_deref() != Some(snapshot.generation.as_str())
        {
            self.confirming = None;
            return ResumeOutcome::TargetGone {
                receipt_key: snapshot.receipt_key,
                code: CODE_WATCHDOG_TARGET_GONE,
            };
        }
        self.confirming = Some(snapshot.clone());
        ResumeOutcome::Reinstated {
            receipt_key: snapshot.receipt_key,
            generation: snapshot.generation,
            deadline_ms: snapshot.deadline_ms,
        }
    }
}

const RECOVERY_GUIDANCE: &[&str] = &[
    "从发布 journal 暂存/保留目录恢复候选内容（<state_dir>/generations/<generation_id>）",
    "以现役面为基重新提案并批准（原 apply 凭证已核销）",
    "以新幂等键执行 rollback_apply——候选身份将逐字校验",
    "恢复同样不恢复连接——既有会话迁移由排空时限决定（RIL-023）",
];

/// 恢复失败修复指引（验收「恢复失败给出具体修复信息」）：按稳定码
/// 分类的具体步骤——未知码走默认三方核对（现役 / 磁盘 / 回执）。
pub fn repair_guidance(code: &str) -> Vec<&'static str> {
    match code {
        "rollback.live.moved" | "watchdog.live.moved" => vec![
            "核实现役来源（人工修改 / 订阅刷新 / 更晚 apply）——不要强制回滚",
            "以新现役为基重新提案并决策（带外变更须显式重定基）",
            "对账：ApplyLedger::reconcile(live_generation) 查回执尾与现役分歧",
        ],
        "rollback.candidate.mismatch" => vec![
            "重新从发布 journal 暂存/保留目录恢复候选（<state_dir>/generations/<generation_id>）",
            "校验候选摘要与目标回执 base_hash 逐字一致后重试（换新回滚键）",
        ],
        "rollback.target.not_applied" | "rollback.target.unknown" | "rollback.target.foreign" => vec![
            "目标回执不可回滚（非 Applied / 不在册 / 他人）——先核对手上的回执键",
            "对账 PublishCoordinator::reconcile() 解释磁盘目录与现役代际",
        ],
        "apply.execute.failed" => vec![
            "检查 side_effects 所有权登记与逆序撤销状态（OS 面补偿归执行侧）",
            "手动恢复：从保留代际目录恢复候选内容后按候选重提案",
            "对账 publish journal（publish 是提交点——未提交即不作数）",
        ],
        "apply.capacity" => vec![
            "先 ApplyLedger::prune_older_than 回收窗口外回执，再以新幂等键重试",
        ],
        "apply.base.conflict" | "apply.hash.conflict" => vec![
            "现役面已前进 / 内容漂移——旧提案失效，以当前现役为基重新提案",
        ],
        code if code.starts_with("approval.") => vec![
            "回滚须新授权：以现役面为基重新提案并批准（原凭证已核销或失配）",
            "有界自动化可用 PreauthorizedGrant 档内自批（次数与期限有界）",
        ],
        code if code.starts_with("proposal.") => vec![
            "提案已失效 / 越权 / 不存在——重新 create 提案（TTL 上限 24h）再走批准",
        ],
        _ => vec![
            "默认三方核对：现役（ApplyLedger::reconcile）/ 磁盘（PublishCoordinator::reconcile）/ 回执（ApplyLedger::receipt）",
            "三方一致后按候选重提案；仍失败则带外修复管理通路后人工对账",
        ],
    }
}

/// 标签纪律（与 apply / rollback / proposal / approval 面同款）。
fn validate_label(field: &str) -> Result<(), &'static str> {
    if field.is_empty() || field.chars().count() > 128 {
        return Err(CODE_WATCHDOG_INPUT_INVALID);
    }
    if field.chars().any(char::is_control) {
        return Err(CODE_WATCHDOG_INPUT_INVALID);
    }
    Ok(())
}

#[cfg(test)]
mod watchdog_tests {
    use super::*;
    use crate::apply::{ApplyRequest, ApplyResult, ExecutionOutcome, APPLY_LABEL_MAX_CHARS};
    use crate::approval::ApprovalAuthority;
    use crate::approval::ProposalApproval;
    use crate::proposal::ProposalStore;
    use crate::proposal::{new_proposal_id, ProposalInput};

    const OWNER: &str = "cli:local";
    const GEN_A: &str = "gen-a";
    const GEN_B: &str = "gen-b";
    const HASH_A: &str = "hash-a";
    const HASH_B: &str = "hash-b";

    fn input_on(gen_id: &str, hash: &str) -> ProposalInput {
        ProposalInput {
            base_generation: gen_id.to_string(),
            base_hash: hash.to_string(),
            owner: OWNER.to_string(),
            scope: vec!["management".to_string()],
            patch: serde_json::json!({"management": {"listen": "127.0.0.1:9100"}}),
            ttl_ms: 600_000,
        }
    }

    /// apply gen-A → gen-B 并返回受试回执键（幂等键 "k-sev"）。
    fn seed_severing_apply(
        ledger: &mut ApplyLedger,
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
    ) -> String {
        let p = proposals
            .create(new_proposal_id(), input_on(GEN_A, HASH_A), 0)
            .expect("登记提案");
        let a: ProposalApproval = approvals.approve(&p, None, 0, 600_000).expect("批准");
        let req = ApplyRequest {
            idempotency_key: "k-sev".to_string(),
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
            .expect("变更 apply 成功")
        {
            ApplyResult::Executed(_) => "k-sev".to_string(),
            _ => panic!("应是 Executed"),
        }
    }

    /// 交付一：管理通路关键段分类（listen/凭证/开关/宿主注入前缀）。
    #[test]
    fn risk_assessment_flags_management_paths() {
        let assessment = assess_management_risk(
            &[
                "management.listen",
                "management.admin_token",
                "management.enable",
                "routing.default_node",
            ],
            &["dns.listen"],
        );
        assert!(assessment.may_sever);
        assert_eq!(
            assessment.critical_paths,
            vec![
                "management.listen".to_string(),
                "management.admin_token".to_string(),
                "management.enable".to_string()
            ]
        );
        let kinds: Vec<&str> = assessment.risks.iter().map(|r| r.kind.code()).collect();
        assert_eq!(
            kinds,
            vec![
                "watchdog.risk.listen",
                "watchdog.risk.auth",
                "watchdog.risk.toggle"
            ]
        );
        assert!(
            assessment.advice.contains("确认窗口"),
            "总结建议点名确认窗口"
        );

        // 无管理通路变更：不预警；宿主注入段命中 diff 才预警
        let plain = assess_management_risk(&["routing.default_node"], &[]);
        assert!(!plain.may_sever);
        assert!(plain.advice.is_empty(), "无风险不预警");
        let injected_miss = assess_management_risk(&["udp.ipv6"], &["dns.listen"]);
        assert!(!injected_miss.may_sever, "注入段未命中 diff 不预警");
    }

    /// 交付二：arm → Confirming → confirm 逐字应答清窗 → Idle。
    #[test]
    fn arm_and_confirm_roundtrip() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        let state = watchdog
            .arm(&ledger, &key, WATCHDOG_DEFAULT_WINDOW_MS, 100)
            .expect("开窗");
        assert_eq!(state.generation, GEN_B, "受试代际自回执取得");
        assert_eq!(state.deadline_ms, 100 + WATCHDOG_DEFAULT_WINDOW_MS);

        match watchdog.evaluate(200) {
            WatchdogVerdict::Confirming {
                receipt_key,
                generation,
                remaining_ms,
                misses,
            } => {
                assert_eq!(receipt_key, "k-sev");
                assert_eq!(generation, GEN_B);
                assert!(remaining_ms > 0);
                assert_eq!(misses, 0);
            }
            other => panic!("应是 Confirming: {other:?}"),
        }

        // 探错代际不算确认
        let err = watchdog.confirm(GEN_A, 200).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_GENERATION_MISMATCH);

        watchdog.confirm(GEN_B, 200).expect("确认");
        assert!(matches!(watchdog.evaluate(300), WatchdogVerdict::Idle));
        assert!(watchdog.snapshot().is_none());
    }

    /// 迟到确认不清窗（恢复已到期）；窗口非法（0/超上限）拒绝。
    #[test]
    fn late_confirm_and_invalid_window_rejected() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        let err = watchdog.arm(&ledger, &key, 0, 0).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_WINDOW_INVALID);
        let err = watchdog
            .arm(&ledger, &key, WATCHDOG_MAX_WINDOW_MS + 1, 0)
            .unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_WINDOW_INVALID);

        watchdog.arm(&ledger, &key, 1_000, 100).expect("开窗");
        let err = watchdog.confirm(GEN_B, 1_100).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_WINDOW_EXPIRED);
        assert!(
            matches!(watchdog.evaluate(1_100), WatchdogVerdict::Due { .. }),
            "迟到的确认不清窗——恢复已到期"
        );
    }

    /// miss 累计与到点裁决；take_recovery 产出事务化计划并清窗（一次性）。
    #[test]
    fn misses_accrue_and_recovery_plan_is_transactional() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        watchdog.arm(&ledger, &key, 1_000, 100).expect("开窗");
        watchdog.miss("connection refused", 300).expect("记缺失");
        watchdog.miss("timeout", 500).expect("记缺失");
        assert!(matches!(
            watchdog.evaluate(600),
            WatchdogVerdict::Confirming { misses: 2, .. }
        ));

        // 未到期索取恢复：看门狗不早退
        let err = watchdog.take_recovery(&ledger, GEN_B, 600).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_NOT_DUE);

        // 到点：计划候选 = 回执 base_*（按回执恢复），一次清窗
        let plan = watchdog
            .take_recovery(&ledger, GEN_B, 1_200)
            .expect("到期产出恢复计划");
        assert_eq!(plan.receipt_key, "k-sev");
        assert_eq!(plan.candidate_generation, GEN_A);
        assert_eq!(plan.candidate_hash, HASH_A);
        assert_eq!(plan.retired_generation, GEN_B);
        assert_eq!(plan.misses, 2);
        assert!(!plan.guidance.is_empty(), "执行前提示在场");
        assert!(
            matches!(watchdog.evaluate(1_300), WatchdogVerdict::Idle),
            "计划移交即清窗"
        );
        let err = watchdog.take_recovery(&ledger, GEN_B, 1_300).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_NOT_DUE, "一次性移交");
    }

    /// 盲覆盖防线同样适用于恢复：现役前进后不产出计划。
    #[test]
    fn recovery_refuses_when_live_moved() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        watchdog.arm(&ledger, &key, 1_000, 100).expect("开窗");
        let err = watchdog.take_recovery(&ledger, "gen-x", 1_200).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_LIVE_MOVED);
    }

    /// 验收「客户端断开时仍按事务恢复并验证」：窗口是 daemon 侧状态
    /// ——断开不影响窗口语义（不重置不清零），miss 后照常可确认。
    #[test]
    fn client_disconnect_does_not_reset_window() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        watchdog.arm(&ledger, &key, 1_000, 100).expect("开窗");

        // 客户端断开（纯面无动作可做——窗口不受任何客户端事件影响）
        watchdog.miss("client gone", 400).expect("记缺失");
        // 客户端重连后探测成功：窗口保持原 deadline，确认有效
        watchdog.confirm(GEN_B, 900).expect("原窗口内确认");
        assert!(matches!(watchdog.evaluate(1_000), WatchdogVerdict::Idle));
    }

    /// 验收「daemon 重启时仍按事务恢复并验证」：快照与账本对账——
    /// 对上重立窗口（deadline 不重置）；对不上解除（账本是权威，
    /// 不信快照单方面之言——快照被篡改代际 / 回执被 prune 都 TargetGone）。
    #[test]
    fn restart_resumes_only_when_snapshot_agrees_with_ledger() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        let armed = watchdog.arm(&ledger, &key, 10_000, 100).expect("开窗");

        // —— daemon 重启：新进程新 watchdog，快照落盘面回来 ——
        let mut restarted = Watchdog::new();
        match restarted.resume(Some(armed.clone()), &ledger) {
            ResumeOutcome::Reinstated {
                receipt_key,
                generation,
                deadline_ms,
            } => {
                assert_eq!(receipt_key, "k-sev");
                assert_eq!(generation, GEN_B);
                assert_eq!(deadline_ms, armed.deadline_ms, "时限不重置");
            }
            other => panic!("应 Reinstated: {other:?}"),
        }
        // 重立后到点照常产出恢复计划
        let plan = restarted
            .take_recovery(&ledger, GEN_B, 10_200)
            .expect("到期恢复");
        assert_eq!(plan.candidate_generation, GEN_A);

        // —— 快照代际被篡改：与账本对不上，解除 ——
        let mut tampered = armed.clone();
        tampered.generation = "gen-fake".to_string();
        let mut w2 = Watchdog::new();
        match w2.resume(Some(tampered), &ledger) {
            ResumeOutcome::TargetGone { code, .. } => assert_eq!(code, CODE_WATCHDOG_TARGET_GONE),
            other => panic!("应 TargetGone: {other:?}"),
        }
        assert!(w2.snapshot().is_none(), "解除后无窗口");

        // —— 回执被 prune：TargetUnknown ——
        let mut prunable = ApplyLedger::new();
        let mut props = ProposalStore::new();
        let mut appr = ApprovalAuthority::new();
        let key2 = seed_severing_apply_named(&mut prunable, &mut props, &mut appr, "k-prune");
        let mut w3 = Watchdog::new();
        let armed3 = w3.arm(&prunable, &key2, 10_000, 100).expect("开窗");
        prunable.prune_older_than(10_000, 100);
        match w3.resume(Some(armed3), &prunable) {
            ResumeOutcome::TargetGone { code, .. } => {
                assert_eq!(code, CODE_WATCHDOG_TARGET_UNKNOWN)
            }
            other => panic!("应 TargetUnknown: {other:?}"),
        }

        // 无快照：Idle
        assert!(matches!(
            Watchdog::new().resume(None, &ledger),
            ResumeOutcome::Idle
        ));
    }

    /// 验收「恢复并验证」全环：计划 → rollback_apply 执行 → verify_recovery
    /// 校验恢复回执 Applied 且产物 = 候选；失败回执验证失配。
    #[test]
    fn recovery_executes_via_rollback_and_verifies() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        watchdog.arm(&ledger, &key, 1_000, 100).expect("开窗");
        let plan = watchdog
            .take_recovery(&ledger, GEN_B, 1_200)
            .expect("到期恢复");

        // 按计划走 RIL-077 回滚（新提案 + 新凭证，以现役 gen-B 为基）
        let p = proposals
            .create(new_proposal_id(), input_on(GEN_B, HASH_B), 2)
            .expect("登记回滚提案");
        let a = approvals.approve(&p, None, 2, 600_000).expect("批准回滚");
        let report = crate::rollback::rollback_apply(
            &mut ledger,
            &mut proposals,
            &mut approvals,
            crate::rollback::RollbackRequest {
                idempotency_key: "k-recover".to_string(),
                target_key: plan.receipt_key.clone(),
                proposal_id: p.id,
                approval_id: Some(a.approval_id),
                caller_owner: OWNER.to_string(),
                live_generation: GEN_B.to_string(),
                live_hash: HASH_B.to_string(),
                candidate_generation: plan.candidate_generation.clone(),
                candidate_hash: plan.candidate_hash.clone(),
                drain_deadline_ms: Some(6_000),
            },
            3,
            |_| {
                Ok(crate::rollback::RollbackExecution {
                    generation_id: plan.candidate_generation.clone(),
                    os_applied: true,
                    capabilities_validated: true,
                })
            },
        )
        .expect("恢复回滚成功");

        // 验证：恢复回执 Applied 且产物 = 候选
        watchdog
            .verify_recovery(&ledger, "k-recover", &plan.candidate_generation)
            .expect("恢复验证通过");
        assert_eq!(report.receipt.generation_or_empty(), GEN_A);

        // 失败的恢复验证失配（键不符 / 代际不符）
        let err = watchdog
            .verify_recovery(&ledger, "k-missing", GEN_A)
            .unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_VERIFY_MISMATCH);
        let err = watchdog
            .verify_recovery(&ledger, "k-recover", GEN_B)
            .unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_VERIFY_MISMATCH);
    }

    /// 验收「恢复失败给出具体修复信息」：按稳定码分类的具体步骤，
    /// 未知码走默认三方核对。
    #[test]
    fn repair_guidance_maps_failure_codes_concretely() {
        let cases: Vec<(&str, &str)> = vec![
            ("rollback.live.moved", "重定基"),
            ("rollback.candidate.mismatch", "journal"),
            (
                "rollback.target.not_applied",
                "PublishCoordinator::reconcile",
            ),
            ("apply.execute.failed", "side_effects"),
            ("apply.capacity", "prune_older_than"),
            ("apply.base.conflict", "重新提案"),
            ("approval.stale", "新授权"),
            ("proposal.expired", "重新 create 提案"),
        ];
        for (code, keyword) in cases {
            let steps = repair_guidance(code);
            assert!(!steps.is_empty(), "{code} 须有具体步骤");
            let joined = steps.join(" | ");
            assert!(
                joined.contains(keyword),
                "{code} 步骤须点名 {keyword}: {joined}"
            );
        }
        // 未知码：默认三方核对
        let fallback = repair_guidance("some.unknown.code");
        assert!(fallback[0].contains("PublishCoordinator::reconcile"));
    }

    /// 输入面：arm 非法回执键 / confirm 非法代际 / miss 非法理由。
    #[test]
    fn input_labels_validated() {
        let mut ledger = ApplyLedger::new();
        let mut proposals = ProposalStore::new();
        let mut approvals = ApprovalAuthority::new();
        let key = seed_severing_apply(&mut ledger, &mut proposals, &mut approvals);

        let mut watchdog = Watchdog::new();
        let err = watchdog.arm(&ledger, "", 1_000, 0).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_INPUT_INVALID);
        let err = watchdog
            .arm(&ledger, &"x".repeat(APPLY_LABEL_MAX_CHARS + 1), 1_000, 0)
            .unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_INPUT_INVALID);

        watchdog.arm(&ledger, &key, 1_000, 100).expect("开窗");
        let err = watchdog.confirm("bad\u{7}gen", 200).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_INPUT_INVALID);
        let err = watchdog.miss("", 200).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_INPUT_INVALID);

        // 目标不在册 / 非 Applied
        let err = watchdog.arm(&ledger, "k-missing", 1_000, 200).unwrap_err();
        assert_eq!(err.code(), CODE_WATCHDOG_TARGET_UNKNOWN);
    }

    /// 以指定幂等键登记一条可能断通路的 apply（restart 用例复用）。
    fn seed_severing_apply_named(
        ledger: &mut ApplyLedger,
        proposals: &mut ProposalStore,
        approvals: &mut ApprovalAuthority,
        key: &str,
    ) -> String {
        let p = proposals
            .create(new_proposal_id(), input_on(GEN_A, HASH_A), 0)
            .expect("登记提案");
        let a = approvals.approve(&p, None, 0, 600_000).expect("批准");
        let req = ApplyRequest {
            idempotency_key: key.to_string(),
            proposal_id: p.id,
            approval_id: Some(a.approval_id),
            caller_owner: OWNER.to_string(),
            live_generation: GEN_A.to_string(),
            live_hash: HASH_A.to_string(),
        };
        let result = ledger
            .execute(proposals, approvals, req, 1, |_| {
                Ok(ExecutionOutcome {
                    generation_id: GEN_B.to_string(),
                    os_applied: true,
                })
            })
            .expect("apply 成功");
        assert!(matches!(result, ApplyResult::Executed(_)));
        key.to_string()
    }
}
