//! RIL-140 选路模式覆盖预览与有效回执（纯面，零 IO 零时钟）。
//!
//! 设计口径（ui-prototype-v1.md §3）：普通订阅 REJECT 不是硬性安全拒绝，
//! 全局/直连绕过普通路由规则时必须在预览里**明示影响**，不能含糊承诺
//! 「所有拦截保持」。本模块给出两份纯推演报告：
//!
//! - [`mode_override_preview`]：切换到请求模式前的影响预览——暂停哪些
//!   场景/规则、其中哪些是普通 REJECT 拦截、逐模式固定说明（认证/资源
//!   限制/硬性拒绝/防环不受影响；模式不改变 DNS 应答；仅作用已接管流）；
//! - [`mode_receipt`]：应用后的有效回执——已请求模式、已生效模式（读
//!   自发布代际的 routing 面）、代际与冲突（请求≠生效时点名，不静默）。
//!
//! 控制面（HTTP/CLI/MCP）接线归 rillaned；本面只交付可核验的纯契约。

use serde::Serialize;

use crate::RoutingConfig;
use crate::SelectionMode;

/// 内建拒绝出口的规则 target 名（G0-5 reject 出口；路由规则以
/// `target: reject` 引用）。普通 REJECT 规则在全局/直连模式下随普通
/// 规则面一起暂停——这不是硬性安全边界，预览必须点名。
pub const REJECT_TARGET: &str = "reject";

/// 选路模式覆盖预览（RIL-140）：切换前的影响明示。全部字段可序列化，
/// 无敏感值（只含规则/场景名与固定说明文案）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeOverridePreview {
    /// 请求切换到的模式
    pub requested: SelectionMode,
    /// 当前配置的模式
    pub current: SelectionMode,
    /// 全局/直连下暂停的场景名（声明序；规则模式为空）
    pub paused_scenarios: Vec<String>,
    /// 全局/直连下暂停的普通规则名（声明序；规则模式为空）
    pub paused_rules: Vec<String>,
    /// 暂停规则中 target 为 reject 的普通 REJECT 拦截（子集；预览点名
    /// ——这些拦截在全局/直连下不再生效，不是「所有拦截保持」）
    pub paused_reject_rules: Vec<String>,
    /// 逐模式固定说明（口径见模块文档）
    pub note: String,
}

/// 切换预览：纯推演，不改配置。规则模式 = 无覆盖（空列表 + 固定说明）；
/// 全局/直连 = 场景与普通规则全量暂停、REJECT 子集点名。
pub fn mode_override_preview(
    config: &RoutingConfig,
    requested: SelectionMode,
) -> ModeOverridePreview {
    let current = config.mode;
    let (paused_scenarios, paused_rules, paused_reject_rules, note) = match requested {
        SelectionMode::Rule => {
            let note = "规则模式：场景、区域与普通规则按声明优先级正常求值，无覆盖。".to_string();
            (Vec::new(), Vec::new(), Vec::new(), note)
        }
        SelectionMode::Global | SelectionMode::Direct => {
            let paused_scenarios: Vec<String> =
                config.scenarios.iter().map(|s| s.name.clone()).collect();
            let paused_rules: Vec<String> = config.rules.iter().map(|r| r.name.clone()).collect();
            let paused_reject_rules: Vec<String> = config
                .rules
                .iter()
                .filter(|r| r.target.trim().eq_ignore_ascii_case(REJECT_TARGET))
                .map(|r| r.name.clone())
                .collect();
            let note = if requested == SelectionMode::Global {
                "全局模式：普通场景/区域/规则求值暂停（含上列普通 REJECT 拦截——\
                 普通订阅 REJECT 不是硬性安全拒绝）；身份认证、资源限制、硬性\
                 安全拒绝与防环仍生效；模式不改变 DNS 应答；仅作用已接管业务流；\
                 全局出口不可用时按显式失败返回，不静默落直连。"
                    .to_string()
            } else {
                "直连模式：已接管业务流走显式直连出口——普通场景/区域/规则求值\
                 暂停（含上列普通 REJECT 拦截，同全局模式口径）；不等于关闭 \
                 TUN/VPN、DNS、统计或系统代理配置；身份认证、资源限制、硬性\
                 安全拒绝与防环仍生效；模式不改变 DNS 应答。"
                    .to_string()
            };
            (paused_scenarios, paused_rules, paused_reject_rules, note)
        }
    };
    ModeOverridePreview {
        requested,
        current,
        paused_scenarios,
        paused_rules,
        paused_reject_rules,
        note,
    }
}

/// 选路模式有效回执（RIL-140）：应用后读发布代际的 routing 面回填
/// 「已生效」，与请求不一致时点名冲突（代际回执链的模式面投影）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeReceipt {
    /// 已请求模式
    pub requested: SelectionMode,
    /// 已生效模式（读自发布代际的 routing 配置）
    pub effective: SelectionMode,
    /// 发布代际 ID（控制面接线时回填；纯面调用可为 None）
    pub generation_id: Option<String>,
    /// 冲突清单：请求 ≠ 生效时给出可读条目（不静默吞差异）
    pub conflicts: Vec<String>,
}

/// 有效回执：`requested` 与发布代际 routing 面的实际模式比对——一致 =
/// 空冲突；不一致 = 点名双方与代际（调用方据此决定重试或人工介入，
/// 本面不自动重发）。
pub fn mode_receipt(
    requested: SelectionMode,
    published: &RoutingConfig,
    generation_id: Option<&str>,
) -> ModeReceipt {
    let effective = published.mode;
    let mut conflicts = Vec::new();
    if effective != requested {
        conflicts.push(format!(
            "已生效模式 {effective:?} 与请求 {requested:?} 不一致（代际 {}）",
            generation_id.unwrap_or("<未提供>")
        ));
    }
    ModeReceipt {
        requested,
        effective,
        generation_id: generation_id.map(str::to_string),
        conflicts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchCondition, RouteRule, ScenarioFailureAction, ScenarioRule};

    fn rule(name: &str, target: &str) -> RouteRule {
        RouteRule {
            name: name.to_string(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["example.test".to_string()],
            }],
            target: target.to_string(),
        }
    }

    fn config(mode: SelectionMode) -> RoutingConfig {
        RoutingConfig {
            mode,
            scenarios: vec![ScenarioRule {
                name: "game-scene".to_string(),
                conditions: Vec::new(),
                target: "game-group".to_string(),
                priority: 10,
                on_failure: ScenarioFailureAction::Fallback,
            }],
            rules: vec![
                rule("ads-block", REJECT_TARGET),
                rule("cn-direct", "direct-main"),
                rule("proxy-rule", "proxy-group"),
            ],
            ..RoutingConfig::default()
        }
    }

    #[test]
    fn rule_mode_preview_reports_no_override() {
        let p = mode_override_preview(&config(SelectionMode::Rule), SelectionMode::Rule);
        assert_eq!(p.requested, SelectionMode::Rule);
        assert_eq!(p.current, SelectionMode::Rule);
        assert!(p.paused_scenarios.is_empty());
        assert!(p.paused_rules.is_empty());
        assert!(p.paused_reject_rules.is_empty());
        assert!(p.note.contains("无覆盖"));
    }

    #[test]
    fn global_preview_pauses_rules_and_names_reject_impact() {
        let p = mode_override_preview(&config(SelectionMode::Rule), SelectionMode::Global);
        assert_eq!(p.paused_scenarios, vec!["game-scene".to_string()]);
        assert_eq!(
            p.paused_rules,
            vec![
                "ads-block".to_string(),
                "cn-direct".to_string(),
                "proxy-rule".to_string()
            ]
        );
        // 普通 REJECT 点名：只有 target=reject 的规则进 REJECT 清单
        assert_eq!(p.paused_reject_rules, vec!["ads-block".to_string()]);
        assert!(p.note.contains("REJECT"));
        assert!(p.note.contains("不是硬性安全拒绝"));
        assert!(p.note.contains("不改变 DNS 应答"));
        assert!(p.note.contains("不静默落直连"));
    }

    #[test]
    fn direct_preview_states_scope_and_bounds() {
        let p = mode_override_preview(&config(SelectionMode::Global), SelectionMode::Direct);
        assert_eq!(p.current, SelectionMode::Global);
        assert_eq!(p.paused_reject_rules, vec!["ads-block".to_string()]);
        assert!(p.note.contains("直连"));
        assert!(p.note.contains("不等于关闭"));
        assert!(p.note.contains("不改变 DNS 应答"));
    }

    #[test]
    fn receipt_matches_when_effective_equals_requested() {
        let published = config(SelectionMode::Global);
        let r = mode_receipt(SelectionMode::Global, &published, Some("gen-b"));
        assert_eq!(r.effective, SelectionMode::Global);
        assert_eq!(r.generation_id.as_deref(), Some("gen-b"));
        assert!(r.conflicts.is_empty());
    }

    #[test]
    fn receipt_names_conflict_when_effective_differs() {
        let published = config(SelectionMode::Rule);
        let r = mode_receipt(SelectionMode::Global, &published, Some("gen-c"));
        assert_eq!(r.effective, SelectionMode::Rule);
        assert_eq!(r.requested, SelectionMode::Global);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].contains("Rule") && r.conflicts[0].contains("Global"));
        assert!(r.conflicts[0].contains("gen-c"));
    }

    #[test]
    fn preview_reject_target_is_case_insensitive_and_trimmed() {
        let mut cfg = config(SelectionMode::Rule);
        cfg.rules[0].target = "  Reject ".to_string();
        let p = mode_override_preview(&cfg, SelectionMode::Global);
        assert_eq!(p.paused_reject_rules, vec!["ads-block".to_string()]);
    }
}
