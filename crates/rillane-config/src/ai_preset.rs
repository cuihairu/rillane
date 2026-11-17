//! AI/LLM 提供商分流规则模板（RIL-153，口径 [ai-routing.md]）。
//!
//! 识别面只含**域名条件**（`domain_suffix` / `domain_keyword` / `domain_full`，
//! 现有 `MatchCondition` 即可表达，不新增引擎）——不猜流量内容：SNI/HTTP 头
//! 特征依赖 RIL-143 有界证据面（后续接入，模板首版不含），无 UDP 面（主流
//! AI 提供商 API 均为 HTTPS/TCP，如实标注不预留不宣称）。模板为 in-tree
//! 版本化常量，不远程拉取（无供应链面）。
//!
//! 合入/摘除（RIL-153 `ai on` / `ai off` 语义）：
//! - [`RoutingConfig::apply_ai_preset`]：按 `ai-` 前缀摘除在场模板规则后
//!   重插模板（目标切换 = 摘旧插新，幂等）；插入位置在**泛化区域规则之前**
//!   （第一个 `region-` 规则处，无区域规则则追加尾部——区域预设展开在配置
//!   装载时进行，其规则在场即排在模板之后，先命中先决策）；
//! - [`RoutingConfig::remove_ai_preset`]：按 `ai-` 前缀摘除，用户规则零触碰；
//!   无在场模板规则为 no-op（幂等）。
//!
//! 命名空间：`ai-` 前缀规则名归本模板所有（CLI on/off 按前缀寻址）——用户
//! 自建规则不得占用该前缀（文档明示；前缀内规则随 on/off 被替换/摘除）。
//! 预设规则即普通规则：全局/直连选路模式下面向暂停清单（`mode_override_preview`）
//! 与既有规则同口径，不是硬性安全边界。

use crate::{MatchCondition, RouteRule, RoutingConfig};
use crate::region_preset::REGION_RULE_PREFIX;

/// 模板版本（in-tree 域名表随版本发布，来源可查）
pub const AI_PRESET_VERSION: u32 = 1;

/// 模板规则名前缀（合入/摘除的寻址命名空间）
pub const AI_RULE_PREFIX: &str = "ai-";

pub const AI_OPENAI_RULE: &str = "ai-openai";
pub const AI_ANTHROPIC_RULE: &str = "ai-anthropic";
pub const AI_GEMINI_RULE: &str = "ai-gemini";
pub const AI_OTHER_RULE: &str = "ai-other";

/// 规则名是否属模板命名空间（`ai-` 前缀）
pub fn is_ai_preset_rule(name: &str) -> bool {
    name.starts_with(AI_RULE_PREFIX)
}

/// 模板规则（域名面首版；`target` 由用户指定——组名或直连节点名）。
/// 规则内多条件为 AND，`any` 内为 OR；四条按 first-match-wins 依次评估，
/// 命中的 `reason` 即规则名（诊断面逐提供商可分辨）。
pub fn ai_preset_rules(target: &str) -> Vec<RouteRule> {
    let rule = |name: &'static str, conditions: Vec<MatchCondition>| RouteRule {
        name: name.to_string(),
        matches: vec![MatchCondition::Any { conditions }],
        target: target.to_string(),
    };
    vec![
        rule(
            AI_OPENAI_RULE,
            vec![
                MatchCondition::DomainSuffix {
                    values: vec![
                        "openai.com".into(),
                        "oaistatic.com".into(),
                        "oaiusercontent.com".into(),
                    ],
                },
                // CDN 承载面：第三方域名中含 openai 字样
                MatchCondition::DomainKeyword {
                    values: vec!["openai".into()],
                },
            ],
        ),
        rule(
            AI_ANTHROPIC_RULE,
            vec![
                MatchCondition::DomainSuffix {
                    values: vec!["anthropic.com".into(), "claude.ai".into()],
                },
                MatchCondition::DomainKeyword {
                    values: vec!["anthropic".into()],
                },
            ],
        ),
        // Gemini 主域精确面（子域面过大，按 full 逐个点名）
        rule(
            AI_GEMINI_RULE,
            vec![MatchCondition::DomainFull {
                values: vec!["gemini.google.com".into(), "aistudio.google.com".into()],
            }],
        ),
        // 示例：自有/小众端点按需补 full/suffix（用户规则可自由扩展）
        rule(
            AI_OTHER_RULE,
            vec![MatchCondition::DomainFull {
                values: vec!["api.kaipulse.com".into()],
            }],
        ),
    ]
}

/// 模板规则名（观测/诊断面与 on/off 寻址）
pub fn ai_rule_names() -> Vec<&'static str> {
    vec![
        AI_OPENAI_RULE,
        AI_ANTHROPIC_RULE,
        AI_GEMINI_RULE,
        AI_OTHER_RULE,
    ]
}

impl RoutingConfig {
    /// AI 模板合入（RIL-153 `ai on` 语义）：先按 `ai-` 前缀摘除在场模板
    /// 规则，再把模板插在泛化区域规则之前（见模块注释），用户规则零触碰。
    /// 幂等：同目标重复调用规则面零差异；目标切换 = 摘旧插新。
    /// 返回 (摘除数, 插入数)。
    pub fn apply_ai_preset(&mut self, target: &str) -> (usize, usize) {
        let removed = self.remove_ai_preset();
        let insert_at = self
            .rules
            .iter()
            .position(|r| r.name.starts_with(REGION_RULE_PREFIX))
            .unwrap_or(self.rules.len());
        let template = ai_preset_rules(target);
        let added = template.len();
        let tail = self.rules.split_off(insert_at);
        self.rules.extend(template);
        self.rules.extend(tail);
        (removed, added)
    }

    /// AI 模板摘除（RIL-153 `ai off` 语义）：按 `ai-` 前缀移除，用户规则
    /// 不触碰；无在场模板规则为 no-op（幂等）。返回摘除数。
    pub fn remove_ai_preset(&mut self) -> usize {
        let before = self.rules.len();
        self.rules.retain(|r| !is_ai_preset_rule(&r.name));
        before - self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 条件面收口：模板只含域名条件（suffix/keyword/full）——无端口/IP/
    /// 进程/Geo 条件（不猜流量内容、不泛化劫持）
    #[test]
    fn template_is_domain_only() {
        for rule in ai_preset_rules("proxy") {
            assert!(rule.name.starts_with(AI_RULE_PREFIX));
            assert_eq!(rule.target, "proxy");
            for m in &rule.matches {
                let MatchCondition::Any { conditions } = m else {
                    panic!("模板条件应为 any 包裹: {}", rule.name);
                };
                for c in conditions {
                    assert!(
                        matches!(
                            c,
                            MatchCondition::DomainSuffix { .. }
                                | MatchCondition::DomainKeyword { .. }
                                | MatchCondition::DomainFull { .. }
                        ),
                        "模板出现非域名条件（{}）: {c:?}",
                        rule.name
                    );
                }
            }
        }
    }

    /// openai/anthropic 带 CDN keyword 面；gemini/other 为 full 精确面
    #[test]
    fn template_shapes() {
        let rules = ai_preset_rules("t");
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].name, AI_OPENAI_RULE);
        assert_eq!(rules[1].name, AI_ANTHROPIC_RULE);
        let suffix_of = |r: &RouteRule| r
            .matches
            .iter()
            .flat_map(|m| match m {
                MatchCondition::Any { conditions } => conditions.clone(),
                _ => vec![],
            })
            .any(|c| matches!(c, MatchCondition::DomainSuffix { .. }));
        let keyword_of = |r: &RouteRule| r
            .matches
            .iter()
            .flat_map(|m| match m {
                MatchCondition::Any { conditions } => conditions.clone(),
                _ => vec![],
            })
            .any(|c| matches!(c, MatchCondition::DomainKeyword { .. }));
        assert!(suffix_of(&rules[0]) && keyword_of(&rules[0]), "openai 面");
        assert!(suffix_of(&rules[1]) && keyword_of(&rules[1]), "anthropic 面");
        assert!(!suffix_of(&rules[2]), "gemini 为 full 精确面");
        assert!(!suffix_of(&rules[3]), "other 为 full 精确面");
    }

    /// 幂等与目标切换：重复 on 规则面零差异；换 target = 摘旧插新；
    /// 用户规则零触碰（含非前缀名规则、前缀名规则归模板命名空间）
    #[test]
    fn apply_idempotent_and_target_switch() {
        let mut r = RoutingConfig::default();
        r.rules.push(RouteRule {
            name: "user-web".into(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["example.com".into()],
            }],
            target: "direct-main".into(),
        });
        let (removed, added) = r.apply_ai_preset("ai-proxy");
        assert_eq!((removed, added), (0, 4));
        let snapshot_len = r.rules.len();
        let again = r.apply_ai_preset("ai-proxy");
        assert_eq!(again, (4, 4), "同目标重 on = 摘旧插新，规则面零差异");
        assert_eq!(r.rules.len(), snapshot_len);
        assert_eq!(r.rules.iter().filter(|x| x.name == "user-web").count(), 1);
        assert!(r.rules.iter().all(|x| !is_ai_preset_rule(&x.name) || x.target == "ai-proxy"));

        let _ = r.apply_ai_preset("other-group");
        assert!(
            r.rules
                .iter()
                .all(|x| !is_ai_preset_rule(&x.name) || x.target == "other-group"),
            "目标切换后全部模板指向新 target"
        );
        // 模板命名空间：用户占用 ai- 前缀的规则同样按前缀被摘除（文档明示）
        r.rules.push(RouteRule {
            name: "ai-user-custom".into(),
            matches: vec![MatchCondition::DomainFull {
                values: vec!["custom.example".into()],
            }],
            target: "x".into(),
        });
        let removed = r.remove_ai_preset();
        assert_eq!(removed, 5, "off 摘除全部 ai- 前缀规则");
        assert_eq!(r.rules.len(), 1, "user-web 保留");
    }

    /// 合入位置：泛化区域规则之前（region- 规则在场即插其前；
    /// 无区域规则则追加尾部）
    #[test]
    fn insert_position_before_region_rules() {
        let mut with_region = RoutingConfig::default();
        with_region.rules.push(RouteRule {
            name: "user-first".into(),
            matches: vec![MatchCondition::Geoip {
                country: "CN".into(),
            }],
            target: "d".into(),
        });
        with_region.rules.push(RouteRule {
            name: "region-cn-domain".into(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["cn".into()],
            }],
            target: "d".into(),
        });
        with_region.rules.push(RouteRule {
            name: "region-cn-ip".into(),
            matches: vec![MatchCondition::IpCidr {
                cidrs: vec!["10.0.0.0/8".into()],
            }],
            target: "d".into(),
        });
        with_region.apply_ai_preset("p");
        let names: Vec<_> = with_region.rules.iter().map(|r| r.name.as_str()).collect();
        let ai_first = names.iter().position(|n| n.starts_with(AI_RULE_PREFIX)).unwrap();
        let region_first = names.iter().position(|n| n.starts_with("region-")).unwrap();
        assert_eq!(&names[..ai_first], &["user-first"][..], "用户规则仍在前");
        assert!(ai_first < region_first, "模板须在泛化区域规则之前: {names:?}");

        let mut no_region = RoutingConfig::default();
        no_region.rules.push(RouteRule {
            name: "user-only".into(),
            matches: vec![MatchCondition::Geoip {
                country: "US".into(),
            }],
            target: "d".into(),
        });
        no_region.apply_ai_preset("p");
        assert_eq!(no_region.rules.len(), 5);
        assert_eq!(no_region.rules.last().unwrap().name, AI_OTHER_RULE, "无区域规则追加尾部");
    }

    /// 模板往返零损失（验收锚点）：合入 → YAML 导出 → 回读，规则面逐字节等价
    #[test]
    fn template_roundtrip_via_yaml_lossless() {
        let mut config = RoutingConfig::default();
        config.rules.push(RouteRule {
            name: "user-keep".into(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["example.com".into()],
            }],
            target: "direct-main".into(),
        });
        config.apply_ai_preset("ai-proxy");
        let yaml = serde_yaml::to_string(&config).expect("导出");
        let back: RoutingConfig = serde_yaml::from_str(&yaml).expect("回读");
        assert_eq!(back.rules, config.rules, "合入 → 导出 → 回读零损失");
    }
}
