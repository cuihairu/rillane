//! RIL-146 Git/SSH/GitHub 路由预设（纯面）。
//!
//! 口径：in-tree 版本化预设——Git HTTPS/API、release/LFS/下载（重定向
//! CDN 面）与 Git over SSH 的域名/端口规则模板；展开追加在用户规则之后、
//! 泛化区域规则之前（先用户 → 应用预设 → 区域），同名规则/规则集用户
//! 显式声明优先、模板退让、重复展开幂等。
//!
//! 边界（验收原文）：
//! - **连通不等于加速**：预设只按域名/端口改写路由走向，不承诺 Git 传输
//!   更快——速度取决于所选出口的实际链路质量；
//! - **SSH 主机密钥与认证保持**：预设只做「移动哪些域名/端口」的域名
//!   能力路由，SSH 的 known_hosts/主机密钥校验与端到端认证不受影响，
//!   也不把 SSH 面混同成 HTTPS 出口协议（载体协议由出口自身决定）；
//! - **样例种子非全量**：重定向/下载 CDN 域以各托管商官方文档为准，
//!   用户规则可自由扩展；规则来源卡片随预览交付可查。

use serde::{Deserialize, Serialize};

use crate::MatchCondition;
use crate::RouteRule;
use crate::RoutingConfig;

/// 预设版本（in-tree 载荷变更时递增；来源卡片随预览交付可查）
pub const GIT_PRESET_VERSION: u32 = 1;

/// 预设规则名前缀（模板命名空间——用户同名声明视为显式覆盖，模板退让）
pub const GIT_RULE_PREFIX: &str = "git-";

/// Git over SSH 主机域名集（SSH 面 + port 22）
pub const GIT_SSH_HOSTS_SET: &str = "git-ssh-hosts";
/// SSH-over-443 备用入口域名集（ssh.github.com 等 + port 443）
pub const GIT_SSH_ALT_HOSTS_SET: &str = "git-ssh-alt-hosts";
/// Git HTTPS/API 主域集（API 均为主域子域，suffix 语义一并覆盖）
pub const GIT_HTTPS_HOSTS_SET: &str = "git-https-hosts";
/// release/LFS/下载 CDN 面（重定向域）集
pub const GIT_ASSETS_HOSTS_SET: &str = "git-assets-hosts";

/// 预设规则名（展开产物；同名在场即视为已展开/用户声明）
pub const GIT_SSH_RULE: &str = "git-ssh";
pub const GIT_SSH_ALT_RULE: &str = "git-ssh-alt";
pub const GIT_HTTPS_RULE: &str = "git-https";
pub const GIT_ASSETS_RULE: &str = "git-assets";

/// Git 路由预置块（RIL-146）：`routing.git_preset` 声明面。块在场即
/// 展开生效；`target` 为组名或出口节点名（与规则 target 同口径）。
/// deny_unknown_fields 让拼错子字段立刻报错。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPresetBlock {
    /// Git HTTPS/API/release/LFS/下载面走向目标（组或出口名）
    pub target: String,
    /// Git over SSH 面走向目标；缺席 = 同 `target`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
}

impl GitPresetBlock {
    /// SSH 面目标（缺席回落 `target`）
    pub fn ssh_target(&self) -> &str {
        self.ssh.as_deref().unwrap_or(&self.target)
    }
}

/// 版本化规则集来源卡片（`规则来源可查`验收面）：名字/语义域/版本/
/// 来源/条目数随预览交付。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitRuleSetCard {
    /// 规则集名（config.rule_sets 键）
    pub name: String,
    /// 语义域：`domain`
    pub behavior: String,
    /// 载荷版本（`GIT_PRESET_VERSION`）
    pub version: u32,
    /// 来源说明（in-tree 常量的出处口径）
    pub source: String,
    /// 载荷条件条数
    pub entries: usize,
}

/// Git 路由预设样例预览（RIL-146）：导入/切换前可读的求值序、来源卡片
/// 与固定说明。全部可序列化、无敏感值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitPresetPreview {
    /// 预设版本
    pub version: u32,
    /// Git HTTPS/API/release/LFS/下载面目标
    pub target: String,
    /// Git over SSH 面目标（展开后的实际值，含回落）
    pub ssh: String,
    /// 版本化规则集来源卡片（声明序）
    pub rule_sets: Vec<GitRuleSetCard>,
    /// 求值序样例：`规则名 → target`（用户规则之后的追加段——先用户 →
    /// 应用预设 → 区域；不含用户自身规则，其顺序不被改写）
    pub order_sample: Vec<String>,
    /// 固定说明（连通不等于加速 / SSH 密钥认证保持 / 样例非全量 / 模式暂停）
    pub notes: Vec<String>,
}

/// Git over SSH 主机种子（**非全量**——文档化样例；SSH 面按域名+端口 22）
fn git_ssh_host_seeds() -> &'static [&'static str] {
    &[
        "github.com",
        "gitlab.com",
        "gitee.com",
        "bitbucket.org",
        "codeberg.org",
        "git.sr.ht",
    ]
}

/// SSH-over-443 备用入口种子（GitHub/GitLab 官方 443 SSH 端点样例）
fn git_ssh_alt_host_seeds() -> &'static [&'static str] {
    &["ssh.github.com", "altssh.gitlab.com"]
}

/// Git HTTPS/API 主域种子（**非全量**——API 均为主域子域，suffix 覆盖）
fn git_https_host_seeds() -> &'static [&'static str] {
    &[
        "github.com",
        "gitlab.com",
        "gitee.com",
        "bitbucket.org",
        "codeberg.org",
        "git.sr.ht",
    ]
}

/// release/LFS/下载 CDN 面种子（**非全量**——重定向/下载域以托管商
/// 官方文档为准；githubusercontent.com suffix 覆盖 raw/objects/releases
/// 等子域）
fn git_assets_host_seeds() -> &'static [&'static str] {
    &["githubusercontent.com", "github-cloud.s3.amazonaws.com"]
}

/// 版本化规则集来源卡片（声明序：SSH → SSH-443 → HTTPS → 下载面）
pub fn git_rule_set_cards() -> Vec<GitRuleSetCard> {
    vec![
        GitRuleSetCard {
            name: GIT_SSH_HOSTS_SET.to_string(),
            behavior: "domain".to_string(),
            version: GIT_PRESET_VERSION,
            source: "in-tree 样例种子（非全量）：Git over SSH 主机，配 port 22 使用"
                .to_string(),
            entries: git_ssh_host_seeds().len(),
        },
        GitRuleSetCard {
            name: GIT_SSH_ALT_HOSTS_SET.to_string(),
            behavior: "domain".to_string(),
            version: GIT_PRESET_VERSION,
            source: "in-tree 样例种子：SSH-over-443 官方备用入口，配 port 443 使用"
                .to_string(),
            entries: git_ssh_alt_host_seeds().len(),
        },
        GitRuleSetCard {
            name: GIT_HTTPS_HOSTS_SET.to_string(),
            behavior: "domain".to_string(),
            version: GIT_PRESET_VERSION,
            source: "in-tree 样例种子（非全量）：Git HTTPS/API 主域——API 均为主域子域（api.github.com 等），suffix 语义一并覆盖"
                .to_string(),
            entries: git_https_host_seeds().len(),
        },
        GitRuleSetCard {
            name: GIT_ASSETS_HOSTS_SET.to_string(),
            behavior: "domain".to_string(),
            version: GIT_PRESET_VERSION,
            source: "in-tree 样例种子（非全量）：release/LFS/下载 CDN 面（重定向域以托管商官方文档为准）"
                .to_string(),
            entries: git_assets_host_seeds().len(),
        },
    ]
}

/// 预设规则集载荷（`config.rule_sets` 注入面）：名字 → 条件列表。
pub fn git_preset_rule_sets() -> Vec<(&'static str, Vec<MatchCondition>)> {
    vec![
        (
            GIT_SSH_HOSTS_SET,
            vec![MatchCondition::DomainSuffix {
                values: git_ssh_host_seeds()
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            }],
        ),
        (
            GIT_SSH_ALT_HOSTS_SET,
            vec![MatchCondition::DomainSuffix {
                values: git_ssh_alt_host_seeds()
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            }],
        ),
        (
            GIT_HTTPS_HOSTS_SET,
            vec![MatchCondition::DomainSuffix {
                values: git_https_host_seeds()
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            }],
        ),
        (
            GIT_ASSETS_HOSTS_SET,
            vec![MatchCondition::DomainSuffix {
                values: git_assets_host_seeds()
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            }],
        ),
    ]
}

/// 预设展开产物规则（声明序：SSH:22 → SSH:443 备用 → HTTPS/API → 下载面）。
/// 同规则内多条件 = AND（主机面 + 端口面同时命中才中——端口条件限定 SSH
/// 面不被泛化劫持，HTTPS 面不设端口条件即全端口）。
pub fn git_preset_rules(target: &str, ssh_target: &str) -> Vec<RouteRule> {
    vec![
        // Git over SSH：SSH 主机 + port 22（AND 限定——不泛化劫持所有 22 端口流量）
        RouteRule {
            name: GIT_SSH_RULE.to_string(),
            matches: vec![
                MatchCondition::RuleSetRef {
                    name: GIT_SSH_HOSTS_SET.to_string(),
                },
                MatchCondition::Port { values: vec![22] },
            ],
            target: ssh_target.to_string(),
        },
        // SSH-over-443 官方备用入口 + port 443
        RouteRule {
            name: GIT_SSH_ALT_RULE.to_string(),
            matches: vec![
                MatchCondition::RuleSetRef {
                    name: GIT_SSH_ALT_HOSTS_SET.to_string(),
                },
                MatchCondition::Port { values: vec![443] },
            ],
            target: ssh_target.to_string(),
        },
        // Git HTTPS/API 主域（无端口条件——443 与镜像端口一并覆盖）
        RouteRule {
            name: GIT_HTTPS_RULE.to_string(),
            matches: vec![MatchCondition::RuleSetRef {
                name: GIT_HTTPS_HOSTS_SET.to_string(),
            }],
            target: target.to_string(),
        },
        // release/LFS/下载 CDN 面（重定向域）
        RouteRule {
            name: GIT_ASSETS_RULE.to_string(),
            matches: vec![MatchCondition::RuleSetRef {
                name: GIT_ASSETS_HOSTS_SET.to_string(),
            }],
            target: target.to_string(),
        },
    ]
}

impl RoutingConfig {
    /// Git 路由预设展开（RIL-146）：块在场即生效——规则集载荷按名注入
    /// （同名用户声明优先，模板退让），预设规则**追加在用户规则之后**
    /// （先用户 → 应用预设 → 区域：解析面在 `apply_region_preset` 之前
    /// 调用本展开，应用预设先于泛化区域规则），同名规则在场即跳过
    /// （幂等；用户显式声明/前次展开均不再重复追加）。
    pub fn apply_git_preset(&mut self) {
        let Some(block) = self.git_preset.clone() else {
            return;
        };
        // 规则集载荷注入：同名在场不覆盖（用户显式声明优先）
        for (name, conditions) in git_preset_rule_sets() {
            if self.rule_sets.get(name).is_none() {
                self.rule_sets.insert(name, conditions);
            }
        }
        // 规则追加：同名在场即跳过（幂等 + 用户声明退让）
        let ssh_target = block.ssh_target().to_string();
        for rule in git_preset_rules(&block.target, &ssh_target) {
            if self.rules.iter().any(|r| r.name == rule.name) {
                continue;
            }
            self.rules.push(rule);
        }
    }
}

/// Git 路由预设样例预览（RIL-146）：无块时 None；有块时给出求值序样例、
/// 来源卡片与固定说明（连通不等于加速 / SSH 主机密钥与认证保持 / 样例
/// 非全量 / 全局与直连模式暂停本预设规则）。
pub fn git_preset_preview(routing: &RoutingConfig) -> Option<GitPresetPreview> {
    let block = routing.git_preset.as_ref()?;
    let ssh_target = block.ssh_target().to_string();
    let order_sample = git_preset_rules(&block.target, &ssh_target)
        .into_iter()
        .map(|r| format!("{} → {}", r.name, r.target))
        .collect();
    let notes = vec![
        "连通不等于加速：预设只按域名/端口改写路由走向，不承诺 Git 传输更快——速度取决于所选出口的实际链路质量。".to_string(),
        "SSH 主机密钥与认证保持：预设只做「移动哪些域名/端口」的域名能力路由，known_hosts/主机密钥校验与端到端认证不受影响；不把 SSH 面混同成 HTTPS 出口协议（载体协议由出口自身决定）。".to_string(),
        "样例种子非全量：重定向/下载 CDN 域以各托管商官方文档为准，用户规则可自由扩展；来源卡片见 rule_sets。".to_string(),
        "全局/直连选路模式暂停本预设规则（mode_override_preview 暂停清单可见）；预设规则即普通规则，不是硬性安全边界。".to_string(),
        format!("预设版本 {GIT_PRESET_VERSION}：规则集载荷 in-tree 版本化；SSH 面缺省跟随 target（本块 ssh 目标：`{ssh_target}`）。"),
    ];
    Some(GitPresetPreview {
        version: GIT_PRESET_VERSION,
        target: block.target.clone(),
        ssh: ssh_target,
        rule_sets: git_rule_set_cards(),
        order_sample,
        notes,
    })
}

/// 模式集成便捷面：预设规则名（全局/直连模式下的暂停清单应包含这些
/// 名字——预设规则即普通规则）。
pub fn git_preset_rule_names() -> Vec<&'static str> {
    vec![
        GIT_SSH_RULE,
        GIT_SSH_ALT_RULE,
        GIT_HTTPS_RULE,
        GIT_ASSETS_RULE,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::mode_override_preview;
    use crate::SelectionMode;

    fn preset_block(target: &str, ssh: Option<&str>) -> GitPresetBlock {
        GitPresetBlock {
            target: target.to_string(),
            ssh: ssh.map(|s| s.to_string()),
        }
    }

    /// 展开形状：4 规则追加 + 4 规则集注入；SSH 面目标回落/显式两态
    #[test]
    fn preset_rules_shape_and_ssh_fallback() {
        let same = git_preset_rules("proxy-group", "proxy-group");
        assert_eq!(same.len(), 4);
        assert_eq!(same[0].target, "proxy-group", "SSH 缺席回落 target");
        assert_eq!(same[2].target, "proxy-group");

        let split = git_preset_rules("proxy-group", "direct-main");
        assert_eq!(split[0].target, "direct-main", "SSH:22 面走 ssh 目标");
        assert_eq!(split[1].target, "direct-main", "SSH:443 备用走 ssh 目标");
        assert_eq!(split[2].target, "proxy-group", "HTTPS 面走 target");
        assert_eq!(split[3].target, "proxy-group", "下载面走 target");
        // AND 语义：SSH 规则带端口条件，HTTPS 规则不带
        assert!(
            split[0]
                .matches
                .iter()
                .any(|m| matches!(m, MatchCondition::Port { values } if values == &[22][..])),
            "SSH 规则须带 port 22 条件"
        );
        assert!(split[2].matches.len() == 1, "HTTPS 规则仅主机面");
    }

    /// 端口条件限定：预设不产生无主机限定的裸端口规则（不泛化劫持）
    #[test]
    fn ssh_rules_are_host_scoped() {
        for rule in git_preset_rules("t", "s") {
            let has_host = rule
                .matches
                .iter()
                .any(|m| matches!(m, MatchCondition::RuleSetRef { .. }));
            assert!(has_host, "规则 {} 必须有主机面条件", rule.name);
        }
    }

    /// 卡片：版本/来源/条数
    #[test]
    fn cards_carry_version_and_source() {
        let cards = git_rule_set_cards();
        assert_eq!(cards.len(), 4);
        for c in cards {
            assert_eq!(c.version, GIT_PRESET_VERSION);
            assert!(!c.source.is_empty());
            assert!(c.entries > 0);
        }
    }

    /// 预览：求值序、卡片、固定说明（连通不等于加速 / SSH 密钥 / 暂停）
    #[test]
    fn preview_reports_order_cards_and_notes() {
        let mut routing = RoutingConfig {
            git_preset: Some(preset_block("proxy-group", Some("direct-main"))),
            default_node: "proxy-group".to_string(),
            ..RoutingConfig::default()
        };
        routing.apply_git_preset();
        let p = git_preset_preview(&routing).expect("有块须有预览");
        assert_eq!(p.version, GIT_PRESET_VERSION);
        assert_eq!(p.target, "proxy-group");
        assert_eq!(p.ssh, "direct-main", "预览点名展开后的 SSH 目标");
        assert_eq!(p.order_sample.len(), 4);
        assert!(p.order_sample[0].starts_with(GIT_SSH_RULE));
        let joined = p.notes.join("\n");
        assert!(joined.contains("连通不等于加速"));
        assert!(joined.contains("主机密钥"));
        assert!(joined.contains("非全量"));
        assert!(joined.contains("暂停"));

        // 无块 → None
        let bare = RoutingConfig::default();
        assert!(git_preset_preview(&bare).is_none());
    }

    /// 模式集成：展开后的配置在全局模式下，暂停清单含预设规则名
    #[test]
    fn paused_names_match_mode_preview_for_preset_rules() {
        let mut routing = RoutingConfig {
            git_preset: Some(preset_block("proxy-group", None)),
            default_node: "proxy-group".to_string(),
            ..RoutingConfig::default()
        };
        routing.apply_git_preset();
        let preview = mode_override_preview(&routing, SelectionMode::Global);
        for name in git_preset_rule_names() {
            assert!(
                preview.paused_rules.iter().any(|r| r == name),
                "全局模式暂停清单须含预设规则 {name}: {:?}",
                preview.paused_rules
            );
        }
    }
}
