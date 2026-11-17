//! RIL-141 区域绕过预设与样例预览（纯面）。
//!
//! 设计口径（ui-prototype-v1.md §4）：普通规则模式建议明确顺序——硬性
//! 边界 → 用户明确的高优先级应用/域名规则 → 选定区域规则 → 默认动作；
//! **导入时展示相对顺序，不能在刷新时改写用户优先级**；GeoIP/域名证据
//! 缺失或矛盾时使用配置的兜底并显示原因；局域网/代理节点/DNS 引导等
//! 旁路独立于区域预设。
//!
//! 本模块交付：
//! - 两个 in-tree 版本化预设：[`RegionPresetKind::MainlandDirect`]（大陆
//!   直连/其余走默认=代理方向）与 [`RegionPresetKind::MainlandProxy`]
//!   （反向：大陆走代理、其余走默认=直连方向）；
//! - 版本化域名/IP 规则集（in-tree 常量载荷 + 来源卡片可查；样例种子
//!   集如实标注非全量，全量面走 geosite_db/geoip_db 数据库条件）；
//! - [`RoutingConfig::apply_region_preset`]：模板展开（追加在用户规则
//!   之后——先用户后区域，用户优先级不被改写；同名规则/规则集用户
//!   显式声明优先，模板退让；重复展开幂等）；
//! - [`region_preset_preview`]：样例预览（求值序、规则集来源卡片、
//!   方向提示与未知地理兜底说明）。
//!
//! 全局/直连模式暂停预设规则由 RIL-140 `mode::mode_override_preview`
//! 的暂停清单自然覆盖（预设规则就是普通规则）——集成测试钉住。

use serde::{Deserialize, Serialize};

use crate::MatchCondition;
use crate::RouteRule;
use crate::RoutingConfig;

/// 预设版本（in-tree 载荷变更时递增；来源卡片随预览交付可查）
pub const REGION_PRESET_VERSION: u32 = 1;

/// 预设规则名前缀（模板命名空间——用户同名声明视为显式覆盖，模板退让）
pub const REGION_RULE_PREFIX: &str = "region-";

/// LAN 绕过规则集名（IP 面；载荷 = RFC 1918/4193/4291 在网段，完整稳定）
pub const REGION_LAN_SET: &str = "region-lan";
/// CN 域名样例规则集名（域名面种子；全量走 geo_site `cn` 类别）
pub const REGION_CN_DOMAIN_SAMPLE_SET: &str = "region-cn-domain-sample";
/// CN IP 样例规则集名（IP 面种子；全量走 geoip 数据库）
pub const REGION_CN_IP_SAMPLE_SET: &str = "region-cn-ip-sample";

/// 预设规则名（展开产物；同名在场即视为已展开/用户声明）
pub const REGION_LAN_RULE: &str = "region-lan";
pub const REGION_CN_DOMAIN_RULE: &str = "region-cn-domain";
pub const REGION_CN_IP_RULE: &str = "region-cn-ip";

/// 区域预设方向（RIL-141）：
/// - `mainland_direct`（大陆直连）：CN 域名/IP 与 LAN → `direct` 出口，
///   其余流量走 `routing.default_node`（期望指向代理组/节点）；
/// - `mainland_proxy`（反向预设）：CN 域名/IP → `proxy` 出口、LAN 恒
///   直连（旁路独立），其余流量走 `routing.default_node`（期望指向
///   直连出口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionPresetKind {
    /// 大陆直连：CN → 直连出口，其余走默认（代理方向）
    MainlandDirect,
    /// 反向预设：CN → 代理出口，其余走默认（直连方向）
    MainlandProxy,
}

/// 区域预设置块（RIL-141）：`routing.region_preset` 声明面。块在场即
/// 展开生效；`direct`/`proxy` 为组名或出口节点名（与规则 target 同
/// 口径）。deny_unknown_fields 让拼错子字段立刻报错。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionPresetBlock {
    /// 预设方向
    pub kind: RegionPresetKind,
    /// 直连侧目标（组名或 Direct 出口节点名；LAN 绕过恒用它）
    pub direct: String,
    /// 代理侧目标（组名或节点名；反向预设的 CN 面用它）
    pub proxy: String,
}

/// 版本化规则集来源卡片（`来源范围可查`验收面）：名字/语义域/版本/
/// 来源/条目数随预览交付。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegionRuleSetCard {
    /// 规则集名（config.rule_sets 键）
    pub name: String,
    /// 语义域：`domain` / `ipcidr`
    pub behavior: String,
    /// 载荷版本（`REGION_PRESET_VERSION`）
    pub version: u32,
    /// 来源说明（in-tree 常量的出处口径）
    pub source: String,
    /// 载荷条件条数
    pub entries: usize,
}

/// 样例预览（RIL-141 `样例预览`验收面）：导入/切换前可读的求值序、
/// 来源卡片与固定说明。全部可序列化、无敏感值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegionPresetPreview {
    /// 预设版本
    pub version: u32,
    /// 预设方向
    pub kind: RegionPresetKind,
    /// 直连侧目标
    pub direct: String,
    /// 代理侧目标
    pub proxy: String,
    /// 版本化规则集来源卡片（声明序）
    pub rule_sets: Vec<RegionRuleSetCard>,
    /// 求值序样例：`规则名 → target`（用户规则之后的追加段——先用户
    /// 后区域；不含用户自身规则，其顺序不被改写）
    pub order_sample: Vec<String>,
    /// 固定说明（方向提示/未知地理兜底/LAN 独立/模式暂停）
    pub notes: Vec<String>,
}

/// LAN 绕过 IP 面（RFC 1918 / RFC 4193 ULA / RFC 4291 loopback 与
/// link-local）——完整、稳定、in-tree 版本化；旁路独立于预设方向。
fn lan_cidrs() -> &'static [&'static str] {
    &[
        "127.0.0.0/8",    // IPv4 loopback
        "10.0.0.0/8",     // RFC 1918
        "172.16.0.0/12",  // RFC 1918
        "192.168.0.0/16", // RFC 1918
        "169.254.0.0/16", // IPv4 link-local
        "::1/128",        // IPv6 loopback
        "fe80::/10",      // IPv6 link-local
        "fc00::/7",       // IPv6 ULA
    ]
}

/// CN 域名样例种子（**非全量**——文档化样例；全量面走 geo_site `cn`
/// 类别，geosite_db 缺席时种子集仍提供可查的兜底识别面）
fn cn_domain_seeds() -> &'static [&'static str] {
    &[
        "baidu.com",
        "qq.com",
        "163.com",
        "126.com",
        "bilibili.com",
        "zhihu.com",
        "aliyun.com",
        "taobao.com",
        "jd.com",
        "weibo.com",
    ]
}

/// CN IP 样例种子（**非全量**——文档化样例；全量面走 geoip 数据库）。
/// 取公共基础设施网段（公共 DNS 等），来源口径见卡片 source。
fn cn_ip_seeds() -> &'static [&'static str] {
    &[
        "223.5.5.0/24",     // AliDNS 公共 DNS
        "119.29.29.0/24",   // DNSPod 公共 DNS
        "114.114.114.0/24", // 114DNS 公共 DNS
        "1.2.4.0/24",       // CNNIC（APNIC CN 段样例）
    ]
}

/// 版本化规则集来源卡片（声明序：LAN → CN 域名样例 → CN IP 样例）
pub fn rule_set_cards() -> Vec<RegionRuleSetCard> {
    vec![
        RegionRuleSetCard {
            name: REGION_LAN_SET.to_string(),
            behavior: "ipcidr".to_string(),
            version: REGION_PRESET_VERSION,
            source: "in-tree: RFC 1918 / RFC 4193 ULA / RFC 4291 loopback+link-local（完整稳定）"
                .to_string(),
            entries: lan_cidrs().len(),
        },
        RegionRuleSetCard {
            name: REGION_CN_DOMAIN_SAMPLE_SET.to_string(),
            behavior: "domain".to_string(),
            version: REGION_PRESET_VERSION,
            source: "in-tree 样例种子（非全量；全量面走 geo_site `cn` 类别）".to_string(),
            entries: cn_domain_seeds().len(),
        },
        RegionRuleSetCard {
            name: REGION_CN_IP_SAMPLE_SET.to_string(),
            behavior: "ipcidr".to_string(),
            version: REGION_PRESET_VERSION,
            source: "in-tree 样例种子（非全量；全量面走 geoip 数据库）".to_string(),
            entries: cn_ip_seeds().len(),
        },
    ]
}

/// 预设规则集载荷（`config.rule_sets` 注入面）：名字 → 条件列表。
/// 规则集条目独立参与 OR 语义（首匹配层每条单独命中即中）。
pub fn preset_rule_sets() -> Vec<(&'static str, Vec<MatchCondition>)> {
    vec![
        (
            REGION_LAN_SET,
            vec![MatchCondition::IpCidr {
                cidrs: lan_cidrs().iter().map(|s| (*s).to_string()).collect(),
            }],
        ),
        (
            REGION_CN_DOMAIN_SAMPLE_SET,
            vec![MatchCondition::DomainSuffix {
                values: cn_domain_seeds().iter().map(|s| (*s).to_string()).collect(),
            }],
        ),
        (
            REGION_CN_IP_SAMPLE_SET,
            vec![MatchCondition::IpCidr {
                cidrs: cn_ip_seeds().iter().map(|s| (*s).to_string()).collect(),
            }],
        ),
    ]
}

/// 预设展开产物规则（声明序：LAN 绕过 → CN 域名 → CN IP）。
/// `cn_target` 按 [`RegionPresetKind`] 取向：大陆直连 = `direct`、
/// 反向 = `proxy`；LAN 恒 `direct`（旁路独立于方向）。
pub fn preset_rules(kind: RegionPresetKind, direct: &str, proxy: &str) -> Vec<RouteRule> {
    let cn_target = match kind {
        RegionPresetKind::MainlandDirect => direct,
        RegionPresetKind::MainlandProxy => proxy,
    };
    vec![
        // LAN 绕过：独立于预设方向，恒直连目标（设计 §4 口径）
        RouteRule {
            name: REGION_LAN_RULE.to_string(),
            matches: vec![MatchCondition::RuleSetRef {
                name: REGION_LAN_SET.to_string(),
            }],
            target: direct.to_string(),
        },
        // CN 域名面：geo_site 数据库类别 + 版本化样例种子（任一命中即中）
        RouteRule {
            name: REGION_CN_DOMAIN_RULE.to_string(),
            matches: vec![MatchCondition::Any {
                conditions: vec![
                    MatchCondition::GeoSite {
                        category: "cn".to_string(),
                    },
                    MatchCondition::RuleSetRef {
                        name: REGION_CN_DOMAIN_SAMPLE_SET.to_string(),
                    },
                ],
            }],
            target: cn_target.to_string(),
        },
        // CN IP 面：geoip 数据库国家 + 版本化样例种子（任一命中即中）
        RouteRule {
            name: REGION_CN_IP_RULE.to_string(),
            matches: vec![MatchCondition::Any {
                conditions: vec![
                    MatchCondition::Geoip {
                        country: "CN".to_string(),
                    },
                    MatchCondition::RuleSetRef {
                        name: REGION_CN_IP_SAMPLE_SET.to_string(),
                    },
                ],
            }],
            target: cn_target.to_string(),
        },
    ]
}

impl RoutingConfig {
    /// 区域预设展开（RIL-141）：块在场即生效——规则集载荷按名注入
    /// （同名用户声明优先，模板退让），预设规则**追加在用户规则之后**
    /// （先用户后区域——用户优先级不被改写；设计 §4 顺序口径），同名
    /// 规则在场即跳过（幂等；用户显式声明/前次展开均不再重复追加）。
    /// 刷新/重解析时随解析面重新展开（块在场即生效语义），用户规则
    /// 面原序保留。
    pub fn apply_region_preset(&mut self) {
        let Some(block) = self.region_preset.clone() else {
            return;
        };
        // 规则集载荷注入：同名在场不覆盖（用户显式声明优先）
        for (name, conditions) in preset_rule_sets() {
            if self.rule_sets.get(name).is_none() {
                self.rule_sets.insert(name, conditions);
            }
        }
        // 规则追加：同名在场即跳过（幂等 + 用户声明退让）
        for rule in preset_rules(block.kind, &block.direct, &block.proxy) {
            if self.rules.iter().any(|r| r.name == rule.name) {
                continue;
            }
            self.rules.push(rule);
        }
    }
}

/// 样例预览（RIL-141）：无预置块时 None；有块时给出求值序样例、
/// 来源卡片与固定说明（方向提示点名当前 default_node、未知地理兜底、
/// LAN 独立、全局/直连模式暂停本预设规则）。
pub fn region_preset_preview(routing: &RoutingConfig) -> Option<RegionPresetPreview> {
    let block = routing.region_preset.as_ref()?;
    let order_sample = preset_rules(block.kind, &block.direct, &block.proxy)
        .into_iter()
        .map(|r| format!("{} → {}", r.name, r.target))
        .collect();
    let direction = match block.kind {
        RegionPresetKind::MainlandDirect => {
            "其余流量走 routing.default_node（期望指向代理组/代理节点）"
        }
        RegionPresetKind::MainlandProxy => "其余流量走 routing.default_node（期望指向直连出口）",
    };
    let notes = vec![
        format!("方向提示：CN 面（域名/IP）按预设走向，{direction}；当前 default_node: `{}`。", routing.default_node),
        "未知地理兜底：geoip/geosite 数据库缺席或证据缺失时对应条件恒不命中，流量落 routing.default_node（不猜测归属）。"
            .to_string(),
        "LAN 旁路独立于预设方向：region-lan 恒走直连侧目标（节点/引导旁路面与此互不影响）".to_string(),
        "全局/直连选路模式暂停本预设规则（mode_override_preview 暂停清单可见）；预设规则即普通规则，不是硬性安全边界。"
            .to_string(),
        format!("预设版本 {REGION_PRESET_VERSION}：规则集载荷 in-tree 版本化，来源卡片见 rule_sets。"),
    ];
    Some(RegionPresetPreview {
        version: REGION_PRESET_VERSION,
        kind: block.kind,
        direct: block.direct.clone(),
        proxy: block.proxy.clone(),
        rule_sets: rule_set_cards(),
        order_sample,
        notes,
    })
}

/// 模式集成便捷面：预设规则名（全局/直连模式下的暂停清单应包含这些
/// 名字——RIL-141 验收「全局/直连显示暂停」）。
pub fn preset_rule_names() -> Vec<&'static str> {
    vec![REGION_LAN_RULE, REGION_CN_DOMAIN_RULE, REGION_CN_IP_RULE]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::mode_override_preview;
    use crate::SelectionMode;

    #[test]
    fn lan_cidrs_cover_private_and_local_ranges() {
        let cidrs = lan_cidrs();
        for expect in [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "::1/128",
            "fe80::/10",
            "fc00::/7",
        ] {
            assert!(cidrs.contains(&expect), "LAN 面须含 {expect}");
        }
    }

    #[test]
    fn preset_rules_direction_by_kind() {
        let md = preset_rules(
            RegionPresetKind::MainlandDirect,
            "direct-main",
            "proxy-group",
        );
        assert_eq!(md.len(), 3);
        assert_eq!(md[0].target, "direct-main", "LAN 恒直连");
        assert_eq!(md[1].target, "direct-main", "大陆直连 CN 面→直连");
        assert_eq!(md[2].target, "direct-main");

        let mp = preset_rules(
            RegionPresetKind::MainlandProxy,
            "direct-main",
            "proxy-group",
        );
        assert_eq!(mp[0].target, "direct-main", "LAN 旁路独立于方向");
        assert_eq!(mp[1].target, "proxy-group", "反向预设 CN 面→代理");
        assert_eq!(mp[2].target, "proxy-group");
    }

    #[test]
    fn cards_carry_version_and_source() {
        let cards = rule_set_cards();
        assert_eq!(cards.len(), 3);
        for c in cards {
            assert_eq!(c.version, REGION_PRESET_VERSION);
            assert!(!c.source.is_empty());
            assert!(c.entries > 0);
        }
    }

    #[test]
    fn preview_reports_direction_and_fallback() {
        let routing = RoutingConfig {
            region_preset: Some(RegionPresetBlock {
                kind: RegionPresetKind::MainlandDirect,
                direct: "direct-main".to_string(),
                proxy: "proxy-group".to_string(),
            }),
            default_node: "proxy-group".to_string(),
            ..RoutingConfig::default()
        };
        let p = region_preset_preview(&routing).expect("有块须有预览");
        assert_eq!(p.version, REGION_PRESET_VERSION);
        assert_eq!(p.order_sample.len(), 3);
        assert_eq!(
            p.order_sample[0],
            format!("{REGION_LAN_RULE} → direct-main")
        );
        let joined = p.notes.join("\n");
        assert!(
            joined.contains("proxy-group"),
            "方向提示点名当前 default_node"
        );
        assert!(joined.contains("兜底"));
        assert!(joined.contains("LAN"));
        assert!(joined.contains("暂停"));
        // 无块 → None
        let bare = RoutingConfig::default();
        assert!(region_preset_preview(&bare).is_none());
    }

    #[test]
    fn paused_names_match_mode_preview_for_preset_rules() {
        // 集成面：预设展开后的配置在全局模式下，暂停清单应含预设规则名
        let mut routing = RoutingConfig {
            region_preset: Some(RegionPresetBlock {
                kind: RegionPresetKind::MainlandDirect,
                direct: "direct-main".to_string(),
                proxy: "proxy-group".to_string(),
            }),
            default_node: "proxy-group".to_string(),
            ..RoutingConfig::default()
        };
        routing.apply_region_preset();
        let preview = mode_override_preview(&routing, SelectionMode::Global);
        for name in preset_rule_names() {
            assert!(
                preview.paused_rules.iter().any(|r| r == name),
                "全局模式暂停清单须含预设规则 {name}: {:?}",
                preview.paused_rules
            );
        }
    }
}
