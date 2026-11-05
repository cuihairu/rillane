//! geosite/chnroutes 文本规则源批量导入（O-dns1，dns-partition.md §10）
//!
//! 输入 = v2fly 文本规则源行集（geosite 域名清单 / chnroutes CIDR 清单），
//! 逐行解析为结构化条目，再按目标面产出：
//! - 路由面（`routing.rules`）：域清单 → `DomainSuffix` 联合条件、
//!   `full:` → `DomainFull`（G0-2 完全域匹配独立条件）、`keyword:` →
//!   `DomainKeyword`、`regexp:` → `DomainRegex`、CIDR → `Network`——各成
//!   一条规则
//!   （`matches` 多条件是 AND，不同类型清单不能并进一条，见本文件 §AND）；
//! - DNS 分流面（`network.dns.rules`）：裸域/`domain:` → exact + suffix
//!   双 pattern（D-2：suffix 需前导点且不含本域，exact 补本域）、`full:` →
//!   exact；keyword/regexp/CIDR 在 DNS 面无对应模式，显式报错不静默降级。
//!
//! 语义对齐先例：clash.rs `DOMAIN → DomainFull`（G0-2 完全域匹配路由条件
//! 已就位，不再转 suffix 超集）。

use std::net::IpAddr;

use anyhow::{anyhow, Result};
use seep_config::{DnsGroup, DnsRuleConfig, MatchCondition, RouteRule};

/// 解析后的规则源条目集
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSourceImport {
    /// 裸域/`domain:` 条目（路由面 = suffix 联合；DNS 面 = exact + suffix）
    pub domains: Vec<String>,
    /// `full:` 条目（路由面 = 并入 suffix 联合；DNS 面 = exact）
    pub fulls: Vec<String>,
    /// `keyword:` 条目（仅路由面）
    pub keywords: Vec<String>,
    /// `regexp:` 条目（仅路由面；Rust `regex` 语法，`is_match` 语义）
    pub regexps: Vec<String>,
    /// 规范化 CIDR（裸 IP 补 /32 或 /128）
    pub cidrs: Vec<String>,
    /// 无法表达的条目及原因（regexp/include/属性行/格式坏行）——逐条报告不阻塞
    pub skipped: Vec<String>,
}

/// 路由面产物：最多四条规则（域/完全域/关键词/CIDR 各一，空类不出规则）。
/// 规则名取 `<name>`、`<name>-full`、`<name>-keyword`、`<name>-regexp`、
/// `<name>-cidr`。
pub fn to_routing_rules(src: &RuleSourceImport, name: &str, target: &str) -> Vec<RouteRule> {
    let mut rules = Vec::new();
    if !src.domains.is_empty() {
        rules.push(RouteRule {
            name: name.to_string(),
            matches: vec![MatchCondition::DomainSuffix {
                values: src.domains.clone(),
            }],
            target: target.to_string(),
        });
    }
    if !src.fulls.is_empty() {
        // G0-2 `full:`：完全域匹配独立条件（不再并入 suffix 超集）。
        rules.push(RouteRule {
            name: format!("{name}-full"),
            matches: vec![MatchCondition::DomainFull {
                values: src.fulls.clone(),
            }],
            target: target.to_string(),
        });
    }
    if !src.keywords.is_empty() {
        rules.push(RouteRule {
            name: format!("{name}-keyword"),
            matches: vec![MatchCondition::DomainKeyword {
                values: src.keywords.clone(),
            }],
            target: target.to_string(),
        });
    }
    if !src.regexps.is_empty() {
        rules.push(RouteRule {
            name: format!("{name}-regexp"),
            matches: vec![MatchCondition::DomainRegex {
                patterns: src.regexps.clone(),
            }],
            target: target.to_string(),
        });
    }
    if !src.cidrs.is_empty() {
        rules.push(RouteRule {
            name: format!("{name}-cidr"),
            matches: vec![MatchCondition::IpCidr {
                cidrs: src.cidrs.clone(),
            }],
            target: target.to_string(),
        });
    }
    rules
}

/// DNS 分流面产物：裸域/`domain:` → exact + suffix 双 pattern；
/// `full:` → exact。keyword/CIDR 无 DNS 面模式，报错（不静默降级）。
pub fn to_dns_rules(src: &RuleSourceImport, group: DnsGroup) -> Result<Vec<DnsRuleConfig>> {
    if !src.keywords.is_empty() {
        return Err(anyhow!(
            "keyword 条目（{} 条）无 DNS 分流面对应模式（exact/suffix），请走 --face routing",
            src.keywords.len()
        ));
    }
    if !src.regexps.is_empty() {
        return Err(anyhow!(
            "regexp 条目（{} 条）无 DNS 分流面对应模式（exact/suffix），请走 --face routing",
            src.regexps.len()
        ));
    }
    if !src.cidrs.is_empty() {
        return Err(anyhow!(
            "CIDR 条目（{} 条）不适用于 DNS 分流面（域名 pattern），请走 --face routing",
            src.cidrs.len()
        ));
    }
    let mut rules = Vec::new();
    let mut push = |pattern: &str| {
        rules.push(DnsRuleConfig {
            pattern: pattern.to_string(),
            group,
        });
    };
    for d in &src.domains {
        push(d); // exact：本域自身
        push(&format!(".{d}")); // suffix：子域（前导点，不含本域——D-2）
    }
    for f in &src.fulls {
        push(f);
    }
    Ok(rules)
}

/// 逐行解析文本规则源。支持 `#` 注释与空行；`domain:`/`full:`/`keyword:`/
/// `regexp:`/`include:` 前缀与裸行；`@attr` 属性行整行跳过（属性过滤语义
/// 不在轻量面内）；CIDR 判定 = IP 或 IP/前缀。
pub fn parse_rule_source(raw: &str) -> RuleSourceImport {
    let mut out = RuleSourceImport::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("include:") {
            out.skipped
                .push(format!("{line}（include 需多文件聚合，单文件导入不支持）"));
            continue;
        }
        // @属性过滤先于 regexp 分支（审核发现 2026-11-04）：`regexp:... @cn`
        // 的属性文本若进入表达式会导致预期域名不命中，且该行本应整行跳过
        // 报告；故属性检查前置，正则行含属性即整行 skipped。
        if line.contains('@') {
            out.skipped
                .push(format!("{line}（@属性过滤语义不在轻量面内）"));
            continue;
        }
        if let Some(v) = line.strip_prefix("regexp:") {
            if v.is_empty() {
                out.skipped.push(format!("{line}（regexp 为空）"));
            } else {
                out.regexps.push(v.to_string());
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("domain:") {
            push_domain(&mut out, v, line);
        } else if let Some(v) = line.strip_prefix("full:") {
            if valid_domain(v) {
                out.fulls.push(v.to_string());
            } else {
                out.skipped.push(format!("{line}（域名格式非法）"));
            }
        } else if let Some(v) = line.strip_prefix("keyword:") {
            if v.is_empty() {
                out.skipped.push(format!("{line}（keyword 为空）"));
            } else {
                out.keywords.push(v.to_string());
            }
        } else if let Some(cidr) = normalize_cidr(line) {
            out.cidrs.push(cidr);
        } else if line.contains('/') {
            out.skipped.push(format!("{line}（CIDR 格式非法）"));
        } else {
            push_domain(&mut out, line, line);
        }
    }
    out
}

fn push_domain(out: &mut RuleSourceImport, v: &str, raw: &str) {
    if valid_domain(v) {
        out.domains.push(v.to_string());
    } else {
        out.skipped.push(format!("{raw}（域名格式非法）"));
    }
}

/// 域名轻校验：非空、无空白、无 `/`（CIDR 已在前序分支分流）。
fn valid_domain(v: &str) -> bool {
    !v.is_empty() && !v.contains(char::is_whitespace) && !v.contains('/')
}

/// 裸 IP → /32（v4）或 /128（v6）；`ip/prefix` 校验前缀界并保持原样。
/// 解析失败返回 None（调用方按域名或坏行处理）。
fn normalize_cidr(line: &str) -> Option<String> {
    if let Some((ip, prefix)) = line.rsplit_once('/') {
        let ip: IpAddr = ip.parse().ok()?;
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix: u8 = prefix.parse().ok()?;
        if prefix > max {
            return None;
        }
        Some(format!("{ip}/{prefix}"))
    } else {
        let ip: IpAddr = line.parse().ok()?;
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some(format!("{ip}/{max}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_geosite_text_matrix() {
        let src = parse_rule_source(
            "# 注释行\n\
             \n\
             example.com\n\
             domain:foo.bar\n\
             full:exact.org\n\
             keyword:video\n\
             regexp:^ad\\d+\\.\n\
             include:cn\n\
             bad domain\n\
             domain:\n\
             example.net @cn\n",
        );
        assert_eq!(src.domains, vec!["example.com", "foo.bar"]);
        assert_eq!(src.fulls, vec!["exact.org"]);
        assert_eq!(src.keywords, vec!["video"]);
        assert_eq!(src.regexps, vec![r"^ad\d+\."]);
        assert!(src.cidrs.is_empty());
        // include/属性行/坏域行逐条入 skipped 且原因可辨（regexp 已入 regexps）
        assert_eq!(src.skipped.len(), 4, "{:?}", src.skipped);
        assert!(src.skipped.iter().all(|s| !s.contains("regexp")));
        assert!(src.skipped.iter().any(|s| s.contains("include")));
        assert!(src.skipped.iter().any(|s| s.contains("@属性")));
        assert!(src.skipped.iter().filter(|s| s.contains("非法")).count() >= 2);
    }

    #[test]
    fn parse_chnroutes_cidrs() {
        let src = parse_rule_source(
            "1.0.1.0/24\n1.0.2.0/24\n8.8.8.8\n2001:db8::/32\n::1\n1.2.3.4/33\nnope/24\n",
        );
        assert_eq!(
            src.cidrs,
            vec![
                "1.0.1.0/24",
                "1.0.2.0/24",
                "8.8.8.8/32",
                "2001:db8::/32",
                "::1/128",
            ]
        );
        // 越界前缀与坏行入 skipped
        assert_eq!(src.skipped.len(), 2, "{:?}", src.skipped);
        assert!(src.domains.is_empty());
    }

    /// 审核发现 2026-11-04：`regexp:` 分支原先先于 `@` 属性检查，使
    /// `regexp:^example\.com$ @cn` 被当作正则导入而非整行跳过——属性文本
    /// 进入表达式导致预期域名不命中。回归：属性行整行 skipped，不入 regexps。
    #[test]
    fn regexp_with_attribute_is_skipped_whole_line() {
        let src = parse_rule_source("regexp:^example\\.com$ @cn\nregexp:^plain\\.com$\n");
        assert_eq!(src.regexps, vec![r"^plain\.com$"], "纯正则入 regexps");
        assert!(
            src.regexps.iter().all(|r| !r.contains('@')),
            "属性文本不得进入 regexps"
        );
        assert!(
            src.skipped.iter().any(|s| s.contains("@属性")),
            "含属性正则行应整行 skipped：{:?}",
            src.skipped
        );
    }

    #[test]
    fn routing_rules_split_by_condition_type() {
        // matches 多条件是 AND：不同类型清单各成一条规则（§AND）
        let src = parse_rule_source("example.com\nkeyword:video\nregexp:^ad\\.\n10.0.0.0/8\n");
        let rules = to_routing_rules(&src, "cn", "direct-main");
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].name, "cn");
        assert_eq!(rules[0].target, "direct-main");
        assert!(
            matches!(&rules[0].matches[0], MatchCondition::DomainSuffix { values } if values == &vec!["example.com".to_string()])
        );
        assert_eq!(rules[1].name, "cn-keyword");
        assert!(matches!(
            &rules[1].matches[0],
            MatchCondition::DomainKeyword { .. }
        ));
        assert_eq!(rules[2].name, "cn-regexp");
        assert!(matches!(
            &rules[2].matches[0],
            MatchCondition::DomainRegex { patterns } if patterns == &vec![r"^ad\.".to_string()]
        ));
        assert_eq!(rules[3].name, "cn-cidr");
        assert!(matches!(
            &rules[3].matches[0],
            MatchCondition::IpCidr { .. }
        ));

        // G0-2：`full:` 独立成完全域匹配规则，不再并入 suffix 超集。
        let full_src = parse_rule_source("a.com\nfull:b.com\n");
        let rules = to_routing_rules(&full_src, "x", "auto");
        assert_eq!(rules.len(), 2);
        assert!(matches!(
            &rules[0].matches[0],
            MatchCondition::DomainSuffix { values } if values == &vec!["a.com".to_string()]
        ));
        assert_eq!(rules[1].name, "x-full");
        assert!(matches!(
            &rules[1].matches[0],
            MatchCondition::DomainFull { values } if values == &vec!["b.com".to_string()]
        ));
    }

    #[test]
    fn dns_rules_expand_exact_plus_suffix() {
        let src = parse_rule_source("example.com\nfull:exact.org\n");
        let rules = to_dns_rules(&src, DnsGroup::Trusted).expect("应可展开");
        // 裸域 → exact 本域 + suffix 子域两条；full → exact 一条
        assert_eq!(
            rules,
            vec![
                DnsRuleConfig {
                    pattern: "example.com".into(),
                    group: DnsGroup::Trusted
                },
                DnsRuleConfig {
                    pattern: ".example.com".into(),
                    group: DnsGroup::Trusted
                },
                DnsRuleConfig {
                    pattern: "exact.org".into(),
                    group: DnsGroup::Trusted
                },
            ]
        );

        // regexp 条目无 DNS 分流面模式，显式报错不静默降级
        let src = parse_rule_source("regexp:^ad\\.\n");
        let err = to_dns_rules(&src, DnsGroup::Trusted).unwrap_err();
        assert!(err.to_string().contains("regexp"), "{err}");
    }

    #[test]
    fn dns_rules_reject_keyword_and_cidr() {
        let kw = parse_rule_source("keyword:video\n");
        assert!(to_dns_rules(&kw, DnsGroup::Domestic).is_err());
        let cidr = parse_rule_source("10.0.0.0/8\n");
        assert!(to_dns_rules(&cidr, DnsGroup::Domestic).is_err());
    }

    #[test]
    fn emitted_fragments_roundtrip_via_serde() {
        // 产物可被 serde 原样读回（seepctl 输出面契约）
        let src = parse_rule_source("example.com\n10.0.0.0/8\n");
        let routing = to_routing_rules(&src, "cn", "direct-main");
        let yaml = serde_yaml::to_string(&routing).expect("应可序列化");
        let back: Vec<RouteRule> = serde_yaml::from_str(&yaml).expect("应可读回");
        assert_eq!(back.len(), 2);

        let dns = to_dns_rules(&parse_rule_source("a.com"), DnsGroup::Domestic).unwrap();
        let yaml = serde_yaml::to_string(&dns).expect("应可序列化");
        let back: Vec<DnsRuleConfig> = serde_yaml::from_str(&yaml).expect("应可读回");
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn empty_source_yields_no_rules() {
        let src = parse_rule_source("# 只有注释\n\n");
        assert!(to_routing_rules(&src, "n", "t").is_empty());
        assert!(to_dns_rules(&src, DnsGroup::Domestic).unwrap().is_empty());
    }
}
