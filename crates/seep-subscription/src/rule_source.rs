//! geosite/chnroutes 文本规则源批量导入（O-dns1，dns-partition.md §10）
//!
//! 输入 = v2fly 文本规则源行集（geosite 域名清单 / chnroutes CIDR 清单），
//! 逐行解析为结构化条目，再按目标面产出：
//! - 路由面（`routing.rules`）：域清单 → `DomainSuffix` 联合条件、
//!   `keyword:` → `DomainKeyword`、CIDR → `Network`——各成一条规则
//!   （`matches` 多条件是 AND，不同类型清单不能并进一条，见本文件 §AND）；
//! - DNS 分流面（`network.dns.rules`）：裸域/`domain:` → exact + suffix
//!   双 pattern（D-2：suffix 需前导点且不含本域，exact 补本域）、`full:` →
//!   exact；keyword/CIDR 在 DNS 面无对应模式，显式报错不静默降级。
//!
//! 语义对齐先例：clash.rs `DOMAIN → DomainSuffix`（Seep 无完全域匹配路由
//! 条件，转 suffix 并承认超集——`full:` 在路由面同样转 suffix）。

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
    /// 规范化 CIDR（裸 IP 补 /32 或 /128）
    pub cidrs: Vec<String>,
    /// 无法表达的条目及原因（regexp/include/属性行/格式坏行）——逐条报告不阻塞
    pub skipped: Vec<String>,
}

/// 路由面产物：最多三条规则（域/关键词/CIDR 各一，空类不出规则）。
/// 规则名取 `<name>`、`<name>-keyword`、`<name>-cidr`。
pub fn to_routing_rules(src: &RuleSourceImport, name: &str, target: &str) -> Vec<RouteRule> {
    let mut rules = Vec::new();
    let mut suffixes: Vec<String> = src.domains.clone();
    suffixes.extend(src.fulls.iter().cloned());
    if !suffixes.is_empty() {
        rules.push(RouteRule {
            name: name.to_string(),
            matches: vec![MatchCondition::DomainSuffix { values: suffixes }],
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
    if !src.cidrs.is_empty() {
        rules.push(RouteRule {
            name: format!("{name}-cidr"),
            matches: vec![MatchCondition::Network {
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
        if let Some(rest) = line.strip_prefix("regexp:") {
            out.skipped.push(format!("{line}（regexp 不进轻量规则面）"));
            let _ = rest;
            continue;
        }
        if line.starts_with("include:") {
            out.skipped
                .push(format!("{line}（include 需多文件聚合，单文件导入不支持）"));
            continue;
        }
        if line.contains('@') {
            out.skipped
                .push(format!("{line}（@属性过滤语义不在轻量面内）"));
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
        assert!(src.cidrs.is_empty());
        // regexp/include/属性行/坏域行逐条入 skipped 且原因可辨
        assert_eq!(src.skipped.len(), 5, "{:?}", src.skipped);
        assert!(src.skipped.iter().any(|s| s.contains("regexp")));
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

    #[test]
    fn routing_rules_split_by_condition_type() {
        // matches 多条件是 AND：不同类型清单各成一条规则（§AND）
        let src = parse_rule_source("example.com\nkeyword:video\n10.0.0.0/8\n");
        let rules = to_routing_rules(&src, "cn", "direct-main");
        assert_eq!(rules.len(), 3);
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
        assert_eq!(rules[2].name, "cn-cidr");
        assert!(matches!(
            &rules[2].matches[0],
            MatchCondition::Network { .. }
        ));

        // 纯域源只出一条规则；full 并入 suffix 联合（路由面无完全域匹配）
        let only_domains = parse_rule_source("a.com\nfull:b.com\n");
        let rules = to_routing_rules(&only_domains, "x", "auto");
        assert_eq!(rules.len(), 1);
        assert!(
            matches!(&rules[0].matches[0], MatchCondition::DomainSuffix { values } if values.len() == 2)
        );
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
