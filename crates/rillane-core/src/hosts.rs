//! DNS 静态 hosts 映射（G2-15，todo.md）：`network.dns.hosts` 域名→IP
//! 静态表，本地 DNS 面 A/AAAA 查询命中直接应答（真实映射地址，不触上游、
//! 不经 fake-ip——命中即静态直答语义，地址不属 fake-ip 池段故入口反查
//! 不介入，路由按该地址语义走）。
//!
//! 语义：
//! - 键统一小写精确匹配（DNS 大小写不敏感口径）；通配符/suffix 键 M1
//!   显式不做（命中失败即走上游，行为可预期）；
//! - 值须为 IPv4/IPv6 字面量；A 查询取表中 IPv4，AAAA 取 IPv6；名命中
//!   但该族无地址 → 空应答（NOERROR 0 answers，不泄上游）。

use std::collections::BTreeMap;
use std::net::IpAddr;

/// 静态 hosts 表：键小写域名，值该域的映射地址。
pub struct DnsHosts {
    entries: BTreeMap<String, Vec<IpAddr>>,
}

impl DnsHosts {
    /// 从配置映射构建。键 trim + 小写归一，键空白拒绝；值须为 IPv4/IPv6
    /// 字面量（trim 后解析）。空映射 = 空表（合法，等价 None）。
    pub fn from_map(map: &BTreeMap<String, String>) -> Result<Self, String> {
        let mut entries = BTreeMap::new();
        for (k, v) in map {
            let key = k.trim().to_ascii_lowercase();
            if key.is_empty() {
                return Err(format!("hosts 键不能为空：{k:?}"));
            }
            let ip: IpAddr = v
                .trim()
                .parse()
                .map_err(|_| format!("hosts 值须为 IPv4/IPv6 字面量：{k:?} → {v:?}"))?;
            entries.entry(key).or_insert_with(Vec::new).push(ip);
        }
        Ok(Self { entries })
    }

    /// 查询（精确小写匹配）：`None` = 名不在表中（调用方继续 fake-ip/
    /// 上游）；`Some(ips)` = 名在表中——A 取 IPv4、AAAA 取 IPv6（族不符
    /// 为空 Vec，调用方直接空应答）。
    pub fn lookup(&self, domain: &str, want_v4: bool) -> Option<Vec<IpAddr>> {
        let key = domain.trim().to_ascii_lowercase();
        self.entries.get(&key).map(|ips| {
            ips.iter()
                .filter(|ip| ip.is_ipv4() == want_v4)
                .copied()
                .collect()
        })
    }

    /// 表内域名数（观测面）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 表是否为空（观测面）。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample() -> DnsHosts {
        let mut map = BTreeMap::new();
        map.insert("a.test".to_string(), "10.0.0.1".to_string());
        map.insert("v6.test".to_string(), "::1".to_string());
        DnsHosts::from_map(&map).expect("应可构建")
    }

    #[test]
    fn from_map_parses_and_normalizes() {
        let mut map = BTreeMap::new();
        map.insert("  MiXeD.Test ".to_string(), " 10.0.0.2 ".to_string());
        let t = DnsHosts::from_map(&map).expect("应可构建");
        assert_eq!(t.len(), 1);
        // 键小写归一后可命中
        assert_eq!(
            t.lookup("mixed.test", true),
            Some(vec![IpAddr::from([10, 0, 0, 2])])
        );
        assert!(sample().len() == 2);
        // 空映射 = 空表
        let empty = DnsHosts::from_map(&BTreeMap::new()).expect("应可构建");
        assert!(empty.is_empty());
    }

    #[test]
    fn lookup_filters_family_and_misses() {
        let t = sample();
        // A 命中 v4；AAAA 名命中但族不符 → Some(空)（调用方空应答不泄上游）
        assert_eq!(
            t.lookup("a.test", true),
            Some(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
        );
        assert_eq!(t.lookup("a.test", false), Some(Vec::new()));
        // v6 条目对称
        assert_eq!(
            t.lookup("v6.test", false),
            Some(vec![IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])])
        );
        assert_eq!(t.lookup("v6.test", true), Some(Vec::new()));
        // 未命中 = None（继续 fake-ip/上游）
        assert_eq!(t.lookup("other.test", true), None);
        // 大小写不敏感
        assert_eq!(
            t.lookup("A.TEST", true).as_deref(),
            t.lookup("a.test", true).as_deref()
        );
    }

    #[test]
    fn from_map_rejects_bad_entries() {
        let mut map = BTreeMap::new();
        map.insert("bad.test".to_string(), "not-an-ip".to_string());
        assert!(DnsHosts::from_map(&map).is_err(), "非法 IP 字面量应拒绝");

        let mut map = BTreeMap::new();
        map.insert("   ".to_string(), "10.0.0.1".to_string());
        assert!(DnsHosts::from_map(&map).is_err(), "空白键应拒绝");

        let mut map = BTreeMap::new();
        map.insert("host.test".to_string(), "example.com".to_string());
        assert!(
            DnsHosts::from_map(&map).is_err(),
            "域名值应拒绝（M1 仅 IP 字面量）"
        );
    }
}
