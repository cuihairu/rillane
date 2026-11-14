//! GeoIP/GeoSite 数据库接入（G0-2）。
//!
//! 本模块持有路由面两类外部数据库：
//! - **GeoIP**：MaxMind DB 格式（`.mmdb`，GeoLite2/GeoIP2 Country），经
//!   `maxminddb` 惰性加载，按目标 IP 查询 ISO 3166-1 alpha-2 国家码；
//! - **GeoSite**：v2fly 格式（`.dat`，protobuf），经 `geosite-rs` 惰性加载，
//!   按域名查询站点类别（Plain/Domain/Full/Regex 四类匹配语义）。
//!
//! 数据库文件路径由配置面给出（`routing.geoip_db` / `routing.geosite_db`）。
//! 路径缺失时数据库缺席：对应条件恒不命中（与原「无数据库」行为一致），
//! 不阻塞启动（懒加载 + 缺失即 None）。文件存在但解析失败在首次匹配时
//! 记录 WARN 并保持未加载（fail-open，不静默吞错——见 `load_once`）。

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

/// 单一 GeoIP/GeoSite 数据库的惰性加载容器。
///
/// `RwLock<Option<Arc<...>>>`：None = 未加载或加载失败（记录 WARN 后保持
/// None 并置 `failed`，避免每流重复读盘/重复告警）；Some = 已加载句柄。
/// 加载失败只告警一次（`failed` 位），文件后续被替换需重启（热更不追踪
/// 数据库 mtime——数据库文件独立于配置热更，属 G0-2 明确范围外）。
pub struct GeoDatabases {
    geoip: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
    geosite: RwLock<Option<Arc<GeoSiteDb>>>,
    geoip_path: Option<PathBuf>,
    geosite_path: Option<PathBuf>,
    geoip_failed: RwLock<bool>,
    geosite_failed: RwLock<bool>,
}

/// 解析后的 GeoSite 数据库（v2fly `.dat`）。
///
/// 预构建「站点类别 → 域条目」索引，匹配热路径不做 protobuf 解析。
/// 域条目类型沿用 v2fly 语义：Plain=0（子串）、Regex=1（正则 `is_match`）、
/// Domain=2（根域后缀）、Full=3（完全相等）。未知类型整条跳过。
pub struct GeoSiteDb {
    /// 类别名（country_code 字段，如 `cn`）→ 条目集。
    groups: std::collections::HashMap<String, GeoSiteGroup>,
}

#[derive(Default)]
pub struct GeoSiteGroup {
    pub plains: Vec<String>,
    pub domains: Vec<GeoSiteDomain>,
    pub fulls: Vec<String>,
    pub regexes: Vec<Arc<regex::Regex>>,
}

/// GeoSite Domain 条目（加载期预小写并缓存 `.` + 值后缀串，匹配热路径
/// 不再逐条 `to_ascii_lowercase` / `format!` 分配）。
pub struct GeoSiteDomain {
    pub value: String,
    pub dotted: String,
}

impl GeoDatabases {
    /// 构造空容器（数据库路径可缺省）。
    pub fn new(geoip_path: Option<PathBuf>, geosite_path: Option<PathBuf>) -> Self {
        Self {
            geoip: RwLock::new(None),
            geosite: RwLock::new(None),
            geoip_path,
            geosite_path,
            geoip_failed: RwLock::new(false),
            geosite_failed: RwLock::new(false),
        }
    }

    /// 惰性加载 GeoIP mmdb（首次匹配时）。加载失败仅告警一次。
    pub fn geoip(&self) -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
        if let Some(db) = self.geoip.read().expect("geoip lock poisoned").clone() {
            return Some(db);
        }
        if *self.geoip_failed.read().expect("geoip_failed poisoned") {
            return None;
        }
        let Some(path) = &self.geoip_path else {
            return None;
        };
        let loaded = Self::load_mmdb(path);
        let mut slot = self.geoip.write().expect("geoip lock poisoned");
        if let Some(db) = loaded {
            *slot = Some(Arc::new(db));
            return slot.clone();
        }
        *self.geoip_failed.write().expect("geoip_failed poisoned") = true;
        None
    }

    /// 惰性加载 GeoSite `.dat`（首次匹配时）。加载失败仅告警一次。
    pub fn geosite(&self) -> Option<Arc<GeoSiteDb>> {
        if let Some(db) = self.geosite.read().expect("geosite lock poisoned").clone() {
            return Some(db);
        }
        if *self.geosite_failed.read().expect("geosite_failed poisoned") {
            return None;
        }
        let Some(path) = &self.geosite_path else {
            return None;
        };
        let loaded = Self::load_geosite(path);
        let mut slot = self.geosite.write().expect("geosite lock poisoned");
        if let Some(db) = loaded {
            *slot = Some(Arc::new(db));
            return slot.clone();
        }
        *self
            .geosite_failed
            .write()
            .expect("geosite_failed poisoned") = true;
        None
    }

    fn load_mmdb(path: &Path) -> Option<maxminddb::Reader<Vec<u8>>> {
        match maxminddb::Reader::open_readfile(path) {
            Ok(db) => Some(db),
            Err(e) => {
                tracing::warn!(
                    target: "rillane::routing::geo",
                    path = %path.display(),
                    error = %e,
                    "GeoIP mmdb 加载失败，geoip 条件恒不命中"
                );
                None
            }
        }
    }

    fn load_geosite(path: &Path) -> Option<GeoSiteDb> {
        let buf = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    target: "rillane::routing::geo",
                    path = %path.display(),
                    error = %e,
                    "GeoSite dat 读取失败，geosite 条件恒不命中"
                );
                return None;
            }
        };
        let list = match geosite_rs::decode_geosite(&buf) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    target: "rillane::routing::geo",
                    path = %path.display(),
                    error = %e,
                    "GeoSite dat 解析失败，geosite 条件恒不命中"
                );
                return None;
            }
        };
        let mut groups = std::collections::HashMap::new();
        for entry in &list.entry {
            let group = groups
                .entry(entry.country_code.to_ascii_lowercase())
                .or_insert_with(GeoSiteGroup::default);
            for domain in &entry.domain {
                match domain.r#type {
                    // v2fly 域条目类型：Plain=0（子串）、Regex=1、Domain=2
                    // （根域后缀）、Full=3（完全相等）。未知类型整条跳过。
                    0 => group.plains.push(domain.value.to_ascii_lowercase()),
                    1 => {
                        if let Ok(re) = regex::RegexBuilder::new(&domain.value)
                            .case_insensitive(true)
                            .build()
                        {
                            group.regexes.push(Arc::new(re));
                        }
                    }
                    2 => {
                        let value = domain.value.to_ascii_lowercase();
                        let dotted = format!(".{value}");
                        group.domains.push(GeoSiteDomain { value, dotted });
                    }
                    3 => group.fulls.push(domain.value.to_ascii_lowercase()),
                    _ => {}
                }
            }
        }
        Some(GeoSiteDb { groups })
    }
}

impl GeoSiteDb {
    /// 查询指定站点类别（不区分大小写）是否命中目标主机。
    /// 类别不存在 → false。匹配语义按 v2fly：
    /// - Plain：子串包含；
    /// - Domain：主机等于类别值或以其 `.` + 值为后缀（根域及子域）；
    /// - Full：完全相等；
    /// - Regex：加载期预编译并启用大小写不敏感，非法正则整条跳过。
    pub fn matches(&self, group: &str, host: &str) -> bool {
        // 类别键已按小写存储；常见类别即小写时免分配直查，否则回退小写查。
        let g = self
            .groups
            .get(group)
            .or_else(|| self.groups.get(&group.to_ascii_lowercase()));
        let Some(g) = g else {
            return false;
        };
        let host_lower = host.to_ascii_lowercase();
        g.plains.iter().any(|p| host_lower.contains(p))
            || g.domains
                .iter()
                .any(|d| host_lower == d.value || host_lower.ends_with(&d.dotted))
            || g.fulls.iter().any(|f| host_lower == f.as_str())
            || g.regexes.iter().any(|re| re.is_match(&host_lower))
    }
}

/// 查询 GeoIP mmdb 中某 IP 的 ISO 国家码（大写，如 `CN`）。未命中/解析
/// 失败返回 None（geoip 条件恒不命中）。
pub fn geoip_country(reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<String> {
    let result = reader.lookup(ip).ok()?;
    let rec: maxminddb::geoip2::Country = result.decode().ok()??;
    rec.country
        .iso_code
        .map(|s| s.to_ascii_uppercase())
        .or_else(|| {
            rec.registered_country
                .iso_code
                .map(|s| s.to_ascii_uppercase())
        })
}

/// 目标主机 → 可查询 IP：字面量直接解析；域名不解析（路由面不做 DNS，
/// GeoIP 仅对 IP 字面量目标生效——与 G0-1 IpCidr 同口径）。
pub fn host_to_ip(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rillane-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let path = temp_dir().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    fn sample_geosite_dat() -> Vec<u8> {
        use geosite_rs::{domain, Domain, GeoSite, GeoSiteList};
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "cn".to_string(),
                domain: vec![
                    Domain {
                        r#type: domain::Type::Domain as i32,
                        value: "example.com".to_string(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: domain::Type::Full as i32,
                        value: "exact.org".to_string(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: domain::Type::Plain as i32,
                        value: "video".to_string(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: domain::Type::Regex as i32,
                        value: r"^ad\d+\.".to_string(),
                        attribute: vec![],
                    },
                ],
            }],
        };
        geosite_rs::encode_geosite(list)
    }

    fn sample_mmdb() -> Vec<u8> {
        use maxminddb_writer::{paths::IpAddrWithMask, Database};
        let mut db = Database::default();
        db.metadata.database_type = "GeoLite2-Country".to_string();
        db.metadata.languages = vec!["en".to_string()];
        db.metadata.binary_format_major_version = 2;
        let cn: maxminddb::geoip2::Country = maxminddb::geoip2::Country {
            country: maxminddb::geoip2::country::Country {
                iso_code: Some("CN"),
                ..Default::default()
            },
            ..Default::default()
        };
        let data = db.insert_value(cn).unwrap();
        db.insert_node("1.0.0.0/8".parse::<IpAddrWithMask>().unwrap(), data);
        let mut buf = Vec::new();
        db.write_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn geosite_matches_v2fly_semantics() {
        let dat = sample_geosite_dat();
        let path = write_temp("sample-geosite.dat", &dat);
        let db = GeoDatabases::new(None, Some(path.clone()));
        let loaded = db.geosite().expect("应加载成功");

        // Domain 后缀：根域及子域命中
        assert!(loaded.matches("cn", "example.com"));
        assert!(loaded.matches("cn", "www.example.com"));
        assert!(!loaded.matches("cn", "notexample.com"));
        // Full 完全相等，子域不命中
        assert!(loaded.matches("cn", "exact.org"));
        assert!(!loaded.matches("cn", "sub.exact.org"));
        // Plain 子串
        assert!(loaded.matches("cn", "myvideo.net"));
        // Regex
        assert!(loaded.matches("cn", "ad123.example.net"));
        assert!(!loaded.matches("cn", "plain.example.net"));
        // 类别大小写不敏感；未知类别不命中
        assert!(loaded.matches("CN", "example.com"));
        assert!(!loaded.matches("us", "example.com"));
    }

    #[test]
    fn geosite_matching_is_case_insensitive_across_entry_types() {
        use geosite_rs::{domain, Domain, GeoSite, GeoSiteList};
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "CN".to_string(),
                domain: vec![
                    Domain {
                        r#type: domain::Type::Plain as i32,
                        value: "VIDEO".to_string(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: domain::Type::Domain as i32,
                        value: "EXAMPLE.COM".to_string(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: domain::Type::Full as i32,
                        value: "EXACT.ORG".to_string(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: domain::Type::Regex as i32,
                        value: r"^AD\d+\.".to_string(),
                        attribute: vec![],
                    },
                ],
            }],
        };
        let path = write_temp(
            "case-insensitive-geosite.dat",
            &geosite_rs::encode_geosite(list),
        );
        let db = GeoDatabases::new(None, Some(path));
        let loaded = db.geosite().expect("应加载成功");
        assert!(loaded.matches("cn", "MyVideo.Net"));
        assert!(loaded.matches("cn", "WWW.Example.Com"));
        assert!(loaded.matches("cn", "Exact.Org"));
        assert!(loaded.matches("cn", "AD123.Example.Net"));
    }

    #[test]
    fn geosite_missing_and_invalid_db_never_match() {
        // 路径缺失：恒不命中
        let db = GeoDatabases::new(None, None);
        assert!(db.geosite().is_none());

        // 文件不存在：加载失败一次，之后缓存失败位不再重复读盘
        let db = GeoDatabases::new(None, Some(temp_dir().join("no-such.dat")));
        assert!(db.geosite().is_none());
        assert!(db.geosite().is_none(), "失败位应保持");

        // 无效文件
        let path = write_temp("bad-geosite.dat", b"not protobuf");
        let db = GeoDatabases::new(None, Some(path));
        assert!(db.geosite().is_none());
    }

    #[test]
    fn geoip_country_lookup() {
        let mmdb = sample_mmdb();
        let path = write_temp("sample-geoip.mmdb", &mmdb);
        let db = GeoDatabases::new(Some(path.clone()), None);
        let reader = db.geoip().expect("应加载成功");
        assert_eq!(
            geoip_country(&reader, "1.2.3.4".parse().unwrap()),
            Some("CN".into())
        );
        assert_eq!(geoip_country(&reader, "8.8.8.8".parse().unwrap()), None);
        // 域名不解析
        assert_eq!(host_to_ip("example.com"), None);
        assert_eq!(host_to_ip("1.2.3.4"), Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn geoip_missing_db_never_matches() {
        let db = GeoDatabases::new(None, None);
        assert!(db.geoip().is_none());
        let db = GeoDatabases::new(Some(temp_dir().join("no-such.mmdb")), None);
        assert!(db.geoip().is_none());
    }
}
