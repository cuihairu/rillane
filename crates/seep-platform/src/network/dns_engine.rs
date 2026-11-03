//! DNS 分流解析引擎（dns-partition.md §2/§3）
//!
//! `dns.rs` 是数据模型层；本文件是引擎面：
//! - wire format 手写 RFC 1035 最小编解码（A/AAAA/CNAME，D-1）
//! - 分流判定（exact/suffix 规则 → domestic/trusted 两组，D-2）
//! - TTL 钳位缓存 + 负缓存（D-4）
//! - 防污染二态（off / cross_check 并发双查，D-3）
//! - 原子计数统计快照（D-5）+ 本地 UDP 监听（D-7）

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU16, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::dns::{
    DnsCacheConfig, DnsConfig, DnsFilterRule, DnsHandler, DnsMonitor, DnsQuery, DnsRecord,
    DnsRecordData, DnsRecordType, DnsResponse, DnsResponseCode, DnsServer, DnsServerType, DnsStats,
};

// ---------------------------------------------------------------------------
// 域名规范化（D-4 / §5-E4）
// ---------------------------------------------------------------------------

/// 域名规范化：trim + 剔尾点 + ASCII 小写折叠；空域/超长/空标签 → Invalid。
///
/// 缓存键、分流匹配、wire 编码统一走本形——命中与判定一致性的前提。
pub fn normalize_domain(domain: &str) -> Result<String, ResolveError> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        return Err(ResolveError::InvalidDomain(domain.to_string()));
    }
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ResolveError::InvalidDomain(domain.to_string()));
        }
    }
    Ok(d)
}

/// 解析错误（§5-E2/NxDomain 区分面）
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("域名不存在（NXDOMAIN）：{0}")]
    NxDomain(String),
    #[error("上游全部失败：{0}")]
    UpstreamFailure(String),
    #[error("非法域名：{0}")]
    InvalidDomain(String),
}

// ---------------------------------------------------------------------------
// wire format（D-1 / §5-E5/E6）
// ---------------------------------------------------------------------------

/// 已解码的查询报文
#[derive(Debug, Clone)]
pub struct DnsWireQuery {
    pub id: u16,
    pub domain: String,
    pub qtype: DnsRecordType,
}

/// 已解码的应答报文
#[derive(Debug, Clone)]
pub struct DnsWireResponse {
    pub id: u16,
    pub rcode: u8,
    pub answers: Vec<DnsAnswer>,
}

/// 应答记录（引擎面数据形）
#[derive(Debug, Clone, PartialEq)]
pub struct DnsAnswer {
    pub domain: String,
    pub rtype: DnsRecordType,
    pub ttl: u32,
    pub data: DnsAnswerData,
}

/// 应答数据（MVP 支持面；`Other` 不回写应答）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswerData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Other,
}

impl DnsAnswer {
    /// A 记录便捷构造（测试/构造面）
    pub fn a(domain: &str, ip: Ipv4Addr, ttl: u32) -> Self {
        Self {
            domain: domain.to_string(),
            rtype: DnsRecordType::A,
            ttl,
            data: DnsAnswerData::A(ip),
        }
    }

    /// 应答中的 IP 集合（cross_check 分歧判定面，§5-E7）
    fn ips(&self) -> Option<IpAddr> {
        match self.data {
            DnsAnswerData::A(v4) => Some(IpAddr::V4(v4)),
            DnsAnswerData::Aaaa(v6) => Some(IpAddr::V6(v6)),
            _ => None,
        }
    }
}

/// 编码域名（标签形；调用前须规范化，编码失败即构造期错误）
fn encode_name(out: &mut Vec<u8>, domain: &str) -> Result<()> {
    let mut total = 1usize;
    for label in domain.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "非法域名标签：{label:?}"
        );
        total += 1 + label.len();
        ensure!(total <= 255, "域名超长（>255）：{domain:?}");
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// 读域名（支持压缩指针；§5-E5 跳数上限 32、总长上限 255）
///
/// 返回 `(域名, 名字结束处偏移)`——首个指针之后按跳转计，回溯位置记在
/// `next` 中供连续读取。
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut next: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        ensure!(pos < buf.len(), "名字读取越界");
        let len = buf[pos];
        match len & 0xC0 {
            0 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let l = len as usize;
                ensure!(pos + 1 + l <= buf.len(), "标签越界");
                labels.push(String::from_utf8_lossy(&buf[pos + 1..pos + 1 + l]).into_owned());
                pos += 1 + l;
                let total: usize = labels.iter().map(|s| s.len() + 1).sum();
                ensure!(total <= 255, "名字超长（>255）");
            }
            0xC0 => {
                ensure!(pos + 2 <= buf.len(), "压缩指针越界");
                let target = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
                if next.is_none() {
                    next = Some(pos + 2);
                }
                pos = target;
                jumps += 1;
                ensure!(jumps <= 32, "压缩指针跳数超限（疑似环）");
            }
            _ => bail!("保留标签类型（01/10）"),
        }
    }
    Ok((labels.join("."), next.unwrap_or(pos)))
}

/// 编码查询（header + 单 QD，RD=1，D-1）
pub fn encode_query(id: u16, domain: &str, qtype: DnsRecordType) -> Result<Vec<u8>> {
    let norm = normalize_domain(domain).map_err(|e| anyhow!("{e}"))?;
    let mut out = Vec::with_capacity(norm.len() + 16);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&[0u8; 6]); // AN/NS/AR = 0
    encode_name(&mut out, &norm)?;
    out.extend_from_slice(&qtype.as_u16().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

/// 解码查询（监听侧入面）
pub fn decode_query(buf: &[u8]) -> Result<DnsWireQuery> {
    ensure!(buf.len() >= 12, "查询报文短于头部");
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    ensure!(flags & 0x8000 == 0, "收到应答而非查询（QR=1）");
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    ensure!(qd >= 1, "查询无问题段（QD=0）");
    let (domain, pos) = read_name(buf, 12)?;
    ensure!(pos + 4 <= buf.len(), "问题段越界");
    let qtype = DnsRecordType::from_u16(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
    Ok(DnsWireQuery { id, domain, qtype })
}

/// 解码应答（上游入面；§5-E6 由调用方校验 id）
pub fn decode_response(buf: &[u8]) -> Result<DnsWireResponse> {
    ensure!(buf.len() >= 12, "应答报文短于头部");
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    ensure!(flags & 0x8000 != 0, "非应答报文（QR=0）");
    let rcode = (flags & 0x000F) as u8;
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(buf, pos)?;
        ensure!(p + 4 <= buf.len(), "问题段越界");
        pos = p + 4;
    }
    let mut answers = Vec::with_capacity(an.min(64));
    for _ in 0..an {
        let (name, p) = read_name(buf, pos)?;
        pos = p;
        ensure!(pos + 10 <= buf.len(), "应答固定段越界");
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        ensure!(pos + rdlen <= buf.len(), "rdata 越界");
        let data = match rtype {
            1 if rdlen == 4 => DnsAnswerData::A(Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            )),
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[pos..pos + 16]);
                DnsAnswerData::Aaaa(Ipv6Addr::from(octets))
            }
            5 => {
                let (cname, _) = read_name(buf, pos)?;
                DnsAnswerData::Cname(cname)
            }
            _ => DnsAnswerData::Other,
        };
        answers.push(DnsAnswer {
            domain: name,
            rtype: DnsRecordType::from_u16(rtype),
            ttl,
            data,
        });
        pos += rdlen;
    }
    Ok(DnsWireResponse { id, rcode, answers })
}

/// 编码应答（监听侧出面；`Other` 数据不回写，QR|RD|RA 置位）
pub fn encode_response(
    id: u16,
    domain: &str,
    qtype: DnsRecordType,
    rcode: u8,
    answers: &[DnsAnswer],
) -> Vec<u8> {
    // 先组记录体（类型从数据变体派生，防 rtype 与 rdata 失配）
    let mut body: Vec<(String, u16, u32, Vec<u8>)> = Vec::with_capacity(answers.len());
    for a in answers {
        let (rtype, rdata) = match &a.data {
            DnsAnswerData::A(v4) => (1u16, v4.octets().to_vec()),
            DnsAnswerData::Aaaa(v6) => (28u16, v6.octets().to_vec()),
            DnsAnswerData::Cname(c) => {
                let cn = match normalize_domain(c) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let mut tmp = Vec::new();
                if encode_name(&mut tmp, &cn).is_err() {
                    continue;
                }
                (5u16, tmp)
            }
            DnsAnswerData::Other => continue,
        };
        let name = match normalize_domain(&a.domain) {
            Ok(n) => n,
            Err(_) => continue,
        };
        body.push((name, rtype, a.ttl, rdata));
    }
    let qname = normalize_domain(domain).unwrap_or_else(|_| "_invalid".to_string());
    let mut out = Vec::with_capacity(12 + qname.len() + 16 + body.len() * 40);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8180u16 | (u16::from(rcode) & 0x000F)).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1（回显问题段）
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0u8; 4]); // NS/AR = 0
    let _ = encode_name(&mut out, &qname); // 规范化后必然成功
    out.extend_from_slice(&qtype.as_u16().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    for (name, rtype, ttl, rdata) in body {
        let _ = encode_name(&mut out, &name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

// ---------------------------------------------------------------------------
// 分流判定（D-2）
// ---------------------------------------------------------------------------

/// 上游组（命名按「污染风险」语义建模，§9-3）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamGroup {
    Domestic,
    Trusted,
}

/// 分流规则模式（轻量两态——正则变体不进热路径，§9-5）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionPattern {
    /// 完全匹配（规范化形存储）
    Exact(String),
    /// 后缀匹配（存储带前导点：`.cn`）
    Suffix(String),
}

impl PartitionPattern {
    fn matches(&self, norm_domain: &str) -> bool {
        match self {
            PartitionPattern::Exact(e) => norm_domain == e,
            PartitionPattern::Suffix(s) => norm_domain.ends_with(s.as_str()),
        }
    }
}

/// 分流表：规则先到先得 + default 兜底（D-2）
#[derive(Debug, Clone)]
pub struct DnsPartition {
    rules: Vec<(PartitionPattern, UpstreamGroup)>,
    default: UpstreamGroup,
}

impl DnsPartition {
    /// 构造并校验（§5-E1：exact 非空、suffix 须前导点、模式须可规范化）
    pub fn new(
        rules: Vec<(PartitionPattern, UpstreamGroup)>,
        default: UpstreamGroup,
    ) -> Result<Self> {
        let mut normalized = Vec::with_capacity(rules.len());
        for (pat, group) in rules {
            let pat = match pat {
                PartitionPattern::Exact(d) => {
                    let n =
                        normalize_domain(&d).map_err(|e| anyhow!("分流规则 exact 非法：{e}"))?;
                    PartitionPattern::Exact(n)
                }
                PartitionPattern::Suffix(s) => {
                    ensure!(
                        s.starts_with('.') && s.len() > 1,
                        "分流规则 suffix 须以 '.' 开头（裸域用 exact）：{s:?}"
                    );
                    let body = normalize_domain(&s[1..])
                        .map_err(|e| anyhow!("分流规则 suffix 主体非法：{e}"))?;
                    PartitionPattern::Suffix(format!(".{body}"))
                }
            };
            normalized.push((pat, group));
        }
        Ok(Self {
            rules: normalized,
            default,
        })
    }

    /// 判定域名应走的上游组（输入须为规范化形）
    pub fn select(&self, norm_domain: &str) -> UpstreamGroup {
        self.rules
            .iter()
            .find(|(pat, _)| pat.matches(norm_domain))
            .map(|(_, group)| *group)
            .unwrap_or(self.default)
    }
}

// ---------------------------------------------------------------------------
// 缓存（D-4 / §5-E3）
// ---------------------------------------------------------------------------

struct CacheEntry {
    expires: Instant,
    seq: u64,
    data: CacheEntryData,
}

enum CacheEntryData {
    Positive(Vec<DnsAnswer>),
    Negative,
}

/// 缓存命中形
#[derive(Debug, Clone)]
pub(crate) enum CacheHit {
    Positive(Vec<DnsAnswer>),
    Negative,
}

/// TTL 钳位缓存（键 = 规范域名 + qtype；负缓存独立开关）
pub(crate) struct DnsCache {
    max_entries: usize,
    min_ttl: u64,
    max_ttl: u64,
    enable_negative: bool,
    negative_ttl: u64,
    entries: HashMap<(String, u16), CacheEntry>,
    seq: u64,
}

impl DnsCache {
    pub(crate) fn new(cfg: &DnsCacheConfig) -> Self {
        Self {
            max_entries: cfg.max_entries.max(1),
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl.max(cfg.min_ttl),
            enable_negative: cfg.enable_negative_cache,
            negative_ttl: cfg.negative_ttl,
            entries: HashMap::new(),
            seq: 0,
        }
    }

    /// 查命中（过期当场移除；`now` 入参供测试钉时序）
    pub(crate) fn get(&mut self, key: &(String, u16), now: Instant) -> Option<CacheHit> {
        let expired = self.entries.get(key)?.expires <= now;
        if expired {
            self.entries.remove(key);
            return None;
        }
        match &self.entries.get(key)?.data {
            CacheEntryData::Positive(a) => Some(CacheHit::Positive(a.clone())),
            CacheEntryData::Negative => Some(CacheHit::Negative),
        }
    }

    /// 插正缓存（逐应答 TTL 钳位；全 0 不缓存，§5-E3）
    pub(crate) fn insert_positive(
        &mut self,
        key: (String, u16),
        answers: &[DnsAnswer],
        now: Instant,
    ) {
        let mut clamped: Vec<DnsAnswer> = Vec::with_capacity(answers.len());
        let mut entry_ttl: Option<u64> = None;
        for a in answers {
            let raw = u64::from(a.ttl);
            if raw == 0 {
                continue;
            }
            let t = raw.clamp(self.min_ttl, self.max_ttl);
            let mut a = a.clone();
            a.ttl = u32::try_from(t).unwrap_or(u32::MAX);
            entry_ttl = Some(entry_ttl.map_or(t, |e: u64| e.min(t)));
            clamped.push(a);
        }
        let Some(ttl) = entry_ttl else {
            return;
        };
        self.evict_if_full(&key);
        self.seq += 1;
        self.entries.insert(
            key,
            CacheEntry {
                expires: now + Duration::from_secs(ttl),
                seq: self.seq,
                data: CacheEntryData::Positive(clamped),
            },
        );
    }

    /// 插负缓存（独立开关与 TTL）
    pub(crate) fn insert_negative(&mut self, key: (String, u16), now: Instant) {
        if !self.enable_negative {
            return;
        }
        self.evict_if_full(&key);
        self.seq += 1;
        self.entries.insert(
            key,
            CacheEntry {
                expires: now + Duration::from_secs(self.negative_ttl),
                seq: self.seq,
                data: CacheEntryData::Negative,
            },
        );
    }

    /// 满员逐出最早插入（seq 序，D-4）
    fn evict_if_full(&mut self, key: &(String, u16)) {
        if self.entries.contains_key(key) || self.entries.len() < self.max_entries {
            return;
        }
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.seq)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            self.entries.remove(&k);
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// 统计（D-5）
// ---------------------------------------------------------------------------

/// 引擎统计计数器（Atomic 面——热路径无锁）
#[derive(Debug, Default)]
pub struct DnsStatsCounters {
    total_queries: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    upstream_failures: AtomicU64,
    pollution_suspected: AtomicU64,
    domestic_queries: AtomicU64,
    trusted_queries: AtomicU64,
}

impl DnsStatsCounters {
    fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 快照（hit_rate 口径同 `DnsStats::cache_hit_rate`）
    pub fn snapshot(&self) -> DnsStatsSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let hits = g(&self.cache_hits);
        let misses = g(&self.cache_misses);
        DnsStatsSnapshot {
            total_queries: g(&self.total_queries),
            cache_hits: hits,
            cache_misses: misses,
            upstream_failures: g(&self.upstream_failures),
            pollution_suspected: g(&self.pollution_suspected),
            domestic_queries: g(&self.domestic_queries),
            trusted_queries: g(&self.trusted_queries),
            cache_hit_rate: if hits + misses == 0 {
                0.0
            } else {
                hits as f64 / (hits + misses) as f64
            },
        }
    }
}

/// 统计快照（控制面暴露面，M1）
#[derive(Debug, Clone, PartialEq)]
pub struct DnsStatsSnapshot {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_failures: u64,
    pub pollution_suspected: u64,
    pub domestic_queries: u64,
    pub trusted_queries: u64,
    pub cache_hit_rate: f64,
}

// ---------------------------------------------------------------------------
// 解析器（D-3 / §5-E1/E2）
// ---------------------------------------------------------------------------

/// 防污染模式（D-3；不设 TrustedOnly——见 §9-3）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AntiPoison {
    /// 纯分流：单组直查，污染如实呈现
    #[default]
    Off,
    /// 并发双查：应答 IP 集合不相交判分歧，取 trusted 面
    CrossCheck,
}

/// 解析器构造配置
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// 国内/本地组上游
    pub domestic: Vec<SocketAddr>,
    /// 可信组上游
    pub trusted: Vec<SocketAddr>,
    /// 分流规则（先到先得）
    pub rules: Vec<(PartitionPattern, UpstreamGroup)>,
    /// 未命中兜底组
    pub default_group: UpstreamGroup,
    /// 防污染模式
    pub anti_poison: AntiPoison,
    /// 单次查询超时
    pub timeout: Duration,
    /// 每服务器重试次数（0 = 单次）
    pub retries: u32,
    /// 缓存配置（None = 不缓存）
    pub cache: Option<DnsCacheConfig>,
}

/// 分流解析器
pub struct DnsResolver {
    domestic: Vec<SocketAddr>,
    trusted: Vec<SocketAddr>,
    partition: DnsPartition,
    cache: Option<Mutex<DnsCache>>,
    anti_poison: AntiPoison,
    timeout: Duration,
    retries: u32,
    stats: DnsStatsCounters,
    query_ids: AtomicU16,
    /// singleflight（2026-11-03 P2）：并发冷名 miss 各自查上游的 stampede
    /// 去重。键 =（规范域名, qtype）；值 = 首查任务的 watch 发送端。首查
    /// 结果（含负缓存）经 watch 广播给所有等待者；等待者不重复查上游。
    /// tokio Mutex（守卫可跨 await，锁不跨上游查询——仅保护 map 访问）。
    inflight: tokio::sync::Mutex<InflightMap>,
}

/// singleflight 映射（见 DnsResolver::inflight 注）。
type InflightMap =
    HashMap<(String, u16), watch::Sender<Option<Result<Vec<DnsAnswer>, ResolveError>>>>;

impl fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsResolver")
            .field("anti_poison", &self.anti_poison)
            .field("domestic", &self.domestic)
            .field("trusted", &self.trusted)
            .finish_non_exhaustive()
    }
}

impl DnsResolver {
    /// 构造（§5-E1 全量校验：default 组 / 规则引用组非空、cross_check 双组非空）
    pub fn new(cfg: ResolverConfig) -> Result<Self> {
        ensure!(cfg.timeout > Duration::ZERO, "DNS 超时须大于 0");
        let group_empty = |g: UpstreamGroup| match g {
            UpstreamGroup::Domestic => cfg.domestic.is_empty(),
            UpstreamGroup::Trusted => cfg.trusted.is_empty(),
        };
        ensure!(
            !group_empty(cfg.default_group),
            "缺省上游组 {:?} 无可用服务器",
            cfg.default_group
        );
        for (_, group) in &cfg.rules {
            ensure!(
                !group_empty(*group),
                "分流规则指向的上游组 {group:?} 无可用服务器"
            );
        }
        if cfg.anti_poison == AntiPoison::CrossCheck {
            ensure!(
                !cfg.domestic.is_empty(),
                "cross_check 防污染需要 domestic 上游"
            );
            ensure!(
                !cfg.trusted.is_empty(),
                "cross_check 防污染需要 trusted 上游"
            );
        }
        let partition = DnsPartition::new(cfg.rules, cfg.default_group)?;
        let cache = cfg.cache.as_ref().map(|c| Mutex::new(DnsCache::new(c)));
        Ok(Self {
            domestic: cfg.domestic,
            trusted: cfg.trusted,
            partition,
            cache,
            anti_poison: cfg.anti_poison,
            timeout: cfg.timeout,
            retries: cfg.retries,
            stats: DnsStatsCounters::default(),
            query_ids: AtomicU16::new(0x4E00),
            inflight: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// 统计快照（验收「命中率有指标」的读取面）
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot {
        self.stats.snapshot()
    }

    /// 清空缓存
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.lock().expect("dns cache lock").clear();
        }
    }

    /// 解析域名（分流 → 防污染 → 缓存；§5-E2 全败不 fallback）
    pub async fn resolve(
        &self,
        domain: &str,
        qtype: DnsRecordType,
    ) -> Result<Vec<DnsAnswer>, ResolveError> {
        let d = normalize_domain(domain)?;
        let key = (d.clone(), qtype.as_u16());
        self.stats.inc(&self.stats.total_queries);

        if let Some(cache) = &self.cache {
            let hit = cache
                .lock()
                .expect("dns cache lock")
                .get(&key, Instant::now());
            match hit {
                Some(CacheHit::Positive(a)) => {
                    self.stats.inc(&self.stats.cache_hits);
                    return Ok(a);
                }
                Some(CacheHit::Negative) => {
                    self.stats.inc(&self.stats.cache_hits);
                    return Err(ResolveError::NxDomain(d));
                }
                None => self.stats.inc(&self.stats.cache_misses),
            }
        }

        // singleflight：并发冷名去重。首个调用者执行上游查询，其余等待其
        // 结果（watch 广播），不重复查上游（§5-E 突发 stampede 防御）。
        // 锁只保护 map 访问（短临界），不跨上游查询。循环：先看槽位——
        // 占用则等待；空则抢占成为首查者（退出循环执行查询）。
        let (tx, _rx) = watch::channel(None);
        let mut saw_dead_leader = false;
        loop {
            let mut inflight = self.inflight.lock().await;
            if let Some(existing) = inflight.get(&key) {
                let mut rx = existing.subscribe();
                drop(inflight);
                if rx.changed().await.is_ok() {
                    if let Some(res) = rx.borrow_and_update().clone() {
                        return res;
                    }
                }
                // 首查失败/发送端 drop：继续循环，重试抢占（防活锁）。
                if saw_dead_leader {
                    break;
                }
                saw_dead_leader = true;
                continue;
            } else {
                inflight.insert(key.clone(), tx.clone());
                break;
            }
        }

        // 首查者：执行上游查询并广播结果。
        let group = self.partition.select(&d);
        let result = match (group, self.anti_poison) {
            (UpstreamGroup::Domestic, AntiPoison::CrossCheck) => self.cross_check(&d, qtype).await,
            (g, _) => self.query_group(g, &d, qtype).await,
        };

        if let Some(cache) = &self.cache {
            let now = Instant::now();
            let mut c = cache.lock().expect("dns cache lock");
            match &result {
                Ok(answers) => c.insert_positive(key.clone(), answers, now),
                Err(ResolveError::NxDomain(_)) => c.insert_negative(key.clone(), now),
                Err(_) => {}
            }
        }

        // 广播给等待者，随后移除 inflight 槽位（仅首查者移除）。
        let _ = tx.send(Some(result.clone()));
        self.inflight.lock().await.remove(&key);
        result
    }

    /// cross_check 面（§5-E7）：两面 IP 集合不相交 → 取 trusted + 计数
    async fn cross_check(
        &self,
        domain: &str,
        qtype: DnsRecordType,
    ) -> Result<Vec<DnsAnswer>, ResolveError> {
        let (dom, trs) = tokio::join!(
            self.query_group(UpstreamGroup::Domestic, domain, qtype),
            self.query_group(UpstreamGroup::Trusted, domain, qtype),
        );
        match (dom, trs) {
            (Ok(d), Ok(t)) => {
                let ipset = |a: &[DnsAnswer]| -> HashSet<IpAddr> {
                    a.iter().filter_map(DnsAnswer::ips).collect()
                };
                let (sd, st) = (ipset(&d), ipset(&t));
                if !sd.is_empty() && !st.is_empty() && sd.is_disjoint(&st) {
                    self.stats.inc(&self.stats.pollution_suspected);
                    Ok(t)
                } else {
                    Ok(d)
                }
            }
            (Ok(d), Err(_)) => Ok(d),
            (Err(_), Ok(t)) => Ok(t),
            (Err(a), Err(b)) => Err(ResolveError::UpstreamFailure(format!(
                "domestic: {a}; trusted: {b}"
            ))),
        }
    }

    /// 单组查询（组内逐服务器 × retries；§5-E2 全败记数返回）
    async fn query_group(
        &self,
        group: UpstreamGroup,
        domain: &str,
        qtype: DnsRecordType,
    ) -> Result<Vec<DnsAnswer>, ResolveError> {
        let servers = match group {
            UpstreamGroup::Domestic => {
                self.stats.inc(&self.stats.domestic_queries);
                &self.domestic
            }
            UpstreamGroup::Trusted => {
                self.stats.inc(&self.stats.trusted_queries);
                &self.trusted
            }
        };
        let mut last_err: Option<String> = None;
        for server in servers {
            for _attempt in 0..=self.retries {
                match query_upstream(*server, domain, qtype, self.timeout, &self.query_ids).await {
                    Ok(resp) => {
                        if resp.rcode == 3 {
                            // NXDOMAIN 终止重试（负缓存由 resolve 插入）
                            return Err(ResolveError::NxDomain(domain.to_string()));
                        }
                        if resp.rcode != 0 {
                            last_err = Some(format!("{server}: rcode {}", resp.rcode));
                            continue;
                        }
                        if resp.answers.is_empty() {
                            last_err = Some(format!("{server}: 空应答"));
                            continue;
                        }
                        return Ok(resp.answers);
                    }
                    Err(e) => last_err = Some(e),
                }
            }
        }
        self.stats.inc(&self.stats.upstream_failures);
        Err(ResolveError::UpstreamFailure(
            last_err.unwrap_or_else(|| "无可用上游".to_string()),
        ))
    }
}

/// 单上游 UDP 查询（临时端口 + connect 源过滤 + §5-E6 id 校验）
async fn query_upstream(
    server: SocketAddr,
    domain: &str,
    qtype: DnsRecordType,
    timeout: Duration,
    ids: &AtomicU16,
) -> Result<DnsWireResponse, String> {
    let id = ids.fetch_add(1, Ordering::Relaxed);
    let packet = encode_query(id, domain, qtype).map_err(|e| format!("编码失败：{e}"))?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("绑定临时端口失败：{e}"))?;
    sock.connect(server)
        .await
        .map_err(|e| format!("连接 {server} 失败：{e}"))?;
    let recv = tokio::time::timeout(timeout, async {
        sock.send(&packet)
            .await
            .map_err(|e| format!("发送失败：{e}"))?;
        let mut buf = vec![0u8; 512];
        let n = sock
            .recv(&mut buf)
            .await
            .map_err(|e| format!("接收失败：{e}"))?;
        buf.truncate(n);
        Ok::<Vec<u8>, String>(buf)
    })
    .await
    .map_err(|_| format!("{server} 超时（{timeout:?}）"))??;
    let resp = decode_response(&recv).map_err(|e| format!("{server} 解码失败：{e}"))?;
    if resp.id != id {
        return Err(format!(
            "{server} 应答 id 不匹配（期望 {id}，得 {}）",
            resp.id
        ));
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// 本地 UDP 监听（D-7）
// ---------------------------------------------------------------------------

/// 本地 DNS 监听（recv → 解码 → resolve → 回包；oneshot 关桥排空）
pub struct LocalDnsServer {
    resolver: Arc<DnsResolver>,
    local_address: IpAddr,
    local_port: u16,
}

impl LocalDnsServer {
    pub fn new(resolver: Arc<DnsResolver>, local_address: IpAddr, local_port: u16) -> Self {
        Self {
            resolver,
            local_address,
            local_port,
        }
    }

    /// 监听地址
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.local_address, self.local_port)
    }

    /// 服务循环：关桥信号到达即停收（在途查询任务自然收尾）
    pub async fn serve(self, shutdown: oneshot::Receiver<()>) -> Result<()> {
        let std_sock = std::net::UdpSocket::bind((self.local_address, self.local_port))
            .with_context(|| {
                format!(
                    "绑定 DNS 监听 {}:{} 失败",
                    self.local_address, self.local_port
                )
            })?;
        std_sock.set_nonblocking(true).context("设监听非阻塞失败")?;
        let sock = UdpSocket::from_std(std_sock.try_clone().context("克隆监听 socket 失败")?)
            .context("注册监听 socket 失败")?;
        let mut shutdown = shutdown;
        let mut buf = vec![0u8; 512];
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                recvd = sock.recv_from(&mut buf) => match recvd {
                    Ok((n, peer)) => {
                        let data = buf[..n].to_vec();
                        // 每查询克隆 socket 走独立任务（回包源端口不变；克隆继承非阻塞位）
                        let worker = match std_sock.try_clone() {
                            Ok(s) => match UdpSocket::from_std(s) {
                                Ok(w) => w,
                                Err(e) => { warn!("注册查询 socket 失败：{e}"); continue }
                            },
                            Err(e) => { warn!("克隆查询 socket 失败：{e}"); continue }
                        };
                        let resolver = self.resolver.clone();
                        tokio::spawn(async move {
                            handle_dns_query(worker, peer, data, resolver).await;
                        });
                    }
                    Err(e) => warn!("DNS 监听收包失败：{e}"),
                }
            }
        }
        Ok(())
    }
}

/// 单查询处理（坏查询丢弃；NXDOMAIN/失败按 rcode 回写）
async fn handle_dns_query(
    sock: UdpSocket,
    peer: SocketAddr,
    data: Vec<u8>,
    resolver: Arc<DnsResolver>,
) {
    let reply = match decode_query(&data) {
        Ok(q) => match resolver.resolve(&q.domain, q.qtype).await {
            Ok(answers) => encode_response(q.id, &q.domain, q.qtype, 0, &answers),
            Err(ResolveError::NxDomain(_)) => encode_response(q.id, &q.domain, q.qtype, 3, &[]),
            Err(e) => {
                debug!("DNS 查询失败（回 SERVFAIL）：{e}");
                encode_response(q.id, &q.domain, q.qtype, 2, &[])
            }
        },
        Err(e) => {
            debug!("丢弃坏 DNS 查询：{e:#}");
            return;
        }
    };
    if let Err(e) = sock.send_to(&reply, peer).await {
        debug!("DNS 回包失败：{e}");
    }
}

// ---------------------------------------------------------------------------
// DnsHandler 桥接（D-6：工厂真实现）
// ---------------------------------------------------------------------------

/// 引擎承载的 `DnsHandler` 实现（既有 NetworkManager 路径的桥）
pub struct EngineDnsHandler {
    config: DnsConfig,
    resolver: Arc<DnsResolver>,
    local_address: IpAddr,
    local_port: u16,
    shutdown_tx: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for EngineDnsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineDnsHandler")
            .field(
                "listen",
                &format_args!("{}:{}", self.local_address, self.local_port),
            )
            .finish_non_exhaustive()
    }
}

impl EngineDnsHandler {
    /// 从 `DnsConfig` 装配（D-6：UDP 直连可用；加密/零上游 Err 指引）
    pub fn from_dns_config(config: &DnsConfig) -> Result<Self> {
        let mut udp = Vec::new();
        let mut rejected = Vec::new();
        for s in &config.servers {
            if !s.enabled {
                continue;
            }
            s.validate()?;
            match s.server_type {
                DnsServerType::Udp => udp.push(s.address),
                other => rejected.push(format!("{}({:?})", s.name, other)),
            }
        }
        ensure!(
            rejected.is_empty(),
            "DNS 上游为 TCP/加密类型（MVP 仅支持 UDP 上游，dns-partition.md §9-1）：{}",
            rejected.join(", ")
        );
        ensure!(!udp.is_empty(), "无可用 UDP DNS 上游（enabled 或类型核对）");
        ensure!(
            config.local_port != 0,
            "本地监听端口不能为 0（配置面无端口发现通道）"
        );
        if !config.filters.is_empty() {
            warn!(
                "DNS 过滤规则（filters）不在 P2-8 面内，已忽略 {} 条（dns-partition.md §9-5）",
                config.filters.len()
            );
        }
        let resolver = DnsResolver::new(ResolverConfig {
            domestic: Vec::new(),
            trusted: udp,
            rules: Vec::new(),
            default_group: UpstreamGroup::Trusted,
            anti_poison: AntiPoison::Off,
            timeout: config.timeout,
            retries: config.retries,
            cache: config.cache.clone(),
        })?;
        Ok(Self {
            config: config.clone(),
            resolver: Arc::new(resolver),
            local_address: config.local_address,
            local_port: config.local_port,
            shutdown_tx: tokio::sync::Mutex::new(None),
            task: tokio::sync::Mutex::new(None),
        })
    }

    /// 引擎直通（控制面/测试读取面）
    pub fn resolver(&self) -> Arc<DnsResolver> {
        self.resolver.clone()
    }
}

fn answer_to_record(a: &DnsAnswer) -> DnsRecord {
    let data = match &a.data {
        DnsAnswerData::A(v4) => DnsRecordData::A(*v4),
        DnsAnswerData::Aaaa(v6) => DnsRecordData::Aaaa(*v6),
        DnsAnswerData::Cname(c) => DnsRecordData::Cname(c.clone()),
        DnsAnswerData::Other => DnsRecordData::Unknown(Vec::new()),
    };
    DnsRecord::new(a.domain.clone(), a.rtype, a.ttl, data)
}

#[async_trait::async_trait]
impl DnsHandler for EngineDnsHandler {
    fn config(&self) -> &DnsConfig {
        &self.config
    }

    fn stats(&self) -> DnsStats {
        let s = self.resolver.stats_snapshot();
        let mut server_queries = HashMap::new();
        server_queries.insert("domestic".to_string(), s.domestic_queries);
        server_queries.insert("trusted".to_string(), s.trusted_queries);
        DnsStats {
            total_queries: s.total_queries,
            cache_hits: s.cache_hits,
            cache_misses: s.cache_misses,
            filter_hits: 0,
            successful_responses: 0,
            failed_responses: 0,
            average_response_time_ms: 0.0,
            server_queries,
            record_type_queries: HashMap::new(),
            last_updated: Instant::now(),
        }
    }

    async fn start(&self) -> Result<()> {
        let mut tx = self.shutdown_tx.lock().await;
        ensure!(tx.is_none(), "DNS 监听已启动（重复 start）");
        let (stx, srx) = oneshot::channel();
        let server =
            LocalDnsServer::new(self.resolver.clone(), self.local_address, self.local_port);
        let handle = tokio::spawn(async move {
            if let Err(e) = server.serve(srx).await {
                error!("DNS 监听异常退出：{e:#}");
            }
        });
        *self.task.lock().await = Some(handle);
        *tx = Some(stx);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        if let Some(stx) = self.shutdown_tx.lock().await.take() {
            let _ = stx.send(());
        }
        if let Some(handle) = self.task.lock().await.take() {
            let _ = handle.await;
        }
        Ok(())
    }

    async fn handle_query(&self, query: DnsQuery) -> Result<DnsResponse> {
        let started = Instant::now();
        let (code, records) = match self
            .resolver
            .resolve(&query.domain, query.record_type)
            .await
        {
            Ok(answers) => (
                DnsResponseCode::NoError,
                answers.iter().map(answer_to_record).collect(),
            ),
            Err(ResolveError::NxDomain(_)) => (DnsResponseCode::NXDomain, Vec::new()),
            Err(e) => {
                debug!("DNS 查询失败：{e}");
                (DnsResponseCode::ServFail, Vec::new())
            }
        };
        Ok(DnsResponse {
            query_id: query.id,
            response_code: code,
            ttl: records.iter().map(|r| r.ttl).min().unwrap_or(0),
            records,
            authority_records: Vec::new(),
            additional_records: Vec::new(),
            response_time: started.elapsed(),
            server: SocketAddr::new(self.local_address, self.local_port),
        })
    }

    async fn add_server(&self, _server: DnsServer) -> Result<()> {
        Err(anyhow!(
            "MVP 静态配置面：上游变更走配置热更新（dns-partition.md §9-5）"
        ))
    }

    async fn remove_server(&self, _name: &str) -> Result<()> {
        Err(anyhow!(
            "MVP 静态配置面：上游变更走配置热更新（dns-partition.md §9-5）"
        ))
    }

    async fn add_filter_rule(&self, _rule: DnsFilterRule) -> Result<()> {
        Err(anyhow!("过滤规则不在 P2-8 面内（dns-partition.md §9-5）"))
    }

    async fn remove_filter_rule(&self, _name: &str) -> Result<()> {
        Err(anyhow!("过滤规则不在 P2-8 面内（dns-partition.md §9-5）"))
    }

    async fn clear_cache(&self) -> Result<()> {
        self.resolver.clear_cache();
        Ok(())
    }

    async fn flush_cache(&self) -> Result<()> {
        self.resolver.clear_cache();
        Ok(())
    }

    async fn monitor_events(&self) -> Result<Box<dyn DnsMonitor>> {
        Err(anyhow!("MVP 无 DNS 事件流（dns-partition.md §6）"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use super::super::dns::{DnsMode, DnsQueryType, TlsConfig};

    fn v4(domain: &str, ip: [u8; 4], ttl: u32) -> DnsAnswer {
        DnsAnswer::a(domain, Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), ttl)
    }

    fn base_cfg() -> ResolverConfig {
        ResolverConfig {
            domestic: Vec::new(),
            trusted: Vec::new(),
            rules: Vec::new(),
            default_group: UpstreamGroup::Trusted,
            anti_poison: AntiPoison::Off,
            timeout: Duration::from_millis(400),
            retries: 0,
            cache: Some(DnsCacheConfig::default()),
        }
    }

    /// mock 上游：按域名返回 (rcode, answers)，计数到达查询（§7-4/5 数据源）
    async fn spawn_mock(
        responder: impl Fn(&str) -> (u8, Vec<DnsAnswer>) + Send + Sync + 'static,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(q) = decode_query(&buf[..n]) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let (rcode, answers) = responder(&q.domain);
                let reply = encode_response(q.id, &q.domain, q.qtype, rcode, &answers);
                let _ = sock.send_to(&reply, peer).await;
            }
        });
        (addr, hits)
    }

    /// §7-1：查询 golden 字节（id/flags/qname/qtype 逐偏移；含规范化小写）
    #[test]
    fn wire_query_golden_bytes() {
        let q = encode_query(0x1234, "Example.COM.", DnsRecordType::A).unwrap();
        let expect: Vec<u8> = [
            &[0x12, 0x34][..],
            &[0x01, 0x00], // RD=1
            &[0x00, 0x01], // QDCOUNT
            &[0x00; 6],
            &[7],
            b"example" as &[u8],
            &[3],
            b"com",
            &[0],
            &[0x00, 0x01], // qtype A
            &[0x00, 0x01], // IN
        ]
        .concat();
        assert_eq!(q, expect);
    }

    /// §7-1：压缩指针应答解码（golden 手组字节）
    #[test]
    fn wire_decode_response_with_compression_ptr() {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&0xabcu16.to_be_bytes());
        b.extend_from_slice(&0x8180u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes()); // QD
        b.extend_from_slice(&2u16.to_be_bytes()); // AN
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&[7]);
        b.extend_from_slice(b"example");
        b.extend_from_slice(&[3]);
        b.extend_from_slice(b"com");
        b.extend_from_slice(&[0]);
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        // answer1: 指针 → offset 12，A 1.2.3.4 ttl 300
        b.extend_from_slice(&0xC00Cu16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&[1, 2, 3, 4]);
        // answer2: 指针，AAAA ::1 ttl 60
        b.extend_from_slice(&0xC00Cu16.to_be_bytes());
        b.extend_from_slice(&28u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&60u32.to_be_bytes());
        b.extend_from_slice(&16u16.to_be_bytes());
        b.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let resp = decode_response(&b).unwrap();
        assert_eq!(resp.id, 0xabc);
        assert_eq!(resp.rcode, 0);
        assert_eq!(resp.answers.len(), 2);
        assert_eq!(
            resp.answers[0].data,
            DnsAnswerData::A(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(resp.answers[0].ttl, 300);
        assert_eq!(
            resp.answers[1].data,
            DnsAnswerData::Aaaa(Ipv6Addr::LOCALHOST)
        );
    }

    /// §7-1：E5 指针环 / 截断 / QR=0 拒收
    #[test]
    fn wire_decode_rejects_bad_frames() {
        // 短头
        assert!(decode_response(&[0u8; 8]).is_err());
        // QR=0（查询当应答）
        let mut q = encode_query(1, "a.b", DnsRecordType::A).unwrap();
        assert!(decode_response(&q).is_err());
        // 压缩指针自指环（E5）
        let mut ring = vec![0u8; 12];
        ring[4] = 0;
        ring[5] = 1; // QD=1 迫使读名字
        ring.extend_from_slice(&[0xC0, 0x0C]); // 指向自身
        assert!(decode_response(&ring).is_err());
        // rdata 越界（rdlen 声 4 实 2）
        q[2] = 0x81;
        q[3] = 0x80; // QR=1
        q[6] = 0;
        q[7] = 1; // AN=1
        q.extend_from_slice(&0xC00Cu16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u32.to_be_bytes());
        q.extend_from_slice(&4u16.to_be_bytes());
        q.extend_from_slice(&[1, 2]);
        assert!(decode_response(&q).is_err());
    }

    /// §7-2：规则命中 / 先到先得 / default 回退 / 规范化存储
    #[test]
    fn partition_select_order_and_default() {
        let p = DnsPartition::new(
            vec![
                (
                    PartitionPattern::Exact("a.b".into()),
                    UpstreamGroup::Domestic,
                ),
                (
                    PartitionPattern::Suffix(".b".into()),
                    UpstreamGroup::Trusted,
                ),
            ],
            UpstreamGroup::Trusted,
        )
        .unwrap();
        assert_eq!(p.select("a.b"), UpstreamGroup::Domestic, "先到先得");
        assert_eq!(p.select("x.b"), UpstreamGroup::Trusted);
        assert_eq!(
            p.select("other.com"),
            UpstreamGroup::Trusted,
            "default 兜底"
        );
        let p2 = DnsPartition::new(
            vec![(
                PartitionPattern::Exact("MiXeD.CaSe".into()),
                UpstreamGroup::Domestic,
            )],
            UpstreamGroup::Trusted,
        )
        .unwrap();
        assert_eq!(p2.select("mixed.case"), UpstreamGroup::Domestic, "小写存储");
    }

    /// §5-E1：suffix 前导点校验 + 尾点规范化 + 裸 TLD 不吃 suffix
    #[test]
    fn partition_validates_and_normalizes_suffix() {
        assert!(DnsPartition::new(
            vec![(
                PartitionPattern::Suffix("cn".into()),
                UpstreamGroup::Domestic
            )],
            UpstreamGroup::Trusted,
        )
        .is_err());
        assert!(DnsPartition::new(
            vec![(
                PartitionPattern::Exact(String::new()),
                UpstreamGroup::Domestic
            )],
            UpstreamGroup::Trusted,
        )
        .is_err());
        let p = DnsPartition::new(
            vec![(
                PartitionPattern::Suffix(".CN.".into()),
                UpstreamGroup::Domestic,
            )],
            UpstreamGroup::Trusted,
        )
        .unwrap();
        assert_eq!(p.select("www.x.cn"), UpstreamGroup::Domestic);
        assert_eq!(
            p.select("cn"),
            UpstreamGroup::Trusted,
            "裸 TLD 不吃 .cn 后缀"
        );
    }

    /// §7-3：TTL 钳位 / ttl=0 不缓存 / 逐出最旧 / 负缓存到期
    #[test]
    fn cache_clamp_evict_negative() {
        let cfg = DnsCacheConfig {
            max_entries: 10,
            min_ttl: 60,
            max_ttl: 100,
            enable_negative_cache: true,
            negative_ttl: 30,
            ..DnsCacheConfig::default()
        };
        let now = Instant::now();
        let mut c = DnsCache::new(&cfg);
        let key = ("a.test".to_string(), 1);
        c.insert_positive(key.clone(), &[v4("a.test", [1, 1, 1, 1], 5)], now);
        match c.get(&key, now).unwrap() {
            CacheHit::Positive(a) => assert_eq!(a[0].ttl, 60, "下钳位"),
            _ => panic!("应命中正缓存"),
        }
        let key2 = ("b.test".to_string(), 1);
        c.insert_positive(key2.clone(), &[v4("b.test", [2, 2, 2, 2], 1000)], now);
        match c.get(&key2, now).unwrap() {
            CacheHit::Positive(a) => assert_eq!(a[0].ttl, 100, "上钳位"),
            _ => panic!("应命中正缓存"),
        }
        let key0 = ("zero.test".to_string(), 1);
        c.insert_positive(key0.clone(), &[v4("zero.test", [3, 3, 3, 3], 0)], now);
        assert!(c.get(&key0, now).is_none(), "ttl=0 不缓存");
        let nk = ("nx.test".to_string(), 1);
        c.insert_negative(nk.clone(), now);
        assert!(matches!(c.get(&nk, now), Some(CacheHit::Negative)));
        assert!(
            c.get(&nk, now + Duration::from_secs(31)).is_none(),
            "负缓存应到期"
        );
        // 逐出最旧（独立小缓存 max=2）
        let mut small = DnsCache::new(&DnsCacheConfig {
            max_entries: 2,
            ..DnsCacheConfig::default()
        });
        let k1 = ("1".to_string(), 1);
        let k2 = ("2".to_string(), 1);
        let k3 = ("3".to_string(), 1);
        small.insert_positive(k1.clone(), &[v4("1", [1, 1, 1, 1], 300)], now);
        small.insert_positive(k2.clone(), &[v4("2", [2, 2, 2, 2], 300)], now);
        small.insert_positive(k3.clone(), &[v4("3", [3, 3, 3, 3], 300)], now);
        assert!(small.get(&k1, now).is_none(), "最旧应被逐出");
        assert!(small.get(&k2, now).is_some());
        assert!(small.get(&k3, now).is_some());
    }

    /// §5-E1 构造校验：default/规则引用组/cross_check 双组/timeout
    #[test]
    fn resolver_config_validates() {
        let err = DnsResolver::new(base_cfg()).unwrap_err();
        assert!(err.to_string().contains("无可用服务器"), "{err}");
        let cfg = ResolverConfig {
            trusted: vec!["223.5.5.5:53".parse().unwrap()],
            rules: vec![(
                PartitionPattern::Suffix(".cn".into()),
                UpstreamGroup::Domestic,
            )],
            ..base_cfg()
        };
        let err = DnsResolver::new(cfg).unwrap_err();
        assert!(err.to_string().contains("Domestic"), "{err}");
        let cfg = ResolverConfig {
            trusted: vec!["1.1.1.1:53".parse().unwrap()],
            anti_poison: AntiPoison::CrossCheck,
            ..base_cfg()
        };
        let err = DnsResolver::new(cfg).unwrap_err();
        assert!(err.to_string().contains("cross_check"), "{err}");
        let cfg = ResolverConfig {
            trusted: vec!["1.1.1.1:53".parse().unwrap()],
            timeout: Duration::ZERO,
            ..base_cfg()
        };
        assert!(DnsResolver::new(cfg).is_err());
    }

    /// §7-3：规范化入缓存键——二次查询命中 + hit_rate 口径 + E4 非法域
    #[tokio::test]
    async fn resolver_normalizes_and_serves_from_cache() {
        let (mock, hits) = spawn_mock(|_| (0, vec![v4("x", [9, 9, 9, 9], 300)])).await;
        let cfg = ResolverConfig {
            trusted: vec![mock],
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a1 = r.resolve("EXAMPLE.COM.", DnsRecordType::A).await.unwrap();
        assert_eq!(a1[0].data, DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)));
        let a2 = r.resolve("example.com", DnsRecordType::A).await.unwrap();
        assert_eq!(a2, a1, "大小写+尾点规范化后同键");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "第二次应走缓存");
        let s = r.stats_snapshot();
        assert_eq!((s.cache_hits, s.cache_misses), (1, 1));
        assert!((s.cache_hit_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(
            r.resolve("", DnsRecordType::A).await,
            Err(ResolveError::InvalidDomain(String::new()))
        );
        assert_eq!(
            r.resolve("a..b", DnsRecordType::A).await,
            Err(ResolveError::InvalidDomain("a..b".into()))
        );
    }

    /// P2 深审回归（2026-11-03）：并发冷名 miss 只查一次上游（singleflight）。
    /// tokio::join! 同时发起 N=8 同名 A 查询，上游到达计数应为 1（此前
    /// 全部 miss 会击穿上游）。全部结果一致且非空。
    #[tokio::test]
    async fn resolver_concurrent_cold_miss_singleflight() {
        let (mock, hits) = spawn_mock(|_| (0, vec![v4("x", [9, 9, 9, 9], 300)])).await;
        let cfg = ResolverConfig {
            trusted: vec![mock],
            ..base_cfg()
        };
        let r = Arc::new(DnsResolver::new(cfg).unwrap());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let rr = r.clone();
            tasks.push(tokio::spawn(async move {
                rr.resolve("singleflight.test", DnsRecordType::A).await
            }));
        }
        for task in tasks {
            let answers = task.await.unwrap().unwrap();
            assert!(!answers.is_empty());
            assert_eq!(answers[0].data, DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)));
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "并发冷名 miss 应 singleflight，仅一次上游查询"
        );
        // inflight 槽位应被清理，不泄漏。
        assert!(
            r.inflight.lock().await.is_empty(),
            "查询完成后 inflight 应清理"
        );
    }

    /// 验收口径 1：规则命中走 domestic、未命中走 default（到达面断言）
    #[tokio::test]
    async fn resolver_routes_to_selected_group() {
        let (dom, dom_hits) = spawn_mock(|_| (0, vec![v4("x", [6, 6, 6, 6], 300)])).await;
        let (trs, trs_hits) = spawn_mock(|_| (0, vec![v4("x", [9, 9, 9, 9], 300)])).await;
        let cfg = ResolverConfig {
            domestic: vec![dom],
            trusted: vec![trs],
            rules: vec![(
                PartitionPattern::Suffix(".cn".into()),
                UpstreamGroup::Domestic,
            )],
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a = r.resolve("site.CN", DnsRecordType::A).await.unwrap();
        assert_eq!(
            a[0].data,
            DnsAnswerData::A(Ipv4Addr::new(6, 6, 6, 6)),
            "规则命中走 domestic"
        );
        assert_eq!(dom_hits.load(Ordering::SeqCst), 1);
        assert_eq!(trs_hits.load(Ordering::SeqCst), 0);
        let a = r.resolve("other.com", DnsRecordType::A).await.unwrap();
        assert_eq!(
            a[0].data,
            DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)),
            "未命中走 default"
        );
        assert_eq!(dom_hits.load(Ordering::SeqCst), 1);
        assert_eq!(trs_hits.load(Ordering::SeqCst), 1);
        let s = r.stats_snapshot();
        assert_eq!((s.domestic_queries, s.trusted_queries), (1, 1));
    }

    /// 验收口径 3（off 面）：domestic 污染结果如实返回
    #[tokio::test]
    async fn anti_poison_off_serves_domestic_as_is() {
        let (dom, _) = spawn_mock(|d| {
            let ip = if d == "evil.test" {
                [6, 6, 6, 6]
            } else {
                [7, 7, 7, 7]
            };
            (0, vec![v4(d, ip, 300)])
        })
        .await;
        let (trs, _) = spawn_mock(|_| (0, vec![v4("x", [9, 9, 9, 9], 300)])).await;
        let cfg = ResolverConfig {
            domestic: vec![dom],
            trusted: vec![trs],
            rules: vec![(
                PartitionPattern::Suffix(".test".into()),
                UpstreamGroup::Domestic,
            )],
            ..base_cfg() // anti_poison = Off
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a = r.resolve("evil.test", DnsRecordType::A).await.unwrap();
        assert_eq!(
            a[0].data,
            DnsAnswerData::A(Ipv4Addr::new(6, 6, 6, 6)),
            "off 面如实呈现 domestic 结果"
        );
        assert_eq!(r.stats_snapshot().pollution_suspected, 0);
    }

    /// 验收口径 3（cross_check 面）：分歧取 trusted + 计数；一致取 domestic
    #[tokio::test]
    async fn anti_poison_cross_check_detects_disagreement() {
        let (dom, _) = spawn_mock(|d| {
            let ip = if d == "agree.test" {
                [7, 7, 7, 7]
            } else {
                [6, 6, 6, 6]
            };
            (0, vec![v4(d, ip, 300)])
        })
        .await;
        let (trs, _) = spawn_mock(|d| {
            let ip = if d == "agree.test" {
                [7, 7, 7, 7]
            } else {
                [9, 9, 9, 9]
            };
            (0, vec![v4(d, ip, 300)])
        })
        .await;
        let cfg = ResolverConfig {
            domestic: vec![dom],
            trusted: vec![trs],
            rules: vec![(
                PartitionPattern::Suffix(".test".into()),
                UpstreamGroup::Domestic,
            )],
            anti_poison: AntiPoison::CrossCheck,
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a = r.resolve("evil.test", DnsRecordType::A).await.unwrap();
        assert_eq!(
            a[0].data,
            DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)),
            "分歧取 trusted 面（防污染）"
        );
        assert_eq!(r.stats_snapshot().pollution_suspected, 1);
        let a = r.resolve("agree.test", DnsRecordType::A).await.unwrap();
        assert_eq!(
            a[0].data,
            DnsAnswerData::A(Ipv4Addr::new(7, 7, 7, 7)),
            "一致取 domestic 面（地理就近）"
        );
        assert_eq!(r.stats_snapshot().pollution_suspected, 1, "一致不计分歧");
    }

    /// §5-E7：单边失败取成功方不计分歧
    #[tokio::test]
    async fn cross_check_single_side_failure_takes_success() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let (trs, _) = spawn_mock(|_| (0, vec![v4("x", [9, 9, 9, 9], 300)])).await;
        let cfg = ResolverConfig {
            domestic: vec![silent_addr],
            trusted: vec![trs],
            rules: vec![(
                PartitionPattern::Suffix(".test".into()),
                UpstreamGroup::Domestic,
            )],
            anti_poison: AntiPoison::CrossCheck,
            timeout: Duration::from_millis(150),
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a = r.resolve("evil.test", DnsRecordType::A).await.unwrap();
        assert_eq!(a[0].data, DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(r.stats_snapshot().pollution_suspected, 0);
    }

    /// §5-E2：上游全败（不 fallback 系统 DNS）
    #[tokio::test]
    async fn resolver_all_upstreams_fail() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a1 = s1.local_addr().unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a2 = s2.local_addr().unwrap();
        let cfg = ResolverConfig {
            trusted: vec![a1, a2],
            timeout: Duration::from_millis(80),
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let err = r.resolve("x.com", DnsRecordType::A).await.unwrap_err();
        assert!(matches!(err, ResolveError::UpstreamFailure(_)));
        assert_eq!(r.stats_snapshot().upstream_failures, 1);
    }

    /// §7-3：NXDOMAIN 负缓存命中（上游计数不增）
    #[tokio::test]
    async fn nxdomain_negative_cache_hit() {
        let (mock, hits) = spawn_mock(|_| (3, vec![])).await;
        let cfg = ResolverConfig {
            trusted: vec![mock],
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let err = r.resolve("gone.test", DnsRecordType::A).await.unwrap_err();
        assert!(matches!(err, ResolveError::NxDomain(_)));
        let err2 = r.resolve("gone.test", DnsRecordType::A).await.unwrap_err();
        assert!(matches!(err2, ResolveError::NxDomain(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "第二次走负缓存");
        let s = r.stats_snapshot();
        assert_eq!((s.cache_hits, s.cache_misses), (1, 1));
    }

    /// §7-6：监听端到端（真 socket 查询 → 应答/NXDOMAIN → 关桥退出）
    #[tokio::test]
    async fn local_dns_server_end_to_end() {
        let (mock, _) = spawn_mock(|d| {
            if d == "nx.test" {
                (3, vec![])
            } else {
                (0, vec![v4(d, [8, 8, 4, 4], 120)])
            }
        })
        .await;
        let cfg = ResolverConfig {
            trusted: vec![mock],
            ..base_cfg()
        };
        let resolver = Arc::new(DnsResolver::new(cfg).unwrap());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let server = LocalDnsServer::new(resolver, "127.0.0.1".parse().unwrap(), port);
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(server.serve(rx));
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli.connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        // 端口释放有窗口——发包轮询直到收答
        let mut raw = [0u8; 512];
        let mut got = None;
        for _ in 0..100 {
            let q = encode_query(0x4242, "example.com", DnsRecordType::A).unwrap();
            if cli.send(&q).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            if let Ok(n) =
                tokio::time::timeout(Duration::from_millis(100), cli.recv(&mut raw)).await
            {
                got = Some(n.unwrap());
                break;
            }
        }
        let n = got.expect("监听应答查询");
        let resp = decode_response(&raw[..n]).unwrap();
        assert_eq!(resp.id, 0x4242);
        assert_eq!(resp.rcode, 0);
        assert_eq!(
            resp.answers[0].data,
            DnsAnswerData::A(Ipv4Addr::new(8, 8, 4, 4))
        );
        // NXDOMAIN → rcode 3
        let q = encode_query(0x77, "nx.test", DnsRecordType::A).unwrap();
        cli.send(&q).await.unwrap();
        let n = cli.recv(&mut raw).await.unwrap();
        let resp = decode_response(&raw[..n]).unwrap();
        assert_eq!((resp.id, resp.rcode), (0x77, 3));
        // 关桥排空
        drop(tx);
        let out = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("serve 应退出")
            .unwrap();
        assert!(out.is_ok());
    }

    /// §7-7 工厂：UDP 可用 / 加密上游 Err / 零上游 Err / 端口 0 Err
    #[test]
    fn factory_udp_ok_encrypted_err() {
        let dns_cfg = |servers: Vec<DnsServer>, port: u16| DnsConfig {
            mode: DnsMode::Direct,
            servers,
            cache: None,
            filters: vec![],
            enabled: true,
            local_port: port,
            local_address: "127.0.0.1".parse().unwrap(),
            timeout: Duration::from_secs(1),
            retries: 1,
        };
        let udp = DnsServer::new(
            "udp".into(),
            "223.5.5.5:53".parse().unwrap(),
            DnsServerType::Udp,
        );
        let h = EngineDnsHandler::from_dns_config(&dns_cfg(vec![udp], 15353)).unwrap();
        assert_eq!(h.config().local_port, 15353);
        let mut doh = DnsServer::new(
            "doh".into(),
            "1.1.1.1:443".parse().unwrap(),
            DnsServerType::Doh,
        );
        doh.tls_config = Some(TlsConfig::new("cloudflare-dns.com".into()));
        let err = EngineDnsHandler::from_dns_config(&dns_cfg(vec![doh], 15353)).unwrap_err();
        assert!(err.to_string().contains("UDP"), "{err}");
        let err = EngineDnsHandler::from_dns_config(&dns_cfg(vec![], 15353)).unwrap_err();
        assert!(err.to_string().contains("UDP"), "{err}");
        let udp = DnsServer::new(
            "udp".into(),
            "223.5.5.5:53".parse().unwrap(),
            DnsServerType::Udp,
        );
        let err = EngineDnsHandler::from_dns_config(&dns_cfg(vec![udp], 0)).unwrap_err();
        assert!(err.to_string().contains("端口"), "{err}");
    }

    /// DnsHandler 桥接：handle_query 直通 + start/stop 生命周期
    #[tokio::test]
    async fn handler_lifecycle_and_handle_query() {
        let (mock, _) = spawn_mock(|_| (0, vec![v4("x", [1, 0, 0, 1], 60)])).await;
        let dns_cfg = DnsConfig {
            mode: DnsMode::Direct,
            servers: vec![DnsServer::new("udp".into(), mock, DnsServerType::Udp)],
            cache: None,
            filters: vec![],
            enabled: true,
            local_port: 15354,
            local_address: "127.0.0.1".parse().unwrap(),
            timeout: Duration::from_secs(2),
            retries: 0,
        };
        let h = EngineDnsHandler::from_dns_config(&dns_cfg).unwrap();
        let q = DnsQuery {
            id: 7,
            domain: "example.com".into(),
            record_type: DnsRecordType::A,
            query_type: DnsQueryType::Standard,
            client_ip: "127.0.0.1".parse().unwrap(),
            timestamp: Instant::now(),
        };
        let resp = h.handle_query(q).await.unwrap();
        assert_eq!(resp.query_id, 7);
        assert_eq!(resp.response_code, DnsResponseCode::NoError);
        assert_eq!(resp.records.len(), 1);
        assert!(
            matches!(&resp.records[0].data, DnsRecordData::A(ip) if *ip == "1.0.0.1".parse::<Ipv4Addr>().unwrap()),
            "A 记录数据面：{:?}",
            resp.records[0].data
        );
        h.start().await.unwrap();
        assert!(h.start().await.is_err(), "重复 start 应 Err");
        h.stop().await.unwrap();
        h.start().await.unwrap();
        h.stop().await.unwrap();
    }
}
