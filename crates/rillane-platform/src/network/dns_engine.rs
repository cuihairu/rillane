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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::{
    rustls::{self, client::danger::ServerCertVerifier},
    TlsConnector,
};
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

/// 加密上游形态（G1-8）：UDP / DoT（RFC 7858）/ DoH（RFC 8484）。
///
/// wire 格式三态共用（RFC 1035 编解码复用同一套）；UDP 之外的 TLS 校验
/// 由 [`ResolverConfig::tls_skip_verify`] 统一裁决（缺省校验，webpki 根）。
#[derive(Debug, Clone, PartialEq)]
pub enum DnsUpstream {
    /// 传统 UDP DNS（`ip:port`）
    Udp(SocketAddr),
    /// DNS over TLS：`tls://host[:port]`（缺省 853）。host 可为 IP 或域名
    /// （域名在连接期经系统解析器落地——引导期自举问题 M1 接受此口径）；
    /// SNI = host 原串。
    Dot {
        host: String,
        port: u16,
        sni: String,
    },
    /// DNS over HTTPS：完整 `https://…` URL（GET `?dns=` base64url，
    /// RFC 8484 §4.1 建议载荷 id=0）
    Doh { url: String },
}

impl DnsUpstream {
    /// 解析上游串（dns_config.rs 转换层与引擎测试共用）：
    /// `ip:port` → Udp；`tls://host[:port]` / `dot://…` → Dot（缺省 853，
    /// host 缺失即 Err）；`https://…` → Doh（整 URL 保留）。
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("https://") {
            ensure!(
                !rest.trim().is_empty() && rest.trim() != "/",
                "DoH 上游 URL 缺 host:{s:?}"
            );
            return Ok(DnsUpstream::Doh { url: s.to_string() });
        }
        if let Some(rest) = s
            .strip_prefix("tls://")
            .or_else(|| s.strip_prefix("dot://"))
        {
            let (host, port) = match rest.rsplit_once(':') {
                Some((h, p)) => {
                    let port: u16 = p
                        .parse()
                        .with_context(|| format!("DoT 上游端口非法:{s:?}"))?;
                    ensure!(port != 0, "DoT 上游端口不能为 0:{s:?}");
                    (h, port)
                }
                None => (rest, 853),
            };
            ensure!(
                !host.is_empty() && !host.contains('/'),
                "DoT 上游缺 host:{s:?}"
            );
            return Ok(DnsUpstream::Dot {
                host: host.to_string(),
                port,
                sni: host.to_string(),
            });
        }
        let addr: SocketAddr = s.parse().with_context(|| {
            format!("DNS 上游须为 ip:port / tls://host:port / https://url 形式:{s:?}")
        })?;
        ensure!(addr.port() != 0, "DNS 上游端口不能为 0:{s:?}");
        Ok(DnsUpstream::Udp(addr))
    }
}

impl fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsUpstream::Udp(a) => write!(f, "udp:{a}"),
            DnsUpstream::Dot { host, port, .. } => write!(f, "tls://{host}:{port}"),
            DnsUpstream::Doh { url } => write!(f, "doh:{url}"),
        }
    }
}

/// 解析器构造配置
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// 国内/本地组上游
    pub domestic: Vec<DnsUpstream>,
    /// 可信组上游
    pub trusted: Vec<DnsUpstream>,
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
    /// DoT/DoH 证书校验开关（缺省 false = 校验；回环测试置 true）
    pub tls_skip_verify: bool,
    /// 出站 fwmark（RIL-020 DNS 上游 socket 旁路）：非 0 时上游 UDP/DoT
    /// socket 打 SO_MARK 走逃逸表（net_mark 半边①配套 `ip rule fwmark`
    /// 半边②）——TUN include 路由下 DNS 上游不被拽回代理环。0 = 不打
    /// （存量零差异）；DoH 经 reqwest 无 socket 级入口，mark ≠ 0 时
    /// 显式降级 warn（一次）。
    pub egress_mark: u32,
}

/// DoT/DoH 共享 TLS 面（每解析器构造一次；connector + DoH HTTP 客户端）。
/// 进程级 TLS 提供方显式选 ring（依赖图同持 ring 与 aws_lc_rs 两特征，
/// `builder()` 双提供方歧义下 panic——rillane-protocols tls.rs 同款裁决）。
struct DnsTlsCtx {
    connector: TlsConnector,
    doh: reqwest::Client,
}

fn dns_tls_ctx(skip_verify: bool) -> Result<DnsTlsCtx> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        // install_default Err = 已有默认 provider，尊重既有安装
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?;
    let config = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    let doh = reqwest::Client::builder()
        .danger_accept_invalid_certs(skip_verify)
        .build()
        .context("DoH HTTP 客户端构造失败")?;
    Ok(DnsTlsCtx {
        connector: TlsConnector::from(std::sync::Arc::new(config)),
        doh,
    })
}

/// 跳过证书验证的验证器（回环测试专用路径；生产缺省不启用）
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// 分流解析器
pub struct DnsResolver {
    domestic: Vec<DnsUpstream>,
    trusted: Vec<DnsUpstream>,
    partition: DnsPartition,
    cache: Option<Mutex<DnsCache>>,
    anti_poison: AntiPoison,
    timeout: Duration,
    retries: u32,
    stats: DnsStatsCounters,
    query_ids: AtomicU16,
    /// singleflight（2026-11-03 P2）：并发冷名 miss 各自查上游的 stampede
    /// 去重。键 =（规范域名, qtype）；值 = 首查任务的 watch 接收端。首查
    /// 结果（含负缓存）经 watch 广播给所有等待者；等待者不重复查上游。
    /// tokio Mutex（守卫可跨 await，锁不跨上游查询——仅保护 map 访问）。
    inflight: tokio::sync::Mutex<InflightMap>,
    /// DoT/DoH 共享 TLS 面（无加密上游也构造——构造成本一次，避免逐查询判空）
    tls: DnsTlsCtx,
    /// 出站 fwmark（RIL-020 上游 socket 旁路；0 = 不打）
    egress_mark: u32,
}

/// singleflight 映射（见 DnsResolver::inflight 注）。
#[derive(Clone)]
struct InflightSlot {
    receiver: watch::Receiver<Option<Result<Vec<DnsAnswer>, ResolveError>>>,
    token: Arc<()>,
}

type InflightMap = HashMap<(String, u16), InflightSlot>;

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
        let tls = dns_tls_ctx(cfg.tls_skip_verify)?;
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
            egress_mark: cfg.egress_mark,
            tls,
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
        let (tx, rx) = watch::channel(None);
        let token = Arc::new(());
        loop {
            let mut inflight = self.inflight.lock().await;
            if let Some(slot) = inflight.get(&key) {
                let mut rx = slot.receiver.clone();
                let token = slot.token.clone();
                drop(inflight);
                if rx.changed().await.is_ok() {
                    if let Some(res) = rx.borrow_and_update().clone() {
                        return res;
                    }
                }
                let mut inflight = self.inflight.lock().await;
                if let Some(current) = inflight.get(&key) {
                    if Arc::ptr_eq(&current.token, &token) {
                        inflight.remove(&key);
                    }
                }
                continue;
            } else {
                inflight.insert(
                    key.clone(),
                    InflightSlot {
                        receiver: rx.clone(),
                        token: token.clone(),
                    },
                );
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
        let mut inflight = self.inflight.lock().await;
        if let Some(current) = inflight.get(&key) {
            if Arc::ptr_eq(&current.token, &token) {
                inflight.remove(&key);
            }
        }
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
                match query_upstream(
                    server,
                    domain,
                    qtype,
                    self.timeout,
                    &self.query_ids,
                    &self.tls,
                    self.egress_mark,
                )
                .await
                {
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

/// 单上游查询分发（G1-8）：UDP / DoT / DoH 三态同 wire 格式（RFC 1035）。
/// UDP/DoT 用随机 id 并校验应答 id（§5-E6）；DoH 按 RFC 8484 §4.1 载荷
/// id=0（缓存友好，TLS 已保真伪）。
async fn query_upstream(
    server: &DnsUpstream,
    domain: &str,
    qtype: DnsRecordType,
    timeout: Duration,
    ids: &AtomicU16,
    tls: &DnsTlsCtx,
    egress_mark: u32,
) -> Result<DnsWireResponse, String> {
    match server {
        DnsUpstream::Udp(addr) => {
            let id = ids.fetch_add(1, Ordering::Relaxed);
            udp_exchange(
                *addr,
                id,
                &encode_query(id, domain, qtype).map_err(|e| format!("编码失败:{e}"))?,
                timeout,
                egress_mark,
            )
            .await
        }
        DnsUpstream::Dot { host, port, sni } => {
            let id = ids.fetch_add(1, Ordering::Relaxed);
            let packet = encode_query(id, domain, qtype).map_err(|e| format!("编码失败:{e}"))?;
            let io = DotIo {
                connector: &tls.connector,
                egress_mark,
            };
            dot_exchange(host, *port, sni, &packet, id, timeout, &io).await
        }
        DnsUpstream::Doh { url } => {
            if egress_mark != 0 {
                warn_doh_unbypassed(url);
            }
            let packet = encode_query(0, domain, qtype).map_err(|e| format!("编码失败:{e}"))?;
            doh_exchange(url, &packet, timeout, &tls.doh).await
        }
    }
}

/// DoH 旁路缺口显式降级（进程级一次）：reqwest 无 socket 级打点入口，
/// mark ≠ 0 时 DoH 上游走系统栈（TUN include 下可能进隧道）——点名
/// 原因与可用替代（UDP/DoT 上游已旁路），不静默。
static DOH_UNBYPASSED_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
fn warn_doh_unbypassed(url: &str) {
    if DOH_UNBYPASSED_WARNED.get().is_none() && DOH_UNBYPASSED_WARNED.set(()).is_ok() {
        tracing::warn!(
            target: "rillane::network",
            %url,
            "DoH 上游无 socket 级旁路入口（reqwest 不暴露 socket），egress_mark 对 DoH 不生效——TUN include 下 DoH 查询可能经隧道；需要旁路请改用 UDP/DoT 上游"
        );
    }
}

/// 单上游 UDP 查询（临时端口 + connect 源过滤 + §5-E6 id 校验）。
/// socket 经 net_mark 旁路面建（RIL-020：mark ≠ 0 打 SO_MARK，TUN
/// include 下查询不被拽回隧道；降级纪律同 net_mark）。
async fn udp_exchange(
    server: SocketAddr,
    id: u16,
    packet: &[u8],
    timeout: Duration,
    egress_mark: u32,
) -> Result<DnsWireResponse, String> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let bind_addr: SocketAddr = bind.parse().expect("临时绑定地址恒法");
    let std_sock = rillane_core::net_mark::bind_udp_marked(bind_addr, egress_mark)
        .map_err(|e| format!("绑定临时端口失败：{e}"))?;
    let sock = UdpSocket::from_std(std_sock).map_err(|e| format!("socket 收编失败：{e}"))?;
    sock.connect(server)
        .await
        .map_err(|e| format!("连接 {server} 失败：{e}"))?;
    let recv = tokio::time::timeout(timeout, async {
        sock.send(packet)
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

/// DoT 对端连接（RIL-020 旁路面）：mark=0 走原生 `connect`（多候选
/// 首胜语义零差异）；mark ≠ 0 时先落地 host 候选再逐个 marked 连接
///（首个胜出；set_mark 失败降级由 net_mark 统一处理）。
async fn connect_peer_marked(peer: &str, egress_mark: u32) -> Result<TcpStream, String> {
    if egress_mark == 0 {
        return TcpStream::connect(peer)
            .await
            .map_err(|e| format!("连接 {peer} 失败：{e}"));
    }
    let addrs = tokio::task::spawn_blocking({
        let peer = peer.to_string();
        move || {
            std::net::ToSocketAddrs::to_socket_addrs(&peer)
                .map(|i| i.collect::<Vec<_>>())
                .map_err(std::io::Error::other)
        }
    })
    .await
    .map_err(|e| format!("解析任务失败：{e}"))?
    .map_err(|e| format!("解析 {peer} 失败：{e}"))?;
    let mut last: Option<std::io::Error> = None;
    for addr in addrs {
        match rillane_core::net_mark::connect_tcp_marked(addr, egress_mark).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(format!(
        "连接 {peer} 失败：{}",
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "无候选地址".to_string())
    ))
}

/// DoT 交换（RFC 7858）：TCP+TLS 连接后逐消息 2 字节大端长度前缀。
/// host 允许域名（连接期经系统解析器落地）；SNI = 配置 host。
/// DoT 连接 IO 上下文（TLS 面 + 旁路 mark，RIL-020）。
struct DotIo<'a> {
    connector: &'a TlsConnector,
    egress_mark: u32,
}

async fn dot_exchange(
    host: &str,
    port: u16,
    sni: &str,
    packet: &[u8],
    id: u16,
    timeout: Duration,
    io: &DotIo<'_>,
) -> Result<DnsWireResponse, String> {
    let peer = format!("{host}:{port}");
    let fut = async {
        // RIL-020：连接经 net_mark 旁路面（mark ≠ 0 打 SO_MARK 逃逸）
        let tcp = connect_peer_marked(&peer, io.egress_mark).await?;
        let name = rustls::pki_types::ServerName::try_from(sni.to_string())
            .map_err(|e| format!("SNI {sni:?} 非法：{e}"))?;
        let mut stream = io
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| format!("{peer} TLS 握手失败：{e}"))?;
        stream
            .write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .map_err(|e| format!("{peer} 写长度失败：{e}"))?;
        stream
            .write_all(packet)
            .await
            .map_err(|e| format!("{peer} 写查询失败：{e}"))?;
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("{peer} 读长度失败：{e}"))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| format!("{peer} 读应答失败：{e}"))?;
        Ok::<Vec<u8>, String>(buf)
    };
    let recv = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| format!("{peer} 超时（{timeout:?}）"))??;
    let resp = decode_response(&recv).map_err(|e| format!("{peer} 解码失败：{e}"))?;
    if resp.id != id {
        return Err(format!(
            "{peer} 应答 id 不匹配（期望 {id}，得 {}）",
            resp.id
        ));
    }
    Ok(resp)
}

/// DoH 交换（RFC 8484 GET）：`?dns=` base64url 无填充，载荷 id=0，
/// `accept: application/dns-message`；应答体即 wire 消息。
async fn doh_exchange(
    url: &str,
    packet: &[u8],
    timeout: Duration,
    client: &reqwest::Client,
) -> Result<DnsWireResponse, String> {
    let b64 = URL_SAFE_NO_PAD.encode(packet);
    let fut = async {
        let resp = client
            .get(url)
            .query(&[("dns", &b64)])
            .header("accept", "application/dns-message")
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| format!("{url} 请求失败：{e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("{url} 上游返回 {status}"));
        }
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !content_type.starts_with("application/dns-message") {
            tracing::warn!(target: "rillane::network", %content_type, %url, "DoH 应答 content-type 非 dns-message");
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("{url} 读应答失败：{e}"))?;
        Ok::<Vec<u8>, String>(body.to_vec())
    };
    let recv = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| format!("{url} 超时（{timeout:?}）"))??;
    let resp = decode_response(&recv).map_err(|e| format!("{url} 解码失败：{e}"))?;
    if resp.id != 0 {
        return Err(format!("{url} 应答 id 应为 0（RFC 8484），得 {}", resp.id));
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
    /// fake-ip 池（G1-10）：Some = 对客户端 A 查询按池段稳定假地址应答
    ///（不触上游，TTL 1）；None = 关闭，存量行为零差异
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
    /// 静态 hosts 表（G2-15）：Some = A/AAAA 查询命中直接应答真实映射
    /// 地址（不触上游、不经 fake-ip，优先级高于 fake-ip）；None = 无表，
    /// 存量行为零差异
    hosts: Option<Arc<rillane_core::hosts::DnsHosts>>,
    /// 代际源（RIL-020 解析上下文）：Some = fake-ip 分配把当下配置代际
    /// 身份写进绑定（`reverse_with_context` 可读，路由据此挂正确代际）；
    /// None = 空代际（显式缺失，不伪造）。builder 注入，存量构造零差异。
    generation_source: Option<Arc<dyn Fn() -> String + Send + Sync>>,
}

impl LocalDnsServer {
    pub fn new(
        resolver: Arc<DnsResolver>,
        local_address: IpAddr,
        local_port: u16,
        fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
        hosts: Option<Arc<rillane_core::hosts::DnsHosts>>,
    ) -> Self {
        Self {
            resolver,
            local_address,
            local_port,
            fake_ip,
            hosts,
            generation_source: None,
        }
    }

    /// 注入代际源（RIL-020 解析上下文）：fake-ip 分配时取当下配置代际
    /// 身份写进绑定。运行时装配在发布协调器（RIL-019）接线后传入真实
    /// 代际读数；未注入 = 空代际。
    pub fn with_generation_source(mut self, source: Arc<dyn Fn() -> String + Send + Sync>) -> Self {
        self.generation_source = Some(source);
        self
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
                        let fake_ip = self.fake_ip.clone();
                        let hosts = self.hosts.clone();
                        let generation_source = self.generation_source.clone();
                        tokio::spawn(async move {
                            handle_dns_query(
                                worker,
                                peer,
                                data,
                                resolver,
                                fake_ip,
                                hosts,
                                generation_source,
                            )
                            .await;
                        });
                    }
                    Err(e) => warn!("DNS 监听收包失败：{e}"),
                }
            }
        }
        Ok(())
    }
}

/// 单查询处理（坏查询丢弃；NXDOMAIN/失败按 rcode 回写）。
/// hosts 表（G2-15）命中即静态映射直答（真实地址、TTL 1，不触上游；
/// 名命中族不符给空 NOERROR 不泄上游）。fake-ip 开启时客户端 A 查询按
/// 池段稳定假地址直接应答（不触上游，TTL 1 秒）；AAAA 与其余类型照常
/// 真实解析（应用走 IPv6 即回到 IP 直连路由语义，不破流）。
async fn handle_dns_query(
    sock: UdpSocket,
    peer: SocketAddr,
    data: Vec<u8>,
    resolver: Arc<DnsResolver>,
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
    hosts: Option<Arc<rillane_core::hosts::DnsHosts>>,
    generation_source: Option<Arc<dyn Fn() -> String + Send + Sync>>,
) {
    let reply = match decode_query(&data) {
        Ok(q) => {
            // hosts 直答（G2-15，先于 fake-ip：映射即静态语义，命中给真实
            // 地址——该地址不属池段，入口反查不介入，路由按地址语义走）。
            // None = 无表或名未命中（继续 fake-ip/上游）；Some(空) = 名命中
            // 但族不符（空 NOERROR，不泄上游）
            let hosts_hit = match (hosts.as_ref(), q.qtype) {
                (Some(t), DnsRecordType::A) => t.lookup(&q.domain, true),
                (Some(t), DnsRecordType::Aaaa) => t.lookup(&q.domain, false),
                _ => None,
            };
            if let Some(ips) = hosts_hit {
                let answers: Vec<DnsAnswer> = ips
                    .iter()
                    .map(|ip| DnsAnswer {
                        domain: q.domain.clone(),
                        rtype: q.qtype,
                        ttl: 1,
                        data: match *ip {
                            std::net::IpAddr::V4(v4) => DnsAnswerData::A(v4),
                            std::net::IpAddr::V6(v6) => DnsAnswerData::Aaaa(v6),
                        },
                    })
                    .collect();
                encode_response(q.id, &q.domain, q.qtype, 0, &answers)
            } else if let (Some(table), DnsRecordType::A) = (fake_ip.as_ref(), q.qtype) {
                // RIL-020：分配挂解析上下文（代际源注入则取当下代际，未
                // 注入空串=显式缺失）；池满且全钉住（活跃会话在用）→
                // SERVFAIL，绝不转手在用地址
                let generation = generation_source.as_ref().map(|f| f()).unwrap_or_default();
                match table.alloc_with_generation(&q.domain, &generation) {
                    Ok(ip) => {
                        debug!("fake-ip 应答：{} → {ip}（gen {generation:?}）", q.domain);
                        encode_response(
                            q.id,
                            &q.domain,
                            q.qtype,
                            0,
                            &[DnsAnswer {
                                domain: q.domain.clone(),
                                rtype: DnsRecordType::A,
                                ttl: 1,
                                data: DnsAnswerData::A(ip),
                            }],
                        )
                    }
                    Err(e) => {
                        debug!("fake-ip 池耗尽（{e}），回 SERVFAIL");
                        encode_response(q.id, &q.domain, q.qtype, 2, &[])
                    }
                }
            } else {
                match resolver.resolve(&q.domain, q.qtype).await {
                    Ok(answers) => encode_response(q.id, &q.domain, q.qtype, 0, &answers),
                    Err(ResolveError::NxDomain(_)) => {
                        encode_response(q.id, &q.domain, q.qtype, 3, &[])
                    }
                    Err(e) => {
                        debug!("DNS 查询失败（回 SERVFAIL）：{e}");
                        encode_response(q.id, &q.domain, q.qtype, 2, &[])
                    }
                }
            }
        }
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
                DnsServerType::Udp => udp.push(DnsUpstream::Udp(s.address)),
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
            tls_skip_verify: false,
            egress_mark: 0,
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
        // task 闸先行（start/stop 同序，避免死锁）；shutdown_tx 获取后
        // 仅同步赋值，不再跨 await（P3：曾持 shutdown_tx 锁跨 task 锁 await）。
        let mut task_guard = self.task.lock().await;
        let mut tx = self.shutdown_tx.lock().await;
        ensure!(tx.is_none(), "DNS 监听已启动（重复 start）");
        let (stx, srx) = oneshot::channel();
        let server = LocalDnsServer::new(
            self.resolver.clone(),
            self.local_address,
            self.local_port,
            None,
            None,
        );
        let handle = tokio::spawn(async move {
            if let Err(e) = server.serve(srx).await {
                error!("DNS 监听异常退出：{e:#}");
            }
        });
        *task_guard = Some(handle);
        *tx = Some(stx);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let mut task_guard = self.task.lock().await;
        let mut tx = self.shutdown_tx.lock().await;
        if let Some(stx) = tx.take() {
            let _ = stx.send(());
        }
        let handle = task_guard.take();
        drop(task_guard);
        drop(tx);
        if let Some(handle) = handle {
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
            tls_skip_verify: false,
            egress_mark: 0,
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
            trusted: vec![DnsUpstream::Udp("223.5.5.5:53".parse().unwrap())],
            rules: vec![(
                PartitionPattern::Suffix(".cn".into()),
                UpstreamGroup::Domestic,
            )],
            ..base_cfg()
        };
        let err = DnsResolver::new(cfg).unwrap_err();
        assert!(err.to_string().contains("Domestic"), "{err}");
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp("1.1.1.1:53".parse().unwrap())],
            anti_poison: AntiPoison::CrossCheck,
            ..base_cfg()
        };
        let err = DnsResolver::new(cfg).unwrap_err();
        assert!(err.to_string().contains("cross_check"), "{err}");
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp("1.1.1.1:53".parse().unwrap())],
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
            trusted: vec![DnsUpstream::Udp(mock)],
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
            trusted: vec![DnsUpstream::Udp(mock)],
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

    /// 审核回归（2026-11-03）：首查任务被取消时，singleflight 槽位必须
    /// 随 sender drop 自愈；等待者不能永久挂在已死首查者上。
    #[tokio::test]
    async fn resolver_recovers_when_singleflight_leader_is_cancelled() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (query_tx, query_rx) = oneshot::channel();
        let (response_tx, response_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let mut query_tx = Some(query_tx);
            let mut response_rx = Some(response_rx);
            let mut buf = vec![0u8; 512];
            let mut first = true;
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(q) = decode_query(&buf[..n]) else {
                    continue;
                };
                if first {
                    first = false;
                    if let Some(tx) = query_tx.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = response_rx.take() {
                        let _ = rx.await;
                    }
                }
                let answers = vec![v4(&q.domain, [9, 9, 9, 9], 300)];
                let reply = encode_response(q.id, &q.domain, q.qtype, 0, &answers);
                let _ = sock.send_to(&reply, peer).await;
            }
        });
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp(addr)],
            ..base_cfg()
        };
        let resolver = Arc::new(DnsResolver::new(cfg).unwrap());

        let leader_resolver = resolver.clone();
        let leader = tokio::spawn(async move {
            leader_resolver
                .resolve("cancelled-leader.test", DnsRecordType::A)
                .await
        });
        query_rx.await.unwrap();
        let follower_resolver = resolver.clone();
        let follower = tokio::spawn(async move {
            follower_resolver
                .resolve("cancelled-leader.test", DnsRecordType::A)
                .await
        });
        tokio::task::yield_now().await;
        leader.abort();
        response_tx.send(()).unwrap();

        let answers = tokio::time::timeout(Duration::from_secs(2), follower)
            .await
            .expect("等待者应从被取消的首查者自愈")
            .unwrap()
            .unwrap();
        assert_eq!(answers[0].data, DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)));
        server.abort();
        assert!(
            resolver.inflight.lock().await.is_empty(),
            "自愈后 inflight 应清理"
        );
    }

    /// 验收口径 1：规则命中走 domestic、未命中走 default（到达面断言）
    #[tokio::test]
    async fn resolver_routes_to_selected_group() {
        let (dom, dom_hits) = spawn_mock(|_| (0, vec![v4("x", [6, 6, 6, 6], 300)])).await;
        let (trs, trs_hits) = spawn_mock(|_| (0, vec![v4("x", [9, 9, 9, 9], 300)])).await;
        let cfg = ResolverConfig {
            domestic: vec![DnsUpstream::Udp(dom)],
            trusted: vec![DnsUpstream::Udp(trs)],
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
            domestic: vec![DnsUpstream::Udp(dom)],
            trusted: vec![DnsUpstream::Udp(trs)],
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
            domestic: vec![DnsUpstream::Udp(dom)],
            trusted: vec![DnsUpstream::Udp(trs)],
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
            domestic: vec![DnsUpstream::Udp(silent_addr)],
            trusted: vec![DnsUpstream::Udp(trs)],
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
            trusted: vec![DnsUpstream::Udp(a1), DnsUpstream::Udp(a2)],
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
            trusted: vec![DnsUpstream::Udp(mock)],
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
            trusted: vec![DnsUpstream::Udp(mock)],
            ..base_cfg()
        };
        let resolver = Arc::new(DnsResolver::new(cfg).unwrap());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let server = LocalDnsServer::new(resolver, "127.0.0.1".parse().unwrap(), port, None, None);
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

    /// G1-10 fake-ip：A 查询按池段稳定假地址应答（不触上游），同域名复得
    /// 同地址，反查还原原域名；AAAA 照常走真实解析路径（mock 上游计数可辨）。
    #[tokio::test]
    async fn fake_ip_dns_answers_and_reverses() {
        let (mock, hits) = spawn_mock(|d| (0, vec![v4(d, [8, 8, 4, 4], 120)])).await;
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp(mock)],
            ..base_cfg()
        };
        let resolver = Arc::new(DnsResolver::new(cfg).unwrap());
        let table =
            Arc::new(rillane_core::fake_ip::FakeIpTable::from_cidr("198.18.0.0/15").unwrap());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let server = LocalDnsServer::new(
            resolver,
            "127.0.0.1".parse().unwrap(),
            port,
            Some(table.clone()),
            None,
        );
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(server.serve(rx));
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli.connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        let query = |id: u16, domain: &str, qtype: DnsRecordType| {
            let domain = domain.to_string();
            let cli = &cli;
            async move {
                let mut raw = [0u8; 512];
                for _ in 0..100 {
                    let q = encode_query(id, &domain, qtype).unwrap();
                    if cli.send(&q).await.is_err() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(200), cli.recv(&mut raw)).await
                    {
                        return decode_response(&raw[..n]).unwrap();
                    }
                }
                panic!("监听未在限时内应答 {domain} {qtype:?}");
            }
        };

        // A 查询 → 池段假地址（非上游真值），稳定复得，反查命中
        let resp = query(0x11, "example.com", DnsRecordType::A).await;
        let DnsAnswerData::A(fake) = resp.answers[0].data else {
            panic!("应为 A 应答");
        };
        assert_eq!(resp.rcode, 0);
        assert_eq!(resp.answers[0].ttl, 1, "假地址 TTL 1");
        assert!(table.in_range(&fake), "应答应落在池段内：{fake}");
        assert_ne!(fake, Ipv4Addr::new(8, 8, 4, 4), "不得是上游真值");
        assert_eq!(table.reverse(&fake).as_deref(), Some("example.com"));
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "A 查询不触上游"
        );

        // 同域名再查 → 同假地址
        let again = query(0x12, "example.com", DnsRecordType::A).await;
        let DnsAnswerData::A(fake2) = again.answers[0].data else {
            panic!("应为 A 应答");
        };
        assert_eq!(fake, fake2, "同域名恒同假地址");

        // AAAA → 照常真实解析（触上游；mock 按域名回 A 值，AAAA 查询上游
        // 无 AAAA 应答 → 引擎按无应答/失败路径回包，仅断言触达上游）
        let _ = query(0x13, "other.test", DnsRecordType::Aaaa).await;
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "AAAA 应触上游（fake-ip 只拦 A）"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    /// RIL-020 解析上下文：代际源注入后 fake-ip 分配把当下代际写进绑定
    ///（reverse_with_context 可读）；未注入 = 空代际显式缺失；池满全钉
    /// → SERVFAIL（不转手在用地址）。
    #[tokio::test]
    async fn fake_ip_alloc_carries_generation_context_and_servfails_when_exhausted() {
        let (mock, _hits) = spawn_mock(|d| (0, vec![v4(d, [8, 8, 4, 4], 120)])).await;
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp(mock)],
            ..base_cfg()
        };
        let resolver = Arc::new(DnsResolver::new(cfg).unwrap());
        // /30 池恰 4 地址，便于打满
        let table =
            Arc::new(rillane_core::fake_ip::FakeIpTable::from_cidr("198.18.0.0/30").unwrap());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let current = Arc::new(std::sync::Mutex::new("gen-live-1".to_string()));
        let gen_src: Arc<dyn Fn() -> String + Send + Sync> = {
            let reader = current.clone();
            Arc::new(move || reader.lock().unwrap().clone())
        };
        let server = LocalDnsServer::new(
            resolver,
            "127.0.0.1".parse().unwrap(),
            port,
            Some(table.clone()),
            None,
        )
        .with_generation_source(gen_src);
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(server.serve(rx));
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli.connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        // 分配 4 个域名（打满 /30 池），代际读数应进绑定
        async fn query(cli: &UdpSocket, id: u16, domain: &str) -> DnsWireResponse {
            let q = encode_query(id, domain, DnsRecordType::A).unwrap();
            cli.send(&q).await.unwrap();
            let mut raw = [0u8; 512];
            let n = tokio::time::timeout(Duration::from_secs(2), cli.recv(&mut raw))
                .await
                .expect("监听应答查询")
                .unwrap();
            decode_response(&raw[..n]).unwrap()
        }
        let mut fakes = Vec::new();
        for i in 1..=4 {
            let resp = query(&cli, 0x20 + i, &format!("d{i}.test")).await;
            assert_eq!(resp.rcode, 0, "打满前应答 NOERROR");
            let DnsAnswerData::A(ip) = resp.answers[0].data else {
                panic!("应为 A 应答");
            };
            fakes.push(ip);
        }
        let ctx = table.reverse_with_context(&fakes[0]).expect("应有上下文");
        assert_eq!(ctx.domain, "d1.test");
        assert_eq!(ctx.generation_id, "gen-live-1", "代际源读数应进绑定");

        // 钉满全池 → 新域名 SERVFAIL（不转手在用地址）
        for ip in &fakes {
            assert!(table.pin(ip), "钉住在用地址");
        }
        let resp = query(&cli, 0x30, "overflow.test").await;
        assert_eq!(resp.rcode, 2, "全钉住耗尽应 SERVFAIL");
        assert!(resp.answers.is_empty());

        // 关桥排空
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    /// RIL-020 上游 socket 旁路：egress_mark ≠ 0 时 UDP 上游查询走
    /// net_mark 建连面（无 CAP 环境 set_mark 失败降级普通 socket）——
    /// mark 全局态串行化同 net_mark 测试纪律。
    #[tokio::test]
    async fn resolver_with_egress_mark_still_resolves_via_marked_path() {
        let (mock, hits) = spawn_mock(|d| (0, vec![v4(d, [9, 9, 9, 9], 60)])).await;
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp(mock)],
            egress_mark: 0x5E45,
            ..base_cfg()
        };
        let resolver = DnsResolver::new(cfg).unwrap();
        let answers = resolver
            .resolve("marked.test", DnsRecordType::A)
            .await
            .expect("mark ≠ 0（降级或真打）都应解析成功");
        assert_eq!(answers[0].data, DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)));
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "上游应收到查询"
        );
    }

    /// G2-15 hosts 映射：A/AAAA 命中按映射直答真实地址（不触上游、不经
    /// fake-ip，TTL 1）；名命中族不符 → 空 NOERROR 不泄上游；未命中回落
    /// 既有路径（A → fake-ip 池段、AAAA → 上游）；hosts 优先于 fake-ip
    ///（表内域名给真值不被假地址化）。
    #[tokio::test]
    async fn hosts_answers_before_upstream_and_fake_ip() {
        let (mock, hits) = spawn_mock(|d| (0, vec![v4(d, [8, 8, 4, 4], 120)])).await;
        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Udp(mock)],
            ..base_cfg()
        };
        let resolver = Arc::new(DnsResolver::new(cfg).unwrap());
        let mut map = std::collections::BTreeMap::new();
        map.insert("mapped.test".to_string(), "10.0.0.9".to_string());
        map.insert("v6only.test".to_string(), "::1".to_string());
        let hosts = Arc::new(rillane_core::hosts::DnsHosts::from_map(&map).unwrap());
        let table =
            Arc::new(rillane_core::fake_ip::FakeIpTable::from_cidr("198.18.0.0/15").unwrap());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let server = LocalDnsServer::new(
            resolver,
            "127.0.0.1".parse().unwrap(),
            port,
            Some(table.clone()),
            Some(hosts),
        );
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(server.serve(rx));
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli.connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        let query = |id: u16, domain: &str, qtype: DnsRecordType| {
            let domain = domain.to_string();
            let cli = &cli;
            async move {
                let mut raw = [0u8; 512];
                for _ in 0..100 {
                    let q = encode_query(id, &domain, qtype).unwrap();
                    if cli.send(&q).await.is_err() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(200), cli.recv(&mut raw)).await
                    {
                        return decode_response(&raw[..n]).unwrap();
                    }
                }
                panic!("监听未在限时内应答 {domain} {qtype:?}");
            }
        };

        // A 命中 → 真实映射地址（非池段、非上游真值），不触上游
        let resp = query(0x21, "mapped.test", DnsRecordType::A).await;
        let DnsAnswerData::A(mapped) = resp.answers[0].data else {
            panic!("应为 A 应答");
        };
        assert_eq!(resp.rcode, 0);
        assert_eq!(mapped, Ipv4Addr::new(10, 0, 0, 9), "hosts 映射直答真值");
        assert_eq!(resp.answers[0].ttl, 1);
        assert!(!table.in_range(&mapped), "hosts 命中不经 fake-ip");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

        // 名命中族不符（mapped.test 仅 v4）→ 空 NOERROR，不泄上游
        let resp = query(0x22, "mapped.test", DnsRecordType::Aaaa).await;
        assert_eq!(resp.rcode, 0, "族不符应为 NOERROR 空应答");
        assert!(resp.answers.is_empty(), "族不符不应答任何记录");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

        // AAAA 命中 v6 条目 → Aaaa 直答
        let resp = query(0x23, "v6only.test", DnsRecordType::Aaaa).await;
        let DnsAnswerData::Aaaa(v6) = resp.answers[0].data else {
            panic!("应为 AAAA 应答");
        };
        assert_eq!(v6, std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

        // 表外域名：A → fake-ip 池段（hosts 未命中回落既有路径）
        let resp = query(0x24, "unknown.test", DnsRecordType::A).await;
        let DnsAnswerData::A(fake) = resp.answers[0].data else {
            panic!("应为 A 应答");
        };
        assert!(table.in_range(&fake), "表外 A 应走 fake-ip 池段：{fake}");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

        // 表外域名 AAAA → 上游（fake-ip 只拦 A；计数可辨）
        let _ = query(0x25, "unknown.test", DnsRecordType::Aaaa).await;
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "表外 AAAA 应触上游"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
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

    // -------------------------------------------------------------------
    // G1-8：加密上游（DoT RFC 7858 / DoH RFC 8484）
    // -------------------------------------------------------------------

    /// 上游串三形态解析：`ip:port`（UDP）/ `tls://`、`dot://`（DoT，缺省
    /// 853）/ `https://`（DoH）；其余形态与非法值拒绝。
    #[test]
    fn upstream_parse_forms() {
        assert_eq!(
            DnsUpstream::parse(" 1.2.3.4:53 ").unwrap(),
            DnsUpstream::Udp("1.2.3.4:53".parse().unwrap())
        );
        assert_eq!(
            DnsUpstream::parse("tls://dns.example").unwrap(),
            DnsUpstream::Dot {
                host: "dns.example".into(),
                port: 853,
                sni: "dns.example".into()
            }
        );
        assert_eq!(
            DnsUpstream::parse("dot://dns.example:8853").unwrap(),
            DnsUpstream::Dot {
                host: "dns.example".into(),
                port: 8853,
                sni: "dns.example".into()
            }
        );
        assert_eq!(
            DnsUpstream::parse("https://dns.example/dns-query").unwrap(),
            DnsUpstream::Doh {
                url: "https://dns.example/dns-query".into()
            }
        );
        assert!(DnsUpstream::parse("ftp://x").is_err());
        assert!(DnsUpstream::parse("tls://").is_err());
        assert!(DnsUpstream::parse("https://").is_err());
        assert!(DnsUpstream::parse("1.2.3.4:0").is_err());
        assert!(DnsUpstream::parse("no-address").is_err());
        assert!(DnsUpstream::parse("tls://h:0").is_err());
    }

    /// 回环自签 acceptor（SAN=localhost；配合 tls_skip_verify 使用）
    fn loopback_acceptor() -> tokio_rustls::TlsAcceptor {
        use rustls::pki_types::pem::PemObject;
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(certified.cert.pem().as_bytes())
                .collect::<Result<_, _>>()
                .expect("证书 PEM 解析");
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
            certified.key_pair.serialize_pem().as_bytes(),
        )
        .expect("私钥读取");
        let builder = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("协议版本");
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            builder
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("服务端证书装配"),
        ))
    }

    /// DoT 回环（RFC 7858）：2 字节大端长度前缀逐消息；应答 id 与查询一致。
    #[tokio::test]
    async fn dot_loopback_roundtrip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = loopback_acceptor();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut len_buf = [0u8; 2];
            if tls.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            if tls.read_exact(&mut buf).await.is_err() {
                return;
            }
            let Ok(q) = decode_query(&buf) else {
                return;
            };
            let reply =
                encode_response(q.id, &q.domain, q.qtype, 0, &[v4("d", [10, 1, 2, 3], 120)]);
            if tls
                .write_all(&(reply.len() as u16).to_be_bytes())
                .await
                .is_err()
            {
                return;
            }
            let _ = tls.write_all(&reply).await;
        });

        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Dot {
                host: "127.0.0.1".into(),
                port,
                sni: "localhost".into(),
            }],
            tls_skip_verify: true,
            egress_mark: 0,
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a = r.resolve("dot.test", DnsRecordType::A).await.unwrap();
        assert_eq!(a[0].data, DnsAnswerData::A(Ipv4Addr::new(10, 1, 2, 3)));
    }

    /// DoH 回环（RFC 8484 GET）：`?dns=` base64url 无填充、载荷 id=0、
    /// `application/dns-message`；应答体即 wire 消息。
    #[tokio::test]
    async fn doh_loopback_roundtrip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = loopback_acceptor();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            // 读请求直到头结束（\r\n\r\n）
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = match tls.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&buf);
            let path = text.split_whitespace().nth(1).unwrap_or("");
            let b64 = path
                .split("dns=")
                .nth(1)
                .unwrap_or("")
                .split('&')
                .next()
                .unwrap_or("");
            let Ok(wire) = URL_SAFE_NO_PAD.decode(b64) else {
                return;
            };
            let Ok(q) = decode_query(&wire) else {
                return;
            };
            let reply = encode_response(q.id, &q.domain, q.qtype, 0, &[v4("h", [10, 0, 9, 9], 60)]);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            if tls.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let _ = tls.write_all(&reply).await;
        });

        let cfg = ResolverConfig {
            trusted: vec![DnsUpstream::Doh {
                url: format!("https://127.0.0.1:{port}/dns-query"),
            }],
            tls_skip_verify: true,
            egress_mark: 0,
            ..base_cfg()
        };
        let r = DnsResolver::new(cfg).unwrap();
        let a = r.resolve("doh.test", DnsRecordType::A).await.unwrap();
        assert_eq!(a[0].data, DnsAnswerData::A(Ipv4Addr::new(10, 0, 9, 9)));
    }

    /// DoH 载荷 id=0 口径（RFC 8484 §4.1）：doh_exchange 发出的查询包
    /// 头两字节（id 字段）为 0；对照 UDP/DoT 路径 id 原样编码。
    #[test]
    fn doh_payload_uses_zero_id() {
        let packet = encode_query(0, "zero.test", DnsRecordType::A).unwrap();
        assert_eq!(&packet[..2], &[0, 0], "DoH 载荷 id 须为 0");
        let packet = encode_query(0x4E00, "zero.test", DnsRecordType::A).unwrap();
        assert_eq!(&packet[..2], &[0x4E, 0x00], "UDP/DoT id 原样编码");
    }
}
