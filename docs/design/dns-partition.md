# P2-8 DNS 分流解析（设计稿）

> 2026-10-02 就绪；M0 落地（引擎 + 工厂切换）。定位依据：positioning.md
> 「DNS 分流（网页加速）」行——国内外 DNS 分流、缓存、防污染。

## 0. 范围与验收口径

**todo 原文**：国内外 DNS 分流、缓存、防污染，对接 `seep-platform::network::dns`
设计。
**验收原文**：分流解析正确且缓存命中率有指标；被污染域名返回可信结果。

**可测口径（显式改写）**：

1. **分流正确**：域名规则选中的上游组与实际查询到达的服务器一致
   （mock 本地双上游断言到达面）；
2. **缓存命中指标**：同域二次查询计 hit，stats 快照
   `cache_hits/cache_misses/cache_hit_rate` 逐项正确；
3. **防污染**：domestic 上游返回污染 IP 时，`cross_check` 面返回 trusted
   结果并计 `pollution_suspected`；`off` 面如实呈现 domestic 结果
   （行为差异三测钉死，见 §7-4）。

## 1. 现状与结构约束

- `dns.rs` 是**数据模型层**（DnsConfig/DnsServer/DnsStats/DnsHandler
  trait，991 行），引擎面零实现——`mod.rs::create_dns_handler` 恒 Err
  「真实现归 P2-8」，T0 钉测在位；
- seep-platform 依赖已含 tokio/socket2/regex/thiserror——**MVP 零新依赖**，
  wire format 手写（RFC 1035 A/AAAA/CNAME 最小面）；
- seep-config 镜像不加依赖（network-route.md §1.2 裁决先例）；
- `TunBlockConfig.dns_servers` 注记「仅记录（消费归 P2-8）」；
- `DnsConfig` 平台类型无 domestic/trusted 分组概念——分组与规则是
  **配置镜像 + 转换层**的职责（M1），引擎只收「两组上游 + 规则表」。

## 2. 设计决策

- **D-1 最小 wire 面**：手写 RFC 1035——查询编码（header + 单 QD，RD=1）
  + 应答解码（header / question 跳过 / answer 的 A、AAAA、CNAME，其余
  rdata 按 rdlength 跳过）；读侧支持压缩指针（跳数上限 §5-E5）；UDP
  报文面（≤512B 传统查询），不做 TCP/EDNS0（§9-2）。
- **D-2 分流 = 域名规则 → 上游组**：两组 `Domestic`/`Trusted`（命名按
  「污染风险」语义建模，用户可把 domestic 组配成任意本地 ISP DNS）+
  规则表（exact/suffix 两种轻量模式）+ default 兜底；判定纯函数
  **先到先得**（配置序即优先级，与 routing 规则同风格）；suffix 要求
  前导点（`.cn` 匹配 `x.cn` 不匹配 `cn`——裸域用 exact，E1 校验）。
- **D-3 防污染二态**：`off`（纯分流，单组直查）/ `cross_check`
  （Domestic 选中的查询**并发双查** domestic+trusted：应答集合不相交
  判分歧——取 trusted 面 + `pollution_suspected` 计数；一致或单边成功
  取成功面）。`TrustedOnly` 不设：污染敏感域走 trusted 组本来就是
  分流规则的表达，「路由式防污染」不另设模式（§9-3）。
- **D-4 缓存**：键 `(domain 规范形, qtype)`，TTL 逐应答钳位
  `[min_ttl, max_ttl]`（`DnsCacheConfig` 字段承接），条目到期 =
  各应答钳位后最小值；`ttl=0` 不缓存；NXDOMAIN 负缓存
  （`enable_negative_cache` + `negative_ttl`）；`max_entries` 满逐出
  **最早插入**（seq 序，简单可测）；域名规范化 = 小写折叠 + 尾点剔除
  （缓存命中正确性前提，§5-E4）。
- **D-5 统计**：`DnsStats`（Mutex 聚合形）不带入引擎热路径——引擎用
  `AtomicU64` 计数器组（total/cache_hits/cache_misses/
  upstream_failures/pollution_suspected/两组成员查询数）+
  `stats_snapshot()` 即时一致快照，hit_rate 计算同
  `DnsStats::cache_hit_rate()` 口径；控制面暴露归 M1。
- **D-6 工厂切换**：`create_dns_handler` 对「含 enabled UDP 上游」的
  `DnsConfig` 返回真实现（全部 UDP 服务器入 default=Trusted 组、无
  规则——工厂是既有 `NetworkManager` 路径的桥，分流配置面归 M1 转换）；
  DoT/DoH/DoQ **enabled** 上游 → Err 带指引（§9-1）；零可用上游 →
  Err。T0 钉测半边改口径（DNS：UDP 可用 + 加密 Err；filter 不动）。
- **D-7 本地 UDP 监听 = MVP 交付形**：`LocalDnsServer` 绑
  `local_address:local_port`，recv → 解码 → resolve → 编码应答
  （QR|RD|RA + rcode，应答含 CNAME 原样回写）；oneshot 关桥排空退出
  （control_plane serve 同款语义）；TUN DNS 劫持集成归 P1-1/P1-2
  落地后（§9-4，不阻塞验收——监听即独立可用面）。
- **D-8 文件布局**：引擎落新文件 `dns_engine.rs`（dns.rs 保持数据模型
  层不动，991 行不再膨胀；mod.rs 接线 pub mod + re-export）。

## 3. 数据结构（dns_engine.rs）

```rust
pub enum DnsAnswerData { A(Ipv4Addr), Aaaa(Ipv6Addr), Cname(String), Other }
pub struct DnsAnswer { pub domain: String, pub rtype: DnsRecordType,
                       pub ttl: u32, pub data: DnsAnswerData }
pub struct DnsWireResponse { pub id: u16, pub rcode: u8, pub answers: Vec<DnsAnswer> }

pub fn encode_query(id: u16, domain: &str, qtype: DnsRecordType) -> Result<Vec<u8>>;
pub fn decode_response(buf: &[u8]) -> Result<DnsWireResponse>;
pub fn encode_response(id: u16, domain: &str, qtype: DnsRecordType,
                       rcode: u8, answers: &[DnsAnswer]) -> Vec<u8>;

pub enum UpstreamGroup { Domestic, Trusted }
pub enum PartitionPattern { Exact(String), Suffix(String) }   // 规范化小写存储
pub struct DnsPartition { rules: Vec<(PartitionPattern, UpstreamGroup)>, default: UpstreamGroup }
impl DnsPartition { pub fn select(&self, norm_domain: &str) -> UpstreamGroup; }

#[derive(Debug, Default)]
pub struct DnsStatsCounters { /* AtomicU64 × 7 */ }
pub struct DnsStatsSnapshot { pub total_queries: u64, /* … */ pub cache_hit_rate: f64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiPoison { Off, CrossCheck }

pub enum ResolveError { NxDomain, UpstreamFailure(String), InvalidDomain(String) } // thiserror

pub struct DnsResolver { /* groups, partition, cache: Mutex<DnsCache>, anti_poison, timeout, retries, stats */ }
impl DnsResolver {
    pub fn new(cfg: ResolverConfig) -> Result<Self>;          // E1 校验
    pub async fn resolve(&self, domain: &str, qtype: DnsRecordType)
        -> Result<Vec<DnsAnswer>, ResolveError>;
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot;
    pub fn clear_cache(&self);
}

pub struct LocalDnsServer { /* Arc<DnsResolver>, bind addr */ }
impl LocalDnsServer {
    pub async fn serve(self, shutdown: oneshot::Receiver<()>) -> Result<()>;
}
```

## 4. 接线点

| # | 点 | 动作 | 步 |
|---|----|------|----|
| 1 | `network/dns_engine.rs` 新文件 | 引擎全量（wire/cache/partition/resolver/server/stats） | M0 |
| 2 | `network/mod.rs` | pub mod + re-export；`create_dns_handler` 切真实现；T0 测改口径（D-6） | M0 |
| 3 | seep-config `NetworkBlockConfig.dns` 子块镜像 + validate | deny_unknown_fields；规则/组/缓存/防污染面 | M1 |
| 4 | seep-runtime 转换 + runtime_builder 接线 + listener 启停 | `DnsBlockConfig → ResolverConfig`；`TunBlockConfig.dns_servers` 消费落地 | M1 |
| 5 | 控制面 `/stats` dns 段 | `stats_snapshot()` 暴露（验收「命中率有指标」） | M1 |

## 5. 错误与边界

- **E1 配置校验**（ResolverConfig 构造期）：trusted 组空（cross_check
  必需）/ 分流规则指向的组无服务器 / suffix 无前导点 / exact 空 /
  default 组无服务器——带原值报错；
- **E2 上游全失败**：组内逐服务器 × retries，全败 →
  `UpstreamFailure`（不 fallback 系统 DNS——行为确定可测）；
- **E3 TTL 钳位**：`clamp(ttl, min_ttl, max_ttl)`；`ttl=0` 不缓存；
- **E4 域名规范化**：trim 尾点 + ASCII 小写折叠；空/超长（>253）/
  空标签 → `InvalidDomain`；
- **E5 压缩指针环**：指针跳数上限 32、名字总长上限 255——超限
  decode Err（防恶意应答死循环）；
- **E6 应答校验**：id 不匹配 / 源地址非目标服务器 / 解码失败 → 丢弃
  计入重试（防错配与Basic 伪造）；
- **E7 分歧判定**：cross_check 两面 A/AAAA 集合**不相交**才算分歧
  （子集/超集不算——CDN 多答常态）；任一面失败取成功面不计分歧。

## 6. 控制面

M1：`/stats` 增 dns 段（total/cache_hits/cache_misses/cache_hit_rate/
pollution_suspected/组内 per-server 计数）。无新端点（复用 stats 面）。

## 7. 测试策略

1. **wire 纯函数**：query golden 字节（id/flags/qname/qtype 逐偏移）；
   含压缩指针的应答解码 golden；E5 指针环 / 截断报文拒收；
2. **分流判定**：规则命中两模式 / default 回退 / 先到先得序 / 大小写
   与尾点规范化后命中；
3. **缓存**：二次查询 hit 计数与 hit_rate；TTL 钳位三态；过期失效；
   负缓存 NXDOMAIN 命中；max_entries 逐出最旧；
4. **防污染**（mock 双上游本地 UDP）：off 面=domestic 污染结果如实
   返回；cross_check 面=集合不相交 → trusted 结果 + suspected=1；
   一致面 → domestic 结果 + suspected=0；单边失败面 → 成功方；
5. **resolver 集成**：mock UDP 上游全链路（resolve → 应答解码 →
   服务器到达面断言 = 验收口径 1）；E2 全败路径；
6. **监听**：LocalDnsServer 绑 :0，客户端发查询收应答（rcode/answers
   断言）+ oneshot 关桥退出；
7. **工厂**：UDP 上游 Ok / DoH 上游 Err 指引 / 零上游 Err（T0 改口径）。

## 8. 分步实施清单

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M0 | 设计稿 + dns_engine.rs 全量（§3）+ mod.rs 工厂切换 + §7-1..7 测 | — | §7 全绿；mock 双上游防污染三面成立 |
| M1 | seep-config dns 子块 + validate + runtime 转换/listener 接线 + 控制面指标 + 文档回填 | M0 | 控制面可见命中率；本地 dig 形端到端 |

## 9. 偏差与假设

1. **DoT/DoH/DoQ 上游 MVP 不做**（数据模型有形、引擎不实现）——
   「防污染」的可信通道由 **trusted 组的部署选择**承担（可信 IP/自建
   网关 UDP 面）；加密上游归 V2。E6 的 id+源地址校验是 Basic 面非
   加密面，明文 UDP 上游链路可被中间盒污染——R-dns1；
2. **UDP 报文面**：≤512B 无 EDNS0，A/AAAA/CNAME 面足够网页加速场景；
   TCP 重传/大应答归 V2；
3. **不设 TrustedOnly 模式**（D-3）：污染敏感域显式规则走 trusted 组
   即等价表达，少一个模式少一份口径；
4. **TUN 劫持集成不在本步**：P1-1/P1-2 归他会话在途；本地监听已是
   独立可用面（resolv.conf 指向即生效），验收不依赖 TUN；
5. **filter 规则面挂起**：`DnsConfig.filters`（广告过滤）不属本条目
   验收，工厂路径非空 filters 忽略 + warn（不 Err——不阻塞既有形）；
   正则规则每查询编译的既有 filter.rs 问题不带入引擎（分流用轻量
   exact/suffix）。

## 10. 风险与未决

- **R-dns1**：trusted 组可信性由部署者保证（明文 UDP 链路仍可被
  链路级污染）——文档注明；加密通道归 V2（§9-1）；
- **O-dns1**：geosite/chnroutes 批量规则源导入（配置面 M1 之后按需）；
- **O-dns2**：DoH/DoT 上游、EDNS0、TCP 面归 V2。
