use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// 场景预设（P2-3 scenario-profiles.md §3）：配置期展开为既有块缺省填充
/// （§2 D-2），运行期不可见——展开产物与手写等价配置走同一 build() 链
/// （验收「无独立代码路径」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Proxy,
    Game,
    Web,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SeepConfig {
    pub control: ControlConfig,
    pub telemetry: TelemetryConfig,
    pub ingress: Vec<IngressDescriptor>,
    pub egress: Vec<EgressDescriptor>,
    pub routing: RoutingConfig,
    /// UDP 数据面（P0-2；缺省整块关闭，兼容既有配置）
    #[serde(default)]
    pub udp: UdpConfig,
    /// 网络虚拟化（P1-3 network-route.md §1；缺省 None = 整块关闭，行为零差异）
    #[serde(default)]
    pub network: Option<NetworkBlockConfig>,
    /// 流量混淆（P1-4 obfuscation-middleware.md §3；缺省 None = 整块关闭，
    /// 构建期零 middleware 零注解注入，行为零差异 §2.5）
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    /// 出站连接池（P1-5 egress-connection-pool.md §3；缺省 None = 整块关闭，
    /// 不构池不注工厂，行为零差异 §3.4）
    #[serde(default)]
    pub egress_pool: Option<EgressPoolBlock>,
    /// 场景预设（P2-3 scenario-profiles.md §2-D1；缺省 None = 存量零差异；
    /// 仅 from_str 入口展开——订阅/程序化构造不触发，§5-1）
    #[serde(default)]
    pub profile: Option<ProfileKind>,
    /// relay IO 性能参数（P3-5 performance-io.md §3；缺省 None = 不设定、
    /// 缓冲维持 8192×2 缺省，行为零差异 §2-D5）
    #[serde(default)]
    pub performance: Option<PerformanceBlock>,
}

/// P3-5 performance-io.md §3：进程级 relay 缓冲参数。
/// deny_unknown_fields = 新块无存量兼容负担，拼错子字段立刻报错。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceBlock {
    /// TCP relay 双向缓冲（字节）；None = 缺省 8192（tokio copy 同值）。
    /// 进程级单值：RuntimeBuilder::build 期读取设定，变更需重启（§2-D1）。
    pub relay_buffer: Option<u32>,
}

impl PerformanceBlock {
    /// E1：非法值构建期报错（域约束对齐 seep-core `set_relay_buffer`）。
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(n) = self.relay_buffer {
            anyhow::ensure!(
                (1..=1024 * 1024).contains(&n),
                "performance.relay_buffer 必须 1..=1048576 字节，当前 {n}"
            );
        }
        Ok(())
    }
}

/// UDP 数据面配置（udp-dataplane.md §5.2 / udp-relay-path.md §2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UdpConfig {
    /// 总开关：false 时 socks5 ASSOCIATE 应答 0x07（udp-relay-path.md §2.1）
    #[serde(default)]
    pub enabled: bool,
    /// 数据报源 IP 校验（防中继借用，§2.3 步骤 3；默认开）
    #[serde(default = "default_true")]
    pub strict_udp_source: bool,
    /// 会话空闲上限（秒）
    #[serde(default = "default_udp_session_idle")]
    pub session_idle_secs: u64,
    /// 目标映射空闲上限（秒）
    #[serde(default = "default_udp_mapping_idle")]
    pub mapping_idle_secs: u64,
    /// 全局并发会话上界（满员拒新）
    #[serde(default = "default_udp_max_sessions")]
    pub max_sessions: usize,
    /// 回收扫描周期（秒；P0-5 §1.2——配置面收紧到秒粒度）
    #[serde(default = "default_udp_sweep_interval")]
    pub sweep_interval_secs: u64,
    /// 会话内映射上界（溢出逐最久空闲）
    #[serde(default = "default_udp_max_mappings")]
    pub max_mappings: usize,
    /// 可选会话寿命上界（秒；缺省不限——长局游戏不断流）
    #[serde(default)]
    pub session_lifetime_secs: Option<u64>,
    /// 下行通道容量（满即丢 + DownlinkFull 计数，UDP 无背压）
    #[serde(default = "default_udp_downlink_queue_depth")]
    pub downlink_queue_depth: usize,
    /// 并发 ASSOCIATE 上限（超限回 0x01 且计数；P0-5 §1.2 防滥用）
    #[serde(default = "default_udp_max_associates")]
    pub max_associates: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strict_udp_source: true,
            session_idle_secs: 180,
            mapping_idle_secs: 60,
            max_sessions: 4096,
            sweep_interval_secs: 15,
            max_mappings: 256,
            session_lifetime_secs: None,
            downlink_queue_depth: 64,
            max_associates: 256,
        }
    }
}

const fn default_true() -> bool {
    true
}
const fn default_udp_session_idle() -> u64 {
    180
}
const fn default_udp_mapping_idle() -> u64 {
    60
}
const fn default_udp_max_sessions() -> usize {
    4096
}
const fn default_udp_sweep_interval() -> u64 {
    15
}
const fn default_udp_max_mappings() -> usize {
    256
}
const fn default_udp_downlink_queue_depth() -> usize {
    64
}
const fn default_udp_max_associates() -> usize {
    256
}

impl UdpConfig {
    /// P0-5 §1.6：非法值构建期报错（约束对齐 `UdpSessionConfig::validate`，
    /// `session_lifetime_secs` 存在时须 ≥ `session_idle_secs`）。
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.sweep_interval_secs >= 1,
            "udp.sweep_interval_secs 必须 ≥ 1"
        );
        anyhow::ensure!(self.max_mappings >= 1, "udp.max_mappings 必须 ≥ 1");
        anyhow::ensure!(
            self.downlink_queue_depth >= 1,
            "udp.downlink_queue_depth 必须 ≥ 1"
        );
        anyhow::ensure!(self.max_associates >= 1, "udp.max_associates 必须 ≥ 1");
        if let Some(lifetime) = self.session_lifetime_secs {
            anyhow::ensure!(
                lifetime >= self.session_idle_secs,
                "udp.session_lifetime_secs 不应小于 udp.session_idle_secs"
            );
        }
        Ok(())
    }
}

/// per-ingress `udp_enabled` 判定（P0-5 §1.3/§9-4）：None 继承全局，
/// Some 显式覆盖。求值点 = `build_ingress_endpoints` 逐入口一次。
pub fn resolve_udp_enabled(global_enabled: bool, per_ingress: Option<bool>) -> bool {
    per_ingress.unwrap_or(global_enabled)
}

/// network 区块（network-route.md §1.1/§1.5）：seep-config 镜像 serde 类型，
/// 到 seep-platform `NetworkConfig` 的转换在 seep-runtime（§1.2 裁决：镜像而非加依赖，
/// `UdpConfig` 先例）。deny_unknown_fields = 新块无存量兼容负担，拼错子字段立刻报错（B2 定向收口）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBlockConfig {
    /// 网络模式；缺省 tun（MVP 唯一实现，validate 拒其余）
    #[serde(default)]
    pub mode: NetworkBlockMode,
    /// TUN 设备块（mode=tun 时可选——routing 缺省即只建设备不设路由，E4 合法）
    #[serde(default)]
    pub tun: Option<TunBlockConfig>,
    /// 路由块（include 语义）
    #[serde(default)]
    pub routing: Option<RoutingBlockConfig>,
    /// DNS 分流块（P2-8 M1，dns-partition.md §4-3；None = 整体关闭零差异）
    #[serde(default)]
    pub dns: Option<DnsBlockConfig>,
    /// 出站 fwmark（networking.md §2 direct 出口自环逃逸正解半边①）：出站
    /// socket 打 `SO_MARK`，配套 `ip rule fwmark` 逃逸规则（半边② R3）把
    /// seep 自身流量从 TUN include 路由拽回直连。缺省 None = 不打 mark
    /// 零差异；0 同 None。运行期非 Linux/无 CAP_NET_ADMIN 降级直连（warn 一次）。
    #[serde(default)]
    pub egress_fwmark: Option<u32>,
}

/// network.mode（serde 名随 platform 枚举：transparent 弃 "redir"，§1.3 B4 收口）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum NetworkBlockMode {
    #[default]
    Tun,
    Transparent,
    Tap,
    Hybrid,
}

/// network.tun 块（§1.1；字段镜像 platform `TunConfig` 的用户可配子集）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunBlockConfig {
    /// 接口名；缺省 None → 内核分配 tun%d（TUNGETIFF 读回）
    #[serde(default)]
    pub name: Option<String>,
    /// MTU（TunConfig::validate 口径：≥68）
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// 设备地址 CIDR（进 auto-bypass，tun-dataplane §2.7）
    #[serde(default = "default_tun_ipv4")]
    pub ipv4: Option<String>,
    /// IPv6 地址 CIDR（可选）
    #[serde(default)]
    pub ipv6: Option<String>,
    /// DNS 服务器列表（P2-8 M1 消费：network.dns.domestic 缺省回落此列表
    /// 加 53 端口，见 seep-runtime `dns_config.rs`；device 层透传
    /// TunConfig.dns_servers）
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
}

const fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_ipv4() -> Option<String> {
    Some("10.255.0.1/24".to_string())
}

/// network.routing 块（§1.1：main 表显式路由纳入集，include 语义）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingBlockConfig {
    /// 纳入 tun 的前缀列表；include 负向即天然 bypass（§9-3：不暴露用户 bypass 列表）
    #[serde(default)]
    pub include: Vec<String>,
}

/// network 块 CIDR 解析（schema 层最小实现——seep-config 不依赖 seep-platform，
/// 语法口径对齐 route.rs::parse_cidr；要求显式前缀形式：裸 IP 不收，主机路由写 /32，
/// `RouteDestination::Host` 变体不进 schema——§9-10）
pub fn parse_cidr_pair(cidr: &str) -> Result<(IpAddr, u8)> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR 须为 addr/prefix 形式（主机路由写 /32）：{cidr:?}"))?;
    let addr: IpAddr = addr_str
        .parse()
        .with_context(|| format!("CIDR 地址段非法：{cidr:?}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .with_context(|| format!("CIDR 前缀段非法：{cidr:?}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    anyhow::ensure!(prefix <= max, "CIDR 前缀超上限 /{max}：{cidr:?}");
    Ok((addr, prefix))
}

impl NetworkBlockConfig {
    /// §1.4 构建期校验：E1（mode 仅 tun）/ E3（mtu ≥68、CIDR 逐条过解析带原串）。
    /// E5（include 命中 auto-bypass 剔除 + warning）落转换处——validate 是只读检查，
    /// 见 seep-runtime `network_config.rs`（egress/mesh/control 地址集 R1 接线时并入）。
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.mode == NetworkBlockMode::Tun,
            "network.mode = {:?} 未实现（E1）——MVP 仅 tun；transparent/tap/hybrid 归 V2 全局接管条目",
            self.mode
        );
        if let Some(tun) = &self.tun {
            anyhow::ensure!(
                tun.mtu >= 68,
                "network.tun.mtu 必须 ≥ 68（最小 IPv4 MTU），当前 {}",
                tun.mtu
            );
            if let Some(ipv4) = &tun.ipv4 {
                parse_cidr_pair(ipv4)?;
            }
            if let Some(ipv6) = &tun.ipv6 {
                parse_cidr_pair(ipv6)?;
            }
        }
        if let Some(routing) = &self.routing {
            for cidr in &routing.include {
                parse_cidr_pair(cidr)?;
            }
        }
        if let Some(dns) = &self.dns {
            dns.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// network.dns 块（P2-8 M1，dns-partition.md §2/§4-3）：分流上游两组 + 规则 +
// 防污染 + 缓存 + 本地监听面。seep-config 只镜像 serde 形（到引擎
// `ResolverConfig` 的转换在 seep-runtime `dns_config.rs`，§1.2 裁决同
// `NetworkBlockConfig` 先例）；deny_unknown_fields = 新块无存量负担。
// ---------------------------------------------------------------------------

/// DNS 上游组（镜像引擎 `UpstreamGroup`）：domestic=地理就近组，
/// trusted=部署者信任面（可信性由部署者保证，dns-partition.md §10-R-dns1）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DnsGroup {
    #[default]
    Domestic,
    Trusted,
}

/// 防污染模式（镜像引擎 `AntiPoison`，D-3 二态；不设 TrustedOnly——§9-3）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DnsAntiPoisonMode {
    /// 纯分流：选中组单查直答
    #[default]
    Off,
    /// domestic 选中项并发双查，应答集合不相交判分歧 → 取 trusted +
    /// `pollution_suspected` 计数
    CrossCheck,
}

/// 分流规则（D-2）：pattern 前导点 = suffix 匹配（`.cn` 收 `x.cn` 不收 `cn`），
/// 其余 = exact；对规范化（小写折叠+剔尾点）后的域名先到先得，配置序即优先级
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRuleConfig {
    pub pattern: String,
    pub group: DnsGroup,
}

/// 缓存块（D-4：TTL 逐应答钳位 [min_ttl, max_ttl]、ttl=0 不缓存、NXDOMAIN
/// 负缓存、满员逐出最旧）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCacheBlockConfig {
    /// 满员逐出阈值
    #[serde(default = "default_dns_cache_entries")]
    pub max_entries: usize,
    #[serde(default = "default_dns_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_dns_max_ttl")]
    pub max_ttl: u32,
    /// NXDOMAIN 负缓存开关
    #[serde(default = "default_true")]
    pub enable_negative_cache: bool,
    #[serde(default = "default_dns_negative_ttl")]
    pub negative_ttl: u32,
}

const fn default_dns_cache_entries() -> usize {
    10_000
}
const fn default_dns_min_ttl() -> u32 {
    60
}
const fn default_dns_max_ttl() -> u32 {
    86_400
}
const fn default_dns_negative_ttl() -> u32 {
    300
}
const fn default_dns_timeout_ms() -> u64 {
    5_000
}
const fn default_dns_retries() -> u32 {
    2
}
fn default_dns_listen_address() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}
const fn default_dns_listen_port() -> u16 {
    15_353
}

/// network.dns 块：两组上游 + 分流规则 + 防污染 + 缓存 + 本地监听。
/// 块在场缺省启用（与 obfuscation 的 enabled=false 缺省相反——DNS 监听是
/// 显式 opt-in 配置块，场即意图；false 供临时下线，容忍半配置）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsBlockConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// domestic 组上游 `ip:port` 列表；缺省（空）回落 `network.tun.dns_servers`
    /// 加 53 端口（回落落转换处——validate 只见本块，dns-partition.md §4-4）
    #[serde(default)]
    pub domestic: Vec<String>,
    /// trusted 组上游；可信性由部署者保证（§10-R-dns1），不设回落
    #[serde(default)]
    pub trusted: Vec<String>,
    /// 分流规则（配置序即优先级，先到先得）
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,
    /// 未命中兜底组；缺省 domestic（网页加速场景：未列名域走地理就近）
    #[serde(default)]
    pub default_group: DnsGroup,
    /// 防污染；缺省 off
    #[serde(default)]
    pub anti_poison: DnsAntiPoisonMode,
    /// 单次上游查询超时（毫秒）
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    /// 每服务器重试次数
    #[serde(default = "default_dns_retries")]
    pub retries: u32,
    /// 缓存块；None = 不缓存
    #[serde(default)]
    pub cache: Option<DnsCacheBlockConfig>,
    /// 本地监听地址（LocalDnsServer 交付形 §2-D-7；TUN 劫持归 P1-2 落地后集成，
    /// §9-4——监听即独立可用面）
    #[serde(default = "default_dns_listen_address")]
    pub listen_address: IpAddr,
    /// 本地监听端口；0 构建期拒绝（同 M0 工厂口径）
    #[serde(default = "default_dns_listen_port")]
    pub listen_port: u16,
}

impl DnsBlockConfig {
    /// dns-partition.md §5-E1 构建期校验。domestic 空回落 tun.dns_servers 的
    /// 可满足性不在此判（validate 只见本块）——回落后仍空且被引用的拦截在
    /// seep-runtime 转换处；enabled=false 首位短路容忍半配置（§2.5 口径）。
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for (group, servers) in [("domestic", &self.domestic), ("trusted", &self.trusted)] {
            for s in servers {
                let addr: std::net::SocketAddr = s
                    .parse()
                    .with_context(|| format!("network.dns.{group} 上游须为 ip:port 形式:{s:?}"))?;
                anyhow::ensure!(
                    addr.port() != 0,
                    "network.dns.{group} 上游端口不能为 0:{s:?}"
                );
            }
        }
        for rule in &self.rules {
            anyhow::ensure!(
                !rule.pattern.trim().is_empty(),
                "network.dns.rules[].pattern 不能为空"
            );
            if let Some(suffix) = rule.pattern.strip_prefix('.') {
                anyhow::ensure!(
                    !suffix.is_empty(),
                    "network.dns.rules[].pattern 裸 \".\" 不构成 suffix 规则:{:?}",
                    rule.pattern
                );
            }
        }
        // 重复 pattern = 配置错误：先到先得语义下后者永不生效（静默覆盖不可测）
        for (i, a) in self.rules.iter().enumerate() {
            for b in &self.rules[i + 1..] {
                anyhow::ensure!(
                    a.pattern != b.pattern,
                    "network.dns.rules pattern 重复:{:?}",
                    a.pattern
                );
            }
        }
        if self.anti_poison == DnsAntiPoisonMode::CrossCheck {
            anyhow::ensure!(
                !self.trusted.is_empty(),
                "network.dns.anti_poison = cross_check 需要 trusted 组非空（E1,dns-partition.md §5）"
            );
        }
        if let Some(cache) = &self.cache {
            anyhow::ensure!(
                cache.min_ttl <= cache.max_ttl,
                "network.dns.cache.min_ttl ({}) 不应大于 max_ttl ({})",
                cache.min_ttl,
                cache.max_ttl
            );
            anyhow::ensure!(
                cache.max_entries >= 1,
                "network.dns.cache.max_entries 必须 ≥ 1"
            );
            anyhow::ensure!(
                cache.negative_ttl >= 1,
                "network.dns.cache.negative_ttl 必须 ≥ 1"
            );
        }
        anyhow::ensure!(self.timeout_ms >= 1, "network.dns.timeout_ms 必须 ≥ 1");
        anyhow::ensure!(self.listen_port != 0, "network.dns.listen_port 不能为 0");
        Ok(())
    }
}

/// obfuscation 区块（obfuscation-middleware.md §3.1）：seep-config 镜像 serde 类型，
/// 到 `PaddingSpec`/中间件链的转换在 seep-runtime（§3.2 裁决镜像而非加依赖，
/// `UdpConfig`/`NetworkBlockConfig` 先例）。deny_unknown_fields = 新块无存量
/// 负担（§3.4，B2 定向收口）；enabled 缺省 false（§2.5 零开销旁路）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfuscationConfig {
    /// 总开关；false = 构建期不构造任何 middleware、不注入注解（§2.5）
    #[serde(default)]
    pub enabled: bool,
    /// 引用 profiles 中的名字；与内联 padding 互斥（§3.3-2）
    #[serde(default)]
    pub default_padding: Option<String>,
    /// 选择器（chain | single | all | "egress:<name>"，匹配 §1.4 注解）；
    /// 缺省 chain——MVP 帧执行侧仅 chain 帧（§2.3），单跳 no-op 少生注解
    #[serde(default)]
    pub apply_to: ApplyTo,
    /// 声明链顺序（已知名 = padding / latency_probe / timing / shaping，§3.3-5 + §4.1，P2-4 扩）
    #[serde(default = "default_obfs_middleware")]
    pub middleware: Vec<String>,
    /// 命名策略集（P2-3 三场景预设的落点容器，§3.5；本文 schema 为其真子集）
    #[serde(default)]
    pub profiles: BTreeMap<String, ObfsProfileConfig>,
    /// 内联策略（无 default_padding 时生效；两者互斥，§3.3-2）
    #[serde(default)]
    pub padding: Option<PaddingBlockConfig>,
    /// P2-4：引用 profiles 中的名字（与内联 timing 互斥，同 §3.3-2 语义）
    #[serde(default)]
    pub default_timing: Option<String>,
    /// P2-4：内联 timing 策略
    #[serde(default)]
    pub timing: Option<TimingBlockConfig>,
    /// P2-4：引用 profiles 中的名字（与内联 shaping 互斥）
    #[serde(default)]
    pub default_shaping: Option<String>,
    /// P2-4：内联 shaping 策略
    #[serde(default)]
    pub shaping: Option<ShapingBlockConfig>,
    /// P3-2 WASM 插件块（plugin-loader.md §2.3）：在内置链之后按声明序追加
    #[serde(default)]
    pub plugins: Vec<ObfsPluginConfig>,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_padding: None,
            apply_to: ApplyTo::default(),
            middleware: default_obfs_middleware(),
            profiles: BTreeMap::new(),
            padding: None,
            default_timing: None,
            timing: None,
            default_shaping: None,
            shaping: None,
            plugins: Vec::new(),
        }
    }
}

/// P3-2 插件条目（plugin-loader.md §2.3）：wasm 产物路径 + 每调用 fuel 预算。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsPluginConfig {
    /// wasm 二进制路径（相对路径按进程 CWD 解析）
    pub path: PathBuf,
    /// 每调用 fuel 指令预算（缺省 1e8，seep-plugins::DEFAULT_PLUGIN_FUEL）
    #[serde(default)]
    pub fuel: Option<u64>,
}

fn default_obfs_middleware() -> Vec<String> {
    vec!["padding".to_string()]
}

impl ObfuscationConfig {
    /// §3.3 构建期校验（六条）。E5（apply_to 指向不存在 egress 名 → warning +
    /// 降级不生效）不在此处：validate 只见本块，egress 名集在调用侧，
    /// 落 seep-runtime `to_padding_policy`（§6 E5）。
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(()); // §3.3-1：关闭容忍半成品配置
        }
        anyhow::ensure!(
            !(self.default_padding.is_some() && self.padding.is_some()),
            "obfuscation.default_padding 与内联 obfuscation.padding 互斥（§3.3-2）"
        );
        anyhow::ensure!(
            !(self.default_timing.is_some() && self.timing.is_some()),
            "obfuscation.default_timing 与内联 obfuscation.timing 互斥（§3.3-2 同语义）"
        );
        anyhow::ensure!(
            !(self.default_shaping.is_some() && self.shaping.is_some()),
            "obfuscation.default_shaping 与内联 obfuscation.shaping 互斥（§3.3-2 同语义）"
        );
        anyhow::ensure!(
            self.default_padding.is_some()
                || self.padding.is_some()
                || self.default_timing.is_some()
                || self.timing.is_some()
                || self.default_shaping.is_some()
                || self.shaping.is_some()
                || !self.plugins.is_empty(),
            "obfuscation.enabled=true 但未配策略（default_*/内联/plugins 任一维任选其一，E1）"
        );
        // P3-2（plugin-loader.md §2.3）：enabled 时 path 必须存在（E1 同款构建期拦截；
        // 关闭态容忍半成品，§3.3-1 同语义）
        for plugin in &self.plugins {
            anyhow::ensure!(
                plugin.path.exists(),
                "obfuscation.plugins 路径不存在：{:?}（E1，相对路径按进程 CWD 解析）",
                plugin.path
            );
            if let Some(fuel) = plugin.fuel {
                anyhow::ensure!(
                    fuel >= 1,
                    "obfuscation.plugins fuel 必须 ≥ 1（{:?}）",
                    plugin.path
                );
            }
        }
        if let Some(name) = &self.default_padding {
            let profile = self.profiles.get(name).ok_or_else(|| {
                anyhow::anyhow!("obfuscation.default_padding 指向未定义 profile：{name:?}（E3）")
            })?;
            anyhow::ensure!(
                profile.padding.is_some(),
                "profile {name:?} 未定义 padding（E1：开了但没有策略）"
            );
        }
        if let Some(name) = &self.default_timing {
            let profile = self.profiles.get(name).ok_or_else(|| {
                anyhow::anyhow!("obfuscation.default_timing 指向未定义 profile：{name:?}（E3）")
            })?;
            anyhow::ensure!(
                profile.timing.is_some(),
                "profile {name:?} 未定义 timing（E1：开了但没有策略）"
            );
        }
        if let Some(name) = &self.default_shaping {
            let profile = self.profiles.get(name).ok_or_else(|| {
                anyhow::anyhow!("obfuscation.default_shaping 指向未定义 profile：{name:?}（E3）")
            })?;
            anyhow::ensure!(
                profile.shaping.is_some(),
                "profile {name:?} 未定义 shaping（E1：开了但没有策略）"
            );
        }
        // §3.3-4/5：全部块逐个校验——未选中的坏 profile 也构建期拦截
        if let Some(inline) = &self.padding {
            inline.validate()?;
        }
        if let Some(inline) = &self.timing {
            inline.validate()?;
        }
        if let Some(inline) = &self.shaping {
            inline.validate()?;
        }
        for (name, profile) in &self.profiles {
            if let Some(block) = &profile.padding {
                block
                    .validate()
                    .with_context(|| format!("profile {name:?}"))?;
            }
            if let Some(block) = &profile.timing {
                block
                    .validate()
                    .with_context(|| format!("profile {name:?}"))?;
            }
            if let Some(block) = &profile.shaping {
                block
                    .validate()
                    .with_context(|| format!("profile {name:?}"))?;
            }
        }
        for mw in &self.middleware {
            anyhow::ensure!(
                matches!(mw.as_str(), "padding" | "latency_probe" | "timing" | "shaping"),
                "obfuscation.middleware 含未知名字 {mw:?}（E2/§4.1：padding|latency_probe|timing|shaping）"
            );
        }
        Ok(())
    }
}

/// obfuscation.profiles 条目（§3.1）：命名策略集；MVP 仅 padding 一维（P2-3
/// 在此扩字段如 routing_template，本文 schema 为其真子集，§3.5）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsProfileConfig {
    /// 该 profile 的 padding 策略；None + 被引用 = E1（开了没有策略）
    #[serde(default)]
    pub padding: Option<PaddingBlockConfig>,
    /// P2-4：该 profile 的 timing 策略（引用面 = default_timing）
    #[serde(default)]
    pub timing: Option<TimingBlockConfig>,
    /// P2-4：该 profile 的 shaping 策略（引用面 = default_shaping）
    #[serde(default)]
    pub shaping: Option<ShapingBlockConfig>,
}

/// obfuscation.padding 块（§3.1 内联 / profiles 内嵌共用形状）：mode 必填
/// 字符串（fixed|bucket|range），各模式字段缺省 0/空；validate 按所属模式
/// 校验（§3.3-4）。mode 字符串 → `PaddingMode` 枚举在 seep-runtime 转换（§3.2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddingBlockConfig {
    /// fixed | bucket | range（E2）
    pub mode: String,
    /// fixed：目标长度（须非 0）；bucket/range 忽略
    #[serde(default)]
    pub target: usize,
    /// bucket：候选桶（升序非空）；对齐到最近上界桶
    #[serde(default)]
    pub buckets: Vec<usize>,
    /// range：下界
    #[serde(default)]
    pub min: usize,
    /// range：上界（min ≤ max）
    #[serde(default)]
    pub max: usize,
    /// overhead 保护上限（§2.6：len' > max(len*(1+ratio), min) 则放弃填充）
    #[serde(default = "default_max_overhead_ratio")]
    pub max_overhead_ratio: f32,
}

const fn default_max_overhead_ratio() -> f32 {
    0.5
}

impl Default for PaddingBlockConfig {
    fn default() -> Self {
        Self {
            mode: "fixed".to_string(),
            target: 0,
            buckets: Vec::new(),
            min: 0,
            max: 0,
            max_overhead_ratio: default_max_overhead_ratio(),
        }
    }
}

impl PaddingBlockConfig {
    /// §3.3-4/5：mode 三值 + 按模式参数 + ratio ≥ 0，带原值报错（E2）。
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            matches!(self.mode.as_str(), "fixed" | "bucket" | "range"),
            "obfuscation.padding.mode 非法：{:?}（E2，须为 fixed|bucket|range）",
            self.mode
        );
        anyhow::ensure!(
            self.max_overhead_ratio >= 0.0,
            "obfuscation.padding.max_overhead_ratio 须 ≥ 0（当前 {}）",
            self.max_overhead_ratio
        );
        match self.mode.as_str() {
            "fixed" => anyhow::ensure!(
                self.target != 0,
                "fixed 模式 target 须非 0（E2，当前 {}）",
                self.target
            ),
            "bucket" => {
                anyhow::ensure!(!self.buckets.is_empty(), "bucket 模式 buckets 非空（E2）");
                anyhow::ensure!(
                    self.buckets.windows(2).all(|w| w[0] < w[1]),
                    "bucket 模式 buckets 须严格升序（E2）：{:?}",
                    self.buckets
                );
            }
            "range" => anyhow::ensure!(
                self.min <= self.max,
                "range 模式须 min ≤ max（E2）：min={}, max={}",
                self.min,
                self.max
            ),
            _ => unreachable!("上方 ensure 已拦非三值 mode"),
        }
        Ok(())
    }
}

/// P2-4：obfuscation.timing 块（内联 / profiles 内嵌共用形状）：mode 必填
/// 字符串（fixed|uniform），逐模式参数 + 硬闸门 max_delay_ms。mode 字符串
/// → `TimingMode` 枚举在 seep-runtime 转换（对称 PaddingBlockConfig）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingBlockConfig {
    /// fixed | uniform（E2）
    pub mode: String,
    /// fixed：注入抖动毫秒值（须非 0）
    #[serde(default)]
    pub fixed_ms: u64,
    /// uniform：下界
    #[serde(default)]
    pub min_ms: u64,
    /// uniform：上界（min ≤ max）
    #[serde(default)]
    pub max_ms: u64,
    /// 硬闸门：决策值截断上限（E2：须 ≥ 1 且 ≥ uniform min 的可用下界——
    /// 0 即未配置视为非法，避免「开了但恒 0」的假开关）
    #[serde(default)]
    pub max_delay_ms: u64,
}

impl Default for TimingBlockConfig {
    fn default() -> Self {
        Self {
            mode: "fixed".to_string(),
            fixed_ms: 0,
            min_ms: 0,
            max_ms: 0,
            max_delay_ms: 0,
        }
    }
}

impl TimingBlockConfig {
    /// P2-4 §6-E2：mode 两值 + 逐模式参数 + 闸门须配置，带原值报错。
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            matches!(self.mode.as_str(), "fixed" | "uniform"),
            "obfuscation.timing.mode 非法：{:?}（E2，须为 fixed|uniform）",
            self.mode
        );
        anyhow::ensure!(
            self.max_delay_ms >= 1,
            "obfuscation.timing.max_delay_ms 须 ≥ 1（E2，当前 {}）",
            self.max_delay_ms
        );
        match self.mode.as_str() {
            "fixed" => anyhow::ensure!(
                self.fixed_ms >= 1,
                "fixed 模式 fixed_ms 须 ≥ 1（E2，当前 {}）",
                self.fixed_ms
            ),
            "uniform" => {
                anyhow::ensure!(
                    self.min_ms <= self.max_ms,
                    "uniform 模式须 min_ms ≤ max_ms（E2）：min_ms={}, max_ms={}",
                    self.min_ms,
                    self.max_ms
                );
                anyhow::ensure!(
                    self.max_ms <= self.max_delay_ms,
                    "uniform 模式 max_ms 须 ≤ max_delay_ms 闸门（E2）：max_ms={}, max_delay_ms={}",
                    self.max_ms,
                    self.max_delay_ms
                );
            }
            _ => unreachable!("上方 ensure 已拦非双值 mode"),
        }
        Ok(())
    }
}

/// P2-4：obfuscation.shaping 块（内联 / profiles 内嵌共用形状）：mode 必填
/// 字符串（interval），网格间隔 + 抖动幅度 + 硬闸门。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShapingBlockConfig {
    /// interval（E2，M0 仅此一值）
    pub mode: String,
    /// 网格间隔毫秒（须非 0）
    #[serde(default)]
    pub interval_ms: u64,
    /// 网格抖动幅度（须 ≤ interval_ms：抖动不喧宾夺主）
    #[serde(default)]
    pub jitter_ms: u64,
    /// 硬闸门：单写延迟截断上限（须 ≥ interval_ms 之外的抖动余量内…
    /// 口径：max_delay_ms ≥ 1 且 ≥ interval_ms，保证最坏路径可控）
    #[serde(default)]
    pub max_delay_ms: u64,
}

impl Default for ShapingBlockConfig {
    fn default() -> Self {
        Self {
            mode: "interval".to_string(),
            interval_ms: 0,
            jitter_ms: 0,
            max_delay_ms: 0,
        }
    }
}

impl ShapingBlockConfig {
    /// P2-4 §6-E2：mode 单值 + 间隔/抖动/闸门三字段矩阵，带原值报错。
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.mode == "interval",
            "obfuscation.shaping.mode 非法：{:?}（E2，须为 interval）",
            self.mode
        );
        anyhow::ensure!(
            self.interval_ms >= 1,
            "obfuscation.shaping.interval_ms 须 ≥ 1（E2，当前 {}）",
            self.interval_ms
        );
        anyhow::ensure!(
            self.jitter_ms <= self.interval_ms,
            "obfuscation.shaping.jitter_ms 须 ≤ interval_ms（E2）：jitter_ms={}, interval_ms={}",
            self.jitter_ms,
            self.interval_ms
        );
        anyhow::ensure!(
            self.max_delay_ms >= self.interval_ms,
            "obfuscation.shaping.max_delay_ms 须 ≥ interval_ms（E2）：max_delay_ms={}, interval_ms={}",
            self.max_delay_ms,
            self.interval_ms
        );
        Ok(())
    }
}

/// obfuscation.apply_to 选择器（§3.1/§3.2 表行 2）：匹配 §1.4 注解
/// `seep.route.kind`（"chain"/"single"）与 `seep.route.egress`（最终节点名）。
/// serde 呈现为扁平字符串：`chain` / `single` / `all` / `egress:<name>`
/// （§3.1 样例形态），未知值构建期解析报错。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ApplyTo {
    #[default]
    Chain,
    Single,
    All,
    Egress(String),
}

impl ApplyTo {
    /// 扁平字符串形（serde 序列化值；`egress:<name>` 带名展开）
    pub fn as_config_str(&self) -> String {
        match self {
            ApplyTo::Chain => "chain".to_string(),
            ApplyTo::Single => "single".to_string(),
            ApplyTo::All => "all".to_string(),
            ApplyTo::Egress(name) => format!("egress:{name}"),
        }
    }

    /// 解析扁平字符串形（serde 反序列化路径）：未知值 / `egress:` 空名报错。
    pub fn parse_config_str(s: &str) -> Result<Self> {
        match s {
            "chain" => Ok(ApplyTo::Chain),
            "single" => Ok(ApplyTo::Single),
            "all" => Ok(ApplyTo::All),
            _ => {
                if let Some(name) = s.strip_prefix("egress:") {
                    anyhow::ensure!(
                        !name.is_empty(),
                        "apply_to = {s:?} 非法：egress 名为空（形如 egress:<name>）"
                    );
                    Ok(ApplyTo::Egress(name.to_string()))
                } else {
                    anyhow::bail!(
                        "apply_to = {s:?} 非法：须为 chain | single | all | egress:<name>"
                    )
                }
            }
        }
    }
}

impl Serialize for ApplyTo {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_config_str())
    }
}

impl<'de> Deserialize<'de> for ApplyTo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ApplyTo::parse_config_str(&s).map_err(serde::de::Error::custom)
    }
}

/// egress_pool 区块（egress-connection-pool.md §3.1）：seep-config 镜像 serde
/// 类型，到 `PoolPolicy` 的转换在 seep-runtime `to_pool_policy`（§3.2 裁决
/// 镜像而非加依赖，`ObfuscationConfig`/`NetworkBlockConfig` 先例）。
/// deny_unknown_fields = 新块无存量负担（§3.4）；除 enabled 外全 Option
/// （§3.2 表），其中 max_idle_global 缺席有独立语义：取 runtime
/// `connection_pool_size`（D-8 孤儿字段收编），其余缺席 = §3.1 缺省值。
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPoolBlock {
    /// 池总开关（§3.1 缺省关 = 对齐 udp:/obfuscation: 先例，D-9 零差异）
    #[serde(default)]
    pub enabled: bool,
    /// 共享 ClientConfig + 会话缓存；块存在即生效，独立于 enabled（§3.1；缺省 true）
    #[serde(default)]
    pub tls_resumption: Option<bool>,
    /// 每键 idle 上限（预热/补充目标；缺省 2）
    #[serde(default)]
    pub max_idle_per_key: Option<usize>,
    /// 全局 idle 上限；缺省取 runtime.connection_pool_size（D-8）
    #[serde(default)]
    pub max_idle_global: Option<usize>,
    /// 借出后 idle 低于此值即触发补充（≤ max_idle_per_key；缺省 1）
    #[serde(default)]
    pub low_watermark: Option<usize>,
    /// idle 条目寿命（秒，自入池起算；缺省 30）
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// 单次拨号超时（TCP+TLS 全程；缺省 5）
    #[serde(default)]
    pub dial_timeout_secs: Option<u64>,
    /// ClientSessionMemoryCache 容量（缺省 256）
    #[serde(default)]
    pub session_cache_size: Option<usize>,
    /// direct 按 target 投机预拨（默认关；对外观感风险 R-pool2，开启者显式承担）
    #[serde(default)]
    pub pre_dial_direct: Option<bool>,
}

impl EgressPoolBlock {
    /// 块存在即生效的 TLS 会话恢复开关（§4.1 装配 filter 取用；缺省 true）
    pub fn tls_resumption(&self) -> bool {
        self.tls_resumption.unwrap_or(true)
    }

    /// 投机预拨开关（缺省 false）
    pub fn pre_dial_direct(&self) -> bool {
        self.pre_dial_direct.unwrap_or(false)
    }

    /// §3.3 构建期校验（四条）。规则 3（idle_timeout_secs < dial_timeout_secs
    /// → warning 不 Err）不在此处：seep-config 无 tracing 依赖（network E5
    /// 「warning 落转换处」先例），warning 落 seep-runtime `to_pool_policy`。
    pub fn validate(&self) -> Result<()> {
        // §3.3-1：池与 TLS 恢复全关 → 后续容量/水位字段无视（容忍半成品配置）
        if !self.enabled && !self.tls_resumption() {
            return Ok(());
        }
        if self.max_idle_per_key == Some(0) {
            anyhow::bail!("egress_pool.max_idle_per_key 须 ≥ 1（当前 0，E1/§3.3-2）");
        }
        if let Some(low) = self.low_watermark {
            let per_key = self.max_idle_per_key.unwrap_or(2);
            if low > per_key {
                anyhow::bail!(
                    "egress_pool.low_watermark ({low}) 不应大于 max_idle_per_key ({per_key}，E1/§3.3-2)"
                );
            }
        }
        if self.tls_resumption() && self.session_cache_size == Some(0) {
            anyhow::bail!(
                "egress_pool.session_cache_size 须 ≥ 1（tls_resumption 开启时，当前 0，E1/§3.3-2）"
            );
        }
        if self.pre_dial_direct() && !self.enabled {
            anyhow::bail!(
                "egress_pool.pre_dial_direct=true 须搭配 egress_pool.enabled=true（无池则无从预拨，§3.3-4）"
            );
        }
        Ok(())
    }
}

impl SeepConfig {
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件: {}", path.display()))?;
        let hint = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);
        Self::from_str(&raw, hint.as_deref())
    }

    pub fn from_str(raw: &str, hint: Option<&str>) -> Result<Self> {
        let mut config: Self = match hint {
            Some("json") => serde_json::from_str(raw).context("JSON 配置解析失败")?,
            Some("toml") => toml::from_str(raw).context("TOML 配置解析失败")?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(raw).context("YAML 配置解析失败")?,
            _ => serde_yaml::from_str(raw)
                .or_else(|_| serde_json::from_str(raw))
                .or_else(|_| toml::from_str(raw))
                .context("无法识别配置格式")?,
        };
        // P2-3 §5-1：场景预设缺省填充（唯一入口——load_from_path 经此覆盖；
        // 订阅转换等程序化构造不触发，「订阅不产场景块」同 obfuscation 先例）
        config.apply_profile();
        Ok(config)
    }

    /// 场景预设展开（scenario-profiles.md §2-D2/D4）：**缺省填充，显式恒
    /// 优先**——只往「未指定」位（groups/rules 空、obfuscation/egress_pool
    /// None）填预设，不覆盖不删除，天然幂等（§6-E4：填过即非空，再展开
    /// 为 no-op）。规则模板与组模板同生共死：组非空（用户自组在场）时
    /// 不填规则——模板 target 指向组模板名，用户自组名不可猜测（§6-E6）。
    pub fn apply_profile(&mut self) {
        let Some(kind) = self.profile else {
            return;
        };
        let mut created_group = false;
        if self.routing.groups.is_empty() {
            let (name, slo) = match kind {
                ProfileKind::Game => (
                    "game-auto",
                    Some(SloPolicy {
                        p95_ms: Some(80),
                        loss_ratio: Some(0.02),
                        loss_penalty_ms: None,
                    }),
                ),
                ProfileKind::Proxy => ("auto", None),
                ProfileKind::Web => ("web-auto", None),
            };
            self.routing.groups.push(PolicyGroup {
                name: name.to_string(),
                strategy: Strategy::Latency,
                members: vec![GroupMember::Node {
                    name: self.routing.default_node.clone(),
                }],
                slo,
            });
            created_group = true;
        }
        if self.routing.rules.is_empty() && created_group {
            self.routing.rules = match kind {
                ProfileKind::Game => GAME_DOMAIN_SUFFIXES
                    .iter()
                    .map(|d| RouteRule {
                        name: format!("game-{}", d.replace('.', "-")),
                        matches: vec![MatchCondition::DomainSuffix {
                            values: vec![(*d).to_string()],
                        }],
                        target: "game-auto".to_string(),
                    })
                    .collect(),
                ProfileKind::Proxy => vec![profile_cn_rule("auto")],
                ProfileKind::Web => vec![profile_cn_rule("web-auto")],
            };
        }
        // game：QoS 包长打散（positioning §2.4；apply_to 缺省 chain = MVP
        // 帧执行侧，obfuscation-middleware.md §2.3）+ P2-4 M2 启动抖动演示
        // （fixed 10ms ≤ 闸门 20ms 对 p95 80ms SLO 可量化余量）
        if kind == ProfileKind::Game && self.obfuscation.is_none() {
            self.obfuscation = Some(ObfuscationConfig {
                default_timing: None,
                timing: Some(TimingBlockConfig {
                    mode: "fixed".to_string(),
                    fixed_ms: 10,
                    max_delay_ms: 20,
                    ..TimingBlockConfig::default()
                }),
                default_shaping: None,
                shaping: None,
                enabled: true,
                middleware: vec!["padding".to_string(), "timing".to_string()],
                padding: Some(PaddingBlockConfig {
                    mode: "bucket".to_string(),
                    buckets: vec![128, 256, 512, 1024],
                    ..PaddingBlockConfig::default()
                }),
                ..ObfuscationConfig::default()
            });
        }
        // web：网页短连接复用（P1-5；其余字段缺省 = §3.1 缺省值）
        if kind == ProfileKind::Web && self.egress_pool.is_none() {
            self.egress_pool = Some(EgressPoolBlock {
                enabled: true,
                ..EgressPoolBlock::default()
            });
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        PathBuf::from("/etc/seep")
    }
}

/// game 预设规则模板域（scenario-profiles.md §4/§9-4：示例性常见平台域
/// 非穷举——模板价值在展示策略块写法，精确清单归用户维护；显式 rules
/// 恒优先 D-2）
const GAME_DOMAIN_SUFFIXES: &[&str] = &[
    "steampowered.com",
    "steamcontent.com",
    "epicgames.com",
    "riotgames.com",
    "battle.net",
    "playstation.com",
    "xbox.com",
    "nintendo.com",
];

/// proxy/web 预设 cn 规则（同 config/seep.yaml 基线形：geoip CN → 场景组）
fn profile_cn_rule(target: &str) -> RouteRule {
    RouteRule {
        name: "cn".to_string(),
        matches: vec![MatchCondition::Geoip {
            country: "CN".to_string(),
        }],
        target: target.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlConfig {
    pub api_bind: String,
    pub uds_path: Option<PathBuf>,
    pub admin_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub enable_metrics: bool,
    pub enable_tracing: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngressDescriptor {
    pub name: String,
    #[serde(flatten)]
    pub spec: IngressConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressDescriptor {
    pub name: String,
    #[serde(flatten)]
    pub spec: EgressConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IngressConfig {
    Socks5 {
        bind: String,
        auth: Option<Vec<Credential>>,
        /// per-ingress UDP 覆盖（P0-5 §1.3）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 ASSOCIATE。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
    Http {
        bind: String,
        /// 入站认证（Proxy-Authorization: Basic）；None/空表 = 匿名放行，语义同 Socks5。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<Vec<Credential>>,
        /// Bearer Token 认证（Proxy-Authorization: Bearer <token>）；None/空表 = 不启用。
        /// 与 auth 并列：任一 scheme 通过即放行，407 挑战同时通告两者。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bearer_tokens: Option<Vec<String>>,
    },
    Mixed {
        bind: String,
        /// 入站认证：socks5 分支走 RFC 1929、http 分支走 Proxy-Authorization
        /// Basic（407 拒绝），语义同 Socks5；None/空表 = 匿名放行。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<Vec<Credential>>,
        /// per-ingress UDP 覆盖（P0-5 §1.3），语义同 Socks5。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
        /// Bearer Token 认证（仅 http 分支，语义同 Http）；None/空表 = 不启用。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bearer_tokens: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressConfig {
    /// reject 出口（G0-5）：路由命中即断流（广告/恶意目标拦截）。
    /// 无网络 I/O，forward 层直接返回错误。
    Reject,
    Direct,
    Socks5 {
        server: String,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Http {
        server: String,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls_fingerprint: Option<String>,
    },
    Shadowsocks {
        server: String,
        port: u16,
        method: String,
        password: String,
        /// SIP003 插件可执行名（如 v2ray-plugin / obfs-local）；None = 直连
        /// SS 协议（shadowsocks crate）。插件模式下 TCP 数据面由插件进程桥接。
        #[serde(skip_serializing_if = "Option::is_none")]
        plugin: Option<String>,
        /// SIP003 插件参数（空格分词后作为插件 argv 追加；语义由插件自解析）
        #[serde(skip_serializing_if = "Option::is_none")]
        plugin_opts: Option<String>,
    },
    Vmess {
        server: String,
        port: u16,
        uuid: String,
        #[serde(default)]
        alter_id: u16,
        #[serde(default = "default_security")]
        security: String,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        /// gRPC 服务名（network=grpc 时必填；线上路径 = /{name}/Tun）
        #[serde(skip_serializing_if = "Option::is_none")]
        grpc_service_name: Option<String>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls_fingerprint: Option<String>,
    },
    Vless {
        server: String,
        port: u16,
        uuid: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<String>,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        /// gRPC 服务名（network=grpc 时必填；线上路径 = /{name}/Tun）
        #[serde(skip_serializing_if = "Option::is_none")]
        grpc_service_name: Option<String>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls_fingerprint: Option<String>,
    },
    Trojan {
        server: String,
        port: u16,
        password: String,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        /// gRPC 服务名（network=grpc 时必填；线上路径 = /{name}/Tun）
        #[serde(skip_serializing_if = "Option::is_none")]
        grpc_service_name: Option<String>,
        #[serde(default = "default_tls_true")]
        tls: bool,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls_fingerprint: Option<String>,
    },
    Hysteria {
        server: String,
        port: u16,
        password: String,
        #[serde(default = "default_protocol")]
        protocol: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        up_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        down_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_str: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs_param: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_name: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Hysteria2 {
        server: String,
        port: u16,
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mport: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs_param: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_name: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    Wireguard {
        endpoint: String,
        private_key: String,
        public_key: String,
        address: String,
        /// Allowed IPs for peer routing (e.g. ["10.0.0.0/24", "0.0.0.0/0"]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_ips: Option<Vec<String>>,
        /// Optional pre-shared key (base64 or hex).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preshared_key: Option<String>,
        /// Optional persistent keepalive in seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persistent_keepalive: Option<u16>,
        /// Optional local listen port (0/None means auto).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        listen_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mtu: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dns: Option<Vec<String>>,
    },
}

fn default_security() -> String {
    "auto".to_string()
}
fn default_network() -> String {
    "tcp".to_string()
}
fn default_protocol() -> String {
    "udp".to_string()
}
fn default_tls_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub default_node: String,
    pub groups: Vec<PolicyGroup>,
    pub rules: Vec<RouteRule>,
}

impl RoutingConfig {
    /// 组级 SLO 值域构建期拦截（slo-scoring.md §4）：runtime build()/热更新
    /// 装配前防御性调用。
    pub fn validate(&self) -> anyhow::Result<()> {
        for group in &self.groups {
            if let Some(slo) = &group.slo {
                slo.validate()
                    .map_err(|e| anyhow::anyhow!("组 {} 的 slo 配置非法: {e}", group.name))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGroup {
    pub name: String,
    pub strategy: Strategy,
    pub members: Vec<GroupMember>,
    /// 组级 SLO 目标（slo-scoring.md §3）：`latency` 策略以 p95 RTT/丢包
    /// 为目标门 + 加性罚分评分（§2 D-1/D-2）；缺省 None = 纯最低分
    /// （存量行为兼容面）
    #[serde(default)]
    pub slo: Option<SloPolicy>,
}

/// 组级 SLO 目标策略（slo-scoring.md §2 D-1/D-2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloPolicy {
    /// p95 RTT 目标门（ms）：有真链路数据的成员超过即不合规（无数据成员
    /// 视为合规——unknown 不误杀，§6 E1）
    #[serde(default)]
    pub p95_ms: Option<u32>,
    /// 丢包率目标门（0.0-1.0）
    #[serde(default)]
    pub loss_ratio: Option<f64>,
    /// 丢包罚分权重（ms / 单位丢包率）；缺省 1000.0（1% 丢包 ≈ +10ms 罚分）
    #[serde(default)]
    pub loss_penalty_ms: Option<f64>,
}

impl SloPolicy {
    /// 值域构建期拦截（slo-scoring.md §4 validate 行）：由
    /// `RoutingConfig::validate` 逐组调用。
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(loss) = self.loss_ratio {
            anyhow::ensure!(
                (0.0..=1.0).contains(&loss),
                "slo.loss_ratio 必须 ∈ [0,1]，当前 {loss}"
            );
        }
        if let Some(penalty) = self.loss_penalty_ms {
            anyhow::ensure!(
                penalty >= 0.0,
                "slo.loss_penalty_ms 必须 ≥ 0，当前 {penalty}"
            );
        }
        Ok(())
    }

    /// 罚分权重（None → 1000.0，§2 D-1 缺省）
    pub fn penalty_or_default(&self) -> f64 {
        self.loss_penalty_ms.unwrap_or(1000.0)
    }
}

/// 运行时组描述符，包含解析后的组和统计信息
#[derive(Debug, Clone)]
pub struct GroupDescriptor {
    pub name: String,
    pub strategy: Strategy,
    pub members: Vec<GroupDescriptorMember>,
    pub fallback_enabled: bool,
    pub health_check_interval: Option<u64>,
    /// 组级 SLO 目标（自 PolicyGroup.slo 透传，slo-scoring.md §4）
    pub slo: Option<SloPolicy>,
}

#[derive(Debug, Clone)]
pub enum GroupDescriptorMember {
    Node {
        name: String,
        weight: u32,
        is_healthy: bool,
    },
    Group {
        name: String,
        weight: u32,
        descriptor: Box<GroupDescriptor>,
    },
}

impl GroupDescriptorMember {
    pub fn as_name(&self) -> &str {
        match self {
            GroupDescriptorMember::Node { name, .. } => name,
            GroupDescriptorMember::Group { name, .. } => name,
        }
    }

    pub fn as_weight(&self) -> u32 {
        match self {
            GroupDescriptorMember::Node { weight, .. } => *weight,
            GroupDescriptorMember::Group { weight, .. } => *weight,
        }
    }

    pub fn is_healthy(&self) -> bool {
        match self {
            GroupDescriptorMember::Node { is_healthy, .. } => *is_healthy,
            GroupDescriptorMember::Group { descriptor, .. } => {
                // 组健康状态可以基于成员健康状态计算
                descriptor.has_healthy_members()
            }
        }
    }
}

impl GroupDescriptor {
    pub fn new(
        name: String,
        strategy: Strategy,
        members: Vec<GroupDescriptorMember>,
        slo: Option<SloPolicy>,
    ) -> Self {
        Self {
            name,
            strategy,
            members,
            fallback_enabled: true,
            health_check_interval: Some(30),
            slo,
        }
    }

    pub fn has_healthy_members(&self) -> bool {
        self.members.iter().any(|m| m.is_healthy())
    }

    pub fn healthy_members(&self) -> Vec<&GroupDescriptorMember> {
        self.members.iter().filter(|m| m.is_healthy()).collect()
    }

    /// 展开所有节点（处理组嵌套）
    pub fn flatten_nodes(&self) -> Vec<(String, u32)> {
        let mut nodes = Vec::new();
        for member in &self.members {
            match member {
                GroupDescriptorMember::Node { name, weight, .. } => {
                    nodes.push((name.clone(), *weight));
                }
                GroupDescriptorMember::Group {
                    descriptor, weight, ..
                } => {
                    // 递归展开嵌套组，应用权重
                    let nested_nodes = descriptor.flatten_nodes();
                    for (node_name, node_weight) in nested_nodes {
                        nodes.push((node_name, node_weight.saturating_mul(*weight)));
                    }
                }
            }
        }
        nodes
    }
}

#[derive(Debug, Clone)]
pub enum GroupMember {
    /// 直接节点引用
    Node { name: String },
    /// 嵌套组引用
    Group { name: String },
    /// 带权重的节点
    WeightedNode { name: String, weight: u32 },
    /// 带权重的组
    WeightedGroup { name: String, weight: u32 },
}

/// 手写序列化（internally-tagged `{type, name, weight?}` 形）：derive 出的
/// externally-tagged `!Node` 形与 `GroupMemberRepr` 反序列化面（字符串
/// 简写 / `type:` 标签形）互不相认——serde_yaml 序列化的 SeepConfig
/// （如 seepctl import-clash）seepd 读不回。此实现与 Tagged 反序列化
/// 镜像，保证往返自洽。
impl Serialize for GroupMember {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (tag, name, weight) = match self {
            GroupMember::Node { name } => ("node", name, None),
            GroupMember::Group { name } => ("group", name, None),
            GroupMember::WeightedNode { name, weight } => ("weighted_node", name, Some(*weight)),
            GroupMember::WeightedGroup { name, weight } => ("weighted_group", name, Some(*weight)),
        };
        let mut st =
            serializer.serialize_struct("GroupMember", if weight.is_some() { 3 } else { 2 })?;
        st.serialize_field("type", tag)?;
        st.serialize_field("name", name)?;
        if let Some(w) = weight {
            st.serialize_field("weight", &w)?;
        }
        st.end()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GroupMemberTagged {
    Node { name: String },
    Group { name: String },
    WeightedNode { name: String, weight: u32 },
    WeightedGroup { name: String, weight: u32 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum GroupMemberRepr {
    /// Shorthand: treat a plain string as `Node { name: ... }`.
    String(String),
    Tagged(GroupMemberTagged),
}

impl From<GroupMemberTagged> for GroupMember {
    fn from(v: GroupMemberTagged) -> Self {
        match v {
            GroupMemberTagged::Node { name } => GroupMember::Node { name },
            GroupMemberTagged::Group { name } => GroupMember::Group { name },
            GroupMemberTagged::WeightedNode { name, weight } => {
                GroupMember::WeightedNode { name, weight }
            }
            GroupMemberTagged::WeightedGroup { name, weight } => {
                GroupMember::WeightedGroup { name, weight }
            }
        }
    }
}

impl<'de> Deserialize<'de> for GroupMember {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let repr = GroupMemberRepr::deserialize(deserializer)?;
        Ok(match repr {
            GroupMemberRepr::String(name) => GroupMember::Node { name },
            GroupMemberRepr::Tagged(v) => v.into(),
        })
    }
}

impl GroupMember {
    pub fn as_name(&self) -> String {
        match self {
            GroupMember::Node { name } => name.clone(),
            GroupMember::Group { name } => name.clone(),
            GroupMember::WeightedNode { name, .. } => name.clone(),
            GroupMember::WeightedGroup { name, .. } => name.clone(),
        }
    }

    pub fn as_weight(&self) -> u32 {
        match self {
            GroupMember::Node { .. } => 1,
            GroupMember::Group { .. } => 1,
            GroupMember::WeightedNode { weight, .. } => *weight,
            GroupMember::WeightedGroup { weight, .. } => *weight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Fixed,
    Latency,
    Random,
    /// 基于带宽选择
    Bandwidth,
    /// 加权随机选择
    Weighted,
    /// 一致性哈希
    ConsistentHash,
    /// 轮询
    RoundRobin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub name: String,
    pub matches: Vec<MatchCondition>,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchCondition {
    /// 逻辑 OR：任一子条件命中即命中（`matches` 顶层仍是 AND）。
    /// 嵌套 NOT 内的 Any 可表达 OR-of-NOT 等任意组合。
    Any {
        conditions: Vec<MatchCondition>,
    },
    /// 逻辑 NOT：子条件不命中即命中（用于排除/反选）。
    Not {
        condition: Box<MatchCondition>,
    },
    DomainSuffix {
        values: Vec<String>,
    },
    DomainKeyword {
        values: Vec<String>,
    },
    Geoip {
        country: String,
    },
    Network {
        cidrs: Vec<String>,
    },
    /// 目的 IP-CIDR 匹配（G0-1）：目标主机为 IP 字面量时按 CIDR 前缀匹配。
    /// 与 `Network`（绑定 `client.cidr` 源注解）不同，本条件直接匹配流的
    /// 目标地址，供「目标网段走指定出口」分流；host 为域名时不命中（域名
    /// 解析由 sniff/回填层负责，路由面不做 DNS）。
    IpCidr {
        cidrs: Vec<String>,
    },
    Port {
        values: Vec<u16>,
    },
    /// 按源进程名匹配（tun-dataplane.md §2.5）：值为 `/proc/<pid>/comm` 口径
    /// 的进程名（内核截断 15 字节），由 TUN 入口首包归因后写入
    /// `process.name` 注解——仅 TUN 面有该注解，其它 ingress 流恒不命中。
    Process {
        values: Vec<String>,
    },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("未知的入口类型: {0}")]
    UnknownIngress(String),
    #[error("未知的出口类型: {0}")]
    UnknownEgress(String),
}
