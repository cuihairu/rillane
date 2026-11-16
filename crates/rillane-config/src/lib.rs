use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod apply;
pub mod approval;
pub mod contract;
pub mod generations;
pub mod preview;
pub mod proposal;
pub mod protocol_catalog;
pub mod rollback;
pub mod source;
pub mod watchdog;

pub use apply::{
    ApplyError, ApplyLedger, ApplyReceipt, ApplyReconcile, ApplyRequest, ApplyResult, ApplyStatus,
    ExecutionOutcome, APPLY_LABEL_MAX_CHARS, APPLY_RECEIPT_CAP, CODE_APPLY_BASE_CONFLICT,
    CODE_APPLY_CAPACITY, CODE_APPLY_EXECUTE_FAILED, CODE_APPLY_HASH_CONFLICT,
    CODE_APPLY_INPUT_INVALID, CODE_APPLY_KEY_MISMATCH,
};
pub use approval::{
    proposal_digest, ApprovalAuthority, ApprovalError, PreauthorizedGrant, ProposalApproval,
    APPROVAL_STORE_CAP, CODE_APPROVAL_CAPACITY, CODE_APPROVAL_EXPIRED, CODE_APPROVAL_FOREIGN,
    CODE_APPROVAL_POLICY_EXHAUSTED, CODE_APPROVAL_REPLAYED, CODE_APPROVAL_REQUIRED,
    CODE_APPROVAL_SCOPE_EXCEEDED, CODE_APPROVAL_SCOPE_INVALID, CODE_APPROVAL_STALE,
    CODE_APPROVAL_UNKNOWN, PREAUTH_GRANT_CAP,
};
pub use contract::{
    CapabilitySet, ConfigError, ConfigVersion, CODE_UNKNOWN_VERSION, CODE_UNSUPPORTED_COMBINATION,
};
pub use generations::{
    digest_parts, GenerationEdge, GenerationError, GenerationObject, GenerationStore,
    RuntimeGeneration, CODE_GENERATION_CYCLE, CODE_GENERATION_DANGLING, CODE_GENERATION_DUPLICATE,
    CODE_GENERATION_ID_MISMATCH,
};
pub use preview::{
    merge_patch, preview_config_patch, AffectedCategory, ConfigPreview, DiffEntry, DiffOp,
    PreviewDiagnostic, SideEffectHint, CODE_PREVIEW_CONFIG_INVALID, CODE_PREVIEW_PATCH_INVALID,
};
pub use proposal::{
    new_proposal_id, ConfigProposal, ProposalInput, ProposalRead, ProposalStore,
    ProposalStoreError, CODE_PROPOSAL_BASE_CHANGED, CODE_PROPOSAL_CAPACITY, CODE_PROPOSAL_EXPIRED,
    CODE_PROPOSAL_FOREIGN, CODE_PROPOSAL_ID_CLASH, CODE_PROPOSAL_INPUT_INVALID,
    CODE_PROPOSAL_SCOPE_INVALID, CODE_PROPOSAL_TTL_INVALID, CODE_PROPOSAL_UNKNOWN,
    PROPOSAL_MAX_TTL_MS, PROPOSAL_STORE_CAP,
};
pub use rollback::{
    rollback_apply, ConnectionTruth, DrainPlan, RollbackError, RollbackExecution, RollbackReport,
    RollbackRequest, CODE_ROLLBACK_CANDIDATE_MISMATCH, CODE_ROLLBACK_INPUT_INVALID,
    CODE_ROLLBACK_LIVE_MOVED, CODE_ROLLBACK_TARGET_FOREIGN, CODE_ROLLBACK_TARGET_NOT_APPLIED,
    CODE_ROLLBACK_TARGET_UNKNOWN, CONNECTION_TRUTH_STATEMENT,
};
pub use source::{
    derive_local_id, CompatibilityDiagnostic, ObjectCatalog, ObjectId, ObjectKind, ObjectRenamed,
    SnapshotDiff, SourceContractError, SourceId, SourceLocation, SourceObject, SourceSnapshot,
    CODE_COMPAT_LOSSY, CODE_COMPAT_UNSUPPORTED, CODE_SOURCE_ID_INVALID, CODE_SOURCE_MISMATCH,
};
pub use watchdog::{
    assess_management_risk, repair_guidance, ManagementAssessment, ManagementRisk,
    ManagementRiskKind, RecoveryPlan, ResumeOutcome, Watchdog, WatchdogError, WatchdogSnapshot,
    WatchdogVerdict, CODE_WATCHDOG_GENERATION_MISMATCH, CODE_WATCHDOG_INPUT_INVALID,
    CODE_WATCHDOG_LIVE_MOVED, CODE_WATCHDOG_NOT_DUE, CODE_WATCHDOG_TARGET_GONE,
    CODE_WATCHDOG_TARGET_UNKNOWN, CODE_WATCHDOG_VERIFY_MISMATCH, CODE_WATCHDOG_WINDOW_EXPIRED,
    CODE_WATCHDOG_WINDOW_INVALID, WATCHDOG_DEFAULT_WINDOW_MS, WATCHDOG_MAX_WINDOW_MS,
};

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

/// 各场景的参数面（RIL-017）：暂为空壳（展开产物即既有块缺省填充），
/// deny_unknown_fields 让拼错子字段立刻报错；场景专属参数后续在此扩展。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ScenarioOpts {}

/// 并列场景策略（RIL-017）：proxy/game/web **可同时声明**——旧
/// `profile` 单枚举的互斥控制就此废弃（新配置不得再由单枚举控制）。
/// 旧配置 `profile: <kind>` 仍可读（legacy 面，见 RillaneConfig::from_str
/// 迁移诊断）；两面同时声明解析期拒绝（迁移未完成，二选一）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ScenarioScopes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ScenarioOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game: Option<ScenarioOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<ScenarioOpts>,
}

impl ScenarioScopes {
    pub fn is_empty(&self) -> bool {
        self.proxy.is_none() && self.game.is_none() && self.web.is_none()
    }

    /// 已声明场景（稳定顺序 proxy → game → web）
    pub fn declared(&self) -> Vec<ProfileKind> {
        let mut out = Vec::new();
        if self.proxy.is_some() {
            out.push(ProfileKind::Proxy);
        }
        if self.game.is_some() {
            out.push(ProfileKind::Game);
        }
        if self.web.is_some() {
            out.push(ProfileKind::Web);
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RillaneConfig {
    /// 规范配置版本（RIL-001，contract 模块）：缺省 V1——旧配置无此字段
    /// 按 V1 适配；显式未知版本解析期稳定拒绝（`contract::CODE_UNKNOWN_VERSION`）
    #[serde(default)]
    pub version: ConfigVersion,
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
    /// 主动探测授权块（RIL-061，debug-and-mcp.md §3；缺省 None = 探测面
    /// 整体关闭——无授权无网络副作用，端点 503）。块只存在于操作员本地
    /// 配置：来源合并面是对象登记（SourceSnapshot.objects），顶层块结构上
    /// 不在合并面——订阅文本永远无法扩探测范围。
    #[serde(default)]
    pub probe: Option<ProbeConfigBlock>,
    /// 场景预设（P2-3 scenario-profiles.md §2-D1；缺省 None = 存量零差异；
    /// 仅 from_str 入口展开——订阅/程序化构造不触发，§5-1）。
    /// RIL-017 起为 legacy 面：与 `scenarios` 并列面互斥，解析期二选一。
    #[serde(default)]
    pub profile: Option<ProfileKind>,
    /// 并列场景策略（RIL-017；缺省空 = 全不声明，行为零差异）：
    /// proxy/game/web 可同时声明，展开产物与手写等价配置同链
    #[serde(default, skip_serializing_if = "ScenarioScopes::is_empty")]
    pub scenarios: ScenarioScopes,
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
    /// E1：非法值构建期报错（域约束对齐 rillane-core `set_relay_buffer`）。
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

/// network 区块（network-route.md §1.1/§1.5）：rillane-config 镜像 serde 类型，
/// 到 rillane-platform `NetworkConfig` 的转换在 rillane-runtime（§1.2 裁决：镜像而非加依赖，
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
    /// rillane 自身流量从 TUN include 路由拽回直连。缺省 None = 不打 mark
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
    /// 加 53 端口，见 rillane-runtime `dns_config.rs`；device 层透传
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

/// network 块 CIDR 解析（schema 层最小实现——rillane-config 不依赖 rillane-platform，
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
    /// 见 rillane-runtime `network_config.rs`（egress/mesh/control 地址集 R1 接线时并入）。
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
// 防污染 + 缓存 + 本地监听面。rillane-config 只镜像 serde 形（到引擎
// `ResolverConfig` 的转换在 rillane-runtime `dns_config.rs`，§1.2 裁决同
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

/// fake-ip 块（G1-10）：None = 关闭（存量零差异）。启用后本地 DNS 面对客户端
/// A 查询按池段稳定假地址应答；出站面按假地址反查原域名回填路由。仅 IPv4；
/// AAAA 查询照常走真实解析（应用若走 IPv6 即回到 IP 直连路由语义，不破流）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeIpConfig {
    /// 块在场缺省启用
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// fake-ip 池段（IPv4 CIDR；RFC 2544 基准段 198.18.0.0/15）
    #[serde(default = "default_fake_ip_range")]
    pub range: String,
}

fn default_fake_ip_range() -> String {
    "198.18.0.0/15".to_string()
}

impl FakeIpConfig {
    /// 值域构建期拦截：段须为合法 IPv4 CIDR 且前缀 1..=30（池 ≥4 地址）。
    /// 深检（前缀非法/地址非法/主机位未清零）在此报，构建失败浮出配置
    /// 加载面。
    pub fn validate(&self) -> Result<()> {
        let (ip_part, prefix_part) = self.range.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("network.dns.fake_ip.range 缺前缀长度:{:?}", self.range)
        })?;
        let ip: std::net::Ipv4Addr = ip_part
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("network.dns.fake_ip.range 地址须为 IPv4:{ip_part:?}"))?;
        let prefix: u32 = prefix_part.trim().parse().map_err(|_| {
            anyhow::anyhow!("network.dns.fake_ip.range 前缀须为数字:{prefix_part:?}")
        })?;
        anyhow::ensure!(
            (1..=30).contains(&prefix),
            "network.dns.fake_ip.range 前缀须在 1..=30（池至少 4 地址）:{:?}",
            self.range
        );
        let host_bits = 32 - prefix;
        let mask = u32::MAX << host_bits;
        anyhow::ensure!(
            u32::from(ip) & mask == u32::from(ip),
            "network.dns.fake_ip.range 地址含主机位（应写网络地址）:{:?}",
            self.range
        );
        Ok(())
    }
}

/// network.dns 块：两组上游 + 分流规则 + 防污染 + 缓存 + 本地监听。
/// 块在场缺省启用（与 obfuscation 的 enabled=false 缺省相反——DNS 监听是
/// 显式 opt-in 配置块，场即意图；false 供临时下线，容忍半配置）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsBlockConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// domestic 组上游列表；缺省（空）回落 `network.tun.dns_servers` 加 53
    /// 端口（回落落转换处——validate 只见本块，dns-partition.md §4-4）。
    /// 形式（G1-8）：`ip:port`（UDP）/ `tls://host[:port]`（DoT，缺省 853）/
    /// `https://url`（DoH）
    #[serde(default)]
    pub domestic: Vec<String>,
    /// trusted 组上游（形式同 domestic）；可信性由部署者保证（§10-R-dns1），
    /// 不设回落
    #[serde(default)]
    pub trusted: Vec<String>,
    /// DoT/DoH 上游证书校验开关；缺省 false = 校验（webpki 根）。
    /// 仅限内网/回环测试显式置 true——生产置 true 属部署者自担风险。
    #[serde(default)]
    pub tls_skip_verify: bool,
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
    /// fake-ip 块（G1-10）；None = 关闭（存量零差异）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_ip: Option<FakeIpConfig>,
    /// 静态 hosts 映射（G2-15）：域名 → IPv4/IPv6 字面量；本地 DNS 面
    /// A/AAAA 查询命中直接应答（真实映射地址，不触上游、不经 fake-ip）。
    /// 键精确匹配（小写归一，通配符不做）；None/空 = 关闭（存量零差异）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<std::collections::BTreeMap<String, String>>,
}

impl DnsBlockConfig {
    /// dns-partition.md §5-E1 构建期校验。domestic 空回落 tun.dns_servers 的
    /// 可满足性不在此判（validate 只见本块）——回落后仍空且被引用的拦截在
    /// rillane-runtime 转换处；enabled=false 首位短路容忍半配置（§2.5 口径）。
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for (group, servers) in [("domestic", &self.domestic), ("trusted", &self.trusted)] {
            for s in servers {
                // 三种形式（G1-8）：`ip:port`（UDP）/ `tls://host[:port]`（DoT）/
                // `https://url`（DoH）；此处只做形态校验，真正解析归引擎转换层
                let s_trim = s.trim();
                if let Some(rest) = s_trim.strip_prefix("https://") {
                    anyhow::ensure!(
                        !rest.trim().is_empty() && rest.trim() != "/",
                        "network.dns.{group} DoH 上游 URL 缺 host:{s:?}"
                    );
                    continue;
                }
                if let Some(rest) = s_trim
                    .strip_prefix("tls://")
                    .or_else(|| s_trim.strip_prefix("dot://"))
                {
                    let host = rest
                        .rsplit_once(':')
                        .filter(|(_, p)| p.parse::<u16>().is_ok())
                        .map_or(rest, |(h, _)| h);
                    anyhow::ensure!(
                        !host.is_empty(),
                        "network.dns.{group} DoT 上游缺 host:{s:?}"
                    );
                    if let Some((_, p)) = rest.rsplit_once(':') {
                        anyhow::ensure!(
                            p.parse::<u16>().map(|p| p != 0).unwrap_or(false),
                            "network.dns.{group} DoT 上游端口非法:{s:?}"
                        );
                    }
                    continue;
                }
                let addr: std::net::SocketAddr = s
                    .parse()
                    .with_context(|| {
                        format!("network.dns.{group} 上游须为 ip:port / tls://host:port / https://url 形式:{s:?}")
                    })?;
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
        if let Some(fake) = &self.fake_ip {
            if fake.enabled {
                fake.validate()?;
            }
        }
        if let Some(hosts) = &self.hosts {
            for (k, v) in hosts {
                anyhow::ensure!(!k.trim().is_empty(), "network.dns.hosts 键不能为空");
                anyhow::ensure!(
                    k.trim().parse::<std::net::IpAddr>().is_err(),
                    "network.dns.hosts 键须为域名而非 IP 地址：{k:?}"
                );
                anyhow::ensure!(
                    v.trim().parse::<std::net::IpAddr>().is_ok(),
                    "network.dns.hosts 值须为 IPv4/IPv6 字面量：{k:?} → {v:?}"
                );
            }
        }
        Ok(())
    }
}

/// obfuscation 区块（obfuscation-middleware.md §3.1）：rillane-config 镜像 serde 类型，
/// 到 `PaddingSpec`/中间件链的转换在 rillane-runtime（§3.2 裁决镜像而非加依赖，
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
    /// 每调用 fuel 指令预算（缺省 1e8，rillane-plugins::DEFAULT_PLUGIN_FUEL）
    #[serde(default)]
    pub fuel: Option<u64>,
}

fn default_obfs_middleware() -> Vec<String> {
    vec!["padding".to_string()]
}

impl ObfuscationConfig {
    /// §3.3 构建期校验（六条）。E5（apply_to 指向不存在 egress 名 → warning +
    /// 降级不生效）不在此处：validate 只见本块，egress 名集在调用侧，
    /// 落 rillane-runtime `to_padding_policy`（§6 E5）。
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
/// 校验（§3.3-4）。mode 字符串 → `PaddingMode` 枚举在 rillane-runtime 转换（§3.2）。
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
/// → `TimingMode` 枚举在 rillane-runtime 转换（对称 PaddingBlockConfig）。
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
/// `rillane.route.kind`（"chain"/"single"）与 `rillane.route.egress`（最终节点名）。
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

/// egress_pool 区块（egress-connection-pool.md §3.1）：rillane-config 镜像 serde
/// 类型，到 `PoolPolicy` 的转换在 rillane-runtime `to_pool_policy`（§3.2 裁决
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
    /// → warning 不 Err）不在此处：rillane-config 无 tracing 依赖（network E5
    /// 「warning 落转换处」先例），warning 落 rillane-runtime `to_pool_policy`。
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

/// 主动探测授权块（RIL-061，debug-and-mcp.md §3「Probe: active
/// verification」）：块存在 = 操作员显式授权探测面；targets 是闭合登记表
/// （无登记 = 无目标可探测）。untrusted 文本不授权内网扫描——本块只有
/// 本地配置一个入口（订阅/来源合并面是对象登记，顶层块结构上不可达）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfigBlock {
    /// 可探测目标逐条登记（缺省空 = 无目标；submit 对未登记目标以
    /// `probe.target.out_of_scope` 拒绝）
    #[serde(default)]
    pub targets: Vec<ProbeTargetSpec>,
    /// 限额覆盖（缺省 = 全部内核定值）
    #[serde(default)]
    pub limits: ProbeLimitsConfig,
}

impl ProbeConfigBlock {
    /// 构建期校验：目标字段非空、addr 形如合法 SocketAddr、限额为正——
    /// 非法值启动期拒绝，不带病装配探测授权。
    pub fn validate(&self) -> Result<()> {
        for (i, t) in self.targets.iter().enumerate() {
            match t {
                ProbeTargetSpec::Dns { host } => {
                    if host.trim().is_empty() {
                        anyhow::bail!("probe.targets[{i}] dns.host 不能为空");
                    }
                }
                ProbeTargetSpec::Connect { addr } | ProbeTargetSpec::UdpEcho { addr } => {
                    addr.parse::<std::net::SocketAddr>().map_err(|e| {
                        anyhow::anyhow!("probe.targets[{i}] addr 非法（{addr}）: {e}")
                    })?;
                }
            }
        }
        if let Some(n) = self.limits.max_active {
            if n == 0 {
                anyhow::bail!("probe.limits.max_active 须 ≥ 1（当前 0）");
            }
        }
        if let Some(ms) = self.limits.job_timeout_ms {
            if ms == 0 {
                anyhow::bail!("probe.limits.job_timeout_ms 须 ≥ 1（当前 0）");
            }
        }
        if let Some(n) = self.limits.udp_payload_max_bytes {
            if n == 0 {
                anyhow::bail!("probe.limits.udp_payload_max_bytes 须 ≥ 1（当前 0）");
            }
        }
        if let Some(n) = self.limits.byte_budget {
            if n == 0 {
                anyhow::bail!("probe.limits.byte_budget 须 ≥ 1（当前 0）");
            }
        }
        Ok(())
    }
}

/// 单条探测目标（显式类型标签——无自由文本变体，与内核 ProbeTarget
/// 闭合枚举同构；`addr` 为 `ip:port` 文本，validate() 里解析校验）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeTargetSpec {
    /// DNS 解析探测目标
    Dns { host: String },
    /// TCP connect 探测目标
    Connect { addr: String },
    /// UDP 回显探测目标（对端须具备回显能力——无回应按丢包如实报告）
    UdpEcho { addr: String },
}

/// 探测限额覆盖（全可选——None = 内核定值：并发 4 / 超时 5s /
/// UDP 载荷 512B / 预算 64KiB）
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeLimitsConfig {
    /// 同时运行作业上限（超额排队不丢弃）
    #[serde(default)]
    pub max_active: Option<usize>,
    /// 单作业超时（毫秒）
    #[serde(default)]
    pub job_timeout_ms: Option<u64>,
    /// UDP 回显载荷上限（字节）
    #[serde(default)]
    pub udp_payload_max_bytes: Option<usize>,
    /// 流量预算（字节；提交预留、完成按实耗双向结算）
    #[serde(default)]
    pub byte_budget: Option<u64>,
}

impl RillaneConfig {
    /// 版本字段合约错误探测（parse_any_format 用）：合法 YAML 且 version
    /// 值非法 → 返回携带稳定原因码的错误；其余情形返回 None。
    fn peek_version_error_probe(raw: &str) -> Option<anyhow::Error> {
        let value = serde_yaml::from_str::<serde_yaml::Value>(raw).ok()?;
        let ver = value.get("version")?;
        if let Some(text) = ver.as_str() {
            return contract::ConfigVersion::parse(text)
                .err()
                .map(anyhow::Error::msg);
        }
        if let Some(n) = ver.as_i64() {
            if n != 1 {
                return contract::ConfigVersion::parse(&n.to_string())
                    .err()
                    .map(anyhow::Error::msg);
            }
        }
        None
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件: {}", path.display()))?;
        let hint = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);
        // 迁移诊断（RIL-017）：config crate 不引 tracing，落 stderr 由
        // 调用方环境捕获（进程级配置装载一次性提示，非热路径）
        let (mut config, diagnostics) = Self::from_str_with_diagnostics(&raw, hint.as_deref())?;
        for note in &diagnostics {
            eprintln!("rillane-config warn ({}): {note}", path.display());
        }
        let base_dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
        if let Some(base_dir) = base_dir {
            config.routing.geoip_db = config
                .routing
                .geoip_db
                .map(|db| resolve_geo_db(&db, base_dir));
            config.routing.geosite_db = config
                .routing
                .geosite_db
                .map(|db| resolve_geo_db(&db, base_dir));
        }
        config.apply_profile();
        Ok(config)
    }

    pub fn from_str(raw: &str, hint: Option<&str>) -> Result<Self> {
        Ok(Self::from_str_with_diagnostics(raw, hint)?.0)
    }

    /// 带迁移诊断的解析入口（RIL-017）：旧 `profile` 单枚举可读，但返回
    /// 迁移提示（迁移到 `scenarios` 并列面——game/web 可同时声明）；
    /// 两面同时声明解析期拒绝（迁移未完成，二选一）。`from_str` 丢弃
    /// 诊断保持兼容；`load_from_path` 会把诊断打到 tracing warn。
    pub fn from_str_with_diagnostics(raw: &str, hint: Option<&str>) -> Result<(Self, Vec<String>)> {
        let mut config = Self::from_str_without_profile(raw, hint)?;
        let mut diagnostics = Vec::new();
        if config.profile.is_some() && !config.scenarios.is_empty() {
            anyhow::bail!(
                "profile 与 scenarios 同时声明（迁移未完成）：旧 profile 单枚举与新并列场景面二选一——请把 profile: <kind> 迁移为 scenarios: {{ <kind>: {{}} }}"
            );
        }
        if config.profile.is_some() {
            diagnostics.push(
                "配置使用了旧 profile 单枚举（proxy/game/web 互斥）；建议迁移到 scenarios 并列面（proxy/game/web 可同时声明）".to_string(),
            );
        }
        // RIL-061：探测授权块构建期校验——非法目标/限额启动期拒绝，
        // 不带病装配（块缺席 = 探测面整体关闭，无校验面）
        if let Some(probe) = &config.probe {
            probe.validate()?;
        }
        config.apply_profile();
        Ok((config, diagnostics))
    }

    fn from_str_without_profile(raw: &str, hint: Option<&str>) -> Result<Self> {
        let config: Self = match hint {
            Some("json") => serde_json::from_str(raw).context("JSON 配置解析失败")?,
            Some("toml") => toml::from_str(raw).context("TOML 配置解析失败")?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(raw).context("YAML 配置解析失败")?,
            _ => Self::parse_any_format(raw)?,
        };
        Ok(config)
    }

    /// 无格式提示的自动检测：YAML → JSON → TOML 依次尝试。全败时若内容
    /// 是合法 YAML 且 version 值非法，优先透出合约稳定原因码
    /// （`config.version.unknown`），不让三格式回退链把它埋成
    /// 「无法识别配置格式」（RIL-001 验收：未知版本产生稳定原因码）。
    fn parse_any_format(raw: &str) -> Result<Self> {
        serde_yaml::from_str(raw)
            .or_else(|_| serde_json::from_str(raw))
            .or_else(|_| toml::from_str(raw))
            .map_err(|_| {
                Self::peek_version_error_probe(raw)
                    .unwrap_or_else(|| anyhow::anyhow!("无法识别配置格式"))
            })
    }

    /// 场景预设展开（scenario-profiles.md §2-D2/D4）：**缺省填充，显式恒
    /// 优先**——只往「未指定」位（groups/rules 空、obfuscation/egress_pool
    /// None）填预设，不覆盖不删除，天然幂等（§6-E4：填过即非空，再展开
    /// 为 no-op）。规则模板与组模板同生共死：组非空（用户自组在场）时
    /// 不填规则——模板 target 指向组模板名，用户自组名不可猜测（§6-E6）。
    pub fn apply_profile(&mut self) {
        // RIL-017：并列面在场时按场景逐个展开（多场景共存：各填各的
        // 模板组/规则，按名守卫互不挤占）；legacy 单枚举走原语义路径
        let scopes = self.scenarios.clone();
        if !scopes.is_empty() {
            for kind in scopes.declared() {
                self.apply_scenario(kind);
            }
            return;
        }
        let Some(kind) = self.profile else {
            return;
        };
        self.apply_legacy_profile(kind);
    }

    /// legacy `profile` 单枚举展开（原 apply_profile 主体，语义原样——
    /// 存量配置零差异）：groups 非空（用户自组在场）即整体退让不填模板。
    fn apply_legacy_profile(&mut self, kind: ProfileKind) {
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
                url_test: None,
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

    /// 并列场景展开（RIL-017）：按**模板组名**守卫而非「groups 全空」守卫
    /// ——多场景共存时各填各的模板组/规则（game-auto 与 web-auto 并立），
    /// 互不挤占；用户自建同名组在场即视为显式声明，模板退让（显式恒
    /// 优先）。场景间规则按 target 归属（模板规则 target 指向本场景组名），
    /// 天然幂等。
    fn apply_scenario(&mut self, kind: ProfileKind) {
        let (group_name, slo) = match kind {
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
        let group_absent = !self.routing.groups.iter().any(|g| g.name == group_name);
        if group_absent {
            self.routing.groups.push(PolicyGroup {
                name: group_name.to_string(),
                strategy: Strategy::Latency,
                members: vec![GroupMember::Node {
                    name: self.routing.default_node.clone(),
                }],
                slo,
                url_test: None,
            });
            // 规则模板与组模板同生共死：组是本次新建且同名 target 规则
            // 缺席才填（多场景各自带自己的规则集，target 各指各组）
            if !self.routing.rules.iter().any(|r| r.target == group_name) {
                let template_rules = match kind {
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
                self.routing.rules.extend(template_rules);
            }
        }
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
        if kind == ProfileKind::Web && self.egress_pool.is_none() {
            self.egress_pool = Some(EgressPoolBlock {
                enabled: true,
                ..EgressPoolBlock::default()
            });
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        PathBuf::from("/etc/rillane")
    }
}

/// GeoIP/GeoSite 数据库路径解析（load_from_path 专属）：相对路径 join 配
/// 置文件目录并归一化（`..`/`.` 逐段消解，保留根路径），绝对路径原样返回。
fn resolve_geo_db(db: &Path, base_dir: &Path) -> PathBuf {
    if db.is_absolute() {
        return db.to_path_buf();
    }
    let mut parts: Vec<std::path::Component> = Vec::new();
    for comp in base_dir.components().chain(db.components()) {
        match comp {
            std::path::Component::ParentDir => {
                if parts.last() == Some(&std::path::Component::RootDir) {
                    // 越出配置目录深度时钳制在根：`..` 不再弹出根、不累积。
                } else if let Some(std::path::Component::Normal(_)) = parts.last() {
                    parts.pop();
                } else {
                    // 相对配置目录越界时保留前导 `..`，不能静默丢弃上级路径。
                    parts.push(comp);
                }
            }
            std::path::Component::CurDir => {}
            other => parts.push(other),
        }
    }
    parts.into_iter().collect()
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

/// proxy/web 预设 cn 规则（同 config/rillane.yaml 基线形：geoip CN → 场景组）
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
    /// Shadowsocks 入口（RIL-134）：复用 shadowsocks crate server 面
    /// （ProxyListener TCP + ProxySocket Server 数据报，见两语
    /// protocol-backends.md shadowsocks 服务端面评估）。method/password
    /// 校验与 egress 同口径（none/未编译面点名拒绝、SS2022 base64 密钥
    /// 形状），拒绝落在装配期（RuntimeBuilder 构造 `ShadowsocksIngress`
    /// 即校验）。SIP003 插件服务端面未交付——IR 不留字段。
    Shadowsocks {
        bind: String,
        /// 加密方法（同 egress shadowsocks 编译面口径）
        method: String,
        /// 预共享密码（v1 AEAD 任意串；SS2022 为 base64 密钥）
        password: String,
        /// per-ingress UDP 覆盖（语义同 Socks5）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 UDP 数据报面。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
    /// Trojan 入口（RIL-135）：自写 server 面（评估见两语
    /// protocol-backends.md trojan 服务端面段——crates.io 全谱系 GPL-3.0-only
    /// 与本仓 Apache-2.0 不兼容，且 trojan-server 为整装 run 循环不可组合）。
    /// TLS 材料随 IR 内联（PEM），装配期解析（错误启动时暴露）。UDP 关联面
    /// 随 `udp.enabled`/`udp_enabled` 门。
    Trojan {
        bind: String,
        /// 预共享密码（任意非空串；服务端比对 SHA224 hex，恒时）
        password: String,
        /// 证书链 PEM（含叶起全链；自签测试夹具 rcgen）
        cert: String,
        /// 私钥 PEM
        cert_key: String,
        /// per-ingress UDP 覆盖（语义同 Socks5）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 UDP 关联面。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
    /// VLESS 入口（RIL-136）：自写 server 面（评估见两语
    /// protocol-backends.md vless 服务端面段——xray-rs 有可组合形状 Handler
    /// 但单包无特性门拖全内核；meow-proxy 仅出口面；jets 无 VLESS 入站）。
    /// TLS 材料随 IR 内联（PEM），装配期解析（错误启动时暴露）；uuid 装配期
    /// 校验。UDP 关联面随 `udp.enabled`/`udp_enabled` 门。Vision/REALITY
    /// 服务端组合另验，不留字段。
    Vless {
        bind: String,
        /// 认证 UUID（标准形；服务端 16 字节恒时比对）
        uuid: String,
        /// 证书链 PEM（含叶起全链；自签测试夹具 rcgen）
        cert: String,
        /// 私钥 PEM
        cert_key: String,
        /// per-ingress UDP 覆盖（语义同 Socks5）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 UDP 关联面。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
    /// VMess 入口（RIL-137）：自写 server 面（评估见两语
    /// protocol-backends.md vmess 服务端面段——vmess-rs 为零依赖空壳；
    /// tobira AGPL 且 binary-only 拖应用内核）。裸 TCP 承载——VMess AEAD
    /// 封头即认证面，无 TLS 字段；AEAD/alter_id=0 口径，security 由客户端
    /// 自选（0x03/0x04），不留旋钮。uuid 装配期校验。UDP 关联面随
    /// `udp.enabled`/`udp_enabled` 门。
    Vmess {
        bind: String,
        /// 认证 UUID（标准形；cmdKey = MD5(uuid ‖ 常量) 派生）
        uuid: String,
        /// per-ingress UDP 覆盖（语义同 Socks5）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 UDP 关联面。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
    /// Hysteria2 入口（RIL-138）：自写 server 面（评估见两语
    /// protocol-backends.md hysteria2 服务端面段——hysteria2/rsteria2 均
    /// 无服务端面；crapthings/hysteria-rust 有 server face 但 publish=false
    /// 不可审计 + rc 级 + MSRV 耦合，沿前判拒绝）。QUIC 端点即监听面——
    /// TLS 材料随 IR 内联（PEM），装配期解析（错误启动时暴露），ALPN 恒
    /// h3；口令恒时比对。obfs/masquerade/ACME/Brutal 不交付不留字段。
    /// UDP 关联面随 `udp.enabled`/`udp_enabled` 门。
    Hysteria2 {
        bind: String,
        /// 预共享口令（任意非空串；服务端恒时比对）
        password: String,
        /// 证书链 PEM（含叶起全链；自签测试夹具 rcgen）
        cert: String,
        /// 私钥 PEM
        cert_key: String,
        /// per-ingress UDP 覆盖（语义同 Socks5）：None 继承 `udp.enabled`，
        /// Some 显式开/关该入口的 UDP 关联面。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_enabled: Option<bool>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

/// REALITY 出站选项（G1-6）：XTLS/Xray REALITY 伪装 TLS 的客户端参数。
/// 仅承载配置（serde 保留键不再静默丢弃）；拨号期由 VLESS 连接器点名
/// 拒绝（rustls 无 ClientHello 字节级控制，见设计文档 §4.3 栈决策）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealityConfig {
    /// 服务端 REALITY 公钥（x25519；Clash `reality-opts.public-key`）
    #[serde(alias = "public-key")]
    pub public_key: String,
    /// short-id（服务端允许列表内的认证标识；可空）
    #[serde(alias = "short-id", skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
}

/// gRPC gun 流复用旋钮（RIL-130，订阅 grpc-opts 键位 max-connections/
/// min-streams/max-streams；mihomo gun.NewClient 口径）：三键全缺 = 单
/// 连接全复用（复用恒开——gun 线格式不变，每流仍是 POST /{service}/Tun）；
/// max-connections>0 = 连接数上限（每连接先填到 min-streams 再另开）；
/// max-connections 缺席且 max-streams>0 = 单连接流数上限。仅 network=grpc
/// 消费——其余传输面携带即构建期具名拒绝
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GrpcReuseConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_streams: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,
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
        /// gRPC gun 流复用旋钮（RIL-130；仅 network=grpc 消费）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grpc_reuse: Option<GrpcReuseConfig>,
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
        /// REALITY 选项（G1-6）：Some = REALITY 节点（配置保留，拨号期
        /// 点名拒绝——rustls 无 ClientHello 字节级控制，防静默降级）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<RealityConfig>,
        #[serde(default = "default_network")]
        network: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<Vec<String>>,
        /// gRPC 服务名（network=grpc 时必填；线上路径 = /{name}/Tun）
        #[serde(skip_serializing_if = "Option::is_none")]
        grpc_service_name: Option<String>,
        /// gRPC gun 流复用旋钮（RIL-130；仅 network=grpc 消费）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grpc_reuse: Option<GrpcReuseConfig>,
        /// XHTTP 模式（RIL-129，network=xhttp 时有效）：`auto`（缺省，判为
        /// packet-up）/ `packet-up` / `stream-one`；其余取值拨号期具名拒绝
        #[serde(default, skip_serializing_if = "Option::is_none")]
        xhttp_mode: Option<String>,
        /// vless UDP 包编码（RIL-130，UDP 面）：缺省 raw（Xray 原生
        /// [2B 长度] 分帧、命令 0x02 单目标）；`xudp`（命令 0x03 + XUDP 帧，
        /// 逐报寻址）/ `packetaddr`（命令 0x02 + magic 地址，逐报寻址）；
        /// 其余取值构建期具名拒绝
        #[serde(default, skip_serializing_if = "Option::is_none")]
        packet_encoding: Option<String>,
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
        /// gRPC gun 流复用旋钮（RIL-130；仅 network=grpc 消费）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grpc_reuse: Option<GrpcReuseConfig>,
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
    /// AnyTLS 出口（RIL-106）：TLS 承载的会话复用代理（缓解 TLS-in-TLS
    /// 指纹）。TLS 拨号在本仓（skip_cert_verify/sni 可组合），会话帧/
    /// 多路复用/填充由 anytls 库承载；UDP 为 UDP-over-TCP（UoT）面。
    Anytls {
        server: String,
        port: u16,
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(default)]
        skip_cert_verify: bool,
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
    Tuic {
        server: String,
        port: u16,
        /// TUIC v5 客户端 UUID（16 字节；拨号期解析，非法值具名拒绝）
        uuid: String,
        password: String,
        /// QUIC 拥塞控制：`cubic`（缺省，quinn 缺省载体）/ `bbr` / `new_reno`
        /// ——非 cubic 拨号期具名拒绝（RIL-105 自写面仅 cubic，不静默降级）
        #[serde(skip_serializing_if = "Option::is_none")]
        congestion_controller: Option<String>,
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
    /// GeoIP 数据库文件（MaxMind DB `.mmdb`，GeoLite2/GeoIP2 Country）。
    /// G0-2：路径缺省 None = 无数据库，`Geoip` 条件恒不命中（与原「注解
    /// 等价物」行为一致）；文件存在但解析失败在首次匹配时 WARN 并保持未
    /// 加载（fail-open）。相对路径按配置文件所在目录解析（见 load）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip_db: Option<PathBuf>,
    /// GeoSite 数据库文件（v2fly `.dat`，protobuf）。语义同 `geoip_db`：
    /// None = 无数据库，`GeoSite` 条件恒不命中。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite_db: Option<PathBuf>,
    /// rule-provider 声明（RIL-014）：RULE-SET 引用的规则集来源元数据
    /// （behavior/format/url/path/interval）。载荷获取与生命周期归
    /// RIL-010；此处仅声明面，供引用追踪与下载器配置。键 = 规则集名。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_providers: BTreeMap<String, RuleProviderDecl>,
    /// 命名规则集库（RIL-014）：`RuleSetRef` 条件的解析结果面。载荷未
    /// 装入时引用恒不命中（与 GeoSite 缺库同语义）；控制面随快照刷新
    /// 重装，热更随 `RoutingConfig` 整体替换。
    #[serde(default, skip_serializing_if = "RuleSetLibrary::is_empty")]
    pub rule_sets: RuleSetLibrary,
    /// proxy-provider 声明（RIL-009）：远端/本地节点目录的来源元数据
    /// （type/url/path/interval/health-check）。引用可追踪：组内 `use:`
    /// 引用须指向已声明的 provider。载荷下载与更新生命周期归 RIL-010；
    /// 此处仅声明面，供引用追踪与下载器配置。键 = provider 名。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proxy_providers: BTreeMap<String, ProxyProviderDecl>,
    /// 命名 provider 节点库（RIL-009）：`GroupMember::Provider` 的解析
    /// 结果面——`provider 名 → 当前提供的出口节点名列表`。载荷未装入或
    /// 来源失效时该名为空集：失效成员退出新流候选（不伪装成有成员），
    /// 与 `RuleSetRef` 缺库恒不命中同语义。控制面随快照刷新重装，热更
    /// 随 `RoutingConfig` 整体替换。
    #[serde(default, skip_serializing_if = "ProviderNodeLibrary::is_empty")]
    pub provider_nodes: ProviderNodeLibrary,
    /// 用户选择面（RIL-011 select 保真）：组名 → 选中的成员名（节点或
    /// 嵌套组）。`Strategy::Fixed` 求值时优先命中：所选成员仍在组的成员
    /// 集（含不健康）则尊重手动点选；所选成员被更新/删除移除则走明确
    /// 恢复策略（清除选择、回落首健康成员、回落原因显式）。这是用户
    /// 运行态——配置更新**不得随意清空**仍有效的选择（引擎 reload 时
    /// 并集合并）。空面不落盘。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub selections: BTreeMap<String, String>,
    /// 并列场景面（RIL-021）：game/web/general 等场景的路由期求值——
    /// 条件合取（AND 全中）即命中，命中场景的 `target` 即决策入口。
    /// 优先级数值小者先评估（同优先级按声明序稳定）；场景面先于规则
    /// 面（声明的场景意图压过泛化规则）。失败动作：目标组不可用时
    /// `fallback` = 落回规则面继续评估，`reject` = 显式拒绝。空面不落盘。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scenarios: Vec<ScenarioRule>,
}

/// 场景失败动作（RIL-021）：场景命中但目标不可用（组无健康成员等
/// 解析/前置失败）时的处置——执行面拨号失败的排空重试归 RIL-022 消费。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioFailureAction {
    /// 回落规则面（场景不命中同路径继续评估；默认动作）
    #[default]
    Fallback,
    /// 显式拒绝（错误上抛点名场景与原因，不悄悄改道）
    Reject,
}

/// 场景规则（RIL-021）：并列场景求值的声明面。
///
/// - **条件**：[`MatchCondition`] 合取（AND 全中才算本场景），复用规则
///   匹配面（process/proto/domain/… 同一语义）；空条件 = 无条件命中
///   （general 兜底场景，应配最低优先级放最后）；
/// - **优先级**：数值小者先评估，同优先级按声明序（稳定排序不重排）；
/// - **目标**：组名或直连节点名（与规则 target 同口径）；
/// - **失败动作**：见 [`ScenarioFailureAction`]。
///
/// 验收锚点：同目标的不同本机应用按 process 条件选不同组；QUIC 按
/// proto 字面归类（`quic` ≠ `udp`）——游戏场景 `proto: [udp]` 不会把
/// 浏览器 QUIC 流量并进去。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioRule {
    /// 场景名（决策 reason 与诊断面可读标识）
    pub name: String,
    /// 条件合取（AND 全中）；空 = 无条件命中（兜底场景）
    #[serde(default)]
    pub conditions: Vec<MatchCondition>,
    /// 目标组/直连节点名
    pub target: String,
    /// 优先级：数值小者先评估；缺省 100
    #[serde(default = "default_scenario_priority")]
    pub priority: i64,
    /// 失败动作（目标不可用时）；缺省 fallback
    #[serde(default)]
    pub on_failure: ScenarioFailureAction,
}

fn default_scenario_priority() -> i64 {
    100
}

/// rule-provider 声明（RIL-014）：一个 RULE-SET 规则集的来源元数据。
/// behavior 决定载荷行的语义域（domain/ipcidr/classical）——导入链按
/// behavior 校验载荷条件类型，不静默混用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleProviderDecl {
    /// 来源类型：`http`（远端）/ `file`（本地路径）
    #[serde(rename = "type")]
    pub provider_type: String,
    /// 语义域：`domain` / `ipcidr` / `classical`
    pub behavior: String,
    /// 载荷格式：`yaml`（payload: 列表）/ `text`（每行一条规则）；缺省 yaml
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// 远端 URL（type=http 必有；凭证不得出现在 URL 查询串——RIL-010 口径）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 本地路径（type=file 必有）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 更新周期（秒）；None = 不自动更新
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_node: "direct".to_string(),
            scenarios: Vec::new(),
            groups: Vec::new(),
            rules: Vec::new(),
            geoip_db: None,
            geosite_db: None,
            rule_providers: BTreeMap::new(),
            rule_sets: RuleSetLibrary::default(),
            proxy_providers: BTreeMap::new(),
            provider_nodes: ProviderNodeLibrary::default(),
            selections: BTreeMap::new(),
        }
    }
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
            if let Some(url_test) = &group.url_test {
                url_test.validate(&group.name)?;
            }
        }
        // G0-2 域名正则构建期校验（审核发现 2026-11-04）：非法或不支持的
        // 正则若不在构建期拦截，匹配面会吞掉编译错误回落默认路由，使拦截
        // 或代理规则静默失效。此处逐条编译验证，报错含规则名与 pattern。
        for rule in &self.rules {
            for cond in &rule.matches {
                validate_condition_regex(cond, &rule.name)?;
            }
        }
        // RIL-009：provider 成员引用须已声明（悬空引用会让组静默少成员）
        for group in &self.groups {
            for member in &group.members {
                if let GroupMember::Provider { name } = member {
                    anyhow::ensure!(
                        self.proxy_providers.contains_key(name),
                        "组 {} 引用了未声明的 provider `{name}`",
                        group.name
                    );
                }
            }
        }
        // RIL-011：组循环拒绝（嵌套组引用 A→B→A 会让运行时解析/选择无限
        // 递归——构建期点名拒绝循环路径），同遍历拒绝**悬空组引用**（引用
        // 未声明组 = 导入链 bug，静默少成员）；加权组引用同组引用对待。
        {
            // 邻接表：组名 → 它引用的组名集合
            let mut refs: std::collections::BTreeMap<&str, Vec<&str>> =
                std::collections::BTreeMap::new();
            for group in &self.groups {
                let mut outs = Vec::new();
                for member in &group.members {
                    match member {
                        GroupMember::Group { name } | GroupMember::WeightedGroup { name, .. } => {
                            anyhow::ensure!(
                                self.groups.iter().any(|g| &g.name == name),
                                "组 {} 引用了未声明的组 `{name}`",
                                group.name
                            );
                            outs.push(name.as_str());
                        }
                        _ => {}
                    }
                }
                refs.insert(group.name.as_str(), outs);
            }
            // 三色迭代 DFS：phase-1 弹出 = 收尾（标黑 + 退路径）；
            // phase-0 弹出仅白节点处理（去重，重复条目直接丢弃）。
            // gray 邻居 = 回边 = 环，报错带完整环路径。
            const GRAY: u8 = 0;
            const BLACK: u8 = 1;
            let mut color: std::collections::HashMap<&str, u8> = std::collections::HashMap::new();
            let mut path: Vec<&str> = Vec::new();
            for root in refs.keys() {
                if color.contains_key(root) {
                    continue;
                }
                let mut stack = vec![(*root, 0usize)];
                while let Some((node, phase)) = stack.pop() {
                    if phase == 1 {
                        color.insert(node, BLACK);
                        path.pop();
                        continue;
                    }
                    if color.contains_key(node) {
                        continue; // 已入路径或已完成：重复条目
                    }
                    color.insert(node, GRAY);
                    path.push(node);
                    stack.push((node, 1));
                    for next in &refs[node] {
                        match color.get(next) {
                            Some(&GRAY) => {
                                // 回边：路径上从 next 到栈顶即环（闭合回 next）
                                let start = path.iter().position(|n| n == next).unwrap_or(0);
                                let cycle = path[start..].join(" → ");
                                anyhow::bail!("组循环: {cycle} → {next}");
                            }
                            Some(&BLACK) | Some(&(2u8..=u8::MAX)) => {}
                            None => stack.push((*next, 0)),
                        }
                    }
                }
            }
        }
        // RIL-011：用户选择的组须已声明（组名打错 = 永不生效的选择面）；
        // 值（成员名）不做构建期校验——provider 展开节点构建期不可知，
        // 悬空值由引擎求值期恢复策略处理。
        for group in self.selections.keys() {
            anyhow::ensure!(
                self.groups.iter().any(|g| &g.name == group),
                "选择面引用了未声明的组 `{group}`"
            );
        }
        // RIL-014：RuleSetRef 引用名非空（空名是导入链 bug，不是合法配置；
        // 引用是否存在载荷不做构建期拒绝——载荷随 RIL-010 异步装入，缺席
        // 为文档化恒不命中）。
        for rule in &self.rules {
            let mut stack: Vec<&MatchCondition> = rule.matches.iter().collect();
            while let Some(cond) = stack.pop() {
                match cond {
                    MatchCondition::Any { conditions } => {
                        stack.extend(conditions.iter());
                    }
                    MatchCondition::Not { condition } => stack.push(condition),
                    MatchCondition::RuleSetRef { name } => {
                        anyhow::ensure!(
                            !name.trim().is_empty(),
                            "规则 {} 的规则集引用名为空",
                            rule.name
                        );
                    }
                    _ => {}
                }
            }
        }
        // RIL-021：场景面构建期校验——name/target 非空（空 = 导入链 bug，
        // 不是合法配置）；条件正则逐条编译验证（与规则面同口径，非法正则
        // 不得吞成默认路由）。target 是否已声明组不拒绝——直连节点名是
        // 合法 target（与规则面同口径），组存在性由求值面处理。
        for scenario in &self.scenarios {
            anyhow::ensure!(!scenario.name.trim().is_empty(), "场景名不得为空");
            anyhow::ensure!(
                !scenario.target.trim().is_empty(),
                "场景 {} 的 target 不得为空",
                scenario.name
            );
            for cond in &scenario.conditions {
                validate_condition_regex(cond, &format!("scenario:{}", scenario.name))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod geo_db_tests {
    use super::*;

    fn base_yaml() -> &'static str {
        "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n"
    }

    #[test]
    fn routing_geo_db_fields_parse_and_serialize() {
        let yaml = "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n  geoip_db: /data/geoip.mmdb\n  geosite_db: /data/geosite.dat\n";
        let cfg: RillaneConfig = serde_yaml::from_str(yaml).expect("应解析");
        assert_eq!(
            cfg.routing.geoip_db.as_deref(),
            Some(std::path::Path::new("/data/geoip.mmdb"))
        );
        assert_eq!(
            cfg.routing.geosite_db.as_deref(),
            Some(std::path::Path::new("/data/geosite.dat"))
        );
        let rendered = serde_yaml::to_string(&cfg).unwrap();
        let reparsed: RillaneConfig = serde_yaml::from_str(&rendered).unwrap();
        assert_eq!(reparsed.routing.geoip_db, cfg.routing.geoip_db);
        assert_eq!(reparsed.routing.geosite_db, cfg.routing.geosite_db);
    }

    /// RIL-014：源端口/协议/规则集引用条件与声明面、规则集库的 serde
    /// 往返——标签 snake_case（src_port/rule_set_ref/proto），库平铺为
    /// 名字→条件映射；空库/空声明不落盘（skip_serializing_if）。
    #[test]
    fn ruleset_and_port_conditions_roundtrip() {
        let yaml = "default_node: direct\n\
             groups: []\n\
             rules:\n\
             \x20 - name: r1\n\
             \x20   matches:\n\
             \x20     - type: src_port\n\
             \x20       values: [80, 443]\n\
             \x20     - type: proto\n\
             \x20       protocols: [TCP]\n\
             \x20     - type: rule_set_ref\n\
             \x20       name: ads\n\
             \x20   target: proxy\n\
             rule_providers:\n\
             \x20 ads:\n\
             \x20   type: http\n\
             \x20   behavior: domain\n\
             \x20   url: https://x.invalid/a.yaml\n\
             \x20   interval_secs: 86400\n\
             rule_sets:\n\
             \x20 ads:\n\
             \x20   conditions:\n\
             \x20     - type: domain_suffix\n\
             \x20       values: [ads.example]\n";
        let cfg: RoutingConfig = serde_yaml::from_str(yaml).expect("应解析");
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(
            cfg.rules[0].matches[0],
            MatchCondition::SrcPort {
                values: vec![80, 443]
            }
        );
        assert_eq!(
            cfg.rules[0].matches[1],
            MatchCondition::Proto {
                protocols: vec!["TCP".to_string()]
            }
        );
        assert_eq!(
            cfg.rules[0].matches[2],
            MatchCondition::RuleSetRef {
                name: "ads".to_string()
            }
        );
        let decl = cfg.rule_providers.get("ads").expect("声明解析");
        assert_eq!(decl.interval_secs, Some(86400));
        assert_eq!(decl.provider_type, "http");
        let entry = cfg.rule_sets.get("ads").expect("库载荷解析");
        assert_eq!(
            entry.conditions[0],
            MatchCondition::DomainSuffix {
                values: vec!["ads.example".to_string()]
            }
        );

        // 往返：序列化再解析语义不变（逐字段——RoutingConfig 未派生整体相等）
        let text = serde_yaml::to_string(&cfg).expect("序列化");
        let back: RoutingConfig = serde_yaml::from_str(&text).expect("往返解析");
        assert_eq!(back.rules, cfg.rules, "规则面往返语义不变");
        assert_eq!(back.rule_providers.len(), 1);
        assert_eq!(
            back.rule_providers.get("ads").map(|d| d.interval_secs),
            Some(Some(86400))
        );
        assert_eq!(
            back.rule_sets.get("ads").map(|e| e.conditions.clone()),
            Some(cfg.rule_sets.get("ads").expect("库非空").conditions.clone())
        );
        // 空库/空声明不落盘
        let empty = RoutingConfig::default();
        let empty_text = serde_yaml::to_string(&empty).expect("序列化");
        assert!(
            !empty_text.contains("rule_sets:") && !empty_text.contains("rule_providers:"),
            "空面不落盘: {empty_text}"
        );
    }

    /// RIL-009：proxy-provider 声明、provider 成员、provider 节点库的
    /// serde 往返——声明 interval 秒口径原样、库平铺为 名字→节点集；空面
    /// 不落盘。悬空 provider 引用由 `RoutingConfig::validate` 构建期拦截。
    #[test]
    fn proxy_provider_and_member_roundtrip() {
        let yaml = r#"
default_node: direct
groups:
  - name: pgroup
    strategy: fixed
    members:
      - { type: provider, name: remote }
rules: []
proxy_providers:
  remote:
    type: http
    url: https://provider.example.com/sub.yaml
    interval_secs: 3600
    health_check:
      enable: true
      interval_secs: 300
provider_nodes:
  remote:
    nodes: [node-a]
"#;
        let mut cfg: RoutingConfig = serde_yaml::from_str(yaml).expect("应解析");
        let decl = cfg.proxy_providers.get("remote").expect("provider 声明");
        assert_eq!(decl.provider_type, "http");
        assert_eq!(decl.interval_secs, Some(3600), "interval 秒口径原样");
        assert_eq!(
            decl.health_check.as_ref().and_then(|h| h.interval_secs),
            Some(300),
            "health-check 周期须保留"
        );
        assert_eq!(
            cfg.groups[0].members,
            vec![GroupMember::Provider {
                name: "remote".to_string()
            }]
        );
        assert_eq!(
            cfg.provider_nodes.nodes("remote"),
            vec!["node-a".to_string()]
        );

        // 往返：序列化再解析语义不变（须在清空声明前）
        let text = serde_yaml::to_string(&cfg).expect("序列化");
        let back: RoutingConfig = serde_yaml::from_str(&text).expect("往返解析");
        assert_eq!(
            back.proxy_providers
                .get("remote")
                .and_then(|d| d.interval_secs),
            Some(3600),
            "声明 interval 往返语义不变"
        );
        assert_eq!(
            back.groups[0].members, cfg.groups[0].members,
            "provider 成员往返语义不变"
        );
        assert_eq!(
            back.provider_nodes.nodes("remote"),
            cfg.provider_nodes.nodes("remote"),
            "节点库往返语义不变"
        );

        // 引用已声明 → 校验通过；清空声明 → 悬空引用构建期点名拦截
        cfg.validate().expect("已声明引用应通过校验");
        cfg.proxy_providers.clear();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("remote"), "悬空引用须点名: {err}");

        // 空面不落盘
        let empty_text = serde_yaml::to_string(&RoutingConfig::default()).expect("序列化");
        assert!(
            !empty_text.contains("proxy_providers:") && !empty_text.contains("provider_nodes:"),
            "空面不落盘: {empty_text}"
        );
    }
    /// RIL-011：组循环构建期点名拒绝（A→B→A、自环 A→A、以及经加权组
    /// 的环）；悬空组引用同遍历拒绝；合法链（A→B→节点）放行。
    #[test]
    fn group_cycles_and_dangling_refs_rejected() {
        let yaml = |groups: &str| {
            format!(
                r#"
default_node: direct
groups:
{groups}
rules: []
"#
            )
        };
        // 二元环
        let cfg: RoutingConfig = serde_yaml::from_str(&yaml(
            "  - name: a
    strategy: fixed
    members: [{ type: group, name: b }]
  - name: b
    strategy: fixed
    members: [{ type: group, name: a }]",
        ))
        .expect("应解析");
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("组循环"), "{err}");
        assert!(
            err.contains('a') && err.contains('b'),
            "环路径须点名: {err}"
        );

        // 自环
        let cfg: RoutingConfig = serde_yaml::from_str(&yaml(
            "  - name: a
    strategy: fixed
    members: [{ type: group, name: a }]",
        ))
        .expect("应解析");
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("组循环") && err.contains("a → a"), "{err}");

        // 经加权组的环（WeightedGroup 同样参与图）
        let cfg: RoutingConfig = serde_yaml::from_str(&yaml(
            "  - name: a
    strategy: fixed
    members: [{ type: weighted_group, name: b, weight: 2 }]
  - name: b
    strategy: fixed
    members: [{ type: group, name: a }]",
        ))
        .expect("应解析");
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("组循环"), "加权组环须被拒: {err}");

        // 悬空组引用
        let cfg: RoutingConfig = serde_yaml::from_str(&yaml(
            "  - name: a
    strategy: fixed
    members: [{ type: group, name: ghost }]",
        ))
        .expect("应解析");
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("未声明的组") && err.contains("ghost"), "{err}");

        // 合法链放行
        let cfg: RoutingConfig = serde_yaml::from_str(&yaml(
            "  - name: a
    strategy: fixed
    members: [{ type: group, name: b }]
  - name: b
    strategy: fixed
    members: [n1]",
        ))
        .expect("应解析");
        cfg.validate().expect("合法链应通过");
    }

    /// RIL-011：用户选择面 serde——组名须已声明（键面校验），往返语义
    /// 不变，空面不落盘。
    #[test]
    fn selections_roundtrip_and_key_validation() {
        let yaml = r#"
default_node: direct
groups:
  - name: pick
    strategy: fixed
    members: [n1, n2]
rules: []
selections:
  pick: n2
"#;
        let cfg: RoutingConfig = serde_yaml::from_str(yaml).expect("应解析");
        assert_eq!(cfg.selections.get("pick").map(String::as_str), Some("n2"));
        cfg.validate().expect("已声明组的选择应通过校验");

        // 往返
        let back: RoutingConfig =
            serde_yaml::from_str(&serde_yaml::to_string(&cfg).expect("序列化")).expect("读回");
        assert_eq!(back.selections, cfg.selections, "选择面往返语义不变");

        // 键面校验：未声明组的选择构建期点名拒绝
        let bad: RoutingConfig = serde_yaml::from_str(
            r#"
default_node: direct
groups:
  - name: pick
    strategy: fixed
    members: [n1]
rules: []
selections:
  typo-group: n1
"#,
        )
        .expect("应解析");
        let err = bad.validate().unwrap_err().to_string();
        assert!(
            err.contains("未声明的组") && err.contains("typo-group"),
            "{err}"
        );

        // 空面不落盘
        let empty_text = serde_yaml::to_string(&RoutingConfig::default()).expect("序列化");
        assert!(
            !empty_text.contains("selections:"),
            "空选择面不落盘: {empty_text}"
        );
    }

    #[test]
    fn routing_geo_db_absent_defaults_to_none() {
        let cfg: RillaneConfig =
            serde_yaml::from_str(base_yaml()).expect("无 geoip_db/geosite_db 应可解析");
        assert_eq!(cfg.routing.geoip_db, None);
        assert_eq!(cfg.routing.geosite_db, None);
    }

    #[test]
    fn load_from_path_resolves_relative_geo_db() {
        let dir = std::env::temp_dir().join(format!("rillane-cfg-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rillane.yaml");
        let yaml = "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n  geoip_db: geoip.mmdb\n  geosite_db: ../geosite.dat\n";
        std::fs::write(&path, yaml).unwrap();
        let cfg = RillaneConfig::load_from_path(&path).unwrap();
        assert_eq!(
            cfg.routing.geoip_db.as_deref(),
            Some(dir.join("geoip.mmdb").as_path())
        );
        assert_eq!(
            cfg.routing.geosite_db.as_deref(),
            Some(dir.parent().unwrap().join("geosite.dat").as_path())
        );
    }

    #[test]
    fn resolve_geo_db_clamps_relative_paths_at_root() {
        assert_eq!(
            resolve_geo_db(Path::new("../../../geoip.mmdb"), Path::new("/etc/rillane")),
            Path::new("/geoip.mmdb")
        );
        assert_eq!(
            resolve_geo_db(
                Path::new("databases/../../geoip.mmdb"),
                Path::new("/etc/rillane")
            ),
            Path::new("/etc/geoip.mmdb")
        );
        assert_eq!(
            resolve_geo_db(Path::new("../../geoip.mmdb"), Path::new("conf")),
            Path::new("../geoip.mmdb")
        );
    }
}

/// 递归校验逻辑组合条件内的 `DomainRegex` pattern（Any/Not 嵌套）。
fn validate_condition_regex(cond: &MatchCondition, rule_name: &str) -> anyhow::Result<()> {
    match cond {
        MatchCondition::Any { conditions } => {
            for c in conditions {
                validate_condition_regex(c, rule_name)?;
            }
        }
        MatchCondition::Not { condition } => {
            validate_condition_regex(condition, rule_name)?;
        }
        MatchCondition::DomainRegex { patterns } => {
            for p in patterns {
                regex::RegexBuilder::new(p)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| anyhow::anyhow!("规则 {} 的正则非法（{}）: {e}", rule_name, p))?;
            }
        }
        _ => {}
    }
    Ok(())
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
    /// 组级 url-test 常驻测速（G1-9）：配置后成员按 interval 真实探测
    /// （经成员出口 HTTP 探测，健康+RTT 入路由质量面）；缺省 None 不探测
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_test: Option<UrlTestConfig>,
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

/// 组级 url-test 探测配置（G1-9）：成员常驻真实测速。缺省 None = 该组
/// 不做真实探测（无探测句柄时沿用默认健康兜底）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlTestConfig {
    /// 探测目标 host:port（HTTP 探测经成员出口拨达）
    pub probe: String,
    /// 探测路径；缺省 /generate_204
    #[serde(default = "default_url_test_path")]
    pub path: String,
    /// 探测间隔（秒）；缺省 300
    #[serde(default = "default_url_test_interval")]
    pub interval_secs: u64,
    /// 单次探测超时（毫秒）；缺省 5000
    #[serde(default = "default_url_test_timeout")]
    pub timeout_ms: u64,
}

fn default_url_test_path() -> String {
    "/generate_204".to_string()
}

fn default_url_test_interval() -> u64 {
    300
}

fn default_url_test_timeout() -> u64 {
    5_000
}

impl UrlTestConfig {
    /// 值域构建期拦截：probe 须 host:port 且端口非 0；path 须以 / 开头；
    /// 间隔 ≥1s；超时 ≥1ms。由 `RoutingConfig::validate` 逐组调用。
    pub fn validate(&self, group: &str) -> anyhow::Result<()> {
        let host = self
            .probe
            .rsplit_once(':')
            .filter(|(_, p)| !p.is_empty())
            .map_or(self.probe.as_str(), |(h, _)| h);
        anyhow::ensure!(
            !host.is_empty(),
            "组 {group} 的 url_test.probe 缺 host:{probe:?}",
            probe = self.probe
        );
        let port: u16 = match self.probe.rsplit_once(':') {
            Some((_, p)) => p.parse().map_err(|_| {
                anyhow::anyhow!(
                    "组 {group} 的 url_test.probe 端口非法:{probe:?}",
                    probe = self.probe
                )
            })?,
            None => anyhow::bail!(
                "组 {group} 的 url_test.probe 缺端口:{probe:?}",
                probe = self.probe
            ),
        };
        anyhow::ensure!(
            port != 0,
            "组 {group} 的 url_test.probe 端口不能为 0:{probe:?}",
            probe = self.probe
        );
        anyhow::ensure!(
            self.path.starts_with('/'),
            "组 {group} 的 url_test.path 须以 / 开头:{path:?}",
            path = self.path
        );
        anyhow::ensure!(
            self.interval_secs >= 1,
            "组 {group} 的 url_test.interval_secs 须 ≥1"
        );
        anyhow::ensure!(
            self.timeout_ms >= 1,
            "组 {group} 的 url_test.timeout_ms 须 ≥1"
        );
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq)]
pub enum GroupMember {
    /// 直接节点引用
    Node { name: String },
    /// 嵌套组引用
    Group { name: String },
    /// 带权重的节点
    WeightedNode { name: String, weight: u32 },
    /// 带权重的组
    WeightedGroup { name: String, weight: u32 },
    /// 远端 provider 引用（RIL-009，Clash `use:` 口径）：成员集不是静态
    /// 名单而是「该 provider 当前提供的节点」。求值期按
    /// `RoutingConfig::provider_nodes` 库展开——载荷未装入/下载失败时展开
    /// 为空集，即**失效成员退出新流候选**（不伪装成有成员），与
    /// `RuleSetRef` 缺库恒不命中同语义。与 `Node`/`Group` 语义独立：
    /// provider 是来源（source），不是某个具体出口的名字。
    Provider { name: String },
}

/// 手写序列化（internally-tagged `{type, name, weight?}` 形）：derive 出的
/// externally-tagged `!Node` 形与 `GroupMemberRepr` 反序列化面（字符串
/// 简写 / `type:` 标签形）互不相认——serde_yaml 序列化的 RillaneConfig
/// （如 rillanectl import-clash）rillaned 读不回。此实现与 Tagged 反序列化
/// 镜像，保证往返自洽。
impl Serialize for GroupMember {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (tag, name, weight) = match self {
            GroupMember::Node { name } => ("node", name, None),
            GroupMember::Group { name } => ("group", name, None),
            GroupMember::WeightedNode { name, weight } => ("weighted_node", name, Some(*weight)),
            GroupMember::WeightedGroup { name, weight } => ("weighted_group", name, Some(*weight)),
            GroupMember::Provider { name } => ("provider", name, None),
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
    Provider { name: String },
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
            GroupMemberTagged::Provider { name } => GroupMember::Provider { name },
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
            // provider 名即引用名（展开结果面在 provider_nodes 库）
            GroupMember::Provider { name } => name.clone(),
        }
    }

    pub fn as_weight(&self) -> u32 {
        match self {
            GroupMember::Node { .. } => 1,
            GroupMember::Group { .. } => 1,
            GroupMember::WeightedNode { weight, .. } => *weight,
            GroupMember::WeightedGroup { weight, .. } => *weight,
            // provider 展开为多个等权节点，成员自身权重不参与组内选点
            GroupMember::Provider { .. } => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Fixed,
    Latency,
    /// 按序回退（RIL-012）：恒取声明序里首个健康成员——首位恢复健康即
    /// 回到首位，不为延迟次序所动（那是 Latency 的语义）
    Fallback,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteRule {
    pub name: String,
    pub matches: Vec<MatchCondition>,
    pub target: String,
}

/// proxy-provider 声明（RIL-009）：一个远端/本地节点目录的来源元数据。
/// 与 rule-provider 分离：provider 交付的是**出口节点**（egress 候选集），
/// rule-provider 交付的是**规则条件**（规则集载荷）。
/// `interval_secs` 是 Clash 口径的**秒**——原样透传，导入不换算单位
/// （RIL-092 同判：误当毫秒会把更新节奏放大约 1000 倍）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProviderDecl {
    /// 来源类型：`http`（远端）/ `file`（本地路径）
    #[serde(rename = "type")]
    pub provider_type: String,
    /// 远端 URL（type=http 必有；凭证不得出现在 URL 查询串——RIL-010 口径）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 本地路径（type=file 必有）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 更新周期（秒）；None = 不自动更新
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
    /// 目录级健康检查（Clash `health-check` 块）；原样带入供下载器与
    /// 节点健康面消费
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<ProviderHealthCheck>,
}

/// provider 目录健康检查参数（Clash `health-check` 块）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderHealthCheck {
    pub enable: bool,
    /// 探测目标 URL（Clash `url`）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 探测周期（秒，Clash 口径即秒）；None = 继承 provider 周期
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
}

/// 命名 provider 节点库（RIL-009）：`GroupMember::Provider` 引用的解析
/// 结果——`provider 名 → 当前提供的出口节点名`。载荷来源：provider
/// 快照内容（下载生命周期归 RIL-010；快照原子替换归 RIL-008），由
/// 控制面解析后装入；随 `RoutingConfig` 热更整体替换。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderNodeLibrary {
    /// 平铺序列化：`provider_nodes: { <名>: { nodes: [...] } }`
    #[serde(flatten)]
    providers: BTreeMap<String, ProviderNodeEntry>,
}

/// 单个 provider 条目：当前提供的出口节点名列表。空列表 = 载荷未装入或
/// 来源失效，展开为空集（失效成员退出新流候选）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderNodeEntry {
    pub nodes: Vec<String>,
}

impl ProviderNodeLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    /// 装入/替换一个 provider 的节点集（调用方持有载荷解析职责）
    pub fn insert(&mut self, name: impl Into<String>, nodes: Vec<String>) {
        self.providers
            .insert(name.into(), ProviderNodeEntry { nodes });
    }

    /// 查询 provider 当前节点集；无此名 = 未装入，返回 None
    pub fn get(&self, name: &str) -> Option<&ProviderNodeEntry> {
        self.providers.get(name)
    }

    /// provider 当前提供的节点名；缺席或载荷为空均为空集
    pub fn nodes(&self, name: &str) -> Vec<String> {
        self.providers
            .get(name)
            .map(|e| e.nodes.clone())
            .unwrap_or_default()
    }

    /// 已装入的 provider 数量
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// 域名正则匹配（G0-2）：按 Rust `regex` 语法对目标 host 做 `is_match`。
    /// 构建期 `RoutingConfig::validate` 逐条编译校验，非法 pattern 即 Err；
    /// 路由面经引擎级缓存编译（`reload` 按新配置 prune 失效 pattern），非法
    /// pattern 防御面恒不命中。与 `DomainSuffix`/`DomainKeyword` 并列，供
    /// `regexp:` 文本规则源与 `DOMAIN-REGEX` 规则导入。
    DomainRegex {
        patterns: Vec<String>,
    },
    Geoip {
        country: String,
    },
    /// GeoSite 站点类别匹配（G0-2）：目标主机按 v2fly `.dat` 数据库查询
    /// 站点类别（`geosite:` 前缀，如 `cn`/`geolocation-!cn`）。数据库由
    /// `routing.geosite_db` 给出；缺失/未加载时恒不命中（与原「无数据库」
    /// 行为一致）。匹配语义见 rillane-routing `geo.rs`。
    GeoSite {
        category: String,
    },
    /// 完全域名匹配（G0-2 `domain full:`）：目标主机与值**完全相等**
    /// （大小写不敏感，ASCII 小写化比较）。与 `DomainSuffix` 不同，本
    /// 条件只命中域名自身，不含其子域——文本规则源 `full:` 与 Clash
    /// `DOMAIN` 规则导入走此变体（不再并入 suffix 联合的超集语义）。
    DomainFull {
        values: Vec<String>,
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
    /// 大小写语义独立（RIL-015）：**精确区分大小写**比较，不做域名式
    /// 小写折叠；平台适配器如需不区分大小写语义在注解注入侧归一。
    Process {
        values: Vec<String>,
    },
    /// 按源进程可执行路径匹配（RIL-015）：值为完整可执行路径，经
    /// `process.path` 注解进入求值面（TUN 归因产出；对应
    /// `ProcessIdentity::executable_path`——不可得时注解缺席恒不命中，
    /// 不以短名冒充路径）。与 `Process`（短名）语义独立：路径精确
    /// 区分大小写、含分隔符全串比较，不做 comm 截断。
    ProcessPath {
        values: Vec<String>,
    },
    /// 源端口匹配（RIL-014）：本机侧五元组源端口。取值经 `net.src_port`
    /// 注解进入求值面（与 `client.cidr`/`process.name` 同一注入先例）；
    /// 注解缺席恒不命中。与 `Port`（目标端口）语义严格分离——导入链
    /// 不得把 SRC-PORT 折进目标端口（RIL-014 验收：源/目标端口正确）。
    SrcPort {
        values: Vec<u16>,
    },
    /// 传输协议匹配（RIL-014 逻辑规则子条件）：`tcp`/`udp`/`quic`，
    /// 大小写不敏感。Clash 逻辑规则的 `NETWORK,<proto>` 子条件走此变体。
    Proto {
        protocols: Vec<String>,
    },
    /// 命名规则集引用（RIL-014）：按名解析 `routing.rule_sets` 库中的
    /// 载荷条件，任一命中即命中。库中无此名（载荷未加载/来源失效）恒
    /// 不命中——与 GeoSite 缺数据库同一语义，不伪装命中也不整体拒绝。
    /// 引用可追踪：导入链要求 RULE-SET 指向已声明的 rule-provider。
    RuleSetRef {
        name: String,
    },
}

/// 命名规则集库（RIL-014）：RULE-SET 引用的载荷解析结果——`规则集名 →
/// 条件列表`（任一命中即命中）。载荷来源：rule-provider 快照内容
/// （下载生命周期归 RIL-010；快照原子替换归 RIL-008），由控制面解析后
/// 装入；随 `RoutingConfig` 热更整体替换。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuleSetLibrary {
    /// 平铺序列化：`rule_sets: { <名>: { conditions: [...] } }`——配置面
    /// 即名字到条件的直接映射，无包装层
    #[serde(flatten)]
    sets: BTreeMap<String, RuleSetEntry>,
}

/// 单个规则集条目：展开后的条件列表（首匹配层每条独立参与 OR 语义）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSetEntry {
    pub conditions: Vec<MatchCondition>,
}

impl RuleSetLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    /// 装入/替换一个规则集（调用方持有载荷解析职责）
    pub fn insert(&mut self, name: impl Into<String>, conditions: Vec<MatchCondition>) {
        self.sets.insert(name.into(), RuleSetEntry { conditions });
    }

    /// 查询规则集
    pub fn get(&self, name: &str) -> Option<&RuleSetEntry> {
        self.sets.get(name)
    }

    /// 清空规则集库（RIL-016 nodes-only 导入剥离策略面用）
    pub fn clear(&mut self) {
        self.sets.clear();
    }

    /// 已装入的规则集数量
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}
