//! 桌面客户端核心页面模型（RIL-148，ui-prototype-v1.md）：总览/节点/
//! 规则/网络 DNS/连接/开发者六页入口的**纯投影层**。页面不发明数据
//! 通道——可取数处全部复用闭合 [`crate::ops::AppOperation`] 集（统一
//! 应用服务边界，RIL-065）；取不到的面（DNS 读面、路由状态面、流媒体
//! 检测、代写宿主文件）以不可用/未知如实呈现，**绝不伪装可用**（原型
//! 红线：平台权限能力主宰开关，未经宿主确认不得显示已启用）。
//!
//! 三条诚实约束（todo.md RIL-148 验收口径）：
//! - **平台能力**：Windows/macOS/Linux 分别给出能力矩阵；[`CapabilityStatus`]
//!   只有 `Confirmed` 才算可用（[`CapabilityStatus::is_available`]）——未经
//!   宿主确认不得显示已启用；流媒体检测（RIL-145 控制面未接线）与代写
//!   宿主文件（RIL-147 只产计划，落盘在 CLI 侧）在任何平台都不是
//!   `Confirmed`。
//! - **接管状态**：以回执链（`/config/receipts`，RIL-073 审计面）为准——
//!   `apply.applied` + `os_applied` + reconcile 一致 + 代际吻合才确认；
//!   失败 / OS 未落 / 代际不一致一律点名原因（[`takeover_state`]），不信
//!   开关自述。
//! - **统计**：字段缺席/非数值 = [`StatValue::Unknown`]，不落 0 冒充实测；
//!   采集距今超过 [`STALE_STATS_SECONDS`] 视为陈旧并如实标记。

use serde_json::Value;

use crate::dev_snippets::{
    git_config_lines, plan_ssh_write, ssh_config_block, terminal_env_lines, DevShell,
    ProxyEndpoints, SshWritePlan,
};
use crate::ops::{AppOperation, FlowListFilter, OriginFilter, StateFilter};
use crate::reply::AppError;
use rillane_config::{ModeOverridePreview, ModeReceipt, SelectionMode};

// ---------------------------------------------------------------------------
// 页面入口
// ---------------------------------------------------------------------------

/// 桌面六页入口（ui-prototype-v1.md 信息架构）。每页声明取数所需的闭合
/// 操作名（[`AppOperation::name`] 口径）——页面不持有 HTTP 栈，只声明
/// 依赖；执行由调用方经统一应用服务完成。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DesktopPage {
    /// 总览：运行时统计 + 路由质量 + 回执审计（接管状态）+ 平台能力矩阵。
    Overview,
    /// 节点/订阅：订阅节点计数（来自运行时统计；`/nodes`、`/subscriptions`
    /// 属管理员 grade 面，未晋升进闭合操作集）。
    Nodes,
    /// 规则/区域：模式覆盖预览（rillane-config 纯面，本地配置直算）+ 试算
    /// 推演（`explain`）。
    Rules,
    /// 网络/DNS：入口保留，读面（`/dns/*`、`/network/route/status`）未晋升
    /// 进闭合操作集——见 [`network_page`]。
    Network,
    /// 连接：流列表 / 单流 / 事件 / SVG 轨迹。
    Connections,
    /// 开发者：Git/SSH/终端代理片段与写盘计划（RIL-147 纯面，本地生成）。
    Developer,
}

impl DesktopPage {
    /// 六页声明序（信息架构顺序）。
    pub const ALL: &'static [DesktopPage] = &[
        DesktopPage::Overview,
        DesktopPage::Nodes,
        DesktopPage::Rules,
        DesktopPage::Network,
        DesktopPage::Connections,
        DesktopPage::Developer,
    ];

    /// 页面标题（原型侧导航文案）。
    pub fn title(self) -> &'static str {
        match self {
            DesktopPage::Overview => "总览",
            DesktopPage::Nodes => "节点",
            DesktopPage::Rules => "规则",
            DesktopPage::Network => "网络",
            DesktopPage::Connections => "连接",
            DesktopPage::Developer => "开发者",
        }
    }

    /// 页面取数所需的闭合操作名（[`AppOperation::name`] 口径，声明序）。
    /// 空切片 = 页面纯本地生成（Network/Developer），不发起任何守护进程
    /// 调用——不得在调用方补发未声明操作。
    pub fn operations(self) -> &'static [&'static str] {
        match self {
            DesktopPage::Overview => &["runtime_stats", "routing_quality", "config_audit"],
            DesktopPage::Nodes => &["runtime_stats"],
            DesktopPage::Rules => &["explain", "config_audit"],
            DesktopPage::Network => &[],
            DesktopPage::Connections => &["flow_list", "flow_trace", "flow_events", "flow_svg"],
            DesktopPage::Developer => &[],
        }
    }
}

impl DesktopPage {
    /// 连接页流列表请求构造（复用统一应用服务；limit=0 客户端侧先行拒绝）。
    pub fn flow_list_op(
        state: Option<StateFilter>,
        origin: Option<OriginFilter>,
        generation: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<AppOperation, AppError> {
        Ok(AppOperation::FlowList(FlowListFilter::new(
            state, origin, generation, offset, limit,
        )?))
    }
}

// ---------------------------------------------------------------------------
// 平台能力矩阵（验收：Windows/macOS/Linux 权限能力分别显示）
// ---------------------------------------------------------------------------

/// 宿主操作系统（页面矩阵按 OS 分开；移动端/路由器不在本层）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostOs {
    Windows,
    MacOs,
    Linux,
}

impl HostOs {
    pub const ALL: &'static [HostOs] = &[HostOs::Windows, HostOs::MacOs, HostOs::Linux];

    pub fn label(self) -> &'static str {
        match self {
            HostOs::Windows => "Windows",
            HostOs::MacOs => "macOS",
            HostOs::Linux => "Linux",
        }
    }
}

/// 宿主权限态（页面层不自测——由调用方（UI 壳）按宿主事实注入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// 宿主已确认具备所需权限。
    Confirmed,
    /// 宿主已明确拒绝（缺权限/被降权）。
    Denied,
    /// 未在宿主上验证过。
    Unknown,
}

/// 能力种类（矩阵条目；与原型「平台权限能力主宰开关」一一对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    /// TUN 接管抓包（Linux `tun.rs` / Windows Wintun；需管理员权限建适配器）。
    TunCapture,
    /// 透明接管 redirect/tproxy（RIL-139，仅 Linux nftables + ip rule）。
    TransparentCapture,
    /// 系统服务安装/自恢复（Windows SCM 面 `win_service.rs`；Linux/macOS 未接线）。
    ServiceInstall,
    /// DNS 劫持（进程内解析器 RIL-144，接管宿主 DNS 经 TUN——与 TUN 同门）。
    DnsInterception,
    /// 流媒体解锁检测（RIL-145 执行器已落地，控制面/端点未接线）。
    MediaDetection,
    /// 代写宿主文件（RIL-147 只产片段与写盘计划，落盘在 CLI 侧显式执行）。
    WriteFile,
}

/// 全部能力种类（矩阵声明序）。
pub const CAPABILITY_KINDS: &[CapabilityKind] = &[
    CapabilityKind::TunCapture,
    CapabilityKind::TransparentCapture,
    CapabilityKind::ServiceInstall,
    CapabilityKind::DnsInterception,
    CapabilityKind::MediaDetection,
    CapabilityKind::WriteFile,
];

/// 单项能力状态（只有 [`CapabilityStatus::Confirmed`] 才算可用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityStatus {
    /// 已在宿主上确认可用（可安全显示为已启用）。
    Confirmed,
    /// 宿主明确拒绝/缺权限（带原因；不可显示为已启用）。
    Denied { reason: &'static str },
    /// 本平台无实现面（结构性不支持，不是「待验证」）。
    Unsupported { note: &'static str },
    /// 未在宿主验证过 / 实现面未接线（不伪装可用）。
    Unknown { note: &'static str },
}

impl CapabilityStatus {
    /// 是否可视为已启用——只认 `Confirmed`（未经宿主确认不得显示已启用）。
    pub fn is_available(&self) -> bool {
        matches!(self, CapabilityStatus::Confirmed)
    }
}

/// 能力矩阵条目（种类 + 状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEntry {
    pub kind: CapabilityKind,
    pub status: CapabilityStatus,
}

/// 某宿主 OS + 权限态下的能力矩阵（全种类声明序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub os: HostOs,
    pub privilege: Privilege,
    pub entries: Vec<CapabilityEntry>,
}

impl PlatformCapabilities {
    /// 未验证权限态下的矩阵（调用方随后用实际权限态重建，见
    /// [`PlatformCapabilities::with_privilege`]）。
    pub fn for_os(os: HostOs) -> Self {
        Self::with_privilege(os, Privilege::Unknown)
    }

    /// 按宿主事实权限态给矩阵。
    pub fn with_privilege(os: HostOs, privilege: Privilege) -> Self {
        let entries = CAPABILITY_KINDS
            .iter()
            .map(|&kind| CapabilityEntry {
                kind,
                status: capability_status(os, kind, privilege),
            })
            .collect();
        Self {
            os,
            privilege,
            entries,
        }
    }

    pub fn status(&self, kind: CapabilityKind) -> Option<&CapabilityStatus> {
        self.entries
            .iter()
            .find(|e| e.kind == kind)
            .map(|e| &e.status)
    }

    /// 该项是否可视为已启用（只认 `Confirmed`）。
    pub fn available(&self, kind: CapabilityKind) -> bool {
        self.status(kind).map(|s| s.is_available()).unwrap_or(false)
    }
}

/// 需要提升权限的能力：未确认权限态下不得显示可用（宿主确认才可启用）。
fn privilege_gated(privilege: Privilege, requirement: &'static str) -> CapabilityStatus {
    match privilege {
        Privilege::Confirmed => CapabilityStatus::Confirmed,
        Privilege::Denied => CapabilityStatus::Denied {
            reason: requirement,
        },
        Privilege::Unknown => CapabilityStatus::Unknown { note: requirement },
    }
}

/// 某 OS + 权限态下的能力状态（逐条映射平台实现面事实；见模块文档注释
/// 引用的平台源码路径——矩阵不发明「应该支持」，只反映已接线事实）。
pub fn capability_status(
    os: HostOs,
    kind: CapabilityKind,
    privilege: Privilege,
) -> CapabilityStatus {
    match (os, kind) {
        // TUN 接管：Linux（tun.rs，用户态封环）与 Windows（Wintun）均有
        // 实现面，但建适配器/策略路由需管理员权限——权限未确认前不可用。
        (HostOs::Linux | HostOs::Windows, CapabilityKind::TunCapture) => privilege_gated(
            privilege,
            "需要管理员权限（建 TUN 设备与策略路由；未经宿主确认不得显示已启用）",
        ),
        (HostOs::MacOs, CapabilityKind::TunCapture) => CapabilityStatus::Unknown {
            note: "macOS utun 实现面未接线",
        },

        // 透明接管：RIL-139 仅 Linux（nftables 事务 + ip rule）；其余平台无面。
        (HostOs::Linux, CapabilityKind::TransparentCapture) => privilege_gated(
            privilege,
            "需要 CAP_NET_ADMIN（nftables 规则与策略路由；未经宿主确认不得显示已启用）",
        ),
        (HostOs::Windows, CapabilityKind::TransparentCapture) => CapabilityStatus::Unsupported {
            note: "Windows 无 nftables/iptables 透明接管面",
        },
        (HostOs::MacOs, CapabilityKind::TransparentCapture) => CapabilityStatus::Unknown {
            note: "macOS PF 接线未实现",
        },

        // 服务安装：Windows SCM 面（win_service.rs / install-service.ps1）；
        // Linux/macOS 装配面未接线（包管理器/手动装配，不冒充系统服务能力）。
        (HostOs::Windows, CapabilityKind::ServiceInstall) => privilege_gated(
            privilege,
            "SCM 建系统服务需要管理员权限（未经宿主确认不得显示已启用）",
        ),
        (HostOs::Linux, CapabilityKind::ServiceInstall) => CapabilityStatus::Unknown {
            note: "Linux 系统服务装配面未接线（包管理器/手动装配）",
        },
        (HostOs::MacOs, CapabilityKind::ServiceInstall) => CapabilityStatus::Unknown {
            note: "macOS launchd 装配面未接线",
        },

        // DNS 劫持：进程内解析器（RIL-144）跨平台，但接管宿主 DNS 经 TUN
        // ——与 TUN 接管同门（Linux/Windows 权限门控；macOS 无 TUN 面）。
        (HostOs::Linux | HostOs::Windows, CapabilityKind::DnsInterception) => privilege_gated(
            privilege,
            "接管宿主 DNS 经 TUN——与 TUN 接管同门（需要管理员权限）",
        ),
        (HostOs::MacOs, CapabilityKind::DnsInterception) => CapabilityStatus::Unknown {
            note: "macOS 无 TUN 面，DNS 接管未接线",
        },

        // 流媒体：RIL-145 决策面 + 执行器已落地，控制面/端点未接线——
        // 任何平台都不是 Confirmed（不伪装「检测可用」）。
        (_, CapabilityKind::MediaDetection) => CapabilityStatus::Unknown {
            note: "流媒体检测控制面未接线（RIL-145 执行器已落地，端点待接）",
        },

        // 代写宿主文件：RIL-147 只产片段与写盘计划（plan_ssh_write），
        // 落盘在 CLI 侧显式执行——页面/应用服务层不承诺写文件。
        (_, CapabilityKind::WriteFile) => CapabilityStatus::Unsupported {
            note: "页面/服务只生成片段与写盘计划，落盘由 CLI 显式执行（RIL-147）",
        },
    }
}

// ---------------------------------------------------------------------------
// 接管状态（验收：接管状态以回执为准）
// ---------------------------------------------------------------------------

/// 接管状态判定用稳定码（`ApplyStatus::code()` 口径，见 rillane-config/apply.rs）。
pub const APPLY_STATUS_APPLIED: &str = "apply.applied";
pub const APPLY_STATUS_EXECUTE_FAILED: &str = "apply.execute.failed";

/// 接管状态：只认回执链（`/config/receipts`），不信开关自述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeoverState {
    /// 无任何回执：从未提交/应用过配置（未接管）。
    NotConfigured,
    /// 最近回执 `apply.applied` + `os_applied` + reconcile 一致 + 代际吻合。
    Confirmed { generation: String },
    /// 最近回执失败（`apply.execute.failed` 或带 `failure_reason`）。
    Failed { code: String, reason: String },
    /// 回执在但未闭环（OS 未落 / 代际不一致 / reconcile 不一致 / 状态未定论）。
    Unconfirmed { reason: String },
    /// 审计面不可达/非对象（无法判定——不是「未接管」也不是「已接管」）。
    Unknown { reason: String },
}

/// 由 `/config/receipts` 响应体推接管状态（纯函数；`None` = 审计不可达）。
pub fn takeover_state(audit: Option<&Value>) -> TakeoverState {
    let Some(v) = audit else {
        return TakeoverState::Unknown {
            reason: "回执审计不可达".into(),
        };
    };
    let Some(receipts) = v.get("receipts").and_then(Value::as_array) else {
        return TakeoverState::Unknown {
            reason: "回执审计缺 receipts 链".into(),
        };
    };
    if receipts.is_empty() {
        return TakeoverState::NotConfigured;
    }
    // 回执链 seq 降序声明，仍防御性取最大 seq（对账以最新回执为准）。
    let Some(latest) = receipts
        .iter()
        .max_by_key(|r| r.get("seq").and_then(Value::as_u64).unwrap_or(0))
    else {
        return TakeoverState::Unknown {
            reason: "回执链为空".into(),
        };
    };

    let status = latest
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if let Some(reason) = latest.get("failure_reason").and_then(Value::as_str) {
        return TakeoverState::Failed {
            code: status.to_string(),
            reason: reason.to_string(),
        };
    }
    if status == APPLY_STATUS_EXECUTE_FAILED {
        return TakeoverState::Failed {
            code: status.to_string(),
            reason: "OS 执行失败（回执未带原因明细）".into(),
        };
    }
    if status != APPLY_STATUS_APPLIED {
        return TakeoverState::Unconfirmed {
            reason: format!("回执状态 {status} 未定论"),
        };
    }

    if latest.get("os_applied").and_then(Value::as_bool) != Some(true) {
        return TakeoverState::Unconfirmed {
            reason: "应用已确认但 OS 层未落（os_applied != true）".into(),
        };
    }
    let Some(receipt_gen) = latest.get("generation").and_then(Value::as_str) else {
        return TakeoverState::Unconfirmed {
            reason: "回执未带代际，无法对账现役面".into(),
        };
    };
    let live = v.get("live_generation").and_then(Value::as_str);
    let agrees = v
        .get("reconcile")
        .and_then(|r| r.get("agrees"))
        .and_then(Value::as_bool);
    match (live, agrees) {
        (Some(l), _) if l != receipt_gen => TakeoverState::Unconfirmed {
            reason: format!("回执代际 {receipt_gen} 与现役面 {l} 不一致"),
        },
        (Some(l), Some(true)) => TakeoverState::Confirmed {
            generation: l.to_string(),
        },
        (_, Some(false)) => TakeoverState::Unconfirmed {
            reason: "回执链与现役面 reconcile 不一致".into(),
        },
        (None, _) => TakeoverState::Unconfirmed {
            reason: "审计缺现役代际，无法对账".into(),
        },
        (_, None) => TakeoverState::Unconfirmed {
            reason: "审计缺 reconcile 摘要，无法对账".into(),
        },
    }
}

// ---------------------------------------------------------------------------
// 统计（验收：未知统计正确——不落 0 冒充实测）
// ---------------------------------------------------------------------------

/// 统计值：`Known` 才是实测；`Unknown` = 字段缺席/非数值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatValue {
    Known(u64),
    Unknown,
}

impl StatValue {
    pub fn known(self) -> Option<u64> {
        match self {
            StatValue::Known(n) => Some(n),
            StatValue::Unknown => None,
        }
    }

    pub fn is_unknown(self) -> bool {
        matches!(self, StatValue::Unknown)
    }

    fn from_field(v: Option<&Value>) -> Self {
        match v.and_then(Value::as_u64) {
            Some(n) => StatValue::Known(n),
            None => StatValue::Unknown,
        }
    }
}

/// 统计陈旧阈值（采集距今超过此秒数 = 陈旧，如实标记不冒充新鲜）。
pub const STALE_STATS_SECONDS: f64 = 30.0;

/// 运行时统计投影（`/runtime/stats` 响应体；`None` = 不可达 → 全 Unknown + 陈旧）。
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeStatsView {
    pub uptime_seconds: StatValue,
    pub total_connections: StatValue,
    pub active_connections: StatValue,
    pub bytes_uploaded: StatValue,
    pub bytes_downloaded: StatValue,
    pub mesh_nodes: StatValue,
    pub subscription_nodes: StatValue,
    pub error_count: StatValue,
    /// 采集距今秒数（缺席 = None）。
    pub last_updated_ago_seconds: Option<f64>,
    /// 采集距今超过 [`STALE_STATS_SECONDS`]（或不可达）= 陈旧。
    pub stale: bool,
}

fn u64_field(v: &Value, key: &str) -> StatValue {
    StatValue::from_field(v.get(key))
}

fn f64_field(v: &Value, key: &str) -> Option<f64> {
    v.get(key).and_then(Value::as_f64)
}

/// 由 `/runtime/stats` 响应体推统计视图（纯函数）。
pub fn runtime_stats_view(body: Option<&Value>) -> RuntimeStatsView {
    let Some(v) = body else {
        return RuntimeStatsView {
            uptime_seconds: StatValue::Unknown,
            total_connections: StatValue::Unknown,
            active_connections: StatValue::Unknown,
            bytes_uploaded: StatValue::Unknown,
            bytes_downloaded: StatValue::Unknown,
            mesh_nodes: StatValue::Unknown,
            subscription_nodes: StatValue::Unknown,
            error_count: StatValue::Unknown,
            last_updated_ago_seconds: None,
            stale: true,
        };
    };
    let last = f64_field(v, "last_updated_ago_seconds");
    let stale = !matches!(last, Some(t) if t <= STALE_STATS_SECONDS);
    RuntimeStatsView {
        uptime_seconds: u64_field(v, "uptime_seconds"),
        total_connections: u64_field(v, "total_connections"),
        active_connections: u64_field(v, "active_connections"),
        bytes_uploaded: u64_field(v, "bytes_uploaded"),
        bytes_downloaded: u64_field(v, "bytes_downloaded"),
        mesh_nodes: u64_field(v, "mesh_nodes"),
        subscription_nodes: u64_field(v, "subscription_nodes"),
        error_count: u64_field(v, "error_count"),
        last_updated_ago_seconds: last,
        stale,
    }
}

/// 订阅状态（验收：空订阅正确显示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    Empty,
    Nodes(usize),
    Unknown,
}

/// 由 `/runtime/stats` 推订阅节点状态（`subscription_nodes`）。
pub fn subscription_state(stats: Option<&Value>) -> SubscriptionState {
    match u64_field(stats.unwrap_or(&Value::Null), "subscription_nodes") {
        StatValue::Known(0) => SubscriptionState::Empty,
        StatValue::Known(n) => SubscriptionState::Nodes(n as usize),
        StatValue::Unknown => SubscriptionState::Unknown,
    }
}

// ---------------------------------------------------------------------------
// 总览视图
// ---------------------------------------------------------------------------

/// 总览页装配：统计 + 订阅 + 接管状态 + 平台能力矩阵。
#[derive(Debug, Clone, PartialEq)]
pub struct OverviewView {
    pub stats: RuntimeStatsView,
    pub subscription: SubscriptionState,
    pub takeover: TakeoverState,
    pub capabilities: PlatformCapabilities,
}

/// 总览视图（纯函数；统计/审计为 `None` 时各自如实呈现不可达）。
pub fn overview_view(
    stats: Option<&Value>,
    audit: Option<&Value>,
    os: HostOs,
    privilege: Privilege,
) -> OverviewView {
    OverviewView {
        stats: runtime_stats_view(stats),
        subscription: subscription_state(stats),
        takeover: takeover_state(audit),
        capabilities: PlatformCapabilities::with_privilege(os, privilege),
    }
}

// ---------------------------------------------------------------------------
// 规则/区域（模式覆盖预览 + 试算推演；RIL-140 纯面复用）
// ---------------------------------------------------------------------------

/// 选择模式（rillane-config `SelectionMode` snake_case 线格式投影）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSelection {
    Rule,
    Global,
    Direct,
}

impl ModeSelection {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "rule" => Some(ModeSelection::Rule),
            "global" => Some(ModeSelection::Global),
            "direct" => Some(ModeSelection::Direct),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ModeSelection::Rule => "rule",
            ModeSelection::Global => "global",
            ModeSelection::Direct => "direct",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ModeSelection::Rule => "规则模式",
            ModeSelection::Global => "全局模式",
            ModeSelection::Direct => "直连模式",
        }
    }
}

/// rillane-config `SelectionMode` → 页面投影（不经过线格式——枚举恒定）。
fn mode_from_selection(m: SelectionMode) -> ModeSelection {
    match m {
        SelectionMode::Rule => ModeSelection::Rule,
        SelectionMode::Global => ModeSelection::Global,
        SelectionMode::Direct => ModeSelection::Direct,
    }
}

/// 模式覆盖预览（规则页；rillane-config `mode_override_preview` 纯面投影）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeOverrideView {
    pub requested: ModeSelection,
    pub current: ModeSelection,
    pub paused_scenarios: Vec<String>,
    pub paused_rules: Vec<String>,
    pub paused_reject_rules: Vec<String>,
    pub note: String,
}

/// 由 rillane-config 纯面预览构造（不经守护进程——本地配置直算）。
pub fn mode_override_view(preview: &ModeOverridePreview) -> ModeOverrideView {
    ModeOverrideView {
        requested: mode_from_selection(preview.requested),
        current: mode_from_selection(preview.current),
        paused_scenarios: preview.paused_scenarios.clone(),
        paused_rules: preview.paused_rules.clone(),
        paused_reject_rules: preview.paused_reject_rules.clone(),
        note: preview.note.clone(),
    }
}

/// 模式覆盖回执（规则页；`mode_receipt` 纯面投影——以回执为准判定是否生效）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeReceiptView {
    pub requested: ModeSelection,
    pub effective: ModeSelection,
    pub generation_id: Option<String>,
    pub conflicts: Vec<String>,
    /// 冲突空 = 覆盖已被发布代际承认（以回执为准）。
    pub honored: bool,
}

pub fn mode_receipt_view(receipt: &ModeReceipt) -> ModeReceiptView {
    ModeReceiptView {
        requested: mode_from_selection(receipt.requested),
        effective: mode_from_selection(receipt.effective),
        generation_id: receipt.generation_id.clone(),
        conflicts: receipt.conflicts.clone(),
        honored: receipt.conflicts.is_empty(),
    }
}

// ---------------------------------------------------------------------------
// 连接页
// ---------------------------------------------------------------------------

/// 连接行（`/trace/flows` items 投影；缺席字段如实为 None/Unknown）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRow {
    pub flow: String,
    pub origin: Option<String>,
    pub generation: Option<String>,
    /// "active"/"closed"（缺席 = None）。
    pub state: Option<String>,
    pub events: StatValue,
    pub first_wall_ms: Option<u64>,
    pub last_code: Option<String>,
}

/// 连接列表视图（`/trace/flows` 响应体；`None` = 不可达 → Unknown + 空行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionsView {
    pub total_matching: StatValue,
    pub offset: u64,
    pub limit: u64,
    pub rows: Vec<ConnectionRow>,
}

impl ConnectionsView {
    /// 已知为空（total_matching == 0）；Unknown 不算空（不冒充）。
    pub fn known_empty(&self) -> bool {
        matches!(self.total_matching, StatValue::Known(0))
    }
}

fn opt_str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// last_code 可为字符串或数字（兼容两种投影），非两者 = None。
fn display_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn row_of(item: &Value) -> Option<ConnectionRow> {
    let flow = item.get("flow").and_then(Value::as_str)?.to_string();
    Some(ConnectionRow {
        flow,
        origin: opt_str_field(item, "origin"),
        generation: opt_str_field(item, "generation"),
        state: opt_str_field(item, "state"),
        events: StatValue::from_field(item.get("events")),
        first_wall_ms: item.get("first_wall_ms").and_then(Value::as_u64),
        last_code: display_field(item, "last_code"),
    })
}

/// 由 `/trace/flows` 响应体推连接视图（纯函数）。
pub fn connections_view(body: Option<&Value>) -> ConnectionsView {
    let Some(v) = body else {
        return ConnectionsView {
            total_matching: StatValue::Unknown,
            offset: 0,
            limit: 0,
            rows: Vec::new(),
        };
    };
    let rows = v
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(row_of).collect())
        .unwrap_or_default();
    ConnectionsView {
        total_matching: u64_field(v, "total_matching"),
        offset: v.get("offset").and_then(Value::as_u64).unwrap_or(0),
        limit: v.get("limit").and_then(Value::as_u64).unwrap_or(0),
        rows,
    }
}

// ---------------------------------------------------------------------------
// 网络/DNS 页（入口保留，读面未晋升）
// ---------------------------------------------------------------------------

/// 网络页模型：DNS 读面（`/dns/stats`、`/dns/resolvers`）与路由状态面
/// （`/network/route/status`）均属管理员 grade，未晋升进闭合操作集——
/// 入口存在、数据经统一应用服务不可达，如实标注（不伪装成「关闭」或
/// 「未知」之外的任何断言）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPageModel {
    /// 现状恒 false：读面未晋升进闭合操作集。
    pub data_available: bool,
    pub unavailable_reason: &'static str,
}

pub fn network_page() -> NetworkPageModel {
    NetworkPageModel {
        data_available: false,
        unavailable_reason: "DNS 读面与路由状态面属管理员 grade，未晋升进统一应用服务闭合操作集——入口保留，数据不伪装",
    }
}

// ---------------------------------------------------------------------------
// 开发者页（RIL-147 纯面片段 + 写盘计划）
// ---------------------------------------------------------------------------

/// 开发者页视图：终端/Git/SSH 片段 + 写盘计划；页面层不落盘。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeveloperSnippetView {
    pub shell_label: &'static str,
    pub terminal_lines: String,
    pub git_lines: Vec<String>,
    pub ssh_block: String,
    pub ssh_write_plan: SshWritePlan,
    /// 恒 false：页面/应用服务只产计划，落盘由 CLI 侧显式执行（验收红线）。
    pub can_write_files: bool,
}

/// 开发者页片段（纯本地生成；`ssh_path`/`current_ssh` 为宿主 SSH 配置位）。
pub fn developer_snippets(
    shell: DevShell,
    endpoints: &ProxyEndpoints,
    ssh_hosts: &[&str],
    ssh_path: &str,
    current_ssh: Option<&str>,
) -> DeveloperSnippetView {
    let ssh_block = ssh_config_block(ssh_hosts, endpoints);
    let ssh_write_plan = plan_ssh_write(ssh_path, current_ssh, &ssh_block);
    DeveloperSnippetView {
        shell_label: shell.label(),
        terminal_lines: terminal_env_lines(shell, endpoints),
        git_lines: git_config_lines(endpoints),
        ssh_block,
        ssh_write_plan,
        can_write_files: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_snippets::{
        forbidden_ssh_lines, GIT_CONFIG_KEYS, SSH_BACKUP_SUFFIX, SSH_MANAGED_MARKER,
    };
    use rillane_config::SelectionMode;

    /// 闭合操作名目录（AppOperation::name() 全量 17 变体的稳定名；页面
    /// 声明面不得越界——新操作入集须在此补名 + 补 app_contract 线格式）。
    const CLOSED_OPS: &[&str] = &[
        "runtime_stats",
        "routing_quality",
        "flow_list",
        "flow_trace",
        "flow_events",
        "flow_svg",
        "explain",
        "probe_list",
        "probe_submit",
        "probe_cancel",
        "probe_result",
        "validate_config",
        "preview_config_change",
        "config_audit",
        "apply_config_change",
        "rollback_config",
    ];

    #[test]
    fn page_operations_stay_within_closed_op_set() {
        assert_eq!(DesktopPage::ALL.len(), 6, "六页入口（ui-prototype-v1）");
        for &page in DesktopPage::ALL {
            for op in page.operations() {
                assert!(
                    CLOSED_OPS.contains(op),
                    "{page:?} 声明了闭合集外的操作 {op}"
                );
            }
        }
        // 网络/开发者页纯本地，不发起任何守护进程调用
        assert_eq!(DesktopPage::Network.operations().len(), 0);
        assert_eq!(DesktopPage::Developer.operations().len(), 0);
        assert_eq!(DesktopPage::Connections.operations().len(), 4);
        assert_eq!(DesktopPage::Overview.operations().len(), 3);
    }

    #[test]
    fn flow_list_op_reuses_unified_service_and_rejects_zero_limit() {
        let op = DesktopPage::flow_list_op(Some(StateFilter::Active), None, None, 0, 20)
            .expect("合法翻页应构造成功");
        assert_eq!(op.name(), "flow_list");
        let err =
            DesktopPage::flow_list_op(None, None, None, 0, 0).expect_err("limit=0 应客户端侧拒绝");
        assert_eq!(err.code, "query.page.invalid");
    }

    #[test]
    fn capability_matrix_per_os_and_never_fakes_unready() {
        for &os in HostOs::ALL {
            let caps = PlatformCapabilities::for_os(os);
            assert_eq!(
                caps.entries.len(),
                CAPABILITY_KINDS.len(),
                "{} 矩阵须覆盖全部能力种类",
                os.label()
            );
            // 未就绪面在任何平台/权限下都不可伪装可用
            assert!(
                !caps.available(CapabilityKind::MediaDetection),
                "流媒体检测不得伪装可用（控制面未接线）"
            );
            assert!(
                !caps.available(CapabilityKind::WriteFile),
                "写文件不得伪装可用（落盘在 CLI 侧）"
            );
        }

        // macOS：实现面未接线——即便宿主权限确认也无任何 Confirmed
        let mac = PlatformCapabilities::with_privilege(HostOs::MacOs, Privilege::Confirmed);
        for e in &mac.entries {
            assert!(
                !e.status.is_available(),
                "macOS {:?} 未接线不得 Confirmed",
                e.kind
            );
        }

        // Linux 权限确认：TUN/透明/DNS 可用；服务面未接线仍不可用
        let linux = PlatformCapabilities::with_privilege(HostOs::Linux, Privilege::Confirmed);
        assert!(linux.available(CapabilityKind::TunCapture));
        assert!(linux.available(CapabilityKind::TransparentCapture));
        assert!(linux.available(CapabilityKind::DnsInterception));
        assert!(
            !linux.available(CapabilityKind::ServiceInstall),
            "Linux 服务装配面未接线"
        );

        // Linux 权限未确认：即便有实现面也不显示可用（原型红线）
        let linux_unknown = PlatformCapabilities::with_privilege(HostOs::Linux, Privilege::Unknown);
        assert!(!linux_unknown.available(CapabilityKind::TunCapture));

        // Linux 权限被拒：Denied 带原因
        let linux_denied = PlatformCapabilities::with_privilege(HostOs::Linux, Privilege::Denied);
        assert!(matches!(
            linux_denied.status(CapabilityKind::TunCapture).unwrap(),
            CapabilityStatus::Denied { .. }
        ));

        // Windows：TUN/服务可用，透明接管结构性不支持（非待验证）
        let win = PlatformCapabilities::with_privilege(HostOs::Windows, Privilege::Confirmed);
        assert!(win.available(CapabilityKind::TunCapture));
        assert!(win.available(CapabilityKind::ServiceInstall));
        assert!(matches!(
            win.status(CapabilityKind::TransparentCapture).unwrap(),
            CapabilityStatus::Unsupported { .. }
        ));

        // Windows 权限被拒：TUN 同样不可用
        let win_denied = PlatformCapabilities::with_privilege(HostOs::Windows, Privilege::Denied);
        assert!(!win_denied.available(CapabilityKind::TunCapture));
    }

    fn audit(json: &str) -> Value {
        serde_json::from_str(json).expect("审计样例应可解析")
    }

    #[test]
    fn takeover_state_is_receipt_governed() {
        // 审计不可达 = Unknown（不是「未接管」也不是「已接管」）
        assert!(matches!(
            takeover_state(None),
            TakeoverState::Unknown { .. }
        ));
        assert!(matches!(
            takeover_state(Some(&Value::String("x".into()))),
            TakeoverState::Unknown { .. }
        ));

        // 空回执链 = 未配置
        let empty = audit(
            r#"{"live_generation":"g1","live_hash":"h","reconcile":{"agrees":true},"receipts":[]}"#,
        );
        assert_eq!(takeover_state(Some(&empty)), TakeoverState::NotConfigured);

        // applied + os_applied + reconcile 一致 + 代际吻合 = 确认
        let ok = audit(
            r#"{"live_generation":"g7","live_hash":"h","reconcile":{"agrees":true},
                "receipts":[{"seq":3,"status":"apply.applied","generation":"g7","os_applied":true}]}"#,
        );
        assert_eq!(
            takeover_state(Some(&ok)),
            TakeoverState::Confirmed {
                generation: "g7".into()
            }
        );

        // OS 层未落 = 未确认（应用确认不算接管）
        let no_os = audit(
            r#"{"live_generation":"g7","reconcile":{"agrees":true},
                "receipts":[{"seq":3,"status":"apply.applied","generation":"g7","os_applied":false}]}"#,
        );
        assert!(matches!(
            takeover_state(Some(&no_os)),
            TakeoverState::Unconfirmed { .. }
        ));

        // 代际不一致 = 未确认
        let stale = audit(
            r#"{"live_generation":"g8","reconcile":{"agrees":true},
                "receipts":[{"seq":3,"status":"apply.applied","generation":"g7","os_applied":true}]}"#,
        );
        assert!(matches!(
            takeover_state(Some(&stale)),
            TakeoverState::Unconfirmed { .. }
        ));

        // reconcile 不一致 = 未确认
        let diverged = audit(
            r#"{"live_generation":"g7","reconcile":{"agrees":false},
                "receipts":[{"seq":3,"status":"apply.applied","generation":"g7","os_applied":true}]}"#,
        );
        assert!(matches!(
            takeover_state(Some(&diverged)),
            TakeoverState::Unconfirmed { .. }
        ));

        // 执行失败 = Failed（带原因时回显原因；无明细时点名）
        let failed = audit(
            r#"{"live_generation":"g7","receipts":[{"seq":4,"status":"apply.execute.failed",
                "generation":null,"os_applied":false,"failure_reason":"nft: rule add failed"}]}"#,
        );
        assert_eq!(
            takeover_state(Some(&failed)),
            TakeoverState::Failed {
                code: "apply.execute.failed".into(),
                reason: "nft: rule add failed".into(),
            }
        );

        // 乱序声明仍取最大 seq（链序防御）
        let unordered = audit(
            r#"{"live_generation":"g7","reconcile":{"agrees":true},"receipts":[
                {"seq":1,"status":"apply.applied","generation":"g5","os_applied":true},
                {"seq":5,"status":"apply.applied","generation":"g7","os_applied":true}]}"#,
        );
        assert_eq!(
            takeover_state(Some(&unordered)),
            TakeoverState::Confirmed {
                generation: "g7".into()
            }
        );
    }

    #[test]
    fn stats_unknown_when_absent_and_stale_flagged() {
        // 不可达 = 全 Unknown + 陈旧（不落 0 冒充实测）
        let none = runtime_stats_view(None);
        assert!(none.total_connections.is_unknown());
        assert!(none.subscription_nodes.is_unknown());
        assert!(none.stale);

        // 字段缺席 = Unknown；数值正常 = Known
        let v: Value = serde_json::json!({
            "uptime_seconds": 120u64,
            "total_connections": 42u64,
            "subscription_nodes": 0u64,
            "last_updated_ago_seconds": 1.5f64,
        });
        let view = runtime_stats_view(Some(&v));
        assert_eq!(view.uptime_seconds, StatValue::Known(120));
        assert_eq!(view.total_connections, StatValue::Known(42));
        assert!(view.bytes_uploaded.is_unknown(), "缺席字段不得落 0");
        assert!(!view.stale, "1.5s 采集距今不陈旧");

        // 采集距今超阈值 = 陈旧
        let old: Value = serde_json::json!({ "last_updated_ago_seconds": 91.0f64 });
        assert!(runtime_stats_view(Some(&old)).stale);
        // 采集距今缺席 = 无法证新鲜 = 陈旧
        let no_ts: Value = serde_json::json!({ "total_connections": 1u64 });
        assert!(runtime_stats_view(Some(&no_ts)).stale);
    }

    #[test]
    fn subscription_state_shapes() {
        let empty: Value = serde_json::json!({ "subscription_nodes": 0u64 });
        assert_eq!(subscription_state(Some(&empty)), SubscriptionState::Empty);
        let some: Value = serde_json::json!({ "subscription_nodes": 5u64 });
        assert_eq!(subscription_state(Some(&some)), SubscriptionState::Nodes(5));
        let missing: Value = serde_json::json!({});
        assert_eq!(
            subscription_state(Some(&missing)),
            SubscriptionState::Unknown
        );
        assert_eq!(subscription_state(None), SubscriptionState::Unknown);
    }

    #[test]
    fn mode_views_project_pure_surface() {
        let preview = ModeOverridePreview {
            requested: SelectionMode::Global,
            current: SelectionMode::Rule,
            paused_scenarios: vec!["vpn".into()],
            paused_rules: vec!["ads-block".into()],
            paused_reject_rules: vec!["ads-block".into()],
            note: "全局下普通选路面暂停".into(),
        };
        let v = mode_override_view(&preview);
        assert_eq!(v.requested, ModeSelection::Global);
        assert_eq!(v.current, ModeSelection::Rule);
        assert_eq!(v.paused_reject_rules, vec!["ads-block".to_string()]);
        assert_eq!(ModeSelection::Global.label(), "全局模式");
        assert_eq!(ModeSelection::from_wire("rule"), Some(ModeSelection::Rule));
        assert_eq!(ModeSelection::from_wire("nonsense"), None);

        let receipt = ModeReceipt {
            requested: SelectionMode::Direct,
            effective: SelectionMode::Direct,
            generation_id: Some("g9".into()),
            conflicts: vec![],
        };
        let r = mode_receipt_view(&receipt);
        assert!(r.honored, "冲突空 = 回执承认覆盖生效");

        let conflicted = ModeReceipt {
            requested: SelectionMode::Global,
            effective: SelectionMode::Rule,
            generation_id: None,
            conflicts: vec!["global 出口缺失".into()],
        };
        assert!(!mode_receipt_view(&conflicted).honored);
    }

    #[test]
    fn connections_view_decode_and_honest_empty() {
        let body: Value = serde_json::json!({
            "schema_version": 1u32,
            "total_matching": 2u64,
            "offset": 0u64,
            "limit": 50u64,
            "items": [
                {"flow": "f-1", "origin": "stream", "generation": "g7", "state": "active",
                 "events": 3u64, "first_wall_ms": 1700000000000u64, "last_code": "200"},
                {"flow": "f-2", "origin": null, "generation": null, "state": "closed",
                 "events": null, "first_wall_ms": null, "last_code": 502u64},
                {"origin": "no-flow-id"}
            ]
        });
        let view = connections_view(Some(&body));
        assert_eq!(view.total_matching, StatValue::Known(2));
        assert_eq!(view.rows.len(), 2, "缺 flow id 的行不入投影");
        assert_eq!(view.rows[0].flow, "f-1");
        assert_eq!(view.rows[0].state.as_deref(), Some("active"));
        assert_eq!(view.rows[1].events, StatValue::Unknown, "缺席事件数不落 0");
        assert_eq!(view.rows[1].last_code.as_deref(), Some("502"));
        assert!(!view.known_empty());

        let empty: Value = serde_json::json!({
            "schema_version": 1u32, "total_matching": 0u64,
            "offset": 0u64, "limit": 50u64, "items": []
        });
        assert!(connections_view(Some(&empty)).known_empty());
        // 不可达 = Unknown（不冒充已知空）
        let none = connections_view(None);
        assert!(none.total_matching.is_unknown());
        assert!(none.rows.is_empty());
        assert!(!none.known_empty());
    }

    #[test]
    fn network_page_never_fakes_data() {
        let page = network_page();
        assert!(!page.data_available, "读面未晋升——入口保留，数据不伪装");
        assert!(page.unavailable_reason.contains("闭合操作集"));
    }

    #[test]
    fn developer_page_generates_but_never_writes() {
        let ep = ProxyEndpoints::new("127.0.0.1:7890", "127.0.0.1:7891");
        let v = developer_snippets(
            DevShell::Bash,
            &ep,
            &["github.com"],
            "/home/u/.ssh/config",
            None,
        );
        assert!(!v.can_write_files, "页面/服务只产计划，落盘在 CLI 侧");
        assert!(v.terminal_lines.contains("7890"));
        assert_eq!(
            v.git_lines.len(),
            GIT_CONFIG_KEYS.len() + 1,
            "注释行 + 每键一行 git config"
        );
        assert!(v.git_lines[1].contains("http.proxy"));
        assert!(v.git_lines[2].contains("https.proxy"));
        assert!(v.ssh_block.contains(SSH_MANAGED_MARKER));
        assert!(v.ssh_block.contains("github.com"));
        assert!(forbidden_ssh_lines(&v.ssh_block).is_empty(), "生成块须自洽");
        assert_eq!(v.ssh_write_plan.path, "/home/u/.ssh/config");
        assert!(v.ssh_write_plan.backup_path.ends_with(SSH_BACKUP_SUFFIX));
        assert!(!v.ssh_write_plan.idempotent);
    }

    #[test]
    fn overview_composes_all_surfaces() {
        let stats: Value = serde_json::json!({
            "total_connections": 9u64, "subscription_nodes": 0u64,
            "last_updated_ago_seconds": 2.0f64,
        });
        let audit_v = audit(
            r#"{"live_generation":"g3","reconcile":{"agrees":true},"receipts":[
                {"seq":2,"status":"apply.applied","generation":"g3","os_applied":true}]}"#,
        );
        let view = overview_view(
            Some(&stats),
            Some(&audit_v),
            HostOs::Linux,
            Privilege::Confirmed,
        );
        assert_eq!(view.stats.total_connections, StatValue::Known(9));
        assert_eq!(view.subscription, SubscriptionState::Empty);
        assert_eq!(
            view.takeover,
            TakeoverState::Confirmed {
                generation: "g3".into()
            }
        );
        assert!(view.capabilities.available(CapabilityKind::TunCapture));

        // 全不可达：接管 Unknown + 订阅 Unknown + 统计陈旧，不冒充任何状态
        let dark = overview_view(None, None, HostOs::MacOs, Privilege::Unknown);
        assert!(matches!(dark.takeover, TakeoverState::Unknown { .. }));
        assert_eq!(dark.subscription, SubscriptionState::Unknown);
        assert!(dark.stats.stale);
        assert!(!dark.capabilities.available(CapabilityKind::TunCapture));
    }
}
