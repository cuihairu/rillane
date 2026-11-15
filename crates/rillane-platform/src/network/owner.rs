//! 本机身份契约（RIL-005）：OwnerResolver、Known/Unknown/Unsupported 三
//! 态、查询截止时间与 unknown 策略。三桌面（Windows/macOS/Linux）身份用
//! PID + 启动身份/连接键 + 可执行路径组合验证——不能只缓存 PID；其余
//! 平台不强制提供 PID（`OwnerResolution::Unsupported`），也不得伪造。
//!
//! 硬边界（RIL-005 验收）：
//! - 首包查询走预算与截止时间（`deadline`）；超时/权限不足返回
//!   `Unknown(reason)`，绝不无限等；
//! - `Unknown` ≠ `Unsupported`：前者「有能力但本次没查到」，后者「平台
//!   根本无该能力」——下游必须可区分；
//! - 失败不能静默直连：`UnknownOwnerPolicy` 只有显式枚举（拒绝/指定回
//!   退组/用户显式直连），不存在「隐式直连」变体；依赖进程身份的配置
//!   必须声明其一（RIL-015/016 在配置面强制）。
//!
//! Linux /proc 真实实现归 RIL-030；契约测试用内存 mock 钉语义。

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::ports::TransportProtocol;

/// 连接键（RIL-005）：定位一条本机流以查询归属。四元组与传输协议共同
/// 唯一；同源多连接（同目标两进程）靠 local 侧端口区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    /// 传输协议
    pub transport: TransportProtocol,
    /// 本地侧地址（发起连接的本机 socket）
    pub local: SocketAddr,
    /// 远端地址（流的目标）
    pub remote: SocketAddr,
}

impl ConnectionKey {
    /// 构造连接键
    pub fn new(transport: TransportProtocol, local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            transport,
            local,
            remote,
        }
    }
}

/// 进程身份（RIL-005）：PID + 启动身份组合——PID 复用靠
/// `started_at_unix_ms` 防护，不能只信 PID。名称/路径分开建模：Linux
/// comm 截断（15 字符）不得冒充完整可执行名（`comm_truncated` 如实标注）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// 进程 ID
    pub pid: u32,
    /// 进程启动时间（Unix 毫秒；PID 复用防护。None = 平台未提供）
    pub started_at_unix_ms: Option<u64>,
    /// 完整可执行路径（None = 不可得，不以短名冒充）
    pub executable_path: Option<String>,
    /// 短名/comm（可能被截断）
    pub process_name: Option<String>,
    /// comm/短名是否被平台截断
    pub comm_truncated: bool,
    /// 用户 ID
    pub user_id: Option<u32>,
}

impl ProcessIdentity {
    /// 同一进程判定（验收「PID 启动身份可验证」）：PID 相同**且**启动
    /// 身份一致。启动时间两侧都缺失时按「不可验证」处理——返回 false，
    /// 不猜：调用方须按 Unknown 策略兜底。路径/用户变化（exec、提权）
    /// 不改变进程身份，由调用方按需另行比较。
    pub fn same_process(&self, other: &Self) -> bool {
        if self.pid != other.pid {
            return false;
        }
        match (self.started_at_unix_ms, other.started_at_unix_ms) {
            (Some(a), Some(b)) => a == b,
            // 启动身份缺失即不可验证，不判同（宁可重查，不误归因）
            _ => false,
        }
    }
}

/// Unknown 细分原因：有能力但本次没查到——各原因下游可分别诊断/上报。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    /// 查询截止时间已过（预算口径，不无限等）
    DeadlineExceeded,
    /// 权限不足（如 /proc 读受限、未授权）
    PermissionDenied,
    /// 连接不存在（已关闭/尚未建立/非本机连接）
    NotFound,
    /// 首包预算耗尽（每流查询次数上限）
    BudgetExhausted,
}

/// 归属解析结果（RIL-005）：三态显式分离。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerResolution {
    /// 查到归属：携带可验证身份（PID + 启动身份 + 路径/用户）
    Known(ProcessIdentity),
    /// 有能力但本次没查到：携带原因（按 unknown 策略处理）
    Unknown(UnknownReason),
    /// 平台根本无本机归因能力（三桌面之外）：不提供也不伪造 PID
    Unsupported,
}

/// 平台本机归因能力（配置校验期探测用；运行期三态由
/// [`OwnerResolution`] 承载）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerCapability {
    /// 支持本机归因（三桌面）
    Supported,
    /// 该平台不提供本机归因（不强制；进程规则配置须显式处理）
    NotAvailableOnPlatform,
}

/// 本机归属解析器（RIL-005）：按连接键解析流的本机进程身份。
/// `deadline` 是绝对截止时间——实现必须在截止前返回，超时返回
/// `Unknown(DeadlineExceeded)`；平台无能力实现 `capability()` 返回
/// `NotAvailableOnPlatform` 且 `resolve` 返回 `Unsupported`。
pub trait OwnerResolver: Send + Sync {
    /// 能力声明（配置校验期）
    fn capability(&self) -> OwnerCapability;

    /// 解析一条连接的本机归属
    fn resolve(&self, key: &ConnectionKey, deadline: Instant) -> OwnerResolution;
}

/// unknown 策略（RIL-005）：依赖进程身份的规则在身份不可得
/// （`Unknown`/`Unsupported`）时的显式行为。**不存在隐式直连变体**——
/// 直连只能是用户显式声明（`ExplicitDirect`），验收「失败不能静默直连」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownOwnerPolicy {
    /// 拒绝（安全失败）：按 REJECT 处理该流
    Reject,
    /// 回退到显式命名的策略组（不得是匿名/隐式目标）
    FallbackGroup(String),
    /// 用户显式选择直连（诊断按显式决策记录，不与静默直连混淆）
    ExplicitDirect,
}

impl UnknownOwnerPolicy {
    /// 策略的可解释口径（诊断/Explain 用；穷尽 match 保证新增变体必接线）
    pub fn describe(&self) -> String {
        match self {
            UnknownOwnerPolicy::Reject => "身份未知 → 拒绝".to_string(),
            UnknownOwnerPolicy::FallbackGroup(group) => {
                format!("身份未知 → 回退组 {group}")
            }
            UnknownOwnerPolicy::ExplicitDirect => "身份未知 → 显式直连（用户声明）".to_string(),
        }
    }
}

/// 内存 mock 解析器（契约测试用）：按连接键查表；`fake_now` 驱动截止
/// 时间判定（不真实睡眠）；`capability()` 可配置以覆盖 Unsupported 路径。
pub struct InMemoryOwnerResolver {
    known: HashMap<ConnectionKey, ProcessIdentity>,
    permission_denied: Vec<ConnectionKey>,
    capability: OwnerCapability,
    fake_now: Instant,
}

impl InMemoryOwnerResolver {
    /// 空 mock（Supported、无已知身份）
    pub fn new() -> Self {
        Self {
            known: HashMap::new(),
            permission_denied: Vec::new(),
            capability: OwnerCapability::Supported,
            fake_now: Instant::now(),
        }
    }

    /// 登记一条已知归属
    pub fn with_owner(mut self, key: ConnectionKey, identity: ProcessIdentity) -> Self {
        self.known.insert(key, identity);
        self
    }

    /// 标记某连接查询必返权限不足
    pub fn with_permission_denied(mut self, key: ConnectionKey) -> Self {
        self.permission_denied.push(key);
        self
    }

    /// 配置平台能力
    pub fn with_capability(mut self, capability: OwnerCapability) -> Self {
        self.capability = capability;
        self
    }

    /// 推进 mock 时钟
    pub fn advance_now(&mut self, delta: Duration) {
        self.fake_now += delta;
    }
}

impl Default for InMemoryOwnerResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnerResolver for InMemoryOwnerResolver {
    fn capability(&self) -> OwnerCapability {
        self.capability
    }

    fn resolve(&self, key: &ConnectionKey, deadline: Instant) -> OwnerResolution {
        if self.capability == OwnerCapability::NotAvailableOnPlatform {
            // 平台无能力：Unsupported，绝不伪造身份
            return OwnerResolution::Unsupported;
        }
        if deadline <= self.fake_now {
            return OwnerResolution::Unknown(UnknownReason::DeadlineExceeded);
        }
        if self.permission_denied.contains(key) {
            return OwnerResolution::Unknown(UnknownReason::PermissionDenied);
        }
        match self.known.get(key) {
            Some(identity) => OwnerResolution::Known(identity.clone()),
            None => OwnerResolution::Unknown(UnknownReason::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(local_port: u16) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Tcp,
            format!("127.0.0.1:{local_port}").parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        )
    }

    fn identity(pid: u32, started_at: Option<u64>) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            started_at_unix_ms: started_at,
            executable_path: Some(format!("/usr/bin/p{pid}")),
            process_name: Some(format!("p{pid}")),
            comm_truncated: false,
            user_id: Some(1000),
        }
    }

    #[test]
    fn pid_reuse_detected_by_start_identity() {
        // 验收：PID 启动身份/连接键可验证——同 PID 不同启动时间 = 不同进程
        let a = identity(42, Some(1_700_000_000_000));
        let b = identity(42, Some(1_700_000_000_000));
        let reused = identity(42, Some(1_700_050_000_000));
        assert!(a.same_process(&b), "同 PID 同启动时间 = 同一进程");
        assert!(
            !a.same_process(&reused),
            "PID 复用必须被启动身份识别，不能误归因"
        );
        // 启动身份缺失 = 不可验证，不猜
        let no_start = identity(42, None);
        assert!(!a.same_process(&no_start));

        // 连接键：同目标两连接靠 local 端口区分
        assert_ne!(key(40000), key(40001));
        assert_eq!(key(40000), key(40000));
    }

    #[test]
    fn known_unknown_unsupported_are_three_distinct_states() {
        let resolver = InMemoryOwnerResolver::new().with_owner(key(40000), identity(7, Some(1)));
        let k = key(40000);

        // Known：身份可验证（PID + 启动时间 + 路径/用户齐备）
        let known = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert!(matches!(known, OwnerResolution::Known(_)));
        let OwnerResolution::Known(id) = known else {
            unreachable!()
        };
        assert_eq!(id.pid, 7);
        assert_eq!(id.started_at_unix_ms, Some(1));

        // Unknown(NotFound)：连接不在表内
        let missing = resolver.resolve(&key(40002), Instant::now() + Duration::from_secs(1));
        assert_eq!(missing, OwnerResolution::Unknown(UnknownReason::NotFound));

        // Unsupported：平台无能力 ≠ Unknown，不伪造 PID（三桌面外不强制）
        let bare =
            InMemoryOwnerResolver::new().with_capability(OwnerCapability::NotAvailableOnPlatform);
        let unsupported = bare.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(unsupported, OwnerResolution::Unsupported);
        assert_ne!(
            unsupported,
            OwnerResolution::Unknown(UnknownReason::NotFound)
        );
        assert_eq!(bare.capability(), OwnerCapability::NotAvailableOnPlatform);
    }

    #[test]
    fn deadline_bounds_every_query() {
        // 截止时间已过：立即 DeadlineExceeded，不无限等
        let mut resolver =
            InMemoryOwnerResolver::new().with_owner(key(40000), identity(7, Some(1)));
        let k = key(40000);
        let deadline = Instant::now() + Duration::from_millis(50);
        assert_eq!(
            resolver.resolve(&k, deadline),
            OwnerResolution::Known(identity(7, Some(1)))
        );
        resolver.advance_now(Duration::from_secs(1));
        assert_eq!(
            resolver.resolve(&k, deadline),
            OwnerResolution::Unknown(UnknownReason::DeadlineExceeded),
            "过截止时间的查询不再成功"
        );
    }

    #[test]
    fn permission_denied_is_unknown_not_silent_direct() {
        let resolver = InMemoryOwnerResolver::new().with_permission_denied(key(40000));
        let resolution = resolver.resolve(&key(40000), Instant::now() + Duration::from_secs(1));
        assert_eq!(
            resolution,
            OwnerResolution::Unknown(UnknownReason::PermissionDenied)
        );

        // 验收「失败不能静默直连」：策略穷尽匹配，无隐式直连变体；
        // 直连只能是显式声明
        for policy in [
            UnknownOwnerPolicy::Reject,
            UnknownOwnerPolicy::FallbackGroup("game-default".into()),
            UnknownOwnerPolicy::ExplicitDirect,
        ] {
            let described = policy.describe();
            assert!(!described.is_empty());
            // 每个变体都给出显式去向；「显式直连」字样只在用户声明变体出现
            assert_eq!(
                described.contains("显式直连"),
                policy == UnknownOwnerPolicy::ExplicitDirect
            );
        }
    }
}
