//! Windows 进程归属决策面（RIL-034 代码面首段交付）：`OwnerResolver`
//! 的 Windows 表驱动决策层——**OS-free**，Linux 验证席确定性可测（表
//! 探针/身份源可注入，测试钉死全部验收语义）。真机 IO 面
//! （`GetExtendedTcpTable`/`GetExtendedUdpTable` 表探针、
//! `OpenProcess`+`GetProcessTimes`+`QueryFullProcessImageNameW` 身份源
//! FFI）**未落地**——手写从未运行的 FFI 不交付（与 RIL-033
//! wireguard-nt 同纪律），归机批次；验收「同目标多进程、UDP、进程
//! 退出/端口复用/权限失败，unknown 策略均有真机证据」的真机证据归机
//! 批次。
//!
//! 与 Linux [`super::owner_linux::ProcOwnerResolver`] 缓存纪律同构：
//! TTL+容量双界、惰性清退、新鲜才命中。Windows 特有差异——**命中回验
//! 表探针**（`table_probe` 是唯一活源；缓存只省「身份源」这一次贵查
//! 询）：
//! - 命中 Known(pid) → 回验表：`Pid(p)` 且 `p == 缓存 pid` → 返回缓存
//!   （身份源查询被省）；`Pid(p)` 且 `p != 缓存 pid` → **端口/进程复用
//!   立即识别**，缓存作废、按新 pid 现解析；`Absent` → 连接已消失，
//!   缓存作废 → `NotFound`（负缓存同界）；`Denied` → 本次探针被拒，
//!   覆盖缓存返回 `PermissionDenied`（授权可能中途获得——拒绝态**永不
//!   入缓存**，每次现探）；
//! - **具名缺口（不冒充已解）**：表探针无启动时间列——同 pid 同端口
//!   且进程在 TTL 窗口内被复用时，回验只见 pid 相同、身份不重查，旧
//!   身份在 TTL 界内残留。识别它必须每次命中重查身份源（OpenProcess
//!   全代价），缓存即失效——按 TTL 短界（缺省 500ms）+ 真机批次验证
//!   取舍，不在决策面伪装已解决；
//! - UDP 与 TCP 同机制同界（UDP 端点随 socket 关闭即从表消失——负缓存
//!   条目在端口被新进程重绑时由回验自动翻正，无需独立 UDP 策略）。
//!
//! deadline 纪律同契约：先查截止时间再动探针；Unknown ≠ Unsupported
//! 恒分离；本模块不做 unknown 策略应用（`UnknownOwnerPolicy` 由配置/
//! 路由面强制——RIL-015/016）。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::owner::{
    ConnectionKey, OwnerCapability, OwnerResolution, OwnerResolver, ProcessIdentity, UnknownReason,
};

/// Windows 连接表探针结果（真实现 = GetExtendedTcpTable/GetExtendedUdpTable
/// 单行投影；测试 = 注入表）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableProbe {
    /// 表中该连接的归属 PID
    Pid(u32),
    /// 表中无此连接（socket 已关/未建立）
    Absent,
    /// 表读取被拒（权限不足——调用方身份/完整性级别不够）
    Denied,
}

/// 表探针源（连接键 → 当下归属 PID）；真机 FFI 归机批次
pub type WinTableProbe = Arc<dyn Fn(&ConnectionKey) -> TableProbe + Send + Sync>;

/// 身份源（pid → 当下身份）；真机 FFI 归机批次
pub type WinIdentitySource = Arc<dyn Fn(u32) -> Option<ProcessIdentity> + Send + Sync>;

#[derive(Clone)]
struct CacheEntry {
    resolution: OwnerResolution,
    stamp_ms: u64,
}

/// Windows 表驱动归属解析器（RIL-034）：实现 [`OwnerResolver`]。缓存
/// 纪律与 Linux 同构；命中回验表探针（模块头注记的 Windows 差异）。
pub struct WinOwnerResolver {
    table_probe: WinTableProbe,
    identity_source: WinIdentitySource,
    /// 有界缓存：全量 ConnectionKey → 条目（TTL+容量双界、惰性清退）
    cache: Mutex<HashMap<ConnectionKey, CacheEntry>>,
    /// 缓存条目有效期（缺省 500ms——同 pid 复用残留窗口的短界注记见模块头）
    cache_ttl: Duration,
    /// 缓存最大条目数（满时按最旧 stamp 驱逐）
    cache_capacity: usize,
    /// Unix 毫秒时钟（测试注入）
    now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl WinOwnerResolver {
    /// 注入双源构造（测试用；真机装配归机批次 FFI 落地后提供
    /// `with_real_sources()`）
    pub fn new(table_probe: WinTableProbe, identity_source: WinIdentitySource) -> Self {
        Self {
            table_probe,
            identity_source,
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_millis(500),
            cache_capacity: 1024,
            now_unix_ms: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            }),
        }
    }

    /// 调整缓存界（TTL、容量；测试用）
    pub fn with_cache(mut self, ttl: Duration, capacity: usize) -> Self {
        self.cache_ttl = ttl;
        self.cache_capacity = capacity;
        self
    }

    /// 注入时钟（测试用）
    pub fn with_now(mut self, now: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.now_unix_ms = now;
        self
    }

    /// 当前缓存条目数（测试观察有界性用）
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// 查缓存：新鲜才命中；过期顺手清除（惰性清退，无独立 GC 任务）。
    /// 命中 Known 条目还要过表探针回验（模块头：Windows 唯一活源）。
    fn cache_get(&self, key: &ConnectionKey) -> Option<OwnerResolution> {
        let now_ms = (self.now_unix_ms)();
        let mut cache = self.cache.lock().ok()?;
        let ttl_ms = self.cache_ttl.as_millis() as u64;
        let entry = cache.get(key)?;
        if now_ms.saturating_sub(entry.stamp_ms) > ttl_ms {
            cache.remove(key);
            return None;
        }
        let cached = entry.resolution.clone();
        drop(cache);
        self.revalidate(key, cached)
    }

    /// 命中回验：Known 条目对照表探针当下 pid；负缓存（NotFound）条目
    /// 对照表探针当下状态（端口被重绑即翻正为现解析）。Denied/过期由
    /// 调用方先分流。
    fn revalidate(&self, key: &ConnectionKey, cached: OwnerResolution) -> Option<OwnerResolution> {
        match (&cached, (self.table_probe)(key)) {
            (OwnerResolution::Known(identity), TableProbe::Pid(p)) => {
                if p == identity.pid {
                    Some(cached) // 表 pid 未变——身份源重查被缓存省下
                } else {
                    None // 端口/进程复用：缓存作废，走现解析
                }
            }
            (OwnerResolution::Unknown(UnknownReason::NotFound), TableProbe::Absent) => {
                Some(cached) // 负缓存仍成立
            }
            _ => None, // 其余组合一律现解析（复用翻正/缓存类型不符/Denied 覆盖）
        }
    }

    /// 回填缓存；容量满驱逐最旧 stamp 条目再插入。Denied 永不入缓存
    /// （授权可能中途获得）；DeadlineExceeded 不入缓存（非事实性结果）。
    fn cache_put(&self, key: ConnectionKey, resolution: &OwnerResolution) {
        if matches!(
            resolution,
            OwnerResolution::Unknown(UnknownReason::PermissionDenied)
                | OwnerResolution::Unknown(UnknownReason::DeadlineExceeded)
        ) {
            return;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let now_ms = (self.now_unix_ms)();
        while cache.len() >= self.cache_capacity {
            let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, e)| e.stamp_ms)
                .map(|(k, _)| *k)
            else {
                break;
            };
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            CacheEntry {
                resolution: resolution.clone(),
                stamp_ms: now_ms,
            },
        );
    }

    /// 无缓存解析：表探针 → pid → 身份源。Absent=NotFound；Denied=
    /// PermissionDenied（不缓存）；身份源查无（进程刚退）=NotFound。
    fn resolve_uncached(&self, key: &ConnectionKey) -> OwnerResolution {
        match (self.table_probe)(key) {
            TableProbe::Absent => OwnerResolution::Unknown(UnknownReason::NotFound),
            TableProbe::Denied => OwnerResolution::Unknown(UnknownReason::PermissionDenied),
            TableProbe::Pid(pid) => match (self.identity_source)(pid) {
                Some(identity) => OwnerResolution::Known(identity),
                None => OwnerResolution::Unknown(UnknownReason::NotFound),
            },
        }
    }
}

impl OwnerResolver for WinOwnerResolver {
    fn capability(&self) -> OwnerCapability {
        OwnerCapability::Supported
    }

    fn resolve(&self, key: &ConnectionKey, deadline: Instant) -> OwnerResolution {
        // deadline 纪律先于一切（缓存命中也不过在截止后返回旧值）
        if deadline <= Instant::now() {
            return OwnerResolution::Unknown(UnknownReason::DeadlineExceeded);
        }
        if let Some(cached) = self.cache_get(key) {
            return cached;
        }
        let resolution = self.resolve_uncached(key);
        self.cache_put(*key, &resolution);
        resolution
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::super::ports::TransportProtocol;

    fn key_tcp(local_port: u16) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Tcp,
            format!("127.0.0.1:{local_port}")
                .parse::<SocketAddr>()
                .unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        )
    }

    fn key_udp(local_port: u16) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Udp,
            format!("127.0.0.1:{local_port}")
                .parse::<SocketAddr>()
                .unwrap(),
            "8.8.8.8:53".parse().unwrap(),
        )
    }

    fn identity(pid: u32, started_at: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            started_at_unix_ms: Some(started_at),
            executable_path: Some(format!(r"C:\\Program Files\\app{pid}\\app{pid}.exe")),
            process_name: Some(format!("app{pid}.exe")),
            comm_truncated: false,
            user_id: Some(1000),
        }
    }

    /// 可编程双源表：pid 表 + 身份表 + 调用计数（回验省查的观察面）
    struct FakeSources {
        table: Mutex<HashMap<ConnectionKey, TableProbe>>,
        identities: Mutex<HashMap<u32, ProcessIdentity>>,
        table_calls: AtomicU64,
        identity_calls: AtomicU64,
    }

    impl FakeSources {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                table: Mutex::new(HashMap::new()),
                identities: Mutex::new(HashMap::new()),
                table_calls: AtomicU64::new(0),
                identity_calls: AtomicU64::new(0),
            })
        }

        fn bind(&self, key: ConnectionKey, pid: u32, started_at: u64) {
            self.table.lock().unwrap().insert(key, TableProbe::Pid(pid));
            self.identities
                .lock()
                .unwrap()
                .entry(pid)
                .or_insert_with(|| identity(pid, started_at));
        }

        fn absent(&self, key: ConnectionKey) {
            self.table.lock().unwrap().insert(key, TableProbe::Absent);
        }

        fn denied(&self, key: ConnectionKey) {
            self.table.lock().unwrap().insert(key, TableProbe::Denied);
        }

        fn sources(self: &Arc<Self>) -> (WinTableProbe, WinIdentitySource) {
            let table_me = self.clone();
            let table: WinTableProbe = Arc::new(move |key: &ConnectionKey| {
                table_me.table_calls.fetch_add(1, Ordering::SeqCst);
                table_me
                    .table
                    .lock()
                    .unwrap()
                    .get(key)
                    .cloned()
                    .unwrap_or(TableProbe::Absent)
            });
            let ident_me = self.clone();
            let identity: WinIdentitySource = Arc::new(move |pid: u32| {
                ident_me.identity_calls.fetch_add(1, Ordering::SeqCst);
                ident_me.identities.lock().unwrap().get(&pid).cloned()
            });
            (table, identity)
        }
    }

    fn fixed_clock() -> (Arc<dyn Fn() -> u64 + Send + Sync>, Arc<AtomicU64>) {
        let ms = Arc::new(AtomicU64::new(1_000_000));
        let ms2 = ms.clone();
        (Arc::new(move || ms2.load(Ordering::SeqCst)), ms)
    }

    #[test]
    fn win_owner_known_hit_skips_identity_source_and_deadline_first() {
        let fs = FakeSources::new();
        fs.bind(key_tcp(40000), 4242, 1_700_000_000_000);
        let (table, ident) = fs.sources();
        let (now, _ms) = fixed_clock();
        let resolver = WinOwnerResolver::new(table, ident).with_now(now);

        // 首查：表 + 身份源各一次，Known 带完整身份
        let k = key_tcp(40000);
        let r = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(r, OwnerResolution::Known(identity(4242, 1_700_000_000_000)));
        assert_eq!(fs.table_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs.identity_calls.load(Ordering::SeqCst), 1);

        // 命中回验：表探针再次被调（活源），身份源不再查（缓存省下贵查询）
        let r2 = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(r2, r);
        assert_eq!(fs.table_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs.identity_calls.load(Ordering::SeqCst), 1);

        // deadline 纪律先于缓存：过截止 → DeadlineExceeded，探针零调用
        let before = fs.table_calls.load(Ordering::SeqCst);
        let r3 = resolver.resolve(&k, Instant::now() - Duration::from_secs(1));
        assert_eq!(
            r3,
            OwnerResolution::Unknown(UnknownReason::DeadlineExceeded)
        );
        assert_eq!(fs.table_calls.load(Ordering::SeqCst), before);
    }

    #[test]
    fn win_owner_port_reuse_detected_by_table_pid_change() {
        let fs = FakeSources::new();
        fs.bind(key_tcp(41000), 111, 1_700_000_000_000);
        let (table, ident) = fs.sources();
        let (now, ms) = fixed_clock();
        let resolver = WinOwnerResolver::new(table, ident).with_now(now);
        let k = key_tcp(41000);
        assert!(matches!(
            resolver.resolve(&k, Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Known(_)
        ));

        // 进程退出、另一进程绑定同端口（不同 pid）→ 缓存必须翻车重解析
        fs.bind(key_tcp(41000), 222, 1_700_000_500_000);
        let r = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(
            r,
            OwnerResolution::Known(identity(222, 1_700_000_500_000)),
            "端口复用被表 pid 回验识别——旧进程身份不得残留"
        );

        // pid 复用（同 pid 新启动时间）：表 pid 相同 → 决策面只回验 pid；
        // 启动时间残留是模块头具名缺口（TTL 短界 + 真机批次取舍），此处
        // 不伪装成已解决——测试只钉「pid 不同必被识别」这一结构性保证。
        let r2 = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert!(matches!(r2, OwnerResolution::Known(_)));
        let _ = ms;
    }

    #[test]
    fn win_owner_process_exit_flips_to_notfound_and_negative_cache_revives() {
        let fs = FakeSources::new();
        fs.bind(key_udp(53000), 333, 1_700_000_000_000);
        let (table, ident) = fs.sources();
        let (now, _ms) = fixed_clock();
        let resolver = WinOwnerResolver::new(table, ident).with_now(now.clone());
        let k = key_udp(53000);
        assert!(matches!(
            resolver.resolve(&k, Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Known(_)
        ));

        // UDP socket 关闭：端点从表消失 → Known 缓存作废 → NotFound
        fs.absent(k);
        let r = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(r, OwnerResolution::Unknown(UnknownReason::NotFound));
        // NotFound 负缓存命中路径（表探针 Absent 复核成立）
        let r2 = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(r2, OwnerResolution::Unknown(UnknownReason::NotFound));

        // 端口被新进程重绑 → 负缓存条目由回验自动翻正为现解析（无独立
        // UDP 策略——同机制覆盖 TCP/UDP）
        fs.bind(k, 999, 1_700_001_000_000);
        let r3 = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(r3, OwnerResolution::Known(identity(999, 1_700_001_000_000)));
    }

    #[test]
    fn win_owner_permission_denied_never_cached_and_overrides_cache() {
        let fs = FakeSources::new();
        fs.bind(key_tcp(42000), 55, 1_700_000_000_000);
        let (table, ident) = fs.sources();
        let (now, _ms) = fixed_clock();
        let resolver = WinOwnerResolver::new(table, ident).with_now(now.clone());
        let k = key_tcp(42000);
        assert!(matches!(
            resolver.resolve(&k, Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Known(_)
        ));

        // 表读取被拒（权限失败）：覆盖 Known 缓存 → PermissionDenied，
        // 且不入缓存（缓存条目仍在但拒绝态不落盘）
        fs.denied(k);
        let r = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(r, OwnerResolution::Unknown(UnknownReason::PermissionDenied));

        // 授权中途获得（表恢复可读）：立即可查——拒绝态无缓存残留
        fs.bind(key_tcp(42000), 55, 1_700_000_000_000);
        let r2 = resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert!(matches!(r2, OwnerResolution::Known(_)));

        // 纯拒绝键也绝不入缓存（首次即拒）
        let k2 = key_tcp(42001);
        fs.denied(k2);
        assert_eq!(
            resolver.resolve(&k2, Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Unknown(UnknownReason::PermissionDenied)
        );
    }

    #[test]
    fn win_owner_same_target_two_processes_distinct_keys_no_cross_talk() {
        let fs = FakeSources::new();
        // 同目标（同 remote）两进程：仅 local 端口不同
        fs.bind(key_tcp(43000), 71, 1_700_000_000_000);
        fs.bind(key_tcp(43001), 72, 1_700_000_000_000);
        let (table, ident) = fs.sources();
        let (now, _ms) = fixed_clock();
        let resolver = WinOwnerResolver::new(table, ident).with_now(now);
        let a = resolver.resolve(&key_tcp(43000), Instant::now() + Duration::from_secs(1));
        let b = resolver.resolve(&key_tcp(43001), Instant::now() + Duration::from_secs(1));
        assert_eq!(a, OwnerResolution::Known(identity(71, 1_700_000_000_000)));
        assert_eq!(b, OwnerResolution::Known(identity(72, 1_700_000_000_000)));

        // 一边进程退出不影响另一边缓存命中
        fs.absent(key_tcp(43000));
        assert_eq!(
            resolver.resolve(&key_tcp(43000), Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Unknown(UnknownReason::NotFound)
        );
        assert!(matches!(
            resolver.resolve(&key_tcp(43001), Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Known(_)
        ));
    }

    #[test]
    fn win_owner_cache_bounds_ttl_and_capacity_and_absent_negative() {
        let fs = FakeSources::new();
        fs.bind(key_tcp(44000), 81, 1_700_000_000_000);
        let (table, ident) = fs.sources();
        let (now, ms) = fixed_clock();
        let resolver = WinOwnerResolver::new(table, ident)
            .with_cache(Duration::from_millis(100), 2)
            .with_now(now);
        let k = key_tcp(44000);
        resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert_eq!(resolver.cache_len(), 1);

        // TTL 过界：条目惰性清除 → 现解析（表+身份源再各一次）
        ms.store(1_000_000 + 500, Ordering::SeqCst);
        let before_id = fs.identity_calls.load(Ordering::SeqCst);
        resolver.resolve(&k, Instant::now() + Duration::from_secs(1));
        assert!(
            fs.identity_calls.load(Ordering::SeqCst) > before_id,
            "过期后身份源重查"
        );

        // 容量双界：满 2 后插入第 3 条驱逐最旧
        fs.bind(key_tcp(44001), 82, 1_700_000_000_000);
        fs.bind(key_tcp(44002), 83, 1_700_000_000_000);
        resolver.resolve(&key_tcp(44001), Instant::now() + Duration::from_secs(1));
        resolver.resolve(&key_tcp(44002), Instant::now() + Duration::from_secs(1));
        assert_eq!(resolver.cache_len(), 2, "容量上界不超过 2");

        // 表 Absent（无身份源查询）→ NotFound 且入负缓存（同界）
        let k3 = key_tcp(44999);
        fs.absent(k3);
        assert_eq!(
            resolver.resolve(&k3, Instant::now() + Duration::from_secs(1)),
            OwnerResolution::Unknown(UnknownReason::NotFound)
        );
        let before_table = fs.table_calls.load(Ordering::SeqCst);
        resolver.resolve(&k3, Instant::now() + Duration::from_secs(1));
        assert!(
            fs.table_calls.load(Ordering::SeqCst) > before_table,
            "负缓存命中仍回验表（活源纪律）"
        );
    }
}
