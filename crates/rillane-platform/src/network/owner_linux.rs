//! Linux 本机身份真实实现（RIL-030）：/proc/net/{tcp,tcp6,udp,udp6}
//! 四元组→inode，/proc/<pid>/fd socket 链接 inode→pid，
//! /proc/<pid>/{stat,comm,exe,status} → [`ProcessIdentity`]。
//!
//! 边界（验收口径）：
//! - **namespace 边界**：`/proc/net` 是按网络命名空间挂载的视图——
//!   本解析器只见**当前 netns** 的 socket；其它 netns 的连接查不到，
//!   如实返回 `Unknown(NotFound)`，不伪造。PID 命名空间同理：只扫描
//!   可见的 pid 目录，看不到就查不到。
//! - **权限边界**：`hidepid` 挂载或他人进程的 fd 目录不可列时记录
//!   「权限盲区」——盲区落在本次查询路径上（fd 扫描没能穷尽全部
//!   进程）且未命中时，返回 `Unknown(PermissionDenied)` 而**不是
//!   NotFound**：分不清「不存在」和「看不见」时按看不见报，绝不
//!   伪造身份。exe readlink 受 ptrace_scope 限制读不到时按契约给
//!   `executable_path: None`（不以 comm 短名冒充完整路径），其余可
//!   验证字段照常返回——`started_at`（stat+btime）是 Known 的硬性
//!   要求，缺启动身份就不判 Known（PID 复用不误归因）。
//! - **有界缓存**：[`ProcOwnerResolver`] 内置按 ConnectionKey 的
//!   TTL+容量双界缓存（缺省 1s / 1024 条，满按最旧时间戳驱逐）。
//!   缓存键是全量四元组+协议；过期即重查——端口被新进程复用后最迟
//!   一个 TTL 内旧身份失效，不跨复用期误归因。
//! - **截止时间**：解析入口、逐表文件、逐 pid 目录、身份读取前都查
//!   `deadline`，超时立即 `Unknown(DeadlineExceeded)`，不无限等。
//!
//! fork 共享 socket 说明：多进程共享同一 inode（fork 后未关）时，
//! 归因到其中之一都是真 owner——本实现取扫描序首见者；不做跨进程
//! 合谋判定（超出契约面）。未 connect 的 UDP 在表里只有一行通配
//! 远端，多 socket 绑同一本地地址（SO_REUSEPORT）时取表序首行。
//!
//! 测试面：`proc_root` 可注入（假 proc 树）、时钟可注入——全部验收
//! 项（PID/端口复用、UDP、权限不足、comm 截断、同目标两进程）在假
//! 树单测钉死；真机 /proc 集成测在 `tests/owner_linux_contract.rs`。

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::network::owner::{
    ConnectionKey, OwnerCapability, OwnerResolution, OwnerResolver, ProcessIdentity, UnknownReason,
};
use crate::network::ports::TransportProtocol;

/// /proc stat 启动时间的时基：proc(5) 规定 utime/starttime 等
/// 以 USER_HZ（用户态 ABI 固定 100）为单位，不随内核 HZ 配置变化。
const USER_HZ: u64 = 100;

/// 内核 comm 可见长度上限：TASK_COMM_LEN=16 含 NUL → 可见 15 字符。
const COMM_MAX: usize = 15;

/// 有界缓存条目：解析结果 + 写入时戳（注入时钟的 Unix 毫秒）。
#[derive(Clone)]
struct CacheEntry {
    resolution: OwnerResolution,
    stamp_ms: u64,
}

/// Linux /proc 归属解析器（RIL-030）：实现 [`OwnerResolver`]。
pub struct ProcOwnerResolver {
    /// /proc 根（真实机为 `/proc`；测试注入假树）
    proc_root: PathBuf,
    /// 有界缓存：全量 ConnectionKey → 条目（TTL+容量双界）
    cache: Mutex<HashMap<ConnectionKey, CacheEntry>>,
    /// 缓存条目有效期
    cache_ttl: Duration,
    /// 缓存最大条目数（满时按最旧 stamp 驱逐）
    cache_capacity: usize,
    /// fd 扫描权限盲区记录位：本轮扫描有读不到的 /proc/<pid>/fd
    /// 目录时置位——未命中时 NotFound 升级为 PermissionDenied
    scan_blind: AtomicBool,
    /// Unix 毫秒时钟（测试注入）
    now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl ProcOwnerResolver {
    /// 真实机解析器：/proc + 1s TTL + 1024 条上限。
    pub fn new() -> Self {
        Self::with_paths(Path::new("/proc"))
    }

    /// 指定 proc 根（测试注入假树）。
    pub fn with_paths(proc_root: &Path) -> Self {
        Self {
            proc_root: proc_root.to_path_buf(),
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(1),
            cache_capacity: 1024,
            scan_blind: AtomicBool::new(false),
            now_unix_ms: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            }),
        }
    }

    /// 调整缓存界（TTL、容量；测试用）。
    pub fn with_cache(mut self, ttl: Duration, capacity: usize) -> Self {
        self.cache_ttl = ttl;
        self.cache_capacity = capacity;
        self
    }

    /// 注入时钟（测试用）。
    pub fn with_now(mut self, now: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.now_unix_ms = now;
        self
    }

    /// 当前缓存条目数（测试观察有界性用）。
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// 查缓存：新鲜才命中；过期顺手清除（延迟清扫，无独立 GC 任务）。
    fn cache_get(&self, key: &ConnectionKey) -> Option<OwnerResolution> {
        let now_ms = (self.now_unix_ms)();
        let mut cache = self.cache.lock().ok()?;
        let ttl_ms = self.cache_ttl.as_millis() as u64;
        if let Some(entry) = cache.get(key) {
            if now_ms.saturating_sub(entry.stamp_ms) <= ttl_ms {
                return Some(entry.resolution.clone());
            }
            cache.remove(key);
        }
        None
    }

    /// 回填缓存；容量满驱逐最旧 stamp 条目再插入。
    fn cache_put(&self, key: ConnectionKey, resolution: OwnerResolution) {
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
                resolution,
                stamp_ms: now_ms,
            },
        );
    }

    /// 无缓存解析：四元组→inode → pid → 身份，三段都受 deadline 约束。
    fn resolve_uncached(&self, key: &ConnectionKey, deadline: Instant) -> OwnerResolution {
        let inode = match self.find_inode(key, deadline) {
            Ok(Some(inode)) => inode,
            Ok(None) => return OwnerResolution::Unknown(UnknownReason::NotFound),
            Err(()) => return OwnerResolution::Unknown(UnknownReason::DeadlineExceeded),
        };
        let pid = match self.find_pid(inode, deadline) {
            Ok(Some(pid)) => pid,
            Ok(None) => {
                // 表里有行但 fd 扫不到：要么正在关闭，要么扫描有权限
                // 盲区——有盲区时如实报 PermissionDenied，不冒充 NotFound。
                if self.scan_blind.load(Ordering::Relaxed) {
                    return OwnerResolution::Unknown(UnknownReason::PermissionDenied);
                }
                return OwnerResolution::Unknown(UnknownReason::NotFound);
            }
            Err(()) => return OwnerResolution::Unknown(UnknownReason::DeadlineExceeded),
        };
        match self.identity_of(pid, deadline) {
            Ok(identity) => OwnerResolution::Known(identity),
            Err(IdentityError::Permission) => {
                OwnerResolution::Unknown(UnknownReason::PermissionDenied)
            }
            // pid 在 fd 命中与身份读取之间退出，或身份文件损坏——
            // 按「本次没查到」处理，绝不返回无启动身份的 Known。
            Err(IdentityError::Gone) | Err(IdentityError::Malformed) => {
                OwnerResolution::Unknown(UnknownReason::NotFound)
            }
            Err(IdentityError::Deadline) => {
                OwnerResolution::Unknown(UnknownReason::DeadlineExceeded)
            }
        }
    }

    /// 四元组 → socket inode。查 tcp/tcp6/udp/udp6 四表；UDP 精确
    /// 匹配失败回退「仅本地侧匹配」（未 connect 的 UDP 行远端是通配
    /// 0.0.0.0:0，应用层键却带真实远端——不能因内核未记录远端就查无）。
    fn find_inode(&self, key: &ConnectionKey, deadline: Instant) -> Result<Option<u64>, ()> {
        let (tables, transport) = match key.transport {
            TransportProtocol::Tcp => (["tcp", "tcp6"], TransportProtocol::Tcp),
            TransportProtocol::Udp => (["udp", "udp6"], TransportProtocol::Udp),
        };
        let mut udp_local_fallback: Option<u64> = None;
        for name in tables {
            if Instant::now() >= deadline {
                return Err(());
            }
            let path = self.proc_root.join("net").join(name);
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            for row in raw.lines().skip(1) {
                let Some(entry) = parse_sock_row(row, transport) else {
                    continue;
                };
                if entry.local == key.local && entry.remote == key.remote {
                    return Ok(Some(entry.inode));
                }
                if transport == TransportProtocol::Udp
                    && entry.local == key.local
                    && udp_local_fallback.is_none()
                {
                    udp_local_fallback = Some(entry.inode);
                }
            }
            if Instant::now() >= deadline {
                return Err(());
            }
        }
        Ok(udp_local_fallback)
    }

    /// socket inode → pid：扫 /proc/<pid>/fd/*，readlink 出
    /// `socket:[inode]` 即命中。fd 目录不可列（他人进程/hidepid）置
    /// 权限盲区位——本次查询的可见性不再完备。
    fn find_pid(&self, inode: u64, deadline: Instant) -> Result<Option<u32>, ()> {
        self.scan_blind.store(false, Ordering::Relaxed);
        let dirs = match fs::read_dir(&self.proc_root) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        for dir in dirs {
            if Instant::now() >= deadline {
                return Err(());
            }
            let Ok(dir) = dir else { continue };
            let Ok(name) = dir.file_name().into_string() else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue; // 非数字目录（acpi/irq/…）不是进程
            };
            let Ok(fds) = fs::read_dir(dir.path().join("fd")) else {
                // 权限盲区：这个 pid 可能持有目标 socket，但我们看不见
                self.scan_blind.store(true, Ordering::Relaxed);
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = fs::read_link(fd.path()) {
                    if target.to_str() == Some(&format!("socket:[{inode}]")) {
                        return Ok(Some(pid));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(());
            }
        }
        Ok(None)
    }

    /// pid → 身份。stat+btime 是 Known 硬性要求（启动身份可验证）；
    /// exe 读不到给 None（不冒充）；comm ≥15 字符标 comm_truncated。
    fn identity_of(&self, pid: u32, deadline: Instant) -> Result<ProcessIdentity, IdentityError> {
        if Instant::now() >= deadline {
            return Err(IdentityError::Deadline);
        }
        let dir = self.proc_root.join(pid.to_string());
        // 启动身份：stat 字段 22（starttime ticks）+ /proc/stat btime
        let stat_raw = fs::read_to_string(dir.join("stat")).map_err(map_identity_err)?;
        let start_ticks = parse_stat_starttime(&stat_raw).ok_or(IdentityError::Malformed)?;
        let btime_sec = self.boottime_unix_sec().ok_or(IdentityError::Malformed)?;
        let started_at_unix_ms = Some(btime_sec * 1000 + start_ticks * 1000 / USER_HZ);

        // comm：/proc/<pid>/comm 优先，stat 括号字段兜底（同受 15 字符
        // 内核上限约束，截断规则一致）
        let (comm, truncated) = match fs::read_to_string(dir.join("comm")) {
            Ok(raw) => {
                let trimmed = raw.trim_end_matches('\n');
                (trimmed.to_string(), trimmed.len() >= COMM_MAX)
            }
            Err(_) => {
                let name = parse_stat_comm(&stat_raw).ok_or(IdentityError::Malformed)?;
                let truncated = name.len() >= COMM_MAX;
                (name, truncated)
            }
        };

        // 完整可执行路径：readlink /proc/<pid>/exe；读不到 = 不可得，
        // 不以 comm 短名冒充（契约：None 是显式状态）
        let executable_path = fs::read_link(dir.join("exe"))
            .ok()
            .and_then(|p| p.into_string().ok());

        // user_id：status Uid 行（真实 uid），读不到按不可得
        let user_id = fs::read_to_string(dir.join("status"))
            .ok()
            .and_then(|raw| parse_status_uid(&raw));

        Ok(ProcessIdentity {
            pid,
            started_at_unix_ms,
            executable_path,
            process_name: Some(comm),
            comm_truncated: truncated,
            user_id,
        })
    }

    /// /proc/stat 的 btime（Unix 秒）；假树缺失/损坏返回 None。
    fn boottime_unix_sec(&self) -> Option<u64> {
        let raw = fs::read_to_string(self.proc_root.join("stat")).ok()?;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("btime ") {
                return rest.trim().parse().ok();
            }
        }
        None
    }
}

impl Default for ProcOwnerResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnerResolver for ProcOwnerResolver {
    fn capability(&self) -> OwnerCapability {
        OwnerCapability::Supported
    }

    fn resolve(&self, key: &ConnectionKey, deadline: Instant) -> OwnerResolution {
        // 已过截止：不动缓存不动 IO，立即失败
        if Instant::now() >= deadline {
            return OwnerResolution::Unknown(UnknownReason::DeadlineExceeded);
        }
        if let Some(hit) = self.cache_get(key) {
            return hit;
        }
        let resolution = self.resolve_uncached(key, deadline);
        // 全部结果（含 Unknown）都进缓存：同一连接短窗内重复查询不重复
        // 扫表；Unknown 受同一 TTL 界——连接建立/进程换手最迟 TTL 后
        // 可查到新状态。
        self.cache_put(*key, resolution.clone());
        resolution
    }
}

// —— 解析纯函数（无 IO，单测直钉字节级语义） ——

/// /proc/net 单行的中立形态。
struct SockRow {
    local: SocketAddr,
    remote: SocketAddr,
    inode: u64,
}

/// 解析 /proc/net/{tcp,udp,…} 数据行：
/// `sl: local_hex:port remote_hex:port st tx:rx tr:when retrnsmt uid timeout inode …`
/// inode 是第 10 个空白分隔字段（索引 9）。协议由表文件名决定、调用方
/// 传入（行本身不带）。
fn parse_sock_row(row: &str, transport: TransportProtocol) -> Option<SockRow> {
    let cols: Vec<&str> = row.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }
    let (local_hex, local_port) = split_hex_addr(cols[1])?;
    let (remote_hex, remote_port) = split_hex_addr(cols[2])?;
    let inode = cols[9].parse().ok()?;
    let local = SocketAddr::new(hex_bytes_to_ip(local_hex)?, local_port);
    let remote = SocketAddr::new(hex_bytes_to_ip(remote_hex)?, remote_port);
    let _ = transport; // 协议已由表名决定，行内无此字段
    Some(SockRow {
        local,
        remote,
        inode,
    })
}

/// `0100007F:D9B7` → (hex 主体, 十六进制端口)。
fn split_hex_addr(field: &str) -> Option<(&str, u16)> {
    let (hex, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((hex, port))
}

/// 小端十六进制串 → IP。IPv4 长度 8（一个 LE u32）；IPv6 长度 32
/// （四个 LE u32 依序铺 bytes[0..16]）。其余长度一律 None。
fn hex_bytes_to_ip(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let v = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(v.to_le_bytes())))
        }
        32 => {
            let bytes_hex = hex.as_bytes();
            let mut bytes = [0u8; 16];
            for (group, slot) in bytes_hex.chunks(8).zip(bytes.chunks_mut(4)) {
                let s = std::str::from_utf8(group).ok()?;
                let v = u32::from_str_radix(s, 16).ok()?;
                slot.copy_from_slice(&v.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// /proc/<pid>/stat：首个 `(` 与最后一个 `)` 之间是 comm（可含空格/
/// 括号）；`) ` 之后 state 是字段 3——starttime（字段 22）即 comm 后
/// 第 20 个空白字段（0 基索引 19，含 state 本身）。
fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let mut after = stat[close + 1..].split_whitespace();
    after.nth(19)?.parse().ok()
}

/// stat 括号里的 comm（comm 文件读不到时的兜底）。
fn parse_stat_comm(stat: &str) -> Option<String> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    Some(stat[open + 1..close].to_string())
}

/// /proc/<pid>/status 的 `Uid:\t<real>\t<effective>\t<saved>\t<fs>` → 真实 uid。
fn parse_status_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// 身份读取失败的细分。
enum IdentityError {
    /// 目录/文件 EACCES（hidepid、他人进程）——权限不足不误归因
    Permission,
    /// ENOENT：进程已退出——按本次没查到
    Gone,
    /// 文件在但内容解析不出——环境损坏，按本次没查到
    Malformed,
    /// 截止时间到
    Deadline,
}

fn map_identity_err(e: std::io::Error) -> IdentityError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => IdentityError::Permission,
        std::io::ErrorKind::NotFound => IdentityError::Gone,
        _ => IdentityError::Malformed,
    }
}

// —— 假 proc 树单测（RIL-030 验收项全部在此钉死） ——

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// 唯一临时假 proc 根。
    fn fake_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ril030-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    /// /proc/<pid>/stat 行：`)` 后 state(字段3) 起 19 个字段到
    /// itrealvalue(字段21)，starttime 是字段 22。
    fn stat_line(comm: &str, start_ticks: u64) -> String {
        format!("123 ({comm}) S {}{start_ticks} 0 0 0 0\n", "0 ".repeat(18))
    }

    fn write_proc_pid(
        root: &Path,
        pid: u32,
        inodes: &[u64],
        start_ticks: u64,
        comm: &str,
        exe: &str,
    ) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(dir.join("fd")).unwrap();
        for (i, inode) in inodes.iter().enumerate() {
            symlink(
                format!("socket:[{inode}]"),
                dir.join("fd").join(i.to_string()),
            )
            .unwrap();
        }
        write(&dir.join("stat"), &stat_line(comm, start_ticks));
        write(&dir.join("comm"), &format!("{comm}\n"));
        symlink(exe, dir.join("exe")).unwrap();
        write(
            &dir.join("status"),
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n",
        );
    }

    /// 表行：小端十六进制地址。
    fn sock_row(local_hex_port: &str, remote_hex_port: &str, inode: u64) -> String {
        format!(
            "   0: {local_hex_port} {remote_hex_port} 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 ffff0000 100 0 0 10 0\n"
        )
    }

    fn write_net_table(root: &Path, name: &str, rows: &[String]) {
        let mut body = String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid timeout inode\n");
        for r in rows {
            body.push_str(r);
        }
        write(&root.join("net").join(name), &body);
    }

    fn write_btime(root: &Path, btime: u64) {
        write(
            &root.join("stat"),
            &format!("cpu  0 0 0 0 0 0 0 0 0 0\nbtime {btime}\n"),
        );
    }

    fn key_tcp(local_port: u16, remote: &str) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Tcp,
            format!("127.0.0.1:{local_port}").parse().unwrap(),
            remote.parse().unwrap(),
        )
    }

    fn key_udp(local_port: u16, remote: &str) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Udp,
            format!("127.0.0.1:{local_port}").parse().unwrap(),
            remote.parse().unwrap(),
        )
    }

    /// 固定毫秒时钟。
    fn fixed_clock(
        start_ms: u64,
    ) -> (
        Arc<std::sync::atomic::AtomicU64>,
        ProcOwnerResolver,
        PathBuf,
    ) {
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(start_ms));
        let root = fake_root("clock");
        let resolver = ProcOwnerResolver::with_paths(&root).with_now({
            let clock = clock.clone();
            Arc::new(move || clock.load(Ordering::Relaxed))
        });
        (clock, resolver, root)
    }

    #[test]
    fn hex_row_parsing_is_little_endian() {
        // 0100007F 小端 u32 → 7F 00 00 01 → 127.0.0.1；端口十六进制直读
        let row = parse_sock_row(
            &sock_row("0100007F:D9B7", "01020304:01BB", 1)[..],
            TransportProtocol::Tcp,
        )
        .unwrap();
        assert_eq!(row.local, "127.0.0.1:55735".parse::<SocketAddr>().unwrap());
        assert_eq!(row.remote, "4.3.2.1:443".parse::<SocketAddr>().unwrap());
        assert_eq!(row.inode, 1);

        // IPv6：四组 LE u32 铺 16 字节——00000000000000000000000001000000 = ::1
        let v6 = parse_sock_row(
            "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1",
            TransportProtocol::Tcp,
        )
        .unwrap();
        assert_eq!(v6.local, "[::1]:22".parse::<SocketAddr>().unwrap());
        assert_eq!(v6.inode, 99);

        // 坏行：字段不足 / 非十六进制——None 不猜
        assert!(parse_sock_row("  0: 0100007F 0A", TransportProtocol::Tcp).is_none());
        assert!(parse_sock_row(
            "xx: zz:00 zz:00 01 0 0 0 0 notanumber 1",
            TransportProtocol::Tcp
        )
        .is_none());
    }

    #[test]
    fn tcp_known_identity_from_fake_proc() {
        let root = fake_root("tcp-known");
        write_btime(&root, 1_700_000_000);
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C40", "01020304:01BB", 123)],
        );
        write_proc_pid(&root, 4242, &[123], 500, "short", "/usr/bin/real-game");
        let resolver = ProcOwnerResolver::with_paths(&root);
        let out = resolver.resolve(
            &key_tcp(40000, "4.3.2.1:443"),
            Instant::now() + Duration::from_secs(5),
        );
        let OwnerResolution::Known(identity) = out else {
            panic!("tcp 应查到 Known，实际 {out:?}");
        };
        assert_eq!(identity.pid, 4242);
        // btime*1000 + ticks*1000/USER_HZ = 1700000000000 + 500*10
        assert_eq!(identity.started_at_unix_ms, Some(1_700_000_005_000));
        assert_eq!(
            identity.executable_path.as_deref(),
            Some("/usr/bin/real-game")
        );
        assert_eq!(identity.process_name.as_deref(), Some("short"));
        assert!(!identity.comm_truncated);
        assert_eq!(identity.user_id, Some(1000));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn udp_unconnected_wildcard_remote_matches() {
        let root = fake_root("udp-wild");
        write_btime(&root, 1_700_000_000);
        // 未 connect 的 UDP 行：远端通配 0.0.0.0:0
        write_net_table(
            &root,
            "udp",
            &[sock_row("0100007F:14F2", "00000000:0000", 77)],
        );
        write_proc_pid(&root, 999, &[77], 10, "quicgame", "/opt/games/quicgame");
        let resolver = ProcOwnerResolver::with_paths(&root);
        // 应用层键带真实远端——回退仅本地匹配仍要查到
        let out = resolver.resolve(
            &key_udp(5362, "8.8.8.8:53"),
            Instant::now() + Duration::from_secs(5),
        );
        let OwnerResolution::Known(identity) = out else {
            panic!("UDP 通配远端应回退本地匹配，实际 {out:?}");
        };
        assert_eq!(identity.pid, 999);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn port_reuse_yields_new_identity_after_ttl() {
        let (clock, resolver, root) = fixed_clock(1_000_000);
        write_btime(&root, 1_700_000_000);
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C41", "01020304:01BB", 10)],
        );
        write_proc_pid(&root, 100, &[10], 100, "oldgame", "/opt/old");

        let key = key_tcp(40001, "4.3.2.1:443");
        let deadline = Instant::now() + Duration::from_secs(5);
        let OwnerResolution::Known(first) = resolver.resolve(&key, deadline) else {
            panic!("首轮应 Known");
        };
        assert_eq!(first.pid, 100);

        // 端口被新进程复用：表换行、inode/pid/start 全换
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C41", "01020304:01BB", 20)],
        );
        write_proc_pid(&root, 200, &[20], 900_000, "newgame", "/opt/new");

        // TTL 内：缓存仍在服务窗——如实返回旧身份（有界缓存语义）
        let again = resolver.resolve(&key, deadline);
        assert_eq!(again, OwnerResolution::Known(first.clone()));

        // 过 TTL：重查换新身份，绝不把旧进程冒充给复用后的端口
        clock.store(1_000_000 + 2_000, Ordering::Relaxed);
        let reused = resolver.resolve(&key, deadline);
        let OwnerResolution::Known(second) = reused else {
            panic!("过期后应重查到新身份");
        };
        assert_eq!(second.pid, 200);
        assert!(!first.same_process(&second), "端口复用必须换身份，不误归因");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cache_stays_bounded_and_evicts_oldest() {
        let (_clock, resolver, root) = fixed_clock(5_000_000);
        write_btime(&root, 1_700_000_000);
        write_net_table(
            &root,
            "tcp",
            &[
                sock_row("0100007F:A001", "01020304:01BB", 1),
                sock_row("0100007F:A002", "01020304:01BB", 2),
                sock_row("0100007F:A003", "01020304:01BB", 3),
            ],
        );
        write_proc_pid(&root, 1, &[1, 2, 3], 5, "g", "/g");
        let resolver = resolver.with_cache(Duration::from_secs(60), 2);
        let deadline = Instant::now() + Duration::from_secs(5);
        // 0xA001/A002/A003 = 40961/40962/40963
        for port in [40961u16, 40962, 40963] {
            let out = resolver.resolve(&key_tcp(port, "4.3.2.1:443"), deadline);
            assert!(matches!(out, OwnerResolution::Known(_)));
        }
        assert!(
            resolver.cache_len() <= 2,
            "容量 2 的缓存绝不能涨到 {}",
            resolver.cache_len()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn permission_blind_fd_scan_is_denied_not_found() {
        let root = fake_root("blind");
        write_btime(&root, 1_700_000_000);
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C42", "01020304:01BB", 30)],
        );
        write_proc_pid(&root, 300, &[30], 5, "hidden", "/opt/hidden");
        // 属主进程的 fd 目录不可列（模拟 hidepid/他人进程盲区）
        let fd_dir = root.join("300").join("fd");
        fs::set_permissions(&fd_dir, fs::Permissions::from_mode(0o000)).unwrap();
        // 另一个可读但无关的进程，证明盲区不是全树不可读
        write_proc_pid(&root, 301, &[31], 5, "other", "/opt/other");

        let resolver = ProcOwnerResolver::with_paths(&root);
        let out = resolver.resolve(
            &key_tcp(40002, "4.3.2.1:443"),
            Instant::now() + Duration::from_secs(5),
        );
        assert_eq!(
            out,
            OwnerResolution::Unknown(UnknownReason::PermissionDenied),
            "分不清「不存在」和「看不见」时报 PermissionDenied，不当 NotFound 也不伪造"
        );
        fs::set_permissions(&fd_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unreadable_stat_is_denied_known_never_fabricated() {
        let root = fake_root("nostat");
        write_btime(&root, 1_700_000_000);
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C43", "01020304:01BB", 40)],
        );
        write_proc_pid(&root, 400, &[40], 5, "game", "/opt/game");
        // fd 可读、stat 不可读：启动身份拿不到 → 绝不返回无启动身份的 Known
        let stat = root.join("400").join("stat");
        fs::set_permissions(&stat, fs::Permissions::from_mode(0o000)).unwrap();

        let resolver = ProcOwnerResolver::with_paths(&root);
        let out = resolver.resolve(
            &key_tcp(40003, "4.3.2.1:443"),
            Instant::now() + Duration::from_secs(5),
        );
        assert_eq!(
            out,
            OwnerResolution::Unknown(UnknownReason::PermissionDenied),
            "缺启动身份就不判 Known（PID 复用不误归因）"
        );
        fs::set_permissions(&stat, fs::Permissions::from_mode(0o644)).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn comm_truncation_flagged_not_masquerading() {
        let root = fake_root("trunc");
        write_btime(&root, 1_700_000_000);
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C44", "01020304:01BB", 50)],
        );
        // 内核 comm 上限 15 可见字符：超长名被截断——短名不得冒充完整路径
        write_proc_pid(
            &root,
            500,
            &[50],
            5,
            "superlonggameex",
            "/usr/bin/superlonggameexec",
        );
        let resolver = ProcOwnerResolver::with_paths(&root);
        let OwnerResolution::Known(identity) = resolver.resolve(
            &key_tcp(40004, "4.3.2.1:443"),
            Instant::now() + Duration::from_secs(5),
        ) else {
            panic!("应 Known");
        };
        assert_eq!(identity.process_name.as_deref(), Some("superlonggameex"));
        assert!(identity.comm_truncated, "15 字符 comm 必须如实标注截断");
        assert_eq!(
            identity.executable_path.as_deref(),
            Some("/usr/bin/superlonggameexec"),
            "完整路径独立可得，不被短名冒充"
        );

        // 短名：不标截断
        write_net_table(
            &root,
            "tcp",
            &[sock_row("0100007F:9C45", "01020304:01BB", 51)],
        );
        write_proc_pid(&root, 501, &[51], 5, "hi", "/usr/bin/hi");
        let OwnerResolution::Known(short) = resolver.resolve(
            &key_tcp(40005, "4.3.2.1:443"),
            Instant::now() + Duration::from_secs(5),
        ) else {
            panic!("应 Known");
        };
        assert!(!short.comm_truncated);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn same_target_two_processes_route_separately() {
        let root = fake_root("twoproc");
        write_btime(&root, 1_700_000_000);
        // 同一目标、两个本地端口、两个进程——分别归因
        write_net_table(
            &root,
            "tcp",
            &[
                sock_row("0100007F:9C46", "06070809:01BB", 60),
                sock_row("0100007F:9C47", "06070809:01BB", 61),
            ],
        );
        write_proc_pid(&root, 600, &[60], 111, "gamea", "/opt/a");
        write_proc_pid(&root, 601, &[61], 222, "gameb", "/opt/b");
        let resolver = ProcOwnerResolver::with_paths(&root);
        let deadline = Instant::now() + Duration::from_secs(5);
        // 06070809 小端 → 9.8.7.6
        let a = resolver.resolve(&key_tcp(40006, "9.8.7.6:443"), deadline);
        let b = resolver.resolve(&key_tcp(40007, "9.8.7.6:443"), deadline);
        let OwnerResolution::Known(ka) = a else {
            panic!("a 应 Known")
        };
        let OwnerResolution::Known(kb) = b else {
            panic!("b 应 Known")
        };
        assert_eq!(ka.pid, 600);
        assert_eq!(kb.pid, 601);
        assert_ne!(ka, kb, "同目标两进程各自路由，不共享身份");
        assert!(!ka.same_process(&kb));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn deadline_already_passed_fails_fast() {
        let (_clock, resolver, root) = fixed_clock(9_000_000);
        let key = key_tcp(40008, "4.3.2.1:443");
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            resolver.resolve(&key, past),
            OwnerResolution::Unknown(UnknownReason::DeadlineExceeded)
        );
        assert_eq!(resolver.cache_len(), 0, "过截止的查询不落缓存不做 IO");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_connection_is_not_found() {
        let root = fake_root("absent");
        write_btime(&root, 1_700_000_000);
        write_net_table(&root, "tcp", &[]);
        let resolver = ProcOwnerResolver::with_paths(&root);
        assert_eq!(
            resolver.resolve(
                &key_tcp(40009, "4.3.2.1:443"),
                Instant::now() + Duration::from_secs(5)
            ),
            OwnerResolution::Unknown(UnknownReason::NotFound)
        );
        let _ = fs::remove_dir_all(&root);
    }
}
