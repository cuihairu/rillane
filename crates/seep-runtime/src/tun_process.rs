//! TUN 首包进程归因（tun-dataplane.md §2.5）
//!
//! `(src ip:port) → (pid, comm)` 归因：`/proc/net/{tcp,tcp6,udp,udp6}` 取
//! 本端 socket 行 → inode → 扫 `/proc/<pid>/fd` 的 `socket:[inode]` 符号链接
//! → `/proc/<pid>/comm`。best-effort：任何一步 miss/权限失败 → None（E15：
//! 注解缺省 + `process_attr_miss` 计数，不报错）。
//!
//! - fs 读走 `spawn_blocking`（run 循环不被 /proc 扫描阻塞）；
//! - 结果缓存 TTL 30s（含负缓存——归因 miss 多为「非本机 socket / 已关闭」，
//!   重复扫描纯浪费）；
//! - root 路径可注入（默认 `/proc`；测试指向 fixture 目录，§4.1 无特权）。

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// 归因 socket 表族选择（tcp/udp × v4/v6 四表）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SockProto {
    Tcp,
    Udp,
}

/// 归因产物：pid + `/proc/<pid>/comm` 口径进程名（内核截断 15 字节）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
}

/// `/proc/net/<table>` 行的本端地址解码（内核以 LE 字序打印 32 位字）
fn parse_proc_hex_v4(hex: &str) -> Option<Ipv4Addr> {
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(v.swap_bytes()))
}

fn parse_proc_hex_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, word) in hex.as_bytes().chunks(8).enumerate() {
        let word = std::str::from_utf8(word).ok()?;
        let v = u32::from_str_radix(word, 16).ok()?;
        octets[i * 4..i * 4 + 4].copy_from_slice(&v.swap_bytes().to_be_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

/// `3600007F:0035` 形 → `127.0.0.54:53`
fn parse_proc_local_addr(field: &str, v6: bool) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        IpAddr::V6(parse_proc_hex_v6(ip_hex)?)
    } else {
        IpAddr::V4(parse_proc_hex_v4(ip_hex)?)
    };
    Some(SocketAddr::new(ip, port))
}

/// 在一张 `/proc/net/<table>` 表中找本端地址命中的 inode
///（行格式：`sl local_address rem_address st … inode ref pointer drops`，
/// inode = 第 10 列；本机实测 `/proc/net/udp` 钉死）
fn find_inode(table: &str, src: SocketAddr) -> Option<u64> {
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if parse_proc_local_addr(fields[1], src.is_ipv6()) == Some(src) {
            return fields[9].parse::<u64>().ok();
        }
    }
    None
}

/// 扫 `/proc/<pid>/fd`：`socket:[inode]` 符号链接命中即返回 pid
fn find_pid_by_inode(root: &Path, inode: u64) -> Option<u32> {
    let expect = format!("socket:[{inode}]");
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue; // net/ 等 非 pid 目录
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue; // 权限/已退出 → 下一个 pid
        };
        for fd in fds.flatten() {
            // /proc/<pid>/fd/* 恒为符号链接（内核 fd 表导出，无非链接形态）——
            // 直读 read_link 免 symlink_metadata：strace 实测本机 593 进程
            // 6.8k fd，statx 占归因扫描 syscall 面 ~36%（首包 345ms 里的大头）
            if std::fs::read_link(fd.path())
                .ok()
                .is_some_and(|l| l.to_string_lossy() == expect)
            {
                return Some(pid);
            }
        }
    }
    None
}

/// 同步归因（spawn_blocking 内执行；root 可注入）
fn lookup_sync(root: &Path, src: SocketAddr, proto: SockProto) -> Option<ProcessInfo> {
    let table = match (proto, src.is_ipv6()) {
        (SockProto::Tcp, false) => "net/tcp",
        (SockProto::Tcp, true) => "net/tcp6",
        (SockProto::Udp, false) => "net/udp",
        (SockProto::Udp, true) => "net/udp6",
    };
    let content = std::fs::read_to_string(root.join(table)).ok()?;
    let inode = find_inode(&content, src)?;
    let pid = find_pid_by_inode(root, inode)?;
    let comm = std::fs::read_to_string(root.join(pid.to_string()).join("comm"))
        .ok()?
        .trim_end()
        .to_string();
    Some(ProcessInfo { pid, comm })
}

/// 归因缓存（键含 proto：同地址的 tcp/udp 行在不同 /proc 表，结果独立）
type AttrCache = HashMap<(SocketAddr, SockProto), (Option<ProcessInfo>, Instant)>;
/// 单flight 状态：cell 存最终结果（`get()==Some` 表示已 set，含负结果）；
/// notify 供等待者唤醒。
struct InflightState {
    cell: tokio::sync::OnceCell<Option<ProcessInfo>>,
    notify: tokio::sync::Notify,
}
type InflightCell = Arc<InflightState>;

/// 进程归因器（缓存 TTL 30s，含负缓存；§2.5「每流首包归因一次」的支撑面）
pub struct ProcessAttributor {
    root: PathBuf,
    ttl: Duration,
    cache: Arc<Mutex<AttrCache>>,
    /// 并发同 key miss 单flight：合并重复 /proc 扫描（fd 遍历贵，见模块头）。
    /// `tokio::sync::Mutex<HashMap<key, Weak<OnceCell>>>`——弱引用防已结束
    /// 任务占位泄漏；TTL 过期后的下一次 miss 自会新建 cell。
    inflight: Arc<Mutex<HashMap<(SocketAddr, SockProto), InflightCell>>>,
    /// 测试观测：lookup_sync 实际调用次数（并发合并断言用）。
    #[cfg(test)]
    scan_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for ProcessAttributor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessAttributor {
    pub fn new() -> Self {
        Self::with_root("/proc")
    }

    /// 测试注入形：root 指向 fixture 目录（`<root>/net/udp`、`<root>/<pid>/fd`）
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            ttl: Duration::from_secs(30),
            cache: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// 归因（缓存 TTL 内直出；miss 走 spawn_blocking 读 /proc——fd 扫描贵，
    /// 仅 `has_process_rules` 时由调用方触发）
    pub async fn attribute(&self, src: SocketAddr, proto: SockProto) -> Option<ProcessInfo> {
        if let Some((cached, at)) = self.cache.lock().unwrap().get(&(src, proto)) {
            if at.elapsed() < self.ttl {
                return cached.clone();
            }
        }

        let key = (src, proto);
        let cell = {
            let mut inflight = self.inflight.lock().unwrap();
            if let Some(existing) = inflight.get(&key) {
                existing.clone()
            } else {
                let cell = Arc::new(InflightState {
                    cell: tokio::sync::OnceCell::new(),
                    notify: tokio::sync::Notify::new(),
                });
                let root = self.root.clone();
                let cache = self.cache.clone();
                let inflight_map = self.inflight.clone();
                let cell2 = cell.clone();
                #[cfg(test)]
                let scan_count = self.scan_count.clone();
                tokio::spawn(async move {
                    #[cfg(test)]
                    scan_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let found =
                        tokio::task::spawn_blocking(move || lookup_sync(&root, src, proto))
                            .await
                            .ok()
                            .flatten();
                    cache
                        .lock()
                        .unwrap()
                        .insert(key, (found.clone(), Instant::now()));
                    let _ = cell2.cell.set(found);
                    cell2.notify.notify_waiters();
                    // 先 set 再移除：set 后新来者经 cell.get() 直接命中；移除
                    // 使 TTL 过期后的下一次 miss 新建 cell 重扫（不复用旧 cell）。
                    let mut infl = inflight_map.lock().unwrap();
                    if infl.get(&key).is_some_and(|c| Arc::ptr_eq(c, &cell2)) {
                        infl.remove(&key);
                    }
                });
                inflight.insert(key, cell.clone());
                cell
            }
        };
        if cell.cell.get().is_none() {
            cell.notify.notified().await;
        }
        cell.cell.get().and_then(|v| v.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// fixture：`<root>/net/udp`（v4 两行：192.168.0.192:4660 → inode 9999、
    /// 10.0.0.7:53 → inode 8888）+ `<root>/net/udp6`（[::1]:53 → 7777）+
    /// `<root>/4242/fd/3 → socket:[9999]` + comm "gameproc"；
    /// `<root>/7/fd/3 → socket:[7777]` + comm "dnsd"
    fn fixture() -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seep-tun-proc-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("net")).unwrap();
        // 行列距真实 /proc：inode 在第 10 列（idx 9）
        std::fs::write(
            dir.join("net/udp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops            \n\
             100: C000A8C0:1234 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 9999 2 0000000000000000 0\n\
             101: 0700000A:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 8888 2 0000000000000000 0\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("net/udp6"),
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
             200: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 7777 2 0000000000000000 0\n",
        )
        .unwrap();
        for (pid, inode) in [(4242u32, 9999u64), (7, 7777)] {
            std::fs::create_dir_all(dir.join(pid.to_string()).join("fd")).unwrap();
            symlink(
                format!("socket:[{inode}]"),
                dir.join(pid.to_string()).join("fd").join("3"),
            )
            .unwrap();
        }
        std::fs::write(dir.join("4242/comm"), "gameproc\n").unwrap();
        std::fs::write(dir.join("7/comm"), "dnsd\n").unwrap();
        dir
    }

    /// §4.1：/proc 行地址解码（LE 字序打印）——v4/v6/端口真值
    #[test]
    fn proc_hex_address_decoding() {
        assert_eq!(
            parse_proc_hex_v4("3600007F"),
            Some(Ipv4Addr::new(127, 0, 0, 54)),
            "本机 /proc/net/udp 实测行（127.0.0.54:53 systemd-resolved）"
        );
        assert_eq!(
            parse_proc_local_addr("C000A8C0:1234", false),
            Some("192.168.0.192:4660".parse().unwrap())
        );
        // ::1 = 末 32 位字 0x01000000（LE 打印）
        let v6 = parse_proc_local_addr("00000000000000000000000001000000:0035", true).unwrap();
        assert_eq!(v6.port(), 53);
        assert_eq!(v6.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        // 长度不足拒绝
        assert_eq!(parse_proc_hex_v6("01000000"), None);
    }

    /// §2.5 全链路：socket 行 → inode → fd 扫描 → comm；miss 负缓存
    #[tokio::test]
    async fn attribute_hits_v4_v6_and_misses() {
        let root = fixture();
        let attr = ProcessAttributor::with_root(&root);

        let hit = attr
            .attribute("192.168.0.192:4660".parse().unwrap(), SockProto::Udp)
            .await;
        assert_eq!(
            hit,
            Some(ProcessInfo {
                pid: 4242,
                comm: "gameproc".into()
            })
        );

        let v6 = attr
            .attribute("[::1]:53".parse().unwrap(), SockProto::Udp)
            .await;
        assert_eq!(
            v6,
            Some(ProcessInfo {
                pid: 7,
                comm: "dnsd".into()
            })
        );

        // miss：表内无此本端地址
        assert_eq!(
            attr.attribute("192.168.0.192:9999".parse().unwrap(), SockProto::Udp)
                .await,
            None
        );
        // tcp 表缺席（fixture 未建 net/tcp）→ None 不报错
        assert_eq!(
            attr.attribute("192.168.0.192:4660".parse().unwrap(), SockProto::Tcp)
                .await,
            None
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// §2.5 缓存语义：TTL 内命中缓存（fixture 撤除仍可归因）；TTL=0 恒重扫；
    /// 负缓存同样生效
    #[tokio::test]
    async fn cache_ttl_and_negative_caching() {
        let root = fixture();
        let src: SocketAddr = "192.168.0.192:4660".parse().unwrap();
        let attr = ProcessAttributor::with_root(&root);

        let first = attr.attribute(src, SockProto::Udp).await;
        assert!(first.is_some());
        // 撤掉 fixture：TTL 内仍出缓存值
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(attr.attribute(src, SockProto::Udp).await, first);

        // TTL=0：缓存恒过期 → 源已撤 → None（证明确实重扫）
        let root2 = fixture();
        let attr0 = ProcessAttributor::with_root(&root2).with_ttl(Duration::ZERO);
        assert!(attr0.attribute(src, SockProto::Udp).await.is_some());
        std::fs::remove_dir_all(&root2).unwrap();
        assert_eq!(attr0.attribute(src, SockProto::Udp).await, None);

        // 负缓存：miss 后 TTL 内不重扫（fixture 恢复为「命中源」也不翻案）
        let root3 = fixture();
        let attrn = ProcessAttributor::with_root(&root3);
        let miss: SocketAddr = "10.9.9.9:1234".parse().unwrap();
        assert!(attrn.attribute(miss, SockProto::Udp).await.is_none());
        std::fs::write(
            root3.join("net/udp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops            \n\
             102: 0909090A:04D2 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 9999 2 0000000000000000 0\n",
        )
        .unwrap();
        assert!(
            attrn.attribute(miss, SockProto::Udp).await.is_none(),
            "负缓存 TTL 内不重扫"
        );
        let _ = std::fs::remove_dir_all(&root3);
    }

    /// 回归：并发同 key miss 只做一次 /proc 扫描（单flight 合并），
    /// 其余等待者复用结果；TTL 过期后的下一次 miss 重扫（cell 已移除）。
    #[tokio::test]
    async fn concurrent_miss_singleflights_one_scan() {
        let root = fixture();
        let attr = Arc::new(ProcessAttributor::with_root(&root));
        let src: SocketAddr = "192.168.0.192:4660".parse().unwrap();

        // 并发 8 个同 key miss（首次扫描前都未命中缓存）。
        let mut handles = Vec::new();
        for _ in 0..8 {
            let attr = attr.clone();
            handles.push(tokio::spawn(async move {
                attr.attribute(src, SockProto::Udp).await
            }));
        }
        for h in handles {
            let r = h.await.unwrap();
            assert_eq!(
                r,
                Some(ProcessInfo { pid: 4242, comm: "gameproc".into() })
            );
        }

        // 单flight 合并：8 个并发 miss 只触发 1 次 lookup_sync。
        assert_eq!(attr.scan_count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // cell 已完成并移除：TTL 过期后的下一次 miss 新建 cell 重扫。
        let attr_expired = Arc::new(
            ProcessAttributor::with_root(&root).with_ttl(Duration::from_millis(50)),
        );
        let attr_expired2 = attr_expired.clone();
        let first = attr_expired.attribute(src, SockProto::Udp).await;
        assert!(first.is_some());
        tokio::time::sleep(Duration::from_millis(80)).await;
        let second = attr_expired2.attribute(src, SockProto::Udp).await;
        assert!(second.is_some());
        assert_eq!(attr_expired2.scan_count.load(std::sync::atomic::Ordering::SeqCst), 2);

        let _ = std::fs::remove_dir_all(&root);
    }
}
