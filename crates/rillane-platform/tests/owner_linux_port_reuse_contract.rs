//! RIL-085 第二段：Linux「端口复用 / 同目标多进程」归属的真实实测。
//!
//! 同一监听目标上两个独立进程（同 uid）各自建立 TCP 连接——四元组靠
//! 本地端口区分，`/proc/net/tcp` 两行 inode 不同，`ProcOwnerResolver` 必须
//! 把每条连接归因到各自的进程，且带启动身份（PID 复用防护）。这正是
//! RIL-085 验收里「PID/端口复用均实测」的 Linux 面（此前仅 Windows 有
//! P4/P4b 真机证据）。

#![cfg(target_os = "linux")]

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rillane_platform::network::{
    ConnectionKey, OwnerResolution, OwnerResolver, ProcOwnerResolver, TransportProtocol,
};

const HELPER_ADDR_ENV: &str = "RILLANE_OWNER_REUSE_ADDR";
const HELPER_REPORT_ENV: &str = "RILLANE_OWNER_REUSE_REPORT";
const HELPER_HOLD_MS: u64 = 8_000;
const BOUND_MS: u64 = 5_000;

/// helper 模式：连回目标、把 pid 与本地端口写进报告文件、短暂持住连接。
/// 无环境变量时空操作，避免被全 workspace 测试误跑成连接持有者。
#[test]
fn helper_same_target_connection() {
    let Some(addr) = std::env::var(HELPER_ADDR_ENV).ok() else {
        return;
    };
    let report = std::env::var(HELPER_REPORT_ENV).expect("helper 缺报告文件路径");
    let stream = TcpStream::connect(addr).expect("helper 连回目标");
    let local = stream.local_addr().expect("本地端口");
    fs::write(
        &report,
        format!("{} {}\n", std::process::id(), local.port()),
    )
    .expect("helper 写报告");
    std::thread::sleep(Duration::from_millis(HELPER_HOLD_MS));
    drop(stream);
}

/// 子进程与报告文件的唯一持有者；Drop 保证任何失败路径都不留残留。
struct HelperGuard {
    children: Vec<Child>,
    reports: Vec<PathBuf>,
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        for path in &self.reports {
            let _ = fs::remove_file(path);
        }
    }
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟")
        .as_nanos()
}

/// 从 helper 报告文件读 pid 与本地端口（有界轮询）。
fn read_report(path: &PathBuf, start: Instant) -> (u32, u16) {
    loop {
        if let Ok(raw) = fs::read_to_string(path) {
            let mut parts = raw.split_whitespace();
            if let (Some(pid), Some(port)) = (parts.next(), parts.next()) {
                if let (Ok(pid), Ok(port)) = (pid.parse::<u32>(), port.parse::<u16>()) {
                    return (pid, port);
                }
            }
        }
        assert!(
            start.elapsed() < Duration::from_millis(BOUND_MS),
            "helper 未在 {BOUND_MS}ms 内交报告 {path:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn two_processes_same_target_attribute_to_own_pid() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定目标监听口");
    listener.set_nonblocking(true).expect("非阻塞");
    let target = listener.local_addr().expect("目标地址");

    let exe = std::env::current_exe().expect("测试二进制自身路径");
    let start = Instant::now();
    let mut guard = HelperGuard {
        children: Vec::new(),
        reports: Vec::new(),
    };

    for _ in 0..2 {
        let report = std::env::temp_dir().join(format!(
            "rillane-reuse-{}-{}.rpt",
            std::process::id(),
            nonce()
        ));
        let child = Command::new(&exe)
            .env(HELPER_ADDR_ENV, target.to_string())
            .env(HELPER_REPORT_ENV, &report)
            .args(["--exact", "helper_same_target_connection", "--nocapture"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("拉起同目标 helper");
        guard.children.push(child);
        guard.reports.push(report);
    }

    // 收两条连接（非阻塞 accept 有界轮询）；持住服务端一侧到断言完成。
    let mut accepted = Vec::new();
    while accepted.len() < 2 {
        match listener.accept() {
            Ok(pair) => accepted.push(pair),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    start.elapsed() < Duration::from_millis(BOUND_MS),
                    "未在 {BOUND_MS}ms 内收齐两条连接"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept 失败: {e}"),
        }
    }

    let mut info = Vec::new();
    for report in &guard.reports {
        let (pid, port) = read_report(report, start);
        assert_ne!(pid, std::process::id(), "helper 必须是独立进程");
        info.push((pid, port));
    }
    assert_ne!(
        info[0].1, info[1].1,
        "两条连接的本地端口应不同（四元组区分）"
    );
    assert_ne!(info[0].0, info[1].0, "两个 helper 应是不同进程");

    // 每条 (本地端口, 目标) 必须归因到各自的 helper pid，且带启动身份。
    let resolver = ProcOwnerResolver::new();
    for (i, (pid, port)) in info.iter().enumerate() {
        let key = ConnectionKey::new(
            TransportProtocol::Tcp,
            format!("127.0.0.1:{port}").parse().unwrap(),
            target,
        );
        let out = resolver.resolve(&key, Instant::now() + Duration::from_secs(3));
        let OwnerResolution::Known(identity) = out else {
            panic!("连接 {i}（本地端口 {port}）应归因到 helper，实际 {out:?}");
        };
        assert_eq!(
            identity.pid, *pid,
            "连接 {i}（本地端口 {port}）应归到其 helper pid {pid}，实际 {}",
            identity.pid
        );
        assert!(
            identity.started_at_unix_ms.is_some(),
            "连接 {i} 必须带启动身份（PID 复用防护）"
        );
        assert_ne!(
            identity.pid,
            info[1 - i].0,
            "连接 {i} 不得串到另一个 helper（同目标多进程零串扰）"
        );
    }
}
