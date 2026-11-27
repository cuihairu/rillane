//! RIL-085 第二段：Linux 跨 uid「权限不足」路径的真实实测。
//!
//! 本进程用 `sudo -n` + `setpriv` 把同一测试二进制以 nobody(65534) 身份拉起一个
//! helper：helper 连回本进程监听的回环 TCP 端口并短暂持住连接。本进程从
//! `/proc/net/tcp` 看得到该 socket inode，却读不到他人 uid 的
//! `/proc/<pid>/fd`——`ProcOwnerResolver` 必须如实返回
//! `Unknown(PermissionDenied)`，不得编造身份，也不得降级成 `NotFound`。
//! 同一监听口上本 uid 的控制连接必须仍归因到自身，证明盲区是跨 uid 而非
//! 解析器整体失效。
//!
//! CI/无 sudo 环境：跳过（打印 skip），不冒充实测。helper 用例单独以
//! `--exact helper_cross_uid_connection` 运行；无环境变量时是空操作，
//! 不会被全 workspace 测试误跑成挂死的连接持有者。

#![cfg(target_os = "linux")]

use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rillane_platform::network::{
    ConnectionKey, OwnerResolution, OwnerResolver, ProcOwnerResolver, TransportProtocol,
    UnknownReason,
};

const NOBODY_UID: u32 = 65534;
const HELPER_ADDR_ENV: &str = "RILLANE_OWNER_HELPER_ADDR";
const HELPER_PID_ENV: &str = "RILLANE_OWNER_HELPER_PID_FILE";
const HELPER_HOLD_MS: u64 = 6_000;
const BOUND_MS: u64 = 5_000;

/// helper 模式：由跨 uid 的 sudo/setpriv 子进程单独调用；无环境变量时空操作。
#[test]
fn helper_cross_uid_connection() {
    let Some(addr) = std::env::var(HELPER_ADDR_ENV).ok() else {
        return;
    };
    let pid_file = std::env::var(HELPER_PID_ENV).expect("helper 缺 pid 文件路径");
    fs::write(&pid_file, std::process::id().to_string()).expect("helper 写 pid 文件");
    let stream = TcpStream::connect(addr).expect("helper 连回监听口");
    std::thread::sleep(Duration::from_millis(HELPER_HOLD_MS));
    drop(stream);
}

struct HelperGuard {
    child: Child,
    pid_file: std::path::PathBuf,
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.pid_file);
    }
}

fn sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// /proc/<pid>/status 对所有 uid 可读——用来证明 helper 真在 nobody 下，
/// 而不是「盲区」断言自说自话。
fn uid_of(pid: u32) -> Option<u32> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟")
        .as_nanos()
}

#[test]
fn cross_uid_connection_is_permission_denied_not_identity() {
    if !sudo_available() {
        eprintln!("skip: sudo -n 不可用，跨 uid 权限面未实测");
        return;
    }
    if !Path::new("/usr/bin/setpriv").exists() {
        eprintln!("skip: setpriv 不可用，跨 uid 权限面未实测");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定回环监听口");
    listener.set_nonblocking(true).expect("设为非阻塞");
    let listen_addr = listener.local_addr().expect("监听地址");
    let pid_file = std::env::temp_dir().join(format!(
        "rillane-owner-perm-{}-{}.pid",
        std::process::id(),
        nonce()
    ));
    let _ = fs::remove_file(&pid_file);

    let child = Command::new("sudo")
        .args([
            "-n",
            "env",
            &format!("{HELPER_ADDR_ENV}={listen_addr}"),
            &format!("{HELPER_PID_ENV}={}", pid_file.display()),
            "setpriv",
            "--reuid",
            &NOBODY_UID.to_string(),
            "--regid",
            &NOBODY_UID.to_string(),
            "--clear-groups",
        ])
        .arg(std::env::current_exe().expect("测试二进制自身路径"))
        .args(["--exact", "helper_cross_uid_connection", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("拉起跨 uid helper（sudo -n）");
    let guard = HelperGuard {
        child,
        pid_file: pid_file.clone(),
    };

    let start = Instant::now();
    let helper_pid = loop {
        if let Ok(raw) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = raw.trim().parse::<u32>() {
                break pid;
            }
        }
        assert!(
            start.elapsed() < Duration::from_millis(BOUND_MS),
            "helper 未在 {BOUND_MS}ms 内写 pid 文件（跨 uid 启动失败）"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_ne!(helper_pid, std::process::id(), "helper 必须是另一进程");
    assert_eq!(
        uid_of(helper_pid),
        Some(NOBODY_UID),
        "helper 必须真在 nobody(65534) uid 下——否则权限盲区断言无意义"
    );

    let (helper_stream, helper_local) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(
                    start.elapsed() < Duration::from_millis(BOUND_MS),
                    "helper 未在 {BOUND_MS}ms 内连回监听口"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept 失败: {e}"),
        }
    };

    // 跨 uid 连接：表中 inode 可见，但 /proc/<pid>/fd 不可列——必须报权限盲区。
    let cross_key = ConnectionKey::new(TransportProtocol::Tcp, helper_local, listen_addr);
    let cross =
        ProcOwnerResolver::new().resolve(&cross_key, Instant::now() + Duration::from_secs(3));
    assert!(
        matches!(
            cross,
            OwnerResolution::Unknown(UnknownReason::PermissionDenied)
        ),
        "跨 uid 连接必须如实报 PermissionDenied（未知且具名），实际 {cross:?}"
    );

    // 同 uid 控制连接：同一监听口、同一解析器，必须仍归因到自身——
    // 证明上面是权限盲区，不是解析器整体坏掉。
    let self_stream = TcpStream::connect(listen_addr).expect("本进程连接监听口");
    let (_, self_local) = listener.accept().expect("接收本进程连接");
    let self_key = ConnectionKey::new(TransportProtocol::Tcp, self_local, listen_addr);
    let own = ProcOwnerResolver::new().resolve(&self_key, Instant::now() + Duration::from_secs(3));
    assert!(
        matches!(&own, OwnerResolution::Known(id) if id.pid == std::process::id()),
        "同 uid 控制连接应归因到自身，实际 {own:?}"
    );

    drop(helper_stream);
    drop(self_stream);
    drop(guard);
}
