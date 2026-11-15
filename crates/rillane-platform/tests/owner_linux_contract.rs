//! RIL-030 真机 /proc 集成验收：本测试进程自身发起的真实 TCP/UDP
//! 连接必须归因到自身（pid、启动身份、完整路径、comm 截断如实标注）。
//! Linux-only（owner_linux 模块同门控）。

#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rillane_platform::network::{
    ConnectionKey, OwnerCapability, OwnerResolution, OwnerResolver, ProcOwnerResolver,
    TransportProtocol, UnknownReason,
};

fn resolver() -> ProcOwnerResolver {
    ProcOwnerResolver::new()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 自身真实 uid：/proc/self/status 的 Uid 行（std-only，不引 nix user feature）。
fn self_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status 必须可读");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .expect("Uid 行第一个字段是真实 uid");
        }
    }
    panic!("status 缺 Uid 行");
}

#[test]
fn real_tcp_attribution_known_self() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = std::thread::spawn(move || {
        let (_s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(500));
    });
    let client = std::net::TcpStream::connect(addr).unwrap();
    let local = client.local_addr().unwrap();
    let key = ConnectionKey::new(TransportProtocol::Tcp, local, addr);
    let out = resolver().resolve(&key, Instant::now() + Duration::from_secs(5));
    let OwnerResolution::Known(identity) = out else {
        panic!("真机 TCP 连接应归因到自身，实际 {out:?}");
    };
    assert_eq!(identity.pid, std::process::id(), "TCP 归因到测试进程自身");
    // 启动身份：本进程启动不久，秒级内可验证
    let started = identity
        .started_at_unix_ms
        .expect("Linux 实现必须提供启动身份（PID 复用防护）");
    let now = now_unix_ms();
    assert!(
        started > 0 && started <= now,
        "启动时间应合理：{started} vs now {now}"
    );
    assert!(now - started < 3_600_000, "测试进程应在一小时内启动");
    // 完整路径独立可得，不被短名冒充
    let exe = identity
        .executable_path
        .expect("同 uid 进程的 exe readlink 应可得");
    let exe_name = exe.rsplit('/').next().unwrap_or("");
    assert!(
        exe_name.starts_with("owner_linux_contract"),
        "完整路径应指向测试二进制，实际 {exe}"
    );
    // comm 是内核 15 字符可见上限内的短名，截断如实标注
    let comm = identity.process_name.expect("comm 应可得");
    assert!(comm.len() <= 15, "comm 受内核 15 字符上限，实际 {comm}");
    assert_eq!(
        identity.comm_truncated,
        comm.len() >= 15,
        "截断标注与长度一致"
    );
    assert_eq!(identity.user_id, Some(self_uid()), "uid 归因到测试进程属主");
    accept.join().unwrap();
}

#[test]
fn real_udp_attribution_known_self() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = sock.local_addr().unwrap();
    sock.send_to(b"ril030", peer_addr).unwrap();
    // 未 connect 的 UDP：表行远端通配，靠本地侧回退匹配
    let key = ConnectionKey::new(TransportProtocol::Udp, local, peer_addr);
    let out = resolver().resolve(&key, Instant::now() + Duration::from_secs(5));
    let OwnerResolution::Known(identity) = out else {
        panic!("真机 UDP 端点应归因到自身，实际 {out:?}");
    };
    assert_eq!(identity.pid, std::process::id(), "UDP 归因到测试进程自身");
    assert!(identity.started_at_unix_ms.is_some(), "启动身份必须可得");
    drop(sock);
    drop(peer);
}

#[test]
fn real_closed_connection_is_not_known() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let sock = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:1".parse().unwrap(),
        Duration::from_millis(50),
    );
    let _ = sock; // 可能失败，无关紧要——查一条必然不存在的键即可
    let key = ConnectionKey::new(TransportProtocol::Tcp, "127.0.0.1:1".parse().unwrap(), addr);
    let out = resolver().resolve(&key, Instant::now() + Duration::from_secs(5));
    assert!(
        matches!(out, OwnerResolution::Unknown(_)),
        "已关闭连接绝不返回 Known，实际 {out:?}"
    );
    // NotFound（表里无行且无盲区）或 PermissionDenied（多用户机上
    // 他人 fd 目录不可列、盲区如实上报）都是诚实答案；伪造身份不是。
}

#[test]
fn real_deadline_in_past_fails_fast() {
    let resolver = resolver();
    let key = ConnectionKey::new(
        TransportProtocol::Tcp,
        "127.0.0.1:1".parse().unwrap(),
        "127.0.0.1:2".parse().unwrap(),
    );
    let out = resolver.resolve(&key, Instant::now() - Duration::from_secs(1));
    assert_eq!(
        out,
        OwnerResolution::Unknown(UnknownReason::DeadlineExceeded),
        "过截止立即失败，不扫表不做 IO"
    );
    assert_eq!(resolver.cache_len(), 0, "失败查询不落缓存");
}

#[test]
fn real_capability_is_supported() {
    assert_eq!(resolver().capability(), OwnerCapability::Supported);
}
