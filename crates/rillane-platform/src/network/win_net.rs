//! Windows 真机 IO 面（RIL-033）：决策全在 win_takeover.rs（OS-free、
//! Linux 验证席已确定性回归）——本模块只做四件事：进程执行、真机文本
//! 读取后委托解析、旁路绑定原语、适配器 If 索引取 OS 权威口径。
//!
//! **真机运行期证据（RIL-033 机批次，2026-11-21 imac）**：
//! `examples/win_probe.rs` 实跑——Wintun 适配器上线、真实应用流
//! （ping.exe / curl.exe）经封环进入数据面、旁路绑定原语、失败补偿与
//! 幂等清理全部实测；证据见
//! `docs/acceptance-evidence/ril-033-windows-takeover.md`。
//! 本模块运行期现状 = 已在 Windows 真机运行（非仅跨编译检查）。
//!
//! 边界（诚实注记）：
//! - wireguard-nt 会话（内核加密隧道面）不在此——选型事实与替代
//!   论证见 win_tun.rs 模块头；
//! - DNS 劫持撤销 = source=dhcp（还原 DHCP 解析器）；接管前静态配置
//!   的原文快照归 recovery 面（与 Linux 同边界）。

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};

use super::win_takeover::{
    parse_netsh_dnsservers, parse_netsh_ipv4_interfaces, parse_netsh_ipv6_addresses,
    parse_route_print_ipv4, parse_route_print_ipv6, WinNetSnapshot, WinStepExecutor,
};

/// 真机步骤执行器：argv[0] = route.exe / netsh.exe（System32 前缀
/// 不必显式——CreateProcess 按系统路径解析）；非零退出 → stderr 文本
/// 进 io::Error（win_takeover 的 eexist/missing 文本谓词吃的就是这个
/// 形状）。
pub fn win_step_executor() -> WinStepExecutor {
    Arc::new(|argv: &[String]| {
        let output = Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| io::Error::other(format!("{} 启动失败: {e}", argv[0])))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // route.exe 把错误写 stdout、netsh 写 stderr——两处拼接成谓词
        // 可吃的单一文本（非零退出即失败，文本只服务于幂等分类）
        Err(io::Error::other(format!(
            "{} 退出 {:?}: {}{}",
            argv[0],
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        )))
    })
}

/// 读取真机网络快照：`route print -4` → parse_route_print_ipv4，
/// `netsh interface ip show dnsservers` → parse_netsh_dnsservers
/// （决策与容错全在解析器——本函数只负责取回文本）。
pub fn read_net_snapshot() -> Result<WinNetSnapshot> {
    let out = |argv: &[&str]| -> Result<String> {
        let o = Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .with_context(|| format!("{} 启动失败", argv[0]))?;
        if !o.status.success() {
            anyhow::bail!(
                "{} 退出 {:?}: {}",
                argv[0],
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let v4 = parse_route_print_ipv4(&out(&["route", "print", "-4"])?);
    let v6_routes = parse_route_print_ipv6(&out(&["route", "print", "-6"])?);
    let v6_addrs = parse_netsh_ipv6_addresses(&out(&[
        "netsh", "interface", "ipv6", "show", "addresses",
    ])?);
    let dns = parse_netsh_dnsservers(&out(&["netsh", "interface", "ip", "show", "dnsservers"])?);
    Ok(WinNetSnapshot {
        default_routes: v4,
        default_routes_v6: v6_routes,
        v6_if_addresses: v6_addrs,
        dns_servers: dns,
    })
}

/// 适配器 If 索引（**OS 权威口径**）：`netsh interface ipv4 show interfaces`
/// 按适配器名查。为什么不以 `WintunGetAdapterLUID` 为准——RIL-033 imac
/// 真机实证（2026-11-21 11:03）：新建 Wintun 适配器 LUID 的 If 索引位可
/// 为 0，直接取低 24 位会得到不可路由的索引，`route add … if 0` 报
/// 「指定的接口不存在」；netsh 口径即 TCP/IP 栈真实索引。调用方把
/// LUID 派生值当回退。
pub fn adapter_if_index(name: &str) -> Option<u32> {
    let o = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    parse_netsh_ipv4_interfaces(&String::from_utf8_lossy(&o.stdout))
        .into_iter()
        .find(|i| i.name == name)
        .map(|i| i.if_index)
}

/// 旁路绑定原语（RIL-032 imac 实证的面）：出站 UDP socket 显式 bind
/// 物理口 IP → 同目标全程钉在物理口，不被 TUN 捕获。bind_ip 来自
/// [`WinNetSnapshot::escape_bind_ip`]；端口 0 = 系统分配（socket 生命周期
/// 由调用方持有）。
pub fn bind_escape_udp(bind_ip: std::net::IpAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind((bind_ip, 0))
}

/// TCP 旁路拨号（RIL-033 机批次接入 socket2 面）：先 bind 物理口 IP 再
/// connect——std `TcpStream` 无「先 bind 后 connect」直配接口，走
/// socket2 原语。代理拨号/DNS 上游的 TCP 出站全走这里，杜绝被 TUN
/// 路由吸走成环（RIL-032 双连接对照实验的原语化）。
pub fn connect_escape_tcp(bind_ip: IpAddr, remote: SocketAddr) -> io::Result<TcpStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(remote),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_nonblocking(false)?;
    socket.bind(&socket2::SockAddr::from(SocketAddr::new(bind_ip, 0)))?;
    socket.connect(&socket2::SockAddr::from(remote))?;
    Ok(socket.into())
}
