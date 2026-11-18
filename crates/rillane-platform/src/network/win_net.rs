//! Windows 真机 IO 面（RIL-033 代码面首段交付的 cfg windows 薄层）：
//! 决策全在 win_takeover.rs（OS-free、Linux 验证席已确定性回归）——
//! 本模块只做三件事：进程执行、真机文本读取后委托解析、旁路绑定
//! 原语。**未在任何真机运行过**（SSH 授权面待恢复）——运行期验收
//! （真实浏览器/游戏流进入共享内核、DNS/代理拨号不循环、失败可
//! 补偿）归机批次；本模块现状 = 跨编译检查通过 + 决策层确定性回归。
//!
//! 边界（诚实注记）：
//! - wireguard-nt 会话（TUN 捕获面）未落地——需要 wireguard-nt 驱动
//!   FFI，归机批次（手写从未运行的 FFI 不交付）；
//! - IPv6 主出口身份未并入快照（route print -6 行无接口地址列）——
//!   需按 If 索引查接口地址（Get-NetIPAddress / Get-NetIPInterface），
//!   真机核过输出形状再并；
//! - DNS 劫持撤销 = source=dhcp（还原 DHCP 解析器）；接管前静态配置
//!   的原文快照归 recovery 面（与 Linux 同边界）。

use std::io;
use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};

use super::win_takeover::{
    parse_netsh_dnsservers, parse_route_print_ipv4, WinNetSnapshot, WinStepExecutor,
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
    let dns = parse_netsh_dnsservers(&out(&["netsh", "interface", "ip", "show", "dnsservers"])?);
    Ok(WinNetSnapshot {
        default_routes: v4,
        dns_servers: dns,
    })
}

/// 旁路绑定原语（RIL-032 imac 实证的面）：出站 UDP socket 显式 bind
/// 物理口 IP → 同目标全程钉在物理口，不被 TUN 捕获。bind_ip 来自
/// [`WinNetSnapshot::escape_bind_ip`]；端口 0 = 系统分配（socket 生命周期
/// 由调用方持有）。TCP 旁路同原语但 std `TcpStream` 无「先 bind 后
/// connect」直配接口——socket2 归 wireguard-nt 批次一并接入。
pub fn bind_escape_udp(bind_ip: std::net::IpAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind((bind_ip, 0))
}
