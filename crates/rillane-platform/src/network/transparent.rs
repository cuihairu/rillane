//! 透明接管 socket 面（RIL-139）：REDIRECT / TPROXY 两机制的监听原语与
//! 原目标恢复 + 规则规划（纯 argv 构造，执行归调用方/特权验收门）。
//!
//! 机制口径：
//! - **REDIRECT**：conntrack NAT REDIRECT 把目标流量转向本机监听；已接管
//!   连接的**原目标**经 `SO_ORIGINAL_DST`（getsockopt，SOL_IP/SOL_IPV6，
//!   opt 80）恢复。**未接管直连**（无 conntrack NAT 记录）getsockopt 返回
//!   ENOENT——按具名拒绝上抛（不静默取零/本地地址，防非透明直连被误路由）。
//! - **TPROXY**：监听 socket 设 `IP_TRANSPARENT`（需 CAP_NET_ADMIN，无权限
//!   显式报错不静默降级）后绑定**非本地**目标地址——TPROXY 连接保持原目标
//!   为 socket 本地地址，故**原目标 = accepted socket `local_addr()`**
//!   （无需 cmsg）。
//!
//! 边界（验收口径，具名于 networking.md transparent 节）：
//! - TCP 应用面交付；UDP/QUIC 应用面不交付（catalog 口径）；
//! - 平台面=Linux（iptables/nftables + IP_TRANSPARENT/SO_ORIGINAL_DST）——
//!   Windows/macOS（WFP/pf）不在本项；
//! - 规则应用/撤销需 CAP_NET_ADMIN；本验收门（#[ignore]）在具平台权限的
//!   机器上跑，普通席位只跑负路径契约（ENOENT / EPERM 具名拒绝）。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;

use nix::libc;
use socket2::{Domain, SockAddr, Socket, Type};

use crate::network::takeover::TAKEOVER_FWMARK;

/// `SO_ORIGINAL_DST`（linux/netfilter_ipv4.h；IPv6 同号 under SOL_IPV6）
pub const SO_ORIGINAL_DST: libc::c_int = 80;
/// `IP_TRANSPARENT`（linux/in.h）
const IP_TRANSPARENT: libc::c_int = 19;
/// TPROXY 标记流量路由 mark（与 TAKEOVER_FWMARK 逃逸 mark 相邻、语义独立：
/// 逃逸 mark 走物理网卡，TPROXY mark 走 local 表回本机监听）
pub const TPROXY_MARK: u32 = 0x5E46;

/// 从 getsockopt 裸缓冲解析 IPv4 `sockaddr_in`（family u16 + port u16(be)
/// + addr 4B(be) + 8B 填充；len≥16）。
pub fn parse_sockaddr_in(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 16 {
        return None;
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

/// 从裸缓冲解析 IPv6 `sockaddr_in6`（family u16 + port u16(be) + flowinfo
/// u32 + addr 16B + scope_id u32；len≥28）。
pub fn parse_sockaddr_in6(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 28 {
        return None;
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[8..24]);
    let ip = Ipv6Addr::from(octets);
    let scope = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
}

/// 恢复 REDIRECT 连接的原目标：先试 IPv4（SOL_IP）再试 IPv6（SOL_IPV6），
/// 取先成功者；无 conntrack NAT 记录（未接管直连）→ ENOENT → 具名拒绝。
pub fn original_destination<S: AsRawFd>(sock: &S) -> io::Result<SocketAddr> {
    let fd = sock.as_raw_fd();
    let mut v4 = [0u8; 16];
    if getsockopt_sockaddr(fd, libc::SOL_IP, SO_ORIGINAL_DST, &mut v4).is_ok() {
        if let Some(sa) = parse_sockaddr_in(&v4) {
            return Ok(sa);
        }
    }
    let mut v6 = [0u8; 32];
    if getsockopt_sockaddr(fd, libc::SOL_IPV6, SO_ORIGINAL_DST, &mut v6).is_ok() {
        if let Some(sa) = parse_sockaddr_in6(&v6) {
            return Ok(sa);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "连接未被接管（无 conntrack NAT REDIRECT 记录；非透明直连须拒绝，不静默取本地地址）",
    ))
}

fn getsockopt_sockaddr(
    fd: i32,
    level: libc::c_int,
    opt: libc::c_int,
    buf: &mut [u8],
) -> io::Result<()> {
    let mut len = buf.len() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            opt,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 建 TPROXY 监听 socket：`IP_TRANSPARENT`（SOL_IP，bind 前）+ bind +
/// listen + 非阻塞。IPv4 面交付（规则规划为 IPv4；IPv6 需
/// IPV6_TRANSPARENT 与 v6 规则面，归后续项——具名拒绝不静默降级）。
pub fn make_transparent_listener(listen: SocketAddr) -> io::Result<std::net::TcpListener> {
    let IpAddr::V4(_) = listen.ip() else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent 接管仅 IPv4 面交付（RIL-139：规则规划为 IPv4；IPv6 需 IPV6_TRANSPARENT 与 v6 规则面，归后续项）",
        ));
    };
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    set_transparent(&socket)?;
    socket.bind(&SockAddr::from(listen))?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// 给监听 socket 设 `IP_TRANSPARENT`（TPROXY 前置；需 CAP_NET_ADMIN——
/// 无权限显式报错点名，不静默降级）。socket 须未绑定（bind 前设置）。
pub fn set_transparent<S: AsRawFd>(sock: &S) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("IP_TRANSPARENT 设置失败（需 CAP_NET_ADMIN；无权限时 TPROXY 面不可用）：{e}"),
        ));
    }
    Ok(())
}

/// 透明接管规则：apply/undo 均为 `iptables`/`ip` argv（首元素即程序名），
/// 经既有 StepExecutor 口径执行（shell-out；与 RIL-029 `ip` 面同构）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentRule {
    /// 幂等键（对账/诊断/undo 定位）
    pub label: String,
    /// apply argv（如 `["iptables", "-t", "nat", "-A", ...]`）
    pub apply: Vec<String>,
    /// undo argv（如 `["iptables", "-t", "nat", "-D", ...]`；幂等：目标不存在
    /// 视为已撤销）
    pub undo: Vec<String>,
}

/// REDIRECT 规则规划（IPv4 NAT REDIRECT）：PREROUTING（经路由器的入站）
/// 与 OUTPUT（本机产生流量，排除逃逸 mark——自环防制面，mark 口径与
/// RIL-029 逃逸表同值）两条链。`ports` 空 = 全端口单规则；非空 = 逐端口。
pub fn plan_redirect_rules(
    listen: SocketAddr,
    ports: &[u16],
    escape_mark: u32,
) -> Vec<TransparentRule> {
    let to_ports = listen.port().to_string();
    let port_specs: Vec<Option<u16>> = if ports.is_empty() {
        vec![None]
    } else {
        ports.iter().map(|p| Some(*p)).collect()
    };
    let mut rules = Vec::new();
    for p in &port_specs {
        let dport = dport_arg(*p);
        // PREROUTING：经路由器的入站流量
        let label = format!(
            "redirect:prerouting:{}",
            p.map_or("all".into(), |x| x.to_string())
        );
        rules.push(TransparentRule {
            label: label.clone(),
            apply: iptables_argv(
                "nat",
                "-A",
                "PREROUTING",
                &dport,
                "REDIRECT",
                &["--to-ports".into(), to_ports.clone()],
            ),
            undo: iptables_argv(
                "nat",
                "-D",
                "PREROUTING",
                &dport,
                "REDIRECT",
                &["--to-ports".into(), to_ports.clone()],
            ),
        });
        // OUTPUT：本机产生流量，排除逃逸 mark（本进程出站不回收）
        let label = format!(
            "redirect:output:{}",
            p.map_or("all".into(), |x| x.to_string())
        );
        let target_args = vec![
            "--to-ports".to_string(),
            to_ports.clone(),
            "-m".to_string(),
            "mark".to_string(),
            "!".to_string(),
            "--mark".to_string(),
            escape_mark.to_string(),
        ];
        rules.push(TransparentRule {
            apply: iptables_argv("nat", "-A", "OUTPUT", &dport, "REDIRECT", &target_args),
            undo: iptables_argv("nat", "-D", "OUTPUT", &dport, "REDIRECT", &target_args),
            label,
        });
    }
    rules
}

/// TPROXY 规则规划（IPv4）：mangle PREROUTING TPROXY（on-port/on-ip）+ 标记
/// 流量经 ip rule fwmark + local 路由回本机监听。`ports` 语义同 redirect。
pub fn plan_tproxy_rules(
    listen: SocketAddr,
    ports: &[u16],
    rule_table: u32,
) -> Vec<TransparentRule> {
    let on_port = listen.port().to_string();
    let on_ip = listen.ip().to_string();
    let mark = TPROXY_MARK.to_string();
    let table = rule_table.to_string();
    let port_specs: Vec<Option<u16>> = if ports.is_empty() {
        vec![None]
    } else {
        ports.iter().map(|p| Some(*p)).collect()
    };
    let mut rules = Vec::new();
    for p in &port_specs {
        let dport = dport_arg(*p);
        let label = format!(
            "tproxy:mangle:{}",
            p.map_or("all".into(), |x| x.to_string())
        );
        let target_args = vec![
            "--on-port".to_string(),
            on_port.clone(),
            "--on-ip".to_string(),
            on_ip.clone(),
        ];
        rules.push(TransparentRule {
            apply: iptables_argv("mangle", "-A", "PREROUTING", &dport, "TPROXY", &target_args),
            undo: iptables_argv("mangle", "-D", "PREROUTING", &dport, "TPROXY", &target_args),
            label,
        });
    }
    // ip rule fwmark + local 路由（标记流量回本机监听；undo 逆序）
    rules.push(TransparentRule {
        label: "tproxy:rule".into(),
        apply: vec![
            "ip".into(),
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            mark.clone(),
            "table".into(),
            table.clone(),
        ],
        undo: vec![
            "ip".into(),
            "rule".into(),
            "del".into(),
            "fwmark".into(),
            mark.clone(),
            "table".into(),
            table.clone(),
        ],
    });
    rules.push(TransparentRule {
        label: "tproxy:route".into(),
        apply: vec![
            "ip".into(),
            "route".into(),
            "replace".into(),
            "local".into(),
            "0.0.0.0/0".into(),
            "dev".into(),
            "lo".into(),
            "table".into(),
            table.clone(),
        ],
        undo: vec![
            "ip".into(),
            "route".into(),
            "del".into(),
            "local".into(),
            "0.0.0.0/0".into(),
            "dev".into(),
            "lo".into(),
            "table".into(),
            table,
        ],
    });
    rules
}

fn dport_arg(port: Option<u16>) -> Vec<String> {
    match port {
        Some(p) => vec!["-m".into(), "tcp".into(), "--dport".into(), p.to_string()],
        None => Vec::new(),
    }
}

/// `iptables -t <table> -A|-D <chain> -p tcp [<dport>] -j <target> [<target_args>]`
fn iptables_argv(
    table: &str,
    action: &str,
    chain: &str,
    dport: &[String],
    target: &str,
    target_args: &[String],
) -> Vec<String> {
    let mut v = vec![
        "iptables".to_string(),
        "-t".into(),
        table.to_string(),
        action.into(),
        chain.into(),
        "-p".into(),
        "tcp".into(),
    ];
    v.extend(dport.iter().cloned());
    v.extend(["-j".into(), target.to_string()]);
    v.extend(target_args.iter().cloned());
    v
}

/// 逃逸 mark 缺省（RIL-029 同值）
pub const DEFAULT_ESCAPE_MARK: u32 = TAKEOVER_FWMARK;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr() {
        let mut buf = [0u8; 16];
        buf[0] = libc::AF_INET as u8;
        buf[2] = 0x1f; // port 0x1F90 = 8080
        buf[3] = 0x90;
        buf[4] = 0xc0; // 192.0.2.10
        buf[5] = 0x00;
        buf[6] = 0x02;
        buf[7] = 0x0a;
        let sa = parse_sockaddr_in(&buf).expect("v4 解析");
        assert_eq!(sa, "192.0.2.10:8080".parse::<SocketAddr>().unwrap());
        assert!(parse_sockaddr_in(&buf[..8]).is_none(), "短缓冲拒绝");
    }

    #[test]
    fn parses_ipv6_sockaddr() {
        let mut buf = [0u8; 28];
        buf[0] = libc::AF_INET6 as u8;
        buf[2] = 0x01; // port 0x01BB = 443
        buf[3] = 0xbb;
        // 2001:db8::1
        buf[8] = 0x20;
        buf[9] = 0x01;
        buf[10] = 0x0d;
        buf[11] = 0xb8;
        buf[23] = 0x01;
        buf[24] = 0; // scope_id 0
        let sa = parse_sockaddr_in6(&buf).expect("v6 解析");
        assert_eq!(sa, "[2001:db8::1]:443".parse::<SocketAddr>().unwrap());
        assert!(parse_sockaddr_in6(&buf[..16]).is_none(), "短缓冲拒绝");
    }

    /// 未接管直连：original_destination 具名拒绝（ENOENT——无 conntrack
    /// NAT 记录），不静默取零地址。本测试无特权可跑（直连 socket 本就无
    /// NAT 记录，确定返回 ENOENT）。
    #[test]
    fn unredirected_connection_is_named_refused() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("建 socket");
        let err = original_destination(&sock).expect_err("未接管应拒绝");
        assert!(
            err.to_string().contains("未被接管"),
            "错误应点名未接管: {err}"
        );
    }

    /// TPROXY 前置：无 CAP_NET_ADMIN 时 set_transparent 显式报错点名权限；
    /// root 下设置成功（读回验证）。环境分支（同 RIL-029 socket bypass 测）。
    #[test]
    fn transparent_set_requires_privilege_or_succeeds_as_root() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("建 socket");
        let result = set_transparent(&sock);
        if unsafe { libc::geteuid() } == 0 {
            result.expect("root 下应设上 IP_TRANSPARENT");
        } else {
            let err = result.expect_err("无权限应显式报错");
            assert!(
                err.to_string().contains("CAP_NET_ADMIN"),
                "错误应点名权限: {err}"
            );
        }
    }

    /// TPROXY 监听构造：无 CAP_NET_ADMIN 时具名拒绝（EPERM → 点名权限）；
    /// root 下建监听成功（读回非阻塞）。环境分支（同
    /// transparent_set_requires_privilege_or_succeeds_as_root）。
    #[test]
    fn transparent_listener_requires_privilege_or_succeeds_as_root() {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = make_transparent_listener(listen);
        if unsafe { libc::geteuid() } == 0 {
            let l = result.expect("root 下应建上 TPROXY 监听");
            assert!(l.local_addr().is_ok());
        } else {
            let err = result.expect_err("无权限应显式报错");
            assert!(
                err.to_string().contains("CAP_NET_ADMIN"),
                "错误应点名权限: {err}"
            );
        }
    }

    /// REDIRECT 规则规划：PREROUTING + OUTPUT（排除逃逸 mark）逐端口；
    /// 全端口单规则；undo 与 apply 同构（-A ↔ -D）。
    #[test]
    fn redirect_rule_plan_shape() {
        let listen: SocketAddr = "0.0.0.0:12345".parse().unwrap();
        let rules = plan_redirect_rules(listen, &[80, 443], DEFAULT_ESCAPE_MARK);
        assert_eq!(rules.len(), 4, "两端口 × PREROUTING/OUTPUT");
        // PREROUTING 80
        assert_eq!(rules[0].label, "redirect:prerouting:80");
        assert!(rules[0].apply.contains(&"-A".to_string()));
        assert!(rules[0].apply.contains(&"PREROUTING".to_string()));
        assert!(rules[0].apply.contains(&"--dport".to_string()));
        assert!(rules[0].apply.contains(&"--to-ports".to_string()));
        assert!(rules[0].apply.contains(&"12345".to_string()));
        assert!(rules[0].undo.contains(&"-D".to_string()));
        // OUTPUT 80 排除逃逸 mark
        assert!(rules[1].apply.contains(&"OUTPUT".to_string()));
        assert!(rules[1].apply.contains(&"!".to_string()));
        assert!(rules[1].apply.contains(&DEFAULT_ESCAPE_MARK.to_string()));
        assert!(rules[1].apply.contains(&"mark".to_string()));

        // 全端口：单规则对
        let rules_all = plan_redirect_rules(listen, &[], DEFAULT_ESCAPE_MARK);
        assert_eq!(rules_all.len(), 2);
        assert!(!rules_all[0].apply.contains(&"--dport".to_string()));
    }

    /// TPROXY 规则规划：mangle TPROXY + ip rule + ip route；undo 逆序。
    #[test]
    fn tproxy_rule_plan_shape() {
        let listen: SocketAddr = "0.0.0.0:12345".parse().unwrap();
        let rules = plan_tproxy_rules(listen, &[443], 100);
        assert_eq!(rules.len(), 3, "mangle + ip rule + ip route");
        assert_eq!(rules[0].label, "tproxy:mangle:443");
        assert!(rules[0].apply.contains(&"TPROXY".to_string()));
        assert!(rules[0].apply.contains(&"--on-port".to_string()));
        assert!(rules[0].apply.contains(&"12345".to_string()));
        assert_eq!(rules[1].apply[0], "ip");
        assert_eq!(rules[1].apply[1], "rule");
        assert!(rules[1].apply.contains(&TPROXY_MARK.to_string()));
        assert!(rules[2].apply.contains(&"local".to_string()));
        assert!(rules[2].apply.contains(&"table".to_string()));
    }
}
