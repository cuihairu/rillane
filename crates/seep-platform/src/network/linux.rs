//! Linux TUN 真实现（tun-dataplane.md §1）
//!
//! T1（设备生命周期与读写，§1.1/§1.2）：
//! - `create_interface` = open `/dev/net/tun`（E1/E2 错误提示）→ TUNSETIFF
//!   （`IFF_TUN | IFF_NO_PI` 纯 IP 包无 4 字节前缀，E3/E4 错误映射）→
//!   TUNGETIFF 读回实际名（None → 内核分配 `tun%d`）→ 非阻塞 + `AsyncFd`；
//! - destroy = drop fd（内核自动回收接口，E16 幂等）；
//! - `up`/`down`/`configure_ip` 走 `ip` 命令子进程（§1.3 shell-out，构造/
//!   执行分离）；`configure_routing` 委托点为 `LinuxRouteManager`（T2 落地）；
//! - `read_packet`/`write_packet` = AsyncFd 就绪循环 + MTU 缓冲 +
//!   `PacketInfo` 联动（E9 坏包丢弃计数、不中断流；E8 真错误上抛）。
//!
//! T2（系统路由）见同文件 `LinuxRouteManager`：MVP = main 表显式路由
//! include 语义（§1.3），`AppliedStep` 记录已执行步骤供逆序撤销。

use std::{
    fmt, fs,
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Mutex,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use nix::{libc, errno::Errno};
use tokio::{io::unix::AsyncFd, process::Command};
use tracing::debug;

use super::route::{RouteManager, RouteMonitor, RouteRule, RouteStats, RoutingConfig};
use super::tun::{InterfaceStats, PacketInfo, PacketType, TunConfig, TunProvider};

// TUN ioctl（§1.1：libc 定义与内核 tun.h 同源——TUNSETIFF = _IOW('T', 202, int)）
nix::ioctl_write_ptr_bad!(tun_set_iff, libc::TUNSETIFF, libc::ifreq);
nix::ioctl_read_bad!(tun_get_iff, libc::TUNGETIFF, libc::ifreq);

/// 构建 TUNSETIFF 请求：ifr_name 按给定名（空名 = 内核分配 tun%d）、
/// flags 固定 `IFF_TUN | IFF_NO_PI`（§6-4：TAP 归 V2）
fn build_iff_request(name: &str) -> Result<libc::ifreq> {
    if name.len() >= libc::IFNAMSIZ as usize {
        return Err(anyhow!(
            "TUN 接口名 {:?} 超长（≥{} 字节，E4 早期拦截）",
            name,
            libc::IFNAMSIZ
        ));
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        req.ifr_name[i] = b as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    Ok(req)
}

/// 从 ifreq 读回接口名（TUNGETIFF 后内核填写）
fn ifreq_name(req: &libc::ifreq) -> String {
    let raw: Vec<u8> = req
        .ifr_name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&raw).into_owned()
}

/// IPv4 点分掩码 → 前缀长度（`ip addr replace` 的 CIDR 半边）
fn netmask_prefix(netmask: Ipv4Addr) -> u8 {
    u32::from(netmask).leading_ones() as u8
}

/// §4.1：`ip` 命令构造与执行分离——以下构造函数只拼 argv（含程序名），
/// 不执行；执行统一走 [`run_ip`]（E6/E7 语义）
fn ip_argv_link_up(name: &str, mtu: u16) -> Vec<String> {
    vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        "dev".into(),
        name.into(),
        "up".into(),
        "mtu".into(),
        mtu.to_string(),
    ]
}

fn ip_argv_link_down(name: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        "dev".into(),
        name.into(),
        "down".into(),
    ]
}

fn ip_argv_addr_replace(cidr: &str, name: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "addr".into(),
        "replace".into(),
        cidr.into(),
        "dev".into(),
        name.into(),
    ]
}

/// 执行 `ip` 子进程（§1.3 shell-out）
///
/// - E6：命令不存在 → 附 iproute2/busybox 提示；
/// - E7：非零退出 → 带 stdout/stderr 撤销前信息上抛（启动失败不静默）。
async fn run_ip(argv: &[String]) -> Result<()> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| anyhow!("ip argv 为空（构造器缺陷）"))?;
    let out = Command::new(prog)
        .args(args)
        .output()
        .await
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => anyhow!(
                "ip 命令不可用（E6）——需 iproute2 或 busybox ip：{e}"
            ),
            _ => anyhow!("执行 ip 失败：{e}"),
        })?;
    if !out.status.success() {
        return Err(anyhow!(
            "ip {} 失败（{}，E7）：{}",
            args.join(" "),
            out.status,
            [
                String::from_utf8_lossy(&out.stdout).trim().to_string(),
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ]
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("；")
        ));
    }
    Ok(())
}

/// 打开 `/dev/net/tun`（E1/E2 错误提示）
fn open_tun_file() -> Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => anyhow!(
                "打开 /dev/net/tun 失败（ENOENT，E1）——需 modprobe tun，容器需映射设备节点：{e}"
            ),
            io::ErrorKind::PermissionDenied => anyhow!(
                "打开 /dev/net/tun 失败（EPERM/EACCES，E2）——需 CAP_NET_ADMIN（root/capabilities）：{e}"
            ),
            _ => anyhow!("打开 /dev/net/tun 失败：{e}"),
        })
}

/// TUNSETIFF errno 映射（E2/E3/E4）
fn map_tunsetiff_err(name: &str, e: Errno) -> anyhow::Error {
    match e {
        Errno::EEXIST => anyhow!(
            "TUNSETIFF EEXIST——接口名 {name:?} 已被占用（config.name 强制名冲突，E3）：{e}"
        ),
        Errno::EPERM | Errno::EACCES => anyhow!(
            "TUNSETIFF {e}——需 CAP_NET_ADMIN（root/capabilities，E2）：接口 {name:?}"
        ),
        Errno::EINVAL => anyhow!(
            "TUNSETIFF EINVAL——flags={:#x}（IFF_TUN|IFF_NO_PI）非法（程序缺陷，E4）：{e}",
            libc::IFF_TUN | libc::IFF_NO_PI
        ),
        _ => anyhow!("TUNSETIFF 失败：{e}"),
    }
}

/// TUN 包解析（§1.1 IFF_NO_PI：纯 IP 包、无以太网头、无 4 字节 PI 前缀）——
/// 直接按首 nibble 定版本再走 `PacketInfo::parse_ip_header`；
/// 不复用 `parse_packet_info` 的以太网猜测（TUN 输入无 ethertype，
/// 误判会把 src IP 前两字节当 ethertype）
fn parse_tun_packet(data: &[u8]) -> Result<PacketInfo> {
    if data.is_empty() {
        return Err(anyhow!("空数据包"));
    }
    let version = (data[0] >> 4) & 0x0F;
    let mut info = PacketInfo::new(PacketType::from_ip_version(version), data.len());
    info.parse_ip_header(data)?;
    Ok(info)
}

/// Linux TUN 设备提供者（tun-dataplane.md §1.1/§1.2）
///
/// 单 fd（IFF_MULTI_QUEUE 归 V2）；`fd = None` 表示设备尚未创建，
/// `name` 在 `create_interface` 中由 TUNGETIFF 读回（内核分配 tun%d）。
pub struct LinuxTunProvider {
    config: TunConfig,
    fd: Option<AsyncFd<OwnedFd>>,
    name: String,
    up: bool,
    stats: InterfaceStats,
}

impl fmt::Debug for LinuxTunProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // AsyncFd 不承诺 Debug；fd 只输出开关态
        f.debug_struct("LinuxTunProvider")
            .field("name", &self.name)
            .field("fd_open", &self.fd.is_some())
            .field("up", &self.up)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LinuxTunProvider {
    /// 创建提供者（不触碰设备；设备 open/attach 在 [`Self::create_interface`]）
    pub fn new(config: TunConfig) -> Self {
        Self {
            name: config.name.clone().unwrap_or_default(),
            fd: None,
            config,
            up: false,
            stats: InterfaceStats::default(),
        }
    }

    fn ensure_created(&self) -> Result<()> {
        if self.fd.is_some() {
            Ok(())
        } else {
            Err(anyhow!(
                "TUN 设备未创建——先调用 create_interface（接口 {:?}）",
                self.config.name
            ))
        }
    }
}

#[async_trait]
impl TunProvider for LinuxTunProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn config(&self) -> &TunConfig {
        &self.config
    }

    fn is_up(&self) -> bool {
        self.up
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn stats(&self) -> InterfaceStats {
        self.stats.clone()
    }

    async fn create_interface(&mut self) -> Result<()> {
        if self.fd.is_some() {
            return Ok(()); // 幂等（E16 同口径）
        }

        let file = open_tun_file()?;
        let requested = self.config.name.clone().unwrap_or_default();
        let req = build_iff_request(&requested)?;
        unsafe { tun_set_iff(file.as_raw_fd(), &req) }
            .map_err(|e| map_tunsetiff_err(&requested, e))?;

        // 内核为名的唯一事实源：TUNGETIFF 读回（None → tun%d 分配名）
        let mut back = build_iff_request("")?;
        unsafe { tun_get_iff(file.as_raw_fd(), &mut back) }
            .map_err(|e| anyhow!("TUNGETIFF 读回接口名失败：{e}"))?;
        self.name = ifreq_name(&back);
        if self.name.is_empty() {
            return Err(anyhow!("TUNGETIFF 读回空接口名——内核状态异常"));
        }

        // 非阻塞（AsyncFd 就绪语义要求，§1.1）
        nix::fcntl::fcntl(
            file.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .map_err(|e| anyhow!("设置 O_NONBLOCK 失败：{e}"))?;

        // File → OwnedFd 所有权交接（随即由 AsyncFd 持有，无泄漏）
        let owned: OwnedFd = file.into();
        self.fd = Some(AsyncFd::new(owned).context("注册 AsyncFd 失败")?);
        debug!(target: "seep::tun", name = %self.name, mtu = self.config.mtu, "Linux TUN 设备已创建");
        Ok(())
    }

    async fn destroy_interface(&mut self) -> Result<()> {
        if self.fd.take().is_some() {
            // drop fd = 内核回收接口（E16 幂等）
            debug!(target: "seep::tun", name = %self.name, "Linux TUN 设备已销毁");
        }
        self.up = false;
        Ok(())
    }

    async fn up_interface(&mut self) -> Result<()> {
        self.ensure_created()?;
        // up 与 MTU 一条命令（均幂等，§1.3）；MTU 取 TunConfig.mtu（§1.1）
        run_ip(&ip_argv_link_up(&self.name, self.config.mtu)).await?;
        self.up = true;
        Ok(())
    }

    async fn down_interface(&mut self) -> Result<()> {
        if self.fd.is_none() {
            return Ok(()); // 幂等（E16）
        }
        run_ip(&ip_argv_link_down(&self.name)).await?;
        self.up = false;
        Ok(())
    }

    async fn configure_ip(&mut self) -> Result<()> {
        self.ensure_created()?;
        // 掩码缺省按 /32（单机假设，TunConfig::validate 已对不完整配置 WARN）；
        // ipv4_gateway 不在此消费——默认路由/网关接管归 P1-3（§6-3）
        let mut configured = false;
        if let Some(v4) = self.config.ipv4_addr {
            let prefix = self
                .config
                .ipv4_netmask
                .map(netmask_prefix)
                .unwrap_or(32);
            run_ip(&ip_argv_addr_replace(
                &format!("{v4}/{prefix}"),
                &self.name,
            ))
            .await?;
            configured = true;
        }
        if let Some(v6) = self.config.ipv6_addr {
            let prefix = self.config.ipv6_prefix_len.unwrap_or(128);
            run_ip(&ip_argv_addr_replace(
                &format!("{v6}/{prefix}"),
                &self.name,
            ))
            .await?;
            configured = true;
        }
        if !configured {
            debug!(target: "seep::tun", name = %self.name, "无地址可配置，直通");
        }
        Ok(())
    }

    async fn configure_routing(&mut self) -> Result<()> {
        // 委托点 = LinuxRouteManager（TunIngress 属主化设备+路由，§2.6/§6-7）；
        // 路由真实现归 T2
        Err(anyhow!(
            "configure_routing 委托 LinuxRouteManager——路由落 T2（tun-dataplane.md §1.3）"
        ))
    }

    async fn configure_dns(&mut self) -> Result<()> {
        // MVP 直通：TunConfig.dns_servers 仅记录，DNS 劫持归 P2-8
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<(Bytes, PacketInfo)> {
        let mtu = self.config.mtu as usize;
        let fd = self
            .fd
            .as_mut()
            .ok_or_else(|| anyhow!("TUN 设备未创建——先调用 create_interface"))?;
        loop {
            let mut guard = fd.readable().await?;
            let mut buf = vec![0u8; mtu];
            let attempt = guard.try_io(|inner| {
                let raw = inner.get_ref().as_raw_fd();
                match nix::unistd::read(raw, &mut buf) {
                    Ok(n) => Ok(n),
                    Err(Errno::EAGAIN) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                    Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
                }
            });
            let n = match attempt {
                Ok(Ok(0)) => continue, // 0 字节非包，继续等就绪
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    self.stats.receive_errors += 1;
                    // E8：设备已关/异常 → 错误上抛（ingress 运行时即终止语义）
                    return Err(anyhow!(e).context("TUN 读包失败（E8）"));
                }
                Err(_would_block) => continue, // readiness 已清，回 readable().await
            };
            buf.truncate(n);

            // PacketInfo 联动（E9：坏包丢弃 + 计数，不中断读流）
            let info = match parse_tun_packet(&buf) {
                Ok(info) => info,
                Err(e) => {
                    self.stats.receive_errors += 1;
                    debug!(target: "seep::tun", error = %e, "TUN 包解析失败，丢弃（E9）");
                    continue;
                }
            };
            self.stats.packets_received += 1;
            self.stats.bytes_received += n as u64;
            return Ok((Bytes::from(buf), info));
        }
    }

    async fn write_packet(&mut self, packet: Bytes) -> Result<()> {
        let fd = self
            .fd
            .as_mut()
            .ok_or_else(|| anyhow!("TUN 设备未创建——先调用 create_interface"))?;
        loop {
            let mut guard = fd.writable().await?;
            let attempt = guard.try_io(|inner| match nix::unistd::write(
                inner.get_ref(),
                packet.as_ref(),
            ) {
                Ok(n) => Ok(n),
                Err(Errno::EAGAIN) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
            });
            match attempt {
                Ok(Ok(n)) if n == packet.len() => {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += n as u64;
                    return Ok(());
                }
                Ok(Ok(n)) => {
                    // TUN 包面向写，部分写不应发生——防御性报错（计数见 send_errors）
                    self.stats.send_errors += 1;
                    return Err(anyhow!("TUN 部分写入 {n}/{} 字节", packet.len()));
                }
                Ok(Err(e)) => {
                    self.stats.send_errors += 1;
                    return Err(anyhow!(e).context("TUN 写包失败"));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// 已执行的配置步骤——apply 逆序撤销与 clear_routing 的事实源
/// （tun-dataplane.md §1.3：ip addr/link/route replace 均幂等，
/// 撤销对应 del/down）
#[derive(Debug, Clone)]
pub enum AppliedStep {
    /// `ip addr replace` 配置到接口的地址
    AddrReplaced { interface: String, cidr: String },
    /// `ip link set up` 拉起的接口
    LinkUp { interface: String },
    /// `ip route replace` 安装到 main 表的路由
    RouteReplaced {
        cidr: String,
        interface: String,
        metric: u32,
    },
}

/// Linux 系统路由管理器（tun-dataplane.md §1.3）
///
/// MVP = main 表显式路由 include 语义（不改默认路由、不用 ip rule、
/// 无需 fwmark）；`ip` 命令子进程执行（netlink 归 V2）。
#[derive(Debug)]
pub struct LinuxRouteManager {
    config: RoutingConfig,
    /// T2 起由 apply/clear 读写（记录已执行步骤供逆序撤销）
    #[allow(dead_code)]
    applied: Mutex<Vec<AppliedStep>>,
}

impl LinuxRouteManager {
    /// 创建路由管理器（不触碰系统路由；首次变更在 `apply_routing`）
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config,
            applied: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl RouteManager for LinuxRouteManager {
    fn config(&self) -> &RoutingConfig {
        &self.config
    }

    fn stats(&self) -> RouteStats {
        RouteStats::default()
    }

    async fn apply_routing(&self) -> Result<()> {
        Err(anyhow!("Linux 路由应用（ip route replace + AppliedStep 记录）归 T2（tun-dataplane.md §1.3）"))
    }

    async fn clear_routing(&self) -> Result<()> {
        Err(anyhow!("Linux 路由清理（逆序撤销 AppliedStep）归 T2（tun-dataplane.md §1.3）"))
    }

    async fn add_route(&self, _rule: RouteRule) -> Result<()> {
        Err(anyhow!("Linux 单条路由添加归 T2（tun-dataplane.md §1.3）"))
    }

    async fn remove_route(&self, _name: &str) -> Result<()> {
        Err(anyhow!("Linux 单条路由删除归 T2（tun-dataplane.md §1.3）"))
    }

    async fn modify_route(&self, _rule: RouteRule) -> Result<()> {
        Err(anyhow!("Linux 路由修改归 T2（tun-dataplane.md §1.3）"))
    }

    async fn get_routing_table(&self) -> Result<Vec<RouteRule>> {
        Err(anyhow!("Linux 路由表读取归 T2（tun-dataplane.md §1.3）"))
    }

    async fn lookup_route(&self, _destination: std::net::IpAddr) -> Result<Option<RouteRule>> {
        Err(anyhow!("Linux 路由查找归 T2（tun-dataplane.md §1.3）"))
    }

    async fn enable_route(&self, _name: &str, _enabled: bool) -> Result<()> {
        Err(anyhow!("Linux 路由启停归 T2（tun-dataplane.md §1.3）"))
    }

    async fn flush_cache(&self) -> Result<()> {
        // 骨架无路由缓存可刷——真缓存随 T2 落地
        Ok(())
    }

    async fn monitor_changes(&self) -> Result<Box<dyn RouteMonitor>> {
        Err(anyhow!("Linux 路由变化监控归 T2+（tun-dataplane.md §1.3）"))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use super::*;

    // ---------- 单测（§4.1：无特权，任何环境） ----------

    #[test]
    fn iff_request_build_and_readback() {
        let req = build_iff_request("seep0").unwrap();
        assert_eq!(ifreq_name(&req), "seep0");
        assert_eq!(
            // union 字段读取需 unsafe（写入点在 build_iff_request 已初始化）
            unsafe { req.ifr_ifru.ifru_flags },
            (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short
        );

        // 空名 = 内核分配（tun%d）——全零 ifr_name
        let empty = build_iff_request("").unwrap();
        assert_eq!(ifreq_name(&empty), "");

        // 15 字节内合法，16 字节起超长（IFNAMSIZ=16 含 NUL）
        assert!(build_iff_request(&"a".repeat(15)).is_ok());
        let err = build_iff_request(&"a".repeat(16)).unwrap_err();
        assert!(err.to_string().contains("超长"), "超长名应早期拦截：{err}");
    }

    #[test]
    fn netmask_prefix_conversion() {
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(netmask_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn ip_argv_constructors() {
        assert_eq!(
            ip_argv_link_up("tun0", 1400),
            ["ip", "link", "set", "dev", "tun0", "up", "mtu", "1400"]
        );
        assert_eq!(
            ip_argv_link_down("tun0"),
            ["ip", "link", "set", "dev", "tun0", "down"]
        );
        assert_eq!(
            ip_argv_addr_replace("10.66.0.1/24", "tun0"),
            ["ip", "addr", "replace", "10.66.0.1/24", "dev", "tun0"]
        );
    }

    #[test]
    fn parse_tun_packet_v4_udp_golden() {
        // 最小 IPv4(20B, ihl=5, proto=17) + UDP 头前 4 字节（sport/dport）
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x1C, // ver/ihl, tos, total_len
            0x00, 0x00, 0x00, 0x00, // id, flags
            0x40, 0x11, 0x00, 0x00, // ttl, proto=UDP, csum
            1, 2, 3, 4, // src 1.2.3.4
            5, 6, 7, 8, // dst 5.6.7.8
            0x04, 0xD2, // sport 1234
            0x00, 0x50, // dport 80
        ];
        pkt.extend_from_slice(&[0u8; 4]); // UDP len/csum
        let info = parse_tun_packet(&pkt).unwrap();
        assert_eq!(info.packet_type, PacketType::Ipv4);
        assert_eq!(info.src_ip, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(info.dst_ip, Some("5.6.7.8".parse().unwrap()));
        assert_eq!(info.protocol, Some(17));
        assert_eq!(info.src_port, Some(1234));
        assert_eq!(info.dst_port, Some(80));
        assert_eq!(info.length, pkt.len());
        assert!(info.is_udp() && !info.is_tcp());
    }

    #[test]
    fn parse_tun_packet_v6_and_rejects() {
        // IPv6(40B, next=6/TCP) + TCP sport/dport
        let mut pkt = vec![0x60, 0, 0, 0, 0, 4, 6, 60]; // next=6(TCP), hop=60
        pkt.extend_from_slice(&[0u8; 16]); // src
        pkt.extend_from_slice(&[0u8; 16]); // dst
        pkt.extend_from_slice(&[0x1F, 0x90, 0x01, 0xBB]); // 8080 → 443
        let info = parse_tun_packet(&pkt).unwrap();
        assert_eq!(info.packet_type, PacketType::Ipv6);
        assert_eq!(info.protocol, Some(6));
        assert_eq!(info.src_port, Some(8080));
        assert_eq!(info.dst_port, Some(443));
        assert!(info.is_tcp());

        // 拒绝面：空 / 截断 / 未知版本
        assert!(parse_tun_packet(&[]).is_err());
        let truncated = [0x45u8; 10];
        assert!(parse_tun_packet(&truncated).is_err());
        let unknown_ver = [0x30u8; 24];
        let err = parse_tun_packet(&unknown_ver).unwrap_err();
        assert!(err.to_string().contains("不支持的 IP 版本"), "{err}");
    }

    // ---------- Linux 集成（§4.2：cfg(linux) 由本文件级 cfg 保证；
    //          运行时 skip 守卫——无 /dev/net/tun 或无 CAP_NET_ADMIN → 打印
    //          skip 返回，不算失败） ----------

    /// 探测 /dev/net/tun 可用性（ENOENT / EACCES → skip）
    fn tun_device_available() -> bool {
        match fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun") {
            Ok(_) => true,
            Err(e) => {
                eprintln!("skip: /dev/net/tun 不可用（{:?}）——需 modprobe tun / 容器映射设备节点", e.kind());
                false
            }
        }
    }

    /// 判断错误是否为「无 CAP_NET_ADMIN」（skip 而非失败）
    fn is_permission_skip(err: &anyhow::Error) -> bool {
        err.chain().any(|e| e.to_string().contains("CAP_NET_ADMIN"))
    }

    #[tokio::test]
    async fn device_lifecycle_and_capture() {
        if !tun_device_available() {
            return;
        }

        // 周期 A：强制名（§4.2 创建/强制名）+ up/addr/mtu 断言 + 捕获钉子
        let forced = format!("seepT1{}", std::process::id());
        let mut tun = LinuxTunProvider::new(
            TunConfig::default()
                .with_name(forced.clone())
                .with_ipv4(
                    Ipv4Addr::new(10, 66, 0, 1),
                    Ipv4Addr::new(255, 255, 255, 0),
                    Ipv4Addr::new(10, 66, 0, 1),
                ),
        );
        if let Err(e) = tun.create_interface().await {
            if is_permission_skip(&e) {
                eprintln!("skip: 无 CAP_NET_ADMIN——{e}");
                return;
            }
            panic!("create_interface 失败：{e:#}");
        }
        assert_eq!(tun.name(), forced, "强制名应原样生效（§4.2）");

        tun.up_interface().await.expect("up_interface");
        assert!(tun.is_up());
        tun.configure_ip().await.expect("configure_ip");

        // ip 命令读回断言（§4.2：up/addr/mtu）
        let out = Command::new("ip")
            .args(["addr", "show", "dev", tun.name()])
            .output()
            .await
            .expect("ip addr show");
        let addr_text = String::from_utf8_lossy(&out.stdout);
        assert!(
            addr_text.contains("10.66.0.1/24"),
            "addr 断言失败：{addr_text}"
        );
        let out = Command::new("ip")
            .args(["link", "show", "dev", tun.name()])
            .output()
            .await
            .expect("ip link show");
        let link_text = String::from_utf8_lossy(&out.stdout);
        assert!(
            link_text.contains(&format!("mtu {}", tun.mtu())),
            "mtu 断言失败：{link_text}"
        );

        // 捕获钉子（P1-1 验收核心，provider 半边）：应用 socket 发往
        // 10.66.0.2:9999 → 内核经 connected 路由注入 tun fd → read_packet 收包。
        // 先发后读（tun 队列缓冲不丢）；循环筛目标五元组——link up 后内核
        // 可能注入其他包（如 IPv6 RS），非目标包忽略不计入断言
        let sock = tokio::net::UdpSocket::bind("10.66.0.1:0")
            .await
            .expect("bind 10.66.0.1");
        let local_port = sock.local_addr().unwrap().port();
        let sent = sock
            .send_to(b"seep-t1", (Ipv4Addr::new(10, 66, 0, 2), 9999))
            .await
            .expect("send_to");
        assert_eq!(sent, 7, "应用侧发出 7 字节");

        let captured = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (bytes, info) = tun.read_packet().await.expect("read_packet");
                if info.dst_ip == Some(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)))
                    && info.dst_port == Some(9999)
                {
                    return (bytes, info);
                }
            }
        })
        .await
        .expect("5s 内未捕获目标 IP 包——内核未向 tun 注入");
        let (bytes, info) = captured;

        assert_eq!(info.packet_type, PacketType::Ipv4);
        assert_eq!(
            info.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)))
        );
        assert_eq!(
            info.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)))
        );
        assert_eq!(info.src_port, Some(local_port));
        assert_eq!(info.dst_port, Some(9999));
        assert_eq!(info.protocol, Some(17));
        assert_eq!(info.length, bytes.len());
        assert!(bytes.ends_with(b"seep-t1"), "UDP 载荷应在包尾");
        let stats = tun.stats();
        assert!(
            stats.packets_received >= 1,
            "读计数应含目标包（可能含链路噪声）"
        );
        assert!(stats.bytes_received >= stats.packets_received);

        tun.down_interface().await.expect("down_interface");
        assert!(!tun.is_up());
        tun.destroy_interface().await.expect("destroy_interface");

        // destroy = drop fd → 内核回收（§1.1）
        let gone = Command::new("ip")
            .args(["link", "show", "dev", &forced])
            .output()
            .await
            .expect("ip link show after destroy");
        assert!(
            !gone.status.success(),
            "destroy 后接口应被内核回收，仍见：{}",
            String::from_utf8_lossy(&gone.stdout)
        );

        // 周期 B：自动名读回（§4.2 创建/自动名读回 → tun%d）
        let mut auto = LinuxTunProvider::new(TunConfig::default());
        auto.create_interface().await.expect("auto create");
        assert!(
            auto.name().starts_with("tun"),
            "内核分配名应为 tun%%d 形式：{}",
            auto.name()
        );
        auto.destroy_interface().await.expect("auto destroy");
    }
}
