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

#[cfg(test)]
use std::sync::Arc;
use std::{
    fmt, fs, io,
    net::{IpAddr, Ipv4Addr},
    os::fd::{AsRawFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::SystemTime,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use nix::{errno::Errno, libc};
use tokio::{io::unix::AsyncFd, process::Command};
use tracing::debug;

use super::route::{
    parse_cidr, RouteDestination, RouteManager, RouteMonitor, RouteRule, RouteStats, RoutingConfig,
};
use super::tun::{InterfaceStats, PacketInfo, PacketType, TunConfig, TunProvider};

// TUN ioctl（§1.1：libc 定义与内核 tun.h 同源——TUNSETIFF = _IOW('T', 202, int)）
// ohos（musl 系 libc）：libc::ioctl 的 request 形参是 c_int（nix::sys::ioctl::ioctl_num_type
// 在 linux 恒为 c_ulong，两代 nix 均无 ohos 面）——`_bad` 宏的 `as c_ulong` 转换与目标
// libc 签名结构性冲突，故 ohos 面手写同形包装（-1 转 Errno，语义同 nix convert_ioctl_res）
#[cfg(target_env = "ohos")]
unsafe fn convert_ioctl_res(res: libc::c_int) -> nix::Result<libc::c_int> {
    if res == -1 {
        Err(Errno::last())
    } else {
        Ok(res)
    }
}

#[cfg(target_env = "ohos")]
pub unsafe fn tun_set_iff(fd: libc::c_int, data: *const libc::ifreq) -> nix::Result<libc::c_int> {
    convert_ioctl_res(unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::c_int, data) })
}

#[cfg(target_env = "ohos")]
pub unsafe fn tun_get_iff(fd: libc::c_int, data: *mut libc::ifreq) -> nix::Result<libc::c_int> {
    convert_ioctl_res(unsafe { libc::ioctl(fd, libc::TUNGETIFF as libc::c_int, data) })
}

#[cfg(not(target_env = "ohos"))]
nix::ioctl_write_ptr_bad!(tun_set_iff, libc::TUNSETIFF, libc::ifreq);
#[cfg(not(target_env = "ohos"))]
nix::ioctl_read_bad!(tun_get_iff, libc::TUNGETIFF, libc::ifreq);

/// 构建 TUNSETIFF 请求：ifr_name 按给定名（空名 = 内核分配 tun%d）、
/// flags 固定 `IFF_TUN | IFF_NO_PI`（§6-4：TAP 归 V2）
fn build_iff_request(name: &str) -> Result<libc::ifreq> {
    if name.len() >= libc::IFNAMSIZ {
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
            io::ErrorKind::NotFound => {
                anyhow!("ip 命令不可用（E6）——需 iproute2 或 busybox ip：{e}")
            }
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

/// `ip route replace <cidr> dev <iface> metric <metric>` 构造器
fn ip_argv_route_replace(cidr: &str, iface: &str, metric: u32) -> Vec<String> {
    vec![
        "ip".into(),
        "route".into(),
        "replace".into(),
        cidr.into(),
        "dev".into(),
        iface.into(),
        "metric".into(),
        metric.to_string(),
    ]
}

/// `ip route del <cidr> dev <iface>` 构造器（撤销用）
fn ip_argv_route_del(cidr: &str, iface: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "route".into(),
        "del".into(),
        cidr.into(),
        "dev".into(),
        iface.into(),
    ]
}

/// `ip addr del <cidr> dev <iface>` 构造器（撤销用）
fn ip_argv_addr_del(cidr: &str, iface: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "addr".into(),
        "del".into(),
        cidr.into(),
        "dev".into(),
        iface.into(),
    ]
}

/// `ip link set <iface> down` 构造器（撤销用）
fn ip_argv_link_down_name(iface: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        iface.into(),
        "down".into(),
    ]
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
        Errno::EEXIST => {
            anyhow!("TUNSETIFF EEXIST——接口名 {name:?} 已被占用（config.name 强制名冲突，E3）：{e}")
        }
        Errno::EPERM | Errno::EACCES => {
            anyhow!("TUNSETIFF {e}——需 CAP_NET_ADMIN（root/capabilities，E2）：接口 {name:?}")
        }
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
        // SAFETY: `owned` 是刚由 `file` 独占转换的 TUN fd，未被任何其他
        // AsyncFd 注册、无别名（I/O safety 契约成立）；`AsyncFd::new` 因缺
        // 乏该保证被弃用（tokio#8587），此处以 `register` + 显式契约注释迁移。
        self.fd = Some(
            unsafe { AsyncFd::register(owned) }
                .map_err(io::Error::from)
                .context("注册 AsyncFd 失败")?,
        );
        debug!(target: "rillane::tun", name = %self.name, mtu = self.config.mtu, "Linux TUN 设备已创建");
        Ok(())
    }

    async fn destroy_interface(&mut self) -> Result<()> {
        if self.fd.take().is_some() {
            // drop fd = 内核回收接口（E16 幂等）
            debug!(target: "rillane::tun", name = %self.name, "Linux TUN 设备已销毁");
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
            let prefix = self.config.ipv4_netmask.map(netmask_prefix).unwrap_or(32);
            run_ip(&ip_argv_addr_replace(&format!("{v4}/{prefix}"), &self.name)).await?;
            configured = true;
        }
        if let Some(v6) = self.config.ipv6_addr {
            let prefix = self.config.ipv6_prefix_len.unwrap_or(128);
            run_ip(&ip_argv_addr_replace(&format!("{v6}/{prefix}"), &self.name)).await?;
            configured = true;
        }
        if !configured {
            debug!(target: "rillane::tun", name = %self.name, "无地址可配置，直通");
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
                    debug!(target: "rillane::tun", error = %e, "TUN 包解析失败，丢弃（E9）");
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
            let attempt =
                guard.try_io(
                    |inner| match nix::unistd::write(inner.get_ref(), packet.as_ref()) {
                        Ok(n) => Ok(n),
                        Err(Errno::EAGAIN) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
                    },
                );
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

/// fwmark 逃逸表号（networking.md §2 半边②：rillane 自身出站 SO_MARK 逃逸
/// include 自环）——固定 100（用户自定义表段，避开 local/main/default
/// 系统保留表 255/254/253）；与 `ip rule fwmark` 规则配套，undo 逆序删除
const ESCAPE_TABLE: u32 = 100;

/// 解析 `ip route show default table main` 输出的首行 → escape 表默认路由
/// 模板（`default ` 后部分，如 `via 192.168.1.1 dev eth0 proto dhcp`）；
/// 无默认路由（空/非 default 行/仅空白）→ None（escape 表无出口，跳过
/// 逃逸面）。probe 与单测共用此纯函数，避免解析口径漂移
fn parse_escape_route_template(text: &str) -> Option<&str> {
    text.lines()
        .next()
        .and_then(|l| l.trim().strip_prefix("default "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// 已执行的配置步骤——apply 逆序撤销与 clear_routing 的事实源
/// （tun-dataplane.md §1.3：ip addr/link/route replace 均幂等，
/// 撤销对应 del/down）
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// `ip rule add fwmark <mark> table <escape>`（EEXIST 容忍 = 幂等；
    /// iproute2 无 rule replace，重复 add 报 File exists 视为已生效）
    FwmarkRule { mark: u32, table: u32 },
    /// `ip route replace default <via_dev> table <escape>`（escape 表默认
    /// 路由，via_dev 取 main 表首条默认路由——带 mark 的包查 escape 表
    /// 需有出口，否则丢弃）
    EscapeRoute { table: u32, via_dev: String },
}

impl AppliedStep {
    /// 正向执行 argv（apply 执行与 REST/CLI step 渲染共用——planner 只拼
    /// 步骤，argv 从步骤还原保证「计划 = 执行」无第二构造路径）
    pub fn argv(&self) -> Vec<String> {
        match self {
            AppliedStep::AddrReplaced { interface, cidr } => ip_argv_addr_replace(cidr, interface),
            AppliedStep::LinkUp { interface } => vec![
                "ip".into(),
                "link".into(),
                "set".into(),
                "dev".into(),
                interface.clone(),
                "up".into(),
            ],
            AppliedStep::RouteReplaced {
                cidr,
                interface,
                metric,
            } => ip_argv_route_replace(cidr, interface, *metric),
            AppliedStep::FwmarkRule { mark, table } => vec![
                "ip".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                mark.to_string(),
                "table".into(),
                table.to_string(),
            ],
            AppliedStep::EscapeRoute { table, via_dev } => vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                "default".into(),
                via_dev.clone(),
                "table".into(),
                table.to_string(),
            ],
        }
    }

    /// 逆序撤销 argv（clear/apply 中途回滚共用——del/down）
    pub fn undo_argv(&self) -> Vec<String> {
        match self {
            AppliedStep::AddrReplaced { interface, cidr } => ip_argv_addr_del(cidr, interface),
            AppliedStep::LinkUp { interface } => ip_argv_link_down_name(interface),
            AppliedStep::RouteReplaced {
                cidr, interface, ..
            } => ip_argv_route_del(cidr, interface),
            AppliedStep::FwmarkRule { mark, table } => vec![
                "ip".into(),
                "rule".into(),
                "del".into(),
                "fwmark".into(),
                mark.to_string(),
                "table".into(),
                table.to_string(),
            ],
            AppliedStep::EscapeRoute { table, .. } => vec![
                "ip".into(),
                "route".into(),
                "del".into(),
                "default".into(),
                "table".into(),
                table.to_string(),
            ],
        }
    }

    /// EEXIST 是否视为成功（仅 `ip rule add`——iproute2 无 rule replace，
    /// 重复 add 报 File exists 即规则已生效，幂等语义；其余步骤 false）
    pub fn eexist_ok(&self) -> bool {
        matches!(self, AppliedStep::FwmarkRule { .. })
    }
}

impl fmt::Display for AppliedStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppliedStep::AddrReplaced { interface, cidr } => {
                write!(f, "AddrReplaced({cidr} dev {interface})")
            }
            AppliedStep::LinkUp { interface } => write!(f, "LinkUp({interface})"),
            AppliedStep::RouteReplaced {
                cidr,
                interface,
                metric,
            } => write!(f, "RouteReplaced({cidr} dev {interface} metric {metric})"),
            AppliedStep::FwmarkRule { mark, table } => {
                write!(f, "FwmarkRule(fwmark {mark:#x} table {table})")
            }
            AppliedStep::EscapeRoute { table, via_dev } => {
                write!(f, "EscapeRoute(default {via_dev} table {table})")
            }
        }
    }
}

/// E10 口径（network-route.md §6）：TunIngress 未运行/已退（接口未创建）
pub const E10_TUN_DISABLED: &str = "TUN 未启用（检查 network 配置与日志）";

/// apply 产物（network-route.md §2.3）：dry_run=true 时 executed/rolled_back 空
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub planned: Vec<AppliedStep>,
    pub executed: Vec<AppliedStep>,
    pub rolled_back: Vec<AppliedStep>,
}

/// apply 的类型化失败（§6 E7）——控制面错误响应要同时携带 error 文本与
/// 已逆序回滚的本批步骤（anyhow 装不下结构化负载，端点消费此形）
#[derive(Debug)]
pub struct ApplyFailure {
    pub error: anyhow::Error,
    pub rolled_back: Vec<AppliedStep>,
}

/// 已入账步骤（步骤 + 记录时刻——status 响应的 at 字段来源）
#[derive(Debug, Clone)]
pub struct AppliedRecord {
    pub step: AppliedStep,
    pub at: SystemTime,
}

/// 路由面状态快照（§2.3，同步读不持写锁）
#[derive(Debug, Clone)]
pub struct RouteStatus {
    pub device: Option<String>,
    pub mtu: Option<u16>,
    pub up: bool,
    pub applied: Vec<AppliedRecord>,
}

/// 计算 auto-bypass 集（§2.7）：
/// - egress server/endpoint 解析地址
/// - mesh listen_address 与已注册 peer 地址
/// - control.api_bind
/// - tun 自身网段（TunConfig.ipv4_addr/ipv6_addr + prefix）
///
/// 这些前缀**不写入** include 路由，且进进程内兜底名单。
fn compute_auto_bypass(
    _routing_config: &RoutingConfig,
    tun_config: Option<&TunConfig>,
) -> Vec<RouteDestination> {
    let mut bypass = Vec::new();

    // 注：private/loopback/multicast 默认 bypass 不在本集——它们由包循环②
    // 的 BypassRule::matches（default_bypass_rules）承担，本集只收 §2.7
    // 「不写入 include 路由」的显式前缀（tun 网段 + 运行时注入 extra）。

    // tun 自身网段（若配置了地址）
    if let Some(tun) = tun_config {
        if let Some(v4) = tun.ipv4_addr {
            if let Some(netmask) = tun.ipv4_netmask {
                let prefix = u32::from(netmask).leading_ones() as u8;
                bypass.push(RouteDestination::Ipv4Network {
                    network: v4,
                    prefix,
                });
            }
        }
        if let Some(v6) = tun.ipv6_addr {
            if let Some(prefix) = tun.ipv6_prefix_len {
                bypass.push(RouteDestination::Ipv6Network {
                    network: v6,
                    prefix,
                });
            }
        }
    }

    // TODO: egress/mesh/control 地址解析（运行时注入，此处为静态配置占位）
    // RoutingConfig 本身不含这些字段，实际 auto-bypass 由 TunIngress 运行时组装后再过滤

    bypass
}

/// 取目标的「头地址」（Host 即自身、网络即其 network 字段）；Default 无头
fn destination_head(d: &RouteDestination) -> Option<IpAddr> {
    match d {
        RouteDestination::Ipv4Network { network, .. } => Some(IpAddr::V4(*network)),
        RouteDestination::Ipv6Network { network, .. } => Some(IpAddr::V6(*network)),
        RouteDestination::Host { address } => Some(*address),
        RouteDestination::Default => None,
    }
}

/// 两个路由目标是否重叠（§2.7：include 规则与 auto-bypass 集的排除判定）。
/// - CIDR 两两关系必为「嵌套或不交」→ 查一方头地址落在对方掩码内即精确；
/// - Host 与网络查包含（双向经同一臂折叠）；
/// - Default 与一切重叠（`0.0.0.0/0` 类纳入在有 auto-bypass 在场时恒跳过）。
fn overlaps(a: &RouteDestination, b: &RouteDestination) -> bool {
    use RouteDestination::*;
    match (a, b) {
        (Default, _) | (_, Default) => true,
        (Host { address }, Host { address: b_addr }) => address == b_addr,
        (Host { address }, net) | (net, Host { address }) => net.matches(*address),
        (Ipv4Network { .. }, Ipv6Network { .. }) | (Ipv6Network { .. }, Ipv4Network { .. }) => {
            false
        }
        (net_a, net_b) => match (destination_head(net_a), destination_head(net_b)) {
            (Some(ha), Some(hb)) => net_a.matches(hb) || net_b.matches(ha),
            _ => false,
        },
    }
}

/// Linux 系统路由管理器（tun-dataplane.md §1.3）
///
/// MVP = main 表显式路由 include 语义（不改默认路由、不用 ip rule、
/// 无需 fwmark）；`ip` 命令子进程执行（netlink 归 V2）。
#[derive(Debug)]
pub struct LinuxRouteManager {
    config: RoutingConfig,
    /// T2 起由 apply/clear 读写（记录已执行步骤供逆序撤销——含记录时刻，
    /// status 的 at 字段；§5 去重：同 argv 已在册不重复入账）
    applied: Mutex<Vec<AppliedRecord>>,
    /// tun 配置（用于 auto-bypass 计算 tun 自身网段）
    tun_config: Option<TunConfig>,
    /// 实际接口名（create_interface 后由 TUNGETIFF 读回，供路由操作使用）
    interface_name: Option<String>,
    /// 设备 up 态（TunIngress up_interface 成功后置位 / teardown 清零；
    /// 设备生命周期属主仍是 TunIngress，此处仅承接 status 的 up 字段）
    device_up: AtomicBool,
    /// §2.7 extra auto-bypass（构建期注入：egress 字面量地址 + api_bind +
    /// mesh listen；run() 起始处再并入域名解析结果）——与 tun 网段合并后
    /// 即完整 auto-bypass 集
    extra_auto_bypass: Vec<RouteDestination>,
    /// escape 表默认路由模板（networking.md §2 半边②）：probe 读 main 表
    /// 首条默认路由填入（`ip route show default table main` 的 `default `
    /// 后部分）；None = 未探测/无默认路由（跳过 escape 面）。仅 None 时
    /// probe 执行——显式注入值（builder/测试）不被覆盖
    escape_default_route: Mutex<Option<String>>,
    /// §7.1 mock executor：在场时 exec/undo 不跑真 ip，只记录调用序列，
    /// 可注入第 k 步非零退出（E7 语义单测；仅测试构建存在）
    #[cfg(test)]
    mock_exec: Option<Arc<Mutex<Vec<Vec<String>>>>>,
    #[cfg(test)]
    mock_fail_at: Option<usize>,
    /// §7.1 mock：在第 k 步返回带 "File exists" 的失败（EEXIST 容忍语义
    /// 单测；None = 不注入）
    #[cfg(test)]
    mock_eexist_at: Option<usize>,
    /// §7.1 测试钩子：跳过 probe（直接控制 escape_default_route 字段，
    /// 避免真环境默认路由干扰「无默认路由」测试）
    #[cfg(test)]
    skip_probe: bool,
}

impl LinuxRouteManager {
    /// 创建路由管理器（不触碰系统路由；首次变更在 `apply_routing`）
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config,
            applied: Mutex::new(Vec::new()),
            tun_config: None,
            interface_name: None,
            device_up: AtomicBool::new(false),
            extra_auto_bypass: Vec::new(),
            escape_default_route: Mutex::new(None),
            #[cfg(test)]
            mock_exec: None,
            #[cfg(test)]
            mock_fail_at: None,
            #[cfg(test)]
            mock_eexist_at: None,
            #[cfg(test)]
            skip_probe: false,
        }
    }

    /// 注入 escape 表默认路由模板（builder 形；测试与潜在调用方用——
    /// 显式值不被 [`Self::probe_escape_default_route`] 覆盖）
    pub fn with_escape_default_route(self, via_dev: Option<String>) -> Self {
        *self.escape_default_route.lock().unwrap() = via_dev;
        self
    }

    /// 设置 tun 配置（用于 auto-bypass 计算 tun 自身网段）
    pub fn with_tun_config(mut self, tun_config: TunConfig) -> Self {
        self.tun_config = Some(tun_config);
        self
    }

    /// 注入 §2.7 auto-bypass 追加集（builder 形）
    pub fn with_auto_bypass(mut self, v: Vec<RouteDestination>) -> Self {
        self.extra_auto_bypass = v;
        self
    }

    /// 覆写 §2.7 auto-bypass 追加集（run() 起始处并入域名解析结果时用）
    pub fn set_auto_bypass(&mut self, v: Vec<RouteDestination>) {
        self.extra_auto_bypass = v;
    }

    /// 完整 auto-bypass 集 = compute_auto_bypass（tun 网段）∪ extra 注入集
    pub fn merged_auto_bypass(&self) -> Vec<RouteDestination> {
        let mut all = compute_auto_bypass(&self.config, self.tun_config.as_ref());
        all.extend(self.extra_auto_bypass.iter().cloned());
        all
    }

    /// §2.7 进程内兜底：目标 IP 是否落在 auto-bypass 集（含 tun 网段与
    /// 运行时注入集；包循环②处命中即丢 + 计数）
    pub fn is_auto_bypass_ip(&self, ip: IpAddr) -> bool {
        self.merged_auto_bypass().iter().any(|d| d.matches(ip))
    }

    /// 设置实际接口名（create_interface 后调用，TUNGETIFF 读回的名字）
    pub fn set_interface_name(&mut self, name: String) {
        self.interface_name = Some(name);
    }

    /// 清零接口名（TunIngress teardown 调用——设备已销毁，后续 apply 得到
    /// E10 明确错误而非裸 ip 报错）
    pub fn clear_interface_name(&mut self) {
        self.interface_name = None;
    }

    /// 设备 up 态回填（status 的 up 字段；见结构体注释）
    pub fn set_device_up(&self, up: bool) {
        self.device_up.store(up, Ordering::Relaxed);
    }

    fn get_interface_name(&self) -> Result<String> {
        self.interface_name
            .clone()
            .ok_or_else(|| anyhow!("接口名未设置——先调用 set_interface_name 或 create_interface"))
    }

    /// planner（§2.3 dry-run 面）：构造期望步骤序列——addr 步骤（tun_config
    /// 在场）+ include 规则步骤（enabled、auto-bypass 重叠剔除）。
    /// 与执行同源（apply_desired 逐条跑 planned 的 argv）——不存在第二决策
    /// 路径；接口未创建 → E10。
    fn plan_steps(&self) -> Result<Vec<AppliedStep>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }
        let interface = self
            .get_interface_name()
            .map_err(|_| anyhow!(E10_TUN_DISABLED))?;
        let auto_bypass = self.merged_auto_bypass();
        let mut planned = Vec::new();

        // 0. escape 步骤（networking.md §2 半边②：rillane 自身出站 SO_MARK
        //    逃逸 include 自环）——fwmark ≠ 0 且 main 表默认路由在场时，
        //    先建 `ip rule fwmark` 逃逸规则 + escape 表默认路由（带 mark
        //    的包查 escape 表走真实默认网关，跳过 main 表 include 路由）
        if let Some(via_dev) = &*self.escape_default_route.lock().unwrap() {
            let mark = rillane_core::net_mark::egress_fwmark();
            if mark != 0 {
                planned.push(AppliedStep::FwmarkRule {
                    mark,
                    table: ESCAPE_TABLE,
                });
                planned.push(AppliedStep::EscapeRoute {
                    table: ESCAPE_TABLE,
                    via_dev: via_dev.clone(),
                });
            }
        }

        // 1. 地址步骤（configure_ip 已在 LinuxTunProvider 做；此处重复
        //    replace 幂等无害，且使 clear 能一并还原地址）
        if let Some(tun) = &self.tun_config {
            if let Some(v4) = tun.ipv4_addr {
                let prefix = tun
                    .ipv4_netmask
                    .map(|nm| u32::from(nm).leading_ones() as u8)
                    .unwrap_or(32);
                planned.push(AppliedStep::AddrReplaced {
                    interface: interface.clone(),
                    cidr: format!("{v4}/{prefix}"),
                });
            }
            if let Some(v6) = tun.ipv6_addr {
                let prefix = tun.ipv6_prefix_len.unwrap_or(128);
                planned.push(AppliedStep::AddrReplaced {
                    interface: interface.clone(),
                    cidr: format!("{v6}/{prefix}"),
                });
            }
        }

        // 2. 路由步骤（按 priority 升序：数字越小优先级越高）
        let mut rules = self.config.rules.clone();
        rules.sort_by_key(|r| r.priority);
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            if auto_bypass.iter().any(|b| overlaps(&rule.destination, b)) {
                debug!(target: "rillane::route", name = %rule.name, dest = %rule.destination.as_string(), "跳过与 auto-bypass 重叠的 include 目标");
                continue;
            }
            let interface = rule.interface.clone().unwrap_or_else(|| interface.clone());
            if interface.is_empty() {
                return Err(anyhow!("路由规则 {} 缺少接口（tun 未配置）", rule.name));
            }
            planned.push(AppliedStep::RouteReplaced {
                cidr: rule.destination.as_string(),
                interface,
                metric: rule.metric.unwrap_or(0),
            });
        }
        Ok(planned)
    }

    /// 执行单步（§7.1 mock executor 挂点：测试在场时记录调用序列并
    /// 可在第 fail_at 步注入非零退出、eexist_at 步注入 File exists——
    /// E7/EEXIST 语义无特权可测）
    async fn exec_step(&self, _idx: usize, step: &AppliedStep) -> Result<()> {
        #[cfg(test)]
        {
            if let Some(log) = &self.mock_exec {
                log.lock().unwrap().push(step.argv());
                if self.mock_fail_at == Some(_idx) {
                    return Err(anyhow!("mock ip 非零退出（注入 E7）"));
                }
                if self.mock_eexist_at == Some(_idx) {
                    // 模拟真实执行器的 EEXIST 容忍：FwmarkRule 容忍，其余步骤不容忍
                    if step.eexist_ok() {
                        return Ok(());
                    } else {
                        return Err(anyhow!(
                            "mock ip 非零退出（注入 EEXIST）：RTNETLINK answers: File exists"
                        ));
                    }
                }
                return Ok(());
            }
        }
        let argv = step.argv();
        run_ip(&argv).await.or_else(|e| {
            // ip rule add 幂等：规则已存在（File exists）视为生效——iproute2
            // 无 rule replace，重复 apply 不能因 EEXIST 触发 E7 回滚
            if step.eexist_ok() && e.to_string().contains("File exists") {
                Ok(())
            } else {
                Err(e)
            }
        })
    }

    /// 撤销单步 argv（mock 在场时只记录、恒成功——撤销阶段尽力而为的镜像）
    async fn undo_step(&self, argv: &[String]) -> Result<()> {
        #[cfg(test)]
        {
            if let Some(log) = &self.mock_exec {
                log.lock().unwrap().push(argv.to_vec());
                return Ok(());
            }
        }
        run_ip(argv).await
    }

    /// 探测 main 表首条默认路由作 escape 表路由模板（networking.md §2
    /// 半边②）——`ip route show default table main` 输出 `default ` 后部分
    /// （如 `via 192.168.1.1 dev eth0 proto dhcp`）；无默认路由/探测失败
    /// → None（跳过 escape 面，不因逃逸功能自爆启动）。仅字段为 None 时
    /// 执行——显式注入值（builder/测试）不被覆盖
    async fn probe_escape_default_route(&self) {
        #[cfg(test)]
        if self.skip_probe {
            return;
        }
        if self.escape_default_route.lock().unwrap().is_some() {
            return;
        }
        let out = match Command::new("ip")
            .args(["route", "show", "default", "table", "main"])
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "探测 main 表默认路由失败，跳过 fwmark 逃逸面");
                return;
            }
        };
        if !out.status.success() {
            tracing::warn!(
                status = %out.status,
                "ip route show 非零退出，跳过 fwmark 逃逸面"
            );
            return;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        match parse_escape_route_template(&text) {
            Some(v) => {
                *self.escape_default_route.lock().unwrap() = Some(v.to_string());
            }
            None => {
                // main 表无默认路由 → escape 表无出口，跳过逃逸面
                debug!(target: "rillane::route", "main 表无默认路由，跳过 fwmark 逃逸面");
            }
        }
    }

    /// 幂等重放期望路由集（network-route.md §2.3/§5）——CLI apply 与启动
    /// apply 的同一入口。dry_run=true 只跑 planner 不执行不入账；执行失败
    /// 逆序撤销本批已执行步骤（E7，在册步骤不动），Err 携 rolled_back；
    /// 成功后去重入账（同 argv 已在册不重复入账，status 稳定）。
    pub async fn apply_desired(
        &self,
        dry_run: bool,
    ) -> std::result::Result<ApplyOutcome, ApplyFailure> {
        // escape 面探测（dry_run 也要——计划需含 escape 步骤；仅 None 时跑）
        self.probe_escape_default_route().await;
        let planned = match self.plan_steps() {
            Ok(p) => p,
            Err(e) => {
                return Err(ApplyFailure {
                    error: e,
                    rolled_back: Vec::new(),
                })
            }
        };
        if dry_run {
            return Ok(ApplyOutcome {
                planned,
                executed: Vec::new(),
                rolled_back: Vec::new(),
            });
        }
        let mut executed: Vec<AppliedStep> = Vec::new();
        for (idx, step) in planned.iter().enumerate() {
            if let Err(e) = self.exec_step(idx, step).await {
                let mut rolled_back = Vec::new();
                for s in executed.iter().rev() {
                    let _ = self.undo_step(&s.undo_argv()).await; // 撤销尽力而为
                    rolled_back.push(s.clone());
                }
                return Err(ApplyFailure {
                    error: e.context(format!(
                        "apply 第 {} 步失败（E7），已逆序回滚 {} 步",
                        idx + 1,
                        rolled_back.len()
                    )),
                    rolled_back,
                });
            }
            executed.push(step.clone());
        }
        {
            let mut applied = self.applied.lock().unwrap();
            for s in &executed {
                if !applied.iter().any(|r| r.step == *s) {
                    applied.push(AppliedRecord {
                        step: s.clone(),
                        at: SystemTime::now(),
                    });
                }
            }
        }
        Ok(ApplyOutcome {
            planned,
            executed,
            rolled_back: Vec::new(),
        })
    }

    /// 逆序撤销全部在册步骤并清空账本（§2.3；§5「完全还原」= 还原 rillane
    /// 所加步骤，非清空系统路由表）；无步骤时 Ok 空表（E8 幂等）
    pub async fn clear(&self) -> Result<Vec<AppliedStep>> {
        let records = {
            let mut applied = self.applied.lock().unwrap();
            applied.drain(..).rev().collect::<Vec<_>>()
        };
        let mut undone = Vec::new();
        for r in records {
            let _ = self.undo_step(&r.step.undo_argv()).await; // 尽力而为
            undone.push(r.step);
        }
        Ok(undone)
    }

    /// 状态快照（§2.3 同步读）：设备态 + 已应用步骤表
    pub fn status(&self) -> RouteStatus {
        RouteStatus {
            device: self.interface_name.clone(),
            mtu: self.tun_config.as_ref().map(|t| t.mtu),
            up: self.device_up.load(Ordering::Relaxed),
            applied: self.applied.lock().unwrap().clone(),
        }
    }

    /// §7.1 mock executor 开启（返回调用记录句柄；fail_at = 注入非零退出
    /// 的正向步骤下标，eexist_at = 注入 File exists 失败，None = 恒成功）
    #[cfg(test)]
    pub(crate) fn enable_mock_exec(
        &mut self,
        fail_at: Option<usize>,
    ) -> Arc<Mutex<Vec<Vec<String>>>> {
        self.enable_mock_exec_with_eexist(fail_at, None)
    }

    /// §7.1 mock executor 全开（fail_at + eexist_at 双注入点）
    #[cfg(test)]
    pub(crate) fn enable_mock_exec_with_eexist(
        &mut self,
        fail_at: Option<usize>,
        eexist_at: Option<usize>,
    ) -> Arc<Mutex<Vec<Vec<String>>>> {
        let log = Arc::new(Mutex::new(Vec::new()));
        self.mock_exec = Some(Arc::clone(&log));
        self.mock_fail_at = fail_at;
        self.mock_eexist_at = eexist_at;
        log
    }

    /// 应用单条路由（add_route 动态面用；apply_desired 走批量路径不经此）
    async fn apply_step(&self, step: AppliedStep) -> Result<()> {
        match &step {
            AppliedStep::AddrReplaced { interface, cidr } => {
                run_ip(&ip_argv_addr_replace(cidr, interface)).await?;
            }
            AppliedStep::LinkUp { interface: _ } => {
                // LinkUp 已在 up_interface 处理，此处仅记录
            }
            AppliedStep::RouteReplaced {
                cidr,
                interface,
                metric,
            } => {
                run_ip(&ip_argv_route_replace(cidr, interface, *metric)).await?;
            }
            // escape 步骤（动态面不经此——escape 只走 apply 批量面；
            // match 穷尽需要，语义与 argv 执行一致）
            AppliedStep::FwmarkRule { .. } | AppliedStep::EscapeRoute { .. } => {
                run_ip(&step.argv()).await?;
            }
        }
        self.applied.lock().unwrap().push(AppliedRecord {
            step,
            at: SystemTime::now(),
        });
        Ok(())
    }
}

#[async_trait]
impl RouteManager for LinuxRouteManager {
    fn config(&self) -> &RoutingConfig {
        &self.config
    }

    fn stats(&self) -> RouteStats {
        let applied = self.applied.lock().unwrap();
        RouteStats {
            active_routes: applied
                .iter()
                .filter(|r| matches!(r.step, AppliedStep::RouteReplaced { .. }))
                .count(),
            total_routes: applied.len(),
            ..Default::default()
        }
    }

    /// §5「启动 apply ≡ CLI apply」：trait 面向 enable_route 等既有消费者，
    /// 内部即 apply_desired(false) 单一写路径（planner/执行/去重入账同源）
    async fn apply_routing(&self) -> Result<()> {
        self.apply_desired(false)
            .await
            .map(|_| ())
            .map_err(|f| f.error)
    }

    async fn clear_routing(&self) -> Result<()> {
        self.clear().await.map(|_| ())
    }

    async fn add_route(&self, rule: RouteRule) -> Result<()> {
        let auto_bypass = self.merged_auto_bypass();
        if auto_bypass.iter().any(|b| overlaps(&rule.destination, b)) {
            return Err(anyhow!(
                "目标 {} 与 auto-bypass 集重叠，不写入路由",
                rule.destination.as_string()
            ));
        }
        let interface = rule
            .interface
            .unwrap_or_else(|| self.get_interface_name().unwrap_or_default());
        if interface.is_empty() {
            return Err(anyhow!("路由规则 {} 缺少接口", rule.name));
        }
        let metric = rule.metric.unwrap_or(0);
        let cidr = rule.destination.as_string();
        let step = AppliedStep::RouteReplaced {
            cidr: cidr.clone(),
            interface: interface.clone(),
            metric,
        };
        self.apply_step(step).await?;
        Ok(())
    }

    async fn remove_route(&self, name: &str) -> Result<()> {
        // 先找到并取出步骤，释放锁再 await
        let step = {
            let mut applied = self.applied.lock().unwrap();
            if let Some(idx) = applied.iter().position(|r| {
                matches!(r.step, AppliedStep::RouteReplaced { .. })
                    && r.step.to_string().contains(name)
            }) {
                applied.remove(idx).step
            } else {
                return Err(anyhow!("未找到路由规则: {name}"));
            }
        };
        if let AppliedStep::RouteReplaced {
            cidr,
            interface,
            metric: _,
        } = step
        {
            run_ip(&ip_argv_route_del(&cidr, &interface)).await?;
        }
        Ok(())
    }

    async fn modify_route(&self, rule: RouteRule) -> Result<()> {
        // 简化：先删后加（幂等 replace 也可直接 apply）
        let _ = self.remove_route(&rule.name).await;
        self.add_route(rule).await
    }

    async fn get_routing_table(&self) -> Result<Vec<RouteRule>> {
        // 从 applied 重建 RouteRule（简化版本，仅含已应用的路由）
        let applied = self.applied.lock().unwrap();
        Ok(applied
            .iter()
            .filter_map(|r| {
                if let AppliedStep::RouteReplaced {
                    cidr,
                    interface,
                    metric,
                } = &r.step
                {
                    let dest = parse_cidr(cidr).ok()?;
                    Some(
                        RouteRule::new(format!("route-{cidr}"), dest)
                            .with_interface(interface.clone())
                            .with_metric(*metric),
                    )
                } else {
                    None
                }
            })
            .collect())
    }

    async fn lookup_route(&self, destination: IpAddr) -> Result<Option<RouteRule>> {
        let applied = self.applied.lock().unwrap();
        for r in applied.iter() {
            if let AppliedStep::RouteReplaced {
                cidr,
                interface,
                metric,
            } = &r.step
            {
                if let Ok(dest) = parse_cidr(cidr) {
                    if dest.matches(destination) {
                        return Ok(Some(
                            RouteRule::new(format!("route-{cidr}"), dest)
                                .with_interface(interface.clone())
                                .with_metric(*metric),
                        ));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn enable_route(&self, name: &str, enabled: bool) -> Result<()> {
        if enabled {
            // 重新应用（幂等）
            self.apply_routing().await
        } else {
            self.remove_route(name).await
        }
    }

    async fn flush_cache(&self) -> Result<()> {
        // MVP 无路由缓存可刷
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

    /// 全局测试锁：`apply_desired` 的 planner 读全局 `net_mark` 单例
    /// （escape 步骤生成依赖 mark 值）——并行测试会互踩，持锁串行化。
    /// async-aware（tokio Mutex）：guard 跨 await 持有合法
    static ROUTE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    // ---------- 单测（§4.1：无特权，任何环境） ----------

    #[test]
    fn iff_request_build_and_readback() {
        let req = build_iff_request("rillane0").unwrap();
        assert_eq!(ifreq_name(&req), "rillane0");
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

    /// §2.7 overlaps 判定：Host 等值/网络包含双向、CIDR 嵌套或不交、
    /// 版本错配不交、Default 与一切重叠（`0.0.0.0/0` 类纳入恒跳过）
    #[test]
    fn auto_bypass_overlap_semantics() {
        let host = |s: &str| RouteDestination::host(s.parse().unwrap());
        let v4net = |s: &str| {
            let (a, p) = s.split_once('/').unwrap();
            RouteDestination::ipv4(a.parse().unwrap(), p.parse().unwrap()).unwrap()
        };
        let v6net = |s: &str| {
            let (a, p) = s.split_once('/').unwrap();
            RouteDestination::ipv6(a.parse().unwrap(), p.parse().unwrap()).unwrap()
        };

        // Host vs Host：等值重叠、异值不交
        assert!(overlaps(&host("1.1.1.1"), &host("1.1.1.1")));
        assert!(!overlaps(&host("1.1.1.1"), &host("1.1.1.2")));

        // Host vs 网络：双向包含（包入网段即重叠）
        assert!(overlaps(&host("10.1.2.3"), &v4net("10.0.0.0/8")));
        assert!(overlaps(&v4net("10.0.0.0/8"), &host("10.1.2.3")));
        assert!(!overlaps(&host("192.0.2.1"), &v4net("10.0.0.0/8")));

        // CIDR：嵌套双向（include 更宽 / auto 更宽）皆重叠——egress 宿主
        // 落在更宽 include 内必须整条跳过（防环，§2.7）
        assert!(overlaps(&v4net("10.0.0.0/8"), &v4net("10.1.2.3/32")));
        assert!(overlaps(&v4net("10.1.2.3/32"), &v4net("10.0.0.0/8")));
        assert!(overlaps(&v4net("10.0.0.0/8"), &v4net("10.0.0.0/8")));
        // 不交 → false
        assert!(!overlaps(&v4net("10.0.0.0/8"), &v4net("192.168.0.0/16")));
        assert!(!overlaps(&v4net("10.1.0.0/16"), &v4net("10.2.0.0/16")));

        // 版本错配（v4 vs v6 网络）恒不交
        assert!(!overlaps(&v4net("0.0.0.0/0"), &v6net("2001:db8::/32")));
        assert!(overlaps(&v6net("2001:db8::/32"), &v6net("2001:db8:1::/48")));

        // Default 与一切重叠（双序）
        assert!(overlaps(&RouteDestination::Default, &host("1.1.1.1")));
        assert!(overlaps(&host("1.1.1.1"), &RouteDestination::Default));
        assert!(overlaps(&RouteDestination::Default, &v4net("10.0.0.0/8")));
    }

    /// §2.7 auto-bypass 集组装（§4.1）：tun 网段 ∪ extra 注入集
    /// （egress 字面量 + api_bind + mesh listen 来源的运行时注入形）+
    /// `is_auto_bypass_ip` 进程内兜底判定两态
    #[test]
    fn merged_auto_bypass_and_ip_check() {
        let routing = RoutingConfig {
            enabled: true,
            ..RoutingConfig::default()
        };
        let tun = TunConfig {
            ipv4_addr: Some(Ipv4Addr::new(10, 255, 0, 1)),
            ipv4_netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            ..TunConfig::default()
        };
        // extra = egress 服务端字面量 + control.api_bind（构建期注入形）
        let extra = vec![
            RouteDestination::host("203.0.113.9".parse().unwrap()),
            RouteDestination::host("127.0.0.1".parse().unwrap()),
        ];
        let mgr = LinuxRouteManager::new(routing)
            .with_tun_config(tun)
            .with_auto_bypass(extra);

        let merged = mgr.merged_auto_bypass();
        assert_eq!(merged.len(), 3, "tun 网段 + 2 个注入宿主");
        assert!(
            merged
                .iter()
                .any(|d| matches!(d, RouteDestination::Ipv4Network { prefix: 24, .. })),
            "tun 自身网段应入集"
        );

        // 进程内兜底判定：三者命中、集外不命中
        assert!(mgr.is_auto_bypass_ip("203.0.113.9".parse().unwrap()));
        assert!(mgr.is_auto_bypass_ip("127.0.0.1".parse().unwrap()));
        assert!(
            mgr.is_auto_bypass_ip("10.255.0.77".parse().unwrap()),
            "tun 网段内命中"
        );
        assert!(
            !mgr.is_auto_bypass_ip("198.51.100.1".parse().unwrap()),
            "集外不命中"
        );

        // set_auto_bypass 覆写形（run() 起始处并入域名解析结果的入口）
        let mut mgr2 = LinuxRouteManager::new(RoutingConfig::default());
        assert!(!mgr2.is_auto_bypass_ip("198.51.100.1".parse().unwrap()));
        mgr2.set_auto_bypass(vec![RouteDestination::host(
            "198.51.100.1".parse().unwrap(),
        )]);
        assert!(mgr2.is_auto_bypass_ip("198.51.100.1".parse().unwrap()));
    }

    // ---------- RouteControl 契约（network-route.md §2.3/§5/§7.1） ----------

    /// 契约测试基座：1 条 tun 地址 + 2 条 include（一条正常 TEST-NET-2、
    /// 一条落 tun 网段内应被 §2.7 剔除）
    fn route_control_routing() -> RoutingConfig {
        let mut routing = RoutingConfig {
            enabled: true,
            ..RoutingConfig::default()
        };
        routing.rules.push(
            RouteRule::new(
                "include[0]".into(),
                RouteDestination::ipv4(Ipv4Addr::new(198, 51, 100, 0), 24).unwrap(),
            )
            .with_metric(7),
        );
        routing.rules.push(RouteRule::new(
            "include[1]".into(),
            RouteDestination::ipv4(Ipv4Addr::new(10, 90, 0, 55), 32).unwrap(),
        ));
        routing
    }

    fn route_control_tun() -> TunConfig {
        TunConfig {
            ipv4_addr: Some(Ipv4Addr::new(10, 90, 0, 1)),
            ipv4_netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            mtu: 1400,
            ..TunConfig::default()
        }
    }

    /// dry-run（§2.3/§7.1）：planner 产出 addr+include 步骤（auto-bypass
    /// 重叠项剔除）、不执行不入账；status 快照字段齐备
    #[tokio::test]
    async fn apply_desired_dry_run_plans_without_exec_or_record() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        let mut mgr =
            LinuxRouteManager::new(route_control_routing()).with_tun_config(route_control_tun());
        mgr.set_interface_name("rillaneR2dry".into());

        let out = mgr.apply_desired(true).await.expect("dry-run 应成功");
        assert_eq!(
            out.planned.len(),
            2,
            "addr + 1 条不重叠 include（tun 网段内目标剔除）：{:?}",
            out.planned
        );
        assert_eq!(
            out.planned[0].argv(),
            [
                "ip",
                "addr",
                "replace",
                "10.90.0.1/24",
                "dev",
                "rillaneR2dry"
            ]
        );
        assert_eq!(
            out.planned[1].argv(),
            [
                "ip",
                "route",
                "replace",
                "198.51.100.0/24",
                "dev",
                "rillaneR2dry",
                "metric",
                "7"
            ]
        );
        assert!(out.executed.is_empty() && out.rolled_back.is_empty());

        let st = mgr.status();
        assert!(st.applied.is_empty(), "dry-run 不入账");
        assert_eq!(st.device.as_deref(), Some("rillaneR2dry"));
        assert_eq!(st.mtu, Some(1400));
        assert!(!st.up, "设备 up 态未置位");
    }

    /// E10（§6）：接口未创建（TunIngress 未运行/已退）→ Err 携明确口径
    #[tokio::test]
    async fn apply_desired_without_interface_errors_e10() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        let mgr = LinuxRouteManager::new(RoutingConfig {
            enabled: true,
            ..RoutingConfig::default()
        });
        let f = mgr
            .apply_desired(false)
            .await
            .expect_err("接口未创建应 E10");
        assert!(
            f.error.to_string().contains(E10_TUN_DISABLED),
            "E10 口径：{}",
            f.error
        );
        assert!(f.rolled_back.is_empty());
    }

    /// E7（§5/§7.1 mock executor）：注入第 2 步非零退出 → 前 1 步收到逆序
    /// undo argv、账本清空（失败批不入账）
    #[tokio::test]
    async fn apply_desired_e7_rolls_back_batch_in_reverse() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        let mut mgr =
            LinuxRouteManager::new(route_control_routing()).with_tun_config(route_control_tun());
        mgr.set_interface_name("rillaneR2e7".into());
        let log = mgr.enable_mock_exec(Some(1));

        let f = mgr.apply_desired(false).await.expect_err("注入失败应 E7");
        assert!(
            format!("{:#}", f.error).contains("mock ip 非零退出"),
            "错误链应含注入根因：{:#}",
            f.error
        );
        assert_eq!(f.rolled_back.len(), 1, "前 1 步（addr）应回滚");
        assert_eq!(
            f.rolled_back[0].undo_argv(),
            ["ip", "addr", "del", "10.90.0.1/24", "dev", "rillaneR2e7"]
        );
        // 调用序列：正向 addr、正向 route#0（失败）、逆序 undo addr
        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 3, "mock 调用序列：{calls:?}");
        assert_eq!(
            calls[2],
            ["ip", "addr", "del", "10.90.0.1/24", "dev", "rillaneR2e7"]
        );
        assert!(
            mgr.status().applied.is_empty(),
            "失败批不入账（E7 后账本干净）"
        );
    }

    /// §5 幂等：重复 apply 去重入账（status 稳定）；clear 逆序全量撤销 +
    /// E8 空表幂等
    #[tokio::test]
    async fn apply_desired_idempotent_record_and_clear_e8() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        let mut mgr =
            LinuxRouteManager::new(route_control_routing()).with_tun_config(route_control_tun());
        mgr.set_interface_name("rillaneR2idem".into());
        let _log = mgr.enable_mock_exec(None);

        mgr.apply_desired(false).await.expect("首次应成功");
        mgr.apply_desired(false)
            .await
            .expect("重放应成功（replace 幂等）");
        let st = mgr.status();
        assert_eq!(
            st.applied.len(),
            2,
            "重放后账本去重稳定（同 argv 不重复入账）：{:?}",
            st.applied
        );

        let undone = mgr.clear().await.expect("clear 应成功");
        assert_eq!(undone.len(), 2, "逆序全量撤销");
        assert_eq!(
            undone[0].undo_argv(),
            [
                "ip",
                "route",
                "del",
                "198.51.100.0/24",
                "dev",
                "rillaneR2idem"
            ]
        );
        assert!(mgr.status().applied.is_empty(), "clear 后账本清空");
        assert!(
            mgr.clear().await.unwrap().is_empty(),
            "无步骤时 Ok 空表（E8 幂等）"
        );
    }

    /// 真 exec 面 E7（无特权可跑）：接口名不存在 → 首 ip 命令非零退出，
    /// 失败不入账（回滚面 mocked 路径已覆盖，此处在真 run_ip 上钉同一账目语义）
    #[tokio::test]
    async fn apply_desired_real_exec_failure_keeps_ledger_clean() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        let mut mgr =
            LinuxRouteManager::new(route_control_routing()).with_tun_config(route_control_tun());
        mgr.set_interface_name(format!("rillaneN{:x}", std::process::id()));

        let f = mgr
            .apply_desired(false)
            .await
            .expect_err("不存在的设备必失败");
        assert!(f.rolled_back.is_empty(), "首步即败无回滚步骤");
        assert!(mgr.status().applied.is_empty(), "失败不入账");
    }

    // ---------- fwmark 逃逸面（networking.md §2 半边②） ----------

    /// escape 步骤 argv/undo_argv 形状 + eexist_ok 仅 FwmarkRule
    #[test]
    fn escape_step_argv_undo_and_eexist_flag() {
        let rule = AppliedStep::FwmarkRule {
            mark: 0x5E45,
            table: ESCAPE_TABLE,
        };
        assert_eq!(
            rule.argv(),
            ["ip", "rule", "add", "fwmark", "24133", "table", "100"]
        );
        assert_eq!(
            rule.undo_argv(),
            ["ip", "rule", "del", "fwmark", "24133", "table", "100"]
        );
        assert!(rule.eexist_ok(), "ip rule add 幂等需容忍 EEXIST");

        let route = AppliedStep::EscapeRoute {
            table: ESCAPE_TABLE,
            via_dev: "via 192.168.1.1 dev eth0 proto dhcp".into(),
        };
        assert_eq!(
            route.argv(),
            [
                "ip",
                "route",
                "replace",
                "default",
                "via 192.168.1.1 dev eth0 proto dhcp",
                "table",
                "100"
            ]
        );
        assert_eq!(
            route.undo_argv(),
            ["ip", "route", "del", "default", "table", "100"]
        );
        assert!(!route.eexist_ok(), "route replace 本身幂等无需 EEXIST 容忍");

        // 其余步骤均不容忍 EEXIST
        let addr = AppliedStep::AddrReplaced {
            interface: "tun0".into(),
            cidr: "10.0.0.1/24".into(),
        };
        assert!(!addr.eexist_ok());
        let link = AppliedStep::LinkUp {
            interface: "tun0".into(),
        };
        assert!(!link.eexist_ok());
        let route_replaced = AppliedStep::RouteReplaced {
            cidr: "1.2.3.0/24".into(),
            interface: "tun0".into(),
            metric: 7,
        };
        assert!(!route_replaced.eexist_ok());

        // Display 渲染
        assert_eq!(rule.to_string(), "FwmarkRule(fwmark 0x5e45 table 100)");
        assert_eq!(
            route.to_string(),
            "EscapeRoute(default via 192.168.1.1 dev eth0 proto dhcp table 100)"
        );
    }

    /// mark ≠ 0 + 默认路由在场 → planned 含 escape 步骤（addr 之前）；
    /// mock 执行全成功、入账含 escape 两步
    #[tokio::test]
    async fn escape_steps_planned_and_applied_with_mark() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        rillane_core::net_mark::set_egress_fwmark(0x5E45);
        let mut mgr = LinuxRouteManager::new(route_control_routing())
            .with_tun_config(route_control_tun())
            .with_escape_default_route(Some("via 192.168.1.1 dev eth0 proto dhcp".into()));
        mgr.set_interface_name("rillaneR2esc".into());
        let _log = mgr.enable_mock_exec(None);

        let out = mgr.apply_desired(false).await.expect("应成功");
        // planned: FwmarkRule + EscapeRoute + addr + 1 条不重叠 include
        assert_eq!(out.planned.len(), 4, "含 escape 两步：{:?}", out.planned);
        assert_eq!(
            out.planned[0].argv(),
            ["ip", "rule", "add", "fwmark", "24133", "table", "100"]
        );
        assert_eq!(
            out.planned[1].argv(),
            [
                "ip",
                "route",
                "replace",
                "default",
                "via 192.168.1.1 dev eth0 proto dhcp",
                "table",
                "100"
            ]
        );
        // addr 步骤仍在 escape 之后
        assert_eq!(
            out.planned[2].argv(),
            [
                "ip",
                "addr",
                "replace",
                "10.90.0.1/24",
                "dev",
                "rillaneR2esc"
            ]
        );

        let st = mgr.status();
        assert_eq!(st.applied.len(), 4, "escape 两步入账");

        // clear 逆序：先 route/addr，再 EscapeRoute，最后 FwmarkRule
        let undone = mgr.clear().await.expect("clear 应成功");
        assert_eq!(undone.len(), 4);
        assert_eq!(
            undone[3].undo_argv(),
            ["ip", "rule", "del", "fwmark", "24133", "table", "100"]
        );
        rillane_core::net_mark::set_egress_fwmark(0);
    }

    /// mark = 0（缺省）→ 无 escape 步骤（零差异）
    #[tokio::test]
    async fn escape_steps_absent_when_mark_zero() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        rillane_core::net_mark::set_egress_fwmark(0);
        let mut mgr = LinuxRouteManager::new(route_control_routing())
            .with_tun_config(route_control_tun())
            .with_escape_default_route(Some("via 192.168.1.1 dev eth0".into()));
        mgr.set_interface_name("rillaneR2noesc".into());

        let out = mgr.apply_desired(true).await.expect("dry-run 应成功");
        assert!(
            !out.planned.iter().any(|s| matches!(
                s,
                AppliedStep::FwmarkRule { .. } | AppliedStep::EscapeRoute { .. }
            )),
            "mark=0 不应有 escape 步骤：{:?}",
            out.planned
        );
        assert_eq!(out.planned.len(), 2, "addr + 1 条不重叠 include");
    }

    /// 无默认路由（main 表无出口）→ 无 escape 步骤（escape 表无出口会丢包）
    #[tokio::test]
    async fn escape_steps_absent_without_default_route() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        rillane_core::net_mark::set_egress_fwmark(0x5E45);
        let mut mgr = LinuxRouteManager::new(route_control_routing())
            .with_tun_config(route_control_tun())
            .with_escape_default_route(None);
        mgr.skip_probe = true; // 跳过 probe，字段保持 None = 无默认路由
        mgr.set_interface_name("rillaneR2nrt".into());

        let out = mgr.apply_desired(true).await.expect("dry-run 应成功");
        assert!(
            !out.planned.iter().any(|s| matches!(
                s,
                AppliedStep::FwmarkRule { .. } | AppliedStep::EscapeRoute { .. }
            )),
            "无默认路由不应有 escape 步骤：{:?}",
            out.planned
        );
        rillane_core::net_mark::set_egress_fwmark(0);
    }

    /// EEXIST 容忍：FwmarkRule 步注入 File exists → 视为成功（幂等），
    /// 后续步骤继续执行
    #[tokio::test]
    async fn fwmark_rule_eexist_tolerated_keeps_batch_going() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        rillane_core::net_mark::set_egress_fwmark(0x5E45);
        let mut mgr = LinuxRouteManager::new(route_control_routing())
            .with_tun_config(route_control_tun())
            .with_escape_default_route(Some("via 192.168.1.1 dev eth0".into()));
        mgr.set_interface_name("rillaneR2eexist".into());
        let log = mgr.enable_mock_exec_with_eexist(None, Some(0));

        // 第 0 步（FwmarkRule）注入 File exists → 容忍成功
        let out = mgr.apply_desired(false).await.expect("EEXIST 应容忍");
        assert_eq!(out.planned.len(), 4);
        assert_eq!(out.executed.len(), 4, "全部步骤执行（EEXIST 不中断）");
        assert_eq!(mgr.status().applied.len(), 4, "全部入账");

        // 调用序列：4 步正向（第 0 步的 File exists 在 mock 层注入，
        // 不产生额外 undo 调用）
        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 4, "无回滚调用：{calls:?}");
        rillane_core::net_mark::set_egress_fwmark(0);
    }

    /// 非 FwmarkRule 步骤注入 File exists → 不容忍，正常 E7 回滚
    #[tokio::test]
    async fn non_fwmark_step_eexist_triggers_e7_rollback() {
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);
        rillane_core::net_mark::set_egress_fwmark(0x5E45);
        let mut mgr = LinuxRouteManager::new(route_control_routing())
            .with_tun_config(route_control_tun())
            .with_escape_default_route(Some("via 192.168.1.1 dev eth0".into()));
        mgr.set_interface_name("rillaneR2ex2".into());
        let _log = mgr.enable_mock_exec_with_eexist(None, Some(2));

        // 第 2 步（addr）注入 File exists → 不容忍 → E7 回滚前 2 步
        let f = mgr.apply_desired(false).await.expect_err("应 E7");
        assert_eq!(f.rolled_back.len(), 2, "前 2 步回滚");
        assert!(mgr.status().applied.is_empty(), "失败批不入账");
        rillane_core::net_mark::set_egress_fwmark(0);
    }

    /// probe 解析（共用纯函数）：`default via ... dev ...` → via_dev 取
    /// `default ` 后部分；空输出/仅空白/非 default 首行 → None（跳过
    /// escape 面，escape 表无出口会丢包）
    #[test]
    fn probe_parses_default_route_output() {
        // 有默认路由（典型 dhcp 输出）
        assert_eq!(
            parse_escape_route_template(
                "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100\n"
            ),
            Some("via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100")
        );

        // 无默认路由（空输出）
        assert_eq!(parse_escape_route_template(""), None);

        // 仅空白行
        assert_eq!(parse_escape_route_template("\n"), None);

        // 首行非 default（如只有 include 路由）→ None
        assert_eq!(
            parse_escape_route_template("10.90.0.0/24 dev rillaneTun0 scope link\n"),
            None
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
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
        {
            Ok(_) => true,
            Err(e) => {
                eprintln!(
                    "skip: /dev/net/tun 不可用（{:?}）——需 modprobe tun / 容器映射设备节点",
                    e.kind()
                );
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
        let forced = format!("rillane1{:x}", std::process::id());
        let mut tun =
            LinuxTunProvider::new(TunConfig::default().with_name(forced.clone()).with_ipv4(
                Ipv4Addr::new(10, 66, 0, 1),
                Ipv4Addr::new(255, 255, 255, 0),
                Ipv4Addr::new(10, 66, 0, 1),
            ));
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
            .send_to(b"rillane-t1", (Ipv4Addr::new(10, 66, 0, 2), 9999))
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
        assert_eq!(info.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))));
        assert_eq!(info.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2))));
        assert_eq!(info.src_port, Some(local_port));
        assert_eq!(info.dst_port, Some(9999));
        assert_eq!(info.protocol, Some(17));
        assert_eq!(info.length, bytes.len());
        assert!(bytes.ends_with(b"rillane-t1"), "UDP 载荷应在包尾");
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

    /// §7.2 集成（skip 守卫同 §4.2）：apply/clear 全程对账——dry-run 零变化 →
    /// apply ×2 幂等（前缀唯一 + 去重入账）→ status 对账 → clear 还原（仅
    /// rillane 所加行消失，设备仍 up）→ E8 空表幂等。include 用 pid 派生 /32
    /// 宿主路由（多会话共享内核路由表，独占命名防互踩）
    #[tokio::test]
    async fn route_apply_clear_roundtrip() {
        if !tun_device_available() {
            return;
        }
        // planner 读全局 net_mark 单例——与其他 apply_desired 测试串行；
        // 显式 mark=0（本测不验 escape 面，避免真机 ip rule 变更）
        let _guard = ROUTE_TEST_LOCK.lock().await;
        rillane_core::net_mark::set_egress_fwmark(0);

        async fn route_show(query: &str) -> String {
            let out = Command::new("ip")
                .args(["route", "show", query])
                .output()
                .await
                .expect("ip route show");
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        let pid = std::process::id();
        let iface = format!("rillane2{pid:x}");
        let octet = ((pid % 200) + 20) as u8; // 20..=219，避开 0/1/255
        let prefix = format!("198.51.100.{octet}/32");

        let tun_cfg = TunConfig::default().with_name(iface.clone()).with_ipv4(
            Ipv4Addr::new(10, 197, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 197, 0, 1),
        );
        let mut tun = LinuxTunProvider::new(tun_cfg.clone());
        if let Err(e) = tun.create_interface().await {
            if is_permission_skip(&e) {
                eprintln!("skip: 无 CAP_NET_ADMIN——{e}");
                return;
            }
            panic!("create_interface 失败：{e:#}");
        }
        tun.up_interface().await.expect("up_interface");

        let mut routing = RoutingConfig {
            enabled: true,
            ..RoutingConfig::default()
        };
        routing.rules.push(
            RouteRule::new(
                "include[0]".into(),
                RouteDestination::ipv4(Ipv4Addr::new(198, 51, 100, octet), 32).unwrap(),
            )
            .with_metric(77),
        );
        let mut mgr = LinuxRouteManager::new(routing).with_tun_config(tun_cfg);
        mgr.set_interface_name(iface.clone());
        mgr.set_device_up(true);

        // 基线（pid 复用留下的历史残留也兼容：全程按「相对基线」断言）
        let baseline = route_show(&prefix).await;

        // dry-run：planned 含 include 宿主路由，路由表零变化（§7.2）
        let out = mgr.apply_desired(true).await.expect("dry-run 应成功");
        assert!(out.executed.is_empty() && out.rolled_back.is_empty());
        assert!(
            out.planned.iter().any(|s| s.argv().contains(&prefix)),
            "planned 应含 include 宿主路由：{:?}",
            out.planned
        );
        assert_eq!(route_show(&prefix).await, baseline, "dry-run 零变化");

        // apply ×2：幂等（replace + 去重入账）——前缀唯一且 dev/metric 落位
        mgr.apply_desired(false).await.expect("首次 apply");
        mgr.apply_desired(false).await.expect("重放 apply（幂等）");
        let after = route_show(&prefix).await;
        let lines: Vec<&str> = after.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "重放后前缀唯一：{after}");
        assert!(
            lines[0].contains(&format!("dev {iface}")) && lines[0].contains("metric 77"),
            "dev/metric 落位：{}",
            lines[0]
        );

        // status 对账：去重入账稳定（addr + route 共 2 条）、设备态齐备
        let st = mgr.status();
        assert_eq!(st.applied.len(), 2, "去重入账：{:?}", st.applied);
        assert!(st.applied.iter().any(|r| matches!(
            &r.step,
            AppliedStep::RouteReplaced { cidr, interface, .. }
                if *cidr == prefix && *interface == iface
        )));
        assert_eq!(st.device.as_deref(), Some(iface.as_str()));
        assert_eq!(st.mtu, Some(tun.config().mtu));
        assert!(st.up);

        // clear 还原：仅 rillane 所加行消失（回到基线）、账本清空、设备仍 up（§5）
        let undone = mgr.clear().await.expect("clear 应成功");
        assert_eq!(undone.len(), 2, "逆序全量撤销：{undone:?}");
        assert_eq!(route_show(&prefix).await, baseline, "clear 后回到基线");
        let st = mgr.status();
        assert!(st.applied.is_empty());
        assert!(st.up, "clear 后设备仍 up（数据面空转，§5）");
        assert!(
            mgr.clear().await.unwrap().is_empty(),
            "无步骤时 Ok 空表（E8 幂等）"
        );

        // teardown：账面归零 + 设备回收
        mgr.set_device_up(false);
        mgr.clear_interface_name();
        tun.down_interface().await.expect("down_interface");
        tun.destroy_interface().await.expect("destroy_interface");
    }
}
