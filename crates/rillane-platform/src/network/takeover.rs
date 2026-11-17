//! Linux 接管端口迁移（RIL-029）：把 RIL-004 的四个平台端口契约
//! （CapturePort / SocketBypass / NetworkEvents / RouteTransaction）落
//! 到 Linux 现有机制上——**复用**现有 TUN 数据面（tun.rs
//! TunProvider + linux.rs AppliedStep 逃逸表），不另起第二套实现。
//!
//! 边界（验收口径）：
//! - **双栈捕获**：[`parse_packet_meta`] 解析 IPv4/IPv6 L3 整包为中立
//!   三元组（TCP/UDP/ICMP；QUIC 走 UDP 载荷原样过、DNS 走 UDP 端口
//!   53 载荷原样过——分类面不拆传输层头，端口只保真传递）；扩展头
//!   IPv6 按下一头号如实记 `Other(nh)`，不猜语义；
//! - **MTU 守卫**：超 TunConfig MTU 的包不进捕获面（计数可见，不当
//!   零不当坏——内核本不应发出，出现即配置漂移信号）；
//! - **无自代理环**：[`LinuxSocketBypass`] 把本进程出站 socket 打
//!   SO_MARK（与 net_mark/linux.rs 同值 `0x5E45`），带 mark 包查
//!   linux.rs 逃逸表（fwmark rule + escape 默认路由，已有实现）出物理
//!   网卡——代理自身流量不回灌 TUN；权限不足显式报错不静默降级；
//! - **多网卡回归**：[`NetSnapshot`] 记**全部**默认路由出口序列
//!   （`ip route show default` 逐行 dev），主出口切换/全丢/恢复的
//!   事件映射确定（Change / Lost+None / Restored 对成对出现，一次
//!   迁移一事件，不下游双反应）；DNS 变化独立事件；
//! - **事务补偿**：[`LinuxRouteTransaction`] 载荷 = AppliedStep argv
//!   空格序列（「计划 = 执行」同源——payload 解析回 AppliedStep，无
//!   第二构造路径）；prepare 只解析零系统改动；apply 逐步执行、失败
//!   逆序补偿本事务已应用步（EEXIST 按幂等成功——仅 fwmark rule）；
//!   rollback 逆序撤销、目标不存在视为已撤销（幂等）、重复回滚
//!   无操作。
//!
//! 接线边界：TUN 包泵 [`pump_tun`] 由 runtime 在接管启动时挂
//! TunProvider.read_packet → 通道；[`read_net_snapshot`] 轮询挂周期
//! 任务；`ip_step_executor` 真执行器挂事务应用。内核无时钟无 IO 面
//! 之外的决策全部确定性可测（执行器可注入）。

use std::collections::VecDeque;
use std::io;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::FromRawFd;
use std::process::Command;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;

use anyhow::{Context, Result};
use nix::libc;

use crate::network::linux::AppliedStep;
use crate::network::ports::{
    CapturePort, CapturedInput, IpProtocol, NetworkEvent, NetworkEvents, PacketInput, PacketMeta,
    RouteTransaction, SocketBypass, SocketHandle, SystemChange,
};
use crate::network::tun::TunProvider;

/// 接管逃逸 fwmark（与 linux.rs 逃逸表 / net_mark egress 同值——同一
/// 个环豁免机制，不引入第二 mark 语义）
pub const TAKEOVER_FWMARK: u32 = 0x5E45;

/// 从 L3 整包解析 IP 三元组（双栈）：IPv4（IHL 弹性头长）与 IPv6（固定
/// 40 字节主头）→ PacketMeta。协议映射 6→Tcp、17→Udp（QUIC/DNS 同面
/// 原样过）、1/58→Icmp、其余→Other(号)。坏版本/截断头显式报错不猜。
pub fn parse_packet_meta(packet: &[u8]) -> io::Result<PacketMeta> {
    let bad = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());
    if packet.is_empty() {
        return Err(bad("空包"));
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(bad("IPv4 头截断"));
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 || ihl > packet.len() {
                return Err(bad("IPv4 IHL 越界"));
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Ok(PacketMeta {
                src: src.into(),
                dst: dst.into(),
                protocol: map_ip_proto(packet[9]),
            })
        }
        6 => {
            if packet.len() < 40 {
                return Err(bad("IPv6 头截断"));
            }
            let u16_at = |i: usize| u16::from_be_bytes([packet[i], packet[i + 1]]);
            let src = Ipv6Addr::new(
                u16_at(8),
                u16_at(10),
                u16_at(12),
                u16_at(14),
                u16_at(16),
                u16_at(18),
                u16_at(20),
                u16_at(22),
            );
            let dst = Ipv6Addr::new(
                u16_at(24),
                u16_at(26),
                u16_at(28),
                u16_at(30),
                u16_at(32),
                u16_at(34),
                u16_at(36),
                u16_at(38),
            );
            Ok(PacketMeta {
                src: src.into(),
                dst: dst.into(),
                protocol: map_ip_proto(packet[6]),
            })
        }
        v => Err(bad(&format!("未知 IP 版本 {v}"))),
    }
}

/// 协议号 → 中立枚举（v4/v6 共用：58 = ICMPv6）
fn map_ip_proto(n: u8) -> IpProtocol {
    match n {
        6 => IpProtocol::Tcp,
        17 => IpProtocol::Udp,
        1 | 58 => IpProtocol::Icmp,
        other => IpProtocol::Other(other),
    }
}

/// 捕获端口用量（MTU 守卫与解析失败的可见计数——不当零不当坏）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TakeoverPortStats {
    /// 已捕获进契约面的包数
    pub captured: u64,
    /// 超 MTU 跳过数（内核不应发出——出现即 MTU 配置漂移信号）
    pub skipped_oversize: u64,
    /// 解析失败跳过数（坏包显式计数）
    pub parse_errors: u64,
}

/// Linux TUN 捕获端口（RIL-004 CapturePort 实现）：复用现有 TUN 数据
/// 面——runtime 把 `TunProvider::read_packet` 经 [`pump_tun`] 泵进通道，
/// 本端口在同步面按就绪语义取用（无包 `WouldBlock`，不自旋阻塞）；
/// 端口关闭（通道断）→ `Ok(None)`。MTU 守卫与坏包跳过均计数可见。
pub struct LinuxTakeoverPort {
    rx: Receiver<Vec<u8>>,
    mtu: u16,
    open: bool,
    stats: TakeoverPortStats,
}

impl LinuxTakeoverPort {
    /// 从包通道构造（mtu 取 TunConfig.mtu）
    pub fn new(rx: Receiver<Vec<u8>>, mtu: u16) -> Self {
        Self {
            rx,
            mtu,
            open: true,
            stats: TakeoverPortStats::default(),
        }
    }

    /// 捕获用量
    pub fn stats(&self) -> TakeoverPortStats {
        self.stats
    }
}

impl CapturePort for LinuxTakeoverPort {
    fn recv(&mut self) -> io::Result<Option<CapturedInput>> {
        if !self.open {
            return Ok(None);
        }
        loop {
            match self.rx.try_recv() {
                Ok(bytes) => {
                    if bytes.len() > self.mtu as usize {
                        self.stats.skipped_oversize += 1;
                        continue;
                    }
                    match parse_packet_meta(&bytes) {
                        Ok(meta) => {
                            self.stats.captured += 1;
                            return Ok(Some(CapturedInput::Packet(PacketInput {
                                packet: bytes,
                                meta,
                            })));
                        }
                        Err(_) => {
                            self.stats.parse_errors += 1;
                            continue;
                        }
                    }
                }
                Err(TryRecvError::Empty) => {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "无就绪包"));
                }
                Err(TryRecvError::Disconnected) => {
                    self.open = false;
                    return Ok(None);
                }
            }
        }
    }
}

/// TUN 包泵：现有 TunProvider 数据面 → 捕获通道（复用现有 TUN 的对接
/// 点；runtime 在接管启动时 spawn）。接收端关闭即正常收尾返回已转发数；
/// 读包错误原样上抛（ dataplane 错误不许吞）。
pub async fn pump_tun(
    provider: &mut dyn TunProvider,
    tx: std::sync::mpsc::Sender<Vec<u8>>,
) -> Result<u64> {
    let mut forwarded = 0u64;
    loop {
        let (bytes, _info) = provider.read_packet().await?;
        if tx.send(bytes.to_vec()).is_err() {
            return Ok(forwarded);
        }
        forwarded += 1;
    }
}

/// Linux 出站旁路（RIL-004 SocketBypass 实现）：对句柄指向的 socket
/// 设 SO_MARK = 逃逸 mark。带 mark 的出站包查 linux.rs 逃逸表（fwmark
/// rule + escape 默认路由）走物理网卡——本进程代理/DNS 流量不回灌
/// TUN（无自代理环的机制面）。setsockopt 天然幂等：重复标记同一
/// socket 无状态变化。句柄必须是合法 fd（契约层不透明，适配器解释）。
#[derive(Debug, Clone)]
pub struct LinuxSocketBypass {
    mark: u32,
}

impl LinuxSocketBypass {
    /// 自定义 mark（与逃逸表 fwmark rule 对齐时用）
    pub fn new(mark: u32) -> Self {
        Self { mark }
    }

    /// 默认 mark（TAKEOVER_FWMARK，对齐 linux.rs/net_mark 同一逃逸面）
    pub fn with_default() -> Self {
        Self::new(TAKEOVER_FWMARK)
    }
}

impl SocketBypass for LinuxSocketBypass {
    fn bypass(&self, socket: SocketHandle) -> Result<()> {
        let fd = i32::try_from(socket.as_u64()).context("SocketHandle 不是合法 fd 口径")?;
        // 不取得所有权：包装只为 setsockopt，标记完不关闭调用方的 fd
        let sock = ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(fd) });
        sock.set_mark(self.mark).with_context(|| {
            format!(
                "SO_MARK {} 设置失败（需 CAP_NET_ADMIN；无权限时接管旁路面不可用）",
                self.mark
            )
        })?;
        Ok(())
    }
}

/// 读回 socket 的 SO_MARK（测试/诊断用）
pub fn read_so_mark(fd: i32) -> io::Result<u32> {
    let mut mark: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark as *mut u32 as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(mark)
}

/// 网络快照：全部默认路由出口序列（多网卡回归面：主出口 = 首条）+
/// 系统解析器序。两次快照的差分 = 网络事件。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetSnapshot {
    /// 默认路由出口接口名序（`ip route show default` 逐行 dev；
    /// 空 = 无默认路由）
    pub default_ifaces: Vec<String>,
    /// 系统解析器地址序（resolv.conf nameserver 行序）
    pub dns_servers: Vec<IpAddr>,
}

impl NetSnapshot {
    /// 主出口接口（首条默认路由；None = 无默认路由）
    pub fn primary_iface(&self) -> Option<&String> {
        self.default_ifaces.first()
    }

    /// 差分 → 网络事件（self = 新，prev = 旧）。映射确定：
    /// - 主出口变换（Some a → Some b，a≠b）：`DefaultRouteChanged{Some b}`
    /// - 主出口丢失（Some → None）：`DefaultRouteChanged{None}` +
    ///   `ConnectivityLost`（成对——一次迁移一事件）
    /// - 主出口恢复（None → Some b）：`DefaultRouteChanged{Some b}` +
    ///   `ConnectivityRestored`
    /// - 解析器序变化：`SystemDnsChanged`（独立事件）
    ///
    /// 路由事件在前、DNS 事件在后。
    pub fn diff_events(&self, prev: &Self) -> Vec<NetworkEvent> {
        let mut events = Vec::new();
        let new_primary = self.primary_iface();
        match (prev.primary_iface(), new_primary) {
            (Some(a), Some(b)) if a != b => events.push(NetworkEvent::DefaultRouteChanged {
                interface: Some(b.clone()),
            }),
            (Some(_), None) => {
                events.push(NetworkEvent::DefaultRouteChanged { interface: None });
                events.push(NetworkEvent::ConnectivityLost);
            }
            (None, Some(b)) => {
                events.push(NetworkEvent::DefaultRouteChanged {
                    interface: Some(b.clone()),
                });
                events.push(NetworkEvent::ConnectivityRestored);
            }
            _ => {}
        }
        if prev.dns_servers != self.dns_servers {
            events.push(NetworkEvent::SystemDnsChanged);
        }
        events
    }
}

/// 解析 `ip route show default` 输出：逐行 `default ... dev <iface>` →
/// 接口名序（多网卡多默认路由按输出序保真；非 default 行忽略）。
pub fn parse_default_ifaces(route_show: &str) -> Vec<String> {
    route_show
        .lines()
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            if tokens.next()? != "default" {
                return None;
            }
            let mut dev = None;
            while let Some(tok) = tokens.next() {
                if tok == "dev" {
                    dev = tokens.next().map(str::to_string);
                    break;
                }
            }
            dev
        })
        .collect()
}

/// 解析 resolv.conf：`nameserver <addr>` 行序（注释/空行/其它指令忽略；
/// 解析失败的行跳过不猜）。
pub fn parse_resolv_nameservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.split('#').next()?.trim();
            let line = line.split(';').next()?.trim();
            let mut tokens = line.split_whitespace();
            if tokens.next()? != "nameserver" {
                return None;
            }
            tokens.next().and_then(|s| s.parse().ok())
        })
        .collect()
}

/// 读真机网络快照（`ip route show default` + `/etc/resolv.conf`）。
/// `ip` 执行失败上抛；resolv 缺失按无解析器处理（不猜）。
pub fn read_net_snapshot() -> Result<NetSnapshot> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("ip route show default 执行失败")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let dns_servers = std::fs::read_to_string("/etc/resolv.conf")
        .map(|t| parse_resolv_nameservers(&t))
        .unwrap_or_default();
    Ok(NetSnapshot {
        default_ifaces: parse_default_ifaces(&text),
        dns_servers,
    })
}

/// Linux 网络事件源（RIL-004 NetworkEvents 实现）：周期 [`refresh`]
/// 快照差分入缓冲，`recv` 按序吐出（None = 暂无事件；流不关闭——
/// 轮询面持续在）。
pub struct LinuxNetworkEvents {
    buf: VecDeque<NetworkEvent>,
    last: NetSnapshot,
}

impl LinuxNetworkEvents {
    /// 以初始快照构造（首个周期起差分）
    pub fn new(initial: NetSnapshot) -> Self {
        Self {
            buf: VecDeque::new(),
            last: initial,
        }
    }

    /// 周期刷新：差分新快照并入缓冲，返回本次新增事件数
    pub fn refresh(&mut self, next: NetSnapshot) -> usize {
        let events = next.diff_events(&self.last);
        let count = events.len();
        for ev in events {
            self.buf.push_back(ev);
        }
        self.last = next;
        count
    }

    /// 最近一次快照（可观测）
    pub fn last_snapshot(&self) -> &NetSnapshot {
        &self.last
    }
}

impl NetworkEvents for LinuxNetworkEvents {
    fn recv(&mut self) -> Option<NetworkEvent> {
        self.buf.pop_front()
    }
}

/// 步骤执行器（事务可注入面；真实现见 [`ip_step_executor`]）
pub type StepExecutor = Arc<dyn Fn(&[String]) -> io::Result<()> + Send + Sync>;

/// AppliedStep → 变更载荷（argv 空格序列——「计划 = 执行」同源，无
/// 第二构造路径；argv 各项无内嵌空格）
pub fn step_payload(step: &AppliedStep) -> String {
    step.argv().join(" ")
}

/// 变更载荷 → AppliedStep（形状不符显式拒绝——prepare 系统零改动的
/// 前提是载荷先可解释）
pub fn parse_step_payload(payload: &str) -> Result<AppliedStep> {
    let argv: Vec<&str> = payload.split_whitespace().collect();
    let bad = || anyhow::anyhow!("未知变更载荷: {payload}");
    Ok(match argv.as_slice() {
        ["ip", "addr", "replace", cidr, "dev", iface] => AppliedStep::AddrReplaced {
            cidr: (*cidr).to_string(),
            interface: (*iface).to_string(),
        },
        ["ip", "link", "set", "dev", iface, "up"] => AppliedStep::LinkUp {
            interface: (*iface).to_string(),
        },
        ["ip", "route", "replace", cidr, "dev", iface, "metric", metric] => {
            AppliedStep::RouteReplaced {
                cidr: (*cidr).to_string(),
                interface: (*iface).to_string(),
                metric: metric.parse().map_err(|_| bad())?,
            }
        }
        ["ip", "rule", "add", "fwmark", mark, "table", table] => AppliedStep::FwmarkRule {
            mark: mark.parse().map_err(|_| bad())?,
            table: table.parse().map_err(|_| bad())?,
        },
        ["ip", "route", "replace", "default", iface, "table", table] => AppliedStep::EscapeRoute {
            table: table.parse().map_err(|_| bad())?,
            via_dev: (*iface).to_string(),
        },
        _ => return Err(bad()),
    })
}

fn is_eexist(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::AlreadyExists || e.to_string().contains("File exists")
}

/// 撤销幂等口径：目标不存在（路由/地址/规则已不在、设备已无）视为
/// 已撤销——rollback 幂等的机制面
fn is_missing(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
        || e.to_string().contains("No such")
        || e.to_string().contains("Cannot find device")
}

/// Linux 路由事务（RIL-004 RouteTransaction 实现）：复用 linux.rs
/// AppliedStep 的 argv/undo_argv 机器。prepare 只解析载荷零系统改动；
/// apply 逐步执行、失败逆序补偿本事务已应用步（fwmark rule 的 EEXIST
/// 按幂等成功）；rollback 逆序撤销、目标不存在视为已撤销、重复回滚
/// 无操作。执行器可注入（测试确定性；真实现 shell-out `ip`）。
pub struct LinuxRouteTransaction {
    exec: StepExecutor,
    staged: Vec<AppliedStep>,
    applied: Vec<AppliedStep>,
    closed: bool,
}

impl LinuxRouteTransaction {
    /// 注入执行器构造
    pub fn new(exec: StepExecutor) -> Self {
        Self {
            exec,
            staged: Vec::new(),
            applied: Vec::new(),
            closed: false,
        }
    }

    /// 真执行器：shell-out argv[0]（载荷解析保证只有 `ip` 面），非零
    /// 退出码带 stderr 文本（is_eexist/is_missing 的口径在文本上判定）
    pub fn ip_step_executor() -> StepExecutor {
        Arc::new(|argv: &[String]| {
            let (prog, rest) = argv
                .split_first()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "空 argv"))?;
            let out = Command::new(prog).args(rest).output()?;
            if out.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(io::Error::other(stderr))
        })
    }

    /// 已应用步骤（测试/对账观察面）
    pub fn applied(&self) -> &[AppliedStep] {
        &self.applied
    }

    /// 逆序撤销一批步骤；目标不存在视为已撤销。返回 (已撤销数, 未消化
    /// 失败)。
    fn undo_all(&self, steps: &[AppliedStep]) -> (usize, Vec<String>) {
        let mut undone = 0usize;
        let mut failures = Vec::new();
        for step in steps.iter().rev() {
            if let Err(e) = (self.exec)(&step.undo_argv()) {
                if is_missing(&e) {
                    undone += 1;
                    continue;
                }
                failures.push(format!("{step}: {e}"));
            } else {
                undone += 1;
            }
        }
        (undone, failures)
    }
}

impl RouteTransaction for LinuxRouteTransaction {
    fn prepare(&mut self, changes: Vec<SystemChange>) -> Result<()> {
        if self.closed {
            anyhow::bail!("事务已回滚关闭");
        }
        let mut staged = Vec::with_capacity(changes.len());
        for change in &changes {
            staged.push(
                parse_step_payload(&change.payload)
                    .with_context(|| format!("变更载荷解析失败 id={}", change.id))?,
            );
        }
        self.staged = staged;
        Ok(())
    }

    fn apply(&mut self) -> Result<()> {
        if self.closed {
            anyhow::bail!("事务已回滚关闭");
        }
        let steps = std::mem::take(&mut self.staged);
        let mut executed = Vec::new();
        for step in &steps {
            match (self.exec)(&step.argv()) {
                Ok(()) => executed.push(step.clone()),
                Err(e) if step.eexist_ok() && is_eexist(&e) => executed.push(step.clone()),
                Err(e) => {
                    let (undone, _) = self.undo_all(&executed);
                    anyhow::bail!("步骤 {step} 应用失败: {e}；已逆序补偿回滚 {undone} 步");
                }
            }
        }
        self.applied.extend(executed);
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        if self.closed {
            return Ok(()); // 幂等：重复回滚无操作
        }
        let applied = std::mem::take(&mut self.applied);
        self.staged.clear();
        self.closed = true;
        let (_, failures) = self.undo_all(&applied);
        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("撤销未完全消化: {:?}", failures)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;

    // ---- 包构造助手（测试用，不进生产面）----

    fn v4_header(proto: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p
    }

    fn v6_header(next_header: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, next_header, 64];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p
    }

    fn udp_header(sport: u16, dport: u16, payload_len: usize) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&sport.to_be_bytes());
        h.extend_from_slice(&dport.to_be_bytes());
        h.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        h.extend_from_slice(&[0, 0]); // cksum
        h
    }

    fn v4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = v4_header(17, src, dst);
        p.extend(udp_header(sport, dport, payload.len()));
        p.extend_from_slice(payload);
        p
    }

    // ---- 验收①：TCP/UDP/QUIC/DNS 双栈捕获分类 ----

    /// 双栈分类：v4 TCP、v4 UDP（DNS 53 / QUIC 443 载荷原样）、v6 TCP、
    /// ICMP/ICMPv6、未知协议 Other、坏包拒绝
    #[test]
    fn parse_packet_meta_dual_stack_classifies_protocols() {
        // v4 TCP
        let meta = parse_packet_meta(&v4_header(6, [10, 0, 0, 2], [1, 1, 1, 1])).expect("v4 tcp");
        assert_eq!(meta.src, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(meta.dst, IpAddr::from([1, 1, 1, 1]));
        assert_eq!(meta.protocol, IpProtocol::Tcp);

        // DNS：UDP dport 53，载荷含 DNS 报文头（原样过——端口面不拆传输层）
        let dns_query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let dns_pkt = v4_udp([10, 0, 0, 2], [8, 8, 8, 8], 40000, 53, &dns_query);
        let meta = parse_packet_meta(&dns_pkt).expect("dns udp");
        assert_eq!(meta.protocol, IpProtocol::Udp);
        assert_eq!(meta.dst, IpAddr::from([8, 8, 8, 8]));

        // QUIC：UDP dport 443 长载荷（IHL 弹性头长路径同时覆盖）
        let quic = vec![0xc0u8; 64];
        let quic_pkt = v4_udp([10, 0, 0, 2], [93, 184, 216, 34], 50000, 443, &quic);
        let meta = parse_packet_meta(&quic_pkt).expect("quic udp");
        assert_eq!(meta.protocol, IpProtocol::Udp);

        // ICMP
        let meta = parse_packet_meta(&v4_header(1, [10, 0, 0, 2], [10, 0, 0, 1])).expect("icmp");
        assert_eq!(meta.protocol, IpProtocol::Icmp);

        // v6 TCP + ICMPv6(58) → Icmp + 未知协议 Other
        let mut v6src = [0u8; 16];
        v6src[..4].copy_from_slice(&[0xfd, 0x00, 0, 1]);
        let mut v6dst = [0u8; 16];
        v6dst[..4].copy_from_slice(&[0x20, 0x01, 0x48, 0x60]);
        let meta = parse_packet_meta(&v6_header(6, v6src, v6dst)).expect("v6 tcp");
        assert_eq!(meta.protocol, IpProtocol::Tcp);
        assert_eq!(meta.src, IpAddr::from(Ipv6Addr::from(v6src)));
        let meta = parse_packet_meta(&v6_header(58, v6src, v6dst)).expect("icmpv6");
        assert_eq!(meta.protocol, IpProtocol::Icmp);
        let meta = parse_packet_meta(&v6_header(0, v6src, v6dst)).expect("hop-by-hop");
        assert_eq!(meta.protocol, IpProtocol::Other(0), "扩展头如实记号不猜");

        // 坏包拒绝：空 / 未知版本 / 截断
        assert!(parse_packet_meta(&[]).is_err());
        assert!(parse_packet_meta(&[0x70, 0, 0]).is_err());
        assert!(parse_packet_meta(&v4_header(6, [1, 2, 3, 4], [5, 6, 7, 8])[..12]).is_err());
    }

    // ---- 验收④：MTU 守卫 + 捕获端口通道语义 ----

    /// MTU 守卫：超 MTU 跳过计数可见；通道就绪/WouldBlock/关闭语义
    #[test]
    fn takeover_port_mtu_guard_and_channel_semantics() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mtu = 1500u16;
        let mut port = LinuxTakeoverPort::new(rx, mtu);

        // 无包 → WouldBlock（就绪语义，不自旋阻塞）
        let err = port.recv().expect_err("空通道应 WouldBlock");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // 正常包（DNS）→ 捕获，载荷逐字节保真
        let dns_pkt = v4_udp([10, 0, 0, 2], [8, 8, 8, 8], 40000, 53, &[1, 2, 3]);
        tx.send(dns_pkt.clone()).expect("发送");
        let Some(CapturedInput::Packet(p)) = port.recv().expect("捕获") else {
            panic!("应是包输入");
        };
        assert_eq!(p.packet, dns_pkt, "载荷逐字节保真");
        assert_eq!(p.meta.protocol, IpProtocol::Udp);

        // 超 MTU → 跳过计数（不当零不当坏）
        let oversize = vec![0x45u8; (mtu as usize + 1) + 20];
        tx.send(oversize).expect("发送");
        // 同通道再放一个好包：recv 跳过超限包后应给好包（守卫不吞好流量）
        let good = v4_header(6, [1, 2, 3, 4], [5, 6, 7, 8]);
        tx.send(good.clone()).expect("发送");
        let Some(CapturedInput::Packet(p)) = port.recv().expect("跳过超限后捕获好包")
        else {
            panic!("应是包输入");
        };
        assert_eq!(p.meta.protocol, IpProtocol::Tcp);
        assert_eq!(port.stats().skipped_oversize, 1);

        // 坏包 → parse_errors 计数，好流量不受连累
        tx.send(vec![0x70, 0, 0]).expect("发送");
        tx.send(good).expect("发送");
        let Some(CapturedInput::Packet(_)) = port.recv().expect("坏包跳过后捕获") else {
            panic!("应是包输入");
        };
        assert_eq!(port.stats().parse_errors, 1);

        // 关闭 → Ok(None)（端口关闭语义）
        drop(tx);
        assert_eq!(port.recv().expect("关闭"), None);
        assert_eq!(port.recv().expect("重复关闭"), None);
        let stats = port.stats();
        assert_eq!(stats.captured, 3);
        assert_eq!(stats.skipped_oversize, 1);
        assert_eq!(stats.parse_errors, 1);
    }

    /// 泵：现有 TunProvider 数据面 → 通道转发；接收端关闭正常收尾
    #[tokio::test]
    async fn pump_tun_forwards_packets_until_receiver_closes() {
        #[derive(Debug)]
        struct MockTun {
            queue: VecDeque<Vec<u8>>,
            cfg: crate::network::tun::TunConfig,
        }
        #[async_trait::async_trait]
        impl TunProvider for MockTun {
            fn name(&self) -> &str {
                "mock0"
            }
            fn config(&self) -> &crate::network::tun::TunConfig {
                &self.cfg
            }
            fn is_up(&self) -> bool {
                true
            }
            fn mtu(&self) -> u16 {
                1500
            }
            fn stats(&self) -> crate::network::tun::InterfaceStats {
                Default::default()
            }
            async fn create_interface(&mut self) -> Result<()> {
                Ok(())
            }
            async fn destroy_interface(&mut self) -> Result<()> {
                Ok(())
            }
            async fn up_interface(&mut self) -> Result<()> {
                Ok(())
            }
            async fn down_interface(&mut self) -> Result<()> {
                Ok(())
            }
            async fn configure_ip(&mut self) -> Result<()> {
                Ok(())
            }
            async fn configure_routing(&mut self) -> Result<()> {
                Ok(())
            }
            async fn configure_dns(&mut self) -> Result<()> {
                Ok(())
            }
            async fn read_packet(
                &mut self,
            ) -> Result<(bytes::Bytes, crate::network::tun::PacketInfo)> {
                match self.queue.pop_front() {
                    Some(b) => {
                        let len = b.len();
                        Ok((
                            bytes::Bytes::from(b),
                            crate::network::tun::PacketInfo::new(
                                crate::network::tun::PacketType::from_ip_version(4),
                                len,
                            ),
                        ))
                    }
                    None => Err(anyhow::anyhow!("EOF")),
                }
            }
            async fn write_packet(&mut self, _packet: bytes::Bytes) -> Result<()> {
                Ok(())
            }
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let mut tun = MockTun {
            queue: VecDeque::from(vec![
                vec![0x45u8; 20],
                v4_header(6, [1, 2, 3, 4], [5, 6, 7, 8]),
            ]),
            cfg: crate::network::tun::TunConfig::new(),
        };
        // 前两个包转发进通道；第三个读失败 → 泵上抛（数据面错误不吞）
        let err = pump_tun(&mut tun, tx).await.expect_err("EOF 应上抛");
        assert!(err.to_string().contains("EOF"));
        drop(rx);

        // 接收端已关：泵在转发前发现通道关闭 → 正常收尾返回 0
        let (tx2, rx2) = std::sync::mpsc::channel();
        drop(rx2);
        let mut tun = MockTun {
            queue: VecDeque::from(vec![vec![0x45u8; 20]]),
            cfg: crate::network::tun::TunConfig::new(),
        };
        let sent = pump_tun(&mut tun, tx2).await.expect("接收端关闭应正常收尾");
        assert_eq!(sent, 0);
    }

    // ---- 验收⑤：无自代理环（SO_MARK 旁路面）----

    /// SO_MARK 旁路：root 下真打 mark 并读回校验（幂等重复标记）；非
    /// root 下显式报错点名 CAP_NET_ADMIN（不静默降级）。句柄 fd 不被
    /// 关闭（测试末尾自行 close 验证所有权边界）。
    #[test]
    fn socket_bypass_sets_mark_live() {
        let bypass = LinuxSocketBypass::with_default();
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("建探针 socket");
        let fd = sock.into_raw_fd();
        let handle = SocketHandle::new(fd as u64);

        let result = bypass.bypass(handle);
        if unsafe { libc::geteuid() } == 0 {
            result.expect("root 下应设上 mark");
            assert_eq!(
                read_so_mark(fd).expect("读回 SO_MARK"),
                TAKEOVER_FWMARK,
                "mark 与逃逸表同值"
            );
            // 幂等：重复标记无副作用
            bypass.bypass(handle).expect("重复标记幂等");
            assert_eq!(read_so_mark(fd).expect("读回"), TAKEOVER_FWMARK);
        } else {
            let err = result.expect_err("无权限应显式报错");
            assert!(
                err.to_string().contains("CAP_NET_ADMIN"),
                "错误应点名权限: {err}"
            );
        }
        // 所有权边界：适配器不关闭调用方 fd——句柄 fd 仍归调用方，close
        // 成功即证（若适配器误关，这里 close 会命中已回收 fd）
        let rc = unsafe { libc::close(fd) };
        assert_eq!(rc, 0, "fd 应仍属调用方（未被适配器关闭）");
    }

    // ---- 验收⑥：多网卡快照解析与事件差分 ----

    /// 多网卡解析：双默认路由按输出序保真；resolv 注释/去重/坏行跳过
    #[test]
    fn snapshot_parsers_handle_multi_nic_and_resolv_noise() {
        let routes = "\
default via 10.0.0.1 dev ens18 metric 100
default via 10.8.0.1 dev wg-mlt metric 200
10.0.0.0/8 dev ens18 scope link
";
        assert_eq!(
            parse_default_ifaces(routes),
            vec!["ens18".to_string(), "wg-mlt".to_string()],
            "多网卡多默认路由按序保真，主出口 = 首条"
        );
        assert!(parse_default_ifaces("").is_empty(), "无默认路由 = 空");
        assert!(
            parse_default_ifaces("10.0.0.0/8 dev eth0\n").is_empty(),
            "非 default 行忽略"
        );

        let resolv = "\
# Generated by resolvconf
nameserver 10.0.0.1
; legacy comment
nameserver 2001:db8::53
nameserver 10.0.0.1
search lan
nameserver not-an-ip
";
        assert_eq!(
            parse_resolv_nameservers(resolv),
            vec![
                IpAddr::from([10, 0, 0, 1]),
                IpAddr::from([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x53]),
                IpAddr::from([10, 0, 0, 1]),
            ],
            "注释/坏行跳过、IPv6 解析、重复保真（差分按序比较）"
        );
    }

    /// 事件差分确定映射：主出口切换/丢失/恢复成对出现、DNS 独立、
    /// 无变化零事件
    #[test]
    fn snapshot_diff_emits_network_events_deterministically() {
        let on_ens18 = NetSnapshot {
            default_ifaces: vec!["ens18".into(), "wg-mlt".into()],
            dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
        };
        let on_wg = NetSnapshot {
            default_ifaces: vec!["wg-mlt".into()],
            dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
        };
        let offline = NetSnapshot {
            default_ifaces: vec![],
            dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
        };
        let dns_moved = NetSnapshot {
            default_ifaces: vec!["wg-mlt".into()],
            dns_servers: vec![IpAddr::from([8, 8, 8, 8])],
        };

        // 多网卡切换：ens18 主 → wg-mlt 主
        assert_eq!(
            on_wg.diff_events(&on_ens18),
            vec![NetworkEvent::DefaultRouteChanged {
                interface: Some("wg-mlt".into())
            }]
        );
        // 全丢：DefaultRouteChanged{None} + ConnectivityLost 成对
        assert_eq!(
            offline.diff_events(&on_wg),
            vec![
                NetworkEvent::DefaultRouteChanged { interface: None },
                NetworkEvent::ConnectivityLost
            ]
        );
        // 恢复：DefaultRouteChanged + ConnectivityRestored 成对
        assert_eq!(
            on_wg.diff_events(&offline),
            vec![
                NetworkEvent::DefaultRouteChanged {
                    interface: Some("wg-mlt".into())
                },
                NetworkEvent::ConnectivityRestored
            ]
        );
        // 同网卡无变化：零事件（DNS 同序）
        assert!(on_wg.diff_events(&on_wg).is_empty());
        // DNS 变化独立事件
        assert_eq!(
            dns_moved.diff_events(&on_wg),
            vec![NetworkEvent::SystemDnsChanged]
        );
    }

    /// 事件端口：refresh 差分入缓冲、recv 按序吐出
    #[test]
    fn network_events_port_buffers_and_drains() {
        let mut port = LinuxNetworkEvents::new(NetSnapshot {
            default_ifaces: vec!["ens18".into()],
            dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
        });
        assert!(port.recv().is_none(), "无变化无事件");

        port.refresh(NetSnapshot {
            default_ifaces: vec![],
            dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
        });
        port.refresh(NetSnapshot {
            default_ifaces: vec!["wg-mlt".into()],
            dns_servers: vec![IpAddr::from([9, 9, 9, 9])],
        });
        assert_eq!(
            port.recv(),
            Some(NetworkEvent::DefaultRouteChanged { interface: None })
        );
        assert_eq!(port.recv(), Some(NetworkEvent::ConnectivityLost));
        assert_eq!(
            port.recv(),
            Some(NetworkEvent::DefaultRouteChanged {
                interface: Some("wg-mlt".into())
            })
        );
        assert_eq!(port.recv(), Some(NetworkEvent::ConnectivityRestored));
        assert_eq!(port.recv(), Some(NetworkEvent::SystemDnsChanged));
        assert!(port.recv().is_none());
        assert_eq!(
            port.last_snapshot().primary_iface().map(String::as_str),
            Some("wg-mlt")
        );
    }

    /// 真机快照：能读、字段良构（不断言具体值——多环境可跑）
    #[test]
    fn live_snapshot_reads_real_state() {
        let snap = read_net_snapshot().expect("真机快照可读");
        for iface in &snap.default_ifaces {
            assert!(!iface.is_empty(), "接口名非空");
        }
        for dns in &snap.dns_servers {
            assert!(!dns.to_string().is_empty());
        }
    }

    // ---- 验收⑦：事务 prepare/apply/补偿/回滚 ----

    fn takeover_changes() -> Vec<SystemChange> {
        vec![
            SystemChange::new(
                "link:tun0",
                step_payload(&AppliedStep::LinkUp {
                    interface: "tun0".into(),
                }),
            ),
            SystemChange::new(
                "route:tun0",
                step_payload(&AppliedStep::RouteReplaced {
                    cidr: "10.66.0.0/24".into(),
                    interface: "tun0".into(),
                    metric: 0,
                }),
            ),
            SystemChange::new(
                "fwmark:escape",
                step_payload(&AppliedStep::FwmarkRule {
                    mark: TAKEOVER_FWMARK,
                    table: 100,
                }),
            ),
        ]
    }

    fn recording_executor() -> (StepExecutor, Arc<std::sync::Mutex<Vec<String>>>) {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log2 = log.clone();
        let exec: StepExecutor = Arc::new(move |argv: &[String]| {
            log2.lock().expect("锁").push(argv.join(" "));
            Ok(())
        });
        (exec, log)
    }

    /// prepare：载荷解析回 AppliedStep（计划=执行同源）；坏载荷零系统
    /// 改动且不污染后续正常 prepare
    #[test]
    fn transaction_prepare_parses_and_rejects_bad_payload() {
        let (exec, log) = recording_executor();
        let mut tx = LinuxRouteTransaction::new(exec);

        tx.prepare(takeover_changes()).expect("正常 prepare");
        assert!(tx.applied().is_empty(), "prepare 系统零改动");
        assert!(log.lock().expect("锁").is_empty(), "prepare 不执行任何命令");

        let err = tx
            .prepare(vec![SystemChange::new("bad", "rm -rf /")])
            .expect_err("未知载荷应拒");
        let chain = format!("{err:#}");
        assert!(chain.contains("未知变更载荷"), "错误链含根因: {chain}");
        assert!(chain.contains("id=bad"), "错误链含幂等键: {chain}");
        assert!(tx.applied().is_empty());

        // 数字字段坏 → 拒绝
        let bad_metric = "ip route replace 10.0.0.0/24 dev tun0 metric abc";
        tx.prepare(vec![SystemChange::new("m", bad_metric)])
            .expect_err("坏 metric 应拒");

        // 坏 prepare 不污染：正常 prepare 照常可用（最后一次为准）
        tx.prepare(takeover_changes()).expect("恢复 prepare");
        assert!(log.lock().expect("锁").is_empty());
    }

    /// apply：全部成功入账；失败逆序补偿本事务已应用步；fwmark rule
    /// EEXIST 按幂等成功
    #[test]
    fn transaction_apply_compensates_on_failure() {
        // 全成功
        let (exec, log) = recording_executor();
        let mut tx = LinuxRouteTransaction::new(exec);
        tx.prepare(takeover_changes()).expect("prepare");
        tx.apply().expect("apply");
        assert_eq!(tx.applied().len(), 3);
        let calls = log.lock().expect("锁");
        assert_eq!(calls.len(), 3);
        assert!(calls[0].starts_with("ip link set dev tun0 up"));
        assert!(calls[1].starts_with("ip route replace 10.66.0.0/24 dev tun0 metric 0"));
        assert!(calls[2].starts_with("ip rule add fwmark 24133 table 100"));
        drop(calls);

        // rollback 逆序撤销（fwmark del → route del → link down）
        tx.rollback().expect("rollback");
        let calls = log.lock().expect("锁")[3..].to_vec();
        assert_eq!(calls.len(), 3);
        assert!(
            calls[0].starts_with("ip rule del fwmark 24133 table 100"),
            "逆序: {calls:?}"
        );
        assert!(calls[1].starts_with("ip route del 10.66.0.0/24 dev tun0"));
        assert!(calls[2].starts_with("ip link set tun0 down"));
        drop(calls);
        // 幂等：重复回滚无操作
        tx.rollback().expect("重复回滚幂等");
        assert_eq!(log.lock().expect("锁").len(), 6);

        // 中途失败：第 2 步挂 → 第 1 步逆序补偿
        let fail_route = move |argv: &[String]| -> io::Result<()> {
            if argv.len() > 3 && argv[3] == "10.66.0.0/24" && argv[1] == "route" {
                return Err(io::Error::other(
                    "RTNETLINK answers: Network is unreachable",
                ));
            }
            Ok(())
        };
        let mut tx = LinuxRouteTransaction::new(Arc::new(fail_route));
        tx.prepare(takeover_changes()).expect("prepare");
        let err = tx.apply().expect_err("第 2 步失败应报");
        assert!(
            err.to_string().contains("RouteReplaced"),
            "报错点名步骤: {err}"
        );
        assert!(err.to_string().contains("1 步"), "报错携带补偿数: {err}");
        assert!(tx.applied().is_empty(), "失败步骤不入账");

        // fwmark rule EEXIST 幂等成功
        let eexist_fwmark = move |argv: &[String]| -> io::Result<()> {
            if argv.len() > 2 && argv[1] == "rule" {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "RTNETLINK answers: File exists",
                ));
            }
            Ok(())
        };
        let mut tx = LinuxRouteTransaction::new(Arc::new(eexist_fwmark));
        tx.prepare(takeover_changes()).expect("prepare");
        tx.apply().expect("EEXIST 按 fwmark 幂等成功");
        assert_eq!(tx.applied().len(), 3);
    }

    /// rollback 幂等口径：目标不存在视为已撤销；撤销真失败显式报错
    #[test]
    fn transaction_rollback_tolerates_missing_but_reports_failures() {
        // undo（argv 带 del/down）遇 NotFound → 容忍（幂等撤销）；apply
        // 面（replace/add/up）照常成功
        let del_missing = move |argv: &[String]| -> io::Result<()> {
            let is_undo = argv.iter().any(|a| a == "del" || a == "down");
            if is_undo {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "RTNETLINK answers: No such file or directory",
                ));
            }
            Ok(())
        };
        let mut tx = LinuxRouteTransaction::new(Arc::new(del_missing));
        tx.prepare(takeover_changes()).expect("prepare");
        tx.apply().expect("apply 全成功");
        tx.rollback().expect("目标不存在视为已撤销");
        tx.rollback().expect("重复回滚无操作");

        // undo 真失败（如权限）→ rollback 报错点名；apply 面不受影响
        let undo_fails = move |argv: &[String]| -> io::Result<()> {
            if argv.iter().any(|a| a == "down") {
                return Err(io::Error::other("Operation not permitted"));
            }
            Ok(())
        };
        let mut tx = LinuxRouteTransaction::new(Arc::new(undo_fails));
        tx.prepare(takeover_changes()).expect("prepare");
        tx.apply().expect("apply");
        let err = tx.rollback().expect_err("撤销真失败应报");
        assert!(
            err.to_string().contains("LinkUp"),
            "报错点名失败步骤: {err}"
        );
    }

    /// 端到端：捕获端口接事件端口独立可用（端口迁移完成面——契约四口
    /// 全部有 Linux 实现且可独立 mock/替换）
    #[test]
    fn all_four_ports_have_linux_implementations() {
        // CapturePort
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(v4_udp([10, 0, 0, 2], [8, 8, 8, 8], 40000, 53, &[1, 2, 3]))
            .expect("发送");
        let mut port = LinuxTakeoverPort::new(rx, 1500);
        assert!(matches!(
            port.recv().expect("捕获"),
            Some(CapturedInput::Packet(_))
        ));

        // SocketBypass（构造面；真打 mark 在上面 live 测）
        let _bypass = LinuxSocketBypass::with_default();

        // NetworkEvents
        let mut events = LinuxNetworkEvents::new(NetSnapshot::default());
        assert_eq!(
            events.refresh(NetSnapshot {
                default_ifaces: vec!["ens18".into()],
                dns_servers: Vec::new(),
            }),
            2,
            "从无到有：DefaultRouteChanged + ConnectivityRestored"
        );
        assert!(events.recv().is_some());

        // RouteTransaction
        let (exec, _log) = recording_executor();
        let mut tx = LinuxRouteTransaction::new(exec);
        tx.prepare(takeover_changes()).expect("prepare");
        assert!(tx.applied().is_empty());
    }
}
