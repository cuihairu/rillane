//! Windows 接管面（RIL-033 代码面首段交付）：路由/DNS 事务与快照解析的
//! **OS-free 决策层**——在 Linux 验证席上确定性可测（执行器可注入，
//! 解析器吃真机文本形状的夹具）。真机 IO 面（wireguard-nt 会话、
//! `route print` / `netsh` 真读、socket 旁路真绑定）归 win_net.rs
//! （cfg windows，跨编译检查验证；运行期证据待真机——imac 主 /
//! openclaw 备，SSH 授权面待恢复；验收「真实浏览器/游戏流进入共享
//! 内核，DNS/代理拨号不循环，失败可补偿」的真机证据归机批次）。
//!
//! 形状对齐（RIL-032 探针结论的承接）：
//! - **无自代理环原语**：RIL-032 在 imac 实证「出站 socket 显式 bind
//!   物理口 IP 后同目标全程钉在物理口」——[`escape_bind_ip`] 即该
//!   原语的计划面（主默认路由接口地址）；真绑定在 win_net.rs；
//! - **事务补偿**：[`WinRouteTransaction`] 镜像 LinuxRouteTransaction
//!   语义（prepare 零系统改动 / apply 失败逆序补偿 / rollback 幂等，
//!   EEXIST 容忍仅 route add）——载荷 = argv 空格序列，「计划 = 执行」
//!   同源无第二构造路径；
//! - **事件映射**：[`WinNetSnapshot::diff_events`] 与 Linux NetSnapshot
//!   同配对纪律（Change / Lost 成对 / Restored 成对，路由事件在前、
//!   DNS 独立殿后；一次迁移一事件，不下游双反应）。Windows 身份 = 接口
//!   地址（`route print` 无接口名列——名身份不可得，地址身份确定性
//!   等价且 v4/v6 同构）；
//! - **DNS 还原边界**：DnsHijack 撤销 = `source=dhcp`（还原 DHCP 提供
//!   的解析器）；接管前静态配置的原文还原归 recovery 快照面（Linux
//!   addr replace undo=del 同一边界注记，不冒充无损）。
//!
//! 命令口径（现代 Windows，RIL-032 实测环境同代）：`route add/delete`
//! 与 `netsh interface ip set dnsservers`；文本解析吃 `route print -4/-6`
//! 与 `netsh interface ip show dnsservers` 的真机输出形状。

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};

use super::ports::{NetworkEvent, RouteTransaction, SystemChange};

// ---------------------------------------------------------------------------
// 步骤形状（argv / undo / 载荷同源）
// ---------------------------------------------------------------------------

/// 已执行的 Windows 接管步骤——apply 逆序撤销的事实源（与 Linux
/// AppliedStep 同构：argv() 正向、undo_argv() 撤销、eexist_ok 幂等口径）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinAppliedStep {
    /// `route add <destination> mask <mask> <gateway> metric <m> if <idx>`
    /// （include 路由与默认路由劫持同形；route add 重复添加报
    /// "The object already exists" → eexist 视为已生效）
    RouteAdded {
        destination: String,
        mask: String,
        gateway: String,
        metric: u32,
        interface_index: u32,
    },
    /// `netsh interface ip set dnsservers name=<iface> source=static
    /// address=<addr> register=primary validate=no`（DNS 劫持到本地
    /// 监听）；撤销 = source=dhcp 还原 DHCP 解析器（静态原文还原归
    /// recovery 快照面——同 Linux addr undo=del 边界）
    DnsHijack { interface: String, address: IpAddr },
}

impl WinAppliedStep {
    /// 正向执行 argv（apply 执行与载荷渲染共用——planner 只拼步骤，
    /// argv 从步骤还原保证「计划 = 执行」无第二构造路径）
    pub fn argv(&self) -> Vec<String> {
        match self {
            WinAppliedStep::RouteAdded {
                destination,
                mask,
                gateway,
                metric,
                interface_index,
            } => vec![
                "route".into(),
                "add".into(),
                destination.clone(),
                "mask".into(),
                mask.clone(),
                gateway.clone(),
                "metric".into(),
                metric.to_string(),
                "if".into(),
                interface_index.to_string(),
            ],
            WinAppliedStep::DnsHijack { interface, address } => vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "set".into(),
                "dnsservers".into(),
                format!("name={interface}"),
                "source=static".into(),
                format!("address={address}"),
                "register=primary".into(),
                "validate=no".into(),
            ],
        }
    }

    /// 逆序撤销 argv（rollback 与 apply 中途补偿共用）
    pub fn undo_argv(&self) -> Vec<String> {
        match self {
            WinAppliedStep::RouteAdded {
                destination,
                mask,
                interface_index,
                ..
            } => vec![
                "route".into(),
                "delete".into(),
                destination.clone(),
                "mask".into(),
                mask.clone(),
                "if".into(),
                interface_index.to_string(),
            ],
            WinAppliedStep::DnsHijack { interface, .. } => vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "set".into(),
                "dnsservers".into(),
                format!("name={interface}"),
                "source=dhcp".into(),
                "validate=no".into(),
            ],
        }
    }

    /// EEXIST 是否视为成功（仅 `route add`——重复添加报 The object
    /// already exists 即路由已生效，幂等语义；netsh set 天然幂等无
    /// eexist 面）
    pub fn eexist_ok(&self) -> bool {
        matches!(self, WinAppliedStep::RouteAdded { .. })
    }
}

/// WinAppliedStep → 变更载荷（argv 空格序列——「计划 = 执行」同源）
pub fn win_step_payload(step: &WinAppliedStep) -> String {
    step.argv().join(" ")
}

/// 变更载荷 → WinAppliedStep（形状不符显式拒绝——prepare 系统零改动
/// 的前提是载荷先可解释）
pub fn parse_win_step_payload(payload: &str) -> Result<WinAppliedStep> {
    let argv: Vec<&str> = payload.split_whitespace().collect();
    let bad = || anyhow::anyhow!("未知 Windows 变更载荷: {payload}");
    Ok(match argv.as_slice() {
        ["route", "add", destination, "mask", mask, gateway, "metric", metric, "if", index] => {
            WinAppliedStep::RouteAdded {
                destination: (*destination).to_string(),
                mask: (*mask).to_string(),
                gateway: (*gateway).to_string(),
                metric: metric.parse().map_err(|_| bad())?,
                interface_index: index.parse().map_err(|_| bad())?,
            }
        }
        ["netsh", "interface", "ip", "set", "dnsservers", name, "source=static", address, "register=primary", "validate=no"] =>
        {
            let interface = name.strip_prefix("name=").ok_or_else(bad)?.to_string();
            let address: IpAddr = address
                .strip_prefix("address=")
                .ok_or_else(bad)?
                .parse()
                .map_err(|_| bad())?;
            WinAppliedStep::DnsHijack { interface, address }
        }
        _ => return Err(bad()),
    })
}

// ---------------------------------------------------------------------------
// 事务（镜像 LinuxRouteTransaction 语义）
// ---------------------------------------------------------------------------

/// 步骤执行器（事务可注入面；真实现 win_net.rs `win_step_executor`）
pub type WinStepExecutor = Arc<dyn Fn(&[String]) -> io::Result<()> + Send + Sync>;

/// Windows 路由/DNS 事务（RIL-004 RouteTransaction 实现）：与 Linux
/// 同一纪律——prepare 只解析载荷零系统改动；apply 逐步执行、失败逆序
/// 补偿本事务已应用步（route add 的 EEXIST 按幂等成功）；rollback 逆序
/// 撤销、目标不存在视为已撤销（幂等）、重复回滚无操作。
#[derive(Clone)]
pub struct WinRouteTransaction {
    exec: WinStepExecutor,
    staged: Vec<WinAppliedStep>,
    applied: Vec<WinAppliedStep>,
    closed: bool,
}

impl WinRouteTransaction {
    /// 注入执行器构造
    pub fn new(exec: WinStepExecutor) -> Self {
        Self {
            exec,
            staged: Vec::new(),
            applied: Vec::new(),
            closed: false,
        }
    }

    /// 已应用步骤（测试/对账观察面）
    pub fn applied(&self) -> &[WinAppliedStep] {
        &self.applied
    }

    /// 逆序撤销一批步骤；目标不存在视为已撤销。返回 (已撤销数, 未消化
    /// 失败)。
    fn undo_all(&self, steps: &[WinAppliedStep]) -> (usize, Vec<String>) {
        let mut undone = 0usize;
        let mut failures = Vec::new();
        for step in steps.iter().rev() {
            if let Err(e) = (self.exec)(&step.undo_argv()) {
                if is_missing(&e) {
                    undone += 1;
                    continue;
                }
                failures.push(format!("{step:?}: {e}"));
            } else {
                undone += 1;
            }
        }
        (undone, failures)
    }
}

impl RouteTransaction for WinRouteTransaction {
    fn prepare(&mut self, changes: Vec<SystemChange>) -> Result<()> {
        if self.closed {
            anyhow::bail!("事务已回滚关闭");
        }
        let mut staged = Vec::with_capacity(changes.len());
        for change in &changes {
            staged.push(
                parse_win_step_payload(&change.payload)
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
                    anyhow::bail!("步骤 {step:?} 应用失败: {e}；已逆序补偿回滚 {undone} 步");
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

/// EEXIST 口径（route add 重复添加的两种真机文本：The object already
/// exists / Element already exists；win_recovery 重放路径复用）
pub fn is_eexist(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::AlreadyExists
        || e.to_string().contains("already exists")
        || e.to_string().contains("Already exists")
}

/// 撤销幂等口径：目标不存在（route delete 未命中 / 接口已无）视为已
/// 撤销——rollback 幂等的机制面（真机文本：The route deletion failed:
/// The element could not be found / Element not found / The system
/// cannot find the file specified；win_recovery 撤销路径复用）
pub fn is_missing(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
        || e.to_string().contains("could not be found")
        || e.to_string().contains("not found")
        || e.to_string().contains("cannot find")
        || e.to_string().contains("cannot be found")
}

// ---------------------------------------------------------------------------
// 快照（route print / netsh 解析 + 事件映射）
// ---------------------------------------------------------------------------

/// 单条默认路由（Windows 身份三件：网关 / 接口地址 / 度量）。接口名
/// 不可得（route print 无名列）——接口地址即身份（确定性等价）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinDefaultRoute {
    /// 网关地址（v6 行可能带 %zone 后缀——zone 剥离，接口地址已承载
    /// 接口身份）
    pub gateway: IpAddr,
    /// 接口地址（身份列）
    pub interface: IpAddr,
    /// 度量（route print 输出序即优先序——低者优先，序保持不过重排）
    pub metric: u32,
    /// 接口索引（v6 行首列 If 有值；v4 行无 → None）
    pub if_index: Option<u32>,
}

/// Windows 网络快照（[`super::takeover::NetSnapshot`] 的 Windows 同构；
/// takeover 模块 cfg linux 门控——Windows 面自带形状避免跨门控引用）。
pub struct WinNetSnapshot {
    /// 默认路由序（route print 输出序 = 系统优先序；空 = 无默认路由）
    pub default_routes: Vec<WinDefaultRoute>,
    /// 全接口解析器地址序（netsh dnsservers 逐接口按输出序拼接）
    pub dns_servers: Vec<IpAddr>,
}

impl WinNetSnapshot {
    /// 主出口身份（首条默认路由的接口地址；None = 无默认路由）
    pub fn primary_iface_id(&self) -> Option<String> {
        self.default_routes.first().map(|r| r.interface.to_string())
    }

    /// 旁路原语计划面（RIL-032 实证：出站 socket 显式 bind 物理口 IP
    /// 后不被 TUN 捕获——本函数给「绑哪个 IP」的确定性答案；真绑定
    /// 在 win_net.rs）。无默认路由 = None（不猜物理口）。
    pub fn escape_bind_ip(&self) -> Option<IpAddr> {
        self.default_routes.first().map(|r| r.interface)
    }

    /// 差分 → 网络事件（self = 新，prev = 旧）。与 Linux NetSnapshot
    /// 同配对纪律：
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
        let new_primary = self.primary_iface_id();
        match (prev.primary_iface_id(), new_primary) {
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

/// 解析 `route print -4` 输出的默认路由（IPv4 表 Active Routes 段：
/// 五列 `Network Destination Netmask Gateway Interface Metric`，仅收
/// `0.0.0.0 0.0.0.0` 行；表头/分隔线/Interface List/持久路由段/
/// Default gateway 尾行全部忽略；输出序 = 系统优先序不过重排）。
pub fn parse_route_print_ipv4(text: &str) -> Vec<WinDefaultRoute> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() != 5 {
                return None;
            }
            if cols[0] != "0.0.0.0" || cols[1] != "0.0.0.0" {
                return None;
            }
            // 表头行本身也是 5 列文本（Network/Netmask/Gateway/Interface/
            // Metric）——后三列必须可解析才收（表头不 parse，自然滤除）
            let gateway: IpAddr = cols[2].parse().ok()?;
            let interface: IpAddr = cols[3].parse().ok()?;
            let metric: u32 = cols[4].parse().ok()?;
            Some(WinDefaultRoute {
                gateway,
                interface,
                metric,
                if_index: None,
            })
        })
        .collect()
}

/// IPv6 默认路由行（`route print -6` 的 `::/0` 行）。IPv6 表无接口
/// 地址列——If 索引即接口身份；接口地址归 win_net.rs 组合面（真机
/// 按 If 索引查 Get-NetIPAddress），此处只承载行本身的事实。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinV6DefaultRoute {
    /// If 列（接口索引——Windows v6 侧的接口身份）
    pub if_index: u32,
    /// Metric 列
    pub metric: u32,
    /// 网关（`%zone` 后缀剥离——zone 是作用域号，接口身份由 if_index
    /// 承载）
    pub gateway: IpAddr,
}

/// 解析 `route print -6` 输出的默认路由（IPv6 表 Active Routes 段：
/// 四列 `If Metric Network Destination Gateway`，仅收目的 `::/0` 行；
/// 表头/分隔线/其他目的行忽略；解析失败行跳过不猜）。
pub fn parse_route_print_ipv6(text: &str) -> Vec<WinV6DefaultRoute> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // 表头也是四列（If/Metric/Network Destination/Gateway）——
            // 数字列必须可解析才收
            if cols.len() != 4 || cols[2] != "::/0" {
                return None;
            }
            Some(WinV6DefaultRoute {
                if_index: cols[0].parse().ok()?,
                metric: cols[1].parse().ok()?,
                gateway: cols[3].split('%').next()?.parse().ok()?,
            })
        })
        .collect()
}

/// 解析 `netsh interface ip show dnsservers` 输出：逐接口配置块收集
/// 解析器地址（静态与 DHCP 提供两形状同收——快照只关心当下生效的
/// 解析器序）。真机两形状：首服务器跟在标签行后（`…DNS Servers:
/// 192.168.5.1` / `…through DHCP: 192.168.5.1`），后续服务器独占缩进行
/// ——整行 parse 优先，失败再取末个冒号后的 token 尝试；标签/`none`
/// /后缀注册行不产出假地址（冒号后非 IP 自然滤除）；输出序保真。
pub fn parse_netsh_dnsservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let t = line.trim();
            if let Ok(ip) = t.parse::<IpAddr>() {
                return Some(ip);
            }
            t.rsplit_once(':')?.1.trim().parse::<IpAddr>().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn route_step() -> WinAppliedStep {
        WinAppliedStep::RouteAdded {
            destination: "198.18.0.0".into(),
            mask: "255.254.0.0".into(),
            gateway: "192.168.5.1".into(),
            metric: 5,
            interface_index: 12,
        }
    }

    fn dns_step() -> WinAppliedStep {
        WinAppliedStep::DnsHijack {
            interface: "Wi-Fi".into(),
            address: "127.0.0.1".parse().unwrap(),
        }
    }

    /// 记录 argv 序的假执行器（可编程第 n 次失败）
    type RecordedCalls = Arc<std::sync::Mutex<Vec<Vec<String>>>>;

    fn recording_exec(
        fail_at: Option<usize>,
    ) -> (WinStepExecutor, RecordedCalls, Arc<AtomicUsize>) {
        let calls: Arc<std::sync::Mutex<Vec<Vec<String>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls2 = calls.clone();
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let exec: WinStepExecutor = Arc::new(move |argv: &[String]| {
            let i = n2.fetch_add(1, Ordering::SeqCst);
            calls2.lock().unwrap().push(argv.to_vec());
            if Some(i) == fail_at {
                return Err(io::Error::other("拒绝执行（注入失败）"));
            }
            Ok(())
        });
        (exec, calls, n)
    }

    // ---- 步骤形状（argv / undo / 载荷同源）----

    #[test]
    fn win_step_roundtrip_and_undo_shapes() {
        let r = route_step();
        assert_eq!(
            r.argv(),
            vec![
                "route",
                "add",
                "198.18.0.0",
                "mask",
                "255.254.0.0",
                "192.168.5.1",
                "metric",
                "5",
                "if",
                "12"
            ]
        );
        assert_eq!(
            r.undo_argv(),
            vec![
                "route",
                "delete",
                "198.18.0.0",
                "mask",
                "255.254.0.0",
                "if",
                "12"
            ]
        );
        assert!(r.eexist_ok());

        let d = dns_step();
        assert_eq!(
            d.argv(),
            vec![
                "netsh",
                "interface",
                "ip",
                "set",
                "dnsservers",
                "name=Wi-Fi",
                "source=static",
                "address=127.0.0.1",
                "register=primary",
                "validate=no"
            ]
        );
        assert_eq!(
            d.undo_argv(),
            vec![
                "netsh",
                "interface",
                "ip",
                "set",
                "dnsservers",
                "name=Wi-Fi",
                "source=dhcp",
                "validate=no"
            ]
        );
        assert!(!d.eexist_ok());

        // 载荷同源往返：「计划 = 执行」无第二构造路径
        for s in [route_step(), dns_step()] {
            let payload = win_step_payload(&s);
            assert_eq!(parse_win_step_payload(&payload).unwrap(), s);
        }
        // 形状不符显式拒绝（ip 面载荷不是 Windows 形状）
        assert!(parse_win_step_payload("ip route replace default dev eth0 table 100").is_err());
        assert!(parse_win_step_payload("route add broken").is_err());
    }

    // ---- 事务（镜像 LinuxRouteTransaction 语义）----

    #[test]
    fn win_transaction_prepare_zero_change_and_apply_order() {
        let (exec, calls, _n) = recording_exec(None);
        let mut tx = WinRouteTransaction::new(exec.clone());
        let changes = vec![
            SystemChange {
                id: "route:include:198.18.0.0/10".into(),
                payload: win_step_payload(&route_step()),
            },
            SystemChange {
                id: "dns:hijack:Wi-Fi".into(),
                payload: win_step_payload(&dns_step()),
            },
        ];
        // prepare 零系统改动（执行器零调用）
        tx.prepare(changes.clone()).unwrap();
        assert!(calls.lock().unwrap().is_empty());
        // apply 按暂存序执行，argv 与步骤同源
        tx.apply().unwrap();
        let done = calls.lock().unwrap();
        assert_eq!(done.len(), 2);
        assert_eq!(done[0], route_step().argv());
        assert_eq!(done[1], dns_step().argv());
        drop(done);
        assert_eq!(tx.applied(), &[route_step(), dns_step()]);
        // prepare 载荷不可解释 → Err 且零系统改动
        let mut tx2 = WinRouteTransaction::new(exec.clone());
        tx2.prepare(vec![SystemChange {
            id: "bad".into(),
            payload: "netsh interface ip set dns name=X source=static address=nonsense".into(),
        }])
        .unwrap_err();
        assert_eq!(calls.lock().unwrap().len(), 2); // 仍只有首轮 apply 的两次
    }

    #[test]
    fn win_transaction_apply_failure_compensates_in_reverse() {
        // 第 2 步（DNS 劫持）失败 → 已执行的 route add 被逆序补偿
        let (exec, calls, _n) = recording_exec(Some(1));
        let mut tx = WinRouteTransaction::new(exec);
        tx.prepare(vec![
            SystemChange {
                id: "route".into(),
                payload: win_step_payload(&route_step()),
            },
            SystemChange {
                id: "dns".into(),
                payload: win_step_payload(&dns_step()),
            },
        ])
        .unwrap();
        let err = tx.apply().unwrap_err();
        assert!(err.to_string().contains("逆序补偿回滚 1 步"), "{err}");
        let done = calls.lock().unwrap();
        assert_eq!(done.len(), 3);
        assert_eq!(done[0], route_step().argv()); // apply
        assert_eq!(done[1], dns_step().argv()); // apply 失败
        assert_eq!(done[2], route_step().undo_argv()); // 补偿
    }

    #[test]
    fn win_transaction_eexist_tolerated_for_route_add_only() {
        // route add 报 "The object already exists" → 幂等成功
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls2 = calls.clone();
        let exec: WinStepExecutor = Arc::new(move |argv: &[String]| {
            calls2.lock().unwrap().push(argv.to_vec());
            Err(io::Error::other("The object already exists."))
        });
        let mut tx = WinRouteTransaction::new(exec);
        tx.prepare(vec![SystemChange {
            id: "route".into(),
            payload: win_step_payload(&route_step()),
        }])
        .unwrap();
        tx.apply().unwrap();
        assert_eq!(tx.applied(), &[route_step()]);

        // DnsHijack 无 eexist 面：同样报错必须失败并报补偿
        let exec2: WinStepExecutor =
            Arc::new(|_: &[String]| Err(io::Error::other("The object already exists.")));
        let mut tx2 = WinRouteTransaction::new(exec2);
        tx2.prepare(vec![SystemChange {
            id: "dns".into(),
            payload: win_step_payload(&dns_step()),
        }])
        .unwrap();
        assert!(tx2.apply().is_err());
    }

    #[test]
    fn win_transaction_rollback_idempotent_and_missing_as_undone() {
        let (exec, calls, _n) = recording_exec(None);
        let mut tx = WinRouteTransaction::new(exec);
        tx.prepare(vec![
            SystemChange {
                id: "route".into(),
                payload: win_step_payload(&route_step()),
            },
            SystemChange {
                id: "dns".into(),
                payload: win_step_payload(&dns_step()),
            },
        ])
        .unwrap();
        tx.apply().unwrap();
        tx.rollback().unwrap();
        // 撤销逆序：DNS 先、路由后
        {
            let done = calls.lock().unwrap();
            assert_eq!(done.len(), 4);
            assert_eq!(done[2], dns_step().undo_argv());
            assert_eq!(done[3], route_step().undo_argv());
        }
        // 重复回滚无操作（幂等）
        tx.rollback().unwrap();
        assert_eq!(calls.lock().unwrap().len(), 4);
        // 关闭后 prepare/apply 拒绝
        assert!(tx.prepare(vec![]).is_err());
        assert!(tx.apply().is_err());

        // 撤销目标不存在（Element not found）→ 视为已撤销，不报错
        let exec2: WinStepExecutor = Arc::new(|argv: &[String]| {
            if argv[0] == "route" && argv[1] == "delete" {
                Err(io::Error::other(
                    "The route deletion failed: The element could not be found.",
                ))
            } else {
                Ok(())
            }
        });
        let mut tx3 = WinRouteTransaction::new(exec2);
        tx3.prepare(vec![SystemChange {
            id: "route".into(),
            payload: win_step_payload(&route_step()),
        }])
        .unwrap();
        tx3.apply().unwrap();
        tx3.rollback().unwrap(); // missing-as-undone
    }

    // ---- 快照解析（真机文本形状夹具）----

    #[test]
    fn win_route_print_ipv4_parsing_scopes_sections_and_order() {
        let fixture = "\
===========================================================================
Interface List
 12...xx xx xx xx xx xx ......Realtek PCIe GbE Family Controller
  1...........................Loopback Pseudo-Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.5.1    192.168.5.117     25
          0.0.0.0          0.0.0.0     192.168.6.1    192.168.6.14      35
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
     192.168.5.0    255.255.255.0         On-link     192.168.5.117    281
===========================================================================
Persistent Routes:
  None

Default gateway:      192.168.5.1
===========================================================================";
        let routes = parse_route_print_ipv4(fixture);
        assert_eq!(routes.len(), 2, "仅 0.0.0.0/0 行；输出序=优先序不过重排");
        assert_eq!(routes[0].gateway, "192.168.5.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            routes[0].interface,
            "192.168.5.117".parse::<IpAddr>().unwrap()
        );
        assert_eq!(routes[0].metric, 25);
        assert_eq!(routes[0].if_index, None);
        assert_eq!(routes[1].gateway, "192.168.6.1".parse::<IpAddr>().unwrap());
        // On-link 行不是 5 列可解析形状（网关列 On-link 不 parse）自然滤除
        // —— 隐含于 len==2；表头/Interface List/持久路由段同样滤除
    }

    #[test]
    fn win_route_print_ipv6_parsing_strips_zone() {
        let fixture = "\
If        Metric Network Destination      Gateway
 1     331 ::1/128                  On-link
12       25 ::/0                    fe80::1%12
12      281 2001:db8:1::/64          On-link
 9       35 ::/0                    2001:db8:ffff::1";
        let routes = parse_route_print_ipv6(fixture);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].if_index, 12);
        assert_eq!(routes[0].metric, 25);
        assert_eq!(
            routes[0].gateway,
            "fe80::1".parse::<IpAddr>().unwrap(),
            "%zone 剥离"
        );
        assert_eq!(routes[1].if_index, 9);
        assert_eq!(
            routes[1].gateway,
            "2001:db8:ffff::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn win_netsh_dnsservers_parsing_static_dhcp_and_none() {
        let fixture = "

Configuration for interface \"Wi-Fi\"
    Statically Configured DNS Servers: 192.168.5.1
        10.0.0.53
    Register with which suffix:        Primary only
    Subnet prefix:                     (none)

Configuration for interface \"以太网\"
    DNS servers configured through DHCP: 192.168.5.1
        Register with which suffix:        Primary only";
        assert_eq!(
            parse_netsh_dnsservers(fixture),
            vec![
                "192.168.5.1".parse::<IpAddr>().unwrap(),
                "10.0.0.53".parse::<IpAddr>().unwrap(),
                "192.168.5.1".parse::<IpAddr>().unwrap(),
            ],
            "静态与 DHCP 两形状同收；none/表头/标签行自然滤除；序保真"
        );
        assert!(
            parse_netsh_dnsservers("Configuration for interface \"X\"\n    (none)\n").is_empty()
        );
    }

    // ---- 事件差分（与 Linux NetSnapshot 同配对纪律）----

    fn snap(iface: Option<&str>, dns: &[&str]) -> WinNetSnapshot {
        let default_routes = iface
            .map(|ip| {
                vec![WinDefaultRoute {
                    gateway: "192.168.5.1".parse().unwrap(),
                    interface: ip.parse().unwrap(),
                    metric: 25,
                    if_index: None,
                }]
            })
            .unwrap_or_default();
        WinNetSnapshot {
            default_routes,
            dns_servers: dns.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn win_snapshot_diff_events_pairing_matches_linux_discipline() {
        // 无变化 → 零事件（一次迁移一事件，不下游双反应）
        let a = snap(Some("192.168.5.117"), &["192.168.5.1"]);
        assert!(a.diff_events(&a).is_empty());

        // 主出口变换（Some a → Some b）：单事件 Change{b}
        let b = snap(Some("192.168.6.14"), &["192.168.5.1"]);
        assert_eq!(
            b.diff_events(&a),
            vec![NetworkEvent::DefaultRouteChanged {
                interface: Some("192.168.6.14".into())
            }]
        );

        // 主出口丢失（Some → None）：Change{None} + Lost 成对（DNS 序
        // 不变——纯路由丢失场景）
        let lost = snap(None, &["192.168.5.1"]);
        assert_eq!(
            lost.diff_events(&a),
            vec![
                NetworkEvent::DefaultRouteChanged { interface: None },
                NetworkEvent::ConnectivityLost,
            ]
        );

        // 主出口恢复（None → Some）：Change{b} + Restored 成对
        assert_eq!(
            a.diff_events(&lost),
            vec![
                NetworkEvent::DefaultRouteChanged {
                    interface: Some("192.168.5.117".into())
                },
                NetworkEvent::ConnectivityRestored,
            ]
        );

        // 解析器序变化：独立 SystemDnsChanged（路由不变则仅此一件）
        let dns_changed = snap(Some("192.168.5.117"), &["10.0.0.53"]);
        assert_eq!(
            dns_changed.diff_events(&a),
            vec![NetworkEvent::SystemDnsChanged]
        );

        // 路由 + 解析器同变：路由事件在前、DNS 殿后
        let both = snap(Some("192.168.6.14"), &["10.0.0.53"]);
        assert_eq!(
            both.diff_events(&a),
            vec![
                NetworkEvent::DefaultRouteChanged {
                    interface: Some("192.168.6.14".into())
                },
                NetworkEvent::SystemDnsChanged,
            ]
        );
    }

    #[test]
    fn win_snapshot_escape_bind_ip_and_primary_identity() {
        let s = snap(Some("192.168.5.117"), &["192.168.5.1"]);
        assert_eq!(s.primary_iface_id().as_deref(), Some("192.168.5.117"));
        // 旁路原语计划面 = 主默认路由接口地址（RIL-032 imac 实证原语的输入）
        assert_eq!(s.escape_bind_ip(), Some("192.168.5.117".parse().unwrap()));
        // 无默认路由不猜物理口
        let lost = snap(None, &[]);
        assert_eq!(lost.escape_bind_ip(), None);
        assert_eq!(lost.primary_iface_id(), None);
    }
}
