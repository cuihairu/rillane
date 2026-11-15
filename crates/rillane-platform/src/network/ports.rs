//! 平台端口契约（RIL-004）：CapturePort、SocketBypass、NetworkEvents 与
//! RouteTransaction 的最小接口。新增端口先留在本模块（架构 §5 落点），
//! 不把所有方法堆进一个巨型 trait——Mihomo/sing-box 的平台接口仅作参照。
//!
//! 三条硬边界（RIL-004 验收）：
//! 1. packet 与 socket 输入分别建模（`CapturedInput` 两个变体、载荷不同），
//!    不共享一个笼统的「流量」类型；
//! 2. 契约零 OS 细节——只有 `IpAddr`/`SocketAddr`/不透明句柄，没有
//!    `RawFd`/`libc`/平台结构体；Linux TUN、移动 packetFlow、透明代理
//!    适配器（RIL-029/033/043）在实现侧各自映射；
//! 3. OS 细节不流入规则求值——rillane-routing 只依赖 rillane-config +
//!    rillane-core，本模块类型不出现在任何规则求值输入里。
//!
//! 同步最小面：trait 不绑定异步运行时，适配器自行包 async（tun.rs/
//! linux.rs 已是 async 面）。系统副作用的完整计划/补偿语义在 RIL-018
//! 展开，这里只钉住最小事务语义：apply 失败自动撤销本事务已应用步、
//! rollback 幂等、只撤销本实例修改。

use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
};

use anyhow::Result;

/// 进入内核的捕获输入（RIL-004）：packet 与 socket 分别建模。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturedInput {
    /// 包输入（TUN / 移动 packetFlow）：原始 L3 整包，内核负责解析重组
    Packet(PacketInput),
    /// 套接字输入（透明代理 REDIRECT/TPROXY、本机拨号）：已还原的五元组
    Socket(SocketInput),
}

/// 包输入载荷：整包字节 + 观察 IP 头元数据。零 OS 类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInput {
    /// 原始 L3 整包字节（含 IP 头）
    pub packet: Vec<u8>,
    /// IP 头元数据（适配器解析，避免规则求值重复解包）
    pub meta: PacketMeta,
}

/// 包输入元数据：网络中立三元组。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    /// 源地址
    pub src: IpAddr,
    /// 目的地址
    pub dst: IpAddr,
    /// IP 协议
    pub protocol: IpProtocol,
}

/// IP 协议（中立枚举；未建模协议走 `Other`，由规则求值按不支持处理）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// TCP
    Tcp,
    /// UDP（含 QUIC）
    Udp,
    /// ICMP
    Icmp,
    /// 未建模协议号
    Other(u8),
}

/// 套接字输入载荷：透明代理/本机入口已还原的五元组。与包输入不同，
/// 无需解析——直接给出会话两端。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketInput {
    /// 传输协议
    pub transport: TransportProtocol,
    /// 本地侧地址（REDIRECT/TPROXY 命中的本地 socket）
    pub local: SocketAddr,
    /// 原始目的地址（get_original_dst 还原）
    pub remote: SocketAddr,
}

/// 传输协议（套接字输入面只承载流式与数据报两种）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// TCP 流
    Tcp,
    /// UDP 数据报（含 QUIC）
    Udp,
}

/// 流量接管端口（RIL-004）：内核统一从这里取输入。Linux TUN（RIL-029）、
/// Windows Wintun（RIL-033）、移动 packetFlow（RIL-043）各自实现。
pub trait CapturePort: Send {
    /// 接收下一个捕获输入；`Ok(None)` = 端口已关闭、不再有输入。
    /// 实现不得自旋阻塞占用内核线程——同步面按就绪语义返回错误或
    /// 由适配器在 async 侧包装。
    fn recv(&mut self) -> std::io::Result<Option<CapturedInput>>;
}

/// 不透明 socket 句柄：适配器自有解释（Linux fd、Android protect 目标、
/// Windows socket 等）。契约层禁止把 fd 语义带进来（RIL-004 边界）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketHandle(pub(crate) u64);

impl SocketHandle {
    /// 构造句柄（适配器从自己的 socket 表示映射）
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// 数值口径（仅适配器实现侧使用；诊断输出不解释其含义）
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// 出站旁路（RIL-004）：把内核自己的出站 socket（代理拨号、DNS 上游）
/// 标记为绕过接管，防自环。Linux 对 SO_MARK 逃逸表（linux.rs auto-bypass
/// 集）、Android 对 VpnService.protect——契约只保留「标记一次 socket」
/// 这一最小面。
pub trait SocketBypass: Send {
    /// 标记该 socket 旁路接管。幂等：重复标记同一句柄无副作用。
    fn bypass(&self, socket: SocketHandle) -> Result<()>;
}

/// 网络事件（RIL-004）：宿主网络状态变化的最小事件面。切网恢复语义
/// （RIL-031/046）由各平台适配器产生，契约只钉事件种类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEvent {
    /// 默认路由/出口接口变化（Wi-Fi↔蜂窝、网卡切换）
    DefaultRouteChanged {
        /// 新出口接口名（None = 无默认路由）
        interface: Option<String>,
    },
    /// 网络连通性丢失
    ConnectivityLost,
    /// 网络连通性恢复
    ConnectivityRestored,
    /// 系统解析器变化（DNS 服务器列表变更）
    SystemDnsChanged,
}

/// 网络事件源（RIL-004）。
pub trait NetworkEvents: Send {
    /// 接收下一个事件；`None` = 事件流已关闭。
    fn recv(&mut self) -> Option<NetworkEvent>;
}

/// 单条系统副作用（RIL-004 最小建模）：幂等键 + 适配器自有载荷。契约
/// 不解释载荷——它只流向 [`RouteTransaction`] 的平台实现（nftables/WFP/
/// 路由表细节都在里面），绝不流入规则求值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemChange {
    /// 幂等键：撤销与对账按它识别（如 `route:default:eth0`、`nft:rillane/0`）
    pub id: String,
    /// 适配器自有载荷（变更的序列化规格；契约层不透明）
    pub payload: String,
}

impl SystemChange {
    /// 构造系统变更
    pub fn new(id: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            payload: payload.into(),
        }
    }
}

/// 系统副作用事务（RIL-004 最小面；完整计划/补偿与持久化在 RIL-018）：
/// prepare → apply →（可选）rollback。语义：
/// - prepare 只登记预检，失败时系统零改动；
/// - apply 任一步失败自动撤销**本事务**已应用步（补偿），不触碰其他
///   实例/其他事务的修改；
/// - rollback 撤销本事务已应用的全部变更，幂等（重复调用 `Ok(())`），
///   未 apply 的事务回滚为无操作。
pub trait RouteTransaction: Send {
    /// 预检并暂存变更（系统零改动）。重复 prepare 以最后一次为准。
    fn prepare(&mut self, changes: Vec<SystemChange>) -> Result<()>;

    /// 应用暂存的变更；失败自动补偿本事务已应用步并报错。
    fn apply(&mut self) -> Result<()>;

    /// 显式撤销本事务全部已应用变更（幂等）。
    fn rollback(&mut self) -> Result<()>;
}

/// 内存参考实现（契约测试/适配器对照）：钉住最小事务语义，也证明四个
/// trait 可实现、可 mock（RIL-004 交付面的一部分；真实 Linux 实现归
/// RIL-029/RIL-018）。
#[derive(Debug, Default)]
pub struct InMemoryRouteTransaction {
    staged: Vec<SystemChange>,
    applied: Vec<SystemChange>,
    closed: bool,
}

impl InMemoryRouteTransaction {
    /// 本事务已应用的变更（测试/对账观察面）
    pub fn applied(&self) -> &[SystemChange] {
        &self.applied
    }
}

impl RouteTransaction for InMemoryRouteTransaction {
    fn prepare(&mut self, changes: Vec<SystemChange>) -> Result<()> {
        if self.closed {
            anyhow::bail!("事务已回滚关闭");
        }
        self.staged = changes;
        Ok(())
    }

    fn apply(&mut self) -> Result<()> {
        if self.closed {
            anyhow::bail!("事务已回滚关闭");
        }
        if self.applied.is_empty() && self.staged.is_empty() {
            return Ok(()); // 无变更即无操作
        }
        // 参考实现按序全量应用；真实实现逐步应用、失败即补偿
        self.applied = self.staged.clone();
        self.staged.clear();
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        if self.closed {
            return Ok(()); // 幂等：重复回滚无操作
        }
        self.applied.clear();
        self.staged.clear();
        self.closed = true;
        Ok(())
    }
}

/// 内存事件源（契约测试用）：按序吐出事件后关闭。
#[derive(Debug, Default)]
pub struct InMemoryNetworkEvents {
    queue: VecDeque<NetworkEvent>,
}

impl InMemoryNetworkEvents {
    /// 构造内存事件源
    pub fn new(events: Vec<NetworkEvent>) -> Self {
        Self {
            queue: events.into(),
        }
    }
}

impl NetworkEvents for InMemoryNetworkEvents {
    fn recv(&mut self) -> Option<NetworkEvent> {
        self.queue.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_input() -> CapturedInput {
        CapturedInput::Packet(PacketInput {
            packet: vec![0x45, 0, 0, 0x14],
            meta: PacketMeta {
                src: "192.168.1.2".parse().unwrap(),
                dst: "1.1.1.1".parse().unwrap(),
                protocol: IpProtocol::Udp,
            },
        })
    }

    fn socket_input() -> CapturedInput {
        CapturedInput::Socket(SocketInput {
            transport: TransportProtocol::Tcp,
            local: "127.0.0.1:1200".parse().unwrap(),
            remote: "93.184.216.34:443".parse().unwrap(),
        })
    }

    #[test]
    fn packet_and_socket_inputs_modeled_separately() {
        // 验收：packet/socket 输入分别建模——穷尽匹配必须分别处理两类
        fn describe(input: &CapturedInput) -> &'static str {
            match input {
                CapturedInput::Packet(p) => {
                    // 包输入携带整包字节 + IP 元数据
                    assert!(!p.packet.is_empty());
                    "packet"
                }
                CapturedInput::Socket(s) => {
                    // 套接字输入直接携带五元组，无需解包
                    assert_eq!(s.transport, TransportProtocol::Tcp);
                    "socket"
                }
            }
        }
        assert_eq!(describe(&packet_input()), "packet");
        assert_eq!(describe(&socket_input()), "socket");
        assert_ne!(packet_input(), socket_input());
    }

    #[test]
    fn capture_port_mock_yields_then_closes() -> std::io::Result<()> {
        struct MockPort {
            queue: VecDeque<CapturedInput>,
        }
        impl CapturePort for MockPort {
            fn recv(&mut self) -> std::io::Result<Option<CapturedInput>> {
                Ok(self.queue.pop_front())
            }
        }
        let mut port = MockPort {
            queue: VecDeque::from(vec![packet_input(), socket_input()]),
        };
        assert!(port.recv()?.is_some());
        assert!(port.recv()?.is_some());
        assert!(port.recv()?.is_none(), "端口关闭后返回 None");
        Ok(())
    }

    #[test]
    fn socket_handle_is_opaque_no_os_types() -> anyhow::Result<()> {
        // 句柄是 u64 不透明值——不是 RawFd、不含平台结构
        let h = SocketHandle::new(42);
        assert_eq!(h.as_u64(), 42);
        struct MarkingBypass {
            marked: std::cell::RefCell<Vec<u64>>,
        }
        impl SocketBypass for MarkingBypass {
            fn bypass(&self, socket: SocketHandle) -> Result<()> {
                let mut marked = self.marked.borrow_mut();
                if !marked.contains(&socket.as_u64()) {
                    marked.push(socket.as_u64()); // 幂等
                }
                Ok(())
            }
        }
        let bypass = MarkingBypass {
            marked: std::cell::RefCell::new(vec![]),
        };
        bypass.bypass(h)?;
        bypass.bypass(h)?; // 重复标记无副作用
        assert_eq!(*bypass.marked.borrow(), vec![42]);
        Ok(())
    }

    #[test]
    fn network_events_minimal_surface() {
        let mut events = InMemoryNetworkEvents::new(vec![
            NetworkEvent::DefaultRouteChanged {
                interface: Some("wlan0".into()),
            },
            NetworkEvent::ConnectivityLost,
            NetworkEvent::ConnectivityRestored,
            NetworkEvent::SystemDnsChanged,
        ]);
        assert_eq!(
            events.recv().unwrap(),
            NetworkEvent::DefaultRouteChanged {
                interface: Some("wlan0".into())
            }
        );
        assert_eq!(events.recv(), Some(NetworkEvent::ConnectivityLost));
        assert_eq!(events.recv(), Some(NetworkEvent::ConnectivityRestored));
        assert_eq!(events.recv(), Some(NetworkEvent::SystemDnsChanged));
        assert_eq!(events.recv(), None, "事件流关闭");
    }

    #[test]
    fn route_transaction_minimal_semantics() -> anyhow::Result<()> {
        let mut tx = InMemoryRouteTransaction::default();
        // 未 apply 的回滚 = 无操作，且关闭事务
        tx.rollback()?;
        // 关闭后 prepare/apply 拒绝
        assert!(tx.prepare(vec![SystemChange::new("r1", "spec")]).is_err());

        let mut tx = InMemoryRouteTransaction::default();
        tx.prepare(vec![
            SystemChange::new("route:default:tun0", "via 10.0.0.1"),
            SystemChange::new("nft:rillane/0", "udp dport 53 tproxy"),
        ])?;
        assert!(tx.applied().is_empty(), "prepare 阶段系统零改动");
        tx.apply()?;
        assert_eq!(tx.applied().len(), 2);
        tx.rollback()?; // 撤销全部
        assert!(tx.applied().is_empty());
        tx.rollback()?; // 幂等
        Ok(())
    }
}
