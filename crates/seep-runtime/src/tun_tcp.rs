//! TUN TCP 用户态终结栈（tun-dataplane.md §2.4 / §2.9，T4）
//!
//! 模型（§2.4）：单 smoltcp `Interface`（phy = 包队列适配器）承载全部连接——
//! smoltcp 对本机应用扮演"对端"（应答 SYN-ACK/ACK/窗口），应用的 SYN 即主动
//! 接入。**连接归属唯一句柄**：smoltcp 被动开放须 `listen` 先行，而"每 TCP
//! 五元组一个 TcpSocket"在实现上= 端口监听句柄接生——首 SYN 到即按目的端口建
//! 监听（本端口唯一），SYN 绑定后该句柄即该五元组的连接 socket，同端口**立即
//! 补位新监听**续接下一个 SYN；监听表只收 `state == Listen` 的句柄，句柄在
//! 流表/监听表/退役列三者必居其一、互斥流转（详见 [`StackInner`]）。
//!
//! 驱动（§2.9 单 poll 驱动点 + 事件驱动，不另起独立定时任务）：
//! - 上行：run 循环读包 → [`TunTcpStack::ingest`]（喂 phy 队列 + `iface.poll` 一次）
//!   → poll 产出的下行段经 run 循环写 tun；
//! - 下行注入：egress 侧写 [`SmolTcpStream`] → 数据入 socket 发送缓冲 →
//!   `kick`（`tokio::sync::Notify`）唤醒 run 循环补一次 poll 出段；
//! - 定时推进（重传/延迟 ACK/关闭态收敛）：复用 run 循环既有 sweep 周期补 poll；
//! - waker：[`SmolTcpStream`] 的 AsyncRead/AsyncWrite 在 socket 不可立即满足时
//!   登记 tokio waker（smoltcp `register_*_waker`，cfg async），poll 推进状态后
//!   唤醒对应任务——无忙轮询。
//!
//! 交接（§2.4）：握手完成（Established）→ `Flow{id, target, io: SmolTcpStream,
//! metadata(+process 注解)}` → `output.forward(decision, flow)`，决策取自该流
//! 首 SYN 的粘滞缓存（[`TcpFlow::decision`]）；缓存缺档（seep 中途重启后接入）
//! 时在交接点兜底路由。
//!
//! 与设计稿的实施偏差（§6 口径，已注明）：
//! - 监听句柄接生代替字面"每五元组预建"——smoltcp 无按五元组预绑定 API，
//!   监听+补位在语义上等价（句柄归属唯一）；
//! - Nagle 关闭（低延迟面，游戏长连接敏感同 §2.4 keep-alive 关闭口径）；
//! - `max_flows` 同口径限新连接接入（超限丢 SYN，防 SYN 洪泛无界膨胀）。

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll as TaskPoll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use seep_core::RouteDecision;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{self, SocketBuffer, State},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tracing::debug;

use crate::tun_process::ProcessInfo;

/// 缓冲下限（§2.4：缓冲按 tun MTU−40−20；极小 MTU 时保底可用窗口）
const MIN_SOCKET_BUF: usize = 512;

/// TCP 流键（五元组的 app/server 两半——与 UDP 面同为全量键）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    /// 本机应用侧（首 SYN 源 = 归因/标注面）
    pub app: SocketAddr,
    /// 目标服务器侧（首 SYN 目的 = FlowTarget 面）
    pub server: SocketAddr,
}

/// TCP 流条目（首 SYN 起册；句柄在流表期间归属唯一连接）
struct TcpFlow {
    key: TcpFlowKey,
    /// 首 SYN 粘滞路由决策（None = 缺档，Established 交接时兜底路由）
    decision: Option<RouteDecision>,
    /// 首 SYN 进程归因（has_process_rules=false 时恒 None）
    process: Option<ProcessInfo>,
    /// 已交接（Established 检出即置位，防重复交接）
    handed_off: bool,
    /// 空闲触达（SYN 入册/交接检出/桥接读写续期；sweep 按此回收）
    last_active: Instant,
}

/// Established 待交接（run 循环从栈内检出 → TunIngress 走 route/forward 面）
pub struct EstablishedTcp {
    pub handle: SocketHandle,
    pub key: TcpFlowKey,
    pub decision: Option<RouteDecision>,
    pub process: Option<ProcessInfo>,
}

/// 一次 poll 的产物：下行段（→ run 循环写 tun）+ 新交接清单
#[derive(Default)]
pub struct TcpOutcome {
    pub tx_packets: Vec<Bytes>,
    pub established: Vec<EstablishedTcp>,
}

/// phy 适配器（§2.9：包队列 → smoltcp RxToken/TxToken；TxToken 期间累积发信面，
/// 由调用方在 await 环境出队——TxToken::consume 是同步回调，不能直写 tun）
struct TunPhy {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
    caps: DeviceCapabilities,
}

struct PhyRxToken {
    data: Bytes,
}

impl RxToken for PhyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.data)
    }
}

struct PhyTxToken<'a> {
    tx: &'a mut VecDeque<Bytes>,
}

impl TxToken for PhyTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.push_back(Bytes::from(buf));
        r
    }
}

impl Device for TunPhy {
    type RxToken<'a>
        = PhyRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PhyTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let data = self.rx.pop_front()?;
        Some((PhyRxToken { data }, PhyTxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(PhyTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

/// 栈内部状态（单把 std 互斥锁短持——全同步、不跨 await；桥接面与 run 循环共锁）
///
/// 句柄三态互斥流转：
/// - `listeners`：端口 → 监听句柄（只收 `state == Listen`——离 Listen 即刻摘除）
/// - `flows`：句柄 → 流条目（SYN 入册；Established 检出置 handed_off；
///   撤条目后句柄进 `retiring`）
/// - `retiring`：已关待收敛句柄（对端不 ACK FIN 的慢收敛跨 sweep 周期清；
///   `!is_open()` 即从 SocketSet 移除——只有 GC 出口移除句柄，防悬垂 handle）
struct StackInner {
    iface: Interface,
    device: TunPhy,
    sockets: SocketSet<'static>,
    listeners: HashMap<u16, SocketHandle>,
    flows: HashMap<SocketHandle, TcpFlow>,
    retiring: Vec<SocketHandle>,
    /// 每 socket 收发缓冲（§2.4 tun MTU−40−20，下限保底）
    buf_size: usize,
}

impl StackInner {
    /// 端口监听接生：已有监听直取；否则新建（本端口唯一监听句柄）
    fn add_listener(&mut self, port: u16) -> Result<SocketHandle> {
        if let Some(h) = self.listeners.get(&port) {
            return Ok(*h);
        }
        let mut s = tcp::Socket::new(
            SocketBuffer::new(vec![0u8; self.buf_size]),
            SocketBuffer::new(vec![0u8; self.buf_size]),
        );
        // 游戏低延迟面：小写立即出段；keep-alive 保持 smoltcp 默认关闭（§2.4）
        s.set_nagle_enabled(false);
        s.listen(port)
            .map_err(|e| anyhow!("TCP listen({port}) 失败：{e:?}"))?;
        let h = self.sockets.add(s);
        self.listeners.insert(port, h);
        Ok(h)
    }

    /// 撤条目 + 关 socket + 进退役列（句柄有效前提：条目在撤前存在——
    /// 「had」口径防「sweep 先手 + GC 已收敛」的悬垂 get_mut）
    fn teardown_handle(&mut self, handle: SocketHandle) -> bool {
        let had = self.flows.remove(&handle).is_some();
        if self.retiring.contains(&handle) || !had {
            return false;
        }
        let s = self.sockets.get_mut::<tcp::Socket>(handle);
        if s.is_open() {
            s.close();
        }
        self.retiring.push(handle);
        true
    }
}

/// 单 poll 驱动点（§2.9）：入栈包与定时器一次推进 → 监听离听检测 →
/// Established 交接检出 → 退役收敛 → 发信面出队
fn run_locked(inner: &mut StackInner) -> TcpOutcome {
    inner
        .iface
        .poll(SmolInstant::now(), &mut inner.device, &mut inner.sockets);

    // ① 监听句柄离 Listen → 归属连接（凭端点补建缺档条目）+ 同端口立即补位
    let departed: Vec<(u16, SocketHandle)> = inner
        .listeners
        .iter()
        .filter(|(_, h)| inner.sockets.get::<tcp::Socket>(**h).state() != State::Listen)
        .map(|(p, h)| (*p, *h))
        .collect();
    for (port, h) in departed {
        inner.listeners.remove(&port);
        if let Err(e) = inner.add_listener(port) {
            debug!(target: "seep::tun", port, error = %e, "TCP 补位监听失败（本端口暂不可接新连接）");
        }
        if inner.flows.contains_key(&h) {
            continue; // 首 SYN 已入册（正常路径）
        }
        // 中途接入（seep 重启/首 SYN 缺档）：凭连接端点补建条目，决策空缺
        // → Established 交接时兜底路由（§2.4 粘滞缓存的反向兜底）
        let (local, remote) = {
            let s = inner.sockets.get::<tcp::Socket>(h);
            (s.local_endpoint(), s.remote_endpoint())
        };
        if let (Some(local), Some(remote)) = (local, remote) {
            let (local, remote): (SocketAddr, SocketAddr) = (local.into(), remote.into());
            inner.flows.insert(
                h,
                TcpFlow {
                    key: TcpFlowKey {
                        app: remote,
                        server: local,
                    },
                    decision: None,
                    process: None,
                    handed_off: true,
                    last_active: Instant::now(),
                },
            );
        } else {
            // 无端点的异常态句柄：直接退役收敛
            let s = inner.sockets.get_mut::<tcp::Socket>(h);
            if s.is_open() {
                s.close();
            }
            if !inner.retiring.contains(&h) {
                inner.retiring.push(h);
            }
        }
    }

    // ② Established 未交接 → 交接清单（每句柄检出一次）
    let now = Instant::now();
    let mut established = Vec::new();
    for (h, f) in inner.flows.iter_mut() {
        if !f.handed_off && inner.sockets.get::<tcp::Socket>(*h).state() == State::Established {
            f.handed_off = true;
            f.last_active = now;
            established.push(EstablishedTcp {
                handle: *h,
                key: f.key,
                decision: f.decision.clone(),
                process: f.process.clone(),
            });
        }
    }

    // ③ 退役句柄收敛（!is_open 含 Closed/TimeWait——GC 唯一移除出口）
    let mut keep = Vec::with_capacity(inner.retiring.len());
    for h in std::mem::take(&mut inner.retiring) {
        if inner.sockets.get::<tcp::Socket>(h).is_open() {
            keep.push(h);
        } else {
            inner.sockets.remove(h);
        }
    }
    inner.retiring = keep;

    // ④ 发信面出队（调用方写 tun 或测试通道）
    let mut tx_packets = Vec::new();
    while let Some(p) = inner.device.tx.pop_front() {
        tx_packets.push(p);
    }
    TcpOutcome {
        tx_packets,
        established,
    }
}

/// TUN TCP 用户态栈（§2.4/§2.9）：run 循环与转发桥接面（[`SmolTcpStream`]）
/// 共享的句柄持有者
pub struct TunTcpStack {
    inner: StdMutex<StackInner>,
    kick: Notify,
}

impl TunTcpStack {
    /// 创建栈（纯用户态——不触碰 TUN 设备；I/O 在 TunIngress run 循环）
    ///
    /// `local`：tun 本端 (地址, 前缀)——回程路由此此查（应用源地址 on-link）；
    /// 另恒压 `0.0.0.0/0` 兜底（任意源应用地址可达；栈只回客户端方向包）。
    pub fn new(local: Option<(Ipv4Addr, u8)>, mtu: u16) -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip; // TUN IFF_NO_PI：纯 IP 媒质无以太头
        caps.max_transmission_unit = usize::from(mtu);
        let mut device = TunPhy {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            caps,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        // ISN 随机种子（防端口/序号碰撞——Config 文档强烈建议）
        config.random_seed = uuid::Uuid::new_v4().as_u128() as u64;
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        // AnyIP：TUN 上行目的 = 应用原始连接目标（任意公网地址）→ 须全数
        // 视作本机收包（has_ip_addr any_ip 恒真；§2.4 应用 SYN 即主动接入）
        iface.set_any_ip(true);
        iface.update_ip_addrs(|ips| {
            if let Some((addr, prefix)) = local {
                let _ = ips.push(IpCidr::new(
                    IpAddress::from(std::net::IpAddr::V4(addr)),
                    prefix,
                ));
            }
            let _ = ips.push(IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0));
        });
        let buf_size = usize::from(mtu).saturating_sub(40 + 20).max(MIN_SOCKET_BUF);
        Self {
            inner: StdMutex::new(StackInner {
                iface,
                device,
                sockets: SocketSet::new(vec![]),
                listeners: HashMap::new(),
                flows: HashMap::new(),
                retiring: Vec::new(),
                buf_size,
            }),
            kick: Notify::new(),
        }
    }

    /// 下行注入唤醒面（§2.9：SmolTcpStream 写入后唤醒 run 循环补 poll）
    pub fn kick_notify(&self) -> &Notify {
        &self.kick
    }

    /// 活跃 TCP 流数（T5 seep_tun_flows_active 源之一）
    pub fn active_count(&self) -> usize {
        self.inner.lock().unwrap().flows.len()
    }

    /// 五元组已有条目？（SYN 重传判定——决策粘滞不重路由）
    pub fn has_flow(&self, key: &TcpFlowKey) -> bool {
        self.inner
            .lock()
            .unwrap()
            .flows
            .values()
            .any(|f| f.key == *key)
    }

    /// 首 SYN 入栈：监听接生 + 粘滞决策入册 + 喂包 + poll（§2.4 决策取首 SYN）
    pub fn ingest_syn(
        &self,
        pkt: Bytes,
        key: TcpFlowKey,
        decision: RouteDecision,
        process: Option<ProcessInfo>,
    ) -> Result<TcpOutcome> {
        let mut inner = self.inner.lock().unwrap();
        let h = inner.add_listener(key.server.port())?;
        inner.flows.insert(
            h,
            TcpFlow {
                key,
                decision: Some(decision),
                process,
                handed_off: false,
                last_active: Instant::now(),
            },
        );
        inner.device.rx.push_back(pkt);
        Ok(run_locked(&mut inner))
    }

    /// 常规包入栈（SYN 重传 / 握手中途 / 中途接入）：防御性确保目的端口
    /// 有监听——接不上连接的（无首 SYN 缓存）由 smoltcp 按 RFC 回 RST 收口
    pub fn ingest(&self, pkt: Bytes, server_port: u16) -> Result<TcpOutcome> {
        let mut inner = self.inner.lock().unwrap();
        inner.add_listener(server_port)?;
        inner.device.rx.push_back(pkt);
        Ok(run_locked(&mut inner))
    }

    /// 补 poll（run 循环 TcpKick/Sweep 臂；测试直驱同路径）
    pub fn drive(&self) -> TcpOutcome {
        let mut inner = self.inner.lock().unwrap();
        run_locked(&mut inner)
    }

    /// 空闲清扫：超龄条目撤除 + 关 socket（已交接连接的桥接面随 EOF 退场，
    /// forward 任务终局再走 retire 收敛句柄）
    pub fn sweep(&self, idle: Duration) -> u64 {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let expired: Vec<SocketHandle> = inner
            .flows
            .iter()
            .filter(|(_, f)| now.saturating_duration_since(f.last_active) >= idle)
            .map(|(h, _)| *h)
            .collect();
        let n = expired.len() as u64;
        for h in expired {
            if inner.teardown_handle(h) {
                debug!(target: "seep::tun", handle = ?h, "TCP 流空闲过期回收");
            }
        }
        n
    }

    /// 交接夭折（兜底路由失败/输出未注入）：撤条目 + 关 socket（应用侧收 FIN/RST）
    pub fn abort(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock().unwrap();
        inner.teardown_handle(handle);
        self.kick.notify_one(); // 关段需 poll 出队
    }

    /// forward 任务终局：撤条目 + 关 socket + 退役句柄（桥接面已随 Flow 消亡）
    pub fn retire(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock().unwrap();
        inner.teardown_handle(handle);
        self.kick.notify_one();
    }

    /// teardown：全量关闭（应用连接随 EOF 退场；设备即将销毁不再出段）
    pub fn shutdown_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        // 句柄先收集：MutexGuard 不支持字段分裂借用，drain 迭代不可与
        // sockets 变更并发（借用面收窄为语句内）
        let handles: Vec<SocketHandle> = inner.flows.drain().map(|(h, _)| h).collect();
        for h in handles {
            let s = inner.sockets.get_mut::<tcp::Socket>(h);
            if s.is_open() {
                s.close();
            }
        }
        inner.listeners.clear();
        inner.retiring.clear();
        inner.device.rx.clear();
        inner.device.tx.clear();
    }
}

/// smoltcp socket ↔ tokio `IoStream` 适配（§2.4 SmolTcpStream：双缓冲 + waker）
///
/// 桥接面在锁内短持访问 socket（读缓冲/写缓冲/登记 waker），不跨 await；
/// 读方向数据到达/状态变化、写方向缓冲腾位由 smoltcp 在 poll 中唤醒登记的
/// waker；写入后 `kick` 唤醒 run 循环补 poll 出段（§2.9 下行注入面）。
pub struct SmolTcpStream {
    stack: Arc<TunTcpStack>,
    handle: SocketHandle,
}

impl SmolTcpStream {
    pub fn new(stack: Arc<TunTcpStack>, handle: SocketHandle) -> Self {
        Self { stack, handle }
    }

    /// 条目已撤（sweep 回收/retire 收敛）= 该流已拆除——读侧视为 EOF、
    /// 写侧视为管道破裂
    fn flow_live(&self, inner: &StackInner) -> bool {
        inner.flows.contains_key(&self.handle)
    }
}

impl AsyncRead for SmolTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> TaskPoll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock().unwrap();
        if !this.flow_live(&inner) {
            return TaskPoll::Ready(Ok(())); // 拆除 → EOF
        }
        let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        let n = {
            let unfilled = buf.initialize_unfilled();
            s.recv_slice(unfilled)
        };
        match n {
            Ok(0) => {
                // 缓冲空 → 登记读 waker（数据到达/状态变化时 poll 唤醒）
                s.register_recv_waker(cx.waker());
                TaskPoll::Pending
            }
            Ok(n) => {
                buf.advance(n);
                if let Some(f) = inner.flows.get_mut(&this.handle) {
                    f.last_active = Instant::now();
                }
                TaskPoll::Ready(Ok(()))
            }
            // FIN 且缓冲已尽（recv 面保证先读完再报 Finished）→ EOF
            Err(tcp::RecvError::Finished) => TaskPoll::Ready(Ok(())),
            Err(e) => TaskPoll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }
}

impl AsyncWrite for SmolTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> TaskPoll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock().unwrap();
        if !this.flow_live(&inner) {
            return TaskPoll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        match s.send_slice(buf) {
            Ok(0) => {
                // 发送缓冲满 → 登记写 waker + kick 补 poll（出段腾位后唤醒）
                s.register_send_waker(cx.waker());
                drop(inner);
                this.stack.kick.notify_one();
                TaskPoll::Pending
            }
            Ok(n) => {
                if let Some(f) = inner.flows.get_mut(&this.handle) {
                    f.last_active = Instant::now();
                }
                drop(inner);
                // 数据须经 poll 出段 → 唤醒 run 循环（§2.9 下行注入）
                this.stack.kick.notify_one();
                TaskPoll::Ready(Ok(n))
            }
            Err(e) => TaskPoll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> TaskPoll<io::Result<()>> {
        // 数据已入 smoltcp 发送缓冲（poll_write 内已 kick 出段）——出段/ACK
        // 面不在此等（AsyncWrite flush 只要求应用缓冲排空）
        TaskPoll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> TaskPoll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock().unwrap();
        if this.flow_live(&inner) {
            let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
            if s.is_open() {
                s.close(); // 发 FIN（对端应用收到半关读侧 EOF）
            }
        }
        drop(inner);
        this.stack.kick.notify_one();
        TaskPoll::Ready(Ok(()))
    }
}

impl Drop for SmolTcpStream {
    fn drop(&mut self) {
        // forward 终局（Flow 消亡）→ 关 socket 走 FIN 收敛；句柄移除归
        // forward 任务的 retire（本 Drop 先于其执行）
        let mut inner = self.stack.inner.lock().unwrap();
        if self.flow_live(&inner) {
            let s = inner.sockets.get_mut::<tcp::Socket>(self.handle);
            if s.is_open() {
                s.close();
            }
        }
        drop(inner);
        self.stack.kick.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_platform::network::ipcodec::{build_tcp_packet, parse_tcp_segment, TcpFlags};

    #[allow(clippy::too_many_arguments)]
    fn uplink(
        src: &str,
        dst: &str,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Bytes {
        let pkt = build_tcp_packet(
            src.parse().unwrap(),
            dst.parse().unwrap(),
            sport,
            dport,
            seq,
            ack,
            flags,
            payload,
        )
        .expect("build tcp");
        Bytes::from(pkt)
    }

    /// §4.1 无特权栈面：首 SYN → 监听接生 + SYN-ACK 下行段；补位监听续接
    /// 第二连接；ACK 完成握手 → Established 检出（只检出一次）
    #[test]
    fn stack_syn_handshake_and_established_detection() {
        let stack = TunTcpStack::new(None, 1500);
        let key1 = TcpFlowKey {
            app: "10.66.0.1:40000".parse().unwrap(),
            server: "203.0.113.10:8080".parse().unwrap(),
        };

        // ① 首 SYN：入册 + 下行 SYN-ACK
        let out = stack
            .ingest_syn(
                uplink(
                    "10.66.0.1",
                    "203.0.113.10",
                    40000,
                    8080,
                    1000,
                    0,
                    TcpFlags::SYN,
                    b"",
                ),
                key1,
                RouteDecision::direct("n1".into()),
                None,
            )
            .expect("ingest_syn");
        assert_eq!(out.established.len(), 0, "SYN 阶段不应检出 Established");
        assert_eq!(out.tx_packets.len(), 1, "应有 SYN-ACK 下行段");
        let synack = parse_tcp_segment(&out.tx_packets[0]).expect("parse");
        assert!(synack.syn && synack.ack);
        assert_eq!(synack.sport, 8080);
        assert_eq!(synack.dport, 40000);
        assert_eq!(synack.ack_seq, 1001, "SYN 占 1 序号");

        // ② 同端口第二 SYN：补位监听独立接生（句柄互不串）
        let key2 = TcpFlowKey {
            app: "10.66.0.1:40001".parse().unwrap(),
            server: "203.0.113.10:8080".parse().unwrap(),
        };
        let out2 = stack
            .ingest_syn(
                uplink(
                    "10.66.0.1",
                    "203.0.113.10",
                    40001,
                    8080,
                    2000,
                    0,
                    TcpFlags::SYN,
                    b"",
                ),
                key2,
                RouteDecision::direct("n2".into()),
                None,
            )
            .expect("ingest_syn 2");
        assert_eq!(out2.tx_packets.len(), 1);
        assert_eq!(stack.active_count(), 2, "两条流独立在册");

        // ③ 第一连接 ACK → Established 检出（且仅一次）
        let ack1 = uplink(
            "10.66.0.1",
            "203.0.113.10",
            40000,
            8080,
            1001,
            synack.seq + 1,
            TcpFlags::ACK,
            b"",
        );
        let out3 = stack.ingest(ack1, 8080).expect("ingest ack");
        assert_eq!(out3.established.len(), 1, "应检出一条 Established");
        let est = &out3.established[0];
        assert_eq!(est.key, key1);
        assert!(est.decision.is_some(), "首 SYN 粘滞决策应随行");
        let out4 = stack.drive();
        assert_eq!(out4.established.len(), 0, "重复 drive 不重复检出");

        // ④ 已有条目判定（SYN 重传口径）
        assert!(stack.has_flow(&key1));
        assert!(!stack.has_flow(&TcpFlowKey {
            app: "10.66.0.1:49999".parse().unwrap(),
            server: "203.0.113.10:8080".parse().unwrap(),
        }));

        // ⑤ 清扫：ZERO 即全数超龄撤除（句柄退役收敛）
        assert_eq!(stack.sweep(Duration::ZERO), 2);
        assert_eq!(stack.active_count(), 0);
    }
}
