//! UDP 中继契约：出站侧交付字节级 `UdpRelay`，会话表侧统一收口收发/指标/错误分类
//! （udp-relay-path.md §4：forwarder 归属表侧，出站保持"纯管道"）。

use crate::{FlowContext, FlowTarget, RouteDecision};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// 上游 → 客户端方向的下行包（入站侧封装 SOCKS5 UDP 头需要 target）
#[derive(Debug, Clone)]
pub struct DownlinkPacket {
    pub target: FlowTarget,
    pub data: Bytes,
}

/// 出站 UDP 关联的字节级句柄（udp-dataplane.md §1.2）。
#[async_trait]
pub trait UdpRelay: Send + Sync {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()>;
    /// 阻塞等待下一个上游数据报（forwarder task 中调用）
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)>;
}

/// 出站 UDP 连接器按粘滞路由决策选载体（udp-relay-path.md §3.4）：
/// 决策的最终节点决定用哪个出站连接器，保证同会话粘滞在同一出口。
pub struct RoutingUdpConnector {
    by_node: Mutex<HashMap<String, Arc<dyn EgressUdpConnector>>>,
}

impl RoutingUdpConnector {
    pub fn new() -> Self {
        Self {
            by_node: Mutex::new(HashMap::new()),
        }
    }

    /// 注册节点 → 连接器（构建期一次性填入，运行期只读）
    pub fn register(&self, node: String, connector: Arc<dyn EgressUdpConnector>) {
        self.by_node.lock().unwrap().insert(node, connector);
    }

    pub fn registered_nodes(&self) -> Vec<String> {
        self.by_node.lock().unwrap().keys().cloned().collect()
    }
}

impl Default for RoutingUdpConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EgressUdpConnector for RoutingUdpConnector {
    fn name(&self) -> &str {
        "routing"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        let node = decision.final_node();
        let connector = self
            .by_node
            .lock()
            .unwrap()
            .get(&node)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("节点 {node} 未注册 UDP 出站连接器（能力表扫描应在构建期拦截）")
            })?;
        connector.associate(ctx, decision).await
    }
}

/// direct 出站的本地已连接 socket 实现（udp-relay-path.md §3.2 + RIL-154）：
/// 拨号与运行期都按解析顺序逐地址回退——首个 connect 成功即用；运行期收到
/// connection 类内核错误（refused/unreachable：数据报已被内核判定未达对端
/// 端口）时按序切到下一解析地址，全失败则以显式错误回报完整尝试清单，
/// 不静默黑洞。UDP connect 几乎只查路由（有默认路由时坏地址也 connect
/// 成功），黑洞面在运行期由收发错误暴露，回退因此挂在收发两处。
pub struct LocalRelay {
    target: FlowTarget,
    /// 按解析顺序的完整地址表（回退游标上限；顺序即 getaddrinfo/RFC 6724 序）
    addrs: Vec<SocketAddr>,
    state: Mutex<RelayState>,
}

struct RelayState {
    socket: Arc<UdpSocket>,
    /// addrs 中当前活跃地址下标（只随回退成功推进）
    active: usize,
    /// 最近一次成功发出的数据报及其发送时的地址下标：下行侧回退时若该下标
    /// ≤ 被回退地址下标，补发——内核已判定其未达对端端口（refused/unreachable
    /// 是否定性证据），补发不构成重复投递；下标 pairing 排除并发回退时把已在
    /// 新地址正常发出的数据报误补发的面
    last_sent: Option<(usize, Arc<Vec<u8>>)>,
    /// 全地址穷尽后的显式错误（sticky：后续收发直接返回同一错误，不静默黑洞）
    exhausted: Option<String>,
    /// 逐次尝试记录（拨号 connect 失败 + 运行期回退失败），穷尽时随显式错误回报
    attempts: Vec<(SocketAddr, String)>,
}

/// 穷尽显式错误文本：目标点名 + 逐地址尝试清单。io 错误文案天然含
/// refused/unreachable → classify_failure 照旧归 Timeout（§3.2 映射保留）。
fn exhaustion_text(target: &FlowTarget, attempts: &[(SocketAddr, String)], head: &str) -> String {
    let list = attempts
        .iter()
        .enumerate()
        .map(|(i, (addr, err))| format!("[{i}] {addr}: {err}"))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{head}: 目标 {}:{} 共尝试 {} 个解析地址全部失败: {list}",
        target.host,
        target.port,
        attempts.len()
    )
}

/// connection 类内核错误（RIL-154 回退触发面）：UDP 已连接 socket 上这些
/// 错误来自 ICMP 回程（对端端口未达/网络不可达），数据报确定未投递。
/// Windows 的 WSAECONNRESET 以 ConnectionReset 呈现，同面纳入。
fn is_connection_class(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::NetworkDown
    )
}

/// 按地址族新建并 connect 的单地址拨号（bind 族随地址，与既有 §3.2 同法）
async fn dial_one(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

impl LocalRelay {
    /// 解析目标并拨号（RIL-154）：解析结果按序逐地址 connect，首个成功即用；
    /// 全部失败 → 显式错误携带尝试清单。
    pub async fn connect(target: &FlowTarget) -> Result<Self> {
        let addrs = resolve_all(&target.host, target.port).await?;
        Self::connect_addrs(target, addrs).await
    }

    /// 以给定地址表拨号（resolve_all 的注入点：测试固定地址顺序复现
    /// RFC 6724 首址布局，不依赖 hosts 文件排布）
    pub(crate) async fn connect_addrs(
        target: &FlowTarget,
        addrs: Vec<SocketAddr>,
    ) -> Result<Self> {
        if addrs.is_empty() {
            anyhow::bail!("目标解析失败: {}:{}（解析结果为空）", target.host, target.port);
        }
        let mut attempts: Vec<(SocketAddr, String)> = Vec::new();
        for (i, addr) in addrs.iter().enumerate() {
            match dial_one(*addr).await {
                Ok(socket) => {
                    return Ok(Self {
                        target: target.clone(),
                        addrs,
                        state: Mutex::new(RelayState {
                            socket: Arc::new(socket),
                            active: i,
                            last_sent: None,
                            exhausted: None,
                            attempts,
                        }),
                    });
                }
                Err(e) => attempts.push((*addr, format!("{e:#}"))),
            }
        }
        anyhow::bail!("{}", exhaustion_text(target, &attempts, "出口拨号失败"))
    }

    /// 当前活跃上游地址（观测面：粘滞与回退位置可见）
    pub fn active_addr(&self) -> SocketAddr {
        let st = self.state.lock().unwrap();
        self.addrs[st.active]
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.state.lock().unwrap().socket.local_addr()?)
    }

    /// connection 类错误后的按序回退（RIL-154）：把 active 推进到 act 之后
    /// 首个可连接地址；返回 (socket, 是否发生切换)——切换 = 本次把 active 从
    /// act 推进到了新地址，调用方可据此补发未达数据报；全部试尽 → Err
    /// （sticky 显式错误）。上行 send / 下行 recv 两任务并发触发时以 CAS
    /// 推进：仅当 active 仍为 act 才换 socket；败者（本错误来自已被换掉的
    /// 旧 socket）沿用胜者结果且不算切换。
    async fn recover(&self, act: usize, cause: &std::io::Error) -> Result<(Arc<UdpSocket>, bool)> {
        loop {
            {
                let st = self.state.lock().unwrap();
                if st.active > act {
                    return Ok((Arc::clone(&st.socket), false));
                }
                if let Some(text) = &st.exhausted {
                    anyhow::bail!("{text}");
                }
            }
            let mut attempts: Vec<(SocketAddr, String)> =
                vec![(self.addrs[act], format!("{cause:#}"))];
            let mut found: Option<(usize, Arc<UdpSocket>)> = None;
            for (i, addr) in self.addrs.iter().enumerate().skip(act + 1) {
                match dial_one(*addr).await {
                    Ok(socket) => {
                        found = Some((i, Arc::new(socket)));
                        break;
                    }
                    Err(e) => attempts.push((*addr, format!("{e:#}"))),
                }
            }
            let mut st = self.state.lock().unwrap();
            st.attempts.extend(attempts);
            match found {
                Some((i, socket)) if st.active == act => {
                    st.socket = Arc::clone(&socket);
                    st.active = i;
                    return Ok((socket, true));
                }
                Some(_) => {}                       // 他人已推进：弃本 socket 沿用当前
                None if st.active == act => {
                    // 全部试尽：sticky 显式错误（穷尽后仍带全量尝试清单）
                    let text = exhaustion_text(
                        &self.target,
                        &st.attempts,
                        "出口 UDP 面按序回退穷尽",
                    );
                    st.exhausted = Some(text.clone());
                    anyhow::bail!("{text}");
                }
                None => {}                          // 他人已推进：回循环顶部复查
            }
        }
    }
}

/// 解析目标全部地址（RIL-154）：保序去重交调用方逐地址拨号回退，
/// 不再取首地址（首址不可达即黑洞的面）
pub(crate) async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for addr in tokio::net::lookup_host((host, port)).await? {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    Ok(addrs)
}

/// direct 出站连接器（udp-relay-path.md §3.2）：每目标独立本地 UDP socket，
/// send 错误含 ConnectionRefused 归类 Timeout（§3.6），映射保留由空闲回收。
pub struct DirectUdpConnector;

#[async_trait]
impl EgressUdpConnector for DirectUdpConnector {
    fn name(&self) -> &str {
        "direct"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        Ok(Arc::new(LocalRelay::connect(&ctx.target).await?))
    }
}

#[async_trait]
impl UdpRelay for LocalRelay {
    async fn send_to(&self, _target: &FlowTarget, buf: &[u8]) -> Result<()> {
        // 已 connect：目标即构造时的 target（target 参数保留以统一 trait 签名）
        if let Some(text) = self.state.lock().unwrap().exhausted.clone() {
            anyhow::bail!("{text}");
        }
        loop {
            let (socket, act) = {
                let st = self.state.lock().unwrap();
                (Arc::clone(&st.socket), st.active)
            };
            match socket.send(buf).await {
                Ok(_) => {
                    self.state.lock().unwrap().last_sent = Some((act, Arc::new(buf.to_vec())));
                    return Ok(());
                }
                // connection 类：数据报确定未投递 → 按序回退后重发本数据报
                Err(e) if is_connection_class(&e) => {
                    self.recover(act, &e).await?;
                }
                Err(e) => return Err(anyhow::Error::from(e)),
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        if let Some(text) = self.state.lock().unwrap().exhausted.clone() {
            anyhow::bail!("{text}");
        }
        loop {
            let (socket, act) = {
                let st = self.state.lock().unwrap();
                (Arc::clone(&st.socket), st.active)
            };
            match socket.recv(buf).await {
                Ok(n) => return Ok((self.target.clone(), n)),
                Err(e) if is_connection_class(&e) => {
                    let (socket, switched) = self.recover(act, &e).await?;
                    // 下行侧回退（仅真实切换时）：错误对应一发数据报被内核判定
                    // 未达（refused/unreachable）；若最近一次发出发生在被回退
                    // 地址（下标 pairing），补发它，上行不静默丢失。补发若再遇
                    // connection 类错误，由下一轮 recv 的 pending 错误暴露并
                    // 继续回退，此处不吞错不放大。
                    if switched {
                        let last = self.state.lock().unwrap().last_sent.clone();
                        if let Some((sent_at, last)) = last {
                            if sent_at <= act {
                                let _ = socket.send(&last).await;
                            }
                        }
                    }
                }
                Err(e) => return Err(anyhow::Error::from(e)),
            }
        }
    }
}

impl fmt::Debug for LocalRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalRelay")
            .field("target", &self.target)
            .finish()
    }
}

/// reject 出站 UDP（G0-5 UDP 面，审核发现 2026-11-04）：拒绝语义 = 静默
/// 丢弃而非构建期判负——与 TCP `RejectFlowOutput` 断流对齐，广告/黑名单
/// 目标可拦截 UDP 而不阻塞整机构建。关联即返回 drop-only relay。
pub struct RejectUdpConnector;

#[async_trait]
impl EgressUdpConnector for RejectUdpConnector {
    fn name(&self) -> &str {
        "reject"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        Ok(Arc::new(RejectUdpRelay { target: ctx.target }))
    }
}

/// reject 出站 UDP relay：`send_to` 吞包（uplink 计 Sent），`recv_from`
/// 永久 pending（无下行源；downlink task 仅被取消时退出）。
pub struct RejectUdpRelay {
    target: FlowTarget,
}

#[async_trait]
impl UdpRelay for RejectUdpRelay {
    async fn send_to(&self, _target: &FlowTarget, _buf: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        std::future::pending().await
    }
}

impl fmt::Debug for RejectUdpRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectUdpRelay")
            .field("target", &self.target)
            .finish()
    }
}

/// 测试用可编程 relay：send 可注入失败；下行经返回的 mpsc sender 注入。
pub struct MockUdpRelay {
    target: FlowTarget,
    state: Mutex<MockState>,
    /// recv 需持锁跨 await，用 tokio Mutex（async_trait 的 Send future 约束）
    rx: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
}

struct MockState {
    sends: Vec<(FlowTarget, Vec<u8>)>,
    /// Some(消息) = 注入发送失败；消息措辞决定 classify_failure 的分类
    fail_msg: Option<String>,
}

impl MockUdpRelay {
    pub fn new(target: FlowTarget) -> (Arc<Self>, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(16);
        let relay = Arc::new(Self {
            target,
            state: Mutex::new(MockState {
                sends: Vec::new(),
                fail_msg: None,
            }),
            rx: AsyncMutex::new(rx),
        });
        (relay, tx)
    }

    /// 注入 Connection 类失败（默认）
    pub fn fail_sends(&self, on: bool) {
        self.fail_with(on.then(|| "mock send failure".to_string()));
    }

    /// 注入 Route 类失败（消息含 "route"）
    pub fn fail_route(&self, on: bool) {
        self.fail_with(on.then(|| "mock route failure".to_string()));
    }

    /// 注入 Timeout 类失败（消息含 "timeout"）
    pub fn fail_timeout(&self, on: bool) {
        self.fail_with(on.then(|| "mock timeout failure".to_string()));
    }

    /// 注入任意失败消息（措辞决定 classify_failure 的分类，如 wg 的
    /// "MTU 超限"/"allowed_ips" 关键词）
    pub fn fail_with(&self, msg: Option<String>) {
        self.state.lock().unwrap().fail_msg = msg;
    }

    pub fn clear_failures(&self) {
        self.state.lock().unwrap().fail_msg = None;
    }

    pub fn send_count(&self) -> usize {
        self.state.lock().unwrap().sends.len()
    }
}

#[async_trait]
impl UdpRelay for MockUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        if let Some(msg) = s.fail_msg.clone() {
            anyhow::bail!("{msg}");
        }
        s.sends.push((target.clone(), buf.to_vec()));
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut guard = self.rx.lock().await;
        let data = guard.recv().await;
        drop(guard);
        match data {
            Some(d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Ok((self.target.clone(), n))
            }
            None => anyhow::bail!("mock relay closed"),
        }
    }
}

impl fmt::Debug for MockUdpRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockUdpRelay")
            .field("target", &self.target)
            .finish()
    }
}

/// 出站 UDP 连接器（udp-dataplane.md §1.2 / udp-relay-path.md §3）。
/// 每次关联一个目标；实现方保证不缓存可跨目标复用的状态。
#[async_trait]
pub trait EgressUdpConnector: Send + Sync {
    fn name(&self) -> &str;
    /// UDP 能力标记：能力表扫描（udp-relay-path.md §3.1）构建期使用
    fn udp_capable(&self) -> bool {
        true
    }
    /// 关联一个出站 relay；`decision` 为会话的粘滞路由决策（relay-path §3.4），
    /// 实现方按其最终节点选承载，不重新路由（粘滞语义）
    async fn associate(
        &self,
        ctx: FlowContext,
        decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlowId, RouteDecision, TargetProto};
    use std::time::Duration;

    /// 回声对端：绑 127.0.0.1 随机口，收到的数据报原样回发源地址
    async fn spawn_udp_echo() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("回声 UDP 绑定");
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], src).await;
            }
        });
        addr
    }

    /// 摘一个当前无人监听的 UDP 口（bind 即弃）——其上收发将得到端口不可达
    fn reserve_dead_udp_port() -> u16 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("占位绑定");
        let p = s.local_addr().unwrap().port();
        drop(s);
        p
    }

    fn udp_target(host: &str, port: u16) -> FlowTarget {
        FlowTarget {
            host: host.into(),
            port,
            proto: TargetProto::Udp,
        }
    }

    /// reject UDP 面（G0-5，审核发现 2026-11-04）：关联成功返回 drop-only
    /// relay；`send_to` 吞包（Ok），`recv_from` 永久 pending——上行计 Sent、
    /// 下行无源不误发，与 TCP `RejectFlowOutput` 断流语义对齐。
    #[tokio::test]
    async fn reject_udp_connector_drops_sends_and_never_recvs() {
        let connector = RejectUdpConnector;
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "ads.example.com".into(),
                port: 53,
                proto: TargetProto::Udp,
            },
            metadata: Default::default(),
        };
        let decision = RouteDecision::direct("block-ads".into());
        let relay = connector
            .associate(ctx, &decision)
            .await
            .expect("reject 关联应成功");

        // send_to 吞包（静默丢弃）
        relay
            .send_to(
                &FlowTarget {
                    host: "ads.example.com".into(),
                    port: 53,
                    proto: TargetProto::Udp,
                },
                &[1, 2, 3],
            )
            .await
            .expect("reject 吞包应 Ok");

        // recv_from 永久 pending：select 带超时确认不产出数据
        let mut buf = [0u8; 8];
        let recv = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            relay.recv_from(&mut buf),
        )
        .await;
        assert!(recv.is_err(), "reject 下行应无数据（超时）");
    }

    /// RIL-154 拨号面：首个 connect 成功即用，同 relay 端到端往返
    #[tokio::test]
    async fn dial_uses_first_connectable_address_and_roundtrips() {
        let echo = spawn_udp_echo().await;
        let target = udp_target("dial-first.example.test", echo.port());
        let relay = LocalRelay::connect_addrs(&target, vec![echo])
            .await
            .expect("首地址可连接即用");
        assert_eq!(relay.active_addr(), echo, "首个 connect 成功地址即活跃面");

        relay.send_to(&target, b"ping").await.expect("上行");
        let mut buf = [0u8; 16];
        let (_, n) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
            .await
            .expect("往返不超时")
            .expect("下行");
        assert_eq!(&buf[..n], b"ping");
    }

    /// RIL-154 拨号回退：connect 失败的地址被跳过记录，后续地址接替；
    /// 全部失败 → 显式错误携带尝试清单（地址 + 逐条原因）
    #[tokio::test]
    async fn dial_falls_back_past_failed_connect_and_lists_attempts() {
        let echo = spawn_udp_echo().await;
        let target = udp_target("dial-fallback.example.test", echo.port());
        let dead = SocketAddr::from(([255, 255, 255, 255], 9)); // 广播地址 connect 被拒

        let relay = LocalRelay::connect_addrs(&target, vec![dead, echo])
            .await
            .expect("首址 connect 失败应回退到次址");
        assert_eq!(relay.active_addr(), echo, "活跃面应落在首个可连接地址");

        let err = LocalRelay::connect_addrs(&target, vec![dead])
            .await
            .expect_err("全部 connect 失败应显式报错");
        let text = format!("{err:#}");
        assert!(text.contains("出口拨号失败"), "穷尽错误应点名头部: {text}");
        assert!(
            text.contains(&dead.to_string()),
            "尝试清单应含失败地址: {text}"
        );
        assert!(
            text.contains("共尝试 1 个解析地址全部失败"),
            "尝试清单应带计数: {text}"
        );
    }

    /// RIL-154 事件复现：解析序 ::1 在前（RFC 6724 / hosts `::1 localhost`
    /// 布局）而对端只听 127.0.0.1——运行期 refused 回程触发按序回退 + 补发，
    /// localhost 级往返不再依赖 hosts 文件布局；无 IPv6 栈的机器上首址
    /// connect 直接失败落到 v4，本测同样通过（双布局确定性）。
    #[tokio::test]
    async fn rollover_heals_first_address_blackhole() {
        let echo = spawn_udp_echo().await;
        let v6_first = SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], echo.port())); // [::1]
        let target = udp_target("rollover.example.test", echo.port());
        let relay = LocalRelay::connect_addrs(&target, vec![v6_first, echo])
            .await
            .expect("拨号应按序回退完成");

        relay
            .send_to(&target, b"blackhole-probe")
            .await
            .expect("上行（首址黑洞由下行错误面暴露）");
        let mut buf = [0u8; 64];
        let (_, n) = tokio::time::timeout(Duration::from_secs(3), relay.recv_from(&mut buf))
            .await
            .expect("回退后往返不得超时（不静默黑洞）")
            .expect("下行应经回退面送达");
        assert_eq!(&buf[..n], b"blackhole-probe", "补发数据报应往返");
        assert_eq!(
            relay.active_addr(),
            echo,
            "活跃面应已切换到可达地址"
        );
    }

    /// RIL-154 穷尽面：所有解析地址运行期均 refused → 显式错误携带完整
    /// 尝试清单（地址 + 原因 + 计数），且 sticky——后续收发直接返回同一错误，
    /// 全程无静默黑洞（限时验证不挂起）。
    #[tokio::test]
    async fn rollover_exhaustion_is_explicit_with_attempt_list_and_sticky() {
        let p1 = reserve_dead_udp_port();
        let p2 = reserve_dead_udp_port();
        let a1 = SocketAddr::from(([127, 0, 0, 1], p1));
        let a2 = SocketAddr::from(([127, 0, 0, 1], p2));
        let target = udp_target("exhaust.example.test", 9999);
        let relay = LocalRelay::connect_addrs(&target, vec![a1, a2])
            .await
            .expect("无监听口 connect 仍成功（UDP connect 只查路由）");

        relay.send_to(&target, b"q").await.expect("首址发送面上 Ok");
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(3), relay.recv_from(&mut buf))
            .await
            .expect("穷尽必须显式报错而非挂起")
            .expect_err("全地址 refused 应穷尽显式报错");
        let text = format!("{err:#}");
        assert!(
            text.contains("出口 UDP 面按序回退穷尽"),
            "穷尽错误应点名头部: {text}"
        );
        assert!(text.contains(&a1.to_string()), "清单应含首址: {text}");
        assert!(text.contains(&a2.to_string()), "清单应含次址: {text}");
        assert!(
            text.contains("refused"),
            "io 文案 refused 保留（classify_failure 归 Timeout）: {text}"
        );
        assert!(
            text.contains("共尝试 2 个解析地址全部失败"),
            "清单应带全量计数: {text}"
        );

        // sticky：穷尽后收发直接返回同一显式错误，不再黑洞挂起
        let err2 = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
            .await
            .expect("sticky 错误即时返回")
            .expect_err("穷尽后 recv 显式报错");
        assert_eq!(format!("{err2:#}"), text, "sticky 错误保持同一口径");
        let send_err = tokio::time::timeout(Duration::from_secs(2), relay.send_to(&target, b"x"))
            .await
            .expect("sticky 错误即时返回")
            .expect_err("穷尽后 send 显式报错");
        assert_eq!(format!("{send_err:#}"), text, "sticky 错误保持同一口径");
    }

    /// RIL-154 验收面：真实解析入口（localhost，双栈解析）端到端往返，
    /// 不依赖 hosts 文件把哪个地址排在首——首址不可达时由运行期回退接替。
    #[tokio::test]
    async fn localhost_resolution_roundtrip_is_layout_independent() {
        let echo = spawn_udp_echo().await;
        let target = udp_target("localhost", echo.port());
        let relay = LocalRelay::connect(&target)
            .await
            .expect("localhost 解析拨号应成功");
        assert!(
            !relay.active_addr().ip().is_unspecified(),
            "活跃面应为具体解析地址"
        );

        relay.send_to(&target, b"layout-free").await.expect("上行");
        let mut buf = [0u8; 32];
        let (_, n) = tokio::time::timeout(Duration::from_secs(3), relay.recv_from(&mut buf))
            .await
            .expect("localhost 级往返不得依赖 hosts 布局（不静默黑洞）")
            .expect("下行");
        assert_eq!(&buf[..n], b"layout-free");
    }
}
