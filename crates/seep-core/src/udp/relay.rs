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

/// direct 出站的本地已连接 socket 实现（udp-relay-path.md §3.2）。
pub struct LocalRelay {
    socket: Arc<UdpSocket>,
    target: FlowTarget,
}

impl LocalRelay {
    /// 解析目标并 connect（域名取首个解析地址）
    pub async fn connect(target: &FlowTarget) -> Result<Self> {
        let addr = resolve_first(&target.host, target.port).await?;
        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            target: target.clone(),
        })
    }

    pub fn from_connected(socket: Arc<UdpSocket>, target: FlowTarget) -> Self {
        Self { socket, target }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

pub(crate) async fn resolve_first(host: &str, port: u16) -> Result<SocketAddr> {
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("目标解析失败: {host}:{port}"))?;
    Ok(addr)
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
        Ok(self.socket.send(buf).await.map(|_| ())?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let n = self.socket.recv(buf).await?;
        Ok((self.target.clone(), n))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlowId, RouteDecision, TargetProto};

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
