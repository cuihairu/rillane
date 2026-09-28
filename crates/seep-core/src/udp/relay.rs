//! UDP 中继契约：出站侧交付字节级 `UdpRelay`，会话表侧统一收口收发/指标/错误分类
//! （udp-relay-path.md §4：forwarder 归属表侧，出站保持"纯管道"）。

use crate::{FlowContext, FlowTarget};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
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

/// direct 出站的本地已连接 socket 实现（udp-relay-path.md §3.2）。
pub struct LocalRelay {
    socket: Arc<UdpSocket>,
    target: FlowTarget,
}

impl LocalRelay {
    /// 解析目标并 connect（域名取首个解析地址）
    pub async fn connect(target: &FlowTarget) -> Result<Self> {
        let addr = resolve_first(&target.host, target.port).await?;
        let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        Ok(Self { socket: Arc::new(socket), target: target.clone() })
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
        f.debug_struct("LocalRelay").field("target", &self.target).finish()
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
    fail_sends: bool,
}

impl MockUdpRelay {
    pub fn new(target: FlowTarget) -> (Arc<Self>, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(16);
        let relay = Arc::new(Self {
            target,
            state: Mutex::new(MockState { sends: Vec::new(), fail_sends: false }),
            rx: AsyncMutex::new(rx),
        });
        (relay, tx)
    }

    pub fn fail_sends(&self, on: bool) {
        self.state.lock().unwrap().fail_sends = on;
    }

    pub fn send_count(&self) -> usize {
        self.state.lock().unwrap().sends.len()
    }
}

#[async_trait]
impl UdpRelay for MockUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        if s.fail_sends {
            anyhow::bail!("mock send failure");
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
        f.debug_struct("MockUdpRelay").field("target", &self.target).finish()
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
    async fn associate(&self, ctx: FlowContext) -> Result<Box<dyn UdpRelay>>;
}
