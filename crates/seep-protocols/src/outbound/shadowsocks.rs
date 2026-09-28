//! Shadowsocks 出口连接器实现（TCP 面 + UDP 面，udp-relay-path.md §3.3）

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use seep_core::udp::{EgressUdpConnector, UdpRelay};
use seep_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::SharedContext,
    crypto::CipherKind,
    relay::tcprelay::proxy_stream::ProxyClientStream,
    relay::udprelay::ProxySocket,
    relay::Address,
    ServerAddr,
};
use std::sync::Arc;

/// Shadowsocks 出口连接器
pub struct ShadowsocksConnector {
    server: String,
    method: String,
    context: SharedContext,
    server_config: ServerConfig,
}

impl ShadowsocksConnector {
    pub fn new(server: String, port: u16, method: String, password: String) -> Result<Self> {
        let context = shadowsocks::context::Context::new_shared(ServerType::Local);
        // 加密方法校验提前到构建期（udp-relay-path.md §3.1 能力扫描同口径：
        // 配置错误在启动时暴露，而非首个连接时）
        let server_config = Self::build_server_config(&server, port, &method, &password)?;

        Ok(Self {
            server,
            method,
            context,
            server_config,
        })
    }

    fn build_server_config(
        server: &str,
        port: u16,
        method: &str,
        password: &str,
    ) -> Result<ServerConfig> {
        let cipher = method
            .parse::<CipherKind>()
            .map_err(|_| anyhow!("不支持的加密方法: {method}"))?;
        let addr = ServerAddr::DomainName(server.to_string(), port);
        Ok(ServerConfig::new(addr, password.to_string(), cipher)?)
    }

    fn server_config(&self) -> &ServerConfig {
        &self.server_config
    }
}

#[async_trait]
impl EgressConnector for ShadowsocksConnector {
    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);

        tracing::debug!(
            target: "seep::shadowsocks",
            id = %flow.id.as_uuid(),
            %target,
            server = %self.server,
            method = %self.method,
            "通过 Shadowsocks 连接"
        );

        // 解析目标地址
        let target_addr = Address::DomainNameAddress(flow.target.host.clone(), flow.target.port);

        // 建立 Shadowsocks 连接
        let mut outbound =
            ProxyClientStream::connect(self.context.clone(), self.server_config(), target_addr)
                .await
                .with_context(|| format!("Shadowsocks 连接失败: {}", self.server))?;

        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
            .await
            .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

/// Shadowsocks UDP 出站连接器（udp-relay-path.md §3.3 R7）：
/// `ProxySocket` 无连接语义，目标地址随每个数据报携带，关联时固定会话目标。
pub struct ShadowsocksUdpConnector {
    context: SharedContext,
    server_config: ServerConfig,
    server: String,
}

impl ShadowsocksUdpConnector {
    /// 从已校验的 TCP 连接器复用 server_config（保证两侧同一节点配置）
    pub fn from_connector(conn: &ShadowsocksConnector) -> Self {
        Self {
            context: shadowsocks::context::Context::new_shared(ServerType::Local),
            server_config: conn.server_config().clone(),
            server: format!("{}", conn.server_config().addr()),
        }
    }
}

#[async_trait]
impl EgressUdpConnector for ShadowsocksUdpConnector {
    fn name(&self) -> &str {
        "shadowsocks"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        // 客户端出站用 connect（绑定远端 ss 服务器）；bind 是服务端入站监听
        let socket = ProxySocket::connect(self.context.clone(), &self.server_config)
            .await
            .context(format!("shadowsocks UDP 连接失败（server={})", self.server))?;
        Ok(Arc::new(SsUdpRelay {
            socket,
            fixed_target: ctx.target,
        }))
    }
}

/// 字节级 ss UDP relay：send/recv 走 shadowsocks ProxySocket（AEAD 封包由 crate 承担）
struct SsUdpRelay {
    socket: ProxySocket<shadowsocks::net::UdpSocket>,
    /// §3.3 R7：关联时固定的会话目标（映射语义下一映射一目标，与参数一致）
    fixed_target: FlowTarget,
}

fn ss_address_of(target: &FlowTarget) -> Address {
    match target.host.parse::<std::net::IpAddr>() {
        Ok(ip) => Address::SocketAddress(std::net::SocketAddr::new(ip, target.port)),
        Err(_) => Address::DomainNameAddress(target.host.clone(), target.port),
    }
}

fn flow_target_of(addr: &Address) -> FlowTarget {
    match addr {
        Address::SocketAddress(sa) => FlowTarget {
            host: sa.ip().to_string(),
            port: sa.port(),
            proto: TargetProto::Udp,
        },
        Address::DomainNameAddress(host, port) => FlowTarget {
            host: host.clone(),
            port: *port,
            proto: TargetProto::Udp,
        },
    }
}

#[async_trait]
impl UdpRelay for SsUdpRelay {
    async fn send_to(&self, _target: &FlowTarget, buf: &[u8]) -> Result<()> {
        // 目标编码进 ss 协议头（R7 固定目标）；已 connect 的映射参数与此一致
        self.socket
            .send(&ss_address_of(&self.fixed_target), buf)
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("shadowsocks UDP 发送失败: {e}"))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        // crate 建议缓冲 ≥65536（上游可能回更大的源地址编码）
        let (n, addr, _) = self
            .socket
            .recv(buf)
            .await
            .map_err(|e| anyhow!("shadowsocks UDP 接收失败: {e}"))?;
        Ok((flow_target_of(&addr), n))
    }
}
