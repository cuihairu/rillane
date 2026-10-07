//! Shadowsocks 出口连接器实现（TCP 面 + UDP 面，udp-relay-path.md §3.3）

use anyhow::{anyhow, bail, Context, Result};
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
use std::{net::SocketAddr, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};

/// 插件端口就绪探测时限（插件进程冷启动通常 <100ms，留慢环境余量）
const PLUGIN_READY_TIMEOUT: Duration = Duration::from_secs(3);

/// Shadowsocks 出口连接器
pub struct ShadowsocksConnector {
    server: String,
    port: u16,
    method: String,
    context: SharedContext,
    server_config: ServerConfig,
    /// SIP003 插件可执行名；None = shadowsocks crate 直连
    plugin: Option<String>,
    /// SIP003 插件参数（空格分词后作为插件 argv 追加）
    plugin_opts: Option<String>,
}

impl ShadowsocksConnector {
    pub fn new(
        server: String,
        port: u16,
        method: String,
        password: String,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    ) -> Result<Self> {
        let context = shadowsocks::context::Context::new_shared(ServerType::Local);
        // 加密方法校验提前到构建期（udp-relay-path.md §3.1 能力扫描同口径：
        // 配置错误在启动时暴露，而非首个连接时）
        let server_config = Self::build_server_config(&server, port, &method, &password)?;

        Ok(Self {
            server,
            port,
            method,
            context,
            server_config,
            plugin,
            plugin_opts,
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

        // SIP003 插件桥模式：加密/混淆由插件进程负责，seep 只把客户端流量
        // 原样送进插件本地端口（_bridge 持子进程句柄，函数收尾 drop 即 kill）
        if let Some(plugin) = &self.plugin {
            let (mut outbound, _bridge) =
                spawn_plugin(plugin, self.plugin_opts.as_deref(), &self.server, self.port)
                    .await
                    .with_context(|| format!("节点 {} 插件桥接失败", self.server))?;

            let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                &mut flow.io,
                &mut outbound,
                seep_core::performance::relay_buffer(),
                seep_core::performance::relay_buffer(),
            )
            .await
            .context("双向转发失败")?;

            return Ok(FlowReport {
                upstream: up,
                downstream: down,
            });
        }

        // 解析目标地址
        let target_addr = Address::DomainNameAddress(flow.target.host.clone(), flow.target.port);

        // 建立 Shadowsocks 连接
        let mut outbound =
            ProxyClientStream::connect(self.context.clone(), self.server_config(), target_addr)
                .await
                .with_context(|| format!("Shadowsocks 连接失败: {}", self.server))?;

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut outbound,
            seep_core::performance::relay_buffer(),
            seep_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

/// SIP003 插件桥（plugin 模式 TCP 数据面）：
/// 插件进程按 SS_LOCAL_*/SS_REMOTE_* 环境变量约定自监听本地端口，seep 连该
/// 端口把明文目标流量交给插件（SS 协议加密与混淆由插件完成）；子进程随连接
/// 生命周期收尾（kill_on_drop）。
///
/// UDP 数据面不经插件（SIP003 仅定义 TCP）：plugin 模式下 UDP 能力判负，
/// 由 `scan_udp_capability` 按既有口径构建期报错。
struct PluginBridge {
    #[allow(dead_code)] // 仅持句柄：drop → kill_on_drop 收尾子进程
    child: Child,
}

/// 分配本地空闲端口（SIP003：插件自 bind SS_LOCAL_*；bind 后让位存在极小
/// 竞速窗口，与 ss-local 同惯例）
fn reserve_local_addr() -> Result<SocketAddr> {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = std_listener.local_addr()?;
    drop(std_listener);
    Ok(addr)
}

/// 等插件端口就绪并把就绪连接直接复用为 outbound（省一次重连，且探测连接
/// 即数据面连接，对插件无副作用——未发数据的半开连接由插件 accept 正常处理）
async fn wait_plugin_ready(local: SocketAddr, deadline: Duration) -> Result<TcpStream> {
    let attempt = async {
        loop {
            match TcpStream::connect(local).await {
                Ok(s) => return Ok(s),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => return Err(anyhow!(e)),
            }
        }
    };
    match tokio::time::timeout(deadline, attempt).await {
        Ok(res) => res,
        Err(_) => bail!("插件端口在限时内未就绪: {local}"),
    }
}

async fn spawn_plugin(
    plugin: &str,
    plugin_opts: Option<&str>,
    server: &str,
    server_port: u16,
) -> Result<(TcpStream, PluginBridge)> {
    let local = reserve_local_addr().context("分配插件本地端口失败")?;

    let mut cmd = Command::new(plugin);
    if let Some(opts) = plugin_opts {
        // SIP003：opts 按空白分词后追加 argv；分号串（如 tls;host=x）保持单参数
        cmd.args(opts.split_whitespace());
    }
    cmd.env("SS_LOCAL_HOST", local.ip().to_string())
        .env("SS_LOCAL_PORT", local.port().to_string())
        .env("SS_REMOTE_HOST", server)
        .env("SS_REMOTE_PORT", server_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let child = cmd
        .spawn()
        .with_context(|| format!("插件进程启动失败: {plugin}（检查 PATH 与可执行位）"))?;

    let stream = wait_plugin_ready(local, PLUGIN_READY_TIMEOUT)
        .await
        .with_context(|| format!("插件 {plugin} 未在限时内监听 {local}"))?;

    Ok((stream, PluginBridge { child }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::{Flow, FlowId, FlowTarget};
    use tokio::net::TcpListener as TokioListener;

    fn connector_with_plugin(plugin: Option<&str>) -> ShadowsocksConnector {
        ShadowsocksConnector::new(
            "127.0.0.1".into(),
            8388,
            "aes-256-gcm".into(),
            "pw".into(),
            plugin.map(str::to_string),
            None,
        )
        .unwrap()
    }

    fn duplex_flow() -> Flow {
        let (client, _server_side) = tokio::io::duplex(64);
        Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(client),
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn plugin_spawn_failure_reports_binary_name() {
        // 不存在的插件二进制：spawn 失败错误须含插件名（排障定位入口）
        let conn = connector_with_plugin(Some("seep-no-such-plugin-bin"));
        let err = conn
            .forward(duplex_flow())
            .await
            .expect_err("不存在的插件应失败");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("seep-no-such-plugin-bin"),
            "错误链应含插件名: {rendered}"
        );
    }

    #[tokio::test]
    async fn wait_plugin_ready_times_out_on_closed_port() {
        // 占位拿空闲端口再让位（无监听）→ 限时内 refused 重试直至超时
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let err = wait_plugin_ready(addr, Duration::from_millis(200))
            .await
            .expect_err("无监听端口应超时");
        assert!(err.to_string().contains("未就绪"), "超时语义: {err:#}");
    }

    #[tokio::test]
    async fn wait_plugin_ready_reuses_listening_connection() {
        // 已监听端口：探测连接直接复用为 outbound（accept 半边保活）
        let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await });

        let stream = wait_plugin_ready(addr, Duration::from_secs(2))
            .await
            .expect("监听中的端口应立即就绪");
        let (accepted, _) = accept_task.await.unwrap().unwrap();
        // 探测流本地端 == accept 侧看到的对端（同一条连接的两半）
        assert_eq!(stream.local_addr().unwrap(), accepted.peer_addr().unwrap());
    }
}
