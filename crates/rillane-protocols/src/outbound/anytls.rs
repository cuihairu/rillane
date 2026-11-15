//! AnyTLS 出口连接器（RIL-106）：TLS 拨号与会话认证在本仓（TlsConnectorFactory
//! 组合，skip_cert_verify/sni 可控），会话帧/多路复用/填充与 UoT 数据报面由
//! anytls 库承载——选库评估与角色边界见 protocol-backends.md#anytls

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use anytls::{
    Address, Client, DEFAULT_MAX_SESSION_AGE, DEFAULT_SCHEME, Dialer, PaddingFactory, StreamIo,
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream, uot_sentinel_destination,
    write_auth_with_client_id,
};
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OnceCell, RwLock};

/// 会话空闲回收（库内建 idle 会话池——协议本体的复用面）
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// AnyTLS 出口连接器：内建会话池（流间复用 TLS 会话），TLS 拨号经本仓
/// TlsConnectorFactory（评估记录旁路面：库不拥有拨号）
pub struct AnytlsConnector {
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    /// 惰性会话池：首个流建立时拨号；后续流复用空闲会话（Arc 使 UDP 面
    /// 可经 from_connector 共享同一池）
    client: Arc<OnceCell<Arc<Client>>>,
}

impl AnytlsConnector {
    pub fn new(
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            client: Arc::new(OnceCell::new()),
        }
    }

    fn proxy_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// 会话池（进程内惰性单例）：拨号闭包经 TlsConnectorFactory 组合，
    /// 认证（write_auth_with_client_id）在库会话帧之前完成——与库自带
    /// client_app 同序（TLS → write_auth → BoxTransport）
    async fn client(&self) -> Result<&Arc<Client>> {
        self.client
            .get_or_try_init(|| async {
                let padding = Arc::new(RwLock::new(
                    PaddingFactory::new(DEFAULT_SCHEME)
                        .ok_or_else(|| anyhow!("AnyTLS 填充方案解析失败"))?,
                ));
                let tls = crate::tls::create_tls_connector_with_profile(
                    self.skip_cert_verify,
                    None,
                    crate::TlsFingerprint::None,
                )
                .context("AnyTLS TLS 连接器构建失败")?;
                let (server, password, sni) =
                    (self.proxy_addr(), self.password.clone(), self.sni.clone());
                let dial_padding = Arc::clone(&padding);
                let dialer: Dialer = Arc::new(move || {
                    let (server, password, sni) =
                        (server.clone(), password.clone(), sni.clone());
                    let tls = tls.clone();
                    let padding = Arc::clone(&dial_padding);
                    Box::pin(async move { dial(&server, sni.as_deref(), &password, &padding, tls).await })
                });
                Ok(Client::new(
                    dialer,
                    padding,
                    SESSION_IDLE_TIMEOUT,
                    DEFAULT_MAX_SESSION_AGE,
                ))
            })
            .await
            .map_err(|e: anyhow::Error| e)
    }
}

/// 单次拨号：TCP → TLS（本仓 TLS 面）→ 会话认证（库面）→ 传输体
async fn dial(
    server: &str,
    sni: Option<&str>,
    password: &str,
    padding: &RwLock<PaddingFactory>,
    tls: tokio_rustls::TlsConnector,
) -> std::io::Result<anytls::BoxTransport> {
    let tcp = TcpStream::connect(server)
        .await
        .map_err(|e| std::io::Error::other(format!("AnyTLS 控制连接失败（server={server}）: {e}")))?;
    let name = sni.unwrap_or(server.split(':').next().unwrap_or(server));
    let server_name = rustls::pki_types::ServerName::try_from(name.to_string())
        .map_err(|e| std::io::Error::other(format!("AnyTLS SNI 名称非法（{name}）: {e}")))?;
    let mut transport = tls.connect(server_name, tcp).await.map_err(|e| {
        std::io::Error::other(format!("AnyTLS TLS 握手失败（server={server}）: {e}"))
    })?;
    let padding = padding.read().await.clone();
    write_auth_with_client_id(&mut transport, password, &padding, None)
        .await
        .map_err(|e| std::io::Error::other(format!("AnyTLS 会话认证失败（server={server}）: {e}")))?;
    Ok(Box::new(transport))
}

/// 目标 → SOCKS5 地址格式（AnyTLS 会话流首载荷即目标）
fn address_of(target: &FlowTarget) -> Result<Address> {
    Ok(match target.host.parse::<IpAddr>() {
        Ok(ip) => Address::from(std::net::SocketAddr::new(ip, target.port)),
        Err(_) => Address::from((target.host.clone(), target.port)),
    })
}

/// 地址 → 会话目标（下行源随包带回）
fn flow_target_of(source: Option<Address>, fallback: &FlowTarget) -> FlowTarget {
    match source {
        Some(Address::SocketAddress(sa)) => FlowTarget {
            host: sa.ip().to_string(),
            port: sa.port(),
            proto: TargetProto::Udp,
        },
        Some(Address::DomainAddress(host, port)) => FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        // 无源地址（服务端未回源）→ 会话固定目标
        _ => fallback.clone(),
    }
}

#[async_trait]
impl EgressConnector for AnytlsConnector {
    fn name(&self) -> &'static str {
        "anytls"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let client = self.client().await?;
        let stream = client
            .create_stream()
            .await
            .context("AnyTLS 会话开流失败")?;
        let mut remote = StreamIo::new(stream);
        // 目标地址 = 会话流首载荷（协议约定；SOCKS5 地址编码经库的
        // From<Address> for Vec<u8>，AsyncStreamOperation 特征未被 anytls
        // 再导出，逐字节等价）
        let bytes: Vec<u8> = address_of(&flow.target)?.into();
        remote
            .write_all(&bytes)
            .await
            .context("AnyTLS 目标地址写入失败")?;

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut remote,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// 出站 UDP（RIL-106）：库 uot 特性——UDP-over-TCP 数据报面
// ---------------------------------------------------------------------------

/// AnyTLS UDP 出站连接器：与 TCP 面共用同一会话池（地址/凭据一致）
pub struct AnytlsUdpConnector {
    inner: Arc<AnytlsConnector>,
}

impl AnytlsUdpConnector {
    /// 从已构建的 TCP 连接器复用同一节点配置与会话池
    pub fn from_connector(conn: &AnytlsConnector) -> Self {
        Self {
            inner: Arc::new(AnytlsConnector {
                server: conn.server.clone(),
                port: conn.port,
                password: conn.password.clone(),
                sni: conn.sni.clone(),
                skip_cert_verify: conn.skip_cert_verify,
                client: conn.client.clone(),
            }),
        }
    }
}

#[async_trait]
impl EgressUdpConnector for AnytlsUdpConnector {
    fn name(&self) -> &str {
        "anytls"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        let client = self.inner.client().await?;
        let stream = client
            .create_stream()
            .await
            .context("AnyTLS UoT 会话开流失败")?;
        let mut io = StreamIo::new(stream);
        // 数据报模式声明：sentinel destination + UotRequest（库 client_app 同序）
        let outer: Vec<u8> = uot_sentinel_destination().into();
        io.write_all(&outer).await.context("UoT sentinel 写入失败")?;
        let request: Vec<u8> =
            UotRequest::new(UotMode::Datagram, Address::unspecified_v4()).into();
        io.write_all(&request).await.context("UoT 请求写入失败")?;
        Ok(Arc::new(AnytlsUdpRelay {
            stream: Mutex::new(io),
            fixed_target: ctx.target,
        }))
    }
}

/// 字节级 AnyTLS UoT relay：数据报经会话流逐包收发（UoT 帧内含目标地址，
/// TCP 承载无本地 UDP socket），stream 随 relay 生命周期持有——drop 即关流
/// （会话帧 FIN）
struct AnytlsUdpRelay {
    /// UoT 会话流（互斥包级串行：单消费面）
    stream: Mutex<StreamIo>,
    /// §3.3 R7 同口径：关联时固定的会话目标（粘滞语义与 SS/socks5 relay 同）
    fixed_target: FlowTarget,
}

#[async_trait]
impl UdpRelay for AnytlsUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        // 上行目标以会话固定目标为准（粘滞语义，与 SS/socks5 relay 同口径）
        let dest = if target.host == self.fixed_target.host && target.port == self.fixed_target.port
        {
            target
        } else {
            &self.fixed_target
        };
        let frame = uot_encode_packet(UotMode::Datagram, Some(&address_of(dest)?), buf)
            .context("UoT 封包失败")?;
        let mut io = self.stream.lock().await;
        io.write_all(&frame).await.context("AnyTLS UoT 上行失败")
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut io = self.stream.lock().await;
        let (source, payload) = uot_get_packet_from_stream(UotMode::Datagram, &mut *io)
            .await
            .context("AnyTLS UoT 下行失败")?;
        if buf.len() < payload.len() {
            return Err(anyhow!(
                "缓冲过小（{} < {} 字节）",
                buf.len(),
                payload.len()
            ));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((
            flow_target_of(source, &self.fixed_target),
            payload.len(),
        ))
    }
}
