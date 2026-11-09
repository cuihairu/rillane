//! Trojan 出口连接器实现

use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use seep_core::udp::{EgressUdpConnector, UdpRelay};
use seep_core::{
    BoxedIo, EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision,
};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

use super::grpc::grpc_tunnel;
use super::ws::{ws_client_handshake, WsClient};
use crate::fingerprint::TlsFingerprint;
use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};

/// Trojan 出口连接器
pub struct TrojanConnector {
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    /// 客户端 TLS 指纹形态（P2-5；None = rustls 缺省形态）
    fingerprint: TlsFingerprint,
    /// 传输层：tcp | ws | grpc（ws/grpc 恒叠 TLS；clash 订阅面 network 字段）
    network: String,
    /// ws 路径（缺省 /）
    path: Option<String>,
    /// ws Host 头/回退 SNI（取首值）
    host: Option<Vec<String>>,
    /// gRPC 服务名（network=grpc 时必填；线上路径 = /{name}/Tun）
    grpc_service_name: Option<String>,
    /// 出站连接池（P1-5 §4.2；None = 旧行为内联路径，D-9）
    pool: Option<Arc<TransportPool>>,
    /// 共享 ClientConfig 工厂：pool=None 时使 TLS 会话恢复独立于池生效
    /// （§3.1「块存在即生效」；None = 既有每流 ClientConfig）
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl TrojanConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        fingerprint: TlsFingerprint,
        network: String,
        path: Option<String>,
        host: Option<Vec<String>>,
        grpc_service_name: Option<String>,
        pool: Option<Arc<TransportPool>>,
        factory: Option<Arc<TlsConnectorFactory>>,
    ) -> Self {
        Self {
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            fingerprint,
            network,
            path,
            host,
            grpc_service_name,
            pool,
            factory,
        }
    }

    /// 计算 Trojan 密码的 SHA224 哈希（十六进制）
    fn password_hash(&self) -> String {
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result)
    }

    /// 构建 Trojan 请求头（CONNECT 路径）
    fn build_request(&self, host: &str, port: u16) -> Result<Vec<u8>> {
        self.build_request_command(host, port, 0x01)
    }

    fn build_request_command(&self, host: &str, port: u16, command: u8) -> Result<Vec<u8>> {
        // P2 深审（2026-11-03）：域名长度无守卫，`len() as u8` 会静默截断
        // 产畸形帧（对照 vless.rs:165 有守卫）。加显式拒绝（>255 域名不可能
        // 出现在合法目标，拒发比发畸形帧安全）。
        if host.len() > u8::MAX as usize {
            anyhow::bail!("trojan: 目标主机名超长（>255 字节）");
        }
        let hash = self.password_hash();
        let mut request = Vec::with_capacity(256);

        // 密码哈希 (56 bytes hex)
        request.extend_from_slice(hash.as_bytes());

        // CRLF
        request.extend_from_slice(b"\r\n");

        // CMD: 0x01 CONNECT / 0x03 UDP ASSOCIATE
        request.push(command);

        // 地址类型和地址
        // 0x03 = 域名
        request.push(0x03);
        let host_bytes = host.as_bytes();
        request.push(host_bytes.len() as u8);
        request.extend_from_slice(host_bytes);

        // 端口 (big endian)
        request.extend_from_slice(&port.to_be_bytes());

        // CRLF
        request.extend_from_slice(b"\r\n");

        Ok(request)
    }

    /// 传输键（§4.2：alpn 空 = trojan 路径不设 ALPN；sni 取实际值——
    /// tcp = sni ∥ server，ws = sni ∥ ws host 首值，同 vmess 口径）
    fn transport_key(&self, sni_actual: &str) -> TransportKey {
        TransportKey::tls(
            &self.server,
            self.port,
            Some(sni_actual),
            self.skip_cert_verify,
            &[],
            self.fingerprint,
        )
    }

    fn ws_host_header(&self) -> String {
        self.host
            .as_ref()
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| self.sni.clone())
            .unwrap_or_else(|| self.server.clone())
    }

    fn ws_path(&self) -> String {
        let path = self.path.clone().unwrap_or_else(|| "/".to_string());
        if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        }
    }
}

#[async_trait]
impl EgressConnector for TrojanConnector {
    fn name(&self) -> &'static str {
        "trojan"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        match &self.pool {
            Some(pool) => self.forward_pooled(flow, pool).await,
            None => self.forward_inline(flow).await,
        }
    }
}

impl TrojanConnector {
    /// 池借出路径（§4.2）：acquire → 写协议头（bind）/ ws upgrade → 双向转发；
    /// 首写/upgrade 失败 → stale 一次性重拨（D-11）。
    async fn forward_pooled(
        &self,
        mut flow: Flow,
        pool: &Arc<TransportPool>,
    ) -> Result<FlowReport> {
        let server_addr = format!("{}:{}", self.server, self.port);
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        tracing::debug!(
            target: "seep::trojan",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            network = %self.network,
            pooled = true,
            "通过 Trojan 连接"
        );

        match self.network.as_str() {
            "tcp" => {
                let sni_actual = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let key = self.transport_key(&sni_actual);
                let request = self.build_request(&flow.target.host, flow.target.port)?;
                let (mut outbound, _lease) = pool
                    .acquire_bound(&key, |io| {
                        let request = request.clone();
                        Box::pin(async move { io.write_all(&request).await.map_err(Into::into) })
                    })
                    .await
                    .with_context(|| format!("连接 Trojan 服务器失败: {server_addr}"))?;

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
            "ws" | "websocket" => {
                let ws_host = self.ws_host_header();
                let ws_path = self.ws_path();
                let sni_actual = self.sni.clone().unwrap_or_else(|| ws_host.clone());
                let key = self.transport_key(&sni_actual);

                // 借出传输层（TLS 已由池侧建立）；ws upgrade 借出后进行（§4.2）
                let (boxed, first_lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接 Trojan 服务器失败: {server_addr}"))?;
                let handshake = ws_client_handshake(boxed, &ws_host, &ws_path).await;
                let (ws, _lease) = match handshake {
                    Ok(ws) => (ws, first_lease),
                    Err(_) => {
                        // upgrade 首写首读失败 → stale 一次性重拨（D-11）
                        drop(first_lease);
                        pool.note_stale(&key);
                        let (boxed, lease) = pool.acquire_fresh(&key).await?;
                        let ws = ws_client_handshake(boxed, &ws_host, &ws_path).await?;
                        (ws, lease)
                    }
                };
                self.relay_trojan_over_ws(flow, ws).await
            }
            "grpc" => {
                let service = self.grpc_service_name()?;
                let sni_actual = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let key = self.transport_key_alpn_h2(&sni_actual);

                // 借出传输层（TLS 已由池侧建立）；gRPC 隧道借出后进行（§4.2）
                let (boxed, first_lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接 Trojan 服务器失败: {server_addr}"))?;
                let tunnel = grpc_tunnel(boxed, &sni_actual, &service).await;
                let tunnel = match tunnel {
                    Ok(t) => t,
                    Err(_) => {
                        // 首写首读失败 → stale 一次性重拨（D-11）
                        drop(first_lease);
                        pool.note_stale(&key);
                        let (boxed, _lease) = pool.acquire_fresh(&key).await?;
                        grpc_tunnel(boxed, &sni_actual, &service).await?
                    }
                };
                self.relay_trojan_over_grpc(flow, tunnel).await
            }
            other => Err(anyhow!("暂不支持的 Trojan network: {}", other)),
        }
    }

    /// 内联路径（pool=None）：与既有实现逐 IO 序列同构（D-9）；factory=Some 时
    /// TLS 连接器改取共享 ClientConfig（tls_resumption 独立于池生效）。
    async fn forward_inline(&self, mut flow: Flow) -> Result<FlowReport> {
        let server_addr = format!("{}:{}", self.server, self.port);
        let target = format!("{}:{}", flow.target.host, flow.target.port);

        tracing::debug!(
            target: "seep::trojan",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            network = %self.network,
            "通过 Trojan 连接"
        );

        match self.network.as_str() {
            "tcp" => {
                // 建立 TCP 连接（net_mark 统一拨号：SO_MARK 逃逸面，networking.md §2）
                let tcp_stream = seep_core::net_mark::connect_tcp(server_addr.clone())
                    .await
                    .with_context(|| format!("连接 Trojan 服务器失败: {}", server_addr))?;

                // TLS 握手
                let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let connector = match &self.factory {
                    Some(factory) => {
                        factory.connector(self.skip_cert_verify, &[], self.fingerprint)?
                    }
                    None => create_tls_connector_with_profile(
                        self.skip_cert_verify,
                        None,
                        self.fingerprint,
                    )?,
                };
                let server_name =
                    rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

                // 发送 Trojan 请求
                let request = self.build_request(&flow.target.host, flow.target.port)?;
                tls_stream.write_all(&request).await?;

                // 双向转发
                let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                    &mut flow.io,
                    &mut tls_stream,
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
            "ws" | "websocket" => {
                let ws_host = self.ws_host_header();
                let ws_path = self.ws_path();

                // ws 恒叠 TLS：SNI 缺省回退 ws host（同 vmess/vless 口径）
                let sni = self.sni.clone().unwrap_or_else(|| ws_host.clone());
                let connector = match &self.factory {
                    Some(factory) => {
                        factory.connector(self.skip_cert_verify, &[], self.fingerprint)?
                    }
                    None => create_tls_connector_with_profile(
                        self.skip_cert_verify,
                        None,
                        self.fingerprint,
                    )?,
                };
                let server_name =
                    rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                let tcp_stream = seep_core::net_mark::connect_tcp(server_addr.clone())
                    .await
                    .with_context(|| format!("连接 Trojan 服务器失败: {}", server_addr))?;
                let tls_stream = connector.connect(server_name, tcp_stream).await?;

                let ws = ws_client_handshake(tls_stream, &ws_host, &ws_path)
                    .await
                    .with_context(|| "Trojan over WS upgrade 失败")?;
                self.relay_trojan_over_ws(flow, ws).await
            }
            "grpc" => {
                let service = self.grpc_service_name()?;
                // grpc 恒叠 TLS：ALPN 固定 h2（gRPC over TLS 语义），SNI 回退 server
                let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let connector = match &self.factory {
                    Some(factory) => factory.connector(
                        self.skip_cert_verify,
                        &["h2".to_string()],
                        self.fingerprint,
                    )?,
                    None => create_tls_connector_with_profile(
                        self.skip_cert_verify,
                        Some(&["h2".to_string()]),
                        self.fingerprint,
                    )?,
                };
                let server_name =
                    rustls::pki_types::ServerName::try_from(sni.clone()).context("无效的 SNI")?;
                let tcp_stream = seep_core::net_mark::connect_tcp(server_addr.clone())
                    .await
                    .with_context(|| format!("连接 Trojan 服务器失败: {}", server_addr))?;
                let tls_stream = connector.connect(server_name, tcp_stream).await?;

                let tunnel = grpc_tunnel(tls_stream, &sni, &service)
                    .await
                    .with_context(|| "Trojan over gRPC 隧道握手失败")?;
                self.relay_trojan_over_grpc(flow, tunnel).await
            }
            other => Err(anyhow!("暂不支持的 Trojan network: {}", other)),
        }
    }

    /// gRPC 服务名（network=grpc 必填；缺省/空串构建期由 runtime_builder
    /// 校验，此处运行期兜底）
    fn grpc_service_name(&self) -> Result<String> {
        self.grpc_service_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("Trojan gRPC 缺少 grpc_service_name"))
    }

    /// 传输键（grpc）：TLS 身份 + ALPN h2（池预拨按键携带 ALPN 协商）
    fn transport_key_alpn_h2(&self, sni_actual: &str) -> TransportKey {
        TransportKey::tls(
            &self.server,
            self.port,
            Some(sni_actual),
            self.skip_cert_verify,
            &["h2".to_string()],
            self.fingerprint,
        )
    }

    /// Trojan over gRPC 双向转发：请求头 = 首条 gRPC 消息；成功后无独立
    /// 应答头，直接双向泵（客户端 EOF → 零长 DATA + END_STREAM 收尾——
    /// 服务端按流终对目标侧收尾，下行侧经 message None 语义同步收敛）。
    async fn relay_trojan_over_grpc(
        &self,
        flow: Flow,
        tunnel: super::grpc::GrpcTunnel,
    ) -> Result<FlowReport> {
        let req = self.build_request(&flow.target.host, flow.target.port)?;
        let (mut grpc_r, mut grpc_w) = tunnel.split();
        grpc_w.message(&req).await?;

        let (mut client_r, mut client_w) = tokio::io::split(flow.io);

        let up_task = tokio::spawn(async move {
            let mut up: u64 = 0;
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = client_r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                grpc_w.message(&buf[..n]).await?;
                up += n as u64;
            }
            // 客户端半关 → 零长 DATA + END_STREAM 传播（服务端收尾后关流，
            // 下行侧经 message None 语义同步收敛）
            let _ = grpc_w.finish().await;
            Result::<u64>::Ok(up)
        });

        let down_task = tokio::spawn(async move {
            let mut down: u64 = 0;
            while let Some(msg) = grpc_r.message().await? {
                if msg.is_empty() {
                    continue;
                }
                client_w.write_all(&msg).await?;
                down += msg.len() as u64;
            }
            let _ = client_w.shutdown().await;
            Result::<u64>::Ok(down)
        });

        let (up, down) =
            tokio::try_join!(up_task, down_task).context("Trojan over gRPC 双向转发任务失败")?;
        let up = up?;
        let down = down?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }

    /// Trojan over WS 双向转发（trojan-go 惯例：请求头 = 首个 binary 消息；
    /// 成功后无独立应答头，直接双向泵；池路径复用——
    /// `WsClient<ReadHalf<BoxedIo>, WriteHalf<BoxedIo>>` 同型可用）。
    async fn relay_trojan_over_ws<R, W>(
        &self,
        flow: Flow,
        mut ws: WsClient<R, W>,
    ) -> Result<FlowReport>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt;

        // Trojan 请求作为首个 binary 消息发出
        let req = self.build_request(&flow.target.host, flow.target.port)?;
        ws.write_binary(&req).await?;

        // 双向泵（与 vless relay 同构，去 VLESS 应答头段——trojan 无应答头）
        let (mut client_r, mut client_w) = tokio::io::split(flow.io);
        let (mut ws_r, mut ws_w) = ws.split();

        let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        ws_r.set_pong_sender(pong_tx);

        let up_task = tokio::spawn(async move {
            let mut up: u64 = 0;
            let mut buf = [0u8; 16 * 1024];
            loop {
                tokio::select! {
                    biased;
                    Some(payload) = pong_rx.recv() => {
                        ws_w.write_pong(&payload).await?;
                    }
                    n = client_r.read(&mut buf) => {
                        let n = n?;
                        if n == 0 {
                            break;
                        }
                        ws_w.write_binary(&buf[..n]).await?;
                        up += n as u64;
                    }
                }
            }
            // 客户端半关 → 向服务端传播 ws Close（服务端对目标侧收尾后
            // 回 Close/关 TLS，下行侧经 read_binary None 语义同步收敛）
            let _ = ws_w.write_close().await;
            Result::<u64>::Ok(up)
        });

        let down_task = tokio::spawn(async move {
            let mut down: u64 = 0;
            while let Some(msg) = ws_r.read_binary().await? {
                if msg.is_empty() {
                    continue;
                }
                client_w.write_all(&msg).await?;
                down += msg.len() as u64;
            }
            let _ = client_w.shutdown().await;
            Result::<u64>::Ok(down)
        });

        let (up, down) =
            tokio::try_join!(up_task, down_task).context("Trojan over WS 双向转发任务失败")?;
        let up = up?;
        let down = down?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// UDP 数据面（G0-4）：command 0x03 + 每报 [ATYP][ADDR][PORT][LEN][CRLF][payload]
// ---------------------------------------------------------------------------

/// Trojan UDP 出站连接器（udp-relay-path.md §3.1 能力表扩展）。数据面 =
/// trojan-gfw protocol.md `UDP ASSOCIATE`：每数据报 =
/// [ATYP][DST.ADDR][DST.PORT(2BE)][Length(2BE)][CRLF][payload]，逐报携带
/// 目标（单连接多目标；seep 映射语义下一映射一目标）。Trojan 恒叠 TLS。
///
/// 仅 network=tcp 注册（ws/grpc 的 UDP 面构建期由 scan_udp_capability 判负）。
pub struct TrojanUdpConnector {
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    fingerprint: TlsFingerprint,
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl TrojanUdpConnector {
    /// 从已校验的 TCP 连接器复用节点配置（保证 UDP 面与 TCP 面同一份配置）
    pub fn from_connector(conn: &TrojanConnector) -> Self {
        Self {
            server: conn.server.clone(),
            port: conn.port,
            password: conn.password.clone(),
            sni: conn.sni.clone(),
            skip_cert_verify: conn.skip_cert_verify,
            fingerprint: conn.fingerprint,
            factory: conn.factory.clone(),
        }
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    fn password_hash(&self) -> String {
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        hex::encode(&hasher.finalize())
    }

    /// TLS over tcp boxed 传输（trojan 恒叠 TLS；UDP 长连，不走连接池）
    async fn open_transport(&self) -> Result<BoxedIo> {
        let tcp = seep_core::net_mark::connect_tcp(self.server_addr())
            .await
            .with_context(|| format!("连接 Trojan 服务器失败: {}", self.server_addr()))?;
        let _ = tcp.set_nodelay(true);
        let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
        let connector = match &self.factory {
            Some(f) => f.connector(self.skip_cert_verify, &[], self.fingerprint)?,
            None => {
                create_tls_connector_with_profile(self.skip_cert_verify, None, self.fingerprint)?
            }
        };
        let server_name = rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
        Ok(Box::new(connector.connect(server_name, tcp).await?))
    }

    /// UDP ASSOCIATE 请求：hash + CRLF + 0x03 + ATYP + ADDR + PORT + CRLF
    fn build_udp_associate(&self, host: &str, port: u16) -> Result<Vec<u8>> {
        if host.len() > u8::MAX as usize {
            anyhow::bail!("trojan: 目标主机名超长（>255 字节）");
        }
        let mut request = Vec::with_capacity(128);
        request.extend_from_slice(self.password_hash().as_bytes());
        request.extend_from_slice(b"\r\n");
        request.push(0x03);
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    request.push(0x01);
                    request.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    request.push(0x04);
                    request.extend_from_slice(&v6.octets());
                }
            }
        } else {
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
        request.extend_from_slice(&port.to_be_bytes());
        request.extend_from_slice(b"\r\n");
        Ok(request)
    }
}

#[async_trait]
impl EgressUdpConnector for TrojanUdpConnector {
    fn name(&self) -> &str {
        "trojan"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        let mut stream = self.open_transport().await?;
        let req = self.build_udp_associate(&ctx.target.host, ctx.target.port)?;
        stream.write_all(&req).await?;
        stream.flush().await?;
        // trojan UDP ASSOCIATE 无独立应答头（serversession.cpp：直接进入
        // UDP_FORWARD 转发循环），请求头写毕即收发数据报
        let (rr, ww) = tokio::io::split(stream);
        Ok(Arc::new(TrojanUdpRelay {
            reader: AsyncMutex::new(rr),
            writer: AsyncMutex::new(ww),
            initial_target: ctx.target,
        }))
    }
}

/// 字节级 Trojan UDP relay（G0-4）：每报 [ATYP][ADDR][PORT][LEN][CRLF][payload]。
/// send/recv 分属 forward_up/forwarder 两任务，读写半各持 tokio Mutex。
struct TrojanUdpRelay {
    reader: AsyncMutex<tokio::io::ReadHalf<BoxedIo>>,
    writer: AsyncMutex<tokio::io::WriteHalf<BoxedIo>>,
    /// 关联时的首目标（recv 未解析出地址时的兜底；实际逐报带地址）
    initial_target: FlowTarget,
}

/// 编码 SOCKS5 风格地址段：[ATYP][ADDR][PORT(2BE)]，返回写出的字节数
fn write_socks_addr(out: &mut Vec<u8>, target: &FlowTarget) -> Result<()> {
    if target.host.len() > u8::MAX as usize {
        anyhow::bail!("trojan: 目标主机名超长（>255 字节）");
    }
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(0x03);
        out.push(target.host.len() as u8);
        out.extend_from_slice(target.host.as_bytes());
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

#[async_trait]
impl UdpRelay for TrojanUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let mut w = self.writer.lock().await;
        if buf.len() > u16::MAX as usize {
            return Err(anyhow!("Trojan UDP 数据报过大（>65535）"));
        }
        let mut frame = Vec::with_capacity(64 + buf.len());
        write_socks_addr(&mut frame, target)?;
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(buf);
        w.write_all(&frame).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut r = self.reader.lock().await;
        let mut atyp = [0u8; 1];
        r.read_exact(&mut atyp).await?;
        let host;
        let port: u16;
        match atyp[0] {
            0x01 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                host = std::net::Ipv4Addr::from(b).to_string();
            }
            0x04 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                host = std::net::Ipv6Addr::from(b).to_string();
            }
            0x03 => {
                let mut l = [0u8; 1];
                r.read_exact(&mut l).await?;
                let mut h = vec![0u8; l[0] as usize];
                r.read_exact(&mut h).await?;
                host = String::from_utf8_lossy(&h).into_owned();
            }
            other => return Err(anyhow!("Trojan UDP 未知地址类型: {other}")),
        }
        let mut port_b = [0u8; 2];
        r.read_exact(&mut port_b).await?;
        port = u16::from_be_bytes(port_b);
        let mut len_b = [0u8; 2];
        r.read_exact(&mut len_b).await?;
        let len = u16::from_be_bytes(len_b) as usize;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf).await?;
        if crlf != [0x0d, 0x0a] {
            return Err(anyhow!("Trojan UDP 帧 CRLF 校验失败"));
        }
        let n = len.min(buf.len());
        r.read_exact(&mut buf[..n]).await?;
        if len > n {
            let mut skip = vec![0u8; len - n];
            r.read_exact(&mut skip).await?;
        }
        let target = if host.is_empty() {
            self.initial_target.clone()
        } else {
            FlowTarget {
                host,
                port,
                proto: seep_core::TargetProto::Udp,
            }
        };
        Ok((target, n))
    }
}

impl fmt::Debug for TrojanUdpRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanUdpRelay")
            .field("initial_target", &self.initial_target)
            .finish()
    }
}

// 辅助模块：hex 编码
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject as _;
    use seep_core::{FlowContext, FlowId, FlowMetadata, RouteDecision, TargetProto};
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const TEST_PASSWORD: &str = "test-trojan-password";

    fn test_connector(port: u16) -> TrojanConnector {
        TrojanConnector::new(
            "127.0.0.1".to_string(),
            port,
            TEST_PASSWORD.to_string(),
            Some("localhost".to_string()),
            true, // skip_cert_verify：自签证书
            TlsFingerprint::None,
            "tcp".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
    }

    fn test_ctx() -> (FlowContext, RouteDecision) {
        let ctx = FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: TargetProto::Udp,
            },
            metadata: FlowMetadata::default(),
        };
        (ctx, RouteDecision::direct("test".to_string()))
    }

    /// 读一个 trojan UDP 数据报帧 [ATYP][ADDR][PORT][LEN][CRLF][payload]，
    /// 返回完整帧字节（含地址段），供 echo 原样回写。
    async fn read_udp_frame<S>(stream: &mut S) -> Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let mut out = Vec::new();
        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await?;
        out.push(atyp[0]);
        match atyp[0] {
            0x01 => {
                let mut b = [0u8; 4];
                stream.read_exact(&mut b).await?;
                out.extend_from_slice(&b);
            }
            0x04 => {
                let mut b = [0u8; 16];
                stream.read_exact(&mut b).await?;
                out.extend_from_slice(&b);
            }
            0x03 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await?;
                out.push(l[0]);
                let mut h = vec![0u8; l[0] as usize];
                stream.read_exact(&mut h).await?;
                out.extend_from_slice(&h);
            }
            other => anyhow::bail!("trojan UDP 测试未知地址类型: {other}"),
        }
        let mut port_b = [0u8; 2];
        stream.read_exact(&mut port_b).await?;
        out.extend_from_slice(&port_b);
        let mut len_b = [0u8; 2];
        stream.read_exact(&mut len_b).await?;
        out.extend_from_slice(&len_b);
        let len = u16::from_be_bytes(len_b) as usize;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        assert_eq!(crlf, [0x0d, 0x0a], "trojan UDP 帧 CRLF 校验失败");
        out.extend_from_slice(&crlf);
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// trojan UDP ASSOCIATE 回环服务端（G0-4）：TLS 握手 → 校验 hash + 命令
    /// 0x03 → 逐报 echo（无应答头，UDP_FORWARD 直进）。
    async fn serve_trojan_udp<S>(mut stream: S, rounds: usize) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // 请求头：hash(56) CRLF CMD(1) ATYP(1) ADDR PORT(2) CRLF(2)
        let mut head = [0u8; 56 + 2 + 1 + 1];
        stream.read_exact(&mut head).await?;
        let hash = String::from_utf8_lossy(&head[..56]).to_string();
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "hash 非 hex");
        let mut hasher = Sha224::new();
        hasher.update(TEST_PASSWORD.as_bytes());
        let expect_hash = hex::encode(&hasher.finalize());
        assert_eq!(hash, expect_hash, "trojan 密码 hash 不匹配");
        assert_eq!(&head[56..58], b"\r\n", "请求头 CRLF 不匹配");
        assert_eq!(head[58], 0x03, "trojan UDP 命令应为 0x03");
        // ATYP=0x03（域名 example.com）+ len + domain + port(2) + CRLF(2)
        assert_eq!(head[59], 0x03, "请求应为域名地址类型");
        let mut rest = [0u8; 1];
        stream.read_exact(&mut rest).await?;
        let dlen = rest[0] as usize;
        let mut domain = vec![0u8; dlen];
        stream.read_exact(&mut domain).await?;
        assert_eq!(String::from_utf8_lossy(&domain), "example.com");
        let mut port_b = [0u8; 2];
        stream.read_exact(&mut port_b).await?;
        assert_eq!(u16::from_be_bytes(port_b), 443);
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        assert_eq!(crlf, [0x0d, 0x0a], "请求尾 CRLF 不匹配");

        for _ in 0..rounds {
            let frame = read_udp_frame(&mut stream).await?;
            stream.write_all(&frame).await?;
            stream.flush().await?;
        }
        Ok(())
    }

    /// G0-4：trojan UDP ASSOCIATE 回环（恒叠 TLS；命令 0x03；逐报
    /// [ATYP][ADDR][PORT][LEN][CRLF][payload]）。
    #[tokio::test]
    async fn udp_loopback_command_03_tls() {
        // 自签证书（SAN=localhost；客户端 skip_cert_verify 不校验链）
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("证书 PEM 解析");
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("私钥读取");

        let provider = crate::tls::tls_crypto_provider();
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("协议版本");
        let config = Arc::new(
            builder
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("服务端证书装配"),
        );
        let acceptor = TlsAcceptor::from(config);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        const ROUNDS: usize = 2;
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            if let Err(e) = serve_trojan_udp(&mut tls, ROUNDS).await {
                eprintln!("测试服务端错误: {e:#}");
            }
            let _ = tls.shutdown().await;
        });

        let connector = TrojanUdpConnector::from_connector(&test_connector(port));
        let (ctx, decision) = test_ctx();
        let relay = connector.associate(ctx.clone(), &decision).await.unwrap();

        let msgs: Vec<Vec<u8>> = vec![b"hello udp trojan".to_vec(), vec![3u8; 18 * 1024]];
        for m in &msgs {
            relay.send_to(&ctx.target, m).await.unwrap();
            let mut buf = vec![0u8; m.len() + 64];
            let (tgt, n) = relay.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &m[..], "trojan UDP 回环载荷不一致");
            assert_eq!(tgt.host, "example.com");
            assert_eq!(tgt.port, 443);
            assert_eq!(tgt.proto, TargetProto::Udp);
        }
    }
}
