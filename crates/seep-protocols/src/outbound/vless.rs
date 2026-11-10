//! VLESS 出口连接器实现（TCP/TLS/WS/gRPC）

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use seep_config::RealityConfig;
use seep_core::udp::{EgressUdpConnector, UdpRelay};
use seep_core::{
    BoxedIo, EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use super::grpc::grpc_tunnel;
use super::h2::h2_tunnel;
use super::httpupgrade::httpupgrade_client_handshake;
use super::ws::{ws_client_handshake, WsClient};
use crate::fingerprint::TlsFingerprint;
use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};

/// REALITY/Vision 拨号期门（G1-6 配置保留面，TCP/UDP 面共用）：配置保留至
/// 此拦，拒绝静默降级——普通 TLS 会被 REALITY 服务端回落伪装站点（流量
/// 不走代理且无报错），普通 VLESS 连不上期望 Vision 分帧的服务端且无报错。
fn gate_reality_flow(reality: &Option<RealityConfig>, flow: &Option<String>) -> Result<()> {
    if reality.is_some() {
        return Err(anyhow!(
            "REALITY 出站未实现（G1-6）：需要 ClientHello 字节级控制（session_id 认证材料/浏览器指纹仿冒），rustls 不暴露且无维护中的 Rust uTLS 等价物（设计文档 §4.3 栈决策待定）；拒绝静默降级为普通 TLS——服务端将回落伪装站点且无报错"
        ));
    }
    if let Some(f) = flow {
        return Err(anyhow!(
            "VLESS flow {f}（XTLS-Vision 等流控）分帧未实现（G1-6 M3）；拒绝静默降级为普通 VLESS——服务端期望 Vision 分帧，连接将失败且无报错"
        ));
    }
    Ok(())
}

/// 请求头字节（TCP/UDP 共用，G0-4）：Version(0x00) + UUID + OptLen(0) +
/// Command（0x01 TCP / 0x02 UDP，xray RequestCommand）+ Port(BE) + Address。
fn build_vless_request_bytes(
    uuid: [u8; 16],
    target_host: &str,
    target_port: u16,
    command: u8,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64 + target_host.len());

    // Version
    out.push(0x00);
    // UUID
    out.extend_from_slice(&uuid);
    // OptLen = 0
    out.push(0x00);
    // Command: 0x01 TCP / 0x02 UDP
    out.push(command);
    // Port (BE)
    out.extend_from_slice(&target_port.to_be_bytes());

    // Address
    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let host_bytes = target_host.as_bytes();
        if host_bytes.len() > 255 {
            return Err(anyhow!("目标域名过长（>255）"));
        }
        out.push(0x03);
        out.push(host_bytes.len() as u8);
        out.extend_from_slice(host_bytes);
    }

    Ok(out)
}

pub struct VlessConnector {
    server: String,
    port: u16,
    uuid: String,
    flow: Option<String>,
    /// REALITY 选项（G1-6 配置保留面；Some = 拨号期点名拒绝——rustls 无
    /// ClientHello 字节级控制，拒绝静默降级为普通 TLS）
    reality: Option<RealityConfig>,
    network: String,
    path: Option<String>,
    host: Option<Vec<String>>,
    grpc_service_name: Option<String>,
    tls: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
    /// 客户端 TLS 指纹形态（P2-5；None = rustls 缺省形态；仅 tls=true 时生效）
    fingerprint: TlsFingerprint,
    /// 出站连接池（P1-5 §4.2；None = 旧行为内联路径，D-9）
    pool: Option<Arc<TransportPool>>,
    /// 共享 ClientConfig 工厂：pool=None 且 tls 时使 TLS 会话恢复独立于池
    /// 生效（§3.1「块存在即生效」；None = 既有每流 ClientConfig）
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl VlessConnector {
    /// 参数面镜像 `EgressConfig::Vless` 字段 1:1，不收敛 options 结构
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        uuid: String,
        flow: Option<String>,
        reality: Option<RealityConfig>,
        network: String,
        path: Option<String>,
        host: Option<Vec<String>>,
        grpc_service_name: Option<String>,
        tls: bool,
        skip_cert_verify: bool,
        sni: Option<String>,
        alpn: Option<Vec<String>>,
        fingerprint: TlsFingerprint,
        pool: Option<Arc<TransportPool>>,
        factory: Option<Arc<TlsConnectorFactory>>,
    ) -> Self {
        Self {
            server,
            port,
            uuid,
            flow,
            reality,
            network,
            path,
            host,
            grpc_service_name,
            tls,
            skip_cert_verify,
            sni,
            alpn,
            fingerprint,
            pool,
            factory,
        }
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// REALITY/Vision 不支持面点名拒绝（G1-6 配置保留面）：配置保留至拨号
    /// 期在此拦——拒绝静默降级（普通 TLS 会被 REALITY 服务端回落伪装站点，
    /// 普通 VLESS 连不上期望 Vision 分帧的服务端且无报错）。
    fn gate_reality_and_flow(&self) -> Result<()> {
        gate_reality_flow(&self.reality, &self.flow)
    }

    /// 传输键（§4.2）：TLS 走五元组键（sni = 实际握手 SNI，tcp/ws 分支各异），
    /// 平文走 plain 键；alpn 规一化入键（D-2）。
    fn transport_key(&self, actual_sni: &str) -> TransportKey {
        if self.tls {
            TransportKey::tls(
                &self.server,
                self.port,
                Some(actual_sni),
                self.skip_cert_verify,
                self.alpn.as_deref().unwrap_or(&[]),
                self.fingerprint,
            )
        } else {
            TransportKey::plain(&self.server, self.port)
        }
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

    /// gRPC 服务名（network=grpc 必填；缺省/空串构建期由 runtime_builder
    /// 校验，此处运行期兜底）
    fn grpc_service_name(&self) -> Result<String> {
        self.grpc_service_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("VLESS gRPC 缺少 grpc_service_name"))
    }

    fn uuid_bytes(&self) -> Result<[u8; 16]> {
        let id = Uuid::parse_str(self.uuid.trim()).context("无效的 VLESS uuid")?;
        Ok(*id.as_bytes())
    }

    fn build_vless_tcp_request(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        build_vless_request_bytes(self.uuid_bytes()?, target_host, target_port, 0x01)
    }

    async fn read_vless_response_header<S: AsyncRead + Unpin + ?Sized>(
        stream: &mut S,
    ) -> Result<()> {
        // Response: Version(1) + OptLen(1) + Opt(OptLen)
        let mut hdr = [0u8; 2];
        stream
            .read_exact(&mut hdr)
            .await
            .context("读取 VLESS 响应头失败")?;
        let opt_len = hdr[1] as usize;
        if opt_len > 0 {
            let mut opt = vec![0u8; opt_len];
            stream
                .read_exact(&mut opt)
                .await
                .context("读取 VLESS 响应 Opt 失败")?;
        }
        Ok(())
    }
}

#[async_trait]
impl EgressConnector for VlessConnector {
    fn name(&self) -> &'static str {
        "vless"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        match &self.pool {
            Some(pool) => self.forward_pooled(flow, pool).await,
            None => self.forward_inline(flow).await,
        }
    }
}

impl VlessConnector {
    /// 池借出路径（§4.2）：acquire → 协议绑定（tcp = 请求头往返；ws = upgrade
    /// 借出后进行）→ 双向转发；绑定失败 → stale 一次性重拨（D-11）。
    async fn forward_pooled(
        &self,
        mut flow: Flow,
        pool: &Arc<TransportPool>,
    ) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            _ => return Err(anyhow!("VLESS 暂仅支持 TCP 转发")),
        }
        self.gate_reality_and_flow()?;

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_addr = self.server_addr();

        tracing::debug!(
            target: "seep::vless",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            tls = %self.tls,
            network = %self.network,
            pooled = true,
            "通过 VLESS 连接"
        );

        match self.network.as_str() {
            "tcp" => {
                let sni_actual = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let key = self.transport_key(&sni_actual);
                let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                let (mut stream, _lease) = pool
                    .acquire_bound(&key, |io| {
                        let req = req.clone();
                        Box::pin(async move {
                            io.write_all(&req).await?;
                            io.flush().await?;
                            Self::read_vless_response_header(io).await
                        })
                    })
                    .await
                    .with_context(|| format!("连接 VLESS 服务器失败: {server_addr}"))?;

                let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                    &mut flow.io,
                    &mut stream,
                    seep_core::performance::relay_buffer(),
                    seep_core::performance::relay_buffer(),
                )
                .await?;
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
                    .with_context(|| format!("连接 VLESS 服务器失败: {server_addr}"))?;
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
                self.relay_vless_over_ws(flow, ws).await
            }
            "httpupgrade" => {
                // upgrade 头与 ws 同语义；101 后裸流直读直写（无帧）
                let host_hdr = self.ws_host_header();
                let path = self.ws_path();
                let sni_actual = self.sni.clone().unwrap_or_else(|| host_hdr.clone());
                let key = self.transport_key(&sni_actual);

                // 借出传输层（TLS 已由池侧建立）；upgrade 握手借出后进行（§4.2）
                let (boxed, first_lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接 VLESS 服务器失败: {server_addr}"))?;
                let handshake = httpupgrade_client_handshake(boxed, &host_hdr, &path).await;
                let (stream, _lease) = match handshake {
                    Ok(s) => (s, first_lease),
                    Err(_) => {
                        // 握手首写首读失败 → stale 一次性重拨（D-11）
                        drop(first_lease);
                        pool.note_stale(&key);
                        let (boxed, lease) = pool.acquire_fresh(&key).await?;
                        let s = httpupgrade_client_handshake(boxed, &host_hdr, &path).await?;
                        (s, lease)
                    }
                };

                // 裸字节流协议段与 tcp/h2 同序：请求头直写、响应头直读、双向泵
                let mut stream = stream;
                let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                stream.write_all(&req).await?;
                stream.flush().await?;
                Self::read_vless_response_header(&mut stream).await?;

                let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                    &mut flow.io,
                    &mut stream,
                    seep_core::performance::relay_buffer(),
                    seep_core::performance::relay_buffer(),
                )
                .await?;
                Ok(FlowReport {
                    upstream: up,
                    downstream: down,
                })
            }
            "grpc" => {
                let service = self.grpc_service_name()?;
                // grpc 恒叠 TLS + ALPN h2（gRPC over TLS 语义），SNI 回退 server
                if !self.tls {
                    return Err(anyhow!("VLESS network=grpc 需叠 TLS（gRPC over TLS 语义）"));
                }
                let sni_actual = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let alpn_h2 = vec!["h2".to_string()];
                let key = TransportKey::tls(
                    &self.server,
                    self.port,
                    Some(&sni_actual),
                    self.skip_cert_verify,
                    &alpn_h2,
                    self.fingerprint,
                );

                // 借出传输层（TLS 已由池侧建立）；gRPC 隧道借出后进行（§4.2）
                let (boxed, first_lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接 VLESS 服务器失败: {server_addr}"))?;
                let tunnel = grpc_tunnel(boxed, &sni_actual, &service).await;
                let (tunnel, _lease) = match tunnel {
                    Ok(t) => (t, first_lease),
                    Err(_) => {
                        // 隧道握手失败 → stale 一次性重拨（D-11）
                        drop(first_lease);
                        pool.note_stale(&key);
                        let (boxed, lease) = pool.acquire_fresh(&key).await?;
                        let t = grpc_tunnel(boxed, &sni_actual, &service)
                            .await
                            .with_context(|| "VLESS over gRPC 隧道握手失败")?;
                        (t, lease)
                    }
                };
                self.relay_vless_over_grpc(flow, tunnel).await
            }
            "h2" => {
                // h2 恒叠 TLS + ALPN h2（mihomo 口径 h2 仅 TLS；authority/SNI
                // 回退链与 ws 同源：host 首值 → sni → server）
                if !self.tls {
                    return Err(anyhow!("VLESS network=h2 需叠 TLS（h2 over TLS 语义）"));
                }
                let h2_host = self.ws_host_header();
                let sni_actual = self.sni.clone().unwrap_or_else(|| h2_host.clone());
                let alpn_h2 = vec!["h2".to_string()];
                let key = TransportKey::tls(
                    &self.server,
                    self.port,
                    Some(&sni_actual),
                    self.skip_cert_verify,
                    &alpn_h2,
                    self.fingerprint,
                );

                // 借出传输层（TLS 已由池侧建立）；h2 隧道借出后进行（§4.2）
                let (boxed, first_lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接 VLESS 服务器失败: {server_addr}"))?;
                let tunnel = h2_tunnel(boxed, &h2_host, &self.ws_path()).await;
                let (mut stream, _lease) = match tunnel {
                    Ok(s) => (s, first_lease),
                    Err(_) => {
                        // 隧道握手失败 → stale 一次性重拨（D-11）
                        drop(first_lease);
                        pool.note_stale(&key);
                        let (boxed, lease) = pool.acquire_fresh(&key).await?;
                        let s = h2_tunnel(boxed, &h2_host, &self.ws_path())
                            .await
                            .with_context(|| "VLESS over h2 隧道握手失败")?;
                        (s, lease)
                    }
                };

                // 裸字节流协议段与 tcp 同序：请求头直写、响应头直读、双向泵
                let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                stream.write_all(&req).await?;
                stream.flush().await?;
                Self::read_vless_response_header(&mut stream).await?;

                let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                    &mut flow.io,
                    &mut stream,
                    seep_core::performance::relay_buffer(),
                    seep_core::performance::relay_buffer(),
                )
                .await?;
                Ok(FlowReport {
                    upstream: up,
                    downstream: down,
                })
            }
            other => Err(anyhow!("暂不支持的 VLESS network: {}", other)),
        }
    }

    /// 内联路径（pool=None）：与既有实现逐 IO 序列同构（D-9）；factory=Some
    /// 且 tls 时 TLS 连接器改取共享 ClientConfig（tls_resumption 独立于池生效）。
    async fn forward_inline(&self, mut flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            _ => return Err(anyhow!("VLESS 暂仅支持 TCP 转发")),
        }
        self.gate_reality_and_flow()?;

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_addr = self.server_addr();

        tracing::debug!(
            target: "seep::vless",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            tls = %self.tls,
            network = %self.network,
            "通过 VLESS 连接"
        );

        // net_mark 统一拨号（SO_MARK 逃逸面，networking.md §2；缺省 0 零差异）
        let mut tcp = seep_core::net_mark::connect_tcp(server_addr.clone())
            .await
            .with_context(|| format!("连接 VLESS 服务器失败: {}", server_addr))?;
        let _ = tcp.set_nodelay(true);

        match self.network.as_str() {
            "tcp" => {
                if self.tls {
                    let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
                    let connector = match &self.factory {
                        Some(factory) => factory.connector(
                            self.skip_cert_verify,
                            self.alpn.as_deref().unwrap_or(&[]),
                            self.fingerprint,
                        )?,
                        None => create_tls_connector_with_profile(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
                            self.fingerprint,
                        )?,
                    };
                    let server_name =
                        rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                    let mut stream = connector.connect(server_name, tcp).await?;

                    let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                    stream.write_all(&req).await?;
                    stream.flush().await?;
                    Self::read_vless_response_header(&mut stream).await?;

                    let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                        &mut flow.io,
                        &mut stream,
                        seep_core::performance::relay_buffer(),
                        seep_core::performance::relay_buffer(),
                    )
                    .await?;
                    Ok(FlowReport {
                        upstream: up,
                        downstream: down,
                    })
                } else {
                    let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                    tcp.write_all(&req).await?;
                    tcp.flush().await?;
                    Self::read_vless_response_header(&mut tcp).await?;

                    let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                        &mut flow.io,
                        &mut tcp,
                        seep_core::performance::relay_buffer(),
                        seep_core::performance::relay_buffer(),
                    )
                    .await?;
                    Ok(FlowReport {
                        upstream: up,
                        downstream: down,
                    })
                }
            }
            "ws" | "websocket" => {
                let ws_host = self.ws_host_header();
                let ws_path = self.ws_path();

                if self.tls {
                    let sni = self.sni.clone().unwrap_or_else(|| ws_host.clone());
                    let connector = match &self.factory {
                        Some(factory) => factory.connector(
                            self.skip_cert_verify,
                            self.alpn.as_deref().unwrap_or(&[]),
                            self.fingerprint,
                        )?,
                        None => create_tls_connector_with_profile(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
                            self.fingerprint,
                        )?,
                    };
                    let server_name =
                        rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                    let tls_stream = connector.connect(server_name, tcp).await?;
                    self.forward_vless_over_ws(flow, tls_stream, ws_host, ws_path)
                        .await
                } else {
                    self.forward_vless_over_ws(flow, tcp, ws_host, ws_path)
                        .await
                }
            }
            "httpupgrade" => {
                // upgrade 头与 ws 同语义；101 后裸流直读直写（无帧）
                let host_hdr = self.ws_host_header();
                let path = self.ws_path();

                if self.tls {
                    let sni = self.sni.clone().unwrap_or_else(|| host_hdr.clone());
                    let connector = match &self.factory {
                        Some(factory) => factory.connector(
                            self.skip_cert_verify,
                            self.alpn.as_deref().unwrap_or(&[]),
                            self.fingerprint,
                        )?,
                        None => create_tls_connector_with_profile(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
                            self.fingerprint,
                        )?,
                    };
                    let server_name =
                        rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                    let tls_stream = connector.connect(server_name, tcp).await?;
                    self.forward_vless_over_httpupgrade(flow, tls_stream, host_hdr, path)
                        .await
                } else {
                    self.forward_vless_over_httpupgrade(flow, tcp, host_hdr, path)
                        .await
                }
            }
            "grpc" => {
                let service = self.grpc_service_name()?;
                // grpc 恒叠 TLS + ALPN h2（gRPC over TLS 语义），SNI 回退 server
                if !self.tls {
                    return Err(anyhow!("VLESS network=grpc 需叠 TLS（gRPC over TLS 语义）"));
                }
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
                let tls_stream = connector.connect(server_name, tcp).await?;

                let tunnel = grpc_tunnel(tls_stream, &sni, &service)
                    .await
                    .with_context(|| "VLESS over gRPC 隧道握手失败")?;
                self.relay_vless_over_grpc(flow, tunnel).await
            }
            "h2" => {
                // h2 恒叠 TLS + ALPN h2（mihomo 口径 h2 仅 TLS）
                if !self.tls {
                    return Err(anyhow!("VLESS network=h2 需叠 TLS（h2 over TLS 语义）"));
                }
                let h2_host = self.ws_host_header();
                let sni = self.sni.clone().unwrap_or_else(|| h2_host.clone());
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
                    rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                let tls_stream = connector.connect(server_name, tcp).await?;

                let mut stream = h2_tunnel(tls_stream, &h2_host, &self.ws_path())
                    .await
                    .with_context(|| "VLESS over h2 隧道握手失败")?;
                let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                stream.write_all(&req).await?;
                stream.flush().await?;
                Self::read_vless_response_header(&mut stream).await?;

                let (up, down) = tokio::io::copy_bidirectional_with_sizes(
                    &mut flow.io,
                    &mut stream,
                    seep_core::performance::relay_buffer(),
                    seep_core::performance::relay_buffer(),
                )
                .await?;
                Ok(FlowReport {
                    upstream: up,
                    downstream: down,
                })
            }
            other => Err(anyhow!("暂不支持的 VLESS network: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// UDP 数据面（G0-4）：command 0x02 + 每报 [2B BE len][payload]
// ---------------------------------------------------------------------------

/// VLESS 明文/TLS over tcp 传输上的 UDP 出站连接器（udp-relay-path.md §3.1
/// 能力表扩展）。数据面 = xray vless `MultiLengthPacketWriter`/`LengthPacketReader`
/// （proxy/vless/encoding/addons.go）：每个 UDP 数据报 = [2B BE 载荷长度][载荷]，
/// 单目标单连接（会话目标即请求头目标）。
///
/// 仅 network=tcp 注册（ws/grpc/h2 与 flow=XTLS-Vision 的 UDP 面构建期由
/// scan_udp_capability 判负）。
pub struct VlessUdpConnector {
    server: String,
    port: u16,
    uuid: String,
    flow: Option<String>,
    reality: Option<RealityConfig>,
    tls: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
    fingerprint: TlsFingerprint,
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl VlessUdpConnector {
    /// 从已校验的 TCP 连接器复用节点配置（保证 UDP 面与 TCP 面同一份配置）
    pub fn from_connector(conn: &VlessConnector) -> Self {
        Self {
            server: conn.server.clone(),
            port: conn.port,
            uuid: conn.uuid.clone(),
            flow: conn.flow.clone(),
            reality: conn.reality.clone(),
            tls: conn.tls,
            skip_cert_verify: conn.skip_cert_verify,
            sni: conn.sni.clone(),
            alpn: conn.alpn.clone(),
            fingerprint: conn.fingerprint,
            factory: conn.factory.clone(),
        }
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// 建立明文/TLS over tcp 的 boxed 传输（UDP 长连，不走连接池）
    async fn open_transport(&self) -> Result<BoxedIo> {
        let tcp = seep_core::net_mark::connect_tcp(self.server_addr())
            .await
            .with_context(|| format!("连接 VLESS 服务器失败: {}", self.server_addr()))?;
        let _ = tcp.set_nodelay(true);
        if !self.tls {
            return Ok(Box::new(tcp));
        }
        let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
        let connector = match &self.factory {
            Some(f) => f.connector(
                self.skip_cert_verify,
                self.alpn.as_deref().unwrap_or(&[]),
                self.fingerprint,
            )?,
            None => create_tls_connector_with_profile(
                self.skip_cert_verify,
                self.alpn.as_deref(),
                self.fingerprint,
            )?,
        };
        let server_name = rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
        Ok(Box::new(connector.connect(server_name, tcp).await?))
    }
}

#[async_trait]
impl EgressUdpConnector for VlessUdpConnector {
    fn name(&self) -> &str {
        "vless"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        gate_reality_flow(&self.reality, &self.flow)?;
        let mut stream = self.open_transport().await?;
        let req = self.build_vless_udp_request(&ctx.target.host, ctx.target.port)?;
        stream.write_all(&req).await?;
        stream.flush().await?;
        let (mut rr, ww) = tokio::io::split(stream);
        VlessConnector::read_vless_response_header(&mut rr).await?;
        Ok(Arc::new(VlessUdpRelay {
            reader: AsyncMutex::new(rr),
            writer: AsyncMutex::new(ww),
            target: ctx.target,
        }))
    }
}

impl VlessUdpConnector {
    /// UDP 请求（G0-4）：command 0x02（xray vless RequestCommandUDP）
    fn build_vless_udp_request(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        build_vless_request_bytes(self.uuid_bytes()?, target_host, target_port, 0x02)
    }

    fn uuid_bytes(&self) -> Result<[u8; 16]> {
        let id = Uuid::parse_str(self.uuid.trim()).context("无效的 VLESS uuid")?;
        Ok(*id.as_bytes())
    }
}

/// 字节级 VLESS UDP relay（G0-4）：每报 [2B BE len][payload]。
/// send/recv 分属 forward_up/forwarder 两任务，读写半各持 tokio Mutex。
struct VlessUdpRelay {
    reader: AsyncMutex<tokio::io::ReadHalf<BoxedIo>>,
    writer: AsyncMutex<tokio::io::WriteHalf<BoxedIo>>,
    /// 会话绑定的目标（VLESS 明文 UDP 单目标/单连接，映射目标即此）
    target: FlowTarget,
}

#[async_trait]
impl UdpRelay for VlessUdpRelay {
    async fn send_to(&self, _target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let mut w = self.writer.lock().await;
        if buf.len() > u16::MAX as usize {
            return Err(anyhow!("VLESS UDP 数据报过大（>65535）"));
        }
        let len = buf.len() as u16;
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(buf).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut r = self.reader.lock().await;
        let mut len_b = [0u8; 2];
        r.read_exact(&mut len_b).await?;
        let len = u16::from_be_bytes(len_b) as usize;
        let n = len.min(buf.len());
        r.read_exact(&mut buf[..n]).await?;
        // 上游长度超出调用方缓冲：丢弃余量，保流对齐
        if len > n {
            let mut skip = vec![0u8; len - n];
            r.read_exact(&mut skip).await?;
        }
        Ok((self.target.clone(), n))
    }
}

impl fmt::Debug for VlessUdpRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessUdpRelay")
            .field("target", &self.target)
            .finish()
    }
}

impl VlessConnector {
    async fn forward_vless_over_ws<S>(
        &self,
        flow: Flow,
        stream: S,
        ws_host: String,
        ws_path: String,
    ) -> Result<FlowReport>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ws = ws_client_handshake(stream, &ws_host, &ws_path).await?;
        self.relay_vless_over_ws(flow, ws).await
    }

    /// VLESS over HTTPUpgrade：upgrade 握手后协议段走裸字节流（与 tcp
    /// 同序：请求头直写、响应头直读、双向泵——无 WS 帧收发）
    async fn forward_vless_over_httpupgrade<S>(
        &self,
        mut flow: Flow,
        stream: S,
        host_hdr: String,
        path: String,
    ) -> Result<FlowReport>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut stream = httpupgrade_client_handshake(stream, &host_hdr, &path).await?;
        let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
        stream.write_all(&req).await?;
        stream.flush().await?;
        Self::read_vless_response_header(&mut stream).await?;

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            seep_core::performance::relay_buffer(),
            seep_core::performance::relay_buffer(),
        )
        .await?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }

    /// VLESS over WS 双向转发（upgrade 完成后的协议段；池路径复用——
    /// `WsClient<ReadHalf<BoxedIo>, WriteHalf<BoxedIo>>` 同型可用）。
    async fn relay_vless_over_ws<R, W>(
        &self,
        flow: Flow,
        mut ws: WsClient<R, W>,
    ) -> Result<FlowReport>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        // Send VLESS request as first binary message.
        let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
        ws.write_binary(&req).await?;

        // Read and discard VLESS response header from incoming WS byte stream.
        let mut buf = BytesMut::new();
        let mut hdr = [0u8; 2];
        ws.read_exact(&mut buf, &mut hdr).await?;
        let opt_len = hdr[1] as usize;
        if opt_len > 0 {
            let mut opt = vec![0u8; opt_len];
            ws.read_exact(&mut buf, &mut opt).await?;
        }

        // Split client IO for concurrent copy.
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
            tokio::try_join!(up_task, down_task).context("VLESS over WS 双向转发任务失败")?;
        let up = up?;
        let down = down?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }

    /// VLESS over gRPC 双向转发（请求头 = 首条 gRPC 消息；响应头 [ver][opt_len]
    /// [+opt] 经跨消息 read_exact 抽取；客户端 EOF → 零长 DATA + END_STREAM
    /// 收尾——服务端按流对目标侧收尾，下行侧经 message None 语义同步收敛）。
    async fn relay_vless_over_grpc(
        &self,
        flow: Flow,
        tunnel: super::grpc::GrpcTunnel,
    ) -> Result<FlowReport> {
        let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
        let (mut grpc_r, mut grpc_w) = tunnel.split();
        grpc_w.message(&req).await?;

        // 响应头：Version(1) + OptLen(1) + Opt(OptLen)（跨消息边界拼凑）
        let mut hdr = [0u8; 2];
        grpc_r.read_exact(&mut hdr).await?;
        let opt_len = hdr[1] as usize;
        if opt_len > 0 {
            let mut opt = vec![0u8; opt_len];
            grpc_r.read_exact(&mut opt).await?;
        }

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
            tokio::try_join!(up_task, down_task).context("VLESS over gRPC 双向转发任务失败")?;
        let up = up?;
        let down = down?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use seep_core::{Flow, FlowId, FlowMetadata, FlowTarget, RouteDecision, TargetProto};
    use sha1::{Digest, Sha1};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TEST_UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";

    fn test_connector(port: u16) -> VlessConnector {
        VlessConnector::new(
            "127.0.0.1".to_string(),
            port,
            TEST_UUID.to_string(),
            None,
            None,
            "tcp".to_string(),
            None,
            None,
            None,
            false, // tls
            false,
            None,
            None,
            TlsFingerprint::None,
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
        let decision = RouteDecision::direct("test".to_string());
        (ctx, decision)
    }

    /// 读取 VLESS 请求头（version + uuid + opt + cmd + port + address），返回
    /// (uuid, command, host, port)。校验 version=0、optlen=0。
    async fn parse_vless_request<S>(stream: &mut S) -> Result<([u8; 16], u8, String, u16)>
    where
        S: AsyncRead + Unpin,
    {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await?;
        assert_eq!(ver[0], 0x00, "VLESS 请求版本应为 0");
        let mut uuid = [0u8; 16];
        stream.read_exact(&mut uuid).await?;
        let mut optlen = [0u8; 1];
        stream.read_exact(&mut optlen).await?;
        assert_eq!(optlen[0], 0x00, "VLESS 请求 OptLen 应为 0");
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        let mut port_b = [0u8; 2];
        stream.read_exact(&mut port_b).await?;
        let port = u16::from_be_bytes(port_b);
        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await?;
        let host = match atyp[0] {
            0x01 => {
                let mut b = [0u8; 4];
                stream.read_exact(&mut b).await?;
                std::net::Ipv4Addr::from(b).to_string()
            }
            0x04 => {
                let mut b = [0u8; 16];
                stream.read_exact(&mut b).await?;
                std::net::Ipv6Addr::from(b).to_string()
            }
            0x03 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await?;
                let mut h = vec![0u8; l[0] as usize];
                stream.read_exact(&mut h).await?;
                String::from_utf8_lossy(&h).into_owned()
            }
            other => anyhow::bail!("VLESS 未知地址类型: {other}"),
        };
        Ok((uuid, cmd[0], host, port))
    }

    /// VLESS UDP 回环服务端（G0-4）：断言命令 0x02 + 目标；应答头
    /// [0x00][0x00]；逐报 [2B len][payload] echo（rounds 次）。
    async fn serve_vless_udp<S>(mut stream: S, rounds: usize) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (uuid, cmd, host, port) = parse_vless_request(&mut stream).await?;
        assert_eq!(cmd, 0x02, "VLESS UDP 请求命令应为 0x02");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        let expect_uuid: [u8; 16] = *Uuid::parse_str(TEST_UUID).unwrap().as_bytes();
        assert_eq!(uuid, expect_uuid, "UUID 不匹配");

        // 响应头：version=0 + optlen=0
        stream.write_all(&[0x00, 0x00]).await?;
        stream.flush().await?;

        for _ in 0..rounds {
            let mut len_b = [0u8; 2];
            stream.read_exact(&mut len_b).await?;
            let len = u16::from_be_bytes(len_b) as usize;
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await?;
            stream.write_all(&len_b).await?;
            stream.write_all(&payload).await?;
            stream.flush().await?;
        }
        Ok(())
    }

    /// G0-4：VLESS 明文 UDP 回环（command 0x02，[2B len][payload] 帧）。
    #[tokio::test]
    async fn udp_loopback_command_02() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        const ROUNDS: usize = 2;
        tokio::spawn(async move {
            let (st, _) = listener.accept().await.unwrap();
            if let Err(e) = serve_vless_udp(st, ROUNDS).await {
                eprintln!("测试服务端错误: {e:#}");
            }
        });

        let connector = VlessUdpConnector::from_connector(&test_connector(port));
        let (ctx, decision) = test_ctx();
        let relay = connector.associate(ctx.clone(), &decision).await.unwrap();

        let msgs: Vec<Vec<u8>> = vec![b"hello udp vless".to_vec(), vec![5u8; 20 * 1024]];
        for m in &msgs {
            relay.send_to(&ctx.target, m).await.unwrap();
            let mut buf = vec![0u8; m.len() + 64];
            let (tgt, n) = relay.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &m[..], "VLESS UDP 回环载荷不一致");
            assert_eq!(tgt.host, "example.com");
            assert_eq!(tgt.port, 443);
            assert_eq!(tgt.proto, TargetProto::Udp);
        }
    }

    /// httpupgrade 传输回环服务端（G2-15/G3-16）：upgrade 握手（请求头
    /// 与 ws 同语义，101+accept 复刻 xray httpupgrade 服务端形）→ 101 后
    /// 裸流直入协议段：VLESS 头（与 tcp 同序）+ 原样 echo。
    async fn serve_vless_httpupgrade<S>(mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("httpupgrade 握手中连接关闭");
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("GET /hp HTTP/1.1"), "请求行不符: {text}");
        assert!(text.contains("Host: h.test"), "缺 Host 头: {text}");
        for expect in ["upgrade: websocket", "connection: upgrade"] {
            assert!(
                text.to_ascii_lowercase().contains(expect),
                "缺头 {expect}: {text}"
            );
        }
        let key = text
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("sec-websocket-key")
                    .then(|| v.trim().to_string())
            })
            .ok_or_else(|| anyhow!("缺 Sec-WebSocket-Key"))?;
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(super::super::ws::WS_MAGIC.as_bytes());
        let accept = BASE64.encode(hasher.finalize());
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;

        // 协议段：VLESS 请求头（tcp 同序）→ 响应头 → 原样 echo
        let (_uuid, cmd, host, port) = parse_vless_request(&mut stream).await?;
        assert_eq!(cmd, 0x01, "应为 TCP 命令");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        stream.write_all(&[0x00, 0x00]).await?;
        stream.flush().await?;

        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            stream.write_all(&chunk[..n]).await?;
            stream.flush().await?;
        }
        Ok(())
    }

    /// G2-15/G3-16：VLESS over httpupgrade 回环（明文；101 后裸流直读直写，
    /// 请求头直写/响应头直读与 tcp 同序）。
    #[tokio::test]
    async fn echo_loopback_httpupgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (st, _) = listener.accept().await.unwrap();
            if let Err(e) = serve_vless_httpupgrade(st).await {
                eprintln!("测试服务端错误: {e:#}");
            }
        });

        let (client_io, mut test_end) = tokio::io::duplex(256 * 1024);
        let connector = VlessConnector::new(
            "127.0.0.1".to_string(),
            port,
            TEST_UUID.to_string(),
            None,
            None,
            "httpupgrade".to_string(),
            Some("/hp".to_string()),
            Some(vec!["h.test".to_string()]),
            None,
            false, // tls
            false,
            None,
            None,
            TlsFingerprint::None,
            None,
            None,
        );
        let flow = Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(client_io),
            metadata: FlowMetadata::default(),
        };
        let fwd = connector.forward(flow);
        let outcome = tokio::time::timeout(Duration::from_secs(10), async move {
            tokio::join!(fwd, async {
                test_end
                    .write_all(b"hello vless httpupgrade")
                    .await
                    .unwrap();
                let mut buf = [0u8; 23];
                test_end.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello vless httpupgrade");

                let big = vec![7u8; 40 * 1024];
                test_end.write_all(&big).await.unwrap();
                let mut rb = vec![0u8; big.len()];
                test_end.read_exact(&mut rb).await.unwrap();
                assert_eq!(rb, big);

                // 半关写侧：裸流转发的双向泵以 EOF 收敛（vless 无帧
                // 协议的带内终止语义，EOF 即收尾信号）
                test_end.shutdown().await.unwrap();
            })
        })
        .await
        .expect("回环超时");
        let (report, ()) = outcome;
        let report = report.expect("forward 失败");
        assert!(report.upstream >= 40 * 1024 + 23);
        assert!(report.downstream >= 40 * 1024 + 23);
    }

    /// G1-6 拨号期门（防静默降级）：REALITY 连接器 forward 必须在任何网络
    /// I/O 前点名报错——若静默降级为普通 TLS，REALITY 服务端会按非 REALITY
    /// 握手回落伪装站点，流量不走向代理且无任何报错。duplex io 足以证明
    /// 门先于 connect 触发（端口不可达，真 connect 必报连接错而非点名）。
    #[tokio::test]
    async fn forward_rejects_reality_named_before_io() {
        let connector = VlessConnector::new(
            "127.0.0.1".to_string(),
            1, // 不可达端口：门未先拦时必然是连接失败而非点名 REALITY
            TEST_UUID.to_string(),
            None,
            Some(RealityConfig {
                public_key: "PBQh7j2tWxQmZHVub3RUYXJnZXQ".to_string(),
                short_id: Some("0123ac".to_string()),
            }),
            "tcp".to_string(),
            None,
            None,
            None,
            true,
            true, // skip_cert_verify 亦不绕过门
            None,
            None,
            TlsFingerprint::None,
            None,
            None,
        );
        let (client, _peer) = tokio::io::duplex(64);
        let flow = Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(client),
            metadata: FlowMetadata::default(),
        };
        let err = connector.forward(flow).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("REALITY"), "应点名 REALITY: {msg}");
        assert!(msg.contains("未实现"), "应说明未实现而非连接失败: {msg}");
    }

    /// G1-6 拨号期门：flow（XTLS-Vision）连接器 forward 点名报错——
    /// 静默降级为普通 VLESS 连不上期望 Vision 分帧的服务端且无报错。
    #[tokio::test]
    async fn forward_rejects_flow_named_before_io() {
        let connector = VlessConnector::new(
            "127.0.0.1".to_string(),
            1, // 不可达端口：门未先拦时必然是连接失败而非点名 flow
            TEST_UUID.to_string(),
            Some("xtls-rprx-vision".to_string()),
            None,
            "tcp".to_string(),
            None,
            None,
            None,
            true,
            true,
            None,
            None,
            TlsFingerprint::None,
            None,
            None,
        );
        let (client, _peer) = tokio::io::duplex(64);
        let flow = Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(client),
            metadata: FlowMetadata::default(),
        };
        let err = connector.forward(flow).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("xtls-rprx-vision"), "应点名 flow 值: {msg}");
    }

    /// G1-6 UDP 面（command 0x02）同门：REALITY UDP 关联在 associate 期点名拒绝。
    #[tokio::test]
    async fn udp_associate_rejects_reality_named() {
        let conn = VlessConnector::new(
            "127.0.0.1".to_string(),
            1,
            TEST_UUID.to_string(),
            None,
            Some(RealityConfig {
                public_key: "PBQh7j2tWxQmZHVub3RUYXJnZXQ".to_string(),
                short_id: None,
            }),
            "tcp".to_string(),
            None,
            None,
            None,
            true,
            false,
            None,
            None,
            TlsFingerprint::None,
            None,
            None,
        );
        let udp = VlessUdpConnector::from_connector(&conn);
        let (ctx, decision) = test_ctx();
        let err = udp
            .associate(ctx, &decision)
            .await
            .err()
            .expect("REALITY UDP 应被点名拒绝");
        let msg = format!("{err:#}");
        assert!(msg.contains("REALITY"), "应点名 REALITY: {msg}");
    }
}
