//! VLESS 出口连接器实现（TCP/TLS/WS）

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use seep_core::{EgressConnector, Flow, FlowReport, TargetProto};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use uuid::Uuid;

use super::ws::{ws_client_handshake, WsClient};
use crate::fingerprint::TlsFingerprint;
use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};

pub struct VlessConnector {
    server: String,
    port: u16,
    uuid: String,
    flow: Option<String>,
    network: String,
    path: Option<String>,
    host: Option<Vec<String>>,
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
        network: String,
        path: Option<String>,
        host: Option<Vec<String>>,
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
            network,
            path,
            host,
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

    fn uuid_bytes(&self) -> Result<[u8; 16]> {
        let id = Uuid::parse_str(self.uuid.trim()).context("无效的 VLESS uuid")?;
        Ok(*id.as_bytes())
    }

    fn build_vless_tcp_request(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        let uuid = self.uuid_bytes()?;
        let mut out = Vec::with_capacity(64 + target_host.len());

        // Version
        out.push(0x00);
        // UUID
        out.extend_from_slice(&uuid);
        // OptLen = 0
        out.push(0x00);
        // Command: TCP = 0x01
        out.push(0x01);
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
        if self.flow.is_some() {
            return Err(anyhow!(
                "VLESS 暂不支持 flow（例如 xtls-rprx-vision），请设置为 null/省略"
            ));
        }

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

                let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut stream).await?;
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
        if self.flow.is_some() {
            return Err(anyhow!(
                "VLESS 暂不支持 flow（例如 xtls-rprx-vision），请设置为 null/省略"
            ));
        }

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

        let mut tcp = TcpStream::connect(&server_addr)
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

                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut flow.io, &mut stream).await?;
                    Ok(FlowReport {
                        upstream: up,
                        downstream: down,
                    })
                } else {
                    let req = self.build_vless_tcp_request(&flow.target.host, flow.target.port)?;
                    tcp.write_all(&req).await?;
                    tcp.flush().await?;
                    Self::read_vless_response_header(&mut tcp).await?;

                    let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut tcp).await?;
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
            other => Err(anyhow!("暂不支持的 VLESS network: {}", other)),
        }
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

        let (pong_tx, mut pong_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
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
}
