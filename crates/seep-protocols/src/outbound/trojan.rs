//! Trojan 出口连接器实现

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    /// 构建 Trojan 请求头
    fn build_request(&self, host: &str, port: u16) -> Vec<u8> {
        let hash = self.password_hash();
        let mut request = Vec::with_capacity(256);

        // 密码哈希 (56 bytes hex)
        request.extend_from_slice(hash.as_bytes());

        // CRLF
        request.extend_from_slice(b"\r\n");

        // CMD: CONNECT (0x01)
        request.push(0x01);

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

        request
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
                let request = self.build_request(&flow.target.host, flow.target.port);
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
                let request = self.build_request(&flow.target.host, flow.target.port);
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
        let req = self.build_request(&flow.target.host, flow.target.port);
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
        let req = self.build_request(&flow.target.host, flow.target.port);
        ws.write_binary(&req).await?;

        // 双向泵（与 vless relay 同构，去 VLESS 应答头段——trojan 无应答头）
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
