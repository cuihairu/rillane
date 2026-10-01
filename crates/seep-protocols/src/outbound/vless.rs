//! VLESS 出口连接器实现（TCP/TLS/WS）

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::BytesMut;
use rand::{rngs::OsRng, RngCore};
use seep_core::{EgressConnector, Flow, FlowReport, TargetProto};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use uuid::Uuid;

use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_alpn, TlsConnectorFactory};

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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
                        )?,
                        None => create_tls_connector_with_alpn(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
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
                        )?,
                        None => create_tls_connector_with_alpn(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
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

struct WsClient<R, W> {
    reader: WsReader<R>,
    writer: WsWriter<W>,
}

impl<R, W> WsClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn split(self) -> (WsReader<R>, WsWriter<W>) {
        (self.reader, self.writer)
    }

    async fn read_exact(&mut self, stash: &mut BytesMut, out: &mut [u8]) -> Result<()> {
        while stash.len() < out.len() {
            let Some(msg) = self.reader.read_binary().await? else {
                return Err(anyhow!("WebSocket 连接已关闭"));
            };
            stash.extend_from_slice(&msg);
        }
        out.copy_from_slice(&stash.split_to(out.len()));
        Ok(())
    }

    async fn write_binary(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_binary(data).await
    }
}

async fn ws_client_handshake<S>(
    mut stream: S,
    host: &str,
    path: &str,
) -> Result<WsClient<tokio::io::ReadHalf<S>, tokio::io::WriteHalf<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut key_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut key_bytes);
    let key = BASE64.encode(key_bytes);

    let mut req = String::with_capacity(512);
    req.push_str("GET ");
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\n");
    req.push_str("Host: ");
    req.push_str(host);
    req.push_str("\r\n");
    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Connection: Upgrade\r\n");
    req.push_str("Sec-WebSocket-Key: ");
    req.push_str(&key);
    req.push_str("\r\n");
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    req.push_str("User-Agent: seep\r\n\r\n");

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut resp = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("WebSocket 握手连接意外关闭"));
        }
        resp.extend_from_slice(&tmp[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if resp.len() > 16 * 1024 {
            return Err(anyhow!("WebSocket 握手响应过大"));
        }
    }

    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or_else(|| anyhow!("WebSocket 握手响应解析失败（无头部结束符）"))?;
    let leftover = resp.split_off(header_end);

    let header_block = String::from_utf8_lossy(&resp);
    let mut lines = header_block.lines();

    let status = lines
        .next()
        .ok_or_else(|| anyhow!("WebSocket 握手响应缺少状态行"))?;
    if !status.starts_with("HTTP/1.1 101") && !status.starts_with("HTTP/1.0 101") {
        return Err(anyhow!("WebSocket 握手失败：{}", status));
    }

    let mut accept: Option<String> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("sec-websocket-accept") {
                accept = Some(v.trim().to_string());
            }
        }
    }

    let accept = accept.ok_or_else(|| anyhow!("WebSocket 握手响应缺少 Sec-WebSocket-Accept"))?;
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_MAGIC.as_bytes());
    let expected = BASE64.encode(hasher.finalize());
    if accept != expected {
        return Err(anyhow!("WebSocket 握手响应 Sec-WebSocket-Accept 不匹配"));
    }

    let (read_half, write_half) = tokio::io::split(stream);
    let reader = WsReader::new(read_half, leftover);
    let writer = WsWriter::new(write_half);
    Ok(WsClient { reader, writer })
}

struct WsReader<R> {
    stream: R,
    stash: BytesMut,
    pong_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
}

impl<R> WsReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(stream: R, stash: BytesMut) -> Self {
        Self {
            stream,
            stash,
            pong_tx: None,
        }
    }

    fn set_pong_sender(&mut self, tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) {
        self.pong_tx = Some(tx);
    }

    async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        if self.stash.len() >= out.len() {
            out.copy_from_slice(&self.stash.split_to(out.len()));
            return Ok(());
        }

        let mut copied = 0usize;
        if !self.stash.is_empty() {
            let n = out.len().min(self.stash.len());
            out[..n].copy_from_slice(&self.stash.split_to(n));
            copied = n;
        }

        self.stream.read_exact(&mut out[copied..]).await?;
        Ok(())
    }

    async fn read_binary(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let frame = self.read_frame().await?;
            let Some(frame) = frame else {
                return Ok(None);
            };
            match frame.opcode {
                0x2 => return Ok(Some(frame.payload)),
                0x0 => return Ok(Some(frame.payload)),
                0x8 => return Ok(None),
                0x9 => {
                    if let Some(tx) = &self.pong_tx {
                        let _ = tx.send(frame.payload);
                    }
                    continue;
                }
                0xA => continue,
                _ => continue,
            }
        }
    }

    async fn read_frame(&mut self) -> Result<Option<WsFrame>> {
        let mut hdr = [0u8; 2];
        match self.read_exact(&mut hdr).await {
            Ok(()) => {}
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|ioe| ioe.kind() == std::io::ErrorKind::UnexpectedEof) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }

        let opcode = hdr[0] & 0x0f;
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7f) as u64;

        if len == 126 {
            let mut ext = [0u8; 2];
            self.read_exact(&mut ext).await?;
            len = u16::from_be_bytes(ext) as u64;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            self.read_exact(&mut ext).await?;
            len = u64::from_be_bytes(ext);
        }

        if len > 16 * 1024 * 1024 {
            return Err(anyhow!("WebSocket 帧过大（>16MiB）"));
        }

        let mut mask_key = [0u8; 4];
        if masked {
            self.read_exact(&mut mask_key).await?;
        }

        let mut payload = vec![0u8; len as usize];
        self.read_exact(&mut payload).await?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask_key[i % 4];
            }
        }

        Ok(Some(WsFrame { opcode, payload }))
    }
}

struct WsWriter<W> {
    stream: W,
}

impl<W> WsWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(stream: W) -> Self {
        Self { stream }
    }

    async fn write_binary(&mut self, data: &[u8]) -> Result<()> {
        write_ws_message(&mut self.stream, 0x2, data).await
    }

    async fn write_pong(&mut self, data: &[u8]) -> Result<()> {
        write_ws_message(&mut self.stream, 0xA, data).await
    }
}

struct WsFrame {
    opcode: u8,
    payload: Vec<u8>,
}

async fn write_ws_message<S>(stream: &mut S, opcode: u8, data: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // Fragment large messages to keep memory bounded on intermediates.
    const CHUNK: usize = 16 * 1024;
    if data.len() <= CHUNK {
        write_ws_frame(stream, true, opcode, data).await?;
        stream.flush().await?;
        return Ok(());
    }

    let mut first = true;
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + CHUNK).min(data.len());
        let fin = end == data.len();
        let op = if first { opcode } else { 0x0 };
        write_ws_frame(stream, fin, op, &data[offset..end]).await?;
        first = false;
        offset = end;
    }
    stream.flush().await?;
    Ok(())
}

async fn write_ws_frame<S>(stream: &mut S, fin: bool, opcode: u8, payload: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut header = Vec::with_capacity(14);
    let b0 = (if fin { 0x80 } else { 0x00 }) | (opcode & 0x0f);
    header.push(b0);

    // Client-to-server must be masked.
    let mask_bit = 0x80u8;
    let len = payload.len();
    if len <= 125 {
        header.push(mask_bit | (len as u8));
    } else if len <= 65535 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }

    let mut mask = [0u8; 4];
    OsRng.fill_bytes(&mut mask);
    header.extend_from_slice(&mask);

    let mut masked = payload.to_vec();
    for (i, b) in masked.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }

    stream.write_all(&header).await?;
    stream.write_all(&masked).await?;
    Ok(())
}
