//! WebSocket 客户端传输面（vless/vmess 共用）
//!
//! 自 vless.rs 抽出（VMess 出站接入时共用同一 upgrade/帧收发面）；
//! 行为与抽取前逐字节同构：upgrade 握手（SHA1 accept 校验）、帧解析
//! （binary/continuation/close/ping→pong、16MiB 上限、客户端掩码）、
//! 16KiB 分片发送。

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::BytesMut;
use rand::{rngs::OsRng, RngCore};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) struct WsClient<R, W> {
    pub(crate) reader: WsReader<R>,
    pub(crate) writer: WsWriter<W>,
}

impl<R, W> WsClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) fn split(self) -> (WsReader<R>, WsWriter<W>) {
        (self.reader, self.writer)
    }

    pub(crate) async fn read_exact(&mut self, stash: &mut BytesMut, out: &mut [u8]) -> Result<()> {
        while stash.len() < out.len() {
            let Some(msg) = self.reader.read_binary().await? else {
                return Err(anyhow!("WebSocket 连接已关闭"));
            };
            stash.extend_from_slice(&msg);
        }
        out.copy_from_slice(&stash.split_to(out.len()));
        Ok(())
    }

    pub(crate) async fn write_binary(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_binary(data).await
    }
}

pub(crate) async fn ws_client_handshake<S>(
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

pub(crate) struct WsReader<R> {
    pub(crate) stream: R,
    pub(crate) stash: BytesMut,
    pong_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
}

impl<R> WsReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn new(stream: R, stash: BytesMut) -> Self {
        Self {
            stream,
            stash,
            pong_tx: None,
        }
    }

    pub(crate) fn set_pong_sender(&mut self, tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) {
        self.pong_tx = Some(tx);
    }

    pub(crate) async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
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

    pub(crate) async fn read_binary(&mut self) -> Result<Option<Vec<u8>>> {
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

pub(crate) struct WsWriter<W> {
    pub(crate) stream: W,
}

impl<W> WsWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(stream: W) -> Self {
        Self { stream }
    }

    pub(crate) async fn write_binary(&mut self, data: &[u8]) -> Result<()> {
        write_ws_message(&mut self.stream, 0x2, data).await
    }

    pub(crate) async fn write_pong(&mut self, data: &[u8]) -> Result<()> {
        write_ws_message(&mut self.stream, 0xA, data).await
    }

    /// Close 帧半关传播：客户端 EOF 时通知服务端收尾（服务端回 Close 或
    /// 关 TLS 后下行侧经 read_binary 的 None/EOF 语义同步收敛）
    pub(crate) async fn write_close(&mut self) -> Result<()> {
        write_ws_message(&mut self.stream, 0x8, &[]).await
    }
}

pub(crate) struct WsFrame {
    pub(crate) opcode: u8,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn write_ws_message<S>(stream: &mut S, opcode: u8, data: &[u8]) -> Result<()>
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

pub(crate) async fn write_ws_frame<S>(
    stream: &mut S,
    fin: bool,
    opcode: u8,
    payload: &[u8],
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = encode_ws_frame(fin, opcode, payload);
    stream.write_all(&frame).await?;
    Ok(())
}

/// 客户端形帧编码（掩码位 + 随机掩码）——`write_ws_frame` 的纯内存面，
/// 供逐帧写路径（含 vmess 的 AsyncWrite 适配）复用。
pub(crate) fn encode_ws_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
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

    header.extend_from_slice(&masked);
    header
}
