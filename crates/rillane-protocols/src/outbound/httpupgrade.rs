//! HTTPUpgrade 客户端传输面（vless/vmess 共用；G2-15/G3-16）
//!
//! 握手形同 WebSocket upgrade（GET path、Host、Upgrade/Connection、
//! Sec-WebSocket-Key/Version），服务端 101 后通道即移交协议层：**裸字节流
//! 直读直写，无 WS 帧收发**——与 ws 传输的本质差异（ws 是帧协议，
//! httpupgrade 只借 upgrade 语义穿 intermediates）。Sec-WebSocket-Accept
//! 带则校验、缺则放行（httpupgrade 生态存在省略该头的非真 WS 服务端，
//! xray 口径只认 101 状态行）。

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::BytesMut;
use rand::{rngs::OsRng, RngCore};
use sha1::{Digest, Sha1};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::ws::WS_MAGIC;

/// 101 后的裸字节流：握手读多的响应残余先回放（`prefix`），此后透传底层流。
pub(crate) struct HttpUpgradeStream<S> {
    inner: S,
    prefix: BytesMut,
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpUpgradeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let taken = self.prefix.split_to(n);
            buf.put_slice(&taken);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpUpgradeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// HTTPUpgrade 握手：发送 upgrade 请求（与 ws 同头语义）、校验 101 状态行、
/// accept 带则校验；返回裸流（含响应头多读残余的回放）。
pub(crate) async fn httpupgrade_client_handshake<S>(
    mut stream: S,
    host: &str,
    path: &str,
) -> Result<HttpUpgradeStream<S>>
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
    req.push_str("User-Agent: rillane\r\n\r\n");

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut resp = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("HTTPUpgrade 握手连接意外关闭"));
        }
        resp.extend_from_slice(&tmp[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if resp.len() > 16 * 1024 {
            return Err(anyhow!("HTTPUpgrade 握手响应过大"));
        }
    }

    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or_else(|| anyhow!("HTTPUpgrade 握手响应解析失败（无头部结束符）"))?;
    let leftover = resp.split_off(header_end);

    let header_block = String::from_utf8_lossy(&resp);
    let status = header_block
        .lines()
        .next()
        .ok_or_else(|| anyhow!("HTTPUpgrade 握手响应缺少状态行"))?;
    if !status.starts_with("HTTP/1.1 101") && !status.starts_with("HTTP/1.0 101") {
        return Err(anyhow!("HTTPUpgrade 握手失败：{}", status));
    }

    // accept 带则校验（RFC 6455 口径），缺则放行（httpupgrade 非真 WS，
    // xray 服务端面只认 101）
    let mut accept: Option<String> = None;
    for line in header_block.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("sec-websocket-accept") {
                accept = Some(v.trim().to_string());
            }
        }
    }
    if let Some(accept) = accept {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_MAGIC.as_bytes());
        let expected = BASE64.encode(hasher.finalize());
        if accept != expected {
            return Err(anyhow!("HTTPUpgrade 握手响应 Sec-WebSocket-Accept 不匹配"));
        }
    }

    Ok(HttpUpgradeStream {
        inner: stream,
        prefix: leftover,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream};

    /// 服务端读全请求头，断言 upgrade 头语义，回 101（accept 按请求 key
    /// 现算；`with_accept=false` 时省略该头——xray 兼容形）。
    async fn serve_handshake<S>(mut stream: S, with_accept: bool) -> Result<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("握手中连接关闭");
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("GET /hp HTTP/1.1"), "请求行不符: {text}");
        assert!(text.contains("Host: h.test"), "缺 Host 头: {text}");
        for expect in [
            "upgrade: websocket",
            "connection: upgrade",
            "sec-websocket-version: 13",
        ] {
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
        let mut resp = String::from(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
        );
        if with_accept {
            let mut hasher = Sha1::new();
            hasher.update(key.as_bytes());
            hasher.update(WS_MAGIC.as_bytes());
            let accept = BASE64.encode(hasher.finalize());
            resp.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
        }
        resp.push_str("\r\n");
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// 驱动端：写读两轮（小 + >16KiB）后收尾；裸流直读直写语义。
    async fn drive_raw_echo<S>(mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        stream.write_all(b"hello httpupgrade").await.unwrap();
        let mut buf = [0u8; 17];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello httpupgrade");

        let big = vec![7u8; 40 * 1024];
        stream.write_all(&big).await.unwrap();
        let mut rb = vec![0u8; big.len()];
        stream.read_exact(&mut rb).await.unwrap();
        assert_eq!(rb, big);
    }

    async fn loopback(with_accept: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (st, _) = listener.accept().await.unwrap();
            let res = async {
                let mut st = serve_handshake(st, with_accept).await?;
                // 101 后裸字节流原样 echo（服务端语义）
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let n = st.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    st.write_all(&buf[..n]).await?;
                    st.flush().await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            if let Err(e) = res.await {
                eprintln!("测试服务端错误: {e:#}");
            }
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let stream = httpupgrade_client_handshake(tcp, "h.test", "/hp")
            .await
            .expect("握手失败");
        drive_raw_echo(stream).await;
    }

    #[tokio::test]
    async fn handshake_with_accept_then_raw_stream_echo() {
        loopback(true).await;
    }

    #[tokio::test]
    async fn handshake_without_accept_tolerated() {
        loopback(false).await;
    }

    #[tokio::test]
    async fn handshake_rejects_non_101_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (st, _) = listener.accept().await.unwrap();
            let mut st = st;
            let _ = st
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let err = httpupgrade_client_handshake(tcp, "h.test", "/hp")
            .await
            .err()
            .expect("非 101 应拒绝");
        assert!(err.to_string().contains("404"), "错误应含状态: {err}");
    }

    #[tokio::test]
    async fn handshake_rejects_mismatched_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (st, _) = listener.accept().await.unwrap();
            let mut st = st;
            let _ = st
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: not-the-right-value==\r\n\r\n",
                )
                .await;
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let err = httpupgrade_client_handshake(tcp, "h.test", "/hp")
            .await
            .err()
            .expect("accept 不匹配应拒绝");
        assert!(
            err.to_string().contains("不匹配"),
            "错误应指 accept 不匹配: {err}"
        );
    }

    /// 响应头与首批业务字节同包到达（`leftover` 回放面）：握手后的首次读
    /// 应先吐头部残余，再接底层流——顺序与边界保真。
    #[tokio::test]
    async fn stream_replays_leftover_before_inner() {
        let (client, mut server) = duplex(64 * 1024);
        server
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nEXTRA-PAYLOAD",
            )
            .await
            .unwrap();

        let mut stream = httpupgrade_client_handshake(client, "h.test", "/hp")
            .await
            .expect("握手失败");
        let mut first = [0u8; 13];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"EXTRA-PAYLOAD", "握手残余应先回放");

        server.write_all(b"TAIL").await.unwrap();
        let mut tail = [0u8; 4];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"TAIL", "残余耗尽后接底层流");
    }
}
