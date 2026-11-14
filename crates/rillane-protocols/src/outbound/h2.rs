//! HTTP/2 裸流传输面（vmess/vless 共用）
//!
//! h2 客户端握手 + 单流隧道：POST `{path}`（:authority = host 首值，回退 SNI），
//! 请求体与响应体即双方向**裸字节流**——无帧格式（与 gRPC 的 5 字节前缀帧
//! 不同，xray h2 传输语义）。恒叠 TLS + ALPN h2（mihomo 口径 h2 仅 TLS），
//! 隧道握手后 `H2Stream` 以 AsyncRead/AsyncWrite 形态暴露，协议段可直接
//! 复用 tcp 路径的读写序列。

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 已建立的 HTTP/2 隧道单流（h2 连接驱动任务持有底层 IO，读写两半仅是
/// 流句柄——`H2Stream` 组合两半以 AsyncRead/AsyncWrite 形态供协议段复用）
pub(crate) struct H2Stream {
    reader: H2Reader,
    writer: H2Writer,
}

impl H2Stream {
    pub(crate) fn from_parts(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            reader: H2Reader {
                recv,
                pending: None,
            },
            writer: H2Writer { send },
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// 读半：h2 响应体分块 → 裸字节流；每块 release_capacity 保持窗口推进，
/// 跨 poll_read 调用的余量入 pending 续接。
struct H2Reader {
    recv: RecvStream,
    pending: Option<Bytes>,
}

impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(mut chunk) = self.pending.take() {
                let n = chunk.len().min(buf.remaining());
                let take = chunk.split_to(n);
                buf.put_slice(&take);
                if !chunk.is_empty() {
                    self.pending = Some(chunk);
                }
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    if data.is_empty() {
                        continue;
                    }
                    let len = data.len();
                    self.recv
                        .flow_control()
                        .release_capacity(len)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                    self.pending = Some(data);
                }
                Some(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
                }
                // 响应体耗尽 = 服务端关流（对目标侧收尾）
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// 写半：h2 请求体写入按授予容量分片（h2 流控口径）；shutdown 发零长 DATA +
/// END_STREAM 传播客户端半关。
struct H2Writer {
    send: SendStream<Bytes>,
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send.reserve_capacity(buf.len());
        match std::task::ready!(self.send.poll_capacity(cx)) {
            Some(Ok(granted)) => {
                if granted == 0 {
                    // 已预留非零容量却未授予：挂起待窗口回授（流复位走
                    // None/Err 分支）；不零预留 poll（grpc 教训）
                    return Poll::Pending;
                }
                let n = granted.min(buf.len());
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                Poll::Ready(Ok(n))
            }
            Some(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
            }
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2 流已关闭",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // send_data 即时交由连接驱动任务入链（本任务已 spawn），无需显式 flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.send
            .send_data(Bytes::new(), true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
        Poll::Ready(Ok(()))
    }
}

/// 发起 HTTP/2 隧道：h2 握手 → POST {path}（:authority = host 首值）→ 校验
/// 200。`authority` 取 SNI/Host 实际值（ws Host 同口径）；`path` 为 h2-opts
/// 路径（缺省 `/`，连接器侧归一）。
pub(crate) async fn h2_tunnel<S>(io: S, authority: &str, path: &str) -> Result<H2Stream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, conn) = h2::client::handshake(io).await?;
    // 连接驱动：流全收尾/对端关闭即自然退出
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .body(())
        .map_err(|e| anyhow!("HTTP/2 请求构造失败: {e}"))?;

    let (response, send) = client.ready().await?.send_request(req, false)?;
    let resp = response.await?;
    if resp.status() != http::StatusCode::OK {
        return Err(anyhow!("HTTP/2 隧道握手失败：HTTP {}", resp.status()));
    }
    Ok(H2Stream::from_parts(send, resp.into_body()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// mock h2 服务端：h2 握手 → 校验 POST + path → 回 200 → 裸字节流逐块
    /// echo（按授予容量分片）至 EOS，回 EOS 收尾。
    async fn spawn_echo_server(path_want: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(socket).await.unwrap();
                    // h2 连接驱动须留在 accept 循环所在任务（await body.data()
                    // 期间须有人推进连接，否则 socket 不再被读、双向挂死）
                    while let Some(req) = conn.accept().await {
                        let (req, mut respond) = req.unwrap();
                        tokio::spawn(async move {
                            assert_eq!(req.method(), http::Method::POST);
                            assert_eq!(req.uri().path(), path_want);
                            let response = http::Response::builder().status(200).body(()).unwrap();
                            let mut stream = respond.send_response(response, false).unwrap();
                            let mut body = req.into_body();
                            let mut pending: Bytes = Bytes::new();
                            loop {
                                if pending.is_empty() {
                                    match body.data().await {
                                        Some(Ok(chunk)) => {
                                            let len = chunk.len();
                                            body.flow_control().release_capacity(len).unwrap();
                                            if chunk.is_empty() {
                                                continue; // 空帧不回显
                                            }
                                            pending = chunk;
                                        }
                                        Some(Err(e)) => panic!("服务端读数据失败: {e}"),
                                        None => break,
                                    }
                                }
                                stream.reserve_capacity(pending.len());
                                let granted =
                                    match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await
                                    {
                                        Some(Ok(n)) => n,
                                        _ => break, // None = 对端关流；Err = 流已坏
                                    };
                                let n = granted.min(pending.len());
                                stream.send_data(pending.split_to(n), false).unwrap();
                            }
                            stream.send_data(Bytes::new(), true).unwrap();
                        });
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tunnel_handshake_headers_and_echo_roundtrip() {
        let addr = spawn_echo_server("/h2-svc/echo").await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let mut stream = h2_tunnel(tcp, "example.com", "/h2-svc/echo").await.unwrap();
        stream.write_all(b"h2-up").await.unwrap();
        stream.flush().await.unwrap();
        // 半关（END_STREAM）→ 服务端 echo 完毕回 EOS，read_to_end 收敛
        stream.shutdown().await.unwrap();
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"h2-up");
    }

    #[tokio::test]
    async fn large_stream_roundtrips_across_data_frames() {
        let addr = spawn_echo_server("/h2-svc/big").await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let stream = h2_tunnel(tcp, "example.com", "/h2-svc/big").await.unwrap();
        // 100KiB：写侧按 h2 容量授予分帧、读侧跨帧重组；echo 场景读写两半
        // 并发驱动（大载荷单线程先写后读会与回灌互等）
        let H2Stream { reader, writer } = stream;
        let payload: Vec<u8> = (0..100 * 1024).map(|i| (i % 251) as u8).collect();
        let payload_write = payload.clone();
        let up = tokio::spawn(async move {
            let mut w = writer;
            w.write_all(&payload_write).await.unwrap();
            w.shutdown().await.unwrap(); // END_STREAM → 服务端 echo 完毕回 EOS
        });
        let mut got = Vec::new();
        let mut r = reader;
        r.read_to_end(&mut got).await.unwrap();
        up.await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn non_200_response_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let _ = req;
            let response = http::Response::builder().status(503).body(()).unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            stream.send_data(Bytes::new(), true).unwrap();
            // 连接驱动须持续推进到客户端读到响应头（直接 drop 会在帧 flush
            // 前 RST，客户端误报 broken pipe）；单请求场景 drain 到连接结束
            while conn.accept().await.is_some() {}
        });

        let tcp = TcpStream::connect(&addr).await.unwrap();
        let err = match h2_tunnel(tcp, "example.com", "/svc").await {
            Err(e) => e,
            Ok(_) => panic!("expected non-200 rejection"),
        };
        assert!(err.to_string().contains("503"));
    }
}
