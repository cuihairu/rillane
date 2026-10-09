//! gRPC 客户端传输面（trojan/vless/vmess 共用）
//!
//! h2 客户端握手 + 单流隧道：POST `/{service}/Tun`（content-type:
//! application/grpc），数据面为 gRPC 消息帧——5 字节前缀（1B 压缩旗标
//! + 4B BE 长度），双方向同构。这是 xray / mihomo / trojan-go 的 grpc
//! 传输共用的线格式。
//!
//! 帧边界按消息缓存重组（一条 DATA 帧可含多条消息、一条消息可跨多帧）；
//! 上限 16MiB（对齐 ws 帧上限），压缩旗标 0x01 拒绝（未协商 grpc-encoding）。

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) const MAX_GRPC_MSG: usize = 16 * 1024 * 1024;

/// 已建立的 gRPC 隧道单流（h2 连接驱动任务持有底层 IO，
/// 读写两半仅是流句柄——`split()` 后可分属两个泵任务）
pub(crate) struct GrpcTunnel {
    send: SendStream<Bytes>,
    recv: RecvStream,
}

impl GrpcTunnel {
    pub(crate) fn split(self) -> (GrpcReader, GrpcWriter) {
        (
            GrpcReader {
                recv: self.recv,
                buf: BytesMut::new(),
            },
            GrpcWriter { send: self.send },
        )
    }
}

/// 发起 gRPC 隧道：h2 握手 → POST /{service}/Tun → 校验响应头
/// （200 + content-type application/grpc）。`authority` 取 SNI 实际值
/// （ws Host 同口径）；service 为订阅/config 面的 grpc-service-name。
pub(crate) async fn grpc_tunnel<S>(io: S, authority: &str, service: &str) -> Result<GrpcTunnel>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, conn) = h2::client::handshake(io).await?;
    // 连接驱动：流全收尾/对端关闭即自然退出
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let service = service.trim_matches('/');
    let path = format!("/{service}/Tun");
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| anyhow!("gRPC 请求构造失败: {e}"))?;

    let (response, send) = client.ready().await?.send_request(req, false)?;
    let resp = response.await?;
    if resp.status() != http::StatusCode::OK {
        return Err(anyhow!("gRPC 隧道握手失败：HTTP {}", resp.status()));
    }
    let content_type_ok = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/grpc"));
    if !content_type_ok {
        return Err(anyhow!(
            "gRPC 隧道握手失败：content-type 非 application/grpc"
        ));
    }
    Ok(GrpcTunnel {
        send,
        recv: resp.into_body(),
    })
}

pub(crate) struct GrpcReader {
    recv: RecvStream,
    buf: BytesMut,
}

impl GrpcReader {
    /// 下一条 gRPC 消息载荷；None = 服务端流已终（DATA 尽 + trailers/关）
    pub(crate) async fn message(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(msg) = self.try_parse()? {
                return Ok(Some(msg));
            }
            match self.recv.data().await {
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    self.recv.flow_control().release_capacity(len)?;
                    self.buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(e.into()),
                None => {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(anyhow!("gRPC 流在消息中间终止"));
                }
            }
        }
    }

    /// 消息流上的 read_exact（跨消息边界拼凑；vless/vmess gRPC 应答头读取用）。
    /// `buf` 始终保持「带帧头」形态：消息载荷不落入 `buf`，单条消息超出
    /// `out` 长度的余量回灌为一条完整帧消息，FIFO 顺序留给后续读取。
    pub(crate) async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            let Some(msg) = self.message().await? else {
                return Err(anyhow!("gRPC 流已终止"));
            };
            let take = msg.len().min(out.len() - filled);
            out[filled..filled + take].copy_from_slice(&msg[..take]);
            filled += take;
            if take < msg.len() {
                let rest = &msg[take..];
                let mut framed = BytesMut::with_capacity(5 + rest.len() + self.buf.len());
                framed.extend_from_slice(&[0u8]);
                framed.extend_from_slice(&(rest.len() as u32).to_be_bytes());
                framed.extend_from_slice(rest);
                framed.extend_from_slice(&self.buf);
                self.buf = framed;
            }
        }
        Ok(())
    }

    /// 从缓存解一条完整消息（不满足则等待更多 DATA）
    fn try_parse(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let flag = self.buf[0];
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if flag != 0 {
            return Err(anyhow!(
                "gRPC 压缩消息不支持（flag=0x01，未协商 grpc-encoding）"
            ));
        }
        if len > MAX_GRPC_MSG {
            return Err(anyhow!("gRPC 消息过大（>16MiB）"));
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let _ = self.buf.split_to(5);
        let payload = self.buf.split_to(len);
        Ok(Some(payload.to_vec()))
    }
}

pub(crate) struct GrpcWriter {
    send: SendStream<Bytes>,
}

impl GrpcWriter {
    /// 发送一条 gRPC 消息（容量许可循环推进——大消息按 h2 授予窗口分片）
    pub(crate) async fn message(&mut self, data: &[u8]) -> Result<()> {
        let frame_len = 5 + data.len();
        let mut frame = BytesMut::with_capacity(frame_len);
        frame.extend_from_slice(&[0u8]);
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(data);
        let mut remaining = frame.freeze();
        while !remaining.is_empty() {
            self.send.reserve_capacity(remaining.len());
            let granted = std::future::poll_fn(|cx| self.send.poll_capacity(cx))
                .await
                .ok_or_else(|| anyhow!("gRPC 流已关闭"))??;
            if granted == 0 {
                continue;
            }
            let chunk = remaining.split_to(granted.min(remaining.len()));
            self.send.send_data(chunk, false)?;
        }
        Ok(())
    }

    /// 收尾：零长 DATA + END_STREAM（客户端半关传播；服务端按流终收尾）
    pub(crate) async fn finish(&mut self) -> Result<()> {
        self.send.send_data(Bytes::new(), true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// mock gRPC 服务端：校验请求头后按 DATA 原样回显（字节级回显保持
    /// 客户端自身帧格式，读侧重组逻辑即被真实行使）。
    /// h2 连接驱动须留在 accept 循环所在任务（await body.data() 期间须有人
    /// 推进连接，否则 socket 不再被读、双向挂死）；per-stream 回显独立 spawn，
    /// 且出方向按授予容量分片（对齐客户端 GrpcWriter 的流控口径）。
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
                    while let Some(req) = conn.accept().await {
                        let (req, mut respond) = req.unwrap();
                        tokio::spawn(async move {
                            assert_eq!(req.method(), http::Method::POST);
                            assert_eq!(req.uri().path(), path_want);
                            assert_eq!(req.headers().get("te").unwrap(), "trailers");
                            assert_eq!(
                                req.headers().get("content-type").unwrap(),
                                "application/grpc"
                            );
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap();
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
                                                continue; // 空帧（END_STREAM 载荷）不回显
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

    fn frame(msg: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(5 + msg.len());
        f.push(0u8);
        f.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        f.extend_from_slice(msg);
        f
    }

    #[tokio::test]
    async fn tunnel_handshake_headers_and_echo_roundtrip() {
        let addr = spawn_echo_server("/my-svc/Tun").await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let tunnel = grpc_tunnel(tcp, "example.com", "my-svc").await.unwrap();
        let (mut reader, mut writer) = tunnel.split();

        // 三条消息回显（含空消息）
        for msg in [b"hello".as_slice(), b"", b"seep-grpc"] {
            writer.message(msg).await.unwrap();
        }
        writer.finish().await.unwrap();
        let mut got = Vec::new();
        while let Some(m) = reader.message().await.unwrap() {
            got.extend_from_slice(&m);
        }
        assert_eq!(got, b"helloseep-grpc");
    }

    #[tokio::test]
    async fn large_message_reassembles_across_data_frames() {
        let addr = spawn_echo_server("/svc/Tun").await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let tunnel = grpc_tunnel(tcp, "example.com", "svc").await.unwrap();
        let (mut reader, mut writer) = tunnel.split();

        // 100KiB 消息：写侧按 h2 容量授予分帧、读侧跨帧重组
        let payload: Vec<u8> = (0..100 * 1024).map(|i| (i % 251) as u8).collect();
        writer.message(&payload).await.unwrap();
        writer.finish().await.unwrap();
        let mut got = Vec::new();
        while let Some(m) = reader.message().await.unwrap() {
            got.extend_from_slice(&m);
        }
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn read_exact_reassembles_across_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let _ = req; // 头已由握手语义覆盖，此处只测下发重组
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            // 两条消息：服务端帧界与 read_exact 的读界刻意不对齐
            stream.send_data(Bytes::from(frame(b"ab")), false).unwrap();
            stream
                .send_data(Bytes::from(frame(b"cdef")), false)
                .unwrap();
            stream.send_data(Bytes::new(), true).unwrap();
            // 连接驱动须持续推进到客户端收完（直接 drop 会在帧 flush 前 RST，
            // 客户端误报 broken pipe）；单请求场景 drain accept 到连接结束
            while conn.accept().await.is_some() {}
        });

        let tcp = TcpStream::connect(&addr).await.unwrap();
        let tunnel = grpc_tunnel(tcp, "example.com", "svc").await.unwrap();
        let (mut reader, _writer) = tunnel.split();
        let mut four = [0u8; 4];
        reader.read_exact(&mut four).await.unwrap();
        assert_eq!(&four, b"abcd");
        let mut two = [0u8; 2];
        reader.read_exact(&mut two).await.unwrap();
        assert_eq!(&two, b"ef");
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
            let response = http::Response::builder().status(404).body(()).unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            stream.send_data(Bytes::new(), true).unwrap();
            // 驱动连接直至客户端读到响应头（直接 drop 会在帧 flush 前 RST）
            while conn.accept().await.is_some() {}
        });

        let tcp = TcpStream::connect(&addr).await.unwrap();
        let err = match grpc_tunnel(tcp, "example.com", "svc").await {
            Err(e) => e,
            Ok(_) => panic!("expected non-200 rejection"),
        };
        assert!(err.to_string().contains("404"));
    }
}
