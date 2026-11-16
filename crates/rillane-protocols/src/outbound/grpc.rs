//! gRPC 客户端传输面（trojan/vless/vmess 共用）
//!
//! h2 客户端握手 + 单流隧道：POST `/{service}/Tun`（content-type:
//! application/grpc），数据面为 gRPC 消息帧——5 字节前缀（1B 压缩旗标
//! 与 4B BE 长度），双方向同构。这是 xray / mihomo / trojan-go 的 grpc
//! 传输共用的线格式。
//!
//! 帧边界按消息缓存重组（一条 DATA 帧可含多条消息、一条消息可跨多帧）；
//! 上限 16MiB（对齐 ws 帧上限），压缩旗标 0x01 拒绝（未协商 grpc-encoding）。

use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;

pub(crate) const MAX_GRPC_MSG: usize = 16 * 1024 * 1024;

/// 已建立的 gRPC 隧道单流（h2 连接驱动任务持有底层 IO，
/// 读写两半仅是流句柄——`split()` 后可分属两个泵任务）
pub(crate) struct GrpcTunnel {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// gun 复用面流计数守卫（None = 非复用路径）——读写两半任一收尾
    /// 即递减连接现役流数
    close: Option<(StreamCloseGuard, StreamCloseGuard)>,
}

impl GrpcTunnel {
    pub(crate) fn set_close_guard(&mut self, count: Arc<AtomicUsize>) {
        self.close = Some(StreamCloseGuard::new(count));
    }

    pub(crate) fn split(self) -> (GrpcReader, GrpcWriter) {
        let (r_guard, w_guard) = match self.close {
            Some((a, b)) => (Some(a), Some(b)),
            None => (None, None),
        };
        (
            GrpcReader {
                recv: self.recv,
                buf: BytesMut::new(),
                close: r_guard,
            },
            GrpcWriter {
                send: self.send,
                close: w_guard,
            },
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
    let client = grpc_client(io).await?;
    grpc_post(client, authority, service).await
}

/// h2 握手：返回可克隆的流发起句柄（gun 复用面核心——每连接一份，
/// 多流共享），连接驱动任务随握手 spawn（流全收尾/对端关闭即自然退出）。
pub(crate) async fn grpc_client<S>(io: S) -> Result<h2::client::SendRequest<Bytes>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, conn) = h2::client::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

/// 在既有 h2 连接上开一条 gun 流（POST /{service}/Tun → 校验 200 +
/// application/grpc）。
pub(crate) async fn grpc_post(
    client: h2::client::SendRequest<Bytes>,
    authority: &str,
    service: &str,
) -> Result<GrpcTunnel> {
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
        close: None,
    })
}

// ---------------------------------------------------------------------------
// gRPC gun 流复用（RIL-130）
// ---------------------------------------------------------------------------

/// gRPC gun 客户端（mihomo transport/gun gun.go `Client` 同构，真源对照
/// 2026-11-16）：每节点一个——多条流共享 h2 连接（gun 线格式不变，每流
/// 仍是 POST /{service}/Tun）。旋钮（订阅 grpc-opts 键位）语义随 mihomo：
///
/// - 三键全缺（0/0/0）→ `max_connections = 1`：单连接全复用（NewClient
///   缺省面）；
/// - `max_connections > 0`：连接数上限。选现役流最少的连接：流数
///   `< min_streams` 或连接数已满上限 → 复用；否则另开新连接（连接数
///   先铺满、每连接先填到 min_streams 的 mihomo 口径）；
/// - `max_connections == 0`（不限连接数）：受 `max_streams` 约束（>0 时
///   单连接流数达上限即另开）。
///
/// 选型恒取现役流最少的连接（getTransport 同款）。流关闭递减计数
/// （CloseOnce 守卫，读写任一半收尾即减）——min/max streams 语义随流
/// 生命周期滚动。复用面发送失败（对端已收束）→ 逐出该连接重拨一次。
pub(crate) struct GunClient {
    conns: AsyncMutex<Vec<GunConn>>,
    max_connections: u32,
    min_streams: u32,
    max_streams: u32,
    authority: String,
    service: String,
    next_id: AtomicU64,
}

struct GunConn {
    id: u64,
    client: h2::client::SendRequest<Bytes>,
    /// 现役流数（流关闭经 CloseOnce 递减）
    streams: Arc<AtomicUsize>,
    /// 连接生命周期内持有的池租借（多路复用 = 共享资源不还池——
    /// resources.rs 口径「TLS 恢复独占取出、连接复用共享」）
    _lease: crate::pool::LeaseGuard,
}

/// 复用判据（mihomo getTransport 纯逻辑提取）：`num_streams` = 最少现役
/// 流数连接的流数，`conn_count` = 现役连接总数。流数 0 恒复用；否则
/// `max_connections > 0` 时连接数满上限或流数未达 min_streams → 复用；
/// `max_connections == 0` 时仅 `max_streams > 0` 且流数未达上限 → 复用。
fn should_reuse(
    num_streams: usize,
    conn_count: usize,
    max_connections: u32,
    min_streams: u32,
    max_streams: u32,
) -> bool {
    if num_streams == 0 {
        return true;
    }
    if max_connections > 0 {
        conn_count >= max_connections as usize || num_streams < min_streams as usize
    } else {
        max_streams > 0 && num_streams < max_streams as usize
    }
}

impl GunClient {
    pub(crate) fn new(
        authority: String,
        service: String,
        max_connections: u32,
        min_streams: u32,
        max_streams: u32,
    ) -> Self {
        // 三键全缺 → 单连接全复用（mihomo NewClient 缺省）
        let max_connections = if max_connections == 0 && min_streams == 0 && max_streams == 0 {
            1
        } else {
            max_connections
        };
        Self {
            conns: AsyncMutex::new(Vec::new()),
            max_connections,
            min_streams,
            max_streams,
            authority,
            service,
            next_id: AtomicU64::new(0),
        }
    }

    /// 取一条 gun 流：优先复用现役连接（mihomo getTransport 同款选型），
    /// 无可复用面时经 `dial` 新建（拨号持连接表锁——mihomo 同款，冷启动
    /// 串行化可接受；锁为 tokio Mutex 不阻塞线程）。复用面 ready/发送
    /// 失败（对端已收束）→ 逐出该连接、重拨一次（D-11 同口径）。
    pub(crate) async fn connect<F, Fut>(&self, mut dial: F) -> Result<GrpcTunnel>
    where
        F: FnMut() -> Fut,
        Fut:
            std::future::Future<Output = anyhow::Result<(crate::BoxedIo, crate::pool::LeaseGuard)>>,
    {
        // 复用面选型（锁内纯计算 + 克隆句柄，不跨 IO）
        let reuse = {
            let mut conns = self.conns.lock().await;
            let conn_count = conns.len();
            let best = conns
                .iter_mut()
                .min_by_key(|c| c.streams.load(Ordering::SeqCst));
            match best {
                None => None,
                Some(c) => {
                    let num = c.streams.load(Ordering::SeqCst);
                    if should_reuse(
                        num,
                        conn_count,
                        self.max_connections,
                        self.min_streams,
                        self.max_streams,
                    ) {
                        c.streams.fetch_add(1, Ordering::SeqCst);
                        Some((c.id, c.client.clone(), Arc::clone(&c.streams)))
                    } else {
                        None
                    }
                }
            }
        };
        if let Some((id, client, streams)) = reuse {
            match grpc_post(client, &self.authority, &self.service).await {
                Ok(mut t) => {
                    t.set_close_guard(Arc::clone(&streams));
                    return Ok(t);
                }
                Err(_) => {
                    // 对端已收束（stale 连接）→ 递回流计数并逐出，落新拨面
                    streams.fetch_sub(1, Ordering::SeqCst);
                    let mut conns = self.conns.lock().await;
                    conns.retain(|c| c.id != id);
                }
            }
        }
        // 新拨面：io（含池租借，随连接生命周期记账）→ h2 握手 → 首流 POST
        let (io, lease) = dial().await?;
        let client = grpc_client(io).await?;
        let mut tunnel = grpc_post(client.clone(), &self.authority, &self.service)
            .await
            .with_context(|| "gRPC gun 隧道握手失败")?;
        let mut conns = self.conns.lock().await;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let streams = Arc::new(AtomicUsize::new(1));
        tunnel.set_close_guard(Arc::clone(&streams));
        conns.push(GunConn {
            id,
            client,
            streams,
            _lease: lease,
        });
        Ok(tunnel)
    }
}

/// 流关闭计数守卫：GrpcTunnel split 后读写两半各持克隆，任一半收尾
/// （Drop）即递减一次连接现役流数——min/max streams 语义随流生命周期
/// 滚动（mihomo Transport.count 同口径）。
#[derive(Clone)]
struct StreamCloseGuard(Arc<AtomicBool>, Arc<AtomicUsize>);

impl StreamCloseGuard {
    fn new(count: Arc<AtomicUsize>) -> (Self, Self) {
        let closed = Arc::new(AtomicBool::new(false));
        (
            Self(Arc::clone(&closed), Arc::clone(&count)),
            Self(closed, count),
        )
    }
}

impl Drop for StreamCloseGuard {
    fn drop(&mut self) {
        if !self.0.swap(true, Ordering::SeqCst) {
            self.1.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

pub(crate) struct GrpcReader {
    recv: RecvStream,
    buf: BytesMut,
    /// gun 复用面流计数守卫（半收尾即递减一次）；无读取面——仅为 Drop
    /// 效应持有
    #[allow(dead_code)]
    close: Option<StreamCloseGuard>,
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
    /// gun 复用面流计数守卫（半收尾即递减一次）；无读取面——仅为 Drop
    /// 效应持有
    #[allow(dead_code)]
    close: Option<StreamCloseGuard>,
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
        for msg in [b"hello".as_slice(), b"", b"rillane-grpc"] {
            writer.message(msg).await.unwrap();
        }
        writer.finish().await.unwrap();
        let mut got = Vec::new();
        while let Some(m) = reader.message().await.unwrap() {
            got.extend_from_slice(&m);
        }
        assert_eq!(got, b"hellorillane-grpc");
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

    // ---------------- gun 流复用面（RIL-130） ----------------

    #[test]
    fn reuse_decision_matches_mihomo_get_transport_matrix() {
        // 流数 0 恒复用（空载连接优先）
        assert!(should_reuse(0, 1, 1, 0, 0));
        // max_connections>0：连接数满上限 → 复用
        assert!(should_reuse(1, 1, 1, 0, 0));
        assert!(should_reuse(3, 5, 5, 3, 0));
        // max_connections>0：流数未达 min_streams → 复用（先填满再铺开）
        assert!(should_reuse(2, 1, 5, 3, 0));
        // max_connections>0：流数达 min_streams 且连接数未满 → 另开新连接
        assert!(!should_reuse(3, 1, 5, 3, 0));
        // max_connections==0：max_streams 约束面
        assert!(should_reuse(1, 1, 0, 0, 2));
        assert!(!should_reuse(2, 1, 0, 0, 2));
        assert!(!should_reuse(2, 1, 0, 0, 0));
    }

    #[test]
    fn gun_client_new_defaults_to_single_connection() {
        // 三键全缺 → max_connections=1（mihomo NewClient 缺省）
        let c = GunClient::new("gun.test".into(), "svc".into(), 0, 0, 0);
        assert_eq!(c.max_connections, 1);
        assert_eq!(c.min_streams, 0);
        assert_eq!(c.max_streams, 0);
        // 显式旋钮原样保留
        let c = GunClient::new("gun.test".into(), "svc".into(), 4, 2, 8);
        assert_eq!(c.max_connections, 4);
        assert_eq!(c.min_streams, 2);
        assert_eq!(c.max_streams, 8);
    }

    /// 回显服务端（计数 TCP accept 次数）——gun 复用面用：单连接多流 =
    /// accepts 计数恒 1
    async fn spawn_echo_server_counting(_path_want: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts2 = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                accepts2.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(socket).await.unwrap();
                    while let Some(req) = conn.accept().await {
                        let (req, mut respond) = req.unwrap();
                        tokio::spawn(async move {
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
                                                continue;
                                            }
                                            pending = chunk;
                                        }
                                        _ => break,
                                    }
                                }
                                stream.reserve_capacity(pending.len());
                                let granted =
                                    match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await
                                    {
                                        Some(Ok(n)) => n,
                                        _ => break,
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
        (addr, accepts)
    }

    /// 拨号产物（h2 握手用 io + 池租借）：收敛 clippy type_complexity
    type DialIo = anyhow::Result<(crate::BoxedIo, crate::pool::LeaseGuard)>;

    fn gun_dial(
        addr: String,
    ) -> impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = DialIo> + Send>> {
        move || {
            let addr = addr.clone();
            Box::pin(async move {
                let io = TcpStream::connect(&addr).await?;
                Ok((
                    Box::new(io) as crate::BoxedIo,
                    crate::pool::LeaseGuard::lease_for_tests(),
                ))
            })
        }
    }

    async fn gun_roundtrip(tunnel: GrpcTunnel, payload: &[u8]) {
        let (mut reader, mut writer) = tunnel.split();
        writer.message(payload).await.unwrap();
        writer.finish().await.unwrap();
        let mut got = Vec::new();
        while let Some(m) = reader.message().await.unwrap() {
            got.extend_from_slice(&m);
        }
        assert_eq!(&got, payload);
    }

    #[tokio::test]
    async fn gun_client_default_reuses_single_connection_across_streams() {
        let (addr, accepts) = spawn_echo_server_counting("/gun-svc/Tun").await;
        let client = GunClient::new("gun.test".into(), "gun-svc".into(), 0, 0, 0);

        let t1 = client.connect(gun_dial(addr.clone())).await.unwrap();
        gun_roundtrip(t1, b"flow-one").await;
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "首流新拨");

        // 次流复用现役连接（无新 TCP accept）
        let t2 = client.connect(gun_dial(addr.clone())).await.unwrap();
        gun_roundtrip(t2, b"flow-two").await;
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "复用恒单连接");
        assert_eq!(client.conns.lock().await.len(), 1);

        // 流收尾递减计数：t1 释放后 t3 仍复用同一连接
        let t3 = client.connect(gun_dial(addr.clone())).await.unwrap();
        gun_roundtrip(t3, b"flow-three").await;
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "流收尾后仍单连接");
    }

    #[tokio::test]
    async fn gun_client_stale_connection_evicted_and_redialed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts2 = Arc::clone(&accepts);
        // 服务面：每连接只服务一条流，回应后立即断 TCP（制造 stale 面）
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                accepts2.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(socket).await.unwrap();
                    if let Some(Ok((req, mut respond))) = conn.accept().await {
                        // 回显独立 spawn：连接驱动须留在本任务（await 流体
                        // 期间无人推进连接将双向挂死——counting 服务同款）
                        let mut echo = tokio::spawn(async move {
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap();
                            let mut stream = respond.send_response(response, false).unwrap();
                            let mut body = req.into_body();
                            let mut pending = Bytes::new();
                            loop {
                                if pending.is_empty() {
                                    match body.data().await {
                                        Some(Ok(chunk)) => {
                                            let len = chunk.len();
                                            body.flow_control().release_capacity(len).unwrap();
                                            if chunk.is_empty() {
                                                continue;
                                            }
                                            pending = chunk;
                                        }
                                        _ => break,
                                    }
                                }
                                stream.reserve_capacity(pending.len());
                                let granted =
                                    match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await
                                    {
                                        Some(Ok(n)) => n,
                                        _ => break,
                                    };
                                let n = granted.min(pending.len());
                                stream.send_data(pending.split_to(n), false).unwrap();
                            }
                            stream.send_data(Bytes::new(), true).unwrap();
                        });
                        // 连接驱动与首流回显并行；首流回毕即断（stale 面）。
                        // 断前限时驱动落盘流尾帧——直接 drop 会吞掉缓冲帧，
                        // 客户端将永等流尾；限时到期即收束，客户端迟于此重
                        // 连才命中 stale 面。
                        loop {
                            tokio::select! {
                                _ = &mut echo => break,
                                r = conn.accept() => {
                                    if r.is_none() { break; }
                                }
                            }
                        }
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            conn.accept(),
                        )
                        .await;
                        drop(conn);
                    }
                });
            }
        });

        let client = GunClient::new("gun.test".into(), "gun-svc".into(), 0, 0, 0);
        let t1 = client.connect(gun_dial(addr.clone())).await.unwrap();
        gun_roundtrip(t1, b"before-stale").await;
        // 对端断连落地（服务端断前驱动窗 100ms，此处过之再重连）
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        // 复用面命中 stale 连接 → 逐出 + 重拨一次（D-11 同口径）
        let t2 = client.connect(gun_dial(addr.clone())).await.unwrap();
        gun_roundtrip(t2, b"after-redial").await;
        assert_eq!(accepts.load(Ordering::SeqCst), 2, "stale 逐出后恰新拨一次");
        assert_eq!(client.conns.lock().await.len(), 1, "重拨连接入表");
    }

    #[tokio::test]
    async fn gun_client_max_streams_cap_opens_new_connection() {
        let (addr, accepts) = spawn_echo_server_counting("/cap-svc/Tun").await;
        // max_streams=1：首流现役未收尾时现役流达上限 → 次流另开新连接
        let client = GunClient::new("gun.test".into(), "cap-svc".into(), 0, 0, 1);

        let t1 = client.connect(gun_dial(addr.clone())).await.unwrap();
        let t2 = client.connect(gun_dial(addr.clone())).await.unwrap();
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "max_streams=1 且首流现役时第二条流另开连接"
        );
        assert_eq!(client.conns.lock().await.len(), 2);
        gun_roundtrip(t1, b"cap-one").await;
        gun_roundtrip(t2, b"cap-two").await;

        // 流收尾计数回落（现役流 0 恒复用）→ 复用现役连接，不再新拨
        let t3 = client.connect(gun_dial(addr.clone())).await.unwrap();
        gun_roundtrip(t3, b"cap-three").await;
        assert_eq!(accepts.load(Ordering::SeqCst), 2, "流收尾后不再新拨");
        assert_eq!(client.conns.lock().await.len(), 2, "连接面不回收");
    }
}
