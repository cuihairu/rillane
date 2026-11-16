//! XHTTP 传输面（RIL-129，vless 载体）
//!
//! xray splithttp 语义的自写客户端面（评估留证 protocol-backends.md#xhttp，
//! 线格式对照 Xray-core transport/internet/splithttp/{config,dialer,client}.go）：
//! TLS+ALPN h2 之上的 HTTP/2 请求族承载裸字节流——
//! - `packet-up`：下载 `GET {path}{session}`（响应体流 = 下行）；上行按序
//!   `POST {path}{session}/{seq}`（body 分块，逐 POST 期望 200）
//! - `stream-one`：单条 `POST {path}`（无 session 段，Content-Type:
//!   application/grpc），请求体开放（EOS = 上行收束），响应体 = 下行
//!
//! 模式边界（不承载即点名拒绝，防静默降级）：`auto` 在 H2/无 REALITY/
//! 无 download settings 口径下判为 `packet-up`（xray dialer.go 同判定）；
//! `stream-up`/HTTP3/HTTP1.1/xmux/browser dialer/填充 obfs 均不在本面。

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::RecvStream;
use rand::RngCore;
use std::pin::Pin;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// 上行单 POST 分块上限（xray scMaxEachPostBytes 缺省 1MB；本面取 64KiB——
/// 分块只影响 POST 频度不影响线语义，具名边界留证评估记录）
pub(crate) const MAX_POST_BODY: usize = 64 * 1024;

/// XHTTP 模式（`auto` 缺省判 packet-up——H2/无 REALITY/无 download settings
/// 口径，与 xray dialer.go decideHTTPVersion/mode 解析同源）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XhttpMode {
    PacketUp,
    StreamOne,
}

impl XhttpMode {
    /// IR `xhttp_mode` 解析（拨号期具名拒绝，不静默降级）
    pub(crate) fn parse(raw: &Option<String>) -> Result<Self> {
        match raw.as_deref() {
            None | Some("auto") | Some("") => Ok(Self::PacketUp),
            Some("packet-up") => Ok(Self::PacketUp),
            Some("stream-one") => Ok(Self::StreamOne),
            Some(other) => Err(anyhow!(
                "XHTTP mode 仅支持 auto/packet-up/stream-one（stream-up/HTTP3/HTTP1.1 载具未交付），当前: {other}"
            )),
        }
    }
}

/// session id：16 hex 随机（xray path 放置缺省口径——服务端视为不透明
/// 路径段；长度/字母表非线格式约束）
fn generate_session_id() -> String {
    let mut raw = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// 由基路径构造请求目标：`{base}{session}/{seq}`（seq 为 None 时不带；
/// 查询串保留——xray GetNormalizedPath 把 query 与 path 分置口径）
fn request_target(base: &str, session: &str, seq: Option<u64>) -> String {
    let (path, query) = match base.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (base, None),
    };
    let mut target = String::with_capacity(path.len() + session.len() + 24);
    if !path.starts_with('/') {
        target.push('/');
    }
    target.push_str(path);
    if !target.ends_with('/') {
        target.push('/');
    }
    target.push_str(session);
    if let Some(seq) = seq {
        target.push('/');
        target.push_str(&seq.to_string());
    }
    if let Some(q) = query {
        target.push('?');
        target.push_str(q);
    }
    target
}

/// POST 失败毒化槽：上行 POST 非 200/失败时具名留痕，读写两半均以命名
/// 错误收束（不静默降级为空流）
#[derive(Default)]
struct Poison {
    failed: AtomicBool,
    message: Mutex<Option<String>>,
    /// 读半泊位唤醒槽：读侧泊于下行 data() 时登记 waker，上行失败面毒化
    /// 即唤醒重查（poison 先置位后取票、读侧先存票后复查——无错票窗口）
    waker: Mutex<Option<std::task::Waker>>,
}

impl Poison {
    fn poison(&self, message: String) {
        self.message.lock().unwrap().get_or_insert(message);
        self.failed.store(true, Ordering::SeqCst);
        let waker = self.waker.lock().unwrap().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn check(&self) -> std::io::Result<()> {
        if self.failed.load(Ordering::SeqCst) {
            let message = self
                .message
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "XHTTP 上行已失败".into());
            return Err(std::io::Error::other(message));
        }
        Ok(())
    }
}

/// XHTTP 隧道双工流：读半（响应体流）+ 写半（stream-one 单请求体 /
/// packet-up POST 序列）。协议段（VLESS 请求头往返 + 双向泵）直接复用。
pub(crate) struct XhttpStream {
    recv: XhttpReader,
    send: XhttpWriter,
}

// 手工 Debug（h2 流面未实现）：测试断言（expect/expect_err）与日志面需要
impl std::fmt::Debug for XhttpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpStream").finish_non_exhaustive()
    }
}

/// 读半：h2 响应体分块 → 裸字节流（packet-up GET 流 / stream-one 响应体
/// 同形）；先查毒化槽——上行 POST 失败时读侧以命名错误收束而非悬挂
struct XhttpReader {
    recv: RecvStream,
    pending: Option<Bytes>,
    poison: Option<std::sync::Arc<Poison>>,
}

impl AsyncRead for XhttpReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(poison) = &self.poison {
            // 先存唤醒票再复查毒化位（与 poison 面的先置位后取票配对——
            // 读侧泊位期间上行失败面能即时唤醒，无错票窗口）
            *poison.waker.lock().unwrap() = Some(cx.waker().clone());
            poison.check()?;
        }
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
                    // 上行失败面优先具名（403 毒化与下行流复位竞速——毒化
                    // 已置位时以命名错误收束而非底层 h2 流错误）
                    if let Some(poison) = &self.poison {
                        poison.check()?;
                    }
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e,
                    )));
                }
                // 响应体耗尽 = 服务端关流（对目标侧收尾）
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// 写半（stream-one）：h2 请求体按授予容量分片直写；shutdown 发 EOS。
struct StreamOneWriter {
    send: h2::SendStream<Bytes>,
}

impl AsyncWrite for StreamOneWriter {
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
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.send
            .send_data(Bytes::new(), true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
        Poll::Ready(Ok(()))
    }
}

/// 写半（packet-up）：写块推入通道（分块上限内），上传任务逐块 POST。
/// shutdown = 取走发送端（任务排干即退出）；POST 失败毒化读写两半。
/// 通道取 unbounded：背压由 relay 写预算承担（copy_bidirectional 缓冲
/// 有界），POST 逐块串行等 200，排队深度受写半节奏约束。
struct PacketUpWriter {
    tx: Option<mpsc::UnboundedSender<Option<Bytes>>>,
    poison: std::sync::Arc<Poison>,
}

impl AsyncWrite for PacketUpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poison.check()?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(tx) = self.tx.as_ref() else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "XHTTP 上行已收束",
            )));
        };
        let n = buf.len().min(MAX_POST_BODY);
        tx.send(Some(Bytes::copy_from_slice(&buf[..n])))
            .map_err(|_| std::io::Error::other("XHTTP 上行任务已退出（POST 失败或连接收束）"))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 取走发送端：上传任务排干存量后退出（不发尾随空 POST——xray 同口径）
        self.tx.take();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// 发起 XHTTP 隧道：h2 握手 → 按模式建立下行流/上行面（`authority` 取
/// Host/SNI 实际值；`path` 为节点路径，session/seq 以路径段追加）。
/// 非期望状态码一律具名拒绝（XHTTP 无独立错误响应面——HTTP 状态即拒绝面）。
pub(crate) async fn xhttp_tunnel<S>(
    io: S,
    authority: &str,
    path: &str,
    mode: XhttpMode,
) -> Result<XhttpStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, conn) = h2::client::handshake(io).await?;
    // 连接驱动：流全收尾/对端关闭即自然退出
    tokio::spawn(async move {
        let _ = conn.await;
    });

    match mode {
        XhttpMode::StreamOne => {
            // stream-one：单条 POST {path}（无 session 段），Content-Type:
            // application/grpc（xray FillStreamRequest 口径），上行体开放
            let uri = http::Uri::builder()
                .scheme("https")
                .authority(authority)
                .path_and_query(path)
                .build()?;
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri(uri)
                .header("content-type", "application/grpc")
                .body(())
                .map_err(|e| anyhow!("XHTTP 请求构造失败: {e}"))?;
            // 就绪等待 + 直发（poll_ready 借用 &mut；消费式 ready(self) 只
            // 适合单请求连接，本面同连接承载下行流与上行 POST 序列）
            std::future::poll_fn(|cx| client.poll_ready(cx)).await?;
            let (response, send) = client.send_request(req, false)?;
            let resp = response.await?;
            if resp.status() != http::StatusCode::OK {
                return Err(anyhow!("XHTTP stream-one 握手失败：HTTP {}", resp.status()));
            }
            Ok(XhttpStream {
                recv: XhttpReader {
                    recv: resp.into_body(),
                    pending: None,
                    poison: None,
                },
                send: XhttpWriter::StreamOne(StreamOneWriter { send }),
            })
        }
        XhttpMode::PacketUp => {
            let session = generate_session_id();
            // 下载流：GET {path}{session}，响应体 = 下行（先建下行再开上行，
            // 与 xray Dial 次序一致）
            let uri = http::Uri::builder()
                .scheme("https")
                .authority(authority)
                .path_and_query(request_target(path, &session, None))
                .build()?;
            let req = http::Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(())
                .map_err(|e| anyhow!("XHTTP 请求构造失败: {e}"))?;
            std::future::poll_fn(|cx| client.poll_ready(cx)).await?;
            let (response, _) = client.send_request(req, true)?;
            let resp = response.await?;
            if resp.status() != http::StatusCode::OK {
                return Err(anyhow!("XHTTP 下载流被拒：HTTP {}", resp.status()));
            }
            let recv = resp.into_body();

            // 上行面：写块 → 通道 → 任务逐块 POST {path}{session}/{seq}
            let poison = std::sync::Arc::new(Poison::default());
            let (tx, mut rx) = mpsc::unbounded_channel::<Option<Bytes>>();
            let up_authority = authority.to_string();
            let up_path = path.to_string();
            let up_session = session.clone();
            let up_poison = poison.clone();
            tokio::spawn(async move {
                let mut client = client;
                let mut seq: u64 = 0;
                while let Some(Some(chunk)) = rx.recv().await {
                    let uri = http::Uri::builder()
                        .scheme("https")
                        .authority(up_authority.as_str())
                        .path_and_query(request_target(&up_path, &up_session, Some(seq)))
                        .build();
                    let Ok(uri) = uri else {
                        up_poison.poison("XHTTP 上行请求构造失败".into());
                        break;
                    };
                    let req = http::Request::builder()
                        .method(http::Method::POST)
                        .uri(uri)
                        .header("content-length", chunk.len().to_string())
                        .body(())
                        .ok();
                    let Some(req) = req else {
                        up_poison.poison("XHTTP 上行请求构造失败".into());
                        break;
                    };
                    if std::future::poll_fn(|cx| client.poll_ready(cx))
                        .await
                        .is_err()
                    {
                        up_poison.poison(format!("XHTTP 上行 POST #{seq} 发送失败"));
                        break;
                    }
                    let Ok((respond, mut send)) = client.send_request(req, false) else {
                        up_poison.poison(format!("XHTTP 上行 POST #{seq} 发送失败"));
                        break;
                    };
                    // 容量驱动分帧：h2 send_data 要求授予容量覆盖整块
                    // （64KiB 块 > 缺省流窗口，须按授予量切 DATA 帧）
                    send.reserve_capacity(chunk.len());
                    let mut body = chunk;
                    let mut posted = true;
                    while !body.is_empty() {
                        match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                            Some(Ok(granted)) if granted > 0 => {
                                let take = body.split_to(granted.min(body.len()));
                                send.reserve_capacity(body.len());
                                if send.send_data(take, false).is_err() {
                                    up_poison.poison(format!("XHTTP 上行 POST #{seq} 发送失败"));
                                    posted = false;
                                    break;
                                }
                            }
                            Some(Ok(_)) => send.reserve_capacity(body.len()),
                            Some(Err(e)) => {
                                up_poison.poison(format!("XHTTP 上行 POST #{seq} 失败: {e}"));
                                posted = false;
                                break;
                            }
                            None => {
                                up_poison.poison(format!("XHTTP 上行 POST #{seq} 流已关闭"));
                                posted = false;
                                break;
                            }
                        }
                    }
                    if !posted {
                        break;
                    }
                    let _ = send.send_data(Bytes::new(), true); // EOS
                    match respond.await {
                        Ok(resp) if resp.status() == http::StatusCode::OK => {}
                        Ok(resp) => {
                            up_poison.poison(format!(
                                "XHTTP 上行 POST #{seq} 被拒：HTTP {}",
                                resp.status()
                            ));
                            break;
                        }
                        Err(e) => {
                            up_poison.poison(format!("XHTTP 上行 POST #{seq} 失败: {e}"));
                            break;
                        }
                    }
                    seq += 1;
                }
            });

            Ok(XhttpStream {
                recv: XhttpReader {
                    recv,
                    pending: None,
                    poison: Some(std::sync::Arc::clone(&poison)),
                },
                send: XhttpWriter::PacketUp(PacketUpWriter {
                    tx: Some(tx),
                    poison,
                }),
            })
        }
    }
}

/// 写半分派（枚举避免 trait object装箱）
enum XhttpWriter {
    StreamOne(StreamOneWriter),
    PacketUp(PacketUpWriter),
}

impl AsyncWrite for XhttpWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            XhttpWriter::StreamOne(w) => Pin::new(w).poll_write(cx, buf),
            XhttpWriter::PacketUp(w) => Pin::new(w).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            XhttpWriter::StreamOne(w) => Pin::new(w).poll_flush(cx),
            XhttpWriter::PacketUp(w) => Pin::new(w).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            XhttpWriter::StreamOne(w) => Pin::new(w).poll_shutdown(cx),
            XhttpWriter::PacketUp(w) => Pin::new(w).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// 模式解析：合法集 + 越界点名拒绝
    #[test]
    fn mode_parse_boundary() {
        assert_eq!(XhttpMode::parse(&None).unwrap(), XhttpMode::PacketUp);
        assert_eq!(
            XhttpMode::parse(&Some("auto".into())).unwrap(),
            XhttpMode::PacketUp
        );
        assert_eq!(
            XhttpMode::parse(&Some("packet-up".into())).unwrap(),
            XhttpMode::PacketUp
        );
        assert_eq!(
            XhttpMode::parse(&Some("stream-one".into())).unwrap(),
            XhttpMode::StreamOne
        );
        let err = XhttpMode::parse(&Some("stream-up".into())).unwrap_err();
        assert!(err.to_string().contains("stream-up"), "{err}");
        let err = XhttpMode::parse(&Some("h3".into())).unwrap_err();
        assert!(err.to_string().contains("仅支持"), "{err}");
    }

    /// 请求目标：session/seq 路径段 + 查询串保留 + 斜杠归一
    #[test]
    fn request_target_shape() {
        assert_eq!(request_target("/upload", "abc123", None), "/upload/abc123");
        assert_eq!(
            request_target("/upload", "abc123", Some(7)),
            "/upload/abc123/7"
        );
        // xray 口径：path 放置要求尾斜杠（GetNormalizedPath）
        assert_eq!(request_target("/up", "s", None), "/up/s");
        assert_eq!(request_target("/", "s", Some(0)), "/s/0");
        // 查询串保留在尾（path 段追加不吞 query）
        assert_eq!(request_target("/u?ed=2560", "s", Some(2)), "/u/s/2?ed=2560");
    }

    /// session id：16 hex 随机、逐次不同
    #[test]
    fn session_id_shape() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_eq!(a.len(), 16, "{a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "随机 session 不得重合");
    }

    /// mock h2 服务端（stream-one）：POST + Content-Type 校验 → 200 →
    /// 请求体全量收齐 EOS 后回声至响应体、EOS 收尾
    ///
    /// h2 服务端 RecvStream::data() 不驱动连接：处理器须放独立任务，accept
    /// 循环驻留持续读 socket（await body.data() 期间无人驱动则双向挂死——
    /// 同 h2.rs/grpc.rs 口径）
    async fn spawn_stream_one_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let mut conn = h2::server::handshake(socket).await.unwrap();
            while let Some(req) = conn.accept().await {
                let (req, mut respond) = req.unwrap();
                tokio::spawn(async move {
                    assert_eq!(req.method(), http::Method::POST);
                    assert_eq!(req.uri().path(), "/xh");
                    assert_eq!(
                        req.headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok()),
                        Some("application/grpc"),
                        "stream-one 须携带 grpc Content-Type（xray FillStreamRequest 口径）"
                    );
                    let response = http::Response::builder().status(200).body(()).unwrap();
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
                                        continue; // EOS 帧
                                    }
                                    pending = chunk;
                                }
                                Some(Err(_)) | None => break,
                            }
                        }
                        let out = pending.split_to(pending.len().min(64));
                        stream.send_data(out, false).unwrap();
                    }
                    stream.send_data(Bytes::new(), true).unwrap();
                });
            }
        });
        addr
    }

    /// 容量驱动的 h2 发送（fixture 用）：按授予量切帧直至发完
    async fn h2_send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) {
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(granted)) if granted > 0 => {
                    let take = data.split_to(granted.min(data.len()));
                    send.reserve_capacity(data.len());
                    send.send_data(take, false).unwrap();
                }
                Some(Ok(_)) => send.reserve_capacity(data.len()),
                _ => panic!("h2 下载流发送失败"),
            }
        }
    }

    /// mock h2 服务端（packet-up）：GET {session} 下载流 + POST
    /// {session}/{seq} 逐序收集；收满 `expected_posts` 个 POST 后按 seq
    /// 顺序回放至 GET 响应体并收束（URL 形状与 seq 面貌逐项断言——镜像
    /// 对端核心职责；xray packet-up 无上行 EOF 显式信令，测试以期望
    /// POST 数确定性收束）
    ///
    /// 连接驱动同 stream-one：accept 循环 select 驱动 + 处理器独立任务；
    /// 回放亦放独立任务（>64KiB 依赖客户端窗口更新，须有人持续驱动连接）
    async fn spawn_packet_up_server(
        expected_posts: usize,
        record_seq: impl Fn(u64) + Send + 'static,
    ) -> String {
        use std::sync::{Arc, Mutex};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            // 流/连接窗口放大到 1MiB：64KiB POST 块 > 缺省 65535 窗口，
            // 排水-更新互易依赖 h2 服务端 WINDOW_UPDATE 时机，镜像对端不
            // 复刻该细节（被测契约是 URL/seq/重组形状，非窗口调优）
            let mut conn = h2::server::Builder::new()
                .initial_window_size(1 << 20)
                .initial_connection_window_size(1 << 20)
                .handshake::<_, Bytes>(socket)
                .await
                .unwrap();
            let uploads: Arc<Mutex<std::collections::BTreeMap<u64, Vec<u8>>>> =
                Arc::new(Mutex::new(std::collections::BTreeMap::new()));
            let session: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
            let download: Arc<Mutex<Option<h2::SendStream<Bytes>>>> = Arc::new(Mutex::new(None));
            let done = Arc::new(tokio::sync::Notify::new());
            loop {
                tokio::select! {
                    req = conn.accept() => {
                        let Some(req) = req else {
                            break;
                        };
                        let (req, mut respond) = req.unwrap();
                        let parts = req.uri().path().split('/').collect::<Vec<_>>();
                        if req.method() == http::Method::GET {
                            // GET {base}/{session}
                            assert_eq!(
                                parts.len(),
                                3,
                                "GET 形状 /{{base}}/{{session}}: {}",
                                req.uri().path()
                            );
                            *session.lock().unwrap() = parts[2].to_string();
                            assert!(!parts[2].is_empty(), "session 段不得为空");
                            let response = http::Response::builder().status(200).body(()).unwrap();
                            *download.lock().unwrap() =
                                Some(respond.send_response(response, false).unwrap());
                            continue;
                        }
                        // POST {base}/{session}/{seq}
                        assert_eq!(
                            parts.len(),
                            4,
                            "POST 形状 /{{base}}/{{session}}/{{seq}}: {}",
                            req.uri().path()
                        );
                        assert_eq!(
                            parts[2],
                            session.lock().unwrap().as_str(),
                            "POST session 段须与 GET 一致"
                        );
                        let seq: u64 = parts[3].parse().expect("seq 须为数字");
                        record_seq(seq);
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let _ = respond.send_response(response, true).unwrap();
                        let uploads_h = uploads.clone();
                        let done_h = done.clone();
                        tokio::spawn(async move {
                            let mut body = req.into_body();
                            let mut acc = Vec::new();
                            // 空 chunk = EOS（语义行）；错误/流尾同径退出
                            while let Some(Ok(chunk)) = body.data().await {
                                let len = chunk.len();
                                body.flow_control().release_capacity(len).unwrap();
                                if chunk.is_empty() {
                                    break; // EOS
                                }
                                acc.extend_from_slice(&chunk);
                            }
                            let mut map = uploads_h.lock().unwrap();
                            map.insert(seq, acc);
                            let full = map.len() >= expected_posts;
                            drop(map);
                            if full {
                                done_h.notify_one();
                            }
                        });
                    }
                    _ = done.notified() => {
                        break;
                    }
                }
            }
            // 收满期望 POST 数 = 上传完结：按 seq 序回放下行（容量驱动——
            // 回放体 >64KiB 缺省窗口，须按授予量切帧；放独立任务，驱动交
            // 由收尾 accept 循环）
            let dl = download.lock().unwrap().take();
            if let Some(mut dl) = dl {
                let ordered = {
                    let mut map = uploads.lock().unwrap();
                    let mut ordered = Vec::new();
                    for part in map.values() {
                        ordered.extend_from_slice(part);
                    }
                    map.clear();
                    Bytes::from(ordered)
                };
                tokio::spawn(async move {
                    h2_send_all(&mut dl, ordered).await;
                    dl.send_data(Bytes::new(), true).unwrap();
                });
            }
            // 下行帧须持续推进到客户端读毕（直接 drop 会在帧 flush 前 RST）
            while conn.accept().await.is_some() {}
        });
        addr
    }

    #[tokio::test]
    async fn stream_one_roundtrip_byte_exact() {
        let addr = spawn_stream_one_server().await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let mut stream = xhttp_tunnel(tcp, "example.com", "/xh", XhttpMode::StreamOne)
            .await
            .expect("隧道建立");

        let payload = deterministic_payload(4096);
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload, "stream-one 往返须逐字节一致");
    }

    #[tokio::test]
    async fn packet_up_roundtrip_reassembles_by_seq() {
        // seq 形状：自 0 连续（镜像对端逐项断言）；> 64KiB 触发多 POST
        // 分块（MAX_POST_BODY 边界核验）→ 恰 3 个 POST
        let payload = deterministic_payload(MAX_POST_BODY * 2 + 1234);
        let seqs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seqs_task = seqs.clone();
        let addr = spawn_packet_up_server(3, move |seq| {
            seqs_task.lock().unwrap().push(seq);
        })
        .await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let mut stream = xhttp_tunnel(tcp, "example.com", "/up", XhttpMode::PacketUp)
            .await
            .expect("隧道建立");

        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload, "packet-up 按 seq 重组须逐字节一致");

        let got = seqs.lock().unwrap().clone();
        assert_eq!(got, vec![0, 1, 2], "seq 须自 0 连续: {got:?}");
    }

    /// 非 200 下载流具名拒绝（XHTTP 无独立错误响应面——HTTP 状态即拒绝面）
    #[tokio::test]
    async fn download_non_200_refused_by_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let mut conn = h2::server::handshake(socket).await.unwrap();
            let Some(req) = conn.accept().await else {
                return;
            };
            let (req, mut respond) = req.unwrap();
            assert_eq!(req.method(), http::Method::GET);
            let response = http::Response::builder().status(403).body(()).unwrap();
            let _ = respond.send_response(response, true);
            // 403 响应头须持续推进到客户端读到（直接 drop 会先断连接）
            while conn.accept().await.is_some() {}
        });

        let tcp = TcpStream::connect(&addr).await.unwrap();
        let err = xhttp_tunnel(tcp, "example.com", "/xh", XhttpMode::PacketUp)
            .await
            .expect_err("非 200 须拒绝");
        assert!(err.to_string().contains("403"), "{err}");
    }

    fn deterministic_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }
}
