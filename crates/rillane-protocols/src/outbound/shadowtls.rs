//! ShadowTLS v2 载具客户端面（RIL-110）。
//!
//! 线格式以官方 ihciah/shadow-tls v0.2.20 为基准（docs/protocol-en.md v2 规格
//! 与 helper_v2.rs / server.rs `relay_v2` / client.rs `relay_v2`/`connect_v2`
//! / util.rs 封帧常量，源码浅读 2026-11-17）：
//! - 握手段：对 shadowtls 服务器做真实 TLS 握手（SNI = 伪装站点，证书链由
//!   真实站点经服务器中继签发）——客户端不改 ClientHello（v2 无需 TLS 库
//!   fork，与官方 v3 的 rustls fork 路线划清边界）；读侧以 HMAC-SHA1(password)
//!   累积握手站点发来的每个字节作挑战源。
//! - 切换段：握手完成后，首条伪 application-data 记录（0x17、版本字节
//!   0x03 0x03）内容前缀 8 字节挑战（20 字节摘要截断，官方 HMAC_SIZE_V2）；
//!   此后内层数据全部按伪记录封帧（单记录内容 ≤ 4091 字节，对齐官方
//!   4096 字节 COPY_BUF）。
//! - 读侧：保留 rustls 会话过滤伪装站点残余帧（能被会话处理的记录丢弃，
//!   官方 SessionFilterStream 语义）；首个会话处理失败的记录即内层数据，
//!   此后仅按记录解帧直通（官方 copy_without_application_data 语义）。
//!
//! 载具无寻址面：目标寻址归内层协议。本面组合 Shadowsocks——经 shadowsocks
//! crate `ProxyClientStream::from_stream`（流注入构造器）把内层 SS 面架在
//! 载具流上；UDP 不经 shadow-tls（载具无 UDP 面，不配 UDP 连接器）。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rillane_core::{EgressConnector, Flow, FlowReport};
use rustls::ClientConnection;
use sha1::Sha1;
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::SharedContext,
    relay::tcprelay::proxy_stream::ProxyClientStream,
    relay::Address,
    ServerAddr,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use crate::{fingerprint::TlsFingerprint, tls::create_tls_connector_with_profile};

/// TLS 记录头长度（type 1 + version 2 + length 2）
const TLS_HEADER_SIZE: usize = 5;
/// application-data 记录类型
const APPLICATION_DATA: u8 = 0x17;
/// 伪记录版本字节（官方 TLS_MAJOR/TLS_MINOR.0 = 0x03/0x03）
const TLS_MAJOR: u8 = 0x03;
const TLS_MINOR: u8 = 0x03;
/// 挑战长度（官方 HMAC_SIZE_V2）：20 字节摘要截断 8 字节
const CHALLENGE_LEN: usize = 8;
/// 伪记录内容上限（官方 COPY_BUF_SIZE 4096 − 记录头）
const RECORD_CONTENT_MAX: usize = 4096 - TLS_HEADER_SIZE;
/// SHA1 摘要长度
const SHA1_LEN: usize = 20;

type HmacSha1 = Hmac<Sha1>;

// ---------------------------------------------------------------------------
// Shadowsocks over ShadowTLS 出站连接器
// ---------------------------------------------------------------------------

/// SS over ShadowTLS（v2）出站连接器：拨载具 → 真实 TLS 握手 → 挑战切换 →
/// 内层 SS 面架在载具流上。SS 方法/口令校验与 [`crate::outbound::shadowsocks`]
/// 同口径（同一套构建期具名拒绝）。
pub struct ShadowsocksShadowTlsConnector {
    /// 载具服务器（shadowtls server）
    server: String,
    port: u16,
    /// 伪装站点域（SNI；挑战应答与证书链都属它）
    host: String,
    /// 载具口令（HMAC-SHA1 键）
    password: String,
    skip_cert_verify: bool,
    /// SS 内层
    context: SharedContext,
    server_config: ServerConfig,
}

impl ShadowsocksShadowTlsConnector {
    pub fn new(
        server: String,
        port: u16,
        host: String,
        password: String,
        skip_cert_verify: bool,
        method: String,
        ss_password: String,
    ) -> Result<Self> {
        let context = shadowsocks::context::Context::new_shared(ServerType::Local);
        // 加密方法校验提前到构建期（与 shadowsocks 出站同口径同文案：
        // 配置错误在启动时暴露，而非首个连接时）
        let server_config = build_server_config(&server, port, &method, &ss_password)?;

        Ok(Self {
            server,
            port,
            host,
            password,
            skip_cert_verify,
            context,
            server_config,
        })
    }

    fn server_config(&self) -> &ServerConfig {
        &self.server_config
    }
}

/// SS 服务器配置构建（与 outbound/shadowsocks.rs `build_server_config`
/// 同口径同文案；该文件归属并发会话，此处独立成面）
fn build_server_config(
    server: &str,
    port: u16,
    method: &str,
    password: &str,
) -> Result<ServerConfig> {
    let cipher = method
        .parse::<shadowsocks::crypto::CipherKind>()
        .map_err(|_| anyhow!("不支持的加密方法: {method}"))?;
    // 无加密不放行；SS2022 的 password 语义是 base64 密钥（长度须与算法
    // 密钥长精确一致），构建期校验
    if cipher == shadowsocks::crypto::CipherKind::NONE {
        bail!("加密方法 none（无加密）不放行: {method}");
    }
    if cipher.is_aead_2022() {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(password)
            .map_err(|_| anyhow!("SS2022 密码须为 base64 密钥: {method}"))?;
        let need = cipher.key_len();
        if key.len() != need {
            bail!(
                "SS2022 密钥长度须为 {need} 字节，得 {} 字节: {method}",
                key.len()
            );
        }
    }
    let addr = ServerAddr::DomainName(server.to_string(), port);
    Ok(ServerConfig::new(addr, password.to_string(), cipher)?)
}

#[async_trait]
impl EgressConnector for ShadowsocksShadowTlsConnector {
    fn name(&self) -> &'static str {
        "shadowsocks-shadowtls"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        // 拨载具
        let tcp = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .with_context(|| format!("ShadowTLS 载具连接失败: {}", self.server))?;

        // 真实 TLS 握手（SNI = 伪装站点；证书链经载具中继自真实站点，
        // 读侧哈希累积挑战源）
        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| anyhow!("ShadowTLS 伪装站点名非法: {}", self.host))?;
        let connector =
            create_tls_connector_with_profile(self.skip_cert_verify, None, TlsFingerprint::None)?;
        let hashed = HashedReadIo::new(tcp, &self.password);
        let tls = connector
            .connect(name, hashed)
            .await
            .context("ShadowTLS 载具 TLS 握手失败")?;

        // 收回裸流 + 保留会话 + 取挑战摘要
        let (io, session) = tls.into_inner();
        let (hash, raw) = io.into_digest();
        let mut challenge = [0u8; CHALLENGE_LEN];
        challenge.copy_from_slice(&hash[..CHALLENGE_LEN]);
        let carrier = ShadowTlsStream::new(raw, session, challenge);

        // 内层 SS 面架在载具流上（目标寻址归 SS 协议——载具无寻址面）
        let target_addr = Address::DomainNameAddress(flow.target.host.clone(), flow.target.port);
        let mut remote = ProxyClientStream::from_stream(
            self.context.clone(),
            carrier,
            self.server_config(),
            target_addr,
        );

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut remote,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// 握手段：读侧哈希累积（挑战源 = 握手站点发来的每个字节）
// ---------------------------------------------------------------------------

/// TLS 握手期的读侧哈希包装：read 的每个字节进 HMAC-SHA1(password)，
/// write 原样透传。握手完成后 [`Self::into_digest`] 取 20 字节摘要并
/// 收回裸流。
struct HashedReadIo<S> {
    io: S,
    mac: HmacSha1,
}

impl<S> HashedReadIo<S> {
    fn new(io: S, password: &str) -> Self {
        Self {
            io,
            // HMAC-SHA1 键接受任意长度（官方同款 new_from_slice 面）
            mac: HmacSha1::new_from_slice(password.as_bytes()).expect("HMAC-SHA1 接受任意长度键"),
        }
    }

    /// 结束哈希累积，返回（裸流，20 字节摘要）
    fn into_digest(self) -> ([u8; SHA1_LEN], S) {
        let hash = self
            .mac
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("SHA1 摘要长度恒 20 字节");
        (hash, self.io)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HashedReadIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = &buf.filled()[before..];
                if !filled.is_empty() {
                    this.mac.update(filled);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HashedReadIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 切换段：伪记录封帧 / 解帧 + 残余帧过滤
// ---------------------------------------------------------------------------

/// ShadowTLS v2 载具流：内层数据的双向伪记录面。
///
/// 写侧：内层字节按 0x17/0x0303 伪记录封帧（首条记录内容前缀 8 字节挑战，
/// 官方 copy_with_application_data 语义）。
/// 读侧：先过 rustls 会话滤除伪装站点残余帧（官方 SessionFilterStream 语义），
/// 首个会话处理失败的记录即内层数据，此后仅解帧直通
/// （官方 copy_without_application_data 语义）。
pub struct ShadowTlsStream<S> {
    io: S,
    /// 握手后的 rustls 会话（仅用于残余帧过滤；direct 后不再触碰）
    session: Option<ClientConnection>,
    rx: RxState,
    tx: TxState,
}

struct RxState {
    /// 原始入站缓冲（记录边界装配）
    raw: BytesMut,
    /// 已解帧待交内容
    plain: BytesMut,
    /// 首个会话处理失败后的直通档（此后仅解帧、不再过滤）
    direct: bool,
}

struct TxState {
    /// 已封帧未写完
    pending: BytesMut,
    /// 首个非空记录前置的挑战
    first: Option<[u8; CHALLENGE_LEN]>,
}

impl<S> ShadowTlsStream<S> {
    fn new(io: S, session: ClientConnection, challenge: [u8; CHALLENGE_LEN]) -> Self {
        Self {
            io,
            session: Some(session),
            rx: RxState {
                raw: BytesMut::new(),
                plain: BytesMut::new(),
                direct: false,
            },
            tx: TxState {
                pending: BytesMut::new(),
                first: Some(challenge),
            },
        }
    }
}

/// 从 raw 缓冲装配一条完整记录（不足则补读；EOF 边界具名处理）
macro_rules! assemble_record {
    ($self:expr, $cx:expr) => {{
        loop {
            if $self.rx.raw.len() >= TLS_HEADER_SIZE {
                let len =
                    u16::from_be_bytes([$self.rx.raw[3], $self.rx.raw[4]]) as usize;
                if $self.rx.raw.len() >= TLS_HEADER_SIZE + len {
                    break Ok(Some($self.rx.raw.split_to(TLS_HEADER_SIZE + len)));
                }
            }
            // 补给
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut $self.io).poll_read($cx, &mut rb)? {
                Poll::Ready(()) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // EOF：缓冲有残 = 记录截断；残帧内容待交 = 先交付再收口
                        if !$self.rx.plain.is_empty() {
                            break Ok(None);
                        }
                        if $self.rx.raw.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        break Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ShadowTLS 记录截断",
                        ));
                    }
                    $self.rx.raw.extend_from_slice(&rb.filled()[..n]);
                }
                Poll::Pending => {
                    if !$self.rx.plain.is_empty() {
                        // 已有解帧内容可交——挂起前先交付
                        break Ok(None);
                    }
                    return Poll::Pending;
                }
            }
        }
    }};
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for ShadowTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 已解帧内容先交付
            if !this.rx.plain.is_empty() {
                let n = this.rx.plain.len().min(buf.remaining());
                let src = this.rx.plain.split_to(n);
                buf.put_slice(&src);
                return Poll::Ready(Ok(()));
            }

            match assemble_record!(this, cx) {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(None) => continue, // 交付 plain 或 EOF 收口
                Ok(Some(rec)) => {
                    let content = rec[TLS_HEADER_SIZE..].to_vec();
                    let direct_now = match this.session.as_mut() {
                        Some(session) => {
                            // 会话过滤：能处理的记录是伪装站点残余帧——丢弃
                            match session.read_tls(&mut &rec[..]) {
                                Ok(_) => session.process_new_packets().is_err(),
                                Err(_) => true,
                            }
                        }
                        None => true,
                    };
                    if direct_now {
                        this.rx.direct = true;
                        // 过滤面退役（官方 direct 语义：此后仅解帧）
                        this.session = None;
                    }
                    if this.rx.direct {
                        this.rx.plain.extend_from_slice(&content);
                    }
                    // 未 direct：残余帧已滤除，继续装配下一条
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for ShadowTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 先排空在途帧
        while !this.tx.pending.is_empty() {
            match Pin::new(&mut this.io).poll_write(cx, &this.tx.pending)? {
                Poll::Ready(n) => {
                    let _ = this.tx.pending.split_to(n);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 封帧：内容 ≤ RECORD_CONTENT_MAX；首条记录前缀挑战
        let challenge_room = this.tx.first.map_or(0, |_| CHALLENGE_LEN);
        let n = buf.len().min(RECORD_CONTENT_MAX - challenge_room);
        {
            let first = this.tx.first.take();
            let p = &mut this.tx.pending;
            p.put_u8(APPLICATION_DATA);
            p.put_u8(TLS_MAJOR);
            p.put_u8(TLS_MINOR);
            p.put_u16((n + challenge_room) as u16);
            if let Some(ch) = first {
                p.put_slice(&ch);
            }
            p.put_slice(&buf[..n]);
        }

        // 尽力写出（写不完留在 pending，poll_flush 收尾）
        while !this.tx.pending.is_empty() {
            match Pin::new(&mut this.io).poll_write(cx, &this.tx.pending)? {
                Poll::Ready(n) => {
                    let _ = this.tx.pending.split_to(n);
                }
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.tx.pending.is_empty() {
            match Pin::new(&mut this.io).poll_write(cx, &this.tx.pending)? {
                Poll::Ready(n) => {
                    let _ = this.tx.pending.split_to(n);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.tx.pending.is_empty() {
            match Pin::new(&mut this.io).poll_write(cx, &this.tx.pending)? {
                Poll::Ready(n) => {
                    let _ = this.tx.pending.split_to(n);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// 无握手会话（任何记录处理即失败 → 立即直通档；封帧/解帧面单测够用）
    fn dummy_session() -> ClientConnection {
        let config = crate::tls::profile_client_config(true, None, TlsFingerprint::None)
            .expect("测试 ClientConfig");
        let name: rustls::pki_types::ServerName<'static> =
            "localhost".try_into().expect("测试 ServerName");
        ClientConnection::new(config, name).expect("测试会话")
    }

    #[tokio::test]
    async fn first_record_wire_shape() {
        let (client_side, mut wire) = duplex(64 * 1024);
        let mut carrier = ShadowTlsStream::new(client_side, dummy_session(), [7u8; 8]);

        carrier.write_all(b"hello").await.expect("写内层");
        carrier.flush().await.expect("flush");

        let mut head = [0u8; TLS_HEADER_SIZE + CHALLENGE_LEN + 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            wire.read_exact(&mut head),
        )
        .await
        .expect("读线超时")
        .expect("读线");
        assert_eq!(head[0], APPLICATION_DATA, "伪记录类型 0x17");
        assert_eq!(head[1], TLS_MAJOR, "版本字节 0x03");
        assert_eq!(head[2], TLS_MINOR, "版本字节 0x03");
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        assert_eq!(len, CHALLENGE_LEN + 5, "记录长度 = 挑战 + 内层");
        assert_eq!(
            &head[TLS_HEADER_SIZE..TLS_HEADER_SIZE + CHALLENGE_LEN],
            &[7u8; 8],
            "挑战前缀"
        );
        assert_eq!(
            &head[TLS_HEADER_SIZE + CHALLENGE_LEN..],
            b"hello",
            "内层字节原样"
        );
    }

    /// 大负载多记录切分：每记录内容 ≤ 4091，重组后逐字节还原
    #[tokio::test]
    async fn large_payload_splits_into_records() {
        let (client_side, mut wire) = duplex(64 * 1024);
        let mut carrier = ShadowTlsStream::new(client_side, dummy_session(), [1u8; 8]);

        let payload: Vec<u8> = (0..RECORD_CONTENT_MAX * 2 + 100)
            .map(|i| (i % 251) as u8)
            .collect();
        carrier.write_all(&payload).await.expect("写内层");
        carrier.flush().await.expect("flush");
        drop(carrier);

        let mut wire_bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            wire.read_to_end(&mut wire_bytes),
        )
        .await
        .expect("读线超时")
        .expect("读线");

        // 解帧重组（首记录含挑战）
        let mut rebuilt = Vec::new();
        let mut cur = &wire_bytes[..];
        let mut first = true;
        while cur.len() >= TLS_HEADER_SIZE {
            assert_eq!(cur[0], APPLICATION_DATA, "记录类型");
            let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;
            let content = &cur[TLS_HEADER_SIZE..TLS_HEADER_SIZE + len];
            assert!(
                len <= RECORD_CONTENT_MAX,
                "记录内容 {len} 超上限 {RECORD_CONTENT_MAX}"
            );
            if first {
                assert_eq!(&content[..CHALLENGE_LEN], &[1u8; 8], "首记录挑战前缀");
                rebuilt.extend_from_slice(&content[CHALLENGE_LEN..]);
                first = false;
            } else {
                rebuilt.extend_from_slice(content);
            }
            cur = &cur[TLS_HEADER_SIZE + len..];
        }
        assert!(cur.is_empty(), "线字节恰为完整记录序列");
        assert_eq!(rebuilt, payload, "多记录重组逐字节还原");
    }

    /// 直通档解帧：无握手会话即判直通，记录内容按序交付
    #[tokio::test]
    async fn direct_mode_deframes_records() {
        let (mut wire_w, client_side) = duplex(64 * 1024);
        let mut carrier = ShadowTlsStream::new(client_side, dummy_session(), [0u8; 8]);

        let mut frame = BytesMut::new();
        frame.put_u8(APPLICATION_DATA);
        frame.put_u8(0x03);
        frame.put_u8(0x03);
        frame.put_u16(5);
        frame.put_slice(b"world");
        wire_w.write_all(&frame).await.expect("写线");

        let mut got = vec![0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut carrier, &mut got),
        )
        .await
        .expect("读超时")
        .expect("读解帧内容");
        assert_eq!(got, b"world", "直通档记录内容交付");
    }
}
