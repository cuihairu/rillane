//! Snell v4 出站客户端面（RIL-111）。
//!
//! 线格式以公开真源 sagernet/sing-snell master 为基准（2026-11-18 浅读；
//! 评估记录 docs/protocol-backends.md#snell——注册表唯一命中 `snells`
//! 0.1.0 占位符、活跃实现皆 Go，自写结论留证后落码）：
//! - 密钥派生（`crypto.go` DeriveKey）：Argon2id(psk, salt, t=3, m=8KiB,
//!   p=1)[:16] → AES-128-GCM；每个方向独立 salt（16 字节随机）。
//! - 记录封帧（`snellv4/record.go`）：每记录 = [salt 仅首记录][头密文 23 =
//!   明文 7 + tag 16][填充明文][负载密文 len+16]；头明文
//!   `{0x04, 0, 0, BE 填充长, BE 负载长}`；AAD 恒空；nonce 从 12 零字节
//!   起，每封一次（头/负载各一次）按 u64le 计数自增（`crypto.go`
//!   IncreaseNonce）；填充与负载密文按**偶数下标**互换（写封后换、读开
//!   前换回）——填充明文不由接收方校验（换回即弃），本客户端出均匀
//!   随机填充（官方 `fillPadding` one-ratio 整形是指纹启发式而非线结构，
//!   具名判负）。
//! - 首记录（`framePaddingLen`/`payloadLimitFor`）：携 salt 与初始填充
//!   len∈[0x100, 0x1ff]，本段负载上限 = 1460 − 55 − 初始填充；后续记录
//!   上限 = 1460 − 39 = 1421（负载上限随写节奏累积的整形面按稳态口径
//!   落定，任何 ≤ 0x3fff 的合法记录对端皆收）。负载长 0 的记录即零块
//!   （EOF 信号，`WriteZeroChunk`）。
//! - 请求负载（`request.go` + `address.go`）：`{0x01, 0x05, len(userkey),
//!   userkey, 1 字节长(host), host, port u16 大端}`——CONNECT 目标恒为
//!   host 串（字面 IP 亦然，官方 targetHandshakeData 语义）。
//! - 应答（`internal/reuse/reuse.go` ParseReply）：首条记录明文首字节
//!   `0x00` 隧道（余下字节即隧道数据）或 `0x02` 错误（`{code u8,
//!   SockString 消息}`，不得有尾随数据）；其余应答码具名拒绝。
//!
//! 交付边界（评估记录具名）：v4 + obfs=none 仅 TCP 面；v5/v6（另一握手
//! 族）、obfs http/tls、UDP-over-TCP 数据报面、连接器复用、服务端面均
//! 不在本段——目录 udp=false。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
#[cfg(test)]
use anyhow::anyhow;
use anyhow::{bail, Context as _, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use bytes::BytesMut;
use rand::{rngs::OsRng, RngCore};
use rillane_core::{EgressConnector, Flow, FlowReport};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

/// 记录头版本（`snell.go` HeaderVersion）
pub(crate) const HEADER_VERSION: u8 = 0x04;
/// 头明文长（`snell.go` HeaderPlainLen）
pub(crate) const HEADER_PLAIN_LEN: usize = 7;
/// AEAD tag 长（`snell.go` AEADTagLen）
pub(crate) const AEAD_TAG_LEN: usize = 16;
/// 头密文长（明文 7 + tag 16）
pub(crate) const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + AEAD_TAG_LEN;
/// 每方向 salt 长（`snell.go` SaltLen）
pub(crate) const SALT_LEN: usize = 16;
/// nonce 长（`snell.go` NonceLen）
pub(crate) const NONCE_LEN: usize = 12;
/// 单记录负载上限（`snell.go` MaxPayloadLen）
pub(crate) const MAX_PAYLOAD_LEN: usize = 0x3fff;
/// 请求版本（`snell.go` RequestVersion）
pub(crate) const REQUEST_VERSION: u8 = 0x01;
/// 命令字（`snell.go`）：ConnectV2（v4 TCP 握手恒用 5，官方注释点名
/// Surge 6.7.0 targetHandshakeData——即便连接器复用关闭）
pub(crate) const COMMAND_CONNECT_V2: u8 = 0x05;
/// 应答码（`snell.go`）：0x00 隧道 / 0x02 错误
pub(crate) const REPLY_TUNNEL: u8 = 0x00;
pub(crate) const REPLY_ERROR: u8 = 0x02;

/// 帧尺寸（`snellv4/record.go` frameSize，`encryptData:outData` 常量族）
pub(crate) const FRAME_SIZE: usize = 1460;
/// 首记录开销（salt 16 + 头 23 + tag 16 = 55）
pub(crate) const FIRST_RECORD_OVERHEAD: usize = 55;
/// 后续记录开销（头 23 + tag 16 = 39）
pub(crate) const RESET_RECORD_OVERHEAD: usize = 39;
/// 初始填充下界 / 跨度（initialPaddingMin / initialPaddingSpan）
pub(crate) const INITIAL_PADDING_MIN: usize = 0x100;
pub(crate) const INITIAL_PADDING_SPAN: usize = 0x100;

/// 拨号超时（与 hysteria/hysteria2 同口径）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// 记录密钥派生（官方 `crypto.go` DeriveKey）：
/// Argon2id(psk, salt, t=3, m=8KiB, p=1)[:16]。
///
/// Go 侧调用是 `argon2.IDKey(psk, salt, 3, 8, 1, 32)`，`memory=8` 的语义是
/// **8 KiB = 8 个 1 KiB 区块**。x/crypto/argon2 有一处夹取
/// （`memory = memory/4/1*4/1`；`memory < 2*4*1` 时抬到 8）——8 恰好不触发
/// 抬升（8 < 8 为假），故 Go 生效内存就是 8 KiB。m_cost 在 argon2 crate 中
/// 亦以 KiB 计（1 区块 = 1 KiB），两侧同量纲，故此处 m_cost 恒写 8。
pub(crate) fn derive_key(psk: &[u8], salt: &[u8]) -> [u8; 16] {
    // 官方参数恒合法：m=8 恰为 argon2 Params::MIN_M_COST（2×4 slices），
    // 出长 32 在 [MIN_OUTPUT_LEN, MAX_OUTPUT_LEN] 内
    let params = Params::new(8, 3, 1, Some(32)).expect("官方参数 m=8/t=3/p=1/32 恒合法");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(psk, salt, &mut out)
        .expect("盐长 16、出长 32 恒在参数约束内");
    out[..16].try_into().expect("恰取前 16 字节")
}

/// nonce 自增（官方 `crypto.go` IncreaseNonce）：低地址节起 u64le 计数
/// 进位透传（4..12 恒零——每次自增至多越过低 8 字节）。
fn increase_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// 单向记录加密上下文（salt 派生的 AES-128-GCM + 会话 nonce 序列）
struct RecordCipher {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
}

impl RecordCipher {
    fn new(psk: &[u8], salt: &[u8; SALT_LEN]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(&derive_key(psk, salt))
                .expect("16 字节密钥恒被 AES-128 接受"),
            nonce: [0u8; NONCE_LEN],
        }
    }
}

/// AEAD 失败 → io::Error（观测口径：协议失败以 io::Error 透出）
fn aead_err(_e: aes_gcm::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Snell 记录解密失败")
}

// ---------------------------------------------------------------------------
// Snell v4 流：双向记录封帧
// ---------------------------------------------------------------------------

/// Snell v4 记录流：`AsyncRead`/`AsyncWrite` 上的双向封帧面。
///
/// 两个方向相互独立（各自的 salt、AEAD 与 nonce 序列）——读侧在首读时
/// 惰性读取对端 salt；写侧在首写时生成自己的 salt（首记录携带）。
/// 关闭写侧（`poll_shutdown`）发送零块记录（payloadLen=0，官方
/// WriteZeroChunk 语义，至多一次）；读到零块即对端写侧收口（干净 EOF），
/// 裸 TCP EOF 若未经零块即为意外 EOF（官方 eof.UnexpectedReader 语义）。
pub struct SnellStream<S> {
    io: S,
    psk: Vec<u8>,
    tx: TxState,
    rx: RxState,
}

struct TxState {
    cipher: Option<RecordCipher>,
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    /// 零块已发（官方 closeWriteOnce 语义：写侧收口至多一次）
    zero_sent: bool,
    /// 初始填充长（[0x100, 0x1ff]，仅首记录）
    initial_padding_len: usize,
    /// 已封帧未写完
    pending: BytesMut,
}

struct RxState {
    cipher: Option<RecordCipher>,
    /// 线字节累积（salt / 头 / 填充 / 负载密文按序装配）
    raw: BytesMut,
    /// 已解密待交
    plain: BytesMut,
    /// 干净收口（零块）；裸 EOF 不置位（报意外 EOF）
    eof: bool,
    /// 对端应答分发状态（官方 `clientConn.readResponse` 惰性口径）
    reply: ReplyState,
    /// 应答分发武装位：仅客户端连接面置位（连接器 forward 与显式
    /// read_reply）。服务器面（镜像对端、UDP 复用段）首条对端记录即
    /// 数据，不持应答头，不武装不分发。
    reply_armed: bool,
    /// 错误应答消息装配缓冲（code 之后的 SockString 本体）
    error_msg: Vec<u8>,
}

/// 对端应答（服务器首条记录明文头部）分发状态。
///
/// 官方客户端写侧不等待应答（`DialConn` 即 `writeRequest` 返回，上行
/// 随发），应答于下行首读分发——官方 v4.1.1 服务器实测在建连/拨号后
/// 不即发应答，先流上行再收应答即无死锁。
enum ReplyState {
    /// 应答码在途（首条对端记录未解出或明文未足）
    Pending,
    /// 错误应答装配中：code 已读，message 余 remaining 字节
    ErrorPartial { code: u8, remaining: usize },
    /// 隧道应答已分发（plain 余量即隧道数据）
    Tunnel,
    /// 具名失败待透出（错误应答装配完毕 / 意外应答码 / 尾随数据）
    Failed(String),
}

/// 应答分发单步结果：Advanced = 已消费明文或已推进状态；NeedMore = 明文
/// 不足，待下一记录补给。
enum ReplyStep {
    Advanced,
    NeedMore,
}

impl<S> SnellStream<S> {
    pub(crate) fn new(io: S, psk: Vec<u8>) -> Self {
        Self {
            io,
            psk,
            tx: TxState {
                cipher: None,
                salt: [0u8; SALT_LEN],
                salt_sent: false,
                zero_sent: false,
                initial_padding_len: 0,
                pending: BytesMut::new(),
            },
            rx: RxState {
                cipher: None,
                raw: BytesMut::new(),
                plain: BytesMut::new(),
                eof: false,
                reply: ReplyState::Pending,
                reply_armed: false,
                error_msg: Vec::new(),
            },
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SnellStream<S> {
    /// 写握手请求（首条记录：salt + 初始填充 + 请求负载）。
    pub(crate) async fn write_request(&mut self, request: &[u8]) -> io::Result<()> {
        self.write_all(request).await?;
        self.flush().await
    }

    /// 读首条应答并按 ParseReply 语义分发：隧道（余下字节即隧道数据，
    /// 留在读缓冲经正常读面交付）或错误（code + SockString 消息，尾随
    /// 数据具名拒绝）。应答于下行首读同样经本机制惰性分发（`reply_step`）；
    /// 本方法只是把分发驱动到定局，供显式握手确认方使用。
    #[cfg(test)]
    pub(crate) async fn read_reply(&mut self) -> Result<()> {
        self.rx.reply_armed = true;
        std::future::poll_fn(|cx| {
            loop {
                match &self.rx.reply {
                    ReplyState::Tunnel => return Poll::Ready(Ok(())),
                    ReplyState::Failed(msg) => return Poll::Ready(Err(anyhow!("{msg}"))),
                    _ => {}
                }
                match self.reply_step() {
                    Err(e) => return Poll::Ready(Err(anyhow!("{e}"))),
                    Ok(ReplyStep::Advanced) => continue,
                    Ok(ReplyStep::NeedMore) => {}
                }
                let outcome = self
                    .poll_read_record(cx)
                    .map_err(|e| anyhow!("Snell 记录读取失败: {e}"))?;
                match outcome {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(payload)) => self.rx.plain.extend_from_slice(&payload),
                    // 零块而应答未定：对端未给应答即收口，具名拒绝
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(anyhow!("Snell 对端应答未至即零块收口")))
                    }
                }
            }
        })
        .await
    }

    /// 应答分发状态判定。
    fn reply_settled(&self) -> bool {
        matches!(self.rx.reply, ReplyState::Tunnel | ReplyState::Failed(_))
    }

    /// 武装对端应答分发（客户端连接面专用：连接器在请求写出后调用，
    /// 下行首读自首条对端记录明文头部剥应答）。
    fn arm_reply(&mut self) {
        self.rx.reply_armed = true;
    }

    /// 应答分发单步：从 plain 头部消费应答码/错误帧，推进 reply 状态。
    /// Advanced = 消费或推进成功（调用方重走交付循环）；NeedMore = 明文
    /// 不足待补给。错误应答具名失败经 Failed 态持久化（每次读透出）。
    fn reply_step(&mut self) -> io::Result<ReplyStep> {
        let RxState {
            plain,
            reply,
            error_msg,
            ..
        } = &mut self.rx;
        match reply {
            ReplyState::Tunnel | ReplyState::Failed(_) => Ok(ReplyStep::Advanced),
            ReplyState::Pending if plain.is_empty() => Ok(ReplyStep::NeedMore),
            ReplyState::Pending => {
                let op = plain[0];
                if op == REPLY_TUNNEL {
                    let _ = plain.split_to(1);
                    *reply = ReplyState::Tunnel;
                    return Ok(ReplyStep::Advanced);
                }
                if op != REPLY_ERROR {
                    let e = format!("Snell 意外应答码 {op:#04x}");
                    *reply = ReplyState::Failed(e.clone());
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
                if plain.len() < 3 {
                    return Ok(ReplyStep::NeedMore);
                }
                let _ = plain.split_to(1);
                let code = plain[0];
                let len = plain[1] as usize;
                let _ = plain.split_to(2);
                *reply = ReplyState::ErrorPartial {
                    code,
                    remaining: len,
                };
                Ok(ReplyStep::Advanced)
            }
            ReplyState::ErrorPartial { code, remaining } => {
                let n = (*remaining).min(plain.len());
                if n > 0 {
                    let part = plain.split_to(n);
                    error_msg.extend_from_slice(&part);
                    *remaining -= n;
                }
                if *remaining > 0 {
                    return Ok(ReplyStep::NeedMore);
                }
                // 官方 ReadServerError：code + 长度 + 消息之外不得有尾随数据
                let e = if !plain.is_empty() {
                    "Snell 错误应答携带尾随数据".to_string()
                } else {
                    let message = String::from_utf8_lossy(error_msg).into_owned();
                    format!("Snell 服务器错误 {code}: {message}")
                };
                *reply = ReplyState::Failed(e.clone());
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }

    /// 读一条完整记录明文；零块返回 None（干净 EOF）。
    ///
    /// 本段（客户端 TCP 段）由 `AsyncRead`/`AsyncWrite` 承载，无调用者——它是
    /// 逐记录复用段（UDP over Snell）的取用点，故以 `cfg(test)` 保留并让
    /// 向量测试经它走通全路；非测试构建不留死码。
    #[cfg(test)]
    pub(crate) async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        std::future::poll_fn(|cx| self.poll_read_record(cx)).await
    }

    fn poll_read_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            // 已装配完整记录则解出
            if let Some(outcome) = self.try_parse_record()? {
                return Poll::Ready(Ok(outcome));
            }
            // 补给线字节
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb)? {
                Poll::Ready(()) => {
                    if rb.filled().is_empty() {
                        // 我方已零块收口后的对端裸 FIN：官方 v4.1.1 实测
                        // 客户端先收口路径对端永不为零块（server 日志有
                        // SN_ENCRYPT_RESULT_ZERO_CHUNK 账，线上无字节——
                        // 本席 10:26/10:28 差分钉死），按干净 EOF 收口。
                        // 与 master eof.UnexpectedReader 严格语义的分叉，
                        // 以官方二进制为准；对端先收口（zero_sent 未置）
                        // 仍按意外 EOF 具名拒绝。
                        if self.tx.zero_sent {
                            self.rx.eof = true;
                            continue;
                        }
                        // 裸 TCP EOF：未经零块即收口 → 意外 EOF（官方
                        // eof.UnexpectedReader 语义；缓冲有残 = 记录截断）
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Snell 对端未经零块即关闭",
                        )));
                    }
                    self.rx.raw.extend_from_slice(rb.filled());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// 从 raw 缓冲装配一条记录。None = 数据不足待补给；
    /// Some(None) = 零块（干净 EOF）；Some(Some(payload)) = 记录明文。
    /// 剩余残字节留在 raw（供尾随数据判定与后续记录装配）。
    fn try_parse_record(&mut self) -> io::Result<Option<Option<Vec<u8>>>> {
        // 对端 salt（首读惰性）
        if self.rx.cipher.is_none() {
            if self.rx.raw.len() < SALT_LEN {
                return Ok(None);
            }
            let salt: [u8; SALT_LEN] = self.rx.raw[..SALT_LEN].try_into().expect("恰 16 字节");
            let _ = self.rx.raw.split_to(SALT_LEN);
            self.rx.cipher = Some(RecordCipher::new(&self.psk, &salt));
        }
        // 头密文 23
        if self.rx.raw.len() < HEADER_CIPHER_LEN {
            return Ok(None);
        }
        let header_cipher: [u8; HEADER_CIPHER_LEN] = self.rx.raw[..HEADER_CIPHER_LEN]
            .try_into()
            .expect("恰 23 字节");
        let rc = self.rx.cipher.as_mut().expect("salt 已装配，cipher 恒在");
        let header_plain = rc
            .cipher
            .decrypt(Nonce::from_slice(&rc.nonce), &header_cipher[..])
            .map_err(aead_err)?;
        increase_nonce(&mut rc.nonce);
        let header = &header_plain[..HEADER_PLAIN_LEN];
        if header[0] != HEADER_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Snell 记录头版本非法: {:#04x}", header[0]),
            ));
        }
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Snell 记录负载超上限",
            ));
        }
        let _ = self.rx.raw.split_to(HEADER_CIPHER_LEN);
        if payload_len == 0 {
            // 零块：内部缓冲不得再有残余（官方「zero chunk has trailing
            // data」语义——bufio 缓冲非空即拒）
            if !self.rx.raw.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Snell 零块携带尾随数据",
                ));
            }
            self.rx.eof = true;
            return Ok(Some(None));
        }
        let total = padding_len + payload_len + AEAD_TAG_LEN;
        if self.rx.raw.len() < total {
            return Ok(None);
        }
        let mut padding = self.rx.raw.split_to(padding_len).to_vec();
        let mut body = self.rx.raw.split_to(payload_len + AEAD_TAG_LEN).to_vec();
        // 偶数下标换回（官方读侧对称逆变换）
        let limit = padding.len().min(body.len());
        for index in (0..limit).step_by(2) {
            core::mem::swap(&mut padding[index], &mut body[index]);
        }
        let payload = rc
            .cipher
            .decrypt(Nonce::from_slice(&rc.nonce), &body[..])
            .map_err(aead_err)?;
        increase_nonce(&mut rc.nonce);
        if payload.len() != payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Snell 记录明文长与头不符",
            ));
        }
        Ok(Some(Some(payload)))
    }

    /// 封一条记录（官方 `makeSliceRecordLocked` 镜像）。
    /// 布局 [salt 仅首记录][头密文 23][填充明文][负载密文]；封后填充与
    /// 负载密文按偶数下标互换。
    fn make_record(&mut self, payload: &[u8]) -> io::Result<BytesMut> {
        debug_assert!(payload.len() <= MAX_PAYLOAD_LEN, "上层已按上限切分");
        let padding_len = if self.tx.salt_sent || payload.is_empty() {
            0
        } else {
            self.tx.initial_padding_len
        };
        let mut out = BytesMut::new();
        if !self.tx.salt_sent {
            out.extend_from_slice(&self.tx.salt);
            self.tx.salt_sent = true;
        }
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[1] = 0;
        header[2] = 0;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let rc = self.tx.cipher.as_mut().expect("首写前已 initialize");
        let header_cipher = rc
            .cipher
            .encrypt(Nonce::from_slice(&rc.nonce), &header[..])
            .map_err(aead_err)?;
        increase_nonce(&mut rc.nonce);
        out.extend_from_slice(&header_cipher);
        let padding_start = out.len();
        out.resize(padding_start + padding_len, 0);
        if !payload.is_empty() {
            let mut body = rc
                .cipher
                .encrypt(Nonce::from_slice(&rc.nonce), payload)
                .map_err(aead_err)?;
            increase_nonce(&mut rc.nonce);
            if padding_len > 0 {
                // 均匀随机填充（官方 fillPadding 的随机回退路径；one-ratio
                // 整形是指纹启发式非线结构，评估记录具名判负）
                OsRng.fill_bytes(&mut out[padding_start..]);
                let (padding, _) = out.split_at_mut(padding_start + padding_len);
                let padding = &mut padding[padding_start..];
                let limit = padding.len().min(body.len());
                for index in (0..limit).step_by(2) {
                    core::mem::swap(&mut padding[index], &mut body[index]);
                }
            }
            out.extend_from_slice(&body);
        }
        Ok(out)
    }

    /// 写侧惰性初始化（官方 `writer.initialize`）：随机 salt + 派生 +
    /// 初始填充长 ∈ [0x100, 0x1ff]。
    fn tx_initialize(&mut self) {
        if self.tx.cipher.is_some() {
            return;
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        self.tx.initial_padding_len =
            INITIAL_PADDING_MIN + (OsRng.next_u32() as usize) % INITIAL_PADDING_SPAN;
        self.tx.cipher = Some(RecordCipher::new(&self.psk, &salt));
        self.tx.salt = salt;
    }

    /// 排空在途帧后封下一段：一次 poll_write 封至多一条记录
    /// （≤ 当前负载上限；与 shadowtls 同形——部分写由上层重试）。
    fn poll_write_one(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // 先排空在途帧
        while !self.tx.pending.is_empty() {
            match Pin::new(&mut self.io).poll_write(cx, &self.tx.pending)? {
                Poll::Ready(n) => {
                    let _ = self.tx.pending.split_to(n);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.tx_initialize();
        // 本记录负载上限（官方 payloadLimitFor 口径：首记录 1460−55−初始
        // 填充；后续 1421 稳态——累积整形面按稳态落定，评估记录具名）
        let payload_limit = if self.tx.salt_sent {
            FRAME_SIZE - RESET_RECORD_OVERHEAD
        } else {
            FRAME_SIZE - FIRST_RECORD_OVERHEAD - self.tx.initial_padding_len
        };
        let n = buf.len().min(payload_limit).min(MAX_PAYLOAD_LEN);
        let record = self.make_record(&buf[..n])?;
        self.tx.pending.extend_from_slice(&record);
        // 尽力写出（写不完留在 pending，poll_flush/poll_shutdown 收尾）
        while !self.tx.pending.is_empty() {
            match Pin::new(&mut self.io).poll_write(cx, &self.tx.pending)? {
                Poll::Ready(written) => {
                    let _ = self.tx.pending.split_to(written);
                }
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(n))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SnellStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 应答惰性分发（官方 `clientConn.readResponse` 口径）：下行首读
            // 时从首条对端记录明文头部剥应答码——隧道剥 1 字节后余量即隧道
            // 数据；错误装配为具名失败透出。上行中继不经此处等待。仅武装
            // 流（客户端连接面）分发；服务器面首条对端记录即数据。
            if this.rx.reply_armed {
                if let ReplyState::Failed(msg) = &this.rx.reply {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        msg.clone(),
                    )));
                }
                if !this.reply_settled() {
                    match this.reply_step() {
                        Err(e) => return Poll::Ready(Err(e)),
                        Ok(ReplyStep::Advanced) => continue,
                        Ok(ReplyStep::NeedMore) => {}
                    }
                }
            }
            // 已解密内容先交付
            if !this.rx.plain.is_empty() {
                let n = this.rx.plain.len().min(buf.remaining());
                let src = this.rx.plain.split_to(n);
                buf.put_slice(&src);
                return Poll::Ready(Ok(()));
            }
            if this.rx.eof {
                // 零块收口而应答未定（武装流）：对端未给应答即收口，具名拒绝
                if this.rx.reply_armed && !this.reply_settled() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Snell 对端应答未至即收口",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            match this.poll_read_record(cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(payload)) => this.rx.plain.extend_from_slice(&payload),
                Poll::Ready(None) => continue, // 零块：下一轮经 eof 位干净收口
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SnellStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_one(cx, buf)
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

    /// 写侧收口：排空在途帧 + 零块记录（官方 WriteZeroChunk，至多一次）
    /// + 底层 shutdown。读侧不受影响（对端仍可回发，直至其零块或关连接）。
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
        if !this.tx.zero_sent {
            if this.tx.cipher.is_none() {
                this.tx_initialize();
            }
            let zero = this.make_record(&[])?;
            this.tx.zero_sent = true;
            let mut zero: &[u8] = &zero;
            while !zero.is_empty() {
                match Pin::new(&mut this.io).poll_write(cx, zero)? {
                    Poll::Ready(n) => zero = &zero[n..],
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 出站连接器
// ---------------------------------------------------------------------------

/// Snell v4 出站连接器（obfs=none）：拨 TCP → 首记录请求（ConnectV2）→
/// 应答分发（隧道/错误）→ 记录封帧双向中继。
#[derive(Debug)]
pub struct SnellConnector {
    server: String,
    port: u16,
    psk: String,
    userkey: String,
}

impl SnellConnector {
    /// 构建期校验（官方 `NewClient` 口径）：空 PSK / 超长 userkey 具名
    /// 拒绝（配置错误在启动时暴露，而非首个连接时）。
    pub fn new(server: String, port: u16, psk: String, userkey: String) -> Result<Self> {
        if psk.is_empty() {
            bail!("Snell 缺少 PSK");
        }
        if userkey.len() > 255 {
            bail!("Snell userkey 超长（> 255 字节）");
        }
        Ok(Self {
            server,
            port,
            psk,
            userkey,
        })
    }
}

/// 请求负载（官方 `request.go` + `address.go`）：
/// `{0x01, 0x05, len(userkey), userkey, len(host), host, port u16 大端}`。
fn build_request(userkey: &str, host: &str, port: u16) -> Result<Vec<u8>> {
    if host.is_empty() || host.len() > 255 {
        bail!("Snell 目标主机名超长: {host}");
    }
    let mut out = Vec::with_capacity(3 + userkey.len() + 1 + host.len() + 2);
    out.push(REQUEST_VERSION);
    out.push(COMMAND_CONNECT_V2);
    out.push(userkey.len() as u8);
    out.extend_from_slice(userkey.as_bytes());
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// 解析请求负载（镜像对端/测试读面）：返回 (userkey, host, port)。
///
/// 服务端面本段未交付，连接器侧无需读入站请求——仅镜像测试对端与布局
/// 向量测试取用，故以 `cfg(test)` 圈定，非测试构建不留死码。
#[cfg(test)]
#[allow(dead_code)] // anyhow!/bail! 宏在测试体外的本函数中展开为 anyhow 路径
fn parse_request(payload: &[u8]) -> Result<(Vec<u8>, String, u16)> {
    let bad = || anyhow!("Snell 请求负载非法");
    if payload.len() < 3 {
        return Err(bad());
    }
    if payload[0] != REQUEST_VERSION {
        return Err(anyhow!("Snell 请求版本非法: {:#04x}", payload[0]));
    }
    if payload[1] != COMMAND_CONNECT_V2 {
        return Err(anyhow!("Snell 不支持的命令: {:#04x}", payload[1]));
    }
    // 最短合法：3 头 + userkey + 1 host 长 + ≥1 host + 2 端口
    let userkey_len = payload[2] as usize;
    if payload.len() < 3 + userkey_len + 4 {
        return Err(bad());
    }
    let userkey = payload[3..3 + userkey_len].to_vec();
    let host_len = payload[3 + userkey_len] as usize;
    // rest = host + 端口（host 长字节已被上方下界消化）
    let rest = &payload[4 + userkey_len..];
    if rest.len() != host_len + 2 || host_len == 0 {
        return Err(bad());
    }
    let host = String::from_utf8_lossy(&rest[..host_len]).into_owned();
    let port = u16::from_be_bytes([rest[host_len], rest[host_len + 1]]);
    Ok((userkey, host, port))
}

#[async_trait]
impl EgressConnector for SnellConnector {
    fn name(&self) -> &'static str {
        "snell"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let addr = format!("{}:{}", self.server, self.port);
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .context("Snell 连接超时")?
            .with_context(|| format!("Snell 服务器连接失败: {addr}"))?;

        let mut stream = SnellStream::new(tcp, self.psk.as_bytes().to_vec());
        let request = build_request(&self.userkey, &flow.target.host, flow.target.port)
            .with_context(|| {
                format!("Snell 目标非法: {}:{}", flow.target.host, flow.target.port)
            })?;
        stream
            .write_request(&request)
            .await
            .context("Snell 请求写入失败")?;
        // 武装对端应答惰性分发；应答不等待：官方客户端 DialConn 即
        // writeRequest 返回，上行随发；
        // 应答于下行首读经流内惰性分发（reply_step）。官方 v4.1.1 服务器
        // 实测拨号后不即发应答（等待数据面首字节），先等应答再中继即死锁
        // ——本席真机差分（server2.log：CONNECT 解出 + 拨号成功 + 应答
        // 缺席）钉死此顺序。
        stream.arm_reply();

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("Snell 双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::{FlowId, TargetProto};
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // -----------------------------------------------------------------------
    // KDF 与 nonce：参数映射 + 向量钉死（真源：crypto.go）
    // -----------------------------------------------------------------------

    /// Argon2id(t=3, m=8KiB, p=1)[:16]：参数合法、与 argon2 参考实现同
    /// 参同截取、固定向量钉死（未来任何参数漂移在此失败）；salt 变则钥变。
    #[test]
    fn derive_key_argon2id_vector_pinned() {
        let params = Params::new(8, 3, 1, Some(32)).expect("官方参数恒合法");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut full = [0u8; 32];
        argon
            .hash_password_into(b"ril111-psk", &[7u8; SALT_LEN], &mut full)
            .expect("盐长 16 合法");
        // derive_key = 官方 32 字节输出的前 16 截取（Go `[:16]` 语义）
        assert_eq!(derive_key(b"ril111-psk", &[7u8; SALT_LEN]), full[..16]);
        // 钉死向量：2026-11-18 由 argon2 0.6.0（Argon2id V0x13, t=3, m=8, p=1,
        // 出长 32）计算落钉——参数或截取长度漂移在此失败
        assert_eq!(
            hex(&derive_key(b"ril111-psk", &[7u8; SALT_LEN])),
            "6921b1af820c8d03041f22c4ecdf3d72"
        );
        assert_ne!(
            derive_key(b"ril111-psk", &[8u8; SALT_LEN]),
            derive_key(b"ril111-psk", &[7u8; SALT_LEN]),
            "salt 变则钥变"
        );
    }

    /// nonce 自增 = 低地址节 u64le 计数进位（官方 IncreaseNonce）
    #[test]
    fn nonce_increment_is_little_endian_with_carry() {
        let mut n = [0u8; NONCE_LEN];
        increase_nonce(&mut n);
        assert_eq!(&n[..5], &[1, 0, 0, 0, 0]);
        // 低字节满溢进位：ff → 00 并抬上一节
        n[0] = 0xff;
        increase_nonce(&mut n);
        assert_eq!(&n[..5], &[0, 1, 0, 0, 0]);
        // 无进位路径：低位非满则只动最低节
        n[3] = 0xff;
        increase_nonce(&mut n);
        assert_eq!(&n[..4], &[1, 1, 0, 255]);
        // 连环进位：低四节全满 → 全归零抬第五节
        n[0] = 0xff;
        n[1] = 0xff;
        n[2] = 0xff;
        increase_nonce(&mut n);
        assert_eq!(&n[..5], &[0, 0, 0, 0, 1]);
        // 5..12 恒零（计数面在低 8 字节内）
        assert!(n[5..].iter().all(|&b| b == 0));
    }

    // -----------------------------------------------------------------------
    // 线形状：不经 SnellStream 读面、手工解密核验字节级布局
    // -----------------------------------------------------------------------

    /// 首记录 = [salt 16][头密文 23][随机填充 ∈ [0x100, 0x1ff]][负载密文]；
    /// 手工派生钥解头核验 7 字节布局、互换还原后逐字节解出请求明文。
    #[tokio::test]
    async fn first_record_wire_shape() {
        let (client_side, mut wire) = tokio::io::duplex(64 * 1024);
        let mut stream = SnellStream::new(client_side, b"ril111-psk".to_vec());
        let request = build_request("user-1", "example.com", 443).expect("请求构造");
        stream.write_request(&request).await.expect("写请求");

        // 精确读 [salt][头密文]（长度已知），解头后再读余量
        let mut head = vec![0u8; SALT_LEN + HEADER_CIPHER_LEN];
        wire.read_exact(&mut head).await.expect("读 salt+头");
        let salt: [u8; SALT_LEN] = head[..SALT_LEN].try_into().expect("salt");
        let cipher =
            Aes128Gcm::new_from_slice(&derive_key(b"ril111-psk", &salt)).expect("手工解密钥");
        let header_cipher = &head[SALT_LEN..];
        // 头 nonce 恒为会话起点 12 零字节
        let header_plain = cipher
            .decrypt(Nonce::from_slice(&[0u8; NONCE_LEN]), header_cipher)
            .expect("手工解头");
        let header = &header_plain[..HEADER_PLAIN_LEN];
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        assert_eq!(header[0], HEADER_VERSION, "头版本 0x04");
        assert_eq!(&header[1..3], &[0, 0], "保留字节为零");
        assert_eq!(payload_len, request.len(), "负载长 = 请求长");
        assert!(
            (INITIAL_PADDING_MIN..INITIAL_PADDING_MIN + INITIAL_PADDING_SPAN)
                .contains(&padding_len),
            "初始填充 ∈ [0x100, 0x1ff]，得 {padding_len}"
        );
        // 余量：填充明文 + 负载密文
        let mut rest = vec![0u8; padding_len + payload_len + AEAD_TAG_LEN];
        wire.read_exact(&mut rest).await.expect("读填充+负载");

        // 偶数下标换回后解出请求明文（负载 nonce = 头封一次后的自增值）
        let mut padding = rest[..padding_len].to_vec();
        let mut body = rest[padding_len..].to_vec();
        let limit = padding.len().min(body.len());
        for index in (0..limit).step_by(2) {
            core::mem::swap(&mut padding[index], &mut body[index]);
        }
        let mut payload_nonce = [0u8; NONCE_LEN];
        payload_nonce[0] = 1;
        let payload = cipher
            .decrypt(Nonce::from_slice(&payload_nonce), &body[..])
            .expect("手工解负载");
        assert_eq!(payload, request, "请求负载逐字节还原");
    }

    /// 后续记录无 salt、无填充；大块写入多记录切分，手工逐记录解密重组。
    #[tokio::test]
    async fn subsequent_records_carry_no_salt_or_padding() {
        let (client_side, mut wire) = tokio::io::duplex(64 * 1024);
        let mut stream = SnellStream::new(client_side, b"psk".to_vec());
        stream.write_all(b"hello world").await.expect("首写");
        stream.write_all(&[0xa5u8; 4000]).await.expect("次写");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire_bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), wire.read_to_end(&mut wire_bytes))
            .await
            .expect("读线超时")
            .expect("读线");

        // 手工逐记录解（salt 后每记录：头 23 [+ 填充] + 负载密文）
        let salt: [u8; SALT_LEN] = wire_bytes[..SALT_LEN].try_into().expect("salt");
        let cipher = Aes128Gcm::new_from_slice(&derive_key(b"psk", &salt)).expect("钥");
        let mut nonce_counter: u64 = 0;
        let mut next_nonce = || {
            let mut n = [0u8; NONCE_LEN];
            n[..8].copy_from_slice(&nonce_counter.to_le_bytes());
            nonce_counter += 1;
            n
        };
        let mut cur = &wire_bytes[SALT_LEN..];
        let mut plaintext = Vec::new();
        let mut record_index = 0usize;
        while !cur.is_empty() {
            let header = cipher
                .decrypt(Nonce::from_slice(&next_nonce()), &cur[..HEADER_CIPHER_LEN])
                .expect("解头");
            assert_eq!(header[0], HEADER_VERSION, "头版本");
            let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
            if record_index == 0 {
                assert!(padding_len >= INITIAL_PADDING_MIN, "首记录携带填充");
            } else {
                assert_eq!(padding_len, 0, "后续记录无填充（记录 {record_index}）");
            }
            let mut body_start = HEADER_CIPHER_LEN + padding_len;
            let mut padding = cur[HEADER_CIPHER_LEN..body_start].to_vec();
            let mut body = cur[body_start..body_start + payload_len + AEAD_TAG_LEN].to_vec();
            body_start += payload_len + AEAD_TAG_LEN;
            let limit = padding.len().min(body.len());
            for i in (0..limit).step_by(2) {
                core::mem::swap(&mut padding[i], &mut body[i]);
            }
            let payload = cipher
                .decrypt(Nonce::from_slice(&next_nonce()), &body[..])
                .expect("解负载");
            plaintext.extend_from_slice(&payload);
            cur = &cur[body_start..];
            record_index += 1;
        }
        // 4000 字节 > 1421 → 至少 3 条：首条 11 字节 + ≥ 3 条
        assert!(record_index >= 4, "多记录切分（得 {record_index} 条）");
        let mut expected = b"hello world".to_vec();
        expected.extend_from_slice(&[0xa5u8; 4000]);
        assert_eq!(plaintext, expected, "多记录手工解密重组还原");
    }

    // -----------------------------------------------------------------------
    // 镜像对端（Rust 镜像官方 reader/writer 记录代码；真源是 Go 源码）
    // -----------------------------------------------------------------------

    /// echo 目标：收多少回多少
    async fn echo_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo 绑定");
        let addr = listener.local_addr().expect("echo 地址");
        let h = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        (addr, h)
    }

    /// 镜像 snell v4 服务器：读请求 → 隧道应答 → 与目标双向记录中继
    /// （目标 EOF → 零块收口）；目标不可达按官方 ReplyError 面
    /// （code + SockString 消息）回错。
    async fn mirror_serve(listener: TcpListener, psk: &'static str, userkey: &'static str) {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                return;
            };
            let psk = psk.as_bytes().to_vec();
            let userkey = userkey.to_string();
            tokio::spawn(async move {
                let mut stream = SnellStream::new(conn, psk);
                let Ok(Some(request)) = stream.read_record().await else {
                    return;
                };
                let Ok((got_userkey, host, port)) = parse_request(&request) else {
                    return;
                };
                if got_userkey != userkey.as_bytes() {
                    return;
                }
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(mut target) => {
                        if stream.write_all(&[REPLY_TUNNEL]).await.is_err()
                            || stream.flush().await.is_err()
                        {
                            return;
                        }
                        // 双向中继：任一侧 EOF → copy 半关对侧（写侧零块）
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                    }
                    Err(e) => {
                        let message = format!("dial failed: {e}");
                        let mut reply = vec![REPLY_ERROR, 1u8];
                        reply.push(message.len() as u8);
                        reply.extend_from_slice(message.as_bytes());
                        if stream.write_all(&reply).await.is_ok() {
                            let _ = stream.flush().await;
                        }
                    }
                }
            });
        }
    }

    async fn spawn_mirror(psk: &'static str, userkey: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("镜像绑定");
        let addr = listener.local_addr().expect("镜像地址");
        tokio::spawn(mirror_serve(listener, psk, userkey));
        addr
    }

    fn make_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
        let (client, outbound_side) = tokio::io::duplex(64 * 1024);
        let flow = Flow {
            id: FlowId::new(),
            target: rillane_core::FlowTarget {
                host: host.to_string(),
                port,
                proto: TargetProto::Tcp,
            },
            io: Box::new(outbound_side),
            metadata: Default::default(),
        };
        (flow, client)
    }

    /// 连接器整链：请求 → 隧道应答 → 记录双向中继（文本 + 多记录大块，
    /// 上行半关 → 零块 → 下行干净 EOF）。
    #[tokio::test]
    async fn connector_roundtrip_via_mirror_server() {
        let (target_addr, _echo) = echo_target().await;
        let mirror_addr = spawn_mirror("ril111-accept-psk", "ril111-user").await;

        let connector = std::sync::Arc::new(
            SnellConnector::new(
                "127.0.0.1".into(),
                mirror_addr.port(),
                "ril111-accept-psk".into(),
                "ril111-user".into(),
            )
            .expect("构造"),
        );
        let (flow, mut client) = make_flow(&target_addr.ip().to_string(), target_addr.port());
        let relay = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.forward(flow).await })
        };

        // 上行：文本 + 大块（> 1421 触发多记录切分）
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        client.write_all(b"snell hello").await.expect("上行写");
        client.write_all(&payload).await.expect("上行大块写");
        client.shutdown().await.expect("上行半关");

        // 下行：echo 回放全部字节后干净 EOF
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
            .await
            .expect("下行超时")
            .expect("下行读");

        let mut expected = b"snell hello".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(got, expected, "回环逐字节还原（含多记录切分）");

        let report = relay.await.expect("join").expect("forward 成功");
        assert_eq!(report.upstream as usize, expected.len(), "上行计数");
        assert_eq!(report.downstream as usize, expected.len(), "下行计数");
    }

    /// 错误应答面：目标不可达 → code + SockString 消息具名透出。
    #[tokio::test]
    async fn unreachable_target_surfaces_error_reply() {
        let mirror_addr = spawn_mirror("ril111-accept-psk", "ril111-user").await;

        let connector = SnellConnector::new(
            "127.0.0.1".into(),
            mirror_addr.port(),
            "ril111-accept-psk".into(),
            "ril111-user".into(),
        )
        .expect("构造");

        // 绑后即弃的端口：回环上即刻 connection refused（保证「不可达」
        // 而非「被占」）
        let blackhole = TcpListener::bind("127.0.0.1:0").await.expect("黑洞绑定");
        let blackhole_addr = blackhole.local_addr().expect("黑洞地址");
        drop(blackhole);

        let (flow, _client) = make_flow(&blackhole_addr.ip().to_string(), blackhole_addr.port());
        let err = connector.forward(flow).await.expect_err("目标不可达应失败");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Snell 服务器错误 1") && msg.contains("dial failed"),
            "错误应答具名透出（code + 消息）: {msg}"
        );
    }

    /// 零块语义：对端零块 → 干净 EOF（read 返回 Ok(0)）；无零块裸关 →
    /// 意外 EOF（官方 eof.UnexpectedReader 语义）。
    #[tokio::test]
    async fn zero_chunk_and_unexpected_eof_semantics() {
        // A. 干净收口：隧道应答 + 数据 + 零块
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = SnellStream::new(a, b"psk-zero".to_vec());
        let mut server = SnellStream::new(b, b"psk-zero".to_vec());
        server
            .write_all(&[REPLY_TUNNEL, 1, 2, 3])
            .await
            .expect("隧道应答+数据同记录");
        server.flush().await.expect("flush");
        client.read_reply().await.expect("隧道应答分发");
        let mut got = [0u8; 3];
        client.read_exact(&mut got).await.expect("隧道数据交付");
        assert_eq!(&got, &[1, 2, 3]);
        // 服务器写侧收口（零块）
        server.shutdown().await.expect("服务器零块收口");
        let mut byte = [0u8; 1];
        let n = client.read(&mut byte).await.expect("零块后读");
        assert_eq!(n, 0, "零块 = 干净 EOF");

        // B. 无零块裸关 → 意外 EOF
        let (c, d) = tokio::io::duplex(64 * 1024);
        let mut client2 = SnellStream::new(c, b"psk-zero".to_vec());
        let mut server2 = SnellStream::new(d, b"psk-zero".to_vec());
        server2.write_all(&[REPLY_TUNNEL]).await.expect("隧道应答");
        server2.flush().await.expect("flush");
        client2.read_reply().await.expect("隧道应答分发");
        drop(server2); // 裸关（无零块）
        let r = client2.read(&mut byte).await;
        assert!(
            matches!(&r, Err(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "裸关应意外 EOF: {r:?}"
        );
    }

    /// 头版本 ≠ 0x04 → 具名拒绝（官方 ErrBadVersion）；PSK 不符 → 解密
    /// 失败（InvalidData）。
    #[tokio::test]
    async fn bad_header_version_and_wrong_psk_refused_by_name() {
        // 伪造 [salt][头密文(版本 0x03)][负载密文] —— 手工封帧，不借道
        // SnellStream 写面
        let (attacker, victim_side) = tokio::io::duplex(64 * 1024);
        let salt = [9u8; SALT_LEN];
        let key = derive_key(b"psk-bad", &salt);
        let cipher = Aes128Gcm::new_from_slice(&key).expect("钥");
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = 0x03; // 非法版本
        header[5..7].copy_from_slice(&1u16.to_be_bytes());
        let sealed_header = cipher
            .encrypt(Nonce::from_slice(&[0u8; NONCE_LEN]), &header[..])
            .expect("封头");
        let mut nonce1 = [0u8; NONCE_LEN];
        nonce1[0] = 1;
        let sealed_body = cipher
            .encrypt(Nonce::from_slice(&nonce1), &b"x"[..])
            .expect("封负载");
        let mut framed = Vec::new();
        framed.extend_from_slice(&salt);
        framed.extend_from_slice(&sealed_header);
        framed.extend_from_slice(&sealed_body);
        {
            use tokio::io::AsyncWriteExt;
            let mut attacker = attacker;
            attacker.write_all(&framed).await.expect("发伪造记录");
            attacker.flush().await.expect("flush");
        }
        let mut victim = SnellStream::new(victim_side, b"psk-bad".to_vec());
        let err = victim.read_record().await.expect_err("非法版本应拒收");
        assert!(err.to_string().contains("版本"), "具名拒绝: {err}");

        // PSK 不符：合法记录但钥不同 → 解密失败（InvalidData）
        let (e, f) = tokio::io::duplex(64 * 1024);
        let mut sender = SnellStream::new(e, b"psk-right".to_vec());
        sender.write_all(&[REPLY_TUNNEL, 7]).await.expect("写");
        sender.flush().await.expect("flush");
        drop(sender);
        let mut wrong_psk = SnellStream::new(f, b"psk-wrong".to_vec());
        let err = wrong_psk.read_record().await.expect_err("钥不符应失败");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "解密失败口径: {err}"
        );
    }

    /// 构建期校验：空 PSK / 超 255 userkey / 超 255 host 具名拒绝
    /// （官方 NewClient + targetHandshakeData 口径）；请求负载逐字节布局。
    #[test]
    fn construction_and_request_layout() {
        let e = SnellConnector::new("s".into(), 1, String::new(), "u".into()).unwrap_err();
        assert!(format!("{e:#}").contains("PSK"), "空 PSK 具名: {e:#}");
        let e = SnellConnector::new("s".into(), 1, "p".into(), "k".repeat(256)).unwrap_err();
        assert!(
            format!("{e:#}").contains("userkey"),
            "超长 userkey 具名: {e:#}"
        );
        assert!(SnellConnector::new("s".into(), 1, "p".into(), "u".into()).is_ok());
        // host 长 255 恰可、256 拒
        assert!(build_request("u", &"h".repeat(255), 80).is_ok());
        assert!(build_request("u", &"h".repeat(256), 80).is_err());
        // 请求负载布局核验
        let req = build_request("user", "example.com", 443).expect("构造");
        assert_eq!(
            req,
            vec![
                REQUEST_VERSION,
                COMMAND_CONNECT_V2,
                4,
                b'u',
                b's',
                b'e',
                b'r',
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'c',
                b'o',
                b'm',
                0x01,
                0xbb,
            ],
            "请求负载逐字节布局"
        );
        let (uk, host, port) = parse_request(&req).expect("对称解析");
        assert_eq!(
            (uk.as_slice(), host.as_str(), port),
            (b"user".as_slice(), "example.com", 443)
        );
        // 残缺负载拒绝
        assert!(parse_request(&req[..req.len() - 1]).is_err());
        assert!(parse_request(&[]).is_err());
    }

    // -----------------------------------------------------------------------
    // 真实对端：官方 snell-server（Surge 官方二进制，本席 127.0.0.1:23410）
    // -----------------------------------------------------------------------

    /// 官方对端常驻面：本席 /tmp/snellpeer snell-server v4.1.1（linux-amd64
    /// 官方静态二进制，psk = SNELL_PEER_PSK，obfs=off）。RIL-111 此前仅对
    /// 镜像对端（本仓 Rust 自写、与官方 sing-snell 源码逐帧对读）验收——
    /// 本测试补官方二进制真机字节流面。
    const SNELL_PEER_ADDR: (&str, u16) = ("127.0.0.1", 23410);
    const SNELL_PEER_PSK: &str = "rillane-peer-psk-2026";

    async fn snell_peer_ready() -> bool {
        tokio::time::timeout(Duration::from_millis(500), async {
            tokio::net::TcpStream::connect((SNELL_PEER_ADDR.0, SNELL_PEER_ADDR.1))
                .await
                .map(|_| ())
        })
        .await
        .is_ok()
    }

    /// 官方对端全链：ConnectV2 请求（零长 userkey = 官方 UserKey 缺省口径）
    /// → 上行先行不半关（官方对端应答惰性：拨号后不即发，等待数据面首字
    /// 节；且官方零块 = 双向收口，半关回读面不可用——与镜像对端语义差记
    /// 录在案）→ 下行回读全量（应答于下行首读经流内惰性分发）→ 全关收束。
    /// 逐字节还原 + FlowReport 计数与镜像对端同口径。对端缺席记名跳过
    /// （与 ssh 对端测试同口径）；跳过不计入验收——验收断言以本席真机
    /// 运行为准。
    #[tokio::test]
    async fn real_official_snell_server_roundtrip() {
        if !snell_peer_ready().await {
            eprintln!(
                "跳过：官方 snell-server 对端缺席 (127.0.0.1:23410，/tmp/snellpeer 常驻实例)"
            );
            return;
        }
        let (target_addr, _echo) = echo_target().await;
        let connector = std::sync::Arc::new(
            SnellConnector::new(
                SNELL_PEER_ADDR.0.into(),
                SNELL_PEER_ADDR.1,
                SNELL_PEER_PSK.into(),
                String::new(),
            )
            .expect("构造"),
        );
        let (flow, mut client) = make_flow(&target_addr.ip().to_string(), target_addr.port());

        // 上行：文本 + 大块（> 1421 触发多记录切分），不半关——官方对端
        // 零块 = 双向收口（本席实证：client 零块即 SN_ENCRYPT_RESULT_ZERO_
        // CHUNK + Send shutdown req，下行随之关闭、UP: 10014 DOWN: 0），
        // 半关回读面在官方语义下不可用，走请求 → 回读全量 → 全关。
        // forward 与本段同任务串行，错误有序透出
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let task_payload = payload.clone();
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            // join 并行：读回侧在 fw 轮转下推进（串行即死锁——读阻塞在
            // fw 连接之前）；回读毕 client 块尾 drop → 上行 EOF → 零块 →
            // 官方双向收口 → forward 收束
            let (report, got) = tokio::join!(fw, async {
                client.write_all(b"official hello").await.expect("上行写");
                client.write_all(&task_payload).await.expect("上行大块写");
                let mut got = vec![0u8; 14 + task_payload.len()];
                // 10s：全量并行下官方对端读侧偶发数秒级迟滞（本席实测
                // 5.15s——server2.log STAGE_INIT 滞后 accept），上限放宽
                // 不改判据（逐字节还原 + 计数对账）
                tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut got))
                    .await
                    .expect("下行超时（官方对端回放面）")
                    .expect("下行读");
                // 全关：client 显式 drop（async 块按借用捕获，块尾不发生
                // drop）→ 上行 EOF → 零块 → 官方双向收口 → forward 收束
                drop(client);
                got
            });
            (report, got)
        });
        let (report, got) = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时（官方对端应答/中继面）")
            .expect("join");

        let mut expected = b"official hello".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(got, expected, "官方对端回环逐字节还原（含多记录切分）");

        let report = report.expect("forward 成功");
        assert_eq!(report.upstream as usize, expected.len(), "上行计数");
        assert_eq!(report.downstream as usize, expected.len(), "下行计数");
    }
}
