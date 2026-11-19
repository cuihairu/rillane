//! Mieru TCP 出站客户端面（RIL-116）。
//!
//! 线格式以官方 spec（enfein/mieru `docs/protocol.md`，2026-11-18 取证
//! docs/protocol-backends.md#mieru）为唯一实现真源；GPL 源码未读未派生，
//! 验收对官方 v3.39.0 参考二进制（`mieru` 客户端 / `mita` 服务器）实机
//! 回环。线上布局由官方二进制全链字节捕获 + AEAD 逐段解密钉定：
//! - 钥表：hashedPassword = SHA-256(password ‖ 0x00 ‖ username)；
//!   timeSalt = SHA-256(be64(unix 对齐最近 2 分钟))；key = PBKDF2-SHA256
//!   （hashedPassword, timeSalt, 64 轮，32B）。收侧按 ±2 分钟邻域试
//!   3 盐（spec 口径——时钟差 ≤4 分钟）。钥双向共享（捕获实证）。
//! - nonce 24B：随机 20B + 末 4B = SHA-256(username ‖ nonce[0..16])[0..4]
//!   （用户定位标记，捕获两端偏移 0 双双命中实证）；逐加密操作大端 +1
//!   （payload tag 于 meta nonce +1 命中、小端失配实证）；计数取尾 8 字节
//!   口径（捕获的计数范围区分不了全 24 位与尾 64 位，真实计数永不达
//!   2^64，两种宽度逐字节同形）；TCP 每方向首段 nonce 于偏移 0
//!   （padding0 = 0，官方两端实测）。
//! - 段 = [nonce?][meta 密文 32][tag 16][padding1][payload 密文][tag 16]
//!   [padding2]；payload 段（含 tag）仅 plen > 0 时存在（openSessionResponse
//!   plen=0 捕获无 tag 实证）；session 段无 padding1 字段。
//! - **隧道内 SOCKS5 回复（官方 mita 行为实证）**：openSessionResponse
//!   之后的首个 dataS2C 载荷 = 原样 SOCKS5 回复（VER/REP/RSV/ATYP +
//!   BND.ADDR/BND.PORT = 目标连接结果——本席回声对端回带 127.0.0.1 +
//!   真实端口的字节被逐段解密实读）。官方客户端 daemon 消化该回复后
//!   对其 socks5 客户端呈现——本连接器同姿态：消化（REP≠0 具名拒绝，
//!   目标不可达浮出）且绝不漏回复字节进隧道（回复可能跨段、或与目标
//!   数据共段——按总长精确取用）。
//! - openSessionRequest(type 2) payload = 原样 SOCKS5 请求字节
//!   （05 01 00 ATYP ADDR PORT——官方客户端原样转发，两条捕获向量钉定）。
//! - 关闭握手：closeSessionRequest(4) = 半关（"我方不再发数据"），
//!   对方回 closeSessionResponse(5)；两侧各自发 4 + 回 5，顺序容忍
//!   （捕获 conn1 服务端先关 / conn2 客户端先关，均收口）。
//! - 流控：seq 每方向自 0 递增（open 亦占 0）；win/unack 捕获观测
//!   4096/0 且小流量无 ACK 段——本客户端声明 win = u16::MAX、不发 ACK，
//!   ACK 段（type 8/9）读侧跳过；低熵扩展段（type 10/11）具名拒绝。
//!
//! 交付边界（评估记录具名）：仅 TCP 载具（UDP 载具与服务端面未交付，
//! catalog udp=false）；mihomo 多路复用（multiplexing）读取容忍不落
//! 行为——每流独立 wire 连接（与官方客户端 MULTIPLEXING_OFF 同形）；
//! 时间戳字段服务端不严格校验（捕获 ts 与真实时钟一致、官方客户端
//! 曾发偏差值仍被受理——本实现如实发当前分钟数）。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rillane_core::{EgressConnector, Flow, FlowReport};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

/// 拨号超时（与 snell/shadowquic 同口径）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// openSessionRequest → openSessionResponse 阶段超时。
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// AEAD tag 长。
const TAG_LEN: usize = 16;
/// 元数据长（官方 protocol.md 恒 32 字节）。
const META_LEN: usize = 32;
/// nonce 长（XChaCha20-Poly1305）。
const NONCE_LEN: usize = 24;
/// 单段负载上限（官方 TCP 切分规则；低熵模式例外不适用本段）。
const MAX_FRAGMENT: usize = 32768;

/// 会话元数据 protocol type（官方 protocol.md Session Metadata）。
const PT_OPEN_SESSION_REQUEST: u8 = 2;
const PT_OPEN_SESSION_RESPONSE: u8 = 3;
const PT_CLOSE_SESSION_REQUEST: u8 = 4;
const PT_CLOSE_SESSION_RESPONSE: u8 = 5;
/// 数据元数据 protocol type（官方 protocol.md Data Metadata）。
const PT_DATA_C2S: u8 = 6;
const PT_DATA_S2C: u8 = 7;
const PT_ACK_C2S: u8 = 8;
const PT_ACK_S2C: u8 = 9;
/// 低熵扩展段（官方 protocol.md Data Metadata Low Entropy Extension）——
/// 本段不产出不解析。
const PT_LOW_ENTROPY_MIN: u8 = 10;
const PT_LOW_ENTROPY_MAX: u8 = 11;

// ---------------------------------------------------------------------------
// 钥表（官方 protocol.md Key Generation Method）
// ---------------------------------------------------------------------------

/// hashedPassword = SHA-256(password ‖ 0x00 ‖ username)。
/// 向量（官方 `mieru describe config` 回显 hashedPassword 实测钉定）：
/// ("ril116", "ril116-pass-2026") → 645a4a68…3286。
fn hashed_password(username: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update([0x00]);
    h.update(username.as_bytes());
    h.finalize().into()
}

/// unixTime 对齐最近 2 分钟（四舍五入，恰在中点向上取整——捕获钉定：
/// 1795032032 → 1795032000）。
fn round_2min(unix: u64) -> u64 {
    (unix + 60) / 120 * 120
}

/// timeSalt = SHA-256(be64(rounded unixTime))。
fn time_salt(rounded: u64) -> [u8; 32] {
    Sha256::digest(rounded.to_be_bytes()).into()
}

/// PBKDF2-SHA256 单块（32B）手写：U1 = PRF(P, S ‖ INT(1) be32)，
/// Ui = PRF(P, Ui-1)，key = U1 ⊕ U2 ⊕ … ⊕ U64。正确性由捕获钉定的
/// 完整钥向量兜底（见 tests key_schedule_vectors_pinned——任何轮次/
/// 编码偏差即向量失配）。
fn pbkdf2_sha256_32(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC 接受任意长度钥");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut acc = [0u8; 32];
    acc.copy_from_slice(&u);
    for _ in 1..rounds {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC 接受任意长度钥");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (a, b) in acc.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    acc
}

/// key = PBKDF2-SHA256(hashedPassword, timeSalt, 64, 32)。
/// 向量（官方捕获 AEAD 逐段验tag 钉定）：rounded=1795032720 →
/// 1a408aa2…e1bd。
fn derive_key(username: &str, password: &str, rounded: u64) -> [u8; 32] {
    let hashed = hashed_password(username, password);
    pbkdf2_sha256_32(&hashed, &time_salt(rounded), 64)
}

/// 收侧盐候选：本分钟邻域 [R-120, R, R+120]（spec：服务器最多试 3 盐；
/// 正常钟差首选 R 命中，捕获实证）。
fn key_candidates(username: &str, password: &str, now_unix: u64) -> [[u8; 32]; 3] {
    let r = round_2min(now_unix);
    [
        derive_key(username, password, r - 120),
        derive_key(username, password, r),
        derive_key(username, password, r + 120),
    ]
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
fn now_minutes() -> u32 {
    (now_unix() / 60) as u32
}

// ---------------------------------------------------------------------------
// nonce（官方 protocol.md：末 4 字节 = SHA-256(username ‖ nonce[0..16])[0..4]）
// ---------------------------------------------------------------------------

/// 生成客户端 nonce：随机 20B + 用户定位标记。
fn make_nonce(username: &str) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce[..20]);
    let hint = nonce_hint(username, &nonce);
    nonce[20..].copy_from_slice(&hint);
    nonce
}

/// 用户定位标记 = SHA-256(username ‖ nonce[0..16])[0..4]。
fn nonce_hint(username: &str, nonce: &[u8; NONCE_LEN]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(&nonce[..16]);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// nonce 校验（收侧：标记不符即凭据/流失配，具名拒绝）。
fn nonce_hint_ok(username: &str, nonce: &[u8; NONCE_LEN]) -> bool {
    nonce_hint(username, nonce) == nonce[20..]
}

/// nonce 逐加密操作大端 +1（捕获钉定：payload tag 以 meta nonce 大端 +1
/// 命中、小端失配）。计数器取尾 8 字节（前 16 随机字节不参与）——捕获的
/// 计数范围区分不了全 24 位与尾 64 位两种宽度（真实计数永不达 2^64，
/// 两者逐字节同形），实现取尾 8 字节口径。
fn bump_nonce(nonce: &[u8; NONCE_LEN], add: u64) -> [u8; NONCE_LEN] {
    let mut v = [0u8; NONCE_LEN];
    v[..16].copy_from_slice(&nonce[..16]);
    let lo = u64::from_be_bytes(nonce[16..].try_into().expect("8 字节"));
    v[16..].copy_from_slice(&lo.wrapping_add(add).to_be_bytes());
    v
}

// ---------------------------------------------------------------------------
// AEAD 面（AAD 恒空——捕获钉定）
// ---------------------------------------------------------------------------

fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &mut [u8]) -> [u8; TAG_LEN] {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32 字节钥");
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), b"", plaintext)
        .expect("加密不失败（ring 恒返回 Ok）");
    tag.into()
}

/// 解密验 tag：失败返回 false（不 panic——凭据/时间偏差是运行态常态）。
fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &mut [u8],
    tag: &[u8],
) -> bool {
    if tag.len() != TAG_LEN {
        return false;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32 字节钥");
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            b"",
            ciphertext,
            Tag::from_slice(tag),
        )
        .is_ok()
}

// ---------------------------------------------------------------------------
// 元数据编解码（官方 protocol.md，全大端）
// ---------------------------------------------------------------------------

/// 会话元数据（type 2/3/4/5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionMeta {
    pub ptype: u8,
    pub timestamp: u32,
    pub session_id: u32,
    pub seq: u32,
    pub status: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

/// 数据元数据（type 6/7/8/9）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataMeta {
    pub ptype: u8,
    pub timestamp: u32,
    pub session_id: u32,
    pub seq: u32,
    pub unack: u32,
    pub window: u16,
    pub fragment: u8,
    pub prefix_len: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 解码 32B 元数据（捕获线向量钉定布局）。
pub(crate) fn decode_meta(raw: &[u8; META_LEN]) -> Result<Meta> {
    let ptype = raw[0];
    if (PT_LOW_ENTROPY_MIN..=PT_LOW_ENTROPY_MAX).contains(&ptype) {
        bail!("Mieru 低熵扩展段（type {ptype}）未交付");
    }
    let timestamp = be_u32(&raw[2..6]);
    let session_id = be_u32(&raw[6..10]);
    let seq = be_u32(&raw[10..14]);
    if matches!(ptype, 2..=5) {
        let (status, payload_len, suffix_len) =
            (raw[14], u16::from_be_bytes([raw[15], raw[16]]), raw[17]);
        return Ok(Meta::Session(SessionMeta {
            ptype,
            timestamp,
            session_id,
            seq,
            status,
            payload_len,
            suffix_len,
        }));
    }
    let unack = be_u32(&raw[14..18]);
    let window = u16::from_be_bytes([raw[18], raw[19]]);
    let fragment = raw[20];
    let prefix_len = raw[21];
    let payload_len = u16::from_be_bytes([raw[22], raw[23]]);
    let suffix_len = raw[24];
    Ok(Meta::Data(DataMeta {
        ptype,
        timestamp,
        session_id,
        seq,
        unack,
        window,
        fragment,
        prefix_len,
        payload_len,
        suffix_len,
    }))
}

/// 元数据（编解码公共载体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Meta {
    Session(SessionMeta),
    Data(DataMeta),
}

impl Meta {
    pub(crate) fn ptype(&self) -> u8 {
        match self {
            Meta::Session(m) => m.ptype,
            Meta::Data(m) => m.ptype,
        }
    }

    pub(crate) fn session_id(&self) -> u32 {
        match self {
            Meta::Session(m) => m.session_id,
            Meta::Data(m) => m.session_id,
        }
    }

    /// 序号（收侧不作强校验——容忍读；发送侧走 TxHalf.seq 记账）。
    #[allow(dead_code)]
    pub(crate) fn seq(&self) -> u32 {
        match self {
            Meta::Session(m) => m.seq,
            Meta::Data(m) => m.seq,
        }
    }

    /// payload 段长度（不含 tag）。
    pub(crate) fn payload_len(&self) -> usize {
        match self {
            Meta::Session(m) => m.payload_len as usize,
            Meta::Data(m) => m.payload_len as usize,
        }
    }

    /// padding1 长（session 段无该字段，恒 0）。
    pub(crate) fn prefix_len(&self) -> usize {
        match self {
            Meta::Session(_) => 0,
            Meta::Data(m) => m.prefix_len as usize,
        }
    }

    /// padding2 长。
    pub(crate) fn suffix_len(&self) -> usize {
        match self {
            Meta::Session(m) => m.suffix_len as usize,
            Meta::Data(m) => m.suffix_len as usize,
        }
    }

    /// 编码 32B（本客户端恒 unused = 0；session 段 suffix 承载 padding2）。
    pub(crate) fn encode(&self) -> [u8; META_LEN] {
        let mut raw = [0u8; META_LEN];
        match self {
            Meta::Session(m) => {
                raw[0] = m.ptype;
                raw[2..6].copy_from_slice(&m.timestamp.to_be_bytes());
                raw[6..10].copy_from_slice(&m.session_id.to_be_bytes());
                raw[10..14].copy_from_slice(&m.seq.to_be_bytes());
                raw[14] = m.status;
                raw[15..17].copy_from_slice(&m.payload_len.to_be_bytes());
                raw[17] = m.suffix_len;
            }
            Meta::Data(m) => {
                raw[0] = m.ptype;
                raw[2..6].copy_from_slice(&m.timestamp.to_be_bytes());
                raw[6..10].copy_from_slice(&m.session_id.to_be_bytes());
                raw[10..14].copy_from_slice(&m.seq.to_be_bytes());
                raw[14..18].copy_from_slice(&m.unack.to_be_bytes());
                raw[18..20].copy_from_slice(&m.window.to_be_bytes());
                raw[20] = m.fragment;
                raw[21] = m.prefix_len;
                raw[22..24].copy_from_slice(&m.payload_len.to_be_bytes());
                raw[24] = m.suffix_len;
            }
        }
        raw
    }
}

// ---------------------------------------------------------------------------
// 请求负载：原样 SOCKS5 请求字节（捕获向量钉定：官方客户端原样转发）
// ---------------------------------------------------------------------------

pub(crate) fn build_socks5_request(host: &str, port: u16) -> Result<Vec<u8>> {
    use std::net::IpAddr;
    let mut out = vec![0x05, 0x01, 0x00];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if host.is_empty() {
                bail!("Mieru 目标主机为空");
            }
            if host.len() > 255 {
                bail!("Mieru 目标主机名超长（> 255 字节）: {host}");
            }
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

// ---------------------------------------------------------------------------
// MieruStream：段流封装（AsyncRead/AsyncWrite）
// ---------------------------------------------------------------------------

/// 发送半侧状态。
struct TxHalf {
    key: [u8; 32],
    nonce: [u8; NONCE_LEN],
    ctr: u64,
    seq: u32,
    session_id: u32,
    timestamp: u32,
    shutdown_sent: bool,
    /// 待写入内层 socket 的已编码字节。
    out: BytesMut,
}

/// 接收半侧状态。
struct RxHalf {
    /// 首段验证后钉定的钥；None = 尚未收过服务端首段。
    key: Option<[u8; 32]>,
    candidates: [[u8; 32]; 3],
    nonce: Option<[u8; NONCE_LEN]>,
    ctr: u64,
    stage: RxStage,
    /// 已解密待交字节。
    buf: BytesMut,
    peer_closed: bool,
    session_id: u32,
    username: String,
    /// 会话建立后的 SOCKS5 回复消化器（首个下行载荷）；None = 已消化。
    reply_parse: Option<Socks5ReplyAcc>,
}

/// 会话建立后首个下行载荷的 SOCKS5 回复消化器（官方 mita 实证：回复以
/// dataS2C 载荷原样入隧道——VER/REP/RSV/ATYP + BND.ADDR + BND.PORT，
/// BND 即目标连接结果地址）。可能跨段、或与目标数据共段——按总长精确
/// 取用。消化即弃（不漏进隧道）；REP≠0 具名拒绝（目标不可达应浮出）。
struct Socks5ReplyAcc {
    acc: Vec<u8>,
    /// 头解析后的回复总长（None = 未定型）。
    total: Option<usize>,
}

#[derive(Clone, Copy)]
enum RxStage {
    /// 读服务端首段 nonce（24B，仅每方向首段）。
    Nonce,
    /// 读元数据密文 48B（32 + tag 16）。
    Meta,
    /// 读 [padding1][payload][tag?][padding2]；decrypt = 该段 payload 解密
    /// 入接收缓冲（数据段）或读掉即弃（ACK 等跳过段）。
    Body {
        prefix_len: usize,
        payload_len: usize,
        suffix_len: usize,
        decrypt: bool,
    },
}

/// Mieru 段流：一条 wire 连接一个会话（与官方客户端 MULTIPLEXING_OFF
/// 同形——每流独立连接）。
pub(crate) struct MieruStream {
    inner: TcpStream,
    tx: TxHalf,
    rx: RxHalf,
}

impl MieruStream {
    /// 构建流并发送 openSessionRequest（原样 SOCKS5 请求为 payload）。
    /// 发送钥取构建时刻本分钟盐；收侧钥在首段验证时钉定。
    pub(crate) async fn open(
        inner: TcpStream,
        username: &str,
        password: &str,
        session_id: u32,
        socks5_request: &[u8],
    ) -> Result<Self> {
        if socks5_request.len() > u16::MAX as usize {
            bail!("Mieru 请求负载超长");
        }
        let now = now_unix();
        let mut stream = MieruStream {
            inner,
            tx: TxHalf {
                key: derive_key(username, password, round_2min(now)),
                nonce: make_nonce(username),
                ctr: 0,
                seq: 0,
                session_id,
                timestamp: (now / 60) as u32,
                shutdown_sent: false,
                out: BytesMut::new(),
            },
            rx: RxHalf {
                key: None,
                candidates: key_candidates(username, password, now),
                nonce: None,
                ctr: 0,
                stage: RxStage::Nonce,
                buf: BytesMut::new(),
                peer_closed: false,
                session_id,
                username: username.to_string(),
                reply_parse: None,
            },
        };
        stream.send_open_request(socks5_request).await?;
        Ok(stream)
    }

    /// 首段：[nonce][meta 密文][tag][payload][tag][padding2]——payload 段
    /// 仅 plen > 0 时存在（捕获实证）。
    async fn send_open_request(&mut self, payload: &[u8]) -> Result<()> {
        let plen = payload.len();
        let mut meta = Meta::Session(SessionMeta {
            ptype: PT_OPEN_SESSION_REQUEST,
            timestamp: self.tx.timestamp,
            session_id: self.tx.session_id,
            seq: self.tx.seq,
            status: 0,
            payload_len: plen as u16,
            suffix_len: 0,
        })
        .encode();
        let tag = seal(
            &self.tx.key,
            &bump_nonce(&self.tx.nonce, self.tx.ctr),
            &mut meta,
        );
        self.tx.seq += 1;
        let mut wire = Vec::with_capacity(NONCE_LEN + META_LEN + TAG_LEN + plen + TAG_LEN);
        wire.extend_from_slice(&self.tx.nonce);
        wire.extend_from_slice(&meta);
        wire.extend_from_slice(&tag);
        if plen > 0 {
            let mut body = payload.to_vec();
            let ptag = seal(
                &self.tx.key,
                &bump_nonce(&self.tx.nonce, self.tx.ctr + 1),
                &mut body,
            );
            wire.extend_from_slice(&body);
            wire.extend_from_slice(&ptag);
        }
        self.tx.ctr += 1 + u64::from(plen > 0);
        self.inner.write_all(&wire).await?;
        self.inner.flush().await?;
        Ok(())
    }

    /// 编码并挂起一个数据段（poll_write 用）。
    fn push_data_segment(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(MAX_FRAGMENT);
        let mut meta = Meta::Data(DataMeta {
            ptype: PT_DATA_C2S,
            timestamp: self.tx.timestamp,
            session_id: self.tx.session_id,
            seq: self.tx.seq,
            unack: 0,
            window: u16::MAX,
            fragment: 0,
            prefix_len: 0,
            payload_len: n as u16,
            suffix_len: 0,
        })
        .encode();
        let tag = seal(
            &self.tx.key,
            &bump_nonce(&self.tx.nonce, self.tx.ctr),
            &mut meta,
        );
        self.tx.seq += 1;
        let mut wire = Vec::with_capacity(META_LEN + TAG_LEN + n + TAG_LEN);
        wire.extend_from_slice(&meta);
        wire.extend_from_slice(&tag);
        if n > 0 {
            let mut body = data[..n].to_vec();
            let ptag = seal(
                &self.tx.key,
                &bump_nonce(&self.tx.nonce, self.tx.ctr + 1),
                &mut body,
            );
            wire.extend_from_slice(&body);
            wire.extend_from_slice(&ptag);
        }
        self.tx.ctr += 1 + u64::from(n > 0);
        self.tx.out.extend_from_slice(&wire);
        n
    }

    /// 编码并挂起一个会话段（plen 恒 0：closeSessionRequest/Response）。
    fn push_session_segment(&mut self, ptype: u8, status: u8) {
        let mut meta = Meta::Session(SessionMeta {
            ptype,
            timestamp: self.tx.timestamp,
            session_id: self.tx.session_id,
            seq: self.tx.seq,
            status,
            payload_len: 0,
            suffix_len: 0,
        })
        .encode();
        let tag = seal(
            &self.tx.key,
            &bump_nonce(&self.tx.nonce, self.tx.ctr),
            &mut meta,
        );
        self.tx.seq += 1;
        self.tx.ctr += 1;
        self.tx.out.extend_from_slice(&meta);
        self.tx.out.extend_from_slice(&tag);
    }

    /// 读服务端首段并验证 openSessionResponse：盐候选逐试钉定收侧钥、
    /// 校验用户定位标记/会话号/状态码。payload 存在时读入并弃置
    /// （捕获中 openSessionResponse 恒 plen=0；>0 语义 spec 未定义）。
    pub(crate) async fn await_open_response(&mut self) -> Result<()> {
        let mut nonce = [0u8; NONCE_LEN];
        self.inner.read_exact(&mut nonce).await?;
        if !nonce_hint_ok(&self.rx.username, &nonce) {
            bail!("Mieru 服务端 nonce 用户定位标记不符（用户名或流失配）");
        }
        let mut meta_wire = [0u8; META_LEN + TAG_LEN];
        self.inner.read_exact(&mut meta_wire).await?;
        let mut resolved: Option<([u8; 32], Meta)> = None;
        for key in &self.rx.candidates {
            let mut ct = meta_wire[..META_LEN].to_vec();
            if open_in_place(key, &nonce, &mut ct, &meta_wire[META_LEN..]) {
                let meta = decode_meta(ct.as_slice().try_into().expect("32 字节"))?;
                match meta.ptype() {
                    PT_OPEN_SESSION_RESPONSE => {}
                    other => bail!("Mieru 首段类型非法（期望 openSessionResponse=3，得 {other}）"),
                }
                if meta.session_id() != self.rx.session_id {
                    bail!(
                        "Mieru 会话号失配（期望 {:#010x}，得 {:#010x}）",
                        self.rx.session_id,
                        meta.session_id()
                    );
                }
                if let Meta::Session(s) = &meta {
                    if s.status != 0 {
                        bail!("Mieru openSessionResponse 状态码 {}", s.status);
                    }
                }
                resolved = Some((*key, meta));
                break;
            }
        }
        let (key, meta) = resolved
            .ok_or_else(|| anyhow!("Mieru 首段解密失败（凭据不符或时钟偏差超 ±4 分钟窗口）"))?;
        self.rx.key = Some(key);
        self.rx.nonce = Some(nonce);
        // 剩余段体：payload（若在，读入并弃置——捕获中 openSessionResponse
        // 恒 plen=0；>0 语义 spec 未定义）+ padding2
        let plen = meta.payload_len();
        let suffix_len = meta.suffix_len();
        if plen > 0 {
            let mut body = vec![0u8; plen + TAG_LEN];
            self.inner.read_exact(&mut body).await?;
        }
        if suffix_len > 0 {
            let mut pad = vec![0u8; suffix_len];
            self.inner.read_exact(&mut pad).await?;
        }
        self.rx.ctr = 1 + u64::from(plen > 0);
        self.rx.stage = RxStage::Meta;
        // 官方 mita 实证：紧随 openSessionResponse 的首个 dataS2C 载荷 =
        // 原样 SOCKS5 回复——消化（见 poll_read 的 reply_parse 面）
        self.rx.reply_parse = Some(Socks5ReplyAcc {
            acc: Vec::new(),
            total: None,
        });
        Ok(())
    }

    /// 处理一条已解密元数据；返回处理决策。
    /// - Data/S2C：payload 入接收缓冲（或空段跳过）
    /// - Close/Request：回 closeSessionResponse，置对端半关 → 读侧 EOF
    /// - Close/Response、ACK、Data/C2S（服务端不该发）：跳过
    fn on_meta(&mut self, meta: &Meta) -> Result<RxDecision> {
        if meta.session_id() != self.rx.session_id {
            bail!(
                "Mieru 会话号失配（期望 {:#010x}，得 {:#010x}）",
                self.rx.session_id,
                meta.session_id()
            );
        }
        match meta.ptype() {
            PT_DATA_S2C => Ok(RxDecision::WantBody),
            PT_CLOSE_SESSION_REQUEST => {
                // 对端半关：回 closeSessionResponse（捕获顺序容忍——两侧
                // 各自发 4 + 回 5），读侧就此 EOF
                self.push_session_segment(PT_CLOSE_SESSION_RESPONSE, 0);
                self.rx.peer_closed = true;
                Ok(RxDecision::EofAfterReply)
            }
            PT_CLOSE_SESSION_RESPONSE | PT_ACK_C2S | PT_ACK_S2C | PT_DATA_C2S => {
                Ok(RxDecision::SkipBody)
            }
            other => bail!("Mieru 数据面段类型非法: {other}"),
        }
    }

    /// 把挂起的发送缓冲尽量写入内层 socket；写满或挂起即返回。
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.tx.out.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.tx.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Mieru wire 写零",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    let _ = self.tx.out.split_to(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// 消化已缓冲字节中的 SOCKS5 回复前缀（只动 rx.buf，不阻塞）。头
    /// 4B 定 VER/REP/ATYP，域名地址再取 1B 定长；凑满总长即消化完成
    /// （回复字节弃置、解析器撤除）。VER/REP/ATYP 非法具名 io 错误。
    fn feed_socks5_reply(&mut self) -> io::Result<()> {
        if self.rx.reply_parse.is_none() {
            return Ok(());
        }
        // 头 4B：VER REP RSV ATYP
        let p = self.rx.reply_parse.as_mut().expect("回复解析器在挂");
        if p.total.is_none() && p.acc.len() < 4 {
            let n = (4 - p.acc.len()).min(self.rx.buf.len());
            p.acc.extend_from_slice(&self.rx.buf.split_to(n));
            if p.acc.len() < 4 {
                return Ok(()); // 等下一段
            }
        }
        let p = self.rx.reply_parse.as_mut().expect("回复解析器在挂");
        if p.total.is_none() {
            let (ver, rep, atyp) = (p.acc[0], p.acc[1], p.acc[3]);
            if ver != 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Mieru 隧道内 SOCKS5 回复版本非法: {ver}"),
                ));
            }
            if rep != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("Mieru 目标连接失败（隧道内 SOCKS5 REP={rep}）"),
                ));
            }
            match atyp {
                1 => p.total = Some(4 + 4 + 2),
                4 => p.total = Some(4 + 16 + 2),
                3 => p.total = None, // 域名：再取 1B 定长
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Mieru 隧道内 SOCKS5 回复地址族非法: {other}"),
                    ))
                }
            }
        }
        if self
            .rx
            .reply_parse
            .as_ref()
            .expect("回复解析器在挂")
            .total
            .is_none()
        {
            let p = self.rx.reply_parse.as_mut().expect("回复解析器在挂");
            if p.acc.len() < 5 {
                let n = (5 - p.acc.len()).min(self.rx.buf.len());
                p.acc.extend_from_slice(&self.rx.buf.split_to(n));
                if p.acc.len() < 5 {
                    return Ok(()); // 等下一段
                }
            }
            let dlen = p.acc[4] as usize;
            p.total = Some(5 + dlen + 2);
        }
        let total = self
            .rx
            .reply_parse
            .as_ref()
            .expect("回复解析器在挂")
            .total
            .expect("回复总长已定型");
        let p = self.rx.reply_parse.as_mut().expect("回复解析器在挂");
        let n = (total - p.acc.len()).min(self.rx.buf.len());
        p.acc.extend_from_slice(&self.rx.buf.split_to(n));
        if p.acc.len() == total {
            self.rx.reply_parse = None; // 消化完成——后续字节即目标数据
        }
        Ok(())
    }

    /// 内层精确读辅助（poll 语义；tokio poll_read 走 ReadBuf）。
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<()>> {
        let mut off = 0;
        while off < buf.len() {
            let mut rb = ReadBuf::new(&mut buf[off..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Mieru wire 提前收束",
                        )));
                    }
                    off += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

enum RxDecision {
    /// 数据段：继续读 payload 入接收缓冲。
    WantBody,
    /// 关闭握手段：已回 closeResponse 并置 EOF。
    EofAfterReply,
    /// 跳过段体（ACK/复用面等）；plen > 0 时仍需按框架读掉保持对齐。
    SkipBody,
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 已解密字节优先交付（SOCKS5 回复面在交付前消化）
            if !this.rx.buf.is_empty() {
                if this.rx.reply_parse.is_some() {
                    this.feed_socks5_reply()?;
                }
                if !this.rx.buf.is_empty() {
                    let n = this.rx.buf.len().min(out.remaining());
                    out.put_slice(&this.rx.buf.split_to(n));
                    return Poll::Ready(Ok(()));
                }
                // 回复恰好耗尽缓冲 → 继续读下一段（等待数据/关闭握手）
                continue;
            }
            if this.rx.peer_closed {
                // 关闭回包先冲净再 EOF：peer_closed 置位后挂起过一次冲刷
                // 时，直接 EOF 会丢 closeSessionResponse（对端等回执收到
                // 的却是 FIN——镜像/官方对端关闭握手就此打断）
                if !this.tx.out.is_empty() {
                    match this.flush_out(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                return Poll::Ready(Ok(())); // EOF
            }
            // 阶段按值取（Copy）——臂内可自由改写 this.rx.stage
            match this.rx.stage {
                RxStage::Nonce => {
                    let mut nonce = [0u8; NONCE_LEN];
                    match this.poll_read_exact(cx, &mut nonce) {
                        Poll::Ready(Ok(())) => {
                            if !nonce_hint_ok(&this.rx.username, &nonce) {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Mieru 服务端 nonce 用户定位标记不符",
                                )));
                            }
                            this.rx.nonce = Some(nonce);
                            this.rx.stage = RxStage::Meta;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RxStage::Meta => {
                    let mut meta_wire = [0u8; META_LEN + TAG_LEN];
                    match this.poll_read_exact(cx, &mut meta_wire) {
                        Poll::Ready(Ok(())) => {
                            let (key, nonce) = match (this.rx.key, this.rx.nonce) {
                                (Some(k), Some(n)) => (k, n),
                                _ => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "Mieru 收侧钥未钉定（首段未验）",
                                    )))
                                }
                            };
                            let mut ct = meta_wire[..META_LEN].to_vec();
                            if !open_in_place(
                                &key,
                                &bump_nonce(&nonce, this.rx.ctr),
                                &mut ct,
                                &meta_wire[META_LEN..],
                            ) {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Mieru 元数据解密失败（流失配）",
                                )));
                            }
                            let meta = match decode_meta(ct.as_slice().try_into().expect("32 字节"))
                            {
                                Ok(m) => m,
                                Err(e) => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        e.to_string(),
                                    )))
                                }
                            };
                            match this.on_meta(&meta) {
                                Ok(RxDecision::WantBody) => {
                                    // 计数在段体消费后统一推进（payload 解密
                                    // 需要 meta nonce +1，尚未消耗）
                                    this.rx.stage = RxStage::Body {
                                        prefix_len: meta.prefix_len(),
                                        payload_len: meta.payload_len(),
                                        suffix_len: meta.suffix_len(),
                                        decrypt: true,
                                    };
                                }
                                Ok(RxDecision::EofAfterReply) => {
                                    // 回包可能未写完——先试冲；冲完（或挂起）后
                                    // EOF 由下一轮 poll_read 在 peer_closed 下给出
                                    match this.flush_out(cx) {
                                        Poll::Ready(Ok(())) => {}
                                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                        Poll::Pending => return Poll::Pending,
                                    }
                                    return Poll::Ready(Ok(())); // 0 字节 = EOF
                                }
                                Ok(RxDecision::SkipBody) => {
                                    let plen = meta.payload_len();
                                    let suffix = meta.suffix_len();
                                    let prefix = meta.prefix_len();
                                    let need =
                                        prefix + plen + if plen > 0 { TAG_LEN } else { 0 } + suffix;
                                    if need > 0 {
                                        this.rx.stage = RxStage::Body {
                                            prefix_len: prefix,
                                            payload_len: plen,
                                            suffix_len: suffix,
                                            decrypt: false,
                                        };
                                    } else {
                                        this.rx.ctr += 1;
                                    }
                                }
                                Err(e) => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        e.to_string(),
                                    )))
                                }
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RxStage::Body {
                    prefix_len,
                    payload_len,
                    suffix_len,
                    decrypt,
                } => {
                    let need = prefix_len
                        + payload_len
                        + if payload_len > 0 { TAG_LEN } else { 0 }
                        + suffix_len;
                    let mut raw = vec![0u8; need];
                    match this.poll_read_exact(cx, &mut raw) {
                        Poll::Ready(Ok(())) => {
                            if decrypt && payload_len > 0 {
                                let (key, nonce) = match (this.rx.key, this.rx.nonce) {
                                    (Some(k), Some(n)) => (k, n),
                                    _ => {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "Mieru 收侧钥未钉定（首段未验）",
                                        )))
                                    }
                                };
                                // [padding1][payload][tag][padding2]：解 payload
                                // 入接收缓冲（meta nonce +1——捕获钉定大端）
                                let start = prefix_len;
                                let end = start + payload_len;
                                let tag_at = end..end + TAG_LEN;
                                let tag = raw[tag_at.clone()].to_vec();
                                let mut ct = raw[start..end].to_vec();
                                let n = bump_nonce(&nonce, this.rx.ctr + 1);
                                if !open_in_place(&key, &n, &mut ct, &tag) {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "Mieru payload 解密失败（流失配）",
                                    )));
                                }
                                this.rx.buf.extend_from_slice(&ct);
                            }
                            this.rx.ctr += 1 + u64::from(payload_len > 0);
                            this.rx.stage = RxStage::Meta;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.tx.shutdown_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Mieru 会话已关闭",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = this.push_data_segment(buf);
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush_out(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.tx.shutdown_sent {
            // closeSessionRequest（半关：我方不再发数据——捕获 conn2 客户端
            // 先关路径实证）。注意不得内层 TCP shutdown：关闭握手还有回程
            // ——对端会续发 closeSessionRequest，我方须能写回
            // closeSessionResponse（提前 FIN = 写回 EPIPE/对端读侧收束）。
            // wire TCP 的最终收口落在流 drop。
            this.push_session_segment(PT_CLOSE_SESSION_REQUEST, 0);
            this.tx.shutdown_sent = true;
        }
        this.flush_out(cx)
    }
}

// ---------------------------------------------------------------------------
// 连接器
// ---------------------------------------------------------------------------

/// Mieru TCP 出站连接器（每流一条 wire 连接）。
#[derive(Debug)]
pub struct MieruConnector {
    server: String,
    port: u16,
    username: String,
    password: String,
}

impl MieruConnector {
    /// 构建期校验：空用户名/密码/服务器具名拒绝（配置错误在装配期暴露）。
    pub fn new(server: String, port: u16, username: String, password: String) -> Result<Self> {
        if username.is_empty() {
            bail!("Mieru 缺少用户名");
        }
        if password.is_empty() {
            bail!("Mieru 缺少密码");
        }
        if server.is_empty() {
            bail!("Mieru 缺少服务器地址");
        }
        Ok(Self {
            server,
            port,
            username,
            password,
        })
    }
}

#[async_trait]
impl EgressConnector for MieruConnector {
    fn name(&self) -> &'static str {
        "mieru"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let addr = format!("{}:{}", self.server, self.port);
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .context("Mieru 连接超时")?
            .with_context(|| format!("Mieru 服务器连接失败: {addr}"))?;

        let request =
            build_socks5_request(&flow.target.host, flow.target.port).with_context(|| {
                format!("Mieru 目标非法: {}:{}", flow.target.host, flow.target.port)
            })?;
        let session_id: u32 = rand::random();
        let mut stream =
            MieruStream::open(tcp, &self.username, &self.password, session_id, &request)
                .await
                .context("Mieru openSessionRequest 写入失败")?;
        tokio::time::timeout(OPEN_TIMEOUT, stream.await_open_response())
            .await
            .context("Mieru openSessionResponse 超时")?
            .context("Mieru 会话建立失败")?;

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("Mieru 双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// 测试：向量钉定（真源 = 官方二进制捕获 + `mieru describe config` 回显）
// + 进程内镜像服务器回环 + 官方 mita 实机对端
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::{FlowId, TargetProto};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // -----------------------------------------------------------------------
    // 钥表向量（黑盒钉定：官方 `mieru describe config` hashedPassword 回显
    // + 官方 v3.39.0 wire 捕获 AEAD 逐段验 tag）
    // -----------------------------------------------------------------------

    /// hashedPassword = SHA-256(password ‖ 0x00 ‖ username)——官方客户端
    /// `describe config` 回显实测（用户名/密码次序钉死，任何次序漂移即失配）。
    #[test]
    fn key_schedule_vectors_pinned() {
        let hashed = hashed_password("ril116", "ril116-pass-2026");
        assert_eq!(
            hex(&hashed),
            "645a4a68d83e3679e6ce5a47a0d52fe58897c69959e78c8b7ed4e2e537083286",
            "hashedPassword 向量（官方 describe config 回显）"
        );
        // 完整钥向量：捕获conn（2026-11-18 本席）AEAD tag 命中唯一对应
        // rounded=1795032720——PBKDF2 轮数/盐编码/取长全链在此失配即暴露。
        let key = derive_key("ril116", "ril116-pass-2026", 1795032720);
        assert_eq!(
            hex(&key),
            "1a408aa242e3b535a6df7b1170230fee5d202fa534b95fc9e8a1d29a453ae1bd",
            "PBKDF2 钥向量（官方捕获 AEAD 验 tag 钉定）"
        );
    }

    /// 时间对齐：整分不漂、恰半分向上（捕获钉定 1795032032 → 1795032000）。
    #[test]
    fn round_2min_boundaries() {
        assert_eq!(round_2min(1795032032), 1795032000);
        assert_eq!(round_2min(1795032000), 1795032000);
        assert_eq!(round_2min(1795032059), 1795032000);
        assert_eq!(round_2min(1795032060), 1795032120, "恰半分向上取整");
        assert_eq!(round_2min(0), 0);
    }

    /// 元数据线向量（捕获 conn1 conn2）：解码字段 + 重编码逐字节还原。
    #[test]
    fn metadata_wire_vectors_roundtrip() {
        // c2s dataC2S（conn1 seg1）：type=6 win=4096 prefix=3 payload=90 suffix=41
        let data_hex = "060001c8801b7150d2e1000000010000000010000003005a2900000000000000";
        let raw: [u8; META_LEN] = unhex(data_hex).try_into().expect("32 字节");
        let meta = decode_meta(&raw).expect("解码");
        match &meta {
            Meta::Data(d) => {
                assert_eq!(d.ptype, PT_DATA_C2S);
                assert_eq!(d.timestamp, 0x01c8_801b);
                assert_eq!(d.session_id, 0x7150_d2e1);
                assert_eq!(d.seq, 1);
                assert_eq!(d.unack, 0);
                assert_eq!(d.window, 4096);
                assert_eq!(d.fragment, 0);
                assert_eq!(d.prefix_len, 3);
                assert_eq!(d.payload_len, 90);
                assert_eq!(d.suffix_len, 41);
            }
            other => panic!("期望数据元数据，得 {other:?}"),
        }
        assert_eq!(meta.encode().to_vec(), raw.to_vec(), "重编码逐字节还原");

        // c2s openSessionRequest（conn0 seg0）：type=2 payload=21 suffix=40
        let sess_hex = "020001c88010ae74a3b400000000000015280000000000000000000000000000";
        let raw: [u8; META_LEN] = unhex(sess_hex).try_into().expect("32 字节");
        let meta = decode_meta(&raw).expect("解码");
        match &meta {
            Meta::Session(s) => {
                assert_eq!(s.ptype, PT_OPEN_SESSION_REQUEST);
                assert_eq!(s.timestamp, 0x01c8_8010);
                assert_eq!(s.session_id, 0xae74_a3b4);
                assert_eq!(s.seq, 0);
                assert_eq!(s.status, 0);
                assert_eq!(s.payload_len, 21);
                assert_eq!(s.suffix_len, 40);
            }
            other => panic!("期望会话元数据，得 {other:?}"),
        }
        assert_eq!(meta.encode().to_vec(), raw.to_vec(), "重编码逐字节还原");
    }

    /// 请求负载向量（捕获两条：官方客户端原样转发 SOCKS5 请求字节）。
    #[test]
    fn socks5_request_builder_vectors() {
        let got = build_socks5_request("api.github.com", 443).expect("域名");
        assert_eq!(
            hex(&got),
            "050100030e6170692e6769746875622e636f6d01bb",
            "域名目标（捕获 conn0）"
        );
        let got = build_socks5_request("127.0.0.1", 18080).expect("IPv4");
        assert_eq!(hex(&got), "050100017f00000146a0", "IPv4 目标（捕获 conn1）");
        assert!(build_socks5_request("", 1).is_err(), "空主机具名拒绝");
    }

    /// nonce：用户定位标记形状 + 大端计数器（捕获钉定 payload tag 以
    /// meta nonce 大端 +1 命中）。
    #[test]
    fn nonce_hint_shape_and_counter() {
        let nonce = make_nonce("ril116");
        assert!(nonce_hint_ok("ril116", &nonce), "标记自洽");
        assert!(!nonce_hint_ok("other", &nonce), "他用户名标记失配");

        let mut n = [0u8; NONCE_LEN];
        n[23] = 0x2a;
        assert_eq!(bump_nonce(&n, 1)[23], 0x2b, "大端 +1");
        let n = [0xffu8; NONCE_LEN];
        let bumped = bump_nonce(&n, 1);
        assert_eq!(&bumped[..16], &[0xffu8; 16], "随机前 16 字节不参与计数");
        assert_eq!(&bumped[16..], &[0u8; 8], "计数器仅尾 8 字节大端回卷");
        assert!(bump_nonce(&n, 0) == n);
    }

    // -----------------------------------------------------------------------
    // 构建期校验
    // -----------------------------------------------------------------------

    #[test]
    fn constructor_validations_named_rejects() {
        let e = MieruConnector::new("s".into(), 1, "".into(), "p".into()).expect_err("空用户名");
        assert!(e.to_string().contains("用户名"), "{e}");
        let e = MieruConnector::new("s".into(), 1, "u".into(), "".into()).expect_err("空密码");
        assert!(e.to_string().contains("密码"), "{e}");
        let e = MieruConnector::new("".into(), 1, "u".into(), "p".into()).expect_err("空服务器");
        assert!(e.to_string().contains("服务器"), "{e}");
    }

    // -----------------------------------------------------------------------
    // 进程内镜像服务器（与连接器共享 codec，双向编码路径都受验）
    // -----------------------------------------------------------------------

    /// 镜像服务器线面：顺序读帧/写帧（async 顺序面，无 poll 机器）。
    struct FakePeer {
        sock: TcpStream,
        cands: [[u8; 32]; 3],
        rx_key: Option<[u8; 32]>,
        rx_nonce: [u8; NONCE_LEN],
        rx_ctr: u64,
        tx_key: [u8; 32],
        tx_nonce: [u8; NONCE_LEN],
        tx_nonce_sent: bool,
        tx_ctr: u64,
        seq: u32,
        sid: u32,
        username: String,
    }

    impl FakePeer {
        async fn new(sock: TcpStream, username: &str, password: &str) -> Self {
            let now = now_unix();
            Self {
                sock,
                cands: key_candidates(username, password, now),
                rx_key: None,
                rx_nonce: [0u8; NONCE_LEN],
                rx_ctr: 0,
                tx_key: derive_key(username, password, round_2min(now)),
                tx_nonce: make_nonce(username),
                tx_nonce_sent: false,
                tx_ctr: 0,
                seq: 0,
                sid: 0,
                username: username.to_string(),
            }
        }

        /// 读一段：首段含 nonce；盐候选逐试钉定收侧钥。
        async fn read_segment(&mut self, first: bool) -> Result<(Meta, Vec<u8>)> {
            if first {
                let mut n = [0u8; NONCE_LEN];
                self.sock.read_exact(&mut n).await?;
                if !nonce_hint_ok(&self.username, &n) {
                    bail!("nonce 标记不符");
                }
                self.rx_nonce = n;
            }
            let mut meta_wire = [0u8; META_LEN + TAG_LEN];
            self.sock.read_exact(&mut meta_wire).await?;
            let key = match self.rx_key {
                Some(k) => k,
                None => {
                    let mut found = None;
                    for k in &self.cands {
                        let mut ct = meta_wire[..META_LEN].to_vec();
                        if open_in_place(k, &self.rx_nonce, &mut ct, &meta_wire[META_LEN..]) {
                            found = Some(*k);
                            break;
                        }
                    }
                    let k = found.ok_or_else(|| anyhow!("首段解密失败"))?;
                    self.rx_key = Some(k);
                    k
                }
            };
            let mut ct = meta_wire[..META_LEN].to_vec();
            if !open_in_place(
                &key,
                &bump_nonce(&self.rx_nonce, self.rx_ctr),
                &mut ct,
                &meta_wire[META_LEN..],
            ) {
                bail!("元数据解密失败");
            }
            let meta = decode_meta(ct.as_slice().try_into().expect("32 字节"))?;
            let plen = meta.payload_len();
            let prefix = meta.prefix_len();
            let suffix = meta.suffix_len();
            let mut payload = Vec::new();
            if plen > 0 {
                let mut body = vec![0u8; prefix + plen + TAG_LEN + suffix];
                self.sock.read_exact(&mut body).await?;
                let tag = body[prefix + plen..prefix + plen + TAG_LEN].to_vec();
                let mut ct = body[prefix..prefix + plen].to_vec();
                if !open_in_place(
                    &key,
                    &bump_nonce(&self.rx_nonce, self.rx_ctr + 1),
                    &mut ct,
                    &tag,
                ) {
                    bail!("payload 解密失败");
                }
                payload = ct;
            } else if suffix > 0 {
                let mut pad = vec![0u8; suffix];
                self.sock.read_exact(&mut pad).await?;
            }
            self.rx_ctr += 1 + u64::from(plen > 0);
            Ok((meta, payload))
        }

        fn seal_meta(&self, meta: &mut [u8; META_LEN]) -> [u8; TAG_LEN] {
            seal(&self.tx_key, &bump_nonce(&self.tx_nonce, self.tx_ctr), meta)
        }

        async fn send_session(&mut self, ptype: u8, status: u8) -> Result<()> {
            let mut meta = Meta::Session(SessionMeta {
                ptype,
                timestamp: now_minutes(),
                session_id: self.sid,
                seq: self.seq,
                status,
                payload_len: 0,
                suffix_len: 0,
            })
            .encode();
            let tag = self.seal_meta(&mut meta);
            self.seq += 1;
            self.tx_ctr += 1;
            let mut wire = meta.to_vec();
            wire.extend_from_slice(&tag);
            // 服务端首段前置自身 nonce（捕获实证：s2c 首 24B 即服务端
            // nonce、用户定位标记命中）；此后段不再重复。
            if !self.tx_nonce_sent {
                let mut with_nonce = self.tx_nonce.to_vec();
                with_nonce.extend_from_slice(&wire);
                wire = with_nonce;
                self.tx_nonce_sent = true;
            }
            self.sock.write_all(&wire).await?;
            Ok(())
        }

        async fn send_data(&mut self, payload: &[u8]) -> Result<()> {
            let plen = payload.len();
            let mut meta = Meta::Data(DataMeta {
                ptype: PT_DATA_S2C,
                timestamp: now_minutes(),
                session_id: self.sid,
                seq: self.seq,
                unack: 0,
                window: u16::MAX,
                fragment: 0,
                prefix_len: 0,
                payload_len: plen as u16,
                suffix_len: 0,
            })
            .encode();
            let tag = self.seal_meta(&mut meta);
            self.seq += 1;
            self.tx_ctr += 1;
            let mut wire = meta.to_vec();
            wire.extend_from_slice(&tag);
            if plen > 0 {
                let mut body = payload.to_vec();
                let ptag = seal(
                    &self.tx_key,
                    &bump_nonce(&self.tx_nonce, self.tx_ctr),
                    &mut body,
                );
                self.tx_ctr += 1;
                wire.extend_from_slice(&body);
                wire.extend_from_slice(&ptag);
            }
            self.sock.write_all(&wire).await?;
            Ok(())
        }
    }

    /// 镜像服务器会话循环：open → 回显数据 → 双侧关闭握手。
    /// 镜像服务器会话循环：open → 隧道内 SOCKS5 回复（官方 mita 实证
    /// 字节形：VER/REP/RSV/ATYP + 请求地址原样回带；rep 供 REP≠0 具名
    /// 拒绝面注入——官方对不可达目标同形）→ 回显数据 → 双侧关闭握手。
    async fn fake_mieru_echo(mut peer: FakePeer, rep: u8) -> Result<()> {
        let (meta, req) = peer.read_segment(true).await?;
        assert_eq!(meta.ptype(), PT_OPEN_SESSION_REQUEST, "首段类型");
        peer.sid = meta.session_id();
        peer.send_session(PT_OPEN_SESSION_RESPONSE, 0).await?;
        // SOCKS5 回复：VER REP RSV ATYP + 请求尾部地址原样回带
        // （mita 对本席回声上游回带 BND.ADDR=127.0.0.1 + 真实端口的同形）
        let mut reply = vec![5u8, rep, 0, req[3]];
        reply.extend_from_slice(&req[4..]);
        peer.send_data(&reply).await?;
        loop {
            let (m, p) = peer.read_segment(false).await?;
            match m.ptype() {
                PT_DATA_C2S => peer.send_data(&p).await?,
                PT_CLOSE_SESSION_REQUEST => {
                    peer.send_session(PT_CLOSE_SESSION_RESPONSE, 0).await?;
                    peer.send_session(PT_CLOSE_SESSION_REQUEST, 0).await?;
                    let (m2, _) = peer.read_segment(false).await?;
                    assert_eq!(m2.ptype(), PT_CLOSE_SESSION_RESPONSE, "关闭回执");
                    break;
                }
                PT_CLOSE_SESSION_RESPONSE => break,
                other => panic!("镜像服务器收面意外段类型 {other}"),
            }
        }
        let _ = peer.sock.shutdown().await;
        Ok(())
    }

    async fn spawn_fake_echo_server(username: &str, password: &str) -> u16 {
        spawn_fake_echo_server_with_rep(username, password, 0).await
    }

    async fn spawn_fake_echo_server_with_rep(username: &str, password: &str, rep: u8) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("镜像绑定");
        let port = listener.local_addr().expect("地址").port();
        let un = username.to_string();
        let pw = password.to_string();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                let peer = FakePeer::new(s, &un, &pw).await;
                tokio::spawn(async move {
                    if let Err(e) = fake_mieru_echo(peer, rep).await {
                        eprintln!("镜像服务器会话终止: {e}");
                    }
                });
            }
        });
        port
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

    // -----------------------------------------------------------------------
    // 进程内回环：连接器（client 面）↔ 镜像服务器（server 面）共享 codec
    // -----------------------------------------------------------------------

    /// 全链回环：openSessionRequest（原样 SOCKS5 请求负载）→ 数据两轮
    /// （文本 + 10KB 越段界）→ 客户端半关（closeSessionRequest）→ 镜像
    /// 回 closeSessionResponse + 自身 closeSessionRequest → 连接器回执
    /// → 双向收口。逐字节还原 + FlowReport 计数对账。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connector_roundtrip_via_in_process_echo() {
        let port = spawn_fake_echo_server("u", "p").await;
        let connector = std::sync::Arc::new(
            MieruConnector::new("127.0.0.1".into(), port, "u".into(), "p".into()).expect("构造"),
        );
        let (flow, mut client) = make_flow("203.0.113.9", 80);

        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let task_payload = payload.clone();
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            // join 并行：读回侧在 fw 轮转下推进（串行即死锁——读阻塞在
            // fw 连接之前）；回读毕 client 显式 drop → 上行 EOF →
            // closeSessionRequest 半关 → 镜像双侧收口 → forward 收束
            let (report, got) = tokio::join!(fw, async {
                client.write_all(b"round0 ").await.expect("上行写");
                client.write_all(b"round1 ").await.expect("上行写");
                client.write_all(&task_payload).await.expect("上行大块写");
                let mut got = vec![0u8; 14 + task_payload.len()];
                tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut got))
                    .await
                    .expect("下行超时（镜像回放面）")
                    .expect("下行读");
                drop(client);
                got
            });
            (report, got)
        });
        let (report, got) = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时")
            .expect("join");

        let mut expected = b"round0 round1 ".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(got, expected, "回环逐字节还原（含 10KB 越段界大块）");
        let report = report.expect("forward 成功");
        assert_eq!(report.upstream as usize, expected.len(), "上行计数");
        assert_eq!(report.downstream as usize, expected.len(), "下行计数");
    }

    /// 错误凭据：镜像服务器盐候选逐试失败 → 裸收口 → 连接器会话建立
    /// 具名失败（官方对端解密失败面同形——无 openSessionResponse 即败）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wrong_credentials_fail_named() {
        let port = spawn_fake_echo_server("u", "other-pass").await;
        let connector =
            MieruConnector::new("127.0.0.1".into(), port, "u".into(), "p".into()).expect("构造");
        let (flow, mut client) = make_flow("203.0.113.9", 80);
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            let _ = client.write_all(b"x").await;
            fw.await
        });
        let err = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时（应快速失败而非悬挂）")
            .expect("join")
            .expect_err("错误凭据必须失败");
        assert!(err.to_string().contains("Mieru"), "具名失败: {err}");
    }

    /// 隧道内 SOCKS5 回复 REP≠0（目标不可达）：连接器具名拒绝、不漏
    /// 回复字节入隧道（官方 mita 对不可达目标同形——REP 码原样入
    /// dataS2C 载荷，实机捕获字节形）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tunnel_socks5_rep_nonzero_fail_named() {
        let port = spawn_fake_echo_server_with_rep("u", "p", 1).await;
        let connector = std::sync::Arc::new(
            MieruConnector::new("127.0.0.1".into(), port, "u".into(), "p".into()).expect("构造"),
        );
        let (flow, mut client) = make_flow("203.0.113.9", 80);
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            let _ = client.write_all(b"x").await;
            fw.await
        });
        let err = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时（应快速失败而非悬挂）")
            .expect("join")
            .expect_err("REP≠0 必须失败");
        assert!(
            format!("{err:#}").contains("REP=1"),
            "具名失败（隧道内 SOCKS5 REP）: {err:#}"
        );
    }

    // -----------------------------------------------------------------------
    // 官方 mita 实机对端（本席常驻 /tmp/mierupeer，v3.39.0）；缺席记名
    // 跳过（与 snell/ssh 对端测试同口径）——验收断言以实机运行为准。
    // -----------------------------------------------------------------------

    const MITA_PEER_ADDR: (&str, u16) = ("127.0.0.1", 23420);

    async fn mita_peer_ready() -> bool {
        TcpStream::connect(format!("{}:{}", MITA_PEER_ADDR.0, MITA_PEER_ADDR.1))
            .await
            .is_ok()
    }

    /// 官方 mita 回环：连接器 → mita（127.0.0.1:23420，用户 ril116，
    /// allowLoopbackIP）→ 本席回声上游。文本 + 10KB 逐字节还原 +
    /// FlowReport 计数对账。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_official_mita_server_roundtrip() {
        if !mita_peer_ready().await {
            eprintln!("跳过：官方 mita 对端缺席 (127.0.0.1:23420，/tmp/mierupeer 常驻实例)");
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("回声绑定");
        let echo_addr: SocketAddr = listener.local_addr().expect("回声地址");
        let echo = tokio::spawn(async move {
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

        let connector = std::sync::Arc::new(
            MieruConnector::new(
                MITA_PEER_ADDR.0.into(),
                MITA_PEER_ADDR.1,
                "ril116".into(),
                "ril116-pass-2026".into(),
            )
            .expect("构造"),
        );
        let (flow, mut client) = make_flow(&echo_addr.ip().to_string(), echo_addr.port());

        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let task_payload = payload.clone();
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            // join 并行（同镜像回环口径）；client drop → closeSessionRequest
            // 半关 → mita 收口 → forward 收束
            let (report, got) = tokio::join!(fw, async {
                client.write_all(b"official hello").await.expect("上行写");
                client.write_all(&task_payload).await.expect("上行大块写");
                let mut got = vec![0u8; 14 + task_payload.len()];
                tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut got))
                    .await
                    .expect("下行超时（官方对端回放面）")
                    .expect("下行读");
                drop(client);
                got
            });
            (report, got)
        });
        let (report, got) = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时（官方对端应答/中继面）")
            .expect("join");
        drop(echo);

        let mut expected = b"official hello".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(got, expected, "官方 mita 回环逐字节还原（含 10KB 越段界）");
        let report = report.expect("forward 成功");
        assert_eq!(report.upstream as usize, expected.len(), "上行计数");
        assert_eq!(report.downstream as usize, expected.len(), "下行计数");
    }
}
