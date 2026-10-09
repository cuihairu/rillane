//! VMess 出站连接器实现（VMess AEAD 认证头 + AES-128-GCM / ChaCha20-Poly1305
//! 数据面；tcp（可叠 TLS）/ ws（可叠 TLS）/ gRPC（恒叠 TLS）传输）
//!
//! 依据 Xray-core 参考实现逐字段移植（proxy/vmess/aead/{kdf,authid,encrypt}.go、
//! proxy/vmess/encoding/client.go、common/crypto/auth.go，main 与 v1.8.24 两版
//! 逐字节比对一致）：
//!
//! - **cmdKey** = MD5(uuid 字节 ‖ `c48619fe-8f02-49e0-b9e9-edf763e17e21`)
//!   （v2ray/xray `NewID` 共同的经典常量，客户端侧自行推导）
//! - **KDF**（`vmess_kdf`）：xray kdf.go 以 `hash2{prev}` 别名视图 + Go 1.27
//!   crypto/hmac 的 Sum 语义（每次 Sum 前 outer Reset 级联、New 只写 ipad）
//!   构造出一条对象链；展开后的闭式见函数注释——单测以 **xray kdf.go 原文
//!   跑出的真值向量**钉死（V0–V11，Go 1.27.1 本机实跑）
//! - **认证头**：authID = AES-128-ECB(KDF16(cmdKey, "AES Auth ID Encryption"),
//!   unix 秒 ‖ 随机 4B ‖ CRC32-IEEE(前 12B))，服务端解块校验 CRC + 时间窗
//!   (±120s) + 防重放；请求头（明文形见 `build_request_header_bytes`）经两级
//!   AES-128-GCM 封装：KDF 路径序为 **[盐串, authID, connNonce] 三路径**，
//!   两处 Seal 的 AAD 均为 authID（encrypt.go 原文；载荷块 AAD 并非长度块），
//!   线形 authID(16) ‖ sealedLen(18) ‖ connNonce(8) ‖ sealedHeader
//! - **响应头**：respKey/respIV = SHA256(reqKey/reqIV) 前 16B；18B 长度块 +
//!   载荷块均为 AES-128-GCM（AAD 空，KDF 单路径），首字节必须回声客户端
//!   shuffle 字节
//! - **数据面**：分块流（option 0x0D = chunk-stream|chunk-masking|
//!   global-padding，AEAD security 下 xray 客户端恒置全三位）；每块 =
//!   [掩码后 2B 长度][AEAD(明文)][明文随机 padding]（padding 随机且服务端
//!   不校验内容，防 SHAKE 内态泄漏）；块 nonce = [2B BE 计数器 ‖ IV[2..12]]
//!   递增（GenerateChunkNonce 原文）；长度掩码与 padding 长度取自
//!   SHAKE128(方向 IV)，**每块先抽 padding 再抽 mask**（AuthenticationWriter.seal
//!   与 AuthenticationReader.readSize 同序）；空载荷块 = 半关闭终止块
//!   （size == 16+padding）
//!
//! 边界：仅 AEAD 头（`alter_id > 0` 的 legacy 认证构建期即拒）；security 仅
//! auto/aes-128-gcm/chacha20-poly1305（xray 同期口径，legacy/none 已删）；
//! 仅 TCP 转发（UDP 在 runtime 构建期扫描即报错）。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use md5::Md5;
use rand::{rngs::OsRng, RngCore};
use seep_core::{EgressConnector, Flow, FlowReport, TargetProto};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, XofReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use super::grpc::grpc_tunnel;
use super::ws::{ws_client_handshake, WsReader, WsWriter};
use crate::fingerprint::TlsFingerprint;
use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};

// ---------------------------------------------------------------------------
// 常量（Xray proxy/vmess/aead/consts.go + common/protocol/id.go）
// ---------------------------------------------------------------------------

const KDF_SALT: &[u8] = b"VMess AEAD KDF";
/// `NewID` 的 cmdKey 盐（v2ray/xray 共同的经典常量）
const UUID_CMDKEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const S_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const S_HDR_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const S_HDR_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const S_HDR_PAY_KEY: &[u8] = b"VMess Header AEAD Key";
const S_HDR_PAY_IV: &[u8] = b"VMess Header AEAD Nonce";
const S_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const S_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const S_RESP_PAY_KEY: &[u8] = b"AEAD Resp Header Key";
const S_RESP_PAY_IV: &[u8] = b"AEAD Resp Header IV";

/// 请求 option（ChunkStream|ChunkMasking|GlobalPadding = 0x01|0x04|0x08）：
/// AEAD security 下 xray 客户端恒置全三位（shouldEnablePadding 恒真）
const REQUEST_OPTION: u8 = 0x01 | 0x04 | 0x08;

/// AEAD 块/头的固定开销（GCM tag）
const AEAD_OVERHEAD: usize = 16;

// ---------------------------------------------------------------------------
// KDF（xray proxy/vmess/aead/kdf.go 的闭式展开）
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let ipad = pad_block(key, 0x36);
    let opad = pad_block(key, 0x5c);
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// xray `KDF(key, paths...)`：Go 对象链（`hash2{prev}` 别名 + Go 1.27
/// fips140/hmac「New 只写 ipad、Sum 前 outer.Reset() 级联」语义）展开后的
/// 闭式——
///
/// ```text
/// H(M) = HMAC-SHA256("VMess AEAD KDF", M)
/// sumk(k, M) = let d  = (k==1 ? H(M) : sumk(k-1, M))
///                  M2 = ipad(v1..k-1) ‖ opad(vk) ‖ d
///              k==1 ? H(M2) : sumk(k-1, M2)
/// KDF(key, v1..vn) = sumk(n, ipad(v1) ‖ … ‖ ipad(vn) ‖ key)
/// ```
///
/// 与直觉相悖的点：消息里只出现各路径的 **ipad**——opad(vk) 经别名写回
/// 在每层 Sum 的 outer 阶段进入下一层消息（`M2` 的 `opad(vk)` 项）。
/// 正确性以 xray kdf.go 原文实跑的真值向量钉死（V0–V11，n=1..5 全覆盖）。
fn vmess_kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let n = paths.len();
    if n == 0 {
        return hmac_sha256(KDF_SALT, key);
    }
    let ipads: Vec<[u8; 64]> = paths.iter().map(|p| pad_block(p, 0x36)).collect();
    let opads: Vec<[u8; 64]> = paths.iter().map(|p| pad_block(p, 0x5c)).collect();

    fn sumk(k: usize, msg: &[u8], ipads: &[[u8; 64]], opads: &[[u8; 64]]) -> [u8; 32] {
        let d = if k == 1 {
            hmac_sha256(KDF_SALT, msg)
        } else {
            sumk(k - 1, msg, ipads, opads)
        };
        let mut m2 = Vec::with_capacity(64 * k + d.len());
        for p in &ipads[..k - 1] {
            m2.extend_from_slice(p);
        }
        m2.extend_from_slice(&opads[k - 1]);
        m2.extend_from_slice(&d);
        if k == 1 {
            hmac_sha256(KDF_SALT, &m2)
        } else {
            sumk(k - 1, &m2, ipads, opads)
        }
    }

    let mut m = Vec::with_capacity(64 * n + key.len());
    for p in &ipads {
        m.extend_from_slice(p);
    }
    m.extend_from_slice(key);
    sumk(n, &m, &ipads, &opads)
}

fn vmess_kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = vmess_kdf(key, paths);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn kdf_nonce12(key: &[u8], paths: &[&[u8]]) -> [u8; 12] {
    let full = vmess_kdf(key, paths);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// HMAC 分组填充（调用面均为短盐/16B 派生量，>64B 分支仅防御）
fn pad_block(key: &[u8], pad: u8) -> [u8; 64] {
    let mut block = [pad; 64];
    let k: &[u8] = if key.len() > 64 {
        &Sha256::digest(key)
    } else {
        key
    };
    for (i, b) in k.iter().enumerate() {
        block[i] ^= b;
    }
    block
}

// ---------------------------------------------------------------------------
// 认证头（aead/authid.go + aead/encrypt.go）
// ---------------------------------------------------------------------------

/// `NewID`：cmdKey = MD5(uuid 字节 ‖ 盐)
fn cmd_key_from_uuid(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid_bytes);
    h.update(UUID_CMDKEY_SALT);
    h.finalize().into()
}

/// `CreateAuthID`：AES-128-ECB 单块加密 (unix 秒 ‖ 随机 4B ‖ CRC32-IEEE(前12B))
fn build_auth_id(auth_id_key: &[u8; 16], unix_ts: i64, rand4: [u8; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&unix_ts.to_be_bytes());
    block[8..12].copy_from_slice(&rand4);
    let crc = crc32fast::hash(&block[..12]);
    block[12..].copy_from_slice(&crc.to_be_bytes());
    let cipher = Aes128::new(auth_id_key.into());
    let mut b = Block::from(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

/// `SealVMessAEADHeader`（随机量注入的确定性核心，返回 (整封头, authID)）：
/// authID(16) ‖ 长度块 AEAD(18，AAD=authID) ‖ connNonce(8) ‖ 头块 AEAD
/// （AAD=authID，与长度块相同——encrypt.go 两处 Seal 的 AAD 均为 authID；
/// KDF 路径序 [盐串, authID, connNonce]）
fn seal_vmess_aead_header_det(
    cmd_key: &[u8; 16],
    data: &[u8],
    unix_ts: i64,
    rand4: [u8; 4],
    conn_nonce: [u8; 8],
) -> Result<(Vec<u8>, [u8; 16])> {
    if data.len() > u16::MAX as usize {
        return Err(anyhow!("VMess 请求头过大（>65535）"));
    }
    let auth_id_key = vmess_kdf16(cmd_key, &[S_AUTH_ID_KEY]);
    let auth_id = build_auth_id(&auth_id_key, unix_ts, rand4);

    // 长度块：AAD = authID
    let len_key = vmess_kdf16(cmd_key, &[S_HDR_LEN_KEY, &auth_id, &conn_nonce]);
    let len_nonce = kdf_nonce12(cmd_key, &[S_HDR_LEN_IV, &auth_id, &conn_nonce]);
    let len_aead =
        Aes128Gcm::new_from_slice(&len_key).map_err(|_| anyhow!("VMess 长度块密钥初始化失败"))?;
    let len_sealed = len_aead
        .encrypt(
            Nonce::from_slice(&len_nonce),
            Payload {
                msg: &(data.len() as u16).to_be_bytes(),
                aad: &auth_id,
            },
        )
        .map_err(|_| anyhow!("VMess 长度块加密失败"))?;

    // 头块：AAD = authID（与长度块相同；encrypt.go 原文两处均为 authID）
    let pay_key = vmess_kdf16(cmd_key, &[S_HDR_PAY_KEY, &auth_id, &conn_nonce]);
    let pay_nonce = kdf_nonce12(cmd_key, &[S_HDR_PAY_IV, &auth_id, &conn_nonce]);
    let pay_aead =
        Aes128Gcm::new_from_slice(&pay_key).map_err(|_| anyhow!("VMess 头块密钥初始化失败"))?;
    let pay_sealed = pay_aead
        .encrypt(
            Nonce::from_slice(&pay_nonce),
            Payload {
                msg: data,
                aad: &auth_id,
            },
        )
        .map_err(|_| anyhow!("VMess 头块加密失败"))?;

    let mut out = Vec::with_capacity(16 + 18 + 8 + pay_sealed.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&len_sealed);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&pay_sealed);
    Ok((out, auth_id))
}

/// `SealVMessAEADHeader`：时间/随机量现场抽取
fn seal_vmess_aead_header(cmd_key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let ts = unix_now()?;
    let mut rand4 = [0u8; 4];
    let mut conn_nonce = [0u8; 8];
    OsRng.fill_bytes(&mut rand4);
    OsRng.fill_bytes(&mut conn_nonce);
    Ok(seal_vmess_aead_header_det(cmd_key, data, ts, rand4, conn_nonce)?.0)
}

// ---------------------------------------------------------------------------
// 数据面（encoding/client.go + common/crypto/auth.go 的 AuthenticationWriter/Reader）
// ---------------------------------------------------------------------------

/// 数据面安全类型（SecurityType 值 3/4；`auto` 按 xray 有 AES 硬件的分支
/// 取 AES-128-GCM）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl VmessSecurity {
    /// 配置字符串 → 枚举
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" | "aes-128-gcm" | "aes128-gcm" => Ok(VmessSecurity::Aes128Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Ok(VmessSecurity::Chacha20Poly1305),
            other => Err(anyhow!(
                "VMess security 仅支持 auto/aes-128-gcm/chacha20-poly1305（xray AEAD 口径），当前 `{other}`"
            )),
        }
    }

    fn header_byte(self) -> u8 {
        match self {
            VmessSecurity::Aes128Gcm => 0x03,
            VmessSecurity::Chacha20Poly1305 => 0x04,
        }
    }
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn unix_now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)?)
}

/// 请求头明文（EncodeRequestHeader，纯函数）：
/// [0x01][reqIV 16][reqKey 16][V][option][(pad<<4)|security][0x00][0x01 TCP]
/// [port BE16][地址][padding][FNV1a32 BE]
fn build_request_header_bytes(
    req_iv: &[u8; 16],
    req_key: &[u8; 16],
    expect_v: u8,
    padding: &[u8],
    security: VmessSecurity,
    target_host: &str,
    target_port: u16,
) -> Result<Vec<u8>> {
    if padding.len() > 15 {
        return Err(anyhow!("VMess 请求头 padding 过长（>15，4bit 位域）"));
    }
    let mut buf = Vec::with_capacity(128);
    buf.push(0x01); // Version
    buf.extend_from_slice(req_iv);
    buf.extend_from_slice(req_key);
    buf.push(expect_v);
    buf.push(REQUEST_OPTION);
    buf.push((padding.len() as u8) << 4 | security.header_byte());
    buf.push(0x00); // Reserved
    buf.push(0x01); // Command: TCP
    buf.extend_from_slice(&target_port.to_be_bytes());

    // 地址（AddressType：1=IPv4 2=域名 3=IPv6）
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            buf.push(0x03);
            buf.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let host = target_host.as_bytes();
            if host.is_empty() || host.len() > 255 {
                return Err(anyhow!("VMess 目标域名为空或过长（>255）"));
            }
            buf.push(0x02);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host);
        }
    }

    if !padding.is_empty() {
        buf.extend_from_slice(padding);
    }

    let checksum = fnv1a32(&buf);
    buf.extend_from_slice(&checksum.to_be_bytes());
    Ok(buf)
}

/// 响应头 AEAD 密钥组（DecodeResponseHeader；KDF 单路径）
#[derive(Clone)]
struct RespHeaderKeys {
    len_key: [u8; 16],
    len_nonce: [u8; 12],
    pay_key: [u8; 16],
    pay_nonce: [u8; 12],
}

impl RespHeaderKeys {
    /// 由 reqKey/reqIV 派生（NewClientSession：SHA256 前 16B，而非 legacy MD5）
    fn derive(req_key: &[u8; 16], req_iv: &[u8; 16]) -> Self {
        let resp_key: [u8; 16] = Sha256::digest(req_key)[..16]
            .try_into()
            .expect("SHA256 截断");
        let resp_iv: [u8; 16] = Sha256::digest(req_iv)[..16]
            .try_into()
            .expect("SHA256 截断");
        RespHeaderKeys {
            len_key: vmess_kdf16(&resp_key, &[S_RESP_LEN_KEY]),
            len_nonce: kdf_nonce12(&resp_iv, &[S_RESP_LEN_IV]),
            pay_key: vmess_kdf16(&resp_key, &[S_RESP_PAY_KEY]),
            pay_nonce: kdf_nonce12(&resp_iv, &[S_RESP_PAY_IV]),
        }
    }
}

struct VmessSession {
    sealed_header: Vec<u8>,
    expect_v: u8,
    req_crypt: ChunkCrypt,
    resp_crypt: ChunkCrypt,
    resp_header_keys: RespHeaderKeys,
}

/// 一次会话的请求头 + 双向分块态（随机量现场抽取）
fn build_session(
    cmd_key: &[u8; 16],
    security: VmessSecurity,
    host: &str,
    port: u16,
) -> Result<VmessSession> {
    let mut req_iv = [0u8; 16];
    let mut req_key = [0u8; 16];
    OsRng.fill_bytes(&mut req_iv);
    OsRng.fill_bytes(&mut req_key);
    let expect_v = OsRng.next_u32() as u8;
    // padding 走 crypto/rand（明文随路，防 SHAKE 掩码流内态泄漏；xray 同源）
    let pad_len = (OsRng.next_u32() % 16) as usize;
    let mut pad = vec![0u8; pad_len];
    OsRng.fill_bytes(&mut pad);

    let plain =
        build_request_header_bytes(&req_iv, &req_key, expect_v, &pad, security, host, port)?;
    let sealed_header = seal_vmess_aead_header(cmd_key, &plain)?;

    Ok(VmessSession {
        sealed_header,
        expect_v,
        req_crypt: ChunkCrypt::new(security, &req_key, &req_iv)?,
        resp_crypt: ChunkCrypt::derive_response(security, &req_key, &req_iv)?,
        resp_header_keys: RespHeaderKeys::derive(&req_key, &req_iv),
    })
}

/// 逐块 AEAD 实例 + 块 nonce/掩码/padding 序列态
struct ChunkCrypt {
    aead: DataAead,
    iv: [u8; 16],
    shake: sha3::Shake128Reader,
    counter: u16,
}

enum DataAead {
    Aes(Box<Aes128Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl DataAead {
    fn new(security: VmessSecurity, key: &[u8; 16]) -> Result<Self> {
        match security {
            VmessSecurity::Aes128Gcm => Ok(DataAead::Aes(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("VMess AEAD 密钥非法"))?,
            ))),
            VmessSecurity::Chacha20Poly1305 => {
                // GenerateChacha20Poly1305Key：md5(k) ‖ md5(md5(k))
                let k1 = Md5::digest(key);
                let k2 = Md5::digest(k1);
                let mut k32 = [0u8; 32];
                k32[..16].copy_from_slice(&k1);
                k32[16..].copy_from_slice(&k2);
                Ok(DataAead::Chacha(Box::new(
                    ChaCha20Poly1305::new_from_slice(&k32)
                        .map_err(|_| anyhow!("VMess AEAD 密钥非法"))?,
                )))
            }
        }
    }

    fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Result<Vec<u8>> {
        let res = match self {
            DataAead::Aes(a) => a.encrypt(Nonce::from_slice(nonce), plain),
            DataAead::Chacha(a) => a.encrypt(Nonce::from_slice(nonce), plain),
        };
        res.map_err(|_| anyhow!("VMess 数据块加密失败"))
    }

    fn open(&self, nonce: &[u8; 12], sealed: &[u8]) -> Result<Vec<u8>> {
        let res = match self {
            DataAead::Aes(a) => a.decrypt(Nonce::from_slice(nonce), sealed),
            DataAead::Chacha(a) => a.decrypt(Nonce::from_slice(nonce), sealed),
        };
        res.map_err(|_| anyhow!("VMess 数据块解密失败（认证不匹配或流损坏）"))
    }
}

impl ChunkCrypt {
    fn new(security: VmessSecurity, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        Ok(ChunkCrypt {
            aead: DataAead::new(security, key)?,
            iv: *iv,
            shake: {
                // XOF 无 Digest::new 面；灌数走 Update UFCS（该 trait 不入
                // 作用域——与 sha2::Digest 的 update 双候选冲突）
                let mut shake = sha3::Shake128::default();
                sha3::digest::Update::update(&mut shake, iv);
                shake.finalize_xof()
            },
            counter: 0,
        })
    }

    /// 响应方向：respKey/respIV = SHA256(reqKey/reqIV)[:16]（NewClientSession）
    fn derive_response(
        security: VmessSecurity,
        req_key: &[u8; 16],
        req_iv: &[u8; 16],
    ) -> Result<Self> {
        let resp_key: [u8; 16] = Sha256::digest(req_key)[..16]
            .try_into()
            .expect("SHA256 截断");
        let resp_iv: [u8; 16] = Sha256::digest(req_iv)[..16]
            .try_into()
            .expect("SHA256 截断");
        Self::new(security, &resp_key, &resp_iv)
    }

    /// 块 nonce = [2B BE 计数器 ‖ IV[2..12]]（GenerateChunkNonce：计数器写进
    /// 16B IV 拷贝的前 2 字节后取前 12B），每次取用后自增
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    /// ShakeSizeParser.next()：2B BE 原始抽取
    fn shake_next(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.shake.read(&mut buf);
        u16::from_be_bytes(buf)
    }

    /// 长度掩码（Encode/Decode 的 `next()` 全 16bit——源码无 `& 0x3FFF`
    /// 截断，官方客户端抓包解码证实；旧 `& 0x3FFF` 致互操作静默 stall）
    fn next_mask(&mut self) -> u16 {
        self.shake_next()
    }

    /// padding 长度（NextPaddingLen，`next() % 64`）——**每块先抽此项再抽掩码**
    fn next_padding(&mut self) -> u16 {
        self.shake_next() % 64
    }
}

// ---------------------------------------------------------------------------
// 分块流字节面（tcp 半流 / ws 读写器统一）
// ---------------------------------------------------------------------------

#[async_trait]
trait ChunkRead: Send {
    async fn exact(&mut self, out: &mut [u8]) -> Result<()>;
}

/// gRPC 消息流 → 字节流适配：跨消息边界拼凑语义见 GrpcReader::read_exact
/// （消息边界与 vmess 块边界无对齐保证，同 ws）
#[async_trait]
impl ChunkRead for super::grpc::GrpcReader {
    async fn exact(&mut self, out: &mut [u8]) -> Result<()> {
        super::grpc::GrpcReader::read_exact(self, out).await
    }
}

#[async_trait]
impl<R: AsyncRead + Unpin + Send> ChunkRead for tokio::io::ReadHalf<R> {
    async fn exact(&mut self, out: &mut [u8]) -> Result<()> {
        self.read_exact(out).await?;
        Ok(())
    }
}

/// ws 二进制消息流 → 字节流适配：消息边界与 vmess 块边界无对齐保证，
/// 跨消息剩余经 stash 续接（与 vless `WsClient::read_exact` 同构）。
///
/// 注意不能直接给 `WsReader` 实现 `ChunkRead`：其固有 `read_exact` 是帧级
/// 原语（消费握手 leftover 后直读裸流），只在 `read_frame` 内正确；字节流
/// 语义的消息重组必须走 `read_binary`（回环挂死即此因）。
struct WsMsgReader<'a, R: AsyncRead + Unpin + Send> {
    inner: &'a mut WsReader<R>,
    stash: Vec<u8>,
}

#[async_trait]
impl<R: AsyncRead + Unpin + Send> ChunkRead for WsMsgReader<'_, R> {
    async fn exact(&mut self, out: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        if !self.stash.is_empty() {
            let n = out.len().min(self.stash.len());
            out[..n].copy_from_slice(&self.stash[..n]);
            self.stash.drain(..n);
            filled = n;
        }
        while filled < out.len() {
            let Some(msg) = self.inner.read_binary().await? else {
                return Err(anyhow!("WebSocket 连接已关闭"));
            };
            if msg.is_empty() {
                continue;
            }
            let n = (out.len() - filled).min(msg.len());
            out[filled..filled + n].copy_from_slice(&msg[..n]);
            filled += n;
            if n < msg.len() {
                self.stash.extend_from_slice(&msg[n..]);
            }
        }
        Ok(())
    }
}

/// `&mut S`（S: AsyncRead）的 ChunkRead 面——测试侧回环服务端复用
/// （产线读面为 ReadHalf/WsMsgReader 两 impl）
#[cfg(test)]
struct StreamSrc<'a, S: ?Sized>(&'a mut S);

#[cfg(test)]
#[async_trait]
impl<S: AsyncRead + Unpin + Send + ?Sized> ChunkRead for StreamSrc<'_, S> {
    async fn exact(&mut self, out: &mut [u8]) -> Result<()> {
        self.0.read_exact(out).await?;
        Ok(())
    }
}

#[async_trait]
trait ChunkWrite: Send {
    async fn put(&mut self, data: &[u8]) -> Result<()>;
    async fn finish(&mut self) -> Result<()>;
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> ChunkWrite for tokio::io::WriteHalf<W> {
    async fn put(&mut self, data: &[u8]) -> Result<()> {
        self.write_all(data).await?;
        self.flush().await?;
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        Ok(self.shutdown().await?)
    }
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> ChunkWrite for WsWriter<W> {
    async fn put(&mut self, data: &[u8]) -> Result<()> {
        WsWriter::write_binary(self, data).await
    }

    /// ws 无半关闭面：终止块即信令，通道随 lease 释放关闭
    async fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ChunkWrite for super::grpc::GrpcWriter {
    async fn put(&mut self, data: &[u8]) -> Result<()> {
        super::grpc::GrpcWriter::message(self, data).await
    }

    /// 终止块为分块流信令；END_STREAM 面由上行 EOF 收尾处显式传播
    async fn finish(&mut self) -> Result<()> {
        super::grpc::GrpcWriter::finish(self).await
    }
}

/// `&mut S`（S: AsyncWrite）的 ChunkWrite 面——测试侧回环服务端的直写复用
/// （产线写面为 WriteHalf/WsWriter/GrpcWriter 多 impl）
#[cfg(test)]
struct StreamSink<'a, S: ?Sized>(&'a mut S);

#[cfg(test)]
#[async_trait]
impl<S: AsyncWrite + Unpin + Send + ?Sized> ChunkWrite for StreamSink<'_, S> {
    async fn put(&mut self, data: &[u8]) -> Result<()> {
        self.0.write_all(data).await?;
        self.0.flush().await?;
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        Ok(self.0.shutdown().await?)
    }
}

/// 写一块：[掩码长度 2B][AEAD(明文)][明文随机 padding]；data 为空 = 终止块。
/// 每块先抽 padding 再抽 mask（AuthenticationWriter.seal 同序）。
async fn write_chunk<W: ChunkWrite + ?Sized>(
    c: &mut ChunkCrypt,
    w: &mut W,
    data: &[u8],
) -> Result<()> {
    let mut out = Vec::with_capacity(2 + data.len() + AEAD_OVERHEAD + 64);
    append_chunk(c, data, &mut out)?;
    w.put(&out).await
}

/// 块构造的纯内存面（构造结果追加进 out）——ws 首条消息与请求头合帧复用。
/// 每块先抽 padding 再抽 mask（AuthenticationWriter.seal 同序）。
fn append_chunk(c: &mut ChunkCrypt, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let padding = c.next_padding();
    let mask = c.next_mask();
    if data.len() + AEAD_OVERHEAD > u16::MAX as usize {
        return Err(anyhow!("VMess 数据块过大（>65535-64）"));
    }
    let len_val = (data.len() + AEAD_OVERHEAD) as u16 + padding;
    let masked = len_val ^ mask;
    let nonce = c.next_nonce();
    let sealed = c.aead.seal(&nonce, data)?;

    out.extend_from_slice(&masked.to_be_bytes());
    out.extend_from_slice(&sealed);
    if padding > 0 {
        // 明文随机 padding（防 SHAKE 内态泄漏；xray 用 crypto/rand）
        let mut pad = vec![0u8; padding as usize];
        OsRng.fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
    }
    Ok(())
}

/// 读一块（独立返回明文；空 Vec = 终止块/半关闭）。
/// 读写同序：先抽 padding 再抽 mask（AuthenticationReader.readSize 一致）。
async fn read_chunk<R: ChunkRead + ?Sized>(c: &mut ChunkCrypt, r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.exact(&mut hdr).await?;
    let padding = c.next_padding();
    let mask = c.next_mask();
    let size = u16::from_be_bytes(hdr) ^ mask;
    if size == AEAD_OVERHEAD as u16 + padding {
        return Ok(Vec::new());
    }
    if (size as usize) < padding as usize + AEAD_OVERHEAD {
        return Err(anyhow!("VMess 数据块长度异常: {size}"));
    }
    let mut body = vec![0u8; size as usize];
    r.exact(&mut body).await?;
    let plain_len = size as usize - padding as usize - AEAD_OVERHEAD;
    let nonce = c.next_nonce();
    c.aead.open(&nonce, &body[..plain_len + AEAD_OVERHEAD])
}

// ---------------------------------------------------------------------------
// 响应头（DecodeResponseHeader）
// ---------------------------------------------------------------------------

/// 18B 长度块（AAD 空）+ 载荷块，首字节必须回声客户端 shuffle 字节
async fn read_response_header<R: ChunkRead + ?Sized>(
    r: &mut R,
    expect_v: u8,
    keys: &RespHeaderKeys,
) -> Result<()> {
    let mut len_sealed = [0u8; 18];
    r.exact(&mut len_sealed)
        .await
        .context("读取 VMess 响应头长度块失败")?;

    let len_aead = Aes128Gcm::new_from_slice(&keys.len_key)
        .map_err(|_| anyhow!("VMess 响应长度块密钥初始化失败"))?;
    let len_plain = len_aead
        .decrypt(Nonce::from_slice(&keys.len_nonce), &len_sealed[..])
        .map_err(|_| anyhow!("VMess 响应头长度块解密失败（认证不匹配）"))?;
    if len_plain.len() != 2 {
        return Err(anyhow!("VMess 响应头长度块长度异常"));
    }
    let pay_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    let mut pay_sealed = vec![0u8; pay_len + AEAD_OVERHEAD];
    r.exact(&mut pay_sealed)
        .await
        .context("读取 VMess 响应头载荷失败")?;
    let pay_aead = Aes128Gcm::new_from_slice(&keys.pay_key)
        .map_err(|_| anyhow!("VMess 响应头密钥初始化失败"))?;
    let payload = pay_aead
        .decrypt(Nonce::from_slice(&keys.pay_nonce), &pay_sealed[..])
        .map_err(|_| anyhow!("VMess 响应头载荷解密失败（认证不匹配）"))?;
    if payload.len() < 4 {
        return Err(anyhow!("VMess 响应头过短"));
    }
    if payload[0] != expect_v {
        return Err(anyhow!(
            "VMess 响应认证字节不匹配：期望 {} 实际 {}",
            expect_v,
            payload[0]
        ));
    }
    // payload[1] = option、payload[2..] = 响应命令（当前均不消费）
    Ok(())
}

// ---------------------------------------------------------------------------
// 连接器
// ---------------------------------------------------------------------------

pub struct VmessConnector {
    server: String,
    port: u16,
    uuid: String,
    alter_id: u16,
    security: VmessSecurity,
    network: String,
    path: Option<String>,
    host: Option<Vec<String>>,
    grpc_service_name: Option<String>,
    tls: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
    /// 客户端 TLS 指纹形态（P2-5；None = rustls 缺省形态；仅 tls=true 时生效）
    fingerprint: TlsFingerprint,
    /// 出站连接池（P1-5 §4.2；None = 旧行为内联路径，D-9）
    pool: Option<Arc<TransportPool>>,
    /// 共享 ClientConfig 工厂：pool=None 且 tls 时使 TLS 会话恢复独立于池生效
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl VmessConnector {
    /// `security` 由调用方预解析（构建期非法值报错）；`alter_id != 0` 的
    /// legacy 认证不支持
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        uuid: String,
        alter_id: u16,
        security: VmessSecurity,
        network: String,
        path: Option<String>,
        host: Option<Vec<String>>,
        grpc_service_name: Option<String>,
        tls: bool,
        skip_cert_verify: bool,
        sni: Option<String>,
        alpn: Option<Vec<String>>,
        fingerprint: TlsFingerprint,
        pool: Option<Arc<TransportPool>>,
        factory: Option<Arc<TlsConnectorFactory>>,
    ) -> Self {
        Self {
            server,
            port,
            uuid,
            alter_id,
            security,
            network,
            path,
            host,
            grpc_service_name,
            tls,
            skip_cert_verify,
            sni,
            alpn,
            fingerprint,
            pool,
            factory,
        }
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// 传输键（§4.2）：TLS 走五元组键（实际 SNI：tcp = sni ∥ server，
    /// ws = sni ∥ host 首值 ∥ server），平文走 plain 键
    fn transport_key(&self, actual_sni: &str) -> TransportKey {
        if self.tls {
            TransportKey::tls(
                &self.server,
                self.port,
                Some(actual_sni),
                self.skip_cert_verify,
                self.alpn.as_deref().unwrap_or(&[]),
                self.fingerprint,
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

    /// gRPC 服务名（network=grpc 必填；缺省/空串构建期由 runtime_builder
    /// 校验，此处运行期兜底）
    fn grpc_service_name(&self) -> Result<String> {
        self.grpc_service_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("VMess gRPC 缺少 grpc_service_name"))
    }

    fn session(&self, target_host: &str, target_port: u16) -> Result<VmessSession> {
        if self.alter_id != 0 {
            return Err(anyhow!(
                "VMess AEAD 仅支持 alter_id=0（legacy MD5 认证已不支持）"
            ));
        }
        let id = Uuid::parse_str(self.uuid.trim()).context("无效的 VMess uuid")?;
        let cmd_key = cmd_key_from_uuid(id.as_bytes());
        build_session(&cmd_key, self.security, target_host, target_port)
    }
}

#[async_trait]
impl EgressConnector for VmessConnector {
    fn name(&self) -> &'static str {
        "vmess"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        match &self.pool {
            Some(pool) => self.forward_pooled(flow, pool).await,
            None => self.forward_inline(flow).await,
        }
    }
}

impl VmessConnector {
    /// 池借出路径（§4.2）：acquire → 协议绑定（tcp = 请求头往返；ws = upgrade
    /// 借出后进行）→ 双向转发；绑定失败 → stale 一次性重拨（D-11）。
    async fn forward_pooled(&self, flow: Flow, pool: &Arc<TransportPool>) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            _ => return Err(anyhow!("VMess 暂仅支持 TCP 转发")),
        }
        if self.alter_id != 0 {
            return Err(anyhow!(
                "VMess AEAD 仅支持 alter_id=0（legacy MD5 认证已不支持）"
            ));
        }

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_addr = self.server_addr();
        tracing::debug!(
            target: "seep::vmess",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            tls = %self.tls,
            network = %self.network,
            security = ?self.security,
            pooled = true,
            "通过 VMess 连接"
        );

        match self.network.as_str() {
            "tcp" => {
                let sni_actual = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let key = self.transport_key(&sni_actual);
                let mut session = self.session(&flow.target.host, flow.target.port)?;
                let sealed = session.sealed_header.clone();
                let expect_v = session.expect_v;
                let resp_keys = session.resp_header_keys.clone();
                let (stream, _lease) = pool
                    .acquire_bound(&key, move |io| {
                        let sealed = sealed.clone();
                        Box::pin(async move {
                            io.write_all(&sealed).await?;
                            io.flush().await?;
                            Ok(())
                        })
                    })
                    .await
                    .with_context(|| format!("连接 VMess 服务器失败: {server_addr}"))?;

                let (rr, ww) = tokio::io::split(stream);
                relay_vmess_stream(
                    flow,
                    rr,
                    ww,
                    &mut session.req_crypt,
                    &mut session.resp_crypt,
                    expect_v,
                    &resp_keys,
                )
                .await
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
                    .with_context(|| format!("连接 VMess 服务器失败: {server_addr}"))?;
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
                self.relay_session_over_ws(flow, ws).await
            }
            "grpc" => {
                let service = self.grpc_service_name()?;
                // grpc 恒叠 TLS + ALPN h2（gRPC over TLS 语义），SNI 回退 server
                if !self.tls {
                    return Err(anyhow!("VMess network=grpc 需叠 TLS（gRPC over TLS 语义）"));
                }
                let sni_actual = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let alpn_h2 = vec!["h2".to_string()];
                let key = TransportKey::tls(
                    &self.server,
                    self.port,
                    Some(&sni_actual),
                    self.skip_cert_verify,
                    &alpn_h2,
                    self.fingerprint,
                );
                let mut session = self.session(&flow.target.host, flow.target.port)?;

                // 借出传输层（TLS 已由池侧建立）；gRPC 隧道借出后进行（§4.2）
                let (boxed, first_lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接 VMess 服务器失败: {server_addr}"))?;
                let tunnel = grpc_tunnel(boxed, &sni_actual, &service).await;
                let (tunnel, _lease) = match tunnel {
                    Ok(t) => (t, first_lease),
                    Err(_) => {
                        // 隧道握手失败 → stale 一次性重拨（D-11）
                        drop(first_lease);
                        pool.note_stale(&key);
                        let (boxed, lease) = pool.acquire_fresh(&key).await?;
                        let t = grpc_tunnel(boxed, &sni_actual, &service)
                            .await
                            .with_context(|| "VMess over gRPC 隧道握手失败")?;
                        (t, lease)
                    }
                };
                self.relay_session_over_grpc(flow, tunnel, &mut session)
                    .await
            }
            other => Err(anyhow!("暂不支持的 VMess network: {other}")),
        }
    }

    /// 内联路径（pool=None）：与既有实现逐 IO 序列同构（D-9）；factory=Some
    /// 且 tls 时 TLS 连接器改取共享 ClientConfig（tls_resumption 独立于池生效）。
    async fn forward_inline(&self, flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            _ => return Err(anyhow!("VMess 暂仅支持 TCP 转发")),
        }
        if self.alter_id != 0 {
            return Err(anyhow!(
                "VMess AEAD 仅支持 alter_id=0（legacy MD5 认证已不支持）"
            ));
        }

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_addr = self.server_addr();
        tracing::debug!(
            target: "seep::vmess",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            tls = %self.tls,
            network = %self.network,
            security = ?self.security,
            "通过 VMess 连接"
        );

        // net_mark 统一拨号（SO_MARK 逃逸面，networking.md §2；缺省 0 零差异）
        let mut tcp = seep_core::net_mark::connect_tcp(server_addr.clone())
            .await
            .with_context(|| format!("连接 VMess 服务器失败: {server_addr}"))?;
        let _ = tcp.set_nodelay(true);

        match self.network.as_str() {
            "tcp" => {
                let mut session = self.session(&flow.target.host, flow.target.port)?;
                if self.tls {
                    let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
                    let connector = match &self.factory {
                        Some(factory) => factory.connector(
                            self.skip_cert_verify,
                            self.alpn.as_deref().unwrap_or(&[]),
                            self.fingerprint,
                        )?,
                        None => create_tls_connector_with_profile(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
                            self.fingerprint,
                        )?,
                    };
                    let server_name =
                        rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                    let mut stream = connector.connect(server_name, tcp).await?;
                    stream.write_all(&session.sealed_header).await?;
                    stream.flush().await?;

                    let (rr, ww) = tokio::io::split(stream);
                    relay_vmess_stream(
                        flow,
                        rr,
                        ww,
                        &mut session.req_crypt,
                        &mut session.resp_crypt,
                        session.expect_v,
                        &session.resp_header_keys,
                    )
                    .await
                } else {
                    tcp.write_all(&session.sealed_header).await?;
                    tcp.flush().await?;

                    let (rr, ww) = tokio::io::split(tcp);
                    relay_vmess_stream(
                        flow,
                        rr,
                        ww,
                        &mut session.req_crypt,
                        &mut session.resp_crypt,
                        session.expect_v,
                        &session.resp_header_keys,
                    )
                    .await
                }
            }
            "ws" | "websocket" => {
                let ws_host = self.ws_host_header();
                let ws_path = self.ws_path();
                let mut session = self.session(&flow.target.host, flow.target.port)?;

                if self.tls {
                    let sni = self.sni.clone().unwrap_or_else(|| ws_host.clone());
                    let connector = match &self.factory {
                        Some(factory) => factory.connector(
                            self.skip_cert_verify,
                            self.alpn.as_deref().unwrap_or(&[]),
                            self.fingerprint,
                        )?,
                        None => create_tls_connector_with_profile(
                            self.skip_cert_verify,
                            self.alpn.as_deref(),
                            self.fingerprint,
                        )?,
                    };
                    let server_name =
                        rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
                    let tls_stream = connector.connect(server_name, tcp).await?;
                    let ws = ws_client_handshake(tls_stream, &ws_host, &ws_path).await?;
                    self.relay_session_over_ws_with(flow, ws, &mut session)
                        .await
                } else {
                    let ws = ws_client_handshake(tcp, &ws_host, &ws_path).await?;
                    self.relay_session_over_ws_with(flow, ws, &mut session)
                        .await
                }
            }
            "grpc" => {
                let service = self.grpc_service_name()?;
                // grpc 恒叠 TLS + ALPN h2（gRPC over TLS 语义），SNI 回退 server
                if !self.tls {
                    return Err(anyhow!("VMess network=grpc 需叠 TLS（gRPC over TLS 语义）"));
                }
                let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
                let mut session = self.session(&flow.target.host, flow.target.port)?;
                let connector = match &self.factory {
                    Some(factory) => factory.connector(
                        self.skip_cert_verify,
                        &["h2".to_string()],
                        self.fingerprint,
                    )?,
                    None => create_tls_connector_with_profile(
                        self.skip_cert_verify,
                        Some(&["h2".to_string()]),
                        self.fingerprint,
                    )?,
                };
                let server_name =
                    rustls::pki_types::ServerName::try_from(sni.clone()).context("无效的 SNI")?;
                let tls_stream = connector.connect(server_name, tcp).await?;
                let tunnel = grpc_tunnel(tls_stream, &sni, &service)
                    .await
                    .with_context(|| "VMess over gRPC 隧道握手失败")?;
                self.relay_session_over_grpc(flow, tunnel, &mut session)
                    .await
            }
            other => Err(anyhow!("暂不支持的 VMess network: {other}")),
        }
    }

    /// ws 传输（upgrade 完成后的协议段；池路径复用）——会话从 flow 现场构建
    async fn relay_session_over_ws<R, W>(
        &self,
        flow: Flow,
        ws: super::ws::WsClient<R, W>,
    ) -> Result<FlowReport>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let mut session = self.session(&flow.target.host, flow.target.port)?;
        self.relay_session_over_ws_with(flow, ws, &mut session)
            .await
    }

    /// VMess over WS：头以首条 binary 消息上送，响应头在下发任务内自 ws
    /// 字节流读取（xray 服务端响应头随下发链路落线，先行阻塞等待会与
    /// 服务端等上行互挂——实测 Xray 1.8.24），随后分块流双向转发
    /// （ping→pong 与上行同 select）
    async fn relay_session_over_ws_with<R, W>(
        &self,
        flow: Flow,
        ws: super::ws::WsClient<R, W>,
        session: &mut VmessSession,
    ) -> Result<FlowReport>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let super::ws::WsClient { reader, writer } = ws;
        let mut ws_r = reader;
        let mut ws_w = writer;

        let (pong_tx, mut pong_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        ws_r.set_pong_sender(pong_tx);
        let expect_v = session.expect_v;
        let resp_keys = session.resp_header_keys.clone();

        let io = flow.io;
        let (mut client_r, mut client_w) = tokio::io::split(io);

        let req_crypt = &mut session.req_crypt;
        let resp_crypt = &mut session.resp_crypt;
        let sealed_header = std::mem::take(&mut session.sealed_header);

        // 请求头与首个数据块合入同一 binary 消息（xray 客户端同形——其 ws
        // 写面按 flush 聚合；实测 Xray 1.8.24 服务端对「头独占一条消息」
        // 的帧序不产出任何下行、上行分块也被弃读，头‖首块合帧即恢复）
        let up = async {
            let mut up: u64 = 0;
            let mut buf = vec![0u8; 16 * 1024];
            let mut first = Some(sealed_header);
            loop {
                tokio::select! {
                    biased;
                    Some(payload) = pong_rx.recv() => {
                        ws_w.write_pong(&payload).await?;
                    }
                    n = client_r.read(&mut buf) => {
                        let n = n?;
                        if n == 0 {
                            let mut msg = first.take().unwrap_or_default();
                            append_chunk(req_crypt, &[], &mut msg)?;
                            ws_w.write_binary(&msg).await?;
                            break;
                        }
                        match first.take() {
                            Some(header) => {
                                let mut msg = header;
                                append_chunk(req_crypt, &buf[..n], &mut msg)?;
                                ws_w.write_binary(&msg).await?;
                            }
                            None => {
                                write_chunk(req_crypt, &mut ws_w, &buf[..n]).await?;
                            }
                        }
                        up += n as u64;
                    }
                }
            }
            Ok::<u64, anyhow::Error>(up)
        };

        let down = async {
            let mut msg_r = WsMsgReader {
                inner: &mut ws_r,
                stash: Vec::new(),
            };
            read_response_header(&mut msg_r, expect_v, &resp_keys).await?;
            let mut down: u64 = 0;
            loop {
                let plain = read_chunk(resp_crypt, &mut msg_r).await?;
                if plain.is_empty() {
                    let _ = client_w.shutdown().await;
                    break;
                }
                client_w.write_all(&plain).await?;
                down += plain.len() as u64;
            }
            Ok::<u64, anyhow::Error>(down)
        };

        let (up, down) = tokio::try_join!(up, down)?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }

    /// gRPC 传输（隧道完成后的协议段；池/内联同参）——会话已由调用方构建
    async fn relay_session_over_grpc(
        &self,
        flow: Flow,
        tunnel: super::grpc::GrpcTunnel,
        session: &mut VmessSession,
    ) -> Result<FlowReport> {
        self.relay_session_over_grpc_with(flow, tunnel, session)
            .await
    }

    /// VMess over gRPC：头‖首块合入首条 gRPC 消息（xray ws 同形语义——
    /// 头独占一条消息服务端不产出下行，见 relay_session_over_ws_with 注）；
    /// 响应头在下发任务内经跨消息 read_exact 抽取，随后分块流双向转发；
    /// 上行 EOF → 终止块 + END_STREAM 收尾，下行至终止块关客户端写侧。
    async fn relay_session_over_grpc_with(
        &self,
        flow: Flow,
        tunnel: super::grpc::GrpcTunnel,
        session: &mut VmessSession,
    ) -> Result<FlowReport> {
        let (mut grpc_r, mut grpc_w) = tunnel.split();
        let expect_v = session.expect_v;
        let resp_keys = session.resp_header_keys.clone();
        let (mut client_r, mut client_w) = tokio::io::split(flow.io);

        let req_crypt = &mut session.req_crypt;
        let resp_crypt = &mut session.resp_crypt;
        let sealed_header = std::mem::take(&mut session.sealed_header);

        let up = async {
            let mut up: u64 = 0;
            let mut buf = vec![0u8; 16 * 1024];
            let mut first = Some(sealed_header);
            loop {
                let n = client_r.read(&mut buf).await?;
                if n == 0 {
                    // 终止块：无数据则头‖终止块合一条消息，否则独条
                    match first.take() {
                        Some(header) => {
                            let mut msg = header;
                            append_chunk(req_crypt, &[], &mut msg)?;
                            grpc_w.message(&msg).await?;
                        }
                        None => {
                            write_chunk(req_crypt, &mut grpc_w, &[]).await?;
                        }
                    }
                    grpc_w.finish().await?;
                    break;
                }
                match first.take() {
                    Some(header) => {
                        let mut msg = header;
                        append_chunk(req_crypt, &buf[..n], &mut msg)?;
                        grpc_w.message(&msg).await?;
                    }
                    None => {
                        write_chunk(req_crypt, &mut grpc_w, &buf[..n]).await?;
                    }
                }
                up += n as u64;
            }
            Ok::<u64, anyhow::Error>(up)
        };

        let down = async {
            read_response_header(&mut grpc_r, expect_v, &resp_keys).await?;
            let mut down: u64 = 0;
            loop {
                let plain = read_chunk(resp_crypt, &mut grpc_r).await?;
                if plain.is_empty() {
                    let _ = client_w.shutdown().await;
                    break;
                }
                client_w.write_all(&plain).await?;
                down += plain.len() as u64;
            }
            Ok::<u64, anyhow::Error>(down)
        };

        let (up, down) = tokio::try_join!(up, down)?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

/// 分块流双向转发（tcp/tls 流路径）：上行至客户端 EOF 发终止块；下行至
/// 终止块关客户端写侧。响应头在下发任务内先于首块读取——不得在上行
/// 启动前单独阻塞等它：xray 服务端响应头经写缓冲随下发链路落线
/// （inbound.Process 的 transferResponse），先读后发会与服务端等待
/// 上行互相挂死（实测 Xray 1.8.24 vmess+ws+tls）。
async fn relay_vmess_stream<R, W>(
    flow: Flow,
    mut rr: R,
    mut ww: W,
    req_crypt: &mut ChunkCrypt,
    resp_crypt: &mut ChunkCrypt,
    expect_v: u8,
    resp_keys: &RespHeaderKeys,
) -> Result<FlowReport>
where
    R: AsyncRead + Unpin + Send + ChunkRead,
    W: AsyncWrite + Unpin + Send + ChunkWrite,
{
    let (mut client_r, mut client_w) = tokio::io::split(flow.io);

    let up = async {
        let mut up: u64 = 0;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                write_chunk(req_crypt, &mut ww, &[]).await?;
                ww.finish().await?;
                break;
            }
            write_chunk(req_crypt, &mut ww, &buf[..n]).await?;
            up += n as u64;
        }
        Ok::<u64, anyhow::Error>(up)
    };

    let down = async {
        read_response_header(&mut rr, expect_v, resp_keys).await?;
        let mut down: u64 = 0;
        loop {
            let plain = read_chunk(resp_crypt, &mut rr).await?;
            if plain.is_empty() {
                let _ = client_w.shutdown().await;
                break;
            }
            client_w.write_all(&plain).await?;
            down += plain.len() as u64;
        }
        Ok::<u64, anyhow::Error>(down)
    };

    let (up, down) = tokio::try_join!(up, down)?;
    Ok(FlowReport {
        upstream: up,
        downstream: down,
    })
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use seep_core::{FlowId, FlowMetadata, FlowTarget};
    use sha1::{Digest as Sha1Digest, Sha1};
    use std::time::Duration;
    use tokio::{io::duplex, net::TcpListener};

    // ---- Go 真值向量（/tmp/vmessvec/main.go：xray kdf.go 原文 + 确定性
    //      seal，Go 1.27.1 本机实跑；路径序为真实协议调用形）----

    const TEST_UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";
    const KEY16: &[u8; 16] = b"0123456789abcdef";
    const IV16_HEX: &str = "00112233445566778899aabbccddeeff";

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn test_cmd_key() -> [u8; 16] {
        let id = Uuid::parse_str(TEST_UUID).unwrap();
        cmd_key_from_uuid(id.as_bytes())
    }

    #[test]
    fn kdf_vectors_match_go_truth() {
        let cmd_key = test_cmd_key();
        // V0 cmdKey = MD5(uuid ‖ 盐)
        assert_eq!(hex(&cmd_key), "9c91b4f8b72c6adcc5e0009f2c2ffd2d");
        // V1 authID 密钥（单路径）
        assert_eq!(
            hex(&vmess_kdf16(&cmd_key, &[S_AUTH_ID_KEY])),
            "9bc3d3b73e7b437cfd2ff43ba71d1e13"
        );

        // V2–V5 头部三路径（盐串, authID, connNonce——真实调用序）
        let auth_id = hx("0102030405060708090a0b0c0d0e0f10");
        let nonce = hx("f1f2f3f4f5f6f7f8");
        assert_eq!(
            hex(&vmess_kdf16(&cmd_key, &[S_HDR_LEN_KEY, &auth_id, &nonce])),
            "953c19fbf01d75d8d1d4a7354145ca67"
        );
        assert_eq!(
            hex(&kdf_nonce12(&cmd_key, &[S_HDR_LEN_IV, &auth_id, &nonce])),
            "d665efbffe173eff0c0f64a4"
        );
        assert_eq!(
            hex(&vmess_kdf16(&cmd_key, &[S_HDR_PAY_KEY, &auth_id, &nonce])),
            "c4edec1fe5d49286d64cee4727cae12e"
        );
        assert_eq!(
            hex(&kdf_nonce12(&cmd_key, &[S_HDR_PAY_IV, &auth_id, &nonce])),
            "aaa977f0dd59af5f1ae636fa"
        );

        // V6–V9 响应头单路径（respKey/respIV = SHA256 派生）
        let rk: [u8; 16] = Sha256::digest(KEY16)[..16].try_into().unwrap();
        let riv_full = Sha256::digest(hx(IV16_HEX));
        let riv: [u8; 16] = riv_full[..16].try_into().unwrap();
        assert_eq!(
            hex(&vmess_kdf16(&rk, &[S_RESP_LEN_KEY])),
            "9d8993dc0569c30ce5278827b18b4766"
        );
        assert_eq!(
            hex(&kdf_nonce12(&riv, &[S_RESP_LEN_IV])),
            "c4b361911422861107652f3c"
        );
        assert_eq!(
            hex(&vmess_kdf16(&rk, &[S_RESP_PAY_KEY])),
            "aca173f6e74c780644a299782a672f79"
        );
        assert_eq!(
            hex(&kdf_nonce12(&riv, &[S_RESP_PAY_IV])),
            "d2ad5f9c9b1c978a01e96640"
        );

        // V10 深递归（n=5）全 32 字节
        let out = vmess_kdf(KEY16, &[b"p1", b"p2", b"p3", b"p4", b"p5"]);
        assert_eq!(
            hex(&out),
            "d200d58c162a0d668e7aa63a1c621280affb70f0f61ad6534664ca09e3fe7914"
        );
    }

    #[test]
    fn chacha_key_derivation_matches_go_truth() {
        // V11 GenerateChacha20Poly1305Key：md5(k) ‖ md5(md5(k))
        let k1 = Md5::digest(KEY16);
        let k2 = Md5::digest(k1);
        let mut k32 = [0u8; 32];
        k32[..16].copy_from_slice(&k1);
        k32[16..].copy_from_slice(&k2);
        assert_eq!(
            hex(&k32),
            "4032af8d61035123906e58e067140cc567304ba676a616064c4340059e1b6370"
        );
    }

    #[test]
    fn shake_draws_match_go_truth() {
        // V16 SHAKE128(方向 IV) 前 16B 原始抽取（2B BE × 8；xray
        // NewShakeSizeParser 喂的是 bodyIV——旧向量误喂 key 作废）
        let iv16 = hx(IV16_HEX);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv16);
        let mut c = ChunkCrypt::new(VmessSecurity::Aes128Gcm, KEY16, &iv).unwrap();
        let expected = hx("20c2be80a64105b3481d90a6910e11f5");
        for pair in expected.chunks(2) {
            assert_eq!(c.shake_next(), u16::from_be_bytes([pair[0], pair[1]]));
        }
        // 抽取序：padding（%64）在 mask（全 16bit、无截断）之前
        let mut c2 = ChunkCrypt::new(VmessSecurity::Aes128Gcm, KEY16, &iv).unwrap();
        assert_eq!(c2.next_padding(), 0x20c2 % 64);
        assert_eq!(c2.next_mask(), 0xbe80);
    }

    #[test]
    fn request_header_bytes_match_go_truth() {
        // V12 确定性请求头明文（domain 形）+ V13 FNV1a32
        let req_iv = hx("101112131415161718191a1b1c1d1e1f");
        let req_key = hx("202122232425262728292a2b2c2d2e2f");
        let iv: [u8; 16] = req_iv.clone().try_into().unwrap();
        let key: [u8; 16] = req_key.clone().try_into().unwrap();
        let bytes = build_request_header_bytes(
            &iv,
            &key,
            0x42,
            &[0x77; 5],
            VmessSecurity::Aes128Gcm,
            "example.com",
            443,
        )
        .unwrap();
        assert_eq!(
            hex(&bytes),
            "01101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f420d53000101bb020b6578616d706c652e636f6d777777777719e40474"
        );
        assert_eq!(
            format!("{:08x}", fnv1a32(&bytes[..bytes.len() - 4])),
            "19e40474"
        );

        // IPv4 地址形（偏移构造性检查：[40]=类型 [41..45]=八位组）
        let v4 = build_request_header_bytes(
            &iv,
            &key,
            1,
            &[],
            VmessSecurity::Aes128Gcm,
            "127.0.0.1",
            80,
        )
        .unwrap();
        assert_eq!(&v4[40..45], &[0x01, 127, 0, 0, 1]);
    }

    #[test]
    fn sealed_header_matches_go_truth() {
        // V14/V15：确定性 authID + 全 seal（钉 authID 构造 + KDF 路径序 +
        // 两级 GCM 的 AAD 面——载荷块 AAD=authID，以 encrypt.go 原文移植的
        // Go 程序输出为准，`aad=lenSealed` 的旧向量作废）
        let req_iv = hx("101112131415161718191a1b1c1d1e1f");
        let req_key = hx("202122232425262728292a2b2c2d2e2f");
        let iv: [u8; 16] = req_iv.try_into().unwrap();
        let key: [u8; 16] = req_key.try_into().unwrap();
        let data = build_request_header_bytes(
            &iv,
            &key,
            0x42,
            &[0x77; 5],
            VmessSecurity::Aes128Gcm,
            "example.com",
            443,
        )
        .unwrap();
        let (sealed, auth_id) = seal_vmess_aead_header_det(
            &test_cmd_key(),
            &data,
            1_700_000_000,
            [0x01, 0x02, 0x03, 0x04],
            [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8],
        )
        .unwrap();
        assert_eq!(hex(&auth_id), "17fda34cc3f9a1049d54cc2877f42512");
        assert_eq!(
            hex(&sealed),
            "17fda34cc3f9a1049d54cc2877f425121e72cb76023105bb6069c9ea8660a46e212da1a2a3a4a5a6a7a873793ede7b9aabf66bf4a9e51b25d7b6874a66a21f0550111ebce1aeeedd6f84008903bcd2628f6cfa29ef4f11799ff00dd1bc04d6cae41d40e2871af16f22e7bdb57c9853fb1558bdef0829078d"
        );
    }

    #[test]
    fn security_parse_matrix() {
        assert_eq!(
            VmessSecurity::parse("auto").unwrap(),
            VmessSecurity::Aes128Gcm
        );
        assert_eq!(
            VmessSecurity::parse("aes-128-gcm").unwrap(),
            VmessSecurity::Aes128Gcm
        );
        assert_eq!(
            VmessSecurity::parse("chacha20-poly1305").unwrap(),
            VmessSecurity::Chacha20Poly1305
        );
        assert!(VmessSecurity::parse("none").is_err());
        assert!(VmessSecurity::parse("zero").is_err());
        assert!(VmessSecurity::parse("").is_err());
    }

    #[tokio::test]
    async fn chunk_duplex_roundtrip() {
        // 分块编解码回环（含终止块语义与 >16KiB 大块；两方向同 IV 独立态）
        let (x, y) = duplex(256 * 1024);
        let (xr, mut xw) = tokio::io::split(x);
        let (mut yr, yw) = tokio::io::split(y);
        drop((xr, yw));

        let mut ca = ChunkCrypt::new(VmessSecurity::Chacha20Poly1305, KEY16, &[7u8; 16]).unwrap();
        let mut cb = ChunkCrypt::new(VmessSecurity::Chacha20Poly1305, KEY16, &[7u8; 16]).unwrap();

        let payload: Vec<Vec<u8>> = vec![
            b"h".to_vec(),
            vec![9u8; 100],
            vec![7u8; 16 * 1024],
            vec![3u8; 40 * 1024],
        ];
        let payload_cloned = payload.clone();
        let writer = tokio::spawn(async move {
            for p in &payload_cloned {
                write_chunk(&mut ca, &mut xw, p).await.unwrap();
            }
            write_chunk(&mut ca, &mut xw, &[]).await.unwrap();
        });
        for p in &payload {
            let plain = read_chunk(&mut cb, &mut yr).await.unwrap();
            assert_eq!(plain, *p);
        }
        // 终止块
        let plain = read_chunk(&mut cb, &mut yr).await.unwrap();
        assert!(plain.is_empty());
        writer.await.unwrap();
    }

    // ---- 回环 echo 测试（测试侧独立实现 xray 服务端语义）----

    struct TestReqHeader {
        req_iv: [u8; 16],
        req_key: [u8; 16],
        expect_v: u8,
        option: u8,
        security: VmessSecurity,
    }

    fn parse_request_plain(plain: &[u8]) -> Result<TestReqHeader> {
        if plain.len() < 44 || plain[0] != 0x01 {
            return Err(anyhow!("请求头明文形不合法"));
        }
        // FNV 校验（末 4B）
        let n = plain.len();
        let expect = u32::from_be_bytes([plain[n - 4], plain[n - 3], plain[n - 2], plain[n - 1]]);
        assert_eq!(fnv1a32(&plain[..n - 4]), expect, "FNV 校验失败");

        let mut req_iv = [0u8; 16];
        let mut req_key = [0u8; 16];
        req_iv.copy_from_slice(&plain[1..17]);
        req_key.copy_from_slice(&plain[17..33]);
        let sec_byte = plain[35];
        let pad_len = (sec_byte >> 4) as usize;
        let security = match sec_byte & 0x0f {
            0x03 => VmessSecurity::Aes128Gcm,
            0x04 => VmessSecurity::Chacha20Poly1305,
            other => return Err(anyhow!("未知 security 字节: {other}")),
        };
        // 地址段跳过（[37]=cmd [38..40]=port [40]=addr type）
        let mut off = 40;
        match plain[off] {
            0x01 => off += 5,
            0x03 => off += 17,
            0x02 => off += 2 + plain[off + 1] as usize,
            other => return Err(anyhow!("未知地址类型: {other}")),
        }
        off += pad_len;
        assert_eq!(off, n - 4, "padding 段长度不符");
        Ok(TestReqHeader {
            req_iv,
            req_key,
            expect_v: plain[33],
            option: plain[34],
            security,
        })
    }

    /// 服务端响应头：[V 回声][option][cmd=1][cmdLen=0] 两级 GCM（AAD 空）
    fn build_response_header(req: &TestReqHeader) -> Result<Vec<u8>> {
        let keys = RespHeaderKeys::derive(&req.req_key, &req.req_iv);
        let payload = [req.expect_v, req.option, 0x01, 0x00];
        let len_aead = Aes128Gcm::new_from_slice(&keys.len_key).unwrap();
        let pay_aead = Aes128Gcm::new_from_slice(&keys.pay_key).unwrap();
        let sealed_len = len_aead
            .encrypt(Nonce::from_slice(&keys.len_nonce), &[0u8, 4][..])
            .unwrap();
        let sealed_pay = pay_aead
            .encrypt(Nonce::from_slice(&keys.pay_nonce), &payload[..])
            .unwrap();
        let mut out = Vec::with_capacity(18 + sealed_pay.len());
        out.extend_from_slice(&sealed_len);
        out.extend_from_slice(&sealed_pay);
        Ok(out)
    }

    async fn open_request_header_stream<S>(
        stream: &mut S,
        cmd_key: &[u8; 16],
    ) -> Result<TestReqHeader>
    where
        S: AsyncRead + Unpin,
    {
        let mut auth_id = [0u8; 16];
        let mut len_sealed = [0u8; 18];
        let mut conn_nonce = [0u8; 8];
        stream.read_exact(&mut auth_id).await?;
        stream.read_exact(&mut len_sealed).await?;
        stream.read_exact(&mut conn_nonce).await?;

        let len_key = vmess_kdf16(cmd_key, &[S_HDR_LEN_KEY, &auth_id, &conn_nonce]);
        let len_nonce = kdf_nonce12(cmd_key, &[S_HDR_LEN_IV, &auth_id, &conn_nonce]);
        let len_aead = Aes128Gcm::new_from_slice(&len_key)?;
        let len_plain = len_aead
            .decrypt(
                Nonce::from_slice(&len_nonce),
                Payload {
                    msg: &len_sealed,
                    aad: &auth_id,
                },
            )
            .map_err(|_| anyhow!("长度块开封失败"))?;
        let pay_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

        let mut pay_sealed = vec![0u8; pay_len + 16];
        stream.read_exact(&mut pay_sealed).await?;
        let pay_key = vmess_kdf16(cmd_key, &[S_HDR_PAY_KEY, &auth_id, &conn_nonce]);
        let pay_nonce = kdf_nonce12(cmd_key, &[S_HDR_PAY_IV, &auth_id, &conn_nonce]);
        let pay_aead = Aes128Gcm::new_from_slice(&pay_key)?;
        let plain = pay_aead
            .decrypt(
                Nonce::from_slice(&pay_nonce),
                Payload {
                    msg: &pay_sealed,
                    aad: &auth_id,
                },
            )
            .map_err(|_| anyhow!("头块开封失败"))?;
        parse_request_plain(&plain)
    }

    async fn serve_vmess_tcp<S>(mut stream: S, cmd_key: [u8; 16]) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let req = open_request_header_stream(&mut stream, &cmd_key).await?;
        stream.write_all(&build_response_header(&req)?).await?;
        stream.flush().await?;

        // 分块 echo（上行解密态 → 下行加密态）
        let mut up = ChunkCrypt::new(req.security, &req.req_key, &req.req_iv)?;
        let mut down = ChunkCrypt::derive_response(req.security, &req.req_key, &req.req_iv)?;
        loop {
            let plain = read_chunk(&mut up, &mut StreamSrc(&mut stream)).await?;
            if plain.is_empty() {
                break;
            }
            write_chunk(&mut down, &mut StreamSink(&mut stream), &plain).await?;
        }
        write_chunk(&mut down, &mut StreamSink(&mut stream), &[]).await?;
        Ok(())
    }

    fn test_connector(port: u16, network: &str) -> VmessConnector {
        VmessConnector::new(
            "127.0.0.1".to_string(),
            port,
            TEST_UUID.to_string(),
            0,
            VmessSecurity::Aes128Gcm,
            network.to_string(),
            Some("/ws".to_string()),
            None,
            None,
            false,
            false,
            None,
            None,
            TlsFingerprint::None,
            None,
            None,
        )
    }

    fn test_flow(io: tokio::io::DuplexStream) -> Flow {
        Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(io),
            metadata: FlowMetadata::default(),
        }
    }

    /// 驱动端：写读两轮（小 + >16KiB）后 EOF；与 forward 并发跑
    async fn drive_echo(mut io: tokio::io::DuplexStream) {
        io.write_all(b"hello vmess").await.unwrap();
        let mut buf = [0u8; 11];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello vmess");

        let big = vec![7u8; 40 * 1024];
        io.write_all(&big).await.unwrap();
        let mut rb = vec![0u8; big.len()];
        io.read_exact(&mut rb).await.unwrap();
        assert_eq!(rb, big);
    }

    async fn run_echo_test(network: &str) -> FlowReport {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cmd_key = test_cmd_key();
        let is_ws = network == "ws";
        tokio::spawn(async move {
            while let Ok((st, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let res = if is_ws {
                        serve_vmess_ws(st, cmd_key).await
                    } else {
                        serve_vmess_tcp(st, cmd_key).await
                    };
                    if let Err(e) = res {
                        eprintln!("测试服务端错误: {e:#}");
                    }
                });
            }
        });

        let (client_io, test_end) = duplex(256 * 1024);
        let connector = test_connector(port, network);
        let fwd = connector.forward(test_flow(client_io));
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(fwd, drive_echo(test_end))
        })
        .await
        .expect("回环超时");
        let (report, ()) = outcome;
        report.expect("forward 失败")
    }

    #[tokio::test]
    async fn echo_loopback_tcp() {
        let report = run_echo_test("tcp").await;
        assert!(report.upstream >= 40 * 1024 + 11);
        assert!(report.downstream >= 40 * 1024 + 11);
    }

    #[tokio::test]
    async fn echo_loopback_ws() {
        let report = run_echo_test("ws").await;
        assert!(report.upstream >= 40 * 1024 + 11);
        assert!(report.downstream >= 40 * 1024 + 11);
    }

    #[tokio::test]
    async fn wrong_uuid_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // 服务端持另一把 uuid 的 cmdKey —— 客户端响应头开封必败；
        // 服务端解密失败断连 → 客户端 bind 失败 → stale 重拨 → 二次失败 Err
        let other = cmd_key_from_uuid(&[0xffu8; 16]);
        tokio::spawn(async move {
            while let Ok((st, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = serve_vmess_tcp(st, other).await;
                });
            }
        });

        let (client_io, test_end) = duplex(64 * 1024);
        drop(test_end);
        let connector = test_connector(port, "tcp");
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            connector.forward(test_flow(client_io)),
        )
        .await
        .expect("回环超时");
        assert!(res.is_err(), "错误 uuid 必须被拒绝");
    }

    #[test]
    fn connector_rejects_alter_id() {
        let c = VmessConnector::new(
            "127.0.0.1".to_string(),
            1,
            TEST_UUID.to_string(),
            64,
            VmessSecurity::Aes128Gcm,
            "tcp".to_string(),
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            TlsFingerprint::None,
            None,
            None,
        );
        assert!(c.session("example.com", 443).is_err());
    }

    // ---- 测试侧 ws 服务端（服务端帧不带掩码；独立消息缓冲解析）----

    async fn ws_srv_handshake<S>(mut s: S) -> Result<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("ws 握手中连接关闭");
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let key = text
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("sec-websocket-key")
                    .then(|| v.trim().to_string())
            })
            .ok_or_else(|| anyhow!("ws 握手缺 Sec-WebSocket-Key"))?;
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(super::super::ws::WS_MAGIC.as_bytes());
        let accept = BASE64.encode(hasher.finalize());
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        s.write_all(resp.as_bytes()).await?;
        s.flush().await?;
        Ok(s)
    }

    async fn ws_srv_read_frame<S>(s: &mut S) -> Result<Option<(bool, u8, Vec<u8>)>>
    where
        S: AsyncRead + Unpin,
    {
        let mut h = [0u8; 2];
        match s.read_exact(&mut h).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let fin = h[0] & 0x80 != 0;
        let opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut e = [0u8; 2];
            s.read_exact(&mut e).await?;
            len = u16::from_be_bytes(e) as usize;
        } else if len == 127 {
            let mut e = [0u8; 8];
            s.read_exact(&mut e).await?;
            len = u64::from_be_bytes(e) as usize;
        }
        let mut mask = [0u8; 4];
        if masked {
            s.read_exact(&mut mask).await?;
        }
        let mut p = vec![0u8; len];
        s.read_exact(&mut p).await?;
        if masked {
            for (i, b) in p.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Ok(Some((fin, opcode, p)))
    }

    /// 一条完整 binary 消息（continuation 拼接）；None = close
    async fn ws_srv_read_message<S>(s: &mut S) -> Result<Option<Vec<u8>>>
    where
        S: AsyncRead + Unpin,
    {
        let mut acc = Vec::new();
        loop {
            let Some((fin, op, p)) = ws_srv_read_frame(s).await? else {
                return Ok(None);
            };
            match op {
                0x8 => return Ok(None),
                0x2 | 0x0 => {
                    acc.extend_from_slice(&p);
                    if fin {
                        return Ok(Some(acc));
                    }
                }
                _ => {}
            }
        }
    }

    async fn ws_srv_write_frame<S>(s: &mut S, opcode: u8, p: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut out = Vec::with_capacity(p.len() + 10);
        out.push(0x80 | opcode);
        if p.len() <= 125 {
            out.push(p.len() as u8);
        } else if p.len() <= 65535 {
            out.push(126);
            out.extend_from_slice(&(p.len() as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(p.len() as u64).to_be_bytes());
        }
        out.extend_from_slice(p);
        s.write_all(&out).await?;
        s.flush().await?;
        Ok(())
    }

    struct WsSrvWriter<'a, S>(&'a mut S);

    #[async_trait]
    impl<S: AsyncWrite + Unpin + Send> ChunkWrite for WsSrvWriter<'_, S> {
        async fn put(&mut self, data: &[u8]) -> Result<()> {
            ws_srv_write_frame(self.0, 0x2, data).await
        }

        async fn finish(&mut self) -> Result<()> {
            Ok(())
        }
    }

    async fn serve_vmess_ws<S>(stream: S, cmd_key: [u8; 16]) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut s = ws_srv_handshake(stream).await?;
        let mut buf: Vec<u8> = Vec::new();

        async fn ensure<S>(s: &mut S, buf: &mut Vec<u8>, n: usize) -> Result<()>
        where
            S: AsyncRead + Unpin,
        {
            while buf.len() < n {
                match ws_srv_read_message(s).await? {
                    Some(m) => buf.extend_from_slice(&m),
                    None => anyhow::bail!("ws 已关闭"),
                }
            }
            Ok(())
        }

        // 请求头封套（16+18+8）从消息缓冲开封
        ensure(&mut s, &mut buf, 42).await?;
        let auth_id: [u8; 16] = buf[..16].try_into().unwrap();
        let len_sealed: [u8; 18] = buf[16..34].try_into().unwrap();
        let conn_nonce: [u8; 8] = buf[34..42].try_into().unwrap();
        buf.drain(..42);
        let len_key = vmess_kdf16(&cmd_key, &[S_HDR_LEN_KEY, &auth_id, &conn_nonce]);
        let len_nonce = kdf_nonce12(&cmd_key, &[S_HDR_LEN_IV, &auth_id, &conn_nonce]);
        let len_aead = Aes128Gcm::new_from_slice(&len_key)?;
        let len_plain = len_aead
            .decrypt(
                Nonce::from_slice(&len_nonce),
                Payload {
                    msg: &len_sealed,
                    aad: &auth_id,
                },
            )
            .map_err(|_| anyhow!("长度块开封失败"))?;
        let pay_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        ensure(&mut s, &mut buf, pay_len + 16).await?;
        let pay_sealed: Vec<u8> = buf.drain(..pay_len + 16).collect();
        let pay_key = vmess_kdf16(&cmd_key, &[S_HDR_PAY_KEY, &auth_id, &conn_nonce]);
        let pay_nonce = kdf_nonce12(&cmd_key, &[S_HDR_PAY_IV, &auth_id, &conn_nonce]);
        let pay_aead = Aes128Gcm::new_from_slice(&pay_key)?;
        let plain = pay_aead
            .decrypt(
                Nonce::from_slice(&pay_nonce),
                Payload {
                    msg: &pay_sealed,
                    aad: &auth_id,
                },
            )
            .map_err(|_| anyhow!("头块开封失败"))?;
        let req = parse_request_plain(&plain)?;

        // 响应头一帧写回
        ws_srv_write_frame(&mut s, 0x2, &build_response_header(&req)?).await?;

        // 分块 echo（从消息缓冲独立解析——与客户端读序对拍）
        let mut up = ChunkCrypt::new(req.security, &req.req_key, &req.req_iv)?;
        let mut down = ChunkCrypt::derive_response(req.security, &req.req_key, &req.req_iv)?;
        loop {
            ensure(&mut s, &mut buf, 2).await?;
            let padding = up.next_padding();
            let mask = up.next_mask();
            let size = u16::from_be_bytes([buf[0], buf[1]]) ^ mask;
            buf.drain(..2);
            if size == 16 + padding {
                break;
            }
            ensure(&mut s, &mut buf, size as usize).await?;
            let body: Vec<u8> = buf.drain(..size as usize).collect();
            let plain_len = size as usize - padding as usize - 16;
            let nonce = up.next_nonce();
            let chunk_plain = up.aead.open(&nonce, &body[..plain_len + 16])?;
            write_chunk(&mut down, &mut WsSrvWriter(&mut s), &chunk_plain).await?;
        }
        write_chunk(&mut down, &mut WsSrvWriter(&mut s), &[]).await?;
        Ok(())
    }
}
