//! ShadowsocksR (SSR) 出口连接器实现（RIL-115，第一段：TCP 客户端面）
//!
//! 真源 = breakwa11 本人 manyuser 分支（Apache-2.0 参考实现，证据链见
//! `protocol-backends.md#shadowsocksr`）：
//! `shadowsocks/encrypt.py`（EVP_BytesToKey-MD5 流密码 + 流式 IV 发射/消费）、
//! `obfsplugin/auth.py` 的 `auth_aes128_sha1` 类（`auth_aes128_md5` /
//! `auth_aes128_sha1` 两个 method 同类共用，salt/哈希函数不同）、
//! `obfsplugin/http_simple.py`（GET 伪装）。
//!
//! 本文件为自写面，逐字节镜像上述参考；GPL C 源未读未派生。
//! 对端验收 = 本机 GPL ssr-server 进程（屋外进程黑盒，mieru/mita 先例）。
//!
//! 首段范围（见 todo.md RIL-115）：
//! - 流密码：aes-128/192/256-cfb、aes-128/192/256-ctr、chacha20-ietf、rc4-md5
//! - 协议：auth_aes128_md5 / auth_aes128_sha1（auth_aes128_sha1 类）
//! - 混淆：plain、http_simple
//! - 未交付（后段）：tls1.2_ticket_auth、auth_chain_a/b、auth_sha1_v4、
//!   UDP 面、服务端面。

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use md5::Digest as _;
use rand::{Rng, RngCore};
use rillane_core::{EgressConnector, Flow, FlowReport};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

// ---------------------------------------------------------------------------
// 通用工具：EVP_BytesToKey（count=1，MD5 链）与 HMAC
// ---------------------------------------------------------------------------

/// `EVP_BytesToKey`（OpenSSL count=1 口径，参考 `encrypt.py::EVP_BytesToKey`）：
/// m[0]=MD5(pw)，m[i]=MD5(m[i-1]+pw)，直到 `key_len+iv_len` 字节；
/// key=ms[..key_len]，iv=ms[key_len..key_len+iv_len]。
pub fn evp_bytes_to_key_md5(password: &[u8], key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let need = key_len + iv_len;
    let mut ms: Vec<u8> = Vec::with_capacity(need);
    let mut prev: Option<Vec<u8>> = None;
    let mut i: usize = 0;
    while ms.len() < need {
        let mut data: Vec<u8> = Vec::new();
        if i > 0 {
            data.extend_from_slice(prev.as_ref().expect("first block always set"));
        }
        data.extend_from_slice(password);
        let digest = md5::Md5::digest(&data);
        ms.extend_from_slice(&digest);
        prev = Some(digest.to_vec());
        i += 1;
    }
    let key = ms[..key_len].to_vec();
    let iv = ms[key_len..key_len + iv_len].to_vec();
    (key, iv)
}

/// 协议哈希函数种类（决定 salt 与 HMAC 面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Md5,
    Sha1,
}

impl HashKind {
    /// 协议 salt（`auth_aes128_md5` → `b"auth_aes128_md5"`，14B；
    /// `auth_aes128_sha1` → `b"auth_aes128_sha1"`，15B）。
    pub fn salt(self) -> &'static [u8] {
        match self {
            HashKind::Md5 => b"auth_aes128_md5",
            HashKind::Sha1 => b"auth_aes128_sha1",
        }
    }

    /// HMAC（`hmac` 0.12；HMAC 允许任意长度 key，构造不会失败）。
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::Mac as _;
        match self {
            HashKind::Md5 => {
                use md5::Md5;
                let mut mac = hmac::Hmac::<Md5>::new_from_slice(key).expect("hmac md5 key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HashKind::Sha1 => {
                use sha1::Sha1;
                let mut mac = hmac::Hmac::<Sha1>::new_from_slice(key).expect("hmac sha1 key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// 消息摘要（rc4-md5 的 RC4 密钥、auth user_key 派生用）。
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Md5 => md5::Md5::digest(data).to_vec(),
            HashKind::Sha1 => sha1::Sha1::digest(data).to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// 流密码（legacy，EVP_BytesToKey-MD5 派钥；参考 encrypt.py + crypto/）
// ---------------------------------------------------------------------------

/// 流密码种类（第一段范围；`encrypt.py` 的 ciphers 表 + `crypto/` 实现）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrCipher {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Chacha20Ietf,
    Rc4Md5,
}

impl SsrCipher {
    /// 按 method 名解析（配置面口径）。
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "aes-128-cfb" => SsrCipher::Aes128Cfb,
            "aes-192-cfb" => SsrCipher::Aes192Cfb,
            "aes-256-cfb" => SsrCipher::Aes256Cfb,
            "aes-128-ctr" => SsrCipher::Aes128Ctr,
            "aes-192-ctr" => SsrCipher::Aes192Ctr,
            "aes-256-ctr" => SsrCipher::Aes256Ctr,
            "chacha20-ietf" => SsrCipher::Chacha20Ietf,
            "rc4-md5" => SsrCipher::Rc4Md5,
            _ => return None,
        })
    }

    pub fn key_len(self) -> usize {
        match self {
            SsrCipher::Aes128Cfb | SsrCipher::Aes128Ctr | SsrCipher::Rc4Md5 => 16,
            SsrCipher::Aes192Cfb | SsrCipher::Aes192Ctr => 24,
            SsrCipher::Aes256Cfb | SsrCipher::Aes256Ctr | SsrCipher::Chacha20Ietf => 32,
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            SsrCipher::Chacha20Ietf => 12,
            _ => 16,
        }
    }
}

/// 对称流密码（CFB 之外的三类，加密解密同一 apply_keystream）。
enum SymCipher {
    Ctr128(ctr::Ctr128BE<aes::Aes128>),
    Ctr192(ctr::Ctr128BE<aes::Aes192>),
    Ctr256(ctr::Ctr128BE<aes::Aes256>),
    ChaCha20(chacha20::ChaCha20),
    Rc4(rc4::Rc4<rc4::consts::U16>),
}

impl SymCipher {
    fn apply_keystream(&mut self, buf: &mut [u8]) {
        use cfb_mode::cipher::StreamCipher as _;
        match self {
            SymCipher::Ctr128(c) => c.apply_keystream(buf),
            SymCipher::Ctr192(c) => c.apply_keystream(buf),
            SymCipher::Ctr256(c) => c.apply_keystream(buf),
            SymCipher::ChaCha20(c) => c.apply_keystream(buf),
            SymCipher::Rc4(c) => c.apply_keystream(buf),
        }
    }
}

/// 加密方向状态。
enum CipherEnc {
    Aes128Cfb(cfb_mode::BufEncryptor<aes::Aes128>),
    Aes192Cfb(cfb_mode::BufEncryptor<aes::Aes192>),
    Aes256Cfb(cfb_mode::BufEncryptor<aes::Aes256>),
    Sym(SymCipher),
}

impl CipherEnc {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            CipherEnc::Aes128Cfb(c) => c.encrypt(buf),
            CipherEnc::Aes192Cfb(c) => c.encrypt(buf),
            CipherEnc::Aes256Cfb(c) => c.encrypt(buf),
            CipherEnc::Sym(s) => s.apply_keystream(buf),
        }
    }
}

/// 解密方向状态。
enum CipherDec {
    Aes128Cfb(cfb_mode::BufDecryptor<aes::Aes128>),
    Aes192Cfb(cfb_mode::BufDecryptor<aes::Aes192>),
    Aes256Cfb(cfb_mode::BufDecryptor<aes::Aes256>),
    Sym(SymCipher),
}

impl CipherDec {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            CipherDec::Aes128Cfb(c) => c.decrypt(buf),
            CipherDec::Aes192Cfb(c) => c.decrypt(buf),
            CipherDec::Aes256Cfb(c) => c.decrypt(buf),
            CipherDec::Sym(s) => s.apply_keystream(buf),
        }
    }
}

/// 构建加密方向（参考 `Encryptor.__init__`：rc4-md5 的 RC4 key=MD5(key+iv)）。
fn build_enc(kind: SsrCipher, key: &[u8], iv: &[u8]) -> Result<CipherEnc> {
    use aes::cipher::KeyIvInit as _;
    use rc4::KeyInit as _;
    let k = |t: &str| anyhow!("SSR 密码流密码初始化失败: {t}");
    Ok(match kind {
        SsrCipher::Aes128Cfb => CipherEnc::Aes128Cfb(
            cfb_mode::BufEncryptor::new_from_slices(key, iv).map_err(|_| k("aes-128-cfb"))?,
        ),
        SsrCipher::Aes192Cfb => CipherEnc::Aes192Cfb(
            cfb_mode::BufEncryptor::new_from_slices(key, iv).map_err(|_| k("aes-192-cfb"))?,
        ),
        SsrCipher::Aes256Cfb => CipherEnc::Aes256Cfb(
            cfb_mode::BufEncryptor::new_from_slices(key, iv).map_err(|_| k("aes-256-cfb"))?,
        ),
        SsrCipher::Aes128Ctr => CipherEnc::Sym(SymCipher::Ctr128(
            ctr::Ctr128BE::new_from_slices(key, iv).map_err(|_| k("aes-128-ctr"))?,
        )),
        SsrCipher::Aes192Ctr => CipherEnc::Sym(SymCipher::Ctr192(
            ctr::Ctr128BE::new_from_slices(key, iv).map_err(|_| k("aes-192-ctr"))?,
        )),
        SsrCipher::Aes256Ctr => CipherEnc::Sym(SymCipher::Ctr256(
            ctr::Ctr128BE::new_from_slices(key, iv).map_err(|_| k("aes-256-ctr"))?,
        )),
        SsrCipher::Chacha20Ietf => CipherEnc::Sym(SymCipher::ChaCha20(
            chacha20::ChaCha20::new_from_slices(key, iv).map_err(|_| k("chacha20-ietf"))?,
        )),
        SsrCipher::Rc4Md5 => {
            let rc4key = md5::Md5::digest([key, iv].concat());
            CipherEnc::Sym(SymCipher::Rc4(
                rc4::Rc4::new_from_slice(&rc4key).map_err(|_| k("rc4-md5"))?,
            ))
        }
    })
}

/// 构建解密方向（rc4-md5 的 RC4 key=MD5(key+iv)，iv=线首消费的 cipher_iv）。
fn build_dec(kind: SsrCipher, key: &[u8], iv: &[u8]) -> Result<CipherDec> {
    use aes::cipher::KeyIvInit as _;
    use rc4::KeyInit as _;
    let k = |t: &str| anyhow!("SSR 密码流密码初始化失败: {t}");
    Ok(match kind {
        SsrCipher::Aes128Cfb => CipherDec::Aes128Cfb(
            cfb_mode::BufDecryptor::new_from_slices(key, iv).map_err(|_| k("aes-128-cfb"))?,
        ),
        SsrCipher::Aes192Cfb => CipherDec::Aes192Cfb(
            cfb_mode::BufDecryptor::new_from_slices(key, iv).map_err(|_| k("aes-192-cfb"))?,
        ),
        SsrCipher::Aes256Cfb => CipherDec::Aes256Cfb(
            cfb_mode::BufDecryptor::new_from_slices(key, iv).map_err(|_| k("aes-256-cfb"))?,
        ),
        SsrCipher::Aes128Ctr => CipherDec::Sym(SymCipher::Ctr128(
            ctr::Ctr128BE::new_from_slices(key, iv).map_err(|_| k("aes-128-ctr"))?,
        )),
        SsrCipher::Aes192Ctr => CipherDec::Sym(SymCipher::Ctr192(
            ctr::Ctr128BE::new_from_slices(key, iv).map_err(|_| k("aes-192-ctr"))?,
        )),
        SsrCipher::Aes256Ctr => CipherDec::Sym(SymCipher::Ctr256(
            ctr::Ctr128BE::new_from_slices(key, iv).map_err(|_| k("aes-256-ctr"))?,
        )),
        SsrCipher::Chacha20Ietf => CipherDec::Sym(SymCipher::ChaCha20(
            chacha20::ChaCha20::new_from_slices(key, iv).map_err(|_| k("chacha20-ietf"))?,
        )),
        SsrCipher::Rc4Md5 => {
            let rc4key = md5::Md5::digest([key, iv].concat());
            CipherDec::Sym(SymCipher::Rc4(
                rc4::Rc4::new_from_slice(&rc4key).map_err(|_| k("rc4-md5"))?,
            ))
        }
    })
}

/// 流密码双向状态（参考 `Encryptor`：encrypt 首调发射每连接随机
/// cipher_iv；decrypt 消费线首对端 cipher_iv 后初始化 decipher）。
pub struct SsrCipherState {
    kind: SsrCipher,
    key: Vec<u8>,
    iv: Vec<u8>,
    enc: Option<CipherEnc>,
    dec: Option<CipherDec>,
    iv_sent: bool,
    /// decrypt 侧 IV 消费缓冲（参考 `Encryptor.iv_buf`）。
    dec_buf: Vec<u8>,
}

impl SsrCipherState {
    pub fn new(kind: SsrCipher, key: Vec<u8>, iv: Vec<u8>) -> Self {
        let enc = Some(build_enc(kind, &key, &iv).expect("build enc"));
        Self {
            kind,
            key,
            iv,
            enc,
            dec: None,
            iv_sent: false,
            dec_buf: Vec::new(),
        }
    }

    /// 加密：首调在明文密文前发射 `cipher_iv`（每连接随机，见 `SsrEngine::new`）。
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() + 16);
        if !self.iv_sent {
            out.extend_from_slice(&self.iv);
            self.iv_sent = true;
        }
        let mut ct = data.to_vec();
        self.enc.as_mut().expect("enc").apply(&mut ct);
        out.extend(ct);
        Ok(out)
    }

    /// 解密：消费线首 `iv_len` 字节作 decipher IV，随后流式解密。
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.dec.is_none() {
            self.dec_buf.extend_from_slice(data);
            let iv_len = self.kind.iv_len();
            if self.dec_buf.len() <= iv_len {
                return Ok(Vec::new());
            }
            let iv: Vec<u8> = self.dec_buf[..iv_len].to_vec();
            self.dec_buf.drain(..iv_len);
            self.dec = Some(build_dec(self.kind, &self.key, &iv)?);
            // 首段只解 iv 之后的残余；data 不能再拼进来（iv 已从中剥除）
            let mut pt = std::mem::take(&mut self.dec_buf);
            self.dec.as_mut().expect("dec").apply(&mut pt);
            return Ok(pt);
        }
        let mut pt = data.to_vec();
        self.dec.as_mut().expect("dec").apply(&mut pt);
        Ok(pt)
    }
}

// ---------------------------------------------------------------------------
// 协议：auth_aes128_md5 / auth_aes128_sha1（auth.py 的 auth_aes128_sha1 类）
// ---------------------------------------------------------------------------

/// SSR 目标地址头长度（`plain.py::get_head_size` 口径）。
pub fn get_head_size(buf: &[u8], def: usize) -> usize {
    if buf.len() < 2 {
        return def;
    }
    match buf[0] & 0x7 {
        1 => 7,
        4 => 19,
        3 => 4 + buf[1] as usize,
        _ => def,
    }
}

/// 构造 SSR 目标地址头（ATYP+ADDR+PORT，参考 tcprelay 客户端 `parse_header`）。
pub fn build_ssr_head(host: &str, port: u16) -> Result<Vec<u8>> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let mut h = vec![1u8];
        h.extend_from_slice(&ip.octets());
        h.extend_from_slice(&port.to_be_bytes());
        return Ok(h);
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        let mut h = vec![4u8];
        h.extend_from_slice(&ip.octets());
        h.extend_from_slice(&port.to_be_bytes());
        return Ok(h);
    }
    let d = host.as_bytes();
    if d.is_empty() || d.len() > 255 {
        bail!("SSR 目标域名长度非法: {host}");
    }
    let mut h = vec![3u8, d.len() as u8];
    h.extend_from_slice(d);
    h.extend_from_slice(&port.to_be_bytes());
    Ok(h)
}

/// 参考 `tcprelay.TCP_MSS`：NETWORK_MTU-40 = 1460（客户端缺省口径）。
const TCP_MSS: usize = 1460;
/// 参考 `tcprelay.BUF_SIZE - overhead`：32768-9（auth_aes128 面 overhead=9）。
const RECV_BUFFER_SIZE: usize = 32759;

/// auth_aes128_sha1 类客户端状态（参考 auth.py 440-626 行）。
pub struct AuthClient {
    hash: HashKind,
    salt: &'static [u8],
    unit_len: usize,
    has_sent_header: bool,
    pack_id: u32,
    recv_id: u32,
    /// 用户密钥（pack_auth_data 首调定，未设则回落 cipher_key）。
    user_key: Option<Vec<u8>>,
    /// client_post_decrypt 帧缓冲。
    recv_buf: Vec<u8>,
    local_client_id: Vec<u8>,
    connection_id: u32,
    /// server_info 面：cipher_iv + cipher_key（pack_auth_data 的 mac_key）。
    iv: Vec<u8>,
    key: Vec<u8>,
    protocol_param: Vec<u8>,
}

impl AuthClient {
    pub fn new(hash: HashKind, iv: Vec<u8>, key: Vec<u8>, protocol_param: Vec<u8>) -> Self {
        Self {
            hash,
            salt: hash.salt(),
            unit_len: 8100,
            has_sent_header: false,
            pack_id: 1,
            recv_id: 1,
            user_key: None,
            recv_buf: Vec::new(),
            local_client_id: Vec::new(),
            connection_id: 0,
            iv,
            key,
            protocol_param,
        }
    }

    /// trapezoid_random_float（参考 auth.py 490-495）。
    fn trapezoid_random_float(&self, rng: &mut dyn RngCore, d: f64) -> f64 {
        if d == 0.0 {
            return rng.gen::<f64>();
        }
        let s: f64 = rng.gen::<f64>();
        let a = 1.0 - d;
        ((a * a + 4.0 * d * s).sqrt() - a) / (2.0 * d)
    }

    fn trapezoid_random_int(&self, rng: &mut dyn RngCore, max_val: i64, d: f64) -> i64 {
        let v = self.trapezoid_random_float(rng, d);
        (v * max_val as f64) as i64
    }

    /// rnd_data_len（参考 auth.py 501-514，端序与端点已逐行核对）。
    fn rnd_data_len(&self, rng: &mut dyn RngCore, buf_size: usize, full_buf_size: usize) -> i64 {
        if full_buf_size >= RECV_BUFFER_SIZE {
            return 0;
        }
        let rev_len = TCP_MSS as i64 - buf_size as i64 - 9;
        if rev_len == 0 {
            return 0;
        }
        if rev_len < 0 {
            if rev_len > -(TCP_MSS as i64) {
                return self.trapezoid_random_int(rng, rev_len + TCP_MSS as i64, -0.3);
            }
            return (rng.gen::<u8>() as i64) % 32;
        }
        if buf_size > 900 {
            let mut b = [0u8; 2];
            rng.fill_bytes(&mut b);
            return (u16::from_be_bytes(b) as i64) % rev_len;
        }
        self.trapezoid_random_int(rng, rev_len, -0.3)
    }

    /// rnd_data（参考 auth.py 516-522）。
    fn rnd_data(&self, rng: &mut dyn RngCore, buf_size: usize, full_buf_size: usize) -> Vec<u8> {
        let data_len = self.rnd_data_len(rng, buf_size, full_buf_size);
        if data_len < 128 {
            let mut out = vec![(data_len + 1) as u8];
            let mut rnd = vec![0u8; data_len as usize];
            rng.fill_bytes(&mut rnd);
            out.extend(rnd);
            return out;
        }
        let mut out = vec![255u8];
        out.extend_from_slice(&((data_len + 1) as u16).to_le_bytes());
        let mut rnd = vec![0u8; (data_len - 2) as usize];
        rng.fill_bytes(&mut rnd);
        out.extend(rnd);
        out
    }

    /// pack_data（参考 auth.py 524-532；确定性核心，padding 为调用方注入的
    /// rnd_data 输出，便于字节级向量测试）。
    fn pack_data_inner(&self, buf: &[u8], padding: &[u8]) -> Vec<u8> {
        let mut data: Vec<u8> = padding.to_vec();
        data.extend_from_slice(buf);
        let data_len = (data.len() + 8) as u16;
        let mut mac_key: Vec<u8> = self.user_key.clone().expect("user_key set").to_vec();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        let mac = self.hash.hmac(&mac_key, &data_len.to_le_bytes());
        let mut frame: Vec<u8> = data_len.to_le_bytes().to_vec();
        frame.extend_from_slice(&mac[..2]);
        frame.extend(data);
        let trailer = self.hash.hmac(&mac_key, &frame);
        frame.extend_from_slice(&trailer[..4]);
        frame
    }

    fn pack_data(&mut self, rng: &mut dyn RngCore, buf: &[u8], full_buf_size: usize) -> Vec<u8> {
        let padding = self.rnd_data(rng, buf.len(), full_buf_size);
        let frame = self.pack_data_inner(buf, &padding);
        self.pack_id = self.pack_id.wrapping_add(1);
        frame
    }

    /// pack_auth_data 确定性核心（参考 auth.py 534-562；随机量：rnd_len、uid、
    /// check_head 首字节、rnd 填充，均由调用方注入）。
    fn pack_auth_data_inner(
        &self,
        auth_data: &[u8],
        buf: &[u8],
        rnd_len: usize,
        uid: &[u8],
        check_head_byte: u8,
        rnd_pad: &[u8],
    ) -> Vec<u8> {
        // data = auth_data(12) + data_len(2) + rnd_len(2) = 16B
        let data_len = (7 + 4 + 16 + 4 + buf.len() + rnd_len + 4) as u16;
        let mut data = auth_data.to_vec();
        data.extend_from_slice(&data_len.to_le_bytes());
        data.extend_from_slice(&(rnd_len as u16).to_le_bytes());

        // AES-128-CBC 单块（streaming 无 padding，EVP_CipherUpdate-only）：
        // key = EVP_BytesToKey(b64(user_key)+salt, 16, 16).key = MD5(b64+salt)；
        // iv = 16 个 0（Encryptor 显式传入的 zeros iv）
        let user_key = self.user_key.clone().expect("user_key set");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&user_key);
        let mut pw = b64.into_bytes();
        pw.extend_from_slice(self.salt);
        let aes_key = md5::Md5::digest(&pw);
        let block = aes_cbc_encrypt_block(&data[..16], &aes_key);

        // mid = uid + enc_block(16) + HMAC(iv+key, mid)[:4]
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let mut mid = uid.to_vec();
        mid.extend_from_slice(&block);
        let mac = self.hash.hmac(&mac_key, &mid);
        mid.extend_from_slice(&mac[..4]);

        // check_head = byte(1) + HMAC(mac_key, byte)[:6]
        let mut check_head = vec![check_head_byte];
        let ch_mac = self.hash.hmac(&mac_key, &check_head);
        check_head.extend_from_slice(&ch_mac[..6]);

        // out = check_head + mid + rnd_pad + buf + HMAC(user_key, out)[:4]
        let mut out = check_head;
        out.extend_from_slice(&mid);
        out.extend_from_slice(rnd_pad);
        out.extend_from_slice(buf);
        let trailer = self.hash.hmac(&user_key, &out);
        out.extend_from_slice(&trailer[..4]);
        out
    }

    fn pack_auth_data(&mut self, rng: &mut dyn RngCore, auth_data: &[u8], buf: &[u8]) -> Vec<u8> {
        if buf.is_empty() {
            return Vec::new();
        }
        let rnd_len = if buf.len() > 400 {
            let mut b = [0u8; 2];
            rng.fill_bytes(&mut b);
            u16::from_le_bytes(b) as usize % 512
        } else {
            let mut b = [0u8; 2];
            rng.fill_bytes(&mut b);
            u16::from_le_bytes(b) as usize % 1024
        };
        // uid / user_key：protocol_param 为 `uid:password` 时定制，否则随机 4B
        let (uid, user_key) = match parse_protocol_param(&self.protocol_param) {
            Some((uid_int, pw)) => {
                let uk = self.hash.digest(pw.as_bytes());
                (uid_int.to_le_bytes().to_vec(), uk)
            }
            None => {
                let mut uid = [0u8; 4];
                rng.fill_bytes(&mut uid);
                (uid.to_vec(), self.key.clone())
            }
        };
        self.user_key = Some(user_key.clone());
        let check_head_byte = rng.gen::<u8>();
        let mut rnd_pad = vec![0u8; rnd_len];
        rng.fill_bytes(&mut rnd_pad);
        self.pack_auth_data_inner(auth_data, buf, rnd_len, &uid, check_head_byte, &rnd_pad)
    }

    /// auth_data（参考 auth.py 564-575）。
    fn auth_data(&mut self, rng: &mut dyn RngCore) -> Vec<u8> {
        let utc_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        if self.connection_id > 0xFF000000 {
            self.local_client_id.clear();
        }
        if self.local_client_id.is_empty() {
            self.local_client_id = vec![0u8; 4];
            rng.fill_bytes(&mut self.local_client_id);
            let mut id4 = [0u8; 4];
            rng.fill_bytes(&mut id4);
            self.connection_id = u32::from_le_bytes(id4) & 0x00FF_FFFF;
        }
        self.connection_id = self.connection_id.wrapping_add(1);
        let mut out = utc_time.to_le_bytes().to_vec();
        out.extend_from_slice(&self.local_client_id);
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        out
    }

    /// client_pre_encrypt（参考 auth.py 577-592）。
    pub fn client_pre_encrypt(&mut self, rng: &mut dyn RngCore, buf: &[u8]) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        let ogn_data_len = buf.len();
        let mut rest = buf;
        if !self.has_sent_header {
            let head_size = get_head_size(rest, 30);
            let datalen = rest.len().min(rng.gen_range(0usize..=31) + head_size);
            let auth = self.auth_data(rng);
            ret.extend(self.pack_auth_data(rng, &auth, &rest[..datalen]));
            rest = &rest[datalen..];
            self.has_sent_header = true;
        }
        while rest.len() > self.unit_len {
            ret.extend(self.pack_data(rng, &rest[..self.unit_len], ogn_data_len));
            rest = &rest[self.unit_len..];
        }
        ret.extend(self.pack_data(rng, rest, ogn_data_len));
        ret
    }

    /// client_post_decrypt（参考 auth.py 593-626；HMAC 失败即断链——客户端面
    /// raw_trans 语义仅服务端用，客户端错误即 fatal）。
    pub fn client_post_decrypt(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        self.recv_buf.extend_from_slice(buf);
        let mut out: Vec<u8> = Vec::new();
        while self.recv_buf.len() > 4 {
            let mut mac_key = self.user_key.clone().expect("user_key set").to_vec();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let mac = self.hash.hmac(&mac_key, &self.recv_buf[..2]);
            if mac[..2] != self.recv_buf[2..4] {
                bail!("SSR client_post_decrypt MAC 不符");
            }
            let length = u16::from_le_bytes([self.recv_buf[0], self.recv_buf[1]]) as usize;
            if !(7..8192).contains(&length) {
                bail!("SSR client_post_decrypt 帧长非法: {length}");
            }
            if length > self.recv_buf.len() {
                break;
            }
            let trailer = self.hash.hmac(&mac_key, &self.recv_buf[..length - 4]);
            if trailer[..4] != self.recv_buf[length - 4..length] {
                bail!("SSR client_post_decrypt checksum 不符");
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let mut pos = self.recv_buf[4] as usize;
            if pos < 255 {
                pos += 4;
            } else {
                pos = u16::from_le_bytes([self.recv_buf[5], self.recv_buf[6]]) as usize + 4;
            }
            out.extend_from_slice(&self.recv_buf[pos..length - 4]);
            self.recv_buf.drain(..length);
        }
        Ok(out)
    }
}

/// AES-128-CBC 单块加密（streaming 无 padding 口径；iv=16 个 0 时 CBC 恰为
/// 单块密码本加密）。
fn aes_cbc_encrypt_block(data: &[u8], key: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes-128 key 16B");
    let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

/// `protocol_param` 解析（`uid:password` 形；参考 auth.py 545-553）。
fn parse_protocol_param(param: &[u8]) -> Option<(u32, String)> {
    if !param.contains(&b':') {
        return None;
    }
    let idx = param.iter().position(|&b| b == b':')?;
    let uid_str = std::str::from_utf8(&param[..idx]).ok()?;
    let uid: u32 = uid_str.parse().ok()?;
    let pw = String::from_utf8_lossy(&param[idx + 1..]).into_owned();
    Some((uid, pw))
}

// ---------------------------------------------------------------------------
// 混淆：plain + http_simple（参考 obfsplugin/plain.py、http_simple.py）
// ---------------------------------------------------------------------------

/// 混淆种类（第一段范围）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsKind {
    Plain,
    HttpSimple,
}

impl ObfsKind {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "plain" => ObfsKind::Plain,
            "http_simple" | "http_simple_compatible" => ObfsKind::HttpSimple,
            _ => return None,
        })
    }
}

/// http_simple 客户端混淆状态（参考 http_simple.py 57-145）。
pub struct HttpSimpleObfs {
    has_sent_header: bool,
    has_recv_header: bool,
    obfs_param: Vec<u8>,
    host: String,
    port: u16,
}

/// 参考 `http_simple.user_agent`（固定列表，取随机一项）。
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
    "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.0 Mobile/9A334 Safari/7534.48.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.0 Mobile/9A334 Safari/7534.48.3",
];

/// percent 编码（参考 http_simple.encode_head：hexlify 逐字节 → `%HH` 小写）。
fn percent_encode(buf: &[u8]) -> String {
    buf.iter().map(|b| format!("%{b:02x}")).collect()
}

impl HttpSimpleObfs {
    pub fn new(obfs_param: Vec<u8>, host: String, port: u16) -> Self {
        Self {
            has_sent_header: false,
            has_recv_header: false,
            obfs_param,
            host,
            port,
        }
    }

    /// client_encode（参考 http_simple.py 82-107；GET 版）。
    pub fn client_encode(
        &mut self,
        rng: &mut dyn RngCore,
        buf: &[u8],
        iv_len: usize,
        head_len: usize,
    ) -> Vec<u8> {
        if self.has_sent_header {
            return buf.to_vec();
        }
        let head_size = iv_len + head_len;
        let headlen = if buf.len() > head_size + 64 {
            head_size + rng.gen_range(0usize..=64)
        } else {
            buf.len()
        };
        let headdata = &buf[..headlen];
        let rest = &buf[headlen..];

        // obfs_param 形如 `host1,host2#body...`；`#` 后为 body（取代标准头）
        let hosts_raw = if self.obfs_param.is_empty() {
            self.host.clone()
        } else {
            String::from_utf8_lossy(&self.obfs_param).into_owned()
        };
        let (hosts_str, body) = match hosts_raw.find('#') {
            Some(p) => {
                let b = hosts_raw[p + 1..]
                    .replace("\n", "\r\n")
                    .replace("\\n", "\r\n");
                (hosts_raw[..p].to_string(), Some(b))
            }
            None => (hosts_raw, None),
        };
        let hosts: Vec<&str> = hosts_str.split(',').collect();
        let host = hosts[rng.gen_range(0..hosts.len())];
        let port_str = if self.port != 80 {
            format!(":{}", self.port)
        } else {
            String::new()
        };

        let mut http_head = format!("GET /{} HTTP/1.1\r\n", percent_encode(headdata));
        http_head.push_str(&format!("Host: {}{port_str}\r\n", host));
        match body {
            Some(b) => {
                http_head.push_str(&b);
                http_head.push_str("\r\n\r\n");
            }
            None => {
                let ua = USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())];
                http_head.push_str(&format!("User-Agent: {ua}\r\n"));
                http_head.push_str("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n");
            }
        }
        self.has_sent_header = true;
        let mut out = http_head.into_bytes();
        out.extend_from_slice(rest);
        out
    }

    /// client_decode（参考 http_simple.py 109-118；首响应剥离 HTTP 头。
    /// 参考实现在头未完整时丢弃残片——本实现内部缓冲，严格更稳。）
    pub fn client_decode(&mut self, buf: &[u8], recv_buf: &mut Vec<u8>) -> Vec<u8> {
        if self.has_recv_header {
            return buf.to_vec();
        }
        recv_buf.extend_from_slice(buf);
        if let Some(pos) = find_subslice(recv_buf, b"\r\n\r\n") {
            self.has_recv_header = true;
            recv_buf.drain(..pos + 4);
            std::mem::take(recv_buf)
        } else {
            Vec::new()
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 混淆客户端状态。
pub enum SsrObfs {
    Plain,
    HttpSimple(HttpSimpleObfs),
}

impl SsrObfs {
    pub fn new(kind: ObfsKind, obfs_param: Vec<u8>, host: String, port: u16) -> Self {
        match kind {
            ObfsKind::Plain => SsrObfs::Plain,
            ObfsKind::HttpSimple => {
                SsrObfs::HttpSimple(HttpSimpleObfs::new(obfs_param, host, port))
            }
        }
    }

    pub fn client_encode(
        &mut self,
        rng: &mut dyn RngCore,
        buf: &[u8],
        iv_len: usize,
        head_len: usize,
    ) -> Vec<u8> {
        match self {
            SsrObfs::Plain => buf.to_vec(),
            SsrObfs::HttpSimple(o) => o.client_encode(rng, buf, iv_len, head_len),
        }
    }

    pub fn client_decode(&mut self, buf: &[u8], recv_buf: &mut Vec<u8>) -> Vec<u8> {
        match self {
            SsrObfs::Plain => buf.to_vec(),
            SsrObfs::HttpSimple(o) => o.client_decode(buf, recv_buf),
        }
    }
}

// ---------------------------------------------------------------------------
// 引擎：写侧 protocol→cipher→obfs；读侧 obfs→cipher→protocol
// ---------------------------------------------------------------------------

/// SSR 客户端面配置（连接器构建期校验后冻结）。
#[derive(Debug)]
pub struct SsrConfig {
    pub password: Vec<u8>,
    pub cipher: SsrCipher,
    pub protocol: HashKind,
    pub obfs: ObfsKind,
    pub obfs_param: Vec<u8>,
    pub protocol_param: Vec<u8>,
    pub host: String,
    pub port: u16,
}

/// SSR 客户端面引擎（跨 poll_write/poll_read 持有全部状态）。
pub struct SsrEngine {
    cipher: SsrCipherState,
    auth: AuthClient,
    obfs: SsrObfs,
    rng: Box<dyn RngCore + Send>,
    head: Vec<u8>,
    head_len: usize,
    iv_len: usize,
    first_write: bool,
    /// obfs 头缓冲（http_simple 首响应 \r\n\r\n 跨段）。
    obfs_recv: Vec<u8>,
}

impl SsrEngine {
    pub fn new(config: &SsrConfig, head: Vec<u8>) -> Result<Self> {
        // 参考 auth.py/Encryptor：cipher_key 走 EVP_BytesToKey 派生，
        // cipher_iv 为每连接随机的 random_string(iv_len)——服务端带全局
        // IV 回放缓存（encrypt.c iv_cache），固定 iv 的第二条连接会被
        // 静默丢弃，故必须逐连接随机。
        let (key, _derived_iv) = evp_bytes_to_key_md5(
            &config.password,
            config.cipher.key_len(),
            config.cipher.iv_len(),
        );
        let head_len = get_head_size(&head, 30);
        let iv_len = config.cipher.iv_len();
        // OsRng（Send；thread_rng 在 rand 0.8 为 !Send 的 Rc 线程本地）
        let mut rng = Box::new(rand::rngs::OsRng);
        let mut iv = vec![0u8; iv_len];
        rng.fill_bytes(&mut iv);
        let auth = AuthClient::new(
            config.protocol,
            iv.clone(),
            key.clone(),
            config.protocol_param.clone(),
        );
        let obfs = SsrObfs::new(
            config.obfs,
            config.obfs_param.clone(),
            config.host.clone(),
            config.port,
        );
        Ok(Self {
            cipher: SsrCipherState::new(config.cipher, key, iv),
            auth,
            obfs,
            rng,
            head,
            head_len,
            iv_len,
            first_write: true,
            obfs_recv: Vec::new(),
        })
    }

    /// 写侧：首调将 SSR 目标头并入明文首帧；protocol→cipher→obfs 三段变换。
    pub fn apply_write(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        let data: Vec<u8> = if self.first_write {
            let mut d = self.head.clone();
            d.extend_from_slice(buf);
            self.first_write = false;
            d
        } else {
            buf.to_vec()
        };
        let framed = self.auth.client_pre_encrypt(&mut *self.rng, &data);
        let enc = self.cipher.encrypt(&framed)?;
        let out = self
            .obfs
            .client_encode(&mut *self.rng, &enc, self.iv_len, self.head_len);
        Ok(out)
    }

    /// 读侧：obfs→cipher→protocol 三段解码（各层内部缓冲，返回可用明文）。
    pub fn apply_read(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        let ct = self.obfs.client_decode(raw, &mut self.obfs_recv);
        if ct.is_empty() {
            return Ok(Vec::new());
        }
        let pt = self.cipher.decrypt(&ct)?;
        self.auth.client_post_decrypt(&pt)
    }
}

// ---------------------------------------------------------------------------
// AsyncRead/AsyncWrite 适配：写侧变换→缓冲落内核；读侧内核→变换→出站
// ---------------------------------------------------------------------------

const RELAY_BUF: usize = 16384;

/// SSR 线格式双向流（内核流 IO ↔ SSR 变换引擎）。
pub struct SsrStream<S> {
    inner: S,
    engine: SsrEngine,
    /// 变换后待写入内核的残余（write 分片/写满缓冲）。
    pending_write: Vec<u8>,
    /// 变换后待交还读方的明文。
    out_buf: Vec<u8>,
}

impl<S> SsrStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: S, engine: SsrEngine) -> Self {
        Self {
            inner,
            engine,
            pending_write: Vec::new(),
            out_buf: Vec::new(),
        }
    }
}

impl<S> AsyncRead for SsrStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.out_buf.is_empty() {
                let n = buf.remaining().min(this.out_buf.len());
                buf.put_slice(&this.out_buf[..n]);
                this.out_buf.drain(..n);
                return std::task::Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; RELAY_BUF];
            let mut rb = ReadBuf::new(&mut scratch);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return std::task::Poll::Ready(Ok(())); // EOF
                    }
                    let out = this
                        .engine
                        .apply_read(rb.filled())
                        .map_err(std::io::Error::other)?;
                    this.out_buf.extend(out);
                }
            }
        }
    }
}

impl<S> AsyncWrite for SsrStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // 阶段 1：先排空上一次变换的残余（保序）
        while !this.pending_write.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.pending_write) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(0)) => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(n)) => {
                    this.pending_write.drain(..n);
                }
            }
        }
        // 阶段 2：变换当前输入并写入（写不满则缓冲残余，输入视为全收）
        let out = match this.engine.apply_write(buf) {
            Ok(o) => o,
            Err(e) => {
                return std::task::Poll::Ready(Err(std::io::Error::other(e)));
            }
        };
        let mut remaining: Vec<u8> = out;
        while !remaining.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &remaining) {
                std::task::Poll::Pending => {
                    this.pending_write.extend_from_slice(&remaining);
                    return std::task::Poll::Ready(Ok(buf.len()));
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(0)) => {
                    this.pending_write.extend_from_slice(&remaining);
                    return std::task::Poll::Ready(Ok(buf.len()));
                }
                std::task::Poll::Ready(Ok(n)) => {
                    remaining.drain(..n);
                }
            }
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.pending_write.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.pending_write) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(0)) => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(n)) => {
                    this.pending_write.drain(..n);
                }
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.pending_write.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.pending_write) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(0)) => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(n)) => {
                    this.pending_write.drain(..n);
                }
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 出口连接器（EgressConnector）
// ---------------------------------------------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// ShadowsocksR 出口连接器（第一段：TCP 客户端面）。
#[derive(Debug)]
pub struct ShadowsocksrConnector {
    config: SsrConfig,
    server: String,
    port: u16,
}

impl ShadowsocksrConnector {
    /// 构建连接器；method/protocol/obfs 名称与空密码在构建期校验（配置错误
    /// 启动即暴露，不拖到首个连接）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        method: String,
        password: String,
        protocol: String,
        obfs: String,
        obfs_param: Option<String>,
        protocol_param: Option<String>,
    ) -> Result<Self> {
        if password.is_empty() {
            bail!("SSR 密码不能为空");
        }
        let cipher = SsrCipher::from_name(&method)
            .ok_or_else(|| anyhow!("不支持的 SSR 加密方法: {method}"))?;
        let hash = match protocol.as_str() {
            "auth_aes128_md5" => HashKind::Md5,
            "auth_aes128_sha1" => HashKind::Sha1,
            _ => bail!("不支持的 SSR 协议: {protocol}（第一段仅 auth_aes128_md5/sha1）"),
        };
        let obfs_kind = ObfsKind::from_name(&obfs)
            .ok_or_else(|| anyhow!("不支持的 SSR 混淆: {obfs}（第一段仅 plain/http_simple）"))?;
        let host = if server.is_empty() {
            bail!("SSR 服务器地址不能为空");
        } else {
            server.clone()
        };
        Ok(Self {
            config: SsrConfig {
                password: password.into_bytes(),
                cipher,
                protocol: hash,
                obfs: obfs_kind,
                obfs_param: obfs_param.unwrap_or_default().into_bytes(),
                protocol_param: protocol_param.unwrap_or_default().into_bytes(),
                host,
                port,
            },
            server,
            port,
        })
    }
}

#[async_trait]
impl EgressConnector for ShadowsocksrConnector {
    fn name(&self) -> &'static str {
        "shadowsocksr"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let addr = format!("{}:{}", self.server, self.port);
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .context("SSR 连接超时")?
            .with_context(|| format!("SSR 服务器连接失败: {addr}"))?;

        let head = build_ssr_head(&flow.target.host, flow.target.port)
            .with_context(|| format!("SSR 目标非法: {}:{}", flow.target.host, flow.target.port))?;
        let engine = SsrEngine::new(&self.config, head)?;
        let mut stream = SsrStream::new(tcp, engine);

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("SSR 双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// 测试：KDF/头/帧结构字节级向量钉定（确定性核心；随机面由互测对端兜底）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// EVP_BytesToKey-MD5 对照 Python 参考（`encrypt.py::EVP_BytesToKey`）：
    /// password="pass", key_len=16, iv_len=16 → key/iv 与参考一致。
    /// 参考口径：m[0]=MD5("pass")；key=ms[0:16]。
    #[test]
    fn evp_bytes_to_key_md5_matches_reference() {
        let pw = b"pass";
        let (key, iv) = evp_bytes_to_key_md5(pw, 16, 16);
        // MD5("pass") = 5f4dcc3b5aa765d61d8327deb882cf99
        let expect_key = md5::Md5::digest(pw);
        assert_eq!(key, expect_key.as_slice(), "key 段须为 MD5(pw)");
        // iv 段 = ms[16:32] = MD5(m[0]+pw) = MD5(MD5(pw)+pw)
        let expect_iv = md5::Md5::digest([expect_key.as_slice(), pw].concat());
        assert_eq!(iv, expect_iv.as_slice(), "iv 段须为 MD5(m0+pw)");
        // 24/32 字节钥长同口径
        let (k24, iv24) = evp_bytes_to_key_md5(pw, 24, 16);
        assert_eq!(k24.len(), 24);
        assert_eq!(iv24.len(), 16);
        let (k32, _) = evp_bytes_to_key_md5(pw, 32, 16);
        assert_eq!(k32.len(), 32);
    }

    /// SSR 目标地址头三种形态。
    #[test]
    fn build_ssr_head_shapes() {
        // IPv4：1 + 4B + 2B = 7B
        assert_eq!(
            build_ssr_head("1.2.3.4", 80).unwrap(),
            vec![0x01, 1, 2, 3, 4, 0, 80]
        );
        // 域名：3 + 1B len + domain + 2B = 6+len
        assert_eq!(
            build_ssr_head("example.com", 443).unwrap(),
            vec![
                0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
                0xbb
            ]
        );
        // IPv6：4 + 16B + 2B = 19B
        let h6 = build_ssr_head("::1", 80).unwrap();
        assert_eq!(h6.len(), 19);
        assert_eq!(h6[0], 4);
    }

    /// get_head_size（plain.py 口径：type 1→7，4→19，3→4+len，缺省）。
    #[test]
    fn get_head_size_cases() {
        assert_eq!(get_head_size(&[0x01, 1, 2, 3, 4, 0, 80], 30), 7);
        assert_eq!(get_head_size(&[0x03, 3, b'a', b'b', b'c', 0, 80], 30), 7);
        assert_eq!(get_head_size(&[0x04; 19], 30), 19);
        assert_eq!(get_head_size(&[0x09], 30), 30);
    }

    /// pack_data_inner 帧结构（固定 padding 与 key）：data_len/u16、MAC[:2]、
    /// trailer HMAC[:4] 三段齐全且 MAC 用 key+pack_id(=1) 作 mac_key。
    #[test]
    fn pack_data_inner_frame_structure() {
        let mut auth = AuthClient::new(HashKind::Md5, vec![0u8; 16], vec![1u8; 16], Vec::new());
        auth.user_key = Some(vec![0xAA; 16]);
        let payload = b"hello";
        let padding = vec![0x03, 0x00, 0x11]; // 假定 rnd_data 输出：len byte 3, 2B 随机
        let frame = auth.pack_data_inner(payload, &padding);

        // 结构：data_len(2) + mac[:2] + padding + payload + trailer[:4]
        assert_eq!(frame.len(), 2 + 2 + padding.len() + payload.len() + 4);
        let data_len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
        assert_eq!(data_len, 2 + 2 + padding.len() + payload.len() + 4);
        // mac_key = user_key + pack_id(1, u32 LE)
        let mut mac_key = vec![0xAA; 16];
        mac_key.extend_from_slice(&1u32.to_le_bytes());
        let mac = HashKind::Md5.hmac(&mac_key, &frame[..2]);
        assert_eq!(
            &frame[2..4],
            &mac[..2],
            "前段 MAC 须等于 HMAC(mac_key, data_len)[:2]"
        );
        let trailer = HashKind::Md5.hmac(&mac_key, &frame[..frame.len() - 4]);
        assert_eq!(
            &frame[frame.len() - 4..],
            &trailer[..4],
            "尾段须等于 HMAC(mac_key, 前段)[:4]"
        );
        // 明文区 = padding + payload
        let mut expect = padding.clone();
        expect.extend_from_slice(payload);
        assert_eq!(&frame[4..frame.len() - 4], &expect[..]);
    }

    /// client_post_decrypt 帧解析（固定构造一帧，含 padding 与 payload）。
    #[test]
    fn client_post_decrypt_parses_frame() {
        let mut auth = AuthClient::new(HashKind::Md5, vec![0u8; 16], vec![1u8; 16], Vec::new());
        auth.user_key = Some(vec![0xAA; 16]);
        let payload = b"resp-data";
        // padding = chr(len+1) + 随机（len<128 路径）
        let mut padding = vec![(payload.len() + 1) as u8];
        padding.extend(std::iter::repeat_n(0x55u8, payload.len()));
        // 帧 = data_len(2) + mac[:2] + padding + payload + trailer[:4]
        let mut mac_key = vec![0xAA; 16];
        mac_key.extend_from_slice(&1u32.to_le_bytes());
        // data_len = (data.len() + 8)，data = padding + payload（pack_data_inner 口径）
        let body_len = padding.len() + payload.len() + 8;
        let data_len = body_len as u16;
        let mac = HashKind::Md5.hmac(&mac_key, &data_len.to_le_bytes());
        let mut frame = data_len.to_le_bytes().to_vec();
        frame.extend_from_slice(&mac[..2]);
        frame.extend_from_slice(&padding);
        frame.extend_from_slice(payload);
        let trailer = HashKind::Md5.hmac(&mac_key, &frame);
        frame.extend_from_slice(&trailer[..4]);

        let out = auth.client_post_decrypt(&frame).expect("帧合法");
        assert_eq!(out, payload);
        assert_eq!(auth.recv_buf.len(), 0, "消费后缓冲清空");
        assert_eq!(auth.recv_id, 2, "帧计数递增");
    }

    /// http_simple GET 编码骨架：percent 编码头 + Host + 标准头 + 尾段直通。
    #[test]
    fn http_simple_encode_skeleton() {
        let mut o = HttpSimpleObfs::new(Vec::new(), "1.2.3.4".into(), 8388);
        let mut rng = rand::thread_rng();
        // 线字节：16B IV + 7B 头 + 数据（> head_size+64 走 headlen 分支）
        let wire: Vec<u8> = (0..200u8).collect();
        let out = o.client_encode(&mut rng, &wire, 16, 7);
        let head = String::from_utf8_lossy(&out);
        assert!(head.starts_with("GET /%"), "GET /%HH 起手");
        assert!(head.contains(" HTTP/1.1\r\nHost: 1.2.3.4:8388\r\n"));
        assert!(head.contains("User-Agent: Mozilla/5.0"));
        // 找到 \r\n\r\n，其后为原始剩余字节
        let pos = find_subslice(&out, b"\r\n\r\n").expect("头完整");
        assert_eq!(&out[pos + 4..], &wire[headlen_of(&out, &wire, 16, 7)..]);
        // 二次调用直通
        let again = o.client_encode(&mut rng, &wire, 16, 7);
        assert_eq!(again, wire);
    }

    fn headlen_of(out: &[u8], wire: &[u8], iv_len: usize, head_len: usize) -> usize {
        // 与 client_encode 同口径：head_size+64 分支下 headlen ∈ [head_size, head_size+64]
        let head_size = iv_len + head_len;
        assert!(wire.len() > head_size + 64, "须走 headlen 分支");
        // 解码 URL 中 percent 编码头得字节数
        let s = String::from_utf8_lossy(out);
        let path_start = s.find("GET /").map(|i| i + 5).expect("GET /");
        let path_end = s.find(" HTTP/1.1").expect("路径结束");
        let path = &s[path_start..path_end];
        let encoded = path.len();
        assert_eq!(encoded % 3, 0, "percent 编码逐字节 %HH");
        encoded / 3
    }

    /// AES-128-CBC 单块（iv=0）= 单块密码本加密。
    #[test]
    fn aes_cbc_single_block_zero_iv_is_block_cipher() {
        let key = md5::Md5::digest(b"key");
        let data = [0x11u8; 16];
        let block = aes_cbc_encrypt_block(&data, &key);
        assert_eq!(block.len(), 16);
        // iv=0 时 CBC 单块等价 AES-ECB 单块；往返校验
        use aes::cipher::{BlockDecrypt, KeyInit};
        let c = aes::Aes128::new_from_slice(&key).expect("aes key");
        let mut b = aes::cipher::Block::<aes::Aes128>::clone_from_slice(&block);
        c.decrypt_block(&mut b);
        assert_eq!(&b[..], &data[..]);
    }

    /// 引擎写侧：首帧 = IV + 变换；http_simple 含 GET 头。
    #[test]
    fn engine_write_first_frame_has_iv_and_get() {
        let cfg = SsrConfig {
            password: b"pw".to_vec(),
            cipher: SsrCipher::Aes128Ctr,
            protocol: HashKind::Md5,
            obfs: ObfsKind::HttpSimple,
            obfs_param: Vec::new(),
            protocol_param: Vec::new(),
            host: "1.2.3.4".into(),
            port: 8388,
        };
        let head = build_ssr_head("9.9.9.9", 80).unwrap();
        let mut e = SsrEngine::new(&cfg, head).expect("engine");
        let out = e.apply_write(b"GET /data").expect("write");
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("GET /%"), "obfs GET 头在最外层");
    }

    /// 连接器构建期名称校验（RIL-115）：未交付 method/protocol/obfs 名点名
    /// 拒绝，空密码/空地址拒绝——配置错误启动即暴露，不拖到首个连接。
    #[test]
    fn connector_new_rejects_unsupported_names() {
        let ok = |m: &str, p: &str, o: &str| {
            ShadowsocksrConnector::new(
                "1.2.3.4".into(),
                8388,
                m.into(),
                "pw".into(),
                p.into(),
                o.into(),
                None,
                None,
            )
        };
        // 未交付加密法（SS 方法名族但非 SSR 族）
        let err = ok("chacha20-ietf-poly1305", "auth_aes128_sha1", "http_simple")
            .expect_err("未交付加密法须拒绝");
        assert!(err.to_string().contains("chacha20-ietf-poly1305"), "{err}");
        // origin 协议（无认证面）未交付
        let err = ok("aes-128-ctr", "origin", "http_simple").expect_err("origin 须拒绝");
        assert!(err.to_string().contains("origin"), "{err}");
        // 未交付混淆
        let err =
            ok("aes-128-ctr", "auth_aes128_sha1", "plain_http").expect_err("未交付混淆须拒绝");
        assert!(err.to_string().contains("plain_http"), "{err}");
        // 空密码
        let err = ShadowsocksrConnector::new(
            "1.2.3.4".into(),
            8388,
            "aes-128-ctr".into(),
            String::new(),
            "auth_aes128_sha1".into(),
            "http_simple".into(),
            None,
            None,
        )
        .expect_err("空密码须拒绝");
        assert!(err.to_string().contains("密码"), "{err}");
        // 空地址
        let err = ShadowsocksrConnector::new(
            String::new(),
            8388,
            "aes-128-ctr".into(),
            "pw".into(),
            "auth_aes128_sha1".into(),
            "http_simple".into(),
            None,
            None,
        )
        .expect_err("空地址须拒绝");
        assert!(err.to_string().contains("地址"), "{err}");
    }
}
