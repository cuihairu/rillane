//! 协议嗅探（G0-3 核心）：从流首包提取路由域名——TLS ClientHello SNI /
//! HTTP Host / QUIC Initial SNI。纯解析、无 I/O，供 TUN/代理面首包缓冲
//! 复用；不覆写 target，只返回 `Some(sni)` 供调用方按域名重路由（域名
//! 分流的前提）。

use aes::cipher::{generic_array::GenericArray, Block, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

/// 单个 QUIC CRYPTO 帧（offset 是握手流偏移，不是包内偏移）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CryptoFrame {
    pub(crate) offset: u64,
    pub(crate) data: Vec<u8>,
}

/// QUIC Initial 解密后的 CRYPTO 帧集合（DCID 用于密钥派生/流归属）。
pub(crate) struct QuicCryptoFrames {
    pub(crate) dcid: Vec<u8>,
    pub(crate) frames: Vec<CryptoFrame>,
}

/// QUIC CRYPTO 重组结果：区分「不是 QUIC Initial」「无 CRYPTO」「仍需
/// 更多分片」与「已提取 SNI」，避免调用方把无 CRYPTO 包永久缓存。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuicSniffStep {
    NotInitial,
    NoCrypto,
    Incomplete,
    Host(String),
}

/// 单流 QUIC CRYPTO 重组器：按握手流偏移拼接跨包 ClientHello。
pub(crate) struct QuicCryptoReassembler {
    dcid: Vec<u8>,
    buffer: Vec<u8>,
}

impl QuicCryptoReassembler {
    pub(crate) fn new() -> Self {
        Self {
            dcid: Vec::new(),
            buffer: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, packet: &[u8]) -> QuicSniffStep {
        let Some(decoded) = quic_initial_crypto_frames(packet) else {
            return QuicSniffStep::NotInitial;
        };
        if decoded.frames.is_empty() {
            return QuicSniffStep::NoCrypto;
        }
        if self.dcid != decoded.dcid {
            self.dcid = decoded.dcid;
            self.buffer.clear();
        }
        if append_crypto_frames(&mut self.buffer, &decoded.frames).is_none() {
            return QuicSniffStep::Incomplete;
        }
        match sniff_tls_handshake_sni(&self.buffer) {
            Some(host) => QuicSniffStep::Host(host),
            None => QuicSniffStep::Incomplete,
        }
    }
}

/// QUIC CRYPTO 重组上限：Initial ClientHello 远小于此值；超限即丢弃缓存。
const QUIC_MAX_CRYPTO_BYTES: usize = 64 * 1024;

/// 从 TLS 记录首包提取 SNI（ClientHello server_name 扩展）。
/// 返回 `Some(host)` 或 `None`（非 ClientHello/无法解析/无 SNI）。
pub fn sniff_tls_sni(buf: &[u8]) -> Option<String> {
    // 最小 TLS 记录头（content_type=22, version, length 2）+ ClientHello 骨架
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return None;
    }
    sniff_tls_handshake_sni(&buf[5..5 + rec_len])
}

/// 从裸 TLS 握手消息（QUIC CRYPTO 载荷无记录层，RFC 9001 §4）提取 SNI。
fn sniff_tls_handshake_sni(hs: &[u8]) -> Option<String> {
    // 握手头：type(1)=1 + length(3) + version(2) + random(32)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let end = hs.len().min(4 + hs_len);
    let mut i = 4;
    if end < i + 34 {
        return None;
    }
    i += 34; // version(2) + random(32)
    let sid_len = *hs.get(i)? as usize;
    i = i.checked_add(1 + sid_len)?;
    if i + 2 > end {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i = i.checked_add(2 + cs_len)?;
    if i >= end {
        return None;
    }
    let comp_len = *hs.get(i)? as usize;
    i = i.checked_add(1 + comp_len)?;
    if i + 2 > end {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2;
    let ext_end = i.checked_add(ext_len)?.min(end);
    while i + 4 <= ext_end {
        let et = u16::from_be_bytes([hs[i], hs[i + 1]]);
        let el = u16::from_be_bytes([hs[i + 2], hs[i + 3]]) as usize;
        let data = hs.get(i + 4..i + 4 + el)?;
        if et == 0x0000 {
            // server_name：list_len(2) + name_type(1) + name_len(2) + name
            if data.len() < 5 {
                return None;
            }
            let name_type = data[2];
            if name_type != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
            let name = data.get(5..5 + name_len)?;
            return std::str::from_utf8(name).ok().map(|s| s.to_string());
        }
        i += 4 + el;
    }
    None
}

/// 从 HTTP/1.x 请求首包提取 Host 头（大小写不敏感）。
/// 返回 `Some(host)` 或 `None`（非 HTTP 请求/无 Host/头部尚不完整）。
///
/// 只解码 `\r\n\r\n` 之前的头部，避免合法请求体含二进制时 UTF-8 解码失败；
/// 未见到头部结束标记即视为不完整，不用截断的域名参与路由。
pub fn sniff_http_host(buf: &[u8]) -> Option<String> {
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    // 请求行：METHOD SP URI SP VERSION
    let request_line = lines.next()?;
    if !request_line.contains(" HTTP/") {
        return None;
    }
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            return strip_host_port(value);
        }
    }
    None
}

/// Host 头去端口：`example.com:443` → `example.com`，
/// `[2001:db8::1]:443` → `2001:db8::1`，裸 IPv6 保持原样。
fn strip_host_port(raw: &str) -> Option<String> {
    let host = raw.trim();
    if host.is_empty() {
        return None;
    }
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        return (end > 0).then(|| rest[..end].to_string());
    }
    if host.matches(':').count() == 1 {
        if let Some((name, port)) = host.rsplit_once(':') {
            if !name.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                return Some(name.to_string());
            }
        }
    }
    Some(host.to_string())
}

/// 统一嗅探入口：按协议分发（TLS SNI / HTTP Host / QUIC SNI）。
pub fn sniff_host(proto: &str, buf: &[u8]) -> Option<String> {
    match proto {
        "tls" => sniff_tls_sni(buf),
        "http" => sniff_http_host(buf),
        "quic" => sniff_quic_sni(buf),
        _ => None,
    }
}

/// 单包 QUIC Initial 提取 SNI（跨包分片由 [`QuicCryptoReassembler`] 处理）。
pub fn sniff_quic_sni(buf: &[u8]) -> Option<String> {
    let decoded = quic_initial_crypto_frames(buf)?;
    let mut buffer = Vec::new();
    append_crypto_frames(&mut buffer, &decoded.frames)?;
    sniff_tls_handshake_sni(&buffer)
}

/// QUIC v1 Initial 包解密 + 返回 CRYPTO 帧（RFC 9000 §17.2 +
/// RFC 9001 §5.2/§5.4.4 + HKDF-Expand-Label RFC 8446 §7.1）。
pub(crate) fn quic_initial_crypto_frames(buf: &[u8]) -> Option<QuicCryptoFrames> {
    if buf.len() < 5 || buf[0] & 0xC0 != 0xC0 || buf[0] & 0x30 != 0x00 {
        return None; // 非长头或非 Initial（长头 bit7=1 + bit6=1；type Initial=0b00）
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != 0x0000_0001 {
        return None;
    }
    let mut i = 5usize;
    let dcid_len = *buf.get(i)? as usize;
    i += 1;
    if dcid_len > 20 || buf.len() < i + dcid_len {
        return None;
    }
    let dcid = &buf[i..i + dcid_len];
    i += dcid_len;
    let scid_len = *buf.get(i)? as usize;
    i += 1;
    if scid_len > 20 || buf.len() < i + scid_len {
        return None;
    }
    i += scid_len;
    // RFC 9000 §17.2：Token Length / Length 均为 QUIC varint，不是固定 u32。
    let (token_len, n) = read_varint(buf, i)?;
    i = i
        .checked_add(n)?
        .checked_add(usize::try_from(token_len).ok()?)?;
    if buf.len() < i {
        return None;
    }
    let (length, n) = read_varint(buf, i)?;
    i = i.checked_add(n)?;
    let pn_offset = i;
    let payload_end = pn_offset.checked_add(usize::try_from(length).ok()?)?;
    if buf.len() < payload_end {
        return None;
    }
    let sample_offset = pn_offset + 4; // PN 最大 4 字节；RFC 9001 §5.4.2 固定取
    if buf.len() < sample_offset + 16 {
        return None;
    }
    let sample = &buf[sample_offset..sample_offset + 16];

    let (key, iv, hp) = quic_initial_keys_v1(dcid);
    let sample: [u8; 16] = sample.try_into().ok()?;
    let mask = aes_ecb_encrypt_block(&hp, &sample)?;
    let mut packet = buf[..payload_end].to_vec();
    packet[0] ^= mask[0] & 0x0f;
    let pn_len = ((packet[0] & 0x03) + 1) as usize;
    if payload_end < pn_offset + pn_len {
        return None;
    }
    for (n, mask_byte) in mask[1..1 + pn_len].iter().enumerate() {
        packet[pn_offset + n] ^= mask_byte;
    }
    let mut pn: u64 = 0;
    for &b in &packet[pn_offset..pn_offset + pn_len] {
        pn = (pn << 8) | b as u64;
    }
    let nonce = quic_aead_nonce(&iv, pn);
    let ciphertext = &packet[pn_offset + pn_len..payload_end];
    if ciphertext.len() < 16 {
        return None;
    }
    let payload = aes128gcm_decrypt(&key, &nonce, &packet[..pn_offset + pn_len], ciphertext)?;
    let frames = parse_crypto_frames(&payload)?;
    Some(QuicCryptoFrames {
        dcid: dcid.to_vec(),
        frames,
    })
}

/// RFC 9001 §5.3：nonce = IV XOR 左填充 packet number。IV 前 4 字节不是
/// 零填充区，必须完整拷入，再对最低 8 字节异或 PN。
fn quic_aead_nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_be = pn.to_be_bytes();
    for n in 0..8 {
        nonce[4 + n] ^= pn_be[n];
    }
    nonce
}

/// RFC 9001 §5.2 QUIC v1 Initial 密钥派生（HKDF-SHA256）。
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn quic_initial_keys_v1(dcid: &[u8]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&QUIC_V1_INITIAL_SALT), dcid);
    let initial_secret = hkdf_expand_label(&prk, b"client in", &[], 32);
    (
        hkdf_expand_label(&initial_secret, b"quic key", &[], 16)
            .try_into()
            .expect("quic key 恒 16B"),
        hkdf_expand_label(&initial_secret, b"quic iv", &[], 12)
            .try_into()
            .expect("quic iv 恒 12B"),
        hkdf_expand_label(&initial_secret, b"quic hp", &[], 16)
            .try_into()
            .expect("quic hp 恒 16B"),
    )
}

/// RFC 8446 §7.1 HKDF-Expand-Label。
fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {}", String::from_utf8_lossy(label));
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    // struct HkdfLabel { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("Initial secret 恒 32B");
    let mut okm = vec![0u8; len];
    hk.expand(&info, &mut okm).expect("OKM ≤255B");
    okm
}

/// AES-128-ECB 单块加密（header protection mask，RFC 9001 §5.4.3）。
fn aes_ecb_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = <Block<Aes128>>::clone_from_slice(block);
    cipher.encrypt_block(&mut out);
    Some(out.into())
}

/// AES-128-GCM 解密（QUIC Initial payload，RFC 9001 §5.4.1）。
fn aes128gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(|p| p.to_vec())
}

/// 按握手流 offset 拼接 CRYPTO 帧；出现空洞或超限返回 None。
fn append_crypto_frames(buffer: &mut Vec<u8>, frames: &[CryptoFrame]) -> Option<()> {
    for frame in frames {
        let offset = usize::try_from(frame.offset).ok()?;
        if offset > buffer.len() {
            return None;
        }
        let end = offset.checked_add(frame.data.len())?;
        if end > QUIC_MAX_CRYPTO_BYTES {
            return None;
        }
        if end > buffer.len() {
            buffer.resize(end, 0);
        }
        buffer[offset..end].copy_from_slice(&frame.data);
    }
    Some(())
}

/// 从 QUIC payload 解析 CRYPTO 帧（type 0x06，RFC 9000 §19.6）。
/// 跳过 Initial 包内合法的 PADDING/PING/ACK 等帧，收集全部 CRYPTO 帧；
/// offset 保持握手流语义，由调用方负责跨包重组。
fn parse_crypto_frames(payload: &[u8]) -> Option<Vec<CryptoFrame>> {
    let mut frames = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        let frame_type = payload[i];
        i += 1;
        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                // ACK: largest_ack, ack_delay, range_count, first_range,
                //       range_count × (gap, range)；0x03 追加 ECN 三计数。
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let (range_count, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                for _ in 0..range_count {
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                }
                if frame_type == 0x03 {
                    for _ in 0..3 {
                        let (_, n) = read_varint(payload, i)?;
                        i = i.checked_add(n)?;
                    }
                }
            }
            0x04 => {
                for _ in 0..3 {
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                }
            }
            0x05 => {
                for _ in 0..2 {
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                }
            }
            0x06 => {
                let (offset, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let (len, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let end = i.checked_add(usize::try_from(len).ok()?)?;
                if payload.len() < end {
                    return None;
                }
                frames.push(CryptoFrame {
                    offset,
                    data: payload[i..end].to_vec(),
                });
                i = end;
            }
            0x07 => {
                let (len, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?.checked_add(usize::try_from(len).ok()?)?;
                if payload.len() < i {
                    return None;
                }
            }
            0x08..=0x0f => {
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                if frame_type & 0x04 != 0 {
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                }
                if frame_type & 0x02 != 0 {
                    let (len, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?.checked_add(usize::try_from(len).ok()?)?;
                    if payload.len() < i {
                        return None;
                    }
                } else {
                    i = payload.len();
                }
            }
            0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x19 => {
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
            }
            0x11 | 0x15 => {
                for _ in 0..2 {
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                }
            }
            0x18 => {
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                let cid_len = *payload.get(i)? as usize;
                i = i.checked_add(1 + cid_len + 16)?;
                if payload.len() < i {
                    return None;
                }
            }
            0x1a | 0x1b => {
                i = i.checked_add(8)?;
                if payload.len() < i {
                    return None;
                }
            }
            0x1c | 0x1d => {
                let (_, n) = read_varint(payload, i)?;
                i = i.checked_add(n)?;
                if frame_type == 0x1c {
                    let (_, n) = read_varint(payload, i)?;
                    i = i.checked_add(n)?;
                }
                let (reason_len, n) = read_varint(payload, i)?;
                i = i
                    .checked_add(n)?
                    .checked_add(usize::try_from(reason_len).ok()?)?;
                if payload.len() < i {
                    return None;
                }
            }
            0x1e => {}
            _ => return None,
        }
        if i > payload.len() {
            return None;
        }
    }
    Some(frames)
}

/// QUIC 变长整数解码（RFC 9000 §16）。
fn read_varint(buf: &[u8], start: usize) -> Option<(u64, usize)> {
    let first = *buf.get(start)?;
    let prefix = first >> 6;
    let (len, value_base) = match prefix {
        0 => (1, (first & 0x3f) as u64),
        1 => (2, (first & 0x3f) as u64),
        2 => (4, (first & 0x3f) as u64),
        3 => (8, (first & 0x3f) as u64),
        _ => return None,
    };
    let end = start.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    let mut value = value_base;
    for b in &buf[start + 1..end] {
        value = (value << 8) | (*b as u64);
    }
    Some((value, len))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn wrap_tls_record(hs: &[u8]) -> Vec<u8> {
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(hs);
        rec
    }

    #[test]
    fn tls_sni_extracts_server_name() {
        // 手工构造最小 ClientHello：仅 server_name 扩展。
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.extend_from_slice(&[0x00, 0x00, 0x00]); // length 占位（3 字节）
        hs.extend_from_slice(&[0x03, 0x03]); // version TLS1.2
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id len
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        hs.push(0); // compression methods len
                    // extensions: server_name
        let name = b"example.com";
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // type server_name
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&[0x00, 0x00]); // list len
        server_name.push(0); // name_type host
        server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(name);
        ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&server_name);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        // 回填握手长度
        let hs_len = (hs.len() - 4) as u16;
        hs[1] = (hs_len >> 8) as u8;
        hs[2] = hs_len as u8;

        assert_eq!(
            sniff_tls_sni(&wrap_tls_record(&hs)).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn tls_sni_none_for_non_client_hello() {
        assert_eq!(sniff_tls_sni(&[]), None);
        assert_eq!(sniff_tls_sni(&[0x15, 0x03, 0x03, 0x00, 0x00]), None);
    }

    #[test]
    fn http_host_extracts_host_header_without_port() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com:443\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff_http_host(req).as_deref(), Some("example.com"));
        let req = b"POST / HTTP/1.1\r\nhost: Example.COM\r\n\r\n";
        assert_eq!(sniff_http_host(req).as_deref(), Some("Example.COM"));
        let req = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n";
        assert_eq!(sniff_http_host(req).as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn http_host_ignores_binary_body_and_requires_complete_headers() {
        // 头部完整、请求体含非法 UTF-8：仍应提取 Host。
        let mut req = b"POST / HTTP/1.1\r\nHost: body.example\r\n\r\n".to_vec();
        req.extend_from_slice(&[0xff, 0x00, 0xfe]);
        assert_eq!(sniff_http_host(&req).as_deref(), Some("body.example"));
        // Host 行截断 / 缺头部结束标记：不得用不完整域名路由。
        assert_eq!(
            sniff_http_host(b"GET / HTTP/1.1\r\nHost: partial.exa"),
            None
        );
        assert_eq!(
            sniff_http_host(b"GET / HTTP/1.1\r\nHost: partial.example\r\n"),
            None
        );
    }

    #[test]
    fn http_host_none_for_non_http() {
        assert_eq!(sniff_http_host(b"\x16\x03\x03\x00\x05"), None);
        assert_eq!(sniff_http_host(b"GET / HTTP/1.0\r\n\r\n"), None);
    }

    /// 构造最小裸 TLS ClientHello 握手消息（无记录层，QUIC CRYPTO 载荷）。
    fn build_client_hello(name: &[u8]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(0x01);
        hs.extend_from_slice(&[0x00, 0x00, 0x00]);
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hs.push(0);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]);
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&[0x00, 0x00]);
        server_name.push(0);
        server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(name);
        ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&server_name);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let hs_len = (hs.len() - 4) as u16;
        hs[1] = (hs_len >> 8) as u8;
        hs[2] = hs_len as u8;
        hs
    }

    /// RFC 9000 §16 变长整数编码（测试加密端使用）。
    fn write_varint(buf: &mut Vec<u8>, value: u64) {
        if value < 64 {
            buf.push(value as u8);
        } else if value < 16384 {
            buf.extend_from_slice(&[0x40 | (value >> 8) as u8, value as u8]);
        } else if value < 1073741824 {
            // 4 字节宽度：prefix=2，值低 30 位按 4 字节大端编码，首字节
            // 高 2 位 = 0b10，其余 6 位为值最高 6 位（bit 29..24）。
            let be = value.to_be_bytes();
            buf.push(0x80 | ((value >> 24) as u8 & 0x3f));
            buf.extend_from_slice(&be[5..]);
        } else {
            // 8 字节宽度：prefix=3，值低 62 位按 8 字节大端编码，首字节
            // 高 2 位 = 0b11，其余 6 位为值最高 6 位（bit 61..56）。
            let be = value.to_be_bytes();
            buf.push(0xC0 | ((value >> 56) as u8 & 0x3f));
            buf.extend_from_slice(&be[1..]);
        }
    }

    #[test]
    fn write_varint_roundtrips_all_widths() {
        for value in [0u64, 63, 64, 16383, 16384, 1 << 20, 1 << 29, 1 << 30] {
            let mut encoded = Vec::new();
            write_varint(&mut encoded, value);
            let (decoded, used) = read_varint(&encoded, 0).expect("decode");
            assert_eq!(decoded, value);
            assert_eq!(used, encoded.len());
        }
    }

    /// 构造加密的 QUIC v1 Initial 包（合成回环：加密 → 解密 → 提取 SNI）。
    /// 覆盖 RFC 9001 §5.2 密钥派生 + §5.4 header protection + §5.4.1 AEAD
    /// 全链路，证明解密端实现正确。
    pub(crate) fn build_quic_initial(dcid: &[u8], name: &[u8]) -> Vec<u8> {
        let hs = build_client_hello(name);
        build_quic_initial_with_crypto(dcid, 0, &hs)
    }

    fn build_quic_initial_with_crypto(dcid: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0x06); // CRYPTO
        write_varint(&mut payload, offset);
        write_varint(&mut payload, data.len() as u64);
        payload.extend_from_slice(data);

        let (key, iv, hp) = quic_initial_keys_v1(dcid);
        let pn: u64 = 0;
        let pn_len = 1usize;
        let mut header = Vec::new();
        header.push(0xC0); // 长头 + Initial + reserved + pn_len=1（低 2 位=00）
        header.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // SCID 空
        write_varint(&mut header, 0); // token_len=0
                                      // length = pn_len + payload_len + tag16，占位回填
        let length = pn_len + payload.len() + 16;
        write_varint(&mut header, length as u64);
        header.push(pn as u8);

        let nonce = quic_aead_nonce(&iv, pn);
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut ciphertext = cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &header,
                },
            )
            .unwrap();

        let mut packet = header.clone();
        let pn_pos = packet.len() - 1; // PN 位于 header 末尾（append 前）
        packet.append(&mut ciphertext);
        let sample = packet[pn_pos + 4..pn_pos + 20].to_vec();
        let mask = aes_ecb_encrypt_block(&hp, &sample.try_into().unwrap()).unwrap();
        packet[0] ^= mask[0] & 0x0f;
        for n in 0..pn_len {
            packet[pn_pos + n] ^= mask[1 + n];
        }
        packet
    }

    #[test]
    fn quic_sni_extracts_server_name_from_initial() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let packet = build_quic_initial(&dcid, b"quic.example.com");
        assert_eq!(sniff_quic_sni(&packet).as_deref(), Some("quic.example.com"));
    }

    #[test]
    fn quic_sni_none_for_non_initial_or_short() {
        assert_eq!(sniff_quic_sni(&[]), None);
        assert_eq!(sniff_quic_sni(&[0xC0, 0, 0, 0, 1]), None);
        // version 不支持（非 v1）→ None
        let mut bad = build_quic_initial(&[1, 2, 3, 4], b"example.com");
        bad[1..5].copy_from_slice(&0xff00_002du32.to_be_bytes());
        assert_eq!(sniff_quic_sni(&bad), None);
        // 非 Initial 长头（type=0b01 → 0xD0）
        let mut not_initial = build_quic_initial(&[1, 2, 3, 4], b"example.com");
        not_initial[0] = 0xD0 | (not_initial[0] & 0x0F);
        assert_eq!(sniff_quic_sni(&not_initial), None);
    }

    #[test]
    fn quic_crypto_reassembles_split_client_hello() {
        let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let hs = build_client_hello(b"split.example.com");
        let mid = hs.len() / 2;
        let first = build_quic_initial_with_crypto(&dcid, 0, &hs[..mid]);
        let second = build_quic_initial_with_crypto(&dcid, mid as u64, &hs[mid..]);
        let mut reassembler = QuicCryptoReassembler::new();
        assert_eq!(
            reassembler.push(&first),
            QuicSniffStep::Incomplete,
            "首片不应提前命中"
        );
        assert_eq!(
            reassembler.push(&second),
            QuicSniffStep::Host("split.example.com".to_string())
        );
    }

    #[test]
    fn quic_initial_keys_match_rfc9001_vector() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (key, iv, hp) = quic_initial_keys_v1(&dcid);
        assert_eq!(
            key,
            [
                0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
                0xa2, 0x2d
            ]
        );
        assert_eq!(
            iv,
            [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]
        );
        assert_eq!(
            hp,
            [
                0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
                0xed, 0xd2
            ]
        );
        // RFC 8446 §7.1 编码：uint16 length + u8 label len + label + u8 context len
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&QUIC_V1_INITIAL_SALT), &dcid);
        assert_eq!(
            hkdf_expand_label(&prk, b"client in", &[], 32),
            [
                0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03,
                0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f,
                0x6c, 0x35, 0x7a, 0xea
            ],
            "RFC 9001 A.1 client initial secret"
        );
    }

    #[test]
    fn quic_aead_nonce_xors_packet_number_into_full_iv() {
        let iv = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        assert_eq!(quic_aead_nonce(&iv, 0), iv);
        assert_eq!(
            quic_aead_nonce(&iv, 1),
            [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5d]
        );
    }
}
