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
    let hs = &buf[5..5 + rec_len];
    // 握手头：type(1)=1 + length(3) + version(2) + random(32)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let mut i = 4;
    if hs.len() < i + 34 {
        return None;
    }
    i += 34; // version(2) + random(32)
    let sid_len = *hs.get(i)? as usize;
    i += 1 + sid_len;
    if i + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2 + cs_len;
    if i >= hs.len() {
        return None;
    }
    let comp_len = *hs.get(i)? as usize;
    i += 1 + comp_len;
    if i + 2 > hs.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2;
    let end = (i + ext_len).min(hs.len());
    while i + 4 <= end {
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
/// 返回 `Some(host)` 或 `None`（非 HTTP 请求/无 Host）。
pub fn sniff_http_host(buf: &[u8]) -> Option<String> {
    let head = std::str::from_utf8(buf).ok()?;
    let mut lines = head.split("\r\n");
    // 请求行：METHOD SP URI SP VERSION
    let request_line = lines.next()?;
    if !request_line.contains(" HTTP/") {
        return None;
    }
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            return Some(value.trim().to_string());
        }
    }
    None
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

/// QUIC v1 Initial 包解密 + 提取 ClientHello SNI（RFC 9000 §17.2 +
/// RFC 9001 §5.2/§5.4.4 + HKDF-Expand-Label RFC 8446 §7.1）。
/// 返回 `Some(sni)` 或 `None`（非 Initial / 解密失败 / 无 CRYPTO 帧 / 无 SNI）。
pub fn sniff_quic_sni(buf: &[u8]) -> Option<String> {
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
    if buf.len() < i + 4 {
        return None;
    }
    let token_len = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
    i += 4 + token_len;
    if buf.len() < i + 4 {
        return None;
    }
    let length = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
    i += 4;
    let pn_offset = i;
    let payload_end = pn_offset.checked_add(length)?;
    if buf.len() < payload_end {
        return None;
    }
    let sample_offset = pn_offset + 4; // PN 最大 4 字节；RFC 9001 §5.4.2 固定取
    if buf.len() < sample_offset + 16 {
        return None;
    }
    let sample = &buf[sample_offset..sample_offset + 16];

    let (key, iv, hp) = quic_initial_keys_v1(dcid);
    let hp: [u8; 16] = hp.try_into().ok()?;
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
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&iv[4..]);
    let pn_be = pn.to_be_bytes();
    for n in 0..8 {
        nonce[4 + n] ^= pn_be[n];
    }
    let ciphertext = &packet[pn_offset + pn_len..payload_end];
    if ciphertext.len() < 16 {
        return None;
    }
    let payload = aes128gcm_decrypt(&key, &nonce, &packet[..pn_offset + pn_len], ciphertext)?;
    parse_crypto_frames_sni(&payload)
}

/// RFC 9001 §5.2 QUIC v1 Initial 密钥派生（HKDF-SHA256）。
fn quic_initial_keys_v1(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    const SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&SALT), dcid);
    let initial_secret = hkdf_expand_label(&prk, b"client in", &[], 32);
    (
        hkdf_expand_label(&initial_secret, b"quic key", &[], 16),
        hkdf_expand_label(&initial_secret, b"quic iv", &[], 12),
        hkdf_expand_label(&initial_secret, b"quic hp", &[], 16),
    )
}

/// RFC 8446 §7.1 HKDF-Expand-Label。
fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {}", String::from_utf8_lossy(label));
    let mut info = Vec::with_capacity(2 + full_label.len() + 2 + context.len());
    info.push(len as u8);
    info.extend_from_slice(&(full_label.len() as u16).to_be_bytes());
    info.extend_from_slice(full_label.as_bytes());
    info.extend_from_slice(&(context.len() as u16).to_be_bytes());
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
            GenericArray::from_slice(nonce).into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(|p| p.to_vec())
}

/// 从 QUIC payload 解析 CRYPTO 帧（type 0x06，RFC 9000 §19.6），提取其中
/// TLS 记录的 SNI。首 Initial 通常完整携带 ClientHello；分片场景由
/// `sniff_tls_sni` 对不完整记录返回 None。
fn parse_crypto_frames_sni(payload: &[u8]) -> Option<String> {
    let mut i = 0usize;
    while i < payload.len() {
        let frame_type = payload[i];
        i += 1;
        if frame_type != 0x06 {
            // PADDING=0x00 可连续；PING=0x01；其余类型单包携带时跳过。
            if frame_type == 0x00 {
                continue;
            }
            return None;
        }
        let (offset, n1) = read_varint(payload, i)?;
        let (len, n2) = read_varint(payload, i + n1)?;
        let start = i + n1 + n2 + offset as usize;
        let end = start.checked_add(len as usize)?;
        if payload.len() < end {
            return None;
        }
        return sniff_tls_sni(&payload[start..end]);
    }
    None
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

        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(sniff_tls_sni(&rec).as_deref(), Some("example.com"));
    }

    #[test]
    fn tls_sni_none_for_non_client_hello() {
        assert_eq!(sniff_tls_sni(&[]), None);
        assert_eq!(sniff_tls_sni(&[0x15, 0x03, 0x03, 0x00, 0x00]), None);
    }

    #[test]
    fn http_host_extracts_host_header() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com:443\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff_http_host(req).as_deref(), Some("example.com:443"));
        let req = b"POST / HTTP/1.1\r\nhost: Example.COM\r\n\r\n";
        assert_eq!(sniff_http_host(req).as_deref(), Some("Example.COM"));
    }

    #[test]
    fn http_host_none_for_non_http() {
        assert_eq!(sniff_http_host(b"\x16\x03\x03\x00\x05"), None);
        assert_eq!(sniff_http_host(b"GET / HTTP/1.0\r\n\r\n"), None);
    }

    /// 构造最小 TLS ClientHello 记录（与 `tls_sni_extracts_server_name`
    /// 同构，抽出复用进 QUIC 合成包）。
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
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// RFC 9000 §16 变长整数编码（测试加密端使用）。
    fn write_varint(buf: &mut Vec<u8>, value: u64) {
        if value < 64 {
            buf.push(value as u8);
        } else if value < 16384 {
            buf.extend_from_slice(&[0x40 | (value >> 8) as u8, value as u8]);
        } else if value < 1073741824 {
            buf.extend_from_slice(&[0x80, 0, 0, 0]);
            let last = buf.len() - 4;
            buf[last..].copy_from_slice(&value.to_be_bytes());
        } else {
            buf.extend_from_slice(&[0xC0, 0, 0, 0, 0, 0, 0, 0]);
            let last = buf.len() - 8;
            buf[last..].copy_from_slice(&value.to_be_bytes());
        }
    }

    /// 构造加密的 QUIC v1 Initial 包（合成回环：加密 → 解密 → 提取 SNI）。
    /// 覆盖 RFC 9001 §5.2 密钥派生 + §5.4 header protection + §5.4.1 AEAD
    /// 全链路，证明解密端实现正确。
    pub(crate) fn build_quic_initial(dcid: &[u8], name: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0x06); // CRYPTO
        write_varint(&mut payload, 0); // offset
        let tls_rec = build_client_hello(name);
        write_varint(&mut payload, tls_rec.len() as u64);
        payload.extend_from_slice(&tls_rec);

        let (key, iv, hp) = quic_initial_keys_v1(dcid);
        let pn: u64 = 0;
        let pn_len = 1usize;
        let mut header = Vec::new();
        header.push(0xC0); // 长头 + Initial + reserved + pn_len=1（低 2 位=00）
        header.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // SCID 空
        header.extend_from_slice(&0u32.to_be_bytes()); // token_len=0
                                                       // length = pn_len + payload_len + tag16，占位回填
        let length = pn_len + payload.len() + 16;
        header.extend_from_slice(&(length as u32).to_be_bytes());
        header.push(pn as u8);

        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&iv[4..]);
        let pn_be = pn.to_be_bytes();
        for n in 0..8 {
            nonce[4 + n] ^= pn_be[n];
        }
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut ciphertext = cipher
            .encrypt(
                GenericArray::from_slice(&nonce).into(),
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
        let mask =
            aes_ecb_encrypt_block(&hp.try_into().unwrap(), &sample.try_into().unwrap()).unwrap();
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
}
