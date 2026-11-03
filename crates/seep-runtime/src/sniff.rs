//! 协议嗅探（G0-3 核心）：从流首包提取路由域名——TLS ClientHello SNI /
//! HTTP Host。纯解析、无 I/O，供 TUN/代理面首包缓冲复用；不覆写 target，
//! 只返回 `Some(sni)` 供调用方按域名重路由（域名分流的前提）。

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

#[cfg(test)]
mod tests {
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
}
