//! P1-5 §8.2 端到端（M4 验收）：mock trojan TLS 服务端（rcgen 自签证书 +
//! rustls acceptor，环回无特权）× 串行 N ≥ 10 同目标转发 → §0.2 判据：
//! acquires hit ≥ N−1、reuse_ratio ≥ (N−1)/N、前台拨号增量 ≤ 1，
//! 且 `seep_tls_handshakes_total` 数据源（factory 握手观测）出现 resumed ≥ 1
//! ——D-5 共享 ClientConfig 会话恢复生效的端到端证据。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use seep_core::EgressConnector;
use seep_protocols::{
    PoolPolicy, TlsConnectorFactory, TlsFingerprint, TransportKey, TransportPool, TrojanConnector,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const FLOWS: usize = 12;
const PASSWORD: &str = "pool-tls-acceptance";

fn pooled_policy() -> PoolPolicy {
    PoolPolicy {
        enabled: true,
        tls_resumption: true,
        max_idle_per_key: 2,
        max_idle_global: 16,
        low_watermark: 1,
        idle_timeout: Duration::from_secs(30),
        dial_timeout: Duration::from_secs(3),
        session_cache_size: 256,
        pre_dial_direct: false,
    }
}

/// duplex 客户端半边 + Flow（io 为对端）
fn make_flow(host: &str, port: u16) -> (seep_core::Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(4096);
    let flow = seep_core::Flow {
        id: seep_core::FlowId::new(),
        target: seep_core::FlowTarget {
            host: host.to_string(),
            port,
            proto: seep_core::TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

/// 往返一次并收尾：写 payload → 读回 → shutdown → join forward
async fn roundtrip_and_finish(
    mut client: tokio::io::DuplexStream,
    handle: tokio::task::JoinHandle<anyhow::Result<seep_core::FlowReport>>,
    payload: &[u8],
) -> seep_core::FlowReport {
    client.write_all(payload).await.expect("客户端写入");
    client.flush().await.expect("flush");
    let mut buf = vec![0u8; payload.len()];
    client.read_exact(&mut buf).await.expect("读回");
    assert_eq!(&buf, payload, "echo 往返");
    client.shutdown().await.expect("半关触发 relay 收尾");
    handle.await.expect("forward join").expect("forward 成功")
}

async fn wait_until(cond: impl Fn() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("条件未在 5s 内满足");
}

/// mock trojan TLS 服务端：rcgen 自签 → rustls acceptor → 解析 trojan 请求头
/// （56 hex + CRLF + CMD + ATYP + 地址 + 端口 + CRLF，校验 hash 形态）→ echo。
/// 返回（地址，服务端接受的 TLS 连接数，服务端见到的密码 hash 集）。
async fn spawn_trojan_tls_server() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    // 自签证书（SAN=localhost；客户端 skip_cert_verify 不校验链）
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM 解析");
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .expect("私钥读取")
        .expect("PKCS8 私钥在位");

    // 服务端与客户端同涉双提供方歧义：显式安装 ring（一次性；客户端工厂
    // 侧 tls.rs 亦同法，先到先装互尊重）
    let provider = seep_tls_provider();
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("协议版本");
    // 会话恢复服务端侧：rustls 默认 ticketer（NewSessionTicket）即启用，
    // 客户端 resumed 断言依赖于此，无需显式配置
    let config = Arc::new(
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("服务端证书装配"),
    );
    let acceptor = TlsAcceptor::from(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let hashes = Arc::new(std::sync::Mutex::new(Vec::new()));

    let conns_task = conns.clone();
    let hashes_task = hashes.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let conns_task = conns_task.clone();
            let hashes_task = hashes_task.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                conns_task.fetch_add(1, Ordering::SeqCst);

                // trojan 请求头：hash(56) CRLF CMD(1) ATYP(1) ...
                let mut head = [0u8; 56 + 2 + 1 + 1];
                if tls.read_exact(&mut head).await.is_err() {
                    return;
                }
                let hash = String::from_utf8_lossy(&head[..56]).to_string();
                assert!(
                    hash.bytes().all(|b| b.is_ascii_hexdigit()),
                    "hash 应为 56 位 hex：{hash}"
                );
                hashes_task.lock().expect("hashes lock").push(hash);
                match head[59] {
                    0x03 => {
                        let mut l = [0u8; 1];
                        if tls.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut rest = vec![0u8; l[0] as usize + 2];
                        if tls.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                    }
                    0x01 => {
                        let mut rest = vec![0u8; 4 + 2];
                        if tls.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
                let mut crlf = [0u8; 2];
                if tls.read_exact(&mut crlf).await.is_err() {
                    return;
                }

                // echo 至 EOF（trojan 无独立应答头语义对本连接器成立：客户端
                // bind 只写不读，中继字节即 echo 往返）。收尾 shutdown 发
                // close_notify——rustls 对无 close_notify 的裸 EOF 视为错误
                //（UnexpectedEof），不发则 copy_bidirectional 以 Err 收场。
                let mut buf = [0u8; 4096];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            let _ = tls.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, conns, hashes)
}

/// 进程级 ring 安装（与 tls.rs 同法；测试 crate 不可见私有 helper，此处独立）
fn seep_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider 已安装")
        .clone()
}

/// §8.2 主验收：N=12 串行同目标 trojan-over-TLS 转发 → 命中 11 / miss 1 /
/// 前台拨号 1 / reuse_ratio ≥ 11/12 / resumed ≥ 1（full 链仅首拨一条）。
#[tokio::test]
async fn trojan_tls_pooled_serial_reuse_and_resumption() {
    let (addr, server_conns, server_hashes) = spawn_trojan_tls_server().await;
    let server = addr.ip().to_string();
    let port = addr.port();

    let factory = Arc::new(TlsConnectorFactory::new(256));
    let pool = TransportPool::new(pooled_policy(), Some(factory.clone()));
    let connector = Arc::new(TrojanConnector::new(
        server.clone(),
        port,
        PASSWORD.to_string(),
        Some("localhost".to_string()),
        true,
        TlsFingerprint::None,
        "tcp".to_string(),
        None,
        None,
        Some(pool.clone()),
        Some(factory.clone()),
    ));

    let key = TransportKey::tls(
        &server,
        port,
        Some("localhost"),
        true,
        &[],
        TlsFingerprint::None,
    );
    let mut payloads = Vec::new();
    for i in 0..FLOWS {
        let (flow, client) = make_flow("www.example.com", 443);
        let connector_for_task = connector.clone();
        let handle = tokio::spawn(async move { connector_for_task.forward(flow).await });
        let payload = format!("tls-flow-{i}").into_bytes();
        let report = roundtrip_and_finish(client, handle, &payload).await;
        assert_eq!(report.upstream, payload.len() as u64);
        payloads.push(payload);

        // 水位补充落地后再发下一流 → 命中路径确定（串行同键）
        wait_until(|| pool.idle_count_of(&key) >= 1).await;
    }

    // §0.2 判据 1：命中 ≥ N−1（本场景确定形态 = miss 1 + hit N−1）
    let snap = pool.snapshot();
    assert_eq!(snap.acquires_hit, (FLOWS - 1) as u64, "流 2..N 全命中");
    assert_eq!(snap.acquires_miss, 1, "仅首流前台 miss");
    assert_eq!(snap.acquires_stale_redial, 0, "活连接无 stale");

    // §0.2 判据 2：reuse_ratio ≥ (N−1)/N
    assert!(
        snap.reuse_ratio() >= (FLOWS - 1) as f64 / FLOWS as f64,
        "reuse_ratio = {} 应 ≥ {}",
        snap.reuse_ratio(),
        (FLOWS - 1) as f64 / FLOWS as f64
    );

    // §0.2 判据 3：前台拨号增量 ≤ 1（补充拨号另计 origin=refill）
    assert_eq!(snap.dials_foreground_ok, 1);
    assert!(snap.dials_refill_ok >= 1, "借出消耗必有补充");

    // D-5 会话恢复端到端：首拨 full，其后 resumed（ticketer 默认启用）。
    // full ≤ 2：首拨必 full；首次补充拨号与首流 relay 读入 NewSessionTicket
    // 存在观测竞态（ticket 随首连接应用数据异步入缓存，补充 ClientHello 可
    // 先于入缓存发出）→ 该一拨也可能 full，其后拨号全部 resumed。
    let (full, full_hrr, resumed) = factory.handshake_snapshot();
    assert!(
        resumed >= 1,
        "应有会话恢复握手：{full}/{full_hrr}/{resumed}"
    );
    assert!(
        full + full_hrr <= 2,
        "完整握手 ≤ 首拨+首补充（ticket 观测竞态上界）：{full}/{full_hrr}/{resumed}"
    );

    // 服务端面：每流 + 每次补充 = 独立 TLS 连接（借出即消费不归还，D-1）
    let seen = server_hashes.lock().expect("hashes lock").clone();
    assert!(seen.iter().all(|h| h.len() == 56), "服务端只见合法 hash 头");
    assert!(
        server_conns.load(Ordering::SeqCst) >= FLOWS,
        "服务端连接数 ≥ 流数（消耗形；补充另增）"
    );
    let _ = payloads;
}

// ==== Trojan over WS（trojan-go 惯例；clash 导出/导入往返面，2026-10-07）====

use base64::engine::general_purpose::STANDARD as WS_BASE64;
use base64::Engine as _;
use sha1::{Digest, Sha1};

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WS 帧解码（客户端→服务端恒掩码）；返回 opcode 与去掩码载荷
async fn read_client_frame<S>(stream: &mut S) -> anyhow::Result<(u8, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    let len = match hdr[1] & 0x7f {
        126 => {
            let mut l = [0u8; 2];
            stream.read_exact(&mut l).await?;
            u16::from_be_bytes(l) as usize
        }
        127 => {
            let mut l = [0u8; 8];
            stream.read_exact(&mut l).await?;
            u64::from_be_bytes(l) as usize
        }
        n => n as usize,
    };
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).await?;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok((hdr[0] & 0x0f, payload))
}

/// 服务端→客户端帧编码（无掩码）
fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80u8 | (opcode & 0x0f)];
    if payload.len() <= 125 {
        f.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        f.push(126);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        f.push(127);
        f.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    f.extend_from_slice(payload);
    f
}

/// mock trojan-ws TLS 服务端：TLS accept → HTTP Upgrade（解析 path/Host/Key，
/// 回 101 + Sec-WebSocket-Accept）→ 首个 binary 帧应为一个完整 trojan 请求头
/// → 逐帧 echo 至 Close。返回（地址，hash 集，见到的 path，见到的 Host）。
#[allow(clippy::type_complexity)]
async fn spawn_trojan_ws_tls_server() -> (
    std::net::SocketAddr,
    Arc<std::sync::Mutex<Vec<String>>>,
    Arc<std::sync::Mutex<String>>,
    Arc<std::sync::Mutex<String>>,
) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM 解析");
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .expect("私钥读取")
        .expect("PKCS8 私钥在位");

    let provider = seep_tls_provider();
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("协议版本");
    let config = Arc::new(
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("服务端证书装配"),
    );
    let acceptor = TlsAcceptor::from(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let hashes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let path_slot = Arc::new(std::sync::Mutex::new(String::new()));
    let host_slot = Arc::new(std::sync::Mutex::new(String::new()));

    let hashes_task = hashes.clone();
    let path_task = path_slot.clone();
    let host_task = host_slot.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let hashes_task = hashes_task.clone();
            let path_task = path_task.clone();
            let host_task = host_task.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };

                // HTTP Upgrade 请求（读至头部结束符）
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match tls.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&buf);
                let mut lines = text.lines();
                let req_line = lines.next().unwrap_or("");
                let path = req_line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut ws_key = String::new();
                let mut ws_host = String::new();
                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        let (k, v) = (k.trim(), v.trim());
                        if k.eq_ignore_ascii_case("sec-websocket-key") {
                            ws_key = v.to_string();
                        }
                        if k.eq_ignore_ascii_case("host") {
                            ws_host = v.to_string();
                        }
                    }
                }
                let mut hasher = Sha1::new();
                hasher.update(ws_key.as_bytes());
                hasher.update(WS_MAGIC.as_bytes());
                let accept = WS_BASE64.encode(hasher.finalize());
                let resp = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                if tls.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }

                // 首个 binary 帧 = 完整 trojan 请求头
                let Ok((0x2, payload)) = read_client_frame(&mut tls).await else {
                    return;
                };
                if payload.len() < 56 {
                    return;
                }
                let hash = String::from_utf8_lossy(&payload[..56]).to_string();
                assert!(
                    hash.bytes().all(|b| b.is_ascii_hexdigit()),
                    "trojan 请求头应 56 位 hex：{hash}"
                );
                hashes_task.lock().expect("hashes lock").push(hash);
                *path_task.lock().expect("path lock") = path;
                *host_task.lock().expect("host lock") = ws_host;

                // 逐帧 echo 至 Close（Close 后回 Close 并关 TLS——下行侧经
                // read_binary 的 None 语义收敛）
                loop {
                    match read_client_frame(&mut tls).await {
                        Ok((0x8, _)) | Err(_) => {
                            let _ = tls.write_all(&server_frame(0x8, &[])).await;
                            let _ = tls.shutdown().await;
                            return;
                        }
                        Ok((0x2, p)) | Ok((0x0, p)) => {
                            if tls.write_all(&server_frame(0x2, &p)).await.is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    (addr, hashes, path_slot, host_slot)
}

/// Trojan over WS（inline 路径）：upgrade path/Host 解析、请求头在首个
/// binary 帧、echo 往返、客户端半关 → Close 传播收尾。
#[tokio::test]
async fn trojan_ws_inline_roundtrip_request_in_first_frame() {
    let (addr, hashes, path_slot, host_slot) = spawn_trojan_ws_tls_server().await;

    let factory = Arc::new(TlsConnectorFactory::new(256));
    let connector = TrojanConnector::new(
        addr.ip().to_string(),
        addr.port(),
        PASSWORD.to_string(),
        None, // SNI 回退 ws Host 首值
        true,
        TlsFingerprint::None,
        "ws".to_string(),
        Some("/ray".to_string()),
        Some(vec!["ws.example.com".to_string()]),
        None,
        Some(factory),
    );

    let (flow, client) = make_flow("www.example.com", 443);
    let handle = tokio::spawn(async move { connector.forward(flow).await });
    let payload = b"trojan-ws-echo";
    let report = roundtrip_and_finish(client, handle, payload).await;
    assert_eq!(report.upstream, payload.len() as u64, "上行计数");

    assert_eq!(hashes.lock().expect("hashes lock").len(), 1, "一次请求头");
    assert_eq!(path_slot.lock().expect("path lock").as_str(), "/ray");
    assert_eq!(
        host_slot.lock().expect("host lock").as_str(),
        "ws.example.com"
    );
}
