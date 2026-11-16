//! REALITY 验收合约（RIL-107）：真实对端 = cfal/rustls fork 服务端面
//! （PreparedServerHello/ServerConnection::new_reality）+ xray 认证语义自装配
//! （open session-id、HMAC 证书、ed25519 CertificateVerify）。
//!
//! 覆盖验收面：合法组合握手成功与双向转发、统计（FlowReport）、
//! 非真实对端失败（错误静钥 / short_id 不符）、取消、资源释放。
//! 平台旁路：REALITY 拨号走 net_mark::connect_tcp 同一 TCP 面
//! （networking.md §2，与普通 VLESS 无差异——不重复测平台面）。

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::pkcs8::EncodePrivateKey;
use rillane_config::RealityConfig;
use rillane_core::EgressConnector;
use rillane_core::{Flow, FlowId, FlowMetadata, FlowTarget, TargetProto};
use rillane_protocols::outbound::{
    derive_auth_key, extract_client_random, extract_session_id, extract_x25519_key_share,
    handshake, hmac_cert_tag, open_session_id, zero_session_id_slot, CORE_VERSION,
};
use rillane_protocols::{TlsFingerprint, VlessConnector};
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

const TEST_UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";
const SHORT_ID_HEX: &str = "0102030405060708";
/// 服务器名称指示（服务端面不校验 SNI——PreparedServerHello 只认模板形状；
/// 保留真实域名字样以贴近真实对端口径）
const PEER_SNI: &str = "target.example";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// 服务端静态密钥 + 期望 short_id（hex 口径即配置样本）
struct PeerKey {
    sk: StaticSecret,
    short_id: [u8; 8],
}

fn peer_key() -> PeerKey {
    let mut sid = [0u8; 8];
    for (i, b) in (0..8).zip(SHORT_ID_HEX.as_bytes().chunks(2)) {
        sid[i] = u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap();
    }
    PeerKey {
        sk: StaticSecret::random_from_rng(rand::rngs::OsRng),
        short_id: sid,
    }
}

impl PeerKey {
    fn public_key_hex(&self) -> String {
        hex_encode(PublicKey::from(&self.sk).as_bytes())
    }
}

/// 目标模板（fork 配方）：普通 rustls 握手，取服务端首飞记录内 ServerHello
/// 握手字节——PreparedServerHello 校验其形状并只替换 key share
fn capture_target_template() -> Vec<u8> {
    #[derive(Debug)]
    struct AcceptAll;

    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            // 模板捕获面：rcgen 默认 ECDSA 证书——广告 ECDSA+Ed25519 全谱
            vec![
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    let x25519_provider = || {
        let mut p = rustls::crypto::aws_lc_rs::default_provider();
        p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        p
    };

    let certified =
        rcgen::generate_simple_self_signed(vec![PEER_SNI.to_string()]).expect("自签证书");
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(certified.cert.pem().as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        certified.key_pair.serialize_pem().as_bytes(),
    )
    .expect("私钥");
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(x25519_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("服务端装配");
    let mut server = rustls::ServerConnection::new(Arc::new(server_config)).expect("server conn");

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(x25519_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(client_config),
        rustls::pki_types::ServerName::try_from(PEER_SNI.to_string()).expect("server name"),
    )
    .expect("client conn");

    // 单步驱动：CH → 服务端首飞（ServerHello 记录 + 密文后续）
    let mut wire = Vec::new();
    client.write_tls(&mut wire).expect("写 ClientHello");
    server.read_tls(&mut &wire[..]).expect("读 ClientHello");
    server.process_new_packets().expect("处理 ClientHello");
    let mut resp = Vec::new();
    server.write_tls(&mut resp).expect("写服务端首飞");
    assert_eq!(resp[0], 22, "首飞首记录须为握手记录");
    let sh_len = u16::from_be_bytes([resp[3], resp[4]]) as usize;
    let template = resp[5..5 + sh_len].to_vec();
    assert_eq!(template[0], 2, "模板须为 ServerHello 握手消息");
    template
}

/// HMAC 证书签名器（shoes 口径）：sign 忽略 TBS、返回 HMAC 标签——
/// 只有能 open session-id 的服务端（持有静钥）能产出该证书
#[derive(Debug)]
struct HmacCertSigner {
    public_key: Vec<u8>,
    tag: [u8; 64],
}

impl rcgen::RemoteKeyPair for HmacCertSigner {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.tag.to_vec())
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// VLESS 请求头消费（合约服务端面；Version+UUID+OptLen+Opt+Cmd+Port+ATYP+Addr）
async fn read_vless_request<S: AsyncRead + Unpin>(r: &mut S) -> io::Result<()> {
    let mut head = [0u8; 18];
    r.read_exact(&mut head).await?;
    let opt_len = head[17] as usize;
    let mut opt = vec![0u8; opt_len];
    r.read_exact(&mut opt).await?;
    let mut tail = [0u8; 4]; // cmd(1)+port(2)+atype(1)
    r.read_exact(&mut tail).await?;
    let addr_len = match tail[3] {
        1 => 4,
        2 => {
            let mut l = [0u8; 1];
            r.read_exact(&mut l).await?;
            l[0] as usize
        }
        3 => 16,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("非法 VLESS atype: {other}"),
            ));
        }
    };
    let mut addr = vec![0u8; addr_len];
    r.read_exact(&mut addr).await?;
    Ok(())
}

/// REALITY 真实对端服务面：认证（open session-id + 窗口/short_id 校验）→
/// HMAC 证书 + PreparedServerHello → REALITY 握手 → VLESS echo。
/// `ended` 在连接结束（成功/失败/取消）时 +1——资源释放可见性。
async fn serve_reality_peer(tcp: TcpStream, peer: Arc<PeerKey>, ended: Arc<AtomicUsize>) {
    let result = serve_reality_peer_inner(tcp, &peer).await;
    ended.fetch_add(1, Ordering::SeqCst);
    if let Err(e) = result {
        eprintln!("测试服务端错误: {e:#}");
    }
}

async fn serve_reality_peer_inner(mut tcp: TcpStream, peer: &PeerKey) -> io::Result<()> {
    // ClientHello 记录（首飞恰一记录承载完整 CH）
    let mut hdr = [0u8; 5];
    tcp.read_exact(&mut hdr).await?;
    if hdr[0] != 22 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非握手记录"));
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut ch = vec![0u8; len];
    tcp.read_exact(&mut ch).await?;
    let hello = ch; // 握手字节（无记录头）

    // xray 认证语义：静钥 ECDH → HKDF → AES-GCM open（AAD=槽置零）
    let random = extract_client_random(&hello)?;
    let sealed = extract_session_id(&hello)?;
    let share = extract_x25519_key_share(&hello)?;
    let shared = peer.sk.diffie_hellman(&PublicKey::from(share));
    let auth_key = derive_auth_key(shared.as_bytes(), &random[..20]);
    let aad = zero_session_id_slot(&hello);
    let session = open_session_id(&auth_key, &random[20..32], &sealed, &aad)?;
    if session.version != CORE_VERSION {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "版本不符"));
    }
    if session.timestamp.abs_diff(now_unix_u32()) > 300 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "时间戳越窗",
        ));
    }
    if session.short_id != peer.short_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "short_id 不符",
        ));
    }

    // HMAC 证书（签名字段 = HMAC-SHA512(auth_key, ed25519 公钥)）+ 同钥 CV 真签
    let mut seed = [0u8; 32];
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let ed = ed25519_dalek::SigningKey::from_bytes(&seed);
    let tag = hmac_cert_tag(&auth_key, ed.verifying_key().as_bytes());
    let signer = HmacCertSigner {
        public_key: ed.verifying_key().as_bytes().to_vec(),
        tag,
    };
    let key_pair = rcgen::KeyPair::from_remote(Box::new(signer))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("rcgen: {e}")))?;
    let params = rcgen::CertificateParams::new(vec![PEER_SNI.to_string()])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("rcgen 参数: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("rcgen 签发: {e}")))?;

    let pkcs8 = ed
        .to_pkcs8_der()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pkcs8: {e}")))?;
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
    );
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("签名密钥: {e}")))?;
    let resolver = rustls::sign::SingleCertAndKey::from(rustls::sign::CertifiedKey::new(
        vec![cert.der().to_owned()],
        signing_key,
    ));

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("版本: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    // 模板 session-id 槽（握手字节 [39..71]）改写为本次客户端的 sealed 认证载荷
    // ——真实 Xray 服务端对抓取的目标 ServerHello 同样改写此槽 + key share
    let mut template = peer_template();
    template[39..71].copy_from_slice(&sealed);
    let prepared = rustls::reality::PreparedServerHello::new(&hello, &template, &provider)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("对端准备: {e}")))?;
    let mut conn = rustls::ServerConnection::new_reality(Arc::new(server_config), prepared)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("REALITY 服务端: {e}")))?;
    // 已读的 CH 记录回灌（认证消费在前，握手循环不再重读 tcp）
    let mut record = hdr.to_vec();
    record.extend_from_slice(&hello);
    conn.read_tls(&mut &record[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("CH 回灌: {e}")))?;
    conn.process_new_packets()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("CH 处理: {e}")))?;
    let mut tls = handshake(tcp, conn).await?;

    // VLESS 面：读请求头 → 写响应头 → echo 直至对端关写
    read_vless_request(&mut tls).await?;
    tls.write_all(&[0x00, 0x00]).await?;
    tls.flush().await?;
    let mut buf = vec![0u8; 8192];
    loop {
        match tls.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tls.write_all(&buf[..n]).await?;
                tls.flush().await?;
            }
        }
    }
    tls.shutdown().await?;
    Ok(())
}

/// 模板 OnceLock（全测试共享一次捕获即可——形状与套件随机数无关，
/// key share 由 PreparedServerHello 每连接替换）
fn peer_template() -> Vec<u8> {
    use std::sync::OnceLock;
    static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();
    TEMPLATE.get_or_init(capture_target_template).clone()
}

/// 拨一个测试 REALITY 连接器（public_key_hex/short_id 可注入错值驱动失败面）
fn reality_connector(
    addr: std::net::SocketAddr,
    public_key_hex: String,
    short_id: Option<&str>,
) -> VlessConnector {
    VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        TEST_UUID.to_string(),
        None,
        Some(RealityConfig {
            public_key: public_key_hex,
            short_id: short_id.map(|s| s.to_string()),
        }),
        "tcp".to_string(),
        None,
        None,
        None,
        true,  // reality 恒叠 TLS（门要求）
        false, // skip_cert_verify 与 REALITY 面无关（认证走 HMAC 绑定）
        None,  // sni 缺省 = server 地址（IP 形 ServerName 合法）
        None,
        TlsFingerprint::None,
        None,
        None,
    )
}

/// 起真实对端监听（每连接 spawn 服务面；`ended` 计数连接结束）
async fn spawn_peer(peer: Arc<PeerKey>, ended: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let peer = peer.clone();
            let ended = ended.clone();
            tokio::spawn(serve_reality_peer(tcp, peer, ended));
        }
    });
    addr
}

fn make_flow(client: tokio::io::DuplexStream) -> Flow {
    Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: "echo.example".to_string(),
            port: 443,
            proto: TargetProto::Tcp,
        },
        io: Box::new(client),
        metadata: FlowMetadata::default(),
    }
}

/// 验收·成功面：真实对端握手成功 → VLESS 双向转发回环一致 →
/// 统计（FlowReport upstream/downstream）覆盖真实字节量
#[tokio::test]
async fn reality_roundtrip_success_with_stats() {
    let peer = Arc::new(peer_key());
    let addr = spawn_peer(peer.clone(), Arc::new(AtomicUsize::new(0))).await;
    let connector = reality_connector(addr, peer.public_key_hex(), Some(SHORT_ID_HEX));

    let (app, app_for_flow) = tokio::io::duplex(64 * 1024);
    let (mut app_rx, app_tx) = tokio::io::split(app);
    let task = tokio::spawn(async move {
        let flow = make_flow(app_for_flow);
        connector.forward(flow).await
    });

    // 写半边全量注入 + 半关（copy_bidirectional 上游 EOF 面）；主侧并发回读
    let payload = vec![0xa7u8; 256 * 1024];
    let payload_len = payload.len();
    let writer = tokio::spawn(async move {
        let mut app_tx = app_tx;
        app_tx.write_all(&payload).await.expect("上行写入");
        app_tx.shutdown().await.expect("上行半关");
    });

    let mut echoed = Vec::new();
    app_rx.read_to_end(&mut echoed).await.expect("下行回读");
    writer.await.expect("写半边任务");

    let report = task.await.expect("forward 任务").expect("forward 失败");
    assert_eq!(echoed.len(), payload_len, "回环字节数一致");
    assert!(echoed.iter().all(|&b| b == 0xa7), "回环载荷一致");
    assert!(
        report.upstream >= payload_len as u64,
        "统计 upstream 覆盖上行: {}",
        report.upstream
    );
    assert!(
        report.downstream >= payload_len as u64,
        "统计 downstream 覆盖下行: {}",
        report.downstream
    );
}

/// 验收·失败面 1：错误静钥（公钥不符）→ 服务端 open session-id 失败即关闭
/// 连接（真实 Xray 同口径）→ 客户端握手期 EOF
#[tokio::test]
async fn reality_wrong_public_key_fails() {
    let peer = Arc::new(peer_key());
    let addr = spawn_peer(peer.clone(), Arc::new(AtomicUsize::new(0))).await;
    // 另一把 x25519 密钥当「错误公钥」
    let wrong = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let connector = reality_connector(
        addr,
        hex_encode(PublicKey::from(&wrong).as_bytes()),
        Some(SHORT_ID_HEX),
    );

    let (client, _app) = tokio::io::duplex(1024);
    let flow = make_flow(client);
    let err = connector.forward(flow).await.expect_err("错误静钥必须失败");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REALITY")
            || msg.contains("握手")
            || msg.contains("EOF")
            || msg.contains("end of file")
            || msg.contains("reset"),
        "应为握手期失败: {msg}"
    );
}

/// 验收·失败面 2：short_id 不符 → 服务端 open 成功但 short_id 比对失败
/// （常时比较面）→ 关闭连接 → 客户端握手期 EOF
#[tokio::test]
async fn reality_short_id_mismatch_fails() {
    let peer = Arc::new(peer_key());
    let addr = spawn_peer(peer.clone(), Arc::new(AtomicUsize::new(0))).await;
    let connector = reality_connector(
        addr,
        peer.public_key_hex(),
        Some("ffffffffffffffff"), // 与服务端期望不符
    );

    let (client, _app) = tokio::io::duplex(1024);
    let flow = make_flow(client);
    let err = connector
        .forward(flow)
        .await
        .expect_err("short_id 不符必须失败");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REALITY")
            || msg.contains("握手")
            || msg.contains("EOF")
            || msg.contains("end of file")
            || msg.contains("reset"),
        "应为握手期失败: {msg}"
    );
}

/// 验收·取消与资源释放：forward 任务被取消（丢弃）→ TCP 关闭 →
/// 真实对端 2s 内见连接结束（ended 计数可见，资源不悬挂）
#[tokio::test]
async fn reality_cancel_releases_connection() {
    let peer = Arc::new(peer_key());
    let ended = Arc::new(AtomicUsize::new(0));
    let addr = spawn_peer(peer.clone(), ended.clone()).await;
    let connector = reality_connector(addr, peer.public_key_hex(), Some(SHORT_ID_HEX));

    let (client, mut app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(client);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    // 标记流写入即代表 forward 已过握手进入拷贝面（回环 RTT 极短）
    app.write_all(b"cancel-marker").await.expect("标记写入");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 取消（任务丢弃 = 连接丢弃）
    task.abort();

    // 资源释放：连接结束计数在 2s 内增加（服务面读到 EOF/重置退出）
    let before = ended.load(Ordering::SeqCst);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "对端 2s 内应见连接结束（资源释放）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
