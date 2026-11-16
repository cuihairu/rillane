//! XTLS Vision（xtls-rprx-vision）验收合约（RIL-108）：真实对端 = rustls
//! TLS 服务端面（rcgen 自签 / fork REALITY 服务端）× xray 同语义回显面
//! （线规格独立实现：UUID 门控 + `[command, clen, plen]` + content +
//! padding 组帧；服务端写规则同构——回显内容含完整内层 ApplicationData
//! 记录即发 Direct 并切裸传）。
//!
//! 覆盖验收面：成功（TLS1.3 内层 → Direct 裸传切换往返；非 TLS → End
//! 留在外层 TLS 内往返）、统计（FlowReport 字节口径）、取消、资源释放、
//! 不支持组合明确拒绝（外层 TLS1.2 命名拒绝、UDP+vision 拒绝）。
//! 平台旁路：拨号走 net_mark::connect_tcp 同一 TCP 面（与普通 VLESS
//! 无差异，不重复测平台面）。

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rillane_config::RealityConfig;
use rillane_core::udp::EgressUdpConnector;
use rillane_core::EgressConnector;
use rillane_core::{
    Flow, FlowContext, FlowId, FlowMetadata, FlowTarget, RouteDecision, TargetProto,
};
use rillane_protocols::outbound::{
    derive_auth_key, extract_client_random, extract_session_id, extract_x25519_key_share,
    handshake, hmac_cert_tag, open_session_id, zero_session_id_slot, FrameDecoder, VisionSignal,
    CORE_VERSION,
};
use rillane_protocols::{TlsFingerprint, VlessConnector, VlessUdpConnector};
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey, StaticSecret};

const TEST_UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";
const SHORT_ID_HEX: &str = "0102030405060708";
const PEER_SNI: &str = "target.example";

/// 请求 addons（xray Addons protobuf：`0x0A 0x10` + flow 串）
fn vision_addons() -> Vec<u8> {
    let mut opt = vec![0x0A, 0x10];
    opt.extend_from_slice(b"xtls-rprx-vision");
    opt
}

fn uuid_bytes() -> [u8; 16] {
    *uuid::Uuid::parse_str(TEST_UUID)
        .expect("测试 uuid")
        .as_bytes()
}

fn rillane_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider 已安装")
        .clone()
}

// ---------------------------------------------------------------------------
// 内层 TLS 形流量构造（触发过滤窗嗅探面：CH → is_tls；SH+TLS1.3 扩展 →
// EnableXtls；完整 ApplicationData 记录 → Direct）
// ---------------------------------------------------------------------------

fn inner_ch() -> Vec<u8> {
    // 记录头 [0x16,0x03,0x01,len_hi,len_lo] + 握手类型 0x01 + 32B 主体
    let mut r = vec![0x16, 0x03, 0x01, 0x00, 0x21, 0x01];
    r.resize(5 + 33, 0xA5);
    r
}

fn inner_sh_tls13() -> Vec<u8> {
    // 记录头 [0x16,0x03,0x03,len] + 握手类型 0x02 + 主体（尾部内嵌
    // TLS1.3 supported_versions 扩展字节 [00 2b 00 02 03 04]）
    let body_len = 40;
    let mut r = vec![0x16, 0x03, 0x03, 0x00, body_len as u8, 0x02];
    r.resize(5 + body_len, 0x5A);
    let ext_start = r.len();
    r[ext_start - 6..ext_start].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    r
}

fn inner_appdata(payload: &[u8]) -> Vec<u8> {
    // 完整内层 ApplicationData 记录：`17 03 03` + 长度自洽
    let mut r = vec![0x17, 0x03, 0x03];
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}

// ---------------------------------------------------------------------------
// 服务端回显面（线规格独立实现——不经被测 crate 的 FrameBuilder）
// ---------------------------------------------------------------------------

const CMD_CONTINUE: u8 = 0x00;
const CMD_DIRECT: u8 = 0x02;

/// 服务端帧组装（首帧前置一次 UUID；padding 恒 0——xray rand 可为 0，
/// 客户端解码器必须兼容）
fn server_frame(cmd: u8, content: &[u8], uuid_once: &mut Option<[u8; 16]>) -> Vec<u8> {
    let mut f = Vec::with_capacity(21 + content.len());
    if let Some(u) = uuid_once.take() {
        f.extend_from_slice(&u);
    }
    f.push(cmd);
    f.extend_from_slice(&(content.len() as u16).to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(content);
    f
}

/// 完整内层 ApplicationData 记录判定（独立实现：`17 03 03` 起，逐记录
/// 长度自洽恰好耗尽）
fn sees_complete_appdata(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if bytes[i] != 0x17 || bytes[i + 1] != 0x03 || bytes[i + 2] != 0x03 {
            return false;
        }
        let len = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
        i += 5 + len;
    }
    i == bytes.len() && !bytes.is_empty()
}

/// VLESS 请求头读取（校验 Opt 恰携 vision addons——xray 服务端按名
/// 期望分帧的镜像面）
async fn read_vless_vision_request<S: AsyncRead + Unpin>(r: &mut S) -> io::Result<()> {
    let mut head = [0u8; 18];
    r.read_exact(&mut head).await?;
    if head[0] != 0x00 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "版本非 0"));
    }
    let opt_len = head[17] as usize;
    let mut opt = vec![0u8; opt_len];
    r.read_exact(&mut opt).await?;
    if opt != vision_addons() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Opt 未携 vision addons",
        ));
    }
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
                format!("非法 atype: {other}"),
            ));
        }
    };
    let mut addr = vec![0u8; addr_len];
    r.read_exact(&mut addr).await?;
    Ok(())
}

/// Direct 切换后的裸传驱动面（外层 TLS 记录态之外的原始 TCP）——
/// xray 切裸后读写不再经 TLS 记录态，测试服务端镜像同口径。
trait VisionRawTap {
    fn raw(&mut self) -> &mut TcpStream;
}

impl VisionRawTap for tokio_rustls::server::TlsStream<TcpStream> {
    fn raw(&mut self) -> &mut TcpStream {
        self.get_mut().0
    }
}

impl VisionRawTap for rillane_protocols::outbound::TlsAdapter<rustls::ServerConnection> {
    fn raw(&mut self) -> &mut TcpStream {
        self.tcp_mut()
    }
}

/// xray 同语义 Vision 回显：解码客户端帧 → 回显（完整内层 ApplicationData
/// 记录 → Direct 帧并切裸传；End 后客户端明文 → 原样经外层 TLS 回显）。
async fn vision_echo<S: AsyncRead + AsyncWrite + Unpin + VisionRawTap>(
    s: &mut S,
    uuid: [u8; 16],
) -> io::Result<()> {
    read_vless_vision_request(s).await?;
    s.write_all(&[0x00, 0x00]).await?;
    s.flush().await?;

    let mut uuid_once = Some(uuid);
    let mut decoder = FrameDecoder::new(uuid);
    let mut raw = false;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = if raw {
            // 裸态读写原始 TCP（EOF 即干净断开，不再有 TLS 记录）
            s.raw().read(&mut buf).await?
        } else {
            s.read(&mut buf).await?
        };
        if n == 0 {
            break;
        }
        if raw {
            s.raw().write_all(&buf[..n]).await?;
            s.raw().flush().await?;
            continue;
        }
        let signal = decoder.push(&buf[..n]);
        let decoded = decoder.take();
        // 服务端写向一律 Continue 分帧（End 只解客户端来向的分帧，服务端
        // 自身写向按 xray XtlsPadding 继续 padding，直至自身过滤窗见完整
        // 内层 ApplicationData 记录才 Direct 并切裸传）
        if !decoded.is_empty() {
            if sees_complete_appdata(&decoded) {
                let frame = server_frame(CMD_DIRECT, &decoded, &mut uuid_once);
                s.write_all(&frame).await?;
                s.flush().await?;
                raw = true;
            } else {
                let frame = server_frame(CMD_CONTINUE, &decoded, &mut uuid_once);
                s.write_all(&frame).await?;
                s.flush().await?;
            }
        }
        match signal {
            VisionSignal::Direct => raw = true,
            // Plain（End 后客户端明文）只改来向读面，写向分帧不变
            VisionSignal::Plain | VisionSignal::Frames => {}
        }
    }
    if raw {
        s.raw().shutdown().await?;
    } else {
        s.shutdown().await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 普通 TLS 服务端面（rcgen 自签；TLS1.3 常规 / TLS1.2 拒绝面变体）
// ---------------------------------------------------------------------------

async fn spawn_vision_tls_server(
    versions: &'static [&'static rustls::SupportedProtocolVersion],
    ended: Arc<AtomicUsize>,
) -> std::net::SocketAddr {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(certified.cert.pem().as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM 解析");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        certified.key_pair.serialize_pem().as_bytes(),
    )
    .expect("私钥读取");
    let builder = rustls::ServerConfig::builder_with_provider(rillane_tls_provider())
        .with_protocol_versions(versions)
        .expect("协议版本")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("服务端证书装配");
    let acceptor = TlsAcceptor::from(Arc::new(builder));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let ended = ended.clone();
            tokio::spawn(async move {
                let result = async {
                    let mut tls = acceptor.accept(tcp).await?;
                    vision_echo(&mut tls, uuid_bytes()).await
                }
                .await;
                ended.fetch_add(1, Ordering::SeqCst);
                if let Err(e) = result {
                    eprintln!("Vision 测试服务端错误: {e:#}");
                }
            });
        }
    });
    addr
}

const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

/// Vision 连接器（普通 TLS 面；sni 缺省 = server 地址，SAN=localhost
/// 由 skip_cert_verify 放行）
fn vision_tls_connector(addr: std::net::SocketAddr) -> VlessConnector {
    VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        TEST_UUID.to_string(),
        Some("xtls-rprx-vision".to_string()),
        None,
        "tcp".to_string(),
        None,
        None,
        None,
        true,
        true, // 环回自签证书
        None,
        None,
        TlsFingerprint::None,
        None,
        None,
    )
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

// ---------------------------------------------------------------------------
// 验收·成功面：TLS1.3 内层 → Direct 裸传切换往返 + 统计
// ---------------------------------------------------------------------------

/// 锁步驱动（每次写一个包、等回显到齐再写下一个——保证过滤窗逐包
/// 观察序与真实 TLS 连接一致，不依赖调度时序）
#[tokio::test]
async fn vision_tls13_inner_direct_switch_roundtrip_with_stats() {
    let ended = Arc::new(AtomicUsize::new(0));
    let addr = spawn_vision_tls_server(TLS13_ONLY, ended.clone()).await;
    let connector = vision_tls_connector(addr);

    let (client, mut app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(client);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    let ch = inner_ch();
    let sh = inner_sh_tls13();
    let app_rec = inner_appdata(&[0xAB; 48]);
    let trailing = inner_appdata(&[0xCD; 32]);

    // 锁步：CH（Continue 帧）→ SH（置位 EnableXtls）→ 完整 AppData
    // 记录（Direct 帧 + 双向切裸传）→ 裸传尾包
    app.write_all(&ch).await.expect("写 CH");
    let mut echoed = vec![0u8; ch.len()];
    app.read_exact(&mut echoed).await.expect("CH 回显");
    assert_eq!(echoed, ch, "CH 回环一致");

    app.write_all(&sh).await.expect("写 SH");
    let mut echoed = vec![0u8; sh.len()];
    app.read_exact(&mut echoed).await.expect("SH 回显");
    assert_eq!(echoed, sh, "SH 回环一致");

    app.write_all(&app_rec).await.expect("写 AppData");
    let mut echoed = vec![0u8; app_rec.len()];
    app.read_exact(&mut echoed).await.expect("AppData 回显");
    assert_eq!(echoed, app_rec, "AppData 经 Direct 帧回环一致");

    app.write_all(&trailing).await.expect("写裸传尾包");
    let mut echoed = vec![0u8; trailing.len()];
    app.read_exact(&mut echoed).await.expect("尾包回显");
    assert_eq!(echoed, trailing, "尾包经裸传回环一致（零字节损失）");

    // 上行半关 → 服务端收束 → 下行 EOF → 中继返回统计
    drop(app);
    let report = task.await.expect("forward 任务").expect("转发成功");
    let total = (ch.len() + sh.len() + app_rec.len() + trailing.len()) as u64;
    assert_eq!(report.upstream, total, "上行统计 = 应用字节");
    assert_eq!(report.downstream, total, "下行统计 = 回显字节");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "服务端 2s 内应见连接收束（资源释放）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// 验收·成功面：非 TLS 内层 → End 收束（全程留在外层 TLS 之内）往返
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vision_tls_end_path_roundtrip_non_tls() {
    let ended = Arc::new(AtomicUsize::new(0));
    let addr = spawn_vision_tls_server(TLS13_ONLY, ended.clone()).await;
    let connector = vision_tls_connector(addr);

    let (client, mut app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(client);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    // 16 包 × 100B 非 TLS 流量：过滤窗 8 包耗尽后 End 收束，余包直通
    let mut total = 0u64;
    for i in 0..16u16 {
        let pkt: Vec<u8> = (0..100u16).map(|j| ((i * 100 + j) % 251) as u8).collect();
        app.write_all(&pkt).await.expect("写包");
        let mut echoed = vec![0u8; pkt.len()];
        app.read_exact(&mut echoed).await.expect("包回显");
        assert_eq!(echoed, pkt, "第 {} 包回环一致", i + 1);
        total += pkt.len() as u64;
    }

    drop(app);
    let report = task.await.expect("forward 任务").expect("转发成功");
    assert_eq!(report.upstream, total, "上行统计 = 应用字节");
    assert_eq!(report.downstream, total, "下行统计 = 回显字节");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "服务端 2s 内应见连接收束（资源释放）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// 验收·失败面：外层 TLS1.2 命名拒绝（xray 同口径：握手后校验）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vision_outer_tls12_named_refusal() {
    let ended = Arc::new(AtomicUsize::new(0));
    let addr = spawn_vision_tls_server(TLS12_ONLY, ended.clone()).await;
    let connector = vision_tls_connector(addr);

    let (client, app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(client);
    let result = connector.forward(flow).await;

    let msg = format!("{:#}", result.expect_err("TLS1.2 外层应命名拒绝"));
    assert!(msg.contains("TLS1.3"), "应点名需外层 TLS1.3: {msg}");
    drop(app);
    // 服务端连接收束（拒绝后客户端断开，服务面退出）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while ended.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "服务端 2s 内应见连接结束（资源释放）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// 验收·取消面：任务丢弃 = 连接丢弃，对端可见收束（资源释放）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vision_cancel_releases_connection() {
    let ended = Arc::new(AtomicUsize::new(0));
    let addr = spawn_vision_tls_server(TLS13_ONLY, ended.clone()).await;
    let connector = vision_tls_connector(addr);

    let (client, mut app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(client);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    // 标记流写入即代表 forward 已过握手进入中继面（回环 RTT 极短）
    app.write_all(b"cancel-marker").await.expect("标记写入");
    tokio::time::sleep(Duration::from_millis(300)).await;

    task.abort();

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

// ---------------------------------------------------------------------------
// 验收·不支持组合：Vision 仅 TCP 承载——UDP 命令点名拒绝
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vision_udp_associate_named_refusal() {
    let conn = VlessConnector::new(
        "127.0.0.1".to_string(),
        1,
        TEST_UUID.to_string(),
        Some("xtls-rprx-vision".to_string()),
        None,
        "tcp".to_string(),
        None,
        None,
        None,
        true,
        true,
        None,
        None,
        TlsFingerprint::None,
        None,
        None,
    );
    let udp = VlessUdpConnector::from_connector(&conn);
    let ctx = FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: "example.com".to_string(),
            port: 443,
            proto: TargetProto::Udp,
        },
        metadata: FlowMetadata::default(),
    };
    let decision = RouteDecision::direct("test".to_string());
    let err = udp
        .associate(ctx, &decision)
        .await
        .err()
        .expect("vision UDP 应点名拒绝");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("xtls-rprx-vision") && msg.contains("TCP"),
        "应点名 vision 仅 TCP: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 验收·REALITY 组合：fork 服务端面 + Vision 分帧 e2e（Direct 往返）
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

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

/// 目标模板（fork 配方）：单步驱动普通 rustls 握手（CH → 服务端首飞），
/// 截取服务端首飞记录内 ServerHello 握手字节——PreparedServerHello 校验
/// 其形状并只替换 key share（reality_contract 同构；全测试共享一次）
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

#[derive(Debug)]
struct HmacCertSigner {
    public_key: Vec<u8>,
    tag: Vec<u8>,
}

/// rcgen 远程签名面（HMAC 证书标签即“签名”字节——与 REALITY 认证语义
/// 对齐，reality_contract 同构）
impl rcgen::RemoteKeyPair for HmacCertSigner {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.tag.clone())
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// REALITY Vision 服务面：认证 → 握手 → vision_echo（同语义回显）
async fn serve_reality_vision_peer(mut tcp: TcpStream, peer: &PeerKey) -> io::Result<()> {
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    let mut hdr = [0u8; 5];
    tcp.read_exact(&mut hdr).await?;
    if hdr[0] != 22 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非握手记录"));
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut ch = vec![0u8; len];
    tcp.read_exact(&mut ch).await?;
    let hello = ch;

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

    let mut seed = [0u8; 32];
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let ed = ed25519_dalek::SigningKey::from_bytes(&seed);
    let tag = hmac_cert_tag(&auth_key, ed.verifying_key().as_bytes());
    let signer = HmacCertSigner {
        public_key: ed.verifying_key().as_bytes().to_vec(),
        tag: tag.to_vec(),
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
    let mut template = peer_template();
    template[39..71].copy_from_slice(&sealed);
    let prepared = rustls::reality::PreparedServerHello::new(&hello, &template, &provider)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("对端准备: {e}")))?;
    let mut conn = rustls::ServerConnection::new_reality(Arc::new(server_config), prepared)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("REALITY 服务端: {e}")))?;
    let mut record = hdr.to_vec();
    record.extend_from_slice(&hello);
    conn.read_tls(&mut &record[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("CH 回灌: {e}")))?;
    conn.process_new_packets()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("CH 处理: {e}")))?;
    let mut tls = handshake(tcp, conn).await?;
    vision_echo(&mut tls, uuid_bytes()).await
}

fn peer_template() -> Vec<u8> {
    use std::sync::OnceLock;
    static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();
    TEMPLATE.get_or_init(capture_target_template).clone()
}

async fn spawn_reality_vision_peer(
    peer: Arc<PeerKey>,
    ended: Arc<AtomicUsize>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let peer = peer.clone();
            let ended = ended.clone();
            tokio::spawn(async move {
                let result = serve_reality_vision_peer(tcp, &peer).await;
                ended.fetch_add(1, Ordering::SeqCst);
                if let Err(e) = result {
                    eprintln!("REALITY Vision 服务端错误: {e:#}");
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn vision_reality_combo_direct_switch_roundtrip() {
    let peer = Arc::new(peer_key());
    let ended = Arc::new(AtomicUsize::new(0));
    let addr = spawn_reality_vision_peer(peer.clone(), ended.clone()).await;
    let connector = VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        TEST_UUID.to_string(),
        Some("xtls-rprx-vision".to_string()),
        Some(RealityConfig {
            public_key: peer.public_key_hex(),
            short_id: Some(SHORT_ID_HEX.to_string()),
        }),
        "tcp".to_string(),
        None,
        None,
        None,
        true,
        false,
        None,
        None,
        TlsFingerprint::None,
        None,
        None,
    );

    let (client, mut app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(client);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    let ch = inner_ch();
    let sh = inner_sh_tls13();
    let app_rec = inner_appdata(&[0x77; 40]);

    app.write_all(&ch).await.expect("写 CH");
    let mut echoed = vec![0u8; ch.len()];
    app.read_exact(&mut echoed).await.expect("CH 回显");
    assert_eq!(echoed, ch);

    app.write_all(&sh).await.expect("写 SH");
    let mut echoed = vec![0u8; sh.len()];
    app.read_exact(&mut echoed).await.expect("SH 回显");
    assert_eq!(echoed, sh);

    app.write_all(&app_rec).await.expect("写 AppData");
    let mut echoed = vec![0u8; app_rec.len()];
    app.read_exact(&mut echoed).await.expect("AppData 回显");
    assert_eq!(echoed, app_rec, "REALITY+Vision Direct 帧回环一致");

    drop(app);
    let report = task.await.expect("forward 任务").expect("转发成功");
    let total = (ch.len() + sh.len() + app_rec.len()) as u64;
    assert_eq!(report.upstream, total, "上行统计 = 应用字节");
    assert_eq!(report.downstream, total, "下行统计 = 回显字节");
}
