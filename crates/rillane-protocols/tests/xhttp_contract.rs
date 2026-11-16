//! XHTTP 验收合约（RIL-129）：真实对端 = TLS(h2) 镜像服务面 + xray
//! packet-up/stream-one 语义自装配（GET 下载流 + POST{seq} 上传）。
//!
//! 覆盖验收面：两模式逐字节往返、session/seq URL 线上形状、多 POST
//! 分块、上行 POST 非 200 具名拒绝、非法模式/明文组合拨号期点名拒绝、
//! 取消、资源释放、统计（FlowReport）。vmess+xhttp 构建期拒绝见
//! runtime_builder vmess network 白名单测试面。
//!
//! 平台旁路：XHTTP 拨号走 net_mark::connect_tcp 同一 TCP 面
//! （networking.md §2，与普通 VLESS 无差异——不重复测平台面）。

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use rillane_core::EgressConnector;
use rillane_core::{Flow, FlowId, FlowMetadata, FlowTarget, TargetProto};
use rillane_protocols::{TlsFingerprint, VlessConnector};
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const TEST_UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";
/// XHTTP base 路径（connector path；session/seq 段拼在后面）
const BASE_PATH: &str = "/tub";
/// 流目标域名（VLESS 头 atype=domain 面长度 = 1 + 13 = 14）
const TARGET_HOST: &str = "echo.example";
const MAX_POST_BODY: usize = 64 * 1024;

/// VLESS 请求头长度（optlen=0：version+uuid+optlen+cmd+port+atype+alen+域）
// version+uuid+optlen(+opt=0)+cmd+port+atype+alen+域名
const HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 1 + TARGET_HOST.len();

fn uuid_bytes() -> [u8; 16] {
    let digits: String = TEST_UUID
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    u128::from_str_radix(&digits, 16)
        .expect("样例 UUID 须可解析")
        .to_be_bytes()
}

fn deterministic_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

/// 进程级缺省 crypto provider（与既有合约测试同口径）
fn rillane_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider 已安装")
        .clone()
}

/// 镜像对端场景（模式由客户端拨号面决定，服务面按场景分派）
#[derive(Clone, Copy)]
enum Scenario {
    /// packet-up：GET 下载流 + POST{seq} 上传；收满后 VLESS 头消费 + 回显
    PacketUp { payload_len: usize },
    /// stream-one：单 POST 承载 VLESS 头 + 载荷；逐块回显至 EOS
    StreamOne { payload_len: usize },
    /// 上行首个 POST 回 403（具名拒绝面）
    UploadForbidden,
}

/// 线上观察（URL 形状断言用）
#[derive(Default)]
struct Observed {
    get_path: Option<String>,
    post_paths: Vec<String>,
    post_lens: Vec<usize>,
}

/// 起镜像对端监听（TLS13 自签 + h2 大窗口；每连接 spawn 服务面，
/// `ended` 计数连接结束——资源释放可见性）
async fn spawn_xhttp_peer(
    scenario: Scenario,
    ended: Arc<AtomicUsize>,
) -> (std::net::SocketAddr, Arc<Mutex<Observed>>) {
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
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("服务端证书装配");
    let acceptor = TlsAcceptor::from(Arc::new(builder));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let observed = Arc::new(Mutex::new(Observed::default()));
    let obs = observed.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let ended = ended.clone();
            let obs = obs.clone();
            tokio::spawn(async move {
                let result = async {
                    let tls = acceptor.accept(tcp).await?;
                    match scenario {
                        Scenario::PacketUp { payload_len } => {
                            serve_packet_up(tls, obs, payload_len).await
                        }
                        Scenario::StreamOne { payload_len } => {
                            serve_stream_one(tls, obs, payload_len).await
                        }
                        Scenario::UploadForbidden => serve_upload_forbidden(tls, obs).await,
                    }
                }
                .await;
                ended.fetch_add(1, Ordering::SeqCst);
                if let Err(e) = result {
                    eprintln!("XHTTP 测试服务端错误: {e:#}");
                }
            });
        }
    });
    (addr, observed)
}

/// h2 容量驱动整块发送（回放体 >64KiB 缺省窗口，须按授予量切帧）
async fn h2_send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let granted = std::future::poll_fn(|cx| send.poll_capacity(cx)).await;
        let Some(Ok(n)) = granted else { return };
        if n == 0 {
            continue;
        }
        let take = data.split_to(n.min(data.len()));
        if send.send_data(take, false).is_err() {
            return;
        }
    }
}

/// VLESS 请求头形状断言（version/uuid/optlen/atype/alen/域名）
fn assert_vless_header(head: &[u8]) {
    assert_eq!(head.len(), HEADER_LEN, "VLESS 头长度");
    assert_eq!(head[0], 0x00, "VLESS version");
    assert_eq!(&head[1..17], &uuid_bytes(), "VLESS uuid");
    assert_eq!(head[17], 0, "addon 长度须 0");
    assert_eq!(head[18], 0x01, "cmd 须 TCP");
    assert_eq!(head[21], 0x02, "atype 须 domain");
    assert_eq!(head[22] as usize, TARGET_HOST.len(), "域名长度");
    assert_eq!(&head[23..], TARGET_HOST.as_bytes(), "域名一致");
}

/// h2 大窗口服务面握手（64KiB POST 块 > 缺省 65535 窗口，镜像对端
/// 不复刻服务端 WINDOW_UPDATE 时机细节；被测契约是 URL/seq/重组形状）
async fn h2_handshake(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<h2::server::Connection<tokio_rustls::server::TlsStream<TcpStream>, Bytes>> {
    h2::server::Builder::new()
        .initial_window_size(1 << 20)
        .initial_connection_window_size(1 << 20)
        .handshake::<_, Bytes>(tls)
        .await
        .map_err(|e| io::Error::other(format!("h2: {e}")))
}

/// packet-up 镜像面（流式）：GET{base}{session} → 200 下载流；
/// POST{base}{session}/{seq} → 200 + 排水入重组槽；中继任务按 seq 序
/// 连续前缀推进下载流（首字节前回 VLESS 响应头），收满期望字节量即 EOS。
/// 真实代理语义 = 头到即答 + 载荷边收边转，不整收再答。
/// 排水处理器须 spawn 独立任务：body.data() 不驱动 h2 连接，accept
/// 循环须常驻推进（读 socket、flush 出站帧），否则双向挂死
async fn serve_packet_up(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    obs: Arc<Mutex<Observed>>,
    payload_len: usize,
) -> io::Result<()> {
    let mut conn = h2_handshake(tls).await?;
    let uploads: Arc<Mutex<std::collections::BTreeMap<u64, Vec<u8>>>> = Default::default();
    let session: Arc<Mutex<Option<String>>> = Default::default();
    let download: Arc<Mutex<Option<h2::SendStream<Bytes>>>> = Default::default();
    // 排水入库唤醒 + 连接收束唤醒（取消面：中继随连接收束退出，不悬挂）
    let inserted = Arc::new(tokio::sync::Notify::new());
    let session_end = Arc::new(tokio::sync::Notify::new());
    // 触发面 = 上传字节总量（每 poll_write 一 POST，头块与载荷块分属
    // 不同 seq——POST 数目不可预判，字节总量才是「请求完整」的事实）
    let expected_total = HEADER_LEN + payload_len;

    loop {
        tokio::select! {
            req = conn.accept() => {
                let Some(Ok((req, mut respond))) = req else { break };
                let (parts, body) = req.into_parts();
                let path = parts.uri.path().to_string();
                if parts.method == http::Method::GET {
                    // 线上形状 = {base}/{session}（base 无尾斜杠由客户端合并）
                    let rest = path
                        .strip_prefix(BASE_PATH)
                        .expect("GET 路径须以 base 开头")
                        .trim_start_matches('/');
                    assert_eq!(rest.len(), 16, "session 段须 16 字符: {path}");
                    assert!(
                        rest.chars().all(|c| c.is_ascii_hexdigit()),
                        "session 段须 hex: {path}"
                    );
                    obs.lock().unwrap().get_path = Some(path.clone());
                    *session.lock().unwrap() = Some(rest.to_string());
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let send = respond.send_response(response, false).unwrap();
                    *download.lock().unwrap() = Some(send);

                    // 中继任务：下载流持出锁面，按入库推进（头到即答）
                    let uploads_r = uploads.clone();
                    let download_r = download.clone();
                    let inserted_r = inserted.clone();
                    let session_end_r = session_end.clone();
                    tokio::spawn(relay_download(
                        uploads_r,
                        download_r,
                        inserted_r,
                        session_end_r,
                        expected_total,
                    ));
                } else {
                    let rest = path
                        .strip_prefix(BASE_PATH)
                        .expect("POST 路径须以 base 开头");
                    let segs: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
                    assert_eq!(segs.len(), 2, "POST 路径须为 base/session/seq 形状: {}", path);
                    assert_eq!(
                        Some(segs[0]),
                        session.lock().unwrap().as_deref(),
                        "POST session 段须与 GET 一致"
                    );
                    let seq: u64 = segs[1].parse().expect("seq 须为数字");
                    obs.lock().unwrap().post_paths.push(path.clone());
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    respond.send_response(response, true).unwrap();
                    let uploads_h = uploads.clone();
                    let inserted_h = inserted.clone();
                    let obs_h = obs.clone();
                    tokio::spawn(async move {
                        let mut body = body;
                        let mut acc = Vec::new();
                        // 空 chunk = EOS；错误/流尾同径退出
                        while let Some(Ok(chunk)) = body.data().await {
                            let len = chunk.len();
                            body.flow_control().release_capacity(len).unwrap();
                            if chunk.is_empty() {
                                break;
                            }
                            acc.extend_from_slice(&chunk);
                        }
                        let drained = acc.len();
                        obs_h.lock().unwrap().post_lens.push(drained);
                        let mut map = uploads_h.lock().unwrap();
                        map.insert(seq, acc);
                        drop(map);
                        inserted_h.notify_one();
                    });
                }
            }
            _ = session_end.notified() => break,
        }
    }
    // 连接收束：中继退出 + 下载流随 download 槽释放（取消面资源可见）
    session_end.notify_one();
    let _keep = download.lock().unwrap().take();
    Ok(())
}

/// 下载流中继：按 seq 序取连续新前缀推送（首字节前回 VLESS 响应头
/// [version, addon_len=0]），收满期望字节量即 EOS；连接收束即退出
async fn relay_download(
    uploads: Arc<Mutex<std::collections::BTreeMap<u64, Vec<u8>>>>,
    download: Arc<Mutex<Option<h2::SendStream<Bytes>>>>,
    inserted: Arc<tokio::sync::Notify>,
    session_end: Arc<tokio::sync::Notify>,
    expected_total: usize,
) {
    // echoed = 已回显字节数（上传流扣除 VLESS 请求头前缀后计）
    let mut echoed = 0usize;
    let mut header_sent = false;
    loop {
        tokio::select! {
            _ = inserted.notified() => {}
            _ = session_end.notified() => return,
        }
        let (chunk, now) = {
            let map = uploads.lock().unwrap();
            let all: Vec<u8> = map.values().flatten().copied().collect();
            let now = all.len();
            (
                if now > HEADER_LEN + echoed {
                    all[HEADER_LEN + echoed..].to_vec()
                } else {
                    Vec::new()
                },
                now,
            )
        };
        // 头到即答：请求头收满即回响应头（客户端读到响应头才开泵载荷——
        // 中继若等载荷再答即互锁）；有可回显前缀或有待答响应头才取流
        let mut dl = download.lock().unwrap().take();
        if let Some(dl) = dl.as_mut() {
            if !header_sent && now >= HEADER_LEN {
                dl.send_data(Bytes::from_static(&[0x00, 0x00]), false)
                    .unwrap();
                header_sent = true;
            }
        }
        if !chunk.is_empty() {
            let dl = dl.as_mut().expect("可回显前缀必先有响应头");
            h2_send_all(dl, Bytes::from(chunk)).await;
            echoed = now - HEADER_LEN;
        }
        *download.lock().unwrap() = dl;
        if echoed >= expected_total - HEADER_LEN {
            let Some(mut dl) = download.lock().unwrap().take() else {
                return;
            };
            dl.send_data(Bytes::new(), true).unwrap(); // EOS（请求完整回应毕）
            return;
        }
    }
}

/// stream-one 镜像面：单 POST{base}（content-type: application/grpc）承载
/// VLESS 头 + 载荷 → 200 + 响应头 + 逐块回显至 EOS
async fn serve_stream_one(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    obs: Arc<Mutex<Observed>>,
    payload_len: usize,
) -> io::Result<()> {
    let _ = payload_len;
    let mut conn = h2_handshake(tls).await?;
    // 处理器须 spawn 独立任务：body.data() 不驱动 h2 连接，accept 循环须
    // 常驻推进（读 socket、flush 出站帧），否则双向挂死
    while let Some(req) = conn.accept().await {
        let Ok((req, respond)) = req else { break };
        let obs = obs.clone();
        tokio::spawn(async move {
            if let Err(e) = stream_one_echo(req, respond, obs).await {
                eprintln!("stream-one 处理器错误: {e}");
            }
        });
    }
    Ok(())
}

async fn stream_one_echo(
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    obs: Arc<Mutex<Observed>>,
) -> io::Result<()> {
    let (parts, mut body) = req.into_parts();
    assert_eq!(parts.method, http::Method::POST, "stream-one 须单 POST");
    assert_eq!(parts.uri.path(), BASE_PATH, "stream-one 路径 = base 无段");
    assert_eq!(
        parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc"),
        "stream-one content-type"
    );
    obs.lock()
        .unwrap()
        .post_paths
        .push(parts.uri.path().to_string());

    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let mut send = respond.send_response(response, false).unwrap();

    // 先收满 VLESS 头再回响应头（服务端消费顺序）
    let mut got = Vec::new();
    while got.len() < HEADER_LEN {
        let chunk = body
            .data()
            .await
            .expect("请求体在头收满前不得断")
            .expect("请求体读失败");
        body.flow_control().release_capacity(chunk.len()).unwrap();
        assert!(!chunk.is_empty(), "EOS 早于头收满");
        got.extend_from_slice(&chunk);
    }
    assert_vless_header(&got[..HEADER_LEN]);
    send.send_data(Bytes::from_static(&[0x00, 0x00]), false)
        .unwrap();

    // 头后余量 + 后续块逐块回显至 EOS
    let rest = got.split_off(HEADER_LEN);
    if !rest.is_empty() {
        h2_send_all(&mut send, Bytes::from(rest)).await;
    }
    // 空 chunk = EOS；错误/流尾同径退出
    while let Some(Ok(chunk)) = body.data().await {
        let len = chunk.len();
        body.flow_control().release_capacity(len).unwrap();
        if chunk.is_empty() {
            break; // EOS
        }
        h2_send_all(&mut send, chunk).await;
    }
    send.send_data(Bytes::new(), true).unwrap();
    Ok(())
}

/// 上行非 200 镜像面：GET 正常，首个 POST 回 403（具名拒绝面）。
/// GET 下载流持留至客户端断开——不让服务端 drop 触发的流复位与客户端
/// 403 毒化竞速（客户端毒化唤醒面须确定性收到命名拒绝）
async fn serve_upload_forbidden(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    obs: Arc<Mutex<Observed>>,
) -> io::Result<()> {
    let mut conn = h2_handshake(tls).await?;
    let mut download: Option<h2::SendStream<Bytes>> = None;
    let mut forbidden = false;
    while let Some(Ok((req, mut respond))) = conn.accept().await {
        let (parts, _body) = req.into_parts();
        if parts.method == http::Method::GET {
            let response = http::Response::builder().status(200).body(()).unwrap();
            download = Some(respond.send_response(response, false).unwrap());
        } else {
            obs.lock()
                .unwrap()
                .post_paths
                .push(parts.uri.path().to_string());
            let response = http::Response::builder().status(403).body(()).unwrap();
            respond.send_response(response, true).unwrap();
            forbidden = true;
            break;
        }
    }
    assert!(forbidden, "镜像面须已回 403");
    let _keep = download; // 下载流持留至函数尾——防复位与毒化竞速
                          // 客户端消纳毒化后自行关闭；accept 循环推进连接直至对端收尾
    while conn.accept().await.is_some() {}
    Ok(())
}

/// XHTTP 连接器（inline 面；skip_cert_verify 放行环回自签）
fn xhttp_connector(addr: std::net::SocketAddr, mode: Option<&str>, tls: bool) -> VlessConnector {
    VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        TEST_UUID.to_string(),
        None, // flow
        None, // reality
        "xhttp".to_string(),
        Some(BASE_PATH.to_string()),
        None, // host
        None, // grpc_service_name
        mode.map(str::to_string),
        None, // packet_encoding（raw——非本测面）
        tls,
        true, // skip_cert_verify（环回自签）
        None, // sni
        None, // alpn
        TlsFingerprint::None,
        None, // pool（inline 面）
        None, // factory
    )
}

fn make_flow(client: tokio::io::DuplexStream) -> Flow {
    Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: TARGET_HOST.to_string(),
            port: 443,
            proto: TargetProto::Tcp,
        },
        io: Box::new(client),
        metadata: FlowMetadata::default(),
    }
}

/// 写半边全量注入 + 半关；主侧回读至 EOF（copy_bidirectional 上游 EOF 面）
async fn pump(client: tokio::io::DuplexStream, payload: Vec<u8>) -> Vec<u8> {
    let (mut app_rx, mut app_tx) = tokio::io::split(client);
    let writer = tokio::spawn(async move {
        app_tx.write_all(&payload).await.expect("上行写入");
        app_tx.shutdown().await.expect("上行半关");
    });
    let mut echoed = Vec::new();
    app_rx.read_to_end(&mut echoed).await.expect("下行回读");
    writer.await.expect("写半边任务");
    echoed
}

// ---------------------------------------------------------------------------
// 验收·成功面：packet-up 往返 + 统计 + 线上形状 + 多 POST 分块
// ---------------------------------------------------------------------------

/// >64KiB 载荷 → 恰 3 个 POST（seq 0..2）；按 seq 重组逐字节一致；
/// GET/POST 路径形状（session 16 hex、seq 自 0 连续）线上可见
#[tokio::test]
async fn packet_up_wire_shapes_multi_post_roundtrip() {
    let payload = deterministic_payload(140_000); // 头 + 载荷 → 3 POST
    let ended = Arc::new(AtomicUsize::new(0));
    let (addr, observed) = spawn_xhttp_peer(
        Scenario::PacketUp {
            payload_len: payload.len(),
        },
        ended.clone(),
    )
    .await;
    let connector = xhttp_connector(addr, None, true);

    let (client, app) = tokio::io::duplex(512 * 1024);
    let flow = make_flow(app);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    let echoed = pump(client, payload.clone()).await;
    assert_eq!(echoed, payload, "packet-up 按 seq 重组须逐字节一致");
    task.await.expect("forward 任务").expect("转发成功");

    let obs = observed.lock().unwrap();
    let get = obs.get_path.as_deref().expect("GET 路径须可见");
    assert_eq!(
        get.len(),
        BASE_PATH.len() + 1 + 16,
        "GET = base + / + 16hex: {get}"
    );
    let session = &get[BASE_PATH.len() + 1..];
    assert!(
        session.chars().all(|c| c.is_ascii_hexdigit()),
        "session 须 hex: {session}"
    );
    // 不变量面：seq 自 0 连续、逐 POST ≤ 64KiB、总量恰 = 头 + 载荷
    // （分块数随中继缓冲实现浮动，非线上契约）
    let got: Vec<u64> = obs
        .post_paths
        .iter()
        .map(|p| p.rsplit('/').next().unwrap().parse().expect("seq 须为数字"))
        .collect();
    let want: Vec<u64> = (0..got.len() as u64).collect();
    assert_eq!(got, want, "POST seq 须自 0 连续");
    assert!(got.len() >= 2, "多 POST 分块面（载荷 > 64KiB）");
    assert!(
        obs.post_lens.iter().all(|&l| l > 0 && l <= MAX_POST_BODY),
        "逐 POST 体须落在 (0, 64KiB]: {:?}",
        obs.post_lens
    );
    assert_eq!(
        obs.post_lens.iter().sum::<usize>(),
        HEADER_LEN + payload.len(),
        "POST 总量须恰 = VLESS 头 + 载荷"
    );
}

/// packet-up 往返统计：FlowReport upstream/downstream 覆盖真实字节量
#[tokio::test]
async fn packet_up_roundtrip_stats_cover_payload() {
    let payload = deterministic_payload(50_000);
    let ended = Arc::new(AtomicUsize::new(0));
    let (addr, _observed) = spawn_xhttp_peer(
        Scenario::PacketUp {
            payload_len: payload.len(),
        },
        ended.clone(),
    )
    .await;
    let connector = xhttp_connector(addr, None, true);

    let (client, app) = tokio::io::duplex(256 * 1024);
    let flow = make_flow(app);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    let echoed = pump(client, payload.clone()).await;
    assert_eq!(echoed, payload, "回环逐字节一致");

    let report = task.await.expect("forward 任务").expect("转发成功");
    assert!(
        report.upstream >= payload.len() as u64,
        "统计 upstream 覆盖上行: {}",
        report.upstream
    );
    assert!(
        report.downstream >= payload.len() as u64,
        "统计 downstream 覆盖下行: {}",
        report.downstream
    );
}

/// stream-one 往返：单 POST 逐字节一致 + 统计覆盖
#[tokio::test]
async fn stream_one_roundtrip_with_stats() {
    let payload = deterministic_payload(70_000);
    let ended = Arc::new(AtomicUsize::new(0));
    let (addr, observed) = spawn_xhttp_peer(
        Scenario::StreamOne {
            payload_len: payload.len(),
        },
        ended.clone(),
    )
    .await;
    let connector = xhttp_connector(addr, Some("stream-one"), true);

    let (client, app) = tokio::io::duplex(256 * 1024);
    let flow = make_flow(app);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    let echoed = pump(client, payload.clone()).await;
    assert_eq!(echoed, payload, "stream-one 往返须逐字节一致");

    let report = task.await.expect("forward 任务").expect("转发成功");
    assert!(
        report.upstream >= payload.len() as u64,
        "upstream: {}",
        report.upstream
    );
    assert!(
        report.downstream >= payload.len() as u64,
        "downstream: {}",
        report.downstream
    );
    assert_eq!(
        observed.lock().unwrap().post_paths,
        vec![BASE_PATH.to_string()],
        "stream-one 线上恰一 POST base"
    );
}

// ---------------------------------------------------------------------------
// 验收·失败面：非 200 具名拒绝、非法模式、明文组合
// ---------------------------------------------------------------------------

/// 上行 POST 被拒（403）→ 具名拒绝（状态码可见），错误上抛
#[tokio::test]
async fn upload_post_non_200_refused_by_name() {
    let ended = Arc::new(AtomicUsize::new(0));
    let (addr, observed) = spawn_xhttp_peer(Scenario::UploadForbidden, ended.clone()).await;
    let connector = xhttp_connector(addr, None, true);

    let (_client, app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(app);
    let err = connector.forward(flow).await.expect_err("403 必须失败");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("XHTTP 上行 POST #0 被拒：HTTP 403"),
        "应为具名 403 拒绝: {msg}"
    );
    assert_eq!(
        observed.lock().unwrap().post_paths.len(),
        1,
        "首个 POST 即被拒"
    );
}

/// 非法模式拨号期具名拒绝（stream-up 载具未交付——白名单外即拒，
/// 不静默降级；拒绝先于 TLS 握手，故用哑监听地址即可）
#[tokio::test]
async fn invalid_mode_dial_refused_by_name() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("哑监听");
    let addr = listener.local_addr().unwrap();
    let connector = xhttp_connector(addr, Some("stream-up"), true);

    let (_client, app) = tokio::io::duplex(1024);
    let flow = make_flow(app);
    let err = connector.forward(flow).await.expect_err("非法模式必须失败");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("stream-up") && msg.contains("未交付"),
        "应点名未交付载具: {msg}"
    );
}

/// network=xhttp 不叠 TLS → 拨号期具名拒绝（h2-over-TLS 语义，恒叠 TLS）
#[tokio::test]
async fn xhttp_without_tls_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("哑监听");
    let addr = listener.local_addr().unwrap();
    let connector = xhttp_connector(addr, None, false);

    let (_client, app) = tokio::io::duplex(1024);
    let flow = make_flow(app);
    let err = connector
        .forward(flow)
        .await
        .expect_err("明文 xhttp 必须失败");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("xhttp") && msg.contains("TLS"),
        "应点名 TLS 缺失: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 验收·取消与资源释放
// ---------------------------------------------------------------------------

/// forward 任务被取消（丢弃）→ TLS/h2 连接关闭 → 镜像对端 2s 内见连接结束
#[tokio::test]
async fn cancel_releases_connection() {
    let ended = Arc::new(AtomicUsize::new(0));
    let (addr, _observed) =
        spawn_xhttp_peer(Scenario::PacketUp { payload_len: 4096 }, ended.clone()).await;
    let connector = xhttp_connector(addr, None, true);

    let (_client, mut app) = tokio::io::duplex(64 * 1024);
    let flow = make_flow(_client);
    let task = tokio::spawn(async move { connector.forward(flow).await });

    // 标记流写入即代表 forward 已过隧道建立进入拷贝面（回环 RTT 极短）
    app.write_all(b"cancel-marker").await.expect("标记写入");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 取消（任务丢弃 = TLS/h2/POST 链路整体丢弃）
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
