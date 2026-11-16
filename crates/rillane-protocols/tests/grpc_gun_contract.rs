//! RIL-130 gRPC gun 流复用契约（真实对端）：mock VLESS-gRPC TLS 服务端
//! （rcgen 自签 + rustls acceptor + h2 连接驱动驻留 accept 循环 + 5B 帧
//! 重组/回显 + TCP accept 计数）× `VlessConnector` network=grpc 池面
//! （gun 复用生产路径）。覆盖三面：
//!
//! 1. 复用主面：两流 ≥ 恰 1 次 TCP accept（单连接多流）+ 每流字节级
//!    echo + 路径 `/{svc}/Tun` + VLESS 请求头语义 + 池记账（复用面只
//!    池拨一次，租借随连接生命周期不还池）；
//! 2. stale 面：服务端首流回毕即断 → 次流复用面命中死连接 → 逐出 +
//!    重拨恰一次（accepts 2、池前台拨 2）；
//! 3. 取消面：中止现役流（abort + 半关）→ 流计数回落、共享连接存活 →
//!    次流照常复用同一连接（accepts 恒 1）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rillane_config::GrpcReuseConfig;
use rillane_core::EgressConnector;
use rillane_protocols::{
    PoolPolicy, TlsConnectorFactory, TlsFingerprint, TransportPool, VlessConnector,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use rustls::pki_types::pem::PemObject as _;

const UUID: &str = "b831381d-6324-4d2a-b1e7-1bf75a1db7b3";
const SERVICE: &str = "gun-svc";

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

/// low_watermark=0：关水位补充拨号——accept 计数纯归 gun 复用面
fn gun_policy() -> PoolPolicy {
    PoolPolicy {
        low_watermark: 0,
        ..pooled_policy()
    }
}

/// duplex 客户端半边 + Flow（io 为对端）
fn make_flow(host: &str, port: u16) -> (rillane_core::Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(4096);
    let flow = rillane_core::Flow {
        id: rillane_core::FlowId::new(),
        target: rillane_core::FlowTarget {
            host: host.to_string(),
            port,
            proto: rillane_core::TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

/// 往返一次并收尾：写 payload → 读回 → shutdown → join forward
async fn roundtrip_and_finish(
    mut client: tokio::io::DuplexStream,
    handle: tokio::task::JoinHandle<anyhow::Result<rillane_core::FlowReport>>,
    payload: &[u8],
) -> rillane_core::FlowReport {
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

/// 等待服务端见到 `want` 条 VLESS 请求头（长度比较用 matches! 表意，
/// 避免 clippy len_zero 口径）
async fn wait_until_header_count(headers: &Arc<std::sync::Mutex<Vec<Vec<u8>>>>, want: usize) {
    wait_until(|| matches!(headers.lock().expect("headers lock").len(), l if l >= want)).await;
}

/// 进程级 ring 安装（与 tls.rs 同法；测试 crate 不可见私有 helper，此处独立）
fn rillane_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider 已安装")
        .clone()
}

/// 单流 gRPC 处理：校验 POST /{svc}/Tun + te/content-type → 200 → 首条
/// 消息按 VLESS 请求头捕获 → 回 2B 应答头（Version=0 + OptLen=0）→ 后续
/// 消息逐条回显至 EOS、回 EOS 收尾。发送容错（取消面 RST 不炸任务）。
async fn vless_grpc_stream_task(
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    streams: Arc<AtomicUsize>,
    headers: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    path_slot: Arc<std::sync::Mutex<String>>,
) {
    assert_eq!(req.method(), http::Method::POST);
    let path = req.uri().path().to_string();
    assert_eq!(req.headers().get("te").unwrap(), "trailers");
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/grpc"
    );
    *path_slot.lock().expect("path lock") = path;
    streams.fetch_add(1, Ordering::SeqCst);

    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let Ok(mut stream) = respond.send_response(response, false) else {
        return;
    };

    // 重组 gRPC 消息（5B 前缀：旗标 + BE 长度）
    let mut body = req.into_body();
    let mut buf: Vec<u8> = Vec::new();
    let mut first = true;
    loop {
        let msg = 'extract: {
            loop {
                if buf.len() >= 5 {
                    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                    if buf.len() >= 5 + len {
                        let m = buf[5..5 + len].to_vec();
                        buf.drain(..5 + len);
                        break 'extract Some(m);
                    }
                }
                match body.data().await {
                    Some(Ok(chunk)) => {
                        let len = chunk.len();
                        body.flow_control().release_capacity(len).unwrap();
                        buf.extend_from_slice(&chunk);
                    }
                    _ => break 'extract None,
                }
            }
        };
        match msg {
            None => break,
            Some(m) => {
                if first {
                    first = false;
                    headers.lock().expect("headers lock").push(m);
                    // VLESS 应答头 Version(0) + OptLen(0)，回 5B 前缀帧
                    let mut f = Vec::with_capacity(7);
                    f.push(0u8);
                    f.extend_from_slice(&2u32.to_be_bytes());
                    f.extend_from_slice(&[0x00, 0x00]);
                    if stream.send_data(bytes::Bytes::from(f), false).is_err() {
                        return;
                    }
                } else if !m.is_empty() {
                    // 数据消息回显（回 5B 前缀帧）
                    let mut f = Vec::with_capacity(5 + m.len());
                    f.push(0u8);
                    f.extend_from_slice(&(m.len() as u32).to_be_bytes());
                    f.extend_from_slice(&m);
                    let _ = stream.send_data(bytes::Bytes::from(f), false);
                }
            }
        }
    }
    let _ = stream.send_data(bytes::Bytes::new(), true);
}

/// mock VLESS-gRPC TLS 服务端：TLS accept → h2 握手（连接驱动驻留 accept
/// 循环——await 流体期间无人推进连接将双向挂死）→ per-stream 独立回显。
/// `close_after_first` = 首流回毕即断 TCP（stale 面；断前限时驱动落盘
/// 流尾帧——直接 drop 会吞掉缓冲帧）。返回（地址，accept 计数，流计数，
/// VLESS 请求头捕获，见到的路径）。
#[allow(clippy::type_complexity)]
async fn spawn_vless_gun_tls_server(
    close_after_first: bool,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    Arc<std::sync::Mutex<String>>,
) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen 自签");
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("证书 PEM 解析");
    let key =
        rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("私钥读取");

    let provider = rillane_tls_provider();
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
    let accepts = Arc::new(AtomicUsize::new(0));
    let streams = Arc::new(AtomicUsize::new(0));
    let headers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let path_slot = Arc::new(std::sync::Mutex::new(String::new()));

    let accepts_task = Arc::clone(&accepts);
    let streams_task = Arc::clone(&streams);
    let headers_task = Arc::clone(&headers);
    let path_task = Arc::clone(&path_slot);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let streams_conn = Arc::clone(&streams_task);
            let headers_conn = Arc::clone(&headers_task);
            let path_conn = Arc::clone(&path_task);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(req) = conn.accept().await {
                    let Ok((req, respond)) = req else {
                        return;
                    };
                    // per-stream 独立回显（连接驱动须留在本任务：await 流体
                    // 期间若无人推进连接，socket 不再被读、双向挂死）
                    let mut echo = tokio::spawn(vless_grpc_stream_task(
                        req,
                        respond,
                        Arc::clone(&streams_conn),
                        Arc::clone(&headers_conn),
                        Arc::clone(&path_conn),
                    ));
                    if close_after_first {
                        // 首流回毕即断（stale 面）：驱动与回显并行；回毕限时
                        // 驱动落盘流尾帧再收束（直接 drop 吞缓冲帧，客户端
                        // 将永等流尾），客户端迟于此重连才命中 stale 面
                        loop {
                            tokio::select! {
                                _ = &mut echo => break,
                                r = conn.accept() => {
                                    if r.is_none() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ =
                            tokio::time::timeout(Duration::from_millis(100), conn.accept()).await;
                        return;
                    }
                }
            });
        }
    });
    (addr, accepts, streams, headers, path_slot)
}

/// 构造 network=grpc 池面连接器（gun 复用生产路径；grpc_reuse 缺省 =
/// 单连接全复用）
fn gun_connector(
    addr: std::net::SocketAddr,
    pool: Arc<TransportPool>,
    factory: Arc<TlsConnectorFactory>,
    reuse: Option<GrpcReuseConfig>,
) -> VlessConnector {
    VlessConnector::new(
        addr.ip().to_string(),
        addr.port(),
        UUID.to_string(),
        None,
        None,
        "grpc".to_string(),
        None,
        None,
        Some(SERVICE.to_string()),
        reuse,
        None,
        None,
        true,
        true,
        Some("localhost".to_string()),
        None,
        TlsFingerprint::None,
        Some(pool),
        Some(factory),
    )
}

/// 复用主面：两流恰 1 次 TCP accept + 每流字节级 echo + 路径断言 + VLESS
/// 请求头语义 + 池记账（复用面只池拨一次，不还池）
#[tokio::test]
async fn vless_grpc_gun_pooled_two_flows_share_single_tcp_connection() {
    let (addr, accepts, streams, headers, path_slot) = spawn_vless_gun_tls_server(false).await;
    let factory = Arc::new(TlsConnectorFactory::new(256));
    let pool = TransportPool::new(gun_policy(), Some(factory.clone()));
    let connector = Arc::new(gun_connector(addr, pool.clone(), factory.clone(), None));

    // 流 1：池借出 + gun 新拨（唯一 TCP accept）
    let (flow, client) = make_flow("www.example.com", 443);
    let connector_for_flow = Arc::clone(&connector);
    let handle = tokio::spawn(async move { connector_for_flow.forward(flow).await });
    let p1 = b"gun-flow-one";
    let r1 = roundtrip_and_finish(client, handle, p1).await;
    assert_eq!(r1.upstream, p1.len() as u64, "流 1 上行计数");
    assert_eq!(r1.downstream, p1.len() as u64, "流 1 下行计数");
    wait_until_header_count(&headers, 1).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "首流新拨恰一次 accept");
    assert_eq!(
        path_slot.lock().expect("path lock").as_str(),
        "/gun-svc/Tun",
        "gRPC 隧道路径 = /service/Tun"
    );

    // 流 2：gun 复用现役 h2 连接——无新 accept、无池借出
    let (flow, client) = make_flow("www.example.com", 443);
    let connector_for_flow = Arc::clone(&connector);
    let handle = tokio::spawn(async move { connector_for_flow.forward(flow).await });
    let p2 = b"gun-flow-two-longer-payload-echo";
    let r2 = roundtrip_and_finish(client, handle, p2).await;
    assert_eq!(r2.upstream, p2.len() as u64, "流 2 上行计数");
    assert_eq!(r2.downstream, p2.len() as u64, "流 2 下行计数");
    wait_until(|| streams.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "次流复用单连接");

    // 池记账：gun 复用面只经池拨一次（租借随连接生命周期，不还池）
    let snap = pool.snapshot();
    assert_eq!(snap.dials_foreground_ok, 1, "gun 面仅一次前台池拨");
    assert_eq!(snap.acquires_miss, 1, "仅首流池 miss");
    assert_eq!(snap.acquires_hit, 0, "流 2 未再借池（gun 复用）");
    assert_eq!(snap.acquires_stale_redial, 0);

    // VLESS 请求头语义：两流首条消息均 ver=0 + uuid + addons 空 + cmd TCP
    // + 端口 443（域寻址）
    let uuid = uuid::Uuid::parse_str(UUID).expect("uuid 解析");
    let hs = headers.lock().expect("headers lock");
    assert_eq!(hs.len(), 2, "两流各一条 VLESS 请求头");
    for m in hs.iter() {
        assert!(m.len() >= 22, "请求头长度: {}", m.len());
        assert_eq!(m[0], 0, "ver=0");
        assert_eq!(&m[1..17], uuid.as_bytes(), "uuid");
        assert_eq!(m[17], 0, "addons 空");
        assert_eq!(m[18], 0x01, "cmd=TCP");
        assert_eq!(&m[19..21], &443u16.to_be_bytes(), "端口 443");
        assert_eq!(m[21], 0x02, "域寻址");
    }
}

/// stale 面：服务端首流回毕即断 → 次流复用面命中死连接 → 逐出 + 重拨
/// 恰一次（accepts 2、池前台拨 2）
#[tokio::test]
async fn vless_grpc_gun_stale_connection_evicted_and_redialed() {
    let (addr, accepts, streams, headers, _path) = spawn_vless_gun_tls_server(true).await;
    let factory = Arc::new(TlsConnectorFactory::new(256));
    let pool = TransportPool::new(gun_policy(), Some(factory.clone()));
    let connector = Arc::new(gun_connector(addr, pool.clone(), factory.clone(), None));

    let (flow, client) = make_flow("www.example.com", 443);
    let connector_for_flow = Arc::clone(&connector);
    let handle = tokio::spawn(async move { connector_for_flow.forward(flow).await });
    let p1 = b"before-stale";
    let r1 = roundtrip_and_finish(client, handle, p1).await;
    assert_eq!(r1.upstream, p1.len() as u64);
    assert_eq!(accepts.load(Ordering::SeqCst), 1);

    // 服务端断连落地（服务端断前驱动窗 100ms，此处过之再重连）
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 复用面命中死连接 → 逐出 + 重拨（accepts +1）
    let (flow, client) = make_flow("www.example.com", 443);
    let connector_for_flow = Arc::clone(&connector);
    let handle = tokio::spawn(async move { connector_for_flow.forward(flow).await });
    let p2 = b"after-redial";
    let r2 = roundtrip_and_finish(client, handle, p2).await;
    assert_eq!(r2.upstream, p2.len() as u64);
    wait_until(|| streams.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 2, "stale 逐出后恰重拨一次");
    assert_eq!(headers.lock().expect("headers lock").len(), 2);
    let snap = pool.snapshot();
    assert_eq!(snap.dials_foreground_ok, 2, "两次池前台拨号");
    assert_eq!(snap.acquires_miss, 2, "重拨走池 miss 面");
    assert_eq!(snap.acquires_hit, 0, "租借随连接生命周期，池无 idle 可还");
}

/// 取消面：中止现役流（abort + 半关）→ 流计数回落、共享连接存活 →
/// 次流照常复用同一连接。`max_streams=1` 旋钮使「流 1 是否已释放」成为
/// 可观测面：未释放 → 次流另开连接（accepts 2）；已释放 → 复用（accepts
/// 恒 1）。
#[tokio::test]
async fn vless_grpc_gun_cancel_midflow_releases_stream_and_keeps_connection() {
    let (addr, accepts, streams, headers, _path) = spawn_vless_gun_tls_server(false).await;
    let factory = Arc::new(TlsConnectorFactory::new(256));
    let pool = TransportPool::new(gun_policy(), Some(factory.clone()));
    let connector = Arc::new(gun_connector(
        addr,
        pool.clone(),
        factory.clone(),
        Some(GrpcReuseConfig {
            max_connections: None,
            min_streams: None,
            max_streams: Some(1),
        }),
    ));

    // 流 1：往返验证后中止转发任务并半关客户端——流收尾、连接保活
    let (flow, client) = make_flow("www.example.com", 443);
    let mut client = client;
    let connector_for_flow = Arc::clone(&connector);
    let handle = tokio::spawn(async move { connector_for_flow.forward(flow).await });
    let p1 = b"cancelled-flow";
    client.write_all(p1).await.expect("写入");
    client.flush().await.expect("flush");
    let mut buf = vec![0u8; p1.len()];
    client.read_exact(&mut buf).await.expect("读回");
    assert_eq!(&buf, p1, "echo 往返");
    handle.abort();
    // EOF → 上行任务收尾（EOS）→ 服务端 EOS → 下行收尾 → 流守卫落定
    drop(client);
    wait_until_header_count(&headers, 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 流 2：现役流已释放（max_streams=1 不触发另开连接）→ 同连接复用
    let (flow, client) = make_flow("www.example.com", 443);
    let connector_for_flow = Arc::clone(&connector);
    let handle = tokio::spawn(async move { connector_for_flow.forward(flow).await });
    let p2 = b"after-cancel";
    let r2 = roundtrip_and_finish(client, handle, p2).await;
    assert_eq!(r2.upstream, p2.len() as u64, "流 2 上行计数");
    assert_eq!(r2.downstream, p2.len() as u64, "流 2 下行计数");
    wait_until_header_count(&headers, 2).await;
    assert_eq!(streams.load(Ordering::SeqCst), 2, "两流同连接");
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "取消不伤共享连接：流释放后 max_streams=1 仍复用（恒单 accept）"
    );
}
