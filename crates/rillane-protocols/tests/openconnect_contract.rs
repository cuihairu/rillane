//! RIL-121 OpenConnect（CSTP）出口面验收。
//!
//! 镜像对端 = 进程内 rustls TLS 服务端（与客户端同载具：rcgen 自签 +
//! rustls + tokio-rustls），实现两步 webvpn 表单认证 + `CONNECT
//! /CSCOSSLC/tunnel` 控制路径；数据面 = CSTP 帧流（`STF\x01`+be16 len+
//! type+0x00，DATA 载荷 = 原始 IP 包）骑一个用户态 smoltcp 监听栈
//! （镜像侧回环——客户端栈与镜像栈经 CSTP DATA 帧互换 IP 包，镜像监听
//! 端口并原样回显）。线格式钉定自 OpenConnect 源码
//! （cstp.c/auth.c/openconnect-internal.h，见 docs/protocol-backends.md
//! #openconnect）。
//!
//! 验收面：成功（镜像栈与客户端栈握手 + 回显 + 统计可观测 + 会话共享——
//! 两条流共一条隧道）、失败（错密码具名——镜像不授 webvpn cookie）、
//! 取消（流中途丢弃 → forward 收束）、平台旁路（UDP 应用面具名拒绝）。
//!
//! 真机交叉面：本席 apt ocserv 1.3.0 真实对端（/home/cui/ocpeer，
//! 127.0.0.1:4433）见 `real_peer_*` 测试（`#[ignore]`，本地手动验收用
//! ——sudo 服务，CI 不跑）。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{bail, Result};
use rcgen::CertifiedKey;
use rillane_core::{EgressConnector, Flow, FlowId, FlowTarget, TargetProto};
use rillane_protocols::OpenConnectConnector;
use rustls::pki_types::pem::PemObject;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, SocketBuffer, State};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

// ---------------- 测试脚手架 ----------------

fn rillane_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_acceptor() -> TlsAcceptor {
    let certified: CertifiedKey =
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
        .with_safe_default_protocol_versions()
        .expect("协议版本");
    TlsAcceptor::from(Arc::new(
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("服务端证书装配"),
    ))
}

fn tcp_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

fn udp_flow(host: &str, port: u16) -> Flow {
    Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        io: Box::new(tokio::io::duplex(4096).1),
        metadata: Default::default(),
    }
}

async fn wait_for(cond: impl Fn() -> bool, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        sleep(Duration::from_millis(20)).await;
    }
    cond()
}

// ---------------- 镜像侧（rustls TLS + CSTP 控制 + smoltcp 监听栈） ----------------

/// 镜像监听栈 phy（与客户端栈同构：rx/tx 包队列）。
struct MirrorPhy {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for MirrorPhy {
    type RxToken<'a> = MirrorRxToken;
    type TxToken<'a> = MirrorTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((
            MirrorRxToken(pkt),
            MirrorTxToken {
                queue: &mut self.tx,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(MirrorTxToken {
            queue: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct MirrorRxToken(Vec<u8>);

impl RxToken for MirrorRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct MirrorTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for MirrorTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt = vec![0u8; len];
        let out = f(&mut pkt);
        self.queue.push_back(pkt);
        out
    }
}

struct MirrorInner {
    iface: Interface,
    device: MirrorPhy,
    sockets: SocketSet<'static>,
    listener: SocketHandle,
    conn: Option<SocketHandle>,
    buf_size: usize,
    listen_port: u16,
}

struct MirrorStack {
    inner: StdMutex<MirrorInner>,
    /// 已建立连接（监听句柄离 Listen 一次）
    established: AtomicBool,
    /// 回显字节（监听连接收 + 原样写回）
    echo_bytes: AtomicU64,
    /// 连接已关闭（对端 FIN/RST 收敛）
    closed: AtomicBool,
}

impl MirrorStack {
    fn new(listen_port: u16) -> Self {
        let mtu = 1372;
        let buf_size = (mtu - 60).max(512);
        let mut device = MirrorPhy {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1111_2222;
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 200, 0, 1), 24));
        });
        let mut listener_sock = tcp::Socket::new(
            SocketBuffer::new(vec![0u8; buf_size]),
            SocketBuffer::new(vec![0u8; buf_size]),
        );
        listener_sock.set_nagle_enabled(false);
        listener_sock.listen(listen_port).expect("镜像监听端口");
        let mut sockets = SocketSet::new(vec![]);
        let listener = sockets.add(listener_sock);
        Self {
            inner: StdMutex::new(MirrorInner {
                iface,
                device,
                sockets,
                listener,
                conn: None,
                buf_size,
                listen_port,
            }),
            established: AtomicBool::new(false),
            echo_bytes: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    fn ingest(&self, pkt: Vec<u8>) {
        self.inner.lock().unwrap().device.rx.push_back(pkt);
    }

    /// poll + 监听移交 + 回显 + 出包。
    fn drive(&self) -> Vec<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
        // 解构：iface/device/sockets 独立可变借位（E0499 规避）
        let MirrorInner {
            iface,
            device,
            sockets,
            listener,
            conn,
            buf_size,
            listen_port,
        } = &mut *inner;
        iface.poll(SmolInstant::now(), device, sockets);

        // 监听句柄离 Listen → 归属连接（一次）
        let l_state = sockets.get::<tcp::Socket>(*listener).state();
        if l_state != State::Listen && conn.is_none() {
            *conn = Some(*listener);
            self.established.store(true, Ordering::Release);
            // 补位监听（同端口）
            let mut s = tcp::Socket::new(
                SocketBuffer::new(vec![0u8; *buf_size]),
                SocketBuffer::new(vec![0u8; *buf_size]),
            );
            s.set_nagle_enabled(false);
            let _ = s.listen(*listen_port);
            *listener = sockets.add(s);
        }

        // 已建立连接：收数据 → 回显；对端 FIN → 回关（FIN 回发）
        if let Some(c) = *conn {
            let s = sockets.get_mut::<tcp::Socket>(c);
            let mut buf = vec![0u8; 2048];
            let mut got = 0;
            let mut remote_eof = false;
            while got < buf.len() {
                match s.recv_slice(&mut buf[got..]) {
                    Ok(0) => break,
                    Ok(k) => {
                        got += k;
                        if got == buf.len() {
                            break;
                        }
                    }
                    Err(tcp::RecvError::Finished) => {
                        remote_eof = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if got > 0 {
                let _ = s.send_slice(&buf[..got]);
                self.echo_bytes.fetch_add(got as u64, Ordering::Relaxed);
            }
            if remote_eof || !s.is_open() {
                if s.is_open() {
                    s.close(); // 回关：FIN 入发送缓冲，下轮 poll 出段
                }
                *conn = None;
                self.closed.store(true, Ordering::Release);
            }
        }

        let mut out = Vec::new();
        while let Some(p) = device.tx.pop_front() {
            out.push(p);
        }
        out
    }
}

/// 读一个 HTTP 请求（首行 + 头 + Content-Length 体），返回 (method, path, headers, body)。
async fn read_http_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            bail!("对端提前关连接");
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
        if line.len() > 16384 {
            bail!("请求行超限");
        }
    }
    let first = String::from_utf8(line)?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    loop {
        let mut hline = Vec::new();
        loop {
            let n = reader.read(&mut byte).await?;
            if n == 0 {
                bail!("对端提前关连接（头）");
            }
            if byte[0] == b'\n' {
                break;
            }
            if byte[0] != b'\r' {
                hline.push(byte[0]);
            }
        }
        if hline.is_empty() {
            break;
        }
        if let Some((k, v)) = String::from_utf8_lossy(&hline).split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let body_len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    Ok((method, path, headers, body))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// 读一个 CSTP 帧（跨读边界缓冲），返回 (type, payload)；None = EOF。
async fn read_cstp_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    pending: &mut Vec<u8>,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    while pending.len() < 8 {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(None);
        }
        pending.push(byte[0]);
    }
    if &pending[0..4] != b"STF\x01" || pending[7] != 0x00 {
        return Err(std::io::Error::other("镜像收到非法 CSTP 头"));
    }
    let len = u16::from_be_bytes([pending[4], pending[5]]) as usize;
    while pending.len() < 8 + len {
        let mut chunk = vec![0u8; (8 + len) - pending.len()];
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        pending.extend_from_slice(&chunk[..n]);
    }
    let pkt_type = pending[6];
    let payload = pending[8..8 + len].to_vec();
    pending.drain(..8 + len);
    Ok(Some((pkt_type, payload)))
}

/// 编 CSTP 帧（镜像侧）。
fn cstp_encode(pkt_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(b"STF\x01");
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(pkt_type);
    out.push(0);
    out.extend_from_slice(payload);
    Ok(out)
}

/// 发 HTTP 响应（Content-Length 由 body 实长计算——手数必错）。
async fn write_http_response(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    status_line: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> std::io::Result<()> {
    let mut resp = format!("{status_line}\r\n");
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    resp.push_str(body);
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

/// 镜像观测状态（连接计数 + 隧道收束）。
struct MirrorState {
    /// 错误密码时镜像不授 webvpn cookie（认证失败面）
    deny_password: bool,
    /// 连接计数（观测会话共享：成功面恰 3 条 TLS 连接）
    connects: AtomicU64,
    /// 隧道断连（DISCONN/TERM_SERVER/EOF）
    tunnel_down: AtomicBool,
}

/// 启动镜像对端：绑定随机端口，返回 (地址, 状态)。
async fn spawn_mirror(
    deny_password: bool,
    stack: Arc<MirrorStack>,
) -> (SocketAddr, Arc<MirrorState>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定镜像端口");
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(MirrorState {
        deny_password,
        connects: AtomicU64::new(0),
        tunnel_down: AtomicBool::new(false),
    });
    let acceptor = tls_acceptor();
    let state_clone = state.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            state_clone.connects.fetch_add(1, Ordering::Relaxed);
            let stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let state = state_clone.clone();
            let stack = stack.clone();
            tokio::spawn(async move {
                let _ = serve_conn(stream, state, stack).await;
            });
        }
    });

    (addr, state)
}

/// 每连接分派：POST /auth（username 或 password）→ 步认证；CONNECT → CSTP 循环。
async fn serve_conn(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Arc<MirrorState>,
    stack: Arc<MirrorStack>,
) {
    let req = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let (method, path, headers, body) = req;

    if method == "POST" && path == "/auth" {
        let body_str = String::from_utf8_lossy(&body);
        if body_str.starts_with("username=") {
            let _ = write_http_response(
                &mut stream,
                "HTTP/1.1 200 OK",
                &[
                    ("Content-Type", "text/xml"),
                    ("Set-Cookie", "webvpncontext=ctx-123; Path=/"),
                    ("Connection", "close"),
                ],
                "<config><response type=\"complete\">success</response></config>",
            )
            .await;
        } else if body_str.starts_with("password=") {
            let cookie = header(&headers, "cookie").unwrap_or("");
            if state.deny_password || !cookie.contains("webvpncontext=ctx-123") {
                // 认证失败面：不授 webvpn cookie（type 非 complete）
                let _ = write_http_response(
                    &mut stream,
                    "HTTP/1.1 200 OK",
                    &[("Content-Type", "text/xml"), ("Connection", "close")],
                    "<config><response type=\"invalid\"/></config>",
                )
                .await;
            } else {
                let _ = write_http_response(
                    &mut stream,
                    "HTTP/1.1 200 OK",
                    &[
                        ("Content-Type", "text/xml"),
                        ("Set-Cookie", "webvpn=sess-456; Path=/"),
                        ("Connection", "close"),
                    ],
                    "<config><response type=\"complete\">success</response></config>",
                )
                .await;
            }
        } else {
            let _ = write_http_response(&mut stream, "HTTP/1.1 400 Bad Request", &[], "").await;
        }
        return;
    }

    if method == "CONNECT" && path == "/CSCOSSLC/tunnel" {
        let cookie = header(&headers, "cookie").unwrap_or("");
        if !cookie.contains("webvpn=sess-456") {
            let _ = write_http_response(&mut stream, "HTTP/1.1 403 Forbidden", &[], "").await;
            return;
        }
        // 200 CONNECTED + X-CSTP-* 头（地址/掩码/DNS/MTU）；此连接即隧道
        // （Content-Length: 0、无 Connection: close——保持开流读 CSTP 帧）
        let _ = write_http_response(
            &mut stream,
            "HTTP/1.1 200 CONNECTED",
            &[
                ("X-CSTP-Address", "10.200.0.100"),
                ("X-CSTP-Netmask", "255.255.255.0"),
                ("X-CSTP-DNS", "8.8.8.8"),
                ("X-CSTP-MTU", "1372"),
            ],
            "",
        )
        .await;

        // CSTP 数据循环：DATA 入镜像栈 → poll → 出包编 DATA 帧回发
        let mut pending = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                f = read_cstp_frame(&mut stream, &mut pending) => {
                    match f {
                        Ok(Some((0, pkt))) => stack.ingest(pkt),
                        Ok(Some((3, payload))) => {
                            // DPD_OUT → KEEPALIVE 回
                            if let Ok(kp) = cstp_encode(7, &payload) {
                                let _ = stream.write_all(&kp).await;
                            }
                        }
                        Ok(Some((5, _))) | Ok(Some((9, _))) | Ok(None) => {
                            state.tunnel_down.store(true, Ordering::Release);
                            break;
                        }
                        Ok(Some((_, _))) => {}
                        Err(_) => {
                            state.tunnel_down.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
                _ = tick.tick() => {}
            }
            for pkt in stack.drive() {
                if let Ok(fr) = cstp_encode(0, &pkt) {
                    if stream.write_all(&fr).await.is_err() {
                        break;
                    }
                }
            }
        }
        return;
    }

    let _ = write_http_response(&mut stream, "HTTP/1.1 404 Not Found", &[], "").await;
}

// ---------------- 验收测试 ----------------

/// 成功 + 统计 + 会话共享：两条 TCP 流经同一镜像隧道回显，FlowReport 可观测。
#[tokio::test]
async fn mirror_success_roundtrip_and_stats() {
    let echo_port = 18080;
    let stack = Arc::new(MirrorStack::new(echo_port));
    let (addr, state) = spawn_mirror(false, stack.clone()).await;

    let connector = Arc::new(
        OpenConnectConnector::new(
            addr.ip().to_string(),
            addr.port(),
            "demo".into(),
            "demo".into(),
            None,
            true, // skip_cert_verify（自签镜像）
        )
        .expect("连接器"),
    );

    // 流 1：回显 roundtrip
    let (flow, mut client) = tcp_flow("10.200.0.50", echo_port);
    let task = tokio::spawn({
        let c = connector.clone();
        async move { c.forward(flow).await }
    });
    let msg = b"hello-cstp-echo-1";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    let n = timeout(Duration::from_secs(15), client.read_exact(&mut buf))
        .await
        .expect("回显超时")
        .expect("读回显");
    assert_eq!(n, msg.len());
    assert_eq!(&buf, msg, "镜像应原样回显");
    drop(client);

    let report = timeout(Duration::from_secs(5), task)
        .await
        .expect("forward 超时")
        .expect("forward 错误")
        .expect("forward 失败");
    assert!(
        report.upstream >= msg.len() as u64,
        "upstream 应计入回显字节：{:?}",
        report
    );
    assert!(
        report.downstream >= msg.len() as u64,
        "downstream 应计入回显字节：{:?}",
        report
    );

    // 会话共享：第二条流复用同一隧道（不再认证——connect 数仍为 3）
    let (flow2, mut client2) = tcp_flow("10.200.0.50", echo_port);
    let task2 = tokio::spawn({
        let c = connector.clone();
        async move { c.forward(flow2).await }
    });
    let msg2 = b"hello-cstp-echo-2";
    client2.write_all(msg2).await.unwrap();
    let mut buf2 = vec![0u8; msg2.len()];
    let n2 = timeout(Duration::from_secs(15), client2.read_exact(&mut buf2))
        .await
        .expect("回显2超时")
        .expect("读回显2");
    assert_eq!(n2, msg2.len());
    assert_eq!(&buf2, msg2, "第二流应回显");
    drop(client2);
    let _ = timeout(Duration::from_secs(5), task2).await;

    assert!(
        wait_for(
            || state.connects.load(Ordering::Relaxed) == 3,
            Duration::from_secs(5)
        )
        .await,
        "会话共享：两流共用一条隧道，TLS 连接数应为 3（用户/密码/CONNECT），实为 {}",
        state.connects.load(Ordering::Relaxed)
    );
    assert!(
        stack.echo_bytes.load(Ordering::Relaxed) >= (msg.len() + msg2.len()) as u64,
        "镜像应回显两流字节：{}",
        stack.echo_bytes.load(Ordering::Relaxed)
    );
    assert!(stack.established.load(Ordering::Relaxed), "镜像应建立连接");
}

/// 认证失败（错密码）：镜像不授 webvpn cookie → 具名错误。
#[tokio::test]
async fn mirror_bad_password_is_named() {
    let echo_port = 18081;
    let stack = Arc::new(MirrorStack::new(echo_port));
    let (addr, _state) = spawn_mirror(true, stack).await;
    let connector = OpenConnectConnector::new(
        addr.ip().to_string(),
        addr.port(),
        "demo".into(),
        "wrong-password".into(),
        None,
        true,
    )
    .expect("连接器");
    let (flow, _client) = tcp_flow("10.200.0.50", echo_port);
    let err = connector.forward(flow).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("未认证") || msg.contains("webvpn"),
        "认证失败应具名（未认证通过/webvpn cookie）：{msg}"
    );
}

/// 平台旁路：UDP 应用面具名拒绝（不建会话）。
#[tokio::test]
async fn mirror_udp_flow_is_named_refused() {
    let echo_port = 18082;
    let stack = Arc::new(MirrorStack::new(echo_port));
    let (addr, state) = spawn_mirror(false, stack).await;
    let connector = OpenConnectConnector::new(
        addr.ip().to_string(),
        addr.port(),
        "demo".into(),
        "demo".into(),
        None,
        true,
    )
    .expect("连接器");
    let flow = udp_flow("10.200.0.50", echo_port);
    let err = connector.forward(flow).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("TCP 应用面") || msg.contains("UDP"),
        "UDP 应具名拒绝：{msg}"
    );
    assert_eq!(
        state.connects.load(Ordering::Relaxed),
        0,
        "UDP 拒绝应在会话建立前：不触达镜像"
    );
}

/// 取消：流中途丢弃 → forward 收束（不挂死）。
#[tokio::test]
async fn mirror_cancel_drops_flow() {
    let echo_port = 18083;
    let stack = Arc::new(MirrorStack::new(echo_port));
    let (addr, _state) = spawn_mirror(false, stack.clone()).await;
    let connector = OpenConnectConnector::new(
        addr.ip().to_string(),
        addr.port(),
        "demo".into(),
        "demo".into(),
        None,
        true,
    )
    .expect("连接器");

    let (flow, mut client) = tcp_flow("10.200.0.50", echo_port);
    let task = tokio::spawn(async move { connector.forward(flow).await });
    let _ = client.write_all(b"cancel-mid-flight").await;
    drop(client);
    // forward 应结束（EOF 传播），不挂死
    let result = timeout(Duration::from_secs(10), task).await;
    assert!(result.is_ok(), "流取消后 forward 应在超时前收束");
    assert!(
        wait_for(
            || stack.established.load(Ordering::Relaxed),
            Duration::from_secs(5)
        )
        .await,
        "取消前镜像应已建立连接"
    );
    assert!(
        wait_for(
            || stack.closed.load(Ordering::Relaxed),
            Duration::from_secs(5)
        )
        .await,
        "取消后镜像应观测到连接收束"
    );
}

// ---------------- 真机对端（本地 apt ocserv，sudo 服务） ----------------

/// 真机对端：本地 ocserv 1.3.0（/home/cui/ocpeer，127.0.0.1:4433，
/// demo/demo）。本地手动验收用（CI 不跑：sudo 服务 + 本席专属）。
///
/// 判定：认证 + CONNECT + 隧道拨号均越过（目标 10.200.0.99:9 无主机，
/// 失败点为连接建立而非认证）——即 error 含「目标连接建立失败」，
/// 且不含「未认证」。
#[tokio::test]
#[ignore = "真机对端（本席 sudo ocserv /home/cui/ocpeer），本地手动验收用"]
async fn real_peer_openconnect_reaches_tunnel() {
    let connector = OpenConnectConnector::new(
        "127.0.0.1".into(),
        4433,
        "demo".into(),
        "demo".into(),
        Some("localhost".into()),
        true,
    )
    .expect("连接器");
    let (flow, _client) = tcp_flow("10.200.0.99", 9);
    let err = connector.forward(flow).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("目标连接建立失败") && !msg.contains("未认证"),
        "真机对端应越过认证（失败点为连接建立而非认证）：{msg}"
    );
}
