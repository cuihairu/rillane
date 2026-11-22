//! RIL-122 OpenVPN 出口面验收。
//!
//! 镜像对端 = 进程内 corevpn-protocol 0.6.0 服务端角色（载具
//! `ProtocolSession::new_server` + `TlsHandler` + rcgen 自签 CA），实现
//! HARD_RESET_V2 → TLS 握手 → KeyMethodV2（服务端格式，无 pre_master）→
//! PUSH_REPLY → PRF 数据通道密钥派生（服务端向，install_keys(true)）；数据面
//! = UDP 数据通道加密 IP 包骑一个用户态 smoltcp 监听栈（镜像侧回环——客户
//! 端栈与镜像栈经数据通道互换 IP 包，镜像监听端口并原样回显）。线格式钉定
//! 自 corevpn-protocol 0.6.0（见 docs/protocol-backends.md#openvpn）。
//!
//! 验收面：成功（镜像栈与客户端栈握手 + 回显 + 统计可观测 + 会话共享——
//! 两条流共一条隧道）、失败（CA/证书缺失具名）、取消（流中途丢弃 →
//! forward 收束）、平台旁路（UDP 应用面具名拒绝）。
//!
//! 真机交叉面：本席 apt openvpn 2.7.0 真实对端（/home/cui/ovpnsrv，
//! 127.0.0.1:21194）见 `real_peer_openvpn_2_7_roundtrip`（`#[ignore]`，
//! 本地手动验收用——sudo 服务，CI 不跑）。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use corevpn_crypto::{openvpn_prf, random_bytes, CipherSuite, KeyMaterial};
use corevpn_protocol::{
    create_server_config, load_certs_from_pem, load_key_from_pem, KeyMethodV2, ProcessedPacket,
    ProtocolSession, ProtocolState, PushReply, TlsHandler,
};
use rillane_core::{EgressConnector, Flow, FlowId, FlowTarget, TargetProto};
use rillane_protocols::OpenVpnConnector;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, SocketBuffer, State};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

// ---------------- 测试脚手架 ----------------

/// 进程级 rustls 提供者（fork 版要求显式 install_default）。
fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

/// OpenVPN PING 魔术载荷（与连接器同值；收到即原样回，不入栈）。
const PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

/// rcgen 自签 CA（is_ca=true——载具根库 `RootCertStore::add` 要求 CA 位）。
/// 返回 (cert_pem, key_pem)。同一 CA 兼作镜像服务端证书与客户端证书
/// （服务端 with_no_client_auth、客户端核验器放宽——均不校链）。
fn mirror_ca_certs() -> (String, String) {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("rcgen 参数");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = rcgen::KeyPair::generate().expect("CA 密钥");
    let cert = params.self_signed(&key_pair).expect("CA 自签");
    (cert.pem(), key_pair.serialize_pem())
}

// ---------------- 镜像侧（corevpn 服务端角色 + smoltcp 监听栈） ----------------

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

/// 镜像 smoltcp 监听栈：10.8.0.1/24，监听 echo_port，收数据原样回显。
struct VpnEchoStack {
    inner: StdMutex<MirrorInner>,
    established: AtomicBool,
    echo_bytes: AtomicU64,
    closed: AtomicBool,
}

impl VpnEchoStack {
    fn new(listen_port: u16) -> Self {
        let mtu = 1372;
        let buf_size = (mtu - 60).max(512);
        let mut device = MirrorPhy {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x2222_3333;
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 8, 0, 1), 24));
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

    fn drive(&self) -> Vec<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
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

        let l_state = sockets.get::<tcp::Socket>(*listener).state();
        if l_state != State::Listen && conn.is_none() {
            *conn = Some(*listener);
            self.established.store(true, Ordering::Release);
            let mut s = tcp::Socket::new(
                SocketBuffer::new(vec![0u8; *buf_size]),
                SocketBuffer::new(vec![0u8; *buf_size]),
            );
            s.set_nagle_enabled(false);
            let _ = s.listen(*listen_port);
            *listener = sockets.add(s);
        }

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
                    s.close();
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

/// 镜像观测状态（硬复位次数 + 会话收束）。
struct MirrorStats {
    /// 硬复位次数（观测会话共享：两条流恰 1 次硬复位）
    hard_resets: AtomicU64,
    /// 会话建立（密钥安装完成）
    established: AtomicBool,
    /// 会话终止（错误/对端断开）
    down: AtomicBool,
}

impl Default for MirrorStats {
    fn default() -> Self {
        Self {
            hard_resets: AtomicU64::new(0),
            established: AtomicBool::new(false),
            down: AtomicBool::new(false),
        }
    }
}

struct MirrorCore {
    session: ProtocolSession,
    tls: TlsHandler,
    client_km: Option<KeyMethodV2>,
    cipher: CipherSuite,
}

struct VpnMirror {
    inner: StdMutex<MirrorCore>,
    stack: Arc<VpnEchoStack>,
    stats: Arc<MirrorStats>,
}

impl VpnMirror {
    /// 补发 ACK 与重传（与连接器同口径）。
    fn acks_and_retransmits(session: &mut ProtocolSession) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if session.should_send_ack() {
            if let Some(ack) = session.create_ack_packet() {
                out.push(ack.to_vec());
            }
        }
        for pkt in session.get_retransmits() {
            out.push(pkt.to_vec());
        }
        out
    }

    /// TLS 待发数据收拢成控制包（与连接器 flush_tls 同口径）。
    fn flush_tls(session: &mut ProtocolSession, tls: &mut TlsHandler) -> Result<Vec<Vec<u8>>> {
        let mut all = Vec::new();
        while tls.wants_write() {
            match tls.get_outgoing().context("TLS 出包失败")? {
                Some(out) => all.extend_from_slice(&out),
                None => break,
            }
        }
        if all.is_empty() {
            return Ok(vec![]);
        }
        let ctrl = session
            .create_control_packets(Bytes::from(all))
            .context("控制包构造失败")?;
        Ok(ctrl.into_iter().map(|b| b.to_vec()).collect())
    }

    /// 处理一个 UDP 报文 → 待发报文队列。
    fn handle_packet(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut core = self.inner.lock().unwrap();
        let mut out = Vec::new();
        let result = core.session.process_packet(data).context("报文处理失败")?;
        match result {
            ProcessedPacket::HardReset { .. } => {
                self.stats.hard_resets.fetch_add(1, Ordering::Relaxed);
                if let Ok(pkt) = core.session.create_hard_reset_response() {
                    out.push(pkt.to_vec());
                }
                out.extend(Self::acks_and_retransmits(&mut core.session));
            }
            ProcessedPacket::TlsData(records) => {
                core.tls
                    .process_tls_records(records)
                    .context("TLS 处理失败")?;
                // 握手完成后收取客户端 KeyMethodV2 明文（跨报文累积）
                if core.tls.is_handshake_complete() && core.client_km.is_none() {
                    let mut buf = [0u8; 8192];
                    let mut acc = Vec::new();
                    loop {
                        let n = core.tls.read_plaintext(&mut buf).context("TLS 读失败")?;
                        if n == 0 {
                            break;
                        }
                        acc.extend_from_slice(&buf[..n]);
                    }
                    if let Ok(km) = KeyMethodV2::parse(&acc) {
                        core.client_km = Some(km);
                        // 服务端密钥交换 + PUSH_REPLY（密钥先装——对端数据先到无 KeyNotAvailable）
                        let srv_random1: [u8; 32] = random_bytes();
                        let srv_random2: [u8; 32] = random_bytes();
                        let srv_km = KeyMethodV2 {
                            pre_master: [0u8; 48],
                            random1: srv_random1,
                            random2: srv_random2,
                            options: format!(
                                "V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto UDPv4,cipher {},auth [null-digest],keysize 256,key-method 2,tls-server",
                                cipher_name(core.cipher)
                            ),
                            username: None,
                            password: None,
                            peer_info: None,
                        };
                        let mut push = PushReply {
                            ifconfig: Some(("10.8.0.2".into(), "255.255.255.0".into())),
                            route_gateway: Some("10.8.0.1".into()),
                            ..PushReply::default()
                        };
                        push.dns.push("1.1.1.1".into());
                        push.ping = 10;
                        push.ping_restart = 60;
                        let mut push_text = srv_km.encode(true);
                        push_text.push(0);
                        push_text.extend_from_slice(push.encode().as_bytes());
                        core.tls.write_plaintext(&push_text).context("TLS 写失败")?;

                        // PRF 派生（服务端向：pre_master 来自客户端 KM）
                        let client_km = core.client_km.as_ref().expect("刚写入");
                        let client_sid = core
                            .session
                            .remote_session_id()
                            .copied()
                            .context("缺客户端会话 id")?;
                        let server_sid = *core.session.local_session_id();
                        let mut seed1 = Vec::with_capacity(64);
                        seed1.extend_from_slice(&client_km.random1);
                        seed1.extend_from_slice(&srv_random1);
                        let master_secret = openvpn_prf(
                            &client_km.pre_master,
                            b"OpenVPN master secret",
                            &seed1,
                            48,
                        )
                        .context("PRF master secret 失败")?;
                        let mut seed2 = Vec::with_capacity(80);
                        seed2.extend_from_slice(&client_km.random2);
                        seed2.extend_from_slice(&srv_random2);
                        seed2.extend_from_slice(&client_sid);
                        seed2.extend_from_slice(&server_sid);
                        let key_block =
                            openvpn_prf(&master_secret, b"OpenVPN key expansion", &seed2, 256)
                                .context("PRF key expansion 失败")?;
                        let km = KeyMaterial::from_openvpn_key2_block(&key_block);
                        core.session.install_keys(&km, true);
                        core.session.set_state(ProtocolState::Established);
                        self.stats.established.store(true, Ordering::Release);
                    }
                }
                {
                    let MirrorCore { session, tls, .. } = &mut *core;
                    out.extend(Self::flush_tls(session, tls)?);
                }
                out.extend(Self::acks_and_retransmits(&mut core.session));
            }
            ProcessedPacket::Data(dec) => {
                if dec.len() == PING_PAYLOAD.len() && dec.as_ref() == PING_PAYLOAD {
                    if let Ok(enc) = core.session.encrypt_data(&PING_PAYLOAD) {
                        out.push(enc.to_vec());
                    }
                } else {
                    self.stack.ingest(dec.to_vec());
                }
            }
            ProcessedPacket::None | ProcessedPacket::HardResetAck | ProcessedPacket::SoftReset => {
                out.extend(Self::acks_and_retransmits(&mut core.session));
            }
        }
        Ok(out)
    }

    /// 出栈 IP 包加密（数据面）。
    fn encrypt_outbound(&self, pkt: Vec<u8>) -> Result<Vec<u8>> {
        let mut core = self.inner.lock().unwrap();
        let enc = core.session.encrypt_data(&pkt).context("数据加密失败")?;
        Ok(enc.to_vec())
    }
}

fn cipher_name(c: CipherSuite) -> &'static str {
    match c {
        CipherSuite::Aes256Gcm => "AES-256-GCM",
        CipherSuite::ChaCha20Poly1305 => "CHACHA20-POLY1305",
    }
}

/// 启动镜像对端：绑定随机 UDP 端口，返回 (地址, 观测状态, 监听栈)。
async fn spawn_vpn_mirror(echo_port: u16) -> (SocketAddr, Arc<MirrorStats>, Arc<VpnEchoStack>) {
    install_tls_provider();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("绑定镜像端口");
    let addr = socket.local_addr().unwrap();
    let (cert_pem, key_pem) = mirror_ca_certs();
    let certs = load_certs_from_pem(&cert_pem).expect("服务端证书解析");
    let key = load_key_from_pem(&key_pem).expect("服务端私钥解析");
    let server_config = create_server_config(certs, key, None).expect("服务端 TLS 配置");
    let tls = TlsHandler::new(server_config).expect("TLS 处理器");
    let cipher = CipherSuite::Aes256Gcm;
    let session = ProtocolSession::new_server(cipher);
    let stats = Arc::new(MirrorStats::default());
    let stack = Arc::new(VpnEchoStack::new(echo_port));
    let mirror = Arc::new(VpnMirror {
        inner: StdMutex::new(MirrorCore {
            session,
            tls,
            client_km: None,
            cipher,
        }),
        stack: stack.clone(),
        stats: stats.clone(),
    });

    let stack_task = stack.clone();
    let stats_task = stats.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut peer: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = socket.recv_from(&mut buf) => {
                    match r {
                        Ok((n, from)) => {
                            peer = Some(from);
                            match mirror.handle_packet(&buf[..n]) {
                                Ok(packets) => {
                                    for p in packets {
                                        if socket.send_to(&p, from).await.is_err() {
                                            stats_task.down.store(true, Ordering::Release);
                                            return;
                                        }
                                    }
                                }
                                Err(_) => {
                                    stats_task.down.store(true, Ordering::Release);
                                    return;
                                }
                            }
                        }
                        Err(_) => {
                            stats_task.down.store(true, Ordering::Release);
                            return;
                        }
                    }
                }
                _ = tick.tick() => {}
            }
            if let Some(to) = peer {
                for pkt in stack_task.drive() {
                    match mirror.encrypt_outbound(pkt) {
                        Ok(enc) => {
                            if socket.send_to(&enc, to).await.is_err() {
                                stats_task.down.store(true, Ordering::Release);
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    });

    (addr, stats, stack)
}

/// 连接器（CA + 客户端证书自签 CA 复用）。
fn connector_at(addr: SocketAddr) -> OpenVpnConnector {
    let (cert_pem, key_pem) = mirror_ca_certs();
    OpenVpnConnector::new(
        addr.ip().to_string(),
        addr.port(),
        cert_pem.clone(),
        cert_pem,
        key_pem,
        "AES-256-GCM".into(),
        None,
        None,
        Some("localhost".into()),
    )
    .expect("连接器")
}

// ---------------- 验收测试 ----------------

/// 成功 + 统计 + 会话共享：两条 TCP 流经同一镜像隧道回显，FlowReport 可观测。
#[tokio::test]
async fn mirror_success_roundtrip_and_stats() {
    let echo_port = 18090;
    let (addr, stats, stack) = spawn_vpn_mirror(echo_port).await;
    let connector = Arc::new(connector_at(addr));

    // 流 1：回显 roundtrip
    let (flow, mut client) = tcp_flow("10.8.0.1", echo_port);
    let task = tokio::spawn({
        let c = connector.clone();
        async move { c.forward(flow).await }
    });
    let msg = b"hello-openvpn-echo-1";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    let n = timeout(Duration::from_secs(20), client.read_exact(&mut buf))
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
    assert!(
        stats.established.load(Ordering::Acquire),
        "镜像应安装数据通道密钥"
    );

    // 会话共享：第二条流复用同一隧道（不再硬复位——hard_resets 仍为 1）
    let (flow2, mut client2) = tcp_flow("10.8.0.1", echo_port);
    let task2 = tokio::spawn({
        let c = connector.clone();
        async move { c.forward(flow2).await }
    });
    let msg2 = b"hello-openvpn-echo-2";
    client2.write_all(msg2).await.unwrap();
    let mut buf2 = vec![0u8; msg2.len()];
    let n2 = timeout(Duration::from_secs(20), client2.read_exact(&mut buf2))
        .await
        .expect("回显2超时")
        .expect("读回显2");
    assert_eq!(n2, msg2.len());
    assert_eq!(&buf2, msg2, "第二流应回显");
    drop(client2);
    let _ = timeout(Duration::from_secs(5), task2).await;

    assert_eq!(
        stats.hard_resets.load(Ordering::Relaxed),
        1,
        "会话共享：两流共用一条隧道，硬复位应为 1"
    );
    assert!(
        stack.echo_bytes.load(Ordering::Relaxed) >= (msg.len() + msg2.len()) as u64,
        "镜像应回显两流字节：{}",
        stack.echo_bytes.load(Ordering::Relaxed)
    );
    assert!(stack.established.load(Ordering::Relaxed), "镜像应建立连接");
}

/// 建期失败（CA 缺失）：构造即具名错误，不触达网络。
#[tokio::test]
async fn mirror_missing_ca_is_named() {
    let (cert_pem, key_pem) = mirror_ca_certs();
    let err = match OpenVpnConnector::new(
        "127.0.0.1".into(),
        21195,
        String::new(),
        cert_pem,
        key_pem,
        "AES-256-GCM".into(),
        None,
        None,
        None,
    ) {
        Err(e) => e,
        Ok(_) => panic!("CA 缺失应构造失败"),
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("CA 证书缺失") || msg.contains("ca_pem"),
        "CA 缺失应具名：{msg}"
    );
}

/// 平台旁路：UDP 应用面具名拒绝（不建会话）。
#[tokio::test]
async fn mirror_udp_flow_is_named_refused() {
    let echo_port = 18092;
    let (addr, stats, _stack) = spawn_vpn_mirror(echo_port).await;
    let connector = connector_at(addr);
    let flow = udp_flow("10.8.0.1", echo_port);
    let err = connector.forward(flow).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("TCP 应用面") || msg.contains("UDP"),
        "UDP 应具名拒绝：{msg}"
    );
    assert_eq!(
        stats.hard_resets.load(Ordering::Relaxed),
        0,
        "UDP 拒绝应在会话建立前：不触达镜像"
    );
}

/// 取消：流中途丢弃 → forward 收束（不挂死）。
#[tokio::test]
async fn mirror_cancel_drops_flow() {
    let echo_port = 18093;
    let (addr, _stats, stack) = spawn_vpn_mirror(echo_port).await;
    let connector = connector_at(addr);

    let (flow, mut client) = tcp_flow("10.8.0.1", echo_port);
    let task = tokio::spawn(async move { connector.forward(flow).await });
    let _ = client.write_all(b"cancel-mid-flight").await;
    drop(client);
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

// ---------------- 真机对端（本地 apt openvpn 2.7.0，sudo 服务） ----------------

/// 真机对端：本地 openvpn 2.7.0（/home/cui/ovpnsrv，127.0.0.1:21194，
/// 证书认证 + 10.8.0.0/24）。本地手动验收用（CI 不跑：sudo 服务 +
/// 本席专属；对端证书与监听栈须预先就绪——脚本见 docs/protocol-backends.md
/// #openvpn 真机对端小节）。
///
/// 判定：完整隧道拨号 + 10.8.0.1:PORT 回显 roundtrip（客户端栈 10.8.0.2/24
/// 经真实 openvpn 服务端路由至 10.8.0.1 上本地 TCP 监听栈）。
#[tokio::test]
#[ignore = "真机对端（本席 sudo openvpn /home/cui/ovpnsrv），本地手动验收用"]
async fn real_peer_openvpn_2_7_roundtrip() {
    install_tls_provider();
    // 对端凭据（/home/cui/ovpnsrv 持久化；缺失即明确失败）
    let dir = std::path::Path::new("/home/cui/ovpnsrv");
    let ca = std::fs::read_to_string(dir.join("ca.crt"))
        .expect("对端 CA 缺失：请先按 docs/protocol-backends.md#openvpn 真机对端小节搭建");
    let cert = std::fs::read_to_string(dir.join("client.crt")).expect("对端客户端证书缺失");
    let key = std::fs::read_to_string(dir.join("client.key")).expect("对端客户端私钥缺失");
    let connector = OpenVpnConnector::new(
        "127.0.0.1".into(),
        21194,
        ca,
        cert,
        key,
        "AES-256-GCM".into(),
        None,
        None,
        Some("localhost".into()),
    )
    .expect("连接器");

    // 10.8.0.1 上本地 TCP 回显监听（非特权端口；openvpn 服务端 tun0=10.8.0.1）。
    // bind 只占端口——**必须有 accept 回显任务**：否则内核回了 SYN-ACK 后无人
    // accept，回显永不返回（隧道数据面已通，服务端日志可见全链握手）。
    let listener = tokio::net::TcpListener::bind("10.8.0.1:0")
        .await
        .expect("10.8.0.1 监听（须本席 root/服务端 tun 就绪）");
    let echo_port = listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let Ok((mut stream, _addr)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 512];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let (flow, mut client) = tcp_flow("10.8.0.1", echo_port);
    let task = tokio::spawn(async move { connector.forward(flow).await });
    let msg = b"real-peer-openvpn-echo";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    let n = timeout(Duration::from_secs(30), client.read_exact(&mut buf))
        .await
        .expect("回显超时")
        .expect("读回显");
    assert_eq!(&buf[..n], msg, "真实对端应回显");
    echo_task.abort();
    drop(client);
    let report = timeout(Duration::from_secs(5), task)
        .await
        .expect("forward 超时")
        .expect("forward 错误")
        .expect("forward 失败");
    assert!(
        report.upstream >= msg.len() as u64,
        "upstream 计入：{:?}",
        report
    );
}
