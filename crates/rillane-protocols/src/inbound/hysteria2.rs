//! Hysteria2 服务端入口协议实现（RIL-138）
//!
//! 自写 server 面（评估见两语 protocol-backends.md hysteria2 服务端面段——
//! hysteria2 0.1.6 与 rsteria2 均无服务端面；crapthings/hysteria-rust 有真实
//! server face 但 publish=false 不可审计 + hysteria-realm/obfs 传递拖挂 +
//! rc 级成熟度 + edition 2024 MSRV 耦合，沿前判拒绝入库）。线格式与仓内
//! 已互验客户端面镜像互源：认证/UDPMessage 编解码取 outbound/hysteria2.rs
//! （RIL-133，apernet/hysteria PROTOCOL.md 口径），TCPRequest/TCPResponse
//! 取 hysteria2 crate（官方 Go 服务端互验的客户端线格式）：
//! - 认证：HTTP/3 POST https://hysteria/auth（Hysteria-Auth/CC-RX/Padding），
//!   口令恒时比对通过回状态码 233；UDP 关联面启用时附 Hysteria-UDP: true
//!   声明（未启用不声明——客户端见无声明即拒 UDP 面）；
//! - TCP：accept_bi 流上读 `[varint 0x401][varint addr_len][addr]
//!   [varint pad_len][padding]`，回 `[0x00][varint msg_len][msg]
//!   [varint pad_len][padding]`（OK 空 msg 零填充）后原样双向搬运；
//!   解析失败/路由失败回非零状态 + 文案；
//! - UDP：QUIC 不可靠数据报 `[u32 session][u16 packet][u8 frag_id]
//!   [u8 frag_count][varint addr_len][addr][payload]`（session 由客户端
//!   自选，回程按上行登记回写同 id；上行多分片重装配，下行超预算分片——
//!   与客户端 relay 镜像互源），会话生命周期归 `UdpSessionTable`
//!   （粘滞键 = QUIC 连接远端地址；连接收束即吊销本关联键）。
//!
//! QUIC 端点即入口监听（TLS 材料内联 PEM 装配期解析，ALPN 恒 h3）。
//! 不交付：obfs/Salamander 混淆、masquerade（非 /auth 请求一律 404）、
//! ACME、Brutal 拥塞控制、流量统计 API。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex, Once,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, StatusCode};
use rustls::pki_types::pem::PemObject as _;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use rillane_core::udp::{
    DownlinkPacket, DropReason, EgressUdpConnector, UdpIngressMetrics, UdpSessionKey,
    UdpSessionTable, UpResult,
};
use rillane_core::{
    constant_time_eq, fake_ip, BoxedIo, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput,
    FlowRouter, FlowTarget, IngressEndpoint, TargetProto,
};

use crate::outbound::hysteria2::{
    encode_udp_message, flow_target_of_addr, parse_udp_message, put_varint, read_varint_stream,
    QuicDuplex, Reassembler, UdpSessionStats, DGRAM_SEND_TIMEOUT,
};
use crate::tls::tls_crypto_provider;

/// TCP 请求类型（官方仅 0x401 TCP 请求，其余类型点名拒绝）
const TCP_REQUEST_ID: u64 = 0x401;
/// 目标地址串上限（host:port 形；防御性——正常地址远小于此）
const MAX_ADDR_LEN: usize = 512;
/// 请求 padding 上限（官方为随机混淆填充；越限即畸形）
const MAX_PADDING_LEN: usize = 65535;

/// Hysteria2 UDP 关联面装配件：进程级会话表 + 出站连接器族（与 vless/vmess/
/// socks5 ASSOCIATE 同源共享，由 RuntimeBuilder 从 UdpAssociateService 抽出传入）
#[derive(Clone)]
pub struct Hysteria2UdpParts {
    pub table: Arc<UdpSessionTable>,
    pub connector: Arc<dyn EgressUdpConnector>,
}

/// Hysteria2 入口服务
#[derive(Clone)]
pub struct Hysteria2Ingress {
    name: String,
    bind: String,
    /// 认证基准：共享口令（恒时比对）
    password: String,
    /// QUIC 服务端配置（TLS 材料 + ALPN h3 已装配；Endpoint 在 run 期绑定）
    server_config: quinn::ServerConfig,
    /// UDP 关联面（None = 不声明 Hysteria-UDP——客户端 UDP 面自拒）
    udp: Option<Hysteria2UdpParts>,
    /// fake-ip 池表（G1-10；None = 关闭，target 原样路由；TCP/UDP 两面共用）
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    /// 周期回收任务随 UDP 面启用拉起（与 associate 服务各自 Once——多 UDP
    /// 面并存时至多两路 sweep，幂等无害）
    reclaimer_once: Arc<Once>,
}

impl Hysteria2Ingress {
    pub fn new(
        name: String,
        bind: String,
        password: &str,
        cert_pem: &str,
        key_pem: &str,
        udp: Option<Hysteria2UdpParts>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<Self> {
        let password = password.trim();
        if password.is_empty() {
            bail!("hysteria2 入口 password 为空（认证面必须非空）");
        }
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .context("hysteria2 入口证书 PEM 解析失败")?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .context("hysteria2 入口私钥 PEM 解析失败")?;
        let mut config = rustls::ServerConfig::builder_with_provider(tls_crypto_provider())
            .with_safe_default_protocol_versions()
            .context("hysteria2 入口 TLS 协议版本装配失败")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("hysteria2 入口 TLS 证书装配失败")?;
        // QUIC TLS 要求 ALPN 非空（QuicServerConfig::try_from 校验）；官方恒 h3
        config.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .map_err(|e| anyhow!("hysteria2 入口 QUIC TLS 配置失败: {e}"))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        bind.parse::<SocketAddr>()
            .with_context(|| format!("hysteria2 入口 bind 非法: {bind}"))?;
        Ok(Self {
            name,
            bind,
            password: password.to_string(),
            server_config,
            udp,
            fake_ip,
            reclaimer_once: Arc::new(Once::new()),
        })
    }

    /// 单连接面：HTTP/3 认证门 → TCP 流环 + UDP 数据报环（认证通过后才开）
    async fn serve_connection(
        &self,
        conn: quinn::Connection,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let peer = conn.remote_address();

        // ---- 认证门：首个 h3 请求须 POST /auth（masquerade 不交付） ----
        let mut h3_conn: h3::server::Connection<_, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(conn.clone()))
                .await
                .context("Hysteria2 HTTP/3 层建立失败")?;
        let udp_enabled = self.udp.is_some();
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let (req, mut stream) = resolver
                    .resolve_request()
                    .await
                    .context("Hysteria2 认证请求读取失败")?;
                if req.method() != Method::POST || req.uri().path() != "/auth" {
                    let _ = stream
                        .send_response(
                            http::Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(())
                                .expect("固定 404 响应构建"),
                        )
                        .await;
                    let _ = stream.finish().await;
                    bail!("hysteria2 非 /auth 请求（masquerade 面未交付），连接收束");
                }
                let presented = req
                    .headers()
                    .get("Hysteria-Auth")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| constant_time_eq(v.as_bytes(), self.password.as_bytes()))
                    .unwrap_or(false);
                if !presented {
                    let _ = stream
                        .send_response(
                            http::Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .body(())
                                .expect("固定 401 响应构建"),
                        )
                        .await;
                    let _ = stream.finish().await;
                    bail!("hysteria2 认证被拒（口令不符），连接收束");
                }
                // 233 放行；UDP 关联面启用才声明 Hysteria-UDP: true（客户端
                // 无声明即自拒 UDP 面——不建哑管道）
                let resp = http::Response::builder()
                    .status(StatusCode::from_u16(233).context("233 状态码非法")?)
                    .header("Hysteria-UDP", "true")
                    .body(())
                    .context("认证响应构建失败")?;
                stream
                    .send_response(if udp_enabled {
                        resp
                    } else {
                        // 未启用：按官方语义不附声明头
                        http::Response::builder()
                            .status(StatusCode::from_u16(233).context("233 状态码非法")?)
                            .body(())
                            .context("认证响应构建失败")?
                    })
                    .await
                    .context("认证响应发送失败")?;
                stream.finish().await.context("认证流收束失败")?;
            }
            Ok(None) => bail!("hysteria2 连接在认证前收束"),
            Err(e) => bail!("hysteria2 HTTP/3 接受失败: {e}"),
        }

        // ---- h3 连接保活（认证后仅持有、不轮询 accept）：h3 若继续轮询
        // accept，其内部流接受环与下方 accept_bi 竞争同一 QUIC 连接的客户端
        // 双向流——TCPRequest 线格式会被 h3 当未知帧吞占，TCP 面整面饿死
        // （契约测试实证）。保留连接对象（Drop 会关闭自身控制流，对端按
        // H3_CLOSED_CRITICAL_STREAM 断链），持至连接终结（closed 在连接
        // 收束/丢失时完成，对象随后 Drop——对端已死，无影响） ----
        {
            let conn_keeper = conn.clone();
            tokio::spawn(async move {
                let _keeper = h3_conn;
                let _ = conn_keeper.closed().await;
            });
        }

        // ---- TCP 面：accept_bi 环（认证通过后才取流——流在 QUIC 层排队） ----
        {
            let name = self.name.clone();
            let fake_ip = self.fake_ip.clone();
            let router = router.clone();
            let output = output.clone();
            let conn_tcp = conn.clone();
            tokio::spawn(async move {
                while let Ok((send, recv)) = conn_tcp.accept_bi().await {
                    tokio::spawn(handle_tcp_stream(
                        send,
                        recv,
                        name.clone(),
                        peer,
                        fake_ip.clone(),
                        router.clone(),
                        output.clone(),
                    ));
                }
                // 连接收束：accept_bi 报错退出（流资源随连接收束）
            });
        }

        // ---- UDP 面：QUIC 数据报环（仅声明启用时开） ----
        if let Some(parts) = self.udp.as_ref() {
            let key = UdpSessionKey::new(peer);
            let max_dgram = conn.max_datagram_size().unwrap_or(1200);
            let stats = Arc::new(UdpSessionStats::default());
            let packet_id = Arc::new(StdMutex::new(0u16));
            // 上行登记：真实目标键 → 客户端 session id（回程回写同 id——
            // 客户端按本连接 session 过滤外来数据报）
            let sessions: Arc<StdMutex<HashMap<String, u32>>> =
                Arc::new(StdMutex::new(HashMap::new()));
            let last_session = Arc::new(StdMutex::new(0u32));
            let reassembler = Arc::new(tokio::sync::Mutex::new(Reassembler::default()));
            let metrics = Arc::new(UdpIngressMetrics::default());

            let conn_udp = conn.clone();
            let parts = parts.clone();
            let fake_ip = self.fake_ip.clone();
            let key_probe = key.clone();
            let sessions_up = sessions.clone();
            let last_session_up = last_session.clone();
            let stats_up = stats.clone();
            let packet_id_up = packet_id.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(buf) = conn_udp.read_datagram().await else {
                        break; // 连接收束/丢失 → 关联终止
                    };
                    let Some((session, packet, frag_id, frag_count, addr, payload)) =
                        parse_udp_message(&buf)
                    else {
                        stats_up.frag_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let mut target = match flow_target_of_addr(&addr) {
                        Ok(t) => t,
                        Err(_) => {
                            stats_up.frag_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    // fake-ip 回填（G1-10）：池段假 IP 反查原域名改写
                    if let Some(table) = fake_ip.as_ref() {
                        if let Some(domain) = fake_ip::reverse_host(table, &target.host) {
                            target.host = domain;
                        }
                    }
                    // 上行登记 session id（回程回写；客户端同连接通常单 session，
                    // 未知来源回声回退最近 session）
                    {
                        let mut map = sessions_up.lock().expect("hysteria2 会话映射锁中毒");
                        map.insert(format!("{}|{}", target.host, target.port), session);
                    }
                    *last_session_up
                        .lock()
                        .expect("hysteria2 last_session 锁中毒") = session;

                    let data = Bytes::copy_from_slice(payload);
                    // 上行多分片重装配（客户端按 max_dgram 分片上行——镜像互源）
                    let data = if frag_count > 1 {
                        let mut re = reassembler.lock().await;
                        match re.push(packet, frag_id, frag_count, &data, &stats_up.frag_dropped) {
                            Some(whole) => Bytes::from(whole),
                            None => continue, // 未凑齐/非法分片头
                        }
                    } else {
                        data
                    };
                    bump(&metrics.uplink_packets);

                    // 快路径：命中映射直接发
                    match parts.table.forward_up(&key, &target, data.clone()).await {
                        UpResult::Sent => continue,
                        UpResult::Dropped {
                            reason: DropReason::ShuttingDown,
                        } => break,
                        _ => {}
                    }
                    // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
                    if let Err(e) = slow_path_udp(
                        &parts,
                        conn_udp.clone(),
                        &sessions_up,
                        &last_session_up,
                        &packet_id_up,
                        max_dgram,
                        metrics.clone(),
                        stats_up.clone(),
                        &key,
                        &target,
                        peer,
                        data,
                    )
                    .await
                    {
                        bump(&metrics.associate_errors);
                        tracing::debug!(
                            target: "rillane::hysteria2_udp",
                            client = %peer,
                            target = %target.host,
                            error = %e,
                            "UDP 慢路径失败，数据报丢弃"
                        );
                    }
                }
                // 连接收束：吊销本关联键（vmess 控制流 EOF 同口径）
                parts.table.force_revoke(&key_probe);
            });
        }

        Ok(())
    }
}

/// 读 TCP 请求（官方形）：`[varint 0x401][varint addr_len][addr]
/// [varint pad_len][padding 丢弃]`。其余请求类型/越界长度点名拒绝。
/// varint 面 = 出站共享的 `read_varint_stream`（RFC 9000 §16）。
async fn read_tcp_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let id = read_varint_stream(r).await?;
    if id != TCP_REQUEST_ID {
        bail!("Hysteria2 TCP 请求类型不支持（仅 0x401）: 0x{id:X}");
    }
    let addr_len = read_varint_stream(r).await? as usize;
    if addr_len == 0 || addr_len > MAX_ADDR_LEN {
        bail!("Hysteria2 TCP 请求地址长度非法: {addr_len}");
    }
    let mut addr_bytes = vec![0u8; addr_len];
    r.read_exact(&mut addr_bytes)
        .await
        .context("Hysteria2 TCP 请求地址读取失败")?;
    let addr = String::from_utf8(addr_bytes).context("Hysteria2 TCP 请求地址非 UTF-8")?;
    let pad_len = read_varint_stream(r).await? as usize;
    if pad_len > MAX_PADDING_LEN {
        bail!("Hysteria2 TCP 请求 padding 越限: {pad_len}");
    }
    let mut scratch = [0u8; 4096];
    let mut remaining = pad_len;
    while remaining > 0 {
        let n = remaining.min(scratch.len());
        r.read_exact(&mut scratch[..n])
            .await
            .context("Hysteria2 TCP 请求 padding 读取失败")?;
        remaining -= n;
    }
    Ok(addr)
}

/// host:port 劈分（IPv6 字面量按最后一个冒号——与 flow_target_of_addr 同口径，
/// 但 TCP 面目标协议为 TCP）
fn split_addr(addr: &str) -> Result<(String, u16)> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("Hysteria2 地址缺端口: {addr}"))?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("Hysteria2 地址端口非法: {addr}"))?;
    Ok((host.to_string(), port))
}

/// TCP 响应封帧（官方形）：`[u8 status][varint msg_len][msg][varint pad_len][padding]`
/// ——OK 状态 0x00 空 msg 零填充；失败非零状态 + 简短文案
fn seal_tcp_response(status: u8, msg: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg.len() + 10);
    buf.push(status);
    put_varint(&mut buf, msg.len() as u64);
    buf.extend_from_slice(msg.as_bytes());
    put_varint(&mut buf, 0);
    buf
}

/// 单流 TCP 面：请求解出目标 → fake-ip 回填 → 路由 → OK 响应 → Flow 转发
/// （vless forward_tcp 同构；io = QuinnDuplex 原样承接）。解析/路由失败回
/// 非零状态响应；拨号失败面 = 流 EOF（拨号归 output 侧，与 vless/socks5 同口径）
async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    node_name: String,
    client_addr: SocketAddr,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
) -> Result<()> {
    let addr = match read_tcp_request(&mut recv).await {
        Ok(a) => a,
        Err(e) => {
            // 解析失败：错误响应 + 流收束（客户端 read_tcp_response 见非零状态）
            let _ = send
                .write_all(&seal_tcp_response(0x01, "bad request"))
                .await;
            return Err(e);
        }
    };
    let (mut host, port) = split_addr(&addr)?;

    let mut metadata = FlowMetadata {
        tags: vec!["ingress:hysteria2".into(), format!("node:{}", node_name)],
        ..Default::default()
    };
    metadata
        .annotations
        .insert("client.addr".into(), client_addr.to_string());
    metadata
        .annotations
        .insert("ingress.node".into(), node_name.clone());

    // fake-ip 回填（G1-10）：池段假 IP 反查原域名改写
    if let Some(table) = fake_ip.as_ref() {
        if let Some(domain) = fake_ip::reverse_host(table, &host) {
            metadata
                .annotations
                .insert("dns.fakeip".into(), domain.clone());
            host = domain;
        }
    }

    let flow_id = FlowId::new();
    let ctx = FlowContext {
        id: flow_id,
        target: FlowTarget {
            host: host.clone(),
            port,
            proto: TargetProto::Tcp,
        },
        metadata: metadata.clone(),
    };
    let decision = match router.route(ctx).await {
        Ok(d) => d,
        Err(e) => {
            let _ = send
                .write_all(&seal_tcp_response(0x01, "route failure"))
                .await;
            return Err(anyhow!("路由计算失败: {e}"));
        }
    };
    // OK 响应（空 msg 零填充 3 字节；此后原样双向搬运）
    send.write_all(&seal_tcp_response(0x00, ""))
        .await
        .context("Hysteria2 TCP 响应发送失败")?;
    let flow = Flow {
        id: flow_id,
        target: FlowTarget {
            host,
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(QuicDuplex { send, recv }) as BoxedIo,
        metadata,
    };
    output
        .forward(decision, flow)
        .await
        .context("出口转发失败")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn slow_path_udp(
    parts: &Hysteria2UdpParts,
    conn: quinn::Connection,
    sessions: &Arc<StdMutex<HashMap<String, u32>>>,
    last_session: &Arc<StdMutex<u32>>,
    packet_id: &Arc<StdMutex<u16>>,
    max_dgram: usize,
    metrics: Arc<UdpIngressMetrics>,
    stats: Arc<UdpSessionStats>,
    key: &UdpSessionKey,
    target: &FlowTarget,
    peer: SocketAddr,
    data: Bytes,
) -> Result<()> {
    let sref = parts.table.resolve(key, target).await?;
    if !sref.has_mapping(target) {
        // 关联时机：首包路由决策产出后、映射创建处（relay-path §4.1）
        let ctx = FlowContext {
            id: *sref.id(),
            target: target.clone(),
            metadata: FlowMetadata::default(),
        };
        let decision = sref
            .decision()
            .ok_or_else(|| anyhow!("会话缺少路由决策（resolve 应已产出）"))?;
        let relay = parts
            .connector
            .associate(ctx, &decision)
            .await
            .context("出站 UDP 关联失败")?;
        sref.bind_mapping(target, relay).await?;
        // 按会话摘下行通道 → UDPMessage 编码沿 QUIC 数据报回送客户端
        //（多目标会话：单下行任务按包目标回写 session id）
        if let Some(rx) = sref.take_downlink_rx().await {
            tokio::spawn(downlink_loop(
                conn,
                rx,
                sessions.clone(),
                last_session.clone(),
                packet_id.clone(),
                max_dgram,
                peer,
                metrics,
                stats,
            ));
        }
    }
    match sref.send_up(target, data).await {
        UpResult::Sent => Ok(()),
        // Miss：映射刚被策略吊销——本包丢弃，下一包重新关联
        UpResult::Miss => Ok(()),
        UpResult::Dropped { .. } => Ok(()), // 已在表侧计数，UDP 静默丢弃语义
    }
}

/// 下行任务：会话下行通道（多目标混流）→ 按包目标回写 session id →
/// UDPMessage 编码（超预算分片——客户端 Reassembler 镜像互源）→ QUIC 数据报
#[allow(clippy::too_many_arguments)]
async fn downlink_loop(
    conn: quinn::Connection,
    mut rx: mpsc::Receiver<DownlinkPacket>,
    sessions: Arc<StdMutex<HashMap<String, u32>>>,
    last_session: Arc<StdMutex<u32>>,
    packet_id: Arc<StdMutex<u16>>,
    max_dgram: usize,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
    stats: Arc<UdpSessionStats>,
) {
    while let Some(pkt) = rx.recv().await {
        let real_key = format!("{}|{}", pkt.target.host, pkt.target.port);
        // 回程回写 session id（客户端按本连接 session 过滤外来数据报）；
        // 未知来源回声（fake-ip 解析改写等）回退最近上行 session
        let session = match sessions
            .lock()
            .expect("hysteria2 会话映射锁中毒")
            .get(&real_key)
            .copied()
        {
            Some(s) => s,
            None => *last_session.lock().expect("hysteria2 last_session 锁中毒"),
        };
        if let Err(e) = send_downlink(
            &conn,
            max_dgram,
            session,
            &packet_id,
            &pkt.target,
            &pkt.data,
        )
        .await
        {
            tracing::debug!(
                target: "rillane::hysteria2_udp",
                client = %client,
                error = %e,
                "下行发送失败"
            );
            stats.frag_dropped.fetch_add(1, Ordering::Relaxed);
            break; // 连接收束：后续帧无意义
        }
        bump(&metrics.downlink_packets);
    }
}

/// 下行单包/分片发送（客户端 send_to 镜像互源：单包直发，超预算同 packet_id
/// 分片 frag_id 0..count，官方 §Fragmentation）
async fn send_downlink(
    conn: &quinn::Connection,
    max_dgram: usize,
    session: u32,
    packet_id: &Arc<StdMutex<u16>>,
    target: &FlowTarget,
    payload: &[u8],
) -> Result<()> {
    let addr = format!("{}:{}", target.host, target.port);
    let overhead = 8 + varint_len(addr.len()) + addr.len();

    if payload.len() + overhead <= max_dgram {
        let msg = encode_udp_message(session, next_packet_id(packet_id), 0, 1, &addr, payload);
        return send_datagram(conn, msg).await;
    }

    // 分片：同一 Packet ID，Fragment ID 0..count（官方 §Fragmentation）
    let per_frag = max_dgram.saturating_sub(overhead);
    if per_frag == 0 {
        bail!("Hysteria2 QUIC 数据报过小（{max_dgram}B），无法承载 UDP 分片头");
    }
    let count = payload.len().div_ceil(per_frag);
    if count > u8::MAX as usize {
        bail!(
            "Hysteria2 UDP 下行载荷过大（{}B，需 {count} 分片 > 255 上限）",
            payload.len()
        );
    }
    let packet = next_packet_id(packet_id);
    for (frag_id, chunk) in payload.chunks(per_frag).enumerate() {
        let msg = encode_udp_message(session, packet, frag_id as u8, count as u8, &addr, chunk);
        send_datagram(conn, msg).await?;
    }
    Ok(())
}

async fn send_datagram(conn: &quinn::Connection, msg: Vec<u8>) -> Result<()> {
    let wait = conn.send_datagram_wait(Bytes::from(msg));
    match tokio::time::timeout(DGRAM_SEND_TIMEOUT, wait).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Hysteria2 QUIC 数据报发送失败: {e}")),
        Err(_) => Err(anyhow!(
            "Hysteria2 QUIC 数据报缓冲满超时（{}s）——连接不可用",
            DGRAM_SEND_TIMEOUT.as_secs()
        )),
    }
}

fn next_packet_id(gen: &StdMutex<u16>) -> u16 {
    let mut guard = gen.lock().unwrap();
    let id = *guard;
    *guard = guard.wrapping_add(1);
    id
}

/// varint 字节数按 RFC 9000 §16（前缀 2 位 + 6/14/30/62 位值域）
fn varint_len(v: usize) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[async_trait]
impl IngressEndpoint for Hysteria2Ingress {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // 会话回收任务随 UDP 面启用即拉起（纯 Hysteria2 入口无 ASSOCIATE，
        // 无人代拉；重复 sweep 幂等）
        if let Some(parts) = self.udp.as_ref() {
            let table = Arc::clone(&parts.table);
            let once = Arc::clone(&self.reclaimer_once);
            once.call_once(move || {
                table.spawn_reclaimer();
            });
        }

        let bind_addr: SocketAddr = self
            .bind
            .parse()
            .with_context(|| format!("hysteria2 入口 bind 非法: {}", self.bind))?;
        let endpoint = quinn::Endpoint::server(self.server_config.clone(), bind_addr)
            .with_context(|| format!("无法监听 {}", self.bind))?;
        tracing::info!(
            target: "rillane::hysteria2",
            bind = %self.bind,
            "Hysteria2 入口启动"
        );

        loop {
            let Some(incoming) = endpoint.accept().await else {
                break;
            };
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();
            tokio::spawn(async move {
                let conn = match incoming.accept() {
                    Ok(connecting) => match connecting.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!(
                                target: "rillane::hysteria2",
                                error = %e,
                                "QUIC 握手失败"
                            );
                            return;
                        }
                    },
                    Err(e) => {
                        tracing::debug!(
                            target: "rillane::hysteria2",
                            error = %e,
                            "QUIC 连接受理失败"
                        );
                        return;
                    }
                };
                let peer = conn.remote_address();
                if let Err(err) = this.serve_connection(conn, router, output).await {
                    tracing::warn!(
                        target: "rillane::hysteria2",
                        client = %peer,
                        error = %err,
                        "Hysteria2 连接处理失败"
                    );
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::udp::DownlinkPacket;
    use tokio::io::{duplex, AsyncWriteExt as _};

    #[tokio::test]
    async fn tcp_request_reader_parses_varints_addr_and_skips_padding() {
        // 官方形 TCPRequest：varint(0x401) + varint(len) + addr + varint(pad) + pad
        // （pad > 127 触发两字节 varint；客户端线格式与 vendored crate 镜像互源）
        let addr = "echo.example.test:8080";
        let pad = vec![0xA5u8; 300];
        let mut buf = Vec::new();
        put_varint(&mut buf, TCP_REQUEST_ID);
        put_varint(&mut buf, addr.len() as u64);
        buf.extend_from_slice(addr.as_bytes());
        put_varint(&mut buf, pad.len() as u64);
        buf.extend_from_slice(&pad);

        let (mut client, mut server_side) = duplex(64 * 1024);
        client.write_all(&buf).await.expect("请求写入");
        drop(client); // 收束 → 后续读取见 EOF

        let got = read_tcp_request(&mut server_side).await.expect("请求解析");
        assert_eq!(got, addr, "地址串保形");

        // 请求后流已收束 → 再读报 EOF（帧边界收束口径）
        assert!(
            read_tcp_request(&mut server_side).await.is_err(),
            "EOF 收束"
        );
    }

    #[tokio::test]
    async fn tcp_request_reader_refuses_unknown_request_id() {
        let mut buf = Vec::new();
        put_varint(&mut buf, 0x501); // 非 0x401：未知请求类型
        put_varint(&mut buf, 3usize as u64);
        buf.extend_from_slice(b"1:2");

        let (mut client, mut server_side) = duplex(64 * 1024);
        client.write_all(&buf).await.expect("请求写入");
        drop(client);

        let err = read_tcp_request(&mut server_side)
            .await
            .expect_err("未知类型须点名拒绝");
        assert!(
            err.to_string().contains("0x401"),
            "拒绝文案须点名仅支持 0x401: {err}"
        );
    }

    #[test]
    fn tcp_response_seal_ok_and_error_shapes() {
        // OK：status 0 + 空 msg + 零 padding → 3 字节
        assert_eq!(seal_tcp_response(0x00, ""), vec![0x00, 0x00, 0x00]);
        // 失败：status 非零 + msg 文案 + 零 padding
        let err = seal_tcp_response(0x01, "boom");
        assert_eq!(err[0], 0x01);
        assert_eq!(err[1], 4, "varint msg_len = 4");
        assert_eq!(&err[2..6], b"boom");
        assert_eq!(err[6], 0);
    }

    #[test]
    fn reassembler_assembles_and_rejects_illegal_frags() {
        let dropped = AtomicU64::new(0);
        let mut re = Reassembler::default();
        // 两分片同 packet：凑齐拼回整包（frag0 落位在先——乱序容水面）
        let f1 = encode_udp_message(1, 7, 1, 2, "1.2.3.4:53", b"llo");
        let f0 = encode_udp_message(1, 7, 0, 2, "1.2.3.4:53", b"he");
        let (_, p1, i1, c1, _, pay1) = parse_udp_message(&f1).expect("分片 1 解析");
        let (_, p0, i0, c0, _, pay0) = parse_udp_message(&f0).expect("分片 0 解析");
        assert!(
            re.push(p1, i1, c1, pay1, &dropped).is_none(),
            "未凑齐返回 None"
        );
        let whole = re.push(p0, i0, c0, pay0, &dropped).expect("凑齐返回整包");
        assert_eq!(whole, b"hello");

        // 非法分片头：frag_count=0 / frag_id>=frag_count 点名拒绝
        assert!(
            re.push(1, 0, 0, b"x", &dropped).is_none(),
            "frag_count=0 非法"
        );
        assert!(
            re.push(1, 5, 2, b"x", &dropped).is_none(),
            "frag_id 越界非法"
        );
        // 单分片（frag_count=1）直通
        assert_eq!(
            re.push(2, 0, 1, b"whole", &dropped).expect("单分片直通"),
            b"whole"
        );
    }

    #[test]
    fn split_addr_parses_v4_v6_and_rejects_bad_ports() {
        assert_eq!(
            split_addr("127.0.0.1:5353").expect("v4 劈分"),
            ("127.0.0.1".to_string(), 5353)
        );
        assert_eq!(
            split_addr("[::1]:53").expect("v6 字面量劈分"),
            ("[::1]".to_string(), 53)
        );
        assert!(split_addr("no-port-here").is_err(), "缺端口须拒");
        assert!(split_addr("host:99999").is_err(), "端口越界须拒");
    }

    #[test]
    fn auth_faces_gate_on_password_and_udp_declaration() {
        // 恒时比对：正/负例（认证门唯一判据）
        assert!(constant_time_eq(b"pass-1234", b"pass-1234"));
        assert!(!constant_time_eq(b"pass-1234", b"pass-1235"));
        // 233 响应：UDP 启用附声明头；未启用不附（客户端无声明即自拒 UDP 面）
        let with_udp = http::Response::builder()
            .status(StatusCode::from_u16(233).expect("233 合法"))
            .header("Hysteria-UDP", "true")
            .body(())
            .expect("响应构建");
        assert_eq!(with_udp.status().as_u16(), 233);
        assert_eq!(
            with_udp
                .headers()
                .get("Hysteria-UDP")
                .map(|v| v.to_str().unwrap()),
            Some("true")
        );
        let without_udp = http::Response::builder()
            .status(StatusCode::from_u16(233).expect("233 合法"))
            .body(())
            .expect("响应构建");
        assert!(without_udp.headers().get("Hysteria-UDP").is_none());
        // FlowTarget 形：TCP 面目标协议恒 TCP（UDP 面走 flow_target_of_addr 恒 UDP）
        let t = flow_target_of_addr("10.0.0.1:8888").expect("UDP 目标解析");
        assert_eq!(t.proto, TargetProto::Udp);
        let _ = DownlinkPacket {
            target: t,
            data: Bytes::new(),
        };
    }
}
