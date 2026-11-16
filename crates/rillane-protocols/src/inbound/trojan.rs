//! Trojan 入口协议实现（RIL-135）
//!
//! 自写 server 面（评估见两语 protocol-backends.md trojan 服务端面段——
//! crates.io 全谱系 GPL-3.0-only 与本仓 Apache-2.0 不兼容，且 trojan-server
//! 为整装 run 循环不可组合进 IngressEndpoint）。帧原语与仓内客户端面
//! （outbound/trojan.rs）镜像互源：请求 `[56-hex][CRLF][CMD][ATYP addr
//! port][CRLF]`（CMD 0x01 CONNECT / 0x03 UDP ASSOCIATE），口令 = SHA224
//! hex 恒时比对（core `constant_time_eq`）。UDP 关联无应答（镜像参考实现
//! 直进 UDP_FORWARD 循环），数据报走同一条 TLS 流，帧形
//! `[ATYP addr port][len][CRLF][payload]`；会话生命周期归 `UdpSessionTable`
//! （与 socks5 ASSOCIATE 同机制：粘滞决策、空闲回收；控制流 = TLS 流
//! 本体，EOF 即吊销本关联键——socks5 §2.5 同语义）。
//! TLS 材料随 IR 内联（PEM），装配期解析（`TrojanIngress::new` 即装配）。

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Once,
    },
};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rustls::pki_types::pem::PemObject as _;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use rillane_core::udp::{
    DownlinkPacket, DropReason, EgressUdpConnector, UdpIngressMetrics, UdpSessionKey,
    UdpSessionTable, UpResult,
};
use rillane_core::{
    constant_time_eq, fake_ip, BoxedIo, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput,
    FlowRouter, FlowTarget, IngressEndpoint, TargetProto,
};

use crate::tls::tls_crypto_provider;

/// Trojan UDP 关联面装配件：进程级会话表 + 出站连接器族（与 socks5
/// ASSOCIATE / TUN 同源共享，由 RuntimeBuilder 从 UdpAssociateService 抽出传入）
#[derive(Clone)]
pub struct TrojanUdpParts {
    pub table: Arc<UdpSessionTable>,
    pub connector: Arc<dyn EgressUdpConnector>,
}

/// Trojan 入口服务
#[derive(Clone)]
pub struct TrojanIngress {
    name: String,
    bind: String,
    /// SHA224(password) 小写 hex（56 字符）——请求头比对基准
    password_hash: String,
    /// TLS server 面（PEM 材料已随构造装配；TlsAcceptor = Arc 共享）
    acceptor: TlsAcceptor,
    /// UDP 关联面（None = udp 未启用——CMD 0x03 连接收束）
    udp: Option<TrojanUdpParts>,
    /// fake-ip 池表（G1-10；None = 关闭，target 原样路由；TCP/UDP 两面共用）
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    /// 周期回收任务随 UDP 面启用拉起（与 associate 服务各自 Once——多 UDP
    /// 面并存时至多两路 sweep，幂等无害）
    reclaimer_once: Arc<Once>,
}

impl TrojanIngress {
    pub fn new(
        name: String,
        bind: String,
        password: String,
        cert_pem: &str,
        key_pem: &str,
        udp: Option<TrojanUdpParts>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<Self> {
        if password.is_empty() {
            bail!("trojan 入口密码不得为空");
        }
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .context("trojan 入口证书 PEM 解析失败")?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .context("trojan 入口私钥 PEM 解析失败")?;
        let config = rustls::ServerConfig::builder_with_provider(tls_crypto_provider())
            .with_safe_default_protocol_versions()
            .context("trojan 入口 TLS 协议版本装配失败")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("trojan 入口 TLS 证书装配失败")?;
        bind.parse::<SocketAddr>()
            .with_context(|| format!("trojan 入口 bind 非法: {bind}"))?;
        Ok(Self {
            name,
            bind,
            password_hash: to_hex(&Sha224::digest(password.as_bytes())),
            acceptor: TlsAcceptor::from(Arc::new(config)),
            udp,
            fake_ip,
            reclaimer_once: Arc::new(Once::new()),
        })
    }

    /// CONNECT 既有路径（socks5 forward_tcp 同构）：请求解出目标 →
    /// fake-ip 回填 → Flow 流式转发。
    async fn forward_tcp(
        ingress_node_name: &str,
        client_addr: SocketAddr,
        stream: TlsStream<TcpStream>,
        target: FlowTarget,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<()> {
        let mut host = target.host;
        let port = target.port;
        let mut metadata = FlowMetadata {
            tags: vec![
                "ingress:trojan".into(),
                format!("node:{}", ingress_node_name),
            ],
            ..Default::default()
        };
        metadata
            .annotations
            .insert("client.addr".into(), client_addr.to_string());
        metadata
            .annotations
            .insert("ingress.node".into(), ingress_node_name.to_string());

        // fake-ip 回填（G1-10）：target 为池段假 IPv4 时反查原域名改写
        if let Some(table) = fake_ip.as_ref() {
            if let Some(domain) = fake_ip::reverse_host(table, &host) {
                metadata
                    .annotations
                    .insert("dns.fakeip".into(), domain.clone());
                host = domain;
            }
        }

        let flow = Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host,
                port,
                proto: TargetProto::Tcp,
            },
            io: Box::new(stream) as BoxedIo,
            metadata,
        };

        let ctx = flow.context();
        let decision = router.route(ctx).await.context("路由计算失败")?;
        output
            .forward(decision, flow)
            .await
            .context("出口转发失败")?;

        Ok(())
    }

    /// UDP ASSOCIATE（CMD 0x03）：无应答（镜像参考实现直进 UDP_FORWARD
    /// 循环），数据报帧沿 TLS 流增量解析 → 会话表快/慢路径；控制流 = TLS
    /// 流本体，EOF 即吊销本关联键（socks5 §2.5 同语义）。
    async fn serve_association(
        &self,
        stream: TlsStream<TcpStream>,
        peer: SocketAddr,
    ) -> Result<()> {
        let Some(parts) = self.udp.as_ref() else {
            bail!("trojan UDP 关联面未启用（udp 门关闭），连接收束");
        };
        let (mut rr, ww) = tokio::io::split(stream);
        let writer = Arc::new(tokio::sync::Mutex::new(ww));
        let metrics = Arc::new(UdpIngressMetrics::default());
        let key = UdpSessionKey::new(peer);

        let uplink =
            uplink_loop(parts, &mut rr, writer, peer, self.fake_ip.clone(), &metrics).await;

        // 控制流终止 → 吊销本关联键（关下行 → 摘映射 → 计数在表侧）
        let revoked = parts.table.force_revoke(&key);
        tracing::debug!(
            target: "rillane::trojan_udp",
            client = %peer,
            revoked,
            "trojan UDP 关联收束"
        );
        uplink
    }

    async fn handle_conn(
        self: Arc<Self>,
        tcp: TcpStream,
        peer: SocketAddr,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let _ = tcp.set_nodelay(true);
        let mut tls = self.acceptor.accept(tcp).await.context("TLS 握手失败")?;

        // 请求头：hash(56) CRLF CMD(1)
        let mut head = [0u8; 59];
        tls.read_exact(&mut head)
            .await
            .context("trojan 请求头读取")?;
        if !constant_time_eq(&head[..56], self.password_hash.as_bytes()) {
            bail!("trojan 密码哈希不匹配（恒时比对），连接收束");
        }
        if &head[56..58] != b"\r\n" {
            bail!("trojan 请求头 CRLF 不匹配");
        }
        let cmd = head[58];
        let (host, port) = read_socks_addr(&mut tls).await?;
        let mut crlf = [0u8; 2];
        tls.read_exact(&mut crlf)
            .await
            .context("trojan 请求尾读取")?;
        if crlf != [0x0d, 0x0a] {
            bail!("trojan 请求尾 CRLF 不匹配");
        }

        match cmd {
            0x01 => {
                let target = FlowTarget {
                    host,
                    port,
                    proto: TargetProto::Tcp,
                };
                Self::forward_tcp(
                    self.name.as_str(),
                    peer,
                    tls,
                    target,
                    router,
                    output,
                    self.fake_ip.clone(),
                )
                .await
            }
            0x03 => self.serve_association(tls, peer).await,
            other => bail!("trojan 未知命令: {other}"),
        }
    }
}

#[async_trait]
impl IngressEndpoint for TrojanIngress {
    fn name(&self) -> &'static str {
        "trojan"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // 会话回收任务随 UDP 面启用即拉起（纯 Trojan 入口无 ASSOCIATE，
        // 无人代拉；重复 sweep 幂等）
        if let Some(parts) = self.udp.as_ref() {
            let table = Arc::clone(&parts.table);
            let once = Arc::clone(&self.reclaimer_once);
            once.call_once(move || {
                table.spawn_reclaimer();
            });
        }

        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("无法监听 {}", self.bind))?;
        tracing::info!(
            target: "rillane::trojan",
            bind = %self.bind,
            "Trojan 入口启动"
        );

        loop {
            let Ok((tcp, peer)) = listener.accept().await else {
                break;
            };
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();

            tokio::spawn(async move {
                if let Err(err) = this.handle_conn(tcp, peer, router, output).await {
                    tracing::warn!(
                        target: "rillane::trojan",
                        client = %peer,
                        error = %err,
                        "Trojan 连接处理失败"
                    );
                }
            });
        }
        Ok(())
    }
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// 上行循环：逐帧 `[ATYP addr port][len][CRLF][payload]` 增量解析 →
/// fake-ip 回填 → 会话表快/慢路径（与 socks5 ASSOCIATE uplink 同构）。
/// ATYP 处干净 EOF 为正常帧边界收束，返回 Ok。
async fn uplink_loop(
    parts: &TrojanUdpParts,
    rr: &mut (impl AsyncRead + Unpin),
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TlsStream<TcpStream>>>>,
    peer: SocketAddr,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    metrics: &Arc<UdpIngressMetrics>,
) -> Result<()> {
    let key = UdpSessionKey::new(peer);
    let mut payload = vec![0u8; 65535];
    loop {
        // 帧头：ATYP + 地址 + 端口 + 长度 + CRLF
        let Some((mut host, port)) = read_frame_addr(rr).await? else {
            return Ok(()); // EOF
        };
        let mut len_b = [0u8; 2];
        rr.read_exact(&mut len_b).await?;
        let len = u16::from_be_bytes(len_b) as usize;
        let mut crlf = [0u8; 2];
        rr.read_exact(&mut crlf).await?;
        if crlf != [0x0d, 0x0a] {
            bail!("trojan UDP 帧 CRLF 校验失败");
        }
        rr.read_exact(&mut payload[..len]).await?;
        bump(&metrics.uplink_packets);

        // fake-ip 回填（G1-10 UDP 面）：帧目标为池段假 IPv4 时反查原域名
        // 改写（会话按改写后 target 绑定，同域名后续帧复用会话）
        if let Some(t) = fake_ip.as_ref() {
            if let Some(domain) = fake_ip::reverse_host(t, &host) {
                host = domain;
            }
        }
        let target = FlowTarget {
            host,
            port,
            proto: TargetProto::Udp,
        };
        let data = Bytes::copy_from_slice(&payload[..len]);

        // 快路径：命中映射直接发
        match parts.table.forward_up(&key, &target, data.clone()).await {
            UpResult::Sent => continue,
            UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            } => bail!("会话表收束，trojan UDP 关联终止"),
            _ => {}
        }
        // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
        if let Err(e) = slow_path(parts, &writer, metrics, &key, &target, peer, data).await {
            bump(&metrics.associate_errors);
            tracing::debug!(
                target: "rillane::trojan_udp",
                client = %peer,
                target = %target.host,
                error = %e,
                "UDP 慢路径失败，数据报丢弃"
            );
        }
    }
}

async fn slow_path(
    parts: &TrojanUdpParts,
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TlsStream<TcpStream>>>>,
    metrics: &Arc<UdpIngressMetrics>,
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
            .ok_or_else(|| anyhow::anyhow!("会话缺少路由决策（resolve 应已产出）"))?;
        let relay = parts
            .connector
            .associate(ctx, &decision)
            .await
            .context("出站 UDP 关联失败")?;
        sref.bind_mapping(target, relay).await?;
        // 按会话摘下行通道 → trojan 帧沿 TLS 流回送客户端
        if let Some(rx) = sref.take_downlink_rx().await {
            let writer = Arc::clone(writer);
            let metrics = Arc::clone(metrics);
            tokio::spawn(downlink_loop(writer, rx, peer, metrics));
        }
    }
    match sref.send_up(target, data).await {
        UpResult::Sent => Ok(()),
        // Miss：映射刚被策略吊销——本包丢弃，下一包重新关联
        UpResult::Miss => Ok(()),
        UpResult::Dropped { .. } => Ok(()), // 已在表侧计数，UDP 静默丢弃语义
    }
}

/// 下行任务：会话下行通道 → `[ATYP addr port][len][CRLF][payload]` 帧沿
/// TLS 流回送客户端（源地址段 = 原目标，客户端按回包地址段区分来源）
async fn downlink_loop(
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TlsStream<TcpStream>>>>,
    mut rx: tokio::sync::mpsc::Receiver<DownlinkPacket>,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
) {
    while let Some(pkt) = rx.recv().await {
        let mut frame = Vec::with_capacity(pkt.data.len() + 64);
        if write_socks_addr(&mut frame, &pkt.target).is_err() {
            tracing::warn!(
                target: "rillane::trojan_udp",
                host = %pkt.target.host,
                "下行封帧失败（目标主机名非法），丢弃"
            );
            continue;
        }
        frame.extend_from_slice(&(pkt.data.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(&pkt.data);
        let mut w = writer.lock().await;
        let outcome = match w.write_all(&frame).await {
            Ok(_) => match w.flush().await {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        match outcome {
            Ok(_) => bump(&metrics.downlink_packets),
            Err(e) => {
                tracing::debug!(
                    target: "rillane::trojan_udp",
                    client = %client,
                    error = %e,
                    "下行发送失败"
                );
                break; // 写侧死亡：关联收束，后续帧无意义
            }
        }
    }
}

/// 读帧地址段（`[ATYP][ADDR][PORT]`）；ATYP 处干净 EOF（0 字节）回 None
/// ——流边界即帧边界收束。
async fn read_frame_addr(rr: &mut (impl AsyncRead + Unpin)) -> Result<Option<(String, u16)>> {
    let mut atyp = [0u8; 1];
    match rr.read_exact(&mut atyp).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // read_exact 对 0 字节 EOF 报 UnexpectedEof——干净的帧边界收束
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }
    let host = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4];
            rr.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x04 => {
            let mut b = [0u8; 16];
            rr.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            rr.read_exact(&mut l).await?;
            let mut h = vec![0u8; l[0] as usize];
            rr.read_exact(&mut h).await?;
            String::from_utf8_lossy(&h).into_owned()
        }
        other => bail!("trojan UDP 未知地址类型: {other}"),
    };
    let mut port_b = [0u8; 2];
    rr.read_exact(&mut port_b).await?;
    Ok(Some((host, u16::from_be_bytes(port_b))))
}

/// 请求地址段读取（与帧地址段同形；请求侧 EOF 即错误）
async fn read_socks_addr(rr: &mut (impl AsyncRead + Unpin)) -> Result<(String, u16)> {
    match read_frame_addr(rr).await? {
        Some(x) => Ok(x),
        None => bail!("trojan 请求地址段截断"),
    }
}

/// SOCKS5 风格地址段编码（与 outbound/trojan.rs write_socks_addr 同口径：
/// 域名 >255 字节点名拒绝，拒发比发畸形帧安全）
fn write_socks_addr(out: &mut Vec<u8>, target: &FlowTarget) -> Result<()> {
    if target.host.len() > u8::MAX as usize {
        bail!("trojan: 目标主机名超长（>255 字节）");
    }
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(0x03);
        out.push(target.host.len() as u8);
        out.extend_from_slice(target.host.as_bytes());
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 密码哈希口径与客户端面一致（SHA224 小写 hex 56 字符）；空密码点名拒绝
    #[test]
    fn password_hash_matches_client_posture_and_empty_refused() {
        let h = to_hex(&Sha224::digest(b"test-trojan-password"));
        assert_eq!(h.len(), 56, "SHA224 hex 长 56");
        assert!(
            h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "小写 hex"
        );
        // 与 outbound/trojan.rs 客户端 password_hash 同值（镜像互源）
        let mut hasher = Sha224::new();
        hasher.update(b"test-trojan-password");
        assert_eq!(h, to_hex(&hasher.finalize()));

        let Err(err) = TrojanIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            String::new(),
            "x",
            "y",
            None,
            None,
        ) else {
            panic!("空密码必须拒绝");
        };
        assert!(err.to_string().contains("密码不得为空"), "{err}");
    }

    /// TLS 材料装配期校验：坏证书/坏私钥 PEM 点名拒绝（错误启动时暴露）
    #[test]
    fn tls_material_refused_at_assembly() {
        let Err(err) = TrojanIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "pw".into(),
            "not-a-cert-pem",
            "not-a-key-pem",
            None,
            None,
        ) else {
            panic!("坏材料必须拒绝");
        };
        // 垃圾输入：cert 无 PEM 块得空链，key 解析先点名（两段均 PEM 面）
        assert!(err.to_string().contains("PEM"), "{err}");
    }

    /// 地址段编码三形态：v4/v6/域名（与客户端 write_socks_addr 同口径）
    #[test]
    fn socks_addr_encode_ip_and_domain() {
        let v4 = FlowTarget {
            host: "203.0.113.9".into(),
            port: 8080,
            proto: TargetProto::Udp,
        };
        let mut out = Vec::new();
        write_socks_addr(&mut out, &v4).expect("v4 编码");
        assert_eq!(out, [0x01, 203, 0, 113, 9, 0x1F, 0x90]);

        let v6 = FlowTarget {
            host: "2001:db8::9".into(),
            port: 443,
            proto: TargetProto::Udp,
        };
        let mut out = Vec::new();
        write_socks_addr(&mut out, &v6).expect("v6 编码");
        assert_eq!(out[0], 0x04);
        assert_eq!(out.len(), 1 + 16 + 2);

        let domain = FlowTarget {
            host: "echo.example.com".into(),
            port: 53,
            proto: TargetProto::Udp,
        };
        let mut out = Vec::new();
        write_socks_addr(&mut out, &domain).expect("域名编码");
        assert_eq!(out[0], 0x03);
        assert_eq!(out[1] as usize, "echo.example.com".len());

        // 超长域名点名拒绝
        let long = FlowTarget {
            host: "a".repeat(256),
            port: 1,
            proto: TargetProto::Udp,
        };
        let mut out = Vec::new();
        let err = write_socks_addr(&mut out, &long).expect_err("超长域名必须拒绝");
        assert!(err.to_string().contains("超长"), "{err}");
    }
}
