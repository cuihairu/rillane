//! VLESS 入口协议实现（RIL-136）
//!
//! 自写 server 面（评估见两语 protocol-backends.md vless 服务端面段——
//! xray-rs 1.0.3 有可组合形状的入站 Handler，但单包无特性门（1192 文件），
//! 引入即拖整个 Xray 内核进工作区；meow-proxy 仅出口面；jets 无 VLESS
//! 入站）。帧原语与仓内已验收客户端面（outbound/vless.rs）镜像互源：
//! 请求 `[0x00][UUID 16B][OptLen][addons][CMD][Port BE][ATYP addr]`
//! （CMD 0x01 TCP / 0x02 UDP；ATYP 1=v4 / 2=域名 / 3=v6，xray 口径），
//! UUID 16 字节恒时比对；响应头 `[Version][OptLen][Opt]` 于中继前写出
//! （TCP/UDP 两路均写，客户端 associate 在 UDP 路径亦先读响应头）。
//! UDP 单连接单目标，双向 `[2B BE len][payload]` 帧；packetaddr/xudp
//! 服务端面未交付（请求目标命中 magic 地址即点名拒绝）。会话生命周期
//! 归 `UdpSessionTable`（与 socks5 ASSOCIATE 同机制：粘滞决策、空闲回收；
//! 控制流 = TLS 流本体，EOF 即吊销本关联键——socks5 §2.5 同语义）。
//! TLS 材料随 IR 内联（PEM），装配期解析（`VlessIngress::new` 即装配）。

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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use uuid::Uuid;

use rillane_core::udp::{
    DownlinkPacket, DropReason, EgressUdpConnector, UdpIngressMetrics, UdpSessionKey,
    UdpSessionTable, UpResult,
};
use rillane_core::{
    constant_time_eq, fake_ip, BoxedIo, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput,
    FlowRouter, FlowTarget, IngressEndpoint, TargetProto,
};

use crate::tls::tls_crypto_provider;

/// packetaddr magic 地址（镜像 outbound/vless_packet.rs；私有 mod 不可跨
/// 引用，字面量同源注释锚定）。命中即点名拒绝：packetaddr/xudp 服务端面
/// 未交付（RIL-136 交付边界）。
const PACKETADDR_MAGIC_HOST: &str = "sp.packet-addr.v2fly.arpa";

/// VLESS UDP 关联面装配件：进程级会话表 + 出站连接器族（与 socks5
/// ASSOCIATE / TUN 同源共享，由 RuntimeBuilder 从 UdpAssociateService 抽出传入）
#[derive(Clone)]
pub struct VlessUdpParts {
    pub table: Arc<UdpSessionTable>,
    pub connector: Arc<dyn EgressUdpConnector>,
}

/// VLESS 入口服务
#[derive(Clone)]
pub struct VlessIngress {
    name: String,
    bind: String,
    /// 认证基准：UUID 16 字节（恒时比对）
    uuid_bytes: [u8; 16],
    /// TLS server 面（PEM 材料已随构造装配；TlsAcceptor = Arc 共享）
    acceptor: TlsAcceptor,
    /// UDP 关联面（None = udp 未启用——CMD 0x02 连接收束）
    udp: Option<VlessUdpParts>,
    /// fake-ip 池表（G1-10；None = 关闭，target 原样路由；TCP/UDP 两面共用）
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    /// 周期回收任务随 UDP 面启用拉起（与 associate 服务各自 Once——多 UDP
    /// 面并存时至多两路 sweep，幂等无害）
    reclaimer_once: Arc<Once>,
}

impl VlessIngress {
    pub fn new(
        name: String,
        bind: String,
        uuid: &str,
        cert_pem: &str,
        key_pem: &str,
        udp: Option<VlessUdpParts>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<Self> {
        let id =
            Uuid::parse_str(uuid.trim()).context("vless 入口 uuid 非法（须为标准 UUID 形）")?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .context("vless 入口证书 PEM 解析失败")?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .context("vless 入口私钥 PEM 解析失败")?;
        let config = rustls::ServerConfig::builder_with_provider(tls_crypto_provider())
            .with_safe_default_protocol_versions()
            .context("vless 入口 TLS 协议版本装配失败")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("vless 入口 TLS 证书装配失败")?;
        bind.parse::<SocketAddr>()
            .with_context(|| format!("vless 入口 bind 非法: {bind}"))?;
        Ok(Self {
            name,
            bind,
            uuid_bytes: *id.as_bytes(),
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
                "ingress:vless".into(),
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

    /// UDP 关联（CMD 0x02）：响应头写出后进帧循环。单连接单目标（raw
    /// 编码，xray 原生 UDP 面）——请求目标即本关联唯一目标，双向帧
    /// `[2B BE len][payload]` 不携地址段。控制流 = TLS 流本体，EOF 即
    /// 吊销本关联键（socks5 §2.5 同语义）。
    async fn serve_association(
        &self,
        mut stream: TlsStream<TcpStream>,
        peer: SocketAddr,
        target: FlowTarget,
    ) -> Result<()> {
        let Some(parts) = self.udp.as_ref() else {
            bail!("vless UDP 关联面未启用（udp 门关闭），连接收束");
        };
        // packetaddr/xudp 服务端面未交付：命中 magic 地址即点名拒绝
        if target.host == PACKETADDR_MAGIC_HOST {
            bail!("vless UDP packetaddr/xudp 服务端面未交付（raw 编码仅为交付面），连接收束");
        }
        // fake-ip 回填（G1-10 UDP 面）：请求目标为池段假 IPv4 时反查原域名
        let mut host = target.host;
        if let Some(t) = self.fake_ip.as_ref() {
            if let Some(domain) = fake_ip::reverse_host(t, &host) {
                host = domain;
            }
        }
        let target = FlowTarget {
            host,
            port: target.port,
            proto: TargetProto::Udp,
        };

        // 响应头 [Version(0)][OptLen(0)] 先于帧循环（客户端 associate 于
        // UDP 路径亦先读响应头再进帧解析）
        write_response_header(&mut stream).await?;

        let (mut rr, ww) = tokio::io::split(stream);
        let writer = Arc::new(tokio::sync::Mutex::new(ww));
        let metrics = Arc::new(UdpIngressMetrics::default());
        let key = UdpSessionKey::new(peer);

        let uplink = uplink_loop(parts, &mut rr, writer, peer, &target, &metrics).await;

        // 控制流终止 → 吊销本关联键（关下行 → 摘映射 → 计数在表侧）
        let revoked = parts.table.force_revoke(&key);
        tracing::debug!(
            target: "rillane::vless_udp",
            client = %peer,
            revoked,
            "vless UDP 关联收束"
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

        // 请求头：Version(1) UUID(16) OptLen(1)
        let mut head = [0u8; 18];
        tls.read_exact(&mut head)
            .await
            .context("vless 请求头读取")?;
        if head[0] != 0x00 {
            bail!("vless 协议版本不支持: {}", head[0]);
        }
        if !constant_time_eq(&head[1..17], &self.uuid_bytes) {
            bail!("vless uuid 不匹配（恒时比对），连接收束");
        }
        let opt_len = head[17] as usize;
        if opt_len > 0 {
            let mut addons = vec![0u8; opt_len];
            tls.read_exact(&mut addons)
                .await
                .context("vless 请求 addons 读取")?;
            refuse_vision_addons(&addons)?;
        }
        let mut cmd_b = [0u8; 1];
        tls.read_exact(&mut cmd_b).await.context("vless 命令读取")?;
        let (host, port) = read_xray_addr(&mut tls).await?;

        match cmd_b[0] {
            0x01 => {
                // 响应头先于中继（客户端 forward 读响应头后才双向搬运）
                write_response_header(&mut tls).await?;
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
            0x02 => {
                let target = FlowTarget {
                    host,
                    port,
                    proto: TargetProto::Udp,
                };
                self.serve_association(tls, peer, target).await
            }
            other => bail!("vless 未知命令: {other}"),
        }
    }
}

/// Vision flow（xtls-rprx-vision）服务端组合另验（RIL-136 另验口径）：
/// addons 携 flow 即点名拒绝（xray addons protobuf 的 flow 字段为明文
/// UTF-8 子串，子串比对足以识别，免完整 protobuf 解码）
fn refuse_vision_addons(addons: &[u8]) -> Result<()> {
    const FLOW_VISION: &[u8] = b"xtls-rprx-vision";
    if addons.windows(FLOW_VISION.len()).any(|w| w == FLOW_VISION) {
        bail!("vless 入口暂不受理 Vision flow（服务端 Vision/REALITY 组合另验），连接收束");
    }
    Ok(())
}

#[async_trait]
impl IngressEndpoint for VlessIngress {
    fn name(&self) -> &'static str {
        "vless"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // 会话回收任务随 UDP 面启用即拉起（纯 VLESS 入口无 ASSOCIATE，
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
            target: "rillane::vless",
            bind = %self.bind,
            "VLESS 入口启动"
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
                        target: "rillane::vless",
                        client = %peer,
                        error = %err,
                        "VLESS 连接处理失败"
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

/// 响应头 `[Version(0)][OptLen(0)]`（Opt 面未交付，恒空——客户端
/// read_vless_response_header 按 OptLen 弹性读取，0 即两字节收束）
async fn write_response_header(w: &mut TlsStream<TcpStream>) -> Result<()> {
    w.write_all(&[0x00, 0x00]).await?;
    w.flush().await?;
    Ok(())
}

/// 上行循环：逐帧 `[2B BE len][payload]` → 会话表快/慢路径（与 socks5
/// ASSOCIATE uplink 同构；目标恒为关联时绑定的单目标）。
async fn uplink_loop(
    parts: &VlessUdpParts,
    rr: &mut (impl AsyncRead + Unpin),
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TlsStream<TcpStream>>>>,
    peer: SocketAddr,
    target: &FlowTarget,
    metrics: &Arc<UdpIngressMetrics>,
) -> Result<()> {
    let key = UdpSessionKey::new(peer);
    let mut payload = vec![0u8; 65535];
    loop {
        let mut len_b = [0u8; 2];
        match rr.read_exact(&mut len_b).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(()); // 干净 EOF：帧边界收束
            }
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_b) as usize;
        rr.read_exact(&mut payload[..len]).await?;
        bump(&metrics.uplink_packets);
        let data = Bytes::copy_from_slice(&payload[..len]);

        // 快路径：命中映射直接发
        match parts.table.forward_up(&key, target, data.clone()).await {
            UpResult::Sent => continue,
            UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            } => bail!("会话表收束，vless UDP 关联终止"),
            _ => {}
        }
        // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
        if let Err(e) = slow_path(parts, &writer, metrics, &key, target, peer, data).await {
            bump(&metrics.associate_errors);
            tracing::debug!(
                target: "rillane::vless_udp",
                client = %peer,
                target = %target.host,
                error = %e,
                "UDP 慢路径失败，数据报丢弃"
            );
        }
    }
}

async fn slow_path(
    parts: &VlessUdpParts,
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
        // 按会话摘下行通道 → vless 帧沿 TLS 流回送客户端
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

/// 下行任务：会话下行通道 → `[2B BE len][payload]` 帧沿 TLS 流回送客户端
/// （单目标关联：帧不携地址段，客户端按关联时目标对齐）
async fn downlink_loop(
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TlsStream<TcpStream>>>>,
    mut rx: tokio::sync::mpsc::Receiver<DownlinkPacket>,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
) {
    while let Some(pkt) = rx.recv().await {
        let mut frame = Vec::with_capacity(pkt.data.len() + 2);
        frame.extend_from_slice(&(pkt.data.len() as u16).to_be_bytes());
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
                    target: "rillane::vless_udp",
                    client = %client,
                    error = %e,
                    "下行发送失败"
                );
                break; // 写侧死亡：关联收束，后续帧无意义
            }
        }
    }
}

/// 请求地址段读取（xray 线序：`[Port BE][ATYP][ADDR]`——Command 后端口
/// 在地址之前，与 outbound/vless.rs build_vless_request_bytes 编码镜像
/// 互源；ATYP 1=IPv4 2=域名 3=IPv6；请求侧 EOF 即错误）
async fn read_xray_addr(rr: &mut (impl AsyncRead + Unpin)) -> Result<(String, u16)> {
    let mut port_b = [0u8; 2];
    rr.read_exact(&mut port_b).await?;
    let port = u16::from_be_bytes(port_b);
    let mut atyp = [0u8; 1];
    rr.read_exact(&mut atyp).await?;
    let host = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4];
            rr.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut b = [0u8; 16];
            rr.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        0x02 => {
            let mut l = [0u8; 1];
            rr.read_exact(&mut l).await?;
            let mut h = vec![0u8; l[0] as usize];
            rr.read_exact(&mut h).await?;
            String::from_utf8_lossy(&h).into_owned()
        }
        other => bail!("vless 请求地址类型未知: {other}"),
    };
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UUID 装配期校验：非法形点名拒绝；合法形入基（16 字节恒等）
    #[test]
    fn uuid_parse_validated_at_assembly() {
        let Err(err) = VlessIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "not-a-uuid",
            "x",
            "y",
            None,
            None,
        ) else {
            panic!("非法 uuid 必须拒绝");
        };
        assert!(err.to_string().contains("uuid"), "{err}");

        // 合法形：与客户端 uuid_bytes 镜像互源（Uuid::as_bytes）
        let id = Uuid::parse_str("b831381d-6324-4d2a-b1e7-1bf75a1db7b3").expect("样本 uuid");
        assert_eq!(id.as_bytes().len(), 16);
    }

    /// TLS 材料装配期校验：坏证书/坏私钥 PEM 点名拒绝（错误启动时暴露）
    #[test]
    fn tls_material_refused_at_assembly() {
        let Err(err) = VlessIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "b831381d-6324-4d2a-b1e7-1bf75a1db7b3",
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

    /// Vision flow addons 点名拒绝；无 flow 的 addons 放行
    #[test]
    fn vision_addons_refused_others_pass() {
        // xray addons protobuf 形：flow 字段携明文 "xtls-rprx-vision"
        let vision_addons = b"\x12\x10xtls-rprx-vision";
        let err = refuse_vision_addons(vision_addons).expect_err("vision 必须拒绝");
        assert!(err.to_string().contains("Vision"), "{err}");

        // 空 addons（OptLen>0 但无 flow 载荷）放行
        refuse_vision_addons(b"").expect("空 addons 放行");
        // 非 vision 载荷放行
        refuse_vision_addons(b"\x08\x01").expect("非 vision addons 放行");
    }

    /// 请求地址段解码三形态：v4/域名/v6（线序 `[Port BE][ATYP][ADDR]`，
    /// xray 口径——与客户端 build_vless_request_bytes 编码镜像互源）
    #[tokio::test]
    async fn xray_addr_decode_ip_and_domain() {
        // v4: port BE + ATYP 1 + 4B
        let v4 = [0x1F, 0x90, 0x01, 203, 0, 113, 9];
        let (host, port) = read_xray_addr(&mut std::io::Cursor::new(v4))
            .await
            .expect("v4 解码");
        assert_eq!((host.as_str(), port), ("203.0.113.9", 8080));

        // 域名: port BE + ATYP 2 + len + bytes
        let mut domain = 53u16.to_be_bytes().to_vec();
        domain.push(0x02);
        domain.push(9);
        domain.extend_from_slice(b"echo.test");
        let (host, port) = read_xray_addr(&mut std::io::Cursor::new(domain))
            .await
            .expect("域名解码");
        assert_eq!((host.as_str(), port), ("echo.test", 53));

        // v6: port BE + ATYP 3 + 16B（xray 口径 3=v6）
        let mut v6 = 443u16.to_be_bytes().to_vec();
        v6.push(0x03);
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let (host, port) = read_xray_addr(&mut std::io::Cursor::new(v6))
            .await
            .expect("v6 解码");
        assert_eq!(host, "2001:db8::9");
        assert_eq!(port, 443);

        // 未知 ATYP 点名拒绝
        let bad = [0x00, 0x35, 0x09, 0x00];
        let err = read_xray_addr(&mut std::io::Cursor::new(bad))
            .await
            .expect_err("未知 ATYP 必须拒绝");
        assert!(err.to_string().contains("地址类型未知"), "{err}");
    }
}
