//! Shadowsocks 入口协议实现（RIL-134）
//!
//! 复用 shadowsocks crate server 面（两语 protocol-backends.md shadowsocks
//! 服务端面评估——自写无增益）：TCP 面 `ProxyListener`（accept → handshake
//! 解出目标，解密流即 Flow io）+ UDP 面 `ProxySocket`（`UdpSocketType::
//! Server` 数据报解包/封包），会话生命周期归 `UdpSessionTable`（与 socks5
//! ASSOCIATE 同机制：粘滞路由、空闲回收、链路失败吊销）。
//! method/password 校验与 egress 同口径（none/未编译面点名拒绝、SS2022
//! base64 密钥形状），拒绝落在装配期（`ShadowsocksIngress::new` 即校验）。
//! SIP003 插件服务端面未交付（IR 不留字段）。

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Once,
    },
};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rillane_core::udp::{
    DownlinkPacket, DropReason, EgressUdpConnector, UdpIngressMetrics, UdpSessionKey,
    UdpSessionTable, UpResult,
};
use rillane_core::{
    fake_ip, BoxedIo, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget,
    IngressEndpoint, TargetProto,
};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context as SsContext,
    crypto::CipherKind,
    net::{AcceptOpts, TcpListener as ShadowTcpListener, UdpSocket as ShadowUdpSocket},
    relay::socks5::Address,
    relay::tcprelay::{ProxyListener, ProxyServerStream},
    relay::udprelay::proxy_socket::{ProxySocket, UdpSocketType},
};
use tokio::net::{TcpStream, UdpSocket};

/// SS UDP 面装配件：进程级会话表 + 出站连接器族（与 socks5 ASSOCIATE /
/// TUN 同源共享，由 RuntimeBuilder 从 UdpAssociateService 抽出传入）
#[derive(Clone)]
pub struct ShadowsocksUdpParts {
    pub table: Arc<UdpSessionTable>,
    pub connector: Arc<dyn EgressUdpConnector>,
}

/// Shadowsocks 入口服务
pub struct ShadowsocksIngress {
    name: String,
    bind: String,
    /// server 面配置（cipher/password 校验已随构造完成）
    svr_cfg: ServerConfig,
    /// UDP 数据报面（None = udp 未启用——数据报面不绑定）
    udp: Option<ShadowsocksUdpParts>,
    /// fake-ip 池（G1-10；None = 关闭，target 原样路由；TCP/UDP 两面共用）
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    /// 周期回收任务随 UDP 面启动拉起（build 阶段无 tokio 上下文；与
    /// associate 服务各自 Once——双 UDP 面并存时至多两路 sweep，幂等无害）
    reclaimer_once: Arc<Once>,
}

impl ShadowsocksIngress {
    pub fn new(
        name: String,
        bind: String,
        method: String,
        password: String,
        udp: Option<ShadowsocksUdpParts>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<Self> {
        // 构建期校验（egress 同口径；配置错误启动时暴露，而非首个连接时）
        let cipher = validate_method_password(&method, &password)?;
        let addr: std::net::SocketAddr = bind
            .parse()
            .with_context(|| format!("shadowsocks 入口 bind 非法: {bind}"))?;
        let svr_cfg = ServerConfig::new(addr, password, cipher)?;
        Ok(Self {
            name,
            bind,
            svr_cfg,
            udp,
            fake_ip,
            reclaimer_once: Arc::new(Once::new()),
        })
    }

    /// CONNECT 既有路径（socks5 forward_tcp 同构）：协议头解出目标 →
    /// fake-ip 回填 → Flow 流式转发。
    async fn forward_tcp(
        ingress_node_name: &str,
        client_addr: SocketAddr,
        mut stream: ProxyServerStream<TcpStream>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<()> {
        let target_addr = stream.handshake().await.context("shadowsocks 握手失败")?;
        let (mut host, port) = match target_addr {
            Address::SocketAddress(sa) => (sa.ip().to_string(), sa.port()),
            Address::DomainNameAddress(d, p) => (d, p),
        };

        let mut metadata = FlowMetadata {
            tags: vec![
                "ingress:shadowsocks".into(),
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

    async fn handle_client(
        self: Arc<Self>,
        stream: ProxyServerStream<TcpStream>,
        peer: SocketAddr,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        Self::forward_tcp(
            self.name.as_str(),
            peer,
            stream,
            router,
            output,
            self.fake_ip.clone(),
        )
        .await
    }
}

#[async_trait]
impl IngressEndpoint for ShadowsocksIngress {
    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // UDP 数据报面（同端口绑定；None = udp 未启用不绑）
        if let Some(parts) = self.udp.clone() {
            let bind = self.bind.clone();
            let svr_cfg = self.svr_cfg.clone();
            let fake_ip = self.fake_ip.clone();
            let reclaimer = Arc::clone(&self.reclaimer_once);
            tokio::spawn(async move {
                if let Err(err) = serve_udp(&bind, &svr_cfg, parts, fake_ip, reclaimer).await {
                    tracing::warn!(
                        target: "rillane::shadowsocks_udp",
                        bind = %bind,
                        error = %err,
                        "shadowsocks UDP 面收束"
                    );
                }
            });
        }

        let listener = ShadowTcpListener::bind_with_opts(
            &self
                .bind
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("shadowsocks 入口 bind 非法: {}", self.bind))?,
            AcceptOpts::default(),
        )
        .await
        .with_context(|| format!("无法监听 {}", self.bind))?;
        let svr_cfg = self.svr_cfg.clone();
        let listener = ProxyListener::from_listener(
            SsContext::new_shared(ServerType::Server),
            listener,
            &svr_cfg,
        );

        tracing::info!(
            target: "rillane::shadowsocks",
            bind = %self.bind,
            "Shadowsocks 入口启动"
        );

        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();

            tokio::spawn(async move {
                if let Err(err) = this.handle_client(stream, peer, router, output).await {
                    tracing::warn!(
                        target: "rillane::shadowsocks",
                        client = %peer,
                        error = %err,
                        "Shadowsocks 连接处理失败"
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

/// SS UDP 数据报面主循环：解包（crate server 面处理加密与 SS 头）→
/// fake-ip 回填 → 会话表快/慢路径（与 socks5 ASSOCIATE uplink 同构）→
/// 下行任务按会话摘通道回封回送。
async fn serve_udp(
    bind: &str,
    svr_cfg: &ServerConfig,
    parts: ShadowsocksUdpParts,
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    reclaimer_once: Arc<Once>,
) -> Result<()> {
    let addr: std::net::SocketAddr = bind
        .parse()
        .with_context(|| format!("shadowsocks 入口 bind 非法: {bind}"))?;
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("无法绑定 UDP {addr}"))?;
    let ctx = SsContext::new_shared(ServerType::Server);
    let socket = Arc::new(ProxySocket::from_socket(
        UdpSocketType::Server,
        ctx,
        svr_cfg,
        ShadowUdpSocket::from(socket),
    ));

    // 会话回收任务随 UDP 面启用即拉起（纯 SS 入口无 ASSOCIATE，无人
    // 代拉；重复 sweep 幂等）
    reclaimer_once.call_once(|| {
        parts.table.spawn_reclaimer();
    });

    let metrics = Arc::new(UdpIngressMetrics::default());
    tracing::info!(
        target: "rillane::shadowsocks_udp",
        bind = %addr,
        "Shadowsocks UDP 数据报面启动"
    );

    let mut buf = vec![0u8; 65535];
    loop {
        // crate server 面：解密 + SS 头解析一步完成（n=载荷长，off=载荷偏移）
        let (n, peer, target, _off) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => break,
        };
        bump(&metrics.uplink_packets);
        let Some((mut host, port)) = address_parts(&target) else {
            bump(&metrics.malformed_dropped);
            continue;
        };
        // fake-ip 回填（G1-10 UDP 面）：数据报 target 为池段假 IPv4 时
        // 反查原域名改写（域名/池外 IP 不命中即原样）。改写先于粘滞键
        // 建立——会话按改写后 target 绑定，同域名后续数据报复用会话。
        if let Some(table) = fake_ip.as_ref() {
            if let Some(domain) = fake_ip::reverse_host(table, &host) {
                host = domain;
            }
        }
        let target = FlowTarget {
            host,
            port,
            proto: TargetProto::Udp,
        };
        let data = Bytes::copy_from_slice(&buf[..n]);
        let key = UdpSessionKey::new(peer);

        // 快路径：命中映射直接发
        match parts.table.forward_up(&key, &target, data.clone()).await {
            UpResult::Sent => continue,
            UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            } => break,
            _ => {}
        }
        // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
        if let Err(e) = slow_path(&parts, &socket, &metrics, &key, &target, peer, data).await {
            bump(&metrics.associate_errors);
            tracing::debug!(
                target: "rillane::shadowsocks_udp",
                client = %peer,
                target = %target.host,
                error = %e,
                "UDP 慢路径失败，数据报丢弃"
            );
        }
    }
    Ok(())
}

async fn slow_path(
    parts: &ShadowsocksUdpParts,
    socket: &Arc<ProxySocket<ShadowUdpSocket>>,
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
        // 按会话摘下行通道 → SS 封包回送客户端（crate server 面）
        if let Some(rx) = sref.take_downlink_rx().await {
            let socket = Arc::clone(socket);
            let metrics = Arc::clone(metrics);
            tokio::spawn(downlink_loop(socket, rx, peer, metrics));
        }
    }
    match sref.send_up(target, data).await {
        UpResult::Sent => Ok(()),
        // Miss：映射刚被吊销——本包丢弃，下一包重新关联
        UpResult::Miss => Ok(()),
        UpResult::Dropped { .. } => Ok(()), // 已在表侧计数，UDP 静默丢弃语义
    }
}

/// 下行任务：会话下行通道 → SS 回包封包（源地址段 = 原目标，客户端按
/// 回包地址段区分来源）回送客户端
async fn downlink_loop(
    socket: Arc<ProxySocket<ShadowUdpSocket>>,
    mut rx: tokio::sync::mpsc::Receiver<DownlinkPacket>,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
) {
    while let Some(pkt) = rx.recv().await {
        let addr = to_ss_address(&pkt.target);
        match socket.send_to(client, &addr, &pkt.data).await {
            Ok(_) => bump(&metrics.downlink_packets),
            Err(e) => {
                tracing::debug!(
                    target: "rillane::shadowsocks_udp",
                    client = %client,
                    error = %e,
                    "下行发送失败"
                );
            }
        }
    }
}

/// FlowTarget → SS 地址段（回包用；方括号剥除同 encode_udp_header 口径）
fn to_ss_address(target: &FlowTarget) -> Address {
    let host = target.host.trim_matches(|c| c == '[' || c == ']');
    match host.parse::<IpAddr>() {
        Ok(ip) => Address::SocketAddress(SocketAddr::new(ip, target.port)),
        Err(_) => Address::DomainNameAddress(host.to_string(), target.port),
    }
}

/// SS 地址段 → (host, port)（解包用）
fn address_parts(addr: &Address) -> Option<(String, u16)> {
    match addr {
        Address::SocketAddress(sa) => Some((sa.ip().to_string(), sa.port())),
        Address::DomainNameAddress(d, p) => Some((d.to_string(), *p)),
    }
}

/// 构建期校验（egress shadowsocks 同口径）：方法须在编译面且非 none；
/// SS2022 password = base64 密钥且长度与算法密钥长精确一致
fn validate_method_password(method: &str, password: &str) -> Result<CipherKind> {
    let cipher = method
        .parse::<CipherKind>()
        .map_err(|_| anyhow::anyhow!("不支持的加密方法: {method}"))?;
    if cipher == CipherKind::NONE {
        bail!("加密方法 none（无加密）不放行: {method}");
    }
    if cipher.is_aead_2022() {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(password)
            .map_err(|_| anyhow::anyhow!("SS2022 密码须为 base64 密钥: {method}"))?;
        let need = cipher.key_len();
        if key.len() != need {
            bail!(
                "SS2022 密钥长度须为 {need} 字节，得 {} 字节: {method}",
                key.len()
            );
        }
    }
    Ok(cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构建期点名拒绝：none（无加密不进数据面）与 stream 时代方法名
    /// （特性未编译）
    #[test]
    fn validation_refuses_none_and_uncompiled_methods() {
        let err = validate_method_password("none", "whatever").expect_err("none 必须拒绝");
        assert!(err.to_string().contains("none（无加密）不放行"), "{err}");
        for name in ["rc4-md5", "aes-cfb128", "chacha20-ietf"] {
            let err = validate_method_password(name, "whatever").expect_err("未编译面必须拒绝");
            assert!(err.to_string().contains("不支持的加密方法"), "{err}");
        }
    }

    /// SS2022 password 形状：base64 且长度与算法密钥长精确一致
    #[test]
    fn validation_enforces_ss2022_password_shape() {
        use base64::Engine as _;
        // 非 base64
        let err = validate_method_password("2022-blake3-aes-128-gcm", "不是base64!!")
            .expect_err("非 base64 必须拒绝");
        assert!(err.to_string().contains("base64"), "{err}");
        // 错长度（aes-128 需 16B，给 32B）
        let long = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let err =
            validate_method_password("2022-blake3-aes-128-gcm", &long).expect_err("错长度必须拒绝");
        assert!(err.to_string().contains("16 字节"), "{err}");
        // 正确形状放行
        let ok = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        assert!(validate_method_password("2022-blake3-aes-128-gcm", &ok).is_ok());
        // v1 AEAD 任意串放行
        assert!(validate_method_password("aes-128-gcm", "arbitrary-password").is_ok());
    }

    /// FlowTarget ↔ SS 地址段互转：v4/v6/域名三形态
    #[test]
    fn ss_address_roundtrip_ip_and_domain() {
        let v4 = FlowTarget {
            host: "203.0.113.9".into(),
            port: 8080,
            proto: TargetProto::Udp,
        };
        match to_ss_address(&v4) {
            Address::SocketAddress(sa) => {
                assert_eq!(sa.to_string(), "203.0.113.9:8080");
                assert_eq!(
                    address_parts(&Address::SocketAddress(sa)),
                    Some(("203.0.113.9".into(), 8080))
                );
            }
            other => panic!("v4 字面量须为 SocketAddress: {other:?}"),
        }
        let v6 = FlowTarget {
            host: "2001:db8::9".into(),
            port: 443,
            proto: TargetProto::Udp,
        };
        assert!(matches!(to_ss_address(&v6), Address::SocketAddress(_)));
        let domain = FlowTarget {
            host: "echo.example.com".into(),
            port: 53,
            proto: TargetProto::Udp,
        };
        assert_eq!(
            address_parts(&to_ss_address(&domain)),
            Some(("echo.example.com".into(), 53))
        );
    }
}
