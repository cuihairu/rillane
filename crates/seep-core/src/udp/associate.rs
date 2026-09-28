//! SOCKS5 UDP ASSOCIATE 入站服务（P0-2，udp-relay-path.md §2）。
//!
//! 职责：控制连接生命周期（RFC 1928：TCP 终止即结束关联）、中继 socket
//! 绑定（与 TCP 监听同端口）、数据报头解析与准入（FRAG≠0 / strict 源校验）、
//! 上行接会话表快路径、按会话摘下行通道并封帧回送。
//! 会话表侧（映射/forwarder/指标/回收）不在本模块，见 [`super::table`]。

use crate::udp::key::UdpSessionKey;
use crate::udp::metrics::DropReason;
use crate::udp::relay::{DownlinkPacket, EgressUdpConnector};
use crate::udp::table::{UdpSessionTable, UpResult};
use crate::{FlowContext, FlowMetadata, FlowTarget, TargetProto};
use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

// ---------- 数据报头编解码（RFC 1928 §7：RSV(2) FRAG(1) ATYP(1) ADDR PORT） ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpHeaderError {
    /// 长度不足（RSV/ATYP 截断或地址/端口截断）
    TooShort,
    /// 不支持的地址类型
    BadAtyp(u8),
}

/// 解析 SOCKS5 UDP 请求头，返回 (目标, 头部长度)。
/// 注意：UDP 数据报头**没有 VER 字段**（与 TCP 请求帧不同）。
pub fn parse_udp_header(buf: &[u8]) -> Result<(FlowTarget, usize), UdpHeaderError> {
    if buf.len() < 4 {
        return Err(UdpHeaderError::TooShort);
    }
    let atyp = buf[3];
    let (host, hlen) = match atyp {
        0x01 => {
            if buf.len() < 10 {
                return Err(UdpHeaderError::TooShort);
            }
            (
                Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]).to_string(),
                10,
            )
        }
        0x03 => {
            let l = buf[4] as usize;
            if buf.len() < 5 + l + 2 {
                return Err(UdpHeaderError::TooShort);
            }
            (
                String::from_utf8_lossy(&buf[5..5 + l]).into_owned(),
                5 + l + 2,
            )
        }
        0x04 => {
            if buf.len() < 22 {
                return Err(UdpHeaderError::TooShort);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            (Ipv6Addr::from(o).to_string(), 22)
        }
        a => return Err(UdpHeaderError::BadAtyp(a)),
    };
    let port = u16::from_be_bytes([buf[hlen - 2], buf[hlen - 1]]);
    Ok((
        FlowTarget {
            host,
            port,
            proto: TargetProto::Udp,
        },
        hlen,
    ))
}

/// 编码 SOCKS5 UDP 帧头（FRAG 恒 0，MVP 不做分片重组，上游 O2）。
pub fn encode_udp_header(target: &FlowTarget, payload_len: usize) -> Vec<u8> {
    let host = target.host.trim_matches(|c| c == '[' || c == ']');
    // 预判地址类型：IPv4 字面量 / IPv6 字面量 / 域名
    let (atyp, addr_bytes): (u8, Vec<u8>) = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        (0x01, v4.octets().to_vec())
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        (0x04, v6.octets().to_vec())
    } else {
        (0x03, host.as_bytes().to_vec())
    };
    let addr_len = addr_bytes.len() + if atyp == 0x03 { 1 } else { 0 };
    let mut out = Vec::with_capacity(4 + addr_len + 2 + payload_len);
    out.extend_from_slice(&[0x00, 0x00, 0x00, atyp]);
    if atyp == 0x03 {
        out.push(addr_bytes.len() as u8);
    }
    out.extend_from_slice(&addr_bytes);
    out.extend_from_slice(&target.port.to_be_bytes());
    out
}

// ---------- 入站侧指标（P0-5 接 /metrics；此处供测试直读） ----------

#[derive(Debug, Default)]
pub struct UdpIngressMetrics {
    pub associates_total: AtomicU64,
    pub associates_active: AtomicI64,
    pub associate_rejected: AtomicU64,
    pub uplink_packets: AtomicU64,
    pub downlink_packets: AtomicU64,
    pub frag_dropped: AtomicU64,
    pub source_dropped: AtomicU64,
    pub malformed_dropped: AtomicU64,
    pub associate_errors: AtomicU64,
}

impl UdpIngressMetrics {
    fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    /// 计量型指标（正负计数，如 associates_active）
    pub fn get_gauge(c: &AtomicI64) -> i64 {
        c.load(Ordering::Relaxed)
    }
}

// ---------- 服务 ----------

pub struct UdpAssociateService {
    table: Arc<UdpSessionTable>,
    connector: Arc<dyn EgressUdpConnector>,
    strict_udp_source: bool,
    metrics: Arc<UdpIngressMetrics>,
    /// 并发 ASSOCIATE 门（§2.6）：同一控制连接对端 (ip, port) 只允许一条
    active: Mutex<HashSet<SocketAddr>>,
    /// 周期回收任务随首个 ASSOCIATE 拉起（build 阶段无 tokio 上下文；
    /// 会话不可能先于任何 ASSOCIATE 存在，语义等价）
    reclaimer_once: std::sync::Once,
}

impl UdpAssociateService {
    pub fn new(
        table: Arc<UdpSessionTable>,
        connector: Arc<dyn EgressUdpConnector>,
        strict_udp_source: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            table,
            connector,
            strict_udp_source,
            metrics: Arc::new(UdpIngressMetrics::default()),
            active: Mutex::new(HashSet::new()),
            reclaimer_once: std::sync::Once::new(),
        })
    }

    pub fn table(&self) -> &Arc<UdpSessionTable> {
        &self.table
    }

    pub fn metrics(&self) -> &Arc<UdpIngressMetrics> {
        &self.metrics
    }

    pub fn strict_udp_source(&self) -> bool {
        self.strict_udp_source
    }

    /// 并发门登记（serve 内部使用；pub 供状态迁移/测试注入）
    pub fn try_register_associate(&self, peer: &SocketAddr) -> bool {
        self.active.lock().unwrap().insert(*peer)
    }

    /// 承载一条 ASSOCIATE 控制连接。调用前提：方法协商与认证已完成
    ///（`user` 为认证用户名，None = 无认证），请求帧已由命令分派读出。
    pub async fn serve(
        self: &Arc<Self>,
        control: &mut TcpStream,
        user: Option<String>,
    ) -> Result<()> {
        let peer = control.peer_addr()?;
        let local = control.local_addr()?;
        if !self.try_register_associate(&peer) {
            UdpIngressMetrics::inc(&self.metrics.associate_rejected);
            write_reply(control, 0x01, 0).await.ok(); // §2.6：general failure
            anyhow::bail!("并发 ASSOCIATE 被拒绝: {peer}");
        }
        UdpIngressMetrics::inc(&self.metrics.associates_total);
        self.metrics
            .associates_active
            .fetch_add(1, Ordering::Relaxed);
        self.reclaimer_once.call_once(|| {
            self.table.spawn_reclaimer();
        });
        let result = self.serve_inner(control, peer, local, user).await;
        self.active.lock().unwrap().remove(&peer);
        self.metrics
            .associates_active
            .fetch_sub(1, Ordering::Relaxed);
        result
    }

    async fn serve_inner(
        self: &Arc<Self>,
        control: &mut TcpStream,
        peer: SocketAddr,
        local: SocketAddr,
        user: Option<String>,
    ) -> Result<()> {
        // 中继 socket 与 TCP 监听同端口绑 UDP（§2.2；TCP/UDP 端口空间独立）
        let relay = match UdpSocket::bind((local.ip(), local.port())).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                write_reply(control, 0x01, 0).await.ok();
                return Err(e).context("UDP 中继 socket 绑定失败");
            }
        };
        let relay_port = relay.local_addr()?.port();
        // BND.ADDR = 0.0.0.0（客户端按控制连接对端 IP 处理），BND.PORT = 实际端口
        //（多宿主 advertise_addr 预留 = 上游 R3）
        write_reply(control, 0x00, relay_port).await?;
        tracing::info!(
            target: "seep::socks5_udp",
            client = %peer,
            relay_port,
            "UDP ASSOCIATE 建立"
        );

        let (closed_tx, closed_rx) = watch::channel(false);
        // 本关联实际使用过的粘滞键（数据报源端口可能与控制连接不同）
        let keys: Arc<Mutex<HashSet<UdpSessionKey>>> = Arc::new(Mutex::new(HashSet::new()));

        let uplink = tokio::spawn(uplink_loop(UdpUplink {
            service: Arc::clone(self),
            relay: Arc::clone(&relay),
            client_ip: peer.ip(),
            user,
            keys: Arc::clone(&keys),
            closed: closed_rx,
        }));

        // 控制连接 EOF 监视：TCP 终止 → 结束关联（§2.5）。控制连接上的
        // 后续字节无意义，读后即弃。
        let mut scratch = [0u8; 256];
        loop {
            match control.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }

        // teardown：停上行 → 吊销本关联键集（关下行→摘映射→计数在表侧）；
        // 各会话的下行任务随 rx 关闭自行退出。会话空闲回收不触碰控制连接（§2.5 反向）。
        let _ = closed_tx.send(true);
        let _ = uplink.await;
        let keys_to_revoke: Vec<UdpSessionKey> = keys.lock().unwrap().drain().collect();
        let revoked = keys_to_revoke.len();
        for key in keys_to_revoke {
            self.table.force_revoke(&key);
        }
        tracing::info!(
            target: "seep::socks5_udp",
            client = %peer,
            revoked_sessions = revoked,
            "UDP ASSOCIATE 结束"
        );
        Ok(())
    }
}

/// SOCKS5 控制面应答（VER REP RSV ATYP BND.ADDR BND.PORT）
async fn write_reply<S: AsyncWrite + Unpin>(s: &mut S, rep: u8, port: u16) -> Result<()> {
    let resp = [
        0x05,
        rep,
        0x00,
        0x01,
        0,
        0,
        0,
        0,
        (port >> 8) as u8,
        port as u8,
    ];
    s.write_all(&resp).await?;
    s.flush().await?;
    Ok(())
}

// ---------- 上行 ----------

struct UdpUplink {
    service: Arc<UdpAssociateService>,
    relay: Arc<UdpSocket>,
    client_ip: IpAddr,
    user: Option<String>,
    keys: Arc<Mutex<HashSet<UdpSessionKey>>>,
    closed: watch::Receiver<bool>,
}

async fn uplink_loop(mut u: UdpUplink) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = tokio::select! {
            _ = u.closed.changed() => break,
            r = u.relay.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(_) => break,
            },
        };
        UdpIngressMetrics::inc(&u.service.metrics.uplink_packets);

        // 源校验（§2.3 步骤 3）：数据报源 IP ≠ 控制连接对端 IP → 丢弃（防借用，R7）
        if u.service.strict_udp_source && src.ip() != u.client_ip {
            UdpIngressMetrics::inc(&u.service.metrics.source_dropped);
            continue;
        }
        // FRAG≠0 → 丢弃（§2.3 步骤 2）
        if buf.len() >= 3 && buf[2] != 0 {
            UdpIngressMetrics::inc(&u.service.metrics.frag_dropped);
            continue;
        }
        // 头解析（步骤 1）
        let (target, hlen) = match parse_udp_header(&buf[..n]) {
            Ok(x) => x,
            Err(_) => {
                UdpIngressMetrics::inc(&u.service.metrics.malformed_dropped);
                continue;
            }
        };
        let data = Bytes::copy_from_slice(&buf[hlen..n]);
        // 换源端口 = 新粘滞键 = 新会话（§2.3 换源语义，不做迁移）
        let key = UdpSessionKey::new(src).with_user(u.user.clone());
        u.keys.lock().unwrap().insert(key.clone());

        // 快路径（步骤 4-5）：命中映射直接发
        match u
            .service
            .table
            .forward_up(&key, &target, data.clone())
            .await
        {
            UpResult::Sent => continue,
            UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            } => break,
            _ => {}
        }
        // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
        if let Err(e) = u.slow_path(&key, &target, src, data).await {
            UdpIngressMetrics::inc(&u.service.metrics.associate_errors);
            tracing::debug!(
                target: "seep::socks5_udp",
                client = %src,
                target = %target.host,
                error = %e,
                "UDP 慢路径失败，数据报丢弃"
            );
        }
    }
}

impl UdpUplink {
    async fn slow_path(
        &self,
        key: &UdpSessionKey,
        target: &FlowTarget,
        src: SocketAddr,
        data: Bytes,
    ) -> Result<()> {
        let sref = self.service.table.resolve(key, target).await?;
        if !sref.has_mapping(target) {
            // 关联时机：首包路由决策产出后、映射创建处（relay-path §4.1）
            let ctx = FlowContext {
                id: sref.id().clone(),
                target: target.clone(),
                metadata: FlowMetadata::default(),
            };
            // 粘滞决策：resolve→ensure_decision 已产出并缓存于会话（relay-path §3.4）
            let decision = sref
                .decision()
                .ok_or_else(|| anyhow::anyhow!("会话缺少路由决策（resolve 应已产出）"))?;
            let relay = self
                .service
                .connector
                .associate(ctx, &decision)
                .await
                .context("出站 UDP 关联失败")?;
            sref.bind_mapping(target, relay).await?;
            // 按会话摘下行通道 → 封 SOCKS5 帧回送客户端（§2.4）
            if let Some(rx) = sref.take_downlink_rx().await {
                tokio::spawn(downlink_loop(
                    rx,
                    Arc::clone(&self.relay),
                    src,
                    Arc::clone(&self.service.metrics),
                ));
            }
        }
        match sref.send_up(target, data).await {
            UpResult::Sent => Ok(()),
            // Miss：映射刚被 §3.6 策略吊销——本包丢弃，下一包重新关联
            UpResult::Miss => Ok(()),
            UpResult::Dropped { .. } => Ok(()), // 已在表侧计数，UDP 静默丢弃语义
        }
    }
}

// ---------- 下行 ----------

async fn downlink_loop(
    mut rx: mpsc::Receiver<DownlinkPacket>,
    relay: Arc<UdpSocket>,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
) {
    while let Some(pkt) = rx.recv().await {
        let mut frame = encode_udp_header(&pkt.target, pkt.data.len());
        frame.extend_from_slice(&pkt.data);
        match relay.send_to(&frame, client).await {
            Ok(_) => UdpIngressMetrics::inc(&metrics.downlink_packets),
            Err(e) => {
                tracing::debug!(
                    target: "seep::socks5_udp",
                    client = %client,
                    error = %e,
                    "下行发送失败"
                );
            }
        }
    }
}
