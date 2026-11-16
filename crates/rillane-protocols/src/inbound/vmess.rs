//! VMess 入口协议实现（RIL-137）
//!
//! 自写 server 面（评估见两语 protocol-backends.md vmess 服务端面段——
//! vmess-rs 0.0.0 为 869 字节零依赖空壳；tobira AGPL-3.0 且 binary-only
//! path 依赖拖整个应用内核；xray-rs/shoes/corduit/jets/meow-proxy 均沿
//! 前判）。帧原语与仓内已验收客户端面（outbound/vmess.rs）镜像互源：
//! 封头 `authID(16) ‖ 长度块 AEAD(18) ‖ connNonce(8) ‖ 头块 AEAD`
//! 两段流式开面；authID = AES-128-ECB([8B unix BE][4B rand][4B CRC32])，
//! CRC 快筛 + ±120s 时间窗 + 防重放缓存（同 authID 二次命中即收束——
//! 客户端每次建连换 rand4，正常流量无误伤面）。明文请求头
//! `[0x01][reqIV][reqKey][V][opt][sec][rsv][cmd][port BE][ATYP addr]
//! [padding][FNV1a32 BE]`：option 恒 0x0D（AEAD 分块面），security 仅
//! AEAD 0x03/0x04（客户端自选，服务端照开），命令 0x01 TCP / 0x02 UDP。
//! 裸 TCP 承载（无 TLS——VMess AEAD 封头即认证面）；TCP 经 duplex 明文桥
//! 接 Flow（分块密面 ↔ 明文面，终止块/半关闭同 client relay 口径）；
//! UDP 单连接单目标，双向逐数据报一块，无终止块语义。会话生命周期归
//! `UdpSessionTable`（与 vless/socks5 同机制：粘滞决策、空闲回收；控制
//! 流 = 裸 TCP 流本体，EOF 即吊销本关联键）。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex, Once,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use rillane_core::udp::{
    DownlinkPacket, DropReason, EgressUdpConnector, UdpIngressMetrics, UdpSessionKey,
    UdpSessionTable, UpResult,
};
use rillane_core::{
    fake_ip, BoxedIo, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget,
    IngressEndpoint, TargetProto,
};

use crate::outbound::vmess::{
    append_chunk, auth_id_timestamp, cmd_key_from_uuid, fnv1a32, open_vmess_header_len_block,
    open_vmess_header_pay_block, read_chunk, seal_response_header, write_chunk, ChunkCrypt,
    RespHeaderKeys, VmessSecurity, AEAD_OVERHEAD, REQUEST_OPTION,
};

/// authID 时间窗（xray 口径 ±120s；防重放缓存按同窗修剪）
const AUTH_WINDOW_SECS: i64 = 120;

/// VMess UDP 关联面装配件：进程级会话表 + 出站连接器族（与 vless/socks5
/// ASSOCIATE 同源共享，由 RuntimeBuilder 从 UdpAssociateService 抽出传入）
#[derive(Clone)]
pub struct VmessUdpParts {
    pub table: Arc<UdpSessionTable>,
    pub connector: Arc<dyn EgressUdpConnector>,
}

/// VMess 入口服务
#[derive(Clone)]
pub struct VmessIngress {
    name: String,
    bind: String,
    /// 认证基准：cmdKey = MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    /// （与客户端 cmd_key_from_uuid 镜像互源）
    cmd_key: [u8; 16],
    /// UDP 关联面（None = udp 未启用——CMD 0x02 连接收束）
    udp: Option<VmessUdpParts>,
    /// fake-ip 池表（G1-10；None = 关闭，target 原样路由；TCP/UDP 两面共用）
    fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    /// 防重放缓存：authID → 首见时间戳（同 authID 二次命中即收束；窗口外
    /// 条目逐连接修剪，容量随窗口内连接速率有界）
    replay: Arc<StdMutex<HashMap<[u8; 16], i64>>>,
    /// 周期回收任务随 UDP 面启用拉起（与 associate 服务各自 Once——多 UDP
    /// 面并存时至多两路 sweep，幂等无害）
    reclaimer_once: Arc<Once>,
}

impl VmessIngress {
    pub fn new(
        name: String,
        bind: String,
        uuid: &str,
        udp: Option<VmessUdpParts>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<Self> {
        let id =
            Uuid::parse_str(uuid.trim()).context("vmess 入口 uuid 非法（须为标准 UUID 形）")?;
        bind.parse::<SocketAddr>()
            .with_context(|| format!("vmess 入口 bind 非法: {bind}"))?;
        Ok(Self {
            name,
            bind,
            cmd_key: cmd_key_from_uuid(id.as_bytes()),
            udp,
            fake_ip,
            replay: Arc::new(StdMutex::new(HashMap::new())),
            reclaimer_once: Arc::new(Once::new()),
        })
    }

    /// 防重放判定：窗口外条目修剪后，同 authID 二次命中即点名拒绝
    fn check_replay(&self, auth_id: [u8; 16], ts: i64) -> Result<()> {
        let now = unix_now_secs()?;
        let mut cache = self.replay.lock().expect("vmess 防重放缓存锁中毒");
        cache.retain(|_, t| now - *t <= AUTH_WINDOW_SECS);
        if cache.contains_key(&auth_id) {
            bail!("vmess authID 重放（防重放缓存命中），连接收束");
        }
        cache.insert(auth_id, ts);
        Ok(())
    }

    /// TCP 命令（0x01）：响应头先出 → duplex 明文桥接 Flow（分块密面 ↔
    /// 明文面）。上行空块 = 客户端半关闭 → 桥写侧 shutdown（flow 面见
    /// EOF，上游收束传播）；下行上游 EOF = 终止块回送客户端。
    async fn forward_tcp(
        ingress_node_name: &str,
        client_addr: SocketAddr,
        tcp: TcpStream,
        req: VmessReqHeader,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
        fake_ip: Option<Arc<fake_ip::FakeIpTable>>,
    ) -> Result<()> {
        // 响应头先于中继（客户端 forward 读响应头后才双向搬运）；resp
        // 密钥 = SHA256(reqKey/reqIV)[:16] 派生（NewClientSession 镜像）
        let keys = RespHeaderKeys::derive(&req.req_key, &req.req_iv);
        let sealed_resp = seal_response_header(&keys, req.expect_v)?;
        let (mut rr, mut ww) = tokio::io::split(tcp);
        ww.write_all(&sealed_resp).await?;
        ww.flush().await?;

        // 明文桥：flow 侧入 Flow.io（须明文），vmess 侧归本端两个泵
        let (vmess_side, flow_side) = tokio::io::duplex(64 * 1024);
        let (mut vs_r, mut vs_w) = tokio::io::split(vmess_side);

        let mut host = req.host;
        let port = req.port;
        let mut metadata = FlowMetadata {
            tags: vec![
                "ingress:vmess".into(),
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
            io: Box::new(flow_side) as BoxedIo,
            metadata,
        };

        let ctx = flow.context();
        let decision = router.route(ctx).await.context("路由计算失败")?;
        let out_task = tokio::spawn(async move { output.forward(decision, flow).await });

        // 数据面密钥参数先行抽出（Copy 字段，两泵各持一份）
        let sec = req.security;
        let req_key = req.req_key;
        let req_iv = req.req_iv;

        // 上行泵：分块密面 → 明文。退出时无条件收束桥写侧（无论正常半
        // 关闭还是密面错误），flow 面见 EOF，下游不悬。
        let up = async move {
            let mut req_crypt = ChunkCrypt::new(sec, &req_key, &req_iv)?;
            let res: Result<()> = loop {
                match read_chunk(&mut req_crypt, &mut rr).await {
                    Ok(plain) => {
                        if plain.is_empty() {
                            break Ok(()); // 终止块：客户端半关闭
                        }
                        if vs_w.write_all(&plain).await.is_err() {
                            break Ok(()); // flow 侧已收束，静默退出
                        }
                    }
                    Err(e) => break Err(e),
                }
            };
            let _ = vs_w.shutdown().await;
            res
        };

        // 下行泵：明文 → 分块密面。上游 EOF → 终止块（客户端面 read_chunk
        // 空明文即半关闭）；写侧死亡即收束（后续块无意义）。
        let down = async move {
            let mut resp_crypt = ChunkCrypt::derive_response(sec, &req_key, &req_iv)?;
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match vs_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if write_chunk(&mut resp_crypt, &mut ww, &buf[..n])
                    .await
                    .is_err()
                {
                    break; // 客户端写侧死亡：关联收束
                }
            }
            let _ = write_chunk(&mut resp_crypt, &mut ww, &[]).await;
            Ok::<(), anyhow::Error>(())
        };

        let (up_res, down_res) = tokio::join!(up, down);
        out_task
            .await
            .context("出口任务中止")?
            .context("出口转发失败")?;
        up_res?;
        down_res?;
        Ok(())
    }

    /// UDP 关联（CMD 0x02）：响应头（AEAD 双块）写出后进分块帧循环。单
    /// 连接单目标——请求目标即本关联唯一目标，双向逐数据报一块（无终止
    /// 块语义）。控制流 = 裸 TCP 流本体，EOF 即吊销本关联键（socks5 §2.5
    /// 同语义）。
    async fn serve_association(
        &self,
        tcp: TcpStream,
        peer: SocketAddr,
        req: VmessReqHeader,
    ) -> Result<()> {
        let Some(parts) = self.udp.as_ref() else {
            bail!("vmess UDP 关联面未启用（udp 门关闭），连接收束");
        };
        // fake-ip 回填（G1-10 UDP 面）：请求目标为池段假 IPv4 时反查原域名
        let mut host = req.host.clone();
        if let Some(t) = self.fake_ip.as_ref() {
            if let Some(domain) = fake_ip::reverse_host(t, &host) {
                host = domain;
            }
        }
        let target = FlowTarget {
            host,
            port: req.port,
            proto: TargetProto::Udp,
        };

        // 响应头先于帧循环（客户端 associate 于 UDP 路径亦先读响应头再进
        // 块解析）；密钥面与 TCP 同源（reqKey/reqIV 派生）
        let keys = RespHeaderKeys::derive(&req.req_key, &req.req_iv);
        let sealed_resp = seal_response_header(&keys, req.expect_v)?;
        let (mut rr, mut ww) = tokio::io::split(tcp);
        ww.write_all(&sealed_resp).await?;
        ww.flush().await?;
        let writer = Arc::new(tokio::sync::Mutex::new(ww));
        let metrics = Arc::new(UdpIngressMetrics::default());
        let key = UdpSessionKey::new(peer);

        let uplink = uplink_loop(parts, &mut rr, &writer, peer, &target, &metrics, req).await;

        // 控制流终止 → 吊销本关联键（关下行 → 摘映射 → 计数在表侧）
        let revoked = parts.table.force_revoke(&key);
        tracing::debug!(
            target: "rillane::vmess_udp",
            client = %peer,
            revoked,
            "vmess UDP 关联收束"
        );
        uplink
    }

    async fn handle_conn(
        self: Arc<Self>,
        mut tcp: TcpStream,
        peer: SocketAddr,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let _ = tcp.set_nodelay(true);

        // 封头第一段：authID(16) ‖ 长度块 AEAD(18) ‖ connNonce(8) = 42B
        let mut head = [0u8; 42];
        tcp.read_exact(&mut head).await.context("vmess 封头读取")?;
        let (pay_len, auth_id, conn_nonce) = open_vmess_header_len_block(&self.cmd_key, &head)
            .context("vmess 封头长度块开面失败（凭据不匹配或线形非法）")?;

        // authID 三重门：CRC 快筛（非本凭据派生即拒）→ ±120s 窗 → 防重放
        let ts = auth_id_timestamp(&self.cmd_key, &auth_id).context("vmess authID 快筛失败")?;
        let now = unix_now_secs()?;
        if (now - ts).abs() > AUTH_WINDOW_SECS {
            bail!(
                "vmess authID 时间戳越窗（±{}s），连接收束",
                AUTH_WINDOW_SECS
            );
        }
        self.check_replay(auth_id, ts)?;

        // 封头第二段：头块 AEAD（密文 ‖ tag）
        let mut pay_sealed = vec![0u8; pay_len + AEAD_OVERHEAD];
        tcp.read_exact(&mut pay_sealed)
            .await
            .context("vmess 封头头块读取")?;
        let plain = open_vmess_header_pay_block(&self.cmd_key, &auth_id, &conn_nonce, &pay_sealed)
            .context("vmess 封头头块开面失败（凭据不匹配）")?;
        let req = parse_request_header(&plain)?;

        match req.command {
            0x01 => {
                Self::forward_tcp(
                    self.name.as_str(),
                    peer,
                    tcp,
                    req,
                    router,
                    output,
                    self.fake_ip.clone(),
                )
                .await
            }
            0x02 => self.serve_association(tcp, peer, req).await,
            other => bail!("vmess 未知命令: {other}"),
        }
    }
}

/// 解析后的明文请求头（parse_request_header 产出；数据面密钥/IV/V 由
/// TCP/UDP 两路共用）
#[derive(Clone, Debug)]
struct VmessReqHeader {
    req_iv: [u8; 16],
    req_key: [u8; 16],
    /// 响应认证字节（客户端 shuffle 字节，响应头须原样回声）
    expect_v: u8,
    security: VmessSecurity,
    host: String,
    port: u16,
    /// 已过三重门后的命令（0x01 TCP / 0x02 UDP）
    command: u8,
}

/// 明文请求头解析（严格形）：40B 固定段 + ATYP 地址段 + padding + FNV1a32。
/// 任一越界/不支持组合点名拒绝（RIL-137 验收：不支持组合明确拒绝）。
fn parse_request_header(plain: &[u8]) -> Result<VmessReqHeader> {
    // 最小形：40B 固定头 + ATYP(1) + v4 地址(4) + FNV(4)（padding 可为 0）
    if plain.len() < 49 {
        bail!("vmess 请求头过短: {} 字节", plain.len());
    }
    if plain[0] != 0x01 {
        bail!(
            "vmess 协议版本不支持（仅 0x01，legacy 面未交付）: {}",
            plain[0]
        );
    }
    let n = plain.len();
    let checksum = u32::from_be_bytes([plain[n - 4], plain[n - 3], plain[n - 2], plain[n - 1]]);
    if fnv1a32(&plain[..n - 4]) != checksum {
        bail!("vmess 请求头 FNV1a32 校验不过");
    }
    let option = plain[34];
    if option != REQUEST_OPTION {
        bail!(
            "vmess 入站仅交付 AEAD 分块面 option=0x0D（ChunkStream|ChunkMasking|\
             GlobalPadding），实际 0x{option:02X}"
        );
    }
    // sec 字节：低 4bit security，高 4bit padding 长度
    let security = VmessSecurity::from_header_byte(plain[35] & 0x0F)?;
    let pad_len = (plain[35] >> 4) as usize;
    let command = plain[37];
    if command != 0x01 && command != 0x02 {
        bail!("vmess 命令不支持（0x01 TCP / 0x02 UDP）: {command}");
    }
    let port = u16::from_be_bytes([plain[38], plain[39]]);
    let body_end = n - 4; // FNV 尾段之前

    let mut off = 40;
    let host = match plain[off] {
        0x01 => {
            off += 1;
            if off + 4 > body_end {
                bail!("vmess 请求头地址段越界");
            }
            let host = std::net::Ipv4Addr::from([
                plain[off],
                plain[off + 1],
                plain[off + 2],
                plain[off + 3],
            ])
            .to_string();
            off += 4;
            host
        }
        0x02 => {
            let l = *plain
                .get(off + 1)
                .ok_or_else(|| anyhow!("vmess 请求头地址段越界"))? as usize;
            off += 2;
            if off + l > body_end {
                bail!("vmess 请求头地址段越界");
            }
            let host = String::from_utf8_lossy(&plain[off..off + l]).into_owned();
            off += l;
            host
        }
        0x03 => {
            off += 1;
            if off + 16 > body_end {
                bail!("vmess 请求头地址段越界");
            }
            let seg: [u8; 16] = plain[off..off + 16].try_into().expect("v6 段");
            let host = std::net::Ipv6Addr::from(seg).to_string();
            off += 16;
            host
        }
        other => bail!("vmess 请求地址类型未知: {other}"),
    };
    if off + pad_len != body_end {
        bail!(
            "vmess 请求头 padding 段长度不符（声明 {pad_len}，实余 {}）",
            body_end - off
        );
    }

    Ok(VmessReqHeader {
        req_iv: plain[1..17].try_into().expect("reqIV 段"),
        req_key: plain[17..33].try_into().expect("reqKey 段"),
        expect_v: plain[33],
        security,
        host,
        port,
        command,
    })
}

fn unix_now_secs() -> Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

/// anyhow 链上找 io UnexpectedEof（read_exact 的帧边界收束口径）
fn is_eof(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::UnexpectedEof {
                return true;
            }
        }
    }
    false
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[async_trait]
impl IngressEndpoint for VmessIngress {
    fn name(&self) -> &'static str {
        "vmess"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // 会话回收任务随 UDP 面启用即拉起（纯 VMess 入口无 ASSOCIATE，
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
            target: "rillane::vmess",
            bind = %self.bind,
            "VMess 入口启动"
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
                        target: "rillane::vmess",
                        client = %peer,
                        error = %err,
                        "VMess 连接处理失败"
                    );
                }
            });
        }
        Ok(())
    }
}

/// 上行循环：逐数据报一块（分块密面 → 明文）→ 会话表快/慢路径（与 vless
/// uplink 同构；目标恒为关联时绑定的单目标）。控制流 EOF 即帧边界收束。
async fn uplink_loop(
    parts: &VmessUdpParts,
    rr: &mut tokio::io::ReadHalf<TcpStream>,
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TcpStream>>>,
    peer: SocketAddr,
    target: &FlowTarget,
    metrics: &Arc<UdpIngressMetrics>,
    req: VmessReqHeader,
) -> Result<()> {
    let key = UdpSessionKey::new(peer);
    let mut req_crypt = ChunkCrypt::new(req.security, &req.req_key, &req.req_iv)?;
    loop {
        let plain = match read_chunk(&mut req_crypt, rr).await {
            Ok(p) => p,
            Err(e) if is_eof(&e) => return Ok(()), // 干净 EOF：帧边界收束
            Err(e) => return Err(e),
        };
        if plain.is_empty() {
            continue; // UDP 面无终止块语义：空块容忍跳过
        }
        bump(&metrics.uplink_packets);
        let data = Bytes::copy_from_slice(&plain);

        // 快路径：命中映射直接发
        match parts.table.forward_up(&key, target, data.clone()).await {
            UpResult::Sent => continue,
            UpResult::Dropped {
                reason: DropReason::ShuttingDown,
            } => bail!("会话表收束，vmess UDP 关联终止"),
            _ => {}
        }
        // 慢路径：resolve（容量/路由门）→ associate → bind → 下行任务 → 发送
        if let Err(e) = slow_path(
            parts,
            writer,
            metrics,
            &key,
            target,
            peer,
            data,
            req.clone(),
        )
        .await
        {
            bump(&metrics.associate_errors);
            tracing::debug!(
                target: "rillane::vmess_udp",
                client = %peer,
                target = %target.host,
                error = %e,
                "UDP 慢路径失败，数据报丢弃"
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn slow_path(
    parts: &VmessUdpParts,
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TcpStream>>>,
    metrics: &Arc<UdpIngressMetrics>,
    key: &UdpSessionKey,
    target: &FlowTarget,
    peer: SocketAddr,
    data: Bytes,
    req: VmessReqHeader,
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
        // 按会话摘下行通道 → vmess 块沿裸 TCP 流回送客户端
        if let Some(rx) = sref.take_downlink_rx().await {
            let writer = Arc::clone(writer);
            let metrics = Arc::clone(metrics);
            tokio::spawn(downlink_loop(writer, rx, peer, metrics, req));
        }
    }
    match sref.send_up(target, data).await {
        UpResult::Sent => Ok(()),
        // Miss：映射刚被策略吊销——本包丢弃，下一包重新关联
        UpResult::Miss => Ok(()),
        UpResult::Dropped { .. } => Ok(()), // 已在表侧计数，UDP 静默丢弃语义
    }
}

/// 下行任务：会话下行通道 → 逐数据报一块（append_chunk 拼帧）沿裸 TCP 流
/// 回送客户端（单目标关联：块不携地址段，客户端按关联时目标对齐；UDP 面
/// 无终止块语义，通道收束即流收束）
async fn downlink_loop(
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TcpStream>>>,
    mut rx: tokio::sync::mpsc::Receiver<DownlinkPacket>,
    client: SocketAddr,
    metrics: Arc<UdpIngressMetrics>,
    req: VmessReqHeader,
) {
    // resp 密钥面沿连接续用（counter/SHAKE 状态逐块推进，与客户端读侧
    // derive_response 镜像互源）
    let mut resp_crypt = match ChunkCrypt::derive_response(req.security, &req.req_key, &req.req_iv)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                target: "rillane::vmess_udp",
                client = %client,
                error = %e,
                "响应密钥面构造失败，下行收束"
            );
            return;
        }
    };
    while let Some(pkt) = rx.recv().await {
        let mut frame = Vec::with_capacity(pkt.data.len() + 2 + 64);
        let outcome = match append_chunk(&mut resp_crypt, &pkt.data, &mut frame) {
            Err(e) => Err(e),
            Ok(_) => {
                let mut w = writer.lock().await;
                async {
                    w.write_all(&frame).await?;
                    w.flush().await?;
                    Ok::<(), anyhow::Error>(())
                }
                .await
            }
        };
        match outcome {
            Ok(_) => bump(&metrics.downlink_packets),
            Err(e) => {
                tracing::debug!(
                    target: "rillane::vmess_udp",
                    client = %client,
                    error = %e,
                    "下行发送失败"
                );
                break; // 写侧死亡：关联收束，后续帧无意义
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::outbound::vmess::build_request_header_bytes;

    /// UUID/bind 装配期校验：非法形点名拒绝；合法形入基
    #[test]
    fn uuid_and_bind_validated_at_assembly() {
        let Err(err) =
            VmessIngress::new("t".into(), "127.0.0.1:0".into(), "not-a-uuid", None, None)
        else {
            panic!("非法 uuid 必须拒绝");
        };
        assert!(err.to_string().contains("uuid"), "{err}");

        let Err(err) = VmessIngress::new(
            "t".into(),
            "bad-bind".into(),
            "b831381d-6324-4d2a-b1e7-1bf75a1db7b3",
            None,
            None,
        ) else {
            panic!("非法 bind 必须拒绝");
        };
        assert!(err.to_string().contains("bind"), "{err}");

        let ing = VmessIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "b831381d-6324-4d2a-b1e7-1bf75a1db7b3",
            None,
            None,
        )
        .expect("合法装配");
        // cmdKey 与客户端 cmd_key_from_uuid 镜像互源（同 uuid 同键）
        let id = Uuid::parse_str("b831381d-6324-4d2a-b1e7-1bf75a1db7b3").expect("样本 uuid");
        assert_eq!(ing.cmd_key, cmd_key_from_uuid(id.as_bytes()));
    }

    /// 防重放缓存：同 authID 窗内二次命中即拒；窗口外条目修剪后放行
    #[test]
    fn replay_cache_refuses_duplicates_and_prunes_window() {
        let ing = VmessIngress::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "b831381d-6324-4d2a-b1e7-1bf75a1db7b3",
            None,
            None,
        )
        .expect("装配");
        let now = unix_now_secs().expect("时钟");
        let a = [7u8; 16];
        let b = [9u8; 16];

        ing.check_replay(a, now).expect("首见放行");
        let err = ing.check_replay(a, now).expect_err("重放必须拒绝");
        assert!(err.to_string().contains("重放"), "{err}");

        // 另一 authID 同窗放行
        ing.check_replay(b, now).expect("不同 authID 放行");

        // 窗口外条目修剪：以旧时间戳入基的 a 在下次修剪时清出，再入放行
        let old = now - AUTH_WINDOW_SECS - 1;
        let c = [11u8; 16];
        ing.check_replay(c, old)
            .expect("旧戳入基（窗校验在 handle_conn 层）");
        ing.check_replay(c, now).expect("窗外面目已修剪，放行");
    }

    /// FNV 重算（测试造变形头用：改字节后校验和须同步重算才可越过 FNV 门）
    fn fix_fnv(plain: &mut [u8]) {
        let n = plain.len();
        let c = fnv1a32(&plain[..n - 4]);
        plain[n - 4..].copy_from_slice(&c.to_be_bytes());
    }

    /// 请求头解码三形态（v4/域名/v6）+ 字段回读（与客户端
    /// build_request_header_bytes 编码镜像互源）
    #[test]
    fn request_header_decode_three_addr_forms() {
        let req_iv = *b"0011223344556677";
        let req_key = *b"8899aabbccddeeff";

        // v4
        let plain = build_request_header_bytes(
            &req_iv,
            &req_key,
            0x5A,
            b"",
            VmessSecurity::Aes128Gcm,
            "203.0.113.9",
            8080,
            0x01,
        )
        .expect("编码");
        let req = parse_request_header(&plain).expect("v4 解码");
        assert_eq!(req.host, "203.0.113.9");
        assert_eq!(req.port, 8080);
        assert_eq!(req.expect_v, 0x5A);
        assert_eq!(req.security, VmessSecurity::Aes128Gcm);
        assert_eq!(req.command, 0x01);
        assert_eq!(req.req_iv, req_iv);
        assert_eq!(req.req_key, req_key);

        // 域名 + padding + ChaCha
        let plain = build_request_header_bytes(
            &req_iv,
            &req_key,
            0x11,
            b"\x01\x02\x03",
            VmessSecurity::Chacha20Poly1305,
            "echo.test",
            53,
            0x02,
        )
        .expect("编码");
        let req = parse_request_header(&plain).expect("域名解码");
        assert_eq!(req.host, "echo.test");
        assert_eq!(req.port, 53);
        assert_eq!(req.expect_v, 0x11);
        assert_eq!(req.security, VmessSecurity::Chacha20Poly1305);
        assert_eq!(req.command, 0x02);

        // v6
        let plain = build_request_header_bytes(
            &req_iv,
            &req_key,
            0x00,
            b"",
            VmessSecurity::Aes128Gcm,
            "2001:db8::9",
            443,
            0x01,
        )
        .expect("编码");
        let req = parse_request_header(&plain).expect("v6 解码");
        assert_eq!(req.host, "2001:db8::9");
        assert_eq!(req.port, 443);
    }

    /// 不支持组合点名拒绝：版本/FNV/option/security/命令/ATYP/越界/padding
    #[test]
    fn request_header_named_refusals() {
        let req_iv = *b"0011223344556677";
        let req_key = *b"8899aabbccddeeff";
        let base = |security| {
            build_request_header_bytes(
                &req_iv,
                &req_key,
                0x01,
                b"",
                security,
                "echo.test",
                443,
                0x01,
            )
            .expect("编码")
        };

        // 过短
        let err = parse_request_header(&[0u8; 10]).expect_err("过短必须拒绝");
        assert!(err.to_string().contains("过短"), "{err}");

        // 版本
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain[0] = 0x02;
        let err = parse_request_header(&plain).expect_err("版本必须拒绝");
        assert!(err.to_string().contains("版本"), "{err}");

        // FNV（改载荷不重算校验和）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        let n = plain.len();
        plain[10] ^= 0xFF;
        let err = parse_request_header(&plain).expect_err("FNV 必须拒绝");
        assert!(err.to_string().contains("FNV1a32"), "{err}");
        let _ = n;

        // option（非 0x0D，重算 FNV 越过 FNV 门）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain[34] = 0x05;
        fix_fnv(&mut plain);
        let err = parse_request_header(&plain).expect_err("option 必须拒绝");
        assert!(err.to_string().contains("0x0D"), "{err}");

        // security（legacy 0x02，重算 FNV）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain[35] = (plain[35] & 0xF0) | 0x02;
        fix_fnv(&mut plain);
        let err = parse_request_header(&plain).expect_err("security 必须拒绝");
        assert!(err.to_string().contains("security"), "{err}");

        // 命令（0x03，重算 FNV）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain[37] = 0x03;
        fix_fnv(&mut plain);
        let err = parse_request_header(&plain).expect_err("命令必须拒绝");
        assert!(err.to_string().contains("命令"), "{err}");

        // ATYP 未知（重算 FNV）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain[40] = 0x09;
        fix_fnv(&mut plain);
        let err = parse_request_header(&plain).expect_err("ATYP 必须拒绝");
        assert!(err.to_string().contains("地址类型未知"), "{err}");

        // 地址段越界（域名长度声明越尾，重算 FNV）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain[41] = 0x7F;
        fix_fnv(&mut plain);
        let err = parse_request_header(&plain).expect_err("越界必须拒绝");
        assert!(err.to_string().contains("越界"), "{err}");

        // padding 段长度不符（追加脏字节后重算 FNV）
        let mut plain = base(VmessSecurity::Aes128Gcm);
        plain.insert(plain.len() - 4, 0xAA);
        fix_fnv(&mut plain);
        let err = parse_request_header(&plain).expect_err("padding 必须拒绝");
        assert!(err.to_string().contains("padding"), "{err}");
    }
}
