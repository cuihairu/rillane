//! SOCKS5 出口连接器实现（TCP 隧道经 tokio-socks；UDP ASSOCIATE 自写——
//! tokio-socks 0.5.2 无 UDP 面，选库结论见 protocol-backends.md#socks5）

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_socks::tcp::Socks5Stream;

/// SOCKS5 代理出口连接器
pub struct Socks5Connector {
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Connector {
    pub fn new(
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            server,
            port,
            username,
            password,
        }
    }

    fn proxy_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

#[async_trait]
impl EgressConnector for Socks5Connector {
    fn name(&self) -> &'static str {
        "socks5"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let proxy_addr = self.proxy_addr();

        tracing::debug!(
            target: "rillane::socks5_out",
            id = %flow.id.as_uuid(),
            %target,
            proxy = %proxy_addr,
            "通过 SOCKS5 代理连接"
        );

        // 建立 SOCKS5 连接
        let mut outbound = if let (Some(user), Some(pass)) =
            (self.username.as_ref(), self.password.as_ref())
        {
            Socks5Stream::connect_with_password(proxy_addr.as_str(), target.as_str(), user, pass)
                .await
                .with_context(|| format!("SOCKS5 代理连接失败: {}", proxy_addr))?
        } else {
            Socks5Stream::connect(proxy_addr.as_str(), target.as_str())
                .await
                .with_context(|| format!("SOCKS5 代理连接失败: {}", proxy_addr))?
        };

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut outbound,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

// ---------------------------------------------------------------------------
// 出站 UDP ASSOCIATE（RIL-132，RFC 1928 §6/§7）
// ---------------------------------------------------------------------------

/// SOCKS5 UDP 出站连接器：TCP 控制信道上完成方法协商与 UDP ASSOCIATE，
/// 数据报按 RFC 1928 §7 帧头（RSV/FRAG/ATYP/ADDR/PORT）收发。
/// tokio-socks 只覆盖 TCP 面——UDP 面按选库结论自写（评估记录
/// protocol-backends.md#socks5：0.5.2 源码无 udp 模块）。
pub struct Socks5UdpConnector {
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5UdpConnector {
    /// 从已构建的 TCP 连接器复用同一节点配置（地址/凭据两侧一致）
    pub fn from_connector(conn: &Socks5Connector) -> Self {
        Self {
            server: conn.server.clone(),
            port: conn.port,
            username: conn.username.clone(),
            password: conn.password.clone(),
        }
    }

    fn proxy_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// TCP 控制信道：方法协商（RFC 1928 §3）+ UDP ASSOCIATE（§6）。
    /// 返回控制流与对端中继端点（BND.ADDR/BND.PORT；BND 不指定时取控制
    /// 信道落地地址——RFC 1928 §7「以客户端连代理所用地址为准」，RIL-154
    /// 同面收口：不再解析服务器地址取首址）。
    async fn associate_control(&self) -> Result<(TcpStream, SocketAddr)> {
        let proxy_addr = self.proxy_addr();
        let mut control = TcpStream::connect(&proxy_addr)
            .await
            .with_context(|| format!("SOCKS5 UDP 控制连接失败（server={proxy_addr}）"))?;

        // 方法协商：有凭据选 0x02（RFC 1929 用户/密码），否则 0x00
        let want_auth = self.username.is_some() && self.password.is_some();
        let method = if want_auth { 0x02u8 } else { 0x00u8 };
        control
            .write_all(&[0x05, 0x01, method])
            .await
            .context("SOCKS5 方法协商写入失败")?;
        let mut method_reply = [0u8; 2];
        control
            .read_exact(&mut method_reply)
            .await
            .context("SOCKS5 方法协商应答缺失")?;
        if method_reply[1] != method {
            return Err(anyhow!(
                "SOCKS5 代理未接受选择的方法（请求 {method:#04x}，应答 {:#04x}）",
                method_reply[1]
            ));
        }
        if want_auth {
            let (user, pass) = (
                self.username.as_ref().unwrap(),
                self.password.as_ref().unwrap(),
            );
            let mut req = Vec::with_capacity(3 + user.len() + pass.len());
            req.push(0x01);
            req.push(user.len() as u8);
            req.extend_from_slice(user.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            control.write_all(&req).await.context("认证写入失败")?;
            let mut auth_reply = [0u8; 2];
            control
                .read_exact(&mut auth_reply)
                .await
                .context("认证应答缺失")?;
            if auth_reply[1] != 0x00 {
                return Err(anyhow!("SOCKS5 认证被拒（status {:#04x}）", auth_reply[1]));
            }
        }

        // UDP ASSOCIATE：CMD=3，DST.ADDR=0.0.0.0:0（客户端后续以数据报出现）
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .context("UDP ASSOCIATE 请求写入失败")?;
        let mut head = [0u8; 4];
        control
            .read_exact(&mut head)
            .await
            .context("UDP ASSOCIATE 应答缺失")?;
        if head[0] != 0x05 {
            return Err(anyhow!("SOCKS5 应答版本异常（{:#04x}）", head[0]));
        }
        if head[1] != 0x00 {
            return Err(anyhow!(
                "UDP ASSOCIATE 被拒（REP {:#04x}，节点 {}）",
                head[1],
                proxy_addr
            ));
        }
        let (bnd, bnd_port) = read_reply_endpoint(&mut control, head[3]).await?;
        // RFC 1928 §7 中继地址（RIL-154 同面收口，不再解析取首址）：
        // BND 未指定（0.0.0.0/::）→ 以控制信道实际落地地址为准——该地址族
        // 在本机→代理路径上已被 TCP 建连证实可达；BND 为域名 → 解析全部
        // 地址并按控制信道地址族优先选取（无同族落回首址），解析失败显式
        // 报错带主机名。
        let control_peer = control.peer_addr().context("控制信道对端地址缺失")?;
        let relay_ip = match bnd {
            EndpointAddr::Ip(ip) if ip.is_unspecified() => control_peer.ip(),
            EndpointAddr::Ip(ip) => ip,
            EndpointAddr::Domain(host) => resolve_relay_ip(&host, control_peer.ip()).await?,
        };
        Ok((control, SocketAddr::new(relay_ip, bnd_port)))
    }
}

/// 应答/帧头中的地址形态
enum EndpointAddr {
    Ip(std::net::IpAddr),
    Domain(String),
}

/// 读 ASSOCIATE 应答的 BND.ADDR/BND.PORT（ATYP 已随应答头读入，1/3/4）
async fn read_reply_endpoint(control: &mut TcpStream, atyp: u8) -> Result<(EndpointAddr, u16)> {
    let addr = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            control
                .read_exact(&mut b)
                .await
                .context("BND.ADDR(IPv4) 缺失")?;
            EndpointAddr::Ip(std::net::IpAddr::V4(b.into()))
        }
        0x03 => {
            let mut len = [0u8; 1];
            control.read_exact(&mut len).await.context("BND.LEN 缺失")?;
            let mut b = vec![0u8; len[0] as usize];
            control
                .read_exact(&mut b)
                .await
                .context("BND.ADDR(域名) 缺失")?;
            EndpointAddr::Domain(String::from_utf8_lossy(&b).into_owned())
        }
        0x04 => {
            let mut b = [0u8; 16];
            control
                .read_exact(&mut b)
                .await
                .context("BND.ADDR(IPv6) 缺失")?;
            EndpointAddr::Ip(std::net::IpAddr::V6(b.into()))
        }
        other => return Err(anyhow!("SOCKS5 应答地址类型不支持（{other:#04x}）")),
    };
    let mut port = [0u8; 2];
    control
        .read_exact(&mut port)
        .await
        .context("BND.PORT 缺失")?;
    Ok((addr, u16::from_be_bytes(port)))
}

/// 解析域名型 BND.ADDR 为中继 IP（RIL-154 同面收口）：解析结果按序扫描，
/// 优先取与控制信道落地地址同族的地址（该族可达性已被 TCP 建连证实），
/// 无同族落回首址；字面 IP 直接透传。解析失败显式报错带主机名。
async fn resolve_relay_ip(host: &str, prefer: std::net::IpAddr) -> Result<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    let mut first = None;
    let mut same_family = None;
    for addr in tokio::net::lookup_host((host, 0u16))
        .await
        .with_context(|| format!("代理中继地址解析失败（{host}）"))?
    {
        let ip = addr.ip();
        if first.is_none() {
            first = Some(ip);
        }
        if same_family.is_none() && ip.is_ipv4() == prefer.is_ipv4() {
            same_family = Some(ip);
            break; // 同族命中即取——族优先语义不要求扫全部
        }
    }
    same_family
        .or(first)
        .ok_or_else(|| anyhow!("代理中继地址解析为空（{host}）"))
}

/// RFC 1928 §7 数据报帧头（RSV2 FRAG1 ATYP1 ADDR.. PORT2）
fn datagram_header(target: &FlowTarget) -> Result<Vec<u8>> {
    let mut head = vec![0x00, 0x00, 0x00]; // RSV、FRAG=0（不重组分片）
    match target.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            head.push(0x01);
            head.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            head.push(0x04);
            head.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let bytes = target.host.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(anyhow!("目标域名超长（{} 字节）", bytes.len()));
            }
            head.push(0x03);
            head.push(bytes.len() as u8);
            head.extend_from_slice(bytes);
        }
    }
    head.extend_from_slice(&target.port.to_be_bytes());
    Ok(head)
}

/// 逐条解析帧头，返回 (目标, 载荷起点)
fn parse_datagram(buf: &[u8]) -> Result<(FlowTarget, usize)> {
    if buf.len() < 4 {
        return Err(anyhow!("SOCKS5 数据报过短（{} 字节）", buf.len()));
    }
    let mut pos = 3usize;
    let host = match buf[pos] {
        0x01 => {
            if buf.len() < pos + 5 {
                return Err(anyhow!("IPv4 目标不完整"));
            }
            let host = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
                buf[pos + 4],
            ));
            pos += 5;
            host.to_string()
        }
        0x03 => {
            let len = buf[pos + 1] as usize;
            if buf.len() < pos + 2 + len {
                return Err(anyhow!("域名目标不完整"));
            }
            let host = String::from_utf8_lossy(&buf[pos + 2..pos + 2 + len]).into_owned();
            pos += 2 + len;
            host
        }
        0x04 => {
            if buf.len() < pos + 17 {
                return Err(anyhow!("IPv6 目标不完整"));
            }
            let octets: [u8; 16] = buf[pos + 1..pos + 17].try_into().expect("16 字节切片");
            pos += 17;
            std::net::IpAddr::V6(octets.into()).to_string()
        }
        other => return Err(anyhow!("SOCKS5 数据报地址类型不支持（{other:#04x}）")),
    };
    if buf.len() < pos + 2 {
        return Err(anyhow!("数据报端口缺失"));
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Ok((
        FlowTarget {
            host,
            port,
            proto: TargetProto::Udp,
        },
        pos,
    ))
}

#[async_trait]
impl EgressUdpConnector for Socks5UdpConnector {
    fn name(&self) -> &str {
        "socks5"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        let (control, relay_addr) = self.associate_control().await?;
        // 本地数据报 socket：出站 UDP 的源端（对端按来源校验中继端点）
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("SOCKS5 UDP 本地 socket 绑定失败")?;
        Ok(Arc::new(Socks5UdpRelay {
            control,
            udp,
            relay_addr,
            fixed_target: ctx.target,
            foreign_dropped: AtomicU64::new(0),
            frag_dropped: AtomicU64::new(0),
        }))
    }
}

/// 字节级 SOCKS5 UDP relay：持有 ASSOCIATE 控制流（生命周期绑定）+
/// 数据报 socket；上行按 RFC 1928 §7 组帧发往中继端点，下行逐条解析。
struct Socks5UdpRelay {
    /// ASSOCIATE 控制流——TCP 连接关闭即中继失效（RFC 1928 §7），随 relay
    /// 生命周期持有，drop 即释放
    #[allow(dead_code)] // 仅持句柄：连接保持本身即是中继有效性
    control: TcpStream,
    udp: UdpSocket,
    /// 对端中继端点（BND.ADDR/BND.PORT）——来源校验基准
    relay_addr: SocketAddr,
    /// §3.3 R7 同口径：关联时固定的会话目标
    fixed_target: FlowTarget,
    /// 来源校验丢弃计数（非中继端点来源的数据报不下传）
    foreign_dropped: AtomicU64,
    /// 分片丢弃计数（FRAG≠0 不支持重组，不下传）
    frag_dropped: AtomicU64,
}

#[async_trait]
impl UdpRelay for Socks5UdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        // 上行目标以会话固定目标为准（与 SS relay 同口径——粘滞语义下
        // 目标编码进帧头，中继转发到该目标）
        let dest = if target.host == self.fixed_target.host && target.port == self.fixed_target.port
        {
            target
        } else {
            &self.fixed_target
        };
        let mut frame = datagram_header(dest)?;
        frame.extend_from_slice(buf);
        self.udp
            .send_to(&frame, self.relay_addr)
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("SOCKS5 UDP 发送失败: {e}"))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        loop {
            let (n, source) = self
                .udp
                .recv_from(buf)
                .await
                .map_err(|e| anyhow!("SOCKS5 UDP 接收失败: {e}"))?;
            // 来源验证（RIL-132）：只接受中继端点的数据报，其余丢弃并计数
            // ——不把陌生来源当作上游载荷（与入口 strict_udp_source 同口径，
            // 这是出站侧的对应面）
            if source != self.relay_addr {
                let dropped = self.foreign_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(
                    target: "rillane::socks5_out_udp",
                    dropped,
                    %source,
                    relay = %self.relay_addr,
                    "丢弃非中继端点来源的数据报"
                );
                continue;
            }
            // 分片先于解析丢弃（FRAG≠0 不重组；分片头不必完整，先查 FRAG
            // 再解析，避免把分片当畸形报文误报会话错误）
            if buf[2] != 0x00 {
                let dropped = self.frag_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    target: "rillane::socks5_out_udp",
                    dropped,
                    frag = buf[2],
                    "丢弃分片数据报（FRAG≠0 不支持重组）"
                );
                continue;
            }
            let (target, payload_at) = parse_datagram(&buf[..n])?;
            let payload_len = n - payload_at;
            // 载荷已在 buf 内但前移到缓冲头部（调用方契约：返回 (目标, 载荷长)）
            buf.copy_within(payload_at..n, 0);
            return Ok((target, payload_len));
        }
    }
}
