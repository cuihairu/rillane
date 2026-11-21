//! OpenConnect / Cisco AnyConnect (CSTP) 出口连接器实现（RIL-121）。
//!
//! 三层 VPN 客户端面（WireGuard 族，非面向地址的代理）。载具 rustls TLS
//! + HTTP/1.1 控制通道（表单认证 POST /auth → CONNECT /CSCOSSLC/tunnel），
//! 数据面 = CSTP 帧流（每帧一个原始 IP 包）。评估与验收对端留证
//! protocol-backends.md#openconnect（真实对端 = apt ocserv 1.3.0，本地
//! /home/cui/ocpeer 服务，127.0.0.1:4433；线格式对照 OpenConnect 源码
//! cstp.c/auth.c/openconnect-internal.h 核读）。
//!
//! 线格式钉定（OpenConnect 源码为真源）：
//! - CSTP 帧头：8 字节 `S T F 0x01` + `payload_len`（大端 u16）+
//!   `packet_type`（u8）+ `0x00`。接收侧拒绝任何不匹配魔术/版本的头及
//!   任何非零第 7 字节。包类型：`DATA=0`（未压缩 IP 包）、`DPD_OUT=3`、
//!   `DPD_RESP=4`、`DISCONN=5`、`KEEPALIVE=7`、`COMPRESSED=8`（本面不收）、
//!   `TERM_SERVER=9`（服务器关隧道）。
//! - 控制通道：`POST /auth`（表单，`Connection: close`——每个认证 POST 用
//!   独立连接，keep-alive POST 会得到空响应）→ 用户名字步获
//!   `Set-Cookie: webvpncontext=<token>`；密码步携 `Cookie: webvpncontext`
//!   → `type="complete"` + `Set-Cookie: webvpn=<token>`；随后
//!   `CONNECT /CSCOSSLC/tunnel` + `Cookie: webvpn=<token>` + X-CSTP-* 头
//!   → `200 CONNECTED` + X-CSTP-Address/Netmask/DNS/MTU。GET / 会先返回
//!   空过期 webvpncontext cookie 破坏认证——绝不先 GET。
//! - 数据面：TLS 连接上持续 CSTP 帧流；本模块是会话建立 + 帧编解码，
//!   三层桥（用户态 smoltcp）与驱动循环在 openconnect_stack 段（同文件
//!   后续增量，见 OpenConnectConnector）。

use anyhow::{anyhow, bail, Context, Result};
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::fingerprint::TlsFingerprint;
use crate::tls::create_tls_connector_with_profile;

/// 会话建立（TLS 握手 + webvpn 认证 + CONNECT）超时上限
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// CSTP 帧头长度（魔术 4 + 长度 2 + 类型 1 + 保留 1）
const CSTP_HEADER_LEN: usize = 8;
/// 单帧载荷上限（IP 包；MTU 由对端 X-CSTP-MTU 给出，缺省 1400）
const CSTP_MAX_PAYLOAD: usize = 65535 - CSTP_HEADER_LEN;

/// 包类型（openconnect-internal.h `AC_PKT_*`）
pub(crate) const PKT_DATA: u8 = 0;
pub(crate) const PKT_DPD_OUT: u8 = 3;
pub(crate) const PKT_DPD_RESP: u8 = 4;
pub(crate) const PKT_DISCONN: u8 = 5;
pub(crate) const PKT_KEEPALIVE: u8 = 7;
pub(crate) const PKT_TERM_SERVER: u8 = 9;

/// 单帧（类型 + 载荷）。数据面载荷 = 原始 IP 包。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CstpFrame {
    pub(crate) pkt_type: u8,
    pub(crate) payload: Vec<u8>,
}

/// 编一帧为线字节（头 + 载荷）。
pub(crate) fn encode_frame(pkt_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > CSTP_MAX_PAYLOAD {
        bail!(
            "CSTP 帧载荷超限：{} 字节 > {CSTP_MAX_PAYLOAD}",
            payload.len()
        );
    }
    let mut out = Vec::with_capacity(CSTP_HEADER_LEN + payload.len());
    out.extend_from_slice(b"STF\x01");
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(pkt_type);
    out.push(0x00);
    out.extend_from_slice(payload);
    Ok(out)
}

/// 解一帧（校验魔术/版本/保留字节/长度），返回 (类型, 载荷)。
///
/// 错误具名：任何不匹配 `STF\x01` 的头、任何非零第 7 字节、载荷越界均
/// 点名（对端串协议面）。
pub(crate) fn decode_frame(header: &[u8], body: &[u8]) -> Result<CstpFrame> {
    if header.len() != CSTP_HEADER_LEN {
        bail!("CSTP 帧头长度异常：{} 字节", header.len());
    }
    if &header[0..4] != b"STF\x01" {
        bail!("CSTP 帧魔术/版本不匹配：{:02x?}", &header[0..4]);
    }
    if header[7] != 0x00 {
        bail!("CSTP 帧保留字节非零：0x{:02x}", header[7]);
    }
    let len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if len != body.len() {
        bail!("CSTP 帧载荷长度不一致：头 {len} vs 体 {}", body.len());
    }
    Ok(CstpFrame {
        pkt_type: header[6],
        payload: body.to_vec(),
    })
}

/// 隧道信息（CONNECT 200 应答 X-CSTP-* 头）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TunnelInfo {
    /// 客户端隧道地址（X-CSTP-Address）
    pub(crate) address: Ipv4Addr,
    /// 前缀长度（由 X-CSTP-Netmask 换算）
    pub(crate) prefix: u8,
    /// 隧道 DNS 服务器（X-CSTP-DNS，可空）
    pub(crate) dns: Vec<Ipv4Addr>,
    /// 隧道 MTU（X-CSTP-MTU，缺省 1400）
    pub(crate) mtu: u16,
}

/// 从 X-CSTP-Netmask（点分十进制）换算前缀长度。
pub(crate) fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from(netmask);
    // 连续 1 计数（网络掩码必须连续；非连续按 0 前缀保守处理）
    let mut prefix = 0u8;
    let mut seen_zero = false;
    for i in (0..32).rev() {
        let bit = (bits >> i) & 1;
        if bit == 1 {
            if seen_zero {
                return 0; // 非连续掩码：保守 0（视同 /0 无掩码路由）
            }
            prefix += 1;
        } else {
            seen_zero = true;
        }
    }
    prefix
}

/// 表单编码（application/x-www-form-urlencoded；本面仅键值恒等转义）。
fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// HTTP/1.1 响应（状态行 + 头 + 体）。
#[derive(Debug, Clone)]
struct HttpResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set_cookie(&self) -> Option<&str> {
        self.header("set-cookie")
    }
}

/// 读取一个 HTTP/1.1 响应（状态行 + 头 + Content-Length 体）。
async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<HttpResponse> {
    // 状态行
    let status_line = read_line_until(reader, buf).await?;
    let mut parts = status_line.split_whitespace();
    let _http = parts.next().ok_or_else(|| anyhow!("空状态行"))?;
    let status: u16 = parts
        .next()
        .ok_or_else(|| anyhow!("状态行缺状态码：{status_line}"))?
        .parse()
        .with_context(|| format!("状态码非法：{status_line}"))?;
    let reason = parts.collect::<Vec<_>>().join(" ");

    // 头（至空行）
    let mut headers = Vec::new();
    loop {
        let line = read_line_until(reader, buf).await?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    // 体（Content-Length；chunked 不在认证/CONNECT 面出现，缺省空）
    let body_len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await.with_context(|| {
        format!("读 HTTP 响应体（{body_len} 字节）失败：{} {reason}", status)
    })?;

    Ok(HttpResponse {
        status,
        reason,
        headers,
        body,
    })
}

/// 读一行（CRLF 结尾；不含结尾）。
async fn read_line_until<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> Result<String> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            bail!("对端提前关连接（HTTP 头未读完）");
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() > 65536 {
            bail!("HTTP 行超限（>64KiB）");
        }
    }
    String::from_utf8(buf.clone()).map_err(|_| anyhow!("HTTP 头非 UTF-8"))
}

/// 发起一个 HTTP/1.1 请求（首行 + 头 + 体），返回原始首行文本（供读状态）。
async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<()> {
    let mut req = String::new();
    req.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    writer.write_all(req.as_bytes()).await?;
    if !body.is_empty() {
        writer.write_all(body).await?;
    }
    writer.flush().await?;
    Ok(())
}

/// OpenConnect 客户端配置（会话建立参数）。
#[derive(Debug, Clone)]
pub(crate) struct OpenConnectConfig {
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) sni: Option<String>,
    pub(crate) skip_cert_verify: bool,
}

impl OpenConnectConfig {
    fn sni_or_server(&self) -> String {
        self.sni.clone().unwrap_or_else(|| self.server.clone())
    }
}

/// 建立一次 TLS 连接到服务器（拨号 + 握手；ALPN 不设——ocserv 期望
/// HTTP/1.1 CONNECT，无 ALPN 协商）。
async fn tls_connect(cfg: &OpenConnectConfig) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let addr = format!("{}:{}", cfg.server, cfg.port);
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP 拨号 {addr} 失败"))?;
    tcp.set_nodelay(true).ok();
    let connector = create_tls_connector_with_profile(
        cfg.skip_cert_verify,
        None,
        TlsFingerprint::None,
    )?;
    let server_name = cfg.sni_or_server();
    let dns_name = tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|_| anyhow!("SNI 非法：{server_name}"))?;
    connector
        .connect(dns_name, tcp)
        .await
        .with_context(|| format!("TLS 握手 {} 失败", cfg.sni_or_server()))
}

/// 认证两阶段 + CONNECT，返回 (数据 TLS 流, 隧道信息)。
///
/// 每阶段独立连接（`Connection: close`——keep-alive POST 会得到空响应）。
/// 返回的流即 CONNECT 隧道数据流（后续 CSTP 帧读写在它之上）。
pub(crate) async fn establish_session(
    cfg: &OpenConnectConfig,
) -> Result<(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, TunnelInfo)> {
    let username_body = form_encode(&[("username", &cfg.username)]);
    let password_body = form_encode(&[("password", &cfg.password)]);
    let host = cfg.sni_or_server();

    // ① 用户名步：POST /auth → Set-Cookie: webvpncontext
    let webvpncontext = {
        let mut stream = tls_connect(cfg).await?;
        write_request(
            &mut stream,
            "POST",
            "/auth",
            &[
                ("Host", &host),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Connection", "close"),
            ],
            username_body.as_bytes(),
        )
        .await?;
        let resp = read_response(&mut stream, &mut Vec::new()).await?;
        if resp.status != 200 {
            bail!("用户名步 HTTP {}：{}", resp.status, resp.reason);
        }
        cookie_value(resp.set_cookie()).ok_or_else(|| {
            anyhow!(
                "用户名步未获 webvpncontext cookie：{}",
                String::from_utf8_lossy(&resp.body)
            )
        })?
    };

    // ② 密码步：POST /auth + Cookie: webvpncontext → type="complete" +
    //    Set-Cookie: webvpn
    let webvpn = {
        let mut stream = tls_connect(cfg).await?;
        write_request(
            &mut stream,
            "POST",
            "/auth",
            &[
                ("Host", &host),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Connection", "close"),
                ("Cookie", &format!("webvpncontext={webvpncontext}")),
            ],
            password_body.as_bytes(),
        )
        .await?;
        let resp = read_response(&mut stream, &mut Vec::new()).await?;
        if resp.status != 200 {
            bail!("密码步 HTTP {}：{}", resp.status, resp.reason);
        }
        if !resp.body.windows(8).any(|w| w == b"complete") {
            bail!(
                "密码步未认证通过（type 非 complete）：{}",
                String::from_utf8_lossy(&resp.body)
            );
        }
        cookie_value(resp.set_cookie()).ok_or_else(|| {
            anyhow!(
                "密码步未获 webvpn cookie：{}",
                String::from_utf8_lossy(&resp.body)
            )
        })?
    };

    // ③ CONNECT /CSCOSSLC/tunnel（webvpn 会话 cookie）→ 200 CONNECTED +
    //    X-CSTP-* 头；此连接即数据隧道。
    let mut stream = tls_connect(cfg).await?;
    write_request(
        &mut stream,
        "CONNECT",
        "/CSCOSSLC/tunnel",
        &[
            ("Host", &host),
            ("User-Agent", "rillane/0.1"),
            ("Cookie", &format!("webvpn={webvpn}")),
            ("X-CSTP-Version", "2"),
            ("X-CSTP-MTU", "1400"),
            ("X-CSTP-Base-MTU", "1400"),
            ("X-CSTP-Address-Type", "IPv4"),
            ("X-CSTP-Protocol", "Cisco-VPN"),
            ("X-CSTP-Client-Split-Exclude", "::"),
        ],
        b"",
    )
    .await?;
    let resp = read_response(&mut stream, &mut Vec::new()).await?;
    if resp.status != 200 {
        bail!("CONNECT HTTP {}：{}", resp.status, resp.reason);
    }
    let info = parse_tunnel_info(&resp)?;
    Ok((stream, info))
}

/// 从 set-cookie 头取值（`name=value` 前缀，取到首个 `;`）。
fn cookie_value(set_cookie: Option<&str>) -> Option<String> {
    let sc = set_cookie?;
    let v = sc.split(';').next()?.trim();
    let (_, val) = v.split_once('=')?;
    Some(val.trim().to_string())
}

/// 解析 CONNECT 应答 X-CSTP-* 头为隧道信息。
fn parse_tunnel_info(resp: &HttpResponse) -> Result<TunnelInfo> {
    let addr: Ipv4Addr = resp
        .header("x-cstp-address")
        .ok_or_else(|| anyhow!("CONNECT 应答缺 X-CSTP-Address"))?
        .trim()
        .parse()
        .context("X-CSTP-Address 非法")?;
    let netmask: Ipv4Addr = resp
        .header("x-cstp-netmask")
        .ok_or_else(|| anyhow!("CONNECT 应答缺 X-CSTP-Netmask"))?
        .trim()
        .parse()
        .context("X-CSTP-Netmask 非法")?;
    let prefix = netmask_to_prefix(netmask);
    let dns = resp
        .header("x-cstp-dns")
        .map(|v| {
            v.split(|c| c == ',' || c == ' ')
                .filter(|s| !s.trim().is_empty())
                .filter_map(|s| s.trim().parse().ok())
                .collect::<Vec<Ipv4Addr>>()
        })
        .unwrap_or_default();
    let mtu: u16 = resp
        .header("x-cstp-mtu")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1400);
    Ok(TunnelInfo {
        address: addr,
        prefix,
        dns,
        mtu,
    })
}

// ===================== 三层桥（用户态 smoltcp egress） =====================
//
// CSTP 数据载荷 = 原始 IP 包（三层隧道，非字节流）——目标连接由用户态
// smoltcp 栈拨出：栈的 phy 即 CSTP 隧道（rx = 隧道 DATA 帧载荷入栈、
// tx = 栈出包编 DATA 帧回隧道）。驱动循环（会话级单例）独占隧道读写与
// 栈 poll；应用流经 `EgressTcpStream`（AsyncRead/AsyncWrite 适配）骑栈
// 上的 TCP socket。tun_tcp.rs（runtime 入面）同构先例，此处为出面向。

use smoltcp::iface::{Config, Interface, SocketHandle as SmolHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::dns::{self, Socket as DnsSocket};
use smoltcp::wire::DnsQueryType as DnsType;
use smoltcp::socket::tcp::{self, SocketBuffer, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Mutex as StdMutex;
use tokio::sync::Notify;

type TlsStreamT = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// 隧道端 phy：rx = 隧道 DATA 帧入栈队列，tx = 栈出包待编帧队列。
struct EgressPhy {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for EgressPhy {
    type RxToken<'a> = PhyRxToken;
    type TxToken<'a> = PhyTxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((
            PhyRxToken(pkt),
            PhyTxToken { queue: &mut self.tx },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(PhyTxToken { queue: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = None;
        caps
    }
}

struct PhyRxToken(Vec<u8>);

impl RxToken for PhyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct PhyTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for PhyTxToken<'_> {
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

/// 每 socket 收发缓冲（同 tun_tcp 口径：MTU−60，下限保底）
const MIN_SOCKET_BUF: usize = 512;
/// 本地源端口分配起点（临时端口段）
const EPHEMERAL_BASE: u16 = 32768;

struct StackInner {
    iface: Interface,
    device: EgressPhy,
    sockets: SocketSet<'static>,
    /// 活跃应用流（存在 = 活；流经 EgressTcpStream Drop 收敛）
    flows: HashMap<SmolHandle, ()>,
    retiring: Vec<SmolHandle>,
    /// DNS 套接字（惰性建，隧道 X-CSTP-DNS 服务器）
    dns: Option<SmolHandle>,
    dns_servers: Vec<IpAddress>,
    buf_size: usize,
    local_addr: IpAddress,
    next_port: u16,
    used_ports: HashSet<u16>,
}

impl StackInner {
    /// 临时源端口分配（回绕；碰撞重试，上界防御）
    fn next_local_port(&mut self) -> u16 {
        for _ in 0..(u16::MAX as u32) {
            let p = self.next_port;
            self.next_port = if self.next_port >= 65535 {
                EPHEMERAL_BASE
            } else {
                self.next_port + 1
            };
            if !self.used_ports.contains(&p) {
                self.used_ports.insert(p);
                return p;
            }
        }
        EPHEMERAL_BASE // 满表兜底（理论不可达：flows 上界远小于端口段）
    }

    fn release_port(&mut self, port: u16) {
        self.used_ports.remove(&port);
    }

    /// 单 poll 驱动点：入栈包与定时器一次推进 → 退役收敛 → 发信面出队。
    fn drive(&mut self) -> Vec<Vec<u8>> {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);

        // 退役句柄收敛（!is_open 含 Closed/TimeWait——唯一移除出口）
        let mut keep = Vec::with_capacity(self.retiring.len());
        for h in std::mem::take(&mut self.retiring) {
            if self.sockets.get::<tcp::Socket>(h).is_open() {
                keep.push(h);
            } else {
                // 归还源端口
                let port = self.sockets.get::<tcp::Socket>(h).local_endpoint().map(|e| e.port);
                if let Some(p) = port {
                    self.used_ports.remove(&p);
                }
                self.sockets.remove(h);
            }
        }
        self.retiring = keep;

        let mut out = Vec::new();
        while let Some(p) = self.device.tx.pop_front() {
            out.push(p);
        }
        out
    }
}

/// 用户态 egress 栈（驱动循环与 [`EgressTcpStream`] 共享的句柄持有者）。
struct EgressStack {
    inner: StdMutex<StackInner>,
    kick: Notify,
}

impl EgressStack {
    fn new(info: &TunnelInfo) -> Self {
        let mtu = info.mtu.max(576) as usize;
        let buf_size = (mtu - 60).max(MIN_SOCKET_BUF);
        let mut device = EgressPhy {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5EED_1210;
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::from(std::net::IpAddr::V4(info.address)),
                info.prefix.min(32),
            ));
        });
        // 网关 = 网络基址 | 1（ocserv 约定：服务器取网段首地址）；Medium::Ip
        // 无邻居解析（点对点），via 仅用于路由选择
        let net = u32::from(info.address) & netmask_of(info.prefix);
        let gw = net | 1;
        let gateway = Ipv4Address::new(
            ((gw >> 24) & 0xff) as u8,
            ((gw >> 16) & 0xff) as u8,
            ((gw >> 8) & 0xff) as u8,
            (gw & 0xff) as u8,
        );
        let _ = iface.routes_mut().add_default_ipv4_route(gateway);
        Self {
            inner: StdMutex::new(StackInner {
                iface,
                device,
                sockets: SocketSet::new(vec![]),
                flows: HashMap::new(),
                retiring: Vec::new(),
                dns: None,
                dns_servers: info
                    .dns
                    .iter()
                    .map(|d| IpAddress::from(std::net::IpAddr::V4(*d)))
                    .collect(),
                buf_size,
                local_addr: IpAddress::from(std::net::IpAddr::V4(info.address)),
                next_port: EPHEMERAL_BASE,
                used_ports: HashSet::new(),
            }),
            kick: Notify::new(),
        }
    }

    fn kick_notify(&self) -> &Notify {
        &self.kick
    }

    /// 隧道 DATA 帧载荷入栈（驱动循环调用）。
    fn ingest(&self, pkt: Vec<u8>) {
        self.inner.lock().unwrap().device.rx.push_back(pkt);
    }

    /// poll + 退役收敛 + 出包（驱动循环调用）。
    fn drive(&self) -> Vec<Vec<u8>> {
        self.inner.lock().unwrap().drive()
    }

    /// 拨一条 TCP 连接（源端口显式分配——smoltcp connect 拒绝端口 0）。
    fn open_tcp(&self, remote: IpEndpoint) -> Result<SmolHandle> {
        let mut inner = self.inner.lock().unwrap();
        let port = inner.next_local_port();
        let local = IpEndpoint::new(inner.local_addr, port);
        let mut sock = tcp::Socket::new(
            SocketBuffer::new(vec![0u8; inner.buf_size]),
            SocketBuffer::new(vec![0u8; inner.buf_size]),
        );
        sock.set_nagle_enabled(false);
        let h = inner.sockets.add(sock);
        let conn = {
            let StackInner {
                iface, sockets, ..
            } = &mut *inner;
            let cx = iface.context();
            let s = sockets.get_mut::<tcp::Socket>(h);
            s.connect(cx, remote, local)
        };
        if let Err(e) = conn {
            inner.sockets.remove(h);
            inner.release_port(port);
            return Err(anyhow!("TCP 拨号 {remote} 失败：{e:?}"));
        }
        inner.flows.insert(h, ());
        drop(inner);
        self.kick.notify_one();
        Ok(h)
    }

    /// 等待连接 Established（驱动循环持续推进栈）。
    async fn wait_established(&self, handle: SmolHandle, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let inner = self.inner.lock().unwrap();
                if !inner.flows.contains_key(&handle) {
                    bail!("TCP 连接已拆除（流收口）");
                }
                match inner.sockets.get::<tcp::Socket>(handle).state() {
                    TcpState::Established => return Ok(()),
                    TcpState::Closed | TcpState::TimeWait => {
                        bail!("TCP 握手失败：连接被对端关闭")
                    }
                    _ => {}
                }
            }
            if std::time::Instant::now() >= deadline {
                bail!("TCP 握手超时");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 隧道 DNS 解析（经栈内 dns 套接字；驱动循环持续推进）。
    async fn dns_query(&self, host: &str) -> Result<Vec<std::net::Ipv4Addr>> {
        let query = {
            let mut inner = self.inner.lock().unwrap();
            if inner.dns_servers.is_empty() {
                bail!("隧道未下发 DNS 服务器（X-CSTP-DNS 空），无法解析 {host}");
            }
            if inner.dns.is_none() {
                let servers: Vec<IpAddress> = inner.dns_servers.clone();
                let slots: Vec<Option<dns::DnsQuery>> =
                    (0..4).map(|_| None).collect();
                let sock = DnsSocket::new(&servers, slots);
                inner.dns = Some(inner.sockets.add(sock));
            }
            let dh = inner.dns.expect("dns handle");
            let StackInner {
                iface, sockets, ..
            } = &mut *inner;
            let cx = iface.context();
            let s = sockets.get_mut::<DnsSocket>(dh);
            match s.start_query(cx, host, DnsType::A) {
                Ok(q) => q,
                Err(e) => return Err(anyhow!("DNS 查询启动失败（{host}）：{e:?}")),
            }
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let result = {
                let mut inner = self.inner.lock().unwrap();
                let dh = inner.dns.expect("dns handle");
                let s = inner.sockets.get_mut::<DnsSocket>(dh);
                s.get_query_result(query)
            };
            match result {
                Ok(addrs) => {
                    let v4: Vec<std::net::Ipv4Addr> = addrs
                        .into_iter()
                        .filter_map(|a| match std::net::IpAddr::from(a) {
                            std::net::IpAddr::V4(v) => Some(v),
                            _ => None,
                        })
                        .collect();
                    if v4.is_empty() {
                        bail!("DNS 无 IPv4 结果：{host}");
                    }
                    return Ok(v4);
                }
                Err(dns::GetQueryResultError::Pending) => {}
                Err(dns::GetQueryResultError::Failed) => bail!("DNS 解析失败：{host}"),
            }
            if std::time::Instant::now() >= deadline {
                bail!("DNS 解析超时：{host}");
            }
            self.kick.notify_one();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// 隧道断链收敛：abort 全部活跃 socket（流读侧 EOF / 写侧破裂）。
    fn shutdown_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        let handles: Vec<SmolHandle> = inner.flows.keys().copied().collect();
        for h in handles {
            let s = inner.sockets.get_mut::<tcp::Socket>(h);
            if s.is_open() {
                s.abort();
            }
        }
        inner.flows.clear();
        inner.used_ports.clear();
        drop(inner);
        self.kick.notify_one();
    }
}

/// 由前缀长算网络掩码。
fn netmask_of(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// 应用流面：栈上 TCP socket 的 AsyncRead/AsyncWrite 适配（同构
/// tun_tcp.rs `SmolTcpStream`；Drop → close 进退役列，驱动循环收敛）。
struct EgressTcpStream {
    stack: std::sync::Arc<EgressStack>,
    handle: SmolHandle,
}

impl EgressTcpStream {
    fn new(stack: std::sync::Arc<EgressStack>, handle: SmolHandle) -> Self {
        Self { stack, handle }
    }

    /// 条目已撤（shutdown_all/收敛）= 该流已拆除——读侧 EOF、写侧破裂
    fn flow_live(&self, inner: &StackInner) -> bool {
        inner.flows.contains_key(&self.handle)
    }
}

impl tokio::io::AsyncRead for EgressTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock().unwrap();
        if !this.flow_live(&inner) {
            return std::task::Poll::Ready(Ok(())); // 拆除 → EOF
        }
        let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        let n = {
            let unfilled = buf.initialize_unfilled();
            s.recv_slice(unfilled)
        };
        match n {
            Ok(0) => {
                s.register_recv_waker(cx.waker());
                std::task::Poll::Pending
            }
            Ok(n) => {
                buf.advance(n);
                std::task::Poll::Ready(Ok(()))
            }
            Err(tcp::RecvError::Finished) => std::task::Poll::Ready(Ok(())),
            Err(e) => std::task::Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }
}

impl tokio::io::AsyncWrite for EgressTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock().unwrap();
        if !this.flow_live(&inner) {
            return std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        match s.send_slice(buf) {
            Ok(0) => {
                s.register_send_waker(cx.waker());
                drop(inner);
                this.stack.kick.notify_one();
                std::task::Poll::Pending
            }
            Ok(n) => {
                drop(inner);
                this.stack.kick.notify_one();
                std::task::Poll::Ready(Ok(n))
            }
            Err(e) => std::task::Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // 数据已入栈发送缓冲（poll_write 内已 kick 出段）
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.stack.inner.lock().unwrap();
        if this.flow_live(&inner) {
            let s = inner.sockets.get_mut::<tcp::Socket>(this.handle);
            if s.is_open() {
                s.close();
            }
        }
        drop(inner);
        this.stack.kick.notify_one();
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for EgressTcpStream {
    fn drop(&mut self) {
        let mut inner = self.stack.inner.lock().unwrap();
        if inner.flows.remove(&self.handle).is_some() {
            let s = inner.sockets.get_mut::<tcp::Socket>(self.handle);
            if s.is_open() {
                s.close();
            }
            inner.retiring.push(self.handle);
        }
        drop(inner);
        self.stack.kick.notify_one();
    }
}

/// 从字节流提取完整 CSTP 帧（跨读边界缓冲；畸形帧清空缓冲 = 会话终止面）。
fn extract_frames(pending: &mut Vec<u8>) -> Result<Vec<CstpFrame>> {
    let mut out = Vec::new();
    while pending.len() >= CSTP_HEADER_LEN {
        let len = u16::from_be_bytes([pending[4], pending[5]]) as usize;
        if pending.len() < CSTP_HEADER_LEN + len {
            break;
        }
        let header = pending[..CSTP_HEADER_LEN].to_vec();
        let body = pending[CSTP_HEADER_LEN..CSTP_HEADER_LEN + len].to_vec();
        out.push(decode_frame(&header, &body)?);
        pending.drain(..CSTP_HEADER_LEN + len);
    }
    Ok(out)
}

/// 驱动循环：独占隧道读写与栈 poll。DATA 帧入栈；DPD_OUT 应 KEEPALIVE
/// （载荷原样回）；DISCONN/TERM_SERVER/隧道断链/畸形帧 → 会话终止面
/// （dead 置位 + abort 全部活跃流）。
async fn drive_session(
    stack: std::sync::Arc<EgressStack>,
    dead: std::sync::Arc<AtomicBool>,
    mut reader: tokio::io::ReadHalf<TlsStreamT>,
    mut writer: tokio::io::WriteHalf<TlsStreamT>,
) {
    let mut buf = vec![0u8; 65536];
    let mut pending: Vec<u8> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    let mut running = true;
    while running {
        tokio::select! {
            r = reader.read(&mut buf) => {
                match r {
                    Ok(0) | Err(_) => running = false,
                    Ok(n) => {
                        pending.extend_from_slice(&buf[..n]);
                        let frames = match extract_frames(&mut pending) {
                            Ok(f) => f,
                            Err(_) => { running = false; Vec::new() }
                        };
                        for f in frames {
                            match f.pkt_type {
                                PKT_DATA => stack.ingest(f.payload),
                                PKT_DPD_OUT => {
                                    if let Ok(kp) = encode_frame(PKT_KEEPALIVE, &f.payload) {
                                        let _ = writer.write_all(&kp).await;
                                    }
                                }
                                PKT_DPD_RESP | PKT_KEEPALIVE => {}
                                PKT_DISCONN | PKT_TERM_SERVER => running = false,
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ = stack.kick_notify().notified() => {}
            _ = tick.tick() => {}
        }
        if running {
            for pkt in stack.drive() {
                match encode_frame(PKT_DATA, &pkt) {
                    Ok(fr) => {
                        if writer.write_all(&fr).await.is_err() {
                            running = false;
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    dead.store(true, AtomicOrdering::Release);
    stack.shutdown_all();
    stack.kick_notify().notify_one();
}

/// 已建立的会话（栈 + 驱动循环句柄）。
struct OpenConnectSession {
    stack: std::sync::Arc<EgressStack>,
    dead: std::sync::Arc<AtomicBool>,
    _driver: tokio::task::JoinHandle<()>,
}

impl OpenConnectSession {
    fn is_dead(&self) -> bool {
        self.dead.load(AtomicOrdering::Acquire)
    }
}

impl Drop for OpenConnectSession {
    fn drop(&mut self) {
        self._driver.abort();
    }
}

/// OpenConnect 出口连接器（RIL-121）。
///
/// 每节点一条 CSTP 隧道（惰性建立，断链后下一条流重建）；应用流骑用户态
/// smoltcp 栈（三层桥）。仅交付 TCP 应用面（UDP/QUIC 应用面不交付——
/// catalog udp=false 同口径，构建期由 scan_udp_capability 拒绝）。
pub struct OpenConnectConnector {
    cfg: OpenConnectConfig,
    session: tokio::sync::Mutex<Option<std::sync::Arc<OpenConnectSession>>>,
}

impl OpenConnectConnector {
    pub fn new(
        server: String,
        port: u16,
        username: String,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
    ) -> Result<Self> {
        if server.trim().is_empty() {
            return Err(anyhow!("openconnect 服务器地址为空"));
        }
        if username.trim().is_empty() || password.trim().is_empty() {
            return Err(anyhow!("openconnect 凭证缺失（username/password 均必填）"));
        }
        Ok(Self {
            cfg: OpenConnectConfig {
                server,
                port,
                username,
                password,
                sni,
                skip_cert_verify,
            },
            session: tokio::sync::Mutex::new(None),
        })
    }

    /// 取共享会话（死会话丢弃重建；Mutex 串行化建立——避免并发流重复建隧道）。
    async fn session(&self) -> Result<std::sync::Arc<OpenConnectSession>> {
        let mut slot = self.session.lock().await;
        if let Some(s) = slot.as_ref() {
            if !s.is_dead() {
                return Ok(s.clone());
            }
        }
        let (stream, info) = tokio::time::timeout(CONNECT_TIMEOUT, establish_session(&self.cfg))
            .await
            .map_err(|_| anyhow!("OpenConnect 会话建立超时（{CONNECT_TIMEOUT:?}）"))?
            .context("OpenConnect 会话建立失败")?;
        let stack = std::sync::Arc::new(EgressStack::new(&info));
        let dead = std::sync::Arc::new(AtomicBool::new(false));
        let (reader, writer) = tokio::io::split(stream);
        let driver = tokio::spawn(drive_session(
            stack.clone(),
            dead.clone(),
            reader,
            writer,
        ));
        let s = std::sync::Arc::new(OpenConnectSession {
            stack,
            dead,
            _driver: driver,
        });
        *slot = Some(s.clone());
        Ok(s)
    }
}

#[async_trait::async_trait]
impl rillane_core::EgressConnector for OpenConnectConnector {
    fn name(&self) -> &'static str {
        "openconnect"
    }

    async fn forward(&self, mut flow: rillane_core::Flow) -> Result<rillane_core::FlowReport> {
        use rillane_core::{FlowReport, TargetProto};
        if !matches!(flow.target.proto, TargetProto::Tcp) {
            return Err(anyhow!(
                "OpenConnect 仅交付 TCP 应用面（UDP/QUIC 应用面不交付）"
            ));
        }
        let session = self.session().await?;
        let remote = match flow.target.host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => IpEndpoint::new(
                IpAddress::from(std::net::IpAddr::V4(ip)),
                flow.target.port,
            ),
            Err(_) => {
                if flow.target.host.parse::<std::net::Ipv6Addr>().is_ok() {
                    return Err(anyhow!(
                        "OpenConnect 隧道仅 IPv4（ipv4-network 面），IPv6 目标不支持：{}",
                        flow.target.host
                    ));
                }
                let addrs = session.stack.dns_query(&flow.target.host).await?;
                let ip = addrs
                    .first()
                    .copied()
                    .ok_or_else(|| anyhow!("DNS 无结果：{}", flow.target.host))?;
                IpEndpoint::new(
                    IpAddress::from(std::net::IpAddr::V4(ip)),
                    flow.target.port,
                )
            }
        };
        let handle = session.stack.open_tcp(remote)?;
        session
            .stack
            .wait_established(handle, Duration::from_secs(15))
            .await
            .context("目标连接建立失败")?;
        let mut stream = EgressTcpStream::new(session.stack.clone(), handle);
        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut stream)
            .await
            .map_err(|e| anyhow!("relay 失败：{e}"))?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_rejections() {
        let pkt = b"\x45\x00\x00\x2c\x01\x02\x40\x00\x40\x06\x00\x00\x0a\xc8\x00\x01\x0a\xc8\x00\x02";
        let enc = encode_frame(PKT_DATA, pkt).unwrap();
        assert_eq!(&enc[0..4], b"STF\x01");
        assert_eq!(&enc[4..6], &((pkt.len() as u16).to_be_bytes()));
        assert_eq!(enc[6], PKT_DATA);
        assert_eq!(enc[7], 0);
        assert_eq!(&enc[8..], pkt);
        let dec = decode_frame(&enc[0..8], &enc[8..]).unwrap();
        assert_eq!(dec.pkt_type, PKT_DATA);
        assert_eq!(dec.payload, pkt);
    }

    #[test]
    fn frame_rejects_bad_magic_version_and_reserved() {
        let mut h = [0u8; 8];
        h[4] = 0;
        h[5] = 0;
        h[6] = PKT_DATA;
        // 魔术错误
        assert!(decode_frame(&h, &[]).unwrap_err().to_string().contains("魔术"));
        // 版本错误
        h[0..4].copy_from_slice(b"STF\x02");
        assert!(decode_frame(&h, &[]).unwrap_err().to_string().contains("版本"));
        // 保留字节非零
        h[0..4].copy_from_slice(b"STF\x01");
        h[7] = 1;
        assert!(decode_frame(&h, &[]).unwrap_err().to_string().contains("保留"));
        // 长度不一致
        h[7] = 0;
        h[5] = 4;
        assert!(decode_frame(&h, &[1, 2, 3]).unwrap_err().to_string().contains("长度"));
    }

    #[test]
    fn netmask_prefix_conversion() {
        assert_eq!(netmask_to_prefix("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(netmask_to_prefix("255.255.255.255".parse().unwrap()), 32);
        assert_eq!(netmask_to_prefix("0.0.0.0".parse().unwrap()), 0);
        assert_eq!(netmask_to_prefix("255.255.0.0".parse().unwrap()), 16);
    }

    #[test]
    fn form_and_cookie() {
        assert_eq!(
            form_encode(&[("username", "demo")]),
            "username=demo"
        );
        assert_eq!(
            cookie_value(Some("webvpncontext=abc123; Path=/; HttpOnly")),
            Some("abc123".into())
        );
        assert_eq!(cookie_value(None), None);
    }
}
