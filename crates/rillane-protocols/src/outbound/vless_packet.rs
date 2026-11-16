//! VLESS UDP 包编码面（RIL-130）：raw（vless.rs G0-4 原生 [2B 长度] 分帧、
//! 命令 0x02 单目标）之外的两种逐报寻址编码——`xudp` 与 `packetaddr`。
//! 真源对照逐字节核验（2026-11-16，见 docs/zh/protocol-backends.md「公共
//! 传输与复用矩阵」）：sing-vmess v0.2.4 xudp.go（帧读写）+ protocol.go
//! AddressSerializer（port-first 地址）、mihomo transport/vless/conn.go
//! （Mux 分支命令 0x03 头**不带目标地址**）与 adapter/outbound/vless.go
//! （编码判定、packetaddr magic 地址）。
//!
//! - xudp：vless 请求头 = 版本+uuid+addons 长(0)+命令 0x03（无地址段）；
//!   首报 New 帧（类型 1、opt 1、网络 2、目标地址、GlobalID 零则省），
//!   后续 Keep 帧（类型 2）逐报携目标；下行同构（元长==4 时目标即会话
//!   目标；sing 表 3=End/xray 表 4=End——客户端按「2=数据、3/4=会话收束」
//!   容忍面收束；opt 位 0x01 有载荷、0x02 对端故障）。
//! - packetaddr：vless 请求头 = 命令 0x02 + magic 地址
//!   `sp.packet-addr.v2fly.arpa`:443；每报在 vless [2B 长度] 分帧内再带
//!   family-first 地址前缀（0x01 v4 / 0x02 v6，无域名面——
//!   ErrFqdnUnsupported 同口径，域名目标具名拒绝）。

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use rillane_core::udp::UdpRelay;
use rillane_core::{FlowTarget, TargetProto};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

/// xudp/packetaddr 编码白名单与解析：其余取值具名拒绝（不静默当 raw 用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    /// 缺省：Xray 原生 UDP 面（vless.rs G0-4）
    Raw,
    /// 命令 0x03 + XUDP 帧（逐报寻址）
    Xudp,
    /// 命令 0x02 + magic 地址 + family-first 逐报寻址
    Packetaddr,
}

impl PacketEncoding {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None => Ok(Self::Raw),
            Some("raw") => Ok(Self::Raw),
            Some("xudp") => Ok(Self::Xudp),
            Some("packetaddr") => Ok(Self::Packetaddr),
            Some(other) => Err(anyhow!(
                "VLESS packet-encoding 仅支持 raw/xudp/packetaddr（缺省 raw），当前： {other}"
            )),
        }
    }
}

/// packetaddr 会话 magic 地址（sing-vmess packetaddr.SeqPacketMagicAddress；
/// mihomo adapter 侧 SeqPacketMagicAddress + 端口 443）
pub const PACKETADDR_MAGIC_HOST: &str = "sp.packet-addr.v2fly.arpa";
pub const PACKETADDR_MAGIC_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// 地址序列化
// ---------------------------------------------------------------------------

/// xudp 地址（port-first，sing-vmess protocol.go AddressSerializer，与
/// Xray PortThenAddress 同）：`[2B BE port][0x01 v4 | 0x02 域名(1B 长+串) |
/// 0x03 v6][地址]`
pub(crate) fn xudp_encode_addr(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(19);
    out.extend_from_slice(&port.to_be_bytes());
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(0x03);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let bytes = host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(anyhow!("XUDP 域名目标长度越界（1..=255）"));
            }
            out.push(0x02);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    Ok(out)
}

/// xudp 地址逆序列化：返回 (host, port) 与消耗字节数
pub(crate) fn xudp_decode_addr(buf: &[u8]) -> Result<(FlowTarget, usize)> {
    if buf.len() < 3 {
        return Err(anyhow!("XUDP 地址段越界（<3B）"));
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let atype = buf[2];
    let (host, consumed) = match atype {
        0x01 => {
            if buf.len() < 7 {
                return Err(anyhow!("XUDP IPv4 地址段越界"));
            }
            (
                std::net::Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]).to_string(),
                3 + 4,
            )
        }
        0x02 => {
            let len = buf[3] as usize;
            if buf.len() < 4 + len {
                return Err(anyhow!("XUDP 域名地址段越界"));
            }
            (
                String::from_utf8(buf[4..4 + len].to_vec()).context("XUDP 域名目标非 UTF-8")?,
                4 + len,
            )
        }
        0x03 => {
            if buf.len() < 19 {
                return Err(anyhow!("XUDP IPv6 地址段越界"));
            }
            let octets: [u8; 16] = buf[3..19].try_into().expect("16B 切片已核长");
            (std::net::Ipv6Addr::from(octets).to_string(), 3 + 16)
        }
        other => return Err(anyhow!("XUDP 未知地址族： {other:#04x}")),
    };
    Ok((
        FlowTarget {
            host,
            port,
            proto: TargetProto::Udp,
        },
        consumed,
    ))
}

/// packetaddr 地址（family-first，sing-vmess packetaddr AddressSerializer，
/// 无域名面）：`[0x01 v4 | 0x02 v6][地址][2B BE port]`
pub(crate) fn packetaddr_encode_addr(host: &str, port: u16) -> Result<Vec<u8>> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| anyhow!("packetaddr 不承载域名目标（ErrFqdnUnsupported 同口径）： {host}"))?;
    let mut out = Vec::with_capacity(19);
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// packetaddr 地址逆序列化：返回 (target, 消耗字节数)
pub(crate) fn packetaddr_decode_addr(buf: &[u8]) -> Result<(FlowTarget, usize)> {
    if buf.is_empty() {
        return Err(anyhow!("packetaddr 地址段越界（空）"));
    }
    let (host, consumed) = match buf[0] {
        0x01 => {
            if buf.len() < 5 {
                return Err(anyhow!("packetaddr IPv4 地址段越界"));
            }
            (
                std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]).to_string(),
                5,
            )
        }
        0x02 => {
            if buf.len() < 17 {
                return Err(anyhow!("packetaddr IPv6 地址段越界"));
            }
            let octets: [u8; 16] = buf[1..17].try_into().expect("16B 切片已核长");
            (std::net::Ipv6Addr::from(octets).to_string(), 17)
        }
        other => return Err(anyhow!("packetaddr 未知地址族： {other:#04x}")),
    };
    if buf.len() < consumed + 2 {
        return Err(anyhow!("packetaddr 地址段缺端口"));
    }
    let port = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]);
    Ok((
        FlowTarget {
            host,
            port,
            proto: TargetProto::Udp,
        },
        consumed + 2,
    ))
}

// ---------------------------------------------------------------------------
// XUDP 帧
// ---------------------------------------------------------------------------

/// XUDP 首报 New 帧（sing-vmess v0.2.4 xudp.go WritePacket 首分支；GlobalID
/// 零则省——仓内会话无本地源地址，恒省略）：`[2B BE 元长][0x00 0x00][0x01]
/// [0x01][0x02][地址][2B BE 载荷长][载荷]`；元长 = 会话段(2)+类型+opt+网络(3)
/// +地址，不含载荷长字段
pub(crate) fn xudp_frame_new(target: &FlowTarget, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("XUDP 数据报过大（>65535）"));
    }
    let addr = xudp_encode_addr(&target.host, target.port)?;
    let meta_len = 5 + addr.len();
    let mut out = Vec::with_capacity(2 + meta_len + 2 + payload.len());
    out.extend_from_slice(&(meta_len as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x02]);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// XUDP 后续 Keep 帧（逐报携目标）：`[2B BE 元长][0x00 0x00][0x02][0x01]
/// [0x02][地址][2B BE 载荷长][载荷]`
pub(crate) fn xudp_frame_keep(target: &FlowTarget, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("XUDP 数据报过大（>65535）"));
    }
    let addr = xudp_encode_addr(&target.host, target.port)?;
    let meta_len = 5 + addr.len();
    let mut out = Vec::with_capacity(2 + meta_len + 2 + payload.len());
    out.extend_from_slice(&(meta_len as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x02]);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// XUDP 下行帧（sing-vmess v0.2.4 xudp.go ReadPacket 同构）：读
/// `[2B BE 元长][2B 会话][状态][opt]`；状态 2=Keep（元长>4 时元段 =
/// `[1B 网络][地址][2B BE 载荷长]`——载荷长在元段尾部，与 sing
/// length-2 读面一致；==4 时目标即会话目标、载荷长在流上）、
/// 3/4=会话收束（sing 表 End/KeepAlive 与 xray 表互换，按收束容忍）；
/// opt 0x02=对端故障具名、0x01=有载荷。无载荷帧跳过续读下一帧
/// （sing 递归同口径）。返回 None = 会话收束（EOF 语义）。
pub(crate) async fn xudp_read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    session: &FlowTarget,
    buf: &mut [u8],
) -> Result<Option<(FlowTarget, usize)>> {
    loop {
        let mut head = [0u8; 6];
        r.read_exact(&mut head).await?;
        let meta_len = u16::from_be_bytes([head[0], head[1]]) as usize;
        let status = head[4];
        let opt = head[5];
        // opt 0x02 = 对端故障（sing：remote closed）
        if opt & 0x02 == 0x02 {
            return Err(anyhow!("XUDP 对端故障收束（opt error）"));
        }
        match status {
            // Keep 带寻址（下行常规）：元段尾 2B 即载荷长
            2 if meta_len > 4 => {
                let mut meta = vec![0u8; meta_len - 2];
                r.read_exact(&mut meta).await?;
                let (target, _) = xudp_decode_addr(&meta[1..])?;
                if opt & 0x01 != 0x01 {
                    continue;
                }
                let len = u16::from_be_bytes([meta[meta.len() - 2], meta[meta.len() - 1]]) as usize;
                let n = len.min(buf.len());
                r.read_exact(&mut buf[..n]).await?;
                // 上游长度超出调用方缓冲：丢弃余量，保流对齐
                if len > n {
                    let mut skip = vec![0u8; len - n];
                    r.read_exact(&mut skip).await?;
                }
                return Ok(Some((target, n)));
            }
            // Keep 无寻址（元长==4）：载荷长在流上
            2 => {
                if opt & 0x01 != 0x01 {
                    continue;
                }
                let mut len_b = [0u8; 2];
                r.read_exact(&mut len_b).await?;
                let len = u16::from_be_bytes(len_b) as usize;
                let n = len.min(buf.len());
                r.read_exact(&mut buf[..n]).await?;
                if len > n {
                    let mut skip = vec![0u8; len - n];
                    r.read_exact(&mut skip).await?;
                }
                return Ok(Some((session.clone(), n)));
            }
            // 3/4 = 会话收束（sing End / xray discard 表互换容忍面）
            3 | 4 => return Ok(None),
            other => return Err(anyhow!("XUDP 未知帧状态： {other:#04x}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Relay 面
// ---------------------------------------------------------------------------

/// XUDP relay：send/recv 分属 forward_up/forwarder 两任务，读写半各持
/// tokio Mutex（与 raw 面 VlessUdpRelay 同构）。send 首报 New、后续 Keep
/// 逐报携目标（逐报寻址 = 全锥能力面）；recv 返回帧内源地址。
pub struct XudpRelay {
    reader: AsyncMutex<tokio::io::ReadHalf<crate::BoxedIo>>,
    writer: AsyncMutex<tokio::io::WriteHalf<crate::BoxedIo>>,
    /// 会话目标（元长==4 的下行帧回落此目标）
    session: FlowTarget,
    /// 首报 New 已写（AtomicBool：send 路径单写者，仅作「首报一次」判定）
    new_written: AtomicBool,
}

impl XudpRelay {
    pub(crate) fn new(
        reader: tokio::io::ReadHalf<crate::BoxedIo>,
        writer: tokio::io::WriteHalf<crate::BoxedIo>,
        session: FlowTarget,
    ) -> Self {
        Self {
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(writer),
            session,
            new_written: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl UdpRelay for XudpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let frame = if self.new_written.swap(true, Ordering::SeqCst) {
            xudp_frame_keep(target, buf)?
        } else {
            xudp_frame_new(target, buf)?
        };
        let mut w = self.writer.lock().await;
        w.write_all(&frame).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut r = self.reader.lock().await;
        match xudp_read_frame(&mut *r, &self.session, buf).await? {
            Some(pair) => Ok(pair),
            None => Err(anyhow!("XUDP 会话收束（End/KeepAlive 帧）")),
        }
    }
}

impl std::fmt::Debug for XudpRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XudpRelay")
            .field("session", &self.session)
            .finish()
    }
}

/// packetaddr relay：send 每报 = vless [2B 长度] 分帧内携 family-first
/// 地址前缀；recv 剥前缀返回帧内源地址（域名目标发送具名拒绝——
/// ErrFqdnUnsupported 同口径）。
pub struct PacketAddrRelay {
    reader: AsyncMutex<tokio::io::ReadHalf<crate::BoxedIo>>,
    writer: AsyncMutex<tokio::io::WriteHalf<crate::BoxedIo>>,
    /// 会话目标（保留供 Debug；分帧内逐报寻址不依赖）
    target: FlowTarget,
}

impl PacketAddrRelay {
    pub(crate) fn new(
        reader: tokio::io::ReadHalf<crate::BoxedIo>,
        writer: tokio::io::WriteHalf<crate::BoxedIo>,
        target: FlowTarget,
    ) -> Self {
        Self {
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(writer),
            target,
        }
    }
}

#[async_trait]
impl UdpRelay for PacketAddrRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let addr = packetaddr_encode_addr(&target.host, target.port)?;
        let inner = addr.len() + buf.len();
        if inner > u16::MAX as usize {
            return Err(anyhow!("packetaddr 数据报过大（>65535）"));
        }
        let mut w = self.writer.lock().await;
        w.write_all(&(inner as u16).to_be_bytes()).await?;
        w.write_all(&addr).await?;
        w.write_all(buf).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut r = self.reader.lock().await;
        let mut len_b = [0u8; 2];
        r.read_exact(&mut len_b).await?;
        let len = u16::from_be_bytes(len_b) as usize;
        let mut inner = vec![0u8; len];
        r.read_exact(&mut inner).await?;
        let (target, addr_len) = packetaddr_decode_addr(&inner)?;
        let payload = &inner[addr_len..];
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Ok((target, n))
    }
}

impl std::fmt::Debug for PacketAddrRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketAddrRelay")
            .field("target", &self.target)
            .finish()
    }
}

/// vless Mux 请求头（xudp 载具，mihomo transport/vless/conn.go Mux 分支）：
/// 版本+uuid+addons 长(0)+命令 0x03——**不带端口/地址段**
pub(crate) fn build_vless_mux_request(uuid: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    out.push(0x00);
    out.extend_from_slice(&uuid);
    out.push(0);
    out.push(0x03);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_encoding_parse_whitelist() {
        // anyhow::Error 不实现 PartialEq：以 matches!/expect 逐支断言
        let raw = |v: Option<&str>| matches!(PacketEncoding::parse(v), Ok(PacketEncoding::Raw));
        assert!(raw(None));
        assert!(raw(Some("")));
        assert!(raw(Some("raw")));
        assert!(matches!(
            PacketEncoding::parse(Some("xudp")),
            Ok(PacketEncoding::Xudp)
        ));
        assert!(matches!(
            PacketEncoding::parse(Some("packetaddr")),
            Ok(PacketEncoding::Packetaddr)
        ));
        let err = PacketEncoding::parse(Some("smux")).expect_err("白名单外必须拒绝");
        assert!(err.to_string().contains("smux"));
        assert!(err.to_string().contains("raw/xudp/packetaddr"));
    }

    #[test]
    fn xudp_addr_port_first_roundtrip() {
        // IPv4：[2B port][0x01][4B]
        let v4 = xudp_encode_addr("10.1.2.3", 0x1f90).expect("编码");
        assert_eq!(
            v4,
            vec![0x1f, 0x90, 0x01, 10, 1, 2, 3],
            "port-first + 0x01 + 地址"
        );
        let (t, n) = xudp_decode_addr(&v4).expect("解码");
        assert_eq!((t.host.as_str(), t.port, n), ("10.1.2.3", 0x1f90, 7));

        // 域名：[2B port][0x02][1B len][域名]
        let dom = xudp_encode_addr("echo.example", 53).expect("编码");
        assert_eq!(dom[2], 0x02);
        assert_eq!(dom[3] as usize, "echo.example".len());
        let (t, n) = xudp_decode_addr(&dom).expect("解码");
        assert_eq!(
            (t.host.as_str(), t.port, n),
            ("echo.example", 53, dom.len())
        );

        // IPv6：[2B port][0x03][16B]
        let v6 = xudp_encode_addr("2001:db8::1", 443).expect("编码");
        assert_eq!(v6[2], 0x03);
        assert_eq!(v6.len(), 19);
        let (t, _) = xudp_decode_addr(&v6).expect("解码");
        assert_eq!(t.host, "2001:db8::1");
    }

    #[test]
    fn packetaddr_addr_family_first_no_domain() {
        // IPv4：[0x01][4B][2B port]（family-first）
        let v4 = packetaddr_encode_addr("10.1.2.3", 0x1f90).expect("编码");
        assert_eq!(v4, vec![0x01, 10, 1, 2, 3, 0x1f, 0x90]);
        let (t, n) = packetaddr_decode_addr(&v4).expect("解码");
        assert_eq!((t.host.as_str(), t.port, n), ("10.1.2.3", 0x1f90, 7));

        // IPv6：[0x02][16B][2B port]
        let v6 = packetaddr_encode_addr("2001:db8::1", 443).expect("编码");
        assert_eq!(v6[0], 0x02);
        let (t, _) = packetaddr_decode_addr(&v6).expect("解码");
        assert_eq!(t.host, "2001:db8::1");

        // 域名：具名拒绝（ErrFqdnUnsupported 同口径）
        let err = packetaddr_encode_addr("echo.example", 53).expect_err("域名必须拒绝");
        assert!(err.to_string().contains("packetaddr"));
        assert!(err.to_string().contains("域名"));
    }

    #[test]
    fn xudp_frame_shapes_byte_exact() {
        let target = FlowTarget {
            host: "10.1.2.3".into(),
            port: 0x1f90,
            proto: TargetProto::Udp,
        };
        // New 帧：元长 = 5+addrLen = 5+7 = 12；[0x000c][0000][01][01][02][addr][2B len][载荷]
        let new = xudp_frame_new(&target, b"ping").expect("New 帧");
        let mut want = Vec::new();
        want.extend_from_slice(&12u16.to_be_bytes());
        want.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x02]);
        want.extend_from_slice(&xudp_encode_addr("10.1.2.3", 0x1f90).expect("addr"));
        want.extend_from_slice(&4u16.to_be_bytes());
        want.extend_from_slice(b"ping");
        assert_eq!(new, want, "New 帧逐字节");

        // Keep 帧：同构但类型 0x02
        let keep = xudp_frame_keep(&target, b"pong").expect("Keep 帧");
        assert_eq!(keep[4], 0x02, "Keep 帧类型位");
        assert_eq!(&keep[..4], &new[..4], "元长/会话段同构");
        // opt/网络/地址/载荷长同构（载荷数据各异，不入比）
        assert_eq!(&keep[5..16], &new[5..16], "opt/地址/载荷长同构");

        // 载荷越界具名拒绝
        let big = vec![0u8; u16::MAX as usize + 1];
        assert!(xudp_frame_new(&target, &big).is_err());
    }

    #[test]
    fn xudp_read_frame_semantics() {
        let session = FlowTarget {
            host: "10.0.0.1".into(),
            port: 53,
            proto: TargetProto::Udp,
        };
        // Keep 带寻址（下行常规）：元长>4
        let mut wire = Vec::new();
        wire.extend_from_slice(&(5u16 + 7).to_be_bytes());
        wire.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x02]);
        wire.extend_from_slice(&xudp_encode_addr("10.9.9.9", 9999).expect("addr"));
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(b"abc");
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let got = rt.block_on(async {
            let mut r = &wire[..];
            xudp_read_frame(&mut r, &session, &mut [0u8; 64])
                .await
                .expect("读帧")
        });
        let (src, n) = got.expect("有载荷");
        assert_eq!((src.host.as_str(), src.port, n), ("10.9.9.9", 9999, 3));

        // Keep 无寻址（元长==4）：目标回落会话目标
        let mut wire4 = Vec::new();
        wire4.extend_from_slice(&4u16.to_be_bytes());
        wire4.extend_from_slice(&[0x00, 0x00, 0x02, 0x01]);
        wire4.extend_from_slice(&2u16.to_be_bytes());
        wire4.extend_from_slice(b"ok");
        let got4 = rt.block_on(async {
            let mut r = &wire4[..];
            xudp_read_frame(&mut r, &session, &mut [0u8; 64])
                .await
                .expect("读帧")
        });
        let (src4, n4) = got4.expect("有载荷");
        assert_eq!((src4.host.as_str(), src4.port, n4), ("10.0.0.1", 53, 2));

        // 3/4 = 会话收束（sing End / xray discard 容忍面）
        for status in [3u8, 4u8] {
            let wire_end = [0u8, 4, 0x00, 0x00, status, 0x00];
            let got_end = rt.block_on(async {
                let mut r = &wire_end[..];
                xudp_read_frame(&mut r, &session, &mut [0u8; 64]).await
            });
            assert!(
                matches!(got_end, Ok(None)),
                "状态 {status} 必须收束会话: {got_end:?}"
            );
        }

        // opt 0x02 = 对端故障具名
        let wire_err = [0u8, 4, 0x00, 0x00, 0x02, 0x02];
        let got_err = rt.block_on(async {
            let mut r = &wire_err[..];
            xudp_read_frame(&mut r, &session, &mut [0u8; 64]).await
        });
        assert!(got_err.is_err(), "opt error 必须报错");
    }

    #[test]
    fn vless_mux_request_header_no_address() {
        let uuid = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x2a, 0xb1, 0xe7, 0x1b, 0xf7, 0x5a, 0x1d,
            0xb7, 0xb3,
        ];
        let req = build_vless_mux_request(uuid);
        // 版本 + uuid16 + optlen0 + 命令 0x03——共 19B，无端口/地址段
        assert_eq!(req.len(), 19);
        assert_eq!(req[0], 0x00, "版本位");
        assert_eq!(&req[1..17], &uuid, "uuid 段");
        assert_eq!(req[17], 0x00, "optlen 位");
        assert_eq!(req[18], 0x03, "Mux 命令位");
    }
}
