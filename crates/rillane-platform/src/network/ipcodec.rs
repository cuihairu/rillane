//! IP/UDP/TCP 报文编解码纯函数（tun-dataplane.md §2.3 / §4.1）
//!
//! - [`parse_udp_datagram`]：TUN 上行 UDP 载荷提取——截断/非法长度/非首分片
//!   一律拒绝（E9：丢弃 + 计数，不中断流）；
//! - [`build_udp_packet`]：TUN 下行反向包构造（IP(src=dst,dst=src) + UDP 反头）
//!   —— IPv4 头/UDP 校验和真实现（RFC 1071），IPv6 UDP 校验和强制
//!   （0 非法 → 0xFFFF 兜底），TTL 64、DF 置位、IP id 外置自增、不分片；
//! - [`parse_tcp_segment`]：TUN 上行 TCP 段提取（§2.4 T4 分流判定用——五元组 +
//!   控制位 + 序号）——仅 IPv4（smoltcp 栈面 MVP 只开 proto-ipv4），截断/
//!   头长非法/非首分片一律拒绝；
//! - [`build_tcp_packet`]：测试/回环侧 TCP 段构造（IPv4 头 + 伪首部校验和全现），
//!   供 §4.1 无特权全路径测试扮演本机应用；
//! - 校验和真值向量（§4.1 golden）由独立 Python 参考实现预生成，钉死字节面。
//!
//! 纯函数、无 IO、无平台依赖——单测任何环境可跑（§4.1 无特权面）。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

use super::ports::{IpProtocol, PacketMeta};

/// RFC 1071 互联网校验和（ones-complement）：偶数对齐求和、奇数补 0、
/// 折返进位、取反。含校验和字段在内的整段求和应得 0xFFFF（验证口径）。
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 已解析的上行 UDP 数据报（载荷借用输入缓冲，零拷贝）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

/// 解析 TUN 上行包为 UDP 数据报（仅 IPv4/IPv6 + UDP；扩展头/分片拒绝）
pub fn parse_udp_datagram(pkt: &[u8]) -> Result<UdpDatagram<'_>> {
    if pkt.is_empty() {
        bail!("空数据包");
    }
    match pkt[0] >> 4 {
        4 => parse_v4_udp(pkt),
        6 => parse_v6_udp(pkt),
        v => bail!("不支持的 IP 版本 {v}"),
    }
}

fn parse_v4_udp(pkt: &[u8]) -> Result<UdpDatagram<'_>> {
    if pkt.len() < 20 {
        bail!("IPv4 包头太短（{} 字节 < 20）", pkt.len());
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    if ihl < 20 {
        bail!("IPv4 IHL 非法：{}（<20 字节）", pkt[0] & 0x0F);
    }
    if pkt.len() < ihl {
        bail!("IPv4 包头截断：IHL 需 {ihl} 字节，实收 {} 字节", pkt.len());
    }
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total < ihl + 8 {
        bail!("IPv4 总长 {total} 不足 IP 头({ihl})+UDP 头(8)");
    }
    if total > pkt.len() {
        bail!("IPv4 截断：总长 {total} 字节 > 实收 {} 字节", pkt.len());
    }
    // 分片面：MF 置位或分片偏移非零 = 非首分片 → 拒绝（E9；DF 不算分片）
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x3FFF != 0 {
        bail!("非首分片/带 MF 分片不支持（flags={frag:#06x}）");
    }
    if pkt[9] != 17 {
        bail!("非 UDP 协议号 {}", pkt[9]);
    }
    let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let udp = &pkt[ihl..total];
    let ulen = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if ulen < 8 {
        bail!("UDP 长度 {ulen} < 8");
    }
    if ihl + ulen > total {
        bail!("UDP 长度 {ulen} 越出 IPv4 总长 {total}");
    }
    Ok(UdpDatagram {
        src,
        dst,
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..ulen],
    })
}

fn parse_v6_udp(pkt: &[u8]) -> Result<UdpDatagram<'_>> {
    if pkt.len() < 40 {
        bail!("IPv6 包头太短（{} 字节 < 40）", pkt.len());
    }
    if pkt[6] != 17 {
        bail!("IPv6 下一跳头 {}（非 UDP；扩展头 MVP 不支持）", pkt[6]);
    }
    let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if plen < 8 {
        bail!("IPv6 载荷长 {plen} 不足 UDP 头(8)");
    }
    if 40 + plen > pkt.len() {
        bail!("IPv6 截断：40+{plen} 字节 > 实收 {} 字节", pkt.len());
    }
    let mut s16 = [0u8; 16];
    s16.copy_from_slice(&pkt[8..24]);
    let mut d16 = [0u8; 16];
    d16.copy_from_slice(&pkt[24..40]);
    let udp = &pkt[40..40 + plen];
    let ulen = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if ulen < 8 {
        bail!("UDP 长度 {ulen} < 8");
    }
    if ulen > plen {
        bail!("UDP 长度 {ulen} 越出 IPv6 载荷长 {plen}");
    }
    Ok(UdpDatagram {
        src: IpAddr::V6(Ipv6Addr::from(s16)),
        dst: IpAddr::V6(Ipv6Addr::from(d16)),
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..ulen],
    })
}

/// 构造下行反向 IP+UDP 包（§2.3）：src/dst 由调用方按五元组对调给出。
/// IPv4：真实头校验和 + DF + TTL 64 + 外置 ip_id；IPv6：UDP 校验和强制。
pub fn build_udp_packet(
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    payload: &[u8],
    ip_id: u16,
) -> Result<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => build_v4_udp(s, d, sport, dport, payload, ip_id),
        (IpAddr::V6(s), IpAddr::V6(d)) => build_v6_udp(s, d, sport, dport, payload),
        _ => bail!("src/dst IP 版本不一致或混合（{src} → {dst}）"),
    }
}

fn build_v4_udp(
    s: Ipv4Addr,
    d: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
    ip_id: u16,
) -> Result<Vec<u8>> {
    let ulen = 8 + payload.len();
    let total = 20 + ulen;
    if total > usize::from(u16::MAX) {
        bail!("IPv4 下行包超长：{total} 字节");
    }
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[0x45, 0x00]); // ver/ihl、TOS
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&ip_id.to_be_bytes());
    pkt.extend_from_slice(&[0x40, 0x00]); // DF 置位、不分片
    pkt.push(64); // TTL
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // 头校验和占位
    pkt.extend_from_slice(&s.octets());
    pkt.extend_from_slice(&d.octets());
    let hc = internet_checksum(&pkt);
    pkt[10..12].copy_from_slice(&hc.to_be_bytes());

    let mut udp = Vec::with_capacity(ulen);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(ulen as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]); // 校验和占位
    udp.extend_from_slice(payload);
    let uc = udp_checksum_v4(s, d, &udp);
    udp[6..8].copy_from_slice(&uc.to_be_bytes());
    pkt.extend_from_slice(&udp);
    Ok(pkt)
}

fn build_v6_udp(
    s: Ipv6Addr,
    d: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let ulen = 8 + payload.len();
    if ulen > usize::from(u16::MAX) {
        bail!("IPv6 UDP 长度超限：{ulen}");
    }
    let mut pkt = Vec::with_capacity(40 + ulen);
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // 版本 6 + 流标签 0
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes()); // 载荷长（= UDP 长）
    pkt.push(17); // 下一跳头 = UDP
    pkt.push(64); // 跳数
    pkt.extend_from_slice(&s.octets());
    pkt.extend_from_slice(&d.octets());

    let mut udp = Vec::with_capacity(ulen);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(ulen as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(payload);
    let uc = udp_checksum_v6(s, d, &udp);
    udp[6..8].copy_from_slice(&uc.to_be_bytes());
    pkt.extend_from_slice(&udp);
    Ok(pkt)
}

/// IPv4 UDP 校验和（伪首部 + UDP 头/载荷；校验和字段须已置 0）。
/// RFC 768：计算结果为 0 时以全 1 发送（0 在 UDP 校验和中表示"未校验"）。
fn udp_checksum_v4(s: Ipv4Addr, d: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + udp.len());
    buf.extend_from_slice(&s.octets());
    buf.extend_from_slice(&d.octets());
    buf.push(0x00);
    buf.push(17);
    buf.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    buf.extend_from_slice(udp);
    match internet_checksum(&buf) {
        0 => 0xFFFF,
        c => c,
    }
}

/// IPv6 UDP 校验和（RFC 8200 强制；伪首部带 32 位 UDP 长 + 下一跳头）
fn udp_checksum_v6(s: Ipv6Addr, d: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + udp.len());
    buf.extend_from_slice(&s.octets());
    buf.extend_from_slice(&d.octets());
    buf.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 17]);
    buf.extend_from_slice(udp);
    match internet_checksum(&buf) {
        0 => 0xFFFF,
        c => c,
    }
}

/// 已解析的上行 TCP 段（IPv4；载荷借用输入缓冲，零拷贝）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
    pub psh: bool,
    pub payload: &'a [u8],
}

/// TCP 控制位（构造面：[`build_tcp_packet`] 入参；与解析面字段镜像）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    pub const SYN: Self = Self {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: false,
    };
    pub const SYN_ACK: Self = Self {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: true,
    };
    pub const ACK: Self = Self {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: true,
    };
    pub const PSH_ACK: Self = Self {
        fin: false,
        syn: false,
        rst: false,
        psh: true,
        ack: true,
    };
    pub const FIN_ACK: Self = Self {
        fin: true,
        syn: false,
        rst: false,
        psh: false,
        ack: true,
    };

    fn to_byte(self) -> u8 {
        u8::from(self.fin)
            | (u8::from(self.syn) << 1)
            | (u8::from(self.rst) << 2)
            | (u8::from(self.psh) << 3)
            | (u8::from(self.ack) << 4)
    }
}

/// 解析 TUN 上行包为 TCP 段（仅 IPv4；扩展选项载荷按数据偏移切分）。
/// 非 TCP/截断/头长非法/分片一律 Err——调用方计 parse_errors 丢弃（E9）。
pub fn parse_tcp_segment(pkt: &[u8]) -> Result<TcpSegment<'_>> {
    if pkt.is_empty() {
        bail!("空数据包");
    }
    if pkt[0] >> 4 != 4 {
        bail!(
            "非 IPv4 TCP 段（版本 {}——T4 MVP 栈面仅 proto-ipv4）",
            pkt[0] >> 4
        );
    }
    if pkt.len() < 20 {
        bail!("IPv4 包头太短（{} 字节 < 20）", pkt.len());
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    if ihl < 20 {
        bail!("IPv4 IHL 非法：{}（<20 字节）", pkt[0] & 0x0F);
    }
    if pkt.len() < ihl {
        bail!("IPv4 包头截断：IHL 需 {ihl} 字节，实收 {} 字节", pkt.len());
    }
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total < ihl + 20 {
        bail!("IPv4 总长 {total} 不足 IP 头({ihl})+TCP 头(20)");
    }
    if total > pkt.len() {
        bail!("IPv4 截断：总长 {total} 字节 > 实收 {} 字节", pkt.len());
    }
    // 分片面同 UDP：MF 置位或分片偏移非零 = 非首分片 → 拒绝（DF 不算分片）
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x3FFF != 0 {
        bail!("非首分片/带 MF 分片不支持（flags={frag:#06x}）");
    }
    if pkt[9] != 6 {
        bail!("非 TCP 协议号 {}", pkt[9]);
    }
    let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let tcp = &pkt[ihl..total];
    let data_off = usize::from(tcp[12] >> 4) * 4;
    if data_off < 20 {
        bail!("TCP 数据偏移非法：{}（<20 字节）", tcp[12] >> 4);
    }
    if tcp.len() < data_off {
        bail!(
            "TCP 头截断：偏移需 {data_off} 字节，实收 {} 字节",
            tcp.len()
        );
    }
    let flags = tcp[13];
    Ok(TcpSegment {
        src,
        dst,
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack_seq: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
        fin: flags & 0x01 != 0,
        psh: flags & 0x08 != 0,
        payload: &tcp[data_off..],
    })
}

/// 构造 IPv4 TCP 段（测试/回环面：§4.1 无特权全路径测试扮演本机应用）。
/// 头校验和 + 伪首部校验和（RFC 9293 同 RFC 768 口径）真实现；TTL 64、DF、
/// 固定窗口 65535、无选项（数据偏移 5）。IPv6 形 MVP 不支持（栈面同口径）。
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack_seq: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let tlen = 20 + payload.len();
    let total = 20 + tlen;
    if total > usize::from(u16::MAX) {
        bail!("IPv4 TCP 包超长：{total} 字节");
    }
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[0x45, 0x00]); // ver/ihl、TOS
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // ip id
    pkt.extend_from_slice(&[0x40, 0x00]); // DF 置位、不分片
    pkt.push(64); // TTL
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // 头校验和占位
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let hc = internet_checksum(&pkt);
    pkt[10..12].copy_from_slice(&hc.to_be_bytes());

    let mut tcp = Vec::with_capacity(tlen);
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack_seq.to_be_bytes());
    tcp.push(0x50); // 数据偏移 5（20 字节，无选项）
    tcp.push(flags.to_byte());
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // 窗口
    tcp.extend_from_slice(&[0x00, 0x00]); // 校验和占位
    tcp.extend_from_slice(&[0x00, 0x00]); // 紧急指针
    tcp.extend_from_slice(payload);
    let tc = tcp_checksum_v4(src, dst, &tcp);
    tcp[16..18].copy_from_slice(&tc.to_be_bytes());
    pkt.extend_from_slice(&tcp);
    Ok(pkt)
}

/// IPv4 TCP 校验和（伪首部同 UDP 口径但协议号 6；TCP 校验和 0 是合法值——
/// 无 0xFFFF 兜底）。
fn tcp_checksum_v4(s: Ipv4Addr, d: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp.len());
    buf.extend_from_slice(&s.octets());
    buf.extend_from_slice(&d.octets());
    buf.push(0x00);
    buf.push(6);
    buf.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp);
    internet_checksum(&buf)
}

// ---------------------------------------------------------------------------
// L3 整包元数据解析（RIL-033 自 takeover 搬移：OS-free 纯函数，Linux/
// Windows 捕获端口共用）
// ---------------------------------------------------------------------------

/// 从 L3 整包解析 IP 三元组（双栈）：IPv4（IHL 弹性头长）与 IPv6（固定
/// 40 字节主头）→ PacketMeta。协议映射 6→Tcp、17→Udp（QUIC/DNS 同面
/// 原样过）、1/58→Icmp、其余→Other(号)。坏版本/截断头显式报错不猜。
pub fn parse_packet_meta(packet: &[u8]) -> io::Result<PacketMeta> {
    let bad = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());
    if packet.is_empty() {
        return Err(bad("空包"));
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(bad("IPv4 头截断"));
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 || ihl > packet.len() {
                return Err(bad("IPv4 IHL 越界"));
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Ok(PacketMeta {
                src: src.into(),
                dst: dst.into(),
                protocol: map_ip_proto(packet[9]),
            })
        }
        6 => {
            if packet.len() < 40 {
                return Err(bad("IPv6 头截断"));
            }
            let u16_at = |i: usize| u16::from_be_bytes([packet[i], packet[i + 1]]);
            let src = Ipv6Addr::new(
                u16_at(8),
                u16_at(10),
                u16_at(12),
                u16_at(14),
                u16_at(16),
                u16_at(18),
                u16_at(20),
                u16_at(22),
            );
            let dst = Ipv6Addr::new(
                u16_at(24),
                u16_at(26),
                u16_at(28),
                u16_at(30),
                u16_at(32),
                u16_at(34),
                u16_at(36),
                u16_at(38),
            );
            Ok(PacketMeta {
                src: src.into(),
                dst: dst.into(),
                protocol: map_ip_proto(packet[6]),
            })
        }
        v => Err(bad(&format!("未知 IP 版本 {v}"))),
    }
}

/// 协议号 → 中立枚举（v4/v6 共用：58 = ICMPv6）
fn map_ip_proto(n: u8) -> IpProtocol {
    match n {
        6 => IpProtocol::Tcp,
        17 => IpProtocol::Udp,
        1 | 58 => IpProtocol::Icmp,
        other => IpProtocol::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_GOLDEN: &str = "450000201c46400040110e74010203040506070804d20035000c25f561626364";
    const V6_GOLDEN: &str =
        "60000000000c114020010db800000000000000000000000120010db800000000000000000000000204d214e9000cc5df61626364";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// §4.1 golden：独立 Python 参考实现预生成的 IPv4 UDP 下行包字节面
    /// （1.2.3.4:1234 → 5.6.7.8:53，载荷 "abcd"，ip_id=0x1c46）+ 头校验和
    /// 复验 + 解析往返。
    #[test]
    fn golden_v4_udp_packet_bytes() {
        let pkt = build_udp_packet(
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            1234,
            53,
            b"abcd",
            0x1c46,
        )
        .expect("build");
        assert_eq!(pkt, unhex(V4_GOLDEN), "v4 下行包字节面应与真值向量一致");
        // 头校验和复验：含字段整段求和取反 = 0
        assert_eq!(internet_checksum(&pkt[..20]), 0x0000, "IPv4 头校验和应自洽");
        // 解析往返
        let d = parse_udp_datagram(&pkt).expect("parse");
        assert_eq!(d.src, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(d.dst, "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!((d.sport, d.dport), (1234, 53));
        assert_eq!(d.payload, b"abcd");
    }

    /// §4.1 golden：IPv6 UDP 下行包字节面（2001:db8::1 → 2001:db8::2）
    /// + UDP 校验和伪首部复验 + 解析往返。
    #[test]
    fn golden_v6_udp_packet_bytes() {
        let pkt = build_udp_packet(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            1234,
            5353,
            b"abcd",
            0,
        )
        .expect("build");
        assert_eq!(pkt, unhex(V6_GOLDEN), "v6 下行包字节面应与真值向量一致");
        // UDP 校验和复验：伪首部 + UDP 段（含字段）整段求和取反 = 0
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&pkt[8..24]); // src
        pseudo.extend_from_slice(&pkt[24..40]); // dst
        pseudo.extend_from_slice(&12u32.to_be_bytes()); // UDP 长（32 位）
        pseudo.extend_from_slice(&[0x00, 0x00, 0x00, 17]); // 保留 + 下一跳头
        pseudo.extend_from_slice(&pkt[40..]);
        assert_eq!(internet_checksum(&pseudo), 0x0000, "v6 UDP 校验和应自洽");

        let d = parse_udp_datagram(&pkt).expect("parse");
        assert_eq!(d.src, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(d.dst, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!((d.sport, d.dport), (1234, 5353));
        assert_eq!(d.payload, b"abcd");
    }

    /// v4 校验和通用复验：多长度 payload 构造的包——IP 头校验和自洽 +
    /// 伪首部叠 UDP 段（含校验和字段）求和取反为 0 + 解析往返（§4.1）。
    #[test]
    fn v4_udp_checksum_self_consistent_for_varied_payloads() {
        for len in [0usize, 1, 3, 7, 32] {
            let payload: Vec<u8> = (0..len as u8).collect();
            let pkt = build_udp_packet(
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                40000,
                9999,
                &payload,
                len as u16,
            )
            .expect("build");
            assert_eq!(internet_checksum(&pkt[..20]), 0, "IP 头校验和");

            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&pkt[12..20]); // v4 伪首部 = src || dst
            pseudo.push(0x00);
            pseudo.push(17);
            pseudo.extend_from_slice(&pkt[24..26]); // UDP 长（网络序两字节）
            pseudo.extend_from_slice(&pkt[20..]);
            assert_eq!(internet_checksum(&pseudo), 0, "len={len} UDP 校验和自洽");

            let d = parse_udp_datagram(&pkt).expect("parse");
            assert_eq!(d.payload, payload.as_slice());
        }
    }

    /// 校验和为 0 时按 RFC 768 以 0xFFFF 发送的兜底分支（0 = 未校验，歧义面）
    /// ——扫描双字节 payload 找到使原始和取反为 0 的入参，钉死分支行为。
    #[test]
    fn udp_checksum_zero_maps_to_ffff() {
        let s: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let d: Ipv4Addr = "192.0.2.2".parse().unwrap();
        let mut hit = false;
        for i in 0..=0xFFFFu32 {
            let payload = [(i >> 8) as u8, i as u8];
            let mut udp = Vec::new();
            udp.extend_from_slice(&1u16.to_be_bytes());
            udp.extend_from_slice(&2u16.to_be_bytes());
            udp.extend_from_slice(&10u16.to_be_bytes());
            udp.extend_from_slice(&[0, 0]);
            udp.extend_from_slice(&payload);
            if internet_checksum(&pseudo_v4(&s, &d, &udp)) == 0 {
                // 折返和 0xFFFF → 取反 0 → 实现须发 0xFFFF 而非 0
                assert_eq!(udp_checksum_v4(s, d, &udp), 0xFFFF, "0 → 0xFFFF 兜底");
                hit = true;
                break;
            }
        }
        assert!(hit, "65536 扫描内必命中原始校验和为 0 的入参");
    }

    fn pseudo_v4(s: &Ipv4Addr, d: &Ipv4Addr, udp: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&s.octets());
        buf.extend_from_slice(&d.octets());
        buf.push(0x00);
        buf.push(17);
        buf.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        buf.extend_from_slice(udp);
        buf
    }

    /// 截断与非法输入拒绝面（§4.1：E9 丢弃口径的纯函数半边）
    #[test]
    fn truncated_and_invalid_inputs_rejected() {
        // 空包 / 版本未知
        assert!(parse_udp_datagram(&[]).is_err());
        let e = parse_udp_datagram(&[0x30; 40]).unwrap_err();
        assert!(e.to_string().contains("不支持的 IP 版本"), "{e}");

        // v4 包头截断
        assert!(parse_udp_datagram(&[0x45; 10]).is_err());
        // v4 IHL 非法（ihl=4 < 5）
        let mut ihl_bad = vec![0x44; 40];
        ihl_bad[2] = 0;
        ihl_bad[3] = 40;
        assert!(parse_udp_datagram(&ihl_bad).is_err());
        // 总长 > 实收（截断）
        let mut trunc = unhex(V4_GOLDEN);
        trunc.truncate(30);
        let e = parse_udp_datagram(&trunc).unwrap_err();
        assert!(e.to_string().contains("截断"), "{e}");
        // MF 分片拒绝（flags 字节 0x20 = MF）
        let mut frag = unhex(V4_GOLDEN);
        frag[6] = 0x20;
        let e = parse_udp_datagram(&frag).unwrap_err();
        assert!(e.to_string().contains("分片"), "{e}");
        // 非 UDP 协议号
        let mut tcpish = unhex(V4_GOLDEN);
        tcpish[9] = 6;
        let e = parse_udp_datagram(&tcpish).unwrap_err();
        assert!(e.to_string().contains("非 UDP"), "{e}");

        // v6 截断 / 下一跳头非 UDP / 载荷长越界
        assert!(parse_udp_datagram(&[0x60; 30]).is_err());
        let mut ext = unhex(V6_GOLDEN);
        ext[6] = 0;
        let e = parse_udp_datagram(&ext).unwrap_err();
        assert!(e.to_string().contains("下一跳头"), "{e}");
        let mut short = unhex(V6_GOLDEN);
        short.truncate(45);
        assert!(parse_udp_datagram(&short).is_err());

        // 版本混合构造拒绝
        let err = build_udp_packet(
            "1.2.3.4".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            1,
            2,
            b"x",
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("版本不一致"), "{err}");
    }

    /// TCP 段构造→解析往返：五元组/序号/控制位/载荷真值 + IPv4 头与
    /// TCP 伪首部校验和自洽（§4.1 T4 面）
    #[test]
    fn tcp_segment_roundtrip_and_checksums() {
        let pkt = build_tcp_packet(
            "10.66.0.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            40000,
            8080,
            0xDEAD_BEEF,
            0x0102_0304,
            TcpFlags::PSH_ACK,
            b"hello",
        )
        .expect("build");
        assert_eq!(internet_checksum(&pkt[..20]), 0x0000, "IPv4 头校验和自洽");

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&pkt[12..20]); // v4 伪首部 = src || dst
        pseudo.push(0x00);
        pseudo.push(6);
        pseudo.extend_from_slice(&(25u16).to_be_bytes()); // TCP 段长 20+5
        pseudo.extend_from_slice(&pkt[20..]);
        assert_eq!(internet_checksum(&pseudo), 0x0000, "TCP 校验和自洽");

        let seg = parse_tcp_segment(&pkt).expect("parse");
        assert_eq!(seg.src, "10.66.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(seg.dst, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!((seg.sport, seg.dport), (40000, 8080));
        assert_eq!((seg.seq, seg.ack_seq), (0xDEAD_BEEF, 0x0102_0304));
        assert!(seg.psh && seg.ack && !seg.syn && !seg.fin && !seg.rst);
        assert_eq!(seg.payload, b"hello");

        // 握手控制位形（SYN / SYN-ACK / 纯 ACK / FIN-ACK）
        let syn = build_tcp_packet(
            "10.66.0.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            40001,
            443,
            1000,
            0,
            TcpFlags::SYN,
            b"",
        )
        .unwrap();
        let s = parse_tcp_segment(&syn).unwrap();
        assert!(s.syn && !s.ack && s.payload.is_empty());
        let flags = [
            TcpFlags::SYN_ACK,
            TcpFlags::ACK,
            TcpFlags::FIN_ACK,
            TcpFlags::default(),
        ];
        assert_eq!(flags[0].to_byte(), 0x12);
        assert_eq!(flags[1].to_byte(), 0x10);
        assert_eq!(flags[2].to_byte(), 0x11);
        assert_eq!(flags[3].to_byte(), 0x00);
    }

    /// TCP 解析拒绝面（§4.1：E9 丢弃口径纯函数半边）
    #[test]
    fn tcp_parse_rejects_invalid() {
        // 空包 / 非 IPv4（v6 段）
        assert!(parse_tcp_segment(&[]).is_err());
        let mut v6 = build_v6_udp(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            1,
            2,
            b"x",
        )
        .unwrap();
        v6[6] = 6; // 下一跳头改 TCP——版本 6 仍应先被版本门拒
        let e = parse_tcp_segment(&v6).unwrap_err();
        assert!(e.to_string().contains("非 IPv4"), "{e}");

        // 非 TCP 协议号
        let mut udpish = build_tcp_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            2,
            0,
            0,
            TcpFlags::ACK,
            b"",
        )
        .unwrap();
        udpish[9] = 17;
        let e = parse_tcp_segment(&udpish).unwrap_err();
        assert!(e.to_string().contains("非 TCP"), "{e}");

        // 截断（总长 > 实收）
        let mut trunc = build_tcp_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            2,
            0,
            0,
            TcpFlags::ACK,
            b"abcdef",
        )
        .unwrap();
        trunc.truncate(35);
        assert!(parse_tcp_segment(&trunc)
            .unwrap_err()
            .to_string()
            .contains("截断"));

        // TCP 数据偏移非法（12 字节高半字节 = 4 → 16 < 20）
        let mut bad_off = build_tcp_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            2,
            0,
            0,
            TcpFlags::ACK,
            b"",
        )
        .unwrap();
        bad_off[32] = 0x40;
        let e = parse_tcp_segment(&bad_off).unwrap_err();
        assert!(e.to_string().contains("数据偏移"), "{e}");

        // 非首分片拒绝（同 UDP 口径）
        let mut frag = build_tcp_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            2,
            0,
            0,
            TcpFlags::ACK,
            b"",
        )
        .unwrap();
        frag[6] = 0x20;
        assert!(parse_tcp_segment(&frag)
            .unwrap_err()
            .to_string()
            .contains("分片"));
    }

    /// 奇数长度载荷（校验和补 0 对齐）与空载荷往返；v4/v6 双栈
    #[test]
    fn odd_and_empty_payload_roundtrip() {
        for payload in [&b""[..], b"a", b"odd-payload"] {
            for (src, dst) in [("10.1.2.3", "10.4.5.6"), ("fd00::1", "fd00::2")] {
                let pkt =
                    build_udp_packet(src.parse().unwrap(), dst.parse().unwrap(), 1, 2, payload, 7)
                        .expect("build");
                let d = parse_udp_datagram(&pkt).expect("parse");
                assert_eq!(d.payload, payload, "src={src} dst={dst}");
            }
        }
    }
}
