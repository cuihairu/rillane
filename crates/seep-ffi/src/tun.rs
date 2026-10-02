//! TUN 最小数据通路（P3-4 demo 面）：ICMP echo 轮转。
//!
//! 线程模型：独占 `std::thread` + `poll(200ms)` 轮询——不进 tokio（tun fd
//! 非异步源；200ms 超时兜底让停止旗标可见，且不依赖 shutdown/close 语义，
//! 对真 TUN 字符设备同样成立）。TCP/UDP 真实代理路径随 P1-2 TunIngress
//! 接入，届时替换本模块的处理函数，轮询骨架与 C ABI 形状不变。

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Context;

/// 单包读上限（IP 报文理论上限）
const MAX_PACKET: usize = 65535;
/// poll 超时：停止旗标的最大可见延迟
const POLL_TICK_MS: i32 = 200;

/// 起 TUN 轮转线程；`read`/`write` 可为同一 fd 的两个句柄（真 TUN 双向），
/// 线程退出（stop 旗标或 fd 读尽/失效）时两者一并 drop（fd 归还内核）
pub(crate) fn spawn(
    read: std::fs::File,
    write: std::fs::File,
    stop: Arc<AtomicBool>,
    tun_fd: Arc<AtomicI32>,
) -> anyhow::Result<JoinHandle<()>> {
    let fd = read.as_raw_fd();
    std::thread::Builder::new()
        .name("seep-ffi-tun".into())
        .spawn(move || {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let mut pfds = [libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                // EINTR 重试（信号打断不算错）
                match unsafe { libc::poll(pfds.as_mut_ptr(), 1, POLL_TICK_MS) } {
                    n if n < 0 => {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        break;
                    }
                    0 => continue, // 超时：回看 stop 旗标
                    _ => {}
                }
                if pfds[0].revents & libc::POLLIN == 0 {
                    // POLLERR/POLLHUP：fd 失效（VpnService 撤销等），自然收尾
                    break;
                }
                let mut buf = vec![0u8; MAX_PACKET];
                match (&read).read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Some(reply) = echo_reply(&buf[..n]) {
                            // 下行写失败不致命（对端不收），继续读
                            let _ = (&write).write_all(&reply);
                        }
                    }
                }
            }
            tun_fd.store(-1, Ordering::Relaxed);
        })
        .context("起 TUN 线程失败")
}

/// ICMP echo 请求 → 应答（仅 echo；其余包静默丢弃）。
///
/// v4：重组整个包（地址互换 + ICMP type 8→0 + ICMP/IP 校验和重算）；
/// v6：不做扩展头遍历（next_header 直指 ICMPv6 才处理，demo 边界），
/// ICMPv6 校验和按伪首部重算。
pub fn echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 20 {
        return None;
    }
    match pkt[0] >> 4 {
        4 => echo_reply_v4(pkt),
        6 => echo_reply_v6(pkt),
        _ => None,
    }
}

fn echo_reply_v4(pkt: &[u8]) -> Option<Vec<u8>> {
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if !(20..=pkt.len()).contains(&ihl) {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len > pkt.len() || total_len < ihl + 8 {
        return None;
    }
    // proto 1 = ICMP；仅 echo request（type 8, code 0）
    if pkt[9] != 1 || pkt[ihl] != 8 || pkt[ihl + 1] != 0 {
        return None;
    }
    let mut reply = pkt[..total_len].to_vec();
    // 地址互换（对端视角回包）
    reply[12..16].copy_from_slice(&pkt[16..20]);
    reply[16..20].copy_from_slice(&pkt[12..16]);
    // ICMP：type 8→0，校验和重算（覆盖 icmp_off..total_len）
    reply[ihl] = 0;
    reply[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let icmp_sum = checksum(&reply[ihl..total_len]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    // IP 头校验和重算（覆盖 0..ihl）
    reply[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    Some(reply)
}

fn echo_reply_v6(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 {
        return None;
    }
    // 不做扩展头遍历（demo 边界，见模块注释）
    if pkt[6] != 58 {
        return None;
    }
    if pkt.len() < 48 || pkt[40] != 128 || pkt[41] != 0 {
        return None;
    }
    let mut reply = pkt.to_vec();
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[24..40]); // 原始 dst → 应答 src
    dst.copy_from_slice(&pkt[8..24]); // 原始 src → 应答 dst
    reply[8..24].copy_from_slice(&src);
    reply[24..40].copy_from_slice(&dst);
    reply[40] = 129; // echo reply
    reply[42..44].copy_from_slice(&[0, 0]);
    let sum = icmpv6_checksum(&src, &dst, &reply[40..]);
    reply[42..44].copy_from_slice(&sum.to_be_bytes());
    Some(reply)
}

/// RFC1071 因特网校验和（16 位反码求和）
fn checksum(data: &[u8]) -> u16 {
    let (chunks, remainder) = data.as_chunks::<2>();
    let mut sum = 0u32;
    for c in chunks {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if let [b] = remainder {
        sum += (*b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMPv6 校验和（伪首部：src + dst + 上层长度 + zero + next header 58）
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + icmp.len());
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
    buf.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 58]);
    buf.extend_from_slice(icmp);
    checksum(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::time::Duration;

    /// 组一个校验和合法的 IPv4 ICMP echo request
    fn build_v4_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4 ihl 5
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64; // ttl
        p[9] = 1; // icmp
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20] = 8; // echo request
        p[21] = 0;
        // echo 头布局：type(20) code(21) checksum(22..24) id(24..26) seq(26..28)
        p[24..26].copy_from_slice(&id.to_be_bytes());
        p[26..28].copy_from_slice(&seq.to_be_bytes());
        p[28..].copy_from_slice(payload);
        // ICMP 校验和（覆盖 20..total；checksum 字段 22..24 恒零后求和）
        let icmp_sum = checksum(&p[20..]);
        p[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
        let ip_sum = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        p
    }

    #[test]
    fn v4_echo_replies_with_swapped_addrs_and_valid_checksums() {
        let req = build_v4_echo([10, 111, 0, 1], [10, 111, 0, 2], 0xabcd, 7, b"seep");
        // 请求自身校验和合法（自证）
        let mut req_c = req.clone();
        req_c[22..24].copy_from_slice(&[0, 0]);
        assert_eq!(
            checksum(&req_c[20..]),
            u16::from_be_bytes([req[22], req[23]]),
            "测试夹具 ICMP 校验和应自洽"
        );
        let mut req_ip = req.clone();
        req_ip[10..12].copy_from_slice(&[0, 0]);
        assert_eq!(
            checksum(&req_ip[..20]),
            u16::from_be_bytes([req[10], req[11]]),
            "测试夹具 IP 校验和应自洽"
        );

        let reply = echo_reply(&req).expect("echo request 应得应答");
        assert_eq!(reply.len(), req.len());
        assert_eq!(reply[20], 0, "type 应为 echo reply");
        assert_eq!(&reply[12..16], &[10, 111, 0, 2], "src 应为原 dst");
        assert_eq!(&reply[16..20], &[10, 111, 0, 1], "dst 应为原 src");
        assert_eq!(&reply[28..], b"seep", "payload 原样保留");
        let mut csum = reply.clone();
        csum[22..24].copy_from_slice(&[0, 0]);
        assert_eq!(
            checksum(&csum[20..]),
            u16::from_be_bytes([reply[22], reply[23]])
        );
        let mut ip = reply.clone();
        ip[10..12].copy_from_slice(&[0, 0]);
        assert_eq!(
            checksum(&ip[..20]),
            u16::from_be_bytes([reply[10], reply[11]])
        );
    }

    #[test]
    fn v6_echo_replies_with_valid_icmpv6_checksum() {
        let src = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut p = vec![0u8; 40 + 8 + 4];
        p[0] = 0x60; // v6
        p[6] = 58; // icmpv6
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40] = 128; // echo request
        p[42..44].copy_from_slice(&[0, 0]);
        p[48..52].copy_from_slice(b"ping");
        let sum = icmpv6_checksum(&src, &dst, &p[40..]);
        p[42..44].copy_from_slice(&sum.to_be_bytes());

        let reply = echo_reply(&p).expect("v6 echo request 应得应答");
        assert_eq!(reply[40], 129);
        assert_eq!(&reply[8..24], &dst, "src 应为原 dst");
        assert_eq!(&reply[24..40], &src, "dst 应为原 src");
        let rsrc: [u8; 16] = reply[8..24].try_into().expect("src");
        let rdst: [u8; 16] = reply[24..40].try_into().expect("dst");
        let mut csum = reply.clone();
        csum[42..44].copy_from_slice(&[0, 0]);
        assert_eq!(
            icmpv6_checksum(&rsrc, &rdst, &csum[40..]),
            u16::from_be_bytes([reply[42], reply[43]])
        );
    }

    #[test]
    fn non_echo_packets_are_dropped() {
        // 截断包
        assert!(echo_reply(&[0x45, 0, 0]).is_none());
        // proto = TCP(6) 不处理
        let mut tcp = build_v4_echo([10, 0, 0, 1], [10, 0, 0, 2], 1, 1, b"x");
        tcp[9] = 6;
        assert!(echo_reply(&tcp).is_none());
        // ICMP 但非 echo request（type 0 = reply）
        let mut other = build_v4_echo([10, 0, 0, 1], [10, 0, 0, 2], 1, 1, b"x");
        other[20] = 0;
        assert!(echo_reply(&other).is_none());
        // v6 但 next_header 非 ICMPv6（TCP 6）
        let mut v6tcp = vec![0u8; 48];
        v6tcp[0] = 0x60;
        v6tcp[6] = 6;
        assert!(echo_reply(&v6tcp).is_none());
        // 未知版本
        assert!(echo_reply(&[0x20; 20]).is_none());
    }

    #[test]
    fn tun_loop_roundtrips_echo_over_unix_socketpair() {
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;
        use std::os::unix::net::UnixStream;

        let (mut a, b) = UnixStream::pair().expect("socketpair");
        a.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("读超时");
        b.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("读超时");

        // b 交给 FFI 层（所有权转移）；a 留在测试侧当“内核”
        let file = unsafe { std::fs::File::from_raw_fd(b.into_raw_fd()) };
        let writer = file.try_clone().expect("clone");
        let stop = Arc::new(AtomicBool::new(false));
        let tun_fd = Arc::new(AtomicI32::new(-1));
        let join = spawn(file, writer, stop.clone(), tun_fd.clone()).expect("起轮转");

        let req = build_v4_echo([10, 111, 0, 1], [10, 111, 0, 2], 0x1234, 1, b"roundtrip");
        a.write_all(&req).expect("写请求");

        let mut reply = vec![0u8; req.len()];
        a.read_exact(&mut reply).expect("读应答");
        let want = echo_reply(&req).expect("参照应答");
        assert_eq!(reply, want, "轮转线程应答应与纯函数一致");

        // 停止：旗标 → 线程 200ms 内退出、fd 观测面归 -1
        stop.store(true, Ordering::Relaxed);
        join.join().expect("join");
        assert_eq!(tun_fd.load(Ordering::Relaxed), -1);
    }
}
