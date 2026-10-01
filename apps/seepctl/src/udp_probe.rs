//! P0-5 §3.3：`seepctl udp-probe` 核心逻辑——最小 RFC 1928 UDP ASSOCIATE 客户端
//! （收口 P0-2「标准 CLI 联调」遗留：curl 走 TCP、dig 无代理面、proxychains 依赖
//! 系统栈不可控）。clap 接线与退出码映射在 main.rs；本模块函数签名收
//! `&str`/`Duration` 参数，测试直调同一函数（§10-S5）。
//!
//! 数据报头编解码复用 seep-core 的 `encode_udp_header`/`parse_udp_header`
//! （与数据面同一份 RFC 1928 §7 实现，避免两套头漂移；TCP 帧前 4 字节为
//! VER CMD RSV ATYP，与 UDP 头不同，另行拼装）。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use seep_core::udp::{encode_udp_header, parse_udp_header};
use seep_core::{FlowTarget, TargetProto};

/// 成功结果（§9-3 退出码 0：源地址与载荷长度；RTT 一并回填）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOk {
    pub rtt: Duration,
    /// 回包源（SOCKS5 头解析出的 host:port）
    pub source: String,
    pub payload_len: usize,
}

/// 失败分类（§9-3 退出码表 1–4；main.rs 只做映射不做判别）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// TCP 连接 / SOCKS5 握手 / 认证失败（阶段与 IO 错误）→ 1
    Connect(String),
    /// ASSOCIATE 被拒（REP 0x01/0x07）→ 2
    Rejected { rep: u8, detail: String },
    /// 超时无回包（附带已发出字节数）→ 3
    Timeout { sent_bytes: usize },
    /// 回包包头解析失败（解码错误）→ 4
    BadReply(String),
}

impl ProbeError {
    /// §9-3 退出码映射
    pub fn exit_code(&self) -> i32 {
        match self {
            ProbeError::Connect(_) => 1,
            ProbeError::Rejected { .. } => 2,
            ProbeError::Timeout { .. } => 3,
            ProbeError::BadReply(_) => 4,
        }
    }

    /// stderr 附带信息（§9-3 第三列）
    pub fn detail(&self) -> String {
        match self {
            ProbeError::Connect(m) | ProbeError::BadReply(m) => m.clone(),
            ProbeError::Rejected { detail, .. } => detail.clone(),
            ProbeError::Timeout { sent_bytes } => format!("已发出 {sent_bytes} 字节"),
        }
    }
}

/// REP 码语义（§9-3：0x07 = 入口未开 UDP）
fn rep_detail(rep: u8) -> String {
    match rep {
        0x01 => "通用 ASSOCIATE 失败（REP 0x01）".to_string(),
        0x07 => "入口未开 UDP（REP 0x07）".to_string(),
        other => format!("ASSOCIATE 被拒（REP 0x{other:02x}）"),
    }
}

/// 目标地址的 ATYP 分派（与 `encode_udp_header` 同判型：v4 / v6 / 域名）
fn target_addr_bytes(host: &str) -> (u8, Vec<u8>) {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        (0x01, v4.octets().to_vec())
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        (0x04, v6.octets().to_vec())
    } else {
        (0x03, host.as_bytes().to_vec())
    }
}

/// 完整探测流程（§3.3）：TCP 协商 → ASSOCIATE → 头封装发查询 → 等回包 → RTT。
/// 认证只支持无认证（METHOD 0x00）与用户名/密码法（METHOD 0x02），与入口
/// 现有能力对齐，不做扩展协商。
pub async fn run(
    socks5: &str,
    host: &str,
    port: u16,
    payload: &[u8],
    timeout: Duration,
    auth: Option<(&str, &str)>,
) -> Result<ProbeOk, ProbeError> {
    let socks_addr: SocketAddr = socks5
        .parse()
        .map_err(|e| ProbeError::Connect(format!("socks5 地址无法解析（{socks5}）: {e}")))?;

    // 1. TCP 连接 + 方法协商
    let mut ctrl = TcpStream::connect(socks_addr)
        .await
        .map_err(|e| ProbeError::Connect(format!("TCP 连接失败（{socks5}）: {e}")))?;
    let methods: &[u8] = if auth.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend_from_slice(methods);
    ctrl.write_all(&hello)
        .await
        .map_err(|e| ProbeError::Connect(format!("发送方法协商失败: {e}")))?;
    let mut m = [0u8; 2];
    ctrl.read_exact(&mut m)
        .await
        .map_err(|e| ProbeError::Connect(format!("读取方法应答失败: {e}")))?;
    match m[1] {
        0x00 => {}
        0x02 => {
            let Some((user, pass)) = auth else {
                return Err(ProbeError::Connect(
                    "入口要求用户名/密码认证但未提供 --user/--pass".into(),
                ));
            };
            // RFC 1929 子协商：VER(0x01) ULEN USER PLEN PASS
            let mut sub = vec![0x01, user.len() as u8];
            sub.extend_from_slice(user.as_bytes());
            sub.push(pass.len() as u8);
            sub.extend_from_slice(pass.as_bytes());
            ctrl.write_all(&sub)
                .await
                .map_err(|e| ProbeError::Connect(format!("发送认证请求失败: {e}")))?;
            let mut st = [0u8; 2];
            ctrl.read_exact(&mut st)
                .await
                .map_err(|e| ProbeError::Connect(format!("读取认证应答失败: {e}")))?;
            if st[1] != 0x00 {
                return Err(ProbeError::Connect(format!(
                    "认证失败（状态 0x{:02x}）",
                    st[1]
                )));
            }
        }
        other => {
            return Err(ProbeError::Connect(format!(
                "入口不接受可用认证方法（0x{other:02x}）"
            )))
        }
    }

    // 2. ASSOCIATE（TCP 帧：VER CMD(0x03) RSV ATYP ADDR PORT；DST 填探测目标）
    let (atyp, addr) = target_addr_bytes(host);
    let mut req = vec![0x05, 0x03, 0x00, atyp];
    if atyp == 0x03 {
        req.push(addr.len() as u8);
    }
    req.extend_from_slice(&addr);
    req.extend_from_slice(&port.to_be_bytes());
    ctrl.write_all(&req)
        .await
        .map_err(|e| ProbeError::Connect(format!("发送 ASSOCIATE 失败: {e}")))?;
    let mut rh = [0u8; 4];
    ctrl.read_exact(&mut rh)
        .await
        .map_err(|e| ProbeError::Connect(format!("读取 ASSOCIATE 应答失败: {e}")))?;
    if rh[1] != 0x00 {
        return Err(ProbeError::Rejected {
            rep: rh[1],
            detail: rep_detail(rh[1]),
        });
    }
    let bnd: SocketAddr = match rh[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            ctrl.read_exact(&mut rest)
                .await
                .map_err(|e| ProbeError::Connect(format!("读取 BND 失败: {e}")))?;
            SocketAddr::from((
                std::net::Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]),
                u16::from_be_bytes([rest[4], rest[5]]),
            ))
        }
        0x04 => {
            let mut rest = [0u8; 18];
            ctrl.read_exact(&mut rest)
                .await
                .map_err(|e| ProbeError::Connect(format!("读取 BND 失败: {e}")))?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&rest[..16]);
            SocketAddr::from((
                std::net::Ipv6Addr::from(o),
                u16::from_be_bytes([rest[16], rest[17]]),
            ))
        }
        other => {
            return Err(ProbeError::Connect(format!(
                "BND ATYP 不支持: 0x{other:02x}"
            )))
        }
    };
    // RFC 1928 惯例：BND 0.0.0.0 表示「用你连进来的这个地址」
    let relay = if bnd.ip().is_unspecified() {
        SocketAddr::new(socks_addr.ip(), bnd.port())
    } else {
        bnd
    };

    // 3. UDP 头封装发查询 → 等回包（RTT 自发送起算）
    let target = FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Udp,
    };
    let bind = if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let udp = UdpSocket::bind(bind)
        .await
        .map_err(|e| ProbeError::Connect(format!("本地 UDP bind 失败: {e}")))?;
    let mut frame = encode_udp_header(&target, payload.len());
    frame.extend_from_slice(payload);
    let started = Instant::now();
    udp.send_to(&frame, relay)
        .await
        .map_err(|e| ProbeError::Connect(format!("UDP 发送失败: {e}")))?;
    let sent_bytes = frame.len();

    let mut rx = vec![0u8; 65535];
    let n = match tokio::time::timeout(timeout, udp.recv_from(&mut rx)).await {
        Ok(Ok((n, _))) => n,
        Ok(Err(e)) => return Err(ProbeError::Connect(format!("UDP 接收失败: {e}"))),
        Err(_) => return Err(ProbeError::Timeout { sent_bytes }),
    };
    let rtt = started.elapsed();

    let (parsed, hlen) = parse_udp_header(&rx[..n])
        .map_err(|e| ProbeError::BadReply(format!("回包头解析失败: {e:?}")))?;
    Ok(ProbeOk {
        rtt,
        source: format!("{}:{}", parsed.host, parsed.port),
        payload_len: n - hlen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCP 桩：无认证协商 + 对 ASSOCIATE 回指定 REP 与 BND（127.0.0.1:bnd_port）。
    /// 控制连接保持到对端关闭（EOF 前会话不吊销）。
    async fn spawn_tcp_stub(rep: u8, bnd_port: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut m = [0u8; 2];
            s.read_exact(&mut m).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            // 探测目标以 IP 字面量传入（ATYP=0x01 → 请求帧恰 10 字节）
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            let p = bnd_port.to_be_bytes();
            s.write_all(&[0x05, rep, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
                .await
                .unwrap();
            let mut sink = [0u8; 16];
            let _ = s.read(&mut sink).await;
        });
        addr.to_string()
    }

    /// UDP 回环 echo 桩：收帧解头，按原目标回封（模拟中继下行）
    async fn spawn_udp_echo() -> (std::sync::Arc<UdpSocket>, u16) {
        let sock = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = sock.local_addr().unwrap().port();
        let s = std::sync::Arc::clone(&sock);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                if let Ok((t, hlen)) = parse_udp_header(&buf[..n]) {
                    let mut frame = encode_udp_header(&t, n - hlen);
                    frame.extend_from_slice(&buf[hlen..n]);
                    let _ = s.send_to(&frame, from).await;
                }
            }
        });
        (sock, port)
    }

    /// §10-S5 测试 1：进程内最小 socks5 UDP echo 桩 → run() Ok 且 RTT>0、
    /// 源/长度回填正确（验收 #6 的桩级口径）
    #[tokio::test]
    async fn udp_probe_roundtrip_against_local_stub() {
        let (_sock, udp_port) = spawn_udp_echo().await;
        let socks = spawn_tcp_stub(0x00, udp_port).await;

        let ok = run(
            &socks,
            "127.0.0.1",
            5353,
            b"probe-payload",
            Duration::from_secs(2),
            None,
        )
        .await
        .expect("桩级往返应成功");
        assert_eq!(ok.source, "127.0.0.1:5353", "回包源 = 头解析目标");
        assert_eq!(ok.payload_len, "probe-payload".len());
        assert!(ok.rtt.as_nanos() > 0, "RTT 应为正");
    }

    /// §10-S5 测试 2：桩回 REP 0x07 → 退出码 2、含「入口未开 UDP」语义
    #[tokio::test]
    async fn udp_probe_rejected_maps_exit_code_2() {
        let socks = spawn_tcp_stub(0x07, 0).await;
        let err = run(&socks, "127.0.0.1", 53, b"q", Duration::from_secs(1), None)
            .await
            .expect_err("REP 0x07 应失败");
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.detail().contains("入口未开 UDP"),
            "语义应点名 0x07: {}",
            err.detail()
        );
    }

    /// §10-S5 测试 3：桩吞包不回（黑洞 UDP 口）→ 1ms 级 timeout 触发退出码 3
    #[tokio::test]
    async fn udp_probe_timeout_maps_exit_code_3() {
        // 黑洞：绑定但不读不回（数据报落缓冲，不产生 ICMP 拒绝）
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = blackhole.local_addr().unwrap().port();
        let socks = spawn_tcp_stub(0x00, port).await;

        let err = run(
            &socks,
            "127.0.0.1",
            53,
            b"query",
            Duration::from_millis(80),
            None,
        )
        .await
        .expect_err("黑洞应超时");
        assert_eq!(err.exit_code(), 3);
        match &err {
            ProbeError::Timeout { sent_bytes } => assert!(*sent_bytes > 0, "应附带已发出字节数"),
            other => panic!("应为 Timeout: {other:?}"),
        }
        assert!(err.detail().contains("已发出"), "{}", err.detail());
    }
}
