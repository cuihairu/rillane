//! 真实探测执行器（RIL-061 运行时装配面）：[`ProbeExecutor`] 的本机
//! I/O 实现——DNS 解析 / TCP connect / UDP 回显三类测量。取消经令牌
//! 协作（入口检查点 + 多包回显逐包检查点）；超时归服务面强制
//! （deadline 内自约束等待）。
//!
//! 诚实边界：
//! - [`ProbeTarget::ProxyHandshake`] 返回 [`CODE_PROBE_UNSUPPORTED`]——
//!   内核 `EgressConnector` 是流级 forward 面，无「拨到指定地址并测
//!   握手」形态；硬造合成流既污染业务会计也测不出握手 RTT，宁可显式
//!   不支持（配置面也据此不登记 handshake 目标）。
//! - UDP 回显要求对端真回显：无回应按 replies=0 / rtt=None 如实报告，
//!   不造 RTT（RIL-059 口径）。
//! - 测量只含本机到登记目标的往返时延与计数——不含任何「机场内部
//!   路径」推断（debug-and-mcp.md §3：do not infer provider internals）。

use std::net::IpAddr;
use std::time::Instant;

use rillane_core::probe::CancelToken;
use rillane_core::{
    ProbeExecError, ProbeExecutor, ProbeOutcome, ProbeTarget, CODE_PROBE_CANCELLED,
};

/// UDP 回显发包数（固定小样本——丢包率由计数可算，样本量如实可见）
const UDP_ECHO_PROBES: u32 = 3;

/// 单包等待回应上限（毫秒）：受作业 deadline 双重约束——取两者较小。
/// 回显对端不回包时每个探测槽最多耗这么多。
const UDP_ECHO_REPLY_WAIT_MS: u64 = 400;

/// 本机真实探测执行器（无状态——测量互不共享）
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalProbeExecutor;

impl LocalProbeExecutor {
    pub fn new() -> Self {
        Self
    }
}

/// 取消检查点：置位即协作退出（稳定码 [`CODE_PROBE_CANCELLED`]）
fn checkpoint(cancel: &CancelToken) -> Result<(), ProbeExecError> {
    if cancel.is_cancelled() {
        return Err(ProbeExecError {
            code: CODE_PROBE_CANCELLED,
            detail: "cancelled at checkpoint".into(),
        });
    }
    Ok(())
}

/// 毫秒时长（实测经过——四舍五入到毫秒，回环上可能为 0：0 是真实
/// 测得不是缺失）
fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[async_trait::async_trait]
impl ProbeExecutor for LocalProbeExecutor {
    async fn run(
        &self,
        target: &ProbeTarget,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        checkpoint(cancel)?;
        match target {
            ProbeTarget::Dns { host } => self.probe_dns(host).await,
            ProbeTarget::Connect { addr } => self.probe_connect(*addr).await,
            ProbeTarget::ProxyHandshake { .. } => Err(ProbeExecError::unsupported(
                "proxy handshake executor not wired: egress connector is a flow-level \
                 forward surface without a dial-and-measure shape",
            )),
            ProbeTarget::UdpEcho { addr, payload_len } => {
                self.probe_udp_echo(*addr, *payload_len, deadline, cancel)
                    .await
            }
        }
    }
}

impl LocalProbeExecutor {
    /// DNS 解析：系统解析器（getaddrinfo）+ 实测 RTT。解析出的地址
    /// 去重保序（A/AAAA 混合双栈如实并陈）。
    async fn probe_dns(&self, host: &str) -> Result<ProbeOutcome, ProbeExecError> {
        let start = Instant::now();
        let addrs = tokio::net::lookup_host((host, 0u16))
            .await
            .map_err(|e| ProbeExecError::failed(format!("dns resolve failed: {e}")))?;
        let mut resolved: Vec<IpAddr> = Vec::new();
        for a in addrs {
            if !resolved.contains(&a.ip()) {
                resolved.push(a.ip());
            }
        }
        Ok(ProbeOutcome::Dns {
            resolved,
            rtt_ms: Some(elapsed_ms(start)),
        })
    }

    /// TCP connect：实测建连 RTT（握手成功即完成——不带业务流量）
    async fn probe_connect(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        let start = Instant::now();
        tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| ProbeExecError::failed(format!("tcp connect failed: {e}")))?;
        Ok(ProbeOutcome::Connect {
            rtt_ms: elapsed_ms(start),
        })
    }

    /// UDP 回显：固定 [`UDP_ECHO_PROBES`] 包（载荷 [标记, 序号, 0…]——
    /// 回包按「等长且标记序号一致」认定为本探测的回应，串扰不误计）。
    /// RTT 取首个成功回应的实测值；全无回应 rtt=None（不造数）。
    /// 实耗字节 = 包数 × 载荷（预算双向结算口径）。
    async fn probe_udp_echo(
        &self,
        addr: std::net::SocketAddr,
        payload_len: usize,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<ProbeOutcome, ProbeExecError> {
        let bind: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("常量地址")
        } else {
            "[::]:0".parse().expect("常量地址")
        };
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| ProbeExecError::failed(format!("udp bind failed: {e}")))?;
        socket
            .connect(addr)
            .await
            .map_err(|e| ProbeExecError::failed(format!("udp connect failed: {e}")))?;

        let mut sent: u32 = 0;
        let mut replies: u32 = 0;
        let mut rtt_ms: Option<u64> = None;
        let mut buf = vec![0u8; payload_len.max(2)];
        for seq in 0u8..UDP_ECHO_PROBES as u8 {
            checkpoint(cancel)?;
            // 载荷首字节标记 + 次字节序号（回包认定口径）；payload_len
            // 为 0/1 时载荷不足标记位——按最小 2 字节发送并如实记账
            let wire_len = payload_len.max(2);
            buf[0] = b'R';
            buf[1] = seq;
            socket
                .send(&buf[..wire_len])
                .await
                .map_err(|e| ProbeExecError::failed(format!("udp send failed: {e}")))?;
            sent += 1;

            // 单包等待：受回显等待上限与作业 deadline 双重约束
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(std::time::Duration::from_millis(UDP_ECHO_REPLY_WAIT_MS));
            let start = Instant::now();
            match tokio::time::timeout(wait, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if n == wire_len && buf[0] == b'R' && buf[1] == seq {
                        replies += 1;
                        if rtt_ms.is_none() {
                            rtt_ms = Some(elapsed_ms(start));
                        }
                    }
                    // 不匹配的数据报不算回应（同端口串扰不误计丢包）
                }
                Ok(Err(e)) => {
                    return Err(ProbeExecError::failed(format!("udp recv failed: {e}")));
                }
                Err(_) => {} // 本包超时：计丢包，继续下一包
            }
        }
        Ok(ProbeOutcome::UdpEcho {
            sent,
            replies,
            payload_len,
            rtt_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::CODE_PROBE_UNSUPPORTED;
    use std::net::SocketAddr;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
    }

    fn far_deadline() -> Instant {
        Instant::now() + std::time::Duration::from_secs(10)
    }

    fn token() -> CancelToken {
        CancelToken::default()
    }

    #[tokio::test]
    async fn connect_measures_loopback_rtt() {
        let listener = tokio::net::TcpListener::bind(loopback(0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 半连接只等 accept 不影响 connect 成功——测量建连本身
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let outcome = LocalProbeExecutor
            .run(&ProbeTarget::Connect { addr }, far_deadline(), &token())
            .await
            .unwrap();
        match outcome {
            ProbeOutcome::Connect { rtt_ms } => {
                // 回环建连亚毫秒很常见——0 是真实测得不是缺失
                assert!(rtt_ms <= 5_000, "回环建连不应耗秒级: {rtt_ms}");
            }
            other => panic!("应得 connect 测量，得到 {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_refused_is_failed_with_stable_code() {
        // 关闭端口：内核回 RST → connect 失败 → 稳定码 exec.failed
        let addr = loopback(1); // 端口 1 需特权监听，常态关闭
        let err = LocalProbeExecutor
            .run(&ProbeTarget::Connect { addr }, far_deadline(), &token())
            .await
            .unwrap_err();
        assert_eq!(err.code, rillane_core::CODE_PROBE_EXEC_FAILED);
        assert!(err.detail.contains("tcp connect failed"));
    }

    #[tokio::test]
    async fn udp_echo_counts_replies_and_measures_rtt() {
        let socket = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        // 真回显：原样回发
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        let outcome = LocalProbeExecutor
            .run(
                &ProbeTarget::UdpEcho {
                    addr,
                    payload_len: 64,
                },
                far_deadline(),
                &token(),
            )
            .await
            .unwrap();
        match outcome {
            ProbeOutcome::UdpEcho {
                sent,
                replies,
                payload_len,
                rtt_ms,
            } => {
                assert_eq!((sent, replies, payload_len), (3, 3, 64));
                assert!(rtt_ms.is_some(), "有回应必有实测 RTT");
            }
            other => panic!("应得 udp 回显测量，得到 {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_echo_without_peer_reports_loss_explicitly() {
        // 绑定但不回显：三包全丢 → replies=0 / rtt=None（不造数）
        let socket = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let outcome = LocalProbeExecutor
            .run(
                &ProbeTarget::UdpEcho {
                    addr,
                    payload_len: 32,
                },
                far_deadline(),
                &token(),
            )
            .await
            .unwrap();
        match outcome {
            ProbeOutcome::UdpEcho {
                sent,
                replies,
                payload_len,
                rtt_ms,
            } => {
                assert_eq!((sent, replies, payload_len), (3, 0, 32));
                assert_eq!(rtt_ms, None, "无回应不造 RTT");
            }
            other => panic!("应得 udp 回显测量，得到 {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_echo_budget_bytes_are_payload_times_packets() {
        // 预算记账口径钉：3 包 × 64B = 192B（测量字节面真实）
        let socket = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        let outcome = LocalProbeExecutor
            .run(
                &ProbeTarget::UdpEcho {
                    addr,
                    payload_len: 64,
                },
                far_deadline(),
                &token(),
            )
            .await
            .unwrap();
        assert_eq!(outcome.bytes_used(), 192);
    }

    #[tokio::test]
    async fn cancelled_at_entry_fails_fast_without_io() {
        let cancel = token();
        cancel.cancel();
        let err = LocalProbeExecutor
            .run(
                &ProbeTarget::Connect { addr: loopback(1) },
                far_deadline(),
                &cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_CANCELLED);
    }

    #[tokio::test]
    async fn cancelled_mid_echo_stops_at_checkpoint() {
        // 对端不回显（每包耗满等待窗）→ 第二包检查点看到置位令牌退出
        let socket = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let cancel = token();
        let exec = LocalProbeExecutor;
        let deadline = far_deadline();
        let task_token = cancel.clone();
        let handle = tokio::spawn(async move {
            exec.run(
                &ProbeTarget::UdpEcho {
                    addr,
                    payload_len: 16,
                },
                deadline,
                &task_token,
            )
            .await
        });
        // 首包进入等待窗（400ms）后置位——协作检查点应在下个包前退出
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        cancel.cancel();
        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.code, CODE_PROBE_CANCELLED);
    }

    #[tokio::test]
    async fn proxy_handshake_is_explicitly_unsupported() {
        let target = ProbeTarget::ProxyHandshake {
            egress: "direct".into(),
            addr: loopback(1),
        };
        let err = LocalProbeExecutor
            .run(&target, far_deadline(), &token())
            .await
            .unwrap_err();
        assert_eq!(err.code, CODE_PROBE_UNSUPPORTED);
    }

    #[tokio::test]
    async fn dns_resolves_localhost() {
        let outcome = LocalProbeExecutor
            .run(
                &ProbeTarget::Dns {
                    host: "localhost".into(),
                },
                far_deadline(),
                &token(),
            )
            .await
            .unwrap();
        match outcome {
            ProbeOutcome::Dns { resolved, rtt_ms } => {
                assert!(!resolved.is_empty(), "localhost 至少解析出环回地址");
                assert!(rtt_ms.is_some(), "解析完成必有实测 RTT");
            }
            other => panic!("应得 dns 测量，得到 {other:?}"),
        }
    }
}
