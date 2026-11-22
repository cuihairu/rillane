//! Cloudflared 出口连接器契约测试（RIL-128）。
//!
//! 两层（与 tailcat_contract 同构）：
//! - **CI 可跑**（不触网）：UDP 目标具名拒绝（forward 在触网前判负）+
//!   hostname/path/CF Access 令牌成对建期具名拒绝（构造期判负，不建
//!   TLS、不拨 edge）。
//! - **`#[ignore]` 真机对端**（本地手动验收，CI 不跑）：本仓
//!   `CloudflaredConnector` 经真实 Cloudflare edge 拨 WS 回显 roundtrip
//!   ——对端链路 = CF edge（生产）→ QUIC/H2 隧道 → 隧道客户端（载具
//!   libcfd 0.2.0 参考实现，quick tunnel 自预配）→ 本机回显桥。命名
//!   隧道经环境变量外配（隧道客户端已由运维运行，载具不入验收门）：
//!   - `RIL_CLOUDFLARED_HOSTNAME`：命名隧道公共主机名（缺失即自预配
//!     quick tunnel——trycloudflare.com 匿名隧道）
//!   - `RIL_CLOUDFLARED_PATH`：WS upgrade 路径（缺省 `/ws`）
//!   - `RIL_CLOUDFLARED_ACCESS_ID` / `RIL_CLOUDFLARED_ACCESS_SECRET`：
//!     CF Access 服务令牌（命名隧道受 Access 保护时；须成对）
//!
//! 搭建步骤见 docs/protocol-backends.md#cloudflared 真机对端小节。

use rillane_core::{EgressConnector, Flow, FlowId, FlowTarget, TargetProto};
use rillane_protocols::CloudflaredConnector;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// 进程级 rustls 提供者（fork 版要求显式 install_default）。
fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn tcp_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

fn udp_flow(host: &str, port: u16) -> Flow {
    Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        io: Box::new(tokio::io::duplex(4096).1),
        metadata: Default::default(),
    }
}

/// UDP 应用面判负：forward 在触网前具名拒绝（catalog udp=false 口径）。
#[tokio::test]
async fn udp_target_is_named_refused() {
    install_tls_provider();
    let c = CloudflaredConnector::new("x.example".into(), "/".into(), None, None).expect("连接器");
    let flow = udp_flow("x.example", 443);
    let err = c.forward(flow).await.unwrap_err().to_string();
    assert!(err.contains("仅交付 TCP 应用面"), "UDP 应具名拒绝：{err}");
}

/// hostname 建期具名拒绝：空/scheme/带端口均在构造期失败（触网前判负）。
#[tokio::test]
async fn bad_hostname_is_named_at_construction() {
    install_tls_provider();
    for bad in ["", "   ", "https://x.example", "x.example:443"] {
        let err = CloudflaredConnector::new(bad.into(), "/".into(), None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("hostname"), "建期具名拒绝（{bad:?}）：{err}");
    }
}

/// path 建期具名拒绝：不以 / 起首构造期失败。
#[tokio::test]
async fn bad_path_is_named_at_construction() {
    install_tls_provider();
    for bad in ["ws", "tunnel/ws"] {
        let err = CloudflaredConnector::new("x.example".into(), bad.into(), None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("path"), "建期具名拒绝（{bad:?}）：{err}");
    }
}

/// CF Access 令牌成对建期具名拒绝：id 无 secret / secret 无 id 均拒绝
/// （不静默降级为匿名——连接必失败且无报错）。
#[tokio::test]
async fn half_token_pair_is_named_at_construction() {
    install_tls_provider();
    for (id, secret) in [
        (Some("id".to_string()), None),
        (None, Some("secret".to_string())),
    ] {
        let err = CloudflaredConnector::new("x.example".into(), "/".into(), id, secret)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("成对"), "建期具名拒绝：{err}");
    }
}

// ---------------------------------------------------------------------------
// 真机对端（#[ignore]）
// ---------------------------------------------------------------------------

/// 本机回显监听（隧道 origin 桥接到此——CF edge → 隧道 → origin 桥 →
/// 本机 TCP 服务，与 cloudflared 端到端口转发同口径）。
async fn spawn_local_echo() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("本机回显监听");
    let address = listener.local_addr().expect("回显地址");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// WS origin：应答 upgrade（RFC 6455 accept）并把裸字节桥接到本机回显
/// 监听（edge 终结 WS 帧后 origin 侧收到裸字节——载具 pump 同口径）。
#[derive(Clone)]
struct BridgeEchoOrigin {
    echo: std::net::SocketAddr,
}

impl libcfd::StreamOrigin<libcfd::WebSocketResponder> for BridgeEchoOrigin {
    fn connect(&self, request: libcfd::Request, respond: libcfd::WebSocketResponder) {
        let echo = self.echo;
        tokio::spawn(async move {
            let Ok(sock) = tokio::net::TcpStream::connect(echo).await else {
                return respond.fail(format!("回显监听不可达：{echo}"));
            };
            let key = request
                .headers
                .get("sec-websocket-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "Sec-WebSocket-Accept",
                libcfd::websocket_accept(key)
                    .parse()
                    .expect("合法 accept 头值"),
            );
            respond.upgrade(libcfd::WebSocketConnection {
                response: libcfd::Response::new(
                    http::StatusCode::SWITCHING_PROTOCOLS,
                    headers,
                    libcfd::Body::empty(),
                ),
                origin: libcfd::Stream::from_io(sock.compat()),
            });
        });
    }
}

/// 恒 404 的 HTTP origin（验收门仅走 WS 面）。
struct NoHttpOrigin;

impl libcfd::HttpOrigin for NoHttpOrigin {
    fn handle(&self, _request: libcfd::Request, respond: libcfd::HttpResponder) {
        respond.send(libcfd::Response::new(
            http::StatusCode::NOT_FOUND,
            http::HeaderMap::new(),
            libcfd::Body::from_bytes(b"no http face".to_vec()),
        ));
    }
}

/// 一轮 roundtrip：连接器 forward + 回显断言（返回 FlowReport）。
async fn roundtrip_once(
    hostname: &str,
    path: &str,
    access: (Option<String>, Option<String>),
) -> anyhow::Result<rillane_core::FlowReport> {
    let connector =
        CloudflaredConnector::new(hostname.to_string(), path.to_string(), access.0, access.1)?;
    let (flow, mut client) = tcp_flow(hostname, 443);
    let task = tokio::spawn(async move { connector.forward(flow).await });
    let msg = b"real-peer-cloudflared-echo";
    client.write_all(msg).await?;
    let mut buf = vec![0u8; msg.len()];
    match timeout(Duration::from_secs(30), client.read_exact(&mut buf)).await {
        Ok(Ok(n)) => assert_eq!(&buf[..n], msg, "真实对端应字节精确回显"),
        Ok(Err(e)) => {
            // 回显读失败时回吐 forward 侧真实错误（否则只看到被掩盖的 EOF）
            let forward_err = match timeout(Duration::from_secs(5), task).await {
                Ok(Ok(Ok(r))) => format!("forward 竟成功：{r:?}"),
                Ok(Ok(Err(e))) => format!("{e:#}"),
                Ok(Err(e)) => format!("join 失败：{e}"),
                Err(_) => "forward 收尾超时（回显读失败）".to_string(),
            };
            anyhow::bail!("回显读失败（{e}）；forward 侧错误：{forward_err}")
        }
        Err(_) => anyhow::bail!("回显读超时（30s）"),
    }
    drop(client);
    let report = timeout(Duration::from_secs(10), task)
        .await
        .map_err(|_| anyhow::anyhow!("forward 收尾超时"))?
        .map_err(|e| anyhow::anyhow!("forward 任务失败：{e}"))?
        .map_err(|e| anyhow::anyhow!("forward 失败：{e:#}"))?;
    anyhow::ensure!(
        report.upstream >= msg.len() as u64,
        "upstream 计入：{:?}",
        report
    );
    Ok(report)
}

/// 真机对端：真实 Cloudflare edge（生产）→ 隧道 → 本机回显桥的 WS
/// roundtrip。quick tunnel 自预配（trycloudflare.com，匿名）或命名隧道
/// 外配（环境变量，隧道客户端已由运维运行）。quick tunnel 生效需数秒，
/// 重试窗口 8×5s（载具 poll_public 同口径）。
#[tokio::test]
#[ignore = "真机对端（真实 Cloudflare edge + quick tunnel 自预配/命名隧道），本地手动验收用"]
async fn real_peer_cloudflared_roundtrip() {
    install_tls_provider();

    let external = std::env::var("RIL_CLOUDFLARED_HOSTNAME").ok();
    let path = std::env::var("RIL_CLOUDFLARED_PATH").unwrap_or_else(|_| "/ws".to_string());
    let access = (
        std::env::var("RIL_CLOUDFLARED_ACCESS_ID").ok(),
        std::env::var("RIL_CLOUDFLARED_ACCESS_SECRET").ok(),
    );

    // 命名隧道外配：隧道客户端已由运维运行（cloudflared），验收门只起
    // 本机回显与连接器。quick 自预配：载具 libcfd 起隧道客户端（真实
    // edge 注册 + QUIC/H2），origin 桥本机回显。
    let (hostname, _tunnel_task, _shutdown_tx) = if let Some(hostname) = external {
        (hostname, None, None)
    } else {
        let echo = spawn_local_echo().await;
        let origin = libcfd::Origin::http(NoHttpOrigin).with_websocket(BridgeEchoOrigin { echo });
        let tunnel = libcfd::create_quick_tunnel(&libcfd::QuickTunnelOptions::default())
            .await
            .expect("quick tunnel 申请（trycloudflare.com）");
        let hostname = tunnel
            .url()
            .strip_prefix("https://")
            .expect("quick tunnel URL 形态")
            .to_string();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let edge = libcfd::EdgeConnector::new(libcfd::EdgeOptions::default());
        let task = tokio::spawn(async move {
            edge.run(libcfd::Tunnel::quick(tunnel), origin, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        (hostname, Some(task), Some(shutdown_tx))
    };

    // 重试窗口：quick tunnel 生效需数秒（edge 注册 + DNS 传播）
    let mut last_err = String::new();
    let mut report = None;
    for _ in 0..8 {
        match roundtrip_once(&hostname, &path, access.clone()).await {
            Ok(r) => {
                report = Some(r);
                break;
            }
            Err(e) => {
                last_err = format!("{e:#}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
    let report = report.unwrap_or_else(|| panic!("真机对端 roundtrip 未通过：{last_err}"));
    eprintln!("cloudflared real-peer roundtrip ok: {report:?}");

    // 收尾：停隧道客户端（quick 路径）
    if let Some(tx) = _shutdown_tx {
        let _ = tx.send(());
    }
    if let Some(task) = _tunnel_task {
        let _ = timeout(Duration::from_secs(10), task).await;
    }
}
