//! ShadowQUIC 出站客户端面（RIL-118，库承载）。
//!
//! 载具 `shadowquic` 0.4.12：协议自身的 Rust 实现、唯一 crates.io 落点
//! （评估 + 探针留证 docs/protocol-backends.md#shadowquic，2026-11-18；
//! 伴生 shadowquic-macros 线格式 derive 随行）。直连路径不取 crate 的应用
//! 机械（Manager/SOCKS 挂具）：
//!
//! `ShadowQuicClient::new(cfg, resolver)`（同步构造，端点 OnceCell 惰性
//! 初始化）→ `get_conn()`（地址解析 → QUIC 连接——直连路径逐流新建 QUIC
//! 连接，zero_rtt 启用时握手 0-RTT 复用（探针实测二次 get_conn 0.64ms）；
//! 客户端内 prepare_conn 的连接缓存属应用机械面（Manager/SOCKS 挂具），
//! 直连路径不经）→ `squic::outbound::connect_tcp(&conn, SocksAddr)`（打开
//! 双向流并预编码 `SQConnect(dst)` 请求，AsyncRead/AsyncWrite）→ 双向中继。
//!
//! 认证面（crate 源码核验）：ShadowQUIC 的 username/password 走 JLS 伪装
//! TLS 握手层（服务端 `authed_user()` 从握手里取用户，无此用户即拒接）
//! ——凭据错误在 QUIC 握手期暴露，不在流打开期。直连路径客户端侧不另发
//! SQAuthenticate 流（sunnyquic/UDP 面专用）。
//!
//! 配置口径（探针实测 + mihomo 文档对齐）：
//! - `zero_rtt` 缺省 **false**（mihomo 文档缺省 false——官方服务器
//!   ≤v0.3.11 存在 zero-rtt 断连 bug，mihomo 具名；crate 自身缺省 true
//!   不迁移，显式带 zero-rtt: true 者透传）。
//! - ALPN 缺省 `["h3"]`（crate serde 缺省与 mihomo 文档同口径）；显式
//!   空表具名拒绝（无公共 ALPN 握手必败，防静默）。
//! - SNI（server_name）缺省回落 server——crate 文档具名须与服务器
//!   jls_upstream 域一致（JLS = crate 自带伪装 TLS client hello 的 rustls
//!   fork）。
//! - 拥塞控制缺省 BBR（crate 缺省载具，探针实测口径）；mihomo 键形
//!   `new_reno` 与 crate 键形 `new-reno` 同收（命名方差归一）；brutal
//!   需 up/down 参数面（mihomo 私有）、bbr3 在 crate 文档支持集外——均
//!   具名拒绝，不静默降级。
//! - `initial_mtu = 1200`、`over_stream = true` 为探针实测口径钉定
//!   （over_stream 仅影响 UDP 中继模式，本仓不交付 UDP 面，取探针原值
//!   不漂移）；mihomo 私有调参面（up/down、cwnd、bbr-profile、
//!   recv-window 族）不入 IR。
//!
//! 交付边界：仅 TCP 面（catalog udp=false）——库的两种 UDP 中继面
//! （over-datagram / over-stream）均未交付；服务端面与逐用户统计 API
//! 未交付（服务端面仅测试镜像取用，见 cfg(test)）。
//!
//! 端点生命周期（探针实证毛刺，交付相关）：后台任务仍在轮询时丢弃 QUIC
//! 端点会在 crate 内 panic（"Quic endpoint closed"，
//! quinn_wrapper/wrapper.rs:486）——客户端整体 `Arc` 持于连接器内，端点
//! 随连接器存活，流存活期间绝不触发 drop。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use rillane_core::{EgressConnector, Flow, FlowReport};
use shadowquic::config::{CongestionControl, ShadowQuicClientCfg};
use shadowquic::dns::ResolverManager;
use shadowquic::msgs::socks5::SocksAddr;
use shadowquic::shadowquic::outbound::ShadowQuicClient;
use shadowquic::squic::outbound::connect_tcp;

/// 拨号超时（地址解析 + QUIC 握手 + 目标流打开，与 snell/hysteria2 同口径）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// 探针实测钉定的初始 MTU（crate 下界 1200；官方文档推荐 1400 于高丢包
/// 网络——本席回环无丢包面，取下界不遮蔽 MTU 协商问题）
const INITIAL_MTU: u16 = 1200;

/// 拥塞控制归一：`None` 随 crate 缺省载具 BBR；`bbr` / `new-reno`
/// （mihomo 键形 `new_reno` 同收）/ `cubic` 具名落键；brutal（需 up/down
/// 参数面）与支持集外值具名拒绝。
fn normalize_congestion(raw: Option<&str>) -> Result<CongestionControl> {
    let Some(raw) = raw else {
        return Ok(CongestionControl::Bbr);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "bbr" => Ok(CongestionControl::Bbr),
        "new-reno" | "new_reno" => Ok(CongestionControl::NewReno),
        "cubic" => Ok(CongestionControl::Cubic),
        other => Err(anyhow!(
            "ShadowQUIC 拥塞控制 {other:?} 未交付（支持 bbr/new-reno/cubic；brutal 需 up/down 参数面）"
        )),
    }
}

/// ShadowQUIC 出站连接器：QUIC 连接缓存于客户端内（复用/断连重建），
/// 逐流打开双向流携 SQConnect 请求，双向中继。
///
/// Debug 手写（crate 客户端面未实现 Debug——端点/连接句柄不作格式化面）。
pub struct ShadowQuicConnector {
    /// 客户端整体持于 Arc：端点（OnceCell 惰性初始化）随连接器存活——
    /// 探针实证的后台任务轮询期 drop-panic 毛刺见模块头注
    client: Arc<ShadowQuicClient>,
    server: String,
    port: u16,
}

impl ShadowQuicConnector {
    /// 构建期校验（配置错误在启动时暴露，而非首个连接时）：认证面非空、
    /// 拥塞控制在支持集内、ALPN 非空表。
    pub fn new(
        server: String,
        port: u16,
        username: String,
        password: String,
        server_name: Option<String>,
        alpn: Option<Vec<String>>,
        congestion_controller: Option<String>,
        zero_rtt: bool,
    ) -> Result<Self> {
        if server.is_empty() {
            bail!("ShadowQUIC 缺少服务器地址");
        }
        if username.is_empty() || password.is_empty() {
            bail!("ShadowQUIC 缺少 username/password 认证面");
        }
        let congestion = normalize_congestion(congestion_controller.as_deref())?;
        let alpn = match alpn {
            None => vec!["h3".to_string()],
            Some(v) if v.is_empty() => {
                bail!("ShadowQUIC alpn 为空表（缺省即 [h3]；无公共 ALPN 握手必败）")
            }
            Some(v) => v,
        };
        let server_name = server_name.unwrap_or_else(|| server.clone());
        let addr = format!("{server}:{port}");
        let cfg = ShadowQuicClientCfg {
            tag: "rillane".into(),
            username,
            password,
            addr,
            server_name,
            alpn,
            initial_mtu: INITIAL_MTU,
            congestion_control: congestion,
            zero_rtt,
            over_stream: true,
            ..Default::default()
        };
        let client = Arc::new(ShadowQuicClient::new(cfg, Arc::new(ResolverManager::new())));
        Ok(Self {
            client,
            server,
            port,
        })
    }
}

impl std::fmt::Debug for ShadowQuicConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowQuicConnector")
            .field("server", &self.server)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl EgressConnector for ShadowQuicConnector {
    fn name(&self) -> &'static str {
        "shadowquic"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        // 连接获取（地址解析 → QUIC 握手）：直连路径逐流新建连接，
        // zero_rtt 启用时握手 0-RTT 复用（见模块头注认证面/缓存面说明）
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, self.client.get_conn())
            .await
            .context("ShadowQUIC 连接超时")?
            .with_context(|| format!("ShadowQUIC 连接失败: {}:{}", self.server, self.port))?;
        // 打开双向流并携 SQConnect(dst) 请求（IP 字面量经 canonicalize_ip
        // 归一，域名交 crate 解析器）
        let mut stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_tcp(
                &conn,
                SocksAddr::from_domain(flow.target.host.clone(), flow.target.port),
            ),
        )
        .await
        .context("ShadowQUIC 目标流打开超时")?
        .with_context(|| {
            format!(
                "ShadowQUIC 目标流打开失败: {}:{}",
                flow.target.host, flow.target.port
            )
        })?;

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("ShadowQUIC 双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::{FlowId, TargetProto};
    use shadowquic::config::{AuthUser, JlsUpstream, ShadowQuicServerCfg};
    use shadowquic::shadowquic::inbound::ShadowQuicServer;
    use shadowquic::{Inbound, ProxyRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 库服务端面固定测试口（本仓 QUIC 族测试仅占 40443；测试间并行，
    /// 各测试独占端口避碰撞）
    const SQ_PORT_MAIN: u16 = 44790;
    const SQ_PORT_AUTH: u16 = 44791;

    /// 库服务端面（与探针 /tmp/sqprobe 同构）：AuthUser 认证 + jls_upstream
    /// 伪装声明 + h3 + BBR；accept 的 TCP 会话中继到回声上游。端点随 accept
    /// 任务存活（生命周期毛刺见模块头注）。
    async fn spawn_sq_server(port: u16, username: &str, password: &str, echo: &str) {
        let mut server = ShadowQuicServer::new(ShadowQuicServerCfg {
            tag: "sq-test".into(),
            bind_addr: format!("127.0.0.1:{port}").parse().expect("绑定点"),
            users: vec![AuthUser {
                username: username.into(),
                password: password.into(),
            }],
            jls_upstream: JlsUpstream {
                addr: "localhost:443".into(),
                ..Default::default()
            },
            alpn: vec!["h3".into()],
            zero_rtt: true,
            congestion_control: CongestionControl::Bbr,
            ..Default::default()
        })
        .await
        .expect("服务端面构造");
        server.init().await.expect("服务端面启动");
        let echo = echo.to_string();
        tokio::spawn(async move {
            loop {
                match server.accept().await {
                    Ok(ProxyRequest::Tcp(s)) => {
                        let mut up = match tokio::net::TcpStream::connect(&echo).await {
                            Ok(u) => u,
                            Err(_) => continue,
                        };
                        tokio::spawn(async move {
                            let _ = tokio::io::copy_bidirectional(&mut { s.stream }, &mut up).await;
                        });
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
    }

    /// 回声上游：端口 0 内核分配，测试间无碰撞面。
    async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo 绑定");
        let addr = listener.local_addr().expect("echo 地址");
        let h = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        (addr, h)
    }

    fn make_flow(host: &str, port: u16) -> (Flow, tokio::io::DuplexStream) {
        let (client, outbound_side) = tokio::io::duplex(64 * 1024);
        let flow = Flow {
            id: FlowId::new(),
            target: rillane_core::FlowTarget {
                host: host.to_string(),
                port,
                proto: TargetProto::Tcp,
            },
            io: Box::new(outbound_side),
            metadata: Default::default(),
        };
        (flow, client)
    }

    /// 全链回环（库服务端面镜像）：连接器 forward（QUIC 连接 → SQConnect
    /// 双向流）→ 文本 + 大块（10KB，越流帧界）逐字节还原 → FlowReport
    /// 计数对账 → 第二条流复用同连接（OnceCell 缓存面）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connector_roundtrip_via_library_server_face() {
        let (echo_addr, _echo) = spawn_echo().await;
        spawn_sq_server(SQ_PORT_MAIN, "u", "p", &echo_addr.to_string()).await;

        let connector = std::sync::Arc::new(
            ShadowQuicConnector::new(
                "127.0.0.1".into(),
                SQ_PORT_MAIN,
                "u".into(),
                "p".into(),
                Some("localhost".into()),
                None,
                None,
                false,
            )
            .expect("构造"),
        );

        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        for round in 0..2u8 {
            let (flow, mut client) = make_flow(&echo_addr.ip().to_string(), echo_addr.port());
            let task_payload = payload.clone();
            let conn = connector.clone();
            let task = tokio::spawn(async move {
                let fw = conn.forward(flow);
                tokio::pin!(fw);
                // join 并行：读回侧在 fw 轮转下推进（串行即死锁——读阻塞
                // 在 fw 连接之前）；回读毕 client 显式 drop → 上行 EOF →
                // 下行收口 → forward 收束（写半关闭被对端尊重，探针实测）
                let (report, got) = tokio::join!(fw, async {
                    client
                        .write_all(format!("round{round} ").as_bytes())
                        .await
                        .expect("上行写");
                    client.write_all(&task_payload).await.expect("上行大块写");
                    let mut got = vec![0u8; format!("round{round} ").len() + task_payload.len()];
                    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
                        .await
                        .expect("下行超时（回声回放面）")
                        .expect("下行读");
                    drop(client);
                    got
                });
                (report, got)
            });
            let (report, got) = tokio::time::timeout(Duration::from_secs(35), task)
                .await
                .expect("任务超时（QUIC 连接/流打开面）")
                .expect("join");

            let mut expected = format!("round{round} ").into_bytes();
            expected.extend_from_slice(&payload);
            assert_eq!(got, expected, "回环逐字节还原（round {round}）");

            let report = report.expect("forward 成功");
            assert_eq!(report.upstream as usize, expected.len(), "上行计数");
            assert_eq!(report.downstream as usize, expected.len(), "下行计数");
        }
    }

    /// 错误凭据具名拒绝：JLS 伪装 TLS 握手层认证失败（服务端 authed_user
    /// 无此用户拒接）→ forward 在 CONNECT_TIMEOUT 内 Err（不静默成功；
    /// 消息出自 crate，只判失败面与不悬挂）。外层上限须 > 15s 拨号超时。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wrong_credentials_fail_named() {
        let (echo_addr, _echo) = spawn_echo().await;
        // 服务端面凭据 u/p；客户端凭据 u/wrong
        spawn_sq_server(SQ_PORT_AUTH, "u", "p", &echo_addr.to_string()).await;
        let connector = ShadowQuicConnector::new(
            "127.0.0.1".into(),
            SQ_PORT_AUTH,
            "u".into(),
            "wrong".into(),
            Some("localhost".into()),
            None,
            None,
            false,
        )
        .expect("构造");
        let (flow, mut client) = make_flow(&echo_addr.ip().to_string(), echo_addr.port());
        let task = tokio::spawn(async move {
            let fw = connector.forward(flow);
            tokio::pin!(fw);
            let (report, _) = tokio::join!(fw, async {
                // 凭据错 → 无回放面：读侧由超时兜底，不阻塞判负
                let mut buf = [0u8; 16];
                let _ = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await;
            });
            report
        });
        let verdict = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("任务超时（错误凭据判负面）")
            .expect("join");
        assert!(verdict.is_err(), "错误凭据必须失败（不静默成功）");
    }

    // ---------------------------------------------------------------------
    // 构建期校验：具名拒绝面 + 键形归一
    // ---------------------------------------------------------------------

    #[test]
    fn constructor_validations_named_rejects() {
        // 认证面缺失
        let e = ShadowQuicConnector::new(
            "sq.example.test".into(),
            443,
            String::new(),
            "p".into(),
            None,
            None,
            None,
            false,
        )
        .expect_err("空 username 必拒");
        assert!(e.to_string().contains("username/password"), "{e}");
        let e = ShadowQuicConnector::new(
            "sq.example.test".into(),
            443,
            "u".into(),
            String::new(),
            None,
            None,
            None,
            false,
        )
        .expect_err("空 password 必拒");
        assert!(e.to_string().contains("username/password"), "{e}");
        // 空服务器地址
        let e = ShadowQuicConnector::new(
            String::new(),
            443,
            "u".into(),
            "p".into(),
            None,
            None,
            None,
            false,
        )
        .expect_err("空 server 必拒");
        assert!(e.to_string().contains("服务器地址"), "{e}");
        // 空表 alpn
        let e = ShadowQuicConnector::new(
            "sq.example.test".into(),
            443,
            "u".into(),
            "p".into(),
            None,
            Some(Vec::new()),
            None,
            false,
        )
        .expect_err("空表 alpn 必拒");
        assert!(e.to_string().contains("alpn"), "{e}");
        // 拥塞控制支持集外（含 brutal——需 up/down 参数面）具名拒绝
        for bad in ["brutal", "bbr3", "westwood"] {
            let e = ShadowQuicConnector::new(
                "sq.example.test".into(),
                443,
                "u".into(),
                "p".into(),
                None,
                None,
                Some(bad.into()),
                false,
            )
            .expect_err("支持集外拥塞控制必拒");
            assert!(e.to_string().contains(bad), "{e}");
        }
    }

    #[test]
    fn constructor_accepts_supported_congestion_and_aliases() {
        // 缺省（None）+ 三支持值 + mihomo 键形 new_reno 归一
        for cc in [
            None,
            Some("bbr"),
            Some("new-reno"),
            Some("new_reno"),
            Some("cubic"),
        ] {
            ShadowQuicConnector::new(
                "sq.example.test".into(),
                443,
                "u".into(),
                "p".into(),
                None,
                Some(vec!["h3".into()]),
                cc.map(str::to_string),
                false,
            )
            .unwrap_or_else(|e| panic!("拥塞控制 {cc:?} 应接受: {e}"));
        }
    }
}
