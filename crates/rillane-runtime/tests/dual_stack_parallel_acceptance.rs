//! RIL-086 第二段：Linux 双栈并行转发真实实测（同日/同实例）。
//!
//! 一个运行时实例（SOCKS5 入口 → direct 出口）同时承载 IPv4 与 IPv6
//! 两条真实回环连接：SOCKS5 请求分别以 ATYP=0x01 / ATYP=0x04 指定目标，
//! 两条流各自逐字节回显。这把矩阵里 Linux `dual_stack` 从「仅配置面
//! 有测试」（partial）推进到真实双栈并行转发（verified_local），但不
//! 冒充真实网站/QUIC+游戏并行矩阵（核心场景仍 partial）。
//!
//! 边界：本机无 v6 默认路由，只用 ::1 回环；不测外网 v6 可达性。

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rillane_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig,
    RoutingConfig, TelemetryConfig, UdpConfig,
};
use rillane_runtime::{Runtime, RuntimeBuilder, RuntimeConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// 并行测试的绑定面串行化（探端口 → 释放 → 复绑窗口不被并行测试偷走）。
static BIND_GUARD: Mutex<()> = Mutex::const_new(());

const PAYLOAD: usize = 64 * 1024;

fn free_bind() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
    format!("127.0.0.1:{}", l.local_addr().expect("端口").port())
}

/// 回环回显服务（IPv4 / IPv6 各一）。
async fn spawn_echo(bind: &str) -> u16 {
    let l = tokio::net::TcpListener::bind(bind).await.expect("回显监听");
    let port = l.local_addr().expect("端口").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    port
}

fn runtime_config(socks_bind: String) -> RillaneConfig {
    RillaneConfig {
        version: rillane_config::ConfigVersion::default(),
        control: ControlConfig {
            api_bind: "127.0.0.1:0".to_string(),
            uds_path: None,
            admin_token: None,
        },
        telemetry: TelemetryConfig {
            log_level: "warn".to_string(),
            enable_metrics: false,
            enable_tracing: false,
        },
        ingress: vec![IngressDescriptor {
            name: "dual-socks".to_string(),
            spec: IngressConfig::Socks5 {
                bind: socks_bind,
                auth: None,
                udp_enabled: Some(false),
            },
        }],
        egress: vec![EgressDescriptor {
            name: "local-direct".to_string(),
            spec: EgressConfig::Direct,
        }],
        routing: RoutingConfig {
            default_node: "local-direct".to_string(),
            ..RoutingConfig::default()
        },
        udp: UdpConfig {
            enabled: false,
            ..Default::default()
        },
        network: None,
        obfuscation: None,
        profile: None,
        scenarios: Default::default(),
        performance: None,
        egress_pool: None,
        probe: None,
        streaming: None,
    }
}

async fn start_runtime() -> (String, Arc<Runtime>) {
    let _guard = BIND_GUARD.lock().await;
    let socks_bind = free_bind();
    let runtime = Arc::new(
        RuntimeBuilder::new(runtime_config(socks_bind.clone()))
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("运行时装配"),
    );
    let _tasks = runtime.start().await.expect("启动");
    drop(_guard);
    (socks_bind, runtime)
}

#[derive(Clone, Copy)]
enum Target {
    V4(u16),
    V6(u16),
}

/// SOCKS5 无认证 CONNECT 到指定栈目标（IPv4 ATYP=0x01 / IPv6 ATYP=0x04）。
async fn socks5_connect(bind: &str, target: Target) -> tokio::net::TcpStream {
    tokio::time::timeout(Duration::from_secs(10), async move {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut s = None;
        while s.is_none() {
            match tokio::net::TcpStream::connect(bind).await {
                Ok(stream) => s = Some(stream),
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(e) => panic!("connect {bind} 失败: {e}"),
            }
        }
        let mut s = s.expect("连接入口");
        s.write_all(&[0x05, 0x01, 0x00]).await.expect("方法协商");
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.expect("方法应答");
        assert_eq!(method, [0x05, 0x00], "无认证应被选中");

        let mut req = vec![0x05, 0x01, 0x00];
        match target {
            Target::V4(port) => {
                req.push(0x01);
                req.extend_from_slice(&[127, 0, 0, 1]);
                req.extend_from_slice(&port.to_be_bytes());
            }
            Target::V6(port) => {
                req.push(0x04);
                req.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
                req.extend_from_slice(&port.to_be_bytes());
            }
        }
        s.write_all(&req).await.expect("CONNECT 请求");
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.expect("CONNECT 应答");
        assert_eq!(reply[1], 0x00, "双栈 CONNECT 应成功，实际 {reply:?}");
        s
    })
    .await
    .expect("建链 10s 内完成")
}

async fn roundtrip(bind: &str, target: Target, seed: u8) -> usize {
    let s = socks5_connect(bind, target).await;
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| seed.wrapping_add(i as u8)).collect();
    let (mut rd, mut wr) = tokio::io::split(s);
    let to_send = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&to_send).await.expect("写入");
        wr.shutdown().await.expect("半关闭");
    });
    let mut got = vec![0u8; PAYLOAD];
    let mut read = 0;
    while read < PAYLOAD {
        let n = tokio::time::timeout(Duration::from_secs(10), rd.read(&mut got[read..]))
            .await
            .expect("回读 10s 内完成")
            .expect("回读");
        assert_ne!(n, 0, "对端提前关闭");
        read += n;
    }
    writer.await.expect("写手收束");
    assert_eq!(got, payload, "双栈往返必须逐字节一致");
    drop(rd);
    read
}

/// 同一实例、同一 direct 出口，IPv4 与 IPv6 两条流**并行**真实转发。
#[tokio::test]
async fn dual_stack_targets_forward_concurrently() {
    let (socks_bind, _runtime) = start_runtime().await;
    let v4_port = spawn_echo("127.0.0.1:0").await;
    let v6_port = spawn_echo("[::1]:0").await;

    let (v4, v6) = tokio::join!(
        roundtrip(&socks_bind, Target::V4(v4_port), 0x11),
        roundtrip(&socks_bind, Target::V6(v6_port), 0xA7),
    );
    assert_eq!(v4, PAYLOAD, "IPv4 往返全量");
    assert_eq!(v6, PAYLOAD, "IPv6 往返全量");
}

/// 入口侧也可双栈：同一实例同时绑 IPv4 与 IPv6 两个 SOCKS5 入口，
/// 各自承载一条连接到 ::1 的真实流转发。
#[tokio::test]
async fn dual_stack_ingress_bindings_forward() {
    let (v4_bind, v6_bind) = {
        let _guard = BIND_GUARD.lock().await;
        let v4 = free_bind();
        let probe = std::net::TcpListener::bind("[::1]:0").expect("探 v6 端口");
        let v6 = format!("[::1]:{}", probe.local_addr().expect("v6 端口").port());
        drop(probe);
        (v4, v6)
    };
    let mut cfg = runtime_config(v4_bind.clone());
    cfg.ingress.push(IngressDescriptor {
        name: "dual-socks-v6".to_string(),
        spec: IngressConfig::Socks5 {
            bind: v6_bind.clone(),
            auth: None,
            udp_enabled: Some(false),
        },
    });
    let runtime = Arc::new(
        RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("双入口装配"),
    );
    let _tasks = runtime.start().await.expect("启动");
    let v6_port = spawn_echo("[::1]:0").await;

    let (a, b) = tokio::join!(
        roundtrip(&v4_bind, Target::V6(v6_port), 0x01),
        roundtrip(&v6_bind, Target::V6(v6_port), 0x02),
    );
    assert_eq!(a, PAYLOAD, "IPv4 入口 → IPv6 目标全量");
    assert_eq!(b, PAYLOAD, "IPv6 入口 → IPv6 目标全量");
}
