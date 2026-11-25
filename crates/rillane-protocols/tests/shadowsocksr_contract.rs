//! RIL-115 ShadowsocksR 合同验收（真实对端 ssr-native C 服务端回环）。
//!
//! 对端是 ShadowsocksR-Native（GPL）C 服务端二进制，不在仓内——测试以
//! `SSR_PEER_BIN`（缺省 `/home/cui/ssrrefs/ssrnative/build-debug/src/ssr-server`）指向该对端；
//! 对端缺失时本测试整体跳过（外部进程不属仓内可复现面，真值由
//! protocol-backends.md#shadowsocksr 记录）。对端仅作验收对端，非本仓
//! 承载代码，授权语义归上游 README（见协议评估留证）。
//!
//! 验收面：
//! 成功——TCP 4KB 二进制经真实 ssr-server 服务端往返（protocol
//!       auth_aes128_md5、obfs plain）；
//! 失败——错密码对端解不开，回声不达；
//! 构建——method/protocol/obfs 未交付名构建期点名拒绝。

use std::{net::SocketAddr, time::Duration};

use rillane_core::{EgressConnector as _, Flow, FlowId, TargetProto};
use rillane_protocols::ShadowsocksrConnector;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

/// 对端二进制路径（可被环境变量覆盖）。
/// 缺省取 Debug 构建——ssr-native 的 Release 构建在本席被 `-O3` 误编译，
/// `init_obfs` 段启动即崩溃（SIGSEGV，随机源指针损坏），Debug 构建正常
/// 启动监听（2026-11-23 实机核验），故 Debug 为可用验收对端。
fn peer_bin() -> String {
    std::env::var("SSR_PEER_BIN")
        .unwrap_or_else(|_| "/home/cui/ssrrefs/ssrnative/build-debug/src/ssr-server".into())
}

fn flow_of(target: rillane_core::FlowTarget, io: DuplexStream) -> Flow {
    Flow {
        id: FlowId::new(),
        target,
        io: Box::new(io),
        metadata: Default::default(),
    }
}

fn tcp_flow_target(host: &str, port: u16) -> rillane_core::FlowTarget {
    rillane_core::FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Tcp,
    }
}

/// 纯 TCP 回声端（ssr-server 从 SSR 协议头解析目标后真实转发到此）
async fn spawn_plain_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn deterministic(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 13) as u8).collect()
}

/// 申请一个空闲端口（绑定后立即释放，供 ssr-server 配置绑定）
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe free port")
        .local_addr()
        .unwrap()
        .port()
}

/// 启动真实 ssr-server 对端（后台子进程），等待端口就绪
/// 返回 (子进程, 对端日志文件)——失败面诊断用（ssr-native 把拒绝原因写 stderr）
async fn spawn_ssr_peer(
    port: u16,
    method: &str,
    password: &str,
    protocol: &str,
    obfs: &str,
) -> (tokio::process::Child, std::path::PathBuf) {
    let bin = peer_bin();
    let dir = tempfile_dir();
    // 并行测试共用临时目录，config/log 均按端口命名避免互写
    let cfg_path = dir.join(format!("ssr-server-{port}.json"));
    let log_path = dir.join(format!("peer-{port}.log"));
    let cfg = format!(
        r#"{{
    "password": "{password}",
    "method": "{method}",
    "protocol": "{protocol}",
    "protocol_param": "",
    "obfs": "{obfs}",
    "obfs_param": "",
    "udp": false,
    "idle_timeout": 30,
    "connect_timeout": 6,
    "udp_timeout": 6,
    "server_settings": {{
        "listen_address": "127.0.0.1",
        "listen_port": {port}
    }}
}}"#
    );
    std::fs::write(&cfg_path, cfg).expect("write ssr config");
    let log = std::fs::File::create(&log_path).expect("peer log file");
    let log_err = log.try_clone().expect("clone peer log");

    let mut child = tokio::process::Command::new(&bin)
        .arg("-c")
        .arg(&cfg_path)
        .stdout(log)
        .stderr(log_err)
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("启动对端 {bin}: {e}"));

    // 端口就绪轮询（子进程启动 + 绑定窗口）
    let mut ready = false;
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    if !ready {
        let _ = child.kill().await;
        panic!(
            "ssr-server 端口 {port} 未就绪（对端日志）：{}",
            peer_log_text(&log_path)
        );
    }
    (child, log_path)
}

/// 读对端日志（诊断面；失败时把 ssr-native 的拒绝原因透出）
fn peer_log_text(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// 临时目录（config.json 配置文件落点）
fn tempfile_dir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("ssr-interop-{}", std::process::id()));
    std::fs::create_dir_all(&base).expect("tmp dir");
    base
}

// ---------- 成功面：TCP 往返 ----------

#[tokio::test]
async fn tcp_roundtrip_against_native_peer() {
    let bin = peer_bin();
    if !std::path::Path::new(&bin).exists() {
        eprintln!("[skip] ssr 对端缺失（{bin}）——外部进程不在仓内，验收留 protocol-backends.md");
        return;
    }

    let password = "interop-password";
    let method = "aes-128-ctr";
    let protocol = "auth_aes128_md5";
    let obfs = "plain";
    let port = free_port().await;
    let echo = spawn_plain_tcp_echo().await;
    let (mut peer, log_path) = spawn_ssr_peer(port, method, password, protocol, obfs).await;

    let conn = ShadowsocksrConnector::new(
        "127.0.0.1".to_string(),
        port,
        method.to_string(),
        password.to_string(),
        protocol.to_string(),
        obfs.to_string(),
        None,
        None,
    )
    .expect("connector 构建");

    let (mut user, ingress) = tokio::io::duplex(64 * 1024);
    let flow = flow_of(tcp_flow_target("127.0.0.1", echo.port()), ingress);
    let _fwd = tokio::spawn(async move { conn.forward(flow).await });

    let payload = deterministic(4096);
    user.write_all(&payload).await.expect("客户端写入");
    let mut back = vec![0u8; payload.len()];
    let got = timeout(Duration::from_secs(5), user.read_exact(&mut back)).await;
    if got.is_err() || !matches!(got, Ok(Ok(_))) {
        panic!(
            "客户端回读失败（对端日志）：{got:?}；{}",
            peer_log_text(&log_path)
        );
    }
    assert_eq!(back, payload, "经真实 ssr-server 往回声字节须逐字节相等");

    let _ = peer.kill().await;
    let _ = peer.wait().await;
}

// ---------- 失败面：错密码回声不达 ----------

#[tokio::test]
async fn wrong_password_yields_no_echo() {
    let bin = peer_bin();
    if !std::path::Path::new(&bin).exists() {
        eprintln!("[skip] ssr 对端缺失（{bin}）");
        return;
    }

    let port = free_port().await;
    let echo = spawn_plain_tcp_echo().await;
    let (mut peer, log_path) = spawn_ssr_peer(
        port,
        "aes-128-ctr",
        "right-pass",
        "auth_aes128_md5",
        "plain",
    )
    .await;

    // 客户端侧密码与对端不一致 → 对端解不开，回声不达
    let conn = ShadowsocksrConnector::new(
        "127.0.0.1".to_string(),
        port,
        "aes-128-ctr".to_string(),
        "wrong-pass".to_string(),
        "auth_aes128_md5".to_string(),
        "plain".to_string(),
        None,
        None,
    )
    .expect("connector 构建");

    let (mut user, ingress) = tokio::io::duplex(64 * 1024);
    let flow = flow_of(tcp_flow_target("127.0.0.1", echo.port()), ingress);
    let _fwd = tokio::spawn(async move { conn.forward(flow).await });

    let payload = deterministic(64);
    let _ = user.write_all(&payload).await;
    let mut back = vec![0u8; payload.len()];
    let got = timeout(Duration::from_secs(3), user.read_exact(&mut back)).await;
    // 回声不得达：读侧超时或对端终止（EOF/IO 错）皆为预期；
    // 只有完整读到回声字节才算失败。
    match got {
        Err(_) => {}     // 读超时
        Ok(Err(_)) => {} // 对端拒绝后终止连接（对端日志可见拒绝原因）
        Ok(Ok(_)) => panic!(
            "错密码回声不得达（读到回声字节；对端日志：{}）",
            peer_log_text(&log_path)
        ),
    }

    let _ = peer.kill().await;
    let _ = peer.wait().await;
}

// ---------- 构建面：未交付名点名拒绝 ----------

#[test]
fn connector_rejects_unsupported_names() {
    let ok = |m: &str, p: &str, o: &str| {
        ShadowsocksrConnector::new(
            "127.0.0.1".to_string(),
            8388,
            m.to_string(),
            "pw".to_string(),
            p.to_string(),
            o.to_string(),
            None,
            None,
        )
    };
    let err =
        ok("chacha20-ietf-poly1305", "auth_aes128_sha1", "plain").expect_err("未交付加密法须拒绝");
    assert!(err.to_string().contains("chacha20-ietf-poly1305"), "{err}");
    let err = ok("aes-128-ctr", "origin", "plain").expect_err("origin 须拒绝");
    assert!(err.to_string().contains("origin"), "{err}");
    let err =
        ok("aes-128-ctr", "auth_aes128_sha1", "tls1.2_ticket_auth").expect_err("未交付混淆须拒绝");
    assert!(err.to_string().contains("tls1.2_ticket_auth"), "{err}");
}
