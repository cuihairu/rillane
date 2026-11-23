//! SSH 出站连接器契约测试。
//!
//! 构造期校验为密闭测试（不依赖外设）；连接/认证/数据面测试对真实
//! OpenSSH sshd 对端运行（127.0.0.1:23411，/tmp/sshpeer 独立配置——
//! 本席验收外设：authorized_keys 持 user 与 user_ppk 两把公钥，
//! user_ppk 为带口令 OpenSSH 加密键，PerSourcePenalties 已关——负例
//! 测试的认证失败会按源累积处罚；对端测试另有串行闸（PEER_SERIAL）
//! ——预认证阶段对并发拨号存在概率性拒绝面，正例不因负例连坐）：
//! 对端缺席时降级为记名跳过（CI 无外设环境下伪造失败比静默跳过更
//! 不诚实，故此口径），跳过不计入验收——验收断言以本席真机运行为准。

use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use rillane_core::{FlowId, TargetProto};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;

/// 真实对端（本席 /tmp/sshpeer 专用 sshd 实例）
const PEER_ADDR: &str = "127.0.0.1:23411";
const PEER_USER: &str = "cui";
const PEER_KEY: &str = "/tmp/sshpeer/user";
const PEER_KEY_ENC: &str = "/tmp/sshpeer/user_ppk";
const PEER_KEY_ENC_PW: &str = "testpw123";
const PEER_HOST_PUB: &str = "/tmp/sshpeer/host_ed25519.pub";

/// 真实对端测试串行闸：sshd 是系统外设，预认证阶段（MaxStartups 计数）
/// 对并发拨号存在概率性拒绝面——串行化消除测试间交叉干扰（正例不因负例
/// 的认证失败而遭连坐）
static PEER_SERIAL: Mutex<()> = Mutex::new(());

fn peer_ready() -> bool {
    let files_ok = [PEER_HOST_PUB, PEER_KEY, PEER_KEY_ENC]
        .iter()
        .all(|p| Path::new(p).exists());
    let port_ok = std::net::TcpStream::connect_timeout(
        &PEER_ADDR.parse().expect("对端地址解析"),
        Duration::from_secs(2),
    )
    .is_ok();
    files_ok && port_ok
}

/// 钉扎指纹从主机钥公钥文件现算（确定性，不依赖先连一次捕获）
fn host_pin() -> String {
    let content = std::fs::read_to_string(PEER_HOST_PUB).expect("主机钥公钥读取");
    let key = ssh_key::PublicKey::from_openssh(&content).expect("主机钥公钥解析");
    key.fingerprint(ssh_key::HashAlg::Sha256)
        .to_string()
        .trim_start_matches("SHA256:")
        .to_string()
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

/// 回环 echo（循环读-写至对端半关，支持多写大块）。回传 accept 信号
/// oneshot（sshd 已拨入 = direct-tcpip 通道已建立）与任务句柄（撤销后
/// 读到 EOF 退出 = 对端资源释放可观测）。
async fn echo_target() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo 绑定");
    let addr = listener.local_addr().expect("echo 地址");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("echo 接受");
        let _ = accepted_tx.send(());
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    (addr, accepted_rx, handle)
}

// -----------------------------------------------------------------------
// 构造期校验（密闭，不依赖外设）
// -----------------------------------------------------------------------

/// 钉扎必填 + 认证恰一选一（双带/双缺/空面均具名拒绝）+ 前缀剥离。
#[test]
fn constructor_requires_pin_and_exactly_one_auth() {
    // 无钉扎（首用即信是具名拒绝的降级面）
    let e = SshConnector::new("203.0.113.9", 22, "cui", Some("pw".into()), None, None, "")
        .expect_err("无钉扎应被拒");
    let m = format!("{e:#}");
    assert!(m.contains("host_key"), "无钉扎具名: {m}");

    // 认证双带
    let e = SshConnector::new(
        "203.0.113.9",
        22,
        "cui",
        Some("pw".into()),
        Some("/tmp/k".into()),
        None,
        "SHA256:abc",
    )
    .expect_err("双带应被拒");
    assert!(format!("{e:#}").contains("恰一"), "双带具名: {e:#}");

    // 认证双缺
    let e = SshConnector::new("203.0.113.9", 22, "cui", None, None, None, "SHA256:abc")
        .expect_err("双缺应被拒");
    assert!(format!("{e:#}").contains("恰一"), "双缺具名: {e:#}");

    // 空密码面 / 空私钥路径
    let e = SshConnector::new(
        "203.0.113.9",
        22,
        "cui",
        Some(String::new()),
        None,
        None,
        "SHA256:abc",
    )
    .expect_err("空密码应被拒");
    assert!(format!("{e:#}").contains("密码认证面"), "空密码具名: {e:#}");
    let e = SshConnector::new(
        "203.0.113.9",
        22,
        "cui",
        None,
        Some(String::new()),
        None,
        "SHA256:abc",
    )
    .expect_err("空私钥路径应被拒");
    assert!(format!("{e:#}").contains("私钥路径"), "空路径具名: {e:#}");

    // 合法构造（钉扎前缀可带可不带）
    let c = SshConnector::new(
        "203.0.113.9",
        22,
        "cui",
        None,
        Some("/tmp/k".into()),
        None,
        "SHA256:abc",
    )
    .expect("带前缀合法");
    assert_eq!(c.name(), "ssh");
    SshConnector::new(
        "203.0.113.9",
        22,
        "cui",
        Some("pw".into()),
        None,
        None,
        "abc",
    )
    .expect("裸指纹合法");
}

// -----------------------------------------------------------------------
// 真实对端：连接 + 钉扎 + 认证 + direct-tcpip 数据面
// -----------------------------------------------------------------------

/// 整链回环（公钥认证）：sshd 握手 → 钉扎命中 → publickey 认证 →
/// direct-tcpip 通道 → 双向转发逐字节还原（含多写大块）+ 字节计数。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn real_sshd_roundtrip_publickey_auth() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    let connector = Arc::new(
        SshConnector::new(
            "127.0.0.1",
            23411,
            PEER_USER,
            None,
            Some(PEER_KEY.into()),
            None,
            host_pin(),
        )
        .expect("构造"),
    );
    let (target, _accepted, _echo) = echo_target().await;
    let (flow, mut client) = make_flow(&target.ip().to_string(), target.port());
    let relay = {
        let connector = connector.clone();
        tokio::spawn(async move { connector.forward(flow).await })
    };

    let payload: Vec<u8> = (0..8000u32).map(|i| (i % 251) as u8).collect();
    client.write_all(b"ssh direct-tcpip").await.expect("上行写");
    client.write_all(&payload).await.expect("上行大块写");
    client.shutdown().await.expect("上行半关");

    let report = relay.await.expect("join").expect("forward 成功");

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), client.read_to_end(&mut got))
        .await
        .expect("下行超时")
        .expect("下行读");

    let mut expected = b"ssh direct-tcpip".to_vec();
    expected.extend_from_slice(&payload);
    assert_eq!(got, expected, "direct-tcpip 通道回环逐字节还原");

    assert_eq!(report.upstream as usize, expected.len(), "上行计数");
    assert_eq!(report.downstream as usize, expected.len(), "下行计数");
}

/// 整链回环（加密私钥 + 口令解码）：OpenSSH KDF 加密键携口令解码后
/// 同面走通。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn real_sshd_roundtrip_encrypted_key() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    let connector = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        None,
        Some(PEER_KEY_ENC.into()),
        Some(PEER_KEY_ENC_PW.into()),
        host_pin(),
    )
    .expect("构造");
    let (target, _accepted, _echo) = echo_target().await;
    let (flow, mut client) = make_flow(&target.ip().to_string(), target.port());
    let relay = tokio::spawn(async move { connector.forward(flow).await });

    client
        .write_all(b"encrypted key path")
        .await
        .expect("上行写");
    client.shutdown().await.expect("上行半关");

    let report = relay.await.expect("join").expect("forward 成功");

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), client.read_to_end(&mut got))
        .await
        .expect("下行超时")
        .expect("下行读");
    assert_eq!(got, b"encrypted key path", "加密键路径回环还原");

    assert_eq!(
        report.upstream,
        b"encrypted key path".len() as u64,
        "上行计数"
    );
}

/// 钉扎不符：连接期拒绝且具名透出期望/实际指纹（观测槽跨 handler
/// 消费留存）。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn wrong_host_key_pin_refused_with_named_error() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    let connector = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        None,
        Some(PEER_KEY.into()),
        None,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .expect("构造");
    let (flow, _client) = make_flow("127.0.0.1", 9);
    let err = connector.forward(flow).await.expect_err("钉扎不符应拒绝");
    let m = format!("{err:#}");
    assert!(
        m.contains("主机钥不符") && m.contains("期望") && m.contains("实际"),
        "具名透出期望/实际: {m}"
    );
}

/// 错密码：真实 sshd 服务端拒绝（PasswordAuthentication yes）→ 认证
/// 被拒具名透出。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn wrong_password_refused_by_real_sshd() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    let connector = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        Some("definitely-not-the-password-9x8y7z".into()),
        None,
        None,
        host_pin(),
    )
    .expect("构造");
    let (flow, _client) = make_flow("127.0.0.1", 9);
    let err = connector.forward(flow).await.expect_err("错密码应被拒");
    let m = format!("{err:#}");
    assert!(m.contains("认证"), "认证拒绝具名: {m}");
}

/// 加密键口令面：无口令具名拒绝；错口令解码失败具名拒绝（两例均在
/// 连接 + 钉扎命中后、认证前发生，需真实对端）。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn encrypted_key_passphrase_faces_named_refusal() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    // 无口令
    let c = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        None,
        Some(PEER_KEY_ENC.into()),
        None,
        host_pin(),
    )
    .expect("构造");
    let (flow, _client) = make_flow("127.0.0.1", 9);
    let err = c.forward(flow).await.expect_err("加密键无口令应被拒");
    assert!(
        format!("{err:#}").contains("已加密但未提供口令"),
        "无口令具名: {err:#}"
    );

    // 错口令
    let c = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        None,
        Some(PEER_KEY_ENC.into()),
        Some("wrong-pw".into()),
        host_pin(),
    )
    .expect("构造");
    let (flow, _client) = make_flow("127.0.0.1", 9);
    let err = c.forward(flow).await.expect_err("错口令应被拒");
    assert!(
        format!("{err:#}").contains("口令解码失败"),
        "错口令具名: {err:#}"
    );
}

/// 取消面 + 资源释放：转发任务中途撤销 → direct-tcpip 通道收束
/// （echo 对端读到 EOF 退出）——通道与 SSH 连接不悬挂。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn cancel_mid_relay_closes_channel_and_releases_peer() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    let connector = Arc::new(
        SshConnector::new(
            "127.0.0.1",
            23411,
            PEER_USER,
            None,
            Some(PEER_KEY.into()),
            None,
            host_pin(),
        )
        .expect("构造"),
    );
    let (target, mut accepted, echo) = echo_target().await;
    let (flow, mut client) = make_flow(&target.ip().to_string(), target.port());
    let relay = tokio::spawn(async move { connector.forward(flow).await });

    client.write_all(b"partial").await.expect("上行写");
    // 不半关——转发挂在中继态；撤销前等 echo accept 信号（sshd 拨入 =
    // direct-tcpip 通道已建立且对端资源确实存在——固定时窗在满载下会
    // 撤销在通道建立前，可观测面不成立）
    tokio::time::timeout(Duration::from_secs(15), &mut accepted)
        .await
        .expect("通道建立超时（sshd 未拨入 echo）")
        .expect("accept 信号面不应关闭");
    relay.abort();
    let _ = relay.await;

    // 客户侧资源释放：flow.io 随任务撤销丢弃 → client 读面即刻收束
    let mut sink = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(5), client.read(&mut sink))
        .await
        .expect("客户侧收束超时（撤销后流未释放）")
        .expect("duplex 读面");
    // 对端资源释放：通道 Close → sshd 收束 → echo 读到 EOF 退出
    tokio::time::timeout(Duration::from_secs(10), echo)
        .await
        .expect("通道收束超时（撤销后 echo 未退出）")
        .expect("echo 任务不应 panic");
}

/// 私钥文件缺失：读取失败具名透出（连接 + 钉扎命中后到达）。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn missing_key_file_named_refusal() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }
    let connector = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        None,
        Some("/tmp/sshpeer/does-not-exist".into()),
        None,
        host_pin(),
    )
    .expect("构造");
    let (flow, _client) = make_flow("127.0.0.1", 9);
    let err = connector.forward(flow).await.expect_err("键文件缺失应被拒");
    assert!(
        format!("{err:#}").contains("私钥文件读取失败"),
        "缺失具名: {err:#}"
    );
}

// -----------------------------------------------------------------------
// 平台旁路拨号面 + keepalive 生命周期
// -----------------------------------------------------------------------

/// 平台旁路拨号面（RIL-113 验收「平台旁路」项）：底传输由调用方经前置
/// 跳板建立（本地 TCP 前置 → sshd），`forward_over` 只做 SSH 会话——
/// russh 从不拨号，会话骑在调用方拨的前置流上，与连接器配置的
/// server/port 拨号路径解耦。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn platform_bypass_forward_over_fronted_stream() {
    #[allow(clippy::await_holding_lock)]
    let _serial = PEER_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !peer_ready() {
        eprintln!("跳过：真实 sshd 对端缺席 (127.0.0.1:23411)");
        return;
    }

    // 前置跳板 = 本面之外的拨号路径（模拟平台前置/代理跳板）
    let front = TcpListener::bind("127.0.0.1:0").await.expect("前置绑定");
    let front_addr = front.local_addr().expect("前置地址");
    let hop = tokio::spawn(async move {
        let (mut down, _) = front.accept().await.expect("前置接受");
        let mut up = TcpStream::connect(PEER_ADDR).await.expect("前置连 sshd");
        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
    });

    let connector = SshConnector::new(
        "127.0.0.1",
        23411,
        PEER_USER,
        None,
        Some(PEER_KEY.into()),
        None,
        host_pin(),
    )
    .expect("构造");
    let (target, _accepted, _echo) = echo_target().await;
    let (flow, mut client) = make_flow(&target.ip().to_string(), target.port());
    let bottom = TcpStream::connect(front_addr).await.expect("调用方拨前置");

    let relay = tokio::spawn(async move { connector.forward_over(flow, bottom).await });

    client.write_all(b"platform bypass").await.expect("上行写");
    client.shutdown().await.expect("上行半关");

    let report = relay.await.expect("join").expect("forward_over 成功");

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), client.read_to_end(&mut got))
        .await
        .expect("下行超时")
        .expect("下行读");
    assert_eq!(got, b"platform bypass", "前置底传输回环逐字节还原");
    assert_eq!(
        report.upstream,
        b"platform bypass".len() as u64,
        "上行计数（统计面走旁路拨号同样成立）"
    );

    drop(hop);
}

/// keepalive 配置（连接生命周期）：30s 探测 / 3 次无回应收束——密闭
/// 断言配置值（russh 缺省 None，长空闲流原依服务端 sshd 策略；探测的
/// 长空闲行为需 >90s 空闲窗口不入套件，具名边界）。
#[test]
fn client_config_carries_keepalive_lifecycle() {
    let config = client_config();
    assert_eq!(
        config.keepalive_interval,
        Some(Duration::from_secs(30)),
        "keepalive 探测间隔"
    );
    assert_eq!(config.keepalive_max, 3, "keepalive 无回应上限");
    let default = client::Config::default();
    assert_eq!(
        default.keepalive_interval, None,
        "russh 缺省无 keepalive——探测面由本连接器注入而非库缺省"
    );
}
