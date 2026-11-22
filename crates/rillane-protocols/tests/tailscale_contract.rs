//! Tailscale 出口连接器契约测试（RIL-123）。
//!
//! 两层（与 openvpn_contract 同构）：
//! - **CI 可跑**（不触达载具控制面）：UDP 目标具名拒绝（forward 在触达
//!   Device 前判负）+ 控制面 URL 建期具名拒绝。这两条不建立任何 tailnet
//!   会话、不落身份文件。
//! - **`#[ignore]` 真机对端**（本地手动验收，CI 不跑）：自托管 headscale
//!   协调面 + 官方 tailscaled Go 客户端作 tailnet 对端，本仓
//!   `TailscaleConnector` 以 preauth key 入网并对对端拨 TCP 回显 roundtrip。
//!   环境变量（缺失即明确失败）：
//!   - `RIL_TS_CONTROL_URL`：headscale 协调面（缺省 `http://127.0.0.1:8080`）
//!   - `RIL_TS_AUTH_KEY`：rillane 节点入网 preauth key（headscale
//!     `preauthkeys create`）
//!   - `RIL_TS_PEER`：对端主机名或 tailnet IP（tailscaled 对端节点；
//!     hostname 经 `peer_by_name`，IP 字面量直用）
//!   - `RIL_TS_KEY_FILE`：rillane 节点身份持久文件（缺省
//!     `/home/cui/tsrs_acceptance/keys.json`，须在持久盘）
//!
//! 搭建步骤见 docs/protocol-backends.md#tailscale 真机对端小节。

use rillane_core::{EgressConnector, Flow, FlowId, FlowTarget, TargetProto};
use rillane_protocols::TailscaleConnector;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// 进程级 rustls 提供者（fork 版要求显式 install_default）。
fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn connector() -> TailscaleConnector {
    TailscaleConnector::new(
        "http://127.0.0.1:8080".into(),
        "preauth-key-xyz".into(),
        Some("rillane-node".into()),
        true,
        "/tmp/tsrs_contract_keys.json".into(),
    )
    .expect("连接器")
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

/// UDP 应用面判负：forward 在触达 Device 前具名拒绝（catalog udp=false 口径）。
#[tokio::test]
async fn udp_target_is_named_refused() {
    install_tls_provider();
    let c = connector();
    let flow = udp_flow("100.64.0.2", 8080);
    let err = c.forward(flow).await.unwrap_err().to_string();
    assert!(
        err.contains("仅交付 TCP 应用面"),
        "UDP 应具名拒绝：{err}"
    );
}

/// 控制面 URL 建期具名拒绝：非法 URL 在构造期失败，不落身份文件、不触达
/// 载具。
#[tokio::test]
async fn bad_control_url_is_named_at_construction() {
    install_tls_provider();
    let err = TailscaleConnector::new(
        "not a url".into(),
        "preauth-key-xyz".into(),
        None,
        false,
        "/tmp/tsrs_contract_keys.json".into(),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("控制面 URL 非法"), "建期具名拒绝：{err}");
}

/// 真机对端：自托管 headscale 协调面 + 官方 tailscaled Go 客户端（tailnet
/// 对端），本仓 TailscaleConnector 以 preauth key 入网并对对端拨 TCP 回显
/// roundtrip。本地手动验收用（CI 不跑：headscale/tailscaled 进程 + 对端
/// preauth key 须预先就绪）。
#[tokio::test]
#[ignore = "真机对端（headscale + tailscaled + preauth key），本地手动验收用"]
async fn real_peer_tailnet_roundtrip() {
    install_tls_provider();
    let control_url = std::env::var("RIL_TS_CONTROL_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let auth_key = std::env::var("RIL_TS_AUTH_KEY")
        .expect("RIL_TS_AUTH_KEY 缺失：headscale preauthkeys create 后导出");
    let peer = std::env::var("RIL_TS_PEER").expect("RIL_TS_PEER 缺失：对端主机名或 tailnet IP");
    let key_file = std::env::var("RIL_TS_KEY_FILE")
        .unwrap_or_else(|_| "/home/cui/tsrs_acceptance/keys.json".to_string());

    let connector = TailscaleConnector::new(
        control_url,
        auth_key,
        Some("rillane-node".into()),
        true,
        key_file,
    )
    .expect("连接器");

    // 回显服务跑在本机 127.0.0.1（tailscaled 用户态代理把 tailnet
    // IP:PORT 转发到 localhost:PORT——对端节点须 --userland-proxy 缺省）。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("本机回显监听");
    let echo_port = listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let Ok((mut stream, _addr)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 512];
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

    let (flow, mut client) = tcp_flow(&peer, echo_port);
    let task = tokio::spawn(async move { connector.forward(flow).await });
    let msg = b"real-peer-tailscale-echo";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    let n = timeout(Duration::from_secs(60), client.read_exact(&mut buf))
        .await
        .expect("回显超时")
        .expect("读回显");
    assert_eq!(&buf[..n], msg, "真实对端应回显");
    echo_task.abort();
    drop(client);
    let report = timeout(Duration::from_secs(5), task)
        .await
        .expect("forward 超时")
        .expect("forward 错误")
        .expect("forward 失败");
    assert!(
        report.upstream >= msg.len() as u64,
        "upstream 计入：{:?}",
        report
    );
}
