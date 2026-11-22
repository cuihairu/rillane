//! Tailcat 出口连接器契约测试（RIL-127）。
//!
//! 两层（与 tailscale_contract 同构）：
//! - **CI 可跑**（不触网）：UDP 目标具名拒绝（forward 在触达载具 Client
//!   前判负）+ tc 地址建期具名拒绝（载具 validate_address 离线校验，触网
//!   前判负，错误不回显地址内容）+ 身份私钥建期具名拒绝。这几条不建立
//!   任何 WireGuard/DERP 会话。
//! - **`#[ignore]` 真机对端**（本地手动验收，CI 不跑）：官方 tailscale/
//!   tailcat Go 服务端（BSD-3-Clause）+ 本机回显监听，本仓
//!   `TailcatConnector` 经 DERP 中继注册并对服务端伺服端口拨 TCP 回显
//!   roundtrip。环境变量（缺失即明确失败）：
//!   - `RIL_TAILCAT_ADDRESS`：Go 服务端打印的 `tc` 紧凑地址
//!   - `RIL_TAILCAT_PORT`：Go 服务端伺服的回显端口（服务端经
//!     `tailcat serve <port>` 伺服，按流转发至本机 localhost:port）
//!   - `RIL_TAILCAT_PRIVATE_KEY`（可选）：节点身份私钥；缺省临时身份
//!
//! 搭建步骤见 docs/protocol-backends.md#tailcat 真机对端小节。

use rillane_core::{EgressConnector, Flow, FlowId, FlowTarget, TargetProto};
use rillane_protocols::TailcatConnector;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// 进程级 rustls 提供者（fork 版要求显式 install_default）。
fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 合法形态的 tc 地址（结构与载具单测同构：CBOR {p,i,k} base64url-nopad）。
fn valid_address() -> String {
    use base64::Engine;
    let mut bytes = Vec::new();
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("p".into()),
            ciborium::Value::Bytes(vec![1u8; 32]),
        ),
        (
            ciborium::Value::Text("i".into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Text("k".into()),
            ciborium::Value::Bytes(vec![2u8; 32]),
        ),
    ]);
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    format!(
        "tc{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn tcp_flow(port: u16) -> (Flow, tokio::io::DuplexStream) {
    let (client, outbound_side) = tokio::io::duplex(64 * 1024);
    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: "tailcat-server".to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(outbound_side),
        metadata: Default::default(),
    };
    (flow, client)
}

fn udp_flow(port: u16) -> Flow {
    Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: "tailcat-server".to_string(),
            port,
            proto: TargetProto::Udp,
        },
        io: Box::new(tokio::io::duplex(4096).1),
        metadata: Default::default(),
    }
}

/// UDP 应用面判负：forward 在触达载具 Client 前具名拒绝（catalog udp=false
/// 口径）。合法形态地址保证拒绝发生在地址校验之后、网络之前。
#[tokio::test]
async fn udp_target_is_named_refused() {
    install_tls_provider();
    let c = TailcatConnector::new(valid_address(), None, false, None).expect("连接器");
    let flow = udp_flow(8080);
    let err = c.forward(flow).await.unwrap_err().to_string();
    assert!(err.contains("仅交付 TCP 应用面"), "UDP 应具名拒绝：{err}");
}

/// tc 地址建期具名拒绝：非法地址在构造期失败（载具 validate_address 离线
/// 校验），不建会话、不触网；错误不回显地址内容（地址含凭证）。
#[tokio::test]
async fn bad_address_is_named_at_construction() {
    install_tls_provider();
    for bad in ["", "   ", "not-a-tailcat-address", "tc!!!!"] {
        let err = TailcatConnector::new(bad.into(), None, false, None)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("server_address") || err.contains("tc 地址非法"),
            "建期具名拒绝（{bad:?}）：{err}"
        );
    }
}

/// 身份私钥建期具名拒绝：非法私钥构造期失败（载具语义：导入失败绝不
/// 静默换新钥），不生成任何身份。
#[tokio::test]
async fn bad_private_key_is_named_at_construction() {
    install_tls_provider();
    for key in ["", "not-a-key", &format!("privkey:{}", "00".repeat(32))] {
        let err = TailcatConnector::new(valid_address(), Some(key.into()), false, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("私钥非法"), "建期具名拒绝（{key:?}）：{err}");
    }
}

/// 真机对端：官方 tailscale/tailcat Go 服务端（tc 地址 + 伺服回显端口），
/// 本仓 TailcatConnector 经 DERP 注册并对服务端伺服端口拨 TCP 回显
/// roundtrip。本地手动验收用（CI 不跑：Go tailcat 进程 + tc 地址须预先
/// 就绪）。
#[tokio::test]
#[ignore = "真机对端（官方 Go tailcat serve + tc 地址），本地手动验收用"]
async fn real_peer_tailcat_roundtrip() {
    install_tls_provider();
    let address = std::env::var("RIL_TAILCAT_ADDRESS")
        .expect("RIL_TAILCAT_ADDRESS 缺失：Go tailcat serve 后导出 tc 地址");
    let port: u16 = std::env::var("RIL_TAILCAT_PORT")
        .expect("RIL_TAILCAT_PORT 缺失：Go tailcat serve 伺服端口")
        .parse()
        .expect("RIL_TAILCAT_PORT 须为端口号");
    let private_key = std::env::var("RIL_TAILCAT_PRIVATE_KEY").ok();

    let connector = TailcatConnector::new(address, private_key, false, None).expect("连接器");

    // 回显服务跑在本机 127.0.0.1（Go tailcat serve 按流转发至本机
    // localhost:port——与 tailscaled userland-proxy 同口径）。
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("本机回显监听（Go 服务端伺服端口）");
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

    let (flow, mut client) = tcp_flow(port);
    let task = tokio::spawn(async move { connector.forward(flow).await });
    let msg = b"real-peer-tailcat-echo";
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
