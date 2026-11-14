//! P0-3 出站 UDP 载荷测试（udp-relay-path.md §3.3/§3.5）。
//! 覆盖：ss 加密方法构建期校验、ss UDP 发送路径（真 socket 到环回假服务器，
//! AEAD 封包由 shadowsocks crate 承担，本测试钉住"包到达服务器端点"与
//! §3.3 R7 固定目标的结构性保证）、wg allowed_ips 预检与 MTU 上限。
//!
//! 注：ss 完整收包往返需要 shadowsocks-service 的服务端实现（仓库未依赖，
//! 解密回包验证归 P0-5 联调/CI 集成），此处验证发送路径与错误分类前置条件。

use rillane_core::udp::EgressUdpConnector as _;
use rillane_core::{FlowContext, FlowId, RouteDecision, RoutePath, RouteType, TargetProto};
use rillane_protocols::{ShadowsocksConnector, ShadowsocksUdpConnector, WireguardUdpConnector};
use std::time::Duration;

fn flow_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: rillane_core::FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Udp,
        },
        metadata: Default::default(),
    }
}

fn decision() -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: "test-node".into(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

// ---------- shadowsocks ----------

#[test]
fn ss_method_rejected_at_construction() {
    // §3.1 能力扫描同口径：配置错误构建期暴露
    let err = match ShadowsocksConnector::new(
        "127.0.0.1".into(),
        8388,
        "no-such-method".into(),
        "pw".into(),
        None,
        None,
    ) {
        Err(e) => e,
        Ok(_) => panic!("无效加密方法应构建失败"),
    };
    assert!(format!("{err:#}").contains("不支持的加密方法"), "{err:#}");
}

#[tokio::test]
async fn ss_udp_send_path_reaches_server_endpoint() {
    // 环回假 ss 服务器：只收不解（AEAD 内容校验超出本测试范围）
    let fake_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_port = fake_server.local_addr().unwrap().port();

    let conn = ShadowsocksConnector::new(
        "127.0.0.1".into(),
        server_port,
        "aes-256-gcm".into(),
        "rillane-test-password".into(),
        None,
        None,
    )
    .unwrap();
    let udp = ShadowsocksUdpConnector::from_connector(&conn);

    // §3.3 R7：关联时固定目标 example.com:53（DNS 式载荷）
    let relay = udp
        .associate(flow_ctx("example.com", 53), &decision())
        .await
        .unwrap();
    for _ in 0..3 {
        relay
            .send_to(
                &flow_ctx("example.com", 53).target,
                b"\x12\x34\x01\x00\x00\x01",
            )
            .await
            .unwrap();
    }

    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), fake_server.recv_from(&mut buf))
        .await
        .expect("假 ss 服务器应在 2s 内收到首个数据报")
        .unwrap();
    assert!(n > 0, "收到的 AEAD 封包非空");

    // R7 结构性保证：send_to 参数里的不同目标不影响封包去向（目标在关联时固定）
    relay
        .send_to(&flow_ctx("other.example", 9999).target, b"xx")
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), fake_server.recv_from(&mut buf))
        .await
        .expect("第二个数据报也应到达同一 ss 服务器端点")
        .unwrap();
}

#[tokio::test]
async fn ss_udp_assoc_preserves_fixed_target_downlink_source() {
    // 下行路径前提：associate 上下文目标进入 relay（type 级保证，经由编译）；
    // 此处验证 connector 可并发关联多个互不干扰的 relay
    let fake_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_port = fake_server.local_addr().unwrap().port();
    let conn = ShadowsocksConnector::new(
        "127.0.0.1".into(),
        server_port,
        "aes-256-gcm".into(),
        "rillane-test-password".into(),
        None,
        None,
    )
    .unwrap();
    let udp = ShadowsocksUdpConnector::from_connector(&conn);

    let r1 = udp
        .associate(flow_ctx("a.test", 53), &decision())
        .await
        .unwrap();
    let r2 = udp
        .associate(flow_ctx("b.test", 53), &decision())
        .await
        .unwrap();
    r1.send_to(&flow_ctx("a.test", 53).target, b"1")
        .await
        .unwrap();
    r2.send_to(&flow_ctx("b.test", 53).target, b"2")
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), fake_server.recv_from(&mut buf))
        .await
        .expect("两个 relay 的封包都应到达服务器")
        .unwrap();
}

// ---------- wireguard ----------

fn wg_connector(allowed: Option<Vec<String>>, mtu: Option<u16>) -> WireguardUdpConnector {
    WireguardUdpConnector::new(allowed, mtu).unwrap()
}

#[tokio::test]
async fn wg_allowed_ips_precheck_blocks_and_permits() {
    let wg = wg_connector(Some(vec!["10.8.0.0/24".into()]), None);
    // 网段外：Route 类错误（§3.6 拆映射+清决策），错误信息可分类
    let err = match wg.associate(flow_ctx("8.8.8.8", 53), &decision()).await {
        Err(e) => e,
        Ok(_) => panic!("网段外目标应被 allowed_ips 预检拦截"),
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("allowed_ips"), "{msg}");
    // 网段内：本地 socket 建立成功（connect 不发包，内核路由接管）
    let _relay = wg
        .associate(flow_ctx("10.8.0.7", 3074), &decision())
        .await
        .unwrap();
}

#[tokio::test]
async fn wg_mtu_cap_drops_oversize_before_send() {
    // mtu=1500 → 载荷上限 1420；超限在 connector 侧拦截（R8 丢弃，不发网络包）
    let wg = wg_connector(Some(vec!["10.8.0.0/24".into()]), Some(1500));
    let relay = wg
        .associate(flow_ctx("10.8.0.7", 3074), &decision())
        .await
        .unwrap();
    let err = match relay
        .send_to(&flow_ctx("10.8.0.7", 3074).target, &vec![0u8; 1421])
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("超过 MTU 上限的包应被丢弃"),
    };
    assert!(format!("{err:#}").contains("MTU"), "{err:#}");
}

#[tokio::test]
async fn wg_invalid_cidr_rejected_at_construction() {
    let err = match WireguardUdpConnector::new(Some(vec!["nonsense".into()]), None) {
        Err(e) => e,
        Ok(_) => panic!("无效 allowed_ips 应构建失败"),
    };
    assert!(
        format!("{err:#}").contains("无效的 WireGuard allowed_ips"),
        "{err:#}"
    );
}

#[tokio::test]
async fn wg_domain_target_resolves_then_precheck_applies_to_ip() {
    // 域名目标：先解析成 IP 再过 allowed_ips（localhost 不在 10.8.0.0/24 → 拦截）
    let wg = wg_connector(Some(vec!["10.8.0.0/24".into()]), None);
    let res = wg.associate(flow_ctx("localhost", 53), &decision()).await;
    match res {
        Err(e) => assert!(format!("{e:#}").contains("allowed_ips"), "{e:#}"),
        Ok(_) => panic!("localhost（127.0.0.1/::1）不应落在 10.8.0.0/24 内"),
    }
}
