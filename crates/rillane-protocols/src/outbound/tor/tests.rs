//! Tor 出站连接器契约测试。
//!
//! 构造期校验为密闭测试（不依赖外设）；数据面对真实 Tor 网络运行——
//! 前置代理 URI 取环境 `RILLANE_TOR_FRONT`（本席原始出网被防火墙拦截，
//! 引导必经局域网 HTTP 代理前置，探针已验证该面；该 URI 是席位局域网
//! 配置，其他环境可设为自己的可用前置）。环境缺席时降级为记名跳过
//! （与 ssh 对端测试同口径：CI 无外设环境下伪造失败比静默跳过更不诚实），
//! 跳过不计入验收——验收断言以本席真机运行为准。运行时形态用
//! multi_thread（生产面 rillane-ffi 即 new_multi_thread，且为本席探针
//! 200 OK 往返的验证形态）。

use std::{sync::Arc, time::Duration};

use rillane_core::{Flow, FlowId, TargetProto};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// 前置代理 URI（本席=局域网 HTTP 代理；未设则真实网络测试记名跳过）
const FRONT_ENV: &str = "RILLANE_TOR_FRONT";

// -----------------------------------------------------------------------
// 构造期校验（密闭，不依赖外设）
// -----------------------------------------------------------------------

/// 前置代理 URI 经 arti 自家解析器具名校验：不支持方案 / 域名主机 /
/// 缺端口 / 越界端口均拒；None 与空串均视为未设置（合法）。
#[test]
fn constructor_proxy_uri_validation() {
    // 不支持的方案（注：非缺省端口——url crate 对方案缺省端口返回 None，
    // 会先落缺端口的具名错误）
    let e = TorConnector::new(Some("ftp://1.2.3.4:2222".into())).expect_err("ftp 方案应被拒");
    let m = format!("{e:#}");
    assert!(m.contains("Tor 通道前置代理 URI 无效"), "具名拒绝: {m}");
    assert!(m.contains("ftp"), "方案具名透出: {m}");

    // 域名主机（arti 仅认 IP）
    let e = TorConnector::new(Some("http://example.com:8080".into())).expect_err("域名主机应被拒");
    let m = format!("{e:#}");
    assert!(m.contains("Tor 通道前置代理 URI 无效"), "具名拒绝: {m}");

    // 缺端口
    let e = TorConnector::new(Some("http://1.2.3.4".into())).expect_err("缺端口应被拒");
    assert!(
        format!("{e:#}").contains("Tor 通道前置代理 URI 无效"),
        "缺端口具名: {e:#}"
    );

    // 越界端口
    let e = TorConnector::new(Some("socks5://10.0.0.1:99999".into())).expect_err("越界端口应被拒");
    assert!(
        format!("{e:#}").contains("Tor 通道前置代理 URI 无效"),
        "越界端口具名: {e:#}"
    );

    // 合法构造：None / 空串（=未设置）/ http / socks5
    let c = TorConnector::new(None).expect("None 合法");
    assert_eq!(c.name(), "tor");
    assert!(c.front.is_none(), "None → 直连");
    let c = TorConnector::new(Some(String::new())).expect("空串合法");
    assert!(c.front.is_none(), "空串 → 未设置（arti 同语义）");
    let c = TorConnector::new(Some("  ".into())).expect("空白串合法");
    assert!(c.front.is_none(), "空白串 → 未设置");
    let c = TorConnector::new(Some("http://127.0.0.1:7897".into())).expect("http 合法");
    assert!(c.front.is_some(), "http 前置留存");
    let c = TorConnector::new(Some("socks5://10.0.0.1:1080".into())).expect("socks5 合法");
    assert!(c.front.is_some(), "socks5 前置留存");

    // Debug 面不展开客户端内部（引导状态布尔 + 前置代理）
    let d = format!("{c:?}");
    assert!(d.contains("TorConnector"), "Debug 面含类型名: {d}");
    assert!(d.contains("bootstrapped: false"), "Debug 面含引导状态: {d}");
}

// -----------------------------------------------------------------------
// 真实 Tor 网络：引导共享 + 逐流隔离 + flush 泵数据面
// -----------------------------------------------------------------------

/// 双流整链：首流触发惰性引导（共享客户端成活）→ isolated_client 隔离
/// 流 → HTTP/1.0 GET 经真实电路往返（200 响应体逐字节可见）→ 次流复用
/// 同一客户端（client_cell 已初始化，无重复引导）→ 双流字节计数非零。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tor_two_flows_shared_bootstrap_http_roundtrip() {
    let Some(front) = std::env::var(FRONT_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    else {
        eprintln!(
            "跳过：真实 Tor 网络前置未配置（设 {FRONT_ENV}=<proxy-uri> 启用，\
             例 http://IP:port——本席原始出网被防火墙拦截，直连环境该项可空置）"
        );
        return;
    };
    let connector = Arc::new(TorConnector::new(Some(front)).expect("前置 URI 合法"));
    assert!(!format!("{connector:?}").contains("bootstrapped: true"));

    // 双流（串行驱动：首流引导，次流复用；引导不可观测的重叠无意义）
    for i in 1..=2 {
        let (flow, mut client) = make_flow("example.com", 80);
        let fwd = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.forward(flow).await })
        };

        // 客户端侧：发请求 → 读到 200 响应与 EOF（HTTP/1.0 服务端关连接）
        // → 收尾关写半（上行泵见 EOF，forward 得以收束）
        const REQ: &str = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(60), async {
            client.write_all(REQ.as_bytes()).await?;
            client.flush().await?;
            loop {
                let mut buf = [0u8; 4096];
                let n = client.read(&mut buf).await?;
                response.extend_from_slice(&buf[..n]);
                if n == 0 {
                    break;
                }
            }
            client.shutdown().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .expect("客户端侧 60s 内完成（含首流引导）")
        .expect("客户端侧 IO 无错");

        let report = tokio::time::timeout(Duration::from_secs(60), fwd)
            .await
            .expect("forward 60s 内收束")
            .expect("forward 任务无 panic")
            .expect("forward 成功");
        let head = String::from_utf8_lossy(&response);
        let status = head.lines().next().unwrap_or("").to_string();
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "流 {i} 应见 HTTP 200 状态行，实际 {status:?}（flush 泵面失效症状 = 空读）"
        );
        assert!(
            report.upstream > 0 && report.downstream > 0,
            "流 {i} 字节计数应非零（up={} down={}）",
            report.upstream,
            report.downstream
        );
        assert!(
            connector.client_cell.get().is_some(),
            "流 {i} 后共享客户端应已成活（引导共享面）"
        );
    }
}

/// 测试用流构造（回环 duplex 客户端侧 + Flow 载体）
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
