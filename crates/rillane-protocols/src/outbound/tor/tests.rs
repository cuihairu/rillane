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
/// 直连门（=1 启用直连引导面；CI 默认跳过不打第三方公网）
const DIRECT_ENV: &str = "RILLANE_TOR_DIRECT";
const REQ: &str = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";

/// 直连引导门：本席原始出网已恢复（2026-11-23 探针 example.com →
/// 200/0.05s、无代理 env）——直连引导与平台旁路两面在直连环境下行使。
fn direct_enabled() -> bool {
    std::env::var(DIRECT_ENV).ok().is_some_and(|s| s == "1")
}

/// 客户端侧驱动一次 HTTP/1.0 往返（写请求 → 读到 EOF → 半关），返回全量
/// 响应字节。60s 闸含首流引导。
async fn drive_http(mut client: tokio::io::DuplexStream) -> Vec<u8> {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), async {
        client.write_all(REQ.as_bytes()).await?;
        client.flush().await?;
        loop {
            let mut buf = [0u8; 4096];
            let n = client.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
        }
        client.shutdown().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .expect("客户端侧 60s 内完成（含首流引导）")
    .expect("客户端侧 IO 无错");
    response
}

fn status_line(response: &[u8]) -> String {
    String::from_utf8_lossy(response)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

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

/// 本地 CONNECT 前置（测试自建，与 ssh 前置跳板测试同族）：接受 arti 的
/// CONNECT 请求、应答 200、直拨上游隧道。行使通道前置面的全部代码路径
/// （outbound_proxy → CONNECT → 隧道 → 真实 Tor 网络），不依赖外部
/// CONNECT 代理在场。
async fn spawn_local_connect_front() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("前置绑定");
    let addr = listener.local_addr().expect("前置地址");
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // 读到请求头末（CONNECT host:port HTTP/1.1）
                let mut buf = vec![0u8; 4096];
                let mut len = 0;
                loop {
                    let n = match client.read(&mut buf[len..]).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if n == 0 {
                        return;
                    }
                    len += n;
                    if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if len >= buf.len() {
                        return;
                    }
                }
                let target = String::from_utf8_lossy(&buf[..len])
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                let _ = client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let Ok(mut upstream) = tokio::net::TcpStream::connect(&target).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    format!("http://{addr}")
}

/// 双流整链：首流触发惰性引导（共享客户端成活）→ isolated_client 隔离
/// 流 → HTTP/1.0 GET 经真实电路往返（200 响应体逐字节可见）→ 次流复用
/// 同一客户端（client_cell 已初始化，无重复引导）→ 双流字节计数非零。
/// 前置面：优先环境给定的真实前置（RILLANE_TOR_FRONT），否则本测试自建
/// 本地 CONNECT 前置（确定性行使前置面；本席 2026-11-23 现存代理
/// 8080/9880 均只收绝对式 GET、CONNECT 一律 405，不能前置）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tor_two_flows_shared_bootstrap_http_roundtrip() {
    let front = match std::env::var(FRONT_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(uri) => uri,
        None if direct_enabled() => spawn_local_connect_front().await,
        None => {
            eprintln!(
                "跳过：前置面未配置（设 {FRONT_ENV}=<proxy-uri> 或 {DIRECT_ENV}=1 用本地前置）"
            );
            return;
        }
    };
    let connector = Arc::new(TorConnector::new(Some(front)).expect("前置 URI 合法"));
    assert!(!format!("{connector:?}").contains("bootstrapped: true"));

    // 双流（串行驱动：首流引导，次流复用；引导不可观测的重叠无意义）
    for i in 1..=2 {
        let (flow, client) = make_flow("example.com", 80);
        let fwd = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.forward(flow).await })
        };

        let response = drive_http(client).await;
        let report = tokio::time::timeout(Duration::from_secs(60), fwd)
            .await
            .expect("forward 60s 内收束")
            .expect("forward 任务无 panic")
            .expect("forward 成功");
        let status = status_line(&response);
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

/// 直连引导面（RIL-114 验收「真实对端」直连臂）：`TorConnector::new(None)`
/// 无前置直连引导（2026-11-23 本席出网恢复后可行），HTTP 200 往返 + 引导
/// 共享断言。与前置面测试互补——同一会话逻辑的两条引导路径。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tor_direct_bootstrap_http_roundtrip() {
    if !direct_enabled() {
        eprintln!(
            "跳过：直连引导未启用（设 {DIRECT_ENV}=1 启用；本席 2026-11-23 探针出网已恢复，\
             直连环境真跑绿）"
        );
        return;
    }
    let connector = Arc::new(TorConnector::new(None).expect("无前置构造"));
    assert!(connector.front.is_none(), "直连面无前置");

    let (flow, client) = make_flow("example.com", 80);
    let fwd = {
        let connector = connector.clone();
        tokio::spawn(async move { connector.forward(flow).await })
    };
    let response = drive_http(client).await;
    let report = fwd.await.expect("join").expect("forward 成功");
    let status = status_line(&response);
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "直连引导应见 HTTP 200，实际 {status:?}"
    );
    assert!(
        report.upstream > 0 && report.downstream > 0,
        "直连面字节计数非零（up={} down={}）",
        report.upstream,
        report.downstream
    );
    assert!(
        connector.client_cell.get().is_some(),
        "直连引导后共享客户端成活"
    );
}

/// 平台旁路拨号面（RIL-114 验收「平台旁路」项）：调用方自建客户端
/// （`with_runtime` 显式运行时 + 引导）传入 `forward_over_client`——
/// 连接器从不引导（client_cell 恒空），整个会话跑在调用方客户端上。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tor_forward_over_caller_client() {
    if !direct_enabled() {
        eprintln!("跳过：平台旁路面需直连引导环境（设 {DIRECT_ENV}=1 启用）");
        return;
    }
    // 调用方引导（不借连接器任何路径）：toml 配置 + rustls provider + 调用方
    // 选定的具体运行时类型 TokioRustlsRuntime（连接器标准面用缺省
    // PreferredRuntime——两面经泛型 R 区分，会话逻辑同一）
    let cfg: TorClientConfig =
        toml::from_str::<TorClientConfigBuilder>("[storage]\npermissions.denied = []\n")
            .context("调用方 toml 配置解析")
            .and_then(|b: TorClientConfigBuilder| b.build().context("调用方配置构建"))
            .expect("调用方配置构建");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = tokio::time::timeout(
        Duration::from_secs(180),
        TorClient::with_runtime(
            tor_rtcompat::tokio::TokioRustlsRuntime::current().expect("当前 tokio 运行时"),
        )
        .config(cfg)
        .create_bootstrapped(),
    )
    .await
    .context("调用方引导超时")
    .and_then(|r| r.context("调用方引导失败"))
    .expect("调用方引导");

    let connector = Arc::new(TorConnector::new(None).expect("构造"));
    let (flow, client_duplex) = make_flow("example.com", 80);
    let fwd = {
        let connector = connector.clone();
        let client = client.clone();
        tokio::spawn(async move { connector.forward_over_client(flow, client).await })
    };
    let response = drive_http(client_duplex).await;
    let report = fwd.await.expect("join").expect("旁路面 forward 成功");
    let status = status_line(&response);
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "旁路面应见 HTTP 200，实际 {status:?}"
    );
    assert!(
        report.upstream > 0 && report.downstream > 0,
        "旁路面字节计数非零（up={} down={}）",
        report.upstream,
        report.downstream
    );
    assert!(
        connector.client_cell.get().is_none(),
        "旁路面连接器从不引导（client_cell 恒空）"
    );
}

/// 取消 + 资源释放面（RIL-114 验收「取消、资源释放」项）：中继在途撤销
/// 转发任务——flow.io 随任务撤销丢弃（客户侧即刻收束），TorTcpStream 拆线
/// 走 END 单元异步收束（不可直连观测出口侧，具名边界）；可观测断言 =
/// 客户侧即刻收束 + 撤销后同连接器次流照常往返（共享客户端不中毒、引导
/// 槽与电路状态无泄漏悬挂）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tor_cancel_mid_relay_releases_resources() {
    if !direct_enabled() {
        eprintln!("跳过：取消/资源释放面需直连引导环境（设 {DIRECT_ENV}=1 启用）");
        return;
    }
    let connector = Arc::new(TorConnector::new(None).expect("构造"));

    // 首流：请求后不半关（转发挂在中继态），等对端首批响应字节 = 电路
    // 已建立且数据在途（撤销面可观测前提成立）
    let (flow, mut client) = make_flow("example.com", 80);
    let relay = {
        let connector = connector.clone();
        tokio::spawn(async move { connector.forward(flow).await })
    };
    client.write_all(REQ.as_bytes()).await.expect("上行写");
    client.flush().await.expect("上行 flush");
    let mut first = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(60), client.read(&mut first))
        .await
        .expect("首响应字节 60s 内到达（含引导）")
        .expect("duplex 读面");
    assert!(n > 0, "对端应已回数据（流建立且中继在途）");

    // 中继在途撤销
    relay.abort();
    let _ = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("撤销 5s 内收束（任务 Drop 即时运行）");

    // 客户侧资源释放：flow.io 随任务撤销丢弃 → 读面即刻收束
    let mut sink = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(5), client.read(&mut sink))
        .await
        .expect("客户侧收束超时（撤销后流未释放）")
        .expect("duplex 读面");

    // 对端资源释放的连接器级可观测面：同连接器次流照常完整往返（共享
    // 客户端不中毒、无泄漏悬挂电路阻塞后续流）
    let (flow2, client2) = make_flow("example.com", 80);
    let fwd2 = {
        let connector = connector.clone();
        tokio::spawn(async move { connector.forward(flow2).await })
    };
    let response = drive_http(client2).await;
    let report = fwd2.await.expect("join").expect("次流 forward 成功");
    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "撤销后次流应照常往返，实际 {:?}",
        status_line(&response)
    );
    assert!(
        report.upstream > 0 && report.downstream > 0,
        "次流字节计数非零（up={} down={}）",
        report.upstream,
        report.downstream
    );
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
