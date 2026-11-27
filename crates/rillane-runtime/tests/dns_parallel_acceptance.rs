//! RIL-086 第二段：Linux「并行场景下 DNS 解析/缓存」真实运行时实测。
//!
//! 本地 UDP mock 上游（真实线格式编解码，零外网依赖）+ 真实 `DnsService`
//! 本地监听，验证并行场景的 DNS 面：① 多客户端同一冷名并发查询走
//! singleflight（只打上游一次，其余等广播结果，防 stampede）；② 命中后
//! 二次查询走缓存（上游计数不动、cache_hits 增长）；③ `clear_cache`
//! 后重回上游（换网/运维冲刷面生效）；④ 不同域名各自独立解析不串答。
//!
//! 边界：仅本机回环 DNS 监听 + mock 上游，不测 TUN 劫持、真实公网解析器、
//! 六平台真机矩阵——核心「真实网站/QUIC 与游戏并行」场景仍 partial。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rillane_config::{DnsBlockConfig, DnsGroup};
use rillane_platform::network::{
    dns_engine::{
        decode_query, decode_response, encode_query, encode_response, DnsAnswer, DnsAnswerData,
        DnsUpstream,
    },
    DnsRecordType,
};
use rillane_runtime::{dns_block_to_resolver_config, DnsService};
use tokio::net::UdpSocket;

/// mock 上游：真实 RFC1035 查询/应答编解码，按域名映射 A 记录，并计数
/// 收到的查询数（singleflight / 缓存断言的观测锚点）。
async fn spawn_mock() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("mock 绑定"));
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = hits.clone();
    let task_sock = sock.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = task_sock.recv_from(&mut buf).await else {
                break;
            };
            let Ok(q) = decode_query(&buf[..n]) else {
                continue;
            };
            task_hits.fetch_add(1, Ordering::Relaxed);
            let ip = match q.domain.as_str() {
                "alpha.test" => Ipv4Addr::new(9, 9, 9, 9),
                "beta.test" => Ipv4Addr::new(8, 8, 8, 8),
                _ => Ipv4Addr::new(7, 7, 7, 7),
            };
            let answers = vec![DnsAnswer {
                domain: q.domain.clone(),
                rtype: DnsRecordType::A,
                ttl: 60,
                data: DnsAnswerData::A(ip),
            }];
            let resp = encode_response(q.id, &q.domain, q.qtype, 0, &answers);
            let _ = task_sock.send_to(&resp, peer).await;
        }
    });
    (sock.local_addr().expect("mock 地址"), hits)
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("探针绑定")
        .local_addr()
        .expect("端口")
        .port()
}

/// 一次真实 UDP 查询：编码 → 本地 DNS 监听 → 解码应答，返回 A 地址。
async fn query(listen_port: u16, id: u16, domain: &str) -> Ipv4Addr {
    let cli = UdpSocket::bind("127.0.0.1:0").await.expect("客户端绑定");
    cli.connect(SocketAddr::from(([127, 0, 0, 1], listen_port)))
        .await
        .expect("连接本地 DNS");
    let q = encode_query(id, domain, DnsRecordType::A).expect("查询编码");
    let raw = tokio::time::timeout(Duration::from_secs(3), async {
        for _ in 0..100 {
            if cli.send(&q).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            let mut buf = [0u8; 512];
            if let Ok(n) = cli.recv(&mut buf).await {
                return buf[..n].to_vec();
            }
        }
        panic!("未收到 DNS 应答");
    })
    .await
    .expect("3s 内应答");
    let resp = decode_response(&raw).expect("应答解码");
    assert_eq!(resp.id, id, "应答 ID 应匹配");
    assert_eq!(resp.rcode, 0, "应答应成功");
    let DnsAnswerData::A(ip) = resp.answers[0].data else {
        panic!("应为 A 应答");
    };
    ip
}

fn service(mock: SocketAddr, port: u16) -> DnsService {
    let block: DnsBlockConfig = serde_yaml::from_str(
        "default_group: trusted\ntrusted: ['127.0.0.1:53']\ncache: { max_entries: 64 }",
    )
    .expect("块解析");
    let mut cfg = dns_block_to_resolver_config(&block, &[]).expect("转换");
    assert_eq!(block.default_group, DnsGroup::Trusted);
    cfg.trusted = vec![DnsUpstream::Udp(mock)];
    let resolver = Arc::new(rillane_platform::network::DnsResolver::new(cfg).expect("解析器装配"));
    DnsService::new(
        resolver,
        SocketAddr::from(([127, 0, 0, 1], port)),
        None,
        None,
    )
}

/// 并行 DNS 面端到端：冷名并发 singleflight → 缓存 → 冲刷 → 重回上游。
#[tokio::test]
async fn dns_parallel_queries_cache_and_flush() {
    let (mock, hits) = spawn_mock().await;
    let port = free_udp_port();
    let svc = service(mock, port);
    svc.start().await.expect("启动 DNS 监听");

    // 八个客户端同时查同一冷名：singleflight 应合并为一次上游查询。
    let clients = (0..8u16).map(|i| query(port, 0x1000 + i, "alpha.test"));
    let results = futures::future::join_all(clients).await;
    for ip in &results {
        assert_eq!(*ip, Ipv4Addr::new(9, 9, 9, 9), "并发查询应得同一正确 A");
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "并发冷名只应打上游一次（singleflight 防 stampede）"
    );
    let snap = svc.stats_snapshot();
    assert_eq!(snap.total_queries, 8, "八个查询都应被计数");
    assert_eq!(snap.upstream_failures, 0, "零上游失败");

    // 缓存命中：再查同域名，上游计数不动、cache_hits 增长。
    let before = snap.cache_hits;
    assert_eq!(
        query(port, 0x2000, "alpha.test").await,
        Ipv4Addr::new(9, 9, 9, 9)
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1, "缓存命中不触上游");
    assert!(svc.stats_snapshot().cache_hits > before, "缓存命中应被计数");

    // 不同域名独立解析：单独打一次上游，答不串。
    assert_eq!(
        query(port, 0x2001, "beta.test").await,
        Ipv4Addr::new(8, 8, 8, 8)
    );
    assert_eq!(hits.load(Ordering::Relaxed), 2, "第二个冷名独立打上游");

    // 冲刷缓存后同域名重回上游（换网/运维面生效）。
    svc.clear_cache();
    assert_eq!(
        query(port, 0x2002, "alpha.test").await,
        Ipv4Addr::new(9, 9, 9, 9)
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "clear_cache 后应重回上游（缓存已失效）"
    );

    svc.stop().await.expect("收尾 stop");
}
