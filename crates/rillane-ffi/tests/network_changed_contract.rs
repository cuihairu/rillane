//! RIL-044 第三段：网络变化面契约（本地可核验面）。
//!
//! 生命周期条款「网络变化」核心半边的钉法：`rillane_ffi_network_changed`
//! 通知核心宿主底层网络已变化，当下语义 = 冲刷 DNS 缓存（publisher.rs
//! 把会话排空记为 RIL-022/023 消费侧边界——网络变化沿同一边界，不擅自
//! 斩在途流）。以**真实 DNS 解析往返**证明冲刷确实生效：mock 上游复用
//! 平台 crate 自己的线格式编解码（与解析器同方言，零失配面）——同一
//! 域名二次查询走缓存（上游命中数不增）、`network_changed` 后第三次
//! 查询重回上游（命中数 +1；若缓存未失效则停在基线，对账器自证点名）。
//! 幂等可重复；DNS 块缺席 = 诚实 no-op 仍 0；NULL 句柄 -1 + last_error。
//!
//! 诚实边界：本门钉核心半边（缓存冲刷行为 + 句柄面）；Kotlin 半边
//! （onAvailable → networkChanged 接线纪律）与真机切网行为（Wi-Fi↔蜂窝
//! 实测）归 RIL-046 真机批次；在途流不斩断是具名边界非缺陷。JNI 符号面
//! 由 jni_symbol_face 恰等门覆盖（16 方法），C 头面由 contract_query_face
//! 头门覆盖。

use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rillane_platform::network::dns_engine::{
    decode_query, encode_query, encode_response, DnsAnswer, DnsAnswerData,
};
use rillane_platform::network::DnsRecordType;

const CONTROL_PORT: u16 = 27990;
const SOCKS_PORT: u16 = 27600;
const DNS_LISTEN_PORT: u16 = 27710;
const CONTROL_PORT_B: u16 = 27991;
const SOCKS_PORT_B: u16 = 27601;
// 对账器自用端口（与主测试并行跑，不得共占监听）
const CONTROL_PORT_C: u16 = 27992;
const SOCKS_PORT_C: u16 = 27602;
const DNS_LISTEN_PORT_C: u16 = 27711;

const QNAME: &str = "flush.probe.test.";

fn config_with_dns(mock_port: u16, socks: u16, control: u16, dns_listen: u16) -> String {
    format!(
        r#"
control:
  api_bind: 127.0.0.1:{control}
  uds_path: null
  admin_token: contract-token
telemetry:
  log_level: warn
  enable_metrics: false
  enable_tracing: false
ingress:
  - name: socks-in
    type: socks5
    bind: 127.0.0.1:{socks}
egress:
  - name: direct-main
    type: direct
routing:
  default_node: direct-main
  groups: []
  rules: []
network:
  dns:
    enabled: true
    trusted:
      - 127.0.0.1:{mock_port}
    default_group: trusted
    cache:
      max_entries: 128
      min_ttl: 30
      max_ttl: 600
    listen_port: {dns_listen}
"#
    )
}

/// 无 network.dns 块的最小配置（no-op 面自用）
fn config_without_dns(socks: u16, control: u16) -> String {
    format!(
        r#"
control:
  api_bind: 127.0.0.1:{control}
  uds_path: null
  admin_token: contract-token
telemetry:
  log_level: warn
  enable_metrics: false
  enable_tracing: false
ingress:
  - name: socks-in
    type: socks5
    bind: 127.0.0.1:{socks}
egress:
  - name: direct-main
    type: direct
routing:
  default_node: direct-main
  groups: []
  rules: []
"#
    )
}

fn last_error() -> String {
    let raw = unsafe { rillane_ffi::rillane_ffi_last_error() };
    assert!(!raw.is_null(), "失败面必须有 last_error");
    let msg = unsafe { CStr::from_ptr(raw) }
        .to_str()
        .expect("UTF-8")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    msg
}

/// mock 上游：任何 A 查询回 9.9.9.9（TTL 300），计到达查询数。
/// 编解码用平台 crate 自己的线格式函数——mock 与解析器同方言。
fn spawn_mock_upstream() -> (u16, Arc<AtomicUsize>) {
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("mock 上游绑定");
    let port = sock.local_addr().expect("mock 地址").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    sock.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("mock 读超时");
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            let Ok(q) = decode_query(&buf[..n]) else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let reply = encode_response(
                q.id,
                &q.domain,
                q.qtype,
                0,
                &[DnsAnswer {
                    domain: q.domain.clone(),
                    rtype: DnsRecordType::A,
                    ttl: 300,
                    data: DnsAnswerData::A(Ipv4Addr::new(9, 9, 9, 9)),
                }],
            );
            let _ = sock.send_to(&reply, peer);
        }
    });
    (port, hits)
}

/// 向本地解析器发一次 A 查询并等应答（事务 ID 匹配 + RCODE 0 + 至少一条
/// 应答）。有界重试只等监听/上游就绪；返回应答是否非空。
fn dns_query_expect_answer(dns_port: u16) {
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("查询端绑定");
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("查询读超时");
    let q = encode_query(0x4321, QNAME, DnsRecordType::A).expect("编码查询");
    for _ in 0..40 {
        sock.send_to(&q, ("127.0.0.1", dns_port)).expect("发送查询");
        let mut buf = [0u8; 512];
        if let Ok(n) = sock.recv(&mut buf) {
            if n >= 12
                && buf[0] == 0x43
                && buf[1] == 0x21
                && (buf[2] & 0x80) != 0
                && (buf[3] & 0x0F) == 0
                && u16::from_be_bytes([buf[6], buf[7]]) >= 1
            {
                return;
            }
        }
    }
    panic!("DNS 查询在 12s 内未获有效应答（监听未就绪或上游失联）");
}

/// 读 FFI dns_stats 计数（cache_hits / cache_misses）
fn dns_cache_counters(h: *const rillane_ffi::FfiHandle) -> (u64, u64) {
    let raw = unsafe { rillane_ffi::rillane_ffi_dns_stats_json(h) };
    assert!(!raw.is_null(), "dns_stats 应答非 NULL");
    let s = unsafe { CStr::from_ptr(raw) }.to_str().expect("UTF-8");
    let v: serde_json::Value = serde_json::from_str(s).expect("dns_stats JSON");
    unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    assert_eq!(v["enabled"], true, "DNS 块在场应 enabled");
    (
        v["cache_hits"].as_u64().expect("cache_hits"),
        v["cache_misses"].as_u64().expect("cache_misses"),
    )
}

// ---------------------------------------------------------------------------
// 正向面：冲刷真实生效（上游命中数 + dns_stats 计数双证）+ 幂等 + 空态
// ---------------------------------------------------------------------------

/// 冲刷行为证明：二次查询走缓存（上游命中不增）→ network_changed → 三次
/// 查询重回上游（命中 +1）→ 再次 network_changed → 四次查询再回（幂等）。
#[test]
fn network_changed_flushes_dns_cache_real_roundtrip() {
    let (mock_port, hits) = spawn_mock_upstream();
    let yaml = config_with_dns(mock_port, SOCKS_PORT, CONTROL_PORT, DNS_LISTEN_PORT);
    let h = unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    assert!(!h.is_null(), "DNS 块在场应启动成功");

    // 暖身（首轮入缓存；重试副产查询可能多发——基线在应答稳定后读）
    dns_query_expect_answer(DNS_LISTEN_PORT);
    std::thread::sleep(Duration::from_millis(300));
    let baseline = hits.load(Ordering::SeqCst);
    assert!(baseline >= 1, "首轮查询应至少到达上游一次");

    // 二次查询：同域名 → 缓存命中，上游命中数不动
    dns_query_expect_answer(DNS_LISTEN_PORT);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        baseline,
        "二次查询应走缓存（上游命中不增）——缓存未生效则后续冲刷证明无意义"
    );
    let (cache_hits, _) = dns_cache_counters(h);
    assert!(cache_hits >= 1, "dns_stats 应记录到缓存命中");

    // 网络变化 → 缓存冲刷 → 三次查询重回上游
    assert_eq!(unsafe { rillane_ffi::rillane_ffi_network_changed(h) }, 0);
    dns_query_expect_answer(DNS_LISTEN_PORT);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        hits.load(Ordering::SeqCst) > baseline,
        "网络变化后未重查上游——缓存未失效（network_changed 未冲刷）"
    );

    // 幂等：再次通知 + 再查 → 命中数继续前进（无状态、可重复）
    assert_eq!(unsafe { rillane_ffi::rillane_ffi_network_changed(h) }, 0);
    dns_query_expect_answer(DNS_LISTEN_PORT);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        hits.load(Ordering::SeqCst) > baseline + 1,
        "重复通知后应再回上游一次（幂等冲刷）"
    );

    assert_eq!(unsafe { rillane_ffi::rillane_ffi_stop(h) }, 0);
}

/// DNS 块缺席 = 诚实 no-op 0；NULL 句柄 = -1 + last_error 点名。
#[test]
fn network_changed_disabled_dns_and_null_handle_fail_named() {
    let yaml = config_without_dns(SOCKS_PORT_B, CONTROL_PORT_B);
    let h = unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    assert!(!h.is_null(), "无 DNS 块应照常启动");
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_network_changed(h) },
        0,
        "DNS 缺席应诚实 no-op 0（冲刷空即成功）"
    );
    // dns_stats 同面佐证：缺席块 enabled:false
    let raw = unsafe { rillane_ffi::rillane_ffi_dns_stats_json(h) };
    let s = unsafe { CStr::from_ptr(raw) }.to_str().expect("UTF-8");
    assert!(s.contains("\"enabled\":false"), "缺席块应 enabled:false");
    unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    assert_eq!(unsafe { rillane_ffi::rillane_ffi_stop(h) }, 0);

    // NULL 句柄：-1 + 稳定点名（不得与成功 0 混同）
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_network_changed(std::ptr::null()) },
        -1
    );
    let err = last_error();
    assert!(err.contains("句柄为空"), "NULL 句柄应点名，得到：{err:?}");
}

// ---------------------------------------------------------------------------
// 对账器自证
// ---------------------------------------------------------------------------

/// 自证：不做 network_changed 直接三次查询 → 「网络变化后未重查上游」
/// 断言必须咬住（缓存仍在 = 冲刷缺席可检出，不是恒真断言）。
#[test]
#[should_panic(expected = "缓存未失效")]
fn comparator_bites_on_missing_flush() {
    let (mock_port, hits) = spawn_mock_upstream();
    let yaml = config_with_dns(mock_port, SOCKS_PORT_C, CONTROL_PORT_C, DNS_LISTEN_PORT_C);
    let h = unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    assert!(!h.is_null(), "DNS 块在场应启动成功");

    dns_query_expect_answer(DNS_LISTEN_PORT_C);
    std::thread::sleep(Duration::from_millis(300));
    let baseline = hits.load(Ordering::SeqCst);

    // 二次查询入缓存后【不】通知网络变化，直接断言三次查询回上游
    dns_query_expect_answer(DNS_LISTEN_PORT_C);
    std::thread::sleep(Duration::from_millis(200));
    dns_query_expect_answer(DNS_LISTEN_PORT_C);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        hits.load(Ordering::SeqCst) > baseline,
        "网络变化后未重查上游——缓存未失效（network_changed 未冲刷）"
    );

    assert_eq!(unsafe { rillane_ffi::rillane_ffi_stop(h) }, 0);
}
