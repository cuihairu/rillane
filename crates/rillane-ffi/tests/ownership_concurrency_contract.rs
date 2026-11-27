//! RIL-043 第三段：FFI 缓冲所有权与并发查询面契约。
//!
//! RIL-043 验收词里的「缓冲所有权、线程、取消、ABI 版本」在**拉模型
//! FFI**（无回调、无共享队列）上的本地可核验半边：
//!
//! - **缓冲所有权**：查询面每次返回的 `char*` 是独立堆分配（两次调用
//!   指针不同、内容各自合法 JSON），由宿主以 `rillane_ffi_free_string`
//!   归还恰一次；`version()` 指针进程级静态（两次调用同指针）且**不**
//!   走堆——所有权两族（堆归还 vs 静态只读）按文档分野钉死；缺席编码
//!   为 NULL（无效句柄查询 NULL、`free_string(NULL)` 容忍）；`last_error`
//!   读后即清——同一线程每条错误串恰交出一次，无重复领取。
//! - **线程**：同一句柄多线程并发查询 + 数据面真实传输同时进行——
//!   查询面不阻塞数据面（传输字节精确回声完成），并发应答全部
//!   `schema_version=1`（无撕裂/无串代际）。
//! - **ABI 版本**：`rillane_ffi_version()` 返回串与根 Cargo.toml
//!   `[workspace.package].version` 逐字一致（workspace 继承链：
//!   `rillane-ffi` `version.workspace = true`）——升版本忘过门即失败。
//!
//! 诚实边界：fd 桥接已由 tun_fd_injection_contract 钉；公开 packetFlow
//! 批次（iOS NE）与真机 ABI 批次归 RIL-094 设备面未跑；悬空句柄解引用
//! 是 UB 不可测——宿主侧「stop 后清引用」纪律由 host_lifecycle 的
//! Kotlin 文本门钉，本门不冒充。

use serde_json::Value;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

const CONTROL_PORT: u16 = 27986;
const SOCKS_PORT: u16 = 27582;
const ECHO_PORT: u16 = 27583;

/// 两个测试共用固定端口——cargo 默认并行跑 #[test]，须串行化
/// （否则两个 start_runtime 抢 bind，输家的 5 次重试可能全撞在赢家在场的窗口上）。
static PORT_GUARD: Mutex<()> = Mutex::new(());

fn test_config() -> String {
    format!(
        r#"
control:
  api_bind: 127.0.0.1:{CONTROL_PORT}
  uds_path: null
  admin_token: contract-token
telemetry:
  log_level: warn
  enable_metrics: false
  enable_tracing: false
ingress:
  - name: socks-in
    type: socks5
    bind: 127.0.0.1:{SOCKS_PORT}
egress:
  - name: direct-main
    type: direct
routing:
  default_node: direct-main
  groups: []
  rules: []
udp:
  enabled: true
"#
    )
}

unsafe fn start_runtime() -> *mut rillane_ffi::FfiHandle {
    let yaml = test_config();
    // start 返回与入站监听 bind 完成之间有竞态（并行 workspace 全量下
    // 曾见 ConnectionRefused）——有界重试只等监听就绪。
    for attempt in 0..5 {
        let h =
            unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast::<c_char>(), yaml.len()) };
        if !h.is_null() {
            // 监听就绪才返回（最多 ~2.5s）。
            for _ in 0..50 {
                if std::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT)).is_ok() {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            panic!("FFI start 后 socks 入站 2.5s 内未监听");
        }
        let _ = attempt; // 端口瞬时被并行套件占用时退避重试
        std::thread::sleep(std::time::Duration::from_millis(200));
        unsafe { rillane_ffi::rillane_ffi_last_error() }; // 清错误槽
    }
    panic!("FFI start 重试后仍失败");
}

unsafe fn read_json(s: *mut c_char) -> Value {
    assert!(!s.is_null(), "查询面缺席应编码为 NULL，而非空串");
    let raw = unsafe { CStr::from_ptr(s) }
        .to_str()
        .expect("返回串应为 UTF-8 JSON")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(s) };
    serde_json::from_str(&raw).expect("返回串应为合法 JSON")
}

fn workspace_version() -> String {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let text = std::fs::read_to_string(&root).expect("读根 Cargo.toml");
    let section = text
        .split("[workspace.package]")
        .nth(1)
        .expect("根 Cargo.toml 缺 [workspace.package]");
    for line in section.lines() {
        if let Some(v) = line.strip_prefix("version = \"") {
            return v.trim_end_matches('"').to_string();
        }
    }
    panic!("[workspace.package] 缺 version 字段");
}

/// 缓冲所有权：堆族每次独立分配 + 恰一次归还；静态族（version）同指针；
/// 缺席 = NULL；last_error 读后即清恰一次。
#[test]
fn string_buffers_follow_ownership_contract() {
    let _guard = PORT_GUARD.lock().expect("端口守卫");
    let h = unsafe { start_runtime() };

    // -- 堆族：两次 stats_json 独立分配（指针不同、内容各自合法）--
    let p1 = unsafe { rillane_ffi::rillane_ffi_stats_json(h) };
    let p2 = unsafe { rillane_ffi::rillane_ffi_stats_json(h) };
    assert!(!p1.is_null() && !p2.is_null(), "活句柄查询不得缺席");
    assert_ne!(
        p1, p2,
        "两次查询共用同一缓冲（静态串冒充堆归还——宿主 free 一次即坏两处）"
    );
    let v1 = unsafe { read_json(p1) };
    let v2 = unsafe { read_json(p2) };
    // stats_json 是 stats 子集面（无信封 schema_version 键）——用冻结面键集核形。
    for v in [&v1, &v2] {
        for k in [
            "uptime_seconds",
            "total_connections",
            "is_running",
            "tun_fd",
        ] {
            assert!(v.get(k).is_some(), "stats 缺冻结面键 {k}");
        }
        assert_eq!(v["is_running"], true, "活句柄 stats 须报运行中");
    }
    assert_eq!(v1, v2, "同刻两次 stats 内容应一致");

    // -- 静态族：version 两次调用同指针（进程级，不归 free_string 管）--
    let ver1 = unsafe { rillane_ffi::rillane_ffi_version() };
    let ver2 = unsafe { rillane_ffi::rillane_ffi_version() };
    assert_eq!(ver1, ver2, "version 指针两次调用不同（文档承诺进程级静态）");
    let ver = unsafe { CStr::from_ptr(ver1) }
        .to_str()
        .expect("version 应为 UTF-8");
    assert_eq!(
        ver,
        workspace_version(),
        "ABI 版本串与根 Cargo.toml [workspace.package].version 漂移"
    );

    // -- 缺席编码：NULL 句柄查询 → NULL；free_string(NULL) 容忍 --
    assert!(
        unsafe { rillane_ffi::rillane_ffi_stats_json(std::ptr::null_mut()) }.is_null(),
        "无效句柄查询必须 NULL（缺席编码），不得返回垃圾指针"
    );
    unsafe { rillane_ffi::rillane_ffi_free_string(std::ptr::null_mut()) };

    // -- last_error 读后即清：一次失败恰交出一条错误串 --
    let bad = CString::new("::not-yaml::").expect("坏配置");
    let started = unsafe {
        rillane_ffi::rillane_ffi_start(bad.as_ptr().cast::<c_char>(), bad.as_bytes().len())
    };
    assert!(started.is_null(), "坏配置必须启动失败");
    let err1 = unsafe { rillane_ffi::rillane_ffi_last_error() };
    assert!(!err1.is_null(), "失败后 last_error 应在场");
    let err2 = unsafe { rillane_ffi::rillane_ffi_last_error() };
    assert!(err2.is_null(), "last_error 读后即清——同条错误不得交出两次");
    let err_text = unsafe { CStr::from_ptr(err1) }
        .to_str()
        .expect("UTF-8")
        .to_string();
    assert!(!err_text.is_empty(), "错误串不得为空");
    unsafe { rillane_ffi::rillane_ffi_free_string(err1) };

    unsafe { rillane_ffi::rillane_ffi_stop(h) };
    // stop 后句柄悬空不得复用（宿主清引用纪律归 host_lifecycle 门）。
    unsafe { rillane_ffi::rillane_ffi_stop(std::ptr::null_mut()) };
}

/// 线程：同一句柄 4 线程并发查询（每线程 25 轮三查询 + 解析 + 归还），
/// 同时一条真实 SOCKS5→direct→echo 传输进行——查询面不得阻塞数据面
/// （传输字节精确回声完成），并发应答全部 schema_version=1。
#[test]
fn concurrent_queries_do_not_stall_data_plane() {
    let _guard = PORT_GUARD.lock().expect("端口守卫");
    let h = unsafe { start_runtime() };
    let handle_addr = h as usize;

    // 数据面：echo 服务 + 一条经 SOCKS5 的真实传输（独立线程跑完）。
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let listener = std::net::TcpListener::bind(("127.0.0.1", ECHO_PORT)).expect("echo 绑定");
    // echo 侧按定长读满再回（载荷长度编进线程，避免单次 read 截断）。
    let echo_len = payload.len();
    let echo = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut sock, _) = listener.accept().expect("accept");
        let mut got = vec![0u8; 0];
        while got.len() < echo_len {
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let _ = sock.write_all(&got);
        let _ = sock.flush();
        got.len()
    });
    let transfer = std::thread::spawn(move || -> Vec<u8> {
        use std::io::{Read, Write};
        let mut sock = (0..100)
            .find_map(|_| std::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT)).ok())
            .expect("连 socks 入站");
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("读超时");
        sock.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
        let mut reply = [0u8; 2];
        sock.read_exact(&mut reply).expect("method reply");
        assert_eq!(reply, [0x05, 0x00], "SOCKS5 无鉴权协商");
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&ECHO_PORT.to_be_bytes());
        sock.write_all(&req).expect("connect 请求");
        let mut rep = [0u8; 4];
        sock.read_exact(&mut rep).expect("connect reply 头");
        assert_eq!(rep[1], 0, "CONNECT 须成功");
        match rep[3] {
            1 => {
                let mut b = [0u8; 6];
                sock.read_exact(&mut b).expect("v4 尾");
            }
            3 => {
                let mut l = [0u8; 1];
                sock.read_exact(&mut l).expect("域名长");
                let mut b = vec![0u8; l[0] as usize + 2];
                sock.read_exact(&mut b).expect("域名尾");
            }
            4 => {
                let mut b = [0u8; 18];
                sock.read_exact(&mut b).expect("v6 尾");
            }
            x => panic!("未知 ATYP {x}"),
        }
        sock.write_all(&payload).expect("发载荷");
        let expect_len = payload.len();
        let mut got = vec![0u8; 0];
        while got.len() < expect_len {
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).expect("回读");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    });

    // 查询面：4 线程并发，与传输同时进行。
    let mut query_threads = Vec::new();
    for t in 0..4 {
        query_threads.push(std::thread::spawn(move || {
            let h = handle_addr as *mut rillane_ffi::FfiHandle;
            for i in 0..25 {
                let stats = unsafe { read_json(rillane_ffi::rillane_ffi_stats_json(h)) };
                assert!(
                    stats.get("is_running").is_some(),
                    "并发应答形漂移 @stats #{i}"
                );
                let flows = unsafe { read_json(rillane_ffi::rillane_ffi_flows_json(h, 0, 50)) };
                assert_eq!(
                    flows["schema_version"], 1u32,
                    "并发应答代际撕裂 @flows #{i}"
                );
                let nodes = unsafe { read_json(rillane_ffi::rillane_ffi_nodes_json(h)) };
                assert_eq!(
                    nodes["schema_version"], 1u32,
                    "并发应答代际撕裂 @nodes #{i}"
                );
            }
            t
        }));
    }
    let echoed = transfer.join().expect("传输线程");
    let expect_payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    for th in query_threads {
        th.join().expect("查询线程");
    }
    let echoed_n = echo.join().expect("echo 线程");
    assert_eq!(echoed.len(), expect_payload.len(), "回声长度不符");
    assert!(
        echoed == expect_payload,
        "回声字节不符（查询面干扰了数据面）"
    );
    assert_eq!(echoed_n, expect_payload.len(), "echo 侧计数不符");

    unsafe { rillane_ffi::rillane_ffi_stop(h) };
}
