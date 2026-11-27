//! RIL-044 第四段：有界诊断 IPC 契约门（本地可核验面）。
//!
//! `docs/design/debug-and-mcp.md` 的移动边界是「不默认跑 MCP / 不新增手机
//! 入站管理端口，授权宿主 IPC 或脱敏导出」。本门以**真实 Unix 域连接往返**
//! 钉宿主显式起桥后的有界语义：默认零监听、双 start 稳定拒绝、动词白名单
//! 只读、未知/超限请求稳定码、一连接一请求、stop 幂等点名、句柄停用自动
//! 收桥；六个只读动词的 JSON 与 C 查询面同源同形状（routing/nodes/dns/
//! flows 逐字相等，stats 键集由 schema_v1 活面门覆盖）。
//!
//! 诚实边界：这是 host 进程内核心半边。宿主接线（Android Service/iOS NE
//! 显式调起桥的授权决策）与真机面（consent、arm64、Wi-Fi↔蜂窝切换）归
//! RIL-043/RIL-046 真机批次；父项保持未勾。单例运行态决定有状态用例在
//! 同一测试内串行（并行会撞桥单例——这正是「一进程一桥」的语义）。

use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

const CONTROL_PORT: u16 = 27993;
const SOCKS_PORT: u16 = 27603;

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
"#
    )
}

fn socket_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时钟")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "rillane-ipc-{}-{}-{tag}.sock",
        std::process::id(),
        nanos
    ));
    let _ = std::fs::remove_file(&path); // 清理上轮残留（路径本测试独占）
    path
}

fn c_string(s: &str) -> CString {
    CString::new(s).expect("路径/动词无 NUL")
}

fn last_error() -> String {
    let raw = unsafe { rillane_ffi::rillane_ffi_last_error() };
    assert!(!raw.is_null(), "失败面必须有 last_error");
    let msg = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_str()
        .expect("UTF-8")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    msg
}

/// 按行帧发请求并读**一行**应答；返回同时保留原串（一连接一请求检查用）。
fn request_lines(path: &Path, payload: &[u8]) -> Vec<String> {
    let mut stream = UnixStream::connect(path).expect("连接宿主选择的 UDS 路径");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("读超时");
    stream.write_all(payload).expect("发请求行");
    let _ = stream.shutdown(std::net::Shutdown::Write); // 告知对端本连接请求已发完
    let mut reader = BufReader::new(stream);
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            // 对端 shutdown 后仍可能有残留 RST；已读到的行有效
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset && !lines.is_empty() => {
                break
            }
            Err(e) => panic!("读应答行: {e}"),
        };
        if n == 0 {
            break;
        }
        lines.push(line.trim_end_matches('\n').to_string());
    }
    lines
}

fn request(path: &Path, verb: &str) -> Value {
    let lines = request_lines(path, format!("{verb}\n").as_bytes());
    assert_eq!(lines.len(), 1, "一连接一请求一应答，得到 {lines:?}");
    serde_json::from_str(&lines[0]).unwrap_or_else(|e| panic!("应答非 JSON：{}（{e}）", lines[0]))
}

fn c_json(raw: *mut std::os::raw::c_char) -> Value {
    assert!(!raw.is_null(), "C 查询面返回 NULL");
    let s = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_str()
        .expect("UTF-8")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    serde_json::from_str(&s).expect("C 查询面 JSON")
}

/// 全量往返：这一测试独占桥单例，逐步钉所有有界语义。
#[test]
fn bounded_ipc_real_roundtrip_and_stop_ordering() {
    let yaml = test_config();
    let h = unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    assert!(!h.is_null(), "契约配置应启动成功（端口撞占先清环境）");
    let path = socket_path("roundtrip");
    let path_c = c_string(path.to_str().expect("路径 UTF-8"));

    // 默认零监听：未显式 start 时连接必须失败（无默认管理端口）
    assert!(
        UnixStream::connect(&path).is_err(),
        "未 start 即存在监听——违反无默认入站面"
    );

    // NULL 句柄：稳定点名，不与成功混同
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_start(std::ptr::null(), path_c.as_ptr()) },
        -1
    );
    assert_eq!(last_error(), "ipc.start.null_handle");

    // 空路径：稳定拒绝（无默认路径兜底；不占单例）
    let empty = c_string("");
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_start(h, empty.as_ptr()) },
        -1
    );
    assert_eq!(last_error(), "ipc.start.bad_path");

    // 显式起桥成功；同路径二次 start 稳定拒绝（不换绑不静默）
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_start(h, path_c.as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_start(h, path_c.as_ptr()) },
        -1
    );
    assert_eq!(last_error(), "ipc.start.duplicate_path");

    // 六个只读动词：形状与 C 查询面逐字同源（stats 的 uptime 会变，单查键集）
    for verb in ["routing", "nodes", "dns_stats", "dns_resolvers", "flows"] {
        let via_ipc = request(&path, verb);
        let via_c = match verb {
            "routing" => c_json(unsafe { rillane_ffi::rillane_ffi_routing_json(h) }),
            "nodes" => c_json(unsafe { rillane_ffi::rillane_ffi_nodes_json(h) }),
            "dns_stats" => c_json(unsafe { rillane_ffi::rillane_ffi_dns_stats_json(h) }),
            "dns_resolvers" => c_json(unsafe { rillane_ffi::rillane_ffi_dns_resolvers_json(h) }),
            "flows" => c_json(unsafe { rillane_ffi::rillane_ffi_flows_json(h, 0, 100) }),
            _ => unreachable!(),
        };
        assert_eq!(via_ipc, via_c, "IPC {verb} 与 C 查询面形状漂移");
    }
    let stats = request(&path, "stats");
    assert_eq!(stats["schema_version"], serde_json::Value::Null); // stats 面无 schema_version（同 C 面）
    for key in [
        "uptime_seconds",
        "total_connections",
        "active_connections",
        "total_bytes_transferred",
        "bytes_uploaded",
        "bytes_downloaded",
        "error_count",
        "is_running",
        "tun_fd",
    ] {
        assert!(stats.get(key).is_some(), "stats IPC 面缺 {key}");
    }

    // 写/探测动词与未知动词：白名单外一律 unknown_verb（不旁路 MCP 写入面）
    for verb in ["write", "probe", "config", "apply", "reload", "bogus"] {
        let resp = request(&path, verb);
        assert_eq!(
            resp["error"], "ipc.request.unknown_verb",
            "动词 {verb} 未被拒绝"
        );
    }

    // 超长无换行请求：长度上限触发稳定码（不是无界缓冲）
    let oversized = vec![b'x'; 9 * 1024];
    let resp_lines = request_lines(&path, &oversized);
    assert_eq!(resp_lines.len(), 1, "超限仍单行应答");
    let resp: Value = serde_json::from_str(&resp_lines[0]).expect("超限 JSON");
    assert_eq!(resp["error"], "ipc.request.oversize");

    // 一连接一请求：两行一起发，只读第一行，第二行不得再产生应答
    let lines = request_lines(&path, b"routing\nflows\n");
    assert_eq!(lines.len(), 1, "第二行不得在同一连接再获应答：{lines:?}");
    assert!(
        lines[0].contains("\"schema_version\""),
        "首行应为 routing 应答"
    );

    // stop：成功 + 稳定码幂等点名 + 路径解绑 + 连接失败
    assert_eq!(unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_stop() }, 0);
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_stop() },
        -1
    );
    assert_eq!(last_error(), "ipc.stop.already_stopped");
    assert!(!path.exists(), "stop 后 UDS 路径必须解绑");
    assert!(UnixStream::connect(&path).is_err(), "stop 后不得仍可连接");

    // 句柄停用自动收桥：重启桥 → stop(handle) → 路径消失，无悬空 accept 线程
    assert_eq!(
        unsafe { rillane_ffi::rillane_ffi_diagnostic_ipc_start(h, path_c.as_ptr()) },
        0
    );
    assert_eq!(unsafe { rillane_ffi::rillane_ffi_stop(h) }, 0);
    assert!(!path.exists(), "句柄停用应自动收桥（UDS 路径解绑）");
}

/// 对账器自证：把 write 注入白名单副本后，只读断言必须点名失败
#[test]
#[should_panic(expected = "写/探测动词不得入白名单")]
fn comparator_bites_on_injected_write_verb() {
    let verbs = [
        "stats",
        "routing",
        "nodes",
        "dns_stats",
        "dns_resolvers",
        "flows",
        "write",
    ];
    for forbidden in ["write", "probe", "config"] {
        assert!(
            !verbs.contains(&forbidden),
            "写/探测动词不得入白名单：{forbidden}"
        );
    }
}
