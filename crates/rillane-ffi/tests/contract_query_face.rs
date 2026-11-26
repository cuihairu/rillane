//! FFI 查询面契约（RIL-083）：RIL-150 冻结形（schema_version=1）的
//! **exact 面**钉在 `contracts/schema_v1/ffi_face_v1.json`——移动端脚本
//! （Android Kotlin / iOS Swift）按字段名消费，加键减键都要求显式过门
//! （contracts/schema_v1/README.md 的 schema_v2 目录事务）。
//!
//! 对账面**活面取证**：真实启动 runtime，七查询逐一断言；并经 socks5
//! 入站 → direct 出口 → 本机 echo 监听的真实 TCP 往返钉「诚实空态」
//! ——会话执行面 SessionTracer 接线随数据面装配推进（runtime_builder.rs
//! 模块注记），此前 /trace/flows 恒空：真实流量过后 items 仍空、缺席形
//! 携采集器实况。flows 条目面与 flow found 形**尚不可活面取证**，face
//! 文件标 `verification: pending_live_trace_wiring`——接线落地批次须
//! 活面取证并摘除标记（本门对标记在场的断言保证摘除是显式动作）。
//!
//! C 头文件 ↔ Rust 导出符号集一致另钉一门——头文件是宿主桥接的编译
//! 契约，符号漂移即宿主构建失败。JNI 符号面（android 目标）不在本门，
//! 归 RIL-043 移动批次门（边界见模块尾注）。

use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};

const CONTROL_PORT: u16 = 27996;
const SOCKS_PORT: u16 = 27592;
const ECHO_PORT: u16 = 27593;

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

fn repo_root(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_face() -> Value {
    let path = repo_root("contracts/schema_v1/ffi_face_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取 ffi 面 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("ffi 面 JSON 解析失败: {e}"))
}

fn face_of<'a>(face: &'a Value, id: &str) -> &'a Value {
    face["faces"]
        .get(id)
        .unwrap_or_else(|| panic!("ffi 面文件缺 {id} 登记"))
}

/// serde_json 值类型词表 → 实测判定（`T|null` 复合任一命中）
fn type_matches(actual: &Value, declared: &str) -> bool {
    match declared {
        "object" => actual.is_object(),
        "array" => actual.is_array(),
        "string" => actual.is_string(),
        "boolean" => actual.is_boolean(),
        "number" => actual.is_number(),
        "null" => actual.is_null(),
        compound if compound.contains('|') => {
            compound.split('|').any(|t| type_matches(actual, t.trim()))
        }
        other => panic!("ffi 面类型词表外声明「{other}」（face 文件自身写错）"),
    }
}

/// exact 面：实际键集恰等于声明键集且类型相符；subset 面（absence 体）：
/// 必需键在场即可——collector 变体是 code/note 的超集，两缺席形态共门。
fn assert_face(actual: &Value, face: &Value, face_id: &str) {
    let declared = face["keys"]
        .as_object()
        .unwrap_or_else(|| panic!("面 {face_id} 缺 keys 对象"));
    let obj = actual
        .as_object()
        .unwrap_or_else(|| panic!("面 {face_id}：实际投影不是对象"));
    let declared_keys: BTreeSet<&str> = declared.keys().map(String::as_str).collect();
    let actual_keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let missing: Vec<&str> = declared_keys.difference(&actual_keys).copied().collect();
    let extra: Vec<&str> = actual_keys.difference(&declared_keys).copied().collect();
    let exact = face["mode"] == "exact";
    assert!(
        missing.is_empty(),
        "ffi 面漂移 @ {face_id}：缺键 {missing:?}（减键=破坏兼容，须过 schema_v2 事务）"
    );
    if exact {
        assert!(
            extra.is_empty(),
            "ffi 面漂移 @ {face_id}：多键 {extra:?}（加键=冻结形变更，须更新 face 并具名理由）"
        );
    }
    for (k, declared) in declared {
        let declared = declared.as_str().expect("类型声明是字符串");
        if !obj.contains_key(k) {
            continue; // subset 面只查在场键的类型
        }
        let v = &obj[k];
        assert!(
            type_matches(v, declared),
            "ffi 面漂移 @ {face_id}.{k}：类型漂移，声明 {declared}，实际 {v}"
        );
    }
}

unsafe fn start_runtime() -> *mut rillane_ffi::FfiHandle {
    let yaml = test_config();
    let h = unsafe {
        rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast::<std::os::raw::c_char>(), yaml.len())
    };
    assert!(
        !h.is_null(),
        "契约配置应启动成功（端口 {CONTROL_PORT}/{SOCKS_PORT} 撞占时先清环境）"
    );
    h
}

unsafe fn read_json(s: *mut std::os::raw::c_char) -> Value {
    let raw = unsafe { CStr::from_ptr(s) }
        .to_str()
        .expect("返回串应为 UTF-8 JSON")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(s) };
    serde_json::from_str(&raw).expect("返回串应为合法 JSON")
}

#[test]
fn ffi_query_faces_match_frozen_contract() {
    let face = load_face();
    assert_eq!(face["schema_version"], serde_json::json!(1u32));
    let h = unsafe { start_runtime() };

    // -- stats_json + 与控制面公共子集（control_face_v1 shared_stats_subset）--
    let stats = unsafe { read_json(rillane_ffi::rillane_ffi_stats_json(h)) };
    assert_face(&stats, face_of(&face, "stats_json"), "stats_json");
    let control_raw =
        std::fs::read_to_string(repo_root("contracts/schema_v1/control_face_v1.json"))
            .expect("读取 control_face_v1.json");
    let control: Value = serde_json::from_str(&control_raw).expect("control face JSON");
    let shared = &control["faces"]["shared_stats_subset"]["keys"];
    for k in shared.as_object().expect("shared keys").keys() {
        assert!(
            stats.get(k).is_some(),
            "公共子集漂移 @ stats_json.{k}：FFI 面收窄了与控制面的公共子集"
        );
    }

    // -- 静态查询面 --
    let routing = unsafe { read_json(rillane_ffi::rillane_ffi_routing_json(h)) };
    assert_face(&routing, face_of(&face, "routing_json"), "routing_json");
    let nodes = unsafe { read_json(rillane_ffi::rillane_ffi_nodes_json(h)) };
    assert_face(&nodes, face_of(&face, "nodes_json"), "nodes_json");
    let dns = unsafe { read_json(rillane_ffi::rillane_ffi_dns_stats_json(h)) };
    assert_face(&dns, face_of(&face, "dns_stats_json"), "dns_stats_json");
    let resolvers = unsafe { read_json(rillane_ffi::rillane_ffi_dns_resolvers_json(h)) };
    assert_face(
        &resolvers,
        face_of(&face, "dns_resolvers_json"),
        "dns_resolvers_json",
    );

    // -- 分页信封 + limit=0 显式拒绝信封 --
    let flows = unsafe { read_json(rillane_ffi::rillane_ffi_flows_json(h, 0, 50)) };
    assert_face(&flows, face_of(&face, "flows_envelope"), "flows_envelope");
    let invalid = unsafe { read_json(rillane_ffi::rillane_ffi_flows_json(h, 0, 0)) };
    assert_face(
        &invalid,
        face_of(&face, "flows_invalid_page"),
        "flows_invalid_page",
    );
    assert_eq!(
        invalid["error"], "query.page.invalid",
        "拒绝码是稳定码（移动端按码分支，不靠文案）"
    );

    // -- 真实流量往返（socks5 → direct → 本机 echo）：数据面可用性 +
    //    「诚实空态」钉死——SessionTracer 接线未落地，流量过后 items 仍空 --
    let listener = std::net::TcpListener::bind(("127.0.0.1", ECHO_PORT)).expect("echo 绑定");
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 13];
        let n = sock.read(&mut buf).unwrap_or(0);
        let _ = sock.write_all(&buf[..n]);
        let _ = sock.flush();
        std::thread::sleep(std::time::Duration::from_millis(80));
    });
    {
        use std::io::{Read, Write};
        let mut sock =
            std::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT)).expect("连 socks 入站");
        sock.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
        let mut reply = [0u8; 2];
        sock.read_exact(&mut reply).expect("method reply");
        assert_eq!(reply, [0x05, 0x00]);
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&ECHO_PORT.to_be_bytes());
        sock.write_all(&req).expect("connect req");
        let mut rep = [0u8; 10];
        sock.read_exact(&mut rep).expect("connect reply");
        assert_eq!(rep[1], 0x00, "CONNECT 应成功");
        sock.write_all(b"contract-echo").expect("payload");
        let mut echo = [0u8; 13];
        sock.read_exact(&mut echo).expect("echo");
        assert_eq!(&echo, b"contract-echo", "出口往返逐字节还原");
    }
    server.join().expect("echo 线程");

    let page = unsafe { read_json(rillane_ffi::rillane_ffi_flows_json(h, 0, 50)) };
    let items = page["items"].as_array().cloned().expect("items 数组");
    assert!(
        items.is_empty(),
        "SessionTracer 接线落地前 flows 恒空（诚实空态）；此处非空说明接线已落地\
         ——须按 face 文件 pending_live_trace_wiring 标记转正 flows_item/flow_found 活面取证"
    );

    // -- 待接线面标记在场断言：摘标记 = 显式过门动作 --
    for pending_id in ["flows_item", "flow_found"] {
        assert_eq!(
            face["faces"][pending_id]["verification"], "pending_live_trace_wiring",
            "面 {pending_id} 标记状态变化须同步改本门（接线落地 → 活面取证替换）"
        );
    }

    // -- flow 详情缺席形（活面：采集器在场，未知 ID = found:false + 计数）--
    let absent_id = CString::new("flow-contract-absent").expect("ID");
    let absent = unsafe { read_json(rillane_ffi::rillane_ffi_flow_json(h, absent_id.as_ptr())) };
    assert_face(&absent, face_of(&face, "flow_absent"), "flow_absent");
    assert_eq!(absent["found"], serde_json::json!(false));
    assert_face(
        &absent["absence"],
        face_of(&face, "flow_absence_body"),
        "flow_absence_body",
    );

    unsafe { rillane_ffi::rillane_ffi_stop(h) };
}

/// C 头文件 ↔ Rust 导出符号集恰等（宿主桥接的编译契约）：
/// 头文件多声明 = 链接期未定义引用；头文件少声明 = 导出面不可达。
#[test]
fn header_symbols_match_rust_exports() {
    let header = std::fs::read_to_string(repo_root("crates/rillane-ffi/include/rillane_ffi.h"))
        .expect("读取 rillane_ffi.h");
    let lib =
        std::fs::read_to_string(repo_root("crates/rillane-ffi/src/lib.rs")).expect("读取 lib.rs");

    let scan = |text: &str| -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let needle = "rillane_ffi_";
        let bytes = text.as_bytes();
        let mut i = 0;
        while let Some(pos) = text[i..].find(needle) {
            let start = i + pos;
            let mut end = start + needle.len();
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let name = &text[start..end];
            // 只收「名字后紧跟 (」的形态（声明/定义），跳过注释与提法
            let rest = text[end..].trim_start();
            if rest.starts_with('(') {
                names.insert(name.to_string());
            }
            i = end;
        }
        names
    };

    let header_names = scan(&header);
    let export_names = scan(&lib);
    assert!(
        !header_names.is_empty() && !export_names.is_empty(),
        "两侧都应扫描到符号（扫描器自身失效）"
    );
    let header_only: Vec<&String> = header_names.difference(&export_names).collect();
    let export_only: Vec<&String> = export_names.difference(&header_names).collect();
    assert!(
        header_only.is_empty(),
        "头文件多声明 {header_only:?}（链接期未定义引用面）"
    );
    assert!(
        export_only.is_empty(),
        "头文件少声明 {export_only:?}（导出面不可达——宿主桥接缺失）"
    );
}

/// 对账器自证：face 漏登记一个真实存在的键 → 本门以「多键」点名失败
/// （face 落后于实际面 = 漂移被放行，同门可查）。
#[test]
#[should_panic(expected = "ffi 面漂移 @ stats_json：多键 [\"tun_fd\"]")]
fn comparator_bites_on_face_lagging_reality() {
    let mut face = load_face();
    face["faces"]["stats_json"]["keys"]
        .as_object_mut()
        .expect("keys")
        .remove("tun_fd");
    // 全形态 stats（漏登记的是 face，不是实际面——实际面取完整真实形）
    let stats = serde_json::json!({
        "uptime_seconds": 1u64,
        "total_connections": 0u64,
        "active_connections": 0u64,
        "total_bytes_transferred": 0u64,
        "bytes_uploaded": 0u64,
        "bytes_downloaded": 0u64,
        "error_count": 0u64,
        "is_running": true,
        "tun_fd": 0i64,
    });
    assert_face(&stats, face_of(&face, "stats_json"), "stats_json");
}
