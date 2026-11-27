//! FFI 查询面契约（RIL-083）：RIL-150 冻结形（schema_version=1）的
//! **exact 面**钉在 `contracts/schema_v1/ffi_face_v1.json`——移动端脚本
//! （Android Kotlin / iOS Swift）按字段名消费，加键减键都要求显式过门
//! （contracts/schema_v1/README.md 的 schema_v2 目录事务）。
//!
//! 对账面**活面取证**：真实启动 runtime，七查询逐一断言；并经 socks5
//! 入站 → direct 出口 → 本机 echo 监听的真实 TCP 往返验证诊断轨迹
//! 活面——RIL-083 第二段起 TCP 入口流接 SessionTracer（TracedFlowOutput），
//! 真实流量过后 flows 列表非空，flows_item 项面与 flow_found 详情面
//! 均从活 daemon 取数钉死；未知 ID 仍走 flow_absent 稳定缺席码。
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
const UDP_ECHO_PORT: u16 = 27594;

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
    //    活面取证——RIL-083 第二段起入口流接 SessionTracer（TracedFlowOutput），
    //    流量必须产出轨迹并收口，不得再回到「流量过后仍空」的旧空态 --
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
        // start 返回与入站监听 bind 完成之间有竞态（并行 workspace 全量
        // 下曾见 ConnectionRefused）——有界重试只等监听就绪，超时仍具名失败。
        let mut sock = (0..100)
            .find_map(|_| std::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT)).ok())
            .expect("连 socks 入站（2s 内监听应就绪）");
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

    // -- RIL-083 第四段：真实 SOCKS5 UDP ASSOCIATE → direct → 本机 UDP
    //    echo 往返，控制链 EOF 吊销后关联轨迹必须入活面（origin
    //    association / last_code association.reclaimed / 映射事件在场）--
    let udp_echo = std::net::UdpSocket::bind(("127.0.0.1", UDP_ECHO_PORT)).expect("UDP echo 绑定");
    udp_echo
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("UDP echo 超时");
    let udp_server = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        if let Ok((n, peer)) = udp_echo.recv_from(&mut buf) {
            let _ = udp_echo.send_to(&buf[..n], peer);
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    });
    {
        use std::io::{Read, Write};
        let mut control = std::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT))
            .expect("连 socks 入站（UDP ASSOCIATE 控制链）");
        control.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
        let mut method = [0u8; 2];
        control.read_exact(&mut method).expect("method reply");
        assert_eq!(method, [0x05, 0x00]);
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("ASSOCIATE 请求");
        let mut reply = [0u8; 10];
        control.read_exact(&mut reply).expect("ASSOCIATE 应答");
        assert_eq!(reply[1], 0x00, "ASSOCIATE 应成功");
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let relay = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("UDP 客户端");
        relay
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("UDP 超时");
        // SOCKS5 UDP 请求头：ATYP=IPv4 + DST 127.0.0.1:UDP_ECHO_PORT + payload
        let mut req = vec![0, 0, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&UDP_ECHO_PORT.to_be_bytes());
        req.extend_from_slice(b"udp-contract");
        let relay_addr = format!("127.0.0.1:{relay_port}");
        relay.send_to(&req, &relay_addr).expect("UDP 上行");
        let mut buf = [0u8; 64];
        let (n, _) = relay.recv_from(&mut buf).expect("UDP 回声");
        assert_eq!(&buf[n - 12..n], b"udp-contract", "UDP 往返逐字节还原");
        // 控制链 EOF → force_revoke → 轨迹 association.reclaimed 终态
        drop(control);
    }
    udp_server.join().expect("UDP echo 线程");

    // 流量收口在独立任务：有界重试等轨迹入采集器并到终态（2s 内应就绪），
    // 超时仍具名失败——不把「迟到」当「恒空」放行
    let mut live_page = None;
    for _ in 0..100 {
        let page = unsafe { read_json(rillane_ffi::rillane_ffi_flows_json(h, 0, 50)) };
        let items = page["items"].as_array().cloned().expect("items 数组");
        if items
            .first()
            .map(|i| i["state"] == serde_json::json!("closed"))
            .unwrap_or(false)
        {
            live_page = Some(page);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let page = live_page.expect(
        "TCP 入口流接线后，真实流量必须产出轨迹并收口——恒 active/恒空说明接线回退或轨迹未准入",
    );

    // -- flows_item 活面：真实 socks5 流条目（接管→计划→关闭）。
    //    RIL-083 第四段起列表含 UDP 关联条目，按 origin 取 TCP 流条目核对 --
    let first = page["items"]
        .as_array()
        .expect("items 数组")
        .iter()
        .find(|i| i["origin"] == serde_json::json!("stream"))
        .expect("TCP 流条目必须在场");
    assert_face(first, face_of(&face, "flows_item"), "flows_item");
    assert_eq!(first["origin"], serde_json::json!("stream"), "TCP 流语义");
    assert_eq!(
        first["state"],
        serde_json::json!("closed"),
        "流量收口后已关闭"
    );
    assert_eq!(
        first["last_code"],
        serde_json::json!("session.closed"),
        "正常收口码（失败应为 session.failed）"
    );
    assert!(
        first["events"].as_u64().unwrap_or(0) >= 3,
        "轨迹至少含 takeover/plan/closed 三事件：{first}"
    );
    assert_eq!(
        first["generation"],
        serde_json::json!("local"),
        "构建期配置代际"
    );

    // -- flow_found 活面：按条目流 ID 取详情，事件序列与列表口径一致 --
    let flow_id = CString::new(first["flow"].as_str().expect("flow id 字符串")).expect("ID");
    let found = unsafe { read_json(rillane_ffi::rillane_ffi_flow_json(h, flow_id.as_ptr())) };
    assert_face(&found, face_of(&face, "flow_found"), "flow_found");
    assert_eq!(found["found"], serde_json::json!(true), "活面流必须命中");
    let trace = &found["trace"];
    assert_eq!(trace["closed"], serde_json::json!(true));
    assert_eq!(
        trace["events"].as_array().map(Vec::len),
        first["events"].as_u64().map(|n| n as usize),
        "详情事件数与列表摘要一致"
    );
    assert_eq!(
        trace["events"][0]["code"],
        serde_json::json!("session.takeover"),
        "轨迹首事件为接管（采集器准入锚点）"
    );

    // -- RIL-083 第四段：UDP 关联活面——真实 SOCKS5 UDP 往返后列表必含
    //    origin=association 的闭合轨迹，association.mapped 与 reclaimed
    //    终码在场（同一 exact flows_item 面，语义分侧不另立面） --
    let udp_item = {
        let mut found = None;
        for _ in 0..100 {
            let page = unsafe { read_json(rillane_ffi::rillane_ffi_flows_json(h, 0, 50)) };
            found = page["items"]
                .as_array()
                .expect("items 数组")
                .iter()
                .find(|i| i["origin"] == serde_json::json!("association"))
                .cloned();
            if found
                .as_ref()
                .is_some_and(|i| i["state"] == serde_json::json!("closed"))
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        found.expect("UDP 关联面接线后真实流量必须产出轨迹——恒缺席说明 attach_trace_wiring 回退")
    };
    assert_face(&udp_item, face_of(&face, "flows_item"), "flows_item");
    assert_eq!(udp_item["state"], serde_json::json!("closed"));
    assert_eq!(
        udp_item["last_code"],
        serde_json::json!("association.reclaimed"),
        "控制链 EOF 吊销 = reclaimed 终码"
    );
    assert_eq!(
        udp_item["generation"],
        serde_json::json!("local"),
        "关联面代际与 TCP 面同源"
    );
    assert!(
        udp_item["events"].as_u64().unwrap_or(0) >= 4,
        "关联轨迹至少 takeover/plan/mapped/reclaimed 四事件：{udp_item}"
    );
    let udp_id = CString::new(udp_item["flow"].as_str().expect("flow id")).expect("ID");
    let udp_found = unsafe { read_json(rillane_ffi::rillane_ffi_flow_json(h, udp_id.as_ptr())) };
    assert_face(&udp_found, face_of(&face, "flow_found"), "flow_found");
    assert_eq!(udp_found["found"], serde_json::json!(true));
    let udp_trace = &udp_found["trace"];
    assert_eq!(
        udp_trace["events"][0]["code"],
        serde_json::json!("session.takeover")
    );
    assert!(
        udp_trace["events"]
            .as_array()
            .expect("events 数组")
            .iter()
            .any(|e| e["code"] == serde_json::json!("association.mapped")),
        "详情轨迹必含映射建立观测事件"
    );
    assert!(
        !udp_trace["events"]
            .as_array()
            .expect("events 数组")
            .iter()
            .any(|e| e["code"]
                .as_str()
                .is_some_and(|c| c.starts_with("transfer."))),
        "首字节未逐次测量——不造数"
    );

    // -- 活面取证后的面标记：pending 标记不得回潮（摘除是显式动作） --
    for live_id in ["flows_envelope", "flows_item", "flow_found"] {
        assert_ne!(
            face["faces"][live_id]["verification"], "pending_live_trace_wiring",
            "面 {live_id} 已活面取证（RIL-083 第二段）——pending 标记不得回潮"
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

/// 对账器自证：实现丢一个已声明键（减键=破坏兼容）→ 本门以「缺键」点名
/// 失败（面保持冻结不动，丢键的是实际投影——消费方按字段名取数即断）。
#[test]
#[should_panic(expected = "ffi 面漂移 @ stats_json：缺键 [\"uptime_seconds\"]")]
fn comparator_bites_on_dropped_key() {
    let face = load_face();
    let stats = serde_json::json!({
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
