//! RIL-044 第一段：移动宿主生命周期契约（本地可核验面）。
//!
//! 验收条款「**停止可重复调用**」的真实主机测试：start → stop → 再次
//! stop（按文档化路径传 NULL——Rust 契约：stop 后句柄悬空，重复停止的
//! 安全性 = NULL 容忍 + 宿主侧清零句柄）→ 全查询面在 NULL 句柄上给出
//! 稳定缺席应答（-1 / NULL），全程无崩溃无 UB；start → stop → start
//! 再起新实例（生命周期可重复）。
//!
//! 宿主侧纪律（`platforms/android/.../RillaneVpnService.kt`）由文本契约
//! 门钉住：`stopVpn()` 守卫非零句柄、stop 后立即清零（重复停止安全性
//! 的宿主半边）、onRevoke/onDestroy 有序收尾 + 幂等兜底。
//!
//! 诚实边界：本门只钉生命周期停止面与宿主纪律；RIL-044 交付面的
//! 「配置/秘密引用注入」「网络变化」「有界诊断 IPC」需 RIL-043 真机
//! 批次（缓冲所有权/线程/背压），主勾选保持关闭。「核心不假定移动 VPN
//! 与宿主同 OS 进程」由 FFI fd 注入边界承载（宿主持 tun fd，Rust 侧
//! 经 `rillane_ffi_tun_start` 接收——不共享栈对象、不假设同进程 VPN 面）。

use std::ffi::{CStr, CString};

const CONTROL_PORT: u16 = 27997;
const SOCKS_PORT: u16 = 27594;

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

unsafe fn start(yaml: &str) -> *mut rillane_ffi::FfiHandle {
    let h = unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    assert!(!h.is_null(), "契约配置应启动成功");
    h
}

unsafe fn read_json(s: *mut std::os::raw::c_char) -> serde_json::Value {
    let raw = unsafe { CStr::from_ptr(s) }
        .to_str()
        .expect("UTF-8 JSON")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(s) };
    serde_json::from_str(&raw).expect("合法 JSON")
}

/// 「停止可重复调用」：stop(NULL) 与二次走 NULL 的收尾是稳定缺席应答；
/// 全查询面在 NULL 句柄上恒 -1/NULL；进程不崩。
#[test]
fn stop_is_repeatable_via_null_and_queries_stay_absent() {
    unsafe {
        // NULL stop：稳定 -1 + last_error（幂等收尾文档化路径）
        assert_eq!(rillane_ffi::rillane_ffi_stop(std::ptr::null_mut()), -1);
        let err = rillane_ffi::rillane_ffi_last_error();
        assert!(!err.is_null(), "NULL stop 应留 last_error");
        let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
        rillane_ffi::rillane_ffi_free_string(err);
        assert!(
            msg.contains("句柄为空"),
            "NULL stop 缺席理由应点名句柄，实际 {msg:?}"
        );

        // NULL 句柄上的全查询面：稳定缺席（-1 或 NULL），无崩溃
        assert_eq!(rillane_ffi::rillane_ffi_is_running(std::ptr::null()), -1);
        assert!(rillane_ffi::rillane_ffi_stats_json(std::ptr::null()).is_null());
        assert!(rillane_ffi::rillane_ffi_routing_json(std::ptr::null()).is_null());
        assert!(rillane_ffi::rillane_ffi_nodes_json(std::ptr::null()).is_null());
        assert!(rillane_ffi::rillane_ffi_dns_stats_json(std::ptr::null()).is_null());
        assert!(rillane_ffi::rillane_ffi_dns_resolvers_json(std::ptr::null()).is_null());
        assert!(rillane_ffi::rillane_ffi_flows_json(std::ptr::null(), 0, 50).is_null());
        let id = CString::new("flow-lifecycle-absent").unwrap();
        assert!(rillane_ffi::rillane_ffi_flow_json(std::ptr::null(), id.as_ptr()).is_null());
        assert_eq!(rillane_ffi::rillane_ffi_tun_stop(std::ptr::null_mut()), -1);

        // 真实 start → stop → NULL 二次收尾（宿主清零句柄后的调用形态）
        let yaml = test_config();
        let h = start(&yaml);
        assert_eq!(rillane_ffi::rillane_ffi_is_running(h), 1, "启动后应运行");
        assert_eq!(rillane_ffi::rillane_ffi_stop(h), 0, "首次 stop 应成功");
        // 句柄悬空后宿主纪律 = 清零 → 二次 stop 传 NULL（不触 UB 面）
        let zeroed: *mut rillane_ffi::FfiHandle = std::ptr::null_mut();
        assert_eq!(
            rillane_ffi::rillane_ffi_stop(zeroed),
            -1,
            "二次收尾是稳定缺席"
        );
        assert_eq!(rillane_ffi::rillane_ffi_is_running(zeroed), -1);
    }
}

/// 生命周期可重复：同一进程内 start → stop → start 新实例照常起、查询
/// 照常答、再 stop 干净收尾（移动宿主「停了再开」面）。
#[test]
fn lifecycle_is_repeatable_start_stop_start() {
    unsafe {
        let yaml = test_config();
        let h1 = start(&yaml);
        let stats1 = read_json(rillane_ffi::rillane_ffi_stats_json(h1));
        assert_eq!(stats1["is_running"], serde_json::json!(true));
        assert_eq!(rillane_ffi::rillane_ffi_stop(h1), 0, "第一实例收尾");

        let h2 = start(&yaml);
        assert_eq!(rillane_ffi::rillane_ffi_is_running(h2), 1, "第二实例应运行");
        let routing = read_json(rillane_ffi::rillane_ffi_routing_json(h2));
        assert!(routing.is_object(), "第二实例查询应答（生命周期可重复）");
        assert_eq!(rillane_ffi::rillane_ffi_stop(h2), 0, "第二实例收尾");
    }
}

/// 宿主纪律契约门（文本扫描，与符号门同一纪律）：
/// `stopVpn()` 必须守卫非零句柄、stop 后立即清零——重复停止的安全半边
/// 在宿主（Rust 契约：stop 后句柄悬空，二次触碰是 UB）；onRevoke 与
/// onDestroy 都必须走 `stopVpn()`（有序收尾 + 幂等兜底）。
#[test]
fn kotlin_host_keeps_repeatable_stop_discipline() {
    let kt = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../platforms/android/app/src/main/java/com/rillane/rillane/RillaneVpnService.kt",
    ))
    .expect("读取 RillaneVpnService.kt");

    // stopVpn 体：守卫 + 停 + 清零（顺序钉死——清零必须紧跟 stop）
    let body_start = kt
        .find("private fun stopVpn()")
        .expect("缺 stopVpn 收尾函数");
    let body = &kt[body_start..];
    let body_end = body
        .find("\n    }\n")
        .expect("stopVpn 函数体未闭合（扫描器边界）");
    let body = &body[..body_end];
    assert!(
        body.contains("if (ffiHandle != 0L)"),
        "stopVpn 必须守卫非零句柄（0 = 无效/已停，二次调用直接跳过）"
    );
    let stop_pos = body
        .find("RillaneFfi.stop(ffiHandle)")
        .expect("stopVpn 必须调 RillaneFfi.stop");
    let zero_pos = body[stop_pos..]
        .find("ffiHandle = 0")
        .expect("stop 后必须立即清零句柄（宿主半边的重复停止安全）");
    assert!(
        zero_pos < 120,
        "清零必须紧跟 stop（之间不得插入其他 FFI 调用——句柄已悬空）"
    );

    // onRevoke / onDestroy 都走 stopVpn（撤销有序收尾 + 销毁幂等兜底）
    for hook in ["override fun onRevoke()", "override fun onDestroy()"] {
        let pos = kt.find(hook).unwrap_or_else(|| panic!("缺 {hook}"));
        let tail = &kt[pos..];
        let next_hook = tail[1..]
            .find("override fun ")
            .map(|p| p + 1)
            .unwrap_or(tail.len());
        assert!(
            tail[..next_hook].contains("stopVpn()"),
            "{hook} 必须走 stopVpn()（撤销/销毁都收敛到同一幂等收尾）"
        );
    }
}

/// 对账器自证：宿主丢了清零纪律 → 本门必须点名失败。
#[test]
#[should_panic(expected = "stop 后必须立即清零句柄")]
fn comparator_bites_on_missing_handle_zeroing() {
    let kt = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../platforms/android/app/src/main/java/com/rillane/rillane/RillaneVpnService.kt",
    ))
    .expect("读取 RillaneVpnService.kt");
    // 模拟宿主回归：从文本里抹掉清零行后重放断言
    let tampered = kt.replace("            ffiHandle = 0\n", "");
    let body_start = tampered
        .find("private fun stopVpn()")
        .expect("缺 stopVpn 收尾函数");
    let body = &tampered[body_start..];
    let body_end = body.find("\n    }\n").expect("stopVpn 函数体未闭合");
    let body = &body[..body_end];
    assert!(
        body.contains("if (ffiHandle != 0L)"),
        "stopVpn 必须守卫非零句柄"
    );
    let stop_pos = body
        .find("RillaneFfi.stop(ffiHandle)")
        .expect("stopVpn 必须调 RillaneFfi.stop");
    let zero_pos = body[stop_pos..]
        .find("ffiHandle = 0")
        .expect("stop 后必须立即清零句柄（宿主半边的重复停止安全）");
    assert!(zero_pos < 120, "清零必须紧跟 stop");
}
