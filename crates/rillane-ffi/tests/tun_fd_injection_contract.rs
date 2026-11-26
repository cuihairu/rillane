//! RIL-043 第二段：TUN fd 注入面契约（宿主视角集成面，本地可核验）。
//!
//! 验收条款「核心不假定移动 VPN 与宿主同 OS 进程」的注入半边：宿主
//! （Android VpnService）持 tun fd，经 `rillane_ffi_tun_start(handle, fd)`
//! 移交所有权。本门钉注入面在故障 fd 下的行为（经公共导出面调用，
//! 补 lib.rs 单测已有的 -1 返回/挂载成功面）：
//! 具名拒绝——NULL 句柄 / 负 fd 必须留点名 last_error（宿主可诊断）；
//! 确定性坏 fd——远超 RLIMIT/nr_open 的 fd 号进程内不可能打开（无竞态），
//! 失败必须具名且句柄不被污染：观测面 tun_fd 保持未挂载标记 -1、
//! 重挂载真实 fd 照常成功（不留半挂载状态）、stop 收尾照常；
//! 幂等——未挂载 tun_stop 重复调用恒 0。
//!
//! 源纪律文本门：try_clone 必须先于 tun_fd 挂载（EBADF 走不到 store），
//! 句柄初始与 TUN 线程退出都以 -1 为未挂载标记。
//!
//! 诚实边界：真实 TUN 设备数据通路（ICMP 轮转 + 真隧道流量）属真机
//! 批次，RIL-043 主勾选保持关闭；此处 socketpair 只作可挂载性证明。

use std::ffi::CStr;
use std::os::unix::io::IntoRawFd;
use std::os::unix::net::UnixStream;

/// 远超 RLIMIT_NOFILE/nr_open 的 fd 号：进程内不可能打开（无竞态），
/// dup 确定性失败，close(EBADF) 亦无副作用
const IMPOSSIBLE_FD: i32 = 1_000_000_000;

fn test_config(control: u16, socks: u16) -> String {
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

unsafe fn start(control: u16, socks: u16) -> *mut rillane_ffi::FfiHandle {
    let yaml = test_config(control, socks);
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

/// 取走一次性 last_error（读后即清语义）
unsafe fn last_error_msg() -> String {
    let err = unsafe { rillane_ffi::rillane_ffi_last_error() };
    assert!(!err.is_null(), "应留 last_error");
    let msg = unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { rillane_ffi::rillane_ffi_free_string(err) };
    msg
}

unsafe fn stats_tun_fd(h: *const rillane_ffi::FfiHandle) -> i64 {
    let v = unsafe { read_json(rillane_ffi::rillane_ffi_stats_json(h)) };
    v["tun_fd"].as_i64().expect("stats 应携带 tun_fd 观测面")
}

/// 具名拒绝：NULL 句柄 / 负 fd 的拒绝必须留点名理由（宿主 lastError 可
/// 诊断），拒绝路径不得触碰 tun_fd 观测面；tun_stop 的 NULL 缺席同样具名。
#[test]
fn invalid_injections_are_named_rejections() {
    unsafe {
        assert_eq!(
            rillane_ffi::rillane_ffi_tun_start(std::ptr::null_mut(), 7),
            -1,
            "NULL 句柄应被拒"
        );
        let msg = last_error_msg();
        assert!(
            msg.contains("句柄或 fd 无效"),
            "NULL 注入缺席理由应点名，实际 {msg:?}"
        );

        // 真实句柄 + 负 fd：同一条具名拒绝路径
        let h = start(27998, 27595);
        assert_eq!(
            rillane_ffi::rillane_ffi_tun_start(h, -1),
            -1,
            "负 fd 应被拒"
        );
        let msg = last_error_msg();
        assert!(
            msg.contains("句柄或 fd 无效"),
            "负 fd 缺席理由应点名 fd，实际 {msg:?}"
        );
        assert_eq!(stats_tun_fd(h), -1, "拒绝路径不得写 tun_fd 观测面");

        // tun_stop NULL：具名缺席（幂等收尾的文档化路径）
        assert_eq!(rillane_ffi::rillane_ffi_tun_stop(std::ptr::null_mut()), -1);
        let msg = last_error_msg();
        assert!(
            msg.contains("句柄为空"),
            "tun_stop NULL 应点名句柄：{msg:?}"
        );
        assert_eq!(rillane_ffi::rillane_ffi_stop(h), 0);
    }
}

/// 确定性坏 fd：远超 nr_open 的 fd 号进程内不可能打开（无竞态面），
/// dup 必失败 → 具名「TUN 启动失败」。失败后句柄不被污染：观测面保持
/// -1、句柄仍存活、未挂载 tun_stop 幂等、重挂载真实 fd 照常成功
/// （socketpair 替身，EOF 自然收尾）——不留半挂载状态。
#[test]
fn impossible_fd_fails_named_without_tainting_handle() {
    unsafe {
        let h = start(27999, 27596);
        assert_eq!(stats_tun_fd(h), -1, "初始观测面 = 未挂载标记 -1");

        assert_eq!(
            rillane_ffi::rillane_ffi_tun_start(h, IMPOSSIBLE_FD),
            -1,
            "进程内不可能打开的 fd 必须确定性失败"
        );
        let msg = last_error_msg();
        assert!(
            msg.contains("TUN 启动失败"),
            "坏 fd 失败理由应具名，实际 {msg:?}"
        );

        // 失败路径不污染：观测面不动、句柄存活、tun_stop 幂等
        assert_eq!(stats_tun_fd(h), -1, "EBADF 路径不得写 tun_fd 观测面");
        assert_eq!(rillane_ffi::rillane_ffi_is_running(h), 1, "句柄应仍存活");
        assert_eq!(rillane_ffi::rillane_ffi_tun_stop(h), 0, "未挂载 stop 幂等");

        // 重挂载照常成功（坏 fd 不得留下半挂载状态）
        let (a, b) = UnixStream::pair().expect("socketpair");
        drop(a); // 关掉测试侧半边，轮转线程读尽 EOF 自然退出
        assert_eq!(
            rillane_ffi::rillane_ffi_tun_start(h, b.into_raw_fd()),
            0,
            "坏 fd 失败后重挂载必须成功"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(stats_tun_fd(h), -1, "EOF 收束后观测面复位 -1");
        assert_eq!(rillane_ffi::rillane_ffi_tun_stop(h), 0);
        assert_eq!(rillane_ffi::rillane_ffi_stop(h), 0);
    }
}

/// 幂等：未挂载句柄上 tun_stop 重复调用恒 0，观测面不动，收尾照常。
#[test]
fn unmounted_tun_stop_is_repeatable() {
    unsafe {
        let h = start(28000, 27597);
        assert_eq!(stats_tun_fd(h), -1);
        assert_eq!(
            rillane_ffi::rillane_ffi_tun_stop(h),
            0,
            "未挂载首次 stop 应 0"
        );
        assert_eq!(
            rillane_ffi::rillane_ffi_tun_stop(h),
            0,
            "重复 stop 仍 0（幂等）"
        );
        assert_eq!(stats_tun_fd(h), -1, "幂等 stop 不得动观测面");
        assert_eq!(rillane_ffi::rillane_ffi_stop(h), 0);
    }
}

/// 源纪律文本门：挂载顺序 + 未挂载标记。
/// unix `tun_start_inner` 必须 try_clone 在前、`tun_fd.store(fd)` 在后
/// （EBADF 失败路径走不到 store，观测面才不被污染）；句柄构造初始与
/// TUN 线程退出都必须落未挂载标记 -1。
#[test]
fn fd_mount_discipline_is_pinned_in_source() {
    let lib = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("读取 lib.rs");

    assert!(
        lib.contains("tun_fd: Arc::new(AtomicI32::new(-1))"),
        "句柄初始 tun_fd 必须是未挂载标记 -1（观测面口径）"
    );
    let body_start = lib.find("fn tun_start_inner").expect("缺 tun_start_inner");
    let body = &lib[body_start..];
    let body_end = body
        .find("\n}\n")
        .expect("tun_start_inner 函数体未闭合（扫描器边界）");
    let body = &body[..body_end];
    let clone_pos = body
        .find("file.try_clone()?")
        .expect("tun_start_inner 必须先 try_clone 确认 fd 可用");
    let store_pos = body
        .find("h.tun_fd.store(fd")
        .expect("tun_start_inner 必须挂载 tun_fd 观测面");
    assert!(
        clone_pos < store_pos,
        "tun_fd 只能在 try_clone 成功后挂载（EBADF 失败路径不得污染观测面）"
    );

    let tun = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tun.rs"),
    )
    .expect("读取 tun.rs");
    assert!(
        tun.contains("tun_fd.store(-1"),
        "TUN 线程退出必须复位未挂载标记 -1（观测面收回口径）"
    );
}

/// 对账器自证：挂载前丢了 try_clone 验证 → 本门必须点名失败。
#[test]
#[should_panic(expected = "tun_start_inner 必须先 try_clone")]
fn comparator_bites_on_mount_without_clone() {
    let lib = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("读取 lib.rs");
    // 模拟回归：抹掉 try_clone 验证行后重放顺序门
    let tampered = lib.replacen("let writer = file.try_clone()?;", "", 1);
    let body_start = tampered
        .find("fn tun_start_inner")
        .expect("缺 tun_start_inner");
    let body = &tampered[body_start..];
    let body_end = body.find("\n}\n").expect("tun_start_inner 函数体未闭合");
    let body = &body[..body_end];
    let clone_pos = body
        .find("file.try_clone()?")
        .expect("tun_start_inner 必须先 try_clone 确认 fd 可用");
    let store_pos = body
        .find("h.tun_fd.store(fd")
        .expect("必须挂载 tun_fd 观测面");
    assert!(clone_pos < store_pos, "tun_fd 只能在 try_clone 成功后挂载");
}
