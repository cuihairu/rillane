//! rillane-ffi —— 移动端 C ABI 最小通路（P3-4）
//!
//! 面向 Android（VpnService）/iOS（NEPacketTunnelProvider）暴露的 C ABI：
//! 配置 YAML 字符串 → 启动完整 rillane runtime（与 rillaned 同一条 `RuntimeBuilder`
//! 路径），TUN fd 交由本层持有并跑**最小数据通路**——ICMP echo 应答轮转，
//! 供「VpnService 建 tun → 内核路由 → FFI 应答 → ping 通」的一轮流量验收。
//!
//! ## 边界（如实说明）
//! - TCP/UDP 的真实代理路径（IP 流重组 → FlowRouter → egress）随 P1-2
//!   TunIngress 落地接入；本层 `tun_start` 的 fd 持有与轮询循环即其接管点，
//!   届时以 TunIngress 替换 `echo_reply` 的位置，C ABI 形状不变。
//! - 异步任务内的运行时错误不进 `last_error`（TLS 只记录 FFI 调用同步错误，
//!   与 rillaned 控制面 rt_task 呈现路径同界）。
//!
//! ## 内存与线程约定
//! - 返回给 C 的字符串（`version`/`stats_json`/`last_error`）一律以
//!   `rillane_ffi_free_string` 归还；`last_error` 的指针在同线程下一次错误
//!   覆盖前有效。
//! - 所有句柄入参来自 `rillane_ffi_start`，`rillane_ffi_stop` 后即悬空，不得复用。
//! - 单实例独立 tokio runtime（worker 2——移动端省电取舍，见 `start`）。

use std::ffi::{c_char, CStr, CString};
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rillane_config::RillaneConfig;
use rillane_runtime::runtime_builder::RuntimeBuilder;

// TUN 接管面（fd 持有 + poll 循环）为 unix 语义（Android/iOS/Linux）；
// 非 unix 编译面留空壳（tun_start 运行期 Err，口径同平台面非 Linux 恒 Err）
#[cfg(unix)]
mod tun;
#[cfg(unix)]
pub use tun::echo_reply;

#[cfg(target_os = "android")]
mod jni_bridge;

// ---------------------------------------------------------------------------
// 内部实例
// ---------------------------------------------------------------------------

/// FFI 句柄（对 C 侧不透明；头文件里是 `typedef struct rillane_ffi_handle ...`）
pub struct FfiHandle {
    /// 实例私有 tokio runtime：单实例隔离，stop 时 shutdown_timeout 收尾
    tokio_rt: tokio::runtime::Runtime,
    rillane: rillane_runtime::runtime_builder::Runtime,
    /// TUN 线程停止旗标（poll 超时 200ms 内可见，见 tun::spawn）
    tun_stop: Arc<AtomicBool>,
    /// 当前 TUN 线程（Some = 在跑）；stop/rillane_ffi_tun_stop 时 join
    tun_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// 持有的 TUN fd（-1 = 未挂），仅观测面；所有权在线程内的 OwnedFd
    tun_fd: Arc<AtomicI32>,
}

impl FfiHandle {
    fn is_running(&self) -> bool {
        self.rillane.is_running()
    }
}

// ---------------------------------------------------------------------------
// last_error（TLS）
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(msg: String) {
    let c = CString::new(msg)
        .unwrap_or_else(|_| CString::new("last error contained NUL").expect("static"));
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(c));
}

fn take_last_error_str() -> Option<&'static str> {
    // 取走消息：错误是“一次性”的，读后即清，避免陈旧错误跨调用误报
    LAST_ERROR.with(|slot| {
        slot.borrow_mut().take().map(|c| {
            let leaked: &'static CStr = Box::leak(c.into_boxed_c_str());
            leaked.to_str().expect("last_error 恒由 String 构造，UTF-8")
        })
    })
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// 版本串（workspace version），指针静态有效
///
/// # Safety
/// 返回的指针生命周期为进程级，无需释放；仅读。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION
        .get_or_init(|| CString::new(env!("CARGO_PKG_VERSION")).expect("version 无 NUL"))
        .as_ptr()
}

/// 读取并清空同线程最近一次 FFI 错误（读后即清）；无错误返回 NULL
///
/// # Safety
/// 返回指针有效至同线程下一次错误设置前；用 `rillane_ffi_free_string` 释放。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_last_error() -> *mut c_char {
    match take_last_error_str() {
        Some(s) => match CString::new(s) {
            Ok(c) => c.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// 以配置 YAML 启动完整 rillane runtime，返回不透明句柄（失败 NULL + last_error）
///
/// # Safety
/// `config_yaml` 须指向 ≥ `config_len` 字节的合法 UTF-8（可含尾随 NUL，
/// 尾 NUL 会被剔除）；返回句柄只能配对一次 `rillane_ffi_stop`。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_start(
    config_yaml: *const c_char,
    config_len: usize,
) -> *mut FfiHandle {
    if config_yaml.is_null() || config_len == 0 {
        set_last_error("config_yaml 为空".into());
        return ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(config_yaml.cast::<u8>(), config_len) };
    // 容忍调用方传带尾随 NUL 的 C 字符串（Kotlin jstring→UTF-8 常见形态）
    let bytes = match bytes.iter().position(|&b| b == 0) {
        Some(0) => {
            set_last_error("config_yaml 以 NUL 开头".into());
            return ptr::null_mut();
        }
        Some(i) => &bytes[..i],
        None => bytes,
    };
    let yaml = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("config_yaml 非 UTF-8：{e}"));
            return ptr::null_mut();
        }
    };

    match catch_unwind(AssertUnwindSafe(|| start_inner(yaml))) {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            set_last_error(format!("启动失败：{e:#}"));
            ptr::null_mut()
        }
        Err(_) => {
            set_last_error("启动过程 panic（已拦截）".into());
            ptr::null_mut()
        }
    }
}

fn start_inner(yaml: &str) -> anyhow::Result<*mut FfiHandle> {
    let config: RillaneConfig = serde_yaml::from_str(yaml)?;
    // 移动端 worker=2：ingress/DNS/订阅面任务量小，多核让位省电（桌面 rillaned
    // 用默认 num_cpus，此处是 FFI 面的显式取舍）
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let rillane = RuntimeBuilder::new(config).build()?;
    tokio_rt.block_on(rillane.start())?;
    Ok(Box::into_raw(Box::new(FfiHandle {
        tokio_rt,
        rillane,
        tun_stop: Arc::new(AtomicBool::new(false)),
        tun_thread: Mutex::new(None),
        tun_fd: Arc::new(AtomicI32::new(-1)),
    })))
}

/// 停止并释放句柄（TUN 线程先行收尾，句柄此后悬空）；0 成功 / -1 失败
///
/// # Safety
/// `handle` 必须是 `rillane_ffi_start` 返回且尚未 stop 的指针；NULL 容忍
/// （-1 + last_error，供幂等收尾）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_stop(handle: *mut FfiHandle) -> i32 {
    if handle.is_null() {
        set_last_error("rillane_ffi_stop：句柄为空".into());
        return -1;
    }
    let boxed = unsafe { Box::from_raw(handle) };
    match catch_unwind(AssertUnwindSafe(|| stop_inner(boxed))) {
        Ok(()) => 0,
        Err(_) => {
            set_last_error("停止过程 panic（已拦截）".into());
            -1
        }
    }
}

fn stop_inner(h: Box<FfiHandle>) {
    tun_stop_inner(&h);
    let _ = h.tokio_rt.block_on(h.rillane.stop());
    // 收尾 shutdown：上限 2s，防个别收尾任务拖住调用线程（普通 async 任务
    // 在 await 点被取消，无阻塞线程滞留面）；Box 部分移出 tokio_rt 合法
    // （FfiHandle 无 Drop）
    h.tokio_rt.shutdown_timeout(Duration::from_secs(2));
}

/// 运行状态（1 运行 / 0 停止 / -1 句柄无效）
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → -1）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_is_running(handle: *const FfiHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &*handle };
    if h.is_running() {
        1
    } else {
        0
    }
}

/// 运行统计 JSON（调用方以 `rillane_ffi_free_string` 释放；句柄无效返回 NULL）
///
/// # Safety
/// `handle` 须为有效句柄或 NULL。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_stats_json(handle: *const FfiHandle) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_stats_json：句柄为空".into());
        return ptr::null_mut();
    }
    let h = unsafe { &*handle };
    let stats = h.rillane.get_stats();
    let dto = serde_json::json!({
        // RuntimeStats 未实现 Serialize（Instant 不可序列化）——FFI 面自持
        // DTO，字段名与 rillaned 控制面 /stats 形态对齐，移动端脚本可直接复用
        "uptime_seconds": stats.uptime_seconds,
        "total_connections": stats.total_connections,
        "active_connections": stats.active_connections,
        "total_bytes_transferred": stats.total_bytes_transferred,
        "bytes_uploaded": stats.bytes_uploaded,
        "bytes_downloaded": stats.bytes_downloaded,
        "error_count": stats.error_count,
        "is_running": h.is_running(),
        "tun_fd": h.tun_fd.load(Ordering::Relaxed),
    });
    match CString::new(dto.to_string()) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// 挂载 TUN fd 并起最小数据通路（ICMP echo 轮转）；0 成功 / -1 失败
///
/// fd 所有权转移至本层（调用方 detach 后不得再关闭）；重复挂载先停旧再起新。
///
/// # Safety
/// `handle` 须为有效句柄；`fd` 须为合法打开的 TUN（或测试替身）fd。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_tun_start(handle: *mut FfiHandle, fd: i32) -> i32 {
    if handle.is_null() || fd < 0 {
        set_last_error("rillane_ffi_tun_start：句柄或 fd 无效".into());
        return -1;
    }
    let h = unsafe { &*handle };
    match catch_unwind(AssertUnwindSafe(|| tun_start_inner(h, fd))) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            set_last_error(format!("TUN 启动失败：{e:#}"));
            -1
        }
        Err(_) => {
            set_last_error("TUN 启动 panic（已拦截）".into());
            -1
        }
    }
}

#[cfg(unix)]
fn tun_start_inner(h: &FfiHandle, fd: i32) -> anyhow::Result<()> {
    tun_stop_inner(h);
    // 所有权转移：OwnedFd 接管 fd（Android 侧 pfd.detachFd() 后传入；线程
    // 结束时随 File drop 关闭）
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let file = std::fs::File::from(owned);
    let writer = file.try_clone()?;
    h.tun_fd.store(fd, Ordering::Relaxed);
    let stop = h.tun_stop.clone();
    stop.store(false, Ordering::Relaxed);
    let join = tun::spawn(file, writer, stop.clone(), h.tun_fd.clone())?;
    let mut guard = match h.tun_thread.lock() {
        Ok(g) => g,
        Err(p) => {
            set_last_error("tun_thread lock 曾被毒化，恢复使用".into());
            p.into_inner()
        }
    };
    *guard = Some(join);
    Ok(())
}

#[cfg(not(unix))]
fn tun_start_inner(_h: &FfiHandle, _fd: i32) -> anyhow::Result<()> {
    anyhow::bail!("TUN 接管仅 unix 平台（Android/iOS/Linux）")
}

/// 停 TUN 线程（fd 随线程收尾关闭）；0 成功。未挂载亦返回 0（幂等）
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → -1）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_tun_stop(handle: *mut FfiHandle) -> i32 {
    if handle.is_null() {
        set_last_error("rillane_ffi_tun_stop：句柄为空".into());
        return -1;
    }
    let h = unsafe { &*handle };
    tun_stop_inner(h);
    0
}

fn tun_stop_inner(h: &FfiHandle) {
    h.tun_stop.store(true, Ordering::Relaxed);
    let mut guard = match h.tun_thread.lock() {
        Ok(g) => g,
        Err(p) => {
            set_last_error("tun_thread lock 曾被毒化，恢复使用".into());
            p.into_inner()
        }
    };
    let join = guard.take();
    if let Some(j) = join {
        // poll 200ms 超时兜底，正常 <300ms 返回；join 失败仅忽略（线程自然退出）
        let _ = j.join();
    }
}

/// 释放 `rillane_ffi_last_error`/`rillane_ffi_stats_json` 返回的字符串；NULL 容忍
///
/// # Safety
/// `s` 须来自本 crate 的 `into_raw`，且未释放过。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    /// FFI 测试面最小配置（端口取 rillane-ffi 专属段防撞；runtime 不绑 control 面，
    /// api_bind 仅配置承载）
    fn test_config() -> String {
        r#"
control:
  api_bind: 127.0.0.1:27990
  uds_path: null
  admin_token: test-token
telemetry:
  log_level: warn
  enable_metrics: false
  enable_tracing: false
ingress:
  - name: socks-in
    type: socks5
    bind: 127.0.0.1:27890
egress:
  - name: direct-main
    type: direct
routing:
  default_node: direct-main
  groups: []
  rules: []
"#
        .to_string()
    }

    unsafe fn start_from(yaml: &str) -> *mut FfiHandle {
        unsafe { rillane_ffi_start(yaml.as_ptr().cast::<c_char>(), yaml.len()) }
    }

    #[test]
    fn version_matches_cargo_pkg() {
        let v = unsafe { CStr::from_ptr(rillane_ffi_version()) }
            .to_str()
            .expect("版本串 UTF-8");
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn start_bad_config_sets_last_error_once() {
        let h = unsafe { start_from("control: { not-a-field: true }\n") };
        assert!(h.is_null(), "坏配置应返回 NULL");
        let err = unsafe { rillane_ffi_last_error() };
        assert!(!err.is_null(), "错误应已记录");
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().to_string();
        unsafe { rillane_ffi_free_string(err) };
        assert!(!msg.is_empty());
        // 读后即清：第二次读取应为 NULL
        assert!(unsafe { rillane_ffi_last_error() }.is_null());
    }

    #[test]
    fn start_rejects_null_and_empty() {
        unsafe {
            assert!(rillane_ffi_start(ptr::null(), 8).is_null());
            assert!(!rillane_ffi_last_error().is_null());
            let empty = b"\0";
            assert!(rillane_ffi_start(empty.as_ptr().cast::<c_char>(), 1).is_null());
            rillane_ffi_free_string(rillane_ffi_last_error());
        }
    }

    #[test]
    fn start_stop_roundtrip_with_stats() {
        let yaml = test_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null(), "合法配置应启动成功：{:?}", unsafe {
            rillane_ffi_last_error()
        });
        unsafe { assert_eq!(rillane_ffi_is_running(h), 1) };

        let stats = unsafe { rillane_ffi_stats_json(h) };
        assert!(!stats.is_null());
        let raw = unsafe { CStr::from_ptr(stats) }
            .to_str()
            .expect("stats UTF-8");
        let v: serde_json::Value = serde_json::from_str(raw).expect("stats 应为合法 JSON");
        assert_eq!(v["is_running"], serde_json::json!(true));
        assert!(v["uptime_seconds"].is_u64());
        assert_eq!(
            v["tun_fd"],
            serde_json::json!(-1),
            "未挂 TUN 时 fd 观测面为 -1"
        );
        unsafe { rillane_ffi_free_string(stats) };

        // 尾随 NUL 形态（Kotlin jstring 常见）也应被容忍
        let mut yaml_nul = test_config().into_bytes();
        yaml_nul.push(0);
        let h2 = unsafe { rillane_ffi_start(yaml_nul.as_ptr().cast::<c_char>(), yaml_nul.len()) };
        assert!(!h2.is_null(), "带尾随 NUL 的配置应启动成功");

        unsafe {
            assert_eq!(rillane_ffi_tun_start(h, -1), -1, "非法 fd 应被拒");
            rillane_ffi_free_string(rillane_ffi_last_error());
            assert_eq!(rillane_ffi_stop(h), 0, "首个句柄应正常停止");
            assert_eq!(rillane_ffi_stop(h2), 0);
            assert_eq!(rillane_ffi_stop(ptr::null_mut()), -1, "空句柄停止应报错");
            rillane_ffi_free_string(rillane_ffi_last_error());
        }
    }

    #[test]
    fn stats_and_is_running_on_null_handle() {
        unsafe {
            assert!(rillane_ffi_stats_json(ptr::null()).is_null());
            assert_eq!(rillane_ffi_is_running(ptr::null()), -1);
            rillane_ffi_free_string(rillane_ffi_last_error());
            rillane_ffi_free_string(ptr::null_mut()); // NULL 容忍不炸
        }
    }

    #[test]
    fn tun_start_rejects_bad_fd_and_stop_is_idempotent() {
        let yaml = test_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null());
        unsafe {
            assert_eq!(rillane_ffi_tun_start(ptr::null_mut(), 3), -1);
            rillane_ffi_free_string(rillane_ffi_last_error());
            // 未挂载时 stop 幂等返回 0
            assert_eq!(rillane_ffi_tun_stop(h), 0);
            // socketpair fd 可挂（真轮转路径已在 tun.rs 单测覆盖，此处只验
            // 挂载/卸载与句柄观测面）
            let (a, b) = UnixStream::pair().expect("socketpair");
            drop(a); // 关掉测试侧半边，轮转线程读尽即自然退出
            assert_eq!(rillane_ffi_tun_start(h, b.into_raw_fd()), 0);
            std::thread::sleep(Duration::from_millis(500)); // 等 EOF 收尾
            assert_eq!(
                (*h).tun_fd.load(Ordering::Relaxed),
                -1,
                "EOF 后 fd 观测面归 -1"
            );
            assert_eq!(rillane_ffi_tun_stop(h), 0);
            assert_eq!(rillane_ffi_stop(h), 0);
        }
    }
}
