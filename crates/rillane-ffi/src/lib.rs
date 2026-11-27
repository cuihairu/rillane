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
use rillane_core::query::{FlowQueryFilter, FlowState};
use rillane_core::trace::FlowId;
use rillane_core::trace_json::{collector_stats_json, trace_json};
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
    let Some(yaml) = (unsafe { read_config_str(config_yaml, config_len) }) else {
        return ptr::null_mut();
    };
    // 直通路径不含解析面：配置里出现秘密引用 = 宿主走错启动口，
    // 把引用字面量当密码用是静默错误配置——fail-closed 指向正确入口。
    if yaml.contains(SECRET_REF_MARKER) {
        set_last_error(
            "config_yaml 含秘密引用，须经 rillane_ffi_start_with_secrets 提供 [secret.ref.missing]"
                .into(),
        );
        return ptr::null_mut();
    }
    start_from_yaml(yaml)
}

/// 读取并校验配置 YAML（两个启动口共用）：null/空、尾随 NUL 容忍、UTF-8。
/// 失败时已写入 last_error 并返回 None（口径同原 `rillane_ffi_start` 文案）。
///
/// # Safety
/// `config_yaml` 须指向 ≥ `config_len` 字节（可含尾随 NUL）。
unsafe fn read_config_str<'a>(config_yaml: *const c_char, config_len: usize) -> Option<&'a str> {
    if config_yaml.is_null() || config_len == 0 {
        set_last_error("config_yaml 为空".into());
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(config_yaml.cast::<u8>(), config_len) };
    // 容忍调用方传带尾随 NUL 的 C 字符串（Kotlin jstring→UTF-8 常见形态）
    let bytes = match bytes.iter().position(|&b| b == 0) {
        Some(0) => {
            set_last_error("config_yaml 以 NUL 开头".into());
            return None;
        }
        Some(i) => &bytes[..i],
        None => bytes,
    };
    match std::str::from_utf8(bytes) {
        Ok(s) => Some(s),
        Err(e) => {
            set_last_error(format!("config_yaml 非 UTF-8：{e}"));
            None
        }
    }
}

/// 捕获启动 panic 并收敛到 NULL + last_error（两个启动口共用收尾）
fn start_from_yaml(yaml: &str) -> *mut FfiHandle {
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

/// `${secret:<name>}` 引用标记（RIL-044 配置/秘密引用注入面）
const SECRET_REF_MARKER: &str = "${secret:";

/// 解析配置 YAML 里的 `${secret:<name>}` 秘密引用（RIL-044）。
///
/// 纪律（模块头与头文件同名口径）：
/// - **单遍扫描、替换值不重扫**——替换进输出的秘密值即使长得像引用
///   （值里含 `${secret:`）也按字面量对待，绝不二次展开（防递归注入）；
/// - **fail-closed**——缺右括号/空名/表值非字符串 → `secret.ref.malformed`，
///   表里没有对应键 → `secret.ref.missing`，绝不静默替换成空串；
/// - **表漂移不静默**——表里未被引用的键（模板改了引用名或键拼错）
///   → `secret.map.unused` 点名，不让宿主误以为秘密已接线。
fn resolve_secret_refs(
    yaml: &str,
    secrets: &serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<String> {
    let mut out = String::with_capacity(yaml.len());
    let mut rest = yaml;
    let mut used: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    while let Some(pos) = rest.find(SECRET_REF_MARKER) {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos + SECRET_REF_MARKER.len()..];
        let Some(close) = tail.find('}') else {
            anyhow::bail!(
                "秘密引用缺右括号 [secret.ref.malformed]：{}…",
                &rest[pos..(pos + 40).min(rest.len())]
            );
        };
        let name = &tail[..close];
        if name.is_empty() {
            anyhow::bail!("秘密引用名字为空 [secret.ref.malformed]");
        }
        match secrets.get(name) {
            Some(serde_json::Value::String(value)) => {
                used.insert(name);
                // 字面量插入，不重扫（非递归）
                out.push_str(value);
            }
            Some(_) => anyhow::bail!("秘密引用值须为字符串 [secret.ref.malformed]：{name}"),
            None => anyhow::bail!("秘密引用未提供 [secret.ref.missing]：{name}"),
        }
        rest = &tail[close + 1..];
    }
    out.push_str(rest);
    let unused: Vec<&String> = secrets
        .keys()
        .filter(|k| !used.contains(k.as_str()))
        .collect();
    if !unused.is_empty() {
        anyhow::bail!("秘密表含未使用键 [secret.map.unused]：{unused:?}");
    }
    Ok(out)
}

/// 以配置 YAML + 秘密引用表启动完整 runtime（RIL-044 配置/秘密引用注入面）。
///
/// config YAML 内 `${secret:<name>}` 由 `secrets_json`（JSON 对象，值全为
/// 字符串）解析替换：单遍非递归、fail-closed（稳定码 `secret.ref.missing` /
/// `secret.ref.malformed` / `secret.map.invalid` / `secret.map.unused`）。
/// 无引用的配置 + 空表 `{}` 等价 `rillane_ffi_start` 的直通路径。
///
/// # Safety
/// 两对指针同 `rillane_ffi_start` 口径（≥ len 字节 UTF-8，可含尾随 NUL）；
/// 返回句柄只能配对一次 `rillane_ffi_stop`。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_start_with_secrets(
    config_yaml: *const c_char,
    config_len: usize,
    secrets_json: *const c_char,
    secrets_len: usize,
) -> *mut FfiHandle {
    let Some(yaml) = (unsafe { read_config_str(config_yaml, config_len) }) else {
        return ptr::null_mut();
    };
    if secrets_json.is_null() || secrets_len == 0 {
        set_last_error("secrets_json 为空".into());
        return ptr::null_mut();
    }
    let sbytes = unsafe { std::slice::from_raw_parts(secrets_json.cast::<u8>(), secrets_len) };
    let sbytes = match sbytes.iter().position(|&b| b == 0) {
        Some(0) => {
            set_last_error("secrets_json 以 NUL 开头".into());
            return ptr::null_mut();
        }
        Some(i) => &sbytes[..i],
        None => sbytes,
    };
    let stext = match std::str::from_utf8(sbytes) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("secrets_json 非 UTF-8：{e}"));
            return ptr::null_mut();
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(stext) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("secrets_json 非法 JSON [secret.map.invalid]：{e}"));
            return ptr::null_mut();
        }
    };
    let Some(map) = parsed.as_object() else {
        set_last_error("secrets_json 须为 JSON 对象 [secret.map.invalid]".into());
        return ptr::null_mut();
    };
    if map.values().any(|v| !v.is_string()) {
        set_last_error("secrets_json 值须全为字符串 [secret.map.invalid]".into());
        return ptr::null_mut();
    }
    let resolved = match resolve_secret_refs(yaml, map) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("{e:#}"));
            return ptr::null_mut();
        }
    };
    start_from_yaml(&resolved)
}

/// JSON 值 → C 字符串（`into_raw`；调用方以 `rillane_ffi_free_string` 归还）
fn json_to_raw(value: serde_json::Value) -> *mut c_char {
    match CString::new(value.to_string()) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
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

/// 通知核心宿主底层网络已变化（RIL-044 生命周期契约「网络变化」面的核心半边）
///
/// 当下语义：冲刷 DNS 缓存（`DnsService::clear_cache` 透传）——换网后旧网
/// 缓存应答不再复用，后续解析走新网重查；DNS 块缺席/关闭 = 诚实 no-op 仍
/// 0（冲刷空即成功）。可重复调用（无状态、幂等）。在途转发流不主动斩断：
/// 会话排空边界归 RIL-022/023 消费侧（publisher 只记账），网络变化沿同一
/// 边界——旧网流自然失败，宿主不必也不得依赖本面斩流。
///
/// 返回 0 成功 / -1 句柄无效（NULL → -1 + last_error）。
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → -1）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_network_changed(handle: *const FfiHandle) -> i32 {
    if handle.is_null() {
        set_last_error("rillane_ffi_network_changed：句柄为空".into());
        return -1;
    }
    let h = unsafe { &*handle };
    match catch_unwind(AssertUnwindSafe(|| {
        if let Some(svc) = h.rillane.get_dns_service() {
            svc.clear_cache();
        }
    })) {
        Ok(()) => 0,
        Err(_) => {
            set_last_error("网络变化处理 panic（已拦截）".into());
            -1
        }
    }
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
    json_to_raw(dto)
}

// ---------------------------------------------------------------------------
// 查询面（RIL-150）：Android 四 Tab 数据源——与 rillaned 控制面同一字段
// 口径（routing/nodes/dns 缺席如实、flows 分页、flow 详情），移动端脚本
// 可直接复用控制面 DTO 字段名。全部 `handle -> *mut c_char`，`free_string`。
// ---------------------------------------------------------------------------

/// 路由概要 JSON（选路模式/默认与全局/直连出口/组/规则计数——首页模式
/// 只读面；`mode` 经 serde snake_case（rule/global/direct））
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → NULL + last_error）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_routing_json(handle: *const FfiHandle) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_routing_json：句柄为空".into());
        return ptr::null_mut();
    }
    let h = unsafe { &*handle };
    let cfg = h.rillane.get_config();
    let groups = serde_json::to_value(&cfg.routing.groups).unwrap_or(serde_json::Value::Null);
    json_to_raw(serde_json::json!({
        "schema_version": 1u32,
        "mode": cfg.routing.mode,
        "default_node": cfg.routing.default_node,
        "global_node": cfg.routing.global_node,
        "direct_node": cfg.routing.direct_node,
        "groups": groups,
        "rules_count": cfg.routing.rules.len(),
    }))
}

/// 节点 JSON（组实时质量报告 + 出口节点名/类型 + 订阅源——节点 Tab；
/// 组质量已 `Serialize`，出口只取 name/type 不泄凭证）
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → NULL + last_error）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_nodes_json(handle: *const FfiHandle) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_nodes_json：句柄为空".into());
        return ptr::null_mut();
    }
    let h = unsafe { &*handle };
    let cfg = h.rillane.get_config();
    let quality =
        serde_json::to_value(h.rillane.get_routing_quality()).unwrap_or(serde_json::Value::Null);
    let egress: Vec<serde_json::Value> = cfg
        .egress
        .iter()
        .map(|e| {
            let spec = serde_json::to_value(&e.spec).unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "name": e.name,
                "type": spec.get("type").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect();
    let subscriptions: Vec<serde_json::Value> = match h.rillane.get_subscription_manager() {
        Some(m) => m
            .list_subscriptions()
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "enabled": s.enabled,
                    "type": s.r#type,
                })
            })
            .collect(),
        None => Vec::new(),
    };
    json_to_raw(serde_json::json!({
        "schema_version": 1u32,
        "groups": quality,
        "egress": egress,
        "subscriptions": subscriptions,
    }))
}

/// DNS 统计 JSON（`/dns/stats` DTO 同款字段——设置 DNS 卡；
/// `network.dns` 块缺席 = enabled:false 零值如实）
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → NULL + last_error）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_dns_stats_json(handle: *const FfiHandle) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_dns_stats_json：句柄为空".into());
        return ptr::null_mut();
    }
    let h = unsafe { &*handle };
    let dto = match h.rillane.get_dns_service() {
        Some(svc) => {
            let s = svc.stats_snapshot();
            serde_json::json!({
                "schema_version": 1u32,
                "enabled": true,
                "listen": svc.listen().to_string(),
                "total_queries": s.total_queries,
                "cache_hits": s.cache_hits,
                "cache_misses": s.cache_misses,
                "cache_hit_rate": s.cache_hit_rate,
                "upstream_failures": s.upstream_failures,
                "pollution_suspected": s.pollution_suspected,
                "domestic_queries": s.domestic_queries,
                "trusted_queries": s.trusted_queries,
            })
        }
        None => serde_json::json!({
            "schema_version": 1u32,
            "enabled": false,
            "listen": null,
            "total_queries": 0u64,
            "cache_hits": 0u64,
            "cache_misses": 0u64,
            "cache_hit_rate": 0.0,
            "upstream_failures": 0u64,
            "pollution_suspected": 0u64,
            "domestic_queries": 0u64,
            "trusted_queries": 0u64,
        }),
    };
    json_to_raw(dto)
}

/// DNS 解析器形状 JSON（`/dns/resolvers` DTO 同款字段——设置 DNS 卡；
/// 块缺席 = enabled:false 空形态，`/dns/stats` 同款）
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → NULL + last_error）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_dns_resolvers_json(handle: *const FfiHandle) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_dns_resolvers_json：句柄为空".into());
        return ptr::null_mut();
    }
    let h = unsafe { &*handle };
    let dto = match h.rillane.get_dns_service() {
        Some(svc) => {
            let s = svc.resolver_snapshot();
            serde_json::json!({
                "schema_version": 1u32,
                "enabled": true,
                "listen": svc.listen().to_string(),
                "domestic": s.domestic,
                "trusted": s.trusted,
                "bootstrap": s.bootstrap,
                "bootstrap_mode": s.bootstrap_mode,
                "rules": s.rules,
                "default_group": s.default_group,
                "anti_poison": s.anti_poison,
                "timeout_ms": s.timeout_ms,
                "retries": s.retries,
                "cache_enabled": s.cache_enabled,
                "tls_skip_verify": s.tls_skip_verify,
                "egress_mark": s.egress_mark,
                "udp_egress_marked": s.udp_egress_marked,
                "dot_egress_marked": s.dot_egress_marked,
                "doh_egress_marked": s.doh_egress_marked,
            })
        }
        None => serde_json::json!({
            "schema_version": 1u32,
            "enabled": false,
            "listen": null,
            "domestic": Vec::<String>::new(),
            "trusted": Vec::<String>::new(),
            "bootstrap": Vec::<String>::new(),
            "bootstrap_mode": "",
            "rules": 0usize,
            "default_group": "",
            "anti_poison": "",
            "timeout_ms": 0u64,
            "retries": 0u32,
            "cache_enabled": false,
            "tls_skip_verify": false,
            "egress_mark": 0u32,
            "udp_egress_marked": false,
            "dot_egress_marked": false,
            "doh_egress_marked": false,
        }),
    };
    json_to_raw(dto)
}

/// 活动/近期连接分页 JSON（`/trace/flows` 同款信封与项字段——连接 Tab）。
/// `limit=0` 显式拒绝 → 信封内 `"error":"query.page.invalid"`（非 NULL）。
///
/// # Safety
/// `handle` 须为有效句柄或 NULL（NULL → NULL + last_error）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_flows_json(
    handle: *const FfiHandle,
    offset: usize,
    limit: usize,
) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_flows_json：句柄为空".into());
        return ptr::null_mut();
    }
    let h = unsafe { &*handle };
    if limit == 0 {
        return json_to_raw(serde_json::json!({
            "schema_version": 1u32,
            "error": "query.page.invalid",
        }));
    }
    let page = match h
        .rillane
        .flow_query()
        .list(&FlowQueryFilter::default(), offset, limit)
    {
        Ok(page) => page,
        Err(err) => {
            return json_to_raw(serde_json::json!({
                "schema_version": 1u32,
                "error": err.code(),
            }))
        }
    };
    let items: Vec<serde_json::Value> = page
        .items
        .iter()
        .map(|summary| {
            serde_json::json!({
                "flow": summary.flow.as_str(),
                "origin": summary.origin.as_str(),
                "generation": summary.generation,
                "state": match summary.state {
                    FlowState::Active => "active",
                    FlowState::Closed => "closed",
                },
                "events": summary.events,
                "first_wall_ms": summary.first_wall_ms,
                "last_code": summary.last_code,
            })
        })
        .collect();
    json_to_raw(serde_json::json!({
        "schema_version": 1u32,
        "total_matching": page.total_matching,
        "offset": page.offset,
        "limit": limit,
        "items": items,
    }))
}

/// 单流详情 JSON（`/trace/flow` 同款信封——连接详情；未知/无效 ID =
/// found:false + 稳定码 + 采集器计数，从不「未发包」结论）
///
/// # Safety
/// `handle`/`flow_id` 须有效（NULL → NULL + last_error）。
#[no_mangle]
pub unsafe extern "C" fn rillane_ffi_flow_json(
    handle: *const FfiHandle,
    flow_id: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        set_last_error("rillane_ffi_flow_json：句柄为空".into());
        return ptr::null_mut();
    }
    if flow_id.is_null() {
        set_last_error("rillane_ffi_flow_json：flow_id 为空".into());
        return ptr::null_mut();
    }
    let id = match unsafe { CStr::from_ptr(flow_id) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("rillane_ffi_flow_json：flow_id 非 UTF-8".into());
            return ptr::null_mut();
        }
    };
    let h = unsafe { &*handle };
    let flow = match FlowId::new(id) {
        Ok(flow) => flow,
        Err(err) => {
            return json_to_raw(serde_json::json!({
                "schema_version": 1u32,
                "found": false,
                "trace": null,
                "absence": {
                    "code": err.code(),
                    "note": err.context,
                },
            }))
        }
    };
    let dto = match h.rillane.flow_query().flow(&flow) {
        rillane_core::query::FlowRecord::Found(trace) => serde_json::json!({
            "schema_version": 1u32,
            "found": true,
            "trace": trace_json(&trace),
            "absence": null,
        }),
        rillane_core::query::FlowRecord::Absent(absent) => serde_json::json!({
            "schema_version": 1u32,
            "found": false,
            "trace": null,
            "absence": {
                "code": absent.code,
                "note": absent.note,
                "collector": collector_stats_json(&absent.collector),
            },
        }),
    };
    json_to_raw(dto)
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
    // 注入面健壮性：宿主可能传来已关闭/伪造 fd（double-detach 等宿主侧
    // 缺陷）。OwnedFd 接管前先以 F_GETFD 确认 fd 真实打开——坏 fd 若
    // 直接接管，try_clone 失败后 File drop 的 close(EBADF) 会触发 std
    // IO safety abort（整进程崩溃）而非本层的具名拒绝。
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("fd {fd} 未打开（F_GETFD：{err}）");
    }
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

    /// 读取 C 字符串 JSON 并释放
    unsafe fn read_json(s: *mut c_char) -> serde_json::Value {
        let raw = unsafe { CStr::from_ptr(s) }
            .to_str()
            .expect("返回串应为 UTF-8 JSON");
        let v: serde_json::Value = serde_json::from_str(raw).expect("返回串应为合法 JSON");
        unsafe { rillane_ffi_free_string(s) };
        v
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

    // ------------------------------------------------------------------
    // 查询面（RIL-150）：六 Tab 数据源——字段口径与控制面 DTO 一致
    // ------------------------------------------------------------------

    /// 查询面最小配置：direct 出口 + 空组 + 空规则（无 network.dns 块——
    /// DNS 缺席形态即该配置下验收）
    fn query_config() -> String {
        test_config()
    }

    #[test]
    fn routing_json_reports_mode_groups_and_rule_count() {
        let yaml = query_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null());
        let v = unsafe { read_json(rillane_ffi_routing_json(h)) };
        assert_eq!(v["schema_version"], 1u32);
        assert_eq!(v["mode"], "rule", "SelectionMode serde snake_case");
        assert_eq!(v["default_node"], "direct-main");
        assert_eq!(v["global_node"], serde_json::Value::Null);
        assert_eq!(v["direct_node"], serde_json::Value::Null);
        assert_eq!(v["groups"], serde_json::json!([]));
        assert_eq!(v["rules_count"], 0u64);
        unsafe { assert_eq!(rillane_ffi_stop(h), 0) };
    }

    #[test]
    fn nodes_json_reports_egress_names_types_and_empty_subscriptions() {
        let yaml = query_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null());
        let v = unsafe { read_json(rillane_ffi_nodes_json(h)) };
        assert_eq!(v["schema_version"], 1u32);
        assert_eq!(v["groups"], serde_json::json!([]), "空组质量报告如实空");
        let egress = v["egress"].as_array().expect("egress 数组");
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0]["name"], "direct-main");
        assert_eq!(egress[0]["type"], "direct", "EgressConfig tag=type");
        assert_eq!(v["subscriptions"], serde_json::json!([]));
        unsafe { assert_eq!(rillane_ffi_stop(h), 0) };
    }

    #[test]
    fn dns_json_absent_when_no_dns_block() {
        let yaml = query_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null());
        let stats = unsafe { read_json(rillane_ffi_dns_stats_json(h)) };
        assert_eq!(stats["enabled"], false, "无 network.dns 块 → 缺席如实");
        assert_eq!(stats["listen"], serde_json::Value::Null);
        assert_eq!(stats["total_queries"], 0u64);
        let resolvers = unsafe { read_json(rillane_ffi_dns_resolvers_json(h)) };
        assert_eq!(resolvers["enabled"], false);
        assert_eq!(resolvers["domestic"], serde_json::json!([]));
        assert_eq!(resolvers["trusted"], serde_json::json!([]));
        assert_eq!(resolvers["bootstrap"], serde_json::json!([]));
        unsafe { assert_eq!(rillane_ffi_stop(h), 0) };
    }

    #[test]
    fn flows_json_rejects_zero_limit_with_error_envelope() {
        let yaml = query_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null());
        // limit=0 → 非 NULL 错误信封（Kotlin 侧恒可解析 JSON）
        let v = unsafe { read_json(rillane_ffi_flows_json(h, 0, 0)) };
        assert_eq!(v["error"], "query.page.invalid");
        assert_eq!(v["schema_version"], 1u32);
        // 合法分页 → 信封形态齐全（demo 数据面无业务流 → items 空）
        let page = unsafe { read_json(rillane_ffi_flows_json(h, 0, 20)) };
        assert_eq!(page["schema_version"], 1u32);
        assert_eq!(page["total_matching"], 0u64);
        assert_eq!(page["offset"], 0u64);
        assert_eq!(page["limit"], 20u64);
        assert_eq!(page["items"], serde_json::json!([]));
        unsafe { assert_eq!(rillane_ffi_stop(h), 0) };
    }

    #[test]
    fn flow_json_unknown_id_reports_absent_with_collector() {
        let yaml = query_config();
        let h = unsafe { start_from(&yaml) };
        assert!(!h.is_null());
        let id = std::ffi::CString::new("flow-does-not-exist").expect("无 NUL");
        let v = unsafe { read_json(rillane_ffi_flow_json(h, id.as_ptr())) };
        assert_eq!(v["found"], false);
        assert!(v["trace"].is_null());
        let absence = &v["absence"];
        assert!(
            absence["code"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "缺席须带稳定码：{absence}"
        );
        assert!(
            absence["collector"]["active_traces"].is_u64(),
            "缺席答复带采集器计数（可对账）"
        );
        unsafe { assert_eq!(rillane_ffi_stop(h), 0) };
    }

    #[test]
    fn query_fns_reject_null_handle_and_null_flow_id() {
        unsafe {
            assert!(rillane_ffi_routing_json(ptr::null()).is_null());
            assert!(rillane_ffi_nodes_json(ptr::null()).is_null());
            assert!(rillane_ffi_dns_stats_json(ptr::null()).is_null());
            assert!(rillane_ffi_dns_resolvers_json(ptr::null()).is_null());
            assert!(rillane_ffi_flows_json(ptr::null(), 0, 20).is_null());
            assert!(rillane_ffi_flow_json(ptr::null(), c"x".as_ptr()).is_null());
            rillane_ffi_free_string(rillane_ffi_last_error());
            // 句柄有效但 flow_id 为空 → NULL + last_error（参数错误）
            let yaml = query_config();
            let h = start_from(&yaml);
            assert!(!h.is_null());
            assert!(rillane_ffi_flow_json(h, ptr::null()).is_null());
            rillane_ffi_free_string(rillane_ffi_last_error());
            assert_eq!(rillane_ffi_stop(h), 0);
        }
    }
}
