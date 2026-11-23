//! Android JNI 桥：Kotlin `RillaneFfi` object（包 `com.rillane.rillane`）直连。
//!
//! 符号形 `Java_com_rillane_rillane_RillaneFfi_<name>`；句柄以 `jlong` 传指针宽度值
//! （ARM32 上 jlong 仍 64 位，承载指针无损）。字符串经 JNI UTF-8 往返；
//! 错误经 `rillane_ffi_last_error` 在调用线程同侧取回（TLS 语义与 JNI 单线程
//! 调用约定对齐）。本模块仅 `target_os = "android"` 编译，宿主面零负担。

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use std::os::raw::c_char;

use crate::FfiHandle;
use crate::{
    rillane_ffi_dns_resolvers_json, rillane_ffi_dns_stats_json, rillane_ffi_flow_json,
    rillane_ffi_flows_json, rillane_ffi_free_string, rillane_ffi_is_running,
    rillane_ffi_last_error, rillane_ffi_nodes_json, rillane_ffi_routing_json,
    rillane_ffi_stats_json, rillane_ffi_stop, rillane_ffi_tun_start, rillane_ffi_tun_stop,
};

fn handle_from(j: jlong) -> *mut FfiHandle {
    // jlong(64) → usize → 指针：指针宽度截断安全（指针值本身不超宽度）
    j as usize as *mut FfiHandle
}

// jni 0.21：JNIEnv 方法多取 &mut（保守的 Java 交互面签名）
fn jstring_from(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(j) => j.into_raw(),
        // JString 构造失败（OOM 等）：返回 NULL，Kotlin 侧按可空处理
        Err(_) => std::ptr::null_mut(),
    }
}

fn config_bytes(env: &mut JNIEnv, config: &JString) -> Result<String, jstring> {
    match env.get_string(config) {
        Ok(s) => Ok(s.to_string_lossy().into_owned()),
        Err(_) => Err(std::ptr::null_mut()),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = unsafe { std::ffi::CStr::from_ptr(crate::rillane_ffi_version()) }
        .to_string_lossy()
        .into_owned();
    jstring_from(&mut env, &v)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_lastError(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let err = unsafe { rillane_ffi_last_error() };
    if err.is_null() {
        return std::ptr::null_mut();
    }
    let msg = unsafe { std::ffi::CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { rillane_ffi_free_string(err) };
    jstring_from(&mut env, &msg)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_start(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jlong {
    let yaml = match config_bytes(&mut env, &config) {
        Ok(s) => s,
        Err(null) => return null as jlong,
    };
    let h = unsafe { crate::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    h as usize as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_stop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    unsafe { rillane_ffi_stop(handle_from(handle)) }
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_isRunning(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    unsafe { rillane_ffi_is_running(handle_from(handle)) }
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_statsJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let s = unsafe { rillane_ffi_stats_json(handle_from(handle)) };
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { std::ffi::CStr::from_ptr(s) }
        .to_string_lossy()
        .into_owned();
    unsafe { rillane_ffi_free_string(s) };
    jstring_from(&mut env, &raw)
}

/// 查询面 JSON（RIL-150）：handle-only 六查询共用包装——NULL → 可空 jstring。
/// 命名口径同 `statsJson`：camelCase 对齐 Kotlin `external fun`。
fn query_json(
    env: &mut JNIEnv,
    handle: jlong,
    f: unsafe extern "C" fn(*const FfiHandle) -> *mut c_char,
) -> jstring {
    let s = unsafe { f(handle_from(handle)) };
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { std::ffi::CStr::from_ptr(s) }
        .to_string_lossy()
        .into_owned();
    unsafe { rillane_ffi_free_string(s) };
    jstring_from(env, &raw)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_routingJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    query_json(&mut env, handle, rillane_ffi_routing_json)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_nodesJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    query_json(&mut env, handle, rillane_ffi_nodes_json)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_dnsStatsJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    query_json(&mut env, handle, rillane_ffi_dns_stats_json)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_dnsResolversJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    query_json(&mut env, handle, rillane_ffi_dns_resolvers_json)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_flowsJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    limit: jlong,
) -> jstring {
    let s = unsafe { rillane_ffi_flows_json(handle_from(handle), offset as usize, limit as usize) };
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { std::ffi::CStr::from_ptr(s) }
        .to_string_lossy()
        .into_owned();
    unsafe { rillane_ffi_free_string(s) };
    jstring_from(&mut env, &raw)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_flowJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    flow_id: JString,
) -> jstring {
    // jstring → UTF-8 C 字符串（CString 保 NUL 终止——String 指针直接
    // 传 CStr::from_ptr 是越界读；id 含 NUL → NULL + last_error）
    let id_bytes = match env.get_string(&flow_id) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return std::ptr::null_mut(),
    };
    let id_c = match std::ffi::CString::new(id_bytes) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let s = unsafe { rillane_ffi_flow_json(handle_from(handle), id_c.as_ptr()) };
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { std::ffi::CStr::from_ptr(s) }
        .to_string_lossy()
        .into_owned();
    unsafe { rillane_ffi_free_string(s) };
    jstring_from(&mut env, &raw)
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_tunStart(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    fd: jint,
) -> jint {
    unsafe { rillane_ffi_tun_start(handle_from(handle), fd) }
}

#[no_mangle]
pub extern "system" fn Java_com_rillane_rillane_RillaneFfi_tunStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    unsafe { rillane_ffi_tun_stop(handle_from(handle)) }
}
