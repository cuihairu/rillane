//! Android JNI 桥：Kotlin `SeepFfi` object（包 `com.seep.seep`）直连。
//!
//! 符号形 `Java_com_seep_seep_SeepFfi_<name>`；句柄以 `jlong` 传指针宽度值
//! （ARM32 上 jlong 仍 64 位，承载指针无损）。字符串经 JNI UTF-8 往返；
//! 错误经 `seep_ffi_last_error` 在调用线程同侧取回（TLS 语义与 JNI 单线程
//! 调用约定对齐）。本模块仅 `target_os = "android"` 编译，宿主面零负担。

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;

use crate::FfiHandle;
use crate::{
    seep_ffi_free_string, seep_ffi_is_running, seep_ffi_last_error, seep_ffi_stats_json,
    seep_ffi_stop, seep_ffi_tun_start, seep_ffi_tun_stop,
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
pub extern "system" fn Java_com_seep_seep_SeepFfi_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = unsafe { std::ffi::CStr::from_ptr(crate::seep_ffi_version()) }
        .to_string_lossy()
        .into_owned();
    jstring_from(&mut env, &v)
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_lastError(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let err = unsafe { seep_ffi_last_error() };
    if err.is_null() {
        return std::ptr::null_mut();
    }
    let msg = unsafe { std::ffi::CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { seep_ffi_free_string(err) };
    jstring_from(&mut env, &msg)
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_start(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jlong {
    let yaml = match config_bytes(&mut env, &config) {
        Ok(s) => s,
        Err(null) => return null as jlong,
    };
    let h = unsafe { crate::seep_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    h as usize as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_stop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    unsafe { seep_ffi_stop(handle_from(handle)) }
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_isRunning(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    unsafe { seep_ffi_is_running(handle_from(handle)) }
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_statsJson(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let s = unsafe { seep_ffi_stats_json(handle_from(handle)) };
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { std::ffi::CStr::from_ptr(s) }
        .to_string_lossy()
        .into_owned();
    unsafe { seep_ffi_free_string(s) };
    jstring_from(&mut env, &raw)
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_tunStart(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    fd: jint,
) -> jint {
    unsafe { seep_ffi_tun_start(handle_from(handle), fd) }
}

#[no_mangle]
pub extern "system" fn Java_com_seep_seep_SeepFfi_tunStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    unsafe { seep_ffi_tun_stop(handle_from(handle)) }
}
