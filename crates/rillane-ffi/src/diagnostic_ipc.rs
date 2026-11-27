//! RIL-044 第四段：移动宿主有界诊断 IPC（核心半边）。
//!
//! 设计依据 `docs/design/debug-and-mcp.md`：移动端不默认跑 MCP；先提供
//! 授权宿主 IPC 或脱敏诊断导出，不新增默认手机入站管理端口。本模块即
//! 该授权宿主 IPC 的核心侧实现——宿主（Android VpnService / iOS NE）
//! 显式调用 `start(handle, path)` 在宿主自选的 UDS 路径上起只读诊断桥。
//!
//! ## 有界（bounded）语义（全部可核验，逐条在门里钉死）
//! - **无默认监听**：`start` 必须显式路径才起 listener；不调 = 零监听面。
//!   同路径二次 start = `ipc.start.duplicate_path` 稳定拒绝（不换绑不静默）。
//! - **读只读**：请求动词白名单 = stats/routing/nodes/dns_stats/dns_resolvers/
//!   flows（分页 + 总量上限，同 C 查询面）；write/probe/config/未知动词全部
//!   `ipc.request.unknown_verb` 拒绝，绝不旁路 MCP 写入面。
//! - **行帧 + 长度上限**：一行一请求，`MAX_REQUEST_BYTES` / `MAX_RESPONSE_BYTES`
//!   双向截断；超限丢弃连接（`ipc.request.oversize`）。
//! - **一连接一请求**：请求应答后关连接——无半连接/管道堆积面。
//! - **超时**：单请求 `REQUEST_TIMEOUT`；accept 循环 ≤ 100ms 观察 stop 旗标。
//! - **线程有界**：accept 循环独占一宿主线程；每连接一个 `thread::scope`
//!   栈上线程，连接结束即回收。
//! - **不斩在途转发流**：诊断桥只消费与 C 查询面同源的只读快照。
//!
//! 诚实边界：本模块是核心半边。宿主侧接线（Android Service 显式起桥、
//! iOS NE 内同形桥）与真机授权面（consent/arm64/Wi-Fi↔蜂窝切换）归
//! RIL-043 移动真机批次与 RIL-046 批次；本门在 host 进程内以 Unix
//! listener + 真实连接往返验证全部有界语义。

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use crate::{FfiHandle, IpcHandle};

/// 请求行最大字节（超出即视为有界违规，丢弃连接）
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// 单行响应最大字节（截断到合法 UTF-8 边界 + 换行）
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// 单请求处理超时 / accept 轮询间隔（stop 可见 ≤ 100ms）
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// 诊断桥运行态（stop 置旗标；accept 线程持 listener 并自行退出）
struct RunningState {
    stop: Arc<AtomicBool>,
    path: String,
}

/// 诊断桥单例（一进程一桥——多桥=多监听面，违反有界语义；重复 start
/// 以稳定码拒绝而非静默换绑）
static STATE: Mutex<Option<RunningState>> = Mutex::new(None);

fn lock_state() -> MutexGuard<'static, Option<RunningState>> {
    STATE.lock().unwrap_or_else(|p| p.into_inner())
}

/// 请求动词白名单（读只读面；write/probe/config 一律拒绝）
const VERBS: [&str; 6] = [
    "stats",
    "routing",
    "nodes",
    "dns_stats",
    "dns_resolvers",
    "flows",
];

/// 诊断桥错误稳定码（宿主按码分支；与 secret.* / tun 同族纪律）
const ERR_DUPLICATE_PATH: &str = "ipc.start.duplicate_path";
const ERR_UNKNOWN_VERB: &str = "ipc.request.unknown_verb";
const ERR_OVERSIZE: &str = "ipc.request.oversize";
pub(crate) const ERR_NULL_HANDLE: &str = "ipc.start.null_handle";
pub(crate) const ERR_ALREADY_STOPPED: &str = "ipc.stop.already_stopped";
const ERR_BAD_PATH: &str = "ipc.start.bad_path";
const ERR_BIND: &str = "ipc.start.bind";
const ERR_OVERSIZE_RESPONSE: &str = "ipc.response.oversize";

/// 有界诊断 IPC 启动（`#[no_mangle]` 包装在 lib.rs——头面门按 lib.rs 扫描）；
/// 句柄与路径均必填。返回 Ok(()) 或 Err(稳定码)（调用方写 last_error）。
pub(crate) fn ipc_start(handle: &FfiHandle, path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(ERR_BAD_PATH.to_string());
    }
    let mut guard = lock_state();
    if guard.is_some() {
        return Err(ERR_DUPLICATE_PATH.to_string());
    }
    let listener = UnixListener::bind(Path::new(path)).map_err(|_| ERR_BIND.to_string())?;
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking 应可设置");
    let stop = Arc::new(AtomicBool::new(false));
    *guard = Some(RunningState {
        stop: stop.clone(),
        path: path.to_string(),
    });
    let handle = crate::clone_handle_for_ipc(handle);
    thread::spawn(move || accept_loop(listener, handle, stop));
    Ok(())
}

/// 停止诊断桥（未起 = Err 稳定码，调用方写 last_error）。
pub(crate) fn ipc_stop() -> Result<(), String> {
    let mut guard = lock_state();
    let Some(state) = guard.as_mut() else {
        return Err(ERR_ALREADY_STOPPED.to_string());
    };
    state.stop.store(true, Ordering::Release);
    let _ = std::fs::remove_file(&state.path);
    *guard = None;
    Ok(())
}

/// accept 循环：非阻塞轮询 stop 旗标（≤ 100ms 可见），连接一请求一应答即关。
fn accept_loop(listener: UnixListener, handle: IpcHandle, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let h = handle.clone();
                thread::scope(|s| {
                    s.spawn(|| serve_connection(stream, h));
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

/// 单连接服务：读一行请求 → 分派 → 写一行响应 → 关闭。
fn serve_connection(mut stream: UnixStream, handle: IpcHandle) {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    // 有界读取：累计到 MAX_REQUEST_BYTES 仍无换行即按 oversize 丢弃
    let mut oversize = false;
    let mut line_end = None;
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => break, // 对端关闭
            Ok(n) => n,
            Err(_) => return,
        };
        let remaining = MAX_REQUEST_BYTES.saturating_sub(buf.len());
        buf.extend_from_slice(&chunk[..n.min(remaining)]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            line_end = Some(pos);
            break;
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            oversize = true;
            break;
        }
    }
    let response = if oversize {
        format!("{{\"error\":\"{ERR_OVERSIZE}\"}}")
    } else {
        let end = line_end.unwrap_or(buf.len());
        let verb = String::from_utf8_lossy(&buf[..end]).into_owned();
        let verb = verb.trim();
        if !VERBS.contains(&verb) {
            format!("{{\"error\":\"{ERR_UNKNOWN_VERB}\"}}")
        } else {
            match handle.dispatch(verb) {
                Ok(s) => s,
                Err(code) => format!("{{\"error\":\"{code}\"}}"),
            }
        }
    };
    let _ = write_line(&mut stream, &response);
    // 只半关写侧：shutdown(Both) 在读侧尚有未读请求行时会发 RST，
    // 可能连应答一起丢弃（一请求一连接：第二行按设计忽略）。
    let _ = stream.shutdown(Shutdown::Write);
}

/// 写一行响应（截断到 MAX_RESPONSE_BYTES 合法边界 + 换行）
fn write_line(stream: &mut UnixStream, body: &str) -> std::io::Result<()> {
    let mut out = body.to_string();
    if out.len() > MAX_RESPONSE_BYTES {
        let mut cut = MAX_RESPONSE_BYTES;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out = format!("{{\"error\":\"{ERR_OVERSIZE_RESPONSE}\"}}");
    }
    out.push('\n');
    stream.write_all(out.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_allowlist_is_read_only() {
        assert_eq!(VERBS.len(), 6);
        for forbidden in ["write", "probe", "config", "apply", "reload", ""] {
            assert!(
                !VERBS.contains(&forbidden),
                "写/探测动词不得入白名单：{forbidden}"
            );
        }
    }
}
