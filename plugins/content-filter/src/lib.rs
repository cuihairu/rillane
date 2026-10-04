//! P3-2 示例插件：首块关键词内容过滤（docs/design/plugin-loader.md §1.2/§2.2）。
//!
//! 导出面：`memory` / `alloc` / `plugin_name` / `wants_payload`(=1) / `on_flow`。
//! 裁决面：ctx.first_chunk（base64，宿主首块探测注入，≤4096B）命中内置禁词表
//! 即 deny——MVP 只 allow/deny 二值不改写（§0 范围裁决）；纯计算零 WASI。

use serde::Deserialize;

/// 内置禁词表（示例取值：常见扫描器/注入探针；按需改后重编）。
/// 匹配语义：首块字节（小写化后）子串命中。
const BANNED: &[&str] = &["/wp-admin", "/.env", "phpmyadmin", "select%20", "<script"];

/// 纯逻辑判定（可宿主单测）：返回命中的禁词。
fn find_banned(first_chunk: &[u8]) -> Option<&'static str> {
    let lowered: Vec<u8> = first_chunk.iter().map(|b| b.to_ascii_lowercase()).collect();
    BANNED
        .iter()
        .find(|kw| {
            let kw = kw.as_bytes();
            lowered.windows(kw.len()).any(|w| w == kw)
        })
        .copied()
}

#[derive(Deserialize)]
struct Ctx {
    #[serde(default)]
    first_chunk: Option<String>,
}

// ---- ABI 导出（plugin-loader.md §1.2，与 rate-limit 同脚手架）----

static HEAP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(65_536);

#[no_mangle]
pub extern "C" fn alloc(size: u32) -> u32 {
    use std::sync::atomic::Ordering;
    let align = 8u32;
    let size = size.div_ceil(align) * align;
    let old = HEAP.fetch_add(size, Ordering::SeqCst);
    // 扩容面 wasm 专属（宿主 cargo test 只走纯逻辑面，不触 alloc）
    #[cfg(target_arch = "wasm32")]
    {
        let needed = (old + size) as usize;
        let cur_pages = core::arch::wasm32::memory_size(0);
        if needed > cur_pages * 65_536 {
            let delta_pages = (needed - cur_pages * 65_536).div_ceil(65_536);
            core::arch::wasm32::memory_grow(0, delta_pages);
        }
    }
    old
}

#[no_mangle]
pub extern "C" fn plugin_name() -> u32 {
    static NAME: &[u8] = b"content-filter\0";
    NAME.as_ptr() as u32
}

#[no_mangle]
pub extern "C" fn wants_payload() -> u32 {
    1 // 内容过滤必须看首块（§2.2：宿主探测 + allow 回放）
}

#[no_mangle]
pub extern "C" fn on_flow(ctx_ptr: u32, ctx_len: u32, out_ptr: u32, out_cap: u32) -> i32 {
    use base64::Engine as _;
    // SAFETY：宿主契约（§1.2）——ctx_ptr 指向宿主刚写入的 ctx_len 字节
    let ctx_bytes = unsafe {
        core::slice::from_raw_parts(ctx_ptr as *const u8, ctx_len as usize)
    };
    let ctx: Ctx = match serde_json::from_slice(ctx_bytes) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let chunk = match ctx.first_chunk.as_deref() {
        Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(c) => c,
            Err(_) => return -3,
        },
        None => Vec::new(), // 对端未发数据即 EOF：空载荷按 allow 放行
    };
    let decision = match find_banned(&chunk) {
        Some(kw) => format!(
            r#"{{"action":"deny","note":"content filter: keyword hit ({kw})"}}"#
        ),
        None => r#"{"action":"allow"}"#.to_string(),
    };
    if decision.len() > out_cap as usize {
        return -2;
    }
    // SAFETY：宿主契约——out_ptr/out_cap 由宿主 alloc 分配且容量足够（上方已查）
    unsafe {
        core::ptr::copy_nonoverlapping(
            decision.as_ptr(),
            out_ptr as *mut u8,
            decision.len(),
        );
    }
    decision.len() as i32
}

// ---- 宿主侧纯逻辑单测（cargo test 在 host 跑，§4.2）----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_hits_deny_clean_passes() {
        assert_eq!(find_banned(b"GET /wp-admin/setup.php"), Some("/wp-admin"));
        assert_eq!(find_banned(b"GET /.ENV"), Some("/.env"), "大小写不敏感");
        assert_eq!(find_banned(b"q=SELECT%20*%20FROM"), Some("select%20"));
        assert_eq!(find_banned(b"<script>alert(1)</script>"), Some("<script"));
        assert_eq!(find_banned(b"GET /index.html HTTP/1.1"), None, "干净载荷放行");
        assert_eq!(find_banned(b""), None, "空载荷放行");
    }
}
