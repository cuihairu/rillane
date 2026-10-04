//! P3-2 示例插件：令牌桶限速（docs/design/plugin-loader.md §1.2 ABI）。
//!
//! 导出面：`memory` / `alloc` / `plugin_name` / `wants_payload`(=0) / `on_flow`。
//! 状态面：桶状态存活于插件实例全局（宿主侧 Store Mutex 串行化保证跨流共享，
//! §2.1/§9 偏差 4）；时钟由宿主 ctx 注入 `now_ms`（wasm32-unknown-unknown 无钟，
//! §0 载具裁决）。纯计算零 WASI、零宿主 import。

use std::sync::Mutex;

use serde::Deserialize;

/// 桶容量（并发突发上限）——示例取值，按需改后重编
const CAPACITY: i64 = 3;
/// 回补周期（ms）——每周期回 1 token
const REFILL_INTERVAL_MS: i64 = 1_000;

struct Bucket {
    tokens: i64,
    last_ms: i64,
}

// wasm32 单线程：std Mutex 即轻量锁；Host 侧 Store Mutex 已串行化全部调用
static BUCKET: Mutex<Bucket> = Mutex::new(Bucket {
    tokens: CAPACITY,
    last_ms: 0,
});

/// 取一个 token（宿主注入 now_ms 推进回补）。纯逻辑、可宿主单测。
fn take_token(now_ms: i64) -> bool {
    let mut b = BUCKET.lock().unwrap();
    let elapsed = now_ms - b.last_ms;
    if elapsed >= REFILL_INTERVAL_MS {
        let periods = elapsed / REFILL_INTERVAL_MS;
        b.tokens = (b.tokens + periods).min(CAPACITY);
        b.last_ms += periods * REFILL_INTERVAL_MS;
    }
    if b.tokens > 0 {
        b.tokens -= 1;
        true
    } else {
        false
    }
}

#[derive(Deserialize)]
struct Ctx {
    now_ms: i64,
}

// ---- ABI 导出（plugin-loader.md §1.2）----

/// 线性内存内 bump 分配器基址：静态数据区之上（页大小起步，growth 由本函数
/// 按需 memory_grow）
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
            // 示例插件：扩容失败（OOM）即弃——宿主侧 write 会越界报错并计 traps
            let delta_pages = (needed - cur_pages * 65_536).div_ceil(65_536);
            core::arch::wasm32::memory_grow(0, delta_pages);
        }
    }
    old
}

#[no_mangle]
pub extern "C" fn plugin_name() -> u32 {
    static NAME: &[u8] = b"rate-limit\0";
    NAME.as_ptr() as u32
}

#[no_mangle]
pub extern "C" fn wants_payload() -> u32 {
    0 // 限速不看载荷：宿主免首块探测（§2.2 零干扰路径）
}

/// 裁决入口：桶空 → deny（note 可见），否则 allow。返回负码 = 插件内错误。
#[no_mangle]
pub extern "C" fn on_flow(ctx_ptr: u32, ctx_len: u32, out_ptr: u32, out_cap: u32) -> i32 {
    // SAFETY：宿主契约（§1.2）——ctx_ptr 指向宿主刚写入的 ctx_len 字节
    let ctx_bytes = unsafe {
        core::slice::from_raw_parts(ctx_ptr as *const u8, ctx_len as usize)
    };
    let ctx: Ctx = match serde_json::from_slice(ctx_bytes) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let decision = if take_token(ctx.now_ms) {
        r#"{"action":"allow"}"#
    } else {
        r#"{"action":"deny","note":"rate limit: token bucket empty"}"#
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn burst_then_throttle_then_refill() {
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        // 容量内放行
        for i in 0..CAPACITY {
            assert!(take_token(base + i), "第 {} token 应放行", i + 1);
        }
        // 桶空即拒
        assert!(!take_token(base + CAPACITY), "桶空应拒绝");
        assert!(!take_token(base + CAPACITY + 100), "未到回补周期仍拒绝");
        // 一个周期后回补 1 token
        assert!(
            take_token(base + CAPACITY + REFILL_INTERVAL_MS),
            "回补后应放行"
        );
        // 长时间空闲回补封顶：恰 CAPACITY 次放行，第 CAPACITY+1 次拒
        let far = base + 10_000_000;
        for i in 0..CAPACITY {
            assert!(take_token(far + i), "空闲回补后 token {} 应放行", i + 1);
        }
        assert!(
            !take_token(far + CAPACITY),
            "第 {} 次应拒（回补封顶于容量）",
            CAPACITY + 1
        );
    }
}
