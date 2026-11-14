//! 进程级 relay IO 性能参数（P3-5 performance-io.md §2-D1/§3）。
//!
//! `EgressConnector::forward(Flow)` 无 config 通道（rillane-core lib.rs trait
//! 签名），relay 缓冲走进程级单值：`RuntimeBuilder::build` 从
//! `performance:` 块读取并在此设定一次（启动期，变更需重启——P1-5 池
//! 参数烧构造期同律），rillane-protocols 出站与 mesh 面全部 relay 点读取。

use std::sync::atomic::{AtomicUsize, Ordering};

/// tokio `copy_bidirectional` 内部缓冲（与 tokio 缺省一致）——未配置时
/// 全链路行为与现状逐字节一致（performance-io.md D-5）。
pub const DEFAULT_RELAY_BUFFER: usize = 8192;

/// 缓冲合法上界：1 MiB（E3——每流双份，按并发量估算内存代价）。
pub const MAX_RELAY_BUFFER: usize = 1024 * 1024;

static RELAY_BUFFER: AtomicUsize = AtomicUsize::new(DEFAULT_RELAY_BUFFER);

/// 设定进程级 relay 缓冲（字节）。非法值报错（E1 二次防御——schema
/// validate 已先行拦截，此处兜底程序化构造路径）。
pub fn set_relay_buffer(n: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=MAX_RELAY_BUFFER).contains(&n),
        "relay_buffer 必须 1..={MAX_RELAY_BUFFER} 字节，当前 {n}"
    );
    RELAY_BUFFER.store(n, Ordering::Relaxed);
    Ok(())
}

/// 当前 relay 缓冲（字节）。全部 `copy_bidirectional_with_sizes` 调用点读取。
pub fn relay_buffer() -> usize {
    RELAY_BUFFER.load(Ordering::Relaxed)
}

/// 恢复缺省（仅测试使用——生产路径只 set 一次）。
#[cfg(test)]
pub(crate) fn reset_relay_buffer() {
    RELAY_BUFFER.store(DEFAULT_RELAY_BUFFER, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // 单测试串行覆盖：全局静态与并行测试会互扰。
    #[test]
    fn relay_buffer_set_get_and_validate() {
        assert_eq!(relay_buffer(), DEFAULT_RELAY_BUFFER);
        assert_eq!(DEFAULT_RELAY_BUFFER, 8192);

        set_relay_buffer(64 * 1024).unwrap();
        assert_eq!(relay_buffer(), 64 * 1024);

        assert!(set_relay_buffer(0).is_err());
        assert!(set_relay_buffer(MAX_RELAY_BUFFER + 1).is_err());
        assert_eq!(relay_buffer(), 64 * 1024); // 非法值不改状态

        reset_relay_buffer();
        assert_eq!(relay_buffer(), DEFAULT_RELAY_BUFFER);
    }
}
