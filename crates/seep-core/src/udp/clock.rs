//! 时钟注入：单调 epoch 秒（A1——进程单调时钟，免 NTP 跳变）。
//! `MockClock` 供超时类单测确定性拨秒（api 文档 §6）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub trait Clock: Send + Sync + std::fmt::Debug {
    /// 进程单调时钟的秒值（表启动基点无关紧要，仅差值有意义）
    fn now_epoch(&self) -> u64;
}

#[derive(Debug)]
pub struct RealClock {
    epoch_base: AtomicU64,
    instant_base: Instant,
}

impl RealClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch_base: AtomicU64::new(0),
            instant_base: Instant::now(),
        })
    }
}

impl Default for RealClock {
    fn default() -> Self {
        Self { epoch_base: AtomicU64::new(0), instant_base: Instant::now() }
    }
}

impl Clock for RealClock {
    fn now_epoch(&self) -> u64 {
        self.instant_base.elapsed().as_secs() + self.epoch_base.load(Ordering::Relaxed)
    }
}

/// 可拨动的测试时钟（pub 供其他 crate 的集成测试复用）。
#[derive(Debug, Default)]
pub struct MockClock {
    now: AtomicU64,
}

impl MockClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { now: AtomicU64::new(0) })
    }

    pub fn set_epoch(&self, secs: u64) {
        self.now.store(secs, Ordering::Relaxed);
    }

    pub fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now_epoch(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}
