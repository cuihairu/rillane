//! 表级指标与快照（指标命名对齐 udp-dataplane.md §5.3 / udp-session-table.md §7）。

use serde::Serialize;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum DropReason {
    /// 全局会话满（拒新不逐旧）
    SessionLimit,
    /// 会话内映射上界异常触发（正常路径为 LRU 逐出）
    MappingLimit,
    /// 绑定已回收（teardown 竞态中的迟包）
    NoBinding,
    /// 表关停
    ShuttingDown,
    /// 上行发送失败（映射随即吊销，下一包重新关联）
    SendFailed,
    /// 会话下行通道满（UDP 无背压，丢包计数）
    DownlinkFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ExpireReason {
    Idle,
    Lifetime,
    /// force_revoke（ASSOCIATE 控制连接关闭等）
    Revoked,
}

/// 方向记账（ledger / 映射计数共用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Up,
    Down,
}

#[derive(Debug, Default)]
pub struct TableMetrics {
    pub sessions_total: AtomicU64,
    pub sessions_active: AtomicI64,
    pub mappings_active: AtomicI64,
    pub reroutes: AtomicU64,
    dropped: [AtomicU64; DROP_KINDS],
    expired: [AtomicU64; EXPIRE_KINDS],
}

pub const DROP_KINDS: usize = 6;
pub const EXPIRE_KINDS: usize = 3;

fn drop_idx(r: DropReason) -> usize {
    match r {
        DropReason::SessionLimit => 0,
        DropReason::MappingLimit => 1,
        DropReason::NoBinding => 2,
        DropReason::ShuttingDown => 3,
        DropReason::SendFailed => 4,
        DropReason::DownlinkFull => 5,
    }
}

fn expire_idx(r: ExpireReason) -> usize {
    match r {
        ExpireReason::Idle => 0,
        ExpireReason::Lifetime => 1,
        ExpireReason::Revoked => 2,
    }
}

impl TableMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn drop_inc(&self, r: DropReason) {
        self.dropped[drop_idx(r)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn expired_inc(&self, r: ExpireReason) {
        self.expired[expire_idx(r)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn drop_count(&self, r: DropReason) -> u64 {
        self.dropped[drop_idx(r)].load(Ordering::Relaxed)
    }

    pub fn expired_count(&self, r: ExpireReason) -> u64 {
        self.expired[expire_idx(r)].load(Ordering::Relaxed)
    }
}

/// 每会话快照（`/flows` 与 `seepctl stats` 用；脱敏在控制面渲染层做）
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub client: String,
    pub user: Option<String>,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub mappings: usize,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_count: u64,
    pub current_path: Vec<String>,
    pub reconnect_count: u32,
}

/// 表快照（`UdpSessionTable::snapshot`）
#[derive(Debug, Clone, Serialize)]
pub struct TableSnapshot {
    pub sessions_active: usize,
    pub sessions_total: u64,
    pub mappings_active: i64,
    pub reroutes: u64,
    pub dropped: std::collections::BTreeMap<String, u64>,
    pub expired: std::collections::BTreeMap<String, u64>,
    pub sessions: Vec<SessionSnapshot>,
}
