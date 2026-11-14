//! 周期回收（udp-session-table.md §4 / api 文档 §4）：
//! 单一 sweep 任务 15s 一拍；映射空闲 60s、会话空闲 180s、可选寿命上界；
//! 判定边界为严格大于（`idle > limit`），回收顺序与 force_revoke 一致
//! （关下行 → 摘映射 → 计数）。

use crate::udp::key::UdpSessionKey;
use crate::udp::metrics::ExpireReason;
use crate::udp::table::UdpSessionTable;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub mappings_expired: usize,
    pub sessions_expired: usize,
}

/// 单次扫描：返回本轮回收量（测试直接驱动，不起真实定时器）。
pub fn sweep_once(table: &UdpSessionTable) -> SweepStats {
    let now = table.now();
    let cfg = &table.config;
    let mut stats = SweepStats::default();
    let mut expired_sessions: Vec<(UdpSessionKey, ExpireReason)> = Vec::new();

    for item in table.sessions.iter() {
        let inner = item.value();
        // 1) 映射层：空闲超限 → close（forwarder 自行摘除自身并扣计数）
        {
            let mut map = inner.mappings.lock().unwrap();
            let stale: Vec<_> = map
                .iter()
                .filter(|(_, m)| m.idle_secs(now) > cfg.mapping_idle.as_secs())
                .map(|(k, _)| k.clone())
                .collect();
            for k in &stale {
                if let Some(m) = map.remove(k) {
                    m.close();
                    stats.mappings_expired += 1;
                    table.metrics.expired_inc(ExpireReason::Idle);
                    table
                        .metrics
                        .mappings_active
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        // 2) 会话层：空闲超限或寿命超限 → 整会话回收
        let idle_limit = cfg.session_idle.as_secs();
        let lifetime_exceeded = cfg
            .session_max_lifetime
            .map(|l| inner.age_secs(now) > l.as_secs())
            .unwrap_or(false);
        if inner.idle_secs(now) > idle_limit || lifetime_exceeded {
            let reason = if lifetime_exceeded {
                ExpireReason::Lifetime
            } else {
                ExpireReason::Idle
            };
            expired_sessions.push((inner.key.clone(), reason));
        }
    }

    for (key, reason) in expired_sessions {
        if let Some((_, inner)) = table.sessions.remove(&key) {
            let mut map = inner.mappings.lock().unwrap();
            let remaining = map.len();
            for (_, m) in map.drain() {
                m.close();
            }
            drop(map);
            if remaining > 0 {
                table
                    .metrics
                    .mappings_active
                    .fetch_sub(remaining as i64, std::sync::atomic::Ordering::Relaxed);
            }
            table.metrics.expired_inc(reason);
            table
                .metrics
                .sessions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            stats.sessions_expired += 1;
        }
    }
    stats
}

/// 常驻回收任务：sweep_interval 一拍；shutdown 置位后退出。
pub(crate) fn spawn_reclaimer(
    table: &Arc<UdpSessionTable>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let table = Arc::clone(table);
    let interval = table.config.sweep_interval;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = tick.tick() => {
                    sweep_once(&table);
                }
            }
        }
    })
}

impl UdpSessionTable {
    /// 启动周期回收任务（api 文档 §3.5）。返回任务句柄供测试 join。
    pub fn spawn_reclaimer(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        spawn_reclaimer(self, self.shutdown_rx.clone())
    }
}
