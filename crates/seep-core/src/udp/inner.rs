//! 会话内层：目标映射（`MappingShared`）与 `UdpSessionInner`。
//! 内部表示与草案的差异（api 文档「实施注记」）：映射统一为
//! `Arc<MappingShared>`（自带关闭 watch + 原子计数），forwarder task 与发送路径共享。

use crate::udp::key::UdpSessionKey;
use crate::udp::ledger::SessionLedger;
use crate::udp::relay::{DownlinkPacket, UdpRelay};
use crate::{FlowId, FlowTarget, RouteDecision, TargetProto};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::{mpsc, watch};

/// `FlowTarget` 的可哈希归一化键（host 小写；域名不做解析展开，见设计 O6）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowTargetKey {
    pub host: String,
    pub port: u16,
    pub proto: TargetProto,
}

impl FlowTargetKey {
    pub fn of(target: &FlowTarget) -> Self {
        Self { host: target.host.to_lowercase(), port: target.port, proto: target.proto }
    }
}

/// 映射共享体：发送路径与 forwarder task 各持 Arc。
pub struct MappingShared {
    pub relay: Arc<dyn UdpRelay>,
    pub last_activity: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pkts_up: AtomicU64,
    pub pkts_down: AtomicU64,
    /// 关闭信号：teardown 置 true，forwarder 退出（锁外 IO 原则，api 文档 §5.1）
    pub close_tx: watch::Sender<bool>,
    /// 连续发送失败计数（§3.6：Connection 类 ≥3 次触发映射重建；成功归零）
    pub consecutive_errors: AtomicU64,
}

impl MappingShared {
    pub fn touch(&self, now: u64) {
        self.last_activity.store(now, Ordering::Relaxed);
    }

    pub fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    pub fn count_up(&self, bytes: usize) {
        self.bytes_up.fetch_add(bytes as u64, Ordering::Relaxed);
        self.pkts_up.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_down(&self, bytes: usize) {
        self.bytes_down.fetch_add(bytes as u64, Ordering::Relaxed);
        self.pkts_down.fetch_add(1, Ordering::Relaxed);
    }

    /// 请求 forwarder 退出（socket/relay 的实际关闭由两侧 Arc 释放完成）
    pub fn close(&self) {
        let _ = self.close_tx.send(true);
    }
}

/// 会话内层：粘滞决策 + 映射 + 下行通道 + ledger。
pub struct UdpSessionInner {
    pub key: UdpSessionKey,
    pub id: FlowId,
    pub ledger: SessionLedger,
    /// 粘滞决策缓存；`None` = 决策已被链路失效，下一包重路由。
    /// 锁序（api 文档 §5.1）：DashMap shard → mappings → decision/ledger。
    pub decision: RwLock<Option<Arc<RouteDecision>>>,
    pub mappings: Mutex<HashMap<FlowTargetKey, Arc<MappingShared>>>,
    pub downlink_tx: mpsc::Sender<DownlinkPacket>,
    pub downlink_rx: tokio::sync::Mutex<Option<mpsc::Receiver<DownlinkPacket>>>,
    pub last_activity: AtomicU64,
    pub created_at_epoch: u64,
    /// 本会话累计做出的路由决策数（首次为 1；>1 的增量计入 reroutes 指标）
    pub decisions: AtomicU64,
}

impl UdpSessionInner {
    pub fn touch(&self, now: u64) {
        self.last_activity.store(now, Ordering::Relaxed);
    }

    pub fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    pub fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.created_at_epoch)
    }
}
