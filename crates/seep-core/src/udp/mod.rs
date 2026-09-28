//! # seep-core :: UDP 会话层（P0-1）
//!
//! NAT 式 UDP 会话表：两级映射（全局会话表 → 会话内目标映射）、粘滞键
//! （进程 > 认证用户 + 五元组 > 五元组）、周期扫描回收、与 [`crate::FlowSession`]
//! 经 [`ledger::SessionLedger`] 单写入口集成。
//!
//! 实现口径：`docs/design/udp-session-table-api.md`（接口草案），
//! 设计依据：`docs/design/udp-session-table.md`，总设计：`docs/design/udp-dataplane.md` §1。
//!
//! 与草案的已注记差异（实施裁决，见 api 文档「实施注记」）：
//! - `forward_up` 为 async（`UdpRelay::send_to` 为 async，草案 §8 允许放宽）；
//! - 映射统一为 `Arc<MappingShared>`（含关闭用 watch），替代 `UdpBinding` 枚举的内部表示；
//! - 新增 `SessionRef::{bind_mapping, send_up, has_mapping, take_downlink_rx}`（中继路径接线所需）。

pub mod clock;
pub mod config;
pub mod key;
pub mod ledger;
pub mod metrics;
pub mod relay;
pub mod table;

mod inner;
mod reclaim;

pub use clock::{Clock, MockClock, RealClock};
pub use config::UdpSessionConfig;
pub use inner::{FlowTargetKey, MappingShared, UdpSessionInner};
pub use key::{ProcessIdentity, UdpSessionKey};
pub use ledger::SessionLedger;
pub use metrics::{Dir, DropReason, ExpireReason, SessionSnapshot, TableMetrics, TableSnapshot};
pub use reclaim::{sweep_once, SweepStats};
pub use relay::{
    EgressUdpConnector, LocalRelay, MockUdpRelay, DownlinkPacket, UdpRelay,
};
pub use table::{BindOutcome, ResolveError, SessionRef, UpResult, UdpSessionTable};

/// 链路故障事件（由 runtime 从 `ChainManager` 故障处理映射而来，驱动决策缓存失效）。
#[derive(Debug, Clone)]
pub struct ChainFailureEvent {
    pub chain_id: String,
    pub failed_nodes: Vec<String>,
}
