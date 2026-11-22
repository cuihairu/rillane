//! Rillane 运行时库
//!
//! 提供完整的运行时环境，整合所有核心组件：
//! - 运行时构建器
//! - 网络虚拟化
//! - 流量路由
//! - Mesh 协作
//! - 订阅管理
//! - 热更新
//! - 多跳链路构建
//! - Mesh 数据平面传输

pub mod chain;
pub mod dns_config;
pub mod hot_reload;
pub mod mesh_transport;
pub mod network_config;
pub mod obfs_config;
pub mod pool_config;
pub mod publisher;
pub mod runtime_builder;
pub mod sniff;
// 透明接管入口（RIL-139）：REDIRECT/TPROXY socket 面——Linux 门控
//（iptables/IP_TRANSPARENT 内核面；同 tun_ingress 口径，非 Linux 整体门控）
#[cfg(target_os = "linux")]
pub mod transparent_ingress;
// TUN 入口 + /proc 进程归因 + TCP 用户态栈（tun-dataplane.md §2；Linux 数据面）。
// 非 Linux 编译单元整体门控（windows-gnu 打包面 platform-packaging.md；
// 破损修复：tun_ingress 的 rillane_platform::network::linux import 无门控，
// E0432 于 x86_64-pc-windows-gnu）
#[cfg(target_os = "linux")]
pub mod tun_ingress;
#[cfg(target_os = "linux")]
pub mod tun_process;
#[cfg(target_os = "linux")]
pub mod tun_tcp;
// 统计快照是平台无关面（控制面 rillane_tun_* 恒渲染，§2.8）
pub mod tun_stats;
mod udp_chain; // P0-4 §5 客户端出站（私有：消费点 = runtime_builder UDP 块，S5 接线）

pub use chain::{
    ChainBuildResult, ChainBuilder, ChainConfig, ChainConstraints, ChainDryRunResult, ChainManager,
    ChainManagerStats, PathOptimizationStrategy, SwitchEvent, SwitchReason,
};
pub use dns_config::{dns_block_to_resolver_config, DnsService};
pub use hot_reload::{HotReloadConfig, HotReloadManager, ReloadEvent, ReloadStats};
pub use mesh_transport::{MeshDataPlane, MeshEnvelope, ObfsPadSnapshot, UdpFaceSnapshot};
pub use network_config::network_block_to_platform;
pub use obfs_config::{
    build_middleware_chain, to_padding_policy, to_shaping_policy, to_timing_policy, PaddingPolicy,
    ShapingPolicy, TimingPolicy,
};
pub use pool_config::to_pool_policy;
pub use publisher::{
    EffectiveEntry, PendingTx, PublishCoordinator, PublishError, PublishJournal, PublishPhase,
    PublishTxnOutcome, ReconcileReport, RetainedEntry, CODE_GENERATION_UNCHANGED,
    CODE_JOURNAL_CORRUPT,
};
pub use rillane_platform::network::NetworkMode;
pub use runtime_builder::{
    ConfigMergeStats, FlowStatItem, MeshConfig, MeshEventType, NetworkEventType, Runtime,
    RuntimeBuilder, RuntimeConfig, RuntimeEvent, RuntimeStats, SourceMergeStats, SourceOwnedNames,
    SubscriptionEventType, LOCAL_SOURCE,
};

// O-slo1 观测面：路由组实时质量（控制面 /routing/stats 经 Runtime getter 取数）
pub use rillane_routing::{GroupQuality, MemberQuality};
#[cfg(target_os = "linux")]
pub use tun_ingress::{Proto as TunProto, TunIngress, TunIngressConfig};
#[cfg(target_os = "linux")]
pub use tun_process::{ProcessAttributor, ProcessInfo, SockProto};
pub use tun_stats::TunIngressStats;
// P0-5 §2.4：client 出站侧 UDP 计数（模块私有，观测 getter 的返回类型经此公开）
pub use udp_chain::UdpClientMetrics;

use rillane_config::EgressDescriptor;
use rillane_core::EgressConnector;

/// 简化的出口注册表实现
pub struct EgressRegistry {
    pub connectors: Vec<(String, Box<dyn EgressConnector>)>,
}

impl EgressRegistry {
    /// 获取出口描述符列表
    pub fn get_egress_descriptors(&self) -> Vec<EgressDescriptor> {
        self.connectors
            .iter()
            .map(|(name, _)| EgressDescriptor {
                name: name.clone(),
                spec: rillane_config::EgressConfig::Direct, // 简化实现
            })
            .collect()
    }
}
