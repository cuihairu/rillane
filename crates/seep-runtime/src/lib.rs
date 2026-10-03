//! Seep 运行时库
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
pub mod runtime_builder;
// TUN 入口 + /proc 进程归因 + TCP 用户态栈（tun-dataplane.md §2；Linux 数据面）
pub mod tun_ingress;
pub mod tun_process;
pub mod tun_tcp;
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
pub use runtime_builder::{
    ConfigMergeStats, FlowStatItem, MeshConfig, MeshEventType, NetworkEventType, Runtime,
    RuntimeBuilder, RuntimeConfig, RuntimeEvent, RuntimeStats, SubscriptionEventType,
};
pub use seep_platform::network::NetworkMode;
pub use tun_ingress::{Proto as TunProto, TunIngress, TunIngressConfig, TunIngressStats};
pub use tun_process::{ProcessAttributor, ProcessInfo, SockProto};
// P0-5 §2.4：client 出站侧 UDP 计数（模块私有，观测 getter 的返回类型经此公开）
pub use udp_chain::UdpClientMetrics;

use seep_config::EgressDescriptor;
use seep_core::EgressConnector;

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
                spec: seep_config::EgressConfig::Direct, // 简化实现
            })
            .collect()
    }
}
