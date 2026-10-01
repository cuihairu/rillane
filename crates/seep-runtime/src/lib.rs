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
pub mod hot_reload;
pub mod mesh_transport;
pub mod network_config;
pub mod obfs_config;
pub mod runtime_builder;
mod udp_chain; // P0-4 §5 客户端出站（私有：消费点 = runtime_builder UDP 块，S5 接线）

pub use chain::{
    ChainBuildResult, ChainBuilder, ChainConfig, ChainConstraints, ChainDryRunResult, ChainManager,
    ChainManagerStats, PathOptimizationStrategy,
};
pub use hot_reload::{HotReloadConfig, HotReloadManager, ReloadEvent, ReloadStats};
pub use mesh_transport::{MeshDataPlane, MeshEnvelope, UdpFaceSnapshot};
pub use network_config::network_block_to_platform;
pub use obfs_config::{build_middleware_chain, to_padding_policy, PaddingPolicy};
pub use runtime_builder::{
    ConfigMergeStats, FlowStatItem, MeshConfig, MeshEventType, NetworkEventType, Runtime,
    RuntimeBuilder, RuntimeConfig, RuntimeEvent, RuntimeStats, SubscriptionEventType,
};
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
