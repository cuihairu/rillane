//! Seep 运行时库
//!
//! 提供完整的运行时环境，整合所有核心组件：
//! - 运行时构建器
//! - 网络虚拟化
//! - 流量路由
//! - Mesh 协作
//! - 订阅管理
//! - 热更新

pub mod hot_reload;
pub mod runtime_builder;

pub use hot_reload::{HotReloadConfig, HotReloadManager, ReloadEvent, ReloadStats};
pub use runtime_builder::{
    MeshConfig, NetworkEventType, Runtime, RuntimeBuilder, RuntimeConfig, RuntimeEvent,
    RuntimeStats, SubscriptionEventType,
};

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
