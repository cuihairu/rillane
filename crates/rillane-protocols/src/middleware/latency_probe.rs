//! 延迟探测中间件

use anyhow::Result;
use async_trait::async_trait;
use rillane_core::{Flow, FlowMiddleware};
use tokio::time::{sleep, Duration};

/// 延迟探测中间件
pub struct LatencyProbe;

impl LatencyProbe {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LatencyProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FlowMiddleware for LatencyProbe {
    fn name(&self) -> &'static str {
        "latency_probe"
    }

    async fn handle(&self, flow: Flow) -> Result<Flow> {
        // 微小延迟用于探测
        sleep(Duration::from_millis(1)).await;
        Ok(flow)
    }
}
