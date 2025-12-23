//! 直连出口实现

use anyhow::{Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};
use tokio::net::TcpStream;

/// 直连出口连接器
#[derive(Default)]
pub struct DirectConnector;

impl DirectConnector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EgressConnector for DirectConnector {
    fn name(&self) -> &'static str {
        "direct"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);

        tracing::debug!(
            target: "seep::direct",
            id = %flow.id.as_uuid(),
            %target,
            "直连目标"
        );

        let mut outbound = TcpStream::connect(&target)
            .await
            .with_context(|| format!("连接目标 {} 失败", target))?;

        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
            .await
            .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}
