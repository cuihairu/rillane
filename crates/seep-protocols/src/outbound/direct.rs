//! 直连出口实现

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};

use crate::pool::{TransportKey, TransportPool};

/// 直连出口连接器
#[derive(Default)]
pub struct DirectConnector {
    /// 出站连接池（P1-5 §4.1：仅 `pre_dial_direct` 开启时注入——投机预拨
    /// 对目标产生未请求的连接，默认关，开启者显式承担 R-pool2）
    pool: Option<Arc<TransportPool>>,
}

impl DirectConnector {
    pub fn new() -> Self {
        Self { pool: None }
    }

    /// 池注入构造（pre_dial_direct 选通；§2.5 能力矩阵 direct 行）
    pub fn with_pool(pool: Arc<TransportPool>) -> Self {
        Self { pool: Some(pool) }
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

        let mut outbound = match &self.pool {
            Some(pool) => {
                // direct 无协议握手期（bind 缺席）→ 无 stale 判定（§4.2 bind
                // 语义 = 首写首读；死闲连接暴露为流错误，由 idle_timeout 兜底）
                let key = TransportKey::plain(&flow.target.host, flow.target.port);
                let (io, _lease) = pool
                    .acquire(&key)
                    .await
                    .with_context(|| format!("连接目标 {target} 失败"))?;
                io
            }
            None => Box::new(
                // net_mark 统一拨号（缺省 mark=0 与 TcpStream::connect 零差异；
                // fwmark ≠ 0 时 SO_MARK 逃逸 include 路由自环，networking.md §2）
                seep_core::net_mark::connect_tcp(target.clone())
                    .await
                    .with_context(|| format!("连接目标 {} 失败", target))?,
            ),
        };

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut outbound,
            seep_core::performance::relay_buffer(),
            seep_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}
