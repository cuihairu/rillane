//! SOCKS5 出口连接器实现

use anyhow::{Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};
use tokio_socks::tcp::Socks5Stream;

/// SOCKS5 代理出口连接器
pub struct Socks5Connector {
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Connector {
    pub fn new(
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            server,
            port,
            username,
            password,
        }
    }

    fn proxy_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

#[async_trait]
impl EgressConnector for Socks5Connector {
    fn name(&self) -> &'static str {
        "socks5"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let proxy_addr = self.proxy_addr();

        tracing::debug!(
            target: "seep::socks5_out",
            id = %flow.id.as_uuid(),
            %target,
            proxy = %proxy_addr,
            "通过 SOCKS5 代理连接"
        );

        // 建立 SOCKS5 连接
        let mut outbound = if let (Some(user), Some(pass)) =
            (self.username.as_ref(), self.password.as_ref())
        {
            Socks5Stream::connect_with_password(
                proxy_addr.as_str(),
                target.as_str(),
                user,
                pass,
            )
            .await
            .with_context(|| format!("SOCKS5 代理连接失败: {}", proxy_addr))?
        } else {
            Socks5Stream::connect(proxy_addr.as_str(), target.as_str())
                .await
                .with_context(|| format!("SOCKS5 代理连接失败: {}", proxy_addr))?
        };

        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
            .await
            .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}
