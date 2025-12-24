//! Shadowsocks 出口连接器实现

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::SharedContext,
    crypto::CipherKind,
    relay::tcprelay::proxy_stream::ProxyClientStream,
    ServerAddr,
};

/// Shadowsocks 出口连接器
pub struct ShadowsocksConnector {
    server: String,
    port: u16,
    method: String,
    password: String,
    context: SharedContext,
}

impl ShadowsocksConnector {
    pub fn new(server: String, port: u16, method: String, password: String) -> Result<Self> {
        let context = shadowsocks::context::Context::new_shared(ServerType::Local);

        Ok(Self {
            server,
            port,
            method,
            password,
            context,
        })
    }

    fn server_config(&self) -> Result<ServerConfig> {
        let cipher = self
            .method
            .parse::<CipherKind>()
            .map_err(|_| anyhow!("不支持的加密方法: {}", self.method))?;

        let addr = ServerAddr::DomainName(self.server.clone(), self.port);
        let config = ServerConfig::new(addr, self.password.clone(), cipher)?;

        Ok(config)
    }
}

#[async_trait]
impl EgressConnector for ShadowsocksConnector {
    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_config = self.server_config()?;

        tracing::debug!(
            target: "seep::shadowsocks",
            id = %flow.id.as_uuid(),
            %target,
            server = %self.server,
            method = %self.method,
            "通过 Shadowsocks 连接"
        );

        // 解析目标地址
        let target_addr = shadowsocks::relay::Address::DomainNameAddress(
            flow.target.host.clone(),
            flow.target.port,
        );

        // 建立 Shadowsocks 连接
        let mut outbound =
            ProxyClientStream::connect(self.context.clone(), &server_config, target_addr)
                .await
                .with_context(|| format!("Shadowsocks 连接失败: {}:{}", self.server, self.port))?;

        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
            .await
            .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}
