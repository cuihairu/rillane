//! Mixed 入口协议实现（同端口同时支持 SOCKS5 与 HTTP CONNECT）

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use seep_core::udp::UdpAssociateService;
use seep_core::{FlowOutput, FlowRouter, IngressEndpoint};
use tokio::net::{TcpListener, TcpStream};

use super::{http::handle_http_connect_stream, socks5::handle_socks5_stream};

/// Mixed 入口服务
pub struct MixedIngress {
    name: String,
    bind: String,
    /// UDP ASSOCIATE 服务（socks5 分支共享；None = 未启用）
    udp: Option<Arc<UdpAssociateService>>,
}

impl MixedIngress {
    pub fn new(name: String, bind: String, udp: Option<Arc<UdpAssociateService>>) -> Self {
        Self { name, bind, udp }
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let mut first = [0u8; 1];
        let n = stream.peek(&mut first).await?;
        if n == 0 {
            bail!("连接意外关闭");
        }

        if first[0] == 0x05 {
            handle_socks5_stream(self.name.as_str(), &[], stream, router, output, self.udp.clone()).await
        } else {
            handle_http_connect_stream(self.name.as_str(), stream, router, output).await
        }
    }
}

#[async_trait]
impl IngressEndpoint for MixedIngress {
    fn name(&self) -> &'static str {
        "mixed"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("无法监听 {}", self.bind))?;

        tracing::info!(
            target: "seep::mixed",
            bind = %self.bind,
            "Mixed 入口启动"
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();

            tokio::spawn(async move {
                if let Err(err) = this.handle_client(stream, router, output).await {
                    tracing::warn!(
                        target: "seep::mixed",
                        client = %addr,
                        error = %err,
                        "Mixed 连接处理失败"
                    );
                }
            });
        }
    }
}
