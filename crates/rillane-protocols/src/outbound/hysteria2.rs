//! Hysteria2 出口连接器实现

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use rillane_core::{EgressConnector, Flow, FlowReport, TargetProto};
use tokio::sync::Mutex;

/// 连接建立（DNS 解析 + QUIC 握手 + HTTP/3 认证）超时上限（P2 深审
/// 2026-11-03）。`get_or_connect_client` 有意 single-flight（防连接风暴），
/// 但无超时则挂起拨号会永久钉住全部该出站流；此上限令挂起握手在超时后
/// 失败释放互斥，后续调用可重试。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Hysteria2 出口连接器
pub struct Hysteria2Connector {
    server: String,
    port: u16,
    password: String,
    mport: Option<String>,
    obfs: Option<String>,
    obfs_param: Option<String>,
    server_name: Option<String>,
    skip_cert_verify: bool,
    alpn: Option<Vec<String>>,
    client: Mutex<Option<std::sync::Arc<hysteria2::HysteriaClient>>>,
}

impl Hysteria2Connector {
    /// 参数面镜像 `EgressConfig::Hysteria2` 字段 1:1，不收敛 options 结构
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        password: String,
        mport: Option<String>,
        obfs: Option<String>,
        obfs_param: Option<String>,
        server_name: Option<String>,
        skip_cert_verify: bool,
        alpn: Option<Vec<String>>,
    ) -> Self {
        Self {
            server,
            port,
            password,
            mport,
            obfs,
            obfs_param,
            server_name,
            skip_cert_verify,
            alpn,
            client: Mutex::new(None),
        }
    }

    fn validate_config(&self) -> Result<()> {
        if self.obfs.is_some() || self.obfs_param.is_some() {
            return Err(anyhow!(
                "Hysteria2 暂不支持 obfs/obfs_param（当前 connector 基于 hysteria2 crate 的基础能力）"
            ));
        }
        if let Some(alpn) = &self.alpn {
            // Hysteria2 认证握手基于 HTTP/3，ALPN 至少需要包含 h3。
            if !alpn.iter().any(|p| p == "h3") {
                return Err(anyhow!("Hysteria2 alpn 必须包含 \"h3\""));
            }
        }
        Ok(())
    }

    fn parse_port_range(range_str: &str) -> Result<(u16, u16)> {
        if let Some((start_str, end_str)) = range_str.split_once('-') {
            let start: u16 = start_str
                .trim()
                .parse()
                .with_context(|| format!("无效的 mport 起始端口: {}", start_str.trim()))?;
            let end: u16 = end_str
                .trim()
                .parse()
                .with_context(|| format!("无效的 mport 结束端口: {}", end_str.trim()))?;
            if start > end {
                return Err(anyhow!("无效的 mport 范围: start > end"));
            }
            Ok((start, end))
        } else {
            let port: u16 = range_str
                .trim()
                .parse()
                .with_context(|| format!("无效的 mport 端口: {}", range_str.trim()))?;
            Ok((port, port))
        }
    }

    fn build_client_config(&self) -> Result<hysteria2::config::Config> {
        let server_name = self
            .server_name
            .clone()
            .unwrap_or_else(|| self.server.clone());

        let port_hopping_range = match self.mport.as_deref() {
            Some(s) => Some(Self::parse_port_range(s)?),
            None => None,
        };

        Ok(hysteria2::config::Config {
            auth: self.password.clone(),
            server_addr: format!("{}:{}", self.server, self.port),
            server_name,
            insecure: self.skip_cert_verify,
            port_hopping_range,
        })
    }

    async fn connect_client(&self) -> Result<std::sync::Arc<hysteria2::HysteriaClient>> {
        self.validate_config()?;
        let cfg = self.build_client_config()?;
        let client = hysteria2::connect(&cfg)
            .await
            .map_err(|e| anyhow!("Hysteria2 连接失败: {e}"))?;
        Ok(std::sync::Arc::new(client))
    }

    async fn get_or_connect_client(&self) -> Result<std::sync::Arc<hysteria2::HysteriaClient>> {
        self.validate_config()?;
        let mut guard = self.client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }

        // 持锁跨握手（single-flight 语义），但加显式超时：超时则释放互斥、
        // 不缓存半成品（fail-closed），后续调用可重新尝试。
        let client = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_client())
            .await
            .map_err(|_| anyhow!("Hysteria2 连接建立超时（{}s）", CONNECT_TIMEOUT.as_secs()))??;
        *guard = Some(client.clone());
        Ok(client)
    }

    async fn invalidate_client(&self) {
        let mut guard = self.client.lock().await;
        *guard = None;
    }
}

#[async_trait]
impl EgressConnector for Hysteria2Connector {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            other => {
                return Err(anyhow!("Hysteria2 暂仅支持 TCP 转发（got {:?}）", other));
            }
        }

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let server_addr = format!("{}:{}", self.server, self.port);

        tracing::debug!(
            target: "rillane::hysteria2",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            "通过 Hysteria2 连接"
        );

        let client = self.get_or_connect_client().await?;
        let mut outbound = match client.tcp_connect(&target).await {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    target: "rillane::hysteria2",
                    id = %flow.id.as_uuid(),
                    %target,
                    server = %server_addr,
                    error = %err,
                    "Hysteria2 tcp_connect 失败，尝试重连并重试"
                );

                self.invalidate_client().await;
                let client = self.get_or_connect_client().await?;
                client
                    .tcp_connect(&target)
                    .await
                    .with_context(|| format!("Hysteria2 tcp_connect 失败: {}", target))?
            }
        };

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut outbound,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}
