//! Trojan 出口连接器实现

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::fingerprint::TlsFingerprint;
use crate::pool::{TransportKey, TransportPool};
use crate::tls::{create_tls_connector_with_profile, TlsConnectorFactory};

/// Trojan 出口连接器
pub struct TrojanConnector {
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    /// 客户端 TLS 指纹形态（P2-5；None = rustls 缺省形态）
    fingerprint: TlsFingerprint,
    /// 出站连接池（P1-5 §4.2；None = 旧行为内联路径，D-9）
    pool: Option<Arc<TransportPool>>,
    /// 共享 ClientConfig 工厂：pool=None 时使 TLS 会话恢复独立于池生效
    /// （§3.1「块存在即生效」；None = 既有每流 ClientConfig）
    factory: Option<Arc<TlsConnectorFactory>>,
}

impl TrojanConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        fingerprint: TlsFingerprint,
        pool: Option<Arc<TransportPool>>,
        factory: Option<Arc<TlsConnectorFactory>>,
    ) -> Self {
        Self {
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            fingerprint,
            pool,
            factory,
        }
    }

    /// 计算 Trojan 密码的 SHA224 哈希（十六进制）
    fn password_hash(&self) -> String {
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result)
    }

    /// 构建 Trojan 请求头
    fn build_request(&self, host: &str, port: u16) -> Vec<u8> {
        let hash = self.password_hash();
        let mut request = Vec::with_capacity(256);

        // 密码哈希 (56 bytes hex)
        request.extend_from_slice(hash.as_bytes());

        // CRLF
        request.extend_from_slice(b"\r\n");

        // CMD: CONNECT (0x01)
        request.push(0x01);

        // 地址类型和地址
        // 0x03 = 域名
        request.push(0x03);
        let host_bytes = host.as_bytes();
        request.push(host_bytes.len() as u8);
        request.extend_from_slice(host_bytes);

        // 端口 (big endian)
        request.extend_from_slice(&port.to_be_bytes());

        // CRLF
        request.extend_from_slice(b"\r\n");

        request
    }

    /// 传输键（§4.2：alpn 空 = 既有 trojan 路径不设 ALPN）
    fn transport_key(&self) -> TransportKey {
        TransportKey::tls(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            &[],
            self.fingerprint,
        )
    }
}

#[async_trait]
impl EgressConnector for TrojanConnector {
    fn name(&self) -> &'static str {
        "trojan"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        match &self.pool {
            Some(pool) => self.forward_pooled(flow, pool).await,
            None => self.forward_inline(flow).await,
        }
    }
}

impl TrojanConnector {
    /// 池借出路径（§4.2）：acquire → 写协议头（bind）→ 双向转发；首写失败
    /// → stale 一次性重拨（D-11，[`TransportPool::acquire_bound`]）。
    async fn forward_pooled(
        &self,
        mut flow: Flow,
        pool: &Arc<TransportPool>,
    ) -> Result<FlowReport> {
        let server_addr = format!("{}:{}", self.server, self.port);
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        tracing::debug!(
            target: "seep::trojan",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            pooled = true,
            "通过 Trojan 连接"
        );

        let key = self.transport_key();
        let request = self.build_request(&flow.target.host, flow.target.port);
        let (mut outbound, _lease) = pool
            .acquire_bound(&key, |io| {
                let request = request.clone();
                Box::pin(async move { io.write_all(&request).await.map_err(Into::into) })
            })
            .await
            .with_context(|| format!("连接 Trojan 服务器失败: {server_addr}"))?;

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

    /// 内联路径（pool=None）：与既有实现逐字节同构（D-9）；factory=Some 时
    /// TLS 连接器改取共享 ClientConfig（tls_resumption 独立于池生效）。
    async fn forward_inline(&self, mut flow: Flow) -> Result<FlowReport> {
        let server_addr = format!("{}:{}", self.server, self.port);
        let target = format!("{}:{}", flow.target.host, flow.target.port);

        tracing::debug!(
            target: "seep::trojan",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            "通过 Trojan 连接"
        );

        // 建立 TCP 连接（net_mark 统一拨号：SO_MARK 逃逸面，networking.md §2）
        let tcp_stream = seep_core::net_mark::connect_tcp(server_addr.clone())
            .await
            .with_context(|| format!("连接 Trojan 服务器失败: {}", server_addr))?;

        // TLS 握手
        let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
        let connector = match &self.factory {
            Some(factory) => factory.connector(self.skip_cert_verify, &[], self.fingerprint)?,
            None => {
                create_tls_connector_with_profile(self.skip_cert_verify, None, self.fingerprint)?
            }
        };
        let server_name = rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // 发送 Trojan 请求
        let request = self.build_request(&flow.target.host, flow.target.port);
        tls_stream.write_all(&request).await?;

        // 双向转发
        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut tls_stream,
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

// 辅助模块：hex 编码
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
}
