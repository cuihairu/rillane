//! Trojan 出口连接器实现

use anyhow::{Context, Result};
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowReport};
use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncWriteExt},
    net::TcpStream,
};

use crate::tls::create_tls_connector;

/// Trojan 出口连接器
pub struct TrojanConnector {
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
}

impl TrojanConnector {
    pub fn new(
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            server,
            port,
            password,
            sni,
            skip_cert_verify,
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
}

#[async_trait]
impl EgressConnector for TrojanConnector {
    fn name(&self) -> &'static str {
        "trojan"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let server_addr = format!("{}:{}", self.server, self.port);
        let target = format!("{}:{}", flow.target.host, flow.target.port);

        tracing::debug!(
            target: "seep::trojan",
            id = %flow.id.as_uuid(),
            %target,
            server = %server_addr,
            "通过 Trojan 连接"
        );

        // 建立 TCP 连接
        let tcp_stream = TcpStream::connect(&server_addr)
            .await
            .with_context(|| format!("连接 Trojan 服务器失败: {}", server_addr))?;

        // TLS 握手
        let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
        let connector = create_tls_connector(self.skip_cert_verify)?;
        let server_name = rustls::pki_types::ServerName::try_from(sni).context("无效的 SNI")?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // 发送 Trojan 请求
        let request = self.build_request(&flow.target.host, flow.target.port);
        tls_stream.write_all(&request).await?;

        // 双向转发
        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut tls_stream)
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
