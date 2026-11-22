//! Tailcat 出口连接器实现（RIL-127）。
//!
//! mesh 客户端面（出口）——库承载 `tailcat-client` 0.1.1（kosumic/whip，
//! MIT；评估留证 protocol-backends.md#tailcat）。本模块嵌入载具
//! `tailcat_client::Client`：`Client::connect(address, &Identity,
//! ClientOptions)` 完成 `tc` 紧凑地址解析 + WireGuard 数据通道建立
//! （boringtun default_features=False，纯 Rust）+ DERP 中继注册（载具内置
//! relay-authenticated ping）+ 直连发现，`dial_tcp(port)` 给出已解封的
//! `Stream`（tokio AsyncRead + AsyncWrite，双向独立 FIN）——与 tailscale 的
//! `Device::tcp_connect -> netstack::TcpStream` 同构的用户态三层桥，无
//! TUN、无路由、无 root。
//!
//! 目标寻址口径：`tc` 地址即端点身份（内含服务端 WireGuard 公钥 + 发现
//! 密钥 + DERP 区域 + 预共享密钥——即访问凭证），Client 恒指向该地址所
//! 标识的服务端；flow 目标端口选择服务端所伺服端口，flow 目标主机名不
//! 参预路由（载具无主机寻址面——地址即端点，与 tailscale 的 peer 寻址
//! 不同口径，具名于此）。
//!
//! 安全姿态与具名边界（见 protocol-backends.md#tailcat）：载具 0.1.1
//! pre-1.0（自述 experimental、wire 可能变更；许可 0.1.0→0.1.1 由 BSD-3
//! 改 MIT，两者均宽松）；DERP 中继为可达性保底（直连发现失败即回退，
//! 验收须标注）；UDP/QUIC 应用面不交付（catalog udp=false）；服务端面
//! 不交付（载具 client-only）。入口（服务端）面无可用载具——`tailcat`
//! 0.1.0（spullara/tailcat-rs，BSD-3，双面 + 官方 Go 互通套件）被
//! ssh-key 精确 rc 冲突硬阻断（russh 0.63.1 需 `=rc.11`，工作区为
//! RIL-113 钉 `=rc.12`，两 russh major 各自精确 rc 不可统一）。
//! `server_address` 必填非空（不静默指官方 DERP/端点），建期经载具
//! `validate_address` 离线校验（触网前具名拒绝）；`private_key` 可选
//! （缺省临时身份；导入失败绝不静默换新钥——载具语义，建期具名拒绝）。

use anyhow::{anyhow, Context, Result};
use tokio::sync::OnceCell;

/// Tailcat 出口配置（IR `EgressConfig::Tailcat` 展开后的私有形态）
#[derive(Debug, Clone)]
struct TailcatConfig {
    /// 服务端 `tc` 紧凑地址（访问凭证）
    server_address: String,
    /// 节点身份私钥（None → 临时身份，每次连接新建，不持久）
    private_key: Option<String>,
    /// 仅 DERP 中继（禁用直连发现）
    relay_only: bool,
    /// 自定义 DERP map URL（None → 载具内建 DERP map）
    derp_map_url: Option<String>,
}

/// Tailcat 连接器：一个服务端地址一个共享 `Client`（一条到该服务端的
/// WireGuard + DERP 会话），全部流多路复用其上（载具 max_streams=32，
/// 与 tailscale 一节点一共享 Device 同口径）。
pub struct TailcatConnector {
    cfg: TailcatConfig,
    client: OnceCell<tailcat_client::Client>,
}

impl TailcatConnector {
    pub fn new(
        server_address: String,
        private_key: Option<String>,
        relay_only: bool,
        derp_map_url: Option<String>,
    ) -> Result<Self> {
        if server_address.trim().is_empty() {
            return Err(anyhow!(
                "tailcat server_address 为空（tc 紧凑地址即凭证，必填，不静默指官方 DERP/端点）"
            ));
        }
        // 建期离线校验（载具 validate_address：触网前判负，错误不回显地址
        // 内容——地址含凭证）
        if let Err(e) = tailcat_client::validate_address(&server_address) {
            return Err(anyhow!("tailcat tc 地址非法：{e}"));
        }
        // 私钥建期校验（导入失败绝不静默换新钥——载具语义）
        if let Some(key) = private_key.as_deref() {
            tailcat_client::Identity::from_private_key(key)
                .map_err(|e| anyhow!("tailcat 身份私钥非法：{e}"))?;
        }
        if let Some(url) = derp_map_url.as_deref() {
            if url.trim().is_empty() {
                return Err(anyhow!("tailcat derp_map_url 为空串（不设置请用 null）"));
            }
            if url::Url::parse(url).is_err() {
                return Err(anyhow!("tailcat derp_map_url 非法 URL：{url}"));
            }
        }
        Ok(Self {
            cfg: TailcatConfig {
                server_address,
                private_key,
                relay_only,
                derp_map_url,
            },
            client: OnceCell::new(),
        })
    }

    /// 惰性建立共享 Client（载具 connect：tc 地址解析 + WireGuard 建立 +
    /// DERP 注册 + relay-authenticated ping；一次性，超时归载具
    /// connect_timeout=30s 具名）。
    async fn client(&self) -> Result<tailcat_client::Client> {
        let client = self
            .client
            .get_or_try_init(|| async {
                let identity = match self.cfg.private_key.as_deref() {
                    Some(key) => tailcat_client::Identity::from_private_key(key)
                        .map_err(|e| anyhow!("tailcat 身份私钥非法：{e}"))?,
                    None => tailcat_client::Identity::generate(),
                };
                let options = tailcat_client::ClientOptions {
                    relay_only: self.cfg.relay_only,
                    derp_map_url: self.cfg.derp_map_url.clone(),
                    ..tailcat_client::ClientOptions::default()
                };
                tailcat_client::Client::connect(&self.cfg.server_address, &identity, options)
                    .await
                    .context("tailcat 服务端连接失败（tc 地址/DERP 中继不可达或凭证被拒）")
            })
            .await?;
        Ok(client.clone())
    }
}

#[async_trait::async_trait]
impl rillane_core::EgressConnector for TailcatConnector {
    fn name(&self) -> &'static str {
        "tailcat"
    }

    async fn forward(&self, mut flow: rillane_core::Flow) -> Result<rillane_core::FlowReport> {
        use rillane_core::FlowReport;
        if !matches!(flow.target.proto, rillane_core::TargetProto::Tcp) {
            return Err(anyhow!(
                "Tailcat 仅交付 TCP 应用面（UDP/QUIC 应用面不交付）"
            ));
        }
        let client = self.client().await?;
        // 端口即服务端所伺服端口（tc 地址即端点，主机名不参预路由——见
        // 模块注释）；载具拨出超时 dial_timeout=20s 具名
        let mut stream = client
            .dial_tcp(flow.target.port)
            .await
            .context("tailcat 服务端端口拨出失败（端口未伺服或被拒）")?;
        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut stream)
            .await
            .map_err(|e| anyhow!("relay 失败：{e}"))?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法形态的 tc 地址（结构与载具单测同构：CBOR {p:32B, i:1, k:32B}
    /// base64url-nopad）
    fn valid_address() -> String {
        use base64::Engine;
        let mut bytes = Vec::new();
        let value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("p".into()),
                ciborium::Value::Bytes(vec![1u8; 32]),
            ),
            (
                ciborium::Value::Text("i".into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Text("k".into()),
                ciborium::Value::Bytes(vec![2u8; 32]),
            ),
        ]);
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();
        format!(
            "tc{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        )
    }

    #[test]
    fn new_rejects_empty_address() {
        let err = TailcatConnector::new(String::new(), None, false, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("server_address"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_bad_address() {
        let err = TailcatConnector::new("tc!!!!".into(), None, false, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("tc 地址非法"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_bad_private_key() {
        let err = TailcatConnector::new(valid_address(), Some("not-a-key".into()), false, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("私钥非法"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_bad_derp_map_url() {
        let err = TailcatConnector::new(valid_address(), None, false, Some("not a url".into()))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("derp_map_url"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_empty_derp_map_url() {
        let err = TailcatConnector::new(valid_address(), None, false, Some("  ".into()))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("derp_map_url"), "具名拒绝：{err}");
    }

    #[test]
    fn new_accepts_valid() {
        assert!(TailcatConnector::new(valid_address(), None, true, None).is_ok());
        assert!(TailcatConnector::new(valid_address(), None, false, None).is_ok());
    }
}
