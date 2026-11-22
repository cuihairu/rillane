//! Tailscale 出口连接器实现（RIL-123）。
//!
//! 三层 mesh 客户端面（库承载——`tailscale` 0.7.1，tailscale-rs，BSD-3-Clause；
//! 评估留证 protocol-backends.md#tailscale：自托管协调 + 官方 Go 客户端为真机
//! 对端）。本模块嵌入载具 `tailscale::Device`：`Device::new(&Config,
//! Some(auth_key))` 完成噪音控制面握手 + tailnet 授权（`is_authorized`），
//! 数据面 = 载具 WireGuard 数据通道（直连或 DERP 中继）经
//! `ts_netstack_smoltcp` 用户态栈，`Device::tcp_connect` 给出已解封的
//! `netstack::TcpStream`（tokio AsyncRead + AsyncWrite）——与
//! OpenConnect/OpenVPN 同构的三层桥，但目标寻址为 tailnet 地址（对端
//! tailnet IP 字面量或 peer 主机名，经 `peer_by_name`）。一节点一个共享
//! `Device`（一条 tailnet 身份），全部流多路复用其上。
//!
//! 安全姿态与具名边界（见 protocol-backends.md#tailscale）：载具为 pre-1.0
//! （自述无兼容保证），NAT 穿透在研——数据面可能回退 DERP 中继（验收须
//! 标注）；不支持出口节点/MagicDNS/子网路由器/私有 DERP/taildrop。UDP/QUIC
//! 应用面不交付（catalog udp=false）；服务端面不交付；系统 TUN 路线未走
//! （用户态栈）。`control_url` 必填非空（不静默指官方协调端点）；`auth_key`
//! 必填非空（preauth key）；`key_file` 为节点身份持久路径（载具
//! `load_or_init`：缺失即新建身份）。

use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::timeout;

/// 控制面握手 + 授权超时上限
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// 目标拨出超时
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// 节点身份配置（IR `EgressConfig::Tailscale` 展开后的私有形态）
#[derive(Debug, Clone)]
struct TailscaleConfig {
    /// 控制面 URL（自托管 headscale 或 Tailscale 协调端点）
    control_url: String,
    /// preauth key
    auth_key: String,
    /// 请求主机名（tailnet 内名称；None → 载具用系统主机名）
    hostname: Option<String>,
    /// 是否临时节点（注销即清）
    ephemeral: bool,
    /// 节点身份持久文件（载具 `load_or_init`：缺失即新建身份）
    key_file: String,
}

/// Tailscale 连接器：一节点一个共享 `tailscale::Device`（一条 tailnet 身份），
/// 全部流多路复用其上（与 OpenVPN 每节点一会话同口径）。
pub struct TailscaleConnector {
    cfg: TailscaleConfig,
    device: OnceCell<Arc<tailscale::Device>>,
}

impl TailscaleConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        control_url: String,
        auth_key: String,
        hostname: Option<String>,
        ephemeral: bool,
        key_file: String,
    ) -> Result<Self> {
        if control_url.trim().is_empty() {
            return Err(anyhow!(
                "tailscale 控制面地址为空（control_url 必填，不静默指官方协调端点）"
            ));
        }
        // 控制面 URL 建期解析校验（具名非法，不落任何身份文件）
        if url::Url::parse(&control_url).is_err() {
            return Err(anyhow!("tailscale 控制面 URL 非法：{control_url}"));
        }
        if auth_key.trim().is_empty() {
            return Err(anyhow!("tailscale auth_key 必填非空（preauth key）"));
        }
        if key_file.trim().is_empty() {
            return Err(anyhow!("tailscale key_file 必填非空（节点身份持久路径）"));
        }
        Ok(Self {
            cfg: TailscaleConfig {
                control_url,
                auth_key,
                hostname,
                ephemeral,
                key_file,
            },
            device: OnceCell::new(),
        })
    }

    /// 惰性建立共享 Device（载具控制面握手 + 授权；一次性，超时具名）。
    async fn device(&self) -> Result<Arc<tailscale::Device>> {
        let dev =
            self.device
                .get_or_try_init(|| async {
                    let mut config = tailscale::Config::default_with_key_file(&self.cfg.key_file)
                        .await
                        .context("载具密钥文件初始化失败")?;
                    config.control_server_url =
                        self.cfg.control_url.parse().with_context(|| {
                            format!("控制面 URL 非法：{}", self.cfg.control_url)
                        })?;
                    if let Some(h) = self.cfg.hostname.clone() {
                        config.requested_hostname = Some(h);
                    }
                    config.ephemeral = self.cfg.ephemeral;
                    let dev = timeout(
                        CONNECT_TIMEOUT,
                        tailscale::Device::new(&config, Some(self.cfg.auth_key.clone())),
                    )
                    .await
                    .context("tailscale 控制面连接超时（控制服务不可达）")?
                    .context("载具启动失败")?;
                    match timeout(CONNECT_TIMEOUT, dev.is_authorized()).await {
                        Ok(Ok(tailscale::AuthState::Authorized)) => {}
                        Ok(Ok(tailscale::AuthState::NotAuthorized(url))) => {
                            bail!("tailscale 未授权（preauth key 失效，须重新申请）：{url}");
                        }
                        Ok(Err(e)) => bail!("tailscale 授权失败：{e}"),
                        Err(_) => bail!("tailscale 授权超时（控制面不可达）"),
                    }
                    Ok(Arc::new(dev))
                })
                .await;
        dev.cloned()
    }

    /// 目标解析：字面量 IP 直用；主机名经 `peer_by_name` 取对端 tailnet IPv4。
    async fn resolve(&self, dev: &tailscale::Device, host: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let node = dev
            .peer_by_name(host)
            .await
            .context("tailnet 对端查询失败")?
            .ok_or_else(|| anyhow!("tailnet 无此对端：{host}"))?;
        Ok(SocketAddr::new(
            node.tailnet_address.ipv4.addr().into(),
            port,
        ))
    }
}

#[async_trait::async_trait]
impl rillane_core::EgressConnector for TailscaleConnector {
    fn name(&self) -> &'static str {
        "tailscale"
    }

    async fn forward(&self, mut flow: rillane_core::Flow) -> Result<rillane_core::FlowReport> {
        use rillane_core::{FlowReport, TargetProto};
        if !matches!(flow.target.proto, TargetProto::Tcp) {
            return Err(anyhow!(
                "Tailscale 仅交付 TCP 应用面（UDP/QUIC 应用面不交付）"
            ));
        }
        let dev = self.device().await?;
        let remote = self
            .resolve(&dev, &flow.target.host, flow.target.port)
            .await?;
        let mut stream = timeout(DIAL_TIMEOUT, dev.tcp_connect(remote))
            .await
            .context("tailnet 目标连接超时")?
            .context("tailnet 目标连接失败")?;
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

    #[test]
    fn new_rejects_empty_control_url() {
        let err = TailscaleConnector::new(
            String::new(),
            "preauth-key-xyz".into(),
            None,
            false,
            "/tmp/tsrs_keys.json".into(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("control_url"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_empty_auth_key() {
        let err = TailscaleConnector::new(
            "http://127.0.0.1:8080".into(),
            "  ".into(),
            None,
            false,
            "/tmp/tsrs_keys.json".into(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("auth_key"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_empty_key_file() {
        let err = TailscaleConnector::new(
            "http://127.0.0.1:8080".into(),
            "preauth-key-xyz".into(),
            None,
            false,
            String::new(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("key_file"), "具名拒绝：{err}");
    }

    #[test]
    fn new_rejects_bad_control_url() {
        let err = TailscaleConnector::new(
            "not a url".into(),
            "preauth-key-xyz".into(),
            None,
            false,
            "/tmp/tsrs_keys.json".into(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("控制面 URL 非法"), "具名拒绝：{err}");
    }

    #[test]
    fn new_accepts_valid() {
        assert!(TailscaleConnector::new(
            "http://127.0.0.1:8080".into(),
            "preauth-key-xyz".into(),
            Some("rillane-node".into()),
            true,
            "/tmp/tsrs_keys.json".into(),
        )
        .is_ok());
    }
}
