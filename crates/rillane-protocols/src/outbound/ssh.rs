//! SSH-2 出站客户端面（RIL-113）。
//!
//! 载具 = russh 0.65.2（评估记录 docs/protocol-backends.md#ssh——唯一
//! 纯 Rust 异步 SSH-2 可嵌入流库，thrussh 前身无维护、ssh2/async-ssh2-lite
//! 为 libssh2 C 绑定、openssh 包系统二进制，均落选留证）：
//! - 主机钥钉扎（`Handler::check_server_key`）：服务器公钥 SHA256 指纹
//!   对照配置 `host_key`（`SHA256:` 前缀可带可不带，比对先剥前缀）。
//!   **钉扎必填**——不钉扎的客户端首用即信是本面按名拒绝的降级面；
//!   不符时观测指纹具名透出（期望/实际）。
//! - 认证恰一选一：`password`（`authenticate_password`）或
//!   `private_key`（OpenSSH 格式文件路径，`authenticate_publickey` 携
//!   `PrivateKeyWithHashAlg`——恒显式 `HashAlg::Sha256`，RSA 缺省 None
//!   会落回 legacy SHA-1 签名族；非 RSA 键该参数被忽略）。
//!   加密私钥（OpenSSH KDF）须携口令解码，无口令具名拒绝。
//! - 数据面：`channel_open_direct_tcpip(target_host, target_port,
//!   "127.0.0.1", 0)` → `into_stream()`——通道流即统一 EgressConnector
//!   面的流 IO；目标寻址用 host 字符串原样（由 sshd 解析），本面不查
//!   fake-ip 池。
//!
//! 交付边界（评估记录具名）：每流一条 SSH 连接（协议内建通道复用未
//! 交付）；UDP 面不交付（direct-tcpip 仅 TCP，catalog udp=false）；
//! 服务端面不交付；客户端 keepalive 未配置（russh 缺省 None——长空闲
//! 流的收束面依服务端 sshd 策略）；russh 底部拨号旁路（`connect_stream`
//! 接受现成流）结构性存在但首段不用。

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use rillane_core::{EgressConnector, Flow, FlowReport};
use russh::client::{self, Handle, Handler};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};

/// 拨号超时（与 hysteria/hysteria2/snell 同口径）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 认证超时（在 SSH 握手之后，独立给闸防悬挂）
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
/// 开通道超时（direct-tcpip 请求往返）
const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// 认证面（恰一选一，构造期强制）
#[derive(Debug, Clone)]
enum SshAuth {
    Password(String),
    /// OpenSSH 格式私钥文件路径 + 可选解密口令
    PrivateKey {
        path: String,
        passphrase: Option<String>,
    },
}

/// SSH-2 出站连接器（RIL-113，russh 承载）
#[derive(Debug)]
pub struct SshConnector {
    server: String,
    port: u16,
    username: String,
    auth: SshAuth,
    /// 主机钥 SHA256 指纹（比对口径：剥 `SHA256:` 前缀的裸 base64）
    host_key: String,
}

impl SshConnector {
    /// 构造期校验：主机钥钉扎必填、认证恰一选一（缺一/双带均具名拒绝，
    /// 不静默取一边）
    pub fn new(
        server: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: Option<String>,
        private_key: Option<String>,
        private_key_passphrase: Option<String>,
        host_key: impl Into<String>,
    ) -> Result<Self> {
        let server = server.into();
        let username = username.into();
        let host_key = host_key.into();
        if server.is_empty() {
            bail!("SSH 缺少服务器地址");
        }
        if username.is_empty() {
            bail!("SSH 缺少用户名");
        }
        let bare = host_key.trim_start_matches("SHA256:").trim().to_string();
        if bare.is_empty() {
            bail!("SSH 缺少 host_key 钉扎（不钉扎首用即信是具名拒绝的降级面）");
        }
        let auth = match (password, private_key) {
            (Some(_), Some(_)) => {
                bail!("SSH 认证须 password 与 private-key 恰一选一，不得双带");
            }
            (None, None) => bail!("SSH 认证须 password 与 private-key 恰一选一，二者皆缺"),
            (Some(p), None) => {
                if p.is_empty() {
                    bail!("SSH 密码认证面为空");
                }
                SshAuth::Password(p)
            }
            (None, Some(path)) => {
                if path.is_empty() {
                    bail!("SSH 私钥路径为空");
                }
                SshAuth::PrivateKey {
                    path,
                    passphrase: private_key_passphrase.filter(|p| !p.is_empty()),
                }
            }
        };
        Ok(Self {
            server,
            port,
            username,
            auth,
            host_key: bare,
        })
    }

    /// 加载 OpenSSH 格式私钥（文件路径）；加密键须携口令解码——
    /// 无口令具名拒绝（不静默在认证期炸出不可读错误）。
    fn load_private_key(path: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("SSH 私钥文件读取失败: {path}"))?;
        let key = PrivateKey::from_openssh(&content)
            .with_context(|| format!("SSH 私钥解析失败（须 OpenSSH 格式）: {path}"))?;
        if key.is_encrypted() {
            let Some(p) = passphrase else {
                bail!("SSH 私钥已加密但未提供口令: {path}");
            };
            key.decrypt(p)
                .context("SSH 私钥口令解码失败（口令不符或键损坏）")
        } else {
            Ok(key)
        }
    }
}

/// 主机钥钉扎 Handler：`check_server_key` 对照钉扎指纹，观测值写入
/// 共享槽（Arc 所有制在 handler 被 `client::connect` 消费后仍留存），
/// 连接失败路径据此具名透出期望/实际。
struct HostKeyPin {
    pin: String,
    observed: Arc<Mutex<Option<String>>>,
}

impl Handler for HostKeyPin {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // 证书形态取其内层公钥（本面不做证书策略，指纹按公钥比对）
        let fingerprint = key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            .trim_start_matches("SHA256:")
            .to_string();
        *self.observed.lock().expect("主机钥观测槽不可 poisoned") = Some(fingerprint.clone());
        Ok(fingerprint == self.pin)
    }
}

/// 连接错误→具名错误：主机钥已见且不符时点名期望/实际，其余保留
/// russh 错误链并冠以地址（`client::connect` 的错误型即 `H::Error`，
/// 本 Handler 为 anyhow）。
fn named_connect_error(
    err: anyhow::Error,
    observed: &Arc<Mutex<Option<String>>>,
    pin: &str,
    addr: &str,
) -> anyhow::Error {
    if let Some(seen) = observed
        .lock()
        .expect("主机钥观测槽不可 poisoned")
        .as_deref()
    {
        if seen != pin {
            return anyhow!("SSH 主机钥不符: 期望 SHA256:{pin}, 实际 SHA256:{seen} ({addr})");
        }
    }
    err.context(format!("SSH 连接失败: {addr}"))
}

#[async_trait]
impl EgressConnector for SshConnector {
    fn name(&self) -> &'static str {
        "ssh"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        let addr = format!("{}:{}", self.server, self.port);
        let config = Arc::new(client::Config::default());

        // 连接 + 主机钥钉扎（15s 闸）；观测槽 Arc 在 handler 被 connect
        // 消费后留存，错误路径据此对名
        let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let mut handle: Handle<HostKeyPin> = tokio::time::timeout(
            CONNECT_TIMEOUT,
            client::connect(
                config,
                &addr,
                HostKeyPin {
                    pin: self.host_key.clone(),
                    observed: observed.clone(),
                },
            ),
        )
        .await
        .context("SSH 连接超时")?
        .map_err(|e| named_connect_error(e, &observed, &self.host_key, &addr))?;

        // 认证（恰一面，构造期已强制）
        match &self.auth {
            SshAuth::Password(p) => {
                let authed = tokio::time::timeout(
                    AUTH_TIMEOUT,
                    handle.authenticate_password(self.username.clone(), p.clone()),
                )
                .await
                .context("SSH 认证超时")?
                .context("SSH 认证失败")?;
                if !authed.success() {
                    bail!("SSH 密码认证被拒: {}@{addr}", self.username);
                }
            }
            SshAuth::PrivateKey { path, passphrase } => {
                let key = Self::load_private_key(path, passphrase.as_deref())?;
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
                let authed = tokio::time::timeout(
                    AUTH_TIMEOUT,
                    handle.authenticate_publickey(self.username.clone(), key),
                )
                .await
                .context("SSH 认证超时")?
                .context("SSH 认证失败")?;
                if !authed.success() {
                    bail!("SSH 公钥认证被拒: {}@{addr} (key={path})", self.username);
                }
            }
        }

        // direct-tcpip 通道（目标 host 字符串原样，sshd 解析）
        let channel = tokio::time::timeout(
            CHANNEL_OPEN_TIMEOUT,
            handle.channel_open_direct_tcpip(
                flow.target.host.clone(),
                u32::from(flow.target.port),
                "127.0.0.1",
                0,
            ),
        )
        .await
        .context("SSH 开通道超时")?
        .with_context(|| {
            format!(
                "SSH direct-tcpip 被拒: {}:{}@{addr}",
                flow.target.host, flow.target.port
            )
        })?;
        let mut stream = channel.into_stream();

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(
            &mut flow.io,
            &mut stream,
            rillane_core::performance::relay_buffer(),
            rillane_core::performance::relay_buffer(),
        )
        .await
        .context("SSH 通道双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests;
