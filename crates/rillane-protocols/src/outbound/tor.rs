//! Tor 出站客户端面（RIL-114）。
//!
//! 载具 = arti-client 0.48.0（评估记录 docs/protocol-backends.md#tor——
//! 所有语言中唯一的可嵌入 Tor 客户端库；sing-box 的 tor 出站是 bine 托管
//! `tor` 守护进程，与 openssh 二进制包装同族，非库载具，落选留证）：
//! - 引导共享：每连接器一枚 `TorClient`（`create_bootstrapped`，磁盘缓存
//!   在缺省 `~/.cache/arti` + `~/.local/share/arti`），首次流时惰性引导
//!   （冷引导探针实测 25.6s，热缓存 2.4s，180s 闸）；后续流共享目录信息
//!   不重复引导。
//! - 逐流隔离：每流经 `isolated_client()` 派生隔离客户端建出口流——
//!   流间不共享电路（协议内建的电路共享复用未交付，与 SSH 每流一连接
//!   同口径；隔离客户端共享目录信息，无重复引导成本）。
//! - 通道前置代理：`proxy` 可选（`http://IP:port` / `socks5://IP:port`，
//!   arti 经 tor-chanmgr `ProxyProtocol` 前置每条通道——本席原始出网被
//!   防火墙拦截的实况下引导即走此面探针验证；主机须为 IP，空串视为
//!   未设置，与 arti 语义一致）。
//! - 数据面泵：`TorTcpStream` 写后必须显式 `flush()`——未 flush 的写只在
//!   本地缓冲、永不离开客户端（探针 tor_proto 层追踪：BEGIN 已发、
//!   CONNECTED 已收、零 DATA 单元出站、出口约 15s 后关闭闲置流、读得
//!   EOF）。`tokio::io::copy_bidirectional` 从不调 flush，在该流上不可用
//!   ——本面每方向跑显式读→写→flush 泵，EOF 排空尾包后半关闭（对端
//!   见 EOF，半关闭语义），任一方向收束后另一方向给 5s 排空宽限。
//!
//! 交付边界（评估记录具名）：UDP 面不交付（Tor 客户端流仅 TCP，
//! catalog udp=false）；服务端面（onion service）不交付；目标寻址 host
//! 字符串原样（出口解析，本面不查 fake-ip 池）；多 tor 节点各自引导
//! （同一缺省存储路径由 sqlite 锁面承载并发，跨节点客户端共享池未交付）；
//! arti 底部拨号旁路（`with_runtime` + 自带通道工厂）结构性存在但首段不用。

use std::{fmt, future::Future, sync::Arc, time::Duration};

use anyhow::{anyhow, Context as _, Result};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use async_trait::async_trait;
use rillane_core::{EgressConnector, Flow, FlowReport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OnceCell;
use tor_chanmgr::ProxyProtocol;
use tor_rtcompat::PreferredRuntime;

/// 引导超时（冷引导探针实测 25.6s；慢网络 + 目录权威多源余量）
const TOR_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
/// 出口流建立超时（电路搭建 + 出口 BEGIN/CONNECTED；探针实测 0.5~15s）
const TOR_STREAM_TIMEOUT: Duration = Duration::from_secs(30);
/// 对端 EOF 后另一方向的排空宽限（半关闭残余回包送达面）
const RELAY_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Tor 出站连接器（RIL-114，arti-client 承载）。
///
/// [`ProxyProtocol`] 无 [`fmt::Debug`] 缺口的字段面直印；`TorClient` 不实现
/// Debug（arti-client 未派生），连接器手写 Debug 只印前置代理与引导状态，
/// 不展开客户端内部。
pub struct TorConnector {
    /// 通道前置代理（None = 直连；构造期经 arti 自家 `ProxyProtocol`
    /// 解析器校验——URI 语法错误构造即具名拒绝，不拖到引导期）
    front: Option<ProxyProtocol>,
    /// 共享 Tor 客户端（首次流惰性引导；引导失败不清槽，下一流重试）
    client_cell: OnceCell<Arc<TorClient<PreferredRuntime>>>,
}

impl fmt::Debug for TorConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorConnector")
            .field("front", &self.front)
            .field("bootstrapped", &self.client_cell.get().is_some())
            .finish()
    }
}

impl TorConnector {
    /// 构造期校验：前置代理 URI 经 arti 自家解析器具名校验（支持
    /// `http://IP:port` CONNECT 与 `socks5://`/`socks4a://`；主机须为 IP，
    /// 域名拒绝；空串视为未设置——与 arti 反序列化语义一致）
    pub fn new(proxy: Option<String>) -> Result<Self> {
        let front = match proxy {
            None => None,
            Some(ref s) if s.trim().is_empty() => None,
            Some(s) => Some(s.parse::<ProxyProtocol>().map_err(|e| {
                anyhow!(
                    "Tor 通道前置代理 URI 无效: {e}（支持 http://IP:port、socks5://IP:port；主机须为 IP）"
                )
            })?),
        };
        Ok(Self {
            front,
            client_cell: OnceCell::new(),
        })
    }

    /// 共享客户端（惰性引导，一次成活）。配置以 toml 面构建（与探针同形，
    /// 已在本席真机验证）：`[channel] outbound_proxy` 前置面 +
    /// `[storage] permissions.denied = []`（探针验证过的配置形状）。
    async fn client(&self) -> Result<Arc<TorClient<PreferredRuntime>>> {
        let front = self.front.clone();
        self.client_cell
            .get_or_try_init(|| async move {
                let toml_src = match &front {
                    Some(p) => format!(
                        "[channel]\noutbound_proxy = \"{p}\"\n[storage]\npermissions.denied = []\n"
                    ),
                    None => "[storage]\npermissions.denied = []\n".to_string(),
                };
                let bld: TorClientConfigBuilder =
                    toml::from_str(&toml_src).context("Tor toml 配置解析失败")?;
                let cfg: TorClientConfig = bld.build().context("Tor 客户端配置构建失败")?;
                // rustls provider：本仓 rustls fork 缺省无 process 级 provider，
                // 既有 TLS 面均显式选 provider（mesh_transport/dns_engine/
                // shadowtls 契约测试同口径）——引导前安装 ring 缺省，已装则
                // 尊重既有（`let _ =` 是仓内同款容忍；arti 通道 TLS 用
                // process 缺省 provider 建客户端配置）
                let _ = rustls::crypto::ring::default_provider().install_default();
                let client = tokio::time::timeout(
                    TOR_BOOTSTRAP_TIMEOUT,
                    TorClient::create_bootstrapped(cfg),
                )
                .await
                .context("Tor 引导超时")?
                .context("Tor 引导失败（目录权威不可达或前置代理失效）")?;
                tracing::info!(target: "rillane::protocols::tor", "Tor 客户端引导完成");
                Ok(client)
            })
            .await
            .cloned()
    }
}

/// 单向泵：读 → 写 → flush（TorTcpStream 必须 flush 才真正出站——探针
/// 验证过的坑）。EOF 时 flush 排空尾包再半关闭（对端见 EOF）。
async fn pump<R, W>(mut r: R, mut w: W) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buf = vec![0u8; rillane_core::performance::relay_buffer()];
    loop {
        let n = r.read(&mut buf).await.context("Tor 流读取失败")?;
        if n == 0 {
            w.flush().await.context("Tor 流收尾 flush 失败")?;
            w.shutdown().await.context("Tor 流半关闭失败")?;
            return Ok(total);
        }
        total += n as u64;
        w.write_all(&buf[..n]).await.context("Tor 流写入失败")?;
        w.flush().await.context("Tor 流 flush 失败")?;
    }
}

/// 另一方向排空（对端 EOF 后残余回包送达面）：宽限内收束计实字节数；
/// 宽限到期或排空出错按 0 记并留痕（具名边界：对端未收尾，不悬挂整流；
/// 排空期报错属对端已离场的拆线噪声，不再上抛）。
async fn drain<F>(second: F) -> u64
where
    F: Future<Output = Result<u64>>,
{
    match tokio::time::timeout(RELAY_DRAIN_GRACE, second).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!(target: "rillane::protocols::tor", "反向排空出错（按 0 记）: {e:#}");
            0
        }
        Err(_) => {
            tracing::debug!(target: "rillane::protocols::tor", "反向排空宽限到期，残余字节按 0 记");
            0
        }
    }
}

#[async_trait]
impl EgressConnector for TorConnector {
    fn name(&self) -> &'static str {
        "tor"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        let client = self.client().await?;
        // 逐流隔离：流间不共享电路（隔离客户端共享目录信息，无重复引导）
        let iso = client.isolated_client();
        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let stream = tokio::time::timeout(
            TOR_STREAM_TIMEOUT,
            iso.connect((flow.target.host.as_str(), flow.target.port)),
        )
        .await
        .context("Tor 出口流建立超时")?
        .with_context(|| format!("Tor 出口流被拒: {target}"))?;

        let (client_read, client_write) = tokio::io::split(flow.io);
        let (tor_read, tor_write) = tokio::io::split(stream);
        let up = pump(client_read, tor_write);
        let down = pump(tor_read, client_write);
        tokio::pin!(up, down);
        // 任一方向收束（EOF/错）即结束转发；错误面直接传出（另一方向随
        // future 丢弃撤销），EOF 面给另一方向排空宽限（半关闭残余送达）
        let report = tokio::select! {
            up = &mut up => {
                let upstream = up.context("Tor 上行转发失败")?;
                let downstream = drain(down).await;
                FlowReport { upstream, downstream }
            }
            down = &mut down => {
                let downstream = down.context("Tor 下行转发失败")?;
                let upstream = drain(up).await;
                FlowReport { upstream, downstream }
            }
        };
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
