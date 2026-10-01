//! WireGuard 出口连接器实现（系统级接口）
//!
//! 说明：
//! - 该实现会创建/配置 WireGuard 接口并注入路由（wg-quick 风格），依赖系统权限。
//! - 转发阶段仍使用常规 `TcpStream::connect`，由系统路由将流量导入 WireGuard 接口。

use std::{net::IpAddr, str::FromStr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, Userspace, WGApi,
    WireguardInterfaceApi,
};
use seep_core::{
    EgressConnector, Flow, FlowContext, FlowReport, FlowTarget, RouteDecision, TargetProto,
};
use sha1::{Digest, Sha1};
use tokio::{net::TcpStream, sync::OnceCell};

pub struct WireguardConnector {
    egress_name: String,
    endpoint: String,
    private_key: String,
    public_key: String,
    address: String,
    allowed_ips: Option<Vec<String>>,
    preshared_key: Option<String>,
    persistent_keepalive: Option<u16>,
    listen_port: Option<u16>,
    mtu: Option<u16>,
    dns: Option<Vec<String>>,
    api: OnceCell<tokio::sync::Mutex<WGApi<Userspace>>>,
}

impl WireguardConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        egress_name: String,
        endpoint: String,
        private_key: String,
        public_key: String,
        address: String,
        allowed_ips: Option<Vec<String>>,
        preshared_key: Option<String>,
        persistent_keepalive: Option<u16>,
        listen_port: Option<u16>,
        mtu: Option<u16>,
        dns: Option<Vec<String>>,
    ) -> Self {
        Self {
            egress_name,
            endpoint,
            private_key,
            public_key,
            address,
            allowed_ips,
            preshared_key,
            persistent_keepalive,
            listen_port,
            mtu,
            dns,
            api: OnceCell::new(),
        }
    }

    fn iface_candidates(&self) -> Vec<String> {
        let mut seed = [0u8; 8];
        {
            let mut hasher = Sha1::new();
            hasher.update(self.egress_name.as_bytes());
            let digest = hasher.finalize();
            seed.copy_from_slice(&digest[..8]);
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS userspace implementation uses utunX interfaces.
            let start = u16::from_be_bytes([seed[0], seed[1]]) % 200 + 10;
            (0..32).map(|i| format!("utun{}", start + i)).collect()
        }

        #[cfg(not(target_os = "macos"))]
        {
            // Linux/FreeBSD: interface name length is typically <= 15.
            let hex = hex8(&seed);
            let mut name = format!("seepwg-{}", &hex[..6]);
            if name.len() > 15 {
                name.truncate(15);
            }
            vec![name]
        }
    }

    fn parse_addresses(&self) -> Result<Vec<IpAddrMask>> {
        let parts = self
            .address
            .split([',', ' ', '\n', '\t', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if parts.is_empty() {
            return Err(anyhow!("WireGuard address 不能为空"));
        }
        let mut out = Vec::new();
        for p in parts {
            let m =
                IpAddrMask::from_str(p).map_err(|_| anyhow!("无效的 WireGuard address: {p}"))?;
            out.push(m);
        }
        Ok(out)
    }

    fn parse_allowed_ips(&self) -> Result<Vec<IpAddrMask>> {
        let Some(ips) = self.allowed_ips.clone() else {
            return Err(anyhow!(
                "WireGuard 缺少 allowed_ips（例如 [\"10.0.0.0/24\"] 或 [\"0.0.0.0/0\", \"::/0\"]）"
            ));
        };
        if ips.is_empty() {
            return Err(anyhow!(
                "WireGuard allowed_ips 不能为空（例如 [\"0.0.0.0/0\", \"::/0\"]）"
            ));
        };
        let mut out = Vec::new();
        for s in ips {
            let m = IpAddrMask::from_str(s.trim())
                .map_err(|_| anyhow!("无效的 WireGuard allowed_ips: {s}"))?;
            out.push(m);
        }
        Ok(out)
    }

    fn parse_dns(&self) -> Result<Vec<IpAddr>> {
        let mut out = Vec::new();
        for s in self.dns.clone().unwrap_or_default() {
            let ip: IpAddr = s.parse().with_context(|| format!("无效的 DNS IP: {s}"))?;
            out.push(ip);
        }
        Ok(out)
    }

    async fn ensure_interface(&self) -> Result<()> {
        self.api
            .get_or_try_init(|| async {
                let candidates = self.iface_candidates();
                let endpoint = self.endpoint.clone();
                let private_key = self.private_key.clone();
                let public_key = self.public_key.clone();
                let preshared_key = self.preshared_key.clone();
                let persistent_keepalive = self.persistent_keepalive;
                let listen_port = self.listen_port.unwrap_or(0);
                let mtu = self.mtu.map(u32::from);
                let addresses = self.parse_addresses()?;
                let allowed_ips = self.parse_allowed_ips()?;
                let dns = self.parse_dns()?;

                tokio::task::spawn_blocking(
                    move || -> Result<tokio::sync::Mutex<WGApi<Userspace>>> {
                        let mut last_err: Option<anyhow::Error> = None;
                        for ifname in candidates {
                            let mut wgapi = WGApi::<Userspace>::new(ifname.clone())
                                .context("创建 WGApi 失败")?;
                            match wgapi.create_interface() {
                                Ok(()) => {
                                    let mut peer = Peer::new(
                                        Key::try_from(public_key.as_str())
                                            .context("无效的 WireGuard public_key")?,
                                    );
                                    peer.set_endpoint(&endpoint)
                                        .context("无效的 WireGuard endpoint")?;
                                    peer.set_allowed_ips(allowed_ips.clone());
                                    if let Some(psk) = &preshared_key {
                                        peer.preshared_key = Some(
                                            Key::try_from(psk.as_str())
                                                .context("无效的 WireGuard preshared_key")?,
                                        );
                                    }
                                    peer.persistent_keepalive_interval = persistent_keepalive;

                                    let iface = InterfaceConfiguration {
                                        name: ifname.clone(),
                                        prvkey: private_key.clone(),
                                        addresses: addresses.clone(),
                                        port: listen_port,
                                        peers: vec![peer.clone()],
                                        mtu,
                                    };

                                    wgapi.configure_interface(&iface).map_err(|e| {
                                        anyhow!("配置 WireGuard interface 失败: {e}")
                                    })?;

                                    // Add routes for AllowedIPs (wg-quick style).
                                    wgapi.configure_peer_routing(&iface.peers).map_err(|e| {
                                        anyhow!("配置 WireGuard peer routing 失败: {e}")
                                    })?;

                                    if !dns.is_empty() {
                                        wgapi
                                            .configure_dns(&dns, &[])
                                            .map_err(|e| anyhow!("配置 WireGuard DNS 失败: {e}"))?;
                                    }

                                    tracing::info!(
                                        target: "seep::wireguard",
                                        ifname = %ifname,
                                        endpoint = %endpoint,
                                        "WireGuard 接口已初始化"
                                    );

                                    return Ok(tokio::sync::Mutex::new(wgapi));
                                }
                                Err(e) => {
                                    last_err =
                                        Some(anyhow!("创建 WireGuard 接口失败({ifname}): {e}"));
                                    continue;
                                }
                            }
                        }
                        Err(last_err.unwrap_or_else(|| anyhow!("无法创建 WireGuard 接口")))
                    },
                )
                .await
                .context("WireGuard 初始化任务失败")?
            })
            .await?;

        Ok(())
    }
}

#[async_trait]
impl EgressConnector for WireguardConnector {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
        match flow.target.proto {
            TargetProto::Tcp => {}
            _ => return Err(anyhow!("WireGuard connector 暂仅支持 TCP 转发")),
        }

        self.ensure_interface().await?;

        let target = format!("{}:{}", flow.target.host, flow.target.port);
        let mut outbound = TcpStream::connect(&target)
            .await
            .with_context(|| format!("连接目标 {} 失败", target))?;

        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
            .await
            .context("双向转发失败")?;

        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(not(target_os = "macos"))]
fn hex8(bytes: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// WireGuard UDP 出站连接器（udp-relay-path.md §3.5 注记）。
///
/// 与 TCP 面同一架构：本实现是系统接口（wg-quick 风格），UDP 面不手工构造
/// IP 包 —— 本地 UDP socket `connect` 目标，由内核路由导入 wg 接口。
/// - `allowed_ips` 预检：目标 IP 不在任何网段 → Route 类错误（§3.6：关映射+清决策）；
///   网段在构建期解析，配置错误启动即报。
/// - MTU 上限：wg 封装开销按 80B 预留（IPv6 最坏值），超限包丢弃（R8），
///   错误归类 Timeout（映射保留待空闲回收，丢弃计入 send_failed）。
pub struct WireguardUdpConnector {
    allowed_ips: Vec<IpAddrMask>,
    mtu_cap: usize,
}

impl WireguardUdpConnector {
    pub fn new(allowed_ips: Option<Vec<String>>, mtu: Option<u16>) -> Result<Self> {
        let mut parsed = Vec::new();
        if let Some(ips) = &allowed_ips {
            for s in ips {
                let m = IpAddrMask::from_str(s.trim())
                    .map_err(|_| anyhow!("无效的 WireGuard allowed_ips: {s}"))?;
                parsed.push(m);
            }
        }
        // 界面 MTU 减去 wg 封装开销（最坏 80B）；未配置用保守 1400
        let mtu_cap = match mtu {
            Some(m) if m >= 100 => (m as usize) - 80,
            Some(m) => return Err(anyhow!("WireGuard mtu 过小: {m}")),
            None => 1400,
        };
        Ok(Self {
            allowed_ips: parsed,
            mtu_cap,
        })
    }

    async fn resolve_target(&self, target: &FlowTarget) -> Result<std::net::SocketAddr> {
        let addr = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .with_context(|| format!("目标解析失败: {}:{}", target.host, target.port))?
            .next()
            .ok_or_else(|| anyhow!("目标解析失败: {}:{}", target.host, target.port))?;
        Ok(addr)
    }

    fn allowed_ips_contain(&self, ip: std::net::IpAddr) -> bool {
        if self.allowed_ips.is_empty() {
            return true; // 未配置网段：不预检，交内核路由判定
        }
        self.allowed_ips.iter().any(|m| cidr_contains(m, ip))
    }
}

struct WgUdpRelay {
    socket: tokio::net::UdpSocket,
    target: FlowTarget,
    mtu_cap: usize,
}

#[async_trait]
impl seep_core::udp::EgressUdpConnector for WireguardUdpConnector {
    fn name(&self) -> &str {
        "wireguard"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> Result<Arc<dyn seep_core::udp::UdpRelay>> {
        let addr = self.resolve_target(&ctx.target).await?;
        if !self.allowed_ips_contain(addr.ip()) {
            return Err(anyhow!(
                "路由不可达: 目标 {addr} 不在 wireguard allowed_ips 网段内"
            ));
        }
        let bind = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        socket.connect(addr).await?;
        Ok(Arc::new(WgUdpRelay {
            socket,
            target: ctx.target,
            mtu_cap: self.mtu_cap,
        }))
    }
}

#[async_trait]
impl seep_core::udp::UdpRelay for WgUdpRelay {
    async fn send_to(&self, _target: &FlowTarget, buf: &[u8]) -> Result<()> {
        if buf.len() > self.mtu_cap {
            return Err(anyhow!(
                "wireguard MTU 超限: {} 字节 > 上限 {}（超出部分按 R8 丢弃）",
                buf.len(),
                self.mtu_cap
            ));
        }
        // 已 connect：内核路由导入 wg 接口（target 参数与构造时一致）
        Ok(self.socket.send(buf).await.map(|_| ())?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let n = self.socket.recv(buf).await?;
        Ok((self.target.clone(), n))
    }
}

/// CIDR 网段包含判定（defguard_wireguard_rs 0.8 的 IpAddrMask 无 contains）。
/// 地址族不匹配视为不包含（v4 网段不含 v6 目标，反之亦然）。
fn cidr_contains(m: &IpAddrMask, ip: std::net::IpAddr) -> bool {
    match (m.address, ip) {
        (IpAddr::V4(net), IpAddr::V4(a)) => {
            let cidr = m.cidr.min(32);
            let mask = if cidr == 0 {
                0
            } else {
                u32::MAX << (32 - cidr)
            };
            (u32::from(net) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(a)) => {
            let cidr = m.cidr.min(128);
            let mask = if cidr == 0 {
                0
            } else {
                u128::MAX << (128 - cidr)
            };
            (u128::from(net) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}
