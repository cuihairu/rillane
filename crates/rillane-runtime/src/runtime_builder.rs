//! 运行时构建器
//!
//! 整合配置、路由、网络虚拟化与 Mesh/订阅组件，
//! 构建可运行的 Rillane runtime。
//! 支持多跳链路构建与故障转移。

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    task::JoinHandle,
    time,
};

use rillane_config::{
    resolve_udp_enabled, EgressConfig, EgressDescriptor, GroupMember, IngressConfig,
    IngressDescriptor, PolicyGroup, RillaneConfig, RoutingConfig, SelectionMode, UdpConfig,
};
// TUN 装配块专用（Linux 门控面，platform-packaging.md）
#[cfg(target_os = "linux")]
use rillane_config::MatchCondition;
// 协议目录准入（RIL-104）：装配期先查目录，未准入/编目外类型不进热路径
use rillane_config::contract::CODE_UNKNOWN_EGRESS;
use rillane_config::protocol_catalog::{
    admission, Admission, Registration, CODE_EGRESS_NOT_ADMITTED,
};
use rillane_core::udp::table::chain_id_of;
use rillane_core::udp::{ChainFailureEvent, EgressUdpConnector};
use rillane_core::{
    EgressConnector, Flow, FlowContext, FlowOutput, FlowReport, FlowRouter, IngressEndpoint,
    MiddlewareChain, RouteDecision, RoutePath,
};
use rillane_mesh::{MeshRegistry, MeshSession, NodeId, SessionId};
#[cfg(target_os = "linux")]
use rillane_platform::network::route::RouteDestination;
use rillane_platform::network::{NetworkConfig, NetworkManager, NetworkMode};
use rillane_protocols::middleware::{ANN_ROUTE_EGRESS, ANN_ROUTE_KIND};
#[cfg(target_os = "linux")]
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use crate::tun_ingress::{TunIngress, TunIngressConfig};
use rillane_protocols::{
    AnytlsConnector, AnytlsUdpConnector, DirectConnector, HttpConnector, HttpIngress,
    Hysteria2Connector, Hysteria2Ingress, Hysteria2UdpConnector, Hysteria2UdpParts,
    HysteriaConnector, HysteriaIngress, HysteriaUdpConnector, HysteriaUdpParts, MasqueConnector,
    MasqueUdpConnector, MieruConnector, MixedIngress, OpenConnectConnector, OpenVpnConnector,
    ShadowQuicConnector,
    ShadowTlsIngress,
    ShadowsocksConnector, ShadowsocksIngress, ShadowsocksShadowTlsConnector,
    ShadowsocksUdpConnector, ShadowsocksUdpParts, SnellConnector, Socks5Connector, Socks5Ingress,
    Socks5UdpConnector, SshConnector, TailscaleConnector, TlsConnectorFactory, TlsFingerprint,
    TorConnector,
    TransportKey, TransportPool, TrojanConnector, TrojanIngress, TrojanUdpConnector,
    TrojanUdpParts, TrustTunnelConnector, TrustTunnelUdpConnector, TuicConnector, TuicUdpConnector,
    VlessConnector, VlessIngress, VlessUdpConnector, VlessUdpParts, VmessConnector, VmessIngress,
    VmessSecurity, VmessUdpConnector, VmessUdpParts, WireguardConnector, WireguardUdpConnector,
};
use rillane_routing::RoutingEngine;
use rillane_subscription::SubscriptionConverter;
use rillane_subscription::SubscriptionManager;

use crate::chain::{ChainBuilder, ChainConfig, ChainConstraints, ChainManager, SwitchReason};
use crate::mesh_transport::{
    MeshDataPlane, MeshEnvelope, MeshTlsConfig, MeshUdpGate, RevokedSnapshot, UdpFaceSnapshot,
    UDP_FACE_DEFAULT_MAX,
};
use crate::udp_chain::{MeshUdpBridge, UdpChainRouter, UdpClientMetrics};

/// 运行时构建器
pub struct RuntimeBuilder {
    config: RillaneConfig,
    runtime_config: RuntimeConfig,
    ingress_endpoints: HashMap<String, Arc<dyn IngressEndpoint>>,
    flow_outputs: HashMap<String, Arc<dyn FlowOutput>>,
    egress_connectors: HashMap<String, Arc<dyn EgressConnector>>,
}

impl RuntimeBuilder {
    /// 创建新的构建器
    pub fn new(config: RillaneConfig) -> Self {
        Self {
            config,
            runtime_config: RuntimeConfig::default(),
            ingress_endpoints: HashMap::new(),
            flow_outputs: HashMap::new(),
            egress_connectors: HashMap::new(),
        }
    }

    /// 自定义运行时配置
    pub fn with_runtime_config(mut self, config: RuntimeConfig) -> Self {
        self.runtime_config = config;
        self
    }

    /// 注入自定义入口
    pub fn with_ingress_endpoint<S: Into<String>>(
        mut self,
        name: S,
        endpoint: Arc<dyn IngressEndpoint>,
    ) -> Self {
        self.ingress_endpoints.insert(name.into(), endpoint);
        self
    }

    /// 注入自定义流量输出
    pub fn with_flow_output<S: Into<String>>(
        mut self,
        name: S,
        output: Arc<dyn FlowOutput>,
    ) -> Self {
        self.flow_outputs.insert(name.into(), output);
        self
    }

    /// 注入自定义出口连接器
    pub fn with_egress_connector<S: Into<String>>(
        mut self,
        name: S,
        connector: Arc<dyn EgressConnector>,
    ) -> Self {
        self.egress_connectors.insert(name.into(), connector);
        self
    }

    /// 构建 Runtime
    pub fn build(mut self) -> Result<Runtime> {
        self.validate()?;

        let config = Arc::new(RwLock::new(self.config));
        let config_snapshot = config.read().expect("config poisoned").clone();

        // RIL-016 本地策略所有权：构建期配置整份登记为 local——后续来源
        // 增量以 merge_source_delta 进入时据此拒绝触碰用户名下对象
        let local_owned = SourceOwnedNames {
            egress: config_snapshot
                .egress
                .iter()
                .map(|e| e.name.clone())
                .collect(),
            groups: config_snapshot
                .routing
                .groups
                .iter()
                .map(|g| g.name.clone())
                .collect(),
            rules: config_snapshot
                .routing
                .rules
                .iter()
                .map(|r| r.name.clone())
                .collect(),
        };
        let source_owned = Arc::new(DashMap::new());
        source_owned.insert(LOCAL_SOURCE.to_string(), local_owned);

        // 组级 SLO 值域构建期拦截（slo-scoring.md §4：schema validate +
        // 装配前防御性调用，存量路由配置无 slo 时零开销直通）
        config_snapshot.routing.validate()?;

        // RIL-140 选路模式出口装配门：全局出口须引用已声明组/出口，直连
        // 出口须为 Direct 类型出口节点——引用不存在或类型不符在装配期
        // 点名拒绝，不留到建连期才失败（无静默直连）。
        validate_mode_targets(&config_snapshot)?;

        // P3-5 performance-io.md §3：进程级 relay 缓冲设定（块缺省 None =
        // 不设定，缓冲维持 8192×2，行为零差异 §2-D5；变更需重启）
        if let Some(perf) = &config_snapshot.performance {
            perf.validate().context("performance 校验失败（E1）")?;
            if let Some(n) = perf.relay_buffer {
                rillane_core::performance::set_relay_buffer(n as usize)?;
            }
        }

        // networking.md §2 direct 出口自环逃逸（net_mark 半边①）：进程级出站
        // fwmark 设定（network.egress_fwmark；缺省 None = 不设定不触碰，存量
        // 零差异；变更需重启）。仅 Some 才写——同进程并行 build 不互踩。
        if let Some(mark) = config_snapshot
            .network
            .as_ref()
            .and_then(|n| n.egress_fwmark)
        {
            rillane_core::net_mark::set_egress_fwmark(mark);
        }

        // 创建路由引擎
        let router = Arc::new(RoutingEngine::new(config_snapshot.routing.clone()));

        // UDP 数据面块已整体下移至 ChainManager 初始化之后（P0-4 §9.1 时序裁决：
        // UDP 会话表的 FlowRouter 构造即固化，S5 需把 mesh_registry/chain_manager
        // 注入 RuntimeFlowRouter，早构造晚替换不可行——原位置即此处）。

        // P1-5 §4.1 装配：池/工厂进程级单例（D-10——只在此构造一次，热更新
        // 两路只传句柄不重建；参数烧在构造期，变更需重启，§4.3）。
        // 块缺席 = 双 None（不构池不注工厂，D-9 零差异）；块存在即按
        // enabled/tls_resumption 独立构池/注工厂。
        let egress_pool_policy = match &config_snapshot.egress_pool {
            Some(block) => Some(crate::to_pool_policy(
                block,
                self.runtime_config.connection_pool_size.unwrap_or(1024),
            )?),
            None => None,
        };
        let tls_factory = egress_pool_policy
            .as_ref()
            .filter(|p| p.tls_resumption)
            .map(|p| Arc::new(TlsConnectorFactory::new(p.session_cache_size)));
        let transport_pool = egress_pool_policy
            .filter(|p| p.enabled)
            .map(|p| TransportPool::new(p, tls_factory.clone()));

        // 出口默认实现（入口默认实现是 udp_service 唯一消费点，随 UDP 块顺延，见下）
        if self.flow_outputs.is_empty() {
            let (outputs, connectors) = build_egress_outputs(
                &config_snapshot.egress,
                transport_pool.clone(),
                tls_factory.clone(),
            )?;
            self.flow_outputs = outputs;
            if self.egress_connectors.is_empty() {
                self.egress_connectors = connectors;
            }
        }

        // G1-9 url-test 成员探测句柄注入（出口面就绪后）：按节点名取其出口，
        // 经出口 forward 管道对探测目标发 HTTP HEAD 读首字节判活（实现见
        // rillane-core `probe_via_output`）。调度/间隔门控在路由引擎
        // `perform_health_checks`；未配置 url_test 的组不产生任何探测流量。
        let probe_outputs = self.flow_outputs.clone();
        router.set_probe_handler(Arc::new(
            move |node: &str, host: &str, port: u16, path: &str, timeout: Duration| {
                // 先落 own 再进 async 块：返回 future 与入参引用生命周期解耦
                let node = node.to_string();
                let host = host.to_string();
                let path = path.to_string();
                let output = probe_outputs.get(node.as_str()).cloned();
                Box::pin(async move {
                    let output = output.ok_or_else(|| format!("节点 {node} 无对应出口"))?;
                    rillane_core::probe_via_output(output, &node, &host, port, &path, timeout).await
                }) as Pin<Box<dyn Future<Output = Result<u64, String>> + Send>>
            },
        ));

        // P1-4 §1.2/§3.2：混淆 middleware 链（块缺席/关闭 = 空链零开销，§2.5）。
        // known_egress = 配置 egress 名 ∪ build 期已注册输出名（E5 判定输入；
        // 并集覆盖 with_output 显式注册的自定义出口）。
        // small 档无 struct 字段消费 plugin_middlewares → 允许未用绑定
        #[cfg_attr(not(feature = "plugins"), allow(unused_variables))]
        let (middleware_chain, plugin_middlewares) = {
            let mut names: Vec<String> = config_snapshot
                .egress
                .iter()
                .map(|e| e.name.clone())
                .collect();
            for name in self.flow_outputs.keys() {
                if !names.iter().any(|n| n == name) {
                    names.push(name.clone());
                }
            }
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            // 观测轮（plugin-loader.md §0 计数面）：插件具体类型句柄经元组旁路
            // 留存（控制面 /plugins/stats 取数）——与链内同一实例；
            // RIL-040：small 档（无 plugins feature）仅内置链，无插件旁路面
            #[cfg(feature = "plugins")]
            let pair = crate::obfs_config::build_middleware_chain_with_plugins(
                config_snapshot.obfuscation.as_ref(),
                &refs,
            )?;
            #[cfg(not(feature = "plugins"))]
            let pair = (
                crate::obfs_config::build_middleware_chain(
                    config_snapshot.obfuscation.as_ref(),
                    &refs,
                )?,
                (),
            );
            pair
        };

        // TUN 模式属主裁决（tun-dataplane.md §2.6）：TunIngress 组合设备+路由
        // 属主——NetworkManager 在 Tun 模式让位（双设备 = 内核路由互踩）
        let network_mode_tun = self
            .runtime_config
            .network_config
            .as_ref()
            .is_some_and(|n| n.mode == NetworkMode::Tun);
        let tun_enabled = self.runtime_config.enable_network_virtualization && network_mode_tun;
        let network_manager =
            if self.runtime_config.enable_network_virtualization && !network_mode_tun {
                if let Some(network_cfg) = &self.runtime_config.network_config {
                    let mut manager = NetworkManager::new(network_cfg.clone());
                    manager.initialize()?;
                    Some(Arc::new(Mutex::new(manager)))
                } else {
                    None
                }
            } else {
                None
            };

        // P2-8 M1 §4-4：DNS 分流服务（块缺席/关闭 = None 零开销）。监听独立于
        // 网络虚拟化开关——本地监听即独立可用面（dns-partition.md §9-4，
        // resolv.conf 指向即生效；TUN 劫持归 P1-2 落地后集成）。
        let dns_service = match config_snapshot
            .network
            .as_ref()
            .and_then(|n| n.dns.as_ref())
            .filter(|d| d.enabled)
        {
            Some(dns_cfg) => {
                dns_cfg.validate().context("network.dns 校验失败（E1）")?;
                let tun_dns = config_snapshot
                    .network
                    .as_ref()
                    .and_then(|n| n.tun.as_ref())
                    .map(|t| t.dns_servers.as_slice())
                    .unwrap_or(&[]);
                let resolver_cfg =
                    crate::dns_config::dns_block_to_resolver_config(dns_cfg, tun_dns)?;
                let resolver = rillane_platform::network::DnsResolver::new(resolver_cfg)
                    .map_err(|e| anyhow!("network.dns 引擎装配失败（E1）: {e}"))?;
                let listen = SocketAddr::new(dns_cfg.listen_address, dns_cfg.listen_port);
                // G1-10 fake-ip：块在场且启用 → 构建池表交本地监听（A 查询
                // 稳定假地址应答）与入口面（出站 target 域名回填）；同一张
                // 表两侧共享，分配/反查一致。
                let fake_ip = match dns_cfg.fake_ip.as_ref() {
                    Some(fake) if fake.enabled => {
                        // G1-10 M2 边界守卫：TUN 入口未接回填——假地址无反查
                        // 改写则出口不可达（连接假 IP 必败），构建期显式拒绝
                        // 该组合而非静默断流。
                        if tun_enabled {
                            anyhow::bail!(
                                "network.dns.fake_ip 与 TUN 模式暂不兼容（G1-10 M2：TUN 入口回填未接线）——假地址无回填则出口不可达，请关闭其一"
                            );
                        }
                        let table = rillane_core::fake_ip::FakeIpTable::from_cidr(&fake.range)
                            .map_err(|e| anyhow!("network.dns.fake_ip 配置非法：{e}"))?;
                        // RIL-142 双栈：range6 在场 → 追加独立 v6 池（AAAA
                        // 同答假地址）；缺席 = AAAA 照常真实解析（存量零差异）
                        let table = match fake.range6.as_ref() {
                            Some(range6) => table
                                .with_v6_cidr(range6)
                                .map_err(|e| anyhow!("network.dns.fake_ip.range6 配置非法：{e}"))?,
                            None => table,
                        };
                        Some(Arc::new(table))
                    }
                    _ => None,
                };
                // G2-15 hosts 映射：非空映射 → 构建静态表交本地监听面
                //（A/AAAA 命中直答真实地址，先于 fake-ip）；空/缺 = None
                let hosts_table = match dns_cfg.hosts.as_ref() {
                    Some(map) if !map.is_empty() => Some(Arc::new(
                        rillane_core::hosts::DnsHosts::from_map(map)
                            .map_err(|e| anyhow!("network.dns.hosts 配置非法：{e}"))?,
                    )),
                    _ => None,
                };
                // RIL-142 例外表：非空例外 → 注入监听面（命中例外的
                // A/AAAA 查询跳过池分配照常真实解析）；空 = 不注入
                let dns_service = crate::dns_config::DnsService::new(
                    Arc::new(resolver),
                    listen,
                    fake_ip,
                    hosts_table,
                );
                let dns_service = match dns_cfg.fake_ip.as_ref() {
                    Some(fake) if !fake.exceptions.is_empty() => dns_service
                        .with_fake_ip_exceptions(Arc::new(
                            rillane_core::fake_ip::FakeIpExceptions::new(&fake.exceptions),
                        )),
                    _ => dns_service,
                };
                Some(Arc::new(dns_service))
            }
            None => None,
        };

        let local_node_id = if self.runtime_config.enable_mesh {
            // Persist mesh_config back into runtime_config for later (listener bind, etc).
            if self.runtime_config.mesh_config.is_none() {
                self.runtime_config.mesh_config = Some(MeshConfig::default());
            }
            let mut mesh_cfg = self.runtime_config.mesh_config.clone().unwrap_or_default();
            // Enforce mesh data-plane mTLS when explicitly enabled via env.
            if MeshTlsConfig::enabled_by_env() {
                let tls = MeshTlsConfig::from_env_strict()?
                    .ok_or_else(|| anyhow!("mesh mTLS is enabled but config is missing"))?;
                mesh_cfg.data_plane_tls = Some(tls);
                self.runtime_config.mesh_config = Some(mesh_cfg.clone());
            }
            // Enforce secure-by-default mesh data-plane when chain is enabled.
            if self.runtime_config.enable_chain {
                let allow_plaintext = mesh_cfg.allow_plaintext_data_plane
                    || std::env::var("RILLANE_MESH_ALLOW_PLAINTEXT")
                        .ok()
                        .map(|v| {
                            matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
                        })
                        .unwrap_or(false);
                let allow_no_client_auth = mesh_cfg.allow_no_client_auth
                    || std::env::var("RILLANE_MESH_ALLOW_NO_CLIENT_AUTH")
                        .ok()
                        .map(|v| {
                            matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
                        })
                        .unwrap_or(false);

                if !allow_plaintext {
                    let tls = mesh_cfg.data_plane_tls.as_ref().ok_or_else(|| {
                        anyhow!(
                            "链路功能已启用，mesh data-plane 需要启用 mTLS：请设置 RILLANE_MESH_MTLS=1，并提供 RILLANE_MESH_MTLS_CA/RILLANE_MESH_MTLS_CERT/RILLANE_MESH_MTLS_KEY（开发环境可设置 RILLANE_MESH_ALLOW_PLAINTEXT=1 绕过）"
                        )
                    })?;
                    if !tls.require_client_auth && !allow_no_client_auth {
                        return Err(anyhow!(
                            "链路功能已启用，mesh data-plane 必须开启客户端证书校验：请设置 RILLANE_MESH_MTLS_REQUIRE_CLIENT_AUTH=1（开发环境可设置 RILLANE_MESH_ALLOW_NO_CLIENT_AUTH=1 绕过）"
                        ));
                    }
                }
            }
            let node_id = mesh_cfg.node_id.clone();
            let _registry = register_local_mesh_node(mesh_cfg)?;
            Some((node_id, _registry))
        } else {
            None
        };

        let (local_node_id, mesh_registry) = match local_node_id {
            Some((id, reg)) => (Some(id), Some(reg)),
            None => (None, None),
        };

        // 初始化链路管理器（需要先有 mesh_registry）
        let chain_manager = if self.runtime_config.enable_chain {
            if let Some(ref registry) = mesh_registry {
                let chain_cfg = self.runtime_config.chain_config.clone().unwrap_or_default();
                let builder = Arc::new(ChainBuilder::new(chain_cfg.clone(), registry.clone()));
                Some(Arc::new(ChainManager::new(
                    chain_cfg,
                    builder,
                    registry.clone(),
                )))
            } else {
                tracing::warn!(
                    target: "rillane::runtime",
                    "链路功能已启用但 Mesh 未启用，链路管理器将不可用"
                );
                None
            }
        } else {
            None
        };

        // UDP 数据面（P0-2/P0-3，udp-relay-path.md §2/§3）：udp.enabled 时构建
        // 共享会话表 + 按节点能力表注册的 RoutingUdpConnector；§3.1 构建期扫描
        // 拦截 UDP 不可达节点。周期回收任务随首个 ASSOCIATE 拉起。
        // —— P0-4 §9.1 时序裁决：本块自路由引擎构造之后整体下移至此（ChainManager
        // 之后）：UDP 会话表的 FlowRouter 构造即固化。
        // —— P0-4 §9.2/S5 mesh-chain 接线：chain 启用时 ①UDP 表 FlowRouter 换
        // RuntimeFlowRouter（chain 决策产生处，S0 下移腾出的位置）；②出站连接器包
        // UdpChainRouter（Chain 决策 → MeshUdpBridge）；③UDP 明文门合流（§13-6，
        // cfg ∪ env 求值一次——两消费点 client 桥构造 / 非 client spawn_udp 同源）；
        // ④§8 链路故障事件通道（FlowOutputRouter 切换成功后 → 表 handle_chain_failure）。
        let mut mesh_udp_gate: Option<MeshUdpGate> = None;
        let mut chain_failure_tx: Option<mpsc::Sender<ChainFailureEvent>> = None;
        // TUN UDP 面出站连接器（UDP 块内 clone 于 service 消费前）
        let mut tun_udp_connector: Option<Arc<dyn EgressUdpConnector>> = None;
        // P0-5 §4 观测接缝③：build() 包装 UdpChainRouter 前从 bridge 抽出（None = 无
        // chain-UDP 桥——udp/chain 未同启或本机 client 桥未构建）
        let mut udp_client_metrics: Option<Arc<UdpClientMetrics>> = None;
        // P0-5 §1.3：per-ingress Some(true) 在全局关时仍要可用——构建条件从
        //「全局 enabled」放宽为「全局 ∨ 任一入口显式开」；服务实例仍全局单例。
        // T3 §2.2：TUN 入口的 UDP NAT 面同用 UdpAssociateService 的连接器族——
        // tun_enabled 时 UDP 块必建（clone 连接器给 TunIngress）。
        let udp_needed = config_snapshot.udp.enabled
            || tun_enabled
            || config_snapshot.ingress.iter().any(|d| {
                matches!(
                    &d.spec,
                    IngressConfig::Socks5 {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Mixed {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Shadowsocks {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Trojan {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Vless {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Vmess {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Hysteria2 {
                        udp_enabled: Some(true),
                        ..
                    } | IngressConfig::Hysteria {
                        udp_enabled: Some(true),
                        ..
                    }
                )
            });
        let udp_service = if udp_needed {
            let udp_connectors = build_udp_connectors(
                &config_snapshot.egress,
                transport_pool.clone(),
                tls_factory.clone(),
            )?;
            scan_udp_capability(
                &config_snapshot.routing,
                &config_snapshot.egress,
                &udp_connectors,
            )?;
            let routing_udp = rillane_core::udp::RoutingUdpConnector::new();
            for (node, connector) in udp_connectors {
                routing_udp.register(node, connector);
            }
            let chain_parts = match (&mesh_registry, &chain_manager, &local_node_id) {
                (Some(m), Some(c), Some(l)) if self.runtime_config.enable_chain => {
                    Some((Arc::clone(m), Arc::clone(c), l.clone()))
                }
                _ => None,
            };
            let flow_router: Arc<dyn FlowRouter> = match &chain_parts {
                Some((mesh, chain_mgr, local_id)) => Arc::new(RuntimeFlowRouter::new(
                    Arc::clone(&router),
                    Arc::clone(mesh),
                    Arc::clone(chain_mgr),
                    local_id.clone(),
                )),
                None => Arc::clone(&router) as Arc<dyn FlowRouter>,
            };
            let chain_enabled = chain_parts.is_some();
            let connector: Arc<dyn EgressUdpConnector> = match chain_parts {
                Some((mesh, _chain_mgr, local_id)) => {
                    // §13-6 合流：cfg.udp_allow_plaintext_data_plane ∪ env，build() 求值一次
                    let env_gate = MeshUdpGate::from_env();
                    let allow = self
                        .runtime_config
                        .mesh_config
                        .as_ref()
                        .is_some_and(|c| c.udp_allow_plaintext_data_plane)
                        || env_gate.allow_plaintext;
                    let gate = MeshUdpGate::new(allow);
                    let bridge = MeshUdpBridge::new(
                        local_id,
                        mesh,
                        self.runtime_config
                            .mesh_config
                            .as_ref()
                            .and_then(|c| c.data_plane_tls.as_ref()),
                        &gate,
                    )?;
                    // P0-5 §4 观测接缝③：包装 UdpChainRouter 前抽出进程级 client 计数
                    udp_client_metrics = Some(bridge.client_metrics());
                    mesh_udp_gate = Some(gate);
                    Arc::new(UdpChainRouter::new(routing_udp, Some(bridge)))
                }
                None => Arc::new(routing_udp),
            };
            let table = rillane_core::udp::UdpSessionTable::new(
                udp_session_config(&config_snapshot.udp),
                flow_router,
                rillane_core::udp::RealClock::new(),
            )?;
            if chain_enabled {
                let (tx, rx) = mpsc::channel::<ChainFailureEvent>(256);
                table.attach_chain_events(rx);
                chain_failure_tx = Some(tx);
            }
            // TUN UDP 面与 socks5 UDP 面共用同一出站连接器（tun-dataplane.md
            // §2.2；TUN 流不注册进 UdpSessionTable——流表自治，§2.6）
            if tun_enabled {
                tun_udp_connector = Some(Arc::clone(&connector));
            }
            Some(rillane_core::udp::UdpAssociateService::new(
                table,
                connector,
                config_snapshot.udp.strict_udp_source,
                // P0-5 §1.2：S0 落地的配置字段（S1 签名变更连带接线，S2 再提纯映射）
                config_snapshot.udp.max_associates,
                // G1-10 UDP 面：池段假地址 target 反查域名回填（池表随 DNS
                // 服务装配；None = 未启用，存量零差异）
                dns_service.as_ref().and_then(|d| d.fake_ip()),
            ))
        } else {
            None
        };

        // 入口默认实现（udp_service 唯一消费点，随 UDP 块顺延至此）。
        // fake-ip 池表随 DNS 服务传递：入口面用它把池段假地址反查回原域名
        // （G1-10 出站 target 回填）。
        if self.ingress_endpoints.is_empty() {
            let fake_ip_table = dns_service.as_ref().and_then(|d| d.fake_ip());
            self.ingress_endpoints = build_ingress_endpoints(
                &config_snapshot.ingress,
                udp_service.clone(),
                config_snapshot.udp.enabled,
                fake_ip_table,
            )?;
        }

        // TUN 入口（tun-dataplane.md §2.6/§2.7）：TunIngress 属主化设备+系统
        // 路由（Tun 模式下 NetworkManager 已让位，见上）；与 socks5 等入口并列
        // 注入同一 FlowRouter（start() ingress 循环统一 spawn run()）。
        // 注：validate() 允许 TUN-only（network.mode=tun 豁免空 ingress，
        // tun-dataplane.md「TUN-only 独立启动」；TUN 与 socks5 并存仍为典型
        // 形态）。Linux 门控（platform-packaging.md：TUN 数据面 Linux-only）——非 Linux
        // 编译单元配置了 TUN 显式 Err，未配置恒 None（口径同 network 四工厂）。
        #[cfg(target_os = "linux")]
        let tun_ingress = match (tun_enabled, tun_udp_connector) {
            (true, Some(connector)) => {
                let network_cfg = self
                    .runtime_config
                    .network_config
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "tun_enabled 但 network_config 缺失（内部不变式破坏，应经 derive_runtime_config 一致构造）"
                        )
                    })?;
                // §2.7 auto-bypass 字面量半边：egress 字面量地址 + mesh listen +
                // control.api_bind。域名 server 不在构建期解析（DNS 副作用），
                // 归 TunIngress::run() 起始处（auto_bypass_hosts）
                let mut auto_bypass_literals = Vec::new();
                let mut auto_bypass_hosts = Vec::new();
                for egress in &config_snapshot.egress {
                    if let Some(host) = egress_server_host(&egress.spec) {
                        match host.parse::<IpAddr>() {
                            Ok(ip) => auto_bypass_literals.push(RouteDestination::host(ip)),
                            Err(_) => auto_bypass_hosts.push(host.to_string()),
                        }
                    }
                }
                if self.runtime_config.enable_mesh {
                    if let Some(mesh_cfg) = &self.runtime_config.mesh_config {
                        auto_bypass_literals
                            .push(RouteDestination::host(mesh_cfg.listen_address.ip()));
                    }
                }
                if let Ok(api) = config_snapshot.control.api_bind.parse::<SocketAddr>() {
                    auto_bypass_literals.push(RouteDestination::host(api.ip()));
                }
                let t = Arc::new(TunIngress::new(
                    TunIngressConfig {
                        tun: network_cfg.tun.clone().unwrap_or_default(),
                        routing: network_cfg.routing.clone().unwrap_or_default(),
                        // RIL-143：有界嗅探策略取自原始 network 块（与
                        // network_block_to_platform 同源同代际；None = 按需
                        // 缺省零差异）
                        sniff: config_snapshot
                            .network
                            .as_ref()
                            .and_then(|n| n.sniff.clone())
                            .unwrap_or_default(),
                        // §2.5：Process 规则在场才做 /proc 归因扫描
                        has_process_rules: config_snapshot.routing.rules.iter().any(|r| {
                            r.matches
                                .iter()
                                .any(|m| matches!(m, MatchCondition::Process { .. }))
                        }),
                        auto_bypass_literals,
                        auto_bypass_hosts,
                        ..TunIngressConfig::default()
                    },
                    connector,
                ));
                self.ingress_endpoints.insert("tun".to_string(), t.clone());
                Some(t)
            }
            _ => None,
        };
        #[cfg(not(target_os = "linux"))]
        let () = {
            let _ = tun_udp_connector;
            anyhow::ensure!(
                !tun_enabled,
                "TUN 面仅 Linux 支持（tun-dataplane.md；Windows/macOS 打包面见 platform-packaging.md §6）"
            );
        };

        let subscription_manager = if self.runtime_config.enable_hot_reload {
            Some(Arc::new(SubscriptionManager::new()))
        } else {
            None
        };

        let (event_tx, _event_rx) = broadcast::channel(1024);

        Ok(Runtime {
            config,
            runtime_config: self.runtime_config,
            router,
            local_node_id,
            ingress_endpoints: self.ingress_endpoints,
            flow_outputs: Arc::new(RwLock::new(self.flow_outputs)),
            egress_connectors: Arc::new(RwLock::new(self.egress_connectors)),
            flow_stats: Arc::new(DashMap::new()),
            // RIL-052/055：诊断采集器（有界默认：1024 迹/256 活动/256 事件/
            // 1h TTL/全采 1/启用）——RIL-064 做开销与留存对照后如需调整，
            // 改这里一处
            trace_collector: Arc::new(std::sync::Mutex::new(
                rillane_core::collector::FlowCollector::new(
                    rillane_core::collector::CollectorConfig::new(
                        1024, 256, 256, 3_600_000, 1, true,
                    )
                    .expect("诊断采集器有界默认配置合法"),
                ),
            )),
            mesh_registry,
            chain_manager,
            chain_failure_tx,
            mesh_udp_gate,
            // P1-4 §1.2：静态混淆链（start() 构造 FlowOutputRouter 时消费）
            middleware_chain,
            // P0-5 §4 观测接缝①：控制面 /udp/stats 经 getter 取数（勘误：
            // 设计稿称「Runtime.udp 字段已存在」，实况 P0-2 起即被消费进
            // ingress_endpoints、Runtime 无此字段——本字段为 S2 新增留存）
            udp_service,
            // P0-5 §4 观测接缝②③：mesh 面 OnceLock（start 回填）+ client 计数
            mesh_plane: OnceLock::new(),
            udp_client_metrics,
            transport_pool,
            tls_factory,
            network_manager,
            #[cfg(target_os = "linux")]
            tun_ingress,
            dns_service,
            #[cfg(feature = "plugins")]
            plugin_middlewares,
            subscription_manager,
            event_tx,
            stats: Arc::new(RwLock::new(RuntimeStats::new())),
            running: Arc::new(RwLock::new(false)),
            config_apply_lock: Arc::new(tokio::sync::Mutex::new(())),
            source_owned,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.config.ingress.is_empty() {
            // TUN-only 启动放行（tun-dataplane.md「TUN-only 独立启动」后续项，
            // 2026-10-05 兑现）：network.mode=tun 且启用网络虚拟化时 TUN 即入口
            // （build() 后段注入 ingress_endpoints["tun"]，start() 同一循环
            // spawn——无常规入口特判）；其余空 ingress 维持拒绝
            let tun_only = self.runtime_config.enable_network_virtualization
                && self
                    .runtime_config
                    .network_config
                    .as_ref()
                    .is_some_and(|n| n.mode == NetworkMode::Tun);
            if !tun_only {
                return Err(anyhow!(
                    "至少需要配置一个入口（仅 network.mode=tun 可豁免：TUN 即入口）"
                ));
            }
        }
        if self.config.egress.is_empty() {
            return Err(anyhow!("至少需要配置一个出口"));
        }
        if self.runtime_config.enable_mesh {
            if let Some(mesh_cfg) = &self.runtime_config.mesh_config {
                if mesh_cfg.node_id.trim().is_empty() {
                    return Err(anyhow!("Mesh 节点 ID 不能为空"));
                }
            }
        }
        Ok(())
    }
}

/// 运行时配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub enable_mesh: bool,
    pub enable_network_virtualization: bool,
    pub enable_hot_reload: bool,
    /// 启用多跳链路支持
    pub enable_chain: bool,
    pub mesh_config: Option<MeshConfig>,
    pub network_config: Option<NetworkConfig>,
    /// 链路配置
    pub chain_config: Option<ChainConfig>,
    pub worker_threads: Option<usize>,
    pub connection_pool_size: Option<usize>,
    pub session_timeout: Option<Duration>,
    pub heartbeat_interval: Option<Duration>,
    pub stats_interval: Option<Duration>,
    /// 订阅检查间隔（用于 enable_hot_reload 的自动刷新与应用）
    pub subscription_check_interval: Option<Duration>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            enable_mesh: false,
            enable_network_virtualization: false,
            enable_hot_reload: true,
            enable_chain: false,
            mesh_config: None,
            network_config: None,
            chain_config: None,
            worker_threads: Some(num_cpus::get()),
            connection_pool_size: Some(1024),
            session_timeout: Some(Duration::from_secs(300)),
            heartbeat_interval: Some(Duration::from_secs(30)),
            stats_interval: Some(Duration::from_secs(60)),
            subscription_check_interval: Some(Duration::from_secs(30)),
        }
    }
}

/// Mesh 节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub node_id: String,
    pub role: String,
    pub listen_address: SocketAddr,
    /// Mesh data-plane mTLS（用于 hop-by-hop 转发加密与认证）
    #[serde(default)]
    pub data_plane_tls: Option<MeshTlsConfig>,
    /// Dev-only: allow plaintext mesh data-plane even when chain is enabled.
    #[serde(default)]
    pub allow_plaintext_data_plane: bool,
    /// Dev-only: allow plaintext mesh UDP face（P0-4 §13-6：cfg 侧开关，与
    /// `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` env 在 build() 合流求值一次）。
    #[serde(default)]
    pub udp_allow_plaintext_data_plane: bool,
    /// Dev-only: allow TLS without client auth even when chain is enabled.
    #[serde(default)]
    pub allow_no_client_auth: bool,
    pub topology_update_interval: Duration,
    pub health_check_interval: Duration,
    pub max_sessions: Option<usize>,
    pub enabled_features: Vec<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            node_id: whoami::fallible::hostname().unwrap_or_else(|_| "rillane-node".to_string()),
            role: "client".into(),
            listen_address: "0.0.0.0:9091".parse().unwrap(),
            data_plane_tls: MeshTlsConfig::from_env(),
            allow_plaintext_data_plane: false,
            udp_allow_plaintext_data_plane: false,
            allow_no_client_auth: false,
            topology_update_interval: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(60),
            max_sessions: Some(10_000),
            enabled_features: vec!["relay".into(), "exit".into()],
        }
    }
}

/// 运行时事件
#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    ConfigUpdated {
        config: Box<RillaneConfig>,
    },
    MeshEvent {
        session_id: SessionId,
        event: MeshEventType,
    },
    NetworkEvent {
        event_type: NetworkEventType,
        details: String,
    },
    SubscriptionEvent {
        subscription_name: String,
        event: SubscriptionEventType,
    },
    TelemetryEvent {
        metric_name: String,
        value: f64,
        tags: HashMap<String, String>,
    },
    Error {
        source: String,
        error: String,
        context: HashMap<String, String>,
    },
}

#[derive(Debug, Clone)]
pub enum MeshEventType {
    NodeRegistered {
        node_id: NodeId,
    },
    NodeOffline {
        node_id: NodeId,
    },
    SessionCreated {
        session: MeshSession,
    },
    SessionEnded {
        session_id: SessionId,
        reason: String,
    },
    PathUpdated {
        session_id: SessionId,
        path: Vec<NodeId>,
    },
}

#[derive(Debug, Clone)]
pub enum NetworkEventType {
    InterfaceCreated { name: String },
    InterfaceDestroyed { name: String },
    InterfaceUp { name: String },
    InterfaceDown { name: String },
    RouteUpdated { action: String },
    PacketFiltered { rule_name: String },
}

#[derive(Debug, Clone)]
pub enum SubscriptionEventType {
    Added { node_count: usize },
    Removed { name: String },
    Updated { name: String, changes: Vec<String> },
    Refreshed { name: String, status: String },
    Error { name: String, error: String },
}

/// 运行时统计
#[derive(Debug, Clone)]
pub struct RuntimeStats {
    pub started_at: Instant,
    pub uptime_seconds: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_bytes_transferred: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub mesh_nodes: usize,
    pub mesh_sessions: usize,
    pub network_interfaces: usize,
    pub subscription_nodes: usize,
    pub error_count: u64,
    pub last_updated: Instant,
}

impl Default for RuntimeStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeStats {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            uptime_seconds: 0,
            total_connections: 0,
            active_connections: 0,
            total_bytes_transferred: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            mesh_nodes: 0,
            mesh_sessions: 0,
            network_interfaces: 0,
            subscription_nodes: 0,
            error_count: 0,
            last_updated: Instant::now(),
        }
    }

    pub fn update(&mut self) {
        self.uptime_seconds = self.started_at.elapsed().as_secs();
        self.last_updated = Instant::now();
    }
}

/// 配置合并统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMergeStats {
    pub nodes_added: usize,
    pub groups_added: usize,
    pub rules_added: usize,
    /// 同名规则被新版本原位替换的条数（RIL-008：重复刷新替换不追加）
    pub rules_updated: usize,
    /// 同名节点被新版本原位替换的条数（订阅节点内容更新语义）
    pub nodes_updated: usize,
    /// 同名组被新版本原位替换的条数
    pub groups_updated: usize,
}

/// RIL-016 来源命名空间：单一来源在配置里持有的对象名集（egress /
/// groups / rules 三个合并面各一份）。构建期配置登记在
/// [`LOCAL_SOURCE`] 名下——本地优先级的登记底座。
#[derive(Debug, Clone, Default)]
pub struct SourceOwnedNames {
    pub egress: std::collections::HashSet<String>,
    pub groups: std::collections::HashSet<String>,
    pub rules: std::collections::HashSet<String>,
}

/// 构建期配置的保留来源名：用户手写面（游戏规则、监听口、系统路由、
/// 插件、凭证所在的整份启动配置）。来源增量永不触碰此名下对象。
pub const LOCAL_SOURCE: &str = "local";

/// RIL-016 来源作用域合并统计。added/updated 语义同 [`ConfigMergeStats`]；
/// `skipped_foreign` 是「名下登记属于 local 或其它来源」被拒触碰的条数
/// （刷新不覆盖用户游戏规则/其它订阅对象）；`*_stale` 是本来源名下但
/// 本次载荷缺席的对象数（只计数不删除——删除策略归配置发布协调器
/// RIL-019，提前删除会悬空用户规则对组名的引用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMergeStats {
    pub nodes_added: usize,
    pub nodes_updated: usize,
    pub groups_added: usize,
    pub groups_updated: usize,
    pub rules_added: usize,
    pub rules_updated: usize,
    pub nodes_skipped_foreign: usize,
    pub groups_skipped_foreign: usize,
    pub rules_skipped_foreign: usize,
    pub nodes_stale: usize,
    pub groups_stale: usize,
    pub rules_stale: usize,
}

/// Runtime 实例
pub struct Runtime {
    config: Arc<RwLock<RillaneConfig>>,
    runtime_config: RuntimeConfig,
    router: Arc<RoutingEngine>,
    local_node_id: Option<NodeId>,
    ingress_endpoints: HashMap<String, Arc<dyn IngressEndpoint>>,
    flow_outputs: Arc<RwLock<HashMap<String, Arc<dyn FlowOutput>>>>,
    egress_connectors: Arc<RwLock<HashMap<String, Arc<dyn EgressConnector>>>>,
    flow_stats: Arc<DashMap<(String, String), FlowStatCounter>>,
    mesh_registry: Option<Arc<MeshRegistry>>,
    /// 链路管理器（多跳链路支持）
    chain_manager: Option<Arc<ChainManager>>,
    /// P0-4 §8：链路故障事件 → UDP 会话表（FlowOutputRouter 故障切换成功后发送；
    /// None = udp/chain 未同启，零接线）
    chain_failure_tx: Option<mpsc::Sender<ChainFailureEvent>>,
    /// P0-4 §13-6：folded UDP 明文门（chain+udp 同启时 Some；两消费点同源——
    /// client 桥在 build() 已消费，非 client 的 spawn_udp 在 start() 消费）
    mesh_udp_gate: Option<MeshUdpGate>,
    /// P1-4 §1.2：静态混淆 middleware 链（start() 构造 FlowOutputRouter 时
    /// 消费；关闭态 = 空链，§2.5）
    middleware_chain: MiddlewareChain,
    /// P0-5 §4 观测接缝①：UDP 入站服务留存（控制面 /udp/stats 取数；
    /// ingress_endpoints 内共享同一 Arc 单例）
    udp_service: Option<Arc<rillane_core::udp::UdpAssociateService>>,
    /// P0-5 §4 观测接缝②：mesh UDP 面（start() 在 spawn_udp 后回填，恰好一次、
    /// 观测只读——不引入 ArcSwap；client-only runtime 永远 None）
    mesh_plane: OnceLock<Arc<MeshDataPlane>>,
    /// P0-5 §4 观测接缝③：client 出站侧进程级计数（build() 从 bridge 抽出）
    udp_client_metrics: Option<Arc<UdpClientMetrics>>,
    /// P1-5 §4.1：出站连接池单例（D-10 跨热更新共享；None = 块缺席/未启用）
    transport_pool: Option<Arc<TransportPool>>,
    /// RIL-052/055：诊断事件采集器单例（控制面 /trace/* 查询面取数；
    /// 有界配置在 build 钉死——容量/上限/TTL 见 trace_collector_config）。
    /// 会话执行面的 SessionTracer 接线随数据面装配推进；此前列表恒空
    /// 属诚实空态（查询面回答 tracing 启用状态而非伪造活动流）。
    trace_collector: Arc<std::sync::Mutex<rillane_core::collector::FlowCollector>>,
    /// P1-5 §4.1：TLS 连接器工厂单例（tls_resumption 独立于池生效）
    tls_factory: Option<Arc<TlsConnectorFactory>>,
    network_manager: Option<Arc<Mutex<NetworkManager>>>,
    /// TUN 入口单例（tun-dataplane.md §2.6；None = 未启用/非 Tun 模式）。
    /// ingress_endpoints 内共享同一 Arc——本字段供 stop() 优雅关停与
    /// 控制面指标取数（T5）定向寻址。Linux 门控（platform-packaging.md）
    #[cfg(target_os = "linux")]
    tun_ingress: Option<Arc<TunIngress>>,
    /// P2-8 M1 观测接缝：DNS 分流服务单例（start/stop 消费 + 控制面
    /// /dns/stats 经 getter 取数；None = network.dns 块缺席/关闭）
    dns_service: Option<Arc<crate::dns_config::DnsService>>,
    /// 观测轮（plugin-loader.md §0 计数面）：插件具体类型句柄旁路（控制面
    /// /plugins/stats 经 getter 取数；空 = obfs 未启用/无 plugins 声明；
    /// RIL-040 small 档无此面）
    #[cfg(feature = "plugins")]
    plugin_middlewares: Vec<Arc<rillane_plugins::WasmPluginMiddleware>>,
    subscription_manager: Option<Arc<SubscriptionManager>>,
    event_tx: broadcast::Sender<RuntimeEvent>,
    stats: Arc<RwLock<RuntimeStats>>,
    running: Arc<RwLock<bool>>,
    /// P2（2026-11-03）：配置热交换串行锁。update_config / merge_config_delta /
    /// 订阅刷新循环三方共用，覆盖「读 config → 构建 egress → 落四态」全程。
    /// 曾为 check-then-act——并发 apply 交错即丢失更新（见 update_config 注释）。
    config_apply_lock: Arc<tokio::sync::Mutex<()>>,
    /// RIL-016 本地策略所有权：来源→对象名登记簿。「local」= 构建期
    /// 配置；来源刷新只替换/新增自己名下的对象，local 与他来源名下
    /// 永不触碰（监听口/系统路由/插件/凭证根本不在合并面）。
    source_owned: Arc<DashMap<String, SourceOwnedNames>>,
}

impl Runtime {
    /// 阻塞运行直到所有子任务结束
    pub async fn run(self) -> Result<()> {
        let handles = self.start().await?;
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(join_err) => {
                    return Err(anyhow!("runtime task panicked: {}", join_err));
                }
            }
        }
        Ok(())
    }

    /// 启动所有后台任务
    pub async fn start(&self) -> Result<Vec<JoinHandle<Result<()>>>> {
        let mut tasks = Vec::new();
        *self.running.write().expect("running lock poisoned") = true;

        // P1-5 §4.1 装配尾：warm（D-7，配置内 TLS 出站逐键预拨）+ 周期
        // sweeper。池单例在 build() 构造；后台任务在此挂载（build() 无
        // tokio 上下文约束）。warm 是优化不是前置条件——prewarm 内部即
        // spawn 后台填充，失败退避不阻塞启动。
        if let Some(pool) = &self.transport_pool {
            let egress = self
                .config
                .read()
                .expect("config lock poisoned")
                .egress
                .clone();
            for key in derive_tls_warm_keys(&egress)? {
                pool.prewarm(&key, pool.policy().max_idle_per_key);
            }
            pool.spawn_sweeper();
        }

        // 创建流量输出路由器（支持多跳链路）
        let mesh_tls = self
            .runtime_config
            .mesh_config
            .as_ref()
            .and_then(|c| c.data_plane_tls.clone());
        let output_router = Arc::new(FlowOutputRouter::new(
            self.flow_outputs.clone(),
            self.chain_manager.clone(),
            self.mesh_registry.clone(),
            self.local_node_id.clone(),
            mesh_tls,
            self.event_tx.clone(),
            self.chain_failure_tx.clone(),
            self.middleware_chain.clone(),
        ));

        // Spawn mesh data-plane listener (TCP) for multi-hop transport (requires chain feature).
        if self.runtime_config.enable_chain {
            if let (Some(mesh), Some(local_id), Some(mesh_cfg)) = (
                self.mesh_registry.clone(),
                self.local_node_id.clone(),
                self.runtime_config.mesh_config.clone(),
            ) {
                use rillane_mesh::NodeRole;

                let local_role = mesh
                    .get_node(&local_id)
                    .map(|r| r.role)
                    .unwrap_or(NodeRole::Client);
                if local_role != NodeRole::Client {
                    let plane = MeshDataPlane::new(local_id, mesh)
                        .with_tls(mesh_cfg.data_plane_tls.clone())?;
                    // P0-4 §9.2/S5：chain+udp 同启时并列 UDP 面（同端口双栈）。
                    // gate 已在 build() 前置检查（§13-6 合流值存 mesh_udp_gate，
                    // 此处消费同一实例）；ttl 接 udp.mapping_idle_secs（§3），上界走 R10 默认。
                    let plane = match &self.mesh_udp_gate {
                        Some(gate) => {
                            let ttl = Duration::from_secs(
                                self.config
                                    .read()
                                    .expect("config lock poisoned")
                                    .udp
                                    .mapping_idle_secs,
                            );
                            plane.with_udp_limits(gate.clone(), ttl, UDP_FACE_DEFAULT_MAX)?
                        }
                        None => plane,
                    };
                    let plane = Arc::new(plane);
                    tasks.push(Arc::clone(&plane).spawn(mesh_cfg.listen_address));
                    if self.mesh_udp_gate.is_some() {
                        tasks.push(Arc::clone(&plane).spawn_udp(mesh_cfg.listen_address));
                        // P0-5 §4 观测接缝②：spawn_udp 后回填（恰好一次——二次
                        // start 保持首面，观测只读；client-only 无面路径不触达此处）
                        let _ = self.mesh_plane.set(Arc::clone(&plane));
                    }
                } else {
                    tracing::info!(
                        target: "rillane::mesh::transport",
                        node = %local_id,
                        "mesh chain is enabled but local role is client; skip data-plane listener"
                    );
                }
            }
        }

        for (name, endpoint) in self.ingress_endpoints.iter() {
            let router = self.flow_router();
            let output: Arc<dyn FlowOutput> = Arc::new(StatsFlowOutput::new(
                name.clone(),
                output_router.clone(),
                self.flow_stats.clone(),
            ));
            let ingress = endpoint.clone();
            let label = name.clone();
            tasks.push(tokio::spawn(async move {
                ingress
                    .run(router, output)
                    .await
                    .map_err(|e| anyhow!("入口 {label} 异常退出: {e}"))
            }));
        }

        if let Some(manager) = &self.network_manager {
            let mgr = manager.clone();
            tasks.push(tokio::spawn(async move {
                let mut guard = mgr.lock().await;
                guard.start().await
            }));
        }

        // P2-8 M1：本地 DNS 监听（bind 失败在任务内浮出 → rt_task 呈现）
        if let Some(dns) = &self.dns_service {
            let dns = dns.clone();
            tasks.push(tokio::spawn(async move { dns.start().await }));
        }

        if let Some(mesh) = &self.mesh_registry {
            let registry = mesh.clone();
            let tx = self.event_tx.clone();
            let running = self.running.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker = time::interval(Duration::from_secs(10));
                while *running.read().expect("running lock poisoned") {
                    ticker.tick().await;
                    let stats = registry.get_stats();
                    let _ = tx.send(RuntimeEvent::TelemetryEvent {
                        metric_name: "mesh_nodes".into(),
                        value: stats.total_nodes as f64,
                        tags: HashMap::new(),
                    });
                }
                Ok::<(), anyhow::Error>(())
            }));
        }

        // Subscription auto-refresh + apply loop.
        if self.runtime_config.enable_hot_reload {
            if let Some(sub_mgr) = &self.subscription_manager {
                let sub_mgr = sub_mgr.clone();
                let config = self.config.clone();
                let router = self.router.clone();
                let flow_outputs = self.flow_outputs.clone();
                let egress_connectors = self.egress_connectors.clone();
                // D-10：池/工厂单例句柄（订阅热更新重连装配用）
                let transport_pool = self.transport_pool.clone();
                let tls_factory = self.tls_factory.clone();
                // P2（2026-11-03）：与 update_config / merge_config_delta 共用
                // 同一把热交换串行锁（config_apply_lock）。
                let config_apply_lock = self.config_apply_lock.clone();
                let tx = self.event_tx.clone();
                let running = self.running.clone();
                let check_interval = self
                    .runtime_config
                    .subscription_check_interval
                    .unwrap_or(Duration::from_secs(30));

                tasks.push(tokio::spawn(async move {
                    let converter = SubscriptionConverter::new();
                    let mut ticker = time::interval(check_interval);
                    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

                    while *running.read().expect("running lock poisoned") {
                        ticker.tick().await;

                        let names_to_refresh: Vec<String> = sub_mgr
                            .list_subscriptions()
                            .into_iter()
                            .filter(|s| s.needs_refresh())
                            .map(|s| s.name)
                            .collect();

                        if names_to_refresh.is_empty() {
                            continue;
                        }

                        for name in names_to_refresh {
                            let old_hash = sub_mgr
                                .get_subscription(&name)
                                .and_then(|s| s.content_hash.clone());

                            let content = match sub_mgr.refresh_subscription(&name).await {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                        subscription_name: name.clone(),
                                        event: SubscriptionEventType::Error {
                                            name: name.clone(),
                                            error: e.to_string(),
                                        },
                                    });
                                    continue;
                                }
                            };

                            let new_hash = sub_mgr
                                .get_subscription(&name)
                                .and_then(|s| s.content_hash.clone());

                            let changed = new_hash != old_hash;
                            let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                subscription_name: name.clone(),
                                event: SubscriptionEventType::Refreshed {
                                    name: name.clone(),
                                    status: if changed {
                                        "changed".to_string()
                                    } else {
                                        "not_modified".to_string()
                                    },
                                },
                            });

                            if !changed {
                                continue;
                            }

                            let Some(sub) = sub_mgr.get_subscription(&name) else {
                                continue;
                            };

                            let converted = match converter.auto_convert(&sub, &content).await {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                        subscription_name: name.clone(),
                                        event: SubscriptionEventType::Error {
                                            name: name.clone(),
                                            error: format!("convert failed: {e}"),
                                        },
                                    });
                                    continue;
                                }
                            };

                            // Merge and apply.
                            // P2（2026-11-03）：与 update_config / merge_config_delta
                            // 共用 config_apply_lock——曾读在锁外（config.read 在
                            // 下方），并发 apply 交错丢失更新。锁覆盖
                            // 读→合并→构建→落四态 全程（continue 分支随作用域放锁）。
                            let _apply_guard = config_apply_lock.lock().await;
                            let mut merged = config.read().expect("config lock poisoned").clone();
                            let merge_stats =
                                merge_config_delta_in_place(&mut merged, &converted.config);

                            // D-10：传同一池/工厂句柄重连装配（不重建单例）
                            let (outputs, connectors) = match build_egress_outputs(
                                &merged.egress,
                                transport_pool.clone(),
                                tls_factory.clone(),
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                        subscription_name: name.clone(),
                                        event: SubscriptionEventType::Error {
                                            name: name.clone(),
                                            error: format!("build egress failed: {e}"),
                                        },
                                    });
                                    continue;
                                }
                            };

                            // 写序同 apply_config_inner：先装 egress 面、再 reload
                            // 路由、最后落 config 快照（避免规则引用未就绪名）。
                            // 反向残余同 apply_config_inner 注：outputs/connectors
                            // 替换后、router.reload 前旧规则可解析到已删 egress 名
                            // （瞬时微秒级，多状态非原子交换固有残余，已登记）。
                            *flow_outputs.write().expect("flow_outputs lock poisoned") = outputs;
                            *egress_connectors
                                .write()
                                .expect("egress_connectors lock poisoned") = connectors;
                            router.reload(merged.routing.clone());
                            *config.write().expect("config lock poisoned") = merged.clone();
                            let _ = tx.send(RuntimeEvent::ConfigUpdated {
                                config: Box::new(merged),
                            });

                            let changes = vec![
                                format!("nodes_added={}", merge_stats.nodes_added),
                                format!("groups_added={}", merge_stats.groups_added),
                                format!("rules_added={}", merge_stats.rules_added),
                            ];
                            let _ = tx.send(RuntimeEvent::SubscriptionEvent {
                                subscription_name: name.clone(),
                                event: SubscriptionEventType::Updated {
                                    name: name.clone(),
                                    changes,
                                },
                            });
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                }));
            }
        }

        // 启动链路管理器健康检查任务
        if let Some(chain_mgr) = &self.chain_manager {
            let mgr = chain_mgr.clone();
            let tx = self.event_tx.clone();
            let running = self.running.clone();
            tasks.push(tokio::spawn(async move {
                let mgr_clone = mgr.clone();
                tokio::spawn(async move {
                    mgr_clone.start_health_check_task().await;
                });

                // P2-2 §2 D-5：SLO 劣化 watcher（config.slo_watch 未配置时
                // 首轮即返，零开销）
                let mgr_slo = mgr.clone();
                tokio::spawn(async move {
                    mgr_slo.start_slo_watch_task().await;
                });

                // 定期报告链路统计
                let mut ticker = time::interval(Duration::from_secs(30));
                while *running.read().expect("running lock poisoned") {
                    ticker.tick().await;
                    let stats = mgr.get_stats().await;
                    let _ = tx.send(RuntimeEvent::TelemetryEvent {
                        metric_name: "chain_active_count".into(),
                        value: stats.active_chains as f64,
                        tags: HashMap::new(),
                    });
                    let _ = tx.send(RuntimeEvent::TelemetryEvent {
                        metric_name: "chain_failover_count".into(),
                        value: stats.failover_count as f64,
                        tags: HashMap::new(),
                    });
                }
                Ok::<(), anyhow::Error>(())
            }));
        }

        // G1-9 审核发现（2026-11-10）：url-test 周期探活任务此前从未在运行时
        // 启动——`RoutingEngine::start_health_check_task`（rillane-routing
        // lib.rs:437）在 start() 任务区无调用点，仅 ChainManager 健康任务与
        // mesh→routing 质量桥被 spawn；探测句柄虽在 build 期注入
        // （set_probe_handler），url_test 组运行时永不周期探活，健康/延迟表
        // 恒空、组退化默认健康兜底。此处为唯一启动点（detached 内层同
        // ChainManager 健康任务模式：运行期守护，shutdown 由 runtime drop
        // 收回；外层 running 门控随停止信号退出）。
        {
            let router = self.router.clone();
            let running = self.running.clone();
            tasks.push(tokio::spawn(async move {
                let router = router.clone();
                tokio::spawn(async move {
                    router.start_health_check_task().await;
                });
                while *running.read().expect("running lock poisoned") {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok::<(), anyhow::Error>(())
            }));
        }

        // P2-2 §4：mesh→routing 质量桥（D-4）——周期聚合 MeshRegistry 链路
        // 质量（节点 p95 = 相邻链路最差跳 max；loss = Σerrors/Σconnections）
        // 推进组策略（rillane-routing 零 rillane-mesh 依赖，数据推进式）。10s 周期
        // 同 routing 健康巡检节奏。
        if let Some(registry) = &self.mesh_registry {
            let registry = registry.clone();
            let router = self.router.clone();
            let running = self.running.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker = time::interval(Duration::from_secs(10));
                while *running.read().expect("running lock poisoned") {
                    ticker.tick().await;
                    for (node, p95, loss) in aggregate_link_quality(&registry) {
                        router.update_link_quality(&node, p95, loss);
                    }
                }
                Ok::<(), anyhow::Error>(())
            }));
        }

        let stats = self.stats.clone();
        let tx = self.event_tx.clone();
        let flow_stats = self.flow_stats.clone();
        let config = self.config.clone();
        let mesh_registry = self.mesh_registry.clone();
        let subscription_manager = self.subscription_manager.clone();
        let network_manager = self.network_manager.clone();
        let running = self.running.clone();

        // RIL-064：诊断轨迹 TTL 清扫——「历史可过期」在生产装配的兑现
        // 点（读路径不清账：无人读也不许滞留到天荒地老；容量兜底之外
        // 再加时间界）。60s 周期、错过 tick 跳过——清扫是尽力而为的
        // 维护面，不追账不阻塞。
        {
            let collector = self.trace_collector.clone();
            let running = self.running.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker = time::interval(Duration::from_secs(60));
                ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    if !*running.read().expect("running lock poisoned") {
                        break;
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis() as u64);
                    collector
                        .lock()
                        .expect("trace collector poisoned")
                        .sweep(now);
                }
                Ok::<(), anyhow::Error>(())
            }));
        }
        let stats_interval = self
            .runtime_config
            .stats_interval
            .unwrap_or(Duration::from_secs(60));
        tasks.push(tokio::spawn(async move {
            let mut ticker = time::interval(stats_interval);
            loop {
                ticker.tick().await;

                if !*running.read().expect("running lock poisoned") {
                    break;
                }

                let mut total_connections: u64 = 0;
                let mut bytes_uploaded: u64 = 0;
                let mut bytes_downloaded: u64 = 0;
                for entry in flow_stats.iter() {
                    total_connections = total_connections.saturating_add(entry.value().flows);
                    bytes_uploaded = bytes_uploaded.saturating_add(entry.value().upstream);
                    bytes_downloaded = bytes_downloaded.saturating_add(entry.value().downstream);
                }
                let total_bytes_transferred = bytes_uploaded.saturating_add(bytes_downloaded);

                let (mesh_nodes, mesh_sessions) = match mesh_registry.as_ref() {
                    Some(mesh) => {
                        let s = mesh.get_stats();
                        (s.total_nodes, s.active_sessions)
                    }
                    None => (0, 0),
                };

                let subscription_nodes = match subscription_manager.as_ref() {
                    // 当前实现没有区分“订阅带来的节点”和静态配置节点：先暴露为当前 egress 总数，便于观测规模。
                    Some(_) => config.read().expect("config lock poisoned").egress.len(),
                    None => 0,
                };

                let network_interfaces = match network_manager.as_ref() {
                    Some(mgr) => {
                        let guard = mgr.lock().await;
                        if guard.is_running().await {
                            1
                        } else {
                            0
                        }
                    }
                    None => 0,
                };

                let mut guard = stats.write().expect("stats lock poisoned");
                guard.total_connections = total_connections;
                guard.active_connections = 0;
                guard.bytes_uploaded = bytes_uploaded;
                guard.bytes_downloaded = bytes_downloaded;
                guard.total_bytes_transferred = total_bytes_transferred;
                guard.mesh_nodes = mesh_nodes;
                guard.mesh_sessions = mesh_sessions;
                guard.network_interfaces = network_interfaces;
                guard.subscription_nodes = subscription_nodes;
                guard.update();
                let snapshot = guard.clone();
                drop(guard);
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_uptime".into(),
                    value: snapshot.uptime_seconds as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_total_connections".into(),
                    value: snapshot.total_connections as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_bytes_uploaded".into(),
                    value: snapshot.bytes_uploaded as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_bytes_downloaded".into(),
                    value: snapshot.bytes_downloaded as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_mesh_nodes".into(),
                    value: snapshot.mesh_nodes as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_mesh_sessions".into(),
                    value: snapshot.mesh_sessions as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_network_interfaces".into(),
                    value: snapshot.network_interfaces as f64,
                    tags: HashMap::new(),
                });
                let _ = tx.send(RuntimeEvent::TelemetryEvent {
                    metric_name: "runtime_subscription_nodes".into(),
                    value: snapshot.subscription_nodes as f64,
                    tags: HashMap::new(),
                });
            }

            Ok::<(), anyhow::Error>(())
        }));

        Ok(tasks)
    }

    /// 停止运行时
    pub async fn stop(&self) -> Result<()> {
        *self.running.write().expect("running lock poisoned") = false;
        if let Some(pool) = &self.transport_pool {
            pool.stop_sweeper();
        }
        // TUN 优雅关停：通知 run 循环 → teardown（路由回滚/设备销毁在
        // ingress 任务内完成，tun-dataplane.md §2.6）
        #[cfg(target_os = "linux")]
        if let Some(t) = &self.tun_ingress {
            t.shutdown();
        }
        if let Some(manager) = &self.network_manager {
            let mut guard = manager.lock().await;
            guard.stop().await.ok();
        }
        if let Some(dns) = &self.dns_service {
            if let Err(e) = dns.stop().await {
                tracing::warn!(target: "rillane::runtime", error = %e, "停止 DNS 服务失败");
            }
        }
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        *self.running.read().expect("running lock poisoned")
    }

    pub fn get_stats(&self) -> RuntimeStats {
        self.stats.read().expect("stats lock poisoned").clone()
    }

    pub fn get_config(&self) -> RillaneConfig {
        self.config.read().expect("config lock poisoned").clone()
    }

    /// 组实时质量报告（O-slo1 观测面：控制面 `/routing/stats` 取数；
    /// 口径见 rillane-routing `group_quality_report`）
    pub fn get_routing_quality(&self) -> Vec<rillane_routing::GroupQuality> {
        self.router.group_quality_report()
    }

    /// 纯路由推演（RIL-065 控制面 `/explain` 取数）：生产求值器 + 调用
    /// 时刻冻结的组快照（RIL-054）——无 DNS/拨号/OS 查询，无副作用；
    /// 输入校验错误（proto 非法等）由路由面原样上抛，控制面按稳定码
    /// 映射 400。
    pub fn explain_route(
        &self,
        input: &rillane_routing::ExplainInput,
    ) -> anyhow::Result<rillane_routing::RouteExplanation> {
        let snapshot = self.router.freeze_explain_snapshot();
        self.router.explain(&snapshot, input)
    }

    pub async fn update_config(&self, new_config: RillaneConfig) -> Result<()> {
        // P2（2026-11-03）：热交换串行化。曾为 check-then-act——读 config →
        // 长构建 → 四次独立写；并发 apply（控制面 PUT /runtime/config 与订阅
        // 刷新循环）交错即丢失更新，且 router.reload 先行引用尚未就绪的
        // egress 名。全程持 config_apply_lock（三方共用），写序见
        // apply_config_inner。
        let _apply_guard = self.config_apply_lock.lock().await;
        self.apply_config_inner(new_config).await
    }

    /// 应用新配置的私有实现。调用方必须已持 `config_apply_lock`。
    ///
    /// 写序：先装 egress 面（新 egress 名即刻可解析）→ reload 路由（新规则
    /// 不再引用未就绪名）→ 最后落 config 快照（纯读模型，供控制面诊断）。
    /// 原序 config→router→outputs→connectors 在 router.reload 与 outputs
    /// 落盘之间留「规则引用未就绪 egress 名」窗口。
    ///
    /// 反向残余（2026-11-03 P3 低，已登记）：outputs/connectors 整体替换后、
    /// `router.reload` 前，旧路由规则仍可解析到已被新 egress 集删除的名字，
    /// 该窗口内命中已删 egress 的在途流报「未知 egress」（瞬时微秒级）。此为
    /// 多状态非原子交换的固有残余——彻底消除需单状态原子交换或先 reload
    /// 再换 egress（会重新引入「新规则引用未就绪名」窗口）。在途流本已按旧
    /// 路由解析，窗口仅影响并发新流；接受并文档化。
    async fn apply_config_inner(&self, new_config: RillaneConfig) -> Result<()> {
        // Build egress outputs/connectors before mutating runtime state.
        // D-10/§4.3：传同一池/工厂句柄重连装配（新块的池参数不热生效——
        // 烧在构造期，变更需重启；键作用域自失效覆盖 egress 集变更）。
        let (outputs, connectors) = build_egress_outputs(
            &new_config.egress,
            self.transport_pool.clone(),
            self.tls_factory.clone(),
        )?;

        *self
            .flow_outputs
            .write()
            .expect("flow_outputs lock poisoned") = outputs;
        *self
            .egress_connectors
            .write()
            .expect("egress_connectors lock poisoned") = connectors;
        self.router.reload(new_config.routing.clone());
        *self.config.write().expect("config lock poisoned") = new_config.clone();
        let _ = self.event_tx.send(RuntimeEvent::ConfigUpdated {
            config: Box::new(new_config),
        });
        Ok(())
    }

    /// 将订阅/外部生成的配置增量合并进当前配置，并触发 runtime 更新。
    ///
    /// 当前策略为“只追加不删除”：新增 egress / group，rules 直接追加（不去重）。
    pub async fn merge_config_delta(&self, delta: &RillaneConfig) -> Result<ConfigMergeStats> {
        // P2（2026-11-03）：持 apply 锁覆盖「读当前 → 合并 → 应用」全程。
        // 曾读在锁外——并发 merge 各读同一基态再各自 update，后者覆写前者
        // 增量（lost update）。
        let _apply_guard = self.config_apply_lock.lock().await;
        let mut merged = self.get_config();

        let stats = merge_config_delta_in_place(&mut merged, delta);

        self.apply_config_inner(merged).await?;

        Ok(stats)
    }

    /// RIL-016 来源作用域合并：订阅刷新的规范入口。
    ///
    /// 所有权规则（本地优先级 + 来源命名空间）：
    /// - 对象名登记在本来源名下 → 原位替换（RIL-008 同源刷新语义：
    ///   内容更新必须生效，重复刷新替换不追加）
    /// - 对象名未登记 → 采纳：进配置并登记到本来源名下
    /// - 对象名登记在 local（构建期配置）或其它来源名下 → 跳过并计数
    ///   （`skipped_foreign`）——订阅 A 刷新永不覆盖用户游戏规则、
    ///   监听口、系统路由、插件或管理凭证，也不踩订阅 B 的对象
    ///
    /// 监听口/系统路由/插件/管理凭证不在合并面：本函数只动
    /// egress/groups/rules 三个面，apply 的是「当前配置 + 本增量」——
    /// control/ingress/network/obfuscation 块原样保留（有测试钉住）。
    ///
    /// 本来源名下但本次载荷缺席的对象只计数（`*_stale`）不删除——
    /// 删除会悬空用户规则/组对已撤组名的引用，撤除策略归配置发布
    /// 协调器（RIL-019）统一裁决。
    ///
    /// `source` 是命名空间键（推荐订阅名）；`local` 保留给构建期配置，
    /// 传入即拒绝。
    pub async fn merge_source_delta(
        &self,
        source: &str,
        delta: &RillaneConfig,
    ) -> Result<SourceMergeStats> {
        anyhow::ensure!(!source.is_empty(), "来源名不得为空");
        anyhow::ensure!(
            source != LOCAL_SOURCE,
            "来源名 {LOCAL_SOURCE:?} 保留给构建期配置，来源增量须用别的名字"
        );
        let _apply_guard = self.config_apply_lock.lock().await;
        let mut merged = self.get_config();

        // 先收集「非本来源」的全部对象名（含 local 与其它来源）。
        // DashMap entry 持锁期间不可再迭代自身（同分页锁重入死锁），
        // 故先克隆再 entry。
        let mut foreign_egress = std::collections::HashSet::new();
        let mut foreign_groups = std::collections::HashSet::new();
        let mut foreign_rules = std::collections::HashSet::new();
        for entry in self.source_owned.iter() {
            if entry.key() == source {
                continue;
            }
            let names = entry.value();
            foreign_egress.extend(names.egress.iter().cloned());
            foreign_groups.extend(names.groups.iter().cloned());
            foreign_rules.extend(names.rules.iter().cloned());
        }

        let mut owned = self.source_owned.entry(source.to_string()).or_default();
        let mut stats = SourceMergeStats {
            nodes_added: 0,
            nodes_updated: 0,
            groups_added: 0,
            groups_updated: 0,
            rules_added: 0,
            rules_updated: 0,
            nodes_skipped_foreign: 0,
            groups_skipped_foreign: 0,
            rules_skipped_foreign: 0,
            nodes_stale: 0,
            groups_stale: 0,
            rules_stale: 0,
        };

        // —— egress 面 ——
        let mut seen = std::collections::HashSet::new();
        for e in &delta.egress {
            seen.insert(e.name.clone());
            if foreign_egress.contains(&e.name) {
                stats.nodes_skipped_foreign += 1;
                continue;
            }
            if owned.egress.insert(e.name.clone()) {
                merged.egress.push(e.clone());
                stats.nodes_added += 1;
            } else {
                match merged.egress.iter_mut().find(|t| t.name == e.name) {
                    Some(slot) => {
                        *slot = e.clone();
                        stats.nodes_updated += 1;
                    }
                    None => {
                        // 登记在册但配置里没有（外部整份替换抹掉过）：
                        // 补回，仍算采纳面
                        merged.egress.push(e.clone());
                        stats.nodes_added += 1;
                    }
                }
            }
        }
        stats.nodes_stale = owned
            .egress
            .iter()
            .filter(|n| !seen.contains(*n) && merged.egress.iter().any(|e| &e.name == *n))
            .count();

        // —— groups 面 ——
        let mut seen_groups = std::collections::HashSet::new();
        for g in &delta.routing.groups {
            seen_groups.insert(g.name.clone());
            if foreign_groups.contains(&g.name) {
                stats.groups_skipped_foreign += 1;
                continue;
            }
            if owned.groups.insert(g.name.clone()) {
                merged.routing.groups.push(g.clone());
                stats.groups_added += 1;
            } else {
                match merged.routing.groups.iter_mut().find(|t| t.name == g.name) {
                    Some(slot) => {
                        *slot = g.clone();
                        stats.groups_updated += 1;
                    }
                    None => {
                        merged.routing.groups.push(g.clone());
                        stats.groups_added += 1;
                    }
                }
            }
        }
        stats.groups_stale = owned
            .groups
            .iter()
            .filter(|n| {
                !seen_groups.contains(*n) && merged.routing.groups.iter().any(|g| &g.name == *n)
            })
            .count();

        // —— rules 面 ——
        let mut seen_rules = std::collections::HashSet::new();
        for rule in &delta.routing.rules {
            seen_rules.insert(rule.name.clone());
            if foreign_rules.contains(&rule.name) {
                stats.rules_skipped_foreign += 1;
                continue;
            }
            if owned.rules.insert(rule.name.clone()) {
                merged.routing.rules.push(rule.clone());
                stats.rules_added += 1;
            } else {
                match merged
                    .routing
                    .rules
                    .iter_mut()
                    .find(|t| t.name == rule.name)
                {
                    Some(slot) => {
                        *slot = rule.clone();
                        stats.rules_updated += 1;
                    }
                    None => {
                        merged.routing.rules.push(rule.clone());
                        stats.rules_added += 1;
                    }
                }
            }
        }
        stats.rules_stale = owned
            .rules
            .iter()
            .filter(|n| {
                !seen_rules.contains(*n) && merged.routing.rules.iter().any(|r| &r.name == *n)
            })
            .count();

        self.apply_config_inner(merged).await?;

        Ok(stats)
    }

    /// 订阅运行时事件（广播通道）
    pub fn subscribe_events(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.event_tx.subscribe()
    }

    /// 兼容旧接口：返回事件订阅者
    pub fn get_event_receiver(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.subscribe_events()
    }

    /// 获取链路管理器
    pub fn get_chain_manager(&self) -> Option<Arc<ChainManager>> {
        self.chain_manager.clone()
    }

    /// 获取 Mesh 注册表
    pub fn get_mesh_registry(&self) -> Option<Arc<MeshRegistry>> {
        self.mesh_registry.clone()
    }

    /// 获取出站连接池（P1-5 §4.1：控制面 `/egress/pool/stats` 与指标渲染
    /// 取数入口；None = egress_pool 块缺席或 enabled=false）
    pub fn get_transport_pool(&self) -> Option<Arc<TransportPool>> {
        self.transport_pool.clone()
    }

    /// 获取 TLS 连接器工厂（P1-5 §4.1；None = 块缺席或 tls_resumption=false）
    pub fn get_tls_factory(&self) -> Option<Arc<TlsConnectorFactory>> {
        self.tls_factory.clone()
    }

    /// 获取 UDP 入站服务（P0-5 §4 观测接缝①：控制面 /udp/stats 取数入口；
    /// None = UDP 全关且无 per-ingress 显式开）
    pub fn get_udp_service(&self) -> Option<Arc<rillane_core::udp::UdpAssociateService>> {
        self.udp_service.clone()
    }

    /// 获取 TUN 入口（tun-dataplane.md T5 观测面：rillane_tun_* 指标与流表
    /// 状态取数；None = 未启用）。Linux 门控（platform-packaging.md）
    #[cfg(target_os = "linux")]
    pub fn get_tun_ingress(&self) -> Option<Arc<TunIngress>> {
        self.tun_ingress.clone()
    }

    /// 获取网络虚拟化模式（network-route.md：用于 /network/route/status）
    pub fn get_network_mode(&self) -> Option<NetworkMode> {
        self.runtime_config.network_config.as_ref().map(|n| n.mode)
    }

    /// P2-8 M1 观测接缝：DNS 服务单例（控制面 /dns/stats 取数；
    /// None = network.dns 块缺席/关闭）
    pub fn get_dns_service(&self) -> Option<Arc<crate::dns_config::DnsService>> {
        self.dns_service.clone()
    }

    /// 观测轮（plugin-loader.md §0 计数面）：per-plugin 计数快照（控制面
    /// /plugins/stats 取数；空 = obfs 未启用/无 plugins 声明）。即时快照、
    /// 不暴露内部句柄。RIL-040：small 档无 WASM 插件面，getter 缺席。
    #[cfg(feature = "plugins")]
    pub fn get_plugin_stats(&self) -> Vec<(String, rillane_plugins::PluginStatsSnapshot)> {
        self.plugin_middlewares
            .iter()
            .map(|mw| (mw.name().to_string(), mw.stats()))
            .collect()
    }

    /// 获取 mesh UDP 面快照（P0-5 §4 观测接缝②：start() 在 spawn_udp 后回填；
    /// None = 未 start / client-only / UDP 面未挂）
    pub fn get_mesh_udp_snapshot(&self) -> Option<UdpFaceSnapshot> {
        self.mesh_plane.get().and_then(|p| p.udp_snapshot())
    }

    /// P2-7 M0 §2.2 观测接缝：mesh mTLS 撤销生效面快照（`GET /mtls/revoked`
    /// 数据源；None = 未装配 mesh / 纯明文 TCP 面无 mTLS）。
    pub async fn get_mesh_revoked_snapshot(&self) -> Option<RevokedSnapshot> {
        match self.mesh_plane.get() {
            Some(plane) => plane.revoked_snapshot().await,
            None => None,
        }
    }

    /// P1-4 §5：obfs 填充执行计数快照（进程级 statics，`/metrics` 渲染数据源）。
    pub fn get_obfs_pad_snapshot(&self) -> crate::mesh_transport::ObfsPadSnapshot {
        crate::mesh_transport::obfs_pad_snapshot()
    }

    /// 获取 client 出站侧 UDP 计数（P0-5 §4 观测接缝③：build() 从 bridge 抽出；
    /// None = 无 chain-UDP 桥）
    pub fn get_udp_client_metrics(&self) -> Option<Arc<UdpClientMetrics>> {
        self.udp_client_metrics.clone()
    }

    /// 获取出口连接器
    pub fn get_egress_connectors(&self) -> HashMap<String, Arc<dyn EgressConnector>> {
        self.egress_connectors
            .read()
            .expect("egress_connectors lock poisoned")
            .clone()
    }

    /// 诊断轨迹查询面（RIL-055；控制面 /trace/* 经此取数——查询是
    /// 只读快照，与订阅 drain 互不影响）
    pub fn flow_query(&self) -> rillane_core::query::FlowQueryService {
        rillane_core::query::FlowQueryService::new(self.trace_collector.clone())
    }

    /// 诊断采集器配置快照（追踪开关/上限的可见面——查询面回答「为
    /// 何缺席」时对照）
    pub fn trace_collector_config(&self) -> rillane_core::collector::CollectorConfig {
        self.trace_collector
            .lock()
            .expect("trace collector poisoned")
            .config()
            .clone()
    }

    /// 诊断轨迹 TTL 清扫单次调用（RIL-064；start() 的周期 sweeper 每
    /// 60s 走一次——本方法是可测接缝，测试可直接注入墙钟）。返回本次
    /// 过期条数。
    pub fn trace_sweep_expired(&self, now_wall_ms: u64) -> usize {
        self.trace_collector
            .lock()
            .expect("trace collector poisoned")
            .sweep(now_wall_ms)
    }

    /// 诊断历史显式清除（RIL-064）：控制面 `DELETE /trace/history` 触发
    /// ——只删已关闭迹（活动流不拆），缺席答复从此带
    /// `collector.flow.purged`。返回删除条数。
    pub fn trace_history_purge(&self, now_wall_ms: u64) -> usize {
        self.trace_collector
            .lock()
            .expect("trace collector poisoned")
            .purge_closed(now_wall_ms)
    }

    /// 获取入口 -> 出口的累计流量统计快照
    pub fn get_flow_stats(&self) -> Vec<FlowStatItem> {
        self.flow_stats
            .iter()
            .map(|e| FlowStatItem {
                ingress: e.key().0.clone(),
                egress: e.key().1.clone(),
                flows: e.value().flows,
                upstream: e.value().upstream,
                downstream: e.value().downstream,
            })
            .collect()
    }

    /// 获取订阅管理器
    pub fn get_subscription_manager(&self) -> Option<Arc<SubscriptionManager>> {
        self.subscription_manager.clone()
    }

    /// 获取 FlowRouter（必要时自动包装为 mesh-chain 路由器）
    pub fn flow_router(&self) -> Arc<dyn FlowRouter> {
        if let (Some(chain_mgr), Some(mesh), Some(local_id)) = (
            self.chain_manager.clone(),
            self.mesh_registry.clone(),
            self.local_node_id.clone(),
        ) {
            Arc::new(RuntimeFlowRouter::new(
                self.router.clone(),
                mesh,
                chain_mgr,
                local_id,
            ))
        } else {
            self.router.clone()
        }
    }

    /// 执行链路 Dry Run（预检）
    pub async fn dry_run_chain(
        &self,
        source: &NodeId,
        target: &NodeId,
        constraints: Option<ChainConstraints>,
    ) -> Result<crate::chain::ChainDryRunResult> {
        // 验证链路管理器已启用
        let _ = self
            .chain_manager
            .as_ref()
            .ok_or_else(|| anyhow!("链路管理器未启用"))?;

        let mesh_registry = self
            .mesh_registry
            .as_ref()
            .ok_or_else(|| anyhow!("Mesh 注册表未启用"))?;

        let chain_cfg = self.runtime_config.chain_config.clone().unwrap_or_default();

        let builder = ChainBuilder::new(chain_cfg, mesh_registry.clone());
        builder.dry_run(source, target, constraints).await
    }
}

fn merge_config_delta_in_place(
    target: &mut RillaneConfig,
    delta: &RillaneConfig,
) -> ConfigMergeStats {
    let mut existing_egress: std::collections::HashSet<String> =
        target.egress.iter().map(|e| e.name.clone()).collect();
    let mut existing_groups: std::collections::HashSet<String> = target
        .routing
        .groups
        .iter()
        .map(|g| g.name.clone())
        .collect();

    let mut nodes_added = 0usize;
    let mut nodes_updated = 0usize;
    for e in &delta.egress {
        if existing_egress.insert(e.name.clone()) {
            target.egress.push(e.clone());
            nodes_added += 1;
        } else {
            // RIL-008：同源刷新的更新语义——同名节点原位替换（内容变了
            // 必须生效），不再跳过导致旧内容滞留
            match target.egress.iter_mut().find(|t| t.name == e.name) {
                Some(slot) => {
                    *slot = e.clone();
                    nodes_updated += 1;
                }
                None => {
                    target.egress.push(e.clone());
                    nodes_added += 1;
                }
            }
        }
    }

    let mut groups_added = 0usize;
    let mut groups_updated = 0usize;
    for g in &delta.routing.groups {
        if existing_groups.insert(g.name.clone()) {
            target.routing.groups.push(g.clone());
            groups_added += 1;
        } else {
            // 同名组原位替换（成员/策略更新语义，与节点一致）
            match target.routing.groups.iter_mut().find(|t| t.name == g.name) {
                Some(slot) => {
                    *slot = g.clone();
                    groups_updated += 1;
                }
                None => {
                    target.routing.groups.push(g.clone());
                    groups_added += 1;
                }
            }
        }
    }

    // RIL-008：规则按名原位替换——重复刷新同名规则（rule-1..N 序号稳定）
    // 替换既有条目、保持首匹配顺序原位，不再 extend 反复追加；新名追加。
    let mut rules_added = 0usize;
    let mut rules_updated = 0usize;
    for rule in &delta.routing.rules {
        match target
            .routing
            .rules
            .iter_mut()
            .find(|t| t.name == rule.name)
        {
            Some(slot) => {
                *slot = rule.clone();
                rules_updated += 1;
            }
            None => {
                target.routing.rules.push(rule.clone());
                rules_added += 1;
            }
        }
    }

    ConfigMergeStats {
        nodes_added,
        groups_added,
        rules_added,
        rules_updated,
        nodes_updated,
        groups_updated,
    }
}

/// 在普通 routing 结果之上，识别 mesh.* 目标并自动构建链路
struct RuntimeFlowRouter {
    engine: Arc<RoutingEngine>,
    mesh_registry: Arc<MeshRegistry>,
    chain_manager: Arc<ChainManager>,
    local_node_id: NodeId,
}

impl RuntimeFlowRouter {
    fn new(
        engine: Arc<RoutingEngine>,
        mesh_registry: Arc<MeshRegistry>,
        chain_manager: Arc<ChainManager>,
        local_node_id: NodeId,
    ) -> Self {
        Self {
            engine,
            mesh_registry,
            chain_manager,
            local_node_id,
        }
    }

    fn parse_mesh_target(target: &str) -> Option<&str> {
        target
            .strip_prefix("mesh.")
            .or_else(|| target.strip_prefix("mesh:"))
    }
}

#[async_trait]
impl FlowRouter for RuntimeFlowRouter {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        let base = self.engine.route(ctx.clone()).await?;

        // Already a chain decision; keep as-is.
        if matches!(base.path, RoutePath::Chain { .. }) {
            return Ok(base);
        }

        let target = base.final_node();
        let Some(mesh_target) = Self::parse_mesh_target(&target) else {
            return Ok(base);
        };

        // Validate the target exists/online; otherwise keep base decision.
        let online = self
            .mesh_registry
            .get_online_nodes()
            .into_iter()
            .any(|n| n.id == mesh_target);
        if !online {
            return Ok(base);
        }

        // Use FlowId UUID as session id, so retries of the same flow can reuse the chain.
        let session_id = ctx.id.as_uuid();
        let target_node: NodeId = mesh_target.to_string();
        match self
            .chain_manager
            .get_or_create_chain(session_id, &self.local_node_id, &target_node, None)
            .await
        {
            Ok(chain_ctx) => Ok(self.chain_manager.build_route_decision(&chain_ctx)),
            Err(_) => Ok(base),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct FlowStatCounter {
    flows: u64,
    upstream: u64,
    downstream: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowStatItem {
    pub ingress: String,
    pub egress: String,
    pub flows: u64,
    pub upstream: u64,
    pub downstream: u64,
}

struct StatsFlowOutput {
    ingress: String,
    inner: Arc<dyn FlowOutput>,
    stats: Arc<DashMap<(String, String), FlowStatCounter>>,
}

impl StatsFlowOutput {
    fn new(
        ingress: String,
        inner: Arc<dyn FlowOutput>,
        stats: Arc<DashMap<(String, String), FlowStatCounter>>,
    ) -> Self {
        Self {
            ingress,
            inner,
            stats,
        }
    }

    fn normalize_egress(decision: &RouteDecision) -> String {
        let mut target = decision.final_node();
        if let Some(stripped) = target.strip_prefix("egress.") {
            target = stripped.to_string();
        }
        target
    }
}

#[async_trait]
impl FlowOutput for StatsFlowOutput {
    async fn forward(&self, decision: RouteDecision, flow: Flow) -> Result<FlowReport> {
        let egress = Self::normalize_egress(&decision);
        let report = self.inner.forward(decision, flow).await?;

        self.stats
            .entry((self.ingress.clone(), egress))
            .and_modify(|v| {
                v.flows += 1;
                v.upstream += report.upstream;
                v.downstream += report.downstream;
            })
            .or_insert_with(|| FlowStatCounter {
                flows: 1,
                upstream: report.upstream,
                downstream: report.downstream,
            });

        Ok(report)
    }
}

/// 派发路由决策到具体出口（支持多跳链路）
struct FlowOutputRouter {
    outputs: Arc<RwLock<HashMap<String, Arc<dyn FlowOutput>>>>,
    /// 链路管理器（预留用于故障转移）
    chain_manager: Option<Arc<ChainManager>>,
    mesh_registry: Option<Arc<MeshRegistry>>,
    local_node_id: Option<NodeId>,
    mesh_tls: Option<MeshTlsConfig>,
    event_tx: broadcast::Sender<RuntimeEvent>,
    /// P0-4 §8：链路故障事件 → UDP 会话表（None = udp/chain 未同启）
    chain_failure_tx: Option<mpsc::Sender<ChainFailureEvent>>,
    /// P1-4 §1.3：静态混淆 middleware 链（唯一挂载点在本 forward；
    /// 关闭态 = 空链，§2.5）
    middleware_chain: MiddlewareChain,
}

impl FlowOutputRouter {
    #[allow(clippy::too_many_arguments)]
    fn new(
        outputs: Arc<RwLock<HashMap<String, Arc<dyn FlowOutput>>>>,
        chain_manager: Option<Arc<ChainManager>>,
        mesh_registry: Option<Arc<MeshRegistry>>,
        local_node_id: Option<NodeId>,
        mesh_tls: Option<MeshTlsConfig>,
        event_tx: broadcast::Sender<RuntimeEvent>,
        chain_failure_tx: Option<mpsc::Sender<ChainFailureEvent>>,
        middleware_chain: MiddlewareChain,
    ) -> Self {
        Self {
            outputs,
            chain_manager,
            mesh_registry,
            local_node_id,
            mesh_tls,
            event_tx,
            chain_failure_tx,
            middleware_chain,
        }
    }
}

#[async_trait]
impl FlowOutput for FlowOutputRouter {
    async fn forward(&self, decision: RouteDecision, mut flow: Flow) -> Result<FlowReport> {
        // P1-4 §1.3 三段：① 决策上下文注解注入（§1.4）→ ② middleware 链 →
        // ③ chain/单跳分派。空链（关闭态）时 ①② 一并跳过（§2.5 零开销
        // 旁路：连两次 BTreeMap::insert 都省去，零分配零锁）。
        if !self.middleware_chain.is_empty() {
            let kind = match &decision.path {
                RoutePath::Chain { .. } => "chain",
                _ => "single",
            };
            // §1.4：egress 值口径同 forward_single（"egress." 前缀剥离）
            let final_node = decision.final_node();
            let egress = final_node
                .strip_prefix("egress.")
                .unwrap_or(final_node.as_str())
                .to_string();
            flow.metadata
                .annotations
                .insert(ANN_ROUTE_KIND.to_string(), kind.to_string());
            flow.metadata
                .annotations
                .insert(ANN_ROUTE_EGRESS.to_string(), egress);
            // E8：任一 middleware Err 即中止，错误冒泡（转发失败不静默继续）
            flow = self.middleware_chain.run(flow).await?;
        }

        // 检查是否是多跳链路路由
        match &decision.path {
            RoutePath::Chain { hops } if !hops.is_empty() => {
                // 多跳链路转发
                self.forward_chain(&decision, flow, hops).await
            }
            _ => {
                // P1-4 §4.3/§5：单跳无帧载体——持 spec 不做字节改写（MVP
                // no-op 语义），仅记 skipped{no_frame} 保"开而不效"可见
                if crate::obfs_config::padding_spec_from_annotations(&flow.metadata.annotations)
                    .is_some()
                {
                    crate::mesh_transport::obfs_pad_note_no_frame();
                }
                self.forward_single(&decision, flow).await
            }
        }
    }
}

impl FlowOutputRouter {
    /// 单跳转发
    async fn forward_single(&self, decision: &RouteDecision, flow: Flow) -> Result<FlowReport> {
        let mut target = decision.final_node();
        if let Some(stripped) = target.strip_prefix("egress.") {
            target = stripped.to_string();
        }

        let output = {
            let outputs = self.outputs.read().expect("flow_outputs lock poisoned");
            outputs.get(&target).cloned()
        };
        if let Some(output) = output {
            output.forward(decision.clone(), flow).await
        } else {
            Err(anyhow!("未找到出口 {target}"))
        }
    }

    /// 多跳链路转发
    async fn forward_chain(
        &self,
        decision: &RouteDecision,
        mut flow: Flow,
        hops: &[rillane_core::RouteHop],
    ) -> Result<FlowReport> {
        if hops.is_empty() {
            return Err(anyhow!("多跳链路为空"));
        }

        // Always attach chain metadata (useful for telemetry and future multi-hop implementations).
        if let Ok(path_json) = serde_json::to_string(&decision.all_nodes()) {
            flow.metadata
                .annotations
                .insert("rillane.chain.path".to_string(), path_json);
        }
        if let Some(reason) = decision.reason.as_deref() {
            flow.metadata
                .annotations
                .insert("rillane.route.reason".to_string(), reason.to_string());
        }

        // For mesh chains, hops[0] is usually the local node id; the first actionable remote hop is hops[1].
        if hops.len() >= 2 {
            if let (Some(mesh), Some(local_id)) =
                (self.mesh_registry.clone(), self.local_node_id.clone())
            {
                let next_hop = hops[1].node.clone();

                // Best-effort: if next_hop exists in mesh registry, use mesh transport; otherwise fall back.
                if mesh.get_node_addr(&next_hop).is_some() {
                    tracing::debug!(
                        target: "rillane::mesh::transport",
                        next = %next_hop,
                        "使用 mesh data-plane 转发链路流量"
                    );

                    let plane = MeshDataPlane::new(local_id.clone(), mesh)
                        .with_tls(self.mesh_tls.clone())?;
                    let mesh_path: Vec<String> =
                        hops.iter().skip(1).map(|h| h.node.clone()).collect();
                    if mesh_path.is_empty() {
                        return Err(anyhow!("mesh chain path is empty"));
                    }
                    let env = MeshEnvelope::new(
                        flow.id.as_uuid().to_string(),
                        flow.target.host.clone(),
                        flow.target.port,
                        mesh_path.clone(),
                    );

                    // P1-4 §4.2/E9：注解缺 spec 即 None（旧行为）；命中则填充帧
                    let pad_spec = crate::obfs_config::padding_spec_from_annotations(
                        &flow.metadata.annotations,
                    );
                    match plane
                        .dial_and_tunnel(
                            &next_hop,
                            &env,
                            &mut *flow.io,
                            pad_spec.as_ref(),
                            &flow.id,
                        )
                        .await
                    {
                        Ok(()) => return Ok(FlowReport::default()),
                        Err(e) => {
                            tracing::warn!(
                                target: "rillane::mesh::transport",
                                next = %next_hop,
                                error = %e,
                                "mesh data-plane 转发失败，尝试故障转移"
                            );

                            let session_id = flow.id.as_uuid();
                            if let Some(chain_mgr) = &self.chain_manager {
                                if let Some(chain_ctx) =
                                    chain_mgr.get_chain_for_session(&session_id)
                                {
                                    let chain_id = chain_ctx.chain_id.clone();
                                    if let Ok(Some(new_ctx)) = chain_mgr
                                        .handle_chain_failure(
                                            &chain_id,
                                            &format!("{e}"),
                                            SwitchReason::FailureReported,
                                        )
                                        .await
                                    {
                                        let new_decision = chain_mgr.build_route_decision(&new_ctx);
                                        // P0-4 §8：链路故障事件桥接——chain_id 填
                                        // chain_id_of(切换后的新决策)（与 ChainManager 的
                                        // UUID chain_id 不换算，口径即 P0-1 约定），
                                        // failed_nodes 填旧链失败节点（旧 hops 去本机
                                        // ingress 跳）；逐会话吊销/决策失效由 UDP 表
                                        // handle_chain_failure 完成（try_send 满即丢，
                                        // best-effort 与 event_tx 同水位）
                                        if let Some(tx) = &self.chain_failure_tx {
                                            let _ = tx.try_send(ChainFailureEvent {
                                                chain_id: chain_id_of(&new_decision),
                                                failed_nodes: hops
                                                    .iter()
                                                    .skip(1)
                                                    .map(|h| h.node.clone())
                                                    .collect(),
                                            });
                                        }
                                        if let RoutePath::Chain { hops: new_hops } =
                                            new_decision.path
                                        {
                                            let new_nodes: Vec<String> =
                                                new_hops.iter().map(|h| h.node.clone()).collect();
                                            if let Ok(prev) =
                                                serde_json::to_string(&decision.all_nodes())
                                            {
                                                flow.metadata.annotations.insert(
                                                    "rillane.chain.prev_path".to_string(),
                                                    prev,
                                                );
                                            }
                                            if let Ok(nextv) = serde_json::to_string(&new_nodes) {
                                                flow.metadata.annotations.insert(
                                                    "rillane.chain.next_path".to_string(),
                                                    nextv,
                                                );
                                            }
                                            flow.metadata.annotations.insert(
                                                "rillane.chain.failover".to_string(),
                                                "1".to_string(),
                                            );

                                            let _ = self.event_tx.send(RuntimeEvent::MeshEvent {
                                                session_id,
                                                event: MeshEventType::PathUpdated {
                                                    session_id,
                                                    path: new_nodes.clone(),
                                                },
                                            });

                                            tracing::debug!(
                                                target: "rillane::chain",
                                                session = %session_id,
                                                path = ?new_nodes,
                                                "chain failover 切换完成，中止已消费的流"
                                            );
                                        }
                                    }
                                }
                            }
                            // chain 故障转移只完成路由/事件面切换：
                            // 首跳 tunnel 失败时 flow.io 已被部分消费，
                            // 重放尾流到新链或回退出口都会拼出损坏协议
                            // 流；正确恢复面在上游（TUN retire → RST/FIN），
                            // 无条件返回原错误让调用方中止应用连接。
                            return Err(e);
                        }
                    }
                }
            }
        }

        // 记录链路信息到日志
        tracing::debug!(
            target: "rillane::chain",
            path = ?hops.iter().map(|h| &h.node).collect::<Vec<_>>(),
            "执行多跳链路转发"
        );

        // Fallback behavior: try forward to the first hop that maps to an egress output.
        for hop in hops {
            let mut name = hop.node.clone();
            if let Some(stripped) = name.strip_prefix("egress.") {
                name = stripped.to_string();
            }
            let output = {
                let outputs = self.outputs.read().expect("flow_outputs lock poisoned");
                outputs.get(&name).cloned()
            };
            if let Some(output) = output {
                return output.forward(decision.clone(), flow).await;
            }
        }

        // Last resort: try forward to the final node like a regular egress.
        self.forward_single(decision, flow).await
    }
}

/// 将 EgressConnector 适配为 FlowOutput
struct ConnectorFlowOutput {
    name: String,
    connector: Arc<dyn EgressConnector>,
}

impl ConnectorFlowOutput {
    fn new(name: String, connector: Arc<dyn EgressConnector>) -> Self {
        Self { name, connector }
    }
}

#[async_trait]
impl FlowOutput for ConnectorFlowOutput {
    async fn forward(&self, _decision: RouteDecision, flow: Flow) -> Result<FlowReport> {
        self.connector
            .forward(flow)
            .await
            .map_err(|e| anyhow!("出口 {} 转发失败: {e}", self.name))
    }
}

/// reject 出口（G0-5）：命中即断流，无网络 I/O。返回错误让调用方按
/// 转发失败处置（上层拆流/日志）；计数由外层 metrics 聚合。
struct RejectFlowOutput {
    name: String,
}

impl RejectFlowOutput {
    fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl FlowOutput for RejectFlowOutput {
    async fn forward(&self, _decision: RouteDecision, _flow: Flow) -> Result<FlowReport> {
        Err(anyhow!("出口 {}：拒绝（reject 目标）", self.name))
    }
}

/// RIL-140：选路模式出口的装配期校验（存在性 + 直连类型面）。配置层
/// 看不到出口目录，只能强制非空；本门补齐引用面——全局出口须为已
/// 声明组或已声明出口（含 reject 出口），直连出口须为 Direct 类型出口
/// 节点。引用不存在/类型不符装配期点名拒绝，不留到建连期才失败。
fn validate_mode_targets(config: &RillaneConfig) -> Result<()> {
    match config.routing.mode {
        SelectionMode::Rule => {}
        SelectionMode::Global => {
            let target = config
                .routing
                .global_node
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            let declared = config.routing.groups.iter().any(|g| g.name == target)
                || config.egress.iter().any(|e| e.name == target);
            anyhow::ensure!(
                declared,
                "全局出口 `{target}` 未声明（须为已声明组或已声明出口）"
            );
        }
        SelectionMode::Direct => {
            let target = config
                .routing
                .direct_node
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            let is_direct = config
                .egress
                .iter()
                .any(|e| e.name == target && matches!(e.spec, EgressConfig::Direct));
            anyhow::ensure!(
                is_direct,
                "直连出口 `{target}` 须为已声明的 Direct 类型出口节点"
            );
        }
    }
    Ok(())
}

fn build_ingress_endpoints(
    descriptors: &[IngressDescriptor],
    udp: Option<Arc<rillane_core::udp::UdpAssociateService>>,
    udp_enabled_global: bool,
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
) -> Result<HashMap<String, Arc<dyn IngressEndpoint>>> {
    let mut map = HashMap::new();
    for desc in descriptors {
        // P0-5 §1.3/§9-4：per-ingress 覆盖 ∪ 全局；服务实例仍全局共享单例
        //（会话表/指标单点）。Http/ShadowTls 无 UDP 面，恒 None。
        let per_ingress = match &desc.spec {
            IngressConfig::Socks5 { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Mixed { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Shadowsocks { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Trojan { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Vless { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Vmess { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Hysteria2 { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Hysteria { udp_enabled, .. } => *udp_enabled,
            IngressConfig::Http { .. } => None,
            IngressConfig::ShadowTls { .. } => None,
        };
        if per_ingress == Some(true) && !udp_enabled_global {
            // §2.7 日志口径：构建期一次性结构性提示（非逐包路径）
            tracing::warn!(
                target: "rillane::boot",
                ingress = %desc.name,
                "ingress 显式开启 UDP（udp_enabled: true）而全局 udp.enabled=false：仅该入口可用 UDP ASSOCIATE"
            );
        }
        let udp_here = match udp.as_ref() {
            Some(svc) if resolve_udp_enabled(udp_enabled_global, per_ingress) => {
                Some(Arc::clone(svc))
            }
            _ => None,
        };
        let endpoint: Arc<dyn IngressEndpoint> = match &desc.spec {
            IngressConfig::Socks5 { bind, auth, .. } => Arc::new(Socks5Ingress::new(
                desc.name.clone(),
                bind.clone(),
                auth.clone().unwrap_or_default(),
                udp_here,
                fake_ip.clone(),
            )),
            IngressConfig::Http {
                bind,
                auth,
                bearer_tokens,
            } => Arc::new(HttpIngress::new(
                desc.name.clone(),
                bind.clone(),
                auth.clone().unwrap_or_default(),
                bearer_tokens.clone().unwrap_or_default(),
                fake_ip.clone(),
            )),
            IngressConfig::Mixed {
                bind,
                auth,
                bearer_tokens,
                ..
            } => Arc::new(MixedIngress::new(
                desc.name.clone(),
                bind.clone(),
                auth.clone().unwrap_or_default(),
                bearer_tokens.clone().unwrap_or_default(),
                udp_here,
                fake_ip.clone(),
            )),
            IngressConfig::Shadowsocks {
                bind,
                method,
                password,
                udp_enabled,
            } => {
                // SS UDP 面装配件从进程级 ASSOCIATE 服务抽出同源共享件
                //（会话表 + 出站连接器族；udp 门与 socks5 同口径）
                let ss_udp = match udp.as_ref() {
                    Some(svc) if resolve_udp_enabled(udp_enabled_global, *udp_enabled) => {
                        Some(ShadowsocksUdpParts {
                            table: svc.table().clone(),
                            connector: svc.connector().clone(),
                        })
                    }
                    _ => None,
                };
                // 构建期校验（method/password 形状）拒绝落在装配期——
                // 与 egress ShadowsocksConnector::new 同口径
                Arc::new(ShadowsocksIngress::new(
                    desc.name.clone(),
                    bind.clone(),
                    method.clone(),
                    password.clone(),
                    ss_udp,
                    fake_ip.clone(),
                )?)
            }
            IngressConfig::Trojan {
                bind,
                password,
                cert,
                cert_key,
                udp_enabled,
            } => {
                // Trojan UDP 关联面同用进程级会话表 + 连接器族（udp 门与
                // socks5 同口径）；TLS 材料解析拒绝落在装配期
                let tj_udp = match udp.as_ref() {
                    Some(svc) if resolve_udp_enabled(udp_enabled_global, *udp_enabled) => {
                        Some(TrojanUdpParts {
                            table: svc.table().clone(),
                            connector: svc.connector().clone(),
                        })
                    }
                    _ => None,
                };
                Arc::new(TrojanIngress::new(
                    desc.name.clone(),
                    bind.clone(),
                    password.clone(),
                    cert,
                    cert_key,
                    tj_udp,
                    fake_ip.clone(),
                )?)
            }
            IngressConfig::Vless {
                bind,
                uuid,
                cert,
                cert_key,
                udp_enabled,
            } => {
                // VLESS UDP 关联面同用进程级会话表 + 连接器族（udp 门与
                // socks5 同口径）；TLS 材料/uuid 解析拒绝落在装配期
                let vl_udp = match udp.as_ref() {
                    Some(svc) if resolve_udp_enabled(udp_enabled_global, *udp_enabled) => {
                        Some(VlessUdpParts {
                            table: svc.table().clone(),
                            connector: svc.connector().clone(),
                        })
                    }
                    _ => None,
                };
                Arc::new(VlessIngress::new(
                    desc.name.clone(),
                    bind.clone(),
                    uuid,
                    cert,
                    cert_key,
                    vl_udp,
                    fake_ip.clone(),
                )?)
            }
            IngressConfig::Vmess {
                bind,
                uuid,
                udp_enabled,
            } => {
                // VMess UDP 关联面同用进程级会话表 + 连接器族（udp 门与
                // socks5/vless 同口径）；uuid 解析拒绝落在装配期（裸 TCP
                // 承载，无 TLS 材料）
                let vm_udp = match udp.as_ref() {
                    Some(svc) if resolve_udp_enabled(udp_enabled_global, *udp_enabled) => {
                        Some(VmessUdpParts {
                            table: svc.table().clone(),
                            connector: svc.connector().clone(),
                        })
                    }
                    _ => None,
                };
                Arc::new(VmessIngress::new(
                    desc.name.clone(),
                    bind.clone(),
                    uuid,
                    vm_udp,
                    fake_ip.clone(),
                )?)
            }
            IngressConfig::Hysteria2 {
                bind,
                password,
                cert,
                cert_key,
                udp_enabled,
            } => {
                // Hysteria2 UDP 关联面同用进程级会话表 + 连接器族（udp 门与
                // socks5/vless/vmess 同口径）；TLS 材料/口令解析拒绝落在装配期
                //（QUIC 端点即监听面，ALPN 恒 h3）
                let hy_udp = match udp.as_ref() {
                    Some(svc) if resolve_udp_enabled(udp_enabled_global, *udp_enabled) => {
                        Some(Hysteria2UdpParts {
                            table: svc.table().clone(),
                            connector: svc.connector().clone(),
                        })
                    }
                    _ => None,
                };
                Arc::new(Hysteria2Ingress::new(
                    desc.name.clone(),
                    bind.clone(),
                    password,
                    cert,
                    cert_key,
                    hy_udp,
                    fake_ip.clone(),
                )?)
            }
            IngressConfig::Hysteria {
                bind,
                password,
                cert,
                cert_key,
                up_mbps,
                down_mbps,
                udp_enabled,
            } => {
                // Hysteria v1（RIL-109）UDP 关联面同用进程级会话表 + 连接器族
                //（udp 门与 socks5/hysteria2 同口径）；TLS 材料/口令/速率上限
                // 解析拒绝落在装配期（QUIC 端点即监听面，ALPN 恒 "hysteria"）
                let hy_udp = match udp.as_ref() {
                    Some(svc) if resolve_udp_enabled(udp_enabled_global, *udp_enabled) => {
                        Some(HysteriaUdpParts {
                            table: svc.table().clone(),
                            connector: svc.connector().clone(),
                        })
                    }
                    _ => None,
                };
                Arc::new(HysteriaIngress::new(
                    desc.name.clone(),
                    bind.clone(),
                    password,
                    cert,
                    cert_key,
                    *up_mbps,
                    *down_mbps,
                    hy_udp,
                    fake_ip.clone(),
                )?)
            }
            IngressConfig::ShadowTls {
                bind,
                password,
                handshake_addr,
                target_addr,
            } => {
                // ShadowTLS 载具（RIL-110）：无寻址面入口——挑战命中切换后
                // 的流原样交数据服务器（内层协议入口 bind），router/output
                // 不经手；口令/地址校验拒绝落在装配期（构造即校验）
                Arc::new(ShadowTlsIngress::new(
                    desc.name.clone(),
                    bind.clone(),
                    password.clone(),
                    handshake_addr.clone(),
                    target_addr.clone(),
                )?)
            }
        };
        map.insert(desc.name.clone(), endpoint);
    }
    Ok(map)
}

/// P0-5 §10-S2：`UdpConfig` → `UdpSessionConfig` 显式映射（S0 十字段全覆盖，
/// 禁 `..Default::default()` 兜底——防「字段加了没接线」；lifetime 两态映射）。
/// egress 出口的 server 主机面（Direct 无远端；Wireguard 为 endpoint 字段，
/// 其余同名字段）——§2.7 auto-bypass 集的 egress 半边输入（字面量 IP 或域名）。
/// 仅 TUN 装配块消费（Linux 门控面）
#[cfg(target_os = "linux")]
fn egress_server_host(e: &EgressConfig) -> Option<&str> {
    match e {
        EgressConfig::Reject => None,
        EgressConfig::Direct => None,
        EgressConfig::Socks5 { server, .. }
        | EgressConfig::Http { server, .. }
        | EgressConfig::Shadowsocks { server, .. }
        | EgressConfig::Vmess { server, .. }
        | EgressConfig::Vless { server, .. }
        | EgressConfig::Trojan { server, .. }
        | EgressConfig::Anytls { server, .. }
        | EgressConfig::Hysteria { server, .. }
        | EgressConfig::Hysteria2 { server, .. }
        | EgressConfig::ShadowsocksShadowTls { server, .. }
        | EgressConfig::Tuic { server, .. }
        | EgressConfig::Snell { server, .. }
        | EgressConfig::ShadowQuic { server, .. }
        | EgressConfig::Mieru { server, .. }
        | EgressConfig::TrustTunnel { server, .. }
        | EgressConfig::Masque { server, .. }
        | EgressConfig::OpenConnect { server, .. }
        | EgressConfig::OpenVpn { server, .. }
        | EgressConfig::Ssh { server, .. } => Some(server),
        // Tailscale 的可达面：控制面 URL（载具在此握手+授权；数据面为
        // tailnet 内直连/DERP，不经此地址）
        EgressConfig::Tailscale { control_url, .. } => Some(control_url),
        // Tor 是网络不是服务器：无 server/port 字段（同 Reject/Direct 的
        // None 口径）
        EgressConfig::Tor { .. } => None,
        EgressConfig::Wireguard { endpoint, .. } => Some(endpoint),
    }
}

fn udp_session_config(cfg: &UdpConfig) -> rillane_core::udp::UdpSessionConfig {
    rillane_core::udp::UdpSessionConfig {
        session_idle: Duration::from_secs(cfg.session_idle_secs),
        mapping_idle: Duration::from_secs(cfg.mapping_idle_secs),
        sweep_interval: Duration::from_secs(cfg.sweep_interval_secs),
        max_sessions: cfg.max_sessions,
        max_mappings: cfg.max_mappings,
        session_max_lifetime: cfg.session_lifetime_secs.map(Duration::from_secs),
        downlink_capacity: cfg.downlink_queue_depth,
    }
}

/// UDP 出站连接器表（udp-relay-path.md §3.1 能力表）：
/// direct / shadowsocks / wireguard / reject / vmess / vless / trojan / anytls /
/// socks5 / hysteria / hysteria2 → 有能力（reject 为静默丢弃，审核发现
/// 2026-11-04；hysteria 为 RIL-109 数据报自写面，包层传输判负；hysteria2 为
/// RIL-133 数据报自写面，obfs 判负）；shadowsocks-shadow-tls 组合与其余
/// 类型 → 判负（载具与内层 SS 组合均无 UDP 面；由 `scan_udp_capability`
/// 在构建期报错）。
///
/// vmess/vless/trojan 仅 network=tcp 注册（ws/grpc 的 UDP 面未实现，由
/// scan_udp_capability 判负）；UDP 面复用 TCP 面连接器的构建期校验
/// （VMessSecurity::parse、alter_id=0、trojan tls 等），`from_connector`
/// 保证 UDP 面与 TCP 面同一份节点配置。
fn build_udp_connectors(
    descriptors: &[EgressDescriptor],
    transport_pool: Option<Arc<TransportPool>>,
    tls_factory: Option<Arc<TlsConnectorFactory>>,
) -> Result<HashMap<String, Arc<dyn EgressUdpConnector>>> {
    let mut connectors = HashMap::new();
    for desc in descriptors {
        let connector: Option<Arc<dyn EgressUdpConnector>> = match &desc.spec {
            EgressConfig::Direct => Some(Arc::new(rillane_core::udp::DirectUdpConnector)),
            EgressConfig::Socks5 {
                server,
                port,
                username,
                password,
            } => {
                // 出站 UDP ASSOCIATE（RIL-132）：与 TCP 面同一节点配置
                // （地址/凭据两侧一致）；无 UDP 能力声明留在目录与扫描面
                let conn =
                    Socks5Connector::new(server.clone(), *port, username.clone(), password.clone());
                Some(Arc::new(Socks5UdpConnector::from_connector(&conn)))
            }
            EgressConfig::Anytls {
                server,
                port,
                password,
                sni,
                skip_cert_verify,
            } => {
                // 出站 UoT 数据报面（RIL-106）：与 TCP 面同一节点配置
                // （地址/凭据两侧一致）；UDP 能力声明留在目录与扫描面
                let conn = AnytlsConnector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                );
                Some(Arc::new(AnytlsUdpConnector::from_connector(&conn)))
            }
            EgressConfig::Shadowsocks {
                server,
                port,
                method,
                password,
                plugin,
                ..
            } => {
                // plugin 模式（SIP003）UDP 判负：SIP003 仅定义 TCP 数据面，
                // 该节点 UDP 需求由 scan_udp_capability 按既有口径构建期报错
                if plugin.is_some() {
                    None
                } else {
                    // 复用 TCP 面连接器的构建期校验（加密方法解析在 new 内完成），
                    // 保证 UDP 面与 TCP 面同一份 server_config
                    let conn = ShadowsocksConnector::new(
                        server.clone(),
                        *port,
                        method.clone(),
                        password.clone(),
                        None,
                        None,
                    )
                    .with_context(|| format!("节点 {} 的 shadowsocks 配置无效", desc.name))?;
                    Some(Arc::new(ShadowsocksUdpConnector::from_connector(&conn)))
                }
            }
            EgressConfig::ShadowsocksShadowTls { .. } => {
                // 组合节点 UDP 判负（RIL-110）：shadow-tls 载具仅 TCP 伪
                // 记录中继、内层 SS 组合亦无 UDP 面——该节点 UDP 需求由
                // scan_udp_capability 按既有口径构建期报错
                None
            }
            EgressConfig::Wireguard {
                allowed_ips, mtu, ..
            } => Some(Arc::new(
                WireguardUdpConnector::new(allowed_ips.clone(), *mtu)
                    .with_context(|| format!("节点 {} 的 wireguard UDP 配置无效", desc.name))?,
            )),
            // reject 出口（G0-5）UDP 面（审核发现 2026-11-04）：注册为有能力
            // 连接器，关联即静默丢弃——不再被 scan_udp_capability 判负，广告/
            // 黑名单目标可拦截 UDP 流而不阻塞整机构建。
            EgressConfig::Reject => Some(Arc::new(rillane_core::udp::RejectUdpConnector)),
            EgressConfig::Vmess {
                server,
                port,
                uuid,
                alter_id,
                security,
                network,
                path,
                host,
                grpc_service_name,
                grpc_reuse: _,
                tls,
                skip_cert_verify,
                sni,
                alpn,
                tls_fingerprint,
            } if network == "tcp" => {
                // 仅 network=tcp 支持 UDP 面（G0-4）；ws/grpc/h2 → None 判负。
                // 复用 TCP 面构建期校验（security/alter_id/network 白名单）。
                let conn = VmessConnector::new(
                    server.clone(),
                    *port,
                    uuid.clone(),
                    *alter_id,
                    VmessSecurity::parse(security)?,
                    network.clone(),
                    path.clone(),
                    host.clone(),
                    grpc_service_name.clone(),
                    None,
                    *tls,
                    *skip_cert_verify,
                    sni.clone(),
                    alpn.clone(),
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    transport_pool.clone(),
                    tls_factory.clone(),
                );
                Some(Arc::new(VmessUdpConnector::from_connector(&conn)))
            }
            EgressConfig::Vless {
                server,
                port,
                uuid,
                flow,
                reality,
                network,
                path,
                host,
                grpc_service_name,
                grpc_reuse: _,
                xhttp_mode,
                packet_encoding,
                tls,
                skip_cert_verify,
                sni,
                alpn,
                tls_fingerprint,
            } if network == "tcp" => {
                // G1-6（2026-11-10 拍板改 M1 拒绝策略）：flow/reality 不再在
                // 构建期判负——配置随连接器保留，拨号期点名拒绝（防静默降级），
                // 节点级失败不拖垮整份订阅。
                let conn = VlessConnector::new(
                    server.clone(),
                    *port,
                    uuid.clone(),
                    flow.clone(),
                    reality.clone(),
                    network.clone(),
                    path.clone(),
                    host.clone(),
                    grpc_service_name.clone(),
                    None,
                    xhttp_mode.clone(),
                    packet_encoding.clone(),
                    *tls,
                    *skip_cert_verify,
                    sni.clone(),
                    alpn.clone(),
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    transport_pool.clone(),
                    tls_factory.clone(),
                );
                Some(Arc::new(VlessUdpConnector::from_connector(&conn)))
            }
            EgressConfig::Trojan {
                server,
                port,
                password,
                network,
                path,
                host,
                grpc_service_name,
                grpc_reuse: _,
                tls,
                skip_cert_verify,
                sni,
                tls_fingerprint,
                ..
            } if network == "tcp" && *tls => {
                // Trojan 恒叠 TLS；仅 network=tcp 支持 UDP 面（G0-4）。
                let conn = TrojanConnector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    network.clone(),
                    path.clone(),
                    host.clone(),
                    grpc_service_name.clone(),
                    None,
                    transport_pool.clone(),
                    tls_factory.clone(),
                );
                Some(Arc::new(TrojanUdpConnector::from_connector(&conn)))
            }
            EgressConfig::Hysteria2 {
                server,
                port,
                password,
                mport,
                obfs,
                obfs_param,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                // Hysteria2 UDP 中继面（RIL-133）：官方 UDPMessage 数据报协议
                // 自写（crate 无数据报公开 API，结论留证 protocol-backends.md）。
                // obfs 与 TCP 面同口径判负（salamander 换整个 QUIC 载荷）；
                // mport（端口跳跃）为 TCP 面重连策略，UDP 面不适用
                if obfs.is_some() || obfs_param.is_some() {
                    None
                } else {
                    let conn = Hysteria2Connector::new(
                        server.clone(),
                        *port,
                        password.clone(),
                        mport.clone(),
                        obfs.clone(),
                        obfs_param.clone(),
                        server_name.clone(),
                        *skip_cert_verify,
                        alpn.clone(),
                    );
                    Some(Arc::new(Hysteria2UdpConnector::from_connector(&conn)))
                }
            }
            EgressConfig::Tuic {
                server,
                port,
                uuid,
                password,
                congestion_controller,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                // TUIC UDP 数据报面（RIL-105）：官方 v5 Packet 命令 over QUIC
                // 不可靠数据报，自写（yanked+GPL 结论留证 protocol-backends.md
                // #tuic）——全组合可用（无 obfs/端口白名单组合面），校验归
                // 拨号期（uuid 解析/拥塞控制白名单具名拒绝）
                let conn = TuicConnector::new(
                    server.clone(),
                    *port,
                    uuid.clone(),
                    password.clone(),
                    congestion_controller.clone(),
                    server_name.clone(),
                    *skip_cert_verify,
                    alpn.clone(),
                );
                Some(Arc::new(TuicUdpConnector::from_connector(&conn)))
            }
            EgressConfig::Snell { .. } => {
                // Snell UDP 判负（RIL-111）：TCP 段自写面仅交付；官方 UDP
                // over TCP 数据报面未交付——该节点 UDP 需求由
                // scan_udp_capability 按既有口径构建期报错
                None
            }
            EgressConfig::ShadowQuic { .. } => {
                // ShadowQUIC UDP 判负（RIL-118）：库承载 TCP 面仅交付；库
                // 的两种 UDP 中继面（over-datagram / over-stream）未交付
                // ——该节点 UDP 需求由 scan_udp_capability 按既有口径
                // 构建期报错
                None
            }
            EgressConfig::Mieru { .. } => {
                // Mieru UDP 判负（RIL-116）：TCP 载具仅交付（官方默认
                // MULTIPLEXING_OFF 同形）；UDP 载具未交付——该节点 UDP 需求
                // 由 scan_udp_capability 按既有口径构建期报错
                None
            }
            EgressConfig::TrustTunnel {
                server,
                port,
                username,
                password,
                sni,
                skip_cert_verify,
                tls_fingerprint,
            } => {
                // TrustTunnel UDP 面（RIL-119）：官方 PROTOCOL.md v1.0 自写
                // `_udp2` 单流复用（评估与探针留证 protocol-backends.md
                // #trusttunnel）；构建期校验同 TCP 面（new 内）
                let mut conn = TrustTunnelUdpConnector::new(
                    server.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                )
                .with_context(|| format!("节点 {} 的 trusttunnel 配置无效", desc.name))?;
                if let Some(factory) = tls_factory.as_ref() {
                    conn = conn.with_factory(factory.clone());
                }
                Some(Arc::new(conn))
            }
            EgressConfig::Masque {
                server,
                port,
                sni,
                skip_cert_verify,
                uri_template,
            } => {
                // MASQUE UDP 面（RIL-120）：RFC 9298 CONNECT-UDP + QUIC
                // DATAGRAM 帧（评估与真机对端留证 protocol-backends.md
                // #masque）；构建期校验同 TCP 面（new 内）
                let conn = MasqueUdpConnector::new(
                    server.clone(),
                    *port,
                    sni.clone(),
                    *skip_cert_verify,
                    uri_template.clone(),
                )
                .with_context(|| format!("节点 {} 的 masque 配置无效", desc.name))?;
                Some(Arc::new(conn))
            }
            EgressConfig::OpenConnect { .. } => {
                // OpenConnect UDP 判负（RIL-121）：CSTP 是三层 IP 隧道——UDP
                // 应用面走 IP 隧道由用户态 smoltcp 栈承载，但本仓未交付
                // UDP 应用面（catalog udp=false）；节点级 UDP 需求由
                // scan_udp_capability 按既有口径构建期报错
                None
            }
            EgressConfig::OpenVpn { .. } => {
                // OpenVPN UDP 判负（RIL-122）：三层 IP 隧道——UDP 应用面走
                // 用户态 smoltcp 栈承载，但本仓未交付 UDP 应用面（catalog
                // udp=false）；节点级 UDP 需求由 scan_udp_capability 按既有
                // 口径构建期报错
                None
            }
            EgressConfig::Ssh { .. } => {
                // SSH UDP 判负（RIL-113）：direct-tcpip 仅 TCP 面——该节点
                // UDP 需求由 scan_udp_capability 按既有口径构建期报错
                None
            }
            EgressConfig::Tailscale { .. } => {
                // Tailscale UDP 判负（RIL-123）：载具数据面为 WireGuard 三层
                // 隧道，tcp_connect 仅 TCP 流；本仓未交付 UDP 应用面
                // （catalog udp=false）——该节点 UDP 需求由
                // scan_udp_capability 按既有口径构建期报错
                None
            }
            EgressConfig::Tor { .. } => {
                // Tor UDP 判负（RIL-114）：客户端出口流仅 TCP 面（数据报面
                // 未交付）——该节点 UDP 需求由 scan_udp_capability 按既有
                // 口径构建期报错
                None
            }
            EgressConfig::Hysteria {
                server,
                port,
                password,
                protocol,
                up_mbps,
                down_mbps,
                auth,
                auth_str,
                obfs,
                obfs_param,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                // Hysteria v1 UDP 中继面（RIL-109）：官方 udpMessage 数据报协议
                // 自写（v1 无任何可用库，结论留证 protocol-backends.md#hysteria）。
                // 载具 = 原生 UDP 上的 QUIC——obfs/wechat/faketcp 包层传输换
                // 整个 QUIC 载荷，与 hysteria2 salamander 同族判负（UDP 面不
                // 注册，能力扫描构建期点名）；速率解析拒绝落在连接器拨号期
                //（resolve_rates 具名拒绝 Some(0)）
                if protocol != "udp" || obfs.is_some() || obfs_param.is_some() {
                    None
                } else {
                    let conn = HysteriaConnector::new(
                        server.clone(),
                        *port,
                        password.clone(),
                        Some(protocol.clone()),
                        *up_mbps,
                        *down_mbps,
                        auth.clone(),
                        auth_str.clone(),
                        obfs.clone(),
                        obfs_param.clone(),
                        server_name.clone(),
                        *skip_cert_verify,
                        alpn.clone(),
                    );
                    Some(Arc::new(HysteriaUdpConnector::from_connector(&conn)))
                }
            }
            _ => None,
        };
        if let Some(c) = connector {
            connectors.insert(desc.name.clone(), c);
        }
    }
    Ok(connectors)
}

/// UDP 可达节点的构建期能力扫描（udp-relay-path.md §3.1）：
/// default_node + 规则目标 + 组成员闭包中出现"已知出站节点但无 UDP 能力"
/// → 启动失败，逐个列出节点名、类型与规则来源。
/// 非节点目标（路由器自行解析的字面量）不在此扫描范围。
fn scan_udp_capability(
    routing: &RoutingConfig,
    egress: &[EgressDescriptor],
    connectors: &HashMap<String, Arc<dyn EgressUdpConnector>>,
) -> Result<()> {
    // 可达集：default_node、规则目标，以及这些目标作为组名时递归展开的成员
    let groups: HashMap<&str, &PolicyGroup> = routing
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g))
        .collect();
    // 组展开 visited 集：防组环（g1→g2→g1）队列永不空而 build 无限挂起。
    // 同组二次遇及直接跳过——组成员已入队一次，展开结果一致。
    let mut visited_groups: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut reachable: HashMap<String, String> = HashMap::new();
    let mut queue: Vec<(String, String)> =
        vec![(routing.default_node.clone(), "default_node".to_string())];
    for rule in &routing.rules {
        queue.push((rule.target.clone(), format!("rule:{}", rule.name)));
    }
    while let Some((name, source)) = queue.pop() {
        if let Some(g) = groups.get(name.as_str()) {
            if !visited_groups.insert(g.name.as_str()) {
                continue; // 环/重复：该组已展开，跳过
            }
            for m in &g.members {
                // RIL-009：provider 成员是来源引用，其节点集随 provider
                // 载荷装入（运行时刷新）——构建期无静态节点可入队，跳过
                // 而非展开成 provider 名（那不是出口，会误报悬空引用）。
                if matches!(m, GroupMember::Provider { .. }) {
                    continue;
                }
                let member = match m {
                    GroupMember::Node { name }
                    | GroupMember::Group { name }
                    | GroupMember::WeightedNode { name, .. }
                    | GroupMember::WeightedGroup { name, .. } => name.clone(),
                    GroupMember::Provider { .. } => {
                        unreachable!("provider 成员已在上方跳过（构建期无静态节点集）")
                    }
                };
                queue.push((member, format!("group:{}", g.name)));
            }
            continue;
        }
        reachable.entry(name).or_insert(source);
    }

    let known: HashMap<&str, &EgressDescriptor> =
        egress.iter().map(|d| (d.name.as_str(), d)).collect();
    let mut offenders: Vec<String> = Vec::new();
    for (node, source) in &reachable {
        let Some(desc) = known.get(node.as_str()) else {
            continue; // 非本配置出站节点的目标（内置字面量等）
        };
        if !connectors.contains_key(node) {
            offenders.push(format!(
                "  - 节点 {node}（{}，来源 {source}）",
                egress_kind(&desc.spec)
            ));
        }
    }
    if !offenders.is_empty() {
        let detail = offenders.join("\n");
        anyhow::bail!(
            "udp.enabled 但以下出站节点不支持 UDP 转发（udp-relay-path.md §3.1 能力表）:\n\
             {detail}\n\
             当前支持 UDP 的出站类型: direct / shadowsocks / wireguard / reject / vmess / vless / trojan / socks5 / hysteria2 / tuic（vmess/vless/trojan/hysteria2 仅基础组合：vmess/vless/trojan 限 network=tcp，hysteria2 限无 obfs；tuic 全组合）\n\
             请更换这些节点的出站类型，或将 udp.enabled 关闭并移除 UDP 相关规则"
        );
    }
    Ok(())
}

fn egress_kind(spec: &EgressConfig) -> &'static str {
    // 规范映射单源于 rillane-config 协议目录（RIL-104）——runtime 只委托
    rillane_config::protocol_catalog::egress_kind(spec)
}

/// 出口构建产物：FlowOutput（入口侧复用）+ EgressConnector（chain 消费）对
type EgressBuildPair = (
    HashMap<String, Arc<dyn FlowOutput>>,
    HashMap<String, Arc<dyn EgressConnector>>,
);

/// 配置面指纹解析（P2-5 §4-3）：E1 未知值报错带原值与 egress 名。
fn parse_egress_fingerprint(v: &Option<String>, egress: &str) -> Result<TlsFingerprint> {
    match v {
        None => Ok(TlsFingerprint::None),
        Some(raw) => TlsFingerprint::parse(raw)
            .with_context(|| format!("egress {egress}: 指纹值 `{raw}` 非法")),
    }
}

/// D-7 warm 键推导：配置内 TLS 出站逐键预拨（与各连接器 `forward_pooled`
/// 的传输键同源）。vless ws 网络补 ws 分支键（实际 SNI = sni ∥ host 首值
/// ∥ server）；重复键去重。tcp 主键恒推——同 server 预热无害（warm 是
/// 优化不是前置条件，miss 走前台拨号）。
fn derive_tls_warm_keys(egress: &[EgressDescriptor]) -> Result<Vec<TransportKey>> {
    let mut keys: Vec<TransportKey> = Vec::new();
    for desc in egress {
        match &desc.spec {
            EgressConfig::Trojan {
                server,
                port,
                network,
                tls,
                skip_cert_verify,
                sni,
                host,
                tls_fingerprint,
                ..
            } => {
                // 键与 forward_pooled 的 transport_key 同源（借出键恒
                // Some(实际 SNI)：tcp/grpc = sni ∥ server；ws = sni ∥ ws Host
                // 首值 ∥ server，trojan-go 惯例 ws 恒叠 TLS）。network 单值
                // 决定分支，只推在用键（异于 vless 双键——vless 的 tcp 键
                // 在 ws 节点上永不被借出，属既有预留）。grpc 的池键携带
                // ALPN h2（gRPC over TLS 语义），预热键同源。
                if *tls {
                    let fp = parse_egress_fingerprint(tls_fingerprint, &desc.name)?;
                    let is_ws = network == "ws" || network == "websocket";
                    let sni_actual = if is_ws {
                        sni.clone()
                            .or_else(|| host.as_ref().and_then(|v| v.first().cloned()))
                            .unwrap_or_else(|| server.clone())
                    } else {
                        sni.clone().unwrap_or_else(|| server.clone())
                    };
                    let alpn: Vec<String> = if network == "grpc" {
                        vec!["h2".to_string()]
                    } else {
                        Vec::new()
                    };
                    keys.push(TransportKey::tls(
                        server,
                        *port,
                        Some(&sni_actual),
                        *skip_cert_verify,
                        &alpn,
                        fp,
                    ));
                }
            }
            EgressConfig::Http {
                server,
                port,
                tls: true,
                skip_cert_verify,
                sni,
                tls_fingerprint,
                ..
            } => {
                keys.push(TransportKey::tls(
                    server,
                    *port,
                    sni.as_deref(),
                    *skip_cert_verify,
                    &[],
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                ));
            }
            EgressConfig::Vless {
                server,
                port,
                network,
                tls: true,
                skip_cert_verify,
                sni,
                alpn,
                host,
                tls_fingerprint,
                ..
            } => {
                let empty: Vec<String> = Vec::new();
                let alpn = alpn.as_ref().unwrap_or(&empty);
                let fp = parse_egress_fingerprint(tls_fingerprint, &desc.name)?;
                // tcp 主键实际 SNI = sni ∥ server（与 forward_pooled tcp 分支同源）
                let tcp_sni = sni.clone().unwrap_or_else(|| server.clone());
                if network == "grpc" || network == "h2" || network == "xhttp" {
                    // grpc/h2/xhttp 键 ALPN 固定 h2（gRPC/h2/XHTTP over TLS
                    // 语义，RIL-129 xhttp 同 h2 载体）；此类节点上 tcp/ws
                    // 借出键不存在，只推在用键。SNI 回退链随传输面：
                    // grpc = sni ∥ server，h2/xhttp 同 ws（host 首值 → sni
                    // → server，与 forward_pooled h2/xhttp 分支同源）
                    let h2_sni = if network == "h2" || network == "xhttp" {
                        sni.clone()
                            .or_else(|| host.as_ref().and_then(|v| v.first().cloned()))
                            .unwrap_or_else(|| server.clone())
                    } else {
                        tcp_sni.clone()
                    };
                    keys.push(TransportKey::tls(
                        server,
                        *port,
                        Some(&h2_sni),
                        *skip_cert_verify,
                        &["h2".to_string()],
                        fp,
                    ));
                } else {
                    keys.push(TransportKey::tls(
                        server,
                        *port,
                        Some(&tcp_sni),
                        *skip_cert_verify,
                        alpn,
                        fp,
                    ));
                    // upgrade 面（ws/httpupgrade）借出键 SNI 回退链含 host
                    // 首值——与主键（tcp 面 sni ∥ server）异源时补第二键
                    if network == "ws" || network == "websocket" || network == "httpupgrade" {
                        let ws_sni = sni
                            .clone()
                            .or_else(|| host.as_ref().and_then(|v| v.first().cloned()))
                            .unwrap_or_else(|| server.clone());
                        keys.push(TransportKey::tls(
                            server,
                            *port,
                            Some(&ws_sni),
                            *skip_cert_verify,
                            alpn,
                            fp,
                        ));
                    }
                }
            }
            EgressConfig::Vmess {
                server,
                port,
                network,
                tls: true,
                skip_cert_verify,
                sni,
                alpn,
                host,
                tls_fingerprint,
                ..
            } => {
                let empty: Vec<String> = Vec::new();
                let alpn = alpn.as_ref().unwrap_or(&empty);
                let fp = parse_egress_fingerprint(tls_fingerprint, &desc.name)?;
                // tcp 主键实际 SNI = sni ∥ server
                let tcp_sni = sni.clone().unwrap_or_else(|| server.clone());
                if network == "grpc" || network == "h2" {
                    // grpc/h2 键 ALPN 固定 h2（gRPC/h2 over TLS 语义）；此类
                    // 节点上 tcp/ws 借出键不存在，只推在用键。SNI 回退链随
                    // 传输面：grpc = sni ∥ server，h2 同 ws（host 首值 → sni
                    // → server，与 forward_pooled h2 分支同源）
                    let h2_sni = if network == "h2" {
                        sni.clone()
                            .or_else(|| host.as_ref().and_then(|v| v.first().cloned()))
                            .unwrap_or_else(|| server.clone())
                    } else {
                        tcp_sni.clone()
                    };
                    keys.push(TransportKey::tls(
                        server,
                        *port,
                        Some(&h2_sni),
                        *skip_cert_verify,
                        &["h2".to_string()],
                        fp,
                    ));
                } else {
                    keys.push(TransportKey::tls(
                        server,
                        *port,
                        Some(&tcp_sni),
                        *skip_cert_verify,
                        alpn,
                        fp,
                    ));
                    // upgrade 面（ws/httpupgrade）借出键 SNI 回退链含 host
                    // 首值——与主键（tcp 面 sni ∥ server）异源时补第二键
                    if network == "ws" || network == "websocket" || network == "httpupgrade" {
                        let ws_sni = sni
                            .clone()
                            .or_else(|| host.as_ref().and_then(|v| v.first().cloned()))
                            .unwrap_or_else(|| server.clone());
                        keys.push(TransportKey::tls(
                            server,
                            *port,
                            Some(&ws_sni),
                            *skip_cert_verify,
                            alpn,
                            fp,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    // 非相邻重复也去重（同键多 egress 条目 / vless tcp-ws 同键）
    let mut seen = std::collections::HashSet::new();
    keys.retain(|k| seen.insert(k.clone()));
    Ok(keys)
}

fn build_egress_outputs(
    descriptors: &[EgressDescriptor],
    transport_pool: Option<Arc<TransportPool>>,
    tls_factory: Option<Arc<TlsConnectorFactory>>,
) -> Result<EgressBuildPair> {
    let mut outputs = HashMap::new();
    let mut connectors = HashMap::new();

    for desc in descriptors {
        // 协议目录准入（RIL-104）：编目外类型与未准入后端都不得进热路径——
        // 装配期点名稳定原因码拒绝，不静默降级、不在拨号期才炸。
        let kind = egress_kind(&desc.spec);
        match admission(kind) {
            Admission::Admitted(_) => {}
            Admission::NotAdmitted(e) => {
                let Registration::NotAdmitted { reason } = e.registration else {
                    unreachable!("未准入判定必带原因");
                };
                return Err(anyhow!(
                    "{CODE_EGRESS_NOT_ADMITTED}: 出口类型 {kind} 未准入（节点 {}）：{reason}",
                    desc.name
                ));
            }
            Admission::Unknown => {
                return Err(anyhow!(
                    "{CODE_UNKNOWN_EGRESS}: 出口类型 {kind} 不在协议目录（节点 {}）",
                    desc.name
                ));
            }
        }
        match &desc.spec {
            EgressConfig::Reject => {
                let flow_output: Arc<dyn FlowOutput> =
                    Arc::new(RejectFlowOutput::new(desc.name.clone()));
                outputs.insert(desc.name.clone(), flow_output);
            }
            EgressConfig::Direct => {
                // §2.5/D-6：direct 仅 pre_dial_direct 时带池（投机预拨默认关）
                let connector: Arc<dyn EgressConnector> = match transport_pool
                    .as_ref()
                    .filter(|p| p.policy().pre_dial_direct)
                {
                    Some(pool) => Arc::new(DirectConnector::with_pool(pool.clone())),
                    None => Arc::new(DirectConnector::new()),
                };
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Socks5 {
                server,
                port,
                username,
                password,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(Socks5Connector::new(
                    server.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Http {
                server,
                port,
                username,
                password,
                tls,
                skip_cert_verify,
                sni,
                tls_fingerprint,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(HttpConnector::new(
                    server.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                    *tls,
                    *skip_cert_verify,
                    sni.clone(),
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    transport_pool.clone(),
                    tls_factory.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Shadowsocks {
                server,
                port,
                method,
                password,
                plugin,
                plugin_opts,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(ShadowsocksConnector::new(
                    server.clone(),
                    *port,
                    method.clone(),
                    password.clone(),
                    plugin.clone(),
                    plugin_opts.clone(),
                )?);
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::ShadowsocksShadowTls {
                server,
                port,
                method,
                password,
                shadow_tls,
            } => {
                // SS over shadow-tls v2（RIL-110）：载具版本门先行（v1/v3
                // 点名拒绝，不静默降级），再装配组合连接器（SS 口令与载具
                // 口令两侧独立；加密方法/地址校验拒绝落在 new 内——配置
                // 错误启动时暴露）
                shadow_tls.validated()?;
                let connector: Arc<dyn EgressConnector> =
                    Arc::new(ShadowsocksShadowTlsConnector::new(
                        server.clone(),
                        *port,
                        shadow_tls.host.clone(),
                        shadow_tls.password.clone(),
                        shadow_tls.skip_cert_verify,
                        method.clone(),
                        password.clone(),
                    )?);
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Trojan {
                server,
                port,
                password,
                network,
                path,
                host,
                grpc_service_name,
                grpc_reuse,
                tls,
                skip_cert_verify,
                sni,
                tls_fingerprint,
                ..
            } => {
                // 传输层白名单 tcp/ws/grpc（ws/grpc 恒叠 TLS；grpc 需服务名；
                // gun 流复用旋钮仅 network=grpc 消费——其余传输面携带即拒绝，
                // RIL-130 交付边界）
                match network.as_str() {
                    "tcp" | "ws" | "websocket" => {}
                    "grpc" => {
                        let svc = grpc_service_name.as_deref().map(str::trim).unwrap_or("");
                        if svc.is_empty() {
                            return Err(anyhow!(
                                "Trojan network=grpc 需要非空 grpc_service_name (egress={})",
                                desc.name
                            ));
                        }
                    }
                    other => {
                        return Err(anyhow!(
                            "Trojan network 仅支持 tcp/ws/grpc，当前: {} (egress={})",
                            other,
                            desc.name
                        ));
                    }
                }
                if grpc_reuse.is_some() && network != "grpc" {
                    return Err(anyhow!(
                        "Trojan grpc-opts 流复用旋钮仅 network=grpc 可携带，当前 network={network} (egress={})",
                        desc.name
                    ));
                }
                if !*tls {
                    return Err(anyhow!(
                        "暂不支持的 Trojan 配置：tls=false (egress={})",
                        desc.name
                    ));
                }

                let connector: Arc<dyn EgressConnector> = Arc::new(TrojanConnector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    network.clone(),
                    path.clone(),
                    host.clone(),
                    grpc_service_name.clone(),
                    grpc_reuse.clone(),
                    transport_pool.clone(),
                    tls_factory.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Anytls {
                server,
                port,
                password,
                sni,
                skip_cert_verify,
            } => {
                // AnyTLS（RIL-106）：恒叠 TLS（协议本体），仅 tcp 面；会话
                // 复用/填充由库承载，TLS 拨号经本仓 TlsConnectorFactory
                // （旁路面：库不拥有拨号，见 protocol-backends.md#anytls）
                let connector: Arc<dyn EgressConnector> = Arc::new(AnytlsConnector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Hysteria2 {
                server,
                port,
                password,
                mport,
                obfs,
                obfs_param,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(Hysteria2Connector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    mport.clone(),
                    obfs.clone(),
                    obfs_param.clone(),
                    server_name.clone(),
                    *skip_cert_verify,
                    alpn.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Hysteria {
                server,
                port,
                password,
                protocol,
                up_mbps,
                down_mbps,
                auth,
                auth_str,
                obfs,
                obfs_param,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                // Hysteria v1（RIL-109）：控制流认证 + TCP 请求流 + UDP 数据报
                // 全自写（v1 无任何可用库，结论留证 protocol-backends.md#hysteria）；
                // 速率/载具校验归拨号期（resolve_rates Some(0) 具名拒绝、
                // 非 "udp" 载具与 obfs 包层传输点名拒绝，节点级失败不拖垮整份订阅）
                let connector: Arc<dyn EgressConnector> = Arc::new(HysteriaConnector::new(
                    server.clone(),
                    *port,
                    password.clone(),
                    Some(protocol.clone()),
                    *up_mbps,
                    *down_mbps,
                    auth.clone(),
                    auth_str.clone(),
                    obfs.clone(),
                    obfs_param.clone(),
                    server_name.clone(),
                    *skip_cert_verify,
                    alpn.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Tuic {
                server,
                port,
                uuid,
                password,
                congestion_controller,
                server_name,
                skip_cert_verify,
                alpn,
            } => {
                // TUIC v5（RIL-105）：Connect 流面 + Packet 数据报面自写
                // （yanked+GPL 结论留证 protocol-backends.md#tuic）；校验归
                // 拨号期（uuid 解析/拥塞控制白名单具名拒绝，节点级失败不
                // 拖垮整份订阅）
                let connector: Arc<dyn EgressConnector> = Arc::new(TuicConnector::new(
                    server.clone(),
                    *port,
                    uuid.clone(),
                    password.clone(),
                    congestion_controller.clone(),
                    server_name.clone(),
                    *skip_cert_verify,
                    alpn.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Snell { server, port, psk } => {
                // Snell v4（RIL-111）：记录流 TCP 段自写（obfs=none；评估
                // 留证 protocol-backends.md#snell）；PSK/长度校验在 new 内
                // （节点级失败不拖垮整份订阅）；请求 ClientID 恒零长度
                // （官方 UserKey 缺省口径，配置面不暴露）；UDP 面未交付
                // （catalog udp=false）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    SnellConnector::new(server.clone(), *port, psk.clone(), String::new())
                        .with_context(|| format!("节点 {} 的 snell 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::ShadowQuic {
                server,
                port,
                username,
                password,
                server_name,
                alpn,
                congestion_controller,
                zero_rtt,
                udp_over_stream: _,
            } => {
                // ShadowQUIC（RIL-118）：库承载 TCP 面（协议自身 Rust 实现
                // shadowquic 0.4.12；评估与探针留证 protocol-backends.md
                // #shadowquic）。校验归 new 内（认证面非空/拥塞控制支持集/
                // ALPN 非空表——节点级失败不拖垮整份订阅）；zero_rtt IR
                // 缺省 false（mihomo 口径，官方服务器 ≤v0.3.11 断连 bug）；
                // udp_over_stream 容忍读取不落行为（UDP 面未交付）；SNI
                // 缺省回落 server（new 内）；端点随连接器 Arc 存活（探针
                // 实证 drop-panic 毛刺）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    ShadowQuicConnector::new(
                        server.clone(),
                        *port,
                        username.clone(),
                        password.clone(),
                        server_name.clone(),
                        alpn.clone(),
                        congestion_controller.clone(),
                        zero_rtt.unwrap_or(false),
                    )
                    .with_context(|| format!("节点 {} 的 shadowquic 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Mieru {
                server,
                port,
                username,
                password,
            } => {
                // Mieru（RIL-116）：官方 protocol.md 自写 TCP 客户端面
                // （评估与探针留证 protocol-backends.md#mieru）。空用户名/
                // 密码/服务器校验归 new 内（节点级失败不拖垮整份订阅）；
                // UDP 载具未交付（catalog udp=false）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    MieruConnector::new(server.clone(), *port, username.clone(), password.clone())
                        .with_context(|| format!("节点 {} 的 mieru 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::TrustTunnel {
                server,
                port,
                username,
                password,
                sni,
                skip_cert_verify,
                tls_fingerprint,
            } => {
                // TrustTunnel（RIL-119）：官方 PROTOCOL.md v1.0 自写客户端面
                // ——TLS(ALPN h2) + HTTP/2 CONNECT + Basic 认证（评估与探针
                // 留证 protocol-backends.md#trusttunnel）。TCP 面 CONNECT
                // 直达目标；UDP 面 `_udp2` 复用（UDP 工厂臂交付）。空用户名/
                // 密码/服务器校验归 new 内（节点级失败不拖垮整份订阅）
                let mut connector = TrustTunnelConnector::new(
                    server.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                    sni.clone(),
                    *skip_cert_verify,
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                )
                .with_context(|| format!("节点 {} 的 trusttunnel 配置无效", desc.name))?;
                if let Some(factory) = tls_factory.as_ref() {
                    connector = connector.with_factory(factory.clone());
                }
                let connector: Arc<dyn EgressConnector> = Arc::new(connector);
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Masque {
                server,
                port,
                sni,
                skip_cert_verify,
                uri_template,
            } => {
                // MASQUE（RIL-120）：RFC 9298 CONNECT-UDP 自写客户端面——
                // TCP 面 HTTP/3 CONNECT（评估与真机对端留证
                // protocol-backends.md#masque）；UDP 面归 UDP 工厂臂。
                // 构建期校验归 new 内（节点级失败不拖垮整份订阅）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    MasqueConnector::new(
                        server.clone(),
                        *port,
                        sni.clone(),
                        *skip_cert_verify,
                        uri_template.clone(),
                    )
                    .with_context(|| format!("节点 {} 的 masque 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::OpenConnect {
                server,
                port,
                username,
                password,
                sni,
                skip_cert_verify,
            } => {
                // OpenConnect（RIL-121）：CSTP 三层 VPN 自写客户端面——TCP
                // 面用户态 smoltcp 三层桥 + 隧道 DNS（评估与真机对端留证
                // protocol-backends.md#openconnect）；UDP 应用面归 UDP 工厂
                // 臂（判负）。构建期校验归 new 内（节点级失败不拖垮整份订阅）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    OpenConnectConnector::new(
                        server.clone(),
                        *port,
                        username.clone(),
                        password.clone(),
                        sni.clone(),
                        *skip_cert_verify,
                    )
                    .with_context(|| format!("节点 {} 的 openconnect 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::OpenVpn {
                server,
                port,
                ca_pem,
                cert_pem,
                key_pem,
                cipher,
                tls_auth_key,
                key_direction,
                sni,
            } => {
                // OpenVPN（RIL-122）：corevpn-protocol 0.6.0 库承载三层 VPN
                // 客户端面——TCP 面用户态 smoltcp 三层桥（与 OpenConnect 共用
                // 栈）+ PUSH_REPLY 隧道 DNS（评估与标准对端互通留证
                // protocol-backends.md#openvpn）；UDP 应用面归 UDP 工厂臂
                // （判负）。构建期校验归 new 内（节点级失败不拖垮整份订阅）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    OpenVpnConnector::new(
                        server.clone(),
                        *port,
                        ca_pem.clone(),
                        cert_pem.clone(),
                        key_pem.clone(),
                        cipher.clone(),
                        tls_auth_key.clone(),
                        *key_direction,
                        sni.clone(),
                    )
                    .with_context(|| format!("节点 {} 的 openvpn 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Tailscale {
                control_url,
                auth_key,
                hostname,
                ephemeral,
                key_file,
            } => {
                // Tailscale（RIL-123）：tailscale 0.7.1（tailscale-rs）库承载
                // 三层 mesh 客户端面——噪音控制面握手（自托管 headscale 或
                // 官方协调端点）+ preauth key 授权 + WireGuard 数据通道经
                // ts_netstack_smoltcp 用户态栈直出已解封 TCP 流（评估与交付
                // 边界留证 protocol-backends.md#tailscale）。UDP 应用面归
                // UDP 工厂臂（判负）；构建期校验归 new 内（节点级失败不拖
                // 垮整份订阅）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    TailscaleConnector::new(
                        control_url.clone(),
                        auth_key.clone(),
                        hostname.clone(),
                        *ephemeral,
                        key_file.clone(),
                    )
                    .with_context(|| format!("节点 {} 的 tailscale 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Ssh {
                server,
                port,
                username,
                password,
                private_key,
                private_key_passphrase,
                host_key,
            } => {
                // SSH-2（RIL-113）：russh 客户端面（评估留证
                // protocol-backends.md#ssh）；主机钥钉扎必填 + 认证恰一选一
                // 在 new 内校验（节点级失败不拖垮整份订阅）；UDP 面未交付
                // （catalog udp=false）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    SshConnector::new(
                        server.clone(),
                        *port,
                        username.clone(),
                        password.clone(),
                        private_key.clone(),
                        private_key_passphrase.clone(),
                        host_key.clone(),
                    )
                    .with_context(|| format!("节点 {} 的 ssh 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Tor { proxy } => {
                // Tor（RIL-114）：arti-client 嵌入式客户端面（评估留证
                // protocol-backends.md#tor）；前置代理 URI 校验在 new 内
                // （arti 自家 ProxyProtocol 解析器，节点级失败不拖垮整份
                // 订阅）；共享客户端惰性引导 + 逐流隔离；UDP 面未交付
                // （catalog udp=false）
                let connector: Arc<dyn EgressConnector> = Arc::new(
                    TorConnector::new(proxy.clone())
                        .with_context(|| format!("节点 {} 的 tor 配置无效", desc.name))?,
                );
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Vless {
                server,
                port,
                uuid,
                flow,
                reality,
                network,
                path,
                host,
                grpc_service_name,
                grpc_reuse,
                xhttp_mode,
                packet_encoding,
                tls,
                skip_cert_verify,
                sni,
                alpn,
                tls_fingerprint,
            } => {
                // G1-6（2026-11-10 拍板改 M1 拒绝策略）：flow/reality 不再在构建
                // 期即拦——配置随连接器保留，拨号期点名拒绝（VlessConnector::
                // gate_reality_and_flow，防静默降级），节点级失败不拖垮整份订阅。
                // network=grpc 需非空服务名（恒叠 TLS，ALPN 固定 h2）；
                // network=h2 恒叠 TLS（mihomo 口径 h2 仅 TLS）；
                // network=xhttp 恒叠 TLS 且模式白名单（RIL-129——auto/
                // packet-up/stream-one，越界构建期具名拒绝）；
                // gun 流复用旋钮仅 network=grpc 消费，其余传输面携带即拒绝
                // （RIL-130 交付边界）
                if grpc_reuse.is_some() && network != "grpc" {
                    return Err(anyhow!(
                        "VLESS grpc-opts 流复用旋钮仅 network=grpc 可携带，当前 network={network} (egress={})",
                        desc.name
                    ));
                }
                if network == "grpc" {
                    let svc = grpc_service_name.as_deref().map(str::trim).unwrap_or("");
                    if svc.is_empty() {
                        return Err(anyhow!(
                            "VLESS network=grpc 需要非空 grpc_service_name (egress={})",
                            desc.name
                        ));
                    }
                    if !*tls {
                        return Err(anyhow!(
                            "VLESS network=grpc 需叠 TLS（gRPC over TLS 语义） (egress={})",
                            desc.name
                        ));
                    }
                }
                if network == "h2" && !*tls {
                    return Err(anyhow!(
                        "VLESS network=h2 需叠 TLS（h2 over TLS 语义） (egress={})",
                        desc.name
                    ));
                }
                if network == "xhttp" {
                    if !*tls {
                        return Err(anyhow!(
                            "VLESS network=xhttp 需叠 TLS（h2-over-TLS 语义） (egress={})",
                            desc.name
                        ));
                    }
                    let mode = xhttp_mode.as_deref().unwrap_or("auto");
                    if !matches!(mode, "" | "auto" | "packet-up" | "stream-one") {
                        return Err(anyhow!(
                            "VLESS network=xhttp mode 仅支持 auto/packet-up/stream-one，当前: {mode} (egress={})",
                            desc.name
                        ));
                    }
                }
                // RIL-130：UDP 包编码白名单（raw 缺省/xudp/packetaddr），越界
                // 构建期具名拒绝（同 xhttp mode 口径）
                let encoding = packet_encoding
                    .as_deref()
                    .map(str::trim)
                    .filter(|e| !e.is_empty());
                if let Some(enc) = encoding {
                    if !matches!(enc, "raw" | "xudp" | "packetaddr") {
                        return Err(anyhow!(
                            "VLESS packet-encoding 仅支持 raw/xudp/packetaddr（缺省 raw），当前: {enc} (egress={})",
                            desc.name
                        ));
                    }
                }
                let connector: Arc<dyn EgressConnector> = Arc::new(VlessConnector::new(
                    server.clone(),
                    *port,
                    uuid.clone(),
                    flow.clone(),
                    reality.clone(),
                    network.clone(),
                    path.clone(),
                    host.clone(),
                    grpc_service_name.clone(),
                    grpc_reuse.clone(),
                    xhttp_mode.clone(),
                    packet_encoding.clone(),
                    *tls,
                    *skip_cert_verify,
                    sni.clone(),
                    alpn.clone(),
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    transport_pool.clone(),
                    tls_factory.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Vmess {
                server,
                port,
                uuid,
                alter_id,
                security,
                network,
                path,
                host,
                grpc_service_name,
                grpc_reuse,
                tls,
                skip_cert_verify,
                sni,
                alpn,
                tls_fingerprint,
            } => {
                // build-time validation: security parse, alter_id==0, network
                // tcp/ws/httpupgrade/grpc/h2（clash 侧 network 只产
                // tcp/ws/h2/httpupgrade，见 clash.rs convert 方；"websocket"
                // 长形与 vless 口径一致予以兼容；grpc 需服务名；gun 流复用
                // 旋钮仅 network=grpc 消费——其余传输面携带即拒绝，RIL-130
                // 交付边界）
                if grpc_reuse.is_some() && network != "grpc" {
                    return Err(anyhow!(
                        "VMess grpc-opts 流复用旋钮仅 network=grpc 可携带，当前 network={network} (egress={})",
                        desc.name
                    ));
                }
                let parsed_security = VmessSecurity::parse(security)?;
                if *alter_id != 0 {
                    return Err(anyhow!(
                        "VMess AEAD 仅支持 alter_id=0（legacy MD5 认证已不支持），节点: {}",
                        desc.name
                    ));
                }
                if network != "tcp"
                    && network != "ws"
                    && network != "websocket"
                    && network != "httpupgrade"
                    && network != "grpc"
                    && network != "h2"
                {
                    return Err(anyhow!(
                        "VMess network 仅支持 tcp/ws/httpupgrade/grpc/h2，当前: {}",
                        network
                    ));
                }
                if network == "grpc" {
                    let svc = grpc_service_name.as_deref().map(str::trim).unwrap_or("");
                    if svc.is_empty() {
                        return Err(anyhow!(
                            "VMess network=grpc 需要非空 grpc_service_name (egress={})",
                            desc.name
                        ));
                    }
                    if !*tls {
                        return Err(anyhow!(
                            "VMess network=grpc 需叠 TLS（gRPC over TLS 语义） (egress={})",
                            desc.name
                        ));
                    }
                }
                if network == "h2" && !*tls {
                    return Err(anyhow!(
                        "VMess network=h2 需叠 TLS（h2 over TLS 语义） (egress={})",
                        desc.name
                    ));
                }
                let connector: Arc<dyn EgressConnector> = Arc::new(VmessConnector::new(
                    server.clone(),
                    *port,
                    uuid.clone(),
                    *alter_id,
                    parsed_security,
                    network.clone(),
                    path.clone(),
                    host.clone(),
                    grpc_service_name.clone(),
                    grpc_reuse.clone(),
                    *tls,
                    *skip_cert_verify,
                    sni.clone(),
                    alpn.clone(),
                    parse_egress_fingerprint(tls_fingerprint, &desc.name)?,
                    transport_pool.clone(),
                    tls_factory.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            }
            EgressConfig::Wireguard {
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
            } => {
                let connector: Arc<dyn EgressConnector> = Arc::new(WireguardConnector::new(
                    desc.name.clone(),
                    endpoint.clone(),
                    private_key.clone(),
                    public_key.clone(),
                    address.clone(),
                    allowed_ips.clone(),
                    preshared_key.clone(),
                    *persistent_keepalive,
                    *listen_port,
                    *mtu,
                    dns.clone(),
                ));
                let flow_output: Arc<dyn FlowOutput> = Arc::new(ConnectorFlowOutput::new(
                    desc.name.clone(),
                    connector.clone(),
                ));
                outputs.insert(desc.name.clone(), flow_output);
                connectors.insert(desc.name.clone(), connector);
            } // 防御面已由编译期穷尽性接管（RIL-109 接入 hysteria 后本 match
              // 覆盖全部 IR 变体）：目录与装配工厂失同步在编译期即报错，
              // 「编目内类型无工厂臂」不再可能到运行期。
        }
    }

    Ok((outputs, connectors))
}

fn register_local_mesh_node(mesh_cfg: MeshConfig) -> Result<Arc<MeshRegistry>> {
    use rillane_mesh::{NodeRecord, NodeRole};

    let registry = Arc::new(MeshRegistry::new());
    let role = match mesh_cfg.role.as_str() {
        "client" => NodeRole::Client,
        "relay" => NodeRole::Relay,
        "exit" => NodeRole::Exit,
        "hybrid" => NodeRole::Hybrid,
        _ => NodeRole::Client,
    };

    registry.register_node(NodeRecord::new(
        mesh_cfg.node_id.clone(),
        role,
        mesh_cfg.listen_address,
    ))?;

    let health_interval = mesh_cfg.health_check_interval;
    let topo_interval = mesh_cfg.topology_update_interval;
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        rillane_mesh::spawn_health_checker(registry_clone, health_interval).await;
    });
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        rillane_mesh::spawn_topology_updater(registry_clone, topo_interval).await;
    });

    Ok(registry)
}

/// P2-2 §4：mesh→routing 质量桥聚合——节点视角 p95 = 相邻链路最差跳（max），
/// loss = 相邻链路 errors 总和 / connections 总和（零连接记 0.0，见设计稿 §9 偏差）。
/// 仅产出有 RTT 样本的节点，保证下游 update_link_quality 只喂真实数据（D-3 来源优先级）。
pub fn aggregate_link_quality(registry: &MeshRegistry) -> Vec<(String, u32, f64)> {
    let mut p95: BTreeMap<String, u32> = BTreeMap::new();
    let mut traffic: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for r in registry.get_all_link_rtt() {
        let e = p95.entry(r.from.clone()).or_insert(r.p95_ms);
        if r.p95_ms > *e {
            *e = r.p95_ms;
        }
        let e = p95.entry(r.to.clone()).or_insert(r.p95_ms);
        if r.p95_ms > *e {
            *e = r.p95_ms;
        }
    }
    for t in registry.get_all_link_traffic() {
        let e = traffic.entry(t.from.clone()).or_insert((0, 0));
        e.0 += t.connections_total;
        e.1 += t.errors_total;
        let e = traffic.entry(t.to.clone()).or_insert((0, 0));
        e.0 += t.connections_total;
        e.1 += t.errors_total;
    }
    p95.into_iter()
        .map(|(node, worst)| {
            let (conns, errs) = traffic.get(&node).copied().unwrap_or((0, 0));
            let loss = if conns > 0 {
                errs as f64 / conns as f64
            } else {
                0.0
            };
            (node, worst, loss)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_config::{
        GroupMember, MatchCondition, PolicyGroup, RouteRule, RoutingConfig, Strategy,
    };
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Default)]
    struct DummyIo;

    impl AsyncRead for DummyIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DummyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CaptureOutput {
        annotations: Arc<Mutex<Option<std::collections::BTreeMap<String, String>>>>,
    }

    #[async_trait]
    impl FlowOutput for CaptureOutput {
        async fn forward(&self, _decision: RouteDecision, flow: Flow) -> Result<FlowReport> {
            let mut guard = self.annotations.lock().await;
            *guard = Some(flow.metadata.annotations);
            Ok(FlowReport::default())
        }
    }

    #[tokio::test]
    async fn forward_chain_injects_metadata_annotations() {
        let annotations = Arc::new(Mutex::new(None));
        let mut outputs: HashMap<String, Arc<dyn FlowOutput>> = HashMap::new();
        outputs.insert(
            "direct".to_string(),
            Arc::new(CaptureOutput {
                annotations: annotations.clone(),
            }),
        );
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let router = FlowOutputRouter::new(
            Arc::new(RwLock::new(outputs)),
            None,
            None,
            None,
            None,
            tx,
            None,
            MiddlewareChain::default(),
        );

        let decision = {
            let hops = vec![
                rillane_core::RouteHop {
                    node: "direct".to_string(),
                    hop_type: rillane_core::HopType::Ingress,
                },
                rillane_core::RouteHop {
                    node: "exit1".to_string(),
                    hop_type: rillane_core::HopType::Egress,
                },
            ];
            let mut d = RouteDecision::chain(hops);
            d.reason = Some("test".to_string());
            d
        };

        let flow = Flow {
            id: rillane_core::FlowId::new(),
            target: rillane_core::FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: rillane_core::TargetProto::Tcp,
            },
            io: Box::new(DummyIo),
            metadata: rillane_core::FlowMetadata::default(),
        };

        router.forward(decision, flow).await.unwrap();
        let guard = annotations.lock().await;
        let map = guard.as_ref().expect("annotations captured");
        assert!(map.contains_key("rillane.chain.path"));
        assert_eq!(
            map.get("rillane.route.reason").map(|s| s.as_str()),
            Some("test")
        );
    }

    /// chain 故障转移不复用已消费 flow.io：首跳 mesh tunnel 中途失败
    /// 会部分消费应用流，重放尾流到新链/回退出口都会拼出损坏协议流。
    /// 正确恢复是中止应用连接（上游 TUN retire → RST/FIN），故
    /// forward_chain 必须原样返回 Err，且不得触达回退出口转发。
    #[tokio::test]
    async fn forward_chain_mesh_failure_aborts_without_fallback_forward() {
        use rillane_mesh::{NodeRecord, NodeRole};

        // mesh 节点指向不可达地址：dial_and_tunnel 首跳 connect 即失败。
        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new(
                "relay1".to_string(),
                NodeRole::Relay,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();

        // 回退出口：旧代码故障后回退到此（复用已消费 io），新代码不得触达。
        let fallback_called = Arc::new(AtomicBool::new(false));
        struct NeverCalledOutput(Arc<AtomicBool>);
        #[async_trait]
        impl FlowOutput for NeverCalledOutput {
            async fn forward(&self, _d: RouteDecision, _f: Flow) -> Result<FlowReport> {
                self.0.store(true, Ordering::SeqCst);
                Ok(FlowReport::default())
            }
        }
        let mut outputs: HashMap<String, Arc<dyn FlowOutput>> = HashMap::new();
        outputs.insert(
            "relay1".to_string(),
            Arc::new(NeverCalledOutput(fallback_called.clone())),
        );

        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let router = FlowOutputRouter::new(
            Arc::new(RwLock::new(outputs)),
            None,
            Some(registry.clone()),
            Some("local".to_string()),
            None,
            tx,
            None,
            MiddlewareChain::default(),
        );

        let decision = {
            let hops = vec![
                rillane_core::RouteHop {
                    node: "local".to_string(),
                    hop_type: rillane_core::HopType::Ingress,
                },
                rillane_core::RouteHop {
                    node: "relay1".to_string(),
                    hop_type: rillane_core::HopType::Relay,
                },
                rillane_core::RouteHop {
                    node: "exit1".to_string(),
                    hop_type: rillane_core::HopType::Egress,
                },
            ];
            RouteDecision::chain(hops)
        };

        let flow = Flow {
            id: rillane_core::FlowId::new(),
            target: rillane_core::FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: rillane_core::TargetProto::Tcp,
            },
            io: Box::new(DummyIo),
            metadata: rillane_core::FlowMetadata::default(),
        };

        let result = router.forward(decision, flow).await;
        assert!(result.is_err(), "mesh 首跳失败必须中止（Err），不得回退");
        assert!(
            !fallback_called.load(Ordering::SeqCst),
            "回退出口不得被调用（复用已消费 flow.io 会损坏协议流）"
        );
    }

    /// P1-4 §1.3 测试共用：注册 CaptureOutput("direct") 的 router。
    /// Captured = CaptureOutput 抓取的注解快照通道（clippy type_complexity 收编）。
    type Captured = Arc<Mutex<Option<std::collections::BTreeMap<String, String>>>>;

    fn router_with_chain(middleware_chain: MiddlewareChain) -> (FlowOutputRouter, Captured) {
        let annotations = Arc::new(Mutex::new(None));
        let mut outputs: HashMap<String, Arc<dyn FlowOutput>> = HashMap::new();
        outputs.insert(
            "direct".to_string(),
            Arc::new(CaptureOutput {
                annotations: annotations.clone(),
            }),
        );
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        (
            FlowOutputRouter::new(
                Arc::new(RwLock::new(outputs)),
                None,
                None,
                None,
                None,
                tx,
                None,
                middleware_chain,
            ),
            annotations,
        )
    }

    fn mid_test_flow() -> Flow {
        Flow {
            id: rillane_core::FlowId::new(),
            target: rillane_core::FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: rillane_core::TargetProto::Tcp,
            },
            io: Box::new(DummyIo),
            metadata: rillane_core::FlowMetadata::default(),
        }
    }

    fn mid_chain_decision() -> RouteDecision {
        let hops = vec![
            rillane_core::RouteHop {
                node: "direct".to_string(),
                hop_type: rillane_core::HopType::Ingress,
            },
            rillane_core::RouteHop {
                node: "exit1".to_string(),
                hop_type: rillane_core::HopType::Egress,
            },
        ];
        RouteDecision::chain(hops)
    }

    fn mid_padding_chain() -> MiddlewareChain {
        use rillane_core::{PaddingMode, PaddingSpec};
        use rillane_protocols::middleware::PaddingMiddleware;
        MiddlewareChain::new(vec![Arc::new(PaddingMiddleware::new(
            PaddingSpec {
                mode: PaddingMode::Fixed,
                target: 512,
                buckets: vec![],
                min: 0,
                max: 0,
                max_overhead_ratio: 0.5,
            },
            // 选择器恒命中：隔离验证 ①注入 ②执行 两段接线本身
            Box::new(|_kind, _egress| true),
        ))])
    }

    /// P1-4 §1.3/§1.4/§7.1：链决策 + 链非空 → ① rillane.route.kind=chain、
    /// rillane.route.egress=final_node 注入；② PaddingMiddleware 执行并写
    /// rillane.obfs.padding；carrier 键（rillane.chain.path）照常注入不被改写。
    #[tokio::test]
    async fn forward_chain_runs_middleware_with_route_annotations() {
        let (router, annotations) = router_with_chain(mid_padding_chain());
        router
            .forward(mid_chain_decision(), mid_test_flow())
            .await
            .unwrap();
        let map = annotations.lock().await.as_ref().expect("captured").clone();
        assert_eq!(
            map.get("rillane.route.kind").map(String::as_str),
            Some("chain")
        );
        assert_eq!(
            map.get("rillane.route.egress").map(String::as_str),
            Some("exit1"),
            "final_node 注入（§1.4，链尾跳）"
        );
        let json = map
            .get("rillane.obfs.padding")
            .expect("选择器命中应写 spec 注解");
        let spec: rillane_core::PaddingSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.mode, rillane_core::PaddingMode::Fixed);
        assert!(map.contains_key("rillane.chain.path"), "carrier 键照常");
    }

    /// §1.4：单跳决策 → kind=single、egress 带 egress. 前缀剥离（同
    /// forward_single 口径）；middleware 照样执行（§1.3 单点覆盖两类决策）。
    #[tokio::test]
    async fn forward_single_runs_middleware_with_stripped_egress() {
        let (router, annotations) = router_with_chain(mid_padding_chain());
        let decision = RouteDecision::direct("egress.direct".to_string());
        router.forward(decision, mid_test_flow()).await.unwrap();
        let map = annotations.lock().await.as_ref().expect("captured").clone();
        assert_eq!(
            map.get("rillane.route.kind").map(String::as_str),
            Some("single")
        );
        assert_eq!(
            map.get("rillane.route.egress").map(String::as_str),
            Some("direct")
        );
        assert!(map.contains_key("rillane.obfs.padding"));
    }

    /// P1-4 §4.3/§5：单跳无帧载体——持 spec 不做字节改写（MVP no-op），
    /// 但 skipped{no_frame} 计数递增 + spec 注解在（"开而不效"可见）；
    /// 关闭态（空链）同路径不计数（§2.5 对照）。
    #[tokio::test]
    async fn forward_single_with_padding_spec_counts_no_frame() {
        let (router, annotations) = router_with_chain(mid_padding_chain());
        let pre = crate::mesh_transport::obfs_pad_snapshot().skipped_no_frame;
        router
            .forward(
                RouteDecision::direct("egress.direct".to_string()),
                mid_test_flow(),
            )
            .await
            .unwrap();
        let map = annotations.lock().await.as_ref().expect("captured").clone();
        assert!(map.contains_key("rillane.obfs.padding"), "spec 注解应在");
        assert!(
            crate::mesh_transport::obfs_pad_snapshot().skipped_no_frame > pre,
            "单跳持 spec 应记 skipped{{no_frame}}"
        );

        // 关闭态对照：空链 → 注解缺席 → 同路径不计数
        let (router, annotations) = router_with_chain(MiddlewareChain::default());
        let pre = crate::mesh_transport::obfs_pad_snapshot().skipped_no_frame;
        router
            .forward(
                RouteDecision::direct("egress.direct".to_string()),
                mid_test_flow(),
            )
            .await
            .unwrap();
        assert!(!annotations
            .lock()
            .await
            .as_ref()
            .expect("captured")
            .contains_key("rillane.obfs.padding"));
        assert_eq!(
            crate::mesh_transport::obfs_pad_snapshot().skipped_no_frame,
            pre,
            "关闭态不计数（§2.5）"
        );
    }

    /// §2.5/§7.1：空链（关闭态）→ 路由注解两键与 spec 注解全部缺席
    /// （零副作用——连注解注入都省去）。
    #[tokio::test]
    async fn forward_empty_chain_skips_route_annotations() {
        let (router, annotations) = router_with_chain(MiddlewareChain::default());
        router
            .forward(mid_chain_decision(), mid_test_flow())
            .await
            .unwrap();
        let map = annotations.lock().await.as_ref().expect("captured").clone();
        assert!(!map.contains_key("rillane.route.kind"));
        assert!(!map.contains_key("rillane.route.egress"));
        assert!(!map.contains_key("rillane.obfs.padding"));
        assert!(
            map.contains_key("rillane.chain.path"),
            "既有 carrier 注解不受影响"
        );
    }

    /// §4.1/§8-M1：latency_probe 显式挂载证明管线通（默认不挂——不配置即
    /// 空链；挂载后 forward 正常到达出口、无 padding 副作用）。
    #[tokio::test]
    async fn latency_probe_mounted_proves_pipeline() {
        use rillane_protocols::middleware::LatencyProbe;
        let (router, annotations) =
            router_with_chain(MiddlewareChain::new(vec![Arc::new(LatencyProbe::new())]));
        let decision = RouteDecision::direct("egress.direct".to_string());
        router.forward(decision, mid_test_flow()).await.unwrap();
        let map = annotations.lock().await.as_ref().expect("captured").clone();
        assert_eq!(
            map.get("rillane.route.kind").map(String::as_str),
            Some("single")
        );
        assert!(
            !map.contains_key("rillane.obfs.padding"),
            "probe 不产 spec 注解"
        );
    }

    struct FixedReportOutput {
        report: FlowReport,
    }

    #[async_trait]
    impl FlowOutput for FixedReportOutput {
        async fn forward(&self, _decision: RouteDecision, _flow: Flow) -> Result<FlowReport> {
            Ok(self.report)
        }
    }

    #[tokio::test]
    async fn stats_flow_output_accumulates_reports() {
        let stats = Arc::new(DashMap::new());
        let inner: Arc<dyn FlowOutput> = Arc::new(FixedReportOutput {
            report: FlowReport {
                upstream: 10,
                downstream: 20,
            },
        });
        let out: Arc<dyn FlowOutput> = Arc::new(StatsFlowOutput::new(
            "in1".to_string(),
            inner,
            stats.clone(),
        ));

        let decision = RouteDecision::direct("egress.direct-main".to_string());
        let flow = Flow {
            id: rillane_core::FlowId::new(),
            target: rillane_core::FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: rillane_core::TargetProto::Tcp,
            },
            io: Box::new(DummyIo),
            metadata: rillane_core::FlowMetadata::default(),
        };

        let report = out.forward(decision, flow).await.unwrap();
        assert_eq!(report.upstream, 10);
        assert_eq!(report.downstream, 20);

        let key = ("in1".to_string(), "direct-main".to_string());
        let v = stats.get(&key).expect("stats exists");
        assert_eq!(v.flows, 1);
        assert_eq!(v.upstream, 10);
        assert_eq!(v.downstream, 20);
    }

    #[test]
    fn build_egress_outputs_supports_hysteria2() {
        let egress = vec![EgressDescriptor {
            name: "hy2".to_string(),
            spec: EgressConfig::Hysteria2 {
                server: "example.com".to_string(),
                port: 443,
                password: "secret".to_string(),
                mport: None,
                obfs: None,
                obfs_param: None,
                server_name: Some("example.com".to_string()),
                skip_cert_verify: true,
                alpn: None,
            },
        }];

        let (outputs, connectors) =
            build_egress_outputs(&egress, None, None).expect("build egress outputs");
        assert!(outputs.contains_key("hy2"));
        assert_eq!(
            connectors.get("hy2").expect("connector").name(),
            "hysteria2"
        );
    }

    /// G0-5 reject 出口：构建产出且 forward 即拒绝（断流）。
    #[tokio::test]
    async fn build_egress_outputs_reject_blocks_forward() {
        let egress = vec![node("block-ads", EgressConfig::Reject)];
        let (outputs, connectors) =
            build_egress_outputs(&egress, None, None).expect("build egress outputs");
        assert!(outputs.contains_key("block-ads"));
        assert!(connectors.is_empty(), "reject 非 EgressConnector");

        let flow = rillane_core::Flow {
            id: rillane_core::FlowId::new(),
            target: rillane_core::FlowTarget {
                host: "ads.example.com".into(),
                port: 443,
                proto: rillane_core::TargetProto::Tcp,
            },
            io: Box::new(tokio::io::duplex(64).0),
            metadata: Default::default(),
        };
        let out = outputs.get("block-ads").expect("reject output");
        let err = out
            .forward(
                rillane_core::RouteDecision::direct("block-ads".into()),
                flow,
            )
            .await
            .expect_err("reject 必须拒绝");
        assert!(format!("{err:#}").contains("拒绝"), "实际：{err:#}");
    }

    #[test]
    fn build_egress_outputs_supports_vmess() {
        let egress = vec![node("vm", vmess_spec())];
        let (outputs, connectors) =
            build_egress_outputs(&egress, None, None).expect("build egress outputs");
        assert!(outputs.contains_key("vm"));
        assert_eq!(connectors.get("vm").expect("connector").name(), "vmess");
    }

    #[test]
    fn build_egress_outputs_rejects_vmess_misconfig() {
        // 非法 security 构建期报错
        let mut bad_security = vmess_spec();
        if let EgressConfig::Vmess { security, .. } = &mut bad_security {
            *security = "none".to_string();
        }
        let egress = vec![node("vm-bad-sec", bad_security)];
        let err = build_egress_outputs(&egress, None, None)
            .err()
            .expect("非法 security 必须报错");
        assert!(err.to_string().contains("security"), "实际：{err}");

        // alter_id != 0（legacy 认证）构建期报错
        let mut bad_alter = vmess_spec();
        if let EgressConfig::Vmess { alter_id, .. } = &mut bad_alter {
            *alter_id = 1;
        }
        let egress = vec![node("vm-bad-alter", bad_alter)];
        let err = build_egress_outputs(&egress, None, None)
            .err()
            .expect("alter_id=1 必须报错");
        assert!(err.to_string().contains("alter_id"), "实际：{err}");

        // 非法 network 构建期报错（grpc 已为合法传输，用 quic 作非法值）
        let mut bad_network = vmess_spec();
        if let EgressConfig::Vmess { network, .. } = &mut bad_network {
            *network = "quic".to_string();
        }
        let egress = vec![node("vm-bad-net", bad_network)];
        let err = build_egress_outputs(&egress, None, None)
            .err()
            .expect("非法 network 必须报错");
        assert!(err.to_string().contains("network"), "实际：{err}");

        // xhttp 载具仅 vless 交付（RIL-129）——vmess+xhttp 白名单外，
        // 构建期具名拒绝（不静默当 tcp 用）
        let mut bad_xhttp = vmess_spec();
        if let EgressConfig::Vmess { network, .. } = &mut bad_xhttp {
            *network = "xhttp".to_string();
        }
        let egress = vec![node("vm-xhttp", bad_xhttp)];
        let err = build_egress_outputs(&egress, None, None)
            .err()
            .expect("vmess+xhttp 必须报错");
        assert!(err.to_string().contains("xhttp"), "拒绝须点名 xhttp: {err}");
    }

    #[test]
    fn derive_tls_warm_keys_covers_vmess() {
        let egress = vec![
            EgressDescriptor {
                name: "vm-tcp".to_string(),
                spec: EgressConfig::Vmess {
                    server: "v.example".to_string(),
                    port: 443,
                    uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                    alter_id: 0,
                    security: "auto".to_string(),
                    network: "tcp".to_string(),
                    path: None,
                    host: None,
                    grpc_service_name: None,
                    grpc_reuse: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: Some("sni.example".to_string()),
                    alpn: None,
                    tls_fingerprint: None,
                },
            },
            EgressDescriptor {
                name: "vm-ws".to_string(),
                spec: EgressConfig::Vmess {
                    server: "w.example".to_string(),
                    port: 443,
                    uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                    alter_id: 0,
                    security: "chacha20-poly1305".to_string(),
                    network: "ws".to_string(),
                    path: Some("/vm".to_string()),
                    host: Some(vec!["cdn.example".to_string()]),
                    grpc_service_name: None,
                    grpc_reuse: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                    tls_fingerprint: None,
                },
            },
        ];
        let keys = derive_tls_warm_keys(&egress).expect("REASON");
        assert_eq!(keys.len(), 3, "vmess tcp 主键 + vmess ws 双键");
        assert!(
            keys.contains(&TransportKey::tls(
                "v.example",
                443,
                Some("sni.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "vmess tcp 主键（实际 SNI = sni）"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "w.example",
                443,
                Some("w.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "vmess ws 主键（sni 缺省 = server）"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "w.example",
                443,
                Some("cdn.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "vmess ws 分支键（实际 SNI = host 首值）"
        );
    }

    #[tokio::test]
    async fn merge_config_delta_updates_egress_connectors() {
        let cfg = RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        assert!(!runtime.get_egress_connectors().contains_key("p1"));

        let delta = RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![],
            egress: vec![EgressDescriptor {
                name: "p1".to_string(),
                spec: EgressConfig::Socks5 {
                    server: "127.0.0.1".to_string(),
                    port: 1080,
                    username: None,
                    password: None,
                },
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        let stats = runtime
            .merge_config_delta(&delta)
            .await
            .expect("merge delta");
        assert_eq!(stats.nodes_added, 1);

        let connectors = runtime.get_egress_connectors();
        assert_eq!(connectors.get("p1").expect("p1 connector").name(), "socks5");
    }

    /// P2（2026-11-03）回归：持 config_apply_lock 期间 update_config 必须
    /// 等待（互斥串行化）。曾为 check-then-act，并发 apply 交错丢失更新。
    #[tokio::test]
    async fn update_config_waits_for_config_apply_lock() {
        let cfg = RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg.clone())
                .with_runtime_config(RuntimeConfig {
                    enable_hot_reload: false,
                    ..RuntimeConfig::default()
                })
                .build()
                .expect("build runtime"),
        );

        // 测试同模块可触私有字段：持锁模拟并发的另一个 apply 在临界区内。
        let guard = runtime.config_apply_lock.lock().await;
        let rt = runtime.clone();
        let mut handle = tokio::spawn(async move { rt.update_config(cfg).await });
        // 锁未放前 update_config 不得推进。
        let still_pending =
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut handle).await;
        assert!(
            still_pending.is_err(),
            "持 config_apply_lock 期间 update_config 必须等待"
        );
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("释放锁后 update_config 应完成")
            .expect("task 不应失败")
            .expect("join 不应失败");
    }

    /// P2（2026-11-03）回归：并发 merge_config_delta 两路不相交增量都须保留。
    /// 曾读 config 在锁外——两路并发各读同一基态，后写者覆写前者增量。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_merge_config_delta_keeps_both_deltas() {
        let cfg = RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };
        let runtime = Arc::new(
            RuntimeBuilder::new(cfg)
                .with_runtime_config(RuntimeConfig {
                    enable_hot_reload: false,
                    ..RuntimeConfig::default()
                })
                .build()
                .expect("build runtime"),
        );

        let mk_delta = |name: &str| RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![],
            egress: vec![EgressDescriptor {
                name: name.to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        let d1 = mk_delta("n1");
        let d2 = mk_delta("n2");
        let r1 = runtime.clone();
        let r2 = runtime.clone();
        let (res1, res2) = tokio::join!(
            tokio::spawn(async move { r1.merge_config_delta(&d1).await }),
            tokio::spawn(async move { r2.merge_config_delta(&d2).await }),
        );
        res1.expect("task1 不 panic").expect("merge1 成功");
        res2.expect("task2 不 panic").expect("merge2 成功");

        let connectors = runtime.get_egress_connectors();
        assert!(connectors.contains_key("n1"), "并发 merge 不得丢失增量 n1");
        assert!(connectors.contains_key("n2"), "并发 merge 不得丢失增量 n2");
    }

    // ---- RIL-064 诊断留存面 ----

    /// 留存三面在装配上可见：配置快照（TTL 有界——「历史可过期」的配置
    /// 事实）、TTL 清扫单次调用与显式清除（空采集器都答 0，不造数）。
    /// 周期 sweeper 在 start() 装配（60s），本测钉可测接缝。
    #[tokio::test]
    async fn trace_retention_faces_are_wired() {
        let cfg = source_test_config(
            "127.0.0.1:0",
            vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            vec![],
            vec![],
        );
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        let snap = runtime.trace_collector_config();
        assert!(snap.enabled, "采集默认开启（开销对照的 default 档）");
        assert!(snap.ttl_ms > 0, "TTL 有界可见——历史可过期的配置事实");
        assert!(
            snap.capacity > 0 && snap.max_active_flows > 0,
            "容量双界可见"
        );
        assert_eq!(
            runtime.trace_sweep_expired(9_000_000_000),
            0,
            "空采集器清扫不造数"
        );
        assert_eq!(
            runtime.trace_history_purge(9_000_000_000),
            0,
            "空采集器清除不造数"
        );
    }

    // ---- RIL-016 本地策略所有权：来源作用域合并 ----

    /// 构造来源合并测试用最小配置
    fn source_test_config(
        control_bind: &str,
        egress: Vec<EgressDescriptor>,
        groups: Vec<PolicyGroup>,
        rules: Vec<RouteRule>,
    ) -> RillaneConfig {
        RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: control_bind.to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress,
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups,
                rules,
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        }
    }

    fn socks(name: &str, port: u16) -> EgressDescriptor {
        EgressDescriptor {
            name: name.to_string(),
            spec: EgressConfig::Socks5 {
                server: "127.0.0.1".to_string(),
                port,
                username: None,
                password: None,
            },
        }
    }

    fn node_group(name: &str, member: &str) -> PolicyGroup {
        PolicyGroup {
            name: name.to_string(),
            strategy: Strategy::Fixed,
            members: vec![GroupMember::Node {
                name: member.to_string(),
            }],
            slo: None,
            url_test: None,
        }
    }

    fn host_rule(name: &str, target: &str) -> RouteRule {
        RouteRule {
            name: name.to_string(),
            matches: vec![rillane_config::MatchCondition::DomainSuffix {
                values: vec!["example.com".to_string()],
            }],
            target: target.to_string(),
        }
    }

    #[tokio::test]
    async fn merge_source_delta_never_touches_local_objects() {
        // 本地（构建期）配置：用户节点/游戏组/规则——来源载荷带同名对象
        // 也必须跳过（内容不同的同名对象是「覆盖用户配置」的企图面）
        let local = source_test_config(
            "127.0.0.1:0",
            vec![
                EgressDescriptor {
                    name: "direct".to_string(),
                    spec: EgressConfig::Direct,
                },
                socks("user-node", 1111),
            ],
            vec![node_group("user-game", "user-node")],
            vec![host_rule("user-rule", "user-game")],
        );
        let runtime = RuntimeBuilder::new(local)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        let delta = source_test_config(
            "127.0.0.1:9999",
            vec![socks("user-node", 6666), socks("sub-a-node", 2222)],
            vec![
                node_group("user-game", "sub-a-node"),
                node_group("sub-a-grp", "sub-a-node"),
            ],
            vec![
                host_rule("user-rule", "direct"),
                host_rule("sub-a-rule-1", "sub-a-grp"),
            ],
        );

        let stats = runtime
            .merge_source_delta("sub-a", &delta)
            .await
            .expect("merge");

        // 本地名下三面各拒触碰一次；新对象三面各采纳一个
        assert_eq!(
            stats.nodes_skipped_foreign, 1,
            "user-node 是 local 的: {stats:?}"
        );
        assert_eq!(
            stats.groups_skipped_foreign, 1,
            "user-game 是 local 的: {stats:?}"
        );
        assert_eq!(
            stats.rules_skipped_foreign, 1,
            "user-rule 是 local 的: {stats:?}"
        );
        assert_eq!(stats.nodes_added, 1);
        assert_eq!(stats.groups_added, 1);
        assert_eq!(stats.rules_added, 1);

        let cfg = runtime.get_config();
        let user_node = cfg
            .egress
            .iter()
            .find(|e| e.name == "user-node")
            .expect("user-node 还在");
        match &user_node.spec {
            EgressConfig::Socks5 { port, .. } => {
                assert_eq!(*port, 1111, "本地节点内容不得被载荷覆盖（6666 被拒）")
            }
            other => panic!("user-node 应保持 Socks5，实际 {other:?}"),
        }
        assert!(
            cfg.routing.groups.iter().any(|g| g.name == "user-game"
                && matches!(&g.members[0], GroupMember::Node { name } if name == "user-node")),
            "本地组成员引用不得被改写"
        );
        let user_rule = cfg
            .routing
            .rules
            .iter()
            .find(|r| r.name == "user-rule")
            .expect("user-rule 还在");
        assert_eq!(user_rule.target, "user-game", "本地规则目标不得被改写");
    }

    #[tokio::test]
    async fn merge_source_delta_replaces_own_and_skips_other_source() {
        let local = source_test_config(
            "127.0.0.1:0",
            vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            vec![],
            vec![],
        );
        let runtime = RuntimeBuilder::new(local)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        // sub-a 首刷：采纳 a-node:2222
        let d1 = source_test_config("127.0.0.1:0", vec![socks("a-node", 2222)], vec![], vec![]);
        let stats = runtime
            .merge_source_delta("sub-a", &d1)
            .await
            .expect("merge1");
        assert_eq!(stats.nodes_added, 1);

        // sub-a 二刷：自己名下原位替换（RIL-008 同源刷新语义）
        let d2 = source_test_config("127.0.0.1:0", vec![socks("a-node", 3333)], vec![], vec![]);
        let stats = runtime
            .merge_source_delta("sub-a", &d2)
            .await
            .expect("merge2");
        assert_eq!(stats.nodes_updated, 1, "同源刷新原位替换: {stats:?}");
        let cfg = runtime.get_config();
        let a = cfg
            .egress
            .iter()
            .find(|e| e.name == "a-node")
            .expect("a-node 在");
        assert!(
            matches!(&a.spec, EgressConfig::Socks5 { port: 3333, .. }),
            "内容更新须生效"
        );

        // sub-b 带同名 a-node：sub-a 名下对象拒触碰
        let d3 = source_test_config(
            "127.0.0.1:0",
            vec![socks("a-node", 4444), socks("b-node", 5555)],
            vec![],
            vec![],
        );
        let stats = runtime
            .merge_source_delta("sub-b", &d3)
            .await
            .expect("merge3");
        assert_eq!(stats.nodes_skipped_foreign, 1, "a-node 归 sub-a: {stats:?}");
        assert_eq!(stats.nodes_added, 1, "b-node 采纳");
        let cfg = runtime.get_config();
        let a = cfg
            .egress
            .iter()
            .find(|e| e.name == "a-node")
            .expect("a-node 在");
        assert!(
            matches!(&a.spec, EgressConfig::Socks5 { port: 3333, .. }),
            "sub-b 不得覆盖 sub-a 的 a-node"
        );
    }

    #[tokio::test]
    async fn merge_source_delta_never_touches_control_ingress_faces() {
        // 监听口/管理凭证不在合并面：载荷携带不同 control/ingress 块，
        // 合并后原样保留本地值（验收「刷新不覆盖监听口/管理凭证」）
        let local = source_test_config(
            "127.0.0.1:0",
            vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            vec![],
            vec![],
        );
        let runtime = RuntimeBuilder::new(local)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        let mut delta = source_test_config(
            "127.0.0.1:9999",
            vec![socks("sub-node", 2222)],
            vec![],
            vec![],
        );
        delta.control.admin_token = Some("payload-token".to_string());
        delta.ingress.push(IngressDescriptor {
            name: "payload-in".to_string(),
            spec: IngressConfig::Socks5 {
                bind: "0.0.0.0:9999".to_string(),
                auth: None,
                udp_enabled: None,
            },
        });

        runtime
            .merge_source_delta("sub-a", &delta)
            .await
            .expect("merge");
        let cfg = runtime.get_config();
        assert_eq!(cfg.control.api_bind, "127.0.0.1:0", "监听口不得被载荷改写");
        assert_eq!(cfg.control.admin_token, None, "管理凭证不得被载荷注入");
        assert_eq!(cfg.ingress.len(), 1, "入口面不得被载荷追加");
    }

    #[tokio::test]
    async fn merge_source_delta_counts_stale_without_removing() {
        let local = source_test_config(
            "127.0.0.1:0",
            vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            vec![],
            vec![],
        );
        let runtime = RuntimeBuilder::new(local)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        let d1 = source_test_config(
            "127.0.0.1:0",
            vec![socks("a-node", 2222), socks("a-node2", 2233)],
            vec![node_group("a-grp", "a-node")],
            vec![],
        );
        runtime
            .merge_source_delta("sub-a", &d1)
            .await
            .expect("merge1");

        // 二刷载荷撤掉 a-node2 与 a-grp：只计数不删除（删除策略归 RIL-019，
        // 提前删除会悬空引用）
        let d2 = source_test_config("127.0.0.1:0", vec![socks("a-node", 2222)], vec![], vec![]);
        let stats = runtime
            .merge_source_delta("sub-a", &d2)
            .await
            .expect("merge2");
        assert_eq!(stats.nodes_stale, 1, "a-node2 计数 stale: {stats:?}");
        assert_eq!(stats.groups_stale, 1, "a-grp 计数 stale: {stats:?}");
        let cfg = runtime.get_config();
        assert!(
            cfg.egress.iter().any(|e| e.name == "a-node2"),
            "stale 对象不删"
        );
        assert!(
            cfg.routing.groups.iter().any(|g| g.name == "a-grp"),
            "stale 组不删"
        );

        // 保留来源名拒绝
        let err = runtime
            .merge_source_delta(LOCAL_SOURCE, &d2)
            .await
            .expect_err("local 保留名拒绝");
        assert!(err.to_string().contains("local"));
    }

    #[test]
    fn merge_config_delta_in_place_dedupes_egress_and_groups() {
        let mut target = RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![PolicyGroup {
                    name: "g1".to_string(),
                    strategy: Strategy::Random,
                    members: vec![GroupMember::Node {
                        name: "direct".to_string(),
                    }],
                    slo: None,
                    url_test: None,
                }],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        let delta = RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![],
            egress: vec![
                EgressDescriptor {
                    name: "direct".to_string(),
                    spec: EgressConfig::Direct,
                },
                EgressDescriptor {
                    name: "p1".to_string(),
                    spec: EgressConfig::Socks5 {
                        server: "127.0.0.1".to_string(),
                        port: 1080,
                        username: None,
                        password: None,
                    },
                },
            ],
            routing: RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![
                    PolicyGroup {
                        name: "g1".to_string(),
                        strategy: Strategy::Random,
                        members: vec![GroupMember::Node {
                            name: "direct".to_string(),
                        }],
                        slo: None,
                        url_test: None,
                    },
                    PolicyGroup {
                        name: "g2".to_string(),
                        strategy: Strategy::Random,
                        members: vec![GroupMember::Node {
                            name: "p1".to_string(),
                        }],
                        slo: None,
                        url_test: None,
                    },
                ],
                rules: vec![
                    RouteRule {
                        name: "r1".to_string(),
                        matches: vec![MatchCondition::Port { values: vec![80] }],
                        target: "direct".to_string(),
                    },
                    RouteRule {
                        name: "r2".to_string(),
                        matches: vec![MatchCondition::DomainSuffix {
                            values: vec!["example.com".to_string()],
                        }],
                        target: "p1".to_string(),
                    },
                ],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        };

        let stats = merge_config_delta_in_place(&mut target, &delta);
        assert_eq!(stats.nodes_added, 1);
        assert_eq!(stats.groups_added, 1);
        assert_eq!(stats.rules_added, 2);

        assert_eq!(
            target.egress.iter().filter(|e| e.name == "direct").count(),
            1
        );
        assert!(target.egress.iter().any(|e| e.name == "p1"));
        assert_eq!(
            target
                .routing
                .groups
                .iter()
                .filter(|g| g.name == "g1")
                .count(),
            1
        );
        assert!(target.routing.groups.iter().any(|g| g.name == "g2"));
        assert_eq!(target.routing.rules.len(), 2);
    }

    #[test]
    fn merge_config_delta_repeated_refresh_replaces_in_place() {
        // RIL-008：重复刷新同源 delta——同名规则原位替换（首匹配顺序保持），
        // 不再 extend 反复追加；同名节点/组内容更新原位生效
        let target_yaml = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
  enable_tracing: false
ingress: []
egress:
  - name: direct
    type: direct
routing:
  default_node: direct
  groups: []
  rules: []
"#;
        let delta_yaml = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
  enable_tracing: false
ingress: []
egress:
  - name: direct
    type: direct
  - name: p1
    type: direct
routing:
  default_node: direct
  groups: []
  rules:
    - name: r1
      matches:
        - type: port
          values: [80]
      target: direct
    - name: r2
      matches:
        - type: domain_suffix
          values: [example.com]
      target: p1
"#;
        let mut target =
            rillane_config::RillaneConfig::from_str(target_yaml, None).expect("target 可解析");
        let delta =
            rillane_config::RillaneConfig::from_str(delta_yaml, None).expect("delta 可解析");

        // 首次合并：r1/r2 追加
        let stats1 = merge_config_delta_in_place(&mut target, &delta);
        assert_eq!(stats1.rules_added, 2);
        assert_eq!(target.routing.rules.len(), 2);

        // 重复刷新（同 delta）：原位替换，零新增，总条数不变
        let stats2 = merge_config_delta_in_place(&mut target, &delta);
        assert_eq!(stats2.rules_added, 0, "重复刷新不得新增规则");
        assert_eq!(stats2.rules_updated, 2);
        assert_eq!(stats2.nodes_added, 0);
        assert_eq!(target.routing.rules.len(), 2, "规则不得反复追加");
        assert_eq!(target.egress.len(), 2);

        // 内容更新：r1 目标改为 p1，再刷新 → 原位生效
        let mut delta_updated = delta.clone();
        delta_updated.routing.rules[0].target = "p1".to_string();
        let stats3 = merge_config_delta_in_place(&mut target, &delta_updated);
        assert_eq!(stats3.rules_added, 0);
        assert_eq!(stats3.rules_updated, 2);
        assert_eq!(target.routing.rules[0].target, "p1", "规则内容更新必须生效");
        assert_eq!(target.routing.rules.len(), 2);
    }

    #[test]
    fn parse_mesh_target_supports_mesh_prefix_variants() {
        assert_eq!(
            RuntimeFlowRouter::parse_mesh_target("mesh.exit1"),
            Some("exit1")
        );
        assert_eq!(
            RuntimeFlowRouter::parse_mesh_target("mesh:exit1"),
            Some("exit1")
        );
        assert_eq!(RuntimeFlowRouter::parse_mesh_target("direct"), None);
    }

    // ---------- P0-4 §9.1/S5 build() 接线验收（口径 1-4）----------

    fn s5_udp_config(udp_enabled: bool) -> RillaneConfig {
        RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig {
                enabled: udp_enabled,
                ..Default::default()
            },
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        }
    }

    fn s5_runtime_config(enable_chain: bool, udp_allow_plaintext: bool) -> RuntimeConfig {
        RuntimeConfig {
            enable_mesh: true,
            enable_chain,
            enable_hot_reload: false,
            mesh_config: Some(MeshConfig {
                node_id: "s5-client".into(),
                role: "client".into(),
                listen_address: "127.0.0.1:19091".parse().unwrap(),
                allow_plaintext_data_plane: true, // TCP 面门绕过（本组只验 UDP 门）
                udp_allow_plaintext_data_plane: udp_allow_plaintext,
                ..MeshConfig::default()
            }),
            ..RuntimeConfig::default()
        }
    }

    /// T3 装配钉（tun-dataplane.md §2.6/§2.7）：Tun 模式 + 虚拟化开 →
    /// build() 落 TunIngress（与 socks5 并列注入入口表）、NetworkManager 让位
    /// （防双设备）、UDP 块必建（TUN NAT 面共享连接器）、Process 规则派生
    /// has_process_rules、api_bind 入 auto-bypass 字面量集；未启用 → 全缺省。
    #[test]
    #[cfg(target_os = "linux")]
    fn t3_tun_mode_build_wiring() {
        let tun_platform_cfg = rillane_platform::network::NetworkConfig {
            mode: NetworkMode::Tun,
            tun: Some(rillane_platform::network::TunConfig {
                name: Some("rillaneT3".into()),
                ipv4_addr: Some("10.77.0.1".parse().unwrap()),
                ipv4_netmask: Some("255.255.255.0".parse().unwrap()),
                ..Default::default()
            }),
            routing: Some(rillane_platform::network::RoutingConfig {
                enabled: true,
                ..Default::default()
            }),
            filtering: None,
            dns: None,
        };
        let mut cfg = s5_udp_config(false);
        cfg.routing.rules.push(RouteRule {
            name: "game".into(),
            matches: vec![MatchCondition::Process {
                values: vec!["cs2".into()],
            }],
            target: "direct".into(),
        });
        let rc = RuntimeConfig {
            enable_network_virtualization: true,
            network_config: Some(tun_platform_cfg),
            ..RuntimeConfig::default()
        };
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(rc)
            .build()
            .expect("Tun 模式 build 应成功（设备 I/O 归 start()）");

        let tun = runtime.get_tun_ingress().expect("TunIngress 应装配");
        assert!(
            runtime.network_manager.is_none(),
            "Tun 模式 NetworkManager 让位"
        );
        assert!(
            runtime.udp_service.is_some(),
            "tun_enabled → UDP 块必建（连接器共享）"
        );
        assert!(runtime.ingress_endpoints.contains_key("tun"));
        assert!(
            runtime.ingress_endpoints.contains_key("in1"),
            "socks5 入口与 TUN 并列共存"
        );
        assert!(tun.config().has_process_rules, "Process 规则应派生归因开关");
        // Direct 无远端 server；唯一字面量 = control.api_bind（127.0.0.1:0）
        let literals = &tun.config().auto_bypass_literals;
        assert_eq!(literals.len(), 1, "api_bind 半边入集：{literals:?}");
        assert!(literals[0].matches("127.0.0.1".parse().unwrap()));
        assert!(tun.config().auto_bypass_hosts.is_empty());

        // 未启用虚拟化 → 全缺省（不建 TUN/NetworkManager，UDP 块随全局关）
        let plain = RuntimeBuilder::new(s5_udp_config(false))
            .build()
            .expect("build");
        assert!(plain.get_tun_ingress().is_none());
        assert!(plain.network_manager.is_none());
        assert!(plain.udp_service.is_none());
    }

    /// TUN-only 启动（tun-dataplane.md「TUN-only 独立启动」后续项）：
    /// 空 ingress + network.mode=tun → validate 放行，TUN 为唯一入口；
    /// 非 Tun 时空 ingress 维持拒绝。
    #[test]
    #[cfg(target_os = "linux")]
    fn tun_only_config_builds_with_tun_as_sole_ingress() {
        let tun_platform_cfg = rillane_platform::network::NetworkConfig {
            mode: NetworkMode::Tun,
            tun: Some(rillane_platform::network::TunConfig {
                name: Some("rillaneT3".into()),
                ipv4_addr: Some("10.77.0.1".parse().unwrap()),
                ipv4_netmask: Some("255.255.255.0".parse().unwrap()),
                ..Default::default()
            }),
            routing: Some(rillane_platform::network::RoutingConfig {
                enabled: true,
                ..Default::default()
            }),
            filtering: None,
            dns: None,
        };
        let mut cfg = s5_udp_config(false);
        cfg.ingress.clear();
        let rc = RuntimeConfig {
            enable_network_virtualization: true,
            network_config: Some(tun_platform_cfg),
            ..RuntimeConfig::default()
        };
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(rc)
            .build()
            .expect("TUN-only build 应成功（设备 I/O 归 start()）");
        assert!(runtime.get_tun_ingress().is_some());
        assert!(
            runtime.ingress_endpoints.keys().all(|k| k == "tun"),
            "TUN 应为唯一入口：{:?}",
            runtime.ingress_endpoints.keys().collect::<Vec<_>>()
        );

        // 无 network 块的空 ingress 维持拒绝（豁免面仅 Tun 模式）
        let mut plain = s5_udp_config(false);
        plain.ingress.clear();
        let err = RuntimeBuilder::new(plain)
            .build()
            .err()
            .expect("空 ingress 且非 Tun 模式应拒");
        assert!(err.to_string().contains("至少需要配置一个入口"), "{err:#}");
    }

    /// 出站 fwmark 配置接线（networking.md §2 direct 出口自环逃逸半边①）：
    /// `network.egress_fwmark: Some(m)` → build 期 `set_egress_fwmark` 生效
    /// （net_mark 读回）；缺省 None 不触碰（存量零差异，且同进程并行 build
    /// 不互踩）。
    #[test]
    fn egress_fwmark_config_wires_net_mark() {
        let mut cfg = s5_udp_config(false);
        cfg.network = Some(rillane_config::NetworkBlockConfig {
            sniff: None,
            mode: rillane_config::NetworkBlockMode::Tun,
            tun: None,
            routing: None,
            dns: None,
            egress_fwmark: Some(0x5E45),
        });
        let _rt = RuntimeBuilder::new(cfg).build().expect("build");
        assert_eq!(
            rillane_core::net_mark::egress_fwmark(),
            0x5E45,
            "build 期应设定出站 fwmark"
        );
        // 进程级单例复位（防泄漏到后续测试）
        rillane_core::net_mark::set_egress_fwmark(0);
    }

    /// 口径 1：chain+udp 同启 + 显式允许明文 → build 成功；mesh-chain 装配落位
    /// （UDP 门折叠值与 §8 故障事件通道均在——chain 决策 UDP 可达的装配证据，
    /// 端到端往返归 §10 T2/S6）。
    #[tokio::test]
    async fn s5_chain_udp_build_wires_mesh_bridge_and_event_channel() {
        let runtime = RuntimeBuilder::new(s5_udp_config(true))
            .with_runtime_config(s5_runtime_config(true, true))
            .build()
            .expect("chain+udp+显式明文应 build 成功");
        assert!(
            runtime.mesh_udp_gate.is_some(),
            "chain+udp 同启应装配 UDP 门折叠值"
        );
        assert!(
            runtime.chain_failure_tx.is_some(),
            "chain+udp 同启应装配 §8 故障事件通道"
        );
    }

    /// 口径 4：chain+udp 无 tls 未显式允许明文 → build 期拒绝（client 桥构造点），
    /// 信息含开关名。
    #[tokio::test]
    async fn s5_chain_udp_plaintext_gate_rejects_at_build() {
        let err = RuntimeBuilder::new(s5_udp_config(true))
            .with_runtime_config(s5_runtime_config(true, false))
            .build()
            .err()
            .expect("tls=None 且未允许明文应 build 期拒绝");
        assert!(
            format!("{err:#}").contains("RILLANE_MESH_UDP_ALLOW_PLAINTEXT"),
            "错误信息应含开关名: {err:#}"
        );
    }

    /// 口径 2：无 chain → 等价 P0-3（UDP 块照常构建，mesh 接线零挂载）。
    #[tokio::test]
    async fn s5_udp_without_chain_matches_p03_wiring() {
        let runtime = RuntimeBuilder::new(s5_udp_config(true))
            .with_runtime_config(s5_runtime_config(false, false))
            .build()
            .expect("无 chain 的 udp 构建应等价 P0-3");
        assert!(runtime.mesh_udp_gate.is_none());
        assert!(runtime.chain_failure_tx.is_none());
    }

    /// 口径 3：关 udp → 零差异（chain 仅 TCP 面，门与事件通道均不装配）。
    #[tokio::test]
    async fn s5_chain_without_udp_is_unchanged() {
        let runtime = RuntimeBuilder::new(s5_udp_config(false))
            .with_runtime_config(s5_runtime_config(true, false))
            .build()
            .expect("关 udp 的 chain 构建应零差异");
        assert!(runtime.mesh_udp_gate.is_none());
        assert!(runtime.chain_failure_tx.is_none());
    }

    // ---------- P2-8 M1 dns-partition.md §4-4 DNS 服务装配 ----------

    /// network.dns 块在场（enabled）→ `get_dns_service()` Some 且监听地址 =
    /// 配置形；块缺席 → None 零差异。启停生命周期与端到端查询归
    /// dns_config.rs 单测（builder 层只钉装配面）。
    #[tokio::test]
    async fn dns_block_builds_service_and_absent_is_none() {
        let present = {
            let mut cfg = s5_udp_config(true);
            cfg.network = Some(rillane_config::NetworkBlockConfig {
                sniff: None,
                egress_fwmark: None,
                mode: rillane_config::NetworkBlockMode::Tun,
                tun: None,
                routing: None,
                dns: Some(
                    serde_yaml::from_str::<rillane_config::DnsBlockConfig>(
                        "trusted: ['1.1.1.1:53']\ndefault_group: trusted\nlisten_port: 15353",
                    )
                    .expect("dns 块应可解析"),
                ),
            });
            cfg
        };
        let runtime = RuntimeBuilder::new(present)
            .with_runtime_config(s5_runtime_config(false, false))
            .build()
            .expect("dns 块在场应 build 成功");
        let svc = runtime
            .get_dns_service()
            .expect("dns 块在场应装配 DnsService");
        assert_eq!(
            svc.listen().to_string(),
            "127.0.0.1:15353",
            "监听地址应承接配置"
        );
        assert!(
            svc.stats_snapshot().total_queries == 0,
            "装配期零查询（不拨上游）"
        );

        let runtime = RuntimeBuilder::new(s5_udp_config(true))
            .with_runtime_config(s5_runtime_config(false, false))
            .build()
            .expect("无 dns 块应 build 成功");
        assert!(
            runtime.get_dns_service().is_none(),
            "块缺席应 None（零差异）"
        );
    }

    /// enabled=false 的 dns 块 → 装配 None（临时下线语义，dns-partition.md
    /// §2.5 口径对齐 obfuscation）。
    #[tokio::test]
    async fn dns_block_disabled_builds_none() {
        let mut cfg = s5_udp_config(true);
        cfg.network = Some(rillane_config::NetworkBlockConfig {
            sniff: None,
            egress_fwmark: None,
            mode: rillane_config::NetworkBlockMode::Tun,
            tun: None,
            routing: None,
            dns: Some(
                serde_yaml::from_str::<rillane_config::DnsBlockConfig>(
                    "enabled: false\ndomestic: ['not-an-addr']",
                )
                .expect("半配置应可解析"),
            ),
        });
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(s5_runtime_config(false, false))
            .build()
            .expect("关闭态半配置应零差异 build 成功");
        assert!(runtime.get_dns_service().is_none(), "关闭态应 None");
    }

    /// G1-10 M2 边界守卫：fake_ip 启用 + TUN 模式 → build 拒绝（TUN 入口
    /// 回填未接线，假地址无反查改写则出口不可达——构建期显式拒绝而非静默
    /// 断流）。虚拟化关闭时同配置照常装配（socks5 入口已有回填）。
    #[test]
    #[cfg(target_os = "linux")]
    fn fake_ip_with_tun_mode_build_rejected() {
        let mk_cfg = || {
            let mut cfg = s5_udp_config(false);
            cfg.network = Some(rillane_config::NetworkBlockConfig {
                sniff: None,
                egress_fwmark: None,
                mode: rillane_config::NetworkBlockMode::Tun,
                tun: None,
                routing: None,
                dns: Some(
                    serde_yaml::from_str::<rillane_config::DnsBlockConfig>(
                        "trusted: ['1.1.1.1:53']\ndefault_group: trusted\nfake_ip: {}",
                    )
                    .expect("dns 块应可解析"),
                ),
            });
            cfg
        };
        let tun_platform_cfg = rillane_platform::network::NetworkConfig {
            mode: NetworkMode::Tun,
            tun: Some(rillane_platform::network::TunConfig {
                name: Some("rillaneFakeIp".into()),
                ..Default::default()
            }),
            routing: Some(rillane_platform::network::RoutingConfig {
                enabled: true,
                ..Default::default()
            }),
            filtering: None,
            dns: None,
        };
        let rc = RuntimeConfig {
            enable_network_virtualization: true,
            network_config: Some(tun_platform_cfg),
            ..RuntimeConfig::default()
        };
        let err = RuntimeBuilder::new(mk_cfg())
            .with_runtime_config(rc)
            .build()
            .err()
            .expect("fake_ip + TUN 应构建期拒绝");
        assert!(
            err.to_string().contains("fake_ip"),
            "错误应点名 fake_ip：{err:#}"
        );

        // 非 TUN（虚拟化关）→ fake_ip 照常装配（池表交 DNS 服务 + 入口面）
        let rc_off = RuntimeConfig {
            enable_network_virtualization: false,
            network_config: None,
            ..RuntimeConfig::default()
        };
        let runtime = RuntimeBuilder::new(mk_cfg())
            .with_runtime_config(rc_off)
            .build()
            .expect("非 TUN 下 fake_ip 应装配");
        let svc = runtime.get_dns_service().expect("DNS 服务应在");
        assert!(svc.fake_ip().is_some(), "fake-ip 池应装配");
    }

    /// G2-15 hosts 映射：非空 network.dns.hosts → DnsHosts 表装配 DNS 服务
    ///（svc.hosts() 精确小写命中返回映射地址）；缺省零装配 None；非法值
    /// 构建期拒绝。
    #[test]
    fn hosts_mapping_wired_into_dns_service() {
        let mk_cfg = |dns_yaml: &str| {
            let mut cfg = s5_udp_config(false);
            cfg.network = Some(rillane_config::NetworkBlockConfig {
                sniff: None,
                egress_fwmark: None,
                mode: rillane_config::NetworkBlockMode::Tun,
                tun: None,
                routing: None,
                dns: Some(
                    serde_yaml::from_str::<rillane_config::DnsBlockConfig>(dns_yaml)
                        .expect("dns 块应可解析"),
                ),
            });
            cfg
        };
        let mk_rc = || RuntimeConfig {
            enable_network_virtualization: false,
            network_config: None,
            ..RuntimeConfig::default()
        };

        // 有映射：装配且命中语义正确（键小写归一可辨）
        let runtime = RuntimeBuilder::new(mk_cfg(
            "trusted: ['1.1.1.1:53']\ndefault_group: trusted\nhosts:\n  \"a.test\": \"10.0.0.7\"\n  \"V6.Test\": \"::1\"",
        ))
        .with_runtime_config(mk_rc())
        .build()
        .expect("hosts 映射应装配");
        let hosts = runtime
            .get_dns_service()
            .expect("DNS 服务应在")
            .hosts()
            .expect("hosts 表应装配");
        assert_eq!(hosts.len(), 2);
        assert_eq!(
            hosts.lookup("a.test", true),
            Some(vec![std::net::IpAddr::from([10, 0, 0, 7])])
        );
        assert_eq!(
            hosts.lookup("v6.test", false),
            Some(vec![std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])])
        );
        assert_eq!(hosts.lookup("other.test", true), None);

        // 非法值：构建期拒绝（错误点名 dns.hosts）
        let err = RuntimeBuilder::new(mk_cfg(
            "trusted: ['1.1.1.1:53']\nhosts:\n  \"a.test\": \"bad\"",
        ))
        .with_runtime_config(mk_rc())
        .build()
        .err()
        .expect("非法 hosts 值应构建期拒绝");
        assert!(
            format!("{err:#}").contains("dns.hosts"),
            "错误应点名 dns.hosts：{err:#}"
        );

        // 缺省（无 hosts 键）：零装配 None（存量零差异）
        let runtime =
            RuntimeBuilder::new(mk_cfg("trusted: ['1.1.1.1:53']\ndefault_group: trusted"))
                .with_runtime_config(mk_rc())
                .build()
                .expect("缺省应装配");
        assert!(
            runtime
                .get_dns_service()
                .expect("DNS 服务应在")
                .hosts()
                .is_none(),
            "无 hosts 键应零装配"
        );
    }

    /// G1-9 审核发现（2026-11-10）修复验证：url-test 周期探活任务已接入
    /// start()——此前 `RoutingEngine::start_health_check_task`（rillane-routing
    /// lib.rs:437）在 start() 任务区无调用点，探测句柄虽注入（runtime_builder
    /// :199）仍永不探活，健康/延迟表恒空。start 后首轮 tick（interval 首拍
    /// 立即）即探活：无出口成员经探测句柄 Err → 标不健康（此前恒默认健康
    /// true），不产生真实探测流量。
    #[tokio::test]
    async fn urltest_health_task_wired_into_start() {
        let mut cfg = s5_udp_config(false);
        cfg.routing = rillane_config::RoutingConfig {
            default_node: "direct".to_string(),
            scenarios: Vec::new(),
            groups: vec![rillane_config::PolicyGroup {
                name: "auto".to_string(),
                strategy: rillane_config::Strategy::Latency,
                members: vec![rillane_config::GroupMember::Node {
                    name: "no-such-node".to_string(),
                }],
                slo: None,
                url_test: Some(rillane_config::UrlTestConfig {
                    probe: "127.0.0.1:80".to_string(),
                    path: "/generate_204".to_string(),
                    interval_secs: 300,
                    timeout_ms: 500,
                }),
            }],
            rules: vec![],
            ..Default::default()
        };
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_network_virtualization: false,
                network_config: None,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("url_test 组应装配");
        let tasks = runtime.start().await.expect("start 应成功");

        // 首轮 tick 立即执行：无出口成员被探活标不健康（此前 bug 健康表恒空
        // ——get_health_stats 总为 (0,0)）。探活 Err → 标不健康：(healthy, total)
        // = (0,1) 即表非空且该成员不健康。
        let mut marked = false;
        for _ in 0..100 {
            if runtime.router.get_health_stats() == (0, 1) {
                marked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            marked,
            "url_test 周期探活应标记无出口成员不健康（健康表不再恒空）"
        );
        for t in tasks {
            t.abort();
        }
    }

    /// build 期拦截：enabled 块 + 双空 domestic 引用（无 tun 回落）→ Err
    /// 带指引（E1 面在 build() 前置，不带病启动）。
    #[tokio::test]
    async fn dns_block_referenced_empty_group_rejected_at_build() {
        let mut cfg = s5_udp_config(true);
        cfg.network = Some(rillane_config::NetworkBlockConfig {
            sniff: None,
            egress_fwmark: None,
            mode: rillane_config::NetworkBlockMode::Tun,
            tun: None,
            routing: None,
            dns: Some(
                serde_yaml::from_str::<rillane_config::DnsBlockConfig>("trusted: ['1.1.1.1:53']")
                    .expect("dns 块应可解析"),
            ),
        });
        let err = RuntimeBuilder::new(cfg)
            .with_runtime_config(s5_runtime_config(false, false))
            .build()
            .err()
            .expect("default=domestic 双空应 build 期拒绝");
        assert!(
            format!("{err:#}").contains("tun.dns_servers"),
            "错误应指引回落面: {err:#}"
        );
    }

    // ---------- P0-5 §10-S3 mesh 面观测装配 ----------

    /// 测试 3：start() 于 spawn_udp 后回填 mesh_plane（relay 角色 + chain+udp+
    /// 显式明文、listen 127.0.0.1:0）→ `get_mesh_udp_snapshot()` Some 且零流量
    /// 全零；client-only build（无面路径，复用 s5 helper）恒 None 同测钉住。
    #[tokio::test]
    async fn runtime_mesh_plane_backfilled_after_start() {
        // —— 非 client 角色：数据面监听 + UDP 面拉起 → OnceLock 回填 ——
        let relay_rc = RuntimeConfig {
            enable_mesh: true,
            enable_chain: true,
            enable_hot_reload: false,
            mesh_config: Some(MeshConfig {
                node_id: "s3-relay".into(),
                role: "relay".into(),
                listen_address: "127.0.0.1:0".parse().unwrap(),
                allow_plaintext_data_plane: true, // TCP 面门绕过（本测只验 UDP 面回填）
                udp_allow_plaintext_data_plane: true,
                ..MeshConfig::default()
            }),
            ..RuntimeConfig::default()
        };
        let runtime = RuntimeBuilder::new(s5_udp_config(true))
            .with_runtime_config(relay_rc)
            .build()
            .expect("chain+udp+显式明文应 build 成功");
        assert!(
            runtime.get_udp_client_metrics().is_some(),
            "chain+udp 桥构建应抽出 client 计数（观测接缝③）"
        );
        assert_eq!(
            runtime.get_mesh_udp_snapshot(),
            None,
            "start() 前 OnceLock 未回填"
        );
        let tasks = runtime.start().await.expect("start 应成功");
        let snap = runtime
            .get_mesh_udp_snapshot()
            .expect("spawn_udp 后应回填 mesh_plane（观测接缝②）");
        assert_eq!(snap, UdpFaceSnapshot::default(), "零流量面快照全零");

        // —— client-only（s5 helper：role=client）：无数据面监听路径 → 恒 None ——
        let client = RuntimeBuilder::new(s5_udp_config(true))
            .with_runtime_config(s5_runtime_config(true, true))
            .build()
            .expect("client-only 应 build 成功");
        let client_tasks = client.start().await.expect("start 应成功");
        assert_eq!(
            client.get_mesh_udp_snapshot(),
            None,
            "client 无 data-plane 面（拓扑：只有出站 relay）"
        );

        for t in tasks.iter().chain(client_tasks.iter()) {
            t.abort();
        }
    }

    // ---------- P0-3 UDP 能力扫描 ----------

    fn node(name: &str, spec: EgressConfig) -> EgressDescriptor {
        EgressDescriptor {
            name: name.to_string(),
            spec,
        }
    }

    fn group(name: &str, members: &[(&str, u32)]) -> PolicyGroup {
        PolicyGroup {
            name: name.to_string(),
            strategy: Strategy::Weighted,
            members: members
                .iter()
                .map(|(n, w)| GroupMember::WeightedNode {
                    name: n.to_string(),
                    weight: *w,
                })
                .collect(),
            slo: None,
            url_test: None,
        }
    }

    fn rule(name: &str, target: &str) -> RouteRule {
        RouteRule {
            name: name.to_string(),
            matches: vec![MatchCondition::DomainSuffix {
                values: vec!["test".into()],
            }],
            target: target.to_string(),
        }
    }

    fn ss_spec() -> EgressConfig {
        EgressConfig::Shadowsocks {
            server: "127.0.0.1".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "pw".into(),
            plugin: None,
            plugin_opts: None,
        }
    }

    fn vmess_spec() -> EgressConfig {
        EgressConfig::Vmess {
            server: "127.0.0.1".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            alter_id: 0,
            security: "auto".into(),
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            tls: false,
            skip_cert_verify: false,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    }

    fn trojan_spec() -> EgressConfig {
        EgressConfig::Trojan {
            server: "127.0.0.1".into(),
            port: 443,
            password: "x".into(),
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            tls: true,
            skip_cert_verify: false,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    }

    fn vless_spec() -> EgressConfig {
        EgressConfig::Vless {
            server: "127.0.0.1".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: None,
            packet_encoding: None,
            tls: false,
            skip_cert_verify: false,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    }

    #[test]
    fn build_egress_outputs_carries_vless_flow_and_reality() {
        // G1-6（2026-11-10 拍板改 M1 拒绝策略）：flow/reality 不再构建期判负，
        // 配置随连接器保留、拨号期点名拒绝——含 flow+REALITY 的节点必须装配
        // 成功（节点级失败不拖垮整份订阅，url-test 探活标记不健康即可）。
        let mut with_g6 = vless_spec();
        if let EgressConfig::Vless { flow, reality, .. } = &mut with_g6 {
            *flow = Some("xtls-rprx-vision".to_string());
            *reality = Some(rillane_config::RealityConfig {
                public_key: "pbk-test".to_string(),
                short_id: Some("ab12".to_string()),
            });
        }
        let egress = vec![node("vl-g6", with_g6)];
        let (outputs, connectors) =
            build_egress_outputs(&egress, None, None).expect("flow+reality 应装配成功（保留面）");
        assert!(outputs.contains_key("vl-g6"));
        assert_eq!(connectors.get("vl-g6").expect("connector").name(), "vless");

        // flow/reality 缺省照常装配
        let egress = vec![node("vl-ok", vless_spec())];
        let (outputs, connectors) =
            build_egress_outputs(&egress, None, None).expect("无 flow 应装配成功");
        assert!(outputs.contains_key("vl-ok"));
        assert_eq!(connectors.get("vl-ok").expect("connector").name(), "vless");
    }

    #[test]
    fn udp_capability_scan_passes_when_all_reachable_are_capable() {
        // G0-4：vmess/vless/trojan（network=tcp）入能力表
        let egress = vec![
            node("direct-out", EgressConfig::Direct),
            node("ss-out", ss_spec()),
            node("vm-out", vmess_spec()),
            node("vl-out", vless_spec()),
            node("tj-out", trojan_spec()),
        ];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        let routing = RoutingConfig {
            default_node: "direct-out".into(),
            scenarios: Vec::new(),
            groups: vec![group(
                "g",
                &[
                    ("ss-out", 1),
                    ("direct-out", 1),
                    ("vm-out", 1),
                    ("vl-out", 1),
                ],
            )],
            rules: vec![rule("r1", "g"), rule("r2", "tj-out")],
            ..Default::default()
        };
        assert!(scan_udp_capability(&routing, &egress, &connectors).is_ok());
        assert_eq!(connectors.len(), 5);
    }

    /// G0-5 UDP 面（审核发现 2026-11-04）：reject 出口注册为 UDP 连接器
    /// （RejectUdpConnector），reachable 的 reject 节点不再被 scan_udp_capability
    /// 判负——广告/黑名单目标 + udp.enabled 不再整机构建失败。
    #[test]
    fn udp_capability_scan_passes_with_reject_reachable() {
        let egress = vec![
            node("block-ads", EgressConfig::Reject),
            node("direct-out", EgressConfig::Direct),
        ];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        assert!(connectors.contains_key("block-ads"), "reject 应注册连接器");
        let routing = RoutingConfig {
            default_node: "direct-out".into(),
            scenarios: Vec::new(),
            groups: vec![],
            rules: vec![rule("ads", "block-ads")],
            ..Default::default()
        };
        assert!(
            scan_udp_capability(&routing, &egress, &connectors).is_ok(),
            "reject 目标不应使 UDP 能力扫描失败"
        );
    }

    #[test]
    fn udp_capability_scan_fails_listing_offending_nodes_and_sources() {
        // default_node=vmess-ws（network=ws 无 UDP 面）+ rule target 指向
        // hy2-obfs（RIL-133：obfs 判负——salamander 换整个 QUIC 载荷）
        let mut vmess_ws = vmess_spec();
        if let EgressConfig::Vmess { network, .. } = &mut vmess_ws {
            *network = "ws".into();
        }
        let egress = vec![
            node("vmess-ws", vmess_ws),
            node(
                "hy2-out",
                EgressConfig::Hysteria2 {
                    server: "127.0.0.1".into(),
                    port: 443,
                    password: "x".into(),
                    mport: None,
                    obfs: Some("salamander".into()),
                    obfs_param: Some("ob".into()),
                    server_name: None,
                    skip_cert_verify: false,
                    alpn: None,
                },
            ),
        ];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        assert!(connectors.is_empty(), "vmess-ws/hy2-obfs 均不产 UDP 连接器");
        let routing = RoutingConfig {
            default_node: "vmess-ws".into(),
            scenarios: Vec::new(),
            groups: vec![group("g", &[("hy2-out", 1)])],
            rules: vec![rule("r1", "g")],
            ..Default::default()
        };
        let err = scan_udp_capability(&routing, &egress, &connectors)
            .expect_err("UDP 不可达节点应使构建失败");
        let msg = format!("{err:#}");
        assert!(msg.contains("vmess-ws"), "应点名 vmess-ws: {msg}");
        assert!(
            msg.contains("default_node"),
            "应标注来源 default_node: {msg}"
        );
        assert!(msg.contains("hy2-out"), "应点名 hy2-out: {msg}");
        assert!(
            msg.contains("rule:r1") || msg.contains("group:g"),
            "应标注来源: {msg}"
        );
    }

    /// RIL-133：基础组合（无 obfs）的 hy2 产 UDP 连接器（数据报自写面），
    /// 作为 default_node 可过扫描
    #[test]
    fn udp_capability_scan_admits_plain_hysteria2() {
        let egress = vec![node(
            "hy2-out",
            EgressConfig::Hysteria2 {
                server: "127.0.0.1".into(),
                port: 443,
                password: "x".into(),
                mport: None,
                obfs: None,
                obfs_param: None,
                server_name: None,
                skip_cert_verify: false,
                alpn: None,
            },
        )];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        assert_eq!(connectors.len(), 1, "基础 hy2 应产 UDP 连接器");
        let routing = RoutingConfig {
            default_node: "hy2-out".into(),
            scenarios: Vec::new(),
            groups: vec![],
            rules: vec![],
            ..Default::default()
        };
        assert!(scan_udp_capability(&routing, &egress, &connectors).is_ok());
    }

    #[test]
    fn udp_capability_scan_skips_non_egress_targets() {
        // 规则目标指向 mesh 节点（非本配置出站节点）→ 不报错
        let egress = vec![node("ss-out", ss_spec())];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        let routing = RoutingConfig {
            default_node: "ss-out".into(),
            scenarios: Vec::new(),
            groups: vec![],
            rules: vec![rule("r1", "mesh.exit1")],
            ..Default::default()
        };
        assert!(scan_udp_capability(&routing, &egress, &connectors).is_ok());
    }

    /// 回归：组环（g1→g2→g1）时 BFS 队列永不空，原实现 build 无限挂起。
    /// visited 集使同组二次遇及跳过，scan 必须终止。
    #[test]
    fn udp_capability_scan_terminates_on_group_cycle() {
        let egress = vec![node("direct-out", EgressConfig::Direct)];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        let g1 = PolicyGroup {
            name: "g1".into(),
            strategy: Strategy::Weighted,
            members: vec![GroupMember::Group { name: "g2".into() }],
            slo: None,
            url_test: None,
        };
        let g2 = PolicyGroup {
            name: "g2".into(),
            strategy: Strategy::Weighted,
            members: vec![GroupMember::Group { name: "g1".into() }],
            slo: None,
            url_test: None,
        };
        let routing = RoutingConfig {
            default_node: "g1".into(),
            scenarios: Vec::new(),
            groups: vec![g1, g2],
            rules: vec![],
            ..Default::default()
        };
        // 同步函数若无限循环会挂起测试——线程 + 限时回收判定终止。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = scan_udp_capability(&routing, &egress, &connectors);
            let _ = tx.send(r);
        });
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("组环时 scan_udp_capability 必须终止而非无限挂起")
            .expect("组环应正常扫描（direct-out 有 UDP 能力）");
    }

    /// G0-4：vmess/vless/trojan 仅 network=tcp 注册 UDP 连接器；ws/grpc/h2
    /// 与 hysteria2 静默跳过（由能力扫描兜底报错）。
    #[test]
    fn udp_build_connectors_skips_unsupported_kinds() {
        let egress = vec![
            node("d", EgressConfig::Direct),
            node("v", vmess_spec()),
            node("vl", vless_spec()),
            node(
                "t",
                EgressConfig::Trojan {
                    server: "127.0.0.1".into(),
                    port: 443,
                    password: "x".into(),
                    network: "tcp".into(),
                    path: None,
                    host: None,
                    grpc_service_name: None,
                    grpc_reuse: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                    tls_fingerprint: None,
                },
            ),
        ];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        assert_eq!(connectors.len(), 4, "direct/vmess/vless/trojan(tcp) 全注册");
        assert!(connectors.contains_key("d"));
        assert!(connectors.contains_key("v"));
        assert!(connectors.contains_key("vl"));
        assert!(connectors.contains_key("t"));

        // network=ws 的 vmess 不注册（UDP 面未实现）
        let mut vmess_ws = vmess_spec();
        if let EgressConfig::Vmess { network, .. } = &mut vmess_ws {
            *network = "ws".into();
        }
        let egress = vec![node("v-ws", vmess_ws)];
        let connectors = build_udp_connectors(&egress, None, None).unwrap();
        assert!(connectors.is_empty(), "vmess ws 不应有 UDP 连接器");
    }

    // ---------- P0-5 §10-S2 运行时接线 ----------

    #[test]
    fn udp_session_config_mapping() {
        // 测试 1：纯函数逐字段断言（含 lifetime None/Some 两态），防「字段加了没接线」
        let mut cfg = UdpConfig {
            enabled: true,
            strict_udp_source: false,
            session_idle_secs: 300,
            mapping_idle_secs: 45,
            max_sessions: 128,
            sweep_interval_secs: 5,
            max_mappings: 64,
            session_lifetime_secs: None,
            downlink_queue_depth: 32,
            max_associates: 16,
        };
        let sc = udp_session_config(&cfg);
        assert_eq!(sc.session_idle, Duration::from_secs(300));
        assert_eq!(sc.mapping_idle, Duration::from_secs(45));
        assert_eq!(sc.sweep_interval, Duration::from_secs(5));
        assert_eq!(sc.max_sessions, 128);
        assert_eq!(sc.max_mappings, 64);
        assert_eq!(sc.session_max_lifetime, None);
        assert_eq!(sc.downlink_capacity, 32);

        cfg.session_lifetime_secs = Some(3600);
        assert_eq!(
            udp_session_config(&cfg).session_max_lifetime,
            Some(Duration::from_secs(3600))
        );

        // 缺省配置 = UdpSessionConfig::default 全字段一致（S0 缺省对齐）
        let d = udp_session_config(&UdpConfig::default());
        let dd = rillane_core::udp::UdpSessionConfig::default();
        assert_eq!(d.session_idle, dd.session_idle);
        assert_eq!(d.mapping_idle, dd.mapping_idle);
        assert_eq!(d.sweep_interval, dd.sweep_interval);
        assert_eq!(d.max_sessions, dd.max_sessions);
        assert_eq!(d.max_mappings, dd.max_mappings);
        assert_eq!(d.session_max_lifetime, dd.session_max_lifetime);
        assert_eq!(d.downlink_capacity, dd.downlink_capacity);
    }

    /// 找一个空闲端口（先绑后弃有竞态窗口，测试环境足够）
    fn free_bind() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("127.0.0.1:{}", l.local_addr().unwrap().port())
    }

    fn s2_config(
        udp: UdpConfig,
        socks_udp_enabled: Option<bool>,
        mixed_udp_enabled: Option<bool>,
    ) -> RillaneConfig {
        RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![
                IngressDescriptor {
                    name: "s2-socks".to_string(),
                    spec: IngressConfig::Socks5 {
                        bind: free_bind(),
                        auth: None,
                        udp_enabled: socks_udp_enabled,
                    },
                },
                IngressDescriptor {
                    name: "s2-mixed".to_string(),
                    spec: IngressConfig::Mixed {
                        bind: free_bind(),
                        auth: None,
                        udp_enabled: mixed_udp_enabled,
                        bearer_tokens: None,
                    },
                },
            ],
            egress: vec![EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            }],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp,
            network: None,
            obfuscation: None,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            egress_pool: None,
            probe: None,
        }
    }

    fn s2_runtime_config() -> RuntimeConfig {
        RuntimeConfig {
            enable_hot_reload: false,
            ..RuntimeConfig::default()
        }
    }

    /// 对指定 bind 发 SOCKS5 无认证握手 + CMD 0x03，返回 REP 码
    async fn associate_rep(bind: &str) -> u8 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // start() 内 ingress bind 异步发生——带重试等待监听就绪
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut s = None;
        while s.is_none() {
            match tokio::net::TcpStream::connect(bind).await {
                Ok(stream) => s = Some(stream),
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(e) => panic!("connect {bind} 失败: {e}"),
            }
        }
        let mut s = s.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.unwrap();
        assert_eq!(method[0], 0x05);
        // 请求帧：VER CMD(0x03) RSV ATYP=0x01 DST=0.0.0.0:0（全零 IPv4）
        s.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        reply[1]
    }

    fn socks_bind(cfg: &RillaneConfig) -> String {
        match &cfg.ingress[0].spec {
            IngressConfig::Socks5 { bind, .. } => bind.clone(),
            _ => unreachable!(),
        }
    }

    fn mixed_bind(cfg: &RillaneConfig) -> String {
        match &cfg.ingress[1].spec {
            IngressConfig::Mixed { bind, .. } => bind.clone(),
            _ => unreachable!(),
        }
    }

    /// s2 组互斥：free_bind 的「探端口→释放→复绑」窗口在并行测试下会
    /// 被同组其他测试偷走（TOCTOU——复绑前端口回到内核空闲池）——组内
    /// 串行化让绑定/探测时序确定可重放
    static S2_BIND_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn per_ingress_override_disabled_entry_rejects_associate() {
        // 测试 2：全局开 + socks5 显式 false → 该入口 0x07；mixed（None 继承）可受理
        let _guard = S2_BIND_GUARD.lock().await;
        let cfg = s2_config(
            UdpConfig {
                enabled: true,
                ..Default::default()
            },
            Some(false),
            None,
        );
        let socks = socks_bind(&cfg);
        let mixed = mixed_bind(&cfg);
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(s2_runtime_config())
            .build()
            .expect("全局开 + per-ingress 覆盖应 build 成功");
        assert!(runtime.get_udp_service().is_some());
        let tasks = runtime.start().await.expect("start 应成功");

        assert_eq!(associate_rep(&socks).await, 0x07, "显式关闭入口应回 0x07");
        assert_eq!(
            associate_rep(&mixed).await,
            0x00,
            "继承全局的 mixed 入口应受理"
        );
        for t in tasks {
            t.abort();
        }
    }

    #[tokio::test]
    async fn per_ingress_override_true_enables_when_global_off() {
        // 测试 3：全局关 + mixed 显式 true → 该入口可受理；socks5（None）回 0x07。
        // 构建期 WARN 不强测（判定与装配为准）；UDP 服务因覆盖而构建。
        let _guard = S2_BIND_GUARD.lock().await;
        let cfg = s2_config(UdpConfig::default(), None, Some(true));
        let socks = socks_bind(&cfg);
        let mixed = mixed_bind(&cfg);
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(s2_runtime_config())
            .build()
            .expect("全局关 + 显式开覆盖应 build 成功且构建 UDP 服务");
        assert!(
            runtime.get_udp_service().is_some(),
            "per-ingress Some(true) 应触发 UDP 块构建"
        );
        let tasks = runtime.start().await.expect("start 应成功");

        assert_eq!(
            associate_rep(&mixed).await,
            0x00,
            "显式开启的 mixed 入口应受理"
        );
        assert_eq!(
            associate_rep(&socks).await,
            0x07,
            "继承全局（关）的 socks5 应回 0x07"
        );
        for t in tasks {
            t.abort();
        }
    }

    #[tokio::test]
    async fn udp_disabled_all_ingress_closed() {
        // 测试 4（验收 #4 构建断言半边）：全局关且无覆盖 → 全部入口 0x07、无 UDP 服务
        let _guard = S2_BIND_GUARD.lock().await;
        let cfg = s2_config(UdpConfig::default(), None, None);
        let socks = socks_bind(&cfg);
        let mixed = mixed_bind(&cfg);
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(s2_runtime_config())
            .build()
            .expect("全局关应 build 成功");
        assert!(
            runtime.get_udp_service().is_none(),
            "UDP 全关时不应构建 UdpAssociateService"
        );
        let tasks = runtime.start().await.expect("start 应成功");

        assert_eq!(associate_rep(&socks).await, 0x07);
        assert_eq!(associate_rep(&mixed).await, 0x07);
        for t in tasks {
            t.abort();
        }
    }

    // -----------------------------------------------------------------------
    // P1-5 §4.1/§8.1 装配两态 + D-10 单例（M3）
    // -----------------------------------------------------------------------

    fn pool_assembly_config(egress_pool: Option<rillane_config::EgressPoolBlock>) -> RillaneConfig {
        RillaneConfig {
            version: rillane_config::ConfigVersion::default(),
            control: rillane_config::ControlConfig {
                api_bind: "127.0.0.1:0".to_string(),
                uds_path: None,
                admin_token: None,
            },
            telemetry: rillane_config::TelemetryConfig {
                log_level: "info".to_string(),
                enable_metrics: false,
                enable_tracing: false,
            },
            ingress: vec![IngressDescriptor {
                name: "in1".to_string(),
                spec: IngressConfig::Socks5 {
                    bind: "127.0.0.1:0".to_string(),
                    auth: None,
                    udp_enabled: None,
                },
            }],
            egress: vec![
                EgressDescriptor {
                    name: "direct".to_string(),
                    spec: EgressConfig::Direct,
                },
                EgressDescriptor {
                    name: "tr".to_string(),
                    spec: EgressConfig::Trojan {
                        server: "e.example".to_string(),
                        port: 443,
                        password: "pw".to_string(),
                        network: "tcp".to_string(),
                        path: None,
                        host: None,
                        grpc_service_name: None,
                        grpc_reuse: None,
                        tls: true,
                        skip_cert_verify: false,
                        sni: Some("sni.example".to_string()),
                        alpn: None,
                        tls_fingerprint: None,
                    },
                },
            ],
            routing: rillane_config::RoutingConfig {
                default_node: "direct".to_string(),
                scenarios: Vec::new(),
                groups: vec![],
                rules: vec![],
                ..Default::default()
            },
            udp: rillane_config::UdpConfig::default(),
            network: None,
            obfuscation: None,
            egress_pool,
            profile: None,
            scenarios: Default::default(),
            performance: None,
            probe: None,
        }
    }

    fn pool_block(yaml: &str) -> rillane_config::EgressPoolBlock {
        serde_yaml::from_str(yaml).expect("解析 egress_pool 块")
    }

    /// §4.1：块存在且 enabled → 池+工厂单例就位；getter 句柄同实例。
    #[test]
    fn egress_pool_enabled_builds_pool_and_factory_singletons() {
        let cfg = pool_assembly_config(Some(pool_block(
            "enabled: true\nmax_idle_per_key: 3\nmax_idle_global: 128\n",
        )));
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");

        let pool = runtime.get_transport_pool().expect("池应就位");
        let factory = runtime.get_tls_factory().expect("工厂应就位");
        let pool_again = runtime.get_transport_pool().expect("池应就位");
        assert!(
            Arc::ptr_eq(&pool, &pool_again),
            "getter 返回同实例（D-10 单例）"
        );
        // D-8 映射 + 策略挂池
        assert_eq!(pool.policy().max_idle_per_key, 3);
        assert_eq!(pool.policy().max_idle_global, 128);
        drop(pool_again);

        // 池借出对象键由 trojan 出站推导（此处仅验装配，dial 归连接器测试）
        drop(pool);
        drop(factory);
    }

    /// D-9：块缺席 → 双 None（不构池不注工厂）。
    #[test]
    fn egress_pool_absent_yields_none_handles() {
        let runtime = RuntimeBuilder::new(pool_assembly_config(None))
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");
        assert!(runtime.get_transport_pool().is_none());
        assert!(runtime.get_tls_factory().is_none());
    }

    /// §3.1「块存在即生效，独立于 enabled」：enabled=false 仅构工厂不构池。
    #[test]
    fn egress_pool_disabled_still_builds_factory() {
        let cfg = pool_assembly_config(Some(pool_block("enabled: false\n")));
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");
        assert!(runtime.get_transport_pool().is_none(), "未启用不构池");
        assert!(runtime.get_tls_factory().is_some(), "恢复半边独立生效");
    }

    /// D-10/§4.3：update_config 重连装配不重建池（实例 ptr 断言，warmth 存续）。
    #[tokio::test]
    async fn update_config_keeps_pool_singleton_alive() {
        let cfg = pool_assembly_config(Some(pool_block("enabled: true\n")));
        let runtime = RuntimeBuilder::new(cfg)
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("build runtime");
        let before = runtime.get_transport_pool().expect("池应就位");

        let mut new_cfg = pool_assembly_config(Some(pool_block("enabled: true\n")));
        new_cfg.egress.push(EgressDescriptor {
            name: "tr2".to_string(),
            spec: EgressConfig::Trojan {
                server: "e2.example".to_string(),
                port: 443,
                password: "pw".to_string(),
                network: "tcp".to_string(),
                path: None,
                host: None,
                grpc_service_name: None,
                grpc_reuse: None,
                tls: true,
                skip_cert_verify: false,
                sni: None,
                alpn: None,
                tls_fingerprint: None,
            },
        });
        runtime.update_config(new_cfg).await.expect("update");

        let after = runtime.get_transport_pool().expect("池应就位");
        assert!(Arc::ptr_eq(&before, &after), "热更新后池单例不重建");
        assert!(
            runtime.get_egress_connectors().contains_key("tr2"),
            "新出站已装配"
        );
    }

    /// D-7 warm 键推导：trojan tcp/ws 键与连接器 transport_key 同源（tcp
    /// SNI 缺省回退 server、ws SNI 归 Host 首值）、http-tls 主键、vless ws
    /// 双键，平文/无关出站不产键，跨条目同键去重。
    #[test]
    fn derive_tls_warm_keys_matches_connector_keys() {
        let egress = vec![
            EgressDescriptor {
                name: "tr".to_string(),
                spec: EgressConfig::Trojan {
                    server: "e.example".to_string(),
                    port: 443,
                    password: "pw".to_string(),
                    network: "tcp".to_string(),
                    path: None,
                    host: None,
                    grpc_service_name: None,
                    grpc_reuse: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: Some("sni.example".to_string()),
                    alpn: None,
                    tls_fingerprint: None,
                },
            },
            EgressDescriptor {
                name: "tr-nosni".to_string(),
                spec: EgressConfig::Trojan {
                    server: "t.example".to_string(),
                    port: 443,
                    password: "pw".to_string(),
                    network: "tcp".to_string(),
                    path: None,
                    host: None,
                    grpc_service_name: None,
                    grpc_reuse: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                    tls_fingerprint: None,
                },
            },
            EgressDescriptor {
                name: "trws".to_string(),
                spec: EgressConfig::Trojan {
                    server: "ws.example".to_string(),
                    port: 443,
                    password: "pw".to_string(),
                    network: "ws".to_string(),
                    path: Some("/ray".to_string()),
                    host: Some(vec!["cdn.example".to_string()]),
                    grpc_service_name: None,
                    grpc_reuse: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                    tls_fingerprint: None,
                },
            },
            EgressDescriptor {
                name: "vlws".to_string(),
                spec: EgressConfig::Vless {
                    server: "w.example".to_string(),
                    port: 443,
                    uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                    flow: None,
                    reality: None,
                    network: "ws".to_string(),
                    path: Some("/ws".to_string()),
                    host: Some(vec!["cdn.example".to_string()]),
                    grpc_service_name: None,
                    grpc_reuse: None,
                    xhttp_mode: None,
                    packet_encoding: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                    tls_fingerprint: None,
                },
            },
            EgressDescriptor {
                name: "plain".to_string(),
                spec: EgressConfig::Http {
                    server: "p.example".to_string(),
                    port: 8080,
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                    sni: None,
                    tls_fingerprint: None,
                },
            },
            EgressDescriptor {
                name: "direct".to_string(),
                spec: EgressConfig::Direct,
            },
        ];
        let keys = derive_tls_warm_keys(&egress).expect("REASON");
        assert_eq!(
            keys.len(),
            5,
            "trojan tcp×2（显式 sni / 缺省回退 server）+ trojan ws 键 + vless tcp/ws 双键"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "e.example",
                443,
                Some("sni.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "trojan 键与 forward_pooled 同源"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "t.example",
                443,
                Some("t.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "trojan tcp sni 缺省回退 server（借出键恒 Some，裸 None 键永不相交）"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "ws.example",
                443,
                Some("cdn.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "trojan ws 键（实际 SNI = sni ∥ Host 首值 ∥ server）"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "w.example",
                443,
                Some("w.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "vless tcp 主键（sni 缺省 = server）"
        );
        assert!(
            keys.contains(&TransportKey::tls(
                "w.example",
                443,
                Some("cdn.example"),
                false,
                &[],
                TlsFingerprint::None,
            )),
            "vless ws 分支键（实际 SNI = host 首值）"
        );

        // 同键多 egress 条目去重
        let dup = vec![
            egress[0].clone(),
            EgressDescriptor {
                name: "tr-again".to_string(),
                spec: egress[0].spec.clone(),
            },
        ];
        assert_eq!(
            derive_tls_warm_keys(&dup).expect("REASON").len(),
            1,
            "跨条目同键去重"
        );
    }

    /// P2-2 §7-3：mesh→routing 质量桥聚合——节点 p95 取相邻链路最差跳
    /// （max），loss 按 Σerrors/Σconnections 跨链路聚合，零连接记 0.0；
    /// 无 RTT 样本的节点不产出（D-3 只喂真实数据）。
    #[test]
    fn aggregate_link_quality_worst_hop_and_loss() {
        let registry = MeshRegistry::new();
        let link = |source: &str, target: &str, latency_ms: u32| rillane_mesh::LinkState {
            source: source.into(),
            target: target.into(),
            latency_ms,
            bandwidth_mbps: 100,
            packet_loss_rate: 0.0,
            last_updated: std::time::Instant::now(),
        };
        registry
            .update_link_state(link("client1", "relay1", 10))
            .unwrap();
        registry
            .update_link_state(link("relay1", "exit1", 80))
            .unwrap();
        registry
            .update_link_state(link("client1", "exit1", 30))
            .unwrap();
        registry.record_link_connection(&"relay1".to_string(), &"exit1".to_string());
        registry.record_link_connection(&"relay1".to_string(), &"exit1".to_string());
        registry.record_link_error(&"relay1".to_string(), &"exit1".to_string());

        let rows = aggregate_link_quality(&registry);
        let by_node: HashMap<String, (u32, f64)> =
            rows.into_iter().map(|(n, p, l)| (n, (p, l))).collect();

        // relay1 相邻链路 p95 = max(10, 80) = 80（最差跳），loss = 1/2
        assert_eq!(by_node.get("relay1"), Some(&(80, 0.5)));
        // client1 相邻链路 p95 = max(10, 30) = 30，无连接样本 → loss 0.0
        assert_eq!(by_node.get("client1"), Some(&(30, 0.0)));
        // exit1 相邻链路 p95 = max(80, 30) = 80，loss = 1/2（链路记双向节点）
        assert_eq!(by_node.get("exit1"), Some(&(80, 0.5)));
        // 未出现节点不产出
        assert_eq!(by_node.len(), 3);
    }
}
