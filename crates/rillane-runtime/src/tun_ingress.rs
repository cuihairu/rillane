//! TUN 入口（TunIngress）：UDP NAT 面 + TCP 用户态栈面（tun-dataplane.md §2）
//!
//! 所有权裁决：TunIngress 是 TUN 模式的属主——内部组合 LinuxTunProvider + LinuxRouteManager
//! （创建设备/设址/起路由在 run() 启动时完成，退出时 teardown），**不经 NetworkManager**。
//!
//! 运行循环架构（§2.9 死锁分析结论）：tun guard 全程由 run 循环持有（单任务独占
//! 设备 fd），事件枚举 select——读包/下行写/清扫各自成事件，写发生在 match 臂内
//! （select 语句结束即释放 guard 借用），读挂起时下行写仍可就绪，无锁竞争；
//! select 不加 biased（随机轮询防单方向饿死）。

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rillane_core::udp::table::classify_failure;
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    FailureType, Flow, FlowContext, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget,
    IngressEndpoint, RouteDecision, TargetProto,
};
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify};
use tracing::{debug, error, info, warn};

use rillane_platform::network::ipcodec::{
    build_udp_packet, parse_tcp_segment, parse_udp_datagram, UdpDatagram,
};
use rillane_platform::network::linux::{LinuxRouteManager, LinuxTunProvider};
use rillane_platform::network::route::{
    default_bypass_rules, RouteDestination, RoutingConfig as PlatformRoutingConfig,
};
use rillane_platform::network::tun::{PacketInfo, TunConfig, TunProvider};

use crate::sniff::{sniff_http_host, sniff_tls_sni, QuicCryptoReassembler, QuicSniffStep};
use crate::tun_process::{ProcessAttributor, ProcessInfo, SockProto};
use crate::tun_tcp::{EstablishedTcp, SmolTcpStream, TcpFlowKey, TcpOutcome, TunTcpStack};

/// 下行通道容量（下行任务 → run 循环写 tun）
const DOWNLINK_CHANNEL_CAP: usize = 1024;
/// 清扫周期
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// TunIngress 配置
#[derive(Debug, Clone)]
pub struct TunIngressConfig {
    /// TUN 设备配置
    pub tun: TunConfig,
    /// 路由配置
    pub routing: PlatformRoutingConfig,
    /// UDP 空闲超时（秒）
    pub udp_idle_secs: u64,
    /// TCP 空闲超时（秒）
    pub tcp_idle_secs: u64,
    /// 最大流条目数
    pub max_flows: usize,
    /// 路由规则中是否存在 MatchCondition::Process（§2.5：仅此情形做 /proc
    /// 归因扫描——fd 扫描贵，不该为无 Process 规则的配置买单）
    pub has_process_rules: bool,
    /// §2.7 auto-bypass 字面量集（构建期注入：egress 字面量地址 + api_bind +
    /// mesh listen/peer 字面量）
    pub auto_bypass_literals: Vec<RouteDestination>,
    /// §2.7 auto-bypass 域名集（egress server 为域名时——构建期不解析 DNS，
    /// run() 起始处解析后并入 set_auto_bypass）
    pub auto_bypass_hosts: Vec<String>,
    /// RIL-143 有界域名嗅探策略（off/on_demand/scope + 字节/时间双界；
    /// 缺省按需 = 既有嗅探行为零差异）
    pub sniff: rillane_config::SniffPolicy,
}

impl Default for TunIngressConfig {
    fn default() -> Self {
        Self {
            tun: TunConfig::default(),
            routing: PlatformRoutingConfig::default(),
            udp_idle_secs: 60,  // mapping_idle 同源
            tcp_idle_secs: 180, // session_idle 同源
            max_flows: 4096,    // P0-4 §3 R10 论证
            has_process_rules: false,
            auto_bypass_literals: Vec::new(),
            auto_bypass_hosts: Vec::new(),
            sniff: rillane_config::SniffPolicy::default(),
        }
    }
}

/// 流协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// 流键（五元组全量：src 归属进程/应用，多应用同目标不同流——dst-only 键
/// 会把两个进程发往同一 DNS 的流并为一条，归因与拆除面全错）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TunFlowKey {
    proto: Proto,
    src: SocketAddr,
    dst: SocketAddr,
}

/// 流条目
struct TunFlowEntry {
    /// 首包路由决策（粘滞，本流生命周期内不再重路由）
    decision: RouteDecision,
    /// 首包嗅探/路由所用目标（UDP 首包 QUIC SNI 覆写后固化，后续包复用
    /// 同一域名 target，避免每包以 IP 目标发送导致 relay 语义不一致）
    target: FlowTarget,
    /// UDP 出站 relay（None = 拆除中）
    relay: Option<Arc<dyn UdpRelay>>,
    /// 首包进程归因（§2.5；has_process_rules=false 时恒 None）
    process: Option<ProcessInfo>,
    last_active: Instant,
    /// 空闲回收期限（每包触达续期）
    expiry: Instant,
    /// 下行任务取消信号（sweep/evict/Route 族失败拆除时 notify）
    cancel: Arc<Notify>,
}

/// TunIngress 统计（平台无关面，独立于 tun_stats——非 Linux 编译单元的
/// 控制面恒渲染仍需引用；tun-dataplane.md §2.8）
pub use crate::tun_stats::TunIngressStats;

/// run 循环事件（事件枚举模式：select 产物先物化再 match，写 tun 的可变
/// 借用发生在 match 臂——借用检查与「读挂起时写可就绪」两全）
enum LoopEvent {
    Shutdown,
    Read(Result<(Bytes, PacketInfo)>),
    Downlink(Option<Bytes>),
    Sweep,
    /// §2.9 下行注入唤醒（SmolTcpStream 写入后 kick）：补一次 poll 出段
    TcpKick,
}

/// TunIngress（tun-dataplane.md §2）
pub struct TunIngress {
    config: TunIngressConfig,
    tun: TokioMutex<LinuxTunProvider>,
    route_manager: Arc<TokioMutex<LinuxRouteManager>>,
    flow_table: Arc<DashMap<TunFlowKey, TunFlowEntry>>,
    udp_connector: Arc<dyn EgressUdpConnector>,
    /// TUN TCP 用户态栈（§2.4/§2.9 T4；纯用户态——设备 I/O 仍在 run 循环）
    tcp: Arc<TunTcpStack>,
    /// run() 注入（runtime ingress 循环 @start() 的 router 通道），OnceLock
    /// 使构造期无需持有 runtime 全件
    flow_router: OnceLock<Arc<dyn FlowRouter>>,
    flow_output: OnceLock<Arc<dyn FlowOutput>>,
    stats: Arc<Mutex<TunIngressStats>>,
    /// 进程归因器（§2.5，TTL 30s 含负缓存）
    attributor: Arc<ProcessAttributor>,
    /// 下行包 IPv4 id 计数器
    ipv4_id: Arc<AtomicU16>,
    /// 关闭信号
    shutdown: Arc<Notify>,
    /// 按 UDP 五元组重组跨包 QUIC ClientHello
    quic_sniffers: Arc<DashMap<TunFlowKey, QuicCryptoReassembler>>,
}

impl TunIngress {
    /// 创建新的 TunIngress（不触碰设备/路由——I/O 全在 run()）
    pub fn new(config: TunIngressConfig, udp_connector: Arc<dyn EgressUdpConnector>) -> Self {
        let route_manager =
            LinuxRouteManager::new(config.routing.clone()).with_tun_config(config.tun.clone());
        // TCP 栈面（§2.4）：tun 本端地址作回程路由基准（前缀 = 掩码置位数）；
        // 栈内另恒压 0.0.0.0/0 兜底（任意源应用地址可达），MTU 定 socket 缓冲
        let local = config.tun.ipv4_addr.map(|a| {
            let prefix = config
                .tun
                .ipv4_netmask
                .map(|m| u32::from(m).count_ones() as u8)
                .unwrap_or(0);
            (a, prefix)
        });
        let tcp = Arc::new(TunTcpStack::new(local, config.tun.mtu));
        Self {
            tun: TokioMutex::new(LinuxTunProvider::new(config.tun.clone())),
            route_manager: Arc::new(TokioMutex::new(route_manager)),
            flow_table: Arc::new(DashMap::new()),
            udp_connector,
            tcp,
            flow_router: OnceLock::new(),
            flow_output: OnceLock::new(),
            stats: Arc::new(Mutex::new(TunIngressStats::default())),
            attributor: Arc::new(ProcessAttributor::new()),
            ipv4_id: Arc::new(AtomicU16::new(0)),
            shutdown: Arc::new(Notify::new()),
            quic_sniffers: Arc::new(DashMap::new()),
            config,
        }
    }

    /// 请求关闭（run 循环收到后走 teardown）
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// 配置只读面（控制面/测试：has_process_rules、auto-bypass 集等）
    pub fn config(&self) -> &TunIngressConfig {
        &self.config
    }

    /// 获取路由管理器（network-route.md §2.3：控制面 apply/clear/status 消费；
    /// 返回 Arc 保证与 run() 内部同一实例，操作级互斥由 manager 内部 Mutex 承担）
    pub fn route_manager(&self) -> Arc<TokioMutex<LinuxRouteManager>> {
        Arc::clone(&self.route_manager)
    }

    /// 注入路由器/出口（run() 由 IngressEndpoint 调用前；测试也可直注）
    pub fn set_endpoints(&self, router: Arc<dyn FlowRouter>, output: Arc<dyn FlowOutput>) {
        let _ = self.flow_router.set(router);
        let _ = self.flow_output.set(output);
    }

    fn router(&self) -> Arc<dyn FlowRouter> {
        self.flow_router
            .get()
            .expect("flow_router 未注入——先 set_endpoints/run")
            .clone()
    }

    /// 内部运行方法：设备生命周期 + §2.9 包循环 + teardown
    async fn run_internal(self: Arc<Self>) -> Result<()> {
        // 前置 fail-fast：set_endpoints 未注入（重构漂移/调用方漏接）时启动
        // 即 Err，而非运行期每包在 router()/flow_output 处 panic。
        if self.flow_router.get().is_none() || self.flow_output.get().is_none() {
            anyhow::bail!("flow_router/flow_output 未注入——run() 前须 set_endpoints");
        }
        // tun guard 全程持有（单任务独占设备；§2.9 事件枚举模式的基石）
        let mut tun_guard = self.tun.lock().await;
        tun_guard
            .create_interface()
            .await
            .context("创建 TUN 接口失败")?;
        let iface_name = tun_guard.name().to_string();

        // §2.7 auto-bypass 组装：字面量集（构建期）∪ 域名解析集（run 起始处，
        // 构建期不做 DNS）∪ tun 网段（RouteManager 内置）
        let mut bypass = self.config.auto_bypass_literals.clone();
        for host in &self.config.auto_bypass_hosts {
            match tokio::net::lookup_host((host.as_str(), 0)).await {
                Ok(addrs) => {
                    for a in addrs {
                        bypass.push(RouteDestination::host(a.ip()));
                    }
                }
                Err(e) => {
                    warn!(target: "rillane::tun", host = %host, error = %e, "auto-bypass 域名解析失败（egress 服务器可达性自负）");
                }
            }
        }
        {
            let mut rm = self.route_manager.lock().await;
            rm.set_interface_name(iface_name.clone());
            rm.set_auto_bypass(bypass);
        }

        tun_guard
            .up_interface()
            .await
            .context("启动 TUN 接口失败")?;
        tun_guard.configure_ip().await.context("配置 TUN IP 失败")?;
        // §5「启动 apply ≡ CLI apply」：run() 启动即 apply_desired(false)
        // 幂等重放（与 rillanectl route apply 同一方法——不存在两条路由写路径）；
        // 设备 up 态回填（status 端点消费）
        {
            let rm = self.route_manager.lock().await;
            rm.set_device_up(true);
            rm.apply_desired(false)
                .await
                .map_err(|f| f.error)
                .context("应用路由失败")?;
        }

        info!(target: "rillane::tun", name = %iface_name, "TunIngress 已启动");

        let result = self.packet_loop(&mut tun_guard).await;

        // Teardown（逆序回滚；尽力而为不掩盖主结果）
        for entry in self.flow_table.iter() {
            entry.cancel.notify_one();
        }
        self.flow_table.clear();
        // T4：TCP 栈全量收口（应用连接随 EOF 退场；设备即将销毁不再出段）
        self.tcp.shutdown_all();
        {
            // 路由还原 + 设备态清零（clear 后设备名义上仍 up——§5「clear 后
            // 数据面空转」；此处 teardown 阶段设备将销毁，账面同步归零，
            // 后续 CLI apply 得到 E10 而非裸 ip 报错）
            let mut rm = self.route_manager.lock().await;
            if let Err(e) = rm.clear().await {
                warn!(target: "rillane::tun", error = %e, "清理路由失败");
            }
            rm.set_device_up(false);
            rm.clear_interface_name();
        }
        if let Err(e) = tun_guard.down_interface().await {
            warn!(target: "rillane::tun", error = %e, "关闭 TUN 接口失败");
        }
        if let Err(e) = tun_guard.destroy_interface().await {
            warn!(target: "rillane::tun", error = %e, "销毁 TUN 接口失败");
        }
        drop(tun_guard);

        info!(target: "rillane::tun", name = %iface_name, "TunIngress 已停止");
        result
    }

    /// §2.9 包循环：读 tun / 写下行 / 清扫三事件单循环
    async fn packet_loop(
        &self,
        tun_guard: &mut tokio::sync::MutexGuard<'_, LinuxTunProvider>,
    ) -> Result<()> {
        let (downlink_tx, mut downlink_rx) = mpsc::channel::<Bytes>(DOWNLINK_CHANNEL_CAP);
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // 不加 biased：随机轮询防读/写单方向饿死（guard 已由本循环独占，
            // 无锁竞争面）
            let event = tokio::select! {
                _ = self.shutdown.notified() => LoopEvent::Shutdown,
                read = tun_guard.read_packet() => LoopEvent::Read(read),
                pkt = downlink_rx.recv() => LoopEvent::Downlink(pkt),
                _ = sweep.tick() => LoopEvent::Sweep,
                _ = self.tcp.kick_notify().notified() => LoopEvent::TcpKick,
            };
            match event {
                LoopEvent::Shutdown => {
                    info!(target: "rillane::tun", "收到关闭信号，退出包循环");
                    break;
                }
                LoopEvent::Read(Ok((bytes, info))) => {
                    self.handle_uplink(bytes, info, &downlink_tx).await;
                }
                LoopEvent::Read(Err(e)) => {
                    // E8：设备已关/异常 → 终止（tun-dataplane.md §1.1）
                    error!(target: "rillane::tun", error = %e, "TUN 读包失败（E8），退出包循环");
                    break;
                }
                LoopEvent::Downlink(Some(bytes)) => {
                    let n = bytes.len();
                    if let Err(e) = tun_guard.write_packet(bytes).await {
                        error!(target: "rillane::tun", error = %e, "TUN 写包失败（E8），退出包循环");
                        break;
                    }
                    let mut st = self.stats.lock().unwrap();
                    st.packets_sent += 1;
                    st.bytes_sent += n as u64;
                }
                LoopEvent::Downlink(None) => break, // 下行通道全员撤出（防御分支）
                LoopEvent::Sweep => {
                    self.sweep_expired_flows_at(Instant::now());
                    // TCP 面：空闲回收 + 补 poll（§2.9 定时推进——重传/延迟 ACK/
                    // 关闭态收敛复用既有 sweep 周期，不另起独立定时任务）
                    let n = self
                        .tcp
                        .sweep(Duration::from_secs(self.config.tcp_idle_secs));
                    if n > 0 {
                        debug!(target: "rillane::tun", evicted = n, "TCP 流空闲过期回收");
                    }
                    self.drive_tcp(&downlink_tx).await;
                }
                LoopEvent::TcpKick => self.drive_tcp(&downlink_tx).await,
            }
        }
        Ok(())
    }

    /// 上行包处理：计数 → bypass → 按 proto 分发（TCP T4 前丢弃 + 计数）
    async fn handle_uplink(&self, pkt: Bytes, info: PacketInfo, downlink_tx: &mpsc::Sender<Bytes>) {
        {
            let mut st = self.stats.lock().unwrap();
            st.packets_received += 1;
            st.bytes_received += pkt.len() as u64;
        }
        let Some(dst_ip) = info.dst_ip else {
            self.increment_parse_errors();
            return;
        };
        // Bypass（进程内兜底，§2.7）
        if self.matches_bypass(dst_ip).await {
            self.increment_bypass_dropped();
            return;
        }
        if info.is_udp() {
            match parse_udp_datagram(&pkt) {
                Ok(dgram) => self.handle_udp_packet(dgram, downlink_tx).await,
                Err(e) => {
                    debug!(target: "rillane::tun", error = %e, "UDP 数据报解析失败，丢弃（E9）");
                    self.increment_parse_errors();
                }
            }
        } else if info.is_tcp() {
            self.handle_tcp_packet(pkt, downlink_tx).await;
        } else {
            // ICMP 等：MVP 丢弃 + 计数（E9）
            debug!(target: "rillane::tun", proto = ?info.protocol, "非 UDP/TCP 包丢弃");
            self.increment_parse_errors();
        }
    }

    /// Bypass 判定（§2.7 三源）：默认规则（private/loopback/multicast）∪
    /// 用户 bypass_rules ∪ auto-bypass 集（egress/control/mesh/tun 网段）
    async fn matches_bypass(&self, dst: IpAddr) -> bool {
        if default_bypass_rules().iter().any(|r| r.matches(dst, None)) {
            return true;
        }
        if self
            .config
            .routing
            .bypass_rules
            .iter()
            .any(|r| r.matches(dst, None))
        {
            return true;
        }
        self.route_manager.lock().await.is_auto_bypass_ip(dst)
    }

    /// UDP 上行（§2.2）：已建流直发；首包 归因→路由→associate→驱逐→
    /// 插入→spawn 下行任务→发送（顺序即此序——注解先于路由，路由能吃
    /// process.* 条件；关联成功才建条目，失败不残留）
    async fn handle_udp_packet(&self, dgram: UdpDatagram<'_>, downlink_tx: &mpsc::Sender<Bytes>) {
        let src = SocketAddr::new(dgram.src, dgram.sport);
        let dst = SocketAddr::new(dgram.dst, dgram.dport);
        let key = TunFlowKey {
            proto: Proto::Udp,
            src,
            dst,
        };
        let mut target = udp_target(dst);

        // 已建流：续期 + 直发（DashMap guard 不跨 await——先 clone relay 再放）
        if let Some(entry) = self.flow_table.get(&key) {
            let relay = entry.relay.clone();
            let target = entry.target.clone();
            drop(entry);
            if let Some(relay) = relay {
                let now = Instant::now();
                if let Some(mut e) = self.flow_table.get_mut(&key) {
                    e.last_active = now;
                    e.expiry = now + Duration::from_secs(self.config.udp_idle_secs);
                }
                self.send_uplink(&relay, &key, &target, dgram.payload).await;
            }
            // relay = None：条目拆除中，丢弃
            return;
        }

        // ---- 首包 ----
        // ① 进程归因（§2.5：仅 Process 规则在配置时扫描；miss 计数不报错）
        let process = if self.config.has_process_rules {
            let p = self.attributor.attribute(src, SockProto::Udp).await;
            if p.is_none() {
                self.stats.lock().unwrap().process_attr_miss += 1;
            }
            p
        } else {
            None
        };
        let mut metadata = FlowMetadata::default();
        if let Some(p) = &process {
            metadata
                .annotations
                .insert("process.name".to_string(), p.comm.clone());
            metadata
                .annotations
                .insert("process.pid".to_string(), p.pid.to_string());
        }

        // G0-3 sniff：QUIC Initial 跨包重组提取 SNI，覆写 target.host 后按
        // 域名路由（UDP 面仅 QUIC 能承载域名语义；其余 UDP 保持 IP 目标）。
        // 非 QUIC（NotInitial）/ Initial 无 CRYPTO（NoCrypto）都照常按 IP
        // 目标路由，绝不丢弃 DNS 等普通 UDP 首包；分片未齐才暂缓路由。
        if let Some(mut sniffer) = self.quic_sniffers.get_mut(&key) {
            match sniffer.push(dgram.payload) {
                QuicSniffStep::NotInitial | QuicSniffStep::NoCrypto => {
                    self.quic_sniffers.remove(&key);
                }
                QuicSniffStep::Incomplete => {
                    debug!(target: "rillane::tun", dst = %dst, "QUIC ClientHello 分片未齐");
                    return;
                }
                QuicSniffStep::Host(sni) => {
                    debug!(target: "rillane::tun", sni = %sni, dst = %dst, "TUN UDP 嗅探到 QUIC SNI");
                    target.host.clone_from(&sni);
                    self.quic_sniffers.remove(&key);
                }
            }
        } else {
            let mut sniffer = QuicCryptoReassembler::new();
            match sniffer.push(dgram.payload) {
                QuicSniffStep::NotInitial | QuicSniffStep::NoCrypto => {}
                QuicSniffStep::Incomplete => {
                    self.quic_sniffers.insert(key, sniffer);
                    return;
                }
                QuicSniffStep::Host(sni) => {
                    debug!(target: "rillane::tun", sni = %sni, dst = %dst, "TUN UDP 嗅探到 QUIC SNI");
                    target.host.clone_from(&sni);
                }
            }
        }

        // ② 路由（带着 process.* 注解进引擎——MatchCondition::Process 在此生效）
        let ctx = FlowContext {
            id: FlowId::new(),
            target: target.clone(),
            metadata,
        };
        let decision = match self.router().route(ctx.clone()).await {
            Ok(d) => d,
            Err(e) => {
                error!(target: "rillane::tun", error = %e, dst = %dst, "TUN UDP 流路由失败，丢包");
                return;
            }
        };

        // ③ 出站关联（失败不建条目）
        let relay = match self.udp_connector.associate(ctx, &decision).await {
            Ok(r) => r,
            Err(e) => {
                error!(target: "rillane::tun", error = %e, dst = %dst, "TUN UDP associate 失败，丢包");
                return;
            }
        };

        // ④ 流表满 → 逐最早 expiry 驱逐（同 P0-4 R10）
        if self.flow_table.len() >= self.config.max_flows {
            self.evict_earliest();
        }

        // ⑤ 建条目 + 下行任务
        debug!(
            target: "rillane::tun",
            dst = %dst,
            node = ?decision.path,
            process = ?process.as_ref().map(|p| p.comm.as_str()),
            "TUN UDP 流建立"
        );
        let now = Instant::now();
        let cancel = Arc::new(Notify::new());
        self.flow_table.insert(
            key,
            TunFlowEntry {
                decision,
                target: target.clone(),
                relay: Some(relay.clone()),
                process,
                last_active: now,
                expiry: now + Duration::from_secs(self.config.udp_idle_secs),
                cancel: cancel.clone(),
            },
        );
        let mtu = self.config.tun.mtu as usize;
        tokio::spawn(downlink_task(
            key,
            relay.clone(),
            cancel,
            Arc::clone(&self.flow_table),
            downlink_tx.clone(),
            Arc::clone(&self.stats),
            Arc::clone(&self.ipv4_id),
            mtu,
            self.config.udp_idle_secs,
        ));

        // ⑥ 首包载荷上行
        self.send_uplink(&relay, &key, &target, dgram.payload).await;
    }

    /// 上行发送 + classify_failure 处置（P0-3 §3.6）：Route 族拆映射重路由、
    /// Timeout/Connection 族保映射待空闲回收
    async fn send_uplink(
        &self,
        relay: &Arc<dyn UdpRelay>,
        key: &TunFlowKey,
        target: &FlowTarget,
        payload: &[u8],
    ) {
        if let Err(e) = relay.send_to(target, payload).await {
            match classify_failure(&e) {
                FailureType::Route => {
                    debug!(target: "rillane::tun", error = %e, "上行 Route 族失败，拆除映射");
                    if let Some((_, entry)) = self.flow_table.remove(key) {
                        entry.cancel.notify_one();
                    }
                }
                ft => {
                    debug!(target: "rillane::tun", error = %e, ?ft, "上行失败，映射保留待空闲回收");
                }
            }
        }
    }

    /// TCP 上行（§2.4/§2.9）：首 SYN 归因+粘滞路由 → 入栈；SYN 重传/其余
    /// 包直接入栈；poll 产物（下行段 + Established 交接清单）统一收口
    async fn handle_tcp_packet(&self, pkt: Bytes, downlink_tx: &mpsc::Sender<Bytes>) {
        let seg = match parse_tcp_segment(&pkt) {
            Ok(s) => s,
            Err(e) => {
                debug!(target: "rillane::tun", error = %e, "TCP 段解析失败，丢弃（E9）");
                self.increment_parse_errors();
                return;
            }
        };
        let server = SocketAddr::new(seg.dst, seg.dport);
        let key = TcpFlowKey {
            app: SocketAddr::new(seg.src, seg.sport),
            server,
        };
        let is_first_syn = seg.syn && !seg.ack;
        let outcome = if is_first_syn && !self.tcp.has_flow(&key) {
            if self.tcp.active_count() >= self.config.max_flows {
                warn!(
                    target: "rillane::tun",
                    server = %server,
                    max = self.config.max_flows,
                    "TCP 流表满，拒绝新连接"
                );
                return;
            }
            let Some((decision, process)) = self.tcp_route_decision(key.app, server, None).await
            else {
                return; // 路由失败：丢 SYN（应用侧重传或放弃，E9 同口径）
            };
            self.tcp.ingest_syn(pkt, key, decision, process)
        } else {
            // SYN 重传（决策已粘滞不重路由）/握手中途/中途接入——直接喂栈
            self.tcp.ingest(pkt, server.port())
        };
        match outcome {
            Ok(o) => self.tcp_finish(o, downlink_tx).await,
            Err(e) => {
                debug!(target: "rillane::tun", error = %e, "TCP 入栈失败，丢弃（E9）");
                self.increment_parse_errors();
            }
        }
    }

    /// TCP 决策（§2.4 首 SYN 粘滞；Established 兜底时 known 为 SYN 面随行归因）：
    /// 归因（若需）→ process.* 注解 → 路由。失败 None（调用方丢包/拆流）
    async fn tcp_route_decision(
        &self,
        app: SocketAddr,
        server: SocketAddr,
        known: Option<ProcessInfo>,
    ) -> Option<(RouteDecision, Option<ProcessInfo>)> {
        let mut process = known;
        if process.is_none() && self.config.has_process_rules {
            process = self.attributor.attribute(app, SockProto::Tcp).await;
            if process.is_none() {
                self.stats.lock().unwrap().process_attr_miss += 1;
            }
        }
        let mut metadata = FlowMetadata::default();
        if let Some(p) = &process {
            metadata
                .annotations
                .insert("process.name".to_string(), p.comm.clone());
            metadata
                .annotations
                .insert("process.pid".to_string(), p.pid.to_string());
        }
        let ctx = FlowContext {
            id: FlowId::new(),
            target: tcp_target(server),
            metadata,
        };
        match self.router().route(ctx).await {
            Ok(d) => Some((d, process)),
            Err(e) => {
                error!(target: "rillane::tun", error = %e, server = %server, "TUN TCP 流路由失败，丢包");
                None
            }
        }
    }

    /// poll 产物收口：下行段入通道（run 循环写 tun；测试直驱同路径）+
    /// Established 交接（spawn forward）
    async fn tcp_finish(&self, outcome: TcpOutcome, downlink_tx: &mpsc::Sender<Bytes>) {
        for pkt in outcome.tx_packets {
            if downlink_tx.send(pkt).await.is_err() {
                return; // run 循环已退出——后续产物无处可去
            }
        }
        for est in outcome.established {
            self.spawn_tcp_forward(est).await;
        }
    }

    /// TCP 栈补 poll（run 循环 TcpKick/Sweep 臂；测试直驱同路径）
    async fn drive_tcp(&self, downlink_tx: &mpsc::Sender<Bytes>) {
        let outcome = self.tcp.drive();
        self.tcp_finish(outcome, downlink_tx).await;
    }

    /// Established 交接（§2.4）：粘滞决策命中即用，缺档（中途接入）兜底路由 →
    /// Flow{target, io: SmolTcpStream, metadata} → output.forward。整条交接
    /// 在独立 spawn 任务内完成（含 G0-3 嗅探等待）——不阻塞 run 循环。
    async fn spawn_tcp_forward(&self, est: EstablishedTcp) {
        let EstablishedTcp {
            handle,
            key,
            decision,
            process,
        } = est;
        let (decision, process) = match decision {
            Some(d) => (d, process),
            None => match self.tcp_route_decision(key.app, key.server, process).await {
                Some(pair) => pair,
                None => {
                    self.tcp.abort(handle);
                    return;
                }
            },
        };
        let Some(output) = self.flow_output.get().cloned() else {
            // 未注入（构造期）：拆流收口（应用侧收 FIN/RST）
            self.tcp.abort(handle);
            return;
        };
        let tcp = Arc::clone(&self.tcp);
        let router = Arc::clone(&self.router());
        // RIL-143：策略值拷入 spawn 任务（任务不得借用 self 生命周期）
        let sniff_policy = self.config.sniff.clone();
        let mut target = tcp_target(key.server);
        let mut metadata = FlowMetadata::default();
        if let Some(p) = &process {
            metadata
                .annotations
                .insert("process.name".to_string(), p.comm.clone());
            metadata
                .annotations
                .insert("process.pid".to_string(), p.pid.to_string());
        }
        tokio::spawn(async move {
            // G0-3 sniff：交接后 ClientHello 常在 Established 检出后的独立
            // 分段才到达，单次 peek 常为空。故在此短暂轮询等待数据到达
            // （不阻塞 run 循环；peek 不消费数据，forward 首包照常可读），
            // 提取 SNI/Host 后覆写 target.host 并按域名重路由。
            let mut sniffed_domain = None;
            // RIL-143 嗅探门：off / scope 未命中即零 peek（不付首包时延）；
            // 按需 = 目标为 IP 字面量（路由面缺域名证据）才嗅探——TUN 面
            // 目标恒为字面量，缺省 = 既有行为零差异。字节/时间双界取自
            // 策略（缺省 16389B/120ms），peek 不消费数据、forward 首包
            // 照常可读——有界且不吞数据。
            if sniff_policy.applies(
                target.host.parse::<std::net::IpAddr>().is_ok(),
                key.server.port(),
            ) {
                let peeked = tcp
                    // 上限容纳单条最大 TLS 记录（策略 max_bytes，缺省 16384+5
                    // 记录头），超长 ClientHello 不被截断，`sniff_tls_sni`
                    // 的整记录要求得以满足。
                    .peek_socket_with_wait(
                        handle,
                        sniff_policy.max_bytes as usize,
                        Duration::from_millis(sniff_policy.timeout_ms),
                    )
                    .await;
                if !peeked.is_empty() {
                    let sniffed = sniff_tls_sni(&peeked)
                        .map(|h| (h, "tls_sni"))
                        .or_else(|| sniff_http_host(&peeked).map(|h| (h, "http_host")));
                    if let Some((host, source)) = sniffed {
                        // 来源契约（RIL-143）：域名注记明示证据来源——
                        // SNI/Host 皆为首包明文元数据，不解密 HTTPS、
                        // 不推断 PID、不越认证边界。
                        metadata
                            .annotations
                            .insert("sniff.source".to_string(), source.to_string());
                        metadata
                            .annotations
                            .insert("sniff.domain".to_string(), host.clone());
                        target.host.clone_from(&host);
                        sniffed_domain = Some(host);
                    }
                }
            }
            let decision = if let Some(ref host) = sniffed_domain {
                let ctx = FlowContext {
                    id: FlowId::new(),
                    target: target.clone(),
                    metadata: metadata.clone(),
                };
                match router.route(ctx).await {
                    Ok(d) => d,
                    Err(e) => {
                        error!(
                            target: "rillane::tun",
                            error = %e,
                            server = %key.server,
                            sni = %host,
                            "TUN TCP sniff 后重路由失败，拆流"
                        );
                        tcp.abort(handle);
                        return;
                    }
                }
            } else {
                decision
            };
            debug!(
                target: "rillane::tun",
                server = %key.server,
                node = ?decision.path,
                process = ?process.as_ref().map(|p| p.comm.as_str()),
                sni = ?sniffed_domain,
                "TUN TCP 流建立（交接）"
            );
            let flow = Flow {
                id: FlowId::new(),
                target,
                io: Box::new(SmolTcpStream::new(Arc::clone(&tcp), handle)),
                metadata,
            };
            let stack = Arc::clone(&tcp);
            if let Err(e) = output.forward(decision, flow).await {
                debug!(target: "rillane::tun", error = %e, "TUN TCP forward 结束（错误）");
            }
            stack.retire(handle);
        });
    }

    /// 清扫过期流（`now` 可注入——单测无需真实时钟）
    fn sweep_expired_flows_at(&self, now: Instant) {
        let expired: Vec<TunFlowKey> = self
            .flow_table
            .iter()
            .filter(|e| e.expiry <= now)
            .map(|e| *e.key())
            .collect();
        for k in expired {
            if let Some((_, entry)) = self.flow_table.remove(&k) {
                debug!(
                    target: "rillane::tun",
                    ?k,
                    node = ?entry.decision.path,
                    process = ?entry.process.as_ref().map(|p| p.comm.as_str()),
                    idle = ?now.saturating_duration_since(entry.last_active),
                    "UDP 流空闲过期回收"
                );
                entry.cancel.notify_one();
            }
        }
    }

    /// 驱逐最早过期的流（流表满时）
    fn evict_earliest(&self) {
        let victim = self
            .flow_table
            .iter()
            .min_by_key(|e| e.expiry)
            .map(|e| (*e.key(), e.expiry));
        if let Some((k, expiry)) = victim {
            if let Some((_, entry)) = self.flow_table.remove(&k) {
                warn!(target: "rillane::tun", ?k, ?expiry, "流表满，驱逐最早过期流");
                entry.cancel.notify_one();
            }
        }
    }

    fn increment_bypass_dropped(&self) {
        self.stats.lock().unwrap().bypass_dropped += 1;
    }

    fn increment_parse_errors(&self) {
        self.stats.lock().unwrap().parse_errors += 1;
    }

    /// 统计快照（T5 指标渲染面）
    pub fn get_stats(&self) -> TunIngressStats {
        self.stats.lock().unwrap().clone()
    }

    /// 活跃流数（T5 rillane_tun_flows_active 源；UDP 流表 + TCP 栈面合计）
    pub fn active_flows(&self) -> usize {
        self.flow_table.len() + self.tcp.active_count()
    }
}

/// UDP 下行任务（每流一个）：relay.recv → 反向包构造 → 下行通道（run 循环
/// 写 tun）。流被回收（sweep/evict/Route 族拆除）即 cancel 或 contains_key
/// 双保险退出；不触碰 tun guard（§2.9：写集中 run 循环）。
#[allow(clippy::too_many_arguments)]
async fn downlink_task(
    key: TunFlowKey,
    relay: Arc<dyn UdpRelay>,
    cancel: Arc<Notify>,
    table: Arc<DashMap<TunFlowKey, TunFlowEntry>>,
    tx: mpsc::Sender<Bytes>,
    stats: Arc<Mutex<TunIngressStats>>,
    ipv4_id: Arc<AtomicU16>,
    mtu: usize,
    udp_idle_secs: u64,
) {
    let mut buf = vec![0u8; mtu];
    loop {
        tokio::select! {
            biased;
            _ = cancel.notified() => break,
            received = relay.recv_from(&mut buf) => {
                let Ok((_, n)) = received else {
                    break; // relay 断（egress 关闭/错误）
                };
                if !table.contains_key(&key) {
                    // 流已回收：迟到的下行包（未知流计数，§2.8）
                    stats.lock().unwrap().unknown_flow += 1;
                    break;
                }
                let pkt = build_udp_packet(
                    key.dst.ip(),
                    key.src.ip(),
                    key.dst.port(),
                    key.src.port(),
                    &buf[..n],
                    ipv4_id.fetch_add(1, Ordering::Relaxed),
                );
                match pkt {
                    Ok(p) => {
                        if tx.send(Bytes::from(p)).await.is_err() {
                            break; // run 循环已退出
                        }
                    }
                    Err(e) => {
                        debug!(target: "rillane::tun", error = %e, "下行包构造失败，丢弃（E9）");
                    }
                }
                if let Some(mut e) = table.get_mut(&key) {
                    // 下行亦续 expiry：纯下行推送流（客户端 udp_idle_secs 内
                    // 无上行）不得被中途逐出——续期口径与上行一致。
                    let now = Instant::now();
                    e.last_active = now;
                    e.expiry = now + Duration::from_secs(udp_idle_secs);
                }
            }
        }
    }
}

/// SocketAddr → UDP FlowTarget（host 字面量 IP 形——TUN 面目标恒为 IP，无域名）
fn udp_target(dst: SocketAddr) -> FlowTarget {
    FlowTarget {
        host: dst.ip().to_string(),
        port: dst.port(),
        proto: TargetProto::Udp,
    }
}

/// SocketAddr → TCP FlowTarget（同 udp_target 口径）
fn tcp_target(dst: SocketAddr) -> FlowTarget {
    FlowTarget {
        host: dst.ip().to_string(),
        port: dst.port(),
        proto: TargetProto::Tcp,
    }
}

#[async_trait]
impl IngressEndpoint for TunIngress {
    fn name(&self) -> &'static str {
        "tun"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        self.set_endpoints(router, output);
        self.run_internal().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;
    use rillane_core::udp::relay::MockUdpRelay;
    use rillane_platform::network::ipcodec::{build_tcp_packet, TcpFlags, TcpSegment};
    use rillane_platform::network::route::{BypassAction, BypassCondition, BypassRule};
    use rillane_platform::network::tun::PacketType;

    /// 记录型路由器（断言 ctx 目标与注解进料）
    struct RecordingRouter {
        seen: StdMutex<Vec<FlowContext>>,
        node: &'static str,
    }

    #[async_trait]
    impl FlowRouter for RecordingRouter {
        async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
            self.seen.lock().unwrap().push(ctx);
            Ok(RouteDecision::direct(self.node.to_string()))
        }
    }

    /// 空出口（TUN UDP 面不经 FlowOutput::forward——TCP T4 才用）
    struct NullOutput;

    #[async_trait]
    impl FlowOutput for NullOutput {
        async fn forward(
            &self,
            _decision: RouteDecision,
            _flow: rillane_core::Flow,
        ) -> Result<rillane_core::FlowReport> {
            unreachable!("TUN UDP 面不经 FlowOutput::forward")
        }
    }

    /// echo 型出口（TCP §4.1 全路径）：读一段 → 原样回写 → 报信号；Flow 随帧
    /// 消亡 → SmolTcpStream Drop 关 socket → FIN 收敛
    struct EchoOutput {
        done: mpsc::Sender<()>,
    }

    #[async_trait]
    impl FlowOutput for EchoOutput {
        async fn forward(
            &self,
            _decision: RouteDecision,
            mut flow: rillane_core::Flow,
        ) -> Result<rillane_core::FlowReport> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 256];
            let n = flow.io.read(&mut buf).await?;
            flow.io.write_all(&buf[..n]).await?;
            let _ = self.done.send(()).await;
            Ok(rillane_core::FlowReport::default())
        }
    }

    /// Mock 连接器：associate 返回 MockUdpRelay；注入通道留档供测试喂下行
    struct MockConnector {
        feeds: StdMutex<Vec<mpsc::Sender<Vec<u8>>>>,
    }

    #[async_trait]
    impl EgressUdpConnector for MockConnector {
        fn name(&self) -> &str {
            "mock"
        }
        async fn associate(
            &self,
            ctx: FlowContext,
            _decision: &RouteDecision,
        ) -> Result<Arc<dyn UdpRelay>> {
            let (relay, tx) = MockUdpRelay::new(ctx.target);
            self.feeds.lock().unwrap().push(tx);
            Ok(relay)
        }
    }

    fn uplink_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> (Bytes, PacketInfo) {
        let pkt = build_udp_packet(src.ip(), dst.ip(), src.port(), dst.port(), payload, 0).unwrap();
        let mut info = PacketInfo::new(PacketType::from_ip_version(4), pkt.len());
        info.parse_ip_header(&pkt).unwrap();
        (Bytes::from(pkt), info)
    }

    /// TCP 上行包 + PacketInfo（§4.1 扮演本机应用——build_tcp_packet 真校验和）
    fn tcp_uplink_packet(
        app: &SocketAddr,
        server: &SocketAddr,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> (Bytes, PacketInfo) {
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (app.ip(), server.ip()) else {
            panic!("TCP 全路径测试仅 v4 面");
        };
        let pkt = build_tcp_packet(
            src,
            dst,
            app.port(),
            server.port(),
            seq,
            ack,
            flags,
            payload,
        )
        .expect("build tcp");
        let mut info = PacketInfo::new(PacketType::from_ip_version(4), pkt.len());
        info.parse_ip_header(&pkt).unwrap();
        (Bytes::from(pkt), info)
    }

    /// 驱动 TCP 栈直至下行段命中谓词（无 run 循环场景的轮询替身——
    /// drive_tcp 与 run 循环 TcpKick/Sweep 臂同路径）
    async fn drive_until(
        t: &Arc<TunIngress>,
        tx: &mpsc::Sender<Bytes>,
        rx: &mut mpsc::Receiver<Bytes>,
        mut pred: impl FnMut(&TcpSegment<'_>) -> bool,
    ) -> Bytes {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            t.drive_tcp(tx).await;
            match rx.try_recv() {
                Ok(pkt) => {
                    if let Ok(seg) = parse_tcp_segment(&pkt) {
                        if pred(&seg) {
                            return pkt;
                        }
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    panic!("下行通道断开（run 循环持有发送端——不应发生）");
                }
            }
            assert!(Instant::now() < deadline, "等待下行段（谓词未命中）超时");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn make_ingress(
        config: TunIngressConfig,
    ) -> (Arc<TunIngress>, Arc<RecordingRouter>, Arc<MockConnector>) {
        let router = Arc::new(RecordingRouter {
            seen: StdMutex::new(Vec::new()),
            node: "game-node",
        });
        let connector = Arc::new(MockConnector {
            feeds: StdMutex::new(Vec::new()),
        });
        let t = Arc::new(TunIngress::new(config, connector.clone()));
        t.set_endpoints(router.clone(), Arc::new(NullOutput));
        (t, router, connector)
    }

    /// 回归：set_endpoints 未注入时 run_internal 应返回 Err（启动 fail-fast），
    /// 而非运行期每包在 router()/flow_output 处 panic（原不变式仅由 expect 维持）。
    #[tokio::test]
    async fn run_internal_fails_fast_without_endpoints() {
        let connector = Arc::new(MockConnector {
            feeds: StdMutex::new(Vec::new()),
        });
        let t = Arc::new(TunIngress::new(TunIngressConfig::default(), connector));
        let res = t.clone().run_internal().await;
        assert!(
            res.as_ref()
                .is_err_and(|e| e.to_string().contains("未注入")),
            "未注入 endpoints 必须 fail-fast（含未注入错误），got: {res:?}"
        );
    }

    /// 回归：纯下行推送流也须续 expiry（原只续 last_active，sweep 按
    /// expiry 驱逐，下行推送流在 udp_idle_secs 内无上行会被中途逐出）。
    #[tokio::test]
    async fn downlink_packet_renews_expiry() {
        use rillane_core::udp::relay::MockUdpRelay;

        let key = TunFlowKey {
            proto: Proto::Udp,
            src: "10.66.0.1:40000".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let target = udp_target(key.dst);
        let (relay, feed) = MockUdpRelay::new(target.clone());
        let cancel = Arc::new(Notify::new());
        let table = Arc::new(DashMap::new());
        let now = Instant::now();
        let old_expiry = now + Duration::from_millis(50);
        table.insert(
            key,
            TunFlowEntry {
                decision: RouteDecision::direct("game-node".to_string()),
                target: target.clone(),
                relay: Some(relay.clone()),
                process: None,
                last_active: now,
                expiry: old_expiry,
                cancel: cancel.clone(),
            },
        );
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(downlink_task(
            key,
            relay,
            cancel,
            table.clone(),
            tx,
            Arc::new(StdMutex::new(TunIngressStats::default())),
            Arc::new(AtomicU16::new(0)),
            1500,
            300,
        ));

        feed.send(b"push".to_vec()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("下行包应在超时前返回")
            .expect("downlink_task 持 tx");

        let new_expiry = table.get(&key).expect("下行后流仍在").expiry;
        assert!(
            new_expiry > old_expiry,
            "下行须续 expiry：old={old_expiry:?} new={new_expiry:?}"
        );
        task.abort();
    }

    /// §4.1 UDP 全链路（无设备）：应用包 → 归因旁路（无 Process 规则）→ 路由
    /// → associate → 首包载荷上行 → 下行注入 → 反向包构造 → 下行通道可收。
    #[tokio::test]
    async fn udp_full_path_without_device() {
        let (t, router, connector) = make_ingress(TunIngressConfig::default());
        let (downlink_tx, mut downlink_rx) = mpsc::channel::<Bytes>(DOWNLINK_CHANNEL_CAP);

        let src: SocketAddr = "10.66.0.1:40000".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let (pkt, info) = uplink_packet(src, dst, b"dns-query");
        t.handle_uplink(pkt, info, &downlink_tx).await;

        // 路由进料：目标五元组 + 无归因注解（has_process_rules=false）
        //（guard 单语句快照即放——不跨 await）
        assert_eq!(t.active_flows(), 1);
        let seen: Vec<FlowContext> = router.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let ctx = &seen[0];
        assert_eq!(ctx.target.host, "8.8.8.8");
        assert_eq!(ctx.target.port, 53);
        assert!(
            ctx.metadata.annotations.is_empty(),
            "无 Process 规则时不应归因"
        );

        // 上行统计（tun 读入口径）
        let st = t.get_stats();
        assert_eq!(st.packets_received, 1);
        assert!(st.bytes_received > 0);
        assert_eq!(st.bypass_dropped, 0);

        // 下行：mock 注入响应 → downlink_task 反向构造 → 下行通道收到
        let feed = connector.feeds.lock().unwrap()[0].clone();
        drop(connector);
        feed.send(b"dns-response".to_vec()).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(2), downlink_rx.recv())
            .await
            .expect("下行应在 2s 内回到通道")
            .expect("run 循环持有发送端（测试场景通道存活）");
        let dgram = parse_udp_datagram(&echoed).unwrap();
        assert_eq!(dgram.src, dst.ip(), "下行包源 = 上行目标");
        assert_eq!(dgram.dst, src.ip(), "下行包目标 = 上行源");
        assert_eq!(dgram.sport, 53);
        assert_eq!(dgram.dport, 40000);
        assert_eq!(dgram.payload, b"dns-response");
    }

    /// §4.1 TCP 全链路（无设备）：SYN→SYN-ACK 握手（粘滞路由于首 SYN 进料）→
    /// ACK → Established 交接 forward → 上行数据进 forward → echo 回写经补 poll
    /// 下行 → forward 收尾 Flow 消亡 → FIN 收口。全程单次路由（决策粘滞）。
    #[tokio::test]
    async fn tcp_full_path_echo_without_device() {
        let router = Arc::new(RecordingRouter {
            seen: StdMutex::new(Vec::new()),
            node: "game-node",
        });
        let connector = Arc::new(MockConnector {
            feeds: StdMutex::new(Vec::new()),
        });
        let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
        let output = Arc::new(EchoOutput { done: done_tx });
        let t = Arc::new(TunIngress::new(TunIngressConfig::default(), connector));
        t.set_endpoints(router.clone(), output);
        let (downlink_tx, mut downlink_rx) = mpsc::channel::<Bytes>(DOWNLINK_CHANNEL_CAP);

        let app: SocketAddr = "10.66.0.1:40000".parse().unwrap();
        let server: SocketAddr = "203.0.113.10:8080".parse().unwrap();
        let app_isn = 1000u32;

        // ① 首 SYN：粘滞路由进料（目标五元组 + 无归因注解）+ 下行 SYN-ACK
        let (pkt, info) = tcp_uplink_packet(&app, &server, app_isn, 0, TcpFlags::SYN, b"");
        t.handle_uplink(pkt, info, &downlink_tx).await;
        let seen: Vec<FlowContext> = router.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "首 SYN 应路由一次");
        assert_eq!(seen[0].target.host, "203.0.113.10");
        assert_eq!(seen[0].target.port, 8080);
        assert!(
            seen[0].metadata.annotations.is_empty(),
            "无 Process 规则时不应归因"
        );
        assert_eq!(t.active_flows(), 1, "TCP 流在册");

        let synack_pkt = tokio::time::timeout(Duration::from_secs(2), downlink_rx.recv())
            .await
            .expect("SYN-ACK 应在 2s 内回到通道")
            .expect("run 循环持有发送端（测试场景通道存活）");
        let synack = parse_tcp_segment(&synack_pkt).unwrap();
        assert!(synack.syn && synack.ack, "SYN 阶段应答 SYN-ACK");
        assert_eq!((synack.sport, synack.dport), (8080, 40000));
        assert_eq!(synack.ack_seq, app_isn + 1, "SYN 占 1 序号");
        let srv_isn = synack.seq;

        // ② ACK → Established → 交接（spawn forward 等数据；不重复路由）
        let (pkt, info) =
            tcp_uplink_packet(&app, &server, app_isn + 1, srv_isn + 1, TcpFlags::ACK, b"");
        t.handle_uplink(pkt, info, &downlink_tx).await;

        // ③ 上行 "hello" → forward 读 → echo 回写 → 补 poll 下行
        let (pkt, info) = tcp_uplink_packet(
            &app,
            &server,
            app_isn + 1,
            srv_isn + 1,
            TcpFlags::PSH_ACK,
            b"hello",
        );
        t.handle_uplink(pkt, info, &downlink_tx).await;
        let echo_pkt = drive_until(&t, &downlink_tx, &mut downlink_rx, |seg| {
            seg.payload == b"hello"
        })
        .await;
        let echo = parse_tcp_segment(&echo_pkt).unwrap();
        assert_eq!((echo.sport, echo.dport), (8080, 40000), "下行段方向反转");
        assert_eq!(echo.ack_seq, app_isn + 1 + 5, "应确认 'hello' 5 字节");
        assert_eq!(
            router.seen.lock().unwrap().len(),
            1,
            "决策粘滞：全程只路由一次"
        );

        // ④ forward 收尾（Flow 消亡 → close → FIN）→ 应用侧收到 FIN
        tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
            .await
            .expect("forward 应完成 echo")
            .expect("通道存活");
        let fin_pkt = drive_until(&t, &downlink_tx, &mut downlink_rx, |seg| seg.fin).await;
        let fin = parse_tcp_segment(&fin_pkt).unwrap();
        assert!(fin.fin && fin.ack);
        assert_eq!(fin.ack_seq, app_isn + 1 + 5);

        // ⑤ 统计（tun 读入口径 + 无解析错误）
        let st = t.get_stats();
        assert_eq!(st.packets_received, 3);
        assert_eq!(st.parse_errors, 0);
    }

    /// G0-3 sniff 回归：TLS ClientHello 作首包载荷随 Established 入缓冲 →
    /// spawn_tcp_forward 非阻塞 peek 提取 SNI → 按域名重路由（第二次路由
    /// target.host = SNI，覆盖 SYN 面 IP 粘滞决策）。
    #[tokio::test]
    async fn tcp_sniff_reroutes_on_tls_sni() {
        let router = Arc::new(RecordingRouter {
            seen: StdMutex::new(Vec::new()),
            node: "game-node",
        });
        let connector = Arc::new(MockConnector {
            feeds: StdMutex::new(Vec::new()),
        });
        let (done_tx, _done_rx) = mpsc::channel::<()>(1);
        let output = Arc::new(EchoOutput { done: done_tx });
        let t = Arc::new(TunIngress::new(TunIngressConfig::default(), connector));
        t.set_endpoints(router.clone(), output);
        let (downlink_tx, mut downlink_rx) = mpsc::channel::<Bytes>(DOWNLINK_CHANNEL_CAP);

        let app: SocketAddr = "10.66.0.1:40000".parse().unwrap();
        let server: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let app_isn = 1000u32;

        // ① SYN → SYN-ACK
        let (pkt, info) = tcp_uplink_packet(&app, &server, app_isn, 0, TcpFlags::SYN, b"");
        t.handle_uplink(pkt, info, &downlink_tx).await;
        let synack_pkt = tokio::time::timeout(Duration::from_secs(2), downlink_rx.recv())
            .await
            .expect("SYN-ACK 应在 2s 内回到通道")
            .expect("通道存活");
        let synack = parse_tcp_segment(&synack_pkt).unwrap();
        let srv_isn = synack.seq;

        // ② ACK + TLS ClientHello（SNI=sniffed.example.com）同段 → Established
        // 检出时首包已在 socket 缓冲 → spawn 前 peek 命中 → 重路由。
        let ch = build_minimal_client_hello(b"sniffed.example.com");
        let (pkt, info) = tcp_uplink_packet(
            &app,
            &server,
            app_isn + 1,
            srv_isn + 1,
            TcpFlags::PSH_ACK,
            &ch,
        );
        t.handle_uplink(pkt, info, &downlink_tx).await;

        // ③ 断言：路由进料含第二次调用，target.host = SNI（非 IP）。嗅探+
        // 重路由在独立 spawn 任务内，需等待其完成（上限 2s）。
        let seen = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = router.seen.lock().unwrap().len();
                if n >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            router.seen.lock().unwrap().clone()
        })
        .await
        .expect("spawn 任务应在 2s 内完成重路由");
        assert_eq!(seen.len(), 2, "sniff 命中应触发第二次路由");
        assert_eq!(seen[0].target.host, "203.0.113.10", "首路由仍按 IP");
        assert_eq!(
            seen[1].target.host, "sniffed.example.com",
            "sniff 重路由覆写为 SNI 域名"
        );
    }

    /// G0-3 sniff 回归：ClientHello 在 Established 检出后的独立分段才到达
    /// （真实 TLS 场景，非同段捎带）——spawn 任务的短暂等待必须命中，
    /// 仍按 SNI 重路由而非静默跳过。
    #[tokio::test]
    async fn tcp_sniff_reroutes_when_client_hello_arrives_late() {
        let router = Arc::new(RecordingRouter {
            seen: StdMutex::new(Vec::new()),
            node: "game-node",
        });
        let connector = Arc::new(MockConnector {
            feeds: StdMutex::new(Vec::new()),
        });
        let (done_tx, _done_rx) = mpsc::channel::<()>(1);
        let output = Arc::new(EchoOutput { done: done_tx });
        let t = Arc::new(TunIngress::new(TunIngressConfig::default(), connector));
        t.set_endpoints(router.clone(), output);
        let (downlink_tx, mut downlink_rx) = mpsc::channel::<Bytes>(DOWNLINK_CHANNEL_CAP);

        let app: SocketAddr = "10.66.0.1:40001".parse().unwrap();
        let server: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let app_isn = 2000u32;

        // ① SYN → SYN-ACK
        let (pkt, info) = tcp_uplink_packet(&app, &server, app_isn, 0, TcpFlags::SYN, b"");
        t.handle_uplink(pkt, info, &downlink_tx).await;
        let synack_pkt = tokio::time::timeout(Duration::from_secs(2), downlink_rx.recv())
            .await
            .expect("SYN-ACK 应在 2s 内回到通道")
            .expect("通道存活");
        let synack = parse_tcp_segment(&synack_pkt).unwrap();
        let srv_isn = synack.seq;

        // ② 纯 ACK（无数据）→ Established 检出 → spawn 任务进入等待（此时
        // socket 缓冲为空，peek 空——正是真实 TLS 的交接竞态场景）。
        let (pkt, info) =
            tcp_uplink_packet(&app, &server, app_isn + 1, srv_isn + 1, TcpFlags::ACK, b"");
        t.handle_uplink(pkt, info, &downlink_tx).await;

        // ③ ClientHello 独立分段随后到达（在 spawn 任务的 120ms 窗口内）。
        let ch = build_minimal_client_hello(b"late.example.com");
        let (pkt, info) = tcp_uplink_packet(
            &app,
            &server,
            app_isn + 1,
            srv_isn + 1,
            TcpFlags::PSH_ACK,
            &ch,
        );
        t.handle_uplink(pkt, info, &downlink_tx).await;

        // ④ 等待 spawn 任务完成重路由（上限 2s），断言按 SNI 域名路由。
        let seen = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = router.seen.lock().unwrap().len();
                if n >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            router.seen.lock().unwrap().clone()
        })
        .await
        .expect("spawn 任务应在 2s 内完成重路由");
        assert_eq!(seen.len(), 2, "late ClientHello 也应触发重路由");
        assert_eq!(seen[0].target.host, "203.0.113.10", "首路由仍按 IP");
        assert_eq!(
            seen[1].target.host, "late.example.com",
            "late ClientHello 重路由覆写为 SNI 域名"
        );
    }

    /// 最小 TLS ClientHello 记录（SNI=name）——sniff 测试端构造，与
    /// `sniff.rs` 测试同构。
    fn build_minimal_client_hello(name: &[u8]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(0x01);
        hs.extend_from_slice(&[0x00, 0x00, 0x00]);
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hs.push(0);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]);
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&[0x00, 0x00]);
        server_name.push(0);
        server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(name);
        ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&server_name);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let hs_len = (hs.len() - 4) as u16;
        hs[1] = (hs_len >> 8) as u8;
        hs[2] = hs_len as u8;
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// 流键含 src：同目标不同源 = 两条流（归因/拆除面不串流）
    #[tokio::test]
    async fn flow_key_distinguishes_sources() {
        let (t, _router, _connector) = make_ingress(TunIngressConfig::default());
        let (tx, _rx) = mpsc::channel(DOWNLINK_CHANNEL_CAP);
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        for sport in [40000u16, 40001] {
            let src: SocketAddr = format!("10.66.0.1:{sport}").parse().unwrap();
            let (pkt, info) = uplink_packet(src, dst, b"q");
            t.handle_uplink(pkt, info, &tx).await;
        }
        assert_eq!(t.active_flows(), 2, "同目标不同源应为两条流");
    }

    /// G0-3 sniff 回归：UDP 首包 QUIC Initial → 解密提取 SNI → 路由目标
    /// 覆写为 SNI 域名（而非 IP 目标）。
    #[tokio::test]
    async fn udp_sniff_reroutes_on_quic_sni() {
        use crate::sniff::tests::build_quic_initial;

        let (t, router, _connector) = make_ingress(TunIngressConfig::default());
        let (downlink_tx, _downlink_rx) = mpsc::channel::<Bytes>(DOWNLINK_CHANNEL_CAP);
        let src: SocketAddr = "10.66.0.1:50000".parse().unwrap();
        let dst: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let quic_pkt = build_quic_initial(
            &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
            b"quic.example.org",
        );
        let (pkt, info) = uplink_packet(src, dst, &quic_pkt);
        t.handle_uplink(pkt, info, &downlink_tx).await;

        let seen: Vec<FlowContext> = router.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].target.host, "quic.example.org",
            "QUIC SNI 覆写路由域名"
        );
        assert_eq!(seen[0].target.port, 443);
    }

    /// bypass 三源：默认（private）命中丢弃 + 计数；公网目标放行
    #[tokio::test]
    async fn bypass_private_dropped_public_forwarded() {
        // 用户规则：1.2.3.0/24 直连绕过
        let mut cfg = TunIngressConfig::default();
        cfg.routing.bypass_rules.push(BypassRule::new(
            "corp-lan".into(),
            BypassCondition::IpRange {
                start: "1.2.3.0".parse().unwrap(),
                end: "1.2.3.255".parse().unwrap(),
            },
            BypassAction::Direct,
        ));
        let (t, _router, _connector) = make_ingress(cfg);
        let (tx, _rx) = mpsc::channel(DOWNLINK_CHANNEL_CAP);
        let src: SocketAddr = "10.66.0.1:40000".parse().unwrap();

        for (dst, name) in [("192.168.1.1:53", "private"), ("1.2.3.4:53", "用户规则")] {
            let (pkt, info) = uplink_packet(src, dst.parse().unwrap(), b"q");
            t.handle_uplink(pkt, info, &tx).await;
            assert_eq!(t.active_flows(), 0, "{name} 目标应 bypass 丢弃");
        }
        assert_eq!(t.get_stats().bypass_dropped, 2);

        let (pkt, info) = uplink_packet(src, "8.8.8.8:53".parse().unwrap(), b"q");
        t.handle_uplink(pkt, info, &tx).await;
        assert_eq!(t.active_flows(), 1, "公网目标应建流");
    }

    /// 清扫与驱逐：过期流回收（cancel 通知到位）+ 流表满逐最早 expiry 驱逐
    #[tokio::test]
    async fn sweep_and_evict_semantics() {
        let (t, _router, _connector) = make_ingress(TunIngressConfig::default());
        let now = Instant::now();

        let mk_entry = |secs: u64| TunFlowEntry {
            decision: RouteDecision::direct("n".into()),
            target: udp_target("8.8.8.8:53".parse().unwrap()),
            relay: None,
            process: None,
            last_active: now,
            expiry: now + Duration::from_secs(secs),
            cancel: Arc::new(Notify::new()),
        };
        let k1 = TunFlowKey {
            proto: Proto::Udp,
            src: "10.0.0.1:1".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let entry1 = mk_entry(0); // 立即过期
        let c1 = entry1.cancel.clone();
        t.flow_table.insert(k1, entry1);
        let k2 = TunFlowKey {
            proto: Proto::Udp,
            src: "10.0.0.1:2".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        t.flow_table.insert(k2, mk_entry(300));

        // now+1s 清扫：k1 过期回收（cancel 通知下行任务退出），k2 保留
        t.sweep_expired_flows_at(now + Duration::from_secs(1));
        assert_eq!(t.active_flows(), 1);
        assert!(!t.flow_table.contains_key(&k1));
        tokio::time::timeout(Duration::from_millis(500), c1.notified())
            .await
            .expect("过期回收应通知 cancel");

        // 驱逐：补 2 条更晚的流，满员驱逐最早（k2）
        for port in [3u16, 4] {
            t.flow_table.insert(
                TunFlowKey {
                    proto: Proto::Udp,
                    src: format!("10.0.0.1:{port}").parse().unwrap(),
                    dst: "8.8.8.8:53".parse().unwrap(),
                },
                mk_entry(600),
            );
        }
        t.evict_earliest();
        assert!(!t.flow_table.contains_key(&k2), "最早 expiry 应被驱逐");
        assert_eq!(t.active_flows(), 2);
    }
}
