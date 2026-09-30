//! P0-4 §5 客户端出站：UdpChainRouter + MeshUdpBridge + MeshUdpRelay
//! （udp-mesh-dataplane.md §5；S4——S5 由 runtime_builder 接线消费）。
//!
//! 拓扑（§1 左列）：client 无 data-plane listener，只有出站 relay——本模块即该
//! 出站侧。`UdpChainRouter` 是 P0-3 `RoutingUdpConnector` 的 chain 感知包装：
//! `RoutePath::Chain{hops≥2}` 走 mesh 桥，其余决策原样落 inner（按 final_node
//! 分发，能力表扫描口径不变）。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::UdpSocket;

use seep_core::udp::{EgressUdpConnector, RoutingUdpConnector, UdpRelay};
use seep_core::{FlowContext, FlowTarget, RouteDecision, RouteHop, RoutePath, TargetProto};
use seep_mesh::{MeshRegistry, NodeId};

use crate::mesh_transport::{
    decode_udp_envelope, encode_udp_envelope, MeshTlsConfig, MeshUdpGate, UdpDir, UdpEnvelope,
    UdpPathMode, UDP_ENVELOPE_VERSION,
};

/// FULL 重发间隔（§5）：每 64 个上行包重发一次 FULL。
const FULL_RESEND_PACKETS: u64 = 64;
/// FULL 重发间隔（§5）：距上次 FULL ≥30s 的下一包重发。
const FULL_RESEND_INTERVAL: Duration = Duration::from_secs(30);

/// P0-5 §2.4：client 出站侧进程级计数（`seep_udp_mesh_client_dropped_total` 数据源）。
/// 收编裁决：P0-4 落在 per-relay `AtomicU64`（per-flow 实例无法聚合）→ bridge 构造
/// 本单例 `Arc`，`associate` 把同一 Arc 传入各 `MeshUdpRelay`（fetch_add 点不变）。
/// 面（服务端视角 `seep_udp_mesh_*`）与 client（发起端视角）两序列分立不混算（§0.2）。
#[derive(Debug, Default)]
pub struct UdpClientMetrics {
    /// 下行丢弃（dir=Up / FULL / flow_id 不符 / 解码失败——recv_from 过滤点）
    dropped: AtomicU64,
}

impl UdpClientMetrics {
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// P0-3 `RoutingUdpConnector` 的 chain 感知包装（§5 草图同构）。
pub struct UdpChainRouter {
    inner: RoutingUdpConnector,
    /// chain 决策的 mesh 桥；None + chain 决策 → 构建期已拦截（§6 gate），此处兜底报错
    mesh: Option<MeshUdpBridge>,
}

impl UdpChainRouter {
    pub fn new(inner: RoutingUdpConnector, mesh: Option<MeshUdpBridge>) -> Self {
        Self { inner, mesh }
    }
}

#[async_trait]
impl EgressUdpConnector for UdpChainRouter {
    fn name(&self) -> &str {
        "chain-routing"
    }

    async fn associate(
        &self,
        ctx: FlowContext,
        decision: &RouteDecision,
    ) -> Result<Arc<dyn UdpRelay>> {
        match &decision.path {
            RoutePath::Chain { hops } if hops.len() >= 2 => self
                .mesh
                .as_ref()
                .ok_or_else(|| anyhow!("chain UDP 未启用（mesh 桥未构建——构建期 gate 应已拦截）"))?
                .associate(ctx, hops)
                .await,
            _ => self.inner.associate(ctx, decision).await,
        }
    }
}

/// chain 决策 → 客户端 mesh UDP 承载的桥（§5）。
///
/// gate 在构造点消费（`new` 内 `ensure_usable`——§6：client 侧 UdpChainRouter::mesh
/// 构建前查一次；associate 层不重复检查。设计草图将 `cfg: MeshUdpGate` 留作字段，
/// 落地改为构造即检查，字段无运行期读取点）。
pub struct MeshUdpBridge {
    local_node_id: NodeId,
    registry: Arc<MeshRegistry>,
    /// P0-5 §2.4：进程级 client 侧计数单例（各 relay 共享同一 Arc；观测 getter 抽取点）
    client_metrics: Arc<UdpClientMetrics>,
}

impl MeshUdpBridge {
    pub fn new(
        local_node_id: NodeId,
        registry: Arc<MeshRegistry>,
        tls: Option<&MeshTlsConfig>,
        gate: &MeshUdpGate,
    ) -> Result<Self> {
        gate.ensure_usable(tls)?;
        Ok(Self {
            local_node_id,
            registry,
            client_metrics: Arc::new(UdpClientMetrics::default()),
        })
    }

    /// P0-5 §2.4：build() 包装 `UdpChainRouter` 前抽出（Runtime 观测字段）。
    pub(crate) fn client_metrics(&self) -> Arc<UdpClientMetrics> {
        Arc::clone(&self.client_metrics)
    }

    /// 解析 hops[1] 地址 + 本地 socket（§5：`Arc<MeshUdpRelay>{ sock, next_addr,
    /// path: hops[1..].to_vec(), flow_id, target }`；flow_id 取 FlowId UUID 原始
    /// 16 字节——§11-3 缓存键与线上格式同源）。
    pub(crate) async fn associate(
        &self,
        ctx: FlowContext,
        hops: &[RouteHop],
    ) -> Result<Arc<dyn UdpRelay>> {
        if hops[0].node != self.local_node_id {
            anyhow::bail!(
                "mesh chain path 起点非本机: expected {}, got {}",
                self.local_node_id,
                hops[0].node
            );
        }
        let next = hops[1].node.clone();
        let next_addr = self
            .registry
            .get_node_addr(&next)
            .ok_or_else(|| anyhow!("next hop {next} not found in registry"))?;
        // 域名/字面量地址均可（registry 存 SocketAddr；v4/v6 都 bind 对应栈——与
        // LocalRelay::connect 同法，P0-3 复用语义）
        let bind_addr = if next_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        // connect 到下一跳：内核侧按源地址过滤（下行必来自 relay 面 socket），send 免
        // 逐包地址校验——下一跳由 connect 固化，relay 结构不存 next_addr（无读取点）
        sock.connect(next_addr).await?;
        Ok(Arc::new(MeshUdpRelay {
            sock: Arc::new(sock),
            path: hops[1..].iter().map(|h| h.node.clone()).collect(),
            flow_id: *ctx.id.as_uuid().as_bytes(),
            sent_full: AtomicBool::new(false),
            packets: AtomicU64::new(0),
            last_full: Mutex::new(Instant::now()),
            // P0-5 §2.4：per-relay AtomicU64 → bridge 单例共享 Arc（fetch_add 点不变）
            metrics: Arc::clone(&self.client_metrics),
        }))
    }
}

/// 客户端侧 mesh UDP 承载（§5）：首包 FULL 携带完整路径，此后 CACHED；每 64 包
/// 或 30s 重发一次 FULL 刷中途跳缓存（FULL 丢失的恢复路径——客户端无从感知
/// unknown_flow，MVP 依赖重关联，成本一个头）。下行只认 CACHED dir=Down 且
/// flow_id 匹配，其余丢弃计数。
pub struct MeshUdpRelay {
    sock: Arc<UdpSocket>,
    /// envelope FULL 路径 = hops[1..]（path[0] = 首远端跳——面侧 §4 步骤 2 对位；
    /// 下一跳地址由 associate 时的 connect 固化在 socket 上，不另存字段）
    path: Vec<NodeId>,
    flow_id: [u8; 16],
    sent_full: AtomicBool,
    /// 上行包计数（FULL 重发判据 1）
    packets: AtomicU64,
    /// 上次 FULL 发送时刻（重发判据 2；Instant 非整数故 Mutex 而非 Atomic）
    last_full: Mutex<Instant>,
    /// P0-5 §2.4：下行丢弃进程级计数（dir=Up / FULL / flow_id 不符 / 解码失败）——
    /// bridge 构造单例、同 bridge 各 relay 共享（收编裁决）
    metrics: Arc<UdpClientMetrics>,
}

#[async_trait]
impl UdpRelay for MeshUdpRelay {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()> {
        let n = self.packets.fetch_add(1, Ordering::Relaxed);
        let use_full = {
            let mut last = self.last_full.lock().expect("last_full poisoned");
            let due = !self.sent_full.load(Ordering::Relaxed)
                || n % FULL_RESEND_PACKETS == 0
                || last.elapsed() >= FULL_RESEND_INTERVAL;
            if due {
                self.sent_full.store(true, Ordering::Relaxed);
                *last = Instant::now();
            }
            due
        };
        let env = if use_full {
            UdpEnvelope {
                version: UDP_ENVELOPE_VERSION,
                dir: UdpDir::Up,
                flow_id: self.flow_id,
                target_host: target.host.clone(),
                target_port: target.port,
                path_mode: UdpPathMode::Full,
                hop_index: 0, // §14-1：发送端置 0
                path: self.path.clone(),
                payload: buf.to_vec(),
            }
        } else {
            UdpEnvelope {
                version: UDP_ENVELOPE_VERSION,
                dir: UdpDir::Up,
                flow_id: self.flow_id,
                target_host: target.host.clone(),
                target_port: target.port,
                path_mode: UdpPathMode::Cached,
                hop_index: 0,
                path: Vec::new(),
                payload: buf.to_vec(),
            }
        };
        let wire = encode_udp_envelope(&env)?;
        self.sock.send(&wire).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
        let mut wire = vec![0u8; 65535];
        loop {
            // socket 已 connect 下一跳：send/recv 免逐包地址校验，非 next_addr
            // 来源由内核过滤；wire 缓冲取最大数据报长度，载荷再按调用方 buf
            // 截断（与 direct 面截断语义一致）
            let n = self.sock.recv(&mut wire).await?;
            let env = match decode_udp_envelope(&wire[..n]) {
                Ok(v) => v,
                Err(_) => {
                    self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if env.dir != UdpDir::Down
                || env.path_mode != UdpPathMode::Cached
                || env.flow_id != self.flow_id
            {
                self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let target = FlowTarget {
                host: env.target_host,
                port: env.target_port,
                proto: TargetProto::Udp,
            };
            let len = env.payload.len().min(buf.len());
            buf[..len].copy_from_slice(&env.payload[..len]);
            return Ok((target, len));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::{FlowId, FlowMetadata};
    use seep_mesh::{NodeRecord, NodeRole};

    fn ctx_for(host: &str, port: u16) -> FlowContext {
        FlowContext {
            id: FlowId::new(),
            target: FlowTarget {
                host: host.to_string(),
                port,
                proto: TargetProto::Udp,
            },
            metadata: FlowMetadata::default(),
        }
    }

    /// 桩出站连接器（T7 Direct 臂）：返回记录型 relay，行为即命中证据。
    struct StubConnector {
        hits: Arc<Mutex<Vec<String>>>,
    }

    struct StubRelay {
        hits: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl EgressUdpConnector for StubConnector {
        fn name(&self) -> &str {
            "stub"
        }
        async fn associate(
            &self,
            _ctx: FlowContext,
            _decision: &RouteDecision,
        ) -> Result<Arc<dyn UdpRelay>> {
            self.hits.lock().unwrap().push("stub".into());
            Ok(Arc::new(StubRelay {
                hits: Arc::clone(&self.hits),
            }))
        }
    }

    #[async_trait]
    impl UdpRelay for StubRelay {
        async fn send_to(&self, _target: &FlowTarget, buf: &[u8]) -> Result<()> {
            self.hits
                .lock()
                .unwrap()
                .push(format!("stub-send:{}", buf.len()));
            Ok(())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> Result<(FlowTarget, usize)> {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }

    /// §10 T7：Chain{hops≥2} → MeshUdpBridge（注册表地址命中 MeshUdpRelay，
    /// FULL 发往 hops[1]）；Direct → inner 连接器（行为可观测）。
    #[tokio::test]
    async fn udp_chain_router_dispatches_chain_and_direct() {
        // 桩 relay 面 socket（chain 臂的下一跳）
        let stub_face = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stub_addr = stub_face.local_addr().unwrap();

        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new(
                "client1".into(),
                NodeRole::Client,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                stub_addr,
            ))
            .unwrap();

        let inner = RoutingUdpConnector::new();
        let hits = Arc::new(Mutex::new(Vec::new()));
        inner.register(
            "direct-out".into(),
            Arc::new(StubConnector {
                hits: Arc::clone(&hits),
            }),
        );
        let router = UdpChainRouter::new(
            inner,
            Some(
                MeshUdpBridge::new(
                    "client1".into(),
                    registry,
                    None,
                    &MeshUdpGate::new(true),
                )
                .unwrap(),
            ),
        );

        // —— Direct 臂：inner 命中注册连接器 ——
        let direct_decision = RouteDecision::direct("direct-out".to_string());
        let relay = router
            .associate(ctx_for("127.0.0.1", 53), &direct_decision)
            .await
            .unwrap();
        let direct_target = FlowTarget {
            host: "127.0.0.1".into(),
            port: 53,
            proto: TargetProto::Udp,
        };
        relay.send_to(&direct_target, b"abc").await.unwrap();
        {
            let h = hits.lock().unwrap();
            assert_eq!(h[0], "stub", "Direct 决策应落 inner 注册连接器");
            assert_eq!(h[1], "stub-send:3");
        }

        // —— Chain 臂：MeshUdpRelay 发 FULL 到 hops[1] 注册地址 ——
        let chain_decision = RouteDecision::chain(vec![
            RouteHop {
                node: "client1".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
        ]);
        let ctx = ctx_for("127.0.0.1", 53);
        let relay = router
            .associate(ctx, &chain_decision)
            .await
            .expect("chain 决策应走 mesh 桥");
        relay
            .send_to(
                &FlowTarget {
                    host: "10.1.2.3".into(),
                    port: 5353,
                    proto: TargetProto::Udp,
                },
                b"hi",
            )
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(2), stub_face.recv_from(&mut buf))
            .await
            .expect("chain 臂 FULL 应发往 hops[1] 注册地址")
            .unwrap()
            .0;
        let env = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(env.dir, UdpDir::Up);
        assert_eq!(env.path_mode, UdpPathMode::Full, "首包 FULL（§5）");
        assert_eq!(env.path, vec!["relay1".to_string()], "path = hops[1..]");
        assert_eq!(env.hop_index, 0, "发送端置 0（§14-1）");
        assert_eq!(env.target_host, "10.1.2.3");
        assert_eq!(env.target_port, 5353);
        assert_eq!(env.payload, b"hi");
    }

    /// §10 T7 配套（§5 send/recv 单测）：桩对端（假 relay）收 FULL 存样、回
    /// CACHED dir=Down；第 2 包起 CACHED；第 65 包重发 FULL；recv 只认匹配回包。
    #[tokio::test]
    async fn mesh_udp_relay_full_then_cached_and_downlink() {
        let stub_face = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let stub_addr = stub_face.local_addr().unwrap();

        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new(
                "client1".into(),
                NodeRole::Client,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                stub_addr,
            ))
            .unwrap();
        let bridge = MeshUdpBridge::new(
            "client1".into(),
            registry,
            None,
            &MeshUdpGate::new(true),
        )
        .unwrap();

        let hops = vec![
            RouteHop {
                node: "client1".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
        ];
        let ctx = ctx_for("127.0.0.1", 53);
        let relay = bridge.associate(ctx, &hops).await.unwrap();

        // —— 第 1 包 FULL ——
        let target = FlowTarget {
            host: "10.9.8.7".into(),
            port: 4242,
            proto: TargetProto::Udp,
        };
        relay.send_to(&target, b"ping").await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, client_from) = tokio::time::timeout(Duration::from_secs(2), stub_face.recv_from(&mut buf))
            .await
            .expect("首包 FULL 应到达桩对端")
            .unwrap();
        let full = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(full.path_mode, UdpPathMode::Full);
        assert_eq!(full.payload, b"ping");

        // —— 第 2 包 CACHED ——
        relay.send_to(&target, b"pong").await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), stub_face.recv_from(&mut buf))
            .await
            .expect("第 2 包应到达")
            .unwrap();
        let cached = decode_udp_envelope(&buf[..n]).unwrap();
        assert_eq!(cached.path_mode, UdpPathMode::Cached, "第 2 包起 CACHED");
        assert!(cached.path.is_empty());
        assert_eq!(cached.payload, b"pong");

        // —— 桩回 CACHED dir=Down → recv_from 命中 ——
        let down = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Down,
            flow_id: full.flow_id,
            target_host: "10.9.8.7".into(),
            target_port: 4242,
            path_mode: UdpPathMode::Cached,
            hop_index: 1,
            path: vec![],
            payload: b"echo!".to_vec(),
        };
        stub_face
            .send_to(&encode_udp_envelope(&down).unwrap(), client_from)
            .await
            .unwrap();
        let mut rbuf = [0u8; 128];
        let (rt, rn) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut rbuf))
            .await
            .expect("dir=Down CACHED 回包应被 recv_from 命中")
            .unwrap();
        assert_eq!(&rbuf[..rn], b"echo!");
        assert_eq!(rt.host, "10.9.8.7");
        assert_eq!(rt.port, 4242);
        assert_eq!(rt.proto, TargetProto::Udp);

        // —— 每 64 包重发 FULL（§5）：第 65 包（n=64，64%64==0）——
        for i in 0..63u64 {
            relay.send_to(&target, &[i as u8]).await.unwrap();
        }
        let mut saw_full = 0;
        let mut saw_cached = 0;
        for _ in 0..63 {
            let (n, _) =
                tokio::time::timeout(Duration::from_secs(2), stub_face.recv_from(&mut buf))
                    .await
                    .expect("重发批次包应到达")
                    .unwrap();
            match decode_udp_envelope(&buf[..n]).unwrap().path_mode {
                UdpPathMode::Full => saw_full += 1,
                UdpPathMode::Cached => saw_cached += 1,
            }
        }
        assert_eq!(saw_full, 1, "63 包中恰 1 个 FULL（第 65 包，n=64）");
        assert_eq!(saw_cached, 62);
    }

    /// gate 构造点拦截（§6 client 侧）：tls=None 且 !allow_plaintext → new 即 Err。
    #[test]
    fn mesh_udp_bridge_gate_rejects_plaintext() {
        let registry = Arc::new(MeshRegistry::new());
        let err = MeshUdpBridge::new(
            "client1".into(),
            registry,
            None,
            &MeshUdpGate::new(false),
        )
        .err()
        .expect("tls=None 且 !allow_plaintext 应在构造点拒绝");
        assert!(
            format!("{err:#}").contains("SEEP_MESH_UDP_ALLOW_PLAINTEXT"),
            "错误信息应含开关名: {err:#}"
        );
    }

    /// 链起点非本机 → 拒绝（客户端侧对位检查，与面侧 §4 步骤 2 同语义）。
    #[tokio::test]
    async fn mesh_udp_bridge_rejects_foreign_chain_start() {
        let registry = Arc::new(MeshRegistry::new());
        let bridge = MeshUdpBridge::new(
            "client1".into(),
            registry,
            None,
            &MeshUdpGate::new(true),
        )
        .unwrap();
        let hops = vec![
            RouteHop {
                node: "other".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
        ];
        assert!(
            bridge.associate(ctx_for("127.0.0.1", 53), &hops).await.is_err(),
            "hops[0] 非本机应拒绝"
        );
    }

    /// P0-5 §10-S3 测试 2：同 bridge 两次 associate 的 relay 共享同一
    /// `UdpClientMetrics`——向两 socket 各注入一个非匹配回包（dir=Up），
    /// 进程级 dropped 跨 relay 累加（§2.4 收编语义钉住）。
    #[tokio::test]
    async fn udp_client_metrics_shared_across_relays() {
        let stub_face = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let stub_addr = stub_face.local_addr().unwrap();

        let registry = Arc::new(MeshRegistry::new());
        registry
            .register_node(NodeRecord::new(
                "client1".into(),
                NodeRole::Client,
                "127.0.0.1:1".parse().unwrap(),
            ))
            .unwrap();
        registry
            .register_node(NodeRecord::new(
                "relay1".into(),
                NodeRole::Relay,
                stub_addr,
            ))
            .unwrap();
        let bridge = MeshUdpBridge::new(
            "client1".into(),
            registry,
            None,
            &MeshUdpGate::new(true),
        )
        .unwrap();
        let metrics = bridge.client_metrics();
        assert_eq!(metrics.dropped(), 0, "初始零");

        let hops = vec![
            RouteHop {
                node: "client1".into(),
                hop_type: seep_core::HopType::Ingress,
            },
            RouteHop {
                node: "relay1".into(),
                hop_type: seep_core::HopType::Relay,
            },
        ];
        let target = FlowTarget {
            host: "10.1.2.3".into(),
            port: 5353,
            proto: TargetProto::Udp,
        };
        let r1 = bridge.associate(ctx_for("127.0.0.1", 53), &hops).await.unwrap();
        let r2 = bridge.associate(ctx_for("127.0.0.1", 53), &hops).await.unwrap();

        // recv 任务先拉起（丢弃计数发生在 recv_from 轮询中，无 poll 者不消费）
        let t1 = {
            let r = Arc::clone(&r1);
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                r.recv_from(&mut b).await
            })
        };
        let t2 = {
            let r = Arc::clone(&r2);
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                r.recv_from(&mut b).await
            })
        };

        // 各发首包 FULL，桩记录两 relay socket 的源地址
        r1.send_to(&target, b"a").await.unwrap();
        r2.send_to(&target, b"b").await.unwrap();
        let mut buf = [0u8; 4096];
        let (_, from1) = tokio::time::timeout(Duration::from_secs(2), stub_face.recv_from(&mut buf))
            .await
            .expect("relay1 FULL 应到达桩")
            .unwrap();
        let (_, from2) = tokio::time::timeout(Duration::from_secs(2), stub_face.recv_from(&mut buf))
            .await
            .expect("relay2 FULL 应到达桩")
            .unwrap();
        assert_ne!(from1, from2, "两个 relay 各持独立 socket");

        // 注入非匹配回包（dir=Up，可解码但不匹配过滤条件）→ 各自丢弃、共享计数累加
        let bad = UdpEnvelope {
            version: UDP_ENVELOPE_VERSION,
            dir: UdpDir::Up,
            flow_id: [0u8; 16],
            target_host: "10.1.2.3".into(),
            target_port: 5353,
            path_mode: UdpPathMode::Cached,
            hop_index: 0,
            path: vec![],
            payload: b"junk".to_vec(),
        };
        let wire = encode_udp_envelope(&bad).unwrap();
        stub_face.send_to(&wire, from1).await.unwrap();
        stub_face.send_to(&wire, from2).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while metrics.dropped() < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(metrics.dropped(), 2, "共享 dropped 跨 relay 累加（§2.4 收编）");

        t1.abort();
        t2.abort();
    }
}
