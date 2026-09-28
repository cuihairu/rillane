//! P0-3 出站 UDP 载荷选路（udp-relay-path.md §3.4/§3.5）。
//! 覆盖：RoutingUdpConnector 按粘滞决策的最终节点选载体；wg 场景错误
//! 关键词（MTU 超限→Timeout 保映射 / allowed_ips→Route 拆映射）的
//! classify_failure 分类经由 send 路径全链路生效。

use bytes::Bytes;
use seep_core::udp::{
    DropReason, EgressUdpConnector, MockUdpRelay, RoutingUdpConnector, UdpSessionConfig,
    UdpSessionKey, UdpSessionTable,
};
use seep_core::{
    FlowContext, FlowId, RouteDecision, RoutePath, RouteType, SessionStatus, TargetProto,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// ---------- 测试基础设施 ----------

struct MockRouter {
    calls: AtomicUsize,
    node: String,
    fail: AtomicBool,
}

impl MockRouter {
    fn new(node: &str) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            node: node.to_string(),
            fail: AtomicBool::new(false),
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl seep_core::FlowRouter for MockRouter {
    async fn route(&self, _ctx: FlowContext) -> anyhow::Result<RouteDecision> {
        if self.fail.load(Ordering::SeqCst) {
            anyhow::bail!("route 不可用");
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RouteDecision {
            path: RoutePath::Direct {
                node: self.node.clone(),
            },
            reason: None,
            route_type: RouteType::Standard,
        })
    }
}

fn addr(p: u16) -> SocketAddr {
    format!("127.0.0.1:{p}").parse().unwrap()
}

fn udp_target(host: &str, port: u16) -> seep_core::FlowTarget {
    seep_core::FlowTarget {
        host: host.to_string(),
        port,
        proto: TargetProto::Udp,
    }
}

async fn make_table(node: &str) -> (Arc<UdpSessionTable>, Arc<MockRouter>) {
    let router = MockRouter::new(node);
    let table = UdpSessionTable::new(
        UdpSessionConfig::default(),
        router.clone() as Arc<dyn seep_core::FlowRouter>,
        seep_core::udp::RealClock::new() as Arc<dyn seep_core::udp::Clock>,
    )
    .unwrap();
    (table, router)
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "wait_until 超时");
        sleep(Duration::from_millis(10)).await;
    }
}

/// 可编程出站连接器：关联即返回预置的 MockUdpRelay（hits 记录节点命中）
struct StubConnector {
    relay: Arc<MockUdpRelay>,
    hits: AtomicUsize,
}

#[async_trait::async_trait]
impl EgressUdpConnector for StubConnector {
    fn name(&self) -> &str {
        "stub"
    }

    async fn associate(
        &self,
        _ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> anyhow::Result<Arc<dyn seep_core::udp::UdpRelay>> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        Ok(self.relay.clone())
    }
}

fn decision_to(node: &str) -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: node.to_string(),
        },
        reason: None,
        route_type: RouteType::Standard,
    }
}

fn flow_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: udp_target(host, port),
        metadata: Default::default(),
    }
}

// ---------- RoutingUdpConnector ----------

#[tokio::test]
async fn routing_connector_selects_connector_by_decision_node() {
    let (ra, _ta) = MockUdpRelay::new(udp_target("a.test", 1));
    let (rb, _tb) = MockUdpRelay::new(udp_target("b.test", 1));
    let ca = Arc::new(StubConnector {
        relay: ra,
        hits: AtomicUsize::new(0),
    });
    let cb = Arc::new(StubConnector {
        relay: rb,
        hits: AtomicUsize::new(0),
    });

    let routing = RoutingUdpConnector::new();
    routing.register("node-a".into(), ca.clone() as Arc<dyn EgressUdpConnector>);
    routing.register("node-b".into(), cb.clone() as Arc<dyn EgressUdpConnector>);
    assert_eq!(routing.registered_nodes().len(), 2);

    let relay_a = routing
        .associate(flow_ctx("a.test", 1), &decision_to("node-a"))
        .await
        .unwrap();
    assert_eq!(
        ca.hits.load(Ordering::SeqCst),
        1,
        "node-a 决策应命中连接器 a"
    );
    assert_eq!(cb.hits.load(Ordering::SeqCst), 0);
    // 决策选出的 relay 可直接发送（Arc<dyn UdpRelay> 与表侧共享所有权）
    relay_a
        .send_to(&udp_target("a.test", 1), b"hi")
        .await
        .unwrap();

    let _ = routing
        .associate(flow_ctx("b.test", 1), &decision_to("node-b"))
        .await
        .unwrap();
    assert_eq!(
        ca.hits.load(Ordering::SeqCst),
        1,
        "node-b 决策不应再碰连接器 a"
    );
    assert_eq!(cb.hits.load(Ordering::SeqCst), 1);

    // 未注册节点：错误信息点名（能力表扫描的正常兜底）
    let err = match routing
        .associate(flow_ctx("x.test", 1), &decision_to("node-x"))
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("未注册节点应关联失败"),
    };
    assert!(
        format!("{err:#}").contains("node-x"),
        "错误应包含节点名: {err:#}"
    );
}

// ---------- wg 场景错误分类（§3.5 × §3.6）----------

#[tokio::test]
async fn wg_mtu_error_classified_timeout_keeps_mapping() {
    let (table, _router) = make_table("wg-node").await;
    let key = UdpSessionKey::new(addr(56000));
    let t = udp_target("10.8.0.7", 3074);
    let sref = table.resolve(&key, &t).await.unwrap();
    let (r, _x) = MockUdpRelay::new(t.clone());
    r.fail_with(Some(
        "wireguard MTU 超限: 1501 字节 > 上限 1420（超出部分按 R8 丢弃）".into(),
    ));
    sref.bind_mapping(&t, r).await.unwrap();

    for _ in 0..3 {
        let res = sref.send_up(&t, vec![0u8; 1501].into()).await;
        assert_eq!(
            res,
            seep_core::udp::UpResult::Dropped {
                reason: DropReason::SendFailed
            }
        );
    }
    sleep(Duration::from_millis(50)).await;
    assert!(
        sref.has_mapping(&t),
        "MTU 超限归 Timeout：映射保留待空闲回收"
    );
    assert!(sref.decision().is_some(), "MTU 超限不应失效粘滞决策");
    assert_eq!(table.snapshot().dropped.get("send_failed"), Some(&3));
}

#[tokio::test]
async fn wg_allowed_ips_error_classified_route_revokes_mapping() {
    let (table, router) = make_table("wg-node").await;
    let key = UdpSessionKey::new(addr(56100));
    let t = udp_target("203.0.113.9", 53);
    let sref = table.resolve(&key, &t).await.unwrap();
    assert_eq!(router.calls(), 1);
    let (r, _x) = MockUdpRelay::new(t.clone());
    r.fail_with(Some(
        "路由不可达: 目标 203.0.113.9:53 不在 wireguard allowed_ips 网段内".into(),
    ));
    sref.bind_mapping(&t, r).await.unwrap();
    assert!(sref.decision().is_some());

    let res = sref.send_up(&t, Bytes::from_static(b"x")).await;
    assert_eq!(
        res,
        seep_core::udp::UpResult::Dropped {
            reason: DropReason::SendFailed
        }
    );
    wait_until(|| !sref.has_mapping(&t)).await;
    assert!(
        sref.decision().is_none(),
        "allowed_ips 不含目标应清除决策触发重路由"
    );
    wait_until(|| sref.ledger().status() == SessionStatus::Failed).await;

    // 下一包重路由（决策重建）；映射缺席 → 本包 Miss 由上层重新关联
    assert_eq!(
        table.forward_up(&key, &t, Bytes::from_static(b"x")).await,
        seep_core::udp::UpResult::Miss
    );
    let _ = table.resolve(&key, &t).await.unwrap();
    assert_eq!(router.calls(), 2, "决策清除后应重新路由");
}
