//! TUN 入口集成测试（tun-dataplane.md §4.2，真设备全链路）
//!
//! 无特权环境运行时整组 skip（`/dev/net/tun` 缺失或无 CAP_NET_ADMIN）——
//! 与 linux.rs §4.2 守卫同口径；特权环境（sudo）下覆盖：
//! 设备创建 → include 路由落系统表 → 应用 socket 包进 TUN → 首包 /proc
//! 归因注解 → 路由/关联 → 上行进 mock relay → 下行回注 → 应用收到回声 →
//! 优雅关停后路由回滚 + 设备回收。

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use async_trait::async_trait;
use rillane_core::udp::relay::MockUdpRelay;
use rillane_core::udp::{EgressUdpConnector, UdpRelay};
use rillane_core::{
    Flow, FlowContext, FlowOutput, FlowReport, FlowRouter, IngressEndpoint, RouteDecision,
};
use rillane_platform::network::linux::LinuxTunProvider;
use rillane_platform::network::route::{parse_cidr, RouteRule};
use rillane_platform::network::tun::{TunConfig, TunProvider};
use rillane_platform::network::{NetworkConfig, NetworkMode};
use rillane_runtime::{TunIngress, TunIngressConfig};

/// 记录型路由器（断言目标 + process.* 注解进料）
struct RecordingRouter {
    seen: StdMutex<Vec<FlowContext>>,
}

#[async_trait]
impl FlowRouter for RecordingRouter {
    async fn route(&self, ctx: FlowContext) -> anyhow::Result<RouteDecision> {
        self.seen.lock().unwrap().push(ctx);
        Ok(RouteDecision::direct("mock-egress".into()))
    }
}

/// 空出口（TUN UDP 面不经 FlowOutput::forward）
struct NullOutput;

#[async_trait]
impl FlowOutput for NullOutput {
    async fn forward(&self, _decision: RouteDecision, _flow: Flow) -> anyhow::Result<FlowReport> {
        unreachable!("TUN UDP 面不经 FlowOutput::forward（TCP 归 T4）")
    }
}

/// Stash 连接器：associate 产物（relay + 下行注入通道）留档供测试驱动
struct StashConnector {
    relays: StdMutex<Vec<Arc<MockUdpRelay>>>,
    feeds: StdMutex<Vec<tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

/// run() 签名占位路由器（真实路由经 set_endpoints 先注入——OnceLock 首值胜出）
struct DummyRouter;

#[async_trait]
impl FlowRouter for DummyRouter {
    async fn route(&self, _ctx: FlowContext) -> anyhow::Result<RouteDecision> {
        Ok(RouteDecision::direct("dummy".into()))
    }
}

#[async_trait]
impl EgressUdpConnector for StashConnector {
    fn name(&self) -> &str {
        "stash"
    }
    async fn associate(
        &self,
        ctx: FlowContext,
        _decision: &RouteDecision,
    ) -> anyhow::Result<Arc<dyn UdpRelay>> {
        let (relay, feed) = MockUdpRelay::new(ctx.target);
        self.relays.lock().unwrap().push(relay.clone());
        self.feeds.lock().unwrap().push(feed);
        Ok(relay)
    }
}

/// §4.2 skip 守卫：/dev/net/tun 可开 + 探测建删设备验证 CAP_NET_ADMIN
async fn privileged_tun_or_return() -> bool {
    if let Err(e) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        eprintln!("skip: /dev/net/tun 不可用（{:?}）", e.kind());
        return false;
    }
    let mut probe = LinuxTunProvider::new(TunConfig::default());
    match probe.create_interface().await {
        Ok(()) => {
            let _ = probe.destroy_interface().await;
            true
        }
        Err(e) if e.to_string().contains("CAP_NET_ADMIN") => {
            eprintln!("skip: 无 CAP_NET_ADMIN——{e}");
            false
        }
        Err(e) => panic!("探测 TUN 设备失败：{e:#}"),
    }
}

async fn ip_output(args: &[&str]) -> String {
    let out = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await
        .expect("执行 ip 命令");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// §4.2 全链路（P1-1 捕获钉子 + T3 UDP NAT 面 + §2.5 归因 + §1.3 include
/// 路由 + teardown 回滚）：include 203.0.113.10/32 → 系统路由经 tun →
/// 应用包被 TunIngress 捕获 → 首包归因（本测试进程 comm/pid）→ 上行进
/// mock relay → 下行回注 → 应用 socket 收到回声 → 关停后路由/设备回收。
#[tokio::test]
async fn tun_udp_e2e_capture_route_attribution_echo() {
    if !privileged_tun_or_return().await {
        return;
    }

    let iface = format!("rillane3{:x}", std::process::id());
    let dst: SocketAddr = "203.0.113.10:9999".parse().unwrap();
    let network = NetworkConfig {
        mode: NetworkMode::Tun,
        tun: Some(TunConfig {
            name: Some(iface.clone()),
            ipv4_addr: Some("10.77.0.1".parse().unwrap()),
            ipv4_netmask: Some("255.255.255.0".parse().unwrap()),
            ..Default::default()
        }),
        // include 203.0.113.10/32 → §1.3 main 表显式路由（TEST-NET-3：
        // 不落 private/loopback 默认 bypass，与 tun 网段 auto-bypass 无重叠）
        routing: Some(rillane_platform::network::RoutingConfig {
            enabled: true,
            rules: vec![RouteRule::new(
                "include[0]".into(),
                parse_cidr("203.0.113.10/32").unwrap(),
            )
            .with_metric(0)],
            ..Default::default()
        }),
        filtering: None,
        dns: None,
    };
    let router = Arc::new(RecordingRouter {
        seen: StdMutex::new(Vec::new()),
    });
    let connector = Arc::new(StashConnector {
        relays: StdMutex::new(Vec::new()),
        feeds: StdMutex::new(Vec::new()),
    });
    let tun = Arc::new(TunIngress::new(
        TunIngressConfig {
            tun: network.tun.clone().unwrap(),
            routing: network.routing.clone().unwrap(),
            has_process_rules: true, // §2.5 归因开（进程注解断言面）
            ..Default::default()
        },
        connector.clone(),
    ));
    // 先注记录型 router（run() 二次 set 不覆盖——OnceLock 首值胜出）
    tun.set_endpoints(router.clone(), Arc::new(NullOutput));

    // run：设备生命周期 + include 路由落系统表 + §2.9 包循环（router 已先经
    // set_endpoints 注入记录型——run() 的 set 不覆盖首值）
    let run_handle = tokio::spawn(tun.clone().run(Arc::new(DummyRouter), Arc::new(NullOutput)));

    // 等 include 路由落系统表（§1.3 验收：ip route 读回）
    let route_up = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let out = ip_output(&["route", "show", "203.0.113.10/32"]).await;
            if out.contains(&iface) {
                return out;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("5s 内 include 路由未落系统表");
    assert!(route_up.contains("dev"), "路由读回应带 dev：{route_up}");

    // 应用 socket：bind tun 地址 → 经 include 路由注入 tun fd
    let app = tokio::net::UdpSocket::bind("10.77.0.1:0")
        .await
        .expect("bind 10.77.0.1");
    app.send_to(b"rillane-t3-e2e", dst).await.expect("send_to");

    // 捕获 → 归因 → 路由 → 关联 → 上行（mock relay send 计数）
    let relay = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let r = connector.relays.lock().unwrap().first().cloned();
            if let Some(r) = r {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("5s 内未关联 relay");
    tokio::time::timeout(Duration::from_secs(5), async {
        while relay.send_count() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("5s 内首包载荷未上行");

    // §2.5 归因钉子：process.name = /proc/self/comm（本测试进程）、
    // process.pid = 本进程 pid（应用 socket 即测试进程自己的 UDP socket）
    //（guard 单语句取值即放——不跨 await）
    let ctx = router
        .seen
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("路由器应见到首包 ctx");
    assert_eq!(ctx.target.host, "203.0.113.10");
    assert_eq!(ctx.target.port, 9999);
    let expected_comm = std::fs::read_to_string("/proc/self/comm")
        .expect("读 /proc/self/comm")
        .trim_end()
        .to_string();
    assert_eq!(
        ctx.metadata.annotations.get("process.name"),
        Some(&expected_comm),
        "进程名注解应为测试进程 comm"
    );
    assert_eq!(
        ctx.metadata.annotations.get("process.pid"),
        Some(&std::process::id().to_string()),
        "pid 注解应为测试进程 pid"
    );

    // 下行回注：mock feed → downlink_task → tun 写 → 应用 socket 收回声
    let feed = connector.feeds.lock().unwrap()[0].clone();
    feed.send(b"echo-reply".to_vec()).await.expect("注入下行");
    let mut buf = [0u8; 1500];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), app.recv_from(&mut buf))
        .await
        .expect("5s 内应用未收到下行回声")
        .expect("recv_from");
    assert_eq!(from, dst, "回声源应为目标五元组");
    assert_eq!(&buf[..n], b"echo-reply");

    // 优雅关停：路由回滚 + 设备回收（§2.6 teardown 逆序）
    tun.shutdown();
    tokio::time::timeout(Duration::from_secs(10), run_handle)
        .await
        .expect("run 任务 10s 内退出")
        .expect("join run 任务")
        .expect("run 应正常返回");

    let route_after = ip_output(&["route", "show", "203.0.113.10/32"]).await;
    assert!(
        !route_after.contains(&iface),
        "关停后 include 路由应回滚：{route_after}"
    );
    let link_after = ip_output(&["link", "show", &iface]).await;
    assert!(
        link_after.contains("does not exist") || link_after.contains("无法找到"),
        "关停后设备应回收：{link_after}"
    );
}
