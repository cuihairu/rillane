//! UDP config/key/ledger/metrics/inner 单测（覆盖率批次：这些子模块此前 0%）。
//! 纯逻辑面：validate 约束、粘滞键归一、ledger O7 恢复与链故障、表指标分桶。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rillane_core::udp::{
    Dir, DropReason, ExpireReason, ProcessIdentity, SessionLedger, TableMetrics, UdpSessionConfig,
    UdpSessionKey,
};
use rillane_core::{FailureType, FlowId, RouteDecision, RoutePath, RouteType, SessionStatus};

fn client(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

// ---------- UdpSessionConfig::validate ----------

#[test]
fn udp_config_default_passes_validation() {
    let cfg = UdpSessionConfig::default();
    cfg.validate().expect("默认配置必须合法");
    assert_eq!(cfg.mapping_idle, Duration::from_secs(60));
    assert_eq!(cfg.session_idle, Duration::from_secs(180));
    assert_eq!(cfg.sweep_interval, Duration::from_secs(15));
    assert_eq!(cfg.max_sessions, 4096);
    assert_eq!(cfg.max_mappings, 256);
    assert_eq!(cfg.downlink_capacity, 64);
    assert!(cfg.session_max_lifetime.is_none());
}

#[test]
fn udp_config_validate_rejects_each_zero_field() {
    let bad = UdpSessionConfig {
        mapping_idle: Duration::from_secs(0),
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err(), "mapping_idle=0 必须被拒");

    let bad = UdpSessionConfig {
        session_idle: Duration::from_secs(0),
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err());

    let bad = UdpSessionConfig {
        sweep_interval: Duration::from_millis(0),
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err());

    let bad = UdpSessionConfig {
        max_sessions: 0,
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err());

    let bad = UdpSessionConfig {
        max_mappings: 0,
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err());

    let bad = UdpSessionConfig {
        downlink_capacity: 0,
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err());

    // lifetime < idle 必须被拒；>= idle 合法
    let bad = UdpSessionConfig {
        session_max_lifetime: Some(Duration::from_secs(10)),
        ..UdpSessionConfig::default()
    };
    assert!(bad.validate().is_err());
    let good = UdpSessionConfig {
        session_max_lifetime: Some(Duration::from_secs(180)),
        ..UdpSessionConfig::default()
    };
    good.validate().expect("lifetime == idle 应合法");
}

// ---------- UdpSessionKey ----------

#[test]
fn udp_key_normalizes_user_and_distinguishes_dimensions() {
    use std::collections::HashSet;

    let base = UdpSessionKey::new(client(5000));
    assert_eq!(base.user, None);
    assert_eq!(base.process, None);

    let named = base
        .clone()
        .with_user(Some("Alice".into()))
        .with_process(Some(ProcessIdentity {
            pid: 7,
            name: "game".into(),
        }));
    // 用户名统一小写
    assert_eq!(named.user.as_deref(), Some("alice"));
    assert_eq!(named.process.as_ref().unwrap().pid, 7);
    // None 用户经 with_user 保持 None
    assert_eq!(base.clone().with_user(None).user, None);
    assert_eq!(base.clone().with_process(None).process, None);

    // 维度出现即参与区分（Hash/Eq）
    let mut set = HashSet::new();
    set.insert(base.clone());
    set.insert(named.clone());
    assert_eq!(set.len(), 2);
    // 同键小写归一合并：alice 与 ALICE 是同一个键
    set.insert(named.clone().with_user(Some("ALICE".into())));
    assert_eq!(set.len(), 2, "alice/ALICE 应归一为同键");
    // 端口不同即不同会话
    set.insert(UdpSessionKey::new(client(5001)));
    assert_eq!(set.len(), 3);
}

// ---------- SessionLedger（O7 恢复 / 链故障 / 路由历史） ----------

fn direct_decision(node: &str, reason: Option<&str>) -> RouteDecision {
    RouteDecision {
        path: RoutePath::Direct {
            node: node.to_string(),
        },
        reason: reason.map(String::from),
        route_type: RouteType::Standard,
    }
}

#[test]
fn ledger_counts_packets_and_recovers_via_o7() {
    let ledger = SessionLedger::create(FlowId::new());
    // 新建会话为 Initializing；收到首包即 O7 恢复为 Active
    assert_eq!(ledger.status(), SessionStatus::Initializing);
    ledger.on_packet(Dir::Up, 100);
    ledger.on_packet(Dir::Down, 900);
    ledger.on_packet(Dir::Down, 10);

    let usage = ledger.usage();
    assert_eq!(usage.bytes_uploaded, 100);
    assert_eq!(usage.bytes_downloaded, 910);
    assert_eq!(usage.packets_count, 3);
    assert_eq!(ledger.status(), SessionStatus::Active);

    // Failed → 新包恢复 Active（UDP 链路故障是可退化态，非终态）
    ledger.on_error(FailureType::Timeout);
    assert_eq!(ledger.status(), SessionStatus::Failed);
    ledger.on_packet(Dir::Up, 1);
    assert_eq!(ledger.status(), SessionStatus::Active);
}

#[test]
fn ledger_route_history_and_chain_events() {
    let ledger = SessionLedger::create(FlowId::new());

    // 未 attach 链：链故障与本会话无关 → None
    assert!(ledger
        .on_link_failure("chain-a", &["node-a".to_string()])
        .is_none());

    ledger.attach_chain("chain-a");
    ledger.on_route_changed(&direct_decision("node-a", Some("first pick")));
    assert_eq!(ledger.current_path(), vec!["node-a".to_string()]);

    // 绑定链故障：记录 Route 失败并返回失败节点（表侧据此吊销映射）
    let revoked = ledger
        .on_link_failure("chain-a", &["node-a".to_string(), "node-b".to_string()])
        .expect("绑定链故障必须返回需吊销节点");
    assert_eq!(revoked, vec!["node-a".to_string(), "node-b".to_string()]);
    assert_eq!(ledger.status(), SessionStatus::Failed);

    // 其他链故障与本会话无关
    assert!(ledger
        .on_link_failure("chain-b", &["node-x".to_string()])
        .is_none());

    // 无 reason 的决策落空字符串，不 panic
    ledger.on_route_changed(&direct_decision("node-c", None));
    assert_eq!(ledger.current_path(), vec!["node-c".to_string()]);
}

// ---------- TableMetrics ----------

#[test]
fn table_metrics_buckets_drops_expires_and_bytes() {
    let m = TableMetrics::new();
    m.drop_inc(DropReason::SessionLimit);
    m.drop_inc(DropReason::SessionLimit);
    m.drop_inc(DropReason::MappingLimit);
    m.drop_inc(DropReason::NoBinding);
    m.drop_inc(DropReason::ShuttingDown);
    m.drop_inc(DropReason::SendFailed);
    m.drop_inc(DropReason::DownlinkFull);

    assert_eq!(m.drop_count(DropReason::SessionLimit), 2);
    assert_eq!(m.drop_count(DropReason::MappingLimit), 1);
    assert_eq!(m.drop_count(DropReason::NoBinding), 1);
    assert_eq!(m.drop_count(DropReason::ShuttingDown), 1);
    assert_eq!(m.drop_count(DropReason::SendFailed), 1);
    assert_eq!(m.drop_count(DropReason::DownlinkFull), 1);

    m.expired_inc(ExpireReason::Idle);
    m.expired_inc(ExpireReason::Lifetime);
    m.expired_inc(ExpireReason::Revoked);
    assert_eq!(m.expired_count(ExpireReason::Idle), 1);
    assert_eq!(m.expired_count(ExpireReason::Lifetime), 1);
    assert_eq!(m.expired_count(ExpireReason::Revoked), 1);

    m.count_bytes(Dir::Up, 111);
    m.count_bytes(Dir::Down, 222);
    assert_eq!(m.bytes_up(), 111);
    assert_eq!(m.bytes_down(), 222);

    // default 与 new 等价：零值
    let d = TableMetrics::default();
    assert_eq!(d.bytes_up(), 0);
    assert_eq!(d.drop_count(DropReason::SessionLimit), 0);
}
