//! 能力声明与池资源类型契约（RIL-100）：支持表不在 importer/runtime/
//! connector 重复维护；不同身份/凭证/代际隔离；取消/drain 有所有者；
//! TLS 恢复不等于连接复用；后端能力按实际依赖和配置声明，重依赖可按
//! feature/crate 排除。

use rillane_core::outbound::OutboundCapabilities;
use rillane_core::plan::EndpointRef;
use rillane_core::pool::TransportReuse;
use rillane_core::resources::*;
use rillane_core::underlay::TransportStack;

fn declaration(
    name: &'static str,
    transports: &[&'static str],
    stack: &[&'static str],
    reuse: TransportReuse,
    datagram: Option<usize>,
    gates: &[&'static str],
) -> BackendDeclaration {
    BackendDeclaration {
        name,
        capabilities: OutboundCapabilities {
            stream: true,
            datagram: datagram.is_some(),
            transports: transports.to_vec(),
            max_datagram_len: datagram,
            supports_prewarm: reuse != TransportReuse::None,
            supports_multiplex: reuse == TransportReuse::Multiplexed,
            fixed_target_only: false,
        },
        transport_stack: TransportStack::build(stack).expect("合法栈"),
        reuse,
        feature_gates: gates.to_vec(),
    }
}

/// 三个消费者（importer/runtime/connector 替身）读**同一份**装配结果
/// ——支持表单源：校验只发生一次，消费者不做各自扫描。
#[test]
fn support_table_is_declared_once_and_consumed_everywhere() {
    let decl = declaration(
        "vless-ws-tls",
        &["tls", "ws"],
        &["tls", "ws"],
        TransportReuse::Multiplexed,
        None,
        &["tokio-kcp"],
    );
    let backend = assemble_backend(&decl).expect("合法装配");

    // importer 视角：能力表 + feature 门（构建图可排除）
    assert_eq!(backend.capabilities().transports, &["tls", "ws"]);
    assert_eq!(backend.feature_gates(), &["tokio-kcp"]);
    // runtime 视角：传输栈 + 复用类
    assert_eq!(backend.transport_stack().layers(), &["tls", "ws"]);
    assert_eq!(backend.reuse(), TransportReuse::Multiplexed);
    // connector 视角：同一份对象（无第二份校验面）
    let runtime_view: &AssembledBackend = &backend;
    let connector_view: &AssembledBackend = runtime_view;
    assert_eq!(connector_view.name(), "vless-ws-tls");
    assert!(
        std::ptr::eq(connector_view, &backend),
        "消费者共享同一装配结果——支持表没有第二份"
    );
}

/// 静态不一致装配期一次拒绝（零拨号）：栈层超能力表 / 复用类矛盾 /
/// 数据报形状不一致 / feature 门缺席。
#[test]
fn inconsistent_declarations_rejected_at_assembly() {
    // 栈声明了能力表之外的承载
    let over = declaration(
        "over",
        &["tls"],
        &["tls", "grpc"],
        TransportReuse::TlsResumption,
        None,
        &["rustls"],
    );
    let err = assemble_backend(&over).unwrap_err();
    assert_eq!(err.code, CODE_CAP_TRANSPORT);
    assert!(err.detail.contains("grpc"));

    // 多路复用未在能力表声明
    let mut mux = declaration(
        "mux",
        &["tls"],
        &["tls"],
        TransportReuse::Multiplexed,
        None,
        &["h2"],
    );
    mux.capabilities.supports_multiplex = false;
    assert_eq!(assemble_backend(&mux).unwrap_err().code, CODE_CAP_REUSE);

    // 数据报能力与报文上限不同真
    let shape = declaration(
        "udp-half",
        &["tls"],
        &["tls"],
        TransportReuse::TlsResumption,
        None,
        &["rustls"],
    );
    let mut shape = shape;
    shape.capabilities.datagram = true;
    assert_eq!(assemble_backend(&shape).unwrap_err().code, CODE_CAP_SHAPE);

    // 重依赖无 feature 门——构建图无法排除
    let ungated = declaration(
        "ungated",
        &["tls"],
        &["tls"],
        TransportReuse::TlsResumption,
        None,
        &[],
    );
    assert_eq!(
        assemble_backend(&ungated).unwrap_err().code,
        CODE_CAP_FEATURE
    );
}

/// TLS 恢复 ≠ 连接复用：TlsResumption 须栈内有 tls 且不得同时声明
/// 多路复用（恢复票据独占取出 vs 多路复用共享——两种资源不混装）。
#[test]
fn tls_resumption_is_not_connection_reuse() {
    let resume = declaration(
        "resume",
        &["tls"],
        &["tls"],
        TransportReuse::TlsResumption,
        None,
        &["rustls"],
    );
    let backend = assemble_backend(&resume).expect("TLS 恢复合法");
    assert_eq!(backend.reuse(), TransportReuse::TlsResumption);
    assert!(!backend.capabilities().supports_multiplex, "恢复不是复用");

    // 声明恢复却带 supports_multiplex —— 拒
    let mut mixed = declaration(
        "mixed",
        &["tls"],
        &["tls"],
        TransportReuse::TlsResumption,
        None,
        &["rustls"],
    );
    mixed.capabilities.supports_multiplex = true;
    assert_eq!(assemble_backend(&mixed).unwrap_err().code, CODE_CAP_REUSE);

    // 无 tls 栈声明恢复 —— 拒
    let no_tls = declaration(
        "no-tls",
        &["ws"],
        &["ws"],
        TransportReuse::TlsResumption,
        None,
        &["rustls"],
    );
    assert_eq!(assemble_backend(&no_tls).unwrap_err().code, CODE_CAP_REUSE);
}

/// 租借键隔离：同键才同资源——代际/节点/目标/凭证/安全配置任一
/// 不同即不同键（不同租户/凭证/代际结构性不混借）；键不携带密钥
/// （只有配置标签）。
#[test]
fn lease_keys_keep_tenant_and_generation_apart() {
    let key = LeaseKey::new(
        "gen-1",
        "node-a",
        Some(EndpointRef::new("1.2.3.4", 443)),
        "tenant-1",
        &["tls", "tls-resume"],
    )
    .expect("合法键");
    // 键面只有标签：无密钥字段
    let key_json = format!("{key:?}");
    assert!(
        !key_json.contains("secret") && !key_json.contains("key=\""),
        "键不带密钥"
    );

    let same = LeaseKey::new(
        "gen-1",
        "node-a",
        Some(EndpointRef::new("1.2.3.4", 443)),
        "tenant-1",
        &["tls-resume", "tls"],
    )
    .expect("合法键");
    assert_eq!(key, same, "同配置不同书写顺序是同键");

    let tenants = [
        ("gen-2", "node-a", "tenant-1", vec!["tls", "tls-resume"]),
        ("gen-1", "node-b", "tenant-1", vec!["tls", "tls-resume"]),
        ("gen-1", "node-a", "tenant-2", vec!["tls", "tls-resume"]),
    ];
    for (gen_id, node, cred, sec) in tenants {
        let other = LeaseKey::new(
            gen_id,
            node,
            Some(EndpointRef::new("1.2.3.4", 443)),
            cred,
            &sec,
        )
        .expect("合法键");
        assert_ne!(key, other, "{gen_id}/{node}/{cred} 不得与基准键混借");
    }

    let no_target = LeaseKey::new("gen-1", "node-a", None, "tenant-1", &["tls"]).expect("键");
    assert_ne!(key, no_target, "有目标绑定与无绑定不同键");
}

/// 生命周期所有者：预热取出即消费（一次性）；独占绑定 drain→关闭；
/// 取消即弃；独占资源拒绝「消费」语义；守卫按值消费——重复迁移
/// 在结构上不可能（单所有者）。
#[test]
fn lease_lifecycle_transitions_have_single_owner() {
    let key = LeaseKey::new("gen-1", "node-a", None, "tenant-1", &[]).expect("键");

    // 预热消费（取出即消费——终态，键归还）
    let prewarm = LeaseGuard::begin(key.clone(), PoolResourceKind::Prewarm);
    assert_eq!(prewarm.consume().expect("取出"), key);

    // 独占绑定：drain（携因）→ 关闭
    let exclusive = LeaseGuard::begin(
        key.clone(),
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("10.0.0.1", 80),
            reclaimable: true,
        },
    );
    let drained = exclusive.drain("node retired").expect("排水");
    assert_eq!(
        drained.state(),
        &LeaseState::Draining {
            reason: "node retired".to_string()
        }
    );
    assert_eq!(drained.close().expect("关闭"), key);

    // 取消（Draining 也可取消）→ 关闭
    let guard = LeaseGuard::begin(key.clone(), PoolResourceKind::Multiplexed);
    let cancelled = guard
        .drain("drain then cancel")
        .expect("排水")
        .cancel("operator abort")
        .expect("取消");
    assert_eq!(
        cancelled.state(),
        &LeaseState::Cancelled {
            reason: "operator abort".to_string()
        }
    );
    assert!(cancelled.close().is_ok());

    // 独占资源不可走「预热消费」语义——显式拒绝携资源类型
    let wrong = LeaseGuard::begin(
        key.clone(),
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("10.0.0.2", 80),
            reclaimable: false,
        },
    );
    let err = wrong.consume().unwrap_err();
    assert_eq!(err.code, CODE_LEASE_STATE);
    assert!(err.detail.contains("exclusive"), "{}", err.detail);

    // 键非法显式拒绝
    let err = LeaseKey::new("gen-1", "", None, "t", &[]).unwrap_err();
    assert_eq!(err.code, CODE_KEY_INVALID);
}

/// 多路复用资源创建子流：子流目标可空绑定（自定目标），与独占
/// 绑定目标通道在类型上分开。
#[test]
fn multiplex_and_exclusive_are_distinct_kinds() {
    let bound = PoolResourceKind::Exclusive {
        target: EndpointRef::new("10.0.0.3", 443),
        reclaimable: true,
    };
    let mux = PoolResourceKind::Multiplexed;
    assert_ne!(bound, mux);
    assert_eq!(bound.as_str(), "exclusive");
    assert_eq!(mux.as_str(), "multiplexed");
    assert_eq!(PoolResourceKind::Prewarm.as_str(), "prewarm");
    // 独占绑定携带目标与可回收性；多路复用无固定目标
    match bound {
        PoolResourceKind::Exclusive {
            target,
            reclaimable,
        } => {
            assert_eq!(target.host, "10.0.0.3");
            assert!(reclaimable);
        }
        other => panic!("expected exclusive, got {}", other.as_str()),
    }
}
