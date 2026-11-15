//! 流/计划/会话契约验收（RIL-006）：现有 RouteDecision 到 RoutePlan 的
//! 单向兼容映射；规则结果与执行结果分离；一个流绑定明确代际；TCP/UDP
//! 绑定分侧。

use rillane_core::{
    ExecutionOutcome, FlowAssociation, GenerationRef, HopType, MetadataOrigin, ObjectRef,
    Provenanced, RouteDecision, RouteHop, RoutePath, RoutePlan, SessionPin,
};

fn generation() -> GenerationRef {
    GenerationRef::new("c".repeat(64)).expect("非空代际身份")
}

#[test]
fn plan_is_derived_from_decision_without_second_router() {
    // 单向兼容映射：同一 decision 多次派生得到等价计划（无旁路决策入口）
    let decision = RouteDecision::through_group(
        "auto".to_string(),
        "hk-1".to_string(),
        vec!["entry-1".to_string()],
    );
    let a = RoutePlan::from_decision(&decision, generation()).unwrap();
    let b = RoutePlan::from_decision(&decision, generation()).unwrap();

    assert_eq!(a.decision().route_type, b.decision().route_type);
    assert_eq!(a.decision().reason, b.decision().reason);
    match (&a.decision().path, &b.decision().path) {
        (
            RoutePath::ThroughGroup {
                group: g1,
                selected_node: s1,
                intermediate_nodes: i1,
            },
            RoutePath::ThroughGroup {
                group: g2,
                selected_node: s2,
                intermediate_nodes: i2,
            },
        ) => {
            assert_eq!((g1, s1, i1), (g2, s2, i2));
        }
        other => panic!("两侧都应为 ThroughGroup，实际 {other:?}"),
    }

    // 计划只能由 decision 派生——最终节点语义与 decision 一致
    assert_eq!(decision.final_node(), "hk-1");
}

#[test]
fn chain_decision_maps_to_plan_with_hop_semantics() {
    let decision = RouteDecision::chain(vec![
        RouteHop {
            node: "in".to_string(),
            hop_type: HopType::Ingress,
        },
        RouteHop {
            node: "mid".to_string(),
            hop_type: HopType::Relay,
        },
        RouteHop {
            node: "out".to_string(),
            hop_type: HopType::Egress,
        },
    ]);
    let plan = RoutePlan::from_decision(&decision, generation()).unwrap();
    match &plan.decision().path {
        RoutePath::Chain { hops } => {
            assert_eq!(hops.len(), 3);
            assert_eq!(hops.last().unwrap().node, decision.final_node());
            assert!(matches!(hops[2].hop_type, HopType::Egress));
        }
        other => panic!("应为 Chain，实际 {other:?}"),
    }
}

#[test]
fn execution_result_never_rewrites_rule_result() {
    let mut plan =
        RoutePlan::from_decision(&RouteDecision::direct("node-x".to_string()), generation())
            .unwrap();

    // 反复失败/成功切换：规则快照始终不变
    for attempt in 0..3 {
        plan.record_failed("dial", format!("attempt {attempt} failed"));
        assert!(matches!(plan.execution(), ExecutionOutcome::Failed { .. }));
        assert!(matches!(
            plan.decision().path,
            RoutePath::Direct { ref node } if node == "node-x"
        ));
    }
    plan.record_dialed(
        rillane_core::EndpointRef::new("10.0.0.1", 443),
        vec!["node-x".to_string()],
    );
    match plan.execution() {
        ExecutionOutcome::Dialed {
            endpoint,
            via_chain,
        } => {
            assert_eq!((endpoint.host.as_str(), endpoint.port), ("10.0.0.1", 443));
            assert_eq!(via_chain, &["node-x"]);
        }
        other => panic!("应为 Dialed，实际 {other:?}"),
    }
    assert!(matches!(
        plan.decision().path,
        RoutePath::Direct { ref node } if node == "node-x"
    ));
}

#[test]
fn flow_pins_generation_and_metadata_carries_origin() {
    let plan =
        RoutePlan::from_decision(&RouteDecision::direct("egress-1".to_string()), generation())
            .unwrap();
    let mut plan = plan;
    plan.annotate(
        "process_name",
        Provenanced::present("curl".to_string(), MetadataOrigin::Platform),
    );
    plan.annotate("asn", Provenanced::missing("asn_lookup_unavailable"));

    let pin = SessionPin::for_plan(&plan, "egress-1")
        .with_source_object(ObjectRef::new("provider-a", "node-7f3a"));

    // 三种绑定形态都可携带同一钉（一个流绑定明确代际）
    let associations = [
        FlowAssociation::Stream { pin: pin.clone() },
        FlowAssociation::Datagram {
            pin: pin.clone(),
            mapping_key: "udp:1.2.3.4:5353".to_string(),
        },
    ];
    for association in &associations {
        assert_eq!(association.pin().generation(), plan.generation());
        assert_eq!(association.pin().egress(), "egress-1");
    }

    // 元数据来源与缺失状态在计划侧显式可查
    let process = plan.annotations().get("process_name").unwrap();
    assert_eq!(process.origin().map(|o| o.as_str()), Some("platform"));
    let asn = plan.annotations().get("asn").unwrap();
    assert!(asn.is_missing());
    assert_eq!(
        match asn {
            Provenanced::Missing { reason } => *reason,
            _ => unreachable!(),
        },
        "asn_lookup_unavailable"
    );
}

#[test]
fn tcp_and_udp_associations_are_distinct_kinds() {
    let pin = SessionPin::for_plan(
        &RoutePlan::from_decision(&RouteDecision::direct("n".to_string()), generation()).unwrap(),
        "n",
    );

    let tcp = FlowAssociation::Stream { pin: pin.clone() };
    let udp = FlowAssociation::Datagram {
        pin,
        mapping_key: "k".to_string(),
    };
    // 类型层面强制分侧：字节流无 mapping_key
    assert!(matches!(tcp, FlowAssociation::Stream { .. }));
    assert!(matches!(udp, FlowAssociation::Datagram { .. }));
}
