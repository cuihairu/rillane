use seep_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RoutingConfig,
    SeepConfig, TelemetryConfig,
};
use seep_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, TargetProto};
use seep_mesh::{LinkState, NodeRecord, NodeRole};
use seep_runtime::{MeshConfig, RuntimeBuilder, RuntimeConfig};

#[tokio::test]
async fn mesh_target_routes_to_chain_decision() {
    // Minimal config: socks ingress + direct egress, with default_node pointing at a mesh target.
    let cfg = SeepConfig {
        control: ControlConfig {
            api_bind: "127.0.0.1:0".into(),
            uds_path: None,
            admin_token: None,
        },
        telemetry: TelemetryConfig {
            log_level: "info".into(),
            enable_metrics: false,
            enable_tracing: false,
        },
        ingress: vec![IngressDescriptor {
            name: "socks-in".into(),
            spec: IngressConfig::Socks5 {
                bind: "127.0.0.1:0".into(),
                auth: None,
                udp_enabled: None,
            },
        }],
        egress: vec![EgressDescriptor {
            name: "direct".into(),
            spec: EgressConfig::Direct,
        }],
        routing: RoutingConfig {
            default_node: "mesh.exit1".into(),
            groups: vec![],
            rules: vec![],
        },
    udp: seep_config::UdpConfig::default(),
    network: None,
    obfuscation: None,
    };

    let rt_cfg = RuntimeConfig {
        enable_mesh: true,
        enable_chain: true,
        mesh_config: Some(MeshConfig {
            node_id: "client1".into(),
            role: "client".into(),
            listen_address: "127.0.0.1:10001".parse().unwrap(),
            allow_plaintext_data_plane: true,
            ..MeshConfig::default()
        }),
        ..RuntimeConfig::default()
    };

    let runtime = RuntimeBuilder::new(cfg)
        .with_runtime_config(rt_cfg)
        .build()
        .unwrap();

    let mesh = runtime.get_mesh_registry().unwrap();
    mesh.register_node(NodeRecord::new(
        "exit1".into(),
        NodeRole::Exit,
        "127.0.0.1:10002".parse().unwrap(),
    ))
    .unwrap();

    // Provide link-state so ChainBuilder can build a path client1 -> exit1.
    mesh.update_link_state(LinkState {
        source: "client1".into(),
        target: "exit1".into(),
        latency_ms: 20,
        bandwidth_mbps: 100,
        packet_loss_rate: 0.0,
        last_updated: std::time::Instant::now(),
    })
    .unwrap();

    let router = runtime.flow_router();
    let ctx = FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: "example.com".into(),
            port: 443,
            proto: TargetProto::Tcp,
        },
        metadata: FlowMetadata::default(),
    };

    let decision = router.route(ctx).await.unwrap();
    match decision.path {
        seep_core::RoutePath::Chain { hops } => {
            assert_eq!(hops.first().unwrap().node, "client1");
            assert_eq!(hops.last().unwrap().node, "exit1");
        }
        other => panic!("expected chain decision, got: {other:?}"),
    }
}
