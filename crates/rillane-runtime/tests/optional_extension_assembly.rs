//! 可选 Mesh/插件装配验收（RIL-050 / 基于 RIL-040 档位裁剪 + RIL-022 会
//! 话锚定）：标准订阅产物关闭扩展可用（mesh/chain/插件全关——普通订阅
//! 产物真实接管/转发，无 mesh 注册表与 UDP 面）；受管能力协商（受管信
//! 道声明才可协商、版本交集取最大公共、缺能力显式保守回退不 fail-open，
//! 决策核在 rillane-mesh）；插件隔离（扩展面不触策略面——仅
//! `obfuscation.plugins` 差异的同构配置路由决策逐流一致，真实 wasm 插
//! 件在场也不改路由、不破坏标准转发）；未完成安全承载的 UDP Mesh 明确
//! 拒绝（明文门默认关闭、TLS 齐备放行、显式明文开关是 dev 面——不能
//! 明文旁路发布）。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rillane_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor,
    ObfsPluginConfig, ObfuscationConfig, RillaneConfig, RoutingConfig, TelemetryConfig, UdpConfig,
};
use rillane_core::{FlowContext, FlowId, FlowMetadata, FlowTarget, TargetProto};
use rillane_mesh::{negotiate, CapabilityOffer, NegotiationError, PeerHello, PeerTrust};
use rillane_runtime::mesh_transport::{MeshTlsConfig, MeshUdpGate};
use rillane_runtime::{Runtime, RuntimeBuilder, RuntimeConfig};
use rillane_subscription::ClashConverter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// 样本与装配助手（复用 RIL-095 接管验收同款纪律）
// ---------------------------------------------------------------------------

/// 订阅样例（脱敏）：trojan + ss 节点、select + url-test 组、规则 + MATCH
const SAMPLE: &str = r#"
mixed-port: 7890
proxies:
  - name: a-tro
    type: trojan
    server: 203.0.113.10
    port: 443
    password: "REDACTED-SAMPLE"
    sni: a-tro.example.com
    udp: true
  - name: a-ss
    type: ss
    server: 203.0.113.11
    port: 8388
    cipher: aes-256-gcm
    password: "REDACTED-SAMPLE"
    udp: true
proxy-groups:
  - name: A-PROXY
    type: select
    proxies:
      - a-tro
      - a-ss
rules:
  - DOMAIN-SUFFIX,example.net,A-PROXY
  - MATCH,A-PROXY
"#;

static BIND_GUARD: Mutex<()> = Mutex::const_new(());

fn free_bind() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
    format!("127.0.0.1:{}", l.local_addr().expect("端口").port())
}

async fn spawn_echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回显监听");
    let port = l.local_addr().expect("端口").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// 样例 IR → 可运行配置：本地兜底面合并（订阅 catch-all 剥离——RIL-016）
fn merge_local_takeover(ir: RillaneConfig) -> RillaneConfig {
    let mut merged = ir;
    merged.egress.push(EgressDescriptor {
        name: "local-direct".to_string(),
        spec: EgressConfig::Direct,
    });
    merged.routing.default_node = "local-direct".to_string();
    merged.routing.rules.retain(|r| !r.matches.is_empty());
    merged
}

/// 可运行配置的入口/遥测面；`obfuscation` 由调用方注入（None = 扩展面全关）
fn runtime_shell(
    socks_bind: String,
    routing: RoutingConfig,
    egress: Vec<EgressDescriptor>,
    obfuscation: Option<ObfuscationConfig>,
) -> RillaneConfig {
    RillaneConfig {
        version: rillane_config::ConfigVersion::default(),
        control: ControlConfig {
            api_bind: "127.0.0.1:0".to_string(),
            uds_path: None,
            admin_token: None,
        },
        telemetry: TelemetryConfig {
            log_level: "warn".to_string(),
            enable_metrics: false,
            enable_tracing: false,
        },
        ingress: vec![IngressDescriptor {
            name: "assembly-socks".to_string(),
            spec: IngressConfig::Socks5 {
                bind: socks_bind,
                auth: None,
                udp_enabled: Some(false),
            },
        }],
        egress,
        routing,
        udp: UdpConfig {
            enabled: false,
            ..Default::default()
        },
        network: None,
        obfuscation,
        profile: None,
        scenarios: Default::default(),
        performance: None,
        egress_pool: None,
        probe: None,
        streaming: None,
    }
}

fn extensions_off() -> RuntimeConfig {
    RuntimeConfig {
        enable_hot_reload: false,
        // 显式关面：mesh / chain 均为 Default=false——普通订阅产物不依赖 Mesh
        enable_mesh: false,
        enable_chain: false,
        ..RuntimeConfig::default()
    }
}

async fn socks5_roundtrip(bind: &str, target_port: u16, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async move {
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
        let mut s = s.expect("连接入口");
        s.write_all(&[0x05, 0x01, 0x00]).await.expect("方法协商");
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.expect("方法应答");
        assert_eq!(method[1], 0x00, "无认证应被选中");
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&target_port.to_be_bytes());
        s.write_all(&req).await.expect("CONNECT 请求");
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.expect("CONNECT 应答");
        assert_eq!(reply[1], 0x00, "CONNECT 应成功（回环直连）");
        s.write_all(payload).await.expect("载荷发送");
        let mut echoed = vec![0u8; payload.len()];
        s.read_exact(&mut echoed).await.expect("载荷回显");
        echoed
    })
    .await
    .expect("转发往返 5s 内完成")
}

async fn start_with(cfg: RillaneConfig, opts: RuntimeConfig) -> (String, Arc<Runtime>) {
    let _guard = BIND_GUARD.lock().await;
    let socks_bind = match &cfg.ingress[0].spec {
        IngressConfig::Socks5 { bind, .. } => bind.clone(),
        _ => unreachable!(),
    };
    let runtime = Arc::new(
        RuntimeBuilder::new(cfg)
            .with_runtime_config(opts)
            .build()
            .expect("运行时装配"),
    );
    let _tasks = runtime.start().await.expect("启动");
    drop(_guard);
    (socks_bind, runtime)
}

/// 路由输入流上下文（TCP 形状）
fn flow_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        metadata: FlowMetadata::default(),
    }
}

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

/// 普通订阅产物关闭扩展可用：样例转换 → 本地兜底合并 → 运行时
/// （mesh/chain/插件全关）真实接管/转发；运行时无 mesh 注册表、无 UDP
/// mesh 面（扩展缺席不是隐藏降级——装配面如实缺席）。
#[tokio::test]
async fn subscription_product_works_with_extensions_off() {
    let ir = {
        let converter = ClashConverter::new();
        let clash = converter.parse(SAMPLE).expect("样例解析");
        converter.convert_to_rillane(&clash).expect("样例转换")
    };
    let merged = merge_local_takeover(ir);
    let cfg = runtime_shell(
        free_bind(),
        merged.routing,
        merged.egress,
        None, // 扩展面全关：obfuscation 缺席
    );
    let (bind, runtime) = start_with(cfg, extensions_off()).await;

    // 装配面如实缺席：可选能力不开就没有面——不是「开着但空转」
    assert!(
        runtime.get_mesh_registry().is_none(),
        "mesh 关闭时注册表缺席"
    );
    assert!(
        runtime.get_mesh_udp_snapshot().is_none(),
        "mesh 关闭时 UDP 面缺席"
    );

    // 标准订阅产物照常真实转发（文本 + 二进制载荷）
    let echo_port = spawn_echo_server().await;
    let echoed = socks5_roundtrip(&bind, echo_port, b"no-mesh-e2e").await;
    assert_eq!(echoed, b"no-mesh-e2e", "关闭扩展后照常转发");
    let echoed = socks5_roundtrip(&bind, echo_port, &[0u8, 9, 255]).await;
    assert_eq!(echoed, [0u8, 9, 255], "二进制载荷照实转发");
    runtime.stop().await.expect("停止");
}

/// 插件隔离：真实 wasm 插件（inline wat 编译落盘）在场的运行时与同构
/// 无插件运行时——路由决策逐流一致（扩展面不触策略面）；插件运行时
/// 标准转发照常（插件只做字节变换，不拦截/改向流量）。
#[tokio::test]
async fn plugins_do_not_alter_policy_or_standard_path() {
    // 最小 wasm 插件（与 rillane-plugins §1.2 同 ABI 面）：on_flow 按 §1.3
    // 写出 allow 决策 JSON（18 字节）——空输出会决策解析失败炸流（真实
    // 流量路径的第一只用 wasm 插件，与只装配不转发的链装配单测不同）
    let wat = r#"(module
        (memory (export "memory") 1)
        (global $heap (mut i32) (i32.const 1024))
        (data (i32.const 0) "assembly-test-plugin\00")
        (data (i32.const 512) "{\"action\":\"allow\"}")
        (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $heap))
            (global.set $heap (i32.add (local.get $p) (i32.add (local.get $size) (i32.const 7))))
            (local.get $p))
        (func (export "plugin_name") (result i32) (i32.const 0))
        (func (export "wants_payload") (result i32) (i32.const 0))
        (func (export "on_flow") (param $ctx_ptr i32) (param $ctx_len i32)
            (param $out_ptr i32) (param $out_cap i32) (result i32)
            (local $i i32)
            (local.set $i (i32.const 0))
            (block $done
                (loop $copy
                    (br_if $done (i32.ge_u (local.get $i) (i32.const 18)))
                    (i32.store8
                        (i32.add (local.get $out_ptr) (local.get $i))
                        (i32.load8_u (i32.add (i32.const 512) (local.get $i))))
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))
                    (br $copy)))
            (i32.const 18))
    )"#;
    let dir = std::env::temp_dir().join(format!("rillane-assembly-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("插件临时目录");
    let wasm_path = dir.join("assembly-test.wasm");
    std::fs::write(&wasm_path, wat::parse_str(wat).expect("wat 编译")).expect("落盘");

    let ir = {
        let converter = ClashConverter::new();
        let clash = converter.parse(SAMPLE).expect("样例解析");
        converter.convert_to_rillane(&clash).expect("样例转换")
    };
    let merged = merge_local_takeover(ir);

    // 同构配置：仅 obfuscation.plugins 差异
    let plain = runtime_shell(
        free_bind(),
        merged.routing.clone(),
        merged.egress.clone(),
        None,
    );
    let with_plugin = runtime_shell(
        free_bind(),
        merged.routing,
        merged.egress,
        Some(ObfuscationConfig {
            enabled: true,
            plugins: vec![ObfsPluginConfig {
                path: PathBuf::from(&wasm_path),
                fuel: None,
            }],
            ..ObfuscationConfig::default()
        }),
    );

    let (_plain_bind, plain_runtime) = start_with(plain, extensions_off()).await;
    let (plugin_bind, plugin_runtime) = start_with(with_plugin, extensions_off()).await;

    // 策略面逐流一致：同一组流的决策在两个运行时全同（扩展面不改路由）
    let flows = [
        ("www.example.net", 443), // 命中订阅 DOMAIN-SUFFIX 规则
        ("other.example.org", 80),
        ("203.0.113.9", 8080),
    ];
    for (host, port) in flows {
        let a = plain_runtime
            .flow_router()
            .route(flow_ctx(host, port))
            .await
            .expect("plain 决策");
        let b = plugin_runtime
            .flow_router()
            .route(flow_ctx(host, port))
            .await
            .expect("plugin 决策");
        assert_eq!(
            a.final_node(),
            b.final_node(),
            "插件在场不改路由决策: {host}:{port}"
        );
    }

    // 标准路径不坏：插件运行时照常真实转发
    let echo_port = spawn_echo_server().await;
    let echoed = socks5_roundtrip(&plugin_bind, echo_port, b"plugin-must-not-intercept").await;
    assert_eq!(
        echoed, b"plugin-must-not-intercept",
        "插件只做字节变换，不拦截标准转发"
    );

    plain_runtime.stop().await.expect("停止");
    plugin_runtime.stop().await.expect("停止");
    let _ = std::fs::remove_dir_all(&dir);
}

/// UDP Mesh 安全承载门与受管协商：默认明文门拒绝（缺 TLS 且未显式允许
/// → 拒绝点名明文）；TLS 齐备放行；显式明文开关是 dev 面而非默认；受
/// 管协商任一侧安全承载未完成 → udp_mesh_allowed=false + 原因（不能明
/// 文旁路发布）；未受管声明一律拒绝（能力面不接受匿名申报）。
#[test]
fn udp_mesh_and_capability_negotiation_refuse_incomplete_security() {
    // 默认明文门：TLS 缺席 + 未显式允许 → 拒绝（点名明文与 env 开关）
    let gate = MeshUdpGate::new(false);
    let err = gate
        .ensure_usable(None)
        .expect_err("未配置加密且未显式允许明文须拒绝");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("明文"), "拒绝原因点名明文: {rendered}");

    // TLS 齐备：同一门放行（安全承载在场）
    let tls = MeshTlsConfig {
        ca_cert_path: PathBuf::from("/tmp/rillane-acceptance-ca.pem"),
        cert_path: PathBuf::from("/tmp/rillane-acceptance-cert.pem"),
        key_path: PathBuf::from("/tmp/rillane-acceptance-key.pem"),
        server_name: "mesh-acceptance".to_string(),
        require_client_auth: true,
        verify_peer_node_id: true,
        allow_unknown_peers: false,
        revoked_node_ids: Vec::new(),
        revoked_nodes_path: None,
    };
    gate.ensure_usable(Some(&tls)).expect("TLS 齐备应放行");

    // dev 明文面：只经显式开关进入（显式 new(true)），默认面 gate(false)
    // ——产品默认是拒绝，不是静默旁路
    let explicit_dev = MeshUdpGate::new(true);
    explicit_dev
        .ensure_usable(None)
        .expect("显式明文开关是 dev 面——显式才放行");

    // 受管协商：安全承载任一侧未完成 → 明确拒绝 + 原因（可审计不 fail-open）
    let ready = CapabilityOffer {
        envelope_versions: vec![1, 2],
        padding: true,
        udp_secure_carriage: true,
    };
    let half = CapabilityOffer {
        envelope_versions: vec![2],
        padding: true,
        udp_secure_carriage: false,
    };
    let out = negotiate(
        &ready,
        &PeerHello {
            peer: "peer-1".to_string(),
            offer: half,
            trust: PeerTrust::Managed,
        },
    )
    .expect("受管声明可协商");
    assert!(!out.udp_mesh_allowed, "对端未完成安全承载 → UDP mesh 拒绝");
    assert!(
        out.notes.iter().any(|n| n.contains("明文")),
        "拒绝原因显式留痕: {:?}",
        out.notes
    );

    // 未受管声明一律拒绝：能力面不接受匿名申报（稳定原因码）
    let err = negotiate(
        &ready,
        &PeerHello {
            peer: "stranger".to_string(),
            offer: ready.clone(),
            trust: PeerTrust::Untrusted,
        },
    )
    .expect_err("未受管声明须拒绝");
    let NegotiationError::Untrusted(peer) = &err else {
        panic!("应为 Untrusted: {err:?}");
    };
    assert_eq!(peer, "stranger");
}
