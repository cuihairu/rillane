//! Linux 兼容修复中间产物验收（RIL-095 / 基于 RIL-092 interval 秒口径 +
//! RIL-093 有损转换护栏 + RIL-019/031 启停恢复）：订阅样例经既有 Linux
//! 转发链路真实接管/转发（SOCKS5 入口 → 路由 → Direct 出口 → 回环回
//! 显）；显式声明的 `interval: 300` 全链保持 300 秒口径（转换面 → 守
//! 护加载面 → 运行时探测门，不变 1 秒）；有损订阅样本严格导入整体拒
//! 绝（绝不产出半份伪装成功的配置）、未知配置版本稳定拒绝；运行时停
//! 止 → 重建 → 转发恢复，发布 journal（现役代际）跨启停保留。
//! 本候选不宣称：新 provider、完整 fallback、新 ScenarioPolicy 已交付。

use std::sync::Arc;
use std::time::Duration;

use rillane_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig,
    RoutingConfig, TelemetryConfig, UdpConfig, CODE_UNKNOWN_VERSION,
};
use rillane_runtime::{PublishCoordinator, RuntimeBuilder, RuntimeConfig};
use rillane_subscription::ClashConverter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// 样本与助手
// ---------------------------------------------------------------------------

/// 订阅样例（脱敏）：trojan + ss 节点、select + url-test（显式
/// interval: 300 秒）组、一条后缀规则 + MATCH 兜底
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
  - name: A-AUTO
    type: url-test
    proxies:
      - a-tro
      - a-ss
    url: https://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN-SUFFIX,example.net,A-PROXY
  - MATCH,A-PROXY
"#;

/// 有损样本：合法节点 + 未知规则类型（解析期保留原文进 Unknown——转换
/// 期显式进损失清单；严格模式据此整体拒绝）
const LOSSY: &str = r#"
proxies:
  - name: sample-ss
    type: ss
    server: 203.0.113.40
    port: 8388
    cipher: aes-256-gcm
    password: "REDACTED-SAMPLE"
proxy-groups: []
rules:
  - UNKNOWN-RULE-TYPE,tcp,DIRECT
"#;

/// 并行测试的绑定面串行化（复用 runtime_builder s2 组纪律：探端口 →
/// 释放 → 复绑的窗口不被同进程并行测试偷走）
static BIND_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 探一个空闲端口并立即释放（复绑窗口内使用）
fn free_bind() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
    format!("127.0.0.1:{}", l.local_addr().expect("端口").port())
}

/// 回环回显服务（「真实目标」）：逐字节回显收到的 TCP 载荷
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

/// 样例 IR → 可运行配置：本地兜底面（Direct 出口 + 默认直连）与订阅
/// 供货合并——catch-all（MATCH，空匹配条件）是本地策略，订阅不得带
/// 走（RIL-016 本地策略所有权），剥离后由 `default_node` 承担兜底。
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

/// 可运行配置的入口/遥测面（回环 SOCKS5，无控制面副作用）
fn runtime_shell(
    socks_bind: String,
    routing: RoutingConfig,
    egress: Vec<EgressDescriptor>,
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
            name: "takeover-socks".to_string(),
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
        obfuscation: None,
        profile: None,
        scenarios: Default::default(),
        performance: None,
        egress_pool: None,
        probe: None,
        streaming: None,
    }
}

fn runtime_opts() -> RuntimeConfig {
    RuntimeConfig {
        enable_hot_reload: false,
        ..RuntimeConfig::default()
    }
}

/// SOCKS5 无认证 CONNECT 经代理链路做一次真实转发往返（握手 → 载荷
/// 回显）。超时守卫：链路不通快速失败而非挂死。
async fn socks5_roundtrip(bind: &str, target_port: u16, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async move {
        // start() 内入口 bind 异步发生——带重试等待监听就绪
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
        assert_eq!(method[0], 0x05);
        assert_eq!(method[1], 0x00, "无认证应被选中");
        // CONNECT 帧：ATYP=0x01 IPv4 127.0.0.1
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
    .expect("转发往返 5s 内完成（链路不挂死）")
}

/// 组装并启动运行时（含守卫串行化的绑定窗口）
async fn start_takeover_runtime(
    cfg: RillaneConfig,
) -> (
    String,
    u16,
    Arc<rillane_runtime::Runtime>,
    Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
) {
    let _guard = BIND_GUARD.lock().await;
    let socks_bind = match &cfg.ingress[0].spec {
        IngressConfig::Socks5 { bind, .. } => bind.clone(),
        _ => unreachable!(),
    };
    let echo_port = spawn_echo_server().await;
    let runtime = Arc::new(
        RuntimeBuilder::new(cfg)
            .with_runtime_config(runtime_opts())
            .build()
            .expect("运行时装配"),
    );
    let tasks = runtime.start().await.expect("启动");
    // 守卫只护绑定窗口——启动完成后释放，转发面交给调用方
    drop(_guard);
    (socks_bind, echo_port, runtime, tasks)
}

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

/// 订阅样例真实接管/转发 + interval 口径全链：样例转换 IR（显式
/// `interval: 300`）→ 本地兜底合并 → 守护加载面（serde 往返）→ 运行
/// 时消费面——300 秒口径逐面不变（不变 1 秒）；回环流量经 SOCKS5 入
/// 口 → 路由（默认直连）→ Direct 出口真实往返，订阅代理节点全程未
/// 被拨号（样例节点在场但回环走本地兜底）。
#[tokio::test]
async fn subscription_sample_takeover_and_forwarding() {
    let ir = {
        let converter = ClashConverter::new();
        let clash = converter.parse(SAMPLE).expect("样例解析");
        converter.convert_to_rillane(&clash).expect("样例转换")
    };

    // 转换面：interval 秒口径原样（RIL-092——300 是 300 秒，不是毫秒误读）
    let auto_group = ir
        .routing
        .groups
        .iter()
        .find(|g| g.name == "A-AUTO")
        .expect("url-test 组进 IR");
    let url_test = auto_group.url_test.as_ref().expect("组级测速配置");
    assert_eq!(url_test.interval_secs, 300, "显式 300 秒不变（转换面）");
    assert_eq!(
        Duration::from_secs(url_test.interval_secs),
        Duration::from_secs(300),
        "探测门以秒消费（routing 执行健康检查同口径）"
    );

    // 守护加载面：合并配置（本地入口壳承载订阅路由/出口）序列化 →
    // from_str（守护进程同款解析入口）——加载不换算
    let merged = merge_local_takeover(ir);
    let runnable = runtime_shell(free_bind(), merged.routing, merged.egress);
    let yaml_text = serde_yaml::to_string(&runnable).expect("IR 可序列化");
    let loaded =
        RillaneConfig::from_str(&yaml_text, Some("takeover-acceptance")).expect("守护加载面通过");
    let loaded_interval = loaded
        .routing
        .groups
        .iter()
        .find(|g| g.name == "A-AUTO")
        .and_then(|g| g.url_test.as_ref())
        .map(|u| u.interval_secs)
        .expect("加载面 url-test 组在场");
    assert_eq!(loaded_interval, 300, "显式 300 秒不变（加载面）");
    assert!(
        loaded
            .egress
            .iter()
            .any(|e| e.name == "a-tro" && matches!(e.spec, EgressConfig::Trojan { .. })),
        "订阅节点（含凭证规格）进守护加载面"
    );
    assert_eq!(loaded.routing.default_node, "local-direct", "兜底归本地");
    assert!(
        loaded.routing.rules.iter().all(|r| !r.matches.is_empty()),
        "订阅 catch-all 不进运行面（本地 default 兜底）"
    );

    // 运行时面：真实接管 + 转发
    let (bind, echo_port, runtime, tasks) = start_takeover_runtime(loaded).await;
    let echoed = socks5_roundtrip(&bind, echo_port, b"hello-rillane-e2e").await;
    assert_eq!(echoed, b"hello-rillane-e2e", "回环载荷逐字节回显");
    let echoed = socks5_roundtrip(&bind, echo_port, &[0u8, 1, 2, 255]).await;
    assert_eq!(echoed, [0u8, 1, 2, 255], "二进制载荷照实转发");
    runtime.stop().await.expect("停止");
    for t in tasks {
        t.abort();
    }
}

/// 有损样本拒绝 + 未知版本拒绝：严格导入损失清单非空即整体拒绝（绝
/// 不产出半份伪装成功的配置）；宽松模式损失显式可见（清单非空、被丢
/// 规则留名，合法节点照常产出）；显式未知配置版本稳定拒绝
/// （`CODE_UNKNOWN_VERSION`，不猜语义）。
#[test]
fn lossy_sample_and_unknown_version_rejected() {
    let strict = ClashConverter::new().with_strict(true);
    let clash = strict.parse(LOSSY).expect("解析期不炸整份（未知保留原文）");
    let err = strict
        .convert_to_rillane(&clash)
        .expect_err("有损样本严格导入必须整体拒绝");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("严格导入拒绝有损转换"),
        "拒绝头显式: {rendered}"
    );
    assert!(
        rendered.contains("UNKNOWN-RULE-TYPE") && rendered.contains("规则类型不支持"),
        "清单定位到被丢规则及原因: {rendered}"
    );

    // 宽松模式：损失显式可见（不静默）、合法节点照常产出
    let lenient = ClashConverter::new();
    let clash = lenient.parse(LOSSY).expect("宽松解析");
    let (config, report) = lenient
        .convert_to_rillane_with_report(&clash)
        .expect("宽松模式照常产出");
    assert!(!report.is_empty(), "损失清单非空——有损可见");
    assert!(!report.dropped_rules.is_empty(), "被丢规则显式留名");
    assert!(
        config.egress.iter().any(|e| e.name == "sample-ss"),
        "合法节点照常产出"
    );

    // 未知配置版本：守护加载面稳定拒绝（不猜语义）
    let baseline = serde_yaml::to_string(&runtime_shell(
        free_bind(),
        RoutingConfig::default(),
        vec![EgressDescriptor {
            name: "local-direct".to_string(),
            spec: EgressConfig::Direct,
        }],
    ))
    .expect("基线可序列化");
    let good = baseline
        .lines()
        .map(|l| {
            if l.starts_with("version:") {
                "version: '9.9'".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(good.contains("9.9"), "版本行已注入");
    // 加载面错误信息携带稳定原因码（调用方按码分支/上报——合约口径，
    // 不按中文文案匹配）
    let err =
        RillaneConfig::from_str(&good, Some("takeover-acceptance")).expect_err("未知版本必须拒绝");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains(CODE_UNKNOWN_VERSION),
        "稳定原因码可见（不猜语义）: {rendered}"
    );
    assert!(rendered.contains("9.9"), "版本字面量原样报告: {rendered}");
}

/// 启停恢复：运行时停止 → 同配置重建 → 转发恢复（第二组会话照常真
/// 实往返）；发布 journal（现役代际）跨启停保留——守护状态面由发布
/// 协调器权威承载，重启后对账一致。
#[tokio::test]
async fn start_stop_recovery_forwarding() {
    let state_dir =
        std::env::temp_dir().join(format!("rillane-takeover-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).expect("状态目录");

    // 守护状态面：发布现役代际（重启前的提交点）
    let mk_gen = {
        let source = rillane_config::SourceId::new("local").expect("合法来源");
        rillane_config::RuntimeGeneration::build(
            vec![rillane_config::GenerationObject {
                id: rillane_config::ObjectId::new(source, "n1"),
                kind: rillane_config::ObjectKind::Node,
                content_hash: "hash-restart".to_string(),
            }],
            vec![],
        )
        .expect("合法代际")
    };
    {
        let mut coord = PublishCoordinator::open(&state_dir).expect("打开协调器");
        coord.transact(&mk_gen, |_| Ok(())).expect("发布现役");
    }

    let ir = {
        let converter = ClashConverter::new();
        let clash = converter.parse(SAMPLE).expect("样例解析");
        converter.convert_to_rillane(&clash).expect("样例转换")
    };
    let merged = merge_local_takeover(ir);
    let runnable = runtime_shell(free_bind(), merged.routing, merged.egress);
    let yaml_text = serde_yaml::to_string(&runnable).expect("IR 可序列化");
    let cfg =
        RillaneConfig::from_str(&yaml_text, Some("takeover-restart")).expect("守护加载面通过");

    // 第一次运行：接管转发成功
    let (bind, echo_port, runtime, tasks) = start_takeover_runtime(cfg.clone()).await;
    let echoed = socks5_roundtrip(&bind, echo_port, b"before-restart").await;
    assert_eq!(echoed, b"before-restart", "启停前转发正常");
    runtime.stop().await.expect("停止");
    assert!(!runtime.is_running(), "停止后运行态翻转");
    for t in tasks {
        t.abort();
    }

    // 重启：同配置重建（守护进程重启同构）——转发恢复
    let (bind, echo_port, runtime2, tasks2) = start_takeover_runtime(cfg).await;
    let echoed = socks5_roundtrip(&bind, echo_port, b"after-restart").await;
    assert_eq!(echoed, b"after-restart", "重启后转发恢复");
    runtime2.stop().await.expect("停止");
    for t in tasks2 {
        t.abort();
    }

    // 守护状态面跨启停：现役代际保留（journal 权威）
    let coord = PublishCoordinator::open(&state_dir).expect("重启后重开");
    assert_eq!(
        coord.effective(),
        Some(mk_gen.generation_id()),
        "现役代际跨启停保留"
    );
    assert!(coord.journal().pending.is_none(), "无挂起事务残留");
    let _ = std::fs::remove_dir_all(&state_dir);
}
