//! 订阅兼容样本库验收（RIL-007）：脱敏正反例逐个断言预期对象/诊断——
//! 每个关键输入的产出与损失必须可预期；样本仓库不带节点密码与带 token
//! 的 URL（守卫测试钉住脱敏红线）。纯解析/转换，零网络。

use std::path::PathBuf;

use rillane_config::{SourceId, Strategy, CODE_COMPAT_LOSSY, CODE_COMPAT_UNSUPPORTED};
use rillane_subscription::ClashConverter;

fn sample(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("样本 {path:?} 必须可读: {err}"))
}

fn loose(
    sample_name: &str,
) -> (
    rillane_config::RillaneConfig,
    rillane_subscription::ConversionReport,
) {
    let yaml = sample(sample_name);
    let converter = ClashConverter::new();
    let clash = converter.parse(&yaml).expect("样本必须可解析");
    converter
        .convert_to_rillane_with_report(&clash)
        .expect("宽松导入必须成功")
}

// ---------- 正例：inline 完整配置无损 ----------

#[test]
fn inline_positive_converts_losslessly() {
    let (config, report) = loose("inline_positive.yaml");
    assert!(
        report.is_empty(),
        "正例必须零损失，实际: {}",
        report.summary()
    );

    // 预期对象：3 节点
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-ss", "sample-vmess", "sample-trojan"]);

    // 预期对象：2 组——select 原语义、url-test 300 秒（RIL-092 口径不变）
    let groups = &config.routing.groups;
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].name, "PROXY");
    assert_eq!(groups[0].strategy, Strategy::Fixed);
    assert_eq!(groups[0].members.len(), 3);
    assert_eq!(groups[1].name, "AUTO");
    assert_eq!(groups[1].strategy, Strategy::Latency);
    let url_test = groups[1].url_test.as_ref().expect("url-test 组带探测配置");
    assert_eq!(url_test.interval_secs, 300);

    // 预期对象：3 规则（含 MATCH 兜底）
    assert_eq!(config.routing.rules.len(), 3);
    assert_eq!(config.routing.default_node, "sample-ss");
}

// ---------- 反例：full-policy 有损输入逐项可预期 ----------

#[test]
fn negative_lossy_reports_every_expected_loss() {
    let (config, report) = loose("negative_lossy.yaml");

    // 丢弃节点：port:0 无效节点 + snell 类型暂不支持
    let dropped: Vec<&str> = report
        .dropped_nodes
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        dropped.contains(&"bad-port-node"),
        "无效端口节点必须进清单: {dropped:?}"
    );
    assert!(
        dropped.contains(&"sample-snell"),
        "snell 类型节点必须进清单: {dropped:?}"
    );

    // 组面零损失（RIL-012/013）：fallback 同语义直映、无 relay/LB 降级
    let degraded: Vec<&str> = report
        .degraded_groups
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(degraded.is_empty(), "组面零损失: {degraded:?}");
    // fb-group 保真：Strategy::Fallback + 探测参数随行
    let fb = config
        .routing
        .groups
        .iter()
        .find(|g| g.name.ends_with("fb-group"))
        .expect("fb-group 须产出");
    assert_eq!(fb.strategy, rillane_config::Strategy::Fallback);
    assert!(
        fb.url_test.is_some(),
        "fb-group 带 url/interval 须注入探测参数"
    );

    // 跳过规则：仅未声明引用的 RULE-SET（rule-2）。RIL-015 起
    // PROCESS-NAME（rule-1）转换保留并按引擎降级显式报告
    let dropped_rules: Vec<&str> = report
        .dropped_rules
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(dropped_rules, vec!["rule-2"], "仅未声明引用须进跳过清单");
    let degraded_rules: Vec<&str> = report
        .degraded_rules
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(degraded_rules, vec!["rule-1"], "进程规则须按降级报告");

    // 保留面：好节点、select 组、进程规则与两条支持规则照常产出
    assert_eq!(config.egress.len(), 1, "只有 good-node-a 产出");
    assert_eq!(
        config.routing.rules.len(),
        3,
        "进程+DOMAIN-SUFFIX+MATCH 保留"
    );

    // 诊断桥（RIL-002 契约）：每条损失带稳定码并定位到来源对象
    let source = SourceId::new("sample-lossy").unwrap();
    let diagnostics = report.diagnostics(&source);
    assert_eq!(
        diagnostics.len(),
        report.dropped_nodes.len()
            + report.degraded_groups.len()
            + report.dropped_rules.len()
            + report.degraded_rules.len()
    );
    for diagnostic in &diagnostics {
        assert_eq!(diagnostic.location.source.as_str(), "sample-lossy");
    }
    let node_diagnostic = diagnostics
        .iter()
        .find(|d| d.location.pointer == "proxies/bad-port-node")
        .expect("无效节点定位到 proxies/<名>");
    assert_eq!(node_diagnostic.code, CODE_COMPAT_UNSUPPORTED);
    assert_eq!(
        node_diagnostic.object.as_ref().unwrap().local_id,
        "bad-port-node"
    );
    let rule_diagnostic = diagnostics
        .iter()
        .find(|d| d.location.pointer == "rules/rule-2")
        .expect("跳过规则定位到 rules/<名>");
    assert_eq!(rule_diagnostic.code, CODE_COMPAT_UNSUPPORTED);
    // 进程规则降级是"有损但保留"，不是"不支持"
    let process_diagnostic = diagnostics
        .iter()
        .find(|d| d.location.pointer == "rules/rule-1")
        .expect("降级规则定位到 rules/<名>");
    assert_eq!(process_diagnostic.code, CODE_COMPAT_LOSSY);
}

#[test]
fn negative_lossy_strict_rejects_with_full_list() {
    let yaml = sample("negative_lossy.yaml");
    let converter = ClashConverter::new().with_strict(true);
    let clash = converter.parse(&yaml).expect("样本必须可解析");
    let err = converter
        .convert_to_rillane_with_report(&clash)
        .expect_err("严格导入必须拒绝有损样本");
    let message = err.to_string();
    for expected in ["bad-port-node", "sample-snell", "rule-1", "rule-2"] {
        assert!(
            message.contains(expected),
            "严格拒绝错误须点名 {expected}，实际:\n{message}"
        );
    }
}

// ---------- 反例：provider-only 输入整块显式可见 ----------

#[test]
fn provider_only_surfaces_block_loss_not_silent() {
    let (config, report) = loose("provider_only.yaml");

    // 节点零吸收（proxies: []，provider 未吸收）
    assert!(
        config.egress.is_empty(),
        "provider 生命周期归 RIL-009，当前不得伪装吸收"
    );

    // RIL-009：声明已吸收（不再整块未支持），但节点目录载荷未装入 = 降级
    assert!(
        report.unsupported_blocks.is_empty(),
        "声明已吸收不应再报未支持块: {report:?}"
    );
    assert_eq!(
        config.routing.proxy_providers.len(),
        1,
        "provider 声明须落 routing.proxy_providers"
    );
    let decl = config
        .routing
        .proxy_providers
        .get("sample-provider")
        .expect("声明");
    assert_eq!(decl.provider_type, "http");
    assert_eq!(decl.interval_secs, Some(3600), "interval 秒口径原样");
    assert_eq!(
        decl.health_check.as_ref().and_then(|h| h.interval_secs),
        Some(300),
        "health-check 周期须保留"
    );
    // 载荷未装入须显式可见：组成员集为空集，失效成员退出候选
    assert_eq!(report.degraded_providers.len(), 1, "载荷未装入须按降级报告");
    assert_eq!(report.degraded_providers[0].0, "sample-provider");
    assert!(!report.is_empty());

    // 诊断桥：compat.lossy 定位 proxy-providers/<名>
    let source = SourceId::new("sample-provider-only").unwrap();
    let diagnostics = report.diagnostics(&source);
    let degraded = diagnostics
        .iter()
        .find(|d| d.location.pointer == "proxy-providers/sample-provider")
        .expect("provider 降级必须被诊断定位");
    assert_eq!(degraded.code, CODE_COMPAT_LOSSY);

    // 严格模式：载荷未装入即拒绝（不伪装成员已吸收）
    let yaml = sample("provider_only.yaml");
    let converter = ClashConverter::new().with_strict(true);
    let clash = converter.parse(&yaml).expect("样本必须可解析");
    let err = converter
        .convert_to_rillane_with_report(&clash)
        .expect_err("严格导入必须拒绝 provider-only 样本");
    assert!(
        err.to_string().contains("sample-provider"),
        "拒绝错误须点名 provider: {}",
        err
    );
}

// ---------- RIL-014：rule-providers + RULE-SET + 逻辑规则样本 ----------

#[test]
fn ruleset_logic_sample_converts_with_tracked_references() {
    let (config, report) = loose("ruleset_logic.yaml");
    assert!(
        report.is_empty(),
        "样本必须零损失，实际: {}",
        report.summary()
    );

    // 首匹配顺序 = 声明顺序；rule-N 命名稳定；MATCH 兜底最后
    let names: Vec<&str> = config
        .routing
        .rules
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["rule-1", "rule-2", "rule-3", "rule-4", "rule-5"]
    );

    // RULE-SET → 命名引用（可追踪）
    assert_eq!(
        config.routing.rules[0].matches[0],
        rillane_config::MatchCondition::RuleSetRef {
            name: "ads".to_string()
        }
    );

    // AND 平铺三条件（域名后缀 + 目标端口）、OR → Any（源端口 + 目标
    // 端口语义分离）、NOT → Not
    assert_eq!(config.routing.rules[1].matches.len(), 2);
    assert!(matches!(
        &config.routing.rules[1].matches[0],
        rillane_config::MatchCondition::DomainSuffix { .. }
    ));
    assert!(matches!(
        &config.routing.rules[1].matches[1],
        rillane_config::MatchCondition::Port { .. }
    ));
    assert!(matches!(
        &config.routing.rules[2].matches[0],
        rillane_config::MatchCondition::Any { .. }
    ));
    assert!(matches!(
        &config.routing.rules[3].matches[0],
        rillane_config::MatchCondition::Not { .. }
    ));
    assert!(config.routing.rules[4].matches.is_empty(), "MATCH 无条件");

    // 声明面：http + file 两个 provider，interval 秒口径原样带入
    assert_eq!(config.routing.rule_providers.len(), 2);
    let ads = config.routing.rule_providers.get("ads").expect("ads 声明");
    assert_eq!(ads.behavior, "domain");
    assert_eq!(ads.interval_secs, Some(86400));
    let direct = config
        .routing
        .rule_providers
        .get("direct-cidr")
        .expect("direct-cidr 声明");
    assert_eq!(direct.behavior, "ipcidr");
    assert_eq!(direct.provider_type, "file");
}

// ---------- RIL-132：SOCKS5 出站——订阅字段双向转换样本 ----------

#[test]
fn socks5_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（带认证与匿名各一，字段逐项断言）
    let (config, report) = loose("socks5_auth.yaml");
    assert!(
        report.is_empty(),
        "socks5 样本必须零损失，实际: {}",
        report.summary()
    );
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-socks5-auth", "sample-socks5-plain"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Socks5 {
            server: "203.0.113.30".into(),
            port: 1080,
            username: Some("sample-user".into()),
            password: Some("REDACTED-SAMPLE".into()),
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Socks5 {
            server: "socksgw.example.com".into(),
            port: 1081,
            username: None,
            password: None,
        }
    );

    // 反向：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }
}

// ---------- RIL-106：AnyTLS 出站——订阅字段双向转换样本 ----------

#[test]
fn anytls_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（字段逐项断言；不入 IR 的字段点名降级）
    let (config, report) = loose("anytls_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-anytls-full", "sample-anytls-min"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Anytls {
            server: "anytls.example.com".into(),
            port: 443,
            password: "REDACTED-SAMPLE".into(),
            sni: Some("sni.example.com".into()),
            skip_cert_verify: true,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Anytls {
            server: "203.0.113.41".into(),
            port: 8443,
            password: "REDACTED-SAMPLE".into(),
            sni: None,
            skip_cert_verify: false,
        }
    );
    // 损失点名：alpn/fingerprint/client-fingerprint 不入 IR——节点保留，
    // 降级可见（degraded_nodes，RIL-015 同口径），不伪装无损
    assert!(
        report.dropped_nodes.is_empty(),
        "AnyTLS 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert_eq!(
        report.degraded_nodes.len(),
        1,
        "仅全功能节点降级: {:?}",
        report.degraded_nodes
    );
    let (name, reason) = &report.degraded_nodes[0];
    assert_eq!(name, "sample-anytls-full");
    assert!(reason.contains("alpn"), "点名 alpn: {reason}");
    assert!(
        reason.contains("client-fingerprint"),
        "点名 client-fingerprint: {reason}"
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出 → 导入侧回读再转 IR（真往返证据）
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-anytls-full".into(),
        spec: specs[0].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-anytls-full"],
        "AnyTLS 应可导出"
    );
    assert!(yaml.contains("type: anytls"), "{yaml}");
    assert!(yaml.contains("sni: sni.example.com"), "{yaml}");
    assert!(yaml.contains("skip-cert-verify: true"), "{yaml}");
    assert!(yaml.contains("REDACTED-SAMPLE"), "{yaml}");
    // 回读：sni 别名保证往返不丢 SNI（自签/私有 CA 场景直连面）
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失（导出面不含不入 IR 的字段）: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原 AnyTLS 节点"
    );
}

// ---------- RIL-107：VLESS+REALITY 出站——订阅字段双向转换样本 ----------

#[test]
fn reality_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（reality-opts 逐字段入 IR，节点零损失）
    let (config, report) = loose("reality_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-reality-full", "sample-reality-min"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Vless {
            server: "reality.example.com".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: Some(rillane_config::RealityConfig {
                public_key: "REDACTED-SAMPLE-public-key-0123456789abcdef0123456789abcdef".into(),
                short_id: Some("0102030405060708".into()),
            }),
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,

            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: false,
            sni: Some("sni.example.com".into()),
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.42".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: Some(rillane_config::RealityConfig {
                public_key: "REDACTED-SAMPLE-public-key-fedcba9876543210fedcba9876543210".into(),
                short_id: None,
            }),
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,

            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: false,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "REALITY 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "reality-opts 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（reality-opts 键位）→ 导入侧回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-reality-full".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-reality-min".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-reality-full", "sample-reality-min"],
        "REALITY 节点应可导出"
    );
    assert!(yaml.contains("type: vless"), "{yaml}");
    assert!(yaml.contains("reality-opts:"), "{yaml}");
    assert!(
        yaml.contains("public-key: REDACTED-SAMPLE-public-key-0123456789abcdef0123456789abcdef"),
        "{yaml}"
    );
    // short-id 全数字串，serde_yaml_ng 导出带引号——键位与值都在即可
    assert!(yaml.contains("short-id:"), "{yaml}");
    assert!(yaml.contains("0102030405060708"), "{yaml}");
    assert!(yaml.contains("tls: true"), "{yaml}");
    // 回读：reality-opts kebab 键位保证往返不丢 REALITY 配置
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失（导出面含 reality-opts 全字段）: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原 REALITY 节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "min 节点（short_id 缺席）同样逐字段还原"
    );
}

// ---------- RIL-108：VLESS+XTLS Vision 出站——订阅字段双向转换样本 ----------

#[test]
fn vision_flow_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（flow 随节点保留，vision+reality 合法组合同样零损失）
    let (config, report) = loose("vision_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-vision-tls", "sample-vision-reality"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Vless {
            server: "vision.example.com".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: Some("xtls-rprx-vision".into()),
            reality: None,
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,

            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: false,
            sni: Some("sni.example.com".into()),
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.44".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: Some("xtls-rprx-vision".into()),
            reality: Some(rillane_config::RealityConfig {
                public_key: "REDACTED-SAMPLE-public-key-0123456789abcdef0123456789abcdef".into(),
                short_id: Some("0102030405060708".into()),
            }),
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,

            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: false,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "Vision 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "flow 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（flow 键位）→ 导入侧回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-vision-tls".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-vision-reality".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-vision-tls", "sample-vision-reality"],
        "Vision 节点应可导出"
    );
    assert!(yaml.contains("type: vless"), "{yaml}");
    assert!(
        yaml.contains("flow: xtls-rprx-vision"),
        "导出必须携带 flow 键位: {yaml}"
    );
    assert!(yaml.contains("reality-opts:"), "{yaml}");
    assert!(yaml.contains("tls: true"), "{yaml}");
    // 回读：flow 键位保证往返不丢 Vision 流控
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失（导出面含 flow 全字段）: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原 Vision 节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "vision+reality 组合同样逐字段还原"
    );
}

// ---------- RIL-131：Shadowsocks 算法矩阵——订阅字段双向转换样本 ----------

#[test]
fn ss_matrix_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（v1 AEAD 与 SS2022 各一，cipher/password 逐字段保留）
    let (config, report) = loose("ss_matrix_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-ss-v1-aes256", "sample-ss-2022-aes256"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Shadowsocks {
            server: "ss1.example.com".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "REDACTED-SAMPLE-v1-password".into(),
            plugin: None,
            plugin_opts: None,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Shadowsocks {
            server: "203.0.113.50".into(),
            port: 8443,
            method: "2022-blake3-aes-256-gcm".into(),
            password: "REDACTED-SAMPLE-ss2022-base64-key-placeholder".into(),
            plugin: None,
            plugin_opts: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "SS 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "cipher/password 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（type: ss + cipher 键位）→ 导入侧回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-ss-v1-aes256".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-ss-2022-aes256".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-ss-v1-aes256", "sample-ss-2022-aes256"],
        "SS 节点应可导出"
    );
    assert!(yaml.contains("type: ss"), "{yaml}");
    assert!(yaml.contains("cipher: aes-256-gcm"), "{yaml}");
    assert!(
        yaml.contains("2022-blake3-aes-256-gcm"),
        "导出必须携带 SS2022 算法名: {yaml}"
    );
    assert!(yaml.contains("REDACTED-SAMPLE"), "{yaml}");
    // 回读：cipher 键位保证往返不丢算法（矩阵成员身份随字段保留）
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原 v1 节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "SS2022 节点同样逐字段还原"
    );
}

// ---------- RIL-133：Hysteria2——订阅字段双向转换样本 ----------

#[test]
fn hysteria2_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（基础节点与 mport+obfs 节点各一，逐字段保留）
    let (config, report) = loose("hysteria2_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-hy2-plain", "sample-hy2-mport-obfs"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Hysteria2 {
            server: "hy1.example.com".into(),
            port: 443,
            password: "REDACTED-SAMPLE-hy2-password".into(),
            mport: None,
            obfs: None,
            obfs_param: None,
            server_name: Some("hy1.example.com".into()),
            skip_cert_verify: false,
            alpn: Some(vec!["h3".into()]),
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Hysteria2 {
            server: "203.0.113.60".into(),
            port: 36712,
            password: "REDACTED-SAMPLE-hy2-password-2".into(),
            mport: Some("20000-30000".into()),
            obfs: Some("salamander".into()),
            obfs_param: Some("REDACTED-SAMPLE-hy2-obfs".into()),
            server_name: None,
            skip_cert_verify: false,
            alpn: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "Hysteria2 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "password/mport/obfs/sni/alpn 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（type: hysteria2 + ports/obfs 键位）→ 回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-hy2-plain".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-hy2-mport-obfs".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-hy2-plain", "sample-hy2-mport-obfs"],
        "Hysteria2 节点应可导出"
    );
    assert!(yaml.contains("type: hysteria2"), "{yaml}");
    assert!(yaml.contains("sni: hy1.example.com"), "{yaml}");
    assert!(yaml.contains("alpn:"), "{yaml}");
    assert!(yaml.contains("ports: 20000-30000"), "{yaml}");
    assert!(yaml.contains("obfs: salamander"), "{yaml}");
    assert!(
        yaml.contains("obfs-password: REDACTED-SAMPLE-hy2-obfs"),
        "导出必须携带 obfs-password 键位: {yaml}"
    );
    assert!(yaml.contains("REDACTED-SAMPLE"), "{yaml}");
    // 回读：ports/obfs/sni/alpn 键位保证往返不丢字段
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原基础节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "mport+obfs 节点同样逐字段还原"
    );
}

// ---------- RIL-105：TUIC——订阅字段双向转换样本 ----------

#[test]
fn tuic_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（基础节点与 congestion+skip-cert-verify 节点各一）
    let (config, report) = loose("tuic_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-tuic-plain", "sample-tuic-congestion"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Tuic {
            server: "tu1.example.com".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            password: "REDACTED-SAMPLE-tuic-password".into(),
            congestion_controller: None,
            server_name: Some("tu1.example.com".into()),
            skip_cert_verify: false,
            alpn: Some(vec!["h3".into()]),
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Tuic {
            server: "203.0.113.61".into(),
            port: 8443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            password: "REDACTED-SAMPLE-tuic-password-2".into(),
            congestion_controller: Some("bbr".into()),
            server_name: None,
            skip_cert_verify: true,
            alpn: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "TUIC 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "uuid/password/congestion-controller/sni/skip-cert-verify/alpn 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（type: tuic + uuid/congestion-controller 键位）→ 回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-tuic-plain".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-tuic-congestion".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-tuic-plain", "sample-tuic-congestion"],
        "TUIC 节点应可导出"
    );
    assert!(yaml.contains("type: tuic"), "{yaml}");
    assert!(
        yaml.contains("uuid: 00000000-0000-0000-0000-000000000000"),
        "{yaml}"
    );
    assert!(yaml.contains("sni: tu1.example.com"), "{yaml}");
    assert!(yaml.contains("alpn:"), "{yaml}");
    assert!(
        yaml.contains("congestion-controller: bbr"),
        "导出必须携带 congestion-controller 键位: {yaml}"
    );
    assert!(yaml.contains("skip-cert-verify: true"), "{yaml}");
    assert!(yaml.contains("REDACTED-SAMPLE"), "{yaml}");
    // 回读：uuid/congestion-controller/sni/alpn 键位保证往返不丢字段
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原基础节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "congestion+skip-cert-verify 节点同样逐字段还原"
    );
}

// ---------- RIL-129：XHTTP——订阅字段双向转换样本 ----------

#[test]
fn xhttp_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（auto+host 节点与 stream-one 节点各一）
    let (config, report) = loose("xhttp_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["sample-xhttp-auto", "sample-xhttp-stream-one"]);
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Vless {
            server: "xh1.example.com".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "xhttp".into(),
            path: Some("/xh1".into()),
            host: Some(vec!["cdn1.example.com".into()]),
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: Some("auto".into()),
            packet_encoding: None,
            tls: true,
            skip_cert_verify: false,
            sni: Some("sni.example.com".into()),
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.71".into(),
            port: 8443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "xhttp".into(),
            path: Some("/xh2".into()),
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: Some("stream-one".into()),
            packet_encoding: None,
            tls: true,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "XHTTP 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "network/path/host/mode 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（network: xhttp + xhttp-opts 块键）→ 回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-xhttp-auto".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-xhttp-stream-one".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-xhttp-auto", "sample-xhttp-stream-one"],
        "XHTTP 节点应可导出"
    );
    assert!(yaml.contains("network: xhttp"), "{yaml}");
    assert!(yaml.contains("type: vless"), "{yaml}");
    assert!(
        yaml.contains("xhttp-opts:"),
        "导出必须携带 xhttp-opts 块键: {yaml}"
    );
    assert!(yaml.contains("mode: auto"), "{yaml}");
    assert!(yaml.contains("mode: stream-one"), "{yaml}");
    assert!(yaml.contains("path: /xh1"), "{yaml}");
    assert!(yaml.contains("path: /xh2"), "{yaml}");
    assert!(yaml.contains("host:"), "{yaml}");
    // 回读：xhttp-opts 键位保证往返不丢字段
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原 auto+host 节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "stream-one 节点同样逐字段还原"
    );
}

// ---------- RIL-130：HTTPUpgrade——订阅字段双向转换样本 ----------

#[test]
fn httpupgrade_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（vmess+host 节点与 vless 仅 path 节点各一）
    let (config, report) = loose("httpupgrade_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["sample-httpupgrade-vmess", "sample-httpupgrade-vless"]
    );
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Vmess {
            server: "hu1.example.com".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            alter_id: 0,
            security: "auto".into(),
            network: "httpupgrade".into(),
            path: Some("/hu1".into()),
            host: Some(vec!["cdn1.example.com".into()]),
            grpc_service_name: None,
            grpc_reuse: None,
            tls: true,
            skip_cert_verify: false,
            sni: Some("sni.example.com".into()),
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.72".into(),
            port: 8443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "httpupgrade".into(),
            path: Some("/hu2".into()),
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "HTTPUpgrade 节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "network/path/host 全字段入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（network: httpupgrade + httpupgrade-opts 块键）
    // → 回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-httpupgrade-vmess".into(),
        spec: specs[0].clone(),
    });
    project.egress.push(rillane_config::EgressDescriptor {
        name: "sample-httpupgrade-vless".into(),
        spec: specs[1].clone(),
    });
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec!["sample-httpupgrade-vmess", "sample-httpupgrade-vless"],
        "HTTPUpgrade 节点应可导出"
    );
    assert!(yaml.contains("network: httpupgrade"), "{yaml}");
    assert!(yaml.contains("type: vmess"), "{yaml}");
    assert!(yaml.contains("type: vless"), "{yaml}");
    assert!(
        yaml.contains("httpupgrade-opts:"),
        "导出必须携带 httpupgrade-opts 块键: {yaml}"
    );
    assert!(yaml.contains("path: /hu1"), "{yaml}");
    assert!(yaml.contains("path: /hu2"), "{yaml}");
    assert!(yaml.contains("Host: cdn1.example.com"), "{yaml}");
    // 回读：httpupgrade-opts 键位保证往返不丢字段
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    assert_eq!(
        back_config.egress[0].spec, specs[0],
        "导出→回读必须逐字段还原 vmess+host 节点"
    );
    assert_eq!(
        back_config.egress[1].spec, specs[1],
        "vless 仅 path 节点同样逐字段还原"
    );
}

// ---------- RIL-130：vless UDP 包编码——订阅字段双向转换样本 ----------

#[test]
fn packet_encoding_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（xudp / packetaddr / 显式 raw 各一）
    let (config, report) = loose("packet_encoding_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "sample-packet-xudp",
            "sample-packet-addr",
            "sample-packet-raw"
        ]
    );
    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();
    assert_eq!(
        specs[0],
        rillane_config::EgressConfig::Vless {
            server: "pk1.example.com".into(),
            port: 443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: None,
            packet_encoding: Some("xudp".into()),
            tls: true,
            skip_cert_verify: false,
            sni: Some("sni.example.com".into()),
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        specs[1],
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.81".into(),
            port: 8443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: None,
            packet_encoding: Some("packetaddr".into()),
            tls: true,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        specs[2],
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.82".into(),
            port: 8443,
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
            reality: None,
            network: "tcp".into(),
            path: None,
            host: None,
            grpc_service_name: None,
            grpc_reuse: None,
            xhttp_mode: None,
            // 显式 raw 入 IR（缺省 = 键位缺席 = None，同义不同形，各随其源）
            packet_encoding: Some("raw".into()),
            tls: true,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "包编码节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "packet-encoding 全值入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（平铺 packet-encoding 键）→ 回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    for (i, name) in [
        "sample-packet-xudp",
        "sample-packet-addr",
        "sample-packet-raw",
    ]
    .into_iter()
    .enumerate()
    {
        project.egress.push(rillane_config::EgressDescriptor {
            name: name.into(),
            spec: specs[i].clone(),
        });
    }
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec![
            "sample-packet-xudp",
            "sample-packet-addr",
            "sample-packet-raw"
        ],
        "包编码节点应可导出"
    );
    assert!(yaml.contains("packet-encoding: xudp"), "{yaml}");
    assert!(yaml.contains("packet-encoding: packetaddr"), "{yaml}");
    assert!(yaml.contains("packet-encoding: raw"), "{yaml}");
    // 回读：平铺键位保证往返不丢字段
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    for (i, name) in [
        "sample-packet-xudp",
        "sample-packet-addr",
        "sample-packet-raw",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(back_config.egress[i].name, name, "回读节点序保持");
        assert_eq!(
            back_config.egress[i].spec, specs[i],
            "导出→回读必须逐字段还原 {name}"
        );
    }
}

// ---------- gRPC gun 流复用旋钮双向（RIL-130） ----------

#[test]
fn grpc_reuse_subscription_fields_convert_both_ways() {
    // 正向：clash 订阅 → IR（三键全给 / 单键 / 三键全缺 各一，三族各一）
    let (config, report) = loose("grpc_reuse_node.yaml");
    let names: Vec<&str> = config.egress.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "sample-gun-full",
            "sample-gun-partial",
            "sample-gun-default"
        ]
    );
    let uuid = "00000000-0000-0000-0000-000000000000".to_string();
    let full = Some(rillane_config::GrpcReuseConfig {
        max_connections: Some(2),
        min_streams: Some(1),
        max_streams: Some(4),
    });
    let partial = Some(rillane_config::GrpcReuseConfig {
        max_connections: Some(1),
        min_streams: None,
        max_streams: None,
    });

    assert_eq!(
        config.egress[0].spec,
        rillane_config::EgressConfig::Vmess {
            server: "gr1.example.com".into(),
            port: 443,
            uuid: uuid.clone(),
            alter_id: 0,
            security: "auto".into(),
            network: "grpc".into(),
            path: None,
            host: None,
            grpc_service_name: Some("gun-svc".into()),
            grpc_reuse: full.clone(),
            tls: true,
            skip_cert_verify: false,
            sni: Some("sni.example.com".into()),
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert_eq!(
        config.egress[1].spec,
        rillane_config::EgressConfig::Vless {
            server: "203.0.113.61".into(),
            port: 8443,
            uuid: uuid.clone(),
            flow: None,
            reality: None,
            network: "grpc".into(),
            path: None,
            host: None,
            grpc_service_name: Some("gun-svc".into()),
            grpc_reuse: partial.clone(),
            xhttp_mode: None,
            packet_encoding: None,
            tls: true,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    // 三键全缺 = 构建侧缺省（单连接全复用，mihomo NewClient 同口径）
    assert_eq!(
        config.egress[2].spec,
        rillane_config::EgressConfig::Trojan {
            server: "203.0.113.62".into(),
            port: 8443,
            password: "REDACTED-SAMPLE-gr-password".into(),
            network: "grpc".into(),
            path: None,
            host: None,
            grpc_service_name: Some("gun-svc".into()),
            grpc_reuse: None,
            tls: true,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            tls_fingerprint: None,
        }
    );
    assert!(
        report.dropped_nodes.is_empty(),
        "gun 旋钮节点必须保留，不丢弃: {:?}",
        report.dropped_nodes
    );
    assert!(
        report.degraded_nodes.is_empty(),
        "grpc-opts 旋钮全值入 IR，无降级: {:?}",
        report.degraded_nodes
    );

    let specs: Vec<rillane_config::EgressConfig> =
        config.egress.iter().map(|e| e.spec.clone()).collect();

    // 反向 1：IR → serde → IR（序列化不丢字段，往返逐字段一致）
    for spec in &specs {
        let json = serde_json::to_string(spec).expect("IR 序列化");
        let back: rillane_config::EgressConfig = serde_json::from_str(&json).expect("IR 反序列化");
        assert_eq!(&back, spec, "serde 往返必须逐字段一致");
    }

    // 反向 2：IR → clash 导出（grpc-opts 三键）→ 回读再转 IR
    let mut project: rillane_config::RillaneConfig = serde_yaml::from_str(
        "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
    )
    .expect("基底配置");
    for (i, name) in [
        "sample-gun-full",
        "sample-gun-partial",
        "sample-gun-default",
    ]
    .into_iter()
    .enumerate()
    {
        project.egress.push(rillane_config::EgressDescriptor {
            name: name.into(),
            spec: specs[i].clone(),
        });
    }
    let (yaml, export_report) = rillane_subscription::ClashExporter
        .export(&project)
        .unwrap();
    assert_eq!(
        export_report.exported_proxies,
        vec![
            "sample-gun-full",
            "sample-gun-partial",
            "sample-gun-default"
        ],
        "gun 旋钮节点应可导出"
    );
    assert!(
        yaml.contains("grpc-opts:") && yaml.contains("grpc-service-name: gun-svc"),
        "{yaml}"
    );
    assert!(yaml.contains("max-connections: 2"), "{yaml}");
    assert!(yaml.contains("min-streams: 1"), "{yaml}");
    assert!(yaml.contains("max-streams: 4"), "{yaml}");
    // 回读：grpc-opts 键位保证往返不丢旋钮
    let reparsed = ClashConverter::new()
        .parse(&yaml)
        .expect("导出必须可被导入侧解析");
    let (back_config, back_report) = ClashConverter::new()
        .convert_to_rillane_with_report(&reparsed)
        .expect("回读转换");
    assert!(
        back_report.dropped_nodes.is_empty(),
        "回读不丢节点: {:?}",
        back_report.dropped_nodes
    );
    assert!(
        back_report.degraded_nodes.is_empty(),
        "回读零损失: {:?}",
        back_report.degraded_nodes
    );
    for (i, name) in [
        "sample-gun-full",
        "sample-gun-partial",
        "sample-gun-default",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(back_config.egress[i].name, name, "回读节点序保持");
        assert_eq!(
            back_config.egress[i].spec, specs[i],
            "导出→回读必须逐字段还原 {name}"
        );
    }
}

// ---------- 脱敏红线：样本仓库不得带真实凭据 ----------

#[test]
fn samples_contain_no_secrets() {
    let samples_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    let mut checked = 0;
    for entry in std::fs::read_dir(&samples_dir).expect("样本目录必须存在") {
        let path = entry.expect("可读").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("样本必须可读");
        // 带凭证 URL：任何查询串 token 一律禁止
        assert!(
            !content.contains("token="),
            "{path:?} 不得携带带 token 的 URL"
        );
        // 凭据字段：只允许占位值
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("password:") || line.starts_with("psk:") {
                assert!(
                    line.contains("REDACTED-SAMPLE"),
                    "{path:?} 凭据必须是占位值: {line}"
                );
            }
            if line.starts_with("uuid:") {
                assert!(
                    line.contains("00000000-0000-0000-0000-000000000000"),
                    "{path:?} UUID 必须是全零占位: {line}"
                );
            }
        }
        checked += 1;
    }
    assert!(checked >= 3, "样本库至少 3 份，实际 {checked}");
}
