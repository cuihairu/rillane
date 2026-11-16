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
    assert!(fb.url_test.is_some(), "fb-group 带 url/interval 须注入探测参数");

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
    assert_eq!(config.routing.rules.len(), 3, "进程+DOMAIN-SUFFIX+MATCH 保留");

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
    for expected in [
        "bad-port-node",
        "sample-snell",
        "rule-1",
        "rule-2",
    ] {
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
    let decl = config.routing.proxy_providers.get("sample-provider").expect("声明");
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
    assert_eq!(names, vec!["rule-1", "rule-2", "rule-3", "rule-4", "rule-5"]);

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

// ---------- 脱敏红线：样本仓库不得带真实凭据 ----------
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
