//! network.dns 配置块集成测试（P2-8 M1，dns-partition.md §4-3/§7）。
//!
//! 覆盖：缺省值与存量零差异、三层 deny_unknown_fields、serde 往返、
//! validate 矩阵（E1 面）与 enabled=false 半配置短路。

use rillane_config::{
    parse_cidr_pair, DnsAntiPoisonMode, DnsBlockConfig, DnsCacheBlockConfig, DnsGroup,
    DnsRuleConfig, NetworkBlockConfig, NetworkBlockMode, RillaneConfig, RoutingBlockConfig,
    TunBlockConfig,
};

/// 存量零差异：network 块缺席 / network 块在场但无 dns 键，均解析为 None。
#[test]
fn dns_block_absent_is_none() {
    let src = r#"
control: { api_bind: "127.0.0.1:9090" }
telemetry: { log_level: info, enable_metrics: false, enable_tracing: false }
ingress: []
egress: []
routing: { default_node: direct, groups: [], rules: [] }
"#;
    let cfg: RillaneConfig = serde_yaml::from_str(src).expect("无 network 块应可解析");
    assert!(cfg.network.is_none());

    let src = r#"
control: { api_bind: "127.0.0.1:9090" }
telemetry: { log_level: info, enable_metrics: false, enable_tracing: false }
ingress: []
egress: []
routing: { default_node: direct, groups: [], rules: [] }
network:
  tun:
    name: rillane0
"#;
    let cfg: RillaneConfig = serde_yaml::from_str(src).expect("network 无 dns 键应可解析");
    let network = cfg.network.expect("network 块应在");
    assert!(network.dns.is_none(), "缺省应 None");
    network.validate().expect("存量形态应通过 validate");
}

/// 缺省值面：块在场缺省启用、domestic 兜底、off 防污染、127.0.0.1:15353 监听。
#[test]
fn dns_block_defaults() {
    let cfg: DnsBlockConfig = serde_yaml::from_str("trusted: ['1.1.1.1:53']").expect("应可解析");
    assert!(cfg.enabled, "块在场缺省启用");
    assert!(
        cfg.domestic.is_empty(),
        "domestic 缺省空（回落 tun.dns_servers）"
    );
    assert_eq!(cfg.default_group, DnsGroup::Domestic, "兜底缺省 domestic");
    assert_eq!(cfg.anti_poison, DnsAntiPoisonMode::Off);
    assert_eq!(cfg.timeout_ms, 5_000);
    assert_eq!(cfg.retries, 2);
    assert_eq!(cfg.listen_address.to_string(), "127.0.0.1");
    assert_eq!(cfg.listen_port, 15_353);
    assert!(cfg.cache.is_none(), "缓存块缺省 None = 不缓存");
    cfg.validate()
        .expect("仅 trusted 上游应通过（default=domestic 可回落）");
}

/// 三层 deny_unknown_fields：块本体 / rules[] / cache 子块拼错立刻报。
#[test]
fn dns_block_deny_unknown_fields() {
    assert!(serde_yaml::from_str::<DnsBlockConfig>("upstreams: ['1.1.1.1:53']").is_err());
    assert!(
        serde_yaml::from_str::<DnsBlockConfig>(
            "rules:\n  - { pattern: '.cn', group: domestic, mode: suffix }"
        )
        .is_err(),
        "rules[] 未知名应拒绝"
    );
    assert!(serde_yaml::from_str::<DnsBlockConfig>("cache: { ttl: 300 }").is_err());
}

/// serde 往返：suffix/exact 规则、cross_check、显式 cache 全字段保留。
#[test]
fn dns_block_roundtrip() {
    let cfg = DnsBlockConfig {
        enabled: true,
        domestic: vec!["223.5.5.5:53".to_string()],
        trusted: vec!["1.1.1.1:53".to_string(), "[2001:db8::1]:53".to_string()],
        rules: vec![
            DnsRuleConfig {
                pattern: ".cn".to_string(),
                group: DnsGroup::Domestic,
            },
            DnsRuleConfig {
                pattern: "example.com".to_string(),
                group: DnsGroup::Trusted,
            },
        ],
        default_group: DnsGroup::Trusted,
        anti_poison: DnsAntiPoisonMode::CrossCheck,
        tls_skip_verify: false,
        timeout_ms: 2_500,
        retries: 3,
        cache: Some(DnsCacheBlockConfig {
            max_entries: 1024,
            min_ttl: 30,
            max_ttl: 3600,
            enable_negative_cache: false,
            negative_ttl: 60,
        }),
        listen_address: "0.0.0.0".parse().unwrap(),
        listen_port: 5353,
        fake_ip: None,
        hosts: None,
    };
    let rendered = serde_yaml::to_string(&cfg).expect("应可序列化");
    let reparsed: DnsBlockConfig = serde_yaml::from_str(&rendered).expect("应可往返");
    assert_eq!(reparsed, cfg);
}

/// validate 合法边界：显式 domestic + suffix 规则 + cross_check + cache。
#[test]
fn dns_block_validate_accepts_legal_edge() {
    let cfg = DnsBlockConfig {
        domestic: vec!["223.5.5.5:53".to_string()],
        trusted: vec!["9.9.9.9:53".to_string()],
        rules: vec![DnsRuleConfig {
            pattern: ".cn".to_string(),
            group: DnsGroup::Domestic,
        }],
        anti_poison: DnsAntiPoisonMode::CrossCheck,
        cache: Some(DnsCacheBlockConfig {
            max_entries: 1,
            min_ttl: 60,
            max_ttl: 60,
            enable_negative_cache: true,
            negative_ttl: 1,
        }),
        ..serde_yaml::from_str::<DnsBlockConfig>("{}").unwrap()
    };
    cfg.validate().expect("合法边界应通过");
}

/// validate E1 矩阵：坏上游串 / 端口 0 / 裸 "." / 重复 pattern /
/// cross_check 无 trusted / cache min>max / listen_port 0 / timeout 0。
#[test]
fn dns_block_validate_rejects_illegal_values() {
    let base = || DnsBlockConfig {
        enabled: true,
        domestic: vec!["223.5.5.5:53".to_string()],
        trusted: vec!["1.1.1.1:53".to_string()],
        rules: vec![],
        default_group: DnsGroup::Domestic,
        anti_poison: DnsAntiPoisonMode::Off,
        timeout_ms: 5_000,
        retries: 2,
        cache: None,
        tls_skip_verify: false,
        listen_address: "127.0.0.1".parse().unwrap(),
        listen_port: 15_353,
        fake_ip: None,
        hosts: None,
    };

    let mut cfg = base();
    cfg.domestic = vec!["223.5.5.5".to_string()];
    let err = cfg.validate().expect_err("缺端口上游应拒绝");
    assert!(err.to_string().contains("ip:port"), "应指引进形：{err}");

    let mut cfg = base();
    cfg.trusted = vec!["1.1.1.1:0".to_string()];
    let err = cfg.validate().expect_err("端口 0 上游应拒绝");
    assert!(err.to_string().contains("1.1.1.1:0"), "应带原值：{err}");

    let mut cfg = base();
    cfg.rules = vec![DnsRuleConfig {
        pattern: ".".to_string(),
        group: DnsGroup::Domestic,
    }];
    let err = cfg.validate().expect_err("裸 \".\" 应拒绝");
    assert!(
        err.to_string().contains("suffix"),
        "应指明 suffix 规则：{err}"
    );

    let mut cfg = base();
    cfg.rules = vec![
        DnsRuleConfig {
            pattern: "example.com".to_string(),
            group: DnsGroup::Domestic,
        },
        DnsRuleConfig {
            pattern: "example.com".to_string(),
            group: DnsGroup::Trusted,
        },
    ];
    let err = cfg.validate().expect_err("重复 pattern 应拒绝");
    assert!(err.to_string().contains("example.com"), "应带原值：{err}");

    let mut cfg = base();
    cfg.trusted = vec![];
    cfg.anti_poison = DnsAntiPoisonMode::CrossCheck;
    let err = cfg.validate().expect_err("cross_check 无 trusted 应拒绝");
    assert!(err.to_string().contains("cross_check"), "应点名模式：{err}");

    let mut cfg = base();
    cfg.cache = Some(DnsCacheBlockConfig {
        max_entries: 16,
        min_ttl: 300,
        max_ttl: 60,
        enable_negative_cache: true,
        negative_ttl: 300,
    });
    let err = cfg.validate().expect_err("min>max 应拒绝");
    assert!(err.to_string().contains("min_ttl"), "应点名字段：{err}");

    let mut cfg = base();
    cfg.listen_port = 0;
    assert!(cfg.validate().is_err(), "listen_port 0 应拒绝");

    let mut cfg = base();
    cfg.timeout_ms = 0;
    assert!(cfg.validate().is_err(), "timeout_ms 0 应拒绝");
}

/// enabled=false 首位短路：半配置（坏上游/端口 0/裸 "."）容忍不报。
#[test]
fn dns_block_disabled_tolerates_half_config() {
    let cfg: DnsBlockConfig = serde_yaml::from_str(
        "enabled: false\ndomestic: ['not-an-addr']\nrules:\n  - { pattern: '.', group: domestic }",
    )
    .expect("半配置应可解析");
    cfg.validate().expect("关闭态应短路校验");
}

/// network 块整体 validate 贯通：dns 子块非法经 `NetworkBlockConfig::validate`
/// 透出；含 dns 块的 network 往返（dns_servers 消费注记侧写）。
#[test]
fn network_block_carries_dns_validation() {
    let base = || NetworkBlockConfig {
        sniff: None,
        egress_fwmark: None,
        mode: NetworkBlockMode::Tun,
        tun: Some(TunBlockConfig {
            name: Some("rillane0".to_string()),
            mtu: 1400,
            ipv4: Some("10.255.0.1/24".to_string()),
            ipv6: None,
            dns_servers: vec!["192.168.1.1".parse().unwrap()],
        }),
        routing: Some(RoutingBlockConfig {
            include: vec!["203.0.113.0/24".to_string()],
        }),
        dns: Some(
            serde_yaml::from_str::<DnsBlockConfig>(
                "domestic: ['223.5.5.5:53']\ntrusted: ['1.1.1.1:53']",
            )
            .unwrap(),
        ),
    };
    base().validate().expect("合法形态应通过");

    let mut cfg = base();
    cfg.dns.as_mut().unwrap().listen_port = 0;
    let err = cfg.validate().expect_err("dns 子块非法应透出");
    assert!(
        err.to_string().contains("listen_port"),
        "应带 dns 面：{err}"
    );

    // parse_cidr_pair 仍在位（dns 块未破坏既有导出面）
    assert_eq!(parse_cidr_pair("10.0.0.1/8").unwrap().1, 8);
}

/// G1-8：tls:// / dot:// / https:// 上游形态过 validate；端口 0 与缺 host 拒绝。
#[test]
fn dns_block_encrypted_upstream_forms() {
    let cfg: DnsBlockConfig = serde_yaml::from_str(
        "enabled: true\n\
         domestic: ['tls://dns.cn:8853']\n\
         trusted: ['dot://a.example', 'https://dns.example/dns-query']\n\
         default_group: trusted\n",
    )
    .expect("三形态应解析");
    cfg.validate().expect("三形态应过 validate");
    assert!(!cfg.tls_skip_verify, "缺省不跳过证书校验");

    let cfg: DnsBlockConfig =
        serde_yaml::from_str("enabled: true\ntrusted: ['tls://h:0']\ndefault_group: trusted\n")
            .unwrap();
    let err = cfg.validate().expect_err("DoT 端口 0 应拒绝");
    assert!(err.to_string().contains("端口"), "{err}");

    let cfg: DnsBlockConfig =
        serde_yaml::from_str("enabled: true\ntrusted: ['https://']\ndefault_group: trusted\n")
            .unwrap();
    let err = cfg.validate().expect_err("DoH 缺 host 应拒绝");
    assert!(err.to_string().contains("host"), "{err}");
}

/// fake-ip 块（G1-10）：缺席 None（存量零差异）；在场缺省 enabled + 基准
/// 段 198.18.0.0/15；全配置 validate 逐块透传。
#[test]
fn dns_block_fake_ip_schema_and_defaults() {
    let cfg: DnsBlockConfig =
        serde_yaml::from_str("enabled: true\ntrusted: ['1.1.1.1:53']").expect("应可解析");
    assert!(cfg.fake_ip.is_none(), "块缺席应 None（存量零差异）");
    cfg.validate().expect("无 fake_ip 应过 validate");

    let cfg: DnsBlockConfig = serde_yaml::from_str(
        "enabled: true\ntrusted: ['1.1.1.1:53']\nfake_ip: {}\ndefault_group: trusted",
    )
    .expect("空块应可解析（全缺省）");
    let fake = cfg.fake_ip.as_ref().expect("fake_ip 块应在");
    assert!(fake.enabled, "块在场缺省启用");
    assert_eq!(fake.range, "198.18.0.0/15", "段缺省 RFC 2544 基准");
    cfg.validate().expect("缺省值应过 validate");
}

/// fake_ip.range 值域矩阵：缺前缀 / 非 IPv4 / 非数字前缀 / 前缀越界 /
/// 主机位未清零全拒；enabled=false 容忍半配置（与 dns 块口径一致）。
#[test]
fn dns_block_fake_ip_range_matrix() {
    let block = |range: &str| {
        serde_yaml::from_str::<DnsBlockConfig>(&format!(
            "enabled: true\ntrusted: ['1.1.1.1:53']\nfake_ip:\n  range: \"{range}\""
        ))
        .expect("应可解析")
    };
    for (range, expect) in [
        ("198.18.0.0", "缺前缀"),
        ("host/24", "IPv4"),
        ("198.18.0.0/x", "数字"),
        ("198.18.0.0/0", "1..=30"),
        ("198.18.0.0/31", "1..=30"),
        ("198.18.1.1/15", "主机位"),
    ] {
        let cfg = block(range);
        let err = cfg.validate().expect_err(range);
        assert!(
            err.to_string().contains(expect),
            "range {range:?} 应报 {expect:?}：{err}"
        );
    }

    let cfg: DnsBlockConfig = serde_yaml::from_str(
        "enabled: true\ntrusted: ['1.1.1.1:53']\nfake_ip:\n  enabled: false\n  range: \"bad\"",
    )
    .expect("应可解析");
    cfg.validate()
        .expect("enabled=false 应容忍半配置（首位短路口径）");
}

/// hosts 映射 schema：缺省 None；非空映射过 validate；值须 IPv4/IPv6
/// 字面量；键空白/键为 IP 拒绝（G2-15）。
#[test]
fn dns_block_hosts_schema_and_matrix() {
    // 缺省 None（存量零差异）
    let cfg: DnsBlockConfig =
        serde_yaml::from_str("enabled: true\ntrusted: ['1.1.1.1:53']").expect("应可解析");
    assert!(cfg.hosts.is_none(), "hosts 缺省 None");
    cfg.validate().expect("应过 validate");

    // 合法映射（v4 + v6 混合）
    let cfg: DnsBlockConfig = serde_yaml::from_str(
        "enabled: true\ntrusted: ['1.1.1.1:53']\nhosts:\n  \"a.test\": \"10.0.0.1\"\n  \"v6.test\": \"::1\"",
    )
    .expect("应可解析");
    let hosts = cfg.hosts.as_ref().expect("hosts 应在");
    assert_eq!(hosts.get("a.test").map(String::as_str), Some("10.0.0.1"));
    assert_eq!(hosts.get("v6.test").map(String::as_str), Some("::1"));
    cfg.validate().expect("合法映射应过 validate");

    // 矩阵：坏值 / 空白键 / 键为 IP
    for (yaml, expect) in [
        (
            "enabled: true\ntrusted: ['1.1.1.1:53']\nhosts:\n  \"a.test\": \"not-an-ip\"",
            "IPv4/IPv6",
        ),
        (
            "enabled: true\ntrusted: ['1.1.1.1:53']\nhosts:\n  \"   \": \"10.0.0.1\"",
            "键不能为空",
        ),
        (
            "enabled: true\ntrusted: ['1.1.1.1:53']\nhosts:\n  \"10.0.0.1\": \"10.0.0.2\"",
            "而非 IP",
        ),
    ] {
        let cfg: DnsBlockConfig = serde_yaml::from_str(yaml).expect("应可解析");
        let err = cfg.validate().expect_err(yaml);
        assert!(err.to_string().contains(expect), "应报 {expect:?}：{err}");
    }

    // 空映射 = 合法（等价关闭）
    let cfg: DnsBlockConfig =
        serde_yaml::from_str("enabled: true\ntrusted: ['1.1.1.1:53']\nhosts: {}")
            .expect("应可解析");
    assert!(cfg.hosts.as_ref().expect("hosts 应在").is_empty());
    cfg.validate().expect("空映射应过 validate");
}
