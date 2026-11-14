//! P1-3 network-route.md §7.1（R0 半边）：network 块 schema——存量零差异 /
//! 往返 / deny 收口 / mode 三非法值 / CIDR 与 mtu 非法。转换半边见
//! rillane-runtime `network_config.rs`。

use rillane_config::{
    NetworkBlockConfig, NetworkBlockMode, RillaneConfig, RoutingBlockConfig, TunBlockConfig,
};

const BASE_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
  enable_tracing: false
ingress: []
egress: []
routing:
  default_node: direct
  groups: []
  rules: []
"#;

/// §1.5：存量配置无 network: → None，行为零差异；含块可解析且缺省值正确。
#[test]
fn network_block_defaults_backward_compatible() {
    let cfg: RillaneConfig = serde_yaml::from_str(BASE_YAML).expect("无 network 块应可解析");
    assert_eq!(cfg.network, None, "存量配置 network 应为 None");

    let yaml = format!(
        "{BASE_YAML}network:\n  tun:\n    name: rillane0\n  routing:\n    include:\n      - 203.0.113.0/24\n"
    );
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).expect("含 network 块应可解析");
    let network = cfg.network.expect("network 块应存在");
    assert_eq!(network.mode, NetworkBlockMode::Tun, "mode 缺省 tun");
    assert_eq!(
        network.egress_fwmark, None,
        "egress_fwmark 缺省 None = 不打 mark 零差异"
    );
    let tun = network.tun.expect("tun 块应存在");
    assert_eq!(tun.name.as_deref(), Some("rillane0"));
    assert_eq!(tun.mtu, 1500, "mtu 缺省 1500");
    assert_eq!(
        tun.ipv4.as_deref(),
        Some("10.255.0.1/24"),
        "ipv4 缺省同 §1.1 样例"
    );
    assert_eq!(tun.ipv6, None);
    assert!(tun.dns_servers.is_empty());
    let routing = network.routing.expect("routing 块应存在");
    assert_eq!(routing.include, ["203.0.113.0/24"]);

    // 只建设备不设路由 = 合法（E4：纯抓包/测试场景）
    let yaml = format!("{BASE_YAML}network:\n  tun:\n    mtu: 1400\n");
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).expect("仅 tun 块应可解析");
    assert!(cfg.network.unwrap().routing.is_none());

    // egress_fwmark 显式给值可解析（缺省 None 半边见上）
    let yaml = format!("{BASE_YAML}network:\n  egress_fwmark: 24165\n");
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).expect("egress_fwmark 应可解析");
    assert_eq!(
        cfg.network.expect("network 块").egress_fwmark,
        Some(24165),
        "egress_fwmark 应按值解析"
    );
}

/// §1.5：块级 deny_unknown_fields——拼错子字段构建期即报（B2 定向收口）。
#[test]
fn network_block_denies_unknown_fields() {
    let yaml = "mode: tun\nunknwon_field: 1\n";
    let err = serde_yaml::from_str::<NetworkBlockConfig>(yaml).expect_err("未知字段应被 deny 拒绝");
    assert!(
        err.to_string().contains("unknown field"),
        "错误应点名未知字段：{err}"
    );

    let yaml = "mode: tun\ntun:\n  nam: rillane0\n";
    let err =
        serde_yaml::from_str::<NetworkBlockConfig>(yaml).expect_err("tun 子块未知字段应被拒绝");
    assert!(
        err.to_string().contains("unknown field"),
        "错误应点名未知字段：{err}"
    );

    let yaml = "mode: tun\nrouting:\n  inclde: []\n";
    let err =
        serde_yaml::from_str::<NetworkBlockConfig>(yaml).expect_err("routing 子块未知字段应被拒绝");
    assert!(
        err.to_string().contains("unknown field"),
        "错误应点名未知字段：{err}"
    );
}

/// 含块配置 serde 往返等价（缺省字段往返后仍保留缺省值）。
#[test]
fn network_block_serde_roundtrip() {
    let cfg = NetworkBlockConfig {
        egress_fwmark: None,
        mode: NetworkBlockMode::Tun,
        tun: Some(TunBlockConfig {
            name: Some("rillane0".to_string()),
            mtu: 1400,
            ipv4: Some("10.255.0.1/24".to_string()),
            ipv6: Some("fd00:db8::1/64".to_string()),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
        }),
        routing: Some(RoutingBlockConfig {
            include: vec![
                "203.0.113.0/24".to_string(),
                "2001:db8::/32".to_string(),
                "198.51.100.7/32".to_string(),
            ],
        }),
        dns: None,
    };
    let rendered = serde_yaml::to_string(&cfg).expect("应可序列化");
    let reparsed: NetworkBlockConfig = serde_yaml::from_str(&rendered).expect("序列化结果应可往返");
    assert_eq!(reparsed, cfg);
}

/// §1.4 E1：transparent/tap/hybrid 三非法 mode 构建期报"未实现"。
#[test]
fn network_block_rejects_non_tun_modes() {
    for mode in [
        NetworkBlockMode::Transparent,
        NetworkBlockMode::Tap,
        NetworkBlockMode::Hybrid,
    ] {
        let cfg = NetworkBlockConfig {
            egress_fwmark: None,
            mode,
            tun: None,
            routing: None,
            dns: None,
        };
        let err = cfg.validate().expect_err("非 tun mode 应被拒绝");
        assert!(
            err.to_string().contains("未实现"),
            "错误应含「未实现」指引：{err}"
        );
    }
    // tun 通过（空块 = 最小合法形态）
    NetworkBlockConfig {
        egress_fwmark: None,
        mode: NetworkBlockMode::Tun,
        tun: None,
        routing: None,
        dns: None,
    }
    .validate()
    .expect("空 tun 块应通过");
}

/// §1.4 E3：mtu < 68 / 各处 CIDR 非法（坏地址、坏前缀、超上限、裸 IP）带原串报错。
#[test]
fn network_block_validate_rejects_illegal_values() {
    let base = || NetworkBlockConfig {
        egress_fwmark: None,
        mode: NetworkBlockMode::Tun,
        tun: Some(TunBlockConfig {
            name: None,
            mtu: 1400,
            ipv4: Some("10.255.0.1/24".to_string()),
            ipv6: None,
            dns_servers: vec![],
        }),
        routing: Some(RoutingBlockConfig {
            include: vec!["203.0.113.0/24".to_string()],
        }),
        dns: None,
    };

    // mtu 下界（68 = 最小 IPv4 MTU，TunConfig::validate 口径）
    let mut cfg = base();
    cfg.tun.as_mut().unwrap().mtu = 67;
    let err = cfg.validate().expect_err("mtu<68 应被拒绝");
    assert!(err.to_string().contains("68"), "错误应含下界：{err}");

    // tun.ipv4 坏地址
    let mut cfg = base();
    cfg.tun.as_mut().unwrap().ipv4 = Some("10.255.0.300/24".to_string());
    let err = cfg.validate().expect_err("坏地址应被拒绝");
    assert!(
        err.to_string().contains("10.255.0.300/24"),
        "应带原串：{err}"
    );

    // tun.ipv6 前缀超上限
    let mut cfg = base();
    cfg.tun.as_mut().unwrap().ipv6 = Some("fd00:db8::1/129".to_string());
    let err = cfg.validate().expect_err("v6 前缀超限应被拒绝");
    assert!(err.to_string().contains("/129"), "应带原串：{err}");

    // include 裸 IP（无前缀）——须报并指引 /32（§9-10：Host 变体不进 schema）
    let mut cfg = base();
    cfg.routing.as_mut().unwrap().include = vec!["198.51.100.7".to_string()];
    let err = cfg.validate().expect_err("裸 IP 应被拒绝");
    assert!(
        err.to_string().contains("198.51.100.7") && err.to_string().contains("/32"),
        "应带原串与 /32 指引：{err}"
    );

    // include v4 前缀超上限
    let mut cfg = base();
    cfg.routing.as_mut().unwrap().include = vec!["203.0.113.0/33".to_string()];
    let err = cfg.validate().expect_err("v4 前缀超限应被拒绝");
    assert!(err.to_string().contains("/33"), "应带原串：{err}");

    // 合法边界全通过（/0 与 /32、v6 /128）
    let mut cfg = base();
    cfg.routing.as_mut().unwrap().include = vec![
        "0.0.0.0/0".to_string(),
        "198.51.100.7/32".to_string(),
        "::/0".to_string(),
        "fd00::/128".to_string(),
    ];
    cfg.validate().expect("合法边界应通过");
}
