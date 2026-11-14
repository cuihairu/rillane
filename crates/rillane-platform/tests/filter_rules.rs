//! network::filter 规则模型单测（覆盖率批次 1：文件此前 0%）。
//! 纯逻辑，不依赖 OS——覆盖进程/端口/IP/域名规则与预定义网段。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rillane_platform::network::filter::{
    default_filtering_config, ApplicationRule, DomainPattern, DomainRule, FilterAction,
    FilterResult, FilterStats, FilteringMode, IpRange, IpRule, PacketInfo, PortRange, PortRule,
    PredefinedIpRange, ProcessRule, ProtocolRule, ProtocolType,
};

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

#[test]
fn process_rule_matches_by_name_pid_uid_and_respects_disabled() {
    let rule = ProcessRule::new("game".into(), "game.exe".into(), FilterAction::Allow)
        .with_process_id(42)
        .with_user_id(1000);

    // 名称不符
    assert!(!rule.matches_process("other.exe", Some(42), Some(1000)));
    // pid/uid 任一不符
    assert!(!rule.matches_process("game.exe", Some(43), Some(1000)));
    assert!(!rule.matches_process("game.exe", Some(42), Some(1001)));
    // 全符
    assert!(rule.matches_process("game.exe", Some(42), Some(1000)));
    // 规则未带 pid/uid 时不比对（Option 双 Some 才比）
    let loose = ProcessRule::new("loose".into(), "app".into(), FilterAction::Deny);
    assert!(loose.matches_process("app", None, None));
    assert!(loose.matches_process("app", Some(9), Some(9)));
    // 禁用即不匹配
    let off = rule.clone().with_enabled(false);
    assert!(!off.matches_process("game.exe", Some(42), Some(1000)));
    // 空名规则匹配任意名称
    let wildcard = ProcessRule::new("w".into(), String::new(), FilterAction::Deny);
    assert!(wildcard.matches_process("anything", None, None));
}

#[test]
fn port_range_variants_and_rule_matching() {
    let single = PortRule::new("s".into(), PortRange::single(443), FilterAction::Deny);
    assert!(single.matches_port(443));
    assert!(!single.matches_port(444));
    assert!(!single.clone().with_enabled(false).matches_port(443));

    let range = PortRule::new(
        "r".into(),
        PortRange::range(30000, 40000).unwrap(),
        FilterAction::Deny,
    );
    assert!(range.matches_port(30000));
    assert!(range.matches_port(40000));
    assert!(!range.matches_port(29999));

    assert!(PortRange::range(10, 9).is_err(), "start>end 必须报错");

    let list = PortRange::list(vec![80, 8080]);
    assert!(list.contains(80));
    assert!(!list.contains(81));
    assert_eq!(list.count(), 2);

    assert!(PortRange::all().contains(65535));
    assert_eq!(PortRange::single(1).count(), 1);
    assert_eq!(PortRange::range(10, 20).unwrap().count(), 11);
    assert_eq!(PortRange::all().count(), 65536);
}

#[test]
fn protocol_type_parse_and_ip_protocol_roundtrip() {
    assert_eq!(ProtocolType::parse("tcp").unwrap(), ProtocolType::Tcp);
    assert_eq!(ProtocolType::parse("UDP").unwrap(), ProtocolType::Udp);
    assert_eq!(ProtocolType::parse("icmp").unwrap(), ProtocolType::Icmp);
    assert_eq!(ProtocolType::parse("icmpv6").unwrap(), ProtocolType::Icmpv6);
    assert_eq!(ProtocolType::parse("all").unwrap(), ProtocolType::All);
    assert!(ProtocolType::parse("sctp").is_err());

    assert_eq!(ProtocolType::from_ip_protocol(6), ProtocolType::Tcp);
    assert_eq!(ProtocolType::from_ip_protocol(17), ProtocolType::Udp);
    assert_eq!(ProtocolType::from_ip_protocol(1), ProtocolType::Icmp);
    assert_eq!(ProtocolType::from_ip_protocol(58), ProtocolType::Icmpv6);
    assert_eq!(ProtocolType::from_ip_protocol(99), ProtocolType::All);

    assert_eq!(ProtocolType::Tcp.as_ip_protocol(), 6);
    assert_eq!(ProtocolType::Udp.as_ip_protocol(), 17);
    assert_eq!(ProtocolType::Icmp.as_ip_protocol(), 1);
    assert_eq!(ProtocolType::Icmpv6.as_ip_protocol(), 58);
    assert_eq!(ProtocolType::All.as_ip_protocol(), 0);

    let rule = ProtocolRule::new("udp-block".into(), ProtocolType::Udp, FilterAction::Deny);
    assert_eq!(rule.protocol, ProtocolType::Udp);
    assert!(rule.clone().with_priority(1).priority == 1);
}

#[test]
fn ip_range_contains_for_every_variant() {
    // Single
    assert!(IpRange::single(v4("1.2.3.4")).contains(v4("1.2.3.4")));
    assert!(!IpRange::single(v4("1.2.3.4")).contains(v4("1.2.3.5")));

    // Network：掩码边界（前缀 24 命中同段、不命中邻段）
    let net = IpRange::network(v4("10.0.0.0"), 24).unwrap();
    assert!(net.contains(v4("10.0.0.199")));
    assert!(!net.contains(v4("10.0.1.1")));
    let v6net = IpRange::network(v6("2001:db8::"), 32).unwrap();
    assert!(v6net.contains(v6("2001:db8::1")));
    assert!(!v6net.contains(v6("2001:db9::1")));
    // 版本不匹配恒 false
    assert!(!net.contains(v6("2001:db8::1")));
    assert!(IpRange::network(v4("10.0.0.0"), 33).is_err());
    assert!(IpRange::network(v6("2001:db8::"), 129).is_err());

    // Range：同版本可建、跨版本拒绝
    let r = IpRange::range(v4("10.0.0.1"), v4("10.0.0.9")).unwrap();
    assert!(r.contains(v4("10.0.0.5")));
    assert!(!r.contains(v4("10.0.0.10")));
    let r6 = IpRange::range(v6("::1"), v6("::9")).unwrap();
    assert!(r6.contains(v6("::5")));
    assert!(IpRange::range(v4("10.0.0.1"), v6("::1")).is_err());

    // List
    let l = IpRange::list(vec![v4("8.8.8.8"), v4("1.1.1.1")]);
    assert!(l.contains(v4("8.8.8.8")));
    assert!(!l.contains(v4("9.9.9.9")));

    // IpRule 包装：enabled 门控
    let rule = IpRule::new("cn".into(), net, FilterAction::Deny);
    assert!(rule.matches_ip(v4("10.0.0.7")));
    assert!(!rule.clone().with_enabled(false).matches_ip(v4("10.0.0.7")));
}

#[test]
fn ip_range_as_string_rendering() {
    assert_eq!(IpRange::single(v4("1.2.3.4")).as_string(), "1.2.3.4");
    assert_eq!(
        IpRange::network(v4("10.0.0.0"), 24).unwrap().as_string(),
        "10.0.0.0/24"
    );
    assert_eq!(
        IpRange::range(v4("10.0.0.1"), v4("10.0.0.9"))
            .unwrap()
            .as_string(),
        "10.0.0.1-10.0.0.9"
    );
    assert_eq!(
        IpRange::list(vec![v4("1.1.1.1"), v4("2.2.2.2")]).as_string(),
        "[1.1.1.1, 2.2.2.2]"
    );
    assert_eq!(
        IpRange::predefined(PredefinedIpRange::Private).as_string(),
        "private"
    );
}

#[test]
fn predefined_ip_ranges_classify_representative_addresses() {
    use PredefinedIpRange as P;
    // Private：10/8、172.16/12、192.168/16；v6 fc00::/7
    assert!(P::Private.contains(v4("10.1.2.3")));
    assert!(P::Private.contains(v4("172.16.0.1")));
    assert!(P::Private.contains(v4("172.31.255.255")));
    assert!(!P::Private.contains(v4("172.32.0.1")));
    assert!(P::Private.contains(v4("192.168.1.1")));
    assert!(!P::Private.contains(v4("8.8.8.8")));
    assert!(P::Private.contains(v6("fc00::1")));
    assert!(!P::Private.contains(v6("fe80::1")));

    assert!(P::Loopback.contains(v4("127.0.0.1")));
    assert!(P::Loopback.contains(v6("::1")));
    assert!(!P::Loopback.contains(v4("128.0.0.1")));

    assert!(P::LinkLocal.contains(v4("169.254.1.1")));
    assert!(P::LinkLocal.contains(v6("fe80::1")));
    assert!(!P::LinkLocal.contains(v4("169.255.1.1")));

    assert!(P::Multicast.contains(v4("224.0.0.1")));
    assert!(P::Multicast.contains(v6("ff02::1")));
    assert!(!P::Multicast.contains(v4("8.8.8.8")));

    assert!(P::Broadcast.contains(v4("255.255.255.255")));
    assert!(!P::Broadcast.contains(v4("255.255.255.254")));
    assert!(!P::Broadcast.contains(v6("::1")), "v6 无广播");

    assert!(P::Documentation.contains(v4("192.0.2.1")));
    assert!(P::Documentation.contains(v4("198.51.100.7")));
    assert!(P::Documentation.contains(v4("203.0.113.9")));
    assert!(!P::Documentation.contains(v4("203.0.114.1")));
    assert!(P::Documentation.contains(v6("2001:db8::1")));
    assert!(!P::Documentation.contains(v6("2001:db9::1")));

    assert!(P::Public.contains(v4("8.8.8.8")));
    assert!(!P::Public.contains(v4("10.0.0.1")));
    assert!(!P::Public.contains(v4("255.1.1.1")));
    assert!(!P::Public.contains(v4("224.0.0.1")));
    assert!(!P::Public.contains(v6("fc00::1")));

    for name in [
        "private",
        "loopback",
        "link_local",
        "multicast",
        "broadcast",
        "documentation",
        "public",
    ] {
        assert!(
            [
                P::Private,
                P::Loopback,
                P::LinkLocal,
                P::Multicast,
                P::Broadcast,
                P::Documentation,
                P::Public
            ]
            .iter()
            .any(|p| p.as_string() == name),
            "缺少预定义名 {name}"
        );
    }
}

#[test]
fn domain_pattern_variants() {
    assert!(DomainPattern::exact("a.com".into()).matches("a.com"));
    assert!(!DomainPattern::exact("a.com".into()).matches("b.a.com"));

    assert!(DomainPattern::suffix(".cn".into()).matches("edu.cn"));
    assert!(!DomainPattern::suffix(".cn".into()).matches("edu.com"));

    let re = DomainPattern::regex(r"^gw-\d+\.example\.com$".into()).unwrap();
    assert!(re.matches("gw-1.example.com"));
    assert!(!re.matches("gw-x.example.com"));
    assert!(DomainPattern::regex("([".into()).is_err(), "坏正则必须报错");
    // matches 内部容忍坏正则（false 而非 panic）
    assert!(!DomainPattern::Regex {
        pattern: "([".into()
    }
    .matches("x"));

    let list = DomainPattern::list(vec!["a.com".into(), "b.com".into()]);
    assert!(list.matches("a.com"));
    assert!(!list.matches("c.com"));

    let wc = DomainPattern::wildcard("gw-*.example.com".into());
    assert!(wc.matches("gw-01.example.com"));
    assert!(!wc.matches("api.example.com"));
    // 单段无 * = 等值匹配；多段 * 不支持 = false
    assert!(DomainPattern::wildcard("a.com".into()).matches("a.com"));
    assert!(!DomainPattern::wildcard("a*b*c".into()).matches("abc"));

    let rule = DomainRule::new(
        "docs".into(),
        DomainPattern::suffix(".docs".into()),
        FilterAction::Deny,
    );
    assert!(rule.matches_domain("x.docs"));
    assert!(!rule.clone().with_enabled(false).matches_domain("x.docs"));
}

#[test]
fn filter_action_stats_result_and_packet_info_builders() {
    assert!(FilterAction::Allow.is_allow());
    assert!(!FilterAction::Allow.is_deny());
    assert!(FilterAction::Deny.is_deny());
    assert!(!FilterAction::Deny.is_allow());
    assert!(!FilterAction::Redirect { target: "t".into() }.is_allow());

    let mut stats = FilterStats::new();
    assert_eq!(stats.hit_rate(), 0.0);
    stats.record_packet(&FilterAction::Allow, Some("r1"));
    stats.record_packet(&FilterAction::Deny, Some("r1"));
    stats.record_packet(&FilterAction::Deny, Some("r2"));
    stats.record_packet(&FilterAction::Throttle { rate: 1, burst: 1 }, None);
    stats.update();
    assert_eq!(stats.total_packets, 4);
    assert_eq!(stats.allowed_packets, 1);
    assert_eq!(stats.denied_packets, 2);
    assert_eq!(stats.redirected_packets, 1);
    assert_eq!(stats.hit_rate(), 0.5);
    let top = stats.top_rules(1);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0], ("r1".to_string(), 2));
    let default = FilterStats::default();
    assert_eq!(default.total_packets, 0);

    let allow = FilterResult::allow();
    assert!(allow.is_allowed() && !allow.matched);
    let deny = FilterResult::deny("r".into(), "why".into());
    assert!(deny.matched && !deny.is_allowed());
    let redir = FilterResult::redirect("t:1".into(), "r".into());
    assert!(redir.matched);

    let info = PacketInfo::new(v4("1.1.1.1"), v4("2.2.2.2"), ProtocolType::Tcp, 64)
        .with_ports(51000, 443)
        .with_process(7, 1000)
        .with_application("game")
        .with_domain("gw.example.com");
    assert_eq!(info.dst_port, Some(443));
    assert_eq!(info.process_id, Some(7));
    assert_eq!(info.application.as_deref(), Some("game"));
    assert_eq!(info.domain.as_deref(), Some("gw.example.com"));

    let app = ApplicationRule::new("app".into(), "com.game".into(), FilterAction::Allow)
        .with_priority(10)
        .with_metadata("src", "user")
        .with_enabled(true);
    assert_eq!(app.priority, 10);
    assert_eq!(app.metadata.get("src").map(String::as_str), Some("user"));
}

#[test]
fn default_filtering_config_starts_disabled_blacklist() {
    let cfg = default_filtering_config();
    assert!(!cfg.enabled);
    assert_eq!(cfg.mode, FilteringMode::Blacklist);
    assert!(cfg.applications.is_empty());
    assert!(cfg.processes.is_empty());
    assert!(cfg.protocols.is_empty());
    assert!(cfg.ports.is_empty());
    assert!(cfg.ip_addresses.is_empty());
    assert!(cfg.domains.is_empty());
}
