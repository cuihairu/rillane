//! network 配置区块 → rillane-platform 类型转换（network-route.md §1.2）
//!
//! 裁决：rillane-config 定义镜像 serde 类型（零 platform 依赖），转换落本 crate
//! （`UdpConfig` → `UdpSessionConfig` 同模式先例）。消费点 = R1 rillaned 派生开关
//! （`cfg.network.map(network_block_to_platform)`）。

use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use tracing::warn;

use rillane_config::{
    parse_cidr_pair, NetworkBlockConfig, NetworkBlockMode, RoutingBlockConfig, TunBlockConfig,
};
use rillane_platform::network::route::{
    default_bypass_rules, ipv4_netmask, RouteDestination, RouteRule,
};
use rillane_platform::network::{
    NetworkConfig, NetworkMode, RoutingConfig as PlatformRoutingConfig, TunConfig,
};

/// `NetworkBlockConfig` → platform `NetworkConfig`（§1.2 转换映射表）。
///
/// filtering/dns 恒 None（P2-8，schema 层 deny 已拦）；策略维度不在 config 暴露，
/// 转换处固定 `RoutingMode::Ip` / priority `100+i` / `Some(0)`（§9-6）。
/// E5（include 命中 auto-bypass 剔除 + warning）在此落：validate 是只读检查，
/// 剔除必须改写 rules——当前可比对集 = tun 自身网段；egress/mesh/control 地址
/// 集 R1 接线时并入（tun-dataplane §2.7）。
pub fn network_block_to_platform(cfg: &NetworkBlockConfig) -> Result<NetworkConfig> {
    let mode = match cfg.mode {
        NetworkBlockMode::Tun => NetworkMode::Tun,
        NetworkBlockMode::Transparent => NetworkMode::Transparent,
        NetworkBlockMode::Tap => NetworkMode::Tap,
        NetworkBlockMode::Hybrid => NetworkMode::Hybrid,
    };
    let tun = cfg
        .tun
        .as_ref()
        .map(|t| tun_block_to_platform(t, cfg.routing.is_some()))
        .transpose()?;
    let routing = cfg
        .routing
        .as_ref()
        .map(|r| routing_block_to_platform(r, cfg.tun.as_ref()))
        .transpose()?;
    Ok(NetworkConfig {
        mode,
        tun,
        routing,
        filtering: None,
        dns: None,
    })
}

/// tun 块 → `TunConfig`：CIDR 拆 addr/netmask（v4）/addr/prefix_len（v6）；
/// `enable_routing = routing.is_some()`（R1 消费）、`enable_dns = false`（P2-8）、
/// 网关字段 None（默认路由归 V2 全局接管）。
fn tun_block_to_platform(tun: &TunBlockConfig, enable_routing: bool) -> Result<TunConfig> {
    let mut out = TunConfig {
        name: tun.name.clone(),
        mtu: tun.mtu,
        ..Default::default()
    };
    if let Some(ipv4) = &tun.ipv4 {
        let (addr, prefix) = parse_cidr_pair(ipv4)?;
        let addr = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => anyhow::bail!("network.tun.ipv4 应为 IPv4 CIDR：{ipv4:?}"),
        };
        out.ipv4_addr = Some(addr);
        out.ipv4_netmask = Some(Ipv4Addr::from(ipv4_netmask(prefix)));
    }
    if let Some(ipv6) = &tun.ipv6 {
        let (addr, prefix) = parse_cidr_pair(ipv6)?;
        let addr = match addr {
            IpAddr::V6(v6) => v6,
            IpAddr::V4(_) => anyhow::bail!("network.tun.ipv6 应为 IPv6 CIDR：{ipv6:?}"),
        };
        out.ipv6_addr = Some(addr);
        out.ipv6_prefix_len = Some(prefix);
    }
    out.dns_servers = tun.dns_servers.clone();
    out.enable_dns = false;
    out.enable_routing = enable_routing;
    Ok(out)
}

/// routing 块 → `RoutingConfig`：include 逐条 → `RouteRule{name: "include[i]",
/// priority: 100+i, metric: Some(0), Unicast, enabled}`；auto-bypass 命中剔除
/// + warning（E5）；bypass_rules = `default_bypass_rules()` 兜底。
fn routing_block_to_platform(
    routing: &RoutingBlockConfig,
    tun: Option<&TunBlockConfig>,
) -> Result<PlatformRoutingConfig> {
    let auto_bypass = tun_auto_bypass(tun);
    let mut rules = Vec::with_capacity(routing.include.len());
    for (i, cidr) in routing.include.iter().enumerate() {
        let dest = parse_destination(cidr)?;
        if auto_bypass.iter().any(|b| b == &dest) {
            // 防环优先于严格（§1.4-3）：剔除不 Err
            warn!(
                target: "rillane::network",
                cidr,
                "network.routing.include 命中 auto-bypass（tun 自身网段），已剔除"
            );
            continue;
        }
        rules.push(
            RouteRule::new(format!("include[{i}]"), dest)
                .with_priority(100 + i as i32)
                .with_metric(0),
        );
    }
    Ok(PlatformRoutingConfig {
        mode: rillane_platform::network::RoutingMode::Ip,
        default_gateway: None,
        dns_servers: tun.map(|t| t.dns_servers.clone()).unwrap_or_default(),
        rules,
        bypass_rules: default_bypass_rules(),
        enabled: true,
    })
}

/// 构建期可得的 auto-bypass 集 = tun 自身网段（egress/mesh/control 地址集
/// R1 接线时并入，tun-dataplane §2.7）。
fn tun_auto_bypass(tun: Option<&TunBlockConfig>) -> Vec<RouteDestination> {
    let Some(tun) = tun else {
        return Vec::new();
    };
    [&tun.ipv4, &tun.ipv6]
        .into_iter()
        .flatten()
        .filter_map(|cidr| parse_destination(cidr).ok())
        .collect()
}

fn parse_destination(cidr: &str) -> Result<RouteDestination> {
    let (addr, prefix) = parse_cidr_pair(cidr)?;
    match addr {
        IpAddr::V4(v4) => RouteDestination::ipv4(v4, prefix),
        IpAddr::V6(v6) => RouteDestination::ipv6(v6, prefix),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn block() -> NetworkBlockConfig {
        NetworkBlockConfig {
            transparent: None,
            sniff: None,
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
        }
    }

    /// §1.2 tun 行：CIDR 拆 addr/netmask（v4）+ addr/prefix_len（v6），
    /// enable_routing/enable_dns/gateway 派生口径。
    #[test]
    fn tun_block_maps_cidr_and_derivations() {
        let out = network_block_to_platform(&block()).expect("转换应成功");
        assert!(matches!(out.mode, NetworkMode::Tun));
        assert!(out.filtering.is_none() && out.dns.is_none());

        let tun = out.tun.as_ref().expect("tun 应存在");
        assert_eq!(tun.name.as_deref(), Some("rillane0"));
        assert_eq!(tun.mtu, 1400);
        assert_eq!(
            tun.ipv4_addr,
            Some(Ipv4Addr::new(10, 255, 0, 1)),
            "ipv4 地址段拆解"
        );
        assert_eq!(
            tun.ipv4_netmask,
            Some(Ipv4Addr::new(255, 255, 255, 0)),
            "/24 → 255.255.255.0"
        );
        assert_eq!(tun.ipv4_gateway, None, "网关归 V2 全局接管");
        assert_eq!(
            tun.ipv6_addr,
            Some(Ipv6Addr::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(tun.ipv6_prefix_len, Some(64));
        assert_eq!(tun.dns_servers, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);

        // enable_dns 恒 false（P2-8）；enable_routing 派生 = routing.is_some()
        assert!(!tun.enable_dns);

        let no_routing = NetworkBlockConfig {
            transparent: None,
            sniff: None,
            routing: None,
            ..block()
        };
        let out = network_block_to_platform(&no_routing).expect("无 routing 应成功");
        assert!(
            !out.tun.as_ref().unwrap().enable_routing,
            "routing 缺省 → enable_routing=false（E4：只建设备）"
        );
    }

    /// §1.2 routing 行：include → RouteRule 全字段（name/priority 递增/metric 0/
    /// Unicast/enabled），RoutingMode::Ip，bypass 兜底，dns_servers 承接 tun 块。
    #[test]
    fn routing_block_builds_route_rules() {
        let out = network_block_to_platform(&block()).expect("转换应成功");
        let routing = out.routing.as_ref().expect("routing 应存在");
        assert!(matches!(
            routing.mode,
            rillane_platform::network::RoutingMode::Ip
        ));
        assert_eq!(routing.default_gateway, None);
        assert_eq!(
            routing.dns_servers,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(routing.bypass_rules.len(), default_bypass_rules().len());
        assert!(routing.enabled);

        assert_eq!(routing.rules.len(), 3);
        let r0 = &routing.rules[0];
        assert_eq!(r0.name, "include[0]");
        assert_eq!(r0.priority, 100);
        assert_eq!(
            r0.destination,
            RouteDestination::ipv4("203.0.113.0".parse().unwrap(), 24).unwrap()
        );
        assert_eq!(r0.gateway, None);
        assert_eq!(r0.interface, None, "接口由设备启动期注入（R1）");
        assert_eq!(r0.metric, Some(0));
        assert!(matches!(
            r0.route_type,
            rillane_platform::network::RouteType::Unicast
        ));
        assert!(r0.enabled);

        let r1 = &routing.rules[1];
        assert_eq!(r1.name, "include[1]");
        assert_eq!(r1.priority, 101, "priority 随序号递增");
        assert_eq!(
            r1.destination,
            RouteDestination::ipv6("2001:db8::".parse().unwrap(), 32).unwrap()
        );
        let r2 = &routing.rules[2];
        assert_eq!(r2.priority, 102);
        assert!(
            matches!(
                r2.destination,
                RouteDestination::Ipv4Network { prefix: 32, .. }
            ),
            "/32 即主机路由（§9-10）"
        );
    }

    /// §1.4-3 E5：include 命中 tun 自身网段 → 剔除（不 Err），其余保留；
    /// 剔除后序号仍按原 include 下标（对账可回溯原配置行）。
    #[test]
    fn include_hits_auto_bypass_filtered() {
        let mut cfg = block();
        cfg.routing.as_mut().unwrap().include = vec![
            "203.0.113.0/24".to_string(),
            "10.255.0.1/24".to_string(), // = tun.ipv4 自身网段
            "10.255.0.0/24".to_string(), // 同网段不同主机地址——字面前缀不等，保留
        ];
        let out = network_block_to_platform(&cfg).expect("剔除不应 Err");
        let routing = out.routing.unwrap();
        assert_eq!(routing.rules.len(), 2, "仅字面命中项被剔除");
        assert_eq!(routing.rules[0].destination.as_string(), "203.0.113.0/24");
        assert_eq!(routing.rules[1].destination.as_string(), "10.255.0.0/24");
        assert_eq!(routing.rules[1].name, "include[2]", "name 保留原下标可对账");
    }

    /// 四 mode 枚举映射（拒绝在 validate E1，转换层如实映射供 §2.2 让路条件判别）。
    #[test]
    fn mode_maps_all_variants() {
        for (block_mode, expect) in [
            (NetworkBlockMode::Tun, NetworkMode::Tun),
            (NetworkBlockMode::Transparent, NetworkMode::Transparent),
            (NetworkBlockMode::Tap, NetworkMode::Tap),
            (NetworkBlockMode::Hybrid, NetworkMode::Hybrid),
        ] {
            let cfg = NetworkBlockConfig {
                transparent: None,
                sniff: None,
                egress_fwmark: None,
                mode: block_mode,
                tun: None,
                routing: None,
                dns: None,
            };
            let out = network_block_to_platform(&cfg).expect("空块转换应成功");
            assert!(out.tun.is_none() && out.routing.is_none());
            assert_eq!(out.mode, expect);
        }
    }

    /// 转换防御面：坏 CIDR（validate 未前置时）逐条传播 Err 带原串。
    #[test]
    fn invalid_cidr_propagates() {
        let mut cfg = block();
        cfg.tun.as_mut().unwrap().ipv4 = Some("10.0.0.999/24".to_string());
        let err = network_block_to_platform(&cfg).expect_err("坏 tun.ipv4 应传播");
        assert!(err.to_string().contains("10.0.0.999/24"), "应带原串：{err}");

        let mut cfg = block();
        cfg.routing.as_mut().unwrap().include = vec!["::/129".to_string()];
        let err = network_block_to_platform(&cfg).expect_err("坏 include 应传播");
        assert!(err.to_string().contains("/129"), "应带原串：{err}");
    }
}
