//! network.dns 配置块 → 引擎类型转换 + DNS 服务生命周期（dns-partition.md
//! §4-4）。
//!
//! 裁决：rillane-config 定义镜像 serde 类型（零 platform 依赖），转换落本 crate
//! （`NetworkBlockConfig` → `NetworkConfig` 同模式先例）。监听独立于 TUN/
//! 网络虚拟化开关（§9-4：本地监听即独立可用面，TUN 劫持归 P1-2 落地后集成）。

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use rillane_config::{DnsAntiPoisonMode, DnsBlockConfig, DnsGroup};
use rillane_platform::network::{
    dns::DnsCacheConfig,
    dns_engine::{
        AntiPoison, DnsResolver, DnsStatsSnapshot, DnsUpstream, LocalDnsServer, PartitionPattern,
        ResolverConfig, UpstreamGroup,
    },
};
use tokio::{
    sync::{oneshot, Mutex},
    task::JoinHandle,
};
use tracing::warn;

/// `DnsBlockConfig` → 引擎 `ResolverConfig`（dns-partition.md §4-4 映射）。
///
/// - domestic 缺省（空）回落 `tun_dns_servers` 加 53 端口（E5 面可满足性在
///   此落——validate 只见本块）；回落后仍空且被 default/rules 引用 → Err；
/// - trusted 不设回落（可信性由部署者保证，§10-R-dns1），空且被引用 → Err；
/// - 规则前导点 = suffix、其余 = exact（D-2 判别式）；规范化归引擎
///   `DnsPartition` 构造期（M0 已验）；
/// - validate 未前置时直调防御：上游逐条带原串报错。
pub fn dns_block_to_resolver_config(
    cfg: &DnsBlockConfig,
    tun_dns_servers: &[IpAddr],
) -> Result<ResolverConfig> {
    let parse_group = |group: &str, servers: &[String]| -> Result<Vec<DnsUpstream>> {
        servers
            .iter()
            .map(|s| {
                DnsUpstream::parse(s).with_context(|| {
                    format!("network.dns.{group} 上游解析失败:{s:?}（ip:port / tls://host:port / https://url）")
                })
            })
            .collect()
    };
    let mut domestic = parse_group("domestic", &cfg.domestic)?;
    if domestic.is_empty() && !tun_dns_servers.is_empty() {
        warn!(
            target: "rillane::network",
            count = tun_dns_servers.len(),
            "network.dns.domestic 缺省，回落 network.tun.dns_servers:53"
        );
        domestic = tun_dns_servers
            .iter()
            .map(|ip| DnsUpstream::Udp(SocketAddr::new(*ip, 53)))
            .collect();
    }
    let trusted = parse_group("trusted", &cfg.trusted)?;

    let map_group = |g: DnsGroup| match g {
        DnsGroup::Domestic => UpstreamGroup::Domestic,
        DnsGroup::Trusted => UpstreamGroup::Trusted,
    };
    let rules = cfg
        .rules
        .iter()
        .map(|r| {
            let pattern = if r.pattern.starts_with('.') {
                PartitionPattern::Suffix(r.pattern.clone())
            } else {
                PartitionPattern::Exact(r.pattern.clone())
            };
            (pattern, map_group(r.group))
        })
        .collect::<Vec<_>>();
    let default_group = map_group(cfg.default_group);

    let domestic_referenced = matches!(default_group, UpstreamGroup::Domestic)
        || rules
            .iter()
            .any(|(_, g)| matches!(g, UpstreamGroup::Domestic));
    let trusted_referenced = matches!(default_group, UpstreamGroup::Trusted)
        || rules
            .iter()
            .any(|(_, g)| matches!(g, UpstreamGroup::Trusted));
    anyhow::ensure!(
        !(domestic.is_empty() && domestic_referenced),
        "network.dns.domestic 为空且 tun.dns_servers 未配置，但 domestic 组被 default/rules 引用（E1）——请配置 network.dns.domestic 或 network.tun.dns_servers"
    );
    anyhow::ensure!(
        !(trusted.is_empty() && trusted_referenced),
        "network.dns.trusted 为空但被 default/rules 引用（E1）——trusted 组必须显式配置（dns-partition.md §10-R-dns1）"
    );

    let cache = cfg.cache.as_ref().map(|c| DnsCacheConfig {
        max_entries: c.max_entries,
        min_ttl: u64::from(c.min_ttl),
        max_ttl: u64::from(c.max_ttl),
        enable_negative_cache: c.enable_negative_cache,
        negative_ttl: u64::from(c.negative_ttl),
        ..DnsCacheConfig::default()
    });

    Ok(ResolverConfig {
        domestic,
        trusted,
        rules,
        default_group,
        anti_poison: match cfg.anti_poison {
            DnsAntiPoisonMode::Off => AntiPoison::Off,
            DnsAntiPoisonMode::CrossCheck => AntiPoison::CrossCheck,
        },
        timeout: Duration::from_millis(cfg.timeout_ms),
        retries: cfg.retries,
        cache,
        tls_skip_verify: cfg.tls_skip_verify,
    })
}

/// DNS 服务（P2-8 M1 观测接缝）：`DnsResolver` 单例 + 本地 UDP 监听生命周期。
/// start/stop 语义对齐 `EngineDnsHandler`（oneshot 关桥 + JoinHandle 留存；
/// 取出再 await 避免 MutexGuard 跨 await——rollback_all 同款修复先例）。
pub struct DnsService {
    resolver: Arc<DnsResolver>,
    listen: SocketAddr,
    /// fake-ip 池（G1-10）：Some = 本地监听面对客户端 A 查询按池段稳定假
    /// 地址应答；None = 关闭（存量零差异）
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
    /// 静态 hosts 表（G2-15）：Some = 本地监听面 A/AAAA 查询命中直接应答
    /// 真实映射地址（优先于 fake-ip）；None = 无表（存量零差异）
    hosts: Option<Arc<rillane_core::hosts::DnsHosts>>,
    run: Mutex<Option<DnsServiceRun>>,
}

struct DnsServiceRun {
    /// 发送侧随句柄留存；drop 亦关桥（stop 走显式 send 保语义清晰）
    _shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
}

impl fmt::Debug for DnsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsService")
            .field("listen", &self.listen)
            .finish()
    }
}

impl DnsService {
    pub fn new(
        resolver: Arc<DnsResolver>,
        listen: SocketAddr,
        fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
        hosts: Option<Arc<rillane_core::hosts::DnsHosts>>,
    ) -> Self {
        Self {
            resolver,
            listen,
            fake_ip,
            hosts,
            run: Mutex::new(None),
        }
    }

    /// fake-ip 池句柄（None = 未启用）——运行时装配把它交给入口面做
    /// 出站 target 域名回填（G1-10）。
    pub fn fake_ip(&self) -> Option<Arc<rillane_core::fake_ip::FakeIpTable>> {
        self.fake_ip.clone()
    }

    /// 静态 hosts 表句柄（None = 未配置）——观测/验收面。
    pub fn hosts(&self) -> Option<Arc<rillane_core::hosts::DnsHosts>> {
        self.hosts.clone()
    }

    /// 解析器单例（控制面 flush/指标外的直用面）
    pub fn resolver(&self) -> &Arc<DnsResolver> {
        &self.resolver
    }

    /// 配置监听地址（绑定失败在任务内浮出，非此处回读实名）
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// 统计快照（控制面 /dns/stats 取数；验收「命中率有指标」口径）
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot {
        self.resolver.stats_snapshot()
    }

    /// 清缓存（控制面运维面透传）
    pub fn clear_cache(&self) {
        self.resolver.clear_cache();
    }

    /// 启动本地监听；重复 start Err。绑定失败在任务内浮出——与入口端点
    /// 「异常退出」同一呈现路径。
    pub async fn start(&self) -> Result<()> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            anyhow::bail!("DNS 服务已在运行（listen {}）", self.listen);
        }
        let (tx, rx) = oneshot::channel();
        let server = LocalDnsServer::new(
            Arc::clone(&self.resolver),
            self.listen.ip(),
            self.listen.port(),
            self.fake_ip.clone(),
            self.hosts.clone(),
        );
        let task = tokio::spawn(async move { server.serve(rx).await });
        *run = Some(DnsServiceRun {
            _shutdown: tx,
            task,
        });
        Ok(())
    }

    /// 关桥并等待监听任务退出；未运行 = no-op Ok。
    pub async fn stop(&self) -> Result<()> {
        let run = self.run.lock().await.take();
        if let Some(run) = run {
            let _ = run._shutdown.send(());
            return run.task.await.context("DNS 监听任务异常退出")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rillane_platform::network::{
        dns_engine::{decode_query, encode_query, encode_response, DnsAnswer, DnsAnswerData},
        DnsRecordType,
    };
    use tokio::net::UdpSocket;

    fn block(yaml: &str) -> DnsBlockConfig {
        serde_yaml::from_str(yaml).expect("块应可解析")
    }

    /// §4-4 全字段映射：规则两模式判别式、组映射、防污染、缓存、超时。
    #[test]
    fn conversion_maps_all_fields() {
        let cfg = block(
            "domestic: ['223.5.5.5:53']\n\
             trusted: ['1.1.1.1:53', '[2001:db8::1]:53']\n\
             rules:\n  \
             - { pattern: '.cn', group: domestic }\n  \
             - { pattern: 'Example.COM.', group: trusted }\n\
             default_group: trusted\n\
             anti_poison: cross_check\n\
             timeout_ms: 2500\n\
             retries: 3\n\
             cache: { max_entries: 128, min_ttl: 30, max_ttl: 600, enable_negative_cache: false, negative_ttl: 60 }",
        );
        let out = dns_block_to_resolver_config(&cfg, &[]).expect("转换应成功");
        assert_eq!(
            out.domestic,
            vec![DnsUpstream::Udp(
                "223.5.5.5:53".parse::<SocketAddr>().unwrap()
            )]
        );
        assert_eq!(out.trusted.len(), 2);
        assert_eq!(
            out.trusted[1],
            DnsUpstream::Udp("[2001:db8::1]:53".parse::<SocketAddr>().unwrap()),
            "IPv6 上游应可解析"
        );
        assert_eq!(out.rules.len(), 2);
        assert_eq!(
            out.rules[0].0,
            PartitionPattern::Suffix(".cn".to_string()),
            "前导点 = suffix"
        );
        assert_eq!(
            out.rules[1].0,
            PartitionPattern::Exact("Example.COM.".to_string()),
            "无前导点 = exact（规范化归引擎构造期）"
        );
        assert_eq!(out.rules[0].1, UpstreamGroup::Domestic);
        assert_eq!(out.rules[1].1, UpstreamGroup::Trusted);
        assert_eq!(out.default_group, UpstreamGroup::Trusted);
        assert_eq!(out.anti_poison, AntiPoison::CrossCheck);
        assert_eq!(out.timeout, Duration::from_millis(2_500));
        assert_eq!(out.retries, 3);
        let cache = out.cache.expect("cache 块应映射");
        assert_eq!(cache.max_entries, 128);
        assert_eq!(cache.min_ttl, 30);
        assert_eq!(cache.max_ttl, 600);
        assert!(!cache.enable_negative_cache);
        assert_eq!(cache.negative_ttl, 60);
    }

    /// domestic 缺省回落 tun.dns_servers:53；显式 domestic 优先不混入回落。
    #[test]
    fn domestic_falls_back_to_tun_dns_servers() {
        let cfg = block("default_group: trusted\ntrusted: ['1.1.1.1:53']");
        let tun_dns = ["192.168.1.1".parse::<IpAddr>().unwrap()];
        let out = dns_block_to_resolver_config(&cfg, &tun_dns).expect("回落应成功");
        assert_eq!(
            out.domestic,
            vec![DnsUpstream::Udp(SocketAddr::from(([192, 168, 1, 1], 53)))],
            "回落应派生 53 端口"
        );

        let cfg =
            block("domestic: ['223.5.5.5:53']\ndefault_group: trusted\ntrusted: ['1.1.1.1:53']");
        let out = dns_block_to_resolver_config(&cfg, &tun_dns).expect("显式优先应成功");
        assert_eq!(
            out.domestic,
            vec![DnsUpstream::Udp(
                "223.5.5.5:53".parse::<SocketAddr>().unwrap()
            )],
            "显式 domestic 不混入回落"
        );
    }

    /// G1-8：tls:// / dot:// / https:// 上游串 → 引擎 DnsUpstream 三态映射。
    #[test]
    fn encrypted_upstream_forms_convert() {
        let cfg = block(
            "domestic: ['tls://dns.cn:8853']\n\
             trusted: ['dot://one-dot.example', 'https://dns.example/dns-query', '1.1.1.1:53']\n\
             default_group: trusted",
        );
        let out = dns_block_to_resolver_config(&cfg, &[]).expect("转换应成功");
        assert_eq!(
            out.domestic,
            vec![DnsUpstream::Dot {
                host: "dns.cn".into(),
                port: 8853,
                sni: "dns.cn".into()
            }]
        );
        assert_eq!(
            out.trusted[0],
            DnsUpstream::Dot {
                host: "one-dot.example".into(),
                port: 853,
                sni: "one-dot.example".into()
            },
            "dot:// 别名 + 缺省 853"
        );
        assert_eq!(
            out.trusted[1],
            DnsUpstream::Doh {
                url: "https://dns.example/dns-query".into()
            }
        );
        assert_eq!(
            out.trusted[2],
            DnsUpstream::Udp("1.1.1.1:53".parse().unwrap()),
            "裸 ip:port 仍为 UDP"
        );
        assert!(!out.tls_skip_verify, "缺省校验证书");

        // tls_skip_verify 配置透传
        let cfg =
            block("trusted: ['tls://a.example']\ndefault_group: trusted\ntls_skip_verify: true");
        let out = dns_block_to_resolver_config(&cfg, &[]).expect("转换应成功");
        assert!(out.tls_skip_verify);

        // 非法形态点名报错
        let cfg = block("trusted: ['ftp://x']\ndefault_group: trusted");
        let err = dns_block_to_resolver_config(&cfg, &[]).unwrap_err();
        assert!(err.to_string().contains("trusted"), "{err}");
    }

    /// 回落后仍空且被引用 → Err 带指引；未被引用（default=trusted 且无
    /// domestic 规则）→ Ok（引擎侧再兜底）。trusted 空被引用同理 Err。
    #[test]
    fn empty_referenced_group_rejected() {
        let cfg = block("trusted: ['1.1.1.1:53']");
        let err =
            dns_block_to_resolver_config(&cfg, &[]).expect_err("default=domestic 且双空应拒绝");
        assert!(
            err.to_string().contains("tun.dns_servers"),
            "应指引回落面：{err}"
        );

        let cfg = block("trusted: ['1.1.1.1:53']\nrules:\n  - { pattern: '.cn', group: domestic }");
        let err = dns_block_to_resolver_config(&cfg, &[]).expect_err("规则引用空 domestic 应拒绝");
        assert!(
            err.to_string().contains("domestic"),
            "应点名 domestic：{err}"
        );

        let cfg = block("default_group: trusted\ntrusted: ['1.1.1.1:53']");
        dns_block_to_resolver_config(&cfg, &[]).expect("domestic 未被引用应放行（引擎校验兜底）");

        let cfg = block(
            "domestic: ['223.5.5.5:53']\nrules:\n  - { pattern: 'example.com', group: trusted }",
        );
        let err = dns_block_to_resolver_config(&cfg, &[]).expect_err("规则引用空 trusted 应拒绝");
        assert!(err.to_string().contains("trusted"), "应点名 trusted：{err}");
    }

    /// validate 未前置时直调防御：坏上游串带原串传播。
    #[test]
    fn invalid_upstream_propagates_with_original() {
        let cfg = block("domestic: ['223.5.5.5']\ndefault_group: trusted\ntrusted: ['1.1.1.1:53']");
        let err = dns_block_to_resolver_config(&cfg, &[]).expect_err("缺端口应拒绝");
        assert!(err.to_string().contains("223.5.5.5"), "应带原串：{err}");
    }

    // ---- DnsService 生命周期 + 端到端（mock 上游本地 UDP，零外网依赖）----

    async fn spawn_mock() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("mock 应可绑定");
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(q) = decode_query(&buf[..n]) else {
                    continue;
                };
                let answers = vec![DnsAnswer {
                    domain: q.domain.clone(),
                    rtype: DnsRecordType::A,
                    ttl: 60,
                    data: DnsAnswerData::A(std::net::Ipv4Addr::new(9, 9, 9, 9)),
                }];
                let resp = encode_response(q.id, &q.domain, q.qtype, 0, &answers);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    fn free_udp_port() -> u16 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("探针应可绑定");
        probe.local_addr().unwrap().port()
    }

    fn service(resolver_cfg: ResolverConfig, port: u16) -> DnsService {
        let resolver = Arc::new(DnsResolver::new(resolver_cfg).expect("引擎装配应成功"));
        DnsService::new(
            resolver,
            SocketAddr::from(([127, 0, 0, 1], port)),
            None,
            None,
        )
    }

    /// 生命周期：重复 start Err → 端到端查询 + stats 命中面 → stop →
    /// 重启 Ok → stop；未运行 stop = no-op Ok。
    #[tokio::test]
    async fn dns_service_lifecycle_and_end_to_end() {
        let mock = spawn_mock().await;
        let base = block("default_group: trusted\ntrusted: ['127.0.0.1:53']");
        let mut resolver_cfg = dns_block_to_resolver_config(&base, &[]).expect("缺省转换应成功");
        resolver_cfg.trusted = vec![DnsUpstream::Udp(mock)];
        let port = free_udp_port();
        let svc = service(resolver_cfg, port);

        svc.start().await.expect("首次 start 应成功");
        let err = svc.start().await.expect_err("重复 start 应拒绝");
        assert!(err.to_string().contains("已在运行"), "应点名状态：{err}");

        // 端到端：客户端查询 → 本地监听 → mock 上游 → 应答
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli.connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        let q = encode_query(0x0501, "example.com", DnsRecordType::A).expect("查询应可编码");
        let mut got = None;
        for _ in 0..100 {
            if cli.send(&q).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            let mut buf = [0u8; 512];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(200), cli.recv(&mut buf)).await
            {
                got = Some(buf[..n].to_vec());
                break;
            }
        }
        let raw = got.expect("应收到应答");
        let resp =
            rillane_platform::network::dns_engine::decode_response(&raw).expect("应答应可解码");
        assert_eq!(resp.id, 0x0501);
        assert_eq!(resp.rcode, 0);
        assert_eq!(resp.answers.len(), 1);

        let snap = svc.stats_snapshot();
        assert!(snap.total_queries >= 1, "total 应计数：{snap:?}");
        assert_eq!(
            snap.trusted_queries, snap.total_queries,
            "default=trusted 全落 trusted"
        );

        svc.stop().await.expect("stop 应成功");
        svc.stop().await.expect("未运行 stop 应 no-op Ok");
        svc.start().await.expect("stop 后重启应成功");
        svc.stop().await.expect("收尾 stop 应成功");
    }
}
