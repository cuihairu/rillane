use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use reqwest::blocking::Client;
use seep_config::{EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, SeepConfig};
use seep_subscription::{ClashConverter, ClashExporter};
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};

mod udp_probe;

#[derive(Parser)]
#[command(author, version, about = "Seep 控制台", propagate_version = true)]
struct Cli {
    #[arg(short, long, default_value = "config/seep.yaml")]
    config: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 校验配置文件
    Check,
    /// 打印配置摘要
    Show,
    /// 查看流量统计
    Stats {
        /// 控制面完整 URL，如 http://127.0.0.1:9090/flows
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// 查看组实时质量（O-slo1：成员数据源/门判定/当前选点）
    Group {
        /// 控制面完整 URL，如 http://127.0.0.1:9090/routing/stats
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// 查看链路切换账本（O-link-obs2：最近 100 次 chain 切换事件）
    Switches {
        /// 控制面完整 URL，如 http://127.0.0.1:9090/mesh/switches
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// UDP ASSOCIATE 联调探测（P0-5 §3.3：最小 RFC 1928 客户端）
    UdpProbe {
        /// SOCKS5 入口地址，如 127.0.0.1:1080
        #[arg(long)]
        socks5: String,
        /// 目标主机（域名或 IP）
        #[arg(long)]
        host: String,
        /// 目标端口
        #[arg(long)]
        port: u16,
        /// 查询载荷 hex（如 DNS 查询）
        #[arg(long)]
        payload_hex: String,
        /// 回包等待超时（支持 s/ms/m 单位）
        #[arg(long, default_value = "3s")]
        timeout: String,
        /// SOCKS5 用户名（用户名/密码法，METHOD 0x02）
        #[arg(long)]
        user: Option<String>,
        /// SOCKS5 密码（与 --user 成对）
        #[arg(long)]
        pass: Option<String>,
    },
    /// 查看 mesh 节点
    Nodes {
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// 链路管理（多跳链路）
    Chain {
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// 从 Clash YAML 订阅转换为 Seep 配置 (preview)
    ImportClash {
        /// 订阅 URL 或文件路径
        source: String,
        /// 输出目标文件
        #[arg(short, long, default_value = "config/clash_import.yaml")]
        output: String,
    },
    /// 将 Seep 配置回导出为 Clash YAML（preview，离线转换）
    ExportClash {
        /// Seep 配置文件路径
        source: String,
        /// 输出目标文件
        #[arg(short, long, default_value = "config/clash_export.yaml")]
        output: String,
    },
    /// 订阅管理（seepd 控制面）
    Subscription {
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: SubscriptionCommand,
    },
    /// 系统路由管理（network-route.md §4：apply/clear/status）
    Route {
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// 一键诊断信息收集（生成诊断目录）
    Diagnose {
        /// 控制面 base URL，如 http://127.0.0.1:9090
        #[arg(long)]
        endpoint: Option<String>,
        /// 输出目录（默认 seep-diagnose-<epoch>）
        #[arg(long)]
        output: Option<String>,
        /// 不对配置做脱敏（默认会脱敏 token/password/private_key 等）
        #[arg(long)]
        no_redact: bool,
        /// 不采集本机快照（路由/DNS/接口等）
        #[arg(long)]
        no_local: bool,
    },
    /// Mesh data-plane mTLS 证书工具（生成 CA/节点证书）
    Mtls {
        #[command(subcommand)]
        command: MtlsCommand,
    },
}

#[derive(Subcommand)]
enum MtlsCommand {
    /// 生成一个新的 CA（自签）
    InitCa {
        /// 输出目录
        #[arg(long)]
        out_dir: String,
        /// CA 证书 CommonName
        #[arg(long, default_value = "seep-mesh-ca")]
        common_name: String,
        /// 证书有效期（天）
        #[arg(long, default_value_t = 3650)]
        valid_days: i64,
    },
    /// 用 CA 为节点签发证书（客户端/服务端都可用）
    Issue {
        /// 节点 ID（用于生成文件名与证书 CN）
        #[arg(long)]
        node_id: String,
        /// rustls 验证使用的 server_name（默认 seep；需出现在 SAN 里）
        #[arg(long, default_value = "seep")]
        server_name: String,
        /// CA 证书 PEM 路径（ca.cert.pem）
        #[arg(long)]
        ca_cert: String,
        /// CA 私钥 PEM 路径（ca.key.pem）
        #[arg(long)]
        ca_key: String,
        /// 输出目录
        #[arg(long)]
        out_dir: String,
        /// 证书有效期（天）
        #[arg(long, default_value_t = 365)]
        valid_days: i64,
    },
    /// 为节点生成新证书并原子替换（用于轮换；新连接自动生效）
    Rotate {
        /// 节点 ID（用于生成文件名与证书 CN）
        #[arg(long)]
        node_id: String,
        /// rustls 验证使用的 server_name（默认 seep；需出现在 SAN 里）
        #[arg(long, default_value = "seep")]
        server_name: String,
        /// CA 证书 PEM 路径（ca.cert.pem）
        #[arg(long)]
        ca_cert: String,
        /// CA 私钥 PEM 路径（ca.key.pem）
        #[arg(long)]
        ca_key: String,
        /// 输出目录
        #[arg(long)]
        out_dir: String,
        /// 不保留旧证书备份（默认会备份为 *.bak.<epoch>）
        #[arg(long)]
        no_backup: bool,
        /// 证书有效期（天）
        #[arg(long, default_value_t = 365)]
        valid_days: i64,
    },
    /// 生成 CA bundle（多个 CA cert PEM 拼接）
    BundleCa {
        /// 输入 CA 证书 PEM 路径（可多次传入）：--ca-cert ca1.pem --ca-cert ca2.pem
        #[arg(long = "ca-cert")]
        ca_certs: Vec<String>,
        /// 输出文件路径（如 ca.bundle.pem）
        #[arg(long)]
        out_path: String,
    },
    /// 生成新的 CA，并输出旧+新双信任 CA bundle（用于轮换窗口）
    RotateCa {
        /// 旧 CA 证书 PEM 路径（ca.cert.pem）
        #[arg(long)]
        old_ca_cert: String,
        /// 输出目录
        #[arg(long)]
        out_dir: String,
        /// 新 CA 证书 CommonName
        #[arg(long, default_value = "seep-mesh-ca-next")]
        common_name: String,
        /// 新 CA 证书有效期（天）
        #[arg(long, default_value_t = 3650)]
        valid_days: i64,
    },
    /// 管理撤销列表文件（按 node_id/CN）
    Revoke {
        #[command(subcommand)]
        command: RevokeCommand,
    },
}

#[derive(Subcommand)]
enum RevokeCommand {
    /// 列出撤销列表（逐行 node_id；忽略空行/#注释；支持逗号分隔）
    List {
        /// 撤销列表文件路径（推荐配合 SEEP_MESH_MTLS_REVOKED_NODES_FILE）
        #[arg(long)]
        file: String,
    },
    /// 添加一个 node_id 到撤销列表
    Add {
        /// 撤销列表文件路径
        #[arg(long)]
        file: String,
        /// 节点 ID（证书 CN）
        #[arg(long)]
        node_id: String,
    },
    /// 从撤销列表移除一个 node_id
    Remove {
        /// 撤销列表文件路径
        #[arg(long)]
        file: String,
        /// 节点 ID（证书 CN）
        #[arg(long)]
        node_id: String,
    },
    /// 查询运行节点的撤销生效面（GET 控制面 /mtls/revoked；分发—生效—校验闭环的「生效」观测）
    Status {
        /// 控制面 base URL，如 http://127.0.0.1:9090（缺省读 config.control.api_bind）
        #[arg(long)]
        endpoint: Option<String>,
    },
}

#[derive(Subcommand)]
enum ChainCommand {
    /// 链路 dry-run（预检）
    DryRun {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
    },
    /// 创建链路（或复用同一 session_id 的链路）
    Create {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
        /// 可选：指定会话ID（UUID）；不指定会自动生成
        #[arg(long)]
        session_id: Option<String>,
    },
    /// 获取链路详情
    Get { chain_id: String },
    /// 终止链路
    Terminate { chain_id: String },
    /// 获取链路统计
    Stats,
}

#[derive(Subcommand)]
enum SubscriptionCommand {
    /// 列出订阅
    List,
    /// 添加订阅
    Add {
        name: String,
        url: String,
        #[arg(long)]
        r#type: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        refresh_interval: Option<u64>,
        #[arg(long)]
        timeout: Option<u64>,
        /// 自定义请求头（可多次传入）：--header k=v
        #[arg(long = "header")]
        headers: Vec<String>,
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// 移除订阅
    Remove { name: String },
    /// 刷新订阅（并尝试合并到 runtime）
    Refresh {
        /// 不指定则刷新全部
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum RouteCommand {
    /// 应用路由规则（幂等重放配置中的 include 目标）
    Apply {
        /// 仅打印计划执行的 ip 命令，不实际执行
        #[arg(long)]
        dry_run: bool,
    },
    /// 撤销所有已应用的路由规则（逆序清理）
    Clear,
    /// 查看路由应用状态（设备态 + 已应用步骤表）
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check => {
            SeepConfig::load_from_path(&cli.config)?;
            println!("配置有效");
        }
        Command::Show => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            println!("控制平面监听: {}", config.control.api_bind);
            println!("入口数量: {}", config.ingress.len());
            println!("出口数量: {}", config.egress.len());
        }
        Command::Stats { endpoint } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let target =
                endpoint.unwrap_or_else(|| format!("http://{}/flows", config.control.api_bind));
            // P0-5 §3.2：UDP 段与 /flows 同 base 推导（--endpoint 覆盖仅作用于 /flows 一侧）
            let base = url_base(&target);
            let client = Client::new();
            let mut req = client.get(&target);
            if let Some(token) = &config.control.admin_token {
                req = req.header("x-admin-token", token);
            }
            let resp = req.send().with_context(|| format!("无法访问 {target}"))?;
            if !resp.status().is_success() {
                anyhow::bail!("控制面返回错误: {}", resp.status());
            }
            let stats: Vec<FlowStatItem> = resp.json().context("解析控制面返回数据失败")?;
            if stats.is_empty() {
                println!("暂无流量数据");
            } else {
                println!("Ingress -> Egress 流量统计：");
                for item in stats {
                    println!(
                        "{} -> {} | flows={} upstream={}B downstream={}B",
                        item.ingress, item.egress, item.flows, item.upstream, item.downstream
                    );
                }
            }
            // P0-5 §3.2/§9-2：追加 UDP 段（/udp/stats 不可达/404 → 占位行，不视为失败）
            println!();
            match fetch_udp_stats(&client, config.control.admin_token.as_deref(), &base) {
                Some(udp) => print!("{}", render_udp_section(&udp)),
                None => println!("UDP:\n  (控制面无 UDP 段)"),
            }
        }
        Command::Group { endpoint } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let target = endpoint
                .unwrap_or_else(|| format!("http://{}/routing/stats", config.control.api_bind));
            let client = Client::new();
            let mut req = client.get(&target);
            if let Some(token) = &config.control.admin_token {
                req = req.header("x-admin-token", token);
            }
            let resp = req.send().with_context(|| format!("无法访问 {target}"))?;
            if !resp.status().is_success() {
                anyhow::bail!("控制面返回错误: {}", resp.status());
            }
            let stats: RoutingStatsResponse =
                resp.json().context("解析控制面返回数据失败")?;
            print!("{}", render_routing_stats(&stats.groups));
        }
        Command::Switches { endpoint } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let target = endpoint
                .unwrap_or_else(|| format!("http://{}/mesh/switches", config.control.api_bind));
            let client = Client::new();
            let mut req = client.get(&target);
            if let Some(token) = &config.control.admin_token {
                req = req.header("x-admin-token", token);
            }
            let resp = req.send().with_context(|| format!("无法访问 {target}"))?;
            if !resp.status().is_success() {
                anyhow::bail!("控制面返回错误: {}", resp.status());
            }
            let stats: MeshSwitchesResponse =
                resp.json().context("解析控制面返回数据失败")?;
            print!("{}", render_switches(&stats.events));
        }
        Command::UdpProbe {
            socks5,
            host,
            port,
            payload_hex,
            timeout,
            user,
            pass,
        } => {
            let payload = decode_hex(&payload_hex)?;
            if payload.is_empty() {
                anyhow::bail!("--payload-hex 不能为空");
            }
            let timeout = parse_duration_arg(&timeout)?;
            let auth = match (user, pass) {
                (Some(u), Some(p)) => Some((u, p)),
                (None, None) => None,
                _ => anyhow::bail!("--user 与 --pass 需成对提供"),
            };
            let rt = tokio::runtime::Runtime::new().context("无法启动 tokio 运行时")?;
            let auth_ref = auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            let outcome = rt.block_on(udp_probe::run(
                &socks5, &host, port, &payload, timeout, auth_ref,
            ));
            match outcome {
                Ok(ok) => {
                    println!(
                        "udp-probe 往返成功: source={} payload_len={} rtt={:?}",
                        ok.source, ok.payload_len, ok.rtt
                    );
                }
                Err(e) => {
                    eprintln!("udp-probe 失败（退出码 {}）: {}", e.exit_code(), e.detail());
                    std::process::exit(e.exit_code());
                }
            }
        }
        Command::Nodes { endpoint } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let target =
                endpoint.unwrap_or_else(|| format!("http://{}/nodes", config.control.api_bind));
            let client = Client::new();
            let mut req = client.get(&target);
            if let Some(token) = &config.control.admin_token {
                req = req.header("x-admin-token", token);
            }
            let resp = req.send().with_context(|| format!("无法访问 {target}"))?;
            if !resp.status().is_success() {
                anyhow::bail!("控制面返回错误: {}", resp.status());
            }
            let nodes: Vec<MeshNode> = resp.json().context("解析控制面返回数据失败")?;
            if nodes.is_empty() {
                println!("暂无节点信息");
            } else {
                println!("已注册节点：");
                for node in nodes {
                    println!(
                        "{} [{}] {} bw={:?} country={:?} isp={:?} tags={:?} online={} last_seen={}s",
                        node.id,
                        node.role,
                        node.addr,
                        node.capability.bandwidth_mbps,
                        node.capability.country,
                        node.capability.isp,
                        node.capability.tags,
                        node.online,
                        node.last_seen_seconds
                    );
                }
            }
        }
        Command::ImportClash { source, output } => {
            let raw = if source.starts_with("http://") || source.starts_with("https://") {
                reqwest::blocking::get(&source)
                    .with_context(|| format!("无法下载订阅 {source}"))?
                    .text()
                    .context("解析订阅内容失败")?
            } else {
                fs::read_to_string(&source).with_context(|| format!("无法读取文件 {source}"))?
            };

            let converter = ClashConverter::new().with_filtering(true);
            let clash = converter.parse(&raw).context("无法解析 Clash YAML")?;
            println!(
                "Clash 订阅解析完成: proxies={}, proxy-groups={}, rules={}",
                clash.proxies.len(),
                clash.proxy_groups.len(),
                clash.rules.len()
            );

            let mut converted = converter
                .convert_to_seep(&clash)
                .context("Clash 转换失败")?;
            converted.ingress = vec![build_ingress_from_clash(&clash)];

            // external-controller -> control.api_bind
            if let Some(external) = clash.external_controller.clone() {
                // external-controller sometimes contains a full URL; keep only the host:port part.
                let bind = external
                    .trim()
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_end_matches('/')
                    .to_string();
                if !bind.is_empty() {
                    converted.control.api_bind = bind;
                }
            }

            if converted.egress.is_empty() {
                converted.egress.push(EgressDescriptor {
                    name: "direct-main".into(),
                    spec: EgressConfig::Direct,
                });
                converted.routing.default_node = "direct-main".into();
            }

            let rendered = serde_yaml::to_string(&converted)?;
            fs::write(&output, rendered)?;
            println!("已转换为 Seep 配置并保存至 {output}");
        }
        Command::ExportClash { source, output } => {
            let config = SeepConfig::load_from_path(&source)
                .with_context(|| format!("无法读取 Seep 配置 {source}"))?;
            let (yaml, report) = ClashExporter.export(&config).context("Clash 回导出失败")?;
            fs::write(&output, &yaml)?;
            println!(
                "回导出完成: proxies={}, proxy-groups={}, rules={}（含 MATCH），输出 {output}",
                report.exported_proxies.len(),
                report.exported_groups.len(),
                report.exported_rules
            );
            if !report.skipped.is_empty() {
                println!("降级/跳过 {} 条:", report.skipped.len());
                for s in &report.skipped {
                    println!("  - {s}");
                }
            }
        }
        Command::Chain { endpoint, command } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));
            let client = Client::new();

            let token = config.control.admin_token.clone();
            let with_auth = |req: reqwest::blocking::RequestBuilder| {
                if let Some(t) = &token {
                    req.header("x-admin-token", t)
                } else {
                    req
                }
            };

            match command {
                ChainCommand::DryRun { source, target } => {
                    let url = format!("{base}/chains/dry-run");
                    let body = serde_json::json!({ "source": source, "target": target });
                    let resp = with_auth(client.post(&url).json(&body))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                ChainCommand::Create {
                    source,
                    target,
                    session_id,
                } => {
                    let url = format!("{base}/chains");
                    let mut obj = serde_json::Map::new();
                    obj.insert("source".into(), serde_json::Value::String(source));
                    obj.insert("target".into(), serde_json::Value::String(target));
                    if let Some(sid) = session_id {
                        obj.insert("session_id".into(), serde_json::Value::String(sid));
                    }
                    let resp = with_auth(client.post(&url).json(&obj))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                ChainCommand::Get { chain_id } => {
                    let url = format!("{base}/chains/{chain_id}");
                    let resp = with_auth(client.get(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                ChainCommand::Terminate { chain_id } => {
                    let url = format!("{base}/chains/{chain_id}");
                    let resp = with_auth(client.delete(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                ChainCommand::Stats => {
                    let url = format!("{base}/chains/stats");
                    let resp = with_auth(client.get(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
            }
        }
        Command::Subscription { endpoint, command } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));
            let client = Client::new();

            let token = config.control.admin_token.clone();
            let with_auth = |req: reqwest::blocking::RequestBuilder| {
                if let Some(t) = &token {
                    req.header("x-admin-token", t)
                } else {
                    req
                }
            };

            match command {
                SubscriptionCommand::List => {
                    let url = format!("{base}/subscriptions");
                    let resp = with_auth(client.get(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                SubscriptionCommand::Add {
                    name,
                    url: sub_url,
                    r#type,
                    enabled,
                    refresh_interval,
                    timeout,
                    headers,
                    user_agent,
                } => {
                    let url = format!("{base}/subscriptions");
                    let mut headers_map = serde_json::Map::new();
                    for kv in headers {
                        if let Some((k, v)) = kv.split_once('=') {
                            headers_map
                                .insert(k.to_string(), serde_json::Value::String(v.to_string()));
                        }
                    }
                    let body = serde_json::json!({
                        "name": name,
                        "url": sub_url,
                        "type": r#type,
                        "enabled": enabled,
                        "refresh_interval": refresh_interval,
                        "timeout": timeout,
                        "headers": if headers_map.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(headers_map) },
                        "user_agent": user_agent,
                    });
                    let resp = with_auth(client.post(&url).json(&body))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                SubscriptionCommand::Remove { name } => {
                    let url = format!("{base}/subscriptions/{name}");
                    let resp = with_auth(client.delete(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                SubscriptionCommand::Refresh { name } => {
                    let url = match name.as_deref() {
                        Some(n) => format!("{base}/subscriptions/{n}/refresh"),
                        None => format!("{base}/subscriptions/refresh"),
                    };
                    let resp = with_auth(client.post(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
            }
        }
        Command::Route { endpoint, command } => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));
            let client = Client::new();

            let token = config.control.admin_token.clone();
            let with_auth = |req: reqwest::blocking::RequestBuilder| {
                if let Some(t) = &token {
                    req.header("x-admin-token", t)
                } else {
                    req
                }
            };

            match command {
                RouteCommand::Apply { dry_run } => {
                    let url = format!("{base}/network/route/apply");
                    let body = serde_json::json!({ "dry_run": dry_run });
                    let resp = with_auth(client.post(&url).json(&body))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    let status = resp.status();
                    if !status.is_success() {
                        let err_text = resp.text().unwrap_or_default();
                        anyhow::bail!("控制面返回错误: {} - {}", status, err_text);
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    let undo = step_argv_lines(v.get("rolled_back"));
                    if dry_run {
                        println!("plan:");
                        for line in step_argv_lines(v.get("planned")) {
                            println!("{line}");
                        }
                    } else {
                        println!("ok:");
                        for line in step_argv_lines(v.get("executed")) {
                            println!("{line}");
                        }
                        if !undo.is_empty() {
                            println!("undo:");
                            for line in undo {
                                println!("{line}");
                            }
                        }
                    }
                }
                RouteCommand::Clear => {
                    let url = format!("{base}/network/route/clear");
                    let resp = with_auth(client.post(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    let status = resp.status();
                    if !status.is_success() {
                        let err_text = resp.text().unwrap_or_default();
                        anyhow::bail!("控制面返回错误: {} - {}", status, err_text);
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    println!("undo:");
                    for line in step_argv_lines(v.get("undone")) {
                        println!("{line}");
                    }
                }
                RouteCommand::Status => {
                    let url = format!("{base}/network/route/status");
                    let resp = with_auth(client.get(&url))
                        .send()
                        .with_context(|| format!("无法访问 {url}"))?;
                    if !resp.status().is_success() {
                        anyhow::bail!("控制面返回错误: {}", resp.status());
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    print!("{}", render_route_status(&v));
                }
            }
        }
        Command::Diagnose {
            endpoint,
            output,
            no_redact,
            no_local,
        } => {
            let epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let out_dir = PathBuf::from(output.unwrap_or_else(|| format!("seep-diagnose-{epoch}")));
            fs::create_dir_all(&out_dir)
                .with_context(|| format!("无法创建输出目录: {}", out_dir.display()))?;

            let config = SeepConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));

            let token = config.control.admin_token.clone();
            let client = Client::new();

            let mut log = String::new();

            // Config (redacted by default).
            let raw_config = fs::read_to_string(&cli.config)
                .with_context(|| format!("无法读取 {}", cli.config))?;
            let rendered_config = if no_redact {
                raw_config
            } else {
                redact_config_by_extension(&raw_config, &cli.config)
            };
            fs::write(out_dir.join("config.redacted"), rendered_config)
                .context("写入 config.redacted 失败")?;

            if !no_local {
                collect_local_snapshots(&out_dir, &mut log);
            }

            fetch_text_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/health"),
                &out_dir.join("health.txt"),
                &mut log,
            );
            fetch_json_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/flows"),
                &out_dir.join("flows.json"),
                &mut log,
            );
            fetch_json_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/nodes"),
                &out_dir.join("nodes.json"),
                &mut log,
            );
            fetch_json_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/chains/stats"),
                &out_dir.join("chains_stats.json"),
                &mut log,
            );
            fetch_json_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/subscriptions"),
                &out_dir.join("subscriptions.json"),
                &mut log,
            );
            fetch_text_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/metrics"),
                &out_dir.join("metrics.txt"),
                &mut log,
            );
            fetch_json_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/runtime/stats"),
                &out_dir.join("runtime_stats.json"),
                &mut log,
            );
            fetch_json_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/runtime/config"),
                &out_dir.join("runtime_config.json"),
                &mut log,
            );
            fetch_text_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/events"),
                &out_dir.join("events.log"),
                &mut log,
            );
            fetch_text_snapshot(
                &client,
                token.as_deref(),
                &format!("{base}/logs?lines=2000"),
                &out_dir.join("logs.txt"),
                &mut log,
            );

            let mut files: Vec<&str> = vec![
                "config.redacted",
                "health.txt",
                "flows.json",
                "nodes.json",
                "chains_stats.json",
                "subscriptions.json",
                "metrics.txt",
                "runtime_stats.json",
                "runtime_config.json",
                "events.log",
                "logs.txt",
                "requests.log",
            ];
            if !no_local {
                files.splice(
                    1..1,
                    [
                        "local_system.txt",
                        "local_routes.txt",
                        "local_dns.txt",
                        "local_interfaces.txt",
                    ],
                );
            }

            let meta = serde_json::json!({
                "generated_at_epoch": epoch,
                "config_path": cli.config,
                "control_base": base,
                "redacted": !no_redact,
                "local_snapshots": !no_local,
                "files": files
            });
            fs::write(
                out_dir.join("meta.json"),
                serde_json::to_string_pretty(&meta)?,
            )
            .context("写入 meta.json 失败")?;
            fs::write(out_dir.join("requests.log"), log).context("写入 requests.log 失败")?;

            println!("诊断信息已生成: {}", out_dir.display());
        }
        Command::Mtls { command } => match command {
            MtlsCommand::InitCa {
                out_dir,
                common_name,
                valid_days,
            } => {
                let out_dir = PathBuf::from(out_dir);
                fs::create_dir_all(&out_dir)
                    .with_context(|| format!("无法创建输出目录: {}", out_dir.display()))?;
                let (cert_pem, key_pem) = generate_ca_pem(&common_name, valid_days)?;
                let cert_path = out_dir.join("ca.cert.pem");
                let key_path = out_dir.join("ca.key.pem");
                fs::write(&cert_path, cert_pem).context("写入 ca.cert.pem 失败")?;
                fs::write(&key_path, key_pem).context("写入 ca.key.pem 失败")?;
                println!("已生成 CA:");
                println!("  cert: {}", cert_path.display());
                println!("  key:  {}", key_path.display());
            }
            MtlsCommand::Issue {
                node_id,
                server_name,
                ca_cert,
                ca_key,
                out_dir,
                valid_days,
            } => {
                let ca_cert_pem = fs::read_to_string(&ca_cert)
                    .with_context(|| format!("无法读取 CA cert: {ca_cert}"))?;
                let ca_key_pem = fs::read_to_string(&ca_key)
                    .with_context(|| format!("无法读取 CA key: {ca_key}"))?;
                let out_dir = PathBuf::from(out_dir);
                fs::create_dir_all(&out_dir)
                    .with_context(|| format!("无法创建输出目录: {}", out_dir.display()))?;

                let (cert_pem, key_pem) = generate_node_pem(
                    &node_id,
                    &server_name,
                    &ca_cert_pem,
                    &ca_key_pem,
                    valid_days,
                )?;
                let cert_path = out_dir.join(format!("{node_id}.cert.pem"));
                let key_path = out_dir.join(format!("{node_id}.key.pem"));
                fs::write(&cert_path, cert_pem).context("写入 node cert 失败")?;
                fs::write(&key_path, key_pem).context("写入 node key 失败")?;

                println!("已签发节点证书:");
                println!("  node_id: {node_id}");
                println!("  server_name: {server_name}");
                println!("  cert: {}", cert_path.display());
                println!("  key:  {}", key_path.display());
                println!();
                println!("示例环境变量（在运行 seepd 的环境中设置）：");
                println!("  export SEEP_MESH_MTLS=1");
                println!(
                    "  export SEEP_MESH_MTLS_CA={}",
                    PathBuf::from(ca_cert).display()
                );
                println!("  export SEEP_MESH_MTLS_CERT={}", cert_path.display());
                println!("  export SEEP_MESH_MTLS_KEY={}", key_path.display());
                println!("  export SEEP_MESH_MTLS_SERVER_NAME={server_name}");
            }
            MtlsCommand::Rotate {
                node_id,
                server_name,
                ca_cert,
                ca_key,
                out_dir,
                no_backup,
                valid_days,
            } => {
                let ca_cert_pem = fs::read_to_string(&ca_cert)
                    .with_context(|| format!("无法读取 CA cert: {ca_cert}"))?;
                let ca_key_pem = fs::read_to_string(&ca_key)
                    .with_context(|| format!("无法读取 CA key: {ca_key}"))?;
                let out_dir = PathBuf::from(out_dir);
                fs::create_dir_all(&out_dir)
                    .with_context(|| format!("无法创建输出目录: {}", out_dir.display()))?;

                let (cert_pem, key_pem) = generate_node_pem(
                    &node_id,
                    &server_name,
                    &ca_cert_pem,
                    &ca_key_pem,
                    valid_days,
                )?;

                let epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let cert_path = out_dir.join(format!("{node_id}.cert.pem"));
                let key_path = out_dir.join(format!("{node_id}.key.pem"));
                let cert_tmp = out_dir.join(format!("{node_id}.cert.pem.tmp.{epoch}"));
                let key_tmp = out_dir.join(format!("{node_id}.key.pem.tmp.{epoch}"));

                fs::write(&cert_tmp, cert_pem).context("写入临时 cert 失败")?;
                fs::write(&key_tmp, key_pem).context("写入临时 key 失败")?;

                if !no_backup {
                    let cert_bak = out_dir.join(format!("{node_id}.cert.pem.bak.{epoch}"));
                    let key_bak = out_dir.join(format!("{node_id}.key.pem.bak.{epoch}"));
                    if cert_path.exists() {
                        fs::rename(&cert_path, &cert_bak).ok();
                    }
                    if key_path.exists() {
                        fs::rename(&key_path, &key_bak).ok();
                    }
                }

                fs::rename(&cert_tmp, &cert_path).context("替换 cert 失败")?;
                fs::rename(&key_tmp, &key_path).context("替换 key 失败")?;

                println!("已轮换节点证书（原子替换完成）：");
                println!("  node_id: {node_id}");
                println!("  server_name: {server_name}");
                println!("  cert: {}", cert_path.display());
                println!("  key:  {}", key_path.display());
                if !no_backup {
                    println!("  backup: *.bak.{epoch}");
                }
                println!();
                println!("说明：seepd mesh mTLS 已支持自动 reload，新连接会使用新证书；已有连接不受影响。");
            }
            MtlsCommand::BundleCa { ca_certs, out_path } => {
                if ca_certs.is_empty() {
                    return Err(anyhow::anyhow!("至少需要提供一个 --ca-cert"));
                }
                let mut bundle = String::new();
                for (i, p) in ca_certs.iter().enumerate() {
                    let pem =
                        fs::read_to_string(p).with_context(|| format!("无法读取 CA cert: {p}"))?;
                    if i > 0 && !bundle.ends_with('\n') {
                        bundle.push('\n');
                    }
                    bundle.push_str(&pem);
                    if !bundle.ends_with('\n') {
                        bundle.push('\n');
                    }
                }
                let out_path = PathBuf::from(out_path);
                if let Some(parent) = out_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent).ok();
                    }
                }
                fs::write(&out_path, bundle)
                    .with_context(|| format!("写入失败: {}", out_path.display()))?;
                println!("已生成 CA bundle: {}", out_path.display());
            }
            MtlsCommand::RotateCa {
                old_ca_cert,
                out_dir,
                common_name,
                valid_days,
            } => {
                let old_pem = fs::read_to_string(&old_ca_cert)
                    .with_context(|| format!("无法读取旧 CA cert: {old_ca_cert}"))?;
                let out_dir = PathBuf::from(out_dir);
                fs::create_dir_all(&out_dir)
                    .with_context(|| format!("无法创建输出目录: {}", out_dir.display()))?;

                let (new_cert_pem, new_key_pem) = generate_ca_pem(&common_name, valid_days)?;
                let new_cert_path = out_dir.join("ca.next.cert.pem");
                let new_key_path = out_dir.join("ca.next.key.pem");
                fs::write(&new_cert_path, &new_cert_pem).context("写入 ca.next.cert.pem 失败")?;
                fs::write(&new_key_path, &new_key_pem).context("写入 ca.next.key.pem 失败")?;

                let mut bundle = String::new();
                bundle.push_str(&old_pem);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
                bundle.push_str(&new_cert_pem);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
                let bundle_path = out_dir.join("ca.bundle.pem");
                fs::write(&bundle_path, bundle).context("写入 ca.bundle.pem 失败")?;

                println!("已生成新 CA（用于轮换窗口）：");
                println!("  new_cert: {}", new_cert_path.display());
                println!("  new_key:  {}", new_key_path.display());
                println!("  bundle:   {}", bundle_path.display());
                println!();
                println!("建议流程：先把 ca.bundle.pem 下发到所有节点作为 SEEP_MESH_MTLS_CA，完成双信任窗口；再逐个轮换节点证书到新 CA；最后移除旧 CA。");
            }
            MtlsCommand::Revoke { command } => match command {
                RevokeCommand::List { file } => {
                    let path = PathBuf::from(file);
                    let items = read_revoked_list(&path)?;
                    for v in items {
                        println!("{v}");
                    }
                }
                RevokeCommand::Add { file, node_id } => {
                    let path = PathBuf::from(file);
                    let mut items = read_revoked_list(&path).unwrap_or_default();
                    if !items.iter().any(|v| v == &node_id) {
                        items.push(node_id);
                        items.sort();
                        items.dedup();
                    }
                    write_revoked_list_atomic(&path, &items)?;
                    println!("已更新撤销列表: {}", path.display());
                }
                RevokeCommand::Remove { file, node_id } => {
                    let path = PathBuf::from(file);
                    let mut items = read_revoked_list(&path).unwrap_or_default();
                    items.retain(|v| v != &node_id);
                    items.sort();
                    items.dedup();
                    write_revoked_list_atomic(&path, &items)?;
                    println!("已更新撤销列表: {}", path.display());
                }
                RevokeCommand::Status { endpoint } => {
                    let config = SeepConfig::load_from_path(&cli.config)?;
                    let base =
                        endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));
                    let url = format!("{base}/mtls/revoked");
                    let mut req = Client::new().get(&url);
                    if let Some(t) = &config.control.admin_token {
                        req = req.header("x-admin-token", t);
                    }
                    let resp = req.send().with_context(|| format!("无法访问 {url}"))?;
                    let status = resp.status();
                    if !status.is_success() {
                        let err_text = resp.text().unwrap_or_default();
                        anyhow::bail!("控制面返回错误: {} - {}", status, err_text);
                    }
                    let v: serde_json::Value = resp.json().context("解析控制面返回数据失败")?;
                    print!("{}", render_mtls_revoked(&v));
                }
            },
        },
    }
    Ok(())
}

fn read_revoked_list(path: &PathBuf) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("无法读取撤销列表: {}", path.display()))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for part in line.split(',') {
            let v = part.trim();
            if !v.is_empty() {
                out.push(v.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn write_revoked_list_atomic(path: &PathBuf, items: &[String]) -> Result<()> {
    let mut body = String::new();
    for v in items {
        body.push_str(v);
        body.push('\n');
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("无法创建目录: {}", parent.display()))?;
        }
    }
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tmp = path.with_extension(format!("tmp.{epoch}"));
    fs::write(&tmp, body).with_context(|| format!("写入临时文件失败: {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("替换撤销列表失败: {}", path.display()))?;
    Ok(())
}

fn generate_ca_pem(common_name: &str, valid_days: i64) -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let now = OffsetDateTime::now_utc();
    let skew = TimeDuration::hours(24);
    params.not_before = now - skew;
    params.not_after = now + TimeDuration::days(valid_days.max(1));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    Ok((cert_pem, key_pem))
}

fn generate_node_pem(
    node_id: &str,
    server_name: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    valid_days: i64,
) -> Result<(String, String)> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca = ca_params.self_signed(&ca_key)?;

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![server_name.to_string()])?;
    let now = OffsetDateTime::now_utc();
    let skew = TimeDuration::hours(24);
    params.not_before = now - skew;
    params.not_after = now + TimeDuration::days(valid_days.max(1));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, node_id);
    params.distinguished_name = dn;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let cert = params.signed_by(&key, &ca, &ca_key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    Ok((cert_pem, key_pem))
}

fn fetch_json_snapshot(
    client: &Client,
    token: Option<&str>,
    url: &str,
    out_path: &std::path::Path,
    log: &mut String,
) {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header("x-admin-token", t);
    }

    match req.send() {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>() {
            Ok(v) => {
                let body = serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string());
                match fs::write(out_path, body) {
                    Ok(()) => log.push_str(&format!(
                        "{}: ok\n",
                        out_path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("json")
                    )),
                    Err(e) => log.push_str(&format!(
                        "{}: write failed: {e}\n",
                        out_path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("json")
                    )),
                }
            }
            Err(e) => log.push_str(&format!(
                "{}: json parse failed: {e}\n",
                out_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("json")
            )),
        },
        Ok(r) => log.push_str(&format!(
            "{}: http {} ({url})\n",
            out_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("json"),
            r.status().as_u16()
        )),
        Err(e) => log.push_str(&format!(
            "{}: request failed: {e}\n",
            out_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("json")
        )),
    }
}

fn fetch_text_snapshot(
    client: &Client,
    token: Option<&str>,
    url: &str,
    out_path: &std::path::Path,
    log: &mut String,
) {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header("x-admin-token", t);
    }

    match req.send() {
        Ok(r) if r.status().is_success() => match r.text() {
            Ok(t) => match fs::write(out_path, t) {
                Ok(()) => log.push_str(&format!(
                    "{}: ok\n",
                    out_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("text")
                )),
                Err(e) => log.push_str(&format!(
                    "{}: write failed: {e}\n",
                    out_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("text")
                )),
            },
            Err(e) => log.push_str(&format!(
                "{}: read failed: {e}\n",
                out_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("text")
            )),
        },
        Ok(r) => log.push_str(&format!(
            "{}: http {} ({url})\n",
            out_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("text"),
            r.status().as_u16()
        )),
        Err(e) => log.push_str(&format!(
            "{}: request failed: {e}\n",
            out_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("text")
        )),
    }
}

fn collect_local_snapshots(out_dir: &std::path::Path, log: &mut String) {
    write_cmd_snapshot_candidates(
        out_dir,
        "local_system.txt",
        &[("/usr/bin/uname", &["-a"][..]), ("uname", &["-a"][..])],
        log,
    );

    write_cmd_snapshot_candidates(
        out_dir,
        "local_routes.txt",
        &[
            // macOS / BSD
            ("/usr/sbin/netstat", &["-rn"][..]),
            ("netstat", &["-rn"][..]),
            // Linux
            ("/sbin/ip", &["route"][..]),
            ("ip", &["route"][..]),
            // Windows
            ("route", &["print"][..]),
        ],
        log,
    );

    write_cmd_snapshot_candidates(
        out_dir,
        "local_dns.txt",
        &[
            // macOS
            ("/usr/sbin/scutil", &["--dns"][..]),
            ("scutil", &["--dns"][..]),
            // Linux
            ("resolvectl", &["status"][..]),
            ("/bin/cat", &["/etc/resolv.conf"][..]),
            ("cat", &["/etc/resolv.conf"][..]),
            // Windows
            ("ipconfig", &["/all"][..]),
        ],
        log,
    );

    write_cmd_snapshot_candidates(
        out_dir,
        "local_interfaces.txt",
        &[
            // macOS / BSD
            ("/sbin/ifconfig", &[][..]),
            ("ifconfig", &[][..]),
            // Linux
            ("/sbin/ip", &["addr"][..]),
            ("ip", &["addr"][..]),
            // Windows
            ("ipconfig", &[][..]),
        ],
        log,
    );
}

fn write_cmd_snapshot_candidates(
    out_dir: &std::path::Path,
    file_name: &str,
    candidates: &[(&str, &[&str])],
    log: &mut String,
) {
    use std::process::Command;
    let out_path = out_dir.join(file_name);

    let mut last_err: Option<String> = None;
    let mut rendered: Option<String> = None;

    for &(bin, args) in candidates {
        match Command::new(bin).args(args).output() {
            Ok(o) => {
                let mut s = String::new();
                s.push_str(&format!("cmd: {} {}\n", bin, args.join(" ")));
                s.push_str(&format!("status: {}\n\n", o.status));
                if !o.stdout.is_empty() {
                    s.push_str("stdout:\n");
                    s.push_str(&String::from_utf8_lossy(&o.stdout));
                    if !s.ends_with('\n') {
                        s.push('\n');
                    }
                    s.push('\n');
                }
                if !o.stderr.is_empty() {
                    s.push_str("stderr:\n");
                    s.push_str(&String::from_utf8_lossy(&o.stderr));
                    if !s.ends_with('\n') {
                        s.push('\n');
                    }
                }
                rendered = Some(s);
                break;
            }
            Err(e) => {
                last_err = Some(format!("cmd: {} {}\nerror: {e}\n", bin, args.join(" ")));
                continue;
            }
        }
    }

    let rendered = rendered
        .or(last_err)
        .unwrap_or_else(|| "no candidates\n".to_string());

    match fs::write(&out_path, rendered) {
        Ok(()) => log.push_str(&format!("{file_name}: ok\n")),
        Err(e) => log.push_str(&format!("{file_name}: write failed: {e}\n")),
    }
}

fn redact_config_by_extension(raw: &str, path: &str) -> String {
    let ext = PathBuf::from(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "yaml" || ext == "yml" {
        let v: Result<serde_yaml::Value> = serde_yaml::from_str(raw).map_err(Into::into);
        if let Ok(mut v) = v {
            redact_yaml_value(&mut v);
            return serde_yaml::to_string(&v).unwrap_or_else(|_| raw.to_string());
        }
    }
    if ext == "json" {
        let v: Result<serde_json::Value> = serde_json::from_str(raw).map_err(Into::into);
        if let Ok(mut v) = v {
            redact_json_value(&mut v);
            return serde_json::to_string_pretty(&v).unwrap_or_else(|_| raw.to_string());
        }
    }
    raw.to_string()
}

fn is_secret_key(key: &str) -> bool {
    matches!(
        key,
        "admin_token"
            | "password"
            | "private_key"
            | "preshared_key"
            | "token"
            | "access_token"
            | "refresh_token"
    )
}

fn redact_yaml_value(v: &mut serde_yaml::Value) {
    match v {
        serde_yaml::Value::Mapping(map) => {
            for (k, vv) in map.iter_mut() {
                if let serde_yaml::Value::String(key) = k {
                    if is_secret_key(key) {
                        *vv = serde_yaml::Value::String("REDACTED".to_string());
                        continue;
                    }
                }
                redact_yaml_value(vv);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for vv in seq.iter_mut() {
                redact_yaml_value(vv);
            }
        }
        _ => {}
    }
}

fn redact_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map.iter_mut() {
                if is_secret_key(k) {
                    *vv = serde_json::Value::String("REDACTED".to_string());
                    continue;
                }
                redact_json_value(vv);
            }
        }
        serde_json::Value::Array(arr) => {
            for vv in arr.iter_mut() {
                redact_json_value(vv);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Deserialize)]
struct FlowStatItem {
    ingress: String,
    egress: String,
    flows: u64,
    upstream: u64,
    downstream: u64,
}

#[derive(Debug, Deserialize)]
struct MeshNode {
    id: String,
    role: String,
    addr: String,
    capability: CapabilityDto,
    online: bool,
    last_seen_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct CapabilityDto {
    bandwidth_mbps: Option<u32>,
    country: Option<String>,
    isp: Option<String>,
    tags: Vec<String>,
}

fn build_ingress_from_clash(clash: &seep_subscription::ClashConfig) -> IngressDescriptor {
    let port = clash.mixed_port.unwrap_or(7890);
    let bind_ip = if let Some(bind) = &clash.bind_address {
        bind.clone()
    } else if clash.allow_lan {
        "0.0.0.0".to_string()
    } else {
        "127.0.0.1".to_string()
    };

    IngressDescriptor {
        name: "mixed-in".into(),
        spec: IngressConfig::Mixed {
            bind: format!("{bind_ip}:{port}"),
            auth: None,
            udp_enabled: None,
            bearer_tokens: None,
        },
    }
}

// ---------- O-slo1：group 组实时质量 ----------

/// `/routing/stats` 响应（seepd `RoutingStatsDto` 的 seepctl 侧反序列化视图）
#[derive(Debug, Deserialize)]
struct RoutingStatsResponse {
    groups: Vec<RoutingGroupQuality>,
}

#[derive(Debug, Deserialize)]
struct RoutingGroupQuality {
    name: String,
    strategy: String,
    selected: Option<String>,
    members: Vec<RoutingMemberQuality>,
}

#[derive(Debug, Deserialize)]
struct RoutingMemberQuality {
    name: String,
    #[serde(default)]
    healthy: bool,
    source: String,
    #[serde(default)]
    p95_ms: Option<u64>,
    #[serde(default)]
    loss_ratio: Option<f64>,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    gate_pass: Option<bool>,
}

// ---------- O-link-obs2：switches 链路切换账本 ----------

/// `/mesh/switches` 响应（seepd `MeshSwitchesDto` 的 seepctl 侧反序列化视图）
#[derive(Debug, Deserialize)]
struct MeshSwitchesResponse {
    events: Vec<SwitchEventDto>,
}

#[derive(Debug, Deserialize)]
struct SwitchEventDto {
    chain_id: String,
    from_path: Vec<String>,
    to_path: Option<Vec<String>>,
    reason: String,
    detail: String,
    epoch_seconds: u64,
}

fn render_switches(events: &[SwitchEventDto]) -> String {
    if events.is_empty() {
        return "暂无链路切换记录\n".to_string();
    }
    let mut out = String::new();
    for ev in events {
        let from = ev.from_path.join(" -> ");
        let to = ev
            .to_path
            .as_ref()
            .map(|p| p.join(" -> "))
            .unwrap_or_else(|| "(terminate)".into());
        out.push_str(&format!(
            "[{}] {} {} -> {} | {} | {}\n",
            ev.epoch_seconds, ev.chain_id, from, to, ev.reason, ev.detail
        ));
    }
    out
}

fn render_routing_stats(groups: &[RoutingGroupQuality]) -> String {
    if groups.is_empty() {
        return "暂无路由组\n".to_string();
    }
    let mut out = String::new();
    for g in groups {
        match &g.selected {
            Some(sel) => out.push_str(&format!("组 {} [{}] 当前选点: {sel}\n", g.name, g.strategy)),
            None => out.push_str(&format!("组 {} [{}]\n", g.name, g.strategy)),
        }
        for m in &g.members {
            let p95 = m
                .p95_ms
                .map(|v| format!("{v}ms"))
                .unwrap_or_else(|| "-".into());
            let loss = m
                .loss_ratio
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "-".into());
            let score = m
                .score
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into());
            let gate = match m.gate_pass {
                Some(true) => "pass",
                Some(false) => "FAIL",
                None => "-",
            };
            let healthy = if m.healthy { "ok" } else { "down" };
            let mark = match &g.selected {
                Some(sel) if sel == &m.name => " *",
                _ => "",
            };
            out.push_str(&format!(
                "  {}{} | {} | {} | p95={} loss={} score={} gate={}\n",
                m.name, mark, m.source, healthy, p95, loss, score, gate
            ));
        }
    }
    out
}

// ---------- P0-5 §3.2/§9-2：stats UDP 段 ----------

/// `/udp/stats` 响应（§9-1 结构的 seepctl 侧反序列化视图；BTreeMap 固定序）
#[derive(Debug, Deserialize)]
struct UdpStatsDto {
    table: UdpTableDto,
    ingress: UdpIngressDto,
    mesh: Option<UdpMeshDto>,
    /// 旧 seepd 无该键 → None（§3.6 对拷容错）
    mesh_client: Option<UdpMeshClientDto>,
}

#[derive(Debug, Deserialize)]
struct UdpTableDto {
    sessions_active: u64,
    sessions_total: u64,
    mappings_active: i64,
    bytes_up: u64,
    bytes_down: u64,
    dropped: std::collections::BTreeMap<String, u64>,
    expired: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
struct UdpIngressDto {
    associates_active: i64,
    associates_total: u64,
    associate_rejected: u64,
    uplink_packets: u64,
    downlink_packets: u64,
}

#[derive(Debug, Deserialize)]
struct UdpMeshDto {
    forwarded_up: u64,
    forwarded_down: u64,
    flows_active: i64,
    unknown_flow: u64,
    /// P2-7 M1 §3.6：防重放窗口拒帧；旧 seepd 无该键 → 缺省 0
    #[serde(default)]
    replay_dropped: u64,
}

/// P2-7 M1 §3.6：client 桥计数（旧 seepd 无该键 → Option None；字段 default 容错）
#[derive(Debug, Deserialize)]
struct UdpMeshClientDto {
    dropped: u64,
    #[serde(default)]
    replay_dropped: u64,
}

/// GET {base}/udp/stats；不可达 / 非 2xx / 解析失败均返回 None（§3.2：
/// 对旧版 seepd 兼容，打印占位行且不视为失败）
fn fetch_udp_stats(client: &Client, token: Option<&str>, base: &str) -> Option<UdpStatsDto> {
    let mut req = client.get(format!("{base}/udp/stats"));
    if let Some(t) = token {
        req = req.header("x-admin-token", t);
    }
    let resp = req.send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<UdpStatsDto>().ok()
}

/// 从完整 URL 提取 scheme://host 部分（§3.2：UDP 段与 /flows 同 base 推导）
fn url_base(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("http", url),
    };
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host}")
}

// ---------- network-route.md §4：route 输出渲染（纯函数，§7.1 断言消费） ----------

/// step 数组 → 逐行 argv 表（两空格缩进、argv 空格连接；缺键/非数组 → 空表）
fn step_argv_lines(steps: Option<&serde_json::Value>) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(arr) = steps.and_then(|s| s.as_array()) {
        for step in arr {
            if let Some(argv) = step.get("argv").and_then(|a| a.as_array()) {
                lines.push(format!(
                    "  {}",
                    argv.iter()
                        .map(|v| v.as_str().unwrap_or(""))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
        }
    }
    lines
}

/// route status 渲染（§4：mode/device/mtu/up 四行设备态 + applied 逐行 argv 表；
/// 缺键容错——unknown/false 占位，与 §3 响应形状宽松对齐）
fn render_route_status(v: &serde_json::Value) -> String {
    let mut out = format!(
        "mode: {}\ndevice: {}\nmtu: {}\nup: {}\n",
        v.get("mode").and_then(|m| m.as_str()).unwrap_or("unknown"),
        v.get("device")
            .and_then(|d| d.as_str())
            .unwrap_or("unknown"),
        v.get("mtu")
            .and_then(|m| m.as_u64())
            .map_or("unknown".to_string(), |m| m.to_string()),
        v.get("up").and_then(|u| u.as_bool()).unwrap_or(false)
    );
    out.push_str("applied:\n");
    for line in step_argv_lines(v.get("applied")) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// P2-7 M0 §2.3：`mtls revoke status` 渲染（纯函数，测试直调）。
/// 形状：static 计数行 + file 状态行（null → 未配置占位）+ 逐条 revoked。
fn render_mtls_revoked(v: &serde_json::Value) -> String {
    let mut out = format!(
        "static: {}\n",
        v.get("static_count").and_then(|n| n.as_u64()).unwrap_or(0)
    );
    match v.get("file") {
        Some(f) if !f.is_null() => {
            let loaded = f.get("loaded").and_then(|b| b.as_bool()).unwrap_or(false);
            let error = f
                .get("error")
                .and_then(|e| e.as_str())
                .filter(|e| !e.is_empty())
                .unwrap_or("(无)");
            out.push_str(&format!(
                "file: {} (loaded={} mtime={} entries={} error={})\n",
                f.get("path").and_then(|p| p.as_str()).unwrap_or("unknown"),
                loaded,
                f.get("mtime_secs").and_then(|m| m.as_u64()).unwrap_or(0),
                f.get("count").and_then(|c| c.as_u64()).unwrap_or(0),
                error,
            ));
            if let Some(entries) = f.get("entries").and_then(|e| e.as_array()) {
                for e in entries {
                    if let Some(id) = e.as_str() {
                        out.push_str(&format!("  revoked: {id}\n"));
                    }
                }
            }
        }
        _ => out.push_str("file: (未配置 SEEP_MESH_MTLS_REVOKED_NODES_FILE)\n"),
    }
    out
}

/// §9-2 UDP 段渲染（纯函数，测试直调）。零值行照打（与 §6-2「序列不因开关
/// 消失」同口径，渲染侧无需分支）；dropped/expired 固定序只列非零 reason、
/// 全零打 `(none)`；mesh 未启用打占位（与零流量对象两态可区分）。
fn render_udp_section(s: &UdpStatsDto) -> String {
    let mut out = String::from("UDP:\n");
    push_udp_line(
        &mut out,
        "sessions",
        format!(
            "{} active / {} total (mappings {} active)",
            s.table.sessions_active, s.table.sessions_total, s.table.mappings_active
        ),
    );
    push_udp_line(
        &mut out,
        "relay",
        format!(
            "{} up / {} down ({} / {} packets)",
            format_bytes(s.table.bytes_up),
            format_bytes(s.table.bytes_down),
            s.ingress.uplink_packets,
            s.ingress.downlink_packets
        ),
    );
    push_udp_line(
        &mut out,
        "associates",
        format!(
            "{} active / {} total ({} rejected)",
            s.ingress.associates_active, s.ingress.associates_total, s.ingress.associate_rejected
        ),
    );
    push_udp_line(&mut out, "dropped", render_reason_map(&s.table.dropped));
    push_udp_line(&mut out, "expired", render_reason_map(&s.table.expired));
    match &s.mesh {
        Some(m) => push_udp_line(
            &mut out,
            "mesh",
            format!(
                "{} up / {} down (flows {}, unknown_flow {}, replay_dropped {})",
                m.forwarded_up, m.forwarded_down, m.flows_active, m.unknown_flow, m.replay_dropped
            ),
        ),
        None => push_udp_line(&mut out, "mesh", "(面未启用)".to_string()),
    }
    // P2-7 M1 §3.6：client 桥计数在装配时渲染（旧 seepd 无该键 → 不渲染）
    if let Some(mc) = &s.mesh_client {
        push_udp_line(
            &mut out,
            "mesh_client",
            format!(
                "{} dropped ({} replay_dropped)",
                mc.dropped, mc.replay_dropped
            ),
        );
    }
    out
}

fn push_udp_line(out: &mut String, label: &str, rest: String) {
    out.push_str(&format!("  {label:<12}{rest}\n"));
}

/// reason 键值渲染：固定序（BTreeMap）只列非零，全零 `(none)`
fn render_reason_map(m: &std::collections::BTreeMap<String, u64>) -> String {
    let parts: Vec<String> = m
        .iter()
        .filter(|(_, v)| **v != 0)
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if parts.is_empty() {
        "(none)".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// 最小 hex 解码（P0-5 §3.3 `--payload-hex`；不引入依赖，容忍空白）
fn decode_hex(raw: &str) -> Result<Vec<u8>> {
    let s: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("--payload-hex 长度须为偶数：{s}");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("无效 hex：{}", &s[i..i + 2]))
        })
        .collect()
}

/// 时长参数解析（支持 3 / 3s / 250ms / 2m；udp-probe `--timeout` 默认 3s）
fn parse_duration_arg(raw: &str) -> Result<Duration> {
    let t = raw.trim();
    let split = t.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num
        .parse()
        .with_context(|| format!("无法解析时长数字：{raw}"))?;
    let secs = match unit {
        "" | "s" => n,
        "ms" => n / 1000.0,
        "m" => n * 60.0,
        other => anyhow::bail!("不支持的时长单位 {other:?}（支持 s/ms/m）"),
    };
    Ok(Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §9-1 响应示例原文（数字为设计稿示意）
    const SAMPLE: &str = r#"{
      "table": {
        "sessions_active": 3, "sessions_total": 128, "mappings_active": 7,
        "reroutes": 2, "bytes_up": 1048576, "bytes_down": 2097152,
        "dropped": {"session_limit": 0, "mapping_limit": 0, "no_binding": 0,
                    "shutting_down": 0, "send_failed": 1, "downlink_full": 0},
        "expired": {"idle": 120, "lifetime": 0, "revoked": 1}
      },
      "ingress": {
        "associates_active": 3, "associates_total": 45, "associate_rejected": 2,
        "associate_errors": 0, "uplink_packets": 1024, "downlink_packets": 980,
        "frag_dropped": 0, "source_dropped": 0, "malformed_dropped": 0
      },
      "mesh": {
        "forwarded_up": 512, "forwarded_down": 480, "malformed": 0,
        "unknown_flow": 3, "evicted": 0, "flows_active": 4, "replay_dropped": 2
      },
      "mesh_client": {"dropped": 5, "replay_dropped": 1}
    }"#;

    /// §10-S5 测试 4：§9-1 JSON → §9-2 文本逐行断言（纯函数，零网络）
    #[test]
    fn stats_udp_section_render() {
        let stats: UdpStatsDto = serde_json::from_str(SAMPLE).unwrap();
        let rendered = render_udp_section(&stats);
        let expected = [
            "UDP:",
            "  sessions    3 active / 128 total (mappings 7 active)",
            "  relay       1.0 MiB up / 2.0 MiB down (1024 / 980 packets)",
            "  associates  3 active / 45 total (2 rejected)",
            "  dropped     send_failed=1",
            "  expired     idle=120 revoked=1",
            "  mesh        512 up / 480 down (flows 4, unknown_flow 3, replay_dropped 2)",
            "  mesh_client 5 dropped (1 replay_dropped)",
        ]
        .join("\n");
        assert_eq!(renderled(rendered), expected);
        // P2-7 M1 §3.6：装配态 mesh_client 渲染；旧 seepd 缺键 → 整段不渲染
        assert!(stats.mesh.is_some());
        assert!(stats.mesh_client.is_some());

        // 全零 + mesh null：零值行照打（§9-2 注记），reason 全零 (none)、面占位
        let zero: UdpStatsDto = serde_json::from_str(
            r#"{"table":{"sessions_active":0,"sessions_total":0,"mappings_active":0,
                "bytes_up":0,"bytes_down":0,
                "dropped":{"session_limit":0,"mapping_limit":0,"no_binding":0,
                           "shutting_down":0,"send_failed":0,"downlink_full":0},
                "expired":{"idle":0,"lifetime":0,"revoked":0}},
              "ingress":{"associates_active":0,"associates_total":0,"associate_rejected":0,
                "uplink_packets":0,"downlink_packets":0},
              "mesh":null}"#,
        )
        .unwrap();
        let r2 = render_udp_section(&zero);
        assert!(r2.contains("  sessions    0 active / 0 total (mappings 0 active)"));
        assert!(r2.contains("  relay       0 B up / 0 B down (0 / 0 packets)"));
        assert!(r2.contains("  dropped     (none)"));
        assert!(r2.contains("  expired     (none)"));
        assert!(r2.contains("  mesh        (面未启用)"));

        // 旧 seepd 对拷容错（§3.6）：mesh/mesh_client 缺 replay_dropped 键 → 缺省 0
        let legacy: UdpStatsDto = serde_json::from_str(
            r#"{"table":{"sessions_active":0,"sessions_total":0,"mappings_active":0,
                "bytes_up":0,"bytes_down":0,"dropped":{},"expired":{}},
              "ingress":{"associates_active":0,"associates_total":0,"associate_rejected":0,
                "uplink_packets":0,"downlink_packets":0},
              "mesh":{"forwarded_up":1,"forwarded_down":1,"flows_active":1,
                      "unknown_flow":0},
              "mesh_client":{"dropped":0}}"#,
        )
        .unwrap();
        assert_eq!(legacy.mesh.as_ref().unwrap().replay_dropped, 0);
        assert_eq!(legacy.mesh_client.as_ref().unwrap().replay_dropped, 0);
    }

    fn renderled(s: String) -> String {
        s.trim_end().to_string()
    }

    #[test]
    fn url_base_strips_path() {
        assert_eq!(
            url_base("http://127.0.0.1:9090/flows"),
            "http://127.0.0.1:9090"
        );
        assert_eq!(url_base("http://127.0.0.1:9090"), "http://127.0.0.1:9090");
        assert_eq!(url_base("127.0.0.1:9090/flows"), "http://127.0.0.1:9090");
    }

    /// network-route.md §7.1 CLI 组装断言（不真发）：route 三动作参数形状——
    /// --endpoint/--config 透传、apply --dry-run 开关、缺省 dry_run=false
    #[test]
    fn route_command_parse_shapes() {
        let cli = Cli::parse_from(["seepctl", "route", "status"]);
        assert!(matches!(
            &cli.command,
            Command::Route {
                endpoint: None,
                command: RouteCommand::Status
            }
        ));

        let cli = Cli::parse_from([
            "seepctl",
            "--config",
            "x.yaml",
            "route",
            "--endpoint",
            "http://127.0.0.1:9090",
            "apply",
            "--dry-run",
        ]);
        assert!(matches!(
            &cli.command,
            Command::Route {
                endpoint: Some(e),
                command: RouteCommand::Apply { dry_run: true },
            } if e == "http://127.0.0.1:9090"
        ));
        assert_eq!(cli.config, "x.yaml");

        let cli = Cli::parse_from(["seepctl", "route", "clear"]);
        assert!(matches!(
            &cli.command,
            Command::Route {
                endpoint: None,
                command: RouteCommand::Clear
            }
        ));

        // apply 缺省真执行（dry_run=false）
        let cli = Cli::parse_from(["seepctl", "route", "apply"]);
        assert!(matches!(
            &cli.command,
            Command::Route {
                endpoint: None,
                command: RouteCommand::Apply { dry_run: false }
            }
        ));
    }

    /// mesh-advanced-security.md §2.3/§4.3：mtls revoke status 参数形状——
    /// --endpoint 在子命令体内透传（顶层 mtls 无 endpoint）
    #[test]
    fn mtls_revoke_status_parse_shapes() {
        let cli = Cli::parse_from(["seepctl", "mtls", "revoke", "status"]);
        assert!(matches!(
            &cli.command,
            Command::Mtls {
                command: MtlsCommand::Revoke {
                    command: RevokeCommand::Status { endpoint: None }
                }
            }
        ));

        let cli = Cli::parse_from([
            "seepctl",
            "--config",
            "y.yaml",
            "mtls",
            "revoke",
            "status",
            "--endpoint",
            "http://127.0.0.1:9091",
        ]);
        assert!(matches!(
            &cli.command,
            Command::Mtls {
                command: MtlsCommand::Revoke {
                    command: RevokeCommand::Status {
                        endpoint: Some(e)
                    }
                }
            } if e == "http://127.0.0.1:9091"
        ));
        assert_eq!(cli.config, "y.yaml");
    }

    /// mesh-advanced-security.md §2.3/§4.3：`mtls revoke status` 输出格式——
    /// static 计数行 + file 状态行（loaded/mtime/entries/error）+ 逐条 revoked；
    /// file null → 未配置占位（缺键容错）
    #[test]
    fn mtls_revoke_status_render() {
        let v = serde_json::json!({
            "static_count": 2,
            "file": {
                "path": "/etc/seep/revoked.list",
                "loaded": true,
                "error": null,
                "mtime_secs": 1760000000,
                "count": 2,
                "entries": ["node-b", "node-c"]
            }
        });
        assert_eq!(
            renderled(render_mtls_revoked(&v)),
            [
                "static: 2",
                "file: /etc/seep/revoked.list (loaded=true mtime=1760000000 entries=2 error=(无))",
                "  revoked: node-b",
                "  revoked: node-c",
            ]
            .join("\n")
        );

        let v2 = serde_json::json!({ "static_count": 0, "file": null });
        let out = render_mtls_revoked(&v2);
        assert_eq!(
            out,
            "static: 0\nfile: (未配置 SEEP_MESH_MTLS_REVOKED_NODES_FILE)\n"
        );
    }

    /// network-route.md §4/§3 输出格式：argv 逐行表 + status 四行设备态 +
    /// 缺键容错（unknown/false 占位）
    #[test]
    fn route_render_steps_and_status() {
        let v = serde_json::json!({
            "planned": [{"argv": ["ip", "route", "replace", "203.0.113.0/24", "dev", "seep0", "metric", "0"], "at": 1760000000}],
            "executed": [],
            "rolled_back": [{"argv": ["ip", "addr", "del", "10.255.0.1/24", "dev", "seep0"]}]
        });
        assert_eq!(
            step_argv_lines(v.get("planned")),
            ["  ip route replace 203.0.113.0/24 dev seep0 metric 0"]
        );
        assert!(step_argv_lines(v.get("executed")).is_empty());
        assert_eq!(
            step_argv_lines(v.get("rolled_back")),
            ["  ip addr del 10.255.0.1/24 dev seep0"]
        );
        assert!(step_argv_lines(None).is_empty());

        let st = serde_json::json!({
            "mode": "tun", "device": "seep0", "mtu": 1400, "up": true,
            "applied": [{"argv": ["ip", "route", "replace", "203.0.113.0/24", "dev", "seep0", "metric", "0"], "at": 1760000000}]
        });
        let expected = [
            "mode: tun",
            "device: seep0",
            "mtu: 1400",
            "up: true",
            "applied:",
            "  ip route replace 203.0.113.0/24 dev seep0 metric 0",
        ]
        .join("\n");
        assert_eq!(render_route_status(&st).trim_end(), expected);

        let sparse: serde_json::Value = serde_json::json!({});
        let out = render_route_status(&sparse);
        assert!(out.contains("mode: unknown"));
        assert!(out.contains("device: unknown"));
        assert!(out.contains("mtu: unknown"));
        assert!(out.contains("up: false"));
    }

    #[test]
    fn duration_and_hex_helpers() {
        assert_eq!(parse_duration_arg("3s").unwrap(), Duration::from_secs(3));
        assert_eq!(
            parse_duration_arg("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(parse_duration_arg("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration_arg("5").unwrap(), Duration::from_secs(5));
        assert!(parse_duration_arg("3x").is_err());
        assert!(parse_duration_arg("s").is_err());

        assert_eq!(decode_hex("00ff 10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    /// O-slo1：`/routing/stats` 响应解析 + 渲染（选点标记/门判定/unknown 占位）
    #[test]
    fn routing_stats_parse_and_render() {
        let body = r#"{
          "groups": [
            {
              "name": "auto", "strategy": "latency", "selected": "real",
              "members": [
                {"name": "real", "healthy": true, "source": "real",
                 "p95_ms": 30, "loss_ratio": 0.0, "score": 30.0, "gate_pass": true},
                {"name": "violator", "healthy": true, "source": "real",
                 "p95_ms": 80, "loss_ratio": 0.02, "score": 100.0, "gate_pass": false},
                {"name": "ghost", "healthy": false, "source": "unknown",
                 "p95_ms": null, "loss_ratio": null, "score": null, "gate_pass": null}
              ]
            },
            {"name": "fixed-g", "strategy": "fixed", "selected": null,
             "members": [{"name": "x", "healthy": true, "source": "real",
                          "p95_ms": 70, "loss_ratio": 0.0, "score": null, "gate_pass": null}]}
          ]
        }"#;
        let resp: RoutingStatsResponse =
            serde_json::from_str(body).expect("routing stats 应可解析");
        assert_eq!(resp.groups.len(), 2);

        let out = render_routing_stats(&resp.groups);
        assert!(out.contains("组 auto [latency] 当前选点: real\n"), "{out}");
        assert!(out.contains("real * | real | ok | p95=30ms loss=0.0% score=30.0 gate=pass"));
        assert!(out.contains("violator | real | ok | p95=80ms loss=2.0% score=100.0 gate=FAIL"));
        assert!(out.contains("ghost | unknown | down | p95=- loss=- score=- gate=-"));
        // 非 latency 组无选点标记，raw 数据照常渲染
        assert!(out.contains("组 fixed-g [fixed]\n"));
        assert!(out.contains("x | real | ok | p95=70ms loss=0.0% score=- gate=-"));
    }

    #[test]
    fn routing_stats_render_empty() {
        assert_eq!(render_routing_stats(&[]), "暂无路由组\n");
    }

    /// O-link-obs2：`/mesh/switches` 响应解析 + 渲染（路径/原因/终止事件）
    #[test]
    fn switches_parse_and_render() {
        let body = r#"{
          "events": [
            {"chain_id": "c1", "from_path": ["client1", "relay1", "exit1"],
             "to_path": ["client1", "exit1"], "reason": "hop_failed",
             "detail": "read error", "epoch_seconds": 1750000000},
            {"chain_id": "c2", "from_path": ["client1", "exit2"],
             "to_path": null, "reason": "terminated", "detail": "manual",
             "epoch_seconds": 1750000001}
          ]
        }"#;
        let resp: MeshSwitchesResponse =
            serde_json::from_str(body).expect("switches 应可解析");
        assert_eq!(resp.events.len(), 2);

        let out = render_switches(&resp.events);
        assert!(out.contains(
            "[1750000000] c1 client1 -> relay1 -> exit1 -> client1 -> exit1 | hop_failed | read error"
        ));
        assert!(out.contains("[1750000001] c2 client1 -> exit2 -> (terminate) | terminated | manual"));
    }

    #[test]
    fn switches_render_empty() {
        assert_eq!(render_switches(&[]), "暂无链路切换记录\n");
    }
}
