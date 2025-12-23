use std::fs;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use seep_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor,
    MatchCondition, PolicyGroup, GroupMember, RouteRule, RoutingConfig, SeepConfig, Strategy, TelemetryConfig,
};
use serde::Deserialize;

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
    /// 订阅管理（seepd 控制面）
    Subscription {
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: SubscriptionCommand,
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
    Get {
        chain_id: String,
    },
    /// 终止链路
    Terminate {
        chain_id: String,
    },
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
    Remove {
        name: String,
    },
    /// 刷新订阅（并尝试合并到 runtime）
    Refresh {
        /// 不指定则刷新全部
        name: Option<String>,
    },
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
            let client = Client::new();
            let mut req = client.get(&target);
            if let Some(token) = &config.control.admin_token {
                req = req.header("x-admin-token", token);
            }
            let resp = req
                .send()
                .with_context(|| format!("无法访问 {target}"))?;
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
            let resp = req
                .send()
                .with_context(|| format!("无法访问 {target}"))?;
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

            let doc: serde_yaml::Value =
                serde_yaml::from_str(&raw).context("无法解析 Clash YAML")?;
            let proxies = doc
                .get("proxies")
                .and_then(|v| v.as_sequence())
                .map(|seq| seq.len())
                .unwrap_or(0);
            let proxy_groups = doc
                .get("proxy-groups")
                .and_then(|v| v.as_sequence())
                .map(|seq| seq.len())
                .unwrap_or(0);
            let rules = doc
                .get("rules")
                .and_then(|v| v.as_sequence())
                .map(|seq| seq.len())
                .unwrap_or(0);

            println!(
                "Clash 订阅解析完成: proxies={proxies}, proxy-groups={proxy_groups}, rules={rules}"
            );
            let converted = clash_to_seep_config(&doc)?;
            let rendered = serde_yaml::to_string(&converted)?;
            fs::write(&output, rendered)?;
            println!("已转换为 Seep 配置并保存至 {output}");
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
                ChainCommand::Create { source, target, session_id } => {
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
                            headers_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
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
    }
    Ok(())
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

fn clash_to_seep_config(doc: &serde_yaml::Value) -> Result<SeepConfig> {
    let mut config = SeepConfig {
        control: ControlConfig {
            api_bind: "127.0.0.1:9090".into(),
            uds_path: None,
            admin_token: None,
        },
        telemetry: TelemetryConfig {
            log_level: "info".into(),
            enable_metrics: true,
            enable_tracing: false,
        },
        ingress: vec![IngressDescriptor {
            name: "socks-in".into(),
            spec: IngressConfig::Socks5 {
                bind: "0.0.0.0:7890".into(),
                auth: None,
            },
        }],
        egress: parse_clash_proxies(doc),
        routing: RoutingConfig {
            default_node: String::new(),
            groups: Vec::new(),
            rules: Vec::new(),
        },
    };

    if config.egress.is_empty() {
        config.egress.push(EgressDescriptor {
            name: "direct-main".into(),
            spec: EgressConfig::Direct,
        });
    }

    config.routing.default_node = config.egress[0].name.clone();
    config.routing.groups = vec![PolicyGroup {
        name: "auto".into(),
        strategy: Strategy::Fixed,
        members: config.egress.iter().map(|e| GroupMember::Node { name: e.name.clone() }).collect(),
    }];
    config.routing.rules = parse_clash_rules(doc);
    Ok(config)
}

fn parse_clash_proxies(doc: &serde_yaml::Value) -> Vec<EgressDescriptor> {
    let mut result = Vec::new();
    let proxies = doc
        .get("proxies")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();
    for proxy in proxies {
        let name = match proxy.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let proxy_type = proxy
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let spec = match proxy_type.as_str() {
            "direct" => Some(EgressConfig::Direct),
            "trojan" => {
                let (Some(server), Some(port), Some(password)) = (
                    proxy.get("server").and_then(|v| v.as_str()),
                    proxy.get("port").and_then(|v| v.as_i64()),
                    proxy.get("password").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                Some(EgressConfig::Trojan {
                    server: server.into(),
                    port: port as u16,
                    password: password.into(),
                    network: "tcp".into(),
                    path: None,
                    host: None,
                    tls: true,
                    skip_cert_verify: false,
                    sni: None,
                    alpn: None,
                })
            }
            "ss" | "shadowsocks" => {
                let (Some(server), Some(port), Some(password)) = (
                    proxy.get("server").and_then(|v| v.as_str()),
                    proxy.get("port").and_then(|v| v.as_i64()),
                    proxy.get("password").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let Some(method) = proxy
                    .get("cipher")
                    .or_else(|| proxy.get("method"))
                    .and_then(|v| v.as_str())
                else {
                    continue;
                };
                Some(EgressConfig::Shadowsocks {
                    server: server.into(),
                    port: port as u16,
                    method: method.into(),
                    password: password.into(),
                })
            }
            _ => None,
        };

        if let Some(spec) = spec {
            result.push(EgressDescriptor { name, spec });
        } else {
            println!("跳过暂不支持的代理类型: {}", proxy_type);
        }
    }
    result
}

fn parse_clash_rules(doc: &serde_yaml::Value) -> Vec<RouteRule> {
    let rules = doc
        .get("rules")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();
    let mut result = Vec::new();
    for (idx, rule) in rules.iter().enumerate() {
        if let Some(rule_str) = rule.as_str() {
            let parts: Vec<&str> = rule_str.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 3 {
                if let Some(condition) = convert_clash_match(parts[0], parts[1]) {
                    result.push(RouteRule {
                        name: format!("clash-rule-{idx}"),
                        matches: vec![condition],
                        target: parts[2].to_string(),
                    });
                }
            }
        }
    }
    result
}

fn convert_clash_match(kind: &str, value: &str) -> Option<MatchCondition> {
    match kind {
        "DOMAIN-SUFFIX" => Some(MatchCondition::DomainSuffix {
            values: vec![value.to_string()],
        }),
        "DOMAIN-KEYWORD" => Some(MatchCondition::DomainKeyword {
            values: vec![value.to_string()],
        }),
        "GEOIP" => Some(MatchCondition::Geoip {
            country: value.to_string(),
        }),
        "IP-CIDR" => Some(MatchCondition::Network {
            cidrs: vec![value.to_string()],
        }),
        _ => None,
    }
}
