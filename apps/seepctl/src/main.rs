use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use reqwest::blocking::Client;
use seep_config::{EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, SeepConfig};
use seep_subscription::ClashConverter;
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};

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
            udp_enabled: None,
        },
    }
}
