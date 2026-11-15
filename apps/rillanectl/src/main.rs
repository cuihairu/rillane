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
use rillane_config::{
    EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig,
};
use rillane_core::redact::{RedactionScope, Redactor};
use rillane_subscription::{ClashConverter, ClashExporter};
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};

mod udp_probe;

#[derive(Parser)]
#[command(author, version, about = "Rillane 控制台", propagate_version = true)]
struct Cli {
    #[arg(short, long, default_value = "config/rillane.yaml")]
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
    /// 生成场景骨架配置（O-prof1：proxy|game|web 三选一即运行）
    Profile {
        /// 场景：proxy | game | web
        variant: String,
        /// 输出文件路径（缺省打印到 stdout）
        #[arg(long)]
        out: Option<String>,
    },
    /// TLS 指纹形态预设对照表（O-tfp1：各预设 shape_material 四维导出）
    TlsFingerprint,
    /// 批量导入 geosite/chnroutes 文本规则源（O-dns1：路由或 DNS 分流规则）
    ImportRules {
        /// 规则源：文件路径或 http(s) URL（v2fly 文本清单行集）
        source: String,
        /// routing 面：组/出口名；dns 面：domestic | trusted
        #[arg(long)]
        target: String,
        /// 目标面：routing | dns（缺省 routing）
        #[arg(long, default_value = "routing")]
        face: String,
        /// 规则名（缺省取源文件名去扩展名）
        #[arg(long)]
        name: Option<String>,
        /// 输出文件路径（缺省打印到 stdout）
        #[arg(long)]
        out: Option<String>,
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
    /// 出站连接池（O-pool3：P1-5 §6.2 端点的 CLI 取数面）
    Pool {
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: PoolCommand,
    },
    /// 从 Clash YAML 订阅转换为 Rillane 配置 (preview)
    ImportClash {
        /// 订阅 URL 或文件路径
        source: String,
        /// 输出目标文件
        #[arg(short, long, default_value = "config/clash_import.yaml")]
        output: String,
    },
    /// 将 Rillane 配置回导出为 Clash YAML（preview，离线转换）
    ExportClash {
        /// Rillane 配置文件路径
        source: String,
        /// 输出目标文件
        #[arg(short, long, default_value = "config/clash_export.yaml")]
        output: String,
    },
    /// 订阅管理（rillaned 控制面）
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
    /// 真实连接轨迹查询（Trace CLI，RIL-060；语法冻结：
    /// 退出码 0=成功 / 1=用法或连接错误 / 2=显式缺席）
    Trace {
        /// 控制面 base URL，如 http://127.0.0.1:9090
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: TraceCommand,
    },
    /// 主动探测作业（Probe CLI，RIL-061；语法冻结：
    /// 退出码 0=成功 / 1=用法或连接错误 / 2=显式缺席。
    /// 显式网络副作用——目标必须在服务端登记范围内）
    Probe {
        /// 控制面 base URL，如 http://127.0.0.1:9090
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        command: ProbeCommand,
    },
    /// 一键诊断信息收集（生成诊断目录，按范围选择快照/日志/配置）
    Diagnose {
        /// 控制面 base URL，如 http://127.0.0.1:9090
        #[arg(long)]
        endpoint: Option<String>,
        /// 输出目录（默认 rillane-diagnose-<epoch>）
        #[arg(long)]
        output: Option<String>,
        /// 包范围：safe（默认——不含订阅/运行配置/完整日志）/ full
        /// （全快照，秘密仍剥除）/ raw（不脱敏——仅供本地人工排查，
        /// 清单标注严禁直接上传 AI）
        #[arg(long, default_value = "safe")]
        scope: String,
        /// 不对配置做脱敏（等价 --scope raw）
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

/// Trace CLI 子命令（RIL-060，语法冻结——文本/版本化 JSON 双形态）
#[derive(Subcommand)]
enum TraceCommand {
    /// 活动/近期连接分页列表
    List {
        /// 按状态过滤：active|closed
        #[arg(long)]
        state: Option<String>,
        /// 按起止语义过滤：stream|association
        #[arg(long)]
        origin: Option<String>,
        /// 按计划代际过滤
        #[arg(long)]
        generation: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// 输出版本化 JSON（schema_version=1 信封原样）
        #[arg(long)]
        json: bool,
    },
    /// 单流详情（完整轨迹或显式缺席答复——缺席退出码 2）
    Flow {
        /// 真实 flow ID（聚合键不在此面）
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// 事件增量读取（from_seq 起至多 limit 条）
    Events {
        /// 真实 flow ID
        id: String,
        #[arg(long, default_value_t = 0)]
        from_seq: u64,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

/// Probe CLI 子命令（RIL-061，语法冻结——文本/版本化 JSON 双形态）。
/// id 用 String 手工解析：clap 参数错误退出码会顶掉冻结的缺席码 2。
#[derive(Subcommand)]
enum ProbeCommand {
    /// 显式发起探测作业（目标必须在服务端 probe.targets 登记范围内）
    Submit {
        /// 目标类型：dns | connect | udp-echo
        #[arg(long)]
        kind: String,
        /// dns 目标域名（kind=dns 必填）
        #[arg(long)]
        host: Option<String>,
        /// connect / udp-echo 目标地址 ip:port（对应 kind 必填）
        #[arg(long)]
        addr: Option<String>,
        /// udp-echo 载荷字节数（默认 64；服务端按上限拒绝超额）
        #[arg(long, default_value_t = 64)]
        payload_len: usize,
        /// 输出版本化 JSON（schema_version=1 信封原样）
        #[arg(long)]
        json: bool,
    },
    /// 取消作业（排队中 → 立即终态；运行中 → 协作取消请求）
    Cancel {
        /// 作业 ID（probe submit 返回的 job_id）
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// 查询单个作业结果（未知 ID → 显式缺席，退出码 2）
    Result {
        /// 作业 ID
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// 作业列表（限额与快照一屏可见）
    List {
        #[arg(long)]
        json: bool,
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
        #[arg(long, default_value = "rillane-mesh-ca")]
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
        /// rustls 验证使用的 server_name（默认 rillane；需出现在 SAN 里）
        #[arg(long, default_value = "rillane")]
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
        /// rustls 验证使用的 server_name（默认 rillane；需出现在 SAN 里）
        #[arg(long, default_value = "rillane")]
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
        #[arg(long, default_value = "rillane-mesh-ca-next")]
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
        /// 撤销列表文件路径（推荐配合 RILLANE_MESH_MTLS_REVOKED_NODES_FILE）
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

/// 出站连接池子命令（O-pool3）
#[derive(Subcommand)]
enum PoolCommand {
    /// 池快照：开关/TLS 复会话/复用率/计数族/每键 idle
    Status,
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
            RillaneConfig::load_from_path(&cli.config)?;
            println!("配置有效");
        }
        Command::Show => {
            let config = RillaneConfig::load_from_path(&cli.config)?;
            println!("控制平面监听: {}", config.control.api_bind);
            println!("入口数量: {}", config.ingress.len());
            println!("出口数量: {}", config.egress.len());
        }
        Command::Stats { endpoint } => {
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
            let stats: RoutingStatsResponse = resp.json().context("解析控制面返回数据失败")?;
            print!("{}", render_routing_stats(&stats.groups));
        }
        Command::Switches { endpoint } => {
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
            let stats: MeshSwitchesResponse = resp.json().context("解析控制面返回数据失败")?;
            print!("{}", render_switches(&stats.events));
        }
        Command::Pool { endpoint, command } => {
            let config = RillaneConfig::load_from_path(&cli.config)?;
            let target = endpoint
                .unwrap_or_else(|| format!("http://{}/egress/pool/stats", config.control.api_bind));
            let client = Client::new();
            let mut req = client.get(&target);
            if let Some(token) = &config.control.admin_token {
                req = req.header("x-admin-token", token);
            }
            let resp = req.send().with_context(|| format!("无法访问 {target}"))?;
            if !resp.status().is_success() {
                anyhow::bail!("控制面返回错误: {}", resp.status());
            }
            let stats: EgressPoolStatsResponse = resp.json().context("解析控制面返回数据失败")?;
            match command {
                PoolCommand::Status => print!("{}", render_pool_status(&stats)),
            }
        }
        Command::Profile { variant, out } => {
            let variant = parse_profile_variant(&variant)?;
            let cfg = scenario_skeleton(&variant)?;
            let yaml = serde_yaml::to_string(&cfg).context("场景骨架序列化失败")?;
            match out {
                Some(path) => {
                    fs::write(&path, yaml).with_context(|| format!("写入 {path} 失败"))?;
                    println!("已写入 {path}（RILLANE_CONFIG={path} rillaned）");
                }
                None => print!("{yaml}"),
            }
        }
        Command::TlsFingerprint => {
            print!("{}", render_tls_fingerprints());
        }
        Command::ImportRules {
            source,
            target,
            face,
            name,
            out,
        } => {
            let raw = if source.starts_with("http://") || source.starts_with("https://") {
                reqwest::blocking::get(&source)
                    .with_context(|| format!("无法下载规则源 {source}"))?
                    .text()
                    .context("解析规则源内容失败")?
            } else {
                fs::read_to_string(&source).with_context(|| format!("无法读取文件 {source}"))?
            };
            let name = name.unwrap_or_else(|| derive_rule_name(&source));
            let (yaml, skipped) = render_import_rules(&raw, &name, &target, &face)?;
            for s in &skipped {
                eprintln!("跳过: {s}");
            }
            match out {
                Some(path) => {
                    fs::write(&path, &yaml).with_context(|| format!("写入 {path} 失败"))?;
                    println!("已写入 {path}");
                }
                None => print!("{yaml}"),
            }
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
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
                .convert_to_rillane(&clash)
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
            println!("已转换为 Rillane 配置并保存至 {output}");
        }
        Command::ExportClash { source, output } => {
            let config = RillaneConfig::load_from_path(&source)
                .with_context(|| format!("无法读取 Rillane 配置 {source}"))?;
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
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
            let config = RillaneConfig::load_from_path(&cli.config)?;
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
            scope,
            no_redact,
            no_local,
        } => {
            let scope = parse_diagnose_scope(&scope, no_redact)?;
            let epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let out_dir =
                PathBuf::from(output.unwrap_or_else(|| format!("rillane-diagnose-{epoch}")));
            fs::create_dir_all(&out_dir)
                .with_context(|| format!("无法创建输出目录: {}", out_dir.display()))?;

            let config = RillaneConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));

            let token = config.control.admin_token.clone();
            let client = Client::new();

            let mut log = String::new();

            // Config：raw 范围原样落盘（清单标注禁止上传）；其余范围脱敏。
            let raw_config = fs::read_to_string(&cli.config)
                .with_context(|| format!("无法读取 {}", cli.config))?;
            let config_file = if scope == DiagnoseScope::Raw {
                fs::write(out_dir.join("config.raw"), &raw_config)
                    .context("写入 config.raw 失败")?;
                "config.raw"
            } else {
                let rendered_config = redact_config_by_extension(&raw_config, &cli.config);
                fs::write(out_dir.join("config.redacted"), rendered_config)
                    .context("写入 config.redacted 失败")?;
                "config.redacted"
            };

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
            // 按范围选择敏感快照（RIL-058）：safe 不采集订阅列表与
            // 运行配置；full 采集但秘密仍剥除；raw 原样（清单标注禁止
            // 上传 AI）。
            let mut review_files: Vec<&str> = vec![config_file, "events.log", "logs.txt"];
            match scope {
                DiagnoseScope::Safe => {}
                DiagnoseScope::Full => {
                    fetch_json_snapshot_with(
                        &client,
                        token.as_deref(),
                        &format!("{base}/runtime/config"),
                        &out_dir.join("runtime_config.json"),
                        &mut log,
                        &redact_json_value,
                    );
                    fetch_json_snapshot_with(
                        &client,
                        token.as_deref(),
                        &format!("{base}/subscriptions"),
                        &out_dir.join("subscriptions.json"),
                        &mut log,
                        &strip_json_url_secrets,
                    );
                    review_files.push("runtime_config.json");
                    review_files.push("subscriptions.json");
                }
                DiagnoseScope::Raw => {
                    fetch_json_snapshot(
                        &client,
                        token.as_deref(),
                        &format!("{base}/runtime/config"),
                        &out_dir.join("runtime_config.json"),
                        &mut log,
                    );
                    fetch_json_snapshot(
                        &client,
                        token.as_deref(),
                        &format!("{base}/subscriptions"),
                        &out_dir.join("subscriptions.json"),
                        &mut log,
                    );
                    review_files.push("runtime_config.json");
                    review_files.push("subscriptions.json");
                }
            }
            // 错误日志/事件流出：raw 原样；其余逐行剥除私钥块与
            // key=value 秘密对 + 不可信文本消毒
            let log_transform: &dyn Fn(&str) -> String = match scope {
                DiagnoseScope::Raw => &|text: &str| text.to_string(),
                _ => &sanitize_diagnostic_log,
            };
            fetch_text_snapshot_with(
                &client,
                token.as_deref(),
                &format!("{base}/events"),
                &out_dir.join("events.log"),
                &mut log,
                log_transform,
            );
            fetch_text_snapshot_with(
                &client,
                token.as_deref(),
                &format!("{base}/logs?lines=2000"),
                &out_dir.join("logs.txt"),
                &mut log,
                log_transform,
            );

            if !no_local {
                review_files.push("local_system.txt");
                review_files.push("local_routes.txt");
                review_files.push("local_dns.txt");
                review_files.push("local_interfaces.txt");
            }

            let mut files: Vec<&str> = vec![
                config_file,
                "health.txt",
                "flows.json",
                "nodes.json",
                "chains_stats.json",
                "metrics.txt",
                "runtime_stats.json",
                "events.log",
                "logs.txt",
                "requests.log",
            ];
            if scope != DiagnoseScope::Safe {
                files.splice(5..5, ["subscriptions.json", "runtime_config.json"]);
            }
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

            let (scope_name, ai_policy, note) = match scope {
                DiagnoseScope::Safe => (
                    "safe",
                    "review-before-sharing",
                    "safe by omission: subscription list, runtime config and full logs are not collected; collected text is still secret-stripped but may contain identities",
                ),
                DiagnoseScope::Full => (
                    "full",
                    "review-before-sharing",
                    "secrets are stripped (config secret keys, subscription url credentials, log key=value pairs and pem blocks) but identities remain; review before sharing",
                ),
                DiagnoseScope::Raw => (
                    "raw",
                    "do-not-upload",
                    "raw bundle contains secrets; for local human inspection only; never feed to AI models automatically",
                ),
            };
            let meta = serde_json::json!({
                "generated_at_epoch": epoch,
                "config_path": cli.config,
                "control_base": base,
                "scope": scope_name,
                "redacted": scope != DiagnoseScope::Raw,
                "local_snapshots": !no_local,
                "files": files,
                "review_required_files": review_files,
                "ai_upload_policy": ai_policy,
                "upload_policy": "manual only - rillanectl never uploads the bundle anywhere",
                "note": note,
            });
            fs::write(
                out_dir.join("meta.json"),
                serde_json::to_string_pretty(&meta)?,
            )
            .context("写入 meta.json 失败")?;
            fs::write(out_dir.join("requests.log"), log).context("写入 requests.log 失败")?;

            println!("诊断信息已生成: {}（范围 {scope_name}）", out_dir.display());
            println!("上传政策: {ai_policy}——rillanectl 不做任何自动上传，分享前先看 meta.json");
        }
        Command::Trace { endpoint, command } => {
            // RIL-060 Trace CLI：语法冻结（文本/版本化 JSON 双形态），
            // 退出码 0=成功 / 1=用法或连接错误 / 2=显式缺席
            let config = RillaneConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));
            let token = config.control.admin_token.clone();
            let client = Client::new();
            match command {
                TraceCommand::List {
                    state,
                    origin,
                    generation,
                    offset,
                    limit,
                    json,
                } => {
                    validate_trace_filter(state.as_deref(), origin.as_deref())?;
                    let mut url = trace_query_url(&base, "/trace/flows")?;
                    url.push_str(&format!("&offset={offset}&limit={limit}"));
                    if let Some(state) = &state {
                        url.push_str(&format!("&state={state}"));
                    }
                    if let Some(origin) = &origin {
                        url.push_str(&format!("&origin={origin}"));
                    }
                    if let Some(generation) = &generation {
                        url.push_str(&format!(
                            "&generation={}",
                            rillane_core::redact::sanitize_untrusted(generation, 128)
                        ));
                    }
                    let v = trace_fetch_json(&client, token.as_deref(), &url)?;
                    if let Some(absent) = trace_absence(&v) {
                        print!("{}", render_trace_absent("-", &absent));
                        std::process::exit(2);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", render_trace_list(&v));
                    }
                }
                TraceCommand::Flow { id, json } => {
                    let mut url = trace_query_url(&base, "/trace/flow")?;
                    url.push_str(&format!(
                        "&id={}",
                        rillane_core::redact::sanitize_untrusted(&id, 256)
                    ));
                    let v = trace_fetch_json(&client, token.as_deref(), &url)?;
                    if let Some(absent) = trace_absence(&v) {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&v)?);
                        } else {
                            print!("{}", render_trace_absent(&id, &absent));
                        }
                        std::process::exit(2);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", render_trace_flow(&v));
                    }
                }
                TraceCommand::Events {
                    id,
                    from_seq,
                    limit,
                    json,
                } => {
                    let mut url = trace_query_url(&base, "/trace/events")?;
                    url.push_str(&format!(
                        "&id={}&from_seq={from_seq}&limit={limit}",
                        rillane_core::redact::sanitize_untrusted(&id, 256)
                    ));
                    let result = trace_fetch_json_or_404(&client, token.as_deref(), &url);
                    let v = match result {
                        Ok(v) => v,
                        Err(status) => {
                            // 404 显式缺席：退出码 2（打印已拿到的错误信封）
                            if status.as_u16() == 404 {
                                eprintln!(
                                    "trace events: 显式缺席（HTTP 404，query.flow.unknown 口径）"
                                );
                                std::process::exit(2);
                            }
                            anyhow::bail!("控制面返回错误: {status}");
                        }
                    };
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", render_trace_events(&v));
                    }
                }
            }
        }
        Command::Probe { endpoint, command } => {
            // RIL-061 Probe CLI：语法冻结（文本/版本化 JSON 双形态），
            // 退出码 0=成功 / 1=用法或连接错误 / 2=显式缺席
            let config = RillaneConfig::load_from_path(&cli.config)?;
            let base = endpoint.unwrap_or_else(|| format!("http://{}", config.control.api_bind));
            let token = config.control.admin_token.clone();
            let client = Client::new();
            match command {
                ProbeCommand::Submit {
                    kind,
                    host,
                    addr,
                    payload_len,
                    json,
                } => {
                    // 客户端侧用法校验（kind/参数对应/addr 可解析——非法
                    // 值不发请求，退出码 1）
                    let body = validate_probe_submit(
                        &kind,
                        host.as_deref(),
                        addr.as_deref(),
                        payload_len,
                    )?;
                    let (status, text) =
                        probe_post(&client, token.as_deref(), &base, "/probe", &body)?;
                    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                    if !status.is_success() {
                        // 400 稳定码信封（范围外/预算）/ 503 探测面关闭——
                        // 用法或授权问题，退出码 1
                        if json {
                            println!("{}", serde_json::to_string_pretty(&v)?);
                        } else {
                            eprintln!("probe submit: {}", render_probe_error(&v, &text));
                        }
                        std::process::exit(1);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        let id = v.get("job_id").and_then(|x| x.as_u64()).unwrap_or(0);
                        println!("作业 {id} 已提交（probe result {id} 查询结果）");
                    }
                }
                ProbeCommand::Cancel { id, json } => {
                    let id = parse_probe_id(&id)?;
                    let (status, text) = probe_post(
                        &client,
                        token.as_deref(),
                        &base,
                        &format!("/probe/cancel?id={id}"),
                        "",
                    )?;
                    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                    if status.as_u16() == 404 {
                        // 未知作业：显式缺席（退出码 2）
                        if json {
                            println!("{}", serde_json::to_string_pretty(&v)?);
                        } else {
                            eprintln!("probe cancel {id}: 显式缺席（probe.job.unknown）");
                        }
                        std::process::exit(2);
                    }
                    if !status.is_success() {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&v)?);
                        } else {
                            eprintln!("probe cancel: {}", render_probe_error(&v, &text));
                        }
                        std::process::exit(1);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("-");
                        println!("作业 {id} 取消裁决: {verdict}");
                    }
                }
                ProbeCommand::Result { id, json } => {
                    let id = parse_probe_id(&id)?;
                    let (status, text) = probe_fetch(
                        &client,
                        token.as_deref(),
                        &base,
                        &format!("/probe/result?id={id}"),
                    )?;
                    if status.as_u16() == 404 {
                        // 显式缺席（probe.job.unknown）：退出码 2
                        if json {
                            println!("{text}");
                        } else {
                            let v: serde_json::Value =
                                serde_json::from_str(&text).unwrap_or_default();
                            let note = v
                                .get("absence")
                                .and_then(|a| a.get("note"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("");
                            eprintln!("probe result {id}: 显式缺席（probe.job.unknown）{note}");
                        }
                        std::process::exit(2);
                    }
                    if !status.is_success() {
                        eprintln!("probe result: 控制面返回错误: {status}: {text}");
                        std::process::exit(1);
                    }
                    let v: serde_json::Value = serde_json::from_str(&text)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", render_probe_job(&v));
                    }
                }
                ProbeCommand::List { json } => {
                    let (status, text) = probe_fetch(&client, token.as_deref(), &base, "/probe")?;
                    if !status.is_success() {
                        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                        if json {
                            println!("{}", serde_json::to_string_pretty(&v)?);
                        } else {
                            eprintln!("probe list: {}", render_probe_error(&v, &text));
                        }
                        std::process::exit(1);
                    }
                    let v: serde_json::Value = serde_json::from_str(&text)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", render_probe_list(&v));
                    }
                }
            }
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
                println!("示例环境变量（在运行 rillaned 的环境中设置）：");
                println!("  export RILLANE_MESH_MTLS=1");
                println!(
                    "  export RILLANE_MESH_MTLS_CA={}",
                    PathBuf::from(ca_cert).display()
                );
                println!("  export RILLANE_MESH_MTLS_CERT={}", cert_path.display());
                println!("  export RILLANE_MESH_MTLS_KEY={}", key_path.display());
                println!("  export RILLANE_MESH_MTLS_SERVER_NAME={server_name}");
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
                println!("说明：rillaned mesh mTLS 已支持自动 reload，新连接会使用新证书；已有连接不受影响。");
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
                println!("建议流程：先把 ca.bundle.pem 下发到所有节点作为 RILLANE_MESH_MTLS_CA，完成双信任窗口；再逐个轮换节点证书到新 CA；最后移除旧 CA。");
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
                    let config = RillaneConfig::load_from_path(&cli.config)?;
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
    fetch_json_snapshot_with(client, token, url, out_path, log, &|_v| {});
}

/// 带 JSON 出口变换的快照抓取（RIL-058：runtime_config/订阅列表经
/// 变换剥除秘密后才落盘——出口闸在写入之前）。
fn fetch_json_snapshot_with(
    client: &Client,
    token: Option<&str>,
    url: &str,
    out_path: &std::path::Path,
    log: &mut String,
    transform: &dyn Fn(&mut serde_json::Value),
) {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header("x-admin-token", t);
    }

    match req.send() {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>() {
            Ok(mut v) => {
                transform(&mut v);
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
    fetch_text_snapshot_with(client, token, url, out_path, log, &|text| text.to_string());
}

/// 带文本出口变换的快照抓取（RIL-058：事件/日志流出逐行剥除秘密
/// + 消毒后才落盘）。
fn fetch_text_snapshot_with(
    client: &Client,
    token: Option<&str>,
    url: &str,
    out_path: &std::path::Path,
    log: &mut String,
    transform: &dyn Fn(&str) -> String,
) {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header("x-admin-token", t);
    }

    match req.send() {
        Ok(r) if r.status().is_success() => match r.text() {
            Ok(t) => match fs::write(out_path, transform(&t)) {
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

/// 诊断包范围（RIL-058）：按范围选择快照/日志/配置，默认安全。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagnoseScope {
    /// 默认：不含订阅列表、运行配置与完整错误日志的包（出口面最小）
    Safe,
    /// 全快照：订阅 URL 与运行配置仍剥除秘密后落盘（身份字段保留）
    Full,
    /// 原始包：不脱敏——仅供本地人工排查，清单标注禁止直接上传 AI
    Raw,
}

/// 范围解析（`--no-redact` 显式覆盖为 raw——向后兼容旧参数）。
fn parse_diagnose_scope(scope: &str, no_redact: bool) -> Result<DiagnoseScope> {
    if no_redact {
        return Ok(DiagnoseScope::Raw);
    }
    match scope {
        "safe" => Ok(DiagnoseScope::Safe),
        "full" => Ok(DiagnoseScope::Full),
        "raw" => Ok(DiagnoseScope::Raw),
        other => anyhow::bail!("不支持的诊断范围 {other:?}（支持 safe/full/raw）"),
    }
}

/// 订阅/URL 类 JSON 出口（RIL-058）：任意字符串值里的 URL 剥除秘密
/// ——userinfo 凭证与 token/password/secret/key/sign 类查询参数整体
/// 移除。语义与 RIL-057 `Redactor::url`（Detailed 档剥除面）一致：
/// 诊断导出内秘密永不出边界（身份字段原样保留，供本机排查）。
fn strip_json_url_secrets(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map.iter_mut() {
                let url_key = k.eq_ignore_ascii_case("url")
                    || k.eq_ignore_ascii_case("subscription_url")
                    || k.eq_ignore_ascii_case("webhook_url");
                if url_key {
                    if let serde_json::Value::String(text) = vv {
                        let mut red = Redactor::new(RedactionScope::Detailed);
                        *text = red.url(text);
                        continue;
                    }
                }
                strip_json_url_secrets(vv);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                strip_json_url_secrets(item);
            }
        }
        _ => {}
    }
}

/// 错误日志/事件流出（RIL-058）：逐行剥除私钥块与 key=value 秘密对
/// + 不可信文本消毒（RIL-057 `Redactor::error_message` 同一语义）。
///
/// 日志是不可信数据：不能以原始形态成为诊断包的一部分。
fn sanitize_diagnostic_log(text: &str) -> String {
    // 整体先剥多行 PEM 块（块边界跨行——逐行消毒匹配不到完整块）
    let no_pem = rillane_core::redact::strip_pem(text);
    let mut red = Redactor::new(RedactionScope::Detailed);
    no_pem
        .lines()
        .map(|line| red.error_message(line))
        .collect::<Vec<_>>()
        .join("\n")
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

fn build_ingress_from_clash(clash: &rillane_subscription::ClashConfig) -> IngressDescriptor {
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

/// `/routing/stats` 响应（rillaned `RoutingStatsDto` 的 rillanectl 侧反序列化视图）
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

// ---------- O-prof1：profile 场景骨架 ----------

/// 场景名白名单（O-prof1）：报错给合法值
fn parse_profile_variant(s: &str) -> Result<String> {
    match s {
        "proxy" | "game" | "web" => Ok(s.to_string()),
        other => Err(anyhow::anyhow!(
            "未知场景 {other}（合法值：proxy | game | web）"
        )),
    }
}

/// 场景骨架（O-prof1）：最小可运行配置 + `profile:` 行，经 from_str 解析
/// 校验并展开（scenario-profiles.md §2-D2：显式空位由 profile 缺省填充）——
/// 输出为展开后的完整配置，可直接 `RILLANE_CONFIG=<path> rillaned` 运行。
fn scenario_skeleton(variant: &str) -> Result<RillaneConfig> {
    let raw = format!(
        "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: rillane\n\n\
         telemetry:\n  log_level: info\n  enable_metrics: true\n  enable_tracing: false\n\n\
         ingress:\n  - name: socks-in\n    type: socks5\n    bind: 127.0.0.1:7890\n\n\
         egress:\n  - name: direct-main\n    type: direct\n\n\
         routing:\n  default_node: direct-main\n  groups: []\n  rules: []\n\n\
         profile: {variant}\n"
    );
    RillaneConfig::from_str(&raw, Some("yaml")).context("场景骨架解析失败")
}

// ---------- O-dns1：geosite/chnroutes 文本规则源批量导入 ----------

/// 源路径/URL → 规则名：文件名去扩展名（URL 取末段 query 前）
fn derive_rule_name(source: &str) -> String {
    let trimmed = source.trim_end_matches('/');
    let before_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let file = before_query
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(before_query);
    let stem = file.split('.').next().unwrap_or(file);
    if stem.is_empty() {
        "imported".to_string()
    } else {
        stem.to_string()
    }
}

/// 规则源 → 目标面 YAML 片段 + 跳过清单（走 stderr，stdout 保持纯 YAML 可管道）
fn render_import_rules(
    raw: &str,
    name: &str,
    target: &str,
    face: &str,
) -> Result<(String, Vec<String>)> {
    use rillane_subscription::{parse_rule_source, to_dns_rules, to_routing_rules};
    let src = parse_rule_source(raw);
    match face {
        "routing" => {
            let rules = to_routing_rules(&src, name, target);
            if rules.is_empty() {
                anyhow::bail!("规则源无可导入条目（全部为注释/空行/跳过项）");
            }
            let yaml = serde_yaml::to_string(&rules).context("路由规则序列化失败")?;
            Ok((yaml, src.skipped))
        }
        "dns" => {
            let group = match target {
                "domestic" => rillane_config::DnsGroup::Domestic,
                "trusted" => rillane_config::DnsGroup::Trusted,
                other => anyhow::bail!("未知 DNS 组 {other}（合法值：domestic | trusted）"),
            };
            let rules = to_dns_rules(&src, group)?;
            if rules.is_empty() {
                anyhow::bail!("规则源无可导入条目（全部为注释/空行/跳过项）");
            }
            let yaml = serde_yaml::to_string(&rules).context("DNS 规则序列化失败")?;
            Ok((yaml, src.skipped))
        }
        other => anyhow::bail!("未知目标面 {other}（合法值：routing | dns）"),
    }
}

// ---------- O-pool3：出站连接池 CLI 取数面 ----------

/// `/egress/pool/stats` 响应（rillaned `EgressPoolStatsDto` 的 rillanectl 侧反序列化视图）
#[derive(Debug, Deserialize)]
struct EgressPoolStatsResponse {
    enabled: bool,
    tls_resumption: bool,
    keys: Vec<EgressPoolKeyDto>,
    counters: EgressPoolCountersDto,
    reuse_ratio: f64,
}

#[derive(Debug, Deserialize)]
struct EgressPoolKeyDto {
    key: String,
    idle: usize,
}

#[derive(Debug, Deserialize, Default)]
struct EgressPoolCountersDto {
    hit: u64,
    miss: u64,
    stale_redial: u64,
    dials_ok: u64,
    dials_err: u64,
}

fn render_pool_status(s: &EgressPoolStatsResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "出站连接池: {}（TLS 复会话: {}）\n",
        if s.enabled { "启用" } else { "未启用" },
        if s.tls_resumption { "开" } else { "关" },
    ));
    out.push_str(&format!(
        "计数: hit={} miss={} stale_redial={} dials_ok={} dials_err={}\n",
        s.counters.hit,
        s.counters.miss,
        s.counters.stale_redial,
        s.counters.dials_ok,
        s.counters.dials_err,
    ));
    out.push_str(&format!("复用率: {:.3}\n", s.reuse_ratio));
    if s.keys.is_empty() {
        out.push_str("暂无池键\n");
    } else {
        out.push_str("池键 (idle):\n");
        for k in &s.keys {
            out.push_str(&format!("  {} idle={}\n", k.key, k.idle));
        }
    }
    out
}

// ---------- O-link-obs2：switches 链路切换账本 ----------

/// `/mesh/switches` 响应（rillaned `MeshSwitchesDto` 的 rillanectl 侧反序列化视图）
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

/// O-tfp1：TLS 指纹形态预设对照表——各预设 shape_material 四维导出
/// （版本/套件/群/签名方案），预设间两两互异由 fingerprint.rs §7-3 构造保证。
fn render_tls_fingerprints() -> String {
    use rillane_protocols::TlsFingerprint;
    let presets = [
        TlsFingerprint::None,
        TlsFingerprint::Chrome,
        TlsFingerprint::Ios,
        TlsFingerprint::Safari,
    ];
    let mut out = String::from("TLS 指纹形态预设对照表（shape_material）\n");
    out.push_str("预设        形态串（版本|套件|群|签名方案，hex）\n");
    out.push_str("----        -----------------------------------\n");
    for p in presets {
        out.push_str(&format!("{:<11} {}\n", p.as_str(), p.shape_material()));
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

/// `/udp/stats` 响应（§9-1 结构的 rillanectl 侧反序列化视图；BTreeMap 固定序）
#[derive(Debug, Deserialize)]
struct UdpStatsDto {
    table: UdpTableDto,
    ingress: UdpIngressDto,
    mesh: Option<UdpMeshDto>,
    /// 旧 rillaned 无该键 → None（§3.6 对拷容错）
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
    /// P2-7 M1 §3.6：防重放窗口拒帧；旧 rillaned 无该键 → 缺省 0
    #[serde(default)]
    replay_dropped: u64,
}

/// P2-7 M1 §3.6：client 桥计数（旧 rillaned 无该键 → Option None；字段 default 容错）
#[derive(Debug, Deserialize)]
struct UdpMeshClientDto {
    dropped: u64,
    #[serde(default)]
    replay_dropped: u64,
}

/// GET {base}/udp/stats；不可达 / 非 2xx / 解析失败均返回 None（§3.2：
/// 对旧版 rillaned 兼容，打印占位行且不视为失败）
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

// Trace CLI 纯辅助（RIL-060）：URL 拼装/参数校验/渲染均抽纯函数
// 便于单测——网络与进程退出只在 main 分发臂发生。

/// 拼装 Trace 查询 URL（base 去尾斜杠 + path + `?`，调用方续接参数）
fn trace_query_url(base: &str, path: &str) -> Result<String> {
    let trimmed = base.trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("控制面地址为空");
    }
    Ok(format!("{trimmed}{path}?"))
}

/// 客户端侧过滤参数校验（state/origin 取值面冻结——非法值不发请求）
fn validate_trace_filter(state: Option<&str>, origin: Option<&str>) -> Result<()> {
    if let Some(state) = state {
        if state != "active" && state != "closed" {
            anyhow::bail!("state 只接受 active 或 closed，得到 {state}");
        }
    }
    if let Some(origin) = origin {
        if origin != "stream" && origin != "association" {
            anyhow::bail!("origin 只接受 stream 或 association，得到 {origin}");
        }
    }
    Ok(())
}

/// GET + x-admin-token → JSON（非 2xx 一律 anyhow 错误——退出码 1 路径）
fn trace_fetch_json(client: &Client, token: Option<&str>, url: &str) -> Result<serde_json::Value> {
    let mut req = client.get(url);
    if let Some(token) = token {
        req = req.header("x-admin-token", token);
    }
    let resp = req.send().with_context(|| format!("无法访问 {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .with_context(|| format!("读取 {url} 响应失败"))?;
    let v: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("解析 {url} 响应失败"))?;
    if !status.is_success() {
        anyhow::bail!("控制面返回错误: {status}: {body}");
    }
    Ok(v)
}

/// 同 [`trace_fetch_json`] 但非 2xx 返回状态码（404 显式缺席 → 退出码 2）
fn trace_fetch_json_or_404(
    client: &Client,
    token: Option<&str>,
    url: &str,
) -> std::result::Result<serde_json::Value, reqwest::StatusCode> {
    let mut req = client.get(url);
    if let Some(token) = token {
        req = req.header("x-admin-token", token);
    }
    let resp = req
        .send()
        .map_err(|_| reqwest::StatusCode::SERVICE_UNAVAILABLE)?;
    let status = resp.status();
    let body = resp.text().map_err(|_| status)?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| status)?;
    if !status.is_success() {
        return Err(status);
    }
    Ok(v)
}

/// 显式缺席答复（found:false 信封的 absence 对象投影）
#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceAbsentAnswer {
    code: String,
    note: String,
    collector: serde_json::Value,
}

/// 从响应信封提取显式缺席（found:false 才算——其余形态不算缺席）
fn trace_absence(v: &serde_json::Value) -> Option<TraceAbsentAnswer> {
    if v.get("found").and_then(|f| f.as_bool()) != Some(false) {
        return None;
    }
    let absence = v.get("absence")?;
    Some(TraceAbsentAnswer {
        code: absence
            .get("code")
            .and_then(|c| c.as_str())
            .unwrap_or("unknown")
            .to_string(),
        note: absence
            .get("note")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string(),
        collector: absence.get("collector").cloned().unwrap_or_default(),
    })
}

/// 缺席答复文本（固定说明原样带出——无记录 ≠ 未发包）
fn render_trace_absent(id: &str, absent: &TraceAbsentAnswer) -> String {
    format!(
        "flow {id}: 显式缺席（{}）\n{}\ncollector: {}\n",
        absent.code,
        absent.note,
        serde_json::to_string(&absent.collector).unwrap_or_default()
    )
}

/// 列表文本：表头 + 逐行摘要 + 总数（items 空 = 无匹配不造行）
fn render_trace_list(v: &serde_json::Value) -> String {
    let items = v.get("items").and_then(|i| i.as_array());
    let Some(items) = items else {
        return "trace list: 响应缺少 items 字段\n".into();
    };
    if items.is_empty() {
        return "无匹配轨迹（追踪关闭或暂无连接埋点）\n".into();
    }
    let mut out = String::from("FLOW\tORIGIN\tSTATE\tEVENTS\tGENERATION\tLAST\n");
    for item in items {
        let flow = item.get("flow").and_then(|x| x.as_str()).unwrap_or("-");
        let origin = item.get("origin").and_then(|x| x.as_str()).unwrap_or("-");
        let state = item.get("state").and_then(|x| x.as_str()).unwrap_or("-");
        let events = item.get("events").and_then(|x| x.as_u64()).unwrap_or(0);
        let generation = item
            .get("generation")
            .and_then(|x| x.as_str())
            .unwrap_or("-");
        let last = item
            .get("last_code")
            .and_then(|x| x.as_str())
            .unwrap_or("-");
        out.push_str(&format!(
            "{flow}\t{origin}\t{state}\t{events}\t{generation}\t{last}\n"
        ));
    }
    if let Some(total) = v.get("total_matching").and_then(|t| t.as_u64()) {
        let offset = v.get("offset").and_then(|t| t.as_u64()).unwrap_or(0);
        out.push_str(&format!("共 {total} 条匹配，offset={offset}\n"));
    }
    out
}

/// 单事件行（flow 详情与 events 增量共用）
fn trace_event_line(event: &serde_json::Value) -> String {
    let seq = event.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
    let stage = event.get("stage").and_then(|x| x.as_str()).unwrap_or("-");
    let code = event.get("code").and_then(|x| x.as_str()).unwrap_or("-");
    let evidence = event
        .get("evidence")
        .and_then(|x| x.as_str())
        .unwrap_or("-");
    let attempt = event
        .get("attempt")
        .and_then(|x| x.as_u64())
        .map(|a| a.to_string())
        .unwrap_or_else(|| "-".into());
    let mono = event
        .get("monotonic_ms")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let wall = event.get("wall_ms").and_then(|x| x.as_u64()).unwrap_or(0);
    let detail = event.get("detail").and_then(|x| x.as_str()).unwrap_or("");
    format!(
        "  #{seq} {stage} {code} evidence={evidence} attempt={attempt} mono={mono} wall={wall} {detail}\n"
    )
}

/// 流详情文本：头部（flow/origin/generation/closed）+ 全量事件行
fn render_trace_flow(v: &serde_json::Value) -> String {
    let trace = v.get("trace").unwrap_or(&serde_json::Value::Null);
    let flow = trace.get("flow").and_then(|x| x.as_str()).unwrap_or("-");
    let origin = trace.get("origin").and_then(|x| x.as_str()).unwrap_or("-");
    let generation = trace
        .get("generation")
        .and_then(|x| x.as_str())
        .unwrap_or("-");
    let closed = trace
        .get("closed")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let mut out = format!("flow {flow} origin={origin} generation={generation} closed={closed}\n");
    if let Some(events) = trace.get("events").and_then(|e| e.as_array()) {
        for event in events {
            out.push_str(&trace_event_line(event));
        }
    }
    out
}

/// 事件增量文本：头部（flow/from_seq/count）+ 事件行
fn render_trace_events(v: &serde_json::Value) -> String {
    let flow = v.get("flow").and_then(|x| x.as_str()).unwrap_or("-");
    let from_seq = v.get("from_seq").and_then(|x| x.as_u64()).unwrap_or(0);
    let count = v
        .get("events")
        .and_then(|e| e.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let mut out = format!("flow {flow} from_seq={from_seq} count={count}\n");
    if let Some(events) = v.get("events").and_then(|e| e.as_array()) {
        for event in events {
            out.push_str(&trace_event_line(event));
        }
    }
    out
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

// ---------- Probe CLI 纯辅助（RIL-061）：用法校验/请求/渲染均抽纯函数
// 便于单测——网络与进程退出只在 main 分发臂发生 ----------

/// 作业 ID 解析（非负整数；clap 参数错误退出码会顶掉冻结缺席码 2——
/// 手工解析让非法 ID 走退出码 1）
fn parse_probe_id(id: &str) -> Result<u64> {
    id.parse::<u64>()
        .with_context(|| format!("作业 ID 须为非负整数（得到 {id}）"))
}

/// 客户端侧提交用法校验 + 请求体拼装：kind/参数对应、addr 可解析、
/// 载荷为正——非法值不发请求（退出码 1 路径）
fn validate_probe_submit(
    kind: &str,
    host: Option<&str>,
    addr: Option<&str>,
    payload_len: usize,
) -> Result<String> {
    match kind {
        "dns" => {
            let h = host
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .ok_or_else(|| anyhow::anyhow!("kind=dns 需要 --host"))?;
            Ok(serde_json::json!({"kind": "dns", "host": h}).to_string())
        }
        "connect" => {
            let a = addr.ok_or_else(|| anyhow::anyhow!("kind=connect 需要 --addr"))?;
            let parsed: std::net::SocketAddr = a
                .parse()
                .with_context(|| format!("--addr 须为 ip:port（得到 {a}）"))?;
            Ok(serde_json::json!({"kind": "connect", "addr": parsed}).to_string())
        }
        "udp-echo" => {
            let a = addr.ok_or_else(|| anyhow::anyhow!("kind=udp-echo 需要 --addr"))?;
            let parsed: std::net::SocketAddr = a
                .parse()
                .with_context(|| format!("--addr 须为 ip:port（得到 {a}）"))?;
            if payload_len == 0 {
                anyhow::bail!("--payload-len 须 ≥ 1");
            }
            Ok(
                serde_json::json!({"kind": "udp_echo", "addr": parsed, "payload_len": payload_len})
                    .to_string(),
            )
        }
        other => anyhow::bail!("kind 只接受 dns|connect|udp-echo，得到 {other}"),
    }
}

/// 控制面 URL 拼装（base 去尾斜杠 + path；query 由调用方续接）
fn probe_url(base: &str, path: &str) -> Result<String> {
    let trimmed = base.trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("控制面地址为空");
    }
    Ok(format!("{trimmed}{path}"))
}

/// GET + x-admin-token → (status, body)；连接失败 → Err（退出码 1 路径）
fn probe_fetch(
    client: &Client,
    token: Option<&str>,
    base: &str,
    path: &str,
) -> Result<(reqwest::StatusCode, String)> {
    let url = probe_url(base, path)?;
    let mut req = client.get(&url);
    if let Some(token) = token {
        req = req.header("x-admin-token", token);
    }
    let resp = req.send().with_context(|| format!("无法访问 {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .with_context(|| format!("读取 {url} 响应失败"))?;
    Ok((status, body))
}

/// POST + x-admin-token → (status, body)；连接失败 → Err（退出码 1 路径）
fn probe_post(
    client: &Client,
    token: Option<&str>,
    base: &str,
    path: &str,
    body: &str,
) -> Result<(reqwest::StatusCode, String)> {
    let url = probe_url(base, path)?;
    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string());
    if let Some(token) = token {
        req = req.header("x-admin-token", token);
    }
    let resp = req.send().with_context(|| format!("无法访问 {url}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .with_context(|| format!("读取 {url} 响应失败"))?;
    Ok((status, text))
}

/// 错误信封可读形（error.code + context；非 JSON 原样带出）
fn render_probe_error(v: &serde_json::Value, raw: &str) -> String {
    let code = v
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("-");
    let context = v
        .get("error")
        .and_then(|e| e.get("context"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    if code == "-" {
        // 非 JSON/无信封：原文截断带出（不造语义）
        raw.chars().take(200).collect()
    } else {
        format!("{code}: {context}")
    }
}

/// 测量文本（outcome 三路标记逐行显式——无回应不造 RTT，丢包由计数
/// 可算，无任何路径/跳点推断）
fn probe_outcome_line(outcome: &serde_json::Value) -> String {
    let measurement = outcome
        .get("measurement")
        .and_then(|x| x.as_str())
        .unwrap_or("-");
    let rtt = outcome
        .get("rtt_ms")
        .map(|x| {
            x.as_u64()
                .map(|n| format!("{n}ms"))
                .unwrap_or_else(|| "none".into())
        })
        .unwrap_or_else(|| "-".into());
    match measurement {
        "dns" => {
            let resolved = outcome
                .get("resolved")
                .and_then(|r| r.as_array())
                .map(|a| {
                    a.iter()
                        .map(|x| x.as_str().unwrap_or("?").to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            format!("    measurement=dns resolved={resolved} rtt={rtt}\n")
        }
        "connect" => format!("    measurement=connect rtt={rtt}\n"),
        "udp_echo" => {
            let sent = outcome.get("sent").and_then(|x| x.as_u64()).unwrap_or(0);
            let replies = outcome.get("replies").and_then(|x| x.as_u64()).unwrap_or(0);
            let payload = outcome
                .get("payload_len")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let loss = outcome
                .get("loss_ratio")
                .map(|x| {
                    x.as_f64()
                        .map(|f| format!("{f}"))
                        .unwrap_or_else(|| "none".into())
                })
                .unwrap_or_else(|| "-".into());
            format!("    measurement=udp_echo sent={sent} replies={replies} loss={loss} rtt={rtt} payload={payload}B\n")
        }
        other => format!("    measurement={other}\n"),
    }
}

/// 单作业文本：头部（id/target/state/时刻）+ 失败行 + 测量行
fn render_probe_job(v: &serde_json::Value) -> String {
    let job = v.get("job").unwrap_or(v);
    let id = job.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
    let target = job.get("target").and_then(|x| x.as_str()).unwrap_or("-");
    let state = job.get("state").and_then(|x| x.as_str()).unwrap_or("-");
    let submitted = job
        .get("submitted_unix_ms")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let finished = job
        .get("finished_unix_ms")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into());
    let mut out =
        format!("job {id} {target}\n  state={state} submitted={submitted} finished={finished}\n");
    match job.get("failure") {
        Some(f) if !f.is_null() => {
            let code = f.get("code").and_then(|x| x.as_str()).unwrap_or("-");
            let detail = f.get("detail").and_then(|x| x.as_str()).unwrap_or("");
            out.push_str(&format!("  failure: {code} {detail}\n"));
        }
        _ => out.push_str("  failure: none\n"),
    }
    match job.get("outcome") {
        Some(o) if !o.is_null() => {
            out.push_str("  outcome:\n");
            out.push_str(&probe_outcome_line(o));
        }
        _ => out.push_str("  outcome: none（未完成/失败/取消无测量）\n"),
    }
    out
}

/// 列表文本：限额行 + 表头 + 逐作业行（jobs 空 = 无作业不造行）
fn render_probe_list(v: &serde_json::Value) -> String {
    let limits = v.get("limits");
    let max_active = limits
        .and_then(|l| l.get("max_active"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let timeout = limits
        .and_then(|l| l.get("job_timeout_ms"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let udp_max = limits
        .and_then(|l| l.get("udp_payload_max_bytes"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let budget = limits
        .and_then(|l| l.get("byte_budget"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mut out = format!(
        "limits: max_active={max_active} timeout={timeout}ms udp_max={udp_max}B budget={budget}B\n"
    );
    let jobs = v.get("jobs").and_then(|j| j.as_array());
    let Some(jobs) = jobs else {
        return out;
    };
    if jobs.is_empty() {
        out.push_str("无探测作业（probe submit 显式发起）\n");
        return out;
    }
    out.push_str("ID\tTARGET\tSTATE\tSUBMITTED\tFINISHED\n");
    for job in jobs {
        let id = job.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
        let target = job.get("target").and_then(|x| x.as_str()).unwrap_or("-");
        let state = job.get("state").and_then(|x| x.as_str()).unwrap_or("-");
        let submitted = job
            .get("submitted_unix_ms")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let finished = job
            .get("finished_unix_ms")
            .and_then(|x| x.as_u64())
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "{id}\t{target}\t{state}\t{submitted}\t{finished}\n"
        ));
    }
    out
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
        _ => out.push_str("file: (未配置 RILLANE_MESH_MTLS_REVOKED_NODES_FILE)\n"),
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
    // P2-7 M1 §3.6：client 桥计数在装配时渲染（旧 rillaned 无该键 → 不渲染）
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
        // P2-7 M1 §3.6：装配态 mesh_client 渲染；旧 rillaned 缺键 → 整段不渲染
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

        // 旧 rillaned 对拷容错（§3.6）：mesh/mesh_client 缺 replay_dropped 键 → 缺省 0
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
        let cli = Cli::parse_from(["rillanectl", "route", "status"]);
        assert!(matches!(
            &cli.command,
            Command::Route {
                endpoint: None,
                command: RouteCommand::Status
            }
        ));

        let cli = Cli::parse_from([
            "rillanectl",
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

        let cli = Cli::parse_from(["rillanectl", "route", "clear"]);
        assert!(matches!(
            &cli.command,
            Command::Route {
                endpoint: None,
                command: RouteCommand::Clear
            }
        ));

        // apply 缺省真执行（dry_run=false）
        let cli = Cli::parse_from(["rillanectl", "route", "apply"]);
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
        let cli = Cli::parse_from(["rillanectl", "mtls", "revoke", "status"]);
        assert!(matches!(
            &cli.command,
            Command::Mtls {
                command: MtlsCommand::Revoke {
                    command: RevokeCommand::Status { endpoint: None }
                }
            }
        ));

        let cli = Cli::parse_from([
            "rillanectl",
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
                "path": "/etc/rillane/revoked.list",
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
                "file: /etc/rillane/revoked.list (loaded=true mtime=1760000000 entries=2 error=(无))",
                "  revoked: node-b",
                "  revoked: node-c",
            ]
            .join("\n")
        );

        let v2 = serde_json::json!({ "static_count": 0, "file": null });
        let out = render_mtls_revoked(&v2);
        assert_eq!(
            out,
            "static: 0\nfile: (未配置 RILLANE_MESH_MTLS_REVOKED_NODES_FILE)\n"
        );
    }

    /// network-route.md §4/§3 输出格式：argv 逐行表 + status 四行设备态 +
    /// 缺键容错（unknown/false 占位）
    #[test]
    fn route_render_steps_and_status() {
        let v = serde_json::json!({
            "planned": [{"argv": ["ip", "route", "replace", "203.0.113.0/24", "dev", "rillane0", "metric", "0"], "at": 1760000000}],
            "executed": [],
            "rolled_back": [{"argv": ["ip", "addr", "del", "10.255.0.1/24", "dev", "rillane0"]}]
        });
        assert_eq!(
            step_argv_lines(v.get("planned")),
            ["  ip route replace 203.0.113.0/24 dev rillane0 metric 0"]
        );
        assert!(step_argv_lines(v.get("executed")).is_empty());
        assert_eq!(
            step_argv_lines(v.get("rolled_back")),
            ["  ip addr del 10.255.0.1/24 dev rillane0"]
        );
        assert!(step_argv_lines(None).is_empty());

        let st = serde_json::json!({
            "mode": "tun", "device": "rillane0", "mtu": 1400, "up": true,
            "applied": [{"argv": ["ip", "route", "replace", "203.0.113.0/24", "dev", "rillane0", "metric", "0"], "at": 1760000000}]
        });
        let expected = [
            "mode: tun",
            "device: rillane0",
            "mtu: 1400",
            "up: true",
            "applied:",
            "  ip route replace 203.0.113.0/24 dev rillane0 metric 0",
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
        let resp: MeshSwitchesResponse = serde_json::from_str(body).expect("switches 应可解析");
        assert_eq!(resp.events.len(), 2);

        let out = render_switches(&resp.events);
        assert!(out.contains(
            "[1750000000] c1 client1 -> relay1 -> exit1 -> client1 -> exit1 | hop_failed | read error"
        ));
        assert!(
            out.contains("[1750000001] c2 client1 -> exit2 -> (terminate) | terminated | manual")
        );
    }

    #[test]
    fn switches_render_empty() {
        assert_eq!(render_switches(&[]), "暂无链路切换记录\n");
    }

    /// O-prof1：三场景骨架解析展开（P2-3 缺省填充 + 显式恒优先口径）
    #[test]
    fn scenario_skeleton_expands_all_variants() {
        let proxy = scenario_skeleton("proxy").expect("proxy 骨架应可解析");
        assert_eq!(proxy.profile, Some(rillane_config::ProfileKind::Proxy));
        assert_eq!(proxy.routing.groups.len(), 1);
        assert_eq!(proxy.routing.groups[0].name, "auto");
        assert!(proxy.routing.rules.iter().any(|r| r.name == "cn"));
        assert!(proxy.obfuscation.is_none() && proxy.egress_pool.is_none());

        let game = scenario_skeleton("game").expect("game 骨架应可解析");
        assert_eq!(game.profile, Some(rillane_config::ProfileKind::Game));
        assert_eq!(game.routing.groups[0].name, "game-auto");
        let slo = game.routing.groups[0]
            .slo
            .as_ref()
            .expect("game 组应带 SLO 目标");
        assert_eq!(slo.p95_ms, Some(80));
        assert!(game.obfuscation.is_some());
        assert!(game.egress_pool.is_none());

        let web = scenario_skeleton("web").expect("web 骨架应可解析");
        assert_eq!(web.routing.groups[0].name, "web-auto");
        assert!(web.egress_pool.is_some());
        assert!(web.obfuscation.is_none());
        // 骨架恒含最小 ingress/egress 与 default_node（三场景同构部分）
        assert_eq!(web.ingress.len(), 1);
        assert_eq!(web.egress.len(), 1);
        assert_eq!(web.routing.default_node, "direct-main");

        // 序列化产物仍是合法配置（展开幂等，重载组模板不变）
        let yaml = serde_yaml::to_string(&web).expect("应可序列化");
        let reloaded = RillaneConfig::from_str(&yaml, Some("yaml")).expect("序列化产物应可重载");
        assert_eq!(reloaded.routing.groups[0].name, "web-auto");
    }

    #[test]
    fn profile_variant_whitelist() {
        for v in ["proxy", "game", "web"] {
            assert_eq!(parse_profile_variant(v).unwrap(), v);
        }
        let err = parse_profile_variant("fps").unwrap_err();
        assert!(err.to_string().contains("fps"), "{}", err);
    }

    /// O-tfp1：对照表含四预设且各预设名与其 shape_material 均呈现
    #[test]
    fn tls_fingerprint_table_lists_all_presets() {
        use rillane_protocols::TlsFingerprint;
        let out = render_tls_fingerprints();
        for p in [
            TlsFingerprint::None,
            TlsFingerprint::Chrome,
            TlsFingerprint::Ios,
            TlsFingerprint::Safari,
        ] {
            assert!(out.contains(p.as_str()), "{out}");
            assert!(out.contains(&p.shape_material()), "{out}");
        }
    }

    /// O-pool3：池快照渲染（启用含键 / 未启用空键两态）
    #[test]
    fn pool_status_renders_both_states() {
        let s = EgressPoolStatsResponse {
            enabled: true,
            tls_resumption: true,
            keys: vec![EgressPoolKeyDto {
                key: "tls:sni=example.com:443".into(),
                idle: 2,
            }],
            counters: EgressPoolCountersDto {
                hit: 9,
                miss: 1,
                stale_redial: 0,
                dials_ok: 12,
                dials_err: 0,
            },
            reuse_ratio: 0.9,
        };
        let out = render_pool_status(&s);
        assert!(out.contains("启用"), "{out}");
        assert!(out.contains("复用率: 0.900"), "{out}");
        assert!(out.contains("tls:sni=example.com:443 idle=2"), "{out}");
        assert!(out.contains("hit=9 miss=1"), "{out}");
        assert!(!out.contains("暂无池键"), "{out}");

        let off = EgressPoolStatsResponse {
            enabled: false,
            tls_resumption: false,
            keys: vec![],
            counters: EgressPoolCountersDto::default(),
            reuse_ratio: 0.0,
        };
        let out = render_pool_status(&off);
        assert!(out.contains("未启用"), "{out}");
        assert!(out.contains("暂无池键"), "{out}");
    }

    /// O-dns1：规则名派生与片段渲染（routing/dns 双面 + 面/组白名单）
    #[test]
    fn import_rules_helpers() {
        assert_eq!(derive_rule_name("https://x.io/data/cn.txt?a=1"), "cn");
        assert_eq!(derive_rule_name("/tmp/chnroutes.txt"), "chnroutes");
        assert_eq!(derive_rule_name("/"), "imported");

        // routing 面：域+CIDR+regexp 混源 → 三条规则 YAML，跳过项走报告
        let (yaml, skipped) = render_import_rules(
            "example.com\n10.0.0.0/8\nregexp:^x\n",
            "cn",
            "direct-main",
            "routing",
        )
        .expect("routing 面应可渲染");
        let rules: Vec<rillane_config::RouteRule> = serde_yaml::from_str(&yaml).expect("应可读回");
        assert_eq!(rules.len(), 3, "域/CIDR/regexp 各成一条规则");
        assert_eq!(skipped.len(), 0, "regexp 现支持，无跳过项");

        // dns 面：裸域展开 exact + suffix，组随 target
        let (yaml, _) =
            render_import_rules("a.com\n", "n", "trusted", "dns").expect("dns 面应可渲染");
        let rules: Vec<rillane_config::DnsRuleConfig> =
            serde_yaml::from_str(&yaml).expect("应可读回");
        assert_eq!(rules.len(), 2);
        assert!(rules
            .iter()
            .all(|r| r.group == rillane_config::DnsGroup::Trusted));

        // 面白名单 / DNS 组白名单 / DNS 面拒 CIDR
        assert!(render_import_rules("a.com", "n", "x", "lan").is_err());
        assert!(render_import_rules("a.com", "bogus", "x", "dns").is_err());
        assert!(render_import_rules("10.0.0.0/8", "domestic", "x", "dns").is_err());
    }

    /// RIL-058：范围解析——默认 safe；--no-redact 显式覆盖 raw；
    /// 非法值报错。
    #[test]
    fn diagnose_scope_parsing() {
        assert_eq!(
            parse_diagnose_scope("safe", false).unwrap(),
            DiagnoseScope::Safe
        );
        assert_eq!(
            parse_diagnose_scope("full", false).unwrap(),
            DiagnoseScope::Full
        );
        assert_eq!(
            parse_diagnose_scope("raw", false).unwrap(),
            DiagnoseScope::Raw
        );
        // --no-redact 是显式的 raw 意图：覆盖任何 scope 参数
        assert_eq!(
            parse_diagnose_scope("safe", true).unwrap(),
            DiagnoseScope::Raw
        );
        assert!(parse_diagnose_scope("everything", false).is_err());
    }

    /// RIL-058：订阅/URL 类 JSON 出口——嵌套与数组里的 url 字段剥除
    /// 秘密（userinfo 凭证 + token/password 类查询参数），非 URL 字段
    /// 原样。
    #[test]
    fn subscription_json_urls_strip_secrets() {
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{
                "items": [
                    {"name": "provider-a", "url": "https://user:secret@example.com/sub?token=abc&flag=1"},
                    {"nested": {"subscription_url": "https://host.example/path"}},
                    {"name": "plain", "endpoint": "http://10.0.0.1:9090"}
                ]
            }"#,
        )
        .unwrap();
        strip_json_url_secrets(&mut v);
        let items = v["items"].as_array().unwrap();
        let stripped = items[0]["url"].as_str().unwrap();
        assert!(!stripped.contains("user:secret"), "userinfo 凭证剥除");
        assert!(!stripped.contains("token=abc"), "token 查询参数剥除");
        assert!(stripped.starts_with("https://example.com"), "剥除后仍可读");
        // 无秘密的 URL 原样；非 URL 字段不受影响
        assert_eq!(
            items[1]["nested"]["subscription_url"],
            "https://host.example/path"
        );
        assert_eq!(items[2]["endpoint"], "http://10.0.0.1:9090");
        assert_eq!(items[2]["name"], "plain");
    }

    /// RIL-058：错误日志/事件流出——私钥块与 key=value 秘密对逐行
    /// 剥除，行数保持（结构不丢）。
    #[test]
    fn diagnostic_log_lines_strip_secrets() {
        let raw = "connect failed to 10.0.0.1:443\npassword=hunter2 rejected\n-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\ndone";
        let clean = sanitize_diagnostic_log(raw);
        assert!(!clean.contains("hunter2"), "key=value 秘密对剥除");
        assert!(!clean.contains("PRIVATE KEY"), "私钥块剥除");
        assert!(clean.contains("connect failed"), "非秘密内容保留");
        assert!(clean.contains("done"), "块外尾行保留");
        assert!(
            clean.lines().count() <= raw.lines().count(),
            "PEM 块塌缩为占位——行数只减不增"
        );
    }

    /// RIL-060：URL 拼装——base 尾斜杠剥除；空 base 显式拒绝
    #[test]
    fn trace_query_url_builds_and_rejects_empty_base() {
        let url = trace_query_url("http://127.0.0.1:9090/", "/trace/flows").expect("合法 base");
        assert_eq!(url, "http://127.0.0.1:9090/trace/flows?");
        assert!(trace_query_url("", "/trace/flows").is_err(), "空 base 拒绝");
    }

    /// RIL-060：过滤参数客户端校验——非法值不发请求
    #[test]
    fn trace_filter_validation_rejects_unknown_values() {
        assert!(validate_trace_filter(Some("active"), Some("association")).is_ok());
        assert!(validate_trace_filter(None, Some("stream")).is_ok());
        assert!(
            validate_trace_filter(Some("open"), None).is_err(),
            "state 非法"
        );
        assert!(
            validate_trace_filter(None, Some("tcp")).is_err(),
            "origin 非法"
        );
    }

    /// RIL-060：显式缺席提取——只认 found:false 信封；code/note/collector
    /// 三件齐全
    #[test]
    fn trace_absence_extracts_found_false_envelope() {
        let absent = serde_json::json!({
            "schema_version": 1,
            "found": false,
            "trace": null,
            "absence": {
                "code": "query.flow.unknown",
                "note": "no record is not evidence of no traffic",
                "collector": {"traces_admitted": 0}
            }
        });
        let answer = trace_absence(&absent).expect("found:false 是缺席");
        assert_eq!(answer.code, "query.flow.unknown");
        assert_eq!(answer.note, "no record is not evidence of no traffic");
        assert_eq!(answer.collector["traces_admitted"], 0);

        let found = serde_json::json!({"schema_version": 1, "found": true, "trace": {}});
        assert!(trace_absence(&found).is_none(), "found:true 不是缺席");
    }

    /// RIL-060：列表文本——空页不造行；有页逐行 + 总数尾行
    #[test]
    fn render_trace_list_handles_empty_and_populated_pages() {
        let empty = serde_json::json!({
            "schema_version": 1, "total_matching": 0, "offset": 0, "limit": 20, "items": []
        });
        let out = render_trace_list(&empty);
        assert!(out.contains("无匹配轨迹"), "空页显式说明");

        let page = serde_json::json!({
            "schema_version": 1, "total_matching": 2, "offset": 1, "limit": 20,
            "items": [
                {"flow": "f-b", "origin": "association", "state": "closed",
                 "events": 3, "generation": "gen-9", "last_code": "stream.closed"},
                {"flow": "f-a", "origin": "stream", "state": "active",
                 "events": 1, "generation": "gen-1", "last_code": null}
            ]
        });
        let out = render_trace_list(&page);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "FLOW\tORIGIN\tSTATE\tEVENTS\tGENERATION\tLAST");
        assert!(lines[1].starts_with("f-b\tassociation\tclosed\t3\tgen-9\tstream.closed"));
        assert!(
            lines[2].starts_with("f-a\tstream\tactive\t1\tgen-1\t-"),
            "null last_code 占位 -"
        );
        assert!(
            out.contains("共 2 条匹配，offset=1"),
            "总数与 offset 诚实回显"
        );
    }

    /// RIL-060：详情/事件文本——事件行携带 seq/stage/code/evidence/attempt，
    /// attempt 缺省占位 -
    #[test]
    fn render_trace_flow_and_events_lines() {
        let found = serde_json::json!({
            "schema_version": 1, "found": true,
            "trace": {
                "flow": "f-1", "origin": "stream", "generation": "gen-1", "closed": false,
                "events": [
                    {"seq": 0, "stage": "takeover", "attempt": null, "code": "trace.takeover",
                     "evidence": "observed", "monotonic_ms": 1000, "wall_ms": 1,
                     "detail": "tcp 8.8.8.8:443"},
                    {"seq": 1, "stage": "attempt", "attempt": 2, "code": "outbound.established",
                     "evidence": "observed", "monotonic_ms": 1010, "wall_ms": 11,
                     "detail": "node A"}
                ]
            }
        });
        let out = render_trace_flow(&found);
        assert!(out.starts_with("flow f-1 origin=stream generation=gen-1 closed=false\n"));
        assert!(out.contains("#0 takeover trace.takeover evidence=observed attempt=- mono=1000 wall=1 tcp 8.8.8.8:443"));
        assert!(out.contains(
            "#1 attempt outbound.established evidence=observed attempt=2 mono=1010 wall=11 node A"
        ));

        let events = serde_json::json!({
            "schema_version": 1, "flow": "f-1", "from_seq": 1,
            "events": [{"seq": 1, "stage": "attempt", "attempt": 2,
                        "code": "outbound.established", "evidence": "observed",
                        "monotonic_ms": 1010, "wall_ms": 11, "detail": "node A"}]
        });
        let out = render_trace_events(&events);
        assert!(out.starts_with("flow f-1 from_seq=1 count=1\n"));
        assert!(out.contains("#1 attempt outbound.established"));
    }

    /// RIL-060：缺席文本——稳定码 + 固定说明 + 采集计数齐全
    #[test]
    fn render_trace_absent_carries_code_note_and_collector() {
        let answer = TraceAbsentAnswer {
            code: "query.flow.unknown".into(),
            note: "no record is not evidence of no traffic".into(),
            collector: serde_json::json!({"traces_admitted": 7}),
        };
        let out = render_trace_absent("f-ghost", &answer);
        assert!(out.starts_with("flow f-ghost: 显式缺席（query.flow.unknown）"));
        assert!(out.contains("no record is not evidence of no traffic"));
        assert!(out.contains("\"traces_admitted\":7"), "计数快照可见");
    }

    // -------------------------------------------------------------------
    // Probe CLI 纯辅助（RIL-061）
    // -------------------------------------------------------------------

    /// 提交用法校验：kind/参数对应 + addr 客户端预解析 + 载荷为正
    #[test]
    fn probe_submit_validation_maps_kind_to_body() {
        let dns = validate_probe_submit("dns", Some(" example.invalid "), None, 64).unwrap();
        assert_eq!(dns, r#"{"host":"example.invalid","kind":"dns"}"#);

        let connect = validate_probe_submit("connect", None, Some("192.0.2.1:443"), 64).unwrap();
        assert_eq!(connect, r#"{"addr":"192.0.2.1:443","kind":"connect"}"#);

        let echo = validate_probe_submit("udp-echo", None, Some("192.0.2.1:53"), 128).unwrap();
        assert_eq!(
            echo,
            r#"{"addr":"192.0.2.1:53","kind":"udp_echo","payload_len":128}"#
        );

        // kind 与参数错配 / 非法值 → 不发请求
        assert!(validate_probe_submit("dns", None, None, 64).is_err());
        assert!(validate_probe_submit("dns", Some("  "), None, 64).is_err());
        assert!(validate_probe_submit("connect", None, None, 64).is_err());
        assert!(validate_probe_submit("connect", None, Some("no-port"), 64).is_err());
        assert!(validate_probe_submit("udp-echo", None, Some("127.0.0.1:53"), 0).is_err());
        assert!(validate_probe_submit("handshake", None, Some("127.0.0.1:1"), 64).is_err());
    }

    /// 作业 ID 手工解析：非负整数通过、负数/非数字拒绝（退出码 1 路径，
    /// 不与缺席码 2 冲突）
    #[test]
    fn probe_id_parses_non_negative_integers_only() {
        assert_eq!(parse_probe_id("7").unwrap(), 7);
        assert_eq!(parse_probe_id("0").unwrap(), 0);
        assert!(parse_probe_id("-1").is_err());
        assert!(parse_probe_id("abc").is_err());
        assert!(parse_probe_id("").is_err());
    }

    /// URL 拼装：尾斜杠归一 + 空地址拒绝
    #[test]
    fn probe_url_trims_base_slash() {
        assert_eq!(
            probe_url("http://127.0.0.1:9090/", "/probe").unwrap(),
            "http://127.0.0.1:9090/probe"
        );
        assert!(probe_url("", "/probe").is_err());
        assert!(probe_url("///", "/probe").is_err());
    }

    /// 单作业渲染：头部 + 失败/测量三路标记分列（丢包由计数可算、
    /// 无回应 rtt=none 不造数、failure none/null 分明）
    #[test]
    fn probe_job_renders_measurements_separately() {
        let completed = serde_json::json!({
            "schema_version": 1,
            "found": true,
            "job": {
                "id": 3,
                "target": "udp-echo:127.0.0.1:53?len=64",
                "state": "completed",
                "submitted_unix_ms": 1760000000000u64,
                "finished_unix_ms": 1760000000040u64,
                "outcome": {
                    "measurement": "udp_echo",
                    "sent": 3,
                    "replies": 1,
                    "payload_len": 64,
                    "loss_ratio": 0.6667,
                    "rtt_ms": 9
                },
                "failure": null
            }
        });
        let out = render_probe_job(&completed);
        assert!(
            out.contains("job 3 udp-echo:127.0.0.1:53?len=64\n"),
            "{out}"
        );
        assert!(out.contains("state=completed submitted=1760000000000 finished=1760000000040"));
        assert!(out.contains("failure: none"));
        assert!(
            out.contains("measurement=udp_echo sent=3 replies=1 loss=0.6667 rtt=9ms payload=64B")
        );

        // 无回应：rtt=none（不造数）；丢失率 none→sent=0 场景 null
        let silent = serde_json::json!({
            "job": {
                "id": 1,
                "target": "udp-echo:127.0.0.1:53?len=32",
                "state": "completed",
                "submitted_unix_ms": 1,
                "finished_unix_ms": 2,
                "outcome": {
                    "measurement": "udp_echo",
                    "sent": 3,
                    "replies": 0,
                    "payload_len": 32,
                    "loss_ratio": 1.0,
                    "rtt_ms": null
                },
                "failure": null
            }
        });
        let out = render_probe_job(&silent);
        assert!(out.contains("rtt=none"), "{out}");
        assert!(out.contains("loss=1"));

        // 失败态：failure 带稳定码 + detail，outcome 显式 none（无测量）
        let failed = serde_json::json!({
            "job": {
                "id": 2,
                "target": "connect:192.0.2.1:443",
                "state": "failed",
                "submitted_unix_ms": 1,
                "finished_unix_ms": 2,
                "outcome": null,
                "failure": {"code": "probe.exec.failed", "detail": "tcp connect failed: refused"}
            }
        });
        let out = render_probe_job(&failed);
        assert!(out.contains("state=failed"));
        assert!(out.contains("failure: probe.exec.failed tcp connect failed: refused"));
        assert!(out.contains("outcome: none（未完成/失败/取消无测量）"));

        // dns 测量：解析地址逐个列出 + rtt
        let dns = serde_json::json!({
            "job": {
                "id": 4,
                "target": "dns:example.invalid",
                "state": "completed",
                "submitted_unix_ms": 1,
                "finished_unix_ms": 2,
                "outcome": {
                    "measurement": "dns",
                    "resolved": ["192.0.2.1", "2001:db8::1"],
                    "rtt_ms": 5
                },
                "failure": null
            }
        });
        let out = render_probe_job(&dns);
        assert!(
            out.contains("measurement=dns resolved=192.0.2.1,2001:db8::1 rtt=5ms"),
            "{out}"
        );
    }

    /// 列表渲染：限额行 + 表头 + 逐行；空列表不造行
    #[test]
    fn probe_list_renders_limits_and_rows() {
        let empty = serde_json::json!({
            "schema_version": 1,
            "limits": {"max_active": 4, "job_timeout_ms": 5000,
                       "udp_payload_max_bytes": 512, "byte_budget": 65536},
            "jobs": []
        });
        let out = render_probe_list(&empty);
        assert!(out.contains("limits: max_active=4 timeout=5000ms udp_max=512B budget=65536B"));
        assert!(out.contains("无探测作业（probe submit 显式发起）"));

        let one = serde_json::json!({
            "schema_version": 1,
            "limits": {"max_active": 2, "job_timeout_ms": 3000,
                       "udp_payload_max_bytes": 256, "byte_budget": 32768},
            "jobs": [
                {"id": 0, "target": "connect:127.0.0.1:443", "state": "completed",
                 "submitted_unix_ms": 1760000000000u64, "finished_unix_ms": 1760000000005u64},
                {"id": 1, "target": "dns:example.invalid", "state": "running",
                 "submitted_unix_ms": 1760000000010u64, "finished_unix_ms": null}
            ]
        });
        let out = render_probe_list(&one);
        assert!(out.contains("ID\tTARGET\tSTATE\tSUBMITTED\tFINISHED\n"));
        assert!(out.contains("0\tconnect:127.0.0.1:443\tcompleted\t1760000000000\t1760000000005"));
        assert!(out.contains("1\tdns:example.invalid\trunning\t1760000000010\t-"));
    }

    /// 错误信封可读形：code+context 提取；非 JSON 原文带出
    #[test]
    fn probe_error_envelope_renders_code_and_fallback() {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "error": {"code": "probe.target.out_of_scope", "context": "connect:192.0.2.1:443 not registered"}
        });
        let out = render_probe_error(&envelope, "raw");
        assert_eq!(
            out,
            "probe.target.out_of_scope: connect:192.0.2.1:443 not registered"
        );

        let out = render_probe_error(&serde_json::Value::Null, "probe disabled plain text");
        assert_eq!(out, "probe disabled plain text");
    }
}
