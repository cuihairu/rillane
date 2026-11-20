//! 订阅格式转换器

use anyhow::{anyhow, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use tracing::{debug, info, warn};
use url::Url;

use crate::clash::{
    ClashConfig, ClashConverter, ClashProxy, ClashProxyGroup, ClashProxyGroupType, ClashProxyType,
    ClashRule,
};
use crate::rillane_dsl::RillaneDslConverter;
use crate::{Subscription, SubscriptionType};

/// 通用转换器
pub struct SubscriptionConverter {
    /// Clash 转换器
    clash_converter: ClashConverter,
    /// Rillane DSL 转换器
    rillane_converter: RillaneDslConverter,
    /// 转换选项
    options: ConversionOptions,
}

/// 订阅导入模式（RIL-016 本地策略所有权）。FullPolicy = 整份策略照收
/// （存量行为）；NodesOnly = 只收出口节点——组、规则、规则集/provider
/// 声明与用户选择面全部不带入（分流策略/游戏规则归用户本地配置，订阅
/// 只供货节点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportMode {
    #[default]
    FullPolicy,
    NodesOnly,
}

/// 转换选项
#[derive(Debug, Clone)]
pub struct ConversionOptions {
    /// 导入模式（RIL-016）：缺省 FullPolicy（存量行为零差异）
    pub import_mode: ImportMode,
    /// 是否启用节点名称规范化
    pub normalize_node_names: bool,
    /// 是否过滤无效节点
    pub filter_invalid_nodes: bool,
    /// 是否过滤重复节点
    pub filter_duplicate_nodes: bool,
    /// 是否启用组名称规范化
    pub normalize_group_names: bool,
    /// 是否保留原始名称
    pub preserve_original_names: bool,
    /// 自定义节点名称前缀
    pub node_name_prefix: String,
    /// 自定义组名称前缀
    pub group_name_prefix: String,
    /// 自定义规则名称前缀
    pub rule_name_prefix: String,
    /// 最大节点数
    pub max_nodes: Option<usize>,
    /// 最大组数
    pub max_groups: Option<usize>,
    /// 严格导入：任何语义损失（不支持的节点类型/组/规则、无效节点）整体
    /// 拒绝而不产出半份配置；宽松（缺省）继续导入但损失清单进 warnings
    /// （RIL-093）
    pub strict_import: bool,
}

impl Default for ConversionOptions {
    fn default() -> Self {
        Self {
            import_mode: ImportMode::FullPolicy,
            normalize_node_names: true,
            filter_invalid_nodes: true,
            filter_duplicate_nodes: true,
            normalize_group_names: true,
            preserve_original_names: false,
            node_name_prefix: String::new(),
            group_name_prefix: String::new(),
            rule_name_prefix: String::new(),
            max_nodes: None,
            max_groups: None,
            strict_import: false,
        }
    }
}

/// 转换结果
#[derive(Debug, Clone)]
pub struct ConversionResult {
    /// 转换后的配置
    pub config: rillane_config::RillaneConfig,
    /// 转换统计信息
    pub stats: ConversionStats,
    /// 转换警告
    pub warnings: Vec<String>,
}

/// 转换统计信息
#[derive(Debug, Clone, Default)]
pub struct ConversionStats {
    /// 输入统计
    pub input: InputStats,
    /// 输出统计
    pub output: OutputStats,
}

/// 输入统计
#[derive(Debug, Clone, Default)]
pub struct InputStats {
    /// 订阅类型
    pub subscription_type: Option<SubscriptionType>,
    /// 原始节点数
    pub original_nodes: usize,
    /// 原始组数
    pub original_groups: usize,
    /// 原始规则数
    pub original_rules: usize,
    /// 原始配置大小（字节）
    pub original_size_bytes: usize,
}

/// 输出统计
#[derive(Debug, Clone, Default)]
pub struct OutputStats {
    /// 有效节点数
    pub valid_nodes: usize,
    /// 过滤的节点数
    pub filtered_nodes: usize,
    /// 重复的节点数
    pub duplicate_nodes: usize,
    /// 转换的组数
    pub converted_groups: usize,
    /// 转换的规则数
    pub converted_rules: usize,
    /// 生成配置大小（字节）
    pub converted_size_bytes: usize,
    /// 转换耗时（毫秒）
    pub conversion_duration_ms: u64,
}

impl SubscriptionConverter {
    /// 创建新的转换器
    pub fn new() -> Self {
        Self::with_options(ConversionOptions::default())
    }

    /// 使用自定义选项创建转换器
    pub fn with_options(options: ConversionOptions) -> Self {
        let clash_converter = ClashConverter::new()
            .with_node_prefix(options.node_name_prefix.clone())
            .with_group_prefix(options.group_name_prefix.clone())
            .with_rule_prefix(options.rule_name_prefix.clone())
            .with_filtering(options.filter_invalid_nodes)
            .with_strict(options.strict_import);

        let rillane_converter = RillaneDslConverter::new()
            .with_validation(true)
            .with_filtering(options.filter_invalid_nodes);

        Self {
            clash_converter,
            rillane_converter,
            options,
        }
    }

    /// 自动检测并转换订阅内容
    pub async fn auto_convert(
        &self,
        subscription: &Subscription,
        content: &str,
    ) -> Result<ConversionResult> {
        let start_time = std::time::Instant::now();

        // 检测订阅类型
        let detected_type = subscription.r#type.unwrap_or_else(|| {
            if content.is_empty() {
                SubscriptionType::Custom
            } else {
                self.detect_subscription_type(content)
            }
        });

        info!(
            target: "rillane::subscription::converter",
            name = %subscription.name,
            detected_type = %detected_type,
            "开始转换订阅"
        );

        // 根据类型进行转换
        let mut result = match detected_type {
            SubscriptionType::Clash => self.convert_clash(content).await?,
            SubscriptionType::Rillane => self.convert_rillane_dsl(content).await?,
            SubscriptionType::V2Ray => self.convert_v2ray(content).await?,
            SubscriptionType::Custom => self.convert_custom(content).await?,
        };

        // RIL-016 NodesOnly：只收出口节点。组/规则/规则集/provider 声明/
        // 用户选择面整块剥离并显式登记剥离条数——分流策略与游戏规则归
        // 用户本地配置，订阅载荷不得携带策略覆盖它
        if self.options.import_mode == ImportMode::NodesOnly {
            let groups = result.config.routing.groups.len();
            let rules = result.config.routing.rules.len();
            let rule_sets = result.config.routing.rule_sets.len();
            let rule_providers = result.config.routing.rule_providers.len();
            let proxy_providers = result.config.routing.proxy_providers.len();
            let selections = result.config.routing.selections.len();
            result.config.routing.groups.clear();
            result.config.routing.rules.clear();
            result.config.routing.rule_sets.clear();
            result.config.routing.rule_providers.clear();
            result.config.routing.proxy_providers.clear();
            result.config.routing.selections.clear();
            result.warnings.push(format!(
                "nodes-only 导入：仅保留 {} 个出口节点，剥离组 {}、规则 {}、规则集 {}、规则 provider 声明 {}、代理 provider 声明 {}、用户选择 {}（策略归本地配置）",
                result.config.egress.len(),
                groups,
                rules,
                rule_sets,
                rule_providers,
                proxy_providers,
                selections
            ));
            result.stats.output.converted_groups = 0;
            result.stats.output.converted_rules = 0;
        }

        let duration = start_time.elapsed().as_millis() as u64;

        // 更新统计信息
        let mut final_result = result;
        final_result.stats.output.conversion_duration_ms = duration;

        info!(
            target: "rillane::subscription::converter",
            name = %subscription.name,
            type = %detected_type,
            duration_ms = duration,
            nodes = final_result.stats.output.valid_nodes,
            groups = final_result.stats.output.converted_groups,
            rules = final_result.stats.output.converted_rules,
            warnings = final_result.warnings.len(),
            "订阅转换完成"
        );

        Ok(final_result)
    }

    /// 检测订阅类型
    pub fn detect_subscription_type(&self, content: &str) -> SubscriptionType {
        // 去除注释和空行
        let cleaned = self.clean_content(content);

        // 检查 Clash 配置
        if cleaned.contains("proxies:") && cleaned.contains("proxy-groups:") {
            debug!(
                target: "rillane::subscription::converter",
                "检测到 Clash 配置格式"
            );
            return SubscriptionType::Clash;
        }

        // 检查 Rillane DSL
        if cleaned.contains("version:") && cleaned.contains("nodes:") {
            debug!(
                target: "rillane::subscription::converter",
                "检测到 Rillane DSL 格式"
            );
            return SubscriptionType::Rillane;
        }

        // 检查 V2Ray 订阅（Base64 编码的链接列表）
        let lines: Vec<&str> = cleaned.lines().collect();
        let v2ray_lines = lines
            .iter()
            .filter(|line| {
                let line = line.trim();
                line.starts_with("vmess://")
                    || line.starts_with("vless://")
                    || line.starts_with("trojan://")
                    || line.starts_with("ss://")
                    || line.starts_with("hysteria2://")
                    || line.starts_with("hy2://")
                    || line.starts_with("socks5://")
                    || line.starts_with("socks://")
                    || line.starts_with("http://")
                    || line.starts_with("https://")
                    || (line.len() > 50 && self.looks_like_base64(line))
            })
            .count();

        if v2ray_lines > 0 && v2ray_lines as f64 / lines.len() as f64 > 0.5 {
            debug!(
                target: "rillane::subscription::converter",
                v2ray_lines = v2ray_lines,
                total_lines = lines.len(),
                "检测到 V2Ray 订阅格式"
            );
            return SubscriptionType::V2Ray;
        }

        // 默认为自定义格式
        debug!(
            target: "rillane::subscription::converter",
            "未知格式，标记为自定义"
        );
        SubscriptionType::Custom
    }

    /// 清理内容
    fn clean_content(&self, content: &str) -> String {
        content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    None
                } else {
                    Some(line)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 转换 Clash 配置
    async fn convert_clash(&self, content: &str) -> Result<ConversionResult> {
        debug!(
            target: "rillane::subscription::converter",
            "开始转换 Clash 配置"
        );

        // 解析 Clash 配置
        let clash_config = self
            .clash_converter
            .parse(content)
            .context("解析 Clash 配置失败")?;

        let mut warnings = Vec::new();

        // 统计原始数据
        let original_nodes = clash_config.proxies.len();
        let original_groups = clash_config.proxy_groups.len();
        let original_rules = clash_config.rules.len();

        // 过滤和去重节点
        let filtered_proxies = self.filter_and_dedup_proxies(&clash_config.proxies, &mut warnings);

        if filtered_proxies.len() != original_nodes {
            warnings.push(format!(
                "节点过滤：原始 {} 个，过滤后 {} 个",
                original_nodes,
                filtered_proxies.len()
            ));
        }

        // 创建修改后的 Clash 配置
        let mut filtered_config = clash_config.clone();
        filtered_config.proxies = filtered_proxies;

        // 转换为 Rillane 配置：损失清单进 warnings，丢弃/降级内容可见、
        // 不伪装成无损成功；严格导入时清单非空在上游直接整体拒绝（RIL-093）
        let (rillane_config, report) = self
            .clash_converter
            .convert_to_rillane_with_report(&filtered_config)
            .context("转换 Clash 配置为 Rillane 配置失败")?;
        if !report.is_empty() {
            warnings.push(format!("有损转换报告:\n{}", report.summary()));
        }

        let stats = ConversionStats {
            input: InputStats {
                subscription_type: Some(SubscriptionType::Clash),
                original_nodes,
                original_groups,
                original_rules,
                original_size_bytes: content.len(),
            },
            output: OutputStats {
                valid_nodes: rillane_config.egress.len(),
                filtered_nodes: original_nodes - rillane_config.egress.len(),
                duplicate_nodes: 0, // 在 filter_and_dedup_proxies 中计算
                converted_groups: rillane_config.routing.groups.len(),
                converted_rules: rillane_config.routing.rules.len(),
                converted_size_bytes: serde_yaml::to_string(&rillane_config)
                    .unwrap_or_default()
                    .len(),
                conversion_duration_ms: 0, // 在调用方设置
            },
        };

        Ok(ConversionResult {
            config: rillane_config,
            stats,
            warnings,
        })
    }

    /// 转换 Rillane DSL 配置
    async fn convert_rillane_dsl(&self, content: &str) -> Result<ConversionResult> {
        debug!(
            target: "rillane::subscription::converter",
            "开始转换 Rillane DSL 配置"
        );

        // 解析 Rillane DSL 配置
        let rillane_dsl_config = self
            .rillane_converter
            .parse(content)
            .context("解析 Rillane DSL 配置失败")?;

        let mut warnings = Vec::new();

        // 统计原始数据
        let original_nodes = rillane_dsl_config.nodes.len();
        let original_groups = rillane_dsl_config.groups.len();
        let original_rules = rillane_dsl_config.rules.len();

        // 过滤和去重节点
        let filtered_nodes =
            self.filter_and_dedup_rillane_nodes(&rillane_dsl_config.nodes, &mut warnings);

        if filtered_nodes.len() != original_nodes {
            warnings.push(format!(
                "节点过滤：原始 {} 个，过滤后 {} 个",
                original_nodes,
                filtered_nodes.len()
            ));
        }

        // 创建修改后的 Rillane DSL 配置
        let mut filtered_config = rillane_dsl_config.clone();
        filtered_config.nodes = filtered_nodes;

        // 转换为标准 Rillane 配置
        let rillane_config = self
            .rillane_converter
            .convert_to_rillane(&filtered_config)
            .context("转换 Rillane DSL 为标准 Rillane 配置失败")?;

        let stats = ConversionStats {
            input: InputStats {
                subscription_type: Some(SubscriptionType::Rillane),
                original_nodes,
                original_groups,
                original_rules,
                original_size_bytes: content.len(),
            },
            output: OutputStats {
                valid_nodes: rillane_config.egress.len(),
                filtered_nodes: original_nodes - rillane_config.egress.len(),
                duplicate_nodes: 0,
                converted_groups: rillane_config.routing.groups.len(),
                converted_rules: rillane_config.routing.rules.len(),
                converted_size_bytes: serde_yaml::to_string(&rillane_config)
                    .unwrap_or_default()
                    .len(),
                conversion_duration_ms: 0,
            },
        };

        Ok(ConversionResult {
            config: rillane_config,
            stats,
            warnings,
        })
    }

    /// 转换 V2Ray 订阅
    async fn convert_v2ray(&self, content: &str) -> Result<ConversionResult> {
        debug!(
            target: "rillane::subscription::converter",
            "开始转换 V2Ray 订阅"
        );

        let mut warnings = Vec::new();
        let mut nodes = Vec::new();

        let cleaned = self.clean_content(content);
        let expanded_lines = self.expand_v2ray_payload(&cleaned, &mut warnings);

        for (index, line) in expanded_lines.iter().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match self.parse_v2ray_link(line) {
                Ok(node) => nodes.push(node),
                Err(err) => warnings.push(format!("行 {}：{}", index + 1, err)),
            }
        }

        // G1-6（2026-11-10 拍板改 M1 拒绝策略）：REALITY/flow 节点不再在
        // 本层跳过——parse_v2ray_link 捕获的 pbk/sid/flow 随节点保留进
        // EgressConfig::Vless；不支持面在拨号期点名拒绝（节点级失败不阻塞
        // 同订阅其余节点）。

        // 过滤和去重
        let filtered_nodes = self.filter_and_dedup_v2ray_nodes(nodes, &mut warnings);
        let node_names: Vec<String> = filtered_nodes.iter().map(|p| p.name.clone()).collect();

        // 创建 Clash 配置格式然后转换
        let clash_config = ClashConfig {
            proxies: filtered_nodes,
            proxy_groups: vec![ClashProxyGroup {
                name: "auto".to_string(),
                group_type: ClashProxyGroupType::UrlTest,
                proxies: node_names,
                use_providers: Vec::new(),
                url: Some("http://www.gstatic.com/generate_204".to_string()),
                interval: Some(300),
                strategy: None,
            }],
            rules: vec![ClashRule::Match {
                target: "auto".to_string(),
            }],
            dns: None,
            mixed_port: None,
            allow_lan: false,
            bind_address: None,
            log_level: "info".to_string(),
            external_controller: None,
            proxy_providers: Default::default(),
            rule_providers: Default::default(),
        };

        // 使用 Clash 转换器
        let rillane_config = self
            .clash_converter
            .convert_to_rillane(&clash_config)
            .context("转换 V2Ray 配置为 Rillane 配置失败")?;

        let original_lines = content.lines().count();
        let stats = ConversionStats {
            input: InputStats {
                subscription_type: Some(SubscriptionType::V2Ray),
                original_nodes: original_lines,
                original_groups: 0,
                original_rules: 0,
                original_size_bytes: content.len(),
            },
            output: OutputStats {
                valid_nodes: rillane_config.egress.len(),
                filtered_nodes: original_lines - rillane_config.egress.len(),
                duplicate_nodes: 0,
                converted_groups: rillane_config.routing.groups.len(),
                converted_rules: rillane_config.routing.rules.len(),
                converted_size_bytes: serde_yaml::to_string(&rillane_config)
                    .unwrap_or_default()
                    .len(),
                conversion_duration_ms: 0,
            },
        };

        Ok(ConversionResult {
            config: rillane_config,
            stats,
            warnings,
        })
    }

    /// 转换自定义格式
    async fn convert_custom(&self, _content: &str) -> Result<ConversionResult> {
        warn!(
            target: "rillane::subscription::converter",
            "自定义格式暂不支持转换"
        );

        Err(anyhow!("自定义格式暂不支持自动转换，请手动配置"))
    }

    /// 检查内容是否看起来像 Base64
    fn looks_like_base64(&self, content: &str) -> bool {
        let trimmed = content.trim();
        // A conservative heuristic:
        // - accept both padded and unpadded Base64 strings
        // - allow URL-safe alphabet as well
        trimmed.len() >= 8
            && trimmed.len() % 4 != 1
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
    }

    /// 解析 V2Ray 链接
    fn parse_v2ray_link(&self, link: &str) -> Result<ClashProxy> {
        let link = link.trim();
        if link.is_empty() {
            return Err(anyhow!("空链接"));
        }

        if let Some(rest) = link.strip_prefix("vmess://") {
            return self.parse_vmess(rest);
        }
        if link.starts_with("socks5://") || link.starts_with("socks://") {
            return self.parse_socks5(link);
        }
        if link.starts_with("http://") || link.starts_with("https://") {
            return self.parse_http_proxy(link);
        }
        if link.starts_with("vless://") {
            return self.parse_vless(link);
        }
        if link.starts_with("trojan://") {
            return self.parse_trojan(link);
        }
        if link.starts_with("ss://") {
            return self.parse_ss(link);
        }
        if link.starts_with("hysteria2://") || link.starts_with("hy2://") {
            return self.parse_hysteria2(link);
        }

        Err(anyhow!("不支持的协议"))
    }

    fn expand_v2ray_payload(&self, content: &str, warnings: &mut Vec<String>) -> Vec<String> {
        let cleaned = content.trim();
        if cleaned.is_empty() {
            return vec![];
        }

        // Many V2Ray subscriptions are a single base64 blob that decodes into newline-separated links.
        if self.looks_like_base64(cleaned) && !cleaned.contains("://") {
            match self.decode_base64_to_string(cleaned) {
                Ok(decoded) => return decoded.lines().map(|s| s.trim().to_string()).collect(),
                Err(e) => warnings.push(format!("订阅内容看似 Base64，但解码失败：{e}")),
            }
        }

        let mut out = Vec::new();
        for line in cleaned.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Some providers encode each line as base64.
            if self.looks_like_base64(line) && !line.contains("://") {
                match self.decode_base64_to_string(line) {
                    Ok(decoded) => out.extend(decoded.lines().map(|s| s.trim().to_string())),
                    Err(_) => out.push(line.to_string()),
                }
            } else {
                out.push(line.to_string());
            }
        }

        out
    }

    fn decode_base64_to_string(&self, input: &str) -> Result<String> {
        let bytes = self.decode_base64_bytes(input)?;
        String::from_utf8(bytes).context("Base64 解码成功但不是有效的 UTF-8")
    }

    fn decode_base64_bytes(&self, input: &str) -> Result<Vec<u8>> {
        let s = input.trim();
        if s.is_empty() {
            return Err(anyhow!("空 Base64 字符串"));
        }

        if let Ok(v) = BASE64.decode(s) {
            return Ok(v);
        }
        if let Ok(v) = URL_SAFE.decode(s) {
            return Ok(v);
        }
        if let Ok(v) = STANDARD_NO_PAD.decode(s) {
            return Ok(v);
        }
        if let Ok(v) = URL_SAFE_NO_PAD.decode(s) {
            return Ok(v);
        }

        // Try adding padding if the input looks unpadded.
        let mut padded = s.to_string();
        let rem = padded.len() % 4;
        if rem != 0 {
            padded.extend(std::iter::repeat_n('=', 4 - rem));
            if let Ok(v) = BASE64.decode(&padded) {
                return Ok(v);
            }
            if let Ok(v) = URL_SAFE.decode(&padded) {
                return Ok(v);
            }
        }

        Err(anyhow!("Base64 解码失败"))
    }

    fn parse_vmess(&self, base64_payload: &str) -> Result<ClashProxy> {
        let payload = base64_payload.trim().trim_start_matches("//").trim();
        let decoded = self
            .decode_base64_to_string(payload)
            .context("VMess Base64 解码失败")?;

        let v: serde_json::Value = serde_json::from_str(&decoded).context("VMess JSON 解析失败")?;
        let get_str = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
        };

        let name = get_str("ps")
            .or_else(|| get_str("remark"))
            .unwrap_or("vmess")
            .to_string();

        let server = get_str("add")
            .or_else(|| get_str("server"))
            .ok_or_else(|| anyhow!("VMess 缺少 server/add"))?
            .to_string();

        let port: u16 = get_str("port")
            .ok_or_else(|| anyhow!("VMess 缺少 port"))?
            .parse()
            .context("VMess port 非法")?;

        let uuid = get_str("id")
            .or_else(|| get_str("uuid"))
            .ok_or_else(|| anyhow!("VMess 缺少 id/uuid"))?
            .to_string();

        let network = get_str("net").map(|s| s.to_string());
        let path = get_str("path").map(|s| s.to_string());
        let host = get_str("host").map(|s| s.to_string());
        let encrypt = get_str("scy")
            .or_else(|| get_str("security"))
            .or_else(|| get_str("cipher"))
            .map(|s| s.to_string());

        let tls_val = get_str("tls").unwrap_or("");
        let tls = !tls_val.is_empty() && tls_val != "none";

        let servername = get_str("sni")
            .or_else(|| get_str("servername"))
            .map(|s| s.to_string());

        let allow_insecure = get_str("allowInsecure")
            .or_else(|| get_str("allowinsecure"))
            .or_else(|| get_str("insecure"))
            .unwrap_or("0");
        let skip_cert_verify = matches!(allow_insecure, "1" | "true" | "True" | "TRUE");

        let alpn = get_str("alpn").map(parse_alpn).unwrap_or_default();

        Ok(ClashProxy {
            name,
            proxy_type: ClashProxyType::Vmess,
            server,
            port,
            uuid: Some(uuid),
            encrypt,
            network,
            path,
            host,
            tls,
            skip_cert_verify,
            alpn,
            servername,
            fingerprint: get_str("fp").map(|s| s.to_string()),
            ..Default::default()
        })
    }

    fn parse_socks5(&self, link: &str) -> Result<ClashProxy> {
        let (base, name) = split_fragment(link);
        let url = Url::parse(base).context("SOCKS5 URL 解析失败")?;
        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("SOCKS5 缺少 host"))?
            .to_string();
        let port = url.port().unwrap_or(1080);

        let username = (!url.username().is_empty()).then(|| url.username().to_string());
        let password = url.password().map(|s| s.to_string());

        Ok(ClashProxy {
            name: name.unwrap_or_else(|| "socks5".to_string()),
            proxy_type: ClashProxyType::Socks5,
            server,
            port,
            username,
            password,
            ..Default::default()
        })
    }

    fn parse_http_proxy(&self, link: &str) -> Result<ClashProxy> {
        let (base, name) = split_fragment(link);
        let url = Url::parse(base).context("HTTP 代理 URL 解析失败")?;
        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("HTTP 代理缺少 host"))?
            .to_string();
        let scheme = url.scheme();
        let tls = scheme == "https";
        let port = url.port().unwrap_or(if tls { 443 } else { 80 });

        let username = (!url.username().is_empty()).then(|| url.username().to_string());
        let password = url.password().map(|s| s.to_string());

        Ok(ClashProxy {
            name: name.unwrap_or_else(|| if tls { "https" } else { "http" }.to_string()),
            proxy_type: if tls {
                ClashProxyType::Https
            } else {
                ClashProxyType::Http
            },
            server,
            port,
            username,
            password,
            tls,
            ..Default::default()
        })
    }

    fn parse_vless(&self, link: &str) -> Result<ClashProxy> {
        let (base, name) = split_fragment(link);
        let url = Url::parse(base).context("VLESS URL 解析失败")?;
        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("VLESS 缺少 host"))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let uuid = url.username();
        if uuid.is_empty() {
            return Err(anyhow!("VLESS 缺少 uuid"));
        }

        let q = query_map(&url);
        let network = q.get("type").or_else(|| q.get("network")).cloned();
        let path = q.get("path").cloned();
        let host = q.get("host").cloned();

        let security = q
            .get("security")
            .or_else(|| q.get("tls"))
            .map(|s| s.as_str())
            .unwrap_or("");
        let tls =
            !security.is_empty() && security != "none" && security != "0" && security != "false";

        let servername = q
            .get("sni")
            .or_else(|| q.get("peer"))
            .or_else(|| q.get("servername"))
            .cloned();

        let skip_cert_verify = q
            .get("allowInsecure")
            .or_else(|| q.get("allowinsecure"))
            .or_else(|| q.get("insecure"))
            .map(|s| matches!(s.as_str(), "1" | "true" | "True" | "TRUE"))
            .unwrap_or(false);

        let alpn = q.get("alpn").map(|s| parse_alpn(s)).unwrap_or_default();

        // REALITY/flow 链接参数（G1-6）：pbk = public-key、sid = short-id、
        // security=reality、flow；捕获随节点保留进 EgressConfig::Vless
        //（拨号期对不支持面点名拒绝，防静默降级为普通 TLS VLESS——服务端
        // 回落伪装站点且无报错）。
        let pbk = q.get("pbk").cloned();
        let sid = q.get("sid").cloned();
        let reality_opts = if security == "reality" || pbk.is_some() {
            let mut m = serde_yaml::Mapping::new();
            if let Some(p) = &pbk {
                m.insert(
                    serde_yaml::Value::String("public-key".to_string()),
                    serde_yaml::Value::String(p.clone()),
                );
            }
            if let Some(s) = &sid {
                m.insert(
                    serde_yaml::Value::String("short-id".to_string()),
                    serde_yaml::Value::String(s.clone()),
                );
            }
            Some(serde_yaml::Value::Mapping(m))
        } else {
            None
        };
        let flow = q.get("flow").cloned();

        Ok(ClashProxy {
            name: name.unwrap_or_else(|| "vless".to_string()),
            proxy_type: ClashProxyType::Vless,
            server,
            port,
            uuid: Some(uuid.to_string()),
            network,
            path,
            host,
            tls,
            skip_cert_verify,
            alpn,
            servername,
            fingerprint: q.get("fp").cloned(),
            flow,
            reality_opts,
            ..Default::default()
        })
    }

    fn parse_trojan(&self, link: &str) -> Result<ClashProxy> {
        let (base, name) = split_fragment(link);
        let url = Url::parse(base).context("Trojan URL 解析失败")?;
        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("Trojan 缺少 host"))?
            .to_string();
        let port = url.port().unwrap_or(443);

        // trojan://password@host:port
        let password = if !url.username().is_empty() {
            url.username().to_string()
        } else if let Some(p) = url.password() {
            p.to_string()
        } else {
            return Err(anyhow!("Trojan 缺少密码"));
        };

        let q = query_map(&url);
        let network = q.get("type").or_else(|| q.get("network")).cloned();
        let path = q.get("path").cloned();
        let host = q.get("host").cloned();

        let servername = q
            .get("sni")
            .or_else(|| q.get("peer"))
            .or_else(|| q.get("servername"))
            .cloned();

        let skip_cert_verify = q
            .get("allowInsecure")
            .or_else(|| q.get("allowinsecure"))
            .or_else(|| q.get("insecure"))
            .map(|s| matches!(s.as_str(), "1" | "true" | "True" | "TRUE"))
            .unwrap_or(false);

        let alpn = q.get("alpn").map(|s| parse_alpn(s)).unwrap_or_default();

        Ok(ClashProxy {
            name: name.unwrap_or_else(|| "trojan".to_string()),
            proxy_type: ClashProxyType::Trojan,
            server,
            port,
            password: Some(password),
            network,
            path,
            host,
            tls: true,
            skip_cert_verify,
            alpn,
            servername,
            fingerprint: q.get("fp").cloned(),
            ..Default::default()
        })
    }

    fn parse_hysteria2(&self, link: &str) -> Result<ClashProxy> {
        let (base, name) = split_fragment(link);
        let url = Url::parse(base).context("Hysteria2 URL 解析失败")?;
        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("Hysteria2 缺少 host"))?
            .to_string();
        let port = url.port().unwrap_or(443);

        let q = query_map(&url);
        let password = q
            .get("auth")
            .or_else(|| q.get("password"))
            .cloned()
            .or_else(|| (!url.username().is_empty()).then(|| url.username().to_string()))
            .ok_or_else(|| anyhow!("Hysteria2 缺少 auth/password"))?;

        let mport = q
            .get("mport")
            .or_else(|| q.get("ports"))
            .or_else(|| q.get("port-range"))
            .or_else(|| q.get("ports-range"))
            .cloned();

        let servername = q
            .get("sni")
            .or_else(|| q.get("peer"))
            .or_else(|| q.get("servername"))
            .cloned();

        let skip_cert_verify = q
            .get("insecure")
            .or_else(|| q.get("allowInsecure"))
            .or_else(|| q.get("allowinsecure"))
            .map(|s| matches!(s.as_str(), "1" | "true" | "True" | "TRUE"))
            .unwrap_or(false);

        let alpn = q.get("alpn").map(|s| parse_alpn(s)).unwrap_or_default();

        Ok(ClashProxy {
            name: name.unwrap_or_else(|| "hysteria2".to_string()),
            proxy_type: ClashProxyType::Hysteria2,
            server,
            port,
            password: Some(password),
            mport,
            obfs: q.get("obfs").cloned(),
            obfs_param: q
                .get("obfs-param")
                .or_else(|| q.get("obfs_param"))
                .or_else(|| q.get("obfs-password"))
                .or_else(|| q.get("obfs_password"))
                .cloned(),
            servername,
            skip_cert_verify,
            alpn,
            ..Default::default()
        })
    }

    fn parse_ss(&self, link: &str) -> Result<ClashProxy> {
        // ss://[userinfo@]host:port[#name]
        // userinfo can be:
        // - method:password (SIP002)
        // - base64(method:password) (SIP002, URL-safe)
        // or the whole payload can be base64(method:password@host:port) (legacy).

        let (without_frag, name_opt) = split_fragment(link);
        let (without_query, _query_opt) = split_query(without_frag);
        let mut rest = without_query
            .strip_prefix("ss://")
            .ok_or_else(|| anyhow!("SS 链接必须以 ss:// 开头"))?
            .trim()
            .trim_start_matches("//")
            .trim()
            .to_string();

        if rest.is_empty() {
            return Err(anyhow!("SS 链接缺少内容"));
        }

        // If no '@' exists, treat as legacy base64 of "method:pass@host:port".
        if !rest.contains('@') {
            let decoded = self
                .decode_base64_to_string(&rest)
                .context("SS Base64 解码失败")?;
            rest = decoded.trim().to_string();
        }

        let (userinfo, server_part) = rest
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("SS 链接格式错误（缺少 @ 或 Base64 解码失败）"))?;

        let (cipher, password) = if userinfo.contains(':') {
            let (c, p) = userinfo
                .split_once(':')
                .ok_or_else(|| anyhow!("SS userinfo 格式错误"))?;
            (percent_decode(c), percent_decode(p))
        } else {
            let decoded = self
                .decode_base64_to_string(userinfo)
                .context("SS userinfo Base64 解码失败")?;
            let (c, p) = decoded
                .split_once(':')
                .ok_or_else(|| anyhow!("SS userinfo Base64 解码后格式错误"))?;
            (c.trim().to_string(), p.trim().to_string())
        };

        let (server, port) = parse_host_port(server_part).context("SS host:port 解析失败")?;

        Ok(ClashProxy {
            name: name_opt.unwrap_or_else(|| "ss".to_string()),
            proxy_type: ClashProxyType::Ss,
            server,
            port,
            cipher: Some(cipher),
            password: Some(password),
            ..Default::default()
        })
    }

    /// 过滤和去重 Clash 代理
    fn filter_and_dedup_proxies(
        &self,
        proxies: &[ClashProxy],
        warnings: &mut Vec<String>,
    ) -> Vec<ClashProxy> {
        let mut filtered = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for proxy in proxies {
            // 检查是否有效
            if self.options.filter_invalid_nodes && !self.clash_converter.is_valid_proxy(proxy) {
                continue;
            }

            // 生成唯一键（服务器:端口）
            let key = format!("{}:{}", proxy.server, proxy.port);

            // 检查是否重复
            if self.options.filter_duplicate_nodes && seen.contains(&key) {
                warnings.push(format!("重复节点：{}:{}", proxy.server, proxy.port));
                continue;
            }

            seen.insert(key);

            // 规范化节点名称
            let mut normalized_proxy = proxy.clone();
            if self.options.normalize_node_names {
                normalized_proxy.name = self.normalize_node_name(&proxy.name);
            }

            // 应用前缀
            normalized_proxy.name =
                format!("{}{}", self.options.node_name_prefix, normalized_proxy.name);

            filtered.push(normalized_proxy);

            // 检查最大节点数限制
            if let Some(max_nodes) = self.options.max_nodes {
                if filtered.len() >= max_nodes {
                    warnings.push(format!("达到最大节点数限制：{}", max_nodes));
                    break;
                }
            }
        }

        filtered
    }

    /// 过滤和去重 Rillane 节点
    fn filter_and_dedup_rillane_nodes(
        &self,
        nodes: &[crate::rillane_dsl::RillaneNode],
        warnings: &mut Vec<String>,
    ) -> Vec<crate::rillane_dsl::RillaneNode> {
        let mut filtered = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for node in nodes {
            // 检查是否有效
            if self.options.filter_invalid_nodes && !self.rillane_converter.is_valid_node(node) {
                continue;
            }

            // 生成唯一键
            let key = format!(
                "{}:{}",
                node.server.as_deref().unwrap_or(""),
                node.port.unwrap_or(0)
            );

            // 检查是否重复
            if self.options.filter_duplicate_nodes && seen.contains(&key) {
                warnings.push(format!("重复节点：{}", key));
                continue;
            }

            seen.insert(key);

            // 规范化节点名称
            let mut normalized_node = node.clone();
            if self.options.normalize_node_names {
                normalized_node.name = self.normalize_node_name(&node.name);
            }

            // 应用前缀
            normalized_node.name =
                format!("{}{}", self.options.node_name_prefix, normalized_node.name);

            filtered.push(normalized_node);

            // 检查最大节点数限制
            if let Some(max_nodes) = self.options.max_nodes {
                if filtered.len() >= max_nodes {
                    warnings.push(format!("达到最大节点数限制：{}", max_nodes));
                    break;
                }
            }
        }

        filtered
    }

    /// 过滤和去重 V2Ray 节点
    fn filter_and_dedup_v2ray_nodes(
        &self,
        nodes: Vec<ClashProxy>,
        warnings: &mut Vec<String>,
    ) -> Vec<ClashProxy> {
        // 重用 Clash 代理的过滤逻辑
        self.filter_and_dedup_proxies(&nodes, warnings)
    }

    /// 规范化节点名称
    fn normalize_node_name(&self, name: &str) -> String {
        if self.options.preserve_original_names {
            return name.to_string();
        }

        // 移除特殊字符，替换为下划线
        let normalized = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string();

        // 如果规范化后为空，使用默认名称
        if normalized.is_empty() {
            "node".to_string()
        } else {
            normalized
        }
    }

    /// 获取转换选项
    pub fn options(&self) -> &ConversionOptions {
        &self.options
    }

    /// 更新转换选项
    pub fn update_options(&mut self, options: ConversionOptions) {
        self.options = options;

        // 更新子转换器的选项
        self.clash_converter = ClashConverter::new()
            .with_node_prefix(self.options.node_name_prefix.clone())
            .with_group_prefix(self.options.group_name_prefix.clone())
            .with_rule_prefix(self.options.rule_name_prefix.clone())
            .with_filtering(self.options.filter_invalid_nodes);

        self.rillane_converter = RillaneDslConverter::new()
            .with_validation(true)
            .with_filtering(self.options.filter_invalid_nodes);
    }

    /// 创建性能分析报告
    pub fn generate_performance_report(&self, results: &[ConversionResult]) -> PerformanceReport {
        let mut total_input_size: usize = 0;
        let mut total_output_size: usize = 0;
        let mut total_nodes: usize = 0;
        let mut total_filtered: usize = 0;
        let mut total_duration: u64 = 0;
        let mut successful_conversions: usize = 0;
        let failed_conversions: usize = 0;
        let mut total_warnings: usize = 0;

        for result in results {
            total_input_size += result.stats.input.original_size_bytes;
            total_output_size += result.stats.output.converted_size_bytes;
            total_nodes += result.stats.output.valid_nodes;
            total_filtered += result.stats.output.filtered_nodes;
            total_duration += result.stats.output.conversion_duration_ms;
            successful_conversions += 1;
            total_warnings += result.warnings.len();
        }

        let compression_ratio = if total_input_size > 0 {
            total_output_size as f64 / total_input_size as f64
        } else {
            0.0
        };

        let average_duration = if successful_conversions > 0 {
            total_duration / (successful_conversions as u64)
        } else {
            0
        };

        PerformanceReport {
            successful_conversions,
            failed_conversions,
            total_input_size,
            total_output_size,
            compression_ratio,
            total_nodes_processed: total_nodes,
            total_nodes_filtered: total_filtered,
            total_duration_ms: total_duration,
            average_conversion_duration_ms: average_duration,
            total_warnings,
            performance_grade: self
                .calculate_performance_grade(compression_ratio, average_duration),
        }
    }

    /// 计算性能等级
    fn calculate_performance_grade(&self, compression_ratio: f64, avg_duration: u64) -> char {
        let score = if compression_ratio <= 0.5 && avg_duration <= 1000 {
            100 // 优秀
        } else if compression_ratio <= 0.8 && avg_duration <= 2000 {
            80 // 良好
        } else if compression_ratio <= 1.2 && avg_duration <= 5000 {
            60 // 一般
        } else {
            40 // 较差
        };

        match score {
            90..=100 => 'A',
            80..=89 => 'B',
            70..=79 => 'C',
            60..=69 => 'D',
            _ => 'F',
        }
    }
}

fn split_fragment(input: &str) -> (&str, Option<String>) {
    match input.split_once('#') {
        Some((base, frag)) => (base, Some(percent_decode(frag))),
        None => (input, None),
    }
}

fn split_query(input: &str) -> (&str, Option<&str>) {
    match input.split_once('?') {
        Some((base, q)) => (base, Some(q)),
        None => (input, None),
    }
}

fn query_map(url: &Url) -> std::collections::HashMap<String, String> {
    url.query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>()
}

fn parse_alpn(val: &str) -> Vec<String> {
    val.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = from_hex(bytes[i + 1]);
                let lo = from_hex(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    let s = input.trim();
    if s.is_empty() {
        return Err(anyhow!("空 host:port"));
    }

    // Strip query if present (ss links sometimes carry plugin params).
    let (s, _q) = split_query(s);

    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("IPv6 地址缺少 ]"))?;
        let tail = tail.strip_prefix(':').ok_or_else(|| anyhow!("缺少端口"))?;
        let port: u16 = tail.parse().context("端口非法")?;
        return Ok((host.to_string(), port));
    }

    let (host, port_str) = s.rsplit_once(':').ok_or_else(|| anyhow!("缺少端口"))?;
    let port: u16 = port_str.parse().context("端口非法")?;
    Ok((host.to_string(), port))
}

/// 性能报告
#[derive(Debug, Clone)]
pub struct PerformanceReport {
    /// 成功转换数
    pub successful_conversions: usize,
    /// 失败转换数
    pub failed_conversions: usize,
    /// 总输入大小（字节）
    pub total_input_size: usize,
    /// 总输出大小（字节）
    pub total_output_size: usize,
    /// 压缩比
    pub compression_ratio: f64,
    /// 处理的总节点数
    pub total_nodes_processed: usize,
    /// 过滤的总节点数
    pub total_nodes_filtered: usize,
    /// 总耗时（毫秒）
    pub total_duration_ms: u64,
    /// 平均转换耗时（毫秒）
    pub average_conversion_duration_ms: u64,
    /// 总警告数
    pub total_warnings: usize,
    /// 性能等级
    pub performance_grade: char,
}

impl Default for SubscriptionConverter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_config::EgressConfig;

    #[test]
    fn test_subscription_type_detection() {
        let converter = SubscriptionConverter::new();

        // Clash 配置
        let clash_content = r#"
proxies:
  - name: test
    type: ss
proxy-groups:
  - name: auto
    type: select
rules:
  - MATCH,auto
        "#;
        assert_eq!(
            converter.detect_subscription_type(clash_content),
            SubscriptionType::Clash
        );

        // Rillane DSL
        let rillane_content = r#"
version: "1.0"
nodes:
  - name: test
    type: direct
rules:
  - type: match
    target: direct
        "#;
        assert_eq!(
            converter.detect_subscription_type(rillane_content),
            SubscriptionType::Rillane
        );

        // V2Ray 订阅
        let v2ray_content = r#"
vmess://eyJ2IjogIjIiLCAicHMiOiAiIn0=
vless://eyJ2IjogIjIiLCAicHMiOiAiIn0=
        "#;
        assert_eq!(
            converter.detect_subscription_type(v2ray_content),
            SubscriptionType::V2Ray
        );

        // 自定义
        let custom_content = r#"Just some random text"#;
        assert_eq!(
            converter.detect_subscription_type(custom_content),
            SubscriptionType::Custom
        );
    }

    #[test]
    fn test_parse_v2ray_links() {
        use base64::{
            engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
            Engine,
        };

        let converter = SubscriptionConverter::new();

        // SS (userinfo: method:password)
        let ss1 = "ss://aes-256-gcm:pass@example.com:8388#ss-plain";
        let p = converter.parse_v2ray_link(ss1).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Ss);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 8388);
        assert_eq!(p.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.name, "ss-plain");

        // SS (userinfo: base64(method:password))
        let ui = URL_SAFE_NO_PAD.encode("aes-256-gcm:pass");
        let ss2 = format!("ss://{}@example.com:8388#ss-b64", ui);
        let p = converter.parse_v2ray_link(&ss2).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Ss);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 8388);
        assert_eq!(p.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.name, "ss-b64");

        // SS (legacy: base64(method:password@host:port))
        let legacy = STANDARD_NO_PAD.encode("aes-256-gcm:pass@example.com:8388");
        let ss3 = format!("ss://{}#ss-legacy", legacy);
        let p = converter.parse_v2ray_link(&ss3).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Ss);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 8388);
        assert_eq!(p.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.name, "ss-legacy");

        // SOCKS5
        let socks5 = "socks5://user:pass@example.com:1080#socks5";
        let p = converter.parse_v2ray_link(socks5).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Socks5);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 1080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.name, "socks5");

        // HTTP/HTTPS
        let http = "http://user:pass@example.com:3128#http";
        let p = converter.parse_v2ray_link(http).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Http);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 3128);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert!(!p.tls);

        let https = "https://user:pass@example.com:443#https";
        let p = converter.parse_v2ray_link(https).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Https);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert!(p.tls);

        // Trojan
        let trojan = "trojan://pass@example.com:443?sni=sni.example.com&allowInsecure=1&type=ws&path=%2Fws&host=cdn.example.com&alpn=h2,http/1.1#trojan";
        let p = converter.parse_v2ray_link(trojan).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Trojan);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.network.as_deref(), Some("ws"));
        assert_eq!(p.path.as_deref(), Some("/ws"));
        assert_eq!(p.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(p.servername.as_deref(), Some("sni.example.com"));
        assert!(p.skip_cert_verify);
        assert!(p.alpn.iter().any(|a| a == "h2"));
        assert!(p.tls);

        // VLESS
        let uuid = "11111111-2222-3333-4444-555555555555";
        let vless = format!(
            "vless://{}@example.com:443?security=tls&type=ws&path=%2Fvless&host=cdn.example.com&sni=sni.example.com&alpn=h2,http/1.1&allowInsecure=true#vless",
            uuid
        );
        let p = converter.parse_v2ray_link(&vless).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Vless);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.uuid.as_deref(), Some(uuid));
        assert_eq!(p.network.as_deref(), Some("ws"));
        assert_eq!(p.path.as_deref(), Some("/vless"));
        assert_eq!(p.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(p.servername.as_deref(), Some("sni.example.com"));
        assert!(p.tls);
        assert!(p.skip_cert_verify);

        // VMess
        let vmess_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let vmess_json = format!(
            "{{\"v\":\"2\",\"ps\":\"vmess\",\"add\":\"example.com\",\"port\":\"443\",\"id\":\"{}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"host\":\"cdn.example.com\",\"path\":\"/ws\",\"tls\":\"tls\",\"sni\":\"sni.example.com\",\"alpn\":\"h2,http/1.1\",\"allowInsecure\":\"1\"}}",
            vmess_uuid
        );
        let vmess_b64 = STANDARD_NO_PAD.encode(vmess_json.as_bytes());
        let vmess = format!("vmess://{}", vmess_b64);
        let p = converter.parse_v2ray_link(&vmess).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Vmess);
        assert_eq!(p.name, "vmess");
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.uuid.as_deref(), Some(vmess_uuid));
        assert_eq!(p.network.as_deref(), Some("ws"));
        assert_eq!(p.path.as_deref(), Some("/ws"));
        assert_eq!(p.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(p.servername.as_deref(), Some("sni.example.com"));
        assert!(p.skip_cert_verify);
        assert!(p.tls);

        // Hysteria2
        let hy2 = "hysteria2://pass@example.com:443?insecure=1&sni=sni.example.com&mport=20000-30000&obfs=salamander&obfs-password=ob&alpn=h3#hy2";
        let p = converter.parse_v2ray_link(hy2).unwrap();
        assert_eq!(p.proxy_type, ClashProxyType::Hysteria2);
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.mport.as_deref(), Some("20000-30000"));
        assert_eq!(p.obfs.as_deref(), Some("salamander"));
        assert_eq!(p.obfs_param.as_deref(), Some("ob"));
        assert_eq!(p.servername.as_deref(), Some("sni.example.com"));
        assert!(p.skip_cert_verify);
        assert!(p.alpn.iter().any(|i| i == "h3"));
    }

    #[test]
    fn test_expand_v2ray_payload_base64_blob() {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};

        let converter = SubscriptionConverter::new();
        let raw = "ss://aes-256-gcm:pass@example.com:8388#n1\ntrojan://pass@example.com:443#n2\n";
        let blob = STANDARD_NO_PAD.encode(raw.as_bytes());
        let mut warnings = Vec::new();
        let lines = converter.expand_v2ray_payload(&blob, &mut warnings);
        assert!(warnings.is_empty());
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("ss://"));
        assert!(lines[1].starts_with("trojan://"));
    }

    #[test]
    fn test_content_cleaning() {
        let converter = SubscriptionConverter::new();

        let content = r#"
# This is a comment
# Another comment

proxies:
  - name: test

# Final comment
        "#;

        let cleaned = converter.clean_content(content);
        assert!(!cleaned.contains('#'));
        assert!(!cleaned.contains("\n\n"));
        assert!(cleaned.contains("proxies:"));
        assert!(cleaned.contains("- name: test"));
    }

    #[test]
    fn test_base64_detection() {
        let converter = SubscriptionConverter::new();

        // 有效的 Base64
        assert!(converter.looks_like_base64("SGVsbG8gV29ybGQ="));
        assert!(converter.looks_like_base64("eyJ2IjogIjIiLCAicHMiOiAiIn0="));

        // 无效的 Base64
        assert!(!converter.looks_like_base64("Hello World"));
        assert!(!converter.looks_like_base64("Hello@World"));
        assert!(!converter.looks_like_base64("short"));
    }

    #[test]
    fn test_node_name_normalization() {
        let converter = SubscriptionConverter::with_options(ConversionOptions {
            preserve_original_names: false,
            ..Default::default()
        });

        assert_eq!(converter.normalize_node_name("Test Node"), "Test_Node");
        assert_eq!(
            converter.normalize_node_name("Test@Node#123"),
            "Test_Node_123"
        );
        assert_eq!(converter.normalize_node_name("___Test___"), "Test");
        assert_eq!(converter.normalize_node_name(""), "node");

        let preserve_converter = SubscriptionConverter::with_options(ConversionOptions {
            preserve_original_names: true,
            ..Default::default()
        });

        assert_eq!(
            preserve_converter.normalize_node_name("Test@Node"),
            "Test@Node"
        );
    }

    #[test]
    fn test_performance_report() {
        let converter = SubscriptionConverter::new();

        let result1 = ConversionResult {
            config: rillane_config::RillaneConfig {
                version: rillane_config::ConfigVersion::default(),
                control: rillane_config::ControlConfig {
                    api_bind: "127.0.0.1:9090".to_string(),
                    uds_path: None,
                    admin_token: Some("rillane".to_string()),
                },
                telemetry: rillane_config::TelemetryConfig {
                    log_level: "info".to_string(),
                    enable_metrics: true,
                    enable_tracing: false,
                },
                ingress: vec![],
                egress: vec![],
                routing: rillane_config::RoutingConfig {
                    default_node: "direct".to_string(),
                    scenarios: Vec::new(),
                    groups: vec![],
                    rules: vec![],
                    geoip_db: None,
                    geosite_db: None,
                    ..rillane_config::RoutingConfig::default()
                },
                udp: rillane_config::UdpConfig::default(),
                network: None,
                obfuscation: None,
                profile: None,
                scenarios: Default::default(),
                performance: None,
                egress_pool: None,
                probe: None,
            },
            stats: ConversionStats {
                input: InputStats {
                    subscription_type: Some(SubscriptionType::Clash),
                    original_nodes: 10,
                    original_groups: 2,
                    original_rules: 5,
                    original_size_bytes: 1000,
                },
                output: OutputStats {
                    valid_nodes: 8,
                    filtered_nodes: 2,
                    duplicate_nodes: 0,
                    converted_groups: 1,
                    converted_rules: 3,
                    converted_size_bytes: 800,
                    conversion_duration_ms: 500,
                },
            },
            warnings: vec!["Test warning".to_string()],
        };

        let report = converter.generate_performance_report(&[result1]);

        assert_eq!(report.successful_conversions, 1);
        assert_eq!(report.total_input_size, 1000);
        assert_eq!(report.total_output_size, 800);
        assert_eq!(report.compression_ratio, 0.8);
        assert_eq!(report.total_nodes_processed, 8);
        assert_eq!(report.total_nodes_filtered, 2);
        assert_eq!(report.total_duration_ms, 500);
        assert_eq!(report.average_conversion_duration_ms, 500);
        assert_eq!(report.total_warnings, 1);
        assert!(['A', 'B', 'C'].contains(&report.performance_grade));
    }

    /// G1-6 REALITY 链接参数捕获：vless:// 的 pbk/sid/flow（及
    /// security=reality）须进 ClashProxy 字段；批量导入路径按既有约定
    /// 警告 + 跳过该行，绝不静默降级为普通 TLS VLESS。
    #[test]
    fn test_vless_reality_link_params_captured() {
        let converter = SubscriptionConverter::new();
        let link = "vless://b831381d-6324-4d2a-b1e7-1bf75a1db7b3@example.com:443?security=reality&pbk=PBQh7j2tWxQmZHVub3RUYXJnZXQ&sid=0123ac&flow=xtls-rprx-vision&sni=www.apple.com&fp=chrome#vl-r";
        let p = converter.parse_v2ray_link(link).unwrap();
        assert!(p.reality_opts.is_some(), "pbk/sid 应进 reality_opts");
        assert_eq!(p.flow.as_deref(), Some("xtls-rprx-vision"));

        // 无 pbk 且非 security=reality 的普通链接不触发捕获
        let plain = converter
            .parse_v2ray_link(
                "vless://b831381d-6324-4d2a-b1e7-1bf75a1db7b3@example.com:443?security=tls&sni=a.com#vl-plain",
            )
            .unwrap();
        assert!(plain.reality_opts.is_none());
        assert!(plain.flow.is_none());
    }

    /// G1-6 批量 v2ray 导入（2026-11-10 拍板改 M1 拒绝策略）：REALITY 行
    /// 照常导入且 pbk/sid/flow 随节点保留，无跳过告警；拨号期才点名拒绝。
    #[tokio::test]
    async fn test_v2ray_bulk_import_preserves_reality_line() {
        let converter = SubscriptionConverter::new();
        let content = "vless://b831381d-6324-4d2a-b1e7-1bf75a1db7b3@example.com:443?security=reality&pbk=PBQh7j2tWxQmZHVub3RUYXJnZXQ&sid=0123ac&flow=xtls-rprx-vision&sni=www.apple.com#vl-r\nvless://b831381d-6324-4d2a-b1e7-1bf75a1db7b3@plain.example.com:443?security=tls&sni=a.com#vl-plain\n";
        let sub = Subscription {
            name: "test".to_string(),
            url: "unused".to_string(),
            r#type: Some(SubscriptionType::V2Ray),
            enabled: true,
            refresh_interval: 0,
            timeout: 5,
            headers: std::collections::HashMap::new(),
            user_agent: None,
            last_updated: None,
            last_error: None,
            etag: None,
            content_hash: None,
            last_modified: None,
        };
        // G1-6（拍板改 M1 拒绝策略）：REALITY 行照常导入且 pbk/sid/flow 随节点
        // 保留（拨号期才点名拒绝）；节点级失败不拖垮整份批量订阅
        let result = converter.auto_convert(&sub, content).await.unwrap();
        let names: Vec<&str> = result
            .config
            .egress
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(names.contains(&"vl-r"), "REALITY 行应照常导入");
        assert!(names.contains(&"vl-plain"), "普通行照常导入");
        assert!(
            result.warnings.is_empty(),
            "不应再有跳过告警: {:?}",
            result.warnings
        );
        let vl_r = result
            .config
            .egress
            .iter()
            .find(|e| e.name == "vl-r")
            .expect("vl-r egress 应存在");
        match &vl_r.spec {
            EgressConfig::Vless { reality, flow, .. } => {
                let r = reality.as_ref().expect("reality 应保留");
                assert_eq!(r.public_key, "PBQh7j2tWxQmZHVub3RUYXJnZXQ");
                assert_eq!(r.short_id.as_deref(), Some("0123ac"));
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            }
            other => panic!("应为 Vless: {other:?}"),
        }
    }
}
