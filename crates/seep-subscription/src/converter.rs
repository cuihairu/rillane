//! 订阅格式转换器

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use tracing::{debug, info, warn};

use crate::{SubscriptionType, Subscription};
use crate::clash::{ClashConfig, ClashConverter, ClashProxy, ClashProxyGroup, ClashProxyGroupType, ClashProxyType, ClashRule};
use crate::seep_dsl::{SeepConfig, SeepDslConverter};

/// 通用转换器
pub struct SubscriptionConverter {
    /// Clash 转换器
    clash_converter: ClashConverter,
    /// Seep DSL 转换器
    seep_converter: SeepDslConverter,
    /// 转换选项
    options: ConversionOptions,
}

/// 转换选项
#[derive(Debug, Clone)]
pub struct ConversionOptions {
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
}

impl Default for ConversionOptions {
    fn default() -> Self {
        Self {
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
        }
    }
}

/// 转换结果
#[derive(Debug, Clone)]
pub struct ConversionResult {
    /// 转换后的配置
    pub config: seep_config::SeepConfig,
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
            .with_filtering(options.filter_invalid_nodes);

        let seep_converter = SeepDslConverter::new()
            .with_validation(true)
            .with_filtering(options.filter_invalid_nodes);

        Self {
            clash_converter,
            seep_converter,
            options,
        }
    }

    /// 自动检测并转换订阅内容
    pub async fn auto_convert(&self, subscription: &Subscription, content: &str) -> Result<ConversionResult> {
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
            target: "seep::subscription::converter",
            name = %subscription.name,
            detected_type = %detected_type,
            "开始转换订阅"
        );

        // 根据类型进行转换
        let result = match detected_type {
            SubscriptionType::Clash => self.convert_clash(content).await?,
            SubscriptionType::Seep => self.convert_seep_dsl(content).await?,
            SubscriptionType::V2Ray => self.convert_v2ray(content).await?,
            SubscriptionType::Custom => self.convert_custom(content).await?,
        };

        let duration = start_time.elapsed().as_millis() as u64;

        // 更新统计信息
        let mut final_result = result;
        final_result.stats.output.conversion_duration_ms = duration;

        info!(
            target: "seep::subscription::converter",
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
                target: "seep::subscription::converter",
                "检测到 Clash 配置格式"
            );
            return SubscriptionType::Clash;
        }

        // 检查 Seep DSL
        if cleaned.contains("version:") && cleaned.contains("nodes:") {
            debug!(
                target: "seep::subscription::converter",
                "检测到 Seep DSL 格式"
            );
            return SubscriptionType::Seep;
        }

        // 检查 V2Ray 订阅（Base64 编码的链接列表）
        let lines: Vec<&str> = cleaned.lines().collect();
        let v2ray_lines = lines.iter()
            .filter(|line| {
                let line = line.trim();
                line.starts_with("vmess://") ||
                line.starts_with("vless://") ||
                line.starts_with("trojan://") ||
                line.starts_with("ss://") ||
                (line.len() > 50 && self.looks_like_base64(line))
            })
            .count();

        if v2ray_lines > 0 && v2ray_lines as f64 / lines.len() as f64 > 0.5 {
            debug!(
                target: "seep::subscription::converter",
                v2ray_lines = v2ray_lines,
                total_lines = lines.len(),
                "检测到 V2Ray 订阅格式"
            );
            return SubscriptionType::V2Ray;
        }

        // 默认为自定义格式
        debug!(
            target: "seep::subscription::converter",
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
            target: "seep::subscription::converter",
            "开始转换 Clash 配置"
        );

        // 解析 Clash 配置
        let clash_config = self.clash_converter.parse(content)
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

        // 转换为 Seep 配置
        let seep_config = self.clash_converter.convert_to_seep(&filtered_config)
            .context("转换 Clash 配置为 Seep 配置失败")?;

        let stats = ConversionStats {
            input: InputStats {
                subscription_type: Some(SubscriptionType::Clash),
                original_nodes,
                original_groups,
                original_rules,
                original_size_bytes: content.len(),
            },
            output: OutputStats {
                valid_nodes: seep_config.egress.len(),
                filtered_nodes: original_nodes - seep_config.egress.len(),
                duplicate_nodes: 0, // 在 filter_and_dedup_proxies 中计算
                converted_groups: seep_config.routing.groups.len(),
                converted_rules: seep_config.routing.rules.len(),
                converted_size_bytes: serde_yaml::to_string(&seep_config).unwrap_or_default().len(),
                conversion_duration_ms: 0, // 在调用方设置
            },
        };

        Ok(ConversionResult {
            config: seep_config,
            stats,
            warnings,
        })
    }

    /// 转换 Seep DSL 配置
    async fn convert_seep_dsl(&self, content: &str) -> Result<ConversionResult> {
        debug!(
            target: "seep::subscription::converter",
            "开始转换 Seep DSL 配置"
        );

        // 解析 Seep DSL 配置
        let seep_dsl_config = self.seep_converter.parse(content)
            .context("解析 Seep DSL 配置失败")?;

        let mut warnings = Vec::new();

        // 统计原始数据
        let original_nodes = seep_dsl_config.nodes.len();
        let original_groups = seep_dsl_config.groups.len();
        let original_rules = seep_dsl_config.rules.len();

        // 过滤和去重节点
        let filtered_nodes = self.filter_and_dedup_seep_nodes(&seep_dsl_config.nodes, &mut warnings);

        if filtered_nodes.len() != original_nodes {
            warnings.push(format!(
                "节点过滤：原始 {} 个，过滤后 {} 个",
                original_nodes,
                filtered_nodes.len()
            ));
        }

        // 创建修改后的 Seep DSL 配置
        let mut filtered_config = seep_dsl_config.clone();
        filtered_config.nodes = filtered_nodes;

        // 转换为标准 Seep 配置
        let seep_config = self.seep_converter.convert_to_seep(&filtered_config)
            .context("转换 Seep DSL 为标准 Seep 配置失败")?;

        let stats = ConversionStats {
            input: InputStats {
                subscription_type: Some(SubscriptionType::Seep),
                original_nodes,
                original_groups,
                original_rules,
                original_size_bytes: content.len(),
            },
            output: OutputStats {
                valid_nodes: seep_config.egress.len(),
                filtered_nodes: original_nodes - seep_config.egress.len(),
                duplicate_nodes: 0,
                converted_groups: seep_config.routing.groups.len(),
                converted_rules: seep_config.routing.rules.len(),
                converted_size_bytes: serde_yaml::to_string(&seep_config).unwrap_or_default().len(),
                conversion_duration_ms: 0,
            },
        };

        Ok(ConversionResult {
            config: seep_config,
            stats,
            warnings,
        })
    }

    /// 转换 V2Ray 订阅
    async fn convert_v2ray(&self, content: &str) -> Result<ConversionResult> {
        debug!(
            target: "seep::subscription::converter",
            "开始转换 V2Ray 订阅"
        );

        let mut warnings = Vec::new();
        let mut nodes = Vec::new();

        for (index, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let node_content = if self.looks_like_base64(line) {
                match base64::decode(line) {
                    Ok(decoded) => match String::from_utf8(decoded) {
                        Ok(decoded_string) => decoded_string,
                        Err(_) => {
                            warnings.push(format!("行 {}：Base64 解码成功但不是有效的 UTF-8", index + 1));
                            continue;
                        }
                    }
                    Err(_) => {
                        // 可能不是 Base64，作为普通链接处理
                        line.to_string()
                    }
                }
            } else {
                line.to_string()
            };

            // 解析 V2Ray 链接
            if let Some(node) = self.parse_v2ray_link(&node_content) {
                nodes.push(node);
            } else {
                warnings.push(format!("行 {}：无法解析的链接", index + 1));
            }
        }

        // 过滤和去重
        let filtered_nodes = self.filter_and_dedup_v2ray_nodes(nodes, &mut warnings);
        let node_count = filtered_nodes.len();

        // 创建 Clash 配置格式然后转换
        let clash_config = ClashConfig {
            proxies: filtered_nodes,
            proxy_groups: vec![
                ClashProxyGroup {
                    name: "auto".to_string(),
                    group_type: ClashProxyGroupType::UrlTest,
                    proxies: (0..node_count).map(|i| format!("node-{}", i + 1)).collect(),
                    url: Some("http://www.gstatic.com/generate_204".to_string()),
                    interval: Some(300),
                    strategy: None,
                }
            ],
            rules: vec![
                ClashRule::Match { target: "auto".to_string() },
            ],
            dns: None,
            mixed_port: None,
            allow_lan: false,
            bind_address: None,
            log_level: "info".to_string(),
            external_controller: None,
        };

        // 使用 Clash 转换器
        let seep_config = self.clash_converter.convert_to_seep(&clash_config)
            .context("转换 V2Ray 配置为 Seep 配置失败")?;

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
                valid_nodes: seep_config.egress.len(),
                filtered_nodes: original_lines - seep_config.egress.len(),
                duplicate_nodes: 0,
                converted_groups: seep_config.routing.groups.len(),
                converted_rules: seep_config.routing.rules.len(),
                converted_size_bytes: serde_yaml::to_string(&seep_config).unwrap_or_default().len(),
                conversion_duration_ms: 0,
            },
        };

        Ok(ConversionResult {
            config: seep_config,
            stats,
            warnings,
        })
    }

    /// 转换自定义格式
    async fn convert_custom(&self, content: &str) -> Result<ConversionResult> {
        warn!(
            target: "seep::subscription::converter",
            "自定义格式暂不支持转换"
        );

        Err(anyhow!("自定义格式暂不支持自动转换，请手动配置"))
    }

    /// 检查内容是否看起来像 Base64
    fn looks_like_base64(&self, content: &str) -> bool {
        let trimmed = content.trim();
        // A conservative heuristic:
        // - Base64 strings are typically padded and length is a multiple of 4
        // - allow URL-safe alphabet as well
        trimmed.len() >= 8
            && trimmed.len() % 4 == 0
            && trimmed.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
            })
    }

    /// 解析 V2Ray 链接
    fn parse_v2ray_link(&self, link: &str) -> Option<ClashProxy> {
        // 这里应该实现完整的 V2Ray 链接解析
        // 包括 vmess://, vless://, trojan://, ss:// 等格式

        // 简化实现，只识别类型并创建基本代理
        if link.starts_with("vmess://") {
            Some(ClashProxy {
                name: format!("vmess-{}", link.len() % 1000),
                proxy_type: ClashProxyType::Vmess,
                server: "vmess.example.com".to_string(),
                port: 443,
                uuid: Some("00000000-0000-0000-0000-000000000000".to_string()),
                network: Some("ws".to_string()),
                tls: true,
                ..Default::default()
            })
        } else if link.starts_with("vless://") {
            Some(ClashProxy {
                name: format!("vless-{}", link.len() % 1000),
                proxy_type: ClashProxyType::Vless,
                server: "vless.example.com".to_string(),
                port: 443,
                uuid: Some("00000000-0000-0000-0000-000000000000".to_string()),
                network: Some("ws".to_string()),
                tls: true,
                ..Default::default()
            })
        } else if link.starts_with("trojan://") {
            Some(ClashProxy {
                name: format!("trojan-{}", link.len() % 1000),
                proxy_type: ClashProxyType::Trojan,
                server: "trojan.example.com".to_string(),
                port: 443,
                password: Some("password".to_string()),
                network: Some("ws".to_string()),
                tls: true,
                ..Default::default()
            })
        } else if link.starts_with("ss://") {
            Some(ClashProxy {
                name: format!("ss-{}", link.len() % 1000),
                proxy_type: ClashProxyType::Ss,
                server: "ss.example.com".to_string(),
                port: 8388,
                cipher: Some("aes-256-gcm".to_string()),
                password: Some("password".to_string()),
                ..Default::default()
            })
        } else {
            None
        }
    }

    /// 过滤和去重 Clash 代理
    fn filter_and_dedup_proxies(&self, proxies: &[ClashProxy], warnings: &mut Vec<String>) -> Vec<ClashProxy> {
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
            normalized_proxy.name = format!("{}{}", self.options.node_name_prefix, normalized_proxy.name);

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

    /// 过滤和去重 Seep 节点
    fn filter_and_dedup_seep_nodes(&self, nodes: &[crate::seep_dsl::SeepNode], warnings: &mut Vec<String>) -> Vec<crate::seep_dsl::SeepNode> {
        let mut filtered = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for node in nodes {
            // 检查是否有效
            if self.options.filter_invalid_nodes && !self.seep_converter.is_valid_node(node) {
                continue;
            }

            // 生成唯一键
            let key = format!("{}:{}",
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
            normalized_node.name = format!("{}{}", self.options.node_name_prefix, normalized_node.name);

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
    fn filter_and_dedup_v2ray_nodes(&self, nodes: Vec<ClashProxy>, warnings: &mut Vec<String>) -> Vec<ClashProxy> {
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
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
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

        self.seep_converter = SeepDslConverter::new()
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
        let mut failed_conversions: usize = 0;
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
            performance_grade: self.calculate_performance_grade(compression_ratio, average_duration),
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
        assert_eq!(converter.detect_subscription_type(clash_content), SubscriptionType::Clash);

        // Seep DSL
        let seep_content = r#"
version: "1.0"
nodes:
  - name: test
    type: direct
rules:
  - type: match
    target: direct
        "#;
        assert_eq!(converter.detect_subscription_type(seep_content), SubscriptionType::Seep);

        // V2Ray 订阅
        let v2ray_content = r#"
vmess://eyJ2IjogIjIiLCAicHMiOiAiIn0=
vless://eyJ2IjogIjIiLCAicHMiOiAiIn0=
        "#;
        assert_eq!(converter.detect_subscription_type(v2ray_content), SubscriptionType::V2Ray);

        // 自定义
        let custom_content = r#"Just some random text"#;
        assert_eq!(converter.detect_subscription_type(custom_content), SubscriptionType::Custom);
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
        assert_eq!(converter.normalize_node_name("Test@Node#123"), "Test_Node_123");
        assert_eq!(converter.normalize_node_name("___Test___"), "Test");
        assert_eq!(converter.normalize_node_name(""), "node");

        let preserve_converter = SubscriptionConverter::with_options(ConversionOptions {
            preserve_original_names: true,
            ..Default::default()
        });

        assert_eq!(preserve_converter.normalize_node_name("Test@Node"), "Test@Node");
    }

    #[test]
    fn test_performance_report() {
        let converter = SubscriptionConverter::new();

        let result1 = ConversionResult {
            config: seep_config::SeepConfig {
                control: seep_config::ControlConfig {
                    api_bind: "127.0.0.1:9090".to_string(),
                    uds_path: None,
                    admin_token: Some("seep".to_string()),
                },
                telemetry: seep_config::TelemetryConfig {
                    log_level: "info".to_string(),
                    enable_metrics: true,
                    enable_tracing: false,
                },
                ingress: vec![],
                egress: vec![],
                routing: seep_config::RoutingConfig {
                    default_node: "direct".to_string(),
                    groups: vec![],
                    rules: vec![],
                },
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
}
