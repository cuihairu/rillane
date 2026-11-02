//! 订阅内容获取器

use std::{collections::HashMap, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{header, Client, Proxy, Response};
use tracing::{debug, warn};

/// 订阅获取器配置
#[derive(Debug, Clone)]
pub struct FetcherConfig {
    /// 超时时间
    pub timeout: Duration,
    /// 最大重试次数
    pub max_retries: u32,
    /// 重试间隔
    pub retry_interval: Duration,
    /// 用户代理
    pub user_agent: Option<String>,
    /// 是否跟随重定向
    pub follow_redirects: bool,
    /// 自定义请求头
    pub headers: HashMap<String, String>,
    /// 代理设置
    pub proxy: Option<String>,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_interval: Duration::from_secs(5),
            user_agent: Some(format!(
                "seep-subscription/{} (rust)",
                env!("CARGO_PKG_VERSION")
            )),
            follow_redirects: true,
            headers: HashMap::new(),
            proxy: None,
        }
    }
}

/// 订阅获取结果
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// 获取到的内容
    pub content: String,
    /// ETag 响应头
    pub etag: Option<String>,
    /// Last-Modified 响应头
    pub last_modified: Option<String>,
    /// 响应状态码
    pub status_code: u16,
    /// 响应头
    pub headers: HashMap<String, String>,
    /// 内容类型
    pub content_type: Option<String>,
}

/// 订阅获取器
pub struct SubscriptionFetcher {
    client: Client,
    config: FetcherConfig,
}

impl SubscriptionFetcher {
    /// 创建新的获取器
    pub fn new() -> Self {
        Self::with_config(FetcherConfig::default())
    }

    /// 使用自定义配置创建获取器
    pub fn with_config(config: FetcherConfig) -> Self {
        let follow_redirects = config.follow_redirects;
        let mut builder =
            Client::builder()
                .timeout(config.timeout)
                .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                    if follow_redirects && attempt.previous().len() < 10 {
                        attempt.follow()
                    } else {
                        attempt.stop()
                    }
                }));

        // 设置代理
        if let Some(proxy_url) = &config.proxy {
            if let Ok(proxy) = Proxy::all(proxy_url) {
                builder = builder.proxy(proxy);
            } else {
                warn!(
                    target: "seep::subscription::fetcher",
                    proxy = %proxy_url,
                    "无效的代理配置"
                );
            }
        }

        if let Some(user_agent) = &config.user_agent {
            builder = builder.user_agent(user_agent.clone());
        }

        let client = builder.build().unwrap_or_default();

        Self { client, config }
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// 设置用户代理
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.config.user_agent = user_agent;
        self
    }

    /// 设置代理
    pub fn with_proxy(mut self, proxy: String) -> Self {
        self.config.proxy = Some(proxy);
        self
    }

    /// 添加请求头
    pub fn add_header(&mut self, key: String, value: String) {
        self.config.headers.insert(key, value);
    }

    /// 获取订阅内容
    pub async fn fetch(&self, url: &str) -> Result<FetchResult> {
        debug!(
            target: "seep::subscription::fetcher",
            url = %url,
            "开始获取订阅内容"
        );

        let mut last_error = None;

        for attempt in 1..=self.config.max_retries {
            match self.fetch_attempt(url).await {
                Ok(result) => {
                    debug!(
                        target: "seep::subscription::fetcher",
                        url = %url,
                        attempt = attempt,
                        status = result.status_code,
                        size = result.content.len(),
                        "订阅内容获取成功"
                    );
                    return Ok(result);
                }
                Err(err) => {
                    warn!(
                        target: "seep::subscription::fetcher",
                        url = %url,
                        attempt = attempt,
                        error = %err,
                        "获取失败，将重试"
                    );

                    last_error = Some(err);

                    // 如果不是最后一次尝试，等待重试间隔
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(self.config.retry_interval).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("所有重试均失败")))
    }

    /// 单次获取尝试
    async fn fetch_attempt(&self, url: &str) -> Result<FetchResult> {
        let mut request = self.client.get(url);

        // 设置请求头
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        // 设置用户代理
        if let Some(user_agent) = &self.config.user_agent {
            request = request.header(header::USER_AGENT, user_agent);
        }

        // 发送请求
        let mut response = request
            .send()
            .await
            .with_context(|| format!("发送请求到 {} 失败", url))?;

        let status_code = response.status().as_u16();

        // 处理 304 Not Modified
        if status_code == 304 {
            debug!(
                target: "seep::subscription::fetcher",
                url = %url,
                "内容未修改"
            );
            return Ok(FetchResult {
                content: String::new(),
                etag: response
                    .headers()
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                last_modified: response
                    .headers()
                    .get(header::LAST_MODIFIED)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                status_code,
                headers: self.extract_headers(&response),
                content_type: response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
            });
        }

        // 检查响应状态
        if !response.status().is_success() {
            return Err(anyhow!(
                "HTTP请求失败: {} {}",
                status_code,
                response.status().canonical_reason().unwrap_or("Unknown")
            ));
        }

        // 在消费 response 前提取响应头
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let headers = self.extract_headers(&response);

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // 读取内容（有界）：订阅端点为第三方不可信面，无界 text() 读取是内存
        // DoS 面（50MiB 上限与 validate_content 同口径；validate_content 现
        // 仅测试调用，须在此处落地）。先查 Content-Length 快速拒绝，再流式
        // 累积并设硬上限，防分块/谎报长度。
        let max_bytes: u64 = 50 * 1024 * 1024;
        if let Some(len) = response.content_length() {
            if len > max_bytes {
                bail!("订阅内容过大: {} 字节（上限 {max_bytes}）", len);
            }
        }
        let mut body = Vec::with_capacity(
            response.content_length().unwrap_or(0).min(max_bytes) as usize,
        );
        loop {
            let chunk = response.chunk().await.context("读取响应内容失败")?;
            let Some(chunk) = chunk else { break };
            if body.len() + chunk.len() > max_bytes as usize {
                bail!("订阅内容超过 {max_bytes} 字节上限");
            }
            body.extend_from_slice(&chunk);
        }
        let content = String::from_utf8(body).context("订阅内容非 UTF-8")?;

        Ok(FetchResult {
            content,
            etag,
            last_modified,
            status_code,
            headers,
            content_type,
        })
    }

    /// 提取响应头
    fn extract_headers(&self, response: &Response) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), value_str.to_string());
            }
        }

        headers
    }

    /// 验证响应内容
    pub fn validate_content(&self, content: &str, url: &str) -> Result<()> {
        if content.is_empty() {
            return Err(anyhow!("订阅内容为空"));
        }

        // 检查内容长度
        if content.len() > 50 * 1024 * 1024 {
            // 50MB
            return Err(anyhow!("订阅内容过大: {} 字节", content.len()));
        }

        // 基本的格式验证
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("订阅内容只包含空白字符"));
        }

        // 检查是否是预期的格式
        let first_char = trimmed.chars().next().unwrap_or('\0');
        if !self.is_valid_content_start(first_char) {
            warn!(
                target: "seep::subscription::fetcher",
                url = %url,
                first_char = %first_char,
                "订阅内容格式可能异常"
            );
        }

        Ok(())
    }

    /// 检查内容开始字符是否有效
    fn is_valid_content_start(&self, c: char) -> bool {
        matches!(c,
            '{' | '[' | '<' | // JSON, YAML, XML
            'A'..='Z' | 'a'..='z' // 字母开头（可能是纯文本）
        )
    }

    /// 尝试解码 Base64 内容
    pub fn try_decode_base64(&self, content: &str) -> Result<String> {
        // 检查是否是 Base64 格式
        if !self.looks_like_base64(content) {
            return Ok(content.to_string());
        }

        match BASE64.decode(content.trim()) {
            Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
                Ok(decoded_string) => {
                    debug!(
                        target: "seep::subscription::fetcher",
                        original_len = content.len(),
                        decoded_len = decoded_string.len(),
                        "成功解码 Base64 内容"
                    );
                    Ok(decoded_string)
                }
                Err(_) => {
                    warn!(
                        target: "seep::subscription::fetcher",
                        "Base64 解码成功但不是有效的 UTF-8"
                    );
                    Ok(content.to_string())
                }
            },
            Err(_) => {
                debug!(
                    target: "seep::subscription::fetcher",
                    "内容不是有效的 Base64"
                );
                Ok(content.to_string())
            }
        }
    }

    /// 检查内容是否看起来像 Base64
    fn looks_like_base64(&self, content: &str) -> bool {
        let trimmed = content.trim();

        // 空行分割检查
        let lines: Vec<&str> = trimmed.lines().collect();

        // 单行且较长，可能是 Base64
        if lines.len() == 1 {
            let t = trimmed;
            return t.len() >= 8
                && t.len().is_multiple_of(4)
                && t.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
                });
        }

        // 多行，每行都是 Base64（V2Ray 订阅格式）
        if lines.len() > 1 {
            let base64_lines = lines
                .iter()
                .filter(|line| {
                    let line = line.trim();
                    if line.is_empty() {
                        return false;
                    }

                    if line.starts_with("vmess://")
                        || line.starts_with("vless://")
                        || line.starts_with("trojan://")
                        || line.starts_with("ss://")
                    {
                        return true;
                    }

                    line.len() >= 8
                        && line.len() % 4 == 0
                        && line.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
                        })
                })
                .count();

            return base64_lines > lines.len() / 2; // 超过一半的行看起来像 Base64
        }

        false
    }

    /// 清理和标准化内容
    pub fn normalize_content(&self, content: &str) -> String {
        let mut lines = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // 跳过空行和注释行
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            lines.push(line);
        }

        lines.join("\n")
    }

    /// 获取配置
    pub fn config(&self) -> &FetcherConfig {
        &self.config
    }
}

impl Default for SubscriptionFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_detection() {
        let fetcher = SubscriptionFetcher::new();

        // 普通 Base64
        let base64_content = "SGVsbG8gV29ybGQ="; // "Hello World"
        assert!(fetcher.looks_like_base64(base64_content));

        // V2Ray 订阅格式
        let v2ray_content = r#"
vmess://eyJ2IjogIjIiLCAicHMiOiAi6L+Z5Liq6L295Lu95py66L2m77yM5riF5r2t5L2c5Li677yB6Zif5Lqy5paH5pys5paH5Lu2"
trojan://password@server.com:443#test
        "#;
        assert!(fetcher.looks_like_base64(v2ray_content));

        // JSON 格式
        let json_content = r#"
{
    "proxies": [
        {
            "name": "proxy1",
            "type": "http"
        }
    ]
}
        "#;
        assert!(!fetcher.looks_like_base64(json_content));
    }

    #[test]
    fn test_content_validation() {
        let fetcher = SubscriptionFetcher::new();

        // 有效内容
        let valid_content = "{\"proxies\": []}";
        assert!(fetcher
            .validate_content(valid_content, "http://example.com")
            .is_ok());

        // 空内容
        assert!(fetcher.validate_content("", "http://example.com").is_err());

        // 空白内容
        assert!(fetcher
            .validate_content("   \n\t   ", "http://example.com")
            .is_err());

        // 过大内容（模拟）
        let large_content = "x".repeat(50 * 1024 * 1024 + 1);
        assert!(fetcher
            .validate_content(&large_content, "http://example.com")
            .is_err());
    }

    #[test]
    fn test_normalize_content() {
        let fetcher = SubscriptionFetcher::new();

        let content = r#"
# This is a comment

{
    "key": "value"
}

# Another comment
        "#;

        let normalized = fetcher.normalize_content(content);
        assert!(!normalized.contains('#'));
        assert!(!normalized.contains("\n\n"));
        assert!(normalized.contains("\"key\": \"value\""));
    }

    #[test]
    fn test_valid_content_start() {
        let fetcher = SubscriptionFetcher::new();

        assert!(fetcher.is_valid_content_start('{'));
        assert!(fetcher.is_valid_content_start('['));
        assert!(fetcher.is_valid_content_start('<'));
        assert!(fetcher.is_valid_content_start('A'));
        assert!(fetcher.is_valid_content_start('v'));
        assert!(fetcher.is_valid_content_start('t'));
        assert!(fetcher.is_valid_content_start('s'));

        assert!(!fetcher.is_valid_content_start('!'));
        assert!(!fetcher.is_valid_content_start('@'));
    }

    /// 有界读取回归：Content-Length 超过 50MiB 上限即快速拒绝（不读体）。
    #[tokio::test]
    async fn fetch_rejects_oversized_content_length() {
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let big: u64 = 50 * 1024 * 1024 + 1;
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt as _;
                // 先读请求头（读到空行），再回响应：hyper 在发送请求头期间
                // 收到响应字节会报 "unexpected message"，须按真实服务器顺序。
                let mut buf = [0u8; 1024];
                let mut seen = Vec::new();
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 { break; }
                    seen.extend_from_slice(&buf[..n]);
                    if seen.windows(4).any(|w| w == b"\r\n\r\n") { break; }
                }
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {big}\r\n\r\n");
                let _ = s.write_all(resp.as_bytes()).await;
                // 保持连接短暂存活，让客户端读完头并命中 content-length 检查
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        // max_retries=1：拒收错误本身即终态，不因 fetch() 的重试把单发
        // 假服务耗尽而把终态错误掩盖成 Connection refused
        let fetcher = SubscriptionFetcher::with_config(FetcherConfig {
            max_retries: 1,
            ..Default::default()
        });
        let err = fetcher.fetch(&format!("http://{addr}/sub")).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("订阅内容过大"),
            "应命中 Content-Length 上限快速拒绝，得到: {msg}"
        );
    }
}
