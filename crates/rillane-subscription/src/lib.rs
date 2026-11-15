//! Rillane 订阅管理模块
//!
//! 支持多种订阅源的拉取、解析和配置转换，包括：
//! - Clash 配置订阅
//! - Rillane DSL 订阅
//! - 自动刷新和缓存管理
//! - 热更新支持

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info};

pub mod cache;
pub mod clash;
pub mod clash_export;
pub mod converter;
pub mod fetcher;
pub mod provider_fetch;
pub mod rillane_dsl;
pub mod rule_source;
// 来源快照原子替换（RIL-008）：以来源版本整体替换，失败保留旧快照
pub mod snapshots;

pub use cache::*;
pub use clash::*;
pub use clash_export::*;
pub use converter::*;
pub use fetcher::*;
pub use provider_fetch::*;
pub use rillane_dsl::*;
pub use rule_source::*;
pub use snapshots::{RefreshError, RefreshOutcome, SourceSnapshotStore};

/// 订阅类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionType {
    /// Clash 配置
    Clash,
    /// Rillane DSL
    Rillane,
    /// V2Ray 订阅
    V2Ray,
    /// 自定义格式
    Custom,
}

impl std::fmt::Display for SubscriptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clash => write!(f, "clash"),
            Self::Rillane => write!(f, "rillane"),
            Self::V2Ray => write!(f, "v2ray"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// 订阅源配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// 订阅名称
    pub name: String,
    /// 订阅 URL
    pub url: String,
    /// 订阅类型（自动检测或手动指定）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<SubscriptionType>,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 刷新间隔（分钟）
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
    /// 超时时间（秒）
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// 自定义请求头
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    /// 用户代理
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// 最后更新时间
    #[serde(skip)]
    pub last_updated: Option<DateTime<Utc>>,
    /// 最后错误
    #[serde(skip)]
    pub last_error: Option<String>,
    /// ETag 缓存
    #[serde(skip)]
    pub etag: Option<String>,
    /// Last-Modified 缓存
    #[serde(skip)]
    pub last_modified: Option<String>,
    /// 内容哈希
    #[serde(skip)]
    pub content_hash: Option<String>,
}

fn default_enabled() -> bool {
    true
}
fn default_refresh_interval() -> u64 {
    60
} // 1小时
fn default_timeout() -> u64 {
    30
}

impl Subscription {
    /// 创建新的订阅
    pub fn new(name: String, url: String) -> Self {
        Self {
            name,
            url,
            r#type: None,
            enabled: true,
            refresh_interval: default_refresh_interval(),
            timeout: default_timeout(),
            headers: HashMap::new(),
            user_agent: None,
            last_updated: None,
            last_error: None,
            etag: None,
            last_modified: None,
            content_hash: None,
        }
    }

    /// 设置订阅类型
    pub fn with_type(mut self, r#type: SubscriptionType) -> Self {
        self.r#type = Some(r#type);
        self
    }

    /// 设置刷新间隔
    pub fn with_refresh_interval(mut self, minutes: u64) -> Self {
        self.refresh_interval = minutes;
        self
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout = seconds;
        self
    }

    /// 添加自定义请求头
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// 设置用户代理
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// 检查是否需要刷新
    pub fn needs_refresh(&self) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(last_updated) = self.last_updated {
            let elapsed = Utc::now().signed_duration_since(last_updated);
            elapsed.num_minutes() >= self.refresh_interval as i64
        } else {
            true
        }
    }

    /// 更新状态信息
    pub fn update_status(&mut self, success: bool, error: Option<String>) {
        self.last_updated = Some(Utc::now());

        if success {
            self.last_error = None;
        } else {
            self.last_error = error;
        }
    }

    /// 检测订阅类型
    pub fn detect_type(&self, content: &str) -> SubscriptionType {
        // 检查是否是 Clash 配置
        if content.contains("proxies:") && content.contains("proxy-groups:") {
            return SubscriptionType::Clash;
        }

        // 检查是否是 Rillane DSL
        if content.contains("version:") && content.contains("nodes:") {
            return SubscriptionType::Rillane;
        }

        // 检查是否是 V2Ray 订阅（Base64 编码的 VMess 链接）
        if content.lines().any(|line| {
            line.trim().starts_with("vmess://")
                || line.trim().starts_with("vless://")
                || line.trim().starts_with("trojan://")
                || line.trim().starts_with("ss://")
                || line.trim().starts_with("hysteria2://")
                || line.trim().starts_with("hy2://")
                || line.trim().starts_with("socks5://")
                || line.trim().starts_with("socks://")
                || line.trim().starts_with("http://")
                || line.trim().starts_with("https://")
        }) {
            return SubscriptionType::V2Ray;
        }

        // 默认为自定义
        SubscriptionType::Custom
    }

    /// 计算内容哈希
    pub fn calculate_hash(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// 检查内容是否已更改
    pub fn has_content_changed(&self, new_content: &str) -> bool {
        let new_hash = self.calculate_hash(new_content);
        match &self.content_hash {
            Some(old_hash) => old_hash != &new_hash,
            None => true,
        }
    }

    /// 更新内容哈希
    pub fn update_content_hash(&mut self, content: &str) {
        self.content_hash = Some(self.calculate_hash(content));
    }
}

/// 订阅管理器
#[derive(Debug)]
pub struct SubscriptionManager {
    /// 订阅列表
    subscriptions: RwLock<HashMap<String, Subscription>>,
    /// 缓存管理器
    cache: Arc<SubscriptionCache>,
    /// 配置文件路径
    config_path: Option<PathBuf>,
    /// 刷新间隔（全局）
    global_refresh_interval: Duration,
    /// 订阅集合变更代（删除/重载递增）。refresh_subscription 在 fetch 前
    /// 快照此代，写回时若代已变（订阅被删除）则不复活旧状态。
    subscription_epoch: Arc<AtomicU64>,
}

impl SubscriptionManager {
    /// 创建新的订阅管理器
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            cache: Arc::new(SubscriptionCache::new()),
            config_path: None,
            global_refresh_interval: Duration::from_secs(300), // 5分钟
            subscription_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 从配置文件加载订阅
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取订阅配置文件: {}", path.display()))?;

        let subscriptions: Vec<Subscription> = if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            == Some("json".to_string())
        {
            serde_json::from_str(&content)?
        } else {
            serde_yaml::from_str(&content)?
        };

        let mut manager = Self::new();
        manager.config_path = Some(path.to_path_buf());

        let sub_count = subscriptions.len();
        let mut subs_map = HashMap::new();
        for sub in subscriptions {
            subs_map.insert(sub.name.clone(), sub);
        }

        *manager
            .subscriptions
            .write()
            .expect("subscriptions lock poisoned") = subs_map;

        info!(
            target: "rillane::subscription",
            count = %sub_count,
            path = %path.display(),
            "从配置文件加载订阅"
        );

        Ok(manager)
    }

    /// 添加订阅
    pub fn add_subscription(&self, subscription: Subscription) -> Result<()> {
        let mut subs = self
            .subscriptions
            .write()
            .expect("subscriptions lock poisoned");

        if subs.contains_key(&subscription.name) {
            return Err(anyhow!("订阅 {} 已存在", subscription.name));
        }

        info!(
            target: "rillane::subscription",
            name = %subscription.name,
            url = %subscription.url,
            "添加订阅"
        );

        subs.insert(subscription.name.clone(), subscription);
        Ok(())
    }

    /// 移除订阅
    pub fn remove_subscription(&self, name: &str) -> Result<()> {
        let mut subs = self
            .subscriptions
            .write()
            .expect("subscriptions lock poisoned");

        if subs.remove(name).is_none() {
            return Err(anyhow!("订阅 {} 不存在", name));
        }
        // 持写锁内递增：与 refresh_subscription 在克隆块内读 map+epoch 串行，
        // 消除「map 已删但 epoch 未变」的复活窗口。
        self.subscription_epoch.fetch_add(1, Ordering::AcqRel);

        info!(
            target: "rillane::subscription",
            name = %name,
            "移除订阅"
        );

        // 从缓存中也移除
        self.cache.remove(name);

        Ok(())
    }

    /// 获取订阅列表
    pub fn list_subscriptions(&self) -> Vec<Subscription> {
        self.subscriptions
            .read()
            .expect("subscriptions lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// 获取特定订阅
    pub fn get_subscription(&self, name: &str) -> Option<Subscription> {
        self.subscriptions
            .read()
            .expect("subscriptions lock poisoned")
            .get(name)
            .cloned()
    }

    /// 刷新单个订阅
    pub async fn refresh_subscription(&self, name: &str) -> Result<String> {
        let (mut subscription, snapshot_epoch) = {
            let subs = self
                .subscriptions
                .read()
                .expect("subscriptions lock poisoned");
            let subscription = subs
                .get(name)
                .ok_or_else(|| anyhow!("订阅 {} 不存在", name))?
                .clone();
            let snapshot_epoch = self.subscription_epoch.load(Ordering::Acquire);
            (subscription, snapshot_epoch)
        };

        if !subscription.enabled {
            return Err(anyhow!("订阅 {} 已禁用", name));
        }

        debug!(
            target: "rillane::subscription",
            name = %name,
            url = %subscription.url,
            "开始刷新订阅"
        );

        // 创建获取器
        let mut fetcher = SubscriptionFetcher::new()
            .with_timeout(Duration::from_secs(subscription.timeout))
            .with_user_agent(subscription.user_agent.clone());

        // 添加自定义请求头
        for (key, value) in &subscription.headers {
            fetcher.add_header(key.clone(), value.clone());
        }

        // 检查缓存
        if self.cache.get(name).is_some() {
            if let Some(etag) = &subscription.etag {
                fetcher.add_header("If-None-Match".to_string(), etag.clone());
            }
            if let Some(last_modified) = &subscription.last_modified {
                fetcher.add_header("If-Modified-Since".to_string(), last_modified.clone());
            }
        }

        // 获取内容
        let fetch_result = fetcher
            .fetch(&subscription.url)
            .await
            .with_context(|| format!("获取订阅 {} 失败", name))?;

        let content = fetch_result.content;
        let etag = fetch_result.etag;
        let last_modified = fetch_result.last_modified;

        // 检查内容是否已更改
        if !subscription.has_content_changed(&content) {
            debug!(
                target: "rillane::subscription",
                name = %name,
                "订阅内容未更改，跳过更新"
            );
            subscription.update_status(true, None);
            self.update_subscription_in_map_checked(subscription, snapshot_epoch)?;
            return Ok(content);
        }

        // 更新订阅状态
        subscription.update_status(true, None);
        subscription.etag = etag;
        subscription.last_modified = last_modified;
        subscription.update_content_hash(&content);

        // 保存到缓存
        self.cache.set(name, &content)?;

        // 更新订阅信息
        self.update_subscription_in_map_checked(subscription, snapshot_epoch)?;

        info!(
            target: "rillane::subscription",
            name = %name,
            size = %content.len(),
            "订阅刷新成功"
        );

        Ok(content)
    }

    /// 刷新所有订阅
    pub async fn refresh_all_subscriptions(&self) -> Vec<(String, Result<String>)> {
        let subscriptions: Vec<String> = {
            self.subscriptions
                .read()
                .expect("subscriptions lock poisoned")
                .keys()
                .cloned()
                .collect()
        };

        let mut results = Vec::new();

        for name in subscriptions {
            let result = self.refresh_subscription(&name).await;
            results.push((name, result));
        }

        let success_count = results.iter().filter(|(_, r)| r.is_ok()).count();
        info!(
            target: "rillane::subscription",
            total = %results.len(),
            success = %success_count,
            failed = %(results.len() - success_count),
            "批量刷新订阅完成"
        );

        results
    }

    /// 保存配置到文件
    pub fn save_config(&self) -> Result<()> {
        let Some(config_path) = &self.config_path else {
            return Err(anyhow!("未设置配置文件路径"));
        };

        let subscriptions: Vec<Subscription> = self
            .subscriptions
            .read()
            .expect("subscriptions lock poisoned")
            .values()
            .cloned()
            .collect();

        let content = if config_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            == Some("json".to_string())
        {
            serde_json::to_string_pretty(&subscriptions)?
        } else {
            serde_yaml::to_string(&subscriptions)?
        };

        std::fs::write(config_path, content)
            .with_context(|| format!("无法写入订阅配置文件: {}", config_path.display()))?;

        info!(
            target: "rillane::subscription",
            path = %config_path.display(),
            count = %subscriptions.len(),
            "保存订阅配置"
        );

        Ok(())
    }

    /// 启动自动刷新任务
    pub fn start_auto_refresh(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(self.global_refresh_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;

                debug!(
                    target: "rillane::subscription",
                    "开始定时刷新订阅"
                );

                // 获取需要刷新的订阅
                let names_to_refresh: Vec<String> = {
                    self.subscriptions
                        .read()
                        .expect("subscriptions lock poisoned")
                        .iter()
                        .filter(|(_, sub)| sub.enabled && sub.needs_refresh())
                        .map(|(name, _)| name.clone())
                        .collect()
                };

                if names_to_refresh.is_empty() {
                    debug!(
                        target: "rillane::subscription",
                        "无需要刷新的订阅"
                    );
                    continue;
                }

                // 并发刷新订阅
                let mut tasks = Vec::new();
                for name in names_to_refresh {
                    let manager = self.clone();
                    tasks.push(tokio::spawn(async move {
                        manager.refresh_subscription(&name).await
                    }));
                }

                // 等待所有任务完成
                let results = futures::future::join_all(tasks).await;
                let success_count = results.iter().filter(|r| matches!(r, Ok(Ok(_)))).count();

                info!(
                    target: "rillane::subscription",
                    total = %results.len(),
                    success = %success_count,
                    failed = %(results.len() - success_count),
                    "定时刷新完成"
                );
            }
        })
    }

    /// 条件写回：仅当快照代仍为当前代（期间订阅未被删除/重载）才插入。
    /// 修复 read-modify-write 复活——refresh_subscription 长 fetch 期间热更
    /// 删除的订阅不得被旧状态回写复活。
    fn update_subscription_in_map_checked(
        &self,
        subscription: Subscription,
        snapshot_epoch: u64,
    ) -> Result<()> {
        let mut subs = self
            .subscriptions
            .write()
            .expect("subscriptions lock poisoned");
        if self.subscription_epoch.load(Ordering::Acquire) != snapshot_epoch {
            return Ok(());
        }
        subs.insert(subscription.name.clone(), subscription);
        Ok(())
    }

    /// 获取订阅统计信息
    pub fn get_stats(&self) -> SubscriptionStats {
        let subs = self
            .subscriptions
            .read()
            .expect("subscriptions lock poisoned");

        let total = subs.len();
        let enabled = subs.values().filter(|s| s.enabled).count();
        let needs_refresh = subs.values().filter(|s| s.needs_refresh()).count();
        let with_errors = subs.values().filter(|s| s.last_error.is_some()).count();

        SubscriptionStats {
            total,
            enabled,
            disabled: total - enabled,
            needs_refresh,
            with_errors,
            healthy: enabled - with_errors,
        }
    }
}

/// 订阅统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionStats {
    /// 总订阅数
    pub total: usize,
    /// 启用数
    pub enabled: usize,
    /// 禁用数
    pub disabled: usize,
    /// 需要刷新
    pub needs_refresh: usize,
    /// 有错误
    pub with_errors: usize,
    /// 健康数
    pub healthy: usize,
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_subscription_creation() {
        let sub = Subscription::new("test".to_string(), "https://example.com".to_string())
            .with_type(SubscriptionType::Clash)
            .with_refresh_interval(30)
            .with_timeout(60);

        assert_eq!(sub.name, "test");
        assert_eq!(sub.url, "https://example.com");
        assert_eq!(sub.r#type, Some(SubscriptionType::Clash));
        assert_eq!(sub.refresh_interval, 30);
        assert_eq!(sub.timeout, 60);
        assert!(sub.enabled);
    }

    #[test]
    fn test_subscription_hash() {
        let mut sub = Subscription::new("test".to_string(), "https://example.com".to_string());
        let content1 = "test content";
        let content2 = "different content";

        let hash1 = sub.calculate_hash(content1);
        let hash2 = sub.calculate_hash(content2);
        let hash1_again = sub.calculate_hash(content1);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1, hash1_again);
        assert!(sub.has_content_changed(content1));
        sub.update_content_hash(content1);
        assert!(!sub.has_content_changed(content1));
    }

    #[test]
    fn test_type_detection() {
        let sub = Subscription::new("test".to_string(), "https://example.com".to_string());

        let clash_content = r#"
proxies:
  - name: proxy1
    type: http
    server: example.com
    port: 8080
proxy-groups:
  - name: group1
    type: select
    proxies:
      - proxy1
"#;

        let rillane_content = r#"
version: "1.0"
nodes:
  - name: node1
    type: direct
rulesets:
  - name: ruleset1
    rules:
      - domain: example.com
        target: node1
"#;

        assert_eq!(sub.detect_type(clash_content), SubscriptionType::Clash);
        assert_eq!(sub.detect_type(rillane_content), SubscriptionType::Rillane);
    }

    /// 回归：refresh_subscription 在长 fetch 期间订阅被热更删除时，不得用
    /// 旧快照回写复活该订阅（read-modify-write 复活 bug）。
    #[tokio::test]
    async fn refresh_does_not_revive_subscription_removed_during_fetch() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 慢端点：收到请求后延迟 150ms 再回 200 + 内容，确保 refresh 仍在
        // fetch 中（订阅快照已克隆、写回未发生）。
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            let body = "proxies:\n  - name: p1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: test\nproxy-groups:\n  - name: g1\n    type: select\n    proxies:\n      - p1\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });

        let manager = Arc::new(SubscriptionManager::default());
        let url = format!("http://{addr}/sub.yaml");
        manager.add_subscription(Subscription::new("hot".to_string(), url))?;

        // 并发：refresh 进入 fetch（克隆快照）后删除订阅。
        let refresh_handle = tokio::spawn({
            let manager = manager.clone();
            async move { manager.refresh_subscription("hot").await }
        });
        // 确保 refresh 已越过克隆并进入 fetch（server 已 accept 请求）。
        tokio::time::sleep(Duration::from_millis(30)).await;
        manager.remove_subscription("hot")?;

        let refresh_result = refresh_handle.await.unwrap();
        assert!(
            refresh_result.is_ok(),
            "fetch 本身应成功（内容已拉取），复活与否取决于写回"
        );
        assert!(
            manager.get_subscription("hot").is_none(),
            "fetch 完成后订阅不得被旧快照复活"
        );
        server.await.unwrap();
        Ok(())
    }
}
