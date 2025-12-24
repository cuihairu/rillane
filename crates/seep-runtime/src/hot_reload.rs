//! 热更新和订阅管理模块

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::{fs, sync::mpsc, task::JoinHandle};
use tracing::{error, info, warn};

use seep_config::SeepConfig;
use seep_routing::RoutingEngine;
use seep_subscription::{Subscription, SubscriptionConverter, SubscriptionManager};

/// 热更新管理器
pub struct HotReloadManager {
    /// 配置文件路径
    config_path: PathBuf,
    /// 当前配置
    current_config: Arc<RwLock<SeepConfig>>,
    /// 路由引擎
    router: Arc<RoutingEngine>,
    /// 订阅管理器
    subscription_manager: Arc<SubscriptionManager>,
    /// 订阅转换器
    subscription_converter: SubscriptionConverter,
    /// 热更新配置
    config: HotReloadConfig,
    /// 运行状态
    running: Arc<RwLock<bool>>,
    /// 更新事件发送器
    reload_tx: mpsc::UnboundedSender<ReloadEvent>,
    /// 更新事件接收器
    reload_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<ReloadEvent>>>>,
}

/// 热更新配置
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// 是否启用配置文件监控
    pub watch_config_file: bool,
    /// 是否启用订阅自动刷新
    pub enable_auto_refresh: bool,
    /// 订阅刷新间隔（分钟）
    pub subscription_refresh_interval: Duration,
    /// 配置重载间隔（秒）- 防止频繁重载
    pub min_reload_interval: Duration,
    /// 最大重载错误次数
    pub max_reload_errors: u32,
    /// 重载错误计数重置间隔（分钟）
    pub reload_error_reset_interval: Duration,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            watch_config_file: true,
            enable_auto_refresh: true,
            subscription_refresh_interval: Duration::from_secs(3600), // 1小时
            min_reload_interval: Duration::from_secs(5),
            max_reload_errors: 5,
            reload_error_reset_interval: Duration::from_secs(300), // 5分钟
        }
    }
}

/// 重载事件
#[derive(Debug, Clone)]
pub enum ReloadEvent {
    /// 配置文件重载
    ConfigReloaded {
        path: PathBuf,
        success: bool,
        error: Option<String>,
    },
    /// 订阅更新
    SubscriptionUpdated {
        name: String,
        success: bool,
        error: Option<String>,
        nodes_added: usize,
        nodes_removed: usize,
    },
    /// 路由重载
    RoutingReloaded {
        success: bool,
        error: Option<String>,
    },
    /// 错误事件
    Error { error: String },
}

/// 重载统计信息
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReloadStats {
    /// 配置重载次数
    pub config_reloads: u64,
    /// 配置重载成功次数
    pub config_reload_successes: u64,
    /// 订阅更新次数
    pub subscription_updates: u64,
    /// 订阅更新成功次数
    pub subscription_update_successes: u64,
    /// 路由重载次数
    pub routing_reloads: u64,
    /// 路由重载成功次数
    pub routing_reload_successes: u64,
    /// 最后重载时间
    pub last_reload_time: Option<chrono::DateTime<chrono::Utc>>,
    /// 错误次数
    pub error_count: u64,
    /// 连续错误次数
    pub consecutive_errors: u32,
}

impl HotReloadManager {
    /// 创建新的热更新管理器
    pub fn new(
        config_path: PathBuf,
        initial_config: SeepConfig,
        router: Arc<RoutingEngine>,
    ) -> Result<Self> {
        let (reload_tx, reload_rx) = mpsc::unbounded_channel();

        // 创建订阅管理器
        let subscription_manager = Arc::new(SubscriptionManager::new());

        // 创建订阅转换器
        let subscription_converter = SubscriptionConverter::new();

        Ok(Self {
            config_path,
            current_config: Arc::new(RwLock::new(initial_config)),
            router,
            subscription_manager,
            subscription_converter,
            config: HotReloadConfig::default(),
            running: Arc::new(RwLock::new(false)),
            reload_tx,
            reload_rx: Arc::new(RwLock::new(Some(reload_rx))),
        })
    }

    /// 设置热更新配置
    pub fn with_config(mut self, config: HotReloadConfig) -> Self {
        self.config = config;
        self
    }

    /// 启动热更新管理器
    pub async fn start(self: Arc<Self>) -> Vec<JoinHandle<()>> {
        let mut handles = Vec::new();

        // 设置运行状态
        *self.running.write().expect("running lock poisoned") = true;

        // 启动配置文件监控
        if self.config.watch_config_file {
            let manager = self.clone();
            handles.push(tokio::spawn(async move {
                manager.watch_config_file().await;
            }));
        }

        // 启动订阅自动刷新
        if self.config.enable_auto_refresh {
            let manager = self.clone();
            handles.push(tokio::spawn(async move {
                manager.run_subscription_refresh().await;
            }));
        }

        // 启动事件处理
        let manager = self.clone();
        handles.push(tokio::spawn(async move {
            manager.handle_reload_events().await;
        }));

        info!(
            target: "seep::runtime::hot_reload",
            config = ?self.config,
            "热更新管理器已启动"
        );

        handles
    }

    /// 停止热更新管理器
    pub async fn stop(&self) -> Result<()> {
        info!(
            target: "seep::runtime::hot_reload",
            "停止热更新管理器"
        );

        *self.running.write().expect("running lock poisoned") = false;

        // 清理资源
        Ok(())
    }

    /// 检查是否运行中
    pub fn is_running(&self) -> bool {
        *self.running.read().expect("running lock poisoned")
    }

    /// 获取当前配置
    pub fn get_current_config(&self) -> SeepConfig {
        self.current_config
            .read()
            .expect("config lock poisoned")
            .clone()
    }

    /// 手动重载配置
    pub async fn reload_config(&self) -> Result<()> {
        info!(
            target: "seep::runtime::hot_reload",
            path = %self.config_path.display(),
            "手动重载配置"
        );

        self.load_config_file().await
    }

    /// 添加订阅
    pub async fn add_subscription(&self, subscription: Subscription) -> Result<()> {
        info!(
            target: "seep::runtime::hot_reload",
            name = %subscription.name,
            "添加订阅"
        );

        self.subscription_manager.add_subscription(subscription)?;

        // 如果启用自动刷新，立即刷新新添加的订阅
        if self.config.enable_auto_refresh {
            // 这里应该触发单个订阅的刷新
        }

        Ok(())
    }

    /// 移除订阅
    pub async fn remove_subscription(&self, name: &str) -> Result<()> {
        info!(
            target: "seep::runtime::hot_reload",
            name = %name,
            "移除订阅"
        );

        self.subscription_manager.remove_subscription(name)?;
        Ok(())
    }

    /// 刷新所有订阅
    pub async fn refresh_all_subscriptions(&self) -> Vec<(String, Result<String>)> {
        info!(
            target: "seep::runtime::hot_reload",
            "刷新所有订阅"
        );

        let results = self.subscription_manager.refresh_all_subscriptions().await;

        // 处理结果并更新配置
        self.process_subscription_results(&results).await;

        results
    }

    /// 获取订阅列表
    pub fn list_subscriptions(&self) -> Vec<Subscription> {
        self.subscription_manager.list_subscriptions()
    }

    /// 获取重载统计信息
    pub fn get_reload_stats(&self) -> ReloadStats {
        // 这里应该维护一个统计状态，现在返回默认值
        ReloadStats::default()
    }

    /// 监控配置文件
    async fn watch_config_file(&self) {
        let config_path = self.config_path.clone();
        let running = self.running.clone();
        let min_interval = self.config.min_reload_interval;
        let reload_tx = self.reload_tx.clone();

        // 简化的文件监控实现（实际应用中应该使用 notify crate）
        let mut last_reload = Instant::now();
        let mut last_mtime = None;

        while *running.read().expect("running lock poisoned") {
            tokio::time::sleep(Duration::from_secs(5)).await;

            // 检查文件修改时间
            if let Ok(metadata) = fs::metadata(&config_path).await {
                if let Ok(modified) = metadata.modified() {
                    let modified_ts = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let has_changed = last_mtime.map(|prev| modified_ts > prev).unwrap_or(true);

                    if has_changed && last_reload.elapsed() >= min_interval {
                        info!(
                            target: "seep::runtime::hot_reload",
                            path = %config_path.display(),
                            "检测到配置文件变化，准备重载"
                        );

                        if let Err(e) = self.load_config_file().await {
                            let _ = reload_tx.send(ReloadEvent::Error {
                                error: format!("配置重载失败: {}", e),
                            });
                        }

                        last_reload = Instant::now();
                        last_mtime = Some(modified_ts);
                    }
                }
            }
        }
    }

    /// 运行订阅刷新循环
    async fn run_subscription_refresh(&self) {
        let running = self.running.clone();
        let refresh_interval = self.config.subscription_refresh_interval;

        while *running.read().expect("running lock poisoned") {
            tokio::time::sleep(refresh_interval).await;

            if !self.config.enable_auto_refresh {
                continue;
            }

            info!(
                target: "seep::runtime::hot_reload",
                "定时刷新订阅"
            );

            let results = self.subscription_manager.refresh_all_subscriptions().await;
            self.process_subscription_results(&results).await;
        }
    }

    /// 处理重载事件
    async fn handle_reload_events(&self) {
        let mut reload_rx = {
            let mut rx_guard = self.reload_rx.write().expect("reload_rx lock poisoned");
            rx_guard.take().expect("reload_rx already taken")
        };

        let running = self.running.clone();

        while *running.read().expect("running lock poisoned") {
            match reload_rx.recv().await {
                Some(event) => {
                    self.handle_reload_event(event).await;
                }
                None => {
                    info!(
                        target: "seep::runtime::hot_reload",
                        "重载事件通道已关闭"
                    );
                    break;
                }
            }
        }
    }

    /// 处理单个重载事件
    async fn handle_reload_event(&self, event: ReloadEvent) {
        match event {
            ReloadEvent::ConfigReloaded {
                path,
                success,
                error,
            } => {
                if success {
                    info!(
                        target: "seep::runtime::hot_reload",
                        path = %path.display(),
                        "配置重载成功"
                    );
                } else {
                    error!(
                        target: "seep::runtime::hot_reload",
                        path = %path.display(),
                        error = %error.as_deref().unwrap_or("unknown"),
                        "配置重载失败"
                    );
                }
            }
            ReloadEvent::SubscriptionUpdated {
                name,
                success,
                nodes_added,
                nodes_removed,
                error,
            } => {
                if success {
                    info!(
                        target: "seep::runtime::hot_reload",
                        name = %name,
                        added = nodes_added,
                        removed = nodes_removed,
                        "订阅更新成功"
                    );
                } else {
                    error!(
                        target: "seep::runtime::hot_reload",
                        name = %name,
                        error = %error.as_deref().unwrap_or("unknown"),
                        "订阅更新失败"
                    );
                }
            }
            ReloadEvent::RoutingReloaded { success, error } => {
                if success {
                    info!(
                        target: "seep::runtime::hot_reload",
                        "路由重载成功"
                    );
                } else {
                    error!(
                        target: "seep::runtime::hot_reload",
                        error = %error.as_deref().unwrap_or("unknown"),
                        "路由重载失败"
                    );
                }
            }
            ReloadEvent::Error { error } => {
                error!(
                    target: "seep::runtime::hot_reload",
                    error = %error,
                    "热更新错误"
                );
            }
        }
    }

    /// 加载配置文件
    async fn load_config_file(&self) -> Result<()> {
        let config_content = fs::read_to_string(&self.config_path)
            .await
            .with_context(|| format!("无法读取配置文件: {}", self.config_path.display()))?;

        let new_config = SeepConfig::from_str(&config_content, None)
            .with_context(|| "解析配置文件失败".to_string())?;

        // 验证配置
        self.validate_config(&new_config)?;

        // 更新路由引擎
        self.router.reload(new_config.routing.clone());

        // 更新当前配置
        *self.current_config.write().expect("config lock poisoned") = new_config;

        let _ = self.reload_tx.send(ReloadEvent::ConfigReloaded {
            path: self.config_path.clone(),
            success: true,
            error: None,
        });

        Ok(())
    }

    /// 验证配置
    fn validate_config(&self, config: &SeepConfig) -> Result<()> {
        // 基本验证
        if config.ingress.is_empty() {
            warn!(
                target: "seep::runtime::hot_reload",
                "配置中未定义入口"
            );
        }

        if config.egress.is_empty() {
            warn!(
                target: "seep::runtime::hot_reload",
                "配置中未定义出口"
            );
        }

        // 验证默认节点存在
        let default_node_exists = config
            .egress
            .iter()
            .any(|e| e.name == config.routing.default_node);

        if !default_node_exists {
            warn!(
                target: "seep::runtime::hot_reload",
                default_node = %config.routing.default_node,
                "默认节点未在出口列表中找到"
            );
        }

        Ok(())
    }

    /// 处理订阅结果
    async fn process_subscription_results(&self, results: &[(String, Result<String>)]) {
        for (name, result) in results {
            match result {
                Ok(content) => {
                    // 尝试解析订阅内容
                    let subscription = self.subscription_manager.get_subscription(name);
                    if let Some(sub) = subscription {
                        let conversion_result = self
                            .subscription_converter
                            .auto_convert(&sub, content)
                            .await;

                        match conversion_result {
                            Ok(converted) => {
                                // 合并到当前配置
                                if let Err(e) =
                                    self.merge_subscription_config(&converted.config).await
                                {
                                    let _ = self.reload_tx.send(ReloadEvent::Error {
                                        error: format!("合并订阅配置失败: {}", e),
                                    });
                                } else {
                                    let _ = self.reload_tx.send(ReloadEvent::SubscriptionUpdated {
                                        name: name.clone(),
                                        success: true,
                                        error: None,
                                        nodes_added: converted.config.egress.len(),
                                        nodes_removed: 0, // 需要计算
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = self.reload_tx.send(ReloadEvent::SubscriptionUpdated {
                                    name: name.clone(),
                                    success: false,
                                    error: Some(format!("转换订阅失败: {}", e)),
                                    nodes_added: 0,
                                    nodes_removed: 0,
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = self.reload_tx.send(ReloadEvent::SubscriptionUpdated {
                        name: name.clone(),
                        success: false,
                        error: Some(format!("获取订阅失败: {}", e)),
                        nodes_added: 0,
                        nodes_removed: 0,
                    });
                }
            }
        }
    }

    /// 合并订阅配置到当前配置
    async fn merge_subscription_config(&self, subscription_config: &SeepConfig) -> Result<()> {
        let mut current_config = self
            .current_config
            .write()
            .expect("config lock poisoned")
            .clone();

        // 合并出口节点
        for egress in &subscription_config.egress {
            if !current_config.egress.iter().any(|e| e.name == egress.name) {
                current_config.egress.push(egress.clone());
            }
        }

        // 合并路由组
        for group in &subscription_config.routing.groups {
            if !current_config
                .routing
                .groups
                .iter()
                .any(|g| g.name == group.name)
            {
                current_config.routing.groups.push(group.clone());
            }
        }

        // 合并路由规则
        for rule in &subscription_config.routing.rules {
            current_config.routing.rules.push(rule.clone());
        }

        // 更新路由引擎
        self.router.reload(current_config.routing.clone());

        // 保存更新后的配置
        let config_content = serde_yaml::to_string(&current_config).context("序列化配置失败")?;

        fs::write(&self.config_path, config_content)
            .await
            .with_context(|| format!("无法写入配置文件: {}", self.config_path.display()))?;

        Ok(())
    }

    /// 获取重载事件接收器
    pub fn take_reload_rx(&self) -> Option<mpsc::UnboundedReceiver<ReloadEvent>> {
        let mut rx_guard = self.reload_rx.write().expect("reload_rx lock poisoned");
        rx_guard.take()
    }

    /// 克隆重载事件发送器
    pub fn clone_reload_tx(&self) -> mpsc::UnboundedSender<ReloadEvent> {
        self.reload_tx.clone()
    }
}

impl Default for HotReloadManager {
    fn default() -> Self {
        // 这里提供一个简单的默认实现，实际使用中需要提供必需的参数
        panic!("HotReloadManager::default() 不可用，请使用 new() 方法")
    }
}
