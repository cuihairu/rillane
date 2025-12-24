//! 订阅内容缓存管理

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::RwLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use tracing::{debug, error, info, warn};

/// 订阅缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// 缓存内容
    pub content: String,
    /// 创建时间
    pub created_at: SystemTime,
    /// 最后访问时间
    pub last_accessed: SystemTime,
    /// 访问次数
    pub access_count: u64,
    /// 过期时间（None 表示永不过期）
    pub expires_at: Option<SystemTime>,
}

impl CacheEntry {
    /// 创建新的缓存条目
    pub fn new(content: String, ttl: Option<Duration>) -> Self {
        let now = SystemTime::now();
        Self {
            content,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            expires_at: ttl.map(|duration| now + duration),
        }
    }

    /// 检查是否已过期
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => SystemTime::now() > expires_at,
            None => false,
        }
    }

    /// 标记访问
    pub fn access(&mut self) {
        self.last_accessed = SystemTime::now();
        self.access_count += 1;
    }

    /// 获取年龄（秒）
    pub fn age_seconds(&self) -> u64 {
        self.created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// 获取上次访问以来的时间（秒）
    pub fn last_access_age_seconds(&self) -> u64 {
        self.last_accessed
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// 订阅缓存配置
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// 缓存目录
    pub cache_dir: PathBuf,
    /// 默认 TTL
    pub default_ttl: Duration,
    /// 最大缓存条目数
    pub max_entries: usize,
    /// 最大缓存大小（字节）
    pub max_size_bytes: u64,
    /// 清理间隔
    pub cleanup_interval: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        fn default_cache_dir() -> PathBuf {
            // Avoid privileged locations like /var/cache (often not writable without sudo).
            // Prefer a per-user cache directory.
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(".cache/seep/subscriptions");
            }
            std::env::temp_dir().join("seep/subscriptions")
        }

        Self {
            cache_dir: default_cache_dir(),
            default_ttl: Duration::from_secs(86400), // 24小时
            max_entries: 1000,
            max_size_bytes: 100 * 1024 * 1024,           // 100MB
            cleanup_interval: Duration::from_secs(3600), // 1小时
        }
    }
}

/// 订阅缓存管理器
#[derive(Debug)]
pub struct SubscriptionCache {
    /// 内存缓存
    memory_cache: RwLock<HashMap<String, CacheEntry>>,
    /// 磁盘缓存目录
    cache_dir: PathBuf,
    /// 配置
    config: CacheConfig,
    /// 当前缓存大小（字节）
    current_size: RwLock<u64>,
}

impl SubscriptionCache {
    /// 创建新的缓存管理器
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// 使用自定义配置创建缓存管理器
    pub fn with_config(config: CacheConfig) -> Self {
        // 确保缓存目录存在
        if let Err(err) = fs::create_dir_all(&config.cache_dir) {
            error!(
                target: "seep::subscription::cache",
                path = %config.cache_dir.display(),
                error = %err,
                "无法创建缓存目录"
            );
        }

        Self {
            memory_cache: RwLock::new(HashMap::new()),
            cache_dir: config.cache_dir.clone(),
            config,
            current_size: RwLock::new(0),
        }
    }

    /// 获取缓存内容
    pub fn get(&self, key: &str) -> Option<String> {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");

        // 首先检查内存缓存
        if let Some(entry) = cache.get_mut(key) {
            if entry.is_expired() {
                debug!(
                    target: "seep::subscription::cache",
                    key = %key,
                    "内存缓存已过期"
                );
                cache.remove(key);
                // 尝试从磁盘加载
                return self.load_from_disk(key);
            } else {
                entry.access();
                debug!(
                    target: "seep::subscription::cache",
                    key = %key,
                    count = entry.access_count,
                    "从内存缓存命中"
                );
                return Some(entry.content.clone());
            }
        }

        // 尝试从磁盘加载
        self.load_from_disk(key)
    }

    /// 设置缓存内容
    pub fn set(&self, key: &str, content: &str) -> Result<()> {
        self.set_with_ttl(key, content, Some(self.config.default_ttl))
    }

    /// 设置带 TTL 的缓存内容
    pub fn set_with_ttl(&self, key: &str, content: &str, ttl: Option<Duration>) -> Result<()> {
        let content_size = content.len() as u64;
        let entry = CacheEntry::new(content.to_string(), ttl);

        // 检查缓存容量限制
        {
            let current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            if *current_size + content_size > self.config.max_size_bytes {
                // 清理过期条目
                self.cleanup_expired()?;

                // 如果仍然超限，按 LRU 清理
                if *current_size + content_size > self.config.max_size_bytes {
                    self.cleanup_lru(content_size)?;
                }
            }
        }

        // 检查条目数量限制
        {
            let mut cache = self.memory_cache.write().expect("cache lock poisoned");
            if cache.len() >= self.config.max_entries {
                self.cleanup_lru_by_count(1)?;
            }

            // 更新大小计算
            if let Some(old_entry) = cache.get(key) {
                let old_size = old_entry.content.len() as u64;
                let mut current_size = self
                    .current_size
                    .write()
                    .expect("current_size lock poisoned");
                *current_size = current_size
                    .saturating_sub(old_size)
                    .saturating_add(content_size);
            } else {
                let mut current_size = self
                    .current_size
                    .write()
                    .expect("current_size lock poisoned");
                *current_size += content_size;
            }

            cache.insert(key.to_string(), entry);
        }

        // 保存到磁盘
        self.save_to_disk(key, content)?;

        debug!(
            target: "seep::subscription::cache",
            key = %key,
            size = content_size,
            "缓存已保存"
        );

        Ok(())
    }

    /// 删除缓存条目
    pub fn remove(&self, key: &str) -> Option<String> {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");

        let old_content = cache.remove(key).map(|entry| {
            // 更新大小统计
            let content_size = entry.content.len() as u64;
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(content_size);

            entry.content
        });

        // 删除磁盘文件
        let disk_path = self.get_disk_path(key);
        if let Err(err) = fs::remove_file(&disk_path) {
            if !matches!(err.kind(), std::io::ErrorKind::NotFound) {
                warn!(
                    target: "seep::subscription::cache",
                    path = %disk_path.display(),
                    error = %err,
                    "无法删除磁盘缓存文件"
                );
            }
        }

        if old_content.is_some() {
            debug!(
                target: "seep::subscription::cache",
                key = %key,
                "缓存已删除"
            );
        }

        old_content
    }

    /// 清空所有缓存
    pub fn clear(&self) -> Result<()> {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");
        cache.clear();

        // 重置大小统计
        let mut current_size = self
            .current_size
            .write()
            .expect("current_size lock poisoned");
        *current_size = 0;

        // 删除所有磁盘文件
        if let Err(err) = fs::read_dir(&self.cache_dir) {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(anyhow!("无法读取缓存目录: {}", err));
            }
            return Ok(());
        }

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Err(err) = fs::remove_file(&path) {
                    warn!(
                        target: "seep::subscription::cache",
                        path = %path.display(),
                        error = %err,
                        "删除缓存文件失败"
                    );
                }
            }
        }

        info!(
            target: "seep::subscription::cache",
            "所有缓存已清空"
        );

        Ok(())
    }

    /// 获取缓存统计信息
    pub fn get_stats(&self) -> CacheStats {
        let cache = self.memory_cache.read().expect("cache lock poisoned");
        let current_size = *self
            .current_size
            .read()
            .expect("current_size lock poisoned");

        let total_entries = cache.len();
        let expired_entries = cache.values().filter(|e| e.is_expired()).count();
        let total_accesses: u64 = cache.values().map(|e| e.access_count).sum();
        let avg_age_seconds = if !cache.is_empty() {
            cache.values().map(|e| e.age_seconds()).sum::<u64>() / cache.len() as u64
        } else {
            0
        };

        CacheStats {
            total_entries,
            expired_entries,
            current_size_bytes: current_size,
            max_entries: self.config.max_entries,
            max_size_bytes: self.config.max_size_bytes,
            total_accesses,
            avg_age_seconds,
        }
    }

    /// 清理过期条目
    pub fn cleanup_expired(&self) -> Result<usize> {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");
        let mut removed_count = 0;
        let mut total_size_removed = 0;

        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            if let Some(entry) = cache.remove(&key) {
                total_size_removed += entry.content.len() as u64;
                removed_count += 1;

                // 删除磁盘文件
                let disk_path = self.get_disk_path(&key);
                if let Err(err) = fs::remove_file(&disk_path) {
                    warn!(
                        target: "seep::subscription::cache",
                        path = %disk_path.display(),
                        error = %err,
                        "删除过期缓存文件失败"
                    );
                }
            }
        }

        // 更新大小统计
        {
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(total_size_removed);
        }

        if removed_count > 0 {
            debug!(
                target: "seep::subscription::cache",
                removed = removed_count,
                size_freed = total_size_removed,
                "清理过期缓存完成"
            );
        }

        Ok(removed_count)
    }

    /// 清理过期的条目（内存缓存）
    pub fn cleanup_lru(&self, needed_space: u64) -> Result<usize> {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");

        if cache.is_empty() {
            return Ok(0);
        }

        // 按最后访问时间排序，收集键和元数据
        let mut entries: Vec<(String, u64, SystemTime)> = cache
            .iter()
            .map(|(k, v)| (k.clone(), v.content.len() as u64, v.last_accessed))
            .collect();

        entries.sort_by_key(|(_, _, last_accessed)| *last_accessed);

        let mut freed_space = 0;
        let mut removed_count = 0;

        for (key, size, _) in entries {
            cache.remove(&key);
            freed_space += size;
            removed_count += 1;

            // 删除磁盘文件
            let disk_path = self.get_disk_path(&key);
            if let Err(err) = fs::remove_file(&disk_path) {
                warn!(
                    target: "seep::subscription::cache",
                    path = %disk_path.display(),
                    error = %err,
                    "删除LRU缓存文件失败"
                );
            }

            if freed_space >= needed_space {
                break;
            }
        }

        // 更新大小统计
        {
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(freed_space);
        }

        debug!(
            target: "seep::subscription::cache",
            removed = removed_count,
            space_freed = freed_space,
            "LRU清理完成"
        );

        Ok(removed_count)
    }

    /// 按数量清理 LRU 条目
    pub fn cleanup_lru_by_count(&self, count: usize) -> Result<usize> {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");

        if cache.len() <= count {
            return Ok(0);
        }

        // 按最后访问时间排序，收集键和元数据
        let mut entries: Vec<(String, u64, SystemTime)> = cache
            .iter()
            .map(|(k, v)| (k.clone(), v.content.len() as u64, v.last_accessed))
            .collect();

        entries.sort_by_key(|(_, _, last_accessed)| *last_accessed);

        let mut removed_count = 0;
        let mut freed_space = 0;

        for (key, size, _) in entries.into_iter().take(count) {
            cache.remove(&key);
            freed_space += size;
            removed_count += 1;

            // 删除磁盘文件
            let disk_path = self.get_disk_path(&key);
            if let Err(err) = fs::remove_file(&disk_path) {
                warn!(
                    target: "seep::subscription::cache",
                    path = %disk_path.display(),
                    error = %err,
                    "删除LRU缓存文件失败"
                );
            }
        }

        // 更新大小统计
        {
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(freed_space);
        }

        debug!(
            target: "seep::subscription::cache",
            removed = removed_count,
            space_freed = freed_space,
            "按数量LRU清理完成"
        );

        Ok(removed_count)
    }

    /// 从磁盘加载缓存
    fn load_from_disk(&self, key: &str) -> Option<String> {
        let disk_path = self.get_disk_path(key);

        match fs::read_to_string(&disk_path) {
            Ok(content) => {
                debug!(
                    target: "seep::subscription::cache",
                    key = %key,
                    path = %disk_path.display(),
                    "从磁盘加载缓存"
                );

                // 重新加载到内存缓存
                let entry = CacheEntry::new(content.clone(), Some(self.config.default_ttl));
                if !entry.is_expired() {
                    let mut cache = self.memory_cache.write().expect("cache lock poisoned");
                    cache.insert(key.to_string(), entry);
                    return Some(content);
                } else {
                    // 磁盘文件也已过期，删除它
                    if let Err(err) = fs::remove_file(&disk_path) {
                        warn!(
                            target: "seep::subscription::cache",
                            path = %disk_path.display(),
                            error = %err,
                            "删除过期磁盘缓存文件失败"
                        );
                    }
                }
            }
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                warn!(
                    target: "seep::subscription::cache",
                    key = %key,
                    path = %disk_path.display(),
                    error = %err,
                    "从磁盘读取缓存失败"
                );
            }
            _ => {}
        }

        None
    }

    /// 保存到磁盘
    fn save_to_disk(&self, key: &str, content: &str) -> Result<()> {
        let disk_path = self.get_disk_path(key);

        // 创建临时文件
        let temp_path = disk_path.with_extension("tmp");
        fs::write(&temp_path, content)
            .with_context(|| format!("无法写入临时缓存文件: {}", temp_path.display()))?;

        // 原子性重命名
        fs::rename(&temp_path, &disk_path)
            .with_context(|| format!("无法重命名缓存文件: {}", disk_path.display()))?;

        Ok(())
    }

    /// 获取磁盘缓存路径
    fn get_disk_path(&self, key: &str) -> PathBuf {
        // 使用文件名安全的哈希
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        self.cache_dir.join(format!("{:016x}.cache", hash))
    }
}

/// 缓存统计信息
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// 总条目数
    pub total_entries: usize,
    /// 过期条目数
    pub expired_entries: usize,
    /// 当前大小（字节）
    pub current_size_bytes: u64,
    /// 最大条目数
    pub max_entries: usize,
    /// 最大大小（字节）
    pub max_size_bytes: u64,
    /// 总访问次数
    pub total_accesses: u64,
    /// 平均年龄（秒）
    pub avg_age_seconds: u64,
}

impl CacheStats {
    /// 获取缓存命中率（简化计算）
    pub fn hit_rate(&self) -> f64 {
        if self.total_accesses == 0 {
            0.0
        } else {
            // 这里简化计算，实际应该记录命中次数
            (self.total_entries as f64 / self.max_entries as f64) * 100.0
        }
    }

    /// 获取空间使用率
    pub fn space_usage_rate(&self) -> f64 {
        if self.max_size_bytes == 0 {
            0.0
        } else {
            (self.current_size_bytes as f64 / self.max_size_bytes as f64) * 100.0
        }
    }

    /// 获取条目使用率
    pub fn entry_usage_rate(&self) -> f64 {
        if self.max_entries == 0 {
            0.0
        } else {
            (self.total_entries as f64 / self.max_entries as f64) * 100.0
        }
    }
}

impl Default for SubscriptionCache {
    fn default() -> Self {
        Self::new()
    }
}
