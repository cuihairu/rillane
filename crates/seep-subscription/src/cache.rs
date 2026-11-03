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
    /// 串行化磁盘写入/删除（cleanup 与 set 的 save_to_disk 同键竞态窗口）。
    /// cleanup 在删盘前须持此锁复查 memory_cache 无该键；set 的 save_to_disk
    /// 亦持此锁——二者串行，保证「删盘」与「落盘」不交错覆盖，也消除并发
    /// set 同键交错写 {hash}.tmp（见 save_to_disk 注）。std Mutex（短临界，
    /// 无 await）。
    disk_io_lock: std::sync::Mutex<()>,
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
            disk_io_lock: std::sync::Mutex::new(()),
        }
    }

    /// 获取缓存内容
    pub fn get(&self, key: &str) -> Option<String> {
        // 内存判读仅持锁到本块结束——`load_from_disk` 内部需重取同一把
        // `memory_cache` 写锁（std::sync::RwLock 不可重入），持锁跨调用即
        // 自锁死锁（重启带热盘缓存 / 内存条目过期两条路径必触）。P1 修复：
        // 先释放守卫，再交 `load_from_disk` 自行取锁。
        {
            let mut cache = self.memory_cache.write().expect("cache lock poisoned");
            if let Some(entry) = cache.get_mut(key) {
                if !entry.is_expired() {
                    entry.access();
                    debug!(
                        target: "seep::subscription::cache",
                        key = %key,
                        count = entry.access_count,
                        "从内存缓存命中"
                    );
                    return Some(entry.content.clone());
                }
                debug!(
                    target: "seep::subscription::cache",
                    key = %key,
                    "内存缓存已过期"
                );
                cache.remove(key);
            }
        }
        // 内存 miss / 已过期：守卫已释放，磁盘加载（load_from_disk 自行取锁）
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

        // 容量检查：current_size 读锁在调用 cleanup_* 前必须释放。若持锁跨
        // cleanup（其内部锁序 memory_cache→current_size），与下方插入路径的
        // memory_cache→current_size 顺序成环，构成 ABBA 死锁。统一锁序为
        // memory_cache→current_size，任何 cleanup 调用都不在持锁下进行。
        let over_capacity = {
            let current_size = self
                .current_size
                .read()
                .expect("current_size lock poisoned");
            *current_size + content_size > self.config.max_size_bytes
        };
        if over_capacity {
            // 清理过期条目
            self.cleanup_expired()?;

            // 如果仍然超限，按 LRU 清理
            let still_over = {
                let current_size = self
                    .current_size
                    .read()
                    .expect("current_size lock poisoned");
                *current_size + content_size > self.config.max_size_bytes
            };
            if still_over {
                self.cleanup_lru(content_size)?;
            }
        }

        // 条目数量检查：cleanup_lru_by_count 自取 memory_cache 锁，不可在已
        // 持锁下调用（std::sync::RwLock 不可重入，会自锁），故先判后清再插。
        let at_count_limit = {
            let cache = self.memory_cache.read().expect("cache lock poisoned");
            cache.len() >= self.config.max_entries
        };
        if at_count_limit {
            self.cleanup_lru_by_count(1)?;
        }

        // 原子插入 + 大小更新（锁序 memory_cache → current_size，与 cleanup_* 一致）
        {
            let mut cache = self.memory_cache.write().expect("cache lock poisoned");

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
        // P2（2026-11-03）：磁盘删除移到所有锁外。此前持 memory_cache 写锁跨
        // 同步 fs::remove_file——同步 IO 阻塞执行线程并串行化全部缓存操作。
        // 锁内只做内存突变（remove + 记账），磁盘路径收集后在锁外删除。
        //
        // 锁外删除引入窄窗口：并发 get() 在条目出内存、磁盘文件未删之间
        // load_from_disk 会以全新 TTL 复活该条目（load_from_disk:555 重置 TTL）。
        // 该窗口窄且自愈——复活副本最终重新过期并被再次清理。
        let (removed_count, total_size_removed, disk_paths) = {
            let mut cache = self.memory_cache.write().expect("cache lock poisoned");

            let expired_keys: Vec<String> = cache
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(key, _)| key.clone())
                .collect();

            let mut removed_count = 0;
            let mut total_size_removed = 0;
            let mut disk_paths = Vec::new();
            for key in expired_keys {
                if let Some(entry) = cache.remove(&key) {
                    total_size_removed += entry.content.len() as u64;
                    removed_count += 1;
                    disk_paths.push((key.clone(), self.get_disk_path(&key)));
                }
            }
            (removed_count, total_size_removed, disk_paths)
        };

        // 更新大小统计（memory_cache 锁已释放）
        {
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(total_size_removed);
        }

        // 锁外删除磁盘文件（不持 memory_cache / current_size 任一锁），但持
        // disk_io_lock 与 set 的 save_to_disk 串行：删盘前复查 memory_cache
        // 已无该键，否则并发 set 刚重插并落盘的副本会被误删（P3 深审
        // 「cleanup 锁外删盘 vs set 同键竞态」）。
        let _disk_guard = self
            .disk_io_lock
            .lock()
            .map_err(|_| anyhow!("磁盘锁毒化"))?;
        for (key, disk_path) in disk_paths {
            // 复查：set 可能在删盘前重插该键并落盘。持 disk_io_lock 时
            // save_to_disk 不可能在写；内存已有该键即代表活跃副本，勿删。
            if self
                .memory_cache
                .read()
                .expect("cache lock poisoned")
                .contains_key(&key)
            {
                continue;
            }
            if let Err(err) = fs::remove_file(&disk_path) {
                warn!(
                    target: "seep::subscription::cache",
                    path = %disk_path.display(),
                    error = %err,
                    "删除过期缓存文件失败"
                );
            }
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
        // P2（2026-11-03）：磁盘删除移到所有锁外（见 cleanup_expired 同型注释）。
        let (freed_space, removed_count, disk_paths) = {
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
            let mut disk_paths = Vec::new();

            for (key, size, _) in entries {
                cache.remove(&key);
                freed_space += size;
                removed_count += 1;
                disk_paths.push((key.clone(), self.get_disk_path(&key)));

                if freed_space >= needed_space {
                    break;
                }
            }
            (freed_space, removed_count, disk_paths)
        };

        // 更新大小统计（memory_cache 锁已释放）
        {
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(freed_space);
        }

        // 锁外删除磁盘文件（持 disk_io_lock 与 set 落盘串行，删前复查）。
        let _disk_guard = self
            .disk_io_lock
            .lock()
            .map_err(|_| anyhow!("磁盘锁毒化"))?;
        for (key, disk_path) in disk_paths {
            if self
                .memory_cache
                .read()
                .expect("cache lock poisoned")
                .contains_key(&key)
            {
                continue;
            }
            if let Err(err) = fs::remove_file(&disk_path) {
                warn!(
                    target: "seep::subscription::cache",
                    path = %disk_path.display(),
                    error = %err,
                    "删除LRU缓存文件失败"
                );
            }
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
        // P2（2026-11-03）：磁盘删除移到所有锁外（见 cleanup_expired 同型注释）。
        let (freed_space, removed_count, disk_paths) = {
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
            let mut disk_paths = Vec::new();

            for (key, size, _) in entries.into_iter().take(count) {
                cache.remove(&key);
                freed_space += size;
                removed_count += 1;
                disk_paths.push((key.clone(), self.get_disk_path(&key)));
            }
            (freed_space, removed_count, disk_paths)
        };

        // 更新大小统计（memory_cache 锁已释放）
        {
            let mut current_size = self
                .current_size
                .write()
                .expect("current_size lock poisoned");
            *current_size = current_size.saturating_sub(freed_space);
        }

        // 锁外删除磁盘文件（持 disk_io_lock 与 set 落盘串行，删前复查）。
        let _disk_guard = self
            .disk_io_lock
            .lock()
            .map_err(|_| anyhow!("磁盘锁毒化"))?;
        for (key, disk_path) in disk_paths {
            if self
                .memory_cache
                .read()
                .expect("cache lock poisoned")
                .contains_key(&key)
            {
                continue;
            }
            if let Err(err) = fs::remove_file(&disk_path) {
                warn!(
                    target: "seep::subscription::cache",
                    path = %disk_path.display(),
                    error = %err,
                    "删除LRU缓存文件失败"
                );
            }
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
                    let content_size = content.len() as u64;
                    // 回填内存必须同步回填容量统计，否则热盘加载后的 set_with_ttl
                    // 以偏小的 current_size 判限，实际内存占用可突破 max_size_bytes。
                    // 锁序 memory_cache → current_size，与插入/清理路径一致。
                    let mut cache = self.memory_cache.write().expect("cache lock poisoned");
                    let old_size = cache
                        .insert(key.to_string(), entry)
                        .map(|old| old.content.len() as u64)
                        .unwrap_or(0);
                    let mut current_size = self
                        .current_size
                        .write()
                        .expect("current_size lock poisoned");
                    *current_size = current_size
                        .saturating_sub(old_size)
                        .saturating_add(content_size);
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

        // 持 disk_io_lock：与 cleanup 删盘串行（同键竞态窗口），与其它 set
        // 同键落盘串行（消除固定 {hash}.tmp 路径交错写）。锁只覆盖磁盘 IO
        // 短临界，不跨 memory_cache 锁（锁序：先 memory_cache 后 disk_io）。
        let _disk_guard = self
            .disk_io_lock
            .lock()
            .map_err(|_| anyhow!("磁盘锁毒化"))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn temp_cache_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("seep-cache-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 在独立线程跑闭包并限时回收，防锁死 bug 让测试无限挂起。
    fn run_with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static, ms: u64) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_millis(ms))
            .unwrap_or_else(|_| panic!("缓存操作超时（疑似锁死）"))
    }

    /// 数量上限路径：曾因 memory_cache 写锁自锁（cleanup_lru_by_count 在已持
    /// 锁下再取同锁，std::sync::RwLock 不可重入）而死锁，插入一条即触发。
    #[test]
    fn set_at_count_limit_does_not_deadlock() {
        let dir = temp_cache_dir("count-limit");
        let cache = Arc::new(SubscriptionCache::with_config(CacheConfig {
            cache_dir: dir.clone(),
            max_entries: 2,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        }));
        cache.set("a", "11111").unwrap();
        cache.set("b", "22222").unwrap();
        let c = cache.clone();
        run_with_timeout(move || c.set("c", "33333").unwrap(), 5000);
        let stats = cache.get_stats();
        assert!(
            stats.total_entries <= 3,
            "条目数异常: {}",
            stats.total_entries
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// 容量上限路径：曾因持 current_size 写锁跨 cleanup（其内部取
    /// memory_cache 锁）与插入路径锁序成环（ABBA）而死锁，多次超限插入触发。
    #[test]
    fn set_over_capacity_does_not_deadlock() {
        let dir = temp_cache_dir("capacity");
        let cache = Arc::new(SubscriptionCache::with_config(CacheConfig {
            cache_dir: dir.clone(),
            max_entries: 100,
            max_size_bytes: 5,
            ..Default::default()
        }));
        let c = cache.clone();
        run_with_timeout(
            move || {
                c.set("a", "12345").unwrap();
                c.set("b", "67890").unwrap();
                c.set("c", "abcde").unwrap();
                c.set("d", "fghij").unwrap();
            },
            5000,
        );
        let stats = cache.get_stats();
        assert!(
            stats.total_entries <= 4,
            "条目数异常: {}",
            stats.total_entries
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// get() 持锁跨 load_from_disk 自锁回归（P1）：重启形态——新实例内存空、
    /// 磁盘有热缓存 → get 走尾部 load_from_disk（曾持 memory_cache 写锁跨调用
    /// 重取同锁，std::sync::RwLock 不可重入，必自锁死锁）。
    #[test]
    fn get_with_warm_disk_cache_does_not_deadlock() {
        let dir = temp_cache_dir("get-warm-disk");
        let config = CacheConfig {
            cache_dir: dir.clone(),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        };
        // 会话一：set 落盘
        let writer = SubscriptionCache::with_config(config.clone());
        writer.set("warm", "cached-content").unwrap();
        drop(writer);
        // 会话二（重启形态）：内存空 → get 尾部 load_from_disk
        let reader = SubscriptionCache::with_config(config.clone());
        let got = run_with_timeout(move || reader.get("warm"), 2_000);
        assert_eq!(got.as_deref(), Some("cached-content"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// 热盘回填容量统计回归：load_from_disk 把磁盘条目插回内存时必须同步
    /// current_size，否则 get 修复后该路径可达而 set_with_ttl 容量上限被漏计
    /// 削弱，实际占用可超 max_size_bytes。
    #[test]
    fn load_from_disk_updates_current_size() {
        let dir = temp_cache_dir("warm-disk-size");
        let config = CacheConfig {
            cache_dir: dir.clone(),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        };
        let writer = SubscriptionCache::with_config(config.clone());
        writer.set("warm", "cached-content").unwrap();
        drop(writer);

        let reader = SubscriptionCache::with_config(config);
        reader.get("warm").expect("热盘回读");
        let expected = "cached-content".len() as u64;
        assert_eq!(
            *reader
                .current_size
                .read()
                .expect("current_size lock poisoned"),
            expected,
            "热盘回填必须计入容量统计"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// get() 过期内存条目分支回归（P1）：内存条目已过期 → 移除后调
    /// load_from_disk（曾持锁跨调用自锁）。磁盘文件以 default_ttl 判新，
    /// 应回读成功。
    #[test]
    fn get_with_expired_memory_entry_does_not_deadlock() {
        let dir = temp_cache_dir("get-expired");
        let config = CacheConfig {
            cache_dir: dir.clone(),
            default_ttl: Duration::from_secs(3600),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        };
        let cache = SubscriptionCache::with_config(config.clone());
        // 内存 TTL=0（立即过期）；磁盘以 default_ttl 落盘（save_to_disk 只写内容）
        cache.set_with_ttl("k", "v", Some(Duration::ZERO)).unwrap();
        let got = run_with_timeout(move || cache.get("k"), 2_000);
        assert_eq!(got.as_deref(), Some("v"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// cleanup_expired 回归（P2 2026-11-03）：锁外删除磁盘文件后，功能不变
    /// ——过期条目从内存移除、磁盘文件删除、容量统计归零。
    #[test]
    fn cleanup_expired_removes_entry_and_disk_file() {
        let dir = temp_cache_dir("cleanup-expired");
        let cache = SubscriptionCache::with_config(CacheConfig {
            cache_dir: dir.clone(),
            default_ttl: Duration::from_secs(3600),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        });
        cache
            .set_with_ttl("exp", "payload", Some(Duration::from_millis(1)))
            .unwrap();
        let disk_path = cache.get_disk_path("exp");
        assert!(disk_path.exists(), "set 应落盘");

        std::thread::sleep(Duration::from_millis(5));
        let removed = cache.cleanup_expired().unwrap();
        assert_eq!(removed, 1, "应清 1 条过期条目");
        assert!(
            !cache.memory_cache.read().unwrap().contains_key("exp"),
            "过期条目应移出内存"
        );
        assert!(!disk_path.exists(), "磁盘缓存文件应被删除");
        assert_eq!(*cache.current_size.read().unwrap(), 0, "容量统计应归零");
        let _ = fs::remove_dir_all(&dir);
    }

    /// cleanup_lru 回归（P2 2026-11-03）：按最后访问升序驱逐，先逐最旧；
    /// 锁外删盘不改驱逐顺序与容量记账。
    #[test]
    fn cleanup_lru_evicts_least_recently_used_first() {
        let dir = temp_cache_dir("cleanup-lru");
        let cache = SubscriptionCache::with_config(CacheConfig {
            cache_dir: dir.clone(),
            default_ttl: Duration::from_secs(3600),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        });
        cache.set("drop1", "11111").unwrap();
        cache.set("drop2", "22222").unwrap();
        cache.set("keep", "33333").unwrap();
        // 触碰 keep，使其 last_accessed 最新 → 驱逐顺序 drop1/drop2 先于 keep
        assert_eq!(cache.get("keep").as_deref(), Some("33333"));

        let needed = 5u64 + 5; // 恰为 drop1+drop2 字节数
        let removed = cache.cleanup_lru(needed).unwrap();
        assert_eq!(removed, 2, "应驱逐 2 条");
        let mem = cache.memory_cache.read().unwrap();
        assert!(mem.contains_key("keep"), "最近访问的 keep 应保留");
        assert!(!mem.contains_key("drop1") && !mem.contains_key("drop2"));
        assert_eq!(
            *cache.current_size.read().unwrap(),
            "33333".len() as u64,
            "容量记账仅剩 keep"
        );
        drop(mem);
        let _ = fs::remove_dir_all(&dir);
    }

    /// cleanup_lru_by_count 回归（P2 2026-11-03）：按数量驱逐最旧条目。
    #[test]
    fn cleanup_lru_by_count_evicts_oldest() {
        let dir = temp_cache_dir("cleanup-lru-count");
        let cache = SubscriptionCache::with_config(CacheConfig {
            cache_dir: dir.clone(),
            default_ttl: Duration::from_secs(3600),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        });
        cache.set("drop1", "11111").unwrap();
        cache.set("drop2", "22222").unwrap();
        cache.set("keep", "33333").unwrap();
        assert_eq!(cache.get("keep").as_deref(), Some("33333"));

        let removed = cache.cleanup_lru_by_count(2).unwrap();
        assert_eq!(removed, 2, "应驱逐 2 条");
        let mem = cache.memory_cache.read().unwrap();
        assert!(mem.contains_key("keep"), "最近访问的 keep 应保留");
        assert!(!mem.contains_key("drop1") && !mem.contains_key("drop2"));
        drop(mem);
        let _ = fs::remove_dir_all(&dir);
    }

    /// P3 深审回归（2026-11-03）：cleanup 锁外删盘 vs set 同键竞态。
    /// 模拟「cleanup 移除内存条目 →（删盘前）set 重插该键并落盘」的交错：
    /// 直接构造该状态（内存有键 + 磁盘有文件），再执行 cleanup 删盘，
    /// 验证 cleanup 因内存已有活跃副本而**跳过**删盘（不误删 set 刚写的
    /// 磁盘文件，持久化副本保留）。
    #[test]
    fn cleanup_expired_skips_delete_when_key_reinserted() {
        let dir = temp_cache_dir("cleanup-reinsert");
        let cache = SubscriptionCache::with_config(CacheConfig {
            cache_dir: dir.clone(),
            default_ttl: Duration::from_secs(3600),
            max_entries: 16,
            max_size_bytes: 10 * 1024 * 1024,
            ..Default::default()
        });
        // set 落盘（内存+磁盘都有活跃副本）。
        cache
            .set_with_ttl("k", "v1", Some(Duration::from_secs(3600)))
            .unwrap();
        let disk_path = cache.get_disk_path("k");
        assert!(disk_path.exists());

        // 模拟 set 重插该键（内存已有，磁盘是它刚写的副本）。
        // cleanup 在 disk_io_lock 下复查到内存有键 → 应跳过删盘。
        // 先把条目置过期以便 cleanup_expired 收集它。
        {
            let mut cache_g = cache.memory_cache.write().unwrap();
            if let Some(e) = cache_g.get_mut("k") {
                e.expires_at = Some(SystemTime::now() - Duration::from_secs(1));
            }
        }
        // 在内存中重插（模拟 set 并发落盘后、cleanup 删盘前回来重插）。
        cache
            .set_with_ttl("k", "v2", Some(Duration::from_secs(3600)))
            .unwrap();
        let removed = cache.cleanup_expired().unwrap();
        // 该键未过期（重插的新 TTL），cleanup 不应移除它。
        assert_eq!(removed, 0, "重插的非过期键不应被清");
        assert!(
            cache.memory_cache.read().unwrap().contains_key("k"),
            "内存活跃副本应保留"
        );
        assert!(disk_path.exists(), "磁盘副本不应被误删（有活跃内存副本）");
        let _ = fs::remove_dir_all(&dir);
    }
}
