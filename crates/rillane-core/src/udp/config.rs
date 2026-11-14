//! 会话表参数（udp-session-table-api.md §2.1；默认值对齐 udp-session-table.md §4.1）。

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct UdpSessionConfig {
    /// 目标映射空闲上限（双向任一方向刷新）
    pub mapping_idle: Duration,
    /// 会话空闲上限
    pub session_idle: Duration,
    /// 回收扫描周期
    pub sweep_interval: Duration,
    /// 全局并发会话上界（满员拒新不逐旧）
    pub max_sessions: usize,
    /// 会话内映射上界（溢出逐最久空闲）
    pub max_mappings: usize,
    /// 可选会话寿命上界（默认禁用，长局游戏不断流）
    pub session_max_lifetime: Option<Duration>,
    /// 下行通道容量（满即丢 + 计数，UDP 无背压）
    pub downlink_capacity: usize,
}

impl Default for UdpSessionConfig {
    fn default() -> Self {
        Self {
            mapping_idle: Duration::from_secs(60),
            session_idle: Duration::from_secs(180),
            sweep_interval: Duration::from_secs(15),
            max_sessions: 4096,
            max_mappings: 256,
            session_max_lifetime: None,
            downlink_capacity: 64,
        }
    }
}

impl UdpSessionConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.mapping_idle.as_secs() >= 1, "mapping_idle 必须 ≥ 1s");
        anyhow::ensure!(self.session_idle.as_secs() >= 1, "session_idle 必须 ≥ 1s");
        anyhow::ensure!(
            self.sweep_interval.as_millis() >= 1,
            "sweep_interval 必须 ≥ 1ms"
        );
        anyhow::ensure!(self.max_sessions >= 1, "max_sessions 必须 ≥ 1");
        anyhow::ensure!(self.max_mappings >= 1, "max_mappings 必须 ≥ 1");
        anyhow::ensure!(self.downlink_capacity >= 1, "downlink_capacity 必须 ≥ 1");
        if let Some(life) = self.session_max_lifetime {
            anyhow::ensure!(
                life >= self.session_idle,
                "session_max_lifetime 不应小于 session_idle"
            );
        }
        Ok(())
    }
}
