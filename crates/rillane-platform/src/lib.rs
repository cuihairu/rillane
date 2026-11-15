use anyhow::{Context, Result};
use async_trait::async_trait;
use rillane_config::RillaneConfig;
use tokio::task::JoinHandle;
use tracing::info;

// Re-export network module
pub mod network;

/// 真实探测执行器（RIL-061）：ProbeExecutor 的本机 I/O 装配面
pub mod probe_exec;

#[derive(Debug, Clone, Copy)]
pub enum PlatformKind {
    Linux,
    Windows,
    Macos,
    Android,
    Ios,
    Openwrt,
}

#[derive(Debug, Clone)]
pub struct PlatformProfile {
    pub kind: PlatformKind,
    pub arch: String,
}

#[async_trait]
pub trait ServiceInstaller: Send + Sync {
    async fn install(&self, config: &RillaneConfig) -> Result<()>;
    async fn uninstall(&self) -> Result<()>;
}

#[async_trait]
pub trait ServiceRuntime: Send + Sync {
    async fn start(&self) -> Result<JoinHandle<Result<()>>>;
    async fn stop(&self) -> Result<()>;
}

pub struct PlatformManager<I: ServiceInstaller, R: ServiceRuntime> {
    installer: I,
    runtime: R,
}

impl<I: ServiceInstaller, R: ServiceRuntime> PlatformManager<I, R> {
    pub fn new(installer: I, runtime: R) -> Self {
        Self { installer, runtime }
    }

    pub async fn install(&self, config: &RillaneConfig) -> Result<()> {
        info!(target: "rillane::platform", "installing service");
        self.installer
            .install(config)
            .await
            .context("platform install failed")
    }

    pub async fn uninstall(&self) -> Result<()> {
        info!(target: "rillane::platform", "removing service");
        self.installer.uninstall().await
    }

    pub async fn launch(&self) -> Result<JoinHandle<Result<()>>> {
        self.runtime
            .start()
            .await
            .context("failed to start platform runtime")
    }

    pub async fn stop(&self) -> Result<()> {
        self.runtime.stop().await
    }
}
