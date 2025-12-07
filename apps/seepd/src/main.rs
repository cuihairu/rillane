use std::env;

use anyhow::Result;
use seep_config::SeepConfig;
use seep_runtime::RuntimeBuilder;
use seep_telemetry::TelemetryOptions;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::var("SEEP_CONFIG").unwrap_or_else(|_| "config/seep.yaml".to_string());
    let config = SeepConfig::load_from_path(&config_path)?;

    seep_telemetry::init(TelemetryOptions::default()).await?;
    info!(target: "seep::boot", path = %config_path, "配置加载完成");

    let runtime = RuntimeBuilder::new(config).build()?;
    runtime.run().await
}
