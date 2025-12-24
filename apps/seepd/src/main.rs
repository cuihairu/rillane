use std::{env, net::SocketAddr, sync::Arc};

use anyhow::Result;
use seep_config::SeepConfig;
use seep_runtime::{RuntimeBuilder, RuntimeConfig};
use seep_telemetry::TelemetryOptions;
use tracing::info;

mod control_plane;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::var("SEEP_CONFIG").unwrap_or_else(|_| "config/seep.yaml".to_string());
    let config = SeepConfig::load_from_path(&config_path)?;

    seep_telemetry::init(TelemetryOptions::default()).await?;
    info!(target: "seep::boot", path = %config_path, "配置加载完成");

    // For seepd, enable control-plane-relevant capabilities by default.
    // These can be made configurable later via a dedicated runtime section in SeepConfig.
    let runtime_config = RuntimeConfig {
        enable_mesh: true,
        enable_chain: true,
        ..RuntimeConfig::default()
    };

    let runtime = Arc::new(
        RuntimeBuilder::new(config.clone())
            .with_runtime_config(runtime_config)
            .build()?,
    );

    let bind: SocketAddr = config.control.api_bind.parse()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let cp = control_plane::ControlPlane::new(runtime.clone(), config.control.admin_token.clone());
    let cp_task = tokio::spawn(async move { cp.serve(bind, shutdown_rx).await });

    // Start runtime background tasks.
    let handles = runtime.start().await?;
    let rt_task = tokio::spawn(async move {
        for h in handles {
            match h.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(anyhow::anyhow!("runtime task panicked: {e}")),
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!(target: "seep::boot", "收到 Ctrl-C，开始退出");
        }
        res = cp_task => {
            // Control plane exited unexpectedly.
            if let Ok(Err(e)) = res {
                return Err(e);
            }
        }
        res = rt_task => {
            if let Ok(Err(e)) = res {
                return Err(e);
            }
        }
    }

    let _ = shutdown_tx.send(());
    runtime.stop().await.ok();
    Ok(())
}
