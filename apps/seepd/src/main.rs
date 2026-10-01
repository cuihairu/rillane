use std::{env, net::SocketAddr, sync::Arc};

use anyhow::Result;
use seep_config::SeepConfig;
use seep_runtime::{RuntimeBuilder, RuntimeConfig};
use seep_telemetry::TelemetryOptions;
use tracing::info;

mod control_plane;

/// 早期退出参数面（无 clap 依赖的最小实现）：`--version`/`-V` → 版本行。
/// 容器 HEALTHCHECK 与 CI docker job 冒烟（`docker run seep:test --version`）依赖此路径。
fn version_flag_response(args: &[String]) -> Option<String> {
    match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") => Some(format!("seepd {}", env!("CARGO_PKG_VERSION"))),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // --version/-V 在配置加载前短路（daemon 不应因版本查询而读配置/起服务）
    if let Some(line) = version_flag_response(&env::args().collect::<Vec<_>>()) {
        println!("{line}");
        return Ok(());
    }

    let config_path = env::var("SEEP_CONFIG").unwrap_or_else(|_| "config/seep.yaml".to_string());
    let config = SeepConfig::load_from_path(&config_path)?;

    if config.telemetry.enable_tracing {
        let capture_logs = env::var("SEEP_CAPTURE_LOGS")
            .ok()
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        seep_telemetry::init(TelemetryOptions {
            level: config.telemetry.log_level.clone(),
            enable_json: false,
            capture_logs,
            capture_max_lines: 2000,
        })
        .await?;
    }
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
    let cp = control_plane::ControlPlane::new(
        runtime.clone(),
        config.control.admin_token.clone(),
        config.telemetry.enable_metrics,
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// --version/-V 输出版本行；无参/其他参数/第三位参数均走正常启动
    #[test]
    fn version_flag_short_circuits() {
        let line = version_flag_response(&args(&["seepd", "--version"])).unwrap();
        assert_eq!(line, format!("seepd {}", env!("CARGO_PKG_VERSION")));

        assert!(version_flag_response(&args(&["seepd", "-V"])).is_some());

        assert!(version_flag_response(&args(&["seepd"])).is_none());
        assert!(version_flag_response(&args(&["seepd", "run"])).is_none());
        // 仅识别首位参数：`seepd start --version` 不短路（位置语义留给未来 CLI 扩展）
        assert!(version_flag_response(&args(&["seepd", "start", "--version"])).is_none());
    }
}
