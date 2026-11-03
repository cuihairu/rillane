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

/// R1 派生（tun-dataplane.md §2.6 / network-route.md §1.2）：network 块在场
/// 即启用网络虚拟化——Tun 模式由 runtime_builder 裁决装配 TunIngress（属主化
/// 设备+系统路由，NetworkManager 让位）；None = 无 network 块，行为与既有
/// 版本零差异。mesh/chain 沿既有默认（控制面相关能力全开）。
fn derive_runtime_config(config: &SeepConfig) -> Result<RuntimeConfig> {
    Ok(RuntimeConfig {
        enable_mesh: true,
        enable_chain: true,
        enable_network_virtualization: config.network.is_some(),
        network_config: config
            .network
            .as_ref()
            .map(seep_runtime::network_block_to_platform)
            .transpose()?,
        ..RuntimeConfig::default()
    })
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
    let runtime_config = derive_runtime_config(&config)?;

    let runtime = Arc::new(
        RuntimeBuilder::new(config.clone())
            .with_runtime_config(runtime_config)
            .build()?,
    );

    let bind: SocketAddr = config.control.api_bind.parse()?;
    // P2 深审（2026-11-03）：非回环绑定 + 无 admin_token 时鉴权门整体跳过，
    // mutating 端点与敏感读全开放（control_plane.rs:135-137）。fail-closed：
    // 拒启（回环绑定保留无 token 能力，供本机开发/诊断）。
    if !bind.ip().is_loopback() && config.control.admin_token.is_none() {
        anyhow::bail!(
            "控制面绑定 {bind} 为非回环且未配置 admin_token——鉴权门被整体跳过，拒启；请设置 admin_token 或改用回环绑定"
        );
    }
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

    /// R1 派生（tun-dataplane.md §2.6）：network 块在场 → 虚拟化开 + platform
    /// 配置转换（Tun 模式直通）；缺块 → 双 None/false（既有行为零差异）。
    /// 转换正确性本体归 network_config.rs 测试（seepd 侧只钉开关派生契约）。
    #[test]
    fn runtime_config_derives_network_block() {
        use seep_config::{NetworkBlockConfig, NetworkBlockMode};
        use seep_platform::network::NetworkMode;

        // 基线 = 仓库示例配置（无 network 块）：与历史默认零差异
        let cfg_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/seep.yaml");
        let mut cfg = SeepConfig::load_from_path(&cfg_path).unwrap();
        assert!(cfg.network.is_none(), "示例配置不应带 network 块");
        let rc = derive_runtime_config(&cfg).unwrap();
        assert!(!rc.enable_network_virtualization);
        assert!(rc.network_config.is_none());
        assert!(rc.enable_mesh && rc.enable_chain, "mesh/chain 默认不变");

        // network 块（Tun 模式最小形——无 Default，显式全字段）→ 虚拟化开 + mode 直通
        cfg.network = Some(NetworkBlockConfig {
            mode: NetworkBlockMode::Tun,
            tun: None,
            routing: None,
            dns: None,
            egress_fwmark: None,
        });
        let rc = derive_runtime_config(&cfg).unwrap();
        assert!(rc.enable_network_virtualization);
        let nc = rc.network_config.expect("network 块应完成平台转换");
        assert!(matches!(nc.mode, NetworkMode::Tun));
    }
}
