use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use rillane_config::{ProbeTargetSpec, RillaneConfig};
use rillane_core::{ProbeLimits, ProbeService, TargetScope};
use rillane_platform::probe_exec::LocalProbeExecutor;
use rillane_runtime::{RuntimeBuilder, RuntimeConfig};
use rillane_telemetry::TelemetryOptions;
use tracing::info;

mod config_tx;
mod control_plane;

/// 早期退出参数面（无 clap 依赖的最小实现）：`--version`/`-V` → 版本行。
/// 容器 HEALTHCHECK 与 CI docker job 冒烟（`docker run rillane:test --version`）依赖此路径。
fn version_flag_response(args: &[String]) -> Option<String> {
    match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") => Some(format!("rillaned {}", env!("CARGO_PKG_VERSION"))),
        _ => None,
    }
}

/// R1 派生（tun-dataplane.md §2.6 / network-route.md §1.2）：network 块在场
/// 即启用网络虚拟化——Tun 模式由 runtime_builder 裁决装配 TunIngress（属主化
/// 设备+系统路由，NetworkManager 让位）；None = 无 network 块，行为与既有
/// 版本零差异。mesh/chain 沿既有默认（控制面相关能力全开）。
fn derive_runtime_config(config: &RillaneConfig) -> Result<RuntimeConfig> {
    Ok(RuntimeConfig {
        enable_mesh: true,
        enable_chain: true,
        enable_network_virtualization: config.network.is_some(),
        network_config: config
            .network
            .as_ref()
            .map(rillane_runtime::network_block_to_platform)
            .transpose()?,
        ..RuntimeConfig::default()
    })
}

/// RIL-061：探测作业服务装配（probe 块缺席 = None = 探测面整体关闭，
/// 端点 503——无授权无网络副作用）。目标登记表只来自操作员本地配置：
/// 来源合并面是对象登记（SourceSnapshot.objects），顶层 probe 块结构上
/// 进不了这里——不可信订阅文本无法扩探测范围（debug-and-mcp.md §3）。
/// 代理握手目标不在配置面（本版执行器无握手测量，见 probe_exec.rs）。
fn build_probe_service(config: &RillaneConfig) -> Result<Option<Arc<ProbeService>>> {
    let Some(block) = config.probe.as_ref() else {
        return Ok(None);
    };
    // 装配侧兜底校验（load 入口已校验——程序化构造路径同门把关）
    block.validate()?;
    let mut scope = TargetScope::empty();
    for target in &block.targets {
        match target {
            ProbeTargetSpec::Dns { host } => {
                scope.allow_host(host.trim().to_string());
            }
            ProbeTargetSpec::Connect { addr } | ProbeTargetSpec::UdpEcho { addr } => {
                let addr: SocketAddr = addr
                    .parse()
                    .map_err(|e| anyhow::anyhow!("probe 目标 addr 非法（{addr}）: {e}"))?;
                scope.allow_addr(addr);
            }
        }
    }
    let mut limits = ProbeLimits::default();
    if let Some(v) = block.limits.max_active {
        limits.max_active = v;
    }
    if let Some(v) = block.limits.job_timeout_ms {
        limits.job_timeout_ms = v;
    }
    if let Some(v) = block.limits.udp_payload_max_bytes {
        limits.udp_payload_max_bytes = v;
    }
    if let Some(v) = block.limits.byte_budget {
        limits.byte_budget = v;
    }
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    });
    let service = ProbeService::new(scope, limits, Arc::new(LocalProbeExecutor::new()), clock);
    Ok(Some(Arc::new(service)))
}

/// SIGTERM 监听（unix；其余平台永不就绪——退出语义仍由 Ctrl-C 承担）。
/// systemd stop / kill 默认信号都走这里，触发与 Ctrl-C 相同的优雅
/// 退出路径（runtime.stop 回滚路由/停 DNS）。
#[cfg(unix)]
async fn wait_sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            term.recv().await;
        }
        Err(e) => {
            // 信号面装不上：记日志继续（不能因监听失败拒绝启动）
            tracing::warn!(target: "rillane::boot", error = %e, "SIGTERM 监听不可用");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_sigterm() {
    std::future::pending::<()>().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    // --version/-V 在配置加载前短路（daemon 不应因版本查询而读配置/起服务）
    if let Some(line) = version_flag_response(&env::args().collect::<Vec<_>>()) {
        println!("{line}");
        return Ok(());
    }

    let config_path =
        env::var("RILLANE_CONFIG").unwrap_or_else(|_| "config/rillane.yaml".to_string());
    let config = RillaneConfig::load_from_path(&config_path)?;

    if config.telemetry.enable_tracing {
        let capture_logs = env::var("RILLANE_CAPTURE_LOGS")
            .ok()
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        rillane_telemetry::init(TelemetryOptions {
            level: config.telemetry.log_level.clone(),
            enable_json: false,
            capture_logs,
            capture_max_lines: 2000,
        })
        .await?;
    }
    info!(target: "rillane::boot", path = %config_path, "配置加载完成");

    // For rillaned, enable control-plane-relevant capabilities by default.
    // These can be made configurable later via a dedicated runtime section in RillaneConfig.
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
    let probe_service = build_probe_service(&config)?;
    let cp = control_plane::ControlPlane::new(
        runtime.clone(),
        config.control.admin_token.clone(),
        config.telemetry.enable_metrics,
    )
    .with_probe_service(probe_service)
    .with_config_service(Some(Arc::new(config_tx::ConfigTxService::new(
        config.clone(),
        rillane_config::CapabilitySet::full(),
    ))));
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
            info!(target: "rillane::boot", "收到 Ctrl-C，开始退出");
        }
        // RIL-031：systemd stop 发 SIGTERM——不接的话默认处理器直接杀
        // 进程，runtime.stop 的 TUN teardown（路由回滚/DNS 停服）根本
        // 不跑，系统侧残留只能靠下次启动的崩溃恢复面收拾。
        _ = wait_sigterm() => {
            info!(target: "rillane::boot", "收到 SIGTERM，开始优雅退出");
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
        let line = version_flag_response(&args(&["rillaned", "--version"])).unwrap();
        assert_eq!(line, format!("rillaned {}", env!("CARGO_PKG_VERSION")));

        assert!(version_flag_response(&args(&["rillaned", "-V"])).is_some());

        assert!(version_flag_response(&args(&["rillaned"])).is_none());
        assert!(version_flag_response(&args(&["rillaned", "run"])).is_none());
        // 仅识别首位参数：`rillaned start --version` 不短路（位置语义留给未来 CLI 扩展）
        assert!(version_flag_response(&args(&["rillaned", "start", "--version"])).is_none());
    }

    /// R1 派生（tun-dataplane.md §2.6）：network 块在场 → 虚拟化开 + platform
    /// 配置转换（Tun 模式直通）；缺块 → 双 None/false（既有行为零差异）。
    /// 转换正确性本体归 network_config.rs 测试（rillaned 侧只钉开关派生契约）。
    #[test]
    fn runtime_config_derives_network_block() {
        use rillane_config::{NetworkBlockConfig, NetworkBlockMode};
        use rillane_platform::network::NetworkMode;

        // 基线 = 仓库示例配置（无 network 块）：与历史默认零差异
        let cfg_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rillane.yaml");
        let mut cfg = RillaneConfig::load_from_path(&cfg_path).unwrap();
        assert!(cfg.network.is_none(), "示例配置不应带 network 块");
        let rc = derive_runtime_config(&cfg).unwrap();
        assert!(!rc.enable_network_virtualization);
        assert!(rc.network_config.is_none());
        assert!(rc.enable_mesh && rc.enable_chain, "mesh/chain 默认不变");

        // network 块（Tun 模式最小形——无 Default，显式全字段）→ 虚拟化开 + mode 直通
        cfg.network = Some(NetworkBlockConfig {
            sniff: None,
            mode: NetworkBlockMode::Tun,
            tun: None,
            routing: None,
            dns: None,
            egress_fwmark: None,
            transparent: None,
        });
        let rc = derive_runtime_config(&cfg).unwrap();
        assert!(rc.enable_network_virtualization);
        let nc = rc.network_config.expect("network 块应完成平台转换");
        assert!(matches!(nc.mode, NetworkMode::Tun));
    }

    /// RIL-061 装配契约：probe 块缺席 = None（探测面关闭，行为零差异）；
    /// 有块 = 服务装配成功且登记表逐条入范围（登记外目标提交必被拒）。
    /// submit 触发服务面 worker——需要 tokio 上下文。
    #[tokio::test]
    async fn probe_service_assembles_from_config_block() {
        use rillane_config::{ProbeConfigBlock, ProbeLimitsConfig, ProbeTargetSpec};

        // 基线 = 仓库示例配置（无 probe 块）→ 探测面整体关闭
        let cfg_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rillane.yaml");
        let mut cfg = RillaneConfig::load_from_path(&cfg_path).unwrap();
        assert!(cfg.probe.is_none());
        assert!(build_probe_service(&cfg).unwrap().is_none());

        // 有块：三类目标入范围（闭合登记）；limits 覆盖生效
        cfg.probe = Some(ProbeConfigBlock {
            targets: vec![
                ProbeTargetSpec::Dns {
                    host: "  example.invalid  ".into(),
                },
                ProbeTargetSpec::Connect {
                    addr: "127.0.0.1:9".into(),
                },
                ProbeTargetSpec::UdpEcho {
                    addr: "127.0.0.1:53".into(),
                },
            ],
            limits: ProbeLimitsConfig {
                max_active: Some(1),
                job_timeout_ms: None,
                udp_payload_max_bytes: None,
                byte_budget: None,
            },
        });
        let service = build_probe_service(&cfg).unwrap().expect("有块应装配");
        // 范围登记可见性：trim 过的 host / 解析过的 addr 逐条允许
        // （TargetScope 无遍历口——经 allows_* 正向核对登记生效）
        let probe_cfg = cfg.probe.as_ref().unwrap();
        assert_eq!(probe_cfg.targets.len(), 3);
        // 服务真实接受已登记目标（唯一入口 submit——范围外必拒）
        let id = service
            .submit(rillane_core::ProbeTarget::Dns {
                host: "example.invalid".into(),
            })
            .expect("登记过的 host 应可提交");
        let _ = service.cancel(id);
    }
}
