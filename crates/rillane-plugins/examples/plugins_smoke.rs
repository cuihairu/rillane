//! P3-2 验收实况（plugin-loader.md §4.2）：载入 `plugins/output/` 两示例产物，
//! 演示限速（桶空后 deny）与内容过滤（禁词 deny / 干净载荷 allow+回放）。
//!
//! ```bash
//! plugins/build.sh && cargo run -p rillane-plugins --example plugins_smoke
//! ```
//!
//! 产物缺席时整例退出并提示构建路径（本例定位为人工验收载具，不入 CI 矩阵）。

use std::{path::PathBuf, time::SystemTime, time::UNIX_EPOCH};

use rillane_core::{Flow, FlowId, FlowMiddleware, FlowTarget, TargetProto};
use rillane_plugins::PluginLoadOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn output_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/output")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

async fn flow_with(payload: &[u8]) -> (Flow, tokio::io::DuplexStream) {
    let (mut test_side, io) = tokio::io::duplex(4096);
    if !payload.is_empty() {
        test_side.write_all(payload).await.unwrap();
    }
    (
        Flow {
            id: FlowId::default(),
            target: FlowTarget {
                host: "example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(io),
            metadata: Default::default(),
        },
        test_side,
    )
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let dir = output_dir();
    let rate_path = dir.join("rate_limit.wasm");
    let filter_path = dir.join("content_filter.wasm");
    for p in [&rate_path, &filter_path] {
        if !p.exists() {
            anyhow::bail!("缺产物 {:?}——先跑 plugins/build.sh", p);
        }
    }
    // 走具体类型载入（stats 观测面）；路径直载 trait 对象形见 load_plugin
    let load = |p: &PathBuf| -> anyhow::Result<_> {
        let bytes = std::fs::read(p)?;
        rillane_plugins::load_plugin_from_bytes(&bytes, PluginLoadOptions::default())
    };

    // ---- 限速：容量 3 → 第 4 流起 deny，note 可见（验收①半边）----
    let rate = load(&rate_path)?;
    println!("loaded: {rate:?}");
    for i in 1..=4 {
        let (flow, _side) = flow_with(b"x").await;
        match rate.handle(flow).await {
            Ok(_) => println!("flow {i}: allow"),
            Err(e) => println!("flow {i}: deny（{e}）"),
        }
    }
    let rate_stats = rate.stats();
    println!("rate-limit stats: {rate_stats:?}");
    anyhow::ensure!(rate_stats.denied >= 1, "限速插件应出现 deny（桶空）");

    // ---- 内容过滤：禁词 deny / 干净载荷 allow + 首块回放 ----
    let filter = load(&filter_path)?;
    println!("loaded: {filter:?}");
    let (flow, _side) = flow_with(b"GET /wp-admin/setup.php HTTP/1.1").await;
    let err = filter.handle(flow).await.expect_err("禁词应 deny");
    println!("banned: deny（{err}）");

    let (flow, mut side) = flow_with(b"GET /index.html HTTP/1.1").await;
    let flow = filter.handle(flow).await.expect("干净载荷应 allow");
    let mut io = flow.io;
    let mut buf = vec![0u8; "GET /index.html HTTP/1.1".len()];
    io.read_exact(&mut buf).await?;
    println!(
        "clean: allow + 回放完好（{:?}）",
        String::from_utf8_lossy(&buf)
    );
    anyhow::ensure!(&buf == b"GET /index.html HTTP/1.1", "首块回放应完好");
    side.write_all(b"live").await?;
    let mut live = [0u8; 4];
    io.read_exact(&mut live).await?;
    anyhow::ensure!(&live == b"live", "回放后应透传");
    drop(io);

    let filter_stats = filter.stats();
    println!("content-filter stats: {filter_stats:?}");
    anyhow::ensure!(filter_stats.denied >= 1, "内容过滤应出现 deny");
    anyhow::ensure!(filter_stats.calls >= 2, "内容过滤应至少两次裁决");

    println!("now_ms = {}（宿主注入时钟，限速回补以此推进）", now_ms());
    println!("plugins_smoke: 全部断言通过");
    Ok(())
}
