//! RIL-064 诊断开销对照量测（collector + 逐连接查询面——会话数据路径
//! 接线前的诚实范围）：关闭/采样/全量三档同负载逐项测量并打印，数字
//! 进 `docs/diagnostics-overhead.md`；测试只钉保守上界防回归（捕获
//! 二次方退化），不追机器间微小差异。

use rillane_core::collector::CollectorConfig;
use rillane_core::collector::FlowCollector;
use rillane_core::outbound::EvidenceKind;
use rillane_core::query::FlowQueryService;
use rillane_core::trace::{FlowId, FlowOrigin, TraceStage};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// 每档准入新流数
const FLOWS: usize = 8_000;
/// 查询面命中测量的取样数
const LOOKUPS: usize = 2_000;

/// 驻留内存（KiB；linux /proc/self/statm，其余平台 0 = 不测）
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096 / 1024)
        .unwrap_or(0)
}

/// 守护进程默认档（Runtime 装配同形：容量 1024 / 活动上限 256 /
/// 每流 256 / TTL 1h）只变追踪开关与采样分母——对照其余变量不动
fn config_for(sample: u32, enabled: bool) -> CollectorConfig {
    CollectorConfig::new(1024, 256, 256, 3_600_000, sample, enabled).unwrap()
}

fn percentile(mut xs: Vec<u64>, p: f64) -> u64 {
    xs.sort_unstable();
    let idx = ((xs.len() as f64 - 1.0) * p).round() as usize;
    xs.get(idx).copied().unwrap_or(0)
}

/// 三档准入开销对照 + 查询面时延。断言保守上界（关闭档纯布尔检查
/// ~亚微秒；全量档有界环形准入微秒级；查询线性扫描十微秒级）——
/// 超界即采集器出现二次方退化，机器差异吃不掉这个量级差。
#[test]
fn overhead_modes_measured_and_within_conservative_bounds() {
    let rss0 = rss_kb();

    // 关闭档：整体 no-op（数据面只付一次布尔检查）
    let mut off = FlowCollector::new(config_for(1, false));
    let t = Instant::now();
    for i in 0..FLOWS {
        let _ = off.admit(
            FlowId::new(format!("off-{i}")).unwrap(),
            FlowOrigin::Stream,
            "gen",
            TraceStage::Takeover,
            "trace.taken_over",
            EvidenceKind::Observed,
            0,
            1_000 + i as u64,
            "",
        );
    }
    let off_admit_us = t.elapsed().as_secs_f64() * 1e6 / FLOWS as f64;

    // 采样档：sample=10（约 1/10 建迹，其余走采样淘汰计数）
    let mut sampled = FlowCollector::new(config_for(10, true));
    let t = Instant::now();
    for i in 0..FLOWS {
        let _ = sampled.admit(
            FlowId::new(format!("samp-{i}")).unwrap(),
            FlowOrigin::Stream,
            "gen",
            TraceStage::Takeover,
            "trace.taken_over",
            EvidenceKind::Observed,
            0,
            1_000 + i as u64,
            "",
        );
    }
    let sampled_admit_us = t.elapsed().as_secs_f64() * 1e6 / FLOWS as f64;
    let sampled_admitted = sampled.stats().traces_admitted;

    // 全量档：sample=1（全部建迹，环形容量兜底逐出）
    let mut full = FlowCollector::new(config_for(1, true));
    let mut per_admit_ns = Vec::with_capacity(FLOWS);
    for i in 0..FLOWS {
        let t0 = Instant::now();
        let _ = full.admit(
            FlowId::new(format!("full-{i}")).unwrap(),
            FlowOrigin::Stream,
            "gen",
            TraceStage::Takeover,
            "trace.taken_over",
            EvidenceKind::Observed,
            0,
            1_000 + i as u64,
            "",
        );
        per_admit_ns.push(t0.elapsed().as_nanos() as u64);
    }
    let full_admit_us = per_admit_ns.iter().sum::<u64>() as f64 / FLOWS as f64 / 1e3;
    let rss1 = rss_kb();

    // 查询面命中时延（容量 1024 线性扫描——找「最旧」命中以量最坏档）
    let svc = FlowQueryService::new(Arc::new(Mutex::new(full)));
    let mut per_lookup_us = Vec::with_capacity(LOOKUPS);
    for i in 0..LOOKUPS {
        // 跨步取样命中（环内最旧的命中档——线性扫描最坏段）
        let idx = i * (FLOWS / LOOKUPS);
        let id = FlowId::new(format!("full-{idx}")).unwrap();
        let t0 = Instant::now();
        let _ = svc.flow(&id);
        per_lookup_us.push(t0.elapsed().as_micros() as u64);
    }
    let p50 = percentile(per_lookup_us.clone(), 0.50);
    let p95 = percentile(per_lookup_us.clone(), 0.95);
    let p99 = percentile(per_lookup_us.clone(), 0.99);

    println!("---- RIL-064 diagnostics overhead (debug build, this machine) ----");
    println!("mode        flows   admit-avg(us)   admitted   rss-delta-kb");
    println!(
        "off         {FLOWS}   {off_admit_us:>10.3}       0          {}",
        rss1.saturating_sub(rss0)
    );
    println!("sample=10   {FLOWS}   {sampled_admit_us:>10.3}       {sampled_admitted}          -");
    println!(
        "full        {FLOWS}   {full_admit_us:>10.3}       {}          -",
        FLOWS
    );
    println!("lookup-hit  n={LOOKUPS}  p50={p50}us p95={p95}us p99={p99}us");

    // 保守上界（debug 构建；采集器若退化成二次方，这个量级差机器差异盖不住）
    assert!(
        off_admit_us < 1.0,
        "关闭档 admit 应为纯布尔检查量级（实测 {off_admit_us}µs）"
    );
    let full_p99_ns = percentile(per_admit_ns, 0.99);
    assert!(
        full_p99_ns < 50_000,
        "全量档 admit p99 应为微秒级（环形有界），实测 {full_p99_ns}ns"
    );
    assert!(
        p99 < 2_000,
        "查询命中 p99 应为十微秒级（1024 迹线性扫描），实测 {p99}µs"
    );
}
