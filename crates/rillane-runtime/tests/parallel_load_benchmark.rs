//! 并行负载性能对照（RIL-089 / Linux 同节点·线路·负载）：同一运行时
//! 实例、同一路由（默认直连）、同一回环线路上三类负载对照——游戏小包
//! 类单独 / 网页吞吐类单独 / 两类并行共存；逐轮打印 p50/p95、抖动、有
//! 效丢包、TTFB、吞吐、进程 CPU/RSS 与重复轮次（数字进
//! `docs/parallel-load.md`）。调度策略对照（公平调度 vs 先到先服务）
//! 以确定性回放在决策层完成——出口发送循环接线前这是诚实范围（RIL-025
//! 边界注记）；回退与无收益条件随对照一并报告。测试只钉保守上界防回
//! 归（捕获饥饿与无界驻留），不追机器间微小差异。

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rillane_config::{
    ControlConfig, EgressConfig, EgressDescriptor, IngressConfig, IngressDescriptor, RillaneConfig,
    RoutingConfig, TelemetryConfig, UdpConfig,
};
use rillane_core::{
    FairScheduler, Grant, QualityMetric, QualitySample, SampleSource, ScenarioProfile,
    ScenarioScorer, ScheduleShape, ScoreInputs, StayReason, SwitchDecision, TrafficClass,
};
use rillane_runtime::{Runtime, RuntimeBuilder, RuntimeConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// 负载形状（对照的负载口径：三类臂共用同一形状）
// ---------------------------------------------------------------------------

/// 游戏小包会话数（并行/单独臂同形）
const GAME_SESSIONS: usize = 4;
/// 每会话往返次数（RTT 样本量）
const GAME_PINGS: usize = 200;
/// 游戏小包大小（字节）
const PING_BYTES: usize = 100;
/// 网页吞吐会话数
const WEB_SESSIONS: usize = 4;
/// 每会话字节数（回显总量）
const WEB_BYTES: u64 = 2 * 1024 * 1024;
/// 网页读写块
const WEB_CHUNK: usize = 64 * 1024;
/// 并行臂重复轮次
const ROUNDS: usize = 5;

// ---------------------------------------------------------------------------
// 运行时装配（复用 RIL-095 接管验收同款纪律）
// ---------------------------------------------------------------------------

/// 并行测试的绑定面串行化（探端口 → 释放 → 复绑窗口不被并行测试偷走）
static BIND_GUARD: Mutex<()> = Mutex::const_new(());

/// 探一个空闲端口并立即释放（复绑窗口内使用）
fn free_bind() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
    format!("127.0.0.1:{}", l.local_addr().expect("端口").port())
}

/// 回环回显服务（「真实目标」）：逐块回显收到的 TCP 载荷（小包逐笔
/// 回 = 游戏 ping-pong；大块流式回 = 网页下载）
async fn spawn_echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回显监听");
    let port = l.local_addr().expect("端口").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; WEB_CHUNK];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// 可运行配置面（回环 SOCKS5 入口 + 单一直连出口 + 默认路由）
fn bench_runtime_config(socks_bind: String) -> RillaneConfig {
    RillaneConfig {
        version: rillane_config::ConfigVersion::default(),
        control: ControlConfig {
            api_bind: "127.0.0.1:0".to_string(),
            uds_path: None,
            admin_token: None,
        },
        telemetry: TelemetryConfig {
            log_level: "warn".to_string(),
            enable_metrics: false,
            enable_tracing: false,
        },
        ingress: vec![IngressDescriptor {
            name: "bench-socks".to_string(),
            spec: IngressConfig::Socks5 {
                bind: socks_bind,
                auth: None,
                udp_enabled: Some(false),
            },
        }],
        egress: vec![EgressDescriptor {
            name: "local-direct".to_string(),
            spec: EgressConfig::Direct,
        }],
        routing: RoutingConfig {
            default_node: "local-direct".to_string(),
            ..RoutingConfig::default()
        },
        udp: UdpConfig {
            enabled: false,
            ..Default::default()
        },
        network: None,
        obfuscation: None,
        profile: None,
        scenarios: Default::default(),
        performance: None,
        egress_pool: None,
        probe: None,
    }
}

/// 组装并启动运行时（含守卫串行化的绑定窗口）
async fn start_bench_runtime() -> (String, u16, u16, Arc<Runtime>) {
    let _guard = BIND_GUARD.lock().await;
    let socks_bind = free_bind();
    let game_port = spawn_echo_server().await;
    let web_port = spawn_echo_server().await;
    let runtime = Arc::new(
        RuntimeBuilder::new(bench_runtime_config(socks_bind.clone()))
            .with_runtime_config(RuntimeConfig {
                enable_hot_reload: false,
                ..RuntimeConfig::default()
            })
            .build()
            .expect("运行时装配"),
    );
    let _tasks = runtime.start().await.expect("启动");
    drop(_guard);
    (socks_bind, game_port, web_port, runtime)
}

/// SOCKS5 无认证 CONNECT 建立到目标的数据通道（握手一次，多往返共用）
async fn socks5_channel(bind: &str, target_port: u16) -> tokio::net::TcpStream {
    tokio::time::timeout(Duration::from_secs(10), async move {
        // start() 内入口 bind 异步发生——带重试等待监听就绪
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut s = None;
        while s.is_none() {
            match tokio::net::TcpStream::connect(bind).await {
                Ok(stream) => s = Some(stream),
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(e) => panic!("connect {bind} 失败: {e}"),
            }
        }
        let mut s = s.expect("连接入口");
        s.write_all(&[0x05, 0x01, 0x00]).await.expect("方法协商");
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.expect("方法应答");
        assert_eq!(method[1], 0x00, "无认证应被选中");
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&target_port.to_be_bytes());
        s.write_all(&req).await.expect("CONNECT 请求");
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.expect("CONNECT 应答");
        assert_eq!(reply[1], 0x00, "CONNECT 应成功（回环直连）");
        s
    })
    .await
    .expect("建链 10s 内完成")
}

// ---------------------------------------------------------------------------
// 负载臂：游戏小包 / 网页吞吐
// ---------------------------------------------------------------------------

/// 一条游戏会话：逐笔 ping-pong，返回 (rtt_µs 样本, 有效丢包笔数)。
/// 载荷逐笔校验（回显内容错也算丢）。
async fn game_session(bind: String, target_port: u16, pings: usize) -> (Vec<u64>, usize) {
    let mut s = socks5_channel(&bind, target_port).await;
    let mut rtts = Vec::with_capacity(pings);
    let mut loss = 0usize;
    for i in 0..pings {
        let payload: Vec<u8> = (0..PING_BYTES).map(|k| (i + k) as u8).collect();
        let t0 = Instant::now();
        let echo = tokio::time::timeout(Duration::from_secs(5), async {
            s.write_all(&payload).await.expect("ping 发送");
            let mut back = vec![0u8; PING_BYTES];
            s.read_exact(&mut back).await.expect("ping 回读");
            back
        })
        .await;
        match echo {
            Ok(back) if back == payload => rtts.push(t0.elapsed().as_micros() as u64),
            Ok(_) => loss += 1, // 内容错——有效丢包
            Err(_) => {
                loss += 1; // 超时——有效丢包
                break; // 链路已不可信，本会话止损
            }
        }
    }
    (rtts, loss)
}

/// 游戏臂：并行会话汇聚 RTT 样本与尝试笔数
async fn run_game_arm(
    bind: &str,
    port: u16,
    sessions: usize,
    pings: usize,
) -> (Vec<u64>, usize, usize) {
    let mut handles = Vec::new();
    for _ in 0..sessions {
        let owned = bind.to_string();
        handles.push(tokio::spawn(game_session(owned, port, pings)));
    }
    let mut rtts = Vec::new();
    let mut loss = 0usize;
    for h in handles {
        let (r, l) = h.await.expect("游戏会话收束");
        rtts.extend(r);
        loss += l;
    }
    let attempts = sessions * pings;
    (rtts, loss, attempts)
}

/// 一条网页会话：全量写入 + 流式回读，返回 (TTFB ms, MiB/s, 回读字节)。
async fn web_session(bind: String, target_port: u16, total: u64) -> (f64, f64, u64) {
    let s = socks5_channel(&bind, target_port).await;
    let (mut rd, mut wr) = tokio::io::split(s);
    // 写手独立任务——边写边读，杜绝全量先写后读的缓冲死锁
    let writer = tokio::spawn(async move {
        let chunk = vec![0xA5u8; WEB_CHUNK];
        let mut left = total;
        while left > 0 {
            let n = left.min(WEB_CHUNK as u64) as usize;
            wr.write_all(&chunk[..n]).await.expect("写入");
            left -= n as u64;
        }
    });
    let started = Instant::now();
    let mut got = 0u64;
    let mut ttfb_ms = 0.0f64;
    let mut buf = vec![0u8; WEB_CHUNK];
    while got < total {
        let n = tokio::time::timeout(
            Duration::from_secs(30),
            rd.read(&mut buf[..((total - got) as usize).min(WEB_CHUNK)]),
        )
        .await
        .expect("回读 30s 内完成")
        .expect("回读");
        if n == 0 {
            panic!("对端提前关闭");
        }
        if got == 0 {
            ttfb_ms = started.elapsed().as_secs_f64() * 1e3;
        }
        got += n as u64;
    }
    writer.await.expect("写手收束");
    let secs = started.elapsed().as_secs_f64();
    let mib_s = (total as f64 / (1024.0 * 1024.0)) / secs;
    (ttfb_ms, mib_s, got)
}

/// 网页臂：并行会话逐条汇总
async fn run_web_arm(bind: &str, port: u16, sessions: usize, total: u64) -> Vec<(f64, f64, u64)> {
    let mut handles = Vec::new();
    for _ in 0..sessions {
        let owned = bind.to_string();
        handles.push(tokio::spawn(web_session(owned, port, total)));
    }
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.expect("网页会话收束"));
    }
    out
}

// ---------------------------------------------------------------------------
// 量测面
// ---------------------------------------------------------------------------

fn percentile(mut xs: Vec<u64>, p: f64) -> u64 {
    xs.sort_unstable();
    let idx = ((xs.len() as f64 - 1.0) * p).round() as usize;
    xs.get(idx).copied().unwrap_or(0)
}

/// 抖动：相邻样本平均绝对差（ms 口径）
fn jitter_ms(rtts_us: &[u64]) -> f64 {
    if rtts_us.len() < 2 {
        return 0.0;
    }
    let sum: u64 = rtts_us.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
    sum as f64 / (rtts_us.len() - 1) as f64 / 1e3
}

/// 进程 CPU 时间片（CLK_TCK=100 口径；utime+stime；非 linux 返回 0）
fn cpu_ticks() -> u64 {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return 0;
    };
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return 0;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // rest[0]=state（第 3 列）——utime 第 14 列 → idx 11，stime 第 15 列 → idx 12
    fields
        .get(11)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        + fields
            .get(12)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
}

/// 驻留内存（KiB；linux /proc/self/statm，其余平台 0 = 不测）
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096 / 1024)
        .unwrap_or(0)
}

fn game_stats(rtts: &[u64]) -> (f64, f64, f64) {
    (
        percentile(rtts.to_vec(), 0.50) as f64 / 1e3,
        percentile(rtts.to_vec(), 0.95) as f64 / 1e3,
        jitter_ms(rtts),
    )
}

// ---------------------------------------------------------------------------
// 端到端对照（同实例 / 同路由 / 同回环线路）
// ---------------------------------------------------------------------------

/// 三臂对照量测：游戏单独 / 网页单独 / 并行共存（重复 ROUNDS 轮）。
/// 并行共存 = 同一实例同时承载两类负载——游戏尾延迟有界、网页不饥饿、
/// 逐笔无有效丢包、驻留有界。对照数字全量打印（p50/p95、抖动、有效丢
/// 包、TTFB、吞吐、CPU/RSS、轮次），断言只钉保守上界。
#[tokio::test]
async fn parallel_load_arms_measured_with_bounds() {
    let (bind, game_port, web_port, runtime) = start_bench_runtime().await;
    let rss0 = rss_kb();

    // —— 臂 1：游戏小包单独（基线）——
    let (alone_rtts, alone_loss, alone_attempts) =
        run_game_arm(&bind, game_port, GAME_SESSIONS, GAME_PINGS).await;
    let (a_p50, a_p95, a_jit) = game_stats(&alone_rtts);

    // —— 臂 2：网页吞吐单独（基线）——
    let alone_web = run_web_arm(&bind, web_port, WEB_SESSIONS, WEB_BYTES).await;

    // —— 臂 3：并行共存（重复 ROUNDS 轮）——
    let cpu0 = cpu_ticks();
    let wall = Instant::now();
    let mut rounds: Vec<(f64, f64, f64, usize, usize, f64, f64)> = Vec::new();
    for _ in 0..ROUNDS {
        let g = run_game_arm(&bind, game_port, GAME_SESSIONS, GAME_PINGS);
        let w = run_web_arm(&bind, web_port, WEB_SESSIONS, WEB_BYTES);
        let (g, w) = tokio::join!(g, w);
        let (rtts, loss, attempts) = g;
        let (p50, p95, jit) = game_stats(&rtts);
        let ttfb_p50 = percentile(
            w.iter().map(|x| (x.0 * 1e3) as u64).collect::<Vec<_>>(),
            0.50,
        ) as f64
            / 1e3;
        let thr_min = w.iter().map(|x| x.1).fold(f64::INFINITY, f64::min);
        let web_loss = w.iter().filter(|x| x.2 != WEB_BYTES).count();
        rounds.push((p50, p95, jit, loss + web_loss, attempts, ttfb_p50, thr_min));
    }
    let wall_secs = wall.elapsed().as_secs_f64();
    let cpu_pct = if cpu_ticks() > 0 {
        (cpu_ticks() - cpu0) as f64 * 10.0 / (wall_secs * 1e3) * 100.0
    } else {
        0.0
    };
    let rss_delta = rss_kb().saturating_sub(rss0);

    // —— 对照表全量打印（数字进 docs/parallel-load.md）——
    println!("---- RIL-089 parallel load (debug build, this machine) ----");
    println!(
        "arm/round       game-p50(ms) game-p95(ms) jitter(ms) loss/attempts web-ttfb-p50(ms) web-MiB/s(min)"
    );
    println!(
        "game-alone      {a_p50:>11.3} {a_p95:>12.3} {a_jit:>10.3} {alone_loss}/{alone_attempts}               -               -"
    );
    for (i, r) in alone_web.iter().enumerate() {
        println!(
            "web-alone[{i}]              -            -          -             -        {:>10.3}      {:>8.1}",
            r.0, r.1
        );
    }
    for (i, r) in rounds.iter().enumerate() {
        println!(
            "parallel[{i}]     {:>11.3} {:>12.3} {:>10.3} {}/{:>9}        {:>10.3}      {:>8.1}",
            r.0, r.1, r.2, r.3, r.4, r.5, r.6
        );
    }
    println!(
        "cpu over parallel phase: {cpu_pct:.1}% (core-equivalent, CLK_TCK=100); wall {wall_secs:.2}s; rss-delta {rss_delta} KiB"
    );
    println!(
        "rounds={ROUNDS} game-samples/round={} web-bytes/round={}B",
        GAME_SESSIONS * GAME_PINGS,
        WEB_SESSIONS as u64 * WEB_BYTES
    );

    // —— 保守上界（任何机器都该成立的量级差；饥饿/无界驻留必挂测）——
    assert_eq!(alone_loss, 0, "游戏单独臂零有效丢包");
    assert_eq!(alone_rtts.len(), alone_attempts, "样本量与尝试笔数一致");
    for x in &alone_web {
        assert_eq!(x.2, WEB_BYTES, "网页单独臂逐字节回显");
    }
    for r in &rounds {
        assert_eq!(r.3, 0, "并行臂零有效丢包（超时/截断/内容错都算丢）");
        assert!(
            r.1 < 1_000.0,
            "并行下游戏 p95 有界（饥饿守卫；实测 {}ms）",
            r.1
        );
        assert!(
            r.6 >= 1.0,
            "并行下网页吞吐不饥饿（每会话 ≥1 MiB/s；实测 {} MiB/s）",
            r.6
        );
        assert!(r.5.is_finite(), "TTFB 有限");
    }
    assert!(
        rss_delta < 128 * 1024,
        "驻留有界（<128 MiB；实测 {rss_delta} KiB）"
    );
    runtime.stop().await.expect("停止");
}

// ---------------------------------------------------------------------------
// 调度策略对照（确定性回放——出口发送循环接线前的诚实范围）
// ---------------------------------------------------------------------------

/// 回放调度形状：16 KiB 轮窗口、延迟预算 3 KiB（夹在 [1 KiB, 8 KiB]）
fn replay_shape() -> ScheduleShape {
    ScheduleShape {
        round_bytes: 16_384,
        latency_budget_bytes: 3_072,
        latency_budget_min: 1_024,
        latency_budget_max: 8_192,
    }
}

/// 轮节拍（回放时间口径：一轮 5 ms）
const REPLAY_ROUND_MS: u64 = 5;

/// 负载形状：一条 64 KiB 持续下载（t=0 在途）+ 每轮一只 100 B 游戏
/// 小包（t=k*5ms 到达）——并行共存的决策层缩影
fn arrivals_mixed() -> Vec<(u64, TrafficClass, u64)> {
    let mut v = vec![(0, TrafficClass::Throughput, 64 * 1024)];
    for k in 0..50u64 {
        v.push((k * REPLAY_ROUND_MS, TrafficClass::Latency, 100));
    }
    v.sort_by_key(|(t, _, _)| *t);
    v
}

/// FIFO 对照服务器（先到先服务、同轮窗口、无类别优先——公平调度的
/// 回退基线）
fn fifo_round(queue: &mut VecDeque<(TrafficClass, u64, u64)>, now_ms: u64) -> Vec<Grant> {
    let mut grants = Vec::new();
    let mut cap = replay_shape().round_bytes;
    while cap > 0 {
        let Some(front) = queue.front_mut() else {
            break;
        };
        let take = front.1.min(cap);
        grants.push(Grant {
            request_id: 0,
            class: front.0,
            bytes: take,
            wait_ms: now_ms.saturating_sub(front.2),
        });
        cap -= take;
        if take == front.1 {
            queue.pop_front();
        } else {
            front.1 -= take;
        }
    }
    grants
}

/// 回放一段到达序列，返回 (延迟类 wait 样本, 逐轮服务字节, 吞吐请求完
/// 成轮次)——公平与 FIFO 共用同一驱动循环
fn replay(
    arrivals: &[(u64, TrafficClass, u64)],
    fair: bool,
) -> (Vec<u64>, Vec<u64>, Option<usize>) {
    let mut sched = FairScheduler::new(replay_shape()).expect("合法形状");
    let mut queue: VecDeque<(TrafficClass, u64, u64)> = VecDeque::new();
    let mut next = 0usize;
    let mut game_waits = Vec::new();
    let mut per_round = Vec::new();
    let mut throughput_done_round = None;
    let mut throughput_left = arrivals
        .iter()
        .filter(|(_, c, _)| *c == TrafficClass::Throughput)
        .map(|(_, _, b)| b)
        .sum::<u64>();
    let total = arrivals.iter().map(|(_, _, b)| b).sum::<u64>();
    let mut served_total = 0u64;
    let mut t = 0u64;
    let mut round = 0usize;
    while served_total < total {
        while next < arrivals.len() && arrivals[next].0 <= t {
            let (at, class, bytes) = arrivals[next];
            if fair {
                let _ = sched.push(class, bytes, at).expect("合法请求");
            } else {
                queue.push_back((class, bytes, at));
            }
            next += 1;
        }
        let grants = if fair {
            sched.serve_round(t)
        } else {
            fifo_round(&mut queue, t)
        };
        let mut served = 0u64;
        for g in &grants {
            served += g.bytes;
            if g.class == TrafficClass::Latency {
                game_waits.push(g.wait_ms);
            } else {
                throughput_left = throughput_left.saturating_sub(g.bytes);
                if throughput_left == 0 && throughput_done_round.is_none() {
                    throughput_done_round = Some(round);
                }
            }
        }
        per_round.push(served);
        served_total += served;
        t += REPLAY_ROUND_MS;
        round += 1;
        assert!(round < 10_000, "回放不收敛——驱动循环有误");
    }
    (game_waits, per_round, throughput_done_round)
}

/// 调度策略对照与条件报告：持续下载在途时公平调度把游戏尾延迟钉在一
/// 轮内（FIFO 基线尾延迟随下载块排队）；回退条件 = 无延迟类流量时公平
/// 调度逐轮退化为与 FIFO 完全一致（工作保守，无收益也无开销差）；无收
/// 益条件 = 游戏 RTT 已达标时预算自动下移（不为延迟类过度占用）；场景
/// 切换回退 = 样本不足/无候选一律驻留现役（缺数据不盲换）。
#[test]
fn scheduling_policy_replay_reports_conditions() {
    // —— 对照：并行共存形状（下载在途 + 逐轮小包）——
    let arrivals = arrivals_mixed();
    let (fair_waits, fair_rounds, fair_done) = replay(&arrivals, true);
    let (fifo_waits, fifo_rounds_log, fifo_done) = replay(&arrivals, false);
    let fair_p95 = percentile(fair_waits.clone(), 0.95);
    let fifo_p95 = percentile(fifo_waits.clone(), 0.95);
    println!("---- RIL-089 scheduling replay (deterministic) ----");
    println!(
        "shape: round={}B latency-budget={}B",
        replay_shape().round_bytes,
        replay_shape().latency_budget_bytes
    );
    println!(
        "game wait p50/p95(ms): fair {}/{}  fifo {}/{}",
        percentile(fair_waits.clone(), 0.50),
        fair_p95,
        percentile(fifo_waits.clone(), 0.50),
        fifo_p95
    );
    println!(
        "download done round: fair {fair_done:?}  fifo {fifo_done:?}; rounds served: fair {} fifo {}",
        fair_rounds.len(),
        fifo_rounds_log.len()
    );
    assert!(
        !fair_waits.is_empty() && !fifo_waits.is_empty(),
        "回放负载里游戏小包在场"
    );
    assert!(
        fair_p95 <= REPLAY_ROUND_MS,
        "公平调度：游戏尾延迟钉在一轮内（实测 {fair_p95}ms）"
    );
    assert!(
        fifo_p95 >= REPLAY_ROUND_MS,
        "FIFO 基线：小包随下载块排队（实测 {fifo_p95}ms）——对照差真实存在"
    );
    assert!(
        fair_done.unwrap() <= fifo_done.unwrap() + 2,
        "吞吐类赤字有界（公平调度不吃掉整轮）"
    );

    // —— 回退条件：无延迟类流量 → 公平调度逐轮与 FIFO 完全一致 ——
    let solo = vec![(0u64, TrafficClass::Throughput, 64 * 1024u64)];
    let (fair_solo_waits, fair_solo_rounds, fair_solo_done) = replay(&solo, true);
    let (_, fifo_solo_rounds, fifo_solo_done) = replay(&solo, false);
    assert!(
        fair_solo_waits.is_empty(),
        "无延迟流量时公平调度不虚发延迟类授予"
    );
    assert_eq!(
        fair_solo_rounds, fifo_solo_rounds,
        "回退条件成立：公平调度退化为工作保守 FIFO（逐轮服务量全同）"
    );
    assert_eq!(fair_solo_done, fifo_solo_done, "吞吐完成轮次一致");

    // —— 无收益条件：游戏 RTT 已达标 → 预算自动下移（不为延迟类过度占用）——
    let mut sched = FairScheduler::new(replay_shape()).expect("合法形状");
    let init = sched.latency_budget();
    let mut applied_sum = 0i64;
    while sched.latency_budget() > replay_shape().latency_budget_min {
        let applied = sched.adapt_latency_budget(10, 200, 256); // 10*2 < 200 → 下移
        assert!(applied < 0, "达标时预算只下移: {applied}");
        applied_sum += applied;
    }
    assert_eq!(
        sched.latency_budget(),
        replay_shape().latency_budget_min,
        "下移夹在下界"
    );
    assert_eq!(
        applied_sum,
        replay_shape().latency_budget_min as i64 - init as i64,
        "步长可审计（应用步长和 = 终值-初值）"
    );
    let over = sched.adapt_latency_budget(1_000, 200, 256); // 超标 → 上移
    assert!(over > 0, "超标时预算上移: {over}");

    // —— 场景切换回退：缺数据驻留现役（不盲换）——
    let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
    let thin = ScoreInputs::new(
        "node-a",
        vec![QualitySample::latency(
            QualityMetric::RttMs,
            SampleSource::Probe,
            "node-a",
            40,
            60,
            1, // < min_samples_per_metric(3)——样本不足
            1_000,
            60_000,
        )],
    );
    assert!(
        scorer.score(&thin, 1_000).score.is_none(),
        "样本不足不给假分数"
    );
    // 检查次序同实现：现役分数未知 → 无候选 → 候选分数未知，三路都驻留
    match scorer.prefer("node-a", &thin, &[], None, 1_000) {
        SwitchDecision::Stay {
            reason: StayReason::CurrentScoreUnknown,
        } => {}
        other => panic!("现役分数未知应驻留: {other:?}"),
    }
    let full = ScoreInputs::new(
        "node-a",
        (0..3)
            .map(|_| {
                QualitySample::latency(
                    QualityMetric::RttMs,
                    SampleSource::Probe,
                    "node-a",
                    40,
                    60,
                    1,
                    1_000,
                    60_000,
                )
            })
            .collect(),
    );
    assert!(
        scorer.score(&full, 1_000).score.is_some(),
        "样本足量给得出分数"
    );
    match scorer.prefer("node-a", &full, &[], None, 1_000) {
        SwitchDecision::Stay {
            reason: StayReason::NoCandidates,
        } => {}
        other => panic!("无候选应驻留现役: {other:?}"),
    }
    let thin_b = ScoreInputs::new(
        "node-b",
        vec![QualitySample::latency(
            QualityMetric::RttMs,
            SampleSource::Probe,
            "node-b",
            20,
            30,
            1, // 样本不足——候选分数未知
            1_000,
            60_000,
        )],
    );
    match scorer.prefer("node-a", &full, &[thin_b], None, 1_000) {
        SwitchDecision::Stay {
            reason: StayReason::CandidateScoreUnknown,
        } => {}
        other => panic!("候选分数未知应驻留（不盲换）: {other:?}"),
    }
    println!(
        "conditions: fallback=fair→FIFO when no latency traffic; no-benefit=budget auto-lowers when game meets target; switch stays put on missing data"
    );
}
