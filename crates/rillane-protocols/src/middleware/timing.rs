//! timing 策略引擎与中间件（obfuscation-timing-shaping.md §2-D1/D3/D4）
//!
//! 与 padding 同管线形态：策略侧写 `rillane.obfs.timing` 注解；执行侧 =
//! 本 middleware `handle` 内一次性 sleep（延迟签名一目了然，零 io 包装）。
//! 决策确定性同源：`decide_timing` = 纯函数，uniform 掷点 = hash(flow_id,0)。

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use rillane_core::{Flow, FlowId, FlowMiddleware, TimingMode, TimingSpec};

use super::{ANN_ROUTE_EGRESS, ANN_ROUTE_KIND};

/// 注解键：`rillane.obfs.timing` = 本次注入的启动抖动毫秒值（观测面）。
pub const ANN_OBFS_TIMING: &str = "rillane.obfs.timing";

/// timing 策略选择器（同 PadSelector 形态：`rillane.route.kind`/`egress`）。
pub type TimingSelector = Box<dyn Fn(&str, Option<&str>) -> bool + Send + Sync>;

/// timing 策略中间件（handle 内直接 sleep，不包装 io）。
pub struct TimingMiddleware {
    spec: TimingSpec,
    selector: TimingSelector,
}

impl TimingMiddleware {
    pub fn new(spec: TimingSpec, selector: TimingSelector) -> Self {
        Self { spec, selector }
    }
}

/// 决策纯函数：fixed → fixed_ms；uniform → min + hash(flow_id,0) % (max-min+1)；
/// 两者统一截断到 max_delay_ms 闸门（§2-D4：增档不 Err，截断即降级）。
pub fn decide_timing(spec: &TimingSpec, flow_id: &FlowId) -> u64 {
    let raw = match spec.mode {
        TimingMode::Fixed => spec.fixed_ms,
        TimingMode::Uniform => {
            let span = (spec.max_ms - spec.min_ms + 1).max(1);
            spec.min_ms + (range_hash(flow_id, 0) % span)
        }
    };
    raw.min(spec.max_delay_ms)
}

/// 确定性随机源（同 padding §2.2 同族：FNV-1a 64 + splitmix64 finalizer）。
fn range_hash(flow_id: &FlowId, frame_seq: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in flow_id.as_uuid().as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= frame_seq;
    let mut z = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[async_trait]
impl FlowMiddleware for TimingMiddleware {
    fn name(&self) -> &'static str {
        "timing"
    }

    async fn handle(&self, mut flow: Flow) -> Result<Flow> {
        let selected = {
            let ann = &flow.metadata.annotations;
            let kind = ann.get(ANN_ROUTE_KIND).map(String::as_str).unwrap_or("");
            let egress = ann.get(ANN_ROUTE_EGRESS).map(String::as_str);
            (self.selector)(kind, egress)
        };
        if selected {
            let delay = decide_timing(&self.spec, &flow.id);
            flow.metadata
                .annotations
                .insert(ANN_OBFS_TIMING.to_string(), delay.to_string());
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
        Ok(flow)
    }
}

#[cfg(test)]
mod tests {
    use rillane_core::{Flow, FlowId, FlowTarget, TargetProto};

    use super::*;

    fn spec(mode: TimingMode, mutate: impl FnOnce(&mut TimingSpec)) -> TimingSpec {
        let mut s = TimingSpec {
            mode,
            fixed_ms: 0,
            min_ms: 0,
            max_ms: 0,
            max_delay_ms: u64::MAX,
        };
        mutate(&mut s);
        s
    }

    fn flow() -> Flow {
        Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(tokio::io::duplex(64).0),
            metadata: Default::default(),
        }
    }

    /// §7-3：fixed 直出；uniform 值域 + 同 flow_id 确定；闸门截断。
    #[test]
    fn decide_timing_range_deterministic_and_capped() {
        let id = FlowId::new();
        let fixed = spec(TimingMode::Fixed, |s| s.fixed_ms = 15);
        assert_eq!(decide_timing(&fixed, &id), 15);

        let uniform = spec(TimingMode::Uniform, |s| {
            s.min_ms = 5;
            s.max_ms = 20;
        });
        let d1 = decide_timing(&uniform, &id);
        let d2 = decide_timing(&uniform, &id);
        assert_eq!(d1, d2, "同 flow_id 恒同值");
        assert!((5..=20).contains(&d1), "值域 [min, max]：{d1}");

        // 闸门：值域整体越过 max_delay_ms → 截断（D-4）
        let capped = spec(TimingMode::Uniform, |s| {
            s.min_ms = 90;
            s.max_ms = 100;
            s.max_delay_ms = 50;
        });
        assert!(decide_timing(&capped, &id) <= 50, "闸门截断");
        let fixed_capped = spec(TimingMode::Fixed, |s| {
            s.fixed_ms = 80;
            s.max_delay_ms = 30;
        });
        assert_eq!(decide_timing(&fixed_capped, &id), 30);
    }

    /// §7-3：middleware handle 写注解 + 真 sleep（小值可感知）+ 未命中
    /// 选择器时既不注解也不 sleep。
    #[tokio::test]
    async fn middleware_annotates_and_sleeps() {
        let mw = TimingMiddleware::new(
            spec(TimingMode::Fixed, |s| s.fixed_ms = 30),
            Box::new(|_, _| true),
        );
        let t0 = std::time::Instant::now();
        let f = mw.handle(flow()).await.unwrap();
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(25),
            "应真 sleep：{elapsed:?}"
        );
        assert_eq!(
            f.metadata
                .annotations
                .get(ANN_OBFS_TIMING)
                .map(String::as_str),
            Some("30")
        );

        let mw_off = TimingMiddleware::new(
            spec(TimingMode::Fixed, |s| s.fixed_ms = 30),
            Box::new(|_, _| false),
        );
        let t0 = std::time::Instant::now();
        let f2 = mw_off.handle(flow()).await.unwrap();
        assert!(t0.elapsed() < Duration::from_millis(10), "未命中不 sleep");
        assert!(!f2.metadata.annotations.contains_key(ANN_OBFS_TIMING));
    }
}
