//! padding 策略引擎与中间件（obfuscation-middleware.md §2）
//!
//! 策略/执行分离（§2.1 裁决）：`PaddingMiddleware` 只产 `rillane.obfs.padding`
//! 注解（§1.4 契约），不触碰 `io`——填充由帧执行侧实施（M3，MeshEnvelope
//! pad/strip）。引擎纯函数确定性（§2.2）：range 随机源 = hash(flow_id,
//! frame_seq)，不用 RNG——测试可复现，无需 seed 配置项。

use anyhow::Result;
use async_trait::async_trait;
use rillane_core::{Flow, FlowId, FlowMiddleware, PaddingMode, PaddingSpec};

/// 注解键（§1.4 契约）：carrier 写路由上下文，middleware 只读；
/// `rillane.obfs.padding` 由本中间件写、帧执行侧读。
pub const ANN_ROUTE_KIND: &str = "rillane.route.kind";
pub const ANN_ROUTE_EGRESS: &str = "rillane.route.egress";
pub const ANN_OBFS_PADDING: &str = "rillane.obfs.padding";

/// 跳过原因（§5 skipped_total 封闭标签的引擎子集）：OverheadCap = E10
/// （len' 超 §2.6 上限，策略层放弃）；TooLarge 兼收 fixed len>target 与
/// bucket 超最大桶——目标形态装不下现帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PadSkipReason {
    OverheadCap,
    TooLarge,
}

/// 填充决策（§7.1 策略引擎输出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PadDecision {
    /// 补 pad_len（>0）字节至 padded_len
    Pad { padded_len: usize, pad_len: usize },
    /// 无需填充（恰在桶上 / 恰为 target / range 掷点 ≤ len）——不计数
    InPlace,
    /// 放弃填充 + 原因（skipped_total 计数）
    Skip { reason: PadSkipReason },
}

/// 策略引擎（§2.2 表 + §2.6 上限）：给定 spec 与帧长求填充决策。
/// 纯函数——同 (spec, len, flow_id, frame_seq) 恒同果；overhead 上限在
/// 策略层判（§2.6），执行侧只按决策办事不再二次判定。
pub fn decide_padding(
    spec: &PaddingSpec,
    len: usize,
    flow_id: &FlowId,
    frame_seq: u64,
) -> PadDecision {
    let candidate = match spec.mode {
        PaddingMode::Fixed => {
            if len > spec.target {
                return PadDecision::Skip {
                    reason: PadSkipReason::TooLarge,
                };
            }
            if len == spec.target {
                return PadDecision::InPlace;
            }
            spec.target
        }
        PaddingMode::Bucket => match spec.buckets.iter().find(|&&b| b >= len) {
            // buckets 严格升序由 config validate（§3.3-4）保证
            None => {
                return PadDecision::Skip {
                    reason: PadSkipReason::TooLarge,
                }
            }
            Some(&b) if b == len => return PadDecision::InPlace,
            Some(&b) => b,
        },
        PaddingMode::Range => {
            // min ≤ max 由 config validate 保证；但为防绕过校验/未来路径
            // 的 `max < min`（下溢 + `% 0` panic），先做健壮化：span 至少 1，
            // 掷点确定性（§2.2）。若 max < min，回退为固定 min（不填充超限）。
            let (lo, hi) = if spec.max >= spec.min {
                (spec.min, spec.max)
            } else {
                (spec.min, spec.min)
            };
            let span = (hi - lo + 1).max(1) as u64;
            let roll = lo + (range_hash(flow_id, frame_seq) % span) as usize;
            roll.max(len)
        }
    };
    // §2.6：len' > max(len*(1+ratio), min) 则不填充（E10）——min 入下界，
    // range 补到 min 恒不违规；r=0 时除掷点恰为 min 外全放弃
    let cap = f64::max(
        len as f64 * (1.0 + spec.max_overhead_ratio as f64),
        spec.min as f64,
    );
    if candidate as f64 > cap {
        return PadDecision::Skip {
            reason: PadSkipReason::OverheadCap,
        };
    }
    if candidate == len {
        // 仅 range 可达（掷点 ≤ len：结果即原长）
        return PadDecision::InPlace;
    }
    PadDecision::Pad {
        padded_len: candidate,
        pad_len: candidate - len,
    }
}

/// 确定性随机源（§2.2）：FNV-1a 64 over flow_id 字节，混入 frame_seq 后以
/// splitmix64 终结——同流不同帧取不同值，全程无 RNG、跨平台确定。
fn range_hash(flow_id: &FlowId, frame_seq: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for byte in flow_id.as_uuid().as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a prime
    }
    h ^= frame_seq;
    // splitmix64 finalizer：打乱相邻输入（seq 递增）的输出相关性
    let mut z = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// padding 策略中间件（§2.1 策略侧）：按固化的选择器闭包判定本流是否填充，
/// 命中则把 spec 序列化写入 `rillane.obfs.padding` 注解（§1.4），不触碰 io。
/// 选择器闭包由 runtime 侧从 `ApplyTo` 固化传入（§3.2 表行 2——本 crate
/// 不依赖 rillane-config/runtime，匹配输入 = §1.4 注解值字符串形）。
pub type PadSelector = Box<dyn Fn(&str, Option<&str>) -> bool + Send + Sync>;

pub struct PaddingMiddleware {
    spec: PaddingSpec,
    selector: PadSelector,
}

impl PaddingMiddleware {
    pub fn new(spec: PaddingSpec, selector: PadSelector) -> Self {
        Self { spec, selector }
    }
}

#[async_trait]
impl FlowMiddleware for PaddingMiddleware {
    fn name(&self) -> &'static str {
        "padding"
    }

    async fn handle(&self, mut flow: Flow) -> Result<Flow> {
        // 只读 carrier 注解（§1.4 单向：不改 rillane.route.* 键）
        let selected = {
            let ann = &flow.metadata.annotations;
            let kind = ann.get(ANN_ROUTE_KIND).map(String::as_str).unwrap_or("");
            let egress = ann.get(ANN_ROUTE_EGRESS).map(String::as_str);
            (self.selector)(kind, egress)
        };
        if selected {
            let json = serde_json::to_string(&self.spec)?;
            flow.metadata
                .annotations
                .insert(ANN_OBFS_PADDING.to_string(), json);
        }
        Ok(flow)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rillane_core::{FlowId, FlowTarget, PaddingMode, PaddingSpec, TargetProto};

    use super::*;

    fn spec(mode: PaddingMode, mutate: impl FnOnce(&mut PaddingSpec)) -> PaddingSpec {
        let mut s = PaddingSpec {
            mode,
            target: 512,
            buckets: vec![256, 512, 1024],
            min: 512,
            max: 1400,
            max_overhead_ratio: 0.5,
        };
        mutate(&mut s);
        s
    }

    /// §2.2 fixed 行：len<target 补到 target；len>target 不填（too_large）；
    /// len==target 无需填。（min=0 对齐 config 缺省——cap 公式的 min 项不参与）
    #[test]
    fn fixed_mode_three_way() {
        let s = spec(PaddingMode::Fixed, |s| s.min = 0);
        let id = FlowId::new();
        // len=400：cap = max(400*1.5, 0) = 600 ≥ 512 → Pad
        assert_eq!(
            decide_padding(&s, 400, &id, 0),
            PadDecision::Pad {
                padded_len: 512,
                pad_len: 112
            }
        );
        assert_eq!(
            decide_padding(&s, 600, &id, 0),
            PadDecision::Skip {
                reason: PadSkipReason::TooLarge
            }
        );
        assert_eq!(decide_padding(&s, 512, &id, 0), PadDecision::InPlace);
    }

    /// §2.2 bucket 行：恰在桶上不填；桶间隙取最近上界；超最大桶不填。
    #[test]
    fn bucket_mode_alignment() {
        let s = spec(PaddingMode::Bucket, |s| {
            s.min = 0;
            s.max_overhead_ratio = 1.0;
        });
        let id = FlowId::new();
        assert_eq!(decide_padding(&s, 256, &id, 0), PadDecision::InPlace);
        // len=300 → 最近上界桶 512（cap = 300*2 = 600 ≥ 512）
        assert_eq!(
            decide_padding(&s, 300, &id, 0),
            PadDecision::Pad {
                padded_len: 512,
                pad_len: 212
            }
        );
        // len=700 → 1024（cap = 700*2 = 1400 ≥ 1024）
        assert_eq!(
            decide_padding(&s, 700, &id, 0),
            PadDecision::Pad {
                padded_len: 1024,
                pad_len: 324
            }
        );
        assert_eq!(
            decide_padding(&s, 1025, &id, 0),
            PadDecision::Skip {
                reason: PadSkipReason::TooLarge
            }
        );
    }

    /// §2.2 range 行：结果落 [max(len,min), max]；同 (flow,seq) 可复现；
    /// 不同帧序号取值不同（宽 span 下多样）。
    #[test]
    fn range_mode_deterministic_and_bounded() {
        let s = spec(PaddingMode::Range, |s| s.max_overhead_ratio = 100.0);
        let id = FlowId::new();
        for seq in 0..50u64 {
            match decide_padding(&s, 60, &id, seq) {
                PadDecision::Pad { padded_len, .. } => {
                    assert!((512..=1400).contains(&padded_len), "掷点越界：{padded_len}");
                }
                other => panic!("r=100 不应放弃：seq={seq} → {other:?}"),
            }
        }
        // 确定性：同 (flow, seq) 两次调用同果
        assert_eq!(
            decide_padding(&s, 60, &id, 7),
            decide_padding(&s, 60, &id, 7)
        );
        // 帧序号生效：50 帧掷点至少 10 个不同长度（恒等长即特征，§2.2）
        let distinct: std::collections::HashSet<usize> = (0..50u64)
            .map(|seq| match decide_padding(&s, 60, &id, seq) {
                PadDecision::Pad { padded_len, .. } => padded_len,
                other => panic!("r=100 不应放弃：{other:?}"),
            })
            .collect();
        assert!(
            distinct.len() >= 10,
            "掷点缺乏多样性：{} 种",
            distinct.len()
        );

        // 掷点 ≤ len：结果即原长（InPlace，不计数）——min < len 场景
        let low = spec(PaddingMode::Range, |s| {
            s.min = 100;
            s.max = 200;
        });
        let big_len = 300;
        let mut outcomes = std::collections::HashSet::new();
        for seq in 0..50u64 {
            outcomes.insert(decide_padding(&low, big_len, &id, seq));
        }
        assert_eq!(
            outcomes,
            std::collections::HashSet::from([PadDecision::InPlace]),
            "len > max 时掷点恒 < len → InPlace"
        );
    }

    /// P2 深审回归（2026-11-03）：range 模式 `max < min`（绕过 config validate
    /// 或未来路径）不得下溢 span（`% 0` panic）。健壮化后回退为固定 min，
    /// 掷点确定性不 panic。
    #[test]
    fn range_mode_max_below_min_does_not_panic() {
        let s = spec(PaddingMode::Range, |s| {
            s.min = 1400;
            s.max = 512; // max < min（非法输入）
            s.max_overhead_ratio = 100.0;
        });
        let id = FlowId::new();
        for seq in 0..20u64 {
            // 不 panic；回退固定 min → 掷点 ≥ min=1400。
            match decide_padding(&s, 60, &id, seq) {
                PadDecision::Pad { padded_len, .. } => {
                    assert!(padded_len >= 1400, "回退应 ≥ min：{padded_len}");
                }
                other => panic!("r=100 不应放弃：seq={seq} → {other:?}"),
            }
        }
        // 确定性保留
        assert_eq!(
            decide_padding(&s, 60, &id, 5),
            decide_padding(&s, 60, &id, 5)
        );
    }

    /// §2.6 overhead 上限：小包对齐大桶放弃（E10）+ ratio=0 除掷点恰为 min
    /// 外全放弃（cap 公式含 min 的意义）。
    #[test]
    fn overhead_cap_guards_small_packets() {
        // 60B 对齐 256 桶，r=0.5 min=0 → cap = 90 < 256 → 放弃
        let s = spec(PaddingMode::Bucket, |s| s.min = 0);
        let id = FlowId::new();
        assert_eq!(
            decide_padding(&s, 60, &id, 0),
            PadDecision::Skip {
                reason: PadSkipReason::OverheadCap
            }
        );
        // fixed 同理：511 → 512，r=0 min=0 → cap = 511 < 512 → 放弃
        let s = spec(PaddingMode::Fixed, |s| {
            s.min = 0;
            s.max_overhead_ratio = 0.0;
        });
        assert_eq!(
            decide_padding(&s, 511, &id, 0),
            PadDecision::Skip {
                reason: PadSkipReason::OverheadCap
            }
        );
        // range：min=512 max=1400 r=0.3，len=1000 → cap = max(1300, 512) = 1300；
        // 掷点 ∈ (1000,1300] 可填、>1300 放弃、≤1000 结果即原长（InPlace）——
        // 200 帧内 pad 与放弃两侧必现（掷点确定性下概率论证：见 §2.2）
        let s = spec(PaddingMode::Range, |s| s.max_overhead_ratio = 0.3);
        let mut saw_pad = false;
        let mut saw_skip = false;
        for seq in 0..200u64 {
            match decide_padding(&s, 1000, &id, seq) {
                PadDecision::Pad { padded_len, .. } => {
                    assert!(padded_len <= 1300, "越 cap 填充：{padded_len}");
                    saw_pad = true;
                }
                PadDecision::Skip {
                    reason: PadSkipReason::OverheadCap,
                } => saw_skip = true,
                // range 模式 candidate = roll.max(len) ≥ len，永不 TooLarge
                // （TooLarge 仅 fixed/bucket 的 len 超目标形态可达）
                PadDecision::Skip {
                    reason: PadSkipReason::TooLarge,
                } => panic!("range 模式不应产生 TooLarge"),
                PadDecision::InPlace => {}
            }
        }
        assert!(
            saw_pad && saw_skip,
            "cap 边界两侧均应出现（pad={saw_pad} skip={saw_skip}）"
        );
    }

    /// §2.1/§1.4：选择器命中 → 写 `rillane.obfs.padding` 注解（JSON 可还原）、
    /// carrier 键与 tags 原样；不命中 → 注解缺席（零副作用）。
    #[tokio::test]
    async fn middleware_writes_annotation_on_selector_hit() {
        let spec = spec(PaddingMode::Fixed, |_| {});
        let mw = PaddingMiddleware::new(
            spec.clone(),
            Box::new(|kind, egress| kind == "chain" && egress == Some("hk-1")),
        );

        let flow = |kind: Option<&str>, egress: Option<&str>| Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".to_string(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(tokio::io::duplex(64).1),
            metadata: rillane_core::FlowMetadata {
                tags: vec!["t".to_string()],
                annotations: BTreeMap::from([
                    ("rillane.chain.path".to_string(), "[\"hk-1\"]".to_string()),
                    (
                        ANN_ROUTE_KIND.to_string(),
                        kind.unwrap_or_default().to_string(),
                    ),
                    (
                        ANN_ROUTE_EGRESS.to_string(),
                        egress.unwrap_or_default().to_string(),
                    ),
                ]),
            },
        };

        // 命中：注解写入且 JSON 还原 == spec；carrier 键未动
        let out = mw
            .handle(flow(Some("chain"), Some("hk-1")))
            .await
            .expect("handle 应成功");
        let json = out
            .metadata
            .annotations
            .get(ANN_OBFS_PADDING)
            .expect("命中应写 rillane.obfs.padding");
        assert_eq!(serde_json::from_str::<PaddingSpec>(json).unwrap(), spec);
        assert_eq!(
            out.metadata
                .annotations
                .get("rillane.chain.path")
                .map(String::as_str),
            Some("[\"hk-1\"]"),
            "不改 carrier 键"
        );
        assert_eq!(out.metadata.tags, ["t".to_string()]);

        // 不命中（egress 不匹配）：注解缺席
        let out = mw
            .handle(flow(Some("chain"), Some("jp-1")))
            .await
            .expect("handle 应成功");
        assert!(!out.metadata.annotations.contains_key(ANN_OBFS_PADDING));

        // 注解缺失（carrier 未注入，M1 前的现实态）：kind 空串不匹配 → 缺席
        let out = mw.handle(flow(None, None)).await.expect("handle 应成功");
        assert!(!out.metadata.annotations.contains_key(ANN_OBFS_PADDING));
    }
}
