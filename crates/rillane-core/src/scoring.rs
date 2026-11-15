//! 场景评分与迟滞（RIL-027）：消费 RIL-026 类型化质量样本，按场景
//! 目标加权出分，并给「要不要换出口」一个带迟滞与冷却的确定性答案。
//!
//! 规则边界（验收口径）：
//! - **不同目标权重**：游戏（rtt/丢包重权、吞吐零权）与网页（吞吐重权）
//!   各自声明 `ObjectiveWeights`——同一份样本在不同目标下排名可以不同；
//! - **样本时效**：过期/未知样本**显式剔除并可见**（报告记剔除数），
//!   绝不当零参与计算（RIL-026 同纪律）；
//! - **样本不足不伪造**：指标样本数 < `min_samples_per_metric` → 该
//!   指标不贡献分数且 SLO 判 `Unknown`（类型面无假数字：`score: Option<f64>`，
//!   全指标不足即 `None`）；SLO 达标只在「有效期内 + 样本足量 + 界内」
//!   三者齐备时成立；
//! - **切换阈值与冷却**：候选分须**超出**现役 `switch_threshold` 才考虑
//!   换（迟滞防抖动）；上次切换后 `cooldown_ms` 内不换（冷却防反复）；
//!   两者都不满足时 `Stay` 带可解释原因；
//! - **不影响已绑定流**：评分器是纯函数（`&self`，无可变状态），产出
//!   的决策只供**新流**选择（绑定在 RIL-022 `SessionPin`/台账，评分器
//!   根本拿不到会话句柄——结构上排除存量流被评分改动）；
//! - **输入快照可重放理由**：报告冻结权重与归一参考快照、逐指标贡献
//!   （用了哪些样本/剔了哪些/原始值/归一值/权重），同快照重放必得同
//!   报告。
//!
//! 接线边界：runtime 把探活/拨号样本按候选装配 `ScoreInputs`，把决策
//! 应用于新流的路由面；RIL-021 场景声明（game/web/general）由配置层
//! 装配 `ScenarioProfile`（内核不依赖 config crate）。

use std::fmt;

use crate::quality::{
    QualityMetric, QualitySample, SampleStatus, SampleValue,
};

/// 稳定原因码：权重全零（无法加权评分）
pub const CODE_WEIGHTS_INVALID: &str = "scoring.weights.invalid";
/// 稳定原因码：画像参数非法（负阈值等）
pub const CODE_PROFILE_INVALID: &str = "scoring.profile.invalid";

/// 目标权重（按场景目标声明；全零非法）
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectiveWeights {
    /// 往返时延权重
    pub rtt_ms: f64,
    /// 真实丢包权重
    pub packet_loss: f64,
    /// 连接失败权重
    pub connection_failure: f64,
    /// 吞吐权重
    pub throughput: f64,
}

impl ObjectiveWeights {
    /// 游戏目标：小包低延迟优先，吞吐零权
    pub fn gaming() -> Self {
        Self {
            rtt_ms: 0.6,
            packet_loss: 0.3,
            connection_failure: 0.1,
            throughput: 0.0,
        }
    }

    /// 网页目标：吞吐优先，时延次之
    pub fn web() -> Self {
        Self {
            rtt_ms: 0.3,
            packet_loss: 0.0,
            connection_failure: 0.1,
            throughput: 0.6,
        }
    }

    /// 权重总和
    pub fn total(&self) -> f64 {
        self.rtt_ms + self.packet_loss + self.connection_failure + self.throughput
    }
}

/// 归一参考（冻结进报告——重放凭据的一半）
#[derive(Debug, Clone, PartialEq)]
pub struct MetricRefs {
    /// rtt 参考：rtt = ref → 归一 1.0，2×ref → 0.5
    pub rtt_ref_ms: f64,
    /// 吞吐参考：throughput = ref → 归一 1.0
    pub throughput_ref_mbps: f64,
    /// 比率参考：ratio = ref → 归一 0.0（再高恒 0）
    pub ratio_ref: f64,
}

impl Default for MetricRefs {
    fn default() -> Self {
        Self {
            rtt_ref_ms: 50.0,
            throughput_ref_mbps: 100.0,
            ratio_ref: 0.01,
        }
    }
}

/// SLO 界（None = 该指标无 SLO 判定）
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SloSpec {
    /// rtt p95 上界（毫秒）
    pub rtt_p95_max_ms: Option<u32>,
    /// 丢包率上界（0..1）
    pub loss_max_ratio: Option<f64>,
    /// 连接失败率上界（0..1）
    pub failure_max_ratio: Option<f64>,
}

/// 场景画像（不同目标的评分与切换规则；RIL-021 场景面的求值半边）
#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioProfile {
    /// 场景名（与 RIL-021 ScenarioRule.name 同口径）
    pub name: String,
    /// 目标权重
    pub weights: ObjectiveWeights,
    /// 单指标最少样本数（不足不伪造）
    pub min_samples_per_metric: u32,
    /// 归一参考
    pub refs: MetricRefs,
    /// SLO 界
    pub slo: SloSpec,
    /// 切换阈值（候选须超出这么多分才考虑换——迟滞）
    pub switch_threshold: f64,
    /// 切换冷却（上次切换后多久内不换——防反复）
    pub cooldown_ms: u64,
}

impl ScenarioProfile {
    /// 游戏画像（默认阈值 0.05、冷却 30s、rtt SLO 80ms）
    pub fn gaming(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            weights: ObjectiveWeights::gaming(),
            min_samples_per_metric: 3,
            refs: MetricRefs::default(),
            slo: SloSpec {
                rtt_p95_max_ms: Some(80),
                ..Default::default()
            },
            switch_threshold: 0.05,
            cooldown_ms: 30_000,
        }
    }

    /// 网页画像（默认阈值 0.05、冷却 30s、无 SLO 界）
    pub fn web(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            weights: ObjectiveWeights::web(),
            min_samples_per_metric: 3,
            refs: MetricRefs::default(),
            slo: SloSpec::default(),
            switch_threshold: 0.05,
            cooldown_ms: 30_000,
        }
    }

    /// 校验画像：权重非全零、阈值非负
    pub fn validate(&self) -> Result<(), ScoreError> {
        if self.weights.total() <= 0.0 {
            return Err(ScoreError::WeightsInvalid);
        }
        if self.switch_threshold < 0.0 {
            return Err(ScoreError::ProfileInvalid);
        }
        Ok(())
    }
}

/// 评分错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreError {
    /// 权重全零（`scoring.weights.invalid`）
    WeightsInvalid,
    /// 画像参数非法（`scoring.profile.invalid`）
    ProfileInvalid,
}

impl ScoreError {
    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        match self {
            ScoreError::WeightsInvalid => CODE_WEIGHTS_INVALID,
            ScoreError::ProfileInvalid => CODE_PROFILE_INVALID,
        }
    }
}

impl fmt::Display for ScoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScoreError::WeightsInvalid => f.write_str("objective weights sum to zero"),
            ScoreError::ProfileInvalid => f.write_str("scenario profile invalid (negative threshold)"),
        }
    }
}

impl std::error::Error for ScoreError {}

/// 一个候选的输入快照（可重放原料：候选身份 + 样本集）
#[derive(Debug, Clone)]
pub struct ScoreInputs {
    /// 候选身份（节点名）
    pub candidate: String,
    /// 该候选的质量样本集（RIL-026 类型化样本）
    pub samples: Vec<QualitySample>,
}

impl ScoreInputs {
    /// 构造输入快照
    pub fn new(candidate: impl Into<String>, samples: Vec<QualitySample>) -> Self {
        Self {
            candidate: candidate.into(),
            samples,
        }
    }
}

/// 单指标贡献（可重放理由的最小单元）
#[derive(Debug, Clone, PartialEq)]
pub struct MetricContribution {
    /// 指标
    pub metric: QualityMetric,
    /// 进入计算的样本数
    pub used_samples: u32,
    /// 显式过期剔除数（可见，不当零）
    pub skipped_expired: u32,
    /// 显式未知剔除数（比率分母 0 等）
    pub skipped_unknown: u32,
    /// 聚合原始值（rtt p95 均值 / 比率 / mbps 均值）
    pub raw: f64,
    /// 归一质量 [0,1]
    pub quality: f64,
    /// 权重快照
    pub weight: f64,
    /// 加权贡献（quality × weight）
    pub weighted: f64,
}

/// SLO 判定
#[derive(Debug, Clone, PartialEq)]
pub enum SloVerdict {
    /// 达标（有效期内 + 样本足量 + 界内三者齐备）
    Met {
        /// 指标
        metric: QualityMetric,
    },
    /// 违约（观测值 + 界）
    Violated {
        /// 指标
        metric: QualityMetric,
        /// 观测值
        observed: f64,
        /// 界
        bound: f64,
    },
    /// 未知——样本不足不伪造达标（类型面无假「达标」）
    Unknown {
        /// 指标
        metric: QualityMetric,
        /// 未知原因
        reason: SloUnknownReason,
    },
}

/// SLO 未知原因
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SloUnknownReason {
    /// 样本不足（have < need）
    InsufficientSamples {
        /// 现有
        have: u32,
        /// 需要的
        need: u32,
    },
    /// 样本全过期
    Expired,
    /// 无有效测量（分母 0）
    NoMeasurement,
}

/// 评分报告（冻结全部输入口径——同快照重放必得同报告）
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreReport {
    /// 候选身份
    pub candidate: String,
    /// 综合分 [0,1]；None = 加权指标全不足——绝不伪造数字
    pub score: Option<f64>,
    /// 逐指标贡献
    pub contributions: Vec<MetricContribution>,
    /// 样本不足的加权指标（不贡献分数，显式列出）
    pub insufficient: Vec<QualityMetric>,
    /// 权重快照（重放凭据）
    pub weights: ObjectiveWeights,
    /// 归一参考快照（重放凭据）
    pub refs: MetricRefs,
    /// SLO 判定
    pub slo: Vec<SloVerdict>,
}

/// 驻留原因（迟滞/冷却/未知——全部可解释）
#[derive(Debug, Clone, PartialEq)]
pub enum StayReason {
    /// 冷却中（距可切换还剩多少毫秒）
    Cooldown { remaining_ms: u64 },
    /// 增益未过阈值（现役分/候选分/阈值——迟滞防抖动）
    BelowThreshold {
        current: f64,
        candidate: f64,
        threshold: f64,
    },
    /// 现役分数未知（样本不足——不在缺数据时盲换）
    CurrentScoreUnknown,
    /// 全部候选分数未知
    CandidateScoreUnknown,
    /// 无候选
    NoCandidates,
}

/// 换口决策（只供新流选择——已绑定流在 RIL-022 台账，评分器不可触及）
#[derive(Debug, Clone, PartialEq)]
pub enum SwitchDecision {
    /// 驻留
    Stay { reason: StayReason },
    /// 切换（携带新候选报告——重放凭据）
    Switch {
        from: String,
        to: String,
        gain: f64,
        report: ScoreReport,
    },
}

/// 场景评分器：纯函数（`&self`），无可变状态——决策不影响任何已
/// 绑定流（结构边界）。
#[derive(Debug, Clone)]
pub struct ScenarioScorer {
    profile: ScenarioProfile,
}

impl ScenarioScorer {
    /// 构造评分器（画像非法拒绝）
    pub fn new(profile: ScenarioProfile) -> Result<Self, ScoreError> {
        profile.validate()?;
        Ok(Self { profile })
    }

    /// 画像（只读）
    pub fn profile(&self) -> &ScenarioProfile {
        &self.profile
    }

    /// 评分（输入快照 → 可重放报告）
    pub fn score(&self, input: &ScoreInputs, now_ms: u64) -> ScoreReport {
        let mut contributions = Vec::new();
        let mut insufficient = Vec::new();
        let mut weighted_sum = 0.0;
        let mut weight_sum = 0.0;

        let mut eval = |metric: QualityMetric, weight: f64| {
            if weight <= 0.0 {
                return;
            }
            let mut used = Vec::new();
            let (mut expired, mut unknown) = (0u32, 0u32);
            for sample in &input.samples {
                if sample.metric() != metric {
                    continue;
                }
                match sample.status(now_ms) {
                    SampleStatus::Current => used.push(sample),
                    SampleStatus::Expired { .. } => expired += 1,
                    SampleStatus::Unknown => unknown += 1,
                }
            }
            if (used.len() as u32) < self.profile.min_samples_per_metric {
                insufficient.push(metric);
                return;
            }
            let raw = aggregate(metric, &used);
            let quality = normalize(metric, raw, &self.profile.refs);
            weighted_sum += quality * weight;
            weight_sum += weight;
            contributions.push(MetricContribution {
                metric,
                used_samples: used.len() as u32,
                skipped_expired: expired,
                skipped_unknown: unknown,
                raw,
                quality,
                weight,
                weighted: quality * weight,
            });
        };

        let w = &self.profile.weights;
        eval(QualityMetric::RttMs, w.rtt_ms);
        eval(QualityMetric::PacketLossRatio, w.packet_loss);
        eval(QualityMetric::ConnectionFailureRatio, w.connection_failure);
        eval(QualityMetric::ThroughputMbps, w.throughput);

        let score = if weight_sum > 0.0 {
            Some(weighted_sum / weight_sum)
        } else {
            None
        };

        ScoreReport {
            candidate: input.candidate.clone(),
            score,
            contributions,
            insufficient,
            weights: self.profile.weights.clone(),
            refs: self.profile.refs.clone(),
            slo: self.slo_verdicts(input, now_ms),
        }
    }

    /// SLO 判定：达标只在「有效期内 + 样本足量 + 界内」齐备时成立；
    /// 样本不足/全过期/无测量都是显式 Unknown（不伪造达标）
    fn slo_verdicts(&self, input: &ScoreInputs, now_ms: u64) -> Vec<SloVerdict> {
        let mut verdicts = Vec::new();
        let slo = &self.profile.slo;
        let need = self.profile.min_samples_per_metric;
        let judge = |metric: QualityMetric, bound: f64, verdicts: &mut Vec<SloVerdict>| {
            let mut used = Vec::new();
            let (mut expired, mut unknown) = (0u32, 0u32);
            for sample in &input.samples {
                if sample.metric() != metric {
                    continue;
                }
                match sample.status(now_ms) {
                    SampleStatus::Current => used.push(sample),
                    SampleStatus::Expired { .. } => expired += 1,
                    SampleStatus::Unknown => unknown += 1,
                }
            }
            if (used.len() as u32) < need {
                let reason = if expired > 0 && used.is_empty() {
                    SloUnknownReason::Expired
                } else if unknown > 0 && used.is_empty() {
                    SloUnknownReason::NoMeasurement
                } else {
                    SloUnknownReason::InsufficientSamples {
                        have: used.len() as u32,
                        need,
                    }
                };
                verdicts.push(SloVerdict::Unknown { metric, reason });
                return;
            }
            let observed = aggregate(metric, &used);
            if observed <= bound {
                verdicts.push(SloVerdict::Met { metric });
            } else {
                verdicts.push(SloVerdict::Violated {
                    metric,
                    observed,
                    bound,
                });
            }
        };
        if let Some(max) = slo.rtt_p95_max_ms {
            judge(QualityMetric::RttMs, max as f64, &mut verdicts);
        }
        if let Some(max) = slo.loss_max_ratio {
            judge(QualityMetric::PacketLossRatio, max, &mut verdicts);
        }
        if let Some(max) = slo.failure_max_ratio {
            judge(QualityMetric::ConnectionFailureRatio, max, &mut verdicts);
        }
        verdicts
    }

    /// 换口决策：候选分超出阈值（迟滞）且冷却已过才换；任一分数未知
    /// 或无候选都驻留并给出原因。纯函数——已绑定流不在本函数任何
    /// 入参里（结构边界：只影响新流选择）。
    pub fn prefer(
        &self,
        current: &str,
        current_input: &ScoreInputs,
        candidates: &[ScoreInputs],
        last_switch_ms: Option<u64>,
        now_ms: u64,
    ) -> SwitchDecision {
        let current_report = self.score(current_input, now_ms);
        let Some(current_score) = current_report.score else {
            return SwitchDecision::Stay {
                reason: StayReason::CurrentScoreUnknown,
            };
        };
        if candidates.is_empty() {
            return SwitchDecision::Stay {
                reason: StayReason::NoCandidates,
            };
        }

        // 候选按分数取最优（分数未知的候选不参与——不盲换）
        let mut best: Option<(&ScoreInputs, ScoreReport)> = None;
        for candidate in candidates {
            if candidate.candidate == current {
                continue;
            }
            let report = self.score(candidate, now_ms);
            let Some(score) = report.score else {
                continue;
            };
            if best
                .as_ref()
                .map(|(_, r)| r.score.expect("已核验 Some") < score)
                .unwrap_or(true)
            {
                best = Some((candidate, report));
            }
        }
        let Some((candidate, report)) = best else {
            return SwitchDecision::Stay {
                reason: StayReason::CandidateScoreUnknown,
            };
        };

        let gain = report.score.expect("已核验 Some") - current_score;
        if gain < self.profile.switch_threshold {
            return SwitchDecision::Stay {
                reason: StayReason::BelowThreshold {
                    current: current_score,
                    candidate: report.score.expect("已核验 Some"),
                    threshold: self.profile.switch_threshold,
                },
            };
        }
        if let Some(last) = last_switch_ms {
            if now_ms >= last {
                let elapsed = now_ms - last;
                if elapsed < self.profile.cooldown_ms {
                    return SwitchDecision::Stay {
                        reason: StayReason::Cooldown {
                            remaining_ms: self.profile.cooldown_ms - elapsed,
                        },
                    };
                }
            }
        }
        SwitchDecision::Switch {
            from: current.to_string(),
            to: candidate.candidate.clone(),
            gain,
            report,
        }
    }
}

/// 指标聚合原始值：时延取 p95 均值；比率合并分子分母（聚合口径正确，
/// 不做均值欺小样本）；吞吐取均值
fn aggregate(metric: QualityMetric, samples: &[&QualitySample]) -> f64 {
    match metric {
        QualityMetric::RttMs | QualityMetric::HandshakeMs => {
            let sum: u64 = samples
                .iter()
                .filter_map(|s| match s.value() {
                    SampleValue::Latency { p95_ms, .. } => Some(*p95_ms as u64),
                    _ => None,
                })
                .sum();
            sum as f64 / samples.len() as f64
        }
        QualityMetric::PacketLossRatio | QualityMetric::ConnectionFailureRatio => {
            let mut num = 0u64;
            let mut den = 0u64;
            for s in samples {
                if let SampleValue::Ratio { numerator, denominator } = s.value() {
                    num += *numerator as u64;
                    den += *denominator as u64;
                }
            }
            if den == 0 {
                0.0
            } else {
                num as f64 / den as f64
            }
        }
        QualityMetric::ThroughputMbps => {
            let sum: u64 = samples
                .iter()
                .filter_map(|s| match s.value() {
                    SampleValue::Throughput { mbps } => Some(*mbps as u64),
                    _ => None,
                })
                .sum();
            sum as f64 / samples.len() as f64
        }
    }
}

/// 归一 [0,1]：时延 ref/raw（越低越好）；吞吐 raw/ref；比率 1-raw/ref
fn normalize(metric: QualityMetric, raw: f64, refs: &MetricRefs) -> f64 {
    match metric {
        QualityMetric::RttMs | QualityMetric::HandshakeMs => {
            if raw <= 0.0 {
                1.0
            } else {
                (refs.rtt_ref_ms / raw).clamp(0.0, 1.0)
            }
        }
        QualityMetric::ThroughputMbps => {
            if refs.throughput_ref_mbps <= 0.0 {
                0.0
            } else {
                (raw / refs.throughput_ref_mbps).clamp(0.0, 1.0)
            }
        }
        QualityMetric::PacketLossRatio | QualityMetric::ConnectionFailureRatio => {
            if refs.ratio_ref <= 0.0 {
                0.0
            } else {
                (1.0 - raw / refs.ratio_ref).clamp(0.0, 1.0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::SampleSource;

    const T0: u64 = 1_000_000;
    const LIFE: u64 = 30_000;

    fn rtt_sample(target: &str, p95: u32, observed: u64) -> QualitySample {
        QualitySample::latency(
            QualityMetric::RttMs,
            SampleSource::Probe,
            target,
            p95 / 2,
            p95,
            5,
            observed,
            LIFE,
        )
    }

    fn throughput_sample(target: &str, mbps: u32, observed: u64) -> QualitySample {
        QualitySample::throughput(SampleSource::Probe, target, mbps, 3, observed, LIFE)
    }

    /// 不同目标权重：同一样本集，游戏画像与网页画像排名相反
    #[test]
    fn different_objectives_rank_same_inputs_differently() {
        let scorer = |profile| ScenarioScorer::new(profile).expect("合法画像");
        let gaming = scorer(ScenarioProfile::gaming("game"));
        let web = scorer(ScenarioProfile::web("web"));

        // A：低延迟低吞吐（游戏友好）；B：高延迟高吞吐（网页友好）
        let a = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 40, T0),
                rtt_sample("node-a", 40, T0),
                rtt_sample("node-a", 40, T0),
                throughput_sample("node-a", 20, T0),
                throughput_sample("node-a", 20, T0),
                throughput_sample("node-a", 20, T0),
            ],
        );
        let b = ScoreInputs::new(
            "node-b",
            vec![
                rtt_sample("node-b", 120, T0),
                rtt_sample("node-b", 120, T0),
                rtt_sample("node-b", 120, T0),
                throughput_sample("node-b", 200, T0),
                throughput_sample("node-b", 200, T0),
                throughput_sample("node-b", 200, T0),
            ],
        );

        let ra = gaming.score(&a, T0);
        let rb = gaming.score(&b, T0);
        let (sa, sb) = (ra.score.expect("A 可评"), rb.score.expect("B 可评"));
        assert!(
            sa > sb,
            "游戏目标下 A({sa}) 应压过 B({sb})——低延迟重权"
        );

        let ra = web.score(&a, T0);
        let rb = web.score(&b, T0);
        let (sa, sb) = (ra.score.expect("A 可评"), rb.score.expect("B 可评"));
        assert!(
            sb > sa,
            "网页目标下 B({sb}) 应压过 A({sa})——吞吐重权"
        );
    }

    /// 输入快照可重放：同快照两次评分报告逐字段相等（权重/参考冻结）
    #[test]
    fn report_is_replayable_from_snapshot() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
        let input = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 40, T0),
                rtt_sample("node-a", 60, T0),
                rtt_sample("node-a", 50, T0),
            ],
        );
        let r1 = scorer.score(&input, T0);
        let r2 = scorer.score(&input, T0);
        assert_eq!(r1, r2, "同快照重放必得同报告");
        assert_eq!(r1.weights, ObjectiveWeights::gaming(), "权重快照入报告");
        assert_eq!(r1.refs, MetricRefs::default(), "参考快照入报告");
        // 贡献可逐项复核：rtt p95 均值 50 → 归一 50/50=1.0
        let c = &r1.contributions[0];
        assert_eq!(c.metric, QualityMetric::RttMs);
        assert_eq!(c.used_samples, 3);
        assert_eq!(c.raw, 50.0);
        assert_eq!(c.quality, 1.0);
        assert_eq!(r1.score, Some(1.0));
    }

    /// 样本时效：过期样本显式剔除并可见（skipped_expired），不当零
    #[test]
    fn expired_samples_excluded_and_visible() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
        let input = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 40, T0),
                rtt_sample("node-a", 40, T0),
                rtt_sample("node-a", 40, T0),
                // 过期样本（观测于 31000ms 前，寿命 30000ms）
                rtt_sample("node-a", 999_999, T0 - LIFE - 1000),
            ],
        );
        let report = scorer.score(&input, T0);
        let c = &report.contributions[0];
        assert_eq!(c.used_samples, 3);
        assert_eq!(c.skipped_expired, 1, "过期剔除可见");
        assert_eq!(c.skipped_unknown, 0);
        assert_eq!(c.raw, 40.0, "过期样本不得拉高均值（不当零也不当坏）");
    }

    /// 样本不足不伪造：加权指标全不足 → score None（无假数字）；
    /// 指标列入 insufficient；SLO Unknown{InsufficientSamples}
    #[test]
    fn insufficient_samples_never_fabricate_score_or_slo() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
        let input = ScoreInputs::new(
            "node-a",
            vec![rtt_sample("node-a", 40, T0), rtt_sample("node-a", 40, T0)],
        );
        let report = scorer.score(&input, T0);
        assert_eq!(report.score, None, "不足不得伪造分数");
        // 游戏权重里 loss/failure 非零，同样无样本 → 一并列入不足
        assert_eq!(
            report.insufficient,
            vec![
                QualityMetric::RttMs,
                QualityMetric::PacketLossRatio,
                QualityMetric::ConnectionFailureRatio
            ]
        );
        assert!(report.contributions.is_empty());
        assert_eq!(
            report.slo,
            vec![SloVerdict::Unknown {
                metric: QualityMetric::RttMs,
                reason: SloUnknownReason::InsufficientSamples { have: 2, need: 3 },
            }],
            "样本不足不得伪造 SLO 达标"
        );
    }

    /// SLO 显式三态：足量新鲜界内 → Met；超界 → Violated 带观测值；
    /// 全过期 → Unknown{Expired}；分母 0 → Unknown{NoMeasurement}
    #[test]
    fn slo_verdicts_are_explicit() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");

        let met = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 60, T0),
                rtt_sample("node-a", 70, T0),
                rtt_sample("node-a", 80, T0),
            ],
        );
        assert_eq!(
            scorer.score(&met, T0).slo,
            vec![SloVerdict::Met {
                metric: QualityMetric::RttMs
            }]
        );

        let violated = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 100, T0),
                rtt_sample("node-a", 100, T0),
                rtt_sample("node-a", 100, T0),
            ],
        );
        assert_eq!(
            scorer.score(&violated, T0).slo,
            vec![SloVerdict::Violated {
                metric: QualityMetric::RttMs,
                observed: 100.0,
                bound: 80.0,
            }]
        );

        let expired = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 40, T0 - LIFE * 2),
                rtt_sample("node-a", 40, T0 - LIFE * 2),
                rtt_sample("node-a", 40, T0 - LIFE * 2),
            ],
        );
        assert_eq!(
            scorer.score(&expired, T0).slo,
            vec![SloVerdict::Unknown {
                metric: QualityMetric::RttMs,
                reason: SloUnknownReason::Expired,
            }]
        );

        // 三个分母 0 的失败率样本（数量够但无有效测量 → Unknown 状态）
        let zero_den = || {
            QualitySample::connection_failures(SampleSource::DialOutcome, "node-a", 1, 0, T0, LIFE)
        };
        let input = ScoreInputs::new("node-a", vec![zero_den(), zero_den(), zero_den()]);
        // 分母 0 → 全部 Unknown 状态 → NoMeasurement（网页画像默认无
        // SLO 界，只声明 failure 界 → 判定面只有这一条）
        let mut profile = ScenarioProfile::web("probe");
        profile.slo.failure_max_ratio = Some(0.01);
        let scorer = ScenarioScorer::new(profile).expect("合法画像");
        assert_eq!(
            scorer.score(&input, T0).slo,
            vec![SloVerdict::Unknown {
                metric: QualityMetric::ConnectionFailureRatio,
                reason: SloUnknownReason::NoMeasurement,
            }]
        );
    }

    /// 迟滞：候选增益未过阈值 → Stay{BelowThreshold}；过阈值且冷却已
    /// 过 → Switch
    #[test]
    fn switch_requires_threshold_hysteresis() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
        // 现役 p95 60 → 归一 50/60 ≈ 0.833
        let strong = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 60, T0),
                rtt_sample("node-a", 60, T0),
                rtt_sample("node-a", 60, T0),
            ],
        );
        // 相近候选：p95 58 → 50/58 ≈ 0.862，增益 0.029 < 0.05（迟滞带内）
        let near = ScoreInputs::new(
            "node-b",
            vec![
                rtt_sample("node-b", 58, T0),
                rtt_sample("node-b", 58, T0),
                rtt_sample("node-b", 58, T0),
            ],
        );
        // 远优候选：p95 20 → 归一 1.0，增益 ≈ 0.167 > 0.05
        let far = ScoreInputs::new(
            "node-c",
            vec![
                rtt_sample("node-c", 20, T0),
                rtt_sample("node-c", 20, T0),
                rtt_sample("node-c", 20, T0),
            ],
        );

        match scorer.prefer("node-a", &strong, &[near], None, T0) {
            SwitchDecision::Stay {
                reason: StayReason::BelowThreshold { threshold, .. },
            } => assert_eq!(threshold, 0.05),
            other => panic!("相近候选应驻留: {other:?}"),
        }
        match scorer.prefer("node-a", &strong, std::slice::from_ref(&far), None, T0) {
            SwitchDecision::Switch { from, to, gain, .. } => {
                assert_eq!(from, "node-a");
                assert_eq!(to, "node-c");
                assert!(gain >= 0.05);
            }
            other => panic!("远优候选应切换: {other:?}"),
        }
    }

    /// 冷却：过阈值但冷却期内 → Stay{Cooldown}（防反复）；冷却过后 → Switch
    #[test]
    fn cooldown_blocks_flapping() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
        // 现役 p95 60（归一 ≈0.833）；候选 p95 20（归一 1.0，增益 ≈0.167 过阈值）
        let strong = ScoreInputs::new(
            "node-a",
            vec![
                rtt_sample("node-a", 60, T0),
                rtt_sample("node-a", 60, T0),
                rtt_sample("node-a", 60, T0),
            ],
        );
        let far = ScoreInputs::new(
            "node-c",
            vec![
                rtt_sample("node-c", 20, T0),
                rtt_sample("node-c", 20, T0),
                rtt_sample("node-c", 20, T0),
            ],
        );
        let last_switch = T0 - 1_000; // 1s 前刚切过（冷却 30s）

        match scorer.prefer("node-a", &strong, &[far], Some(last_switch), T0) {
            SwitchDecision::Stay {
                reason: StayReason::Cooldown { remaining_ms },
            } => assert_eq!(remaining_ms, 29_000),
            other => panic!("冷却期内应驻留: {other:?}"),
        }

        // 冷却过后：同输入 → Switch
        let far = ScoreInputs::new(
            "node-c",
            vec![
                rtt_sample("node-c", 20, T0),
                rtt_sample("node-c", 20, T0),
                rtt_sample("node-c", 20, T0),
            ],
        );
        match scorer.prefer("node-a", &strong, &[far], Some(last_switch), T0 + 29_000) {
            SwitchDecision::Switch { to, .. } => assert_eq!(to, "node-c"),
            other => panic!("冷却过后应切换: {other:?}"),
        }
    }

    /// 分数未知不盲换：现役未知 / 候选全未知 → Stay；已绑定流不在任何
    /// 入参（结构边界：决策只供新流），纯函数两次调用结果一致
    #[test]
    fn unknown_scores_stay_and_decision_is_pure() {
        let scorer = ScenarioScorer::new(ScenarioProfile::gaming("game")).expect("合法画像");
        let thin = ScoreInputs::new(
            "node-a",
            vec![rtt_sample("node-a", 40, T0), rtt_sample("node-a", 40, T0)],
        );
        let rich = ScoreInputs::new(
            "node-b",
            vec![
                rtt_sample("node-b", 20, T0),
                rtt_sample("node-b", 20, T0),
                rtt_sample("node-b", 20, T0),
            ],
        );

        match scorer.prefer("node-a", &thin, std::slice::from_ref(&rich), None, T0) {
            SwitchDecision::Stay {
                reason: StayReason::CurrentScoreUnknown,
            } => {}
            other => panic!("现役未知应驻留: {other:?}"),
        }
        match scorer.prefer("node-a", &rich, &[thin], None, T0) {
            SwitchDecision::Stay {
                reason: StayReason::CandidateScoreUnknown,
            } => {}
            other => panic!("候选全未知应驻留: {other:?}"),
        }
        match scorer.prefer("node-a", &rich, &[], None, T0) {
            SwitchDecision::Stay {
                reason: StayReason::NoCandidates,
            } => {}
            other => panic!("无候选应驻留: {other:?}"),
        }

        // 纯函数：同一输入两次决策一致（无可变状态——不影响任何绑定面）
        let d1 = scorer.prefer("node-a", &rich, std::slice::from_ref(&rich), None, T0);
        let d2 = scorer.prefer("node-a", &rich.clone(), std::slice::from_ref(&rich), None, T0);
        assert_eq!(d1, d2);
    }

    /// 画像非法拒绝：权重全零 / 负阈值（稳定码）
    #[test]
    fn invalid_profile_rejected() {
        let zero = ScenarioProfile {
            name: "bad".into(),
            weights: ObjectiveWeights {
                rtt_ms: 0.0,
                packet_loss: 0.0,
                connection_failure: 0.0,
                throughput: 0.0,
            },
            ..ScenarioProfile::gaming("bad")
        };
        let err = ScenarioScorer::new(zero).expect_err("全零权重应拒");
        assert_eq!(err.code(), CODE_WEIGHTS_INVALID);

        let negative = ScenarioProfile {
            switch_threshold: -0.1,
            ..ScenarioProfile::gaming("bad")
        };
        let err = ScenarioScorer::new(negative).expect_err("负阈值应拒");
        assert_eq!(err.code(), CODE_PROFILE_INVALID);
    }
}
