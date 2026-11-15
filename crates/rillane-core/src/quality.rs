//! 类型化质量样本（RIL-026 / C25）：metric/source/target/count/time/
//! validity 全字段的类型化样本——握手耗时、往返时延、连接失败率、
//! 真实丢包率、吞吐是**不同的量**，不再共用一个裸 f32。
//!
//! 三条验收语义：
//! 1. **连接失败率不再名为丢包率**——`ConnectionFailureRatio` 是独立
//!    指标；旧口径把拨号失败率记在 packet_loss 字段上的（如 mesh
//!    `LinkState::packet_loss_rate` 的拨号来源数据），经
//!    [`QualitySample::migrate_legacy_loss`] 按测量来源改名迁移。
//! 2. **未知/过期不当零**——比率样本分母为 0 是「未知」（稳定原因码
//!    `quality.unknown`），超过有效期是「过期」（`quality.expired`）；
//!    取值接口显式报错，绝不静默回 0.0。本类型不实现 `Default`——
//!    「无测量 = 0.0 = 完美」正是要消灭的反模式。
//! 3. **真实丢包说明测量对端**——`PacketLossRatio` 样本必须携带测量
//!    对端（`quality.peer.missing` 拒绝缺失），说明是哪条链路、对谁
//!    测的丢包。
//!
//! 接线边界：rillane-mesh 不依赖本 crate——旧字段迁移在消费方
//! （RIL-027 场景评分）通过本模块的构造/迁移入口完成；本模块只承载
//! 契约与语义。

/// 稳定原因码：样本超过有效期（过期不当零）。
pub const CODE_QUALITY_EXPIRED: &str = "quality.expired";
/// 稳定原因码：无测量/分母为零（未知不当零）。
pub const CODE_QUALITY_UNKNOWN: &str = "quality.unknown";
/// 稳定原因码：丢包样本缺测量对端说明。
pub const CODE_QUALITY_PEER_MISSING: &str = "quality.peer.missing";

/// 质量指标类型（RIL-026）。`as_str()` 是机器口径，恒定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityMetric {
    /// 握手耗时（毫秒）
    HandshakeMs,
    /// 往返时延（毫秒）
    RttMs,
    /// 连接失败率：拨号/握手失败次数 ÷ 尝试次数——**不是丢包率**
    ConnectionFailureRatio,
    /// 真实丢包率：必须说明测量对端（[`QualitySample::measured_peer`]）
    PacketLossRatio,
    /// 吞吐（Mbps）
    ThroughputMbps,
}

impl QualityMetric {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            QualityMetric::HandshakeMs => "handshake_ms",
            QualityMetric::RttMs => "rtt_ms",
            QualityMetric::ConnectionFailureRatio => "connection_failure_ratio",
            QualityMetric::PacketLossRatio => "packet_loss_ratio",
            QualityMetric::ThroughputMbps => "throughput_mbps",
        }
    }
}

/// 样本来源（RIL-026）：说明测量手段——同名字段的语义随来源变化
///（拨号来源的"失败率"不是丢包）。`as_str()` 是机器口径，恒定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleSource {
    /// 主动探活（url-test 等显式探测）
    Probe,
    /// 拨号结果（真实连接的成功/失败）
    DialOutcome,
    /// Mesh 链路测量（对端协作口径）
    MeshLink,
    /// 用户/配置显式给出
    Manual,
}

impl SampleSource {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            SampleSource::Probe => "probe",
            SampleSource::DialOutcome => "dial_outcome",
            SampleSource::MeshLink => "mesh_link",
            SampleSource::Manual => "manual",
        }
    }
}

/// 样本值（RIL-026）：类型随指标而定；比率显式分子/分母。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleValue {
    /// 时延类样本（p50/p95 毫秒聚合）
    Latency {
        /// 中位时延
        p50_ms: u32,
        /// 95 分位时延
        p95_ms: u32,
    },
    /// 比率样本（分子/分母显式——分母 0 = 未知，不当零）
    Ratio {
        /// 分子（如失败次数/丢包次数）
        numerator: u32,
        /// 分母（如尝试次数/发送总数；0 表示无测量）
        denominator: u32,
    },
    /// 吞吐样本（Mbps；0 为显式测得的零吞吐，非缺失）
    Throughput {
        /// 吞吐值
        mbps: u32,
    },
}

impl SampleValue {
    /// 比率值：非比率样本或分母为 0（无测量）返回 None——调用方必须
    /// 把 None 当「未知」处理，不当零
    pub fn ratio(&self) -> Option<f64> {
        match self {
            SampleValue::Ratio {
                numerator,
                denominator,
            } if *denominator > 0 => Some(*numerator as f64 / *denominator as f64),
            _ => None,
        }
    }
}

/// 样本状态（RIL-026 验收「未知/过期不当零」）：取值前必须先判状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleStatus {
    /// 有效期内，可直接使用
    Current,
    /// 超过有效期——显式过期，不当零
    Expired {
        /// 超期毫秒数
        age_ms: u64,
    },
    /// 无有效测量（分母 0 或样本本身不成立）——显式未知，不当零
    Unknown,
}

/// 质量样本错误（RIL-026）：文案可演进，`code()` 恒定。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QualitySampleError {
    /// 样本超过有效期
    #[error("{CODE_QUALITY_EXPIRED}: 样本已过期 {age_ms}ms，不当零使用")]
    Expired {
        /// 超期毫秒数
        age_ms: u64,
    },
    /// 无有效测量（分母 0 / 非比率取值）
    #[error("{CODE_QUALITY_UNKNOWN}: 样本无有效测量值，不当零使用")]
    Unknown,
    /// 丢包样本缺测量对端说明
    #[error("{CODE_QUALITY_PEER_MISSING}: 丢包样本必须说明测量对端")]
    MissingPeer,
}

impl QualitySampleError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            QualitySampleError::Expired { .. } => CODE_QUALITY_EXPIRED,
            QualitySampleError::Unknown => CODE_QUALITY_UNKNOWN,
            QualitySampleError::MissingPeer => CODE_QUALITY_PEER_MISSING,
        }
    }
}

/// 类型化质量样本（RIL-026 / C25）：metric/source/target/count/time/
/// validity 全字段。构造入口只经 [`QualitySample::latency`] /
/// [`QualitySample::connection_failures`] / [`QualitySample::packet_loss`]
/// / [`QualitySample::throughput`] / [`QualitySample::migrate_legacy_loss`]——
/// 不实现 `Default`，杜绝「无测量默认 0.0」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualitySample {
    metric: QualityMetric,
    source: SampleSource,
    target: String,
    measured_peer: Option<String>,
    count: u32,
    observed_at_unix_ms: u64,
    lifetime_ms: u64,
    value: SampleValue,
}

impl QualitySample {
    /// 时延类样本（握手/RTT）
    #[allow(clippy::too_many_arguments)]
    pub fn latency(
        metric: QualityMetric,
        source: SampleSource,
        target: impl Into<String>,
        p50_ms: u32,
        p95_ms: u32,
        count: u32,
        observed_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Self {
        debug_assert!(
            matches!(metric, QualityMetric::HandshakeMs | QualityMetric::RttMs),
            "latency 构造只接受时延类指标"
        );
        Self {
            metric,
            source,
            target: target.into(),
            measured_peer: None,
            count,
            observed_at_unix_ms,
            lifetime_ms,
            value: SampleValue::Latency { p50_ms, p95_ms },
        }
    }

    /// 连接失败率样本（RIL-026 验收：连接失败率不再名为丢包率）——
    /// 拨号/探活失败次数与尝试次数显式携带；attempts = 0 视为未知样本。
    pub fn connection_failures(
        source: SampleSource,
        target: impl Into<String>,
        failed: u32,
        attempts: u32,
        observed_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Self {
        Self {
            metric: QualityMetric::ConnectionFailureRatio,
            source,
            target: target.into(),
            measured_peer: None,
            count: attempts,
            observed_at_unix_ms,
            lifetime_ms,
            value: SampleValue::Ratio {
                numerator: failed,
                denominator: attempts,
            },
        }
    }

    /// 真实丢包率样本（RIL-026 验收：真实丢包说明测量对端）——
    /// `measured_peer` 必填（为空返回 None），说明哪条链路对谁测量。
    pub fn packet_loss(
        measured_peer: impl Into<String>,
        target: impl Into<String>,
        lost: u32,
        total: u32,
        observed_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Option<Self> {
        let peer = measured_peer.into();
        if peer.is_empty() {
            return None;
        }
        Some(Self {
            metric: QualityMetric::PacketLossRatio,
            source: SampleSource::MeshLink,
            target: target.into(),
            measured_peer: Some(peer),
            count: total,
            observed_at_unix_ms,
            lifetime_ms,
            value: SampleValue::Ratio {
                numerator: lost,
                denominator: total,
            },
        })
    }

    /// 吞吐样本（Mbps；0 为显式测得的零吞吐）
    pub fn throughput(
        source: SampleSource,
        target: impl Into<String>,
        mbps: u32,
        count: u32,
        observed_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Self {
        Self {
            metric: QualityMetric::ThroughputMbps,
            source,
            target: target.into(),
            measured_peer: None,
            count,
            observed_at_unix_ms,
            lifetime_ms,
            value: SampleValue::Throughput { mbps },
        }
    }

    /// 当前指标迁移（RIL-026 验收）：旧口径的裸 `packet_loss_rate` f32
    /// 按测量来源改名迁移——拨号/探活来源是**连接失败率**（不再名为
    /// 丢包率）；Mesh 链路来源保留丢包率但**必须**说明测量对端（缺失
    /// 返回 [`QualitySampleError::MissingPeer`]，不猜语义）。比率以万分
    /// 比显式化（denominator = 10_000），未知来源拒绝。
    pub fn migrate_legacy_loss(
        legacy_packet_loss_rate: f32,
        measured_by: SampleSource,
        target: impl Into<String>,
        measured_peer: Option<String>,
        observed_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<Self, QualitySampleError> {
        let numerator = (legacy_packet_loss_rate.clamp(0.0, 1.0) * 10_000.0).round() as u32;
        match measured_by {
            SampleSource::DialOutcome | SampleSource::Probe => Ok(Self {
                metric: QualityMetric::ConnectionFailureRatio,
                source: measured_by,
                target: target.into(),
                measured_peer: None,
                count: 10_000,
                observed_at_unix_ms,
                lifetime_ms,
                value: SampleValue::Ratio {
                    numerator,
                    denominator: 10_000,
                },
            }),
            SampleSource::MeshLink => {
                let peer = measured_peer
                    .filter(|p| !p.is_empty())
                    .ok_or(QualitySampleError::MissingPeer)?;
                Ok(Self {
                    metric: QualityMetric::PacketLossRatio,
                    source: measured_by,
                    target: target.into(),
                    measured_peer: Some(peer),
                    count: 10_000,
                    observed_at_unix_ms,
                    lifetime_ms,
                    value: SampleValue::Ratio {
                        numerator,
                        denominator: 10_000,
                    },
                })
            }
            SampleSource::Manual => Err(QualitySampleError::Unknown),
        }
    }

    /// 指标类型
    pub fn metric(&self) -> QualityMetric {
        self.metric
    }

    /// 测量来源
    pub fn source(&self) -> SampleSource {
        self.source
    }

    /// 被测对象
    pub fn target(&self) -> &str {
        &self.target
    }

    /// 测量对端（丢包样本必带；其余为 None——缺失显式）
    pub fn measured_peer(&self) -> Option<&str> {
        self.measured_peer.as_deref()
    }

    /// 参与样本数
    pub fn count(&self) -> u32 {
        self.count
    }

    /// 观测时间（Unix 毫秒）
    pub fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// 有效期窗口（毫秒，自观测时刻起）
    pub fn lifetime_ms(&self) -> u64 {
        self.lifetime_ms
    }

    /// 原始样本值
    pub fn value(&self) -> &SampleValue {
        &self.value
    }

    /// 状态判定（RIL-026 验收「未知/过期不当零」）：超过有效期是显式
    /// 过期；比率分母为 0 是显式未知；都绝不表现为 0.0。
    pub fn status(&self, now_unix_ms: u64) -> SampleStatus {
        if let SampleValue::Ratio { denominator: 0, .. } = self.value {
            return SampleStatus::Unknown;
        }
        let observed = self.observed_at_unix_ms;
        if now_unix_ms < observed {
            // 时钟回拨按仍有效处理（不因时钟抖动丢弃样本）
            return SampleStatus::Current;
        }
        let age = now_unix_ms - observed;
        if age > self.lifetime_ms {
            SampleStatus::Expired {
                age_ms: age - self.lifetime_ms,
            }
        } else {
            SampleStatus::Current
        }
    }

    /// 比率取值（RIL-026 验收：不当零）：过期/未知显式报错，只有有效
    /// 期内且分母非零才返回值。
    pub fn ratio_value(&self, now_unix_ms: u64) -> Result<f64, QualitySampleError> {
        match self.status(now_unix_ms) {
            SampleStatus::Expired { age_ms } => Err(QualitySampleError::Expired { age_ms }),
            SampleStatus::Unknown => Err(QualitySampleError::Unknown),
            SampleStatus::Current => self.value.ratio().ok_or(QualitySampleError::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_000_000;
    const LIFETIME: u64 = 30_000;

    #[test]
    fn failure_ratio_is_its_own_metric_not_loss() {
        let sample = QualitySample::connection_failures(
            SampleSource::DialOutcome,
            "node-a",
            3,
            10,
            T0,
            LIFETIME,
        );
        assert_eq!(
            sample.metric().as_str(),
            "connection_failure_ratio",
            "连接失败率不再名为丢包率"
        );
        assert_eq!(sample.source().as_str(), "dial_outcome");
        assert_eq!(sample.target(), "node-a");
        assert_eq!(sample.count(), 10);
        assert_eq!(sample.ratio_value(T0).unwrap(), 0.3);
    }

    #[test]
    fn unknown_and_expired_not_zero() {
        // 分母 0（无测量）= 未知，不是 0.0
        let sample =
            QualitySample::connection_failures(SampleSource::Probe, "node-a", 0, 0, T0, LIFETIME);
        assert_eq!(sample.status(T0), SampleStatus::Unknown);
        assert_eq!(
            sample.ratio_value(T0).unwrap_err().code(),
            CODE_QUALITY_UNKNOWN
        );

        // 超期 = 显式过期，不是 0.0
        let sample =
            QualitySample::connection_failures(SampleSource::Probe, "node-a", 1, 4, T0, LIFETIME);
        assert_eq!(sample.status(T0).clone(), SampleStatus::Current);
        let late = T0 + LIFETIME + 5_000;
        match sample.status(late) {
            SampleStatus::Expired { age_ms } => assert_eq!(age_ms, 5_000),
            other => panic!("应为 Expired，实际 {other:?}"),
        }
        assert_eq!(
            sample.ratio_value(late).unwrap_err().code(),
            CODE_QUALITY_EXPIRED
        );

        // 有效期边界：恰好等于 lifetime 仍有效（age > lifetime 才过期）
        assert_eq!(sample.status(T0 + LIFETIME), SampleStatus::Current);

        // 非比率样本取比率 = 未知
        let latency = QualitySample::latency(
            QualityMetric::RttMs,
            SampleSource::Probe,
            "node-a",
            42,
            80,
            9,
            T0,
            LIFETIME,
        );
        assert_eq!(
            latency.ratio_value(T0).unwrap_err().code(),
            CODE_QUALITY_UNKNOWN
        );
        assert_eq!(
            latency.value(),
            &SampleValue::Latency {
                p50_ms: 42,
                p95_ms: 80
            }
        );
    }

    #[test]
    fn real_packet_loss_states_measured_peer() {
        // 缺测量对端：构造直接拒绝
        assert!(QualitySample::packet_loss("", "node-a", 1, 100, T0, LIFETIME).is_none());

        // 带对端：样本说明对谁测的
        let sample =
            QualitySample::packet_loss("mesh-peer-7", "node-a", 1, 100, T0, LIFETIME).unwrap();
        assert_eq!(sample.metric().as_str(), "packet_loss_ratio");
        assert_eq!(sample.measured_peer(), Some("mesh-peer-7"));
        assert_eq!(sample.ratio_value(T0).unwrap(), 0.01);
    }

    #[test]
    fn legacy_loss_migrates_by_source() {
        // 拨号来源的旧 packet_loss_rate → 连接失败率（改名迁移）
        let migrated = QualitySample::migrate_legacy_loss(
            0.25,
            SampleSource::DialOutcome,
            "node-a",
            None,
            T0,
            LIFETIME,
        )
        .unwrap();
        assert_eq!(
            migrated.metric().as_str(),
            "connection_failure_ratio",
            "拨号失败率迁移后不再名为丢包率"
        );
        assert_eq!(migrated.ratio_value(T0).unwrap(), 0.25);

        // 探活来源同理
        let migrated = QualitySample::migrate_legacy_loss(
            0.1,
            SampleSource::Probe,
            "node-b",
            None,
            T0,
            LIFETIME,
        )
        .unwrap();
        assert_eq!(migrated.metric().as_str(), "connection_failure_ratio");

        // Mesh 链路来源保留丢包率，但必须说明测量对端
        let migrated = QualitySample::migrate_legacy_loss(
            0.02,
            SampleSource::MeshLink,
            "node-c",
            None,
            T0,
            LIFETIME,
        );
        assert_eq!(
            migrated.unwrap_err().code(),
            CODE_QUALITY_PEER_MISSING,
            "真实丢包必须说明测量对端"
        );
        let migrated = QualitySample::migrate_legacy_loss(
            0.02,
            SampleSource::MeshLink,
            "node-c",
            Some("mesh-peer-3".to_string()),
            T0,
            LIFETIME,
        )
        .unwrap();
        assert_eq!(migrated.metric().as_str(), "packet_loss_ratio");
        assert_eq!(migrated.measured_peer(), Some("mesh-peer-3"));

        // 越界值收敛到 [0,1]
        let migrated = QualitySample::migrate_legacy_loss(
            7.5,
            SampleSource::DialOutcome,
            "node-d",
            None,
            T0,
            LIFETIME,
        )
        .unwrap();
        assert_eq!(migrated.ratio_value(T0).unwrap(), 1.0);

        // 未知来源拒绝（不猜语义）
        assert_eq!(
            QualitySample::migrate_legacy_loss(0.1, SampleSource::Manual, "x", None, T0, LIFETIME)
                .unwrap_err()
                .code(),
            CODE_QUALITY_UNKNOWN
        );
    }

    #[test]
    fn throughput_zero_is_explicit_measurement_not_missing() {
        // 吞吐 0 是显式测得（与「未知」区分）；状态仍按有效期判定
        let sample = QualitySample::throughput(SampleSource::Probe, "node-a", 0, 1, T0, LIFETIME);
        assert_eq!(sample.status(T0), SampleStatus::Current);
        assert_eq!(sample.metric().as_str(), "throughput_mbps");
        assert_eq!(sample.value(), &SampleValue::Throughput { mbps: 0 });
    }
}
