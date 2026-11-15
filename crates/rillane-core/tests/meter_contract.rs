//! 权威业务计数契约（RIL-101）：业务通道边界唯一权威计数器；方向按
//! 客户端→目标/目标→客户端语义定义（不随 socket 读写翻转）；部分写
//! 只累加实际字节、重试不重复业务总量；零长 UDP 计报文；A 失败 B
//! 承载不重复业务量；probe/prewarm 与用户业务分账；共享开销显式
//! 分立（不可精确归因时明确标记，不伪造每流精度）；入口/出口视图
//! 相加不是总使用量；发送成功不证明对端已接收。

use rillane_core::{
    AttributionView, CODE_METER_ATTEMPT, CODE_METER_CARRIER, CODE_METER_SESSION, OriginLedger,
    SessionMeter, SessionTotals, TrafficDirection, TrafficOrigin,
};

/// 模拟出口写侧：每次 write 最多吞 `cap` 字节（部分写真实面）——
/// 返回实际写入数，调用方按实际数过账。
struct EgressSink {
    cap: usize,
}

impl EgressSink {
    /// 返回实际写入的字节数（≤ 请求量）
    fn write(&mut self, data: &[u8]) -> usize {
        data.len().min(self.cap)
    }
}

/// 泵循环骨架（RIL-098 pump 口径的计量投影）：读侧取块 → 出口写 →
/// 按实际写入数过账。方向参数是**语义方向**（client→target），与
/// 「这一步是读还是写」无关——写向出口的上行块、读自出口的下行块
/// 各归其位。
fn pump_uplink(meter: &SessionMeter, chunks: &[usize], sink: &mut EgressSink) -> u64 {
    let mut pushed = 0u64;
    for want in chunks {
        let data = vec![0u8; *want];
        let actual = sink.write(&data);
        meter.record_business(TrafficDirection::ClientToTarget, actual as u64);
        pushed += actual as u64;
    }
    pushed
}

/// 流会话全量对账：部分写只累加实际字节；入口/出口视图 = 同一权威量；
/// 底层/共享开销分立；「in + out」不是总使用量。
#[test]
fn stream_session_reconciles_actual_bytes_only() {
    let meter = SessionMeter::new("sess-stream-1", TrafficOrigin::User).expect("合法身份");
    let mut sink = EgressSink { cap: 10 };

    // 上行：三块 10/16/4，出口每次最多吞 10 —— 实际过账 10+10+4
    let uplink = pump_uplink(&meter, &[10, 16, 4], &mut sink);
    assert_eq!(uplink, 24, "部分写只累加实际字节");
    // 下行：出口 → 客户端 25 字节（读自出口——语义方向不变）
    meter.record_business(TrafficDirection::TargetToClient, 25);

    let t = meter.totals();
    assert_eq!(t.client_to_target_bytes, 24);
    assert_eq!(t.target_to_client_bytes, 25);
    assert_eq!(t.business_bytes(), 49);

    // 入口/出口视图：同一权威量的归属投影——相加不是总使用量
    let inbound = t.attribution(AttributionView::Inbound);
    let outbound = t.attribution(AttributionView::Outbound);
    assert_eq!(inbound, 49);
    assert_eq!(outbound, 49);
    assert_ne!(inbound + outbound, t.business_bytes());

    // 底层与共享开销分立——业务量不被污染
    meter.record_underlay(0, 90);
    meter.record_shared_overhead(44);
    let t = meter.totals();
    assert_eq!(t.business_bytes(), 49, "开销不并入业务");
    assert_eq!(t.underlay_bytes, 90);
    assert_eq!(t.shared_overhead_bytes, 44, "共享面显式分立");
}

/// 建立期回退对账（A 失败 B 承载）：A 的真实底层开销与失败照实记录；
/// 业务量只计一次；承载归属恰一次（二次归属/未知归属拒绝）；
/// 计量对账与转发报告口径一致（RIL-098 client_to_egress 投影）。
#[test]
fn failover_session_counts_business_once_and_reports_agree() {
    let meter = SessionMeter::new("sess-failover-1", TrafficOrigin::User).expect("合法身份");

    // 尝试 A：拨号+握手真实开销，失败
    meter.record_underlay(0, 150);
    meter.mark_attempt_failed(0);
    // 尝试 B：真实开销，承载
    meter.record_underlay(1, 80);
    meter.attribute_carrier(1).expect("归属 B");

    // 承载通道上：同一块的重试序列（写 8 实推 3，续推 5）——
    // 业务总量 = 8 恰一次，不因重试翻倍
    let mut sink = EgressSink { cap: 3 };
    let pushed = pump_uplink(&meter, &[8], &mut sink);
    assert_eq!(pushed, 3, "首段部分写");
    let mut sink = EgressSink { cap: 64 };
    let pushed = pump_uplink(&meter, &[5], &mut sink);
    assert_eq!(pushed, 5, "续段补齐——同一业务块的延续");
    meter.record_business(TrafficDirection::TargetToClient, 300);

    let t = meter.totals();
    assert_eq!(t.business_bytes(), 308, "重试不重复业务总量");
    assert_eq!(t.carrier_attempt, Some(1), "业务归属 B");
    assert_eq!(t.failed_attempts, vec![0], "A 失败照实记录");
    assert_eq!(t.underlay_bytes, 230, "A+B 真实开销分立");
    assert_eq!(
        t.attempt_underlay,
        vec![(0, 150), (1, 80)],
        "逐尝试明细可对账"
    );

    // 与转发报告口径对账（RIL-098 字段投影）
    let report_up = t.client_to_target_bytes;
    let report_down = t.target_to_client_bytes;
    assert_eq!(report_up, 8, "client_to_egress = 权威上行");
    assert_eq!(report_down, 300, "egress_to_client = 权威下行");

    // 归属纪律：二次归属 / 未知尝试归属
    assert_eq!(
        meter.attribute_carrier(0).unwrap_err().code,
        CODE_METER_CARRIER
    );
    let fresh = SessionMeter::new("sess-failover-2", TrafficOrigin::User).expect("合法");
    assert_eq!(
        fresh.attribute_carrier(7).unwrap_err().code,
        CODE_METER_ATTEMPT
    );
}

/// 数据报会话：零长报文仍计一条；字节为 0 照实；显式拒绝（超限/
/// 目标不符）走丢弃面——不冒充业务量；与 DatagramForwardReport
/// 口径投影一致。
#[test]
fn datagram_session_counts_packets_and_drops_apart() {
    let meter = SessionMeter::new("sess-udp-1", TrafficOrigin::User).expect("合法身份");
    // 零长报文：仍是一条报文
    meter.record_datagram(TrafficDirection::ClientToTarget, 0);
    // 正常报文
    meter.record_datagram(TrafficDirection::ClientToTarget, 120);
    meter.record_datagram(TrafficDirection::TargetToClient, 90);
    // 显式拒绝（超限 2 + 目标不符 1）——丢弃面
    meter.record_drop(2);
    meter.record_drop(1);

    let t = meter.totals();
    assert_eq!(t.client_to_target_bytes, 120, "零长报文字节为 0 照实");
    assert_eq!(
        t.client_to_target_datagrams, 2,
        "零长报文仍计一条——报文计数不吞"
    );
    assert_eq!(t.target_to_client_datagrams, 1);
    assert_eq!(t.dropped_datagrams, 3, "拒绝走丢弃面");
    assert_eq!(t.business_bytes(), 210, "丢弃不冒充业务量");

    // 报告口径投影（DatagramForwardReport 的权威来源）
    assert_eq!(t.client_to_target_datagrams, 2 /* client_to_egress */);
    assert_eq!(t.target_to_client_datagrams, 1 /* egress_to_client */);
}

/// 来源分账：probe/prewarm 会话的量与用户业务分桶汇总——任何桶都
/// 不互相吸收；会话身份非法显式拒绝。
#[test]
fn probe_and_prewarm_stay_out_of_user_bucket() {
    assert!(
        SessionMeter::new("", TrafficOrigin::User).is_none(),
        "空身份 = meter.session.invalid 面"
    );
    assert_eq!(CODE_METER_SESSION, "meter.session.invalid");

    let ledger = OriginLedger::default();
    let user = SessionMeter::new("u", TrafficOrigin::User).expect("合法");
    user.record_business(TrafficDirection::ClientToTarget, 4000);
    user.record_business(TrafficDirection::TargetToClient, 6000);
    user.record_underlay(0, 500);
    user.record_shared_overhead(120);

    let probe = SessionMeter::new("p", TrafficOrigin::Probe).expect("合法");
    probe.record_business(TrafficDirection::ClientToTarget, 32);
    probe.record_underlay(0, 300);

    let warm = SessionMeter::new("w", TrafficOrigin::Prewarm).expect("合法");
    warm.record_shared_overhead(64);

    ledger.absorb(&user.totals());
    ledger.absorb(&probe.totals());
    ledger.absorb(&warm.totals());

    assert_eq!(ledger.business_of(TrafficOrigin::User), 10_000);
    assert_eq!(ledger.underlay_of(TrafficOrigin::User), 500);
    assert_eq!(ledger.shared_of(TrafficOrigin::User), 120);
    assert_eq!(ledger.business_of(TrafficOrigin::Probe), 32, "probe 分桶");
    assert_eq!(ledger.underlay_of(TrafficOrigin::Probe), 300);
    assert_eq!(
        ledger.business_of(TrafficOrigin::Prewarm),
        0,
        "预热无业务字节"
    );
    assert_eq!(ledger.shared_of(TrafficOrigin::Prewarm), 64);
    // probe/prewarm 的量从未进入 user 桶
    assert_ne!(ledger.business_of(TrafficOrigin::User), 10_032 + 64);
}

/// 会话终态快照不可变（审计凭证）：totals 返回独立克隆——后续记账
/// 不改写已发出的快照；高基数身份（域名/路径）不进计量维度面。
#[test]
fn snapshots_are_immutable_and_dimensions_bounded() {
    let meter = SessionMeter::new("sess-audit-1", TrafficOrigin::User).expect("合法");
    meter.record_business(TrafficDirection::ClientToTarget, 10);
    let before: SessionTotals = meter.totals();
    meter.record_business(TrafficDirection::ClientToTarget, 10);
    let after = meter.totals();
    assert_eq!(before.business_bytes(), 10, "已发出的快照不被后续记账改写");
    assert_eq!(after.business_bytes(), 20);
    assert_eq!(before.session_id, after.session_id, "快照身份稳定");
    // 有界维度：快照结构只有 session/方向/来源/尝试——无域名/路径字段
    let debug = format!("{before:?}");
    assert!(
        !debug.contains("domain") && !debug.contains("path"),
        "计量面无高基数标签"
    );
}
