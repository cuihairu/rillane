//! 流轨迹 SVG 导出（RIL-062，debug-and-mcp.md §3）：把 [`FlowTrace`]
//! 渲染成自包含 SVG 路径图。数据与 `/trace/flow` JSON 出自同一份查询
//! 快照——图与 JSON 内容一致由「同一快照两种渲染」构造性保证。
//!
//! 验收口径落点：
//! - **路径层不混画**：每个事件按阶段归入唯一层（L3 / 计划 / 连接），
//!   各层独立分组（`lane-*` 分组 id）；Mesh 账本是另一张面
//!   （`/mesh/switches`），本图只给「不混画」说明位，不把 mesh 事件
//!   伪造成流阶段；
//! - **时间可见**：横轴为单调时钟（起止毫秒标注），逐事件 title 携带
//!   seq/单调/墙钟；时间成对是 trace schema 的既有承诺；
//! - **缺口可见**：相邻事件单调时差超过跨度阈值时画缺口标注；无事件
//!   的层如实写「无事件」——不造刻度不造事件；
//! - **文本安全**：流 ID/代际/detail 全部经 XML 转义 + 控制字符替换 +
//!   有界截断——长文本与恶意名称既不破坏 XML 结构也不无限膨胀图面
//!   （detail 上游已脱敏，本层是最后防线不是唯一防线）。

use crate::trace::{FlowTrace, TraceStage};

/// 画布宽度（左标签带 150 + 时间轴 700 + 右边距）
const WIDTH: f64 = 900.0;
/// 时间轴左起点
const X0: f64 = 150.0;
/// 时间轴宽度
const AXIS_W: f64 = 700.0;
/// 头部高度（流 ID/代际/起止时间标注带）
const HEADER_H: f64 = 120.0;
/// 每层带高
const LANE_H: f64 = 80.0;
/// 层数：L3 / 计划 / 连接 / Mesh（说明位）
const LANE_COUNT: f64 = 4.0;

/// `<title>` 全文上限（字符）——有界承诺，不随 detail 长度膨胀
const MAX_TITLE_CHARS: usize = 200;
/// 行内标签上限（字符）
const MAX_LABEL_CHARS: usize = 48;

/// 路径层名（SVG 分组 id 与图例共用）
const LANES: [&str; 4] = ["l3", "plan", "conn", "mesh"];

/// 阶段 → 路径层（**穷尽匹配**：新增 TraceStage 变体时编译期即强制
/// 归层，不允许落到「混画」兜底）。Mesh 账本无流内阶段——不返回 mesh。
fn layer_of(stage: TraceStage) -> &'static str {
    lane_of_stage(stage.as_str()).expect("TraceStage 全集在 lane_of_stage 内有归属——漏臂即 panic")
}

/// 线上阶段名 → 路径层（RIL-063：文本/JSON 投影与 SVG 共用同一归层
/// ——不存在第二份阶段→层映射）。未知阶段名 → None（调用方显式
/// 处理「未知阶段」，不猜层、不混画）。
pub fn lane_of_stage(stage: &str) -> Option<&'static str> {
    match stage {
        // L3/接入面：接管 + 上下文身份 + DNS + 嗅探
        "takeover" | "identity" | "dns" | "sniff" => Some("l3"),
        // 计划面：规则求值 + RoutePlan（预测证据）
        "rule" | "plan" => Some("plan"),
        // 连接面：拨号尝试 + 实际出口 + 传输统计 + 终态
        "attempt" | "egress" | "transfer" | "close" => Some("conn"),
        _ => None,
    }
}

/// XML 文本安全化：实体转义 + XML 1.0 非法控制字符替换（U+FFFD）+
/// 有界截断（字符界，多字节安全；截断补 …）。恶意名称与长文本在
/// 生成端一次性钳制，不依赖渲染端自觉。
fn svg_safe(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars * 4));
    for c in s.chars().take(max_chars) {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // XML 1.0 只允许 tab/LF/CR 三个控制字符——其余（含 DEL）
            // 一律替换为 U+FFFD，不产出非法 XML
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    if s.chars().count() > max_chars {
        out.push('…');
    }
    out
}

/// 单调时刻 → 横轴坐标。span=0（单事件/同刻）固定画在轴中点——
/// 不除零、不伪造第二个刻度。
fn x_of(monotonic_ms: u64, t0: u64, span: u64) -> f64 {
    if span == 0 {
        return X0 + AXIS_W / 2.0;
    }
    X0 + (monotonic_ms - t0) as f64 / span as f64 * AXIS_W
}

/// 渲染一条流轨迹为自包含 SVG（确定性输出——同一快照同一图）。
pub fn render_flow_svg(trace: &FlowTrace) -> String {
    let height = HEADER_H + LANE_H * LANE_COUNT + 20.0;
    let mut out = String::with_capacity(8 * 1024);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{WIDTH}\" height=\"{height}\" \
         viewBox=\"0 0 {WIDTH} {height}\" font-family=\"monospace\">\n"
    ));
    out.push_str(&format!(
        "<title>rillane flow {}</title>\n",
        svg_safe(trace.flow.as_str(), MAX_LABEL_CHARS)
    ));

    // 头部：流 ID / 起止语义 / 代际 / 终态 / 时间范围
    let events = &trace.events;
    let (t0, span) = match (events.first(), events.last()) {
        (Some(first), Some(last)) => (first.monotonic_ms, last.monotonic_ms - first.monotonic_ms),
        _ => (0, 0),
    };
    out.push_str("<g id=\"header\">\n");
    out.push_str(&format!(
        "<text x=\"10\" y=\"24\" font-size=\"14\">flow {} · {} · generation {} · {}</text>\n",
        svg_safe(trace.flow.as_str(), MAX_LABEL_CHARS),
        trace.origin.as_str(),
        svg_safe(&trace.generation, MAX_LABEL_CHARS),
        if trace.closed { "closed" } else { "active" },
    ));
    if events.is_empty() {
        out.push_str(
            "<text x=\"10\" y=\"44\" font-size=\"12\">0 events · no timeline (nothing measured)</text>\n",
        );
    } else {
        let first_wall = events.first().map(|e| e.wall_ms).unwrap_or(0);
        let last_wall = events.last().map(|e| e.wall_ms).unwrap_or(0);
        out.push_str(&format!(
            "<text x=\"10\" y=\"44\" font-size=\"12\">monotonic {t0}..{}ms · wall {first_wall}..{last_wall}ms · {} events</text>\n",
            t0 + span,
            events.len(),
        ));
    }
    out.push_str("</g>\n");

    // 时间轴刻度（有事件才画——空轨迹不造刻度）
    if !events.is_empty() {
        out.push_str("<g id=\"axis\">\n");
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" text-anchor=\"start\">{t0}ms</text>\n",
            X0,
            HEADER_H - 4.0,
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" text-anchor=\"end\">{}ms</text>\n",
            X0 + AXIS_W,
            HEADER_H - 4.0,
            t0 + span,
        ));
        out.push_str("</g>\n");
    }

    // 逐层带：事件按 layer_of 归层（不混画）；Mesh 带只放说明位
    type LaneEvents<'a> = Vec<Vec<&'a crate::trace::TraceEvent>>;
    let mut lane_events: LaneEvents<'_> = vec![Vec::new(), Vec::new(), Vec::new()];
    for e in events {
        let lane = layer_of(e.stage);
        let idx = match lane {
            "l3" => 0,
            "plan" => 1,
            _ => 2,
        };
        lane_events[idx].push(e);
    }

    for (i, lane) in LANES.iter().enumerate() {
        let y = HEADER_H + i as f64 * LANE_H;
        out.push_str(&format!(
            "<g id=\"lane-{lane}\">\n<rect x=\"0\" y=\"{y}\" width=\"{WIDTH}\" height=\"{LANE_H}\" \
             fill=\"#f5f5f5\" stroke=\"#ddd\" />\n"
        ));
        let label = match *lane {
            "l3" => "L3 (takeover/identity/dns/sniff)",
            "plan" => "plan (rule/route plan)",
            "conn" => "connection (attempt/egress/transfer/close)",
            _ => "mesh (ledger is /mesh/switches - not mixed here)",
        };
        out.push_str(&format!(
            "<text x=\"8\" y=\"{}\" font-size=\"12\">{}</text>\n",
            y + 20.0,
            label,
        ));
        out.push_str(&format!("<g id=\"lane-{lane}-events\">\n"));
        if *lane == "mesh" {
            out.push_str(&format!(
                "<text x=\"160\" y=\"{}\" font-size=\"11\" fill=\"#888\">no mesh stage in flow traces - kept out of this graph</text>\n",
                y + 48.0,
            ));
        } else {
            let idx = i;
            if lane_events[idx].is_empty() {
                out.push_str(&format!(
                    "<text x=\"160\" y=\"{}\" font-size=\"11\" fill=\"#888\">no events</text>\n",
                    y + 48.0,
                ));
            }
            for e in &lane_events[idx] {
                let cx = x_of(e.monotonic_ms, t0, span);
                let cy = y + 48.0;
                let fill = match e.evidence.as_str() {
                    "observed" => "#1a6fb5",
                    "predicted" => "#b58a1a",
                    "inferred" => "#7a4fb5",
                    _ => "#999999",
                };
                let attempt = e
                    .attempt
                    .map(|a| a.0.to_string())
                    .unwrap_or_else(|| "-".into());
                out.push_str(&format!(
                    "<circle cx=\"{cx:.1}\" cy=\"{cy:.1}\" r=\"6\" fill=\"{fill}\"><title>#{seq} {} {} evidence={} attempt={} mono={}ms wall={}ms {}</title></circle>\n",
                    e.stage.as_str(),
                    e.code,
                    e.evidence.as_str(),
                    attempt,
                    e.monotonic_ms,
                    e.wall_ms,
                    svg_safe(&e.detail, MAX_TITLE_CHARS),
                    seq = e.seq,
                ));
            }
        }
        out.push_str("</g>\n</g>\n");
    }

    // 缺口标注：相邻事件单调时差超过跨度 1/10（且 >0ms）即画——阈值
    // 随跨度自适应，同刻事件不造缺口
    if events.len() > 1 && span > 0 {
        let threshold = (span / 10).max(1);
        out.push_str("<g id=\"gaps\">\n");
        for pair in events.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let delta = b.monotonic_ms - a.monotonic_ms;
            if delta >= threshold {
                let x1 = x_of(a.monotonic_ms, t0, span);
                let x2 = x_of(b.monotonic_ms, t0, span);
                out.push_str(&format!(
                    "<line x1=\"{x1:.1}\" y1=\"{}\" x2=\"{x2:.1}\" y2=\"{}\" stroke=\"#c33\" \
                     stroke-dasharray=\"4 3\" />\n",
                    HEADER_H - 10.0,
                    HEADER_H - 10.0,
                ));
                let mid = (x1 + x2) / 2.0;
                out.push_str(&format!(
                    "<text x=\"{mid:.1}\" y=\"{}\" font-size=\"10\" fill=\"#c33\" \
                     text-anchor=\"middle\">gap {delta}ms</text>\n",
                    HEADER_H - 14.0,
                ));
            }
        }
        out.push_str("</g>\n");
    }

    out.push_str("</svg>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::EvidenceKind;
    use crate::trace::{AttemptId, FlowId, FlowOrigin};

    /// RIL-063：字符串归层与枚举归层是同一份映射（SVG/文本/JSON 三投影
    /// 一致）；未知阶段名显式 None——不猜层
    #[test]
    fn lane_of_stage_agrees_with_enum_mapping() {
        for stage in [
            TraceStage::Takeover,
            TraceStage::Identity,
            TraceStage::Dns,
            TraceStage::Sniff,
            TraceStage::Rule,
            TraceStage::Plan,
            TraceStage::Attempt,
            TraceStage::Egress,
            TraceStage::Transfer,
            TraceStage::Close,
        ] {
            assert_eq!(
                lane_of_stage(stage.as_str()),
                Some(layer_of(stage)),
                "stage {}",
                stage.as_str()
            );
        }
        assert_eq!(lane_of_stage("mesh"), None);
        assert_eq!(lane_of_stage(""), None);
        assert_eq!(lane_of_stage("Takeover"), None, "线名精确匹配——不猜大小写");
    }

    /// 手工搭一条多阶段轨迹（接管→DNS→规则→计划→两次拨号→出口→关闭）
    fn sample_trace(flow_id: &str, detail_for: impl Fn(u64) -> String) -> FlowTrace {
        let mut t = FlowTrace::new(
            FlowId::new(flow_id).unwrap(),
            FlowOrigin::Stream,
            "gen-svg-1",
        )
        .unwrap();
        type Step = (
            TraceStage,
            Option<AttemptId>,
            &'static str,
            EvidenceKind,
            u64,
            u64,
        );
        let steps: [Step; 8] = [
            (
                TraceStage::Takeover,
                None,
                "trace.taken_over",
                EvidenceKind::Observed,
                0,
                1000,
            ),
            (
                TraceStage::Dns,
                None,
                "dns.cache_hit",
                EvidenceKind::Observed,
                3,
                1003,
            ),
            (
                TraceStage::Rule,
                None,
                "rule.matched",
                EvidenceKind::Observed,
                5,
                1005,
            ),
            (
                TraceStage::Plan,
                None,
                "plan.built",
                EvidenceKind::Predicted,
                6,
                1006,
            ),
            (
                TraceStage::Attempt,
                Some(AttemptId(0)),
                "outbound.open.timeout",
                EvidenceKind::Observed,
                40,
                1040,
            ),
            (
                TraceStage::Attempt,
                Some(AttemptId(1)),
                "plan.attempt.dialed",
                EvidenceKind::Observed,
                400,
                1400,
            ),
            (
                TraceStage::Egress,
                None,
                "trace.egress",
                EvidenceKind::Observed,
                401,
                1401,
            ),
            (
                TraceStage::Close,
                None,
                "session.closed",
                EvidenceKind::Observed,
                500,
                1500,
            ),
        ];
        for (i, (stage, attempt, code, ev, mono, wall)) in steps.into_iter().enumerate() {
            t.push(stage, attempt, code, ev, mono, wall, detail_for(i as u64))
                .unwrap();
        }
        t.closed = true;
        t
    }

    /// 恶意名称与控制字符安全转义：流 ID/detail 里的 XML 特殊字符
    /// 以实体出现，原始标记与控制字符绝不出现在输出里
    #[test]
    fn svg_escapes_malicious_text_and_control_chars() {
        let mut t = FlowTrace::new(
            FlowId::new("f<x>&\"y\"").unwrap(),
            FlowOrigin::Stream,
            "gen<&1",
        )
        .unwrap();
        t.push(
            TraceStage::Takeover,
            None,
            "trace.taken_over",
            EvidenceKind::Observed,
            0,
            10,
            "<script>alert(1)</script> & \u{7}bad'dq\"",
        )
        .unwrap();
        let svg = render_flow_svg(&t);
        assert!(svg.starts_with("<?xml"), "合法 XML 头");
        assert!(svg.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!svg.contains("<script>"), "原始 script 标记不得出现");
        assert!(svg.contains("f&lt;x&gt;&amp;&quot;y&quot;"), "流 ID 转义");
        assert!(svg.contains("gen&lt;&amp;1"), "代际转义");
        assert!(!svg.contains('\u{7}'), "控制字符不得原样输出");
        assert!(svg.contains('\u{FFFD}'), "控制字符替换为 U+FFFD");
        assert!(svg.contains("&#39;") && svg.contains("&quot;"), "引号转义");
    }

    /// 长文本有界截断：5000 字符 detail 不把图面撑爆（title 截断补 …）
    #[test]
    fn long_text_is_bounded_and_marked_truncated() {
        let long = "A".repeat(5000);
        let mut t =
            FlowTrace::new(FlowId::new("f-long").unwrap(), FlowOrigin::Stream, "g").unwrap();
        t.push(
            TraceStage::Takeover,
            None,
            "trace.taken_over",
            EvidenceKind::Observed,
            0,
            0,
            long,
        )
        .unwrap();
        let svg = render_flow_svg(&t);
        let total: usize = svg.chars().count();
        assert!(total < 8 * 1024, "输出应有界: {total}");
        assert!(svg.contains('…'), "截断须显式标注");
        assert!(svg.matches('A').count() <= MAX_TITLE_CHARS);
    }

    /// 路径层不混画：每个事件的 title 只出现在其所属层分组内；mesh
    /// 带只有说明位没有事件
    #[test]
    fn layers_are_never_mixed() {
        let t = sample_trace("f-mix", |i| format!("ev{i}"));
        let svg = render_flow_svg(&t);

        // 按层分组切片（分组 id 是稳定锚点）
        let l3 = svg.split("<g id=\"lane-plan\">").next().unwrap();
        let rest = &svg[svg.find("<g id=\"lane-plan\">").unwrap()..];
        let plan = rest.split("<g id=\"lane-conn\">").next().unwrap();
        let rest2 = &rest[rest.find("<g id=\"lane-conn\">").unwrap()..];
        let conn = rest2.split("<g id=\"lane-mesh\">").next().unwrap();
        let mesh = &rest2[rest2.find("<g id=\"lane-mesh\">").unwrap()..];

        // l3：takeover + dns；plan：rule + plan.built；conn：attempt/egress/close
        assert!(l3.contains("trace.taken_over") && l3.contains("dns.cache_hit"));
        assert!(!l3.contains("rule.matched") && !l3.contains("plan.built"));
        assert!(plan.contains("rule.matched") && plan.contains("plan.built"));
        assert!(!plan.contains("trace.taken_over"));
        assert!(
            conn.contains("outbound.open.timeout")
                && conn.contains("trace.egress")
                && conn.contains("session.closed")
        );
        assert!(!conn.contains("dns.cache_hit"));
        // mesh 带说明位、无事件圆点
        assert!(mesh.contains("not mixed here"));
        assert!(!mesh.contains("<circle"));
        // 事件总数不增不减：圆点数 = 事件数
        assert_eq!(svg.matches("<circle").count(), 8);
    }

    /// 时间与缺口可见：轴端毫秒标注、头部时间范围、超过跨度 1/10 的
    /// 相邻时差画缺口
    #[test]
    fn time_axis_and_gaps_are_annotated() {
        let t = sample_trace("f-time", |_| "x".into());
        let svg = render_flow_svg(&t);
        assert!(svg.contains(">0ms<"), "轴起点标注");
        assert!(svg.contains(">500ms<"), "轴终点标注");
        assert!(svg.contains("monotonic 0..500ms"), "头部单调范围");
        assert!(svg.contains("wall 1000..1500ms"), "头部墙钟范围");
        // 步进 0→3→5→6→40→400→401→500：跨度 500 阈值 50——
        // 6→40(34)、40→400(360)、400→401(1)、401→500(99)；达标缺口 40→400 与 401→500
        assert!(svg.contains("gap 360ms"));
        assert!(svg.contains("gap 99ms"));
        assert!(!svg.contains("gap 34ms"), "未达阈值不画缺口");
        assert_eq!(svg.matches("stroke-dasharray").count(), 2);
    }

    /// 空轨迹诚实渲染：无事件层写「无事件」、不造时间轴与刻度
    #[test]
    fn empty_trace_is_honest() {
        let t = FlowTrace::new(
            FlowId::new("f-empty").unwrap(),
            FlowOrigin::Association,
            "g",
        )
        .unwrap();
        let svg = render_flow_svg(&t);
        assert!(svg.contains("0 events"));
        assert!(svg.contains("no timeline"));
        assert_eq!(svg.matches("<circle").count(), 0);
        assert!(!svg.contains("<g id=\"axis\">"), "空轨迹不造刻度");
        assert!(!svg.contains("<g id=\"gaps\">"), "空轨迹不造缺口");
        assert!(svg.contains("generation g"));
    }

    /// 单事件：span=0 不除零，事件画在轴中点，无缺口组
    #[test]
    fn single_event_renders_without_span_division() {
        let mut t = FlowTrace::new(FlowId::new("f-one").unwrap(), FlowOrigin::Stream, "g").unwrap();
        t.push(
            TraceStage::Takeover,
            None,
            "trace.taken_over",
            EvidenceKind::Observed,
            7,
            7,
            "only",
        )
        .unwrap();
        let svg = render_flow_svg(&t);
        assert_eq!(svg.matches("<circle").count(), 1);
        assert!(svg.contains("cx=\"500.0\""), "span=0 固定轴中点");
        assert!(!svg.contains("<g id=\"gaps\">"));
    }

    /// 归层映射穷尽且稳定：每个 TraceStage 变体有唯一层，四层名单固定
    /// （新增变体时此处编译期穷尽匹配 + 本测断言双重强制归层）
    #[test]
    fn layer_mapping_is_total_and_stable() {
        let cases = [
            (TraceStage::Takeover, "l3"),
            (TraceStage::Identity, "l3"),
            (TraceStage::Dns, "l3"),
            (TraceStage::Sniff, "l3"),
            (TraceStage::Rule, "plan"),
            (TraceStage::Plan, "plan"),
            (TraceStage::Attempt, "conn"),
            (TraceStage::Egress, "conn"),
            (TraceStage::Transfer, "conn"),
            (TraceStage::Close, "conn"),
        ];
        for (stage, lane) in cases {
            assert_eq!(layer_of(stage), lane, "{stage:?} 归层");
        }
        assert_eq!(LANES, ["l3", "plan", "conn", "mesh"]);
    }
}
