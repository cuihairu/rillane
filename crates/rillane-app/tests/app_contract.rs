//! 操作集边界契约（RIL-065）：穷尽匹配钉住闭合操作集——每个操作映射
//! 恰一个固定 (method, path)；新增操作必须在此登记（漏臂编译失败），
//! 未经登记的路径无构造入口。形状断言钉参数名/消毒/体形——执行器与
//! 表面不得偏离。

use rillane_app::ops::{
    AppOperation, FlowEventsParams, FlowListFilter, Method, OriginFilter, ProbeJobSpec, StateFilter,
};
use rillane_core::redact::sanitize_untrusted;
use rillane_routing::{DomainSource, ExplainInput};
use std::collections::BTreeMap;

/// 穷尽映射（无通配臂）：操作 → 线上 (method, path)。这里是边界的
/// 审查名单——扩充操作集时此表必须显式回答「新操作打到哪条路径」。
fn wire_of(op: &AppOperation) -> (Method, &'static str) {
    match op {
        AppOperation::RuntimeStats => (Method::Get, "/runtime/stats"),
        AppOperation::RoutingQuality => (Method::Get, "/routing/stats"),
        AppOperation::FlowList(_) => (Method::Get, "/trace/flows"),
        AppOperation::FlowTrace { .. } => (Method::Get, "/trace/flow"),
        AppOperation::FlowEvents(_) => (Method::Get, "/trace/events"),
        AppOperation::FlowSvg { .. } => (Method::Get, "/trace/flow.svg"),
        AppOperation::Explain(_) => (Method::Post, "/explain"),
        AppOperation::ProbeList => (Method::Get, "/probe"),
        AppOperation::ProbeSubmit(_) => (Method::Post, "/probe"),
        AppOperation::ProbeCancel { .. } => (Method::Post, "/probe/cancel"),
        AppOperation::ProbeResult { .. } => (Method::Get, "/probe/result"),
        AppOperation::ConfigPreview { .. } => (Method::Post, "/config/preview"),
        AppOperation::ConfigPropose { .. } => (Method::Post, "/config/proposals"),
    }
}

/// 全集操作样例（新变体加入即编译失败于此——刻意不给 Default/通配）
fn sample_ops() -> Vec<AppOperation> {
    let mut annotations = BTreeMap::new();
    annotations.insert("client.cidr".to_string(), "10.0.0.1/32".to_string());
    vec![
        AppOperation::RuntimeStats,
        AppOperation::RoutingQuality,
        AppOperation::FlowList(
            FlowListFilter::new(
                Some(StateFilter::Closed),
                Some(OriginFilter::Association),
                Some("gen-1".to_string()),
                40,
                20,
            )
            .expect("filter"),
        ),
        AppOperation::FlowTrace {
            id: "f-1".to_string(),
        },
        AppOperation::FlowEvents(FlowEventsParams::new("f-1".to_string(), 3, 200).expect("params")),
        AppOperation::FlowSvg {
            id: "f-1".to_string(),
        },
        AppOperation::Explain(Box::new(ExplainInput {
            generation_id: "gen-1".to_string(),
            ingress: Some("mixed-in".to_string()),
            host: "example.com".to_string(),
            port: 443,
            proto: "tcp".to_string(),
            domain_source: DomainSource::UserProvided,
            process: None,
            annotations,
        })),
        AppOperation::ProbeList,
        AppOperation::ProbeSubmit(ProbeJobSpec::UdpEcho {
            addr: "192.0.2.1:443".to_string(),
            payload_len: 64,
        }),
        AppOperation::ProbeCancel { id: 7 },
        AppOperation::ProbeResult { id: 7 },
        AppOperation::ConfigPreview {
            patch: serde_json::json!({"telemetry": {"log_level": "debug"}}),
            scope: Some(vec!["telemetry".to_string()]),
        },
        AppOperation::ConfigPropose {
            patch: serde_json::json!({"telemetry": {"log_level": "debug"}}),
            scope: vec!["telemetry".to_string()],
            ttl_ms: 60_000,
        },
    ]
}

#[test]
fn operation_set_is_closed_and_each_maps_one_wire_shape() {
    let ops = sample_ops();
    assert_eq!(ops.len(), 13, "全集样例与操作数一致（新操作漏登记即失败）");
    for op in &ops {
        let req = op.request().expect("request builds");
        let (method, path) = wire_of(op);
        assert_eq!(req.method, method, "op {} method", op.name());
        assert_eq!(req.path, path, "op {} path", op.name());
    }
}

/// 线上路径审查名单（与 wire_of 对账——路径不来自操作之外的任何来源）
const PATH_ALLOWLIST: [&str; 12] = [
    "/runtime/stats",
    "/routing/stats",
    "/trace/flows",
    "/trace/flow",
    "/trace/events",
    "/trace/flow.svg",
    "/explain",
    "/probe",
    "/probe/cancel",
    "/probe/result",
    "/config/preview",
    "/config/proposals",
];

#[test]
fn every_request_path_is_on_the_allowlist() {
    for op in sample_ops() {
        let req = op.request().expect("request builds");
        assert!(
            PATH_ALLOWLIST.contains(&req.path),
            "path {} 不在审查名单",
            req.path
        );
    }
}

/// RIL-080：配置操作体形——预检 scope 缺省不入体；提案 owner 恒
/// 适配器固定标签（模型请求面无 owner 字段——冒充结构性不可能）。
#[test]
fn config_operations_carry_fixed_owner_and_minimal_body() {
    let preview = AppOperation::ConfigPreview {
        patch: serde_json::json!({"a": 1}),
        scope: None,
    }
    .request()
    .expect("request");
    assert_eq!(preview.method, Method::Post);
    assert_eq!(preview.path, "/config/preview");
    assert_eq!(
        preview.body.as_ref().expect("body"),
        &serde_json::json!({"patch": {"a": 1}}),
        "scope None 不入体"
    );

    let propose = AppOperation::ConfigPropose {
        patch: serde_json::json!({"a": 1}),
        scope: vec!["a".to_string()],
        ttl_ms: 5,
    }
    .request()
    .expect("request");
    assert_eq!(propose.method, Method::Post);
    assert_eq!(propose.path, "/config/proposals");
    let body = propose.body.expect("body");
    assert_eq!(body["owner"], "mcp", "owner 适配器固定");
    assert_eq!(body["ttl_ms"], serde_json::json!(5));
    assert_eq!(body["patch"], serde_json::json!({"a": 1}));
    assert_eq!(body["scope"], serde_json::json!(["a"]));
}

#[test]
fn flow_list_params_are_typed_and_bounded() {
    let req = AppOperation::FlowList(
        FlowListFilter::new(
            Some(StateFilter::Active),
            None,
            Some("gen-1".to_string()),
            0,
            20,
        )
        .expect("filter"),
    )
    .request()
    .expect("request");
    let keys: Vec<&str> = req.query.iter().map(|(k, _)| *k).collect();
    assert!(keys.contains(&"state"));
    assert!(keys.contains(&"offset"));
    assert!(keys.contains(&"limit"));
    assert!(!keys.contains(&"origin"), "未设过滤不出现在查询串");
    assert_eq!(req.body, None);

    // limit=0 客户端先拒（同服务端 query.page.invalid 码）
    let err = FlowListFilter::new(None, None, None, 0, 0).expect_err("rejected");
    assert_eq!(err.code, "query.page.invalid");
    assert_eq!(err.status, None);
}

#[test]
fn untrusted_ids_are_sanitized_into_query() {
    let hostile = "f\u{1}-1\u{200b}<script>";
    let req = AppOperation::FlowTrace {
        id: hostile.to_string(),
    }
    .request()
    .expect("request");
    let (key, value) = &req.query[0];
    assert_eq!(*key, "id");
    // 零宽移除、控制字符占位（sanitize_untrusted 语义原样）；文本有界
    assert_eq!(*value, sanitize_untrusted(hostile, 256));
    assert!(!value.contains('\u{200b}'));
    assert!(value.contains('\u{FFFD}'));
}

#[test]
fn explain_body_carries_validated_input_and_sanitizes_echo() {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        "process.name\u{200b}".to_string(),
        "app\u{1}\u{200b}".to_string(),
    );
    let op = AppOperation::Explain(Box::new(ExplainInput {
        generation_id: "gen-1".to_string(),
        ingress: Some("mixed-in".to_string()),
        host: "example.com".to_string(),
        port: 443,
        proto: "quic".to_string(),
        domain_source: DomainSource::Sniffed,
        process: None,
        annotations,
    }));
    let req = op.request().expect("request");
    assert_eq!(req.method, Method::Post);
    let body = req.body.expect("body");
    assert_eq!(body["generation_id"], "gen-1");
    assert_eq!(body["port"], 443);
    // 注解键值消毒（零宽移除、控制字符占位）
    let annotations = body["annotations"].as_object().expect("annotations");
    assert!(
        annotations.contains_key("process.name"),
        "消毒后键名保留可读形态"
    );
    let value = annotations
        .get("process.name")
        .and_then(|v| v.as_str())
        .expect("value");
    assert!(!value.contains('\u{200b}'));
    assert!(!value.contains('\u{1}'));
}

#[test]
fn probe_submit_body_matches_wire_contract() {
    let req = AppOperation::ProbeSubmit(ProbeJobSpec::Dns {
        host: "example.com".to_string(),
    })
    .request()
    .expect("request");
    let body = req.body.expect("body");
    assert_eq!(body["kind"], "dns");
    assert_eq!(body["host"], "example.com");

    let req = AppOperation::ProbeSubmit(ProbeJobSpec::Connect {
        addr: "192.0.2.1:443".to_string(),
    })
    .request()
    .expect("request");
    assert_eq!(req.body.expect("body")["kind"], "connect");

    let req = AppOperation::ProbeSubmit(ProbeJobSpec::UdpEcho {
        addr: "192.0.2.1:53".to_string(),
        payload_len: 64,
    })
    .request()
    .expect("request");
    let body = req.body.expect("body");
    assert_eq!(body["kind"], "udp_echo");
    assert_eq!(body["payload_len"], 64);
}

#[test]
fn param_rejections_never_reach_the_wire() {
    // limit=0：列表与事件两处构造期拒绝（操作构造不出非法请求）
    let filter = FlowListFilter::new(None, None, None, 0, 0);
    assert_eq!(filter.unwrap_err().code, "query.page.invalid");
    let params = FlowEventsParams::new("f-1".to_string(), 0, 0);
    assert_eq!(params.unwrap_err().code, "query.page.invalid");
}
