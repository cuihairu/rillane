//! 订阅到执行完整回归（RIL-087）：输入（订阅 YAML）→ IR（转换）→
//! 代际（对象/边图 + 内容摘要）→ 路由 → Explain 推演 → 实际出口，
//! 全链一致。多来源刷新只动本源对象（他源摘要不漂移）；凭证进 IR
//! 与代际身份（变化即新代际——不静默丢失/沿用）；组回退按声明序且
//! Explain 预测与实际出口一致、同快照同输入重放确定；规则（后缀/
//! 网段/兜底）实际出口与决策来源可对账；来源删除显式（引用仍在即
//! 悬空拒绝——本地覆盖引用订阅节点删除后不静默断链）；NodesOnly
//! 本地覆盖：只收节点，组/规则整块剥离并显式登记，刷新合并后用户
//! 策略不被订阅载荷覆盖。

use std::collections::BTreeMap;

use anyhow::Result;
use rillane_config::{
    CODE_GENERATION_DANGLING, EgressConfig, GenerationEdge, GenerationObject, GroupMember,
    MatchCondition, ObjectId, ObjectKind, RillaneConfig, RouteRule, RuntimeGeneration, SourceId,
    Strategy, digest_parts,
};
use rillane_core::{FlowContext, FlowId, FlowMetadata, FlowRouter, FlowTarget, TargetProto};
use rillane_routing::{DomainSource, ExplainInput, RoutingEngine};
use rillane_subscription::{
    ClashConverter, ConversionOptions, ImportMode, Subscription, SubscriptionConverter,
    SubscriptionType,
};

// ---------------------------------------------------------------------------
// 样本（脱敏：RFC 5737 地址 + 占位凭证）
// ---------------------------------------------------------------------------

/// 来源 sub-a：trojan + ss 节点、select 组、2 条规则
const SUB_A: &str = r#"
mixed-port: 7890
allow-lan: false
log-level: info
proxies:
  - name: a-tro
    type: trojan
    server: 203.0.113.10
    port: 443
    password: "trojan-pass-1"
    sni: a-tro.example.com
    udp: true
  - name: a-ss
    type: ss
    server: 203.0.113.11
    port: 8388
    cipher: aes-256-gcm
    password: "ss-pass-1"
    udp: true
proxy-groups:
  - name: A-PROXY
    type: select
    proxies:
      - a-tro
      - a-ss
rules:
  - DOMAIN-SUFFIX,example.net,A-PROXY
  - MATCH,A-PROXY
"#;

/// sub-a 刷新版：新增节点 a-tro2（组声明与既有凭证不动——隔离变量）
const SUB_A_V2: &str = r#"
mixed-port: 7890
proxies:
  - name: a-tro
    type: trojan
    server: 203.0.113.10
    port: 443
    password: "trojan-pass-1"
    sni: a-tro.example.com
    udp: true
  - name: a-ss
    type: ss
    server: 203.0.113.11
    port: 8388
    cipher: aes-256-gcm
    password: "ss-pass-1"
    udp: true
  - name: a-tro2
    type: trojan
    server: 203.0.113.19
    port: 443
    password: "trojan-pass-2"
    sni: a-tro2.example.com
    udp: true
proxy-groups:
  - name: A-PROXY
    type: select
    proxies:
      - a-tro
      - a-ss
rules:
  - DOMAIN-SUFFIX,example.net,A-PROXY
  - MATCH,A-PROXY
"#;

/// sub-a 凭证轮换版：仅 a-tro 口令变化（其余逐字节相同）
const SUB_A_PWC: &str = r#"
mixed-port: 7890
proxies:
  - name: a-tro
    type: trojan
    server: 203.0.113.10
    port: 443
    password: "trojan-pass-rotated"
    sni: a-tro.example.com
    udp: true
  - name: a-ss
    type: ss
    server: 203.0.113.11
    port: 8388
    cipher: aes-256-gcm
    password: "ss-pass-1"
    udp: true
proxy-groups:
  - name: A-PROXY
    type: select
    proxies:
      - a-tro
      - a-ss
rules:
  - DOMAIN-SUFFIX,example.net,A-PROXY
  - MATCH,A-PROXY
"#;

/// 来源 sub-b：vmess 节点（UUID 凭证）
const SUB_B: &str = r#"
mixed-port: 7890
proxies:
  - name: b-vm
    type: vmess
    server: 203.0.113.12
    port: 443
    uuid: "b1111111-2222-3333-4444-555555555555"
    alterId: 0
    cipher: auto
    tls: true
    servername: b-vm.example.com
proxy-groups: []
rules: []
"#;

/// 来源 sub-fb：fallback 组（声明序回退）+ 后缀规则
const SUB_FB: &str = r#"
mixed-port: 7890
proxies:
  - name: f-1
    type: trojan
    server: 203.0.113.20
    port: 443
    password: "fb-pass-1"
    sni: f1.example.com
    udp: true
  - name: f-2
    type: trojan
    server: 203.0.113.21
    port: 443
    password: "fb-pass-2"
    sni: f2.example.com
    udp: true
  - name: f-3
    type: trojan
    server: 203.0.113.22
    port: 443
    password: "fb-pass-3"
    sni: f3.example.com
    udp: true
proxy-groups:
  - name: FB-AUTO
    type: fallback
    proxies:
      - f-1
      - f-2
      - f-3
rules:
  - DOMAIN-SUFFIX,example.com,FB-AUTO
"#;

/// 来源 sub-rules：后缀 / 网段 / MATCH 兜底三类规则
const SUB_RULES: &str = r#"
mixed-port: 7890
proxies:
  - name: node-a
    type: trojan
    server: 203.0.113.23
    port: 443
    password: "rules-pass-a"
    sni: node-a.example.com
    udp: true
  - name: node-b
    type: trojan
    server: 203.0.113.24
    port: 443
    password: "rules-pass-b"
    sni: node-b.example.com
    udp: true
rules:
  - DOMAIN-SUFFIX,example.com,node-a
  - IP-CIDR,10.0.0.0/8,node-b
  - MATCH,node-a
proxy-groups: []
"#;

/// 本地配置：用户自有节点 + 用户分流规则（RIL-016 策略归本地）
const LOCAL_CFG: &str = r#"
mixed-port: 7890
proxies:
  - name: home-direct
    type: trojan
    server: 203.0.113.30
    port: 443
    password: "local-pass"
    sni: home.example.com
    udp: true
rules:
  - DOMAIN-SUFFIX,game.example,home-direct
  - MATCH,home-direct
proxy-groups: []
"#;

// ---------------------------------------------------------------------------
// 助手
// ---------------------------------------------------------------------------

/// 订阅 YAML → IR（转换面：parse + convert_to_rillane）
fn ir_from(yaml: &str) -> RillaneConfig {
    let converter = ClashConverter::new();
    let clash = converter.parse(yaml).expect("clash 解析通过");
    converter
        .convert_to_rillane(&clash)
        .expect("clash → IR 转换通过")
}

/// 订阅源记录（类型显式 Clash——跳过检测，聚焦转换本体）
fn sub(name: &str) -> Subscription {
    Subscription {
        name: name.to_string(),
        url: format!("https://sub.invalid/{name}.yaml"),
        r#type: Some(SubscriptionType::Clash),
        enabled: true,
        refresh_interval: 60,
        timeout: 30,
        headers: std::collections::HashMap::new(),
        user_agent: None,
        last_updated: None,
        last_error: None,
        etag: None,
        last_modified: None,
        content_hash: None,
    }
}

/// IR → 代际对象：出口节点 = Node 对象、策略组 = Group 对象；内容摘要
/// 覆盖名称 + 整份规格（凭证变化即摘要变化——不静默）
fn objects_for(source: &str, ir: &RillaneConfig) -> Result<Vec<GenerationObject>> {
    let sid = SourceId::new(source)?;
    let mut objs = Vec::new();
    for e in &ir.egress {
        let spec = serde_json::to_string(&e.spec)?;
        objs.push(GenerationObject {
            id: ObjectId::new(sid.clone(), e.name.clone()),
            kind: ObjectKind::Node,
            content_hash: digest_parts(&[&e.name, &spec]),
        });
    }
    for g in &ir.routing.groups {
        let spec = serde_json::to_string(g)?;
        objs.push(GenerationObject {
            id: ObjectId::new(sid.clone(), g.name.clone()),
            kind: ObjectKind::Group,
            content_hash: digest_parts(&[&g.name, &spec]),
        });
    }
    Ok(objs)
}

/// IR → 代际引用边（组 → 成员节点/嵌套组；Provider 成员无对象不产边）
fn edges_for(source: &str, ir: &RillaneConfig) -> Result<Vec<GenerationEdge>> {
    let sid = SourceId::new(source)?;
    let mut edges = Vec::new();
    for g in &ir.routing.groups {
        let from = ObjectId::new(sid.clone(), g.name.clone());
        for m in &g.members {
            let to = match m {
                GroupMember::Node { name } | GroupMember::WeightedNode { name, .. } => {
                    ObjectId::new(sid.clone(), name.clone())
                }
                GroupMember::Group { name } | GroupMember::WeightedGroup { name, .. } => {
                    ObjectId::new(sid.clone(), name.clone())
                }
                GroupMember::Provider { .. } => continue,
            };
            edges.push(GenerationEdge {
                from: from.clone(),
                to,
            });
        }
    }
    Ok(edges)
}

/// 路由输入流上下文（TCP 形状——回归聚焦路由决策面）
fn flow_ctx(host: &str, port: u16) -> FlowContext {
    FlowContext {
        id: FlowId::new(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        metadata: FlowMetadata::default(),
    }
}

/// 代际锚定的 Explain 输入（输入 → IR → 代际 → Explain 链条的代际关联）
fn explain_input(generation_id: &str, host: &str, port: u16) -> ExplainInput {
    ExplainInput {
        generation_id: generation_id.to_string(),
        ingress: None,
        host: host.to_string(),
        port,
        proto: "tcp".to_string(),
        domain_source: DomainSource::UserProvided,
        process: None,
        annotations: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

/// 多来源刷新：两来源合并建代际；同内容重build同代际身份（确定性）；
/// 刷新 sub-a（新增节点）→ 新代际、新对象在场、sub-b 对象摘要不漂移
/// （他源对象不因本源刷新被改写/丢失）。
#[test]
fn multi_source_refresh_builds_consistent_generations() -> Result<()> {
    let ir_a = ir_from(SUB_A);
    let ir_b = ir_from(SUB_B);
    let b_objs = objects_for("sub-b", &ir_b)?;

    let mut objs = objects_for("sub-a", &ir_a)?;
    objs.extend(b_objs.clone());
    let mut edges = edges_for("sub-a", &ir_a)?;
    edges.extend(edges_for("sub-b", &ir_b)?);

    // 同内容 → 同代际身份（build 确定性——刷新不无故换代际）
    let gen1 = RuntimeGeneration::build(objs.clone(), edges.clone())?;
    let gen1_again = RuntimeGeneration::build(objs, edges)?;
    assert_eq!(
        gen1.generation_id(),
        gen1_again.generation_id(),
        "同内容同代际身份"
    );

    // 刷新：sub-a 新增节点（sub-b 不动）
    let ir_a2 = ir_from(SUB_A_V2);
    let mut objs2 = objects_for("sub-a", &ir_a2)?;
    objs2.extend(b_objs.clone());
    let mut edges2 = edges_for("sub-a", &ir_a2)?;
    edges2.extend(edges_for("sub-b", &ir_b)?);
    let gen2 = RuntimeGeneration::build(objs2, edges2)?;
    assert_ne!(
        gen1.generation_id(),
        gen2.generation_id(),
        "内容变化 → 新代际"
    );
    assert_eq!(
        gen2.objects().count(),
        gen1.objects().count() + 1,
        "刷新恰带来一个新节点对象"
    );
    let new_id = ObjectId::new(SourceId::new("sub-a")?, "a-tro2");
    assert!(gen2.get(&new_id).is_some(), "新增节点对象在场");

    // 未刷新来源的对象原样保留（同 ID 同摘要——不因他源刷新漂移）
    for b in &b_objs {
        let before = gen1.get(&b.id).expect("sub-b 对象在刷新前在场");
        let kept = gen2.get(&b.id).expect("sub-b 对象在刷新后仍在场");
        assert_eq!(before.content_hash, kept.content_hash, "他源对象摘要不漂移");
    }
    Ok(())
}

/// 凭证不静默丢失：trojan 口令 / ss 密码与算法 / vmess UUID 全部进 IR；
/// 凭证轮换 → 对象摘要变化 → 代际身份变化（刷新后不静默沿用旧凭证代际）。
#[test]
fn credentials_survive_conversion_and_anchor_generation_identity() -> Result<()> {
    let ir = ir_from(SUB_A);
    let tro = ir
        .egress
        .iter()
        .find(|e| e.name == "a-tro")
        .expect("trojan 节点在 IR");
    let rillane_config::EgressConfig::Trojan { password, .. } = &tro.spec else {
        panic!("a-tro 应为 trojan 出口");
    };
    assert_eq!(password, "trojan-pass-1", "trojan 口令进 IR");
    let ssp = ir
        .egress
        .iter()
        .find(|e| e.name == "a-ss")
        .expect("ss 节点在 IR");
    let rillane_config::EgressConfig::Shadowsocks {
        method, password, ..
    } = &ssp.spec
    else {
        panic!("a-ss 应为 shadowsocks 出口");
    };
    assert_eq!(method, "aes-256-gcm", "ss 算法进 IR");
    assert_eq!(password, "ss-pass-1", "ss 口令进 IR");

    let ir_b = ir_from(SUB_B);
    let vm = ir_b
        .egress
        .iter()
        .find(|e| e.name == "b-vm")
        .expect("vmess 节点在 IR");
    let rillane_config::EgressConfig::Vmess { uuid, .. } = &vm.spec else {
        panic!("b-vm 应为 vmess 出口");
    };
    assert_eq!(
        uuid, "b1111111-2222-3333-4444-555555555555",
        "UUID 凭证进 IR"
    );

    // 凭证轮换：对象摘要与代际身份随之变化
    let ir_pwc = ir_from(SUB_A_PWC);
    let tro2 = ir_pwc
        .egress
        .iter()
        .find(|e| e.name == "a-tro")
        .expect("轮换后节点仍在");
    let rillane_config::EgressConfig::Trojan { password, .. } = &tro2.spec else {
        panic!("轮换版 a-tro 仍为 trojan 出口");
    };
    assert_eq!(
        password, "trojan-pass-rotated",
        "新凭证进 IR——不静默沿用旧值"
    );

    let h_old = digest_parts(&["a-tro", &serde_json::to_string(&tro.spec)?]);
    let h_new = digest_parts(&["a-tro", &serde_json::to_string(&tro2.spec)?]);
    assert_ne!(h_old, h_new, "凭证变化 → 对象摘要变化");

    let gen_old = RuntimeGeneration::build(objects_for("sub-a", &ir)?, edges_for("sub-a", &ir)?)?;
    let gen_new =
        RuntimeGeneration::build(objects_for("sub-a", &ir_pwc)?, edges_for("sub-a", &ir_pwc)?)?;
    assert_ne!(
        gen_old.generation_id(),
        gen_new.generation_id(),
        "凭证变化 → 新代际（身份不静默沿用）"
    );
    Ok(())
}

/// 组回退全链一致：订阅 fallback 组直映 Strategy::Fallback；健康态按
/// 声明序取首个健康成员；输入 → IR → 代际 → Explain → 实际出口一致
/// （预测 = 实际、代际关联在场）；同快照同输入重放确定。
#[tokio::test]
async fn group_fallback_execution_matches_explanation() -> Result<()> {
    let ir = ir_from(SUB_FB);
    assert_eq!(ir.routing.groups.len(), 1, "组进 IR");
    assert_eq!(
        ir.routing.groups[0].strategy,
        Strategy::Fallback,
        "clash fallback 直映 Strategy::Fallback"
    );

    // 代际：输入 → IR → 代际（对象 + 组→成员边）
    let generation =
        RuntimeGeneration::build(objects_for("sub-fb", &ir)?, edges_for("sub-fb", &ir)?)?;

    let engine = RoutingEngine::new(ir.routing);

    // 全健康 → 首位 f-1；Explain 预测与实际出口一致（代际锚定）
    let decision = engine.route(flow_ctx("www.example.com", 443)).await?;
    assert_eq!(decision.final_node(), "f-1", "全健康恒取声明首位");
    let snap = engine.freeze_explain_snapshot();
    let input = explain_input(generation.generation_id(), "www.example.com", 443);
    let expl = engine.explain(&snap, &input)?;
    let predicted = expl.predicted.as_ref().expect("确定性策略应有预测节点");
    assert_eq!(
        predicted.node.as_deref(),
        Some(decision.final_node().as_str()),
        "Explain 预测 = 实际出口"
    );
    assert_eq!(expl.generation_id, input.generation_id, "推演回显代际关联");

    // 重放确定：同快照同输入 → 同摘要同预测（可离线重放）
    let replay = engine.explain(&snap, &input)?;
    assert_eq!(expl.input_digest, replay.input_digest, "重放摘要一致");
    assert_eq!(expl.predicted, replay.predicted, "重放预测一致");

    // 首位下线 → 顺延次位 f-2；预测仍与实际一致
    engine.set_node_health("f-1", false);
    let decision = engine.route(flow_ctx("www.example.com", 443)).await?;
    assert_eq!(decision.final_node(), "f-2", "首位下线顺延次位");
    let snap = engine.freeze_explain_snapshot();
    let expl = engine.explain(&snap, &input)?;
    let predicted = expl.predicted.as_ref().expect("回退后仍有预测");
    assert_eq!(
        predicted.node.as_deref(),
        Some(decision.final_node().as_str()),
        "回退后 Explain = 实际出口"
    );

    // 前两位下线 → 第三位 f-3；恢复 → 回首位（按声明序回退）
    engine.set_node_health("f-2", false);
    let decision = engine.route(flow_ctx("www.example.com", 443)).await?;
    assert_eq!(decision.final_node(), "f-3", "前两位下线取第三位");
    engine.set_node_health("f-1", true);
    engine.set_node_health("f-2", true);
    let decision = engine.route(flow_ctx("www.example.com", 443)).await?;
    assert_eq!(decision.final_node(), "f-1", "恢复回声明首位");
    Ok(())
}

/// 规则全链一致：后缀 / 网段 / MATCH 兜底三类规则全量进 IR（不静默
/// 丢失）；实际出口 = 规则目标 = Explain 预测，决策来源 = 规则名
/// （转换器规则名口径 `rule-N`）。
#[tokio::test]
async fn rule_conditions_route_and_explain_agree() -> Result<()> {
    let ir = ir_from(SUB_RULES);
    assert_eq!(
        ir.routing.rules.len(),
        3,
        "三条规则全量进 IR（含 MATCH 兜底）"
    );

    let engine = RoutingEngine::new(ir.routing);
    let snap = engine.freeze_explain_snapshot();

    for (host, port, expect, rule_name) in [
        ("www.example.com", 443, "node-a", "rule-1"),
        ("10.0.0.5", 56001, "node-b", "rule-2"),
        ("other.example.org", 80, "node-a", "rule-3"),
    ] {
        let decision = engine.route(flow_ctx(host, port)).await?;
        assert_eq!(decision.final_node(), expect, "{host} 实际出口 = 规则目标");
        let input = explain_input("gen-rules", host, port);
        let expl = engine.explain(&snap, &input)?;
        assert_eq!(
            expl.matched_by.as_deref(),
            Some(rule_name),
            "{host} 决策来源 = 规则名"
        );
        let predicted = expl.predicted.as_ref().expect("规则命中应有预测出口");
        assert_eq!(
            predicted.node.as_deref(),
            Some(decision.final_node().as_str()),
            "{host} Explain 预测 = 实际出口"
        );
    }
    Ok(())
}

/// 来源删除显式：本地组引用订阅节点（跨源边）；删除 sub-b 而引用
/// 仍在 → 悬空显式拒绝（关键策略不静默断链）；连本地引用边一并
/// 清理 → 删除完成、对象离场、其余对象原样。
#[test]
fn source_deletion_is_explicit_not_silent() -> Result<()> {
    let ir_a = ir_from(SUB_A);
    let ir_b = ir_from(SUB_B);
    let b_id = ObjectId::new(SourceId::new("sub-b")?, "b-vm");

    let mut objs = objects_for("sub-a", &ir_a)?;
    objs.extend(objects_for("sub-b", &ir_b)?);
    // 本地覆盖：LOCAL-PROXY 组引用订阅节点（跨源边——删除面关键场景）
    let local_group = ObjectId::new(SourceId::new("local")?, "LOCAL-PROXY");
    objs.push(GenerationObject {
        id: local_group.clone(),
        kind: ObjectKind::Group,
        content_hash: digest_parts(&["LOCAL-PROXY", "local-override"]),
    });
    let mut edges = edges_for("sub-a", &ir_a)?;
    edges.push(GenerationEdge {
        from: local_group.clone(),
        to: ObjectId::new(SourceId::new("sub-a")?, "a-tro"),
    });
    edges.push(GenerationEdge {
        from: local_group.clone(),
        to: b_id.clone(),
    });

    let full = RuntimeGeneration::build(objs.clone(), edges.clone())?;
    assert!(full.get(&b_id).is_some(), "sub-b 对象在场");

    // 只删对象、留引用 → 显式拒绝（不静默丢边/丢对象）
    let without_b: Vec<GenerationObject> = objs.iter().filter(|o| o.id != b_id).cloned().collect();
    let err = match RuntimeGeneration::build(without_b.clone(), edges.clone()) {
        Err(err) => err,
        Ok(_) => panic!("引用仍在时删除来源必须悬空拒绝"),
    };
    assert_eq!(err.code(), CODE_GENERATION_DANGLING, "来源删除显式报悬空");

    // 连本地引用边一并清理 → 删除完成：对象离场、其余原样
    let edges_cleaned: Vec<GenerationEdge> =
        edges.iter().filter(|e| e.to != b_id).cloned().collect();
    let after = RuntimeGeneration::build(without_b, edges_cleaned)?;
    assert!(after.get(&b_id).is_none(), "删除后对象离场");
    let a_tro = ObjectId::new(SourceId::new("sub-a")?, "a-tro");
    assert!(after.get(&a_tro).is_some(), "他源对象不因删除受累");
    assert_eq!(
        after.objects().count(),
        full.objects().count() - 1,
        "删除恰少一个对象"
    );
    Ok(())
}

/// 本地覆盖（NodesOnly）：只收出口节点——组/规则整块剥离并显式登记
/// （warnings 可见）；节点凭证照常进 IR；刷新合并后用户本地规则不被
/// 订阅载荷覆盖。存量 FullPolicy 行为对照：整份策略照收。
#[tokio::test]
async fn nodes_only_import_keeps_local_policy_ownership() -> Result<()> {
    let conv = SubscriptionConverter::with_options(ConversionOptions {
        import_mode: ImportMode::NodesOnly,
        ..Default::default()
    });
    let res = conv.auto_convert(&sub("sub-a"), SUB_A).await?;
    assert_eq!(res.config.egress.len(), 2, "节点保留");
    assert!(res.config.routing.groups.is_empty(), "组不带入");
    assert!(res.config.routing.rules.is_empty(), "规则不带入");
    assert!(
        res.warnings.iter().any(|w| w.contains("nodes-only")),
        "剥离显式登记进 warnings"
    );
    // 节点凭证照常进 IR（只收节点 ≠ 剥凭证）
    let tro = res
        .config
        .egress
        .iter()
        .find(|e| e.name == "a-tro")
        .expect("a-tro 在 NodesOnly IR");
    let EgressConfig::Trojan { password, .. } = &tro.spec else {
        panic!("a-tro 仍为 trojan 出口");
    };
    assert_eq!(password, "trojan-pass-1", "节点凭证不静默丢失");

    // 刷新合并：节点面由订阅供给替换，规则面保持本地（IR 无策略可覆盖）
    let mut local = ir_from(LOCAL_CFG);
    assert_eq!(local.routing.rules.len(), 2, "本地规则在场");
    local.egress = res.config.egress;
    assert!(
        local.egress.iter().any(|e| e.name == "a-tro"),
        "节点来自订阅"
    );
    assert_eq!(local.routing.rules.len(), 2, "用户规则不被订阅刷新覆盖");
    assert_eq!(
        local.routing.rules[0].target, "home-direct",
        "本地分流目标原样"
    );

    // 存量行为对照：FullPolicy 整份策略照收
    let full = SubscriptionConverter::with_options(ConversionOptions::default())
        .auto_convert(&sub("sub-a"), SUB_A)
        .await?;
    assert_eq!(full.config.routing.groups.len(), 1, "FullPolicy 组照收");
    assert_eq!(full.config.routing.rules.len(), 2, "FullPolicy 规则照收");
    assert!(
        !full.warnings.iter().any(|w| w.contains("nodes-only")),
        "FullPolicy 无剥离登记"
    );

    // 规则构造面对照（引用面健全性）：RouteRule 三元组可直接构造
    let manual = RouteRule {
        name: "manual".to_string(),
        matches: vec![MatchCondition::DomainSuffix {
            values: vec!["manual.example".to_string()],
        }],
        target: "a-tro".to_string(),
    };
    assert_eq!(manual.target, "a-tro");
    Ok(())
}
