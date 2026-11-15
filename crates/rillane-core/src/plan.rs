//! 流、计划与会话契约（RIL-006 / C22-C23）：RoutePlan 是现有
//! RouteDecision 的单向兼容扩展——唯一构造入口
//! [`RoutePlan::from_decision`]，path/reason/route_type 逐字段透传
//! 不改写；**不存在第二套路由决策器**（规则结果冻结在决策快照里，
//! 执行侧只能追加执行结果，不能回写规则结果）。元数据条目带来源
//! 与显式缺失状态，不做静默缺席。SessionPin 把活跃流钉在明确代际
//! 上（代际身份为内容摘要派生的不透明字符串——内核不依赖
//! rillane-config，RIL-001）；TCP 有序字节流与 UDP 映射数据报是
//! 两种绑定（C22），类型层面强制分侧。
//!
//! 接线边界：runtime/拨号侧消费本契约（代际发布归 RIL-008 接线的
//! rillane-config `GenerationStore`；本模块只承载身份与绑定）。

use std::collections::BTreeMap;

use crate::{RouteDecision, RoutePath, RouteType};

/// 会话代际引用（RIL-006）：内容摘要派生的不透明身份字符串
/// （rillane-config `RuntimeGeneration::generation_id` 的承载形式）。
/// 内核不解析其内容，只要求非空。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenerationRef(String);

impl GenerationRef {
    /// 构造代际引用（空字符串拒绝——流必须绑定明确代际）
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let id = id.into();
        if id.is_empty() {
            return None;
        }
        Some(GenerationRef(id))
    }

    /// 代际身份原文
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GenerationRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 元数据来源（RIL-006 验收「元数据有来源」）：标注一条元数据由哪一
/// 环节产出。`as_str()` 是机器口径，恒定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataOrigin {
    /// 规则匹配产出
    Rule,
    /// 协议嗅探产出
    Sniff,
    /// 平台层（进程归因等）产出
    Platform,
    /// 订阅对象映射产出
    Subscription,
    /// 用户/配置显式给出
    Manual,
}

impl MetadataOrigin {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            MetadataOrigin::Rule => "rule",
            MetadataOrigin::Sniff => "sniff",
            MetadataOrigin::Platform => "platform",
            MetadataOrigin::Subscription => "subscription",
            MetadataOrigin::Manual => "manual",
        }
    }
}

/// 带来源与缺失状态的元数据值（RIL-006 验收「元数据有来源和缺失状态」）：
/// 缺失也是显式状态（带稳定原因），不静默缺席。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenanced<T> {
    /// 有值，且注明来源环节
    Present {
        /// 值本身
        value: T,
        /// 产出环节
        origin: MetadataOrigin,
    },
    /// 缺失，注明稳定原因（机器口径，不作文案匹配）
    Missing {
        /// 缺失原因（稳定字面量）
        reason: &'static str,
    },
}

impl<T> Provenanced<T> {
    /// 有值条目
    pub fn present(value: T, origin: MetadataOrigin) -> Self {
        Provenanced::Present { value, origin }
    }

    /// 缺失条目
    pub fn missing(reason: &'static str) -> Self {
        Provenanced::Missing { reason }
    }

    /// 值（缺失时为 None）
    pub fn value(&self) -> Option<&T> {
        match self {
            Provenanced::Present { value, .. } => Some(value),
            Provenanced::Missing { .. } => None,
        }
    }

    /// 是否显式缺失
    pub fn is_missing(&self) -> bool {
        matches!(self, Provenanced::Missing { .. })
    }

    /// 产出环节（缺失时为 None——缺失本身没有来源）
    pub fn origin(&self) -> Option<MetadataOrigin> {
        match self {
            Provenanced::Present { origin, .. } => Some(*origin),
            Provenanced::Missing { .. } => None,
        }
    }
}

/// 规则结果快照（RIL-006 验收「规则结果与执行结果分离」的规则半边）：
/// 由 [`RouteDecision`] 一次性冻结，path/reason/route_type 逐字段透传
/// （验收「保留语义」）。字段公开只读，无再构造入口——防止旁路伪造
/// 第二决策器。
#[derive(Debug, Clone)]
pub struct DecisionSnapshot {
    /// 路由路径（自 RouteDecision 透传）
    pub path: RoutePath,
    /// 路由原因（自 RouteDecision 透传）
    pub reason: Option<String>,
    /// 路由类型（自 RouteDecision 透传）
    pub route_type: RouteType,
}

/// 执行结果（RIL-006 验收「规则结果与执行结果分离」的执行半边）：
/// 规则选中但拨号失败不回写规则结果——失败留在执行侧，供重连/诊断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// 尚未执行（规则已定，执行未开始）
    Pending,
    /// 执行成功：最终端点与经过链路
    Dialed {
        /// 最终出口端点
        endpoint: EndpointRef,
        /// 经过链路（节点名序列；直连为空）
        via_chain: Vec<String>,
    },
    /// 执行失败：阶段 + 原因（不回写规则结果）
    Failed {
        /// 失败阶段（稳定字面量，如 `dial` / `handshake`）
        stage: &'static str,
        /// 人读原因
        reason: String,
    },
}

/// 最终出口端点
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRef {
    /// 主机
    pub host: String,
    /// 端口
    pub port: u16,
}

impl EndpointRef {
    /// 构造端点引用
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// 路由计划（RIL-006 / C14-C15 消费侧）：一个明确代际上的执行计划。
/// 唯一构造入口 [`RoutePlan::from_decision`]——计划由规则结果派生，
/// 不存在独立的第二决策器（验收口径）。执行侧通过
/// [`RoutePlan::record_dialed`] / [`RoutePlan::record_failed`] 追加执行
/// 结果；决策快照一旦冻结不可替换。
#[derive(Debug, Clone)]
pub struct RoutePlan {
    generation: GenerationRef,
    decision: DecisionSnapshot,
    execution: ExecutionOutcome,
    annotations: BTreeMap<String, Provenanced<String>>,
}

impl RoutePlan {
    /// 由现有 RouteDecision 单向派生计划（兼容映射，验收口径）：
    /// path/reason/route_type 逐字段透传保留；执行结果初始为
    /// [`ExecutionOutcome::Pending`]。`generation` 为空身份时返回 None
    /// （流必须绑定明确代际）。
    pub fn from_decision(decision: &RouteDecision, generation: GenerationRef) -> Option<Self> {
        Some(Self {
            generation,
            decision: DecisionSnapshot {
                path: match &decision.path {
                    RoutePath::Direct { node } => RoutePath::Direct { node: node.clone() },
                    RoutePath::ThroughGroup {
                        group,
                        selected_node,
                        intermediate_nodes,
                    } => RoutePath::ThroughGroup {
                        group: group.clone(),
                        selected_node: selected_node.clone(),
                        intermediate_nodes: intermediate_nodes.clone(),
                    },
                    RoutePath::Chain { hops } => RoutePath::Chain { hops: hops.clone() },
                },
                reason: decision.reason.clone(),
                route_type: decision.route_type,
            },
            execution: ExecutionOutcome::Pending,
            annotations: BTreeMap::new(),
        })
    }

    /// 绑定的代际（验收「一个流绑定明确代际」）
    pub fn generation(&self) -> &GenerationRef {
        &self.generation
    }

    /// 规则结果快照（只读——执行侧不可回写）
    pub fn decision(&self) -> &DecisionSnapshot {
        &self.decision
    }

    /// 当前执行结果
    pub fn execution(&self) -> &ExecutionOutcome {
        &self.execution
    }

    /// 元数据条目（带来源与缺失状态）
    pub fn annotations(&self) -> &BTreeMap<String, Provenanced<String>> {
        &self.annotations
    }

    /// 写入一条元数据（执行/嗅探/平台侧追加，不触碰决策快照）
    pub fn annotate(&mut self, key: impl Into<String>, entry: Provenanced<String>) {
        self.annotations.insert(key.into(), entry);
    }

    /// 记录执行成功（可覆盖先前失败——重连语义）
    pub fn record_dialed(&mut self, endpoint: EndpointRef, via_chain: Vec<String>) {
        self.execution = ExecutionOutcome::Dialed {
            endpoint,
            via_chain,
        };
    }

    /// 记录执行失败（不回写规则结果）
    pub fn record_failed(&mut self, stage: &'static str, reason: impl Into<String>) {
        self.execution = ExecutionOutcome::Failed {
            stage,
            reason: reason.into(),
        };
    }
}

/// 代际内对象引用（RIL-006）：`(来源, local_id)` 的内核侧不透明承载
/// （与 rillane-config `ObjectId` 同口径；内核不依赖 config crate）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectRef {
    /// 来源命名空间
    pub source: String,
    /// 来源内稳定 local_id
    pub local_id: String,
}

impl ObjectRef {
    /// 构造对象引用
    pub fn new(source: impl Into<String>, local_id: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            local_id: local_id.into(),
        }
    }
}

/// 会话钉（RIL-006 / C23）：活跃流钉住的执行身份——明确代际 + 出口
/// 对象 + 可选来源对象映射。新流可换代际，已建立的流保持自身 pin
/// 不变（旧代际可被存活会话引用，RIL-003 发布位替换不影响 pin）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPin {
    generation: GenerationRef,
    egress: String,
    source_object: Option<ObjectRef>,
}

impl SessionPin {
    /// 由计划派生会话钉：代际取自计划（流与计划同一代际）
    pub fn for_plan(plan: &RoutePlan, egress: impl Into<String>) -> Self {
        Self {
            generation: plan.generation.clone(),
            egress: egress.into(),
            source_object: None,
        }
    }

    /// 附上来源对象映射（订阅对象 → 会话，可追溯）
    pub fn with_source_object(mut self, object: ObjectRef) -> Self {
        self.source_object = Some(object);
        self
    }

    /// 钉住的代际
    pub fn generation(&self) -> &GenerationRef {
        &self.generation
    }

    /// 钉住的出口对象
    pub fn egress(&self) -> &str {
        &self.egress
    }

    /// 来源对象映射（可缺——缺失显式，经 Option 表达）
    pub fn source_object(&self) -> Option<&ObjectRef> {
        self.source_object.as_ref()
    }
}

/// 流绑定边界（RIL-006 / C22）：TCP 是有序字节流（StreamSession），
/// UDP 是映射数据报（DatagramAssociation）——生命周期、语义与回收
/// 规则不同，类型层面强制分侧，不共用一个"连接"抽象。两种绑定的
/// pin 都必须携带明确代际（[`FlowAssociation::pin`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAssociation {
    /// TCP：有序字节流会话
    Stream {
        /// 会话钉
        pin: SessionPin,
    },
    /// UDP：映射数据报关联
    Datagram {
        /// 会话钉
        pin: SessionPin,
        /// NAT/映射键（datagram 语义：按五元组映射应答，非流内序）
        mapping_key: String,
    },
}

impl FlowAssociation {
    /// 绑定携带的会话钉（两种绑定都必须钉代际）
    pub fn pin(&self) -> &SessionPin {
        match self {
            FlowAssociation::Stream { pin } => pin,
            FlowAssociation::Datagram { pin, .. } => pin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HopType, RouteHop};

    #[test]
    fn from_decision_preserves_path_reason_route_type() {
        // 三种 RoutePath 全部逐字段透传（验收：保留 path/reason/route_type 语义）
        let generation = GenerationRef::new("a".repeat(64)).unwrap();

        let decision = RouteDecision::direct("node-a".to_string());
        let plan = RoutePlan::from_decision(&decision, generation.clone()).unwrap();
        assert!(matches!(
            plan.decision().path,
            RoutePath::Direct { ref node } if node == "node-a"
        ));
        assert_eq!(plan.decision().route_type, RouteType::Standard);
        assert_eq!(plan.decision().reason, None);

        let mut decision = RouteDecision::through_group(
            "proxy".to_string(),
            "node-b".to_string(),
            vec!["relay-1".to_string()],
        );
        decision.reason = Some("rule match".to_string());
        let plan = RoutePlan::from_decision(&decision, generation.clone()).unwrap();
        match &plan.decision().path {
            RoutePath::ThroughGroup {
                group,
                selected_node,
                intermediate_nodes,
            } => {
                assert_eq!(group, "proxy");
                assert_eq!(selected_node, "node-b");
                assert_eq!(intermediate_nodes, &["relay-1"]);
            }
            other => panic!("应为 ThroughGroup，实际 {other:?}"),
        }
        assert_eq!(
            plan.decision().reason.as_deref(),
            Some("rule match"),
            "reason 逐字段透传"
        );

        let decision = RouteDecision::chain(vec![
            RouteHop {
                node: "ingress-1".to_string(),
                hop_type: HopType::Ingress,
            },
            RouteHop {
                node: "exit-1".to_string(),
                hop_type: HopType::Egress,
            },
        ]);
        let plan = RoutePlan::from_decision(&decision, generation).unwrap();
        match &plan.decision().path {
            RoutePath::Chain { hops } => {
                assert_eq!(hops.len(), 2);
                assert_eq!(hops[0].node, "ingress-1");
                assert!(matches!(hops[0].hop_type, HopType::Ingress));
                assert!(matches!(hops[1].hop_type, HopType::Egress));
            }
            other => panic!("应为 Chain，实际 {other:?}"),
        }
        assert_eq!(plan.decision().route_type, RouteType::Collaborative);
    }

    #[test]
    fn rule_and_execution_results_stay_separate() {
        let generation = GenerationRef::new("g".repeat(64)).unwrap();
        let decision = RouteDecision::through_group("p".to_string(), "n".to_string(), vec![]);
        let mut plan = RoutePlan::from_decision(&decision, generation).unwrap();
        assert_eq!(plan.execution(), &ExecutionOutcome::Pending);

        // 执行失败：不回写规则结果
        plan.record_failed("dial", "connection refused");
        match plan.execution() {
            ExecutionOutcome::Failed { stage, reason } => {
                assert_eq!(*stage, "dial");
                assert_eq!(reason, "connection refused");
            }
            other => panic!("应为 Failed，实际 {other:?}"),
        }
        // 规则快照原封不动
        assert!(matches!(
            plan.decision().path,
            RoutePath::ThroughGroup { ref group, .. } if group == "p"
        ));

        // 重连成功：执行结果翻转为 Dialed，规则快照仍然原封不动
        plan.record_dialed(EndpointRef::new("1.2.3.4", 1080), vec!["n".to_string()]);
        assert!(matches!(
            plan.execution(),
            ExecutionOutcome::Dialed { endpoint, .. } if endpoint.host == "1.2.3.4"
        ));
        assert!(matches!(
            plan.decision().path,
            RoutePath::ThroughGroup { ref group, .. } if group == "p"
        ));
    }

    #[test]
    fn annotations_have_origin_and_missing_state() {
        let mut plan = RoutePlan::from_decision(
            &RouteDecision::direct("n".to_string()),
            GenerationRef::new("x".repeat(64)).unwrap(),
        )
        .unwrap();

        plan.annotate(
            "process",
            Provenanced::present("chrome".to_string(), MetadataOrigin::Platform),
        );
        plan.annotate("geo", Provenanced::missing("lookup_disabled"));

        let process = plan.annotations().get("process").unwrap();
        assert_eq!(process.value().map(|v| v.as_str()), Some("chrome"));
        assert_eq!(process.origin().map(|o| o.as_str()), Some("platform"));
        assert!(!process.is_missing());

        let geo = plan.annotations().get("geo").unwrap();
        assert!(geo.is_missing(), "缺失是显式状态");
        assert!(geo.value().is_none());
        assert!(geo.origin().is_none());
    }

    #[test]
    fn pin_binds_flow_to_explicit_generation() {
        let generation = GenerationRef::new("g".repeat(64)).unwrap();
        let plan =
            RoutePlan::from_decision(&RouteDecision::direct("n".to_string()), generation.clone())
                .unwrap();

        // 会话钉的代际必须来自计划——流与计划绑定同一代际
        let pin = SessionPin::for_plan(&plan, "n")
            .with_source_object(ObjectRef::new("sub-a", "node-hash"));
        assert_eq!(pin.generation(), plan.generation());
        assert_eq!(pin.generation().as_str(), &"g".repeat(64));
        assert_eq!(pin.egress(), "n");
        assert_eq!(
            pin.source_object()
                .map(|o| (o.source.as_str(), o.local_id.as_str())),
            Some(("sub-a", "node-hash"))
        );

        // 两种绑定都携带同一钉（TCP/UDP 边界分侧，代际绑定不分侧）
        let tcp = FlowAssociation::Stream { pin: pin.clone() };
        let udp = FlowAssociation::Datagram {
            pin: pin.clone(),
            mapping_key: "5-tuple-1".to_string(),
        };
        assert_eq!(tcp.pin().generation(), &generation);
        assert_eq!(udp.pin().generation(), &generation);
        match udp {
            FlowAssociation::Datagram { mapping_key, .. } => {
                assert_eq!(mapping_key, "5-tuple-1", "datagram 带映射键");
            }
            other => panic!("应为 Datagram，实际 {other:?}"),
        }
    }

    #[test]
    fn generation_ref_rejects_empty() {
        assert!(GenerationRef::new("").is_none(), "空代际身份拒绝");
        let generation = GenerationRef::new("abc").unwrap();
        assert_eq!(generation.as_str(), "abc");
        assert_eq!(generation.to_string(), "abc");
    }
}
