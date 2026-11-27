//! UDP 关联面轨迹接线（RIL-083 第四段）：会话表侧的 [`SessionTracer`]
//! 落点。UDP 关联不走 TCP 的 `FlowOutput` 链（独立泵，relay-path §4），
//! 轨迹事件在会话表的真实生命周期落点上如实产出：
//! - 会话创建（resolve 容量门后）= takeover（采集器准入锚点）；
//! - 粘滞决策产出/重路由 = rule（决策原因在场才发——无原因不造数）+
//!   plan（路径摘要，预测证据）；
//! - 映射绑定成功 = [`CODE_ASSOCIATION_MAPPED`]（观测证据——选中且映射
//!   建成；Reused 复用不发，首绑时已发）；
//! - 控制链/协议会话收口吊销 = [`CODE_ASSOCIATION_RECLAIMED`]；
//! - 空闲/寿命回收 = [`CODE_ASSOCIATION_CLOSED`]。
//!
//! 诚实面：首字节与逐包事件不产（生产泵未逐次测量，不造数——TCP 面
//! 同口径）；接线装配前的会话（生产装配序 attach 先于任何流量）无轨迹
//! 且不回填；开轨失败即降级为不追踪，不阻断数据面。

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime};

use crate::collector::FlowCollector;
use crate::outbound::EvidenceKind;
use crate::plan::{GenerationRef, RoutePlan};
use crate::redact::sanitize_untrusted;
use crate::session_trace::{SessionTracer, CODE_ASSOCIATION_CLOSED, CODE_ASSOCIATION_RECLAIMED};
use crate::trace::{FlowId as TraceFlowId, FlowOrigin};
use crate::{FlowId, RouteDecision, RoutePath};

/// 单调/墙钟锚：进程级一次性基准（流逝部分是真实测量——TCP 面同款）
static TRACE_ANCHOR: OnceLock<Instant> = OnceLock::new();

fn trace_clock_ms() -> (u64, u64) {
    let mono = TRACE_ANCHOR.get_or_init(Instant::now).elapsed().as_millis() as u64;
    let wall = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    (mono, wall)
}

/// UDP 轨迹接线：采集器 + 代际。表构造期无 tokio 上下文、且采集器在
/// Runtime build 后段才存在——装配走 [`crate::udp::UdpSessionTable::
/// attach_trace_wiring`]（与 `attach_chain_events` 同先例）。
pub struct UdpTraceWiring {
    collector: Arc<Mutex<FlowCollector>>,
    generation: GenerationRef,
}

impl UdpTraceWiring {
    /// 装配（代际空白拒绝——流必须绑定明确代际，与 [`GenerationRef`] 同门）
    pub fn new(collector: Arc<Mutex<FlowCollector>>, generation: &str) -> Option<Self> {
        Some(Self {
            collector,
            generation: GenerationRef::new(generation)?,
        })
    }
}

/// 会话轨迹句柄：接线装配后的会话各持一份（会话内层字段）。tracer 为
/// Option = 开轨失败即降级为不追踪（与 TCP wrapper 同降级语义）。
pub struct UdpSessionTrace {
    wiring: Arc<UdpTraceWiring>,
    tracer: Mutex<Option<SessionTracer>>,
}

impl UdpSessionTrace {
    /// 开轨：takeover 为首事件（采集器准入锚点）。`detail` 必须已消毒。
    pub fn start(wiring: &Arc<UdpTraceWiring>, id: &FlowId, detail: String) -> Self {
        let (mono, wall) = trace_clock_ms();
        let tracer = TraceFlowId::new(id.as_uuid().to_string())
            .ok()
            .and_then(|flow_id| {
                SessionTracer::start(
                    Some(Arc::clone(&wiring.collector)),
                    flow_id,
                    FlowOrigin::Association,
                    wiring.generation.as_str(),
                    mono,
                    wall,
                    detail,
                )
                .ok()
            });
        Self {
            wiring: Arc::clone(wiring),
            tracer: Mutex::new(tracer),
        }
    }

    /// 粘滞决策产出/重路由：rule（原因在场才发）+ plan（路径摘要）。
    /// 重路由是真实事件（决策数 >1）——每次产出都如实成对落轨。
    pub fn decision(&self, decision: &RouteDecision) {
        let Some(plan) = RoutePlan::from_decision(decision, self.wiring.generation.clone()) else {
            return;
        };
        if let Some(t) = self.tracer.lock().expect("udp trace poisoned").as_mut() {
            t.rule(&plan);
            t.plan(&plan);
        }
    }

    /// 映射绑定成功（观测证据）：节点 + 映射目标。节点/端点在 tracer
    /// 内按不可信文本消毒（订阅节点名/对端主机名不进注入载荷）。
    pub fn mapped(&self, node: &str, target_host: &str, target_port: u16) {
        if let Some(t) = self.tracer.lock().expect("udp trace poisoned").as_mut() {
            t.egress(node, &format!("{target_host}:{target_port}"), true);
        }
    }

    /// 控制链/协议会话收口吊销（观测证据——SOCKS5 控制连接结束、协议
    /// UDP 面会话收口与管理吊销共用 force_revoke 路径，代码语义 = 先于
    /// 空闲回收的显式回收）
    pub fn close_revoked(&self, detail: &str) {
        if let Some(t) = self.tracer.lock().expect("udp trace poisoned").as_mut() {
            t.close(CODE_ASSOCIATION_RECLAIMED, EvidenceKind::Observed, detail);
        }
    }

    /// 空闲/寿命回收（观测证据）
    pub fn close_expired(&self, detail: &str) {
        if let Some(t) = self.tracer.lock().expect("udp trace poisoned").as_mut() {
            t.close(CODE_ASSOCIATION_CLOSED, EvidenceKind::Observed, detail);
        }
    }
}

/// 决策对应的出口节点名（association.mapped 的 node 口径，与
/// `chain_id_of` 同源取数；链 = 逐跳拼接）
pub fn egress_node_of(decision: &RouteDecision) -> String {
    match &decision.path {
        RoutePath::Direct { node } => node.clone(),
        RoutePath::ThroughGroup { selected_node, .. } => selected_node.clone(),
        RoutePath::Chain { hops } => hops
            .iter()
            .map(|h| h.node.as_str())
            .collect::<Vec<_>>()
            .join(">"),
    }
}

/// takeover detail 构造：粘滞键的客户端 + 认证用户（user 可能来自不可信
/// 对端——整体按不可信文本消毒后才进轨迹）
pub(crate) fn takeover_detail(key: &crate::udp::UdpSessionKey) -> String {
    let mut detail = format!("association client {}", key.client);
    if let Some(user) = &key.user {
        detail.push_str(" user ");
        detail.push_str(user);
    }
    sanitize_untrusted(&detail, 128)
}
