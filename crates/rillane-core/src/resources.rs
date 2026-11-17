//! 能力声明与池资源类型（RIL-100 / io-and-accounting.md §4）。
//!
//! 两条冻结边界：
//!
//! - **同源能力描述**：[`assemble_backend`] 是支持表校验的唯一权威
//!   地点——实现声明的 [`OutboundCapabilities`]（RIL-097）+ 传输栈
//!   （RIL-099）+ 复用类（RIL-028）在此**一次**合并校验，产出
//!   [`AssembledBackend`]；importer/runtime/connector 只消费装配结果，
//!   不各自扫描配置维护第二份支持表。静态不支持在装配期诊断
//!   （`resource.capability.*`），动态失败仍在建立期按类型报告；
//! - **池资源类型与租借键**：预热消费 / 独占目标绑定 / 多路复用
//!   会话是三种生命周期（[`PoolResourceKind`]），租借键
//!   [`LeaseKey`] 携带代际/节点/目标/凭证/安全配置——不同租户、
//!   凭证或代际**结构性不混借**；[`LeaseGuard`] 是唯一的生命周期
//!   所有者句柄——初始化、消费、drain、取消、关闭每一步都有明确
//!   所有者，非法迁移以 `resource.lease.invalid_state` 拒绝。TLS
//!   会话恢复与连接复用在类型上分开（前者独占取出，后者共享），
//!   恢复票据等密钥留在资源侧，租借键只携带**标签**不携带密钥。

use std::fmt;

use crate::outbound::OutboundCapabilities;
use crate::plan::EndpointRef;
use crate::pool::TransportReuse;
use crate::underlay::{TransportStack, STREAM_TRANSPORTS};

// ---------------------------------------------------------------------------
// 稳定原因码
// ---------------------------------------------------------------------------

/// 传输栈声明的承载超出实现能力表（装配期静态拒绝）
pub const CODE_CAP_TRANSPORT: &str = "resource.capability.transport_unsupported";
/// 复用类声明与能力表矛盾（装配期静态拒绝）
pub const CODE_CAP_REUSE: &str = "resource.capability.reuse_unsupported";
/// 数据报/流能力与目标绑定声明矛盾（装配期静态拒绝）
pub const CODE_CAP_SHAPE: &str = "resource.capability.shape_mismatch";
/// 重依赖后端未声明 feature 门（装配期静态拒绝——构建图必须能排除）
pub const CODE_CAP_FEATURE: &str = "resource.capability.feature_undeclared";
/// 租借键非法（节点/凭证空白）
pub const CODE_KEY_INVALID: &str = "resource.lease_key.invalid";
/// 租借生命周期非法迁移（无所有者纪律）
pub const CODE_LEASE_STATE: &str = "resource.lease.invalid_state";

// ---------------------------------------------------------------------------
// 同源能力装配
// ---------------------------------------------------------------------------

/// 后端声明：实现提供、Factory 在此合并校验（io-and-accounting.md §4
/// 「能力由实现提供并由 Factory 合并校验」）。
#[derive(Debug, Clone)]
pub struct BackendDeclaration {
    /// 后端名（稳定诊断口径）
    pub name: &'static str,
    /// 能力表（RIL-097 静态声明——支持表的唯一来源）
    pub capabilities: OutboundCapabilities,
    /// 传输栈（RIL-099 语法已校验）
    pub transport_stack: TransportStack,
    /// 传输复用类（RIL-028 口径）
    pub reuse: TransportReuse,
    /// 后端依赖 feature 门（重依赖按 feature/crate 排除；非空 = 该后端
    /// 在构建图可排除。声明与实现一致由装配期校验）
    pub feature_gates: Vec<&'static str>,
}

/// 装配结果：全部一致性检查通过后的唯一后端视图——importer/runtime/
/// connector 消费同一份，不再各自维护支持表。
#[derive(Debug, Clone)]
pub struct AssembledBackend {
    name: &'static str,
    capabilities: OutboundCapabilities,
    transport_stack: TransportStack,
    reuse: TransportReuse,
    feature_gates: Vec<&'static str>,
}

impl AssembledBackend {
    /// 后端名
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// 已校验能力表（只读）
    pub fn capabilities(&self) -> &OutboundCapabilities {
        &self.capabilities
    }

    /// 已校验传输栈（只读）
    pub fn transport_stack(&self) -> &TransportStack {
        &self.transport_stack
    }

    /// 复用类
    pub fn reuse(&self) -> TransportReuse {
        self.reuse
    }

    /// feature 门（构建图排除面）
    pub fn feature_gates(&self) -> &[&'static str] {
        &self.feature_gates
    }
}

/// 装配期合并校验（io-and-accounting.md §4/§7）：
///
/// - 栈内每个承载都必须在能力表 `transports` 里（支持表唯一来源——
///   importer 不另行放行）；
/// - 复用类与能力表一致：多路复用须声明 `supports_multiplex`；
///   TLS 恢复须栈内有 `tls` 且**不得**同时声明多路复用（TLS 会话
///   恢复与连接复用分开管理——前者独占取出，后者共享）；
///   无复用类不得声明预热/多路复用能力（不伪造）；
/// - 形状一致：声明数据报能力须 `datagram` 与 `max_datagram_len`
///   同真同假（上限是显式面）；
/// - `feature_gates` 非空是重依赖后端装配的前提（构建图可排除——
///   「重依赖以 feature 或独立 crate 隔离」）。
pub fn assemble_backend(decl: &BackendDeclaration) -> Result<AssembledBackend, ResourceError> {
    if decl.feature_gates.is_empty() {
        return Err(ResourceError::new(
            CODE_CAP_FEATURE,
            format!(
                "backend {} carries dependencies but declares no feature gate",
                decl.name
            ),
        ));
    }
    for layer in decl.transport_stack.layers() {
        if !decl.capabilities.transports.contains(layer) {
            return Err(ResourceError::new(
                CODE_CAP_TRANSPORT,
                format!(
                    "stack layer {layer} not in declared transports {:?}",
                    decl.capabilities.transports
                ),
            ));
        }
        if !STREAM_TRANSPORTS.contains(layer) {
            return Err(ResourceError::new(
                CODE_CAP_TRANSPORT,
                format!("stack layer {layer} is not a declared stream transport"),
            ));
        }
    }
    match decl.reuse {
        TransportReuse::Multiplexed => {
            if !decl.capabilities.supports_multiplex {
                return Err(ResourceError::new(
                    CODE_CAP_REUSE,
                    "multiplex reuse declared without supports_multiplex",
                ));
            }
        }
        TransportReuse::TlsResumption => {
            if !decl.transport_stack.layers().contains(&"tls") {
                return Err(ResourceError::new(
                    CODE_CAP_REUSE,
                    "tls resumption requires tls in the transport stack",
                ));
            }
            if decl.capabilities.supports_multiplex {
                return Err(ResourceError::new(
                    CODE_CAP_REUSE,
                    "tls resumption and multiplex reuse are distinct resources — declare one",
                ));
            }
        }
        TransportReuse::None => {
            if decl.capabilities.supports_multiplex || decl.capabilities.supports_prewarm {
                return Err(ResourceError::new(
                    CODE_CAP_REUSE,
                    "no-reuse backend cannot claim prewarm or multiplex capability",
                ));
            }
        }
    }
    if decl.capabilities.datagram != decl.capabilities.max_datagram_len.is_some() {
        return Err(ResourceError::new(
            CODE_CAP_SHAPE,
            "datagram capability and max_datagram_len must agree",
        ));
    }
    Ok(AssembledBackend {
        name: decl.name,
        capabilities: decl.capabilities.clone(),
        transport_stack: decl.transport_stack.clone(),
        reuse: decl.reuse,
        feature_gates: decl.feature_gates.clone(),
    })
}

// ---------------------------------------------------------------------------
// 池资源类型与租借键
// ---------------------------------------------------------------------------

/// 池资源三态（io-and-accounting.md §4）：生命周期不同，不混用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolResourceKind {
    /// 预热连接：未使用，**取出即消费**（消费后不回池——一次性）
    Prewarm,
    /// 独占已绑定目标通道：一次服务一个会话；按协议判断是否可回收
    Exclusive {
        /// 已绑定的目标
        target: EndpointRef,
        /// 协议是否允许回收（不可回收资源关闭即弃，不回池）
        reclaimable: bool,
    },
    /// 可多路复用会话：创建子流共享（子流上限在池限，不在资源内伪造）
    Multiplexed,
}

impl PoolResourceKind {
    /// 机器口径
    pub fn as_str(&self) -> &'static str {
        match self {
            PoolResourceKind::Prewarm => "prewarm",
            PoolResourceKind::Exclusive { .. } => "exclusive",
            PoolResourceKind::Multiplexed => "multiplexed",
        }
    }
}

/// 租借键：池键携带**代际/节点身份、目标绑定与相关传输/安全配置**
/// ——不同租户/凭证/代际结构性不混借（任一字段不同 = 不同资源）。
/// 只携带配置标签与身份，不携带密钥（密钥留在资源侧）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseKey {
    /// 代际（配置与出口同代——跨代租借即混借旧配置）
    pub generation: String,
    /// 节点身份（非空）
    pub node: String,
    /// 目标绑定（多路复用会话可空——子流自定目标）
    pub target: Option<EndpointRef>,
    /// 凭证/租户身份（非空——不同凭证不混借）
    pub credential: String,
    /// 传输/安全配置标签（如 `tls`/`tls-resume`/`ws`；顺序无关，
    /// 语义相同才算同键——内部保持排序）
    pub security: Vec<&'static str>,
}

impl LeaseKey {
    /// 构造租借键（节点/凭证空白拒绝；安全标签排序规范化——同配置
    /// 不同书写顺序是同键）
    pub fn new(
        generation: impl Into<String>,
        node: impl Into<String>,
        target: Option<EndpointRef>,
        credential: impl Into<String>,
        security: &[&'static str],
    ) -> Result<Self, ResourceError> {
        let generation = generation.into();
        let node = node.into();
        let credential = credential.into();
        if node.is_empty() {
            return Err(ResourceError::new(CODE_KEY_INVALID, "node id empty"));
        }
        if credential.is_empty() {
            return Err(ResourceError::new(CODE_KEY_INVALID, "credential id empty"));
        }
        if generation.is_empty() {
            return Err(ResourceError::new(CODE_KEY_INVALID, "generation empty"));
        }
        let mut tags = security.to_vec();
        tags.sort_unstable();
        tags.dedup();
        Ok(Self {
            generation,
            node,
            target,
            credential,
            security: tags,
        })
    }
}

/// 资源生命周期错误（稳定码 + 已脱敏细节）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceError {
    /// 稳定原因码
    pub code: &'static str,
    /// 已脱敏细节
    pub detail: String,
}

impl ResourceError {
    /// 构造错误
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ResourceError {}

/// 租借生命周期状态：每一步迁移都有唯一所有者动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseState {
    /// 使用中（唯一可出发的状态）
    InUse,
    /// 消费（Prewarm 一次性取出——终态，不回池）
    Consumed,
    /// 排水中（所有者主动——不再接收新子流/新借用，存量收尾）
    Draining {
        /// 已脱敏原因
        reason: String,
    },
    /// 已取消（所有者放弃——存量即弃）
    Cancelled {
        /// 已脱敏原因
        reason: String,
    },
    /// 已关闭（资源交还调用方关闭——终态）
    Closed,
}

/// 租借守卫：**唯一**的生命周期所有者句柄。初始化（构造）→ 使用 →
/// 消费/drain/取消 → 关闭的每一步只有持有人能驱动；非法迁移显式拒绝
/// （不静默、不重复关）。
#[derive(Debug)]
pub struct LeaseGuard {
    key: LeaseKey,
    kind: PoolResourceKind,
    state: LeaseState,
}

impl LeaseGuard {
    /// 初始化租借（初始化的所有者是构造者——池在租出时构造）
    pub fn begin(key: LeaseKey, kind: PoolResourceKind) -> Self {
        Self {
            key,
            kind,
            state: LeaseState::InUse,
        }
    }

    /// 租借键（只读）
    pub fn key(&self) -> &LeaseKey {
        &self.key
    }

    /// 资源类型
    pub fn kind(&self) -> &PoolResourceKind {
        &self.kind
    }

    /// 当前状态（只读）
    pub fn state(&self) -> &LeaseState {
        &self.state
    }

    /// 预热取出即消费（仅 Prewarm；一次性——终态不回池）
    pub fn consume(mut self) -> Result<LeaseKey, ResourceError> {
        if self.kind != PoolResourceKind::Prewarm || self.state != LeaseState::InUse {
            return Err(ResourceError::new(
                CODE_LEASE_STATE,
                format!(
                    "consume requires in-use prewarm, got {} / {}",
                    self.kind.as_str(),
                    self.state_name()
                ),
            ));
        }
        self.state = LeaseState::Consumed;
        Ok(self.key)
    }

    /// 所有者发起排水（InUse → Draining；drain 后仍可关闭）
    pub fn drain(mut self, reason: impl Into<String>) -> Result<Self, ResourceError> {
        if self.state != LeaseState::InUse {
            return Err(ResourceError::new(
                CODE_LEASE_STATE,
                format!("drain requires in-use, got {}", self.state_name()),
            ));
        }
        self.state = LeaseState::Draining {
            reason: reason.into(),
        };
        Ok(self)
    }

    /// 所有者取消（InUse/Draining → Cancelled；取消的资源即弃不回池）
    pub fn cancel(mut self, reason: impl Into<String>) -> Result<Self, ResourceError> {
        if !matches!(self.state, LeaseState::InUse | LeaseState::Draining { .. }) {
            return Err(ResourceError::new(
                CODE_LEASE_STATE,
                format!(
                    "cancel requires in-use or draining, got {}",
                    self.state_name()
                ),
            ));
        }
        self.state = LeaseState::Cancelled {
            reason: reason.into(),
        };
        Ok(self)
    }

    /// 关闭（终态；Draining/Cancelled/InUse 均可关——唯一出口，
    /// 重复关闭拒绝）
    pub fn close(mut self) -> Result<LeaseKey, ResourceError> {
        if self.state == LeaseState::Closed {
            return Err(ResourceError::new(CODE_LEASE_STATE, "already closed"));
        }
        self.state = LeaseState::Closed;
        Ok(self.key)
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            LeaseState::InUse => "in_use",
            LeaseState::Consumed => "consumed",
            LeaseState::Draining { .. } => "draining",
            LeaseState::Cancelled { .. } => "cancelled",
            LeaseState::Closed => "closed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundCapabilities;
    use crate::pool::TransportReuse;
    use crate::underlay::TransportStack;

    fn backend(
        name: &'static str,
        transports: &[&'static str],
        stack: &[&'static str],
        reuse: TransportReuse,
        gates: &[&'static str],
    ) -> BackendDeclaration {
        BackendDeclaration {
            name,
            capabilities: OutboundCapabilities {
                stream: true,
                transports: transports.to_vec(),
                supports_multiplex: reuse == TransportReuse::Multiplexed,
                supports_prewarm: reuse != TransportReuse::None,
                ..Default::default()
            },
            transport_stack: TransportStack::build(stack).expect("合法栈"),
            reuse,
            feature_gates: gates.to_vec(),
        }
    }

    /// 同源能力装配：合法声明过检；栈层超能力表/复用类矛盾/
    /// 无 feature 门各自静态拒绝（支持表唯一来源——importer 不另行放行）
    #[test]
    fn assembly_is_single_source_of_truth() {
        let ok = backend(
            "vless-ws-tls",
            &["tls", "ws"],
            &["tls", "ws"],
            TransportReuse::TlsResumption,
            &["rustls"],
        );
        let assembled = assemble_backend(&ok).expect("合法装配");
        assert_eq!(assembled.name(), "vless-ws-tls");
        assert_eq!(assembled.transport_stack().layers(), &["tls", "ws"]);
        assert_eq!(assembled.reuse(), TransportReuse::TlsResumption);
        assert_eq!(assembled.feature_gates(), &["rustls"]);

        // 栈声明了能力表之外的承载——装配期拒绝（零拨号面）
        let over = backend(
            "over-claims",
            &["tls"],
            &["tls", "ws"],
            TransportReuse::TlsResumption,
            &["rustls"],
        );
        let err = assemble_backend(&over).unwrap_err();
        assert_eq!(err.code, CODE_CAP_TRANSPORT);
        assert!(err.detail.contains("ws"));

        // 多路复用未声明
        let mux = backend(
            "mux",
            &["tls"],
            &["tls"],
            TransportReuse::Multiplexed,
            &["h2"],
        );
        let mut mux = mux;
        mux.capabilities.supports_multiplex = false;
        assert_eq!(assemble_backend(&mux).unwrap_err().code, CODE_CAP_REUSE);

        // TLS 恢复但栈里没有 tls
        let no_tls = backend(
            "no-tls",
            &["ws"],
            &["ws"],
            TransportReuse::TlsResumption,
            &["rustls"],
        );
        assert_eq!(assemble_backend(&no_tls).unwrap_err().code, CODE_CAP_REUSE);

        // TLS 恢复与多路复用互斥（两种资源不混装）
        let both = backend(
            "both",
            &["tls"],
            &["tls"],
            TransportReuse::TlsResumption,
            &["rustls"],
        );
        let mut both = both;
        both.capabilities.supports_multiplex = true;
        assert_eq!(assemble_backend(&both).unwrap_err().code, CODE_CAP_REUSE);

        // 无复用类却声明预热/多路复用能力（不伪造）
        let mut fake = backend("fake", &[], &[], TransportReuse::None, &["x"]);
        fake.capabilities.supports_prewarm = true;
        assert_eq!(assemble_backend(&fake).unwrap_err().code, CODE_CAP_REUSE);
        let mut fake2 = backend("fake2", &[], &[], TransportReuse::None, &["x"]);
        fake2.capabilities.supports_multiplex = true;
        assert_eq!(assemble_backend(&fake2).unwrap_err().code, CODE_CAP_REUSE);

        // 重依赖未声明 feature 门
        let ungated = backend(
            "ungated",
            &["tls"],
            &["tls"],
            TransportReuse::TlsResumption,
            &[],
        );
        assert_eq!(
            assemble_backend(&ungated).unwrap_err().code,
            CODE_CAP_FEATURE
        );
    }

    /// 数据报能力与报文上限同真同假
    #[test]
    fn datagram_shape_must_agree() {
        let mut decl = backend(
            "udp",
            &["tls"],
            &["tls"],
            TransportReuse::TlsResumption,
            &["rustls"],
        );
        decl.capabilities.datagram = true;
        decl.capabilities.max_datagram_len = None;
        assert_eq!(assemble_backend(&decl).unwrap_err().code, CODE_CAP_SHAPE);

        decl.capabilities.datagram = false;
        decl.capabilities.max_datagram_len = Some(1500);
        assert_eq!(assemble_backend(&decl).unwrap_err().code, CODE_CAP_SHAPE);
    }

    /// 租借键隔离：任一字段不同即不同键——代际/凭证/目标/安全配置
    /// 结构性不混借；安全标签顺序无关；空白节点/凭证拒绝
    #[test]
    fn lease_keys_isolate_identity() {
        let base = LeaseKey::new(
            "g1",
            "node-a",
            Some(EndpointRef::new("1.2.3.4", 443)),
            "tenant-1",
            &["tls", "ws"],
        )
        .expect("合法键");
        let same = LeaseKey::new(
            "g1",
            "node-a",
            Some(EndpointRef::new("1.2.3.4", 443)),
            "tenant-1",
            &["ws", "tls"],
        )
        .expect("合法键");
        assert_eq!(base, same, "安全标签顺序无关");

        let gen2 = LeaseKey::new(
            "g2",
            "node-a",
            base.target.clone(),
            "tenant-1",
            &["tls", "ws"],
        )
        .expect("合法键");
        let cred2 = LeaseKey::new(
            "g1",
            "node-a",
            base.target.clone(),
            "tenant-2",
            &["tls", "ws"],
        )
        .expect("合法键");
        let node2 = LeaseKey::new(
            "g1",
            "node-b",
            base.target.clone(),
            "tenant-1",
            &["tls", "ws"],
        )
        .expect("合法键");
        let target2 = LeaseKey::new(
            "g1",
            "node-a",
            Some(EndpointRef::new("5.6.7.8", 443)),
            "tenant-1",
            &["tls", "ws"],
        )
        .expect("合法键");
        let sec2 = LeaseKey::new("g1", "node-a", base.target.clone(), "tenant-1", &["tls"])
            .expect("合法键");
        assert_ne!(base, gen2, "跨代不混借");
        assert_ne!(base, cred2, "跨凭证不混借");
        assert_ne!(base, node2, "跨节点不混借");
        assert_ne!(base, target2, "跨目标不混借");
        assert_ne!(base, sec2, "跨安全配置不混借");

        assert!(LeaseKey::new("g1", "", None, "t", &[]).is_err());
        assert!(LeaseKey::new("g1", "n", None, "", &[]).is_err());
        assert_eq!(
            LeaseKey::new("g1", "", None, "t", &[]).unwrap_err().code,
            CODE_KEY_INVALID
        );
    }

    /// 生命周期所有者纪律：预热一次性取出；drain/取消/关闭各自唯一
    /// 出口；非法迁移显式拒绝
    #[test]
    fn lease_lifecycle_has_owners() {
        let key = LeaseKey::new("g1", "n", None, "t", &[]).expect("键");
        // 预热取出即消费（一次性——终态）
        let prewarm = LeaseGuard::begin(key.clone(), PoolResourceKind::Prewarm);
        let consumed = prewarm.consume().expect("取出");
        assert_eq!(consumed, key);
        // 独占绑定目标：drain → 关闭
        let exclusive = LeaseGuard::begin(
            key.clone(),
            PoolResourceKind::Exclusive {
                target: EndpointRef::new("1.2.3.4", 443),
                reclaimable: true,
            },
        );
        let drained = exclusive.drain("generation rotated").expect("排水");
        assert_eq!(
            drained.state(),
            &LeaseState::Draining {
                reason: "generation rotated".to_string()
            }
        );
        let closed = drained.close().expect("关闭");
        assert_eq!(closed, key);
        // 取消路径：InUse → Cancelled → 关闭
        let cancelled = LeaseGuard::begin(key.clone(), PoolResourceKind::Multiplexed)
            .cancel("pool shutdown")
            .expect("取消");
        assert_eq!(
            cancelled.state(),
            &LeaseState::Cancelled {
                reason: "pool shutdown".to_string()
            }
        );
        assert!(cancelled.close().is_ok());
        // 非法迁移显式拒绝（不静默）：独占资源不可「取出即消费」
        let exclusive2 = LeaseGuard::begin(
            key.clone(),
            PoolResourceKind::Exclusive {
                target: EndpointRef::new("1.2.3.4", 443),
                reclaimable: false,
            },
        );
        let err = exclusive2.consume().unwrap_err();
        assert_eq!(err.code, CODE_LEASE_STATE);
        assert!(err.detail.contains("exclusive"));
        // 关闭语义：守卫按值消费——重复关闭在结构上不可能（单所有者）；
        // 未消费预热先关闭合法（池回收预热也是所有者动作）
        let pre2 = LeaseGuard::begin(key.clone(), PoolResourceKind::Prewarm);
        let closed_key = pre2.close().expect("未消费先关闭合法");
        assert_eq!(closed_key, key);
    }
}
