//! 出口建立通道契约（RIL-097 / C24）：把「建立通道」与「业务搬运」分开。
//! 现有 [`crate::EgressConnector::forward`] 把拨号、握手、转发混在一次调用里，
//! 调用方既看不到建立失败的阶段，也拿不到协议包装后的 IO 所有权。本模块
//! 冻结建立期契约：
//!
//! - [`OpenContext`] 携带 session/attempt/generation 身份、截止时间与取消，
//!   **不持有可重新求值的路由器**（io-and-accounting.md §2）——出口只做一次
//!   建立尝试，回退由会话执行器按 RoutePlan 编排；
//! - [`OpenedStream`] / [`OpenedAssociation`] 持有协议包装后的 IO 与握手结果，
//!   加密/分帧状态随 IO 生命周期存在，不泄露给普通复制循环；
//! - [`OpenError`] 分阶段携带稳定原因码、可重试性、证据类型与脱敏上下文。
//!
//! TCP 有序字节流与 UDP 数据报关联是两种生命周期（C22），类型层面分侧
//! （[`StreamOutbound`] / [`DatagramOutbound`]），不共用一次 TCP 式路由决策。

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::plan::GenerationRef;

/// 建立阶段（稳定机器口径）：失败要能说出发生在哪一步，
/// 「超时只说明观测阶段，不自动断言故障责任」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenStage {
    /// 底层拨号（DNS/连接/socket 建立）
    Dial,
    /// 传输层包装（TLS/WS/gRPC/HTTPUpgrade 等）
    Transport,
    /// 协议握手（认证/加密协商/目标绑定）
    Handshake,
    /// 资源池租借
    Pool,
}

impl OpenStage {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            OpenStage::Dial => "dial",
            OpenStage::Transport => "transport",
            OpenStage::Handshake => "handshake",
            OpenStage::Pool => "pool",
        }
    }
}

/// 证据类型：本次失败结论凭什么得出。预测/观测/推断/未知互不混淆
/// （与 RIL-026 质量样本同口径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    /// 实际观测到的错误（系统调用/协议返回）
    Observed,
    /// 由观测推断（例如连续多次超时推断节点不可用）
    Inferred,
    /// 建立前预测（能力表/静态校验）
    Predicted,
    /// 无法确定（外部库无观测点）
    Unknown,
}

impl EvidenceKind {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Observed => "observed",
            EvidenceKind::Inferred => "inferred",
            EvidenceKind::Predicted => "predicted",
            EvidenceKind::Unknown => "unknown",
        }
    }
}

/// 稳定原因码。
pub const CODE_OPEN_TIMEOUT: &str = "outbound.open.timeout";
/// 拨号被拒（连接被拒绝/不可达）
pub const CODE_OPEN_REFUSED: &str = "outbound.open.refused";
/// 传输/协议握手失败
pub const CODE_OPEN_HANDSHAKE: &str = "outbound.open.handshake";
/// 能力不支持该目标/数据报形态（静态拒绝）
pub const CODE_OPEN_UNSUPPORTED: &str = "outbound.open.unsupported";
/// 调用方取消/截止时间已过
pub const CODE_OPEN_CANCELLED: &str = "outbound.open.cancelled";
/// 资源池无可用租借
pub const CODE_OPEN_POOL_EXHAUSTED: &str = "outbound.open.pool_exhausted";

/// 建立失败（分阶段、可诊断）。不含节点凭证或底层秘密：`context` 由适配器
/// 自行脱敏后填入（io-and-accounting.md §2「统一 ConnectFailure 不向客户端
/// 暴露节点凭证或底层秘密」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenError {
    /// 失败阶段
    pub stage: OpenStage,
    /// 稳定原因码（机器判定，不靠文案匹配）
    pub code: &'static str,
    /// 可重试性：同一次会话内重试是否有意义。**不代表应当回退**
    /// （回退由会话执行器按 RoutePlan 决定）
    pub retryable: bool,
    /// 证据类型
    pub evidence: EvidenceKind,
    /// 已脱敏的人读上下文
    pub context: String,
}

impl OpenError {
    /// 构造失败。`context` 必须已脱敏。
    pub fn new(
        stage: OpenStage,
        code: &'static str,
        retryable: bool,
        evidence: EvidenceKind,
        context: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            code,
            retryable,
            evidence,
            context: context.into(),
        }
    }

    /// 超时观测（预测阶段不明责任：evidence 恒 Observed，retryable 由调用方判断）
    pub fn timeout(stage: OpenStage, context: impl Into<String>) -> Self {
        Self::new(
            stage,
            CODE_OPEN_TIMEOUT,
            true,
            EvidenceKind::Observed,
            context,
        )
    }

    /// 取消/截止时间已过（不可重试：调用方已放弃）
    pub fn cancelled(stage: OpenStage) -> Self {
        Self::new(
            stage,
            CODE_OPEN_CANCELLED,
            false,
            EvidenceKind::Observed,
            "cancelled by caller",
        )
    }

    /// 静态不支持（装配期/建立前预测）
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(
            OpenStage::Handshake,
            CODE_OPEN_UNSUPPORTED,
            false,
            EvidenceKind::Predicted,
            detail,
        )
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {} (retryable={}, evidence={}): {}",
            self.code,
            self.stage.as_str(),
            self.retryable,
            self.evidence.as_str(),
            self.context
        )
    }
}

impl std::error::Error for OpenError {}

/// 取消信号：调用方放弃时触发。出口实现必须在建立期检查，
/// 不得等业务搬运开始才响应取消。
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// 新建未取消令牌
    pub fn new() -> Self {
        Self::default()
    }

    /// 请求取消（幂等）
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// 是否已取消
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// 建立上下文：身份 + 时间 + 取消 + 拨号策略引用。
///
/// **不持有 Router**：出口不得重新求值路由；回退由会话执行器按 RoutePlan
/// 编排（io-and-accounting.md §2）。`dial_policy` 是不透明引用，出口只透传。
#[derive(Debug, Clone)]
pub struct OpenContext {
    /// 会话身份
    pub session_id: String,
    /// 尝试序号（同会话内 A 失败后 B 重试时递增，用于诊断对账）
    pub attempt_id: u32,
    /// 流所绑定的代际（RIL-006；确保出口配置与计划同代）
    pub generation: GenerationRef,
    /// 绝对截止时间（毫秒时间戳）；None = 无超时
    pub deadline_ms: Option<u64>,
    /// 取消信号
    pub cancel: CancelToken,
    /// 拨号策略不透明引用（平台旁路/接口绑定等由拨号器解释）
    pub dial_policy: Option<String>,
}

impl OpenContext {
    /// 构造上下文（session_id 为空拒绝——诊断必须能定位会话）
    pub fn new(session_id: impl Into<String>, generation: GenerationRef) -> Option<Self> {
        let session_id = session_id.into();
        if session_id.is_empty() {
            return None;
        }
        Some(Self {
            session_id,
            attempt_id: 0,
            generation,
            deadline_ms: None,
            cancel: CancelToken::new(),
            dial_policy: None,
        })
    }

    /// 设置绝对截止时间
    pub fn with_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    /// 设置尝试序号
    pub fn with_attempt_id(mut self, attempt_id: u32) -> Self {
        self.attempt_id = attempt_id;
        self
    }

    /// 设置拨号策略引用
    pub fn with_dial_policy(mut self, policy: impl Into<String>) -> Self {
        self.dial_policy = Some(policy.into());
        self
    }

    /// 是否已到期（`now_ms` 由调用方提供，避免本模块依赖时钟）
    pub fn is_expired(&self, now_ms: u64) -> bool {
        matches!(self.deadline_ms, Some(d) if now_ms >= d)
    }

    /// 建立前统一检查：取消与到期都按不可重试失败返回。`now_ms` 由实现方提供
    /// （时钟不在本模块内：跨平台口径统一 + 可测试）。
    pub fn check_openable(&self, now_ms: u64) -> Result<(), OpenError> {
        if self.cancel.is_cancelled() {
            return Err(OpenError::cancelled(OpenStage::Dial));
        }
        if self.is_expired(now_ms) {
            return Err(OpenError::cancelled(OpenStage::Dial));
        }
        Ok(())
    }
}

/// 已建立的字节流出口：协议包装后的 IO + 握手结果。
///
/// 协议加密/分帧状态随 `io` 生命周期存在，**不泄露给普通复制循环**——
/// 调用方只能通过 [`OpenedStream::into_parts`] 取走整体 IO。
pub struct OpenedStream {
    name: &'static str,
    endpoint: crate::plan::EndpointRef,
    transport: &'static str,
    handshake_ms: u64,
    io: Box<dyn StreamIo>,
}

/// 已建立的数据报关联：目标绑定形态 + 报文上限 + 源验证与空闲期限。
pub struct OpenedAssociation {
    name: &'static str,
    endpoint: crate::plan::EndpointRef,
    transport: &'static str,
    handshake_ms: u64,
    targets: TargetBinding,
    max_datagram_len: usize,
    idle_timeout_ms: Option<u64>,
    io: Box<dyn DatagramIo>,
}

impl fmt::Debug for OpenedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedStream")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("handshake_ms", &self.handshake_ms)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for OpenedAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedAssociation")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("handshake_ms", &self.handshake_ms)
            .field("targets", &self.targets)
            .field("max_datagram_len", &self.max_datagram_len)
            .field("idle_timeout_ms", &self.idle_timeout_ms)
            .finish_non_exhaustive()
    }
}

impl OpenedStream {
    /// 建立结果（由出口适配器在握手成功后调用）
    pub fn new(
        name: &'static str,
        endpoint: crate::plan::EndpointRef,
        transport: &'static str,
        handshake_ms: u64,
        io: Box<dyn StreamIo>,
    ) -> Self {
        Self {
            name,
            endpoint,
            transport,
            handshake_ms,
            io,
        }
    }

    /// 出口实现名
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// 实际对端端点
    pub fn endpoint(&self) -> &crate::plan::EndpointRef {
        &self.endpoint
    }

    /// 实际传输（`tls` / `ws` / `grpc` / `h2` / `raw` 等，稳定口径）
    pub fn transport(&self) -> &'static str {
        self.transport
    }

    /// 握手耗时（毫秒）
    pub fn handshake_ms(&self) -> u64 {
        self.handshake_ms
    }

    /// 取走 IO（唯一消费入口：协议状态随 IO 走，不单独暴露分帧器）
    pub fn into_parts(self) -> (crate::plan::EndpointRef, &'static str, Box<dyn StreamIo>) {
        (self.endpoint, self.transport, self.io)
    }
}

impl OpenedAssociation {
    /// 建立结果
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'static str,
        endpoint: crate::plan::EndpointRef,
        transport: &'static str,
        handshake_ms: u64,
        targets: TargetBinding,
        max_datagram_len: usize,
        idle_timeout_ms: Option<u64>,
        io: Box<dyn DatagramIo>,
    ) -> Self {
        Self {
            name,
            endpoint,
            transport,
            handshake_ms,
            targets,
            max_datagram_len,
            idle_timeout_ms,
            io,
        }
    }

    /// 出口实现名
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// 实际对端端点
    pub fn endpoint(&self) -> &crate::plan::EndpointRef {
        &self.endpoint
    }

    /// 实际传输
    pub fn transport(&self) -> &'static str {
        self.transport
    }

    /// 握手耗时（毫秒）
    pub fn handshake_ms(&self) -> u64 {
        self.handshake_ms
    }

    /// 目标绑定形态（固定单目标 / 多目标映射）
    pub fn targets(&self) -> &TargetBinding {
        &self.targets
    }

    /// 单报文上限（字节）：超过必须显式失败，不得静默截断
    pub fn max_datagram_len(&self) -> usize {
        self.max_datagram_len
    }

    /// 空闲回收期限（毫秒）；None = 不因空闲回收
    pub fn idle_timeout_ms(&self) -> Option<u64> {
        self.idle_timeout_ms
    }

    /// 取走 IO
    pub fn into_parts(self) -> (crate::plan::EndpointRef, TargetBinding, Box<dyn DatagramIo>) {
        (self.endpoint, self.targets, self.io)
    }
}

/// 数据报目标绑定形态（io-and-accounting.md §3）：固定目标与多目标映射
/// 生命周期不同，不得把多目标塞进一次 TCP 式路由决策。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetBinding {
    /// 固定单目标（如 SOCKS5 UDP ASSOCIATE 绑定的单一对端）
    Fixed {
        /// 目标端点
        target: crate::plan::EndpointRef,
    },
    /// 多目标映射（每个目标独立保持出口粘性）
    Multi {
        /// 已允许的目标集合（空白 = 由实现自行准入）
        allowed: Vec<crate::plan::EndpointRef>,
    },
}

impl TargetBinding {
    /// 是否允许发往该目标（Fixed 须精确匹配；Multi 空集合表示实现自决）
    pub fn allows(&self, target: &crate::plan::EndpointRef) -> bool {
        match self {
            TargetBinding::Fixed { target: fixed } => fixed == target,
            TargetBinding::Multi { allowed } => allowed.is_empty() || allowed.contains(target),
        }
    }
}

/// 字节流 IO（协议包装后的整体句柄）。实现方持有加密/分帧状态，
/// 上层只做字节搬运。
#[async_trait]
pub trait StreamIo: Send + Sync {
    /// 写入全部字节（部分写由实现内部处理，返回实际写入字节数）
    async fn write_all(&mut self, data: Bytes) -> Result<usize, OpenError>;

    /// 读取至多 `max` 字节；Ok(None) = 对端正常关闭
    async fn read(&mut self, max: usize) -> Result<Option<Bytes>, OpenError>;

    /// 半关闭写侧（TCP 语义）
    async fn shutdown_write(&mut self) -> Result<(), OpenError>;
}

/// 数据报 IO：单报文写入/读取 + 目标标识（多目标映射必须回带目标）。
#[async_trait]
pub trait DatagramIo: Send + Sync {
    /// 发送一条数据报（超过 `max_datagram_len` 必须显式失败）
    async fn send(
        &mut self,
        target: &crate::plan::EndpointRef,
        payload: Bytes,
    ) -> Result<(), OpenError>;

    /// 接收一条数据报（返回来源目标与载荷）
    async fn recv(&mut self) -> Result<Option<(crate::plan::EndpointRef, Bytes)>, OpenError>;
}

/// 字节流出口建立契约（RIL-097）。
///
/// 建立只做一次尝试：失败即返回 [`OpenError`]，**不得在内部重试或改选
/// 其它出口**——回退归会话执行器（io-and-accounting.md §2）。
#[async_trait]
pub trait StreamOutbound: Send + Sync {
    /// 实现名（稳定诊断口径）
    fn name(&self) -> &'static str;

    /// 能力声明（静态，装配期可校验）
    fn capabilities(&self) -> OutboundCapabilities;

    /// 建立到 `target` 的字节流通道
    async fn open_stream(
        &self,
        target: &crate::plan::EndpointRef,
        ctx: &OpenContext,
    ) -> Result<OpenedStream, OpenError>;
}

/// 数据报出口建立契约（RIL-097）。
#[async_trait]
pub trait DatagramOutbound: Send + Sync {
    /// 实现名
    fn name(&self) -> &'static str;

    /// 能力声明
    fn capabilities(&self) -> OutboundCapabilities;

    /// 建立数据报关联
    async fn open_association(
        &self,
        target: &TargetBinding,
        ctx: &OpenContext,
    ) -> Result<OpenedAssociation, OpenError>;
}

/// 出口能力声明（静态）。配置校验/装配期诊断使用，运行期动态失败仍按
/// `OpenError` 类型报告。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundCapabilities {
    /// 支持字节流
    pub stream: bool,
    /// 支持数据报
    pub datagram: bool,
    /// 支持的传输组合（稳定名，如 `tls`/`ws`/`grpc`；空 = 仅 raw）
    pub transports: Vec<&'static str>,
    /// 单报文上限（数据报能力为真时有效）
    pub max_datagram_len: Option<usize>,
    /// 是否需要固定目标（不支持多目标映射）
    pub fixed_target_only: bool,
    /// 是否可提供预热点（资源池）
    pub supports_prewarm: bool,
    /// 是否支持多路复用子流
    pub supports_multiplex: bool,
}

impl OutboundCapabilities {
    /// 仅字节流（raw 传输）
    pub fn stream_only() -> Self {
        Self {
            stream: true,
            ..Default::default()
        }
    }

    /// 字节流 + 数据报
    pub fn stream_and_datagram(max_datagram_len: usize) -> Self {
        Self {
            stream: true,
            datagram: true,
            max_datagram_len: Some(max_datagram_len),
            ..Default::default()
        }
    }

    /// 声明支持某传输
    pub fn with_transport(mut self, transport: &'static str) -> Self {
        self.transports.push(transport);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation() -> GenerationRef {
        GenerationRef::new("gen-abc").expect("非空代际")
    }

    /// 建立上下文必须绑定会话与非空代际；空会话拒绝
    #[test]
    fn open_context_requires_session_and_generation() {
        assert!(OpenContext::new("", generation()).is_none());
        let ctx = OpenContext::new("s-1", generation()).expect("合法上下文");
        assert_eq!(ctx.session_id, "s-1");
        assert_eq!(ctx.attempt_id, 0);
        assert!(ctx.deadline_ms.is_none());
    }

    /// 到期与取消都在建立前拦下，且不可重试
    #[test]
    fn expired_and_cancelled_are_not_retryable() {
        let ctx = OpenContext::new("s-1", generation())
            .unwrap()
            .with_deadline_ms(1_000);
        assert!(ctx.is_expired(1_000), "到点即到期");
        assert!(!ctx.is_expired(999));
        let err = ctx.check_openable(1_000).unwrap_err();
        assert_eq!(err.code, CODE_OPEN_CANCELLED);
        assert!(!err.retryable);

        let ctx2 = OpenContext::new("s-2", generation()).unwrap();
        ctx2.cancel.cancel();
        let err2 = ctx2.check_openable(0).unwrap_err();
        assert_eq!(err2.code, CODE_OPEN_CANCELLED);
        assert!(!err2.retryable);
    }

    /// 失败携带阶段 + 原因码 + 证据类型，文案只作补充
    #[test]
    fn open_error_carries_stage_code_and_evidence() {
        let err = OpenError::timeout(OpenStage::Transport, "tls handshake timed out");
        assert_eq!(err.stage.as_str(), "transport");
        assert_eq!(err.code, CODE_OPEN_TIMEOUT);
        assert_eq!(err.evidence, EvidenceKind::Observed);
        assert!(err.to_string().contains("outbound.open.timeout"));

        let predicted = OpenError::unsupported("no ws over quic");
        assert_eq!(predicted.evidence, EvidenceKind::Predicted);
        assert!(!predicted.retryable, "静态不支持不可重试");
        assert_eq!(predicted.code, CODE_OPEN_UNSUPPORTED);
    }

    /// 固定目标须精确匹配；多目标空集合表示实现自决
    #[test]
    fn target_binding_semantics() {
        let a = crate::plan::EndpointRef::new("1.1.1.1", 53);
        let b = crate::plan::EndpointRef::new("8.8.8.8", 53);
        let fixed = TargetBinding::Fixed { target: a.clone() };
        assert!(fixed.allows(&a));
        assert!(!fixed.allows(&b), "固定目标不得旁落到其它对端");

        let multi_open = TargetBinding::Multi { allowed: vec![] };
        assert!(multi_open.allows(&a) && multi_open.allows(&b));
        let multi_closed = TargetBinding::Multi {
            allowed: vec![a.clone()],
        };
        assert!(multi_closed.allows(&a));
        assert!(!multi_closed.allows(&b));
    }

    /// 能力声明是静态口径：数据报能力须带报文上限
    #[test]
    fn capabilities_shape() {
        let s = OutboundCapabilities::stream_only();
        assert!(s.stream && !s.datagram);
        assert!(s.max_datagram_len.is_none());

        let d = OutboundCapabilities::stream_and_datagram(1500).with_transport("tls");
        assert!(d.datagram);
        assert_eq!(d.max_datagram_len, Some(1500));
        assert_eq!(d.transports, vec!["tls"]);
    }
}
