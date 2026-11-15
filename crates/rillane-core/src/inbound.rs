//! 入口两阶段接入契约（RIL-096 / C23）：把「认证/解析准入」与「路由/建立出口」
//! 分开。现有 [`crate::IngressEndpoint::run`] 把监听、认证、路由、拨号、回复、
//! 转发混在一次调用里；本模块冻结两阶段路径（io-and-accounting.md §2）：
//!
//! SOCKS5 CONNECT / HTTP CONNECT：认证/解析目标 → [`PendingStream`] →
//! 路由/建立出口 → 成功回复 → [`AcceptedStream`] → 双向转发。
//!
//! - [`PendingStream`] 独占客户端通道与 responder：`accept`/`reject` 只执行
//!   一次；出口**成功后才回复成功**，失败时把结构化错误映射为入口协议错误，
//!   不能先报告连接成功；
//! - 成功回复失败时，[`PendingStream::accept`] 就地释放已建立的出口
//!   （出口所有权在 accept 内，失败路径 drop，结构上保证不泄漏）；
//! - 取消/超时直接丢弃 [`PendingStream`]：通道关闭、responder 不触发，
//!   不重复回复；
//! - [`PendingAssociation`] 承载 UDP 准入：来源校验（`SourceKey`）、目标绑定
//!   复用 RIL-097 [`crate::outbound::TargetBinding`]，控制连接结束
//!   （[`ControlLink::is_closed`]）后按契约回收关联资源；
//! - [`IngressOrigin::Capture`]（TUN）的回复由用户态网络栈驱动，**不套用
//!   代理回复模型**：TUN 适配器提供栈驱动的 responder，`reject` 语义是
//!   会话复位而非代理错误回复；
//! - [`InboundSpec`] / [`InboundFactory`] 在装配期校验入口组合，入口配置
//!   不参与出口选择（spec 结构上不含路由/出口引用）。
//!
//! 入口只管理认证/握手/准入资源；建立后的会话预算由 SessionExecutor 管理
//! （RIL-098 接线）。

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::outbound::TargetBinding;
use crate::outbound::{CancelToken, EvidenceKind, OpenError, OpenedStream};
use crate::plan::EndpointRef;

/// 接入阶段（稳定机器口径）：错误发生在认证解析、准入判定、回复写入
/// 还是装配校验，一眼可辨。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundStage {
    /// 装配期（spec/factory 校验）
    Factory,
    /// 认证/协议解析（客户端握手）
    Handshake,
    /// 准入判定（accept/reject/取消/一次性消费）
    Admit,
    /// 成功/失败回复写入
    Reply,
}

impl InboundStage {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            InboundStage::Factory => "factory",
            InboundStage::Handshake => "handshake",
            InboundStage::Admit => "admit",
            InboundStage::Reply => "reply",
        }
    }
}

/// 稳定原因码。
pub const CODE_INBOUND_UNSUPPORTED: &str = "inbound.unsupported";
/// 客户端认证失败
pub const CODE_INBOUND_AUTH: &str = "inbound.auth";
/// 协议解析/握手失败（版本、报文格式）
pub const CODE_INBOUND_HANDSHAKE: &str = "inbound.handshake";
/// 策略/准入拒绝（不含出口失败——出口失败用其自身稳定码透传）
pub const CODE_INBOUND_REJECTED: &str = "inbound.rejected";
/// 取消/超时，接入未完成即关闭
pub const CODE_INBOUND_CANCELLED: &str = "inbound.cancelled";
/// 出口已建立但成功回复写失败（出口必须就地释放）
pub const CODE_INBOUND_REPLY_FAILED: &str = "inbound.reply_failed";
/// responder 二次消费（编程错误，非运行态）
pub const CODE_INBOUND_RESPONDER_CONSUMED: &str = "inbound.responder_consumed";
/// 来源校验失败（UDP 关联准入缺合法来源身份）
pub const CODE_INBOUND_SOURCE_INVALID: &str = "inbound.source_invalid";

/// 接入失败（分阶段、可诊断）。`context` 由适配器自行脱敏后填入；
/// 不向客户端暴露节点凭证或底层秘密——对外只经 [`RejectCause`] 映射
/// 为入口协议错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundError {
    /// 失败阶段
    pub stage: InboundStage,
    /// 稳定原因码（机器判定，不靠文案匹配）
    pub code: &'static str,
    /// 可重试性（同监听器继续接新客户端是否有意义）
    pub retryable: bool,
    /// 证据类型（预测/观测/推断/未知，与 RIL-097 同口径互不混淆）
    pub evidence: EvidenceKind,
    /// 已脱敏的人读上下文
    pub context: String,
}

impl InboundError {
    /// 构造失败。`context` 必须已脱敏。
    pub fn new(
        stage: InboundStage,
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

    /// 取消/超时（调用方已放弃，不可重试）
    pub fn cancelled() -> Self {
        Self::new(
            InboundStage::Admit,
            CODE_INBOUND_CANCELLED,
            false,
            EvidenceKind::Observed,
            "cancelled by caller",
        )
    }

    /// 装配期不支持（静态预测）
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(
            InboundStage::Factory,
            CODE_INBOUND_UNSUPPORTED,
            false,
            EvidenceKind::Predicted,
            detail,
        )
    }

    /// responder 二次消费（编程错误，装配即可判定）
    pub fn responder_consumed() -> Self {
        Self::new(
            InboundStage::Admit,
            CODE_INBOUND_RESPONDER_CONSUMED,
            false,
            EvidenceKind::Predicted,
            "accept/reject already consumed",
        )
    }
}

impl fmt::Display for InboundError {
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

impl std::error::Error for InboundError {}

/// 拒绝原因：responder 收到的结构化错误。出口失败原样透传 RIL-097 的
/// [`OpenError`]（稳定码/阶段/证据全部保留），认证与策略拒绝携带已脱敏文案。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectCause {
    /// 客户端认证失败（用户名/密码/令牌不匹配）
    Auth(String),
    /// 策略或解析拒绝（目标不允许、报文不合法等）
    Policy(String),
    /// 出口建立失败（RIL-097 错误原样映射为入口协议错误）
    Egress(OpenError),
}

impl RejectCause {
    /// 稳定原因码：出口失败用出口自身码，认证/策略用入口码
    pub fn as_code(&self) -> &'static str {
        match self {
            RejectCause::Auth(_) => CODE_INBOUND_AUTH,
            RejectCause::Policy(_) => CODE_INBOUND_REJECTED,
            RejectCause::Egress(err) => err.code,
        }
    }
}

impl fmt::Display for RejectCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectCause::Auth(ctx) => write!(f, "{}: {ctx}", CODE_INBOUND_AUTH),
            RejectCause::Policy(ctx) => write!(f, "{}: {ctx}", CODE_INBOUND_REJECTED),
            RejectCause::Egress(err) => write!(f, "{err}"),
        }
    }
}

/// 客户端方向字节流（认证/解析完成后的独占通道）。与出口侧
/// [`crate::outbound::StreamIo`] 是两种生命周期：错误口径是接入协议面
/// 而非出口建立面。
#[async_trait]
pub trait ClientChannel: Send {
    /// 读取至多 `max` 字节；Ok(None) = 客户端正常关闭
    async fn read(&mut self, max: usize) -> Result<Option<Bytes>, InboundError>;

    /// 写入全部字节（部分写由实现内部处理）
    async fn write_all(&mut self, data: Bytes) -> Result<(), InboundError>;

    /// 半关闭写侧（TCP 语义）
    async fn shutdown(&mut self) -> Result<(), InboundError>;
}

/// 成功回复所需信息（SOCKS5 BND.ADDR/BND.PORT 语义）：实际对端端点与传输。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptInfo {
    /// 出口实际对端端点
    pub endpoint: EndpointRef,
    /// 出口实际传输（稳定口径）
    pub transport: &'static str,
}

impl AcceptInfo {
    /// 从已建立出口提取回复信息
    pub fn from_opened(opened: &OpenedStream) -> Self {
        Self {
            endpoint: opened.endpoint().clone(),
            transport: opened.transport(),
        }
    }
}

/// 接入 responder：一次性消费的成功/失败回复。SOCKS5/HTTP 适配器把
/// [`RejectCause`] 映射为入口协议错误；TUN 适配器（[`IngressOrigin::Capture`]）
/// 提供栈驱动实现——`reject` 是会话复位，不是代理错误回复。
#[async_trait]
pub trait InboundResponder: Send {
    /// 成功回复。仅在出口建立成功后由 [`PendingStream::accept`] 调用；
    /// 回复写失败必须返回 Err（出口由 accept 就地释放）。
    async fn accept(&mut self, info: &AcceptInfo) -> Result<(), InboundError>;

    /// 失败/拒绝回复。不得暴露节点凭证或底层秘密（`cause` 上下文须已脱敏）。
    async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError>;
}

/// 接入来源：代理协议接入 vs 网络/栈接入。两种来源的回复语义不同，
/// 执行器不得混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressOrigin {
    /// 代理协议接入（SOCKS5/HTTP CONNECT 等）：responder 驱动协议回复
    Proxy,
    /// TUN/网络栈接入：回复由用户态网络栈驱动，**不套用代理回复模型**——
    /// reject 是会话复位；执行器不得等待或构造代理回复
    Capture,
}

impl IngressOrigin {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            IngressOrigin::Proxy => "proxy",
            IngressOrigin::Capture => "capture",
        }
    }
}

/// 待接入的字节流会话（两阶段的第一阶段产物）：独占客户端通道与 responder。
///
/// 所有权契约：
/// - `accept`/`reject` 各只能执行一次（responder 被 take，二次消费返回
///   `inbound.responder_consumed`）；
/// - [`PendingStream::accept`] 持有出口所有权：成功回复写失败就地 drop 出口
///   （「成功回复失败时立即释放已建立出口」由结构保证）；
/// - 直接丢弃（取消/超时路径）：客户端通道关闭、responder 不触发——
///   不重复回复；
/// - `accept` 成功后客户端通道移入 [`AcceptedStream`]，转发阶段本结构不再持有。
pub struct PendingStream {
    session_id: String,
    origin: IngressOrigin,
    target: EndpointRef,
    channel: Option<Box<dyn ClientChannel>>,
    responder: Option<Box<dyn InboundResponder>>,
}

impl fmt::Debug for PendingStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingStream")
            .field("session_id", &self.session_id)
            .field("origin", &self.origin.as_str())
            .field("target", &self.target)
            .field("admitted", &self.responder.is_some())
            .finish_non_exhaustive()
    }
}

impl PendingStream {
    /// 构造待接入会话（session_id 为空拒绝——诊断必须能定位会话）
    pub fn new(
        session_id: impl Into<String>,
        origin: IngressOrigin,
        target: EndpointRef,
        channel: Box<dyn ClientChannel>,
        responder: Box<dyn InboundResponder>,
    ) -> Option<Self> {
        let session_id = session_id.into();
        if session_id.is_empty() {
            return None;
        }
        Some(Self {
            session_id,
            origin,
            target,
            channel: Some(channel),
            responder: Some(responder),
        })
    }

    /// 会话身份（后续 [`crate::outbound::OpenContext::session_id`] 同源）
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 接入来源（执行器据此区分代理回复与栈驱动语义）
    pub fn origin(&self) -> IngressOrigin {
        self.origin
    }

    /// 认证/解析得到的目标（协议产物；路由决策在出口侧，不在入口）
    pub fn target(&self) -> &EndpointRef {
        &self.target
    }

    /// 是否尚未消费 responder
    pub fn is_pending(&self) -> bool {
        self.responder.is_some()
    }

    /// 第二阶段：出口已建立，回复成功并配对通道。
    ///
    /// 出口所有权在本调用内：回复写失败立即 drop 出口再返回错误
    /// （结构上保证「成功回复失败时立即释放已建立出口」）。
    pub async fn accept(&mut self, egress: OpenedStream) -> Result<AcceptedStream, InboundError> {
        let mut responder = self
            .responder
            .take()
            .ok_or_else(InboundError::responder_consumed)?;
        let info = AcceptInfo::from_opened(&egress);
        match responder.accept(&info).await {
            Ok(()) => {
                let channel = self
                    .channel
                    .take()
                    .expect("channel 与 responder 同生命周期同消费");
                Ok(AcceptedStream {
                    session_id: self.session_id.clone(),
                    origin: self.origin,
                    client: channel,
                    egress,
                })
            }
            Err(reply_err) => {
                // 回复失败：立即释放已建立出口（所有权在 accept 内，就地释放）
                drop(egress);
                Err(reply_err)
            }
        }
    }

    /// 第二阶段：拒绝。出口失败经 [`RejectCause::Egress`] 原样映射；
    /// 二次消费返回 `inbound.responder_consumed`。
    pub async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError> {
        let mut responder = self
            .responder
            .take()
            .ok_or_else(InboundError::responder_consumed)?;
        responder.reject(cause).await
    }
}

/// 两阶段完成后的配对通道：客户端通道 + 已建立出口。转发与预算归
/// SessionExecutor（RIL-098），本结构只完成配对与身份延续。
pub struct AcceptedStream {
    session_id: String,
    origin: IngressOrigin,
    client: Box<dyn ClientChannel>,
    egress: OpenedStream,
}

impl fmt::Debug for AcceptedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedStream")
            .field("session_id", &self.session_id)
            .field("origin", &self.origin.as_str())
            .field("egress", &self.egress)
            .finish_non_exhaustive()
    }
}

impl AcceptedStream {
    /// 会话身份（与 [`PendingStream::session_id`] 同源）
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 接入来源
    pub fn origin(&self) -> IngressOrigin {
        self.origin
    }

    /// 已建立出口（握手结果/实际端点可诊断）
    pub fn egress(&self) -> &OpenedStream {
        &self.egress
    }

    /// 取走双向转发通道对（唯一消费入口：客户端通道 + 出口通道）
    pub fn into_parts(self) -> (Box<dyn ClientChannel>, OpenedStream) {
        (self.client, self.egress)
    }
}

/// UDP 关联来源身份（已验证的客户端五元组/粘滞键）。来源校验在准入期
/// 完成，数据面按 `recv` 返回的来源与此键比对过滤由适配器负责。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceKey(String);

impl SourceKey {
    /// 构造来源键（空白拒绝——无来源身份不准入）
    pub fn new(key: impl Into<String>) -> Option<Self> {
        let key = key.into();
        if key.trim().is_empty() {
            return None;
        }
        Some(Self(key))
    }

    /// 键值
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 控制连接存活句柄（SOCKS5 UDP 的控制连接关联客户端准入与多目标映射；
/// 控制连接结束后按契约回收关联）。适配器在控制连接结束时
/// [`ControlLink::mark_closed`]，执行器观察到 [`ControlLink::is_closed`]
/// 后丢弃 [`DatagramIngress`] 完成回收。
#[derive(Debug, Clone, Default)]
pub struct ControlLink(Arc<AtomicBool>);

impl ControlLink {
    /// 新建存活句柄
    pub fn new() -> Self {
        Self::default()
    }

    /// 标记控制连接结束（幂等）
    pub fn mark_closed(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// 控制连接是否已结束
    pub fn is_closed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// UDP 关联 responder：准入回复（SOCKS5 UDP ASSOCIATE 回复携带中继地址）。
/// TUN UDP 无回复语义——适配器提供空操作实现（与 [`IngressOrigin::Capture`]
/// 同口径：不套用代理回复模型）。
#[async_trait]
pub trait AssociationResponder: Send {
    /// 准入成功回复；写失败必须返回 Err
    async fn accept(&mut self, relay: &EndpointRef) -> Result<(), InboundError>;

    /// 拒绝回复
    async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError>;
}

/// 待准入的 UDP 数据报关联：来源已验证、目标绑定与报文上限显式、
/// 生命周期受控制连接约束。
pub struct PendingAssociation {
    source: SourceKey,
    targets: TargetBinding,
    max_datagram_len: usize,
    control: Option<ControlLink>,
    responder: Option<Box<dyn AssociationResponder>>,
}

impl fmt::Debug for PendingAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAssociation")
            .field("source", &self.source)
            .field("targets", &self.targets)
            .field("max_datagram_len", &self.max_datagram_len)
            .field("admitted", &self.responder.is_some())
            .finish_non_exhaustive()
    }
}

impl PendingAssociation {
    /// 构造待准入关联（来源键空白拒绝；目标绑定常为 `Multi`，多目标映射
    /// 不得塞进一次 TCP 式路由决策——各目标按自身计划保持出口粘性）
    pub fn new(
        source: SourceKey,
        targets: TargetBinding,
        max_datagram_len: usize,
        control: ControlLink,
        responder: Box<dyn AssociationResponder>,
    ) -> Self {
        Self {
            source,
            targets,
            max_datagram_len,
            control: Some(control),
            responder: Some(responder),
        }
    }

    /// 已验证来源
    pub fn source(&self) -> &SourceKey {
        &self.source
    }

    /// 目标绑定形态
    pub fn targets(&self) -> &TargetBinding {
        &self.targets
    }

    /// 单报文上限（字节）
    pub fn max_datagram_len(&self) -> usize {
        self.max_datagram_len
    }

    /// 控制连接是否已结束（结束后执行器必须回收关联）
    pub fn control_closed(&self) -> bool {
        self.control
            .as_ref()
            .map(ControlLink::is_closed)
            .unwrap_or(true)
    }

    /// 是否尚未消费 responder
    pub fn is_pending(&self) -> bool {
        self.responder.is_some()
    }

    /// 准入：回复成功并交付关联句柄。回复写失败时控制链随错误就地丢弃
    /// （资源不泄漏），关联视为未建立。
    pub async fn accept(&mut self, relay: &EndpointRef) -> Result<DatagramIngress, InboundError> {
        let mut responder = self
            .responder
            .take()
            .ok_or_else(InboundError::responder_consumed)?;
        match responder.accept(relay).await {
            Ok(()) => Ok(DatagramIngress {
                source: self.source.clone(),
                targets: self.targets.clone(),
                max_datagram_len: self.max_datagram_len,
                control: self
                    .control
                    .take()
                    .expect("control 与 responder 同生命周期同消费"),
            }),
            Err(reply_err) => {
                // 回复失败：就地释放控制链与关联资源
                self.control = None;
                Err(reply_err)
            }
        }
    }

    /// 拒绝准入（一次性）。控制链就地释放。
    pub async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError> {
        let mut responder = self
            .responder
            .take()
            .ok_or_else(InboundError::responder_consumed)?;
        self.control = None;
        responder.reject(cause).await
    }
}

/// 已准入的 UDP 数据报关联句柄：中继 IO + 控制链 + 绑定/上限快照。
/// 丢弃本结构即回收关联资源；执行器观察到 `control` 关闭后必须丢弃。
pub struct DatagramIngress {
    source: SourceKey,
    targets: TargetBinding,
    max_datagram_len: usize,
    control: ControlLink,
}

impl fmt::Debug for DatagramIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramIngress")
            .field("source", &self.source)
            .field("targets", &self.targets)
            .field("max_datagram_len", &self.max_datagram_len)
            .field("control_closed", &self.control.is_closed())
            .finish_non_exhaustive()
    }
}

impl DatagramIngress {
    /// 已验证来源
    pub fn source(&self) -> &SourceKey {
        &self.source
    }

    /// 目标绑定形态
    pub fn targets(&self) -> &TargetBinding {
        &self.targets
    }

    /// 单报文上限
    pub fn max_datagram_len(&self) -> usize {
        self.max_datagram_len
    }

    /// 控制链（适配器标记关闭 → 执行器回收）
    pub fn control(&self) -> &ControlLink {
        &self.control
    }

    /// 取走关联资源（中继 IO 由适配器在协议侧交付时一并交给调用方持有；
    /// 控制链随本结构生命周期，丢弃即回收）
    pub fn into_parts(self) -> (SourceKey, TargetBinding, ControlLink) {
        (self.source, self.targets, self.control)
    }
}

/// 入口描述（装配期校验的最小面）：名称 + 稳定类型。**入口配置不参与
/// 出口选择**——本结构不含路由/出口/凭证引用（结构性保证）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSpec {
    /// 实例名（诊断定位，非空）
    pub name: String,
    /// 稳定类型（`socks5`/`http`/`mixed`/`tun` 等，与工厂 `kind()` 对齐）
    pub kind: String,
}

impl InboundSpec {
    /// 构造描述（name/kind 任一空白拒绝）
    pub fn new(name: impl Into<String>, kind: impl Into<String>) -> Option<Self> {
        let name = name.into();
        let kind = kind.into();
        if name.trim().is_empty() || kind.trim().is_empty() {
            return None;
        }
        Some(Self { name, kind })
    }
}

/// 待接入会话：字节流（两阶段）或数据报关联（UDP 准入）。
#[derive(Debug)]
pub enum PendingIngress {
    /// 代理/TUN 字节流会话
    Stream(PendingStream),
    /// UDP 数据报关联准入
    Association(PendingAssociation),
}

/// 已验证入口：持续产出待接入会话。监听 socket/网络栈归适配器持有；
/// 取消令牌置位后实现必须返回 `inbound.cancelled`（而不是挂死或静默退出）。
#[async_trait]
pub trait InboundAcceptor: Send + Sync {
    /// 装配时的描述
    fn spec(&self) -> &InboundSpec;

    /// 下一条待接入会话；Ok(None) = 受控关闭。
    async fn next_pending(
        &self,
        cancel: &CancelToken,
    ) -> Result<Option<PendingIngress>, InboundError>;
}

/// 入口工厂：装配期把 spec 校验为已验证入口（认证方式、监听形态等
/// 组合不支持的在这里拒绝，稳定码 `inbound.unsupported`），不让拨号期才失败。
pub trait InboundFactory: Send + Sync {
    /// 工厂支持的稳定类型
    fn kind(&self) -> &'static str;

    /// 装配期校验（类型不匹配/组合不支持 → [`CODE_INBOUND_UNSUPPORTED`]）
    fn validate(&self, spec: &InboundSpec) -> Result<(), InboundError>;

    /// 构建入口（调用方须先 `validate`）
    fn build(&self, spec: &InboundSpec) -> Result<Arc<dyn InboundAcceptor>, InboundError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OpenStage;

    fn origin() -> IngressOrigin {
        IngressOrigin::Proxy
    }

    fn endpoint() -> EndpointRef {
        EndpointRef::new("10.0.0.1", 443)
    }

    /// spec 与工厂校验：空白拒绝、类型不匹配装配期拒绝
    #[test]
    fn spec_and_factory_reject_invalid_input() {
        assert!(InboundSpec::new("", "socks5").is_none());
        assert!(InboundSpec::new("in-1", "  ").is_none());
        let spec = InboundSpec::new("in-1", "socks5").expect("合法 spec");
        assert_eq!(spec.kind, "socks5");

        let err = InboundError::unsupported("tun not in this build");
        assert_eq!(err.stage, InboundStage::Factory);
        assert_eq!(err.code, CODE_INBOUND_UNSUPPORTED);
        assert_eq!(err.evidence, EvidenceKind::Predicted);
        assert!(!err.retryable, "装配期拒绝不可重试");
    }

    /// 错误携带阶段/码/证据，文案含稳定码
    #[test]
    fn inbound_error_carries_stage_code_evidence() {
        for (stage, text) in [
            (InboundStage::Factory, "factory"),
            (InboundStage::Handshake, "handshake"),
            (InboundStage::Admit, "admit"),
            (InboundStage::Reply, "reply"),
        ] {
            let err = InboundError::new(
                stage,
                CODE_INBOUND_HANDSHAKE,
                true,
                EvidenceKind::Observed,
                "x",
            );
            assert_eq!(err.stage.as_str(), text);
            assert!(err.to_string().contains(CODE_INBOUND_HANDSHAKE));
        }

        let cancelled = InboundError::cancelled();
        assert_eq!(cancelled.code, CODE_INBOUND_CANCELLED);
        assert!(!cancelled.retryable);

        let consumed = InboundError::responder_consumed();
        assert_eq!(consumed.code, CODE_INBOUND_RESPONDER_CONSUMED);
        assert_eq!(consumed.evidence, EvidenceKind::Predicted);
    }

    /// 拒绝原因映射稳定码：出口失败透传出口自身码
    #[test]
    fn reject_cause_maps_stable_codes() {
        assert_eq!(
            RejectCause::Auth("bad user".into()).as_code(),
            CODE_INBOUND_AUTH
        );
        assert_eq!(
            RejectCause::Policy("target denied".into()).as_code(),
            CODE_INBOUND_REJECTED
        );
        let egress = OpenError::timeout(OpenStage::Handshake, "tls timeout");
        let cause = RejectCause::Egress(egress.clone());
        assert_eq!(
            cause.as_code(),
            crate::outbound::CODE_OPEN_TIMEOUT,
            "出口码透传"
        );
        assert!(cause.to_string().contains("outbound.open.timeout"));
    }

    /// 会话/来源身份非空拒绝
    #[test]
    fn pending_identity_requires_non_empty_session_and_source() {
        let channel: Box<dyn ClientChannel> = Box::new(DeadChannel);
        let responder: Box<dyn InboundResponder> = Box::new(DeadResponder);
        assert!(PendingStream::new("", origin(), endpoint(), channel, responder).is_none());

        assert!(SourceKey::new("").is_none());
        assert!(SourceKey::new("   ").is_none());
        let key = SourceKey::new("client-1:50000").expect("合法来源");
        assert_eq!(key.as_str(), "client-1:50000");
    }

    /// 来源枚举与控制链生命周期
    #[test]
    fn origin_and_control_link_lifecycle() {
        assert_eq!(IngressOrigin::Proxy.as_str(), "proxy");
        assert_eq!(IngressOrigin::Capture.as_str(), "capture");

        let link = ControlLink::new();
        assert!(!link.is_closed());
        link.mark_closed();
        link.mark_closed(); // 幂等
        assert!(link.is_closed());
    }

    // ---------- 最小桩（仅供身份校验测试编译通过） ----------

    struct DeadChannel;

    #[async_trait::async_trait]
    impl ClientChannel for DeadChannel {
        async fn read(&mut self, _max: usize) -> Result<Option<Bytes>, InboundError> {
            Ok(None)
        }
        async fn write_all(&mut self, _data: Bytes) -> Result<(), InboundError> {
            Ok(())
        }
        async fn shutdown(&mut self) -> Result<(), InboundError> {
            Ok(())
        }
    }

    struct DeadResponder;

    #[async_trait::async_trait]
    impl InboundResponder for DeadResponder {
        async fn accept(&mut self, _info: &AcceptInfo) -> Result<(), InboundError> {
            Ok(())
        }
        async fn reject(&mut self, _cause: RejectCause) -> Result<(), InboundError> {
            Ok(())
        }
    }
}
