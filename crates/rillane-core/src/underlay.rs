//! 拨号与传输组合边界（RIL-099 / io-and-accounting.md §1、§4、§7）。
//!
//! 一次合法路径（例：VLESS over WS over TLS）是**协议要求的固定顺序**，
//! 不是任意 middleware 排列：Dialer 建 TCP → TLS → WS → 协议目标握手 →
//! 业务通道。本模块冻结三条边界：
//!
//! - [`UnderlayDialer`] 是**唯一**开 socket 的入口——DNS、接口绑定、
//!   平台旁路（SO_MARK / VPN protect）都在打开底层 socket 时施加，
//!   不能等协议包装后补救；传输层与协议类拿到的永远是已连接流，
//!   结构上无法复制 DNS/旁路逻辑；
//! - [`TransportStack`] 用**显式语法表**校验 TLS/WS/gRPC/HTTPUpgrade
//!   的排列：非法排列在装配期拒绝（`underlay.stack.*`），不做拨号期
//!   才发现的隐式回退；QUIC/WireGuard 是 [`TransportClass::NativeChannel`]
//!   ——可持有原生资源（QUIC endpoint / 隧道），**不被强制转换**为
//!   普通字节流 wrapper；
//! - [`PlatformBypass`] 把旁路做成可注入端口：外部库自建 socket 也须
//!   能施加平台旁路（`apply_raw` 直达原始句柄）；声明
//!   [`BypassCapability::CannotInject`] 的组件与「旁路必选」策略组合
//!   时在装配期明确拒绝（无法注入即无法保证防环）。

use std::fmt;

use async_trait::async_trait;

use crate::outbound::{EvidenceKind, OpenContext, OpenError, OpenStage};

// ---------------------------------------------------------------------------
// 稳定原因码
// ---------------------------------------------------------------------------

/// 传输栈含未知承载名（装配期静态拒绝）
pub const CODE_STACK_UNKNOWN: &str = "underlay.stack.unknown_layer";
/// 传输栈排列违反协议要求顺序（装配期静态拒绝）
pub const CODE_STACK_ORDER: &str = "underlay.stack.bad_order";
/// 同一承载在栈内重复（装配期静态拒绝）
pub const CODE_STACK_DUP: &str = "underlay.stack.duplicate_layer";
/// 原生资源承载（QUIC/WireGuard）被塞进字节流 wrapper 栈
pub const CODE_STACK_NATIVE: &str = "underlay.stack.native";
/// 栈内声明的承载在装配注册表缺失
pub const CODE_STACK_UNREGISTERED: &str = "underlay.stack.unregistered";
/// 组件声明无法注入旁路，与「旁路必选」策略组合（装配期拒绝——
/// 无法注入即无法保证防环）
pub const CODE_BYPASS_UNINJECTABLE: &str = "underlay.bypass.uninjectable";
/// 拨号目标非法（空主机/超长）
pub const CODE_DIAL_TARGET: &str = "underlay.dial.target_invalid";

// ---------------------------------------------------------------------------
// 平台旁路
// ---------------------------------------------------------------------------

/// 原始 socket 句柄（Unix fd / Windows SOCKET）。外部库自建的 socket
/// 经此句柄交给旁路端口——旁路在 socket 打开时施加，不留包装后补救。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSocketHandle(pub i64);

/// 旁路施加结果（诚实口径）：配置了就必须说清发生了什么，
/// 降级不是成功也不是静默。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassOutcome {
    /// 已施加（携带旁路机制名，如 `so_mark` / `vpn_protect`）
    Applied {
        /// 旁路机制名（稳定口径）
        kind: &'static str,
    },
    /// 未配置旁路（策略允许缺省——零差异语义）
    NotConfigured,
    /// 配置了但施加失败降级（携带已脱敏原因；行为语义由实现声明，
    /// 结果必须如实上报——不冒充 Applied）
    Degraded {
        /// 已脱敏降级原因
        reason: String,
    },
}

/// 旁路注入能力（组件级声明，装配期校验依据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassCapability {
    /// 不开 socket（纯包装层）——旁路面不适用
    NotApplicable,
    /// 自建 socket 且自己施加旁路（标准拨号器）
    InjectsAtDial,
    /// 自建 socket 但可接受外部注入（[`PlatformBypass::apply_raw`] 直达
    /// 原始句柄——外部库适配路径）
    AcceptsRawInjection,
    /// 自建 socket 且既不自施加也不可注入——「旁路必选」策略下
    /// 装配期拒绝（无法保证防环）
    CannotInject,
}

impl BypassCapability {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            BypassCapability::NotApplicable => "not_applicable",
            BypassCapability::InjectsAtDial => "injects_at_dial",
            BypassCapability::AcceptsRawInjection => "accepts_raw_injection",
            BypassCapability::CannotInject => "cannot_inject",
        }
    }
}

/// 平台旁路端口：把「防环」做成可注入能力。拨号器在 socket 打开时
/// 施加；外部库自建的 socket 由适配器拿原始句柄补施加——
/// 「若库自行打开 socket，适配器必须证明这些 socket 能执行平台旁路」。
pub trait PlatformBypass: Send + Sync {
    /// 旁路机制名（稳定诊断口径，如 `so_mark` / `vpn_protect`）
    fn kind(&self) -> &'static str;

    /// 对已存在的原始 socket 施加旁路。`Err` 携带已脱敏原因
    /// （降级语义由调用方决定，本端口只如实报告）。
    fn apply_raw(&self, handle: RawSocketHandle) -> Result<(), String>;
}

/// 旁路策略（装配期输入）：`required` = 本平台防环依赖旁路
/// （TUN include 路由 / 移动 VPN protect 场景）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BypassPolicy {
    /// 旁路是否必选
    pub required: bool,
}

impl BypassPolicy {
    /// 旁路必选（防环依赖）
    pub fn required() -> Self {
        Self { required: true }
    }

    /// 旁路可选（缺省零差异）
    pub fn optional() -> Self {
        Self { required: false }
    }
}

/// 装配期旁路兼容检查：旁路必选时，任何自建 socket 但
/// [`BypassCapability::CannotInject`] 的组件都明确拒绝——
/// 在装配期给出确定性诊断，不留拨号期才发现的防环缺口。
pub fn check_bypass_compat(
    dialer: &dyn UnderlayDialer,
    transports: &[&dyn StreamTransport],
    policy: BypassPolicy,
) -> Result<(), CompositionError> {
    if !policy.required {
        return Ok(());
    }
    let offenders: Vec<&str> = transports
        .iter()
        .filter(|t| t.bypass_capability() == BypassCapability::CannotInject)
        .map(|t| t.name())
        .collect();
    if !offenders.is_empty() {
        return Err(CompositionError::new(
            CODE_BYPASS_UNINJECTABLE,
            format!(
                "transports open sockets without bypass injection: {}",
                offenders.join(",")
            ),
        ));
    }
    if dialer.bypass_capability() == BypassCapability::CannotInject {
        return Err(CompositionError::new(
            CODE_BYPASS_UNINJECTABLE,
            format!(
                "dialer {} opens sockets without bypass injection",
                dialer.name()
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 底层拨号
// ---------------------------------------------------------------------------

/// 拨号目标：主机可能是 IP 字面量或域名——**解析是拨号器平台实现的
/// 职责**；本契约只携带目标，不在传输/协议层重复 DNS。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialTarget {
    /// 主机（IP 字面量或域名；非空、≤256 字节）
    pub host: String,
    /// 端口
    pub port: u16,
}

impl DialTarget {
    /// 构造目标（空主机/超长拒绝——诊断面确定性）
    pub fn new(host: impl Into<String>, port: u16) -> Option<Self> {
        let host = host.into();
        if host.is_empty() || host.len() > 256 {
            return None;
        }
        Some(Self { host, port })
    }
}

/// 拨号结果：已连接的底层字节流 + 旁路施加的诚实记录。
pub struct DialOutcome {
    /// 已连接底层流（唯一由拨号器产出的初始 IO——传输栈从这里开始包装）
    pub io: Box<dyn crate::outbound::StreamIo>,
    /// 旁路施加结果（诚实口径：Applied/NotConfigured/Degraded 不混淆）
    pub bypass: BypassOutcome,
}

impl fmt::Debug for DialOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DialOutcome")
            .field("bypass", &self.bypass)
            .finish_non_exhaustive()
    }
}

/// 底层拨号契约：**唯一**允许打开 socket 的入口。DNS、接口绑定、
/// 平台旁路都在这里落地（平台端口实现）；传输与协议层拿到的永远是
/// 已连接流。建立只做一次尝试，回退归会话执行器（RIL-097 同口径）。
#[async_trait]
pub trait UnderlayDialer: Send + Sync {
    /// 实现名（稳定诊断口径）
    fn name(&self) -> &'static str;

    /// 旁路注入能力声明（装配期校验依据）
    fn bypass_capability(&self) -> BypassCapability;

    /// 拨号到 `target`。`bypass` 为 `Some` 时在打开 socket 时施加；
    /// 施加失败按实现声明的降级语义处理，但 [`BypassOutcome`] 必须如实。
    async fn dial(
        &self,
        target: &DialTarget,
        ctx: &OpenContext,
        bypass: Option<&dyn PlatformBypass>,
    ) -> Result<DialOutcome, OpenError>;
}

/// 拨号目标静态校验助手：非法目标在拨号前以预测证据拒绝
/// （确定性诊断面，供实现共用）。
pub fn check_dial_target(target: &DialTarget) -> Result<(), OpenError> {
    if target.host.is_empty() || target.host.len() > 256 {
        return Err(OpenError::new(
            OpenStage::Dial,
            CODE_DIAL_TARGET,
            false,
            EvidenceKind::Predicted,
            "dial target host empty or oversized",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 传输组合
// ---------------------------------------------------------------------------

/// 承载类别：字节流 wrapper 可进 [`TransportStack`] 排列；原生通道
/// （QUIC/WireGuard）持有自己的资源与拨号面，**不被强制转换**为普通
/// TCP wrapper（Hysteria2 自己持有 QUIC 会话、WireGuard 持有隧道——
/// 向上提供通道能力，不强迫所有协议走相同的字节流套娃）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClass {
    /// 字节流承载（可参与传输栈排列）
    StreamStack,
    /// 原生资源承载（自持拨号/隧道；不参与栈排列）
    NativeChannel,
}

impl TransportClass {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            TransportClass::StreamStack => "stream_stack",
            TransportClass::NativeChannel => "native_channel",
        }
    }
}

/// 合法字节流承载名（内层优先）：排列语法的数据面，显式冻结——
/// 新承载加入必须扩展此表并给出合法位置，而不是靠实现宽容。
pub const STREAM_TRANSPORTS: &[&str] = &["tls", "ws", "grpc", "httpupgrade"];

/// 原生承载名（[`TransportClass::NativeChannel`] 的稳定口径）。
pub const NATIVE_TRANSPORTS: &[&str] = &["quic", "wireguard"];

/// 装配期组合错误：静态、确定性、稳定码。发生在任何拨号之前。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionError {
    /// 稳定原因码（机器判定）
    pub code: &'static str,
    /// 已脱敏人读细节
    pub detail: String,
}

impl CompositionError {
    /// 构造装配错误
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for CompositionError {}

/// 传输栈：**协议要求的固定排列**（内层优先——`["tls", "ws"]` 表示
/// Dialer 建 TCP → TLS → WS）。装配期用显式语法表校验：
///
/// - 合法排列恰是：`[]`（raw）、单层 `tls|ws|grpc|httpupgrade`、
///   以及 `tls` 打底的 `tls→ws|grpc|httpupgrade`；
/// - `tls` 永远直接坐在底层拨号上（TLS over WS 之类内层翻转不是
///   支持的排列——协议顺序是要求，不是可自由组合的 middleware）;
/// - 同层重复拒绝；未知承载名拒绝（原生承载走
///   [`TransportClass::NativeChannel`]，不进栈）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportStack {
    layers: Vec<&'static str>,
}

impl TransportStack {
    /// 构造并校验（装配期静态拒绝——非法排列不做拨号期隐式处理）
    pub fn build(layers: &[&'static str]) -> Result<Self, CompositionError> {
        // 未知承载名（含原生承载——它们不是 wrapper）
        for (i, name) in layers.iter().enumerate() {
            if !STREAM_TRANSPORTS.contains(name) {
                let hint = if NATIVE_TRANSPORTS.contains(name) {
                    format!("{name} holds native resources and is not a stream wrapper")
                } else {
                    format!("{name} is not a known stream transport")
                };
                return Err(CompositionError::new(
                    CODE_STACK_UNKNOWN,
                    format!("layer {i}: {hint}"),
                ));
            }
        }
        // 同层重复
        for (i, name) in layers.iter().enumerate() {
            if layers[..i].contains(name) {
                return Err(CompositionError::new(
                    CODE_STACK_DUP,
                    format!("layer {i}: {name} already present"),
                ));
            }
        }
        // 排列语法：tls 只能打底；其余承载要么单层、要么直接坐在 tls 上
        let legal = matches!(
            layers,
            [] | ["tls"]
                | ["ws"]
                | ["grpc"]
                | ["httpupgrade"]
                | ["tls", "ws"]
                | ["tls", "grpc"]
                | ["tls", "httpupgrade"]
        );
        if !legal {
            let order = layers.join(" -> ");
            return Err(CompositionError::new(
                CODE_STACK_ORDER,
                format!("protocol-required order violated: [{order}]"),
            ));
        }
        Ok(Self {
            layers: layers.to_vec(),
        })
    }

    /// 空 = raw 直连（无承载包装）
    pub fn raw() -> Self {
        Self { layers: Vec::new() }
    }

    /// 已校验的排列（内层优先，只读）
    pub fn layers(&self) -> &[&'static str] {
        &self.layers
    }

    /// 按注册表解析栈内承载；缺一个即装配失败（声明与实现必须一致）
    pub fn resolve<'a>(
        &self,
        registry: impl Fn(&'static str) -> Option<&'a dyn StreamTransport>,
    ) -> Result<Vec<&'a dyn StreamTransport>, CompositionError> {
        self.layers
            .iter()
            .map(|name| {
                registry(name).ok_or_else(|| {
                    CompositionError::new(
                        CODE_STACK_UNREGISTERED,
                        format!("transport {name} declared but not registered"),
                    )
                })
            })
            .collect()
    }
}

/// 字节流承载契约：包装**已连接**的底层流。wrap 输入永远是上一层的
/// 输出（初始层输入是拨号器产物）——承载类型上没有拨号/解析入口，
/// DNS 与旁路逻辑无处复制。
#[async_trait]
pub trait StreamTransport: Send + Sync {
    /// 实现名（稳定口径，[`STREAM_TRANSPORTS`] 之一）
    fn name(&self) -> &'static str;

    /// 承载类别（原生承载不参与栈排列）
    fn class(&self) -> TransportClass;

    /// 旁路注入能力（纯包装层 = [`BypassCapability::NotApplicable`]）
    fn bypass_capability(&self) -> BypassCapability;

    /// 包装已连接流。失败按传输阶段报告（RIL-097 [`OpenError`] 口径）。
    async fn wrap(
        &self,
        io: Box<dyn crate::outbound::StreamIo>,
        ctx: &OpenContext,
    ) -> Result<Box<dyn crate::outbound::StreamIo>, OpenError>;
}

/// 按栈序串联承载（内层优先）：输入拨号器产物，输出协议适配器要的
/// 已包装流。任一层失败即止——**不跳过、不回退**（回退归会话执行器）。
pub async fn wrap_chain(
    transports: &[&dyn StreamTransport],
    mut io: Box<dyn crate::outbound::StreamIo>,
    ctx: &OpenContext,
) -> Result<Box<dyn crate::outbound::StreamIo>, OpenError> {
    for transport in transports {
        // 原生承载不进链（装配期本应拦下——这里是拨号期最后防线，
        // 预测证据：不产生任何 IO 动作）
        if transport.class() != TransportClass::StreamStack {
            return Err(OpenError::new(
                OpenStage::Transport,
                CODE_STACK_NATIVE,
                false,
                EvidenceKind::Predicted,
                format!(
                    "transport {} holds native resources and cannot wrap a stream",
                    transport.name()
                ),
            ));
        }
        io = transport.wrap(io, ctx).await?;
    }
    Ok(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法排列恰是语法表成员；layers 保序
    #[test]
    fn legal_stack_grammar() {
        assert!(TransportStack::build(&[]).is_ok(), "raw 直连合法");
        for name in STREAM_TRANSPORTS {
            assert!(TransportStack::build(&[name]).is_ok(), "单层 {name} 合法");
        }
        for name in ["ws", "grpc", "httpupgrade"] {
            assert!(
                TransportStack::build(&["tls", name]).is_ok(),
                "tls 打底 + {name} 合法"
            );
        }
        let stack = TransportStack::build(&["tls", "ws"]).expect("合法栈");
        assert_eq!(stack.layers(), &["tls", "ws"], "内层优先保序");
        let empty: &[&str] = &[];
        assert_eq!(TransportStack::raw().layers(), empty);
    }

    /// 非法排列装配期即拒：tls 内层翻转、重复层、未知/原生承载
    #[test]
    fn illegal_stack_grammar_rejected() {
        // TLS over WS——内层翻转不是支持的排列
        let err = TransportStack::build(&["ws", "tls"]).unwrap_err();
        assert_eq!(err.code, CODE_STACK_ORDER);
        assert!(err.to_string().contains("ws -> tls"));
        // 三层无对应语法
        assert_eq!(
            TransportStack::build(&["tls", "ws", "grpc"])
                .unwrap_err()
                .code,
            CODE_STACK_ORDER
        );
        // grpc 与 ws 平级拼接
        assert_eq!(
            TransportStack::build(&["grpc", "ws"]).unwrap_err().code,
            CODE_STACK_ORDER
        );
        // 同层重复
        assert_eq!(
            TransportStack::build(&["tls", "tls"]).unwrap_err().code,
            CODE_STACK_DUP
        );
        assert_eq!(
            TransportStack::build(&["ws", "ws"]).unwrap_err().code,
            CODE_STACK_DUP
        );
        // 未知承载名
        let err = TransportStack::build(&["smtp"]).unwrap_err();
        assert_eq!(err.code, CODE_STACK_UNKNOWN);
        // 原生承载不是 wrapper——单独报错口径
        let err = TransportStack::build(&["quic"]).unwrap_err();
        assert_eq!(err.code, CODE_STACK_UNKNOWN);
        assert!(err.detail.contains("native resources"), "{}", err.detail);
    }

    /// 拨号目标静态校验：空/超长拒绝
    #[test]
    fn dial_target_validation() {
        assert!(DialTarget::new("", 443).is_none());
        assert!(DialTarget::new("a".repeat(257), 443).is_none());
        let t = DialTarget::new("example.com", 443).expect("合法目标");
        assert_eq!((t.host.as_str(), t.port), ("example.com", 443));
        let err = check_dial_target(&DialTarget {
            host: String::new(),
            port: 1,
        })
        .unwrap_err();
        assert_eq!(err.code, CODE_DIAL_TARGET);
        assert_eq!(err.stage, OpenStage::Dial);
        assert!(!err.retryable, "静态目标错误不可重试");
    }

    /// 旁路能力口径与策略检查（旁路可选时 CannotInject 放行；必选时
    /// 拨号器/承载任一 CannotInject 都在装配期拒绝——零拨号）
    #[test]
    fn bypass_capability_and_policy() {
        assert_eq!(BypassCapability::NotApplicable.as_str(), "not_applicable");
        assert_eq!(BypassCapability::CannotInject.as_str(), "cannot_inject");

        struct FixedDialer(BypassCapability);
        #[async_trait]
        impl UnderlayDialer for FixedDialer {
            fn name(&self) -> &'static str {
                "fixed-dialer"
            }
            fn bypass_capability(&self) -> BypassCapability {
                self.0
            }
            async fn dial(
                &self,
                _target: &DialTarget,
                _ctx: &OpenContext,
                _bypass: Option<&dyn PlatformBypass>,
            ) -> Result<DialOutcome, OpenError> {
                panic!("装配检查不拨号");
            }
        }

        // 旁路可选：CannotInject 也放行（无防环依赖）
        assert!(check_bypass_compat(
            &FixedDialer(BypassCapability::CannotInject),
            &[],
            BypassPolicy::optional()
        )
        .is_ok());
        // 旁路必选：拨号器 CannotInject 即拒
        let err = check_bypass_compat(
            &FixedDialer(BypassCapability::CannotInject),
            &[],
            BypassPolicy::required(),
        )
        .unwrap_err();
        assert_eq!(err.code, CODE_BYPASS_UNINJECTABLE);
        assert!(err.detail.contains("fixed-dialer"));
        // 旁路必选：承载 CannotInject 即拒（携带承载名）
        struct BlindTransport;
        #[async_trait]
        impl StreamTransport for BlindTransport {
            fn name(&self) -> &'static str {
                "blind-ws"
            }
            fn class(&self) -> TransportClass {
                TransportClass::StreamStack
            }
            fn bypass_capability(&self) -> BypassCapability {
                BypassCapability::CannotInject
            }
            async fn wrap(
                &self,
                _io: Box<dyn crate::outbound::StreamIo>,
                _ctx: &OpenContext,
            ) -> Result<Box<dyn crate::outbound::StreamIo>, OpenError> {
                panic!("装配检查不包装");
            }
        }
        let err = check_bypass_compat(
            &FixedDialer(BypassCapability::InjectsAtDial),
            &[&BlindTransport],
            BypassPolicy::required(),
        )
        .unwrap_err();
        assert_eq!(err.code, CODE_BYPASS_UNINJECTABLE);
        assert!(err.detail.contains("blind-ws"));
        // 合法组合：拨号器自施加 + 纯包装层
        assert!(check_bypass_compat(
            &FixedDialer(BypassCapability::InjectsAtDial),
            &[&BlindTransport],
            BypassPolicy::optional(),
        )
        .is_ok());
    }
}
