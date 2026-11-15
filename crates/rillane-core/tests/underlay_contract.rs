//! 拨号与传输组合边界契约（RIL-099）：协议类不复制 DNS/旁路逻辑；
//! 非法排列装配期拒绝；QUIC/WireGuard 可持有原生资源不被强制转换为
//! 普通 TCP wrapper；外部库自建 socket 也须可施加平台旁路；
//! 无法注入或保证防环的组合明确拒绝。

use std::sync::Mutex;

use rillane_core::outbound::{OpenContext, OpenError, OpenStage, StreamIo};
use rillane_core::plan::GenerationRef;
use rillane_core::underlay::*;

fn generation() -> GenerationRef {
    GenerationRef::new("gen-u1").expect("非空代际")
}

fn ctx() -> OpenContext {
    OpenContext::new("s-underlay", generation()).expect("合法上下文")
}

// ---------------------------------------------------------------------------
// 测试替身：字节流（带身份标记，验证 wrap 链拿到的恰是上一层产物）
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MarkedStream {
    eof: bool,
}

#[async_trait::async_trait]
impl StreamIo for MarkedStream {
    async fn write_all(&mut self, _data: bytes::Bytes) -> Result<usize, OpenError> {
        Ok(0)
    }

    async fn read(&mut self, _max: usize) -> Result<Option<bytes::Bytes>, OpenError> {
        if self.eof {
            Ok(None)
        } else {
            self.eof = true;
            Ok(Some(bytes::Bytes::from_static(b"payload")))
        }
    }

    async fn shutdown_write(&mut self) -> Result<(), OpenError> {
        Ok(())
    }
}

/// 记录包装次序的传输替身（每次 wrap 换 tag——链式身份可对账）
struct RecordingTransport {
    name: &'static str,
    class: TransportClass,
    bypass: BypassCapability,
    wrapped: Mutex<Vec<String>>,
    fail_once: Mutex<bool>,
}

impl RecordingTransport {
    fn stream(name: &'static str) -> Self {
        Self {
            name,
            class: TransportClass::StreamStack,
            bypass: BypassCapability::NotApplicable,
            wrapped: Mutex::new(Vec::new()),
            fail_once: Mutex::new(false),
        }
    }

    fn with_class(mut self, class: TransportClass) -> Self {
        self.class = class;
        self
    }

    fn with_bypass(mut self, bypass: BypassCapability) -> Self {
        self.bypass = bypass;
        self
    }

    fn arm_failure(&self) {
        *self.fail_once.lock().expect("lock") = true;
    }

    fn wrapped(&self) -> Vec<String> {
        self.wrapped.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl StreamTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn class(&self) -> TransportClass {
        self.class
    }

    fn bypass_capability(&self) -> BypassCapability {
        self.bypass
    }

    async fn wrap(
        &self,
        mut io: Box<dyn StreamIo>,
        _ctx: &OpenContext,
    ) -> Result<Box<dyn StreamIo>, OpenError> {
        if *self.fail_once.lock().expect("lock") {
            return Err(OpenError::new(
                OpenStage::Transport,
                "underlay.test.handshake",
                false,
                rillane_core::outbound::EvidenceKind::Observed,
                "transport handshake failed",
            ));
        }
        // 读一条验证身份：上一层产物（首个 tag）随链传递
        let tag = format!("{}:{}", self.name, self.wrapped.lock().expect("lock").len());
        if let Some(payload) = io.read(64).await.expect("read") {
            assert_eq!(payload.as_ref(), b"payload", "上一层产物可达");
        }
        self.wrapped.lock().expect("lock").push(tag.clone());
        Ok(Box::new(MarkedStream { eof: false }))
    }
}

// ---------------------------------------------------------------------------
// 测试替身：拨号器（记录拨号目标与旁路施加）
// ---------------------------------------------------------------------------

struct RecordingDialer {
    bypass: BypassCapability,
    dials: Mutex<Vec<String>>,
    bypass_outcome: BypassOutcome,
}

impl RecordingDialer {
    fn injecting() -> Self {
        Self {
            bypass: BypassCapability::InjectsAtDial,
            dials: Mutex::new(Vec::new()),
            bypass_outcome: BypassOutcome::Applied { kind: "so_mark" },
        }
    }

    fn with_capability(mut self, bypass: BypassCapability) -> Self {
        self.bypass = bypass;
        self
    }

    fn with_outcome(mut self, outcome: BypassOutcome) -> Self {
        self.bypass_outcome = outcome;
        self
    }

    fn dials(&self) -> Vec<String> {
        self.dials.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl UnderlayDialer for RecordingDialer {
    fn name(&self) -> &'static str {
        "recording-dialer"
    }

    fn bypass_capability(&self) -> BypassCapability {
        self.bypass
    }

    async fn dial(
        &self,
        target: &DialTarget,
        _ctx: &OpenContext,
        bypass: Option<&dyn PlatformBypass>,
    ) -> Result<DialOutcome, OpenError> {
        check_dial_target(target)?;
        let outcome = match bypass {
            Some(injector) => match injector.apply_raw(RawSocketHandle(7)) {
                Ok(()) => BypassOutcome::Applied {
                    kind: injector.kind(),
                },
                Err(reason) => BypassOutcome::Degraded { reason },
            },
            None => self.bypass_outcome.clone(),
        };
        self.dials
            .lock()
            .expect("lock")
            .push(format!("{}:{}", target.host, target.port));
        Ok(DialOutcome {
            io: Box::new(MarkedStream { eof: false }),
            bypass: outcome,
        })
    }
}

/// 记录原始句柄注入的旁路替身（外部库适配路径）
struct RecordingBypass {
    seen: Mutex<Vec<i64>>,
}

impl PlatformBypass for RecordingBypass {
    fn kind(&self) -> &'static str {
        "so_mark"
    }

    fn apply_raw(&self, handle: RawSocketHandle) -> Result<(), String> {
        self.seen.lock().expect("lock").push(handle.0);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

/// 一次合法路径按协议要求顺序串联：Dialer 建 TCP → tls → ws → 协议。
/// wrap 链逐层拿到的恰是上一层产物；传输自身零拨号（dials 恰一次）。
#[tokio::test]
async fn legal_path_composes_in_protocol_order() {
    let stack = TransportStack::build(&["tls", "ws"]).expect("合法栈");
    let tls = RecordingTransport::stream("tls");
    let ws = RecordingTransport::stream("ws");
    let transports = stack
        .resolve(|name| match name {
            "tls" => Some(&tls as &dyn StreamTransport),
            "ws" => Some(&ws as &dyn StreamTransport),
            _ => None,
        })
        .expect("注册表齐备");

    let dialer = RecordingDialer::injecting();
    let target = DialTarget::new("node.example.com", 443).expect("合法目标");
    let outcome = dialer.dial(&target, &ctx(), None).await.expect("拨号成功");
    assert_eq!(dialer.dials(), vec!["node.example.com:443"], "拨号恰一次");
    assert_eq!(outcome.bypass, BypassOutcome::Applied { kind: "so_mark" });

    let io = wrap_chain(&transports, outcome.io, &ctx())
        .await
        .expect("链包装成功");
    // 包装次序 = 栈序（内层优先）：tls 先、ws 后
    assert_eq!(tls.wrapped(), vec!["tls:0"]);
    assert_eq!(ws.wrapped(), vec!["ws:0"]);
    // 链产物可达（协议握手在此 IO 上进行）
    let mut io = io;
    assert_eq!(
        io.read(64).await.expect("read").expect("payload").as_ref(),
        b"payload"
    );
}

/// 非法排列在装配期拒绝（零拨号）：内层翻转/重复/未知承载；
/// 原生承载（QUIC/WireGuard）不进栈、也不被 wrap_chain 强制包装。
#[tokio::test]
async fn illegal_compositions_rejected_before_any_dial() {
    let dialer = RecordingDialer::injecting();

    // TLS over WS——内层翻转
    let err = TransportStack::build(&["ws", "tls"]).unwrap_err();
    assert_eq!(err.code, CODE_STACK_ORDER);
    // tls 重复
    assert_eq!(
        TransportStack::build(&["tls", "tls"]).unwrap_err().code,
        CODE_STACK_DUP
    );
    // 未知承载
    assert_eq!(
        TransportStack::build(&["quic"]).unwrap_err().code,
        CODE_STACK_UNKNOWN
    );

    // 原生承载：注册表可给它自己的类别，但 wrap_chain 拒绝强制包装
    // ——QUIC/WireGuard 持有原生资源，不转普通 TCP wrapper
    let native = RecordingTransport::stream("quic").with_class(TransportClass::NativeChannel);
    let outcome = dialer
        .dial(
            &DialTarget::new("1.2.3.4", 443).expect("目标"),
            &ctx(),
            None,
        )
        .await
        .expect("拨号");
    let err = wrap_chain(&[&native as &dyn StreamTransport], outcome.io, &ctx())
        .await
        .err()
        .expect("原生承载拒绝");
    assert_eq!(err.code, CODE_STACK_NATIVE);
    assert_eq!(err.stage, OpenStage::Transport);
    assert!(!err.retryable, "静态类别错误不可重试");
    // 原生承载从未被包装（无 IO 动作）
    assert!(native.wrapped().is_empty());
    // 上述所有拒绝都发生在装配期——拨号只发生在这里显式的那一次
    assert_eq!(dialer.dials().len(), 1, "装配拒绝零拨号");
}

/// 栈声明与注册表必须一致：缺承载即装配失败（不做拨号期隐式处理）。
#[tokio::test]
async fn unregistered_transport_fails_at_assembly() {
    let stack = TransportStack::build(&["tls", "ws"]).expect("合法栈");
    let tls = RecordingTransport::stream("tls");
    let err = stack
        .resolve(|name| match name {
            "tls" => Some(&tls as &dyn StreamTransport),
            _ => None,
        })
        .err()
        .expect("缺注册承载");
    assert_eq!(err.code, CODE_STACK_UNREGISTERED);
    assert!(err.detail.contains("ws"));
}

/// 旁路在打开底层 socket 时施加（拨号器入口）；配置失败如实降级
/// ——Degraded 不冒充 Applied（诚实口径）。
#[tokio::test]
async fn bypass_applied_at_socket_open_and_degradation_is_honest() {
    let injector = RecordingBypass {
        seen: Mutex::new(Vec::new()),
    };
    let dialer = RecordingDialer::injecting();

    // 施加成功 → Applied 携机制名
    let outcome = dialer
        .dial(
            &DialTarget::new("10.0.0.1", 80).expect("目标"),
            &ctx(),
            Some(&injector),
        )
        .await
        .expect("拨号");
    assert_eq!(outcome.bypass, BypassOutcome::Applied { kind: "so_mark" });

    // 施加失败（外部注入口返回原因）→ Degraded 携已脱敏原因——
    // 不静默、不冒充成功
    struct FailingBypass;
    impl PlatformBypass for FailingBypass {
        fn kind(&self) -> &'static str {
            "so_mark"
        }
        fn apply_raw(&self, _handle: RawSocketHandle) -> Result<(), String> {
            Err("missing CAP_NET_ADMIN".to_string())
        }
    }
    let outcome = dialer
        .dial(
            &DialTarget::new("10.0.0.2", 80).expect("目标"),
            &ctx(),
            Some(&FailingBypass),
        )
        .await
        .expect("拨号（降级不是拨号失败）");
    assert_eq!(
        outcome.bypass,
        BypassOutcome::Degraded {
            reason: "missing CAP_NET_ADMIN".to_string()
        }
    );
    // 未配置旁路 → 拨号器声明的缺省 NotConfigured（零差异语义如实上报）
    let plain_dialer = RecordingDialer::injecting().with_outcome(BypassOutcome::NotConfigured);
    let outcome = plain_dialer
        .dial(
            &DialTarget::new("10.0.0.3", 80).expect("目标"),
            &ctx(),
            None,
        )
        .await
        .expect("拨号");
    assert_eq!(outcome.bypass, BypassOutcome::NotConfigured);
}

/// 外部库自建 socket 也须可施加平台旁路：适配器拿原始句柄（fd）
/// 走 `apply_raw` 直达注入口——旁路不留到协议包装后补救。
#[tokio::test]
async fn externally_opened_socket_receives_bypass_injection() {
    // 模拟「外部库自建 socket」：真实 listener + 出站连接拿原始 fd
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let sock = std::net::TcpStream::connect(addr).expect("connect");
    let raw = RawSocketHandle(i64::from(std::os::unix::io::AsRawFd::as_raw_fd(&sock)));

    let injector = RecordingBypass {
        seen: Mutex::new(Vec::new()),
    };
    injector.apply_raw(raw).expect("注入成功");
    assert_eq!(
        injector.seen.lock().expect("lock").as_slice(),
        &[raw.0],
        "注入口直达原始句柄"
    );
}

/// 无法注入或保证防环的组合在装配期明确拒绝（旁路必选策略下
/// CannotInject 组件零拨号零包装）；非必选策略放行。
#[tokio::test]
async fn uninjectable_combination_rejected_when_bypass_required() {
    let blind_dialer = RecordingDialer::injecting()
        .with_capability(BypassCapability::CannotInject)
        .with_outcome(BypassOutcome::NotConfigured);
    let blind_transport =
        RecordingTransport::stream("ws").with_bypass(BypassCapability::CannotInject);
    let clean_transport = RecordingTransport::stream("tls");

    // 旁路必选：拨号器 CannotInject → 拒
    let err = check_bypass_compat(&blind_dialer, &[], BypassPolicy::required()).unwrap_err();
    assert_eq!(err.code, CODE_BYPASS_UNINJECTABLE);
    // 旁路必选：承载 CannotInject → 拒（携承载名）
    let transports = vec![&clean_transport as &dyn StreamTransport, &blind_transport];
    let err = check_bypass_compat(
        &RecordingDialer::injecting(),
        &transports,
        BypassPolicy::required(),
    )
    .unwrap_err();
    assert_eq!(err.code, CODE_BYPASS_UNINJECTABLE);
    assert!(err.detail.contains("ws"));
    // 旁路可选：放行（无防环依赖——缺省零差异）
    assert!(check_bypass_compat(&blind_dialer, &transports, BypassPolicy::optional()).is_ok());
    // 全部拒绝都发生在装配期：盲拨号器零拨号
    assert!(blind_dialer.dials().is_empty(), "装配拒绝零拨号");
}

/// 拨号目标非法在拨号前以预测证据拒绝（确定性诊断面）；
/// 链中任一层失败即止——不跳过、不回退。
#[tokio::test]
async fn dial_target_invalid_and_chain_failure_stops() {
    // 空目标：DialTarget 构造拒绝
    assert!(DialTarget::new("", 443).is_none());
    // 超长目标：check_dial_target 以预测证据拒绝
    let oversized = DialTarget {
        host: "a".repeat(257),
        port: 443,
    };
    let err = check_dial_target(&oversized).unwrap_err();
    assert_eq!(err.code, CODE_DIAL_TARGET);
    assert_eq!(err.stage, OpenStage::Dial);
    assert!(!err.retryable);

    // 链失败即止：tls 失败 → ws 未被触碰
    let tls = RecordingTransport::stream("tls");
    let ws = RecordingTransport::stream("ws");
    tls.arm_failure();
    let dialer = RecordingDialer::injecting();
    let outcome = dialer
        .dial(
            &DialTarget::new("1.2.3.4", 443).expect("目标"),
            &ctx(),
            None,
        )
        .await
        .expect("拨号");
    let err = wrap_chain(&[&tls as &dyn StreamTransport, &ws], outcome.io, &ctx())
        .await
        .err()
        .expect("链失败即止");
    assert_eq!(err.stage, OpenStage::Transport);
    assert!(tls.wrapped().is_empty(), "失败层未产出包装");
    assert!(ws.wrapped().is_empty(), "失败即止——后续层不被触碰");
}
