//! RIL-096 入口两阶段接入契约验收：
//! - 认证/解析与路由分开：入口只产出待接入会话，路由决策在出口侧；
//! - 出口成功后才回复成功；失败经 RejectCause 原样映射为入口协议错误；
//! - accept/reject 一次性消费，二次消费返回稳定码；
//! - 成功回复失败时立即释放已建立出口；取消/丢弃不触发回复（无泄漏）；
//! - TUN（Capture）不套用代理回复模型：reject 是会话复位；
//! - UDP 准入：来源校验、目标绑定显式、控制连接结束按契约回收。
//!
//! 用最小内存适配器钉契约，不依赖任何真实协议实现。

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use rillane_core::{
    AcceptInfo, AssociationResponder, CancelToken, ClientChannel, ControlLink, DatagramIngress,
    EndpointRef, InboundAcceptor, InboundError, InboundFactory, InboundResponder, InboundSpec,
    IngressOrigin, OpenError, OpenStage, OpenedStream, PendingAssociation, PendingStream,
    RejectCause, SourceKey, TargetBinding, CODE_INBOUND_AUTH, CODE_INBOUND_CANCELLED,
    CODE_INBOUND_REPLY_FAILED, CODE_INBOUND_RESPONDER_CONSUMED, CODE_INBOUND_SOURCE_INVALID,
    CODE_INBOUND_UNSUPPORTED,
};

// ---------- 最小内存适配器 ----------

/// 客户端通道桩：记录写入、关闭时置位（观察「丢弃即关闭资源」）
struct MockClient {
    closed: Arc<AtomicBool>,
    written: Mutex<Vec<Bytes>>,
}

impl Drop for MockClient {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

#[async_trait]
impl ClientChannel for MockClient {
    async fn read(&mut self, _max: usize) -> Result<Option<Bytes>, InboundError> {
        Ok(None)
    }

    async fn write_all(&mut self, data: Bytes) -> Result<(), InboundError> {
        self.written.lock().unwrap().push(data);
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), InboundError> {
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}

/// responder 记录：Accept（成功回复）/ Reject（失败回复，带稳定码）
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Accept {
        endpoint: String,
        transport: &'static str,
    },
    Reject {
        code: &'static str,
    },
    /// Capture 语义：会话复位（不是代理错误回复）
    Reset {
        code: &'static str,
    },
}

/// 代理协议 responder：accept 可配置写失败
struct MockResponder {
    replies: Arc<Mutex<Vec<Reply>>>,
    accept_fails: bool,
}

#[async_trait]
impl InboundResponder for MockResponder {
    async fn accept(&mut self, info: &AcceptInfo) -> Result<(), InboundError> {
        if self.accept_fails {
            self.replies.lock().unwrap().push(Reply::Reject {
                code: CODE_INBOUND_REPLY_FAILED,
            });
            return Err(InboundError::new(
                rillane_core::InboundStage::Reply,
                CODE_INBOUND_REPLY_FAILED,
                false,
                rillane_core::EvidenceKind::Observed,
                "client write failed",
            ));
        }
        self.replies.lock().unwrap().push(Reply::Accept {
            endpoint: format!("{}:{}", info.endpoint.host, info.endpoint.port),
            transport: info.transport,
        });
        Ok(())
    }

    async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError> {
        self.replies.lock().unwrap().push(Reply::Reject {
            code: cause.as_code(),
        });
        Ok(())
    }
}

/// TUN 栈驱动 responder：reject = 复位会话（不套用代理回复模型）
struct StackResponder {
    replies: Arc<Mutex<Vec<Reply>>>,
}

#[async_trait]
impl InboundResponder for StackResponder {
    async fn accept(&mut self, info: &AcceptInfo) -> Result<(), InboundError> {
        self.replies.lock().unwrap().push(Reply::Accept {
            endpoint: format!("{}:{}", info.endpoint.host, info.endpoint.port),
            transport: info.transport,
        });
        Ok(())
    }

    async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError> {
        // 网络栈驱动：复位 TCP 会话，只保留稳定码供诊断
        self.replies.lock().unwrap().push(Reply::Reset {
            code: cause.as_code(),
        });
        Ok(())
    }
}

/// 关联 responder 桩
struct MockAssocResponder {
    accept_fails: bool,
    replies: Arc<Mutex<Vec<Reply>>>,
}

#[async_trait]
impl AssociationResponder for MockAssocResponder {
    async fn accept(&mut self, _relay: &EndpointRef) -> Result<(), InboundError> {
        if self.accept_fails {
            return Err(InboundError::new(
                rillane_core::InboundStage::Reply,
                CODE_INBOUND_REPLY_FAILED,
                false,
                rillane_core::EvidenceKind::Observed,
                "control write failed",
            ));
        }
        self.replies.lock().unwrap().push(Reply::Accept {
            endpoint: "relay".into(),
            transport: "udp",
        });
        Ok(())
    }

    async fn reject(&mut self, cause: RejectCause) -> Result<(), InboundError> {
        self.replies.lock().unwrap().push(Reply::Reject {
            code: cause.as_code(),
        });
        Ok(())
    }
}

/// 出口 IO 桩：drop 时置位（观察「回复失败立即释放已建立出口」）
struct MockEgressIo {
    released: Arc<AtomicBool>,
}

impl Drop for MockEgressIo {
    fn drop(&mut self) {
        self.released.store(true, Ordering::Release);
    }
}

#[async_trait]
impl rillane_core::StreamIo for MockEgressIo {
    async fn write_all(&mut self, _data: Bytes) -> Result<usize, OpenError> {
        Ok(0)
    }
    async fn read(&mut self, _max: usize) -> Result<Option<Bytes>, OpenError> {
        Ok(None)
    }
    async fn shutdown_write(&mut self) -> Result<(), OpenError> {
        Ok(())
    }
}

fn pending_proxy(closed: Arc<AtomicBool>, replies: Arc<Mutex<Vec<Reply>>>) -> PendingStream {
    PendingStream::new(
        "s-1",
        IngressOrigin::Proxy,
        EndpointRef::new("8.8.8.8", 443),
        Box::new(MockClient {
            closed,
            written: Mutex::new(Vec::new()),
        }),
        Box::new(MockResponder {
            replies,
            accept_fails: false,
        }),
    )
    .expect("合法会话")
}

fn opened_egress(released: Arc<AtomicBool>) -> OpenedStream {
    OpenedStream::new(
        "mock-egress",
        EndpointRef::new("10.0.0.1", 443),
        "tls",
        42,
        Box::new(MockEgressIo { released }),
    )
}

// ---------- 契约验收 ----------

/// ① 两阶段：出口成功后才回复成功；配对通道连同身份延续交付转发侧
#[tokio::test]
async fn accept_replies_only_after_egress_established() {
    let closed = Arc::new(AtomicBool::new(false));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = pending_proxy(closed.clone(), replies.clone());

    assert!(pending.is_pending());
    assert_eq!(pending.session_id(), "s-1");
    assert_eq!(pending.origin(), IngressOrigin::Proxy);
    assert_eq!(pending.target(), &EndpointRef::new("8.8.8.8", 443));

    let released = Arc::new(AtomicBool::new(false));
    let accepted = pending
        .accept(opened_egress(released.clone()))
        .await
        .expect("出口已建立应准入");

    // 成功回复携带出口实际端点/传输（BND.ADDR 语义）
    assert_eq!(
        *replies.lock().unwrap(),
        vec![Reply::Accept {
            endpoint: "10.0.0.1:443".into(),
            transport: "tls",
        }]
    );
    assert!(
        !released.load(Ordering::Acquire),
        "出口随 AcceptedStream 存活"
    );

    // 配对交付：客户端通道 + 出口通道一起移入转发侧，身份延续
    assert_eq!(accepted.session_id(), "s-1");
    assert_eq!(accepted.origin(), IngressOrigin::Proxy);
    assert_eq!(accepted.egress().handshake_ms(), 42);
    let (mut client, egress) = accepted.into_parts();
    client
        .write_all(Bytes::from_static(b"GET /"))
        .await
        .unwrap();
    let (_ep, _transport, mut egress_io) = egress.into_parts();
    egress_io
        .write_all(Bytes::from_static(b"ok"))
        .await
        .unwrap();
    drop(client);
    assert!(closed.load(Ordering::Acquire), "丢弃即关闭客户端通道");
}

/// ① 反面：出口失败 → reject 原样映射出口稳定码，绝不先回复成功
#[tokio::test]
async fn reject_maps_egress_error_without_success_reply() {
    let closed = Arc::new(AtomicBool::new(false));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = pending_proxy(closed, replies.clone());

    let egress_err = OpenError::timeout(OpenStage::Handshake, "tls timed out");
    pending
        .reject(RejectCause::Egress(egress_err))
        .await
        .unwrap();

    let got = replies.lock().unwrap();
    assert_eq!(
        *got,
        vec![Reply::Reject {
            code: "outbound.open.timeout",
        }],
        "出口失败原样映射为入口协议错误"
    );
    assert!(
        !got.iter().any(|r| matches!(r, Reply::Accept { .. })),
        "失败路径不得出现成功回复"
    );
}

/// ② responder 一次性消费：accept 后再 accept/reject、reject 后再消费
/// 都返回 `inbound.responder_consumed`，不重复回复客户端
#[tokio::test]
async fn responder_is_one_shot() {
    let closed = Arc::new(AtomicBool::new(false));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = pending_proxy(closed, replies.clone());
    let released = Arc::new(AtomicBool::new(false));
    pending.accept(opened_egress(released)).await.unwrap();

    let err = pending
        .accept(opened_egress(Arc::new(AtomicBool::new(false))))
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_RESPONDER_CONSUMED);
    let err = pending
        .reject(RejectCause::Policy("late".into()))
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_RESPONDER_CONSUMED);

    // reject 先消费同理
    let mut p2 = pending_proxy(
        Arc::new(AtomicBool::new(false)),
        Arc::new(Mutex::new(Vec::new())),
    );
    p2.reject(RejectCause::Auth("bad user".into()))
        .await
        .unwrap();
    let err = p2
        .reject(RejectCause::Auth("again".into()))
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_RESPONDER_CONSUMED);

    // 全程只有一次真实回复
    assert_eq!(replies.lock().unwrap().len(), 1);
}

/// ③ 成功回复写失败：accept 返回错误且已建立出口**立即释放**
/// （所有权在 accept 内，失败路径就地 drop——结构保证无泄漏）
#[tokio::test]
async fn accept_reply_failure_releases_established_egress() {
    let closed = Arc::new(AtomicBool::new(false));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = PendingStream::new(
        "s-2",
        IngressOrigin::Proxy,
        EndpointRef::new("8.8.8.8", 443),
        Box::new(MockClient {
            closed,
            written: Mutex::new(Vec::new()),
        }),
        Box::new(MockResponder {
            replies,
            accept_fails: true,
        }),
    )
    .expect("合法会话");

    let released = Arc::new(AtomicBool::new(false));
    let err = pending
        .accept(opened_egress(released.clone()))
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_REPLY_FAILED);
    assert_eq!(err.stage.as_str(), "reply");
    assert!(
        released.load(Ordering::Acquire),
        "成功回复失败必须立即释放已建立出口"
    );
}

/// ④ 取消/超时路径：直接丢弃 PendingStream——通道关闭、responder
/// 不触发（不重复回复），客户端通道资源随之回收
#[test]
fn drop_without_consume_closes_channel_and_never_replies() {
    let closed = Arc::new(AtomicBool::new(false));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let pending = pending_proxy(closed.clone(), replies.clone());
    drop(pending);

    assert!(closed.load(Ordering::Acquire), "丢弃即关闭客户端通道");
    assert!(
        replies.lock().unwrap().is_empty(),
        "取消/超时路径不得触发任何回复"
    );
}

/// ⑤ TUN（Capture）不套用代理回复模型：reject = 会话复位；
/// 稳定码保留供诊断，不产生代理错误回复
#[tokio::test]
async fn capture_origin_resets_session_instead_of_proxy_reply() {
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = PendingStream::new(
        "tun-1",
        IngressOrigin::Capture,
        EndpointRef::new("1.2.3.4", 80),
        Box::new(MockClient {
            closed: Arc::new(AtomicBool::new(false)),
            written: Mutex::new(Vec::new()),
        }),
        Box::new(StackResponder {
            replies: replies.clone(),
        }),
    )
    .expect("合法会话");

    assert_eq!(pending.origin().as_str(), "capture");
    pending
        .reject(RejectCause::Egress(OpenError::timeout(
            OpenStage::Dial,
            "upstream unreachable",
        )))
        .await
        .unwrap();

    assert_eq!(
        *replies.lock().unwrap(),
        vec![Reply::Reset {
            code: "outbound.open.timeout",
        }],
        "TUN 拒绝是会话复位而非代理错误回复"
    );

    // 成功路径与代理一致：出口建立后栈驱动 accept
    let accepted = pending
        .accept(opened_egress(Arc::new(AtomicBool::new(false))))
        .await
        .unwrap_err();
    assert_eq!(
        accepted.code, CODE_INBOUND_RESPONDER_CONSUMED,
        "reset 已消费 responder：TUN 会话复位同样一次性"
    );
}

/// ⑥ UDP 准入：来源校验拒绝空白来源；accept 交付绑定/上限/控制链；
/// 控制连接结束 → 执行器回收；拒绝路径就地释放控制链
#[tokio::test]
async fn association_admission_and_control_reclaim() {
    let replies = Arc::new(Mutex::new(Vec::new()));
    let control = ControlLink::new();
    let mut assoc = PendingAssociation::new(
        SourceKey::new("client-1:50000").expect("合法来源"),
        TargetBinding::Multi { allowed: vec![] },
        1_400,
        control,
        Box::new(MockAssocResponder {
            accept_fails: false,
            replies: replies.clone(),
        }),
    );
    assert_eq!(assoc.source().as_str(), "client-1:50000");
    assert_eq!(assoc.max_datagram_len(), 1_400);
    assert!(!assoc.control_closed());

    let ingress: DatagramIngress = assoc
        .accept(&EndpointRef::new("10.0.0.2", 8388))
        .await
        .expect("准入成功");
    assert_eq!(replies.lock().unwrap().len(), 1, "中继地址已回复");
    assert!(
        ingress.targets().allows(&EndpointRef::new("9.9.9.9", 53)),
        "Multi 空集合 = 实现自决（多目标映射不塞进一次 TCP 式决策）"
    );

    // 控制连接结束 → 执行器观察到后回收
    ingress.control().mark_closed();
    assert!(ingress.control().is_closed());
    let (_source, _targets, control) = ingress.into_parts();
    assert!(control.is_closed(), "控制链随关联句柄交付");

    // 一次性消费
    let err = assoc
        .accept(&EndpointRef::new("10.0.0.2", 8388))
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_RESPONDER_CONSUMED);

    // 拒绝路径：来源身份错误语义由稳定码承载
    let replies2 = Arc::new(Mutex::new(Vec::new()));
    let mut assoc2 = PendingAssociation::new(
        SourceKey::new("client-2:60000").unwrap(),
        TargetBinding::Multi { allowed: vec![] },
        1_400,
        ControlLink::new(),
        Box::new(MockAssocResponder {
            accept_fails: false,
            replies: replies2.clone(),
        }),
    );
    assoc2
        .reject(RejectCause::Auth("mismatched source".into()))
        .await
        .unwrap();
    assert_eq!(
        *replies2.lock().unwrap(),
        vec![Reply::Reject {
            code: CODE_INBOUND_AUTH,
        }]
    );
    assert!(assoc2.control_closed(), "拒绝后控制链就地释放");

    // 回复写失败：关联视为未建立，控制链释放
    let mut assoc3 = PendingAssociation::new(
        SourceKey::new("client-3:70000").unwrap(),
        TargetBinding::Multi { allowed: vec![] },
        1_400,
        ControlLink::new(),
        Box::new(MockAssocResponder {
            accept_fails: true,
            replies: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    let err = assoc3
        .accept(&EndpointRef::new("10.0.0.2", 8388))
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_REPLY_FAILED);
    assert!(assoc3.control_closed(), "回复失败就地释放控制链");
}

/// ⑦ 来源键空白拒绝走稳定码语义（无来源身份不准入）
#[test]
fn source_validation_rejects_blank_identity() {
    assert!(SourceKey::new("").is_none());
    assert!(SourceKey::new("  ").is_none());
    // 稳定码存在且可被适配器用于准入错误
    assert_eq!(CODE_INBOUND_SOURCE_INVALID, "inbound.source_invalid");
}

/// ⑧ 受控关闭与取消：acceptor 契约（取消令牌置位 → inbound.cancelled）
#[tokio::test]
async fn acceptor_honors_cancel_token() {
    let cancel = CancelToken::new();
    let acceptor = MockAcceptor::default();

    // 正常产出一条待接入会话
    let pending = acceptor.next_pending(&cancel).await.unwrap().unwrap();
    assert!(matches!(pending, rillane_core::PendingIngress::Stream(_)));

    // 取消后：实现必须返回稳定码而不是挂死
    cancel.cancel();
    let err = acceptor.next_pending(&cancel).await.unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_CANCELLED);
    assert!(!err.retryable);
    assert_eq!(err.stage.as_str(), "admit");
}

/// ⑨ 工厂装配期校验：类型不匹配 → inbound.unsupported（拨号期才失败被禁止）
#[test]
fn factory_rejects_kind_mismatch_at_assembly() {
    let factory = MockFactory;
    let spec = InboundSpec::new("in-1", "tun").expect("合法 spec");
    let err = factory.validate(&spec).unwrap_err();
    assert_eq!(err.code, CODE_INBOUND_UNSUPPORTED);
    assert_eq!(err.evidence.as_str(), "predicted");
    assert_eq!(err.stage.as_str(), "factory");

    let spec = InboundSpec::new("in-2", "socks5").expect("合法 spec");
    factory.validate(&spec).expect("匹配类型可过");
    let acceptor = factory.build(&spec).expect("构建入口");
    assert_eq!(acceptor.spec().kind, "socks5");
}

// ---------- acceptor/factory 最小桩 ----------

struct MockAcceptor {
    spec: InboundSpec,
    produced: AtomicU32,
}

impl Default for MockAcceptor {
    fn default() -> Self {
        Self {
            spec: InboundSpec::new("mock-in", "socks5").unwrap(),
            produced: AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl rillane_core::InboundAcceptor for MockAcceptor {
    fn spec(&self) -> &InboundSpec {
        &self.spec
    }

    async fn next_pending(
        &self,
        cancel: &CancelToken,
    ) -> Result<Option<rillane_core::PendingIngress>, InboundError> {
        // 契约纪律（与出口 mock 同）：先查取消——取消不算一次产出
        if cancel.is_cancelled() {
            return Err(InboundError::cancelled());
        }
        let n = self.produced.fetch_add(1, Ordering::Relaxed);
        if n > 0 {
            return Ok(None); // 受控关闭
        }
        let pending = PendingStream::new(
            format!("s-mock-{n}"),
            IngressOrigin::Proxy,
            EndpointRef::new("8.8.8.8", 443),
            Box::new(MockClient {
                closed: Arc::new(AtomicBool::new(false)),
                written: Mutex::new(Vec::new()),
            }),
            Box::new(MockResponder {
                replies: Arc::new(Mutex::new(Vec::new())),
                accept_fails: false,
            }),
        )
        .expect("合法会话");
        Ok(Some(rillane_core::PendingIngress::Stream(pending)))
    }
}

struct MockFactory;

impl rillane_core::InboundFactory for MockFactory {
    fn kind(&self) -> &'static str {
        "socks5"
    }

    fn validate(&self, spec: &InboundSpec) -> Result<(), InboundError> {
        if spec.kind != self.kind() {
            return Err(InboundError::unsupported(format!(
                "factory serves {}, got {}",
                self.kind(),
                spec.kind
            )));
        }
        Ok(())
    }

    fn build(
        &self,
        spec: &InboundSpec,
    ) -> Result<Arc<dyn rillane_core::InboundAcceptor>, InboundError> {
        self.validate(spec)?;
        Ok(Arc::new(MockAcceptor {
            spec: spec.clone(),
            produced: AtomicU32::new(0),
        }))
    }
}
