//! RIL-098 会话执行器统一接线验收：
//! - 一条权威路径：接入确认 → 出口尝试（计划内回退，复用执行器唯一选路）
//!   → 成功回复 → 双向转发 → 半关闭/取消/回收；
//! - A 失败 B 成功可追踪（attempts 对账）；
//! - 业务交换后不盲目重放（搬运期失败/取消不发起第二次出口建立）；
//! - TCP/UDP 不同生命周期：UDP 逐报文校验绑定/上限，控制链关闭回收；
//! - 背压：有界分片读一写一，半关闭按 TCP 语义驱动对侧。
//!
//! 用脚本化内存适配器钉契约，不依赖真实协议实现。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use rillane_core::collector::{CollectorConfig, FlowCollector};
use rillane_core::trace::{AttemptId, FlowId, FlowOrigin, TraceStage};
use rillane_core::{
    AttemptOutcome, CancelToken, ClientChannel, ControlLink, DatagramIo, DatagramOutbound,
    EndpointRef, EvidenceKind, FallbackCatalog, GenerationRef, InboundError, InboundResponder,
    IngressOrigin, OpenContext, OpenError, OpenStage, OpenedAssociation, OpenedStream,
    OutboundCapabilities, PendingAssociation, PendingStream, RejectCause, RouteDecision, RoutePlan,
    SessionExecutor, SessionRunError, SessionTracer, SourceKey, StreamForwardReport, StreamIo,
    StreamOutbound, TargetBinding, CODE_ASSOCIATION_MAPPED, CODE_ASSOCIATION_RECLAIMED,
    CODE_EGRESS_ESTABLISHED, CODE_OPEN_TIMEOUT, CODE_STREAM_CLOSED, CODE_TRACE_PLAN,
    CODE_TRACE_RULE, CODE_TRACE_TAKEOVER, CODE_TRANSFER_FIRST_DOWN, CODE_TRANSFER_FIRST_UP,
};

// ---------- 回退目录与计划 ----------

struct ScriptCatalog {
    endpoints: HashMap<&'static str, (&'static str, u16)>,
    fallbacks: HashMap<&'static str, Vec<&'static str>>,
}

impl FallbackCatalog for ScriptCatalog {
    fn endpoint(&self, _generation: &GenerationRef, node: &str) -> Option<EndpointRef> {
        self.endpoints
            .get(node)
            .map(|(host, port)| EndpointRef::new(*host, *port))
    }

    fn fallbacks(&self, _generation: &GenerationRef, node: &str) -> Vec<String> {
        self.fallbacks
            .get(node)
            .map(|v| v.iter().map(|s| (*s).to_string()).collect())
            .unwrap_or_default()
    }
}

fn catalog_ab() -> ScriptCatalog {
    ScriptCatalog {
        endpoints: HashMap::from([("A", ("9.9.9.9", 443)), ("B", ("10.0.0.1", 443))]),
        fallbacks: HashMap::from([("A", vec!["B"])]),
    }
}

/// 单候选目录：无回退，失败即耗尽
fn catalog_a_only() -> ScriptCatalog {
    ScriptCatalog {
        endpoints: HashMap::from([("A", ("9.9.9.9", 443))]),
        fallbacks: HashMap::new(),
    }
}

fn plan_for(node: &str) -> RoutePlan {
    let decision = RouteDecision::direct(node.to_string());
    let generation = GenerationRef::new("gen-1").expect("非空代际");
    RoutePlan::from_decision(&decision, generation).expect("合法计划")
}

fn ctx_for(session: &str) -> OpenContext {
    OpenContext::new(session, GenerationRef::new("gen-1").unwrap()).unwrap()
}

// ---------- 字节流出口脚本 ----------

/// 脚本化流出口：`fail_hosts` 里的对端拨号即超时失败（候选 A），其余
/// 成功并交付按 `egress_script` 驱动的出口 IO
struct ScriptedStream {
    fail_hosts: Vec<&'static str>,
    opens: AtomicU32,
    egress_script: Vec<DgramScript>,
}

/// Hang 为挂起脚本步（当前用例未走到，保留以固定枚举口径）
#[derive(Clone)]
#[allow(dead_code)]
enum DgramScript {
    Packet(Bytes),
    Eof,
    Fail,
    Hang,
}

struct ScriptEgress {
    script: Mutex<VecDeque<DgramScript>>,
    writes: Mutex<Vec<Bytes>>,
    shutdown_written: Arc<AtomicBool>,
}

#[async_trait]
impl StreamIo for ScriptEgress {
    async fn write_all(&mut self, data: Bytes) -> Result<usize, OpenError> {
        let n = data.len();
        self.writes.lock().unwrap().push(data);
        Ok(n)
    }

    async fn read(&mut self, _max: usize) -> Result<Option<Bytes>, OpenError> {
        let step = self.script.lock().unwrap().pop_front();
        match step {
            Some(DgramScript::Packet(data)) => Ok(Some(data)),
            Some(DgramScript::Eof) => Ok(None),
            Some(DgramScript::Fail) => Err(OpenError::new(
                OpenStage::Transport,
                "outbound.io.reset",
                true,
                rillane_core::EvidenceKind::Observed,
                "peer reset after handshake",
            )),
            Some(DgramScript::Hang) | None => Ok(std::future::pending::<Option<Bytes>>().await),
        }
    }

    async fn shutdown_write(&mut self) -> Result<(), OpenError> {
        self.shutdown_written.store(true, Ordering::Release);
        Ok(())
    }
}

#[async_trait]
impl StreamOutbound for ScriptedStream {
    fn name(&self) -> &'static str {
        "scripted"
    }

    fn capabilities(&self) -> OutboundCapabilities {
        OutboundCapabilities::stream_only().with_transport("tls")
    }

    async fn open_stream(
        &self,
        target: &EndpointRef,
        ctx: &OpenContext,
    ) -> Result<OpenedStream, OpenError> {
        ctx.check_openable(0)?;
        self.opens.fetch_add(1, Ordering::Relaxed);
        if self.fail_hosts.contains(&target.host.as_str()) {
            return Err(OpenError::timeout(
                OpenStage::Handshake,
                "tls handshake timed out",
            ));
        }
        Ok(OpenedStream::new(
            "scripted",
            target.clone(),
            "tls",
            21,
            Box::new(ScriptEgress {
                script: Mutex::new(self.egress_script.clone().into()),
                writes: Mutex::new(Vec::new()),
                shutdown_written: Arc::new(AtomicBool::new(false)),
            }),
        ))
    }
}

// ---------- 客户端通道脚本 ----------

struct ScriptClient {
    script: Mutex<VecDeque<DgramScript>>,
    writes: Mutex<Vec<Bytes>>,
    /// 第 n 次 read 时置位取消令牌（搬运期取消脚本）
    cancel_at_read: Option<(u32, CancelToken)>,
    reads_served: AtomicU32,
    shutdown_called: Arc<AtomicBool>,
}

#[async_trait]
impl ClientChannel for ScriptClient {
    async fn read(&mut self, _max: usize) -> Result<Option<Bytes>, InboundError> {
        let n = self.reads_served.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some((at, token)) = &self.cancel_at_read {
            if *at == n {
                token.cancel();
            }
        }
        let step = self.script.lock().unwrap().pop_front();
        match step {
            Some(DgramScript::Packet(data)) => Ok(Some(data)),
            Some(DgramScript::Eof) => Ok(None),
            Some(DgramScript::Fail) => Err(InboundError::new(
                rillane_core::InboundStage::Admit,
                "inbound.handshake",
                true,
                rillane_core::EvidenceKind::Observed,
                "client channel reset",
            )),
            Some(DgramScript::Hang) | None => Ok(std::future::pending::<Option<Bytes>>().await),
        }
    }

    async fn write_all(&mut self, data: Bytes) -> Result<(), InboundError> {
        self.writes.lock().unwrap().push(data);
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), InboundError> {
        self.shutdown_called.store(true, Ordering::Release);
        Ok(())
    }
}

// ---------- responder 记录 ----------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Reply {
    Accept {
        host: String,
        port: u16,
        transport: &'static str,
    },
    Reject {
        code: &'static str,
    },
}

struct RecordResponder {
    replies: Arc<Mutex<Vec<Reply>>>,
}

#[async_trait]
impl InboundResponder for RecordResponder {
    async fn accept(&mut self, info: &rillane_core::AcceptInfo) -> Result<(), InboundError> {
        self.replies.lock().unwrap().push(Reply::Accept {
            host: info.endpoint.host.clone(),
            port: info.endpoint.port,
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

struct AssocResponder {
    replies: Arc<Mutex<Vec<Reply>>>,
}

#[async_trait]
impl rillane_core::AssociationResponder for AssocResponder {
    async fn accept(&mut self, relay: &EndpointRef) -> Result<(), InboundError> {
        self.replies.lock().unwrap().push(Reply::Accept {
            host: relay.host.clone(),
            port: relay.port,
            transport: "raw",
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

fn stream_pending(
    client_script: Vec<DgramScript>,
    cancel_at_read: Option<(u32, CancelToken)>,
    replies: Arc<Mutex<Vec<Reply>>>,
    shutdown_called: Arc<AtomicBool>,
) -> PendingStream {
    PendingStream::new(
        "s-1",
        IngressOrigin::Proxy,
        EndpointRef::new("8.8.8.8", 443),
        Box::new(ScriptClient {
            script: Mutex::new(client_script.into()),
            writes: Mutex::new(Vec::new()),
            cancel_at_read,
            reads_served: AtomicU32::new(0),
            shutdown_called,
        }),
        Box::new(RecordResponder { replies }),
    )
    .expect("合法会话")
}

// ---------- 数据报出口脚本 ----------

#[derive(Clone)]
/// Eof/Hang/CloseAndPacket 为其他用例保留的脚本步（当前用例未走到，
/// 保留以固定枚举口径）
#[allow(dead_code)]
enum DgramAction {
    /// 投递一条报文
    Packet(EndpointRef, Bytes),
    /// 读侧正常关闭
    Eof,
    /// 永久挂起
    Hang,
    /// 置位控制链后投递
    CloseAndPacket(ControlLink, EndpointRef, Bytes),
    /// 置位控制链后关闭
    CloseAndEof(ControlLink),
}

struct ScriptDgramIo {
    script: Mutex<VecDeque<DgramAction>>,
    sent: Mutex<Vec<(EndpointRef, Bytes)>>,
}

#[async_trait]
impl DatagramIo for ScriptDgramIo {
    async fn send(&mut self, target: &EndpointRef, payload: Bytes) -> Result<(), OpenError> {
        self.sent.lock().unwrap().push((target.clone(), payload));
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<(EndpointRef, Bytes)>, OpenError> {
        let step = self.script.lock().unwrap().pop_front();
        match step {
            Some(DgramAction::Packet(ep, data)) => Ok(Some((ep, data))),
            Some(DgramAction::Eof) => Ok(None),
            Some(DgramAction::Hang) | None => {
                Ok(std::future::pending::<Option<(EndpointRef, Bytes)>>().await)
            }
            Some(DgramAction::CloseAndPacket(link, ep, data)) => {
                link.mark_closed();
                Ok(Some((ep, data)))
            }
            Some(DgramAction::CloseAndEof(link)) => {
                link.mark_closed();
                Ok(None)
            }
        }
    }
}

struct ScriptedDatagram {
    fail: bool,
    opens: AtomicU32,
    /// 出口 IO 的 recv 脚本（每次 open 交付一份拷贝）
    egress_script: Vec<DgramAction>,
}

#[async_trait]
impl DatagramOutbound for ScriptedDatagram {
    fn name(&self) -> &'static str {
        "scripted-udp"
    }

    fn capabilities(&self) -> OutboundCapabilities {
        OutboundCapabilities::stream_and_datagram(1500)
    }

    async fn open_association(
        &self,
        target: &TargetBinding,
        ctx: &OpenContext,
    ) -> Result<OpenedAssociation, OpenError> {
        ctx.check_openable(0)?;
        self.opens.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(OpenError::timeout(OpenStage::Dial, "udp dial timed out"));
        }
        Ok(OpenedAssociation::new(
            "scripted-udp",
            EndpointRef::new("10.0.0.2", 8388),
            "raw",
            0,
            target.clone(),
            1500,
            None,
            Box::new(ScriptDgramIo {
                script: Mutex::new(self.egress_script.clone().into()),
                sent: Mutex::new(Vec::new()),
            }),
        ))
    }
}

// ---------- 契约验收 ----------

/// ① 端到端 + 回退可追踪：A 失败 B 成功，成功回复携带 B 的实际端点，
/// 双向字节计数与双侧半关闭齐全
#[tokio::test]
async fn stream_fallback_traceable_end_to_end() {
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec!["9.9.9.9"],
        opens: AtomicU32::new(0),
        egress_script: vec![
            DgramScript::Packet(Bytes::from_static(b"pong")),
            DgramScript::Eof,
        ],
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut pending = stream_pending(
        vec![
            DgramScript::Packet(Bytes::from_static(b"ping")),
            DgramScript::Eof,
        ],
        None,
        replies.clone(),
        shutdown.clone(),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let report: StreamForwardReport = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound.clone(),
        ctx_for("s-1"),
        0,
        None,
    )
    .await
    .expect("A 失败 B 成功应建立成功");

    // A 失败 B 成功可追踪：对账在 attempts（执行器唯一记录面）
    let attempts = report.session.attempts();
    assert_eq!(attempts.len(), 2, "两次候选尝试");
    assert_eq!(attempts[0].node, "A");
    assert!(matches!(
        &attempts[0].outcome,
        AttemptOutcome::Failed { .. }
    ));
    assert_eq!(attempts[1].node, "B");
    assert_eq!(attempts[1].outcome, AttemptOutcome::Dialed);

    // 成功回复只在 B 建立之后发出，携带实际端点与传输
    assert_eq!(
        *replies.lock().unwrap(),
        vec![Reply::Accept {
            host: "10.0.0.1".into(),
            port: 443,
            transport: "tls",
        }]
    );

    // 业务字节双向计数 + 半关闭
    assert_eq!(report.client_to_egress, 4);
    assert_eq!(report.egress_to_client, 4);
    assert!(report.client_closed && report.egress_closed);
    assert!(shutdown.load(Ordering::Acquire), "EOF 驱动客户端半关闭");
}

/// ② 全部候选失败 → 拒绝回复携带出口稳定码，绝无成功回复
#[tokio::test]
async fn stream_all_candidates_fail_rejects_with_egress_code() {
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec!["9.9.9.9", "10.0.0.1"],
        opens: AtomicU32::new(0),
        egress_script: Vec::new(),
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = stream_pending(
        Vec::new(),
        None,
        replies.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let err = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound,
        ctx_for("s-2"),
        0,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(
        err,
        SessionRunError::Rejected {
            code: CODE_OPEN_TIMEOUT,
            attempts: 2,
        }
    );
    assert_eq!(
        *replies.lock().unwrap(),
        vec![Reply::Reject {
            code: CODE_OPEN_TIMEOUT,
        }],
        "出口失败原样映射为协议错误，无成功回复"
    );
}

/// ③ 建立期取消：零回复零拨号（调用方丢弃 pending 关闭资源，不重复回复）
#[tokio::test]
async fn stream_cancel_before_establishment_never_replies() {
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec![],
        opens: AtomicU32::new(0),
        egress_script: Vec::new(),
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = stream_pending(Vec::new(), None, replies, Arc::new(AtomicBool::new(false)));
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let ctx = ctx_for("s-3");
    ctx.cancel.cancel();
    let err = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound.clone(),
        ctx,
        0,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        err,
        SessionRunError::Cancelled {
            client_to_egress: 0,
            egress_to_client: 0,
        }
    );
    assert_eq!(outbound.opens.load(Ordering::Relaxed), 0, "取消不产生拨号");
}

/// ④ 业务交换后失败：**不重放**——出口建立次数停在建立期，失败按
/// TransferFailed 显式声明边界，已交付字节如实计数
#[tokio::test]
async fn stream_transfer_failure_never_replays() {
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec!["9.9.9.9"],
        opens: AtomicU32::new(0),
        egress_script: vec![
            DgramScript::Packet(Bytes::from_static(b"hello")),
            DgramScript::Fail,
        ],
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = stream_pending(Vec::new(), None, replies, Arc::new(AtomicBool::new(false)));
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let err = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound.clone(),
        ctx_for("s-4"),
        0,
        None,
    )
    .await
    .unwrap_err();

    match &err {
        SessionRunError::TransferFailed {
            direction,
            code,
            egress_to_client,
            ..
        } => {
            assert_eq!(direction.as_str(), "egress_to_client");
            assert_eq!(*code, "outbound.io.reset");
            assert_eq!(*egress_to_client, 5, "已交付的业务字节被如实计数");
        }
        other => panic!("应为搬运期失败，得到 {other:?}"),
    }
    // 建立期 2 次尝试（A 失败 B 成功）；搬运期失败**零次新建立**——
    // 业务交换已发生，不得盲目重放到另一出口
    assert_eq!(outbound.opens.load(Ordering::Relaxed), 2);
    assert!(err.to_string().contains("no replay"));
}

/// ⑤ 搬运期取消：立即停止且不发起新建立，已交换字节如实计数
#[tokio::test]
async fn stream_cancel_mid_transfer_stops_without_new_open() {
    let cancel_token = CancelToken::new();
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec!["9.9.9.9"],
        opens: AtomicU32::new(0),
        egress_script: Vec::new(), // 出口读永久挂起：只有客户端方向在流动
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = stream_pending(
        vec![
            DgramScript::Packet(Bytes::from_static(b"a")),
            DgramScript::Packet(Bytes::from_static(b"b")),
        ],
        Some((2, cancel_token.clone())),
        replies,
        Arc::new(AtomicBool::new(false)),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    // 搬运期取消走 ctx.cancel：把测试令牌接进上下文
    let mut ctx = ctx_for("s-5");
    ctx.cancel = cancel_token.clone();
    let err = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound.clone(),
        ctx,
        0,
        None,
    )
    .await
    .unwrap_err();

    match &err {
        SessionRunError::Cancelled {
            client_to_egress,
            egress_to_client,
        } => {
            assert!(*client_to_egress >= 2, "取消前已交换的业务字节如实计数");
            assert_eq!(*egress_to_client, 0);
        }
        other => panic!("应为搬运期取消，得到 {other:?}"),
    }
    assert_eq!(
        outbound.opens.load(Ordering::Relaxed),
        2,
        "取消后零次新建立"
    );
}

/// ⑥ UDP 关联：逐报文校验目标绑定与上限（显式计数拒绝），控制链关闭
/// 按契约回收；出口方向回程投递到客户端元组
#[tokio::test]
async fn association_binding_reject_and_control_reclaim() {
    let control = ControlLink::new();
    let t1 = EndpointRef::new("10.0.0.9", 53);
    let t2 = EndpointRef::new("10.0.0.10", 53);
    let client_endpoint = EndpointRef::new("192.168.1.5", 50000);

    // 客户端中继脚本：旁落目标 → 超限 → 合法 → 挂起（泵 biased 序
    // 客户端上行优先——挂起让出轮询，回程与回收在出口脚本按序到达）
    let mut client_relay = ScriptDgramIo {
        script: Mutex::new(VecDeque::from([
            DgramAction::Packet(t2.clone(), Bytes::from_static(b"wrong")),
            DgramAction::Packet(t1.clone(), Bytes::from(vec![0u8; 2000])),
            DgramAction::Packet(t1.clone(), Bytes::from_static(b"ok")),
            DgramAction::Hang,
        ])),
        sent: Mutex::new(Vec::new()),
    };
    let outbound = Arc::new(ScriptedDatagram {
        fail: false,
        opens: AtomicU32::new(0),
        // 出口脚本：回程一条，然后置位控制链并关闭（回收口径终点——
        // 脚本顺序即泵的服务顺序，同输入同观测，可离线重放）
        egress_script: vec![
            DgramAction::Packet(EndpointRef::new("8.8.8.8", 53), Bytes::from_static(b"back")),
            DgramAction::CloseAndEof(control.clone()),
        ],
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = PendingAssociation::new(
        SourceKey::new("client-1:50000").unwrap(),
        TargetBinding::Multi {
            allowed: vec![t1.clone()],
        },
        1500,
        control.clone(),
        Box::new(AssocResponder {
            replies: replies.clone(),
        }),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let report = rillane_core::run_association_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound.clone(),
        TargetBinding::Multi {
            allowed: vec![t1.clone()],
        },
        ctx_for("u-1"),
        0,
        &EndpointRef::new("10.0.0.2", 8388),
        &client_endpoint,
        &mut client_relay,
        None,
    )
    .await
    .expect("关联会话应建立并回收");

    assert_eq!(report.client_to_egress, 1, "仅合法目标报文送达出口");
    assert_eq!(report.egress_to_client, 1, "回程投递到客户端元组");
    assert_eq!(report.rejected_too_large, 1, "超限显式计数不静默截断");
    assert_eq!(report.rejected_target, 1, "绑定外目标显式计数不旁落");
    assert!(report.reclaimed_by_control, "控制链关闭即回收");
    assert_eq!(outbound.opens.load(Ordering::Relaxed), 1, "关联只建立一次");
    assert_eq!(
        *replies.lock().unwrap(),
        vec![Reply::Accept {
            host: "10.0.0.2".into(),
            port: 8388,
            transport: "raw",
        }]
    );
    // 旁落目标从未到达出口；回程字节投递到客户端元组
    let relay_sent = client_relay.sent.lock().unwrap();
    assert_eq!(
        *relay_sent,
        vec![(client_endpoint.clone(), Bytes::from_static(b"back"))],
        "出口方向报文按客户端元组回程投递"
    );
}

/// ⑦ 数据报出口建立失败 → 拒绝携带出口稳定码
#[tokio::test]
async fn association_establish_failure_rejects() {
    let outbound = Arc::new(ScriptedDatagram {
        fail: true,
        opens: AtomicU32::new(0),
        egress_script: Vec::new(),
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = PendingAssociation::new(
        SourceKey::new("client-2:60000").unwrap(),
        TargetBinding::Multi { allowed: vec![] },
        1500,
        ControlLink::new(),
        Box::new(AssocResponder {
            replies: replies.clone(),
        }),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_a_only()));
    let mut plan = plan_for("A");

    let mut idle_relay = ScriptDgramIo {
        script: Mutex::new(VecDeque::new()),
        sent: Mutex::new(Vec::new()),
    };
    let err = rillane_core::run_association_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound,
        TargetBinding::Multi { allowed: vec![] },
        ctx_for("u-2"),
        0,
        &EndpointRef::new("10.0.0.2", 8388),
        &EndpointRef::new("192.168.1.5", 50001),
        &mut idle_relay,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(
        err,
        SessionRunError::Rejected {
            code: CODE_OPEN_TIMEOUT,
            attempts: 1,
        }
    );
    assert_eq!(
        *replies.lock().unwrap(),
        vec![Reply::Reject {
            code: CODE_OPEN_TIMEOUT,
        }]
    );
}

// ---------- RIL-053 生命周期埋点 ----------

/// 开轨助手：锚注入 + 可选采集器（时钟基准由测试固定，流逝为真实测量）
fn tracer_for(
    collector: Option<Arc<Mutex<FlowCollector>>>,
    flow: &str,
    origin: FlowOrigin,
) -> SessionTracer {
    SessionTracer::start(
        collector,
        FlowId::new(flow).expect("合法 flow id"),
        origin,
        "gen-1",
        1_000,
        1_760_000_000_000,
        "tcp 8.8.8.8:443",
    )
    .expect("开轨")
}

/// ⑧ A 失败 B 成功的完整轨迹：序列连续、终态闭合、事件逐段可解释
/// （接管→规则→计划→尝试×2→实际出口→首字节上/下行→关闭），采集器
/// 汇聚与本地权威轨迹一致；无 RTT/丢包造数
#[tokio::test]
async fn trace_stream_full_lifecycle_explains_fallback() {
    let collector = Arc::new(Mutex::new(FlowCollector::new(
        CollectorConfig::new(64, 8, 64, 3_600_000, 1, true).expect("合法配置"),
    )));
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec!["9.9.9.9"],
        opens: AtomicU32::new(0),
        egress_script: vec![
            DgramScript::Packet(Bytes::from_static(b"pong")),
            DgramScript::Eof,
        ],
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = stream_pending(
        vec![
            DgramScript::Packet(Bytes::from_static(b"ping")),
            DgramScript::Eof,
        ],
        None,
        replies,
        Arc::new(AtomicBool::new(false)),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    // 显式供因：规则事件只在计划携带决策原因时落点（无原因不造数）
    let decision = RouteDecision {
        reason: Some("rule match: direct".to_string()),
        ..RouteDecision::direct("A".to_string())
    };
    let mut plan = RoutePlan::from_decision(&decision, GenerationRef::new("gen-1").unwrap())
        .expect("合法计划");

    let mut tracer = tracer_for(Some(collector.clone()), "flow-tcp-1", FlowOrigin::Stream);

    let report = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound.clone(),
        ctx_for("s-t1"),
        0,
        Some(&mut tracer),
    )
    .await
    .expect("A 失败 B 成功应建立成功");
    assert_eq!(report.client_to_egress, 4);
    assert!(report.first_up_ms.is_some(), "首字节上行实测");
    assert!(report.first_down_ms.is_some(), "首字节下行实测");

    let trace = tracer.into_trace();
    trace.validate().expect("序列连续且终态闭合");

    // 逐段齐全：接管→规则→计划→尝试×2→出口→首字节上/下行→关闭
    let codes: Vec<&str> = trace.events.iter().map(|e| e.code).collect();
    assert_eq!(codes.first(), Some(&CODE_TRACE_TAKEOVER));
    assert!(codes.contains(&CODE_TRACE_RULE), "规则命中入轨");
    assert!(codes.contains(&CODE_TRACE_PLAN), "计划形成入轨");
    let attempts: Vec<_> = trace
        .events
        .iter()
        .filter(|e| e.stage == TraceStage::Attempt)
        .collect();
    assert_eq!(attempts.len(), 2, "A 失败 B 成功逐条入轨");
    for (i, event) in attempts.iter().enumerate() {
        assert_eq!(
            event.attempt,
            Some(AttemptId(i as u32)),
            "尝试事件必须携带 attempt_id"
        );
    }
    assert!(codes.contains(&CODE_EGRESS_ESTABLISHED), "实际出口入轨");
    assert!(codes.contains(&CODE_TRANSFER_FIRST_UP));
    assert!(codes.contains(&CODE_TRANSFER_FIRST_DOWN));
    assert_eq!(codes.last(), Some(&CODE_STREAM_CLOSED));

    // 证据不混淆：规则/计划 = 预测；内核落点 = 观测；绝无 Unknown
    for event in &trace.events {
        match event.stage {
            TraceStage::Rule | TraceStage::Plan => {
                assert_eq!(event.evidence, EvidenceKind::Predicted);
            }
            TraceStage::Attempt => {
                assert_ne!(event.evidence, EvidenceKind::Unknown);
            }
            _ => assert_eq!(event.evidence, EvidenceKind::Observed),
        }
        // 缺少测量证据不造数：无 RTT/丢包字样
        assert!(!event.code.contains("rtt") && !event.code.contains("loss"));
    }
    // 内核供钟单调不减，墙钟与单调成对推进
    let first = trace.events.first().expect("首事件存在");
    let mut last_mono = first.monotonic_ms;
    for event in &trace.events {
        assert!(event.monotonic_ms >= last_mono);
        assert!(event.wall_ms >= first.wall_ms);
        last_mono = event.monotonic_ms;
    }

    // 采集器汇聚同一流：flow id 一致、事件数一致（首流必入选）
    let drained = collector.lock().unwrap().drain_closed(4);
    assert_eq!(drained.len(), 1, "首流必被采集器收录");
    assert_eq!(drained[0].flow.as_str(), "flow-tcp-1");
    assert_eq!(
        drained[0].events.len(),
        trace.events.len(),
        "汇聚轨迹与本地权威轨迹事件一致"
    );
    assert_eq!(
        drained[0].events.last().map(|e| e.code),
        Some(CODE_STREAM_CLOSED)
    );
}

/// ⑨ 建立失败轨迹：终态码与拒绝回复同源（最近一次出口稳定码），
/// 尝试逐条入轨，无出口建立/传输事件
#[tokio::test]
async fn trace_stream_rejection_carries_egress_code() {
    let outbound = Arc::new(ScriptedStream {
        fail_hosts: vec!["9.9.9.9", "10.0.0.1"],
        opens: AtomicU32::new(0),
        egress_script: Vec::new(),
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = stream_pending(Vec::new(), None, replies, Arc::new(AtomicBool::new(false)));
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let mut tracer = tracer_for(None, "flow-tcp-2", FlowOrigin::Stream);
    let err = rillane_core::run_stream_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound,
        ctx_for("s-t2"),
        0,
        Some(&mut tracer),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err,
        SessionRunError::Rejected {
            code: CODE_OPEN_TIMEOUT,
            attempts: 2,
        }
    );

    let trace = tracer.into_trace();
    trace.validate().expect("拒绝路径同样完整闭合");
    let attempts: Vec<_> = trace
        .events
        .iter()
        .filter(|e| e.stage == TraceStage::Attempt)
        .collect();
    assert_eq!(attempts.len(), 2, "两次失败尝试逐条入轨");
    let codes: Vec<&str> = trace.events.iter().map(|e| e.code).collect();
    assert!(
        !codes.contains(&CODE_EGRESS_ESTABLISHED) && !codes.contains(&CODE_TRANSFER_FIRST_UP),
        "失败轨迹无出口建立/传输事件"
    );
    let close = trace.events.last().expect("终态存在");
    assert_eq!(close.stage, TraceStage::Close);
    assert_eq!(close.code, CODE_OPEN_TIMEOUT, "轨迹终态码与拒绝回复同源");
}

/// ⑩ UDP 关联轨迹：起止语义为 association 侧——出口事件 = 映射建立
/// （TCP 出口码不出现），控制链关闭 → association.reclaimed 终态；
/// 首报文上/下行入轨
#[tokio::test]
async fn trace_association_mapped_and_reclaimed() {
    let control = ControlLink::new();
    let t1 = EndpointRef::new("10.0.0.9", 53);
    let client_endpoint = EndpointRef::new("192.168.1.5", 50000);

    let mut client_relay = ScriptDgramIo {
        script: Mutex::new(VecDeque::from([
            DgramAction::Packet(t1.clone(), Bytes::from_static(b"ok")),
            DgramAction::Hang,
        ])),
        sent: Mutex::new(Vec::new()),
    };
    let outbound = Arc::new(ScriptedDatagram {
        fail: false,
        opens: AtomicU32::new(0),
        // 数据报先于控制链关闭入队（脚本逐弹出队）——两条数据报文
        // 必然先于回收被处理，回收经出口读侧观察到控制链已关闭
        egress_script: vec![
            DgramAction::Packet(EndpointRef::new("8.8.8.8", 53), Bytes::from_static(b"back")),
            DgramAction::CloseAndEof(control.clone()),
        ],
    });
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut pending = PendingAssociation::new(
        SourceKey::new("client-t:50000").unwrap(),
        TargetBinding::Multi {
            allowed: vec![t1.clone()],
        },
        1500,
        control,
        Box::new(AssocResponder { replies }),
    );
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));
    let mut plan = plan_for("A");

    let mut tracer = tracer_for(None, "flow-udp-1", FlowOrigin::Association);
    let report = rillane_core::run_association_session(
        &executor,
        &mut pending,
        &mut plan,
        outbound,
        TargetBinding::Multi { allowed: vec![t1] },
        ctx_for("u-t1"),
        0,
        &EndpointRef::new("10.0.0.2", 8388),
        &client_endpoint,
        &mut client_relay,
        Some(&mut tracer),
    )
    .await
    .expect("关联会话应建立并回收");
    assert_eq!(report.client_to_egress, 1);
    assert!(report.reclaimed_by_control);

    let trace = tracer.into_trace();
    trace.validate().expect("关联轨迹完整闭合");
    assert_eq!(
        trace.origin,
        FlowOrigin::Association,
        "起止语义在类型上分侧"
    );
    let codes: Vec<&str> = trace.events.iter().map(|e| e.code).collect();
    assert!(
        codes.contains(&CODE_ASSOCIATION_MAPPED),
        "映射建立为关联出口事件"
    );
    assert!(
        !codes.contains(&CODE_EGRESS_ESTABLISHED),
        "TCP 出口码不进关联轨迹"
    );
    assert!(codes.contains(&CODE_TRANSFER_FIRST_UP));
    assert!(codes.contains(&CODE_TRANSFER_FIRST_DOWN));
    assert_eq!(
        codes.last(),
        Some(&CODE_ASSOCIATION_RECLAIMED),
        "控制链关闭 → 回收终态"
    );
}

/// ⑪ 采样剔除不伤本地权威轨迹：第二流被确定性采样剔除后，其本地轨迹
/// 仍完整（逐会话契约），采集器只留首流、剔除显式计数
#[tokio::test]
async fn trace_local_authority_survives_sampling_out() {
    let collector = Arc::new(Mutex::new(FlowCollector::new(
        CollectorConfig::new(64, 8, 64, 3_600_000, 2, true).expect("合法配置"),
    )));
    let executor = SessionExecutor::new(Arc::new(catalog_ab()));

    // 第一流：确定性采样入选（第 1 条新流）
    let outbound_a = Arc::new(ScriptedStream {
        fail_hosts: vec![],
        opens: AtomicU32::new(0),
        egress_script: vec![DgramScript::Eof],
    });
    let mut pending_a = stream_pending(
        vec![DgramScript::Eof],
        None,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(AtomicBool::new(false)),
    );
    let mut plan_a = plan_for("A");
    let mut tracer_a = tracer_for(Some(collector.clone()), "flow-tcp-a", FlowOrigin::Stream);
    rillane_core::run_stream_session(
        &executor,
        &mut pending_a,
        &mut plan_a,
        outbound_a,
        ctx_for("s-t3"),
        0,
        Some(&mut tracer_a),
    )
    .await
    .expect("第一流应成功");

    // 第二流：确定性采样剔除（第 2 条新流：(2-1)%2 != 0）
    let outbound_b = Arc::new(ScriptedStream {
        fail_hosts: vec![],
        opens: AtomicU32::new(0),
        egress_script: vec![DgramScript::Eof],
    });
    let mut pending_b = stream_pending(
        vec![DgramScript::Eof],
        None,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(AtomicBool::new(false)),
    );
    let mut plan_b = plan_for("A");
    let mut tracer_b = tracer_for(Some(collector.clone()), "flow-tcp-b", FlowOrigin::Stream);
    rillane_core::run_stream_session(
        &executor,
        &mut pending_b,
        &mut plan_b,
        outbound_b,
        ctx_for("s-t4"),
        0,
        Some(&mut tracer_b),
    )
    .await
    .expect("第二流应成功");

    // 本地权威轨迹不受采样影响：仍完整且终态闭合
    let trace_b = tracer_b.into_trace();
    trace_b.validate().expect("被剔除流本地轨迹仍完整闭合");
    assert_eq!(trace_b.flow.as_str(), "flow-tcp-b");
    assert_eq!(
        trace_b.events.first().map(|e| e.code),
        Some(CODE_TRACE_TAKEOVER)
    );
    assert_eq!(
        trace_b.events.last().map(|e| e.code),
        Some(CODE_STREAM_CLOSED)
    );

    // 采集器只留首流；剔除显式计数
    let drained = collector.lock().unwrap().drain_closed(8);
    assert_eq!(drained.len(), 1, "采样剔除流不进采集器");
    assert_eq!(drained[0].flow.as_str(), "flow-tcp-a");
    assert_eq!(collector.lock().unwrap().stats().traces_sampled_out, 1);
}
