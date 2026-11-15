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
use rillane_core::{
    AttemptOutcome, CancelToken, ClientChannel, ControlLink, DatagramIo, DatagramOutbound,
    EndpointRef, FallbackCatalog, GenerationRef, InboundError, InboundResponder, IngressOrigin,
    OpenContext, OpenError, OpenStage, OpenedAssociation, OpenedStream, OutboundCapabilities,
    PendingAssociation, PendingStream, RejectCause, RouteDecision, RoutePlan, SessionExecutor,
    SessionRunError, SourceKey, StreamForwardReport, StreamIo, StreamOutbound, TargetBinding,
    CODE_OPEN_TIMEOUT,
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

    // 客户端中继脚本：旁落目标 → 超限 → 合法 → 置位控制链后 EOF
    let mut client_relay = ScriptDgramIo {
        script: Mutex::new(VecDeque::from([
            DgramAction::Packet(t2.clone(), Bytes::from_static(b"wrong")),
            DgramAction::Packet(t1.clone(), Bytes::from(vec![0u8; 2000])),
            DgramAction::Packet(t1.clone(), Bytes::from_static(b"ok")),
            DgramAction::CloseAndEof(control.clone()),
        ])),
        sent: Mutex::new(Vec::new()),
    };
    let outbound = Arc::new(ScriptedDatagram {
        fail: false,
        opens: AtomicU32::new(0),
        // 出口脚本：回程一条，然后挂起
        egress_script: vec![DgramAction::Packet(
            EndpointRef::new("8.8.8.8", 53),
            Bytes::from_static(b"back"),
        )],
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
