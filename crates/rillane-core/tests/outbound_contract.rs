//! RIL-097 出口建立通道契约验收：
//! - 建立与搬运分开：[`StreamOutbound::open_stream`] 返回已建立通道，
//!   业务 IO 在通道句柄里；
//! - 一次建立只尝试一次（出口不得内部重试/改选，回退归会话执行器）；
//! - 失败携带阶段 + 稳定码 + 证据类型 + 脱敏上下文；
//! - TCP 字节流与 UDP 数据报关联在类型层面分侧；
//! - 目标绑定明确（固定 / 多目标）；报文上限显式。
//!
//! 用最小内存适配器钉契约，不依赖任何真实协议库。

use std::sync::Mutex;

use bytes::Bytes;
use rillane_core::{
    DatagramIo, DatagramOutbound, EndpointRef, GenerationRef, OpenContext, OpenError, OpenStage,
    OutboundCapabilities, StreamIo, StreamOutbound, TargetBinding, CODE_OPEN_CANCELLED,
    CODE_OPEN_TIMEOUT,
};

// ---------- 最小内存适配器 ----------

struct MemStream {
    out: Vec<Bytes>,
    incoming: Vec<Bytes>,
    half_closed: bool,
}

#[async_trait::async_trait]
impl StreamIo for MemStream {
    async fn write_all(&mut self, data: Bytes) -> Result<usize, OpenError> {
        let n = data.len();
        self.out.push(data);
        Ok(n)
    }

    async fn read(&mut self, _max: usize) -> Result<Option<Bytes>, OpenError> {
        Ok(self.incoming.pop())
    }

    async fn shutdown_write(&mut self) -> Result<(), OpenError> {
        self.half_closed = true;
        Ok(())
    }
}

struct MemDatagram {
    sent: Vec<(EndpointRef, Bytes)>,
}

#[async_trait::async_trait]
impl DatagramIo for MemDatagram {
    async fn send(&mut self, target: &EndpointRef, payload: Bytes) -> Result<(), OpenError> {
        self.sent.push((target.clone(), payload));
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<(EndpointRef, Bytes)>, OpenError> {
        Ok(None)
    }
}

/// 适配器：`attempts` 由适配器自身计数——证明「出口内部不做二次尝试」
/// 只能通过调用方观测（回退在会话执行器，不在出口）。
struct MockStream {
    /// 建立次数计数（契约钉：一次 open = 一次尝试）
    attempts: Mutex<u32>,
    fail_open: Option<OpenError>,
}

#[async_trait::async_trait]
impl StreamOutbound for MockStream {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn capabilities(&self) -> OutboundCapabilities {
        OutboundCapabilities::stream_only().with_transport("raw")
    }

    async fn open_stream(
        &self,
        _target: &EndpointRef,
        ctx: &OpenContext,
    ) -> Result<rillane_core::OpenedStream, OpenError> {
        // 契约①：建立期统一先查取消/到期——未开始工作不计为一次尝试
        ctx.check_openable(0)?;
        *self.attempts.lock().unwrap() += 1;
        if let Some(err) = self.fail_open.clone() {
            return Err(err);
        }
        Ok(rillane_core::OpenedStream::new(
            "mock",
            EndpointRef::new("10.0.0.1", 443),
            "tls",
            42,
            Box::new(MemStream {
                out: Vec::new(),
                incoming: Vec::new(),
                half_closed: false,
            }),
        ))
    }
}

struct MockDatagram;

#[async_trait::async_trait]
impl DatagramOutbound for MockDatagram {
    fn name(&self) -> &'static str {
        "mock-udp"
    }

    fn capabilities(&self) -> OutboundCapabilities {
        OutboundCapabilities::stream_and_datagram(1500)
    }

    async fn open_association(
        &self,
        target: &TargetBinding,
        ctx: &OpenContext,
    ) -> Result<rillane_core::OpenedAssociation, OpenError> {
        ctx.check_openable(0)?;
        Ok(rillane_core::OpenedAssociation::new(
            "mock-udp",
            EndpointRef::new("10.0.0.2", 8388),
            "raw",
            0,
            target.clone(),
            1500,
            Some(5_000),
            Box::new(MemDatagram { sent: Vec::new() }),
        ))
    }
}

// ---------- 契约验收 ----------

/// ① 建立与搬运分开：open 返回已建立通道，握手机制结果随通道走；
///    后续读写走通道句柄，出口不再参与。
#[tokio::test]
async fn open_returns_channel_that_owns_protocol_state() {
    let mock = MockStream {
        attempts: Mutex::new(0),
        fail_open: None,
    };
    let ctx = OpenContext::new("s-1", GenerationRef::new("gen-1").unwrap()).unwrap();
    let target = EndpointRef::new("10.0.0.1", 443);

    let opened = mock.open_stream(&target, &ctx).await.unwrap();
    assert_eq!(opened.name(), "mock");
    assert_eq!(opened.transport(), "tls", "传输结果随通道持有");
    assert_eq!(opened.handshake_ms(), 42, "握手结果随通道持有");
    assert_eq!(opened.endpoint(), &EndpointRef::new("10.0.0.1", 443));

    // 业务搬运走通道：取走 IO 后原句柄消失，出口无法再介入
    let (endpoint, _transport, mut io) = opened.into_parts();
    assert_eq!(endpoint, EndpointRef::new("10.0.0.1", 443));
    io.write_all(Bytes::from_static(b"hello")).await.unwrap();
    assert!(io.shutdown_write().await.is_ok());
    assert_eq!(*mock.attempts.lock().unwrap(), 1, "一次建立只尝试一次");
}

/// ② 一次建立只尝试一次：失败立即返回，出口不内部重试、不改选目标。
///    会话执行器按 RoutePlan 决定是否回退（契约外，不在出口内部）。
#[tokio::test]
async fn one_attempt_per_open_no_internal_retry() {
    let mock = MockStream {
        attempts: Mutex::new(0),
        fail_open: Some(OpenError::timeout(OpenStage::Handshake, "tls timed out")),
    };
    let ctx = OpenContext::new("s-2", GenerationRef::new("gen-2").unwrap()).unwrap();

    let err = mock
        .open_stream(&EndpointRef::new("1.1.1.1", 443), &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.stage, OpenStage::Handshake);
    assert_eq!(err.code, CODE_OPEN_TIMEOUT);
    assert!(
        err.to_string().contains(CODE_OPEN_TIMEOUT),
        "失败须可诊断（稳定码入文案）"
    );
    assert_eq!(*mock.attempts.lock().unwrap(), 1, "不得内部重试");

    // 再调一次是新的会话执行器尝试，不是出口自行重试
    let err2 = mock
        .open_stream(&EndpointRef::new("1.1.1.1", 443), &ctx)
        .await
        .unwrap_err();
    assert_eq!(*mock.attempts.lock().unwrap(), 2);
    assert_eq!(err2.stage, OpenStage::Handshake);
}

/// ③ 取消/到期在建立期即拦下，不产生建立尝试，且不可重试
#[tokio::test]
async fn cancel_aborts_before_attempt() {
    let mock = MockStream {
        attempts: Mutex::new(0),
        fail_open: None,
    };

    // 取消令牌已置位
    let ctx = OpenContext::new("s-3", GenerationRef::new("gen-3").unwrap())
        .unwrap()
        .with_attempt_id(2)
        .with_deadline_ms(5_000)
        .with_dial_policy("mark-7");
    ctx.cancel.cancel();
    let err = mock
        .open_stream(&EndpointRef::new("1.2.3.4", 443), &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_OPEN_CANCELLED);
    assert!(!err.retryable, "取消不可重试");
    assert_eq!(*mock.attempts.lock().unwrap(), 0, "取消时不产生建立尝试");
    assert!(!ctx.is_expired(0));

    // 截止期已过：同样按不可重试失败拦下，出口不产生有效建立。
    // 适配器按「检查瞬间」供时钟（本例 now=0），故 deadline 取 0 表示已到。
    let expired = OpenContext::new("s-4", GenerationRef::new("gen-4").unwrap())
        .unwrap()
        .with_deadline_ms(0);
    assert!(expired.is_expired(0), "到点即到期");
    assert!(expired.check_openable(0).is_err());
    let err2 = mock
        .open_stream(&EndpointRef::new("1.2.3.4", 443), &expired)
        .await
        .unwrap_err();
    assert_eq!(err2.code, CODE_OPEN_CANCELLED);
    assert!(!err2.retryable, "到期不可重试");
}

/// ④ TCP 与 UDP 分侧：类型不可互换；数据报关联明确目标绑定与报文上限。
#[tokio::test]
async fn stream_and_datagram_are_distinct_lifecycles() {
    let ctx = OpenContext::new("s-5", GenerationRef::new("gen-5").unwrap()).unwrap();
    let fixed = TargetBinding::Fixed {
        target: EndpointRef::new("10.0.0.2", 8388),
    };

    let assoc = MockDatagram.open_association(&fixed, &ctx).await.unwrap();
    assert_eq!(assoc.max_datagram_len(), 1500, "报文上限显式");
    assert_eq!(assoc.idle_timeout_ms(), Some(5_000), "空闲期限显式");
    assert!(assoc.targets().allows(&EndpointRef::new("10.0.0.2", 8388)));
    assert!(
        !assoc.targets().allows(&EndpointRef::new("9.9.9.9", 53)),
        "固定目标不得旁落"
    );

    let multi = TargetBinding::Multi {
        allowed: vec![EndpointRef::new("10.0.0.3", 53)],
    };
    assert!(multi.allows(&EndpointRef::new("10.0.0.3", 53)));
    assert!(!multi.allows(&EndpointRef::new("10.0.0.9", 53)));
}
