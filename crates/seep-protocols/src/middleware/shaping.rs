//! shaping 策略引擎与中间件（obfuscation-timing-shaping.md §2-D2/D3/D4）
//!
//! `ShapingMiddleware` 写 `seep.obfs.shaping` 注解后把 `flow.io` 包装成
//! `PacedIo`——每次 `AsyncWrite` 之前 sleep 至「起点 + k×interval +
//! jitter(k)」网格点，burst 流形状被归一拉平。读方向不包装（D2 读侧不归一）。

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use seep_core::{Flow, FlowId, FlowMiddleware, ShapingSpec};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{ANN_ROUTE_EGRESS, ANN_ROUTE_KIND};

/// 注解键：`seep.obfs.shaping` = interval_ms 网格间隔（观测面）。
pub const ANN_OBFS_SHAPING: &str = "seep.obfs.shaping";

/// shaping 策略选择器（同 PadSelector/TimingSelector 形态）。
pub type ShapingSelector = Box<dyn Fn(&str, Option<&str>) -> bool + Send + Sync>;

/// shaping 策略中间件。
pub struct ShapingMiddleware {
    spec: ShapingSpec,
    selector: ShapingSelector,
}

impl ShapingMiddleware {
    pub fn new(spec: ShapingSpec, selector: ShapingSelector) -> Self {
        Self { spec, selector }
    }
}

/// 网格点决策（§7-4 纯函数）：第 k 次 write 的目标 offset =
/// k×interval_ms + jitter(k)（jitter ∈ [0, jitter_ms]，确定性 hash 掷点，
/// 上限截断 max_delay_ms 兜底每跳最大等待——注意：本函数返回**目标 offset**，
/// 调用侧 PacedIo 换算为 sleep 时长后再截断）。
pub fn decide_shaping_offset(spec: &ShapingSpec, flow_id: &FlowId, k: u64) -> u64 {
    let jitter = if spec.jitter_ms == 0 {
        0
    } else {
        // jitter_ms=u64::MAX 时 +1 裹 0 → % 0 panic（validate 允许
        // jitter_ms=interval_ms=u64::MAX）；checked_add 满值截断为
        // % u64::MAX，域 [0, u64::MAX-1]，语义不变且无 panic。
        range_hash(flow_id, k) % spec.jitter_ms.checked_add(1).unwrap_or(u64::MAX)
    };
    // k×interval + jitter 可能溢（interval/jitter 允许 u64::MAX）；饱和加再
    // 截断，域有界且不 panic。
    (k.saturating_mul(spec.interval_ms))
        .saturating_add(jitter)
        .min(u64::MAX / 2)
}

/// 确定性随机源（同 padding §2.2 同族 FNV-1a + splitmix64）。
fn range_hash(flow_id: &FlowId, seq: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in flow_id.as_uuid().as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= seq;
    let mut z = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// 写侧网格归一包装：基座 Instant + seq 计数；每次 poll_write 前 sleep。
/// 实现要点——sleep 期间通过 `pending: Option<JoinHandle<()>>` 挂起
/// （返回 Poll::Pending，cx waker 由 tokio sleep 唤醒），不阻塞运行时线程。
pub struct PacedIo<T> {
    inner: T,
    spec: ShapingSpec,
    flow_id: FlowId,
    seq: u64,
    start: Instant,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> PacedIo<T> {
    pub fn new(inner: T, spec: ShapingSpec, flow_id: FlowId) -> Self {
        Self {
            inner,
            spec,
            flow_id,
            seq: 0,
            start: Instant::now(),
            sleep: None,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PacedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PacedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 首次进入（或上次 sleep 完成后）：按网格决定本次是否 sleep
        if self.sleep.is_none() {
            let target = decide_shaping_offset(&self.spec, &self.flow_id, self.seq);
            let elapsed = self.start.elapsed().as_millis() as u64;
            if target > elapsed {
                // 单次等待截断硬闸门（D4）：单写最多阻塞 max_delay_ms
                let wait = (target - elapsed).min(self.spec.max_delay_ms);
                if wait > 0 {
                    self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(wait))));
                }
            }
        }
        if let Some(fut) = &mut self.sleep {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => self.sleep = None,
            }
        }
        let n = match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        self.seq += 1;
        Poll::Ready(n)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl FlowMiddleware for ShapingMiddleware {
    fn name(&self) -> &'static str {
        "shaping"
    }

    async fn handle(&self, mut flow: Flow) -> Result<Flow> {
        let selected = {
            let ann = &flow.metadata.annotations;
            let kind = ann.get(ANN_ROUTE_KIND).map(String::as_str).unwrap_or("");
            let egress = ann.get(ANN_ROUTE_EGRESS).map(String::as_str);
            (self.selector)(kind, egress)
        };
        if selected {
            flow.metadata.annotations.insert(
                ANN_OBFS_SHAPING.to_string(),
                self.spec.interval_ms.to_string(),
            );
            // wrap io：Blanket IoStream 覆盖——PacedIo 满足 AsyncRead+Write+Unpin+Send+Sync
            let inner = std::mem::replace(&mut flow.io, Box::new(tokio::io::duplex(1).0));
            flow.io = Box::new(PacedIo::new(inner, self.spec.clone(), flow.id));
        }
        Ok(flow)
    }
}

#[cfg(test)]
mod tests {
    use seep_core::{Flow, FlowId, FlowTarget, ShapingMode, TargetProto};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn spec() -> ShapingSpec {
        ShapingSpec {
            mode: ShapingMode::Interval,
            interval_ms: 20,
            jitter_ms: 0,
            max_delay_ms: 60,
        }
    }

    fn flow() -> Flow {
        Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: "example.com".into(),
                port: 443,
                proto: TargetProto::Tcp,
            },
            io: Box::new(tokio::io::duplex(1024).0),
            metadata: Default::default(),
        }
    }

    /// 构造 PacedIo + 后台 reader（防缓冲阻塞）。
    fn paced_pair(
        spec: ShapingSpec,
    ) -> (
        PacedIo<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let (a, mut b) = tokio::io::duplex(1024);
        let _reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                match b.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        (PacedIo::new(a, spec, FlowId::new()), _reader)
    }

    /// §7-4：grid 决策 = k×interval（jitter=0 时）+ jitter ∈ [0, jitter_ms]；
    /// 同 flow_id 确定。
    #[test]
    fn shaping_offset_grid_and_deterministic() {
        let id = FlowId::new();
        let s = spec();
        assert_eq!(decide_shaping_offset(&s, &id, 0), 0);
        assert_eq!(decide_shaping_offset(&s, &id, 3), 60);

        let with_jitter = ShapingSpec {
            jitter_ms: 5,
            ..spec()
        };
        for k in 0..8 {
            let a = decide_shaping_offset(&with_jitter, &id, k);
            let b = decide_shaping_offset(&with_jitter, &id, k);
            assert_eq!(a, b, "同 flow_id 同 k 恒同值");
            assert!(a >= k * 20, "offset ≥ k×interval：k={k} a={a}");
            assert!(a <= k * 20 + 5, "offset ≤ k×interval+jitter：k={k} a={a}");
        }
    }

    /// jitter_ms=interval_ms=u64::MAX 时旧代码 `jitter_ms + 1` 裹 0 →
    /// `% 0` panic（config validate 允许该组合，无上界校验）；修复后
    /// `checked_add(1).unwrap_or(u64::MAX)` 域 [0, u64::MAX-1] 无 panic。
    #[test]
    fn shaping_offset_max_jitter_does_not_panic() {
        let id = FlowId::new();
        let s = ShapingSpec {
            interval_ms: u64::MAX,
            jitter_ms: u64::MAX,
            max_delay_ms: u64::MAX,
            ..spec()
        };
        for k in [0u64, 1, 1000, u64::MAX / 2] {
            let off = decide_shaping_offset(&s, &id, k);
            // k*interval 可能裹（saturating_mul），但不得 panic；域有界。
            assert!(off <= u64::MAX / 2, "offset 应截断，k={k} got {off}");
        }
    }

    /// §7-4：PacedIo 真度量——burst 3 片 write，网格间隔拉开总耗时，
    /// 截断闸门给出上界。
    #[tokio::test]
    async fn paced_io_spaces_writes_to_grid() {
        let (mut paced, _reader) = paced_pair(spec());
        let t0 = Instant::now();
        paced.write_all(b"a").await.unwrap();
        paced.write_all(b"b").await.unwrap();
        paced.write_all(b"c").await.unwrap();
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(15),
            "两次网格间隔（第 2/3 片各等 ~interval）应拉开耗时：{elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(500),
            "闸门内收尾：{elapsed:?}"
        );
    }

    /// §7-4：middleware handle 写注解 + io 被 PacedIo 包装（后续 write 延迟）。
    #[tokio::test]
    async fn middleware_wraps_io_and_annotates() {
        let mw = ShapingMiddleware::new(spec(), Box::new(|_, _| true));
        // 包装前是裸 duplex 端；handle 后 flow.io 应为 PacedIo
        let (a, mut b) = tokio::io::duplex(1024);
        let _reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                match b.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let mut f = flow();
        f.io = Box::new(a);
        let f = mw.handle(f).await.unwrap();
        assert_eq!(
            f.metadata
                .annotations
                .get(ANN_OBFS_SHAPING)
                .map(String::as_str),
            Some("20")
        );
        let mut io = f.io;
        let t0 = Instant::now();
        io.write_all(b"x").await.unwrap();
        io.write_all(b"y").await.unwrap();
        let el = t0.elapsed();
        assert!(
            el >= Duration::from_millis(15),
            "第二片应被网格延后：{el:?}"
        );
    }
}
