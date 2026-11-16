//! P1-5 出站传输连接池（egress-connection-pool.md §2.2/§2.3/§5）。
//!
//! 策略/执行分离的**执行侧**：`TransportPool` 零协议知识（只认识
//! `TransportKey`，不见协议字节）；池形态 = 预建立 + 借出即消费（D-1，
//! 绑定即消费的结构约束 §1.2——无归还语义）；键 = 传输身份（D-2）。
//! 协议绑定侧（trojan/http/vless/direct 连接器）只消费 `acquire` API。

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::time::timeout;

use crate::fingerprint::TlsFingerprint;
use crate::tls::TlsConnectorFactory;

// 池借出对象 = rillane_core::IoStream（连接器侧 `Flow.io` 同型，M2 统一：
// 独立 trait 会在连接器接入处产生两种不互通的 trait 对象）
pub use rillane_core::{BoxedIo, IoStream};

// ---------------------------------------------------------------------------
// 时钟注入（循 rillane-core udp/clock.rs 先例）：idle 过期/驱逐次序的确定性单测
// ---------------------------------------------------------------------------

/// 池时钟：毫秒单调值（仅差值有意义）。
pub trait PoolClock: Send + Sync + fmt::Debug {
    fn now_millis(&self) -> u64;
}

/// 系统单调时钟（生产装配用）。
#[derive(Debug)]
pub struct SystemClock {
    base: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            base: std::time::Instant::now(),
        })
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            base: std::time::Instant::now(),
        }
    }
}

impl PoolClock for SystemClock {
    fn now_millis(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }
}

/// 可拨动的测试时钟（pub 供集成测试复用，§8.1 idle 超时/驱逐次序）。
#[derive(Debug, Default)]
pub struct MockPoolClock {
    now: AtomicU64,
}

impl MockPoolClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(0),
        })
    }

    pub fn advance_millis(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::Relaxed);
    }
}

impl PoolClock for MockPoolClock {
    fn now_millis(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// TransportKey（D-2：传输身份，非出站名）
// ---------------------------------------------------------------------------

/// alpn 规一化 = trim + 滤空 + 排序去重（顺序不影响传输身份；工厂同函数，
/// §2.2"键含 alpn"的口径钉）。
pub fn normalize_alpn(alpn: &[String]) -> Vec<String> {
    let mut v: Vec<String> = alpn
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 传输身份键 `(server, port, tls, sni, skip_cert_verify, alpn, fingerprint)`。
/// 不同出站名撞同一传输身份共享键空间——语义等价（同为到该端点的同形
/// 传输），无害且有益（§2.2）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportKey {
    pub server: String,
    pub port: u16,
    pub tls: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    /// 规一化后的 ALPN
    pub alpn: Vec<String>,
    pub fingerprint: TlsFingerprint,
}

impl TransportKey {
    /// 平文键（direct：目标即传输终点，键 = target）
    pub fn plain(server: impl Into<String>, port: u16) -> Self {
        Self {
            server: server.into(),
            port,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            alpn: Vec::new(),
            fingerprint: TlsFingerprint::None,
        }
    }

    /// TLS 键（sni 空串归 None；alpn 规一化；指纹为 hello 形态身份 D-4）
    pub fn tls(
        server: impl Into<String>,
        port: u16,
        sni: Option<&str>,
        skip_cert_verify: bool,
        alpn: &[String],
        fingerprint: TlsFingerprint,
    ) -> Self {
        Self {
            server: server.into(),
            port,
            tls: true,
            sni: sni
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            skip_cert_verify,
            alpn: normalize_alpn(alpn),
            fingerprint,
        }
    }
}

impl fmt::Display for TransportKey {
    /// 可读序列化（控制面/日志用，§2.2）：`tls:sni=x@example.com:443[alpn=a,b]` /
    /// `example.com:443`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.tls {
            write!(f, "tls:sni")?;
            if let Some(sni) = &self.sni {
                write!(f, "={sni}")?;
            }
            write!(f, "@{}:{}", self.server, self.port)?;
            if !self.alpn.is_empty() {
                write!(f, "[alpn={}]", self.alpn.join(","))?;
            }
            if self.fingerprint != TlsFingerprint::None {
                write!(f, "[fp={}]", self.fingerprint.as_str())?;
            }
            Ok(())
        } else {
            write!(f, "{}:{}", self.server, self.port)
        }
    }
}

// ---------------------------------------------------------------------------
// PoolPolicy（D-3 策略侧产物；M1 `to_pool_policy()` 转换填充）
// ---------------------------------------------------------------------------

/// 池策略（配置期定值，运行期只读；§2.3 策略侧不含任何运行期状态）。
#[derive(Debug, Clone)]
pub struct PoolPolicy {
    pub enabled: bool,
    pub tls_resumption: bool,
    pub max_idle_per_key: usize,
    pub max_idle_global: usize,
    pub low_watermark: usize,
    pub idle_timeout: Duration,
    pub dial_timeout: Duration,
    pub session_cache_size: usize,
    pub pre_dial_direct: bool,
}

// ---------------------------------------------------------------------------
// 指标（实例级——池是进程级单例 D-10，实例计数可聚合；§6.1 序列族 M4 渲染）
// ---------------------------------------------------------------------------

/// 池计数快照（控制面 `/egress/pool/stats` 与 `/metrics` 数据源，§6）。
#[derive(Debug, Clone, Default)]
pub struct PoolSnapshot {
    pub acquires_hit: u64,
    pub acquires_miss: u64,
    pub acquires_stale_redial: u64,
    pub dials_foreground_ok: u64,
    pub dials_foreground_err: u64,
    pub dials_warm_ok: u64,
    pub dials_warm_err: u64,
    pub dials_refill_ok: u64,
    pub dials_refill_err: u64,
    pub idle: u64,
    pub leased: u64,
    pub evicted_idle_timeout: u64,
    pub evicted_capacity: u64,
    pub evicted_shutdown: u64,
}

impl PoolSnapshot {
    /// reuse_ratio = hits/(hits+miss)，启动至今（§6.1；零分母 → 0.0）。
    pub fn reuse_ratio(&self) -> f64 {
        let total = self.acquires_hit + self.acquires_miss;
        if total == 0 {
            0.0
        } else {
            self.acquires_hit as f64 / total as f64
        }
    }
}

#[derive(Debug, Default)]
struct PoolMetrics {
    acquires_hit: AtomicU64,
    acquires_miss: AtomicU64,
    acquires_stale_redial: AtomicU64,
    dials_foreground_ok: AtomicU64,
    dials_foreground_err: AtomicU64,
    dials_warm_ok: AtomicU64,
    dials_warm_err: AtomicU64,
    dials_refill_ok: AtomicU64,
    dials_refill_err: AtomicU64,
    idle: AtomicU64,
    leased: AtomicU64,
    evicted_idle_timeout: AtomicU64,
    evicted_capacity: AtomicU64,
    evicted_shutdown: AtomicU64,
}

macro_rules! bump {
    ($f:expr, $v:expr) => {
        $f.fetch_add($v, Ordering::Relaxed)
    };
}

impl PoolMetrics {
    fn snapshot(&self) -> PoolSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        PoolSnapshot {
            acquires_hit: g(&self.acquires_hit),
            acquires_miss: g(&self.acquires_miss),
            acquires_stale_redial: g(&self.acquires_stale_redial),
            dials_foreground_ok: g(&self.dials_foreground_ok),
            dials_foreground_err: g(&self.dials_foreground_err),
            dials_warm_ok: g(&self.dials_warm_ok),
            dials_warm_err: g(&self.dials_warm_err),
            dials_refill_ok: g(&self.dials_refill_ok),
            dials_refill_err: g(&self.dials_refill_err),
            idle: g(&self.idle),
            leased: g(&self.leased),
            evicted_idle_timeout: g(&self.evicted_idle_timeout),
            evicted_capacity: g(&self.evicted_capacity),
            evicted_shutdown: g(&self.evicted_shutdown),
        }
    }
}

// ---------------------------------------------------------------------------
// 池核心
// ---------------------------------------------------------------------------

struct IdleConn {
    io: BoxedIo,
    born_millis: u64,
}

#[derive(Default)]
struct KeyState {
    /// 尾进尾出（LIFO 复用最热连接）；驱逐走最老先逐（首元素）
    idle: Vec<IdleConn>,
    /// 水位补充的在途拨号数（§5.2 不变式：≤ max_idle_per_key − idle）
    inflight_refill: usize,
    /// 后台补充退避（毫秒；1s 起指数 30s 封顶，成功复位，§5.1）
    backoff_millis: u64,
}

/// 每键 idle 快照（§6.2 keys 数组条目；Serialize 供控制面 DTO 直用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeySnapshot {
    pub key: String,
    pub idle: usize,
}

/// RAII 借出守卫：Drop 递减 leased gauge。连接消耗不回池（D-1），
/// guard 只管记账，无归还语义。
pub struct LeaseGuard {
    metrics: Arc<PoolMetrics>,
}

impl fmt::Debug for LeaseGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeaseGuard")
    }
}

impl LeaseGuard {
    fn new(metrics: &Arc<PoolMetrics>) -> Self {
        bump!(metrics.leased, 1);
        Self {
            metrics: metrics.clone(),
        }
    }

    /// 测试面：无池语境的独立租借记账（gun 客户端复用面单测用，RIL-130）
    #[cfg(test)]
    pub(crate) fn lease_for_tests() -> Self {
        Self::new(&Arc::new(PoolMetrics::default()))
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.metrics.leased.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialOrigin {
    Foreground,
    Warm,
    Refill,
}

/// 出站传输连接池（执行侧，§2.3）：拨号/缓存/借出/水位补充/回收/退避/计数。
///
/// 进程级单例跨热更新共享（D-10）；`Mutex` 守卫一律不跨 await（拨号在锁外）。
pub struct TransportPool {
    policy: PoolPolicy,
    keys: Mutex<HashMap<TransportKey, KeyState>>,
    metrics: Arc<PoolMetrics>,
    clock: Arc<dyn PoolClock>,
    tls_factory: Option<Arc<TlsConnectorFactory>>,
    sweeper_running: AtomicBool,
}

impl fmt::Debug for TransportPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportPool")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// 后台补充退避曲线：1s 起指数、30s 封顶（§5.1）。
fn next_backoff_millis(cur: u64) -> u64 {
    if cur == 0 {
        1_000
    } else {
        (cur.saturating_mul(2)).min(30_000)
    }
}

impl TransportPool {
    /// 生产装配（系统时钟）。
    pub fn new(policy: PoolPolicy, tls_factory: Option<Arc<TlsConnectorFactory>>) -> Arc<Self> {
        Self::with_clock(policy, tls_factory, SystemClock::new())
    }

    /// 测试注入时钟（§8.1 idle 超时/驱逐次序确定性）。
    pub fn with_clock(
        policy: PoolPolicy,
        tls_factory: Option<Arc<TlsConnectorFactory>>,
        clock: Arc<dyn PoolClock>,
    ) -> Arc<Self> {
        Arc::new(Self {
            policy,
            keys: Mutex::new(HashMap::new()),
            metrics: Arc::new(PoolMetrics::default()),
            clock,
            tls_factory,
            sweeper_running: AtomicBool::new(false),
        })
    }

    pub fn policy(&self) -> &PoolPolicy {
        &self.policy
    }

    pub fn snapshot(&self) -> PoolSnapshot {
        let mut snap = self.metrics.snapshot();
        snap.idle = self.total_idle();
        snap
    }

    fn total_idle(&self) -> u64 {
        self.keys
            .lock()
            .expect("pool keys lock")
            .values()
            .map(|st| st.idle.len() as u64)
            .sum()
    }

    /// 测试观察点：某键的后台退避当前值（§8.1 退避曲线断言用）。
    pub fn backoff_millis_of(&self, key: &TransportKey) -> u64 {
        self.keys
            .lock()
            .expect("pool keys lock")
            .get(key)
            .map(|st| st.backoff_millis)
            .unwrap_or(0)
    }

    /// 测试观察点：键数（孤儿键回收断言用）。
    pub fn live_key_count(&self) -> usize {
        self.keys.lock().expect("pool keys lock").len()
    }

    /// 每键 idle 快照（控制面 `/egress/pool/stats` keys 数组，§6.2）。
    /// leased 为全局 gauge 不分键记账（D-1 借出即消费，per-key leased 无
    /// 运营动作）——与 §6.2 示例形状的偏差记 M4 提交。
    pub fn key_snapshots(&self) -> Vec<KeySnapshot> {
        self.keys
            .lock()
            .expect("pool keys lock")
            .iter()
            .filter(|(_, st)| !st.idle.is_empty())
            .map(|(key, st)| KeySnapshot {
                key: key.to_string(),
                idle: st.idle.len(),
            })
            .collect()
    }

    fn expired(&self, born_millis: u64) -> bool {
        self.clock.now_millis().saturating_sub(born_millis)
            >= self.policy.idle_timeout.as_millis() as u64
    }

    /// 借出（§4.2）：hit 弹 idle（lazy 过期校验，过期 → close + 继续弹）/
    /// miss 前台拨号（失败 → Err = 今天拨号失败语义，E2）；弹出后触发水位
    /// 补充（§5.2 补充触发点）。
    pub async fn acquire(self: &Arc<Self>, key: &TransportKey) -> Result<(BoxedIo, LeaseGuard)> {
        loop {
            let popped = {
                let mut keys = self.keys.lock().expect("pool keys lock");
                keys.entry(key.clone()).or_default().idle.pop()
            };
            match popped {
                Some(conn) if !self.expired(conn.born_millis) => {
                    bump!(self.metrics.acquires_hit, 1);
                    self.maybe_refill(key);
                    return Ok((conn.io, LeaseGuard::new(&self.metrics)));
                }
                Some(conn) => {
                    // lazy 过期：close + evicted{idle_timeout}，继续弹下一个
                    drop(conn.io);
                    bump!(self.metrics.evicted_idle_timeout, 1);
                }
                None => break,
            }
        }

        // miss → 前台拨号（E2：失败直接 Err，池不吞错）
        bump!(self.metrics.acquires_miss, 1);
        let io = self.dial(key, DialOrigin::Foreground).await?;
        self.maybe_refill(key);
        Ok((io, LeaseGuard::new(&self.metrics)))
    }

    /// stale 一次性重拨（D-11/E3）：绕过 idle 直拨新连接；再失败 → Err
    /// （同今天拨号失败语义，不再三试）。
    pub async fn acquire_fresh(&self, key: &TransportKey) -> Result<(BoxedIo, LeaseGuard)> {
        bump!(self.metrics.acquires_stale_redial, 1);
        let io = self.dial(key, DialOrigin::Foreground).await?;
        Ok((io, LeaseGuard::new(&self.metrics)))
    }

    /// 借出即失效记账（D-11）：连接器在协议绑定首写/首读失败时调用；
    /// 计数落在 `acquire_fresh`（stale_redial），此处仅留观测日志。
    pub fn note_stale(&self, key: &TransportKey) {
        tracing::warn!(key = %key, "pool: 借出连接 stale（首写/首读失败），一次性重拨");
    }

    /// 借出并执行协议绑定（§4.2 时序：acquire → bind → relay 的前两步）。
    ///
    /// `bind` = 协议首写/首读（trojan 写请求头、http CONNECT 握手、vless-tcp
    /// 请求头往返、vless-ws 的 upgrade）。bind 失败 → [`Self::note_stale`] +
    /// [`Self::acquire_fresh`] 一次性重拨 + bind 重放（D-11，二次失败即 Err
    /// 不三试）。闭包 `FnMut`：同一 bind 在两条连接上各执行一次。
    pub async fn acquire_bound<F>(
        self: &Arc<Self>,
        key: &TransportKey,
        mut bind: F,
    ) -> Result<(BoxedIo, LeaseGuard)>
    where
        // 装箱 future + `&mut dyn IoStream`（非 `&mut BoxedIo`）：前者抹平
        // future 生命周期、后者固定 Box 内层 'static——async 闭包 HRTB 泛化
        // 在当前 rustc 下不过（"AsyncFnMut is not general enough"），此为
        // 既有稳定习语（tower service 同形）
        F: FnMut(
            &mut dyn IoStream,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>,
    {
        let (mut io, lease) = self.acquire(key).await?;
        if bind(io.as_mut()).await.is_err() {
            self.note_stale(key);
            drop((io, lease));
            let (mut fresh, lease) = self.acquire_fresh(key).await?;
            // 二次 bind 失败即 Err（新连接新握手仍败 = 真协议/服务端问题）
            bind(fresh.as_mut()).await?;
            return Ok((fresh, lease));
        }
        Ok((io, lease))
    }

    /// 单次拨号（含超时与 dials_total 记账；前台失败直接 Err，后台走退避）。
    async fn dial(&self, key: &TransportKey, origin: DialOrigin) -> Result<BoxedIo> {
        let res = timeout(self.policy.dial_timeout, self.dial_uncounted(key)).await;
        let outcome = match res {
            Ok(Ok(io)) => {
                bump!(
                    match origin {
                        DialOrigin::Foreground => &self.metrics.dials_foreground_ok,
                        DialOrigin::Warm => &self.metrics.dials_warm_ok,
                        DialOrigin::Refill => &self.metrics.dials_refill_ok,
                    },
                    1
                );
                Ok(io)
            }
            Ok(Err(e)) => Err(anyhow!("pool: 拨号 {key} 失败：{e:#}")),
            Err(_) => Err(anyhow!(
                "pool: 拨号 {key} 超时（>{}ms）",
                self.policy.dial_timeout.as_millis()
            )),
        };
        if outcome.is_err() {
            bump!(
                match origin {
                    DialOrigin::Foreground => &self.metrics.dials_foreground_err,
                    DialOrigin::Warm => &self.metrics.dials_warm_err,
                    DialOrigin::Refill => &self.metrics.dials_refill_err,
                },
                1
            );
        }
        outcome
    }

    /// 传输拨号（TCP [+TLS]；零协议字节写入——池与协议层的唯一契约 §2.2）。
    /// net_mark 统一拨号（SO_MARK 逃逸面，networking.md §2；缺省 0 零差异）。
    async fn dial_uncounted(&self, key: &TransportKey) -> Result<BoxedIo> {
        let tcp = rillane_core::net_mark::connect_tcp((key.server.clone(), key.port)).await?;
        let _ = tcp.set_nodelay(true);
        if !key.tls {
            return Ok(Box::new(tcp));
        }
        let factory = self.tls_factory.as_ref().ok_or_else(|| {
            anyhow!("pool: 键 {key} 为 TLS 但池未注入 TlsConnectorFactory（tls_resumption=false 的装配错配）")
        })?;
        let connector = factory.connector(key.skip_cert_verify, &key.alpn, key.fingerprint)?;
        let sni = key.sni.clone().unwrap_or_else(|| key.server.clone());
        let server_name = rustls::pki_types::ServerName::try_from(sni)?;
        let tls = connector.connect(server_name, tcp).await?;
        // HandshakeKind 观测（§2.4 公开 API 直读，驱动 rillane_tls_handshakes_total）
        factory.note_handshake(tls.get_ref().1.handshake_kind());
        Ok(Box::new(tls))
    }

    /// 水位补充触发（§5.2）：弹出后 idle(k) < low_watermark 且在途未到
    /// 每键上界 → 每次调用至多补一条（消费风暴下总量有界 = 总拨号 ≈ 流数）。
    fn maybe_refill(self: &Arc<Self>, key: &TransportKey) {
        if self.policy.low_watermark == 0 {
            return;
        }
        // inflight_refill 是防连接风暴的并发门：判断与登记须在同一锁下原子
        // 完成，否则并发 release 各自见满余量都补拨，击穿每键上限（此前只
        // 递减未递增，门失效）。spawn_fill 收尾处对称递减归还名额。
        let should_spawn = {
            let mut keys = self.keys.lock().expect("pool keys lock");
            let st = keys.entry(key.clone()).or_default();
            let headroom = self
                .policy
                .max_idle_per_key
                .saturating_sub(st.idle.len() + st.inflight_refill);
            let should = st.idle.len() < self.policy.low_watermark && headroom > 0;
            if should {
                st.inflight_refill += 1;
            }
            should
        };
        if should_spawn {
            self.spawn_fill(key.clone(), DialOrigin::Refill);
        }
    }

    /// 预热（D-7）：对已知 TLS 出站键各拨 count 条 warm；失败退避重试，
    /// 不阻塞启动（池是优化不是前置条件）。M3 装配尾调用。
    pub fn prewarm(self: &Arc<Self>, key: &TransportKey, count: usize) {
        for _ in 0..count {
            self.spawn_fill(key.clone(), DialOrigin::Warm);
        }
    }

    /// 后台填充任务：退避（仅后台走退避，成功复位）→ 拨号 → 入池
    /// （per-key/global 容量驱逐在此收口，E5；不再需要则关闭连接）。
    ///
    /// 重试有界（MAX_FILL_ATTEMPTS 次失败即放弃）：无界重试会以 Arc 钉死
    /// 池（E7 shutdown 永不触发）且死出站键常驻任务；放弃后下次 acquire
    /// 的水位检查会重触发新填充任务，语义等价于持续重试（间隔由前台流量
    /// 驱动）——池是优化不是前置条件（D-7）。
    fn spawn_fill(self: &Arc<Self>, key: TransportKey, origin: DialOrigin) {
        const MAX_FILL_ATTEMPTS: u32 = 5;
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            for attempt in 0..MAX_FILL_ATTEMPTS {
                // 退避等待（首次为 0 直拨；仅后台走退避，§5.1）
                let wait = {
                    let keys = pool.keys.lock().expect("pool keys lock");
                    keys.get(&key).map(|st| st.backoff_millis).unwrap_or(0)
                };
                if wait > 0 {
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }

                let filled = pool.dial(&key, origin).await;
                let mut keys = pool.keys.lock().expect("pool keys lock");
                let st = keys.entry(key.clone()).or_default();
                match filled {
                    Ok(io) => {
                        st.backoff_millis = 0;
                        // 键已满（他路填充抢先）→ 关闭本条
                        if st.idle.len() >= pool.policy.max_idle_per_key {
                            drop(io);
                            break;
                        }
                        pool.push_idle_locked(&mut keys, key.clone(), io);
                        break;
                    }
                    Err(_) => {
                        st.backoff_millis = next_backoff_millis(st.backoff_millis);
                        if attempt + 1 == MAX_FILL_ATTEMPTS {
                            // 耗尽即复位：退避只 pacing 本任务内的重试序列，
                            // 下个任务（由下次 acquire 水位检查重触发）从零起，
                            // 免得前台触发的补拨先睡上一任务的遗留退避值
                            st.backoff_millis = 0;
                            break;
                        }
                    }
                }
            }
            // 收尾：归还 inflight 名额 + 孤儿键回收
            let mut keys = pool.keys.lock().expect("pool keys lock");
            let remove = {
                let st = keys.entry(key.clone()).or_default();
                st.inflight_refill = st.inflight_refill.saturating_sub(1);
                st.idle.is_empty() && st.inflight_refill == 0
            };
            if remove {
                keys.remove(&key);
            }
        });
    }

    /// 入池 + 全局容量驱逐（E5：逐最老 idle 驱逐，不拒新——池是优化不是配额）。
    /// 调用方持有 keys 锁。
    fn push_idle_locked(
        &self,
        keys: &mut HashMap<TransportKey, KeyState>,
        key: TransportKey,
        io: BoxedIo,
    ) {
        {
            let st = keys.entry(key).or_default();
            st.idle.push(IdleConn {
                io,
                born_millis: self.clock.now_millis(),
            });
        }
        let max = self.policy.max_idle_global;
        while self.total_idle_locked(keys) > max {
            // 逐最老 idle（born 最小者；并列取先见者）
            let oldest = keys
                .iter()
                .filter_map(|(k, st)| st.idle.first().map(|c| (k.clone(), c.born_millis)))
                .min_by_key(|(_, born)| *born);
            let Some((victim_key, _)) = oldest else { break };
            let st = keys.get_mut(&victim_key).expect("victim key exists");
            let conn = st.idle.remove(0);
            drop(conn.io);
            bump!(self.metrics.evicted_capacity, 1);
        }
    }

    fn total_idle_locked(&self, keys: &HashMap<TransportKey, KeyState>) -> usize {
        keys.values().map(|st| st.idle.len()).sum()
    }

    /// 周期回收（E6 sweep 路径；lazy 路径在 acquire）：过期 idle 关闭 +
    /// 孤儿键（无 idle 无在途）条目移除。
    pub fn sweep_once(&self) {
        let now = self.clock.now_millis();
        let mut keys = self.keys.lock().expect("pool keys lock");
        let timeout_ms = self.policy.idle_timeout.as_millis() as u64;
        keys.retain(|_, st| {
            st.idle.retain(|conn| {
                let live = now.saturating_sub(conn.born_millis) < timeout_ms;
                if !live {
                    bump!(self.metrics.evicted_idle_timeout, 1);
                }
                live
            });
            !st.idle.is_empty() || st.inflight_refill > 0
        });
    }

    /// 周期 sweeper（间隔 = idle_timeout/2，下界 1s）；M3 装配 spawn。
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        let interval = (self.policy.idle_timeout / 2).max(Duration::from_secs(1));
        pool.sweeper_running.store(true, Ordering::Release);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while pool.sweeper_running.load(Ordering::Acquire) {
                tick.tick().await;
                pool.sweep_once();
            }
        })
    }

    /// 停止周期 sweeper（stop 装配调用；已在途单轮扫尾完成后退出）。
    pub fn stop_sweeper(&self) {
        self.sweeper_running.store(false, Ordering::Release);
    }

    pub fn idle_count_of(&self, key: &TransportKey) -> usize {
        self.keys
            .lock()
            .expect("pool keys lock")
            .get(key)
            .map(|st| st.idle.len())
            .unwrap_or(0)
    }
}

impl Drop for TransportPool {
    /// E7：池释放 → idle 全关 + evicted{shutdown}；借出中连接随流自然终结。
    fn drop(&mut self) {
        let mut keys = self.keys.lock().expect("pool keys lock");
        let total: usize = keys.values().map(|st| st.idle.len()).sum();
        if total > 0 {
            bump!(self.metrics.evicted_shutdown, total as u64);
            keys.clear();
        }
    }
}

#[cfg(test)]
mod tests;
