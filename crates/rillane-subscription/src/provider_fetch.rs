//! provider 载荷下载生命周期（RIL-010）
//!
//! proxy-provider（RIL-009 声明）与 rule-provider（RIL-014 声明）共用同一
//! 下载闭环：**大小/并发上限、超时、取消、条件缓存、指数退避与失败状态**。
//! 本层只管「取回内容 + 发布闸」，载荷语义由调用方注入 parse（与
//! [`SourceSnapshotStore::refresh_with`] 同构）——断网/超限/坏内容在**任何**
//! 阶段失败都不发布坏版本：store 旧快照原样保留（RIL-008 语义），失败
//! 状态进入账本，退避间隔内不再发起网络请求。
//!
//! 凭证与重定向边界（验收口径）：
//! - URL 里的凭证（userinfo、凭证类查询参数）**只走传输面**；一切日志、
//!   tracing、错误文案一律经 [`redact_url`] 脱敏；
//! - 重定向至多 10 跳；跨主机时敏感头由 reqwest 内建剥离，本层不额外
//!   合并原查询串到新 URL（凭证不跨主机扩散）；
//! - 摘要（SHA-256，与快照 `content_hash` 同源）**只证明内容一致**——
//!   重试/缓存/发布间的内容身份；来源可信由传输（HTTPS）或
//!   [`ProviderFetcher::set_expected_digest`] 预置摘要比对另行约束，
//!   预置摘要不符按终态失败处理且不发布。

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Semaphore};
use tracing::{debug, warn};

use rillane_config::{SourceId, SourceObject};

use crate::fetcher::{redact_url, ConditionalGet, FetcherConfig, SubscriptionFetcher};
use crate::snapshots::{RefreshOutcome, SourceSnapshotStore};

/// provider 下载策略（RIL-010）：载荷比订阅小、更新频次由声明 interval
/// 驱动，故上限默认值比订阅面收紧。
#[derive(Debug, Clone)]
pub struct ProviderFetchPolicy {
    /// 单次载荷字节上限（Content-Length 快速拒绝 + 流式分块双闸）
    pub max_bytes: u64,
    /// 单次尝试超时
    pub timeout: Duration,
    /// 尝试内重试次数（瞬时错误；终态错误不重试）
    pub max_retries: u32,
    /// 尝试内退避初值（按 2^n 增长，封顶 `attempt_backoff_max`）
    pub attempt_backoff_initial: Duration,
    /// 尝试内退避封顶
    pub attempt_backoff_max: Duration,
    /// 全局并发上限（Semaphore：多 provider 并行刷新时的同时在线请求面）
    pub concurrency: usize,
    /// 刷新间退避初值：连续失败时下次允许发起的最早时刻按 2^n 后移
    pub refresh_backoff_initial: Duration,
    /// 刷新间退避封顶
    pub refresh_backoff_max: Duration,
}

impl Default for ProviderFetchPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024,
            timeout: Duration::from_secs(20),
            max_retries: 3,
            attempt_backoff_initial: Duration::from_secs(1),
            attempt_backoff_max: Duration::from_secs(30),
            concurrency: 4,
            refresh_backoff_initial: Duration::from_secs(30),
            refresh_backoff_max: Duration::from_secs(30 * 60),
        }
    }
}

/// 刷新失败后的退避延迟：初值 × 2^(连续失败-1)，封顶。
/// 纯函数便于核验（验收：退避可核验）。
pub fn refresh_backoff_delay(policy: &ProviderFetchPolicy, fail_count: u32) -> Duration {
    let shift = fail_count.saturating_sub(1).min(20);
    policy
        .refresh_backoff_initial
        .saturating_mul(1u32 << shift)
        .min(policy.refresh_backoff_max)
}

/// 取消信号（RIL-010 取消面）：`watch` 布尔旗——发送端置 true 即取消
/// 在途下载。发送端在未取消时 drop 视为「永不取消」（等待方挂起）。
#[derive(Debug, Clone)]
pub struct CancelToken(watch::Receiver<bool>);

impl CancelToken {
    /// 建立取消通道：`(发送端, 接收端)`
    pub fn channel() -> (watch::Sender<bool>, CancelToken) {
        let (tx, rx) = watch::channel(false);
        (tx, CancelToken(rx))
    }

    /// 是否已置取消旗（立即判定）
    pub fn is_canceled(&self) -> bool {
        *self.0.borrow()
    }
}

/// 等待取消旗翻转；发送端 drop 且未取消则永不返回。
async fn wait_canceled(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            // 发送端已 drop 且未取消：永不取消
            std::future::pending::<()>().await;
        }
    }
}

/// provider 刷新错误（RIL-010 失败状态面）。文案一律脱敏
/// （URL 凭证不外泄）；`Display` 即日志安全面。
#[derive(Debug, thiserror::Error)]
pub enum ProviderRefreshError {
    /// 失败退避门：距上次失败不足退避间隔，**未发起网络**
    #[error("provider {provider} 处于失败退避中，{retry_after_secs} 秒后可重试（上次失败: {last_error:?}）")]
    BackoffGate {
        provider: String,
        retry_after_secs: u64,
        last_error: Option<String>,
    },
    /// 取消：在途下载被取消旗终止，不产生任何发布
    #[error("provider {provider} 下载已取消")]
    Canceled { provider: String },
    /// 下载面失败（超限/状态错/重试耗尽/摘要不符）——旧快照保留
    #[error("provider {provider} 下载失败（旧快照保留）: {reason}")]
    Fetch { provider: String, reason: String },
    /// 载荷解析失败（坏内容）——旧快照保留
    #[error("provider {provider} 载荷解析失败（旧快照保留）: {reason}")]
    Parse { provider: String, reason: String },
}

/// 单来源失败状态账本（RIL-010 失败状态）：连续失败计数驱动刷新间
/// 退避；成功即清零。缓存面保存条件验证器与最近摘要。
#[derive(Debug, Default, Clone)]
struct ProviderSourceState {
    /// 连续失败次数（成功清零）
    fail_count: u32,
    /// 下次允许发起网络刷新的最早时刻（成功清除）
    next_allowed_at: Option<Instant>,
    /// 上次失败原因（已脱敏，供 BackoffGate 文案与诊断）
    last_error: Option<String>,
    /// 条件缓存验证器（ETag/Last-Modified；304 时复用缓存不重发）
    conditional: Option<ConditionalGet>,
    /// 最近成功载荷的 SHA-256（内容身份核对面）
    last_digest: Option<String>,
}

/// provider 载荷下载器（RIL-010）：策略 + 并发闸 + 每来源失败账本。
/// 与 [`SourceSnapshotStore`]（RIL-008，零网络）配合构成下载闭环。
pub struct ProviderFetcher {
    policy: ProviderFetchPolicy,
    fetcher: SubscriptionFetcher,
    /// 并发闸：同时在途载荷请求 ≤ policy.concurrency
    semaphore: Semaphore,
    /// 每来源失败账本（短临界区 std Mutex，绝不跨 await 持锁）
    states: Mutex<BTreeMap<SourceId, ProviderSourceState>>,
    /// 预置摘要（可选）：来源可信的带外约束——载荷摘要与之不符即终态
    /// 失败不发布。摘要一致只证明「拿到的是预期内容」，不证明来源可信
    /// （来源可信由传输/预置摘要策略约束，RIL-010 验收口径）。
    expected_digests: BTreeMap<SourceId, String>,
}

impl ProviderFetcher {
    /// 按策略构建（自带独立 SubscriptionFetcher：超时/上限/退避走策略面）
    pub fn new(policy: ProviderFetchPolicy) -> Self {
        let config = FetcherConfig {
            timeout: policy.timeout,
            max_retries: policy.max_retries,
            retry_interval: policy.attempt_backoff_initial,
            max_backoff: policy.attempt_backoff_max,
            max_bytes: policy.max_bytes,
            ..Default::default()
        };
        Self {
            semaphore: Semaphore::new(policy.concurrency),
            fetcher: SubscriptionFetcher::with_config(config),
            policy,
            states: Mutex::new(BTreeMap::new()),
            expected_digests: BTreeMap::new(),
        }
    }

    /// 预置摘要（可选来源可信策略）：此后该来源的载荷摘要与之不符即
    /// 终态失败（不发布、进失败账本）。传 `None` 解除。
    pub fn set_expected_digest(&mut self, source: &SourceId, digest: Option<String>) {
        match digest {
            Some(d) => {
                self.expected_digests.insert(source.clone(), d);
            }
            None => {
                self.expected_digests.remove(source);
            }
        }
    }

    /// 查询来源失败账本快照：(连续失败次数, 距可重试秒数(向上取整), 上次失败原因)
    pub fn failure_state(&self, source: &SourceId) -> (u32, Option<u64>, Option<String>) {
        let states = self.states.lock().unwrap();
        match states.get(source) {
            None => (0, None, None),
            Some(s) => {
                let wait = s
                    .next_allowed_at
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .map(|d| d.as_secs() + u64::from(d.subsec_millis() > 0));
                (s.fail_count, wait, s.last_error.clone())
            }
        }
    }

    /// 最近成功载荷摘要（内容身份核对面；None = 尚无成功载荷）
    pub fn last_digest(&self, source: &SourceId) -> Option<String> {
        self.states
            .lock()
            .unwrap()
            .get(source)
            .and_then(|s| s.last_digest.clone())
    }

    /// 下载一次载荷（不做解析/发布）：退避门 → 并发闸 →（可取消的）
    /// 条件获取 → 预置摘要比对 → 账本记账。304 直接返回 `not_modified`。
    pub async fn fetch_payload(
        &self,
        source: &SourceId,
        url: &str,
        cancel: &CancelToken,
    ) -> Result<crate::fetcher::FetchResult, ProviderRefreshError> {
        let provider = source.as_str().to_string();

        // 1) 失败退避门：退避间隔内不发起网络（验收「失败状态」面）
        {
            let states = self.states.lock().unwrap();
            if let Some(state) = states.get(source) {
                if let Some(until) = state.next_allowed_at {
                    if until > Instant::now() {
                        let wait = until.saturating_duration_since(Instant::now());
                        return Err(ProviderRefreshError::BackoffGate {
                            provider,
                            retry_after_secs: wait.as_secs() + u64::from(wait.subsec_millis() > 0),
                            last_error: state.last_error.clone(),
                        });
                    }
                }
            }
        }

        // 2) 并发闸（取消可打断排队）
        let mut cancel_rx = cancel.0.clone();
        let permit = tokio::select! {
            _ = wait_canceled(&mut cancel_rx) => None,
            permit = self.semaphore.acquire() => permit.ok(),
        };
        // None = 取消（semaphore 本层从不 close，ok() 失败只会来自取消路径）
        let Some(permit) = permit else {
            return Err(ProviderRefreshError::Canceled { provider });
        };

        // 3) 条件获取（可取消）：带上次验证器，304 = 内容未变
        let conditional = {
            let states = self.states.lock().unwrap();
            states.get(source).and_then(|s| s.conditional.clone())
        };
        let mut cancel_rx = cancel.0.clone();
        let fetch_fut = self.fetcher.fetch_conditional(url, conditional.as_ref());
        let fetched = tokio::select! {
            _ = wait_canceled(&mut cancel_rx) => {
                warn!(
                    target: "rillane::subscription::provider_fetch",
                    source = %source.as_str(),
                    url = %redact_url(url),
                    "载荷下载被取消"
                );
                None
            }
            fetched = fetch_fut => Some(fetched),
        };
        let result = match fetched {
            None => return Err(ProviderRefreshError::Canceled { provider }),
            // 失败进账本：刷新间退避从下次刷新起生效
            Some(Err(err)) => {
                let reason = format!("{err:#}");
                drop(permit);
                self.record_failure(source, &reason);
                return Err(ProviderRefreshError::Fetch { provider, reason });
            }
            Some(Ok(result)) => result,
        };

        // 304：内容未变，缓存仍有效——账本不动（不视作成功也不视作失败），
        // 调用方按 Unchanged 处理
        if result.not_modified {
            debug!(
                target: "rillane::subscription::provider_fetch",
                source = %source.as_str(),
                url = %redact_url(url),
                "载荷 304 未变，复用缓存"
            );
            return Ok(result);
        }

        // 4) 预置摘要比对（可选来源可信策略）
        if let Some(expected) = self.expected_digests.get(source) {
            if *expected != result.content_digest {
                let reason = format!(
                    "载荷摘要 {} 与预置摘要 {expected} 不符（内容身份不一致，拒绝发布）",
                    result.content_digest
                );
                drop(permit);
                self.record_failure(source, &reason);
                return Err(ProviderRefreshError::Fetch { provider, reason });
            }
        }

        // 成功：清零失败账本，更新缓存与摘要（不跨 await 持锁）
        {
            let mut states = self.states.lock().unwrap();
            let state = states.entry(source.clone()).or_default();
            state.fail_count = 0;
            state.next_allowed_at = None;
            state.last_error = None;
            state.conditional = Some(ConditionalGet {
                etag: result.etag.clone(),
                last_modified: result.last_modified.clone(),
            });
            state.last_digest = Some(result.content_digest.clone());
        }
        debug!(
            target: "rillane::subscription::provider_fetch",
            source = %source.as_str(),
            url = %redact_url(url),
            digest = %result.content_digest,
            "载荷下载成功"
        );
        drop(permit);
        Ok(result)
    }

    /// 下载闭环（RIL-010 验收主路径）：`fetch_payload` → 摘要 →
    /// [`SourceSnapshotStore::refresh_with`]。**任何阶段失败都不发布**：
    /// 超限/状态错/断网在下载面被拒，坏内容在解析面被拒——store 旧快照
    /// 原样保留（RIL-008 语义），失败进账本触发刷新间退避。
    pub async fn refresh_payload<E>(
        &self,
        source: &SourceId,
        url: &str,
        store: &mut SourceSnapshotStore,
        cancel: &CancelToken,
        parse: impl FnOnce(&str) -> Result<Vec<SourceObject>, E>,
    ) -> Result<RefreshOutcome, ProviderRefreshError>
    where
        E: std::fmt::Display,
    {
        let provider = source.as_str().to_string();
        let fetched = self.fetch_payload(source, url, cancel).await?;

        // 304：内容未变，发布层无新意（不重发解析——parse 对空体也不该跑）
        if fetched.not_modified {
            return Ok(RefreshOutcome::Unchanged);
        }

        match store.refresh_with(source.clone(), &fetched.content, parse) {
            Ok(outcome) => Ok(outcome),
            Err(refresh_err) => {
                // 坏内容进失败账本（坏载荷同样不该被反复拉取），并作废
                // 本次 fetch 更新的条件缓存——载荷从未发布，下次必须全量
                // GET，不得让 304 掩盖「从未成功发布」的事实
                self.record_failure(source, &refresh_err.reason);
                {
                    let mut states = self.states.lock().unwrap();
                    if let Some(state) = states.get_mut(source) {
                        state.conditional = None;
                    }
                }
                Err(ProviderRefreshError::Parse {
                    provider,
                    reason: refresh_err.reason,
                })
            }
        }
    }

    /// 失败记账：连续失败 +1，下次允许时刻按指数退避后移（封顶）。
    fn record_failure(&self, source: &SourceId, reason: &str) {
        let (fail_count, delay) = {
            let mut states = self.states.lock().unwrap();
            let state = states.entry(source.clone()).or_default();
            state.fail_count = state.fail_count.saturating_add(1);
            state.last_error = Some(reason.to_string());
            let delay = refresh_backoff_delay(&self.policy, state.fail_count);
            state.next_allowed_at = Some(Instant::now() + delay);
            (state.fail_count, delay)
        };
        warn!(
            target: "rillane::subscription::provider_fetch",
            source = %source.as_str(),
            fail_count = fail_count,
            backoff_secs = delay.as_secs(),
            "载荷刷新失败，进入退避"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_config::SourceSnapshot;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// 测试解析桩：内容 "BAD" 报错；否则按逗号拆成节点对象
    fn parse_stub(content: &str) -> Result<Vec<SourceObject>, String> {
        if content.trim() == "BAD" {
            return Err("模拟坏载荷".to_string());
        }
        let source = SourceId::new("p").unwrap();
        Ok(content
            .split(',')
            .filter(|s| !s.is_empty())
            .enumerate()
            .map(|(i, server)| SourceObject {
                id: rillane_config::ObjectId::new(
                    source.clone(),
                    rillane_config::derive_local_id(&["http", server, "80"]),
                ),
                kind: rillane_config::ObjectKind::Node,
                display_name: format!("节点-{i}"),
                location: rillane_config::SourceLocation::new(
                    source.clone(),
                    format!("proxies/{i}"),
                ),
            })
            .collect())
    }

    /// 最小 HTTP/1.1 假服务：固定响应（响应前 hold）；返回监听地址。
    async fn serve(response: String, hold: Duration) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let response = response.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut buf = [0u8; 2048];
                    let mut seen = Vec::new();
                    loop {
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&buf[..n]);
                        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    tokio::time::sleep(hold).await;
                    let _ = s.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}/payload")
    }

    fn tiny_policy() -> ProviderFetchPolicy {
        ProviderFetchPolicy {
            max_bytes: 10 * 1024 * 1024,
            timeout: Duration::from_secs(5),
            max_retries: 1,
            attempt_backoff_initial: Duration::from_millis(1),
            attempt_backoff_max: Duration::from_millis(10),
            concurrency: 2,
            refresh_backoff_initial: Duration::from_millis(50),
            refresh_backoff_max: Duration::from_millis(200),
        }
    }

    /// 验收「坏内容不发布坏版本」：载荷解析失败 → Parse 错误，旧快照
    /// 原样保留；随后命中刷新间退避门（未发起网络）。
    #[tokio::test]
    async fn bad_content_keeps_old_snapshot_and_enters_backoff() {
        let body = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBAD";
        let url = serve(body.to_string(), Duration::from_millis(0)).await;

        let pf = ProviderFetcher::new(tiny_policy());
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(SourceId::new("p").unwrap(), "1.1.1.1", parse_stub)
            .unwrap();
        let before = store
            .snapshot(&SourceId::new("p").unwrap())
            .unwrap()
            .clone();

        let (_, cancel) = CancelToken::channel();
        let err = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderRefreshError::Parse { .. }), "{err}");

        let after = store.snapshot(&SourceId::new("p").unwrap()).unwrap();
        assert_eq!(after.content_hash, before.content_hash, "坏内容不得发布");
        assert_eq!(after.objects.len(), 1, "旧快照对象原样保留");

        // 失败进账本：退避间隔内的下一次刷新被门拦下（未发起网络）
        let (fail_count, wait, last_err) = pf.failure_state(&SourceId::new("p").unwrap());
        assert_eq!(fail_count, 1);
        assert!(wait.is_some(), "应有退避余量");
        assert!(last_err.unwrap().contains("坏载荷"));
        let err2 = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err2, ProviderRefreshError::BackoffGate { .. }),
            "退避期内不得再发起网络: {err2}"
        );

        // 退避过期后可再次发起（策略里退避仅 50ms）；账本余量归零
        tokio::time::sleep(Duration::from_millis(80)).await;
        let (_, wait2, _) = pf.failure_state(&SourceId::new("p").unwrap());
        assert!(
            matches!(wait2, None | Some(0)),
            "退避过期后应放行: {wait2:?}"
        );
    }

    /// 验收「超限不发布坏版本」：载荷超过策略上限 → 下载面终态拒绝，
    /// 旧快照保留。
    #[tokio::test]
    async fn oversize_rejected_and_snapshot_kept() {
        let big = "x".repeat(64);
        let body = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{big}",
            big.len()
        );
        let url = serve(body, Duration::from_millis(0)).await;

        let policy = ProviderFetchPolicy {
            max_bytes: 32,
            ..tiny_policy()
        };
        let pf = ProviderFetcher::new(policy);
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(SourceId::new("p").unwrap(), "1.1.1.1", parse_stub)
            .unwrap();
        let before = store
            .snapshot(&SourceId::new("p").unwrap())
            .unwrap()
            .content_hash
            .clone();

        let (_, cancel) = CancelToken::channel();
        let err = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderRefreshError::Fetch { .. }), "{err}");
        assert!(
            format!("{err}").contains("订阅内容过大"),
            "应为尺寸上限错误: {err}"
        );

        let after = store
            .snapshot(&SourceId::new("p").unwrap())
            .unwrap()
            .content_hash
            .clone();
        assert_eq!(after, before, "超限不得发布");
    }

    /// 验收「断网不发布坏版本」：连接拒绝（重试耗尽）→ Fetch 错误，
    /// 旧快照保留；退避门随后拦截下一次网络尝试。
    #[tokio::test]
    async fn network_down_never_publishes() {
        // 先占住一个端口再释放 → 该端口连接被拒
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let pf = ProviderFetcher::new(tiny_policy());
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(SourceId::new("p").unwrap(), "1.1.1.1", parse_stub)
            .unwrap();
        let before = store
            .snapshot(&SourceId::new("p").unwrap())
            .unwrap()
            .content_hash
            .clone();

        let (_, cancel) = CancelToken::channel();
        let err = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &format!("http://{addr}/payload"),
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderRefreshError::Fetch { .. }), "{err}");

        let after = store
            .snapshot(&SourceId::new("p").unwrap())
            .unwrap()
            .content_hash
            .clone();
        assert_eq!(after, before, "断网不得发布");
        let (_, wait, _) = pf.failure_state(&SourceId::new("p").unwrap());
        assert!(wait.is_some(), "断网失败应进退避");
    }

    /// 验收「条件缓存」：同来源第二次刷新携带 If-None-Match，服务端 304
    /// → Unchanged，且**解析器不再被调用**（复用缓存不重发）。
    #[tokio::test]
    async fn conditional_get_304_skips_parse() {
        use std::sync::Mutex as SyncMutex;
        let seen_if_none_match: Arc<SyncMutex<Vec<String>>> = Arc::new(SyncMutex::new(Vec::new()));

        // 首响 200 + ETag v1；带 If-None-Match 的请求回 304
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = seen_if_none_match.clone();
        tokio::spawn(async move {
            let body200 =
                "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Type: text/yaml\r\nContent-Length: 7\r\nConnection: close\r\n\r\na.com,b.com";
            let body304 = "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n";
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let seen = seen.clone();
                let body200 = body200.to_string();
                let body304 = body304.to_string();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut buf = [0u8; 4096];
                    let mut seen_bytes = Vec::new();
                    loop {
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        seen_bytes.extend_from_slice(&buf[..n]);
                        if seen_bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&seen_bytes);
                    if let Some(inm) = text
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("if-none-match:"))
                    {
                        seen.lock()
                            .unwrap()
                            .push(inm.split(':').nth(1).unwrap_or("").trim().to_string());
                        let _ = s.write_all(body304.as_bytes()).await;
                    } else {
                        let _ = s.write_all(body200.as_bytes()).await;
                    }
                });
            }
        });
        let url = format!("http://{addr}/payload");

        let pf = ProviderFetcher::new(tiny_policy());
        let mut store = SourceSnapshotStore::new(1);

        let (_, cancel) = CancelToken::channel();
        let out = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, RefreshOutcome::Published { .. }),
            "首刷必须发布"
        );

        // 二刷：验证器已入账本，服务端 304 → Unchanged
        let parse_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_parse = parse_calls.clone();
        let out2 = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                move |c| {
                    calls_for_parse.fetch_add(1, Ordering::SeqCst);
                    parse_stub(c)
                },
            )
            .await
            .unwrap();
        assert_eq!(out2, RefreshOutcome::Unchanged, "304 应按无新意处理");
        assert_eq!(
            parse_calls.load(Ordering::SeqCst),
            0,
            "304 不得触发解析（复用缓存）"
        );
        let seen = seen_if_none_match.lock().unwrap();
        assert_eq!(
            seen.last().map(String::as_str),
            Some("\"v1\""),
            "应携带 If-None-Match 验证器"
        );
    }

    /// 验收「取消」：在途下载被取消旗终止（快），不产生发布。
    #[tokio::test]
    async fn cancellation_stops_inflight_download() {
        // 响应前 hold 5s：取消必须在 hold 期间命中
        let body = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBAD";
        let url = serve(body.to_string(), Duration::from_secs(5)).await;

        let pf = Arc::new(ProviderFetcher::new(tiny_policy()));
        let (cancel_tx, cancel) = CancelToken::channel();
        let src = SourceId::new("p").unwrap();

        // 直接走 fetch_payload（不做发布），验证取消面
        let pf2 = pf.clone();
        let src2 = src.clone();
        let handle = tokio::spawn(async move { pf2.fetch_payload(&src2, &url, &cancel).await });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        cancel_tx.send(true).unwrap();
        let res = handle.await.unwrap();
        assert!(
            matches!(res, Err(ProviderRefreshError::Canceled { .. })),
            "取消后应为 Canceled: {res:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "取消应即时生效，实际 {:?}",
            started.elapsed()
        );
        assert!(pf.last_digest(&src).is_none(), "取消不得记下成功摘要");
    }

    /// 验收「并发上限」：8 个并行下载，策略 concurrency=2 → 服务端观测
    /// 同时在线请求 ≤ 2。
    #[tokio::test]
    async fn concurrency_cap_respected() {
        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cur, mx) = (current.clone(), max_seen.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let cur = cur.clone();
                let mx = mx.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                    mx.fetch_max(now, Ordering::SeqCst);
                    let mut buf = [0u8; 2048];
                    let mut seen = Vec::new();
                    loop {
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&buf[..n]);
                        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nn1,n2",
                        )
                        .await;
                    cur.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        let url = format!("http://{addr}/payload");

        let pf = Arc::new(ProviderFetcher::new(tiny_policy()));
        let (_, cancel) = CancelToken::channel();
        let src = SourceId::new("p").unwrap();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let pf = pf.clone();
            let url = url.clone();
            let src = src.clone();
            let cancel = cancel.clone();
            handles.push(tokio::spawn(async move {
                pf.fetch_payload(&src, &url, &cancel).await
            }));
        }
        for h in handles {
            h.await.unwrap().expect("并发下载应成功");
        }
        let max = max_seen.load(Ordering::SeqCst);
        assert!(max <= 2, "并发上限 2 不得被突破，服务端观测峰值 {max}");
    }

    /// 验收「预置摘要」：载荷摘要与预置不符 → 终态失败不发布；一致 →
    /// 正常发布且账本记下摘要。
    #[tokio::test]
    async fn preset_digest_mismatch_rejects_publish() {
        let body = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\na.com,b.com";
        let url = serve(body.to_string(), Duration::from_millis(0)).await;

        let mut pf = ProviderFetcher::new(tiny_policy());
        let mut store = SourceSnapshotStore::new(1);
        let src = SourceId::new("p").unwrap();

        // 预置一个「别的内容」的摘要
        pf.set_expected_digest(&src, Some(SourceSnapshot::hash_content(b"other")));

        let (_, cancel) = CancelToken::channel();
        let err = pf
            .refresh_payload(&src, &url, &mut store, &cancel, parse_stub)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderRefreshError::Fetch { .. }), "{err}");
        assert!(
            format!("{err}").contains("预置摘要"),
            "应为预置摘要不符: {err}"
        );
        assert!(store.snapshot(&src).is_none(), "摘要不符不得发布");

        // 解除预置后同内容可发布（先等失败退避过期），账本记录摘要
        pf.set_expected_digest(&src, None);
        tokio::time::sleep(Duration::from_millis(80)).await;
        let out = pf
            .refresh_payload(&src, &url, &mut store, &cancel, parse_stub)
            .await
            .unwrap();
        assert!(matches!(out, RefreshOutcome::Published { .. }));
        // Content-Length: 7 → 实际取到的体是 "a.com,b"
        let expect = SourceSnapshot::hash_content(b"a.com,b");
        assert_eq!(pf.last_digest(&src), Some(expect));
    }

    /// 验收「退避可核验」：退避延迟按 2^n 增长且封顶。
    #[test]
    fn backoff_delay_grows_and_caps() {
        let policy = ProviderFetchPolicy {
            refresh_backoff_initial: Duration::from_secs(1),
            refresh_backoff_max: Duration::from_secs(60),
            ..ProviderFetchPolicy::default()
        };
        assert_eq!(refresh_backoff_delay(&policy, 1), Duration::from_secs(1));
        assert_eq!(refresh_backoff_delay(&policy, 2), Duration::from_secs(2));
        assert_eq!(refresh_backoff_delay(&policy, 3), Duration::from_secs(4));
        assert_eq!(refresh_backoff_delay(&policy, 4), Duration::from_secs(8));
        assert_eq!(
            refresh_backoff_delay(&policy, 7),
            Duration::from_secs(60),
            "封顶"
        );
        assert_eq!(
            refresh_backoff_delay(&policy, 100),
            Duration::from_secs(60),
            "封顶"
        );
    }

    /// 凭证不泄漏（验收）：失败文案（含退避门）只含脱敏 URL。
    #[tokio::test]
    async fn failure_messages_do_not_leak_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let pf = ProviderFetcher::new(tiny_policy());
        let mut store = SourceSnapshotStore::new(1);
        let (_, cancel) = CancelToken::channel();
        let url = format!("http://user:hunter2@{addr}/payload?token=abc123");
        let err = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap_err();
        let text = format!("{err}");
        assert!(!text.contains("hunter2"), "口令不得入错误文案: {text}");
        assert!(!text.contains("abc123"), "token 不得入错误文案: {text}");

        // 退避门文案同样脱敏
        let gate = pf
            .refresh_payload(
                &SourceId::new("p").unwrap(),
                &url,
                &mut store,
                &cancel,
                parse_stub,
            )
            .await
            .unwrap_err();
        let gate_text = format!("{gate}");
        assert!(
            matches!(gate, ProviderRefreshError::BackoffGate { .. }),
            "第二次应被退避门拦截: {gate_text}"
        );
        assert!(
            !gate_text.contains("hunter2"),
            "口令不得入退避文案: {gate_text}"
        );
    }
}
