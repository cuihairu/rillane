//! 流媒体可用性与地区检测决策面（RIL-145 代码面首段交付）：结果分类、
//! TTL 缓存、作业配额/取消、自动选组迟滞——**OS-free**（时钟可注入、
//! 证据可注入），Linux 验证席确定性可测。
//!
//! 边界（诚实注记，与 RIL-059 具名缺口同链）：
//! - **出口拨号 HTTP 探测执行器未落地**——「选定出口」的检测须经代理
//!   节点出口发 HTTP 探测，而 EgressConnector 现状是纯流转发面（无
//!   「拨号并测」形态，RIL-059 证据已具名）；执行器归后续接线。本模块
//!   只钉决策契约：执行器侧完成 [`StreamingProbeService::complete`]
//!   即进分类与缓存；
//! - **真服务验证归机批次**（Netflix/Disney 等真端点、地区证据抽取规则
//!   按真响应钉）；本模块的分类判据（标记命中/阻断证据）由服务登记表
//!   显式声明，无一硬编码服务名；
//! - 控制面端点与 CLI 归执行器接线批（本模块快照面已备好展示字段）。
//!
//! 验收语义落点：
//! - **状态分开**：未检测/检测中/可用/受限/未知/失败/过期七态显式
//!   （[`StreamingStatus`]），不互相冒充；
//! - **HTTP 200 ≠ 播放**：200 且无播放判据标记且无阻断证据 =
//!   [`ProbeVerdict::Unknown`]——分类器结构上不允许「200 即可用」；
//! - **不收密码/不装证书/不承诺解锁**：服务登记表只有检测端点与判据
//!   标记，无任何凭据字段（构造上不可能携带账号证据）；
//! - **自动选组显式启用 + 迟滞**：[`AutoSwitchPolicy::enabled`] 缺省
//!   false（门关死）；切换需连续确认阈值，退出需连续失败阈值——且
//!   决策是建议面（只影响新流），不断言无逢迁移；
//! - **检测流量单计**：作业记录独立携带 probe 字节数，与业务计量
//!   分账（快照面分字段展示）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// 稳定原因码：服务未登记（探测范围闭合——登记表之外不可探测）
pub const CODE_STREAMING_SERVICE_UNKNOWN: &str = "streaming.service.unknown";
/// 稳定原因码：同（服务，出口）作业已在运行（重复提交显式拒绝）
pub const CODE_STREAMING_PROBE_RUNNING: &str = "streaming.probe.running";
/// 稳定原因码：并发作业配额已满
pub const CODE_STREAMING_QUOTA_EXCEEDED: &str = "streaming.limit.quota";
/// 稳定原因码：作业 ID 未知（完成/取消回报的显式缺席）
pub const CODE_STREAMING_JOB_UNKNOWN: &str = "streaming.job.unknown";

/// 单条流媒体探测结论（分类器产出；缓存以它为事实源）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// 可用：200 且播放判据标记命中且无阻断证据；region = 服务响应披露
    /// 的地区线索（None = 响应未披露——不猜）
    Available { region: Option<String> },
    /// 受限：有播放阻断证据（代理/VPN 判定、DRM、区域限制文案、403/451）
    Restricted { reason: String },
    /// 未知：证据不足（典型：200 但既无判据也无阻断——HTTP 200 不等于
    /// 播放）
    Unknown,
    /// 检测失败：网络/超时/5xx——非服务侧可用性证据，不得解读为受限
    Failed { code: String },
}

/// 执行器回报的原始证据（分类器唯一输入；字段全部来自真响应，无推断值）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// HTTP 状态码（None = 连接/超时层失败）
    pub http_status: Option<u16>,
    /// 响应中命中的播放判据标记（服务登记表 expect_markers 的子集）
    pub markers_hit: Vec<String>,
    /// 响应披露的地区线索（执行器按服务规则抽取——真服务规则归机批次）
    pub region_hint: Option<String>,
    /// 播放阻断证据（代理/VPN 判定、DRM、区域限制文案命中）
    pub block_indicators: Vec<String>,
}

/// 结果分类（验收「HTTP200 不等于播放」的结构性落点）
pub fn classify(evidence: &ProbeEvidence, expect_markers: &[String]) -> ProbeVerdict {
    let Some(status) = evidence.http_status else {
        return ProbeVerdict::Failed {
            code: "streaming.exec.no_response".into(),
        };
    };
    // 阻断证据优先于判据：200 + 判据命中但带阻断 = 受限（不可用冒充不得）
    if !evidence.block_indicators.is_empty() {
        return ProbeVerdict::Restricted {
            reason: evidence.block_indicators.join(","),
        };
    }
    if (403 == status || 451 == status)
        && !evidence
            .markers_hit
            .iter()
            .any(|m| expect_markers.contains(m))
    {
        return ProbeVerdict::Restricted {
            reason: format!("http_{status}"),
        };
    }
    if (500..600).contains(&status) {
        return ProbeVerdict::Failed {
            code: format!("http_{status}"),
        };
    }
    let has_playback_evidence = evidence
        .markers_hit
        .iter()
        .any(|m| expect_markers.contains(m));
    if 200 == status && has_playback_evidence {
        return ProbeVerdict::Available {
            region: evidence.region_hint.clone(),
        };
    }
    // 200 裸态（无判据无阻断）与其余状态码：证据不足即未知，不猜
    ProbeVerdict::Unknown
}

/// 缓存视角的七态（验收「未检测/未知/受限/失败/过期分开」）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingStatus {
    /// 未检测：无缓存条目且无在跑作业
    Untested,
    /// 检测中：作业在跑（此前结果如有则被作业覆盖展示——重探期间不冒充
    /// 旧值新鲜）
    Running,
    /// 有新鲜结论（TTL 内）
    Fresh(ProbeVerdict),
    /// 过期：有历史结论但 TTL 已过界（与失败分开——不是探测失败，是
    /// 证据老化）
    Expired,
}

/// 服务登记表条目（闭合登记——探测范围只来自操作员声明；**无凭据
/// 字段**：构造上不可能携带账号/证书证据）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingService {
    /// 服务名（登记键）
    pub name: String,
    /// 检测端点（选定出口的 HTTP GET 目标）
    pub check_urls: Vec<String>,
    /// 播放判据标记（响应中出现即视为播放证据）
    pub expect_markers: Vec<String>,
}

/// 缓存条目：结论 + 探测时刻 + 独立计量的探测字节（检测流量单计）
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    verdict: ProbeVerdict,
    probed_at_ms: u64,
    probe_bytes_up: u64,
    probe_bytes_down: u64,
}

/// 在跑作业记录（取消与快照观察面）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningJob {
    pub job_id: u64,
    pub service: String,
    pub exit: String,
}

/// 流媒体探测决策服务：闭合服务登记 + (服务, 出口) 缓存 + 作业配额
/// 与取消。同步决策面（真执行器归后续接线——完成后经
/// [`StreamingProbeService::complete`] 进分类与缓存）。
pub struct StreamingProbeService {
    services: BTreeMap<String, StreamingService>,
    results: BTreeMap<(String, String), CacheEntry>,
    running: BTreeMap<u64, RunningJob>,
    /// 并发作业配额（验收「取消配额」；探测字节预算归底层 ProbeService
    /// 字节面，本层只管作业数）
    max_active: usize,
    /// 结果 TTL
    ttl: Duration,
    next_job_id: AtomicU64,
    now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl StreamingProbeService {
    /// 空服务（时钟取真系统钟；测试用 [`with_now`](Self::with_now) 注入）
    pub fn new(services: Vec<StreamingService>, max_active: usize, ttl: Duration) -> Self {
        Self {
            services: services.into_iter().map(|s| (s.name.clone(), s)).collect(),
            results: BTreeMap::new(),
            running: BTreeMap::new(),
            max_active,
            ttl,
            next_job_id: AtomicU64::new(1),
            now_unix_ms: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            }),
        }
    }

    /// 注入时钟（测试用）
    pub fn with_now(mut self, now: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.now_unix_ms = now;
        self
    }

    /// 登记服务校验（提交入口的范围闭合面）
    pub fn service_registered(&self, name: &str) -> bool {
        self.services.contains_key(name)
    }

    /// 服务判据标记（分类用）
    pub fn expect_markers(&self, name: &str) -> Vec<String> {
        self.services
            .get(name)
            .map(|s| s.expect_markers.clone())
            .unwrap_or_default()
    }

    /// 提交探测作业：服务必须登记、同（服务,出口）不得重复在跑、并发
    /// 配额内。返回作业 ID。
    pub fn submit(&mut self, service: &str, exit: &str) -> Result<u64, String> {
        if !self.service_registered(service) {
            return Err(CODE_STREAMING_SERVICE_UNKNOWN.into());
        }
        if self
            .running
            .values()
            .any(|j| j.service == service && j.exit == exit)
        {
            return Err(CODE_STREAMING_PROBE_RUNNING.into());
        }
        if self.running.len() >= self.max_active {
            return Err(CODE_STREAMING_QUOTA_EXCEEDED.into());
        }
        let job_id = self.next_job_id.fetch_add(1, Ordering::SeqCst);
        self.running.insert(
            job_id,
            RunningJob {
                job_id,
                service: service.into(),
                exit: exit.into(),
            },
        );
        Ok(job_id)
    }

    /// 执行器完成回报：分类 + 入缓存 + 探测字节单计入账。未知作业
    /// 显式拒绝（不冒充完成）。
    pub fn complete(
        &mut self,
        job_id: u64,
        evidence: &ProbeEvidence,
        probe_bytes_up: u64,
        probe_bytes_down: u64,
    ) -> Result<ProbeVerdict, String> {
        let Some(job) = self.running.remove(&job_id) else {
            return Err(CODE_STREAMING_JOB_UNKNOWN.into());
        };
        let verdict = classify(evidence, &self.expect_markers(&job.service));
        self.results.insert(
            (job.service, job.exit),
            CacheEntry {
                verdict: verdict.clone(),
                probed_at_ms: (self.now_unix_ms)(),
                probe_bytes_up,
                probe_bytes_down,
            },
        );
        Ok(verdict)
    }

    /// 取消在跑作业（验收「取消」）：作业移除，既有缓存条目原样保留
    /// （取消不是失败——不伪造 Failed 结论）。未知 ID 返回 false。
    pub fn cancel(&mut self, job_id: u64) -> bool {
        self.running.remove(&job_id).is_some()
    }

    /// 查询（服务, 出口）现状：未检测/检测中/新鲜/过期四态显式。取消
    /// 后回到既有缓存状态（取消不产结论）。
    pub fn status(&self, service: &str, exit: &str) -> StreamingStatus {
        if self
            .running
            .values()
            .any(|j| j.service == service && j.exit == exit)
        {
            return StreamingStatus::Running;
        }
        let Some(entry) = self.results.get(&(service.to_string(), exit.to_string())) else {
            return StreamingStatus::Untested;
        };
        let age_ms = (self.now_unix_ms)().saturating_sub(entry.probed_at_ms);
        if age_ms > self.ttl.as_millis() as u64 {
            StreamingStatus::Expired
        } else {
            StreamingStatus::Fresh(entry.verdict.clone())
        }
    }

    /// 在跑作业快照（取消/观察面）
    pub fn running_jobs(&self) -> Vec<RunningJob> {
        self.running.values().cloned().collect()
    }

    /// 独立探测流量入账快照（验收「检测流量单计」）：(服务, 出口) →
    /// (上行字节, 下行字节)；与业务计量分账，绝不并入。
    pub fn probe_bytes(&self, service: &str, exit: &str) -> Option<(u64, u64)> {
        self.results
            .get(&(service.to_string(), exit.to_string()))
            .map(|e| (e.probe_bytes_up, e.probe_bytes_down))
    }
}

/// 自动选组迟滞决策（验收「自动选组需显式启用与迟滞」）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoSwitchPolicy {
    /// 显式启用门：false（缺省）时决策恒 Stay——自动选组默认关死
    pub enabled: bool,
    /// 切换迟滞：连续 N 次「可用」确认才建议切换
    pub confirmations_needed: u32,
    /// 退出迟滞：连续 M 次「不可用」（受限/未知/失败）才建议切走
    pub failures_needed: u32,
}

/// 迟滞建议（**建议面**——只影响新流的路由选择，不断言存量流无逢迁移）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchDecision {
    /// 维持现状（含：未启用/阈值未到）
    Stay,
    /// 建议切换到该出口（新流生效）
    SwitchTo(String),
}

/// 迟滞计数状态（逐出口独立维护）
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AutoSwitchState {
    consecutive_available: u32,
    consecutive_unavailable: u32,
}

impl AutoSwitchPolicy {
    /// 建议门（enabled=false 时连参数都不该被装配读取——恒 Stay）
    pub fn decide(&self, state: &mut AutoSwitchState, verdict: &ProbeVerdict) -> SwitchDecision {
        if !self.enabled {
            return SwitchDecision::Stay;
        }
        match verdict {
            ProbeVerdict::Available { .. } => {
                state.consecutive_available += 1;
                state.consecutive_unavailable = 0;
                if state.consecutive_available >= self.confirmations_needed {
                    SwitchDecision::SwitchTo("probe-selected".into())
                } else {
                    SwitchDecision::Stay
                }
            }
            ProbeVerdict::Restricted { .. }
            | ProbeVerdict::Unknown
            | ProbeVerdict::Failed { .. } => {
                state.consecutive_unavailable += 1;
                state.consecutive_available = 0;
                if state.consecutive_unavailable >= self.failures_needed {
                    // 切走的目标由路由面按优先序定——本层只表达「该走」
                    SwitchDecision::SwitchTo(String::new())
                } else {
                    SwitchDecision::Stay
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(name: &str, markers: &[&str]) -> StreamingService {
        StreamingService {
            name: name.into(),
            check_urls: vec![format!("https://www.example.com/{name}")],
            expect_markers: markers.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn fixed_now(ms: u64) -> (Arc<dyn Fn() -> u64 + Send + Sync>, Arc<AtomicU64>) {
        let clock = Arc::new(AtomicU64::new(ms));
        let c2 = clock.clone();
        (Arc::new(move || clock.load(Ordering::SeqCst)), c2)
    }

    fn make_service() -> StreamingProbeService {
        let mut s = StreamingProbeService::new(
            vec![
                svc("svc-a", &["playable", "player-ready"]),
                svc("svc-b", &["ok-region"]),
            ],
            2,
            Duration::from_secs(3600),
        );
        let (now, _c) = fixed_now(1_000_000);
        s = s.with_now(now);
        s
    }

    // ---- 分类器：HTTP 200 不等于播放 ----

    #[test]
    fn streaming_classifier_never_treats_bare_200_as_available() {
        let markers = vec!["playable".to_string()];
        // 200 + 判据命中 → 可用（地区来自披露线索，不猜）
        assert_eq!(
            classify(
                &ProbeEvidence {
                    http_status: Some(200),
                    markers_hit: vec!["playable".into()],
                    region_hint: Some("us-east".into()),
                    ..Default::default()
                },
                &markers
            ),
            ProbeVerdict::Available {
                region: Some("us-east".into())
            }
        );
        // 200 裸态（无判据无阻断）→ 未知——HTTP 200 结构上不等播放
        assert_eq!(
            classify(
                &ProbeEvidence {
                    http_status: Some(200),
                    ..Default::default()
                },
                &markers
            ),
            ProbeVerdict::Unknown
        );
        // 200 + 判据命中但带阻断证据 → 受限（阻断优先于判据，可用不冒充）
        assert!(matches!(
            classify(
                &ProbeEvidence {
                    http_status: Some(200),
                    markers_hit: vec!["playable".into()],
                    block_indicators: vec!["proxy_detected".into()],
                    ..Default::default()
                },
                &markers
            ),
            ProbeVerdict::Restricted { .. }
        ));
        // 403/451 无判据 → 受限（地区/法律阻断）；5xx → 失败；无响应 → 失败
        assert!(matches!(
            classify(
                &ProbeEvidence {
                    http_status: Some(403),
                    ..Default::default()
                },
                &markers
            ),
            ProbeVerdict::Restricted { .. }
        ));
        assert!(matches!(
            classify(
                &ProbeEvidence {
                    http_status: Some(503),
                    ..Default::default()
                },
                &markers
            ),
            ProbeVerdict::Failed { .. }
        ));
        assert!(matches!(
            classify(&ProbeEvidence::default(), &markers),
            ProbeVerdict::Failed { .. }
        ));
    }

    // ---- 作业生命周期：未检测/检测中/新鲜/过期/取消分开 ----

    #[test]
    fn streaming_status_lifecycle_states_are_distinct() {
        let mut s = make_service();
        // 未检测
        assert_eq!(s.status("svc-a", "exit-1"), StreamingStatus::Untested);
        // 未登记服务提交拒绝（范围闭合）
        assert_eq!(
            s.submit("no-such", "exit-1").unwrap_err(),
            CODE_STREAMING_SERVICE_UNKNOWN
        );
        // 提交 → 检测中
        let job = s.submit("svc-a", "exit-1").unwrap();
        assert_eq!(s.status("svc-a", "exit-1"), StreamingStatus::Running);
        // 重复提交同 (服务,出口) 拒绝
        assert_eq!(
            s.submit("svc-a", "exit-1").unwrap_err(),
            CODE_STREAMING_PROBE_RUNNING
        );
        // 完成 → 新鲜结论 + 探测字节单计入账
        let v = s
            .complete(
                job,
                &ProbeEvidence {
                    http_status: Some(200),
                    markers_hit: vec!["player-ready".into()],
                    region_hint: None,
                    ..Default::default()
                },
                512,
                4096,
            )
            .unwrap();
        assert_eq!(v, ProbeVerdict::Available { region: None });
        assert_eq!(
            s.status("svc-a", "exit-1"),
            StreamingStatus::Fresh(ProbeVerdict::Available { region: None })
        );
        assert_eq!(s.probe_bytes("svc-a", "exit-1"), Some((512, 4096)));
        // 未知作业回报显式拒绝
        assert_eq!(
            s.complete(job, &ProbeEvidence::default(), 0, 0)
                .unwrap_err(),
            CODE_STREAMING_JOB_UNKNOWN
        );
    }

    #[test]
    fn streaming_ttl_expiry_distinct_from_failure_and_cancel_keeps_old_result() {
        let mut s = make_service();
        let job = s.submit("svc-b", "exit-2").unwrap();
        s.complete(
            job,
            &ProbeEvidence {
                http_status: Some(200),
                markers_hit: vec!["ok-region".into()],
                region_hint: Some("jp".into()),
                ..Default::default()
            },
            100,
            800,
        )
        .unwrap();
        assert!(matches!(
            s.status("svc-b", "exit-2"),
            StreamingStatus::Fresh(_)
        ));

        // TTL 过界 → 过期（不是失败——证据老化单独成态）：换新注入钟
        // 并推到 TTL 之外
        let (now, c) = fixed_now(1_000_000);
        s = s.with_now(now);
        c.store(1_000_000 + 3_600_000 + 1, Ordering::SeqCst);
        assert_eq!(s.status("svc-b", "exit-2"), StreamingStatus::Expired);

        // 取消：作业消失、旧缓存原样（取消不是失败）
        let job2 = s.submit("svc-b", "exit-2").unwrap();
        assert!(s.cancel(job2));
        assert!(!s.cancel(job2), "重复取消显式 false");
        assert_eq!(s.status("svc-b", "exit-2"), StreamingStatus::Expired);
        assert!(s.running_jobs().is_empty());
    }

    #[test]
    fn streaming_quota_gate_and_per_exit_cache_independence() {
        let mut s = make_service(); // max_active = 2
        let j1 = s.submit("svc-a", "exit-1").unwrap();
        let j2 = s.submit("svc-a", "exit-2").unwrap();
        // 配额满
        assert_eq!(
            s.submit("svc-b", "exit-3").unwrap_err(),
            CODE_STREAMING_QUOTA_EXCEEDED
        );
        // 取消释放配额
        assert!(s.cancel(j2));
        let j3 = s.submit("svc-b", "exit-3").unwrap();
        assert_eq!(s.running_jobs().len(), 2);

        // 同服务双出口缓存独立（选定出口各自成键）
        s.complete(
            j1,
            &ProbeEvidence {
                http_status: Some(200),
                markers_hit: vec!["playable".into()],
                region_hint: Some("sg".into()),
                ..Default::default()
            },
            1,
            1,
        )
        .unwrap();
        s.complete(
            j3,
            &ProbeEvidence {
                http_status: Some(403),
                ..Default::default()
            },
            1,
            1,
        )
        .unwrap();
        assert_eq!(
            s.status("svc-a", "exit-1"),
            StreamingStatus::Fresh(ProbeVerdict::Available {
                region: Some("sg".into())
            })
        );
        assert!(matches!(
            s.status("svc-b", "exit-3"),
            StreamingStatus::Fresh(ProbeVerdict::Restricted { .. })
        ));
        // 出口键不串扰：svc-a 的 exit-2 仍无结论
        assert_eq!(s.status("svc-a", "exit-2"), StreamingStatus::Untested);
    }

    // ---- 自动选组：显式启用 + 迟滞 ----

    #[test]
    fn streaming_auto_switch_disabled_is_hard_off() {
        let mut policy = AutoSwitchPolicy {
            enabled: false,
            confirmations_needed: 1,
            failures_needed: 1,
        };
        let mut st = AutoSwitchState::default();
        // 门关死：无论结论多好都 Stay
        for _ in 0..5 {
            assert_eq!(
                policy.decide(&mut st, &ProbeVerdict::Available { region: None }),
                SwitchDecision::Stay
            );
        }
        policy.enabled = true;
        // 启用后阈值 1：一次可用即建议切换
        assert_eq!(
            policy.decide(&mut st, &ProbeVerdict::Available { region: None }),
            SwitchDecision::SwitchTo("probe-selected".into())
        );
    }

    #[test]
    fn streaming_auto_switch_hysteresis_counts_both_directions() {
        let policy = AutoSwitchPolicy {
            enabled: true,
            confirmations_needed: 3,
            failures_needed: 2,
        };
        let mut st = AutoSwitchState::default();
        // 可用 ×2 不够（迟滞）
        for _ in 0..2 {
            assert_eq!(
                policy.decide(&mut st, &ProbeVerdict::Available { region: None }),
                SwitchDecision::Stay
            );
        }
        // 第 3 次确认 → 建议切换（新流生效）
        assert_eq!(
            policy.decide(&mut st, &ProbeVerdict::Available { region: None }),
            SwitchDecision::SwitchTo("probe-selected".into())
        );
        // 一次失败重置连续确认；再两次失败（阈值 2）→ 建议切走
        assert_eq!(
            policy.decide(&mut st, &ProbeVerdict::Failed { code: "x".into() }),
            SwitchDecision::Stay
        );
        assert_eq!(
            policy.decide(
                &mut st,
                &ProbeVerdict::Restricted {
                    reason: "geo".into()
                }
            ),
            SwitchDecision::SwitchTo(String::new()),
            "连续失败达阈值 → 建议切走（目标由路由面定）"
        );
        // 未知也算不可用方向
        let mut st2 = AutoSwitchState::default();
        assert_eq!(
            policy.decide(&mut st2, &ProbeVerdict::Unknown),
            SwitchDecision::Stay
        );
    }
}
