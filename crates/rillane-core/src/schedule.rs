//! 并行负载公平调度（RIL-025）：游戏小包（延迟敏感类）与网页吞吐
//! （吞吐类）的确定性调度规则——
//!
//! - **延迟类优先、预算封顶**：每轮先服务延迟类，但字节数封顶在
//!   `latency_budget_bytes`（默认量级 = 数个 MTU 小包）；预算用尽本轮
//!   不再多取——持续下载在途时游戏小包**必然**在每轮头部被服务，
//!   尾延迟有界且逐笔可测（`Grant.wait_ms` = 服务时刻 - 入队时刻）；
//! - **吞吐类不饥饿**：每轮总预算 `round_bytes` 中延迟类最多取走
//!   `latency_budget_bytes`，其余**保证**归吞吐类（工作保守：延迟类
//!   无流量时吞吐类吃满整轮）；单请求超容量按部分授予排队尾（残量
//!   保留原入队时刻，等待对残余仍可测）；
//! - **报告只影响本地可控瓶颈**：质量报告（RIL-026 样本）只能经
//!   [`FairScheduler::adapt_latency_budget`] 调整延迟预算这一**本地
//!   旋钮**，且被夹在声明边界 `[min, max]` 内（`round_bytes` 等其它
//!   形状参数不可被报告触碰；跨模块资源——RIL-024 预算池、RIL-023
//!   排空——不暴露任何报告入口，结构上排除报告越权）。
//!
//! 边界：本模块是确定性调度决策器（纯字节记账，无时钟无 IO）；
//! runtime 侧把出口发送循环的每轮取数接到 `serve_round`，把 RIL-026
//! 的 rtt_p95 样本接到 `adapt_latency_budget`。

use std::collections::VecDeque;
use std::fmt;

/// 稳定原因码：调度形状非法（预算超轮容量 / 边界倒挂 / 初值越界）
pub const CODE_SHAPE_INVALID: &str = "sched.shape.invalid";
/// 稳定原因码：零字节请求（无调度意义）
pub const CODE_EMPTY_REQUEST: &str = "sched.empty_request";

/// 流量类别（调度规则的两半：小包延迟敏感 vs 大块吞吐）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficClass {
    /// 延迟敏感（游戏小包/交互流量）
    Latency,
    /// 吞吐（网页/下载大块）
    Throughput,
}

impl TrafficClass {
    /// 机器口径
    pub fn as_str(self) -> &'static str {
        match self {
            TrafficClass::Latency => "latency",
            TrafficClass::Throughput => "throughput",
        }
    }
}

/// 调度形状（全部字节口径；构造时校验）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleShape {
    /// 每轮总字节预算（一轮 = 发送循环一次取数窗口）
    pub round_bytes: u64,
    /// 延迟类每轮预算（初值；可被报告适应，但恒夹在 min/max 内）
    pub latency_budget_bytes: u64,
    /// 延迟预算下界（报告不可压破——游戏小包最低保障）
    pub latency_budget_min: u64,
    /// 延迟预算上界（报告不可顶破——网页吞吐最低保障 = round - max）
    pub latency_budget_max: u64,
}

impl ScheduleShape {
    /// 校验形状：延迟预算不超轮容量、边界不倒挂、初值在界内
    pub fn validate(&self) -> Result<(), ScheduleError> {
        if self.latency_budget_max > self.round_bytes
            || self.latency_budget_min > self.latency_budget_max
            || self.latency_budget_bytes < self.latency_budget_min
            || self.latency_budget_bytes > self.latency_budget_max
            || self.round_bytes == 0
        {
            return Err(ScheduleError::ShapeInvalid);
        }
        Ok(())
    }
}

/// 调度错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    /// 形状非法（`sched.shape.invalid`）
    ShapeInvalid,
    /// 零字节请求（`sched.empty_request`）
    EmptyRequest,
}

impl ScheduleError {
    /// 稳定原因码
    pub fn code(&self) -> &'static str {
        match self {
            ScheduleError::ShapeInvalid => CODE_SHAPE_INVALID,
            ScheduleError::EmptyRequest => CODE_EMPTY_REQUEST,
        }
    }
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScheduleError::ShapeInvalid => {
                f.write_str("schedule shape invalid: latency budget must fit round and bounds")
            }
            ScheduleError::EmptyRequest => f.write_str("zero-byte request has nothing to schedule"),
        }
    }
}

impl std::error::Error for ScheduleError {}

/// 排队请求（入队时刻由调用方供——内核无时钟）
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRequest {
    /// 请求身份（`push` 返回，授予可追溯——含部分授予残量）
    request_id: u64,
    /// 类别
    class: TrafficClass,
    /// 剩余字节数（部分授予后递减）
    bytes: u64,
    /// 入队时刻（毫秒；残量保留原值——尾延迟对残余仍可测）
    enqueued_ms: u64,
}

/// 一次授予（调度规则的可测输出：谁、多少字节、等了多久）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// 请求身份
    pub request_id: u64,
    /// 类别
    pub class: TrafficClass,
    /// 本轮授予字节数（可小于请求——部分授予，残量留队）
    pub bytes: u64,
    /// 等待时长（服务时刻 - 入队时刻，毫秒）——尾延迟可测的载体
    pub wait_ms: u64,
}

/// 公平调度器：延迟类头部优先 + 预算封顶，吞吐类保底吃余量。
#[derive(Debug, Clone)]
pub struct FairScheduler {
    shape: ScheduleShape,
    /// 当前延迟预算（在 [min, max] 内；报告适应的唯一可变旋钮）
    latency_budget: u64,
    queues: [VecDeque<PendingRequest>; 2],
    next_request_id: u64,
}

impl FairScheduler {
    /// 构造调度器（形状非法拒绝——调度规则必须可解释才可运行）
    pub fn new(shape: ScheduleShape) -> Result<Self, ScheduleError> {
        shape.validate()?;
        let latency_budget = shape.latency_budget_bytes;
        Ok(Self {
            shape,
            latency_budget,
            queues: [VecDeque::new(), VecDeque::new()],
            next_request_id: 1,
        })
    }

    /// 入队一个请求，返回请求身份（零字节拒绝）
    pub fn push(
        &mut self,
        class: TrafficClass,
        bytes: u64,
        enqueued_ms: u64,
    ) -> Result<u64, ScheduleError> {
        if bytes == 0 {
            return Err(ScheduleError::EmptyRequest);
        }
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.queues[class as usize].push_back(PendingRequest {
            request_id,
            class,
            bytes,
            enqueued_ms,
        });
        Ok(request_id)
    }

    /// 服务一轮：延迟类头部优先（封顶在当前预算），吞吐类吃余量。
    /// 授予逐笔携带 wait_ms；单请求超容量部分授予、残量留队（原入队
    /// 时刻保留）。空轮返回空（工作保守，不虚发）。
    pub fn serve_round(&mut self, now_ms: u64) -> Vec<Grant> {
        let mut grants = Vec::new();
        let mut capacity = self.shape.round_bytes;
        for class in [TrafficClass::Latency, TrafficClass::Throughput] {
            // 延迟类封顶在自己的预算（不超过轮容量）；吞吐类吃全部余量
            let mut class_cap = match class {
                TrafficClass::Latency => self.latency_budget.min(capacity),
                TrafficClass::Throughput => capacity,
            };
            let queue = &mut self.queues[class as usize];
            while class_cap > 0 {
                let Some(front) = queue.front() else {
                    break;
                };
                let take = front.bytes.min(class_cap);
                let wait_ms = now_ms.saturating_sub(front.enqueued_ms);
                let request_id = front.request_id;
                grants.push(Grant {
                    request_id,
                    class,
                    bytes: take,
                    wait_ms,
                });
                class_cap -= take;
                capacity -= take;
                if take == front.bytes {
                    queue.pop_front();
                } else {
                    // 部分授予：残量保留原入队时刻（等待继续累计）
                    let front = queue.front_mut().expect("front 已核验");
                    front.bytes -= take;
                }
                if capacity == 0 {
                    break;
                }
            }
        }
        grants
    }

    /// 当前延迟预算（可观测）
    pub fn latency_budget(&self) -> u64 {
        self.latency_budget
    }

    /// 调度形状（只读——报告不可触碰）
    pub fn shape(&self) -> &ScheduleShape {
        &self.shape
    }

    /// 报告适应（验收「报告只能影响本地可控瓶颈」的唯一入口）：rtt
    /// p95 高于目标 → 预算上移一步；低于目标一半 → 下移一步；夹在
    /// 声明边界内。返回实际施加的带符号步长（可审计：应用步长之和 =
    /// 预算终值 - 初值）。本入口不触碰形状其它参数，更不暴露任何
    /// 跨模块资源（RIL-024 预算池/RIL-023 排空无报告入口）。
    pub fn adapt_latency_budget(&mut self, rtt_p95_ms: u64, target_ms: u64, step: u64) -> i64 {
        let desired = if target_ms > 0 && rtt_p95_ms > target_ms {
            self.latency_budget.saturating_add(step)
        } else if target_ms > 0 && rtt_p95_ms * 2 < target_ms {
            self.latency_budget.saturating_sub(step)
        } else {
            self.latency_budget
        };
        let clamped = desired
            .clamp(self.shape.latency_budget_min, self.shape.latency_budget_max);
        let applied = clamped as i64 - self.latency_budget as i64;
        self.latency_budget = clamped;
        applied
    }

    /// 两队列合计排队请求量（可观测）
    pub fn pending(&self, class: TrafficClass) -> u64 {
        self.queues[class as usize]
            .iter()
            .map(|req| req.bytes)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 形状：轮 64KB，延迟预算 3KB（两枚 MTU 量级），边界 [1KB, 16KB]
    fn shape() -> ScheduleShape {
        ScheduleShape {
            round_bytes: 64 * 1024,
            latency_budget_bytes: 3 * 1024,
            latency_budget_min: 1024,
            latency_budget_max: 16 * 1024,
        }
    }

    /// 验收①：持续下载在途时游戏小包本轮头部被服务、尾延迟逐笔可测
    #[test]
    fn game_tail_latency_measurable_under_sustained_download() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");

        // 网页大块持续下载：三个 64KB 请求占满队列
        let dl1 = sched
            .push(TrafficClass::Throughput, 64 * 1024, 0)
            .expect("入队");
        let _dl2 = sched.push(TrafficClass::Throughput, 64 * 1024, 0).expect("入队");
        let _dl3 = sched.push(TrafficClass::Throughput, 64 * 1024, 0).expect("入队");

        // 游戏小包 100B 在下载进行到 5s 时入队
        let game = sched
            .push(TrafficClass::Latency, 100, 5_000)
            .expect("入队");
        let grants = sched.serve_round(5_000);

        // 本轮头部 = 游戏小包（延迟类优先），等待 0ms
        assert_eq!(grants[0].request_id, game);
        assert_eq!(grants[0].class, TrafficClass::Latency);
        assert_eq!(grants[0].bytes, 100);
        assert_eq!(grants[0].wait_ms, 0, "延迟类头部被服务，尾延迟可测且有界");

        // 其余授予全部是吞吐类（下载块），等待时长逐笔记录
        assert!(grants.len() >= 2);
        assert!(grants[1..]
            .iter()
            .all(|g| g.class == TrafficClass::Throughput));
        assert_eq!(grants[1].request_id, dl1);
        assert_eq!(grants[1].wait_ms, 5_000, "下载块的等待同样可测");
    }

    /// 验收②：延迟类洪泛下吞吐类不饥饿——每轮延迟类封顶在预算内，
    /// 吞吐类拿到保底余量
    #[test]
    fn web_not_starved_under_latency_flood() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");

        // 洪泛：100 个 100B 游戏包（10KB）+ 一个 64KB 下载
        for _ in 0..100 {
            sched.push(TrafficClass::Latency, 100, 0).expect("入队");
        }
        let dl = sched.push(TrafficClass::Throughput, 64 * 1024, 0).expect("入队");

        let grants = sched.serve_round(10);
        let latency_bytes: u64 = grants
            .iter()
            .filter(|g| g.class == TrafficClass::Latency)
            .map(|g| g.bytes)
            .sum();
        let throughput_bytes: u64 = grants
            .iter()
            .filter(|g| g.class == TrafficClass::Throughput)
            .map(|g| g.bytes)
            .sum();

        assert!(
            latency_bytes <= 3 * 1024,
            "延迟类本轮封顶在预算内: {latency_bytes}"
        );
        assert!(
            throughput_bytes >= 64 * 1024 - 3 * 1024,
            "吞吐类拿到保底余量: {throughput_bytes}"
        );
        assert!(
            grants.iter().any(|g| g.request_id == dl),
            "吞吐类本轮不得饥饿"
        );
        // 延迟类残量留队（本轮预算已尽）
        assert!(sched.pending(TrafficClass::Latency) > 0);
    }

    /// 延迟类无流量：吞吐类吃满整轮（工作保守）
    #[test]
    fn full_round_to_throughput_when_no_latency_traffic() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");
        let dl = sched.push(TrafficClass::Throughput, 64 * 1024, 0).expect("入队");
        let grants = sched.serve_round(0);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].request_id, dl);
        assert_eq!(grants[0].bytes, 64 * 1024, "无延迟流量吞吐吃满整轮");
        assert_eq!(sched.pending(TrafficClass::Throughput), 0);
    }

    /// 部分授予：残量留队且保留原入队时刻（尾延迟对残余继续累计）
    #[test]
    fn partial_grant_preserves_enqueue_time() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");
        // 100KB 大块：本轮吃 64KB，残量 36KB
        let big = sched
            .push(TrafficClass::Throughput, 100 * 1024, 1_000)
            .expect("入队");
        let grants1 = sched.serve_round(1_000);
        assert_eq!(grants1.len(), 1);
        assert_eq!(grants1[0].bytes, 64 * 1024);
        assert_eq!(sched.pending(TrafficClass::Throughput), 36 * 1024);

        // 残量在第二轮被服务，等待从原入队时刻累计（2000-1000）
        let grants2 = sched.serve_round(2_000);
        assert_eq!(grants2.len(), 1);
        assert_eq!(grants2[0].request_id, big, "残量请求身份不变");
        assert_eq!(grants2[0].bytes, 36 * 1024);
        assert_eq!(grants2[0].wait_ms, 1_000, "残量等待按原入队时刻累计");
    }

    /// 验收③：报告适应只动延迟预算旋钮且夹在声明边界内——反复上推
    /// 停在 max、下拉停在 min，其它形状参数原封不动
    #[test]
    fn report_adaptation_clamps_within_local_bounds() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");
        let shape_before = sched.shape().clone();

        // 高延迟报告反复上推：停在 max（16KB），不越界
        let mut applied = 0i64;
        for _ in 0..10 {
            applied += sched.adapt_latency_budget(500, 50, 4 * 1024);
        }
        assert_eq!(sched.latency_budget(), 16 * 1024);
        assert_eq!(
            applied,
            16 * 1024i64 - 3 * 1024i64,
            "应用步长之和 = 终值-初值（可审计）"
        );

        // 低延迟报告反复下拉：停在 min（1KB）
        let mut applied_down = 0i64;
        for _ in 0..10 {
            applied_down += sched.adapt_latency_budget(5, 50, 4 * 1024);
        }
        assert_eq!(sched.latency_budget(), 1024);
        assert_eq!(applied_down, 1024i64 - 16 * 1024i64);

        // 目标带内（rtt 在 target/2..target）：不动
        assert_eq!(sched.adapt_latency_budget(30, 50, 1024), 0);
        assert_eq!(sched.latency_budget(), 1024);

        // 本地可控瓶颈边界：形状其它参数（round_bytes 等）不可被报告触碰
        assert_eq!(sched.shape(), &shape_before, "报告只能动延迟预算旋钮");
    }

    /// 适应有行为效果：预算上调后延迟类一轮可过更多字节（旋钮真的
    /// 控制调度，不是摆设）
    #[test]
    fn adaptation_changes_scheduling_behavior() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");
        for _ in 0..50 {
            sched.push(TrafficClass::Latency, 100, 0).expect("入队");
        }
        // 初预算 3KB → 一轮恰取 3072B（30 个整包 + 1 个 72B 部分授予）
        let grants = sched.serve_round(0);
        let served_initial: u64 = grants
            .iter()
            .filter(|g| g.class == TrafficClass::Latency)
            .map(|g| g.bytes)
            .sum();
        assert_eq!(served_initial, 3 * 1024);
        assert_eq!(sched.pending(TrafficClass::Latency), 5_000 - 3_072);

        // 再压 80 个新包（8000B）后上调到 max 16KB：一轮全部排空
        for _ in 0..80 {
            sched.push(TrafficClass::Latency, 100, 0).expect("入队");
        }
        sched.adapt_latency_budget(500, 50, 13 * 1024);
        assert_eq!(sched.latency_budget(), 16 * 1024);
        let grants = sched.serve_round(0);
        let served_raised: u64 = grants
            .iter()
            .filter(|g| g.class == TrafficClass::Latency)
            .map(|g| g.bytes)
            .sum();
        assert_eq!(
            served_raised,
            1928 + 8_000,
            "上调后一轮过完残量+全部新包（3072B 时代需 3+ 轮）"
        );
        assert_eq!(sched.pending(TrafficClass::Latency), 0, "一轮排空");
    }

    /// 形状非法拒绝（预算超轮 / 边界倒挂 / 初值越界 / 零轮）+ 零字节请求拒绝
    #[test]
    fn invalid_shape_and_empty_request_rejected() {
        let over = ScheduleShape {
            round_bytes: 1024,
            latency_budget_bytes: 512,
            latency_budget_min: 256,
            latency_budget_max: 2048, // max > round
        };
        assert_eq!(
            FairScheduler::new(over).expect_err("预算超轮应拒"),
            ScheduleError::ShapeInvalid
        );

        let crossed = ScheduleShape {
            round_bytes: 4096,
            latency_budget_bytes: 512,
            latency_budget_min: 1024, // min > 初值
            latency_budget_max: 2048,
        };
        assert_eq!(
            FairScheduler::new(crossed).expect_err("初值越界应拒"),
            ScheduleError::ShapeInvalid
        );

        let zero_round = ScheduleShape {
            round_bytes: 0,
            latency_budget_bytes: 0,
            latency_budget_min: 0,
            latency_budget_max: 0,
        };
        assert_eq!(
            FairScheduler::new(zero_round).expect_err("零轮应拒"),
            ScheduleError::ShapeInvalid
        );

        let mut sched = FairScheduler::new(shape()).expect("合法形状");
        let err = sched
            .push(TrafficClass::Latency, 0, 0)
            .expect_err("零字节请求应拒");
        assert_eq!(err.code(), CODE_EMPTY_REQUEST);
        assert!(err.to_string().contains("zero-byte"));
    }

    /// 空轮不虚发（工作保守）；类内 FIFO 与请求身份可追溯
    #[test]
    fn empty_round_grants_nothing_and_fifo_order_holds() {
        let mut sched = FairScheduler::new(shape()).expect("合法形状");
        assert!(sched.serve_round(0).is_empty(), "空轮不虚发");

        let first = sched.push(TrafficClass::Latency, 100, 0).expect("入队");
        let second = sched.push(TrafficClass::Latency, 100, 5).expect("入队");
        let grants = sched.serve_round(10);
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].request_id, first, "类内 FIFO");
        assert_eq!(grants[1].request_id, second);
        assert_eq!(grants[0].wait_ms, 10);
        assert_eq!(grants[1].wait_ms, 5);
    }
}
