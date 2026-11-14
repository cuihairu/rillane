use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

pub mod fake_ip;
pub mod hosts;
pub mod net_mark;
pub mod performance;
pub mod udp;

/// Trait object safe IO stream with AsyncRead/AsyncWrite combined.
pub trait IoStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// Boxed bidirectional IO stream used by inbound/outbound handlers.
pub type BoxedIo = Box<dyn IoStream>;

/// Constant-time equality for byte slices (defense-in-depth).
///
/// Compares all bytes regardless of length mismatch, accumulating differences
/// in a single accumulator. Returns false if lengths differ. This mitigates
/// timing side-channel leaks in authentication code paths where an attacker
/// might attempt to measure comparison time to recover credentials.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still perform a comparison over the longer slice to reduce
        // length-based timing signals (not perfect, but better than early return).
        let longer = if a.len() > b.len() { a } else { b };
        let mut acc = 0u8;
        for &byte in longer.iter() {
            acc |= byte;
        }
        std::hint::black_box(acc);
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId(Uuid);

impl Default for FlowId {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetProto {
    Tcp,
    Udp,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTarget {
    pub host: String,
    pub port: u16,
    pub proto: TargetProto,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowMetadata {
    pub tags: Vec<String>,
    pub annotations: BTreeMap<String, String>,
}

pub struct Flow {
    pub id: FlowId,
    pub target: FlowTarget,
    pub io: BoxedIo,
    pub metadata: FlowMetadata,
}

impl fmt::Debug for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flow")
            .field("id", &self.id)
            .field("target", &self.target)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Flow {
    pub fn context(&self) -> FlowContext {
        FlowContext {
            id: self.id,
            target: self.target.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub id: FlowId,
    pub target: FlowTarget,
    pub metadata: FlowMetadata,
}

#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// 路由路径，包含逻辑组和最终节点
    pub path: RoutePath,
    /// 路由选择的原因
    pub reason: Option<String>,
    /// 路由类型
    pub route_type: RouteType,
}

#[derive(Debug, Clone)]
pub enum RoutePath {
    /// 直接路由到单个节点
    Direct { node: String },
    /// 通过组选择路由
    ThroughGroup {
        group: String,
        selected_node: String,
        intermediate_nodes: Vec<String>,
    },
    /// 多跳路由链
    Chain { hops: Vec<RouteHop> },
}

#[derive(Debug, Clone)]
pub struct RouteHop {
    pub node: String,
    pub hop_type: HopType,
}

#[derive(Debug, Clone)]
pub enum HopType {
    /// 入口节点
    Ingress,
    /// 中继节点
    Relay,
    /// 出口节点
    Egress,
    /// 中间处理节点
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    /// 标准路由
    Standard,
    /// 协作路由
    Collaborative,
    /// 游戏加速路由
    Gaming,
    /// 备用路由
    Fallback,
}

impl RouteDecision {
    pub fn direct(node: String) -> Self {
        Self {
            path: RoutePath::Direct { node },
            reason: None,
            route_type: RouteType::Standard,
        }
    }

    pub fn through_group(
        group: String,
        selected_node: String,
        intermediate_nodes: Vec<String>,
    ) -> Self {
        Self {
            path: RoutePath::ThroughGroup {
                group,
                selected_node,
                intermediate_nodes,
            },
            reason: None,
            route_type: RouteType::Standard,
        }
    }

    pub fn chain(hops: Vec<RouteHop>) -> Self {
        Self {
            path: RoutePath::Chain { hops },
            reason: None,
            route_type: RouteType::Collaborative,
        }
    }

    /// 获取最终的目标节点
    pub fn final_node(&self) -> String {
        match &self.path {
            RoutePath::Direct { node } => node.clone(),
            RoutePath::ThroughGroup { selected_node, .. } => selected_node.clone(),
            RoutePath::Chain { hops } => hops.last().map(|h| h.node.clone()).unwrap_or_default(),
        }
    }

    /// 获取所有经过的节点（按顺序）
    pub fn all_nodes(&self) -> Vec<String> {
        match &self.path {
            RoutePath::Direct { node } => vec![node.clone()],
            RoutePath::ThroughGroup {
                selected_node: _selected_node,
                intermediate_nodes,
                ..
            } => {
                let mut nodes = intermediate_nodes.clone();
                nodes.push(_selected_node.clone());
                nodes
            }
            RoutePath::Chain { hops } => hops.iter().map(|h| h.node.clone()).collect(),
        }
    }

    /// 路径长度（跳数）
    pub fn hop_count(&self) -> usize {
        match &self.path {
            RoutePath::Direct { .. } => 1,
            RoutePath::ThroughGroup {
                selected_node: _,
                intermediate_nodes,
                ..
            } => intermediate_nodes.len() + 1,
            RoutePath::Chain { hops } => hops.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowReport {
    pub upstream: u64,
    pub downstream: u64,
}

#[async_trait]
pub trait FlowRouter: Send + Sync {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision>;
}

#[async_trait]
pub trait FlowOutput: Send + Sync {
    async fn forward(&self, decision: RouteDecision, flow: Flow) -> Result<FlowReport>;
}

/// 经出口对探测目标做一次 HTTP 探测（G1-9 url-test 实测数据源）。
///
/// 构造 duplex 流作 ingress 侧、以探测目标为 Flow.target 走既有 forward
/// 路径（与真实流量同管道），发出 HEAD 请求；收到任意响应字节即判健康，
/// RTT = 探测发起到首字节的耗时。探测完 shutdown 写半关流（forward 在
/// 独立任务自然收尾）。
///
/// timeout 覆盖连接+协议握手+请求往返全程；超时/出口缺失/转发失败均 Err。
pub async fn probe_via_output(
    output: Arc<dyn FlowOutput>,
    node: &str,
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<u64, String> {
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let flow = Flow {
        id: FlowId::default(),
        target: FlowTarget {
            host: host.to_string(),
            port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(server),
        metadata: FlowMetadata::default(),
    };
    let decision = RouteDecision {
        path: RoutePath::Direct {
            node: node.to_string(),
        },
        reason: Some("url-test probe".to_string()),
        route_type: RouteType::Standard,
    };
    let forward = tokio::spawn(async move { output.forward(decision, flow).await });

    let fut = async {
        let req = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rillane-urltest/1\r\nConnection: close\r\n\r\n"
        );
        client
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("探测请求写入失败：{e}"))?;
        let mut first = [0u8; 1];
        client
            .read_exact(&mut first)
            .await
            .map_err(|e| format!("探测响应读取失败：{e}"))?;
        Ok::<(), String>(())
    };
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(timeout, fut).await;
    let _ = client.shutdown().await;
    // forward 任务自然收尾：探测写半关后连接器侧 EOF 退出；不阻塞探测返回
    tokio::spawn(async move {
        let _ = forward.await;
    });
    match outcome {
        Err(_) => Err(format!("探测 {node} → {host}:{port} 超时（{timeout:?}）")),
        Ok(Err(e)) => Err(format!("探测 {node} → {host}:{port} 失败：{e}")),
        Ok(Ok(())) => Ok(started.elapsed().as_millis() as u64),
    }
}

#[async_trait]
pub trait FlowMiddleware: Send + Sync {
    fn name(&self) -> &'static str;
    async fn handle(&self, flow: Flow) -> Result<Flow>;
}

/// 静态 middleware 管线（obfuscation-middleware.md §1.2，C1 收口）：build 期
/// 定序、运行期只读的不可变链。关闭态 = `Default`（空链），调用方以
/// `is_empty()` 一次分支旁路（§2.5 零开销：无锁、无分配、无 async 调用）；
/// P3-2 动态加载在此容器之上扩展，本类型不引入任何动态加载依赖（§1.5）。
#[derive(Clone, Default)]
pub struct MiddlewareChain {
    inner: Arc<Vec<Arc<dyn FlowMiddleware>>>,
}

impl fmt::Debug for MiddlewareChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // trait 对象无 Debug：以链内 middleware 名呈现（诊断面兼测试断言可用）
        f.debug_struct("MiddlewareChain")
            .field(
                "names",
                &self.inner.iter().map(|mw| mw.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl MiddlewareChain {
    pub fn new(inner: Vec<Arc<dyn FlowMiddleware>>) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 顺序执行（声明序即执行序，§1.5）：任一 middleware 返回 Err 即中止，
    /// 错误冒泡至调用方（E8：转发失败，不静默继续）。
    pub async fn run(&self, flow: Flow) -> Result<Flow> {
        let mut flow = flow;
        for mw in self.inner.iter() {
            // P1-4 §5：调用即计数（含最终 Err 的调用；锁守卫不跨 await）
            if let Ok(mut map) = MIDDLEWARE_INVOCATIONS.lock() {
                *map.entry(mw.name()).or_insert(0) += 1;
            }
            flow = mw.handle(flow).await?;
        }
        Ok(flow)
    }
}

/// P1-4 §5 `rillane_obfs_middleware_invocations_total{name}` 数据源：进程级
/// 调用计数（键 = `FlowMiddleware::name()`，标签封闭集 = 配置挂载集）。
/// 空链 `run` 不发生（调用方 `is_empty` 旁路，§2.5），关闭态恒无条目；
/// 锁开销仅链非空时出现（每流一次，§2.5 零开销口径只覆盖关闭态）。
static MIDDLEWARE_INVOCATIONS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());

/// P1-4 §5：链内 middleware 调用计数快照（`/metrics` 渲染数据源，名字升序）。
pub fn middleware_invocations() -> Vec<(&'static str, u64)> {
    let Ok(map) = MIDDLEWARE_INVOCATIONS.lock() else {
        return Vec::new();
    };
    map.iter().map(|(k, v)| (*k, *v)).collect()
}

/// padding 三模式（obfuscation-middleware.md §2.2 表）：
/// Fixed 一律补到定长 / Bucket 对齐最近上界桶 / Range 确定性伪随机长度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaddingMode {
    Fixed,
    Bucket,
    Range,
}

/// padding 策略形态（obfuscation-middleware.md §2.2）——策略/执行分离的"策略"侧：
/// 由 padding middleware 写入 `rillane.obfs.padding` 注解（§1.4），帧执行侧读取实施
/// （§2.3）。serde 序列化进注解，故落 core（与注解契约同文件；core 不依赖 runtime）。
/// 非本模式字段保持 0/空，由策略引擎按 mode 取用（M2）；overhead 上限判定在
/// 策略层（§2.6），执行侧只按 spec 办事。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaddingSpec {
    pub mode: PaddingMode,
    /// Fixed：目标长度；Bucket/Range：忽略
    pub target: usize,
    /// Bucket：候选桶（升序非空）；Fixed/Range：忽略
    pub buckets: Vec<usize>,
    /// Range：下界；其余忽略
    pub min: usize,
    /// Range：上界；其余忽略
    pub max: usize,
    /// overhead 保护上限（§2.6，默认 0.5）
    pub max_overhead_ratio: f32,
}

/// timing 两模式（P2-4 obfuscation-timing-shaping.md §3）：
/// Fixed 恒定注入 / Uniform 确定性抖动（hash(flow_id, seq) 取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingMode {
    Fixed,
    Uniform,
}

/// timing 策略形态（P2-4）——与 PaddingSpec 同契约：middleware 写
/// `rillane.obfs.timing` 注解，执行侧（同 middleware handle 内 sleep）读取
/// 实施；`max_delay_ms` 是硬闸门（§2-D4）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimingSpec {
    pub mode: TimingMode,
    /// Fixed：注入毫秒值
    pub fixed_ms: u64,
    /// Uniform：下界
    pub min_ms: u64,
    /// Uniform：上界（min ≤ max，max ≤ max_delay_ms 由 config validate 保证）
    pub max_ms: u64,
    /// 硬闸门
    pub max_delay_ms: u64,
}

/// shaping 单模式（P2-4 M0：interval 网格归一；其余模式留后续）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapingMode {
    Interval,
}

/// shaping 策略形态（P2-4）——middleware 写 `rillane.obfs.shaping` 注解，
/// `PacedIo` 读取实施写侧网格归一（§2-D2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShapingSpec {
    pub mode: ShapingMode,
    /// 网格间隔毫秒
    pub interval_ms: u64,
    /// 网格抖动幅度（≤ interval_ms）
    pub jitter_ms: u64,
    /// 硬闸门
    pub max_delay_ms: u64,
}

/// 流量会话信息
#[derive(Debug, Clone)]
pub struct FlowSession {
    /// 会话ID
    pub id: FlowId,
    /// 创建时间
    pub created_at: Instant,
    /// 最后活跃时间
    pub last_active: Instant,
    /// 会话状态
    pub status: SessionStatus,
    /// 客户端信息
    pub client_info: ClientInfo,
    /// 当前路由路径
    pub current_path: Vec<String>,
    /// 路由历史
    pub route_history: Vec<RouteHistory>,
    /// 使用统计
    pub usage: SessionUsage,
    /// 故障统计
    pub failure_stats: FailureStats,
}

/// 会话状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    /// 初始化
    Initializing,
    /// 活跃中
    Active,
    /// 空闲
    Idle,
    /// 连接中
    Connecting,
    /// 断开中
    Disconnecting,
    /// 已终止
    Terminated,
    /// 失败
    Failed,
}

/// 客户端信息
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    /// 客户端节点ID
    pub node_id: Option<String>,
    /// 客户端地址
    pub address: Option<SocketAddr>,
    /// 用户代理
    pub user_agent: Option<String>,
    /// 认证信息
    pub auth_info: Option<AuthInfo>,
}

/// 认证信息
#[derive(Debug, Clone)]
pub struct AuthInfo {
    /// 认证方法
    pub method: AuthMethod,
    /// 认证用户
    pub username: Option<String>,
    /// 认证时间
    pub authenticated_at: Option<Instant>,
}

/// 认证方法
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// 无认证
    None,
    /// 用户名密码
    UsernamePassword,
    /// Token认证
    Token,
    /// 证书认证
    Certificate,
}

/// 路由历史记录
#[derive(Debug, Clone)]
pub struct RouteHistory {
    /// 路由ID
    pub route_id: String,
    /// 路由路径
    pub path: Vec<String>,
    /// 路由类型
    pub route_type: String,
    /// 选择原因
    pub reason: String,
    /// 创建时间
    pub created_at: Instant,
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

/// 会话使用统计
#[derive(Debug, Clone, Default)]
pub struct SessionUsage {
    /// 上传流量（字节）
    pub bytes_uploaded: u64,
    /// 下载流量（字节）
    pub bytes_downloaded: u64,
    /// 连接时长（秒）
    pub duration_seconds: u64,
    /// 数据包数量
    pub packets_count: u64,
    /// 重连次数
    pub reconnect_count: u32,
}

/// 故障统计
#[derive(Debug, Clone, Default)]
pub struct FailureStats {
    /// 连接失败次数
    pub connection_failures: u32,
    /// 路由失败次数
    pub route_failures: u32,
    /// 超时次数
    pub timeout_count: u32,
    /// 最后故障时间
    pub last_failure: Option<Instant>,
    /// 平均故障间隔（秒）
    pub average_failure_interval: f32,
}

/// 链路上下文（多跳状态管理）
#[derive(Debug, Clone)]
pub struct ChainContext {
    /// 链路ID
    pub chain_id: String,
    /// 源节点
    pub source_node: String,
    /// 目标节点
    pub target_node: String,
    /// 当前路径
    pub current_path: Vec<String>,
    /// 路径跳数
    pub hop_count: usize,
    /// 每跳的延迟统计
    pub hop_latencies: Vec<u32>,
    /// 每跳的带宽统计
    pub hop_bandwidths: Vec<u32>,
    /// 链路可靠性评分
    pub reliability_score: f32,
    /// 链路创建时间
    pub created_at: Instant,
    /// 最后更新时间
    pub last_updated: Instant,
    /// 链路状态
    pub status: ChainStatus,
    /// 备用路径列表
    pub fallback_paths: Vec<Vec<String>>,
    /// 当前使用的备用路径索引
    pub current_fallback_index: usize,
}

/// 链路状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// 初始化中
    Initializing,
    /// 活跃
    Active,
    /// 降级中
    Degraded,
    /// 故障转移中
    FailingOver,
    /// 已终止
    Terminated,
}

impl FlowSession {
    /// 创建新的流量会话
    pub fn new(id: FlowId, _target: FlowTarget) -> Self {
        Self {
            id,
            created_at: Instant::now(),
            last_active: Instant::now(),
            status: SessionStatus::Initializing,
            client_info: ClientInfo::default(),
            current_path: Vec::new(),
            route_history: Vec::new(),
            usage: SessionUsage::default(),
            failure_stats: FailureStats::default(),
        }
    }

    /// 更新路由路径
    pub fn update_route(&mut self, path: Vec<String>, reason: String) {
        self.current_path = path.clone();

        let route_history = RouteHistory {
            route_id: format!("route-{}", self.route_history.len() + 1),
            path: path.clone(),
            route_type: "mesh_chain".to_string(),
            reason,
            created_at: Instant::now(),
            success: true,
            error: None,
        };

        self.route_history.push(route_history);
        self.status = SessionStatus::Active;
        self.last_active = Instant::now();
    }

    /// 更新使用统计
    pub fn update_usage(&mut self, bytes_uploaded: u64, bytes_downloaded: u64) {
        self.usage.bytes_uploaded += bytes_uploaded;
        self.usage.bytes_downloaded += bytes_downloaded;

        let duration = self.created_at.elapsed().as_secs();
        if duration > self.usage.duration_seconds {
            self.usage.duration_seconds = duration;
        }
    }

    /// 记录故障
    pub fn record_failure(&mut self, failure_type: FailureType) {
        match failure_type {
            FailureType::Connection => self.failure_stats.connection_failures += 1,
            FailureType::Route => self.failure_stats.route_failures += 1,
            FailureType::Timeout => self.failure_stats.timeout_count += 1,
        }

        self.failure_stats.last_failure = Some(Instant::now());
        self.status = SessionStatus::Failed;

        // 计算平均故障间隔
        self.failure_stats.average_failure_interval = if self.failure_stats.connection_failures
            + self.failure_stats.route_failures
            + self.failure_stats.timeout_count
            > 0
        {
            let total_failures = self.failure_stats.connection_failures
                + self.failure_stats.route_failures
                + self.failure_stats.timeout_count;
            let total_duration = self.created_at.elapsed().as_secs() as f32;
            total_duration / total_failures as f32
        } else {
            0.0
        };
    }

    /// 获取会话持续时间
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// 是否需要重连
    pub fn should_reconnect(&self) -> bool {
        match self.status {
            SessionStatus::Failed | SessionStatus::Terminated => true,
            SessionStatus::Idle => {
                // 空闲超过30秒认为需要重连
                self.last_active.elapsed() > Duration::from_secs(30)
            }
            _ => false,
        }
    }
}

/// 故障类型
#[derive(Debug, Clone)]
pub enum FailureType {
    /// 连接故障
    Connection,
    /// 路由故障
    Route,
    /// 超时故障
    Timeout,
}

impl ChainContext {
    /// 创建新的链路上下文
    pub fn new(chain_id: String, source: String, target: String) -> Self {
        Self {
            chain_id,
            source_node: source,
            target_node: target,
            current_path: Vec::new(),
            hop_count: 0,
            hop_latencies: Vec::new(),
            hop_bandwidths: Vec::new(),
            reliability_score: 1.0,
            created_at: Instant::now(),
            last_updated: Instant::now(),
            status: ChainStatus::Initializing,
            fallback_paths: Vec::new(),
            current_fallback_index: 0,
        }
    }

    /// 更新链路路径
    pub fn update_path(&mut self, path: Vec<String>) {
        self.current_path = path.clone();
        self.hop_count = path.len();
        self.last_updated = Instant::now();

        // 初始化延迟和带宽统计（实际应用中应该从监控系统获取）
        self.hop_latencies.resize(self.hop_count, 0);
        self.hop_bandwidths.resize(self.hop_count, 0);

        self.status = ChainStatus::Active;
    }

    /// 添加备用路径
    pub fn add_fallback_path(&mut self, path: Vec<String>) {
        self.fallback_paths.push(path);
    }

    /// 获取当前使用的路径
    ///
    /// 单一口径：`current_path` 恒为当前生效路径（主路径或被提升的备用）。
    /// 存量缺陷修缮（P2-1 切换账本测试首度覆盖暴露）：旧实现 fallback 非空时
    /// 恒读 `fallback_paths[current_fallback_index]`——从未切换过的链路谎报
    /// fallback[0] 为当前路径，且首次故障转移跳过 fallback[0] 直取 [1]。
    pub fn get_current_path(&self) -> Option<Vec<String>> {
        Some(self.current_path.clone())
    }

    /// 切换到下一个备用路径
    ///
    /// 提升语义：`fallback_paths[current_fallback_index]` 升为 current_path
    /// （复用 update_path 同步 hop_count/时延带宽向量），索引后移；无备用可切
    /// 返回 false（备用耗尽）。
    pub fn switch_fallback_path(&mut self) -> bool {
        if self.current_fallback_index < self.fallback_paths.len() {
            let next = self.fallback_paths[self.current_fallback_index].clone();
            self.current_fallback_index += 1;
            self.update_path(next);
            self.status = ChainStatus::FailingOver;
            true
        } else {
            false
        }
    }

    /// 计算链路质量评分
    pub fn calculate_quality_score(&self) -> f32 {
        if self.hop_latencies.is_empty() || self.hop_bandwidths.is_empty() {
            // P2 深审（2026-11-03）：hop_bandwidths 空而 hop_latencies 非空
            // 时 `0.0/0.0 = NaN` 传播进评分。两 pub 向量常规同长（update_path），
            // 但外部独立变更即可触发；任一为空视为「无有效样本」，回退可靠性。
            return self.reliability_score;
        }

        // 平均延迟
        let avg_latency: f32 = self
            .hop_latencies
            .iter()
            .map(|&lat| lat as f32)
            .sum::<f32>()
            / self.hop_latencies.len() as f32;

        // 平均带宽
        let avg_bandwidth: f32 = self.hop_bandwidths.iter().map(|&bw| bw as f32).sum::<f32>()
            / self.hop_bandwidths.len() as f32;

        // 综合评分：延迟越低越好，带宽越高越好，结合可靠性
        let latency_score = if avg_latency > 0.0 {
            1000.0 / avg_latency
        } else {
            1000.0
        };

        let bandwidth_score = avg_bandwidth / 10.0; // 归一化到 0-100 分

        (latency_score * 0.3 + bandwidth_score * 0.3 + self.reliability_score * 0.4).min(100.0)
    }

    /// 获取链路持续时间
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }
}

#[async_trait]
pub trait EgressConnector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn forward(&self, flow: Flow) -> Result<FlowReport>;
}

#[async_trait]
pub trait IngressEndpoint: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P3 深审回归（2026-11-03）：非常量时间认证比对防御纵深。恒时等值：
    /// 同长同值 true；同长异值 false；异长 false；空串 true（零长度同值）。
    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"tokens"));
        assert!(!constant_time_eq(b"token", b"tokem"));
        assert!(!constant_time_eq(b"", b"token"));
        assert!(constant_time_eq(b"", b""));
    }

    /// P2-1 修缮钉子：路径语义单口径——current_path 恒为生效路径，切换
    /// 按 fallback 声明序逐一提升（fallback[0] 不再被首跳跳过），耗尽返回
    /// false 且路径停在最后一条备用上。
    #[test]
    fn chain_context_fallback_promotes_in_declaration_order() {
        let mut ctx = ChainContext::new("ch".into(), "c1".into(), "exit1".into());
        ctx.update_path(vec!["c1".into(), "relay1".into(), "exit1".into()]);
        ctx.add_fallback_path(vec!["c1".into(), "relay2".into(), "exit1".into()]);
        ctx.add_fallback_path(vec!["c1".into(), "relay3".into(), "exit1".into()]);

        // 有 fallback 在册时当前路径仍是主路径（旧实现此处谎报 fallback[0]）
        assert_eq!(
            ctx.get_current_path(),
            Some(vec!["c1".into(), "relay1".into(), "exit1".into()])
        );

        assert!(ctx.switch_fallback_path(), "首切提升 fallback[0]");
        assert_eq!(ctx.current_fallback_index, 1);
        assert_eq!(
            ctx.get_current_path(),
            Some(vec!["c1".into(), "relay2".into(), "exit1".into()])
        );

        assert!(ctx.switch_fallback_path(), "次切提升 fallback[1]");
        assert_eq!(
            ctx.get_current_path(),
            Some(vec!["c1".into(), "relay3".into(), "exit1".into()])
        );

        assert!(!ctx.switch_fallback_path(), "备用耗尽");
        assert_eq!(
            ctx.get_current_path(),
            Some(vec!["c1".into(), "relay3".into(), "exit1".into()]),
            "耗尽后路径停在最后一条备用"
        );
    }

    /// 无备用链路：get 恒回主路径，切换恒 false。
    #[test]
    fn chain_context_without_fallbacks_stays_on_primary() {
        let mut ctx = ChainContext::new("ch".into(), "c1".into(), "exit1".into());
        ctx.update_path(vec!["c1".into(), "exit1".into()]);
        assert_eq!(
            ctx.get_current_path(),
            Some(vec!["c1".into(), "exit1".into()])
        );
        assert!(!ctx.switch_fallback_path());
    }

    /// P2 深审回归（2026-11-03）：hop_bandwidths 空而 hop_latencies 非空时
    /// `0.0/0.0 = NaN` 传播进评分。任一为空视为无有效样本，回退可靠性（非
    /// NaN）。
    #[test]
    fn quality_score_no_nan_when_bandwidths_empty() {
        let mut ctx = ChainContext::new("ch".into(), "c1".into(), "exit1".into());
        ctx.update_path(vec!["c1".into(), "exit1".into()]);
        // 构造 latencies 非空、bandwidths 空（update_path 恒同长，此处手工改）。
        ctx.hop_latencies = vec![10, 20];
        ctx.hop_bandwidths = Vec::new();
        ctx.reliability_score = 0.7;
        let score = ctx.calculate_quality_score();
        assert!(!score.is_nan(), "带宽空不得 NaN：{score}");
        assert!(
            (score - 0.7).abs() < f64::EPSILON as f32,
            "应回退可靠性：{score}"
        );
    }

    /// G1-9 探测管道 stub 出口：无视 decision，把 ingress 流直连回环目标
    /// （copy_bidirectional 全双工搬运——与真实出口连接器行为同形）。
    struct ProbeStubOutput {
        addr: std::net::SocketAddr,
    }

    #[async_trait::async_trait]
    impl FlowOutput for ProbeStubOutput {
        async fn forward(&self, _decision: RouteDecision, mut flow: Flow) -> Result<FlowReport> {
            let mut upstream = tokio::net::TcpStream::connect(self.addr).await?;
            tokio::io::copy_bidirectional(flow.io.as_mut(), &mut upstream).await?;
            Ok(FlowReport {
                upstream: 0,
                downstream: 0,
            })
        }
    }

    /// G1-9：回环健康路径——对端回 HTTP 响应，探测拿到首字节返回 Ok 且
    /// RTT 在超时窗口内。
    #[tokio::test]
    async fn probe_via_output_roundtrip_returns_rtt() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let output: Arc<dyn FlowOutput> = Arc::new(ProbeStubOutput { addr });
        let rtt = probe_via_output(
            output,
            "n1",
            &addr.ip().to_string(),
            addr.port(),
            "/generate_204",
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
        assert!(rtt <= 5000, "RTT 应落在超时窗口内：{rtt}ms");
        Ok(())
    }

    /// G1-9：黑洞路径——对端连上不回话，探测在 timeout 内 Err（超时语义
    /// 归 Err 文本，不 panic 不挂起）。
    #[tokio::test]
    async fn probe_via_output_blackhole_times_out() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.expect("accept");
            // 持有连接不读不回，探测侧 read_exact 停在超时
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let output: Arc<dyn FlowOutput> = Arc::new(ProbeStubOutput { addr });
        let outcome = probe_via_output(
            output,
            "n2",
            &addr.ip().to_string(),
            addr.port(),
            "/generate_204",
            Duration::from_millis(200),
        )
        .await;
        let err = outcome.expect_err("黑洞必须 Err");
        assert!(err.contains("超时"), "超时语义：{err}");
        Ok(())
    }
}
