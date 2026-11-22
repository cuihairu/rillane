//! 透明接管入口（RIL-139）：socket 级透明接管——iptables/nftables
//! REDIRECT 或 TPROXY 把目标流量重定向到本机监听，监听器恢复**原目标**
//! 并**固定**路由到配置的 `target` egress 节点（固定目标 tunnel）。
//!
//! 面口径（具名边界，networking.md transparent 节）：
//! - TCP 应用面交付；UDP/QUIC 应用面不交付（catalog 口径）——不留 udp 面；
//! - 平台面=Linux（iptables/nftables + SO_ORIGINAL_DST/IP_TRANSPARENT）；
//!   Windows/macOS（WFP/pf）不在本项；
//! - 规则应用/撤销需 CAP_NET_ADMIN + iptables/ip 二进制——本席位
//!   （uid 1000 无 cap_net_admin）跑负路径契约（ENOENT/EPERM 具名拒绝、
//!   注入面流程）；真机验收（#[ignore] 特权门）在具平台权限的机器上。
//!
//! 入口形状与 socks5 同构（bind → accept 循环 → 每连接 spawn → 建 Flow →
//! forward），差异：平台面按接管机制分叉——redirect 原目标经
//! `SO_ORIGINAL_DST` 恢复；tproxy 原目标 = accepted socket `local_addr()`。
//! 监听面抽象为 [`TakeoverAccept`]（可注入：测试喂已知原目标，真实现见
//! [`RedirectAccept`]/[`TproxyAccept`]）。
//!
//! 固定目标契约：被接管流量恒经 `network.transparent.target`——路由决策即
//! 配置 target（`RouteDecision::direct`），**不经路由引擎重选**（重选会背离
//! 固定目标契约，静默把透明流量送往 `routing.mode` 指向的节点）。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::watch;

use rillane_config::{TransparentBlockConfig, TransparentMode};
use rillane_core::{
    BoxedIo, Flow, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget, IngressEndpoint,
    RouteDecision, TargetProto,
};
use rillane_platform::network::takeover::{LinuxRouteTransaction, StepExecutor};
use rillane_platform::network::transparent::{self as transparent_face, TransparentRule};

/// 透明接管入口配置（network.transparent 块 → 本类型）。
#[derive(Debug, Clone)]
pub struct TransparentIngressConfig {
    /// 接管监听地址（REDIRECT 目标 / TPROXY on-port）
    pub listen: SocketAddr,
    /// 固定目标 egress 节点名（被接管流量恒经它）
    pub target: String,
    /// 接管机制（redirect / tproxy）
    pub mode: TransparentMode,
    /// 被接管的目的端口（空 = 全端口）
    pub intercept_ports: Vec<u16>,
    /// ip rule/route 逃逸表号（TPROXY 面）
    pub rule_table: u32,
}

impl TransparentIngressConfig {
    /// 块 → 入口配置（listen 块级已 validate 为合法 SocketAddr；此处再解析
    /// 一次把错误归位到映射层——防御不变式破坏）。
    pub fn from_block(block: &TransparentBlockConfig) -> Result<Self> {
        let listen = block.listen.parse::<SocketAddr>().with_context(|| {
            format!(
                "network.transparent.listen 须为合法 SocketAddr（当前 {:?}）",
                block.listen
            )
        })?;
        Ok(Self {
            listen,
            target: block.target.trim().to_string(),
            mode: block.mode,
            intercept_ports: block.intercept_ports.clone(),
            rule_table: block.rule_table,
        })
    }

    fn mode_name(&self) -> &'static str {
        match self.mode {
            TransparentMode::Redirect => "redirect",
            TransparentMode::Tproxy => "tproxy",
        }
    }
}

/// 接管监听面（可注入）：accept 一个连接并恢复**原目标**。真实现按机制
/// 分叉（[`RedirectAccept`]/[`TproxyAccept`]）；测试注入喂已知原目标
/// （本席位无 CAP_NET_ADMIN——真实接管连接不可构造）。
#[async_trait]
pub trait TakeoverAccept: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    /// accept 一个连接：返回 (io 端, 原目标)。连接级拒绝（未接管直连无
    /// conntrack NAT 记录等）→ 具名 Err（调用方按连接处理：warn + 关流，
    /// 不崩溃入口；监听 socket 自身故障罕见，同口径继续）。
    async fn accept(&self) -> Result<(BoxedIo, SocketAddr)>;
}

/// REDIRECT 监听面：普通 bind + accept 后经 `SO_ORIGINAL_DST` 恢复原目标。
pub struct RedirectAccept {
    listener: TcpListener,
}

impl RedirectAccept {
    pub async fn bind(listen: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("transparent(redirect) 无法监听 {listen}"))?;
        Ok(Self { listener })
    }
}

#[async_trait]
impl TakeoverAccept for RedirectAccept {
    fn name(&self) -> &'static str {
        "redirect"
    }

    async fn accept(&self) -> Result<(BoxedIo, SocketAddr)> {
        let (stream, _peer) = self
            .listener
            .accept()
            .await
            .context("transparent(redirect) accept 失败")?;
        let dst = transparent_face::original_destination(&stream)
            .map_err(|e| anyhow!("原目标恢复失败（redirect：{e}）"))?;
        Ok((Box::new(stream), dst))
    }
}

/// TPROXY 监听面：`IP_TRANSPARENT` bind（make_transparent_listener）+
/// accept；原目标 = accepted socket `local_addr()`（TPROXY 连接保持原目标
/// 为 socket 本地地址，无需 cmsg）。
pub struct TproxyAccept {
    listener: TcpListener,
}

impl TproxyAccept {
    pub fn bind(listen: SocketAddr) -> Result<Self> {
        let std_listener = transparent_face::make_transparent_listener(listen)
            .with_context(|| format!("transparent(tproxy) 无法建监听 {listen}"))?;
        let listener = TcpListener::from_std(std_listener)
            .context("transparent(tproxy) 监听注册 tokio 失败")?;
        Ok(Self { listener })
    }
}

#[async_trait]
impl TakeoverAccept for TproxyAccept {
    fn name(&self) -> &'static str {
        "tproxy"
    }

    async fn accept(&self) -> Result<(BoxedIo, SocketAddr)> {
        let (stream, _peer) = self
            .listener
            .accept()
            .await
            .context("transparent(tproxy) accept 失败")?;
        let dst = stream
            .local_addr()
            .context("transparent(tproxy) local_addr 读取失败")?;
        Ok((Box::new(stream), dst))
    }
}

/// 透明接管入口：iptables REDIRECT/TPROXY 把目标流量重定向到本机监听，
/// 入口恢复原目标并固定路由到配置 target 节点。
///
/// 生命周期（规则 = 系统副作用，入口属主——同 TunIngress 属主化设备/
/// 路由）：run() 起始应用规则（apply_rules），run() 退出（shutdown 信号或
/// 错误）逆序撤销（undo_rules，幂等）。规则应用/撤销需 CAP_NET_ADMIN +
/// iptables/ip 二进制——无权限具名拒绝（不静默降级）。
pub struct TransparentIngress {
    config: TransparentIngressConfig,
    /// 入口退出信号（stop 路径 → run 循环 break → 规则撤销）
    shutdown_tx: watch::Sender<()>,
    shutdown_rx: watch::Receiver<()>,
    /// 规则计划（argv；执行经 StepExecutor shell-out——与 RIL-029 ip 面同构）
    rules: Vec<TransparentRule>,
    /// 步骤执行器（可注入：测试确定性；真实现 shell-out iptables/ip）
    exec: StepExecutor,
    /// 注入监听面（测试喂已知原目标；None = 生产按 mode 建真面）
    face: Option<Arc<dyn TakeoverAccept>>,
}

impl TransparentIngress {
    /// 生产构造：规则计划（按 mode）+ 真执行器（shell-out iptables/ip）。
    pub fn new(config: TransparentIngressConfig) -> Result<Arc<Self>> {
        let rules = plan_rules(&config);
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        Ok(Arc::new(Self {
            config,
            shutdown_tx,
            shutdown_rx,
            rules,
            exec: LinuxRouteTransaction::ip_step_executor(),
            face: None,
        }))
    }

    /// 入口退出通知（stop 路径调用；run 循环收到后 break → 规则撤销）。
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// 应用规则：逐步执行 apply argv；已存在（ip rule fwmark 重复 add →
    /// EEXIST/File exists）幂等成功；其余失败具名上抛（无 CAP_NET_ADMIN/
    /// iptables 缺席——入口 fail-fast，不静默降级）。
    fn apply_rules(&self) -> Result<()> {
        for rule in &self.rules {
            if let Err(e) = (self.exec)(&rule.apply) {
                if is_already_applied(&e) {
                    continue;
                }
                return Err(anyhow!(
                    "规则应用失败 [{}]：{e}（需 CAP_NET_ADMIN + iptables/ip 二进制）",
                    rule.label
                ));
            }
        }
        Ok(())
    }

    /// 逆序撤销规则：目标不存在（iptables "Bad rule"/ip "No such ..."）
    /// 视为已撤销——幂等（重入/重复撤销无操作）。
    fn undo_rules(&self) -> Result<()> {
        let mut failures = Vec::new();
        for rule in self.rules.iter().rev() {
            if let Err(e) = (self.exec)(&rule.undo) {
                if is_missing(&e) {
                    continue;
                }
                failures.push(format!("[{}]：{e}", rule.label));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("规则撤销失败：{}", failures.join("; ")))
        }
    }

    async fn run_loop(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let face: Arc<dyn TakeoverAccept> = match &self.face {
            Some(f) => f.clone(),
            None => self.build_face().await?,
        };
        // 本地克隆：changed(&mut self) 需要可变借——克隆一份循环内使用
        //（shutdown() 经原 tx 发送，克隆观察同一会话）
        let mut shutdown_rx = self.shutdown_rx.clone();
        tracing::info!(
            target: "rillane::transparent",
            mechanism = face.name(),
            bind = %self.config.listen,
            target = %self.config.target,
            rules = self.rules.len(),
            "透明接管入口启动"
        );
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    // 发送端断 = tx 已 drop（不应发生）；两种情形均退出循环
                    let _ = changed;
                    break;
                }
                accepted = face.accept() => {
                    match accepted {
                        Ok((io, dst)) => {
                            let this = self.clone();
                            let router = router.clone();
                            let output = output.clone();
                            tokio::spawn(async move {
                                if let Err(e) = this
                                    .handle_connection(io, dst, router, output)
                                    .await
                                {
                                    tracing::warn!(
                                        target: "rillane::transparent",
                                        original_dst = %dst,
                                        error = %e,
                                        "透明接管连接处理失败"
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            // 连接级拒绝（未接管直连无 conntrack NAT 记录等）
                            // ——warn + 继续（不崩溃入口）
                            tracing::warn!(
                                target: "rillane::transparent",
                                error = %e,
                                "透明接管连接拒绝（原目标恢复失败——未接管直连按连接拒绝）"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn build_face(&self) -> Result<Arc<dyn TakeoverAccept>> {
        match self.config.mode {
            TransparentMode::Redirect => {
                Ok(Arc::new(RedirectAccept::bind(self.config.listen).await?))
            }
            TransparentMode::Tproxy => Ok(Arc::new(TproxyAccept::bind(self.config.listen)?)),
        }
    }

    /// 单连接：原目标即 Flow.target；固定目标 tunnel——决策 = 配置 target
    ///（不经路由引擎重选，见模块头「固定目标契约」）。
    async fn handle_connection(
        self: Arc<Self>,
        io: BoxedIo,
        original_dst: SocketAddr,
        _router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let mut metadata = FlowMetadata {
            tags: vec![
                "ingress:transparent".into(),
                format!("mechanism:{}", self.config.mode_name()),
            ],
            ..Default::default()
        };
        metadata
            .annotations
            .insert("ingress.node".into(), "transparent".into());
        metadata
            .annotations
            .insert("transparent.original_dst".into(), original_dst.to_string());
        metadata
            .annotations
            .insert("transparent.target".into(), self.config.target.clone());

        let flow = Flow {
            id: FlowId::new(),
            target: FlowTarget {
                host: original_dst.ip().to_string(),
                port: original_dst.port(),
                proto: TargetProto::Tcp,
            },
            io,
            metadata,
        };
        let decision = RouteDecision::direct(self.config.target.clone());
        output
            .forward(decision, flow)
            .await
            .context("透明接管出口转发失败")?;
        Ok(())
    }
}

#[async_trait]
impl IngressEndpoint for TransparentIngress {
    fn name(&self) -> &'static str {
        "transparent"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        // 规则 = 系统副作用，入口属主：run 起始应用，退出撤销（幂等）。
        self.apply_rules().context("透明接管规则应用失败")?;
        tracing::info!(
            target: "rillane::transparent",
            rules = self.rules.len(),
            "透明接管规则已应用"
        );
        let me = self.clone();
        let result = me.run_loop(router, output).await;
        if let Err(e) = self.undo_rules() {
            tracing::warn!(
                target: "rillane::transparent",
                error = %e,
                "透明接管规则撤销失败（幂等——下次启动可重入）"
            );
        }
        result
    }
}

/// 按 mode 规划规则（redirect 排除逃逸 mark；tproxy 带 ip rule/route 面）。
fn plan_rules(config: &TransparentIngressConfig) -> Vec<TransparentRule> {
    match config.mode {
        TransparentMode::Redirect => transparent_face::plan_redirect_rules(
            config.listen,
            &config.intercept_ports,
            transparent_face::DEFAULT_ESCAPE_MARK,
        ),
        TransparentMode::Tproxy => transparent_face::plan_tproxy_rules(
            config.listen,
            &config.intercept_ports,
            config.rule_table,
        ),
    }
}

/// 应用幂等口径：已存在（ip rule fwmark 重复 add → EEXIST/"File exists"；
/// iptables -A 重复规则 → "Rule exists"）视为成功（与 RIL-029 同语义）。
fn is_already_applied(e: &io::Error) -> bool {
    let t = e.to_string();
    e.kind() == io::ErrorKind::AlreadyExists
        || t.contains("File exists")
        || t.contains("Rule exists")
}

/// 撤销幂等口径：目标不存在（iptables "Bad rule"/ip "No such ..."）视为
/// 已撤销（与 RIL-029 takeover is_missing 同语义，补 iptables 文本）。
fn is_missing(e: &io::Error) -> bool {
    let t = e.to_string();
    e.kind() == io::ErrorKind::NotFound
        || t.contains("No such")
        || t.contains("Bad rule")
        || t.contains("does a matching rule exist")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    /// 注入监听面：从通道喂 (io 端, 原目标)；accept 阻塞等待喂入（与真实
    /// 监听一致——不喂就挂起，不 panic）。
    struct FakeFace {
        rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(BoxedIo, SocketAddr)>>>,
        tx: tokio::sync::mpsc::UnboundedSender<(BoxedIo, SocketAddr)>,
    }

    impl FakeFace {
        fn new() -> Self {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            Self {
                rx: Arc::new(tokio::sync::Mutex::new(rx)),
                tx,
            }
        }
        fn push(&self, io: BoxedIo, dst: SocketAddr) {
            self.tx.send((io, dst)).ok();
        }
    }

    #[async_trait]
    impl TakeoverAccept for FakeFace {
        fn name(&self) -> &'static str {
            "fake"
        }

        async fn accept(&self) -> Result<(BoxedIo, SocketAddr)> {
            let mut rx = self.rx.lock().await;
            rx.recv().await.ok_or_else(|| anyhow!("fake 面通道关闭"))
        }
    }

    /// 记录输出：forward 收到 (决策节点, Flow.target)，经 oneshot 通知。
    struct RecordingOutput {
        done: Mutex<Option<oneshot::Sender<(String, FlowTarget)>>>,
    }

    #[async_trait]
    impl FlowOutput for RecordingOutput {
        async fn forward(
            &self,
            decision: RouteDecision,
            flow: Flow,
        ) -> Result<rillane_core::FlowReport> {
            let node = match &decision.path {
                rillane_core::RoutePath::Direct { node } => node.clone(),
                other => panic!("应为 Direct 决策：{other:?}"),
            };
            if let Some(tx) = self.done.lock().unwrap().take() {
                let _ = tx.send((node, flow.target.clone()));
            }
            Ok(rillane_core::FlowReport::default())
        }
    }

    /// 记录执行器：留档 argv（StepExecutor = Arc<dyn Fn>，经闭包注入）。
    struct RecordingExec {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl RecordingExec {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
        fn clear(&self) {
            self.calls.lock().unwrap().clear();
        }
        fn executor(&self) -> StepExecutor {
            let calls = self.calls.clone();
            Arc::new(move |argv: &[String]| {
                calls.lock().unwrap().push(argv.to_vec());
                Ok(())
            })
        }
    }

    /// 构造注入面 + 记录执行器的入口。
    fn make_ingress(
        config: TransparentIngressConfig,
    ) -> (Arc<TransparentIngress>, RecordingExec, Arc<FakeFace>) {
        let (tx, rx) = watch::channel(());
        let exec = RecordingExec::new();
        let face = Arc::new(FakeFace::new());
        let rules = plan_rules(&config);
        let t = Arc::new(TransparentIngress {
            config,
            shutdown_tx: tx,
            shutdown_rx: rx,
            rules,
            exec: exec.executor(),
            face: Some(face.clone()),
        });
        (t, exec, face)
    }

    fn cfg(listen: &str, mode: TransparentMode) -> TransparentIngressConfig {
        TransparentIngressConfig {
            listen: listen.parse().unwrap(),
            target: "tunnel-egress".to_string(),
            mode,
            intercept_ports: vec![443],
            rule_table: 100,
        }
    }

    /// 固定目标契约：注入面喂已知原目标 → 出口收到 Direct{target} 决策 +
    /// Flow.target = 原目标（不经路由引擎重选）。
    #[tokio::test]
    async fn pinned_decision_and_flow_target() {
        let (t, _exec, face) = make_ingress(cfg("0.0.0.0:12345", TransparentMode::Redirect));
        let (done_tx, done_rx) = oneshot::channel();
        let (client, server) = tokio::io::duplex(1024);
        let dst: SocketAddr = "192.0.2.10:8080".parse().unwrap();
        face.push(Box::new(server), dst);
        let output: Arc<dyn FlowOutput> = Arc::new(RecordingOutput {
            done: Mutex::new(Some(done_tx)),
        });
        let router: Arc<dyn FlowRouter> = Arc::new(NoopRouter);
        let me = t.clone();
        let serve = tokio::spawn(async move { me.run_loop(router, output).await });

        let (node, target) = tokio::time::timeout(std::time::Duration::from_secs(2), done_rx)
            .await
            .expect("超时：forward 未到")
            .expect("forward 通道断");
        assert_eq!(node, "tunnel-egress", "决策节点应固定为配置 target");
        assert_eq!(target.proto, TargetProto::Tcp);
        assert_eq!(target.port, 8080);
        assert_eq!(target.host, "192.0.2.10");

        // 验证 io 可读（duplex 对端仍可用）：客户端写 → ingress 读端回显经
        // forward 已消费——此处仅确认 run_loop 未崩（shutdown 后 join）
        t.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(2), serve)
            .await
            .expect("run_loop 应退出")
            .expect("run_loop 不应 panic")
            .expect("run_loop 应 Ok");
        let _ = client;
    }

    /// 规则应用/撤销：按 mode 生成 apply/undo argv；apply 全部执行、undo
    /// 逆序执行（撤销顺序与 apply 相反）。
    #[tokio::test]
    async fn rules_apply_and_undo_order() {
        let (t, exec, _face) = make_ingress(cfg("0.0.0.0:12345", TransparentMode::Redirect));
        t.apply_rules().expect("注入执行器应 Ok");
        let applies = exec.calls();
        assert_eq!(applies.len(), 2, "一端口 → PREROUTING + OUTPUT");
        assert_eq!(applies[0][0], "iptables");
        assert!(applies[0].contains(&"-A".to_string()));
        assert!(applies[0].contains(&"PREROUTING".to_string()));
        assert!(applies[0].contains(&"--to-ports".to_string()));
        assert!(applies[0].contains(&"12345".to_string()));

        exec.clear();
        t.undo_rules().expect("注入执行器应 Ok");
        let undos = exec.calls();
        assert_eq!(undos.len(), 2, "undo 逆序全执行");
        assert!(undos[0].contains(&"-D".to_string()));
        assert!(
            undos[0].contains(&"OUTPUT".to_string()),
            "undo 应逆序：先 OUTPUT"
        );
    }

    /// 规则应用幂等：EEXIST（ip rule fwmark 重复 add）视为成功，不中断。
    #[tokio::test]
    async fn rules_apply_treats_eexist_as_success() {
        let (t, exec, _face) = make_ingress(cfg("0.0.0.0:12345", TransparentMode::Redirect));
        // 注入执行器：第一条 Ok，后续 EEXIST
        let counter = Arc::new(Mutex::new(0usize));
        let c = counter.clone();
        let e: StepExecutor = Arc::new(move |argv: &[String]| {
            *c.lock().unwrap() += 1;
            let _ = argv;
            Err(io::Error::new(io::ErrorKind::AlreadyExists, "File exists"))
        });
        let t2 = Arc::new(TransparentIngress {
            config: cfg("0.0.0.0:12345", TransparentMode::Redirect),
            shutdown_tx: watch::channel(()).0,
            shutdown_rx: watch::channel(()).1,
            rules: plan_rules(&cfg("0.0.0.0:12345", TransparentMode::Redirect)),
            exec: e,
            face: Some(face_fake()),
        });
        t2.apply_rules().expect("EEXIST 应幂等成功");
        assert_eq!(*counter.lock().unwrap(), 2, "两条规则均执行");
        let _ = (t, exec);
    }

    fn face_fake() -> Arc<dyn TakeoverAccept> {
        Arc::new(FakeFace::new())
    }

    /// 规则撤销幂等：目标不存在（iptables "Bad rule"/ip "No such"）视为已撤销。
    #[tokio::test]
    async fn rules_undo_treats_missing_as_success() {
        let e: StepExecutor = Arc::new(|_argv: &[String]| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "iptables: Bad rule (does a matching rule exist in that chain?)",
            ))
        });
        let t = Arc::new(TransparentIngress {
            config: cfg("0.0.0.0:12345", TransparentMode::Redirect),
            shutdown_tx: watch::channel(()).0,
            shutdown_rx: watch::channel(()).1,
            rules: plan_rules(&cfg("0.0.0.0:12345", TransparentMode::Redirect)),
            exec: e,
            face: Some(face_fake()),
        });
        t.undo_rules().expect("目标不存在应视为已撤销");
    }

    /// 应用失败具名：非幂等错误（如无 CAP_NET_ADMIN）上抛并点名规则标签。
    #[tokio::test]
    async fn rules_apply_named_failure() {
        let e: StepExecutor = Arc::new(|_argv: &[String]| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Permission denied (you must be root)",
            ))
        });
        let t = Arc::new(TransparentIngress {
            config: cfg("0.0.0.0:12345", TransparentMode::Redirect),
            shutdown_tx: watch::channel(()).0,
            shutdown_rx: watch::channel(()).1,
            rules: plan_rules(&cfg("0.0.0.0:12345", TransparentMode::Redirect)),
            exec: e,
            face: Some(face_fake()),
        });
        let err = t.apply_rules().expect_err("无权限应上抛");
        let msg = err.to_string();
        assert!(
            msg.contains("redirect:prerouting:443"),
            "错误应点名规则: {msg}"
        );
        assert!(msg.contains("CAP_NET_ADMIN"), "错误应点名权限: {msg}");
    }

    /// 具名拒绝传播（platform 层 ENOENT → accept Err 载荷）：真实内核面
    /// 的 ENOENT（无 conntrack NAT 记录）在 platform 单测
    /// （network::transparent::unredirected_connection_is_named_refused）
    /// 钉住——loopback TCP 直连被 conntrack 跟踪，SO_ORIGINAL_DST 返回
    /// Ok（内核依赖，非稳定契约）；此处只验 RedirectAccept 的拒绝装载
    /// （注入层用 FakeFace，真内核接管连接归 #[ignore] 特权门）。
    #[test]
    fn redirect_accept_refusal_payload_carries_named_text() {
        // 平台 ENOENT 错误文本 → accept 包装后保留「未被接管」
        let inner = transparent_face::original_destination(
            &std::net::UdpSocket::bind("127.0.0.1:0").expect("建 socket"),
        )
        .expect_err("未接管应拒绝");
        let wrapped = anyhow!("原目标恢复失败（redirect：{inner}）");
        assert!(wrapped.to_string().contains("未被接管"));
    }

    /// 规则规划 shape（入口层）：redirect 一端口 → 2 条（PREROUTING+OUTPUT）；
    /// tproxy 一端口 → 3 条（mangle + ip rule + ip route）。
    #[test]
    fn plan_rules_by_mode() {
        let r = plan_rules(&cfg("0.0.0.0:12345", TransparentMode::Redirect));
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].label, "redirect:prerouting:443");
        let t = plan_rules(&cfg("0.0.0.0:12345", TransparentMode::Tproxy));
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].label, "tproxy:mangle:443");
        assert!(t[1].apply.contains(&"fwmark".to_string()));
    }

    /// 块映射：TransparentBlockConfig → TransparentIngressConfig（listen
    /// 解析、target 去空白）。
    #[test]
    fn config_from_block() {
        let block: TransparentBlockConfig = serde_yaml::from_str(
            r#"
mode: redirect
listen: "0.0.0.0:12345"
target: " tunnel-egress "
intercept_ports: [80, 443]
rule_table: 100
"#,
        )
        .expect("yaml 解析");
        block.validate().expect("块校验");
        let cfg = TransparentIngressConfig::from_block(&block).expect("映射");
        assert_eq!(cfg.listen, "0.0.0.0:12345".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.target, "tunnel-egress");
        assert_eq!(cfg.intercept_ports, vec![80, 443]);
        assert_eq!(cfg.rule_table, 100);
    }

    /// NoopRouter：run_loop 不调用 route（固定目标契约），仅在需要时占位。
    struct NoopRouter;

    #[async_trait]
    impl FlowRouter for NoopRouter {
        async fn route(&self, _ctx: rillane_core::FlowContext) -> Result<RouteDecision> {
            panic!("透明接管入口不应调用路由引擎（固定目标契约）");
        }
    }

    /// 特权验收门（#[ignore]——本席位 uid 1000 无 cap_net_admin、规则应用
    /// 必拒；具 CAP_NET_ADMIN + iptables 的机器上 `--ignored` 跑）：
    ///
    /// OUTPUT REDIRECT（真实 iptables）→ 本机客户端连「原目标」端口 →
    /// 内核改写到接管监听 → accept 恢复原目标 = 原目标端口（SO_ORIGINAL_DST
    /// 真路径）→ 撤销规则（幂等）。
    ///
    /// TPROXY 面的完整验收需转发流量（mangle PREROUTING 只捕经路由器的
    /// 入站——本机 OUTPUT 不经 PREROUTING），归路由器形态实测（两机 +
    /// ip_forward）；socket 前置（IP_TRANSPARENT）由 platform 单测
    /// （root 分支）+ `make_transparent_listener`（root 分支）覆盖。
    #[ignore = "需 CAP_NET_ADMIN + iptables（验收机器）；本席位无 cap_net_admin"]
    #[tokio::test]
    async fn privileged_redirect_gate_applies_recovers_and_undoes() {
        // 原目标 = 本机高端口（避开常用端口，防误接管其他流量）
        let orig_port: u16 = 39123;
        let listen_port: u16 = 39124;
        let rules = transparent_face::plan_redirect_rules(
            format!("127.0.0.1:{listen_port}").parse().unwrap(),
            &[orig_port],
            transparent_face::DEFAULT_ESCAPE_MARK,
        );
        // 只取 OUTPUT 对（PREROUTING 面为路由器形态，本机验收不需要；
        // 规划器逐端口顺序 = [PREROUTING, OUTPUT]，取 OUTPUT）
        let output_rules: Vec<_> = rules
            .into_iter()
            .filter(|r| r.label.contains("output"))
            .collect();
        assert_eq!(output_rules.len(), 1, "一端口一 OUTPUT 规则");

        let exec = LinuxRouteTransaction::ip_step_executor();
        for r in &output_rules {
            (exec)(&r.apply).unwrap_or_else(|e| panic!("应用失败 [{}]: {e}", r.label));
        }

        let face = RedirectAccept::bind(format!("127.0.0.1:{listen_port}").parse().unwrap())
            .await
            .expect("接管监听 bind");

        // 本机客户端连「原目标」→ OUTPUT REDIRECT → 接管监听
        let client = tokio::spawn(async move {
            tokio::net::TcpStream::connect(("127.0.0.1", orig_port))
                .await
                .expect("经 REDIRECT 的连接应到达接管监听")
        });
        let (_io, dst) = face
            .accept()
            .await
            .expect("accept 应恢复原目标（SO_ORIGINAL_DST 真路径）");
        client.await.expect("客户端任务");

        assert_eq!(
            dst,
            format!("127.0.0.1:{orig_port}")
                .parse::<SocketAddr>()
                .unwrap(),
            "恢复的原目标 = 原目标地址端口"
        );

        // 撤销（幂等——目标不存在视为已撤销）
        for r in output_rules.iter().rev() {
            if let Err(e) = (exec)(&r.undo) {
                panic!("撤销失败 [{}]: {e}", r.label);
            }
        }
    }
}
