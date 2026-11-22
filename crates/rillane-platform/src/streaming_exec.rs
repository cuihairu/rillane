//! 流媒体探测执行器（RIL-145 出口拨号 HTTP 探测执行器）：经「选定出口」
//! 发 HTTP GET 到服务检测端点、抽取证据、独立计量探测字节、并回报决策层
//! （[`rillane_core::streaming::StreamingProbeService::complete`]）。
//!
//! 与决策层（`rillane_core::streaming`）的分工：决策层是 OS-free 分类/缓存/
//! 配额面；本模块是 I/O 执行面。**拨号面是注入的**（[`StreamingProbeDial`]），
//! 使本执行器的 HTTP/1.1 机械与证据抽取在本席位确定性可测（注入假拨号，
//! 不触网、不需要平台权限）。
//!
//! 边界（诚实注记，与决策层模块注释同链）：
//! - **拨号语义归注入面**：`EgressConnector` 现状是纯流转发面（无「拨号
//!   并测」形态，RIL-059 证据已具名），且连接器对 `flow.target` 的语义
//!   各异（cloudflared 为固定 edge 忽略 target；tailcat 仅用 port；socks5/
//!   direct 用 host+port）。真实拨号面（经 `FlowOutput` 合成 duplex 流走
//!   既有 forward 路径）由运行时装配注入，本模块不假定连接器语义。
//! - **地区/阻断证据规则归机批次**：真服务（Netflix/Disney 等）的
//!   region 抽取与 block 文案规则按真响应钉；本模块提供
//!   [`DefaultEvidenceRules`]（region=None、block=[]——不虚构阻断证据），
//!   真实规则经 [`StreamingEvidenceRules`] 注入。
//! - 检测流量单计：探测字节在 [`StreamingProbeExecutor::probe`] 内独立
//!   累计，经决策层 `complete` 的 `probe_bytes_up/down` 入账，绝不并入
//!   业务计量。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use rillane_core::streaming::{ProbeEvidence, ProbeVerdict, StreamingProbeService};
use rillane_core::{
    BoxedIo, Flow, FlowId, FlowMetadata, FlowOutput, FlowTarget, RouteDecision, RoutePath,
    RouteType, TargetProto,
};

/// 拨号面：经「选定出口」拨到 HTTP 端点，返回可写 HTTP 的字节流。
///
/// 语义由实现方决定（连接器经 `FlowOutput`/`EgressConnector` 合成流，
/// 或本机直连）；本执行器只假定返回流已是「到检测端点的双向字节流」，
/// 直接在其上写 HTTP/1.1。
#[async_trait]
pub trait StreamingProbeDial: Send + Sync {
    /// 经 `exit`（已装配出口节点名）拨到 `host:port`。失败 = 传输层拨号
    /// 失败（执行器据此转下一检测端点或判 Failed）。
    async fn dial(&self, exit: &str, host: &str, port: u16) -> Result<BoxedIo, String>;
}

/// 地区/阻断证据抽取规则（按服务规则；真服务规则归机批次）。
pub trait StreamingEvidenceRules: Send + Sync {
    /// 从响应头部/正文抽 (region_hint, block_indicators)。调用方负责
    /// markers_hit 的结构性子串匹配（expect_markers 子集）。
    fn region_and_blocks(&self, headers: &str, body: &str) -> (Option<String>, Vec<String>);
}

/// 缺省规则：不虚构地区线索与阻断证据（region=None、block=[]）。
/// 真服务规则落地前，分类只能从 HTTP 状态与判据标记得出
/// （Available/Unknown/Failed/403|451→Restricted）。
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEvidenceRules;

impl StreamingEvidenceRules for DefaultEvidenceRules {
    fn region_and_blocks(&self, _headers: &str, _body: &str) -> (Option<String>, Vec<String>) {
        (None, Vec::new())
    }
}

/// 真实拨号面：经「已装配出口」的 [`FlowOutput`] 合成 duplex 流走既有
/// forward 路径（与 [`rillane_core::probe_via_output`] 同一先例），拨号
/// 返回 client 侧字节流——执行器直接在其上写 HTTP/1.1。
///
/// 出口表是**装配期快照**（`RuntimeBuilder::build` 在 `flow_outputs` 构建
/// 后克隆；与 url-test 探测处理器同口径，不挂 Arc/RwLock 热同步）。拨号
/// 成功 ≠ 出口连接成功：出口侧连接失败经 forward 任务丢 server 半显形为
/// 对端 EOF，执行器按「无响应字节 → 下一检测端点」处理（不虚构结论）。
pub struct OutputStreamingDial {
    /// exit 名（已装配出口节点名）→ 出口转发面
    outputs: HashMap<String, Arc<dyn FlowOutput>>,
}

impl OutputStreamingDial {
    /// 出口表快照（`HashMap<String, Arc<dyn FlowOutput>>`，键 = 出口节点名）
    pub fn new(outputs: HashMap<String, Arc<dyn FlowOutput>>) -> Self {
        Self { outputs }
    }
}

#[async_trait]
impl StreamingProbeDial for OutputStreamingDial {
    async fn dial(&self, exit: &str, host: &str, port: u16) -> Result<BoxedIo, String> {
        let output = self
            .outputs
            .get(exit)
            .cloned()
            .ok_or_else(|| format!("出口未装配：{exit}"))?;
        let (client, server) = tokio::io::duplex(16 * 1024);
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
                node: exit.to_string(),
            },
            reason: Some("streaming probe".to_string()),
            route_type: RouteType::Standard,
        };
        // 转发在独立任务：拨号即返，出口侧失败经 EOF 显形（执行器按
        // 无响应字节转下一端点/判 Failed，不阻塞拨号面）
        tokio::spawn(async move {
            let _ = output.forward(decision, flow).await;
        });
        Ok(Box::new(client))
    }
}

/// 流媒体探测执行器：submit → 逐检测端点拨号发 GET → 抽取证据 →
/// complete。检测流量独立计量。
pub struct StreamingProbeExecutor {
    service: Arc<Mutex<StreamingProbeService>>,
    dial: Arc<dyn StreamingProbeDial>,
    rules: Arc<dyn StreamingEvidenceRules>,
    /// 全程超时（拨号 + HTTP 往返）
    timeout: Duration,
    /// 响应体读取上限（超出即截断停止，按已读字节解析——防内存放大）
    max_body: usize,
}

impl StreamingProbeExecutor {
    pub fn new(
        service: Arc<Mutex<StreamingProbeService>>,
        dial: Arc<dyn StreamingProbeDial>,
        rules: Arc<dyn StreamingEvidenceRules>,
        timeout: Duration,
    ) -> Self {
        Self {
            service,
            dial,
            rules,
            timeout,
            max_body: 256 * 1024,
        }
    }

    /// 决策服务访问（控制面查询 status/running_jobs/probe_bytes 经此）。
    pub fn service(&self) -> &Mutex<StreamingProbeService> {
        &self.service
    }

    /// 执行一次 (service, exit) 探测：submit → 拨号发 GET → 抽取证据 →
    /// complete。返回分类结论。
    ///
    /// - 服务未登记 / 同 (service, exit) 在跑 / 配额满 → submit 具名拒绝；
    /// - 传输层全端点失败 → 以 `http_status=None` 证据 complete（→
    ///   [`ProbeVerdict::Failed`]，非取消）；
    /// - 超时 → 同样以 `http_status=None` complete（失败，不伪造结论）；
    /// - 服务无检测端点 → 取消并返回具名错误（配置缺陷，非探测结论）。
    pub async fn probe(&self, service: &str, exit: &str) -> Result<ProbeVerdict, String> {
        let job_id = self.service.lock().await.submit(service, exit)?;
        let check_urls = self.service.lock().await.check_urls(service);
        let expect_markers = self.service.lock().await.expect_markers(service);
        if check_urls.is_empty() {
            self.service.lock().await.cancel(job_id);
            return Err(format!("服务 {service} 无检测端点（check_urls 为空）"));
        }

        let outcome = tokio::time::timeout(
            self.timeout,
            self.run_probe(exit, &check_urls, &expect_markers),
        )
        .await;

        let (evidence, up, down) = match outcome {
            Err(_) => (
                ProbeEvidence {
                    http_status: None,
                    ..ProbeEvidence::default()
                },
                0,
                0,
            ),
            Ok(Ok(x)) => x,
            Ok(Err(e)) => {
                // 配置/内部错误：取消（不产 Failed 结论），显式上抛
                self.service.lock().await.cancel(job_id);
                return Err(e);
            }
        };
        self.service
            .lock()
            .await
            .complete(job_id, &evidence, up, down)
    }

    /// 取消在跑作业（验收「取消」；经决策层，取消不是失败）
    pub async fn cancel(&self, job_id: u64) -> bool {
        self.service.lock().await.cancel(job_id)
    }

    /// 逐端点探测：首个取得 HTTP 响应（状态行可解析）者为准；全部端点
    /// 传输层失败 → http_status=None（Failed）。探测字节全量累计。
    async fn run_probe(
        &self,
        exit: &str,
        check_urls: &[String],
        expect_markers: &[String],
    ) -> Result<(ProbeEvidence, u64, u64), String> {
        let mut up_total = 0u64;
        let mut down_total = 0u64;
        for url in check_urls {
            let (host, port, path) = parse_check_url(url)?;
            let mut stream = match self.dial.dial(exit, &host, port).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("流媒体探测拨号失败 {exit} → {host}:{port}: {e}");
                    continue;
                }
            };
            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rillane-streaming-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            );
            if let Err(e) = stream.write_all(req.as_bytes()).await {
                tracing::warn!("流媒体探测请求写入失败 {exit} → {url}: {e}");
                continue;
            }
            up_total += req.len() as u64;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        down_total += n as u64;
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() >= self.max_body {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("流媒体探测响应读取中断 {exit} → {url}: {e}");
                        break;
                    }
                }
            }
            if buf.is_empty() {
                // 无任何响应字节：传输层失败，转下一端点
                continue;
            }
            let (status, headers, body) = parse_http_response(&buf);
            let (region, blocks) = self.rules.region_and_blocks(&headers, &body);
            let markers_hit: Vec<String> = expect_markers
                .iter()
                .filter(|m| response_contains(&buf, m))
                .cloned()
                .collect();
            return Ok((
                ProbeEvidence {
                    http_status: status,
                    markers_hit,
                    region_hint: region,
                    block_indicators: blocks,
                },
                up_total,
                down_total,
            ));
        }
        // 全部端点传输层失败 → 连接/超时层失败证据（决策层判 Failed）
        Ok((
            ProbeEvidence {
                http_status: None,
                ..ProbeEvidence::default()
            },
            up_total,
            down_total,
        ))
    }
}

/// 检测端点解析：`http(s)://host[:port]/path` → (host, port, path)。
/// 缺省端口 https=443 / http=80；路径缺省 "/"。IPv6 主机须方括号
/// `[::1]:443`。仅 http/https。
fn parse_check_url(url: &str) -> Result<(String, u16, String), String> {
    let (rest, default_port) = match url.strip_prefix("https://") {
        Some(r) => (r, 443u16),
        None => match url.strip_prefix("http://") {
            Some(r) => (r, 80u16),
            None => return Err(format!("仅支持 http/https 检测端点：{url}")),
        },
    };
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 方括号
        match rest.find(']') {
            Some(end) => {
                let host = &rest[..end];
                let tail = &rest[end + 1..];
                let port = if let Some(p) = tail.strip_prefix(':') {
                    p.parse::<u16>().map_err(|_| format!("端口非法：{p}"))?
                } else {
                    default_port
                };
                (host, port)
            }
            None => return Err(format!("IPv6 主机方括号未闭合：{url}")),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port = p.parse::<u16>().map_err(|_| format!("端口非法：{p}"))?;
                (h, port)
            }
            _ => (host_port, default_port),
        }
    };
    if host.is_empty() {
        return Err(format!("检测端点主机为空：{url}"));
    }
    if path.is_empty() {
        return Err(format!("检测端点路径为空：{url}"));
    }
    Ok((host.to_string(), port, path.to_string()))
}

/// HTTP/1.1 响应解析：状态行 + 头部块 + 正文（按 `\r\n\r\n` 分界）。
/// 状态码不可解析（响应残缺）→ None（调用方按传输层失败处理）。
fn parse_http_response(buf: &[u8]) -> (Option<u16>, String, String) {
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match sep {
        Some(i) => (
            String::from_utf8_lossy(&buf[..i]).into_owned(),
            String::from_utf8_lossy(&buf[i + 4..]).into_owned(),
        ),
        None => (String::from_utf8_lossy(buf).into_owned(), String::new()),
    };
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    (status, head, body)
}

/// 判据标记命中：子串匹配（大小写不敏感）——决策层「expect_markers 的
/// 子集」口径，正文与头部一并检查（播放判据可落任一）。
fn response_contains(buf: &[u8], marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    let needle = marker.to_ascii_lowercase();
    let hay = buf.to_ascii_lowercase();
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_core::streaming::{StreamingService, StreamingStatus};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 脚本化假拨号：按出口+主机分派预置响应 / 挂起 / 错误
    struct FakeDial {
        /// exit → host:port → 脚本
        responses: std::collections::HashMap<(String, String), Scripted>,
        calls: std::sync::Mutex<Vec<(String, String, u16)>>,
    }

    enum Scripted {
        Respond(Vec<u8>),
        /// 拨号返回一个永不产出数据、永不 EOF 的流（read 阻塞至超时）
        Hang,
        Fail(String),
    }

    impl FakeDial {
        fn new() -> Self {
            Self {
                responses: std::collections::HashMap::new(),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn set(&mut self, exit: &str, host: &str, port: u16, script: Scripted) {
            self.responses
                .insert((exit.to_string(), format!("{host}:{port}")), script);
        }
        fn set_ok(&mut self, exit: &str, host: &str, port: u16, bytes: Vec<u8>) {
            self.set(exit, host, port, Scripted::Respond(bytes));
        }
        fn set_err(&mut self, exit: &str, host: &str, port: u16, e: &str) {
            self.set(exit, host, port, Scripted::Fail(e.to_string()));
        }
    }

    #[async_trait]
    impl StreamingProbeDial for FakeDial {
        async fn dial(&self, exit: &str, host: &str, port: u16) -> Result<BoxedIo, String> {
            self.calls
                .lock()
                .unwrap()
                .push((exit.to_string(), host.to_string(), port));
            let key = (exit.to_string(), format!("{host}:{port}"));
            match self.responses.get(&key) {
                Some(Scripted::Respond(bytes)) => {
                    let (a, b) = tokio::io::duplex(16 * 1024);
                    let bytes = bytes.clone();
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let mut b = b;
                        let _ = b.write_all(&bytes).await;
                        let _ = b.shutdown().await;
                    });
                    Ok(Box::new(a))
                }
                Some(Scripted::Hang) => {
                    let (a, b) = tokio::io::duplex(16 * 1024);
                    // 持有 b 不写不关：对端 read 阻塞至超时
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        drop(b);
                    });
                    Ok(Box::new(a))
                }
                Some(Scripted::Fail(e)) => Err(e.clone()),
                None => Err(format!("无预置响应：{exit} → {host}:{port}")),
            }
        }
    }

    /// 固定规则：region/block 按预置
    struct FixedRules {
        region: Option<String>,
        blocks: Vec<String>,
    }
    impl StreamingEvidenceRules for FixedRules {
        fn region_and_blocks(&self, _h: &str, _b: &str) -> (Option<String>, Vec<String>) {
            (self.region.clone(), self.blocks.clone())
        }
    }

    fn fixed_now(ms: u64) -> (Arc<dyn Fn() -> u64 + Send + Sync>, Arc<AtomicU64>) {
        let c = Arc::new(AtomicU64::new(ms));
        let c2 = c.clone();
        (Arc::new(move || c2.load(Ordering::SeqCst)), c)
    }

    fn service(name: &str, urls: &[&str], markers: &[&str]) -> StreamingService {
        StreamingService {
            name: name.to_string(),
            check_urls: urls.iter().map(|s| s.to_string()).collect(),
            expect_markers: markers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_executor(
        dial: Arc<dyn StreamingProbeDial>,
        rules: Arc<dyn StreamingEvidenceRules>,
    ) -> (
        Arc<StreamingProbeExecutor>,
        Arc<Mutex<StreamingProbeService>>,
    ) {
        let svc = Arc::new(Mutex::new(
            StreamingProbeService::new(
                vec![
                    service("svc-a", &["https://example.com/a"], &["playable", "ready"]),
                    service("svc-b", &["https://example.com/b"], &["ok-region"]),
                ],
                2,
                Duration::from_secs(3600),
            )
            .with_now(fixed_now(1_000_000).0),
        ));
        let exec = Arc::new(StreamingProbeExecutor::new(
            svc.clone(),
            dial,
            rules,
            Duration::from_secs(5),
        ));
        (exec, svc)
    }

    #[test]
    fn parses_check_url_shapes() {
        assert_eq!(
            parse_check_url("https://example.com/foo").unwrap(),
            ("example.com".to_string(), 443, "/foo".to_string())
        );
        assert_eq!(
            parse_check_url("http://example.com:8080").unwrap(),
            ("example.com".to_string(), 8080, "/".to_string())
        );
        assert_eq!(
            parse_check_url("https://[2001:db8::1]:8443/x").unwrap(),
            ("2001:db8::1".to_string(), 8443, "/x".to_string())
        );
        assert!(parse_check_url("ftp://x/y").is_err(), "非 http/https 拒绝");
        assert!(parse_check_url("https:///path").is_err(), "空主机拒绝");
    }

    #[test]
    fn parses_http_response_status_and_split() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello playable";
        let (status, head, body) = parse_http_response(buf);
        assert_eq!(status, Some(200));
        assert!(head.contains("Content-Type"));
        assert_eq!(body, "hello playable");
        // 残缺：无状态行 → None
        let (status2, _, _) = parse_http_response(b"garbage");
        assert_eq!(status2, None);
    }

    #[test]
    fn marker_match_is_case_insensitive_substring() {
        assert!(response_contains(b"<p>PLAYABLE</p>", "playable"));
        assert!(!response_contains(b"<p>blocked</p>", "playable"));
        assert!(!response_contains(b"anything", ""));
    }

    /// 可用路径：200 + 判据标记命中 + 无阻断 → Available{region}
    #[tokio::test]
    async fn probe_available_with_marker_and_region() {
        let mut dial = FakeDial::new();
        dial.set_ok(
            "edge-1",
            "example.com",
            443,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>playable</html>".to_vec(),
        );
        let (exec, _svc) = make_executor(
            Arc::new(dial),
            Arc::new(FixedRules {
                region: Some("us".into()),
                blocks: vec![],
            }),
        );
        let verdict = exec.probe("svc-a", "edge-1").await.expect("探测应可用");
        assert_eq!(
            verdict,
            ProbeVerdict::Available {
                region: Some("us".into())
            }
        );
        // 字节独立入账
        let bytes = exec.service().lock().await.probe_bytes("svc-a", "edge-1");
        assert!(bytes.is_some(), "探测字节应入账");
        let (up, down) = bytes.unwrap();
        assert!(up > 0, "请求字节应计入 {up}");
        assert!(down > 0, "响应字节应计入 {down}");
    }

    /// HTTP 200 不等于播放：200 无判据无阻断 → Unknown
    #[tokio::test]
    async fn probe_bare_200_is_unknown_not_available() {
        let mut dial = FakeDial::new();
        dial.set_ok(
            "edge-1",
            "example.com",
            443,
            b"HTTP/1.1 200 OK\r\n\r\n<html>no marker</html>".to_vec(),
        );
        let (exec, _svc) = make_executor(Arc::new(dial), Arc::new(DefaultEvidenceRules));
        let verdict = exec.probe("svc-a", "edge-1").await.expect("探测应完成");
        assert_eq!(verdict, ProbeVerdict::Unknown, "裸 200 不得判可用");
    }

    /// 403 无判据 → Restricted（决策层状态面）
    #[tokio::test]
    async fn probe_403_is_restricted() {
        let mut dial = FakeDial::new();
        dial.set_ok(
            "edge-1",
            "example.com",
            443,
            b"HTTP/1.1 403 Forbidden\r\n\r\naccess denied".to_vec(),
        );
        let (exec, _svc) = make_executor(Arc::new(dial), Arc::new(DefaultEvidenceRules));
        let verdict = exec.probe("svc-a", "edge-1").await.expect("探测应完成");
        assert_eq!(
            verdict,
            ProbeVerdict::Restricted {
                reason: "http_403".into()
            }
        );
    }

    /// 全部端点传输层失败 → Failed（非取消、非受限）
    #[tokio::test]
    async fn probe_transport_failure_is_failed_not_restricted() {
        let mut dial = FakeDial::new();
        dial.set_err("edge-1", "example.com", 443, "拨号被拒");
        let (exec, _svc) = make_executor(Arc::new(dial), Arc::new(DefaultEvidenceRules));
        let verdict = exec.probe("svc-a", "edge-1").await.expect("应判 Failed");
        assert_eq!(
            verdict,
            ProbeVerdict::Failed {
                code: "streaming.exec.no_response".into()
            }
        );
    }

    /// 超时（拨号返回挂起流，read 阻塞）→ Failed（timeout 覆盖全程；
    /// 失败结论，非取消）。用短超时避免拖慢套件。
    #[tokio::test]
    async fn probe_timeout_is_failed() {
        let svc = Arc::new(Mutex::new(
            StreamingProbeService::new(
                vec![service("svc-a", &["https://example.com/a"], &["playable"])],
                2,
                Duration::from_secs(3600),
            )
            .with_now(fixed_now(1_000_000).0),
        ));
        let mut dial = FakeDial::new();
        dial.set("edge-1", "example.com", 443, Scripted::Hang);
        let exec = Arc::new(StreamingProbeExecutor::new(
            svc.clone(),
            Arc::new(dial),
            Arc::new(DefaultEvidenceRules),
            Duration::from_millis(200),
        ));
        let verdict = exec.probe("svc-a", "edge-1").await.expect("应判 Failed");
        assert_eq!(
            verdict,
            ProbeVerdict::Failed {
                code: "streaming.exec.no_response".into()
            }
        );
    }

    /// 取消：显式取消在跑作业（经决策层 cancel，不产 Failed 结论）
    #[tokio::test]
    async fn cancel_running_job_keeps_untested() {
        let (exec, _svc) = make_executor(Arc::new(FakeDial::new()), Arc::new(DefaultEvidenceRules));
        let job_id = exec
            .service()
            .lock()
            .await
            .submit("svc-a", "edge-1")
            .unwrap();
        assert!(exec.cancel(job_id).await, "在跑作业应取消成功");
        assert!(!exec.cancel(job_id).await, "重复取消显式 false");
        let st = exec.service().lock().await.status("svc-a", "edge-1");
        assert_eq!(st, StreamingStatus::Untested, "取消不产结论");
    }

    /// submit 拒绝面：未知服务 / 重复在跑 / 配额
    #[tokio::test]
    async fn submit_refusals_named() {
        let (exec, _svc) = make_executor(Arc::new(FakeDial::new()), Arc::new(DefaultEvidenceRules));
        let mut svc = exec.service().lock().await;
        assert!(svc.submit("nope", "edge-1").is_err(), "未知服务拒绝");
        svc.submit("svc-a", "edge-1").unwrap();
        assert!(svc.submit("svc-a", "edge-1").is_err(), "同对在跑拒绝");
        // 配额 = 2：第二对不同服务可跑，第三对超配额
        svc.submit("svc-b", "edge-2").unwrap();
        assert!(svc.submit("svc-a", "edge-2").is_err(), "配额满拒绝");
    }

    /// 多端点回退：首端点传输失败 → 第二端点有响应 → 以其判
    #[tokio::test]
    async fn probe_falls_back_to_next_check_url() {
        // svc-b 只有一个 URL；构造多 URL 服务
        let svc = Arc::new(Mutex::new(
            StreamingProbeService::new(
                vec![service(
                    "multi",
                    &["https://a.example/f", "https://b.example/g"],
                    &["playable"],
                )],
                2,
                Duration::from_secs(3600),
            )
            .with_now(fixed_now(1_000_000).0),
        ));
        let mut dial = FakeDial::new();
        dial.set_err("edge-1", "a.example", 443, "首端点拒");
        dial.set_ok(
            "edge-1",
            "b.example",
            443,
            b"HTTP/1.1 200 OK\r\n\r\nplayable".to_vec(),
        );
        let exec = Arc::new(StreamingProbeExecutor::new(
            svc.clone(),
            Arc::new(dial),
            Arc::new(DefaultEvidenceRules),
            Duration::from_secs(5),
        ));
        let verdict = exec.probe("multi", "edge-1").await.expect("回退后应可用");
        assert_eq!(verdict, ProbeVerdict::Available { region: None });
    }
}
