//! XTLS Vision（xtls-rprx-vision）分帧状态机（RIL-108 自写）。
//!
//! 语义以 Xray-core 源码为准（2026-11-16 浅克隆精读，见
//! docs/protocol-backends.md#vless-xtls-vision）：`proxy/proxy.go`
//! TrafficState/VisionReader/VisionWriter/XtlsFilterTls/XtlsPadding/
//! XtlsUnpadding、`proxy/vless/encoding/{encoding,addons}.go`、
//! `proxy/vless/outbound/outbound.go`。要点：
//!
//! - 请求 addons 以 protobuf `Addons{Flow=1}` 携带 flow 串
//!   （`0x0A 0x10 "xtls-rprx-vision"`，OptLen=18）。
//! - 填充帧：每方向首帧前置一次 16 字节用户 UUID，随后
//!   `[command(1) contentLen(2 BE) paddingLen(2 BE)] + content + padding`。
//! - 命令：Continue=0x00 / End=0x01 / Direct=0x02。End 后流量留在外层
//!   TLS 之内；Direct 后双侧停帧，切换到外层 TLS 之下的裸 TCP。
//! - 填充预算（testseed 缺省 `[900, 500, 900, 256]`）：content < 900 且
//!   长填充 → `rand(0..500) + 900 - content`，否则 `rand(0..256)`；
//!   上限 `2048 - 21 - content`。
//! - 内层 TLS 嗅探（XtlsFilterTls）：过滤窗 8 包；ServerHello 携带
//!   TLS1.3 supported_versions 扩展（`00 2b 00 02 03 04`）置位
//!   EnableXtls；首个完整内层 ApplicationData 记录发出 Direct。
//!   非 TLS / TLS1.2 内层流量以 End 收束，全程留在外层 TLS 之内。

use anyhow::Result;
use rand::Rng;

/// Vision 流控名（xray `vless.XRV`）
pub const FLOW_VISION: &str = "xtls-rprx-vision";
/// 填充命令：后续还有帧（xray CommandPaddingContinue）
pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
/// 填充命令：填充收束，流量留在外层 TLS 之内（xray CommandPaddingEnd）
pub const COMMAND_PADDING_END: u8 = 0x01;
/// 填充命令：双侧停帧，切换裸 TCP 直传（xray CommandPaddingDirect）
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// 填充预算缺省种子（xray NewVisionWriter testseed 缺省）
pub const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];

const FRAME_HEAD: usize = 5;
const UUID_LEN: usize = 16;
/// 首帧 UUID 门控最小长度（xray XtlsUnpadding：`b.Len() >= 21`）
const GATE_MIN: usize = UUID_LEN + FRAME_HEAD;
/// xray buf.Size（单帧上限基数）
const CHUNK_CAP: usize = 2048;
/// 内层 TLS 过滤窗（xray NewTrafficState NumberOfPacketToFilter）
const PACKETS_TO_FILTER: i32 = 8;
/// 首载荷前的伪装填充帧时限（xray ReadMultiBufferTimeout 500ms）
pub const MARKER_AFTER: std::time::Duration = std::time::Duration::from_millis(500);

const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

// ---------------------------------------------------------------------------
// 请求 addons：flow 字段的 protobuf 面（xray EncodeHeaderAddons）
// ---------------------------------------------------------------------------

/// VLESS 请求 addons 字节（Opt 段）：flow=None/空 → OptLen=0（空段）；
/// Vision → protobuf `Addons{Flow=1}`（tag 0x0A + len + 串）；其余取值
/// 点名拒绝（不走静默降级——服务端按名期望分帧）。
pub fn vision_flow_addons(flow: Option<&str>) -> Result<Vec<u8>> {
    let Some(f) = flow.filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    if f != FLOW_VISION {
        return Err(anyhow::anyhow!(
            "VLESS flow {f} 未实现（仅支持 {FLOW_VISION}，RIL-108）；拒绝静默降级为普通 VLESS——服务端期望的分帧与实际不符，连接将失败且无报错"
        ));
    }
    let flow_bytes = f.as_bytes();
    let mut out = Vec::with_capacity(2 + flow_bytes.len());
    out.push(0x0a); // protobuf field 1（Flow），wire type 2（length-delimited）
    out.push(flow_bytes.len() as u8);
    out.extend_from_slice(flow_bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// 填充帧构建（xray XtlsPadding）
// ---------------------------------------------------------------------------

/// 单帧填充长度（xray XtlsPadding 预算）：content < seed[0] 且长填充 →
/// `rand(0..seed[1]) + seed[2] - content`，否则 `rand(0..seed[3])`；
/// 上限 `2048 - 21 - content`（ReshapeMultiBuffer 保证 content 不越限）。
pub fn padding_len(content_len: usize, long_padding: bool, seed: &[u32; 4]) -> usize {
    let mut rng = rand::rngs::OsRng;
    let raw: i64 = if (content_len as u64) < seed[0] as u64 && long_padding {
        let l: i64 = if seed[1] > 0 {
            rng.gen_range(0..seed[1]) as i64
        } else {
            0
        };
        l + seed[2] as i64 - content_len as i64
    } else if seed[3] > 0 {
        rng.gen_range(0..seed[3]) as i64
    } else {
        0
    };
    let cap = CHUNK_CAP.saturating_sub(21 + content_len);
    (raw.max(0) as usize).min(cap)
}

/// 填充帧构建器：持有每方向一次性的 UUID 前置（xray writeOnceUserUUID）
#[derive(Debug)]
pub struct FrameBuilder {
    uuid_once: Option<[u8; UUID_LEN]>,
}

impl FrameBuilder {
    pub fn new(uuid: [u8; UUID_LEN]) -> Self {
        Self {
            uuid_once: Some(uuid),
        }
    }

    /// 构建一帧：`[UUID(首帧一次)] + [command, contentLen(2), paddingLen(2)]
    /// + content + padding`（xray XtlsPadding 序；padding 零填充，同
    /// `buf.Extend` 口径）。
    pub fn frame(&mut self, command: u8, content: &[u8], long_padding: bool) -> Vec<u8> {
        let plen = padding_len(content.len(), long_padding, &DEFAULT_TESTSEED);
        let mut out = Vec::with_capacity(21 + content.len() + plen);
        if let Some(uuid) = self.uuid_once.take() {
            out.extend_from_slice(&uuid);
        }
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(plen as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + plen, 0);
        out
    }
}

// ---------------------------------------------------------------------------
// 填充帧解析（xray XtlsUnpadding）
// ---------------------------------------------------------------------------

/// 读面指令：Continue 继续逐帧；End 后流量留在外层 TLS 之内（Plain）；
/// Direct 后切换裸 TCP（剩余字节即裸流量）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionSignal {
    Frames,
    Plain,
    Direct,
}

/// 增量填充帧解析器（下行读面；xray XtlsUnpadding 状态机）。
/// 首块 UUID 门控：首段 ≥21B 且前缀匹配 → 进帧解析；否则整段按裸流量
/// 放行（xray 同口径：门控失败即 plain 直通）。
#[derive(Debug)]
pub struct FrameDecoder {
    uuid: [u8; UUID_LEN],
    stage: ReadStage,
    head: [u8; FRAME_HEAD],
    head_n: usize,
    content_need: usize,
    padding_need: usize,
    content: Vec<u8>,
    direct: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStage {
    UuidGate,
    Head,
    Content,
    Padding,
    Done,
}

impl FrameDecoder {
    pub fn new(uuid: [u8; UUID_LEN]) -> Self {
        Self {
            uuid,
            stage: ReadStage::UuidGate,
            head: [0u8; FRAME_HEAD],
            head_n: 0,
            content_need: 0,
            padding_need: 0,
            content: Vec::new(),
            direct: false,
        }
    }

    pub fn direct(&self) -> bool {
        self.direct
    }

    /// 取走已解码内容（Continue 链的 content 段 + Done 后的裸流量）
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.content)
    }

    /// 推入一段外层 TLS 解密后的字节；信号在帧边界推进时更新。
    pub fn push(&mut self, chunk: &[u8]) -> VisionSignal {
        let mut cursor = 0usize;
        match self.stage {
            ReadStage::Done => {
                self.content.extend_from_slice(chunk);
                return if self.direct {
                    VisionSignal::Direct
                } else {
                    VisionSignal::Plain
                };
            }
            ReadStage::UuidGate => {
                if chunk.len() < GATE_MIN {
                    // xray 口径：首段不足 21B 或前缀不符 → 整段裸流量放行
                    self.content.extend_from_slice(chunk);
                    self.stage = ReadStage::Done;
                    return VisionSignal::Plain;
                }
                if chunk[..UUID_LEN] != self.uuid {
                    self.content.extend_from_slice(chunk);
                    self.stage = ReadStage::Done;
                    return VisionSignal::Plain;
                }
                cursor = UUID_LEN;
                self.stage = ReadStage::Head;
            }
            _ => {}
        }

        // 恰在块边界收束的零填充帧也要推进（Padding 无需字节即可完成），
        // 否则 Direct 信号延拍到下一推入（验收面暴露的边界缺陷）
        while cursor < chunk.len() || (self.stage == ReadStage::Padding && self.padding_need == 0) {
            match self.stage {
                ReadStage::Head => {
                    let want = FRAME_HEAD - self.head_n;
                    let take = want.min(chunk.len() - cursor);
                    self.head[self.head_n..self.head_n + take]
                        .copy_from_slice(&chunk[cursor..cursor + take]);
                    self.head_n += take;
                    cursor += take;
                    if self.head_n == FRAME_HEAD {
                        let [_, ch, cl, ph, pl] = self.head;
                        self.content_need = u16::from_be_bytes([ch, cl]) as usize;
                        self.padding_need = u16::from_be_bytes([ph, pl]) as usize;
                        self.stage = if self.content_need > 0 {
                            ReadStage::Content
                        } else {
                            ReadStage::Padding
                        };
                        self.head_n = 0;
                    }
                }
                ReadStage::Content => {
                    let take = self.content_need.min(chunk.len() - cursor);
                    self.content
                        .extend_from_slice(&chunk[cursor..cursor + take]);
                    self.content_need -= take;
                    cursor += take;
                    if self.content_need == 0 {
                        self.stage = ReadStage::Padding;
                    }
                }
                ReadStage::Padding => {
                    let take = self.padding_need.min(chunk.len() - cursor);
                    self.padding_need -= take;
                    cursor += take;
                    if self.padding_need == 0 {
                        // 帧收束：Continue → 下一帧头；End/Direct → 收束
                        match self.head[0] {
                            COMMAND_PADDING_CONTINUE => self.stage = ReadStage::Head,
                            cmd => {
                                self.stage = ReadStage::Done;
                                self.direct = cmd == COMMAND_PADDING_DIRECT;
                                // 剩余字节即裸流量（xray：`newbuffer.Write(b.Bytes())`）
                                self.content.extend_from_slice(&chunk[cursor..]);
                                cursor = chunk.len();
                            }
                        }
                    }
                }
                ReadStage::UuidGate | ReadStage::Done => unreachable!("stage 已前置处理"),
            }
        }

        if self.stage == ReadStage::Done {
            if self.direct {
                VisionSignal::Direct
            } else {
                VisionSignal::Plain
            }
        } else {
            VisionSignal::Frames
        }
    }
}

// ---------------------------------------------------------------------------
// 内层 TLS 嗅探（xray XtlsFilterTls）与完整记录判定（IsCompleteRecord）
// ---------------------------------------------------------------------------

/// 内层 TLS 状态过滤窗（xray XtlsFilterTls 子集：EnableXtls 判定所需面）。
/// ServerHello → TLS1.2+；SH 内含 TLS1.3 supported_versions 扩展 →
/// EnableXtls（CCM_8 套件例外在 xray 依赖套件表——本实现按 supported
/// versions 扩展即置位，xray 对非 CCM_8 全部置位，等价面）。
#[derive(Debug, Default)]
pub struct InnerTlsFilter {
    remaining_packets: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    remaining_server_hello: i64,
    enable_xtls: bool,
}

impl InnerTlsFilter {
    pub fn new() -> Self {
        Self {
            remaining_packets: PACKETS_TO_FILTER,
            ..Default::default()
        }
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    pub fn enable_xtls(&self) -> bool {
        self.enable_xtls
    }

    /// 过滤窗耗尽（xray `NumberOfPacketToFilter <= 1` 收束面）
    pub fn exhausted(&self) -> bool {
        self.remaining_packets <= 1
    }

    /// 观察一段上行应用流量（xray 每包递减过滤窗）
    pub fn observe(&mut self, packet: &[u8]) {
        if self.remaining_packets <= 0 {
            return;
        }
        self.remaining_packets -= 1;
        if packet.len() >= 6 {
            let s = &packet[..6];
            if s[0] == 0x16 && s[1] == 0x03 && s[5] == 0x02 {
                // ServerHello：TLS1.2+，跟踪 SH 总长扫 TLS1.3 扩展
                self.is_tls = true;
                self.is_tls12_or_above = true;
                self.remaining_server_hello = ((s[3] as i64) << 8 | s[4] as i64) + 5;
            } else if s[0] == 0x16 && s[1] == 0x03 && s[5] == 0x01 {
                // ClientHello：内层确为 TLS
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(packet.len());
            let tls13 = packet[..end]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|w| w == TLS13_SUPPORTED_VERSIONS);
            self.remaining_server_hello -= packet.len() as i64;
            if tls13 {
                self.enable_xtls = true;
                self.remaining_packets = 0;
                self.remaining_server_hello = 0;
            } else if self.remaining_server_hello <= 0 {
                // TLS1.2：EnableXtls 不置位（Direct 不启用）
                self.remaining_packets = 0;
            }
        }
    }
}

/// 是否为完整的内层 TLS 记录序列（xray IsCompleteRecord：`17 03 03` 起，
/// 逐记录长度自洽恰好耗尽）
pub fn is_complete_tls_record(bytes: &[u8]) -> bool {
    const HEADER: usize = 5;
    let mut i = 0usize;
    let mut header_left = HEADER;
    let mut record_len = 0usize;
    while i < bytes.len() {
        if header_left > 0 {
            let b = bytes[i];
            i += 1;
            match header_left {
                5 => {
                    if b != 0x17 {
                        return false;
                    }
                }
                4 | 3 => {
                    if b != 0x03 {
                        return false;
                    }
                }
                2 => record_len = (b as usize) << 8,
                1 => record_len |= b as usize,
                _ => unreachable!(),
            }
            header_left -= 1;
        } else if record_len > 0 {
            let remaining = bytes.len() - i;
            if remaining < record_len {
                return false;
            }
            i += record_len;
            record_len = 0;
            header_left = HEADER;
        } else {
            return false;
        }
    }
    header_left == HEADER && record_len == 0 && !bytes.is_empty()
}

// ---------------------------------------------------------------------------
// 上行写策略（xray VisionWriter::WriteMultiBuffer 决策面）
// ---------------------------------------------------------------------------

/// 上行一次写入的动作
#[derive(Debug)]
pub enum VisionWriteAction {
    /// 经外层 TLS 写出该填充帧
    PaddedFrame(Vec<u8>),
    /// 填充已收束：字节原样经外层 TLS 写（End 面）
    PlainTls(Vec<u8>),
    /// Direct 已切换：字节经裸 TCP 直写
    Raw(Vec<u8>),
}

/// 上行写策略：过滤窗嗅探 + 帧决策（xray VisionWriter 同构）。
#[derive(Debug)]
pub struct VisionWritePolicy {
    filter: InnerTlsFilter,
    padding_active: bool,
    direct_switched: bool,
    builder: FrameBuilder,
    marker_sent: bool,
}

impl VisionWritePolicy {
    pub fn new(uuid: [u8; UUID_LEN]) -> Self {
        Self {
            filter: InnerTlsFilter::new(),
            padding_active: true,
            direct_switched: false,
            builder: FrameBuilder::new(uuid),
            marker_sent: false,
        }
    }

    /// 是否已发出 Direct（切换裸 TCP 直传）
    pub fn direct_switched(&self) -> bool {
        self.direct_switched
    }

    pub fn marker_sent(&self) -> bool {
        self.marker_sent
    }

    pub fn padding_active(&self) -> bool {
        self.padding_active
    }

    /// 首载荷前的伪装填充帧（xray `MultiBuffer{nil}`：空内容 Continue
    /// 长填充，藏 VLESS 头时序）；只发一次。
    pub fn on_marker(&mut self) -> Option<VisionWriteAction> {
        if !self.padding_active || self.marker_sent {
            return None;
        }
        self.marker_sent = true;
        // xray：空内容帧恒用长填充
        Some(VisionWriteAction::PaddedFrame(self.builder.frame(
            COMMAND_PADDING_CONTINUE,
            &[],
            true,
        )))
    }

    /// 上行一段应用流量 → 决策（xray WriteMultiBuffer 主路径）
    pub fn on_payload(&mut self, chunk: &[u8]) -> VisionWriteAction {
        if !self.padding_active {
            // End 面：留在外层 TLS 之内；Direct 面：裸 TCP 直写
            return if self.direct_switched {
                VisionWriteAction::Raw(chunk.to_vec())
            } else {
                VisionWriteAction::PlainTls(chunk.to_vec())
            };
        }
        // xray：过滤先于填充决策（XtlsFilterTls 在 isPadding 块之前）
        self.filter.observe(chunk);
        if self.filter.is_tls()
            && chunk.len() >= 6
            && chunk[..3] == TLS_APPLICATION_DATA_START
            && is_complete_tls_record(chunk)
        {
            // 内层 ApplicationData 完整记录：TLS1.3 → Direct（切换裸传）；
            // TLS1.2 → End（留在外层 TLS 之内）。xray 同口径。
            self.padding_active = false;
            let command = if self.filter.enable_xtls() {
                self.direct_switched = true;
                COMMAND_PADDING_DIRECT
            } else {
                COMMAND_PADDING_END
            };
            // xray：该帧 longPadding=false
            return VisionWriteAction::PaddedFrame(self.builder.frame(command, chunk, false));
        }
        if !self.filter.is_tls12_or_above() && self.filter.exhausted() {
            // 内层非 TLS：过滤窗将尽，提前一包收束（xray 兼容面）
            self.padding_active = false;
            let long = self.filter.is_tls();
            return VisionWriteAction::PaddedFrame(self.builder.frame(
                COMMAND_PADDING_END,
                chunk,
                long,
            ));
        }
        let long = self.filter.is_tls();
        VisionWriteAction::PaddedFrame(self.builder.frame(COMMAND_PADDING_CONTINUE, chunk, long))
    }
}

// ---------------------------------------------------------------------------
// Vision TLS 面：逐记录精确喂入的 rustls 客户端连接（direct 直传无损切换
// 的关键——裸流量绝不会误入 rustls 内部缓冲）
// ---------------------------------------------------------------------------

use std::future::Future as _;
use std::io;
use std::io::{BufRead as _, Write as _};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::outbound::reality::SyncWriteAdapter;

/// 记录头长度（type 1 + version 2 + length 2）
const RECORD_HEAD: usize = 5;
/// TLS 记录体上限（2^14 + 加密膨胀 2048）
const RECORD_BODY_CAP: usize = (1 << 14) + 2048;

/// 逐记录精确喂入的 rustls 客户端连接面。
///
/// 与 TlsAdapter（rustls 自驱读循环）不同：本面自己从裸 TCP 拆出完整
/// TLS 记录再喂 `read_tls`——rustls 永远只见到记录边界内的字节，
/// Direct 切换时把 TCP socket 原样交出，零字节损失（xray 以
/// AccessTLSBuffers 排干 Go TLS 内部缓冲解决同一问题；rustls 无此
/// 排出面，精确喂入是等价的正解）。
pub struct VisionTlsFace {
    tcp: TcpStream,
    conn: rustls::ClientConnection,
    /// 已从 TCP 读入、尚未构成完整记录的字节（记录边界保持面）
    feed: Vec<u8>,
    /// 0 = 收记录头；否则为该记录总长（头 + 体）
    feed_body: usize,
    eof: bool,
}

impl VisionTlsFace {
    pub fn new(tcp: TcpStream, conn: rustls::ClientConnection) -> Self {
        Self {
            tcp,
            conn,
            feed: Vec::new(),
            feed_body: 0,
            eof: false,
        }
    }

    /// 协商版本（外层 TLS 须 TLS1.3 方可用 Vision——xray 同口径）
    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        self.conn.protocol_version()
    }

    /// 从裸 TCP 精确拆一条记录喂入 rustls；返回喂入字节数（0 = EOF）
    fn poll_feed_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        loop {
            let need = if self.feed_body == 0 {
                RECORD_HEAD
            } else {
                self.feed_body
            };
            if self.feed.len() >= need {
                if self.feed_body == 0 {
                    let rec_type = self.feed[0];
                    let body = u16::from_be_bytes([self.feed[3], self.feed[4]]) as usize;
                    if !matches!(rec_type, 20..=23) || body > RECORD_BODY_CAP {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Vision 外层 TLS 记录头非法",
                        )));
                    }
                    self.feed_body = RECORD_HEAD + body;
                    continue;
                }
                let frame = self.feed.drain(..need).collect::<Vec<u8>>();
                self.feed_body = 0;
                let n = self
                    .conn
                    .read_tls(&mut &frame[..])
                    .map_err(io::Error::other)?;
                self.conn.process_new_packets().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Vision 外层记录处理失败: {e}"),
                    )
                })?;
                return Poll::Ready(Ok(n));
            }
            if self.eof {
                return Poll::Ready(Ok(0));
            }
            // TCP 补给（只要不满一条记录就继续读）
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                self.eof = true;
                return Poll::Ready(Ok(0));
            }
            self.feed.extend_from_slice(rb.filled());
        }
    }

    /// 已解密明文是否可读（借用不跨语句：`into_first_chunk` 的切片
    /// 借用 conn，持有时不得再触碰连接面）
    fn has_plaintext(&mut self) -> bool {
        matches!(
            self.conn.reader().into_first_chunk(),
            Ok(data) if !data.is_empty()
        )
    }

    fn poll_fill_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        // 已解密明文优先返回（逐记录喂入边界保持面）：喂完一条记录即停
        // ——Direct 切换后 TCP 后续字节是裸流量，超前喂入会把它误判为
        // 外层 TLS 记录（xray 以排干内部缓冲解决同一问题）
        if self.has_plaintext() {
            return match self.conn.reader().into_first_chunk() {
                Ok(data) => Poll::Ready(Ok(data)),
                Err(e) => Poll::Ready(Err(e)),
            };
        }
        let mut io_pending = false;
        while !self.eof && self.conn.wants_read() {
            match self.poll_feed_record(cx) {
                Poll::Ready(Ok(0)) => {
                    self.eof = true;
                    break;
                }
                Poll::Ready(Ok(_)) => {
                    if self.has_plaintext() {
                        return match self.conn.reader().into_first_chunk() {
                            Ok(data) => Poll::Ready(Ok(data)),
                            Err(e) => Poll::Ready(Err(e)),
                        };
                    }
                }
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        match self.conn.reader().into_first_chunk() {
            // Ok(空) = 干净关闭面（close_notify 已处理）——上层按 EOF 口径
            Ok(data) => Poll::Ready(Ok(data)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if self.eof {
                    // TCP 已 EOF 但对端未发 close_notify：明文已排空，面级收束
                    // 即 EOF 口径（返回空明文，上层读 0 字节按对端 EOF 处理；
                    // 否则 rustls 恒 WouldBlock，本分支 wake 自旋烧 CPU）
                    return Poll::Ready(Ok(&[][..]));
                }
                if !io_pending {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// 读明文（帧态下行路径）
    pub fn poll_read_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let data = ready!(self.poll_fill_buf(cx))?;
        let amount = buf.remaining().min(data.len());
        buf.put_slice(&data[..amount]);
        self.conn.reader().consume(amount);
        Poll::Ready(Ok(()))
    }

    pub async fn read_tls_into(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rb = ReadBuf::new(buf);
        std::future::poll_fn(|cx| self.poll_read_tls(cx, &mut rb)).await?;
        Ok(rb.filled().len())
    }

    /// 写明文并即时冲记录出站（帧态上行路径）
    pub fn poll_write_tls(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut pos = 0;
        loop {
            let mut would_block = false;
            self.conn
                .writer()
                .write(&buf[pos..])
                .map_err(io::Error::other)?;
            while self.conn.wants_write() {
                let mut adapter = SyncWriteAdapter {
                    io: &mut self.tcp,
                    cx,
                };
                match self.conn.write_tls(&mut adapter) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        would_block = true;
                        break;
                    }
                    result => {
                        result.map_err(io::Error::other)?;
                    }
                }
            }
            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (_, true) => Poll::Ready(Ok(pos)),
                (_, false) if pos == buf.len() => Poll::Ready(Ok(pos)),
                (_, false) => {
                    pos = buf.len();
                    continue;
                }
            };
        }
    }

    pub async fn write_tls_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut pos = 0;
        while pos < buf.len() {
            let n = std::future::poll_fn(|cx| self.poll_write_tls(cx, &buf[pos..])).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            pos += n;
        }
        Ok(())
    }

    pub async fn flush_tls(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            self.conn.writer().flush().map_err(io::Error::other)?;
            while self.conn.wants_write() {
                let mut adapter = SyncWriteAdapter {
                    io: &mut self.tcp,
                    cx,
                };
                match self.conn.write_tls(&mut adapter) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                    result => {
                        result.map_err(io::Error::other)?;
                    }
                }
            }
            Poll::Ready(Ok(()))
        })
        .await
    }

    /// TLS 半关（close_notify + 冲队 + TCP 写半边 shutdown）
    pub async fn close_tls(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_close_tls(cx)).await
    }

    pub fn poll_close_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.conn.send_close_notify();
        while self.conn.wants_write() {
            let mut adapter = SyncWriteAdapter {
                io: &mut self.tcp,
                cx,
            };
            match self.conn.write_tls(&mut adapter) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                result => {
                    result.map_err(io::Error::other)?;
                }
            }
        }
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }

    // ---- Direct 切换后的裸 TCP 面（poll 面：中继单任务循环用）----

    pub fn poll_read_raw(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }

    pub fn poll_write_raw(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }

    pub fn poll_shutdown_raw(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }

    /// 切换时带走记录边界之外的预读字节（帧态构造下应为空；防御面：
    /// 万一有残留直接按裸流量放行，不丢失）
    pub fn take_leftover(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.feed)
    }
}

// ---------------------------------------------------------------------------
// 双向中继：单任务 poll 循环（上行填充策略 + 下行解帧 + Direct 双面切换）
//
// 两向共享一个 VisionTlsFace（rustls 连接读写态一体，不可拆分）——
// 全部以非阻塞 poll 驱动，半途进度都在结构体内：relay 任务整体取消
// （abort）即全量丢弃、TCP 随之关闭；select 级取消不存在（单任务
// 无 await 竞争点）。
// ---------------------------------------------------------------------------

use rillane_core::BoxedIo;

/// Vision 中继统计（FlowReport 字节口径：上行/下行均为应用内容字节，
/// 不含填充与分帧头）
#[derive(Debug, Clone, Copy)]
pub struct VisionRelayStats {
    pub upstream: u64,
    pub downstream: u64,
}

/// 上行应用读宽（xray buf.Size 口径拆帧：单帧 content ≤ 2027，
/// 保证填充预算上限不为负）
const UPLINK_READ_CAP: usize = 2027;

/// 单向步进结果
#[derive(PartialEq)]
enum Step {
    /// 本轮推进了一单元（继续轮询）
    Progress,
    /// 无事可做（waker 已由内层 poll 注册）
    Pending,
}

/// 中继状态机（全部字段跨轮次持久）
struct RelayCore {
    policy: VisionWritePolicy,
    decoder: FrameDecoder,
    /// 待写上行字节（已消费 app 字节，必须写完才可再读）
    up_pending: Option<(Vec<u8>, bool)>, // (字节, raw?)
    up_offset: usize,
    /// 待写下行解码字节
    down_pending: Option<Vec<u8>>,
    down_offset: usize,
    /// 上行首载荷前伪装帧（xray 500ms）
    marker: Pin<Box<tokio::time::Sleep>>,
    down_raw: bool,
    /// 上行半关中（Some(raw?) = 关闭面已启动，待收束）
    closing: Option<bool>,
    up_done: bool,
    down_done: bool,
    up_bytes: u64,
    down_bytes: u64,
}

impl RelayCore {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            policy: VisionWritePolicy::new(uuid),
            decoder: FrameDecoder::new(uuid),
            up_pending: None,
            up_offset: 0,
            down_pending: None,
            down_offset: 0,
            marker: Box::pin(tokio::time::sleep(MARKER_AFTER)),
            down_raw: false,
            closing: None,
            up_done: false,
            down_done: false,
            up_bytes: 0,
            down_bytes: 0,
        }
    }

    /// 上行一步：残留帧 → 首载荷伪装窗 → 读 app → 决策 → 存帧即写
    fn poll_up(
        &mut self,
        cx: &mut Context<'_>,
        app_rd: &mut tokio::io::ReadHalf<BoxedIo>,
        face: &mut VisionTlsFace,
    ) -> Poll<io::Result<Step>> {
        // 半关收束（跨轮次）；up_done 先判——shutdown 幂等 Ready 会与
        // closing 分支叠成忙旋（验收面暴露的循环缺陷）
        if self.up_done {
            return Poll::Ready(Ok(Step::Pending));
        }
        if let Some(raw) = self.closing {
            let r = if raw {
                face.poll_shutdown_raw(cx)
            } else {
                face.poll_close_tls(cx)
            };
            ready!(r)?;
            self.up_done = true;
            return Poll::Ready(Ok(Step::Progress));
        }
        // 残留帧先行
        if let Some((bytes, raw)) = &self.up_pending {
            let chunk = &bytes[self.up_offset..];
            let n = ready!(if *raw {
                face.poll_write_raw(cx, chunk)
            } else {
                face.poll_write_tls(cx, chunk)
            })?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.up_offset += n;
            if self.up_offset >= bytes.len() {
                self.up_pending = None;
                self.up_offset = 0;
            }
            return Poll::Ready(Ok(Step::Progress));
        }
        if self.up_done {
            return Poll::Ready(Ok(Step::Pending));
        }

        let mut rbuf = [0u8; UPLINK_READ_CAP];
        let mut rb = ReadBuf::new(&mut rbuf);
        let app_ready = match Pin::new(&mut *app_rd).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Some(rb.filled().len()),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => None,
        };
        if let Some(n) = app_ready {
            if n == 0 {
                // 上行半关启动：Direct 面裸 shutdown；End 面 TLS close_notify
                self.closing = Some(self.policy.direct_switched());
                return Poll::Ready(Ok(Step::Progress));
            }
            self.up_bytes += n as u64;
            let action = self.policy.on_payload(rb.filled());
            match action {
                VisionWriteAction::PaddedFrame(frame) => {
                    // Direct 帧本身仍经外层 TLS（切换自下一帧起，xray 同序）
                    self.up_pending = Some((frame, false));
                }
                VisionWriteAction::PlainTls(bytes) => self.up_pending = Some((bytes, false)),
                VisionWriteAction::Raw(bytes) => self.up_pending = Some((bytes, true)),
            }
            self.up_offset = 0;
            return Poll::Ready(Ok(Step::Progress));
        }

        // 首载荷伪装窗：app 未就绪时让 500ms 定时器先到 → 空内容 Continue
        // 长填充藏 VLESS 头时序（xray ReadMultiBufferTimeout 口径）
        if !self.policy.marker_sent() {
            match self.marker.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    if let Some(VisionWriteAction::PaddedFrame(frame)) = self.policy.on_marker() {
                        self.up_pending = Some((frame, false));
                        self.up_offset = 0;
                        return Poll::Ready(Ok(Step::Progress));
                    }
                }
                Poll::Pending => {}
            }
        }
        Poll::Ready(Ok(Step::Pending))
    }

    /// 下行一步：残留解码字节 → 读（TLS 帧态 / 裸态）→ 解帧 → 存即写
    fn poll_down(
        &mut self,
        cx: &mut Context<'_>,
        app_wr: &mut tokio::io::WriteHalf<BoxedIo>,
        face: &mut VisionTlsFace,
    ) -> Poll<io::Result<Step>> {
        // 残留解码字节先行
        if let Some(bytes) = &self.down_pending {
            let n = ready!(Pin::new(&mut *app_wr).poll_write(cx, &bytes[self.down_offset..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.down_offset += n;
            if self.down_offset >= bytes.len() {
                self.down_bytes += bytes.len() as u64;
                self.down_pending = None;
                self.down_offset = 0;
            }
            return Poll::Ready(Ok(Step::Progress));
        }
        if self.down_done {
            return Poll::Ready(Ok(Step::Pending));
        }

        let mut rbuf = [0u8; 16 * 1024];
        let mut rb = ReadBuf::new(&mut rbuf);
        let n = if self.down_raw {
            ready!(face.poll_read_raw(cx, &mut rb))?;
            rb.filled().len()
        } else {
            ready!(face.poll_read_tls(cx, &mut rb))?;
            rb.filled().len()
        };
        if n == 0 {
            // 下行收束：关 app 写半边（ingress 客户端见 EOF）
            self.down_done = true;
            ready!(Pin::new(&mut *app_wr).poll_shutdown(cx))?;
            return Poll::Ready(Ok(Step::Progress));
        }
        if self.down_raw {
            self.down_pending = Some(rb.filled().to_vec());
        } else {
            let signal = self.decoder.push(rb.filled());
            let decoded = self.decoder.take();
            if !decoded.is_empty() {
                self.down_pending = Some(decoded);
            }
            if signal == VisionSignal::Direct && !self.down_raw {
                // 下行切换裸读（帧态构造下记录边界外无残留；防御面照解帧放行）
                self.down_raw = true;
                let leftover = face.take_leftover();
                if !leftover.is_empty() {
                    self.decoder.push(&leftover);
                    let decoded = self.decoder.take();
                    if !decoded.is_empty() {
                        // 并入待写（解码流保序：追加到现有 pending 尾部）
                        match &mut self.down_pending {
                            Some(p) => p.extend_from_slice(&decoded),
                            None => self.down_pending = Some(decoded),
                        }
                    }
                }
            }
        }
        self.down_offset = 0;
        Poll::Ready(Ok(Step::Progress))
    }
}

/// Vision 双向中继：单任务 poll 循环直至双向收束。app EOF 半关（上行
/// TLS close_notify / 裸 shutdown），下行 EOF 关 app 写半边（ingress
/// 客户端见 EOF）；取消面：任务丢弃即全量丢弃，TCP 随之关闭（真实
/// 对端可见连接结束）。
pub async fn relay(
    app: BoxedIo,
    face: VisionTlsFace,
    uuid: [u8; 16],
) -> io::Result<VisionRelayStats> {
    let mut face = face;
    let (mut app_rd, mut app_wr) = tokio::io::split(app);
    let mut core = RelayCore::new(uuid);
    std::future::poll_fn(|cx| {
        loop {
            if core.up_done && core.down_done {
                return Poll::Ready(Ok(VisionRelayStats {
                    upstream: core.up_bytes,
                    downstream: core.down_bytes,
                }));
            }
            let mut progressed = false;
            match core.poll_down(cx, &mut app_wr, &mut face) {
                Poll::Ready(Ok(Step::Progress)) => progressed = true,
                Poll::Ready(Ok(Step::Pending)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // 该向内层 IO 未就绪（waker 已注册）；不阻塞另一向
                Poll::Pending => {}
            }
            match core.poll_up(cx, &mut app_rd, &mut face) {
                Poll::Ready(Ok(Step::Progress)) => progressed = true,
                Poll::Ready(Ok(Step::Pending)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            if !progressed {
                // 双向皆待内层 IO（waker 已由各 poll 注册）
                return Poll::Pending;
            }
        }
    })
    .await
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; UUID_LEN] = [0xa7u8; 16];

    #[test]
    fn vision_flow_addons_bytes() {
        // Vision：protobuf Addons{Flow=1} —— 0x0A 0x10 + 16 字节串
        let addons = vision_flow_addons(Some(FLOW_VISION)).expect("vision addons");
        assert_eq!(addons.len(), 18);
        assert_eq!(&addons[..2], &[0x0a, 0x10]);
        assert_eq!(&addons[2..], FLOW_VISION.as_bytes());
        // 无 flow：OptLen=0（空段）
        assert!(vision_flow_addons(None).unwrap().is_empty());
        assert!(vision_flow_addons(Some("")).unwrap().is_empty());
        // 其他取值点名拒绝（不静默降级）
        let err = vision_flow_addons(Some("xtls-rprx-direct")).unwrap_err();
        assert!(format!("{err:#}").contains("未实现"), "{err:#}");
    }

    #[test]
    fn padding_len_bounds() {
        // 长填充（content < 900）：rand(0..500)+900-content ≥ 1
        for content in [0usize, 1, 500, 899] {
            let p = padding_len(content, true, &DEFAULT_TESTSEED);
            assert!(p >= 1, "content={content} 长填充下限");
            assert!(p <= 900 + 500 - content, "content={content} 长填充上限");
        }
        // 短填充（非长路径）：rand(0..256)
        for content in [900usize, 1024, 2000] {
            let p = padding_len(content, false, &DEFAULT_TESTSEED);
            assert!(p < 256, "content={content} 短填充上限");
        }
        // 上限收束：2048 - 21 - content
        let p = padding_len(2027, false, &DEFAULT_TESTSEED);
        assert!(p == 0, "content=2027 时上限为 0");
    }

    #[test]
    fn frame_roundtrip_single() {
        let mut b = FrameBuilder::new(UUID);
        let frame = b.frame(COMMAND_PADDING_CONTINUE, b"hello vision", true);
        // 首帧前置 UUID（前缀断言而非定长切片：次帧短填充路径帧长
        // 9+rand(0..256)，rand < 7 时不足 16B，[..16] 切片会越界）
        assert!(frame.starts_with(&UUID), "首帧前置 UUID");
        let mut d = FrameDecoder::new(UUID);
        let signal = d.push(&frame);
        assert_eq!(signal, VisionSignal::Frames, "Continue 帧后仍在帧态");
        assert_eq!(d.take(), b"hello vision");
        // 次帧不再前置 UUID
        let frame2 = b.frame(COMMAND_PADDING_END, b"tail", false);
        assert!(!frame2.starts_with(&UUID), "次帧无 UUID 前置");
        let signal = d.push(&frame2);
        assert_eq!(signal, VisionSignal::Plain, "End 后收束");
        assert_eq!(d.take(), b"tail");
        assert!(!d.direct());
    }

    #[test]
    fn frame_direct_switch_with_leftover() {
        let mut b = FrameBuilder::new(UUID);
        let head = b.frame(COMMAND_PADDING_DIRECT, b"begin", false);
        let mut frame = head;
        frame.extend_from_slice(b"raw-stream"); // Direct 帧后同段裸流量
        let mut d = FrameDecoder::new(UUID);
        let signal = d.push(&frame);
        assert_eq!(signal, VisionSignal::Direct);
        assert!(d.direct());
        assert_eq!(d.take(), b"beginraw-stream", "Direct 帧内容 + 剩余裸流量");
        // 后续推送全部按裸流量放行
        let signal = d.push(b"more-raw");
        assert_eq!(signal, VisionSignal::Direct);
        assert_eq!(d.take(), b"more-raw");
    }

    #[test]
    fn frame_split_pushes_and_continue_chain() {
        let mut b = FrameBuilder::new(UUID);
        let f1 = b.frame(COMMAND_PADDING_CONTINUE, b"AAAA", true);
        let f2 = b.frame(COMMAND_PADDING_CONTINUE, b"BB", false);
        let f3 = b.frame(COMMAND_PADDING_END, b"C", false);
        let mut all = Vec::new();
        all.extend_from_slice(&f1);
        all.extend_from_slice(&f2);
        all.extend_from_slice(&f3);

        let mut d = FrameDecoder::new(UUID);
        let mut decoded = Vec::new();
        // 首帧整段推送（UUID 门控要求首段 ≥21B，xray 同口径）；
        // 余下按 3 字节撕开推送（状态机跨段续拼）
        let gate = all.len().min(f1.len());
        let mut signal = d.push(&all[..gate]);
        decoded.extend_from_slice(&d.take());
        for piece in all[gate..].chunks(3) {
            let s = d.push(piece);
            decoded.extend_from_slice(&d.take());
            signal = s;
        }
        assert_eq!(decoded, b"AAAABBC");
        assert_eq!(signal, VisionSignal::Plain);
    }

    #[test]
    fn frame_uuid_gate_mismatch_is_plain() {
        let mut d = FrameDecoder::new(UUID);
        let payload = [0u8; 40]; // ≥21B 但前缀非本 UUID
        let signal = d.push(&payload);
        assert_eq!(signal, VisionSignal::Plain);
        assert_eq!(d.take(), payload);
        // 后续照旧直通
        let signal = d.push(b"x");
        assert_eq!(signal, VisionSignal::Plain);
        assert_eq!(d.take(), b"x");
    }

    #[test]
    fn frame_uuid_gate_short_first_chunk_is_plain() {
        let mut d = FrameDecoder::new(UUID);
        let signal = d.push(&UUID[..8]); // <21B：xray 同口径整段放行
        assert_eq!(signal, VisionSignal::Plain);
        assert_eq!(d.take(), &UUID[..8]);
    }

    #[test]
    fn filter_tls13_arms_xtls() {
        // 内层 ClientHello → ServerHello(带 TLS1.3 supported_versions) →
        // ApplicationData 完整记录 → Direct
        let mut f = InnerTlsFilter::new();
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x50, 0x01];
        ch.resize(0x55, 0u8);
        f.observe(&ch);
        assert!(f.is_tls());
        assert!(!f.is_tls12_or_above());
        // ServerHello：24B 记录（len=0x0018），体含 supported_versions 扩展
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x18, 0x02];
        sh.extend_from_slice(&[0u8; 9]);
        sh.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        sh.resize(0x1d, 0u8);
        f.observe(&sh);
        assert!(f.is_tls12_or_above());
        assert!(f.enable_xtls());
        // 完整 ApplicationData 记录
        let app = {
            let body = vec![0u8; 100];
            let mut r = vec![0x17, 0x03, 0x03];
            r.extend_from_slice(&(body.len() as u16).to_be_bytes());
            r.extend_from_slice(&body);
            r
        };
        assert!(is_complete_tls_record(&app));
    }

    #[test]
    fn filter_tls12_does_not_arm() {
        let mut f = InnerTlsFilter::new();
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x02];
        sh.resize(0x25, 0u8); // 无 supported_versions TLS1.3 扩展
        f.observe(&sh);
        assert!(f.is_tls12_or_above());
        assert!(!f.enable_xtls(), "TLS1.2 不置位 EnableXtls");
    }

    #[test]
    fn filter_non_tls_exhausts_window() {
        let mut f = InnerTlsFilter::new();
        for _ in 0..7 {
            f.observe(&[0xde, 0xad, 0xbe, 0xef]);
        }
        assert!(!f.is_tls());
        assert!(f.exhausted(), "7 包后窗口将尽（<=1）");
    }

    #[test]
    fn complete_record_check() {
        let mut rec = vec![0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4];
        assert!(is_complete_tls_record(&rec));
        // 两记录相接
        let second = rec.clone();
        rec.extend_from_slice(&second);
        assert!(is_complete_tls_record(&rec));
        // 非应用数据首字节
        assert!(!is_complete_tls_record(&[0x16, 0x03, 0x03, 0x00, 0x00]));
        // 截断（长度越界）
        rec.truncate(7);
        assert!(!is_complete_tls_record(&rec));
        // 空输入：无记录
        assert!(!is_complete_tls_record(&[]));
    }

    #[test]
    fn policy_marker_once_then_payload_path() {
        let mut p = VisionWritePolicy::new(UUID);
        // 伪装帧：空内容 Continue 长填充，只发一次
        let m1 = p.on_marker().expect("首标记帧");
        let VisionWriteAction::PaddedFrame(f) = m1 else {
            panic!("标记应为填充帧");
        };
        assert_eq!(&f[..16], &UUID);
        assert_eq!(f[16], COMMAND_PADDING_CONTINUE);
        assert_eq!(&f[17..19], &0u16.to_be_bytes(), "空内容");
        assert!(p.on_marker().is_none(), "标记只发一次");

        // 非 TLS 上行：Continue……直到过滤窗尽 → End
        //（标记帧已消耗一次性 UUID，载荷帧无前置 → 命令在 [0]）
        let mut saw_end = false;
        for i in 0..10 {
            let action = p.on_payload(&[0x42; 100]);
            let VisionWriteAction::PaddedFrame(frame) = action else {
                panic!("帧 {i} 应为填充帧");
            };
            if frame[0] == COMMAND_PADDING_END {
                saw_end = true;
                assert_eq!(&frame[1..3], &100u16.to_be_bytes());
                break;
            }
            assert_eq!(frame[0], COMMAND_PADDING_CONTINUE);
        }
        assert!(saw_end, "非 TLS 流量应在过滤窗尽时以 End 收束");
        // 收束后 End 面：字节留在外层 TLS 之内（PlainTls，非裸传）
        assert!(!p.padding_active());
        assert!(matches!(
            p.on_payload(b"tail"),
            VisionWriteAction::PlainTls(_)
        ));
    }

    #[test]
    fn policy_tls13_direct_switch() {
        let mut p = VisionWritePolicy::new(UUID);
        // 内层 TLS1.3 握手面喂入过滤窗
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x50, 0x01];
        ch.resize(0x55, 0u8);
        let a = p.on_payload(&ch);
        assert!(matches!(a, VisionWriteAction::PaddedFrame(_)));
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x18, 0x02];
        sh.extend_from_slice(&[0u8; 9]);
        sh.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        sh.resize(0x1d, 0u8);
        let a = p.on_payload(&sh);
        assert!(matches!(a, VisionWriteAction::PaddedFrame(_)));
        // 完整 ApplicationData 记录 → Direct 帧
        let mut app_body = vec![0x99u8; 100];
        app_body.insert(0, 0x17);
        let mut app = vec![0x17, 0x03, 0x03];
        app.extend_from_slice(&(100u16).to_be_bytes());
        app.extend_from_slice(&app_body[1..]);
        let action = p.on_payload(&app);
        let VisionWriteAction::PaddedFrame(frame) = action else {
            panic!("应发出收束填充帧");
        };
        // 第二帧（UUID 已随首帧消耗）→ 命令在 [0]
        assert_eq!(frame[0], COMMAND_PADDING_DIRECT, "TLS1.3 内层 → Direct");
        assert!(!p.padding_active());
        assert!(p.direct_switched());
        // 切换后裸传
        assert!(matches!(p.on_payload(b"raw"), VisionWriteAction::Raw(_)));
    }

    #[test]
    fn policy_tls12_end_switch() {
        let mut p = VisionWritePolicy::new(UUID);
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x02];
        sh.resize(0x25, 0u8);
        let a = p.on_payload(&sh);
        assert!(matches!(a, VisionWriteAction::PaddedFrame(_)));
        // TLS1.2 的 ApplicationData 完整记录 → End（留在外层 TLS 内）
        let app = vec![0x17, 0x03, 0x03, 0x00, 0x02, 1, 2];
        let action = p.on_payload(&app);
        let VisionWriteAction::PaddedFrame(frame) = action else {
            panic!("应发出收束填充帧");
        };
        // 第二帧（UUID 已随首帧消耗）→ 命令在 [0]
        assert_eq!(frame[0], COMMAND_PADDING_END, "TLS1.2 内层 → End");
        assert!(!p.padding_active());
        assert!(!p.direct_switched());
        assert!(matches!(
            p.on_payload(b"still-tls"),
            VisionWriteAction::PlainTls(_)
        ));
    }

    /// 面级 EOF 收束：对端握手后直接丢弃连接（不发 close_notify）——
    /// read_tls_into 须在时限内返回 Ok(0)（对端 EOF 口径）；此前实现
    /// 在「TCP 已 EOF、rustls 恒 WouldBlock」态下 wake 自旋烧 CPU 悬挂。
    #[tokio::test]
    async fn face_surfaces_eof_when_peer_closes_without_close_notify() {
        use std::time::Duration;
        use tokio::time::timeout;

        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        use crate::fingerprint::TlsFingerprint;
        use crate::outbound::reality::handshake;
        use crate::tls::{profile_client_config, tls_crypto_provider};

        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("自签");
        let certs: Vec<CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(certified.cert.pem().as_bytes())
                .collect::<Result<_, _>>()
                .expect("证书 PEM");
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
            certified.key_pair.serialize_pem().as_bytes(),
        )
        .expect("私钥");
        let server_config = rustls::ServerConfig::builder_with_provider(tls_crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("版本")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("服务端装配");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        // 服务端：握手完成后立即丢弃（无 close_notify——TCP FIN 直接收束）
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let conn = rustls::ServerConnection::new(std::sync::Arc::new(server_config))
                    .expect("服务端连接");
                let _tls = handshake(tcp, conn).await;
                // drop：不发 close_notify
            }
        });

        let tcp = TcpStream::connect(addr).await.expect("dial");
        let config = profile_client_config(true, None, TlsFingerprint::None).expect("客户端装配");
        let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("SNI");
        let conn = rustls::ClientConnection::new(config, server_name).expect("客户端连接");
        let (tcp, conn) = handshake(tcp, conn).await.expect("TLS 握手").into_parts();
        let mut face = VisionTlsFace::new(tcp, conn);

        let mut buf = [0u8; 16];
        let n = timeout(Duration::from_secs(2), face.read_tls_into(&mut buf))
            .await
            .expect("面读须收束（不得 WouldBlock 自旋悬挂）")
            .expect("面读不报错");
        assert_eq!(n, 0, "对端 EOF 面须以 0 字节呈现");
    }
}
