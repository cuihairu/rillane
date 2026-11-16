//! ShadowTLS v2 入口载具面（RIL-110）
//!
//! 线格式与 outbound/shadowtls.rs（客户端面）同源：官方 ihciah/shadow-tls
//! v0.2.20 server.rs `relay_v2` + helper_v2.rs 镜像（源码浅读 2026-11-17）。
//! 服务端职责分两段：
//! - 握手段：向伪装站点（handshake site）做纯 TLS 中继——伪装站点→客户端
//!   方向逐字节累积 HMAC-SHA1(password) 并保留最近 10 个快照（容忍在途
//!   竞态）；客户端→伪装站点方向原样透传并解析 TLS 记录：首记录须 0x16
//!   且版本 0x03、minor ∈ {0x01, 0x03}；此后 application-data 记录（须已
//!   见 0x16 与 0x14 change_cipher_spec）内容前 8 字节与快照窗口比对，
//!   命中即切换；未命中累计 > 3 次、或任何畸形记录形状 → 转入永久无辜
//!   中继（主动探测防御：访客拿到完整伪装站点 TLS 面）。
//! - 切换段：丢弃伪装站点连接，连数据服务器（内层 SS 入口 bind），先写
//!   纯数据（挑战记录内容去掉 8 字节挑战的余段 + 管线残余记录），此后
//!   双向伪记录封帧/解帧（内容 ≤ 4091 字节，对齐官方 COPY_BUF）。
//!
//! 载具无寻址面：目标寻址归内层协议（router/output 不经手），组合边界
//! 与 docs/protocol-backends.md shadow-tls 一节一致。

use std::{collections::VecDeque, net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use hmac::{Hmac, Mac};
use rillane_core::{FlowOutput, FlowRouter, IngressEndpoint};
use sha1::Sha1;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::outbound::shadowtls::{
    APPLICATION_DATA, CHALLENGE_LEN, RECORD_CONTENT_MAX, SHA1_LEN, TLS_HEADER_SIZE, TLS_MAJOR,
    TLS_MINOR,
};

/// handshake 记录类型（首记录必须）
const HANDSHAKE: u8 = 0x16;
/// change_cipher_spec 记录类型（挑战检查前置）
const CHANGE_CIPHER_SPEC: u8 = 0x14;
/// TLS 记录内容上限（标准口径 2^14 + 2048；越界即畸形形状）
const TLS_RECORD_CONTENT_LIMIT: usize = 16384 + 2048;
/// 哈希快照窗口（官方容量 10，容忍在途竞态）
const HASH_WINDOW: usize = 10;
/// 挑战未命中容错：累计 > 3 次即转入无辜中继（官方阈值）
const CHALLENGE_MAX_MISMATCH: u32 = 3;

type HmacSha1 = Hmac<Sha1>;

/// ShadowTLS 入口载具（v2）：伪装站点 TLS 中继 + 挑战响应切换 + 伪记录
/// 双向封帧中继，切换后的流交给数据服务器（内层 SS 入口）
#[derive(Debug)]
pub struct ShadowTlsIngress {
    name: String,
    bind: SocketAddr,
    password: String,
    /// 伪装站点（handshake site）地址
    handshake_addr: SocketAddr,
    /// 数据服务器（内层协议入口）地址
    target_addr: SocketAddr,
}

/// 提手段校验结论
#[derive(Debug)]
enum SwitchDecision {
    /// 继续握手段中继
    Continue,
    /// 挑战命中 → 切换（携带纯数据余段与管线残余记录）
    Switch {
        pure_data: BytesMut,
        pending: BytesMut,
    },
    /// 挑战超限 / 畸形形状 → 永久无辜中继
    Innocent,
}

/// 客户端→伪装站点方向的记录校验器（官方 server.rs 校验状态机镜像）。
/// 原样透传在调用方完成——本器只解析记录推进状态，不持有数据面职责。
#[derive(Default)]
struct ChallengeValidator {
    /// 记录累积缓冲（TCP 分段/粘连在此归整）
    buf: BytesMut,
    seen_handshake: bool,
    seen_ccs: bool,
    mismatches: u32,
}

impl ChallengeValidator {
    /// 喂入客户端方向原始字节（调用方已把 chunk 原样透传伪装站点），
    /// 逐记录推进校验状态，返回结论（或缓冲不足以成记录时 Continue）
    fn feed(&mut self, chunk: &[u8], window: &VecDeque<[u8; SHA1_LEN]>) -> SwitchDecision {
        self.buf.extend_from_slice(chunk);
        loop {
            if self.buf.len() < TLS_HEADER_SIZE {
                return SwitchDecision::Continue;
            }
            let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
            if len > TLS_RECORD_CONTENT_LIMIT {
                // 畸形形状（内容长度越界）：即转无辜中继
                return SwitchDecision::Innocent;
            }
            if self.buf.len() < TLS_HEADER_SIZE + len {
                return SwitchDecision::Continue;
            }
            let mut whole = self.buf.split_to(TLS_HEADER_SIZE + len);
            let typ = whole[0];
            let maj = whole[1];
            let min = whole[2];
            whole.advance(TLS_HEADER_SIZE);
            if !self.seen_handshake {
                // 首记录形状门：0x16 + 版本 0x03 + minor ∈ {0x01, 0x03}
                if typ != HANDSHAKE || maj != TLS_MAJOR || (min != 0x01 && min != 0x03) {
                    return SwitchDecision::Innocent;
                }
                self.seen_handshake = true;
                continue;
            }
            match typ {
                CHANGE_CIPHER_SPEC => self.seen_ccs = true,
                APPLICATION_DATA if self.seen_ccs => {
                    let hit = whole.len() >= CHALLENGE_LEN
                        && window
                            .iter()
                            .any(|h| h[..CHALLENGE_LEN] == whole[..CHALLENGE_LEN]);
                    if hit {
                        // 纯数据 = 记录内容去掉 8 字节挑战的余段
                        let mut pure_data = whole;
                        pure_data.advance(CHALLENGE_LEN);
                        let pending = std::mem::take(&mut self.buf);
                        return SwitchDecision::Switch { pure_data, pending };
                    }
                    self.mismatches += 1;
                    if self.mismatches > CHALLENGE_MAX_MISMATCH {
                        return SwitchDecision::Innocent;
                    }
                }
                _ => {}
            }
        }
    }
}

impl ShadowTlsIngress {
    pub fn new(
        name: String,
        bind: String,
        password: String,
        handshake_addr: String,
        target_addr: String,
    ) -> Result<Self> {
        // 构建期校验：配置错误启动时暴露，而非首个连接时
        if password.is_empty() {
            bail!("shadowtls password 不能为空");
        }
        let bind: SocketAddr = bind
            .parse()
            .with_context(|| format!("shadowtls 入口 bind 非法: {bind}"))?;
        let handshake_addr: SocketAddr = handshake_addr
            .parse()
            .with_context(|| format!("shadowtls 握手站点地址非法: {handshake_addr}"))?;
        let target_addr: SocketAddr = target_addr
            .parse()
            .with_context(|| format!("shadowtls 数据服务器地址非法: {target_addr}"))?;
        Ok(Self {
            name,
            bind,
            password,
            handshake_addr,
            target_addr,
        })
    }

    /// 单连接 relay_v2：握手段 select 双向中继（快照窗口单任务无锁）→
    /// 挑战命中即切换；未命中超限/畸形形状 → 无辜中继
    async fn relay_v2(&self, mut client: TcpStream) -> Result<()> {
        let mut camo = TcpStream::connect(self.handshake_addr)
            .await
            .with_context(|| format!("ShadowTLS 握手站点连接失败: {}", self.handshake_addr))?;
        let mut hasher =
            HmacSha1::new_from_slice(self.password.as_bytes()).expect("HMAC-SHA1 接受任意长度键");
        let mut window: VecDeque<[u8; SHA1_LEN]> = VecDeque::with_capacity(HASH_WINDOW);
        let mut validator = ChallengeValidator::default();
        let mut camo_buf = vec![0u8; 8192];
        let mut client_chunk = [0u8; 8192];

        let stage = loop {
            tokio::select! {
                r = camo.read(&mut camo_buf) => match r {
                    // 伪装站点先收束：中继随对端结束
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        hasher.update(&camo_buf[..n]);
                        let snapshot = hasher
                            .clone()
                            .finalize()
                            .into_bytes()
                            .as_slice()
                            .try_into()
                            .expect("SHA1 摘要长度恒 20 字节");
                        window.push_back(snapshot);
                        if window.len() > HASH_WINDOW {
                            window.pop_front();
                        }
                        client.write_all(&camo_buf[..n]).await?;
                    }
                    Err(e) => return Err(e.into()),
                },
                r = client.read(&mut client_chunk) => match r {
                    // 访客先收束：中继随对端结束
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        // 握手段原样透传（纯 TLS 中继语义）
                        camo.write_all(&client_chunk[..n]).await?;
                        match validator.feed(&client_chunk[..n], &window) {
                            SwitchDecision::Continue => {}
                            stage @ (SwitchDecision::Switch { .. }
                            | SwitchDecision::Innocent) => break stage,
                        }
                    }
                    Err(e) => return Err(e.into()),
                },
            }
        };

        match stage {
            SwitchDecision::Continue => unreachable!("循环仅在 Switch/Innocent 处退出"),
            SwitchDecision::Innocent => {
                tracing::info!(
                    target: "rillane::shadowtls",
                    node = %self.name,
                    "shadowtls v2 挑战未命中，转入无辜中继（伪装站点全量 TLS 面）"
                );
                tokio::io::copy_bidirectional(&mut client, &mut camo).await?;
                Ok(())
            }
            SwitchDecision::Switch { pure_data, pending } => {
                tracing::info!(
                    target: "rillane::shadowtls",
                    node = %self.name,
                    "shadowtls v2 挑战命中，切换至数据服务器"
                );
                let mut target = TcpStream::connect(self.target_addr)
                    .await
                    .with_context(|| {
                        format!("ShadowTLS 数据服务器连接失败: {}", self.target_addr)
                    })?;
                // 官方口径：先写纯数据（挑战记录余段），管线残余随后解帧
                target.write_all(&pure_data).await?;
                let (client_read, client_write) = tokio::io::split(client);
                let (target_read, target_write) = tokio::io::split(target);
                let up = de_frame_to(client_read, target_write, pending);
                let down = frame_from(target_read, client_write);
                let (r1, r2) = tokio::join!(up, down);
                r1.context("ShadowTLS 上行解帧中继收束")?;
                r2.context("ShadowTLS 下行封帧中继收束")?;
                Ok(())
            }
        }
    }
}

/// 切换后客户端→数据服务器方向：伪记录解帧（官方
/// copy_without_application_data 语义——剥记录头转发内容）
async fn de_frame_to(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    mut acc: BytesMut,
) -> std::io::Result<()> {
    loop {
        if acc.len() < TLS_HEADER_SIZE {
            let n = reader.read_buf(&mut acc).await?;
            if n == 0 {
                if acc.is_empty() {
                    // 干净 EOF：半关数据服务器写侧，等对端收束
                    return writer.shutdown().await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ShadowTLS 伪记录头截断",
                ));
            }
            continue;
        }
        let len = u16::from_be_bytes([acc[3], acc[4]]) as usize;
        if acc.len() < TLS_HEADER_SIZE + len {
            let before = acc.len();
            reader.read_buf(&mut acc).await?;
            if acc.len() == before {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ShadowTLS 伪记录内容截断",
                ));
            }
            continue;
        }
        let mut whole = acc.split_to(TLS_HEADER_SIZE + len);
        whole.advance(TLS_HEADER_SIZE);
        writer.write_all(&whole).await?;
    }
}

/// 切换后数据服务器→客户端方向：伪记录封帧（官方
/// copy_with_application_data 语义——单记录内容 ≤ RECORD_CONTENT_MAX）
async fn frame_from(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; RECORD_CONTENT_MAX];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return writer.shutdown().await;
        }
        let header = [
            APPLICATION_DATA,
            TLS_MAJOR,
            TLS_MINOR,
            (n >> 8) as u8,
            n as u8,
        ];
        writer.write_all(&header).await?;
        writer.write_all(&buf[..n]).await?;
    }
}

#[async_trait]
impl IngressEndpoint for ShadowTlsIngress {
    fn name(&self) -> &'static str {
        "shadowtls"
    }

    async fn run(
        self: Arc<Self>,
        _router: Arc<dyn FlowRouter>,
        _output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let listener = TcpListener::bind(self.bind)
            .await
            .with_context(|| format!("无法监听 {}", self.bind))?;
        tracing::info!(
            target: "rillane::shadowtls",
            bind = %self.bind,
            node = %self.name,
            handshake = %self.handshake_addr,
            target = %self.target_addr,
            "ShadowTLS 入口载具启动"
        );
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(err) = this.relay_v2(stream).await {
                    tracing::warn!(
                        target: "rillane::shadowtls",
                        node = %this.name,
                        client = %peer,
                        error = %err,
                        "ShadowTLS 连接收束"
                    );
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与客户端一致口径构造快照窗口：逐块累积 HMAC，块末快照入窗
    fn snapshot_stream(password: &str, chunks: &[&[u8]]) -> VecDeque<[u8; SHA1_LEN]> {
        let mut mac = HmacSha1::new_from_slice(password.as_bytes()).unwrap();
        let mut window = VecDeque::with_capacity(HASH_WINDOW);
        for c in chunks {
            mac.update(c);
            let snapshot = mac
                .clone()
                .finalize()
                .into_bytes()
                .as_slice()
                .try_into()
                .expect("SHA1 摘要长度恒 20 字节");
            window.push_back(snapshot);
        }
        window
    }

    fn record(typ: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![typ, 0x03, 0x03];
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        v.extend_from_slice(content);
        v
    }

    /// 合法首记录（ClientHello 形状）+ change_cipher_spec
    fn handshake_records() -> Vec<u8> {
        let mut v = record(HANDSHAKE, &[0x01, 0x00, 0x1f, 0x33]);
        v.extend_from_slice(&record(CHANGE_CIPHER_SPEC, &[]));
        v
    }

    #[test]
    fn challenge_hit_switches_with_pure_data_and_pending() {
        let window = snapshot_stream("hunt", &[b"TLS-handshake-bytes-1", b"-2"]);
        let challenge = window.back().unwrap()[..CHALLENGE_LEN].to_vec();
        let mut v = handshake_records();
        v.extend_from_slice(&record(
            APPLICATION_DATA,
            &[challenge.as_slice(), b"GET /"].concat(),
        ));
        // 挑战记录与后续内层记录管线粘连（单段到达）
        v.extend_from_slice(&record(APPLICATION_DATA, b"pipelined"));
        let mut validator = ChallengeValidator::default();
        match validator.feed(&v, &window) {
            SwitchDecision::Switch { pure_data, pending } => {
                assert_eq!(&pure_data[..], b"GET /");
                // 管线残余保留完整记录（含头）——切换后继续解帧
                assert_eq!(pending.len(), TLS_HEADER_SIZE + 9);
            }
            other => panic!("挑战命中须切换: {other:?}"),
        }
    }

    #[test]
    fn window_tolerates_inflight_race() {
        // 挑战取自倒数第二个快照（写侧已前进而客户端尚未收到的竞态位）也须命中
        let window = snapshot_stream("pw2", &[b"chunk-one-", b"chunk-two-"]);
        let challenge = window[0][..CHALLENGE_LEN].to_vec();
        let mut v = handshake_records();
        v.extend_from_slice(&record(
            APPLICATION_DATA,
            &[challenge.as_slice(), b"X"].concat(),
        ));
        let mut validator = ChallengeValidator::default();
        assert!(matches!(
            validator.feed(&v, &window),
            SwitchDecision::Switch { .. }
        ));
    }

    #[test]
    fn first_record_shape_gate_and_malformed_length() {
        let window = snapshot_stream("pw", &[b"x"]);
        // 首记录非 0x16 → 无辜
        let mut validator = ChallengeValidator::default();
        let bad = record(APPLICATION_DATA, &[0u8; 8]);
        assert!(matches!(
            validator.feed(&bad, &window),
            SwitchDecision::Innocent
        ));
        // 首记录版本 minor 越界 → 无辜
        let mut validator = ChallengeValidator::default();
        let v = vec![HANDSHAKE, 0x03, 0x09, 0, 0];
        assert!(matches!(
            validator.feed(&v, &window),
            SwitchDecision::Innocent
        ));
        // 内容长度越界（畸形形状）→ 无辜
        let mut validator = ChallengeValidator::default();
        let v = vec![HANDSHAKE, 0x03, 0x01, 0xff, 0xff];
        assert!(matches!(
            validator.feed(&v, &window),
            SwitchDecision::Innocent
        ));
        // 合法首记录放行（缓冲不足继续等）
        let mut validator = ChallengeValidator::default();
        let ok = record(HANDSHAKE, &[0x01, 0x00]);
        assert!(matches!(
            validator.feed(&ok, &window),
            SwitchDecision::Continue
        ));
    }

    #[test]
    fn three_mismatches_continue_four_innocent() {
        let window = snapshot_stream("pw", &[b"abc"]);
        // 官方阈值 > 3：3 次未命中仍继续
        let mut v = handshake_records();
        for _ in 0..3 {
            v.extend_from_slice(&record(APPLICATION_DATA, &[9u8; 8]));
        }
        let mut validator = ChallengeValidator::default();
        assert!(matches!(
            validator.feed(&v, &window),
            SwitchDecision::Continue
        ));
        // 第 4 次未命中 → 无辜
        let mut v = handshake_records();
        for _ in 0..4 {
            v.extend_from_slice(&record(APPLICATION_DATA, &[9u8; 8]));
        }
        let mut validator = ChallengeValidator::default();
        assert!(matches!(
            validator.feed(&v, &window),
            SwitchDecision::Innocent
        ));
    }

    #[test]
    fn challenge_before_ccs_passes_through() {
        let window = snapshot_stream("pw", &[b"abc"]);
        // CCS 未见的 application-data（早数据/会话票据）原样放行不比对
        let mut v = record(HANDSHAKE, &[0x01, 0x00]);
        v.extend_from_slice(&record(APPLICATION_DATA, &[7u8; 8]));
        let mut validator = ChallengeValidator::default();
        assert!(matches!(
            validator.feed(&v, &window),
            SwitchDecision::Continue
        ));
    }

    #[test]
    fn constructor_refuses_empty_password_and_bad_addrs() {
        let err = ShadowTlsIngress::new(
            "n".into(),
            "127.0.0.1:1".into(),
            String::new(),
            "127.0.0.1:2".into(),
            "127.0.0.1:3".into(),
        )
        .expect_err("空 password 必须拒绝");
        assert!(err.to_string().contains("password"), "{err}");
        let err = ShadowTlsIngress::new(
            "n".into(),
            "nope".into(),
            "p".into(),
            "127.0.0.1:2".into(),
            "127.0.0.1:3".into(),
        )
        .expect_err("非法 bind 必须拒绝");
        assert!(err.to_string().contains("bind 非法"), "{err}");
    }
}
